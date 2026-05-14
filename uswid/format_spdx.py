#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2023 Richard Hughes <richard@hughsie.com>
# (c) Copyright 2025 HP Development Company, L.P.
#
# SPDX-License-Identifier: BSD-2-Clause-Patent

from typing import Dict, Any, Optional, List, Set

import json
import re
import uuid
from datetime import datetime, timezone

from .container import uSwidContainer
from .format import uSwidFormatBase
from .component import uSwidComponent, uSwidComponentType
from .entity import uSwidEntity, uSwidEntityRole
from .errors import NotSupportedError
from .hash import uSwidHashAlg
from .link import uSwidLink, uSwidLinkRel
from .purl import uSwidPurl


def _convert_hash_alg_id(alg_id: uSwidHashAlg) -> str:
    return {
        uSwidHashAlg.SHA256: "SHA256",
        uSwidHashAlg.SHA384: "SHA384",
        uSwidHashAlg.SHA512: "SHA512",
    }.get(alg_id, "UNKNOWN")


def _normalize_spdx_namespace(namespace: Optional[str]) -> Optional[str]:
    if not namespace:
        return None
    namespace = namespace.rstrip("#/")
    if namespace.startswith("urn:uuid:"):
        namespace = namespace[len("urn:uuid:") :]
    return namespace


def _namespaced_tag_id(spdx_id: Optional[str], namespace: Optional[str]) -> Optional[str]:
    if not spdx_id:
        return None
    if spdx_id.startswith("SPDXRef-"):
        spdx_id = spdx_id[8:]
    if namespace:
        return f"{namespace}:{spdx_id}"
    return spdx_id


_SPDXID_DISALLOWED_RE = re.compile(r"[^A-Za-z0-9.-]")


def _sanitize_spdxid(raw: str) -> str:
    """Make a string safe for use inside an SPDXID.

    Per SPDX 2.3 §3.2, ``SPDXID`` must match ``SPDXRef-[A-Za-z0-9.-]+``.
    PURLs (``pkg:foo/bar@1.0``) and CPEs (``cpe:2.3:a:vendor:product:...``) contain
    colons, slashes, ``#``, ``@``, ``+`` — all disallowed. Replace each disallowed
    char with ``-``, collapse runs of ``-`` to a single ``-``, and trim leading
    non-alphanumeric chars (the spec requires the first char after ``SPDXRef-``
    to be alphanumeric).
    """
    if not raw:
        return "NOASSERTION"
    cleaned = _SPDXID_DISALLOWED_RE.sub("-", raw)
    cleaned = re.sub(r"-{2,}", "-", cleaned).strip("-.")
    if not cleaned or not cleaned[0].isalnum():
        cleaned = "x-" + cleaned if cleaned else "NOASSERTION"
    return cleaned


_PERSON_NAME_RE = re.compile(r"^[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+$")
_ORG_MARKER_RE = re.compile(
    r"\b(?:inc|llc|ltd|corp|corporation|foundation|project|gmbh|company|"
    r"developers|authors|team|group|consortium|labs|labs?\.?|software|"
    r"systems|technologies|industries)\b",
    re.IGNORECASE,
)


def _entity_kind(entity: uSwidEntity) -> str:
    """Return ``Person`` or ``Organization`` to prefix an SPDX Creator/Supplier line.

    UEFI SBOM Guidelines §3.1.1.1 lets the author be either; SPDX requires the
    prefix. Default is ``Organization`` (matches historical behavior); we promote to
    ``Person`` only when the heuristic is fairly certain (whitespace-separated
    proper-cased name, no organization markers, no domain regid).
    """
    name = (entity.name or "").strip()
    if not name:
        return "Organization"
    if entity.regid and "." in entity.regid:
        return "Organization"
    if _ORG_MARKER_RE.search(name):
        return "Organization"
    if _PERSON_NAME_RE.match(name):
        return "Person"
    return "Organization"


def _format_creator(entity: uSwidEntity) -> Optional[str]:
    """Render a uSwidEntity as an SPDX ``Creator``/``Supplier``/``Originator`` string.

    Format: ``Person|Organization: <Name> [<email>]`` (UEFI SBOM Guidelines §3.1.1.1).
    Returns ``None`` if the entity has no usable name.
    """
    if not entity.name or entity.name == "NOASSERTION":
        return None
    kind = _entity_kind(entity)
    if entity.email:
        return f"{kind}: {entity.name} <{entity.email}>"
    return f"{kind}: {entity.name}"


class uSwidFormatSpdx(uSwidFormatBase):
    """SPDX file"""

    def __init__(self) -> None:
        """Initializes uSwidFormatSpdx"""
        uSwidFormatBase.__init__(self, "SPDX")
        self.document_namespace: Optional[str] = None
        """Override for ``documentNamespace`` (default: random ``urn:uuid:`` URI)."""
        self.document_name: Optional[str] = None
        """Override for the SPDX document ``name`` (default: ``NOASSERTION``)."""
        self.timestamp: Optional[str] = None
        """Override for ``creationInfo.created`` (default: current UTC, ISO-8601 ``Z``)."""
        self.sbom_type: Optional[str] = None
        """High-level SBOM type from UEFI SBOM Guidelines §3.1.1.3: ``source|build|binary``.
        Appended to ``creationInfo.comment`` for traceability."""

    def _load_single_package(
        self,
        pkg: Dict[str, Any],
        data_root: Dict[str, Any],
        namespace: Optional[str],
    ) -> uSwidComponent:
        """Load a single package from SPDX JSON data"""
        component = uSwidComponent()
        # tag_id: prefer a purl externalRef when present (we emit it for round-trip),
        # else fall back to the namespaced SPDXID.
        component.tag_id = _namespaced_tag_id(pkg.get("SPDXID"), namespace)
        external_refs = pkg.get("externalRefs") or pkg.get("externalReferences") or []
        if isinstance(external_refs, list):
            for ref in external_refs:
                if not isinstance(ref, dict):
                    continue
                ref_type = ref.get("referenceType")
                locator = ref.get("referenceLocator")
                if not locator:
                    continue
                if ref_type == "purl":
                    component.purl = uSwidPurl(locator)
                    component.tag_id = locator
                elif ref_type in ("cpe23Type", "cpe22Type"):
                    component.cpe = locator
                    # Prefer CPE as the internal tag_id only if no PURL was found.
                    if not component.purl:
                        component.tag_id = locator
        # basic fields
        component.software_name = pkg.get("name")
        component.summary = pkg.get("summary")
        component.software_version = pkg.get("versionInfo")
        # UEFI SBOM Guidelines §3.1.11
        copyright_text = pkg.get("copyrightText")
        if copyright_text and copyright_text != "NOASSERTION":
            component.copyright = copyright_text

        # licenseConcluded preferred over licenseDeclared; either may be present.
        for license_key in ("licenseConcluded", "licenseDeclared"):
            spdx_license_ids = pkg.get(license_key)
            if not spdx_license_ids or spdx_license_ids == "NOASSERTION":
                continue
            for spdx_license_id in spdx_license_ids.split(" AND "):
                spdx_license_id = spdx_license_id.strip().strip("()")
                if not spdx_license_id:
                    continue
                component.add_link(
                    uSwidLink(rel=uSwidLinkRel.LICENSE, spdx_id=spdx_license_id)
                )
            # Don't double-add from both fields — they'll be deduped by add_link anyway,
            # but stop after the first one we successfully parsed.
            break

        # supplier / originator (UEFI SBOM Guidelines §3.1.2.2). We treat:
        #   supplier  -> SOFTWARE_CREATOR (symmetric with CycloneDX)
        #   originator -> LICENSOR (upstream/heritage origin)
        for spdx_field, role in (
            ("supplier", uSwidEntityRole.SOFTWARE_CREATOR),
            ("originator", uSwidEntityRole.LICENSOR),
        ):
            value = pkg.get(spdx_field)
            if not value or value == "NOASSERTION":
                continue
            ent = self._parse_creator(value)
            if ent is None:
                continue
            ent.roles = [role]
            component.add_entity(ent)

        # creationInfo creators (tag creators); take every Person/Organization
        try:
            creators = data_root["creationInfo"]["creators"]
        except (KeyError, TypeError):
            creators = []
        for creator in creators or []:
            if not isinstance(creator, str):
                continue
            ent = self._parse_creator(creator)
            if ent is None:
                continue
            ent.roles = [uSwidEntityRole.TAG_CREATOR]
            component.add_entity(ent)

        return component

    @staticmethod
    def _parse_creator(value: str) -> Optional[uSwidEntity]:
        """Parse an SPDX ``Person|Organization|Tool: Name [<email>]`` string.

        Returns ``None`` for ``Tool:`` lines (those are tracked separately as the
        SBOM tool, not as an author/supplier) and for malformed input.
        """
        if not value:
            return None
        if value.startswith("Person: "):
            body = value[len("Person: ") :]
        elif value.startswith("Organization: "):
            body = value[len("Organization: ") :]
        elif value.startswith("Tool: "):
            return None
        else:
            body = value
        email: Optional[str] = None
        match = re.match(r"^(.*?)\s*<\s*([^>]+?)\s*>\s*$", body)
        if match:
            name = match.group(1).strip()
            email = match.group(2).strip() or None
        else:
            name = body.strip()
        if not name:
            return None
        return uSwidEntity(name=name, email=email)

    def load(self, blob: bytes, path: Optional[str] = None) -> uSwidContainer:
        try:
            data = json.loads(blob)
        except json.JSONDecodeError as e:
            raise NotSupportedError(f"invalid JSON file: {e}") from e

        packages = data.get("packages")
        if not packages:
            return uSwidContainer()

        namespace = _normalize_spdx_namespace(data.get("documentNamespace"))
        components_by_spdxid = {}
        container = uSwidContainer()

        # Mark which SPDXID(s) the document declares as primary (UEFI SBOM Guidelines §3.1.1.3)
        primary_spdxids: Set[str] = set()
        for rel in data.get("relationships", []):
            if not isinstance(rel, dict):
                continue
            if (
                rel.get("relationshipType") == "DESCRIBES"
                and rel.get("spdxElementId") == "SPDXRef-DOCUMENT"
            ):
                tgt = rel.get("relatedSpdxElement")
                if tgt:
                    primary_spdxids.add(tgt)
        for legacy in data.get("documentDescribes", []) or []:
            primary_spdxids.add(legacy)

        for pkg in packages:
            comp = self._load_single_package(pkg, data, namespace)
            pkg_spdxid = pkg.get("SPDXID")
            if pkg_spdxid:
                components_by_spdxid[pkg_spdxid] = comp
                if pkg_spdxid in primary_spdxids:
                    comp.is_primary = True
            container.append(comp)

        # relationships (dependencies). Accept both CONTAINS (UEFI Guidelines §3.1.9) and
        # DEPENDS_ON (the legacy uSWID emit form).
        for rel in data.get("relationships", []):
            if not isinstance(rel, dict):
                continue
            if rel.get("relationshipType") not in ("DEPENDS_ON", "CONTAINS"):
                continue
            src = rel.get("spdxElementId")
            tgt = rel.get("relatedSpdxElement")
            if not src or not tgt:
                continue
            if src in components_by_spdxid and tgt in components_by_spdxid:
                csrc = components_by_spdxid[src]
                ctgt = components_by_spdxid[tgt]
                csrc.add_link(
                    uSwidLink(rel=uSwidLinkRel.COMPONENT, href=ctgt.tag_id)
                )

        return container

    def _resolve_primary(
        self, container: uSwidContainer
    ) -> Optional[uSwidComponent]:
        """Pick the SBOM's Primary Component, mirroring the CycloneDX resolver.

        Priority: explicit ``is_primary=True`` → unique ``firmware``-type component →
        first component in the container.
        """
        primaries = [c for c in container if c.is_primary]
        if primaries:
            return primaries[0]
        firmwares = [c for c in container if c.type == uSwidComponentType.FIRMWARE]
        if len(firmwares) == 1:
            return firmwares[0]
        for c in container:
            return c
        return None

    def save(self, container: uSwidContainer) -> bytes:
        root: Dict[str, Any] = {}
        root["SPDXID"] = "SPDXRef-DOCUMENT"
        root["spdxVersion"] = "SPDX-2.3"
        root["dataLicense"] = "CC0-1.0"
        root["documentNamespace"] = (
            self.document_namespace or f"urn:uuid:{str(uuid.uuid4())}"
        )
        root["name"] = self.document_name or "NOASSERTION"
        root["files"] = []  # required by SPDX

        # UEFI SBOM Guidelines §3.1.1.2: tz-aware UTC `Z` timestamp.
        created = self.timestamp or datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        creation_info: Dict[str, Any] = {
            "creators": ["Tool: uSWID"],
            "created": created,
        }

        # UEFI SBOM Guidelines §3.1.1.1: authors as Person/Organization with optional email.
        seen_creators: Set[str] = set()
        for component in container:
            for entity in component.entities:
                if uSwidEntityRole.TAG_CREATOR not in entity.roles:
                    continue
                line = _format_creator(entity)
                if line is None or line in seen_creators:
                    continue
                seen_creators.add(line)
                creation_info["creators"].append(line)

        # UEFI SBOM Guidelines §3.1.1.3 "Type" — surface sbom_type in a comment so SPDX
        # consumers can detect Source vs Build vs Binary SBOMs.
        if self.sbom_type:
            creation_info["comment"] = f"sbomType: {self.sbom_type}"

        root["creationInfo"] = creation_info

        # Build SPDXID assignments first so relationships can reference them.
        primary = self._resolve_primary(container)
        spdxid_by_component: Dict[int, str] = {}
        used_spdxids: Set[str] = set()
        for component in container:
            if not component.tag_id:
                continue
            base = _sanitize_spdxid(component.tag_id)
            candidate = base
            n = 2
            while candidate in used_spdxids:
                candidate = f"{base}-{n}"
                n += 1
            used_spdxids.add(candidate)
            spdxid_by_component[id(component)] = f"SPDXRef-{candidate}"

        packages: List[Dict[str, Any]] = []
        for component in container:
            packages.append(
                self._save_component(component, spdxid_by_component.get(id(component)))
            )
        if packages:
            root["packages"] = packages

        # UEFI SBOM Guidelines §3.1.9: relationships array.
        # DESCRIBES edge from the document to the primary component, plus
        # CONTAINS edges from each component to its uSwidLinkRel.COMPONENT children.
        relationships: List[Dict[str, str]] = []
        if primary is not None and id(primary) in spdxid_by_component:
            relationships.append(
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relatedSpdxElement": spdxid_by_component[id(primary)],
                    "relationshipType": "DESCRIBES",
                }
            )

        # Map internal tag_id → SPDXID so component-component edges resolve.
        tag_id_to_spdxid: Dict[str, str] = {}
        for component in container:
            sid = spdxid_by_component.get(id(component))
            if component.tag_id and sid:
                tag_id_to_spdxid[component.tag_id] = sid

        for component in container:
            src_sid = spdxid_by_component.get(id(component))
            if not src_sid:
                continue
            for link in component.links:
                if link.rel != uSwidLinkRel.COMPONENT or not link.href:
                    continue
                dst_sid = tag_id_to_spdxid.get(link.href)
                if not dst_sid:
                    continue
                relationships.append(
                    {
                        "spdxElementId": src_sid,
                        "relatedSpdxElement": dst_sid,
                        "relationshipType": "CONTAINS",
                    }
                )

        if relationships:
            root["relationships"] = relationships

        # Keep `documentDescribes` (SPDX 2.x legacy compatibility) pointing only at the
        # primary, so old consumers also see the correct root.
        if primary is not None and id(primary) in spdxid_by_component:
            root["documentDescribes"] = [spdxid_by_component[id(primary)]]

        return json.dumps(root, indent=2, ensure_ascii=False).encode()

    def _save_component(
        self, component: uSwidComponent, spdxid: Optional[str] = None
    ) -> Dict[str, Any]:
        root: Dict[str, Any] = {}

        root["SPDXID"] = spdxid or (
            f"SPDXRef-{_sanitize_spdxid(component.tag_id or 'NOASSERTION')}"
        )
        root["downloadLocation"] = "NOASSERTION"
        # UEFI SBOM Guidelines §3.1.2.1: PackageName is the supplier-defined component name.
        if component.software_name:
            root["name"] = component.software_name
        elif component.product:
            # historical fallback when software_name is unset
            root["name"] = component.product
        else:
            root["name"] = "NOASSERTION"
        if component.summary:
            root["summary"] = component.summary
        if component.software_version:
            root["versionInfo"] = component.software_version
        # SPDX 2.3 spec: filesAnalyzed default is true, which then requires
        # PackageVerificationCode. We're emitting a package-level SBOM without
        # per-file analysis, so declare filesAnalyzed=false to make this legal.
        root["filesAnalyzed"] = False

        # checksums (UEFI SBOM Guidelines §3.1.7)
        checksums: List[Dict[str, str]] = []
        if component.payloads:
            if component.payloads[0].name:
                root["packageFileName"] = component.payloads[0].name
            for ihash in component.payloads[0].hashes:
                checksum: Dict[str, str] = {}
                if ihash.value:
                    checksum["checksumValue"] = ihash.value
                if ihash.alg_id:
                    checksum["algorithm"] = _convert_hash_alg_id(ihash.alg_id)
                checksums.append(checksum)
        if checksums:
            root["checksums"] = checksums

        # UEFI SBOM Guidelines §3.1.2.2: supplier <- SOFTWARE_CREATOR (symmetric with CDX).
        # originator <- LICENSOR (upstream origin / heritage).
        supplier_entity: Optional[uSwidEntity] = None
        originator_entity: Optional[uSwidEntity] = None
        for entity in component.entities:
            if uSwidEntityRole.SOFTWARE_CREATOR in entity.roles and supplier_entity is None:
                supplier_entity = entity
            if uSwidEntityRole.LICENSOR in entity.roles and originator_entity is None:
                originator_entity = entity
        if supplier_entity is not None:
            line = _format_creator(supplier_entity)
            if line:
                root["supplier"] = line
        if originator_entity is not None:
            line = _format_creator(originator_entity)
            if line:
                root["originator"] = line

        # annotations
        annotations = []
        for evidence in component.evidences:
            annotation = {"annotationType": "OTHER", "comment": "NOASSERTION"}
            if evidence.date:
                annotation["annotationDate"] = evidence.date.strftime("%FT%TZ")
            if evidence.device_id:
                annotation["annotator"] = f"Tool: {evidence.device_id}"
            annotations.append(annotation)
        if annotations:
            root["annotations"] = annotations

        # UEFI SBOM Guidelines §3.1.10: emit BOTH licenseConcluded and licenseDeclared,
        # falling back to NOASSERTION when unknown.
        license_spdx_ids: List[str] = []
        for link in component.links:
            if link.rel != uSwidLinkRel.LICENSE:
                continue
            if link.spdx_id and link.spdx_id not in license_spdx_ids:
                license_spdx_ids.append(link.spdx_id)
        if license_spdx_ids:
            license_expr = " AND ".join(license_spdx_ids)
        else:
            license_expr = "NOASSERTION"
        root["licenseConcluded"] = license_expr
        root["licenseDeclared"] = license_expr

        # UEFI SBOM Guidelines §3.1.11: Copyright Holder
        root["copyrightText"] = component.copyright or "NOASSERTION"

        # UEFI SBOM Guidelines §3.1.8: round-trip purl/cpe via externalRefs so consumers
        # can recover the canonical identifier even though the SPDXID was sanitized.
        external_refs: List[Dict[str, str]] = []
        if component.purl:
            external_refs.append(
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": str(component.purl),
                }
            )
        elif component.tag_id and component.tag_id.startswith("pkg:"):
            external_refs.append(
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": component.tag_id,
                }
            )
        if component.cpe:
            external_refs.append(
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": component.cpe,
                }
            )
        if external_refs:
            root["externalRefs"] = external_refs

        return root
