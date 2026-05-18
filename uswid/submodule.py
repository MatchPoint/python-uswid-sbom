#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# (c) Copyright 2026 HP Development Company, L.P.
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=too-many-locals,too-many-branches,too-many-statements

"""Project-agnostic helpers for materialising Git submodules as SBOM components.

This module is intentionally **generic**: it knows about ``.gitmodules``,
``git describe`` and the resulting CPE/PURL versioning math, but it has no
knowledge of any specific project (EDK II, U-Boot, Linux, etc.). Project
glue (e.g. EDK II tag parsing and curated package lists) lives in
:mod:`uswid.edk2` so it can be split out into a separate plugin package
later without touching this file.

Two pieces of OSS reference data **do** live here because they are general
NVD/GitHub knowledge rather than project-specific:

* :data:`SUBMODULE_URL_ALIASES` — GitHub org renames and well-known mirror
  relationships (e.g. ``ARMmbed/mbedtls`` ↔ ``Mbed-TLS/mbedtls`` after the
  2024 rename). Any firmware tracking those projects benefits from these
  aliases regardless of toolchain.
* :data:`SUBMODULE_CPE_MAP` — NVD CPE dictionary entries for OSS components
  that ship as Git submodules in many embedded projects. Entries here were
  curated during EDK II work but are general OSS knowledge.

Both tables are mutable defaults that callers can override via the optional
keyword arguments on :func:`make_submodule_components`.
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import Dict, List, Optional, Tuple

from .component import uSwidComponent, uSwidComponentType
from .entity import uSwidEntity, uSwidEntityRole
from .link import uSwidLink, uSwidLinkRel
from .patch import uSwidPatch, uSwidPatchType


# ---------------------------------------------------------------------------
# OSS reference data (general; not project-specific)
# ---------------------------------------------------------------------------

#: GitHub org renames and well-known repo mirrors. Keys and values are stored
#: in :func:`canonicalize_vcs_url` form (lowercased, no trailing ``/``, no
#: ``.git`` suffix). Used when resolving an SBOM template's recorded VCS URL
#: against the URLs actually present in a project's ``.gitmodules`` tree.
SUBMODULE_URL_ALIASES: Dict[str, str] = {
    # Mbed TLS 2024 GitHub org rename (ARMmbed -> Mbed-TLS).
    "https://github.com/mbed-tls/mbedtls": "https://github.com/armmbed/mbedtls",
    # libfdt is shipped from devicetree-org/pylibfdt but originated in
    # dgibson/dtc; the two refer to the same upstream code.
    "https://github.com/dgibson/dtc": "https://github.com/devicetree-org/pylibfdt",
}

#: NVD CPE dictionary entries for OSS components commonly shipped as Git
#: submodules. Keyed by the GitHub ``owner/repo`` fragment (case-sensitive,
#: matching how the URL appears upstream). Value is ``(cpe_vendor,
#: cpe_product)``. Only projects with confirmed NVD entries are listed; the
#: rest stay PURL-only. Verified against the NVD CPE dictionary May 2026.
#:
#: ``*`` in the vendor slot is the CPE 2.3 wildcard, used when NVD has
#: attributed the same product to multiple vendors over time (e.g. mbed TLS
#: has been listed under ARM, trustedfirmware and mbed).
SUBMODULE_CPE_MAP: Dict[str, Tuple[str, str]] = {
    "openssl/openssl":  ("openssl",  "openssl"),
    "ARMmbed/mbedtls":  ("*",        "mbed_tls"),
    "akheron/jansson":  ("*",        "jansson"),
    "kkos/oniguruma":   ("*",        "oniguruma"),
    "google/brotli":    ("google",   "brotli"),
    "DMTF/libspdm":     ("dmtf",     "libspdm"),
}


# ---------------------------------------------------------------------------
# URL normalisation
# ---------------------------------------------------------------------------


def canonicalize_vcs_url(url: str) -> str:
    """Normalise *url* for case- and trailing-suffix-insensitive comparison.

    The normalisation rules match what SBOM templates typically record in
    ``externalReferences[type=vcs].url``:

    * lowercase
    * strip trailing ``/``
    * strip trailing ``.git``

    Anything else (scheme, host, path) is preserved.
    """
    if not url:
        return ""
    out = url.strip().rstrip("/")
    if out.lower().endswith(".git"):
        out = out[:-4]
    return out.lower()


def resolve_with_aliases(
    url: str,
    url_to_path: Dict[str, str],
    aliases: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    """Look up *url* in *url_to_path*; on miss, try the alias map.

    Returns the absolute path to the submodule directory, or ``None``.
    Both *url* and the alias table are :func:`canonicalize_vcs_url`-d before
    comparison; callers do not need to pre-normalise.
    """
    if not url:
        return None
    canon = canonicalize_vcs_url(url)
    if canon in url_to_path:
        return url_to_path[canon]
    if aliases is None:
        aliases = SUBMODULE_URL_ALIASES
    aliased = aliases.get(canon)
    if aliased:
        return url_to_path.get(canonicalize_vcs_url(aliased))
    return None


# ---------------------------------------------------------------------------
# .gitmodules parsing
# ---------------------------------------------------------------------------


_GITMODULES_NAME_RE = re.compile(r'^\s*\[submodule\s+"([^"]+)"\]\s*$')
_GITMODULES_KV_RE = re.compile(r"^\s*(\w+)\s*=\s*(\S+.*?)\s*$")


def parse_gitmodules_file(path: str) -> Dict[str, Dict[str, str]]:
    """Parse a single ``.gitmodules`` file.

    Returns ``{submodule_name: {key: value, ...}}``. Values typically include
    ``path`` and ``url``. Returns an empty dict on read errors so callers can
    treat "no submodules" and "unreadable" uniformly.
    """
    result: Dict[str, Dict[str, str]] = {}
    current: Optional[str] = None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = _GITMODULES_NAME_RE.match(line)
                if m:
                    current = m.group(1)
                    result[current] = {}
                    continue
                if not current:
                    continue
                m = _GITMODULES_KV_RE.match(line)
                if m:
                    result[current][m.group(1).strip()] = m.group(2).strip()
    except OSError:
        return {}
    return result


def walk_gitmodules(
    primary_dir: str,
    *,
    recursive: bool = True,
) -> Dict[str, str]:
    """Walk *primary_dir* and return ``{canonicalised_vcs_url: abs_path}``.

    When *recursive* is true (the default) the walk descends through every
    populated submodule and parses any nested ``.gitmodules`` it finds. This
    covers cases like an embedded OpenSSL pulling its own dependencies
    (``quiche``, ``gost-engine``, ``libprov``).

    The directory order is :func:`os.walk` top-down, so the *outermost*
    occurrence of any given URL wins on collisions — the top-level submodule
    is treated as the canonical instance even if the same URL appears again
    at a deeper nesting level.
    """
    result: Dict[str, str] = {}
    if not primary_dir or not os.path.isdir(primary_dir):
        return result

    def _emit(parent_dir: str, fields: Dict[str, str]) -> None:
        path = fields.get("path")
        url = fields.get("url")
        if not (path and url):
            return
        key = canonicalize_vcs_url(url)
        if not key:
            return
        abs_path = os.path.normpath(os.path.join(parent_dir, path))
        if key not in result:
            result[key] = abs_path

    def _ingest_one(gm_path: str) -> None:
        parent_dir = os.path.dirname(gm_path)
        for fields in parse_gitmodules_file(gm_path).values():
            _emit(parent_dir, fields)

    top_gm = os.path.join(primary_dir, ".gitmodules")
    if os.path.isfile(top_gm):
        _ingest_one(top_gm)

    if not recursive:
        return result

    for root, dirs, files in os.walk(primary_dir):
        if ".git" in dirs:
            dirs.remove(".git")
        if root == primary_dir:
            continue
        if ".gitmodules" in files:
            _ingest_one(os.path.join(root, ".gitmodules"))

    return result


# ---------------------------------------------------------------------------
# git describe parsing
# ---------------------------------------------------------------------------


_GIT_DESCRIBE_SUFFIX_RE = re.compile(r"-(\d+)-g([0-9a-f]+)$")
_PROJECT_SUFFIX_RE = re.compile(r"[+][a-zA-Z0-9_-]+$")
_BARE_COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)


def normalize_submodule_version(
    raw: str,
) -> Tuple[str, int, Optional[str], Optional[str]]:
    """Normalise a ``git describe`` string for NVD/CPE consumption.

    Returns ``(clean_version, patch_count, commit_sha, base_tag)``:

    * ``clean_version`` — semantic version suitable for a CPE lookup
      (``v``/``V`` and project-name prefixes stripped, ``+project`` suffixes
      removed, git-describe commit suffix removed).
    * ``patch_count`` — number of commits applied on top of the last tag.
    * ``commit_sha`` — short commit hash when past-tag commits exist, or the
      bare hash itself when no tag is present, else ``None``.
    * ``base_tag`` — the raw tag string as it appears in the git repo (used
      to scope a ``git log <base_tag>..HEAD`` CVE scan); ``None`` for bare
      commits.

    Worked examples::

        "openssl-3.5.1"            -> ("3.5.1",  0,   None,      "openssl-3.5.1")
        "v3.6.5"                   -> ("3.6.5",  0,   None,      "v3.6.5")
        "v1.2.0-1-ge230f47"        -> ("1.2.0",  1,   "e230f47", "v1.2.0")
        "release-1.11.0-238-g86a"  -> ("1.11.0", 238, "86a",     "release-1.11.0")
        "cmocka-1.1.5-23-g1cc9cde" -> ("1.1.5",  23,  "1cc9cde", "cmocka-1.1.5")
        "v1.1+edk2"                -> ("1.1",    0,   None,      "v1.1")
        "V184"                     -> ("184",    0,   None,      "V184")
        "3.7.0"                    -> ("3.7.0",  0,   None,      "3.7.0")
        "83d4e1e"                  -> ("0.0.0",  0,   "83d4e1e", None)
    """
    raw = (raw or "").strip()
    if _BARE_COMMIT_RE.match(raw):
        return "0.0.0", 0, raw, None

    patch_count = 0
    commit_sha: Optional[str] = None
    m = _GIT_DESCRIBE_SUFFIX_RE.search(raw)
    if m:
        patch_count = int(m.group(1))
        commit_sha = m.group(2)
        raw = raw[: m.start()]

    raw = _PROJECT_SUFFIX_RE.sub("", raw)
    base_tag: Optional[str] = raw or None

    vm = re.search(r"(\d[\d.]*)", raw)
    if not vm:
        return "0.0.0", patch_count, commit_sha, base_tag

    clean_version = vm.group(1).rstrip(".")
    return clean_version, patch_count, commit_sha, base_tag


def resolve_submodule_vcs(
    submodule_dir: str,
) -> Tuple[str, int, Optional[str], Optional[str]]:
    """Run ``git describe --tags --always`` and normalise the result.

    Falls back to the short HEAD sha when ``describe`` fails (typical for a
    bare-commit submodule pin with no reachable tags). Returns the same
    four-tuple as :func:`normalize_submodule_version`.
    """
    if not submodule_dir or not os.path.isdir(submodule_dir):
        return "NOASSERTION", 0, None, None
    try:
        raw_version = _run_git(
            ["describe", "--tags", "--always"], cwd=submodule_dir
        )
    except subprocess.CalledProcessError:
        try:
            raw_version = _run_git(["rev-parse", "HEAD"], cwd=submodule_dir)[:12]
        except subprocess.CalledProcessError:
            return "NOASSERTION", 0, None, None
    return normalize_submodule_version(raw_version)


def patches_for_commits_since_tag(
    cwd: str, base_tag: str, vcs_url: str
) -> List[uSwidPatch]:
    """Return one :class:`uSwidPatch` per commit in ``base_tag..HEAD``.

    Each patch carries the commit subject as ``description`` and a commit
    URL (when *vcs_url* is an ``http(s)`` URL). Patches mentioning a CVE
    identifier are typed :attr:`uSwidPatchType.SECURITY`; otherwise
    :attr:`uSwidPatchType.BACKPORT`.
    """
    _sep = "---USWID_COMMIT_END---"
    try:
        raw_log = _run_git(
            [
                "log",
                f"{base_tag}..HEAD",
                "--no-merges",
                "--reverse",
                f"--format=%H%x09%s%n%b%n{_sep}",
            ],
            cwd=cwd,
        )
    except subprocess.CalledProcessError:
        return []

    patches: List[uSwidPatch] = []
    current_sha = current_subject = ""
    current_body: List[str] = []

    def _flush() -> None:
        nonlocal current_sha, current_subject, current_body
        if not current_sha:
            return
        full_text = current_subject + " " + " ".join(current_body)
        cves = sorted(set(_CVE_RE.findall(full_text)))
        commit_url = (
            f"{vcs_url.rstrip('/')}/commit/{current_sha}" if vcs_url else None
        )
        desc = (current_subject or "").strip()
        if len(desc) > 500:
            desc = desc[:497] + "..."
        ptype = uSwidPatchType.SECURITY if cves else uSwidPatchType.BACKPORT
        patches.append(
            uSwidPatch(
                type=ptype,
                url=commit_url,
                description=desc or None,
                references=cves,
            )
        )
        current_sha = current_subject = ""
        current_body = []

    for line in raw_log.splitlines():
        if line == _sep:
            _flush()
            continue
        if "\t" in line and not current_sha:
            parts = line.split("\t", 1)
            current_sha = parts[0]
            current_subject = parts[1] if len(parts) > 1 else ""
        else:
            current_body.append(line)
    _flush()
    return patches


# ---------------------------------------------------------------------------
# High-level component assembler
# ---------------------------------------------------------------------------


_GITHUB_OWNER_REPO_RE = re.compile(
    r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/.]+)"
)


def make_submodule_components(
    primary_dir: str,
    parent: uSwidComponent,
    *,
    recursive: bool = True,
    cpe_map: Optional[Dict[str, Tuple[str, str]]] = None,
) -> Tuple[List[uSwidComponent], Dict[str, str]]:
    """Materialise *primary_dir*'s ``.gitmodules`` tree as SBOM components.

    For every populated submodule (top-level or nested when *recursive*) this
    function builds a :class:`uSwidComponent` with:

    * a stable ``tag_id`` derived from the submodule's GitHub
      ``owner/repo`` slug and HEAD sha (or the relative submodule path if
      the URL is not a GitHub URL),
    * ``software_name`` taken from the last path segment,
    * ``software_version`` normalised via :func:`resolve_submodule_vcs`,
    * an optional CPE pulled from *cpe_map* (falls back to the module-level
      :data:`SUBMODULE_CPE_MAP`) keyed by GitHub ``owner/repo``,
    * a supplier entity (GitHub owner, or ``NOASSERTION``),
    * one ``pedigree.patches[]`` entry per commit applied past the last tag,
    * a ``SEE_ALSO`` link to the upstream URL.

    *parent* is mutated in-place: each emitted submodule receives a
    ``COMPONENT`` link reference from the parent, materialising the
    Guidelines §3.1.9 dependency relationship.

    Returns ``(components, abs_path_to_tag_id)``. The second mapping is what
    callers use to wire downstream components (e.g. INF wrappers in an EDK II
    build) to their incorporated submodules via CycloneDX ``dependsOn``.
    """
    if cpe_map is None:
        cpe_map = SUBMODULE_CPE_MAP

    # walk_gitmodules() returns the canonical {url: path} map used elsewhere,
    # but here we also need the original URL string (for SEE_ALSO links and
    # owner/repo extraction), so re-parse the records.
    submodule_records: List[Tuple[str, str, str]] = []  # (parent_dir, path, url)
    if os.path.isdir(primary_dir):
        top_gm = os.path.join(primary_dir, ".gitmodules")
        if os.path.isfile(top_gm):
            for fields in parse_gitmodules_file(top_gm).values():
                if fields.get("path") and fields.get("url"):
                    submodule_records.append(
                        (primary_dir, fields["path"], fields["url"])
                    )
        if recursive:
            for root, dirs, files in os.walk(primary_dir):
                if ".git" in dirs:
                    dirs.remove(".git")
                if root == primary_dir or ".gitmodules" not in files:
                    continue
                for fields in parse_gitmodules_file(
                    os.path.join(root, ".gitmodules")
                ).values():
                    if fields.get("path") and fields.get("url"):
                        submodule_records.append(
                            (root, fields["path"], fields["url"])
                        )

    components: List[uSwidComponent] = []
    dir_to_tag: Dict[str, str] = {}
    seen_canonical: set = set()

    for parent_dir, rel_path, url in submodule_records:
        canon = canonicalize_vcs_url(url)
        if canon in seen_canonical:
            continue  # first-write-wins, matching walk_gitmodules
        seen_canonical.add(canon)

        sub_dir = os.path.normpath(os.path.join(parent_dir, rel_path))
        if not os.path.isdir(sub_dir):
            continue
        try:
            sub_sha = _run_git(["rev-parse", "HEAD"], cwd=sub_dir)
        except subprocess.CalledProcessError:
            continue

        clean_version, patch_count, commit_sha, base_tag = resolve_submodule_vcs(
            sub_dir
        )

        m = _GITHUB_OWNER_REPO_RE.search(url)
        github_slug: Optional[str] = None
        if m:
            github_slug = f"{m.group('owner')}/{m.group('repo')}"
            tag_id = f"pkg:github/{github_slug}@{sub_sha}"
            supplier_name = m.group("owner")
        else:
            tag_id = f"pkg:submodule/{rel_path}@{sub_sha}"
            supplier_name = "NOASSERTION"

        comp = uSwidComponent()
        comp.tag_id = tag_id
        comp.software_name = os.path.basename(rel_path)
        comp.software_version = clean_version
        comp.type = uSwidComponentType.LIBRARY

        if github_slug:
            cpe_entry = cpe_map.get(github_slug)
            if cpe_entry:
                cpe_vendor, cpe_product = cpe_entry
                comp.cpe = (
                    f"cpe:2.3:a:{cpe_vendor}:{cpe_product}"
                    f":{clean_version}:*:*:*:*:*:*:*"
                )

        comp.add_entity(
            uSwidEntity(
                name=supplier_name, roles=[uSwidEntityRole.SOFTWARE_CREATOR]
            )
        )

        if patch_count > 0 and base_tag:
            vcs_url = url if url.startswith("http") else ""
            for patch in patches_for_commits_since_tag(sub_dir, base_tag, vcs_url):
                comp.add_patch(patch)
        elif commit_sha and base_tag is None:
            comp.add_patch(
                uSwidPatch(
                    type=uSwidPatchType.CHERRY_PICK,
                    description=(
                        f"No release tag found; pinned at commit {commit_sha}"
                    ),
                )
            )

        if url:
            comp.add_link(uSwidLink(rel=uSwidLinkRel.SEE_ALSO, href=url))
        parent.add_link(uSwidLink(rel=uSwidLinkRel.COMPONENT, href=comp.tag_id))

        dir_to_tag[sub_dir] = tag_id
        components.append(comp)

    return components, dir_to_tag


# ---------------------------------------------------------------------------
# Subprocess wrapper (private)
# ---------------------------------------------------------------------------


def _run_git(args: List[str], cwd: Optional[str] = None) -> str:
    """Run ``git <args>`` and return stripped, utf-8-decoded stdout."""
    return (
        subprocess.check_output(
            ["git", *args], cwd=cwd, stderr=subprocess.STDOUT
        )
        .decode("utf-8", errors="replace")
        .strip()
    )
