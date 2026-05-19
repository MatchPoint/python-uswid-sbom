#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 HP Development Company, L.P.
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=wrong-import-position,too-many-locals,too-many-branches,too-many-statements

"""End-to-end EDK2 SBOM integration test (SBOM4EDK2 parity).

This test exercises ``uswid``'s CycloneDX writer against a real EDK II source tree.
SBOM4EDK2 now drives assembly via ``uswid --load … --primary-dir …`` (see
``uswid/cli.py``); this module still contains the in-process validation path
(parse each ``.inf`` with :class:`uswid.format_inf.uSwidFormatInf`, fold in
:mod:`uswid.submodule` materialisation, merge into one ``edk2.cdx.json``) plus
CLI tests ``test_primary_dir_cli_end_to_end`` and
``test_primary_dir_resolves_parent_vcs_placeholders``, which shell out to
``uswid`` and assert submodule placeholders, primary ``metadata.component``
version/CPE (including ``tests/edk2/sbom.template.cdx.json`` with ``@VCS_*@``),
and a wired ``dependencies[]`` graph. Output is checked against the UEFI SBOM
Guidelines (CISA Level 1) shape.

Gating and configuration are intentionally environment-variable driven so the
test stays compatible with both the project's primary ``unittest`` workflow and
the existing ``pytest`` discovery used in CI (``pytest`` happily runs
``unittest.TestCase`` subclasses). The full list of recognised env vars:

* ``USWID_EDK2_INTEGRATION=1`` — master gate. Without it, the test self-skips.
* ``EDK2_DIR`` — path to a local EDK II checkout. If present and the directory
  contains ``MdePkg/``, the test uses it as-is (no clone). When the checkout's
  submodules are already populated, the test auto-promotes to *full* mode.
* ``USWID_EDK2_REF`` — git ref to clone when ``EDK2_DIR`` is unset
  (default: ``edk2-stable202411``, matching ``tests/edk2/sbom.cdx.json``).
  Ignored when ``EDK2_DIR`` is set; the test calls ``git describe`` to discover
  the actual ref and rewrites the parent CDX's version/CPE/PURL in memory.
* ``USWID_EDK2_FULL=1`` — switch to *full* mode (recurse submodules, walk every
  ``.inf``). Auto-promoted when ``EDK2_DIR`` points to a populated checkout.
* ``USWID_EDK2_MAX_INFS`` — cap on number of ``.inf`` files to process.
  Default 200 in light mode, unlimited in full mode.
* ``USWID_EDK2_SBOM_TYPE`` — override the CycloneDX ``lifecycles[].phase``
  derivation. Defaults to ``source`` (a source SBOM is the appropriate type for
  a tree-walking generator).

Primary run command (mirrors ``Makefile``'s ``setup`` target — sidesteps PEP 668
on Debian/Ubuntu 23.10+ by using ``./env`` instead of system pip)::

    make setup
    USWID_EDK2_INTEGRATION=1 ./env/bin/python -m unittest \\
        uswid.test_edk2_integration -v

Fast path using an existing local clone with submodules populated::

    make setup
    USWID_EDK2_INTEGRATION=1 EDK2_DIR=/mnt/c/temp/edk2/test/SBOM4EDK2/edk2 \\
        ./env/bin/python -m unittest uswid.test_edk2_integration -v
"""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from typing import Dict, List, Optional, Tuple

from .component import uSwidComponent, uSwidComponentType
from .container import uSwidContainer
from .edk2 import (
    EDK2_FULL_MODE_SUBMODULE_HINTS as _FULL_MODE_SUBMODULE_HINTS,
    EDK2_LIGHT_MODE_EXCLUDE as _LIGHT_MODE_EXCLUDE,
    EDK2_LIGHT_MODE_PACKAGES as _LIGHT_MODE_PACKAGES,
    describe_edk2_version,
)
from .entity import uSwidEntity, uSwidEntityRole
from .errors import NotSupportedError
from .format_cyclonedx import uSwidFormatCycloneDX
from .format_inf import uSwidFormatInf
from .link import uSwidLink, uSwidLinkRel
from .purl import uSwidPurl
from .submodule import (
    make_submodule_components,
    parse_gitmodules_file,
)

_REPO_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
_DEFAULT_REF = "edk2-stable202411"
_PARENT_FIXTURE = os.path.join(_REPO_ROOT, "tests", "edk2", "sbom.cdx.json")
_PARENT_TEMPLATE = os.path.join(_REPO_ROOT, "tests", "edk2", "sbom.template.cdx.json")
_CACHE_ROOT = os.path.join(_REPO_ROOT, "tests", "_edk2_cache")


def _have_git() -> bool:
    return shutil.which("git") is not None


def _have_network(host: str = "github.com", timeout: float = 3.0) -> bool:
    """Quick TCP probe to avoid hangs when the test is run offline."""
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(host)
        return True
    except OSError:
        return False


def _run_git(args: List[str], cwd: Optional[str] = None) -> str:
    return subprocess.check_output(
        ["git", *args], cwd=cwd, stderr=subprocess.STDOUT
    ).decode("utf-8", errors="replace").strip()


def _looks_like_edk2_tree(path: str) -> bool:
    if not path or not os.path.isdir(path):
        return False
    return os.path.isdir(os.path.join(path, "MdePkg"))


def _submodules_populated(edk2_dir: str) -> bool:
    """Heuristic: every submodule path in .gitmodules resolves to a non-empty dir."""
    gitmodules = os.path.join(edk2_dir, ".gitmodules")
    if not os.path.isfile(gitmodules):
        return False
    fields_by_name = parse_gitmodules_file(gitmodules)
    if not fields_by_name:
        return False
    for fields in fields_by_name.values():
        relpath = fields.get("path")
        if not relpath:
            continue
        full = os.path.join(edk2_dir, relpath)
        if not os.path.isdir(full):
            return False
        try:
            if not os.listdir(full):
                return False
        except OSError:
            return False
    return True


def _clone_edk2(ref: str, dest: str, full_mode: bool) -> None:
    """Clone tianocore/edk2 at ``ref`` into ``dest``.

    Light mode skips submodules and uses ``blob:none`` to keep the clone small.
    Full mode recurses submodules shallowly so source-bearing modules resolve.
    """
    if os.path.isdir(dest) and _looks_like_edk2_tree(dest):
        return
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    cmd = [
        "git",
        "clone",
        "--depth",
        "1",
        "--branch",
        ref,
        "--no-tags",
        "https://github.com/tianocore/edk2.git",
        dest,
    ]
    if full_mode:
        cmd.insert(-1, "--recurse-submodules")
        cmd.insert(-1, "--shallow-submodules")
    else:
        cmd.insert(-1, "--filter=blob:none")
    subprocess.check_call(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def _iter_inf_files(
    edk2_dir: str, mode: str, limit: Optional[int]
) -> List[str]:
    """Enumerate ``.inf`` files to process, applying mode-specific scope rules."""
    matches: List[str] = []
    if mode == "light":
        roots = [os.path.join(edk2_dir, pkg) for pkg in _LIGHT_MODE_PACKAGES]
    else:
        roots = [edk2_dir]
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, fns in os.walk(root):
            if mode == "light":
                rel = os.path.relpath(dirpath, edk2_dir).replace(os.sep, "/")
                if any(rel.startswith(prefix) for prefix in _LIGHT_MODE_EXCLUDE):
                    continue
            for fn in fns:
                if fn.endswith(".inf"):
                    matches.append(os.path.join(dirpath, fn))
                    if limit is not None and len(matches) >= limit:
                        return matches
    return matches


def _override_parent_for_ref(
    parent: uSwidComponent, purl_version: str, cpe_version: str, version_label: str
) -> None:
    """Rewrite the loaded parent so its purl/cpe/version match the actual EDK2 ref."""
    if parent.purl:
        parent.purl.version = purl_version
    else:
        new_purl = uSwidPurl(f"pkg:github/tianocore/edk2@{purl_version}")
        parent.purl = new_purl
    new_tag_id = f"pkg:github/tianocore/edk2@{purl_version}"
    parent.tag_id = new_tag_id
    parent.cpe = f"cpe:2.3:a:tianocore:edk2:{cpe_version}:*:*:*:*:*:*:*"
    parent.software_version = version_label


def _load_parent_container() -> uSwidContainer:
    fmt = uSwidFormatCycloneDX()
    with open(_PARENT_FIXTURE, "rb") as f:
        return fmt.load(f.read())


def _assert_primary_metadata_resolved(
    test_case: unittest.TestCase,
    primary: dict,
    edk2_dir: str,
) -> None:
    """Assert CycloneDX ``metadata.component`` reflects the EDK II checkout."""
    _, _, expected_cpe_ver = describe_edk2_version(edk2_dir)
    test_case.assertEqual(primary.get("name"), "EDK II")
    test_case.assertNotEqual(
        primary.get("version"),
        "NOASSERTION",
        "primary version must come from the EDK II checkout git describe",
    )
    cpe = primary.get("cpe") or ""
    test_case.assertNotIn("NOASSERTION", cpe)
    test_case.assertIn(
        f":edk2:{expected_cpe_ver}:",
        cpe,
        f"primary CPE must include YYYYMM {expected_cpe_ver!r} from checkout",
    )
    test_case.assertNotIn("@VCS_", json.dumps(primary))


def _build_per_inf_container(
    parent_template: uSwidComponent, inf_path: str
) -> Tuple[Optional[str], Optional[uSwidContainer], Optional[Exception]]:
    """Worker: parse one .inf and return a container with (parent_copy, inf_component)."""
    try:
        fmt_inf = uSwidFormatInf()
        with open(inf_path, "rb") as f:
            blob = f.read()
        inf_container = fmt_inf.load(blob, path=inf_path)
    except FileNotFoundError as e:
        # this can happen for an inf that references missing submodule sources
        return inf_path, None, e
    except NotSupportedError as e:
        return inf_path, None, e

    parent_copy = deepcopy(parent_template)
    per_inf = uSwidContainer([parent_copy])
    for component in inf_container:
        fmt_inf.incorporate(per_inf, component)
        per_inf.append(component)
    return inf_path, per_inf, None


# ---------------------------------------------------------------------------
# INF file parsing helpers for submodule source-reference detection.
# (Generic submodule versioning + CPE handling moved to uswid.submodule;
# EDK II tag parsing moved to uswid.edk2 — see imports at the top of this
# file. The remaining helper below is .inf-format-specific and is kept
# alongside the integration test for now; future work may promote it to
# uswid.edk2 as part of a larger EDK II plugin split.)
# ---------------------------------------------------------------------------

# Matches "DEFINE VAR = value" lines inside an [Defines] section.
_INF_DEFINE_RE = re.compile(r"^\s*DEFINE\s+(\w+)\s*=\s*(\S.*?)\s*$", re.IGNORECASE)
# Matches section headers such as [Defines], [Sources], [Sources.X64].
_INF_SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")


def _parse_inf_submodule_refs(
    inf_path: str,
    submodule_dir_to_tag: Dict[str, str],
) -> List[str]:
    """Return tag_ids of submodule components whose source tree is directly
    incorporated by *inf_path*.

    Two signals are used:

    1. ``DEFINE VAR = path`` entries in the ``[Defines]`` section — the resolved
       first path segment is checked against *submodule_dir_to_tag*.
    2. The leading path segment of every ``[Sources*]`` entry (after expanding
       ``$(VAR)`` references) — checked the same way.

    This correctly detects all current EDK2 patterns:

    * ``DEFINE OPENSSL_PATH = openssl`` + ``$(OPENSSL_PATH)/crypto/...`` (OpensslLib)
    * Bare ``mbedtls/library/aes.c`` with no DEFINE (MbedTlsLib)
    * ``cmocka/src/cmocka.c`` (CmockaLib)
    * ``DEFINE FDT_LIB_PATH = libfdt/libfdt`` (BaseFdtLib)
    """
    inf_dir = os.path.dirname(os.path.realpath(inf_path))
    defines: Dict[str, str] = {}
    in_defines = False
    in_sources = False
    found: Set[str] = set()

    def _first_abs(path_str: str) -> Optional[str]:
        """Expand $(VAR) and return the absolute path of the first segment."""
        for var, val in defines.items():
            path_str = path_str.replace(f"$({var})", val)
        if "$(" in path_str:
            return None  # still-unexpanded reference — skip
        first_seg = path_str.replace("\\", "/").split("/")[0]
        if not first_seg:
            return None
        return os.path.normpath(os.path.join(inf_dir, first_seg))

    try:
        with open(inf_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line_s = line.strip()
                if not line_s or line_s.startswith("#"):
                    continue
                sec_m = _INF_SECTION_RE.match(line_s)
                if sec_m:
                    sec = sec_m.group(1).split(".")[0].strip().upper()
                    in_defines = sec == "DEFINES"
                    in_sources = sec.startswith("SOURCES")
                    continue
                if in_defines:
                    def_m = _INF_DEFINE_RE.match(line)
                    if def_m:
                        defines[def_m.group(1)] = def_m.group(2)
                elif in_sources:
                    src = line_s.split("|")[0].strip()  # drop conditional build flag
                    abs_first = _first_abs(src)
                    if abs_first and abs_first in submodule_dir_to_tag:
                        found.add(submodule_dir_to_tag[abs_first])
    except OSError:
        return []

    # Also probe DEFINE values directly: catches the OPENSSL_PATH pattern even
    # for .inf files where the [Sources] section is absent or skipped early.
    for val in defines.values():
        if "$(" in val:
            continue
        abs_first = _first_abs(val)
        if abs_first and abs_first in submodule_dir_to_tag:
            found.add(submodule_dir_to_tag[abs_first])

    return list(found)


class TestEdk2IntegrationSbom(unittest.TestCase):
    """Replicates the SBOM4EDK2 pipeline as a uSWID end-to-end test."""

    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        if os.environ.get("USWID_EDK2_INTEGRATION") != "1":
            raise unittest.SkipTest(
                "Set USWID_EDK2_INTEGRATION=1 to run the EDK2 integration test"
            )
        if not _have_git():
            raise unittest.SkipTest("git is not on PATH; cannot run EDK2 integration")

        edk2_dir = os.environ.get("EDK2_DIR") or ""
        explicit_full = os.environ.get("USWID_EDK2_FULL") == "1"

        if edk2_dir and _looks_like_edk2_tree(edk2_dir):
            cls.edk2_dir = os.path.realpath(edk2_dir)
            try:
                version_label, purl_v, cpe_v = describe_edk2_version(cls.edk2_dir)
            except subprocess.CalledProcessError:
                version_label, purl_v, cpe_v = "NOASSERTION", "NOASSERTION", "NOASSERTION"
            cls.version_label = version_label
            cls.purl_version = purl_v
            cls.cpe_version = cpe_v
            # auto-promote when the local checkout already has submodules populated
            cls.mode = "full" if (explicit_full or _submodules_populated(cls.edk2_dir)) else "light"
            cls.from_clone = False
        else:
            if edk2_dir:
                print(
                    f"EDK2_DIR={edk2_dir!r} does not look like an EDK II tree "
                    "(missing MdePkg/), falling back to clone",
                    file=sys.stderr,
                )
            ref = os.environ.get("USWID_EDK2_REF") or _DEFAULT_REF
            if not _have_network():
                raise unittest.SkipTest(
                    "github.com is not reachable; cannot clone EDK II"
                )
            cls.mode = "full" if explicit_full else "light"
            dest = os.path.join(_CACHE_ROOT, ref)
            try:
                _clone_edk2(ref, dest, full_mode=(cls.mode == "full"))
            except subprocess.CalledProcessError as e:
                raise unittest.SkipTest(
                    f"git clone of EDK II failed: {e}; skipping"
                ) from e
            cls.edk2_dir = os.path.realpath(dest)
            cls.version_label = ref
            m = re.search(r"(\d+)$", ref)
            short = m.group(1) if m else ref
            cls.purl_version = short
            cls.cpe_version = short
            cls.from_clone = True

        cls.cache_dir = os.path.join(_CACHE_ROOT, cls.version_label)
        os.makedirs(cls.cache_dir, exist_ok=True)
        cls.per_inf_dir = os.path.join(cls.cache_dir, "_cdx_per_inf")
        os.makedirs(cls.per_inf_dir, exist_ok=True)

    def _generate_and_merge(self) -> Tuple[uSwidContainer, Dict[str, dict]]:
        """Run the per-inf parse → save → merge pipeline. Returns the merged
        container and the parsed CDX JSON of the final merged file."""
        # cap selection per mode
        if self.mode == "light":
            default_cap: Optional[int] = 200
        else:
            default_cap = None
        cap_env = os.environ.get("USWID_EDK2_MAX_INFS")
        if cap_env:
            try:
                cap = int(cap_env)
            except ValueError as e:
                self.fail(f"USWID_EDK2_MAX_INFS={cap_env!r} is not an integer: {e}")
        else:
            cap = default_cap

        # load + rewrite the parent CDX for this ref
        parent_container = _load_parent_container()
        self.assertGreaterEqual(len(parent_container), 1)
        # the parent has only one component in the fixture; treat it as primary
        parent = next(iter(parent_container))
        parent.is_primary = True
        _override_parent_for_ref(
            parent, self.purl_version, self.cpe_version, self.version_label
        )

        # gather inf files
        inf_paths = _iter_inf_files(self.edk2_dir, self.mode, cap)
        self.assertGreater(
            len(inf_paths),
            0,
            f"no .inf files found under {self.edk2_dir} in {self.mode} mode",
        )
        # per-inf save+load parallel pipeline
        cdx_fmt = uSwidFormatCycloneDX()
        cdx_fmt.sbom_type = os.environ.get("USWID_EDK2_SBOM_TYPE") or "source"
        per_inf_blobs: Dict[str, bytes] = {}
        # Maps each successfully parsed inf_path to the non-primary component's
        # tag_id so we can wire submodule dependsOn links after the merge.
        inf_to_tag: Dict[str, Optional[str]] = {}
        skip_count = 0
        with ThreadPoolExecutor(max_workers=12) as pool:
            futures = [
                pool.submit(_build_per_inf_container, parent, inf_path)
                for inf_path in inf_paths
            ]
            for fut in futures:
                inf_path, per_inf, err = fut.result()
                if per_inf is None:
                    skip_count += 1
                    if isinstance(err, (FileNotFoundError, NotSupportedError)):
                        # tolerate missing submodule sources and .inf files that
                        # lack a BASE_NAME (e.g. platform-specific stub .inf);
                        # report at the end via the skip-rate assertion
                        continue
                    # any other error type indicates a code-level bug
                    self.fail(f"{inf_path}: unexpected error {err!r}")
                rel = os.path.relpath(inf_path, self.edk2_dir).replace(os.sep, "/")
                out_path = os.path.join(self.per_inf_dir, rel + ".cdx.json")
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                blob = cdx_fmt.save(per_inf)
                with open(out_path, "wb") as f:
                    f.write(blob)
                per_inf_blobs[inf_path] = blob
                # Record the INF component's post-roundtrip identity for later
                # dependency wiring.  After the CDX save/load cycle the
                # component's tag_id becomes its bom-ref, which _bom_ref_for()
                # resolves to the CPE when one is present (§3.1.8), otherwise
                # the PURL.  Store that same value so merged.get_by_id() finds
                # it after the merge step.
                for comp in per_inf:
                    if not comp.is_primary:
                        saved_id = comp.cpe if comp.cpe else comp.tag_id
                        if saved_id:
                            inf_to_tag[inf_path] = saved_id
                        break

        attempted = len(inf_paths)
        if attempted > 0:
            self.assertLess(
                skip_count / attempted,
                0.05,
                f"too many .inf parse failures ({skip_count}/{attempted}); "
                "submodule coverage may be misconfigured",
            )

        # merge: re-load each per-inf CDX and merge into one container
        merged = uSwidContainer()
        merge_fmt = uSwidFormatCycloneDX()
        for blob in per_inf_blobs.values():
            loaded = merge_fmt.load(blob)
            for component in loaded:
                existing = merged.get_by_id(component.tag_id) if component.tag_id else None
                if existing:
                    existing.merge(component)
                else:
                    merged.append(component)

        # ensure the primary survives the merge
        primaries = [c for c in merged if c.is_primary]
        if not primaries:
            firmware = [c for c in merged if c.type == uSwidComponentType.FIRMWARE]
            self.assertEqual(
                len(firmware),
                1,
                "expected exactly one firmware component to act as primary",
            )
            firmware[0].is_primary = True

        # full mode: add synthetic submodule components per UEFI §2.3.1
        submodule_dir_to_tag: Dict[str, str] = {}
        if self.mode == "full":
            primary = next(c for c in merged if c.is_primary)
            sub_comps, submodule_dir_to_tag = make_submodule_components(
                self.edk2_dir, primary
            )
            for sub in sub_comps:
                if not merged.get_by_id(sub.tag_id):
                    merged.append(sub)

            # Wire INF wrapper components to the submodule(s) whose source tree
            # they directly incorporate, based on [Defines]/[Sources] analysis.
            # This produces accurate dependsOn edges in the CycloneDX output.
            if submodule_dir_to_tag:
                for inf_path, comp_tag_id in inf_to_tag.items():
                    if not comp_tag_id:
                        continue
                    sub_tag_ids = _parse_inf_submodule_refs(
                        inf_path, submodule_dir_to_tag
                    )
                    if not sub_tag_ids:
                        continue
                    comp = merged.get_by_id(comp_tag_id)
                    if not comp:
                        continue
                    for sub_tag_id in sub_tag_ids:
                        comp.add_link(
                            uSwidLink(rel=uSwidLinkRel.COMPONENT, href=sub_tag_id)
                        )

        # save final merged SBOM
        final_fmt = uSwidFormatCycloneDX()
        final_fmt.sbom_type = os.environ.get("USWID_EDK2_SBOM_TYPE") or "source"
        out_path = os.path.join(self.cache_dir, "edk2.cdx.json")
        merged_blob = final_fmt.save(merged)
        with open(out_path, "wb") as f:
            f.write(merged_blob)
        merged_json = json.loads(merged_blob)
        return merged, merged_json

    def test_edk2_per_inf_generate_and_merge(self) -> None:
        """Generate a per-inf SBOM, merge, and assert Level-1 conformance."""
        merged, data = self._generate_and_merge()

        # Document-level (UEFI SBOM Guidelines §3.1.1)
        self.assertEqual(data["bomFormat"], "CycloneDX")
        self.assertEqual(data["specVersion"], "1.6")
        self.assertRegex(
            data["metadata"]["timestamp"],
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
        )
        expected_phase = {
            "source": "pre-build",
            "build": "build",
            "binary": "post-build",
        }.get(os.environ.get("USWID_EDK2_SBOM_TYPE") or "source", "pre-build")
        self.assertEqual(data["metadata"]["lifecycles"][0]["phase"], expected_phase)
        self.assertIn("component", data["metadata"])
        primary = data["metadata"]["component"]
        self.assertEqual(primary["name"], "EDK II")
        # bom-ref is CPE-style per §3.1.8
        self.assertTrue(
            primary["bom-ref"].startswith("cpe:2.3:a:tianocore:edk2:"),
            f"bom-ref={primary['bom-ref']!r} should start with cpe:2.3:a:tianocore:edk2:",
        )
        self.assertIn("authors", data["metadata"])
        self.assertTrue(data["metadata"]["authors"])

        # Per-component (§3.1.2.1, §3.1.2.2, §3.1.7, §3.1.8, §3.1.10)
        components = data.get("components", [])
        self.assertGreater(len(components), 0)
        # Only inf-derived components are expected to carry a CPE (the synthetic
        # submodule layer added in full mode intentionally has no known CPE).
        inf_derived = [
            c for c in components if "tianocore:edk2" in (c.get("cpe") or c.get("bom-ref") or "")
        ]
        cpe_count = 0
        bsd_count = 0
        for comp in components:
            self.assertTrue(comp.get("name"))
            self.assertTrue(comp.get("version"))
            self.assertTrue(comp.get("bom-ref"))
            if comp.get("cpe"):
                cpe_count += 1
            for lic in comp.get("licenses", []):
                if lic.get("license", {}).get("id") == "BSD-2-Clause-Patent":
                    bsd_count += 1
                    break
        # Inf-derived components should all pick up a CPE from incorporate(). We assert
        # 90% rather than 100% to leave headroom for inf files whose Defines block
        # omits the BASE_NAME or whose CPE generation otherwise legitimately fails.
        self.assertGreater(
            len(inf_derived),
            0,
            "no inf-derived components ended up in the merged SBOM",
        )
        inf_cpe_count = sum(1 for c in inf_derived if c.get("cpe"))
        self.assertGreaterEqual(
            inf_cpe_count / len(inf_derived),
            0.9,
            f"only {inf_cpe_count}/{len(inf_derived)} inf-derived components have a "
            f"CPE; incorporate() may be misbehaving (overall {cpe_count}/{len(components)})",
        )
        self.assertGreaterEqual(
            bsd_count,
            1,
            "expected at least one BSD-2-Clause-Patent component (EDK II baseline)",
        )

        # Dependencies (§3.1.9)
        deps = data.get("dependencies", [])
        self.assertTrue(deps, "merged SBOM has no dependencies[]")
        for entry in deps:
            self.assertIn("ref", entry)
            self.assertIn("dependsOn", entry)
            self.assertIsInstance(entry["dependsOn"], list)
            for d in entry["dependsOn"]:
                self.assertIsInstance(d, str)
                self.assertTrue(d)
        primary_ref = primary["bom-ref"]
        primary_dep_entries = [d for d in deps if d["ref"] == primary_ref]
        self.assertTrue(
            primary_dep_entries,
            f"no dependencies[] entry for the primary bom-ref {primary_ref!r}",
        )
        self.assertTrue(primary_dep_entries[0]["dependsOn"])

        # Loadability round-trip
        reloaded = uSwidFormatCycloneDX().load(json.dumps(data).encode())
        self.assertEqual(len(reloaded), len(merged))
        reloaded_primary = next(c for c in reloaded if c.is_primary)
        self.assertEqual(reloaded_primary.software_name, "EDK II")

        # Smoke spot-check on a couple of well-known modules
        if self.mode == "light":
            wanted_basenames = ("BaseLib", "UiApp")
            found_basenames = {
                str(c.software_name) for c in merged if c.software_name
            }
            for basename in wanted_basenames:
                # Only spot-check modules that exist in the curated tree
                inf_existed = any(
                    f"{basename}.inf".lower() == os.path.basename(p).lower()
                    for p in _iter_inf_files(self.edk2_dir, self.mode, 5000)
                )
                if inf_existed:
                    self.assertIn(
                        basename,
                        found_basenames,
                        f"{basename}.inf was scanned but no component named {basename!r}"
                        " ended up in the merged SBOM",
                    )

        # Full mode: assert synthetic submodule components landed
        if self.mode == "full":
            sub_names = {
                (c.software_name or "").lower() for c in merged if c.software_name
            }
            found_hints = [
                hint for hint in _FULL_MODE_SUBMODULE_HINTS if hint in sub_names
            ]
            self.assertTrue(
                found_hints,
                f"full mode produced no recognisable submodule components; "
                f"checked for {_FULL_MODE_SUBMODULE_HINTS}, got {sorted(sub_names)[:20]}…",
            )

    def test_primary_dir_cli_end_to_end(self) -> None:
        """End-to-end exercise of the ``uswid --primary-dir`` CLI flag.

        This is the integration smoke test for Phase 2b: invoking the CLI
        with the new flag against a real EDK II checkout must produce a
        CycloneDX SBOM that is:

        * non-empty (``components[]`` populated),
        * primary ``metadata.component`` version and CPE resolved from the
          checkout (not ``NOASSERTION``),
        * placeholder-free in ``components[]`` (no surviving ``@VCS_*@`` —
          orphan fallback templates dropped, matched ones resolved per
          submodule git),
        * structurally complete (``dependencies[]`` present, primary has
          at least one ``dependsOn`` entry).

        Loads ``tests/edk2/sbom.template.cdx.json`` (``@VCS_*@`` placeholders,
        same shape as SBOM4EDK2 ``uswid-data/edk2.cdx.json``) so the primary
        must be re-merged against the checkout; the resolved fixture
        ``tests/edk2/sbom.cdx.json`` is still used by the in-process path.

        The fallback path is optional: when the running developer has a
        local uswid-data clone we point at it, otherwise we still run the
        flag against the EDK II tree alone (synthesised submodule
        components only). Either way the assertions above must hold.
        """
        out_path = os.path.join(self.cache_dir, "edk2.primary-dir-cli.cdx.json")
        if os.path.exists(out_path):
            os.unlink(out_path)

        cmd = [
            sys.executable,
            "-m",
            "uswid.cli",
            "--load",
            _PARENT_TEMPLATE,
            "--primary-dir",
            self.edk2_dir,
            "--fixup",
            "--save",
            out_path,
            "--format",
            "cyclonedx",
        ]

        # Opt-in to a uswid-data fallback path if the environment supplies one;
        # this is what real users will pass when they have curated templates.
        fallback_path = os.environ.get("USWID_DATA_DIR")
        if fallback_path and os.path.isdir(fallback_path):
            cmd += ["--fallback-path", fallback_path]

        try:
            subprocess.check_output(
                cmd, stderr=subprocess.STDOUT, cwd=_REPO_ROOT, timeout=600
            )
        except subprocess.CalledProcessError as exc:
            self.fail(
                f"uswid --primary-dir invocation failed (rc={exc.returncode}):\n"
                f"{exc.output.decode('utf-8', errors='replace')[:4000]}"
            )

        self.assertTrue(
            os.path.isfile(out_path),
            f"uswid did not write output to {out_path!r}",
        )

        with open(out_path, "rb") as f:
            data = json.loads(f.read().decode("utf-8"))

        self.assertEqual(data["bomFormat"], "CycloneDX")
        self.assertIn("component", data.get("metadata", {}))
        primary = data["metadata"]["component"]
        _assert_primary_metadata_resolved(self, primary, self.edk2_dir)

        components = data.get("components") or []
        self.assertGreater(
            len(components), 0, "--primary-dir produced no components"
        )

        # No component should carry an unresolved @VCS_*@ placeholder; the
        # orphan-template filter and per-submodule VCS substitution must
        # have eliminated every one.
        leftover = [
            c for c in components if any(
                "@VCS_" in str(v) for v in c.values() if isinstance(v, str)
            )
        ]
        self.assertEqual(
            leftover,
            [],
            f"{len(leftover)} components retain @VCS_*@ placeholders: "
            f"{[c.get('name') for c in leftover[:5]]}",
        )

        deps = data.get("dependencies") or []
        self.assertTrue(deps, "merged SBOM has no dependencies[]")
        primary_ref = primary["bom-ref"]
        primary_dep_entries = [d for d in deps if d.get("ref") == primary_ref]
        self.assertTrue(
            primary_dep_entries,
            f"no dependencies[] entry for the primary bom-ref {primary_ref!r}",
        )
        self.assertTrue(primary_dep_entries[0]["dependsOn"])

    def test_primary_dir_resolves_parent_vcs_placeholders(self) -> None:
        """``--primary-dir`` must resolve @VCS_*@ on the loaded parent template.

        SBOM4EDK2 loads ``edk2.cdx.json`` from uswid-data (not the checkout).
        Without re-merge against ``--primary-dir``, the primary stays
        ``NOASSERTION`` and GHSA cannot filter by EDK II release (YYYYMM).
        """
        out_path = os.path.join(
            self.cache_dir, "edk2.primary-dir-template-cli.cdx.json"
        )
        if os.path.exists(out_path):
            os.unlink(out_path)

        cmd = [
            sys.executable,
            "-m",
            "uswid.cli",
            "--load",
            _PARENT_TEMPLATE,
            "--primary-dir",
            self.edk2_dir,
            "--fixup",
            "--save",
            out_path,
            "--format",
            "cyclonedx",
        ]
        fallback_path = os.environ.get("USWID_DATA_DIR")
        if fallback_path and os.path.isdir(fallback_path):
            cmd += ["--fallback-path", fallback_path]

        try:
            subprocess.check_output(
                cmd, stderr=subprocess.STDOUT, cwd=_REPO_ROOT, timeout=600
            )
        except subprocess.CalledProcessError as exc:
            self.fail(
                f"uswid --primary-dir + template load failed (rc={exc.returncode}):\n"
                f"{exc.output.decode('utf-8', errors='replace')[:4000]}"
            )

        with open(out_path, "rb") as f:
            data = json.loads(f.read().decode("utf-8"))

        primary = data.get("metadata", {}).get("component") or {}
        _assert_primary_metadata_resolved(self, primary, self.edk2_dir)

        components = data.get("components") or []
        leftover = [
            c
            for c in components
            if any(
                "@VCS_" in str(v) for v in c.values() if isinstance(v, str)
            )
        ]
        self.assertEqual(
            leftover,
            [],
            f"{len(leftover)} components retain @VCS_*@ placeholders",
        )


if __name__ == "__main__":
    unittest.main()
