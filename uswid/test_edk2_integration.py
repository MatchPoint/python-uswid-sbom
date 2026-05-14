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
It mirrors what `MatchPoint/SBOM4EDK2 <https://github.com/MatchPoint/SBOM4EDK2>`_'s
``edk2_json_generator.py`` does: take a TianoCore EDK II checkout, parse each
``.inf`` module into a CycloneDX component (via :class:`uswid.format_inf.uSwidFormatInf`),
incorporate it under a parent EDK2 SBOM, and merge everything into one
``edk2.cdx.json`` that we then validate against the UEFI SBOM Guidelines (CISA
Level 1) shape.

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
from .entity import uSwidEntity, uSwidEntityRole
from .errors import NotSupportedError
from .format_cyclonedx import uSwidFormatCycloneDX
from .format_inf import uSwidFormatInf
from .link import uSwidLink, uSwidLinkRel
from .patch import uSwidPatch, uSwidPatchType
from .purl import uSwidPurl

_REPO_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
_DEFAULT_REF = "edk2-stable202411"
_PARENT_FIXTURE = os.path.join(_REPO_ROOT, "tests", "edk2", "sbom.cdx.json")
_CACHE_ROOT = os.path.join(_REPO_ROOT, "tests", "_edk2_cache")

# Submodule-bearing paths that uSwidFormatInf.load() chokes on in light mode
# (it opens every entry in [Sources] to compute a hash, and missing submodule
# files raise FileNotFoundError). These match the modules that explicitly pull
# in C source under MdePkg/Library/BaseFdtLib/, BrotliCustomDecompressLib, etc.
_LIGHT_MODE_EXCLUDE = (
    "MdePkg/Library/BaseFdtLib/",
    "MdePkg/Library/MipiSysTLib/",
    "MdeModulePkg/Library/BrotliCustomDecompressLib/",
    "MdeModulePkg/Universal/RegularExpressionDxe/",
)
# Curated packages walked in light mode (kept narrow so the run finishes fast
# and so we don't trip on submodule-dependent inf files).
_LIGHT_MODE_PACKAGES = ("MdePkg", "MdeModulePkg", "ShellPkg")

# In full mode we additionally assert these submodule-bearing locations
# produced at least one component, proving that submodule coverage worked.
_FULL_MODE_SUBMODULE_HINTS = (
    "openssl",
    "mbedtls",
    "brotli",
    "oniguruma",
    "libfdt",
    "mipisyst",
    "jansson",
    "libspdm",
)


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
    paths = _parse_gitmodules(gitmodules)
    if not paths:
        return False
    for relpath in paths.values():
        full = os.path.join(edk2_dir, relpath)
        if not os.path.isdir(full):
            return False
        try:
            if not os.listdir(full):
                return False
        except OSError:
            return False
    return True


def _parse_gitmodules(gitmodules_path: str) -> Dict[str, str]:
    """Return ``{submodule_name: relative_path}`` from a ``.gitmodules`` file."""
    result: Dict[str, str] = {}
    current: Optional[str] = None
    name_re = re.compile(r'^\s*\[submodule\s+"([^"]+)"\]\s*$')
    path_re = re.compile(r"^\s*path\s*=\s*(\S+)\s*$")
    try:
        with open(gitmodules_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = name_re.match(line)
                if m:
                    current = m.group(1)
                    continue
                m = path_re.match(line)
                if m and current:
                    result[current] = m.group(1)
    except OSError:
        return {}
    return result


def _parse_gitmodules_full(gitmodules_path: str) -> Dict[str, Dict[str, str]]:
    """Return ``{submodule_name: {key: value, ...}}`` (includes path + url)."""
    result: Dict[str, Dict[str, str]] = {}
    current: Optional[str] = None
    name_re = re.compile(r'^\s*\[submodule\s+"([^"]+)"\]\s*$')
    kv_re = re.compile(r"^\s*(\w+)\s*=\s*(\S+.*?)\s*$")
    try:
        with open(gitmodules_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = name_re.match(line)
                if m:
                    current = m.group(1)
                    result[current] = {}
                    continue
                if not current:
                    continue
                m = kv_re.match(line)
                if m:
                    result[current][m.group(1).strip()] = m.group(2).strip()
    except OSError:
        return {}
    return result


def _describe_edk2(edk2_dir: str) -> Tuple[str, str, str]:
    """Return ``(version_label, purl_version, cpe_version)`` for ``edk2_dir``.

    ``git describe --tags --always`` yields something like
    ``edk2-stable202602-196-g0fe6b755f2`` for a non-tag-exact commit. We convert it
    to a UEFI SBOM Guidelines-friendly version label (``edk2-stable202602+196.g…``)
    so the CycloneDX writer can render coherent ``purl`` / ``cpe`` strings while
    still pointing at the actual checkout.
    """
    describe = _run_git(["describe", "--tags", "--always"], cwd=edk2_dir)
    # match e.g. edk2-stable202602-196-g0fe6b755f2
    m = re.match(
        r"^(?P<tag>edk2-stable\d+)(?:-(?P<dist>\d+)-g(?P<sha>[0-9a-f]+))?$",
        describe,
    )
    if m and m.group("dist"):
        tag, dist, sha = m.group("tag"), m.group("dist"), m.group("sha")
        version_label = f"{tag}+{dist}.g{sha}"
        # purl/cpe should use the year-month suffix from the tag (e.g. "202602")
        m2 = re.search(r"(\d+)$", tag)
        short = m2.group(1) if m2 else tag
        return version_label, short, short
    if m:
        tag = m.group("tag")
        m2 = re.search(r"(\d+)$", tag)
        short = m2.group(1) if m2 else tag
        return tag, short, short
    # opaque sha
    return describe, describe, describe


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
# Submodule versioning and CPE helpers
# ---------------------------------------------------------------------------

# NVD CPE dictionary entries for known EDK2 submodules.
# Keyed by the GitHub "owner/repo" fragment from the submodule URL.
# Only packages with confirmed NVD entries are listed; others stay PURL-only.
# Verified against NVD CPE dictionary May 2026.
_SUBMODULE_CPE_MAP: Dict[str, Tuple[str, str]] = {
    "openssl/openssl":  ("openssl",           "openssl"),
    "ARMmbed/mbedtls":  ("arm",               "mbed_tls"),
    "akheron/jansson":  ("jansson_project",   "jansson"),
    "kkos/oniguruma":   ("oniguruma_project", "oniguruma"),
    "google/brotli":    ("google",            "brotli"),
    "DMTF/libspdm":     ("dmtf",             "libspdm"),
}

# Regex to extract the git-describe patch suffix: -N-gHASH at end of string.
_GIT_DESCRIBE_SUFFIX_RE = re.compile(r"-(\d+)-g([0-9a-f]+)$")
# Regex to strip a project-name suffix added by the downstream fork (e.g. +edk2).
_PROJECT_SUFFIX_RE = re.compile(r"[+][a-zA-Z0-9_-]+$")
# Bare commit hash (7-40 hex chars, no dots or dashes).
_BARE_COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)
# CVE identifier pattern.
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)


def _normalize_submodule_version(raw: str) -> Tuple[str, int, Optional[str], Optional[str]]:
    """Normalize a raw ``git describe`` string into (clean_version, patch_count,
    commit_sha, base_tag).

    * ``clean_version`` — semantic version suitable for a CPE/NVD lookup
      (``v``/``V`` and project-name prefixes stripped, ``+project`` suffixes
      removed, git-describe commit suffix removed).
    * ``patch_count`` — number of commits applied on top of the last tag.
    * ``commit_sha``  — short commit hash when past-tag commits exist, or the
      bare hash itself when no tag is present, else ``None``.
    * ``base_tag``    — the raw tag string as it appears in the git repo (used
      to scope a ``git log <base_tag>..HEAD`` CVE scan); ``None`` for bare
      commits.

    Examples::

        "openssl-3.5.1"             → ("3.5.1",  0,   None,     "openssl-3.5.1")
        "v3.6.5"                    → ("3.6.5",  0,   None,     "v3.6.5")
        "v1.2.0-1-ge230f47"         → ("1.2.0",  1,   "e230f47","v1.2.0")
        "release-1.11.0-238-g86a"   → ("1.11.0", 238, "86a",    "release-1.11.0")
        "cmocka-1.1.5-23-g1cc9cde"  → ("1.1.5",  23,  "1cc9cde","cmocka-1.1.5")
        "v1.1+edk2"                 → ("1.1",    0,   None,     "v1.1")
        "V184"                      → ("184",    0,   None,     "V184")
        "3.7.0"                     → ("3.7.0",  0,   None,     "3.7.0")
        "83d4e1e"                   → ("0.0.0",  0,   "83d4e1e", None)
    """
    raw = raw.strip()

    # Bare commit hash — no release baseline.
    if _BARE_COMMIT_RE.match(raw):
        return "0.0.0", 0, raw, None

    # Step 1: peel off git-describe patch suffix (-N-gHASH).
    patch_count = 0
    commit_sha: Optional[str] = None
    m = _GIT_DESCRIBE_SUFFIX_RE.search(raw)
    if m:
        patch_count = int(m.group(1))
        commit_sha = m.group(2)
        raw = raw[: m.start()]          # e.g. "v1.2.0" or "cmocka-1.1.5"

    # Step 2: remove downstream project suffix (e.g. "+edk2").
    raw = _PROJECT_SUFFIX_RE.sub("", raw)

    # base_tag is what remains — the actual tag name in the git repo.
    base_tag: Optional[str] = raw

    # Step 3: extract the clean version number (first digit-led portion).
    vm = re.search(r"(\d[\d.]*)", raw)
    if not vm:
        return "0.0.0", patch_count, commit_sha, base_tag

    clean_version = vm.group(1).rstrip(".")
    return clean_version, patch_count, commit_sha, base_tag


def _scan_git_log_for_cves(
    cwd: str, base_tag: str, vcs_url: str
) -> List[uSwidPatch]:
    """Scan git log from *base_tag* to HEAD for CVE mentions.

    Returns a list of :class:`uSwidPatch` objects:

    * One **summary** entry (type ``cherry-pick``) noting the total commit
      count, always prepended so readers see the range at a glance.
    * One **security** entry per commit that mentions a CVE in its subject
      or body, carrying the CVE IDs in ``references``.

    Commits are scanned using ``git log <base_tag>..HEAD`` with a separator
    record format so multi-line bodies are handled without ambiguity.
    """
    _SEP = "---USWID_COMMIT_END---"
    try:
        raw_log = _run_git(
            ["log", f"{base_tag}..HEAD", "--no-merges",
             f"--format=%H%x09%s%n%b%n{_SEP}"],
            cwd=cwd,
        )
    except subprocess.CalledProcessError:
        return []

    patches: List[uSwidPatch] = []
    total_commits = 0
    current_sha = current_subject = ""
    current_body_lines: List[str] = []

    def _flush() -> None:
        nonlocal current_sha, current_subject, current_body_lines
        if not current_sha:
            return
        full_text = current_subject + " " + " ".join(current_body_lines)
        cves = sorted(set(_CVE_RE.findall(full_text)))
        if cves:
            commit_url = (
                f"{vcs_url.rstrip('/')}/commit/{current_sha}" if vcs_url else None
            )
            patches.append(
                uSwidPatch(
                    type=uSwidPatchType.SECURITY,
                    url=commit_url,
                    description=current_subject[:200],
                    references=cves,
                )
            )
        current_sha = current_subject = ""
        current_body_lines = []

    for line in raw_log.splitlines():
        if line == _SEP:
            _flush()
            continue
        if "\t" in line and not current_sha:
            # First line of a new commit record: "HASH\tSubject"
            parts = line.split("\t", 1)
            current_sha = parts[0]
            current_subject = parts[1] if len(parts) > 1 else ""
            total_commits += 1
        else:
            current_body_lines.append(line)
    _flush()  # flush last record if separator was missing

    # Prepend the summary entry.
    if total_commits > 0:
        patches.insert(
            0,
            uSwidPatch(
                type=uSwidPatchType.CHERRY_PICK,
                description=f"{total_commits} commit(s) applied since {base_tag}",
            ),
        )
    return patches


def _make_submodule_components(
    edk2_dir: str, parent: uSwidComponent
) -> List[uSwidComponent]:
    """Per UEFI Guidelines §2.3.1, materialise ``.gitmodules`` as components.

    Each populated submodule becomes a ``uSwidComponent`` linked under the parent
    EDK2 component via ``uSwidLinkRel.COMPONENT``. ``software_version`` is
    discovered with ``git describe`` inside the submodule when possible.
    """
    gitmodules = os.path.join(edk2_dir, ".gitmodules")
    if not os.path.isfile(gitmodules):
        return []
    submodules: List[uSwidComponent] = []
    for name, fields in _parse_gitmodules_full(gitmodules).items():
        rel_path = fields.get("path")
        url = fields.get("url") or ""
        if not rel_path:
            continue
        sub_dir = os.path.join(edk2_dir, rel_path)
        if not os.path.isdir(sub_dir):
            continue
        try:
            sub_sha = _run_git(["rev-parse", "HEAD"], cwd=sub_dir)
        except subprocess.CalledProcessError:
            continue
        try:
            raw_version = _run_git(["describe", "--tags", "--always"], cwd=sub_dir)
        except subprocess.CalledProcessError:
            raw_version = sub_sha[:12]

        clean_version, patch_count, commit_sha, base_tag = (
            _normalize_submodule_version(raw_version)
        )

        # derive a stable purl-ish tag_id from the submodule URL when possible
        m = re.search(r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/.]+)", url)
        github_slug: Optional[str] = None
        if m:
            github_slug = f"{m.group('owner')}/{m.group('repo')}"
            tag_id = f"pkg:github/{github_slug}@{sub_sha}"
            supplier_name = m.group("owner")
        else:
            tag_id = f"pkg:edk2-submodule/{rel_path}@{sub_sha}"
            supplier_name = "NOASSERTION"

        comp = uSwidComponent()
        comp.tag_id = tag_id
        comp.software_name = os.path.basename(rel_path)
        comp.software_version = clean_version
        comp.type = uSwidComponentType.LIBRARY

        # Assign a CPE when this submodule has a known NVD entry.
        if github_slug:
            cpe_entry = _SUBMODULE_CPE_MAP.get(github_slug)
            if cpe_entry:
                cpe_vendor, cpe_product = cpe_entry
                comp.cpe = (
                    f"cpe:2.3:a:{cpe_vendor}:{cpe_product}"
                    f":{clean_version}:*:*:*:*:*:*:*"
                )

        comp.add_entity(
            uSwidEntity(name=supplier_name, roles=[uSwidEntityRole.SOFTWARE_CREATOR])
        )

        # Pedigree: if commits were applied past the last tag, scan for CVEs.
        if patch_count > 0 and base_tag and os.path.isdir(sub_dir):
            vcs_url = url if url.startswith("http") else ""
            for patch in _scan_git_log_for_cves(sub_dir, base_tag, vcs_url):
                comp.add_patch(patch)
        elif commit_sha and base_tag is None:
            # Bare commit with no release baseline — record it as a single patch.
            comp.add_patch(
                uSwidPatch(
                    type=uSwidPatchType.CHERRY_PICK,
                    description=f"No release tag found; pinned at commit {commit_sha}",
                )
            )

        if url:
            comp.add_link(uSwidLink(rel=uSwidLinkRel.SEE_ALSO, href=url))
        parent.add_link(uSwidLink(rel=uSwidLinkRel.COMPONENT, href=comp.tag_id))
        submodules.append(comp)
    return submodules


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
                version_label, purl_v, cpe_v = _describe_edk2(cls.edk2_dir)
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
        if self.mode == "full":
            primary = next(c for c in merged if c.is_primary)
            for sub in _make_submodule_components(self.edk2_dir, primary):
                if not merged.get_by_id(sub.tag_id):
                    merged.append(sub)

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


if __name__ == "__main__":
    unittest.main()
