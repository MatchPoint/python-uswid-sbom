#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# (c) Copyright 2026 HP Development Company, L.P.
#
# SPDX-License-Identifier: BSD-2-Clause-Patent

"""EDK II-specific helpers and data tables.

This module is the deliberate **seam** between the project-agnostic uSWID
library (CLI, format readers/writers, :mod:`uswid.submodule`) and the EDK II
specifics that were grafted onto uSWID during the UEFI SBOM Guidelines work.
Everything that requires knowing what an *EDK II tag* or an *MdePkg* is
lives here. Code in this module is structured so it can be lifted into a
separate ``python-uswid-edk2`` plugin package later without affecting any
other part of uSWID:

* nothing in ``uswid/`` outside this file imports :mod:`uswid.edk2`,
* this module imports only from :mod:`uswid.submodule` and the public uSWID
  data types — never from :mod:`uswid.cli` or other glue layers.

Contents:

* :func:`describe_edk2_version` — parses ``edk2-stable<YYYYMM>(-N-gHASH)?``
  tags into the ``(label, purl_version, cpe_version)`` triple that the
  CycloneDX writer expects.
* :data:`EDK2_LIGHT_MODE_PACKAGES`, :data:`EDK2_LIGHT_MODE_EXCLUDE`,
  :data:`EDK2_FULL_MODE_SUBMODULE_HINTS` — scoping constants used by the
  integration test suite to constrain a light-mode EDK II walk.
"""

from __future__ import annotations

import re
import subprocess
from typing import Tuple

from .submodule import _run_git  # private helper reused; see uswid.submodule


__all__ = [
    "EDK2_TAG_PATTERN",
    "describe_edk2_version",
    "EDK2_LIGHT_MODE_PACKAGES",
    "EDK2_LIGHT_MODE_EXCLUDE",
    "EDK2_FULL_MODE_SUBMODULE_HINTS",
]


# ---------------------------------------------------------------------------
# Tag parsing
# ---------------------------------------------------------------------------

#: Matches ``edk2-stable<YYYYMM>`` with an optional ``-N-gHASH`` git-describe
#: suffix. Capture groups: ``tag`` (always present), ``dist`` and ``sha``
#: (present together when the checkout is past the tag).
EDK2_TAG_PATTERN = re.compile(
    r"^(?P<tag>edk2-stable\d+)(?:-(?P<dist>\d+)-g(?P<sha>[0-9a-f]+))?$"
)


def describe_edk2_version(edk2_dir: str) -> Tuple[str, str, str]:
    """Return ``(version_label, purl_version, cpe_version)`` for *edk2_dir*.

    ``git describe --tags --always`` typically yields
    ``edk2-stable202602-196-g0fe6b755f2`` for a non-tag-exact checkout. The
    CycloneDX writer wants:

    * a *version label* (``edk2-stable202602+196.g0fe6b755f2``) that is
      pleasant to render and round-trip,
    * a *PURL version* (``202602``) — the bare YYYYMM portion, matching how
      ``pkg:github/tianocore/edk2@<v>`` is conventionally pinned, and
    * a *CPE version* (``202602``) — the form the NVD CPE dictionary uses
      for ``cpe:2.3:a:tianocore:edk2``.

    Falls back to the opaque ``git describe`` output for untagged trees so
    the SBOM is still emittable, even if NVD lookups won't match.
    """
    describe = _run_git(["describe", "--tags", "--always"], cwd=edk2_dir)
    m = EDK2_TAG_PATTERN.match(describe)
    if m and m.group("dist"):
        tag = m.group("tag")
        dist = m.group("dist")
        sha = m.group("sha")
        version_label = f"{tag}+{dist}.g{sha}"
        m2 = re.search(r"(\d+)$", tag)
        short = m2.group(1) if m2 else tag
        return version_label, short, short
    if m:
        tag = m.group("tag")
        m2 = re.search(r"(\d+)$", tag)
        short = m2.group(1) if m2 else tag
        return tag, short, short
    return describe, describe, describe


# ---------------------------------------------------------------------------
# Test scoping constants
# ---------------------------------------------------------------------------

#: Top-level EDK II packages walked in light mode. Kept narrow so a CI run
#: completes quickly without paying the cost of a full source-tree walk and
#: without depending on populated submodules (HostTestPkg, NetworkPkg, etc.
#: pull in OpenSSL, mbed TLS and friends).
EDK2_LIGHT_MODE_PACKAGES: Tuple[str, ...] = (
    "MdePkg",
    "MdeModulePkg",
    "ShellPkg",
)

#: ``.inf`` directories that :class:`uswid.format_inf.uSwidFormatInf.load`
#: trips on in light mode because their ``[Sources]`` sections reference C
#: files under unpopulated submodules. Listed as path-prefix strings (forward
#: slashes, relative to the EDK II root) for cheap ``startswith()`` checks.
EDK2_LIGHT_MODE_EXCLUDE: Tuple[str, ...] = (
    "MdePkg/Library/BaseFdtLib/",
    "MdePkg/Library/MipiSysTLib/",
    "MdeModulePkg/Library/BrotliCustomDecompressLib/",
    "MdeModulePkg/Universal/RegularExpressionDxe/",
)

#: Submodule-bearing paths the full-mode integration test asserts produced
#: at least one component, proving submodule coverage actually fired.
EDK2_FULL_MODE_SUBMODULE_HINTS: Tuple[str, ...] = (
    "openssl",
    "mbedtls",
    "brotli",
    "oniguruma",
    "libfdt",
)


def _check_git_available() -> None:
    """Defensive runtime check; private to this module."""
    try:
        subprocess.check_call(
            ["git", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(
            "git is required for EDK II tag discovery but is not on PATH"
        ) from exc
