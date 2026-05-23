# AGENTS.md — python-uswid-sbom

Instructions for AI agents working in **MatchPoint/python-uswid-sbom** (the `uswid` fork).

## Role in the ecosystem

This repo is the **SBOM creation engine**. It owns all logic that turns source trees and template files into CycloneDX / SPDX / CoSWID output.

| Repo | Role | Must NOT |
|------|------|----------|
| **python-uswid-sbom** (this repo) | SBOM library + CLI: parse inputs, merge, `--primary-dir` assembly, format writers, UEFI compliance | CVE scanning, git clone orchestration, CSAF VEX batch |
| [SBOM4EDK2](https://github.com/MatchPoint/SBOM4EDK2) | Thin orchestrator: clone EDK2, shell out to `uswid`, run NVD/Grype/GHSA | Per-`.inf` thread pools, CDX merge, submodule version logic |
| [VEX4EDK2](https://github.com/MatchPoint/VEX4EDK2) | Quarterly batch: EDK2 checkout → SBOM4EDK2 → CSAF VEX in `releases/` | SBOM assembly, CVE scanner implementation |

**Related agent docs:** SBOM4EDK2 `AGENTS.md`, VEX4EDK2 `AGENTS.md`.

## Architecture (post v0.2.0)

```text
EDK2 checkout + uswid-data templates
        │
        ▼
  uswid CLI  (--load / --find / --fallback-path / --primary-dir / --fixup / --save)
        │
        ├── uswid/submodule.py   ← generic Git submodule mechanics (upstream-PR-able)
        ├── uswid/edk2.py        ← EDK II-only constants/helpers (future plugin seam)
        ├── uswid/cli.py         ← --primary-dir post-load assembly (gated on flag)
        └── format_* / component / entity / container  ← writers + model
        │
        ▼
   edk2.cdx.json  ──►  SBOM4EDK2 (CVE only)  ──►  VEX4EDK2 (CSAF batch)
```

### Module boundaries (do not blur)

| Module | Contains | Do not put here |
|--------|----------|-----------------|
| `uswid/submodule.py` | `walk_gitmodules`, `normalize_submodule_version`, `SUBMODULE_URL_ALIASES`, `SUBMODULE_CPE_MAP`, `make_submodule_components` | EDK2 tag regex, package name lists |
| `uswid/edk2.py` | `EDK2_TAG_PATTERN`, `describe_edk2_version`, light/full mode package lists | Generic submodule logic, CLI flags |
| `uswid/cli.py` | `--primary-dir`, `.inf` in `--find` suffixes | CVE or NVD code |
| `uswid/test_edk2_integration.py` | Parity tests vs SBOM4EDK2; CLI end-to-end `--primary-dir` tests | Production orchestration |

`uswid/cli.py` **must not** import `uswid.edk2`. EDK II glue stays in tests and downstream tools until a future `python-uswid-edk2` plugin exists.

### `--primary-dir` contract (SBOM4EDK2 depends on this)

When `--primary-dir <DIR>` is set, after `--load` / `--find` / `--fallback-path`:

1. Walk `.gitmodules` under `DIR` (`uswid.submodule.walk_gitmodules`).
2. Re-merge loaded templates so `@VCS_*@` resolves against each submodule's git tree (and the checkout root for the primary).
3. Drop orphan fallback templates with no matching submodule.
4. Synthesise minimal components for submodules without templates.
5. Set `source_dir` on components so `--fixup` builds `dependencies[]`.

SBOM4EDK2 invokes this via `generate_sbom_from_checkout` → `python -m uswid.cli` (see SBOM4EDK2 `AGENTS.md`). **Do not move this pipeline back into SBOM4EDK2.**

## Fork constraints (upstream hygiene)

1. **Do not edit upstream-identical files** without explicit user direction (`vcs.py`, `container.py`, `format_inf.py`, `format_pe.py`, most of `format.py`, etc.). Verify with `git diff` against `hughsie/python-uswid` when unsure.

2. **Append-only on fork-modified files** where possible: `cli.py`, `component.py`, `entity.py`, `format_cyclonedx.py`, `format_spdx.py`, `test_uswid.py`. New behavior gates on **new flags** (e.g. `--primary-dir`); default CLI behavior must match upstream when flags are omitted.

3. **`--primary-dir` vs `--primary`:** `--primary <ID>` designates the SBOM Primary Component; `--primary-dir <DIR>` is the source-tree root for assembly. Do not overload or rename either.

## UEFI SBOM Guidelines (USBT)

Local engineering docs live under `docs/uefi/` (gitignored — USBT draft). Before compliance changes, read `guidelines.md`, `conformance.md`, and `known_doc_issues.md` if present.

Key implementation files: `format_cyclonedx.py`, `format_spdx.py`, `component.py`, `entity.py`, `cli.py`, `submodule.py`, `test_uswid.py`, `test_edk2_integration.py`.

**Do not commit `docs/uefi/`** to the public remote.

## Tests

```bash
pip install -e . cbor2
python -m unittest uswid.test_uswid -v
```

EDK2 integration (slow; needs clone):

```bash
USWID_EDK2_INTEGRATION=1 EDK2_DIR=/path/to/edk2 python -m unittest uswid.test_edk2_integration -v
```

## Gotchas

- **`uswid --load` does not clobber `metadata.component`.** Multiple loads append to `components[]`; do not reintroduce manual CDX merge helpers in downstream repos.
- **CPE version accuracy drives CVE value.** Submodule versions must come from `normalize_submodule_version`, not placeholder `1.0`.
- **Setuptools-scm version** may show `0.2.x.devN` in editable installs; release tags are `v0.1.0`, `v0.2.0`, `v0.2.1`.
- **SBOM4EDK2 pins this repo by git tag** in its `requirements.txt`; bump the tag there when releasing breaking assembly changes.
