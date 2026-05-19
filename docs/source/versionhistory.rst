Version history
===============

.. currentmodule:: uswid

This library adheres to `Semantic Versioning <http://semver.org/>`_.

**v0.2.1** (unreleased)

 - ``patches_for_commits_since_tag``: default CycloneDX pedigree patch type for post-tag commits is ``cherry-pick`` (was ``backport``). ``security`` is still used when a commit message contains a CVE ID. Bare-commit submodule pins without a release tag still emit a single ``cherry-pick`` pedigree note (HP Development Company)
 - CycloneDX: emit ``metadata.tools[]`` as ``USWID SBOM`` with the installed package version; seed ``metadata.authors[]`` with Richard Hughes and Brian Mullen before merging component tag creators (HP Development Company)
 - CLI: when ``--primary-dir`` is set, re-merge the loaded primary SBOM template (from ``--load``) against the checkout root so ``@VCS_*@`` placeholders resolve to the parent tree's git state, not the template file's directory (fixes ``NOASSERTION`` primary version/CPE when SBOM4EDK2 loads ``edk2.cdx.json`` from uswid-data). Adds ``uSwidContainer.remove()`` and ``tests/edk2/sbom.template.cdx.json``; integration tests ``test_primary_dir_cli_end_to_end`` and ``test_primary_dir_resolves_parent_vcs_placeholders`` assert ``metadata.component`` version and CPE (HP Development Company)

**v0.2.0** (2026-05-18 — submodule mechanics promoted to public API; ``uswid --primary-dir`` end-to-end EDK2 SBOM assembly)

 - Add ``uswid/submodule.py``: generic (project-agnostic) Git submodule mechanics, designed for upstream contribution to ``hughsie/python-uswid``. Public APIs: ``canonicalize_vcs_url``, ``resolve_with_aliases``, ``parse_gitmodules_file``, ``walk_gitmodules``, ``normalize_submodule_version``, ``resolve_submodule_vcs``, ``patches_for_commits_since_tag``, ``make_submodule_components``; module-level constants ``SUBMODULE_URL_ALIASES`` (GitHub org-rename aliases for Mbed-TLS, libfdt, etc.) and ``SUBMODULE_CPE_MAP`` (NVD-verified CPE entries for openssl, mbedtls, jansson, oniguruma, brotli, libspdm) (HP Development Company)
 - Add ``uswid/edk2.py``: EDK II-specific seam module. Contains ``EDK2_TAG_PATTERN``, ``describe_edk2_version``, ``EDK2_LIGHT_MODE_PACKAGES``, ``EDK2_LIGHT_MODE_EXCLUDE``, ``EDK2_FULL_MODE_SUBMODULE_HINTS``. Designed to be lifted into a separate ``python-uswid-edk2`` plugin package later without touching ``uswid/cli.py`` or ``uswid/submodule.py`` (HP Development Company)
 - CLI: add ``.inf`` to the ``--find`` suffix list so EDK II module files are discovered alongside CycloneDX / SPDX / CoSWID inputs (HP Development Company)
 - CLI: add ``--primary-dir <DIR>``: post-load processing that walks ``DIR`` recursively for ``.gitmodules``, identifies the primary component, re-merges any ``--fallback-path`` SBOM templates whose VCS URLs match a discovered submodule (applying ``@VCS_*@`` substitutions against the *submodule's* git state), drops orphan templates whose URL doesn't match any submodule, synthesises minimal components for any submodules without a curated template, and sets ``source_dir`` on every component so the subsequent ``--fixup`` builds a correct CycloneDX ``dependencies[]`` tree. Combined with ``--find``, ``--fallback-path``, ``--fixup``, ``--save`` this delivers single-invocation end-to-end EDK II-style SBOM assembly (HP Development Company)
 - Refactor ``uswid/test_edk2_integration.py``: removed ~380 lines of local helpers now replaced by imports from ``uswid.submodule`` and ``uswid.edk2``; added end-to-end test ``test_primary_dir_cli_end_to_end`` that runs the real ``uswid`` CLI with ``--primary-dir`` against a live EDK II checkout and validates the output for component count, absence of unresolved ``@VCS_*@`` placeholders, and a correctly-wired ``dependencies[]`` graph (HP Development Company)
 - Add nine unit tests in ``uswid/test_uswid.py`` covering ``canonicalize_vcs_url``, ``SUBMODULE_URL_ALIASES`` resolution, recursive and non-recursive ``walk_gitmodules`` (including URL normalisation and empty-input handling), ``SUBMODULE_CPE_MAP`` entries, ``patches_for_commits_since_tag`` parse + empty-log paths, and ``EDK2_TAG_PATTERN`` matching (HP Development Company)

**v0.1.0** (2026-05-15 — first release of the MatchPoint/python-uswid-sbom fork; UEFI SBOM Guidelines compliance, EDK2 integration)

 - Add ``uSwidComponent.is_primary`` field to designate the SBOM Primary Component per UEFI SBOM Guidelines §3.1.1.3; CycloneDX emits it as ``metadata.component``, SPDX emits a single ``Relationship: SPDXRef-DOCUMENT DESCRIBES`` (HP Development Company)
 - Add ``uSwidComponent.copyright`` field for copyright notices per UEFI SBOM Guidelines §3.1.11; CycloneDX emits ``component.copyright``, SPDX emits ``PackageCopyrightText`` (defaults to ``NOASSERTION``) (HP Development Company)
 - Add ``uSwidEntity.email`` field for contact email per UEFI SBOM Guidelines §3.1.1.1; CycloneDX emits ``metadata.authors[].email``, SPDX emits ``Person|Organization: Name <email>`` (HP Development Company)
 - CycloneDX: emit ``metadata.authors[]`` with email when ``uSwidEntity.email`` is set (§3.1.1.1) (HP Development Company)
 - CycloneDX: emit ``metadata.timestamp`` in UTC with ``Z`` suffix per ISO-8601 (§3.1.1.2) (HP Development Company)
 - CycloneDX: resolve Primary Component via ``is_primary`` flag, falling back to unique firmware-type component then first component; emit as ``metadata.component`` and exclude from ``components[]`` (§3.1.1.3) (HP Development Company)
 - CycloneDX: derive ``metadata.lifecycles[{"phase": "..."}]`` from SBOM type — ``source``→``pre-build``, ``build``→``build``, ``binary``→``post-build`` (§3.1.1.3 Type) (HP Development Company)
 - CycloneDX: prefer CPE as ``bom-ref`` when ``component.cpe`` is set; resolve ``dependencies[].dependsOn`` refs through an internal ``tag_id_to_bom_ref`` map so CPE-based bom-refs are consistent throughout (§3.1.8) (HP Development Company)
 - CycloneDX: emit ``dependencies[].dependsOn`` as a JSON array (was emitted as a string in some code paths, violating the CycloneDX 1.6 schema) (§3.1.9) (HP Development Company)
 - SPDX: emit ``Creator: Person|Organization: Name <email>`` when email is available (§3.1.1.1) (HP Development Company)
 - SPDX: emit ``Created:`` timestamp in UTC ISO-8601 with ``Z`` suffix (§3.1.1.2) (HP Development Company)
 - SPDX: emit single ``Relationship: SPDXRef-DOCUMENT DESCRIBES <primary>`` using the same Primary Component resolution logic as CycloneDX (§3.1.1.3) (HP Development Company)
 - SPDX: use ``software_name`` (not ``product``) as ``PackageName`` for consistency with CycloneDX ``component.name`` (§3.1.2.1) (HP Development Company)
 - SPDX: map ``SOFTWARE_CREATOR`` entity role to ``PackageSupplier`` and ``LICENSOR`` to ``PackageOriginator`` to preserve upstream heritage (§3.1.2.2) (HP Development Company)
 - SPDX: emit ``filesAnalyzed: false`` on every package so per-package ``PackageChecksum`` is legal without ``PackageVerificationCode`` (§3.1.7) (HP Development Company)
 - SPDX: sanitize ``SPDXID`` by replacing ``:`` ``/`` ``#`` ``@`` ``+`` with ``-``; preserve originals in ``externalRefs`` as ``purl`` / ``cpe23Type`` (§3.1.8) (HP Development Company)
 - SPDX: emit ``Relationship: SPDXRef-x CONTAINS SPDXRef-y`` for ``uSwidLinkRel.COMPONENT`` links (§3.1.9) (HP Development Company)
 - SPDX: emit both ``PackageLicenseConcluded`` and ``PackageLicenseDeclared`` (defaulting to ``NOASSERTION``) (§3.1.10) (HP Development Company)
 - Add CLI ``--sbom-type {source,build,binary}``: maps to CycloneDX ``metadata.lifecycles[].phase`` and annotates SPDX ``creationInfo.comment`` (§3.1.1.3) (HP Development Company)
 - Add CLI ``--lifecycle-phase``: advanced override for CycloneDX ``metadata.lifecycles[].phase``; takes precedence over ``--sbom-type`` (HP Development Company)
 - Add CLI ``--primary <tag_id|CPE|PURL>``: marks the matching component as the SBOM Primary Component; matched against ``tag_id``, ``cpe``, and ``purl`` string (HP Development Company)
 - Add EDK2 integration test (``uswid/test_edk2_integration.py``) mirroring the SBOM4EDK2 pipeline: parses EDK2 ``.inf`` modules into CycloneDX components, materialises ``.gitmodules`` as submodule components, merges into a single ``edk2.cdx.json``, and validates output against UEFI SBOM Guidelines CISA Level 1; supports light mode (subset of packages, no submodule sources) and full mode (all packages, recurse submodules); gated by ``USWID_EDK2_INTEGRATION=1`` (HP Development Company)
 - EDK2 integration: add ``_normalize_submodule_version()`` to convert raw ``git describe`` output into a clean semantic version suitable for CPE/NVD lookup — strips ``v``/``V`` and project-name prefixes (e.g. ``openssl-``, ``cmocka-``), downstream suffixes (e.g. ``+edk2``), and git-describe patch suffixes (``-N-gHASH``); returns base version, commit count, commit SHA, and base tag for CVE scanning (HP Development Company)
 - EDK2 integration: add ``_scan_git_log_for_cves()`` to scan ``git log <tag>..HEAD`` for CVE IDs (``CVE-YYYY-NNNNN``) in commit subjects and bodies; emits ``uSwidPatch`` entries of type ``security`` carrying the CVE IDs in ``resolves.references[]`` and a link to the commit URL, plus a summary entry noting total commit count (HP Development Company)
 - EDK2 integration: add ``_SUBMODULE_CPE_MAP`` — NVD-verified CPE vendor/product mappings for the six EDK2 submodules with confirmed NVD dictionary entries (openssl, mbedtls, jansson, oniguruma, brotli, libspdm); submodules without NVD entries remain PURL-only (HP Development Company)
 - Add ``test_normalize_submodule_version`` unit test covering all twelve EDK2 git-describe version patterns (HP Development Company)

.. note::

   The fork's own version stream begins at ``v0.1.0``.  All entries below
   this line are inherited from the upstream `hughsie/python-uswid
   <https://github.com/hughsie/python-uswid>`_ project and reflect that
   project's release history, not this fork's.  See
   ``docs/uefi/upstream_pr_notes.md`` (local-only) for the proposed
   commit structure when these changes are submitted back to upstream.

**0.6.0** (2025-03-16)

 - Add a workaround for a regression in cbor2 5.8.0 (Richard Hughes)
 - Add capability for patch and ancestor in INI (Baraneedharan Anbazhagan)
 - Add SPDX multi-package parsing + DEPENDS_ON mapping (Baraneedharan Anbazhagan)
 - Add support for metadata.component in CycloneDX (Baraneedharan Anbazhagan)
 - Allow embedding a CycloneDX or SPDX file in a uSWID container (Richard Hughes)
 - Fix lifecycles to be an array in CycloneDX (Richard Hughes)
 - Support reading in a string as a CycloneDX license (Richard Hughes)
 - Use an entry from the global map to encode the CPE (Richard Hughes)
 - Use link href as component tag_id for ancestors (Baraneedharan Anbazhagan)

**0.5.1** (2024-11-xx)

 - Add ``--find`` to recursively find SBOM files (Richard Hughes)
 - Add ``--fixup`` to repair any loaded SBOM files (Richard Hughes)
 - Add support for component CPE values (Richard Hughes)
 - Add support for component types, e.g. library, application or firmware (Richard Hughes)
 - Add support for loading CycloneDX files (Richard Hughes)
 - Add support for loading fallback files (Richard Hughes)
 - Add support for loading SPDX files (Richard Hughes)
 - Add support for substituted values like ``@VCS_VERSION@`` (Richard Hughes)
 - Add support for SWID activationStatus (Richard Hughes)
 - Add support for verifying different SBOM different formats (Richard Hughes)

**0.5.0** (2024-05-09)

 - Add a validation failure for REDACTED text (Richard Hughes)
 - Add initial support for VEX (Richard Hughes)
 - Allow outputting multi-document SWID XML files (Richard Hughes)
 - Correctly validate missing license and compiler links (Richard Hughes)
 - Relicense from LGPL-2.1+ to BSD-2-Clause-Patent (Richard Hughes)
 - Rename identity to component (Richard Hughes)
 - Save HEX strings as bytes to minimize coSWID size (Richard Hughes)

**0.4.7** (2023-12-03)

 - Add support for LZMA payload compression (Richard Hughes)
 - Add --validate with some initial rules (Richard Hughes)

**0.4.6** (2023-10-15)

 - Add SPDX export format (Richard Hughes)
 - Fix the INI payload export to include the hashes (Richard Hughes)
 - Enforce the payload size is integer in more places (Richard Hughes)
 - Correctly export the goSWID annotations (Richard Hughes)

**0.4.5** (2023-10-09)

 - Accept device-id when parsing INI evidenceand deviceId for SWID (Richard Hughes)

**0.4.4** (2023-10-06)

 - Add RTD generated docs (Richard Hughes)
 - Add support for SWID evidence to support the CISA SBOM Tooling guide (Richard Hughes)
 - Ensure that payload.size is always an integer (Richard Hughes)
 - Optionally provide the identity on each swid:-prefixed link (Richard Hughes)

**0.4.3** (2023-10-02)

 - Accept ``cbor`` file extensions as coSWID (Richard Hughes)
 - Add cflags argument (Callum Farmer)
 - Add support for SWID payload sections (Richard Hughes)
 - Add support for hashes in the CycloneDX export (Richard Hughes)
 - Allow loading the coSWID ``tag_id`` as a string (Richard Hughes)
 - Allow loading the payload from an explicit path (Richard Hughes)
 - Automatically calculate the INI payload hash and size (Richard Hughes)
 - Do not allow two payload hashes of the same type (Richard Hughes)
 - Do not assume that goSWID files have a ``software-meta`` section (Richard Hughes)
 - Do not require an ``edition`` to set the ``product`` (Richard Hughes)
 - Load the GoSWID identity correctly (Richard Hughes)
 - Make the goSWID importer cope with one-or-more in all cases (Richard Hughes)

**0.4.2** (2023-09-18)

 - Allow generating 1000 plausible identities for testing (Richard Hughes)
 - Allow specifying the SWID link hrefs by name as well as UUID (Richard Hughes)
 - Autocreate the identity ID from the software-name if required (Richard Hughes)
 - Fix exporting and importing goSWID XML when there is more than one identity (Richard Hughes)
 - Make ``--load`` use multiple files (Martin Fernandez)

**0.4.1** (2023-01-31)

 - Switch to cbor2 for coSWID files (Richard Hughes)

**0.4.0** (2023-01-07)

 - Add support for CycloneDX export (Richard Hughes)
 - Split out the import and exporters into different source files (Richard Hughes)

**0.3.4** (2023-01-04)

 - Add a convenience property for the href to display (Richard Hughes)
 - Don't show a fallback warning when loading .uswid files (Richard Hughes)
 - Fix up incomplete link data during import (Richard Hughes)
 - Load multiple identities from the JSON file (Richard Hughes)
 - Save all identities when exporting to JSON (Richard Hughes)
 - Store the entity role as a single string if only one item (Richard Hughes)

**0.3.3** (2022-10-06)

 - Add CoSWID as an export file type (Richard Hughes)
 - Add Compiler Link type (CodingVoid)
 - Add License link type (Maximilian Brune)

**0.3.2** (2022-07-17)

 - Add support for the ``persistent-id`` (Richard Hughes)
 - Allow adding deps such as the compiler version (Richard Hughes)
 - Allow importing SWID data from pkg-config files (Richard Hughes)
 - Change ``fn`` -> ``filepath`` for clarity/readability (Maximilian Brune)
 - Read compressed uSWID flags correctly (Richard Hughes)

**0.3.1** (2022-05-10)

 - Add a lang and version_scheme attributes to uSwidIdentity (Richard Hughes)
 - Add binary/CBOR representation for version-scheme (CodingVoid)
 - Add compliance to one-or-more CDDL rule in CoSWID (CodingVoid)
 - Add lang to CBOR export (CodingVoid)
 - Allow exporting SWID to JSON format (Richard Hughes)
 - Change ``SOFTWARE_NAME`` to ``ENTITY_NAME`` (Maximilian Brune)
 - Import ``LINK`` objects from the CBOR data (Richard Hughes)
 - Load the CBOR tag as GUID if required (Richard Hughes)

**0.3.0** (2022-04-19)

 - Add import from arbitrary binary blobs (CodingVoid)
 - Add some text describing the uSWID header (Richard Hughes)
 - Find and load multiple external data sections (Richard Hughes)
 - Make uSWID a container that can hold multiple compressed coSWID blobs (Richard Hughes)
 - Make uSwidContainer iterable (Richard Hughes)
 - Never add a ``.sbom`` section using pefile (Richard Hughes)
 - Replace manual search with str.find() (CodingVoid)

**0.2.0** (2022-03-18)

- Initial release
