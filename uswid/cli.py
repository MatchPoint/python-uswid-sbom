#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=wrong-import-position,too-many-locals,too-many-statements,too-many-nested-blocks

from collections import defaultdict
from datetime import datetime
from typing import Optional, List, Dict, Any
import argparse
import socket
import json
import os
import sys

from importlib import metadata as importlib_metadata
from importlib.metadata import PackageNotFoundError

sys.path.append(os.path.realpath("."))

from uswid import (
    NotSupportedError,
    uSwidContainer,
    uSwidEntity,
    uSwidEntityRole,
    uSwidComponent,
    uSwidProblem,
    uSwidVersionScheme,
    uSwidPayloadCompression,
    uSwidPayloadFormat,
    uSwidLink,
    uSwidLinkRel,
    uSwidLinkUse,
)
from uswid.format import uSwidFormatBase
from uswid.format_coswid import uSwidFormatCoswid
from uswid.format_ini import uSwidFormatIni
from uswid.format_goswid import uSwidFormatGoswid
from uswid.format_pkgconfig import uSwidFormatPkgconfig
from uswid.format_swid import uSwidFormatSwid
from uswid.format_uswid import uSwidFormatUswid
from uswid.format_cyclonedx import uSwidFormatCycloneDX
from uswid.format_spdx import uSwidFormatSpdx
from uswid.format_pe import uSwidFormatPe
from uswid.format_inf import uSwidFormatInf
from uswid.vcs import uSwidVcs
from uswid.vex_document import uSwidVexDocument
from uswid.container_utils import container_generate, container_roundtrip


def _detect_format(filepath: str) -> Optional[Any]:
    if filepath.endswith("bom.json") or filepath.endswith("cdx.json"):
        return uSwidFormatCycloneDX()
    if filepath.endswith("spdx.json"):
        return uSwidFormatSpdx()
    ext = filepath.rsplit(".", maxsplit=1)[-1].lower()
    if ext in ["exe", "efi", "o"]:
        return uSwidFormatPe()
    if ext in ["uswid", "raw", "bin"]:
        return uSwidFormatUswid()
    if ext in ["coswid", "cbor"]:
        return uSwidFormatCoswid()
    if ext == "ini":
        return uSwidFormatIni()
    if ext == "inf":
        return uSwidFormatInf()
    if ext == "xml":
        return uSwidFormatSwid()
    if ext == "json":
        return uSwidFormatGoswid()
    if ext == "pc":
        return uSwidFormatPkgconfig()
    return None


def _container_merge_from_filepath(
    container: uSwidContainer,
    base: uSwidFormatBase,
    filepath: str,
    dirpath: Optional[str] = None,
    fixup: bool = False,
) -> None:
    with open(filepath, "rb") as f:
        blob: bytes = f.read()
    vcs = uSwidVcs(filepath=filepath, dirpath=dirpath)
    try:
        text: str = blob.decode()
        replacements: Dict[str, str] = {}

        # substitute some keys with the discovered values
        for key in [
            "@VCS_TAG@",
            "@VCS_VERSION@",
            "@VCS_BRANCH@",
            "@VCS_COMMIT@",
            "@VCS_SBOM_AUTHORS@",
            "@VCS_SBOM_AUTHOR@",
            "@VCS_AUTHORS@",
            "@VCS_AUTHOR@",
        ]:
            if text.find(key) != -1:
                replacements[key] = "NOASSERTION"
        if "@VCS_TAG@" in replacements:
            replacements["@VCS_TAG@"] = vcs.get_tag()
        if "@VCS_VERSION@" in replacements:
            replacements["@VCS_VERSION@"] = vcs.get_version()
        if "@VCS_BRANCH@" in replacements:
            replacements["@VCS_BRANCH@"] = vcs.get_branch()
        if "@VCS_COMMIT@" in replacements:
            replacements["@VCS_COMMIT@"] = vcs.get_commit()
        if "@VCS_SBOM_AUTHORS@" in replacements:
            replacements["@VCS_SBOM_AUTHORS@"] = ", ".join(vcs.get_sbom_authors())
        if "@VCS_SBOM_AUTHOR@" in replacements:
            replacements["@VCS_SBOM_AUTHOR@"] = vcs.get_sbom_authors()[0]
        if "@VCS_AUTHORS@" in replacements:
            replacements["@VCS_AUTHORS@"] = ", ".join(vcs.get_authors())
        if "@VCS_AUTHOR@" in replacements:
            replacements["@VCS_AUTHOR@"] = vcs.get_authors()[0]

        # do substitutions
        if replacements:
            if base.verbose:
                print(f"Substitution required in {filepath}:")
            for key, value in replacements.items():
                if base.verbose:
                    print(f" - {key} → {value}")
                text = text.replace(key, value)
            blob = text.encode()
    except UnicodeDecodeError:
        pass
    for component in base.load(blob, path=filepath):

        # where this came from
        component.add_source_filename(filepath)

        # guess something sane
        if fixup:
            fixup_strs: List[str] = []
            if not component.software_version:
                component.software_version = vcs.get_version()
                if base.verbose:
                    fixup_strs.append(f"Add VCS version → {component.software_version}")
            if not component.version_scheme and component.software_version:
                component.version_scheme = uSwidVersionScheme.from_version(
                    component.software_version
                )
            if not component.edition:
                component.edition = vcs.get_commit()
                if base.verbose:
                    fixup_strs.append(f"Add VCS commit → {component.edition}")
            if not component.get_entity_by_role(uSwidEntityRole.TAG_CREATOR):
                entity_tag: uSwidEntity = uSwidEntity(
                    name=", ".join(vcs.get_sbom_authors()),
                    roles=[uSwidEntityRole.TAG_CREATOR],
                )
                component.add_entity(entity_tag)
                if base.verbose:
                    fixup_strs.append(f"Add VCS SBOM author → {entity_tag.name}")
            if not component.get_entity_by_role(uSwidEntityRole.SOFTWARE_CREATOR):
                entity_creator: uSwidEntity = uSwidEntity(
                    name=", ".join(vcs.get_authors()),
                    roles=[uSwidEntityRole.SOFTWARE_CREATOR],
                )
                component.add_entity(entity_creator)
                if base.verbose:
                    fixup_strs.append(f"Add VCS author → {entity_creator.name}")
            if fixup_strs:
                print(f"Fixup required in {filepath}:")
                for fixup_str in fixup_strs:
                    print(f" - {fixup_str}")

            # get the toplevel so that we can auto-add deps
            component.source_dir = vcs.get_toplevel()

        # add requirements from the loader
        base.incorporate(container, component)

        component_new = container.merge(component)
        if component_new:
            print(
                "{} was merged into existing component {}".format(
                    filepath, component_new.tag_id
                )
            )


def main():
    """Main entrypoint"""
    parser = argparse.ArgumentParser(
        prog="uswid", description="Generate CoSWID metadata"
    )
    try:
        parser.add_argument(
            "--version",
            action="version",
            version="%(prog)s " + importlib_metadata.version("uswid"),
        )
    except PackageNotFoundError:
        pass
    parser.add_argument("--cc", default="gcc", help="Compiler to use for empty object")
    parser.add_argument(
        "--cflags", default="", help="C compiler flags to be used by CC"
    )
    parser.add_argument("--binfile", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--rawfile", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--inifile", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--xmlfile", default=None, help=argparse.SUPPRESS)
    parser.add_argument(
        "--objcopy", default=None, help="Binary file to use for objcopy"
    )
    parser.add_argument(
        "--find",
        default=[],
        nargs="+",
        help="directory to scan, e.g. ~/Code/firmware",
    )
    parser.add_argument(
        "--fallback-path",
        default=[],
        nargs="+",
        help="fallback directory to scan, e.g. ~/fallback",
    )
    parser.add_argument(
        "--load",
        nargs="+",
        help="file to import, .efi,.ini,.uswid,.xml,.json",
    )
    parser.add_argument(
        "--save",
        default=None,
        action="append",
        help="file to export, .efi,.ini,.uswid,.xml,.json",
    )
    parser.add_argument(
        "--compress",
        dest="compress",
        default=False,
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--compression",
        type=uSwidPayloadCompression.argparse,
        choices=list(uSwidPayloadCompression),
        dest="compression",
        default=uSwidPayloadCompression.NONE,
        help="Compress uSWID containers",
    )
    parser.add_argument(
        "--format",
        type=uSwidPayloadFormat.argparse,
        choices=list(uSwidPayloadFormat),
        dest="format",
        default=uSwidPayloadFormat.COSWID,
        help="Format for uSWID container",
    )
    parser.add_argument(
        "--generate",
        dest="generate",
        default=False,
        action="store_true",
        help="Generate plausible SWID entries",
    )
    parser.add_argument(
        "--roundtrip",
        dest="roundtrip",
        default=False,
        action="store_true",
        help="Test various different formats from loaded data",
    )
    parser.add_argument(
        "--fixup",
        dest="fixup",
        default=False,
        action="store_true",
        help="Fix components with missing VCS data",
    )
    parser.add_argument(
        "--validate",
        dest="validate",
        default=False,
        action="store_true",
        help="Validate SWID entries",
    )
    parser.add_argument(
        "--verbose",
        dest="verbose",
        default=False,
        action="store_true",
        help="Show verbose operation",
    )
    parser.add_argument(
        "--sbom-type",
        dest="sbom_type",
        default=None,
        choices=["source", "build", "binary"],
        help=(
            "Declare the SBOM lifecycle type per the UEFI SBOM Guidelines §3.1.1.3 "
            "('Type'). For CycloneDX output, sets metadata.lifecycles[].phase "
            "(source→pre-build, build→build, binary→post-build). For SPDX output, "
            "annotates creationInfo.comment with 'sbomType: <value>'."
        ),
    )
    parser.add_argument(
        "--lifecycle-phase",
        dest="lifecycle_phase",
        default=None,
        choices=[
            "design",
            "pre-build",
            "build",
            "post-build",
            "operations",
            "discovery",
            "decommission",
        ],
        help=(
            "Advanced override for CycloneDX metadata.lifecycles[].phase. "
            "Takes precedence over --sbom-type when both are set."
        ),
    )
    parser.add_argument(
        "--primary",
        dest="primary_tag_id",
        default=None,
        help=(
            "Mark the component with this tag_id, PURL, or CPE as the SBOM Primary "
            "Component (UEFI SBOM Guidelines §3.1.1.3). Surfaces in CycloneDX "
            "metadata.component and SPDX DESCRIBES. Default: pick the unique "
            "firmware-type component, else the first component."
        ),
    )
    parser.add_argument(
        "--primary-dir",
        dest="primary_dir",
        metavar="DIR",
        default=None,
        help=(
            "Source-tree root of the primary component. When set, uswid walks "
            "DIR/.gitmodules recursively, re-merges any --fallback-path SBOM "
            "templates against the matching submodule's actual directory "
            "(so @VCS_*@ placeholders resolve to each submodule's git state), "
            "drops orphan templates with no matching submodule, and synthesises "
            "minimal CycloneDX components for submodules that have no curated "
            "template. The resulting components feed into --fixup's containment-"
            "based dependency wiring to produce a complete CycloneDX dependencies[] "
            "tree per UEFI SBOM Guidelines §3.1.9."
        ),
    )
    args = parser.parse_args()
    load_filepaths = args.load
    if not load_filepaths:
        load_filepaths = []
    save_filepaths = args.save if args.save else []

    # always load into a temporary component
    container = uSwidContainer()

    # load a fallback path of sboms
    container_fallback = uSwidContainer()
    for path in args.fallback_path:
        for basename in os.listdir(path):
            filepath = os.path.join(path, basename)
            base = _detect_format(filepath)
            if not base:
                continue
            base.verbose = args.verbose
            if isinstance(base, uSwidFormatPkgconfig):
                base.filepath = filepath
            with open(filepath, "rb") as f:
                blob: bytes = f.read()
            for component in base.load(blob, path=filepath):
                component.add_source_filename(filepath)
                container_fallback.append(component)

    # search for known suffixes recursively
    sbom_suffixes = [
        "spdx.json",
        "swid.xml",
        "cdx.json",
        "bom.json",
        "bom.coswid",
        "sbom.ini",
        "inf",
    ]
    fallback_dirpaths: List[str] = []
    for path in args.find:
        for dirpath, dirs, fns in os.walk(path):
            if container_fallback:
                for path in dirs:
                    if path == ".git":
                        fallback_dirpaths.append(dirpath)
                for path in fns:
                    if path == ".git":
                        fallback_dirpaths.append(dirpath)
            for fn in fns:
                for sbom_suffix in sbom_suffixes:
                    if fn.endswith(sbom_suffix):
                        load_filepaths.append(os.path.join(dirpath, fn))
    if args.verbose and load_filepaths:
        print("Found:")
        for filepath in load_filepaths:
            print(f" - {filepath}")

    # any fallbacks
    for dirpath in fallback_dirpaths:
        vcs = uSwidVcs(filepath=dirpath, dirpath=dirpath)
        remote_path = vcs.get_remote_url()
        if remote_path:
            component = container_fallback.get_by_link_href(remote_path)
            if component:
                filepath = component.source_filenames[0]
                base = _detect_format(filepath)
                if not base:
                    continue
                base.verbose = args.verbose
                _container_merge_from_filepath(
                    container, base, filepath, dirpath=dirpath, fixup=args.fixup
                )
                if args.verbose:
                    print(f"Using {filepath} fallback for {remote_path}")
            else:
                if args.verbose:
                    print(f"No fallback component for {remote_path}")
        else:
            if args.verbose:
                print(f"No git directory for {dirpath}")

    # handle deprecated --compress
    if args.compress:
        print("WARNING: --compress is deprecated, please use --compression instead")
        args.compression = uSwidPayloadCompression.ZLIB

    # deprecated arguments
    if args.binfile:
        load_filepaths.append(args.binfile)
        save_filepaths.append(args.binfile)
    if args.rawfile:
        save_filepaths.append(args.rawfile)
    if args.xmlfile:
        load_filepaths.append(args.xmlfile)

    # sanity check
    if not load_filepaths and not save_filepaths:
        print("Use uswid --help for command line arguments")
        sys.exit(1)

    # generate plausible components
    if args.generate:
        container_generate(container)

    # collect data here
    for filepath in load_filepaths:
        try:
            if filepath.endswith(".vex"):
                with open(filepath, "rb") as f:
                    container.add_vex_document(
                        uSwidVexDocument(json.loads(f.read().decode()))
                    )
            else:
                base = _detect_format(filepath)
                if not base:
                    print(f"{filepath} has unknown extension, using uSWID")
                    base = uSwidFormatUswid()
                base.verbose = args.verbose
                if isinstance(base, uSwidFormatPe):
                    base.objcopy = args.objcopy
                    with open(filepath, "rb") as f:
                        for component in base.load(f.read(), filepath):
                            base.incorporate(container, component)
                            component_new = container.merge(component)
                            if component_new:
                                print(
                                    "{} was merged into existing component {}".format(
                                        filepath, component_new.tag_id
                                    )
                                )
                else:
                    _container_merge_from_filepath(
                        container, base, filepath, fixup=args.fixup
                    )
        except FileNotFoundError:
            print(f"{filepath} does not exist")
            sys.exit(1)
        except NotSupportedError as e:
            print(e)
            sys.exit(1)

    # --primary-dir: resolve fallback templates against the primary's
    # .gitmodules tree, drop orphans, synthesise any missing submodule
    # components, and anchor source_dir on every component so the --fixup
    # block below can wire a complete CycloneDX dependencies[] tree.
    # See uswid.submodule for the generic helpers; nothing project-specific
    # lives in this block.
    if args.primary_dir:
        from uswid.submodule import (
            SUBMODULE_URL_ALIASES,
            canonicalize_vcs_url,
            make_submodule_components,
            resolve_submodule_vcs,
            resolve_with_aliases,
            walk_gitmodules,
        )

        if not os.path.isdir(args.primary_dir):
            print(f"--primary-dir {args.primary_dir!r} is not a directory")
            sys.exit(1)

        primary_dir_abs = os.path.realpath(args.primary_dir)
        url_to_path = walk_gitmodules(primary_dir_abs)

        # Identify the primary candidate: --primary if given, else the first
        # already-loaded component. Used as the parent for synthesised
        # submodule components and as the anchor for source_dir.
        primary_component: Optional[uSwidComponent] = None
        if args.primary_tag_id:
            for c in container:
                candidates = {c.tag_id, c.cpe}
                if c.purl:
                    candidates.add(str(c.purl))
                if args.primary_tag_id in candidates:
                    primary_component = c
                    break
        if primary_component is None:
            primary_component = next(iter(container), None)
        if primary_component is not None:
            primary_component.source_dir = primary_dir_abs

        # Re-merge each fallback template against its matching submodule
        # directory so @VCS_*@ placeholders resolve against the submodule's
        # git state rather than the fallback file's parent directory.
        matched_sub_dirs: set = set()
        for fb_comp in list(container_fallback):
            fb_url: Optional[str] = None
            for link in fb_comp.links:
                if link.href and link.href.startswith(("http://", "https://")):
                    if resolve_with_aliases(
                        link.href, url_to_path, SUBMODULE_URL_ALIASES
                    ):
                        fb_url = link.href
                        break
            if not fb_url:
                continue
            sub_dir = resolve_with_aliases(fb_url, url_to_path, SUBMODULE_URL_ALIASES)
            if not sub_dir or not os.path.isdir(sub_dir):
                continue
            if not fb_comp.source_filenames:
                continue
            filepath = fb_comp.source_filenames[0]
            base = _detect_format(filepath)
            if not base:
                continue
            base.verbose = args.verbose
            _container_merge_from_filepath(
                container, base, filepath, dirpath=sub_dir, fixup=args.fixup
            )
            matched_sub_dirs.add(os.path.normpath(sub_dir))

            # uSwidVcs.get_version() returns the raw `git describe` output
            # (e.g. ``openssl-3.5.1``); normalise it to the NVD-CPE form so
            # downstream CVE lookups can match. Also anchor source_dir to the
            # actual submodule directory for the --fixup containment loop.
            canon_url = canonicalize_vcs_url(fb_url)
            for c in container:
                if any(
                    link.href and canonicalize_vcs_url(link.href) == canon_url
                    for link in c.links
                ):
                    clean, _, _, _ = resolve_submodule_vcs(sub_dir)
                    if clean and clean != "NOASSERTION":
                        c.software_version = clean
                    c.source_dir = sub_dir
                    break

        # Synthesise minimal components for submodules with no curated
        # fallback template (so every .gitmodules entry produces at least one
        # SBOM component). make_submodule_components also adds parent->child
        # COMPONENT links, materialising the §3.1.9 dependency from the
        # primary to each submodule.
        if primary_component is not None:
            synth_components, synth_dir_to_tag = make_submodule_components(
                primary_dir_abs, primary_component
            )
            tag_to_dir = {tag: d for d, tag in synth_dir_to_tag.items()}
            for comp in synth_components:
                comp_sub_dir = tag_to_dir.get(comp.tag_id)
                if comp_sub_dir is None:
                    continue
                if os.path.normpath(comp_sub_dir) in matched_sub_dirs:
                    continue
                comp.source_dir = comp_sub_dir
                container.append(comp)

    # auto-add deps using the top-level project paths
    if args.fixup:

        fixup_strs: List[str] = []

        # order by length
        components = list(container)
        components.sort(key=lambda s: -len(s.source_dir))
        for component in components:
            if component.get_link_by_rel(uSwidLinkRel.COMPONENT):
                continue
            for component2 in components:
                if component.source_dir == component2.source_dir:
                    continue
                if component.source_dir.find(component2.source_dir) != -1:
                    fixup_strs.append(f"{component2.tag_id} → {component.tag_id}")
                    component2.add_link(
                        uSwidLink(
                            rel=uSwidLinkRel.COMPONENT,
                            href=component.tag_id,
                            use=uSwidLinkUse.REQUIRED,
                        )
                    )
                    break
        if fixup_strs:
            print("Additional dependencies added:")
            for fixup_str in fixup_strs:
                print(f" - {fixup_str}")

    # depsolve any internal SWID links
    container.depsolve()

    # remove any deps that do not exist
    if args.fixup:
        fixup_dep_remove_strs: List[str] = []
        for component in container:
            for link in component.links:
                if link.rel == uSwidLinkRel.COMPONENT and not container.get_by_id(
                    link.href
                ):
                    if args.verbose:
                        fixup_dep_remove_strs.append(
                            f"Removed missing component listed as dep of {component.tag_id} → {link.href}"
                        )
                    component.remove_link(link)
        if fixup_dep_remove_strs:
            print(f"Fixup required in {filepath}:")
            for fixup_str in fixup_dep_remove_strs:
                print(f" - {fixup_str}")

    # validate
    rc: int = 0
    if args.validate:
        problems_dict: dict[Optional[uSwidComponent], List[uSwidProblem]] = defaultdict(
            list
        )
        if len(container) == 0:
            problems_dict[None] += [
                uSwidProblem("all", "There are no defined components", since="0.4.7")
            ]
        for component in container:
            problems = component.problems()
            if problems:
                problems_dict[component].extend(problems)
        if problems_dict:
            rc = 2
            print("Validation problems:")
            for opt_component, problems in problems_dict.items():
                for problem in problems:
                    key: str = "*"
                    if opt_component and opt_component.tag_id:
                        key = opt_component.tag_id
                    print(
                        f"{key.ljust(40)} {problem.kind.rjust(10)}: "
                        f"{problem.description} (uSWID >= v{problem.since})"
                    )

    # test the container with different SBOM formats
    if args.roundtrip:
        container_roundtrip(container, verbose=args.verbose)

    # apply --primary: mark the named component as the SBOM Primary Component.
    # Match against tag_id, CPE, or PURL string for ergonomics.
    if args.primary_tag_id:
        match: Optional[uSwidComponent] = None
        for component in container:
            candidates = {component.tag_id, component.cpe}
            if component.purl:
                candidates.add(str(component.purl))
            if args.primary_tag_id in candidates:
                match = component
                break
        if match is None:
            print(
                f"--primary {args.primary_tag_id!r} did not match any component "
                f"tag_id/CPE/PURL in the merged container"
            )
            sys.exit(1)
        # clear any previously marked primaries; only one primary is allowed
        for component in container:
            component.is_primary = False
        match.is_primary = True
        if args.verbose:
            print(f"Marked {match.tag_id} as Primary Component")

    # add any missing evidence
    for component in container:
        for evidence in component.evidences:
            if not evidence.date and not evidence.device_id:
                evidence.date = datetime.now()
                evidence.device_id = socket.getfqdn()

    # debug
    if load_filepaths and args.verbose:
        print("Loaded:")
        for component in container:
            print(f"{component}")
        for vex_document in container.vex_documents:
            print(f"{vex_document}")

    # optional save
    if save_filepaths and args.verbose:
        print("Saving:")
        for component in container:
            print(f"{component}")
    for filepath in save_filepaths:
        try:
            base = _detect_format(filepath)
            if not base:
                print(f"{filepath} extension is not supported")
                sys.exit(1)
            base.verbose = args.verbose
            if isinstance(base, uSwidFormatUswid):
                base.compression = args.compression
                base.format = args.format
            if isinstance(base, uSwidFormatPe):
                base.filepath = filepath
                base.objcopy = args.objcopy
                base.cc = args.cc
                base.cflags = args.cflags
            # Per UEFI SBOM Guidelines §3.1.1.3 propagate Type/Lifecycle to the
            # CycloneDX and SPDX writers so the emitted SBOM reflects user intent.
            if isinstance(base, uSwidFormatCycloneDX):
                if args.sbom_type:
                    base.sbom_type = args.sbom_type
                if args.lifecycle_phase:
                    base.lifecycle_phase = args.lifecycle_phase
            if isinstance(base, uSwidFormatSpdx):
                if args.sbom_type:
                    base.sbom_type = args.sbom_type
            blob = base.save(container)
            if blob:
                with open(filepath, "wb") as f:
                    f.write(blob)
        except NotSupportedError as e:
            print(e)
            sys.exit(1)

    # success
    sys.exit(rc)


if __name__ == "__main__":
    main()
