#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
# (c) Copyright 2026 HP Development Company, L.P.
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=wrong-import-position,protected-access

import os
import sys
import unittest
from typing import Optional, Any
import shutil
import subprocess
import json

from lxml import etree as ET

# allows us to run this from the project root
sys.path.append(os.path.realpath("."))

from . import __version__ as tool_version
from .container import uSwidContainer
from .errors import NotSupportedError
from .link import uSwidLink, uSwidLinkRel
from .entity import uSwidEntity, uSwidEntityRole
from .enums import uSwidVersionScheme
from .component import uSwidComponent
from .hash import uSwidHash, uSwidHashAlg
from .payload import uSwidPayload
from .patch import uSwidPatch, uSwidPatchType

from .format_ini import uSwidFormatIni
from .format_coswid import uSwidFormatCoswid
from .format_swid import uSwidFormatSwid
from .format_cyclonedx import uSwidFormatCycloneDX
from .format_spdx import uSwidFormatSpdx
from .format_inf import uSwidFormatInf
from .vcs import uSwidVcs

from .purl import uSwidPurl

unittest.TestCase.maxDiff = None


class TestSwidEntity(unittest.TestCase):
    """Tescases for components, entities, links, evidence and payloads"""

    def setUp(self):
        self.git_path = "/tmp/uswid-test-git-tree"
        try:
            shutil.rmtree(self.git_path)
        except FileNotFoundError:
            pass

    def tearDown(self):
        try:
            shutil.rmtree(self.git_path)
        except FileNotFoundError:
            pass

    def _build_fake_git_path(self):
        subprocess.run(
            ["git", "init", self.git_path, "--initial-branch", "main"],
            cwd=".",
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.email", "admin@example.com"],
            cwd=self.git_path,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "RH"],
            cwd=self.git_path,
            check=True,
        )
        subprocess.run(
            ["mkdir", "contrib"],
            cwd=self.git_path,
            check=True,
        )
        with open(os.path.join(self.git_path, "contrib", "bom.cdx.json"), "wb") as f:
            f.write(b"hello")
        subprocess.run(
            ["git", "add", "contrib/bom.cdx.json"],
            cwd=self.git_path,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-a", "-m", "Add SBOM"],
            cwd=self.git_path,
            check=True,
            env={},
        )
        subprocess.run(
            ["mkdir", "edk2"],
            cwd=self.git_path,
            check=True,
        )
        try:
            for basename in ["Shell.inf", "Shell.c", "Shell.h"]:
                shutil.copy(
                    os.path.join(".", "tests", "edk2", basename),
                    os.path.join(self.git_path, "edk2", basename),
                )
            subprocess.run(
                ["git", "add", "edk2/Shell.inf"],
                cwd=self.git_path,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-a", "-m", "Add EDK Inf"],
                cwd=self.git_path,
                check=True,
                env={},
            )
        except FileNotFoundError:
            pass
        subprocess.run(
            ["git", "tag", "v1.2.3"],
            cwd=self.git_path,
            check=True,
        )
        with open(os.path.join(self.git_path, "contrib", "bom.cdx.json"), "wb") as f:
            f.write(b"hello world")
        subprocess.run(
            ["git", "commit", "-a", "-m", "A SBOM fixup"],
            cwd=self.git_path,
            check=True,
            env={},
        )
        subprocess.run(
            [
                "git",
                "remote",
                "add",
                "origin",
                "git@github.com:hughsie/python-uswid.git",
            ],
            cwd=self.git_path,
            check=True,
        )

    def test_format_inf(self):
        """Unit tests for uSwidFormatInf"""

        # generate something plausible
        self._build_fake_git_path()

        fmt_parent = uSwidFormatCycloneDX()
        try:
            with open("./tests/edk2/sbom.cdx.json", "rb") as f:
                container_parent = fmt_parent.load(f.read())
        except FileNotFoundError:
            return
        print(container_parent)

        fmt = uSwidFormatInf()
        fn = os.path.join(self.git_path, "edk2", "Shell.inf")
        try:
            with open(fn, "rb") as f:
                container = fmt.load(f.read(), path=fn)
        except FileNotFoundError:
            return
        for component in container:
            fmt.incorporate(container_parent, component)
            container_parent.append(component)

        self.assertIsNotNone(
            container_parent.get_by_id("pkg:github/tianocore/edk2@202411")
        )
        self.assertIsNotNone(
            container_parent.get_by_id("pkg:github/tianocore/edk2@202411#Shell")
        )

        fmt_parent.serial_number = "urn:uuid:00000000-0000-0000-0000-000000000000"
        fmt_parent.timestamp = "2024-01-01T00:00:00.000000+00:00"
        self.assertEqual(
            fmt_parent.save(container_parent).decode(),
            """{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-01T00:00:00.000000+00:00",
    "tools": [
      {
        "vendor": "uSWID Authors",
        "name": "uSWID",
        "version": "@USWID_VERSION@"
      }
    ],
    "authors": [
      {
        "name": "RH"
      }
    ],
    "lifecycles": [
      {
        "phase": "pre-build"
      }
    ],
    "component": {
      "type": "firmware",
      "cpe": "cpe:2.3:a:tianocore:edk2:202411:*:*:*:*:*:*:*",
      "name": "EDK II",
      "version": "edk2-stable202411-105-gd55d4e22f4",
      "description": "A cross-platform firmware development environment for UEFI and PI specifications",
      "bom-ref": "cpe:2.3:a:tianocore:edk2:202411:*:*:*:*:*:*:*",
      "externalReferences": [
        {
          "type": "vcs",
          "url": "https://github.com/tianocore/edk2"
        }
      ],
      "licenses": [
        {
          "license": {
            "url": "https://spdx.org/licenses/BSD-2-Clause.html",
            "id": "BSD-2-Clause"
          }
        }
      ],
      "supplier": {
        "name": "EDK II developers"
      },
      "authors": [
        {
          "name": "EDK II authors"
        }
      ]
    }
  },
  "components": [
    {
      "type": "application",
      "group": "7c04a583-9e3e-4f1c-ad65-e05268d0b4d1",
      "cpe": "cpe:2.3:a:tianocore:edk2:202411:*:*:*:*:*:*:Shell",
      "name": "Shell",
      "version": "1.0",
      "description": "This is the shell application",
      "bom-ref": "cpe:2.3:a:tianocore:edk2:202411:*:*:*:*:*:*:Shell",
      "externalReferences": [
        {
          "type": "vcs",
          "url": "https://github.com/tianocore/edk2"
        }
      ],
      "licenses": [
        {
          "license": {
            "url": "https://spdx.org/licenses/BSD-2-Clause-Patent.html",
            "id": "BSD-2-Clause-Patent"
          }
        }
      ],
      "supplier": {
        "name": "EDK II developers"
      },
      "authors": [
        {
          "name": "RH"
        }
      ],
      "properties": [
        {
          "name": "colloquialVersion",
          "value": "6e434ee13d3fe6f205f93523c7874a666a75aa6e443f6848a1c11af062861359"
        }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "cpe:2.3:a:tianocore:edk2:202411:*:*:*:*:*:*:*",
      "dependsOn": [
        "cpe:2.3:a:tianocore:edk2:202411:*:*:*:*:*:*:Shell"
      ]
    },
    {
      "ref": "cpe:2.3:a:tianocore:edk2:202411:*:*:*:*:*:*:Shell",
      "dependsOn": [
        "pkg:github/tianocore/edk2@202411#BaseLib"
      ]
    }
  ]
}""".replace("@USWID_VERSION@", tool_version),
        )

    def test_vcs_verfmt(self):
        """Unit tests for uSwidVcs, version format conversion"""

        self.assertEqual(
            uSwidVersionScheme.from_version("123"), uSwidVersionScheme.DECIMAL
        )
        self.assertEqual(
            uSwidVersionScheme.from_version("1.2.3"), uSwidVersionScheme.SEMVER
        )
        self.assertEqual(
            uSwidVersionScheme.from_version("1.2.3-4"),
            uSwidVersionScheme.MULTIPARTNUMERIC,
        )
        self.assertEqual(
            uSwidVersionScheme.from_version("1.2.3-4~5"),
            uSwidVersionScheme.ALPHANUMERIC,
        )

    def test_container(self):
        """Unit tests for uSwidContainer"""

        container = uSwidContainer()

        self.assertIsNone(container.get_by_id("pkg:github/tianocore/edk2@202411"))

        # exact match
        container.append(uSwidComponent(tag_id="pkg:github/tianocore/edk2@202411"))
        self.assertIsNotNone(container.get_by_id("pkg:github/tianocore/edk2@202411"))
        self.assertIsNone(container.get_by_id("pkg:github/tianocore/edk2"))

        # incomplete PURL match
        self.assertIsNone(
            container.get_by_id("pkg:github/tianocore/something@202411", fuzzy=True)
        )
        self.assertIsNone(
            container.get_by_id("pkg:github/tianocore/edk2@12345678", fuzzy=True)
        )
        self.assertIsNone(
            container.get_by_id("pkg:github/intel/edk2@202411", fuzzy=True)
        )
        self.assertIsNotNone(
            container.get_by_id("pkg:github/tianocore/edk2", fuzzy=True)
        )
        self.assertIsNotNone(container.get_by_id("pkg:edk2", fuzzy=True))

    def test_vcs(self):
        """Unit tests for uSwidVcs"""

        # generate something plausible
        self._build_fake_git_path()

        vcs = uSwidVcs(filepath=os.path.join(self.git_path, "contrib", "bom.cdx.json"))

        # 0.5.0
        self.assertEqual(vcs.get_tag(), "1.2.3")

        # 0.5.0-25-g26af980
        self.assertEqual(vcs.get_version().rsplit("-", maxsplit=1)[0], "v1.2.3-1")

        # main
        self.assertEqual(vcs.get_branch(), "main")

        # 26af9806ef407b171481ff234d2fe16386dc75eb
        self.assertEqual(len(vcs.get_commit()), 40)

        # /home/hughsie/Code/uswid
        value: Optional[str] = vcs.get_toplevel()
        self.assertEqual(value, self.git_path)

        # https://github.com/hughsie/python-uswid
        value = vcs.get_remote_url()
        self.assertEqual(value, "https://github.com/hughsie/python-uswid")

        # me!
        self.assertEqual(vcs.get_sbom_authors(), ["RH"])
        self.assertEqual(vcs.get_authors(), ["RH"])

    def test_entity(self):
        """Unit tests for uSwidEntity"""
        entity = uSwidEntity(
            name="test", regid="example.com", roles=[uSwidEntityRole.MAINTAINER]
        )
        self.assertEqual(
            str(entity),
            'uSwidEntity(regid="example.com",name="test",roles=[MAINTAINER])',
        )
        self.assertEqual(
            str(uSwidFormatCoswid()._save_entity(entity)),  # type: ignore
            "{<uSwidGlobalMap.ENTITY_NAME: 31>: 'test', "
            + "<uSwidGlobalMap.REG_ID: 32>: 'example.com', "
            + "<uSwidGlobalMap.ROLE: 33>: <uSwidEntityRole.MAINTAINER: 6>}",
        )

        entity.roles.append(uSwidEntityRole.SOFTWARE_CREATOR)
        self.assertEqual(
            str(uSwidFormatCoswid()._save_entity(entity)),  # type: ignore
            "{<uSwidGlobalMap.ENTITY_NAME: 31>: 'test', "
            + "<uSwidGlobalMap.REG_ID: 32>: 'example.com', "
            + "<uSwidGlobalMap.ROLE: 33>: [<uSwidEntityRole.MAINTAINER: 6>, "
            + "<uSwidEntityRole.SOFTWARE_CREATOR: 2>]}",
        )

        # SWID XML import
        entity = uSwidEntity()
        uSwidFormatSwid()._load_entity(  # type: ignore
            entity,
            ET.Element(
                "Entity",
                attrib={"name": "foo", "regid": "bar", "role": "tagCreator maintainer"},
            ),
        )
        self.assertEqual(
            str(entity),
            'uSwidEntity(regid="bar",name="foo",roles=[TAG_CREATOR,MAINTAINER])',
        )
        with self.assertRaises(NotSupportedError):
            uSwidFormatSwid()._load_entity(  # type: ignore
                entity,
                ET.Element(
                    "Entity", attrib={"name": "foo", "regid": "bar", "role": "baz"}
                ),
            )

        # INI import
        entity = uSwidEntity()
        uSwidFormatIni()._load_entity(  # type: ignore
            entity,
            {"name": "foo", "regid": "bar", "extra-roles": "TagCreator,Maintainer"},
            role_hint="Distributor",
        )
        self.assertEqual(
            str(entity),
            'uSwidEntity(regid="bar",name="foo",roles=[TAG_CREATOR,MAINTAINER])',
        )
        with self.assertRaises(NotSupportedError):
            uSwidFormatIni()._load_entity(  # type: ignore
                entity, {"name": "foo", "regid": "bar", "extra-roles": "baz"}
            )

        # SWID XML export
        root = ET.Element("SoftwareIdentity")
        uSwidFormatSwid()._save_entity(entity, root)  # type: ignore
        self.assertEqual(
            ET.tostring(root, encoding="utf-8"),
            b"<SoftwareIdentity>"
            b'<Entity name="foo" regid="bar" role="tagCreator maintainer"/>'
            b"</SoftwareIdentity>",
        )

    def test_link(self):
        """Unit tests for uSwidLink"""
        # enumerated type
        link = uSwidLink(href="http://test.com/", rel=uSwidLinkRel.SEE_ALSO)
        self.assertEqual(str(link), 'uSwidLink(rel="see-also",href="http://test.com/")')
        self.assertEqual(
            str(uSwidFormatCoswid()._save_link(link)),  # type: ignore
            "{<uSwidGlobalMap.HREF: 38>: 'http://test.com/', "
            + "<uSwidGlobalMap.REL: 40>: <uSwidLinkRel.SEE_ALSO: 9>}",
        )

        # rel from IANA "Software Tag Link Relationship Values" registry
        link = uSwidLink(href="http://test.com/", rel=uSwidLinkRel.LICENSE)
        self.assertEqual(str(link), 'uSwidLink(rel="license",href="http://test.com/")')
        self.assertEqual(
            str(uSwidFormatCoswid()._save_link(link)),  # type: ignore
            "{<uSwidGlobalMap.HREF: 38>: 'http://test.com/', "
            + "<uSwidGlobalMap.REL: 40>: <uSwidLinkRel.LICENSE: -2>}",
        )

        # SWID XML import
        link = uSwidLink()
        uSwidFormatSwid()._load_link(  # type: ignore
            link,
            ET.Element(
                "Url",
                attrib={"href": "http://test.com/", "rel": "seeAlso"},
            ),
        )
        self.assertEqual(str(link), 'uSwidLink(rel="see-also",href="http://test.com/")')

        # INI import
        link = uSwidLink()
        uSwidFormatIni()._load_link(  # type: ignore
            link,
            {"href": "http://test.com/", "rel": "see-also"},
        )
        self.assertEqual(str(link), 'uSwidLink(rel="see-also",href="http://test.com/")')

        # SWID XML export
        root = ET.Element("SoftwareIdentity")
        uSwidFormatSwid()._save_link(link, root)  # type: ignore
        self.assertEqual(
            ET.tostring(root, encoding="utf-8"),
            b"<SoftwareIdentity>"
            b'<Link href="http://test.com/" rel="see-also"/>'
            b"</SoftwareIdentity>",
        )

    def test_payload(self):
        """Unit tests for uSwidPayload"""
        self.maxDiff = None

        # enumerated type
        payload = uSwidPayload(name="foo", size=123)
        payload.add_hash(
            uSwidHash(
                alg_id=uSwidHashAlg.SHA256,
                value="067cb8292dc062eabbe05734ef7987eb1333b6b6",
            )
        )
        self.assertEqual(
            str(payload),
            'uSwidPayload(name="foo",size=123)\n'
            ' - uSwidHash(alg_id=SHA256,value="067cb8292dc062eabbe05734ef7987eb1333b6b6")',
        )
        payload.remove_hash(uSwidHashAlg.SHA256)
        self.assertEqual(
            str(uSwidFormatCoswid()._save_payload(payload)),  # type: ignore
            "{<uSwidGlobalMap.FILE: 17>: {<uSwidGlobalMap.FS_NAME: 24>: 'foo', <uSwidGlobalMap.SIZE: 20>: 123}}",
        )

        # SWID XML import
        payload = uSwidPayload()
        uSwidFormatSwid()._load_payload(  # type: ignore
            payload,
            ET.Element(
                "File",
                attrib={
                    "name": "foo",
                    "size": "123",
                    "{http://www.w3.org/2001/04/xmlenc#sha256}hash": "067cb8292dc062eabbe05734ef7987eb1333b6b6",
                },
            ),
        )
        self.assertEqual(
            str(payload),
            'uSwidPayload(name="foo",size=123)\n'
            ' - uSwidHash(alg_id=SHA256,value="067cb8292dc062eabbe05734ef7987eb1333b6b6")',
        )

        # INI import
        payload = uSwidPayload()
        uSwidFormatIni()._load_payload(  # type: ignore
            payload,
            {
                "name": "foo",
                "size": "123",
                "hash": "8cab6b2125c2b561351b4e02ee531f26dde05c3c6a2be8ff942975fbdef6823c",
            },
        )
        self.assertEqual(
            str(payload),
            'uSwidPayload(name="foo",size=123)\n'
            ' - uSwidHash(alg_id=SHA256,value="8cab6b2125c2b561351b4e02ee531f26dde05c3c6a2be8ff942975fbdef6823c")',
        )

        # SWID XML export
        root = ET.Element("SoftwareIdentity")
        uSwidFormatSwid()._save_payload(payload, root)  # type: ignore
        self.assertEqual(
            ET.tostring(root, encoding="utf-8"),
            b"<SoftwareIdentity>"
            b'<File xmlns:SHA256="http://www.w3.org/2001/04/xmlenc#sha256" '
            b'xmlns:SHA512="http://www.w3.org/2001/04/xmlenc#sha512" name="foo" size="123" '
            b'SHA256:hash="8cab6b2125c2b561351b4e02ee531f26dde05c3c6a2be8ff942975fbdef6823c"/>'
            b"</SoftwareIdentity>",
        )

    def test_patch(self):
        """Unit tests for uSwidPatch"""
        self.maxDiff = None

        # enumerated type
        patch = uSwidPatch(
            type=uSwidPatchType.BACKPORT,
            url="http://foo",
            description="foo",
            references=["foo", "bar", "baz"],
        )
        self.assertEqual(
            str(patch),
            'uSwidPatch(type="backport", description="foo")',
        )

        # CycloneDX export
        jsonstr: str = json.dumps(uSwidFormatCycloneDX()._save_patch(patch))  # type: ignore
        self.assertEqual(
            jsonstr,
            '{"type": "backport", '
            '"diff": {"url": "http://foo"}, '
            '"resolves": {"description": "foo", "references": ["foo", "bar", "baz"]}}',
        )

        # CycloneDX import
        patch2 = uSwidFormatCycloneDX()._load_patch(json.loads(jsonstr))
        self.assertEqual(patch.type, patch2.type)
        self.assertEqual(patch.url, patch2.url)
        self.assertEqual(patch.description, patch2.description)
        self.assertEqual(patch.references, patch2.references)

        # INI export
        ini_save_patch = uSwidFormatIni()._save_patch(patch)
        self.assertEqual(
            ini_save_patch,
            {
                "type": "backport",
                "url": "http://foo",
                "description": "foo",
                "references": "foo,bar,baz",
            },
        )

        # INI import
        ini_load_patch = uSwidPatch()
        uSwidFormatIni()._load_patch(ini_load_patch, ini_save_patch)
        self.assertEqual(ini_load_patch.type, patch.type)
        self.assertEqual(ini_load_patch.url, patch.url)
        self.assertEqual(ini_load_patch.description, patch.description)
        self.assertEqual(ini_load_patch.references, patch.references)

    def test_normalize_submodule_version(self):
        """Unit tests for _normalize_submodule_version (EDK2 submodule versioning)."""
        from .test_edk2_integration import _normalize_submodule_version

        cases = [
            # (raw,                              clean,    patches, has_sha, has_tag)
            ("openssl-3.5.1",                   "3.5.1",  0,       False,   True),
            ("v3.6.5",                          "3.6.5",  0,       False,   True),
            ("v2.13.1",                         "2.13.1", 0,       False,   True),
            ("v6.9.10",                         "6.9.10", 0,       False,   True),
            ("3.7.0",                           "3.7.0",  0,       False,   True),
            ("V184",                            "184",    0,       False,   True),
            ("v1.1+edk2",                       "1.1",    0,       False,   True),
            ("v1.2.0-1-ge230f47",               "1.2.0",  1,       True,    True),
            ("v1.6.1-3-gcfff805",               "1.6.1",  3,       True,    True),
            ("release-1.11.0-238-g86add134",    "1.11.0", 238,     True,    True),
            ("cmocka-1.1.5-23-g1cc9cde",        "1.1.5",  23,      True,    True),
            ("83d4e1e",                         "0.0.0",  0,       True,    False),
        ]
        for raw, exp_ver, exp_patches, exp_sha, exp_tag in cases:
            with self.subTest(raw=raw):
                clean, patches, sha, tag = _normalize_submodule_version(raw)
                self.assertEqual(clean, exp_ver, f"clean version mismatch for {raw!r}")
                self.assertEqual(patches, exp_patches, f"patch count mismatch for {raw!r}")
                self.assertEqual(sha is not None, exp_sha, f"sha presence mismatch for {raw!r}")
                self.assertEqual(tag is not None, exp_tag, f"tag presence mismatch for {raw!r}")

    def test_component_purl(self):
        """Unit tests for uSwidComponent, PURL specific"""

        component = uSwidComponent(
            tag_id="pkg:github/tianocore/edk2@202411",
        )
        self.assertEqual(
            component.tag_id,
            "pkg:github/tianocore/edk2@202411",
        )
        self.assertEqual(
            str(component.purl),
            "pkg:github/tianocore/edk2@202411",
        )

    def test_ancestor(self):
        """Unit tests for uSwidComponent ancestors"""
        self.maxDiff = None
        component = uSwidComponent(tag_id="parent")
        component.ancestors.append(uSwidComponent(tag_id="child1"))
        component.ancestors.append(uSwidComponent(tag_id="child2"))

        # CycloneDX export
        jsonstr = uSwidFormatCycloneDX().save(uSwidContainer([component])).decode()
        assert "parent" in jsonstr
        assert "child1" in jsonstr
        assert "child2" in jsonstr

        # CycloneDX import
        component1 = uSwidFormatCycloneDX().load(jsonstr.encode())[0]
        self.assertEqual(component1.tag_id, "parent")
        self.assertEqual(component1.ancestors[0].tag_id, "child1")
        self.assertEqual(component1.ancestors[1].tag_id, "child2")

    def test_component(self):
        """Unit tests for uSwidComponent"""
        self.maxDiff = None
        component = uSwidComponent(
            tag_id="foobarbaz",
            tag_version=5,
            software_name="foo",
            software_version="1.2.3",
        )
        component.version_scheme = uSwidVersionScheme.MULTIPARTNUMERIC
        self.assertEqual(
            str(component),
            'uSwidComponent(tag_id="foobarbaz",tag_version="5",software_name="foo",software_version="1.2.3")',
        )
        entity = uSwidEntity(
            name="test", regid="example.com", roles=[uSwidEntityRole.MAINTAINER]
        )
        component.add_entity(entity)
        self.assertEqual(
            str(component),
            'uSwidComponent(tag_id="foobarbaz",tag_version="5",software_name="foo",software_version="1.2.3"):\n'
            ' - uSwidEntity(regid="example.com",name="test",roles=[MAINTAINER])',
        )

        # SWID XML import
        xml = b"""<?xml version='1.0' encoding='UTF-8'?>
<SoftwareIdentity name="DellBiosConnectNetwork"
tagId="acbd84ff-9898-4922-8ade-dd4bbe2e40ba" tagVersion="1" version="1.5.2"
versionScheme="unknown" xml:lang="en-us"
xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd"
xmlns:SHA256="http://www.w3.org/2001/04/xmlenc#sha256"
xmlns:SHA512="http://www.w3.org/2001/04/xmlenc#sha512"
xmlns:n8060="http://csrc.nist.gov/ns/swid/2015-extensions/1.0">
<Entity name="Dell Technologies" regid="dell.com" role="softwareCreator tagCreator" />
<Link rel="seeAlso" href="http://hughsie.com"/>
<Link rel="license" href="www.gnu.org/licenses/gpl.txt"/>
<Meta product="Fedora" colloquialVersion="29" persistentId="org.hughski.colorhug"
  summary="Linux distribution developed by the community-supported Fedora Project" />
</SoftwareIdentity>"""
        component = uSwidFormatSwid().load(xml).get_default()  # type: ignore
        self.assertEqual(
            str(component),
            'uSwidComponent(tag_id="acbd84ff-9898-4922-8ade-dd4bbe2e40ba",tag_version="1",'
            'software_name="DellBiosConnectNetwork",software_version="1.5.2"):\n'
            ' - uSwidLink(rel="see-also",href="http://hughsie.com")\n'
            ' - uSwidLink(rel="license",href="www.gnu.org/licenses/gpl.txt")\n'
            ' - uSwidEntity(regid="dell.com",name="Dell Technologies",roles=[SOFTWARE_CREATOR,TAG_CREATOR])',
        )
        self.assertEqual(
            component.summary,
            "Linux distribution developed by the community-supported Fedora Project",
        )
        self.assertEqual(component.product, "Fedora")
        self.assertEqual(component.colloquial_version, "29")
        self.assertEqual(component.persistent_id, "org.hughski.colorhug")

        # INI import
        ini = """[uSWID]
tag-id = acbd84ff-9898-4922-8ade-dd4bbe2e40ba
tag-version = 1
software-name = HughskiColorHug.efi
software-version = 1.0.0
persistent-id = org.hughski.colorhug

[uSWID-Entity:TagCreator]
name = Richard Hughes
regid = hughsie.com
extra-roles = Licensor

[uSWID-Entity:ANYTHING_CAN_GO_HERE]
name = Hughski Limited
regid = hughski.com
extra-roles = Aggregator

[uSWID-Link:ANYTHING]
href = https://hughski.com/
rel = see-also
"""
        component = uSwidFormatIni().load(ini.encode()).get_default()  # type: ignore
        self.assertIsNotNone(component)
        self.assertEqual(
            str(component),
            'uSwidComponent(tag_id="acbd84ff-9898-4922-8ade-dd4bbe2e40ba",tag_version="1",'
            'software_name="HughskiColorHug.efi",software_version="1.0.0"):\n'
            ' - uSwidLink(rel="see-also",href="https://hughski.com/")\n'
            ' - uSwidEntity(regid="hughsie.com",name="Richard Hughes",roles=[TAG_CREATOR,LICENSOR])\n'
            ' - uSwidEntity(regid="hughski.com",name="Hughski Limited",roles=[AGGREGATOR])',
        )

        # INI export
        tmp = uSwidFormatIni().save(uSwidContainer([component])).decode()
        assert "uSWID" in tmp
        assert "uSWID-Entity" in tmp
        assert "uSWID-Link" in tmp

        # SWID XML export
        component.colloquial_version = "22905301d08e69473393d94c3e787e4bf0453268"
        self.assertEqual(
            uSwidFormatSwid().save(uSwidContainer([component])),
            b"<?xml version='1.0' encoding='utf-8'?>\n"
            b"<SoftwareIdentity "
            b'xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" '
            b'xmlns:SHA256="http://www.w3.org/2001/04/xmlenc#sha256" '
            b'xmlns:SHA512="http://www.w3.org/2001/04/xmlenc#sha512" '
            b'xmlns:n8060="http://csrc.nist.gov/ns/swid/2015-extensions/1.0" '
            b'xml:lang="en-US" name="HughskiColorHug.efi" tagId="acbd84ff-9898-4922-8ade-dd4bbe2e40ba" '
            b'tagVersion="1" version="1.0.0">\n'
            b'  <Entity name="Richard Hughes" regid="hughsie.com" role="tagCreator licensor"/>\n'
            b'  <Entity name="Hughski Limited" regid="hughski.com" role="aggregator"/>\n'
            b'  <Link href="https://hughski.com/" rel="see-also"/>\n'
            b'  <Meta colloquialVersion="22905301d08e69473393d94c3e787e4bf0453268" '
            b'persistentId="org.hughski.colorhug" '
            b'type="firmware"/>\n'
            b"</SoftwareIdentity>\n",
        )

        # CycloneDX export
        tmp = uSwidFormatCycloneDX().save(uSwidContainer([component])).decode()
        assert "CycloneDX" in tmp
        assert "uSWID" in tmp
        assert "org.hughski.colorhug" in tmp
        assert "22905301d08e69473393d94c3e787e4bf0453268" in tmp
        assert "manufacturer" in tmp

        # SPDX export. Per UEFI SBOM Guidelines §3.1.2.2 the SPDX `supplier` field is
        # sourced from the SOFTWARE_CREATOR role; this fixture has only a LICENSOR
        # (Richard Hughes), so the SPDX writer emits `originator` for him instead.
        tmp = uSwidFormatSpdx().save(uSwidContainer([component])).decode()
        assert "SPDX" in tmp
        assert "uSWID" in tmp
        assert "originator" in tmp

    def test_cyclonedx_metadata_component_no_duplicate(self):
        """CycloneDX metadata.component should not duplicate components list"""

        jsonstr = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "component": {
                    "type": "application",
                    "name": "MyApp",
                    "version": "1.0",
                    "bom-ref": "myapp",
                },
                "authors": [{"name": "TagCreator"}],
            },
            "components": [
                {
                    "type": "application",
                    "name": "MyApp",
                    "version": "1.0",
                    "bom-ref": "myapp",
                }
            ],
        }
        container = uSwidFormatCycloneDX().load(json.dumps(jsonstr).encode())
        self.assertEqual(len(container), 1)
        component = container[0]
        self.assertEqual(component.tag_id, "myapp")
        self.assertEqual(component.software_name, "MyApp")
        self.assertTrue(
            any(
                e.name == "TagCreator" and uSwidEntityRole.TAG_CREATOR in e.roles
                for e in component.entities
            )
        )

    def test_cyclonedx_metadata_component_only(self):
        """CycloneDX metadata.component should load when components absent"""

        jsonstr = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "component": {
                    "type": "application",
                    "name": "MyApp",
                    "version": "1.0",
                    "bom-ref": "myapp",
                },
                "authors": [{"name": "TagCreator"}],
            },
        }
        container = uSwidFormatCycloneDX().load(json.dumps(jsonstr).encode())
        self.assertEqual(len(container), 1)
        component = container[0]
        self.assertEqual(component.tag_id, "myapp")
        self.assertEqual(component.software_name, "MyApp")
        self.assertTrue(
            any(
                e.name == "TagCreator" and uSwidEntityRole.TAG_CREATOR in e.roles
                for e in component.entities
            )
        )

    def test_cyclonedx_metadata_component_with_components(self):
        """CycloneDX metadata.component with extra components yields two entries"""

        jsonstr = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "component": {
                    "type": "application",
                    "name": "MyApp",
                    "version": "1.0",
                    "bom-ref": "myapp",
                },
                "authors": [{"name": "TagCreator"}],
            },
            "components": [
                {
                    "type": "library",
                    "name": "MyLib",
                    "version": "2.0",
                    "bom-ref": "mylib",
                }
            ],
        }
        container = uSwidFormatCycloneDX().load(json.dumps(jsonstr).encode())
        self.assertEqual(len(container), 2)
        self.assertIsNotNone(container.get_by_id("myapp"))
        self.assertIsNotNone(container.get_by_id("mylib"))

    def test_parse(self):
        """Unit tests for parsing PURL text"""
        purl = uSwidPurl("pkg:protocol/namespace/name@version?qualifiers#subpath")
        self.assertEqual(purl.scheme, "pkg")
        self.assertEqual(purl.protocol, "protocol")
        self.assertEqual(purl.namespace, "namespace")
        self.assertEqual(purl.name, "name")
        self.assertEqual(purl.version, "version")
        self.assertEqual(purl.qualifiers, "qualifiers")
        self.assertEqual(purl.subpath, "subpath")

        purl = uSwidPurl("pkg:protocol/name")
        self.assertEqual(purl.scheme, "pkg")
        self.assertEqual(purl.protocol, "protocol")
        self.assertEqual(purl.name, "name")

        purl = uSwidPurl("pkg:protocol/name@version")
        self.assertEqual(purl.scheme, "pkg")
        self.assertEqual(purl.protocol, "protocol")
        self.assertEqual(purl.namespace, None)
        self.assertEqual(purl.name, "name")
        self.assertEqual(purl.version, "version")
        self.assertEqual(purl.qualifiers, None)
        self.assertEqual(purl.subpath, None)

        purl = uSwidPurl("pkg:bcbd84ff-9898-4922-8ade-dd4bbe2e40ba@20230808")
        self.assertEqual(purl.scheme, "pkg")
        self.assertEqual(purl.protocol, None)
        self.assertEqual(purl.namespace, None)
        self.assertEqual(purl.name, "bcbd84ff-9898-4922-8ade-dd4bbe2e40ba")
        self.assertEqual(purl.version, "20230808")
        self.assertEqual(purl.qualifiers, None)
        self.assertEqual(purl.subpath, None)

    def test_spdx_single_package(self):
        """Unit tests for SPDX single package import"""
        jsonstr = {
            "spdxVersion": "SPDX-2.3",
            "creationInfo": {"creators": ["Organization: TagCo"]},
            "packages": [
                {
                    "SPDXID": "SPDXRef-pkgA",
                    "name": "pkgA",
                    "versionInfo": "1.2.3",
                    "summary": "Test package A",
                    "licenseDeclared": "BSD-2-Clause",
                    "originator": "Organization: OriginCorp",
                    "supplier": "Organization: SupplyCorp",
                }
            ],
        }
        container = uSwidFormatSpdx().load(json.dumps(jsonstr).encode())
        self.assertEqual(len(container), 1)
        comp = container[0]
        self.assertEqual(comp.tag_id, "pkgA")
        self.assertEqual(comp.software_name, "pkgA")
        self.assertEqual(comp.software_version, "1.2.3")
        # licenses extracted
        lic_ids = sorted(
            {l.spdx_id for l in comp.links if l.rel == uSwidLinkRel.LICENSE}
        )
        self.assertEqual(lic_ids, ["BSD-2-Clause"])
        # entity roles. Per UEFI SBOM Guidelines §3.1.2.2 the SPDX `supplier` field maps
        # to SOFTWARE_CREATOR (symmetric with CycloneDX) and `originator` maps to LICENSOR
        # (upstream / heritage origin).
        licensor_names = [
            e.name for e in comp.entities if uSwidEntityRole.LICENSOR in e.roles
        ]
        creator_names = [
            e.name for e in comp.entities if uSwidEntityRole.SOFTWARE_CREATOR in e.roles
        ]
        tag_creator_names = [
            e.name for e in comp.entities if uSwidEntityRole.TAG_CREATOR in e.roles
        ]
        self.assertEqual(licensor_names, ["OriginCorp"])
        self.assertEqual(creator_names, ["SupplyCorp"])
        self.assertEqual(tag_creator_names, ["TagCo"])

    def test_spdx_multiple_packages_with_dep(self):
        """Unit tests for SPDX multiple packages with dependencies"""
        jsonstr: dict[str, Any] = {
            "spdxVersion": "SPDX-2.3",
            "creationInfo": {"creators": ["Organization: TagCo"]},
            "packages": [
                {
                    "SPDXID": "SPDXRef-libX",
                    "name": "libX",
                    "versionInfo": "2.0.0",
                    "licenseDeclared": "BSD-2-Clause",
                },
                {
                    "SPDXID": "SPDXRef-appY",
                    "name": "appY",
                    "versionInfo": "5.1",
                    "licenseDeclared": "GPL-3.0-only",
                },
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-appY",
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": "SPDXRef-libX",
                }
            ],
        }
        container = uSwidFormatSpdx().load(json.dumps(jsonstr).encode())
        self.assertEqual(len(container), 2)
        lib = next(c for c in container if c.tag_id == "libX")
        app = next(c for c in container if c.tag_id == "appY")
        # dependency represented as COMPONENT link to libX (per current implementation fallback)
        self.assertTrue(
            any(l.rel == uSwidLinkRel.COMPONENT and l.href == "libX" for l in app.links)
        )
        # license links exist
        app_lic = [l.spdx_id for l in app.links if l.rel == uSwidLinkRel.LICENSE]
        lib_lic = [l.spdx_id for l in lib.links if l.rel == uSwidLinkRel.LICENSE]
        self.assertEqual(app_lic, ["GPL-3.0-only"])
        self.assertEqual(lib_lic, ["BSD-2-Clause"])
        # TAG_CREATOR added from creationInfo
        self.assertTrue(
            any(
                e.name == "TagCo" and uSwidEntityRole.TAG_CREATOR in e.roles
                for e in app.entities
            )
        )

    def test_spdx_duplicate_spdxid_unique_namespace(self):
        """Duplicate SPDXIDs should be unique when documentNamespace differs"""
        json_a = {
            "spdxVersion": "SPDX-2.3",
            "documentNamespace": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "creationInfo": {"creators": ["Organization: TagCo"]},
            "packages": [
                {
                    "SPDXID": "SPDXRef-dupPkg",
                    "name": "dupPkg",
                    "versionInfo": "1.0",
                }
            ],
        }
        json_b = {
            "spdxVersion": "SPDX-2.3",
            "documentNamespace": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "creationInfo": {"creators": ["Organization: TagCo"]},
            "packages": [
                {
                    "SPDXID": "SPDXRef-dupPkg",
                    "name": "dupPkg",
                    "versionInfo": "2.0",
                }
            ],
        }

        fmt = uSwidFormatSpdx()
        container_a = fmt.load(json.dumps(json_a))
        container_b = fmt.load(json.dumps(json_b))

        # consolidate into one container to simulate merged SBOMs
        merged = uSwidContainer()
        for comp in list(container_a) + list(container_b):
            if comp.tag_id and not merged.get_by_id(comp.tag_id):
                merged.append(comp)

        self.assertEqual(len(merged), 2)
        self.assertIsNotNone(
            merged.get_by_id("11111111-1111-1111-1111-111111111111:dupPkg")
        )
        self.assertIsNotNone(
            merged.get_by_id("22222222-2222-2222-2222-222222222222:dupPkg")
        )


class TestUefiSbomGuidelinesConformance(unittest.TestCase):
    """Conformance tests for the UEFI SBOM Guidelines (CISA Level 1).

    Each test method pins one row of `docs/uefi/conformance.md`. The fixture
    used by the end-to-end test is the section 3.1.8 example pair
    (EDK II as Primary Component + OpenSSL as a contained component).
    """

    maxDiff = None

    def _build_edk2_openssl_container(self) -> uSwidContainer:
        """Build the UEFI SBOM Guidelines §3.1.8 example container in memory.

        Primary component: EDK II (firmware), Tianocore supplier, BSD-2-Clause.
        Contained component: OpenSSL (library), OpenSSL Project supplier, Apache-2.0,
        linked from EDK II via uSwidLinkRel.COMPONENT to exercise dependency emission.
        """
        edk2 = uSwidComponent()
        edk2.tag_id = "pkg:github/tianocore/edk2@stable202411"
        edk2.cpe = "cpe:2.3:a:tianocore:edk2:stable202411:*:*:*:*:*:*:*"
        edk2.software_name = "EDK II"
        edk2.software_version = "stable202411"
        edk2.summary = "EDK II UEFI Firmware Development Environment"
        from .component import uSwidComponentType

        edk2.type = uSwidComponentType.FIRMWARE
        edk2.is_primary = True
        edk2.copyright = "Copyright (c) 2024 Tianocore."
        edk2.add_entity(
            uSwidEntity(
                name="Tianocore",
                email="contact@tianocore.org",
                roles=[uSwidEntityRole.SOFTWARE_CREATOR],
            )
        )
        edk2.add_entity(
            uSwidEntity(
                name="Tianocore Maintainers",
                email="devel@edk2.groups.io",
                roles=[uSwidEntityRole.TAG_CREATOR],
            )
        )
        edk2.add_link(
            uSwidLink(
                rel=uSwidLinkRel.LICENSE,
                href="https://spdx.org/licenses/BSD-2-Clause.html",
                spdx_id="BSD-2-Clause",
            )
        )

        openssl = uSwidComponent()
        openssl.tag_id = "pkg:github/openssl/openssl@3.0.15"
        openssl.cpe = "cpe:2.3:a:openssl:openssl:3.0.15:*:*:*:*:*:*:*"
        openssl.software_name = "OpenSSL"
        openssl.software_version = "3.0.15"
        openssl.summary = "Cryptography and SSL/TLS library used by EDK II"
        openssl.copyright = "Copyright (c) 1998-2024 The OpenSSL Project Authors"
        openssl.add_entity(
            uSwidEntity(
                name="OpenSSL Project",
                email="osslsec@openssl.org",
                roles=[uSwidEntityRole.SOFTWARE_CREATOR],
            )
        )
        openssl.add_link(
            uSwidLink(
                rel=uSwidLinkRel.LICENSE,
                href="https://spdx.org/licenses/Apache-2.0.html",
                spdx_id="Apache-2.0",
            )
        )
        edk2.add_link(
            uSwidLink(
                rel=uSwidLinkRel.COMPONENT,
                href=openssl.tag_id,
            )
        )

        return uSwidContainer([edk2, openssl])

    # ----- CycloneDX -----

    def test_cdx_dependencies_use_dependsOn_array(self):
        """UEFI §3.1.9 / CycloneDX 1.6: dependencies[*].dependsOn must be an array."""
        container = self._build_edk2_openssl_container()
        data = json.loads(uSwidFormatCycloneDX().save(container))
        self.assertIn("dependencies", data)
        self.assertTrue(data["dependencies"])
        for dep in data["dependencies"]:
            self.assertIn("ref", dep)
            self.assertIn("dependsOn", dep)
            self.assertIsInstance(dep["dependsOn"], list)
            for ref in dep["dependsOn"]:
                self.assertIsInstance(ref, str)
                self.assertTrue(ref)

    def test_cdx_primary_component_in_metadata_not_components_array(self):
        """UEFI §3.1.1.3: the Primary Component lives in metadata.component only."""
        container = self._build_edk2_openssl_container()
        data = json.loads(uSwidFormatCycloneDX().save(container))
        self.assertIn("component", data["metadata"])
        primary = data["metadata"]["component"]
        self.assertEqual(primary["name"], "EDK II")
        component_names = [c.get("name") for c in data.get("components", [])]
        self.assertNotIn("EDK II", component_names)
        self.assertIn("OpenSSL", component_names)

    def test_cdx_timestamp_ends_with_Z(self):
        """UEFI §3.1.1.2: metadata.timestamp must be ISO-8601 UTC with Z suffix."""
        import re as _re

        container = self._build_edk2_openssl_container()
        data = json.loads(uSwidFormatCycloneDX().save(container))
        ts = data["metadata"]["timestamp"]
        self.assertRegex(ts, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertTrue(ts.endswith("Z"))
        # extra: must be parseable as UTC
        self.assertEqual(_re.findall(r"[Z+\-]", ts)[-1], "Z")

    def test_cdx_supplier_contact_email_emitted(self):
        """UEFI §3.1.2.2: supplier email surfaces via supplier.contact[].email."""
        container = self._build_edk2_openssl_container()
        data = json.loads(uSwidFormatCycloneDX().save(container))
        primary = data["metadata"]["component"]
        self.assertEqual(primary["supplier"]["name"], "Tianocore")
        self.assertEqual(
            primary["supplier"]["contact"][0]["email"], "contact@tianocore.org"
        )
        # author email also surfaces at metadata.authors[].email
        authors = data["metadata"]["authors"]
        self.assertEqual(authors[0]["name"], "Tianocore Maintainers")
        self.assertEqual(authors[0]["email"], "devel@edk2.groups.io")

    def test_cdx_copyright_emitted_and_round_trips(self):
        """UEFI §3.1.11: component.copyright is emitted and reloads identical."""
        container = self._build_edk2_openssl_container()
        fmt = uSwidFormatCycloneDX()
        blob = fmt.save(container)
        data = json.loads(blob)
        self.assertEqual(
            data["metadata"]["component"]["copyright"],
            "Copyright (c) 2024 Tianocore.",
        )
        # round-trip
        reloaded = fmt.load(blob)
        primary = next(c for c in reloaded if c.is_primary)
        self.assertEqual(primary.copyright, "Copyright (c) 2024 Tianocore.")

    def test_cdx_lifecycle_phase_honors_sbom_type(self):
        """UEFI §3.1.1.3 Type: --sbom-type drives metadata.lifecycles[0].phase."""
        container = self._build_edk2_openssl_container()
        for sbom_type, expected_phase in (
            ("source", "pre-build"),
            ("build", "build"),
            ("binary", "post-build"),
        ):
            fmt = uSwidFormatCycloneDX()
            fmt.sbom_type = sbom_type
            data = json.loads(fmt.save(container))
            self.assertEqual(
                data["metadata"]["lifecycles"][0]["phase"],
                expected_phase,
                f"sbom_type={sbom_type} should map to phase={expected_phase}",
            )
        # explicit --lifecycle-phase overrides --sbom-type
        fmt = uSwidFormatCycloneDX()
        fmt.sbom_type = "source"
        fmt.lifecycle_phase = "post-build"
        data = json.loads(fmt.save(container))
        self.assertEqual(data["metadata"]["lifecycles"][0]["phase"], "post-build")

    def test_cdx_bom_ref_prefers_cpe(self):
        """UEFI §3.1.8: when a CPE is available, the bom-ref is the CPE."""
        container = self._build_edk2_openssl_container()
        data = json.loads(uSwidFormatCycloneDX().save(container))
        self.assertEqual(
            data["metadata"]["component"]["bom-ref"],
            "cpe:2.3:a:tianocore:edk2:stable202411:*:*:*:*:*:*:*",
        )
        openssl_dict = next(c for c in data["components"] if c["name"] == "OpenSSL")
        self.assertEqual(
            openssl_dict["bom-ref"], "cpe:2.3:a:openssl:openssl:3.0.15:*:*:*:*:*:*:*"
        )
        # dep refs use the same CPE-form so consumers can correlate consistently
        primary_ref = data["metadata"]["component"]["bom-ref"]
        primary_deps = next(
            d for d in data["dependencies"] if d["ref"] == primary_ref
        )
        self.assertIn(
            "cpe:2.3:a:openssl:openssl:3.0.15:*:*:*:*:*:*:*",
            primary_deps["dependsOn"],
        )

    # ----- SPDX -----

    def test_spdx_package_name_is_software_name(self):
        """UEFI §3.1.2.1: PackageName must be the supplier-defined software_name."""
        container = self._build_edk2_openssl_container()
        data = json.loads(uSwidFormatSpdx().save(container))
        names = sorted(pkg["name"] for pkg in data["packages"])
        self.assertEqual(names, ["EDK II", "OpenSSL"])

    def test_spdx_relationships_describes_and_contains(self):
        """UEFI §3.1.9: SPDX relationships[] emits DESCRIBES + CONTAINS edges."""
        container = self._build_edk2_openssl_container()
        data = json.loads(uSwidFormatSpdx().save(container))
        rels = data.get("relationships", [])
        rel_types = sorted(r["relationshipType"] for r in rels)
        self.assertEqual(rel_types, ["CONTAINS", "DESCRIBES"])
        describes = next(r for r in rels if r["relationshipType"] == "DESCRIBES")
        self.assertEqual(describes["spdxElementId"], "SPDXRef-DOCUMENT")
        # the DESCRIBES target must be a real package in the document
        package_spdxids = {pkg["SPDXID"] for pkg in data["packages"]}
        self.assertIn(describes["relatedSpdxElement"], package_spdxids)
        # the CONTAINS source is the primary; the target is OpenSSL.
        contains = next(r for r in rels if r["relationshipType"] == "CONTAINS")
        self.assertEqual(contains["spdxElementId"], describes["relatedSpdxElement"])
        self.assertIn(contains["relatedSpdxElement"], package_spdxids)

    def test_spdx_license_concluded_and_copyright_text(self):
        """UEFI §3.1.10 / §3.1.11: emit LicenseConcluded and PackageCopyrightText."""
        container = self._build_edk2_openssl_container()
        data = json.loads(uSwidFormatSpdx().save(container))
        for pkg in data["packages"]:
            self.assertIn("licenseConcluded", pkg)
            self.assertNotEqual(pkg["licenseConcluded"], "")
            self.assertIn("copyrightText", pkg)
        edk2_pkg = next(p for p in data["packages"] if p["name"] == "EDK II")
        self.assertEqual(edk2_pkg["licenseConcluded"], "BSD-2-Clause")
        self.assertEqual(edk2_pkg["licenseDeclared"], "BSD-2-Clause")
        self.assertEqual(edk2_pkg["copyrightText"], "Copyright (c) 2024 Tianocore.")

    def test_spdx_created_timestamp_is_tz_aware_Z(self):
        """UEFI §3.1.1.2: SPDX creationInfo.created uses UTC with Z."""
        container = self._build_edk2_openssl_container()
        data = json.loads(uSwidFormatSpdx().save(container))
        ts = data["creationInfo"]["created"]
        self.assertRegex(ts, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_spdx_supplier_symmetric_with_cdx(self):
        """The same container produces consistent supplier names in CDX and SPDX."""
        container = self._build_edk2_openssl_container()
        cdx = json.loads(uSwidFormatCycloneDX().save(container))
        spdx = json.loads(uSwidFormatSpdx().save(container))
        cdx_edk2_supplier = cdx["metadata"]["component"]["supplier"]["name"]
        spdx_edk2_pkg = next(p for p in spdx["packages"] if p["name"] == "EDK II")
        # SPDX supplier is rendered "Organization: <name> <email>"
        self.assertTrue(
            spdx_edk2_pkg["supplier"].startswith(f"Organization: {cdx_edk2_supplier}")
            or spdx_edk2_pkg["supplier"].startswith(f"Person: {cdx_edk2_supplier}")
        )
        self.assertIn("contact@tianocore.org", spdx_edk2_pkg["supplier"])

    def test_spdx_spdxid_sanitized(self):
        """UEFI §3.1.8: SPDXID strips disallowed chars from PURL/CPE tag_ids."""
        container = self._build_edk2_openssl_container()
        data = json.loads(uSwidFormatSpdx().save(container))
        for pkg in data["packages"]:
            spdxid = pkg["SPDXID"]
            self.assertTrue(spdxid.startswith("SPDXRef-"))
            self.assertRegex(spdxid, r"^SPDXRef-[A-Za-z0-9][A-Za-z0-9.-]*$")
        # purl/cpe still recoverable via externalRefs
        primary_pkg = next(p for p in data["packages"] if p["name"] == "EDK II")
        ref_locators = {r["referenceLocator"] for r in primary_pkg["externalRefs"]}
        self.assertIn("pkg:github/tianocore/edk2@stable202411", ref_locators)
        self.assertIn(
            "cpe:2.3:a:tianocore:edk2:stable202411:*:*:*:*:*:*:*", ref_locators
        )

    def test_spdx_round_trip_preserves_primary(self):
        """Round-trip: loading the saved SPDX recovers `is_primary` on EDK II."""
        container = self._build_edk2_openssl_container()
        fmt = uSwidFormatSpdx()
        blob = fmt.save(container)
        reloaded = fmt.load(blob)
        primaries = [c for c in reloaded if c.is_primary]
        self.assertEqual(len(primaries), 1)
        self.assertEqual(primaries[0].software_name, "EDK II")

    # ----- end-to-end §3.1.8 sample, structural + round-trip -----

    def test_section_3_1_8_end_to_end_cdx_and_spdx(self):
        """Section 3.1.8 EDK II + OpenSSL sample parses, validates structurally,
        and round-trips both CycloneDX and SPDX without losing identity."""
        container = self._build_edk2_openssl_container()

        # CDX
        cdx_fmt = uSwidFormatCycloneDX()
        cdx_blob = cdx_fmt.save(container)
        cdx = json.loads(cdx_blob)
        self.assertEqual(cdx["bomFormat"], "CycloneDX")
        self.assertEqual(cdx["specVersion"], "1.6")
        self.assertIn("metadata", cdx)
        self.assertIn("component", cdx["metadata"])
        self.assertEqual(cdx["metadata"]["component"]["name"], "EDK II")
        # exactly one non-primary component (OpenSSL)
        self.assertEqual(len(cdx["components"]), 1)
        self.assertEqual(cdx["components"][0]["name"], "OpenSSL")
        # dep array structure
        self.assertTrue(cdx["dependencies"])
        for dep in cdx["dependencies"]:
            self.assertIsInstance(dep["dependsOn"], list)

        # CDX round-trip
        cdx_reloaded = cdx_fmt.load(cdx_blob)
        primary_round = next(c for c in cdx_reloaded if c.is_primary)
        self.assertEqual(primary_round.software_name, "EDK II")
        names_round = sorted(c.software_name for c in cdx_reloaded)
        self.assertEqual(names_round, ["EDK II", "OpenSSL"])

        # SPDX
        spdx_fmt = uSwidFormatSpdx()
        spdx_blob = spdx_fmt.save(container)
        spdx = json.loads(spdx_blob)
        self.assertEqual(spdx["spdxVersion"], "SPDX-2.3")
        self.assertEqual(len(spdx["packages"]), 2)
        rel_types = sorted(
            r["relationshipType"] for r in spdx.get("relationships", [])
        )
        self.assertEqual(rel_types, ["CONTAINS", "DESCRIBES"])

        # SPDX round-trip
        spdx_reloaded = spdx_fmt.load(spdx_blob)
        names_spdx_round = sorted(c.software_name for c in spdx_reloaded)
        self.assertEqual(names_spdx_round, ["EDK II", "OpenSSL"])
        spdx_primary = next(c for c in spdx_reloaded if c.is_primary)
        self.assertEqual(spdx_primary.software_name, "EDK II")


if __name__ == "__main__":
    unittest.main()
