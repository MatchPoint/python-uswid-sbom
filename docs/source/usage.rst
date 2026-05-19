Basic API usage
===============

Loading components from a uSWID-format container:

.. code-block:: python

    from uswid import uSwidFormatUswid

    with open(filename, "rb") as f:
        for component in uSwidFormatUswid().load(f.read()):
            print(f"{component!s}")

Loading components from a possible PE file:

.. code-block:: python

    import pefile
    from uswid import uSwidFormatCoswid

    try:
        with open(filename, "rb") as f:
            pe = pefile.PE(data=f.read())
        for sect in pe.sections:
            if sect.Name == b".sbom\0\0\0":
                for component in uSwidFormatCoswid().load(sect.get_data()):
                    print(f"{component!s}")
    except pefile.PEFormatError:
        # not a PE file, which is fine
        pass

Creating a new component, entity and payload:

.. code-block:: python

    from uswid import (
        uSwidComponent,
        uSwidEntity,
        uSwidEntityRole,
        uSwidPayload,
        uSwidHash,
    )

    component = uSwidComponent(
        tag_id="foo",
        software_name="bar",
        software_version="baz",
    )
    component.add_entity(
        uSwidEntity(
            name="me",
            regid="example.domain",
            roles=[uSwidEntityRole.TAG_CREATOR, uSwidEntityRole.DISTRIBUTOR],
        )
    )
    payload = uSwidPayload(name="foo.bin", size=123)
    payload.add_hash(
        uSwidHash(
            alg_id=uSwidHashAlg.SHA256,
            value="067cb8292dc062eabbe05734ef7987eb1333b6b6",
        )
    )
    component.add_payload(payload)

Saving all three to an XML SWID file:

.. code-block:: python

    from uswid import uSwidContainer, uSwidFormatSwid

    with open(filename, "rw") as f:
        f.write(uSwidFormatSwid().save(uSwidContainer([component])))


Git submodules (library API)
---------------------------

This fork adds :mod:`uswid.submodule` for working with ``.gitmodules`` trees in a project-agnostic way: URL canonicalisation, recursive walks, ``git describe`` normalisation for NVD/CPE-friendly versions, and building :class:`uswid.component.uSwidComponent` instances for each submodule. EDK II–specific helpers and package lists are in :mod:`uswid.edk2`.

See :doc:`versionhistory` (v0.2.0) for the CLI flag ``--primary-dir``, which re-merges ``--fallback-path`` templates against submodule checkouts and prepares a container for ``--fixup``.

``patches_for_commits_since_tag`` (v0.2.1) walks ``git log <tag>..HEAD`` and emits one CycloneDX pedigree patch per commit: ``security`` when the message contains a CVE ID, otherwise ``cherry-pick`` (commits applied on top of the last upstream release tag, e.g. cmocka at ``1.1.5`` with 23 post-tag commits).

