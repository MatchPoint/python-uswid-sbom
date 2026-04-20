# Release Process

## Pre-Release

Write NEWS entries in the same format as usual:

    git shortlog <last-tag>.. | grep -i -v trivial | grep -v Merge > NEWS.new
    # add entries to ./docs/source/versionhistory.rst

## Release

Commit changes and create an annotated git tag
(package version is auto-derived from the tag):

    git commit -a -m "Release X.Y.Z"
    git tag -s -m "Release X.Y.Z" X.Y.Z
    rm -rf dist/
    make pkg
    ./env/bin/twine upload dist/uswid-*

## Post-Release

Push commits and tags:

    git push
    git push --tags

## Notes

- Version is automatically derived from git tags using setuptools_scm
- `uswid/_version.py` is generated at build time
- No manual version updates are required
- Release flow: commit → tag → build → upload
