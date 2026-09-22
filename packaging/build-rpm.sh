#!/usr/bin/env bash
# Build a noarch RPM into ./dist. Version comes from pornblock.py.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."

command -v rpmbuild >/dev/null 2>&1 || {
  echo "rpmbuild is missing:  sudo dnf install rpm-build" >&2; exit 1; }

NAME=christwatch
VER="$(grep -m1 '^VERSION = ' pornblock.py | cut -d'"' -f2)"
[ -n "$VER" ] || { echo "could not read VERSION from pornblock.py" >&2; exit 1; }

TOP="$(mktemp -d)"
trap 'rm -rf "$TOP"' EXIT
mkdir -p "$TOP"/{SOURCES,SPECS,BUILD,BUILDROOT,RPMS,SRPMS}

STAGE="$TOP/$NAME-$VER"
mkdir -p "$STAGE"
cp pornblock.py pornblock_gui.py selftest.py guitest.py README.md LICENSE "$STAGE/"
tar -czf "$TOP/SOURCES/$NAME-$VER.tar.gz" -C "$TOP" "$NAME-$VER"

sed "s/^Version:.*/Version:        $VER/" packaging/christwatch.spec \
    > "$TOP/SPECS/$NAME.spec"

rpmbuild --define "_topdir $TOP" -bb "$TOP/SPECS/$NAME.spec"

mkdir -p dist
cp "$TOP"/RPMS/noarch/*.rpm dist/
echo
echo "built: $(ls dist/${NAME}-${VER}*.rpm)"
echo "install it by double-clicking, or:  sudo dnf install ./dist/${NAME}-${VER}*.rpm"
