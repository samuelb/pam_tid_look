#!/bin/bash
# Renders the Homebrew formula for a release, in a tap's layout:
#
#   ./render_formula.sh VERSION SHA256 DIR
#
# writes DIR/Formula/pam_tidcmd.rb: Formula/pam_tidcmd.rb with url set to the
# source archive of the tag vVERSION and sha256 to SHA256, that archive's
# checksum. VERSION is X.Y.Z, without the v. Nothing else in the formula
# changes. The release workflow (.github/workflows/release.yml) publishes DIR
# to samuelb/homebrew-tap.
#
# Modelled on scripts/render-formula.sh in
# https://github.com/samuelb/macos-sudo-touchid-context, which is under the MIT
# License, Copyright (c) 2026 Lauri Gates.

set -euo pipefail

usage="usage: $0 VERSION SHA256 DIR"
die() {
    echo "render_formula: $*" >&2
    exit 1
}

[ $# -eq 3 ] || die "$usage"
version=$1
sha256=$2
dir=$3

version_re='^[0-9]+\.[0-9]+\.[0-9]+$'
sha256_re='^[0-9a-f]{64}$'
[[ $version =~ $version_re ]] || die "VERSION must be X.Y.Z, not '$version'"
[[ $sha256 =~ $sha256_re ]] || die "SHA256 must be 64 lowercase hex digits, not '$sha256'"

src="$(cd "$(dirname "$0")" && pwd)/Formula/pam_tidcmd.rb"
archive=https://github.com/samuelb/pam_tidcmd/archive/refs/tags
url_line="  url \"$archive/v$version.tar.gz\""
sha256_line="  sha256 \"$sha256\""

# The lines to replace, in the form the formula has them. Exactly one each, so
# that a changed formula stops the release instead of going out half rendered.
url_re="^  url \"$archive/v[0-9]+\\.[0-9]+\\.[0-9]+\\.tar\\.gz\"\$"
old_sha256_re='^  sha256 "[0-9a-f]{64}"$'
[ "$(grep -c -E "$url_re" "$src")" = 1 ] ||
    die "$src needs exactly one line of the form: ${url_line/$version/X.Y.Z}"
[ "$(grep -c -E "$old_sha256_re" "$src")" = 1 ] ||
    die "$src needs exactly one line of the form: ${sha256_line/$sha256/<64 hex digits>}"

mkdir -p "$dir/Formula"
out=$dir/Formula/pam_tidcmd.rb
sed -E -e "s|$url_re|$url_line|" -e "s|$old_sha256_re|$sha256_line|" "$src" >"$out.tmp"
if ! grep -qxF "$url_line" "$out.tmp" || ! grep -qxF "$sha256_line" "$out.tmp"; then
    rm -f "$out.tmp"
    die "could not set url and sha256 in $out"
fi
mv "$out.tmp" "$out"
echo "$out"
