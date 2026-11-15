#!/bin/bash
# Tests scripts/render_formula.sh, which the release workflow runs on a tag: that it
# sets url and sha256 and changes nothing else, and that it refuses a bad
# version, a bad checksum and a formula whose lines are not in the form it
# replaces. Needs no network and no root.

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/pam_tid_look_render.XXXXXX")
trap 'rm -rf "$work"' EXIT
failures=0
status=0
out=

check() { # label, then a command that must succeed
    local label=$1
    shift
    if "$@"; then
        echo "ok    $label"
    else
        echo "FAIL  $label"
        [ -z "$out" ] || printf '%s\n' "$out" | sed 's/^/      /'
        failures=$((failures + 1))
    fi
}

render() { # runs the script in $1 with the rest as arguments
    local script=$1
    shift
    status=0
    out=$(/bin/bash "$script" "$@" 2>&1) || status=$?
}

said() { case $out in *"$1"*) return 0 ;; esac; return 1; }
lacks() { ! grep -q "$1" "$2"; }

sum=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
url=https://github.com/samuelb/pam_tid_look/archive/refs/tags/v1.22.333.tar.gz
formula=$root/Formula/pam_tid_look.rb
script=$root/scripts/render_formula.sh

check "render_formula.sh is executable, as the release runs it" [ -x "$script" ]
render "$script" 1.22.333 "$sum" "$work/tap"
rendered=$work/tap/Formula/pam_tid_look.rb
check "a release renders" [ "$status" = 0 ]
check "  and prints the formula's path" [ "$out" = "$rendered" ]
check "  with the tag's url" grep -qxF "  url \"$url\"" "$rendered"
check "  and the checksum" grep -qxF "  sha256 \"$sum\"" "$rendered"
changed=$(diff "$formula" "$rendered" | grep -c '^[<>]' || true)
check "  and no other line changed" [ "$changed" = 4 ]
check "  and no OWNER placeholder is left" lacks OWNER "$rendered"

for bad in v1.2.3 1.2 1.2.3-rc1 ""; do
    render "$script" "$bad" "$sum" "$work/bad"
    check "version '$bad' is refused" [ "$status" = 1 ]
done
for bad in "${sum%?}" "${sum}0" "$(echo "$sum" | tr a-f A-F)" "${sum%?}g"; do
    render "$script" 1.2.3 "$bad" "$work/bad"
    check "checksum '$bad' is refused" [ "$status" = 1 ]
done
render "$script" 1.2.3 "$sum"
check "a missing argument is refused" [ "$status" = 1 ]
check "  with the usage" said "usage:"
check "  and nothing was written" [ ! -e "$work/bad" ]

# A copy of the script with formulas it cannot render.
mkdir -p "$work/copy/Formula" "$work/copy/scripts"
cp "$script" "$work/copy/scripts/"
for case in "another url:s|/refs/tags/v[0-9.]*[.]tar|/refs/heads/main.tar|" "two urls:/^  url /p" \
    "no sha256:/^  sha256 /d" "two sha256s:/^  sha256 /p"; do
    rm -rf "${work:?}/copy/out"
    sed -e "${case#*:}" "$formula" >"$work/copy/Formula/pam_tid_look.rb"
    render "$work/copy/scripts/render_formula.sh" 1.2.3 "$sum" "$work/copy/out"
    check "a formula with ${case%%:*} is refused" [ "$status" = 1 ]
    check "  and nothing is written" [ ! -e "$work/copy/out/Formula/pam_tid_look.rb" ]
done

echo
if [ "$failures" = 0 ]; then
    echo "All formula tests passed."
else
    echo "$failures formula tests failed."
    exit 1
fi
