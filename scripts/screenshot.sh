#!/bin/bash
#
# Takes a screenshot of the Touch ID dialog that sudo shows with
# pam_tid_look, for the README.
#
#   scripts/screenshot.sh [-o FILE] [-C DIRECTORY] [--] [SUDO-ARGUMENT...]
#
# It runs `sudo SUDO-ARGUMENT...` in DIRECTORY with the module that is installed in
# /etc/pam.d/sudo_local, waits for the dialog, saves that one window as a PNG
# to FILE, and withdraws the dialog by killing sudo. Do not answer the
# dialog: approving it runs the command as root.
#
#   -o FILE       where to save it (default: docs/sudo-dialog.png in the
#                 repository)
#   -C DIRECTORY  the directory sudo runs in, shown as "Directory" (default:
#                 the current one)
#   SUDO-ARGUMENT what sudo is given: options, then the command (default: what
#                 Homebrew runs to install a cask's package, below)
#
# By default, the dialog is the one `brew install --cask zoom` raises: Homebrew
# runs the cask's installer package with sudo, as
#
#   sudo -u root -E LOGNAME=you USER=you USERNAME=you -- \
#       /usr/sbin/installer -pkg PREFIX/Caskroom/zoom/VERSION/zoomusInstallerFull.pkg -target /
#
# (SystemCommand#sudo_prefix and Cask::Artifact::Pkg#run_installer in
# Homebrew). The package does not exist, so if the dialog is approved by
# mistake, installer finds nothing to install. The script checks that first.
#
# Run it from a terminal, not from make: the dialog's "Requested by" line
# names the processes that led to sudo, this script's bash first. The
# terminal app needs the Screen Recording permission (System Settings >
# Privacy & Security). The dialog is drawn in the current appearance; switch
# between light and dark to take both.
#
# Before it starts sudo, it runs `sudo -K`, which needs no password, so that
# a cached sudo credential cannot run the command without a dialog. That also
# ends any sudo session you have open in other terminals.

set -euo pipefail

usage() {
    echo "usage: $0 [-o FILE] [-C DIRECTORY] [--] [SUDO-ARGUMENT...]" >&2
    exit 2
}

root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/docs/sudo-dialog.png"
dir=$PWD
while getopts "o:C:h" opt; do
    case $opt in
        o) out=$OPTARG ;;
        C) dir=$OPTARG ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))

die() {
    echo "$0: $*" >&2
    exit 1
}

if [[ $# -eq 0 ]]; then
    user=$(id -un)
    prefix=$(brew --prefix 2>/dev/null || echo /opt/homebrew)
    pkg="$prefix/Caskroom/zoom/7.2.5.90525/zoomusInstallerFull.pkg"
    [[ ! -e $pkg ]] || die "$pkg exists, so approving the dialog would install it; pass another command"
    set -- -u root -E "LOGNAME=$user" "USER=$user" "USERNAME=$user" -- /usr/sbin/installer -pkg "$pkg" -target /
fi

# JavaScript for Automation, run by osascript. It reaches CoreGraphics
# without a compiled helper.
jxa() {
    /usr/bin/osascript -l JavaScript -e "$1"
}

# Whether the terminal app may record the screen. Without it, screencapture
# saves the desktop behind the dialog.
can_record() {
    [[ $(jxa 'ObjC.import("CoreGraphics");
        ObjC.bindFunction("CGPreflightScreenCaptureAccess", ["bool", []]);
        $.CGPreflightScreenCaptureAccess()') == true ]]
}

# The on-screen SecurityAgent windows, one per line: "ID WIDTHxHEIGHT", in
# points. Reading owners and sizes needs no permission.
agent_windows() {
    jxa 'ObjC.import("CoreGraphics");
        const list = ObjC.castRefToObject($.CGWindowListCopyWindowInfo(
            $.kCGWindowListOptionOnScreenOnly, $.kCGNullWindowID));
        const found = [];
        for (let i = 0; i < list.count; i++) {
            const w = list.objectAtIndex(i);
            if (ObjC.unwrap(w.objectForKey("kCGWindowOwnerName")) !== "SecurityAgent") continue;
            const b = w.objectForKey("kCGWindowBounds");
            found.push(ObjC.unwrap(w.objectForKey("kCGWindowNumber")) + " " +
                ObjC.unwrap(b.objectForKey("Width")) + "x" + ObjC.unwrap(b.objectForKey("Height")));
        }
        found.join("\n")'
}

# The line for window ID in agent_windows' output, or nothing.
window_line() {
    grep -E "^$1 " <<<"$2" || true
}

grep -Eq '^[[:space:]]*auth[[:space:]].*pam_tid_look[.]so' /etc/pam.d/sudo_local 2>/dev/null ||
    die "pam_tid_look is not active in /etc/pam.d/sudo_local; install it first"
[[ -d $dir ]] || die "$dir: no such directory"
can_record ||
    die "this terminal may not record the screen; allow it in System Settings > Privacy & Security > Screen Recording, then restart it"
mkdir -p "$(dirname "$out")"

/usr/bin/sudo -K

before=$(agent_windows | cut -d' ' -f1)

# sudo runs in a session of its own, with no controlling terminal, so that it
# cannot fall back to asking for the password here if no dialog appears.
# perl's exec keeps the process, so sudo's parent is still this script.
(
    cd "$dir"
    exec /usr/bin/perl -MPOSIX -e 'POSIX::setsid(); exec { $ARGV[0] } @ARGV or die "$ARGV[0]: $!\n"' \
        /usr/bin/sudo "$@"
) </dev/null >/dev/null 2>&1 &
pid=$!

# Whether sudo is still running. ps rather than kill -0, which a setuid
# process may refuse.
running() {
    local state
    state=$(ps -o state= -p "$pid" 2>/dev/null) && [[ $state != Z* ]]
}

# Kills sudo if it is still waiting, then waits for its dialog to close.
# SIGKILL, because sudo ignores SIGINT and SIGTERM until it has authenticated.
window=
cleanup() {
    if running; then
        kill -KILL "$pid" 2>/dev/null || echo "$0: could not end sudo ($pid); end it, then cancel its dialog" >&2
    fi
    wait "$pid" 2>/dev/null || true
    for _ in {1..30}; do
        [[ -n $window && -n $(window_line "$window" "$(agent_windows)") ]] || return 0
        sleep 0.1
    done
    echo "$0: the dialog is still open; cancel it" >&2
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

echo "Waiting for the dialog. Do not answer it."

# Wait up to 10 s for a new SecurityAgent window, then for its size to stay
# the same for half a second: the dialog grows to fit the text.
last='' steady=0
for _ in {1..100}; do
    sleep 0.1
    running || die "sudo ended without a dialog; is Touch ID available, and does the command exist?"
    windows=$(agent_windows)
    if [[ -z $window ]]; then
        while read -r id _; do
            if [[ -n $id ]] && ! grep -qx "$id" <<<"$before"; then
                window=$id
                break
            fi
        done <<<"$windows"
        continue
    fi
    line=$(window_line "$window" "$windows")
    [[ -n $line ]] || die "the dialog closed before it could be captured; was it answered?"
    if [[ $line == "$last" ]]; then
        steady=$((steady + 1))
    else
        steady=0 last=$line
    fi
    ((steady < 5)) || break
done
[[ -n $window ]] || die "no dialog appeared within 10 seconds"
((steady >= 5)) || die "the dialog did not stop changing size"

# Let the dialog finish fading in.
sleep 0.5
/usr/sbin/screencapture -x -l "$window" "$out"
[[ -s $out ]] || die "screencapture saved nothing"

# The PNG has the screen's pixels, twice the points on a Retina display, and
# says so in its DPI (144 for 2x). The README's <img> sets the width in
# points, so that it shows at its real size.
pixels=$(sips -g pixelWidth "$out" | awk '/pixelWidth/ { print $2 }')
dpi=$(sips -g dpiWidth "$out" | awk '/dpiWidth/ { print int($2) }')
points=$((pixels * 72 / (dpi > 0 ? dpi : 72)))
echo "Saved $out, $points points wide: set width=\"$points\" on the README's <img>."
