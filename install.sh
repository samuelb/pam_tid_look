#!/bin/bash
# Installs or removes pam_tidcmd for sudo.
#
#   sudo ./install.sh                 install, then ask you to confirm sudo still works
#   sudo ./install.sh --timeout 60    the same, with the dialog waiting 60 seconds
#   sudo ./install.sh uninstall       go back to Apple's pam_tid.so
#
# Only /etc/pam.d/sudo_local is edited. If you do not confirm that sudo works
# within five minutes, the previous file is put back.
#
# --timeout sets how long the Touch ID dialog waits for a fingerprint before
# it closes and sudo asks for the password: 0 to 3600 seconds, 0 for no limit.
# Without it, a reinstall keeps the current setting and a first install
# leaves the module's default.

set -euo pipefail

DEST_DIR=/Library/Security/pam_tidcmd
DEST=$DEST_DIR/pam_tidcmd.so
PREVIOUS=$DEST_DIR/.pam_tidcmd.so.previous
CONF=/etc/pam.d/sudo_local
LOCK=/var/run/pam_tidcmd.install.lock
TAG='#pam_tidcmd# '
SRC="$(cd "$(dirname "$0")" && pwd)/pam_tidcmd.so"

# Module fields ($3) naming Apple's module and this one. Brackets, not
# backslashes, because awk -v would interpret backslashes.
TID_RE='(^|/)pam_tid[.]so([.][0-9]+)?$'
TIDCMD_RE='(^|/)pam_tidcmd[.]so$'
DEFAULT_TIMEOUT=30 # kDefaultTimeout in pam_tidcmd.m

usage() {
    echo "usage: sudo $0 [install] [--timeout SECONDS] | uninstall" >&2
    exit 2
}

# The same rule as the module: at most four digits, 3600 at most.
valid_timeout() {
    [[ $1 =~ ^[0-9]{1,4}$ ]] && [ $((10#$1)) -le 3600 ]
}

action=install
timeout=
timeout_given=0
while [ $# -gt 0 ]; do
    case $1 in
    install | uninstall) action=$1 ;;
    --timeout)
        [ $# -ge 2 ] || usage
        timeout=$2
        timeout_given=1
        shift
        ;;
    --timeout=*)
        timeout=${1#--timeout=}
        timeout_given=1
        ;;
    *) usage ;;
    esac
    shift
done
if [ "$timeout_given" = 1 ]; then
    if [ "$action" != install ] || ! valid_timeout "$timeout"; then
        echo "--timeout takes 0 to 3600 seconds, and only when installing." >&2
        exit 2
    fi
    timeout=$((10#$timeout))
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this with sudo." >&2
    exit 1
fi

write_conf() { # $1: function printing the new contents; CONF is replaced only if it succeeds
    local tmp
    tmp=$(mktemp "$CONF.XXXXXX")
    if ! "$1" > "$tmp"; then
        rm -f "$tmp"
        echo "Could not work out the new $CONF; it was left as it was." >&2
        return 1
    fi
    chown root:wheel "$tmp"
    chmod 444 "$tmp"
    mv -f "$tmp" "$CONF"
}

# Modules are recognised by the module field of an auth line ($3), never by a
# mention elsewhere on the line, such as in a comment.
without_tidcmd() { # prints the config with this module removed and pam_tid.so restored
    [ -f "$CONF" ] || return 0
    awk -v tag="$TAG" -v re="$TIDCMD_RE" '
        $1 == "auth" && $3 ~ re { next }
        index($0, tag) == 1 { print substr($0, length(tag) + 1); next }
        { print }
    ' "$CONF"
}

# The last timeout= value on the current pam_tidcmd line, if any. OpenPAM
# ends a line at the first #, even inside a word, so that is cut off first.
current_timeout() {
    [ -f "$CONF" ] || return 0
    awk -v re="$TIDCMD_RE" '
        { line = $0; sub(/#.*/, "", line); n = split(line, f) }
        f[1] == "auth" && f[3] ~ re { for (i = 4; i <= n; i++) if (f[i] ~ /^timeout=/) t = substr(f[i], 9) }
        END { print t }
    ' "$CONF"
}

# The new line takes the place of the pam_tid.so line, with its control flag.
# Without one, it is added at the end as sufficient. $options goes after the
# module path.
with_tidcmd() { # prints the config with pam_tid.so replaced by this module
    without_tidcmd | awk -v dest="$DEST" -v opts="$options" -v tag="$TAG" -v re="$TID_RE" '
        $1 == "auth" && $3 ~ re {
            if (!placed) { printf "auth       %-14s %s%s\n", $2, dest, opts; placed = 1 }
            print tag $0
            next
        }
        { print }
        END { if (!placed) printf "auth       %-14s %s%s\n", "sufficient", dest, opts }
    '
}

# One run at a time, so a run waiting for confirmation keeps its backups. A
# lock left by a killed run is not taken over: two runs could both decide it
# is stale and both proceed.
lock() {
    if ! mkdir "$LOCK" 2>/dev/null; then
        local holder
        holder=$(cat "$LOCK/pid" 2>/dev/null || true)
        echo "Another install.sh holds $LOCK (pid ${holder:-unknown})." >&2
        echo "If none is running, remove it with: sudo rm -r $LOCK" >&2
        exit 1
    fi
    echo $$ > "$LOCK/pid"
    trap finish EXIT
}

pending=0 # 1 while an install can still be rolled back
finish() {
    if [ "$pending" = 1 ]; then
        restore
    fi
    rm -rf "$LOCK"
}

case "$action" in
install)
    if [ ! -f "$SRC" ]; then
        echo "pam_tidcmd.so not found next to this script. Run 'make' first." >&2
        exit 1
    fi

    # The module must not be replaceable by a non-root process. Each
    # inspection is an assignment, so if one fails, set -e stops the script
    # instead of the check passing. ls -le lists ACL entries after the
    # file's own line.
    for dir in /Library /Library/Security; do
        owner=$(stat -f '%u' "$dir")
        writable=$(find "$dir" -maxdepth 0 -perm +022)
        acl=$(/bin/ls -lde "$dir" | sed 1d)
        if [ "$owner" != 0 ] || [ -n "$writable" ] || [[ $acl == *" allow "* ]]; then
            echo "$dir is not owned by root, is group/world writable or has an ACL; refusing to install." >&2
            exit 1
        fi
    done

    lock

    # One replacement line cannot keep the meaning of several pam_tid.so lines.
    count=$(without_tidcmd | awk -v re="$TID_RE" '$1 == "auth" && $3 ~ re { n++ } END { print n + 0 }')
    if [ "$count" -gt 1 ]; then
        echo "$CONF has $count active pam_tid.so lines. Leave one and run this again." >&2
        exit 1
    fi

    if [ "$timeout_given" = 0 ]; then
        timeout=$(current_timeout)
        if [ -n "$timeout" ] && ! valid_timeout "$timeout"; then
            echo "$CONF sets timeout=$timeout, which is not 0 to 3600 seconds. Pass --timeout." >&2
            exit 1
        fi
        [ -z "$timeout" ] || timeout=$((10#$timeout))
    fi
    options=${timeout:+ timeout=$timeout}

    install -d -o root -g wheel -m 755 "$DEST_DIR"
    chmod -N "$DEST_DIR"

    # Keep what is there now, module and config, before changing either.
    saved=$(mktemp /etc/pam.d/.sudo_local.saved.XXXXXX)
    had_conf=0
    if [ -f "$CONF" ]; then
        had_conf=1
        cp -p "$CONF" "$saved"
    fi
    had_module=0
    if [ -f "$DEST" ]; then
        had_module=1
        ln -f "$DEST" "$PREVIOUS"
    fi
    new_module=
    restore() {
        [ -z "$new_module" ] || rm -f "$new_module"
        if [ "$had_module" = 1 ]; then
            mv -f "$PREVIOUS" "$DEST"
        fi
        if [ "$had_conf" = 1 ]; then
            mv -f "$saved" "$CONF"
        else
            rm -f "$CONF" "$saved"
        fi
        if [ "$had_module" = 0 ]; then
            rm -f "$DEST"
        fi
        echo "Previous $CONF and module restored."
    }
    pending=1

    # Not install(1): it copies ACLs from the user-owned build, which could let
    # that user rewrite the module. mktemp creates a root-owned file without one.
    new_module=$(mktemp "$DEST_DIR/.pam_tidcmd.so.XXXXXX")
    cat "$SRC" > "$new_module"
    chmod -N "$new_module"
    chown root:wheel "$new_module"
    chmod 444 "$new_module"
    mv -f "$new_module" "$DEST"
    new_module=

    write_conf with_tidcmd

    if [ "${timeout:-$DEFAULT_TIMEOUT}" = 0 ]; then
        closes="It stays open until you answer it (timeout=0)."
    else
        closes="Left alone, it closes after ${timeout:-$DEFAULT_TIMEOUT} seconds and sudo asks for the password."
    fi
    cat <<EOF

Installed. $CONF now reads:

$(sed 's/^/    /' "$CONF")

Now open a NEW terminal window and run:

    sudo -k true

The Touch ID dialog should show the command.
$closes
Leave this window open.
EOF
    answer=
    read -r -t 300 -p "Did sudo work in the other window? [y/N] " answer < /dev/tty || true
    if [ "$answer" = y ] || [ "$answer" = Y ]; then
        pending=0
        rm -f "$saved" "$PREVIOUS"
        echo "Kept."
    else
        echo
        exit 1 # finish() restores the previous files
    fi
    ;;
uninstall)
    lock
    if [ -f "$CONF" ]; then
        write_conf without_tidcmd
    fi
    rm -f "$DEST" "$PREVIOUS" "$DEST_DIR"/.pam_tidcmd.so.??????
    rmdir "$DEST_DIR" 2>/dev/null || true
    if [ -f "$CONF" ]; then
        echo "Removed. $CONF now reads:"
        sed 's/^/    /' "$CONF"
    else
        echo "Removed."
    fi
    ;;
esac
