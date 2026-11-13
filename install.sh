#!/bin/bash
# Installs or removes pam_tidcmd for sudo.
#
#   sudo ./install.sh            install, then ask you to confirm sudo still works
#   sudo ./install.sh uninstall  go back to Apple's pam_tid.so
#
# Only /etc/pam.d/sudo_local is edited. If you do not confirm that sudo works
# within five minutes, the previous file is put back.

set -euo pipefail

DEST_DIR=/Library/Security/pam_tidcmd
DEST=$DEST_DIR/pam_tidcmd.so
CONF=/etc/pam.d/sudo_local
TAG='#pam_tidcmd# '
SRC="$(cd "$(dirname "$0")" && pwd)/pam_tidcmd.so"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this with sudo." >&2
    exit 1
fi

write_conf() { # stdin: new contents
    local tmp
    tmp=$(mktemp "$CONF.XXXXXX")
    cat > "$tmp"
    chown root:wheel "$tmp"
    chmod 444 "$tmp"
    mv -f "$tmp" "$CONF"
}

without_tidcmd() { # prints the config with this module removed and pam_tid.so restored
    [ -f "$CONF" ] || return 0
    awk -v tag="$TAG" '
        /^[[:space:]]*auth[[:space:]].*pam_tidcmd\.so/ { next }
        index($0, tag) == 1 { print substr($0, length(tag) + 1); next }
        { print }
    ' "$CONF"
}

case "${1:-install}" in
install)
    if [ ! -f "$SRC" ]; then
        echo "pam_tidcmd.so not found next to this script. Run 'make' first." >&2
        exit 1
    fi

    # The module must not be replaceable by a non-root process.
    for dir in /Library /Library/Security; do
        if [ "$(stat -f '%u' "$dir")" != 0 ] || [ -n "$(find "$dir" -maxdepth 0 -perm +022)" ]; then
            echo "$dir is not owned by root or is group/world writable; refusing to install." >&2
            exit 1
        fi
    done

    install -d -o root -g wheel -m 755 "$DEST_DIR"
    install -o root -g wheel -m 444 "$SRC" "$DEST"

    saved=$(mktemp /etc/pam.d/.sudo_local.saved.XXXXXX)
    had_conf=0
    if [ -f "$CONF" ]; then
        had_conf=1
        cp -p "$CONF" "$saved"
    fi
    restore() {
        if [ "$had_conf" = 1 ]; then
            mv -f "$saved" "$CONF"
        else
            rm -f "$CONF" "$saved"
        fi
        echo "Previous $CONF restored."
    }
    trap restore EXIT

    line="auth       sufficient     $DEST"
    without_tidcmd | awk -v line="$line" -v tag="$TAG" '
        /^[[:space:]]*auth[[:space:]].*pam_tid\.so/ {
            if (!placed) { print line; placed = 1 }
            print tag $0
            next
        }
        { print }
        END { if (!placed) print line }
    ' | write_conf

    cat <<EOF

Installed. $CONF now reads:

$(sed 's/^/    /' "$CONF")

Now open a NEW terminal window and run:

    sudo -k true

The Touch ID dialog should show the command. Leave this window open.
EOF
    answer=
    read -r -t 300 -p "Did sudo work in the other window? [y/N] " answer < /dev/tty || true
    if [ "$answer" = y ] || [ "$answer" = Y ]; then
        trap - EXIT
        rm -f "$saved"
        echo "Kept."
    else
        echo
        exit 1 # the EXIT trap restores the previous file
    fi
    ;;
uninstall)
    without_tidcmd | write_conf
    rm -f "$DEST"
    rmdir "$DEST_DIR" 2>/dev/null || true
    echo "Removed. $CONF now reads:"
    sed 's/^/    /' "$CONF"
    ;;
*)
    echo "usage: sudo $0 [install|uninstall]" >&2
    exit 2
    ;;
esac
