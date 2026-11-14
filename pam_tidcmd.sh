#!/bin/bash
# Puts pam_tidcmd into sudo, takes it out again, and gets sudo back if the
# module ever stops it from starting.
#
#   sudo pam_tidcmd install [--timeout SECONDS] [--yes]
#   sudo pam_tidcmd uninstall [--yes]
#   pam_tidcmd status
#   pam_tidcmd rescue [--force]
#
# install copies the module to /Library/Security/pam_tidcmd and puts it in
# /etc/pam.d/sudo_local in place of Apple's pam_tid.so. It changes nothing
# unless sudo starts now and PAM can load the new sudo_local. After the
# change it checks that sudo still starts, then asks you to approve a Touch ID
# dialog for `sudo -S -k /usr/bin/true`. If a check fails, the dialog is
# cancelled or not answered within two minutes, or the run is interrupted,
# the previous files are put back.
#
# install and uninstall show the change to sudo_local, and install the
# module's SHA-256 hash, then ask on the terminal before changing anything.
# --yes answers yes in advance. Without a terminal and without --yes, they
# refuse. The sudo_local they replace is kept in /etc/pam.d as
# .sudo_local.pam_tidcmd-backup.<date-time>, the newest five.
#
# --timeout sets how long the Touch ID dialog waits for a fingerprint before
# it closes and sudo asks for the password: 0 to 3600 seconds, 0 for no limit.
# Without it, a reinstall keeps the current setting and a first install
# leaves the module's default.
#
# uninstall puts pam_tid.so back and removes the module. If sudo starts now
# but would not start without the module, it changes nothing. If sudo does not
# start either way, it moves sudo_local aside, so sudo uses Apple's default.
#
# status and rescue need no sudo. status shows what is installed and whether
# PAM can load sudo's config. rescue is for when sudo no longer starts: it
# asks for an administrator password in a dialog, which does not go through
# sudo, and replaces the module with Apple's pam_tid.so. Then sudo works with
# Apple's Touch ID, and `sudo pam_tidcmd uninstall` can clean up. rescue only
# acts when sudo does not start as root, and root is not asked to
# authenticate, so a module that crashes or hangs while it authenticates you
# goes unnoticed: --force replaces the module even when sudo starts.

set -euo pipefail

# Root runs this through sudo, which can keep the caller's PATH. Use the
# system's tools whatever comes first there: GNU coreutils, for one, has a
# stat and a chmod that take other options, and the checks would misread them.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

DEST_DIR=/Library/Security/pam_tidcmd
MODULE=$DEST_DIR/pam_tidcmd.so
PROBE=$DEST_DIR/pam_tidcmd_probe
SCRIPT=$DEST_DIR/pam_tidcmd
BROKEN=$DEST_DIR/.pam_tidcmd.so.broken # the module rescue replaced
APPLE_TID=/usr/lib/pam/pam_tid.so.2
PAM_DIR=/etc/pam.d
CONF=$PAM_DIR/sudo_local
SUDO_POLICY=$PAM_DIR/sudo
LOCK=/var/run/pam_tidcmd.lock
OSASCRIPT=/usr/bin/osascript
TTY=/dev/tty # where install and uninstall ask
# Backups of sudo_local: this, a dot and the time (YYYYmmdd-HHMMSS). A dot
# file, so that module_users() does not count one that names the module.
BACKUP=$PAM_DIR/.sudo_local.pam_tidcmd-backup
BACKUPS_KEPT=5
TAG='#pam_tidcmd# '

# Module fields ($3) naming Apple's module and this one. Brackets, not
# backslashes, because awk -v would interpret backslashes.
TID_RE='(^|/)pam_tid[.]so([.][0-9]+)?$'
TIDCMD_RE='(^|/)pam_tidcmd[.]so$'
# An awk rule that splits each line into f[1..n] as OpenPAM reads it: OpenPAM
# ends a line at the first #, even inside a word, so that is cut off first.
# Fields are always tested through f, never through $1..$NF.
# shellcheck disable=SC2016 # awk code
FIELDS='{ line = $0; sub(/#.*/, "", line); n = split(line, f) }'
DEFAULT_TIMEOUT=30 # kDefaultTimeout in pam_tidcmd.m
TOUCHID_WAIT=120   # seconds install waits for the Touch ID dialog to be answered

# This script with symlinks resolved, and its directory. The files to install
# are next to it: in the build directory, in Homebrew's libexec, or in
# DEST_DIR for the installed copy.
SELF=$(/usr/bin/readlink -f "${BASH_SOURCE[0]}")
HERE=$(dirname "$SELF")

say() { printf '%s\n' "$@"; }
warn() { printf '%s\n' "$@" >&2; }
die() {
    warn "$@"
    exit 1
}

usage() {
    local me
    me=$(basename "$0")
    warn "usage: sudo $me install [--timeout SECONDS] [--yes]" \
        "       sudo $me uninstall [--yes]" \
        "       $me status" \
        "       $me rescue           when sudo no longer starts" \
        "       $me rescue --force   when sudo crashes or hangs while it authenticates you"
    exit 2
}

rescue_hint() {
    warn "" "If sudo stops starting (\"sudo: unable to initialize PAM\"), run this, without sudo:" \
        "    $SCRIPT rescue" \
        "It asks for an administrator password in a dialog and puts Apple's Touch ID module in this one's place." \
        "If sudo starts but crashes or hangs while it authenticates you, add --force."
}

# Whether the module file is Apple's pam_tid.so, as rescue leaves it: a link
# (only rescue makes one) or a copy.
is_apple_module() {
    [ -L "$MODULE" ] || { [ -f "$MODULE" ] && cmp -s "$MODULE" "$APPLE_TID"; }
}

exists() { [ -e "$1" ] || [ -L "$1" ]; } # a dangling symbolic link exists too

running_as_root() { [ "$(id -u)" -eq 0 ]; }

need_root() {
    running_as_root || die "Run this with sudo. If sudo no longer starts, run: $(basename "$0") rescue"
}

# The same rule as the module: at most four digits, 3600 at most.
valid_timeout() {
    [[ $1 =~ ^[0-9]{1,4}$ ]] && [ $((10#$1)) -le 3600 ]
}

timestamp() { date +%Y%m%d-%H%M%S; } # in the names of the files this script keeps

# --- asking ------------------------------------------------------------------

# install and uninstall ask before they change anything. The question goes to
# the terminal rather than to stdin and stdout, which can be a pipe or a file,
# so that the person at the terminal answers it. --yes answers it in advance.
need_answer() {
    [ "$yes" = 1 ] || { : <"$TTY"; } 2>/dev/null ||
        die "There is no terminal to ask on, so nothing was changed." \
            "Run this in a terminal, or add --yes to answer yes in advance."
}

confirm() { # asks $1 on the terminal; true for y or yes
    local answer=
    [ "$yes" = 0 ] || return 0
    need_answer
    printf '%s [y/N] ' "$1" >>"$TTY"
    read -r answer <"$TTY" || printf '\n' >>"$TTY" # end of input: no
    case $answer in
    [yY] | [yY][eE][sS]) return 0 ;;
    esac
    return 1
}

# Shows how sudo_local changes, from $1 to $2; /dev/null stands for no file.
show_change() {
    local changes status=0
    changes=$(/usr/bin/diff -u -L "$CONF (now)" -L "$CONF (new)" "$1" "$2") || status=$?
    [ "$status" -le 1 ] || die "Could not compare the current and the new $CONF, so nothing was changed."
    if [ -z "$changes" ]; then
        say "" "$CONF stays as it is."
    else
        say "" "Changes to $CONF:" ""
        printf '%s\n' "$changes" | sed 's/^/    /'
    fi
}

# Whether sudo_local is as it was when copied to $1; /dev/null: there was none.
# What was shown is then what gets written.
conf_unchanged() {
    if [ "$1" = /dev/null ]; then
        [ ! -e "$CONF" ] && [ ! -L "$CONF" ]
    else
        [ -f "$CONF" ] && cmp -s "$1" "$CONF"
    fi
}

# Files created by this run, removed when it ends.
TEMPS=()
add_temp() { TEMPS+=("$1"); }

KEEP=          # a temporary file that must outlive the run after all
pending=      # while set, the function that undoes the change in progress
check_pid=    # the Touch ID check, while it runs
created_dir=0 # 1 if this run created DEST_DIR

# Signals that end the script. Each one first ignores them all, so that a
# second signal cannot end the script before the undo in finish has started.
SIGNALS='HUP INT QUIT TERM USR1 USR2 ALRM'
on_signal() {
    # shellcheck disable=SC2086 # one word per signal
    trap '' $SIGNALS PIPE
    exit "$1"
}

finish() {
    local status=$?
    # Nothing may stop the undo halfway: not a second signal, not a closed
    # terminal or pipe.
    # shellcheck disable=SC2086
    trap '' $SIGNALS PIPE
    trap - EXIT
    set +e
    [ -z "$check_pid" ] || kill_tree "$check_pid"
    [ -z "$pending" ] || "$pending"
    local f
    # The + form, because bash 3.2 calls an empty array unbound under set -u.
    for f in ${TEMPS[@]+"${TEMPS[@]}"}; do
        [ "$f" = "$KEEP" ] || rm -rf "$f"
    done
    [ "$created_dir" = 0 ] || rmdir "$DEST_DIR" 2>/dev/null # only if it is empty
    exit "$status"
}

# One install or uninstall at a time, so that a run keeps its backups until it
# is done. A kernel lock: it ends with the process, so it cannot go stale.
#
# Only root may open the lock file. flock(2) also works on a descriptor opened
# for reading, so with a file anyone can read, anyone could hold the lock and
# keep install, uninstall and rescue from running.
take_lock() {
    local mask
    mask=$(umask)
    umask 077
    exec 9>>"$LOCK" || die "Could not open $LOCK."
    umask "$mask"
    chmod 600 "$LOCK" # one made by an earlier version is readable by all
    /usr/bin/lockf -s -t 0 9 || die "Another pam_tidcmd install or uninstall is running. Let it finish, then try again."
}

# The module must not be replaceable by a non-root process. Each inspection
# is an assignment, so if one fails, set -e stops the script instead of the
# check passing. ls -le lists ACL entries after the file's own line.
check_dirs() {
    local dir owner writable acl
    for dir in /Library /Library/Security; do
        owner=$(stat -f '%u' "$dir")
        writable=$(find "$dir" -maxdepth 0 -perm +022)
        acl=$(/bin/ls -lde "$dir" | sed 1d)
        if [ "$owner" != 0 ] || [ -n "$writable" ] || [[ $acl == *" allow "* ]]; then
            die "$dir is not owned by root, is group/world writable or has an ACL; refusing to install."
        fi
    done
}

# macOS lets root change /etc/pam.d only on behalf of an app that may
# administer the computer, which it asks about the first time, or that has
# Full Disk Access. Without that, every change there fails, so find out
# before making any.
check_pam_dir() {
    local tmp
    if ! tmp=$(mktemp "$PAM_DIR/.pam_tidcmd-write.XXXXXX" 2>/dev/null); then
        die "macOS does not let this process change $PAM_DIR, so nothing was changed." \
            "Run this from a terminal app that may administer this computer (macOS asks the first time) or" \
            "has Full Disk Access (System Settings > Privacy & Security). If sudo does not start, run" \
            "this without sudo instead: $(basename "$0") rescue"
    fi
    rm -f "$tmp"
}

# --- sudo_local ------------------------------------------------------------

# Modules are recognised by the module field of an auth line (f[3]), never by
# a mention elsewhere on the line, such as in a comment.
without_tidcmd() { # prints sudo_local ($1, default CONF) with this module removed and pam_tid.so restored
    local file=${1:-$CONF}
    [ -f "$file" ] || return 0
    awk -v tag="$TAG" -v re="$TIDCMD_RE" "$FIELDS"'
        f[1] == "auth" && f[3] ~ re { next }
        index($0, tag) == 1 { print substr($0, length(tag) + 1); next }
        { print }
    ' "$file"
}

# Whether sudo_local has an active line for this module or a line it commented out.
uses_tidcmd() {
    [ -f "$CONF" ] && awk -v tag="$TAG" -v re="$TIDCMD_RE" "$FIELDS"'
        (f[1] == "auth" && f[3] ~ re) || index($0, tag) == 1 { found = 1 }
        END { exit !found }
    ' "$CONF"
}

# The last timeout= value on the current pam_tidcmd line, if any.
current_timeout() {
    [ -f "$CONF" ] || return 0
    awk -v re="$TIDCMD_RE" "$FIELDS"'
        f[1] == "auth" && f[3] ~ re { for (i = 4; i <= n; i++) if (f[i] ~ /^timeout=/) t = substr(f[i], 9) }
        END { print t }
    ' "$CONF"
}

# The new line takes the place of the pam_tid.so line, with its control flag.
# Without one, it is added at the end as sufficient. $options goes after the
# module path.
with_tidcmd() { # prints sudo_local with pam_tid.so replaced by the module at $1
    without_tidcmd | awk -v dest="$1" -v opts="$options" -v tag="$TAG" -v re="$TID_RE" "$FIELDS"'
        f[1] == "auth" && f[3] ~ re {
            if (!placed) { printf "auth       %-14s %s%s\n", f[2], dest, opts; placed = 1 }
            print tag $0
            next
        }
        { print }
        END { if (!placed) printf "auth       %-14s %s%s\n", "sufficient", dest, opts }
    '
}

# Replaces CONF with the output of "$@", only if that succeeds. The new file
# is complete before it takes the old one's place.
write_conf() {
    local tmp
    tmp=$(mktemp "$PAM_DIR/.sudo_local.new.XXXXXX") || return 1
    add_temp "$tmp"
    if ! "$@" >"$tmp" || ! chown root:wheel "$tmp" || ! chmod 444 "$tmp"; then
        warn "Could not write the new $CONF."
        return 1
    fi
    mv -f "$tmp" "$CONF"
}

# Policy files, sudo_local included, with an active line of any kind that
# names this module. Removing the module would stop PAM from loading them.
module_users() {
    local f
    for f in "$PAM_DIR"/*; do
        [ -f "$f" ] || continue
        case ${f##*/} in pam_tidcmd-check.*) continue ;; esac
        if awk -v re="$TIDCMD_RE" "$FIELDS"' f[3] ~ re { found = 1; exit } END { exit !found }' "$f"; then
            echo "$f"
        fi
    done
}

# Keeps saved_conf, the sudo_local this run replaced, as a backup, once the
# change stays. Nothing is kept when the file did not change. The backup is a
# hard link, which is not made over one that a run in the same second left:
# that one shows the file as it had been for longer.
keep_backup() {
    { [ -n "${saved_conf:-}" ] && [ -f "$saved_conf" ]; } || return 0
    if [ -f "$CONF" ] && cmp -s "$saved_conf" "$CONF"; then
        return 0
    fi
    local name
    name=$BACKUP.$(timestamp)
    if ln "$saved_conf" "$name" 2>/dev/null; then
        say "The previous $CONF is kept as $name."
    elif ! exists "$name"; then
        warn "Could not keep the previous $CONF as $name."
    fi
    prune_backups
}

# Deletes all but the newest BACKUPS_KEPT backups. Only names exactly as
# keep_backup makes them, which sort by time: a file named otherwise is not
# this script's to delete.
# After prune_backups() in macos-sudo-touchid-context (MIT, © 2026 Lauri Gates).
prune_backups() {
    local f found=() i=0
    for f in "$BACKUP".[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]; do
        if [ -f "$f" ] && [ ! -L "$f" ]; then
            found+=("$f")
        fi
    done
    while [ $((${#found[@]} - i)) -gt "$BACKUPS_KEPT" ]; do
        rm -f "${found[i]}"
        i=$((i + 1))
    done
}

# --- checks ------------------------------------------------------------------

# The probe next to this script, or the installed one.
find_probe() {
    local p
    for p in "$HERE/pam_tidcmd_probe" "$PROBE"; do
        if [ -x "$p" ]; then
            echo "$p"
            return 0
        fi
    done
}

# Whether PAM can load the policy that "$@" prints. OpenPAM only takes
# service names, so the policy is written to a temporary file in /etc/pam.d.
# Sets probe_error.
policy_loads() {
    local tmp status=0
    probe_error=
    tmp=$(mktemp "$PAM_DIR/pam_tidcmd-check.XXXXXX") || {
        probe_error="Could not create a file in $PAM_DIR."
        return 1
    }
    add_temp "$tmp"
    if ! "$@" >"$tmp" || ! chmod 444 "$tmp"; then
        probe_error="Could not write $tmp."
        return 1
    fi
    probe_error=$("$PROBE_BIN" policy "$tmp" 2>&1 >/dev/null) || status=$?
    probe_error=${probe_error##*: } # without the temporary file's name
    rm -f "$tmp"
    return "$status"
}

# Whether /usr/bin/sudo starts and runs a command. Run as root, sudo asks for
# no authentication but still loads its whole PAM config, as for anyone, and
# fails with "unable to initialize PAM" if a module cannot be loaded. This is
# the real sudo, so on Apple silicon it loads the module's arm64e slice.
# Sets sudo_error.
sudo_starts() {
    local status=0
    sudo_error=$(/usr/bin/sudo -n /usr/bin/true 2>&1 </dev/null) || status=$?
    [ "$status" = 0 ] && return 0
    sudo_error="sudo -n /usr/bin/true as root failed with status $status: ${sudo_error:-no message}"
    return 1
}

kill_tree() { # SIGKILL a process and all its descendants
    local child
    for child in $(pgrep -P "$1" 2>/dev/null); do
        kill_tree "$child"
    done
    kill -KILL "$1" 2>/dev/null || true
}

# Asks the user who ran sudo to approve sudo's Touch ID dialog, through the
# PAM config now in place. -S with no input makes the password fallback fail
# at once, so only an approved dialog passes. -k ignores cached credentials
# and leaves them as they are. Sets check_error.
#
# sudo's output goes to a file in $1, a directory only root can write to. Not
# in TMPDIR: if the caller passed theirs on, its owner could swap the file for
# a link before root opens it, and root would write wherever that points.
#
# The script waits by polling rather than with a helper process that kills
# after a delay: such a helper could outlive an interrupted run and later kill
# a process that has reused the PID. bash reaps the child as soon as it ends,
# so kill -0 fails from then on, and wait still returns its status.
touchid_check() {
    local out status=0 started=$SECONDS timed_out=0 tty_state=
    out=$(mktemp "$1/touchid.XXXXXX") || {
        check_error="Could not create a file in $1."
        return 1
    }
    add_temp "$out"
    tty_state=$(stty -g <"$TTY" 2>/dev/null) || tty_state=
    # shellcheck disable=SC2024 # root writes the output, as intended
    /usr/bin/sudo -n -u "$user" -- /usr/bin/sudo -S -k /usr/bin/true </dev/null >"$out" 2>&1 9>&- &
    check_pid=$!
    while kill -0 "$check_pid" 2>/dev/null; do
        if [ $((SECONDS - started)) -ge "$TOUCHID_WAIT" ]; then
            timed_out=1
            kill_tree "$check_pid"
            break
        fi
        sleep 0.5
    done
    wait "$check_pid" || status=$?
    check_pid=
    [ -z "$tty_state" ] || stty "$tty_state" <"$TTY" 2>/dev/null || true

    [ "$status" = 0 ] && return 0
    if [ "$timed_out" = 1 ]; then
        check_error="The dialog was not answered within $TOUCHID_WAIT seconds."
    elif [ "$status" -gt 128 ]; then
        check_error="sudo was ended by signal $((status - 128)) while authenticating."
    else
        check_error="sudo did not accept Touch ID: the dialog was cancelled, timed out or did not open."
    fi
    check_error="$check_error sudo said: $(tr '\n' ' ' <"$out")"
    return 1
}

# --- install -------------------------------------------------------------------

FILES='pam_tidcmd.so pam_tidcmd_probe pam_tidcmd' # in DEST_DIR, the module first

# Shows the module to install, $1, with its SHA-256 hash, and whether it
# differs from the installed one.
show_module() {
    local sum
    sum=$(/usr/bin/shasum -a 256 <"$1") ||
        die "Could not compute the module's SHA-256 hash, so nothing was changed."
    say "" "Module:     $MODULE" \
        "            from $HERE/pam_tidcmd.so" \
        "            SHA-256 ${sum%% *}"
    if is_apple_module; then
        say "            replaces Apple's pam_tid.so, which rescue put there"
    elif [ ! -f "$MODULE" ]; then
        say "            not installed yet"
    elif cmp -s "$1" "$MODULE"; then
        say "            the same as the installed module"
    else
        say "            differs from the installed module"
    fi
}

undo_install() {
    local name failed=0
    say "Undoing the install."
    if [ -n "$saved_conf" ]; then
        mv -f "$saved_conf" "$CONF" || failed=1
    else
        rm -f "$CONF" || failed=1
    fi
    if [ "$failed" = 1 ]; then
        # sudo_local may still name the new module, so it stays, and so does
        # everything else.
        warn "Could not put $CONF back, so the new module and the old files were left in place."
        if [ -n "$saved_conf" ]; then
            KEEP=$saved_conf
            warn "The previous $CONF is in $saved_conf."
        fi
        rescue_hint
        return
    fi
    for name in $FILES; do
        if exists "$DEST_DIR/.$name.previous"; then
            mv -f "$DEST_DIR/.$name.previous" "$DEST_DIR/$name" || failed=1
        else
            rm -f "$DEST_DIR/$name" || failed=1
        fi
    done
    if [ "$failed" = 0 ] && sudo_starts; then
        say "Done; sudo starts as before."
    else
        warn "Could not put everything back. ${sudo_error:-}"
        rescue_hint
    fi
}

do_install() {
    need_root
    [ "$HERE" != "$DEST_DIR" ] || die "This is the installed copy, which can only uninstall. Run install from the build directory or from Homebrew."
    local name
    for name in pam_tidcmd.so pam_tidcmd_probe; do
        [ -f "$HERE/$name" ] || die "$HERE/$name not found. Run 'make' first."
    done
    user=${SUDO_USER:-}
    if [ -z "$user" ] || [ "$user" = root ]; then
        die "Run this with sudo from your own account: the last check asks that account to approve a Touch ID dialog."
    fi
    need_answer # now rather than after the checks
    check_dirs
    take_lock

    # One replacement line cannot keep the meaning of several pam_tid.so lines.
    local count
    count=$(without_tidcmd | awk -v re="$TID_RE" "$FIELDS"' f[1] == "auth" && f[3] ~ re { c++ } END { print c + 0 }')
    if [ "$count" -gt 1 ]; then
        die "$CONF has $count active pam_tid.so lines. Leave one and run this again."
    fi

    if [ "$timeout_given" = 0 ]; then
        timeout=$(current_timeout)
        if [ -n "$timeout" ] && ! valid_timeout "$timeout"; then
            die "$CONF sets timeout=$timeout, which is not 0 to 3600 seconds. Pass --timeout."
        fi
        [ -z "$timeout" ] || timeout=$((10#$timeout))
    fi
    options=${timeout:+ timeout=$timeout}

    # Without a working sudo now, a check after the change would mean nothing.
    sudo_starts || die "sudo does not start as things are now, so nothing was changed." "$sudo_error"
    check_pam_dir

    if [ ! -d "$DEST_DIR" ]; then
        mkdir -m 755 "$DEST_DIR"
        created_dir=1
    fi
    [ ! -L "$DEST_DIR" ] || die "$DEST_DIR is a symbolic link; refusing to install."
    chown root:wheel "$DEST_DIR"
    chmod 755 "$DEST_DIR"
    chmod -N "$DEST_DIR"

    # Copy the new files next to their final place, under a temporary name.
    # Not install(1): it copies ACLs from the user-owned build, which could let
    # that user rewrite the module. mktemp creates root-owned files without one.
    local staged
    staged=$(mktemp -d "$DEST_DIR/.staged.XXXXXX")
    add_temp "$staged"
    cat "$HERE/pam_tidcmd.so" >"$staged/pam_tidcmd.so"
    cat "$HERE/pam_tidcmd_probe" >"$staged/pam_tidcmd_probe"
    cat "$SELF" >"$staged/pam_tidcmd"
    for name in $FILES; do
        chmod -N "$staged/$name"
        chown root:wheel "$staged/$name"
    done
    chmod 444 "$staged/pam_tidcmd.so"
    chmod 555 "$staged/pam_tidcmd_probe" "$staged/pam_tidcmd"

    # Nothing is changed unless PAM can load the module and the new sudo_local.
    PROBE_BIN=$staged/pam_tidcmd_probe
    probe_error=$("$PROBE_BIN" module "$staged/pam_tidcmd.so" 2>&1) ||
        die "The module does not load, so nothing was changed:" "$probe_error"
    local shown=/dev/null # sudo_local as checked and shown
    if [ -f "$CONF" ]; then
        shown=$staged/sudo_local.shown
        cp -p "$CONF" "$shown"
    fi
    policy_loads with_tidcmd "$staged/pam_tidcmd.so" ||
        die "PAM could not load $CONF with the module in it ($probe_error), so nothing was changed." \
            "A line in it may name a module that does not load."

    # Show what changes, and ask.
    with_tidcmd "$MODULE" >"$staged/sudo_local.new"
    show_module "$staged/pam_tidcmd.so"
    show_change "$shown" "$staged/sudo_local.new"
    say ""
    confirm "Install pam_tidcmd?" || die "Nothing was changed."
    conf_unchanged "$shown" ||
        die "$CONF changed while you were asked, so nothing was changed. Run install again to see the new change."

    # Keep what is there now. The old files are kept as hard links, so a
    # reinstall over a working module can be undone after the new one has
    # taken its place.
    saved_conf=
    if [ -f "$CONF" ]; then
        saved_conf=$(mktemp "$PAM_DIR/.sudo_local.saved.XXXXXX")
        add_temp "$saved_conf"
        cp -p "$CONF" "$saved_conf"
    fi
    for name in $FILES; do
        rm -f "$DEST_DIR/.$name.previous" # left by a run that was killed
        if [ -L "$DEST_DIR/$name" ]; then
            # rescue's link to Apple's module: ln would follow it
            cp -pP "$DEST_DIR/$name" "$DEST_DIR/.$name.previous"
        elif [ -e "$DEST_DIR/$name" ]; then
            ln -f "$DEST_DIR/$name" "$DEST_DIR/.$name.previous"
        fi
    done

    pending=undo_install
    for name in $FILES; do
        mv -f "$staged/$name" "$DEST_DIR/$name"
    done
    write_conf with_tidcmd "$MODULE"
    PROBE_BIN=$PROBE

    say "Checking that PAM can load sudo's config."
    "$PROBE_BIN" policy "$SUDO_POLICY" || die "PAM could not load sudo's config with the module."
    say "Checking that sudo starts."
    sudo_starts || die "sudo does not start with the module." "$sudo_error"

    say "" "A Touch ID dialog opens now for: sudo -S -k /usr/bin/true" \
        "Approve it to keep the module. Cancel it, or leave it for $TOUCHID_WAIT seconds, to go back."
    touchid_check "$staged" || die "$check_error"

    pending=
    for name in $FILES; do
        rm -f "$DEST_DIR/.$name.previous"
    done
    rm -f "$BROKEN"
    keep_backup

    local closes
    if [ "${timeout:-$DEFAULT_TIMEOUT}" = 0 ]; then
        closes="The dialog stays open until you answer it (timeout=0)."
    else
        closes="Left alone, the dialog closes after ${timeout:-$DEFAULT_TIMEOUT} seconds and sudo asks for the password."
    fi
    say "" "Installed. $CONF now reads:" ""
    sed 's/^/    /' "$CONF"
    say "" "$closes"
    rescue_hint 2>&1
}

# --- uninstall -----------------------------------------------------------------

undo_uninstall() {
    say "Putting $CONF back as it was."
    write_conf cat "$saved_conf" || rescue_hint
}

# Takes the module out of sudo_local so that sudo starts, preferring to keep
# the rest of sudo_local. Sets still_broken if sudo does not start afterwards
# for a reason outside sudo_local.
still_broken=
remove_from_conf() {
    local before=ok cleaned aside
    sudo_starts || before=failed
    saved_conf=$(mktemp "$PAM_DIR/.sudo_local.saved.XXXXXX")
    add_temp "$saved_conf"
    cp -p "$CONF" "$saved_conf"
    cleaned=$(mktemp "$PAM_DIR/.sudo_local.cleaned.XXXXXX")
    add_temp "$cleaned"
    without_tidcmd "$saved_conf" >"$cleaned"

    local reason cleaned_loads=1 kept="sudo starts with the module, so $CONF was left as it was and the module was kept."
    if [ -n "$PROBE_BIN" ] && ! policy_loads cat "$cleaned"; then
        cleaned_loads=0
        reason="PAM could not load $CONF without the module ($probe_error)."
        [ "$before" = failed ] || die "$reason" "$kept"
    fi

    # Show what changes, and ask.
    local default="macOS's default: the password, without Touch ID."
    if [ "$cleaned_loads" = 1 ]; then
        show_change "$saved_conf" "$cleaned"
        [ "$before" = ok ] || say "" "sudo does not start now. $sudo_error" \
            "If it does not start with this change either, $CONF is set aside, so that sudo uses $default"
    else
        say "" "$reason" "sudo does not start with the module either. $sudo_error" \
            "So $CONF is set aside, without the module, and sudo uses $default"
    fi
    say "" "Then the module's files in $DEST_DIR are removed, unless a file in $PAM_DIR still uses it." ""
    confirm "Uninstall pam_tidcmd?" || die "Nothing was changed."
    conf_unchanged "$saved_conf" ||
        die "$CONF changed while you were asked, so nothing was changed. Run uninstall again to see the new change."

    # First choice: sudo_local as it was before install, with pam_tid.so.
    # An interrupted run puts back what was there only if sudo started with
    # it; otherwise anything tried here is at least as good.
    if [ "$cleaned_loads" = 1 ]; then
        [ "$before" = failed ] || pending=undo_uninstall
        write_conf cat "$cleaned"
        if sudo_starts; then
            pending=
            say "Removed pam_tidcmd from $CONF, which now reads:" ""
            sed 's/^/    /' "$CONF"
            return 0
        fi
        reason="sudo does not start without the module. $sudo_error"
        if [ "$before" = ok ]; then
            write_conf cat "$saved_conf"
            pending=
            die "$reason" "$kept"
        fi
    fi

    # sudo does not start either way. Second choice: no sudo_local, which is
    # how macOS comes. The rest of it is kept aside, for you to fix.
    aside=$CONF.pam_tidcmd-disabled.$(timestamp)
    cp -p "$cleaned" "$aside"
    chmod 444 "$aside"
    rm -f "$CONF"
    if sudo_starts; then
        pending=
        warn "$reason" "" \
            "sudo starts now without $CONF, so with macOS's default: no Touch ID, just the password." \
            "Its other lines are in $aside. Fix them and move it back to turn Touch ID on again."
        return 0
    fi

    # Not even that helps, so the cause is outside sudo_local. Keep the rest
    # of sudo_local, without the module, unless PAM could not load that.
    if [ "$cleaned_loads" = 1 ]; then
        write_conf cat "$cleaned"
        rm -f "$aside"
        still_broken="Removed pam_tidcmd from $CONF, but sudo does not start with or without $CONF, so the cause is elsewhere. $sudo_error"
    else
        still_broken="$reason So $CONF was set aside as $aside. sudo does not start without it either, so there is another cause outside it. $sudo_error"
    fi
}

do_uninstall() {
    need_root
    take_lock
    PROBE_BIN=$(find_probe)

    if uses_tidcmd; then
        check_pam_dir
        remove_from_conf # asks first
        keep_backup
    else
        say "$CONF does not use pam_tidcmd."
        if [ -d "$DEST_DIR" ] && [ -z "$(module_users)" ]; then
            say "" "Uninstall removes the module's files in $DEST_DIR." ""
            confirm "Remove them?" || die "Nothing was changed."
        fi
    fi

    local users
    users=$(module_users)
    if [ -n "$users" ]; then
        die "Kept $DEST_DIR, because these files still use the module:" "$users" \
            "Take those lines out, then run uninstall again."
    fi
    if [ -d "$DEST_DIR" ]; then
        # Also what an install that was killed, or an older installer, left.
        rm -f "$MODULE" "$PROBE" "$SCRIPT" "$BROKEN" "$DEST_DIR"/.pam_tidcmd*.previous "$DEST_DIR"/.pam_tidcmd.so.??????
        rm -rf "$DEST_DIR"/.staged.?????? "$DEST_DIR"/.rescue.??????
        if rmdir "$DEST_DIR" 2>/dev/null; then
            say "Removed $DEST_DIR."
        else
            warn "Removed the module but left $DEST_DIR: it holds files this script did not put there."
        fi
    fi
    [ -z "$still_broken" ] || die "$still_broken"
}

# --- status and rescue -------------------------------------------------------

# Whether PAM can load sudo's config, checked as the current user.
sudo_loads() {
    PROBE_BIN=$(find_probe)
    if [ -n "$PROBE_BIN" ]; then
        probe_error=$("$PROBE_BIN" policy "$SUDO_POLICY" 2>&1) && return 0
        return 1
    fi
    # Without the probe: sudo -n fails before it would authenticate, and says
    # "unable to initialize PAM" only if it could not load its config.
    probe_error=$(/usr/bin/sudo -n /usr/bin/true 2>&1 </dev/null) && return 0
    [[ $probe_error != *"unable to initialize PAM"* ]]
}

do_status() {
    local healthy=0 reinstall="sudo $0 install"
    # The installed copy refuses to install (see do_install).
    [ "$HERE" != "$DEST_DIR" ] || reinstall="run install from the build directory or from Homebrew"
    if is_apple_module; then
        say "Module:     $MODULE" \
            "            replaced with Apple's pam_tid.so by rescue, so sudo uses Apple's Touch ID." \
            "            To remove pam_tidcmd: sudo $0 uninstall. To install it again: $reinstall"
    elif [ -f "$MODULE" ]; then
        say "Module:     $MODULE"
        if [ "$HERE" != "$DEST_DIR" ] && [ -f "$HERE/pam_tidcmd.so" ]; then
            if cmp -s "$MODULE" "$HERE/pam_tidcmd.so"; then
                say "            the same as $HERE/pam_tidcmd.so"
            else
                say "            differs from $HERE/pam_tidcmd.so; to update it: sudo $0 install"
            fi
        fi
    else
        say "Module:     not installed"
    fi
    say "sudo_local: $CONF"
    if [ -f "$CONF" ] && awk -v re="$TIDCMD_RE" "$FIELDS"' f[1] == "auth" && f[3] ~ re { found = 1 } END { exit !found }' "$CONF"; then
        awk -v re="$TIDCMD_RE" "$FIELDS"' f[1] == "auth" && f[3] ~ re { print "            " $0 }' "$CONF"
    else
        say "            does not use pam_tidcmd"
    fi
    if sudo_loads; then
        say "sudo:       PAM can load its config"
    else
        say "sudo:       PAM CANNOT LOAD ITS CONFIG, so sudo does not start:" "            $probe_error" \
            "            To get sudo working again, run: $(basename "$0") rescue"
        healthy=1
    fi
    return "$healthy"
}

# Whether sudo_local has an active line naming the installed module.
names_module() {
    [ -f "$CONF" ] && awk -v m="$MODULE" "$FIELDS"' f[1] == "auth" && f[3] == m { found = 1 } END { exit !found }' "$CONF"
}

# Gets sudo to start again without touching /etc/pam.d. macOS does not let a
# process started from an administrator dialog change files there (see
# check_pam_dir), but the module file sudo_local names is outside it. It is
# replaced with Apple's pam_tid.so: first with a symbolic link, which keeps up
# with macOS updates, then with a copy. Each is kept only if sudo then starts.
#
# sudo run as root is not asked to authenticate, so it starts even with a
# module that crashes or hangs in pam_sm_authenticate. With --force, the
# module is replaced then too.
rescue_as_root() {
    take_lock
    local started=0
    if sudo_starts; then
        if [ "$force" = 0 ]; then
            say "sudo starts, so there is nothing to rescue. To remove pam_tidcmd: sudo $SCRIPT uninstall" \
                "If sudo crashes or hangs while it authenticates you, run: $SCRIPT rescue --force"
            return 0
        fi
        started=1
        say "sudo starts as root, which is not asked to authenticate. Replacing the module anyway (--force)."
    fi
    local before=${sudo_error:-}
    names_module || die "$CONF does not name $MODULE, so the module is not the cause." \
        "$before" "See \"Break glass\" in the README."
    [ -f "$APPLE_TID" ] || die "$APPLE_TID is missing, so there is nothing to replace the module with." \
        "See \"Break glass\" in the README."
    if [ "$started" = 1 ] && is_apple_module; then
        say "$MODULE is already Apple's pam_tid.so, so pam_tidcmd is not what fails. See \"Break glass\" in the README."
        return 0
    fi

    if [ ! -d "$DEST_DIR" ]; then
        mkdir -m 755 "$DEST_DIR"
        chown root:wheel "$DEST_DIR"
    fi
    local work kind what
    work=$(mktemp -d "$DEST_DIR/.rescue.XXXXXX")
    add_temp "$work"
    rm -f "$BROKEN"
    if exists "$MODULE"; then
        cp -pP "$MODULE" "$BROKEN" # kept to be looked at later
    fi

    for kind in link copy; do
        if [ "$kind" = link ]; then
            what="a link to"
            ln -s "$APPLE_TID" "$work/pam_tidcmd.so"
        else
            what="a copy of"
            cat "$APPLE_TID" >"$work/pam_tidcmd.so"
            chown root:wheel "$work/pam_tidcmd.so"
            chmod 444 "$work/pam_tidcmd.so"
        fi
        mv -f "$work/pam_tidcmd.so" "$MODULE"
        if sudo_starts; then
            say "sudo starts. $MODULE is now $what Apple's $APPLE_TID," \
                "so sudo uses Apple's Touch ID, without the command in the dialog."
            ! exists "$BROKEN" || say "The module it replaced is kept as $BROKEN."
            say "" "To remove pam_tidcmd: sudo $SCRIPT uninstall" \
                "To install a working build again: sudo pam_tidcmd install"
            return 0
        fi
    done

    # Neither helped, so the module is not the cause. Leave it as it was.
    if exists "$BROKEN"; then
        mv -f "$BROKEN" "$MODULE"
    else
        rm -f "$MODULE"
    fi
    die "Replacing the module with Apple's pam_tid.so did not get sudo to start, so it was put back." \
        "$sudo_error" "See \"Break glass\" in the README."
}

do_rescue() {
    if running_as_root; then
        rescue_as_root
        return
    fi
    # The installed copy is root-owned, so prefer it to this one.
    local runner=$SELF
    if [ -f "$SCRIPT" ] && [ "$(stat -f '%u' "$SCRIPT")" = 0 ]; then
        runner=$SCRIPT
    fi
    local option=
    [ "$force" = 0 ] || option=" --force"
    say "Asking for an administrator password, in a dialog that does not use sudo, to run as root:" \
        "    $runner rescue$option" ""
    local result ok=1
    result=$("$OSASCRIPT" \
        -e 'on run argv' \
        -e 'do shell script (quoted form of item 1 of argv) & " rescue" & item 2 of argv & " 2>&1" with prompt "pam_tidcmd is getting sudo to work again." with administrator privileges without altering line endings' \
        -e 'end run' "$runner" "$option" 2>&1) || ok=0
    say "$result"
    [[ $result != *"(-128)"* ]] || die "Cancelled; nothing was changed."
    # The root run can fail and still have fixed sudo, so check either way.
    if sudo_loads; then
        say "sudo starts."
        [ "$ok" = 1 ] || warn "The rescue did not finish everything; see above."
        return 0
    fi
    die "PAM still cannot load sudo's config: $probe_error" "" \
        "See \"Break glass\" in the README for other ways."
}

# --- main ----------------------------------------------------------------------

main() {
    local action=
    timeout=
    timeout_given=0
    force=0
    yes=0
    while [ $# -gt 0 ]; do
        case $1 in
        install | uninstall | status | rescue)
            [ -z "$action" ] || usage
            action=$1
            ;;
        --force) force=1 ;;
        --yes) yes=1 ;;
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
    [ -n "$action" ] || usage
    if [ "$timeout_given" = 1 ]; then
        if [ "$action" != install ] || ! valid_timeout "$timeout"; then
            die "--timeout takes 0 to 3600 seconds, and only when installing."
        fi
        timeout=$((10#$timeout))
    fi
    [ "$force" = 0 ] || [ "$action" = rescue ] || die "--force is only for rescue."
    # rescue never asks: it runs as root from a dialog, without a terminal.
    [ "$yes" = 0 ] || [ "$action" = install ] || [ "$action" = uninstall ] ||
        die "--yes is only for install and uninstall, which ask before they change anything."

    trap finish EXIT
    trap 'on_signal 129' HUP
    trap 'on_signal 130' INT
    trap 'on_signal 131' QUIT
    trap 'on_signal 143' TERM
    trap 'on_signal 158' USR1
    trap 'on_signal 159' USR2
    trap 'on_signal 142' ALRM
    "do_$action"
}

# Nothing runs when the file is sourced, as the tests do. Running main and
# exit from one line means bash has read the whole file before it starts, so
# replacing or deleting the file meanwhile (uninstall deletes the installed
# copy) cannot change what runs.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; exit; fi
