#!/bin/bash
# Runs install and uninstall from pam_tid_look.sh, with their checks and
# rollbacks, against a scratch directory and without root. Shows no dialog.
#
# pam_tid_look.sh is sourced and these are replaced: the paths, the root and
# ownership steps, the probe, sudo and the Touch ID check. The fake probe
# follows a policy's includes, cuts each line at the first # as OpenPAM does,
# and fails on a module that is missing or holds the word BROKEN, or on a
# symbolic link if FAKE_NO_SYMLINK is set. The fake
# sudo starts when the fake probe can load sudo's policy, like the real one,
# unless FAKE_SUDO=broken. FAKE_ROOT makes the script believe it runs as root.
# The terminal is the file $W/tty, which holds the answer: setup() puts y in
# it, and without the file there is no terminal.

set -euo pipefail

# As root, a path the stubs miss would change the real system.
if [ "$(id -u)" -eq 0 ]; then
    echo "Run the installer tests as a normal user, not as root." >&2
    exit 1
fi

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/pam_tid_look_test.XXXXXX")
trap 'rm -rf "$work"' EXIT
W=$work/w
failures=0
out=

cat >"$work/probe" <<'EOF'
#!/bin/bash
module_ok() { [ -f "$1" ] && ! grep -q BROKEN "$1" && { [ -z "${FAKE_NO_SYMLINK:-}" ] || [ ! -L "$1" ]; }; }
policy_ok() {
    local line kind ctl mod rest
    [ -f "$1" ] || return 1
    while IFS= read -r line; do
        read -r kind ctl mod rest <<<"${line%%#*}"
        [ -n "$kind" ] || continue
        if [ "$ctl" = include ]; then
            [ ! -e "$(dirname "$1")/$mod" ] || policy_ok "$(dirname "$1")/$mod" || return 1
        elif [[ $mod == /* ]]; then
            module_ok "$mod" || return 1
        fi
    done <"$1"
}
case $1 in
module) module_ok "$2" ;;
policy) policy_ok "$2" ;;
*) exit 2 ;;
esac || {
    echo "fake probe: $2 does not load" >&2
    exit 1
}
EOF

cat >"$work/stubs" <<'EOF'
DEST_DIR=$W/Security/pam_tid_look
MODULE=$DEST_DIR/pam_tid_look.so
PROBE=$DEST_DIR/pam_tid_look_probe
SCRIPT=$DEST_DIR/pam_tid_look
BROKEN=$DEST_DIR/.pam_tid_look.so.broken
PAM_DIR=$W/pam.d
CONF=$PAM_DIR/sudo_local
SUDO_POLICY=$PAM_DIR/sudo
LOCK=$W/lock
HERE=$W/build
SELF=$HERE/pam_tid_look
SUDO_USER=tester
APPLE_TID=$W/apple/pam_tid.so.2
TTY=$W/tty
BACKUP=$PAM_DIR/.sudo_local.pam_tid_look-backup
running_as_root() { [ -n "${FAKE_ROOT:-}" ]; }
# FAKE_TIME: the time in the names of the files the script keeps.
if [ -n "${FAKE_TIME:-}" ]; then timestamp() { echo "$FAKE_TIME"; }; fi
# FAKE_ASK=hang: waits at the question, and says where. FAKE_ASK=edit:
# sudo_local changes while the question is asked.
if [ -n "${FAKE_ASK:-}" ]; then
    eval "real_$(declare -f confirm)"
    confirm() {
        case $FAKE_ASK in
        hang)
            sleep 30 &
            echo "$$ $!" >"$W/waiting"
            wait $!
            ;;
        edit)
            chmod u+w "$CONF"
            echo "# edited meanwhile" >>"$CONF"
            ;;
        esac
        real_confirm "$@"
    }
fi

need_root() { :; }
check_dirs() { :; }
chown() { :; }
OSASCRIPT=$W/osascript
mv() { # FAKE_MV=fail: putting the saved sudo_local back fails
    case "${FAKE_MV:-} $*" in "fail "*.sudo_local.saved.*) return 1 ;; esac
    command mv "$@"
}
sudo_starts() {
    # FAKE_HANG=cleaned: hangs once sudo_local no longer names the module
    if [ "${FAKE_HANG:-}" = cleaned ] && ! grep -q 'pam_tid_look[.]so' "$CONF" 2>/dev/null; then
        sleep 30 &
        echo "$$ $!" >"$W/waiting"
        wait $!
    fi
    if [ "${FAKE_SUDO:-}" = broken ] || ! "$W/build/pam_tid_look_probe" policy "$SUDO_POLICY" 2>/dev/null; then
        sudo_error="fake sudo: unable to initialize PAM"
        return 1
    fi
}
touchid_check() {
    case ${FAKE_TOUCHID:-ok} in
    ok) return 0 ;;
    hang) # waits like the real check, and says where
        sleep 30 &
        check_pid=$!
        echo "$$ $check_pid" >"$W/waiting"
        wait "$check_pid"
        ;;
    esac
    check_error="fake: the dialog was cancelled"
    return 1
}
# FAKE_BREAK_AFTER: the module stops loading once sudo_local names it.
if [ -n "${FAKE_BREAK_AFTER:-}" ]; then
    eval "real_$(declare -f write_conf)"
    write_conf() {
        real_write_conf "$@" || return 1
        [ "$1" != with_tid_look ] || { chmod u+w "$MODULE"; echo BROKEN >>"$MODULE"; }
    }
fi
EOF

HEAD='# sudo_local: local config file which survives system update and is included for sudo
# uncomment following line to enable Touch ID for sudo'
APPLE="$HEAD
auth       sufficient     pam_tid.so"
INSTALLED="$HEAD
auth       sufficient     $W/Security/pam_tid_look/pam_tid_look.so
#pam_tid_look# auth       sufficient     pam_tid.so"

# A fresh world: a build directory with module v1, and Apple's sudo_local.
setup() {
    rm -rf "$W"
    mkdir -p "$W/build" "$W/pam.d" "$W/Security" "$W/apple"
    echo "apple pam_tid" >"$W/apple/pam_tid.so.2"
    echo "module v1" >"$W/build/pam_tid_look.so"
    cp "$work/probe" "$W/build/pam_tid_look_probe"
    cp "$here/pam_tid_look.sh" "$W/build/pam_tid_look"
    chmod 755 "$W/build/pam_tid_look_probe" "$W/build/pam_tid_look"
    echo "auth       include        sudo_local" >"$W/pam.d/sudo"
    echo "$APPLE" >"$W/pam.d/sudo_local"
    echo y >"$W/tty"
}

# Runs pam_tid_look with the stubs, in a bash of its own as the real one would
# be. Sets out and status.
cat >"$work/driver" <<EOF
source "$here/pam_tid_look.sh"
source "$work/stubs"
main "\$@"
EOF
run() {
    status=0
    out=$(W=$W /bin/bash "$work/driver" "$@" 2>&1) || status=$?
}

# Starts run in the background, in a process group of its own so that it gets
# signals as a foreground run would, and waits until it reports $W/waiting.
# Sets script_pid and waiting_pid.
run_until_waiting() {
    rm -f "$W/waiting" "$W/status" "$W/out"
    set -m
    (
        run "$@"
        echo "$status" >"$W/status"
        echo "$out" >"$W/out"
    ) &
    set +m
    runner=$!
    for _ in $(seq 100); do
        [ -s "$W/waiting" ] && break
        sleep 0.1
    done
    read -r script_pid waiting_pid <"$W/waiting"
}
finish_waiting() {
    wait "$runner" || true
    status=$(cat "$W/status")
    out=$(cat "$W/out")
}

check() { # label, then a command that must succeed
    local label=$1
    shift
    if "$@"; then
        printf 'ok    %s\n' "$label"
    else
        printf 'FAIL  %s\n' "$label"
        printf '      output: %s\n' "$out" | sed '2,$s/^/      /'
        failures=$((failures + 1))
    fi
}

conf_is() { [ "$(cat "$W/pam.d/sudo_local")" = "$1" ]; }
no_leftovers() { # backups are not left over
    [ -z "$(find "$W/pam.d" -name 'pam_tid_look-check.*' -o -name '.sudo_local.*' ! -name '.sudo_local.pam_tid_look-backup.*')" ] &&
        [ -z "$(find "$W/Security" -name '.staged.*' -o -name '.*.previous')" ]
}
set_conf() { # replaces sudo_local
    chmod u+w "$W/pam.d/sudo_local"
    printf '%s\n' "$1" >"$W/pam.d/sudo_local"
    chmod 444 "$W/pam.d/sudo_local"
}
add_line() { # appends a line to sudo_local
    chmod u+w "$W/pam.d/sudo_local"
    echo "$1" >>"$W/pam.d/sudo_local"
    chmod 444 "$W/pam.d/sudo_local"
}
break_module() {
    chmod u+w "$W/Security/pam_tid_look/pam_tid_look.so"
    echo "BROKEN" >>"$W/Security/pam_tid_look/pam_tid_look.so"
}
gone() { [ ! -e "$W/Security/pam_tid_look" ]; }
said() { [[ $out == *"$1"* ]]; }

echo "== the stubs replace every system path"
# Every top-level path in the script must point into the scratch directory, or
# a test could change the real system. Stop before any test if one does not.
# shellcheck disable=SC2013,SC2016 # one name per line; the sed expression is literal
for v in $(sed -n -E 's/^([A-Z_]+)=(\/|\$DEST_DIR|\$PAM_DIR).*/\1/p' "$here/pam_tid_look.sh"); do
    [ "$v" != PATH ] || continue # the search path for the system's tools, not a file
    value=$(W=$W /bin/bash -c 'source "$1"; source "$2"; eval "printf %s \"\${$3}\""' _ \
        "$here/pam_tid_look.sh" "$work/stubs" "$v")
    check "$v is replaced" [ "${value#"$W"/}" != "$value" ]
done
if [ "$failures" != 0 ]; then
    echo "A path is not replaced in the stubs; not running the tests." >&2
    exit 1
fi

echo "== install and uninstall"
setup
run install
check "install succeeds" [ "$status" = 0 ]
check "sudo_local has the module in place of pam_tid.so" conf_is "$INSTALLED"
check "the module is installed" cmp -s "$W/build/pam_tid_look.so" "$W/Security/pam_tid_look/pam_tid_look.so"
check "the probe is installed" cmp -s "$W/build/pam_tid_look_probe" "$W/Security/pam_tid_look/pam_tid_look_probe"
check "this script is installed" cmp -s "$here/pam_tid_look.sh" "$W/Security/pam_tid_look/pam_tid_look"
check "no temporary files or backups are left" no_leftovers
run uninstall
check "uninstall succeeds" [ "$status" = 0 ]
check "sudo_local is Apple's again, byte for byte" conf_is "$APPLE"
check "the module directory is gone" gone

echo "== install is undone when Touch ID is not approved"
setup
FAKE_TOUCHID=cancel run install
check "install fails" [ "$status" = 1 ]
check "it says why" said "fake: the dialog was cancelled"
check "sudo_local is unchanged" conf_is "$APPLE"
check "the module directory is gone" gone
check "it says sudo starts afterwards" said "sudo starts as before"

echo "== a reinstall that fails keeps the previous module"
setup
run install --timeout 45
echo "module v2" >"$W/build/pam_tid_look.so"
before=$(cat "$W/pam.d/sudo_local")
FAKE_TOUCHID=cancel run install
check "the reinstall fails" [ "$status" = 1 ]
check "sudo_local is as before the reinstall" conf_is "$before"
check "module v1 is back" grep -q "module v1" "$W/Security/pam_tid_look/pam_tid_look.so"
check "no temporary files or backups are left" no_leftovers
run install
check "a reinstall keeps timeout=45" grep -q "pam_tid_look.so timeout=45$" "$W/pam.d/sudo_local"
check "  and installs module v2" grep -q "module v2" "$W/Security/pam_tid_look/pam_tid_look.so"

echo "== nothing is changed when the module does not load"
setup
echo "BROKEN" >"$W/build/pam_tid_look.so"
run install
check "install fails" [ "$status" = 1 ]
check "it says the module does not load" said "The module does not load"
check "sudo_local is unchanged" conf_is "$APPLE"
check "the module directory is gone" gone

echo "== nothing is changed when sudo does not start beforehand"
setup
FAKE_SUDO=broken run install
check "install fails" [ "$status" = 1 ]
check "it says sudo does not start now" said "sudo does not start as things are now"
check "sudo_local is unchanged" conf_is "$APPLE"
check "the module directory is gone" gone

echo "== nothing is changed when the new sudo_local would not load"
setup
echo "BROKEN" >"$W/broken.so"
add_line "#pam_tid_look# auth optional $W/broken.so" # the rewrite makes this line active
before=$(cat "$W/pam.d/sudo_local")
run install
check "install fails" [ "$status" = 1 ]
check "it says PAM could not load the new sudo_local" said "with the module in it"
check "sudo_local is unchanged" conf_is "$before"
check "no temporary files are left" no_leftovers
check "the module directory is gone" gone

echo "== install is undone when sudo stops starting"
setup
FAKE_BREAK_AFTER=1 run install
check "install fails" [ "$status" = 1 ]
check "it says PAM could not load sudo's config" said "PAM could not load sudo's config with the module"
check "sudo_local is unchanged" conf_is "$APPLE"
check "the module directory is gone" gone
check "it says sudo starts afterwards" said "sudo starts as before"

echo "== an interrupted install is undone, and holds the lock until then"
setup
FAKE_TOUCHID=hang run_until_waiting install
run uninstall
check "a second run is refused" said "Another pam_tid_look install or uninstall is running"
kill -TERM "$script_pid"
finish_waiting
check "the interrupted run fails" [ "$status" = 143 ]
check "it says it undid the install" said "Undoing the install"
check "sudo_local is unchanged" conf_is "$APPLE"
check "the module directory is gone" gone
check "the Touch ID check was stopped" sh -c "! kill -0 $waiting_pid 2>/dev/null"

for sig in QUIT HUP INT; do
    echo "== SIG$sig during the Touch ID check undoes the install"
    setup
    FAKE_TOUCHID=hang run_until_waiting install
    kill -"$sig" "$script_pid"
    finish_waiting
    check "it says it undid the install" said "Undoing the install"
    check "sudo_local is unchanged" conf_is "$APPLE"
    check "the module directory is gone" gone
done

echo "== two signals at once still undo the install"
setup
FAKE_TOUCHID=hang run_until_waiting install
kill -HUP "$script_pid"
kill -HUP "$script_pid" 2>/dev/null || true
kill -TERM "$script_pid" 2>/dev/null || true
finish_waiting
check "it says it undid the install" said "Undoing the install"
check "sudo_local is unchanged" conf_is "$APPLE"
check "the module directory is gone" gone

echo "== a sudo_local that cannot be put back keeps everything"
setup
FAKE_TOUCHID=cancel FAKE_MV=fail run install
check "install fails" [ "$status" = 1 ]
check "it says so" said "Could not put $W/pam.d/sudo_local back"
check "the module sudo_local names is kept" [ -f "$W/Security/pam_tid_look/pam_tid_look.so" ]
saved=$(find "$W/pam.d" -name '.sudo_local.saved.*')
check "the previous sudo_local is kept" [ "$(cat "$saved" 2>/dev/null)" = "$APPLE" ]
check "  and named" said "The previous $W/pam.d/sudo_local is in $saved"

echo "== uninstall when the installed module no longer loads"
setup
run install
break_module
run uninstall
check "uninstall succeeds" [ "$status" = 0 ]
check "sudo_local is Apple's again" conf_is "$APPLE"
check "the module directory is gone" gone

echo "== uninstall changes nothing if sudo starts only with the module"
setup
run install
echo "BROKEN" >"$W/broken.so"
add_line "#pam_tid_look# auth optional $W/broken.so" # uninstall would make this line active
before=$(cat "$W/pam.d/sudo_local")
run uninstall
check "uninstall fails" [ "$status" = 1 ]
check "it says why" said "sudo starts with the module, so"
check "sudo_local is unchanged" conf_is "$before"
check "the module is kept" [ -f "$W/Security/pam_tid_look/pam_tid_look.so" ]

echo "== uninstall sets sudo_local aside if nothing else gets sudo to start"
setup
run install
echo "BROKEN" >"$W/broken.so"
add_line "auth optional $W/broken.so"
run uninstall
check "uninstall succeeds" [ "$status" = 0 ]
check "sudo_local is gone" [ ! -e "$W/pam.d/sudo_local" ]
aside=$(find "$W/pam.d" -name 'sudo_local.pam_tid_look-disabled.*')
check "its other lines are kept aside" grep -q "broken.so" "$aside"
check "  without the module" sh -c "! grep -q '^auth.*pam_tid_look.so' '$aside'"
check "it says so" said "sudo starts now without"
check "the module directory is gone" gone

echo "== uninstall when sudo fails for another reason"
setup
run install
FAKE_SUDO=broken run uninstall
check "uninstall fails" [ "$status" = 1 ]
check "it says the cause is elsewhere" said "the cause is elsewhere"
check "sudo_local is Apple's again" conf_is "$APPLE"
check "nothing is set aside" [ -z "$(find "$W/pam.d" -name 'sudo_local.pam_tid_look-disabled.*')" ]
check "the module directory is gone" gone

echo "== uninstall does not write back a sudo_local PAM cannot load"
setup
run install
echo "BROKEN" >"$W/broken.so"
add_line "auth optional $W/broken.so"
FAKE_SUDO=broken run uninstall
check "uninstall fails" [ "$status" = 1 ]
check "sudo_local stays aside" [ ! -e "$W/pam.d/sudo_local" ]
aside=$(find "$W/pam.d" -name 'sudo_local.pam_tid_look-disabled.*')
check "  with its other lines" grep -q "broken.so" "$aside"
check "it says PAM could not load it" said "PAM could not load"
check "  and that there is another cause" said "there is another cause outside it"

echo "== an interrupted uninstall that started from a broken sudo keeps the fix"
setup
run install
break_module
FAKE_HANG=cleaned run_until_waiting uninstall
kill -TERM "$script_pid"
kill "$waiting_pid" 2>/dev/null || true
finish_waiting
check "the run fails" [ "$status" = 143 ]
check "sudo_local stays without the module" conf_is "$APPLE"

echo "== uninstall keeps the module while another policy uses it"
setup
run install
echo "auth sufficient $W/Security/pam_tid_look/pam_tid_look.so" >"$W/pam.d/other_service"
run uninstall
check "uninstall fails" [ "$status" = 1 ]
check "it names the file" said "$W/pam.d/other_service"
check "sudo_local is Apple's again" conf_is "$APPLE"
check "the module is kept" [ -f "$W/Security/pam_tid_look/pam_tid_look.so" ]

echo "== uninstall keeps the module while sudo_local still names it"
setup
run install
add_line "account    required       $W/Security/pam_tid_look/pam_tid_look.so"
run uninstall
check "uninstall fails" [ "$status" = 1 ]
check "it names sudo_local" said "these files still use the module:"$'\n'"$W/pam.d/sudo_local"
check "the module is kept" [ -f "$W/Security/pam_tid_look/pam_tid_look.so" ]

echo "== a # right after a module path starts a comment, as in OpenPAM"
setup
set_conf "$HEAD
auth       sufficient     pam_tid.so#Apple's"
commented=$(cat "$W/pam.d/sudo_local")
run install
check "install replaces pam_tid.so#…" grep -qx "#pam_tid_look# auth       sufficient     pam_tid.so#Apple's" "$W/pam.d/sudo_local"
check "  leaving one active auth line" [ "$(grep -c '^auth' "$W/pam.d/sudo_local")" = 1 ]
run uninstall
check "uninstall puts it back byte for byte" conf_is "$commented"
setup
run install
set_conf "$(sed 's|pam_tid_look[.]so$|pam_tid_look.so#local|' "$W/pam.d/sudo_local")"
run uninstall
check "uninstall removes pam_tid_look.so#…" conf_is "$APPLE"
check "  before it removes the module" gone

echo "== rescue as root replaces the module with Apple's"
M=$W/Security/pam_tid_look/pam_tid_look.so
setup
run install
installed=$(cat "$W/pam.d/sudo_local")
break_module
FAKE_ROOT=1 run rescue
check "rescue succeeds" [ "$status" = 0 ]
check "the module is a link to Apple's" [ "$(readlink "$M")" = "$W/apple/pam_tid.so.2" ]
check "it says so" said "is now a link to Apple's"
check "sudo_local is unchanged" conf_is "$installed"
check "the broken module is kept" grep -q BROKEN "$W/Security/pam_tid_look/.pam_tid_look.so.broken"
run status
check "status says the module was replaced" said "replaced with Apple's pam_tid.so by rescue"
check "  and how to install it again" said "To install it again: sudo "
status=0
out=$(W=$W /bin/bash -c 'source "$1"; source "$2"; HERE=$DEST_DIR; main status' _ \
    "$here/pam_tid_look.sh" "$work/stubs" 2>&1) || status=$?
check "  from the installed copy, without telling it to install" \
    sh -c "! printf '%s' \"\$1\" | grep -q 'pam_tid_look/pam_tid_look install'" _ "$out"
check "  but where to install from" said "run install from the build directory or from Homebrew"
run uninstall
check "uninstall afterwards succeeds" [ "$status" = 0 ]
check "  and puts sudo_local back to Apple's" conf_is "$APPLE"
check "  and removes everything" gone
check "  without touching Apple's module" grep -q "apple pam_tid" "$W/apple/pam_tid.so.2"

setup
run install
break_module
FAKE_NO_SYMLINK=1 FAKE_ROOT=1 run rescue
check "without links, rescue uses a copy" cmp -s "$M" "$W/apple/pam_tid.so.2"
check "  which is not a link" [ ! -L "$M" ]
check "  and says so" said "is now a copy of Apple's"

setup
run install
break_module
FAKE_ROOT=1 run rescue
echo "module v2" >"$W/build/pam_tid_look.so"
FAKE_TOUCHID=cancel run install
check "an install over a rescue that fails keeps the link" [ "$(readlink "$M")" = "$W/apple/pam_tid.so.2" ]
run install
check "an install over a rescue succeeds" [ "$status" = 0 ]
check "  with the new module" grep -q "module v2" "$M"
check "  and drops the broken one" [ ! -e "$W/Security/pam_tid_look/.pam_tid_look.so.broken" ]

setup
run install
FAKE_ROOT=1 run rescue
check "rescue when sudo starts changes nothing" said "nothing to rescue"
check "  and keeps the module" grep -q "module v1" "$M"
check "  and points to --force" said "rescue --force"
FAKE_ROOT=1 run rescue --force
check "rescue --force when sudo starts succeeds" [ "$status" = 0 ]
check "  with a link to Apple's" [ "$(readlink "$M")" = "$W/apple/pam_tid.so.2" ]
check "  and keeps the module it replaced" grep -q "module v1" "$W/Security/pam_tid_look/.pam_tid_look.so.broken"
FAKE_ROOT=1 run rescue --force
check "rescue --force over Apple's module changes nothing" said "already Apple's pam_tid.so"
check "  and keeps the link" [ "$(readlink "$M")" = "$W/apple/pam_tid.so.2" ]

setup
run install
FAKE_SUDO=broken FAKE_ROOT=1 run rescue
check "rescue when the module is not the cause fails" [ "$status" = 1 ]
check "  and says so" said "did not get sudo to start, so it was put back"
check "  and puts the module back" grep -q "module v1" "$M"
check "  not a link" [ ! -L "$M" ]

setup
run install
rm -rf "$W/Security/pam_tid_look"
FAKE_ROOT=1 run rescue
check "rescue when the module is gone succeeds" [ "$status" = 0 ]
check "  with a link to Apple's" [ "$(readlink "$M")" = "$W/apple/pam_tid.so.2" ]

setup
echo "BROKEN" >"$W/broken.so"
add_line "auth optional $W/broken.so"
FAKE_ROOT=1 run rescue
check "rescue when sudo_local does not name the module fails" said "does not name"
check "  and creates nothing" gone

echo "== a /etc/pam.d that cannot be changed stops install and uninstall first"
setup
chmod 555 "$W/pam.d"
run install
chmod 755 "$W/pam.d"
check "install fails" [ "$status" = 1 ]
check "it says why" said "macOS does not let this process change $W/pam.d"
check "sudo_local is unchanged" conf_is "$APPLE"
check "nothing is installed" gone
setup
run install
chmod 555 "$W/pam.d"
run uninstall
chmod 755 "$W/pam.d"
check "uninstall fails" [ "$status" = 1 ]
check "it says why" said "macOS does not let this process change $W/pam.d"
check "the module is kept" [ -f "$M" ]

echo "== the Touch ID check itself, with a fake sudo"
# The real touchid_check, with its sudo command replaced by the shell code in
# $1 and a wait of 2 seconds.
check_touchid() {
    local started=$SECONDS
    status=0
    out=$(W=$W FAKE=$1 /bin/bash -c '
        source "$1"
        eval "$(declare -f touchid_check |
            sed "s|/usr/bin/sudo -n -u \"\$user\" -- /usr/bin/sudo -S -k /usr/bin/true|/bin/bash -c \"\$FAKE\"|")"
        TOUCHID_WAIT=2
        if touchid_check "$W"; then echo "check passed"; else echo "check failed: $check_error"; fi
    ' _ "$here/pam_tid_look.sh" 2>&1) || status=$?
    elapsed=$((SECONDS - started))
}
setup
check_touchid 'exit 0'
check "an approved dialog passes" said "check passed"
check_touchid 'echo "no password was provided" >&2; exit 1'
check "a cancelled dialog fails" said "sudo did not accept Touch ID"
check "  with sudo's message" said "sudo said: no password was provided"
# shellcheck disable=SC2016 # expands in the fake sudo's shell
check_touchid 'kill -USR1 $$'
check "sudo ending on a signal fails" said "ended by signal 30"
# shellcheck disable=SC2016 # expands in the fake sudo's shell
check_touchid 'sleep 30 & echo $! >"$W/grandchild"; wait'
check "an unanswered dialog fails" said "not answered within 2 seconds"
check "  after the wait, not later" [ "$elapsed" -lt 10 ]
check "  and every process of the check is killed" sh -c "! kill -0 $(cat "$W/grandchild") 2>/dev/null"

echo "== rescue, with a fake osascript"
fake_osascript() { # $1: what it prints, $2: its exit status. Keeps its arguments in $W/osascript.args.
    {
        echo '#!/bin/bash'
        # shellcheck disable=SC2016 # expands in the fake osascript
        printf 'printf "%%s\\n" "$@" >%q\n' "$W/osascript.args"
        printf 'echo %q\nexit %s\n' "$1" "$2"
    } >"$W/osascript"
    chmod 755 "$W/osascript"
}
setup
fake_osascript "Removed the module." 0
run rescue
check "rescue succeeds when sudo loads afterwards" [ "$status" = 0 ]
check "  and says so" said "sudo starts."
check "  without --force" sh -c "! grep -q -- --force '$W/osascript.args'"
run rescue --force
check "rescue --force passes it on to the root run" grep -qx -- " --force" "$W/osascript.args"
fake_osascript "Kept the module, because another file uses it" 1
run rescue
check "rescue succeeds when uninstall fails but sudo loads" [ "$status" = 0 ]
check "  and says the rescue did not finish" said "The rescue did not finish everything"
fake_osascript "execution error: User canceled. (-128)" 1
run rescue
check "a cancelled dialog fails" [ "$status" = 1 ]
check "  and says so" said "Cancelled; nothing was changed."
setup
run install
break_module
fake_osascript "execution error: No user interaction allowed. (-1713)" 1
run rescue
check "rescue fails when sudo still does not load" [ "$status" = 1 ]
check "  and points to the README" said "Break glass"

echo "== backups of sudo_local"
B=$W/pam.d/.sudo_local.pam_tid_look-backup
backups() { find "$W/pam.d" -name '.sudo_local.pam_tid_look-backup.*' | sort; }
setup
FAKE_TIME=20261114-100000 run install
check "install keeps the sudo_local it replaced" [ "$(cat "$B.20261114-100000" 2>/dev/null)" = "$APPLE" ]
check "  and says where" said "is kept as $B.20261114-100000"
FAKE_TIME=20261114-100001 run install --timeout 45
check "a reinstall keeps the one it replaced" [ "$(cat "$B.20261114-100001" 2>/dev/null)" = "$INSTALLED" ]
FAKE_TIME=20261114-100002 run install
check "  but none when sudo_local stays the same" [ ! -e "$B.20261114-100002" ]
FAKE_TIME=20261114-100003 run uninstall
check "uninstall keeps one too" grep -q "pam_tid_look.so timeout=45$" "$B.20261114-100003"
check "uninstall removes the module while backups name it" gone
check "  and succeeds" [ "$status" = 0 ]
check "  and puts Apple's sudo_local back" conf_is "$APPLE"
check "the backups stay" [ "$(backups | wc -l)" -eq 3 ]

setup
FAKE_TIME=20261114-110000 FAKE_TOUCHID=cancel run install
check "an install that is undone keeps no backup" [ -z "$(backups)" ]
run install
FAKE_TIME=20261114-110001 FAKE_SUDO=broken run uninstall
check "an uninstall that fails keeps one of what it changed" [ "$(cat "$B.20261114-110001" 2>/dev/null)" = "$INSTALLED" ]

setup
for t in 0 1 2 3 4 5; do echo "old $t" >"$B.20250101-00000$t"; done
echo mine >"$B.1"
echo mine >"$B.20250101-000000.orig"
echo mine >"$W/pam.d/sudo_local.bak-20250101-000000"
ln -s "$W/apple/pam_tid.so.2" "$B.20240101-000000"
FAKE_TIME=20261114-120000 run install
kept=$(find "$W/pam.d" -type f -name '.sudo_local.pam_tid_look-backup.*' | grep -cE 'backup[.][0-9]{8}-[0-9]{6}$')
check "only the newest five backups are kept" [ "$kept" = 5 ]
check "  the oldest are deleted" sh -c "[ ! -e '$B.20250101-000000' ] && [ ! -e '$B.20250101-000001' ]"
check "  the next oldest is kept" [ -e "$B.20250101-000002" ]
check "  and the newest" [ -e "$B.20261114-120000" ]
check "  files named otherwise are left alone" sh -c "[ -e '$B.1' ] && [ -e '$B.20250101-000000.orig' ] && [ -e '$W/pam.d/sudo_local.bak-20250101-000000' ]"
check "  and so is a link" [ -L "$B.20240101-000000" ]

setup
FAKE_TIME=20261114-130000 run install
FAKE_TIME=20261114-130000 run uninstall
check "of two runs in one second, the first one's backup is kept" [ "$(cat "$B.20261114-130000" 2>/dev/null)" = "$APPLE" ]
check "  and the second run succeeds" [ "$status" = 0 ]

echo "== install and uninstall show the change and ask first"
setup
run install
check "install asks on the terminal" grep -qF "Install pam_tid_look? [y/N]" "$W/tty"
check "  after showing what goes" said "-auth       sufficient     pam_tid.so"
check "  and what comes" said "+auth       sufficient     $W/Security/pam_tid_look/pam_tid_look.so"
sum=$(/usr/bin/shasum -a 256 <"$W/build/pam_tid_look.so")
check "  and the module's SHA-256 hash" said "SHA-256 ${sum%% *}"
check "  on a first install" said "not installed yet"
check "  and installs on y" conf_is "$INSTALLED"
run install
check "a reinstall of the same build says so" said "the same as the installed module"
check "  and that sudo_local stays as it is" said "$W/pam.d/sudo_local stays as it is."
echo "module v2" >"$W/build/pam_tid_look.so"
run install --timeout 45
check "a reinstall of another build says it differs" said "differs from the installed module"
check "  and shows the new line" said "+auth       sufficient     $W/Security/pam_tid_look/pam_tid_look.so timeout=45"
break_module
FAKE_ROOT=1 run rescue
run install
check "an install after a rescue says it replaces Apple's module" said "replaces Apple's pam_tid.so"

for answer in n no '' x; do
    setup
    printf '%s\n' "$answer" >"$W/tty"
    run install
    check "install answered '$answer' fails" [ "$status" = 1 ]
    check "  and says nothing was changed" said "Nothing was changed."
    check "  and changes nothing" conf_is "$APPLE"
    check "  and installs nothing" gone
    check "  and leaves no temporary files" no_leftovers
done
setup
: >"$W/tty" # end of input, as with Ctrl-D
run install
check "install without an answer fails" [ "$status" = 1 ]
check "  and changes nothing" conf_is "$APPLE"
setup
echo YES >"$W/tty"
run install
check "install answered YES installs" conf_is "$INSTALLED"

setup
rm "$W/tty"
run install
check "install without a terminal is refused" [ "$status" = 1 ]
check "  and says why" said "There is no terminal to ask on"
check "  and changes nothing" conf_is "$APPLE"
check "  and installs nothing" gone
check "  before the checks start" [ ! -e "$W/lock" ]
run install --yes
check "install --yes without a terminal installs" conf_is "$INSTALLED"
check "  without asking" [ ! -e "$W/tty" ]
check "  but shows the change" said "+auth       sufficient     $W/Security/pam_tid_look/pam_tid_look.so"
run uninstall
check "uninstall without a terminal is refused" [ "$status" = 1 ]
check "  and says why" said "There is no terminal to ask on"
check "  and changes nothing" conf_is "$INSTALLED"
check "  and keeps the module" [ -f "$M" ]
echo n >"$W/tty"
run uninstall
check "uninstall answered n fails" [ "$status" = 1 ]
check "  after asking" grep -qF "Uninstall pam_tid_look? [y/N]" "$W/tty"
check "  and showing the change" said "+auth       sufficient     pam_tid.so"
check "  and changes nothing" conf_is "$INSTALLED"
check "  and keeps the module" [ -f "$M" ]
check "  and leaves no temporary files" no_leftovers
echo y >"$W/tty"
run uninstall
check "uninstall answered y uninstalls" conf_is "$APPLE"
check "  and removes the module" gone
setup
run install
rm "$W/tty"
run uninstall --yes
check "uninstall --yes without a terminal uninstalls" conf_is "$APPLE"
check "  and removes the module" gone

setup
mkdir -p "$W/Security/pam_tid_look"
echo "module v1" >"$M"
echo n >"$W/tty"
run uninstall
check "uninstall of files sudo_local does not use asks first" grep -qF "Remove them? [y/N]" "$W/tty"
check "  and keeps them on n" [ -f "$M" ]
echo y >"$W/tty"
run uninstall
check "  and removes them on y" gone

setup
FAKE_ASK=edit run install
check "install refuses when sudo_local changed while it asked" said "changed while you were asked"
check "  and changes nothing more" conf_is "$APPLE"$'\n'"# edited meanwhile"
check "  and installs nothing" gone
setup
run install
FAKE_ASK=edit run uninstall
check "uninstall refuses when sudo_local changed while it asked" said "changed while you were asked"
check "  and changes nothing more" conf_is "$INSTALLED"$'\n'"# edited meanwhile"
check "  and keeps the module" [ -f "$M" ]

setup
run install
break_module
rm "$W/tty"
FAKE_ROOT=1 run rescue
check "rescue does not ask, even without a terminal" [ "$status" = 0 ]
check "  and replaces the module" [ "$(readlink "$M")" = "$W/apple/pam_tid.so.2" ]
run rescue --yes
check "rescue --yes is refused" said "--yes is only for install and uninstall"
run status --yes
check "status --yes is refused" said "--yes is only for install and uninstall"

echo "== an install interrupted at the question changes nothing"
setup
FAKE_ASK=hang run_until_waiting install
kill -INT "$script_pid"
finish_waiting
kill "$waiting_pid" 2>/dev/null || true
check "the interrupted run fails" [ "$status" = 130 ]
check "sudo_local is unchanged" conf_is "$APPLE"
check "nothing is installed" gone
check "no temporary files are left" no_leftovers

echo "== other cases"
setup
run uninstall
check "uninstall without an install succeeds" [ "$status" = 0 ]
check "  and says so" said "does not use pam_tid_look"
setup
rm "$W/pam.d/sudo_local"
run install
check "install without a sudo_local adds the line" grep -q "^auth       sufficient     .*pam_tid_look.so$" "$W/pam.d/sudo_local"
run uninstall
check "  and uninstall takes it out" sh -c "! grep -q pam_tid_look '$W/pam.d/sudo_local'"
setup
add_line "auth       sufficient     pam_tid.so"
run install
check "two pam_tid.so lines are refused" said "2 active pam_tid.so lines"
check "  without a change" gone
setup
run install --timeout 3601
check "--timeout 3601 is refused" said "--timeout takes 0 to 3600 seconds"
run uninstall --timeout 5
check "--timeout with uninstall is refused" said "only when installing"
run install --force
check "--force with install is refused" said "--force is only for rescue"
setup
rm -f "$W/lock"
run install
check "the lock file only root can open is made" [ "$(stat -f %Lp "$W/lock")" = 600 ]
run uninstall
chmod 644 "$W/lock"
run install
check "  and one anyone could read is restricted" [ "$(stat -f %Lp "$W/lock")" = 600 ]
setup
mkdir -p "$W/badbin"
for tool in awk cat chmod cp mktemp mv rm sed stat; do
    printf '#!/bin/sh\necho "the caller'\''s %s" >&2\nexit 1\n' "$tool" >"$W/badbin/$tool"
    chmod 755 "$W/badbin/$tool"
done
status=0
badpath=$W/badbin:$PATH
out=$(PATH=$badpath W=$W /bin/bash "$work/driver" install 2>&1) || status=$?
check "the caller's PATH is not used" [ "$status" = 0 ]
check "  and install works" conf_is "$INSTALLED"
setup
mkdir -p "$W/victim"
nl_path="$W/tmp"$'\n'"$W/victim"
mkdir -p "$nl_path"
W=$W /bin/bash -c 'source "$1"; source "$2"; add_temp "$3"; finish' _ \
    "$here/pam_tid_look.sh" "$work/stubs" "$nl_path" || true
check "a temporary path with a newline in it is removed" [ ! -e "$nl_path" ]
check "  as one path" [ -d "$W/victim" ]
run frobnicate
check "an unknown action is refused" [ "$status" = 2 ]
run
check "no action is refused" [ "$status" = 2 ]
setup
mkdir -p "$W/Security/pam_tid_look"
status=0
out=$(W=$W /bin/bash -c 'source "$1"; source "$2"; HERE=$DEST_DIR; main install' _ \
    "$here/pam_tid_look.sh" "$work/stubs" 2>&1) || status=$?
check "the installed copy refuses to install" said "This is the installed copy"

echo
if [ "$failures" = 0 ]; then
    echo "All installer tests passed."
else
    echo "$failures installer tests failed."
    exit 1
fi
