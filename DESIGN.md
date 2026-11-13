# Design record

Written 2026-11-13, against macOS 27.2.1 and sudo 1.9.17p2.

`pam_tidcmd` is a PAM module for `sudo` on macOS. It authenticates with Touch ID
like Apple's `pam_tid.so`, and adds the sudo command line to the dialog so you
can see what you are approving.

This file records why it is built the way it is. What was checked on a real
install, and how, is under [Verification](#verification).

## Why a new module

Apple's `pam_tid.so` asks Authorization Services for the right
`com.apple.security.sudo` and passes an empty environment, so the dialog has no
description. The module reads no options from the PAM config line, so there is
nothing to configure.

The third-party Touch ID modules found during a web search accept a fixed
`reason=` string in the PAM config. None showed the command being run.

## Authentication

### The decision is delegated, exactly as Apple does it

The module calls `AuthorizationCopyRights` for `com.apple.security.sudo` with
the same flags as Apple's module. Authorization Services and the system rule
decide whether the session owner authenticated. The module adds one thing to
that request: a `kAuthorizationEnvironmentPrompt` item carrying the text to
show.

The alternative was to call LocalAuthentication directly with a custom reason
string. That was rejected:

- sudo runs with effective uid 0, and root has no enrolled fingerprints. Getting
  LocalAuthentication to check the right user from that position needs private
  policies or options, and the module would then own the pass/fail decision.
- Staying on Apple's right means the module contains no authentication logic of
  its own. A bug in it can produce a wrong prompt or a failed login, but the
  approval itself is still Apple's.

### It only works inside `/usr/bin/sudo`

The right's rule is "2 of: `entitled`, `authenticate-session-owner`". The
`entitled` part requires the calling process to hold Apple's sudo entitlement.
The module inherits that by being loaded into sudo. Loaded anywhere else, the
request is denied at once, without a dialog (`errAuthorizationDenied`). So a
test program cannot raise sudo's dialog itself. It can raise the same
SecurityAgent dialog for a right of its own, which `make dialog-check` does.

### Checks before the dialog

These mirror Apple's module, taken from its published source and from the
compiled `pam_tid.so.2` on this system:

| Check | How | If it fails |
| --- | --- | --- |
| GUI session present | audit session flag `0x0010` (has graphic access) | `PAM_AUTH_ERR` |
| PAM user owns the session | PAM user's uid equals the audit session's `ai_auid` | `PAM_AUTH_ERR` |
| `sudo -A` in use | PAM data item `askpass-enabled` is set | `PAM_AUTHINFO_UNAVAIL` |
| Touch ID usable for this user | non-interactive LocalAuthentication evaluation | `PAM_AUTH_ERR` |

The session owner check is not in Apple's module. The right's rule
authenticates the owner of the audit session, so a granted right only vouches
for that user. sudo can ask about someone else: with `targetpw` or `runaspw`
it authenticates the target user, and a shell switched to another user with
`su` still runs in the original user's session. Without the check, the session
owner's finger would pass as that other user whenever that user has Touch ID
set up on the same Mac.

The Touch ID check exists so that sudo falls back to the terminal password
prompt when the lid is closed, no fingerprint is enrolled or biometry is locked
out. Without it, Authorization Services would raise a password dialog instead.

That check uses private API: `-[LAContext evaluatePolicy:options:error:]` with
option keys 1000 (not interactive) and 1019 (user id). The values were read from
the disassembly of `pam_tid.so.2`. If the method is missing after a macOS
update, the module reports Touch ID as unusable and sudo asks for the password.
It never fails open.

### Result mapping

Only `errAuthorizationSuccess` returns `PAM_SUCCESS`. Everything else, including
cancelling the dialog, returns `PAM_AUTH_ERR`. With the module configured as
`sufficient`, sudo then continues to the normal password prompt. Cancelling
returns `errAuthorizationCanceled` (-60006), and sudo was seen to ask for the
password on the terminal.

The module takes no options. In particular, the right name cannot be changed
from the PAM config.

## The prompt

### Where the command comes from

The command is the argv of the process the module is loaded into, read with
`_NSGetArgv()`. That process is the real sudo, so the text is what sudo was
actually asked to run, not something the caller supplies separately.

The whole invocation is shown, sudo flags included. Parsing out "the command"
was rejected: sudo's option grammar is easy to get wrong, and flags such as
`-u`, `-E` and `-s` are part of what you are approving.

The program name is always shown as `sudo`, not as `argv[0]`. The caller picks
`argv[0]` freely (`exec -a echo sudo rm -rf /`) and this sudo does not act on
it: run as `echo` or `sudoedit`, it behaves as plain `sudo`. Showing it would
make that command read `echo rm -rf /`.

sudo changes some arguments in place before PAM runs: it splits
`--preserve-env=A,B` with `strtok_r()`, which writes a NUL over each comma, so
the argument reads `--preserve-env=A` by then. exec stores the argument strings
back to back, so each argument still runs up to the start of the next one. The
module reads up to there and turns those NULs back into commas. The last
argument has no next one to measure against and is read as it is; an option is
only last with `-s`, `-i`, `-l` or `-v`, which approve a root shell or run
nothing.

### Layout

```
Command: sudo brew services restart nginx
Directory: ~/code/myproject
Requested by: zsh ← claude ← T3 Code (Beta)
```

Each line starts with a label so the text still reads correctly if the dialog
collapses line breaks into spaces.

The dialog keeps the line breaks, so each label starts its own line. The dialog
is 260 points wide, so long lines wrap and the dialog grows taller. A single
400-character line makes it about twice as tall. The prompt ends with two
newlines, but they do not show as a gap: the text runs straight into the
dialog's next line.

### Making the text safe to read

The command line is attacker-influenced text shown in a security dialog, so it
is normalised before display:

- Only printable ASCII and Unicode letters, digits, marks, punctuation and
  symbols are shown as-is. Everything else is written as `\u{XXXX}`. That covers
  newlines, escape sequences, bidi overrides, zero-width characters and unusual
  spaces, so an argument cannot start a fake line or reorder the text.
- Characters that draw nothing are written as `\u{XXXX}` too, even where Unicode
  classes them as letters, marks or symbols: every default-ignorable code point
  (variation selectors, the combining grapheme joiner, Hangul fillers) and
  U+2800 BRAILLE PATTERN BLANK. Otherwise `/etc/hosts` followed by a variation
  selector would look like `/etc/hosts`.
- Bytes that are not valid UTF-8 are written as `\xNN`.
- Arguments containing anything outside `A-Za-z0-9_@%+=:,./-` are wrapped in
  single quotes, so argument boundaries stay visible. The quoting is for
  reading. It is not guaranteed to be pasteable into a shell, because of the
  escapes above.
- Command lines over 400 characters keep the first 280 and last 80, with
  `…[N CHARACTERS NOT SHOWN]…` between them. Cutting the middle keeps both the
  program name and the end of the command visible, and the marker makes the
  omission obvious. The cuts are at those fixed positions (UTF-16 units),
  moved by one only to keep a surrogate pair whole. Widening them to whole
  composed characters was rejected: one letter followed by thousands of
  combining marks is a single composed character and would take the whole
  line.
- Arguments are separated by U+200E LEFT-TO-RIGHT MARK as well as a space.
  Without it, the quotes and space between two right-to-left arguments take
  their direction, and AppKit draws `cp 'א' 'ב'` as `cp 'ב' 'א'`.
- The Directory and Requested by lines are cut the same way above 200
  characters: the directory keeps its first 80 and last 100, the process list
  its first 120 and last 60. A deep directory with escaped names would
  otherwise make the dialog taller than the screen.

### Directory and requesting processes

The working directory is shown with the user's home abbreviated to `~`.

"Requested by" lists up to five ancestor processes, nearest first, with
consecutive duplicates collapsed. Names come from the executable path and fall
back to the kernel's process name. This is context, not proof: a process chooses
its own executable name.

## Build

- **Architectures:** arm64e, arm64 and x86_64 in one file. System binaries on
  Apple silicon are arm64e, so that slice is the one sudo is expected to load.
  sudo on Apple silicon loads this ad-hoc signed build (see Verification).
- **Exports:** compiled with hidden visibility. Only `pam_sm_authenticate`,
  `pam_sm_setcred` and `pam_sm_acct_mgmt` are exported.
- **Signing:** ad-hoc.
- **Language:** Objective-C with ARC, because the work is Foundation string
  handling plus one Objective-C call into LocalAuthentication.

## Installation

### Location

The module is installed to `/Library/Security/pam_tidcmd/pam_tidcmd.so`, owned
by root, mode 444, and referenced by absolute path in the PAM config.

`/usr/local/lib/pam` is the usual place for third-party modules, but on this
machine `/usr/local/lib` is owned by the user. Any process running as that user
could then swap the module for one that approves everything. The installer
refuses to continue unless `/Library` and `/Library/Security` are root-owned,
not group or world writable, and without ACL entries that allow anything.

The module is not copied with `install(1)`, because that copies ACLs: an ACL on
the user-owned build that lets the user write would end up on the root-owned,
mode 444 module. The installer writes it into a file that `mktemp` created as
root inside the module's directory, removes any ACL, sets owner and mode, and
renames it into place.

### Config changes

Only `/etc/pam.d/sudo_local` is edited, which is the file Apple provides for
local changes and keeps across system updates.

The existing `pam_tid.so` line is commented out with the prefix `#pam_tidcmd# `
and the new line is put in its place, with the same control flag (`sufficient`
when there was no `pam_tid.so` line and the new one is added at the end).
Changing a `required` line to `sufficient` would let Touch ID skip the rules
after it. Uninstalling removes the new line and strips that prefix, which
restores the file exactly. Leaving both modules active was rejected because
cancelling the first dialog would raise a second one.

Lines are recognised by their module field only. A module name that appears in
a comment or an option does not make a line count as either module. With more
than one active `pam_tid.so` line the installer refuses to change anything,
because one replacement line cannot keep the meaning of several.

The new config is written to a temporary file and renamed into place only if
it was produced without error, so a failure cannot leave a partial file.

Only one install or uninstall runs at a time (a lock directory in `/var/run`
holding the pid). A second run would otherwise replace the first one's backup
while the first waits for confirmation. A lock left by a killed run is not
taken over automatically, since two runs could both judge it stale; the
installer prints the command that removes it.

The ownership, permission and ACL checks on `/Library` and `/Library/Security`
stop the installer if they cannot be carried out, rather than passing.

### Confirm or roll back

After writing the config, the installer asks you to run `sudo -k true` in a new
terminal and confirm that it worked. Without a `y` within five minutes, or on
any error, the previous config and the previous module are restored. Both are
saved before either is changed; the old module is kept as a hard link, so a
reinstall over a working module can be undone even though the new build already
took its place.

This guards against being locked out of sudo if the module fails to load. The
installer is already running as root, so it can undo the change even when sudo
itself is broken.

## Testing

`make test` covers what can run outside sudo: prompt formatting, escaping,
truncation, and the Touch ID availability check. The availability check was also
confirmed to answer per user: usable for the logged-in user, not usable for root
or a nonexistent uid.

`make dialog-check` checks that the prompt is drawn. It raises real dialogs for
about two seconds each and closes them by killing the process that asked
(SIGKILL, since sudo ignores the others). Ctrl-C stops it the same way. It
cannot read the dialog's text without Screen Recording or Accessibility
permission, but it can read the dialog's size, so it compares the height for a
short and a long text, twice:

- a right of its own, with no prompt and with a six-line prompt. An undefined
  right falls back to Apple's `default` rule, so no root and no
  `security authorizationdb write` are needed. If such a dialog is approved,
  that rule leaves an admin credential that the whole session shares for five
  minutes. The program destroys it: it lets a child whose dialog was answered
  finish and free its rights, then asks for the right again without UI and
  destroys whatever that yields.
- `sudo -k /usr/bin/true` through the installed module, with and without 40
  extra arguments. Only the module's prompt depends on the command line.

Approving and cancelling need a person and were tested by hand (see
Verification).

## Verification

Checked on 2026-11-13 on Apple silicon with macOS 27.2.1, with the module
installed.

- **The module loads in sudo.** The unified log shows the module's own
  `pam_tidcmd` log line in the sudo process, and authd granting
  `com.apple.security.sudo` to `/usr/bin/sudo`.
- **The prompt reaches the dialog.** authd copies the request's environment into
  the hints it sends to SecurityAgent (`auth_items_copy(engine->hints,
  environment)` in `OSX/authd/engine.m`, Security-61901.120.67), and
  SecurityAgent reads the `prompt` hint. `dialog_check` measured the heights
  below. The sudo ones vary by a line or so with the Requested by chain, which
  depends on how the check is started:

  | Dialog | Height (points) |
  | --- | --- |
  | Own right, no prompt | 257 |
  | Own right, six-line prompt | 321 |
  | `sudo -k /usr/bin/true` | 369 |
  | The same with 40 extra arguments | 577 |

  Looking at the dialog confirmed it: the Command, Directory and Requested by
  lines each start a new line and are readable.
- **Approving** with Touch ID: sudo exits 0.
- **Cancelling:** sudo prints `Password:` on the terminal. Ctrl-C at that prompt
  ends sudo with "a password is required".
- **Closing the dialog from the terminal.** sudo catches SIGINT and SIGTERM while
  it authenticates (`init_signals()` in sudo's `src/signal.c`), so neither Ctrl-C
  nor `kill` ends it while the dialog is open. With SIGTERM the dialog was seen to
  stay open until it was approved. SIGKILL ends sudo, and authd then closes the
  dialog ("Caller dismissed" in its log). This comes from sudo, so it applies to
  Apple's `pam_tid.so` as well.

## Known limits

- **Credential caching.** sudo caches a successful authentication for five
  minutes per terminal. Commands run in that window show no dialog. Setting
  `Defaults timestamp_timeout=0` in sudoers makes every command prompt.
- **Scripts.** `sudo ./script.sh` shows the script path, not its contents.
- **No way out from the terminal.** While the dialog is open, Ctrl-C in the
  terminal does nothing. The dialog has to be answered, or sudo killed with
  SIGKILL from elsewhere. This is sudo's behaviour (see Verification).
- **Private API.** The Touch ID availability check may stop working after a
  macOS update, in which case sudo falls back to the password prompt.
- **Scope.** The module is for sudo only.
