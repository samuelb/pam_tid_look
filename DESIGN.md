# Design record

Written 2026-11-13, against macOS 27.2.1 and sudo 1.9.17p2.

`pam_tidcmd` is a PAM module for `sudo` on macOS. It authenticates with Touch ID
like Apple's `pam_tid.so`, and adds the sudo command line to the dialog so you
can see what you are approving.

This file records why it is built the way it is. Items marked **Unverified**
have not been confirmed on a real install.

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
request is denied. This is also why the dialog cannot be exercised by a test
program.

### Checks before the dialog

These mirror Apple's module, taken from its published source and from the
compiled `pam_tid.so.2` on this system:

| Check | How | If it fails |
| --- | --- | --- |
| GUI session present | audit session flag `0x0010` (has graphic access) | `PAM_AUTH_ERR` |
| `sudo -A` in use | PAM data item `askpass-enabled` is set | `PAM_AUTHINFO_UNAVAIL` |
| Touch ID usable for this user | non-interactive LocalAuthentication evaluation | `PAM_AUTH_ERR` |

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
`sufficient`, sudo then continues to the normal password prompt.

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

### Layout

```
Command: sudo brew services restart nginx
Directory: ~/code/myproject
Requested by: zsh ← claude ← T3 Code (Beta)
```

Each line starts with a label so the text still reads correctly if the dialog
collapses line breaks into spaces.

**Unverified:** how the system dialog renders this text, including whether line
breaks are kept.

### Making the text safe to read

The command line is attacker-influenced text shown in a security dialog, so it
is normalised before display:

- Only printable ASCII and Unicode letters, digits, marks, punctuation and
  symbols are shown as-is. Everything else is written as `\u{XXXX}`. That covers
  newlines, escape sequences, bidi overrides, zero-width characters and unusual
  spaces, so an argument cannot start a fake line or reorder the text.
- Bytes that are not valid UTF-8 are written as `\xNN`.
- Arguments containing anything outside `A-Za-z0-9_@%+=:,./-` are wrapped in
  single quotes, so argument boundaries stay visible. The quoting is for
  reading. It is not guaranteed to be pasteable into a shell, because of the
  escapes above.
- Command lines over 400 characters keep the first 280 and last 80, with
  `…[N CHARACTERS NOT SHOWN]…` between them. Cutting the middle keeps both the
  program name and the end of the command visible, and the marker makes the
  omission obvious.

### Directory and requesting processes

The working directory is shown with the user's home abbreviated to `~`.

"Requested by" lists up to five ancestor processes, nearest first, with
consecutive duplicates collapsed. Names come from the executable path and fall
back to the kernel's process name. This is context, not proof: a process chooses
its own executable name.

## Build

- **Architectures:** arm64e, arm64 and x86_64 in one file. System binaries on
  Apple silicon are arm64e, so that slice is the one sudo is expected to load.
  **Unverified:** that sudo loads an ad-hoc signed arm64e module. The arm64
  slice was loaded successfully by `python3`.
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
refuses to continue unless `/Library` and `/Library/Security` are root-owned and
not group or world writable.

### Config changes

Only `/etc/pam.d/sudo_local` is edited, which is the file Apple provides for
local changes and keeps across system updates.

The existing `pam_tid.so` line is commented out with the prefix `#pam_tidcmd# `
and the new line is put in its place. Uninstalling removes the new line and
strips that prefix, which restores the file exactly. Leaving both modules active
was rejected because cancelling the first dialog would raise a second one.

### Confirm or roll back

After writing the config, the installer asks you to run `sudo -k true` in a new
terminal and confirm that it worked. Without a `y` within five minutes, or on
any error, the previous file is restored.

This guards against being locked out of sudo if the module fails to load. The
installer is already running as root, so it can undo the change even when sudo
itself is broken.

## Testing

`make test` covers what can run outside sudo: prompt formatting, escaping,
truncation, and the Touch ID availability check. The availability check was also
confirmed to answer per user: usable for the logged-in user, not usable for root
or a nonexistent uid.

The authorization request and the dialog are not covered, for the reason given
under "It only works inside `/usr/bin/sudo`".

## Known limits

- **Credential caching.** sudo caches a successful authentication for five
  minutes per terminal. Commands run in that window show no dialog. Setting
  `Defaults timestamp_timeout=0` in sudoers makes every command prompt.
- **Scripts.** `sudo ./script.sh` shows the script path, not its contents.
- **Private API.** The Touch ID availability check may stop working after a
  macOS update, in which case sudo falls back to the password prompt.
- **Scope.** The module is for sudo only.
