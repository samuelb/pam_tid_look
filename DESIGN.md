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
cancelling the dialog and the dialog timing out, returns `PAM_AUTH_ERR`. An
Objective-C exception inside the module, such as one from the private Touch ID
check after a macOS update, is caught and returns `PAM_AUTHINFO_UNAVAIL`;
uncaught, it would end sudo for everyone who has to authenticate. Every
exception that can happen is thrown before the request is sent. With
the module configured as `sufficient`, sudo then continues to the normal
password prompt. Cancelling returns `errAuthorizationCanceled` (-60006), and
sudo was seen to ask for the password on the terminal.

### Timeout

If nobody answers the dialog within the timeout, 30 seconds by default, the
module closes it and sudo asks for the password on the terminal, as it does
after Cancel. Without this, a sudo started while you are away, or by a program
that waits for it, hangs on the dialog until someone answers it.

The module sends the request with `AuthorizationCopyRightsAsync` and waits for
the answer. When the timeout runs out, it calls `AuthorizationDismiss()`.
authd then destroys the request's SecurityAgent UI and ends the request with
`errAuthorizationDenied` (-60005), which maps to `PAM_AUTH_ERR`. authd's answer
still decides: a fingerprint accepted just before the dismissal still returns
`PAM_SUCCESS`.

The dismissal is handled while the request is still waiting, because authd
runs each message from a client on a concurrent queue (`OSX/authd/main.c`),
and the dismissal does not wait for the per-connection queue that the pending
request holds (`connection_destroy_agents()` in `OSX/authd/connection.c`).

`AuthorizationDismiss()` is private API. `AuthorizationPriv.h` describes it as
dismissing "all Authorization dialogs associated to the calling process"; in
sudo, that is only this module's dialog. The module looks it up at run time.
If it is missing after a macOS update, the module logs an error and the dialog
waits for an answer without a time limit, as Apple's does.

authd ignores a dismissal that reaches it before the request's dialog exists:
`connection_destroy_agents()` acts only on a running engine, and
`engine_authorize()` clears the dismissed flag when it starts. The request is
sent from a dispatch queue, so this is possible in principle with a short
timeout. The module therefore repeats the dismissal every second until the
request has ended, and logs an error if the first one did not end it.

The time counts from the request. It does not restart when you interact with
the dialog, so a password being typed into the dialog's own password field is
cut off too.

Other ways to close the dialog were rejected:

- Killing the requesting process closes the dialog (see Verification), but
  here that process is sudo. The request would have to come from a forked
  child, and XPC and Objective-C are not safe to use in a child forked without
  exec.
- No dialog timeout was found in authd's source. The rule attribute `timeout`
  is how long a credential may be reused, not how long a dialog stays open.

### Options

The module takes one option, on its line in the PAM config:

```
auth       sufficient     /Library/Security/pam_tidcmd/pam_tidcmd.so timeout=60
```

`timeout=SECONDS` is how long the dialog waits for an answer, a whole number
from 0 to 3600 written with at most four digits. 0 means no limit. Without the
option, the timeout is 30 seconds. An invalid value is logged and the default
is used: the timeout only decides how soon sudo falls back to the password,
not whether anyone gets in, so a typo should not disable Touch ID. Unknown
options are logged and ignored. The right name cannot be changed from the PAM
config.

## The prompt

### Where the command comes from

The command is the argv of the process the module is loaded into, read with
`_NSGetArgv()`. That process is the real sudo, so the text is what sudo was
actually asked to run, not something the caller supplies separately.

The whole invocation is shown, sudo flags included. Parsing out "the command"
was rejected: sudo's option grammar is easy to get wrong, and flags such as
`-u`, `-E` and `-s` are part of what you are approving. The PATH hint parses
only enough to find the command word, and adds a section rather than changing
this one.

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
Command:
sudo brew services restart nginx

Found in PATH:
/opt/homebrew/bin/brew
Can be changed without root.

Directory:
~/code/myproject

Requested by:
zsh ← claude ← T3 Code (Beta)
```

Found in PATH is there only for a command word without a `/` (see The PATH
hint), and its last line only when someone other than root can change the
file.

Each label has a line of its own, so a long value starts at the left edge and
wraps under itself, and a blank line separates the sections. The labels also
keep the text readable if a dialog ever collapses line breaks into spaces.

The dialog keeps line breaks and blank lines. On the dialog for a right of its
own, each line of the prompt, blank or not, adds 16 points of height; a line
holding only a space or a no-break space counts the same as an empty one
(measured 2026-11-14). So this layout makes sudo's dialog about 80 points
taller than the earlier one, which had label and value on one line and no
blank lines. **Unverified:** how it looks in sudo's own dialog.

The dialog is 260 points wide, so long lines wrap and the dialog grows taller.
A single 400-character line makes it about twice as tall. The prompt ends with
two newlines. On the dialog for a right of its own they add two lines of
height, but in sudo's dialog they did not show as a gap: the text ran straight
into the dialog's next line.

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
- Letters that look like other letters are written as `\u{XXXX}` too, so
  `sudo /usr/bin/іd` with a Cyrillic `і` reads `'/usr/bin/\u{456}d'`. Within a
  run of letters (marks included), Cyrillic, Greek, Armenian and Cherokee ones
  are escaped when the run also has a Latin letter. Every letter, mark or
  number that NFKC changes is escaped as well: fullwidth `ｉ`, math bold `𝐢`,
  the Kelvin sign, the ligature `ﬁ`, Roman numeral `ⅰ`. A word in one script,
  such as `/tmp/Übersicht/日本.txt` or `Привет.txt`, is shown as it is.
  Escaping every non-ASCII character, as the fork does, was rejected: it makes
  file names in other languages hard to read. The rule needs no parsing, so it
  applies to every line shown, not only the program. It also escapes rarer
  forms that NFKC changes, such as halfwidth katakana and `²`.
- The script of a letter comes from ICU (`u_getIntPropertyValue()` in
  libicucore, which Foundation itself links), by ICU's stable script numbers,
  since `uscript.h` is not in the SDK. NFKC is Foundation's
  `precomposedStringWithCompatibilityMapping`, applied to each code point on
  its own, so that a letter followed by a combining accent still passes.
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
- The Directory, Found in PATH and Requested by lines are cut the same way
  above 200 characters: the directory and the file found keep their first 80
  and last 100, the process list its first 120 and last 60. A deep directory
  with escaped names would otherwise make the dialog taller than the screen.

### Directory and requesting processes

The working directory is shown with the user's home abbreviated to `~`.

"Requested by" lists up to five ancestor processes, nearest first, with
consecutive duplicates collapsed. Names come from the executable path and fall
back to the kernel's process name. This is context, not proof: a process chooses
its own executable name.

### The PATH hint

For a command word without a `/`, sudo runs the first match in the caller's
`PATH`, and the command line does not say which file that is:
`PATH=~/evil:/usr/bin sudo id` reads `sudo id` and runs `~/evil/id`. So the
prompt names the file in a section of its own, after the command:

```
Found in PATH:
~/evil/id
Can be changed without root.
```

It is a hint, not a claim. The Command section stays as it is, and the hint is
left out whenever finding the command or its file is not clear-cut.

**The command word.** The module mirrors only as much of sudo's option rules
(`parse_args()`) as finding it needs. Options end at `--` or at the first word
that is not one. Short flags group, and a value is the rest of the word or the
next word (`-Eu root`, `-uroot`). `VAR=value` words before the command are
skipped, unless the word before is `--`; `argv[0]` does not count as that
word. The hint is left out for:

- long options, since `getopt_long` accepts abbreviations;
- `-s` and `-i`, where a shell finds the command;
- `-e` and `sudoedit` (a program name ending in `edit`, as `parse_args()`
  checks it);
- `-l`, `-v`, `-K`, `-V` and `-h`, which run nothing, and `-k` without a
  command;
- `-D` and `-R`, which change the directory or the root;
- `-u` with anyone but root (`root`, or `#` and a uid of zeros), `-u` given
  twice, `-g` and `-U`;
- `-a`, `-c`, `-r` and `-t`, which macOS does not use, and unknown letters;
- a `PATH=` word on the command line, and a word that starts with `=`.

**Which PATH.** sudoers searches the last non-empty `PATH=` in the environment
exec passed (`init_vars()` in `plugins/sudoers/sudoers.c`), not the first, which
`getenv()` returns. A caller can give a name twice, which a shell cannot. The
module reads that environment with `KERN_PROCARGS2` on its own process: the
strings exec wrote, in order, duplicates kept, followed by the kernel's own
`apple` strings, none of which is a `PATH`. `_NSGetEnviron()` was not used.
It is an array of pointers, which dyld edits in a setuid program (it drops the
`DYLD_` variables) and `setenv()` and `unsetenv()` change. Whether it still
holds the strings sudoers read when PAM runs was not checked: that needs the
module inside sudo. The hint is left out unless the arguments that
`KERN_PROCARGS2` returns are sudo's argv, byte for byte and back to back: then
the environment is known to start where they end. An empty `argv[0]` fails
that, and so does an argument sudo cut in place, except the last one; sudo
only cuts an option, and an option is last only when there is no command.

**The search** is that of sudoers' `find_path()`. Each entry is tried as
`entry/word`, and the first regular file with an execute bit wins. Empty and
`.` entries are tried only after all the others, so a match that only they
could give leaves the hint out. So do a relative entry, a name too long for
sudo, and an error other than "no such file", such as a loop of symbolic links.

**Whose search.** sudoers searches as the user the command runs as, then as the
caller (`resolve_cmnd.c`). The module runs as root and sees every directory,
so for a command that runs as root its first match is sudo's. Another user
might not see into the match's directory and get a later one, which is why the
hint is only given for root. Two sudoers settings change the search:
`secure_path`, which sudo then searches instead of `PATH`, and
`runas_default`, which runs a command without `-u` as another user. Neither is
set on macOS as it ships. The module reads `/etc/sudo.conf` and `/etc/sudoers`
with every file it includes, as root, and gives no hint if either word appears
outside a comment, if `sudo.conf` names a plugin, or if it cannot read or
follow a file. It looks for the words rather than parsing sudoers, so a mistake
only leaves the hint out. **Unverified:** that the module can read sudoers
inside sudo, and that macOS's own `/etc/sudoers` passes. The tests use files
of their own, and `/etc/sudoers` cannot be read without root.

**The warning.** "Can be changed without root." is added when someone other
than root can change the file found: the file, or any directory on the way to
it, through symbolic links, is not owned by root, is group or world writable,
or has an ACL entry that allows something. It is the rule of `check_dirs()` in
`pam_tidcmd.sh`. So it is quiet for `/usr/bin/id` and warns for `~/evil/id`
and for `/opt/homebrew/bin/nginx`.

The `PATH` directories before the match are not checked. sudo searched before
the module does, so someone who can change an earlier directory can make the
two searches differ (see Known limits). Only a warning for every such directory
catches that, which is what the fork does. On a Mac with `~/.local/bin`,
`~/.cargo/bin` and `/opt/homebrew/bin` before `/usr/bin`, that warning would
show for almost every command, and a warning that always shows is not read.

**Display.** The file is escaped like the rest (see Making the text safe to
read), with the home abbreviated to `~`. The section adds three lines to the
dialog, four with the warning: about 48 or 64 points. **Unverified:** how it
looks in sudo's own dialog.

The environment reader, the file check and the sudoers check follow code from
the fork (`process_args()`, `root_only()`, `acl_allows()`,
`read_sudo_policy()`, `sudoers_mentions()`), which is under the MIT License,
© 2026 Lauri Gates. Comments in `pam_tidcmd.m` say where.

## Build

- **Architectures:** arm64e, arm64 and x86_64 in one file. System binaries on
  Apple silicon are arm64e, so that slice is the one sudo is expected to load.
  sudo on Apple silicon loads this ad-hoc signed build (see Verification).
- **Exports:** compiled with hidden visibility. Only `pam_sm_authenticate`,
  `pam_sm_setcred` and `pam_sm_acct_mgmt` are exported.
- **Signing:** ad-hoc.
- **Language:** Objective-C with ARC, because the work is Foundation string
  handling plus one Objective-C call into LocalAuthentication.
- **Checks:** `make analyze` runs clang's static analyzer, and `make sanitize`
  the prompt tests built with AddressSanitizer and UndefinedBehaviorSanitizer.
  `make test` runs both (see Testing). The sanitized build is for the Mac it
  runs on only: only that slice can run there, so other slices would test
  nothing.

## Installation

### What can lock you out of sudo

`/etc/pam.d/sudo` includes `sudo_local`. OpenPAM loads every module a policy
names when sudo calls `pam_start()`, following includes, and if one cannot be
loaded, `pam_start()` fails. sudo then stops with "sudo: unable to initialize
PAM: system error", for every user, root included. A missing module file was
seen to do this (see Verification); a slice or signature that dyld rejects, or
a symbol that a macOS update removed, would fail the same way. A module that
crashes or hangs in `pam_sm_authenticate` stops sudo for everyone who has to
authenticate.

So the installer changes nothing it cannot check first, checks the result
through sudo itself, and undoes the change when a check fails. For a module
that breaks later, there is a way back that does not use sudo (Break glass).

### Files

The installer puts three files in `/Library/Security/pam_tidcmd`, owned by
root:

| File | Mode | Purpose |
| --- | --- | --- |
| `pam_tidcmd.so` | 444 | the module, named by absolute path in `sudo_local` |
| `pam_tidcmd_probe` | 555 | the load check (see Checks) |
| `pam_tidcmd` | 555 | a copy of the script, so that `uninstall` and `rescue` work without Homebrew or the build directory |

`/usr/local/lib/pam` is the usual place for third-party modules, but on this
machine `/usr/local/lib` is owned by the user. Any process running as that user
could then swap the module for one that approves everything. The installer
refuses to continue unless `/Library` and `/Library/Security` are root-owned,
not group or world writable, and without ACL entries that allow anything. These
checks stop the installer if they cannot be carried out, rather than passing.

The files are not copied with `install(1)`, because that copies ACLs: an ACL on
the user-owned build that lets the user write would end up on the root-owned
module. The installer copies the contents into a directory that `mktemp -d`
created as root inside the module's directory, removes any ACL, sets owner and
mode, and renames each file into place.

The script sets its own `PATH` to the system's directories. sudo can keep the
caller's `PATH`, and GNU coreutils put first there have a `stat` and a `chmod`
that take other options, so the ownership checks would misread them. Nothing
is written under the caller's `TMPDIR` either: a file there could be swapped
for a link before root opens it.

### Homebrew

The formula (`Formula/pam_tidcmd.rb`) builds the module and the probe, puts
them and the script in Homebrew's `libexec/pam_tidcmd`, and links
`bin/pam_tidcmd` to the script. The script finds the files next to its own
resolved path, so the same script works from the build directory, from
Homebrew and from `/Library/Security/pam_tidcmd`.

The formula does not touch sudo. Homebrew does not run as root, and PAM must
never load a module from Homebrew's prefix:

- The prefix belongs to the user, which is the problem described under Files.
- `brew upgrade`, `brew cleanup` and `brew uninstall` delete files from it. If
  `sudo_local` named one of them, the next of these commands would stop sudo
  from starting.

So `sudo pam_tidcmd install` copies the files to `/Library/Security/pam_tidcmd`,
as from the build directory. After `brew upgrade`, sudo keeps the copy it has
until install is run again; `pam_tidcmd status` says when the two differ.
`brew uninstall` leaves sudo as it is, and the installed copy of the script can
still uninstall.

The formula is published in the tap `samuelb/tap`, the repository
`samuelb/homebrew-tap`, so it installs as `samuelb/tap/pam_tidcmd`. A release
is a tag `vX.Y.Z` on `samuelb/pam_tidcmd`. Pushing one runs
`.github/workflows/release.yml`:

1. `make lint` and `make test` on the tagged commit, as CI runs them.
2. `render_formula.sh` sets the formula's `url` to GitHub's archive of the tag
   and `sha256` to that archive's checksum, downloaded as Homebrew downloads
   it. The formula is then installed from a local tap, built from source, and
   checked with `brew test`, `brew audit --strict` and `brew style`.
3. The GitHub release, with notes generated from the commits.
4. The formula is pushed to the tap as `Formula/pam_tidcmd.rb`, by the tap's
   reusable publish workflow, which the releases of the tap's other formulae
   use too.

Each step runs only if the one before it passed, so a release that fails a
test publishes nothing. The workflow does nothing in a copy of the repository,
which could not push to the tap anyway.

The formula in this repository is a valid formula with a stand-in `url` and
`sha256`, not a template with markers, so `brew style` can check it as it is.
`render_formula.sh` replaces exactly one `url` line and one `sha256` line of
the form it expects, and stops otherwise: a formula changed in a way it does
not know stops the release instead of going out half rendered. The release
uses GitHub's archive of the tag rather than a tarball of its own, as most
formulae do.

The tap must be trusted before Homebrew loads a formula from it (`brew trust`),
except for `brew install` given the full name. So the release trusts its local
tap before `brew test` and `brew audit`.

Pushing to the tap needs a token in the secret `HOMEBREW_TAP_TOKEN`: the run's
own `GITHUB_TOKEN` can write only to this repository. The actions and the
publish workflow are pinned to full commit SHAs, as the publish workflow pins
its own. **Unverified:** the release has not run; it needs the published
repository and the secret.

### Config changes

Only `/etc/pam.d/sudo_local` is edited, which is the file Apple provides for
local changes and keeps across system updates.

The existing `pam_tid.so` line is commented out with the prefix `#pam_tidcmd# `
and the new line is put in its place, with the same control flag (`sufficient`
when there was no `pam_tid.so` line and the new one is added at the end).
Changing a `required` line to `sufficient` would let Touch ID skip the rules
after it.

`--timeout SECONDS` puts `timeout=SECONDS` on the new line, checked by the same
rule as the module's. Without it, a reinstall keeps the `timeout=` value of the
current line, and stops if that value is invalid; a first install writes no
option, so the module's default applies. Uninstalling removes the new line and
strips that prefix, which restores the file exactly. Leaving both modules
active was rejected because cancelling the first dialog would raise a second
one.

Lines are recognised by their module field only. A module name that appears in
a comment or an option does not make a line count as either module. The fields
are read as OpenPAM reads them, with the line cut at the first `#`, even inside
a word, so `pam_tid.so#note` names `pam_tid.so`. With more
than one active `pam_tid.so` line the installer refuses to change anything,
because one replacement line cannot keep the meaning of several.

The new config is written to a temporary file and renamed into place only if
it was produced without error, so a failure cannot leave a partial file.

Only one install or uninstall runs at a time, so that a run keeps its saved
copies until it is done. The lock is a `flock` on `/var/run/pam_tidcmd.lock`, taken
with `lockf(1)` on a descriptor the script holds. The kernel releases it when
the process ends, so a killed run cannot leave a stale lock to be removed by
hand. Only root may open the lock file: `flock()` also works on a descriptor
opened for reading, so if anyone could read the file, anyone could hold the
lock and keep install, uninstall and rescue from running. The Touch ID check is started without the descriptor, so that it cannot
hold the lock after the script ends.

### Checks

Two checks are used before and after a change:

- **The probe** (`pam_tidcmd_probe`) loads a module with `dlopen()`, as OpenPAM
  does, or calls `pam_start()` for a policy, which loads every module the policy
  names. It authenticates nobody and shows nothing. OpenPAM on macOS takes only
  service names: a name containing `/` is refused. So a policy to check is
  written to a temporary file in `/etc/pam.d`. A service without a policy file
  falls back to `other` and loads, so the probe insists that the file exists.
  The probe is built for the module's architectures; on Apple silicon it runs as
  arm64e and loads the module's arm64e slice, as sudo does.
- **`sudo -n /usr/bin/true` run as root.** Root needs no password, but sudo
  initialises PAM first ("Init authentication system regardless of whether we
  need a password", `check_user()` in sudoers' `check.c`), so this loads the
  whole config in the real sudo and fails with "unable to initialize PAM" when
  a module cannot be loaded. It also catches anything else that keeps sudo
  from running a command.

### Asking before a change

Install and uninstall show what they will change and ask `[y/N]` before they
change anything. Both show a `diff -u` of the current and the new
`sudo_local`. Install also shows the SHA-256 hash of the module it is about to
install, taken from the copy that will be moved into place rather than from the
build, which could change meanwhile, and says whether that module differs from
the installed one. The hash can be compared with a published one.

Install asks after checks 1 to 3 (see Install), so that you are not asked about
a change those checks would refuse, and before it saves the current files or
moves anything into place. Uninstall asks before its first write, once it knows
whether it will have to set `sudo_local` aside, and says so. When `sudo_local`
does not use the module, it asks before deleting the files that are left.

The question goes to the terminal, `/dev/tty`, and the answer is read from
there. stdin and stdout can be a pipe or a file, and the answer should come from
the person at the terminal, not from whatever feeds the script. `y` and `yes`,
in either case, mean yes; anything else, an empty line or the end of input
means no. `--yes` answers in advance, for scripts. Without a terminal and
without `--yes`, install refuses at once, before its checks, and uninstall
refuses when it reaches the question. Either way nothing has been changed.

What is written is what was shown. Install copies `sudo_local` before check 3,
and uninstall before it builds the new file. If `sudo_local` no longer matches
that copy after the answer, the run stops without changing anything.

`rescue` never asks. It runs as root from an administrator dialog, which has no
terminal, and it is for when sudo is already broken. `--yes` is refused with
`rescue` and `status`.

**Unverified:** the question through the real sudo. It was answered on a pty
made by `script(1)`, also with stdin and stdout redirected, and refused in a
session without a controlling terminal (2026-11-14). sudo runs the command on
a pty of its own by default (`use_pty`), which `/dev/tty` should then be.

### Install

Before changing anything, install requires that:

1. `sudo -n /usr/bin/true` as root succeeds now. Otherwise a check after the
   change would prove nothing.
2. The new module, copied next to its final place under a temporary name,
   loads in the probe and exports `pam_sm_authenticate`.
3. PAM can load the new `sudo_local`, written with the module at that
   temporary path.

Then it shows the change and asks (see Asking before a change). If you agree,
it keeps the current `sudo_local` and the current files (as hard links, so
a reinstall over a working module can be undone after the new one has taken its
place), moves the new files into place and writes `sudo_local`. Afterwards it
requires that:

4. The probe can load `/etc/pam.d/sudo`, which now includes the new
   `sudo_local`.
5. `sudo -n /usr/bin/true` as root succeeds.
6. The user who ran the installer approves a Touch ID dialog for
   `sudo -S -k /usr/bin/true`, run as that user through the new config. `-k`
   makes sudo authenticate despite cached credentials, and leaves them as they
   are. `-S` with no input makes the password fallback fail at once, so only an
   approved dialog passes. After two minutes without an answer, the check kills
   that sudo, which closes its dialog.

The sixth check replaces asking you to run `sudo -k true` in a second terminal
and type `y` within five minutes. It tests the same path, authentication
through the module, without relying on the answer. It needs `SUDO_USER`, so
install refuses to run from a root login shell. It also needs the GUI session,
so an install over ssh is always undone.

If check 4, 5 or 6 fails, the script stops on an error, or the run is
interrupted, the EXIT trap puts back the saved `sudo_local`, then the previous
files, and checks again that sudo starts. `sudo_local` goes first, so a failed
first install never leaves it naming a module that is already deleted. If
`sudo_local` cannot be put back, nothing else is touched: the module it names
stays, and so does the saved copy, whose path is printed.

Every signal that ends the script by default and can be caught (HUP, INT,
QUIT, TERM, USR1, USR2, ALRM) leads to that trap. The handler first ignores
all of them, as does the undo, so a second signal cannot end the script before
or during the undo. Closing the terminal, for one, can deliver more than one
signal: the terminal signals every process in it, and sudo relays signals to
the command it runs. Without this, a second signal arriving 30 µs after the
first ended a test run before its undo began, most of the time. Writes to a closed terminal or pipe cannot stop
the undo either: SIGPIPE is ignored there too. Only SIGKILL or a power loss
skips the trap. The new config is then in place, unconfirmed; if sudo does not
start, Break glass applies.

The installed copy of the script refuses to install. It can uninstall, show the
status and rescue.

### Uninstall

Uninstall takes the module out of `sudo_local` in the first of these ways that
leaves sudo starting:

1. `sudo_local` without the module, which brings back the `pam_tid.so` line.
   It is checked with the probe before it is written and with
   `sudo -n /usr/bin/true` after.
2. If that does not start sudo but sudo started with the module, nothing is
   changed and uninstall fails: removing the module would make things worse.
3. If sudo did not start before either, because the module stopped loading or
   another line in `sudo_local` did: no `sudo_local` at all. That is how macOS
   comes, with the password and no Touch ID. A missing `sudo_local` is not an
   error, since `/etc/pam.d/sudo` includes it on every Mac and only the
   template exists until someone creates it. The rest of the file, without the
   module, is kept as `sudo_local.pam_tidcmd-disabled.<date-time>` to be fixed
   and moved back.
4. If sudo does not start without `sudo_local` either, the cause is elsewhere
   (`/etc/pam.d/sudo`, sudoers). `sudo_local` is written back without the
   module, unless PAM could not load that either: then it stays aside, so that
   sudo starts once the other cause is fixed. Uninstall reports the failure.

Before the first of these is written, uninstall shows it and asks (see Asking
before a change). When sudo starts with the module and the probe already
refuses the first way, it fails without asking, since it changes nothing.

An interrupted uninstall puts the old `sudo_local` back only if sudo started
with it. When sudo did not start to begin with, whatever the run has written
is at least as good, so it stays.

The files are deleted only after `sudo_local` no longer names the module, and
not while any file in `/etc/pam.d` still has an active line of any kind naming
it, `sudo_local` included (uninstall removes only `auth` lines), since PAM
could then no longer load that file. `uninstall` needs no files from the build or from Homebrew, so
the installed copy can run it.

### Backups

When install or uninstall has changed `sudo_local` for good, the file it
replaced is kept as `/etc/pam.d/.sudo_local.pam_tidcmd-backup.<date-time>`,
with the original's owner and mode. A run that is undone, or that leaves the
file as it was, keeps none. The newest five are kept. Older ones are deleted,
but only regular files named exactly as the script names them, with
`<date-time>` as `YYYYmmdd-HHMMSS`, which sorts by time. A file renamed by
hand, or a link, is not the script's to delete.

The backup is the copy the run took before the change, linked under the new
name. The link is not made over an existing file, so of two runs in the same
second, the first one's backup is kept: it shows the file as it had been for
longer.

Where they are kept:

- In `/etc/pam.d`, next to `sudo_local`, so that they are found where it is,
  also from macOS Recovery, and survive an uninstall. The directory is
  root's, like `sudo_local`.
- As dot files. Uninstall keeps the module's files while any file in
  `/etc/pam.d` has an active line naming the module, and a backup taken while
  the module was installed has one, so every later uninstall would keep them.
  That scan skips dot files. OpenPAM opens a policy only by its service name,
  so it never reads a backup either.
- Not in `/Library/Security/pam_tidcmd`: uninstall removes that directory.

Putting one back needs a process that may write to `/etc/pam.d`: sudo, or the
Terminal of macOS Recovery, on the Data volume. A root shell from `su`, in a
terminal app that may administer the computer, should do as well
(**Unverified**). The administrator dialog that `rescue` uses cannot (see the
next section). A backup taken while the module was installed names it, so it
stops sudo from starting if put back once the module is gone.

### macOS protects `/etc/pam.d`

Root alone may not change `/etc/pam.d`. The platform sandbox policy puts it
under the privacy class `kTCCServiceSystemPolicySysAdminFiles` ("administer
your computer"), together with files such as `/etc/sudo.conf` and
`/etc/master.passwd` ([list as of macOS 15.1](https://bdash.net.nz/posts/tcc-and-the-platform-sandbox-policy/)).
A write there is allowed only when the process's responsible app holds that
permission, or Full Disk Access, which tccd checks first. Run through sudo in
a terminal, the responsible app is the terminal app: macOS asked once whether
T3 Code may administer the computer (00:10:59 in the log, allowed), and the
install's writes went through.

So install and uninstall first try to create a file in `/etc/pam.d`
(`check_pam_dir`) and stop, before changing anything, with an explanation if
that is refused. Otherwise the refusal would come from whichever write came
first.

### Break glass

When the module keeps sudo from starting, getting it out needs root without
sudo. `pam_tidcmd rescue`, run without sudo, gets root from Authorization
Services instead: it runs `do shell script … with administrator privileges`
through `osascript`, which asks for an administrator's password in a dialog.
StandardAdditions does that with the right `system.privilege.admin` and
authtrampoline; it does not call sudo, and authd does not use
`/etc/pam.d/sudo`, so a broken `sudo_local` does not affect it.

A process started that way cannot change `/etc/pam.d`, though. Its responsible
process is `/System/Library/Frameworks/Security.framework/authtrampoline`
itself, running as root in a background session, which holds neither
permission and cannot be asked. The first version of rescue ran `uninstall`
there, and the first write was refused (see Verification).

So rescue leaves `/etc/pam.d` alone and changes the file `sudo_local` names
instead. As root, it replaces `/Library/Security/pam_tidcmd/pam_tidcmd.so` with
Apple's `/usr/lib/pam/pam_tid.so.2`:

1. first with a symbolic link to it, which stays current through macOS updates;
2. if sudo does not start with that, with a copy. The copy is written to a new
   file and renamed into place, since macOS caches the code signature of a file
   and overwriting a module in place can make it unloadable.

Each is kept only if `sudo -n /usr/bin/true` as root then succeeds. If neither
helps, the module was not the cause, and it is put back as it was. The module
that stopped working is kept as `.pam_tidcmd.so.broken` for a later look.

That check runs sudo as root, which is not asked to authenticate, so it does
not see a module that loads but crashes or hangs in `pam_sm_authenticate`, one
of the ways to lose sudo listed under What can lock you out. When sudo starts,
rescue changes nothing unless it is run as `rescue --force`. Then it replaces
the module all the same, keeps the result only if sudo still starts, and
leaves a module that is already Apple's as it is.

The line in `sudo_local` keeps its control flag, which came from the
`pam_tid.so` line it replaced, so sudo then behaves as before the install:
Apple's Touch ID, without the command. Apple's module imports no option
parsing, so a `timeout=` on the line does no harm. Afterwards, with sudo
working again, `sudo pam_tidcmd uninstall` takes the line out and removes the
files, or `sudo pam_tidcmd install` puts a working build in. Both handle the
link: install keeps it as a backup with `cp -P`, because `ln` would follow it
to the system volume and fail.

`/Library/Security` is not in the `SysAdminFiles` list as of macOS 15.1, and
on macOS 27.2.1 the rescue could write there from the dialog (see
Verification).

Afterwards, the user's side of rescue checks whether PAM can load sudo's
config, whatever the root side reported.

The dialog needs a GUI session. Without one, as over ssh, the README lists
`dsenableroot` and `su` (**Unverified**), where `rescue` then runs as root
directly, and macOS Recovery, where the Data volume's
`/private/etc/pam.d/sudo_local` can be moved aside.

Rejected for now: a LaunchDaemon that runs the checks at boot and replaces the
module when sudo does not start. It would repair the likeliest breakage, a
macOS update, without anyone acting. But it is a root process that runs at
every boot, a background item macOS reports to the user, and one more thing to
install and remove correctly.

## Testing

`make test` covers what can run outside sudo: prompt formatting, escaping,
look-alike letters, truncation, the PATH hint, and the Touch ID availability
check. The PATH tests give every environment and sudoers file themselves, and
start the test program again with a name given twice to check how the
environment is read back. The availability check was also
confirmed to answer per user: usable for the logged-in user, not usable for root
or a nonexistent uid.

`make test` also checks how the `timeout=` option is read, including the
values that fall back to the default, and that an exception thrown inside
`pam_sm_authenticate` (the test makes the private Touch ID check throw)
returns `PAM_AUTHINFO_UNAVAIL` instead of ending the process.

`make dialog-check` checks that the prompt is drawn and that the dialog closes
when the timeout runs out. For the prompt, it raises real dialogs for about two
seconds each and closes them by killing the process that asked (SIGKILL, since
sudo ignores the others). Ctrl-C stops it the same way. It cannot read the
dialog's text without Screen Recording or Accessibility permission, but it can
read the dialog's size, so it compares the height for a short and a long text,
twice:

- a right of its own, with no prompt and with a six-line prompt. An undefined
  right falls back to Apple's `default` rule, so no root and no
  `security authorizationdb write` are needed. If such a dialog is approved,
  that rule leaves an admin credential that the whole session shares for five
  minutes. The program destroys it: it lets a child whose dialog was answered
  finish and free its rights, then asks for the right again without UI and
  destroys whatever that yields.
- `sudo -k /usr/bin/true` through the installed module, with and without 40
  extra arguments. Only the module's prompt depends on the command line.

For the timeout, it leaves the dialog alone and checks that it closes by itself
after the timeout and that the process that asked then ends by itself:

- the same right of its own, asked for through the module's own
  `tidcmd_authorize()` with `timeout=3`. The request must end with
  `errAuthorizationDenied`, as a dismissed one does.
- `sudo -k /usr/bin/true` with the timeout set in `sudo_local`. sudo has no
  terminal there, so after the dialog closes it fails to ask for a password and
  exits. This is skipped when the timeout is 0 or over 60 seconds.

Approving and cancelling need a person and were tested by hand (see
Verification).

`make test` also runs the probe on the built module, and `install_test.sh`,
which needs no root and shows no dialog. It sources the script and runs install
and uninstall against a scratch directory, with fakes for the paths, the root
and ownership steps, the probe, sudo and the Touch ID check. The fake probe
follows includes, cuts lines at `#` as OpenPAM does, and fails on a module
that is missing or contains the word `BROKEN`; the fake sudo starts when the fake probe can load sudo's policy, as
the real one does. It covers each rollback and each uninstall fallback above, a
reinstall that fails and keeps the previous module, an install interrupted
during the Touch ID check, and the lock. Breaking the rollback, a fallback or
the check before uninstalling makes it fail. A file stands in for the
terminal and holds the answer: it tests yes, no, no answer, `--yes`, no
terminal, a `sudo_local` changed while the question is open and a run
interrupted there. For backups, it checks one per change that stays, none for
one undone, the newest five, files it did not name left alone, and that
uninstall still removes the module while backups name it.

`install_test.sh` also runs the real Touch ID check with a fake command in
place of sudo: approved, cancelled, ended by a signal, and unanswered, where it
must give up after the wait and kill every process the check started. And it
runs `rescue` with a fake `osascript`, and as root: the link, the copy when
the fake probe refuses links, nothing to do, `--force` when sudo starts, a
module that is not the cause, a missing module, and install and uninstall
afterwards. A read-only `/etc/pam.d`
stands in for the privacy protection. Before any test, the harness checks that
the stubs replace every system path the script defines, and it refuses to run
as root. The scripts under test run from a file,
not through `bash -c`: bash 3.2 handles some signals differently there.
Interrupted runs are started in a process group of their own, because a
background job of a non-interactive shell starts with SIGINT and SIGQUIT
ignored, and those cannot be trapped. Each signal handler is tested this way,
as are two signals at once.

`make test` starts with clang's static analyzer (`make analyze`) on every
source file: the module, the probe, which the installer runs as root, and the
two test programs. `-analyzer-werror` makes any finding fail. Then it builds
the prompt tests with AddressSanitizer and UndefinedBehaviorSanitizer and runs
them (`make sanitize`). Any finding ends the run and fails it, undefined
behaviour too (`-fno-sanitize-recover`). That build uses the module's flags at
`-O1` with frame pointers, as AddressSanitizer's documentation advises. Traces
go through `/usr/bin/atos`. Both targets are modelled on the fork's `justfile`
(MIT License, © 2026 Lauri Gates). A null pointer dereference, a read past the
end of a heap block and a signed overflow, each put into a copy of
`tidcmd_build_prompt()`, made them fail (2026-11-14).

`render_formula_test.sh`, also run by `make test`, checks the release's
`render_formula.sh`: it sets `url` and `sha256` and changes no other line, and
it refuses a version that is not `X.Y.Z`, a checksum that is not 64 lowercase
hex digits, a missing argument, and a formula with no or two `url` or `sha256`
lines of the form it replaces. Without the script's version check or its
check for one `url` line, or with `sha256` left as it was, the test fails.

`make lint` runs shellcheck on the scripts.

CI (`.github/workflows/ci.yml`) runs `make lint` and `make test` on GitHub's
`macos-latest` runner for every push to `main` and every pull request. It
never runs `make dialog-check`, which raises dialogs and runs sudo. On a
runner, `tidcmd_test` is expected to skip the exception test, since the job
has no GUI session, and to report Touch ID as not usable; neither fails it.
Should a runner have a GUI session owned by its user, the exception test runs
and still shows no dialog. `install_test.sh` runs as the runner's user, which
is not root. **Unverified:** CI has not run; it needs the published
repository.

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
  lines each start a new line and are readable. On 2026-11-14, with the build
  of `d3843de`, which gives each label a line of its own, and started from
  another app, the two sudo dialogs measured 417 and 625 points.
- **Approving** with Touch ID: sudo exits 0.
- **Cancelling:** sudo prints `Password:` on the terminal. Ctrl-C at that prompt
  ends sudo with "a password is required".
- **Timeout, on a right of its own.** `dialog_check` asked for its own right
  through `tidcmd_authorize()` with `timeout=3`: the dialog closed by itself
  after 3.2 seconds and the request returned `errAuthorizationDenied`. The
  module logged "no answer after 3 seconds; dismissing the dialog". With
  `timeout=0` instead, the dialog was still open after 13 seconds and the check
  failed, as it should. A first experiment calling `AuthorizationDismiss()`
  directly saw the request end 13 ms after the call.
- **A lost dismissal is repeated.** A test program defined its own
  `AuthorizationDismiss()`, which the module's lookup finds first, dropping the
  first call and passing later ones on. With `timeout=2`, the module dismissed
  at 2.0 s (dropped) and again at 3.0 s, the dialog closed, the request
  returned `errAuthorizationDenied`, and the module logged the error once.
- **Timeout of sudo's own dialog** (2026-11-14). The installed module was the
  build of commit `d3843de` (its SHA-256 matched a new build of that commit),
  with no `timeout=` on its line, so 30 seconds. `make dialog-check` started
  `sudo -k /usr/bin/true` and left its Touch ID dialog for
  `com.apple.security.sudo` alone. The dialog closed by itself 30.1 s after
  sudo started, and sudo, with no terminal to ask for a password on, exited
  with status 1. The log has a line from the module in sudo at 03:12:23.328,
  authd's "Caller dismissed" 11 ms later, and then sudo's other PAM modules
  (smart card, OpenDirectory) failing to get a password, as after Cancel.
  `log show` could not render the module's text inside sudo
  (`<compose failure [UUID]>`); the timing is that of "no answer after 30
  seconds; dismissing the dialog". In the same run, the right of its own with
  `timeout=3` closed after 3.1 s.
- **Closing the dialog from the terminal.** sudo catches SIGINT and SIGTERM while
  it authenticates (`init_signals()` in sudo's `src/signal.c`), so neither Ctrl-C
  nor `kill` ends it while the dialog is open. With SIGTERM the dialog was seen to
  stay open until it was approved. SIGKILL ends sudo, and authd then closes the
  dialog ("Caller dismissed" in its log). This comes from sudo, so it applies to
  Apple's `pam_tid.so` as well.

### Installation

Checked on 2026-11-13, without root.

- **A module that cannot be loaded stops `pam_start()`.**
  `/etc/pam.d/sudo_local.bak-20261113-193757`, left by an earlier experiment,
  names a module that no longer exists. `pam_tidcmd_probe policy` fails on it
  with "system error", and succeeds on the live `sudo_local` and on
  `/etc/pam.d/sudo`, which loads the installed module through the include.
  Policies given by path, in `/etc/pam.d` or elsewhere, were refused.
- **The probe loads the slice sudo loads.** Built for arm64e, arm64 and x86_64,
  it runs as arm64e on Apple silicon, and the module it loads reports CPU
  subtype `0x80000002` (arm64e).
- **Homebrew.** Homebrew 7.0.13 built and installed the formula from a local
  tap with a tarball of the working tree: a universal module, `brew test`,
  `brew audit --strict` and `brew style` passed. `brew uninstall` left
  `sudo_local` and `/Library/Security/pam_tidcmd` as they were.
- **The rescue's AppleScript** passes the script's path, quoted, and returns
  its output and errors, checked without administrator privileges on `status`.
- **Install as root works,** after macOS asked whether T3 Code may administer
  the computer (2026-11-14).
- **The first rescue failed.** With the module replaced by a file that cannot
  be loaded, `rescue` got root from the dialog and ran `uninstall`, whose first
  write was refused:

  ```
  sandboxd rejected approval request from mktemp for kTCCServiceSystemPolicySysAdminFiles (/private/etc/pam.d/.sudo_local.saved.ziyAM7): denied
  ```

  tccd named `com.apple.authtrampoline` (auid 0, background session) as the
  responsible process, found no grant and could not ask. Nothing was changed.
  This led to the module swap described under Break glass.
- **Apple's module loads from elsewhere.** The probe loads both a copy of
  `/usr/lib/pam/pam_tid.so.2` and a symbolic link to it. The copy keeps
  Apple's signature ("macOS Software Signing", platform identifier 27).
- **The rescue works** (2026-11-14). With the installed module missing, run
  as the user, it got root from the administrator dialog, found that
  `sudo -n /usr/bin/true` as root failed, replaced the module with a symbolic
  link to `/usr/lib/pam/pam_tid.so.2`, and found that sudo then started. So a
  process started from the dialog may write `/Library/Security`, PAM accepts a
  module path that is a link, and the real sudo's check fails while the
  module cannot be loaded and passes once it can. `sudo_local` was not
  touched. `status` then reported the replaced module. With the module
  replaced by a seven-byte text file instead, the rescue did the same and
  kept that file as `.pam_tidcmd.so.broken`.
- **Uninstall after a rescue** put back the original `pam_tid.so` line and
  removed the files, link included (2026-11-14).
- **CI and the release, without a remote** (2026-11-14). actionlint 1.7.12,
  with shellcheck on the `run:` steps, passes both workflows. `make lint` and
  `make test` pass on a copy holding only the files a commit would. The
  pinned SHAs are those of `actions/checkout` v7.0.1 and
  `actions/upload-artifact` v7.0.2, and the tap's `publish.yml` at the pinned
  commit takes the inputs the release passes. `brew style` passes the formula
  and a copy rendered by `render_formula.sh`. Neither workflow has run.
- **`rescue --force`** (2026-11-14). With the module installed and working,
  run as the user, it got root from the administrator dialog, found that sudo
  started as root, replaced the module with a link to
  `/usr/lib/pam/pam_tid.so.2` all the same, kept the old module as
  `.pam_tidcmd.so.broken`, and found that sudo started. `status` then reported
  the replaced module, and `sudo ./pam_tidcmd.sh install` put the current
  build back, its Touch ID check approved. Not tested: a module that actually
  crashes or hangs while it authenticates.
- **The lock file** `/var/run/pam_tidcmd.lock`, made 0644 by an earlier
  version, was 0600 after a run of this one (2026-11-14).
- **The install's Touch ID check.** Cancelling the dialog failed the check
  (sudo said "no password was provided"), the install was undone, `sudo_local`
  was as before and `status` reported no module. Approving it kept the module.

## Known limits

- **Credential caching.** sudo caches a successful authentication for five
  minutes per terminal. Commands run in that window show no dialog. Setting
  `Defaults timestamp_timeout=0` in sudoers makes every command prompt.
- **Scripts.** `sudo ./script.sh` shows the script path, not its contents.
- **The PATH hint can be raced.** sudo looks up the command before the module
  does, and runs what it found then. Someone who can change a directory
  earlier in `PATH` can plant a file there, remove it before the module looks,
  so that the hint names a later match without a warning, and put it back
  before sudo runs it. The hint does not check those directories (see The PATH
  hint).
- **Look-alikes within one script.** A word entirely in Cyrillic, such as `сс`
  for `cc`, is shown as it is. So are Latin letters that resemble others
  (dotless `ı`, `ɑ`), and punctuation and symbols such as the division slash
  `∕`.
- **No way out from the terminal.** While the dialog is open, Ctrl-C in the
  terminal does nothing. The dialog has to be answered or left to time out, or
  sudo killed with SIGKILL from elsewhere. This is sudo's behaviour (see
  Verification).
- **The timeout does not wait for typing.** It counts from the request, so it
  also closes the dialog while a password is being typed into it.
- **Private API.** The Touch ID availability check may stop working after a
  macOS update, in which case sudo falls back to the password prompt. So may
  `AuthorizationDismiss()`, in which case the dialog has no timeout.
- **Scope.** The module is for sudo only.
- **Break glass needs a GUI session** for `rescue`. Over ssh, it takes
  `dsenableroot` and `su`, or macOS Recovery.
- **Homebrew upgrades do not reach sudo.** sudo keeps the installed copy until
  `sudo pam_tidcmd install` is run again.
- **Install and uninstall need permission to administer the computer** for the
  terminal app they run in, which macOS asks for the first time. `rescue` does
  without it, by not changing `/etc/pam.d`.

## License

pam_tidcmd is under the MIT License (LICENSE), chosen 2026-11-14.

Apple's `pam_tid.c` is under the Apple Public Source License, which binds
Apple's code and any file that contains part of it. `pam_tidcmd.m` follows the
same sequence of calls, which Apple's API dictates, but is written
independently. One statement was close to Apple's: the user lookup, with the
same condition, variable names and message. It was rewritten on 2026-11-14 as
two separate checks with messages of their own, so that no part of Apple's
code is left in the file.

Code ported from the fork macos-sudo-touchid-context is under the MIT License,
© 2026 Lauri Gates. Each piece is marked in the source, and LICENSE carries
that copyright line.
