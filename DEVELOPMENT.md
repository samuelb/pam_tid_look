# Development

How the source is laid out, how to build, install and test it, and how a
release is made. Why the module is built the way it is is in
[DESIGN.md](DESIGN.md).

## Layout

| Path        | Holds                                              |
| ----------- | -------------------------------------------------- |
| `src/`      | the module, the installer and the probe            |
| `test/`     | the tests                                          |
| `scripts/`  | the scripts that render the formula and take the README's screenshot |
| `Formula/`  | the Homebrew formula                               |
| `build/`    | what `make` builds                                 |

## Build and install from the source

### Build

```
make
```

`make` builds `pam_tid_look`, `pam_tid_look.so` and `pam_tid_look_probe` into
`build/`, side by side, the same way Homebrew's copy and the installed copy
lay them out.

### Install

```
sudo build/pam_tid_look install
```

This is the same install as Homebrew's: it copies the build to
`/Library/Security/pam_tid_look` and changes `sudo_local`, with the same
checks, confirmation and options. The README describes them under
[What install does](README.md#what-install-does) and
[Options](README.md#options). The other commands, `status` and `rescue`, work
from `build/` too.

The first time, macOS asks whether your terminal app may administer the
computer. Allow it: only then may root change `/etc/pam.d`.

### Update

```
git pull
make
sudo build/pam_tid_look install
```

Until install runs again, sudo keeps the module it has.

### Uninstall

```
sudo build/pam_tid_look uninstall
```

If `build/` is already gone, the installed copy does the same:

```
sudo /Library/Security/pam_tid_look/pam_tid_look uninstall
```

What uninstall does is described under [Uninstall](README.md#uninstall) in
the README.

## Tests

| Command             | What it does                                         |
| ------------------- | ---------------------------------------------------- |
| `make test`         | everything below except `lint` and `dialog-check`    |
| `make analyze`      | clang's static analyzer on every source file         |
| `make sanitize`     | the prompt tests, built with AddressSanitizer and UndefinedBehaviorSanitizer |
| `make lint`         | shellcheck                                           |
| `make dialog-check` | raises real dialogs and runs sudo; see `test/dialog_check.m` |

`make test` needs no root and shows no dialog. It runs the analyzer, runs the
prompt tests twice, once with the sanitizers and once built as usual, loads
the built module, and runs two shell tests:

- `test/install_test.sh` exercises install, uninstall and each rollback
  against a scratch directory.
- `test/render_formula_test.sh` tests the formula script.

## Screenshot

`docs/sudo-dialog.png`, the dialog in the README, is taken by
`scripts/screenshot.sh`. With the module installed, run it from a terminal:

```
scripts/screenshot.sh                         # what `brew install --cask zoom` asks sudo, here
scripts/screenshot.sh -C ~ -- nmap -sS -p 22 localhost   # another command and directory
scripts/screenshot.sh -o /tmp/dark.png        # somewhere else
```

By default it shows the dialog that `brew install --cask zoom` raises:
Homebrew runs the cask's package with `sudo -u root -E LOGNAME=… USER=…
USERNAME=… -- /usr/sbin/installer -pkg … -target /`. The package is not there,
so approving it by mistake installs nothing; the script checks that first.

It runs `sudo -K`, then sudo with the command in the directory, waits for
the dialog, saves that window, and withdraws the dialog by killing sudo. Do
not answer the dialog: approving it runs the command as root. At the end it
prints the dialog's width in points, for the `width` of the README's `<img>`.

- The terminal app needs the Screen Recording permission (System Settings >
  Privacy & Security). Without it the script stops before it runs sudo.
- The dialog's "Requested by" names the processes that led to sudo, starting
  with the script's bash, so run it from the terminal directly, not from
  `make` or another script.
- The dialog follows the system's appearance. Switch between light and dark
  to take both.
- `sudo -K` also ends the sudo session of other terminals.

## CI

CI runs `make lint` and `make test` on a macOS runner for every push to `main`
and every pull request (`.github/workflows/ci.yml`). It never runs
`make dialog-check`.

## Release

`Formula/pam_tid_look.rb` is the Homebrew formula. Its `url` and `sha256` are
placeholders for a release's.

To release, run the release workflow on `main`:

```
gh workflow run release.yml                  # the next version, from the commits
gh workflow run release.yml -f bump=minor    # or force patch, minor or major
gh workflow run release.yml -f dry_run=true  # show the version and notes, publish nothing
```

The workflow computes the next version from the
[Conventional Commits](https://www.conventionalcommits.org) since the last tag
with [git-cliff](https://git-cliff.org) (`cliff.toml`), and tags the commit
with it. No file holds the version, so nothing is committed.

Pushing a tag also releases that commit, as the tag's version, without
bumping it:

```
git tag v0.1.0
git push origin v0.1.0
```

Either way, `.github/workflows/release.yml` then:

1. runs the tests again,
2. renders the formula with `scripts/render_formula.sh`,
3. installs and tests it from a local tap,
4. creates the tag, if it was not pushed,
5. creates the GitHub release, with notes from git-cliff,
6. pushes the formula, set to the tag's source archive, to
   [samuelb/homebrew-tap](https://github.com/samuelb/homebrew-tap).

A dry run stops before the tag.

The workflow needs the repository secret `HOMEBREW_TAP_TOKEN`, a token that
may push to the tap.
