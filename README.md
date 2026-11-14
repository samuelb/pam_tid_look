# pam_tidcmd

Touch ID for `sudo` on macOS, like Apple's `pam_tid.so`, with one difference:
the dialog shows what you are approving.

```
Command:
sudo brew services restart nginx

Found in PATH:
/opt/homebrew/bin/brew
Can be changed without root.

Directory:
~/code/myproject

Requested by:
zsh ← Terminal
```

Authentication is left to Apple, exactly as `pam_tid.so` does it. The module
only adds the text. It needs macOS 14 (Sonoma) or later. Why it is built this
way is in [DESIGN.md](DESIGN.md).

## Install

With Homebrew:

```
brew install samuelb/tap/pam_tidcmd
sudo "$(brew --prefix)/bin/pam_tidcmd" install
```

Homebrew may first ask you to trust the tap (`brew trust`). `brew install` only
puts the files in Homebrew's prefix. The second command is what changes sudo.

From the source:

```
make
sudo ./pam_tidcmd.sh install
```

The first time, macOS asks whether your terminal app may administer the
computer: allow it, since only then may root change `/etc/pam.d`. `install`
copies the module to `/Library/Security/pam_tidcmd`, which only root can
change, and puts it in `/etc/pam.d/sudo_local` in place of the `pam_tid.so`
line. Before changing anything it checks that sudo starts and that PAM can load
the module and the new config. Then it shows the change to `sudo_local` as a
diff, the module's SHA-256 hash and whether it differs from the one installed,
and asks you to confirm. Afterwards it checks that sudo still starts and
opens a Touch ID dialog for `sudo -S -k /usr/bin/true`, which you approve. If a
check fails, you cancel the dialog or leave it for two minutes, or the run is
interrupted, everything is put back as it was.

The question is asked on the terminal. `--yes` answers it in advance, for
scripts; without a terminal and without `--yes`, install changes nothing. The
`sudo_local` it replaces is kept in `/etc/pam.d` (see Backups under Break
glass).

`--timeout SECONDS` sets how long the dialog waits for a fingerprint before it
closes and sudo asks for the password: 0 to 3600, 0 for no limit, 30 by
default. A reinstall keeps the current value.

To see what is installed, without sudo:

```
pam_tidcmd status
```

## Update

After `brew upgrade pam_tidcmd`, or `git pull` and `make`, run install again.
Until then sudo keeps the module it has.

## Uninstall

```
sudo "$(brew --prefix)/bin/pam_tidcmd" uninstall
brew uninstall pam_tidcmd
```

or `sudo ./pam_tidcmd.sh uninstall` from the source. If Homebrew's copy is
already gone, `sudo /Library/Security/pam_tidcmd/pam_tidcmd uninstall` does the
same.

`uninstall` shows the change to `sudo_local` and asks the same way, `--yes`
included. Then it puts the `pam_tid.so` line back and checks that sudo starts.
If it does not, and did not start before either, it moves `sudo_local` aside,
so that sudo works with the password as on a new Mac, and says where the rest
of the file went. The `sudo_local` it replaces is kept as a backup.

## Break glass

If sudo stops working because of this module, for example after a macOS
update, sudo cannot be used to remove it. You would see
`sudo: unable to initialize PAM: system error`, or sudo crashing or hanging.
These ways back do not use sudo. Try them in this order.

**1. `rescue`.** In Terminal, without sudo:

```
/Library/Security/pam_tidcmd/pam_tidcmd rescue
```

`pam_tidcmd rescue` from Homebrew or `./pam_tidcmd.sh rescue` from the source
does the same. It asks for an administrator password in a macOS dialog, which
does not go through sudo, and replaces the module with Apple's own
`pam_tid.so`. sudo then works with Apple's Touch ID, without the command in
the dialog. Then remove pam_tidcmd, or install a working build:

```
sudo pam_tidcmd uninstall
```

The rescue does not edit `/etc/pam.d/sudo_local`: macOS does not let a process
started from that dialog change `/etc/pam.d`, even as root.

If sudo starts but crashes or hangs while it authenticates you, `rescue` finds
nothing wrong, because it checks sudo as root and root is not asked to
authenticate. Run `rescue --force` then: it replaces the module even though
sudo starts.

**2. One line of AppleScript**, if pam_tidcmd's files are gone too. It puts a
copy of Apple's module where `sudo_local` expects this one:

```
osascript -e 'do shell script "mkdir -p /Library/Security/pam_tidcmd && cp /usr/lib/pam/pam_tid.so.2 /Library/Security/pam_tidcmd/.new && mv -f /Library/Security/pam_tidcmd/.new /Library/Security/pam_tidcmd/pam_tidcmd.so" with administrator privileges'
```

Then, with sudo working, take the line out and remove the files:

```
sudo sed -i '' -e '/pam_tidcmd[.]so/d' -e 's/^#pam_tidcmd# //' /etc/pam.d/sudo_local
sudo rm -r /Library/Security/pam_tidcmd
```

**3. Without a GUI session**, over ssh for example, there is no dialog. Give
root a password with `dsenableroot`, which asks for yours and does not use
sudo, then:

```
su -
/Library/Security/pam_tidcmd/pam_tidcmd rescue
exit
dsenableroot -d
```

The last line turns root off again. This way has not been tested.

**4. macOS Recovery**, if nothing else works. On Apple silicon, shut down, hold
the power button until the options appear, and choose Options. On Intel, hold
Command-R while starting up. If FileVault is on, open Disk Utility, select the
Data volume and click Mount. Then choose Utilities > Terminal and run:

```
mv "/Volumes/Macintosh HD - Data/private/etc/pam.d/sudo_local" "/Volumes/Macintosh HD - Data/private/etc/pam.d/sudo_local.disabled"
```

using the Data volume's name as `ls /Volumes` shows it. Restart. sudo then
works with the password only. To get Touch ID back, write the file back
without this module's line:

```
sudo sh -c 'sed -e "/pam_tidcmd[.]so/d" -e "s/^#pam_tidcmd# //" /etc/pam.d/sudo_local.disabled > /etc/pam.d/sudo_local'
sudo rm -r /Library/Security/pam_tidcmd
```

**Backups.** Install and uninstall keep the `sudo_local` they replace, the
newest five, as hidden files next to it, named by date and time:

```
ls -l /etc/pam.d/.sudo_local.pam_tidcmd-backup.*
```

A backup taken while pam_tidcmd was installed names its module, and put back
once the module is gone, it stops sudo from starting. `grep -L pam_tidcmd.so`
on the backups lists those that do not name it.

`rescue` cannot put a backup back: macOS does not let a process started from
its dialog change `/etc/pam.d`. With sudo working, for example after a rescue:

```
sudo cp /etc/pam.d/.sudo_local.pam_tidcmd-backup.20261114-101500 /etc/pam.d/sudo_local
```

with the name `ls` shows. Without sudo, macOS Recovery can, as in way 4, with
the Data volume's path in place of `/etc`:

```
cp "/Volumes/Macintosh HD - Data/private/etc/pam.d/.sudo_local.pam_tidcmd-backup.20261114-101500" "/Volumes/Macintosh HD - Data/private/etc/pam.d/sudo_local"
```

A root shell from `su`, as in way 3, may be able to as well; that has not been
tested.

## Development

`make test` needs no root and shows no dialog. It runs clang's static analyzer
on every source file, runs the prompt tests twice, built with AddressSanitizer
and UndefinedBehaviorSanitizer and built as usual, loads the built module, runs
`install_test.sh`, which exercises install, uninstall and each rollback against
a scratch directory, and runs `render_formula_test.sh`. `make analyze` and
`make sanitize` run the first two on their own. `make lint` runs shellcheck.
`make dialog-check` raises real dialogs and runs sudo; see `dialog_check.m`.

CI runs `make lint` and `make test` on a macOS runner for every push to `main`
and every pull request (`.github/workflows/ci.yml`). It never runs
`make dialog-check`.

`Formula/pam_tidcmd.rb` is the Homebrew formula. Its `url` and `sha256` stand
in for a release's. To release, push a tag:

```
git tag v0.1.0
git push origin v0.1.0
```

`.github/workflows/release.yml` then runs the tests again, sets `url` and
`sha256` to the tag's source archive with `render_formula.sh`, installs and
tests that formula from a local tap, creates the GitHub release, and pushes the
formula to [samuelb/homebrew-tap](https://github.com/samuelb/homebrew-tap).
This needs the repository secret `HOMEBREW_TAP_TOKEN`, a token that may push to
the tap.
