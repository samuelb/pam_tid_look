# Development

How the source is laid out, how to build and test it, and how a release is
made. Why the module is built the way it is is in [DESIGN.md](DESIGN.md).

## Layout

| Path        | Holds                                              |
| ----------- | -------------------------------------------------- |
| `src/`      | the module, the installer and the probe            |
| `test/`     | the tests                                          |
| `scripts/`  | the script that renders the formula for a release  |
| `Formula/`  | the Homebrew formula                               |
| `build/`    | what `make` builds                                 |

`make` builds `pam_tid_look`, `pam_tid_look.so` and `pam_tid_look_probe` into
`build/`, side by side, the same way Homebrew's copy and the installed copy
lay them out.

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
