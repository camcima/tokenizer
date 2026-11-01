# CLI, Make targets and CI

This page is for developers and operators. It describes the `vault` binary's flags and exit behaviour, every `Makefile` target, the pinned tools, the git hooks in `lefthook.yml`, the scripts in `scripts/`, and the GitHub Actions workflows in `.github/workflows/`.

## The `vault` binary

### Usage

| Command | Mode |
|---|---|
| `vault` | Serve: boot and run both listeners. Configuration comes from the environment ([Configuration](configuration.md)). |
| `vault -rotate-dek` | Generate a 32-byte DEK, wrap it with Cloud KMS, check that KMS unwraps it to the same bytes, store it with `vault.add_dek`, print the new version on standard output, exit. Needs only `VAULT_ENV`, `VAULT_DB_URL` and `VAULT_KMS_KEY`, and runs as the `vault_rotator` database role, the only role `schema.sql` grants `vault.add_dek`. |

`-rotate-dek` is the only flag (`main.go`). Flags are parsed with Go's `flag` package, so its defaults apply: `-h` prints usage, and an unknown flag prints usage and exits 2.

The container image (`Dockerfile`) is `scratch` with the binary at `/vault` as `ENTRYPOINT`, the CA bundle at `/etc/ssl/certs/ca-certificates.crt`, and user `65532:65532`.

### Exit behaviour

| Situation | Output | Exit code |
|---|---|---|
| `-rotate-dek` succeeded | the new version on standard output | 0 |
| Shutdown after `SIGTERM` or `SIGINT` | none | 0 |
| Any boot or `-rotate-dek` failure | `boot failed: <reason>` on standard error | 1 |
| No DEK in the database | `no DEKs found; run vault -rotate-dek first` | 1 |
| A listener stopped serving after `ready` | `listener failed listener=<public\|internal>` | 1 |
| Unknown flag | usage from the `flag` package | 2 |

All log lines go to standard error with an RFC 3339 UTC timestamp (see [Logging](logging.md)).

### Signals and shutdown

The vault handles `SIGTERM` and `SIGINT` (`main`, `main.go`):

1. Cancel the background loops: the CVV sweep and the DEK refresh. A refresh already running is not waited for.
2. Call `Shutdown` on both listeners concurrently, within one 20-second budget (`shutdownTimeout`): stop accepting connections and wait for in-flight requests.
3. Close the database pool.
4. Exit 0, whether or not the drain finished within the budget.

## Make targets

Run from the repository root. Go is taken from the module's toolchain (`toolchain go1.27.3` in `go.mod`).

| Target | Runs | Use it |
|---|---|---|
| `build` | `CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w -buildid=" -o vault .` | Build the static `./vault` binary. |
| `test` | `go test -race -count=1 ./...` | Unit tests with the race detector, including the fuzz seeds and saved fuzz inputs. Integration tests skip unless `VAULT_TEST_DB_URL` is set. |
| `lint` | `tools`, then `gofmt -l .` (fails if it cannot run or lists a file), `go vet ./...`, `staticcheck ./...` | Formatting and static analysis. |
| `vuln` | `tools`, then `govulncheck ./...` | Known vulnerabilities in reachable code. |
| `deps-check` | `go mod tidy -diff`; the direct requirements must be exactly `github.com/jackc/pgx/v5`; the number of modules in `go.sum` must not exceed `deps-baseline.txt` (12) | Dependency allowlist. |
| `vendor-check` | `go mod vendor` into a temporary directory, then `diff -r` against `vendor/` | `vendor/` is exactly what `go mod vendor` produces. The working tree is not modified. |
| `docs-check` | `docs-links` first; then greps the three READMEs for retired claims (case-insensitive) and compares their counts of lines starting with `#`, `\|` and `` ```mermaid `` | Links in the documentation resolve, and the English, Spanish and Portuguese READMEs stay structurally identical. |
| `docs-links` | `scripts/check-doc-links.sh` (see [Scripts](#scriptscheck-doc-linkssh)) | Every link in the READMEs and `docs/**/*.md` resolves to an existing, non-ignored file and, with a `#fragment`, to a heading of the target file. |
| `mermaid-check` | Lists the documentation files with `scripts/check-doc-links.sh --list`, keeps those with a `` ```mermaid `` fence, and renders each with `@mermaid-js/mermaid-cli@12.0.0` (run through `npx --yes --package`, installed on first use). Chrome is started with a puppeteer config holding `--no-sandbox`, because Chrome's sandbox needs unprivileged user namespaces, which some hosts refuse; the browser renders only this repository's diagrams. A system Chrome is used when `PUPPETEER_EXECUTABLE_PATH` is set. Output goes to a temporary directory, never the working tree. | Every Mermaid diagram in the documentation renders. Needs Node and `npx`. |
| `comment-check` | `scripts/check-comments.sh` over every tracked `*.go` file outside `vendor/` | No Go file contains the markers `SPEC-DECISION`, `§` or `design doc`. |
| `gitleaks` | `tools`, then `gitleaks git --redact --no-banner --verbose --config .gitleaks.toml .` | Secret scan of the full git history, with the allowlist in `.gitleaks.toml`. |
| `ci` | `lint vuln deps-check vendor-check docs-check mermaid-check comment-check gitleaks test build` | The checks every change must pass. Because of `mermaid-check`, it needs Node and `npx`; the first run downloads the pinned Mermaid CLI. |
| `itest` | Starts `postgres:18` as container `pan-vault-pg` with trust auth on `127.0.0.1:$(PG_PORT)`, waits up to 60 s for `psql`, creates role `vault_owner` and database `vault`, applies `schema.sql` as `vault_owner`, then `go test -race -count=1 -run Integration ./...` with `VAULT_TEST_DB_URL` set. The container is always removed. | Database and end-to-end tests. Needs Docker and `psql`. |
| `stripe-mock-test` | Starts `stripe/stripe-mock` (v0.206.0, pinned by digest) as container `pan-vault-stripe-mock` on `127.0.0.1:$(STRIPE_MOCK_PORT)`, waits up to 60 s with `curl`, then `go test -race -count=1 -run StripeMock -v ./...` with `VAULT_TEST_STRIPE_MOCK_URL` set. The container is always removed. | Checks the embedded catalog's Stripe requests against stripe-mock. Needs Docker and `curl`. |
| `image` | `docker buildx build --provenance=false --build-arg SOURCE_DATE_EPOCH=0 --output type=docker,name=pan-vault:local,rewrite-timestamp=true,unpack=false .`, then prints the image ID | Build the image `pan-vault:local` and print its digest. |
| `image-repro` | Builds the image twice with `--no-cache` and compares the IDs; prints `image-repro: ok <id>` or fails | Check that the build is reproducible. |
| `ci-all` | `ci itest stripe-mock-test image-repro` | Everything CI runs except fuzzing and the commit checks. |
| `fuzz` | Every `Fuzz*` target in the package, one after another, 20 s each | Short fuzz run (pull requests). |
| `fuzz-long` | Every `Fuzz*` target for `$(FUZZTIME)` each | Long fuzz run (nightly). |
| `tools` | Installs each pinned tool into `.tools/bin` with `GOTOOLCHAIN=go1.27.3`, replacing any binary there built from another version or toolchain | Called by `lint`, `vuln`, `gitleaks` and `hooks`; run it directly before using the hooks. |
| `hooks` | `tools`, then `lefthook install` | Install the git hooks into this clone (opt-in). |
| `commit-check` | `scripts/check-commit-msg.sh --message` on every commit in `$(COMMIT_RANGE)` | Check commit messages before pushing; CI runs it on every pull request and push. |

### Variables

| Variable | Default | Used by |
|---|---|---|
| `PG_PORT` | `55432` | `itest`: loopback port for PostgreSQL |
| `STRIPE_MOCK_PORT` | `12111` | `stripe-mock-test`: loopback port for stripe-mock |
| `FUZZTIME` | `10m` | `fuzz-long`: time per target |
| `COMMIT_RANGE` | `origin/main..HEAD` | `commit-check` |

Example: `make itest PG_PORT=55433`.

### Fuzz targets

`make fuzz` and `make fuzz-long` discover targets with `go test -list '^Fuzz' .`. Today they are, in `fuzz_test.go`: `FuzzScanJSON`, `FuzzScanForm`, `FuzzParsePlaceholder`, `FuzzMaskPAN`, `FuzzParseCatalog`, `FuzzCheckSession`, `FuzzNormalizePAN`, `FuzzVerifyReceipt`. A failing input is saved under `testdata/fuzz/<Target>/`; commit it with the fix so `make test` replays it.

### Test environment variables

This table covers the variables a developer sets. `PAN_VAULT_TEST_RUN_MAIN` and `PAN_VAULT_TEST_CATALOG` (`helpers_test.go`) are internal to the test helper `runMain`, which starts the test binary as a boot subprocess; they exist only in the test binary.

| Variable | Read by | Effect |
|---|---|---|
| `VAULT_TEST_DB_URL` | `integration_test.go` | Enables the `Integration` tests; set by `make itest`. |
| `VAULT_TEST_STRIPE_MOCK_URL` | `integration_test.go` | Enables `TestStripeMock`; set by `make stripe-mock-test`. |
| `VAULT_TEST_STRIPE_SECRET` | `integration_test.go` | Enables `TestStripeLive` against the real Stripe test-mode API when it starts with `sk_test_`. Never printed. |

## Pinned tools

| Tool | Module | Version | Installed to |
|---|---|---|---|
| staticcheck | `honnef.co/go/tools` | `v0.8.2` | `.tools/bin/staticcheck` |
| govulncheck | `golang.org/x/vuln` | `v1.9.0` | `.tools/bin/govulncheck` |
| gitleaks | `github.com/zricethezav/gitleaks/v8` | `v8.30.1` | `.tools/bin/gitleaks` |
| lefthook | `github.com/evilmartians/lefthook/v2` | `v2.2.2` | `.tools/bin/lefthook` |

All four are built with toolchain `go1.27.3`. `.tools/` is gitignored, and nothing is installed outside the repository. Other pinned inputs:

| Input | Pin | Where |
|---|---|---|
| Go toolchain | `go1.27.3` | `go.mod` |
| Build image | `golang:1.27.3@sha256:2920bb12…` | `Dockerfile` |
| stripe-mock | `stripe/stripe-mock@sha256:aeb96b83…` (v0.206.0) | `Makefile` |
| PostgreSQL for `itest` | `postgres:18` (tag) | `Makefile` |
| Mermaid CLI for `mermaid-check` | `@mermaid-js/mermaid-cli@12.0.0` (`MERMAID_CLI_VERSION`) | `Makefile` |
| Node in the CI `ci` job | `node-version: 22` (`actions/setup-node@v4`) | `.github/workflows/ci.yml` |

## Git hooks (`lefthook.yml`)

Installed per clone with `make hooks`. CI runs the same checks, so skipping a hook locally does not skip the check.

| Hook | Job | Runs |
|---|---|---|
| `pre-commit` (parallel) | `gofmt` | The staged content of each staged `*.go` file must already be gofmt-formatted (module toolchain's `gofmt`). |
| `pre-commit` | `gitleaks` | `.tools/bin/gitleaks git --pre-commit --staged --redact --no-banner --verbose --config .gitleaks.toml .`; fails if the binary is missing (`make tools`). |
| `pre-commit` | `comment-rule` | `scripts/check-comments.sh --staged` on staged `*.go` files outside `vendor/`. |
| `commit-msg` | `conventional-commit` | `scripts/check-commit-msg.sh` on the message file. |
| `pre-push` | `ci` | `make ci`, so it needs Node and `npx` (see `mermaid-check`). |

## Scripts

### `scripts/check-comments.sh`

```
scripts/check-comments.sh [--staged] file...
```

Fails if any given Go file contains `SPEC-DECISION`, `§` or `design doc`. With `--staged` it checks each file's staged content instead of the working copy. Files under `vendor/` are skipped. Used by the `comment-rule` hook and `make comment-check`.

### `scripts/check-doc-links.sh`

```
scripts/check-doc-links.sh [file...]
scripts/check-doc-links.sh --list
```

Checks the links of the given Markdown files. With no file it checks the documentation set: `README.md`, `README.es.md`, `README.pt-BR.md` and every Markdown file under `docs/` that git tracks or would track (untracked files count; ignored files and `docs/superpowers/` do not). `--list` prints that set, one file per line; `make mermaid-check` reuses it. Used by `make docs-links`, and so by `make docs-check` and `make ci`.

Every link target outside fenced code blocks and inline code is checked: inline links `[text](target)`, images `![alt](target)` and reference definitions `[ref]: target`.

| Target | Rule |
|---|---|
| `http://`, `https://`, `mailto:` | Not checked. |
| A path | Resolved relative to the linking file's directory, or to the repository root when it starts with `/`. It must exist and must not be ignored by git, since an ignored file is not on GitHub. |
| A `#fragment`, alone or after a path to a Markdown file | Must name a heading of that file under GitHub's anchor rule (lowercase, keep letters, digits, spaces, hyphens and underscores, spaces become hyphens; repeated anchors get `-1`, `-2`, …) or an HTML `id`/`name` attribute in it. |

Each failure prints `file:line: broken link: target`. The exit status is 1 if any link is broken.

### `scripts/check-commit-msg.sh`

```
scripts/check-commit-msg.sh <message-file>
scripts/check-commit-msg.sh --message <message>
```

A single argument naming an existing file is read as the message; any other single argument is the message itself. `--message` always treats the next argument as the message; callers passing text they do not control use it. Lines starting with `#` are ignored. The first non-empty line must match:

```
^(feat|fix|docs|test|refactor|chore|build|ci|perf)(\([a-z0-9-]+\))?!?: .{1,72}$
```

That is: a type, an optional scope of lowercase letters, digits and hyphens, an optional `!`, then `: ` and a subject of 1–72 characters. A `Co-Authored-By` trailer, when present, must be `Co-Authored-By: Name <email>`. Messages git writes itself pass unchanged: subjects starting with `Merge branch '`, `Merge branches '`, `Merge remote-tracking branch '`, `Merge tag '`, `Merge commit '`, `Merge pull request #`, `Revert "`, `fixup! `, `squash! ` or `amend! `.

| Exit code | Meaning |
|---|---|
| 0 | Message passes |
| 1 | Rule failure (prints the subject and the expected form) |
| 2 | Usage error or unreadable message file |

## GitHub Actions workflows

All workflows run on `ubuntu-latest` with `permissions: contents: read` and check out without persisted credentials. Every job except `commits` installs Go from `go.mod` with `actions/setup-go@v5`.

| Workflow | File | Triggers | Job | Steps | Timeout |
|---|---|---|---|---|---|
| CI | `ci.yml` | push to `main`; `pull_request` (`opened`, `synchronize`, `reopened`, `edited`) | `ci` | Full-history checkout, Go, Node 22 (`actions/setup-node@v4`, for `mermaid-check`), `make ci` | 30 min |
| CI | `ci.yml` | same | `commits` | `make commit-check` over the event's range; on pull requests, the title check below | 5 min |
| Integration | `integration.yml` | push to `main`; `pull_request` | `integration` | Install `postgresql-client` and `curl`, `make itest`, `make stripe-mock-test` | 30 min |
| Image | `image.yml` | push to `main`; `pull_request` | `image` | `make image-repro`, then `make image`; the last output line must match `^sha256:[0-9a-f]{64}$` and is uploaded as artifact `image-digest` (`image-digest.txt`) | 30 min |
| Fuzz | `fuzz.yml` | `pull_request`; schedule `0 3 * * *` (03:00 UTC daily) | `fuzz` | `make fuzz` on pull requests, `make fuzz-long` on the schedule; on failure, `testdata/fuzz` is uploaded as artifact `fuzz-crashers` | 120 min |

### Commit range in the `commits` job

| Event | `COMMIT_RANGE` |
|---|---|
| `pull_request` | `<base sha>..<head sha>` (the branch's own commits, not GitHub's merge commit) |
| push with a previous commit | `<before sha>..<pushed sha>` |
| push without a previous commit (new branch) | `<pushed sha>^!` |

### Pull request title

`main` takes squash merges, whose commit subject is the pull request title followed by GitHub's ` (#N)` suffix. The `pull request title` step therefore runs:

```
scripts/check-commit-msg.sh --message "$PR_TITLE (#$PR_NUMBER)"
```

so the title plus suffix must fit the 72-character subject rule. The title is passed through the environment, never into the script text. The step runs even when `make commit-check` failed (`!cancelled()`), so both failures show at once. Because `edited` is a trigger, a corrected title is checked again without a new push.

### Concurrency

| Workflow | Group | Cancels older runs |
|---|---|---|
| CI | per pull request ref; per run for pushes | pull requests only; every push to `main` keeps its run |
| Integration, Image, Fuzz | per ref | yes |

### Required checks

The README states that the four workflows (CI, Integration, Image, Fuzz) produce the required checks and that branch protection on `main` should require the five of them: `ci`, `commits`, `integration`, `image` and `fuzz`. Branch protection settings live in the GitHub repository settings, not in this repository, so they cannot be verified from the files here.

## See also

- [Configuration](configuration.md)
- [Logging](logging.md)
- [Rotate keys](../how-to/rotate-keys.md)
- [Local quickstart](../tutorials/local-quickstart.md)
- [Add a provider](../how-to/add-a-provider.md)
- README: [For developers](../../README.md#11-for-developers)
