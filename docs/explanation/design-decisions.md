# Design decisions

This page is for engineers and reviewers who want the reasoning behind PAN Vault's main choices in one place. Each entry is a short decision record: the context, the decision and its consequences, including the trade-off accepted. [README §8](../../README.md#8-why-it-is-built-the-way-it-is) gives the headline version of several of these; the entries here add the mechanism and link to the pages that go deeper.

## Contents

1. [Standard library plus `pgx` only](#1-standard-library-plus-pgx-only)
2. [One `package main`, split by file](#2-one-package-main-split-by-file)
3. [Go 1.27.3 and PostgreSQL 18](#3-go-1273-and-postgresql-18)
4. [`schema.sql` is the only SQL; four functions are the only data access](#4-schemasql-is-the-only-sql-four-functions-are-the-only-data-access)
5. [An advisory lock in `get_card`](#5-an-advisory-lock-in-get_card)
6. [A 16-connection pool and a 5-second database deadline](#6-a-16-connection-pool-and-a-5-second-database-deadline)
7. [Two listeners, not one with path routing](#7-two-listeners-not-one-with-path-routing)
8. [mTLS with one pinned CA, terminated in the vault](#8-mtls-with-one-pinned-ca-terminated-in-the-vault)
9. [Session tokens minted by the platform](#9-session-tokens-minted-by-the-platform)
10. [A provider-agnostic proxy with a compiled-in catalog](#10-a-provider-agnostic-proxy-with-a-compiled-in-catalog)
11. [No provider storage endpoints; the vault credential only for card-carrying calls](#11-no-provider-storage-endpoints-the-vault-credential-only-for-card-carrying-calls)
12. [Cardholder name captured at tokenize](#12-cardholder-name-captured-at-tokenize)
13. [Signed receipts carrying the BIN](#13-signed-receipts-carrying-the-bin)
14. [Token-bound additional data](#14-token-bound-additional-data)
15. [Bounds on the CVV cache](#15-bounds-on-the-cvv-cache)
16. [DEK refresh rules](#16-dek-refresh-rules)
17. [A `scratch` image with a static, reproducible binary](#17-a-scratch-image-with-a-static-reproducible-binary)
18. [Test and CI posture](#18-test-and-ci-posture)
19. [The never-logged list and the leak-scan `TestMain`](#19-the-never-logged-list-and-the-leak-scan-testmain)
20. [Accepted risk RR-1](#20-accepted-risk-rr-1)
21. [Documentation in three languages, kept structurally identical](#21-documentation-in-three-languages-kept-structurally-identical)

## 1. Standard library plus `pgx` only

**Context.** The vault runs inside the cardholder data environment. Every third-party module it imports is code that runs there and a supply-chain path into it.

**Decision.** The only direct dependency is `github.com/jackc/pgx/v5` (the PostgreSQL driver, used through `pgx/v5/stdlib`). There is no HTTP framework, logging library, ORM or cloud SDK. Google APIs (the metadata server, Cloud KMS, Secret Manager) are called with `net/http` in `gcp.go`. The dependency set is vendored.

**Consequences.**
- `make deps-check` fails unless the direct requirements are exactly `github.com/jackc/pgx/v5` and `go.sum` lists no more modules than `deps-baseline.txt`. `make vendor-check` fails unless `vendor/` equals what `go mod vendor` produces.
- The vault carries its own small REST client for KMS and Secret Manager, with the checks a SDK would hide made explicit: resource names validated against `kmsKeyRe` and `secretNameRe` before they go into a URL, responses capped at 64 KiB, the metadata response header required, the Secret Manager CRC32C checked when present, and errors limited to a status code or a fixed phrase.
- Trade-off: a little more code to read, in exchange for no code the reviewers have not read.

## 2. One `package main`, split by file

**Context.** A reviewer or auditor should be able to read the whole service and know that nothing hides in a corner of a package tree.

**Decision.** All code is one Go package at the repository root, split into files by responsibility ([README §11.3](../../README.md#113-repository-layout)). There are no sub-packages, exported APIs, interfaces or generics. Repetition is accepted; indirection is not. The one seam is a set of function fields on `vault` (`putCard`, `getCard`, `ping`, `refreshDEKs`), which production wires to the database and tests to in-memory fakes.

**Consequences.**
- The security core (`scan.go`, `policy.go`, `render.go`, `catalog.go`) can be audited on its own without boot or HTTP plumbing.
- File boundaries are a convention, not a compiler-enforced wall: any file can call anything.
- Some code is repeated (for example the three alert limiters in `tokenize.go`), because a shared abstraction would hide behaviour.

## 3. Go 1.27.3 and PostgreSQL 18

**Context.** The toolchain and database version are fixed by the project's engineering rules (`CLAUDE.md`, "Version overrides").

**Decision.** `go.mod` declares `go 1.27` and `toolchain go1.27.3`; the build image is `golang:1.27.3` pinned by digest in the `Dockerfile`; CI reads the version from `go.mod`; the pinned tools are built with the same toolchain (`TOOLCHAIN = go1.27.3` in the `Makefile`). The integration tests run against `postgres:18`, and production uses Cloud SQL for PostgreSQL 18 ([README §9](../../README.md#9-running-it-safely)).

**Consequences.**
- The code relies on current standard-library behaviour: `crypto/rand.Read` never returns an error and crashes the process if the operating system's generator fails (the code calls it without error handling on purpose, `newToken` in `card.go`), and shutdown uses `sync.WaitGroup.Go` (`main.go`).
- `GOTOOLCHAIN` downloads the pinned toolchain when a developer's local Go is older.

## 4. `schema.sql` is the only SQL; four functions are the only data access

**Context.** If the application could read tables, a compromised vault process could run `SELECT * FROM vault.cards`, and the audit trail would depend on the application choosing to write it.

**Decision.** `schema.sql` holds every table, function and grant, and is applied by a separate owner role (`vault_owner`); the vault never runs migrations. Go calls exactly four `SECURITY DEFINER` functions (`db.go`): `vault.put_card`, `vault.get_card`, `vault.list_deks` and `vault.add_dek`. No table name appears in Go. The serving role `vault_app` may execute `put_card`, `get_card` and `list_deks`; the rotation role `vault_rotator` may execute `list_deks` and `add_dek`; neither has any table privilege. Every call is a single autocommit statement.

**Consequences.**
- Every lookup writes its `access_log` row inside the same function that returns the ciphertext; the application cannot skip it, except by rolling the call back ([RR-1](#20-accepted-risk-rr-1)).
- A compromised vault can read at most one card per call, by token. The velocity limits bind it only for calls that commit: a holder of `vault_app` can call `get_card` inside a transaction and roll it back, which erases the audit row and its velocity count. That is the accepted risk [RR-1](#20-accepted-risk-rr-1); the vault itself makes only single-statement autocommit calls.
- Database errors are reduced to the function name and SQLSTATE (`dbErr`), because a driver error can quote argument values.
- Schema changes go through the migration pipeline, never the vault. The [database reference](../reference/database.md) lists the objects.

## 5. An advisory lock in `get_card`

**Context.** `get_card` enforces two velocity limits by counting `access_log` rows: 300 lookups per minute globally and 20 per hour per token. Counting and then inserting is a check-then-act sequence: concurrent calls can all count before any of them inserts.

**Decision.** `get_card` takes `pg_advisory_xact_lock(hashtext('vault.get_card'))` before it counts. The lock is transaction-scoped, so it is released when the single statement commits.

**Consequences.**
- No velocity race: measured without the lock, 50 simultaneous lookups let 27 or 28 through instead of 20 ([README §8](../../README.md#8-why-it-is-built-the-way-it-is)).
- All lookups run one at a time across every session and every instance, at a few milliseconds each. That is far above the 300-per-minute global limit, so the limit, not the lock, is the effective ceiling.
- The lock is taken before the count, so a lookup that will be refused for velocity also queues for it.
- Lookups waiting on the lock hold pool connections while they wait (see the next entry).

## 6. A 16-connection pool and a 5-second database deadline

**Context.** Serialized lookups and a stalled database can both hold requests. Without bounds, requests would pile up until the listener's write timeout and connections to Cloud SQL would grow without limit.

**Decision.** `openDB` caps the pool at `db.SetMaxOpenConns(16)` in both modes. Each request's database call (`putCard`, `getCard`) runs under `dbCallTimeout = 5 * time.Second`, which includes waiting for a pool slot, derived from the request's context so an earlier deadline or a client disconnect still wins. `GET /healthz` pings with its own 2-second limit.

**Consequences.**
- A saturated pool or a stalled server fails the request with `500 internal error` after at most 5 seconds instead of holding it.
- Two instances open at most 32 connections between them.
- `/tokenize` and `/proxy` share the pool, so a burst of lookups queued on the advisory lock can delay `put_card` calls. The [performance page](performance.md) puts numbers on the ceilings.

## 7. Two listeners, not one with path routing

**Context.** The browser-facing endpoint and the platform-facing endpoint have entirely different callers and trust models: anyone on the internet with a session token, against an authenticated platform service.

**Decision.** Two `http.Server`s on two ports (`newServers` in `main.go`): public `:8443` serves only `/tokenize`, with TLS 1.3 and no client certificate; internal `:9443` serves only `/proxy` and `/healthz`, with TLS 1.3 and a required, verified client certificate. Each has its own handler, so no route is reachable through the wrong port. Timeouts differ: the public `WriteTimeout` is 30 seconds, the internal one 60 seconds, which covers an on-demand key refresh (at most 30 seconds) or a provider round trip (outbound client timeout 30 seconds), though not both at their limits.

**Consequences.**
- A routing bug cannot expose `/proxy` on the public port, because the public handler knows no other route.
- Two load balancers to operate.
- `/tokenize` and `/proxy` for the same card can land on different instances, which is the root of the [CVV cross-instance residual](cvv-lifecycle.md#the-cross-instance-residual).

## 8. mTLS with one pinned CA, terminated in the vault

**Context.** `/proxy` lends the vault's provider credential and decrypts cards. Only the platform's own services may call it, and the vault must know which one did.

**Decision.** The internal listener uses `tls.RequireAndVerifyClientCert` with a pool holding exactly one CA (`loadClientCA`: one PEM block, of type `CERTIFICATE`, with `CA:TRUE`; anything else refuses boot). TLS terminates in the vault, not at a load balancer. The verified client certificate's serial (`callerSerial`) is logged on every internal access-log line and written to `access_log.caller` by `get_card`. A certificate with a negative serial counts as no certificate.

**Consequences.**
- The vault itself sees and records which client certificate made each lookup, for alerts (`ALERT velocity … caller=…`) and the database audit trail.
- The CA must issue certificates only to platform services allowed to call `/proxy`.
- There is no unauthenticated health route. Load balancers use TCP checks, and real readiness is a monitor holding a platform certificate that calls `GET /healthz` ([README §9](../../README.md#9-running-it-safely)).

## 9. Session tokens minted by the platform

**Context.** Without a gate, `/tokenize` is a free card-validity oracle for anyone on the internet.

**Decision.** The platform mints a session token (`v1.<expires_unix>.<hex HMAC-SHA256>`) for each checkout with a key it shares with the vault. The vault checks it in `checkSession`, constant-time, with a window of at most 15 minutes. The [cryptography page](cryptography.md#the-session-token) explains the mechanism.

**Consequences.**
- The vault stays stateless and needs no endpoint to hand out sessions.
- The token is not bound to a card and is not single use; Cloud Armor rate limits on the public endpoint are the second layer.
- The platform holds a secret that lets it create session tokens, which is acceptable: it is the party that decides a checkout has started.

## 10. A provider-agnostic proxy with a compiled-in catalog

**Context.** The platform needs several providers and several accounts per provider. Writing each provider operation as Go code would grow the vault with every provider.

**Decision.** The platform builds the whole provider request with placeholders; the vault checks it against `catalog.json`, which is compiled in with `go:embed` and never read from disk, a database or the environment at runtime. The account chooses the host and the credential; the platform never does. Adding a provider, endpoint or account is a data-only change with a review checklist. The only provider-specific Go code allowed is a named signer (today `payu`). [Proxy design](proxy-design.md) explains the model in depth.

**Consequences.**
- The catalog carries the security weight that builder code would have carried, so every catalog change gets a strict review.
- A catalog change is still a release; because builds are reproducible, the image digest attests the catalog that runs.

## 11. No provider storage endpoints; the vault credential only for card-carrying calls

**Context.** If the vault could call an endpoint that stores the card at the provider, cards would accumulate outside the vault through the vault's own credential. If the vault lent its credential to calls without card data, it would become a general-purpose proxy for the platform's provider traffic.

**Decision.** Card placeholders go only to endpoints that charge or create a single-use hand-off token, never to one that stores the card at the provider or sends data to a caller-chosen URL. Every catalog endpoint must have `"card_data": true` and a `{{pan}}` position (the parser refuses anything else), and every `/proxy` request must contain `{{pan}}`. Calls without card data (a payment with a provider token, a refund, a query) are the platform's, made with its own keys. For Stripe this means `POST /v1/tokens` only; `POST /v1/payment_methods` is excluded because a card PaymentMethod is reusable and attachable.

**Consequences.**
- The vault never makes the platform's later calls with a provider token. The hand-off token itself reaches the platform inside the masked `/proxy` response.
- The vault cannot stop the platform from saving a card through a hand-off token with its own keys. That is a platform rule, not a vault control ([README §7.4](../../README.md#74-what-the-vault-cannot-enforce-hand-off-tokens)).

## 12. Cardholder name captured at tokenize

**Context.** Some provider requests carry the cardholder name. The vault offers no endpoint to add data to a stored card, and the platform should be able to rely on the name it keeps.

**Decision.** `/tokenize` accepts an optional `name`: 1–100 runes of valid UTF-8, no control characters and no U+FFFD (`validName`); `"name": null` is rejected. It is sealed inside the card record and fills `{{name}}` at catalog positions. It is returned to the browser only inside the signed receipt.

**Consequences.**
- A card tokenized without a name cannot fill `{{name}}`: that `/proxy` call gets `409 {"error":"name unavailable"}`, and the vault never edits the body to drop the field.
- A provider may echo the name in its response, and the vault masks only card numbers, so the name can reach the platform that way.
- The `omitempty` tag keeps the plaintext of a card without a name unchanged, so older rows still decode.

## 13. Signed receipts carrying the BIN

**Context.** The platform needs card facts (brand, issuer, how to display the card, expiry) but has no endpoint to ask the vault later, and cannot trust the browser, whose JavaScript could report anything.

**Decision.** `/tokenize` returns `{token, last4, exp_month, exp_year, receipt}`, where the receipt is an Ed25519-signed statement of the token, BIN, last four, expiry, name and issue time. The BIN is the first 8 digits only for a 16-digit number, otherwise the first 6 (`cardBIN`). The BIN and the name appear only inside the receipt, never as top-level fields. The vault does not return a brand: the platform derives brand, issuer and card type from the BIN with its own BIN data.

**Consequences.**
- The platform verifies with a public key and holds no secret that could create a receipt ([cryptography](cryptography.md#the-signed-receipt)).
- There is one place to read the BIN and name from, and that place is signed.
- The vault needs no BIN table to keep current; the platform updates its own.
- 8 + 4 digits always leaves digits hidden, and the BIN rule follows the PCI SSC truncation table without depending on card-brand confirmations the vault does not have.

## 14. Token-bound additional data

**Context.** AES-GCM proves a ciphertext came from a given key, not which row it belongs to. A ciphertext copied into another token's row would otherwise decrypt as that token's card.

**Decision.** Every card is sealed with the additional data `"pan-vault/card/1\x00" + token` (`cardAAD`). The token is drawn before sealing for this reason. Nothing is ever sealed or opened without it.

**Consequences.**
- A moved ciphertext fails authentication: `500` and `ALERT decrypt_failed`, and nothing is sent to the provider.
- The versioned prefix allows the binding to change later without ambiguity. See [cryptography](cryptography.md#the-attack-the-additional-data-defeats).

## 15. Bounds on the CVV cache

**Context.** The CVV is needed once, must never be stored, and a flood of `/tokenize` calls must not be able to pin unbounded memory or push out real customers' CVVs.

**Decision.** An in-memory map per instance (`cvvCache`): 15-minute TTL, swept every 60 seconds, at most 50,000 live entries, single use (`take` removes), zeroed on removal, dropped on any provider 2xx for the token. A full cache refuses new entries and logs `ALERT cvv_cache_full` at most once per second; it never evicts a live entry.

**Consequences.**
- CVVs already cached are protected: real customers mid-checkout keep theirs. Every card tokenized while the cache is full, a real customer's included, is stored without a cached CVV, and a later `{{cvv}}` request for it gets the ordinary `409`.
- A full cache costs at most about 20 MB of resident memory, an upper-bound estimate from two runs of different size (see [performance](performance.md)).
- Per-instance storage means a CVV can be missing on the other instance (409) or survive a hand-off there for up to about 16 minutes. [CVV lifecycle](cvv-lifecycle.md) explains why the stronger options were rejected.

## 16. DEK refresh rules

**Context.** A new DEK version can be added while instances run, and the first instance to load it seals new cards under it at once. Another instance must still open those cards, without a restart and without hammering KMS.

**Decision.** An immutable snapshot behind `atomic.Pointer[dekSet]`, refreshed every 5 minutes and on demand when a card's `key_version` is missing; refreshes are single-flight, at least 10 seconds apart, bounded by 30 seconds and detached from the request's cancellation. Only new versions are unwrapped, keys only accumulate, and a failed refresh keeps the current snapshot.

**Consequences.**
- No rolling restart is needed after rotation.
- A `decrypt_failed` window remains when an instance first meets a new version: up to 10 seconds if its last refresh finished just before the key existed, and for as long as KMS or the database stays unreachable otherwise, with a refresh retried at most every 10 seconds until one succeeds ([README §9](../../README.md#9-running-it-safely)).
- Old keys stay loaded for the life of the process. The reasons for each rule are in [cryptography](cryptography.md#the-rules-and-why-each-exists).

## 17. A `scratch` image with a static, reproducible binary

**Context.** Anything in the image besides the vault is attack surface, and an auditor must be able to check that a running image came from reviewed code, catalog included.

**Decision.** The `Dockerfile` builds with `CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w -buildid="` from only the build inputs (no `.git`, no documentation), then copies into `FROM scratch` exactly three files: the binary, the CA bundle and a one-line `/etc/passwd`. It runs as `USER 65532:65532` (`nonroot`). The `Makefile` builds with `SOURCE_DATE_EPOCH=0`, `rewrite-timestamp=true` and `--provenance=false`; `make image-repro` builds twice without cache and fails if the image IDs differ. The Image workflow runs `image-repro` and keeps the digest as a build artifact.

**Consequences.**
- No shell, no package manager, no root, no dynamic linker.
- Two builds of the same commit give the same digest, so the digest identifies the code and the embedded catalog.
- No debugging inside the container, which is intentional: nobody should debug inside the cardholder data environment.

## 18. Test and CI posture

**Context.** The vault is small but every line is security-relevant, and checks that run only on a developer's machine can be skipped.

**Decision.**
- `make test` runs every unit test with the race detector (`go test -race -count=1`).
- Eight fuzz targets (`FuzzScanJSON`, `FuzzScanForm`, `FuzzParsePlaceholder`, `FuzzMaskPAN`, `FuzzParseCatalog`, `FuzzCheckSession`, `FuzzNormalizePAN`, `FuzzVerifyReceipt`) run for 20 seconds each on every pull request and for 10 minutes each nightly; failing inputs are uploaded and, once fixed, committed under `testdata/fuzz/`, where `make test` replays them.
- `make ci` adds gofmt, `go vet`, staticcheck, govulncheck, the dependency and vendor checks, the documentation checks (`docs-check`, with its link check, and `mermaid-check`), `comment-check` and gitleaks over the full git history, all with pinned tool versions.
- `make itest` runs the database and end-to-end tests against a real `postgres:18`, and `make stripe-mock-test` sends platform-built requests through the embedded catalog to `stripe-mock`.
- Opt-in lefthook hooks (`make hooks`) run gofmt, gitleaks and the comment rule before each commit, the conventional-commit rule on each message, and `make ci` before each push. CI repeats every one of these checks, so skipping a hook skips nothing.
- Branch protection lives in the GitHub repository settings, not in this repository; the README says it should require the four workflows. Checked on 2026-10-31, `main` required five status checks (`ci`, `commits`, `integration`, `image`, `fuzz`, the jobs of the four workflows), up to date with `main`, and linear history, and the repository allowed only squash merges, with the pull request's title as the commit subject. The `commits` job checks that title, with its ` (#N)` suffix, against the conventional-commit rule.

**Consequences.**
- The test code is larger than the service code.
- A change cannot reach `main` without every check passing.

## 19. The never-logged list and the leak-scan `TestMain`

**Context.** Log lines are shipped out of the vault to the log sink. A single card number in a log line would bring that pipeline into PCI scope.

**Decision.** The vault never logs, prints or puts in an error string a PAN, expiry, CVV, the session HMAC key, the receipt seed or private key, a receipt, a provider secret, a request or response body, or any HTTP header. The only log lines are boot lines, one access-log line per request and fixed-format `ALERT` lines. The access log records only known paths and methods (`path=other`, `method=other` otherwise), a panic value is never logged, and `net/http`'s own error log is discarded. In the tests, every test vault logs into one shared buffer, and `TestMain` in `helpers_test.go` scans it after the run: tokens are blanked first, then every window of 13–19 digits inside every digit run is Luhn-checked, both as logged and with space and hyphen runs between digits removed; the buffer is also searched for the test CVV, the test provider secrets, the test cardholder name (raw and URL-escaped), the receipt seed in hex and the receipt private key. Any match fails the build. A Luhn match prints only its offset; a matched CVV, secret, name or receipt key prints a fixed message without the value or its position.

**Consequences.**
- Debugging relies on status codes, fixed error strings and alert reasons, never on request contents.
- A log leak introduced anywhere in the code fails `make test`, as long as a test exercises that path. The [logging reference](../reference/logging.md) lists every line.

## 20. Accepted risk RR-1

**Context.** The audit row and velocity count written by `get_card` live inside the caller's transaction.

**Decision.** Accepted for v1. The description, compensating controls, owner and revisit trigger are in the [risk register, RR-1](../risk-register.md#rr-1-rollback-bypass-of-lookup-accounting). `schema.sql` is not changed for it.

**Consequences.** See the register.

## 21. Documentation in three languages, kept structurally identical

**Context.** The README is read by engineers, security reviewers, auditors and non-engineers, in English, Spanish and Portuguese. A translation that falls behind silently misstates the vault.

**Decision.** `README.md`, `README.es.md` and `README.pt-BR.md` are one document in three languages. `make docs-check`, part of `make ci`, fails if their counts of heading lines, table rows or Mermaid blocks differ, or if any of them repeats a retired claim from a fixed list.

**Consequences.**
- A section, table row or diagram changed in one language only fails CI.
- The check compares structure, not meaning: a sentence changed in one language only still needs review.
- This `docs/` set is English only and is not part of the three-language structure check; `docs-check` does check that every link in the READMEs and in `docs/` resolves, and `mermaid-check` that every diagram renders.
