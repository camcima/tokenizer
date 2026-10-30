# PAN Vault — agent instructions

You are implementing spec/original.md. Read it fully before writing code. These rules override your defaults.

## Version overrides
- Go 1.27.3 (not 1.23) and PostgreSQL 18 (not 16). These supersede the spec.

## Structure
- ALL application code goes in `main.go`. Do not create packages, subdirectories, or additional .go files other than `main_test.go`.
- Do not introduce interfaces, generics, or abstractions to "clean up" the file. Repetition is acceptable; indirection is not.
- `schema.sql` is the only SQL. The Go code calls `vault.put_card`, `vault.get_card`, `vault.list_deks`, `vault.add_dek` and nothing else. No table names appear in Go.

## Dependencies
- Standard library plus `github.com/jackc/pgx/v5/stdlib` only. If you believe something requires another module, STOP and explain; do not add it.
- No cloud SDKs. Google APIs are called with `net/http` as described in SPEC §8.3 and §8.6.

## Things you must never do
- Log, print, or include in an error string: a PAN, expiry, CVV, session HMAC key, provider secret, request body, response body, or any HTTP header.
- Accept a query string on any endpoint.
- Forward any inbound header to a provider except `Idempotency-Key`.
- Use the inbound `Authorization` header for anything on the internal listener.
- Follow redirects. Read `HTTP_PROXY`/`HTTPS_PROXY`.
- Add an endpoint not in SPEC §5 and §6.
- Persist CVV anywhere, including temp files, the database, or logs.
- Build a provider request from a caller-supplied body or path. Each op builds the entire request.
- Skip or weaken a test to make CI pass.

## When unsure
- If the spec is ambiguous, choose the stricter interpretation (reject more, log less, expose less) and note the choice in a code comment prefixed `SPEC-DECISION:`.
- If a spec requirement seems wrong or impossible, stop and report before deviating.

## Deliverables, in order
1. `go.mod`, vendored `pgx/v5`, `Makefile`, `Dockerfile`.
2. `schema.sql` exactly as in SPEC §7.
3. `main.go` with every section of SPEC §5–§11 implemented.
4. `main_test.go` with every test in SPEC §13.1, then §13.2.
5. `make ci` green. Report the final `go list -m all` output and the image digest.
