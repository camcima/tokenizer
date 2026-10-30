# PAN Vault — agent instructions

You are implementing spec/original.md. Read it fully before writing code. These rules override your defaults.

## Version overrides
- Go 1.27.3 (not 1.23) and PostgreSQL 18 (not 16). These supersede the spec.
- `docs/superpowers/specs/2026-10-30-provider-agnostic-proxy-design.md` ("D") supersedes spec §6.2–§6.4 (the `/proxy` request and ops catalog), the "no placeholder syntax" sentence of §6.3 and the "no generic proxy mode" line of §14. Where they disagree, D wins.

## Known limitations (v1)
- **Serialized lookups.** `vault.get_card` takes `pg_advisory_xact_lock` before it counts, so the velocity check and the `access_log` insert cannot race (no velocity TOCTOU). As a result, lookups run one at a time across all sessions. The vault also caps its pool at 16 open connections per instance (`db.SetMaxOpenConns(16)`), and each request's database call has a 5s deadline.
- **Rollback bypass of the audit row (accepted 2026-10-30).** `access_log` rows are written inside the caller's transaction. A holder of the `vault_app` DB role can call `get_card` in an explicit transaction and roll it back. The ciphertext is still returned, but the audit row and its velocity count disappear, so that role holder bypasses the velocity limits. pgaudit (`pgaudit.log='function'`) still logs every call, whether or not it is rolled back. The vault itself only makes single-statement autocommit calls, so it cannot trigger this. The fix, an autonomous write (`dblink`), is planned for v1.1. Do not edit `schema.sql` for this: it must stay byte-identical to spec §7.

## Structure
- All code is one Go package (`package main`) at the repo root, split into files by responsibility (see README §11). No sub-packages, subdirectories, exported APIs, interfaces or generics. Tests live in matching `*_test.go` files; shared test helpers and the leak-scan `TestMain` are in `helpers_test.go`.
- Do not introduce interfaces, generics, or abstractions to "clean up" the code. Repetition is acceptable; indirection is not.
- `schema.sql` is the only SQL. The Go code calls `vault.put_card`, `vault.get_card`, `vault.list_deks`, `vault.add_dek` and nothing else. No table names appear in Go.
- Code comments explain behaviour and reasons; they never reference the spec, its section numbers, the design or plan documents.

## Dependencies
- Standard library plus `github.com/jackc/pgx/v5/stdlib` only. If you believe something requires another module, STOP and explain; do not add it.
- No cloud SDKs. Google APIs are called with `net/http` as described in SPEC §8.3 and §8.6.

## Things you must never do
- Log, print, or include in an error string: a PAN, expiry, CVV, session HMAC key, provider secret, request body, response body, or any HTTP header.
- Accept a query string on any endpoint.
- Use any inbound HTTP header of a `/proxy` request in the provider request. Platform headers reach a provider only through the envelope's `request.headers`, and only the global allowlist `Accept`, `Idempotency-Key`, `X-Idempotency-Key` (plus an endpoint's header template sent verbatim, which the vault renders itself). Everything else is rejected, never dropped or forwarded.
- Use the inbound `Authorization` header for anything on the internal listener.
- Follow redirects. Read `HTTP_PROXY`/`HTTPS_PROXY`.
- Add an endpoint not in SPEC §5 and §6.
- Persist CVV anywhere, including temp files, the database, or logs.
- Send a caller-supplied provider request that has not passed every catalog check (see "Proxy and catalog rules").
- Add provider-specific Go code. The one exception is a named signer (D§5.7, e.g. `payu`), added only when a real provider needs it. A provider, endpoint or account is a `catalog.json` change.
- Make the catalog editable at runtime (database, Secret Manager, env, files). It is compiled in with `go:embed`.
- Skip or weaken a test to make CI pass.

## Proxy and catalog rules (D§5)
- The platform builds the whole provider request (`{account, token, request:{method, path, headers, body}}`) with placeholders. The vault checks it against the compiled-in `catalog.json`, fills the placeholders, attaches the account's credential and sends it to the account's host. The account selects host, base path, secrets and pinned values; the platform never does.
- Placeholder vocabulary is exactly D§5.3: `{{pan}}`, `{{cvv}}`, `{{name}}`, `{{exp_month}}`/`{{exp_month:int}}`, `{{exp_year}}`/`{{exp_year:yy}}`/`{{exp_year:int}}`, `{{exp:yyyy/mm}}`/`{{exp:mm/yy}}`, `{{secret:NAME}}`, `{{basic:NAME}}`, `{{signature}}`. Nothing else, ever sent literally or otherwise.
- Placeholders appear only at catalog positions: a body address listed in the endpoint's `positions` (each address maps to exactly one placeholder), or an endpoint `headers` template. A placeholder fills an entire value; no concatenation. Each card placeholder appears at most once. Literal `{{` anywhere else is rejected.
- Card placeholders (`pan`, `cvv`, `name`, expiry) are never allowed in headers, path or query.
- Vault credentials only appear where the catalog puts them: `{{secret:NAME}}` and `{{signature}}` in an endpoint header template or at a listed body position, and `{{basic:NAME}}` only in a header template (the parser refuses it at a body position). A credential field or header accepts only its vault placeholder; a platform-supplied credential is rejected.
- Body formats are `json` (JSON Pointer addresses, RFC 6901) and `form` (decoded field names). The bytes sent equal the validated bytes plus the substitutions. Form keys match `^[A-Za-z0-9_-]+(\[[A-Za-z0-9_-]+\])*(\[\])?$`: no `.`, and `[]` only at the end (`metadata[order.id]` is rejected).
- The vault sets `Host`, `Content-Type`, `Content-Length` and `User-Agent: pan-vault/1` itself.
- Pins (account value or literal) are verified, never overwritten. `forbid` entries must be absent or equal an allowed literal. Policy rejections are 400 with a fixed `msg*` constant and `ALERT proxy_policy account=<a> endpoint=<id|-> reason=<r>`.
- `{{cvv}}` with no cached CVV and `{{name}}` with a card stored without a name are 409. The vault never edits a body to drop a field.
- Card placeholders (`card_data: true`) go only to endpoints that charge or create a single-use hand-off token. Never to an endpoint that stores the card at the provider or sends data to a caller-chosen URL.
- The vault credential is only for card-carrying calls (D§2, D§5.6). Every catalog endpoint must have `"card_data": true` and a `{{pan}}` position (the parser refuses anything else), and every `/proxy` request must contain `{{pan}}` (else 400 `invalid placeholder use`, `reason=placeholder`). Calls without card data (payments with a provider token, refunds, queries) are made by the platform with its own keys.
- Dev secrets for catalog accounts: `VAULT_DEV_SECRET_<ACCOUNT>_<NAME>`, uppercased, every character outside `[A-Z0-9]` replaced by `_` (e.g. `stripe_test`/`secretKey` → `VAULT_DEV_SECRET_STRIPE_TEST_SECRETKEY`). Used only when `VAULT_ENV=dev`. An unknown `VAULT_DEV_*` name refuses a dev boot, any `VAULT_DEV_*` refuses a prod boot, and boot fails if any secret of a loaded account is missing. There is no `VAULT_STRIPE_SECRET` or `VAULT_DEV_STRIPE_SECRET`.

## Catalog changes
Every PR that adds or changes a provider, endpoint or account in `catalog.json` must, in its description and diff:
- [ ] Link the provider doc proving that each `card_data` endpoint charges, or creates a single-use hand-off token. Never one that stores the card at the provider.
- [ ] List every card-saving or reuse flag the endpoint accepts (save, attach, customer, recurring, setup-for-future-use and the like) and show the `forbid` entry covering each one.
- [ ] Check every form key against the grammar above (no `.`, `[]` only at the end).
- [ ] Update `egress-hosts.<env>.txt` (`egress-hosts.dev.txt` / `egress-hosts.prod.txt`) to the hosts of that environment's accounts (`TestEgressHostsMatchCatalog`), and the matching egress firewall rule in the infra repo.
- [ ] Add an example request for every new endpoint to `embeddedFixtures` in `catalog_test.go` (`TestEmbeddedCatalog` fails without one).
- [ ] Add a fixture to `testCatalogJSON` (and the tests that use it) if the change introduces a new shape: a new body format, pin kind, placeholder modifier, signer or header template form.
- [ ] Create each new account secret in Secret Manager under the resource name the catalog gives.
- [ ] Verify the endpoint against the provider's sandbox (D§6) and record it in the catalog review notes below.

## Catalog review notes
- **Stripe** (`stripe`, account `stripe_test`, dev): `POST /v1/tokens` only, verified against stripe-mock v0.206.0 (`TestStripeMock`). The vault creates a single-use `tok_…`; the platform charges it or creates a PaymentMethod from it with its own keys, and must never save, attach or reuse the card through it (platform policy, README §7.4). `customer` (Connect: a token cloned from a customer's saved card) is forbidden. `POST /v1/payment_methods` is not in the catalog: D§6 classifies a card PaymentMethod as storage (reusable, attachable). D§6's other card endpoint, `POST /v1/payment_intents` with `payment_method_data[card][…]`, is not shipped either: stripe-mock rejects raw card fields there (`payment_method_data[type]` does not accept `card`), so it cannot be verified in CI.
- Adyen, Mercado Pago, PayU and Pagar.me are modelled only in the synthetic `testCatalogJSON`. Each lands in `catalog.json` as its own data-only PR after sandbox verification.

## When unsure
- If the spec is ambiguous, choose the stricter interpretation (reject more, log less, expose less) and explain the choice in a plain code comment (no spec or section references).
- If a spec requirement seems wrong or impossible, stop and report before deviating.

## Deliverables, in order
1. `go.mod`, vendored `pgx/v5`, `Makefile`, `Dockerfile`.
2. `schema.sql` exactly as in SPEC §7.
3. The `package main` sources with every section of SPEC §5–§11 implemented.
4. The `*_test.go` files with every test in SPEC §13.1, then §13.2.
5. `make ci` green. Report the final `go list -m all` output and the image digest.
