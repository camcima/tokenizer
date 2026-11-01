# Respond to vault alerts

This guide is for the on-call engineer who receives an `ALERT` line from the vault. It has one runbook per alert the code emits, and a short section on the other log lines you need while investigating. The complete log vocabulary is in [Logging](../reference/logging.md).

## Before you start

- Every log line is `<RFC3339 UTC timestamp, to the second> <message>` on the instance's standard error (`logf` in `vault.go`). Lines come from one instance; with two instances, check both.
- No line ever holds a card number, CVV, key, receipt, request or response body, or HTTP header. Account and endpoint names come from the catalog, never from the request. Tokens (`tok_` + 32 hex) and client-certificate serials (`caller=`, uppercase hex) are safe to copy into tickets.
- Three alerts are rate-limited to one line per second per instance, each on its own limiter (`tokenize.go`): `session_token_invalid`, `proxy_policy` and `cvv_cache_full`. A count of those lines is a lower bound; count the matching access lines for the real volume.
- The access log has exactly one line per request: `req listener=<public|internal> method=<m> path=<p> status=<code> dur=<n>ms`, plus `caller=<serial>` on the internal listener (`guard` in `vault.go`).

## Severity overview

| Alert | Severity | Emitted in | Rate-limited |
|---|---|---|---|
| `pan_echo` | Page immediately | `proxy.go` | No |
| `decrypt_failed` | Page immediately | `proxy.go` | No |
| `egress_invariant` | Page immediately | `proxy.go` | No |
| `proxy_policy` | Page | `tokenize.go` (`alertPolicy`), called from `proxy.go` | 1/s per instance |
| `velocity` | Page | `proxy.go` | No |
| `session_token_invalid` | Notify on a rate spike | `tokenize.go` (`alertSession`) | 1/s per instance |
| `cvv_cache_full` | Notify | `tokenize.go` (`alertCVVCacheFull`) | 1/s per instance |

These seven are the only `ALERT` lines in the code. There is no alert for a wrong `Origin`; see [Lines that are not alerts](#lines-that-are-not-alerts).

## `pan_echo`

**Format:** `ALERT pan_echo account=<account> endpoint=<endpoint id> token=<token>`

**Trigger:** in `handleProxy` (`proxy.go`), after a provider response is read, `maskPAN` (`outbound.go`) found the card number in the body, plain or grouped in fours with single spaces or hyphens, and replaced each occurrence with `****` plus the last four digits. The masked body was still relayed to the platform with the provider's status.

**First steps:**

1. Note the account, endpoint and token, and the time.
2. Find out from the provider's documentation and sandbox which response field carries the card number for that endpoint. The vault masked what it returned, but confirm nothing else captured the unmasked response (provider-side logs, a debugging proxy, a sidecar).
3. Check whether the same endpoint echoes on every call (look for other `pan_echo` lines with the same `endpoint=`).

**Attack or bug:** an echo on every call to one endpoint is provider behaviour and a catalog review issue: the endpoint returns more than brand, last four, expiry and name, which needs explicit sign-off in the catalog review. Sporadic echoes tied to particular requests suggest the platform found a request shape that makes the provider reflect the card, for example in an error message; look at what the platform sent for that token.

**Involve the platform team:** when echoes are sporadic, to identify the requests. Involve the catalog reviewers in either case.

## `decrypt_failed`

**Format:** `ALERT decrypt_failed token=<token> key_version=<n> account=<account>`

**Trigger:** in `handleProxy` (`proxy.go`), after `vault.get_card` returned the row, the card could not be opened: AES-256-GCM failed under the DEK for `key_version` with the token as additional data, or the plaintext was not a card record. Causes:

- the DEK for that version is not in the instance's snapshot, and the one refresh tried before decrypting did not get it (KMS or the database unreachable, or the previous refresh finished less than 10 seconds earlier, before the key existed);
- the ciphertext in the row was changed or corrupted;
- a ciphertext was copied into another token's row: the additional data `"pan-vault/card/1\x00" + token` makes it open only under its own token.

The platform gets `500 {"error":"internal error"}`. The CVV, if any, is not consumed.

**First steps:**

1. Compare `key_version` with the DEK versions: the last `deks loaded versions=… current=…` boot line of that instance, and a recent `vault -rotate-dek` run.
2. If the version is new and the alerts stop within about 10 seconds, it was the refresh case. If they persist, check that the instance can reach Cloud SQL and KMS, that the serving account still has KMS decrypt, and the state of the KMS key versions.
3. If the version is old and well known, query which tokens fail: one token, several, or every card under one version.

**Attack or bug:** a burst right after a rotation that clears on its own is the known refresh window ([Rotate keys](rotate-keys.md#data-encryption-keys-deks)). Persistent failures for every card under one version point at the key (a disabled or destroyed KMS key version, or a wrong wrapped DEK). Failures for single tokens whose neighbours decrypt point at the rows. A holder of `vault_app` can `put_card` a copied ciphertext under a new token, which then fails here; changing an existing row needs higher database privileges than `vault_app` has. Either is a compromise of the vault's database role or of the database: treat it as one.

**Involve the platform team:** only to stop retries for the affected tokens. This is a vault, key or database incident.

## `egress_invariant`

**Format:** `ALERT egress_invariant account=<account>`

**Trigger:** in `handleProxy` (`proxy.go`), `renderRequest` returned `errEgress` from `accountURL` (`render.go`): the URL about to be sent was not `https` to exactly the account's host, or its path or base path held a `%`, a `.` or `..` segment, a `#`, a non-printable byte, or an empty query. Nothing was sent; the platform gets `500 {"error":"internal error"}`.

**First steps:**

1. Treat it as a possible compromise of the vault binary. The catalog parser and `checkProxy` refuse everything `accountURL` checks, so this line should be unreachable.
2. Record the image digest each instance runs and compare it with a reproducible build of the reviewed commit (`make image-repro`).
3. Check the egress firewall logs for denied connections from the vault's instances around that time.
4. Check whether the build includes a recent change to `catalog.json`, `render.go`, `policy.go` or `catalog.go`.

**Attack or bug:** a digest that matches a reviewed build plus a recent change to those files makes a code defect likely; a digest that matches nothing reviewed is a compromise.

**Involve the platform team:** to pause `/proxy` traffic for that account if the cause is not found quickly.

## `proxy_policy`

**Format:** `ALERT proxy_policy account=<account> endpoint=<endpoint id or -> reason=<reason>`

**Trigger:** `checkProxy` (`policy.go`) rejected a `/proxy` request against the catalog. The platform gets `400` with a fixed message. `endpoint=-` means no endpoint matched.

| `reason` | Error body | Meaning |
|---|---|---|
| `endpoint` | `endpoint not allowed` | No catalog endpoint of the account matches the method and path (or a query key is not allowed) |
| `header` | `header not allowed` | A header outside `Accept`, `Idempotency-Key`, `X-Idempotency-Key` and the endpoint's templates, a template header whose value is not exactly the unrendered template, a repeated name, or an allowlisted header with an invalid value |
| `body` | `invalid request body` | The body does not parse in the provider's format, or any body is sent to a `GET` or `HEAD` endpoint |
| `placeholder` | `invalid placeholder use` | A placeholder outside a rule position, a literal at a position, a repeated card placeholder, or no `{{pan}}` |
| `pin` | `pinned field mismatch` | A pinned field differs from the account value or literal |
| `forbidden_field` | `forbidden field` | A forbidden field (such as Stripe's `customer`) is present with a value that is not allowed |

Rejections before the account is known (`invalid token`, `unknown account`, a malformed envelope, a wrong content type) are also `400` but raise no alert.

**First steps:**

1. Find the `/proxy` access lines with `status=400` on the same instance at the same second: `req listener=internal method=POST path=/proxy status=400 … caller=<serial>`. The serial identifies the platform client certificate. Other 400s can share the second, so the match is approximate.
2. Note the reasons and endpoints over the burst, and whether a platform deploy happened shortly before.

**Attack or bug:** a burst right after a platform deploy, with one reason on one endpoint, is most likely a platform bug. Signs of an attempt: `forbidden_field` or `pin` (saving the card or charging into another account), `placeholder` or `header` patterns that try to put card data or a credential somewhere new, `endpoint=-` across many paths (probing), or a caller serial that should not be calling `/proxy` at all.

**Involve the platform team:** always. They own the request and can see the full error they received; the vault logs nothing from the request.

## `velocity`

**Format:** `ALERT velocity token=<token> caller=<serial> account=<account>`

**Trigger:** `vault.get_card` (`schema.sql`) raised SQLSTATE `P0001` because a lookup limit was reached, and `dbGetCard` (`db.go`) mapped it to `errVelocity`. The limits, counted inside the database across all instances, are 300 lookups per minute in total and 20 lookups per hour for one token. The platform gets `429 {"error":"rate limit exceeded"}`. The alert does not say which limit was hit.

**First steps:**

1. Look at the `token=` values across the alerts. The same token repeating means the per-token limit; many different tokens mean the global limit, which then refuses every caller.
2. Identify the caller serial and the platform service that holds that certificate.
3. Count `/proxy` access lines with `status=429` and with other statuses to size the burst.
4. If you need the lookup history, `vault.access_log` holds every committed lookup with its caller serial. Reading it needs privileged database access: `vault_app` has no table access. Lookups inside a rolled-back transaction are not in it; see [RR-1](../risk-register.md).

**Attack or bug:** one token hitting 20 an hour is usually a platform retry loop (for example retrying a `409` or a provider error). The global limit hit by many tokens from one caller looks like bulk extraction. A legitimate traffic peak above 300 lookups a minute is a capacity question; the limits live in `schema.sql`, and changing them is a schema change.

**Involve the platform team:** always, to stop the caller or the retry loop. If extraction is suspected, stop that platform service or cut its network path to port 9443 (its Private Service Connect endpoint or a firewall rule). Revoking the certificate at its CA has no effect: the vault checks only that a certificate chains to `VAULT_CLIENT_CA` and does no CRL or OCSP checking (`newServers` in `main.go`). To cut the certificate itself off, rotate the client CA ([Rotate keys](rotate-keys.md#platform-client-ca)).

## `session_token_invalid`

**Format:** `ALERT session_token_invalid reason=<format|hmac|expired>`

**Trigger:** `handleTokenize` (`tokenize.go`) rejected the `Authorization` header with `401 {"error":"unauthorized"}`. The check runs only after the `Origin` matched `VAULT_ALLOW_ORIGIN` exactly. `checkSession` checks format, then HMAC, then time, so `expired` is reported only for authentic tokens.

| `reason` | Meaning |
|---|---|
| `format` | No single `Authorization` header, not `Bearer v1.<expires_unix>.<64 lowercase hex>` |
| `hmac` | The MAC does not match the vault's session key |
| `expired` | Authentic, but `expires_unix` is not in the future, or more than 15 minutes ahead |

**First steps:**

1. Look at the rate, not single lines: compare `req listener=public method=POST path=/tokenize status=401` with `status=200`.
2. Check Cloud Armor for the source of the traffic.
3. Check for a recent session key rotation or platform deploy.

**Attack or bug:** a spike of `format` or `hmac` from many sources with no platform change looks like card testing or scripted traffic against `/tokenize`. `hmac` from all checkouts right after a key change means the platform and the vault hold different keys. `expired` from normal checkouts points at clock skew between platform and vault, tokens minted more than 15 minutes ahead, or checkouts left open past the token's expiry.

**Involve the platform team:** for `hmac` after a change (key mismatch) and for `expired` (token minting).

## `cvv_cache_full`

**Format:** `ALERT cvv_cache_full`

**Trigger:** in `handleTokenize` (`tokenize.go`), `cvvCache.put` (`card.go`) refused a CVV because the instance's in-memory cache holds 50,000 live entries (`cvvCacheMax`), even after removing expired ones. An entry lives 15 minutes and leaves earlier when a `/proxy` call uses it or a provider 2xx drops it. The card is still stored and the checkout gets its token; only its CVV is not cached, so a later `{{cvv}}` request for it gets `409 {"error":"cvv unavailable"}`.

**First steps:**

1. Check the `/tokenize` traffic on that instance: `req listener=public method=POST path=/tokenize status=200` lines over the last 15 minutes. Filling the cache takes 50,000 CVVs tokenized and not yet used within 15 minutes.
2. Check Cloud Armor and `session_token_invalid` alerts for a flood.

**Attack or bug:** every successful `/tokenize` call needed a valid session token, so a flood either reuses tokens the platform issued or means the platform mints them too freely. A real traffic peak spread over more instances fills each cache more slowly. The cache is per instance; see [CVV lifecycle](../explanation/cvv-lifecycle.md).

**Involve the platform team:** if the flood carries valid session tokens, to find where they came from.

## Lines that are not alerts

The full list is in [Logging](../reference/logging.md). The ones you need during an incident:

| Line | Meaning |
|---|---|
| `req listener=… method=… path=… status=… dur=…ms [caller=…]` | One per request. Unknown paths log as `path=other` and unknown methods as `method=other`. `caller=` is the client-certificate serial, internal listener only. |
| `config loaded env=<env>` | Boot step 1 (also printed by `vault -rotate-dek`) |
| `deks loaded versions=<v1,v2,…> current=<n>` | DEKs unwrapped at boot. The only line that shows which DEK versions an instance holds. |
| `catalog loaded env=<env> accounts=<n>` | Account secrets loaded |
| `receipt public key=<base64url>` | The receipt public key. Public by design; compare with the platform's accepted keys. |
| `listening public=<addr> internal=<addr>` then `ready` | Both ports bound; the boot is complete |
| `boot failed: <reason>` | Boot refused, exit 1. Reasons name variables and fixed phrases, never values. |
| `no DEKs found; run vault -rotate-dek first` | No DEK in the database, exit 1 |
| `listener failed listener=<public\|internal>` | A listener stopped unexpectedly, exit 1 |

Things that leave no line:

- **DEK refreshes.** Neither the 5-minute background refresh nor the on-demand refresh logs anything, successful or not (`refreshLoop` in `vault.go`); errors could carry KMS or database detail. Watch for `decrypt_failed` instead.
- **A wrong `Origin` on `/tokenize`.** It is `403 {"error":"origin not allowed"}` with no alert; only the access line `path=/tokenize status=403` shows it. A rise usually means a misconfigured `VAULT_ALLOW_ORIGIN` or checkout origin, or scripted traffic.
- **TLS handshake failures**, including a missing or untrusted client certificate on port 9443. They never reach a handler, and `net/http`'s own error lines are discarded (`newServers` in `main.go`).

## See also

- [Logging reference](../reference/logging.md)
- [Running it safely](../../README.md#9-running-it-safely), "Responding to alerts"
- [Nothing sensitive in logs, by construction](../../README.md#76-nothing-sensitive-in-logs-by-construction)
- [Threat model](../explanation/threat-model.md)
- [Rotate keys](rotate-keys.md)
- [Risk register](../risk-register.md)
