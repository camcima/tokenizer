# Limits

This page is for operators, platform engineers and reviewers who need the exact bounds the vault enforces. It lists every size, count, rate and time limit with its value, what happens when it is exceeded, and where it is defined.

Status codes and error strings are those of the [HTTP API](api.md); log lines are described in [Logging](logging.md). "Boot failure" means the vault logs `boot failed: <reason>` and exits 1.

## Request shapes

### Public listener (`POST /tokenize`)

| Limit | Value | When exceeded | Source |
|---|---|---|---|
| Request body (`maxPublicBody`) | 4096 bytes (`4 << 10`) | `413 request body too large` | `tokenize.go:109` |
| Request headers (`MaxHeaderBytes`) | 16 KiB (`16 << 10`); over HTTP/1, `net/http` allows about 4 KiB of slack beyond it | `net/http` answers `431 Request Header Fields Too Large` in plain text before the vault's handler runs, so no access-log line | `main.go:654` |
| Session token expiry digits | 1–19 (`^[0-9]{1,19}$`) | `401 unauthorized`, `ALERT session_token_invalid reason=format` | `tokenize.go:25` |
| Session token MAC | exactly 64 lowercase hex characters | `401 unauthorized`, `reason=format` | `tokenize.go:26` |
| Session token lifetime (`sessionMaxAhead`) | expiry must be after now and at most 900 s (15 min) ahead | `401 unauthorized`, `reason=expired` | `tokenize.go:22`, `tokenize.go:61` |
| PAN length | 13–19 digits after stripping spaces and hyphens | `400 invalid pan` | `card.go:82` |
| CVV length | 3–4 digits | `400 invalid cvv` | `card.go:107` |
| Cardholder name | 1–100 runes | `400 invalid name` | `card.go:124` |
| CORS preflight cache (`Access-Control-Max-Age`) | 600 s | Browser repeats the preflight | `tokenize.go:228` |

### Internal listener (`POST /proxy`, `GET /healthz`)

| Limit | Value | When exceeded | Source |
|---|---|---|---|
| Envelope body (`maxInternalBody`) | 65536 bytes (`64 << 10`) | `413 request body too large` | `proxy.go:18` |
| Request headers (`MaxHeaderBytes`) | 16 KiB (`16 << 10`); over HTTP/1, `net/http` allows about 4 KiB of slack beyond it | `net/http` answers `431 Request Header Fields Too Large` in plain text before the vault's handler runs, so no access-log line | `main.go:670` |
| JSON nesting (`maxJSONDepth`) | 64 levels of objects and arrays | Envelope: `400 invalid request body`. Provider `json` body: `400 invalid request body`, `ALERT proxy_policy … reason=body` | `scan.go:124`, `scan.go:289` |
| Placeholder occurrences per body (`maxOccurrences`) | 64 | `400 invalid placeholder use`, `reason=placeholder` | `scan.go:120`, `scan.go:462`, `scan.go:485` |
| Path wildcard segment | 1–128 characters of `[A-Za-z0-9_-]` | `400 endpoint not allowed`, `reason=endpoint` | `policy.go:66` |
| Platform header value | 1–1024 bytes, each `0x20`–`0x7E`, no `{{` | `400 header not allowed`, `reason=header` | `policy.go:341` |
| Platform header names | `Accept`, `Idempotency-Key`, `X-Idempotency-Key` (plus the endpoint's template headers) | `400 header not allowed`, `reason=header` | `policy.go:56` |
| Request path bytes (`matchEndpoint`) | starts with `/`; no `%`, `//` or `..` | `400 endpoint not allowed`, `reason=endpoint` | `policy.go:254` |
| Request query bytes (`validProxyQuery`) | non-empty; only `A–Z a–z 0–9 . _ ~ % + = & [ ] -` | `400 endpoint not allowed`, `reason=endpoint` | `policy.go:298`–`policy.go:306` |

### Catalog (checked at boot and by `TestEmbeddedCatalog`)

The catalog is compiled in, so a catalog that breaks one of these limits fails the test suite and, if built anyway, refuses boot.

| Limit | Value | Source |
|---|---|---|
| Positions per endpoint | at most 64 (`maxOccurrences`) | `catalog.go:338` |
| Provider, endpoint and account names (`catNameRe`) | `^[a-z0-9_]{1,64}$` | `catalog.go:125` |
| Secret, account value, pin account and wildcard names (`validSecretName`) | `[A-Za-z0-9_]{1,64}` | `scan.go:61` |
| Header template name (`catHeaderNameRe`) | `^[A-Za-z][A-Za-z0-9-]{0,63}$` | `catalog.go:146` |
| Header template value | 1–1024 bytes of printable ASCII, exactly one placeholder | `catalog.go:475` |
| Rule path and base path | at most 1024 bytes | `catalog.go:434` |
| JSON Pointer address | at most 1024 bytes | `catalog.go:514` |
| Account host name | at most 253 characters, labels of 1–63 characters | `catalog.go:576`, `catalog.go:580` |
| Account host port | 1–65535 | `catalog.go:584`–`catalog.go:589` |
| Account value | 1–256 bytes of printable ASCII, no `{{` | `catalog.go:597` |

### Receipt

| Limit | Value | When exceeded | Source |
|---|---|---|---|
| Receipt length accepted by `verifyReceipt` (`maxReceiptLen`) | 2048 bytes | Rejected before any part is scanned | `receipt.go:41` |
| Longest receipt the vault issues | 1097 bytes (documented in the `maxReceiptLen` comment) | n/a | `receipt.go:37`–`receipt.go:40` |
| Signature part length | exactly 86 characters (unpadded base64url of 64 bytes) | Rejected before decoding | `receipt.go:118` |
| BIN in the payload | first 8 digits of a 16-digit PAN, otherwise first 6 | n/a | `receipt.go:57`–`receipt.go:62` |

See [Receipt](receipt.md) for the full verification rules.

## Provider request and response

| Limit | Value | When exceeded | Source |
|---|---|---|---|
| Provider response body (`maxProviderResponse`) | 4 MiB (`4 << 20`) | `502 provider unreachable`; a truncated body is never relayed | `outbound.go:18`, `proxy.go:245` |
| Compressed provider response | no `Content-Encoding` allowed after the transport | `502 provider unreachable` | `proxy.go:237`–`proxy.go:242` |
| Outbound URL path bytes (`accountURL`) | each byte `0x21`–`0x7E`, no `#`; no empty query; no `%` and no `.` or `..` segment in base path + path | `500 internal error`, `ALERT egress_invariant account=<a>` (defence in depth: `matchEndpoint` already refuses such paths) | `render.go:79`–`render.go:96` |
| Outbound TLS | TLS 1.2 minimum | `502 provider unreachable` | `outbound.go:72` |
| Redirects | never followed | The redirect response is relayed as is | `outbound.go:67`–`outbound.go:69` |
| PAN masking needle | PAN of at least 13 digits | A shorter value is never masked (no stored PAN is shorter) | `outbound.go:34` |
| GCP response body (`maxGCPResponse`) | 64 KiB (`64 << 10`) | Error `response too large`: boot failure at boot; a failed refresh or failed connection at runtime | `gcp.go:28` |
| Metadata access token | 1–4096 bytes of printable non-space ASCII, `expires_in` 1–86400 s | Error `metadata token: invalid token response` | `gcp.go:97` |

## Rate and capacity

| Limit | Value | When exceeded | Source |
|---|---|---|---|
| Global lookups | 300 `vault.get_card` calls per rolling minute, counted from committed `get` rows of `access_log` across all instances | `429 rate limit exceeded`, `ALERT velocity token=… caller=… account=…` | `schema.sql:52`–`schema.sql:56` |
| Per-token lookups | 20 `vault.get_card` calls per token per rolling hour | `429 rate limit exceeded`, `ALERT velocity …` | `schema.sql:58`–`schema.sql:62` |
| Lookup serialisation | `pg_advisory_xact_lock(hashtext('vault.get_card'))`: one lookup at a time across all sessions | Lookups queue; each waits within `dbCallTimeout` | `schema.sql:50` |
| Database pool | 16 open connections per instance | Requests wait for a connection within `dbCallTimeout` | `main.go:279` |
| CVV cache entries (`cvvCacheMax`) | 50,000 live entries per instance | `/tokenize` still stores the card and returns `200`; the CVV is not cached; `ALERT cvv_cache_full` | `card.go:233` |
| `ALERT session_token_invalid` | one line per second | Further lines in the same second are dropped; the `401` is still sent | `tokenize.go:69`–`tokenize.go:76` |
| `ALERT proxy_policy` | one line per second | Further lines in the same second are dropped; the `400` is still sent | `tokenize.go:82`–`tokenize.go:92` |
| `ALERT cvv_cache_full` | one line per second | Further lines in the same second are dropped | `tokenize.go:96`–`tokenize.go:103` |
| DEK refreshes (`dekRefreshMinGap`) | at most one per 10 s, single-flight | A request for an unknown key version within the window does not refresh; decrypt fails: `500`, `ALERT decrypt_failed` | `vault.go:103` |
| Outbound idle connections | 16 per host | n/a | `outbound.go:74` |

The velocity checks run before the lookup's own audit row is inserted, so a rejected lookup is not counted. A lookup of an unknown token is counted: its row is inserted before the card is selected. A lookup inside a transaction that is rolled back leaves no row; that accepted risk is [RR-1](../risk-register.md).

## Timeouts

| Timeout | Value | When exceeded | Source |
|---|---|---|---|
| Public `ReadHeaderTimeout` | 5 s | `net/http` closes the connection; no handler, no access-log line | `main.go:650` |
| Public `ReadTimeout` | 10 s | The body read fails: `400 invalid request body` | `main.go:651` |
| Public `WriteTimeout` | 30 s | The response cannot be written; the client sees the connection close | `main.go:652` |
| Public `IdleTimeout` | 60 s | An idle keep-alive connection is closed | `main.go:653` |
| Internal `ReadHeaderTimeout` | 5 s | As public | `main.go:666` |
| Internal `ReadTimeout` | 10 s | As public | `main.go:667` |
| Internal `WriteTimeout` | 60 s | As public; the provider call may already have been made | `main.go:668` |
| Internal `IdleTimeout` | 60 s | As public | `main.go:669` |
| Database call per request (`dbCallTimeout`), pool wait included | 5 s | `500 internal error` | `main.go:602` |
| `/healthz` database ping (`healthzTimeout`) | 2 s | `503 unavailable` | `proxy.go:19` |
| Outbound client overall (`http.Client.Timeout`), response body read included | 30 s | `502 provider unreachable` | `outbound.go:66` |
| Outbound TLS handshake | 10 s | `502 provider unreachable` | `outbound.go:75` |
| Outbound idle connection | 90 s | Connection closed | `outbound.go:76` |
| DEK refresh, one attempt (`dekRefreshTimeout`), detached from the request's cancellation | 30 s | Refresh fails; the current snapshot is kept; decrypt of an unknown version fails: `500`, `ALERT decrypt_failed` | `vault.go:106` |
| Background DEK refresh period (`dekRefreshEvery`) | 5 min | n/a | `vault.go:100` |
| CVV lifetime (`cvvCacheTTL`) | 15 min from `/tokenize` | `{{cvv}}` gets `409 cvv unavailable` | `card.go:228` |
| CVV sweep period (`cvvSweepEvery`) | 60 s | n/a (expired entries are also removed when the cache is full) | `card.go:229` |
| Metadata token reuse margin (`tokenMargin`) | refreshed 60 s before expiry | n/a | `gcp.go:29` |
| Boot database ping (`bootDBTimeout`) | 5 s | Boot failure `database ping failed` | `main.go:677` |
| Boot GCP phase (`bootGCPTimeout`): DEK load, secrets, account secrets, `-rotate-dek`, each | 60 s | Boot failure | `main.go:678` |
| Shutdown drain (`shutdownTimeout`), both listeners concurrently | 20 s | The process closes the pool and exits 0 when the budget ends | `main.go:679` |

## Changing a limit

- Every Go limit on this page is a compile-time constant or literal in the file named. Changing one is a code change and a new image.
- The velocity limits (300 per minute, 20 per token per hour) and the advisory lock live in `vault.get_card` in `schema.sql`, which is the single source of SQL. Changing them is a schema change applied by the migration pipeline.
- No limit is configurable at runtime: none is read from an environment variable, a file or the database.

## See also

- [HTTP API](api.md)
- [Configuration](configuration.md)
- [Logging](logging.md)
- [Database](database.md)
- [Performance](../explanation/performance.md)
- [CVV lifecycle](../explanation/cvv-lifecycle.md)
