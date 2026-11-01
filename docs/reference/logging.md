# Logging

This page is for operators who build alerting on the vault's output and for reviewers who check what it can and cannot reveal. It lists every line the vault writes through its logger, its fields and rate limits, and the data that is never logged.

## Format and destination

| Property | Value | Source |
|---|---|---|
| Destination | Standard error. The logger is `log.New(os.Stderr, "", 0)`: no `log` prefix or flags. | `main.go` |
| Line format | `<timestamp> <message>`, one line per call | `logf`, `vault.go` |
| Timestamp | RFC 3339 in UTC, second precision, for example `2026-10-31T15:04:05Z` | `logf`, `vault.go` |
| Standard output | Used only by `vault -rotate-dek`, which prints the new DEK version (a bare integer) | `main.go` |
| `net/http` error log | Discarded (`ErrorLog: log.New(io.Discard, "", 0)`) on both listeners: its lines can quote client input | `newServers`, `main.go` |

Every line the vault writes goes through `v.logf`. The exceptions are not vault lines: the `flag` package's usage text (for `-h` or an unknown flag) and Go runtime crash output, both on standard error. Callers of `v.logf` pass only fixed format strings and non-sensitive values: tokens, certificate serials, catalog account and endpoint names, statuses, key versions and listen addresses.

## Boot lines

Written in this order by a successful serve-mode boot (`main`, `main.go`):

| Line | Fields |
|---|---|
| `config loaded env=<env>` | `env`: `dev` or `prod` |
| `deks loaded versions=<list> current=<n>` | `versions`: every DEK version held, ascending, comma-separated; `current`: the highest, used to seal new cards |
| `catalog loaded env=<env> accounts=<n>` | `accounts`: number of catalog accounts loaded for this environment |
| `receipt public key=<base64url>` | The Ed25519 receipt public key, unpadded base64url. Public by design; the platform verifies receipts with it. |
| `listening public=<addr> internal=<addr>` | The two listen addresses |
| `ready` | |

Example (dev):

```
2026-10-31T12:00:00Z config loaded env=dev
2026-10-31T12:00:00Z deks loaded versions=1 current=1
2026-10-31T12:00:00Z catalog loaded env=dev accounts=1
2026-10-31T12:00:00Z receipt public key=<base64url>
2026-10-31T12:00:00Z listening public=:8443 internal=:9443
2026-10-31T12:00:00Z ready
```

`vault -rotate-dek` writes only `config loaded env=<env>` to standard error and the version to standard output.

### Failure lines

| Line | Exit | When |
|---|---|---|
| `boot failed: <reason>` | 1 | Any boot or `-rotate-dek` failure. The reason is built only from variable names, fixed phrases, status codes and SQLSTATEs. See [Configuration](configuration.md#boot-sequence-and-log-lines). |
| `no DEKs found; run vault -rotate-dek first` | 1 | The database holds no DEK (no `boot failed:` prefix). |
| `listener failed listener=<public\|internal>` | 1 | A listener stopped serving for a reason other than shutdown. |

### Lines that do not exist

- **Shutdown.** On `SIGTERM` or `SIGINT` the vault drains both listeners and exits 0 without writing a line.
- **DEK refresh.** Neither the background refresh (every 5 minutes) nor an on-demand refresh writes a line, on success or failure. Refresh errors are not logged because they could carry KMS or database detail. A version learned by a refresh appears in no log line; a version still missing after a refresh shows up as `ALERT decrypt_failed`.
- **Errors.** Database, KMS, Secret Manager and transport errors are never logged at runtime, and a recovered panic's value is never logged.

## Access lines

The `guard` middleware (`vault.go`) writes exactly one line for every request that reaches a handler, on both listeners:

```
2026-10-31T15:04:05Z req listener=public method=POST path=/tokenize status=200 dur=12ms
2026-10-31T15:04:05Z req listener=internal method=POST path=/proxy status=200 dur=183ms caller=0A1B2C
```

| Field | Values |
|---|---|
| `listener` | `public` or `internal` |
| `method` | `GET`, `POST` or `OPTIONS`; any other method is logged as `other` (`logMethod`) |
| `path` | `/tokenize`, `/proxy` or `/healthz`; any other path is logged as `other` (`logPath`) |
| `status` | The status code sent to the client; `500` after a recovered panic. A handler that returns without writing is logged as `200`: this happens on `/proxy` when the client disconnects during a DEK refresh, and no response reaches anyone. |
| `dur` | Handler duration in whole milliseconds |
| `caller` | Internal listener only: the client certificate serial as uppercase hex (`callerSerial`), empty when there is no usable serial |

`logPath` and `logMethod` apply the same allowlist on both listeners, so `POST /proxy` sent to the public listener is logged as `path=/proxy status=404`. A card number typed into a URL path is logged as `path=other`. The query string is never logged.

Requests that `net/http` rejects before the handler runs (for example headers over `MaxHeaderBytes`, a header read timeout, or a failed TLS handshake) produce no access line.

## ALERT lines

| Line | Raised by | Rate limit | Fields |
|---|---|---|---|
| `ALERT session_token_invalid reason=<reason>` | `/tokenize`: missing, repeated or invalid session token (`tokenize.go`) | one line per second | `reason`: `format`, `hmac` or `expired` |
| `ALERT proxy_policy account=<a> endpoint=<id\|-> reason=<r>` | `/proxy`: a catalog rule failed (`proxy.go`, `policy.go`) | one line per second | `account`, `endpoint` as spelled in the catalog; `endpoint=-` when no endpoint matched; `reason`: `endpoint`, `header`, `body`, `placeholder`, `pin` or `forbidden_field` |
| `ALERT velocity token=<tok> caller=<serial> account=<a>` | `/proxy`: `vault.get_card` raised a velocity limit (`proxy.go`) | none | token, caller serial, account |
| `ALERT decrypt_failed token=<tok> key_version=<n> account=<a>` | `/proxy`: unseal failed (wrong key, missing key version after refresh, copied ciphertext) or the plaintext is not a card record (`proxy.go`) | none | token, key version from the database row, account |
| `ALERT egress_invariant account=<a>` | `/proxy`: `accountURL` refused the outgoing URL (`proxy.go`, `render.go`) | none | account |
| `ALERT pan_echo account=<a> endpoint=<id> token=<tok>` | `/proxy`: the provider response contained the card's PAN, which was masked (`proxy.go`) | none | account, endpoint, token |
| `ALERT cvv_cache_full` | `/tokenize`: the CVV cache held 50,000 live entries; the card was stored without its CVV (`tokenize.go`) | one line per second | none |

Rate-limited alerts each have their own limiter (`lastSessionAlert`, `lastPolicyAlert`, `lastCVVAlert` in `vault.go`), keyed on the Unix second, so a flood of one kind never hides another. A suppressed alert changes nothing else: the request is answered the same way.

Field alphabets:

| Field | Shape |
|---|---|
| `token` | `tok_` + 32 lowercase hex (validated before any line names it) |
| `caller` | uppercase hex |
| `account`, `endpoint` | catalog names, `^[a-z0-9_]{1,64}$`, never request text |
| `key_version` | integer |
| `reason` | one of the fixed words above |

`ALERT proxy_policy` is not raised for an invalid token, an unknown account or a malformed envelope. To find the caller of a policy alert, match it with the internal access line `path=/proxy status=400` at the same time, which carries `caller=`. Response steps for each alert are in [Respond to alerts](../how-to/respond-to-alerts.md).

## Never logged

`CLAUDE.md` forbids logging, printing or including in an error string any of the items marked "rule" below. The code keeps the others out as well. None of them appears in an error response body either.

| Never logged | Source | Notes |
|---|---|---|
| PAN | rule | A path is logged only if it is a known route, so a PAN in a URL path becomes `path=other` |
| Expiry | rule | |
| CVV | rule | |
| Session HMAC key | rule | |
| Receipt signing seed and private key | rule | Only the public key is logged |
| Receipt | rule | |
| Provider secrets | rule | Account secrets from Secret Manager or `VAULT_DEV_SECRET_*` |
| Request bodies and response bodies | rule | Both listeners, and provider responses |
| HTTP headers | rule | Inbound and outbound |
| Cardholder name | code | Checked by the leak scan |
| DEKs | code | No log call takes key material |
| `VAULT_DB_URL` | code | `openDB` errors and the boot ping failure never contain the URL |

## Leak scan

`TestMain` in `helpers_test.go` enforces the list above for the whole test suite. Every test logs into one shared buffer. After the run, with each `tok_…` token reduced to `tok_`, it fails the run (exit 1) if the buffer contains any of the following. The message never prints the value: a Luhn match prints `LOG LEAK: Luhn-valid 13–19 digit window at offset <n> (as logged|separators removed)`, a fixed value prints `LOG LEAK: test secret/CVV/name/receipt key in log` with no offset.

- any substring of 13–19 digits inside a run of digits that passes the Luhn check, both as logged and with spaces and hyphens between digits removed;
- the test CVV, the test provider secret, the PayU test API key, the test cardholder name (plain and URL-encoded), the receipt seed in hex, or the receipt private key in base64url.

## See also

- [Respond to alerts](../how-to/respond-to-alerts.md)
- [HTTP API](api.md)
- [Configuration](configuration.md)
- [Limits](limits.md)
- [Threat model](../explanation/threat-model.md)
- README: [Nothing sensitive in logs, by construction](../../README.md#76-nothing-sensitive-in-logs-by-construction)
