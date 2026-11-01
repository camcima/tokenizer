# Signed card receipt reference

This page is for engineers who verify or store receipts on the platform, or who change `receipt.go`. It specifies the receipt format, the signature, the payload, the BIN rule, the signing key, the reference verifier and the tests. Why the platform may keep these facts is explained in [README §6.2](../../README.md#62-the-signed-receipt); how to wire verification into the platform is in [Integrate the platform](../how-to/integrate-the-platform.md).

## Purpose

A receipt is the vault's Ed25519-signed statement of which token it issued and the truncated card details (BIN, last four, expiry, name) the platform may keep next to that token.

## Where it appears

`POST /tokenize` returns it as the `receipt` field of the 200 response (`tokenizeResponse` in `tokenize.go`):

```json
{"token":"tok_…","last4":"4242","exp_month":"12","exp_year":"2030","receipt":"rcpt.v1.….…"}
```

| Property | Value | Source |
|---|---|---|
| When it is signed | After `put_card` succeeds, so it never names a token that does not exist. A failed store returns no receipt. | `handleTokenize` |
| BIN and name | Returned to the browser only inside the receipt, never as top-level `/tokenize` fields. | `handleTokenize` |
| Logging | The receipt is never logged. | `handleTokenize`, `CLAUDE.md` |

## Format

```text
rcpt.v1.<base64url(payload)>.<base64url(signature)>
```

| Part | Content |
|---|---|
| 1 | `rcpt` |
| 2 | `v1` |
| 3 | The payload bytes, base64url without padding (`base64.RawURLEncoding`) |
| 4 | The 64-byte Ed25519 signature, base64url without padding: always 86 characters |

The constant `receiptPrefix = "rcpt.v1."` names the scheme and version.

## Signature

| Item | Value |
|---|---|
| Algorithm | Ed25519 (`crypto/ed25519`) |
| Signed bytes | The ASCII string `"rcpt.v1." + <part 3 exactly as transmitted>` |
| Not signed | The decoded payload on its own. A signature over the bare payload part does not verify (`TestReceiptSignatureCoversPrefix`). |

`signReceipt` encodes the payload once and signs those bytes, so a verifier never re-serializes the JSON. Because the prefix is inside the signed bytes, a receipt cannot be relabelled as another scheme or version. `signReceipt` panics if the private key is not 64 bytes, rather than issue an unsigned receipt.

## Payload

The payload is compact JSON, no trailing newline, keys in this order (`receipt` struct in `receipt.go`):

| # | Key | JSON type | Content |
|---|---|---|---|
| 1 | `token` | string | The issued token, `tok_` + 32 lowercase hex characters |
| 2 | `bin` | string | First 8 or 6 digits of the card number (see [BIN rule](#bin-rule)) |
| 3 | `last4` | string | Last four digits |
| 4 | `exp_month` | string | `01`–`12`, as submitted |
| 5 | `exp_year` | string | Four digits, as submitted |
| 6 | `name` | string | Cardholder name as submitted (1–100 runes). Omitted when the card was tokenized without a name. |
| 7 | `iat` | integer | Issue time, Unix seconds (`v.now().Unix()`) |

Encoding details (`encodeReceipt`):

- HTML escaping is off, so `&`, `<` and `>` in a name appear verbatim (`TestReceiptNameRoundTrip`).
- Non-ASCII characters are written as UTF-8. `encoding/json` writes U+2028 and U+2029 as the escape sequences `\u2028` and `\u2029`.
- The longest receipt the vault can issue (100-rune name of six-byte escapes, largest `iat`) is 1097 bytes (`TestVerifyReceiptLengthCap`).

Example payload, with a name:

```json
{"token":"tok_0123456789abcdef0123456789abcdef","bin":"42424242","last4":"4242","exp_month":"12","exp_year":"2030","name":"JANE Q DOE","iat":1793456789}
```

## BIN rule

`cardBIN(pan)` takes the normalized card number (13–19 digits):

| Card number length | `bin` length | `bin` + `last4` digits | Digits never in the receipt |
|---|---|---|---|
| 16 | 8 | 12 | 4 |
| 13 | 6 | 10 | 3 |
| 14 | 6 | 10 | 4 |
| 15 | 6 | 10 | 5 |
| 17 | 6 | 10 | 7 |
| 18 | 6 | 10 | 8 |
| 19 | 6 | 10 | 9 |

The code comment gives the reason: the PCI SSC truncation table allows the first 8 and last 4 digits only for 16-digit numbers; other lengths need the card brand's confirmation, which the vault does not have, so they keep the first 6. `TestReceiptBIN` checks every length from 13 to 19 and that `bin` + `last4` never covers the whole number and never exceeds 12 digits.

## Signing key

| Item | Value | Source |
|---|---|---|
| Prod source | `VAULT_RECEIPT_KEY_SECRET`: Secret Manager resource name, `projects/P/secrets/S` (`^projects/[A-Za-z0-9_-]+/secrets/[A-Za-z0-9_-]+$`). The vault reads `versions/latest`. | `loadConfig`, `accessSecret` |
| Dev source | `VAULT_DEV_RECEIPT_KEY_HEX`: exactly 64 hex characters. When unset in dev, `VAULT_RECEIPT_KEY_SECRET` is used. | `loadConfig` |
| Seed | 32 bytes. A Secret Manager payload must be exactly 64 hex characters. | `loadKey32`, `decodeKey64` |
| Key pair | `ed25519.NewKeyFromSeed(seed)`; the seed is zeroed right after. | `newVault` |
| Public key log | `receipt public key=<base64url>` at boot, unpadded base64url of the 32-byte public key (43 characters), after `catalog loaded` and before `listening`. | `logReceiptPublicKey`, `main` |
| Never logged | The seed, the private key, any receipt. | `logReceiptPublicKey`, `handleTokenize` |

Boot errors (prefixed `boot failed: `):

| Condition | Error |
|---|---|
| Neither variable set | `VAULT_RECEIPT_KEY_SECRET is required (or VAULT_DEV_RECEIPT_KEY_HEX in dev)` |
| `VAULT_DEV_RECEIPT_KEY_HEX` set with `VAULT_ENV=prod` | `VAULT_DEV_RECEIPT_KEY_HEX is refused when VAULT_ENV=prod` |
| Dev value not 64 hex characters | `VAULT_DEV_RECEIPT_KEY_HEX must be exactly 64 hex chars` |
| Resource name of the wrong shape | `VAULT_RECEIPT_KEY_SECRET must be projects/P/secrets/S` |
| Secret Manager payload not 64 hex characters | `VAULT_RECEIPT_KEY_SECRET: payload must be exactly 64 hex chars` |
| Secret Manager call failed | `VAULT_RECEIPT_KEY_SECRET: <secret manager reason>` |

On any failure in `loadSecrets`, the keys already loaded (the session HMAC key) are zeroed. If loading the account secrets fails next, `main` zeroes both the session key and the seed. How to generate the seed and derive the public key offline is in [README §9](../../README.md#9-running-it-safely); all variables are in [Configuration](../reference/configuration.md).

The vault holds one receipt key. The README verifier's comment says to call `Verify` once per accepted public key during a key rotation.

## Verifier rules (`verifyReceipt`)

`verifyReceipt(pub ed25519.PublicKey, s string) (receipt, bool)` returns the decoded receipt and `true`, or the zero `receipt` and `false`. It never panics. The checks run in this order; the first failure rejects:

| # | Check | Detail |
|---|---|---|
| 1 | Length | `len(s) > maxReceiptLen` (`2048`) rejects before any other work. |
| 2 | Public key | `len(pub) != 32` rejects (`ed25519.Verify` would panic). |
| 3 | Split | `strings.SplitN(s, ".", 5)` must give exactly 4 parts, and `parts[0] + "." + parts[1] + "."` must equal `rcpt.v1.`. |
| 4 | Signature length | `len(parts[3])` must be exactly 86, checked before the part is scanned or decoded. |
| 5 | Alphabet | Parts 3 and 4 are non-empty and use only `A–Z a–z 0–9 - _`. Checked first because the Go base64 decoder skips CR and LF. |
| 6 | Signature decode | `base64.RawURLEncoding.Strict()`: unused trailing bits must be zero; the result must be 64 bytes. |
| 7 | Signature | `ed25519.Verify(pub, "rcpt.v1." + parts[2], sig)`. |
| 8 | Payload decode | Strict base64url, as in step 6. Unauthenticated bytes never reach the JSON decoder. |
| 9 | Exact keys | One JSON object; every key is one of the seven receipt keys, spelled exactly, each at most once (`exactKeys`). |
| 10 | Decode | `DisallowUnknownFields`; types must match (`iat` as a string fails); nothing after the object. |
| 11 | Required values | `token`, `bin`, `last4`, `exp_month`, `exp_year` non-empty; `iat > 0`. |
| 12 | Name | If the `name` key is present it must be a non-empty string (`""` and `null` are rejected). |

What `verifyReceipt` does not check: that `token` equals the token the platform received with the receipt (the caller must check it), the format of individual values beyond non-emptiness, and the age of `iat`.

## Reference verifier for the platform

[README §11.4 Verifying a receipt](../../README.md#114-verifying-a-receipt) publishes a standalone Go verifier (`package receipt`, function `Verify`) for the platform, and describes the same rules for other languages: for canonical base64url, re-encode the decoded bytes and require them to equal the received part. `CLAUDE.md` requires README §11.4 to match `verifyReceipt`.

`TestReadmeReceiptVerifier` (`receipt_test.go`) extracts the Go code of the `#### 11.4 ` section from `README.md`, `README.es.md` and `README.pt-BR.md` and checks that:

- the three copies are identical;
- each contains `strings.SplitN(s, ".", 5)`, `base64.RawURLEncoding.Strict()`, `ed25519.Verify(pub, []byte("rcpt.v1."+parts[2])`, `DisallowUnknownFields()`, `const maxReceiptLen = 2048`, `len(s) > maxReceiptLen` and `len(parts[3]) != 86`.

The test does not compare the README code with `receipt.go` byte for byte, and does not execute it.

## What the platform may store

From a receipt that verifies and whose `token` equals the token it received, the platform stores the BIN, last four, expiry and name next to the token ([README §6.2](../../README.md#62-the-signed-receipt)). An invalid receipt is rejected as a whole. README §6.2 also sets three rules for the platform: customers see only the last four; no hash of the card number is stored next to the truncated number; brand, issuer, country and card type come from the platform's own BIN data.

## Worked example

Built with a throwaway program from `signReceipt` and `verifyReceipt` in `receipt.go`, using the dev seed below. Ed25519 signatures are deterministic, so the same seed and payload always give this receipt.

| Input | Value |
|---|---|
| `VAULT_DEV_RECEIPT_KEY_HEX` | `0000000000000000000000000000000000000000000000000000000000000003` |
| Card | `4242 4242 4242 4242`, `12/2030`, name `JANE Q DOE` |
| Token | `tok_0123456789abcdef0123456789abcdef` |
| `iat` | `1793456789` |

Boot log line for this seed:

```text
receipt public key=84FibkHnAn6kMb_jAJ6UvdJadGvuxGiUjWw8fF3JpUs
```

Payload (part 3 decoded):

```json
{"token":"tok_0123456789abcdef0123456789abcdef","bin":"42424242","last4":"4242","exp_month":"12","exp_year":"2030","name":"JANE Q DOE","iat":1793456789}
```

Receipt (298 bytes; shown on several lines here, one line on the wire):

```text
rcpt.v1.
eyJ0b2tlbiI6InRva18wMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiIsImJpbiI6IjQyNDI0MjQyIiwibGFzdDQiOiI0MjQyIiwiZXhwX21vbnRoIjoiMTIiLCJleHBfeWVhciI6IjIwMzAiLCJuYW1lIjoiSkFORSBRIERPRSIsImlhdCI6MTc5MzQ1Njc4OX0
.
WIppD-FhNesdOmsZqH_JRp9HlW9V-AZHQ_O5NN-zXPkVdZRmtQVwIHJX-Y-burU5YedbJ7ptYrhCmMAMp-KIAA
```

`verifyReceipt` with the public key above accepts it and returns the payload's values. This seed is a fixed, public test value; never use it outside local development.

## Tests

| Test | File | Checks |
|---|---|---|
| `TestReceiptBIN` | `receipt_test.go` | `cardBIN` for lengths 13–19: 8 digits only at 16; prefix of the number; `bin` + `last4` ≤ 12 digits and shorter than the number. |
| `TestReceiptRoundTrip` | `receipt_test.go` | Starts with `rcpt.v1.`, four parts, unpadded base64url, verifies, decodes to the signed values, no trailing newline in the payload. |
| `TestReceiptNameRoundTrip` | `receipt_test.go` | Names with non-ASCII and `& < >` round-trip and appear verbatim in the payload. |
| `TestReceiptOmitsEmptyName` | `receipt_test.go` | No `name` key without a name; exact compact payload in key order. |
| `TestVerifyReceiptRejects` | `receipt_test.go` | Wrong, short or nil public key; tampered payload; flipped, truncated or empty signature; other version or prefix (re-signed too); three or five parts; padding; standard alphabet; CR/LF; non-canonical trailing bits; unknown, case-folded, duplicate or missing keys; trailing data; null values; empty or null name; wrong value type; non-object payloads; empty input. Each returns `false` and the zero receipt without panicking. |
| `TestVerifyReceiptLengthCap` | `receipt_test.go` | A signature encodes to 86 characters; the longest issuable receipt is 1097 bytes and verifies; correctly signed receipts just under 2048 bytes verify and just over are rejected. |
| `TestVerifyReceiptSignatureBounds` | `receipt_test.go` | Signature parts of 85, 87 characters and 8 MiB are rejected; rejecting the 8 MiB part allocates under 1 MiB. |
| `TestReceiptSignatureCoversPrefix` | `receipt_test.go` | A signature over the bare payload part is rejected; one over prefix + payload part verifies. |
| `TestReadmeReceiptVerifier` | `receipt_test.go` | See [Reference verifier](#reference-verifier-for-the-platform). |
| `FuzzVerifyReceipt` | `fuzz_test.go` | Seeds include valid receipts (with and without name, short BIN, longest name) and many malformed ones. For any input: a rejection returns the zero receipt; an acceptance is within 2048 bytes and equals exactly what `signReceipt` produces for the returned values. |
| `TestTokenizeReturnsReceipt` | `tokenize_test.go` | Response keys are exactly `token`, `last4`, `exp_month`, `exp_year`, `receipt`; the receipt verifies and states the issued token, BIN, last four, expiry, name and `iat`. |
| `TestTokenizeNoReceiptOnStoreFailure` | `tokenize_test.go` | A failed store returns no receipt. |
| `TestReceiptDoesNotTripLeakScan` | `tokenize_test.go` | A receipt's card fields never form a 13–19 digit Luhn-valid run. |
| `TestNewVaultReceiptKeys` | `boot_test.go` | `newVault` derives the key pair from the seed and zeroes the seed. |
| `TestBootLogsReceiptPublicKey` | `boot_test.go` | The boot line carries the public key as unpadded base64url and never the seed or private key in any encoding. |
| `TestIntegrationEndToEnd` | `integration_test.go` | Over real TLS and a real database: checks that the vault's `receiptPub` equals the test seed's public key, then verifies the receipt from `/tokenize` with it and checks that it states the tokenized card and an `iat` within a minute of now. It does not read the boot log. |

## See also

- [README §6.2 The signed receipt](../../README.md#62-the-signed-receipt)
- [README §11.4 Verifying a receipt](../../README.md#114-verifying-a-receipt)
- [Integrate the platform](../how-to/integrate-the-platform.md)
- [API reference](../reference/api.md)
- [Configuration](../reference/configuration.md)
- [Cryptography](../explanation/cryptography.md)
- [Logging](../reference/logging.md)
