# Provider catalog reference (`catalog.json`)

This page is for engineers who read, review or change `catalog.json`. It describes every key the parser in `catalog.go` accepts, every rule it enforces at parse time with the exact error text, the placeholder vocabulary and how each placeholder is rendered (`render.go`), how the catalog is embedded and loaded, and the tests that guard it. The step-by-step procedure for a catalog change is in [Add a provider](../how-to/add-a-provider.md); the reasons behind the design are in [Proxy design](../explanation/proxy-design.md).

## How the catalog is loaded

| Aspect | Behaviour | Source |
|---|---|---|
| Embedding | `catalog.json` is compiled into the binary with `//go:embed catalog.json` into `catalogJSON`. It is never read from disk, the database, Secret Manager or the environment at runtime. | `catalog.go` |
| When it is parsed | In serve mode, right after the TLS certificate, key and client CA are loaded and before the database, KMS or Secret Manager is touched (boot step 1c). `-rotate-dek` does not parse it. | `main.go` |
| Function | `parseCatalog(data []byte, env string) (*catalog, error)`. `env` must be `dev` or `prod`, otherwise `catalog: environment must be dev or prod`. | `catalog.go` |
| What is validated | Every provider, and every account of every environment. | `parseCatalog` |
| What is kept | All providers; only the accounts whose `env` equals `VAULT_ENV`. Accounts of the other environment are unknown to this vault (`/proxy` answers `unknown account`). | `parseCatalog` |
| Empty account set | If no account matches `VAULT_ENV`, boot fails with `boot failed: catalog has no accounts for env=<env>`. | `main.go` |
| Dev secret check | In dev, `checkDevSecretVars` then checks every `VAULT_DEV_*` variable against the loaded accounts (see [Dev secret variables](#dev-secret-variables)). | `main.go` |
| Account secrets | After the DEKs and the session/receipt keys, `loadAccountSecrets` loads every secret of every loaded account. All or nothing: one missing or invalid secret fails the boot. | `main.go` |
| Boot log | `catalog loaded env=<env> accounts=<n>` once the account secrets are loaded. | `main.go` |

Parse errors never name a Secret Manager resource or an account value. They name the provider, endpoint, account or address at fault. A failed parse at boot is logged as `boot failed: <error>` and the process exits 1.

## Top-level structure

The file is one JSON object. The comment above `rawCatalog` in `catalog.go` summarises the schema:

```text
{"providers": {NAME: {"format": "json"|"form", "endpoints": [{"id", "method", "path", "query": [KEY],
   "card_data": true, "headers": {NAME: TEMPLATE}, "positions": {ADDR: PLACEHOLDER},
   "pins": {ADDR: {"account": VALUE_NAME} | {"literal": SCALAR}}, "forbid": {ADDR: [SCALAR]},
   "signer": "payu"}]}},
 "accounts": {NAME: {"provider", "env": "dev"|"prod", "host", "base_path",
   "secrets": {NAME: RESOURCE}, "values": {NAME: VALUE}}}}
```

| Key | Type | Meaning |
|---|---|---|
| `providers` | object, provider name → provider | The request rules of each provider. |
| `accounts` | object, account name → account | Our accounts at those providers. An account selects the host, base path, secrets and pinned values. |

### Strictness of the JSON itself

Before decoding, `parseCatalog` walks the whole document with `jsonWalk` in strict mode and then checks key spelling with `catExactKeys`.

| Rule | Error |
|---|---|
| Exactly one JSON value, an object; no duplicate keys at any depth; no trailing data; valid UTF-8 | `catalog: not strict JSON (one object, no duplicate keys or trailing data, valid UTF-8)` |
| Every key of a struct object is spelled exactly as listed below (case matters: `Format` is not `format`) | `catalog: unknown key "<key>" in "<JSON Pointer of the parent>"` |
| Every value has the type the decoder expects (for example `"card_data": "yes"`) | `catalog: wrong type at "<field>"` |
| Any other decoder failure | `catalog: invalid structure` |

`catExactKeys` applies to the objects that decode into structs, at fixed depths:

| Object | Allowed keys (`catalog.go` variable) |
|---|---|
| Root | `providers`, `accounts` (`catRootKeys`) |
| `/providers/<P>` | `format`, `endpoints` (`catProviderKeys`) |
| `/providers/<P>/endpoints/<i>` | `id`, `method`, `path`, `query`, `card_data`, `headers`, `positions`, `pins`, `forbid`, `signer` (`catEndpointKeys`) |
| `/providers/<P>/endpoints/<i>/pins/<addr>` | `account`, `literal` (`catPinKeys`) |
| `/accounts/<A>` | `provider`, `env`, `host`, `base_path`, `secrets`, `values` (`catAccountKeys`) |

Keys of map objects (provider names, account names, header names, addresses, secret and value names) are not in these sets; their own rules follow.

## Providers

| Key | Required | Rule | Error |
|---|---|---|---|
| provider name (map key) | yes | `^[a-z0-9_]{1,64}$` (`catNameRe`). Names appear in log lines, so the alphabet is restricted. | `catalog: provider "<p>": invalid name` |
| `format` | yes | `json` or `form`. One body format per provider. | `catalog: provider "<p>": format must be json or form` |
| `endpoints` | yes | At least one endpoint. | `catalog: provider "<p>": no endpoints` |

Across a provider's endpoints:

| Rule | Error |
|---|---|
| Endpoint ids are unique within the provider | `catalog: provider "<p>": endpoint "<id>": duplicate id` |
| No two endpoints share a method and overlapping paths (equal segment by segment, a wildcard matching anything), so a request matches at most one rule (`catPathsOverlap`) | `catalog: provider "<p>": endpoints "<a>" and "<b>" overlap` |

Every endpoint error below is prefixed with `catalog: provider "<p>": `.

## Endpoints

| Key | Required | Type | Rule |
|---|---|---|---|
| `id` | yes | string | `^[a-z0-9_]{1,64}$` |
| `method` | yes | string | One of `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, upper case |
| `path` | yes | string | See [Path rules](#path-rules) |
| `card_data` | yes | bool | Must be `true` |
| `positions` | yes | object, address → placeholder | At most 64; must contain a `{{pan}}` position. See [Positions](#positions) |
| `query` | no | array of strings | Allowed query keys. Each must match the form key grammar; no repeats |
| `headers` | no | object, header name → template | See [Header templates](#header-templates) |
| `pins` | no | object, address → pin | See [Pins](#pins) |
| `forbid` | no | object, address → array of literals | See [Forbid](#forbid) |
| `signer` | no | string | `""` (absent) or `payu`. See [Signers](#signers) |

| Rule | Error |
|---|---|
| `id` matches `^[a-z0-9_]{1,64}$` | `endpoint #<index>: invalid id` |
| `card_data` is `true` (absent counts as `false`) | `endpoint "<id>": card_data must be true (non-card calls are made by the platform)` |
| `method` is one of the five allowed | `endpoint "<id>": method "<m>" not allowed` |
| `path` follows the path rules | `endpoint "<id>": invalid path` |
| Each `query` key matches the form key grammar and appears once | `endpoint "<id>": query key "<k>" invalid or repeated` |

`card_data` must be `true` and `positions` must list `{{pan}}` because the account credential is only for card-carrying calls. Calls without card data (payments with a provider token, refunds, queries) are made by the platform with its own keys. At request time, `checkProxy` (`policy.go`) also refuses any `/proxy` request that contains no `{{pan}}` occurrence.

A `GET` endpoint parses, but `checkProxy` refuses a body on `GET` and `HEAD` requests and requires a `{{pan}}` occurrence, so no request to a `GET` endpoint can pass today (comment on `checkProxy`).

### Path rules

`parseCatPath(p, wildcards=true)`:

- starts with `/` and is at most 1024 bytes;
- is split on `/`; every segment is either a literal of RFC 3986 unreserved characters `^[A-Za-z0-9._~-]+$` (`catSegmentRe`) other than `.` and `..`, or a wildcard `{name}` with `name` matching `[A-Za-z0-9_]{1,64}`, each name at most once;
- so there are no empty segments (`//`, a trailing `/`, or `/` alone), no `%`, no `?`, and a wildcard fills a whole segment (`pi_{id}` is refused).

At request time a wildcard segment matches `^[A-Za-z0-9_-]{1,128}$` (`proxyWildcardRe` in `policy.go`).

### Positions

A position maps one body address to the one placeholder allowed there.

| Rule | Error |
|---|---|
| At most `maxOccurrences` = 64 positions (`scan.go`) | `endpoint "<id>": more than 64 positions` |
| `json`: the address is a JSON Pointer (RFC 6901), see [Address syntax](#address-syntax) | `endpoint "<id>": position "<addr>": invalid address` |
| `form`: the address is a decoded field name matching the [form key grammar](#form-key-grammar) and not ending in `[]` | `endpoint "<id>": position "<addr>": invalid address` |
| The value is exactly one vocabulary placeholder | `endpoint "<id>": position "<addr>": unknown placeholder` |
| `{{basic:NAME}}` is not allowed at a body position | `endpoint "<id>": position "<addr>": {{basic:}} is only allowed in headers` |
| At least one position holds `{{pan}}` | `endpoint "<id>": no {{pan}} position` |

At request time (`checkProxy`), the matching rules for positions are:

- every placeholder occurrence in the body must sit at a listed address and be exactly that address's placeholder;
- a body field present at a position address must hold its placeholder (a literal there, such as the platform's own API key, is refused);
- a field whose address differs from a position address only in letter case is refused;
- each card placeholder kind occurs at most once (`{{exp_year}}` and `{{exp_year:yy}}` count as the same kind);
- positions other than the `{{pan}}` one are optional: the body may omit them.

Each of these failures is `400 invalid placeholder use` with `reason=placeholder`.

### Header templates

| Rule | Error |
|---|---|
| Header name matches `^[A-Za-z][A-Za-z0-9-]{0,63}$` (`catHeaderNameRe`) | `endpoint "<id>": invalid header name "<name>"` |
| The canonical name (`http.CanonicalHeaderKey`) is not reserved (list below) | `endpoint "<id>": header "<Name>": vault-owned or platform header` |
| No two names are equal after canonicalization | `endpoint "<id>": duplicate header "<Name>"` |
| The template holds no card placeholder | `endpoint "<id>": header "<Name>": card placeholder in header` |
| The template is 1–1024 bytes of printable ASCII (0x20–0x7E) holding exactly one `{{secret:NAME}}`, `{{basic:NAME}}` or `{{signature}}` and no other `{` or `}` (`parseHeaderTemplate`) | `endpoint "<id>": header "<Name>": template must hold exactly one {{secret:NAME}}, {{basic:NAME}} or {{signature}} in printable ASCII` |

Reserved header names (`catReservedHeaders`): `Host`, `Content-Type`, `Content-Length`, `User-Agent`, `Transfer-Encoding`, `Connection`, `Keep-Alive`, `Proxy-Authorization`, `Proxy-Connection`, `Te`, `Trailer`, `Upgrade`, `Content-Encoding`, and the platform allowlist `Accept`, `Idempotency-Key`, `X-Idempotency-Key`.

Text around the placeholder is sent verbatim, for example `"Authorization": "Bearer {{secret:secretKey}}"` or `"Authorization": "Basic {{basic:secretKey}}"`. The vault renders and sets every template header on every request. The platform may include a template header in the envelope only with a value equal to the unrendered template text; it is then dropped. Any other value is refused (`400 header not allowed`, `reason=header`; `checkProxyHeaders` in `policy.go`).

### Pins

A pin is a body field that must be present and equal a required value. Pins are verified, never overwritten.

| Pin form | Required value | Comparison at request time |
|---|---|---|
| `{"account": "<valueName>"}` | The account's `values[<valueName>]` | The body field must be a string equal to that value. A JSON number never matches an account pin. |
| `{"literal": <scalar>}` | The literal | Kind and text must match: a string compares by decoded text; a number or bool by its raw JSON text (`3.50` does not match `3.5`). |

| Rule | Error |
|---|---|
| Address valid for the format; a `form` pin address may not end in `[]` | `endpoint "<id>": pin "<addr>": invalid address` |
| The address is not also a position | `endpoint "<id>": address "<addr>" appears in more than one of positions, pins and forbid` |
| Exactly one of `account` and `literal` (`"literal": null` counts as absent) | `endpoint "<id>": pin "<addr>": needs exactly one of account and literal` |
| `account` matches `[A-Za-z0-9_]{1,64}` | `endpoint "<id>": pin "<addr>": invalid account value name` |
| `literal` is a JSON string without `{{`, or (for `json` providers only) a number or bool; never `null`, an object or an array (`catLiteral`) | `endpoint "<id>": pin "<addr>": invalid literal` |

At request time, a pinned field that is missing, different, or accompanied by a case-variant field fails with `400 pinned field mismatch`, `reason=pin`.

### Forbid

A forbid entry names a field that must be absent, or equal one of the listed literals.

| Value | Meaning |
|---|---|
| `[]` | The field must be absent. |
| `[lit, …]` | The field may be absent or equal one of the literals (for example `[false]`). |

| Rule | Error |
|---|---|
| Address valid for the format (a `form` forbid address may end in `[]`) | `endpoint "<id>": forbid "<addr>": invalid address` |
| The address is not also a position or a pin | `endpoint "<id>": address "<addr>" appears in more than one of positions, pins and forbid` |
| The value is a JSON array | `endpoint "<id>": forbid "<addr>": must be a list of allowed literals` |
| Each element is a string without `{{`, or (for `json` providers only) a number, bool or `null` | `endpoint "<id>": forbid "<addr>": invalid literal` |

At request time (`checkProxy`), the request is refused with `400 forbidden field`, `reason=forbidden_field`, when the field is present with a value not in the list, when a case-variant of the address is present, when the field cannot be read as one value, or, for `form` providers, when any key starts with `<addr>[` in any letter case (`customer[x]`, `Customer[]`).

### Signers

| `signer` | Requirements | Error |
|---|---|---|
| absent or `""` | No `{{signature}}` in any position or header template | `endpoint "<id>": {{signature}} without signer` |
| `payu` | The provider's format is `json` | `endpoint "<id>": signer payu needs a json provider` |
| `payu` | At least one `{{signature}}` position or header template | `endpoint "<id>": signer without {{signature}} position or header` |
| anything else | – | `endpoint "<id>": unknown signer "<name>"` |

`payu` is the only signer in the code (`signPayU` in `render.go`). It returns the lowercase hex digest of

```text
hash(apiKey + "~" + merchantId + "~" + referenceCode + "~" + TX_VALUE.value + "~" + TX_VALUE.currency)
```

| Input | Source |
|---|---|
| `hash` | Account value `hash`: `md5`, `sha1` or `sha256` |
| `apiKey` | Account secret `apiKey` |
| `merchantId` | Account value `merchantId` |
| `referenceCode` | Body field `/transaction/order/referenceCode` |
| `TX_VALUE.value` | Body field `/transaction/order/additionalValues/TX_VALUE/value` |
| `TX_VALUE.currency` | Body field `/transaction/order/additionalValues/TX_VALUE/currency` |

The three body fields (`payuSignerInputs` in `policy.go`) are used exactly as written: a JSON string decoded, a JSON number as its raw text. `checkProxy` refuses the request (`400 invalid placeholder use`, `reason=placeholder`) when one is missing, is not a string or number, contains `{{`, or has a case-variant alias. Signers never take card data. No `payu` endpoint is in the shipped `catalog.json`; the signer is exercised by the synthetic test catalog.

## Address syntax

| Format | Address | Rules (`validCatAddress`) |
|---|---|---|
| `json` | JSON Pointer, RFC 6901 (`/paymentMethod/number`, `/payments/0/credit_card/card/number`) | Starts with `/`; at most 1024 bytes; valid UTF-8 without U+FFFD; `~` only as `~0` or `~1`; no empty token (`/a//b`); no control character; the whole-document pointer `""` is refused (`validJSONPointer`). |
| `form` | Decoded field name (`card[number]`) | Matches the form key grammar below (`validFormKey`). Positions and pins may not end in `[]`. |

### Form key grammar

```text
^[A-Za-z0-9_-]+(\[[A-Za-z0-9_-]+\])*(\[\])?$
```

A name of `[A-Za-z0-9_-]`, then zero or more non-empty `[segment]` groups of the same characters, then at most one trailing `[]`. The same grammar applies to `query` keys in the catalog and to every key of a `form` request body (`formFields` in `scan.go`).

| Key | Accepted | Why |
|---|---|---|
| `card[number]` | yes | Name plus one segment |
| `payment_method_data[card][exp_month]` | yes | Several segments |
| `expand[]` | yes | Trailing `[]` |
| `card-holder_1` | yes | `-` and `_` are name characters |
| `metadata[order.id]` | no | `.` is not allowed |
| `card.name` | no | `.` is not allowed |
| `a[]b` | no | `[]` only at the end |
| `a[][b]` | no | `[]` only at the end |
| `customer]` | no | Unbalanced bracket |
| `[customer` | no | Must start with a name |
| `a[b]c` | no | Text after a segment |
| `a[]` as a position or pin | no | Repeatable key, names no single value (allowed in `forbid` and `query`) |

## Placeholder vocabulary

The vocabulary is fixed in `parsePlaceholder` (`scan.go`). A placeholder is the whole `{{…}}` text, with no whitespace; `NAME` matches `[A-Za-z0-9_]{1,64}`. Nothing else is a placeholder.

| Placeholder | Kind | Body position | Header template | Path or query | Rendered value (`renderRequest`) |
|---|---|---|---|---|---|
| `{{pan}}` | card | yes | never | never | The stored card number: 13–19 digits, no separators |
| `{{cvv}}` | card | yes | never | never | The cached CVV (3–4 digits). None cached → `409 cvv unavailable` |
| `{{name}}` | card | yes | never | never | The stored cardholder name. Card stored without one → `409 name unavailable` |
| `{{exp_month}}` | card | yes | never | never | `MM`, two digits (`03`) |
| `{{exp_month:int}}` | card | yes | never | never | Month as an integer (`3`) |
| `{{exp_year}}` | card | yes | never | never | `YYYY` (`2030`) |
| `{{exp_year:yy}}` | card | yes | never | never | Last two digits (`30`) |
| `{{exp_year:int}}` | card | yes | never | never | Year as an integer (`2030`) |
| `{{exp:yyyy/mm}}` | card | yes | never | never | `YYYY/MM` (`2030/03`) |
| `{{exp:mm/yy}}` | card | yes | never | never | `MM/YY` (`03/30`) |
| `{{secret:NAME}}` | credential | yes | yes | never | The account secret `NAME`, as stored |
| `{{basic:NAME}}` | credential | never (parse error) | yes | never | `base64(secret + ":")`, standard encoding with padding |
| `{{signature}}` | credential | yes | yes | never | The endpoint signer's output (`payu`: lowercase hex digest) |

Encoding of the rendered value at a body position (`encodeValue` in `scan.go`):

| Format | Encoding |
|---|---|
| `json` | The occurrence in the body must be exactly `"{{…}}"` (quotes included, no escapes). It is replaced by a JSON string, except `:int` forms, which are replaced by a bare JSON number (`"{{exp_month:int}}"` becomes `3`). |
| `form` | The raw value must be exactly `{{…}}` (not percent-encoded), and not under a key ending in `[]`. It is replaced by `url.QueryEscape(value)`; `:int` forms give canonical digits without a leading zero. `/` in the `exp:` forms becomes `%2F`; a space in a name becomes `+`. |

In a header template the placeholder text is replaced once, and the rest of the template is kept. Every secret value must be printable non-space ASCII (`validSecretValue` in `main.go`), checked at boot and again at render time.

Everything outside a placeholder occurrence is sent byte for byte as the platform wrote it (`substitute` in `scan.go`). A `{{` is never sent literally. In the body, any `{{` that is not an occurrence at a listed position is refused with `400 invalid placeholder use`. In a platform header value it is `400 header not allowed` (`checkProxyHeaders`); in the path or query it is `400 endpoint not allowed` (`matchEndpoint`, `validProxyQuery`).

## Accounts

| Key | Required | Rule | Error (prefix `catalog: account "<a>": `) |
|---|---|---|---|
| account name (map key) | yes | `^[a-z0-9_]{1,64}$` | `invalid name` |
| `env` | yes | `dev` or `prod` | `env must be dev or prod` |
| `provider` | yes | Name of a provider in `providers` | `unknown provider "<p>"` |
| `host` | yes | See [Host rules](#host-rules) | `invalid host` |
| `base_path` | no | `""`, or a path of literal segments (no wildcards), starting with `/`, without a trailing `/` | `invalid base_path` |
| `secrets` | no | Object, secret name → Secret Manager resource | `invalid secret name "<s>"` / `secret "<s>": invalid Secret Manager resource name` |
| `values` | no | Object, value name → value | `invalid value name "<v>"` / `value "<v>": invalid` |

| Field | Rule |
|---|---|
| Secret name, value name | `[A-Za-z0-9_]{1,64}` (`validSecretName`) |
| Secret Manager resource | `^projects/[A-Za-z0-9_-]+/secrets/[A-Za-z0-9_-]+$` (`secretNameRe` in `main.go`); the vault reads `<resource>/versions/latest:access` (`accessSecret` in `gcp.go`) |
| Value | 1–256 bytes of printable ASCII (0x20–0x7E) without `{{` (`validCatValue`). Values are identifiers (merchant accounts, account IDs, hash names) compared with body fields and fed to signers. |

Cross-checks between an account and its provider's endpoints:

| Rule | Error (prefix `catalog: account "<a>": `) |
|---|---|
| Every `{{secret:NAME}}` and `{{basic:NAME}}` in any endpoint's headers or positions names a key of `secrets` | `endpoint "<id>": missing secret "<NAME>"` |
| Every account pin names a key of `values` | `endpoint "<id>": missing value "<name>"` |
| If any endpoint uses `signer: payu`: secret `apiKey`, value `merchantId`, and value `hash` equal to `md5`, `sha1` or `sha256` (lower case) | `payu needs secret apiKey, value merchantId and hash md5, sha1 or sha256` |

### Host rules

`validCatHost`:

- matches `^[a-z0-9.-]+(:[0-9]{1,5})?$` (`catHostRe`): lower case DNS name or IPv4 address, optional port, no scheme, path or userinfo;
- name part at most 253 characters;
- each dot-separated label 1–63 characters, not starting or ending with `-`;
- port, if present, 1–65535.

### How the account shapes the outgoing URL

`accountURL` (`render.go`) builds `https://<host><base_path><request path>[?query]`. The scheme is always `https`; the host is exactly the account's `host`, checked on the built URL and on a reparse of its string form. The platform never chooses the host, base path, secrets or values. Details of the egress checks are in [Limits](../reference/limits.md) and [Proxy design](../explanation/proxy-design.md).

## Dev secret variables

In dev, an account secret can come from an environment variable instead of Secret Manager. `devSecretVar` (`main.go`) names it:

```text
VAULT_DEV_SECRET_<ACCOUNT>_<NAME>
```

uppercased, with every character outside `[A-Z0-9]` replaced by `_`.

| Account | Secret name | Variable |
|---|---|---|
| `stripe_test` | `secretKey` | `VAULT_DEV_SECRET_STRIPE_TEST_SECRETKEY` |

| Rule | Where | Error |
|---|---|---|
| No two secrets of any accounts, in any environment, map to the same variable (`a_b`/`c` and `a`/`b_c`, or `apiKey` and `APIKEY`) | `parseCatalog` | `catalog: account "<a>" secret "<s>" and account "<b>" secret "<t>" share dev variable <VAR>` |
| In dev, every `VAULT_DEV_*` variable is one of the fixed dev variables (`VAULT_DEV_DEK_HEX`, `VAULT_DEV_SESSION_HMAC_HEX`, `VAULT_DEV_RECEIPT_KEY_HEX`) or the variable of a secret of a loaded account, even when empty | `checkDevSecretVars` | `<VAR> is not a dev variable or the dev variable of a dev catalog account secret` |
| A non-empty account variable holds printable ASCII without whitespace. An empty one is accepted and treated as unset: the secret then comes from Secret Manager | `checkDevSecretVars`, `loadAccountSecrets` | `account <a> secret <s>: <VAR> must be non-empty printable ASCII without whitespace` |
| In prod, any `VAULT_DEV_*` variable refuses boot | `devVarSet`, `main` | `<VAR> is refused when VAULT_ENV=prod` |
| Every secret of every loaded account loads (dev: the variable when set, otherwise Secret Manager; prod: Secret Manager only) | `loadAccountSecrets` | `account <a> secret <s>: <reason>` |

There is no `VAULT_STRIPE_SECRET` or `VAULT_DEV_STRIPE_SECRET` variable. All environment variables are listed in [Configuration](../reference/configuration.md).

## Egress host files

`egress-hosts.dev.txt` and `egress-hosts.prod.txt` list the hosts of that environment's accounts, one per line, without ports. The infra repo's firewall check diffs against them. `TestEgressHostsMatchCatalog` (`catalog_test.go`) parses the embedded catalog for each environment and requires the sorted, non-blank lines of the file to equal the sorted set of account hosts with any `:port` removed.

| File | Current content |
|---|---|
| `egress-hosts.dev.txt` | `api.stripe.com` |
| `egress-hosts.prod.txt` | empty |

## Worked example: the shipped `catalog.json`

The embedded catalog holds one provider, one endpoint and one dev account.

```json
{
  "providers": {
    "stripe": {
      "format": "form",
      "endpoints": [
        {
          "id": "tokens",
          "method": "POST",
          "path": "/v1/tokens",
          "card_data": true,
          "headers": {
            "Authorization": "Bearer {{secret:secretKey}}"
          },
          "positions": {
            "card[number]": "{{pan}}",
            "card[exp_month]": "{{exp_month}}",
            "card[exp_year]": "{{exp_year}}",
            "card[cvc]": "{{cvv}}",
            "card[name]": "{{name}}"
          },
          "forbid": {
            "customer": []
          }
        }
      ]
    }
  },
  "accounts": {
    "stripe_test": {
      "provider": "stripe",
      "env": "dev",
      "host": "api.stripe.com",
      "base_path": "",
      "secrets": {
        "secretKey": "projects/pci-cde-dev/secrets/stripe-test-secret-key"
      },
      "values": {}
    }
  }
}
```

| Line(s) | Text | Meaning |
|---|---|---|
| 2–3 | `"providers"`, `"stripe"` | One provider named `stripe`. |
| 4 | `"format": "form"` | Request bodies are `application/x-www-form-urlencoded`; addresses are decoded form keys. |
| 7 | `"id": "tokens"` | Endpoint id, used in `ALERT proxy_policy … endpoint=tokens`. |
| 8–9 | `"method": "POST"`, `"path": "/v1/tokens"` | The only request this provider accepts: `POST /v1/tokens`, no wildcard, no query (no `query` key). |
| 10 | `"card_data": true` | Required on every endpoint. |
| 11–13 | `"Authorization": "Bearer {{secret:secretKey}}"` | The vault sets `Authorization: Bearer <account secret secretKey>`. The platform may send this header only as the unrendered template. |
| 15 | `"card[number]": "{{pan}}"` | The required `{{pan}}` position. |
| 16–17 | `{{exp_month}}`, `{{exp_year}}` | `MM` and `YYYY`. |
| 18 | `"card[cvc]": "{{cvv}}"` | Optional; needs a cached CVV, else `409 cvv unavailable`. |
| 19 | `"card[name]": "{{name}}"` | Optional; needs a stored name, else `409 name unavailable`. |
| 21–23 | `"forbid": {"customer": []}` | `customer` must be absent, and so must any key starting with `customer[` in any case. |
| 28–29 | `"accounts"`, `"stripe_test"` | One account. |
| 30 | `"provider": "stripe"` | Uses the rules above. |
| 31 | `"env": "dev"` | Loaded only when `VAULT_ENV=dev`. There is no prod account (`TestEmbeddedCatalogProdAccounts` asserts zero), so a prod boot fails with `catalog has no accounts for env=prod` (the refusal is tested by `TestBootRefusesEmptyAccountSet`). |
| 32 | `"host": "api.stripe.com"` | Requests go to `https://api.stripe.com`. Listed in `egress-hosts.dev.txt`. |
| 33 | `"base_path": ""` | Nothing is prepended to the path. |
| 34–36 | `"secretKey": "projects/pci-cde-dev/secrets/stripe-test-secret-key"` | Secret Manager resource of `{{secret:secretKey}}`. Dev variable: `VAULT_DEV_SECRET_STRIPE_TEST_SECRETKEY`. |
| 37 | `"values": {}` | No pins or signer, so no values. |

The example envelope in `embeddedFixtures` (`catalog_test.go`, body `embeddedTokensBody` in `helpers_test.go`):

```json
{
  "account": "stripe_test",
  "token": "tok_…",
  "request": {
    "method": "POST",
    "path": "/v1/tokens",
    "headers": {"Idempotency-Key": "ord-1", "Authorization": "Bearer {{secret:secretKey}}"},
    "body": "card[number]={{pan}}&card[exp_month]={{exp_month}}&card[exp_year]={{exp_year}}&card[cvc]={{cvv}}&card[name]={{name}}"
  }
}
```

For a card `4242 4242 4242 4242`, expiry `12/2030`, name `JANE Q DOE`, the vault sends:

```http
POST /v1/tokens HTTP/1.1
Host: api.stripe.com
Authorization: Bearer <secret secretKey>
Idempotency-Key: ord-1
Content-Type: application/x-www-form-urlencoded
User-Agent: pan-vault/1

card[number]=4242424242424242&card[exp_month]=12&card[exp_year]=2030&card[cvc]=<cached CVV>&card[name]=JANE+Q+DOE
```

Only the five placeholder values change; the keys stay exactly as the platform wrote them. The headers shown are the ones `renderRequest` sets or copies; the Go transport adds `Content-Length` (from the body) and requests gzip itself (`Accept-Encoding` is deliberately not set by the vault). The full `/proxy` contract is in [API reference](../reference/api.md).

## Tests

### Fixtures

| Fixture | File | Content |
|---|---|---|
| `testCatalogJSON` | `helpers_test.go` | Synthetic catalog the proxy tests run against. Providers: `stripe` (form: `payment_intents`, `tokens`, `confirm_payment_intent` with a `{id}` wildcard and `query: ["expand[]"]`), `adyen` (json, `X-API-Key` header, account pin `/merchantAccount`, forbid with literal `[false]`), `mercadopago` (json, `:int` expiry, Bearer), `payu` (json, body credential `{{secret:apiKey}}`, literal and account pins, `signer: payu`, `{{exp:yyyy/mm}}`), `pagarme` (json, `Basic {{basic:secretKey}}`, array-index positions). Accounts: `stripe_t`, `adyen_br`, `mp_ar`, `payu_co`, `pagarme_br` (dev) and `adyen_br_live` (prod). Every host is `upstream.test`, which `testCatalog` replaces with the host under test. |
| `embeddedFixtures` | `catalog_test.go` | At least one example envelope per endpoint of the embedded catalog, keyed `provider/endpoint`. Today: `stripe/tokens`. |
| `catalogMutations()` | `catalog_test.go` | One mutation of `testCatalogJSON` per parse rule, each with the error substring it must produce. |

### What each test checks

| Test | File | Checks |
|---|---|---|
| `TestParseCatalogValid` | `catalog_test.go` | `testCatalogJSON` decodes: dev and prod account sets, all five providers kept in both, and the decoded shape of each modelled endpoint (positions, headers, pins, forbid, signer, wildcard path, query keys). |
| `TestParseCatalogRejects` | `catalog_test.go` | Every entry of `catalogMutations()` is rejected with an error containing its expected text, and no error contains `projects/` or `sk_test`; `parseCatalog` refuses the environments `""`, `staging`, `Dev`, `PROD`. |
| `TestParseCatEndpointPositionCap` | `catalog_test.go` | For both formats, 64 positions are accepted and 65 fail with `more than 64 positions`. |
| `TestEmbeddedCatalog` | `catalog_test.go` | The embedded catalog parses for dev and prod; Stripe is `form` with exactly one endpoint, `POST /v1/tokens`, `card[number]` = `{{pan}}`; `forbid` is exactly `customer: []`; every endpoint is `card_data` with a `{{pan}}` position; `stripe_test` has host `api.stripe.com` and the expected secret resource; every endpoint has an `embeddedFixtures` entry; every fixture passes `checkProxy` and matches its endpoint; for `form` providers, each fixture with a forbidden field appended is refused as `forbidden field`. |
| `TestEmbeddedCatalogProdAccounts` | `catalog_test.go` | The embedded catalog has no prod account. The test is to be changed to require at least one when the first reviewed prod account lands. |
| `TestEgressHostsMatchCatalog` | `catalog_test.go` | `egress-hosts.<env>.txt` equals the account hosts of that environment (see above). |
| `FuzzParseCatalog` | `fuzz_test.go` | Seeds: `testCatalogJSON`, the embedded catalog and every mutation. For any input, an error returns no catalog; an accepted catalog has `card_data` and a `{{pan}}` position on every endpoint, and keeps only accounts of the requested environment with a known provider. |
| `TestDevSecretVar` | `boot_test.go` | `devSecretVar` naming, e.g. `stripe_test`/`secretKey` → `VAULT_DEV_SECRET_STRIPE_TEST_SECRETKEY`. |
| `TestCheckDevSecretVars` | `boot_test.go` | A dev boot refuses an unknown `VAULT_DEV_*` name and an invalid account secret value; prod is left to `devVarSet`. |
| `TestLoadAccountSecrets` | `boot_test.go` | Loading account secrets from dev variables and Secret Manager, all or nothing. |
| `TestBootCatalogFailsFast` | `boot_test.go` | Catalog and dev-variable failures exit 1 before the database, KMS or Secret Manager is touched; no value reaches stderr. |
| `TestBootRefusesEmptyAccountSet` | `boot_test.go` | A catalog with no account for the boot environment exits 1 right after parsing. |
| `TestProxyEmbeddedCardOnly` | `proxy_test.go` | With the embedded catalog, card-free `/v1/tokens` bodies, endpoints outside the catalog (`payment_methods`) and `customer` are refused with 400 and an alert, before `get_card`, with nothing sent. |
| `TestStripeMock` | `integration_test.go` | The embedded `stripe_test` requests against stripe-mock (`make stripe-mock-test`, needs `VAULT_TEST_STRIPE_MOCK_URL`). |
| `TestStripeLive` | `integration_test.go` | Tokenize with a name, then `/proxy` through the embedded `stripe_test` account against the real Stripe test-mode API, with a forged inbound `Authorization` header: `POST /v1/tokens` with the CVV, then again without it. Runs only when `VAULT_TEST_STRIPE_SECRET` holds an `sk_test_` key. |
| `TestProxyPayUSignature` | `proxy_test.go` | PayU end to end: the provider receives the body credential, the signature over the signer inputs (sha256 for `payu_co`) and the rest of the body unchanged. |
| `TestSignPayU` | `render_test.go` | `signPayU` for md5, sha1 and sha256 against PayU's documented example input. |
| `TestRenderJSONTyped` | `render_test.go` | `json` rendering: `{{pan}}` as a string, `:int` forms as bare numbers (`3`, `2030`). |
| `TestRenderExpiryFormats` | `render_test.go` | The rendered output of each expiry placeholder in `json` and `form`. |
| `TestRenderForm` | `render_test.go` | `form` rendering: each placeholder replaced in place (`{{exp_month}}` → `03`), the rest of the body and the query unchanged. |
| `TestRenderHeaders` | `render_test.go` | Header templates rendered and set (`{{secret:}}`, `{{basic:}}`), the platform's allowlisted headers copied, nothing else. |

## Request-time rejections caused by the catalog

All are status 400 and fire `ALERT proxy_policy account=<a> endpoint=<id|-> reason=<r>` (at most once per second, `alertPolicy` in `tokenize.go`), except where the reason is empty.

| `msg` constant | Body `error` | Reason | Cause |
|---|---|---|---|
| `msgInvalidToken` | `invalid token` | – (no alert) | Token does not match `^tok_[0-9a-f]{32}$` |
| `msgUnknownAccount` | `unknown account` | – (no alert) | Account not loaded for this environment |
| `msgEndpointNotAllowed` | `endpoint not allowed` | `endpoint` | No single endpoint matches method, path and query |
| `msgHeaderNotAllowed` | `header not allowed` | `header` | Header outside the allowlist; two names equal after canonicalization; a template header with another value; an allowlisted value that is empty, over 1024 bytes, not printable ASCII, or contains `{{` |
| `msgBadBody` | `invalid request body` | `body` | Body fails the strict parse, or a body on `GET`/`HEAD` |
| `msgPlaceholder` | `invalid placeholder use` | `placeholder` | Position rule broken, no `{{pan}}`, or a bad signer input |
| `msgPinMismatch` | `pinned field mismatch` | `pin` | Pin missing or different |
| `msgForbiddenField` | `forbidden field` | `forbidden_field` | Forbidden field present |

The complete list of `/proxy` responses is in [API reference](../reference/api.md); the alert lines are in [Logging](../reference/logging.md).

## See also

- [README §11.2 The provider catalog](../../README.md#112-the-provider-catalog-catalogjson) and [§6.5 The current catalog](../../README.md#65-the-current-catalog)
- [Add a provider](../how-to/add-a-provider.md)
- [Proxy design](../explanation/proxy-design.md)
- [API reference](../reference/api.md)
- [Configuration](../reference/configuration.md)
- [Limits](../reference/limits.md)
- [Logging](../reference/logging.md)
