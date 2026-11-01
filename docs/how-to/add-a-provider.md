# Add a provider, endpoint or account

This guide is for an engineer adding a payment provider, an endpoint or an account to the vault. Each of these is a data-only change to `catalog.json` plus its review evidence: no Go code changes. It walks through the catalog pull request step by step, using the Stripe entry that ships in `catalog.json` as the running example. The complete schema is in the [catalog reference](../reference/catalog.md).

`catalog.json` is compiled into the binary (`go:embed` in `catalog.go`) and validated by `parseCatalog` at boot and in the tests. Nothing can change it at runtime, so every change ships as a new image.

## 1. Decide whether the endpoint qualifies

Answer these questions from the provider's own documentation before writing anything. Keep the links: the pull request needs them.

1. **Does it carry the card?** Every catalog endpoint must have `"card_data": true` and a `{{pan}}` position, and the parser refuses anything else. Calls without card data (payments with a provider token, refunds, queries) are the platform's, made with its own keys. They never go through the vault.
2. **Does it charge the card, or create a single-use hand-off token?** Only those two kinds qualify. Stripe's `POST /v1/tokens` creates a single-use `tok_…`, so it qualifies.
3. **Could it store the card at the provider?** If the endpoint creates something reusable or attachable, it doesn't qualify. Stripe's `POST /v1/payment_methods` is not in the catalog for this reason: a card PaymentMethod is reusable and can be attached to a customer.
4. **Could it send data to a URL the caller chooses?** If so, it doesn't qualify.
5. **Which card-saving or reuse flags does it accept?** List every one: save, attach, customer, recurring, setup-for-future-use and the like. Each needs a `forbid` entry (step 4). For Stripe's tokens endpoint that is `customer` (Connect: a token cloned from a customer's saved card).
6. **Can its request be expressed with the rule format?** The body must be `json` or `form`, every card value must fill a whole field, and any signature must come from an existing signer (today only `payu`). If the provider needs a new body format, signer or placeholder, stop: that is a code change with its own design review, not a catalog change.

## 2. Check every form key

For a `form` provider, list every field name the platform will send, not only the placeholder fields. Each must match the form-key grammar (`validFormKey` in `scan.go`):

```
^[A-Za-z0-9_-]+(\[[A-Za-z0-9_-]+\])*(\[\])?$
```

No `.` anywhere, and `[]` only at the end. `card[number]` and `expand[]` pass. `metadata[order.id]` and `items[][price]` fail. A body with a failing key is refused as `invalid request body`. If the provider requires such a key, the endpoint can't be used.

## 3. Write the provider entry

Skip this step when you only add an endpoint or an account to an existing provider.

```json
"providers": {
  "stripe": {
    "format": "form",
    "endpoints": [ … ]
  }
}
```

| Field | Rule (`parseCatProvider`) |
|---|---|
| name (the key) | `[a-z0-9_]{1,64}`. Provider names appear in boot-failure messages; endpoint ids and account names also appear in `ALERT` lines, so all three use a restricted alphabet. |
| `format` | `json` (addresses are JSON Pointers, RFC 6901) or `form` (addresses are decoded field names). One format per provider. |
| `endpoints` | At least one. No two share an `id`, and no two with the same method have overlapping paths. |

Every key in the catalog is spelled exactly. Unknown keys, keys in another letter case and duplicate keys are refused.

## 4. Write the endpoint entry

The Stripe endpoint:

```json
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
```

Field by field (`parseCatEndpoint` in `catalog.go`):

| Field | Required | Rule |
|---|---|---|
| `id` | yes | `[a-z0-9_]{1,64}`, unique within the provider. Logged as `endpoint=<id>` in `ALERT` lines. |
| `method` | yes | `GET`, `POST`, `PUT`, `PATCH` or `DELETE`, uppercase. Use a method with a body: a `GET` request must have an empty body, so it can never carry `{{pan}}`. |
| `path` | yes | Starts with `/`, at most 1024 bytes. Each segment is literal (`[A-Za-z0-9._~-]`, not `.` or `..`) or a wildcard `{name}` (`name` is `[A-Za-z0-9_]{1,64}`, each at most once), which matches 1–128 characters of `[A-Za-z0-9_-]` in a request. No `%`, no query, no trailing `/`. |
| `query` | no | List of allowed query keys, each matching the form-key grammar, no repeats. Omit it and the endpoint accepts no query. |
| `card_data` | yes | Must be `true`. |
| `headers` | no | Credential header templates (below). |
| `positions` | yes | Body address → the one placeholder allowed there (below). Must include a `{{pan}}` position. At most 64. |
| `pins` | no | Body address → the value that field must hold (below). |
| `forbid` | no | Body address → the literals that field may hold; `[]` means it must be absent (below). |
| `signer` | no | Omit, or `payu` (below). |

### Header templates

A template sets a credential header that the vault renders itself. The platform may send the exact template string or leave the header out. Any other value is refused.

- The name matches `^[A-Za-z][A-Za-z0-9-]{0,63}$` and is canonicalized (`X-API-Key` becomes `X-Api-Key`). Two names that canonicalize to the same one are refused.
- The name may not be one the vault sets, a transfer or hop-by-hop header, or a platform-allowlisted header: `Host`, `Content-Type`, `Content-Length`, `User-Agent`, `Transfer-Encoding`, `Connection`, `Keep-Alive`, `Proxy-Authorization`, `Proxy-Connection`, `Te`, `Trailer`, `Upgrade`, `Content-Encoding`, `Accept`, `Idempotency-Key`, `X-Idempotency-Key`.
- The value is 1–1024 bytes of printable ASCII holding exactly one `{{secret:NAME}}`, `{{basic:NAME}}` or `{{signature}}`, and no other `{` or `}`. Text around it is allowed: `Bearer {{secret:secretKey}}`, `Basic {{basic:secretKey}}`, `{{secret:apiKey}}`. A card placeholder in a header is refused.

### Positions

Each entry maps one body address to one placeholder.

- **Addresses.** For `json`, a JSON Pointer naming a field: `/paymentMethod/number`, or `/payments/0/credit_card/card/number` for an array element. Not `""`, no empty token, `~` only as `~0` or `~1`. For `form`, a field name matching the form-key grammar and not ending in `[]` (a repeatable key names no single value): `card[number]`.
- **Placeholders.** Any of `{{pan}}`, `{{cvv}}`, `{{name}}`, `{{exp_month}}`, `{{exp_month:int}}`, `{{exp_year}}`, `{{exp_year:yy}}`, `{{exp_year:int}}`, `{{exp:yyyy/mm}}`, `{{exp:mm/yy}}`, `{{secret:NAME}}` and `{{signature}}`. `{{basic:NAME}}` is header-only. Pick the expiry form the provider documents: `:int` sends a JSON number, `:yy` two digits.
- A body credential, such as PayU's `/merchant/apiKey` in the synthetic test catalog (`testCatalogJSON` in `helpers_test.go`), is a position holding `{{secret:apiKey}}`. The platform must then send exactly that placeholder there, never a value of its own.

### Pins

A pin is a field the platform must send with exactly one value. Use it for account-selecting fields (a merchant account, an account ID) and for fixed values.

```json
"pins": {
  "/merchantAccount": {"account": "merchantAccount"},
  "/command": {"literal": "SUBMIT_TRANSACTION"}
}
```

- Each pin has exactly one of `account` (the name of a value in the account's `values`) or `literal` (a JSON scalar).
- A `form` provider accepts only string literals. A `json` provider accepts strings, numbers and booleans, not `null`. A string literal may not contain `{{`.
- A pin address can't also be a position or a forbid address, and in a `form` provider it can't end in `[]`.

These examples come from the synthetic test catalog (`testCatalogJSON` in `helpers_test.go`). The shipped Stripe endpoint has no pins.

### Forbid

Each card-saving or reuse flag from step 1 gets a `forbid` entry. The value is the list of literals the field may hold:

- `[]`: the field must be absent. Stripe's `"customer": []`.
- `[false]`: absent, or exactly `false`. The test catalog's Adyen `"/storePaymentMethod": [false]`.

A `json` provider's list may include `null`. A `form` provider's list may hold only strings. In a `form` body, forbidding `customer` also refuses every key that starts with `customer[`, in any letter case. A forbid address can't also be a position or a pin.

### Signer

`signer` names Go code that computes `{{signature}}`. Today the only one is `payu`. It needs a `json` provider and a `{{signature}}` position or header, and the account needs the secret `apiKey`, the value `merchantId` and the value `hash` (`md5`, `sha1` or `sha256`). A `{{signature}}` without a signer is refused. A new signer is a code change.

## 5. Write the account entry

```json
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
```

| Field | Rule (`parseCatAccount`) |
|---|---|
| name (the key) | `[a-z0-9_]{1,64}`. This is what the platform puts in the envelope's `account`. |
| `provider` | An existing provider name. |
| `env` | `dev` or `prod`. A vault loads only the accounts of its `VAULT_ENV`. |
| `host` | Lowercase DNS name or IPv4 address, optional `:port`. Labels of 1–63 characters, not starting or ending with `-`, at most 253 characters in all. |
| `base_path` | Optional; omitted means `""`. Otherwise literal segments such as `/checkout`: no wildcards, no trailing `/`. The URL is `https://` + host + base path + request path. |
| `secrets` | Optional when no endpoint of the provider uses a secret. Secret name (`[A-Za-z0-9_]{1,64}`) → Secret Manager resource `projects/P/secrets/S`. Every `{{secret:NAME}}` and `{{basic:NAME}}` used by any endpoint of the provider must be listed. |
| `values` | Optional when no pin or signer needs one. Value name (`[A-Za-z0-9_]{1,64}`) → 1–256 bytes of printable ASCII without `{{`. Non-secret identifiers used by pins and signers. Every pin's `account` value must be listed. |

Every account in every environment is validated, whichever environment the vault runs in.

**Dev secret variables.** Each secret of each account has a local stand-in variable, `VAULT_DEV_SECRET_<ACCOUNT>_<NAME>`: account and secret name uppercased, every character outside `[A-Z0-9]` replaced by `_` (`devSecretVar` in `main.go`). `stripe_test` / `secretKey` becomes `VAULT_DEV_SECRET_STRIPE_TEST_SECRETKEY`. The parser refuses two account secrets that map to the same variable, across all environments. The variable is read only when `VAULT_ENV=dev`. A dev boot refuses an unknown `VAULT_DEV_*` name, a prod boot refuses any `VAULT_DEV_*` variable, and every boot fails if a secret of a loaded account is missing.

**The first prod account.** `TestEmbeddedCatalogProdAccounts` in `catalog_test.go` pins the prod account set at zero today, because a prod boot is refused until a reviewed prod account exists (`catalog has no accounts for env=prod`). The pull request that adds the first prod account changes that test to require at least one.

## 6. Update the egress host list

`egress-hosts.dev.txt` and `egress-hosts.prod.txt` list exactly the hosts of that environment's accounts, one per line, without ports. Today `egress-hosts.dev.txt` holds `api.stripe.com` and `egress-hosts.prod.txt` is empty. `TestEgressHostsMatchCatalog` fails when a file and the catalog disagree.

Change the matching egress firewall rule in the infra repository in the same release: it must allow only that provider's published IP ranges for the environment.

## 7. Add an example request to `embeddedFixtures`

`TestEmbeddedCatalog` fails for any endpoint of the embedded catalog without an example request in `embeddedFixtures` (`catalog_test.go`), keyed `"<provider>/<endpoint id>"`. The Stripe entry:

```go
var embeddedFixtures = map[string]*proxyEnvelope{
	"stripe/tokens": newEnvelope("stripe_test", "POST", "/v1/tokens",
		map[string]string{"Idempotency-Key": "ord-1", "Authorization": "Bearer {{secret:secretKey}}"}, embeddedTokensBody),
}
```

Its body is the constant `embeddedTokensBody` in `helpers_test.go`:

```
card[number]={{pan}}&card[exp_month]={{exp_month}}&card[exp_year]={{exp_year}}&card[cvc]={{cvv}}&card[name]={{name}}
```

Write the fixture the way the platform will send the request. The test checks that it passes `checkProxy` for the named account and matches the intended endpoint. For a `form` provider it also appends each `forbid` field to the body and expects `forbidden field`. The test parses the dev catalog, so the fixture's account must be a dev account: add a provider's sandbox account before, or together with, its prod account.

Run the catalog tests:

```sh
go test -count=1 -run 'TestEmbeddedCatalog|TestEgressHostsMatchCatalog' .
```

```
ok  	pan-vault	0.092s
```

The time varies.

## 8. Add a `testCatalogJSON` fixture for a new shape

The synthetic catalog `testCatalogJSON` in `helpers_test.go` models every rule shape the proxy tests exercise: Stripe (form, wildcard path, query key), Adyen (account pin, forbid list, `X-API-Key` header), Mercado Pago (`:int` expiry), PayU (body credential, account and literal pins, the `payu` signer, `yyyy/mm` expiry) and Pagar.me (Basic auth header, array positions).

If your change introduces a shape none of these has (a new pin kind, placeholder modifier or header template form, for example), add an endpoint or account using it to `testCatalogJSON`, and extend the tests that use it. Keep each endpoint's and account's identifying fields on one line, as the existing entries do: the tests mutate them with string replacements.

## 9. Create the account secrets

Create each new account secret in Secret Manager, in the account's environment project, under exactly the resource name the catalog gives. The value must be printable ASCII without whitespace, with no trailing newline, or the vault refuses to boot. The vault reads the latest version (`accessSecret` in `gcp.go`). Pipe the value in with `printf '%s'`, which adds no newline, rather than writing it to a file. For example:

```sh
gcloud secrets create stripe-test-secret-key --project=pci-cde-dev
printf '%s' "$KEY" | gcloud secrets versions add stripe-test-secret-key --project=pci-cde-dev --data-file=-
```

The vault's service account must be able to read it. See [Deploy on Google Cloud](deploy-on-gcp.md).

## 10. Verify against the provider's sandbox

Send the fixture request through a vault to the provider's sandbox, and confirm the documented success response. Two ways exist today:

- **A mock in CI**, when the provider publishes one. Stripe's endpoint runs against the official `stripe-mock` in `TestStripeMock` (`make stripe-mock-test`), and against Stripe's test mode in `TestStripeLive` when `VAULT_TEST_STRIPE_SECRET` holds an `sk_test_…` key.
- **A local dev vault** built from your branch: follow the [local quickstart](../tutorials/local-quickstart.md) with the sandbox account in `catalog.json`, put the sandbox key in the account's `VAULT_DEV_SECRET_…` variable, and send the fixture through `/proxy`.

Collect, for each endpoint, the provider's documented success and error responses. The vault masks only this card's own number, as plain digits or in groups of four separated by spaces or hyphens. Everything else a provider returns, such as a name or an error message, reaches the platform unchanged. A documented response field beyond brand, last four, expiry and cardholder name needs explicit sign-off in the pull request.

## 11. Record the review notes

Add an entry to the "Catalog review notes" section of `CLAUDE.md`, next to the Stripe one: the provider and account names, the endpoints, how and when each was verified, the documented success and error responses, and anything deliberately left out of the catalog, with the reason.

## 12. Open the pull request

Use this description, with every box checked and every item filled in:

```markdown
## Catalog change: <provider> / <endpoint ids> / <accounts>

- [ ] Provider documentation showing that each `card_data` endpoint charges, or creates a single-use
      hand-off token, and never stores the card at the provider: <links>
- [ ] Card-saving and reuse flags the endpoint accepts, and the `forbid` entry covering each:
      | Flag | `forbid` entry |
      |---|---|
      | <flag> | `"<address>": []` |
- [ ] Every form key checked against `^[A-Za-z0-9_-]+(\[[A-Za-z0-9_-]+\])*(\[\])?$` (no `.`, `[]` only at the end)
- [ ] `egress-hosts.<env>.txt` updated; infra egress firewall rule: <link>
- [ ] `embeddedFixtures` example for every new endpoint (`TestEmbeddedCatalog`)
- [ ] `testCatalogJSON` fixture and tests for any new shape, or "no new shape"
- [ ] Secret Manager secrets created: <resource names>
- [ ] Sandbox verification recorded in the "Catalog review notes" of `CLAUDE.md`, with the documented
      success and error responses
- [ ] Response fields beyond brand, last four, expiry and cardholder name: <none, or list with sign-off>
```

Then run `make ci` before asking for review.

## See also

- [Catalog reference](../reference/catalog.md)
- [Integrate the platform](integrate-the-platform.md)
- [Why the proxy works this way](../explanation/proxy-design.md)
- [README §11.2: The provider catalog](../../README.md#112-the-provider-catalog-catalogjson)
- [README §7.4: hand-off tokens](../../README.md#74-what-the-vault-cannot-enforce-hand-off-tokens)
