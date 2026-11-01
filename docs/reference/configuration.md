# Configuration

This page is for operators and developers who configure a vault instance. It lists every environment variable the binary reads, the `-rotate-dek` flag, each validation rule as written in `main.go`, the boot log line each phase produces, and the fixed timeouts and pool settings.

The vault reads configuration only from environment variables. There is no configuration file, and the catalog is compiled in (see [Catalog](catalog.md)). An empty variable counts as unset, except where a rule below says a variable is refused "even when empty".

## Modes

| Mode | Started with | Reads |
|---|---|---|
| serve | `vault` | Every variable below. |
| rotate | `vault -rotate-dek` | `VAULT_ENV`, `VAULT_DB_URL`, `VAULT_KMS_KEY`. In prod it also refuses boot when a `VAULT_DEV_*` variable is present (see [Dev and prod rules](#dev-and-prod-rules)). No certificate, catalog, secret or listener. |

`-rotate-dek` generates a 32-byte DEK, wraps it with KMS encrypt, checks that KMS decrypt returns the same bytes, stores it with `vault.add_dek`, prints the new version on standard output and exits 0. See [CLI and Make](cli-and-make.md#the-vault-binary).

## Environment variables

| Variable | serve | rotate | Default | Rule |
|---|---|---|---|---|
| `VAULT_ENV` | required | required | none | `dev` or `prod`. Also selects which catalog accounts load. |
| `VAULT_PUBLIC_ADDR` | optional | not read | `:8443` | Listen address of the public listener. |
| `VAULT_INTERNAL_ADDR` | optional | not read | `:9443` | Listen address of the internal listener. |
| `VAULT_CERT` | required | not read | none | Path to the server certificate (PEM). |
| `VAULT_KEY` | required | not read | none | Path to the server private key (PEM). |
| `VAULT_CLIENT_CA` | required | not read | none | Path to the CA for platform client certificates. See [Client CA file](#client-ca-file). |
| `VAULT_ALLOW_ORIGIN` | required | not read | none | Exact checkout origin. See [`VAULT_ALLOW_ORIGIN`](#vault_allow_origin). |
| `VAULT_DB_URL` | required | required | none | PostgreSQL URL. See [`VAULT_DB_URL`](#vault_db_url). |
| `VAULT_KMS_KEY` | required unless `VAULT_DEV_DEK_HEX` is set | required | none | Cloud KMS key name, `kmsKeyRe`. |
| `VAULT_SESSION_HMAC_SECRET` | required unless `VAULT_DEV_SESSION_HMAC_HEX` is set | not read | none | Secret Manager resource name, `secretNameRe`. |
| `VAULT_RECEIPT_KEY_SECRET` | required unless `VAULT_DEV_RECEIPT_KEY_HEX` is set | not read | none | Secret Manager resource name, `secretNameRe`. |
| `VAULT_DEV_DEK_HEX` | dev only | prod: refused if present; dev: not read | none | 64 hex characters (`decodeKey64`). |
| `VAULT_DEV_SESSION_HMAC_HEX` | dev only | prod: refused if present; dev: not read | none | 64 hex characters (`decodeKey64`). |
| `VAULT_DEV_RECEIPT_KEY_HEX` | dev only | prod: refused if present; dev: not read | none | 64 hex characters (`decodeKey64`). |
| `VAULT_DEV_SECRET_<ACCOUNT>_<NAME>` | dev only | prod: refused if present; dev: not read | none | A catalog account secret. See [Dev account secret variables](#dev-account-secret-variables). |

In prod every key comes from KMS or Secret Manager. In dev each key comes from its `VAULT_DEV_*` variable when that is set, otherwise from KMS or Secret Manager like prod.

Provider account secrets are not configured by variable names of their own. Each catalog account names its secrets by Secret Manager resource name, and every secret of every account of `VAULT_ENV` is loaded at boot (`loadAccountSecrets`, `main.go`). There is no `VAULT_STRIPE_SECRET` or `VAULT_DEV_STRIPE_SECRET`.

### Validation rules

| Name | Rule | Source |
|---|---|---|
| `kmsKeyRe` | `^projects/[A-Za-z0-9_-]+/locations/[A-Za-z0-9_-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+$` | `main.go` |
| `secretNameRe` | `^projects/[A-Za-z0-9_-]+/secrets/[A-Za-z0-9_-]+$` | `main.go` |
| `decodeKey64` | Exactly 64 characters that `hex.DecodeString` accepts (upper- or lowercase hex), giving 32 bytes. | `main.go` |
| Secret Manager payload for `VAULT_SESSION_HMAC_SECRET` and `VAULT_RECEIPT_KEY_SECRET` | Exactly 64 hex characters, nothing else (a trailing newline is refused). | `loadKey32`, `main.go` |
| Account secret value | Non-empty, every byte `0x21`–`0x7E` (printable ASCII, no whitespace). | `validSecretValue`, `main.go` |

### Parse errors

`loadConfig` (`main.go:67`–`main.go:159`) checks the environment in this order and returns the first error; `main` logs it as `boot failed: <error>`. Errors name the variable, never its value.

| # | Mode | Check | Error |
|---|---|---|---|
| 1 | both | `VAULT_ENV` is `dev` or `prod` | `VAULT_ENV must be dev or prod` |
| 2 | both, prod only | `VAULT_DEV_DEK_HEX`, `VAULT_DEV_SESSION_HMAC_HEX`, `VAULT_DEV_RECEIPT_KEY_HEX` unset or empty | `<NAME> is refused when VAULT_ENV=prod` |
| 3 | serve | `VAULT_CERT`, `VAULT_KEY`, `VAULT_CLIENT_CA`, `VAULT_ALLOW_ORIGIN` set, in that order | `VAULT_CERT is required`, `VAULT_KEY is required`, `VAULT_CLIENT_CA is required`, `VAULT_ALLOW_ORIGIN is required` |
| 4 | serve | `validOrigin` | `VAULT_ALLOW_ORIGIN must be an exact origin (scheme://host[:port], https in prod)` |
| 5 | both | `VAULT_DB_URL` set | `VAULT_DB_URL is required` |
| 6 | both | `VAULT_KMS_KEY`, if set, matches `kmsKeyRe` | `VAULT_KMS_KEY must be projects/P/locations/L/keyRings/R/cryptoKeys/K` |
| 7 | rotate | `VAULT_KMS_KEY` set (rotate mode stops checking here) | `VAULT_KMS_KEY is required for -rotate-dek` |
| 8 | serve | `VAULT_SESSION_HMAC_SECRET`, if set, matches `secretNameRe` | `VAULT_SESSION_HMAC_SECRET must be projects/P/secrets/S` |
| 9 | serve | `VAULT_RECEIPT_KEY_SECRET`, if set, matches `secretNameRe` | `VAULT_RECEIPT_KEY_SECRET must be projects/P/secrets/S` |
| 10 | serve | `VAULT_DEV_DEK_HEX`, if set, passes `decodeKey64`; otherwise `VAULT_KMS_KEY` is set | `VAULT_DEV_DEK_HEX must be exactly 64 hex chars` / `VAULT_KMS_KEY is required (or VAULT_DEV_DEK_HEX in dev)` |
| 11 | serve | `VAULT_DEV_SESSION_HMAC_HEX`, if set, passes `decodeKey64`; otherwise `VAULT_SESSION_HMAC_SECRET` is set | `VAULT_DEV_SESSION_HMAC_HEX must be exactly 64 hex chars` / `VAULT_SESSION_HMAC_SECRET is required (or VAULT_DEV_SESSION_HMAC_HEX in dev)` |
| 12 | serve | `VAULT_DEV_RECEIPT_KEY_HEX`, if set, passes `decodeKey64`; otherwise `VAULT_RECEIPT_KEY_SECRET` is set | `VAULT_DEV_RECEIPT_KEY_HEX must be exactly 64 hex chars` / `VAULT_RECEIPT_KEY_SECRET is required (or VAULT_DEV_RECEIPT_KEY_HEX in dev)` |

Later boot steps add these:

| Step | Check | Error |
|---|---|---|
| `main` (`main.go:700`–`main.go:702`), both modes, prod only | No variable named `VAULT_DEV_*` present, even empty | `<NAME> is refused when VAULT_ENV=prod` |
| `loadKey32` (`main.go:427`–`main.go:436`), serve, when the key comes from Secret Manager | The secret can be read | `<VAR>: secret manager: <fixed reason>` or `<VAR>: metadata token: <fixed reason>` |
| `loadKey32`, same | The payload is exactly 64 hex characters | `VAULT_SESSION_HMAC_SECRET: payload must be exactly 64 hex chars` / `VAULT_RECEIPT_KEY_SECRET: payload must be exactly 64 hex chars` |

Because KMS key and secret names are concatenated into request URLs, segments are limited to `[A-Za-z0-9_-]`. Domain-scoped project IDs such as `example.com:p` are not supported.

### `VAULT_ALLOW_ORIGIN`

`validOrigin` (`main.go`) accepts only a serialized origin that a browser could send byte-for-byte in its `Origin` header:

| Rule | Refused examples |
|---|---|
| `scheme://host[:port]` only: no userinfo, path, query or fragment | `https://checkout.example.com/`, `https://u@checkout.example.com`, `https://checkout.example.com?x` |
| Canonical form: lowercase scheme and host, and `url.Parse(s).String() == s` | `https://Checkout.example.com` |
| No empty port | `https://checkout.example.com:` |
| Port, if present: no leading zero, 1–65535, not the scheme default | `https://checkout.example.com:443`, `http://localhost:80`, `https://checkout.example.com:08443` |
| Scheme `https`; `http` only when `VAULT_ENV=dev` | `http://checkout.example.com` in prod, `*` |

Error: `VAULT_ALLOW_ORIGIN must be an exact origin (scheme://host[:port], https in prod)`.

### `VAULT_DB_URL`

`openDB` (`main.go`) applies these rules in order:

| # | Rule | Error |
|---|---|---|
| 1 | Starts with `postgres://` or `postgresql://`. The keyword/value form (`host=… dbname=…`) is refused. | `VAULT_DB_URL must be a postgres:// or postgresql:// URL` |
| 2 | `url.Parse` succeeds. | `VAULT_DB_URL cannot be parsed` |
| 3 | The query parses strictly with `url.ParseQuery` (for example, a `;` separator fails). | `VAULT_DB_URL cannot be parsed` |
| 4 | No query key `service`, `servicefile` or `passfile`, compared case-insensitively after percent-decoding. | `VAULT_DB_URL must not set service, servicefile or passfile` |
| 5 | `pgx.ParseConfig` succeeds. | `VAULT_DB_URL cannot be parsed` |
| 6 | prod only: the primary connection and every fallback have a TLS configuration that verifies the server certificate. | `VAULT_DB_URL must use sslmode=verify-ca or verify-full in prod` |

| `sslmode` in prod | Result |
|---|---|
| `verify-ca`, `verify-full` | accepted |
| `require` with `sslrootcert` | accepted (pgx verifies against the given root) |
| `require` without `sslrootcert`, `prefer`, `allow`, `disable`, or no `sslmode` | refused |

In dev the URL is used as given. In prod the password is replaced, before every new connection, by the service account's access token from the metadata server (Cloud SQL IAM authentication); the token is cached until 60 seconds before it expires (`tokenMargin`, `gcp.go`). Errors never contain the URL. The pool is capped at 16 open connections in both modes (`db.SetMaxOpenConns(16)`).

Accepted residue, documented in `openDB`: pgx's `PG*` environment fallbacks (`PGHOST`, `PGSERVICE`, …), which the deployment does not set, and its default `~/.pgpass` lookup when the URL has no password, which in the scratch image resolves to `/.pgpass`, a file that does not exist.

### Client CA file

`loadClientCA` (`main.go`) requires the file named by `VAULT_CLIENT_CA` to contain exactly one PEM block, of type `CERTIFICATE`, with no PEM headers, holding a certificate with `basicConstraints` CA:TRUE. A second PEM block of any type refuses boot.

| Failure | Boot error |
|---|---|
| Cannot read | `VAULT_CLIENT_CA: client CA: cannot read file` |
| First block missing, not `CERTIFICATE`, or with headers | `VAULT_CLIENT_CA: client CA: first PEM block is not a CERTIFICATE` |
| More than one block | `VAULT_CLIENT_CA: client CA: file must contain exactly one PEM block` |
| Does not parse | `VAULT_CLIENT_CA: client CA: certificate does not parse` |
| Not a CA | `VAULT_CLIENT_CA: client CA: certificate is not a CA` |

`VAULT_CERT` and `VAULT_KEY` are loaded with `tls.LoadX509KeyPair`; a failure is `VAULT_CERT/VAULT_KEY: cannot load key pair`.

## Dev and prod rules

| Rule | Where | Boot error |
|---|---|---|
| In prod, `VAULT_DEV_DEK_HEX`, `VAULT_DEV_SESSION_HMAC_HEX` or `VAULT_DEV_RECEIPT_KEY_HEX` set (non-empty), in serve and rotate mode | `loadConfig` | `<NAME> is refused when VAULT_ENV=prod` |
| In prod, any variable whose name starts with `VAULT_DEV_`, even when empty, in serve and rotate mode | `devVarSet`, `main` | `<NAME> is refused when VAULT_ENV=prod` |
| In dev, a `VAULT_DEV_*` name that is neither one of the three fixed dev variables nor the dev variable of a secret of a loaded (dev) account, even when empty | `checkDevSecretVars` | `<NAME> is not a dev variable or the dev variable of a dev catalog account secret` |
| In dev, a set account secret variable whose value fails `validSecretValue` | `checkDevSecretVars` | `account <a> secret <n>: <NAME> must be non-empty printable ASCII without whitespace` |
| Any secret of any loaded account missing or invalid (dev or prod) | `loadAccountSecrets` | `account <a> secret <n>: <reason>` |
| No catalog account for `VAULT_ENV` | `main` | `catalog has no accounts for env=<env>` |

`checkDevSecretVars` runs before the database is touched. Account secrets load all or nothing: on any failure no account receives any secret.

### Dev account secret variables

In dev, an account secret can come from an environment variable instead of Secret Manager. `devSecretVar` (`main.go`) derives its name:

1. Concatenate `VAULT_DEV_SECRET_` + account name + `_` + secret name.
2. Uppercase it.
3. Replace every character outside `[A-Z0-9]` with `_`.

| Account | Secret | Variable |
|---|---|---|
| `stripe_test` | `secretKey` | `VAULT_DEV_SECRET_STRIPE_TEST_SECRETKEY` |

The catalog parser refuses a catalog in which two account secrets, in any environment, derive the same variable. When the variable is unset or empty in dev, the secret is read from Secret Manager under the resource name the catalog gives. Prod never reads these variables.

## Boot sequence and log lines

Boot runs in this order (`main`, `main.go`). Every line is written through `logf` (see [Logging](logging.md)). A failure logs `boot failed: <reason>` and exits 1.

| Step | Phase | Success line | Notes |
|---|---|---|---|
| 1 | Parse environment (`loadConfig`), refuse `VAULT_DEV_*` in prod (`devVarSet`) | `config loaded env=<env>` | |
| 2 | serve: load `VAULT_CERT`/`VAULT_KEY` and `VAULT_CLIENT_CA` | none | Before any network call. |
| 3 | serve: parse the compiled-in catalog for `VAULT_ENV`, require at least one account, `checkDevSecretVars` | none | |
| 4 | Open the database pool (`openDB`) | none | Connects lazily. |
| 4r | rotate: `rotateDEK` | prints the version on standard output | Exits 0, or `boot failed: rotate: <reason>`. |
| 5 | serve: ping the database | none | Failure: `boot failed: database ping failed`. |
| 6 | Load DEKs: the dev DEK as version 1, or every `vault.list_deks` row unwrapped by KMS | `deks loaded versions=<v1,v2,…> current=<n>` | No DEK in the database logs `no DEKs found; run vault -rotate-dek first` (without the `boot failed:` prefix) and exits 1. |
| 7 | Load the session HMAC key and the receipt seed, then every account secret | `catalog loaded env=<env> accounts=<n>` | |
| 8 | Build the vault | `receipt public key=<base64url>` | Unpadded base64url of the Ed25519 public key. |
| 9 | Bind both listeners | `listening public=<addr> internal=<addr>` | Bind failure: `boot failed: VAULT_PUBLIC_ADDR: cannot listen` or `boot failed: VAULT_INTERNAL_ADDR: cannot listen`. |
| 10 | Serve | `ready` | |

Error reasons are built only from variable names, fixed phrases, status codes and SQLSTATEs; they never contain a value, a URL or a secret.

## Fixed settings

None of these is configurable at runtime; each is a compile-time constant or literal.

| Setting | Value | Source |
|---|---|---|
| Public listener `ReadHeaderTimeout` | 5 s | `main.go:650` |
| Public listener `ReadTimeout` | 10 s | `main.go:651` |
| Public listener `WriteTimeout` | 30 s | `main.go:652` |
| Public listener `IdleTimeout` | 60 s | `main.go:653` |
| Public listener `MaxHeaderBytes` | 16 KiB (`16 << 10`) | `main.go:654` |
| Internal listener `ReadHeaderTimeout` | 5 s | `main.go:666` |
| Internal listener `ReadTimeout` | 10 s | `main.go:667` |
| Internal listener `WriteTimeout` | 60 s | `main.go:668` |
| Internal listener `IdleTimeout` | 60 s | `main.go:669` |
| Internal listener `MaxHeaderBytes` | 16 KiB (`16 << 10`) | `main.go:670` |
| Listener TLS minimum | TLS 1.3 | `main.go:649`, `main.go:661` |
| Database pool size | 16 open connections | `main.go:279` |
| Per-request database call timeout (`dbCallTimeout`) | 5 s | `main.go:602` |
| Boot database ping (`bootDBTimeout`) | 5 s | `main.go:677` |
| Boot GCP phase: DEK load, secret load, account secret load, `-rotate-dek` (`bootGCPTimeout`, each phase) | 60 s | `main.go:678` |
| Shutdown drain of both listeners (`shutdownTimeout`) | 20 s | `main.go:679` |
| `/healthz` ping (`healthzTimeout`) | 2 s | `proxy.go:19` |
| Outbound client overall timeout | 30 s | `outbound.go:66` |

The complete list of limits is in [Limits](limits.md).

## See also

- [Limits](limits.md)
- [Logging](logging.md)
- [CLI and Make](cli-and-make.md)
- [Catalog](catalog.md)
- [Deploy on GCP](../how-to/deploy-on-gcp.md) and [Rotate keys](../how-to/rotate-keys.md)
- README: [Configuration (environment only)](../../README.md#111-configuration-environment-only)
