# Performance

This page is for operators and engineers sizing PAN Vault or judging its limits. It records what has been measured and how, explains what dominates the cost of each endpoint and where the real ceilings are, gives sizing guidance, and describes how to repeat the measurements. It also says plainly what has not been measured.

## What was measured

The figures below were measured on 2026-10-31 on a development workstation: an Intel Core Ultra 7 155H (22 logical CPUs) with 16 GB of memory, under WSL2, against a local PostgreSQL 18 container. The vault ran in dev mode (`VAULT_ENV=dev`, with a dev DEK, so neither KMS nor Secret Manager was involved) from a release build made exactly as `make build` and the `Dockerfile` make it:

```
CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w -buildid=" -o vault .
```

### Size

| Artifact | Size |
|---|---|
| Binary `vault` (static, stripped) | 12,095,612 bytes |
| Image `pan-vault:local`, as stored | 4,671,312 bytes (three compressed layers: the CA bundle, `/etc/passwd`, the binary, on `FROM scratch`) |
| Image, unpacked | about 12.3 MB (the binary plus the CA bundle and `/etc/passwd`) |

### Memory and threads

Resident memory was read from `/proc/<pid>/status` (`VmRSS` for the current value, `VmHWM` for the peak).

| State | Resident memory |
|---|---|
| Idle, after boot | 12.5 MB |
| After 2,000 `/tokenize` calls at 32 concurrent clients | 24.5 MB |
| CVV cache full: 52,000 `/tokenize` calls with a CVV at 64 concurrent clients | 44 MB steady, 46.7 MB peak; `Threads: 27` at the end of the run |

During the CVV run the cache reached its 50,000-entry cap and the vault logged `ALERT cvv_cache_full` 7 times (counted with `grep -c` on the log; the alert is limited to one line per second). Comparing the last two rows gives an upper-bound estimate of what a full CVV cache costs: at most about 20 MB of resident memory, garbage-collector headroom included. The two runs differ in concurrency and in call count, so not all of the difference is the cache.

### Throughput

`/tokenize` sustained about 2,040 requests per second at 64 concurrent clients. For a closed-loop load generator, throughput ≈ concurrency ÷ mean client-observed latency, so each request took about 31 ms as the client saw it (64 ÷ 0.031 s ≈ 2,065 requests per second, consistent with the measurement).

The vault's own access log line (`req … dur=<n>ms`, written by `guard` in `vault.go`) showed 3–4 ms per request. That is the handler's duration, not request latency: its clock starts when the handler is called, so it excludes the TLS handshake and the connection handling that come before. The bound of the run was not isolated. Every `vault.put_card` call, including any wait for a pool slot, runs inside the handler and so inside `dur`; most of the ≈31 ms was therefore spent outside the handler (TLS, the single-process load generator on the same host, CPU contention between them), and the database was not shown to be the bottleneck.

`/proxy` was not load-tested: there is no provider on the loopback to send to.

## What dominates each path

### `/tokenize`

| Step | Cost |
|---|---|
| TLS 1.3 on the public listener | A full handshake for each new connection; little per request on a reused connection. |
| Session token check | One HMAC-SHA256 over a short string. |
| Strict parsing | A body of at most 4 KiB (`maxPublicBody`), decoded and key-checked more than once (`exactKeys`, the null checks). |
| Sealing | One AES-256-GCM seal of a short JSON record. |
| `vault.put_card` | One database round trip: two inserts and a commit. |
| Receipt | One Ed25519 signature over a signed input of at most 1,010 bytes (`rcpt.v1.` plus the base64url payload, a JSON payload of about 750 bytes); the whole receipt is at most 1,097 bytes. |

Apart from the handshake on a new connection, every step but the database call is CPU work on small inputs. The database round trip is the one step inside the handler that waits; in the measured run the whole handler, database call included, took 3–4 ms.

### `/proxy`

| Step | Cost |
|---|---|
| mTLS on the internal listener | As above, plus verifying the client certificate on each new connection. |
| Strict parsing and `checkProxy` | CPU only, no network and no database, over a body of at most 64 KiB (`maxInternalBody`). |
| `vault.get_card` | Serialized across every session and every instance by `pg_advisory_xact_lock`; inside the lock, two counts over `access_log` (using its `at` and `(token, at)` indexes), one insert and one select. |
| Key refresh (rare) | Only when the card's key version is missing from the snapshot: a `list_deks` call and a KMS decrypt per new version, within a 30-second budget, at most once every 10 seconds. |
| Unseal and render | CPU only. |
| Provider round trip | A TLS connection to the provider (reused across calls, up to 16 idle connections per host), the provider's own processing, and reading a response of at most 4 MiB. |

The provider round trip is expected to dominate wall-clock time (not measured, see below); the advisory lock decides how many lookups the database can serve, and the velocity limits decide how many it will.

## The effective ceilings

| Ceiling | Value | Source | Effect |
|---|---|---|---|
| Global lookup velocity | 300 lookups per minute | `schema.sql`, `get_card` | The real ceiling on `/proxy`: 5 per second on average, shared by every instance. Over it, `429` and `ALERT velocity`. |
| Per-token lookup velocity | 20 per hour | `schema.sql`, `get_card` | Bounds retries for one card. |
| Serialized lookups | one `get_card` at a time | the advisory lock | At a few milliseconds each, far above 300 per minute, so the velocity limit binds first. A lookup refused for velocity still queues for the lock. |
| Database pool | 16 open connections per instance | `openDB` | `put_card` and `get_card` share it; lookups waiting on the lock hold connections while they wait. |
| Database call deadline | 5 seconds, including the wait for a pool slot | `dbCallTimeout` | A saturated pool fails the request with `500` instead of holding it. |
| CVV cache | 50,000 live entries per instance | `cvvCacheMax` | Beyond it, cards are stored without a cached CVV; at most about 20 MB when full (estimate). |
| Provider response | 4 MiB per in-flight `/proxy` call | `maxProviderResponse` | A cap, not a preallocation: the buffer grows only to the response's actual size. |
| Outbound timeout | 30 seconds | `newOutboundClient` | Bounds a slow provider. |
| Listener write timeouts | public 30 s, internal 60 s | `newServers` | An on-demand key refresh followed by a slow provider can exceed the internal one. |

`access_log` grows with every `put` and `get`, and there is no retention or purge function yet (planned for v1.1, [README §10](../../README.md#10-known-limitations-and-what-comes-next)). The velocity counts read only recent rows through the `at` and `(token, at)` indexes, so their cost follows recent traffic rather than table size, but storage keeps growing.

## Sizing guidance

This is guidance derived from the measurements above, not a tested production configuration.

- **Memory.** The vault does not set `GOMEMLIMIT` or `GOGC`, so Go's garbage collector runs with its default target of letting the heap grow to about twice the live heap before collecting. The highest measured value, 46.7 MB with a full CVV cache, leaves wide room under a **128 MiB** limit per instance. The theoretical worst case is larger: many simultaneous `/proxy` calls each buffering a provider response near the 4 MiB cap. The global velocity limit (300 lookups per minute) bounds how many such calls can start; an instance that must survive a provider returning very large bodies needs more headroom than 128 MiB.
- **CPU likely matters more than memory.** This is reasoning, not a measurement: CPU use was not recorded. Memory stayed far below any sensible limit in every run, while every `/tokenize` does TLS, an AES-GCM seal and an Ed25519 signature, new connections pay a full TLS handshake, and most of the client-observed latency was spent outside the handler. Watch CPU when sizing for a checkout peak, and keep connections reused wherever the load balancer allows.
- **The database is the shared resource.** Both instances share one Cloud SQL instance, one advisory lock and one set of velocity counts. Adding vault instances does not raise the `/proxy` ceiling, and every `/tokenize` adds load to the same database.

## How to reproduce

These steps repeat the dev-mode measurements on a workstation. Nothing here is shipped in the repository; keep the load generator outside it.

### 1. Start PostgreSQL 18 and apply the schema

Follow the first half of the `itest` target in the `Makefile`, without running the tests:

```sh
docker run -d --name pan-vault-pg -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p 127.0.0.1:55432:5432 postgres:18
# wait until this succeeds
psql -q postgres://postgres@127.0.0.1:55432/postgres -c 'select 1'
psql -q -v ON_ERROR_STOP=1 postgres://postgres@127.0.0.1:55432/postgres \
  -c 'CREATE ROLE vault_owner LOGIN CREATEROLE;' -c 'CREATE DATABASE vault OWNER vault_owner;'
psql -q -v ON_ERROR_STOP=1 postgres://vault_owner@127.0.0.1:55432/vault -f schema.sql
```

Trust authentication is safe here only because the port is published on loopback.

### 2. Build and start the vault

Build with `make build`. The vault needs a server certificate and key for `localhost` and a CA certificate for `VAULT_CLIENT_CA` (exactly one PEM block, with `CA:TRUE`); the [local quickstart](../tutorials/local-quickstart.md) shows one way to create them. Then start it with:

| Variable | Value |
|---|---|
| `VAULT_ENV` | `dev` |
| `VAULT_CERT`, `VAULT_KEY`, `VAULT_CLIENT_CA` | paths to the PEM files |
| `VAULT_ALLOW_ORIGIN` | `https://checkout.example.com` |
| `VAULT_DB_URL` | `postgres://vault_app@127.0.0.1:55432/vault?sslmode=disable` (the role the service uses in production) |
| `VAULT_DEV_DEK_HEX` | `0000000000000000000000000000000000000000000000000000000000000000` |
| `VAULT_DEV_SESSION_HMAC_HEX` | `0000000000000000000000000000000000000000000000000000000000000001` |
| `VAULT_DEV_RECEIPT_KEY_HEX` | `0000000000000000000000000000000000000000000000000000000000000001` |
| `VAULT_DEV_SECRET_STRIPE_TEST_SECRETKEY` | `sk_test_placeholder` (boot requires every secret of the dev catalog account; no request reaches Stripe in this test) |

Wait for the `ready` line. Note the process ID and record the idle memory (step 4).

### 3. Generate load

Write a small load generator, in any language, that:

1. **Mints a session token** as the platform would: `v1.<exp>.<mac>`, where `exp` is a Unix time no more than 15 minutes ahead (for example now + 600 seconds) and `mac` is the lowercase hex HMAC-SHA256 of the ASCII string `v1.<exp>`, keyed with the **32 bytes** that `VAULT_DEV_SESSION_HMAC_HEX` decodes to (not the hex text). A token is not single use, so mint one and replace it before it expires. An `ALERT session_token_invalid` line in the vault's log means the token is wrong.
2. **Sends `POST https://127.0.0.1:8443/tokenize`** with exactly one `Origin: https://checkout.example.com`, `Authorization: Bearer <token>` and `Content-Type: application/json`, trusting the vault's server certificate, and a body such as `{"pan":"4242424242424242","exp_month":"12","exp_year":"2030","cvv":"123"}` (use any expiry that is not in the past).
3. **Runs a fixed number of requests over a fixed number of concurrent workers**, reusing connections, and records throughput, latency percentiles and the count of each status code. Every response should be `200`.

For the CVV-cache measurement, send more than 50,000 requests with a CVV within 15 minutes (the cache's time to live); the run above used 52,000 at 64 concurrent clients. Expect `ALERT cvv_cache_full` lines once the cap is reached.

### 4. Read memory

```sh
grep -E '^(VmRSS|VmHWM|Threads):' /proc/<pid>/status
```

`VmRSS` is the current resident memory, `VmHWM` the peak since the process started, and `Threads` the OS thread count. Read them idle after boot, after each run, and again a minute or two after the CVV run to see the steady value.

### 5. Clean up

Stop the vault and remove the container (`docker rm -f pan-vault-pg`). Every `/tokenize` call left a card row and an audit row behind.

## What has not been measured

- **The production path:** Cloud SQL over verified TLS with IAM database authentication, KMS unwrap at boot and during refresh, Secret Manager at boot, and the load balancers in front.
- **`/proxy` end to end**, including the advisory lock under concurrent load and a real provider round trip.
- **More than one instance**, and two instances sharing one database.
- **Long runs:** memory over hours, and the effect of a growing `access_log`.
- **CPU use** of the vault during any run.
- **Client-side latency percentiles:** only the mean, derived from concurrency and throughput, and the server-side `dur` are known.

## See also

- [Limits](../reference/limits.md): every bound and timeout in one table.
- [Design decisions](design-decisions.md): why the pool, the lock and the CVV cache are bounded as they are.
- [CVV lifecycle](cvv-lifecycle.md): what a full cache holds.
- [Deploy on GCP](../how-to/deploy-on-gcp.md).
