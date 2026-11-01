# Run the vault locally

This lesson is for a developer who has cloned the repository and wants to see the vault work. In about twenty minutes you will build the binary, give it a throwaway Postgres 18 database, start it in dev mode, tokenize a test card, verify the signed receipt, call `/healthz` over mTLS, and read every log line the vault wrote.

Everything runs on your machine. Nothing here uses Google Cloud, and nothing is sent to a payment provider.

## What you need

| Tool | Used for |
|---|---|
| Go 1.27.3 | Building the vault and the receipt checker. Inside the repository any recent `go` downloads 1.27.3 by itself (`go.mod` sets `toolchain go1.27.3`). The receipt checker in step 9 lives outside the repository and builds with the `go` on your `PATH`; it uses only the standard library. |
| Docker | A throwaway `postgres:18` container |
| `psql` | Creating the database and applying `schema.sql` |
| OpenSSL 3 | A local CA, the server certificate, a client certificate, and the session token's HMAC |
| `curl` | Calling the vault |

You will use two terminals: **terminal 1** for your commands and **terminal 2** for the running vault. Run every command from the repository root unless a step says otherwise.

## 1. Build the binary

In terminal 1:

```sh
make build
```

Expected output:

```
CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w -buildid=" -o vault .
```

You now have a static binary `./vault`. It has one flag:

```sh
./vault -h
```

```
Usage of ./vault:
  -rotate-dek
    	generate, wrap and store a new DEK, print its version, and exit
```

You won't need `-rotate-dek` here: it talks to Cloud KMS, and dev mode uses a fixed data key instead.

## 2. Start Postgres 18

Pick a free port. This lesson uses `55433`, which leaves the `make itest` default (`55432`) free. The container uses trust authentication, so it is published on loopback only.

```sh
docker run -d --name pan-vault-quickstart-pg \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p 127.0.0.1:55433:5432 postgres:18
```

Docker prints the container ID. Wait until Postgres answers:

```sh
until psql -q postgres://postgres@127.0.0.1:55433/postgres -c 'select 1' >/dev/null 2>&1; do sleep 1; done
```

The command returns once the database is ready.

## 3. Create the database and apply the schema

This is the same bootstrap `make itest` performs. `vault_owner` owns the database and applies `schema.sql`. The schema creates the two login roles the software uses: `vault_app` (the running vault) and `vault_rotator` (the key rotation job).

```sh
psql -v ON_ERROR_STOP=1 postgres://postgres@127.0.0.1:55433/postgres \
  -c 'CREATE ROLE vault_owner LOGIN CREATEROLE;' \
  -c 'CREATE DATABASE vault OWNER vault_owner;'
psql -q -v ON_ERROR_STOP=1 postgres://vault_owner@127.0.0.1:55433/vault -f schema.sql
```

Expected output: `CREATE ROLE` and `CREATE DATABASE` from the first command. The second prints nothing when it succeeds (`-q`).

The vault connects as `vault_app`, which may only execute the vault's functions. See it for yourself:

```sh
psql postgres://vault_app@127.0.0.1:55433/vault -c 'SELECT count(*) FROM vault.cards;'
```

```
ERROR:  permission denied for table cards
```

That refusal is the point: the vault's own database role can't read the card table. It can only call `vault.put_card`, `vault.get_card` and `vault.list_deks`.

## 4. Create the certificates

The vault serves TLS 1.3 on both listeners, and the internal listener demands a client certificate signed by one pinned CA (`VAULT_CLIENT_CA`). Make a working directory outside the repository, so no key can be committed by accident:

```sh
export QS="$HOME/pan-vault-quickstart"
mkdir -p "$QS"
```

Create a CA, a server certificate for `localhost` and `127.0.0.1`, and a client certificate for the "platform". The server step uses process substitution (`<(…)`), so run these commands in bash or zsh:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$QS/ca.key" -out "$QS/ca.crt" -days 7 -subj "/CN=pan-vault-quickstart-ca"

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$QS/server.key" -out "$QS/server.csr" -subj "/CN=localhost"
openssl x509 -req -in "$QS/server.csr" -CA "$QS/ca.crt" -CAkey "$QS/ca.key" -CAcreateserial \
  -days 7 -out "$QS/server.crt" \
  -extfile <(printf 'subjectAltName=DNS:localhost,IP:127.0.0.1')

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$QS/client.key" -out "$QS/client.csr" -subj "/CN=platform"
openssl x509 -req -in "$QS/client.csr" -CA "$QS/ca.crt" -CAkey "$QS/ca.key" -CAcreateserial \
  -days 7 -out "$QS/client.crt"
```

Expected output: a `-----` line from each `openssl req`, and from each signing step:

```
Certificate request self-signature ok
subject=CN = localhost
```

(then `subject=CN = platform` for the client). The vault checks the CA file at boot: it must hold exactly one PEM block, a certificate with `CA:TRUE`. Confirm:

```sh
openssl x509 -in "$QS/ca.crt" -noout -ext basicConstraints
```

```
X509v3 Basic Constraints: critical
    CA:TRUE
```

Note the client certificate's serial number. The vault logs it as the caller of every internal request:

```sh
openssl x509 -in "$QS/client.crt" -noout -serial
```

```
serial=4C3C10DB78DA7AFE57F0796C43F8EB42253BC1F2
```

Yours will differ.

## 5. Write the dev environment

The vault reads its configuration only from environment variables (`loadConfig` in `main.go`). With `VAULT_ENV=dev`, three fixed `VAULT_DEV_*` variables stand in for Cloud KMS and Secret Manager, and each secret of a dev catalog account has its own `VAULT_DEV_SECRET_<ACCOUNT>_<NAME>` variable. The only dev account in `catalog.json` is `stripe_test`, with one secret, `secretKey`.

```sh
cat > "$QS/env.sh" <<EOF
export VAULT_ENV=dev
export VAULT_DB_URL='postgres://vault_app@127.0.0.1:55433/vault?sslmode=disable'
export VAULT_CERT=$QS/server.crt
export VAULT_KEY=$QS/server.key
export VAULT_CLIENT_CA=$QS/ca.crt
export VAULT_ALLOW_ORIGIN=http://localhost:3000
export VAULT_PUBLIC_ADDR=127.0.0.1:18443
export VAULT_INTERNAL_ADDR=127.0.0.1:19443
export VAULT_DEV_DEK_HEX=0000000000000000000000000000000000000000000000000000000000000001
export VAULT_DEV_SESSION_HMAC_HEX=0000000000000000000000000000000000000000000000000000000000000002
export VAULT_DEV_RECEIPT_KEY_HEX=0000000000000000000000000000000000000000000000000000000000000003
export VAULT_DEV_SECRET_STRIPE_TEST_SECRETKEY=sk_test_placeholder
EOF
```

What each line does:

| Variable | Here | Why |
|---|---|---|
| `VAULT_ENV` | `dev` | Allows the `VAULT_DEV_*` variables, plain `http://` origins and an unverified database connection. Selects the catalog's `dev` accounts. |
| `VAULT_DB_URL` | `vault_app` on loopback, `sslmode=disable` | Dev only. With `VAULT_ENV=prod` the vault refuses a URL that doesn't verify the server certificate. |
| `VAULT_CERT`, `VAULT_KEY` | the server certificate | Used by both listeners. |
| `VAULT_CLIENT_CA` | the CA | The one CA whose certificates may call the internal listener. |
| `VAULT_ALLOW_ORIGIN` | `http://localhost:3000` | The exact origin of the checkout page. `/tokenize` compares the `Origin` header to it byte for byte. |
| `VAULT_PUBLIC_ADDR`, `VAULT_INTERNAL_ADDR` | `127.0.0.1:18443`, `127.0.0.1:19443` | Loopback only. The defaults are `:8443` and `:9443`. |
| `VAULT_DEV_DEK_HEX` | 64 hex characters | The data key, version 1. Used instead of KMS-wrapped keys from the database. |
| `VAULT_DEV_SESSION_HMAC_HEX` | 64 hex characters | The session token key the platform shares with the vault. |
| `VAULT_DEV_RECEIPT_KEY_HEX` | 64 hex characters | The seed of the Ed25519 key that signs receipts. |
| `VAULT_DEV_SECRET_STRIPE_TEST_SECRETKEY` | `sk_test_placeholder` | Account `stripe_test`, secret `secretKey`. Required: boot fails if any secret of a loaded account is missing. |

These hex values are public test values. Never use them outside your machine.

## 6. Start the vault

In terminal 2, from the repository root:

```sh
export QS="$HOME/pan-vault-quickstart"
. "$QS/env.sh"
./vault 2>&1 | tee "$QS/vault.log"
```

Expected output (your timestamps will differ; they are always UTC):

```
2026-11-01T02:09:29Z config loaded env=dev
2026-11-01T02:09:29Z deks loaded versions=1 current=1
2026-11-01T02:09:29Z catalog loaded env=dev accounts=1
2026-11-01T02:09:29Z receipt public key=84FibkHnAn6kMb_jAJ6UvdJadGvuxGiUjWw8fF3JpUs
2026-11-01T02:09:29Z listening public=127.0.0.1:18443 internal=127.0.0.1:19443
2026-11-01T02:09:29Z ready
```

The receipt public key is derived from `VAULT_DEV_RECEIPT_KEY_HEX`, so with the seed above it is always `84FibkHnAn6kMb_jAJ6UvdJadGvuxGiUjWw8fF3JpUs`. You will use it in step 9.

If the vault prints `boot failed: …` instead, it exits with status 1. The reason names a variable, never a value:

| Output | Cause |
|---|---|
| `boot failed: database ping failed` | Postgres isn't running, or the port in `VAULT_DB_URL` is wrong. |
| `boot failed: VAULT_DEV_SECRET_STRIPE_TEST_SECRET_KEY is not a dev variable or the dev variable of a dev catalog account secret` | A misspelt `VAULT_DEV_*` variable (here an extra `_`). Any unknown `VAULT_DEV_*` name refuses a dev boot. |
| `boot failed: account stripe_test secret secretKey: metadata token: request failed` | `VAULT_DEV_SECRET_STRIPE_TEST_SECRETKEY` is unset, so the vault tried Secret Manager. |
| `boot failed: VAULT_CERT/VAULT_KEY: cannot load key pair` | A wrong certificate or key path. |

Leave the vault running in terminal 2.

## 7. Mint a session token

`/tokenize` only accepts a request carrying a session token that the platform minted for the checkout. The token is `v1.<expires_unix>.<hex HMAC-SHA256(key, "v1." + expires_unix)>`, and the expiry must be in the future and at most 15 minutes ahead (`checkSession` in `tokenize.go`).

In terminal 1, mint one that expires in 10 minutes, with the dev session key:

```sh
. "$QS/env.sh"
EXP=$(( $(date +%s) + 600 ))
MAC=$(printf 'v1.%s' "$EXP" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$VAULT_DEV_SESSION_HMAC_HEX | awk '{print $NF}')
SESSION="v1.$EXP.$MAC"
echo "$SESSION"
```

Expected output, with your own expiry and MAC:

```
v1.1793499587.1ebe4cc500ff926d7e81b00c0951a031335f6e8c60a680885f9a210a51fb6ec2
```

If a later step answers `{"error":"unauthorized"}`, the token has expired: run this step again.

## 8. Tokenize a test card

Send the Stripe test card `4242 4242 4242 4242`, as a browser on `http://localhost:3000` would:

```sh
curl -sS --cacert "$QS/ca.crt" https://localhost:18443/tokenize \
  -H 'Origin: http://localhost:3000' \
  -H "Authorization: Bearer $SESSION" \
  -H 'Content-Type: application/json' \
  -d '{"pan":"4242 4242 4242 4242","exp_month":"12","exp_year":"2030","cvv":"123","name":"JANE Q DOE"}' \
  | tee "$QS/tok.json"
```

Expected output (one line; your token, receipt and signature will differ):

```json
{"token":"tok_074b92aa3654d6d6f4cc2b21644b245e","last4":"4242","exp_month":"12","exp_year":"2030","receipt":"rcpt.v1.eyJ0b2tlbiI6InRva18wNzRiOTJhYTM2NTRkNmQ2ZjRjYzJiMjE2NDRiMjQ1ZSIsImJpbiI6IjQyNDI0MjQyIiwibGFzdDQiOiI0MjQyIiwiZXhwX21vbnRoIjoiMTIiLCJleHBfeWVhciI6IjIwMzAiLCJuYW1lIjoiSkFORSBRIERPRSIsImlhdCI6MTc5MzQ5ODk4N30.bFpcgWhFK0UGaeVRhTV2yAgwd3Kp6-pbBcv_fTpT_wHfLZt5qKaeEHnnK9UPKsX1NBtSlXXTog072yXpmVCuCw"}
```

The response has exactly five fields: `token`, `last4`, `exp_month`, `exp_year` and `receipt`. The card number was stored encrypted. The CVV `123` was not stored: it is held in this vault process's memory, usable once by `/proxy` within 15 minutes. The BIN and the name are not top-level fields. They are only inside the signed receipt.

Keep the token and receipt in shell variables:

```sh
TOKEN=$(sed -E 's/.*"token":"([^"]+)".*/\1/' "$QS/tok.json")
RECEIPT=$(sed -E 's/.*"receipt":"([^"]+)".*/\1/' "$QS/tok.json")
```

Now break the request a few ways and watch the vault refuse it. Each error body is one fixed string, and none echoes your input.

A failing Luhn check (last digit changed):

```sh
curl -sS --cacert "$QS/ca.crt" https://localhost:18443/tokenize \
  -H 'Origin: http://localhost:3000' -H "Authorization: Bearer $SESSION" -H 'Content-Type: application/json' \
  -d '{"pan":"4242424242424241","exp_month":"12","exp_year":"2030"}'
```

```json
{"error":"invalid pan"}
```

An origin other than `VAULT_ALLOW_ORIGIN`:

```sh
curl -sS --cacert "$QS/ca.crt" https://localhost:18443/tokenize \
  -H 'Origin: http://evil.test' -H "Authorization: Bearer $SESSION" -H 'Content-Type: application/json' \
  -d '{"pan":"4242424242424242","exp_month":"12","exp_year":"2030"}'
```

```json
{"error":"origin not allowed"}
```

A session token with a wrong MAC:

```sh
curl -sS --cacert "$QS/ca.crt" https://localhost:18443/tokenize \
  -H 'Origin: http://localhost:3000' \
  -H "Authorization: Bearer v1.$EXP.0000000000000000000000000000000000000000000000000000000000000000" \
  -H 'Content-Type: application/json' -d '{}'
```

```json
{"error":"unauthorized"}
```

A query string, on any endpoint:

```sh
curl -sS --cacert "$QS/ca.crt" 'https://localhost:18443/tokenize?pan=1' \
  -H 'Origin: http://localhost:3000' -H "Authorization: Bearer $SESSION" -H 'Content-Type: application/json' -d '{}'
```

```json
{"error":"query string not allowed"}
```

## 9. Verify the receipt

The platform must not trust the browser's word about the card. It trusts the receipt, after checking the vault's signature with the public key from the boot log. Build a small checker around the reference verifier published in the README ([§11.4 Verifying a receipt](../../README.md#114-verifying-a-receipt)).

Create a module outside the repository and extract the README's Go block into it unchanged:

````sh
REPO=$PWD
mkdir -p "$QS/verify/receipt" && cd "$QS/verify"
go mod init receiptcheck
awk '/^#### 11.4 /{s=1} s && /^```go$/{c=1; next} c && /^```$/{exit} c' \
  "$REPO/README.md" > receipt/receipt.go
head -1 receipt/receipt.go
````

The `awk` program copies the first Go block under the README's "11.4" heading. Expected output:

```
go: creating new go.mod: module receiptcheck
go: to add module requirements and sums:
	go mod tidy
package receipt
```

Add a `main.go` that calls it:

```sh
cat > main.go <<'EOF'
// Command receiptcheck verifies a vault receipt: receiptcheck <public key> <token> <receipt>.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"receiptcheck/receipt"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: receiptcheck <public key> <token> <receipt>")
		os.Exit(2)
	}
	pub, err := base64.RawURLEncoding.DecodeString(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "public key is not unpadded base64url")
		os.Exit(1)
	}
	r, err := receipt.Verify(ed25519.PublicKey(pub), os.Args[3])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if r.Token != os.Args[2] {
		fmt.Fprintln(os.Stderr, "receipt is for another token")
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(out))
}
EOF
```

Run it with the public key, the token the browser sent, and the receipt:

```sh
go run . 84FibkHnAn6kMb_jAJ6UvdJadGvuxGiUjWw8fF3JpUs "$TOKEN" "$RECEIPT"
```

Expected output:

```json
{
  "token": "tok_074b92aa3654d6d6f4cc2b21644b245e",
  "bin": "42424242",
  "last4": "4242",
  "exp_month": "12",
  "exp_year": "2030",
  "name": "JANE Q DOE",
  "iat": 1793498987
}
```

`bin` has 8 digits because the card number has 16. For any other length the vault puts 6 digits in the receipt (`cardBIN` in `receipt.go`). `iat` is when the vault signed it, in Unix seconds.

Now check that the verifier refuses what it should. A receipt presented with another token:

```sh
go run . 84FibkHnAn6kMb_jAJ6UvdJadGvuxGiUjWw8fF3JpUs tok_00000000000000000000000000000000 "$RECEIPT"
```

```
receipt is for another token
exit status 1
```

A receipt whose payload was altered after signing. Every payload starts with `{"token":`, so its base64url part always starts with `eyJ0`; changing that `0` to `1` changes the signed bytes:

```sh
go run . 84FibkHnAn6kMb_jAJ6UvdJadGvuxGiUjWw8fF3JpUs "$TOKEN" "${RECEIPT/rcpt.v1.eyJ0/rcpt.v1.eyJ1}"
```

```
invalid receipt
exit status 1
```

Go back to the repository root:

```sh
cd "$REPO"
```

## 10. Call `/healthz` over mTLS

The internal listener serves `/proxy` and `/healthz`, and refuses any connection without a client certificate from `VAULT_CLIENT_CA`. Call `/healthz` with the platform certificate:

```sh
curl -sS --cacert "$QS/ca.crt" --cert "$QS/client.crt" --key "$QS/client.key" \
  https://localhost:19443/healthz
```

```json
{"status":"ok"}
```

`/healthz` answers 200 when the database answers a ping within 2 seconds, and `503 {"error":"unavailable"}` otherwise. Now try without the certificate:

```sh
curl -sS --cacert "$QS/ca.crt" https://localhost:19443/healthz
```

```
curl: (56) OpenSSL SSL_read: OpenSSL/3.0.13: error:0A00045C:SSL routines::tlsv13 alert certificate required, errno 0
```

The TLS handshake fails before any HTTP request exists, so the vault never sees a request and writes no log line for it.

## 11. See the catalog refuse a provider request

You can't complete a `/proxy` call locally. The only account in the compiled-in catalog, `stripe_test`, sends to `api.stripe.com`, so a request that passed every check would go to the real Stripe API with the stand-in key `sk_test_placeholder`. The request shape is checked instead against Stripe's official mock by `make stripe-mock-test`.

What you can see locally is the catalog check, which runs before the database or the network is touched. Ask the vault to send a Stripe token request with your own credential header:

```sh
curl -sS --cacert "$QS/ca.crt" --cert "$QS/client.crt" --key "$QS/client.key" \
  https://localhost:19443/proxy -H 'Content-Type: application/json' \
  -d "{\"account\":\"stripe_test\",\"token\":\"$TOKEN\",\"request\":{\"method\":\"POST\",\"path\":\"/v1/tokens\",\"headers\":{\"Authorization\":\"Bearer sk_attacker\"},\"body\":\"card[number]={{pan}}&card[exp_month]={{exp_month}}&card[exp_year]={{exp_year}}\"}}"
```

```json
{"error":"header not allowed"}
```

A credential header must be exactly the catalog's template (`Bearer {{secret:secretKey}}`), and the vault fills in its own secret. Now ask for an endpoint the catalog doesn't list:

```sh
curl -sS --cacert "$QS/ca.crt" --cert "$QS/client.crt" --key "$QS/client.key" \
  https://localhost:19443/proxy -H 'Content-Type: application/json' \
  -d "{\"account\":\"stripe_test\",\"token\":\"$TOKEN\",\"request\":{\"method\":\"POST\",\"path\":\"/v1/payment_methods\",\"headers\":{},\"body\":\"type=card&card[number]={{pan}}\"}}"
```

```json
{"error":"endpoint not allowed"}
```

## 12. Read the log

Look at what the vault wrote in terminal 2, or in the copy:

```sh
cat "$QS/vault.log"
```

After the boot lines you will see lines like these:

```
2026-11-01T02:09:47Z req listener=public method=POST path=/tokenize status=200 dur=11ms
2026-11-01T02:09:57Z req listener=public method=POST path=/tokenize status=400 dur=0ms
2026-11-01T02:09:57Z req listener=public method=POST path=/tokenize status=403 dur=0ms
2026-11-01T02:09:57Z ALERT session_token_invalid reason=hmac
2026-11-01T02:09:57Z req listener=public method=POST path=/tokenize status=401 dur=0ms
2026-11-01T02:09:57Z req listener=public method=POST path=/tokenize status=400 dur=0ms
2026-11-01T02:10:30Z req listener=internal method=GET path=/healthz status=200 dur=2ms caller=4C3C10DB78DA7AFE57F0796C43F8EB42253BC1F2
2026-11-01T02:10:30Z ALERT proxy_policy account=stripe_test endpoint=tokens reason=header
2026-11-01T02:10:30Z req listener=internal method=POST path=/proxy status=400 dur=0ms caller=4C3C10DB78DA7AFE57F0796C43F8EB42253BC1F2
2026-11-01T02:10:31Z ALERT proxy_policy account=stripe_test endpoint=- reason=endpoint
2026-11-01T02:10:31Z req listener=internal method=POST path=/proxy status=400 dur=0ms caller=4C3C10DB78DA7AFE57F0796C43F8EB42253BC1F2
```

How to read them:

- **Boot lines** (`config loaded`, `deks loaded`, `catalog loaded`, `receipt public key`, `listening`, `ready`) appear once, in that order. `deks loaded versions=1 current=1` is the dev data key.
- **`req` lines** are the access log: exactly one per request, written by `guard` in `vault.go`. They carry the listener, method, path, status and duration. On the internal listener they add `caller=`, the client certificate's serial in the form `openssl x509 -serial` prints, which you noted in step 4. A path other than `/tokenize`, `/proxy` or `/healthz` is logged as `path=other`, so text typed into a URL never reaches the log.
- **`ALERT` lines** are the lines that page someone in production. `session_token_invalid reason=hmac` came from the forged session token. `proxy_policy` names the account and endpoint as the catalog spells them (`-` when no endpoint matched) and a fixed reason. Session and policy alerts are each written at most once per second, so a burst of refusals produces fewer `ALERT` lines than `req` lines.

Nothing else is ever logged: no card number, CVV, name, receipt, header or body. Search the log for the card number to confirm:

```sh
grep -c 4242424242424242 "$QS/vault.log"
```

```
0
```

## 13. Clean up

Stop the vault with Ctrl-C in terminal 2. It drains both listeners and exits with status 0. Then remove the database container and the working directory:

```sh
docker rm -f pan-vault-quickstart-pg
rm -rf "$QS"
```

## Where to go next

- [Integrate the platform](../how-to/integrate-the-platform.md): mint session tokens in your backend, call `/tokenize` from the checkout page, verify receipts, and build `/proxy` requests.
- [Add a provider](../how-to/add-a-provider.md): the catalog change, step by step.
- [API reference](../reference/api.md): every endpoint, field and error string.
- [Configuration reference](../reference/configuration.md): every environment variable, in dev and in prod.
- [Logging reference](../reference/logging.md): every log line and alert.
- [How the vault works, step by step](../../README.md#6-how-the-vault-works-step-by-step) in the README.
