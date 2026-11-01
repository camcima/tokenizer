# Rotate keys and certificates

This guide is for the operator who rotates the vault's key material in a deployed environment: data encryption keys, the KMS key-encryption key, the session HMAC key, the receipt signing key, provider account secrets, the platform client CA and the TLS server certificate. Each section gives when to rotate, the steps, how to verify from the logs and how to roll back. For why the keys are built this way, see [Cryptography](../explanation/cryptography.md).

## At a glance

| Material | Where it lives | When the vault reads it | Several at once? | Restart needed |
|---|---|---|---|---|
| Data encryption keys (DEKs) | `vault.deks`, wrapped by KMS | At boot, every 5 minutes, and on demand | Yes, all versions stay loaded | No |
| KMS key-encryption key | Cloud KMS in `pci-keys-<env>` | Through KMS on every unwrap | Yes, KMS keeps old key versions | No |
| Session HMAC key | Secret Manager (`VAULT_SESSION_HMAC_SECRET`) | At boot only | No, exactly one | Yes |
| Receipt signing seed | Secret Manager (`VAULT_RECEIPT_KEY_SECRET`) | At boot only | No, exactly one (the platform can accept several public keys) | Yes |
| Provider account secrets | Secret Manager, named in the account's `secrets` map in `catalog.json` | At boot only | No, one value per secret (the provider may keep two keys valid) | Yes |
| Platform client CA | File at `VAULT_CLIENT_CA` | At boot only | No, exactly one PEM block | Yes |
| TLS server certificate | Files at `VAULT_CERT`, `VAULT_KEY` | At boot only | No, one certificate for both listeners | Yes |

Secret Manager secrets are always read as `versions/latest` (`accessSecret` in `gcp.go`). A new secret version therefore takes effect on the next boot of any instance, including one the instance group starts on its own (autohealing, scale-out). Add a new version only when you are ready for any instance to use it.

The README recommends a new DEK every month and a 90-day KMS key rotation. The vault fixes no schedule for the other items; follow your key management policy, and rotate at once when you suspect exposure.

## Data encryption keys (DEKs)

**When:** monthly, as a scheduled job.

**Steps:**

1. Run the rotation job as the rotator service account (Cloud SQL user granted `vault_rotator`). It needs only `VAULT_ENV`, `VAULT_DB_URL` and `VAULT_KMS_KEY`:

   ```
   /vault -rotate-dek
   ```

   `rotateDEK` (`main.go`) generates 32 random bytes, wraps them with KMS `encrypt`, unwraps the result with KMS `decrypt` and compares, and only then stores the wrapped key through `vault.add_dek`, which returns the new version (`max(version) + 1`). The version is printed on standard output; the job exits 0.
2. Do nothing on the running instances: each one picks the new key up by itself, through a background refresh every 5 minutes or an on-demand refresh when `/proxy` meets an unknown `key_version` (at most one per 10 seconds; the bounds are in [Limits](../reference/limits.md), the mechanism in [Cryptography](../explanation/cryptography.md)).
3. Once an instance holds the new version, it seals new cards under it (the highest version is current). Old cards are not re-encrypted; they keep opening under their own version.

**Verify:**

- The job printed a version one higher than before. A failure prints `boot failed: rotate: <reason>` (for example `rotate: kms encrypt: status 403` or `rotate: vault.add_dek: sqlstate 42501`) and stores nothing.
- There is no log line for a refresh, successful or failed: refresh errors are deliberately not logged (`refreshLoop` in `vault.go`). A newly booted instance logs `deks loaded versions=1,…,N current=N`, which shows the new version.
- No `ALERT decrypt_failed … key_version=<N>` appears. A short burst is possible on one instance if KMS or the database was unreachable when it first met version N, or if its previous refresh had finished less than 10 seconds earlier, before the key existed; it clears with the next successful refresh.
- Normally every instance holds the new key within one background period (5 minutes). A tick that falls within 10 seconds of another refresh is skipped, and a failed refresh is retried on the next tick.

**Rollback:** there is none, and none is needed for a bad key: a key that does not unwrap is never stored. Neither `vault_app` nor `vault_rotator` can delete a DEK (only the table owner `vault_owner` can), and removing a row from `vault.deks` would make every card sealed under it fail with `decrypt_failed`. Never call `vault.add_dek` by hand with anything but a KMS-wrapped key: every instance unwraps every stored DEK at boot and refuses to boot if one fails (`unwrapDEKs` in `main.go`).

## KMS key-encryption key

**When:** every 90 days, as an automatic rotation configured on the KMS key.

**Steps:** none in the vault. KMS encrypt uses the newest key version; KMS decrypt accepts the older ones, so DEKs wrapped earlier stay readable under the key version that wrapped them ([Cryptography](../explanation/cryptography.md)).

**Verify:** after the next `vault -rotate-dek`, instances keep booting (`deks loaded …`).

**Rollback / caution:** never disable or destroy a KMS key version while a DEK wrapped under it is in `vault.deks`. Boot unwraps every DEK and fails on the first one KMS refuses (`boot failed: DEK version <n>: kms decrypt: status <code>`).

## Session HMAC key

The platform mints session tokens (`v1.<expires_unix>.<hex HMAC-SHA256>`) with this key and the vault checks them on `/tokenize` (`checkSession` in `tokenize.go`). A token is valid for at most 15 minutes.

**When:** per your policy, and at once if the key may be exposed.

The vault holds exactly one session key and has no overlap window. During a changeover, a token minted under one key and checked by an instance holding the other gets `401 {"error":"unauthorized"}` and logs `ALERT session_token_invalid reason=hmac` (at most once per second per instance). Plan a short window of failed checkouts, at low traffic.

**Steps:**

1. Generate the new key: 32 random bytes as exactly 64 hex characters, for example `openssl rand -hex 32 | tr -d '\n'`. Any other length or format refuses boot (`VAULT_SESSION_HMAC_SECRET: payload must be exactly 64 hex chars`).
2. Prepare the platform to mint with the new key, but do not switch yet.
3. Add the new key as a new version of the secret named by `VAULT_SESSION_HMAC_SECRET`.
4. Restart the vault instances (a rolling replace of the instance group) and switch the platform's minting key as close to the same moment as you can.
5. Tokens minted under the old key stop working once every instance runs the new key; they would have expired within 15 minutes anyway. A checkout that fetches a new session token after a `401` recovers.

**Verify:** after the restart, `ALERT session_token_invalid reason=hmac` stops and the access log shows `req listener=public method=POST path=/tokenize status=200` again. A persisting `reason=hmac` means the platform and the vault disagree on the key.

**Rollback:** add the previous value again as a new version of the secret, restart the instances, and switch the platform back.

## Receipt signing key

The vault signs every `/tokenize` receipt with an Ed25519 key derived from a 32-byte seed. The platform verifies receipts with the public key and never needs the seed. The format is in [Receipt](../reference/receipt.md).

**When:** per your policy, and at once if the seed may be exposed.

**Order matters:** an instance can boot at any moment, and one that boots with a seed whose public key the platform does not accept yet issues receipts the platform rejects. The platform must trust the new key before any vault signs with it.

**Steps:**

1. Generate the new seed offline, exactly 64 hex characters with no trailing newline (`openssl rand -hex 32 | tr -d '\n' > seed.hex`), and derive its public key with the `pubkey.go` program in [Running it safely](../../README.md#9-running-it-safely) (`go run pubkey.go < seed.hex`).
2. Add the new public key to the platform's list of accepted keys, and confirm the change is deployed everywhere that verifies receipts. The platform accepts a receipt if any accepted key verifies it.
3. Only then add the seed as a new version of the secret named by `VAULT_RECEIPT_KEY_SECRET`, and restart the vault instances. Delete `seed.hex` (`shred -u seed.hex` or equivalent).
4. Keep both public keys accepted until every instance runs the new seed and the receipts signed under the old key are no longer needed: the checkouts that started before the switch have finished, and the longest time the platform accepts a receipt after its `iat` has passed. The vault sets no receipt lifetime itself. Then remove the old public key.

**Verify:** every instance logs `receipt public key=<base64url>` at boot, and after the restart that value equals the key derived in step 1 on every instance. The receipt and the seed are never logged. A seed that is not exactly 64 hex characters refuses boot with `VAULT_RECEIPT_KEY_SECRET: payload must be exactly 64 hex chars`.

**Rollback:** while the old public key is still accepted, add the old seed again as a new version and restart. If the old seed was exposed, do not roll back: generate another seed and repeat from step 1.

## Provider account secrets

Each catalog account names its credentials in its `secrets` map (for example `stripe_test`'s `secretKey`, `projects/pci-cde-dev/secrets/stripe-test-secret-key`). `loadAccountSecrets` (`main.go`) reads `versions/latest` of every secret of every account of the environment at boot only, all or nothing: one missing or invalid value refuses boot.

**When:** per your policy and the provider's, and at once if a key may be exposed.

**Steps:**

1. Create the new key at the provider and keep the old key valid.
2. Add the new key as a new version of the secret the catalog names. The value must be printable ASCII without whitespace.
3. Restart the vault instances one at a time.
4. Once every instance runs the new key and `/proxy` calls for that account succeed, revoke the old key at the provider.

**Verify:** each instance logs `catalog loaded env=<env> accounts=<n>` and reaches `ready`; an invalid value logs `boot failed: account <account> secret <name>: secret must be non-empty printable ASCII without whitespace`. Then a `/proxy` call for the account returns the provider's success (`req listener=internal method=POST path=/proxy status=200`).

**Rollback:** while the old key is still valid at the provider, add the old value again as a new version and restart.

## Platform client CA

`VAULT_CLIENT_CA` names a file with exactly one PEM `CERTIFICATE`, a CA certificate; a second PEM block or a non-CA certificate refuses boot (`loadClientCA` in `main.go`). The internal listener trusts only that CA, so the vault cannot trust an old and a new CA at the same time.

**When:** before the CA certificate expires, and at once if the CA key may be exposed.

**Steps, CA renewed with the same key and subject:**

1. Issue the renewed CA certificate with the same subject and key.
2. Replace the file on the instances and restart them one at a time. Existing platform client certificates keep verifying, since they chain to the same subject and key.

**Steps, new CA key:**

1. Issue new client certificates from the new CA to every platform service allowed to call `/proxy`, and nothing else.
2. Give each platform client both certificates and let it present the one the server asks for. In TLS 1.3 the vault's listener names its trusted CA in the handshake, and a Go client can choose with `tls.Config.GetClientCertificate` and `CertificateRequestInfo.AcceptableCAs`. Without this, expect failed `/proxy` handshakes on instances that hold the other CA during the restart.
3. Replace the file with the new CA on the instances and restart them one at a time.
4. Once every instance runs the new CA, remove the old certificates from the platform clients and retire the old CA.

**Verify:** after each restart, the readiness monitor gets `200 {"status":"ok"}` from `GET /healthz` with a certificate from the new CA, and `/proxy` access lines show the serials of the new certificates (`req listener=internal … caller=<serial>`). A handshake rejected for an untrusted certificate never reaches a handler, so it writes no log line: watch the platform's own error rate. A bad CA file logs `boot failed: VAULT_CLIENT_CA: client CA: …`.

**Rollback:** put the previous CA file back and restart. Platform clients must still hold certificates from that CA.

## TLS server certificate

One certificate and key (`VAULT_CERT`, `VAULT_KEY`) serve both listeners (`newServers` in `main.go`). Platform clients verify it on port 9443, where TLS ends in the vault; on port 8443 the external load balancer is the client, and browsers see the load balancer's own certificate.

**When:** before the certificate expires, and at once if the key may be exposed.

**Steps:**

1. Issue the new certificate from a CA the platform clients and the load balancer already trust, with the names they connect to.
2. Replace both files on each instance (readable by UID 65532) and restart the instances one at a time. The pair is loaded once, at boot.

**Verify:** each instance reaches `ready`; a mismatched or unreadable pair logs `boot failed: VAULT_CERT/VAULT_KEY: cannot load key pair`. Check the served certificate's dates from inside the platform VPC, for example with `openssl s_client -connect <internal-address>:9443 -cert monitor.pem -key monitor.key </dev/null | openssl x509 -noout -dates`, and confirm the readiness monitor still gets `200`.

**Rollback:** put the previous files back and restart, as long as the previous certificate is still valid.

## See also

- [Running it safely](../../README.md#9-running-it-safely), "Key rotation" and "Rotation schedule and key refresh"
- [Cryptography](../explanation/cryptography.md)
- [Receipt reference](../reference/receipt.md)
- [Database reference](../reference/database.md)
- [Respond to alerts](respond-to-alerts.md)
- [Deploy on Google Cloud](deploy-on-gcp.md)
