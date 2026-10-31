**PAN Vault — architecture and security review**

Review date: 2026-10-30. Baseline: commit `1c67e9189d6eb22c710d7bf879261e833d5c420a`.

**Assessment: strong implementation discipline, with material gaps to resolve before handling production card data.** The small service, restricted database API, embedded catalog, strict parsers, and careful logging form a sound foundation. However, passing the current tests does not establish the stronger guarantees about sensitive-data lifetime, response confidentiality, compromise containment, or uninterrupted key rotation.

This review records **three high-priority findings, four medium-priority findings, and one low-priority hardening observation**. These include an explicitly accepted database limitation, deferred lifecycle work, and a deployment integration gap; they are not eight newly discovered remotely exploitable vulnerabilities. No production compromise or live-provider disclosure was observed. R1 was downgraded after reassessing likelihood against the shipped endpoint's documented behavior and the explicit exclusion of malicious providers from the threat model.

**Scope and method**

Reviewed all application Go source files, the SQL schema, embedded catalog, build configuration, tests, README, local original specification, and superseding provider-proxy design. The current requirements in [CLAUDE.md](../CLAUDE.md) and the provider-agnostic proxy design (2026-10-30) take precedence over superseded parts of the original specification.

Validation included the race-enabled test suite, static analysis, dependency and vendor checks, an isolated PostgreSQL 18.4 instance, and seven temporary probes using synthetic fixtures. External documentation was checked for PCI guidance and Google Cloud behavior. Production infrastructure, Cloud SQL IAM configuration, provider sandbox behavior, deployment pipelines, and assessor-approved PCI scope were not available for verification. Source line references below refer to the baseline commit.

**Prioritized findings**

| ID | Priority | Finding | Evidence/status |
|---|---|---|---|
| R1 | Low | Response masking is a limited defense-in-depth control | Synthetic filter limitation reproduced; no demonstrated in-scope provider disclosure |
| R2 | High | CVV expiry limits retrieval, but does not bound retention or tie deletion to transaction completion | Reproduced; architectural lifecycle gap |
| R3 | High | Rolling DEK rotation makes new records unreadable on older instances | Reproduced; normal deployment failure |
| R4 | High | Caller-controlled rollback defeats database lookup accounting | Reproduced on PostgreSQL; already accepted for v1 |
| R5 | Medium | Encrypted records are not authenticated against their token identity | Reproduced; requires database write capability |
| R6 | Medium | Cloud SQL IAM identities are not mapped to the schema's privilege roles in the supplied deployment contract | Repository/documentation gap; external infrastructure may supply it |
| R7 | Medium | Provider request policy allows unreviewed fields and depends on a complete denylist | Acceptance reproduced; no current Stripe exploit demonstrated |
| R8 | Medium | Retention, key retirement, and compromise recovery remain incomplete | Confirmed design deferrals |

**R1 — Low: response masking has limits; provider disclosure is not demonstrated**

Evidence: [outbound.go:24–58](../outbound.go#L24), [proxy.go:214–244](../proxy.go#L214).

`maskPAN` searches response bytes for the current PAN in three representations: contiguous digits, groups of four separated by spaces, and groups of four separated by hyphens. It does not parse response values. A JSON string containing the same digits as Unicode escapes passes unchanged and decodes back to the full PAN at the platform. Other representations, including different grouping and encoded values, are also outside that filter. CVV and provider-secret echoes are not filtered at all. The provider's `Content-Type` is forwarded separately without sensitive-value filtering.

The review's fake TLS provider returned JSON containing an escaped test PAN, a test CVV, and a test provider secret. `/proxy` returned HTTP 200, and decoding its response recovered all three original values. This is a demonstrated filtering gap, not evidence that Stripe currently returns those fields. A deliberately malicious provider is explicitly outside the threat model; accidental echoes and provider error-format changes are the relevant residual risk.

Likelihood and impact: the shipped Stripe card-token endpoint documents a token and limited card details, including last4, with no full PAN or CVV in its example response. There is no evidence from this review that Stripe returns full PANs, escaped PANs, or credentials on this endpoint. A synthetic provider programmed to leak them establishes the filter's limitations, not a likely production attack. Disclosure would have serious consequences if it occurred, but that conditional impact did not justify the original High rating. [Stripe card-token response](https://docs.stripe.com/api/tokens/create_card)

The probe used Unicode escaping, which is reversible encoding, not encryption. It established nothing about a provider returning encrypted PANs or a recipient's ability to decrypt them.

Recommendation: retain response passthrough for reviewed provider endpoints, preserve the existing masking, alerting, decompression checks, size limit, and redirect refusal, and document masking as defense in depth. Verify documented success and error responses during provider onboarding. Do not make a new provider-specific response transformation layer a production prerequisite on the evidence available. Consider structured filtering or projection only where an actual endpoint contract or observed behavior warrants it.

Acceptance: provider onboarding records the response contract and representative success/error fixtures; documentation states the trusted-provider assumption and masking limitations accurately. The synthetic probes can remain useful hardening tests, but their behavior alone does not establish an in-scope exploit.

**R2 — High: CVV lifetime is not enforced as documented**

Evidence: [card.go:213–256](../card.go#L213), [main.go:546](../main.go#L546), [proxy.go:177–190](../proxy.go#L177), [README.md:151](../README.md#L151).

The cache deletes expired entries only during a subsequent `put`, or when that particular token is passed to `take`. An idle instance can retain expired CVV strings indefinitely. The 15-minute deadline stops retrieval; it is not a maximum period of memory residence. Advancing the test clock by 24 hours left the expired entry and its value in the map, although `take` correctly refused to return it.

Separately, a successful proxy call without `{{cvv}}` leaves a previously cached CVV available. This behavior was reproduced. With the shipped token endpoint, the platform can subsequently authorize a payment outside the vault while the unused CVV remains cached; the vault has no completion signal. Future direct-payment endpoints would have the same lifecycle issue when CVV is omitted. A TTL alone cannot establish deletion at transaction completion. PCI SSC guidance prohibits retaining card verification codes after authorization or for future transactions. This review identifies a design risk requiring lifecycle validation, rather than making a compliance determination solely from the use of RAM. [PCI SSC FAQ 1574](https://www.pcisecuritystandards.org/faqs/1574/)

Recommendation: define an explicit transaction-bound lifecycle. Add proactive expiry with a bounded interval and best-effort wiping of mutable buffers. Clear unused cached CVV when the card leaves the vault for the relevant payment or hand-off, or introduce an equally strong completion protocol. Specify retry behavior and ensure callbacks cannot extend retention. Bound cache capacity; the current full-map sweep on each insertion also grows with pending entries.

The documented multi-instance cache miss is a separate accepted availability tradeoff: another instance returns 409. Retrying without CVV is a business decision that may affect authorization success; it is not a substitute for managing the original instance's retained value. Avoid solving this by introducing durable CVV storage.

Acceptance: abandoned entries are removed without further traffic; completion clears unused CVV; expiry and cleanup remain race-free; restart, timeout, retry, and two-instance behavior are explicitly tested. Memory-zeroing limitations in Go must remain accurately documented.

**R3 — High: normal rolling key rotation causes intermittent payment failures**

Evidence: [main.go:271–307](../main.go#L271), [main.go:675–706](../main.go#L675), [tokenize.go:305–320](../tokenize.go#L305), [proxy.go:162–174](../proxy.go#L162), [README.md:632–651](../README.md#L632).

Each instance loads DEKs once at startup and immediately selects the highest version for encryption. During the documented rolling restart, a restarted instance begins writing version N+1 while an older instance still knows only versions through N. A `/proxy` call for a newly tokenized card landing on the older instance fails with HTTP 500 and `decrypt_failed`. Its `/healthz` can still succeed because that endpoint only pings the database.

The probe stored a valid version-2 ciphertext and sent it through an instance whose key map contained only version 1. The handler returned 500. Existing rotation tests verify that a reloaded instance reads older cards; they do not exercise simultaneous old and new instances.

Recommendation: separate key distribution from write activation. First distribute N+1 to all serving readers while keeping N active for new writes; switch the write version only after readiness confirms reader coverage. An alternative is a bounded, synchronized, authenticated refresh on an unknown version, with explicit failure behavior and protection against refresh storms. Rollback must also preserve access to every version already used for writes.

Acceptance: a two-instance integration test continuously tokenizes and proxies during rotation and rollback, with requests deliberately crossing instances, and observes no missing-key failures. Readiness must reflect key compatibility, not merely database connectivity.

**R4 — High, previously accepted: transactional accounting does not contain a compromised vault**

Evidence: [schema.sql:42–65](../schema.sql#L42), [db.go](../db.go), [CLAUDE.md:10–12](../CLAUDE.md#L10), [README.md:673–678](../README.md#L673).

`get_card` returns ciphertext and inserts the audit row in the caller's transaction. A holder of `vault_app` can read inside a transaction and roll it back, discarding the accounting while retaining the returned ciphertext. On the isolated PostgreSQL instance, 25 reads of the same synthetic record succeeded using separate rolled-back transactions, leaving **zero committed `get` rows**, despite the nominal 20/hour per-token threshold.

This is already explicitly accepted for v1 and is not presented as a newly discovered implementation regression. It nevertheless defeats a central containment objective for adversary B: a compromised vault has both the DB role and unwrapped DEKs. The attacker still needs known tokens; this does not provide token enumeration or unrestricted table access. The normal HTTP path uses autocommit and does not expose this rollback capability to adversary A.

The documented external pgaudit trail is a detection mechanism, not enforcement. Its production configuration and rollback coverage were not verified in this review. Egress restrictions also do not restore confidentiality after process compromise: the process already handles permitted inbound connections and provider credentials.

Recommendation: move mandatory lookup accounting and admission control outside the transaction boundary controlled by the compromised caller. Treat an autonomous-write implementation as a security design change requiring privilege, failure-mode, concurrency, and deadlock review. Update the threat-model summary to state the actual residual protection. If deferred, require an explicit production risk decision rather than relying on the existence of a future fix. No schema changes were made in this review.

Acceptance: rollback, savepoints, alternate transaction isolation, concurrent sessions, and caller cancellation cannot obtain ciphertext without durable accounting and enforced limits. Verify immutable external audit delivery independently.

**R5 — Medium: ciphertext is portable between token identities**

Evidence: [card.go:170–194](../card.go#L170), [tokenize.go:310–320](../tokenize.go#L310), [schema.sql:33–39](../schema.sql#L33), [proxy.go:166](../proxy.go#L166).

AES-GCM authenticates the encrypted bytes, but both encryption and decryption pass `nil` additional authenticated data. The token is generated after encryption. Consequently, a ciphertext and its key version can be copied under another valid token and still decrypt successfully. `vault_app` has sufficient function privileges to read a known ciphertext and insert it under a fresh token through `put_card`, without possessing the DEK. The handler probe confirmed that a copied record was accepted under the second token and reached the fake provider.

Impact: record identity is not cryptographically bound to card identity. A DB-role attacker can create aliases for a known card, fragment its per-token audit history, and reset per-token lookup accounting through new aliases. Normal global limits still apply unless R4 is also exploited. This does not let an HTTP-only platform caller select ciphertext, and it does not reveal plaintext to a DB-only attacker.

Recommendation: generate the token first and authenticate a versioned encoding of the token and relevant record context as GCM additional data. Include any future authorization context only if the system actually adopts it. Plan a versioned ciphertext migration so legacy rows remain readable during deployment; do not silently change the cryptographic format.

Acceptance: copying ciphertext to another token or changing authenticated context fails authentication. Existing records migrate safely, and mixed-format reads are tested.

**R6 — Medium: the Cloud SQL IAM privilege mapping is unspecified**

Evidence: [schema.sql:84–95](../schema.sql#L84), [main.go:196–265](../main.go#L196), [integration_test.go:468–473](../integration_test.go#L468).

The schema creates ordinary PostgreSQL login roles named `vault_app` and `vault_rotator` and describes them as IAM-authenticated users. `openDB` replaces the password with a metadata access token but keeps the configured database username. Cloud SQL manual IAM authentication uses the IAM principal's database username; service-account usernames omit the `.gserviceaccount.com` suffix. A `CREATE ROLE vault_app LOGIN` statement alone does not create or map that IAM principal. [Cloud SQL IAM login documentation](https://docs.cloud.google.com/sql/docs/postgres/iam-logins), [IAM user provisioning](https://docs.cloud.google.com/sql/docs/postgres/add-manage-iam-users)

No provisioning or role-membership grant connecting these identities was found in the supplied repository. The integration tests use local trust authentication, so they cannot verify this production boundary. External infrastructure may already provide the missing mapping; obtain that evidence before treating this as a deployed defect.

Impact if deployed as described: authentication or function authorization fails. An improvised fix using an owner identity would compromise the intended separation of duties.

Recommendation: explicitly provision separate serving and rotation IAM principals, authenticate using their Cloud SQL usernames, and grant each only its intended database privilege role. Keep privilege roles separate from login identities and ensure the serving identity cannot acquire owner or rotation privileges. Document the required grants and ownership in the infrastructure contract.

Acceptance: run a Cloud SQL smoke test using the actual service identities and token refresh. Verify allowed function calls and denial of table access, DDL, owner-role escalation, and cross-role operations.

**R7 — Medium: catalog syntax is strict, but provider semantics remain open-ended**

Evidence: [policy.go:124–230](../policy.go#L124), [catalog.go:287–415](../catalog.go#L287), [catalog.json:14–23](../catalog.json#L14).

The implementation carefully restricts placeholder positions, pins, and explicitly forbidden fields. Other body fields pass through if their syntax is acceptable. Adding `unreviewed_future_option=true` to an otherwise valid request for the embedded Stripe endpoint passed `checkProxy` in the review probe. That shows local acceptance only; Stripe may reject the field, and no existing exploitable Stripe parameter was demonstrated.

The architectural risk is that a new provider parameter can acquire security-sensitive meaning without a catalog deployment. A denylist must enumerate every way to save a card, select another account, expand sensitive responses, or trigger an external callback. A compromised platform can exercise any omitted behavior. Exact byte preservation eliminates one class of parser mismatch but cannot establish that a provider interprets every accepted field safely.

Recommendation: add endpoint-specific allowlists and types for security-relevant request shapes, with narrowly scoped extensibility for benign metadata. Pin provider API versions through reviewed configuration where supported. Treat a catalog change as a security-policy change even when it edits only JSON. Keep sandbox verification and negative semantic fixtures in the release gate. Add differential or fuzz testing for the custom parsers as the provider set grows.

Acceptance: unknown fields fail locally unless their namespace is deliberately permitted; every accepted callback, account-selection, storage, and reuse control has a reviewed policy. Provider-version changes trigger revalidation.

**R8 — Medium, partly deferred: key and data lifecycle controls are incomplete**

Evidence: [schema.sql:7–29](../schema.sql#L7), [main.go:287–307](../main.go#L287), [main.go:587–590](../main.go#L587), [README.md:595](../README.md#L595), [README.md:686](../README.md#L686).

The database API has no retention or purge operation and no re-encryption/rewrapping operation. Every boot unwraps all historical DEKs sequentially within a shared 60-second budget. Daily key creation increases the historical dependency set, while old keys remain necessary for old rows. A single unavailable historical key can prevent the entire service from booting.

Generating new DEKs does not remove access to historical data from an attacker who previously copied old DEKs and ciphertext. Similarly, KMS rotation does not automatically re-encrypt existing wrapped DEKs; accepting an old KMS version during decryption is not rewrapping. The original specification's suggestion of automatic rewrapping should be corrected in the operational contract. [Cloud KMS key rotation](https://docs.cloud.google.com/kms/docs/key-rotation), [Re-encrypting data](https://docs.cloud.google.com/kms/docs/re-encrypt-data)

Recommendation: define justified card-data retention, audit retention, backup expiration, and purge ownership. Add controlled re-encryption and wrapped-key migration with progress tracking, reference checks, rollback, and restore procedures. Define emergency response for exposed DEKs and provider/session secrets, including replacement of running processes that retain them. Measure boot behavior with the expected multi-year key history.

Acceptance: expired records are purged under an authorized role; keys are retired only after active data and required backups no longer depend on them; historical restores and compromise-recovery exercises succeed. Treat the current deferrals as explicit release decisions.

**Design choices worth preserving**

| Choice | Assessment |
|---|---|
| One small Go package with files organized by responsibility | Appropriate for the service's size. Additional framework or service layers would not resolve the findings. Preserve direct, readable security checks. |
| Embedded catalog, strict boot validation, separate environment accounts | Strong deployment-controlled policy boundary. Catalog review must include provider semantics, not only schema validity. |
| Dedicated public and internal TLS listeners | Clear separation of HTTP entry points; internal TLS requires a client certificate. Both listeners still share one process, keys, and DB authority, so this is not process-compromise isolation. |
| Opaque random tokens and AES-256-GCM | Sound primitives with key-length, tamper, and randomness tests. Add record-context authentication as described in R5. |
| Function-only database access, revoked table privileges, pinned function search paths | Valuable restriction, verified against PostgreSQL. Preserve it while addressing transaction-controlled accounting. |
| Validation before database lookup or CVV consumption | Good sequencing. Strict duplicate-key handling, canonical paths, header rules, and exact substitutions reduce ambiguity. |
| Fixed error messages and sanitized access logs | Strong implementation. Existing leak tests cover synthetic PAN, CVV, secret, and name sentinels. These tests do not establish safety of provider passthrough responses. |
| Fixed outbound hosts, verified TLS, no redirects or environment proxies, bounded responses | Strong controls against caller-directed egress within the intact application. Network-layer enforcement remains separate evidence. |
| Vendored dependencies and a pinned, non-root scratch image | Good supply-chain and runtime reduction. Preserve the vendor verification and reproducible-image gate. |

**Additional production release gates**

These are configuration, operational, or accepted-design considerations rather than additional counted vulnerabilities.

| Gate | Observation and required evidence |
|---|---|
| Production catalog and readiness | [catalog.json:28–38](../catalog.json#L28) contains only `stripe_test` with `env=dev`; the production host list is empty. Parsing it for production succeeds with zero accounts, as reproduced. With other prerequisites satisfied, startup has no empty-account rejection and health only checks DB connectivity. Add reviewed production accounts and a readiness/configuration assertion, or explicitly designate a tokenize-only mode. A healthy process currently does not prove that production proxy calls are possible. |
| Load-balancer probes | `/healthz` requires the same mTLS as `/proxy`; the public listener has no GET health route. Google documents that health probes for mTLS backends need an arrangement such as TCP checks or a dedicated probe path/port. Specify and test the chosen design, including independent readiness monitoring if TCP is used. Do not weaken `/proxy` authentication to make probes pass. [Google Cloud backend mTLS guidance](https://docs.cloud.google.com/load-balancing/docs/backend-authenticated-tls-backend-mtls) |
| Real firewall correspondence | `TestEgressHostsMatchCatalog` compares the embedded catalog to repository text files. It does not inspect deployed firewall rules, Private Google Access policy, or destination IP ownership. Require evidence from the infrastructure pipeline that the network enforces the intended destinations. |
| Admission control and capacity | Session tokens are reusable, expiration-only HMAC tickets, and the vault itself has no public issuance quota. Cloud Armor controls and their inability to be bypassed are essential. The global 300/min lookup limit is shared; one authorized caller can exhaust it for everyone. Measure legitimate peaks, queueing, cache growth, and abusive traffic before selecting limits. |
| Certificate and secret lifecycle | mTLS authenticates any suitable client certificate from the configured CA; there is no per-account authorization map or application revocation mechanism. This matches the current single-trust-domain design. Validate dedicated CA issuance, short lifetimes, emergency revocation/connection draining, and coordinated HMAC/provider-key replacement. Introduce account/token ownership checks before expanding into independent tenants. |
| Required CI execution | [Makefile:83](../Makefile#L83) excludes PostgreSQL, stripe-mock, and image reproducibility from `ci`; [Makefile:138](../Makefile#L138) adds them in `ci-all`. No checked-in CI workflow establishes which target is mandatory. Require the full intended gate through branch protection or external pipeline evidence, including infrastructure drift checks. |
| PCI boundary and browser control | The README correctly acknowledges payment-page exposure and the assessor's role, but some summaries say the back end is removed from scope categorically. Validate segmentation and security-impacting access, including checkout delivery, build/deploy systems, ingress TLS termination, identities, and logs. Tokenization alone does not establish that all connected platform components are out of scope. [PCI SSC tokenization guidance](https://listings.pcisecuritystandards.org/documents/Tokenization_Guidelines_Info_Supplement.pdf) |

**Validation results**

| Check | Result |
|---|---|
| `go test -race -count=1 ./...` on the baseline application | Passed; 9.353 seconds. Environment-gated PostgreSQL and provider tests were not enabled in this invocation. |
| PostgreSQL integration suite with `-race -count=1 -run Integration -v` | All eight passed on an isolated PostgreSQL 18.4 instance: privileges, audit counts, search path, per-token/concurrent/global velocity, mTLS end-to-end flow, and rotation. |
| `go vet ./...` | Passed. |
| Repository `staticcheck` tool | Passed after directing its cache to a writable temporary directory. |
| Repository `govulncheck` tool | Passed against the online vulnerability database: “No vulnerabilities found.” This is the scanner result, not a statement that the application has no vulnerabilities. |
| `make deps-check vendor-check` | Passed; 12 module paths in `go.sum`, matching the committed baseline, and vendored content matched generated output. |
| Static application build using the Dockerfile's Go build flags | Passed; binary written outside the repository. Container construction and reproducible image digests were not tested. |
| Seven targeted review probes | All observed behaviors reproduced, described below. |
| PostgreSQL rollback probe | 25 same-token reads succeeded with rollback; zero committed `get` audit rows remained. |

Initial restricted-environment attempts could not write the default Go cache or open local sockets. Successful checks used temporary caches and authorized local socket access. The temporary database was stopped and removed. No production service, provider account, or card data was used.

The seven temporary Go probes asserted the current behavior, so a passing probe confirms the finding rather than a fix. They were removed after execution; production source and the existing tests were not changed. Reproduction recipes using the existing test helpers are:

| Probe | Procedure and observed result |
|---|---|
| Idle CVV retention | Insert a synthetic CVV, advance the injected clock 24 hours, inspect the map before another cache operation: entry remains. `take` correctly refuses the expired value. |
| Unused CVV after hand-off | Seed a card with CVV, issue a successful tokens request without the CVV placeholder, then call `take`: value remains available. |
| Encoded response disclosure | Have `newFakeProvider` return JSON with every test-PAN digit encoded as `\u00XX`, plus synthetic CVV and credential fields; decode the proxy response: all original values survive. |
| Mixed key versions | Seal a record with DEK 2, set its stored version to 2, then proxy through a vault containing only DEK 1: HTTP 500. |
| Ciphertext identity substitution | Copy a stored ciphertext and key version under another generated token, proxy that token: HTTP 200 and provider invocation. SQL source confirms that the DB role has the insert/read capabilities needed to perform the copy. |
| Empty production catalog | Call `parseCatalog(catalogJSON, "prod")`: no error and zero accounts. |
| Unreviewed provider field | Append `unreviewed_future_option=true` to a valid embedded Stripe body and invoke `checkProxy`: accepted locally. |

Live Stripe and stripe-mock tests were not run. Production pgaudit, Cloud SQL IAM, firewall enforcement, load-balancer configuration, backup restoration, and container reproducibility remain unverified. The results do not constitute a PCI compliance assessment.

**Recommended execution order**

1. **Before production card traffic:** close R2–R3; resolve or explicitly re-accept R4 against the stated threat model; prove Cloud SQL identity/role mapping; configure production accounts and working health/readiness probes. R1 is optional hardening, not a production blocker on current evidence.
2. **Before broadening the provider catalog:** implement the R7 request contracts, review provider response behavior as described in R1, pin supported provider behavior, and require sandbox evidence for every endpoint. Bind records to tokens with a migration plan for R5.
3. **Before sustained retention and routine rotation:** complete R8's retention, re-encryption, rewrapping, restore, and emergency-recovery procedures; validate two-instance CVV behavior and capacity limits.
4. **For release assurance:** make the complete CI and infrastructure checks mandatory, and retain evidence of successful checks alongside the deployed image and catalog revision.

---

**Disposition (added 2026-10-30, after review by the project owner)**

Each finding and release gate below records what was decided and why. Items marked *addressed* are implemented by the production hardening design (2026-10-30) and its implementation plan.

| ID | Decision | Reason |
|---|---|---|
| R1 | **Not addressed in code; documented as defense in depth** | The review itself downgraded this to Low. The only shipped endpoint, Stripe `/v1/tokens`, documents a response with last4 and no full PAN or CVV, and deliberately malicious providers are outside the threat model. A structured response filter would need a per-endpoint response schema for every provider, which conflicts with the goal of a lean, provider-agnostic vault, and would still not stop a provider that chooses to leak. Instead, the catalog review checklist requires recording each endpoint's documented success and error responses before it is added, and the README states the masking's limits. |
| R2 | **Addressed** (sweeper, zeroing, drop on provider 2xx, capacity cap), with one accepted residual | The drop on hand-off only reaches the instance holding the CVV; `/tokenize` and `/proxy` arrive through different load balancers, so a CVV on another instance lives until its 15-minute TTL plus at most one sweep interval. Linking the two would require either session affinity across two load balancers (not possible) or shared CVV state, which is durable CVV storage and is ruled out. The residual is no worse than the previous behaviour and is stated in the README. |
| R3 | **Addressed** (on-demand key refresh on an unknown version, single-flight and rate-limited, plus a 5-minute periodic refresh) | The review's alternative, distributing a key before activating it for writes, was dropped because it needs `created_at` from `list_deks`, a return-type change that cannot be applied with `CREATE OR REPLACE`, breaks the byte-identical `schema.sql` rule and forces a migrate-before-deploy order. The on-demand refresh already makes a missing-key read impossible whenever the key exists; the residual case (KMS unreachable at the exact first encounter) fails one request and succeeds on retry. |
| R4 | **Accepted for v1; recorded in `docs/risk-register.md`** | Only a holder of the `vault_app` database role can exploit it, which means a compromised vault process; the platform reaches the database only through single-statement autocommit calls. The fix requires writing the audit row outside the caller's transaction (for example the `dblink` extension), which is a database design change with its own privilege, failure-mode and concurrency review and a schema change through the migration pipeline. pgaudit records every call regardless of rollback, so the audit trail survives even though the rate limit does not. The decision, owner and revisit trigger (v1.1) are now written down rather than implied. |
| R5 | **Addressed** (token generated first and bound into the ciphertext as GCM additional data) | No database exists outside local test runs and no card rows exist anywhere, so the format changes once now, without migration. Doing it later would require a versioned migration. |
| R6 | **Documentation only** | The repository holds no infrastructure code; the IAM-to-role mapping belongs to the infrastructure pipeline that applies `schema.sql` as `vault_owner`. The README now specifies the required service accounts, Cloud SQL usernames, `GRANT ... TO` statements and the `VAULT_DB_URL` username, and lists a real-Cloud-SQL smoke test as a deploy prerequisite. |
| R7 | **Deferred until providers are added** | The shipped catalog has one Stripe endpoint with a small, documented parameter set, and its card-saving and account-selecting parameters are already forbidden. Requiring a full field allowlist on every endpoint works against the lean-catalog goal; the agreed middle ground is an optional per-endpoint `allow` list that rejects unknown fields, mandatory on card endpoints, to be added with the first non-Stripe provider. Provider API version pinning (fixed-value headers in the catalog) is noted for the same change. |
| R8 | **Deferred to v1.1, except wording and schedule** | Retention, purge and re-encryption each need a new database function and role, which is a schema change through the migration pipeline, and there is no stored data yet to retain or re-encrypt. Boot failing when a historical key is unavailable is intended fail-closed behaviour: such a key's cards would be unreadable anyway. The two things that could be done now were done: the README no longer claims KMS rewraps DEKs automatically, and the recommended rotation schedule is monthly instead of daily so the historical key set stays small. |

| Release gate | Decision | Reason |
|---|---|---|
| Production catalog and readiness | **Addressed** (boot refuses an empty account set) | A healthy process must mean a usable one; a tokenize-only mode would need a new setting nobody has asked for. |
| Load-balancer probes | **Documented: TCP health checks plus an independent mTLS readiness monitor** | A dedicated unauthenticated probe path would be a new endpoint, which the design forbids, and weakening `/proxy` authentication is ruled out. |
| Real firewall correspondence | **Not addressed in this repository** | Firewall rules and their verification live in the infrastructure pipeline; this repository supplies the per-environment host lists it must match. |
| Admission control and capacity | **Accepted as designed** | Reusable 15-minute session tokens bounded by Cloud Armor, and a shared global lookup limit, are explicit design choices; tuning the limits needs production traffic measurements that do not exist yet. |
| Certificate and secret lifecycle | **Accepted as designed** | A single trust domain (any certificate from the pinned CA may call `/proxy`) is the intended v1 model; per-account authorization becomes necessary only with independent tenants. |
| Required CI execution | **Addressed** (four GitHub Actions workflows: CI runs `make ci` and checks every commit message, Integration runs `make itest` and `make stripe-mock-test`, Image runs `make image-repro` and keeps the image digest, Fuzz runs `make fuzz` on pull requests and `make fuzz-long` nightly) | Branch protection itself is a repository setting outside the code; the README says it should require all four. |
| PCI boundary and browser control | **Addressed in wording** | The README now says the vault is designed to keep the platform's back end out of scope, subject to the assessor's scoping, consistent with its existing payment-page caveat. |
