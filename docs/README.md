# PAN Vault documentation

This folder holds the detailed documentation for PAN Vault. The [main README](../README.md) is the
front door: it explains, in plain language and then in depth, what the vault is for and how it
works, and it is available in English, Spanish and Brazilian Portuguese. The pages here go further
and are written in English only. Each page says who it is for in its first lines.

The pages are organised by what you are trying to do:

| You want to… | Read |
|---|---|
| Run the vault on your machine and see it work | the [tutorial](#tutorial) |
| Integrate, deploy, operate or extend it | a [how-to guide](#how-to-guides) |
| Look up an exact name, value, format or limit | a [reference page](#reference) |
| Understand why it is built this way and what it protects against | an [explanation](#explanation) |

## Tutorial

A lesson for a newcomer. Every step has a command and its expected output.

- [Local quickstart](tutorials/local-quickstart.md): a PostgreSQL container, test certificates,
  the vault in dev mode, a tokenized test card, a verified receipt and a health check over mTLS.

## How-to guides

Step-by-step recipes for one task each, for readers who know the basics.

- [Integrate the platform](how-to/integrate-the-platform.md): session tokens, calling `/tokenize`
  from the browser, building a `/proxy` envelope, handling every response, the CVV lifecycle from
  the platform's side, idempotency and the hand-off token policy.
- [Deploy on Google Cloud](how-to/deploy-on-gcp.md): projects, instances, Cloud SQL IAM, KMS,
  Secret Manager, the two load balancers and firewall rules that keep `/proxy` off the internet,
  egress rules, health checks and the probes that prove the separation holds.
- [Add a provider](how-to/add-a-provider.md): the catalog change procedure, from qualifying the
  endpoint to the pull request.
- [Rotate keys](how-to/rotate-keys.md): data encryption keys, the KMS key-encryption key, the
  session HMAC key, the receipt signing key, provider account secrets, the platform client CA and
  TLS certificates, each with verification and rollback.
- [Respond to alerts](how-to/respond-to-alerts.md): one runbook per `ALERT` line.

## Reference

Complete, neutral descriptions. Exact names and values, taken from the code.

- [API](reference/api.md): both listeners, every endpoint, header rule, status code and error
  constant.
- [Configuration](reference/configuration.md): every environment variable and flag, with the dev
  and prod rules.
- [Catalog](reference/catalog.md): the `catalog.json` schema, placeholder vocabulary, pins,
  forbids, header templates and the form-key grammar.
- [Receipt](reference/receipt.md): the signed card receipt format, the BIN rule and the verifier.
- [Database](reference/database.md): the schema, the four functions, roles, velocity limits and
  what is stored encrypted.
- [Limits](reference/limits.md): sizes, caps, rate limits and timeouts.
- [Logging](reference/logging.md): every log line and alert, and what is never logged.
- [CLI, Make and CI](reference/cli-and-make.md): binary flags, Makefile targets, pinned tools,
  hooks and workflows.

## Explanation

Understanding-oriented pages: the why, the trade-offs and the alternatives.

- [Architecture](explanation/architecture.md): components, state and the path of each request.
- [Threat model](explanation/threat-model.md): the adversaries, the controls that stop each path,
  why `/proxy` is unreachable from the internet, and the residual risks.
- [Proxy design](explanation/proxy-design.md): why the platform builds the provider request and
  the vault only fills, checks, signs and sends it.
- [Cryptography](explanation/cryptography.md): envelope encryption, key refresh, token-bound
  sealing, session tokens and receipts.
- [CVV lifecycle](explanation/cvv-lifecycle.md): why the CVV is held, for how long, and what
  remains open.
- [Design decisions](explanation/design-decisions.md): the record of decisions, with context and
  consequences.
- [Performance](explanation/performance.md): binary and image size, memory, throughput, and how
  to measure them again.
- [PCI DSS mapping](explanation/pci-dss-mapping.md): where each principal requirement is
  addressed, by the code, by the deployment, or not here.

## Other documents

- [Risk register](risk-register.md): accepted risks, their compensating controls and the triggers
  for revisiting them.

## Keeping these pages correct

Every claim in these pages is written from the code. Two checks run in CI, and before every push on a clone that installed the hooks (`make hooks`):
relative links and heading anchors must resolve (`make docs-links`), and every Mermaid diagram
must parse (`make mermaid-check`). When you change behaviour, change the page that describes it in
the same pull request.
