# Risk register

Risks the project has looked at and decided to accept for now, rather than fix. Each entry says who can exploit the risk, what limits the damage meanwhile, who owns the decision and what makes us look at it again. A new entry needs the project owner's sign-off; closing one means linking the change that fixed it.

## RR-1: Rollback bypass of lookup accounting

| Field | Value |
|---|---|
| **ID** | RR-1 |
| **Title** | Rollback bypass of lookup accounting |
| **Description** | `vault.get_card` writes the lookup's `access_log` audit row, which is also what the velocity limits count, inside the caller's database transaction. A session that calls `get_card` inside an explicit transaction and then rolls it back still receives the ciphertext, but the audit row and its count disappear. Repeating this lets that session look up a known token without the per-token (20 an hour) or global (300 a minute) limits ever seeing it. Measured on PostgreSQL in the security review: 25 same-token reads succeeded with rollback and left no committed audit row. |
| **Who can exploit it** | Only a holder of the `vault_app` database role, which in practice means a compromised vault process (adversary B in README §7.1): it holds the role's credentials and can open its own transactions. The platform (adversary A) cannot: it reaches the database only through the vault, and the vault makes single-statement autocommit calls, so there is no transaction to roll back. A stolen copy of the database credentials gets only ciphertext; the decryption keys are not in the database. |
| **Compensating controls** | pgaudit with `pgaudit.log='function'` records every function call in Cloud Logging, whether or not its transaction commits, so the audit trail survives even though the rate limit does not. The egress firewall lets the vault reach only this environment's provider hosts, so cards it reads cannot simply be sent elsewhere. `vault_app` has no table privileges: it can call only `put_card`, `get_card` and `list_deks`, one row per call, so it cannot list or bulk-read cards. The attacker must already know each token (128 random bits; no enumeration). The global limit still counts every lookup that commits, including all of the vault's own traffic. |
| **Decision** | Accepted for v1 on 2026-10-30. |
| **Owner** | The project owner. |
| **Revisit trigger** | v1.1: the audit write moves outside the caller's transaction (an autonomous write, for example through `dblink`), so a rollback can no longer remove it. That is a database design change with its own privilege, failure-mode and concurrency review, applied through the migration pipeline. Revisit sooner if anything other than the vault is ever granted `vault_app`. |
| **Links** | [README §10, Known limitations](../README.md#10-known-limitations-and-what-comes-next) |
