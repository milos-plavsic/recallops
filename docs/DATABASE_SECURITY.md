# CockroachDB authorization and tenant-boundary evidence

RecallOps deliberately separates three database identities:

| Identity | Purpose | Required access |
| --- | --- | --- |
| Migration owner | Ordered schema migrations only | Object ownership and role/grant administration |
| `recallops_api` member | API runtime | Exact table-level `SELECT`/`INSERT`/`UPDATE` grants in migration 019 |
| `recallops_outbox` member | Evidence delivery worker | `SELECT` and `UPDATE` on `evidence_outbox` only |

`recallops_api` and `recallops_outbox` are `NOLOGIN` privilege bundles. CockroachDB
creates roles as `NOLOGIN` by default. Neither role can create roles or databases, bypass
row-level security, delete application rows, change the schema, or read the migration ledger.
Migration 019 also revokes `CREATE` on the dedicated application's `public` schema from
`PUBLIC`. A separately managed `LOGIN` principal receives membership in exactly one runtime
role. This keeps credential rotation independent from grants.

## Provision production principals

Apply migrations with the migration-owner URL first. Then, using a secret-safe CockroachDB
administrative workflow, create distinct login principals and grant role membership:

```sql
CREATE USER recallops_api_login WITH PASSWORD '<generated-secret>';
CREATE USER recallops_outbox_login WITH PASSWORD '<different-generated-secret>';
GRANT CONNECT ON DATABASE recallops TO recallops_api_login;
GRANT CONNECT ON DATABASE recallops TO recallops_outbox_login;
GRANT recallops_api TO recallops_api_login;
GRANT recallops_outbox TO recallops_outbox_login;
```

Do not paste real passwords into source, CI logs, shell history, or CloudFormation parameters.
Store complete `sslmode=verify-full` URLs in separate Secrets Manager secrets. Pass the API
secret as `DatabaseUrlSecretArn`, the outbox secret as `OutboxDatabaseUrlSecretArn`, and the owner
secret as `MigrationDatabaseUrlSecretArn`. The ECS task runs a nonessential migration container
first; the API starts only after it succeeds and never receives the owner or outbox URL. A
dedicated outbox container receives only the outbox principal URL.

The runtime image includes the public Cockroach Cloud CA used by those `verify-full` URLs. No
password, connection string, or private key is committed with the certificate.

`MigrationDatabaseUrlSecretArn` is optional only to keep existing demo stacks deployable. If it
is omitted, the migrator reuses `DatabaseUrlSecretArn`; that legacy configuration is not a
least-privilege production deployment.

Every future migration that adds a runtime table must explicitly update the role grants. There
are intentionally no broad default-table grants: an unreviewed new table remains inaccessible.

## What the tenant constraints prove

Tenant-aware unique keys and composite foreign keys reject cross-tenant relationships at the
database boundary for:

- approvals → incidents;
- execution attestations → incidents;
- evidence outbox entries → incidents;
- memory events → memories;
- learned-memory provenance → source incidents; and
- memory supersession → replacement memories.

Run the verifier against a migrated disposable or staging database with a migration-owner URL:

```bash
recallops-db-verify \
  --database-url "$RECALLOPS_MIGRATION_DATABASE_URL" \
  --output database-boundaries.json
```

It opens real SQL transactions, attempts all six cross-tenant writes, requires rejection by the
exact named foreign key, checks the exact grant allowlist and safe role attributes, and executes
seven forbidden statements under the effective runtime roles. Synthetic rows are rolled back.
The sanitized report contains no URL, credential, row payload, or cluster identifier. CI runs the
same verifier against CockroachDB and retains the report as an assurance artifact.

## Accurate row-authorization boundary

CockroachDB v26.2 supports native row-level security through `CREATE POLICY` and
`ALTER TABLE ... ENABLE ROW LEVEL SECURITY`. RecallOps does **not** enable or claim RLS in the
current shared-pool architecture. Every API request uses the same authenticated SQL principal,
so `current_user` cannot distinguish application tenants. A caller-writable session setting is
not a trustworthy tenant identity, and pooled session state creates leakage risk if it is not set
and cleared transactionally.

Consequently, standalone tenant-row reads are authorized by mandatory application query
predicates, while the database independently enforces relationship integrity and least privilege.
A compromise of the shared API database credential can read or change rows allowed to that role
across tenants; composite foreign keys do not prevent standalone row access.

Before claiming database-enforced row authorization, introduce a trusted per-request database
identity (for example, separately authenticated tenant SQL principals), enable and force policies
on every tenant table, verify policy behavior for `SELECT`, `INSERT`, `UPDATE`, upsert, and
`RETURNING`, and test pool reuse and the documented `ON CONFLICT DO NOTHING` policy limitation.

Primary references:

- [CockroachDB authorization](https://www.cockroachlabs.com/docs/v26.2/security-reference/authorization)
- [CockroachDB `CREATE POLICY`](https://www.cockroachlabs.com/docs/v26.2/create-policy)
- [CockroachDB `GRANT`](https://www.cockroachlabs.com/docs/v26.2/grant)
