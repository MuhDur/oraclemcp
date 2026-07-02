# Upgrading to 0.6.0

This note is for operators and downstream consumers moving from the 0.4.x line
to 0.6.0. The release is additive for normal read-only use, but a few surfaces
are intentionally stricter or more explicit.

## Query result JSON

`oracle_query`, `query`, and catalog extraction now expose non-text Oracle
values through the versioned `OracleCell.structured` contract. Consumers that
inspect raw result JSON must handle the published schema in
[`schemas/oracle-cell-structured.schema.json`](../schemas/oracle-cell-structured.schema.json)
instead of relying on ordinary-looking placeholder strings for ARRAY, JSON,
VECTOR, TSTZ, object, nested-result, or unsupported values.

Text and NUMBER defaults remain conservative: NUMBER is still lossless string
by default, and larger structured decoding still requires `deep_decode = true`
plus explicit row, cell, byte, and depth caps. Metadata cache keys include the
structured contract version, so stale catalog snapshots can be invalidated
without guessing.

## Config schema and new fields

The current config schema is `schema_version = 2`. Schema 1 configs still load,
but use schema 2 when you add the 0.6.0 fields:

```toml
schema_version = 2

# Optional least-privilege profile for operator DB evidence / v$session views.
# monitor_profile = "monitor_ro"

[http]
# Browser SQL Workbench release gate. Default: false.
dashboard_workbench = false

[[profiles]]
name = "dev_ro"
# Browser-originated DDL/Admin apply opt-in for this profile. Default: false.
dashboard_ddl_workbench = false
```

All three fields are default-safe when omitted. They do not raise a profile's
`max_level`, bypass `protected = true`, or weaken the classifier. Config parsing
remains strict: unknown keys and forward-incompatible `schema_version` values
fail at load rather than being ignored.

## Profile switching and HTTP lanes

Stdio remains a single local-client path. Served stateful HTTP isolates work by
server-derived principal and MCP session lane. `oracle_switch_profile` applies
to the active lane/session, revalidates profile exposure and draining state
before resolving credentials, reloads profile-scoped custom tools, bumps the
lane generation, and clears old grants. A failed switch leaves the old
connection/profile in place.

For multi-agent HTTP deployments, use stateful sessions with per-client
credentials, OAuth, or mTLS. Shared-principal or unsupported lane situations
fail closed before touching Oracle rather than falling back to a global mutable
connection.

## Confirmation grants

The legacy deterministic confirmation-MAC shape is retired. Confirmation grants
are now opaque, single-use references bound to the statement or action digest,
active profile, MCP session, dispatch lane, server-derived principal, and lane
generation. Reusing a grant from another lane/principal/session, after a profile
switch or level change, after expiry, or after restart fails closed; preview the
action again and use the fresh `confirm` value returned by that preview.

Committing SQL still writes durable intent metadata before execution. Exact
grant-plus-SQL replay after restart is rejected, and `commit_in_doubt` or
unknown outcomes keep writable startup fail-closed until the database outcome is
verified.

## Audit and service-state migration

New audit records can carry `schema_version = 3` with server-derived subject
and optional DB-evidence fields. Existing signed v1/v2 audit logs still verify;
no audit-log rewrite is required.

If a 0.4.x install still uses the legacy default audit path
`~/.config/oraclemcp/audit.jsonl`, `oraclemcp doctor` reports it. `oraclemcp
doctor --fix` copies that file byte-for-byte into the XDG state audit path only
when the current target is absent, writes a backup artifact first, and leaves
the legacy source untouched. If both locations exist with different bytes,
doctor refuses to merge them.

## Dashboard workbench

The dashboard Workbench remains off by default. Read/classify paths do not need
the DDL flag, but browser-originated DDL/Admin apply requires both:

- `[http].dashboard_workbench = true`
- `dashboard_ddl_workbench = true` on the active profile

Those flags are release gates for the browser surface only. They do not bypass
profile ceilings, confirmation grants, rollback behavior, idempotency, or the
signed audit chain.
