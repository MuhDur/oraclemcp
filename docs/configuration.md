# Configuration reference — oraclemcp

The canonical field reference for `oraclemcp` configuration. It documents the
top-level keys, every connection-profile field (name, type, default, whether it
is required, and its effect), the operating-level ladder, the `mcp_exposed`
opt-out, credentials/secret-refs, the supported auth modes, transports, and
`base` inheritance.

A fully annotated, copy-pasteable starting point lives at the repository root in
[`oraclemcp.example.toml`](../oraclemcp.example.toml) — it shows every field with
its default noted inline and a worked `mcp_exposed` opt-out. (That example is
kept honest by `crates/oraclemcp-config/tests/example_config_parses.rs`, which
loads and validates it through the real loader, so it cannot silently rot.)

Audit-log operation, verification, and WORM/SIEM shipping are documented in
[`docs/operations.md`](operations.md) §5.4–§5.6 and are only summarized here.

---

## Discovery and precedence

### File discovery order

When no explicit path is passed, the binary looks for a config file in this
order and uses the first that exists:

1. `$ORACLEMCP_CONFIG` — an explicit path (launcher/control variable, not part
   of the schema).
2. `$XDG_CONFIG_HOME/oraclemcp/profiles.toml`, then
   `$XDG_CONFIG_HOME/oraclemcp/config.toml` — honored only when
   `XDG_CONFIG_HOME` is set to an absolute path (per the XDG Base Directory
   spec); a relative value is ignored. On most machines `XDG_CONFIG_HOME` is
   unset or already `~/.config`, so this collapses into the next entry.
3. `~/.config/oraclemcp/profiles.toml`, then `~/.config/oraclemcp/config.toml`

State (write-intents, audit, service files) separately follows
`XDG_STATE_HOME`; setting `XDG_CONFIG_HOME` relocates config discovery and the
default `setup --write` target on a fresh machine.

### Layer precedence

Values are composed with strict precedence, lowest to highest:

```
built-in defaults  <  config file (TOML)  <  environment (ORACLEMCP_*)  <  CLI overrides
```

The environment layer reads `ORACLEMCP_*` variables (nested keys split on `__`).
A set of launcher/control variables are explicitly **ignored** as config keys so
they never become "unknown key" errors: `ORACLEMCP_CONFIG`, `ORACLEMCP_LOG`,
`ORACLEMCP_STDIO_TOKEN`, `ORACLEMCP_TOOLS_DIR`, `ORACLEMCP_AUDIT_KEY`,
`ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY`, the `ORACLEMCP_TEST_*` live-test vars, and
the live-gate control vars `ORACLEMCP_LIVE_XE`,
`ORACLEMCP_MULTI_DB_LIVE_XE`, `ORACLEMCP_LIVE_XE_CONTENTION`, and
`ORACLEMCP_PHASE0_*`.

### Strictness

Parsing is **strict and fail-fast**:

- **`deny_unknown_fields`** — any unrecognized key (top-level, in `[http]`,
  `[audit]`, or any profile sub-table) is rejected. A misspelled field is a load
  error, never a silently-ignored no-op.
- **Validation at load** — the whole config is validated when it is loaded (the
  server fails to start on an invalid config rather than discovering a problem
  mid-session).
- **Forward-incompatible versions rejected** — a config declaring a
  `schema_version` higher than the build supports is rejected. Schema `1`
  configs remain valid; schema `2` adds only default-safe fields.

---

## Zero-config TNS discovery (`setup --discover`)

`oraclemcp setup --discover` generates the profiles file for you from an existing
`tnsnames.ora`, so you rarely hand-author the first config. Full contract:
[`tns-discovery-onboarding.md`](tns-discovery-onboarding.md).

- **Search order** — first directory that yields net-services wins, but all are
  scanned for the report: `$TNS_ADMIN`, `$ORACLE_HOME/network/admin`,
  `~/.config/oraclemcp/network`, `~`, `/etc`, common Instant Client dirs, and the
  current directory. Candidates are de-duplicated by canonical path; a
  permission-denied candidate is skipped with a note, never a hard failure.
- **Net-service → profile mapping** — one profile per alias, named by a
  deterministic lower-snake sanitization of the alias (with a numeric suffix on
  collision). `default_profile` is set only when exactly one service is found.
- **`connect_string`** — the TNS alias itself. The discovery flow points the
  server at the resolved `tnsnames.ora` directory (via `TNS_ADMIN`), so the alias
  resolves at runtime; the underlying synthesis library can instead emit a
  normalized EZConnect string from the descriptor's host/port/service when that
  directory is not made reachable.
- **Secret references** — each profile gets `credential_ref = "env:ORACLE_<NAME>_PASSWORD"`
  (and a commented `[profiles.oci].wallet_password_ref` env placeholder for
  TCPS/wallet targets). No secret value is ever read, written, or printed; the
  report lists only the variable *names* to export.
- **READ_ONLY defaults** — `max_level` and `default_level` are both set explicitly
  to `READ_ONLY`, and every profile is flagged needs-verification (no live
  connection is attempted during discovery).
- **Merge and backup** — writing goes through config-ops: an existing config is
  never clobbered, only new profiles are added (hand edits preserved), and a
  timestamped backup is taken before any change with a verify-before-mutate base
  hash so a concurrent edit is rejected rather than overwritten. Finding no
  `tnsnames.ora` falls back to the minimal starter profile.

---

## Top-level fields

| Field | Type | Default | Effect |
|---|---|---|---|
| `schema_version` | integer | `2` | Config schema version this build understands. A higher value than the build supports is rejected (forward-incompatible). Version `1` configs still load; version `2` adds only default-safe fields. |
| `default_profile` | string | none | Profile used when the launcher does not pass `serve --profile <name>`. Must name a defined profile. With no `default_profile` and exactly one profile, that sole profile is used. |
| `monitor_profile` | string | none | Optional least-privilege profile for fleet-wide database observability such as `v$session` and DB evidence. Must name a defined profile. When unset, operator views degrade to self-lane/local telemetry. |
| `[http]` | table | stdio-only | Native Streamable HTTP transport (see [Transports](#transports)). |
| `[audit]` | table | safe defaults | Out-of-band signed audit log (see [`operations.md`](operations.md) §5.4–§5.6). |
| `[[profiles]]` | array of tables | `[]` | Named Oracle connection profiles (see below). |

---

## Audit signing-key rotation

`[audit].key_ref` and `key_id` define the single active signer. Retain old keys
as verification-only entries during rotation:

```toml
[audit]
key_id = "2026-q3"
key_ref = "env:ORACLEMCP_AUDIT_KEY_2026_Q3"

[[audit.verification_keys]]
key_id = "2026-q2"
key_ref = "env:ORACLEMCP_AUDIT_KEY_2026_Q2"
```

Key IDs use only ASCII letters, digits, `.`, `_`, and `-` (maximum 128 bytes);
IDs and resolved key material must be unique. Startup authenticates the
complete existing chain and old head anchor with this keyring. The anchor stays
under the old key until the first new-key record is durably appended, so a
crash on either side of the transition remains recoverable. Secret references
are redacted from diagnostics and never enter audit or protocol output.

---

## Connection-profile fields

Each `[[profiles]]` entry is a named Oracle connection target. Inheritable scalar
fields are modelled internally as "unset vs. set" so `base` inheritance is
well-defined; the **Default** column is the value an accessor returns when the
field is unset after inheritance.

### Identity and connection

| Field | Type | Default | Required | Effect |
|---|---|---|---|---|
| `name` | string | — | **yes** | Stable identifier the agent connects by. Must be unique across profiles. |
| `description` | string | none | no | Friendly description shown in `list_profiles`. |
| `connect_string` | string | none | **yes** (after inheritance) | Oracle Net connect identifier: EZConnect (`host:port/service`), EZConnect-Plus (`tcps://host:port/service?wallet_location=…`), or a `tnsnames.ora` alias. A profile with no usable `connect_string` is a load error. |
| `username` | string | none | no | Oracle username. Omit for wallet / OS-auth / OCI-IAM. |
| `credential_ref` | string | none | no | Reference to the credential in a secrets backend. Use `env:`, `file:`, `keyring:`, or future `vault:` for production; `literal:` is dev-only and rejected when `protected = true`. Never surfaced in `list_profiles` metadata. See [Credentials and secret references](#credentials-and-secret-references). |

### Operating level and protection

| Field | Type | Default | Required | Effect |
|---|---|---|---|---|
| `max_level` | enum | `READ_ONLY` | no | Per-target operating-level ceiling. Immutable cap; session elevation can never exceed it. See [the ladder](#the-operating-level-ladder). |
| `default_level` | enum | `READ_ONLY` | no | The level a fresh session starts at. Must not exceed `max_level` (else config load error). |
| `protected` | bool | `false` | no | Production profile: pins the ceiling immutable. When `true`, `max_level` **must** be `READ_ONLY` (else load error) and `literal:` secret refs are rejected. Implies `require_signed_tools`. |
| `require_signed_tools` | bool | `false` | no | Require a valid HMAC signature for every operator-defined custom tool loaded with this profile. A `protected` profile implies this even when unset. `ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY` must resolve to at least 32 bytes. |
| `read_only_standby` | bool | `false` | no | Mark the target as a read-only standby (Active Data Guard): forces `READ_ONLY` regardless of `max_level`. |
| `allow_change_notification` | bool | `false` | no | Explicitly permit CQN registration for this profile. It does not widen SQL admission: each registration still requires a classifier-proven query, an active confirmed `READ_WRITE` step-up, and durable audit evidence; protected and standby profiles remain ineligible, and OBJECT-level registration is refused. |
| `max_subscriptions` | integer | `4` | no | Per-principal live-subscription cap. Each admitted subscription reserves one EMON notification connection from the profile's database connection ceiling; `0` disables new subscriptions fail-closed. This resource bound does not authorize CQN. |
| `mcp_exposed` | bool | `true` | no | E5 per-profile MCP exposure (opt-out). See [The `mcp_exposed` opt-out](#the-mcp_exposed-opt-out). |
| `dashboard_ddl_workbench` | bool | `false` | no | Browser dashboard DDL/Admin apply opt-in for this profile. Still capped by `max_level`, `protected`, `read_only_standby`, confirmation, rollback, and audit controls. |

### Session and routing

| Field | Type | Default | Required | Effect |
|---|---|---|---|---|
| `call_timeout_seconds` | integer | `30` | no | Oracle call timeout and total request-budget ceiling, in seconds. Omit for the 30s default. Set `0` only to disable the driver call timeout deliberately; `doctor` warns. Tools exposing `timeout_seconds` can tighten the budget for one call but cannot loosen the profile ceiling. |
| `connect_timeout_seconds` | integer | driver default `20` | no | Oracle Net transport connect timeout, in seconds. Bounds TCP/TLS/TNS connect and authentication reads before a session exists by passing `transport_connect_timeout` to the thin driver. Omit for the 20s driver default. Set a positive value to override; `0` is ignored by the driver and `doctor` warns. |
| `inactivity_timeout_seconds` | integer | none | no | Per-read inactivity deadline on an established session. Omit to keep the driver's default read behavior. Set a positive value to bound silent or half-open sessions; `0` is treated as unset and `doctor` warns. |
| `keepalive_minutes` | integer | none | no | Oracle dead-connection-detection probe interval (`EXPIRE_TIME`), in minutes. Omit to disable probes. Set a positive value to request keepalive probes; `0` is treated as unset and `doctor` warns. |
| `sdu` | integer | none | no | Thin Session Data Unit request size. Validated as `512..=65535`; omit to keep the negotiated default. |
| `login_script` | path | none | no | Path to a login script run on lease acquire. Restricted to allowlisted `ALTER SESSION SET …` parameters. |
| `login_statements` | array of strings | none | no | Inline login statements (allowlist-validated `ALTER SESSION SET …`). |
| `trusted_session_statements` | array of strings | none | no | Trusted local session setup, authored by the profile owner and **never** accepted from agent tool calls; run verbatim after the guarded login statements. |
| `base` | string | none | no | Inherit unset fields from another profile (shallow-merge, child wins). See [Base inheritance](#base-inheritance). |

### Sub-tables

| Sub-table | Purpose |
|---|---|
| `[profiles.oci]` | OCI / Autonomous DB connection fields (wallet/TLS/SNI and the IAM-token fields). See [Auth modes](#auth-modes). |
| `[profiles.drcp]` | Database Resident Connection Pooling server routing. |
| `[profiles.pool]` | Local client-side pool for stateless catalog/metadata reads where pool-backed reads are used. |
| `[profiles.masking]` | Result egress masking policy applied after SQL admission and before result JSON leaves the DB layer. |
| `[profiles.proxy_auth]` | Thin proxy authentication. |
| `[[profiles.app_context]]` | Driver-level application-context triples applied at logon (repeatable). |
| `[profiles.session_identity]` | End-to-end Oracle session identity (profile-local; redacted from `list_profiles`). |

#### `[profiles.oci]`

| Field | Type | Default | Effect |
|---|---|---|---|
| `wallet_location` | path | none | TCPS wallet directory. The default build loads `ewallet.pem`; other recognized wallet artifacts are diagnostic-only unless driver support is enabled later. |
| `wallet_password_ref` | string | none | Secret reference for an encrypted-wallet password. Use `env:`, `file:`, `keyring:`, or future `vault:` for production; `literal:` is dev-only and rejected when `protected = true`. |
| `ssl_server_dn_match` | bool | none (driver default) | Override server-certificate DN matching. |
| `ssl_server_cert_dn` | string | none | Exact expected server-certificate DN. |
| `use_sni` | bool | none (driver default) | Override TCPS SNI behavior. |
| `use_iam_token` | bool | `false` | Authenticate with an OCI IAM database token. When set, a pre-fetched token (a JWT) is resolved at connect time from `token_env`/`token_file`/`token_exec` (or the built-in `ORACLEMCP_IAM_TOKEN`) and injected over TCPS — see [Auth modes](#auth-modes). |
| `iam_config_profile` | string | none | `~/.oci/config` profile name for the IAM token. Parses; inert today (reserved for a future OCI-SDK token source). |
| `token_env` | string | none | Name of an environment variable holding the pre-fetched IAM token (a *reference*, not the token). When unset, the built-in `ORACLEMCP_IAM_TOKEN` is read. Resolved fresh on every connect; never persisted or logged. |
| `token_file` | string | none | Path to a file holding the pre-fetched IAM token, **re-read on every connect** so a rotated token is picked up without a restart. Takes precedence over `token_env`. A *reference* (path), never the token value. |
| `token_exec` | array of strings | none | Command argv used to fetch a pre-fetched IAM token from stdout. Mutually exclusive with `token_env` and `token_file`. The command is run directly with no shell, has a timeout and output cap, and is refused before spawn on non-TCPS connections. A *reference* (command argv), never the token value. |

#### `[profiles.drcp]`

| Field | Type | Default | Effect |
|---|---|---|---|
| `pooled` | bool | `false` | Request a DRCP pooled server (`SERVER=POOLED`). |
| `connection_class` | string | none | DRCP connection class (`pool_connection_class`). Requires `pooled = true`; validated as an EZConnect-safe token. |
| `purity` | enum | `reuse` | DRCP session purity: `reuse` or `new`. |

#### `[profiles.pool]`

Local client-side connection reuse for stateless catalog/metadata reads where
pool-backed reads are used. User SQL, sampled rows, LOB reads, transactions,
savepoints, package globals, login setup, session identity, and `DBMS_OUTPUT`
stay on the pinned main session. Served stateless HTTP uses bounded
per-subject/profile read-worker lanes for generated metadata reads instead of
sharing one pool across lane runtimes. This is **separate** from DRCP server
routing.

| Field | Type | Default | Effect |
|---|---|---|---|
| `max_size` | integer | `16` | Maximum pooled connections. Must be ≥ 1. This static default is the documented ceiling; the runtime clamps to `min(configured, cpu*2+1)`. |
| `min_idle` | integer | `2` | Minimum idle connections kept warm. Must be ≤ `max_size`. |
| `acquire_timeout_secs` | integer | `5` | Seconds to wait for a checkout before returning `BUSY`. Range: 1–3600. |
| `statement_cache_size` | integer | `50` | Per-connection statement-cache size passed to the thin driver. |

#### `[profiles.masking]`

Profile-scoped result masking for `oracle_query`-shaped result payloads. When
this table is present, `mask_unknown_default` must be `true`: any result column
not matched by a rule is masked rather than passed through.

| Field | Type | Default | Effect |
|---|---|---|---|
| `mask_unknown_default` | bool | `true` | Required to remain `true` in the current server-side masking seam. |
| `salt_ref` | string | none | Non-secret salt id/reference. Required when any rule uses `action = "tokenize"`; raw salt material is not stored in the profile. |
| `[[profiles.masking.rules]]` | array | `[]` | Ordered masking rules; first match wins. |

Every `tokenize` rule must resolve one exact active record from the private
`$XDG_STATE_HOME/oraclemcp/masking-salts.json` state file (or
`$HOME/.local/state/oraclemcp/masking-salts.json` without XDG). The file must
be mode `0600` or stricter. A missing, malformed, duplicate, retired, or
non-matching record makes startup/profile switching refuse; the server never
silently substitutes `"<masked>"` for a configured tokenization policy.

```json
{
  "kind": "oraclemcp.masking_salts.v1",
  "salts": [{
    "profile": "prod",
    "salt_id": "profile:prod:masking:v1",
    "created_at": "2026-07-13T00:00:00Z",
    "salt_b64": "base64url-no-pad-32-random-bytes",
    "status": "active"
  }]
}
```

`profile` and `salt_id` must exactly match the selected profile and configured
`salt_ref`. The raw `salt_b64` is never emitted in MCP, audit, diagnostics, or
mask certificates; certificates carry only `salt_id`. Rotation appends a new
active record for the new `salt_ref` and marks the prior one `retired`; new
served sessions then produce a new, non-linkable token scope.

Rule fields:

| Field | Type | Effect |
|---|---|---|
| `column_match` | inline table | Selector with optional `schema`/`table` and exactly one of `column` or `tag`. |
| `action` | enum | `mask`, `tokenize`, or `null`. |
| `tag` | string | Optional non-secret policy/audit tag. |

#### `[profiles.proxy_auth]`

| Field | Type | Default | Effect |
|---|---|---|---|
| `proxy_user` | string | none | Authenticating account that owns `credential_ref`. Required if the table is present. |
| `target_schema` | string | none | Target schema/client identity granted `CONNECT THROUGH proxy_user`. Required if the table is present. |

When set, a top-level `username` (if present) must match `proxy_user`. The
database needs `ALTER USER <target_schema> GRANT CONNECT THROUGH <proxy_user>`.

#### `[[profiles.app_context]]`

Repeatable (max 64 entries). Values are treated as sensitive and redacted from
`list_profiles`/diagnostics. A child inherits the base list when omitted,
replaces it when entries are set, and clears it with `app_context = []`.

| Field | Type | Default | Effect |
|---|---|---|---|
| `namespace` | string | — (required, non-empty) | Application-context namespace (≤ 128 chars). |
| `key` | string | — (required, non-empty) | Application-context key/name (≤ 128 chars). |
| `value` | string | `""` | Context value (empty allowed; ≤ 4000 chars). |

#### `[profiles.session_identity]`

All fields default to none and are profile-local (not shown by `list_profiles`).
Connect-time fields (`edition`, `program`, `machine`, `os_user`, `terminal`,
`driver_name`) are applied during thin authentication; `module`, `action`,
`client_identifier`, and `client_info` are applied post-connect through Oracle
session APIs. `oracle_connection_info` does not expose those values by default;
it reports allow-listed connection posture and lists present identity/topology
fields by name in `redacted_fields`.

---

## The operating-level ladder

Statements are graded on a monotonic ladder:

```
READ_ONLY  <  READ_WRITE  <  DDL  <  ADMIN
```

For each raw statement, the fail-closed classifier derives the **minimum** level
the statement needs; the level gate admits it only when the active session
already permits that level. A profile's `default_level` is the starting level
and `max_level` is the **immutable ceiling** — temporary elevation through
`oracle_set_session_level` can never exceed it, and `default_level` may not
exceed `max_level`.

**The protected invariant.** A `protected = true` profile pins its ceiling at
`READ_ONLY`: setting `max_level` above `READ_ONLY` on a protected profile is a
**config load error** (`ProtectedNotReadOnly`), caught at load rather than
silently weakening the lock. `read_only_standby = true` likewise forces
`READ_ONLY` regardless of `max_level`.

Exposure (`mcp_exposed`) is **not** part of this bound. The enforced limit on
what a profile can do is `max_level` / `protected` / `read_only_standby` / the
underlying DB account privileges / the classifier — never visibility.

---

## The `mcp_exposed` opt-out

`mcp_exposed` controls whether a profile is visible to the **MCP agent-facing
(served) surface** (E5 connection-scope isolation). It is a **per-profile
opt-out**:

- A profile is **exposed to the agent by default** (`mcp_exposed` defaults to
  `true`). Set `mcp_exposed = false` to **hide** one.
- A hidden profile is invisible to every agent-facing path:
  `oracle_list_profiles`, `oracle_switch_profile`, `oracle_search_objects`, and
  `completion/complete` all behave as if it does not exist. A hidden or guessed
  name is indistinguishable — both fail closed identically.
- The **operator/CLI always sees every profile** regardless of this flag:
  `oraclemcp profiles`, `oraclemcp doctor`, and `serve --profile <name>` use the
  full topology.
- There is **no global flip and no other knob**. One profile's setting **never**
  affects another's: hiding one profile leaves the rest exposed.
- `mcp_exposed` participates in `base` inheritance like any other scalar field: a
  base that sets `= false` propagates to a child that does not override it, and a
  child `= true` re-exposes.

This is a **visibility/scoping convenience, not an access control.** The real
bound on what an exposed profile can do is `max_level` / `protected` / DB
privileges / the fail-closed classifier (see [the ladder](#the-operating-level-ladder)).
Use it to keep an operator-only or privileged target out of the agent's view —
but pair it with a genuinely low `max_level` and a least-privilege DB account.

**Startup exposure log.** At startup the server emits a behavior-neutral,
operator-facing line to **stderr** summarizing exposure, e.g.:

```
MCP exposing 1 profile(s): dev_ro [ReadOnly] (1 hidden via mcp_exposed=false)
```

or, when nothing is exposed,
`MCP exposing 0 of N profile(s) — all hidden via mcp_exposed=false`. The line is
visibility-only — it changes no behavior — so an operator can confirm at a glance
that, e.g., a writable profile is reachable by the agent. Cross-profile exposure
is enumerated as a threat with its mitigation in
[`docs/threat-model.md`](threat-model.md).

---

## Credentials and secret references

`credential_ref`, `wallet_password_ref`, the audit active/historical
`key_ref` values, and the SIEM
`siem_auth_header_ref` are resolved through the SecretResolver seam and are
never surfaced in `list_profiles` metadata or diagnostics. Production profiles
should use external references; the `literal:` form is a development escape
hatch only and is rejected when `protected = true`. Supported forms:

| Form | Meaning |
|---|---|
| `env:VAR_NAME` | Read from the process environment at use time. |
| `file:/path/to/secret` | Read a local secret file; one trailing line ending is stripped. |
| `keyring:account` / `keyring:service/account` | Resolve through the OS keyring adapter (`ORACLEMCP_KEYRING_COMMAND`, then platform fallback). |
| `vault:path` | Future backend seam; fails closed unless a Vault resolver is wired. |
| `literal:value` | **Dev-only** inline value. **Rejected** when `protected = true`. |

Security-sensitive HMAC keys have an additional size requirement: resolved
`[audit].key_ref`, `[http.oauth].hs256_secret_ref`, and
`ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY` values must contain at least 32 bytes (256
bits). Generate random key material; empty, newline-only, and shorter values
fail closed during startup, verification, or `sign-tool` before use.

---

## Auth modes

| Mode | How to configure | Status |
|---|---|---|
| **Password** | `username` + `credential_ref` (for example `env:`, `file:`, `keyring:`; `literal:` dev-only). | Supported. |
| **Wallet / TCPS (TLS/mTLS)** | `[profiles.oci]` `wallet_location`, `ssl_server_dn_match`, `ssl_server_cert_dn`, `use_sni`; or a `tcps://…` / TLS-descriptor `connect_string`. The default build loads `ewallet.pem`; `cwallet.sso` and standalone `ewallet.p12` are recognized and reported with structured wallet diagnostics instead of a silent fallback. | `ewallet.pem` supported; other recognized wallet formats are diagnostic-only in the default build. |
| **OCI IAM database token** | `[profiles.oci]` `use_iam_token = true` + a token source (`token_env` / `token_file` / `token_exec`, or the built-in `ORACLEMCP_IAM_TOKEN`). | Simple env/file/exec token sources supported over TCPS (beta); an autonomous OCI-SDK token source is not yet wired — see below. |
| **Proxy** | `[profiles.proxy_auth]` `proxy_user` + `target_schema`; `credential_ref` belongs to `proxy_user`. Needs `ALTER USER <target_schema> GRANT CONNECT THROUGH <proxy_user>`. | Supported. |
| **DRCP routing** | `[profiles.drcp]` `pooled` / `connection_class` / `purity`. | Supported (server routing; orthogonal to auth). |
| **External/wallet-only (no user/pass), Kerberos, RADIUS** | — | Unsupported; reported with a structured unsupported-auth diagnostic (never a silent fallback). |

### OCI IAM database-token status

With `use_iam_token = true` under `[profiles.oci]`, the server resolves a
**pre-fetched** database token (a JWT) at connect time from one simple source
and injects it via the driver's `ConnectOptions::with_access_token`
(sent as `AUTH_TOKEN`, TCPS-enforced):

- **`token_file`** — a file holding the token; **re-read on every connect** so a
  rotated token is picked up without a restart (takes precedence).
- **`token_env`** — an environment variable holding the token; when unset, the
  built-in **`ORACLEMCP_IAM_TOKEN`** variable is read.
- **`token_exec`** — an argv array that prints the token to stdout. It is
  executed directly with no shell interpretation, has a timeout and stdout cap,
  and is refused before spawn on non-TCPS connections.

The token is a **reference**: only the env-var name, file path, or command argv
lives in config, and the token value is resolved transiently, never persisted,
rendered, or logged. An empty or missing token is a typed, fail-closed error.
Any token is **refused over a non-TCPS transport** before it reaches the driver
or before `token_exec` can spawn — a token must never travel in clear text
(defense in depth; the driver also rejects it). The `doctor` `IAM token` check
reads the JWT `exp` claim (diagnostic only, no signature validation) and
**warns when the token is expired or within 5 minutes of expiry** — never
printing the token.

`iam_config_profile` still only **parses** (inert), reserved for a future
autonomous OCI-SDK token source that mints/refreshes tokens from an instance
principal or `~/.oci/config` (the richer `IamTokenSource` / `ensure_fresh_token`
refresh seam). Non-TCPS refusal is covered by
`iam_token_over_non_tcps_is_refused_fail_closed` in
`crates/oraclemcp-db/src/connection.rs`, and env/file resolution + rotation +
non-leak by the `oraclemcp-core` `iam_token` tests. Full autonomous
token-minting over a live cloud lane remains a real-cloud (C5) smoke item.

---

## Transports

| Transport | How | Notes |
|---|---|---|
| **stdio** | Default (`oraclemcp serve`). | The parent process is the trust boundary. |
| **Streamable HTTP** | `serve --listen <addr>` + `[http]` / `--client-credentials`. | **Fails closed**: binds only with service-owned per-client credentials, OAuth bearer enforcement, mTLS client-certificate verification, or `--allow-no-auth`; a non-loopback bind requires `ORACLEMCP_HTTP_ALLOW_REMOTE=1`. `Host`/`Origin` allowlists apply. |

The HTTP router serves MCP only at `/mcp` and reserves `/operator/v1` for the
versioned operator API; product binaries may also serve the embedded operator
dashboard outside that API prefix. In stateful mode `/mcp` POST responses are
retained in a bounded in-process result buffer; clients can reconnect with
`GET /mcp?cursor=…` or `Last-Event-ID` to replay buffered SSE events. If the requested cursor has
fallen out of the retained ring, the server returns typed
`410 stream_cursor_expired` and the client must restart the MCP session.
Stateless `DELETE /mcp` is rejected with 405 rather than pretending a session
was closed. `/mcp` also honors `MCP-Protocol-Version`; an unsupported header is
rejected before JSON-RPC dispatch with typed JSON `400 unsupported_protocol_version`.

Native TLS automatically marks stateful MCP and dashboard session cookies
`Secure`. If a plaintext backend listener is reachable only through an HTTPS
terminator, set `[http].trusted_https_termination = true` as an explicit
operator assertion. The backend must not be directly reachable by clients:
oraclemcp deliberately ignores `Forwarded` and `X-Forwarded-*` scheme headers,
and this setting does not relax authentication, host/origin, or remote-bind
guards. Plaintext non-Secure session cookies are permitted only for a
server-observed loopback peer, preserving local development. A remote plaintext
MCP initialize still returns `Mcp-Session-Id` for non-browser clients but does
not mint a privileged browser cookie.

The browser dashboard is never authenticated by loopback alone. `oraclemcp
dashboard` mints a 0600 one-time ticket in the user runtime directory and opens
`/dashboard/pair?ticket=...`; the server consumes that ticket once, within 60
seconds, and returns an HttpOnly, SameSite=Strict dashboard session cookie.
That cookie is `Secure` under native TLS or asserted trusted HTTPS termination;
the only plaintext exception is the loopback pairing flow.
Dashboard session details are fetched from `/dashboard/session` and are kept out
of browser storage. Dashboard-originated `/operator/v1` POSTs additionally
require exact same-origin headers, a CSRF token, and a route-scoped action
ticket.

The dashboard Workbench uses those same action routes. It forwards classify
requests to `oracle_preview_sql`, read execution to `oracle_query`, and guarded
DML to `oracle_execute`; it does not expose a PTY, SQLcl shell, or alternate SQL
path. Browser-originated DDL/Admin apply is release-gated in this line: DDL can
be previewed, and applying it through the dashboard requires both
`[http].dashboard_workbench = true` and `dashboard_ddl_workbench = true` on the
active profile. Those flags do not raise the profile ceiling or bypass
confirmation, rollback, idempotency, or audit.

The Reviews board uses `/operator/v1/change-proposals`,
`/operator/v1/change-proposals/draft`, and
`/operator/v1/change-proposals/apply`. A proposal is scoped to one profile and
is stored as service-owned state without a lane binding; apply chooses the lane
at request time, re-classifies every stored `sql_template`, re-checks the active
level/grants/subject through the existing action route, and ignores any stored
proposal verdict. Agent DML proposals store parameterized SQL templates plus
captured binds rather than inlined literal SQL.

`[http]` fields: `allowed_hosts`, `allowed_origins` (both default `[]`,
loopback-only), `json_response` (default `false`), `stateful` (default `false`),
`stateful_idle_ttl_seconds` (default `900`, `0` disables idle reaping),
`dashboard_workbench` (default `false`), the optional `[http.oauth]`
resource-server table, the `[http.mtls]` client
fingerprint registry, the optional `[http.tls]` rustls material, and the
`[http.operator]` operator-authority table. Optional `[http.control]` starts a
second, separately bounded incident-response listener. It requires
`http.tls.client_ca_path`, at least one registered mTLS fingerprint, and the
matching `mtls:<fingerprint>` in `http.operator.allowed_subjects`. Its
`preauth_workers` (default 4), `operator_workers` (default 1), and
`doctor_workers` (default 1) are independently capped at 64; ordinary MCP and
dashboard routes are never served there. Idle
stateful sessions are reaped by sending a close message to the owning lane; the
watchdog never touches the Oracle connection from the HTTP thread. When OAuth or
per-client credentials are enabled, granted `oracle:*` scopes can only **lower**
the effective ceiling, never raise it, and protected profiles stay `READ_ONLY`.
Server-only TLS is transport encryption, not application authentication —
`/mcp` still needs per-client credentials, OAuth, mTLS, or `--allow-no-auth`.
The built-in HS256 verifier requires the resolved
`[http.oauth].hs256_secret_ref` to contain at least 32 bytes.
It accepts RFC 9068 JWT access tokens only: `typ` must be `at+jwt` or
`application/at+jwt` (case-insensitive), and the required `iss`, `sub`, `aud`,
`exp`, `client_id`, `iat`, and `jti` claims must have valid shapes. A generic
`typ=JWT`, a missing token type, or an ID token fails as `invalid_token`.
Adding `[http.tls.client_ca_path]` requires mTLS client certs, but only leaf DER
SHA-256 fingerprints listed in `[http.mtls].client_fingerprints` become
`mtls:sha256:<hex>` principals.

On `[http.control]`, TLS and registered-certificate identity complete before
the server parses any HTTP header. Unauthenticated handshakes consume only the
pre-authentication cap, never the authenticated operator/readiness reserve.
TLS handshake and HTTP header/body phases use monotonic absolute deadlines, so
a byte-trickling peer cannot retain either class indefinitely. The ordinary
listener keeps its existing fail-closed admission policy.

`[http.operator]` is binary in this line: a request is operator-authorized only
when it is the unauthenticated loopback local-owner path
(`allow_loopback_owner = true`, the default) or its server-derived principal key
is listed in `allowed_subjects`, for example `oauth:<stable-hash>` or
`mtls:sha256:<certificate-fingerprint>`. A regular OAuth-scoped principal is never an
operator merely by asking for it in a tool argument or query parameter. Operator
API actions require the signed audit chain; without an audit sink, `/operator/v1`
fails closed.

`/operator/v1` is schema-first. `GET /operator/v1/schema` serves the generated
bundle in `schemas/operator.schema.json`, and `ui/generated/operator-v1.ts`
contains the matching generated TypeScript types for the dashboard SPA. The
read-only operator routes are `GET /operator/v1/health`, `/metrics`,
`/audit-tail`, `/active-lanes`, `/vsession`, and `/events` (SSE). Every SSE event
carries `event_seq`, `event_id`, `lane_id`, `subject_id_hash`,
`redaction_level`, and `schema_version`. Gated-action routes under
`/operator/v1/actions/*` plus `/operator/v1/session/set-level` and
`/operator/v1/session/switch-profile` forward to the existing MCP guarded
`tools/call` path; they do not bypass SQL classification, profile ceilings, or
confirmation-token checks. These gated-action routes accept an
`Idempotency-Key` header or body `idempotency_key` / `request_id`; when absent,
the server derives a key from the route, tool, redacted subject, lane id,
lane generation, and action arguments. Same-key retries replay the original
redacted operator response, concurrent duplicates return typed
`operator_idempotency_in_progress`, and drift under the same key returns
`operator_idempotency_key_conflict`.

The browser health/stats mirror is the dashboard Overview, Health, and Capacity
pages over `GET /operator/v1/health`, `/metrics`, and active-lane summaries. It
is optional: the embedded browser assets are present only in binaries built with
the `dashboard-bundle` feature, and browser access still requires the paired
dashboard session rather than loopback alone.

---

## Base inheritance

A profile may set `base = "other_profile"` to inherit every **unset** field from
another profile (shallow-merge; the child wins on any field it sets). `name` and
`base` itself are never inherited. Inheritance is resolved **before** validation,
so a child still honors the effective `max_level` ceiling, the protected
invariant, and all other validation rules. The resolver detects unknown bases,
inheritance cycles, and duplicate profile names and rejects them at load.

For list-valued fields (`app_context`): a child inherits the base list when it
omits the field, replaces the whole list when it sets entries, and can clear an
inherited list with `app_context = []`.
