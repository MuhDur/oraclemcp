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
2. `~/.config/oraclemcp/profiles.toml`
3. `~/.config/oraclemcp/config.toml`

### Layer precedence

Values are composed with strict precedence, lowest to highest:

```
built-in defaults  <  config file (TOML)  <  environment (ORACLEMCP_*)  <  CLI overrides
```

The environment layer reads `ORACLEMCP_*` variables (nested keys split on `__`).
A set of launcher/control variables are explicitly **ignored** as config keys so
they never become "unknown key" errors: `ORACLEMCP_CONFIG`, `ORACLEMCP_LOG`,
`ORACLEMCP_STDIO_TOKEN`, `ORACLEMCP_TOOLS_DIR`, `ORACLEMCP_AUDIT_KEY`,
`ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY`, and the `ORACLEMCP_TEST_*` live-test vars.

### Strictness

Parsing is **strict and fail-fast**:

- **`deny_unknown_fields`** — any unrecognized key (top-level, in `[http]`,
  `[audit]`, or any profile sub-table) is rejected. A misspelled field is a load
  error, never a silently-ignored no-op.
- **Validation at load** — the whole config is validated when it is loaded (the
  server fails to start on an invalid config rather than discovering a problem
  mid-session).
- **Forward-incompatible versions rejected** — a config declaring a
  `schema_version` higher than the build supports is rejected.

---

## Top-level fields

| Field | Type | Default | Effect |
|---|---|---|---|
| `schema_version` | integer | `1` | Config schema version this build understands. A higher value than the build supports is rejected (forward-incompatible). |
| `default_profile` | string | none | Profile used when the launcher does not pass `serve --profile <name>`. Must name a defined profile. With no `default_profile` and exactly one profile, that sole profile is used. |
| `[http]` | table | stdio-only | Native Streamable HTTP transport (see [Transports](#transports)). |
| `[audit]` | table | safe defaults | Out-of-band signed audit log (see [`operations.md`](operations.md) §5.4–§5.6). |
| `[[profiles]]` | array of tables | `[]` | Named Oracle connection profiles (see below). |

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
| `credential_ref` | string | none | no | Reference to the credential in a secrets backend. **Never a literal secret**; never surfaced in `list_profiles` metadata. See [Credentials and secret references](#credentials-and-secret-references). |

### Operating level and protection

| Field | Type | Default | Required | Effect |
|---|---|---|---|---|
| `max_level` | enum | `READ_ONLY` | no | Per-target operating-level ceiling. Immutable cap; session elevation can never exceed it. See [the ladder](#the-operating-level-ladder). |
| `default_level` | enum | `READ_ONLY` | no | The level a fresh session starts at. Must not exceed `max_level` (else config load error). |
| `protected` | bool | `false` | no | Production profile: pins the ceiling immutable. When `true`, `max_level` **must** be `READ_ONLY` (else load error) and `literal:` secret refs are rejected. Implies `require_signed_tools`. |
| `require_signed_tools` | bool | `false` | no | Require a valid HMAC signature for every operator-defined custom tool loaded with this profile. A `protected` profile implies this even when unset. |
| `read_only_standby` | bool | `false` | no | Mark the target as a read-only standby (Active Data Guard): forces `READ_ONLY` regardless of `max_level`. |
| `mcp_exposed` | bool | `true` | no | E5 per-profile MCP exposure (opt-out). See [The `mcp_exposed` opt-out](#the-mcp_exposed-opt-out). |

### Session and routing

| Field | Type | Default | Required | Effect |
|---|---|---|---|---|
| `call_timeout_seconds` | integer | `30` | no | Oracle call timeout and total request-budget ceiling, in seconds. Omit for the 30s default. Set `0` only to disable the driver call timeout deliberately; `doctor` warns. Tools exposing `timeout_seconds` can tighten the budget for one call but cannot loosen the profile ceiling. |
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
| `[profiles.pool]` | Local client-side pool for stateless catalog/metadata reads. |
| `[profiles.proxy_auth]` | Thin proxy authentication. |
| `[[profiles.app_context]]` | Driver-level application-context triples applied at logon (repeatable). |
| `[profiles.session_identity]` | End-to-end Oracle session identity (profile-local; redacted from `list_profiles`). |

#### `[profiles.oci]`

| Field | Type | Default | Effect |
|---|---|---|---|
| `wallet_location` | path | none | Cloud wallet directory (`cwallet.sso` + `tnsnames.ora`). |
| `wallet_password_ref` | string | none | Secret reference for an encrypted-wallet password. Never a literal. |
| `ssl_server_dn_match` | bool | none (driver default) | Override server-certificate DN matching. |
| `ssl_server_cert_dn` | string | none | Exact expected server-certificate DN. |
| `use_sni` | bool | none (driver default) | Override TCPS SNI behavior. |
| `use_iam_token` | bool | `false` | Authenticate with an OCI IAM database token. **Parses but fails closed today** — see [Auth modes](#auth-modes). |
| `iam_config_profile` | string | none | `~/.oci/config` profile name for the IAM token. Parses; inert today. |

#### `[profiles.drcp]`

| Field | Type | Default | Effect |
|---|---|---|---|
| `pooled` | bool | `false` | Request a DRCP pooled server (`SERVER=POOLED`). |
| `connection_class` | string | none | DRCP connection class (`pool_connection_class`). Requires `pooled = true`; validated as an EZConnect-safe token. |
| `purity` | enum | `reuse` | DRCP session purity: `reuse` or `new`. |

#### `[profiles.pool]`

Local client-side connection reuse for stateless catalog/metadata reads. User
SQL, sampled rows, LOB reads, transactions, savepoints, package globals, login
setup, session identity, and `DBMS_OUTPUT` stay on the pinned main session. This
is **separate** from DRCP server routing.

| Field | Type | Default | Effect |
|---|---|---|---|
| `max_size` | integer | `16` | Maximum pooled connections. Must be ≥ 1. This static default is the documented ceiling; the runtime clamps to `min(configured, cpu*2+1)`. |
| `min_idle` | integer | `2` | Minimum idle connections kept warm. Must be ≤ `max_size`. |
| `acquire_timeout_secs` | integer | `5` | Seconds to wait for a checkout before returning `BUSY`. Must be ≥ 1. |
| `statement_cache_size` | integer | `50` | Per-connection statement-cache size passed to the thin driver. |

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

`credential_ref`, `wallet_password_ref`, the audit `key_ref`, and the SIEM
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

---

## Auth modes

| Mode | How to configure | Status |
|---|---|---|
| **Password** | `username` + `credential_ref` (for example `env:`, `file:`, `keyring:`; `literal:` dev-only). | Supported. |
| **Wallet / TCPS (TLS/mTLS)** | `[profiles.oci]` `wallet_location` (+ `wallet_password_ref` for an encrypted wallet), `ssl_server_dn_match`, `ssl_server_cert_dn`, `use_sni`; or a `tcps://…` / TLS-descriptor `connect_string`. Auto-login `cwallet.sso`, unencrypted `ewallet.pem`, and password-protected `ewallet.p12` are all supported. | Supported. |
| **OCI IAM database token** | `[profiles.oci]` `use_iam_token = true` (+ optional `iam_config_profile`). | **Parses, fails closed today** — see below. |
| **Proxy** | `[profiles.proxy_auth]` `proxy_user` + `target_schema`; `credential_ref` belongs to `proxy_user`. Needs `ALTER USER <target_schema> GRANT CONNECT THROUGH <proxy_user>`. | Supported. |
| **DRCP routing** | `[profiles.drcp]` `pooled` / `connection_class` / `purity`. | Supported (server routing; orthogonal to auth). |
| **External/wallet-only (no user/pass), Kerberos, RADIUS** | — | Unsupported; reported with a structured unsupported-auth diagnostic (never a silent fallback). |

### OCI IAM database-token status

The fields `use_iam_token` (bool) and `iam_config_profile` (`Option<String>`)
under `[profiles.oci]` **parse** through strict config validation, but the pinned
`oracledb` 0.5.1 thin adapter **fails closed on an IAM-token connect today**:

- The driver exposes the lower-level primitive
  (`ConnectOptions::with_access_token`, sent as `AUTH_TOKEN`), but `oraclemcp`
  wires **no production OCI token source**. A `use_iam_token = true` profile
  therefore returns a structured **unsupported-auth diagnostic** pointing at the
  as-yet-unwired IAM token-source seam, rather than connecting.
- Any database access token is **refused over a non-TCPS transport** before it
  can reach the driver — a token must never travel in clear text (defense in
  depth; the driver also rejects it).

This parse-but-fail-closed behavior is covered by the
`iam_token_over_non_tcps_is_refused_fail_closed` test in
`crates/oraclemcp-db/src/connection.rs`. End-to-end IAM-token support
(production OCI SDK token source + refresh) is **deferred (bead k6q.9)**.

---

## Transports

| Transport | How | Notes |
|---|---|---|
| **stdio** | Default (`oraclemcp serve`). | The parent process is the trust boundary. |
| **Streamable HTTP** | `serve --listen <addr>` + `[http]`. | **Fails closed**: binds only with OAuth bearer enforcement or `--allow-no-auth`; a non-loopback bind requires `ORACLEMCP_HTTP_ALLOW_REMOTE=1`. `Host`/`Origin` allowlists apply. |

The HTTP router serves MCP only at `/mcp` and reserves `/operator/v1` for the
versioned operator API; product binaries may also serve the embedded operator
dashboard outside that API prefix. In stateful mode `/mcp` POST responses are
retained in a bounded in-process result buffer; clients can reconnect with
`GET /mcp?cursor=…` or `Last-Event-ID` to replay buffered SSE events. If the requested cursor has
fallen out of the retained ring, the server returns typed
`410 stream_cursor_expired` and the client must restart the MCP session.
Stateless `DELETE /mcp` is rejected with 405 rather than pretending a session
was closed.

`[http]` fields: `allowed_hosts`, `allowed_origins` (both default `[]`,
loopback-only), `json_response` (default `false`), `stateful` (default `false`),
`stateful_idle_ttl_seconds` (default `900`, `0` disables idle reaping), the
optional `[http.oauth]` resource-server table, and the optional `[http.tls]`
rustls material. Idle stateful sessions are reaped by sending a close message to
the owning lane; the watchdog never touches the Oracle connection from the HTTP
thread. When OAuth is enabled, granted `oracle:*` scopes can only
**lower** the effective ceiling, never raise it, and protected profiles stay
`READ_ONLY`. Server-only TLS is transport encryption, not application
authentication — `/mcp` still needs OAuth or `--allow-no-auth`. Adding
`[http.tls.client_ca_path]` requires mTLS client certs.

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
