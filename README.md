<p align="center">
  <img src=".github/assets/hero.svg" alt="oraclemcp: safe-by-default Oracle Database MCP server in pure Rust" width="100%">
</p>

<p align="center">
  <a href="https://github.com/MuhDur/oraclemcp/actions/workflows/ci.yml"><img src="https://github.com/MuhDur/oraclemcp/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/oraclemcp"><img src="https://img.shields.io/crates/v/oraclemcp.svg" alt="crates.io"></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg" alt="license"></a>
  <img src="https://img.shields.io/badge/unsafe-forbidden-success.svg" alt="forbid(unsafe_code)">
  <img src="https://img.shields.io/badge/rustc-nightly--2026--05--11-orange.svg" alt="nightly-2026-05-11">
</p>

> **Safe-by-default Oracle Database MCP server, in pure Rust.**

`oraclemcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server that gives an AI agent safe-by-default access to an Oracle database: schema introspection, DDL, compile errors, source search, ad-hoc read queries, plan analysis, and an explicit profile-gated execution path for non-read SQL. Every raw statement the agent submits is classified *before* it can reach Oracle. Read tools only admit statements proven read-only; `oracle_execute` only runs statements permitted by the active profile/session level, rolls DML back by default, and requires a preview-derived confirmation token before commit. Session elevation is explicit, temporary, and capped by profile `max_level`. The core is engine-free and `#![forbid(unsafe_code)]`.

> _An independent open-source project; not affiliated with Oracle. For Oracle's own MCP servers, see [oracle/mcp](https://github.com/oracle/mcp)._

## Why oraclemcp

- **Fail-closed by construction.** A SELECT that an agent dreams up should never silently turn into a `DELETE`. Each raw statement runs through the hardened classifier. Read tools admit only **proven** read-only `SELECT`/`WITH` and dictionary introspection. Non-read execution is isolated in `oracle_execute`, bounded by profile `max_level`/`default_level`, rollback-by-default for DML, and explicit-confirm-before-commit. Temporary elevation through `oracle_set_session_level` can never exceed the profile ceiling. *Forbidden* constructs (multi-statement batches, string-concat dynamic SQL, an unproven function call inside a SELECT) are rejected before touching the database, with an `OperatingLevelTooLow` or `ForbiddenStatement` envelope and a suggested safe alternative.
- **Agent-first UX.** Every tool ships a real JSON Schema, title, and explicit MCP annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) so clients do not infer unsafe defaults. Errors are structured [`ErrorEnvelope`](crates/oraclemcp-error)s with machine-stable classes, fuzzy suggestions, and next-step hints, not bare strings. A zero-arg `oracle_capabilities` tool lets an agent discover the surface; MCP resources expose the capability/tool documents plus schema/object read templates; and an offline build degrades to a `RuntimeStateRequired` contract instead of crashing.
- **Pure Rust, no `unsafe`.** Every crate is `#![forbid(unsafe_code)]`; the fail-closed classifier carries a differential cargo-fuzz target.
- **Two transports.** stdio (default) and Streamable HTTP (`--listen`) with
  fail-closed auth defaults, optional OAuth bearer enforcement, and native
  rustls TLS/mTLS.

## Quick start

This branch is pinned to **`nightly-2026-05-11`**. The thin-native line has no
stable MSRV because the Asupersync/oracledb stack uses nightly-only language
features. The repository's `rust-toolchain.toml` selects the pin for local
builds; direct `cargo install` users should use the same toolchain.

```sh
rustup toolchain install nightly-2026-05-11 --component rustfmt --component clippy
```

Live database access is built in through the pure-Rust thin `oracledb` driver:

```sh
cargo +nightly-2026-05-11 install oraclemcp
```

**Runtime requirements** for live database access:

- Optionally `TNS_ADMIN` pointing at a directory with `tnsnames.ora` if you connect by net-service name.

No Oracle Instant Client, ODPI-C library, or C toolchain is required by the
driver.

Use `oraclemcp --json doctor` to verify the binary and offline setup, and
`oraclemcp --json doctor --profile <profile>` to add live connectivity,
authentication, role/open-mode, standby, and privilege checks. Doctor output is
safe to paste into agent sessions: it omits connect strings, usernames,
`credential_ref` values, passwords, proxy identities, wallet passwords, IAM
tokens, wallet paths, and server DNs while keeping
structured failure classes and ORA codes visible.

Generate generic local setup templates for profiles, wrappers, and MCP client
snippets:

```sh
oraclemcp --json setup --profile db_ro
```

**Docker:** a ready-to-run thin-driver image, published to GHCR and listed in the [MCP registry](https://registry.modelcontextprotocol.io) on release as `io.github.MuhDur/oraclemcp`. Mount a profiles config and pass the credential the profile's `credential_ref` expects:

```sh
docker run -i --rm \
  -v "$HOME/.config/oraclemcp:/root/.config/oraclemcp:ro" \
  -e ORACLE_APP_PASSWORD \
  ghcr.io/muhdur/oraclemcp:0.3.0          # MCP over stdio, against the configured profile

docker run -i --rm ghcr.io/muhdur/oraclemcp:0.3.0   # tool surface only (no DB)
```

> The Docker image and crates are Apache-2.0 OR MIT and do not redistribute Oracle Instant Client.

Wire it into an MCP client (e.g. Claude Desktop) over stdio:

```json
{
  "mcpServers": {
    "oracle": {
      "command": "oraclemcp",
      "args": ["serve", "--allow-no-auth"]
    }
  }
}
```

For Codex-style TOML config, the same command is:

```toml
[mcp_servers.oracle]
command = "oraclemcp"
args = ["serve", "--allow-no-auth"]
```

Or run it directly:

```sh
oraclemcp serve                      # stdio (default); --allow-no-auth for local dev
oraclemcp serve --listen 127.0.0.1:7070 --allow-no-auth   # local HTTP dev only
oraclemcp --json setup --profile db_ro    # generic onboarding templates
oraclemcp capabilities               # the advertised tool surface + feature tiers (JSON)
oraclemcp --json profiles            # configured profile names and non-secret metadata
oraclemcp doctor                     # offline diagnostics (thin driver, TNS/wallet, classifier, NLS)
oraclemcp doctor --profile dev_ro    # include live connectivity/auth/role/privilege checks
oraclemcp info                       # build info: version, tools, transports, thin DB
oraclemcp robot-docs guide           # compact in-binary guide for agents
```

`--json` is a visible alias for `--robot-json` and keeps stdout as a single
machine-readable JSON object.

The Streamable HTTP transport (`--listen`) fails closed. It starts only when
OAuth bearer enforcement is configured or `--allow-no-auth` is supplied, and it
refuses any non-loopback bind unless `ORACLEMCP_HTTP_ALLOW_REMOTE=1` is set.
OAuth configuration can come from `profiles.toml` or CLI flags:

```sh
export ORACLEMCP_OAUTH_HS256_SECRET='replace-with-a-long-random-secret'
oraclemcp serve --listen 127.0.0.1:7070 \
  --oauth-resource http://127.0.0.1:7070/mcp \
  --oauth-issuer https://issuer.example.com \
  --oauth-authorization-server https://issuer.example.com \
  --oauth-required-scope oracle:read \
  --oauth-hs256-secret-ref env:ORACLEMCP_OAUTH_HS256_SECRET \
  --http-allowed-host 127.0.0.1:7070 \
  --http-allowed-origin https://client.example.com
```

When OAuth is enabled, `/.well-known/oauth-protected-resource` stays public,
`/mcp` requires a valid bearer token, and granted `oracle:*` scopes lower the
request's effective operating ceiling monotonically. `oracle:read` caps the
request at `READ_ONLY`, `oracle:write`/`oracle:execute` at `READ_WRITE`,
`oracle:ddl` at `DDL`, and `oracle:admin` at `ADMIN`; none of them can raise a
profile above its `max_level`, and protected profiles remain `READ_ONLY`.

Native TLS uses rustls when `[http.tls]` or `--tls-cert` / `--tls-key` are
configured. Adding `[http.tls.client_ca_path]` or `--mtls-client-ca` requires
client certificates (mTLS) verified against that CA. Server-only TLS encrypts
the transport but is not application authentication, so `/mcp` still needs OAuth
or an explicit `--allow-no-auth` development opt-in. Non-loopback binds require
`ORACLEMCP_HTTP_ALLOW_REMOTE=1` even with TLS.

Connection profiles are resolved from layered configuration (`oraclemcp-config`); select one with `serve --profile <name>`.

### Connection profiles

For live database access, create `~/.config/oraclemcp/profiles.toml`:

```toml
schema_version = 1
default_profile = "dev_ro"

[http]
allowed_hosts = ["127.0.0.1:7070"]
allowed_origins = ["https://client.example.com"]
json_response = true
stateful = false

[http.oauth]
resource = "http://127.0.0.1:7070/mcp"
allowed_issuers = ["https://issuer.example.com"]
authorization_servers = ["https://issuer.example.com"]
required_scopes = ["oracle:read"]
hs256_secret_ref = "env:ORACLEMCP_OAUTH_HS256_SECRET"

# Optional native HTTPS / mTLS listener.
# [http.tls]
# cert_chain_path = "/path/to/server-chain.pem"
# private_key_path = "/path/to/server-key.pem"
# client_ca_path = "/path/to/client-ca.pem"  # require mTLS client certs

[[profiles]]
name = "dev_ro"
description = "Read-only development database"
connect_string = "localhost:1521/FREEPDB1"
username = "APP_READONLY"
credential_ref = "env:ORACLE_APP_PASSWORD"
max_level = "READ_ONLY"
default_level = "READ_ONLY"
require_signed_tools = true
# Optional Oracle per-round-trip timeout. Tool calls can override it with
# timeout_seconds where advertised.
call_timeout_seconds = 30
# Optional thin Session Data Unit request. Validated as 512..=65535 bytes.
sdu = 32768
login_statements = [
  "ALTER SESSION SET NLS_LANGUAGE = english",
  "ALTER SESSION SET PLSQL_WARNINGS = 'ENABLE:ALL'",
]
# Optional trusted local setup, authored by the profile owner and never by the
# agent. Use for session-local initialization that is not an ALTER SESSION.
trusted_session_statements = [
  "BEGIN DBMS_OUTPUT.ENABLE(500000); END;",
]

[profiles.oci]
# Optional TCPS/wallet fields. Prefer these named fields over raw
# connect_string query parameters when the value should be validated or redacted.
wallet_location = "/etc/oracle/wallet"
wallet_password_ref = "env:WALLET_PASSWORD"
ssl_server_dn_match = true
ssl_server_cert_dn = "CN=dbhost.example.com"
use_sni = true

# Optional proxy authentication. If enabled, `credential_ref` belongs to
# `proxy_user`; omit top-level `username` or set it to the same value.
# The database needs: ALTER USER <target_schema> GRANT CONNECT THROUGH <proxy_user>
# [profiles.proxy_auth]
# proxy_user = "MCP_PROXY"
# target_schema = "APP_OWNER"

# Optional DRCP server routing. Prefer these named fields over raw
# connect_string query parameters so inheritance, validation, and redaction stay
# predictable. This is separate from [profiles.pool], which controls local
# client-side reuse.
[profiles.drcp]
pooled = true
connection_class = "ORACLE_MCP_AGENTS"
purity = "reuse"

# Optional local client-side pool for stateless metadata/catalog reads.
# User SQL, LOB/sample reads, DBMS_OUTPUT, transactions, and session state stay
# on the pinned main session.
# [profiles.pool]
# max_size = 4
# min_idle = 1
# acquire_timeout_secs = 5
# statement_cache_size = 50

# Optional driver-level application context, applied during thin logon. Values
# can carry tenant/session identifiers, so list_profiles and diagnostics redact
# them. If inherited, setting entries here replaces the base list; omit to
# inherit or set app_context = [] in the profile table to clear it.
[[profiles.app_context]]
namespace = "ORACLEMCP_CTX"
key = "tenant_id"
value = "tenant-123"

[[profiles.app_context]]
namespace = "ORACLEMCP_CTX"
key = "request_id"
value = "req-456"

[profiles.session_identity]
# Optional: all values are profile-local and are not shown by list_profiles.
# oracle_connection_info reports the session-visible fields for verification.
# Edition selection is applied during thin authentication before user SQL.
# edition = "ORA$BASE"
program = "oraclemcp"
machine = "local-workstation"
os_user = "local-operator"
terminal = "agent"
driver_name = "oraclemcp"
module = "oraclemcp"
action = "inspect"
client_identifier = "agent"
client_info = "local-workstation"
```

`max_level` is the profile ceiling; `default_level` is the starting session
level and must not exceed that ceiling. `call_timeout_seconds` is an optional
Oracle per-round-trip timeout for the physical connection; read/write/compile
tools that expose `timeout_seconds` can override it for one call. Both settings
bound individual Oracle round trips, not the total wall-clock time of a
multi-round-trip operation. `login_statements` and `login_script` are for
profile-local session policy only and are restricted to allowlisted `ALTER
SESSION SET ...` parameters.
`trusted_session_statements` are an explicit profile-owner escape hatch for
local session initialization such as `DBMS_APPLICATION_INFO`, application
contexts, or `DBMS_OUTPUT`; they are never accepted from agent tool calls, and
they keep environment-specific conventions in private config rather than in the
open-source core.
The `oracle_connection_info` tool also reports diagnostic fields such as
`os_user`, `program`, `machine`, `terminal`, and `client_driver` when the
database exposes them. The Rust thin backend can set the connect-time client
identity fields (`program`, `machine`, `os_user`, `terminal`, and
`driver_name`) from profile config. It also applies `module`, `action`,
`client_identifier`, and `client_info` after connect through Oracle session
APIs, so operators can keep driver identity and DBMS session attributes
separate.
`require_signed_tools = true` requires HMAC signatures for operator-defined
custom tools on that profile; `protected = true` implies the same policy.

A few further profile keys are optional:

- `base = "other_profile"`: inherit from another profile and override only the
  keys you set. Inheritance is resolved before validation, so a child still
  honors the effective `max_level` ceiling.
- `[profiles.pool]`: local client-side connection reuse settings
  (`max_size`, `min_idle`, `acquire_timeout_secs`, `statement_cache_size`).
  This enables the hybrid runtime strategy: catalog and metadata tools such as
  schema/object/source inspection use a bounded stateless read pool, while
  agent queries, sampled rows, LOB reads, DDL/write previews, transactions,
  savepoints, temp tables, package globals, login setup, session identity, and
  `DBMS_OUTPUT` stay on the pinned main session. `statement_cache_size` is
  passed to the thin driver's bounded per-connection statement cache; omit it to
  keep the driver default. This is separate from DRCP server routing.
- `[profiles.oci]`: OCI-specific connection settings for the underlying driver.
  For TCPS/wallet connections, named fields are available for `wallet_location`,
  `wallet_password_ref`, `ssl_server_dn_match`, `ssl_server_cert_dn`, and
  `use_sni`. Use the named fields for values that should inherit through
  profiles, be redacted from diagnostics, or be validated by strict config
  parsing.
- `sdu = 32768`: optional thin driver Session Data Unit request size. Values are
  validated as `512..=65535`; omit it to keep the driver's negotiated default.
- `[profiles.drcp]`: Database Resident Connection Pooling server routing.
  `pooled = true` appends `server=pooled`; `connection_class` maps to
  `pool_connection_class`; `purity = "reuse" | "new"` maps to `pool_purity`.
  Existing `connect_string` query parameters such as `wallet_location` are
  preserved and DRCP parameters are appended with `&`. Prefer these named fields
  over raw DRCP query parameters when the values should inherit, validate, and be
  covered by redaction tests.
- `[profiles.proxy_auth]`: thin proxy authentication. `proxy_user` is the
  account that authenticates with `credential_ref`; `target_schema` is the
  Oracle user granted `CONNECT THROUGH`. The connect `username`, if present,
  must match `proxy_user`.
- `[[profiles.app_context]]`: driver-level application context triples sent
  during thin logon. Use typed `namespace` / `key` / `value` entries instead of
  raw strings; values are treated as sensitive and omitted from ordinary profile
  output. A child profile inherits the base list when omitted, replaces the whole
  list when entries are set, and can clear inherited entries with
  `app_context = []`.
- `read_only_standby = true`: mark the target as a read-only standby so the
  profile cannot be elevated above `READ_ONLY` regardless of `max_level`.

Then launch:

```sh
export ORACLE_APP_PASSWORD='...'
oraclemcp serve --allow-no-auth
```

Config discovery order is:

1. `$ORACLEMCP_CONFIG`
2. `~/.config/oraclemcp/profiles.toml`
3. `~/.config/oraclemcp/config.toml`

`credential_ref` and `wallet_password_ref` support `env:VAR` for
environment-injected credentials and `literal:value` for local development
only. Literal credentials are rejected when `protected = true`.

The current `oraclemcp` thin adapter fails explicitly for auth/features it
cannot serve end-to-end safely, such as external wallet auth without
username/password, OCI IAM token retrieval from local OCI config, and
Kerberos/RADIUS auth. These appear as structured unsupported diagnostics in
`oraclemcp doctor --profile <profile>` and MCP error envelopes; the binary does
not silently fall back to thick mode. The published `oracledb` 0.2.2 driver has
lower-level access-token support, but `oraclemcp` does not yet wire a complete
IAM token source and refresh flow into connection profiles.

Thin result conversion materializes driver-side locators and cursors before
serializing tool output: CLOB/BLOB/BFILE locators are read with the query LOB
caps, and valid REF CURSOR values or implicit result sets are returned as nested
objects containing child `columns`, `rows`, `row_count`, `fetched_count`, and
`truncated` metadata. Nested cursor materialization has separate row, cell, byte,
and depth caps, and unsupported shapes remain explicit instead of silently
flattening or guessing.

To live-verify driver-level application context against Oracle 23ai/FREE, create
an application context namespace in the test database, configure matching
`[[profiles.app_context]]` triples, then query
`SYS_CONTEXT('<namespace>', '<key>')` through `oracle_query` or run the optional
live test with `ORACLEMCP_TEST_APP_CONTEXT='namespace:key:value;namespace:key2:value2'`.
Invalid or unauthorized context namespaces should fail at connect time with a
structured Oracle server error rather than falling back to post-connect SQL.

To live-verify edition selection against Oracle 23ai/FREE, create or reuse a
valid edition, set `[profiles.session_identity].edition`, connect with that
profile, and query `SYS_CONTEXT('USERENV','CURRENT_EDITION_NAME')` through
`oracle_query` or `oracle_connection_info`. Invalid or unauthorized editions
should fail during connect/authentication with a structured Oracle server error;
oraclemcp must not silently fall back to the database default edition.

Profile/config regression commands:

```sh
# Local, non-secret profile parsing/redaction/setup checks.
cargo test -p oraclemcp-config -p oraclemcp-core profile -- --nocapture
cargo test -p oraclemcp setup_payload_is_generic_and_client_ready -- --nocapture
cargo test -p oraclemcp profiles_json_reports_non_secret_metadata -- --nocapture

# Live Oracle 23ai/FREE thin profile/config matrix.
# Required: ORACLEMCP_TEST_DSN, ORACLEMCP_TEST_USER, ORACLEMCP_TEST_PASSWORD.
# Optional: ORACLEMCP_TEST_WALLET_LOCATION, ORACLEMCP_TEST_WALLET_PASSWORD,
# ORACLEMCP_TEST_SSL_SERVER_DN_MATCH, ORACLEMCP_TEST_SSL_SERVER_CERT_DN,
# ORACLEMCP_TEST_USE_SNI, ORACLEMCP_TEST_PROXY_USER,
# ORACLEMCP_TEST_PROXY_TARGET_SCHEMA, ORACLEMCP_TEST_EDITION,
# ORACLEMCP_TEST_APP_CONTEXT, ORACLEMCP_TEST_DRCP=1,
# ORACLEMCP_TEST_DRCP_CLASS.
cargo test -p oraclemcp-db --features live-xe --test live_oracle -- --nocapture

# Faster profile-only smoke subset.
cargo test -p oraclemcp-db --features live-xe live_profile_config -- --nocapture
```

If `serve --profile <name>` is provided, it overrides `default_profile`. If neither is set and exactly one profile exists, that sole profile is used.

Agents can inspect available profiles with `oracle_list_profiles` and reconnect
the running MCP server with `oracle_switch_profile`. A failed switch leaves the
current connection in place.
`oraclemcp serve --profile <name>` fails fast when the profile or config cannot
be resolved. Without an explicit profile, startup keeps discovery available even
when the default live connection cannot be opened; live database calls then
return structured tool errors instead of crashing the MCP server.

### Operator-defined read-only tools

Operators can expose environment-specific read helpers without forking the
server by placing TOML files in `~/.config/oraclemcp/tools.d/*.toml`. Set
`ORACLEMCP_TOOLS_DIR` to use a different directory. Definitions are loaded and
advertised when `serve` starts, then revalidated before `oracle_switch_profile`
replaces the active connection; malformed files fail closed instead of silently
disappearing.

```toml
[[tool]]
name = "app_customer_lookup"
description = "Lookup customer rows by id"
sql = "SELECT id, name, status FROM app_customers WHERE id = :id"
output_mode = "rows"

[[tool.params]]
name = "id"
type = "integer"
required = true
description = "Customer id"
```

Custom tool SQL uses named binds (`:id` above). Agent-supplied values are typed
from `params` and bound by name; they are never interpolated into SQL text. The
binary only loads definitions the classifier proves are `READ_ONLY`, even if a
profile permits a higher ceiling. Write, DDL, PL/SQL block, and unproven package
call definitions are rejected at load time.

On protected profiles, every custom tool must carry a valid HMAC signature. Set
`ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY` in the server environment to verify signed
definitions. On unprotected profiles, unsigned tools are allowed for local use;
if any definition includes a `signature`, the same key is required and invalid
signatures are rejected.

Sign local tool definitions from the same binary:

```sh
export ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY='...'
oraclemcp sign-tool ~/.config/oraclemcp/tools.d/customer.toml --tool app_customer_lookup
```

The command prints the signature values to place into matching `[[tool]]`
blocks; it does not print the HMAC key.

## Tools

| Tool | Purpose |
| --- | --- |
| `oracle_list_profiles` | List configured connection profiles without exposing connect strings, usernames, or credential references |
| `oracle_connection_info` | Describe the active profile and connection; if live metadata is unavailable, returns `connected=false` with a structured `connection_error` and `next_actions` |
| `oracle_switch_profile` | Reconnect the server to another configured profile |
| `oracle_set_session_level` | Preview/apply a temporary session operating-level elevation within the profile ceiling, or drop back to `READ_ONLY` |
| `oracle_query` | Run a read-only `SELECT`/`WITH` (paginated, parameter-bound) |
| `oracle_preview_sql` | Classify SQL and report whether it is read-only, needs profile-permitted step-up, or exceeds the active profile ceiling, without executing it |
| `oracle_execute` | Execute one non-read statement through the active profile/session gate; DML rolls back by default, while commits and DDL/Admin require the confirmation token from `oracle_preview_sql`; optionally captures bounded `DBMS_OUTPUT` |
| `oracle_compile_object` | Preview or compile one PL/SQL/view object through the `DDL` profile gate; execution requires the confirmation token returned by preview |
| `oracle_create_or_replace` | Preview or apply one `CREATE OR REPLACE` statement through the classifier and `DDL` profile gate |
| `oracle_patch_source` | Preview or apply an exact `old_text`→`new_text` patch to one stored PL/SQL source object (package/body/type/view) through the classifier and `DDL` profile gate; TOCTOU-safe, re-fetching the current source and re-confirming at execute time |
| `oracle_list_schemas` | List schemas that own objects visible to this session |
| `oracle_schema_inspect` | List objects in the current schema, one owner, or all accessible schemas |
| `oracle_describe` | Column and constraint metadata for a table or view |
| `oracle_describe_index` | Index metadata, indexed columns, and function-based expressions |
| `oracle_describe_trigger` | Trigger timing, target table, status, and body |
| `oracle_describe_view` | View definition metadata and columns |
| `oracle_get_ddl` | `DBMS_METADATA` DDL for an object |
| `oracle_get_source` | Full source text for a package, procedure, function, trigger, or type; omit `object_type` to return every visible source variant for the object name |
| `oracle_sample_rows` | Safely sample the first rows of a table or view |
| `oracle_read_clob` | Read one capped CLOB/NCLOB/text value by key |
| `oracle_compile_errors` | Compile errors for the current schema, an owner, or one PL/SQL object |
| `oracle_search_source` | Search `ALL_SOURCE` for a needle; optionally use `owner="*"`, `object_type`, and `name_like` to widen or narrow scope |
| `oracle_plscope_inspect` | Read PL/Scope identifiers/statements for one object and report unused declarations plus dynamic-SQL lines when metadata is populated |
| `oracle_explain_plan` | Diagnostic `EXPLAIN PLAN` for a vetted read-only statement; writes `PLAN_TABLE` and requires `READ_WRITE` plus `allow_plan_table_write=true` |
| `oracle_capabilities` | Zero-arg discovery: tools, operating level, feature tiers |

Every advertised tool descriptor includes a human title plus explicit MCP
annotations. Read-only tools set `readOnlyHint=true`,
`destructiveHint=false`, `idempotentHint=true`, and `openWorldHint=false`.
Guarded execution, session elevation, compile, patch, deploy, and diagnostic
write tools set `destructiveHint=true` and `readOnlyHint=false`. These hints
are advisory for MCP clients; the fail-closed classifier and operating-level
gate remain the enforcement boundary.
`oracle_query`/`query` and `oracle_explain_plan` also advertise
`outputSchema` for their `structuredContent`; the query schema keeps Oracle
`NUMBER` cells as strings by default unless the caller explicitly opts into
`numbers_as_float=true`.

### MCP resources

In addition to `tools/list` and `tools/call`, initialize advertises
`resources` with `subscribe=false` and `listChanged=false`.
`resources/list` exposes concrete static resources for `oracle://capabilities`
and `oracle://tools`. `resources/templates/list` exposes read templates for
`oracle://schema/{owner}` and `oracle://object/{owner}/{type}/{name}`; reading
those routes through the same safe tool dispatch path as
`oracle_schema_inspect`, `oracle_get_source`, and `oracle_get_ddl`, including
the active transport authorization context. `prompts/list` and `prompts/get`
serve the built-in expert playbook catalog. Completion, subscriptions, and
lease-backed `oracle://session/{lease_id}` resources are not advertised in this
release.

### Compatibility aliases

For migrations from shorter Oracle MCP tool surfaces, the server also advertises
compatibility aliases that route to the guarded `oracle_*` tools:

| Alias | Routes to |
| --- | --- |
| `current_database` | `oracle_connection_info` |
| `switch_database` | `oracle_switch_profile` (`db` is accepted as an alias for `profile`) |
| `enable_writes` | `oracle_set_session_level` with `level=READ_WRITE`; preview is still the default |
| `disable_writes` | `oracle_set_session_level` with `action=drop`; immediately returns the session to `READ_ONLY` |
| `query` | `oracle_query` |
| `preview_sql` | `oracle_preview_sql` |
| `execute_approved` | Compatibility wrapper around `oracle_execute`; token-only calls work for five minutes after `preview_sql` in the same server process |
| `compile_object` | `oracle_compile_object` |
| `compile_with_warnings` | `oracle_compile_object` with `warnings=true` |
| `create_or_replace` | `oracle_create_or_replace` |
| `deploy_ddl` | Compatibility wrapper for one DDL statement; preview by default, execution reuses the same DDL profile gate and confirmation |
| `patch_package` | `oracle_patch_source` for a package spec or body |
| `patch_view` | `oracle_patch_source` for a view |
| `read_patch_preview` | Compatibility helper that lists or reads the last in-process source-patch preview created by `oracle_patch_source`, `patch_package`, or `patch_view` |
| `list_objects` | `oracle_schema_inspect` |
| `list_schemas` | `oracle_list_schemas` |
| `get_schema` | `oracle_schema_inspect` |
| `describe_table` | `oracle_describe` |
| `describe_index` | `oracle_describe_index` |
| `describe_trigger` | `oracle_describe_trigger` |
| `describe_view` | `oracle_describe_view` |
| `get_ddl` | `oracle_get_ddl` |
| `get_object_source` | `oracle_get_source` |
| `get_errors` | `oracle_compile_errors` |
| `get_clob` | `oracle_read_clob` |

Aliases share the same SQL classifier, argument validation, profile handling,
and operating-level behavior as their `oracle_*` targets.

`oracle_query` and the inner SQL of `oracle_explain_plan` pass through the read-only gate. `oracle_explain_plan` is not a pure read on Oracle primary databases: `EXPLAIN PLAN` writes `PLAN_TABLE`, so the tool refuses by default, refuses on read-only standby, and only runs when the active session is already `READ_WRITE` and the caller passes `allow_plan_table_write=true`. `oracle_preview_sql` runs the classifier without executing the SQL and includes the active profile ceiling so agents can distinguish "allowed on this profile", "requires a higher profile/session level", and "blocked by policy." When a non-read statement is currently executable, `oracle_preview_sql` also returns `execute_confirmation.confirm`; pass that value to `oracle_execute` with `commit=true` only when you intend to commit that exact statement on the active profile. The dictionary tools build their own parameterized SQL and never execute caller-supplied statements.

Confirmation tokens are process-local preview tokens. Regenerate them after
restarting the server or switching profiles.

When a statement is allowed by the profile ceiling but above the current session
level, call `oracle_set_session_level` first without `execute=true`. The preview
returns the target level, TTL, gate decision, and a confirmation token. A second
call with `execute=true` and that token applies a temporary elevation window.
Lowering to a less-capable level is allowed without a token; use
`oracle_set_session_level` with `action="drop"` (or the `disable_writes` alias)
to return the session to `READ_ONLY`. Elevation cannot raise `max_level`; if a
profile ceiling is `READ_ONLY`, write/DDL/admin work remains blocked and the
next action is selecting a different profile.

## Safety model

Statements are graded on an operating-level ladder:

```
READ_ONLY  <  READ_WRITE  <  DDL  <  ADMIN
```

Profiles default to **`READ_ONLY`** unless the operator explicitly sets a higher `default_level`, and `max_level` is an immutable ceiling for that profile. For every raw statement, the classifier derives the *minimum* level the statement needs; the level gate then admits it only when the active session already permits that level. Everything else is refused fail-closed, and a statement the classifier cannot prove safe is treated as dangerous, never the reverse. The classifier is whitespace-, comment-, quote-, and batch-aware (it fails closed on desynchronized multi-statement input), and is continuously exercised by a differential adversarial corpus and a cargo-fuzz target.

`oracle_set_session_level` is the only general session-elevation tool. It never
touches database data, never raises the profile ceiling, and defaults to
preview. Elevating to `READ_WRITE`, `DDL`, or `ADMIN` requires the preview token
and creates a bounded window (default 900 seconds, maximum 3600 seconds).
Lowering to a less-capable level is immediate and does not require a token.

`oracle_execute` is intentionally narrow. It accepts one statement with positional binds, refuses read-only SQL (use `oracle_query`), refuses anything above the active profile/session level, rolls DML back unless `commit=true`, and requires the `oracle_preview_sql` confirmation token before any commit. DDL/Admin statements cannot be rollback-previewed by Oracle, so they require `commit=true` plus confirmation before execution. Set `capture_dbms_output=true` to enable `DBMS_OUTPUT` before the statement and return bounded output after the commit or rollback; `dbms_output_max_lines` and `dbms_output_max_chars` cap the response.

Cancellation and timeouts are fail-closed at the DB boundary. A cancelled or
failed pooled call is treated as an uncertain Oracle session and is discarded
instead of returned to idle reuse. Lease-backed preview DML rolls back to its
savepoint even when cancellation is observed after the DML; if that cleanup
fails, the lease is force-rolled-back and dropped.

`oracle_compile_object` is the structured alternative to handcrafting `ALTER ... COMPILE`. A call without `execute=true` only previews the validated compile statements, required `DDL` level, gate decision, and confirmation token. A second call with `execute=true` and that token runs the compile and returns current `ALL_ERRORS` rows for the object. Set `plscope=true` to enable PL/Scope collection before compiling, or `warnings=true` to enable `PLSQL_WARNINGS='ENABLE:ALL'` before compiling. Both options remain profile-gated at `DDL`; `compile_with_warnings` is a compatibility alias for the warnings path.

`oracle_create_or_replace` is the structured deployment macro for one full
`CREATE OR REPLACE` statement. It validates that the source has the expected
shape, classifies it, defaults to preview, and applies only through the same
confirmation token and `DDL` session/profile gate as `oracle_execute`. When it
can infer the target object from a simple package/procedure/function/trigger/
type/view name, the apply result includes current compile errors for that
object.

`deploy_ddl` is a compatibility wrapper over that same path. It accepts `name`
and `wait_seconds` for older callers, returns them in the response, and executes
synchronously in the generic core.

`oracle_patch_source`, `patch_package`, and `patch_view` preview exact
`old_text` to `new_text` replacements against current stored source. The
`read_patch_preview` compatibility helper can list or return the last remembered
in-process patch preview for the active profile, but the applying call must
still pass the confirmation token from the preview.

### Least-privilege database account

The classifier and the per-DB operating-level ceiling are the *enforced*
control, but they are strongest when paired with a database account that simply
**cannot** write — defense in depth. For a read-only profile, connect as a
least-privilege user (ideally a [proxy
user](#connection-profiles) so individual identity is preserved in the audit
trail) granted only:

```sql
-- Minimum: connect + read the data dictionary the read tools rely on.
CREATE USER mcp_ro IDENTIFIED BY <secret>;
GRANT CREATE SESSION TO mcp_ro;
GRANT SELECT ANY DICTIONARY TO mcp_ro;   -- powers schema_inspect / get_ddl / describe
-- Then grant SELECT only on the specific objects the agent should read, e.g.:
GRANT SELECT ON app.customers TO mcp_ro;
-- For proxy auth (preferred), let the proxy connect as the read-only target:
ALTER USER mcp_ro GRANT CONNECT THROUGH mcp_proxy;
```

Grant **no** write-implying system privileges (`CREATE TABLE`, `INSERT/UPDATE/
DELETE ANY TABLE`, `CREATE/ALTER ANY PROCEDURE`, `ALTER SYSTEM`, …). For a
read-write profile, grant only the specific object DML/DDL the agent needs, and
keep the profile `max_level` no higher than that work requires.

`oraclemcp doctor --profile <p>` includes a **Write posture** check (11): with a
live connection it reads the session's own `SESSION_PRIVS` and reports a
read-only posture when the principal holds no write-implying system privilege, or
**warns** (naming the offending privileges) when it can write. The same check
reports the supported TCPS wallet modes — auto-login `cwallet.sso`, unencrypted
`ewallet.pem`, and password-protected `ewallet.p12` (via `wallet_password` /
`wallet_password_ref`) are all supported.

## Architecture

The engine-free MCP core is a small, one-way dependency DAG; no crate here imports a PL/SQL analysis engine (a boundary the CI enforces):

```
oraclemcp-error                          structured, agent-facing error envelope (leaf)
oraclemcp-telemetry  → error             tracing / health-endpoint observability
oraclemcp-audit      → error             durable fsync-before-execute audit hash-chain
oraclemcp-guard      → audit, error      fail-closed SQL classifier + operating levels
oraclemcp-config     → guard, error      layered configuration + connection profiles
oraclemcp-db         → guard, error      Oracle connectivity, pooling, NLS-stable serializer, dictionary ops
oraclemcp-auth       → audit, guard, …   transport auth: OAuth 2.1, mTLS, init token
oraclemcp-core       → all of the above  MCP protocol surface, server, tool registry, capabilities
oraclemcp            → core, db, …        this binary
```

## oraclemcp vs. plsql-mcp

`oraclemcp` is the lean half of a two-binary family:

- **`oraclemcp`** (this repo): the engine-free Oracle **database** MCP server for safe DB access. Reach for it when you want schema introspection, guarded reads, and tightly gated SQL execution without a PL/SQL analysis engine.
- **`plsql-mcp`** (in [plsql-intelligence](https://github.com/MuhDur/plsql-intelligence)): the full **superset**. Everything here *plus* offline PL/SQL code intelligence (parse/analyze, dependency graph, lineage, SAST, impact analysis) and richer PL/SQL workflows. Reach for it when you want deep PL/SQL understanding, not just database access. Available as `docker run -i ghcr.io/muhdur/plsql-mcp` and in the MCP registry as `io.github.MuhDur/plsql-mcp`.

## Offline behavior

If no profile is configured or Oracle is unreachable, `oraclemcp` falls back to
a stub connection: `serve`, `capabilities`, and `doctor` all work, and any live
tool call returns a structured error envelope rather than crashing. This makes
the binary safe to install, inspect, and test anywhere, CI included.

## About Contributions

*About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
