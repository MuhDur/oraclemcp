<p align="center">
  <img src=".github/assets/hero.svg" alt="oraclemcp — safe-by-default Oracle Database MCP server in pure Rust" width="100%">
</p>

<p align="center">
  <a href="https://github.com/MuhDur/oraclemcp/actions/workflows/ci.yml"><img src="https://github.com/MuhDur/oraclemcp/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/oraclemcp"><img src="https://img.shields.io/crates/v/oraclemcp.svg" alt="crates.io"></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg" alt="license"></a>
  <img src="https://img.shields.io/badge/unsafe-forbidden-success.svg" alt="forbid(unsafe_code)">
  <img src="https://img.shields.io/badge/rustc-1.88%2B-orange.svg" alt="MSRV 1.88">
</p>

> **Safe-by-default Oracle Database MCP server, in pure Rust.**

`oraclemcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server that gives an AI agent safe-by-default access to an Oracle database: schema introspection, DDL, compile errors, source search, ad-hoc read queries, plan analysis, and an explicit profile-gated execution path for non-read SQL. Every raw statement the agent submits is classified *before* it can reach Oracle. Read tools only admit statements proven read-only; `oracle_execute` only runs statements permitted by the active profile/session level, rolls DML back by default, and requires a preview-derived confirmation token before commit. The core is engine-free and `#![forbid(unsafe_code)]`.

> _An independent open-source project; not affiliated with Oracle. For Oracle's own MCP servers, see [oracle/mcp](https://github.com/oracle/mcp)._

## Why oraclemcp

- **Fail-closed by construction.** A SELECT that an agent dreams up should never silently turn into a `DELETE`. Each raw statement runs through the hardened classifier. Read tools admit only **proven** read-only `SELECT`/`WITH` and dictionary introspection. Non-read execution is isolated in `oracle_execute`, bounded by profile `max_level`/`default_level`, rollback-by-default for DML, and explicit-confirm-before-commit. *Forbidden* constructs (multi-statement batches, string-concat dynamic SQL, an unproven function call inside a SELECT) are rejected before touching the database, with an `OperatingLevelTooLow` or `ForbiddenStatement` envelope and a suggested safe alternative.
- **Agent-first UX.** Every tool ships a real JSON Schema. Errors are structured [`ErrorEnvelope`](crates/oraclemcp-error)s with machine-stable classes, fuzzy suggestions, and next-step hints, not bare strings. A zero-arg `oracle_capabilities` tool lets an agent discover the surface, and an offline build degrades to a `RuntimeStateRequired` contract instead of crashing.
- **Pure Rust, no `unsafe`.** Every crate is `#![forbid(unsafe_code)]`; the fail-closed classifier carries a differential cargo-fuzz target.
- **Two transports.** stdio (default) and Streamable HTTP (`--listen`).

## Quick start

```sh
cargo install oraclemcp
```

The default build is **offline** (no native dependencies), ideal for CI and for trying the tool surface. For live database access, build with the `live-db` feature, which pulls the ODPI-C Oracle driver (needs [Oracle Instant Client](https://www.oracle.com/database/technologies/instant-client.html)):

```sh
cargo install oraclemcp --features live-db
```

**Docker:** a ready-to-run image with Oracle Instant Client bundled (so live-db works out of the box), published to GHCR and listed in the [official MCP registry](https://registry.modelcontextprotocol.io) as `io.github.MuhDur/oraclemcp`:

```sh
docker run -i --rm ghcr.io/muhdur/oraclemcp:0.1.0   # MCP over stdio
```

> The Docker image bundles Oracle Instant Client (Oracle Free Use Terms) and is therefore a mixed-license artifact; the crates themselves are Apache-2.0 OR MIT.

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

Or run it directly:

```sh
oraclemcp serve                      # stdio (default); --allow-no-auth for local dev
oraclemcp serve --listen 127.0.0.1:7070   # Streamable HTTP (bind loopback only)
oraclemcp capabilities               # the advertised tool surface + feature tiers (JSON)
oraclemcp doctor                     # offline diagnostics (classifier self-test, NLS, …)
oraclemcp info                       # build info: version, tools, transports, live-db
```

Connection profiles are resolved from layered configuration (`oraclemcp-config`); select one with `serve --profile <name>`.

### Connection profiles

For live database access, create `~/.config/oraclemcp/profiles.toml`:

```toml
schema_version = 1
default_profile = "dev_ro"

[[profiles]]
name = "dev_ro"
description = "Read-only development database"
connect_string = "localhost:1521/FREEPDB1"
username = "APP_READONLY"
credential_ref = "env:ORACLE_APP_PASSWORD"
max_level = "READ_ONLY"
default_level = "READ_ONLY"
login_statements = [
  "ALTER SESSION SET NLS_LANGUAGE = english",
  "ALTER SESSION SET PLSQL_WARNINGS = 'ENABLE:ALL'",
]
# Optional trusted local setup, authored by the profile owner and never by the
# agent. Use for session-local initialization that is not an ALTER SESSION.
trusted_session_statements = [
  "BEGIN DBMS_OUTPUT.ENABLE(500000); END;",
]

[profiles.session_identity]
# Optional: all values are profile-local and are not shown by list_profiles.
# oracle_connection_info reports the session-visible fields for verification.
edition = "ORA$BASE"
module = "oraclemcp"
action = "inspect"
client_identifier = "agent"
client_info = "local-workstation"
driver_name = "oraclemcp"
```

`max_level` is the profile ceiling; `default_level` is the starting session
level and must not exceed that ceiling. `login_statements` and `login_script`
are for profile-local session policy only and are restricted to allowlisted
`ALTER SESSION SET ...` parameters.
`trusted_session_statements` are an explicit profile-owner escape hatch for
local session initialization such as `DBMS_APPLICATION_INFO`, application
contexts, or `DBMS_OUTPUT`; they are never accepted from agent tool calls, and
they keep environment-specific conventions in private config rather than in the
open-source core.
The `oracle_connection_info` tool also reports diagnostic fields such as
`os_user`, `program`, and `client_driver` when the database exposes them. In the
current Rust backend, profile config can set the session identity fields shown
above and the driver name, but `os_user` and `program` remain backend-reported
values unless the underlying driver exposes setters for them.

Then launch:

```sh
export ORACLE_APP_PASSWORD='...'
oraclemcp serve --allow-no-auth
```

Config discovery order is:

1. `$ORACLEMCP_CONFIG`
2. `~/.config/oraclemcp/profiles.toml`
3. `~/.config/oraclemcp/config.toml`

`credential_ref` supports `env:VAR` for environment-injected credentials and `literal:value` for local development only. Literal credentials are rejected when `protected = true`.

If `serve --profile <name>` is provided, it overrides `default_profile`. If neither is set and exactly one profile exists, that sole profile is used.

Agents can inspect available profiles with `oracle_list_profiles` and reconnect
the running MCP server with `oracle_switch_profile`. A failed switch leaves the
current connection in place.

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

## Tools

| Tool | Purpose |
| --- | --- |
| `oracle_list_profiles` | List configured connection profiles without exposing usernames or credential references |
| `oracle_connection_info` | Describe the active connection: backend, version, role, open mode, read-only database status, session context, and current schema |
| `oracle_switch_profile` | Reconnect the server to another configured profile |
| `oracle_query` | Run a read-only `SELECT`/`WITH` (paginated, parameter-bound) |
| `oracle_preview_sql` | Classify SQL and report whether it is read-only, needs profile-permitted step-up, or exceeds the active profile ceiling, without executing it |
| `oracle_execute` | Execute one non-read statement through the active profile/session gate; DML rolls back by default, while commits and DDL/Admin require the confirmation token from `oracle_preview_sql` |
| `oracle_compile_object` | Preview or compile one PL/SQL/view object through the `DDL` profile gate; execution requires the confirmation token returned by preview |
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
| `oracle_explain_plan` | Execution plan for a read-only statement |
| `oracle_capabilities` | Zero-arg discovery: tools, operating level, feature tiers |

### Compatibility aliases

For migrations from shorter Oracle MCP tool surfaces, the server also advertises
compatibility aliases that route to the guarded `oracle_*` tools:

| Alias | Routes to |
| --- | --- |
| `current_database` | `oracle_connection_info` |
| `switch_database` | `oracle_switch_profile` (`db` is accepted as an alias for `profile`) |
| `query` | `oracle_query` |
| `preview_sql` | `oracle_preview_sql` |
| `compile_object` | `oracle_compile_object` |
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

`oracle_query` and `oracle_explain_plan` accept a raw statement and so pass through the read-only gate. `oracle_preview_sql` runs that classifier without executing the SQL and includes the active profile ceiling so agents can distinguish "allowed on this profile", "requires a higher profile/session level", and "blocked by policy." When a non-read statement is currently executable, `oracle_preview_sql` also returns `execute_confirmation.confirm`; pass that value to `oracle_execute` with `commit=true` only when you intend to commit that exact statement on the active profile. The dictionary tools build their own parameterized SQL and never execute caller-supplied statements.

## Safety model

Statements are graded on an operating-level ladder:

```
READ_ONLY  <  READ_WRITE  <  DDL  <  ADMIN
```

Profiles default to **`READ_ONLY`** unless the operator explicitly sets a higher `default_level`, and `max_level` is an immutable ceiling for that profile. For every raw statement, the classifier derives the *minimum* level the statement needs; the level gate then admits it only when the active session already permits that level. Everything else is refused fail-closed, and a statement the classifier cannot prove safe is treated as dangerous, never the reverse. The classifier is whitespace-, comment-, quote-, and batch-aware (it fails closed on desynchronized multi-statement input), and is continuously exercised by a differential adversarial corpus and a cargo-fuzz target.

`oracle_execute` is intentionally narrow. It accepts one statement with positional binds, refuses read-only SQL (use `oracle_query`), refuses anything above the active profile/session level, rolls DML back unless `commit=true`, and requires the `oracle_preview_sql` confirmation token before any commit. DDL/Admin statements cannot be rollback-previewed by Oracle, so they require `commit=true` plus confirmation before execution.

`oracle_compile_object` is the structured alternative to handcrafting `ALTER ... COMPILE`. A call without `execute=true` only previews the validated compile statements, required `DDL` level, gate decision, and confirmation token. A second call with `execute=true` and that token runs the compile and returns current `ALL_ERRORS` rows for the object. Set `plscope=true` to enable PL/Scope collection before compiling; this is still profile-gated at `DDL`.

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

Without `live-db`, `RustOracleConnection::connect` returns `BackendNotCompiled` and `oraclemcp` falls back to a stub connection: `serve`, `capabilities`, and `doctor` all work, and any live tool call returns a structured `RuntimeStateRequired` envelope rather than crashing. This makes the binary safe to install, inspect, and test anywhere, CI included.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
