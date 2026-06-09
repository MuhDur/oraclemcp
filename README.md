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

`oraclemcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server that gives an AI agent **read-only** access to an Oracle database: schema introspection, DDL, compile errors, source search, ad-hoc query, and plan analysis, all behind a **fail-closed SQL guard**. Every statement the agent submits is classified *before* it can reach Oracle, and anything not provably read-only is refused with a structured, actionable error. The core is engine-free and `#![forbid(unsafe_code)]`.

> _An independent open-source project; not affiliated with Oracle. For Oracle's own MCP servers, see [oracle/mcp](https://github.com/oracle/mcp)._

## Why oraclemcp

- **Fail-closed by construction.** A SELECT that an agent dreams up should never silently turn into a `DELETE`. Each raw statement runs through the hardened classifier and only **proven** read-only `SELECT`/`WITH` and dictionary introspection execute. Writes, DDL, DCL, and *forbidden* constructs (multi-statement batches, string-concat dynamic SQL, an unproven function call inside a SELECT) are rejected before touching the database, with an `OperatingLevelTooLow` or `ForbiddenStatement` envelope and a suggested safe alternative.
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

[profiles.session_identity]
# Optional: all values are profile-local and are not shown by list_profiles.
module = "oraclemcp"
action = "inspect"
client_identifier = "agent"
client_info = "local-workstation"
driver_name = "oraclemcp"
```

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

## Tools

| Tool | Purpose |
| --- | --- |
| `oracle_list_profiles` | List configured connection profiles without exposing usernames or credential references |
| `oracle_connection_info` | Describe the active connection: backend, version, role, open mode, and current schema |
| `oracle_switch_profile` | Reconnect the server to another configured profile |
| `oracle_query` | Run a read-only `SELECT`/`WITH` (paginated, parameter-bound) |
| `oracle_schema_inspect` | List objects in the current schema, one owner, or all accessible schemas |
| `oracle_describe` | Column metadata for a table or view |
| `oracle_describe_index` | Index metadata, indexed columns, and function-based expressions |
| `oracle_describe_trigger` | Trigger timing, target table, status, and body |
| `oracle_describe_view` | View definition metadata and columns |
| `oracle_get_ddl` | `DBMS_METADATA` DDL for an object |
| `oracle_get_source` | Full source text for a package, procedure, function, trigger, or type |
| `oracle_sample_rows` | Safely sample the first rows of a table or view |
| `oracle_read_clob` | Read one capped CLOB/NCLOB/text value by key |
| `oracle_compile_errors` | Compile errors for the current schema, an owner, or one PL/SQL object |
| `oracle_search_source` | Search `ALL_SOURCE` for a needle |
| `oracle_explain_plan` | Execution plan for a read-only statement |
| `oracle_capabilities` | Zero-arg discovery: tools, operating level, feature tiers |

`oracle_query` and `oracle_explain_plan` accept a raw statement and so pass through the read-only gate; the dictionary tools build their own parameterized SQL and never execute caller-supplied statements.

## Safety model

Statements are graded on an operating-level ladder:

```
READ_ONLY  <  READ_WRITE  <  DDL  <  ADMIN
```

This binary runs at **`READ_ONLY`**. For every raw statement, the classifier derives the *minimum* level the statement needs; the level gate then admits it only if that level is `READ_ONLY`. Everything else is refused fail-closed, and a statement the classifier cannot prove safe is treated as dangerous, never the reverse. The classifier is whitespace-, comment-, quote-, and batch-aware (it fails closed on desynchronized multi-statement input), and is continuously exercised by a differential adversarial corpus and a cargo-fuzz target.

The building blocks for *guarded writes* (single-use execution grants, step-up confirmation, an fsync-before-execute audit chain) live in `oraclemcp-guard` / `oraclemcp-audit` / `oraclemcp-auth` and back the broader product; this `0.1` binary deliberately ships the read-only surface only.

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

- **`oraclemcp`** (this repo): the engine-free Oracle **database** MCP server for safe, read-only DB access. Reach for it when you want schema introspection and guarded queries.
- **`plsql-mcp`** (in [plsql-intelligence](https://github.com/MuhDur/plsql-intelligence)): the full **superset**. Everything here *plus* offline PL/SQL code intelligence (parse/analyze, dependency graph, lineage, SAST, impact analysis) and guarded writes. Reach for it when you want deep PL/SQL understanding, not just database access. Available as `docker run -i ghcr.io/muhdur/plsql-mcp` and in the MCP registry as `io.github.MuhDur/plsql-mcp`.

## Offline behavior

Without `live-db`, `RustOracleConnection::connect` returns `BackendNotCompiled` and `oraclemcp` falls back to a stub connection: `serve`, `capabilities`, and `doctor` all work, and any live tool call returns a structured `RuntimeStateRequired` envelope rather than crashing. This makes the binary safe to install, inspect, and test anywhere, CI included.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
