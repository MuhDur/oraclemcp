# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — Unreleased

This is the thin-native line: Oracle Instant Client/ODPI-C thick mode, Tokio,
rmcp, Axum, and Hyper have been removed from the production server. The server
now builds around the pure-Rust `oracledb` driver, native MCP transports, and
Asupersync runtime boundaries. Because this removes thick-mode/stable-MSRV
assumptions, the next release is minor rather than patch.

### Added

- Thin-native performance and footprint evidence in
  `docs/performance-footprint.md`, including release binary size, Docker image
  size, startup/RSS measurements, synthetic read serialization, classifier
  throughput, package sizes, Docker smoke, and Unix pipe behavior.
- Deterministic Asupersync tests for cancellation cleanup, request quiescence,
  preview-token one-shot races, guard-before-I/O behavior, OAuth token
  redaction, and live-XE skip/pass coverage.
- Native stdio and Streamable HTTP transports with golden behavior and MCP
  conformance tests, removing the rmcp/Axum/Hyper runtime surface.
- Release automation for synchronized crates.io, GitHub release, GHCR, and MCP
  registry publication from a single version tag.
- Thin profile coverage for proxy authentication, wallet username/password
  connections, TLS DN/SNI options, application contexts, SDU, DRCP connect-string
  shaping, and edition selection during authentication.
- Bounded DBMS_OUTPUT capture for `oracle_execute` / `execute_approved`, returned
  inline as `dbms_output.lines` without writing operator files.
- Binary-level Streamable HTTP configuration for Host/Origin allowlists,
  JSON-vs-streaming responses, stateful sessions, OAuth protected-resource
  metadata, OAuth issuer/resource/scope validation, HS256 secret references,
  and native rustls TLS/mTLS.
- Native MCP resource handlers for `resources/list`,
  `resources/templates/list`, and `resources/read`; static capability/tool
  resources resolve directly, while schema/object resource reads route through
  the same guarded dispatch path as the read tools.

### Changed

- Live Oracle access now uses the pure-Rust thin `oracledb` 0.2.2 driver by
  default.
  The runtime no longer requires Oracle Instant Client, ODPI-C, r2d2, or a C
  Oracle connectivity library.
- Query serialization now materializes thin LOB locators, REF CURSOR cells, and
  implicit result sets under the existing response-size caps.
- Profile `statement_cache_size` now reaches the thin driver's bounded
  per-connection statement cache instead of being metadata-only.
- The workspace is pinned to `nightly-2026-05-11`; stable/MSRV claims were
  removed because the thin-native Asupersync/oracledb stack is nightly-bound.
- Docker images are thin-driver images and do not redistribute Oracle Instant
  Client.
- CLI stdout emission is fallible, so large JSON commands such as
  `oraclemcp capabilities | head -c 1200` exit cleanly instead of printing a
  Rust broken-pipe panic.

### Security

- CI now hard-fails if forbidden production dependencies return: Tokio,
  asupersync-tokio-compat, rmcp, Axum, Hyper, `oracle`, ODPI-C, r2d2, reqwest,
  async-std, smol, or related removed crate families.
- HTTP OAuth scope validation is enforced at dispatch so bearer-token scopes can
  only lower effective authority and never raise profile/session ceilings.
- `oraclemcp serve --listen` now starts only with configured OAuth enforcement
  or explicit `--allow-no-auth`; native rustls TLS/mTLS is served when
  `[http.tls]` or `--tls-*` material is configured. Server-only TLS encrypts
  the transport but does not replace OAuth or mTLS client-certificate
  authentication.

## [0.2.1] — 2026-06-15

This release turns the read-only preview into a full safe-by-default Oracle MCP
server: connection profiles, a complete read surface, a profile-gated write
path, operator-defined custom tools, and compatibility aliases for older Oracle
MCP clients.

### Added

- **Connection profile system** — layered `profiles.toml` with `default_profile`,
  profile inheritance via `base`, `env:`/`literal:` credential references, an
  immutable `max_level` ceiling with a `default_level` starting point, optional
  `pool`/`oci` settings, and `read_only_standby`. Agents can list profiles
  (`oracle_list_profiles`) and reconnect a running server with
  `oracle_switch_profile`; a failed switch leaves the current connection in
  place.
- **Session identity and local session policy** — per-profile
  `session_identity` (module, action, client identifier, driver name, …),
  allowlisted `login_statements`/`login_script` (`ALTER SESSION SET ...` only),
  and `trusted_session_statements` as a profile-owner escape hatch for local
  initialization (`DBMS_APPLICATION_INFO`, application contexts, `DBMS_OUTPUT`).
  None of these are ever accepted from agent tool calls.
- **Full read tool surface** — `oracle_get_source`, `oracle_sample_rows`,
  `oracle_read_clob`, `oracle_describe_index`, `oracle_describe_trigger`,
  `oracle_describe_view`, constraint metadata in `oracle_describe`,
  `oracle_list_schemas`, `oracle_plscope_inspect`, and owner/type/`name_like`
  filters on `oracle_schema_inspect` and `oracle_search_source`.
- **Profile-gated write path** — `oracle_preview_sql` (classify without
  executing, reporting whether SQL is read-only, needs a profile-permitted
  step-up, or exceeds the ceiling); `oracle_execute` (one non-read statement,
  rollback-by-default for DML, confirmation token required before any commit);
  `oracle_create_or_replace`; `oracle_patch_source` plus the `patch_package`/
  `patch_view` aliases (exact `old_text`→`new_text` patches, re-fetched and
  re-confirmed at execute); `oracle_compile_object` (with `plscope`/`warnings`);
  `deploy_ddl`; and `oracle_set_session_level` for explicit, bounded session
  elevation within the profile ceiling.
- **Operator-defined read-only custom tools** — environment-specific read
  helpers from `tools.d/*.toml` with named binds, loaded only when the
  classifier proves them `READ_ONLY`, with optional HMAC signing
  (`sign-tool`, `ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY`) required on protected
  profiles.
- **Compatibility aliases** for older/shorter Oracle MCP clients
  (`current_database`, `switch_database`, `enable_writes`, `disable_writes`,
  `query`, `preview_sql`, `execute_approved`, `compile_object`,
  `compile_with_warnings`, `create_or_replace`, `deploy_ddl`, `patch_package`,
  `patch_view`, `read_patch_preview`, `list_objects`, `list_schemas`,
  `get_schema`, `describe_*`, `get_ddl`, `get_object_source`, `get_errors`,
  `get_clob`), all routing through the same classifier, validation, and gates.
- **CLI** — `doctor` (offline self-test plus optional live connectivity/role/
  privilege checks), `profiles` (configured profile names and non-secret
  metadata), and `robot-docs` (compact in-binary guide for agents).

### Changed

- Omitted MCP tool arguments (`null`) are now treated as an empty object, so
  zero-arg and all-optional tools no longer reject `null` argument payloads.

### Fixed

- `OracleConnectOptions`’ `Debug` output now redacts credentials instead of
  printing them.

### Security

- Confirmation tokens are now keyed HMAC tokens rather than guessable
  identifiers, hardening the preview-to-commit handshake.
- The patch body-override marker scan is tokenizer-based and resistant to
  comment-wedge evasion, so a crafted comment can no longer smuggle a body
  override past the check.
- The Streamable HTTP transport (`--listen`) is now fail-closed: it refuses to
  start without `--allow-no-auth`, and refuses non-loopback binds unless
  `ORACLEMCP_HTTP_ALLOW_REMOTE=1` is set.

## [0.1.0] — 2026-06-08

Initial public release of `oraclemcp` — an unofficial, engine-free,
safe-by-default Oracle Database [MCP](https://modelcontextprotocol.io) server in
pure Rust. (Not affiliated with Oracle Corporation.)

### Added

- **`oraclemcp` binary** — a Model Context Protocol server exposing a read-only
  Oracle database tool surface over **stdio** (default) and **Streamable HTTP**
  (`--listen`). CLI: `serve`, `info`, `doctor`, `capabilities`, with a global
  `--robot-json`.
- **Seven read-only tools** — `oracle_query`, `oracle_schema_inspect`,
  `oracle_describe`, `oracle_get_ddl`, `oracle_compile_errors`,
  `oracle_search_source`, `oracle_explain_plan` — plus the zero-arg
  `oracle_capabilities` discovery tool.
- **Fail-closed SQL guard** — every raw statement (`oracle_query`,
  `oracle_explain_plan`) is classified before it can reach Oracle; only
  statements proven `READ_ONLY` run. Writes, DDL/DCL, and forbidden constructs
  (multi-statement batches, string-concat dynamic SQL, unproven function calls
  in a SELECT) are refused with a structured `OperatingLevelTooLow` /
  `ForbiddenStatement` envelope and a suggested safe alternative.
- **Agent-first UX** — per-tool JSON Schemas, structured `ErrorEnvelope`s with
  machine-stable classes, fuzzy suggestions, and next-step hints; an offline
  build degrades to a `RuntimeStateRequired` contract instead of crashing.
- **Engine-free crate family** (all `#![forbid(unsafe_code)]`):
  `oraclemcp-error`, `oraclemcp-telemetry`, `oraclemcp-audit`,
  `oraclemcp-guard`, `oraclemcp-config`, `oraclemcp-db`, `oraclemcp-auth`,
  `oraclemcp-core` — a one-way dependency DAG that imports no PL/SQL analysis
  engine.
- **Live database access** behind the opt-in `live-db` feature (ODPI-C via the
  `oracle` crate / Oracle Instant Client). The default build is fully offline
  with no native dependencies.

### Security

- The classifier is whitespace-, comment-, quote-, and batch-aware and fails
  closed on desynchronized multi-statement input. It carries a differential
  adversarial corpus (run in CI) and a `cargo-fuzz` target.

[0.3.0]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.3.0
[0.2.1]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.2.1
[0.1.0]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.1.0
