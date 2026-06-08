# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.1.0
