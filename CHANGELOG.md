# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.3] — 2026-07-02

### Fixed

- Recut the 0.6.2 release train as 0.6.3 after the pushed `v0.6.2` tag
  failed in release gates before publishing crates, binaries, GHCR images, or
  MCP registry metadata.
- Fixed the Windows installer static-analysis gate by making the invalid-PATH
  catch block explicit and renaming the PowerShell helper to use an approved
  singular noun.

### Included

- Publishes the advanced dashboard release line: Change-Review board,
  schema-diff and migration export workflows, the selected 2D BigBoard
  signature skin, and release-gated per-view acceptance for those surfaces.
- Publishes the one-line install/update experience: guided TTY flow,
  non-interactive agent path, self-update, Windows installer parity, and
  structured JSON-line installer acceptance evidence.

## [0.6.2] — 2026-07-02

> The `v0.6.2` tag was pushed, but its workflow failed in release gates before
> external artifacts were published. Use `0.6.3`.

### Added

- Prepared the advanced dashboard release line: Change-Review board, schema-diff
  and migration export workflows, the selected 2D BigBoard signature skin, and
  release-gated per-view acceptance for those surfaces.
- Prepared the one-line install/update experience: guided TTY flow,
  non-interactive agent path, self-update, Windows installer parity, and
  structured JSON-line installer acceptance evidence.

### Fixed

- First-run setup now writes a bootable starter profile, doctor reports exact
  remediation, and generated MCP snippets include paste-ready profile/path
  wiring.
- Fresh-host installers no longer hard-fail when cosign is absent at the
  default verification posture; SHA-256 remains mandatory and stricter
  `require` mode is available.

## [0.6.1] — 2026-07-02

### Changed

- Cut the interactive dashboard release line: governed Workbench, full dashboard
  views, plsql-intelligence IDE wiring, global search, version history, and the
  W8b proof bundle are release-gated through the B.8 dashboard acceptance suite.
- The tag release workflow now validates the npm wrapper package without making
  core signed releases fail on externally gated npm registry credentials. Actual
  npm publication remains in the manual `publish-npm.yml` workflow until npm
  package ownership or trusted publishing is configured.

## [0.6.0] — 2026-07-02

### Upgrade Notes

- See [`docs/upgrading-to-0.6.0.md`](docs/upgrading-to-0.6.0.md) for the
  operator checklist covering result JSON consumers, config schema 2 fields,
  HTTP lane/profile-switch behavior, lane-bound confirmation grants, audit
  migration, and dashboard Workbench gates.
- Query serialization now exposes structured Oracle values through the
  versioned `OracleCell.structured` contract instead of relying on
  ordinary-looking placeholder strings for non-text shapes. Consumers that
  inspect raw query JSON, including `plsql-mcp` catalog snapshot importers,
  should handle the structured contract-version tag, typed
  ARRAY/JSON/VECTOR/TSTZ/object/unsupported variants, and explicit
  truncation/cap markers. The default agent-facing caps remain conservative;
  larger catalog extraction must opt into `deep_decode` and explicit structured
  row/cell/byte/depth caps.
- Audit records now write `schema_version = 3` when they include expanded
  server-derived subject and DB evidence fields. Existing signed v1/v2 audit
  logs continue to verify; no log rewrite is required.
- Config files remain on `schema_version = 2`. Schema 1 configs still load, but
  use schema 2 for the new default-safe `monitor_profile`,
  `[http].dashboard_workbench`, and per-profile `dashboard_ddl_workbench`
  fields. These fields never raise profile ceilings or bypass protected
  profiles, confirmation, rollback, idempotency, or audit controls.
- `oracle_switch_profile` is now lane-aware in served stateful HTTP. The switch
  applies to the active principal/session lane, revalidates exposure and
  draining state before credential resolution, reloads profile-scoped custom
  tools, bumps the lane generation, and clears old grants. Failed switches leave
  the previous connection/profile in place.
- The N8 shared-principal safety path fails closed before Oracle I/O when a
  served HTTP request would otherwise share mutable dispatcher state across
  unsupported principals or sessions. Multi-agent HTTP deployments should use
  stateful sessions with per-client credentials, OAuth, or mTLS.
- Confirmation grants are opaque, single-use, lane-bound references. The legacy
  deterministic confirmation-MAC shape is retired; grants are bound to the
  statement/action digest, active profile, MCP session, dispatch lane,
  server-derived principal, and lane generation. Preview again after profile
  switches, level changes, expiry, lane close, or restart.
- The reserved `/operator/v1` API now requires server-derived operator authority
  from `[http.operator]` or the loopback local-owner default, and authorized
  operator actions require the signed audit chain before routing.
- `/mcp` now rejects unsupported `MCP-Protocol-Version` headers with typed JSON
  `400 unsupported_protocol_version`. `/operator/v1` now serves a generated
  schema bundle, REST/SSE read-only operator routes, and guarded action routes
  that forward through the existing MCP dispatcher.
- `/operator/v1` gated-action routes now accept or derive idempotency keys,
  replay same-key retries, and return typed in-progress/conflict responses
  without bypassing dispatcher-side confirmation grants or durable write intents.
- `/operator/v1/events` now keeps a bounded per-subject/per-lane replay ring and
  supports `cursor` / `Last-Event-ID` resume without crossing lanes.

## [0.4.1] — 2026-06-29

### Changed
- Bumped the exact pure-Rust thin driver pin to `oracledb` 0.5.1 so downstream
  `plsql-mcp` can validate the trio-stack live gate against the current
  rust-oracledb patch line.
- Kept the driver behind the same `oraclemcp-db` adapter seam and release
  metadata gates; no public API removals.

## [0.4.0] — 2026-06-23

Production-hardening line (no API removals from 0.3.0). Trust & safety depth,
async/adapter foundations, the read-only DBA suite, production ops, ergonomics,
and the oracledb driver cut-over.

### Added
- Hash-chained, HMAC-SHA256-signed out-of-band audit log wired into the served
  dispatch path, with an `audit verify` CLI and optional WORM/SIEM shipping.
- Compile-time capability narrowing (read handlers cannot spawn/connect out).
- Read-only DBA diagnostic suite: `oracle_db_health` and `oracle_top_queries`
  (privilege-degrading; AWR/diagnostics-pack license-gated).
- OTLP logs/metrics/traces + `/healthz`//`readyz`//`metrics`, with two-layer
  secret redaction (`db.statement`/`db.query.text` never exported).
- A1 read-only transaction backstop; B6 per-request budget bounds.
- Supply-chain integrity: CycloneDX SBOM, cosign keyless signing, multi-nightly
  CI, ADRs, severity policy.
- Canonical annotated `oraclemcp.example.toml` and `docs/configuration.md`.

### Changed
- Live Oracle access now uses the pure-Rust thin `oracledb` **0.5.0** driver
  (was 0.2.2 in 0.3.0); all driver use stays behind the single adapter seam.
- Full async DB path (dropped the blocking-connection facade; native async
  `oracledb::Connection` with cancellation-correct checkpoints).
- E5 `mcp_exposed` is a **per-profile opt-out** (exposed by default; set
  `mcp_exposed = false` to hide; no global flip).
- The nightly-toolchain requirement is owed to **asupersync** (`try_trait_v2`),
  not oracledb — oracledb 0.5.0 is stable-clean.

### Fixed
- Pool checkout retry no longer parks forever on a timer-less runtime.
- Default per-call timeout prevents a head-of-line hang.
- Hardened `traceparent` parsing (no panic under `panic=abort`); CSPRNG session
  ids; constant-time MAC comparisons; fail-closed SQL classifier on unparseable
  input.

## [0.3.0] — 2026-06-18

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
- Native MCP prompt handlers for the built-in expert playbook catalog via
  `prompts/list` and `prompts/get`.
- Explicit MCP tool titles and advisory annotations for every advertised tool,
  including read-only, destructive, idempotent, and open-world hints.
- MCP `outputSchema` declarations for `oracle_query`, the `query` alias, and
  `oracle_explain_plan`, with the query schema preserving Oracle NUMBER as a
  lossless string by default.

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

[0.6.3]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.6.3
[0.6.2]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.6.2
[0.6.1]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.6.1
[0.6.0]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.6.0
[0.4.1]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.4.1
[0.4.0]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.4.0
[0.3.0]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.3.0
[0.2.1]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.2.1
[0.1.0]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.1.0
