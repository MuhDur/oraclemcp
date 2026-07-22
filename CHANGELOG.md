# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.0] — unreleased

This line was planned as `0.9.1`. It is `0.10.0` because the work below removes
public API, and on a `0.x` line the minor position is the breaking one — the
same call the driver made at `0.8.0`. `cargo semver-checks check-release` is the
gate that forced it, and suppressing that report was never an option: a removed
error variant and a reshaped dictionary signature are exactly what a downstream
consumer needs to be told about.

### Breaking

- The dead session-lease subsystem is gone. `oraclemcp-error` drops
  `OracleMcpError::LeaseRequired`, and `oraclemcp-db` drops `LeaseManager`,
  `LeaseInfo`, `LeaseId`, `PreviewImpact`, and `require_lease_id`. Nothing in
  the shipped surface routed through it.
- Dictionary reads are now bounded at the source rather than trusted to be
  small. `compile_errors`, `describe_constraints`, `plscope_identifiers`, and
  `plscope_statements` take a `max_rows` cap, and `get_sources_by_name` takes an
  inclusive line range, so each grew parameters.
- `oraclemcp_guard::corpus::CorpusRecord` is `#[non_exhaustive]`. Its doc
  comment already said the record was constructible only through the two
  redact-then-verify constructors; the attribute makes that a rule rather than
  a request, and stops a downstream crate assembling a corpus record around an
  unredacted statement the guard never proved safe.

## [0.9.0] — 2026-07-18

### Breaking

- `GuardDecision` now exposes `non_transactional_effect` and
  `query_effect_requires_fetch`. Callers that construct the public struct must
  initialize both fields. The metadata is required to keep sequence and
  query-triggered effects behind explicit confirmation, so this line advances
  to 0.9 rather than suppressing the breaking-change report.

### Added

- A separately bounded, mandatory-mTLS control listener can reserve remote
  operator and readiness capacity before general HTTP parsing. Certificate
  identity must be registered and operator-allowlisted; handshake, header, and
  body deadlines are absolute. See
  [2bc4c68](https://github.com/MuhDur/oraclemcp/commit/2bc4c68).
- Stateful HTTP/SSE notifications are scoped to the owning MCP stream, with
  isolated progress tokens, bounded replay, deterministic gaps, and catalog
  refresh signals for elevation, de-escalation, and TTL expiry. See
  [9cc1299](https://github.com/MuhDur/oraclemcp/commit/9cc1299) and
  [c866330](https://github.com/MuhDur/oraclemcp/commit/c866330).

### Security

- Session leases now use opaque random handles bound to the authenticated
  owner; revocation is linearized and uncertain database calls quarantine the
  session before reuse. See
  [a32b168](https://github.com/MuhDur/oraclemcp/commit/a32b168),
  [81eae00](https://github.com/MuhDur/oraclemcp/commit/81eae00), and
  [6ca5a84](https://github.com/MuhDur/oraclemcp/commit/6ca5a84).
- The fail-closed resolver gained a mock-free adversarial Oracle corpus and no
  longer misclassifies multipart package values as relation-qualified names.
  The corpus covers hidden writes, VPD, synonyms, overloads, ambiguity, and
  invalidation without executing candidate routines. See
  [ebf9bbe](https://github.com/MuhDur/oraclemcp/commit/ebf9bbe).

- New audit records use schema v6 and replace the historical raw SQL preview
  with a fixed redaction marker before hashing, signing, local JSONL storage,
  WORM mirroring, or SIEM encoding. Exact and normalized SQL hashes remain for
  correlation, while custom `Debug` implementations keep current draft SQL and
  historical previews out of logs. Signed v1-v5 records remain verifiable
  byte-for-byte and are not silently rewritten.
- Audit hash-chain schema v5 now encodes optional values with explicit presence
  tags and uses stable, length-framed canonical bytes. This prevents
  `rows_affected = null` from authenticating as `u64::MAX`; historical v1-v4
  records continue to verify byte-for-byte without rewriting the audit log.

## [0.8.0] — 2026-07-09

### Changed

- Adopted the independent `oracledb` driver **0.8.2** (via 0.8.1) and
  `asupersync` 0.3.5; the server and driver now version separately. Wired the
  driver's new accessors (K1 certificate-expiry and wallet cross-check, K2).

### Added

- **K10 streaming query results over MCP.** `oracle_query` can stream rows
  incrementally as cursor-chunked Server-Sent Events, with the fail-closed guard
  still classifying the statement before any row is fetched.
- **K9 flashback AS-OF read mode.** A structured `as_of` parameter selects a
  read-consistent point in time; the classifier is untouched.
- **K2 live server-capability probe.** `oracle_capabilities` reports the
  connected server's actual feature set (`ServerFeatures`).

### Security

- **`oracle_query_execute` re-classifies and re-gates at apply time (SEC-1).** A
  previewed statement is never trusted on its stored verdict; the classifier and
  operating-level check run again before execution.

### Breaking

- `ErrorEnvelope` and `GuardDecision` gained structured-reason fields
  (`structured_reason` / `reason_category` / `offending_construct`) — additive
  diagnostics that require a minor bump under 0.x SemVer.

## [0.7.2] — 2026-07-06

### Security

- **PL/SQL `CREATE OR REPLACE` now requires the `DDL` operating level (bead
  `p0d6`).** Replacing a stored `PROCEDURE`/`FUNCTION`/`PACKAGE`/`TRIGGER` was
  leveled by its PL/SQL body and floored at `READ_WRITE` — one tier below
  `CREATE OR REPLACE VIEW` and `oracle_patch_source` — letting a `READ_WRITE`
  principal replace stored code (definer-rights escalation). It now floors at
  `DDL` (`max(Ddl, body_level)`; a dangerous body still escalates to
  `Forbidden`), and `oracle_create_or_replace` audits under its own tool name.
- Closed a classifier subquery-DML bypass, an audit forged-anchor bypass, an
  auth misclassification, and an audit file-lock gap; interior-fork resume now
  refuses fail-closed.

### Added

- **Keyed full-chain audit verification on resume + parent-directory fsync
  (bead `g4xi`).** A forged interior audit record with a bad MAC now refuses
  startup when the key is present; the audit log's directory entry is fsynced
  so it survives a crash immediately after create.
- Broader governed-tool e2e coverage across all live lanes (bead `rsya`):
  `switch_profile`, `sample_rows`, `read_clob` caps, custom-tool `READ_ONLY`
  enforcement, `DBMS_OUTPUT` caps, `explain_plan`/`PLAN_TABLE` gating.
- Adopted `oracledb` 0.7.2 — pre-23ai cross-version driver fixes (direct-path
  load, break/cancel recovery framing, TPC token, and the below-floor 12.2
  `al8sqlsig`/`oaccolid` write-gate fixes).

### Fixed

- **Connect-error redaction hardened (bead `p0sd`).** Redaction now scrubs
  decomposed host/port/service and case-insensitive Oracle-uppercased
  identifiers (closing two leak paths), with min-length + word-boundary guards
  so it never over-redacts. Mid-cancel/timeout session discard now keys off the
  structural `Cancelled` error kind, not fragile message-text markers.
- Audit hash-chain resumes across restarts; tail-truncation anchor detection;
  MCP protocol-revision hygiene; deterministic shutdown wakeup.

## [0.7.1] — 2026-07-04

### Added

- Adopted `oracledb` 0.7.1: OCI wallet parity (encrypted `ewallet.pem`
  decryption, first-class `ewallet.p12`, always-on `cwallet.sso`) so an
  untouched ADB wallet zip connects directly; Oracle 11g and older servers are
  refused with a structured protocol-floor error instead of a decode error;
  a failed login on pre-23ai servers surfaces the real `ORA-01017` instead of
  an unexpected-MARKER connect error.

### Fixed

- Classifier (tightening): `WITH cte … UPDATE/DELETE/INSERT/MERGE` — a
  CTE-smuggled top-level write that parses as a query — is now always
  classified as a guarded write, never read-only.
- Fixed chrono `TIMESTAMP WITH TIME ZONE` values shifting the instant by the
  display offset (driver 0.7.1; found by the new rust-vs-python ground-truth
  differential, which now runs an identical 29-case statement corpus through
  both drivers field-by-field).
- An explicit `ORACLEMCP_CONFIG` that is empty, relative, missing, or a
  directory is now a hard, actionable error (or falls through to discovery for
  the empty case) instead of silently loading an empty config.
- `setup` Codex snippets emit the command as a TOML literal string, so
  backslash paths and quotes can no longer produce unparseable TOML.
- e2e harness: skips can no longer be miscounted as passes; the version-matrix
  e2e hard-fails when live mode is requested but lane credentials are missing.

## [0.7.0] — 2026-07-04

**oraclemcp now works against pre-23ai Oracle servers (18c/19c/21c
generation).** A fresh-install field test against a 19c fleet found that every
connect failed during the TNS handshake; the root causes were fixed upstream in
the thin driver and adopted here, with a standing multi-server-version test
gate so the server-generation envelope can never silently narrow again.

### Added

- Adopted `oracledb` 0.6.0 (deliberate exact-pin bump): TNS RESEND handling,
  classic (non-fast-auth) session establishment, version-gated function
  headers, and classic response framing. Live-verified end to end on Oracle XE
  18, XE 21, and FREE 23ai — `doctor --online` connectivity and real
  `oracle_query` calls through the MCP surface.
- Operating-level ladder e2e across the Oracle version matrix
  (`scripts/e2e/oracle_version_matrix.sh`): per-lane doctor, READ_ONLY
  value-asserted reads plus write refusal, preview → grant → elevation → DML
  rollback-by-default then granted commit, governed DDL create/drop, drop back
  to READ_ONLY, audit evidence. Wired into the release checklist as a required
  gate.
- Actionable connect-failure envelopes (`ConnectFailureKind`): driver handshake
  failures map to structured error classes with plain-language messages and
  `next_actions` (including `ORACLEDB_TRACE_CONNECT` triage guidance), surfaced
  identically by `doctor --online`.
- Config discovery honors `$XDG_CONFIG_HOME/oraclemcp` ahead of
  `~/.config/oraclemcp` (`ORACLEMCP_CONFIG` stays highest).
- `install.sh`: explicit `--target` accepts the published `linux-gnu` triples;
  `--dry-run` states the cosign soft-skip / require-mode posture up front.

### Fixed

- `setup` MCP snippets default to the resolved real binary instead of a
  never-created wrapper path; explicit `--wrapper-path` states the wrapper must
  exist first.
- `setup` install hint no longer suggests bare `cargo install` (which fails on
  stable); it lists the installer one-liner, `self-update`, and
  `cargo binstall`, with the nightly-pinned source build as the escape hatch.
- `initialize` echoes a supported client-offered `protocolVersion` per the MCP
  spec, and the HTTP `MCP-Protocol-Version` gate accepts the same enumerated
  set (still fail-closed on unknown versions).
- `doctor` prints its checks in numeric order.

## [0.6.6] — 2026-07-02

### Fixed

- Recut the 0.6.5 release train as 0.6.6 after the pushed `v0.6.5` tag
  failed in release gates before publishing crates, binaries, GHCR images, or
  MCP registry metadata.
- Made the installer TTY smoke explicitly clear the inherited `CI` environment
  only for the pseudo-terminal child, so GitHub Actions still exercises the
  interactive guided install path that production shells see.

### Included

- Publishes the advanced dashboard release line: Change-Review board,
  schema-diff and migration export workflows, the selected 2D BigBoard
  signature skin, and release-gated per-view acceptance for those surfaces.
- Publishes the one-line install/update experience: guided TTY flow,
  non-interactive agent path, self-update, Windows installer parity, and
  structured JSON-line installer acceptance evidence.

## [0.6.5] — 2026-07-02

> The `v0.6.5` tag was pushed, but its workflow failed in release gates before
> external artifacts were published. Use `0.6.6`.

### Fixed

- Recut the 0.6.4 release train as 0.6.5 after the pushed `v0.6.4` tag
  failed in release gates before publishing crates, binaries, GHCR images, or
  MCP registry metadata.
- Made the installer TTY smoke test assert stable PATH-prompt fragments instead
  of one long absolute-path prompt, avoiding GitHub pseudo-terminal wrapping
  differences while still proving the exact `.bashrc` mutation.

### Included

- Prepared the advanced dashboard release line: Change-Review board,
  schema-diff and migration export workflows, the selected 2D BigBoard
  signature skin, and release-gated per-view acceptance for those surfaces.
- Prepared the one-line install/update experience: guided TTY flow,
  non-interactive agent path, self-update, Windows installer parity, and
  structured JSON-line installer acceptance evidence.

## [0.6.4] — 2026-07-02

> The `v0.6.4` tag was pushed, but its workflow failed in release gates before
> external artifacts were published. Use `0.6.6`.

### Fixed

- Recut the 0.6.3 release train as 0.6.4 after the pushed `v0.6.3` tag
  failed in release gates before publishing crates, binaries, GHCR images, or
  MCP registry metadata.
- Made the installer TTY smoke test tolerant of pseudo-terminal line wrapping
  around long PATH prompts while still verifying the exact prompt text after
  unwrapping.

### Included

- Prepared the advanced dashboard release line: Change-Review board,
  schema-diff and migration export workflows, the selected 2D BigBoard
  signature skin, and release-gated per-view acceptance for those surfaces.
- Prepared the one-line install/update experience: guided TTY flow,
  non-interactive agent path, self-update, Windows installer parity, and
  structured JSON-line installer acceptance evidence.

## [0.6.3] — 2026-07-02

> The `v0.6.3` tag was pushed, but its workflow failed in release gates before
> external artifacts were published. Use `0.6.6`.

### Fixed

- Recut the 0.6.2 release train as 0.6.3 after the pushed `v0.6.2` tag
  failed in release gates before publishing crates, binaries, GHCR images, or
  MCP registry metadata.
- Fixed the Windows installer static-analysis gate by making the invalid-PATH
  catch block explicit and renaming the PowerShell helper to use an approved
  singular noun.

### Included

- Prepared the advanced dashboard release line: Change-Review board,
  schema-diff and migration export workflows, the selected 2D BigBoard
  signature skin, and release-gated per-view acceptance for those surfaces.
- Prepared the one-line install/update experience: guided TTY flow,
  non-interactive agent path, self-update, Windows installer parity, and
  structured JSON-line installer acceptance evidence.

## [0.6.2] — 2026-07-02

> The `v0.6.2` tag was pushed, but its workflow failed in release gates before
> external artifacts were published. Use `0.6.6`.

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

[0.6.6]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.6.6
[0.6.5]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.6.5
[0.6.4]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.6.4
[0.6.3]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.6.3
[0.6.2]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.6.2
[0.6.1]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.6.1
[0.6.0]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.6.0
[0.4.1]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.4.1
[0.4.0]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.4.0
[0.3.0]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.3.0
[0.2.1]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.2.1
[0.1.0]: https://github.com/MuhDur/oraclemcp/releases/tag/v0.1.0
