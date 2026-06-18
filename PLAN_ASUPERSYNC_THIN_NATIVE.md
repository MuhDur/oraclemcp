# oraclemcp Asupersync Thin-Native Migration Plan

Status: historical planning document, intentionally dependency-ordered rather
than calendar-ordered.

Current status as of 2026-06-18: the thin-native migration tracked by this plan
has been implemented in the working tree, while release-hardening beads remain
tracked in the repo-local `br`/`bv` graph. Treat the tracked
`docs/behavior-inventory.md`, `CHANGELOG.md`, README, code, and live `br`/`bv`
state as the current source of truth. Older sections below may describe
pre-implementation gaps or driver versions that have since been resolved.

Scope: `/home/durakovic/projects/oraclemcp` only. The nearby
`/home/durakovic/projects/rust-oracledb` checkout is relevant as the source
project for the thin Oracle driver, but this plan is for `oraclemcp` and should
not turn into a multi-repo implementation without an explicit operator decision.

This document is intentionally self-contained. A fresh implementation agent
should be able to read it, inspect the referenced files, convert it into beads,
and start work without needing the original chat.

## Executive Decision

The target architecture is:

- pinned nightly Rust,
- pure-Rust Oracle thin mode through `oracledb`,
- Asupersync as the only async runtime,
- native MCP stdio and HTTP transports,
- no production dependency on `tokio`, `rmcp`, `axum`, `hyper`, `r2d2`, or the
  ODPI-C `oracle` crate,
- no weakening of the existing fail-closed SQL guard.

The migration should not be an executor swap. The goal is to reshape
`oraclemcp` around Asupersync's useful primitives: explicit `Cx`, request and
tool-call regions, cancellation, budgets, scoped task ownership, native
sync/time/net/web primitives, deterministic tests, and capability discipline.

## Non-Negotiables

1. The SQL safety invariant stays intact.
   `oracle_query` and `oracle_explain_plan` must keep refusing every statement
   that is not provably read-only before it reaches the database. The migration
   must not create a fallback path that bypasses `oraclemcp-guard`.

2. No `unsafe`.
   The workspace currently forbids unsafe code. Do not introduce `unsafe` in
   `oraclemcp` as part of this migration.

3. Credentials stay redacted.
   Passwords, wallet passwords, bearer tokens, HMAC keys, registry tokens, and
   connection strings that embed secrets must not appear in `Debug`, structured
   logs, test failure output, doctor output, panic messages, or generated
   artifacts. Fixtures and snapshots must also avoid real PII or sensitive
   business data, not only technical secrets.

4. The final production build is thin-only.
   Do not retain thick mode as a fallback unless the operator explicitly changes
   direction. Keeping thick mode would preserve Instant Client, ODPI-C, native
   build/runtime requirements, Docker weight, and dual-driver behavior. That
   conflicts with the current goal.

5. The final production build is native Asupersync.
   `asupersync-tokio-compat` is allowed only as an explicit temporary boundary
   if an implementation slice cannot otherwise move forward. It must not leak
   Tokio types into core business logic, and the final dependency gate must
   fail if Tokio-family crates remain in production.

6. The plan is dependency-ordered, not timeline-ordered.
   Work packages below are ordered by what they unlock. They do not imply wait
   periods, dates, stability windows, or "come back later" gates.

7. Existing hard correctness contracts must survive the migration.
   The current repo already contains several non-obvious safety mechanisms. The
   thin-native rewrite must preserve or deliberately strengthen them:
   - session leases are not replaceable by a bare connection pool,
   - stateful DB work stays pinned to the same physical Oracle session,
   - lease expiry or release force-rolls back open transactions,
   - NUMBER and high-precision decimal output stays lossless by default,
   - canonical output stays NLS-stable,
   - AWR/ASH diagnostics remain license-gated with Statspack/unavailable
     degradation,
   - allow-once preview tokens remain usability friction, not a security
     boundary,
   - no in-process native plugin loading is introduced.

8. Guard classification must remain before execution and before async gaps.
   The migration must not introduce an await, DB connection acquisition, session
   lease acquisition, or mutable state transition before a raw SQL statement has
   been classified and level-gated. This avoids async Time-of-Check to
   Time-of-Use gaps around the fail-closed guard.

9. Thin-only auth coverage must be resolved before the thick adapter disappears.
   Username/password, TCPS/wallet, wallet password, OCI IAM token, and any
   currently documented enterprise-auth surfaces must be audited against the
   chosen `oracledb` version. Unsupported modes must fail explicitly with
   structured errors and documentation; they must not silently fall through to
   password auth or disappear from diagnostics.

10. Panic paths must not disclose secrets.
    Credential-handling and transport-auth code must not rely on `.unwrap()` or
    `.expect()` where sensitive values may be in scope. Panic messages,
    backtraces, hooks, crash reports, and test failures must preserve the same
    redaction boundary as normal structured errors.

## Current Grounding

These facts were checked in the repo while writing the plan.

### Current oraclemcp Shape

- Workspace root: `Cargo.toml`
- Workspace crates:
  - `oraclemcp-error`
  - `oraclemcp-telemetry`
  - `oraclemcp-audit`
  - `oraclemcp-guard`
  - `oraclemcp-config`
  - `oraclemcp-db`
  - `oraclemcp-auth`
  - `oraclemcp-core`
  - `oraclemcp`
- Current workspace package settings:
  - edition `2024`
  - MSRV `1.88`
  - workspace lint `unsafe_code = "forbid"`
- Current live DB feature:
  - `oraclemcp-db` feature `oracle-driver`
  - pulls `oracle = 0.6.3`, `r2d2 = 0.8`, and `tokio`
  - implemented around ODPI-C / Instant Client and `spawn_blocking`
- Current MCP transport:
  - `oraclemcp-core/src/server.rs` uses `rmcp`
  - `oraclemcp-core/src/http.rs` uses `rmcp`, `axum`, and the hyper stack
  - stdio and Streamable HTTP behavior are currently backed by `rmcp`

### Current Tokio Holdouts

Tokio is not only in one place. It enters through direct code and third-party
transitive dependencies.

Direct use:

- `crates/oraclemcp/src/main.rs`
  - runtime bootstrap
  - TCP listener
  - signal handling
- `crates/oraclemcp-core/src/server.rs`
  - `tokio::io::stdin/stdout`
  - `tokio::task::spawn_blocking`
- `crates/oraclemcp-core/src/http.rs`
  - `tokio::net::TcpListener`
  - `axum::serve`
- `crates/oraclemcp-core/src/admission.rs`
  - `tokio::sync::Semaphore`
- `crates/oraclemcp-core/src/shutdown.rs`
  - `tokio::sync::Notify`
- `crates/oraclemcp-core/src/resilience.rs`
  - `tokio::time::timeout`
- `crates/oraclemcp-db/src/pool.rs`
  - `tokio::task::spawn_blocking`
- async tests use `#[tokio::test]`, `tokio::io::duplex`, `tokio::time`, and
  `tokio::spawn`

Transitive use:

- `rmcp` stdio and Streamable HTTP features pull Tokio I/O, `tokio-stream`, and
  `tokio-util`.
- `axum` pulls `hyper`, `hyper-util`, `tower`, and Tokio runtime integration.
- `rust-mcp-sdk` is not an obvious replacement because its default server
  feature set includes axum/hyper/tokio-adjacent transports.

### Thin Driver Grounding

The local `rust-oracledb` checkout currently exposes the crate `oracledb`.

Observed local checkout facts:

- workspace version `0.1.1`
- pure-Rust async Oracle thin-mode driver
- depends on `asupersync = 0.3.4`
- pinned toolchain `nightly-2026-05-11`
- no stable MSRV in that checkout because Asupersync currently requires nightly
- public surfaces include:
  - `ConnectOptions`
  - `Connection::connect(&Cx, options).await`
  - `execute_query`
  - `execute_query_collect`
  - `execute_query_with_binds`
  - `query_named`
  - `commit`
  - `rollback`
  - LOB and timeout-oriented APIs
  - `BlockingConnection` as a compatibility shim

Observed crates.io fact:

- crates.io currently has `oracledb = 0.1.0`
- the local checkout is ahead at `0.1.1`

Release consequence:

- `oraclemcp` cannot publish to crates.io with a local path dependency on
  `../rust-oracledb`.
- The clean release path is to publish the needed `oracledb` version first, then
  depend on the published crate.
- Vendoring `oracledb` into this workspace is possible but should be treated as
  a deliberate product/release decision because it couples the two projects and
  makes `oraclemcp` heavier.

### Current MCP Surface To Preserve

`oraclemcp` currently needs only a narrow MCP surface:

- `initialize`
- `notifications/initialized`
- `tools/list`
- `tools/call`
- `oracle_capabilities`
- structured tool responses
- structured tool errors
- stdio init-token enforcement
- Streamable HTTP at `/mcp`
- protected-resource metadata route at
  `/.well-known/oauth-protected-resource`
- HTTP OAuth bearer validation
- host/origin safety behavior

This narrow surface is why replacing `rmcp` with a native implementation is
reasonable. The goal is not to invent a new protocol; the goal is to implement
the MCP protocol subset `oraclemcp` actually serves, with conformance tests.

### Existing Hard Contracts To Preserve

These contracts are implemented in the current codebase and must be treated as
migration inputs, not optional features.

- Session leases:
  - `crates/oraclemcp-db/src/lease.rs`
  - `crates/oraclemcp-core/src/session_tool.rs`
  - current tests prove forced rollback on lease teardown and stateful routing
    to the pinned session
- Canonical serialization:
  - `crates/oraclemcp-db/src/serialize.rs`
  - NUMBER defaults to string, not f64
  - NLS_DATE/NLS_TIMESTAMP/NLS_NUMERIC settings are pinned for stable output
  - BLOB/RAW and LOB capping behavior are tested
- AWR/ASH license gating:
  - `crates/oraclemcp-db/src/awr.rs`
  - `crates/oraclemcp-db/src/privileges.rs`
  - Diagnostics Pack unavailable path must remain structured and honest
- Protected profile ceilings:
  - `crates/oraclemcp-config/src/lib.rs`
  - `crates/oraclemcp-guard/src/levels.rs`
  - `crates/oraclemcp-auth/src/scope.rs`
  - protected profiles pin `READ_ONLY`, OAuth scopes only lower authority
- Preview and confirmation:
  - `crates/oraclemcp-guard/src/token.rs`
  - `crates/oraclemcp/src/dispatch/mod.rs`
  - preview tokens are process-local, digest-bound, single-use friction; they do
    not replace profile ceilings, OAuth scope caps, or guard classification
- Source patch TOCTOU discipline:
  - current README advertises source patching as re-fetching current source and
    re-confirming at execute time
  - native async dispatch must preserve that exactness

## User Value Of Accretive Additions

These additions are not decorative. Each one should either reduce user setup
pain, preserve compatibility, improve safety, or make failures easier for
agents and humans to fix.

| Addition | What it brings the user |
| --- | --- |
| Golden MCP transcript harness | Users keep the same client-visible behavior while the transport internals are replaced. If a rewrite changes `initialize`, `tools/list`, errors, or tool results, the harness catches it before release. |
| Native MCP conformance harness | Users get standard MCP compatibility even after `rmcp` is removed. It also gives future agents a precise executable contract instead of relying on SDK behavior by memory. |
| Thin-driver feature matrix | Users can see exactly which Oracle behaviors are supported by thin mode: binds, named binds, LOBs, DBMS_OUTPUT, call timeout, session identity, TCPS, and wallet handling. It prevents vague "thin mode works" claims. |
| Thin-mode `doctor` upgrades | Users and agents get actionable setup failures for DNS, listener, service name, auth, TCPS/wallet, privilege, timeout, and server-version issues. This replaces Instant Client troubleshooting with thin-driver troubleshooting. |
| Credential redaction ratchet | Users can run tests, `doctor`, CI, and agent workflows without secrets appearing in logs or debug output. This is especially important because the thin driver has its own connect options and wallet fields. |
| Dependency deny ratchet | Users get proof that thick mode, Tokio, axum, hyper, and rmcp did not silently return through a dependency update. This turns the architecture decision into a CI-enforced invariant. |
| HTTP scope enforcement fix | Users who expose HTTP get real least-privilege behavior from OAuth scopes, not only token validation. A narrow `oracle:read` token must lower the session ceiling instead of merely being recorded. |
| Asupersync deterministic runtime tests | Users get better reliability under cancellation, shutdown, timeout, and overload. Failures become replayable instead of intermittent async bugs. |
| Request/tool budget model | Users get bounded tool execution and clearer timeout semantics. Long DB calls, retries, cleanup, and shutdown do not consume unbounded work. |
| Agent-facing setup and robot docs refresh | Users can hand the server to coding agents with fewer manual instructions. Agents can discover profiles, diagnose connection state, and recover from common errors first-try. |
| Performance and footprint benchmarks | Users can verify the promised practical benefits: no Instant Client, simpler install, smaller Docker image, faster startup, and predictable query latency. No performance claim should ship as a guess. |
| Release smoke matrix | Users get synchronized crates.io, GitHub release, GHCR, and MCP registry artifacts that actually match the new thin-native architecture. This protects against publishing an artifact that still expects thick-mode setup. |
| Session-lease preservation | Users can rely on DBMS_OUTPUT, savepoints, temp tables, package globals, and transactions behaving on the same Oracle session instead of being randomly split across pooled connections. |
| Type-fidelity preservation | Users do not lose money, identifiers, timestamps, or locale-sensitive values because high-precision NUMBER and date/time values were rounded or parsed through host NLS settings. |
| Enterprise-auth audit | Users connecting to Autonomous Database or enterprise Oracle deployments get explicit support or clear structured failure instead of confusing password fallback behavior. |
| MCP conformance tests | Users can connect standards-compliant clients after the SDK is removed, including edge cases around protocol versions, malformed requests, notifications, and errors. |
| Shutdown drain policy | Users can stop the server predictably: active requests are cancelled and cleaned up, DB sessions are not returned dirty, and audit entries are flushed or reported. |

## Target Architecture

### Runtime

Use Asupersync as the runtime and control plane:

- binary bootstrap through `asupersync::runtime::RuntimeBuilder`
- explicit root `Cx`
- request/tool-call child regions
- scoped task ownership instead of detached spawns
- native time, sync, signal, net, and web primitives
- deterministic tests through Asupersync test helpers and `LabRuntime` where
  concurrency invariants matter

### Database

Use thin-only `oracledb`:

- async connection open through `Connection::connect(&Cx, ConnectOptions)`
- profile options mapped into `oracledb::ConnectOptions`
- no ODPI-C
- no Instant Client
- no `r2d2`
- no `spawn_blocking` for normal DB operations
- no `BlockingConnection` except possibly in tests or transitional spikes, and
  not in final production paths

### MCP Protocol

Use a native protocol layer:

- keep `ToolRegistry` and `ToolDispatch` style boundaries, but make dispatch
  async and `Cx`-aware
- implement JSON-RPC request/response/error envelopes directly or with a
  protocol-types-only crate after dependency audit
- candidate type crates:
  - `tower-mcp-types`: attractive because it advertises no Tower/Tokio
  - `rust-mcp-schema`: attractive because it has versioned schema support
  - no full MCP SDK unless it is proven Asupersync-native and Tokio-free
- preserve protocol version behavior currently advertised by capabilities:
  `2025-11-25`, unless a deliberate compatibility review changes it

### HTTP

Use Asupersync-native HTTP/web primitives:

- native listener
- native router or minimal native handler stack
- per-request region
- narrowed request capabilities
- host/origin guards
- OAuth bearer validation
- protected-resource metadata route
- Streamable HTTP behavior compatible with existing clients
- scope grants enforced at dispatch time

### Final Forbidden Production Dependencies

The final production dependency graph must not contain:

- `tokio`
- `tokio-stream`
- `tokio-util`
- `rmcp`
- `axum`
- `hyper`
- `hyper-util`
- `tower` only if used solely by removed HTTP stack; protocol-type-only usage
  must be reviewed explicitly
- `oracle`
- `odpic-sys`
- `r2d2`

Some crates may remain as dev-only references if they are deliberately used for
compatibility comparison tests, but production features must be clean.

## Dependency Graph

This graph is dependency order, not a schedule.

```
W0 repo facts and behavior inventory
  -> W1 golden behavior harness
  -> W2 nightly toolchain and CI ratchet
  -> W3 oracledb release dependency decision
  -> W4 thin driver adapter
  -> W5 thin-mode doctor/docs/security
  -> W6a pure async trait and Cx propagation
  -> W6b DB-facing Cx propagation and cancellation policy
  -> W7 Asupersync runtime bootstrap and primitives
  -> W8 native stdio MCP
  -> W8.5 MCP conformance tests
  -> W9 native HTTP MCP
  -> W10 scope enforcement and transport security
  -> W11 deterministic Asupersync test suite
  -> W12 forbidden dependency hard gate
  -> W13 performance/footprint evidence
  -> W14 release artifact update
```

Cross-links:

- W1 also gates W8 and W9.
- W3 gates any publishable W4 implementation.
- W4 gates W5 and the DB portions of W11.
- W6a gates pure server transport work; W6b gates DB-facing async execution.
- W6a depends only on W2. It does not depend on W4 or W5. Pure server
  layers such as W7, W8, and server-only W9 scaffolding should list W6a as
  their blocker, not all of W6.
- W6b depends on W4. DB-facing dispatch, live DB tool implementations, and
  DB portions of W11 are blocked until W6b completes.
- W7, W8, and W9 depend on the relevant W6 slice rather than all DB adapter
  work when they only touch pure server layers.
- The linear graph above is a natural single-agent walk through the work. The
  bead graph should follow these cross-links for parallel execution.
- W8 should land before W9 because stdio is the smaller transport.
- W8.5 depends on W8 and should gate W9, because the MCP core should be proven
  before HTTP session complexity is added.
- W10 depends on W9 because the current captured-only scope issue lives in the
  HTTP path.
- W11 is partially unblocked by W7 for runtime primitives, but the full suite
  needs W10.
- W12 should start as advisory in W2 and become hard only after W8/W9/W4/W11
  remove the holdouts.
- W14 depends on W12 because release artifacts must prove the final architecture.

## Work Package W0: Repo Facts And Behavior Inventory

Purpose:

Build the exact map of behavior that must survive the rewrite.

Depends on:

- Nothing.

Unlocks:

- W1, W2, W3, W4, W8, W9.

Implementation notes:

- Inventory current public CLI commands and output modes:
  - `serve`
  - `serve --listen`
  - `setup`
  - `capabilities`
  - `profiles`
  - `doctor`
  - `info`
  - `robot-docs`
- Inventory MCP behavior from existing tests:
  - `crates/oraclemcp/tests/e2e_stdio.rs`
  - `crates/oraclemcp-core/tests/e2e_mcp.rs`
- Inventory current tool registry:
  - `crates/oraclemcp/src/registry.rs`
  - `crates/oraclemcp-core/src/tools.rs`
- Inventory SQL guard paths:
  - `crates/oraclemcp-guard`
  - `crates/oraclemcp/src/dispatch`
- Inventory current hard invariants and cite the tests that prove them:
  - session lease pinning and forced rollback,
  - canonical NUMBER/date/NLS serialization,
  - AWR/ASH license gating and Statspack fallback,
  - protected profile ceiling behavior,
  - preview/confirmation token single-use behavior,
  - source patch re-fetch/re-confirm behavior,
  - no in-process native plugin loading.
- Inventory credential surfaces:
  - config loading
  - `credential_ref`
  - environment secrets
  - custom tool HMAC keys
  - OAuth bearer tokens
  - wallet fields
  - logs and debug output
- Record all dependency holdouts with `cargo tree`.
- Audit the `oracledb` API before W3:
  - compare crates.io `oracledb = 0.1.0` with local `0.1.1`,
  - list every API W4 requires,
  - record which published version supplies each API,
  - record gaps that require publishing, vendoring, or upstream work.
- Perform a preliminary audit of the Asupersync web API surface in the target
  nightly version before W9:
  - host/origin guard hooks,
  - header read/write,
  - status-code control,
  - request body size limits,
  - streamable response bodies,
  - connection shutdown/drain hooks.
- Inventory current `oracle_explain_plan` behavior:
  - whether it writes to `PLAN_TABLE`,
  - how it behaves on read-only standby,
  - whether an impact-preview/savepoint path already exists for DML,
  - which behavior is compatibility to preserve versus correctness work to
    schedule separately.
- Audit `oracle_explain_plan` specifically before W4:
  - determine whether it issues `EXPLAIN PLAN FOR ...` and therefore writes
    `PLAN_TABLE`, or whether it can use `DBMS_XPLAN`, `V$SQL_PLAN`, or another
    read-path approach,
  - record the finding in the behavior inventory,
  - if it writes `PLAN_TABLE`, create an explicit parent-tracker bead under the
    oraclemcp epic before W4 starts. Do not leave this as a markdown TODO.
- Inventory current proxy authentication behavior:
  - `AuthAdapter::Proxy`,
  - `proxy_user[target_schema]` connect naming,
  - DRCP/non-homogeneous pool expectations,
  - any documented `CONNECT THROUGH` setup guidance.
- Inventory Autonomous Database and cloud connectivity behavior:
  - wallet discovery,
  - `cwallet.sso` / `ewallet.p12` expectations,
  - `TNS_ADMIN`,
  - TCPS and SNI requirements,
  - connect-string validation,
  - IAM token refresh and expiry classification.
- Capture a baseline before the implementation changes remove it:
  - release binary size,
  - Docker image size or current release image size,
  - cold startup to first `tools/list`,
  - simple read-query latency if a live test DB is configured,
  - current thick-mode live install/runtime prerequisites.

Acceptance criteria:

- The behavior inventory must exist at `docs/behavior-inventory.md` in the
  implementation branch and must be committed before any downstream bead begins
  implementation work.
- The inventory has tables for CLI commands, MCP messages, tool registry,
  credential surfaces, hard invariants, dependency holdouts, `oracledb` API
  coverage, proxy auth, Autonomous Database/cloud connectivity, explain-plan
  behavior, and baseline measurements.
- No implementation task relies on a vague phrase like "preserve current
  behavior" without naming the tests or transcript that prove it.

## Work Package W1: Golden Behavior Harness

Purpose:

Freeze client-visible behavior before replacing the transport and runtime.

Depends on:

- W0.

Unlocks:

- W8 native stdio MCP.
- W9 native HTTP MCP.
- W14 release smoke matrix.

Implementation notes:

- Add golden transcripts for stdio:
  - successful `initialize`
  - failed `initialize` when init token is required and absent/wrong
  - `notifications/initialized`
  - `tools/list`
  - `tools/call` for `oracle_capabilities`
  - unknown tool error
  - structured tool error envelope
- Add golden HTTP cases:
  - `/mcp` initialize request
  - protected-resource metadata route
  - unauthorized request response and `WWW-Authenticate`
  - host/origin guard behavior
  - JSON response mode
  - Streamable HTTP stateful/session behavior
- Normalize fields that legitimately vary:
  - timestamps
  - generated session ids
  - trace ids
  - ordering only where the protocol explicitly allows it
- Keep secrets out of transcript fixtures.

Acceptance criteria:

- Golden tests pass against the current `rmcp`/`axum` implementation before any
  transport rewrite.
- The same golden tests pass after W8 and W9.
- A changed transcript must be reviewed as an intentional protocol change, not
  accepted by regenerating fixtures silently.

## Work Package W2: Nightly Toolchain And CI Ratchet

Purpose:

Make the toolchain honest before introducing `oracledb` and Asupersync APIs.

Depends on:

- W0.

Unlocks:

- W3, W4, W6a, W7, W11.

Implementation notes:

- Add `rust-toolchain.toml` pinned to the same nightly as the thin driver unless
  a deliberate updated pin is chosen:
  - current local thin-driver pin: `nightly-2026-05-11`
- Update CI and release workflows to use the pinned nightly.
- Update README/MSRV language:
  - remove or qualify MSRV `1.88` once thin mode is adopted
  - state that the current thin-native line requires pinned nightly while
    Asupersync requires nightly features
  - explicitly say the published `oraclemcp-*` crates in the thin-native line
    are nightly-bound if they depend on `asupersync` or `oracledb`
- Keep `edition = "2024"` unless a concrete incompatibility appears.
- Add an advisory dependency check that reports forbidden crates but does not
  fail until W12.

Acceptance criteria:

- `cargo fmt --all -- --check` runs on the pinned nightly.
- `cargo clippy --workspace --all-targets -- -D warnings` runs on pinned nightly.
- CI no longer assumes stable Rust.
- Documentation does not claim stable/MSRV support for the thin-native line.

## Work Package W3: Thin Driver Release Dependency Decision

Purpose:

Choose the publishable dependency path for `oraclemcp`.

Depends on:

- W0.
- W2.

Unlocks:

- W4.
- W14.

Recommended decision:

Depend on a published `oracledb` crate version that contains the required thin
driver APIs. Do not use a local path dependency in releaseable `oraclemcp`.

Why:

`oraclemcp` versions are published from this repo. crates.io packages cannot
depend on an unpublished local checkout. Publishing `oracledb` first preserves a
normal open-source dependency model and keeps release automation simple.

Implementation notes:

- Audit whether crates.io `oracledb = 0.1.0` already contains every API needed
  by `oraclemcp`.
- If local `0.1.1` APIs are required, publish `oracledb 0.1.1` or newer before
  changing `oraclemcp` release dependencies.
- Before publishing a new `oracledb` version, review API changes against the
  last published crate and document any breaking changes according to semver
  principles. Do not surprise downstream `oracledb` users just to unblock
  `oraclemcp`.
- If vendoring is chosen instead, record the reason explicitly:
  - why published dependency is not enough,
  - how versioning will work,
  - how security fixes flow between projects,
  - how crates.io package ownership is preserved.
- If the required `oracledb` version cannot be published before W4 work starts,
  a temporary path dependency may be used only for local implementation work.
  Before any `oraclemcp` crates.io release, that path dependency must be
  replaced by a published crate version or by a deliberate vendoring decision
  recorded in the plan/beads.
- Never ship released `oraclemcp` crates with a local path dependency outside
  the workspace package.

Acceptance criteria:

- `oraclemcp` can run `cargo package --workspace` without local path dependency
  failures.
- The chosen `oracledb` dependency version is explicit.
- The plan for thin-driver updates is documented.

## Work Package W4: Thin Driver Adapter

Purpose:

Replace ODPI-C thick mode with pure-Rust thin mode while preserving the
database-facing contracts used by tools.

Depends on:

- W1 for behavior safety.
- W2 for nightly.
- W3 for releaseable dependency path.

Unlocks:

- W5.
- W6b.
- W11 DB tests.
- W12 removal of `oracle`, `r2d2`, and DB-side Tokio.

Implementation notes:

- Replace `RustOracleConnection` with a thin-mode connection adapter.
- Replace `OraclePool` with an Asupersync-native session manager. Do not keep
  `r2d2`.
- Preserve session-lease semantics:
  - stateful operations must use the same physical Oracle session for the whole
    logical unit of work,
  - DBMS_OUTPUT setup/readback, temp tables, package globals, transactions, and
    savepoints require a lease,
  - lease expiry and explicit release force rollback before the session is
    returned or discarded,
  - stateless single-call reads may use any available clean connection,
  - the MCP/session dispatch context must carry the lease id or lease handle
    into the DB adapter,
  - migration tests must prove commit/rollback/savepoint route to the pinned
    session.
- Convert `OracleConnectOptions` to `oracledb::ConnectOptions`.
- Preserve redaction already present in `OracleConnectOptions::Debug`.
- Add or patch redaction for thin-driver connect options if any derived `Debug`
  can print passwords or wallet passwords.
- Map bind types:
  - strings
  - numbers
  - nulls
  - booleans if represented today
  - timestamps/dates
  - binary/LOB values
  - named binds
  - positional binds
- Map result rows into existing `OracleRow` / `OracleCell` serialization.
- Preserve the canonical output contract:
  - Oracle NUMBER and high-precision decimal output serializes losslessly as a
    JSON string by default, never through lossy f64,
  - BINARY_FLOAT/BINARY_DOUBLE may be numeric with documented precision limits,
  - DATE/TIMESTAMP/TIMESTAMP WITH TIME ZONE stay ISO-8601-style strings,
  - INTERVAL stays textual and deterministic,
  - RAW/BLOB stays hex or capped binary representation per existing serializer,
  - ROWID/UROWID stay opaque strings,
  - XML/JSON/object/collection support status must be explicit,
  - output remains independent of host NLS settings.
- Preserve:
  - `query_rows`
  - `query_rows_named`
  - `execute`
  - `commit`
  - `rollback`
  - `describe`
  - `ping`
  - `call_timeout`
  - `set_call_timeout`
  - `enable_dbms_output`
  - `read_dbms_output`
- Re-check profile features:
  - external auth
  - username/password
  - proxy authentication / `CONNECT THROUGH`
  - TCPS
  - wallet location
  - wallet password
  - OCI IAM token auth
  - Kerberos/RADIUS/SEPS or any enterprise auth surface currently represented
    in config/docs
  - session identity
  - driver name
  - edition
  - login statements
  - trusted session statements
  - standby/read-only profile caps
- If a thick-mode feature has no thin equivalent, fail explicitly with a
  structured, actionable error. Do not silently ignore profile keys.
- Verify `oracledb` support for proxy authentication and Autonomous Database
  wallet/TCPS/SNI behavior before claiming parity. If support is absent or
  partial, document the loss of capability, expose a structured unsupported
  error, and make `doctor` surface the exact unsupported feature. If a
  mission-critical auth path for current users is unsupported, treat it as a
  blocker for removing thick mode until the operator explicitly chooses one of:
  upstream the missing feature to `oracledb`, scope the release to deployments
  that do not need it, or pause the thin-native migration.
- Resolve feature flags:
  - remove or rename the ODPI-C-specific `oracle-driver` feature deliberately,
  - do not leave a feature named `oracle-driver` that silently means thin mode,
  - decide whether a `live-db` feature controls thin connectivity or whether
    thin DB code is always compiled,
  - update Cargo feature docs and README examples together.
- Map errors deliberately:
  - create a mapping table from `oracledb` error classes to `DbError`,
    `ErrorEnvelope`, and JSON-RPC/MCP error surfaces,
  - preserve ORA- codes in structured details where available,
  - add thin-specific error variants where needed for wallet format, TCPS
    handshake, unsupported auth mode, server version, and cancellation cleanup.
- Before forwarding any `oracledb` error text to an `ErrorEnvelope` or MCP
  error response, verify the message does not contain a connection string,
  username, password, wallet path, wallet password, IAM token, bearer token, or
  other credential-bearing value. Scrub or replace credential-containing
  substrings with a safe sentinel. ORA codes and Oracle server error text may be
  forwarded when they are not coupled to connection/auth details.
- Apply the same redaction check to the complete structured driver error,
  including fields beyond the display message, before converting it into any
  client-facing or logged error type.
- Add redaction tests for every driver error variant that touches authentication
  or connection setup.
- Map timeout semantics:
  - profile `call_timeout_seconds` and per-tool `timeout_seconds` must become
    explicit Asupersync child budgets or thin-driver call timeouts,
  - cancellation must close, cancel, or discard a dirty connection rather than
    returning it to the clean pool,
  - timeout errors must remain structured and actionable.
- Preserve AWR/ASH license gating and Statspack/unavailable degradation.
- Preserve impact-preview/savepoint behavior already in `lease.rs`; if
  `oracle_explain_plan` still writes `PLAN_TABLE`, record that as a separate
  compatibility/correctness item rather than mixing it into the thin adapter.

Acceptance criteria:

- Default build has no ODPI-C or Instant Client requirement.
- Live DB tests pass through thin mode.
- Every existing database tool either works through thin mode or returns a
  documented structured error for a deliberately unsupported feature.
- `cargo tree -i oracle` and `cargo tree -i r2d2` show no production dependency.
- No normal DB call uses `tokio::task::spawn_blocking`.
- Session lease tests pass through the thin adapter.
- Type-fidelity tests prove NUMBER/string and NLS-stable output still hold.
- Unsupported enterprise auth modes, if any, fail with explicit structured
  errors and are visible in `doctor`.

## Work Package W5: Thin-Mode Doctor, Docs, And Credential Safety

Purpose:

Make thin mode understandable and safe for humans and agents.

Depends on:

- W4.

Unlocks:

- W11 live diagnostics tests.
- W14 release docs.

Implementation notes:

- Update `doctor` to diagnose thin-mode realities:
  - DNS resolution
  - TCP connect
  - service name / SID reachability
  - authentication failure
  - server version
  - current schema
  - role/open mode
  - read-only standby status
  - TCPS handshake
  - wallet directory readability
  - wallet format support
  - session identity visibility
  - basic privileges needed by introspection tools
- Keep ORA codes scrapeable and structured in `doctor` output and MCP error
  envelopes so agents can classify failures and choose retry, introspection, or
  setup-repair workflows.
- Distinguish network/listener unreachable failures from authentication,
  wallet, TCPS, and unsupported-driver-feature failures.
- Remove Instant Client as a required live-mode diagnostic.
  This means Instant Client is removed from the setup requirement, not hidden
  from diagnostics: if a user has Instant Client installed, `doctor` should
  explain that thin mode does not need it and should guide them toward hostname,
  service, TCPS, or wallet configuration instead.
- Update README quickstart:
  - no C toolchain requirement for normal install
  - no `LD_LIBRARY_PATH` / `DYLD_LIBRARY_PATH` / Windows PATH setup for Instant
    Client
  - updated Docker story without bundled Instant Client
- Update `robot-docs` so agents know the thin-mode setup and recovery path.
- Add redaction tests for:
  - `OracleConnectOptions`
  - thin `ConnectOptions`
  - OAuth enforcement debug output
  - config errors
  - doctor output
  - failed connection output
  - wallet fields

Acceptance criteria:

- `doctor` no longer instructs users to install Instant Client for the
  thin-native build.
- No test fixture or snapshot contains a real-looking secret.
- Common setup failures produce clear next actions.

## Work Package W6: Async Tool Dispatch And `Cx` Propagation

Purpose:

Thread Asupersync context through the server's own APIs before replacing all
runtime primitives.

Depends on:

- W2.
- W4 only for W6b, the DB-facing async shape. W6a can start after W2.

Unlocks:

- W6a unlocks W7, W8, and server-only W9 scaffolding.
- W6b unlocks DB-facing dispatch, DB-backed tool execution, and DB portions of
  W11.

Implementation notes:

- Split the work into two dependency slices:
  - W6a: pure server trait and context shape; depends on W2.
  - W6b: DB-facing dispatch and tool implementation shape; depends on W4.
- Replace synchronous `ToolDispatch::dispatch` with an async, `Cx`-aware shape.
  A representative target shape:

  ```rust
  async fn dispatch(&self, cx: &Cx, name: &str, args: Value)
      -> Result<Value, ErrorEnvelope>;
  ```

- Update individual tool execution paths, not only the top-level trait:
  - `crates/oraclemcp/src/dispatch`
  - `crates/oraclemcp/src/registry.rs`
  - `crates/oraclemcp-core/src/tools.rs`
  - `crates/oraclemcp-core/src/custom_tools.rs`
  - `crates/oraclemcp-core/src/session_tool.rs`
  - any compatibility aliases that call the dispatcher
- Keep pure guard/classifier logic pure where it does not need `Cx`.
- Critical safety rule: raw SQL classification and level gating must complete
  before any `await`, DB connection acquisition, lease acquisition, or
  execution-side mutable state transition. If a tool has preview and execute
  phases, both phases must re-check the exact SQL/object/profile/options needed
  by that phase.
- Add `cx.checkpoint()` in:
  - long result serialization loops
  - paginated fetch loops
  - retry bodies
  - shutdown-sensitive code
  - custom tool loading or validation loops if they become async
- Add cancellation cleanup policy for DB calls:
  - a cancelled call must cancel or abandon the thin-driver operation,
  - open transactions on leased sessions must roll back before reuse,
  - open cursors must close or the connection must be discarded,
  - if the thin driver cannot cancel in-flight work, close/discard the
    connection rather than returning it cleanly to the pool.
- Follow `AGENTS.md` editing discipline: no bulk codemods or giant sed/regex
  rewrites. Port tool signatures crate-by-crate or group-by-group and verify
  with focused `cargo check`/tests between slices.
- Preserve `ErrorEnvelope` as the client-facing error contract.
- Preserve `oracle_capabilities` as a cheap zero-arg discovery tool.
- Decide how to represent `Outcome` internally:
  - keep `Outcome::Cancelled` and `Outcome::Panicked` visible until transport
    boundaries,
  - map to JSON-RPC errors only at the MCP edge.

Acceptance criteria:

- Tool dispatch APIs accept `&Cx`.
- Individual DB-backed tools pass `&Cx` down to the thin driver.
- No internal async code depends on ambient runtime handles.
- Cancellation can be tested at tool-call boundary.
- Guard classification tests prove no await/connection/lease boundary can run
  before classification and level gating.

## Work Package W7: Asupersync Runtime Bootstrap And Native Primitives

Purpose:

Replace direct Tokio runtime surfaces with Asupersync primitives.

Depends on:

- W2.
- W6a for pure runtime and server context shape.
- W6b only for DB cancellation cleanup paths.

Unlocks:

- W8.
- W9.
- W11.
- W12.

Implementation notes:

- Replace binary runtime bootstrap with `RuntimeBuilder`.
- Audit `.unwrap()` and `.expect()` in credential, connection, OAuth, HMAC,
  wallet, and token-handling paths. Replace panic-prone handling with structured
  errors where sensitive values may be in scope, and verify any production panic
  hook keeps secrets redacted.
- Audit `oraclemcp-telemetry` before the runtime replacement:
  - plain `tracing`/`tracing-subscriber` can remain,
  - Tokio-tied telemetry layers such as `console-subscriber` or tokio-console
    integrations must be removed or replaced,
  - telemetry must not reintroduce Tokio after W7.
- Replace shutdown coordination:
  - `tokio::sync::Notify` to Asupersync native sync/notification primitive
  - tests for lost-wakeup regression
- Define shutdown drain policy:
  - signal receipt stops new admissions,
  - active request/tool regions are cancelled and drained,
  - DB calls receive cancellation and dirty sessions are rolled back or closed,
  - audit sinks flush before exit where possible,
  - a hard operator-configurable drain timeout prevents indefinite shutdown.
- Replace admission control:
  - `tokio::sync::Semaphore` to Asupersync native semaphore/bulkhead/service
    layer
  - preserve per-agent and global caps
  - preserve stale-agent cleanup behavior
- Replace timeout logic:
  - `tokio::time::timeout` to Asupersync time/budget-aware timeout
- Replace signal handling:
  - `tokio::signal` to Asupersync signal handling, or a small platform-specific
    boundary if necessary
- Replace TCP listener usage:
  - `tokio::net::TcpListener` to Asupersync native net listener
- Replace tests:
  - `#[tokio::test]` to `#[test]` with Asupersync test helpers
  - `tokio::io::duplex` to native or deterministic test transport

Acceptance criteria:

- Direct `tokio::` imports are gone from production code.
- Tests cover shutdown, admission, timeout, and cancellation behavior.
- Any unavoidable temporary compat module is isolated and documented with a
  removal task.
- Shutdown tests prove new work is refused during drain and active work reaches
  cleanup or force-cancel behavior.

## Work Package W8: Native Stdio MCP Transport

Purpose:

Remove `rmcp` from the default local-agent path while preserving MCP client
compatibility.

Depends on:

- W1.
- W6a.
- W7.

Unlocks:

- W9.
- W12 removal of `rmcp` if HTTP is also native or isolated.

Implementation notes:

- Implement JSON-RPC envelope parsing and writing for stdio.
- Preserve current behavior:
  - `initialize`
  - `notifications/initialized`
  - `tools/list`
  - `tools/call`
  - `oracle_capabilities`
  - init-token validation on `initialize`
  - structured successful tool result
  - structured error tool result
  - unknown tool failure
- Decide whether to use protocol-type-only support:
  - audit `tower-mcp-types`
  - audit `rust-mcp-schema`
  - use internal serde structs if either crate adds unwanted dependencies or
    mismatches the MCP version we serve
- Keep transport parsing strict:
  - invalid JSON fails with JSON-RPC parse error
  - unknown method fails with method-not-found or protocol-appropriate error
  - invalid params fail closed
  - oversized messages are rejected with a bounded error
- Compare init tokens with constant-time equality or the existing secret
  comparison primitive; do not use plain string equality if timing behavior is
  observable.
- Reject oversized stdio messages before JSON parsing. Choose a documented
  default request limit and expose it in robot docs.
- Keep logs structured and non-secret.

Acceptance criteria:

- Golden stdio transcripts from W1 pass.
- All tests in `crates/oraclemcp/tests/e2e_stdio.rs` and other stdio-dependent
  tests are ported away from any `rmcp`-specific test clients/helpers and pass
  against the native implementation.
- `initialize` response protocolVersion matches the advertised protocol version
  exactly.
- `cargo tree -i rmcp` no longer points at the stdio path.
- Stdio client compatibility is verified with at least one real MCP client
  invocation or a faithful scripted client.

## Work Package W8.5: MCP Conformance Tests

Purpose:

Prove the native MCP core is spec-shaped, not merely a replay of the old SDK's
happy path.

Depends on:

- W8.

Unlocks:

- W9.
- W11 protocol tests.

Implementation notes:

- Record the MCP spec version under test.
- Test protocol negotiation:
  - supported version accepted,
  - older version behavior documented,
  - newer version behavior documented.
- Test JSON-RPC behavior:
  - malformed JSON returns parse error,
  - unknown method returns method-not-found,
  - invalid params return invalid-params,
  - notifications do not receive responses,
  - ids are echoed correctly,
  - batch support is either implemented and tested or explicitly rejected.
- Test tools behavior:
  - capability advertisement matches `tools/list`,
  - advertised input schemas are object schemas,
  - `tools/call` rejects unadvertised tool names,
  - structured content shape matches current client expectations.
- Apply the same conformance suite to HTTP in W9 where transport differences
  allow it.

Acceptance criteria:

- Native stdio passes the conformance suite before W9 starts.
- Deviations from MCP spec are documented as deliberate compatibility choices.
- The suite becomes a permanent regression gate.

## Work Package W9: Native HTTP MCP Transport

Purpose:

Remove `axum`, `hyper`, and HTTP-side `rmcp` while preserving the HTTP surface.

Depends on:

- W1.
- W7.
- W8, because stdio should prove the native MCP core before HTTP adds session
  complexity.

Unlocks:

- W10.
- W12 hard forbidden dependency gate.
- W14 release artifacts.

Implementation notes:

- Rebuild `/mcp` on Asupersync native HTTP/web primitives.
- Identify the concrete HTTP implementation surface before coding W9:
  - first preference is Asupersync's native HTTP/web API in the pinned version,
  - if that surface is incomplete, choose a minimal HTTP library that does not
    pull Tokio in normal features and can be driven from Asupersync I/O,
  - record the chosen API in the implementation bead before writing handlers.
- Preserve:
  - loopback-safe default binding behavior
  - explicit opt-in for remote bind
  - host guard
  - origin guard
  - JSON response mode
  - Streamable HTTP stateful/session behavior
  - protected-resource metadata route
  - OAuth bearer validation
  - clear unauthenticated failure response
- Host/origin guard behavior must be explicit:
  - default bind is loopback-safe,
  - non-loopback bind requires explicit operator opt-in,
  - Host validation rejects DNS-rebinding attempts,
  - Origin validation uses a configurable allowlist,
  - Host/Origin checks run before OAuth validation.
- Request size limits must reject oversized HTTP bodies before JSON parsing.
- Authorization headers and bearer token strings must never be logged at any
  log level.
- Prefer an explicit allowlist for logged HTTP headers instead of trying to
  blacklist only sensitive names. Headers such as `Authorization`, `Cookie`,
  `Referer`, and proxy-specific auth headers must not leak by default.
- Compare OAuth bearer tokens with constant-time equality or the same secret
  comparison primitive used for init tokens. Reject tokens with invalid shape or
  length before comparison so validation does not leak variable-work detail.
- OAuth token validation must produce a typed `ScopeGrant` or equivalent value
  that flows through the per-request region to dispatch. Do not store grants in
  globals or thread-locals.
- Use request-as-region:
  - every HTTP request gets its own region
  - spawned work belongs to the request
  - cancellation and cleanup drain before request completion where required
- Use narrowed capabilities:
  - most handlers should not receive full authority
  - read-only metadata routes should not get DB or spawn authority unless needed
- Avoid carrying axum/tower abstractions forward mechanically.

Acceptance criteria:

- Golden HTTP transcripts from W1 pass.
- Existing HTTP e2e coverage is ported away from axum test helpers.
- `cargo tree -i axum`, `cargo tree -i hyper`, and `cargo tree -i rmcp` show no
  production dependency.
- HTTP shutdown drains active request regions.
- Streamable HTTP remains supported; it is not optional in the thin-native line.
- Host/origin, OAuth, and request-size tests prove checks happen before tool
  dispatch.

## Work Package W10: HTTP Scope Enforcement And Transport Security

Purpose:

Fix the current captured-only `ScopeGrant` limitation while the HTTP transport
is being rewritten.

Depends on:

- W9.

Unlocks:

- W11 security/concurrency tests.
- W14 release confidence.

Current issue:

`crates/oraclemcp-core/src/http.rs` records validated OAuth scopes in
`ScopeGrant`, but the dispatch path does not read them. A narrow token can
therefore be authenticated without lowering the session operating-level ceiling.

Target behavior:

- OAuth scopes lower authority monotonically.
- Scopes must never raise profile/session authority.
- A token with only `oracle:read` can call read tools but cannot reach write,
  DDL, admin, or challenge-confirmed execution paths if those are ever exposed.
- Absence of an `oracle:*` scope defaults to the safe floor.

Implementation notes:

- Carry scope grant into the native HTTP MCP session/request context.
- Apply `oraclemcp_auth::apply_oauth_scopes` or equivalent monotone-down logic
  before tool dispatch.
- Compute the effective operating level as the minimum of:
  - OAuth scope ceiling,
  - profile `max_level`,
  - current session level or step-up window.
- A token claiming broader authority than the profile ceiling is capped by the
  profile ceiling, never allowed to raise it.
- A protected profile remains `READ_ONLY` even with a valid broader token.
- Include the resolved effective operating level in structured diagnostics where
  useful, without exposing token content.
- Add regression tests:
  - narrow read token cannot call higher-level tools
  - broad token cannot exceed profile `max_level`
  - broad token plus protected profile remains `READ_ONLY`
  - missing token fails when OAuth is enabled
  - metadata route remains discoverable

Acceptance criteria:

- The current captured-only regression is replaced by enforced least privilege.
- Tests prove a narrow OAuth token lowers authority.
- No bearer token is logged.

## Work Package W11: Deterministic Asupersync Test Suite

Purpose:

Prove the migration did not merely compile, but actually adopted cancel-safe
runtime semantics.

Depends on:

- W4 for DB tests.
- W6a for pure `Cx` propagation.
- W6b for DB-facing `Cx` propagation.
- W7 for runtime primitives.
- W8 for stdio.
- W9 for HTTP.
- W10 for HTTP scope tests.

Unlocks:

- W12.
- W13.
- W14.

Implementation notes:

- Convert ordinary async tests to Asupersync test helpers incrementally. Do not
  use bulk regex rewrites across the workspace; port and verify one test suite
  at a time.
- Start runtime-only deterministic tests as soon as W7 exists:
  - shutdown waiters,
  - admission limits,
  - timeout losers,
  - signal/drain behavior.
- Use `LabRuntime` where concurrency matters:
  - shutdown waiters
  - admission permits
  - request cancellation
  - timeout loser drain
  - HTTP request regions
  - DB call cancellation
  - preview-token single-use races
- Add oracles where useful:
  - quiescence
  - obligation leaks
  - loser drain
  - futurelock detection
- Add a safety-invariant negative test with a mock or instrumented adapter:
  malformed or unauthorized SQL must return a guard/classification error before
  any Asupersync network I/O, DNS resolution, DB connection acquisition, session
  lease acquisition, or execution-side mutable state transition.
- Add a preview-token single-use concurrency test: two request/tool regions race
  to redeem the same preview token, exactly one succeeds, and the other receives
  a token-already-used error. The test must control scheduling around the
  check-and-invalidate point.
- Keep fixed seeds for deterministic repro.
- Preserve crashpack/replay metadata for subtle concurrency failures if the
  runtime exposes it in the adopted version.
- Live DB tests should verify:
  - connect
  - ping
  - describe
  - query rows
  - named binds
  - positional binds
  - transaction rollback/commit behavior
  - DBMS_OUTPUT capture
  - call timeout behavior
  - LOB capping
  - query cancellation cleanup
- Protocol tests from W8.5 should run in the normal test suite.
- Redaction tests should include HTTP request logging and Authorization headers,
  not only config/doctor paths.

Acceptance criteria:

- Normal test suite passes without Tokio.
- At least one deterministic test proves cancellation cleanup for a tool call.
- At least one deterministic test proves request/tool region quiescence.
- Live DB tests pass when the required Oracle test environment is available and
  skip with explicit reason when it is not.

## Work Package W12: Forbidden Dependency Hard Gate

Purpose:

Turn the architecture decision into an automated invariant.

Depends on:

- W4 for thick DB removal.
- W8 for stdio `rmcp` removal.
- W9 for HTTP `rmcp`/`axum`/`hyper` removal.
- W11 for test replacement.

Unlocks:

- W13.
- W14.

Implementation notes:

- Update `cargo deny` or a dedicated CI script to fail production builds if
  forbidden crates remain.
- Update `scripts/oraclemcp_boundary_lint.sh` to match the thin-native boundary
  and fail if Tokio, Axum, Hyper, `rmcp`, ODPI-C, or other removed crate families
  appear in the normal production dependency graph.
- Check both normal and all-target dependency graphs carefully, because dev
  dependencies may legitimately include comparison tools during migration.
- Suggested checks:
  - `cargo tree -e normal -i tokio`
  - `cargo tree -e normal -i asupersync-tokio-compat`
  - `cargo tree -e normal -i rmcp`
  - `cargo tree -e normal -i axum`
  - `cargo tree -e normal -i hyper`
  - `cargo tree -e normal -i hyper-util`
  - `cargo tree -e normal -i oracle`
  - `cargo tree -e normal -i odpic-sys`
  - `cargo tree -e normal -i r2d2`
- If a forbidden crate remains only in dev-dependencies, document why and ensure
  it cannot enter published artifacts.
- Prefer `deny.toml` `[bans]` entries for hard forbidden crates, backed by a
  separate `cargo tree -e normal -i ...` CI check so platform/feature surprises
  are visible.
- If `asupersync-tokio-compat` is used temporarily, every callsite must carry a
  `COMPAT-REMOVE` comment tied to an open work item. The hard gate must fail the
  final production graph if compat remains.

Acceptance criteria:

- CI fails if production code reintroduces Tokio, `asupersync-tokio-compat`,
  rmcp, axum, hyper, ODPI-C, or r2d2.
- `cargo deny check` or the chosen gate is part of the required pre-commit /
  pre-publish gate.

## Work Package W13: Performance And Footprint Evidence

Purpose:

Replace assumptions about thin-native benefits with measured evidence.

Depends on:

- W11.
- W12.

Unlocks:

- W14.

Implementation notes:

- Measure before and after where practical:
  - binary size, compared against the W0 baseline,
  - Docker image size, compared against the W0 baseline,
  - install/build complexity, compared against the W0 baseline,
  - cold startup time, compared against the W0 baseline,
  - first connection time
  - simple query latency
  - paginated query latency
  - concurrent tool calls under admission control
  - shutdown drain behavior under active request
- Avoid invented performance claims.
- Store benchmark commands and environment assumptions.
- Use criterion or focused integration benchmarks where they already fit the
  repo; do not overbuild benchmarking infrastructure.

Acceptance criteria:

- README/release notes claims are backed by measured artifacts or removed.
- At least one benchmark proves the thin-native path does not regress the common
  read-query workflow unexpectedly.
- Docker image changes are measured if Docker remains part of release artifacts.

## Work Package W14: Release Artifact Update

Purpose:

Ensure published artifacts match the thin-native architecture.

Depends on:

- W5 docs/doctor.
- W11 tests.
- W12 dependency gates.
- W13 evidence.

Implementation notes:

- Update README:
  - remove thick-mode install path
  - remove Instant Client requirements
  - explain pinned nightly if relevant for source builds
  - update Docker examples
  - update profile examples for thin mode
  - update troubleshooting
- Update `server.json` if install/runtime instructions change.
- Update GHCR Dockerfile/workflow:
  - remove Instant Client install
  - remove ODPI-C build assumptions
  - verify image can run stdio tool-surface mode
  - verify image can run live thin mode when profile/env are supplied
- Update crates.io metadata if needed.
- Determine the version bump before the first thin-native crates.io release.
  Removing Instant Client, switching to pinned nightly, and dropping thick-mode
  feature semantics are breaking changes for source builders and Docker users.
  Do not publish the thin-native line as a patch release; document the breaking
  changes in CHANGELOG or release notes before tagging.
- Update release workflow gates:
  - fmt
  - clippy
  - test
  - deny
  - dependency forbidden gate
  - packaging check
  - Docker smoke
  - MCP registry smoke
- Document rollback/recovery for an immutable crates.io release:
  - bad crates.io versions can be yanked but not unpublished,
  - recovery is yank plus patch release,
  - GHCR/GitHub/MCP registry artifacts must be advanced to the fixed version,
  - release notes must state any thin-native breaking change clearly.

Acceptance criteria:

- `cargo package --workspace` succeeds.
- Release artifacts do not document or require Instant Client.
- GHCR image no longer bundles Instant Client.
- MCP registry instructions point to thin-native setup.
- crates.io, GitHub release, GHCR, and MCP registry are synchronized by the
  existing tag-driven process.

## Beads Conversion Guidance

Convert this plan into this checkout's local `.beads/` database. oraclemcp
beads live with oraclemcp, not in the parent `plsql-intelligence` tracker.
Use `br` from the repo root, then run `br sync --flush-only` so the git-friendly
`.beads/issues.jsonl` export matches the database. Commit `.beads/` with the
planning or code change it describes when the operator asks for a commit.

Suggested bead epics:

- Epic: Thin-only Oracle driver migration
- Epic: Native Asupersync runtime migration
- Epic: Native MCP transport replacement
- Epic: Thin-native security and credential safety
- Epic: Thin-native release and documentation

Suggested dependency shape:

- Golden behavior harness blocks transport rewrite beads.
- Nightly toolchain blocks thin-driver and Asupersync runtime beads.
- Published `oracledb` dependency blocks releaseable thin adapter beads.
- Thin adapter blocks thin doctor/docs and DB live tests.
- `Cx` propagation blocks native runtime, stdio, HTTP, and deterministic tests.
- Native stdio blocks native HTTP.
- Native stdio blocks MCP conformance tests; MCP conformance blocks native HTTP.
- Native HTTP blocks OAuth scope enforcement.
- All native replacement beads block forbidden dependency hard gate.
- Hard gate blocks release artifact beads.

Every implementation bead should include:

- user-facing value,
- files likely touched,
- dependency blockers,
- safety invariant impact,
- credential/logging considerations,
- tests to add or update,
- acceptance criteria,
- rollback or recovery notes if a live release artifact is affected.

## Review Checklist For Future Planning Rounds

Use this checklist before implementation starts.

Self-containment:

- Can an agent implement W4 without reading the original chat?
- Can an agent implement W8 without knowing `rmcp` internals from memory?
- Can an agent implement W10 from the plan and current source alone?

Dependency graph:

- Are there cycles between thin DB, `Cx` propagation, and transport rewrite?
- Are W6a and W6b represented as separate beads with separate blockers?
- Are there orphan tasks that do not unlock a user-visible improvement?
- Is every release task blocked by tests and dependency gates?

Justification:

- Does every architecture decision explain why it helps the user?
- Does every forbidden dependency have a clear reason?
- Does every retained protocol behavior have a compatibility reason?

Steady state:

- A review round should produce refinements, not a new architecture.
- If a review proposes keeping thick fallback, it must justify the operational
  cost against the pure-Rust goal.
- If a review proposes keeping `rmcp`, `axum`, or `hyper`, it must explain why
  a full Asupersync-native goal is no longer desired.

## Review Round Ledger

This plan is meant to go through multiple review rounds before implementation.
Record each round here so future agents can tell whether the plan is converging
or still changing structurally.

### Round 1: Claude + Gemini Review

Inputs:

- `AGENTS.md`
- initial `PLAN_ASUPERSYNC_THIN_NATIVE.md`
- current repo grep checks for session leases, type serialization, AWR/ASH,
  OAuth scopes, preview tokens, telemetry dependencies, and explain-plan paths

Accepted changes:

- Added hard preservation requirements for existing session leases.
  Reason: the current repo already has lease semantics for transaction,
  savepoint, DBMS_OUTPUT, and session state. A thin pool that does not preserve
  pinning would be a correctness regression.

- Added NUMBER/string and NLS-stable output as explicit hard contracts.
  Reason: the current serializer already treats NUMBER losslessly by default;
  the thin adapter must not reintroduce lossy numeric conversion.

- Added AWR/ASH license gating as a preserved invariant.
  Reason: `oraclemcp-db` already models Diagnostics Pack availability and
  fallback. The migration must not make licensed diagnostics silently available
  or silently broken.

- Added async TOCTOU guidance for guard classification.
  Reason: moving dispatch to async creates more places where an implementation
  could accidentally await or acquire a DB lease before classifying a raw SQL
  statement.

- Added individual tool-signature propagation, not only top-level dispatch.
  Reason: `&Cx` has no value if only the dispatcher sees it while DB-backed
  tools continue to hide runtime and cancellation semantics internally.

- Added explicit OCI IAM / enterprise-auth audit.
  Reason: the current config/types mention IAM token auth, while the existing
  thick implementation treats it as ODPI-C-specific work. Thin-only cannot ship
  with an ambiguous auth story.

- Added a native MCP conformance work package.
  Reason: golden transcripts preserve current behavior, but conformance tests
  catch protocol edge cases the current SDK may have handled implicitly.

- Added telemetry audit to runtime migration.
  Reason: `oraclemcp-telemetry` currently uses `tracing-subscriber`, which is
  probably fine, but the plan should prevent future Tokio-tied telemetry from
  reappearing.

- Added hard gate for `asupersync-tokio-compat`.
  Reason: compat is useful only as a temporary bridge; the user asked for a
  fully native final state.

- Added `.beads/` warning.
  Reason: the local checkout currently has an untracked `.beads/` directory,
  while repo instructions say not to use or commit a separate tracker here.

Changed or reframed feedback:

- The review suggested several "hard invariants" as if they came from a memory
  file. These were not accepted blindly. Only invariants verified in the repo or
  safe to phrase as audit tasks were added.

- The review suggested impact preview must always be autonomous
  savepoint-and-rollback. The repo already has savepoint preview machinery in
  `lease.rs`, while `oracle_explain_plan` still appears to use `EXPLAIN PLAN`
  for read-only plan analysis. The plan now treats this as an inventory and
  compatibility/correctness item rather than rewriting tool semantics inside
  the thin adapter task.

- The review suggested HTTP implementation details that depend on the actual
  Asupersync web API surface. The plan now requires identifying the concrete
  API before W9 coding starts instead of pretending the exact API name is known
  without checking the pinned version.

Rejected or deferred feedback:

- No dated vendoring deadline was added.
  Reason: the operator explicitly asked for dependency order, not timeline/date
  planning. The plan still requires replacing local path dependencies before
  crates.io release.

- No claim was added that every enterprise auth mode is supported by thin mode.
  Reason: this must be audited against the chosen `oracledb` version. The plan
  now requires explicit support or explicit structured unsupported errors.

Next review prompt:

```text
Carefully review PLAN_ASUPERSYNC_THIN_NATIVE.md after Round 1 revisions. Focus
on whether the plan is now self-contained, dependency-aware, and implementable.
Do not propose timeline/date changes. Find remaining ambiguity, missing tests,
wrong dependency edges, or safety gaps. Prefer concrete patch-style additions.
```

Self-containment:

- Can an agent implement W4 without reading the original chat?
- Can an agent implement W8 without knowing `rmcp` internals from memory?
- Can an agent implement W10 from the plan and current source alone?

Dependency graph:

- Are there cycles between thin DB, `Cx` propagation, and transport rewrite?
- Are there orphan tasks that do not unlock a user-visible improvement?
- Is every release task blocked by tests and dependency gates?

Justification:

- Does every architecture decision explain why it helps the user?
- Does every forbidden dependency have a clear reason?
- Does every retained protocol behavior have a compatibility reason?

Steady state:

- A review round should produce refinements, not a new architecture.
- If a review proposes keeping thick fallback, it must justify the operational
  cost against the pure-Rust goal.
- If a review proposes keeping `rmcp`, `axum`, or `hyper`, it must explain why
  a full Asupersync-native goal is no longer desired.

### Round 2: Claude + Gemini Review

Inputs:

- Round 1 revised `PLAN_ASUPERSYNC_THIN_NATIVE.md`
- current repo facts for proxy auth, ADB/wallet support, boundary lint, error
  classification, and preview-token safety

Accepted changes:

- Clarified that W6a depends only on W2 while W6b depends on W4.
  Reason: pure server transport work can start without waiting for the thin DB
  adapter, but DB-facing tool execution cannot.

- Filled the future-review checklist instead of leaving an empty heading.
  Reason: an empty section invites skipped review steps during beads conversion.

- Made `docs/behavior-inventory.md` mandatory before downstream implementation.
  Reason: later beads rely on the behavior inventory as a concrete contract.

- Added explicit `oracle_explain_plan` / `PLAN_TABLE` tracking.
  Reason: `EXPLAIN PLAN FOR ...` writes `PLAN_TABLE`; if that is current
  behavior, it must become an explicit correctness bead rather than disappearing
  inside the thin adapter rewrite.

- Added constant-time OAuth bearer-token comparison.
  Reason: bearer tokens are timing-sensitive secrets just like init tokens.

- Added driver-error redaction before MCP/client-facing error envelopes.
  Reason: thin-driver connection errors may include connect strings, usernames,
  wallet paths, or tokens, and MCP clients should never receive those values.

- Added preview-token single-use race testing.
  Reason: single-use authorization is only real if concurrent redemption cannot
  produce two successes.

- Added the parent `oracle-qmwz` epic to beads guidance.
  Reason: the repo policy says oraclemcp work lives in the parent tracker, so
  conversion must not create orphan beads.

- Added semver guidance for the first thin-native release.
  Reason: removing thick mode, Instant Client assumptions, and stable/MSRV
  claims is a breaking source/build/runtime change, not a patch release.

- Added proxy-auth and Autonomous Database/cloud connectivity audits.
  Reason: the current repo has proxy-auth and ADB/wallet code paths; thin-only
  must preserve them or fail with explicit unsupported-feature diagnostics.

- Added ORA-code observability and doctor failure classification.
  Reason: agents and humans use structured ORA codes and failure classes for
  retry, introspection, and setup repair.

- Added a guard-before-I/O negative test.
  Reason: the fail-closed SQL guard invariant must be proven across async gaps,
  not only described.

- Added `scripts/oraclemcp_boundary_lint.sh` to W12.
  Reason: the repo already has a boundary lint script; the final architecture
  should reuse it as part of the hard dependency gate.

Changed or reframed feedback:

- Gemini said the plan is ready for beads conversion with these additions. The
  work is closer, but the planning skill asks for at least four review rounds
  and steady-state convergence before conversion.

- Proxy auth and ADB were added as audited preservation requirements, not as
  claims that the selected thin `oracledb` version already supports every path.

Next review prompt:

```text
Carefully review PLAN_ASUPERSYNC_THIN_NATIVE.md after Round 2 revisions. Focus
only on residual implementability gaps: dependency edges, missing acceptance
criteria, security regressions, release/process traps, and places where the plan
still overclaims unsupported thin-driver behavior. Do not propose timeline/date
changes. Prefer minimal patch-style additions.
```

### Round 3: Gemini Review, Claude CLI Stalled

Inputs:

- Round 2 revised `PLAN_ASUPERSYNC_THIN_NATIVE.md`
- repo facts confirming current proxy auth, ADB/wallet support, boundary lint,
  and stdio e2e test locations

Review execution notes:

- Two Claude CLI attempts were started for Round 3. Both produced no review
  output after several minutes and were terminated so no background process was
  left running.
- Gemini `gemini-2.5-pro` completed the Round 3 review and wrote findings to a
  temporary plans file outside the repo. The findings were integrated manually
  into this untracked plan.

Accepted changes:

- Added panic-path secret disclosure as a non-negotiable.
  Reason: credential redaction must cover panic messages, backtraces, hooks,
  crash reports, and test failures, not only normal logs and error envelopes.

- Added semver hygiene for publishing `oracledb`.
  Reason: `oraclemcp` should not force a surprising `oracledb` release on other
  downstream users just to unblock its own migration.

- Added preliminary Asupersync HTTP/web API audit to W0.
  Reason: W9 should not discover too late that the pinned runtime lacks needed
  host/origin, header, status, stream, size-limit, or drain primitives.

- Added an explicit blocker decision for mission-critical unsupported auth.
  Reason: thin-only remains the target, but removing thick mode while a current
  production auth path is unsupported would be an operator-visible regression.

- Added `.unwrap()` / `.expect()` audit in sensitive paths.
  Reason: panic-prone handling near credentials can bypass normal redaction and
  structured error handling.

- Added native stdio test-harness replacement criteria.
  Reason: passing behavior is not enough if tests still depend on `rmcp` helpers
  that mask native transport regressions.

Changed or reframed feedback:

- The review suggested a broad custom panic hook. The plan now requires verifying
  any production panic hook keeps secrets redacted, without mandating a new hook
  unless implementation needs one.

Next review prompt:

```text
Carefully review PLAN_ASUPERSYNC_THIN_NATIVE.md after Round 3 revisions. This is
the fourth planning review. Look for only marginal issues now: contradictory
dependency edges, acceptance criteria that cannot be verified, missed secret
surfaces, or places where beads conversion would lose dependency information.
Do not propose timeline/date changes or new architecture unless a safety
invariant is broken. Prefer tiny patch-style additions or say steady-state.
```

### Round 4: Gemini Final Convergence Review

Inputs:

- Round 3 revised `PLAN_ASUPERSYNC_THIN_NATIVE.md`
- full current plan supplied on stdin

Result:

- Gemini reported the plan is in steady state and ready for beads conversion.
- No significant gaps, contradictory dependencies, unverifiable acceptance
  criteria, or architectural flaws were reported.

Accepted marginal changes:

- Extended credential-redaction non-negotiable to fixtures, PII, and sensitive
  business data.
  Reason: test artifacts can leak real-world sensitive data even when they do
  not contain passwords or tokens.

- Extended W4 driver-error redaction to all structured driver error fields.
  Reason: sensitive connection/auth details can appear outside a display
  message.

- Added HTTP header logging allowlist guidance to W9.
  Reason: blacklisting only `Authorization` misses `Cookie`, `Referer`, proxy
  auth headers, and deployment-specific sensitive headers.

Planning-workflow status:

- The plan has now survived four review rounds.
- The latest review produced only marginal hardening additions.
- The next planning-workflow step is conversion to beads in the parent
  `plsql-intelligence` tracker under `oracle-qmwz`, preserving the dependency
  graph.

## Final Done Definition

The migration is done only when all of these are true:

- Thin mode is the only production Oracle backend.
- Default install does not require Oracle Instant Client, ODPI-C, or a C
  toolchain for Oracle connectivity.
- Production dependency graph contains no Tokio, rmcp, axum, hyper, ODPI-C
  `oracle`, r2d2, or `asupersync-tokio-compat`.
- Stdio MCP golden transcripts pass.
- HTTP MCP golden transcripts pass.
- MCP conformance tests pass for native stdio and HTTP.
- OAuth scopes are enforced as monotone-down authority caps.
- SQL guard behavior is unchanged or stricter.
- Session lease behavior is preserved.
- NUMBER/string and NLS-stable serialization behavior is preserved.
- AWR/ASH license gating remains enforced.
- Unsupported thin auth modes fail explicitly and are documented.
- Credential redaction tests pass.
- Deterministic Asupersync cancellation/quiescence tests pass.
- Live DB tests pass in a configured Oracle test environment.
- `cargo fmt --all -- --check` passes.
- `cargo clippy --workspace --all-targets -- -D warnings` passes.
- `cargo test --workspace` passes.
- `cargo deny check` passes.
- Forbidden dependency gate passes.
- `cargo package --workspace` passes.
- README, `robot-docs`, Docker, and MCP registry instructions describe the
  thin-native architecture and not thick mode.
