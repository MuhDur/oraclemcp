# oraclemcp Behavior Inventory

Initially generated for bead `oraclemcp-w0-behavior-inventory-4t4` on
2026-06-15, then maintained as the thin-only, Asupersync-native migration
progressed. It intentionally records current behavior and known gaps; it does
not record credentials, live Oracle hostnames, customer schema names, or real
query text.

## Evidence Snapshot

| Area | Current fact | Evidence |
| --- | --- | --- |
| Workspace | Cargo workspace with 9 crates plus `oraclemcp` binary, `resolver = "2"`, edition 2024, pinned nightly `nightly-2026-05-11`, and no stable MSRV on the thin-native line. | `Cargo.toml`, `rust-toolchain.toml` |
| Safety posture | Every crate forbids unsafe code; raw SQL safety is centered on `oraclemcp-guard`. | `Cargo.toml`, crate roots, `AGENTS.md` |
| Current release line | All package versions and `server.json` are aligned at 0.4.1. | `Cargo.toml`, crate `Cargo.toml` files, `server.json` |
| Current DB mode | Default build includes live Oracle support through the pure-Rust `oracledb` thin driver. | `README.md`, `crates/oraclemcp-db/Cargo.toml` |
| Current runtime/transport | Native stdio and native Streamable HTTP live in `oraclemcp-core`; dispatch receives explicit Asupersync `Cx` contexts; Tokio, `rmcp`, Axum, Hyper, ODPI-C, and `r2d2` are absent from the current manifests and lockfile. | `crates/oraclemcp-core/src/server.rs`, `crates/oraclemcp-core/src/http.rs`, `Cargo.lock`, `Cargo.toml` |
| Current bead state | Repo-local `.beads/` contains the migration graph and W-series release hardening work. | `br list --json`, `bv --robot-triage` |
| Local release artifacts | `docs/performance-footprint.md` records release binary size, startup/RSS, package sizes, Docker image size, Docker smoke, and Unix pipe behavior. | `docs/performance-footprint.md`, `tests/artifacts/perf/20260615T182242Z-7dd4a60/` |

## CLI Surface

| Command | Current behavior to preserve or revise deliberately | Evidence |
| --- | --- | --- |
| `oraclemcp serve` | Serves stdio by default; `--listen` enables HTTP; `--allow-no-auth` gates unauthenticated HTTP; OAuth/Host/Origin/stateful/JSON transport config can come from config or CLI; `--stdio-token` may resolve from `$ORACLEMCP_STDIO_TOKEN`; `--profile` selects active profile. | `crates/oraclemcp/src/main.rs`, `crates/oraclemcp-config/src/lib.rs`, `README.md` |
| `oraclemcp info` | Prints package/runtime metadata without requiring a DB connection. | `crates/oraclemcp/src/main.rs` |
| `oraclemcp doctor [--profile] [--online] [--fix]` | Offline checks always run. Profile mode inspects non-secret profile metadata without resolving secrets; `--online --profile` adds live connectivity, auth, role/open-mode, standby, and privilege checks. `--fix` is scoped to service-local state: it may copy the legacy 0.4.x default audit JSONL into the XDG state audit path when the current target is absent, with a backup artifact and no deletion; it still refuses Oracle, audit hash-chain rewrite/merge, classifier, and profile ceiling repairs with exit 4. Output must redact connect strings, usernames, credential refs, passwords, IAM tokens, and wallet paths while preserving ORA codes/failure classes. | `crates/oraclemcp/src/main.rs`, `README.md` |
| `oraclemcp profiles` / `list-profiles` | Lists configured profiles and safe metadata. Connect strings and credential refs are omitted from metadata. | `crates/oraclemcp/src/main.rs`, `crates/oraclemcp-config/src/profile.rs` |
| `oraclemcp capabilities` | Emits robot-readable config, tools, tiers, auth posture, and environment guidance. | `crates/oraclemcp/src/main.rs`, `crates/oraclemcp/src/robot_docs.rs` |
| `oraclemcp robot-docs guide` | Emits agent-oriented setup and usage docs. | `crates/oraclemcp/src/robot_docs.rs` |
| `oraclemcp setup` | Generates local profile/tool templates and references `ORACLEMCP_STDIO_TOKEN`; must not print real secrets. | `crates/oraclemcp/src/main.rs` |
| `oraclemcp sign-tool` | Signs operator-defined TOML custom tools with `ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY`. | `crates/oraclemcp/src/main.rs`, `README.md` |
| Global `--robot-json` / `--json` | Machine-readable output mode for CLI commands that support it. | `crates/oraclemcp/src/main.rs` |

## Agent Ergonomics Contract

| Contract item | Current behavior | Evidence |
| --- | --- | --- |
| Binary names | `oraclemcp` is canonical; `om` is accepted as an argv0-aware short alias in help and hints. | `crates/oraclemcp/src/main.rs` |
| Structured output | `--robot-json` and visible alias `--json` emit compact machine-readable stdout for robot-safe CLI commands; diagnostics remain on stderr. | `crates/oraclemcp/src/main.rs`, `crates/oraclemcp/src/robot_docs.rs` |
| Exit-code dictionary | 0 success (including applied scoped doctor migration); 1 process/transport failure after startup; 2 invalid invocation, config/auth error, failed doctor check, or startup safety block; 3 service-manager state/failure; 4 `doctor --fix` refused unsafe/out-of-scope repair. | `crates/oraclemcp/src/main.rs`, `crates/oraclemcp/src/service_lifecycle.rs`, `crates/oraclemcp-core/src/doctor.rs` |
| Dangerous-operation gating | Local service install/restart/uninstall require `--dry-run` or `--yes`; guarded SQL writes require preview-derived confirmation plus operating-level gates. | `crates/oraclemcp/src/service_lifecycle.rs`, `crates/oraclemcp/src/dispatch/mod.rs` |
| In-tool docs | `oraclemcp robot-docs guide` and `oraclemcp --json capabilities` expose the CLI contract and the MCP/CLI/dashboard parity matrix. | `crates/oraclemcp/src/robot_docs.rs`, `crates/oraclemcp/src/main.rs` |

## MCP / CLI / Dashboard Parity Matrix

| Capability | CLI | MCP | Dashboard | Status |
| --- | --- | --- | --- | --- |
| Tool and server capability discovery | `oraclemcp --json capabilities`, `oraclemcp --json robot-docs guide` | `tools/list`, `tools/call oracle_capabilities`, `resources/read oracle://capabilities` | Operator overview capability posture | Aligned |
| Profile inventory and switching | `oraclemcp --json profiles`, `oraclemcp --json doctor --profile <profile>` | `oracle_list_profiles`, `oracle_switch_profile`, `oracle_connection_info` | Config profiles view, lane profile controls, connection health | Aligned |
| Offline and live diagnostics | `oraclemcp --json doctor`, `oraclemcp --json doctor --online --profile <profile>` | `oracle_connection_info`, `oracle_capabilities` | Doctor probes, health and capacity pages | Aligned |
| Guarded SQL workflow | Documented by `oraclemcp robot-docs guide` | `oracle_preview_sql`, `oracle_query`, `oracle_execute`, DDL/source-patch tools, `oracle_set_session_level` | SQL workbench read/execute/DDL modes | Aligned |
| Schema/object metadata | `oraclemcp --json capabilities` advertises dictionary/source tools | `oracle_list_schemas`, `oracle_schema_inspect`, `oracle_search_objects`, `oracle_get_ddl`, `oracle_get_source` | Explorer schemas, objects, source/DDL detail | Aligned |
| Service lifecycle and auth | `oraclemcp --json service ...`, `oraclemcp --json clients ...` | Stdio init token, HTTP OAuth, mTLS, client credentials | Pairing ticket, service health, active lanes | Aligned |
| Audit-chain visibility | `oraclemcp audit verify <file>` | Privileged MCP actions append audit-chain records | Audit timeline, filters, proof export | Aligned |

## MCP Surface

| Surface | Current contract | Evidence |
| --- | --- | --- |
| Stdio initialize | The native JSON-RPC loop handles MCP initialize over stdin/stdout; optional init token is validated by constant-time comparison before normal use. | `crates/oraclemcp-core/src/server.rs`, `crates/oraclemcp-auth/src/init_token.rs`, `crates/oraclemcp-core/tests/e2e_mcp.rs` |
| Stdio tools | `tools/list` exposes registry descriptors with MCP `inputSchema`, optional `outputSchema`, `title`, and explicit advisory annotations. `oracle_query`/`query` and `oracle_explain_plan` declare structured-output schemas; the query schema preserves NUMBER-as-string by default and advertises capped structured ARRAY/JSON/VECTOR decode (`deep_decode=true` only raises the safe row/cell/byte/depth budgets). Read tools set `readOnlyHint=true`; guarded execution/elevation/DDL/deploy/diagnostic-write tools set `destructiveHint=true`. `tools/call` routes through `ToolDispatch`; annotations do not replace the SQL guard or operating-level gate. | `crates/oraclemcp-core/src/server.rs`, `crates/oraclemcp-core/src/tools.rs`, `crates/oraclemcp/src/registry.rs` |
| Stdio resources/prompts | Initialize advertises served resources with `subscribe=false` and `listChanged=false` plus served prompts with `listChanged=false`. `resources/list`, `resources/templates/list`, `resources/read`, `prompts/list`, and `prompts/get` are handled. Static reads return `oracle://capabilities` and `oracle://tools`; schema/object reads route through the same safe tool dispatch path as `oracle_schema_inspect`, `oracle_get_source`, and `oracle_get_ddl`. Completion, subscriptions, and lease-backed session resources are not advertised. | `crates/oraclemcp-core/src/server.rs`, `crates/oraclemcp-core/src/resources.rs`, `crates/oraclemcp-core/tests/mcp_conformance.rs` |
| HTTP endpoint | Streamable HTTP is mounted at `/mcp` behind an explicit router; request targets retain parsed query pairs. `MCP-Protocol-Version` is honored and unsupported values return typed `400 unsupported_protocol_version` before dispatch. JSON response and stateful/session behavior are configurable. In stateful mode initialize issues `mcp-session-id`, subsequent POST/GET/DELETE requests must present a known id, POST responses are buffered for GET replay by `cursor` / `Last-Event-ID`, and a cursor older than the retained per-session ring returns typed `410 stream_cursor_expired` instead of silently replaying a truncated suffix. DELETE invalidates the session, clears its replay buffer, and invokes the stateful lane lifecycle hook so the bound lane is closed. Listener shutdown stops accepting, drains workers, then closes all stateful lanes. Stateless DELETE returns 405. Product binaries can serve the embedded operator dashboard outside the API prefix; `/operator/v1` is a versioned operator API with generated schema/TS artifacts, REST health/metrics/audit-tail/active-lanes/vsession routes, per-subject/per-lane SSE event replay by `cursor` / `Last-Event-ID`, and guarded action routes that forward through MCP `tools/call`; it never falls through to an HTML history fallback. | `crates/oraclemcp-core/src/http.rs`, `crates/oraclemcp-core/src/operator_protocol.rs`, `crates/oraclemcp-core/src/lane.rs`, `crates/oraclemcp/src/main.rs` |
| HTTP stateful capacity | In served stateful mode, new lane allocation is admitted before the lane thread/factory can open a physical Oracle connection. The listener also admits accepted connection workers before spawning per-connection threads, and long-lived Streamable HTTP GET/SSE subscribers have a separate transport cap because they are not lanes. N4b-finalized upper-bound defaults are 8 stateful lanes or SSE subscribers per principal bucket and 64 total host slots, with 1 operator and 1 doctor/readiness slot reserved outside regular agent admission; accepted connection workers use the same host budget and reserve. The defaults cite the CX-I6 measurement `tests/artifacts/perf/20260630-cx-i6-phase0-capacity/RESULTS.md`. Exhaustion returns `AT_CAPACITY` with `retry_after_ms`, HTTP 429 / `Retry-After`, and a redacted capacity snapshot when the transport can still return an HTTP response. | `crates/oraclemcp-core/src/admission.rs`, `crates/oraclemcp-core/src/lane.rs`, `crates/oraclemcp-core/src/http.rs`, `crates/oraclemcp/src/main.rs` |
| HTTP stateless read workers | In served stateless mode, generated catalog/metadata reads route to bounded read-worker lanes keyed by server-derived principal and active profile. Each read-worker lane owns its own OS thread, current-thread Asupersync runtime, reactor, and Oracle connection; non-read work and pinned-session reads remain on the control lane. Successful profile switches invalidate the old read-worker lane set so later reads cannot hit the previous profile. | `crates/oraclemcp-core/src/lane.rs`, `crates/oraclemcp/src/main.rs` |
| OAuth metadata | `/.well-known/oauth-protected-resource` remains public when OAuth is enabled. | `crates/oraclemcp-core/src/http.rs` |
| HTTP guards | `--listen` starts only with OAuth, mTLS client-certificate verification, or explicit `--allow-no-auth`; mTLS requests become application principals only when their leaf DER SHA-256 fingerprint is registered; remote bind requires explicit opt-in; Host and Origin guards protect loopback usage; missing auth returns WWW-Authenticate when OAuth is enabled. Native TLS/mTLS is served by the rustls listener when `[http.tls]` or `--tls-*` material is configured. | `crates/oraclemcp/src/main.rs`, `crates/oraclemcp-auth/src/http_guard.rs`, `crates/oraclemcp-core/src/http.rs` |
| HTTP OAuth scope enforcement | HTTP validates bearer scopes and carries `ScopeGrant` into `ToolDispatch`; dispatch applies monotone-down scope ceilings so narrow tokens cannot reach higher-level tools, broad tokens cannot exceed profile `max_level`, and protected profiles remain `READ_ONLY`. | `crates/oraclemcp-core/src/http.rs`, `crates/oraclemcp-core/src/server.rs`, `crates/oraclemcp/src/dispatch/mod.rs`, `crates/oraclemcp/src/dispatch/tests.rs` |
| Surface auth/no-leak inventory | `/mcp` POST and stateful SSE GET require OAuth, mTLS, per-client bearer, or explicit local dev bypass; `/operator/v1` requires server-derived operator authority and a signed audit sink; browser-originated dashboard POSTs also require paired session cookie, CSRF header, same-origin headers, and route action ticket; dashboard pairing requires loopback and one-time ticket; config apply/reload goes through the same operator gate plus redacted config-ops; per-client credential issuance is CLI-only, stores salted hashes, and prints bearers once; `/readyz` and `/metrics` are unauthenticated infra probes but the regression test asserts they expose no `v$session`, DB identity, SQL text, bind values, wallet, credential, or password markers. The archive installer is verify-before-mutate and the npx wrapper is not shipped yet; F2 owns the future npm wrapper's verify-before-run/no-postinstall contract. | `crates/oraclemcp-core/src/http.rs::tests::surface_inventory_authn_no_leak`, `crates/oraclemcp-core/src/dashboard_auth.rs`, `crates/oraclemcp-core/src/client_credentials.rs`, `scripts/installer_lint_and_offline_smoke.sh`, `oraclemcp-epic-060-f4xo.10.2` |
| Golden baseline | Golden protocol tests cover stdio/HTTP happy paths, served HTTP auth/scope/session behavior, protected-resource metadata, host/origin guards, and stateful Streamable HTTP behavior. | `crates/oraclemcp-core/tests/golden_behavior.rs`, `tests/golden/http`, `tests/golden/stdio`, `tests/conformance/COVERAGE.md` |

## Tool Registry

| Group | Current tools and behavior | Evidence |
| --- | --- | --- |
| Profile/session | `oracle_list_profiles`, `oracle_connection_info`, `oracle_switch_profile`, `oracle_set_session_level`. Session level cannot exceed profile ceiling; protected profiles remain read-only. | `README.md`, `crates/oraclemcp/src/registry.rs`, `crates/oraclemcp/src/dispatch/mod.rs` |
| Read/query | `oracle_query`, `oracle_preview_sql`, `oracle_sample_rows`, `oracle_read_clob`. Raw SQL is classified before DB access; reads admit only proven read-only SQL. | `crates/oraclemcp/src/dispatch/mod.rs`, `crates/oraclemcp-guard/tests/*` |
| Guarded execution | `oracle_execute`, `oracle_compile_object`, `oracle_create_or_replace`, `oracle_patch_source`. DML is rollback-by-default; DDL/Admin require commit and confirmation; committing paths write a durable intent before DB execution. | `README.md`, `crates/oraclemcp/src/dispatch/mod.rs`, `crates/oraclemcp-core/src/write_intent.rs`, `crates/oraclemcp/src/dispatch/tests.rs` |
| Unadvertised guarded-write router | `crates/oraclemcp-core/src/session_tool.rs` implements `oracle_session` lease/escalation/transaction routing, but `oraclemcp` deliberately does not include it in `TOOL_NAMES` or `tools/list`. The served binary exposes guarded write/DDL execution only through individual classifier-gated tools (`oracle_execute`, `oracle_create_or_replace`, …); it keeps the broader `oracle_session` lease/escalation/transaction router off the served surface unless a future explicit opt-in build adds separate release gates. | `crates/oraclemcp-core/src/session_tool.rs`, `crates/oraclemcp/src/registry.rs`, `AGENTS.md` |
| Dictionary/source | `oracle_list_schemas`, `oracle_schema_inspect`, `oracle_describe`, `oracle_describe_index`, `oracle_describe_trigger`, `oracle_describe_view`, `oracle_get_ddl`, `oracle_get_source`, `oracle_compile_errors`, `oracle_search_source`, `oracle_plscope_inspect`. Uses `ALL_*`/dictionary views with privilege degradation. | `README.md`, `crates/oraclemcp-db/src/intelligence.rs`, `crates/oraclemcp-db/src/privileges.rs` |
| Diagnostics | `oracle_explain_plan`, `oracle_capabilities`. Explain-plan is an explicit diagnostic write on primary because it writes `PLAN_TABLE`; it is refused by default and requires `READ_WRITE` plus `allow_plan_table_write=true`. | `crates/oraclemcp/src/dispatch/mod.rs`, `crates/oraclemcp-db/src/intelligence.rs`, `crates/oraclemcp-db/src/standby.rs`, `oraclemcp-thin-only-oracle-driver-kod.1` |
| Compatibility aliases | Legacy names such as `query`, `execute_approved`, `describe_table`, `get_ddl`, `get_object_source`, and others are still registered for client compatibility. | `README.md`, `crates/oraclemcp/src/registry.rs` |
| Operator-defined tools | TOML custom tools are allowed; protected profiles or `require_signed_tools=true` require HMAC signatures. Custom tool execution is read-only only. There is no native/dynamic plugin execution surface. | `crates/oraclemcp/src/main.rs`, `crates/oraclemcp/src/dispatch/mod.rs`, `README.md` |

## Credentials, Secrets, Logs, and Fixtures

| Surface | Current contract | Evidence |
| --- | --- | --- |
| Profile discovery | `$ORACLEMCP_CONFIG`, `~/.config/oraclemcp/profiles.toml`, and `~/.config/oraclemcp/config.toml` are the config inputs. | `crates/oraclemcp-config/src/lib.rs` |
| Credential refs | `env:VAR`, `file:/path`, and `keyring:service/account` resolve through the SecretResolver seam; `literal:value` exists only for development and is rejected for protected profiles; `vault:` is fail-closed until a backend is wired. | `crates/oraclemcp-auth/src/secrets.rs`, `crates/oraclemcp-config/src/profile.rs` |
| Secret storage | `Secret` zeroizes and redacts debug output. | `crates/oraclemcp-auth/src/secrets.rs` |
| Stdio auth | `ORACLEMCP_STDIO_TOKEN` is optional by policy but constant-time compared when required. | `crates/oraclemcp-auth/src/init_token.rs` |
| Custom tool signing | `ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY` signs/verifies custom tool definitions; missing keys fail when signatures are required. | `crates/oraclemcp/src/main.rs`, `README.md` |
| Release secrets | crates.io publishing uses `CARGO_REGISTRY_TOKEN` in the `crates-io` environment; GHCR uses `GITHUB_TOKEN`; MCP registry publishing uses GitHub OIDC. No separate GHCR or MCP registry secret is required by current workflows. | `.github/workflows/release.yml`, `.github/workflows/docker.yml`, `.github/workflows/publish-mcp.yml` |
| Secret lint | Sensitive-data lint scans for embedded URL credentials, cloud keys, private keys, and optional denylist entries. | `scripts/sensitive_data_lint.sh`, `.github/workflows/ci.yml` |
| Logs/errors/fixtures | Tests, docs, and doctor output must use synthetic SQL/profile names and must not include real Oracle hosts, usernames, wallet paths, bind values, tokens, or customer schema names. | `AGENTS.md`, closed safety/release beads |

## Safety and Data Invariants

| Invariant | Current behavior | Evidence |
| --- | --- | --- |
| Fail-closed SQL guard | Raw SQL enters `oraclemcp-guard`; read tools allow only `READ_ONLY` statements, everything else is refused before Oracle. | `crates/oraclemcp/src/dispatch/mod.rs`, `crates/oraclemcp-guard/tests/adversarial_corpus.rs` |
| Guard before I/O target | Guard/classification must happen before network I/O, DNS, connection acquisition, lease acquisition, or mutable execution state. | `AGENTS.md`, `oraclemcp-w11-deterministic-asupersync-tests-blm` |
| Session levels | `OperatingLevel` controls ReadOnly, ReadWrite, DDL, and Admin. Step-up cannot exceed profile `max_level`; protected profiles pin read-only. | `crates/oraclemcp-config/src/profile.rs`, `crates/oraclemcp/src/dispatch/mod.rs` |
| Preview/confirm grants | `oracle_execute`, `oracle_set_session_level`, `oracle_compile_object`, and `oracle_patch_source` use process-local, single-use confirmation grants bound to statement or action material plus profile/session/lane/principal/generation. The legacy deterministic confirmation MAC path is retired. | `crates/oraclemcp/src/dispatch/mod.rs`, `crates/oraclemcp/src/dispatch/tests.rs`, `oraclemcp-w11-deterministic-asupersync-tests-blm` |
| HTTP service instance guard | `serve --listen` acquires a private runtime `service-instance.json` lock after the TCP bind and before AppSpec startup. A second HTTP service instance fails closed with `ORACLEMCP_SERVICE_ALREADY_RUNNING` and reports the existing pid/listen/start metadata; `service status --json` exposes the same discovery block. | `crates/oraclemcp/src/main.rs`, `crates/oraclemcp/src/service_lifecycle.rs`, `docs/operations.md` |
| Durable write intents | When a writable profile is reachable, startup opens `$XDG_STATE_HOME/oraclemcp/write-intents/intents.jsonl` (or `$HOME/.local/state/oraclemcp/...`) and refuses writable service if unresolved intents are recovered. Committing tools append a pending intent with hashed idempotency key, subject, lane, and SQL hash before DB execution; safe terminal outcomes append a resolved record. Recovery rebuilds both the unresolved set and terminal idempotency index, so exact grant+SQL replay is rejected after restart. `CommitInDoubt`/`UnknownDiscarded` stay unresolved so restart fails closed instead of silently re-executing non-idempotent work. | `crates/oraclemcp-core/src/write_intent.rs`, `crates/oraclemcp-core/src/file_store.rs`, `crates/oraclemcp/src/main.rs`, `crates/oraclemcp/src/dispatch/tests.rs` |
| DML rollback default | `oracle_execute` rollbacks by default for DML unless explicitly confirmed/committed. | `crates/oraclemcp/src/dispatch/mod.rs`, `crates/oraclemcp/src/dispatch/tests.rs` |
| Leases | Leases pin one physical session, keep transaction/savepoint/temp/DBMS_OUTPUT state, and force rollback on expiry/release. Missing lease returns structured `LeaseRequired`. | `crates/oraclemcp-db/src/lease.rs`, `crates/oraclemcp-db/tests/chaos.rs` |
| DBMS_OUTPUT | Capture is opt-in on execution paths, line/character/buffer limits are clamped, and output is returned in tool JSON rather than files. | `crates/oraclemcp/src/dispatch/mod.rs`, `crates/oraclemcp/src/dispatch/tests.rs` |
| Serialization | NUMBER is string by default; float output is opt-in; date/timestamp/NLS output is canonicalized; CLOB/BLOB output is capped and marks truncation. | `crates/oraclemcp-db/src/serialize.rs`, `crates/oraclemcp-db/tests/type_fidelity.rs` |
| Privilege degradation | Dictionary privilege checks fall back `DBA_* -> ALL_* -> USER_*`; AWR/ASH requires Diagnostics Pack, otherwise Statspack or structured unavailable error. | `crates/oraclemcp-db/src/privileges.rs`, `crates/oraclemcp-db/src/awr.rs`, `crates/oraclemcp-db/tests/privilege_degradation.rs` |
| Audit | Audit sink is out-of-band, hash-chained, fsync-before-execute, and poisons closed on durable flush failure. Audit records can carry hash-covered structured lifecycle/cancel metadata (`cancel.kind`, `cancel.reason`); stateful lane close writes `lane_lifecycle` with `User/session_delete`, `Timeout/idle_timeout`, or `Shutdown/server_shutdown`/`Shutdown/runtime_drop` instead of relying on a reason embedded in SQL preview text. | `crates/oraclemcp-audit/src/sink.rs`, `crates/oraclemcp-audit/src/record.rs`, `crates/oraclemcp/src/dispatch/mod.rs` |

## Dependency Holdouts

| Crate/family | Current reason present | Migration target |
| --- | --- | --- |
| `tokio` | Absent from the current manifests and lockfile. | Keep absent from the production graph; retain Asupersync `Cx` as the runtime context boundary. |
| `rmcp` | Absent from the current manifests and lockfile. | Keep the native JSON-RPC/MCP stdio and HTTP implementation as the release surface. |
| `axum` | Absent from the current manifests and lockfile. | Keep HTTP routing in the native transport surface. |
| `hyper` / `hyper-util` | Absent from the current manifests and lockfile. | Keep absent from the production graph. |
| `oracle` / ODPI-C | Removed from the DB crate. | Keep absent. |
| `r2d2` | Removed from the DB crate. | Keep absent; the bounded thin pool exposes cancellation-aware `*_cx` paths at checkout and call sites. |
| `reqwest`, `async-std` | Not present in the current dependency graph. | Keep absent. |
| `smol` | Not present in the current dependency graph. | Keep absent from production graph. |
| `asupersync-tokio-compat` | Not present now. | Do not introduce in final production graph; any temporary compat must carry a removal bead. |

## Thin Driver API Coverage

## Thin Driver Release Dependency Decision

Verified on 2026-06-23:

- `Cargo.lock` resolves the published `oracledb = 0.5.1` and
  `oracledb-protocol = 0.5.1` crates from crates.io.
- The published driver exposes the pure-Rust thin connection path plus the
  blocking facade used by the current synchronous DB trait boundary.
- The local `/home/durakovic/projects/rust-oracledb` checkout is a normal
  upstream checkout, not an `oraclemcp` release dependency. Any future driver
  API needed by `oraclemcp` must be filed as granular `rust-oracledb` work and
  released before this repo consumes it.

Decision:

- `oraclemcp` consumes `oracledb = 0.5.1` from crates.io, declared in the
  workspace dependency table with `default-features = false`.
- No vendoring is used. No releaseable `oraclemcp` crate may depend on
  `/home/durakovic/projects/rust-oracledb` or any other external local path.
- The current production graph uses the driver's `BlockingConnection` facade
  behind explicit Asupersync `Cx` checkpoints. This keeps the transport/runtime
  native while the DB trait remains synchronous.
- Release package validation uses `cargo package --workspace --locked
  --no-verify` in the tag workflow to prove tarball assembly without hidden
  external path dependencies. `scripts/publish_crates.sh` then runs
  `cargo publish -p <crate> --locked --dry-run` immediately before each real
  publish, in dependency order, after earlier sibling crates have appeared in
  the crates.io index.

Semver, ownership, and security-fix flow:

- `oracledb` remains independently owned and released from
  `https://github.com/MuhDur/rust-oracledb`; `oraclemcp` consumes it like any
  other public crate.
- Driver fixes flow into `oraclemcp` through normal published `oracledb` version
  bumps and lockfile updates, with release notes in the driver repo for
  downstream users.
- If `oracledb` lacks a required thin capability, the next step is a
  self-contained `rust-oracledb` issue and a new published driver version, not a
  hidden path dependency.

| oraclemcp need | Legacy/current behavior | `oracledb` / thin migration note |
| --- | --- | --- |
| Connect | Thin `oracledb` connect via `RustOracleConnection`; applies username/password, proxy user, wallet location/password, TLS DN/SNI, client identity, edition, app context, SDU, statement-cache size, NLS, and session statements. | Edition, app context, SDU, and statement-cache sizing are sent through thin driver connect options; driver errors are sanitized against credentials, wallet material, identity fields, app context values, and proxy material. |
| Query rows | Positional and named binds; pagination wraps SQL with `OFFSET ... FETCH`; first page fetches max rows plus one. LOB locators, REF CURSOR cells, and implicit result sets are materialized under serialization caps. | `execute_query_with_binds*`, named/positional bind APIs, fetch APIs, locator reads, and cursor fetches are used without local path dependencies. |
| Execute | Thin adapter reports rows affected, commit/rollback, savepoint rollback preview, and optional bounded DBMS_OUTPUT capture. | Cancellation-aware execute paths roll back dirty dispatcher work; rollback is not skipped by the adapter's own pre-checkpoint, preview DML always attempts rollback-to-savepoint, and commit failure quarantines the session as `commit_in_doubt` instead of attempting a misleading rollback. |
| Call timeout/cancel | Thin adapter has a default 30s call timeout, profile/per-call request-budget `meet` enforcement, and `&Cx` checkpoints at dispatch, DB, pool, and serialization boundaries. | `DbError::Cancelled` maps to `TIMEOUT`; pooled `*_cx` calls discard the checked-out connection on any cancellation/failure because Oracle may already have crossed a round-trip boundary. Direct write paths quarantine uncertain sessions and audit `RolledBack`, `CommitInDoubt`, or `UnknownDiscarded`; leased paths return the matching structured quarantine error and drop the lease. |
| LOBs/JSON/NUMBER | Current serialization caps LOBs and keeps NUMBER lossless by default. | Thin `QueryValue` conversion preserves the JSON schema and truncation markers for CLOB/BLOB/BFILE, nested cursors, JSON, and NUMBER values. |
| DBMS_OUTPUT | `ENABLE` executes through PL/SQL and `GET_LINE` drains through thin output binds when `capture_dbms_output=true`. | Capture is bounded by line and character limits and returned inline as `dbms_output.lines`; no file writes are supported. |
| Pooling | The DB crate uses a small bounded thin session pool instead of `r2d2`/Tokio blocking pools. | Checkout loops observe `&Cx`; a cancelled or failed pooled call is treated as uncertain and the physical connection is not returned to idle reuse. |
| Session identity | Thin connection maps driver name/program/machine/osuser/terminal through `ClientIdentity`, sends edition during authentication, and applies module/action/client_identifier/client_info with PL/SQL. | Invalid editions fail at connect time and are redacted from driver errors. |

Remaining upstream thin-driver gaps tracked in `/home/durakovic/projects/rust-oracledb`:

- `rust-oracledb-o0b`: external wallet auth without username/password.
- `rust-oracledb-5bh`: end-to-end OCI IAM database-token retrieval/refresh for
  `oraclemcp` profiles remains unwired even though `oracledb` 0.5.1 exposes the
  lower-level access-token connect option (`ConnectOptions::with_access_token`).
  Tracked downstream as deferred bead k6q.9.

## Proxy Auth, DRCP, and Enterprise Auth

| Capability | Current behavior | Remaining requirement |
| --- | --- | --- |
| Proxy auth | Thin connect authenticates as `proxy_user` and passes the target schema through the driver's proxy-user connect option. | Requires normal Oracle `CONNECT THROUGH` grants; live tests run when both proxy env vars are set. |
| External/wallet auth | Legacy thick mode could attempt empty username/password wallet auth. Thin mode now reports unsupported external wallet auth explicitly until the published driver grows that path. | Never silently fall back to password auth or thick mode. |
| Kerberos/RADIUS | Thin adapter rejects these modes with targeted unsupported-auth errors. | Add only if the published thin driver exposes a safe implementation. |
| IAM token | `use_iam_token` / `iam_config_profile` parse but fail closed: the `oracledb` 0.5.1 adapter has the `with_access_token` primitive, yet `oraclemcp` wires no production OCI token source, so a configured IAM-token connect returns a structured unsupported-auth diagnostic and any token over a non-TCPS transport is refused. Deferred bead k6q.9. | Wire only with redacted token sourcing, refresh, and live coverage; do not claim support from the lower-level driver primitive alone. |
| DRCP | `drcp.rs` appends connect string parameters such as `server=pooled`, class, and purity. | Parser and live checks cover the connect-string shaping; keep pool identity attributes segregated. |
| Non-homogeneous pools | Pool settings carry the full thin `OracleConnectOptions` for each pool instance. | Do not reuse sessions across incompatible identity/auth attributes. |

## Autonomous Database and Cloud Connectivity

| Area | Current behavior | Current requirement |
| --- | --- | --- |
| Wallet discovery | Requires `cwallet.sso` and `tnsnames.ora`; parses aliases. | Preserve diagnostics; doctor/log output must not print local wallet paths. |
| ADB validation | Accepts `tcps://`, TLS descriptor, or bare wallet alias; rejects plaintext `tcp://`. | Preserve fail-closed TLS/ADB validation before connection. |
| TCPS/SNI/wallet | Thin mode routes TCPS/wallet setup through the published `oracledb` driver where available and otherwise fails explicitly. | Preserve fail-closed diagnostics; unsupported auth/features must not silently fall back to thick mode. |
| IAM refresh | OCI token settings and refresh seams exist, but the thin adapter rejects profile-level `use_iam_token` with structured unsupported-auth diagnostics. | Keep token material redacted until profile-driven token retrieval/refresh is wired and live-tested. |
| Read-only standby | Standby detection caps write behavior and disables `EXPLAIN PLAN` into `PLAN_TABLE`. | Preserve standby cap and diagnostic clarity. |

## Explain-Plan Behavior

| Behavior | Current fact | Migration decision |
| --- | --- | --- |
| User raw `EXPLAIN PLAN` | Guard adversarial corpus treats raw `EXPLAIN PLAN` as guarded, never safe. | Preserve fail-closed guard behavior. |
| `oracle_explain_plan` tool | Dispatch validates the inner SQL as read-only, requires `allow_plan_table_write=true`, and requires the active session gate to allow `READ_WRITE` before `crates/oraclemcp-db/src/intelligence.rs` executes `EXPLAIN PLAN FOR ...`. | Treat as an explicit diagnostic write, not as part of the read-only tool cluster. |
| Standby | `read_only_standby` refuses explain-plan path because `EXPLAIN PLAN` needs `PLAN_TABLE`; standby profiles also cap the session at `READ_ONLY`. | Preserve; use `DBMS_XPLAN.DISPLAY_CURSOR` against an existing cursor for no-write plan inspection. |
| Tracking | The explain-plan contract is implemented and covered by dispatch/guard tests. | Preserve default refusal, standby refusal, READ_WRITE gating, and raw `EXPLAIN PLAN` classifier coverage. |

## Asupersync HTTP/Web Primitives

| Primitive | Current surface | Requirement |
| --- | --- | --- |
| Runtime | The workspace is pinned to nightly and uses `asupersync` runtime/context boundaries for native stdio, native Streamable HTTP, DB calls, cancellation, and tests. | Keep Tokio/compat executors out of the production graph. |
| Context | Dispatch, DB, pool, serialization, and transport operations use explicit `&Cx` checkpoints around work that can block, loop, or cross I/O boundaries. Idle stateful lanes parked on their mailbox are woken by cross-thread close messages; lanes already inside Oracle round trips are interrupted only by DB call timeout/driver break/socket close and then quarantine/discard uncertain sessions. | Keep new controlled APIs cancellation-aware instead of adding hidden blocking adapters. |
| Web router | Native HTTP routing lives in `oraclemcp-core` rather than Axum/Hyper. | Preserve Streamable HTTP compatibility with golden transcripts and e2e protocol tests. |
| HTTP | The current server owns JSON-RPC request/response handling and streaming behavior without `rmcp`, Axum, or Hyper. | Keep the wire behavior stable through golden and conformance coverage. |
| Request regions | `RequestRegion`/`RequestContext` support request-as-region, finalizers, obligations, panic isolation, cancellation, and checkpoints. | Use for HTTP request lifetime and tool-call cleanup. |
| Net caveat | Asupersync net primitives still need load and shutdown evidence as usage grows. | Keep load/shutdown tests close to any transport changes. |
| Tests | `LabRuntime` and deterministic helpers cover quiescence, cancellation cleanup, loser drain, cross-thread idle-lane mailbox wake, and preview-grant redemption races. | Preserve these tests as the evidence path for runtime changes. |

## Baselines To Carry Forward

| Baseline | Current state | Evidence/status |
| --- | --- | --- |
| Protocol behavior | Golden stdio/HTTP transcripts and e2e protocol tests cover the native MCP surface. | Covered by closed transport/golden beads. |
| DB behavior | Unit/live tests cover type fidelity, live Oracle smoke, leases, chaos rollback, privilege degradation, dictionary tools, DBMS_OUTPUT, profile matrix fields, and thin pool behavior. Live tests skip without Oracle env. | Covered by closed thin-driver and live-test beads. |
| Dependency graph | Current manifests and lockfile contain none of Tokio, `rmcp`, Axum, Hyper, `oracle`, `odpic-sys`, or `r2d2`. | Enforced by the forbidden-dependency gate. |
| Release gates | CI runs fmt, clippy, tests, doc, pinned-nightly build, boundary lint, advisory forbidden-dependency reporting, release preflight, cargo deny, thin build, sensitive lint, and fuzz build best-effort. Release workflow publishes crates, GitHub release assets, GHCR, and MCP registry from tags. | Implemented in release/CI workflows. |
| Docker | Docker artifacts build the default thin binary, carry the MCP registry image label, and runtime-smoke without Oracle Instant Client or gcc. | Covered by release artifact gates. |
| Performance | Local oraclemcp binary size, Docker size, startup/RSS, package-size, classifier, synthetic serialization, Docker smoke, and Unix pipe evidence live in `docs/performance-footprint.md`. | Live Oracle latency is intentionally not claimed there. |

## Closed Beads Carrying Current Safeguards

| Safeguard | Closed bead |
| --- | --- |
| Golden stdio/HTTP transcripts stay current as transport behavior evolves. | `oraclemcp-w1-golden-behavior-harness-y8p` |
| Nightly toolchain contract is explicit before Asupersync/oracledb adoption. | `oraclemcp-w2-nightly-toolchain-ci-7ks` |
| Published `oracledb` dependency decision avoids hidden path dependencies. | `oraclemcp-w3-oracledb-release-dependency-y3a` |
| Explain-plan/`PLAN_TABLE` contract is explicit before thin-driver execution. | `oraclemcp-thin-only-oracle-driver-kod.1` |
| HTTP OAuth scope enforcement covers narrow token, broad token, protected profile, missing token, and metadata cases. | `oraclemcp-w10-http-scope-enforcement-b5a` |
| Forbidden production dependency gate keeps removed runtime families out. | `oraclemcp-w12-forbidden-dependency-gate-sbu` |
| Measured install/runtime evidence backs public performance and footprint claims. | `oraclemcp-w13-performance-footprint-evidence-o5y` |
