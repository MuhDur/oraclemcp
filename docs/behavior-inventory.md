# oraclemcp Behavior Inventory

Generated for bead `oraclemcp-w0-behavior-inventory-4t4` on 2026-06-15. This
file is the source-of-truth baseline before the thin-only, Asupersync-native
migration starts. It intentionally records current behavior and known gaps; it
does not record credentials, live Oracle hostnames, customer schema names, or
real query text.

## Evidence Snapshot

| Area | Current fact | Evidence |
| --- | --- | --- |
| Workspace | Cargo workspace with 9 crates plus `oraclemcp` binary, `resolver = "2"`, edition 2024, pinned nightly `nightly-2026-05-11`, and no stable MSRV on the thin-native line. | `Cargo.toml`, `rust-toolchain.toml` |
| Safety posture | Every crate forbids unsafe code; raw SQL safety is centered on `oraclemcp-guard`. | `Cargo.toml`, crate roots, `AGENTS.md` |
| Current release line | All package versions and `server.json` are aligned at 0.2.1. | `Cargo.toml`, crate `Cargo.toml` files, `server.json` |
| Current DB mode | Default build is offline; live Oracle support is feature-gated behind `live-db`/`oracle-driver` and the `oracle` thick driver. | `README.md`, `crates/oraclemcp-db/Cargo.toml` |
| Current runtime/transport | Stdio uses `rmcp`; HTTP uses Axum/Hyper plus `rmcp` Streamable HTTP; DB pool offloads blocking calls through Tokio. | `crates/oraclemcp-core/src/server.rs`, `crates/oraclemcp-core/src/http.rs`, `crates/oraclemcp-db/src/pool.rs` |
| Current bead state | Repo-local `.beads/` contains the migration graph; W0 is the only actionable bead. | `br list --json`, `bv --robot-triage` |
| Local release artifacts | No local `target/release` artifact was present during inventory, so binary-size and startup baselines are not measured yet. | `find target/release ...` |

## CLI Surface

| Command | Current behavior to preserve or revise deliberately | Evidence |
| --- | --- | --- |
| `oraclemcp serve` | Serves stdio by default; `--listen` enables HTTP; `--allow-no-auth` gates unauthenticated HTTP; `--stdio-token` may resolve from `$ORACLEMCP_STDIO_TOKEN`; `--profile` selects active profile. | `crates/oraclemcp/src/main.rs`, `README.md` |
| `oraclemcp info` | Prints package/runtime metadata without requiring a DB connection. | `crates/oraclemcp/src/main.rs` |
| `oraclemcp doctor [--profile]` | Offline checks always run; profile mode adds live connectivity, role, and privilege checks when possible. Must redact secrets. | `crates/oraclemcp/src/main.rs`, `README.md` |
| `oraclemcp profiles` / `list-profiles` | Lists configured profiles and safe metadata. Connect strings and credential refs are omitted from metadata. | `crates/oraclemcp/src/main.rs`, `crates/oraclemcp-config/src/profile.rs` |
| `oraclemcp capabilities` | Emits robot-readable config, tools, tiers, auth posture, and environment guidance. | `crates/oraclemcp/src/main.rs`, `crates/oraclemcp/src/robot_docs.rs` |
| `oraclemcp robot-docs guide` | Emits agent-oriented setup and usage docs. | `crates/oraclemcp/src/robot_docs.rs` |
| `oraclemcp setup` | Generates local profile/tool templates and references `ORACLEMCP_STDIO_TOKEN`; must not print real secrets. | `crates/oraclemcp/src/main.rs` |
| `oraclemcp sign-tool` | Signs operator-defined TOML custom tools with `ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY`. | `crates/oraclemcp/src/main.rs`, `README.md` |
| Global `--robot-json` / `--json` | Machine-readable output mode for CLI commands that support it. | `crates/oraclemcp/src/main.rs` |

## MCP Surface

| Surface | Current contract | Evidence |
| --- | --- | --- |
| Stdio initialize | `rmcp` handles MCP initialize over stdin/stdout; optional init token is validated by constant-time comparison before normal use. | `crates/oraclemcp-core/src/server.rs`, `crates/oraclemcp-auth/src/init_token.rs`, `crates/oraclemcp-core/tests/e2e_mcp.rs` |
| Stdio tools | `tools/list` exposes registry descriptors; `tools/call` routes through `ToolDispatch`. | `crates/oraclemcp-core/src/server.rs`, `crates/oraclemcp-core/src/tools.rs` |
| HTTP endpoint | Streamable HTTP is mounted at `/mcp`; JSON response and stateful/session behavior are configurable. | `crates/oraclemcp-core/src/http.rs` |
| OAuth metadata | `/.well-known/oauth-protected-resource` remains public when OAuth is enabled. | `crates/oraclemcp-core/src/http.rs` |
| HTTP guards | Remote bind requires explicit opt-in; Host and Origin guards protect loopback usage; missing auth returns WWW-Authenticate when OAuth is enabled. | `crates/oraclemcp/src/main.rs`, `crates/oraclemcp-auth/src/http_guard.rs`, `crates/oraclemcp-core/src/http.rs` |
| Current OAuth scope gap | HTTP validates bearer scopes but only stores `ScopeGrant`; dispatch does not yet apply scope-to-level lowering. This is a security bug already represented by W10. | `crates/oraclemcp-core/src/http.rs`, `oraclemcp-w10-http-scope-enforcement-b5a` |
| Golden baseline need | Existing e2e tests cover stdio/HTTP happy paths and auth regressions, but W1 must freeze protocol transcripts before removing `rmcp`/Axum/Hyper. | `crates/oraclemcp-core/tests/e2e_mcp.rs`, `crates/oraclemcp/tests/e2e_stdio.rs`, `oraclemcp-w1-golden-behavior-harness-y8p` |

## Tool Registry

| Group | Current tools and behavior | Evidence |
| --- | --- | --- |
| Profile/session | `oracle_list_profiles`, `oracle_connection_info`, `oracle_switch_profile`, `oracle_set_session_level`. Session level cannot exceed profile ceiling; protected profiles remain read-only. | `README.md`, `crates/oraclemcp/src/registry.rs`, `crates/oraclemcp/src/dispatch/mod.rs` |
| Read/query | `oracle_query`, `oracle_preview_sql`, `oracle_sample_rows`, `oracle_read_clob`. Raw SQL is classified before DB access; reads admit only proven read-only SQL. | `crates/oraclemcp/src/dispatch/mod.rs`, `crates/oraclemcp-guard/tests/*` |
| Guarded execution | `oracle_execute`, `oracle_compile_object`, `oracle_create_or_replace`, `oracle_patch_source`. DML is rollback-by-default; DDL/Admin require commit and confirmation. | `README.md`, `crates/oraclemcp/src/dispatch/mod.rs`, `crates/oraclemcp/src/dispatch/tests.rs` |
| Dictionary/source | `oracle_list_schemas`, `oracle_schema_inspect`, `oracle_describe`, `oracle_describe_index`, `oracle_describe_trigger`, `oracle_describe_view`, `oracle_get_ddl`, `oracle_get_source`, `oracle_compile_errors`, `oracle_search_source`, `oracle_plscope_inspect`. Uses `ALL_*`/dictionary views with privilege degradation. | `README.md`, `crates/oraclemcp-db/src/intelligence.rs`, `crates/oraclemcp-db/src/privileges.rs` |
| Diagnostics | `oracle_explain_plan`, `oracle_capabilities`. Explain-plan behavior is not purely read-only on primary because it writes `PLAN_TABLE`; see W3.5. | `crates/oraclemcp-db/src/intelligence.rs`, `crates/oraclemcp-db/src/standby.rs`, `oraclemcp-thin-only-oracle-driver-kod.1` |
| Compatibility aliases | Legacy names such as `query`, `execute_approved`, `describe_table`, `get_ddl`, `get_object_source`, and others are still registered for client compatibility. | `README.md`, `crates/oraclemcp/src/registry.rs` |
| Operator-defined tools | TOML custom tools are allowed; protected profiles or `require_signed_tools=true` require HMAC signatures. Custom tool execution is read-only only. There is no native/dynamic plugin execution surface. | `crates/oraclemcp/src/main.rs`, `crates/oraclemcp/src/dispatch/mod.rs`, `README.md` |

## Credentials, Secrets, Logs, and Fixtures

| Surface | Current contract | Evidence |
| --- | --- | --- |
| Profile discovery | `$ORACLEMCP_CONFIG`, `~/.config/oraclemcp/profiles.toml`, and `~/.config/oraclemcp/config.toml` are the config inputs. | `crates/oraclemcp-config/src/lib.rs` |
| Credential refs | `env:VAR` resolves from environment; `literal:value` exists but is rejected for protected profiles; `vault:` is feature-gated. | `crates/oraclemcp-auth/src/secrets.rs`, `crates/oraclemcp-config/src/profile.rs` |
| Secret storage | `Secret` zeroizes and redacts debug output. | `crates/oraclemcp-auth/src/secrets.rs` |
| Stdio auth | `ORACLEMCP_STDIO_TOKEN` is optional by policy but constant-time compared when required. | `crates/oraclemcp-auth/src/init_token.rs` |
| Custom tool signing | `ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY` signs/verifies custom tool definitions; missing keys fail when signatures are required. | `crates/oraclemcp/src/main.rs`, `README.md` |
| Release secrets | crates.io publishing uses `CARGO_REGISTRY_TOKEN` in the `crates-io` environment; GHCR uses `GITHUB_TOKEN`; MCP registry publishing uses GitHub OIDC. No separate GHCR or MCP registry secret is required by current workflows. | `.github/workflows/release.yml`, `.github/workflows/docker.yml`, `.github/workflows/publish-mcp.yml` |
| Secret lint | Sensitive-data lint scans for embedded URL credentials, cloud keys, private keys, and optional denylist entries. | `scripts/sensitive_data_lint.sh`, `.github/workflows/ci.yml` |
| Logs/errors/fixtures | Migration tests and docs must use synthetic SQL/profile names and must not include real Oracle hosts, usernames, wallet paths, bind values, tokens, or customer schema names. | `AGENTS.md`, W1/W11/W13/W14 beads |

## Safety and Data Invariants

| Invariant | Current behavior | Evidence |
| --- | --- | --- |
| Fail-closed SQL guard | Raw SQL enters `oraclemcp-guard`; read tools allow only `READ_ONLY` statements, everything else is refused before Oracle. | `crates/oraclemcp/src/dispatch/mod.rs`, `crates/oraclemcp-guard/tests/adversarial_corpus.rs` |
| Guard before I/O target | Downstream migration must preserve guard/classification before network I/O, DNS, connection acquisition, lease acquisition, or mutable execution state. | `AGENTS.md`, `oraclemcp-w11-deterministic-asupersync-tests-blm` |
| Session levels | `OperatingLevel` controls ReadOnly, ReadWrite, DDL, and Admin. Step-up cannot exceed profile `max_level`; protected profiles pin read-only. | `crates/oraclemcp-config/src/profile.rs`, `crates/oraclemcp/src/dispatch/mod.rs` |
| Preview/confirm tokens | Write/DDL flows require preview tokens; tokens are profile/statement/level scoped and single workflow acceptance must be tested under races. | `crates/oraclemcp/src/dispatch/mod.rs`, `crates/oraclemcp/src/dispatch/tests.rs`, `oraclemcp-w11-deterministic-asupersync-tests-blm` |
| DML rollback default | `oracle_execute` rollbacks by default for DML unless explicitly confirmed/committed. | `crates/oraclemcp/src/dispatch/mod.rs`, `crates/oraclemcp/src/dispatch/tests.rs` |
| Leases | Leases pin one physical session, keep transaction/savepoint/temp/DBMS_OUTPUT state, and force rollback on expiry/release. Missing lease returns structured `LeaseRequired`. | `crates/oraclemcp-db/src/lease.rs`, `crates/oraclemcp-db/tests/chaos.rs` |
| DBMS_OUTPUT | Capture is opt-in on execution paths, line/character/buffer limits are clamped, and output is returned in tool JSON rather than files. | `crates/oraclemcp/src/dispatch/mod.rs`, `crates/oraclemcp/src/dispatch/tests.rs` |
| Serialization | NUMBER is string by default; float output is opt-in; date/timestamp/NLS output is canonicalized; CLOB/BLOB output is capped and marks truncation. | `crates/oraclemcp-db/src/serialize.rs`, `crates/oraclemcp-db/tests/type_fidelity.rs` |
| Privilege degradation | Dictionary privilege checks fall back `DBA_* -> ALL_* -> USER_*`; AWR/ASH requires Diagnostics Pack, otherwise Statspack or structured unavailable error. | `crates/oraclemcp-db/src/privileges.rs`, `crates/oraclemcp-db/src/awr.rs`, `crates/oraclemcp-db/tests/privilege_degradation.rs` |
| Audit | Audit sink is out-of-band, hash-chained, fsync-before-execute, and poisons closed on durable flush failure. | `crates/oraclemcp-audit/src/sink.rs`, `crates/oraclemcp-audit/src/record.rs` |

## Dependency Holdouts

| Crate/family | Current reason present | Migration target |
| --- | --- | --- |
| `tokio` | Binary runtime, rmcp, Axum/Hyper, HTTP tests, DB pool `spawn_blocking`, live-db feature. | Remove from production graph; use Asupersync runtime, scopes, time, sync, net, and deterministic test helpers. |
| `rmcp` | Current MCP SDK for stdio and Streamable HTTP. | Replace with native JSON-RPC/MCP stdio first, then native HTTP. |
| `axum` | HTTP router/middleware around Streamable HTTP and metadata route. | Replace with Asupersync web/http primitives or a minimal audited non-Tokio HTTP layer. |
| `hyper` / `hyper-util` | Transitive HTTP stack through Axum/rmcp HTTP. | Remove from production graph. |
| `oracle` / ODPI-C | Thick Oracle driver behind `live-db`; requires native Oracle client at runtime. | Replace with pure-Rust `oracledb` thin driver. |
| `r2d2` | Thick-driver connection pool. | Replace with an Asupersync-aware thin pool/session manager. |
| `reqwest`, `async-std` | Not present in current dependency graph checked during W0. | Keep absent. |
| `smol` | Not known as a current dependency; W12 should make this explicit in forbidden-dependency checks. | Keep absent from production graph. |
| `asupersync-tokio-compat` | Not present now. | Do not introduce in final production graph; any temporary compat must carry a removal bead. |

## Thin Driver API Coverage

| oraclemcp need | Current thick behavior | `oracledb` / thin migration note |
| --- | --- | --- |
| Connect | `oracle::Connection::connect` via `RustOracleConnection`; applies wallet/connect string, identity, NLS, session statements. | `oracledb::Connection::connect(&Cx, ConnectOptions)` and `BlockingConnection` exist in `/home/durakovic/projects/rust-oracledb`; final adapter should use `&Cx`, not the blocking shim except as a short-lived bridge. |
| Query rows | Positional and named binds; pagination wraps SQL with `OFFSET ... FETCH`; first page fetches max rows plus one. | `execute_query_with_binds*`, named/positional bind APIs, and fetch APIs exist. W4 must map `QueryValue` to current JSON serialization exactly. |
| Execute | Thick adapter reports rows affected, commit/rollback, and savepoint rollback preview. | Thin adapter must preserve row counts, savepoints, commit/rollback, and uncertain-session cleanup. |
| Call timeout/cancel | Thick adapter has call timeout setters and DB pool offloading. | Thin driver exposes timeout/cancel APIs; W7b must wire cancellation to connection cleanup and discard dirty sessions when certainty is lost. |
| LOBs/JSON/NUMBER | Current serialization caps LOBs and keeps NUMBER lossless by default. | Thin values include lossless `QueryValue`; W4 must preserve current JSON schema and truncation markers. |
| DBMS_OUTPUT | Current code uses PL/SQL calls against the connection. | Thin adapter can issue equivalent PL/SQL; W4/W11 must test enable/read limits and cleanup. |
| Pooling | Current pool is `r2d2` plus Tokio blocking bridge. | Replace with thin/Asupersync-native pool; no ambient Tokio handle. |
| Session identity | Current thick connection sets edition, driver_name, module, action, client_identifier, client_info where configured. | Thin driver exposes `ClientIdentity`; W4 must preserve profile fields or fail explicitly. |

## Proxy Auth, DRCP, and Enterprise Auth

| Capability | Current behavior | Thin migration requirement |
| --- | --- | --- |
| Proxy auth | Formats proxy users such as `proxy_user[target_schema]` and treats proxy auth as an Oracle Net profile mode. | Preserve if thin driver supports equivalent username/connect metadata; otherwise fail with a precise unsupported-auth error. |
| External/wallet auth | Empty username/password with wallet/external auth can be attempted by thick mode. | Thin-only W4/W5 must document support or explicit unsupported behavior; never silently fall back to password auth. |
| Kerberos/RADIUS | Current adapter labels these thick-mode requirements. | Thin-only migration should remove or explicitly reject with actionable diagnostics. |
| IAM token | Current thick path reports unsupported for `use_iam_token`. | Thin path should either implement from `oci.rs` token source or report a targeted unsupported-cloud-auth error. |
| DRCP | Current `drcp.rs` appends connect string parameters such as `server=pooled`, class, and purity. | Preserve connect-string semantics if thin parser supports them; add live or parser tests. |
| Non-homogeneous pools | Current planning scope mentions proxy/external auth risks. | Thin pool must not reuse sessions across incompatible identity/auth attributes. |

## Autonomous Database and Cloud Connectivity

| Area | Current behavior | Thin migration requirement |
| --- | --- | --- |
| Wallet discovery | Requires `cwallet.sso` and `tnsnames.ora`; parses aliases. | Preserve diagnostics; do not log wallet paths if policy treats paths as sensitive. |
| ADB validation | Accepts `tcps://`, TLS descriptor, or bare wallet alias; rejects plaintext `tcp://`. | Preserve fail-closed TLS/ADB validation before connection. |
| TCPS/SNI/wallet | Thick mode relies on Oracle client behavior. | W3/W4 must verify the published `oracledb` crate supports required TLS/wallet/SNI behavior or split unsupported cases into explicit beads. |
| IAM refresh | `oci.rs` has token structures and refresh seam. | W4/W5 must either wire to thin auth or return structured unsupported diagnostics. |
| Read-only standby | Standby detection caps write behavior and disables `EXPLAIN PLAN` into `PLAN_TABLE`. | Preserve standby cap and diagnostic clarity. |

## Explain-Plan Behavior

| Behavior | Current fact | Migration decision |
| --- | --- | --- |
| User raw `EXPLAIN PLAN` | Guard adversarial corpus treats raw `EXPLAIN PLAN` as guarded, never safe. | Preserve fail-closed guard behavior. |
| `oracle_explain_plan` tool | Dispatch first validates the inner SQL as read-only, then `crates/oraclemcp-db/src/intelligence.rs` executes `EXPLAIN PLAN FOR ...` and queries `DBMS_XPLAN.DISPLAY`. | This writes `PLAN_TABLE` on primary databases and conflicts with a simplistic read-only story. |
| Standby | `read_only_standby` refuses explain-plan path because `EXPLAIN PLAN` needs `PLAN_TABLE`. | Preserve or replace with a non-writing route where possible. |
| Tracking | New bead `oraclemcp-thin-only-oracle-driver-kod.1` blocks W4. | Resolve before thin adapter starts. |

## Asupersync HTTP/Web Primitives

| Primitive | Available target surface | W9 implication |
| --- | --- | --- |
| Runtime | `asupersync 0.3.4` exposes `LabRuntime`, runtime builder, time, sync, channel, net, service, http, web, and grpc modules. It currently requires nightly. | W2 must pin nightly before adopting it. |
| Context | Skill guidance requires `&Cx` first in controlled APIs, checkpoints in long loops, and region-owned spawned work. | W6/W7 must change API shape rather than swapping executors. |
| Web router | `asupersync::web::Router`, method routers, extractors, state, JSON, and request-region APIs exist. | W9 can target native web primitives, but must prove Streamable HTTP compatibility. |
| HTTP | `asupersync::http` exposes HTTP/1.1 and HTTP/2 protocol/body/pool modules. | W9 must verify streaming JSON-RPC and request/response behavior with golden transcripts. |
| Request regions | `RequestRegion`/`RequestContext` support request-as-region, finalizers, obligations, panic isolation, cancellation, and checkpoints. | Use for HTTP request lifetime and tool-call cleanup. |
| Net caveat | Current source docs say net phase 0 exposes synchronous `std::net` wrappers behind async-looking APIs. | Treat as a production feasibility risk for W9; prove load/shutdown behavior before release. |
| Tests | `LabRuntime` and deterministic helpers are the migration's evidence path. | W11 must prove quiescence, cancellation, loser drain, and preview-token races. |

## Baselines To Carry Forward

| Baseline | Current state | Next bead |
| --- | --- | --- |
| Protocol behavior | Existing e2e tests cover current rmcp stdio/HTTP paths but fixtures are not yet golden transcripts. | W1 |
| DB behavior | Unit/live tests cover type fidelity, live Oracle smoke, leases, chaos rollback, privilege degradation, dictionary tools, and pool offload. Live tests skip without Oracle env. | W4/W11 |
| Dependency graph | Current default graph contains Tokio/rmcp/Axum/Hyper; live-db graph adds `oracle` and `r2d2`. | W2 advisory, W12 hard gate |
| Release gates | CI runs fmt, clippy, tests, doc, pinned-nightly build, boundary lint, advisory forbidden-dependency reporting, release preflight, cargo deny, live-db build, sensitive lint, and fuzz build best-effort. Release workflow publishes crates, GitHub release assets, GHCR, and MCP registry from tags. | W2, W14 |
| Docker | Current image builds live-db binary and bundles Oracle Instant Client. | W14 must remove Instant Client for thin-native release. |
| Performance | No local oraclemcp binary/startup/query benchmarks were produced in W0. Existing rust-oracledb docs contain thin-driver performance evidence, but those numbers are not oraclemcp release claims. | W13 |

## Current Gaps Already Reflected In Beads

| Gap | Bead |
| --- | --- |
| Need golden stdio/HTTP transcripts before transport rewrite. | `oraclemcp-w1-golden-behavior-harness-y8p` |
| Need honest nightly toolchain contract before Asupersync/oracledb adoption. | `oraclemcp-w2-nightly-toolchain-ci-7ks` |
| Need published-or-vendored `oracledb` dependency decision. | `oraclemcp-w3-oracledb-release-dependency-y3a` |
| Need explicit explain-plan/`PLAN_TABLE` contract before W4. | `oraclemcp-thin-only-oracle-driver-kod.1` |
| Need HTTP OAuth scope enforcement at dispatch, not just capture. | `oraclemcp-w10-http-scope-enforcement-b5a` |
| Need forbidden production dependency gate. | `oraclemcp-w12-forbidden-dependency-gate-sbu` |
| Need measured install/runtime evidence before public claims. | `oraclemcp-w13-performance-footprint-evidence-o5y` |
