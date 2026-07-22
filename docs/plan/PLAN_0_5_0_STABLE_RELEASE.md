# PLAN — oraclemcp 0.5.0 "Stable & Installable"

> Status: **v3 — FROZEN / STEADY-STATE** (3 review rounds, 9 independent reviewers; ready for beads conversion). See [§12](#12-review-log).
> Owner: operator. Planning skill: `planning-workflow`. Companion skills folded
> in: `installer-workmanship`, `release-preparations`, `changelog-md-workmanship`,
> `rust-crates-publishing`, `beads-workflow`.
> Self-contained: a fresh agent who has never seen the repo can read this top to
> bottom and implement without asking for clarification. All `file:line`
> citations were verified during planning Round 1; re-verify before relying on one.

---

## 0. TL;DR

oraclemcp 0.4.0 is shipped and at rest. The next release, **0.5.0**, is the
"stable & installable" release. It does four things, in priority order:

1. **Bake in the rust-oracledb `=0.5.1` driver** — not a pin bump; 0.5.1 adds new
   public surface (a `TimestampTz` value type, a typed auth-capability surface, a
   wallet-format diagnostic, IAM/TCPS fixes, a now-honored connect timeout) that
   the adapter must *wire*, not just compile against.
2. **Close the three open downstream issues** (#2 routine OUT/IN OUT/return, #3
   non-lossy serialization, #4 query-hang) — adapter work, but **larger than v1
   assumed** (see the Round-1 corrections in §1.2/§3).
3. **Ship a world-class one-line installer** for every supported system, so
   adoption is copy-paste: `curl … | bash` (Unix) and `irm … | iex` (Windows),
   plus cargo-binstall / Docker channels (Homebrew/Scoop stretch). Headline
   user-facing deliverable.
4. **Harden for a stable release** — release-matrix alignment, doctor honesty,
   docs currency (incl. SECURITY.md + an upgrade note), conformance, perf
   re-measure, live-XE qualification, CHANGELOG, then the gated cut + a rollback
   runbook.

**Version: `0.4.0 → 0.5.0` (minor).** Additive features, **no breaking MCP tool
surface** (the api-lock baseline *will* move — that is a reviewed additive delta,
not a break; and serialized *value shapes* change, which needs an explicit upgrade
note — see [G2]/[N7]). Not 1.0 (stability promise deferred to post-production
validation, mirroring the driver). See [D1](#d1-version--stability-posture).

**Biggest external dependency:** rust-oracledb **#14** (TCP keepalive /
`EXPIRE_TIME` application + a read-inactivity / fetch-loop timeout primitive) is
open upstream. We do **not** block 0.5.0 on it — #4 is mitigated adapter-side — but
note [F2 below]: part of the real #4 fix (bounding the continuation/cursor fetch
path) is best solved upstream and may need an adapter-side `time::timeout` wrapper
in the interim.

---

## 1. Current state (verified facts)

### 1.1 oraclemcp (this repo)
- **Shipped 0.4.0** (crates.io, GitHub Releases, GHCR, MCP registry; cosign
  keyless + CycloneDX SBOM). `main` clean, tag `v0.4.0`.
- **9-crate workspace**, ~57k src LOC, 1,001 tests, `#![forbid(unsafe_code)]`,
  pinned nightly `nightly-2026-05-11` (build-time only; shipped binary has no
  nightly runtime dep) because **asupersync 0.3.4** uses `try_trait_v2`; the
  `oracledb` driver is stable-clean.
- **Pure-Rust thin** driver, single seam `crates/oraclemcp-db/src/connection.rs`
  (seam-lint + in-tree `driver_seam` test enforce one file). No ODPI-C/Instant
  Client.
- **CLI commands** (`crates/oraclemcp/src/main.rs` `enum Command`): `serve`,
  `info`, `doctor`, `profiles`, `capabilities`, `robot-docs`, `setup`,
  `sign-tool`, `audit`. **No `completions` subcommand; no `clap_complete` dep**
  (verified) → see [A0].
- **Release matrix** (`.github/workflows/release.yml`): 6 targets —
  `{x86_64,aarch64}-unknown-linux-gnu`, `x86_64-unknown-linux-musl`,
  `{x86_64,aarch64}-apple-darwin`, `x86_64-pc-windows-msvc`. Assets are
  `oraclemcp-{target}.tar.gz`/`.zip` (**no version in the filename**), binary
  nested at `oraclemcp-{target}/oraclemcp`, with `.sha256`. Cosign is **detached
  `sign-blob` → `.sig` + `.crt`** (not a bundle). SBOM is the **oraclemcp
  binary-crate** CycloneDX bom published as the single **versioned** file
  `oraclemcp-{version}.cdx.json` (one file, not per-target; the installer does not
  verify it). **crates.io publishes inside the tag
  workflow** (`publish-crates` job `needs: build`; the GitHub `release` job
  `needs: [build, publish-crates]` and is gated on its success for non-prerelease)
  → so crates.io precedes the GitHub release. Docker job has **no `platforms:`** →
  **amd64-only**. `publish-mcp-registry` `needs: docker`.
- **Beads: 0 open**, 181 closed, 14 deferred (`oraclemcp-040-epic-deferred-k6q`).
  All 0.5.0 work below is **untracked** and must be beaded.
- **Driver pin:** `oracledb = { version = "=0.5.0", … }`.
- **`server.json`:** `version: 0.4.0`, `packages[].identifier:
  ghcr.io/muhdur/oraclemcp:0.4.0` — **both** must bump.

### 1.2 Open GitHub issues (downstream from sibling `plsql-mcp`, all touch shared `oraclemcp-db`)
- **#2** — routine OUT/IN OUT/function-return. Driver already capable
  (`BindValue::{Output,ReturnOutput}`, `execute_raw`, `QueryResult.out_values`,
  `ExecuteOutcome::out_binds()`); the adapter exposes input-only binds and already
  uses the OUT-bind path internally for `DBMS_OUTPUT`. Upstream **#13** (a
  `callproc` convenience) is optional. → **adapter work** (WP-R).
- **#3** — non-lossy / typed serialization. The loss is in
  `connection.rs::value_to_cell` *before* the JSON layer: `ARRAY →
  "<unsupported ARRAY len=N>"` (`:1017`), `JSON/VECTOR → {:?}` (`:1011-1016`),
  object → base64 bytes that drop `schema`/`type_name` (`:979`), plus a
  catch-all `"<unsupported Oracle value kind>"` (`:1026`) and an
  implicit-resultset placeholder (`:1062`). **Correction (Round 1, F3):**
  `OracleCell` (`types.rs:81-98`) has only `value: Option<String>` / `bytes` /
  `nested_result` — **no structured carrier** — so this is *not* "pure flattening";
  it needs a cell-model change ([C0]/[D9]). → **adapter work + public-surface +
  goldens**.
- **#4** — thin live query can hang after Oracle TNS timeout / CLOSE-WAIT.
  **Correction (Round 1, F1/F2/S1 — verified):**
  - A **30s default call timeout already exists**: `connect.rs:281`
    `resolve_call_timeout(None) → Some(resilience::DEFAULT_CALL_TIMEOUT)` (+ a
    `RequestBudget` 30s layer it is *coupled* to, `request_budget.rs:41`). So the
    v1 premise ("unset → no timeout → parks forever") is **false** for the
    oraclemcp binary.
  - But the default is set in **`oraclemcp-core::connect.rs`**, while **plsql-mcp
    consumes `oraclemcp-db` directly** and builds its own `OracleConnectOptions`
    whose `call_timeout` defaults to `None` (`connection.rs:242,352`) — so the
    *shared adapter* gives plsql-mcp no default. **That is the real #4 path.**
  - Even with a timeout armed, it wraps only the **initial `execute_raw`**. The
    **continuation/cursor fetch path** (`collect_all_rows` →
    `fetch_rows_with_columns` / `define_and_fetch_rows_with_columns` /
    `fetch_cursor`) takes **no `timeout_ms`** → a multi-batch result or REF CURSOR
    on a half-open socket still reads unbounded (F2).
  - **`commit`/`rollback`** (`connection.rs:2033-2051`) also take no `timeout_ms`,
    so the post-timeout cleanup ROLLBACK can itself re-hang (S1) — breaking
    rollback-by-default on a dead socket.
  - The explicit `call_timeout_seconds = 0` opt-out → `None` (intended).
  → **adapter work (push the default into the shared layer; bound the fetch loop
  and commit/rollback) + upstream #14** for a true socket-level backstop. WP-B.

### 1.3 rust-oracledb 0.5.1 (local checkout, version `0.5.1`, dated 2026-06-29)
CHANGELOG `[0.5.1]` — "downstream capability honesty for oraclemcp doctor checks."
No breaking changes. Relevant deltas (verified):
- **Added** typed auth surface: `AuthMode`/`AuthModeKind`/`AuthModeSupport`/
  `AuthCapabilities` (+ `AuthCapabilities::THIN` const,
  `ConnectOptions::auth_capabilities()` `lib.rs:1882`), `Error::UnsupportedAuthMode`,
  and `external_auth`/`kerberos_auth`/`radius_auth` (+ `with_*`) constructors.
  Password/proxy/IAM-token remain supported; the rest fail typed, pre-network.
- **Added** `WalletError::UnsupportedFormat` (standalone `ewallet.p12`).
- **Added** offset-preserving TSTZ: **new `#[non_exhaustive]`-enum variants**
  `QueryValue::TimestampTz` and `BindValue::TimestampTz` (both `QueryValue` *and*
  `BindValue` are `#[non_exhaustive]`, `types.rs`) + chrono conversions. Until the
  adapter adds a `value_to_cell` arm, TSTZ hits the fail-safe `"<unsupported
  Oracle value kind>"` (regression).
- **Fixed** IAM/OAuth token connect preserves TCPS + injects
  `(TOKEN_AUTH=OCI_TOKEN)`.
- **Fixed** `transport_connect_timeout`/`connect_timeout` now bound the **full
  connect handshake** (derived from the parsed descriptor, `lib.rs:2148-2151,2401`)
  — the *connect* half of #14 is resolved upstream.

**Still missing in 0.5.1 (so #14 stays open):** `EXPIRE_TIME` **is parsed into the
descriptor but never applied** as a socket keepalive (only `set_nodelay`;
no `SO_KEEPALIVE`, `lib.rs:2175`), and there is **no read-inactivity/fetch-loop
timeout** on the steady-state path (the driver's high-level `Rows` bounds these via
`deadline.run()` at `rows.rs:403-421`, but the adapter uses the low-level
primitives directly).

**Sequencing:** confirm 0.5.1 is on crates.io before cut-over. During dev a temp
`git`/`tag` pin is acceptable; a published crate **must not** ship a git pin —
gated in [H2].

---

## 2. Goals & non-goals

### 2.1 Goals
- G1. One copy-paste line installs a working `oraclemcp` on any supported system —
  no Rust toolchain, no nightly, no Instant Client.
- G2. Issues #2/#3/#4 closed with tests; safety invariant intact.
- G3. Driver `=0.5.1` baked in cleanly, seam-confined; delivers the doctor-honesty
  + TSTZ fidelity the 0.5.1 cut was for.
- G4. `oraclemcp doctor` truthfully reports auth-mode support from the driver's
  typed capabilities (redaction-safe).
- G5. Stable-release bar: full gate battery green, conformance 100%, perf
  re-measured, live-XE qualified, docs current (incl. SECURITY.md + upgrade note),
  CHANGELOG written, rollback runbook ready.
- G6. Everything tracked in beads with a clean DAG.

### 2.2 Non-goals
- N1. **Not 1.0.**
- N2. No new enterprise-auth *implementations* (Kerberos/RADIUS/external wallet
  remain typed-unsupported; full support stays deferred k6q.7/.8 + upstream
  #2/#3/#4/#6).
- N3. No object/UDT typed-attribute decoding beyond `(schema,type_name,bytes)` +
  typed-unsupported marker (driver hands only packed bytes; a walker is a future
  driver FR).
- N4. No deferred-epic features (advisors, RAG, RBAC, rate-limiting, PII, async
  long-query).
- N5. **Do not weaken the safety invariant** (fail-closed classifier, per-profile
  immutable ceiling, rollback-by-default, protected pinning, audit chain, scopes
  only lower). Every new path is gated identically.
- **N6 (new, from review M1): no agent-facing `oracle_call_routine` MCP tool in
  0.5.0.** `call_routine` is adapter-internal for plsql-mcp; exposing arbitrary
  PL/SQL-with-output to an agent needs its own classifier story and is out of
  scope. This is a hard non-goal, enforced in the DoD.
- **N7 (new, from review): no *silent* serialized-shape change.** The serialized
  value shapes for ARRAY/JSON/VECTOR/TSTZ/objects change; this MUST ship with an
  explicit upgrade note ([G2]) — it is not a free internal change.

### 2.3 Success criteria
- Fresh Ubuntu/macOS/Windows box: one-liner installs; `oraclemcp --version` prints
  `0.5.0`; `oraclemcp doctor` green offline.
- `cargo test --workspace` + live-XE green on 0.5.1.
- #2/#3/#4 closed with linked commits + tests.
- Installer passes `--quiet`/`--no-gum`/`--offline`/re-run; SHA256 verify always,
  cosign verify exercised in CI; installer triples match release assets (OP-15).
- README leads with the one-liner; nightly `cargo install` demoted.

---

## 3. Key decisions (with rationale)

### D1. Version & stability posture
Ship `0.5.0` "stable & installable," not `1.0`. **Why:** additive, no breaking
public surface → minor; 1.0 stability promise waits for production mileage (driver
shipped 0.5.0 for the same reason); aligning our minor with the driver's `0.5.x`
reduces user cognitive load.

### D2. Installer is hand-written `install.sh` + `install.ps1`, not cargo-dist
Follow `installer-workmanship`: a first-class `curl|bash` `install.sh` + a
PowerShell `install.ps1` that download **prebuilt** artifacts, emulating the
DCG/RCH gold-standard installers. **Why:** the skill mandates this shape +
non-negotiables; prebuilt download avoids the nightly toolchain for the common
path; we already publish signed, checksummed per-target tarballs. cargo-binstall /
Homebrew / Docker are complementary channels (WP-F). The canonical reference
installers (`/dp/destructive_command_guard/install.sh`,
`/dp/remote_compilation_helper/install.sh`) are **not present on this host** — the
non-negotiables are reproduced inline in [WP-E] for self-containment; fetch the
references if they become reachable.

### D3. "Agent auto-configuration" = MCP-server registration, not hooks
oraclemcp is an **MCP server**, so the installer registers it as an MCP server in
detected clients (exact files verified in [E4]), behind an opt-in prompt, defaulting
to `oraclemcp serve --allow-no-auth` over **stdio only**. **Why:** a PreToolUse
hook (the skill's default) is wrong for an MCP server; registration is the correct
zero-friction setup. **Never** write an HTTP/`--listen` form with `--allow-no-auth`
(that removes the auth gate) — stdio-only, enforced by test ([E4]/[M6]). Never
inject secrets ([D6]).

### D4. Linux installer path standardizes on musl (both arches)
The one-liner installs musl-static Linux binaries for `x86_64` and `aarch64`; add
`aarch64-unknown-linux-musl` to the matrix **with a working cross toolchain**
(rustls→ring needs a target C compiler; use `cargo-zigbuild` or `cross`, or an
aarch64 musl-cross + `CC_aarch64_unknown_linux_musl` —
verified gap in `release.yml:104-114`). `gnu` artifacts stay published.
`install.sh` hard-maps linux→musl; `cargo binstall` host-detects and may fetch the
gnu asset on a glibc box (both published — document the split). **Why:** skill
mandates musl portability; OP-15/OP-16 avoidance.

### D5. #4: the default already exists — keep 30s, fix the real gaps
**Do NOT "arm a default" (done) and do NOT raise 30s→300s** (a 10× liveness
regression, and `DEFAULT_CALL_TIMEOUT` is coupled to the request budget). The real
work (WP-B): push the default into the **shared `oraclemcp-db` layer** so plsql-mcp
inherits it; bound the **continuation/cursor fetch loop** and **commit/rollback**;
warn in doctor when a profile sets `call_timeout_seconds = 0`. **Why:** verified
the binary is already protected; the gap is the shared-adapter default + the
unbounded fetch/cleanup reads.

### D6. Secrets never touched by the installer
Scaffold config templates + MCP registrations only; never read/write/prompt for DB
passwords/tokens; `credential_ref` stays `env:VAR`. **Why:** matches the security
posture; an installer handling secrets is an attack surface.

### D7. Non-lossy serialization via a typed contract (no value-looking placeholders)
Supported complex types serialize losslessly; **every** unsupported rendering
(including the catch-all and implicit-resultset arms, not just the three named
kinds — M7) becomes a typed `{ unsupported: <oracle_type>, reason, schema?,
type_name? }`, never a bare string. Requires the [C0] cell-model carrier.
**Why:** satisfies #3 for both display and plsql-mcp catalog snapshots; "looks like
a value but isn't" is the precise failure to avoid.

### D8. Reviews via independent strong-reasoner subagents to steady-state
GPT Pro isn't callable here; run adversarial review **panels** (independent Opus
subagents, blind to each other), integrate per round, stop when a round yields only
marginal diffs. Record rounds in [§12].

### D9 (new). `OracleCell` gains a structured value carrier
Add a structured carrier (e.g. `structured: Option<serde_json::Value>`) to
`OracleCell`; define serializer precedence vs `value`/`bytes`/`nested_result`; this
is the load-bearing change behind WP-C and ripples into api-lock + goldens +
the plsql-mcp contract. **Why:** the current cell type cannot represent typed
ARRAY/JSON/VECTOR/TSTZ or the typed-unsupported object (F3).

### D10 (new). `call_routine` layering & enforcement
Output binds live on a **new adapter-internal `OracleRoutineArg`** type — **not**
on the agent-deserializable `OracleBind` (which stays input-only). `call_routine`
sits in the shared adapter *below* the classifier, so **every caller (oraclemcp and
plsql-mcp) MUST route the PL/SQL through the classifier + operating-level +
`max_level` + confirmation gate before calling it**; documented as a hard
requirement with a `// SECURITY:` doc-comment and a test/lint that no unclassified
agent path reaches it. **Why:** the invariant is enforced one layer up; adding an
arbitrary-PL/SQL-with-output capability to a deserializable type would silently
hand agents that power (S2/S3).

---

## 4. Work packages & tasks

Task IDs become beads under epic `oraclemcp-050-epic` ([§11]). Routine tasks use
the **`R`** prefix (not `D`) to avoid colliding with decisions D1-D10. Priorities
`0` (critical) … `4` (backlog). **Seam constraint (F5):** A2, B-series, C0/C1,
R1/R2 all edit the single seam file `connection.rs` — they are logically
independent but **must be sequenced / single-owner**, not run as concurrent agents.

### WP-A — Driver 0.5.1 bake-in + CLI completions
- **A0. Implement `oraclemcp completions {bash,zsh,fish,powershell}`.** (p1, deps:
  none)
  - Acceptance: add `clap_complete`; new `Command::Completions`; emits a valid
    script per shell to stdout; unit test that each shell renders non-empty.
  - Why: the installer's required completion step (E2/E3) invokes a subcommand that
    does **not** exist today (verified).
- **A1. Pin bump `=0.5.0 → =0.5.1` + lock refresh.** (p1, deps: none; see §1.3
  sequencing)
  - Acceptance: pin `=0.5.1`; `Cargo.lock` refreshed; `cargo build --workspace`
    green on the pin; seam lint + `driver_seam` test green.
- **A2. Wire `QueryValue::TimestampTz` / `BindValue::TimestampTz`.** (p1, deps: A1)
  - Acceptance: explicit `value_to_cell` arm → offset-preserving ISO-8601 (no
    placeholder); `to_bind` can emit `BindValue::TimestampTz`; live-XE round-trip
    asserts the offset survives. Note: `BindValue` is also `#[non_exhaustive]` —
    construct existing variants, never `match` it exhaustively.
- **A3. Wire typed auth capabilities into doctor + error envelopes (redaction-safe).**
  (p1, deps: A1)
  - Acceptance: doctor reports auth-mode support via `auth_capabilities()`;
    external/Kerberos/RADIUS surface `Error::UnsupportedAuthMode` → structured
    `ErrorEnvelope` (stable class + next-action) **before** network I/O; the prior
    hand-rolled parse-but-fail path is removed; **all output passes through
    `sanitize_driver_error` (`connection.rs:1627-1680`)** — never echo
    principal/DN/connect-string (M3). **Telemetry funnel (R2-safety):** add a test
    that the same connect/auth error rendered into an OTLP span/log attribute also
    carries no connect-string/principal/DN (the telemetry path is separate from the
    error envelope).
- **A4. Surface `WalletError::UnsupportedFormat` in doctor (redaction-safe).** (p2,
  deps: A1)
- **A5. Re-evaluate IAM-token connect now TCPS is preserved.** (p2, deps: A1)
  - Acceptance: a written determination recorded in the bead + the
    `docs/configuration.md` IAM section: state the exact remaining blocker (no
    production OCI token source) and whether end-to-end is now feasible; if not,
    keep parse-but-fail-closed and cite the seam. **Exit criterion:** the
    determination names the specific missing component and a yes/no on feasibility
    without a token source — not an opinion. Do **not** implement IAM in 0.5.0
    unless trivial; if feasible, file a follow-up bead.
- **A6. Honor `transport_connect_timeout`/`connect_timeout` pass-through.** (p2,
  deps: A1)
  - Acceptance: a profile/connect-string connect timeout reaches the driver; a
    blackholed host fails within the bound (test); documented in
    `docs/configuration.md`. **Config-surface decision (must be explicit):** the
    profile struct has `call_timeout_seconds` but **no** connect-timeout field, and
    profile/pool structs are `#[serde(deny_unknown_fields)]`. Choose one and do it
    fully: **(a)** add a new profile field → add it to the config struct +
    resolution + `oraclemcp.example.toml` + extend
    `crates/oraclemcp-config/tests/example_config_parses.rs` + include it in the A7
    api-lock surface; or **(b)** connect-string/descriptor-only → **no** config
    field and **no** `example.toml` change (otherwise `deny_unknown_fields` fails
    the existing parse-test gate). G3's example-config edit must match this choice.
- **A7. Re-baseline `api-lock` + extend the driver-contract suite + full gates.**
  (p1, deps: A2,A3,A4,A6, **C0,C1,C2,C3, R1,R2** — i.e. after *every* public-surface
  change; C3 adds a public `SerializeOptions` item to a locked crate, so it MUST
  precede the api-lock baseline)
  - Acceptance: `scripts/oraclemcp_api_lock.sh` baselines regenerated & reviewed
    (additive only) capturing TSTZ + auth + the `OracleCell` carrier + the
    `OracleRoutineArg`/`call_routine` surface; the driver-contract suite
    (`crates/oraclemcp-db/tests/oracledb_contract.rs`, **not** a "B7" — that
    reference was a typo) gains OUT-bind + TSTZ contract cases; full battery green
    (`fmt`/`clippy -D`/`test`/`deny`/seam/honesty/boundary).
  - Why: the lock must be taken **last**, after the surface stops changing, or H2
    fails (F4).

### WP-B — Fail-closed timeout hardening (issue #4) — *re-scoped per Round 1*
- **B1. Push the default call timeout into the shared `oraclemcp-db` layer +
  bound commit/rollback.** (p0, deps: A1)
  - Acceptance: a consumer that builds `OracleConnectOptions` directly (like
    plsql-mcp) inherits a bounded default (so the shared adapter is safe, not just
    the oraclemcp binary); the value **stays coupled to the existing 30s**
    (`DEFAULT_CALL_TIMEOUT`) — if any change is wanted, decouple from the request
    budget first and justify; the **ROLLBACK** round-trip (`connection.rs:2033-2051`)
    becomes bound-and-discard (on deadline, drop the connection — the server rolls
    back — instead of awaiting an unbounded rollback). **COMMIT is different
    (in-doubt):** bounding/cancelling a COMMIT cannot prove the txn did not commit
    (the code comments this at `:2034`), so a COMMIT timeout MUST surface as a typed
    **ambiguous/in-doubt** outcome, **never reported as "rolled back"** (consistent
    with R2's M2 note). `doctor` warns when a profile sets `call_timeout_seconds = 0`.
    Tests (fault-injection / silent half-open peer): SELECT, DML, and **ROLLBACK**
    resolve to a typed `CallTimeout` within `bound + recovery` (not a park);
    **COMMIT** resolves to the typed in-doubt outcome. Run the timeout test under a
    production-shaped runtime (reactor, no explicit timer driver) to lock in
    asupersync's fallback-timer path.
  - Why: verified real #4 path (shared-layer default gap) + S1 (cleanup rollback
    re-hang).
- **B1b. Bound the continuation/cursor fetch path (per-batch / read-inactivity).**
  (p0, deps: B1)
  - Acceptance: bound **each** fetch round-trip in the `collect_all_rows` loop
    (`connection.rs:766`; drives `define_and_fetch_rows_with_columns`/
    `fetch_rows_with_columns`/`fetch_cursor` — none take `timeout_ms`). **Wrap at a
    single point** (`collect_all_rows` already subsumes `fetch_cursor`, reached via
    `value_to_cell` — do **not** double-wrap). Use **per-batch (read-inactivity)**
    semantics, not a total-call budget, so a large-but-live multi-batch SELECT /
    REF CURSOR is not killed mid-stream: reset the deadline each fetch. Pin the call
    form — `asupersync::time::timeout(time::wall_now(), dur, fut)` (it requires a
    `now: Time`; `wall_now()` is cx-aware with a wall-clock fallback), or
    `time::budget_timeout(cx, dur, fut, time::wall_now())` to clamp to the existing
    RequestBudget. Test: a stalled 2nd-batch / REF CURSOR read resolves to a typed
    error, not a hang; a large live multi-batch result still completes. If/when
    upstream #14 adds timeout-bearing fetch primitives, replace the wrapper.
  - Why: F2 — the documented symptom (hang mid-result after TNS timeout) lives
    here, not in the initial execute; per-batch avoids a regression on big results.
- **B2. Verify (don't re-implement) dirty-discard on timeout + add regression
  test.** (p1, deps: B1)
  - Acceptance: confirm `pool.rs::should_discard_after_call`
    (`result.is_err() || manager_broken()`) treats a `CallTimeout`-class error as
    dirty (drops the connection, frees the slot) and that lease `force_rollback`
    runs post-await; add a regression test pinning this; no code change unless the
    verification finds a gap. **Served single-conn note:** the served
    `OracleDispatcher` holds one `Box<dyn OracleConnection>` in
    `DispatcherState.conn` (not pool-managed); confirm/specify that after a
    `CallTimeout` this connection is reset/reconnected before reuse (availability,
    not invariant — but a stale post-timeout conn would degrade the served path).
  - Why: F8 — the discard logic already exists; B1 makes the await return so it can
    run.
- **B3. Track rust-oracledb #14 as defense-in-depth.** (p2, deps: none)
  - Acceptance: a bead referencing #14 (apply `EXPIRE_TIME`→`SO_KEEPALIVE`;
    timeout-bearing fetch primitives) with trigger = "next driver drop that lands
    it"; README/threat-model note that idle half-open detection currently relies on
    the per-call default + the B1b wrapper.
- **B4. Close issue #4** linking B1/B1b/B2 + the upstream #14 follow-up. (p1, deps:
  B1,B1b,B2)

### WP-C — Non-lossy / typed serialization (issue #3) — *re-scoped per Round 1*
- **C0. Extend `OracleCell` with a structured value carrier.** (p1, deps: A1;
  blocks C1/C2/C3) — per [D9]
  - Acceptance: add `structured: Option<serde_json::Value>` (or equivalent) to
    `OracleCell` (`types.rs:81-98`); define serializer precedence in `serialize.rs`
    vs `value`/`bytes`/`nested_result`; freeze the agent-facing JSON shape + the
    plsql-mcp contract; unit tests for each carrier rendering.
  - Why: F3 — WP-C is impossible without a structured carrier.
- **C1. Typed serialization for ARRAY / JSON / VECTOR / TSTZ.** (p1, deps: C0,A2)
  - Acceptance: `ARRAY` recurses each element (JSON array); `JSON` walks
    `OsonValue → serde_json::Value`; `VECTOR` → numeric JSON array
    (Float32/64/Int8/Binary); `TSTZ` from A2; `REF CURSOR` stays structural; each
    has a test. **This is a public-surface + serializer + golden change**, not a
    localized arm swap.
- **C2. Object/UDT + all remaining unsupported → typed-unsupported.** (p1, deps:
  C1)
  - Acceptance: object cells carry `schema`/`type_name` + base64 `packed_data` +
    a typed `{ unsupported: { reason: "object_attributes_not_decoded", … } }`; the
    **catch-all (`:1026`) and implicit-resultset (`:1062`) arms also route through
    the typed-unsupported form** (M7) — no bare placeholder strings anywhere.
    Documented driver limit (link a future driver FR).
- **C3. Catalog-extraction contract for plsql-mcp (capped, non-default mode).** (p1,
  deps: C1,C2)
  - Acceptance: a **named, non-default** serialize mode (pin the exact surface in
    the bead: a `SerializeOptions` flag or a helper with a stated signature —
    decide explicitly, don't leave "mode or helper") that is non-lossy for
    supported types and typed-unsupported (never placeholder) otherwise; **LOB
    extraction keeps a hard, configurable ceiling** (typed-truncate/fail above it,
    aligned with the per-DB ceiling invariant — M4), not uncapped. Tests: large
    CLOB complete up to the cap then typed-truncated; BLOB/RAW bytes preserved;
    ARRAY/object yields a stable typed state. Names the contract as serving
    plsql-mcp catalog snapshots.
  - Why: the #3 ask; M4 prevents an uncapped read DoS / data-egress surface.
- **C4. Close issue #3** + flag the serialized-shape change for the upgrade note
  ([G2]/N7). (p1, deps: C1,C2,C3)

### WP-R — Routine execution: OUT / IN OUT / return (issue #2) — *renamed from WP-D*
- **R1. Add an adapter-internal `OracleRoutineArg` type (NOT on `OracleBind`).**
  (p1, deps: A1) — per [D10]
  - Acceptance: a new `OracleRoutineArg { In(OracleBind) | Out{type_hint} |
    InOut{value,type_hint} | Return{type_hint} }`; `OracleBind` (the agent-
    deserializable type, `types.rs:32-45`) stays **input-only**; mapping to driver
    `BindValue::{Output,ReturnOutput}` lives here; unit round-trip test.
    **`OracleRoutineArg` MUST NOT derive/`#[serde]`-`Deserialize`** (optional belt:
    a `static_assertions::assert_not_impl_any!(OracleRoutineArg: Deserialize)` test
    so an accidental future derive fails the battery) and must not be
    embedded in any `#[derive(Deserialize)]` args DTO — the real safety line is
    that no agent-deserializable type can ever construct an output bind (the
    input-only guarantee today rests on the `json_to_bind`/`coerce_bind`
    constructors, `dispatch/mod.rs:832`, `custom_tools.rs:553`, emitting only
    scalars — keep it that way).
  - Why: S3 — keep output-bind power off any deserializable type, enforced by the
    type not deriving `Deserialize`, not by convention.
- **R2. Add `call_routine` (adapter-internal, classifier-gated by callers).** (p1,
  deps: R1)
  - Acceptance: `call_routine(cx, plsql, &[OracleRoutineArg]) ->
    Result<Vec<OracleCell>>` runs one `execute_raw`, returns outputs in a
    **documented deterministic order** — define the bind-layout convention it
    enforces (e.g. `Return` at bind index 0 for `:1 := fn(...)`, then OUT/IN OUT in
    positional order) and how it maps `out_values` indices → result order (F10);
    unsupported output classes → typed `DbError` (no placeholder); a `// SECURITY:
    below the classifier — callers MUST gate` doc-comment; live-XE test: a package
    with one return, one OUT, one IN OUT. **Document that a routine body can
    COMMIT/run autonomous txns server-side regardless of lease rollback** (M2) —
    never report its result as "rolled back."
  - Why: the #2 ask; D10 enforcement.
- **R3. Enforce "no agent-facing routine tool" (now a hard non-goal).** (p1, deps:
  R2)
  - Acceptance: N6 is honored — no `oracle_call_routine` MCP tool registered.
    **Teeth (concrete, grep-able — positive allowlist):** `call_routine` appears
    **only in `oraclemcp-db`**; a lint/test asserts it is **absent from every other
    workspace crate — explicitly including BOTH `oraclemcp` AND `oraclemcp-core`**
    (the agent-facing surface spans both: `dispatch/mod.rs` in `oraclemcp` *and*
    `custom_tools.rs`/`coerce_bind` + `tools.rs`/`plugin.rs`/`capability.rs` in
    `oraclemcp-core`). `scripts/oraclemcp_honesty_grep.sh` already globs all of
    `crates/`, so the mechanism exists — only the scope must be all-crates, not the
    binary crate alone. The plsql-mcp integration contract documents that the
    consumer must classify + level-gate + confirm before calling it.
  - Why: M1/S2 — promote the safety decision out of "implementation choice" into a
    testable boundary.
- **R4. Close issue #2** (adapter API; note #13 as optional upstream ergonomics).
  (p1, deps: R2,R3)

### WP-E — Installer workmanship (headline deliverable)
*Follow `installer-workmanship`; non-negotiables reproduced for self-containment.*
- **E1. Expand release matrix to musl-everywhere (with cross toolchain) + verify
  static.** (p1, deps: none)
  - Acceptance: `release.yml` builds + uploads `aarch64-unknown-linux-musl` (add a
    working cross path — `cargo-zigbuild`/`cross` or aarch64 musl-cross +
    `CC_aarch64_unknown_linux_musl`, because rustls→ring needs a target C compiler;
    current `musl-tools` covers x86_64 only); the **musl** artifacts verified static
    via `file <bin> | grep "statically linked"` (NOT `ldd`, OP-4) — **scope the
    static check to musl only; the `gnu` targets link glibc dynamically by design**
    (no `crt-static`), so a static check over all 7 would falsely fail. Cosign
    `.sig`/`.crt` + checksums + the new asset flow through the existing sign/release
    globs automatically (no extra work); the SBOM stays the single versioned
    `oraclemcp-{version}.cdx.json` (binary-crate, not per-target).
  - Why: D4; the one-liner needs musl for both Linux arches.
- **E2. Author `install.sh` (Linux + macOS).** (p0, deps: E1, A0)
  - Acceptance — ALL non-negotiables: `set -euo pipefail`; `umask 022`;
    `shopt -s lastpipe`; `trap cleanup EXIT`; branded header (gum + ANSI fallback);
    `--help` documenting every flag (`--quiet`,`--no-gum`,`--force`,
    `--offline TARBALL`,`--easy-mode`,`--no-cosign`,`--prefix DIR`,`--from-source`);
    (note: the flag is **`--no-cosign`** — it skips *signature* verification only;
    **SHA256 is unconditional and never skippable**, so there is no `--no-verify`);
    curl one-liner header comment w/ cache-buster; proxy support (`PROXY_ARGS`
    array on every curl); platform detect (linux/darwin × x86_64/aarch64 →
    **musl** for linux; on darwin also detect **Rosetta** —
    `sysctl -n sysctl.proc_translated`==1 / `hw.optional.arm64` — and prefer
    `aarch64-apple-darwin` so a translated shell's `uname -m=x86_64` doesn't
    mis-target an arm64 Mac) + WSL warn; version resolution (CLI → GitHub API latest →
    redirect-parse → hardcoded fallback); 4-tier artifact URL fallback (asset name
    is `oraclemcp-{target}.tar.gz`, **no version in filename**); preflight (disk
    **≥30MB prebuilt / ≥5GB if `--from-source`** (M-Q1c), write perms, network,
    existing-version report); atomic mkdir lock w/ stale-PID; download +
    **SHA256 verify (dual `sha256sum`/`shasum -a 256`)**; **cosign verify-blob**
    using the **detached `.sig` + `.crt`** (download both; verify-blob with
    `--certificate-identity-regexp '^https://github\.com/MuhDur/oraclemcp/\.github/workflows/release\.yml@refs/tags/v.*$'`
    and `--certificate-oidc-issuer 'https://token.actions.githubusercontent.com'`;
    **case-sensitive `MuhDur`**; best-effort: hard-fail if cosign present + bad sig,
    soft-skip if cosign absent; **a failed SHA256/cosign check is TERMINAL — never
    falls back to source** (M5)); extract (binary nested at
    `oraclemcp-{target}/oraclemcp`) + `install -m 0755`; **build-from-source is
    opt-in (`--from-source`/confirm), not silent auto-fallback** (M-Q3), and
    installs the **pinned** nightly (`rustup toolchain install nightly-2026-05-11`;
    the cloned repo's `rust-toolchain.toml` also forces it); version-already-
    installed short-circuit (still configures); completions via
    `oraclemcp completions <shell>` (from A0; **best-effort — soft-skip if the
    installed binary lacks the subcommand**, so version skew never aborts the
    install); PATH setup; final summary box
    (per-step + per-client status, uninstall instructions); `info/ok/warn/err` +
    `run_with_spinner` + `draw_box`.
  - Why: gold-standard install UX (G1).
- **E3. Author `install.ps1` (Windows x86_64-msvc).** (p1, deps: E1, A0)
  - Acceptance: PowerShell equivalent — detect, version resolve, download `.zip`,
    SHA256 verify, extract to `%LOCALAPPDATA%\Programs\oraclemcp`, PATH (user
    scope), completions (powershell), summary, `-Quiet`/`-Force`/`-Offline`. Cosign
    best-effort. **Windows `.sha256` is certutil's 3-line format** (header / hex /
    trailer, from `certutil -hashfile … SHA256`), not coreutils `<hash>␠␠<file>` —
    parse the middle hex line and compare to `Get-FileHash`. One-liner
    `irm <url>/install.ps1 | iex`.
- **E4. MCP-client auto-registration (opt-in; verified paths).** (p1, deps: E2,E3)
  — per [D3]/[M6]
  - Acceptance (verified file/keys on this machine):
    - Claude Code → prefer `claude mcp add --scope user oracle -- oraclemcp serve
      --allow-no-auth`; else JSON-merge into **`~/.claude.json` `.mcpServers`**
      (NOT `~/.claude/settings.json`).
    - Codex → **`~/.codex/config.toml` `[mcp_servers.oracle]`**; TOML has no stdlib
      writer — append a guarded `[mcp_servers.oracle]` block (grep the header for
      idempotency) or vendor `tomli_w`; timestamped backup.
    - Gemini → **`~/.gemini/settings.json` `.mcpServers`**.
    - Cursor → **`~/.cursor/mcp.json`** (global, not project `.cursor/`).
    - Claude Desktop → **macOS only** `~/Library/Application Support/Claude/
      claude_desktop_config.json` (skip on Linux; `%APPDATA%\Claude\…` in E3).
    - JSON merges via embedded Python3 with timestamped backup + idempotent
      "already configured" detection; **stdio form only — never an HTTP/`--listen`
      `--allow-no-auth` entry**; a test asserts only the stdio form is ever written
      (M6); **no secrets** written.
- **E5. Config scaffolding (materialize a template).** (p2, deps: E2)
  - Acceptance: the binary can **write** a profile template — add
    `oraclemcp setup --write <path>` (or `oraclemcp init`) since today `setup` only
    *prints* (verified); installer offers to create
    `~/.config/oraclemcp/profiles.toml` with `credential_ref = "env:…"`
    placeholders if none exists; never overwrites without `--force`; prints the
    next-step env export.
- **E6. Uninstall + `--offline` airgap.** (p2, deps: E2)
  - Acceptance: uninstall removes binary/completions and (confirmed) the MCP
    registrations it added (restore backups); `--offline TARBALL` installs from a
    local artifact with SHA256 check and **skips cosign** (verify-blob needs Rekor
    online — M-Q4b); no network.
- **E7. CI: lint + smoke the installers.** (p1, deps: E2,E3,A0)
  - Acceptance: workflow runs `shellcheck install.sh` + `bash -n`,
    PSScriptAnalyzer on `install.ps1`, and an end-to-end smoke into a temp prefix on
    ubuntu/macos/windows runners → assert `oraclemcp --version`. **Smoke against the
    just-built 0.5.0 artifact via `--offline TARBALL`, NOT the published "latest"** —
    `/releases/latest` excludes prereleases, so during 0.5.0 dev "latest" = 0.4.0,
    which lacks `completions`/`setup --write` and would red the smoke. Audit
    installer target triples vs actual release asset names (OP-15 guard).
- **E8. Host + document the one-liner.** (p0, deps: E2,E3) — see [§6]
  - Acceptance: `install.sh`/`install.ps1` at repo root, reachable at
    `https://raw.githubusercontent.com/MuhDur/oraclemcp/main/install.sh`; README
    "Install" leads with the per-OS one-liner; nightly `cargo install` demoted to
    "build from source."

### WP-F — Distribution channels (complementary)
- **F1. cargo-binstall metadata (correct asset shape).** (p2, deps: E1)
  - Acceptance: in `crates/oraclemcp/Cargo.toml`:
    ```toml
    [package.metadata.binstall]
    pkg-url = "{ repo }/releases/download/v{ version }/{ name }-{ target }{ archive-suffix }"
    bin-dir = "{ name }-{ target }/{ bin }{ binary-ext }"
    pkg-fmt = "tgz"
    [package.metadata.binstall.overrides.x86_64-pc-windows-msvc]
    pkg-fmt = "zip"
    ```
    (version only in the `v{version}/` path segment — the filename has none; binary
    is nested; Windows zip override. `pkg-fmt = "tgz"`'s canonical suffix is `.tgz`
    while the asset is `.tar.gz`; binstall tries both `{archive-suffix}` candidates,
    so it resolves.) The snippet is correct by construction; **confirm
    `cargo binstall oraclemcp` actually resolves in CI *after* 0.5.0 is published**
    (it can't be verified pre-publish — the crate is 0.4.0 today and has no binstall
    metadata yet).
  - Why: the v1 default key would 404 → compile from source (needs the nightly the
    channel exists to avoid).
- **F2. Homebrew tap (stretch).** (p3, deps: E1) — `brew install
  MuhDur/oraclemcp/oraclemcp`; ship only if time permits.
- **F3. Scoop/winget manifest (stretch).** (p3, deps: E3) — document if deferred.
- **F4. Verify the tag workflow's docker + MCP-registry emit 0.5.0.** (p1, deps:
  H3) — *reframed (Round 1): not a separate manual publish*
  - Acceptance: H1 bumps `server.json` **`version` AND `packages[].identifier`**
    (`…:0.5.0`) so the automated `release.yml` `docker` + `publish-mcp-registry`
    jobs emit 0.5.0; F4 only **verifies** `ghcr.io/muhdur/oraclemcp:0.5.0` +
    `:latest` exist and the registry entry is 0.5.0 (the standalone `docker.yml`/
    `publish-mcp.yml` are manual fallbacks only). **Docker is amd64-only** today
    (no `platforms:`); either accept that and correct §6, or (stretch) add
    `platforms: linux/amd64,linux/arm64` + `setup-qemu-action` + arm64 build in the
    Dockerfile. Default: **amd64-only for 0.5.0**, §6 corrected, arm64 image a
    stretch/follow-up.
  - Why: the registry/GHCR publish happens *in* the tag run; a post-release manual
    re-publish would race/duplicate.

### WP-G — Stable-release hardening & docs
- **G1. README "Install" rewrite (one-liner first).** (p0, deps: E8)
- **G2. CHANGELOG `[0.5.0]` + an "Upgrading from 0.4.0" subsection.** (p1, deps:
  most WPs) — via `changelog-md-workmanship`. The upgrade note MUST enumerate the
  **behavior changes for consumers** (N7): ARRAY/JSON/VECTOR/TSTZ no longer
  serialize as placeholder strings; objects gain a typed-unsupported marker;
  anything parsing the old `"<unsupported ARRAY len=N>"` strings breaks; api-lock
  baseline moved; any timeout-semantics change — explicitly flagged for plsql-mcp
  catalog consumers. The `[0.5.0]` heading carries the **actual tag date** (set at
  H3; no pre-dated/placeholder heading — Keep-a-Changelog format like `[0.4.0]`).
- **G3. Docs + policy currency sweep.** (p1, deps: A-series,WP-B/C/R)
  - Acceptance: `configuration.md` (connect-timeout, TSTZ, auth caps, catalog
    mode), `operations.md`, **`threat-model.md`** (add: curl|bash installer trust
    model — the bootstrap script is fetched **unsigned/unpinned from `main`** over
    GitHub TLS, and the per-asset `.sha256` is published from the **same GitHub
    origin** as the artifact, so it guards only **transport corruption, not
    authenticity**; the **only real authenticity gate is `cosign verify-blob`
    against Rekor**, which most users won't have — state this honestly, do not
    imply SHA256 provides authenticity (honesty-grep is sensitive to exactly this).
    MCP auto-registration is **stdio-only**, never HTTP-`--allow-no-auth`; the
    registered server inherits the fail-closed default `READ_ONLY`),
    `toolchain.md` (still nightly via asupersync),
    behavior inventory, **`SECURITY.md`** (bump supported-versions to 0.5.x current
    / 0.4.x critical-only; fix the 0.3→0.4 transition sentence),
    `oraclemcp.example.toml` (new fields: connect-timeout, catalog mode if any),
    **LICENSE-APACHE/LICENSE-MIT copyright-year check** for a 2026 cut. Honesty-grep
    stays green.
- **G4. Conformance 100% + golden rebless.** (p1, deps: A7,WP-C,WP-R) — serializer
  + tool-surface changes touch golden transcripts; re-bless deliberately.
- **G5. Perf re-measure on 0.5.1.** (p2, deps: A7) — refresh
  `docs/performance-footprint.md` (binary size, p50/p95/p99) on real 23ai; no
  optimization unless a hotspot ≥2.0.
- **G6. Live-XE qualification on real 23ai.** (p1, deps: A7,B1,B1b,C1,R2) — full
  `ORACLEMCP_TEST_*` live suite + load/soak; record artifacts honestly.
- **G7. Reconcile the deferred-epic ledger.** (p2, deps: A3,A5) — update
  `oraclemcp-040-epic-deferred-k6q` children k6q.7/.8 (now "honest typed surfacing"
  via A3) and k6q.9 (IAM per A5); document the 040-deferred epic's relationship to
  the new `oraclemcp-050-epic`.
- **G8. `doctor` world-class polish (optional).** (p3, deps: A3,A4,A6) — apply
  `world-class-doctor-mode-for-cli-tools` to the new auth/wallet/timeout checks.

### WP-H — Release cut (operator + live gated)
- **H1. Version bump 0.4.0 → 0.5.0** across all 9 manifests + internal pins +
  `server.json` (**`version` AND `packages[].identifier`**) + the **installer
  hardcoded fallback version** in `install.sh`/`install.ps1` + GHCR tag refs +
  lock; `release_preflight.sh` green. (p1, deps: all feature WPs)
- **H2. Full gate battery + test gate (MANDATORY).** (p0, deps: H1) —
  `fmt`/`clippy -D` (on the pin; the real residual is an *untested pin bump*, not
  local-vs-CI drift, OP-3)/`test`/`deny`/seam/honesty/api-lock/boundary/preflight
  + installer CI (E7) + live-XE (G6) + **a "no git/path deps in published crates"
  gate** (`cargo package --locked`/preflight) so the temp 0.5.1 git pin is gone
  (§1.3) + **extend `release_preflight.sh`** to assert the `install.sh`/`install.ps1`
  hardcoded fallback version == workspace version (today its stale-version scan
  covers only README/server.json/src/.github/Dockerfile — the installer files are
  unguarded, so an un-bumped fallback would silently ship 0.4.0).
- **H3. Tag `v0.5.0` → `release.yml`** runs the full pipeline: build all 7 targets
  → **publish-crates (crates.io)** → GitHub release (gated on publish-crates) →
  GHCR (amd64) → MCP registry; verify assets (incl. `aarch64-musl`) + cosign +
  SBOM + the registry-verify gate (identifier == `…:0.5.0`) passes. **`server.json`
  is schema-validated by `mcp-publisher` only in the *final* job — after crates.io/
  GitHub/GHCR have already published irrevocably; so add a *local* `server.json`
  schema-validate to H2/`release_preflight.sh`** to catch structural breakage
  pre-tag. (p0, deps: H2)
- **H4. Verify crates.io publish succeeded** (it runs *inside* H3's workflow before
  the GitHub release — do **not** run a separate `cargo publish`, which would
  double-publish/conflict). (p1, deps: H3) — *corrected order (Round 1)*
- **H5. Verify the one-liner end-to-end on clean Linux/macOS/Windows machines**:
  `curl|bash` → `oraclemcp --version == 0.5.0` → `oraclemcp doctor` green. (p0,
  deps: H3)
- **H6. Post-release fresh-eyes review** + close the 0.5.0 epic + memory update.
  (p2, deps: H3,H4,H5)
- **H7. Rollback / yank runbook (authored pre-tag, executed only on failure).**
  (p1, deps: H1)
  - Acceptance: a documented back-out — `cargo yank --version 0.5.0` per crate in
    leaf order (yank ≠ delete; existing lockfiles keep resolving, new `^` selects
    skip it); **mark the `v0.5.0` GitHub Release as prerelease (or delete it) so
    `/releases/latest` reverts to `v0.4.0`** — otherwise the headline `curl|bash`
    installer (resolves via GitHub-API-latest) and `cargo binstall` (pulls release
    assets) keep serving 0.5.0 despite the yank; re-point GHCR `:latest` to 0.4.0;
    revert/re-publish `server.json` to 0.4.0; user guidance "pin `=0.4.0`";
    **trigger = H5 (one-liner) or F4 (docker/registry) failure post-publish** (H2 is
    a pre-tag gate and cannot fail post-publish).
  - Why: a stable release needs a defined recovery path that covers **the channels
    users actually hit** — the GitHub Release is the source of truth for both binary
    install paths (`rust-crates-publishing`/`release-preparations` expect a yank
    plan).

---

## 5. Dependency DAG

```
A0(completions) ─────────────────────────────► E2,E3,E7
A1(pin 0.5.1) ─┬─ A2 ─────────► C1
               ├─ A3 ─┐                 C0(cell carrier) ─ C1 ─ C2 ─ C3 ─ C4(close #3)
               ├─ A4 ─┤                 (C1 needs A2; C-series need C0)
               ├─ A5 ─┤
               ├─ A6 ─┤
               ├─ C0 ─┘
               ├─ B1 ─ B1b ─┐
               │     └ B2 ──┴─ B4(close #4)        B3 (independent, tracks #14)
               └─ R1 ─ R2 ─┬─ R3 ─ R4(close #2)
                           └ (R3 enforces N6)
A2,A3,A4,A6,C0,C1,C2,C3,R1,R2 ─► A7(api-lock + contract suite + gates)  [LAST surface step]

E1(matrix+aarch64-musl) ─┬─ E2 ─┬─ E4
                         │      ├─ E5
                         │      ├─ E6
                         │      └─ E8 ─ G1
                         ├─ E3 ─ E4
                         ├─ E7
                         └─ F1   (F2/F3 stretch)

A7,WP-B,WP-C,WP-R,WP-E ─► G2,G3,G4,G5,G6,G7(,G8) ─► H1 ─► H2 ─► H3
H3 ─► [crates.io publish (in-workflow) ─► GitHub release ─► GHCR ─► MCP registry]
H3 ─► H4(verify crates.io) ; H3 ─► H5(verify one-liner) ; H3 ─► F4(verify docker/registry)
H1 ─► H7(rollback runbook, ready) ; {H3,H4,H5} ─► H6(close epic)
```
No cycles. **Within-workflow order** (H3): build → publish-crates → GitHub release
→ docker → mcp-registry (the GitHub release is gated on crates.io success).
**Seam serialization (F5):** A2/B*/C0-C1/R1-R2 all edit `connection.rs` —
sequence them; the seam, not the edges, is the binding constraint.
Parallel tracks: **{WP-A→B/C/R}** and **{WP-E/F}** are independent until WP-G/H.

---

## 6. The install one-liner (exact UX)

**Linux & macOS (x86_64 / aarch64):**
```sh
curl -fsSL https://raw.githubusercontent.com/MuhDur/oraclemcp/main/install.sh | bash
```
**Windows (x86_64, PowerShell):**
```powershell
irm https://raw.githubusercontent.com/MuhDur/oraclemcp/main/install.ps1 | iex
```
**Rust users (prebuilt, no nightly):** `cargo binstall oraclemcp`
**Docker (amd64):** `docker run -i --rm ghcr.io/muhdur/oraclemcp:0.5.0`
**Homebrew (stretch):** `brew install MuhDur/oraclemcp/oraclemcp`

> **`| bash`, not `| sh`** — the script uses bashisms (`shopt -s lastpipe`, arrays,
> `[[ ]]`, `local`); piping to `/bin/sh` (dash/ash) throws syntax errors. This was
> a Round-1 fix; the README/E8 must use `bash`.

Behavior: detect OS/arch → download matching **musl-static** (Linux) / native
(macOS/Windows) prebuilt → SHA256 verify (terminal on failure) + cosign verify-blob
if cosign present → install to `~/.local/bin` (or `--prefix`) → install completions
→ optionally register as an MCP server in detected agents (opt-in, **stdio-only**,
no secrets) → print summary + next steps (`oraclemcp setup --write …`, export the
credential env var, `oraclemcp doctor`). Source build only via `--from-source`.

Supported-systems matrix (post-E1):

| OS | arch | artifact triple | channels |
|----|------|-----------------|----------|
| Linux | x86_64 | `x86_64-unknown-linux-musl` | install.sh, binstall, Docker(amd64) |
| Linux | aarch64 | `aarch64-unknown-linux-musl` *(new, E1)* | install.sh, binstall |
| macOS | x86_64 | `x86_64-apple-darwin` | install.sh, binstall, brew* |
| macOS | aarch64 | `aarch64-apple-darwin` | install.sh, binstall, brew* |
| Windows | x86_64 | `x86_64-pc-windows-msvc` | install.ps1, binstall, scoop/winget* |

`*` stretch. `gnu` Linux artifacts stay published (binstall may pick them on glibc
hosts). **Docker is amd64-only** for 0.5.0 (arm64 image is a stretch — F4).

---

## 7. Definition of Done (gates for `v0.5.0`)

H3 is blocked until ALL hold:
1. #2/#3/#4 closed with tests; safety invariant intact (N5); **no agent-facing
   `oracle_call_routine` tool ships** (N6, asserted by R3's lint/test).
2. Driver `=0.5.1` baked in; seam green; **api-lock re-baselined AFTER all
   surface changes** (A7) and reviewed.
3. TSTZ + auth-honesty (redaction-safe) + wallet-diag wired (A2/A3/A4; documented
   in G3).
4. `install.sh` + `install.ps1` pass shellcheck/PSScriptAnalyzer + CI smoke on
   Linux/macOS/Windows; SHA256 always + cosign verify-blob exercised; verify
   failure is terminal; installer triples match release assets (OP-15);
   MCP registration is stdio-only (test).
5. Matrix builds all 7 targets incl. `aarch64-musl`; the **musl** artifacts
   static-verified (`file`, not `ldd`) — gnu targets are expected dynamic; all
   signed, SBOM'd.
6. Full gate battery green on the pin; **no git/path deps in published crates**;
   conformance 100%; live-XE green; perf re-measured.
7. README leads with the `| bash` one-liner; CHANGELOG `[0.5.0]` + upgrade note
   (N7); SECURITY.md/threat-model/configuration current; honesty-grep green.
8. `server.json` `version` AND `identifier` bumped + schema-validates; one-liner
   verified end-to-end on clean machines (H5); rollback runbook ready (H7).

---

## 8. Risks & mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| 0.5.1 not on crates.io at cut-over | can't pin for release | temp git pin in dev; H2 "no git pin" gate before publish |
| `#[non_exhaustive]` driver enums grow again | silent placeholder regressions | A2/C1 explicit arms; a test asserts no known `QueryValue` hits the fail-safe arm |
| aarch64-musl cross-link fails (ring needs CC) | installer arm Linux path → source | E1 adds cargo-zigbuild/cross; E7 static-verify + smoke on both arches |
| #4 only half-fixed (fetch loop still hangs) | symptom persists on multi-batch/REF CURSOR | B1b wraps the fetch loop now; B3 tracks the upstream primitive |
| Cleanup ROLLBACK re-hangs on dead socket | rollback-by-default broken | B1 bounds the ROLLBACK await (drop conn on deadline → server rolls back); COMMIT timeout → typed in-doubt, never "rolled back" + test |
| cosign verify too strict / wrong shape | installer hard-fails | verify-blob with detached `.sig`/`.crt`, case-sensitive `MuhDur` identity, best-effort + terminal-only-on-bad-sig; skip offline |
| MCP auto-registration clobbers config | data loss / support | timestamped backups, idempotent merge, opt-in, restore on uninstall; TOML handled explicitly |
| `| sh` on the headline one-liner | flagship command errors out | `| bash` everywhere (Round-1 fix) |
| crates.io double-publish (manual + workflow) | release conflict | H4 = *verify*, not re-publish (publish is in-workflow) |
| Docker arm64 over-promised | emulated/missing image | §6 says amd64-only; arm64 image a stretch (F4) |
| Serialized-shape change breaks consumers | plsql-mcp / parsers break silently | N7 upgrade note (G2) enumerates every shape change |
| Scope creep into 1.0 / deferred features | blown timeline | N1–N4 hold; deferred epic untouched |

---

## 9. Open questions for the operator

1. **#4 default-timeout value:** keep the existing **30s** (recommended; coupled to
   request budget) or raise (requires decoupling first)? Plan default: **keep 30s**,
   just propagate it to the shared adapter layer.
2. **MCP auto-registration:** opt-in prompt (recommended; default no in `--quiet`)
   vs. print-only?
3. **Docker arm64 image:** amd64-only for 0.5.0 (recommended) or add multi-arch
   now (QEMU + Dockerfile arm64 build)?
4. **Homebrew/Scoop/winget:** in 0.5.0 or fast-follow? Default: **stretch**.
5. **Vanity install URL** (e.g. `get.oraclemcp.<domain>`): want it? Default: **no**,
   use raw.githubusercontent.
6. **`oracle_call_routine` as an agent tool:** confirmed **out** for 0.5.0 (N6) —
   agree?

---

## 10. The "stay tuned" slot (WP-I, reserved)

The operator will reveal a follow-on capability after this plan is reviewed. The
plan is structured so it slots in as **WP-I** without disturbing WP-A…H: the seam
discipline, additive versioning, installer channels, and the beads epic all
accommodate an extra track. Either fold it into 0.5.0 (if small/aligned) or
schedule 0.5.1/0.6.0; leave the 0.5.0 DoD intact.

---

## 11. Beads conversion plan

One epic, preserving the [§5] DAG:
```
oraclemcp-050-epic                       (epic) Stable & Installable 0.5.0
├─ …-wp-a  Driver 0.5.1 bake-in + CLI    A0..A7
├─ …-wp-b  Timeout hardening (#4)        B1,B1b,B2,B3,B4
├─ …-wp-c  Non-lossy serialization (#3)  C0..C4
├─ …-wp-r  Routine execution (#2)        R1..R4
├─ …-wp-e  Installer workmanship         E1..E8
├─ …-wp-f  Distribution channels         F1..F4
├─ …-wp-g  Hardening & docs              G1..G8
└─ …-wp-h  Release cut (gated)           H1..H7
```
Rules (`beads-workflow`): self-contained beads (acceptance copied here), `--deps`
from [§5], types `feature`/`task`/`bug`/`chore`, priorities as tagged,
`br sync --flush-only` before committing `.beads/` with the plan. `…-wp-h` is
`blocked-by` the [§7] DoD beads. Note the **seam-serialization** constraint (F5)
on A2/B*/C0-C1/R1-R2 as a bead comment. Do not start beads before steady-state.

---

## 12. Review log

Per `planning-workflow`, ≥4 adversarial rounds to steady-state before beads.

- **Round 0 (v1 draft):** initial structure.
- **Round 1 (v2, this revision) — STRUCTURAL.** 4-reviewer panel (architecture,
  installer/release, safety, completeness/DAG), all findings verified against
  source by the author. Major integrations:
  - **#4 re-scoped** (the central v1 error): a 30s default already exists in
    `connect.rs`; the real gaps are the shared-adapter default (plsql-mcp path),
    the unbounded continuation/cursor fetch loop (B1b), and unbounded commit/
    rollback (B1/S1). Dropped the 300s proposal.
  - **WP-C re-scoped**: added C0 (cell-model carrier) — WP-C is a public-surface +
    golden change, not "pure flattening"; all unsupported renderings now typed.
  - **WP-D → WP-R**, output binds moved to adapter-internal `OracleRoutineArg`
    (off the deserializable `OracleBind`), classifier-gating made a hard caller
    requirement; **N6** (no agent routine tool) promoted to a non-goal + DoD.
  - **Installer/release facts corrected**: `| sh`→`| bash`; added A0 (no
    `completions` subcommand exists); cosign detached `.sig`/`.crt` verify-blob
    shape; binstall key fixed; aarch64-musl cross toolchain; source-build opt-in;
    verified MCP-client config paths + TOML handling; crates.io publishes
    *in-workflow* before the GitHub release (H4 reframed); Docker amd64-only;
    `server.json` bumps both fields; A7 api-lock sequenced last.
  - **Missing tasks added**: SECURITY.md update, "Upgrading from 0.4.0" note (N7),
    rollback/yank runbook (H7), deferred-epic reconciliation (G7), license-year +
    threat-model installer/MCP entries.
  - Marginal: F6 (EXPIRE_TIME parsed-not-applied wording), F7 (B7→oracledb_contract),
    F9 (BindValue non_exhaustive note), F10 (call_routine ordering convention),
    A5 exit criterion, C3 mode-vs-helper to be pinned.
- **Round 2 (v3, this revision) — MARGINAL.** Fresh 3-reviewer panel
  (architecture/DAG, installer/release, safety/completeness); all Round-1 fixes
  **re-verified clean against source** (no regressions). All three rendered a
  "near steady-state, no Round-3 restructuring" verdict. Integrations:
  - **One structural edge:** `C3 → A7` (C3 adds a public `SerializeOptions` item to
    a locked crate, so api-lock must baseline after it). Added in §4 + §5.
  - **B1/B1b precision:** COMMIT timeout is **in-doubt** (never "rolled back"); only
    ROLLBACK is bound-and-discard. B1b pinned to `time::timeout(wall_now(), …)` with
    **per-batch (read-inactivity)** semantics and a **single** wrap point
    (`collect_all_rows` subsumes `fetch_cursor`).
  - **Safety teeth:** `OracleRoutineArg` must **not** derive `Deserialize`; R3 teeth
    = grep-assert **zero `call_routine` refs in the `oraclemcp` server crate**;
    added a telemetry-redaction test to A3; served single-conn reset note (B2).
  - **Installer/release:** static-verify **scoped to musl** (gnu is dynamic by
    design); `--no-verify`→**`--no-cosign`** (SHA256 unconditional); E7 smoke uses
    the **built 0.5.0 via `--offline`** (latest = 0.4.0 lacks `completions`);
    `release_preflight.sh` extended to guard the installer fallback version (H2);
    macOS **Rosetta** detection (E2); Windows **certutil** checksum format (E3);
    local `server.json` schema-validate moved pre-tag (H3); SBOM reworded
    (versioned binary-crate bom); F1 resolution made post-publish-verified.
  - **Couplings/honesty:** A6 connect-timeout config-field vs
    `example_config_parses`/`deny_unknown_fields` decision made explicit; G3
    threat-model SHA256 wording corrected (transport-only, not authenticity); G2
    CHANGELOG dated at tag.
  - Verified-OK (no change): SLSA/provenance already present; SECURITY.md/
    threat-model/TOOLCHAIN exist; MSRV intentionally absent.
- **Round 3 (v3 final, this revision) — MARGINAL/CONFIRMATION.** 2-reviewer panel
  (consistency/cross-reference; DoD/release-sequence/safety). Consistency reviewer:
  STEADY-STATE — cross-refs clean (A7 deps, `--no-cosign` rename, COMMIT/ROLLBACK
  split, musl-only static scope all coherent across §4–§8), source spot-checks
  (certutil, `OracleBind`/Deserialize, dispatch constructors, `OracleCell` shape,
  Rosetta keys) all pass. DoD/safety reviewer found two tight enforcement fixes
  (applied): (1) **R3 grep scope widened** to a positive allowlist —
  `call_routine` only in `oraclemcp-db`, forbidden in ALL other crates incl.
  `oraclemcp-core` (the agent surface spans both crates, so a single-crate lint
  left N6 unenforced); (2) **H7 rollback now marks the v0.5.0 GitHub Release
  prerelease/delete** so `/releases/latest` reverts (else the headline installer +
  binstall keep serving 0.5.0 after a yank). Plus LOW fixes: H7 trigger = H5/F4
  (not H2, which is pre-tag), DoD item 3 cites A2/A3/A4, §8 risk-row COMMIT-in-doubt
  phrasing, optional `assert_not_impl_any` belt on R1. Release-sequence/ordering
  re-traced against `release.yml` job graph — airtight and acyclic.
- **Round 4:** not needed — Round 3 was marginal/confirmation with no structural
  item; both reviewers reached steady-state after the two local fixes.
- **Steady-state reached:** **YES.** Survived 3 integration rounds across 9
  independent reviews (4 + 3 + 2), the last producing only local prose fixes. Plan
  is frozen and **ready for beads conversion** under `oraclemcp-050-epic` (§11).
