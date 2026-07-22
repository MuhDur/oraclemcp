# PLAN — oraclemcp 0.6.0 "Interactive & Always-On"

> Status: **DRAFT v3.18 — PLAN-SPACE COMPLETE; READY TO BEAD** (v3.18: **Appendix A** =
> source-verified asupersync 0.3.4 API reference resolving **CX-Q1** [+ 5 name-vs-reality corrections:
> `Pool` absent, `epoch_tracker` mis-named, `mask()`→`cx.masked`/`commit_section`, "tracked_channel"→
> `reserve`/`SendPermit`, `current_thread`≈2 OS-threads/lane]; **Appendix B** = per-WP acceptance-test
> specs mapped onto the real test files, by modality [metamorphic/conformance/golden/fuzz/lab/
> real-service-e2e]. §4-RS: reality-check =
> shippable/vision-fully-covered + 4 steers; security-audit = strongly fail-closed + 7 hardening
> adds, esp. **SEC-1 CP-apply must re-classify at apply (never trust the stored verdict)**, SEC-2
> normalize-before-classify, SEC-3 audit-write-fail=fail-closed). Earlier v3.16 — ground-truth
> refreshed; 6 pre-bead gaps resolved (§4-GT, via
> `codebase-archaeology` + `oracle`): repo at 0.4.1 / `oracledb`=0.5.1; **the fail-closed guard
> already ships (oraclemcp-guard) → WP-N is a lane layer over it, not a new classifier**; the
> classifier is mature + Oracle-aware (one open SELECT-side-effect tightening, gated on the engine
> oracle); **plsql-intelligence v0.7.0 engine crates are pure (no tokio/net) → clean bake-in via
> the `SideEffectOracle` purity port [safety core, 0.6.0-eligible] + Workbench IDE [0.6.1]**; D17
> operator-authority allow-list; D18 secrets = external refs via `SecretResolver`; migration +
> `om backup`/`restore`. Earlier v3.15 — Codex triangulation (§4-CX: Codex `gpt-5.5`
> adversarial review integrated — 5 CRITICAL / 11 IMPORTANT / 1 MINOR / 1 QUESTION; key outcomes:
> **D1 reframed to a release train 0.6.0→0.6.1→0.6.2** [one plan, no deferral]; WD-RULE-1 honest
> DML/DDL revert scope; redact-binds-by-default + audited reveal; durable write-ahead idempotency;
> SSE Origin/replay-cursor + ticket-as-bootstrap-secret; file-storage path-safety/fsync; Phase-0
> capacity + panic spikes; ground-truth refreshed [oracledb already =0.5.1]; GSAP kept). Earlier
> v3.14 — DASHBOARD DESIGN COMPLETE (§4-WD.6 SSE/watch+broadcast real-time
> model; §4-WD.7 identity "Ground Control" + Orrery 3D three.js + GO/NO-GO/Clearance/Countdown/
> Logbook signatures + 5 legibility principles + GSAP locked; §4-WD.8 + D16 skinnable
> architecture — view-model/skin/theme/renderer seam, 3D quarantined, grammar-is-contract,
> runtime skins deferred). Prior v3.13: 3 dashboard forks RESOLVED — FORK-1 operator-sees-everything [redaction
> = default-off policy seam], **FORK-2 metric history = append-only files we write ourselves [no
> DB, no Prometheus; OTLP export optional]**, FORK-3 cred lifecycle in UI / secret never in
> browser; **D14: files all the way down [audit/config/snapshots/proposals/metrics], no database;
> redb/SQLite NOT adopted — redb only a never-needed-yet escape hatch behind the `Store` seam**).
> v3.11 D15 design-for-cheap-change [enforced: deps-inward, trait-seams,
> tests-pin-contracts, arch-fitness CI]; §4-WD.5 all 7 per-view specs + cross-view component
> reuse; 3 forks flagged: binds-redaction / metrics-retention / creds-never-in-browser).
> v3.10 dashboard design §4-WD, collaborative: Mission-Control shape + 8-view
> nav locked; Workbench = governed PL/SQL IDE [no fail-closed exception — guard-as-feature],
> WD-RULE-1 DML-uncommitted vs DDL-committed-snapshot-undo; plsql-intelligence wired in [offline];
> Change-Review board "PR for PL/SQL" per profile/author [Git+Cursor]; global DB search; schema
> diff + migration export confirmed; **D14 persistence = files-first/pure-Rust, never SQLite**;
> R3a/R3b resolved). v3.7 (skill-informed hardening §4-SK: deadlock-finder DL-1..DL-10 — block_on
> reconciliation, canonical lock order, poison/lost-wakeup fixes, Pool+bulkhead ceiling,
> lab-oracle N9, concurrency-audit CI; mcp-server-design MCP-1..MCP-14 — educational refusals,
> capability-gated tools/list, discovery resources, coerce-cosmetic/strict-on-safety; agent-
> ergonomics ERG-1..ERG-12 — om Polish-Bar gates, exit-code dict, capabilities/robot-docs,
> parity matrix; doctor DOC-1..DOC-11 — scoped self-repair, audit-chain detect-only, om doctor
> = WP-N health window, unified release-acceptance CI).
> v3.6 (asupersync-leverage 2nd pass §4-AS.2: AppSpec/supervision app-
> topology + RestartPolicy + name-leases; Budget.meet/Outcome/CancelReason/mask carry the
> safety contract to the edge; obligation-tracked mailbox + permit-backed per-DB ceiling;
> ServiceBuilder ingress; cap::None classifier; quiescence/leak/futurelock oracles).
> v3.5 (§4-AS, Codex-triangulated): build WP-N on
> native channels/cancel/supervision/scope/lab/combinator + MT-runtime-for-transport;
> lane = supervised Send handle + thread-pinned block_on loop owning the !Send conn;
> combinator bracket/bulkhead/circuit_breaker/rate_limit + epoch_tracker adopted.
> Earlier: v3.3 Codex cross-model triangulation integrated — CX-1 read-worker
> lanes (not a shared pool), CX-2 panic=quarantine-not-rollback, CX-3 dashboard-api vs
> -bundle features, CX-4 transport-layer capacity, CX-5 retire confirm compat path.
> Two models + 5-lens panel + GPT Pro now agree. Beadable.)
> Earlier: Round-4 multi-agent panel integrated — 3 of 5 reviewers
> completed [installer, feasibility/DAG, security]; 2 [concurrency, protocol] restarted
> with disk-journaling after spend-limit resets. Added safety beads + 3 foundation
> nodes + N0a split + decisions D12/D13. All-in 0.6.0, no deferral). See §4-R + §11.
> GPT-Pro extended-reasoning review integrated — LaneRuntime,
> authenticated Subject, single-use grants, MCP lifecycle, browser-safe dashboard,
> per-client credentials, schema-first operator API, RC gates). One big release;
> supersedes & absorbs the 0.5.0 plan. **Skills used:** planning-workflow, installer-workmanship,
> release-preparations, changelog-md-workmanship, idea-wizard, research-software, beads-workflow,
> multi-model-triangulation, asupersync-mega-skill, deadlock-finder-and-fixer, mcp-server-design,
> agent-ergonomics-…-cli-tools, world-class-doctor-mode-for-cli-tools.
> **Review-complete** — GPT-Pro + a 5-lens code-verified panel + 2× Codex triangulation +
> asupersync 2-pass leverage + 4-skill hardening + the collaborative dashboard design are **all
> integrated** (full history in §11); `file:line` cites verified during research. **Next: convert
> to the `oraclemcp-060-epic` bead graph (idea-wizard Phase 5) — awaiting operator go-ahead.**

---

## 0. TL;DR

oraclemcp becomes **one guarded always-on service + one versioned, schema-first
protocol + many front-ends**, with a first-class **LaneRuntime** as the internal
security & concurrency boundary for HTTP/operator callers. Two access modes,
decoupled:

- **stdio — UNCHANGED.** Each agent spawns its own process → own connection, level,
  DB. Single-principal-per-process, already correct. **Not touched.**
- **http — UPGRADED to true per-lane concurrency.** One persistent service; each
  caller resolves to a **lane** (a `LaneContext` over a pinned lease) bound to a
  **verified Subject** (never caller-supplied), with its own DB/profile, operating
  level, single-use grant store, request budget, audit context, and cancellation
  state. Many agents + a human → **many databases at once**, isolated. The **web
  dashboard** is the human face; a future ftui TUI can attach the same way.

Pillars (one plan, beaded together; shipped as a **release train 0.6.0→0.6.1→0.6.2**, §D1 — no
deferral):
1. **Driver 0.5.1 (already pinned) — validation + close #2/#3/#4/#5** (routine OUT/IN-OUT,
   non-lossy serialization, timeout/hang hardening, doctor precision/soak).
2. **WP-N — per-principal HTTP LaneRuntime** (THE foundation): `LaneRuntime`/
   `LaneContext` over the dormant `LeaseManager`; per-lane connection/level/budget/
   audit/cancellation; **authenticated Subject**; **single-use lane-bound grants**;
   MCP-correct lifecycle; adaptive fail-closed capacity. **stdio untouched.**
3. **WP-P — one versioned, schema-first operator protocol** over the asupersync
   HTTP: MCP (`/mcp`) + `/operator/v1` (read-only stats/events/SSE + gated actions),
   generated schemas, event-replay, idempotency ledger.
4. **WP-S persistent service** + **WP-W web dashboard (the human face)** — thin
   clients of WP-P. (No TUI in 0.6.0; protocol keeps it addable later.)
5. **Broadest sensible installer** (one-liner `curl|bash`/`install.ps1`, **explicit
   `--service`/consent**, opt-in MCP-client registration with **per-client scoped
   credentials**, `npx`, binstall, brew, winget, Docker, completions, cosign+SHA
   +provenance).

**Throughline (non-negotiable):** every face goes through the **same fail-closed
core** (classifier → per-lane ceiling → preview/confirm → rollback-by-default →
audit). Identity is a **verified Subject** (dashboard login / OAuth sub / mTLS fp /
local pairing / OS user) — **never self-supplied in tool args**. Loopback hub
(dashboard still requires local pairing/auth); no foreign-config mutation; no raw
PTY/free-SQL terminal; secrets external; uncertain DB outcomes **poison/quarantine**
the connection.

**Version:** `0.4.x → ` a **release train `0.6.0 → 0.6.1 → 0.6.2`** — one plan, beaded together,
built in one continuous effort, shipped in increments (D1; resolves Codex's scope concern without
deferring anything). **No TUI (web-only)**; future TUI = ftui. **Web stack: React/Vite SPA**
(TanStack Router/Query/Table + shadcn/ui), built at build-time only, **embedded via `rust-embed`;
no runtime Node, no second daemon.**

---

## 1. Current state (verified ground truth)

### 1.1 Session/concurrency (verified in code — decisive)
**Single-principal-per-process today.** `OracleDispatcher` = `AsyncMutex<DispatcherState>`
with **one** pinned `conn`, one optional read conn, **one** `active_profile`, **one**
`SessionLevelState` (`dispatch/mod.rs:177-216`), built once (`main.rs:1011`), shared
via `Arc` across HTTP threads. Level/elevation/active-DB/confirm-tokens/grants are
**process-global**; tokens are HMAC over `(profile,level,sql)` with **no caller
identity** (`:1115-1130`) → **cross-redeemable**; `switch_profile` flips the DB for
the whole process. The dispatch runtime is a **single current-thread asupersync
runtime with deliberately non-`Send` dispatch futures** — fine for single-principal,
but WP-N must make an explicit runtime-topology decision (§N0a) or all lanes funnel
through one executor.
**Dormant primitives exist:** at this historical point the former
`crates/oraclemcp-db/src/lease.rs` `LeaseManager` (per-lease pinned session,
TTL, force-rollback) + former `crates/oraclemcp-core/src/session_tool.rs`
`oracle_session` tool existed — **unwired** (`oracle_session` not in the 52
registered tools; no `LeaseManager` in `main.rs`). Both files were later deleted
by B14b as dead subsystem code.
⚠️ `oracle_session` currently accepts `agent_identity` **as a tool argument** — this
must **not** become the HTTP trust source (§D11).

### 1.2 Carried facts
> **⚠️ GROUND-TRUTH REFRESH (Codex I1, 2026-06-30):** the repo has moved since this section was
> first written — `Cargo.toml` now pins **`oracledb = "=0.5.1"`** (the driver upgrade already
> landed) and the workspace version is **past 0.4.0** (≈0.4.1). **Re-verify the rest of §1.2
> against current code before beading** (the #4 timeout/fetch-loop state in `connect.rs`/the db
> layer may also have changed). The facts below are partially historical.
- 0.4.x shipped; 9-crate workspace, `#![forbid(unsafe_code)]`, pinned nightly
  (asupersync); pure-Rust thin driver; single seam `connection.rs`; **HTTP/SSE is
  asupersync — no tokio/axum/hyper** (boundary-linted). Beads: 0 open.
- **Driver is already pinned `oracledb = "=0.5.1"`** (the bake-in landed). **#5/WP-A is therefore
  re-scoped to *validation*** — doctor precision, wallet/auth diagnostics, timeout fixes, soak,
  live-XE — **not the version bump itself.** Confirm what's done vs remaining at beading.
- **The fail-closed guard already SHIPS (0.4.1)** in `crates/oraclemcp-guard` (classifier 104 KB,
  `OperatingLevel` ladder + `DangerLevel`, 3-valued `purity.rs` with a `SideEffectOracle` port for
  plsql-intelligence, `stepup.rs` confirm-token, `token.rs` single-use grants) — so **WP-N builds
  the per-lane LANE layer *over the existing guard*, not a new classifier.** Full refresh + all 6
  pre-bead gap resolutions in **§4-GT**.
- A 30s default call timeout exists in `connect.rs`, but plsql-mcp (using
  `oraclemcp-db` directly) gets `None`; fetch-loop + commit/rollback unbounded (#4).
- `OracleCell` has no structured carrier (#3).
- Driver 0.5.1 adds `QueryValue::TimestampTz`, typed auth-capability surface,
  `WalletError::UnsupportedFormat`, IAM/TCPS fixes, honored connect timeout;
  `EXPIRE_TIME` parsed-not-applied (upstream rust-oracledb #14 open).
- `ToolDescriptor` already supports an optional `outputSchema` (→ §A7b gate).
- Open issues: **#2** routine OUT/IN-OUT, **#3** non-lossy serialization, **#4**
  hang/timeout (bug), **#5** driver 0.5.1 upgrade.
- Release matrix 6 targets; unversioned asset names; cosign detached `.sig`/`.crt`;
  crates.io publishes in-workflow before the GitHub release; Docker amd64-only;
  `server.json` has version+identifier.
- **License (settled):** `deny.toml` already allow-lists the OpenAI/Anthropic rider
  via 5 scoped exceptions; ftui's license is the same rider, already accepted.
- **References studied:** `mcp_agent_mail_rust` (service/installer patterns) and
  `NousResearch/hermes-agent` (one-core-many-front-ends; React/Vite web control
  plane; loopback-default + single-use tickets). Adopt patterns; **avoid** their
  convenience-first anti-patterns (kill-port, mutate foreign configs, fail-open auth,
  embedded raw PTY).

---

## 2. Goals & non-goals

### Goals
- G1. **stdio unchanged** — per-agent process, own DB/level, isolated.
- G2. **http truly concurrent** — one service, per-principal lanes, many agents + a
  human → many DBs at once, isolated, gated, fairly admitted.
- G3. Reboot → service already running; agents/humans reconnect.
- G4. One copy-paste installer (binary + **explicit** service/registration); `npx`.
- G5. A **web dashboard** (human face): profiles (draft/apply), dashboards, health,
  audit (+DB evidence), schema, and a **gated Safe SQL Workbench**.
- G6. **#2/#3/#4/#5 closed**; driver 0.5.1 (already pinned) **validated**; doctor auth-honesty + TSTZ.
- G7. Stable-release bar: gates green (incl. output-schema validation), conformance
  100%, live-XE (incl. multi-lane), docs, CHANGELOG, rollback runbook. Beaded.

### Non-goals
- N1. Not 1.0. · N2. No new enterprise-auth *implementations* (Kerberos/RADIUS/
  external wallet stay typed-unsupported). · N3. No object/UDT typed-attribute decode
  beyond `(schema,type_name,bytes)`+typed-unsupported. · N4. No deferred-epic
  features (advisors/RAG/RBAC/rate-limiting/PII/async-query).
- N5. **Don't weaken the safety invariant** — extended **per lane**: per-lane
  level/ceiling, rollback-by-default, protected pinned READ_ONLY, scopes only lower,
  **single-use lane-bound grants**, **derived (not supplied) identity**, audit every
  privileged action.
- N6. **No "Total Auto."** No killing processes, no silent foreign-config mutation,
  no auto-minted shared/long-lived tokens; **service install & client registration
  require explicit `--service`/consent.**
- N7. **No silent serialized-shape change** — ships with an upgrade note + schemas.
- N8. Hub **loopback-default**; non-loopback needs `ORACLEMCP_HTTP_ALLOW_REMOTE=1` +
  auth; never `--allow-no-auth` on a network bind; **dashboard requires local
  pairing/auth even on loopback** (loopback ≠ a browser security boundary).
- N9. **No agent-facing arbitrary-PL/SQL tool**; **no raw PTY / SQLcl shell / free
  terminal** in the dashboard.
- N10. **Do not modify the stdio single-principal path** — WP-N is http-only.
- N11. **No TUI in 0.6.0** (web-only; ftui TUI deferred — idea bead).
- N12. **0.6.0 attach = loopback TCP only** (operator UDS deferred — idea bead).
- N13. **Self-repair is fail-closed too** — `om doctor --fix` **never touches Oracle, the audit
  hash-chain, the classifier, or a profile's `max_level`**; its write-scope is service-local
  state only, and out-of-scope ops refuse (exit 4). Audit chain = detect-only, never rewritten
  (DOC-3/DOC-5).

### Success criteria
- Two agents on two different DBs + a human dashboard query on a third — concurrent,
  isolated; no shared level/transaction/grant; each audited under its **verified
  Subject**; a caller passing a fake `agent_identity` cannot change its audit subject.
- A confirm/execute grant is single-use, lane-bound, and rejected across lanes or
  after profile/level change; a client retry with the same idempotency key returns
  the recorded outcome, not a second execution.
- A dropped SSE stream does **not** roll back a long-running call; an HTTP `DELETE`
  does terminate the lane. A malicious web page cannot trigger a dashboard gated
  action against `127.0.0.1`.
- stdio unchanged. At capacity → typed `AtCapacity`+`retry_after`; an agent flood
  cannot consume the reserved operator/doctor lane.

---

## 3. Key decisions

### D1. One **release train** — 0.6.0 → 0.6.1 → 0.6.2 — ONE plan, ONE continuous build, NO deferral
**Operator decision (2026-06-30, resolving Codex C5 "not buildable as one 0.6.0"):** ship in
**version increments**, but keep **everything in this single plan**, beaded **together up front**,
and **implemented in one continuous effort** — the increments are a *release cadence*, **not a
scope cut and not deferral**. Each `0.6.x` is a real public release that delivers shippable value
and earns real-world feedback before the next train departs. This honors "all-in, one go" while
answering the panel's + Codex's "this is 3–4 releases' worth."

**Train mapping (dependency-ordered; all beaded now):**
- **0.6.0 — Foundation (the safety core + a usable product):** WP-A (driver *validation*, §1.2),
  WP-B/WP-C/WP-R (#4/#3/#2), **WP-N (lane foundation)**, WP-P (protocol), WP-S (service), WP-E/WP-F
  (installer/distribution), WP-G core + **`om doctor`**, WP-H. **Dashboard = the read-only control
  plane** (Overview · Sessions · Audit · Doctor; **2D first**, skinnable seam in place). This is
  the "buildable" core Codex asked for, and a real shippable always-on guarded MCP + control room.
- **0.6.1 — Interactive dashboard:** the full views + the **governed Workbench** (Safe SQL,
  governed edit loop, live compile, schema browser, global search) + **plsql-intelligence** wiring
  + version history.
- **0.6.2 — Advanced / wow:** the **Change-Review board ("PR for PL/SQL")** + the **3D Orrery**
  skin (Framer+GSAP) + migration export + the heavier signature features.

**Invariants across the train:** **no dashboard/write feature may weaken or delay the lane-safety
foundation**; the fail-closed core ships whole in 0.6.0; later trains are *additive faces* on the
same guarded core + protocol (D2/D6). The Safe SQL Workbench (W8, 0.6.1) ships only if its
no-bypass gates pass, else stays flag-gated and unadvertised. (Within a train, the old alpha/rc
gating still applies as internal milestones.)

### D2. One service + one versioned, schema-first protocol + many front-ends
The service owns the guarded core; **WP-P** is the stable, **schema-described**
contract (MCP `/mcp` + `/operator/v1`); every front-end is a thin client. Decouples
& future-proofs; the SPA consumes generated types, not Rust internals.

### D3. Human interface = web dashboard primary (React/Vite SPA), no TUI in 0.6.0
React + Vite + TanStack Router/Query/Table + shadcn/ui (Radix) + Tailwind + CodeMirror
(workbench) + a charting lib. **Node is build-time only** → static bundle embedded via
`rust-embed`, served by our asupersync HTTP (static + SSE + POST). **No runtime Node /
no second daemon.** JS deps audited via `npm audit` + lockfile/SBOM alongside
`cargo deny`. ftui TUI deferred.

### D4. stdio untouched; http upgraded to per-principal **lanes** (WP-N) — foundation
Introduce a **`LaneRuntime`/`LaneContext`** layer over the dormant `LeaseManager`
(the lease is the *physical session*; the lane is the *security & concurrency
boundary*). Keyed per `MCP-Session-Id` + **verified Subject**. `LeaseManager` is
reached only through `LaneRuntime`, never from transport code. stdio stays
single-principal-per-process. **Why:** Oracle state is per-session; sharing a session
across principals leaks level/DB/grants and tangles transactions.

### D5. Multi-tenant rule: share only what's safe; isolate the rest; scope observability
Stateless **reads** + **local** observability (service metrics, lane counts,
audit-tail, pool state) are safe to multiplex. **Database-native** observability
(`v$session`, role/open-mode, standby/write-posture beyond the current lane) runs via
the lane's own session (self-observation) or an explicitly configured least-privilege
**`monitor_profile`**; otherwise the UI shows `monitoring_unavailable` rather than
broadening privileges or leaking metadata. Everything stateful (level, elevation,
transactions, temp/output, grants, target DB) is **per-lane**.

### D6. Same fail-closed core for every face
The dashboard's Safe SQL Workbench routes through the **identical** classifier →
per-lane ceiling → preview/confirm → rollback → audit path agents use. No
second/weaker path; **no raw PTY / terminal**.

### D7. #4/#3/#2/#5 (carried, verified)
#4: shared-layer default timeout + total request budget + bound fetch-loop (per-batch)
+ bound ROLLBACK (COMMIT in-doubt) + **poison/quarantine** on any uncertain outcome.
#3: `OracleCell.structured` carrier; typed ARRAY/JSON/VECTOR/TSTZ; typed-unsupported
everywhere; published schema+goldens. #2: `OracleRoutineArg` (non-`Deserialize`) +
adapter-internal `call_routine`; no agent tool. #5: pin `=0.5.1`, close after
doctor/soak/live-XE.

### D8. Installer = dicklesworthstone model, safety-adapted, **explicit-consent**
`install.sh`/`install.ps1` (prebuilt musl, SHA256-terminal + cosign verify-blob
**+verify-attestation**, completions, **service install only with `--service` or
interactive consent + `/readyz` health-gate**, dry-run prints every file/unit it would
touch) + npx + binstall + brew + winget + Docker + MCP registry. Improvements over the
reference: `enable-linger`, completions, binstall, brew, winget, npx, **per-client
scoped credentials** (not a shared bearer), provenance verification.

### D9. Persistence via OS service manager (not self-daemonizing)
`systemd --user` + **`loginctl enable-linger`** / launchd / Windows service;
`sd_notify(READY=1)` → `/readyz`; single-instance guard; **no silent takeover**.

### D10. Loopback-default, but **dashboard-auth always** + browser hardening
Loopback default; network auth mandatory on non-loopback; **the browser dashboard
requires local pairing/auth even on loopback** (loopback protects the network, not the
browser origin). `om dashboard` opens a one-time local ticket URL / short pairing
code; browser gets an **HttpOnly, SameSite=Strict** session cookie. **No bearer token
in localStorage or URLs.** All dashboard POSTs require **Origin/Host validation +
CSRF token + scoped action ticket**; CSP, `frame-ancestors 'none'`, nosniff,
referrer-policy. Secrets stay external refs.

### D11. Authenticated **Subject** is the root of audit, capacity, and token binding
`Subject { kind, stable_id, display_name, authn_method, client_id,
token_thumbprint_or_cert_fingerprint }` is created **once per authenticated
request/session** from verified transport/auth context and copied into the lane.
Display labels are display-only; **authorization, audit, grants, fairness, and
`v$session` tagging use the stable subject id**. Any caller-supplied `agent_identity`/
`operator_name`/label is **ignored** for security decisions. **No-auth case:** with
loopback `--allow-no-auth` (no verifiable Subject) the service runs **single-lane /
single anonymous local subject**; multi-principal lanes **require** auth (OAuth / mTLS
/ local pairing), and multi-lane on an unauthenticated bind is **refused** (fail-closed).

### D12. Service panic profile = `unwind` + per-lane `catch_unwind` (reverses 0.4.0 abort)
The always-on daemon builds with `panic = "unwind"`; each lane's dispatch is wrapped in a
`catch_unwind` isolation boundary so a panic in one lane is contained to **that lane only**
and never aborts the 51-lane process. **Codex correction (CX-2): do NOT promise rollback
after a panic** — the contract is **mark the lane poisoned, revoke its grants, drop/
quarantine its connection, audit `unknown_discarded`** (async rollback from a panicked
state is not a reliable invariant; let server-side PMON reclaim). This reverses the 0.4.0
`panic = "abort"` (DoS-hardening), which is unacceptable for a multi-lane daemon (abort
runs no `Drop`, leaks sessions, defeats N5/B1c). N9 test: a lane panic doesn't abort
siblings; the lane is quarantined + audited. **[Applied.]**

### D13. Dashboard = two cargo features — `dashboard-api` (Rust-only) + `dashboard-bundle` (SPA, NOT default)
**Codex refinement (CX-3) — replaces "default-on":** split the operator/dashboard **API**
(`dashboard-api`, pure Rust — may be default) from the **embedded SPA bundle**
(`dashboard-bundle`, which pulls the rust-embed'd Vite build — **NOT default**). So
**source builds / `cargo install` are Node-free and bundle-free by default**; prebuilt
release binaries + Docker enable `dashboard-bundle` (built via the `web-build` job, E0).
Keeps crates.io clean (no committed `dist`/10-MiB/dirty-tree) without a "default-on needs
the bundle" trap. **[Applied — Codex's better alternative.]**

**Resolution (operator, 2026-06-30) — the features are build-time hygiene only; the end user
never sees them.** The lived experience is: an agent sets up the MCP, the service runs
persistently (D9), and the user just **opens the dashboard** (`om dashboard` → one-time local
pairing URL, D10). To guarantee that:
1. **Product artifacts always ship the full dashboard.** The installer, GitHub release binaries,
   and Docker image are built by the `web-build` job (E0) with **`dashboard-bundle` on** — so
   "start the dashboard" always just works for anyone who installs the product. The feature
   split only changes `cargo install`/source builds (Node-free, bundle-free).
2. **`dashboard-api` default-on but inert.** It compiles + is exercised by tests in the default
   build, but is **served/bound only when configured** (D10 loopback + pairing + auth) — so a
   default or source build carries **no live dashboard surface unless explicitly enabled**. The
   default no longer carries correctness weight (see #3), so this is purely "what's the cleanest
   default," not a risk decision.
3. **"Everything always tested" — feature-powerset CI (the real requirement).** CI builds +
   `clippy -D warnings` + tests the **full curated feature powerset** every PR — `{none ·
   dashboard-api · dashboard-bundle(⇒dashboard-api)}` × the `dashboard_workbench` flag (W8) —
   via `cargo hack --feature-powerset` (curated to skip nonsensical combos). This catches the
   classic feature-flag rot (code that only compiles with a feature on, or breaks with it off)
   before tag. It **joins the unified release-acceptance CI suite** (DL-9 `concurrency-audit` +
   ERG-10 ergonomics drift-guard + DOC-10 doctor fixtures + §4-R `web-build`). **[Applied —
   resolves CX-3's "may be default"; bead → WP-G/WP-H/CI.]**

### D14. Persistence = files-first, pure-Rust-only; never bundle SQLite
State lives in **append-only / content-addressed files** (audit chain, doctor artifacts, DDL
source snapshots, **+ durable metric-history files**), **TOML config** (W2 atomic), and
**in-memory** ephemeral state (grants, idempotency, **live metrics ring**) with the audit chain
as the durable record. (Metrics = a live in-memory ring **plus** append-only per-day history
files — FORK-2/§4-WD.4; never a TSDB/DB.) Structured/mutable/queryable
state (Change Proposals, version-history index) is **files + manifest** for 0.6.0; if it ever
outgrows files, adopt the **pure-Rust** `redb` — **never `rusqlite`/SQLite** (links libsqlite3
C + needs a C toolchain + `unsafe` FFI → violates AGENTS.md's pure-Rust/no-C-toolchain property
and `#![forbid(unsafe_code)]`). Full tiered model + on-disk layout in **§4-WD.4**.

### D15. Design for cheap change — correct patterns from the start (ENFORCED, not aspirational)
A first-class goal: **later extensions, changes, improvements, and refactors must be cheap.**
Encoded in every bead's Definition-of-Done + CI, not left to vibes. Concrete, enforceable rules:
1. **Dependencies point inward (clean architecture).** Domain core (classifier, operating-level
   ladder, audit model, Subject) depends on nothing transport/frontend/storage-specific; adapters
   (db, http, dashboard, persistence) depend on core, never the reverse. Enforced by a
   crate-graph/architecture-fitness lint in the release-acceptance CI.
2. **Trait seams exactly where change is expected (open/closed; YAGNI elsewhere).** Storage
   backend (D14 files→redb), transport (stdio/http/future), classifier rules, doctor
   detectors/fixers, Workbench object-type handlers (tables/views/packages/…), protocol consumers
   — each behind a trait so a new variant = implement + register, **zero caller edits**. No
   speculative abstraction outside these known change axes.
3. **One core, one protocol, many faces (D2 reinforced).** No frontend-specific business logic;
   dashboard/CLI/MCP differ only in presentation.
4. **Schema-first additive evolution (P1/MCP-14).** `contract_version`; add fields/tools without
   breaking; never repurpose a field.
5. **Pure domain + single-owner state** (asupersync actor/GenServer; classifier pure/`cap::None`)
   — localizes change; refactors stay local.
6. **Tests pin contracts so internals are free to move.** The conformance/metamorphic/golden/lab
   suites are the refactor safety net; every public contract ships a pinned test — this is *what
   makes change cheap* (rewrite internals behind a green contract).
7. **No compat shims, no `v2` clones (AGENTS.md).** Migrate callers + delete old code; cruft is
   what makes future change expensive.
8. **Small, single-responsibility crates/modules**; high bar for new files; clear boundaries.

**Lands in beads:** every implementation bead's DoD names the applicable rule (e.g. "new object
handler implements `ObjectHandler`, no dispatch edits"; "storage via the `Store` trait, not raw
fs"; "public output has a pinned schema test"). An **architecture-fitness lint** (dep-direction)
joins the release-acceptance CI suite (DL-9 + ERG-10 + DOC-10 + §4-R web-build + feature-powerset).

### D16. The dashboard presentation layer is skinnable (view-model / skin / theme / renderer)
The visual identity is a declared D15 change-axis. The dashboard separates a **stable semantic
view-model** (from the protocol/resources, D2) from a **swappable presentation skin**. Two
extension axes: **themes** (cheap — token swaps: clearance palette, fonts, textures, motion;
light/dark/colorblind/high-contrast/reduced-motion) and **skins/renderers** (rarer — swap the
*representation* of hero surfaces: Orrery-3D ↔ 2D-board ↔ table). The visual **grammar**
(position=structure, color=clearance, motion=activity, GO/NO-GO, the ladder) is a **contract
invariant** across all skins — comprehension never depends on the skin. Built-in, build-time,
code-split skins for 0.6.0; runtime/third-party skins deferred (YAGNI + a CSS/sandbox security
review). Justified by present needs (the mandatory a11y/no-WebGL fallback = a 2nd renderer today;
light/dark/colorblind = multiple themes today), so the seam is built at 2+ real cases, not
speculatively. Full architecture in **§4-WD.8**.

### D17. Operator authority = a config allow-list above the Subject (never self-claimed)
"Operator" is an **authority capability above a regular authenticated Subject** (D11) — needed for
fleet-wide view, force-actions on other lanes (R3b), bind **reveal** (FORK-1), CP approve/apply +
4-eyes, `om doctor --fix`, and config/cred management. **Sources (never a tool arg):** the loopback
OS-user / local-pairing owner (single-operator default) **or** an explicit operator allow-list
(verified Subject stable-ids / OAuth subs / mTLS fps) in config. **Binary in 0.6.0** (operator vs
scoped principal); fine-grained operator-RBAC is a deferred non-goal (N4). Every operator action is
audited under the Subject; a scoped principal can never escalate to operator. Detail: §4-GT.4.

### D18. Oracle secrets are external references resolved at connect — never persisted/rendered
Oracle DB credentials (passwords, wallet dirs, key files, IAM/TCPS material) live as **external
references** in the profile config — an **env-var name**, a **file path**, or an **OS-keyring**
entry — resolved at connect via a pluggable **`SecretResolver` seam** (D15; future vault/OCI-secrets
plug in). The raw secret never enters the config file, **audit chain, logs, telemetry, protocol, or
UI** (N-S6 redaction newtypes enforce it). Per-client HTTP-access creds (E4/W10) are hashed-at-rest,
shown-once; the dashboard manages lifecycle/metadata, never renders secret material (FORK-3).
Detail: §4-GT.5.

---

## 4. Work packages & tasks

Epic `oraclemcp-060-epic`; priorities 0–4. Seam: A2/B*/C0-C1/R1-R2 edit `connection.rs`
— sequence them.

### WP-A — Driver 0.5.1 validation (#5; pin already landed) + completions
A0 `completions` subcommand · A1 **pin `=0.5.1` already landed** (verify lock + seam still green;
the remaining #5 work is the wiring + validation below — **close #5** only after doctor/soak/
live-XE pass) · A2 TimestampTz wiring · A3 typed auth → doctor
(redaction-safe + telemetry test) · A4 wallet-format diag · A5 IAM re-eval · A6
connect-timeout pass-through (config-field vs example_config_parses) · A7 re-baseline
api-lock + contract suite + gates **after C0-C3,R1-R2,N\*** (last surface step) · **A7b
require `outputSchema` for every changed public MCP tool + every operator route/event;
CI validates `structuredContent` against schema** · A8 ship **`om`** alias (argv0-aware;
`om dashboard` opens the browser; installed by the installer).

### WP-B — Timeout hardening + poison/quarantine (#4)
B1 shared-layer default timeout + **total wall-clock request budget** + bound ROLLBACK
(COMMIT in-doubt) + doctor warn on `=0` · B1b per-batch fetch-loop timeout (single wrap
at `collect_all_rows`) · **B1c poison/quarantine contract**: any timeout / network
error / cancellation deadline / rollback failure / CLOSE-WAIT / unknown-COMMIT marks
the lane connection **poisoned** → dropped, never pooled, **open grants revoked**,
audit records the outcome class (`rolled_back` | `discarded_uncommitted` |
`commit_in_doubt` | `unknown_discarded`) · B2 verify dirty-discard + no poisoned reuse
· B3 track upstream #14 · B4 close #4.

### WP-C — Non-lossy serialization (#3)
C0 `OracleCell.structured` carrier (+contract) · C1 typed ARRAY/JSON/VECTOR/TSTZ · C2
object identity + typed-unsupported everywhere · C3 capped non-default catalog mode ·
C4 close #3 (+upgrade note) · **C4b publish the `OracleCell.structured` JSON schema +
golden fixtures** (ARRAY/JSON/VECTOR/TSTZ/object/unsupported) · **C5 serialization
contract-version tag** consumed by dashboard/schema caches.

### WP-R — Routine execution (#2)
R1 non-`Deserialize` `OracleRoutineArg` · R2 adapter-internal `call_routine`
(deterministic order, COMMIT caveat) · R3 grep-lint: `call_routine` absent from
`oraclemcp` AND `oraclemcp-core` · R4 close #2.

### WP-N — Per-principal HTTP **LaneRuntime**  *(FOUNDATION — highest priority/review)*
*Many principals served concurrently, each in its own isolated lane; stdio untouched.*
- **N8. Interim guard.** (p0) Until N0a-N3 land, the http server runs single-principal
  **or fails closed** on a second concurrent principal — never silently shares
  level/DB/grants. (Closes the latent hole now.)
- **N0a. Introduce `LaneRuntime`/`LaneContext` before exposing multi-lane HTTP.** (p0, N8)
  - Acceptance: no HTTP/operator stateful dispatch receives the process-global
    `DispatcherState`; every stateful request resolves to a `LaneContext` owning lane
    id, **verified Subject**, MCP-session id, profile, DB fingerprint, level state,
    grant store, request budget, cancellation, audit context, export/event
    correlation. Each lane serializes **only its own** stateful ops while others
    progress. **Runtime topology = thread-per-lane (DECIDED):** each lane runs on its
    own OS thread with its own current-thread asupersync runtime + reactor + Oracle
    connection (the proven load/soak pattern — so the non-`Send` dispatch futures are a
    non-issue); the lane/thread budget = the N4 capacity cap; **reads go through a bounded
    set of read-worker lanes (each its own reactor+conn) / per-reactor shards — NOT a
    single cross-reactor `OraclePool`, which is reactor-affine and cannot be shared
    (Codex CX-1)**. Never one global dispatch bottleneck. Test: two blocked lanes don't
    block a third. `LeaseManager` reached only via `LaneRuntime`.
- **N0. Wire the lease layer behind `LaneRuntime`.** (p0, N0a) Each MCP session +
  Subject → distinct `LaneContext` + distinct lease; transport never touches
  `LeaseManager` directly. **stdio path unchanged.**
- **N1. Per-lane connection + per-lane database/profile.** (p0, N0) Each lane owns its
  conn to the **profile it selected**; two lanes → two DBs concurrently;
  `switch_profile` affects **only the calling lane**; service may hold many DBs at once
  (pooled per profile, bounded).
- **N2. Per-lane operating level + elevation.** (p0, N0) `SessionLevelState` per-lane;
  A's elevation never affects B; OAuth scope narrows only the calling lane.
- **N3. Single-use, lane-bound **grant store** (confirm/approved-execute/cursors).** (p0, N0a)
  - Acceptance: preview/confirm creates a **server-side grant** with `grant_id`,
    `lane_id`, verified `subject_id`, `MCP-Session-Id`, `profile_id`,
    `profile_revision`, DB fingerprint, **level generation**, SQL SHA-256,
    classifier-result digest, issued/expiry, and action (`commit_dml`|`execute_ddl`|
    `page_cursor`|…). The returned token is only an opaque signed reference. **Execute
    consumes the grant exactly once**; a retry with the same idempotency key returns
    the recorded outcome; a second fresh execution → `GrantAlreadyConsumed`. A grant
    minted by A is rejected for B, after `switch_profile`, or after level/profile
    generation change. The grant store + P1c idempotency ledger are
    **in-memory/process-local**; the **audit hash-chain is the durable record** (a
    grant lost on restart simply forces re-preview — safe).
- **N4. Adaptive bounded capacity + fairness + fail-closed + operator reserve.** (p1, N1)
  - Acceptance: **two-tier caps** — per-profile **read pool** + **stateful/write
    lanes**, plus a **global host ceiling**. Configured ceilings default **16 read / 8
    stateful per profile / 64 global** (operator's choice) and are treated as **upper
    bounds**; startup/`doctor` compute *effective* caps = min(configured, DB per-user/
    session limit, fd limit, memory budget). **Reserve ≥1 operator + ≥1 doctor lane.**
    Acquire a permit **before** opening a physical connection. At capacity → brief
    wait then typed **`AtCapacity`** with `retry_after_ms` + redacted capacity
    snapshot — **never unbounded sessions**. Fairness = per-subject queues + global
    weighted fairness; idle reaping. DRCP + proxy-auth for scale.
- **N5. Lane lifecycle + MCP Streamable-HTTP semantics.** (p1, N1)
  - Acceptance: distinguish **response-stream disconnect** (does NOT cancel — the call
    continues until completion / explicit `CancelledNotification` / budget expiry),
    **explicit cancellation**, **HTTP `DELETE` `MCP-Session-Id`** (terminate lane:
    rollback if dirty, revoke grants, release/discard conn), **idle TTL**, **service
    shutdown** (bounded drain). Dropped SSE can reconnect/resume or get a typed expired
    result. Failed/cancelled/uncertain → quarantine the conn (B1c), never reuse.
- **N6. Stop serializing reads on a global lock.** (p1, N0a) Stateless reads run
  concurrently via the pool; stateful work serializes only within its lane.
- **N7. Per-Subject audit identity + DB evidence.** (p1, N0, audit)
  - Acceptance: every action records its **verified Subject** (no generic
    `HumanOperator`); **no caller-supplied identity** can change it. Live DB records
    also capture redacted DB fingerprint (`db_unique_name`/service/instance), Oracle
    username/proxy user, and session evidence (`sid`,`serial#`,`client_identifier`,
    `module`,`action`) when visible; absence → `db_evidence_unavailable`, not a failure.
- **N9. Concurrency/session test contract — SET IN STONE.** (p0, deps N0a-N7)
  - *Each invariant = a named test with structured logging (lane/subject/SID/profile/
    level/grant/outcome). Extend `tests/{chaos,load_soak,cancel_correctness,
    live_oracle,trust_safety}.rs`; add `tests/lane_state_machine.rs` (deterministic
    model/fault-injection — no Oracle), `tests/concurrency_contract.rs` (mock), and
    `tests/multi_lane_live_xe.rs` (real 23ai, two DBs). Changing any invariant needs a
    plan change + review.*
  - **A. Lane isolation:** A1 distinct lanes+SIDs · A2 level never leaks (A elevates →
    B refused) · A3 elevation TTL independent · **A4 grant non-replay** (A's grant
    rejected for B; consumed grant rejected/idempotent on re-present) · A5 transaction
    isolation · **A6 profile/level-generation binding** (grant minted before
    switch/ceiling-change/expiry is rejected after).
  - **B. Different DBs:** B1 A→X & B→Y concurrent, correct DB each · B2 `switch_profile`
    affects only A · B3 per-lane ceiling (protected/standby stays READ_ONLY while B
    elevated).
  - **C. Same DB (contention):** C1 readers no head-of-line · C2 same-row write waits →
    succeeds or typed `CallTimeout`, **never hangs**; timed-out lane poisoned/discarded
    · C3 different-row writes concurrent · C4 deadlock → typed ORA-00060 per lane · C5
    reader MVCC snapshot stable under a concurrent writer.
  - **D. Capacity/fairness:** D1 at cap → typed `AtCapacity`, never unbounded · D2
    acquire-timeout typed · D3 caps honored · D4 soak/no-starvation · **D5 agent flood
    can't consume the reserved operator/doctor lane** · **D6 effective caps =
    min(configured, DB/host budget), surfaced by doctor/dashboard**.
  - **E. Lifecycle:** E1 `DELETE` mid-txn → rollback+release/discard (a plain stream
    disconnect is NOT a DELETE) · E2 idle TTL reap · E3 cancelled/failed → dirty-discard
    · E4 stateful op w/o lane → typed `LeaseRequired` · **E5 explicit cancel interrupts;
    if clean cancel unproven by deadline, quarantine & never reuse**.
  - **F. stdio decoupling:** F1 stdio behaves exactly as 0.4.0 (golden) · F2 http + stdio
    coexist, no interference.
  - **G. Audit under concurrency:** G1 per-Subject records, chain verifies · G2
    concurrent appends → valid non-corrupted chain · G3 `v$session` per-caller (where
    monitor/proxy) · **G4 audit records carry `request_id`+`idempotency_key_hash`; a
    client retry doesn't create a second execution record**.
  - **H. Headline e2e:** H1 Codex(X,write)+Claude(Y,read)+human-dashboard(Z,gated)
    concurrent → independent levels/txns/DBs, per-Subject audit, no grant leak, no
    head-of-line · H2 ≥50 mixed lanes/multi-DB under caps; p50/p95/p99; no leak/starve.
  - **I. Interim guard (N8):** I1 a second concurrent principal pre-lane either
    single-principal or fails closed — never silently shares.
  - **J. MCP Streamable-HTTP compliance:** J1 stateful requests missing `MCP-Session-Id`
    → typed 400 · J2 unsupported `MCP-Protocol-Version` → typed 400 · J3 SSE event ids
    unique; `Last-Event-ID` never replays another stream/lane · J4 `DELETE` drains only
    the targeted lane.
  - **K. Lane state-machine (deterministic, no Oracle):** K1 every capacity permit
    released exactly once across success/error/cancel/timeout/DELETE/reaper · K2
    profile switch increments lane generation, invalidates stale grants · K3 elevation
    expiry can't race execute past the ceiling · K4 shutdown drains in bounded time,
    audit uncorrupted · K5 no transition yields a lane mixing Subject A's conn/grants/
    audit with Subject B.

### WP-P — Operator protocol (versioned, schema-first)
- **P1. Define + version `/mcp` + `/operator/v1`.** (p1, WP-N)
  - Acceptance: (a) **MCP** for agents (per-lane); honors `MCP-Protocol-Version`
    (unsupported → typed 400). (b) **read-only operator channel** — metrics/health/
    audit-tail/active-lanes + **optional** `v$session` summary (redacted, privilege-
    scoped, `source = self_lane|monitor_profile|unavailable`) via **SSE** + REST under
    `/operator/v1`. (c) **gated-action** routes (preview/confirm/execute, set-level,
    switch-profile) mapping to the same per-lane guarded dispatch. Carries a protocol
    version **and a generated machine-readable schema bundle** (`operator.schema.json`
    + route/event schemas); every event has `event_seq`,`event_id`,`lane_id`,
    `subject_id_hash`,`redaction_level`,`schema_version`. The SPA imports generated TS
    types; **CI validates captured UI fixtures against the Rust schema.**
- **P1b. Event replay/resume.** (p1, P1) `/operator/v1/events` supports
  `Last-Event-ID`/cursor resume within a bounded ring buffer; never replays another
  subject/lane; payloads stay redacted.
- **P1c. Idempotency ledger for gated actions.** (p0, P1, N3) preview/confirm/execute/
  commit/rollback/set-level/switch-profile take or derive an idempotency key; ledger
  stores request id, lane, subject, grant, SQL hash, audit seq, timestamps, outcome.
  Same key → original result or typed in-progress; a different key can't reuse a
  consumed grant.
- **P2. (DEFERRED idea bead — NOT active in 0.6.0)** Local operator **Unix-domain
  socket** for a future native client. No 0.6.0 consumer (browser=TCP, stdio=pipes,
  TUI deferred) → **0.6.0 ships loopback-TCP-only**; keep the operator transport
  abstracted so a UDS drops in later.

### WP-S — Persistent always-on service
S1 `service install|uninstall|status|logs|restart` (systemd --user + **enable-linger**
/ launchd / Windows) · S2 `sd_notify(READY=1)`+`/readyz` · S3 single-instance guard +
discovery (no silent takeover) · S4 `mimalloc` + gated background workers + documented
lock hierarchy · **S5 safe config reload**: a reload doesn't drop active lanes unless a
profile changed incompatibly; removed/changed profiles **drain** (no new lanes,
existing expire or are explicitly terminated). (deps: WP-N)

### WP-W — Web dashboard (PRIMARY human front-end)
- **W0. Scaffold the SPA + embed pipeline** (D3): React+Vite+TanStack(Router/Query/
  Table)+shadcn+Tailwind (client SPA, **no TanStack Start/SSR**); CI build → static
  bundle; **`rust-embed` + serve over asupersync HTTP**; `npm audit`+lockfile/SBOM;
  `--skip-build` uses the embedded bundle. (p1, P1)
- **W1. Shell + browser-safe auth** (per D10): local pairing/auth even on loopback;
  HttpOnly/SameSite cookie; CSRF + Origin/Host on every POST; CSP/frame-ancestors/
  nosniff/referrer headers; **no token in localStorage**; screen registry, palette,
  themes. Acceptance: a malicious web page **cannot** trigger a gated action against
  `127.0.0.1` (CSRF/Origin/cookie/clickjacking tests pass). (p1, W0, P1)
- **W2. Profiles + config draft/apply workflow** (sanitized; `env:`/`vault:` refs; no
  literal secrets on protected profiles; **no secrets shown/stored**). The dashboard
  **never edits the live file in place**: stage a draft → validate with the real strict
  config loader + redaction tests → optional `doctor --profile` → redacted diff →
  **atomic-rename write with timestamped backup** → ask the service to reload (S5) →
  rollback restores+revalidates. `setup --write` shares this backend. (p1, W1)
- **W3. Dashboards** (tool/latency/error/blocked metrics, **active lanes**, live event
  log via SSE). (p1, W1, P1)
- **W4. Connection health** (pool/latency/role/open-mode/standby/write-posture) — DB
  status via lane self-check or `monitor_profile`; missing privilege = visible degraded
  state, not an error loop. (p1)
- **W5. Audit timeline** (hash-chain + verify; filter by subject/level/tool; **DB
  evidence columns + proof-bundle export** when available). (p1)
- **W6. Operating-level control** (per-lane preview→elevate→drop, TTL, confirm). (p1)
- **W7. Schema/object explorer + bounded metadata cache** — cache keyed by DB
  fingerprint + profile/user + visible schema + serialization-contract version (C5);
  TTL+byte caps; DDL/commit invalidates affected objects; profile switch invalidates
  the lane view; **never caches result rows/secrets; a hidden profile's metadata is
  never shared with an exposed one.** (p2)
- **W8. Safe SQL Workbench (opt-in, gated; NOT a terminal)** — four explicit modes:
  `classify_only`, `read_query`, `dml_preview_confirm`, `ddl_plan_confirm`; all through
  the same classifier → per-lane ceiling → preview/confirm → rollback/commit → audit.
  Read-only default. **DDL disabled unless the profile sets `dashboard_ddl_workbench =
  true`** with a matching ceiling. UI shows required level, profile ceiling, DB
  fingerprint, lane id, audit subject, row/byte caps, preview impact, and **"why
  blocked" + safe alternatives**. **No raw PTY / SQLcl shell / arbitrary PL/SQL.**
  No-bypass safety tests. **Release-gated behind `dashboard_workbench`** until no-bypass
  + audit/idempotency tests pass. (p1, W1, P1, WP-B, WP-C)
- **W8b. Proof bundle** for gated actions (redacted: audit seq/hash, SQL hash,
  classifier decision, subject, lane, DB fingerprint, session tags/SID when available,
  outcome; no bind values/secrets). (p2, W8, W5)
- **W9. Optional read-only browser mirror** of health/stats. (p3)
- **W10. Client-credentials screen** — list registered MCP clients (scopes, created/
  last-used, last source address); **revoke/rotate one without affecting others**; no
  token value shown after creation. (p2)

### WP-E — Installer (broad, explicit-consent)
E1 matrix +aarch64-musl (cross toolchain; static-verify musl only) · E2 `install.sh`
(prebuilt, SHA256-terminal + cosign verify-blob **+verify-attestation**, completions,
**service install only with `--service`/consent + health-gate**, Rosetta detect, source
opt-in, **dry-run prints every file/unit touched**) · E3 `install.ps1` (certutil
checksum) · E4 opt-in MCP-client auto-registration — **unique client id + scoped bearer
per client** (`claude mcp add --transport http`, verified paths,
stdio-only-never-allow-no-auth, no secrets, revocation metadata, rotation command) · E5
`setup --write` (shares W2 backend) · E6 uninstall + `--offline` · E7 CI lint+smoke
(install **built** artifact via `--offline`; no service/client mutation without flag) ·
E8 host one-liner (`| bash`), README install-first.

### WP-F — Distribution channels
F1 cargo-binstall metadata · **F2 npx wrapper** — npm package **`oraclemcp`** (fallback
`@muhdur/oraclemcp`); downloads the binary **after verifying platform SHA256/signature**,
runs stdio; **no npm `postinstall` service/client mutation** · **F3 Homebrew tap +
winget manifest** (Scoop dropped) · F4 verify tag-workflow Docker (amd64-only) +
MCP-registry at 0.6.0.

### WP-G — Hardening & docs
G1 README (one-liner + service + dashboard first) · G2 CHANGELOG `[0.6.0]` + upgrade
note · G3 docs sweep incl. **threat-model** (per-lane isolation; Subject-not-supplied;
loopback hub + browser-origin risks; no-PTY workbench; installer trust;
SHA256=transport-not-authenticity) + SECURITY.md + config + TOOLCHAIN + example.toml +
license-year · G4 conformance 100% + golden rebless · G5 perf re-measure · G6 **live-XE
incl. multi-lane** (two agents/two DBs + human workbench) + service + attach e2e · G7
reconcile deferred-epic ledger · G8 doctor polish · **G9 `audit verify
--with-db-evidence`** (correlate audit seqs with Oracle session tags via monitor
profile/self-lane; degraded report when no privilege).

### WP-H — Release cut (operator + live gated)
H1 bump 0.4.0→0.6.0 (manifests+pins+server.json version+identifier+installer fallback+
GHCR+lock; preflight extended) · H2 full gates + no-git/path-deps + **output-schema
validation** + installer CI + live-XE + server.json schema-validate · H3 tag `v0.6.0`
→ release.yml (crates.io→GitHub→GHCR→registry) · H4 verify crates.io · H5 clean-machine
e2e (reboot→service→dashboard→two agents/two DBs) · H6 post-release fresh-eyes + close
epic + memory · H7 rollback runbook (yank + **mark v0.6.0 Release prerelease/delete** +
GHCR `:latest` + server.json).

---

## 4-R. Round-4 panel hardening (NEW beads — assign to the noted WP at beading)

*From the multi-agent panel (installer, feasibility/DAG, security; all code-verified).
These are mostly best-engineering additions — the architecture is sound but v3 was
incomplete on safety + infrastructure. CRITICAL items break the invariant as-was.*

### Safety beads (→ WP-N / driver tier)
- **N-S1 (CRITICAL) Retire the legacy deterministic confirm-MAC.** Remove
  `confirmation_mac`/`verify_commit_confirmation` (HMAC over `(profile,level,sql)`, no
  caller/lane/nonce, `dispatch/mod.rs:1085-1130`); the single-use server-side grant (N3)
  becomes the **only** confirm path. Else any lane recomputes another lane's token (N9-A4
  passes while a forgeable cross-lane channel survives). Test: cross-lane recompute rejected.
- **N-S2 (CRITICAL) Audit ALL committing tools.** Thread `AuditCtx` into
  `oracle_compile_object` (`:2305-2429`) + `oracle_patch_source` (`:2989-3174`) and run
  the classifier in compile; **DoD test: every committing tool appends an audit record.**
  Else "audit = durable record" (N3) is false and W5/W8b/G9 are empty.
- **N-S3 Gate monitor/`v$session`/db-evidence SQL.** Route `oracle_top_queries`/
  `db_health`/`sample_rows`/dictionary reads + the new operator `v$session`/W4/G9/
  `monitor_profile` through a read-classified gate + `SET TRANSACTION READ ONLY` + audit
  (system Subject), an **allow-list of parameterized** statements (bound params, no caller
  predicates), output-capped. (D6 is currently false for these read-only DBA tools.)
- **N-S4 mTLS peer-cert plumbing.** In `handle_tls_connection` read `peer_certificates()`,
  SHA-256 the leaf DER → `CertFingerprint`; thread it + `peer_addr` through
  HttpRequest→DispatchContext→Subject; require a leaf-fp→registered-client map (any CA
  cert ≠ identity). Else "mTLS-fp Subject" does not exist.
- **N-S5 Lease stamps server-derived Subject + re-asserts ALTER SESSION allowlist.** When
  N0 wires the lease, `agent_identity`→`v$session` must be the server Subject stable_id
  (never a tool arg); the new path re-checks `is_allowed_alter_session` itself (don't
  inherit the former deleted lease implementation's trust-the-caller contract, historical
  `crates/oraclemcp-db/src/lease.rs:427-437`).
- **N-S6 Allow-list-first redaction for every new surface.** Redacting newtypes for
  `OracleBind` + `OracleConnectionInfo`; proof bundle/timeline use `sql_sha256` **not**
  `sql_preview` (or scrub inlined literals — they enter the signed chain today);
  classify raw `ORA-` text into a safe envelope; config diff over **parsed allow-listed**
  fields; redact other sessions' `v$session`; HTML-escape labels/`message` at render.

### Missing-foundation nodes (→ as named; prerequisites, not consumers)
- **FN1 Streaming SSE transport (→ WP-P, before P1).** Chunked/long-lived response,
  server-push channel, **bounded per-subscriber ring buffer + slow-consumer drop**,
  `Last-Event-ID` resume. Today "SSE" = 2 events in one write (`http.rs:1479-1532`).
  P1/P1b/W3/N5 depend on this.
- **FN2 Subject-aware audit rebuild (→ driver tier, before N7).** Extend `AuditRecord`
  with structured `Subject{kind,stable_id,authn_method,client_id,thumbprint}` + DB-evidence
  columns; preserve/upgrade `verify`; bump audit `schema_version`. (Today: free-form
  `agent_identity:String`, single global chain — also a cross-lane p99 serialization point.)
- **FN3 Per-lane telemetry (→ driver tier, before W3).** Per-lane/per-subject label
  dimension across counters + histograms; `blocked` counter; `active_lanes` gauge; per-lane
  MCP-request latency histogram. (Today telemetry is process-global bare atomics.)

### N0a split + concurrency (→ WP-N)
- **N0a → two beads:** (i) **lane runtime/thread ownership** — tear out the shared
  `dispatch_runtime` (`server.rs`), give each lane its own OS thread + current-thread
  runtime + reactor + pinned conn; (ii) **connection-thread↔lane-thread handoff**
  (message-passing; where cancel/DELETE/SSE plug in). This is the critical-path long pole,
  not a lease wrapper. Transport is one-request-per-connection today; a lane must persist
  across connections (keyed MCP-Session-Id + Subject).
- **N4+ Bound the accept/connection-thread layer** (max in-flight connections + accept
  backpressure) independent of DB-session caps; separately cap + idle-timeout
  operator/SSE connections (they aren't lanes). (`http.rs:1585-1615` spawns a thread per
  accept, uncapped.)
- **N-M7 Cross-restart exactly-once:** execute consults the durable audit chain
  (`sql_sha256` + grant) before commit; document at-least-once across restart (needs N-S2).

### CI / release / ops (→ WP-E/F/S/H)
- **E0 `web-build` CI job** (`npm ci && vite build` → dist artifact) feeding `checks`,
  `pinned-nightly`, **all 6 build targets**, and Docker (build JS once, fan to all). Pull
  `rust-embed` **default-features-off** (no web-framework feature → no boundary-lint trip);
  add it to `deny.toml`. (Tie to D13's `dashboard` feature.)
- **E-cred Per-client credential store.** `$XDG_STATE_HOME/oraclemcp/clients.json` (0600,
  dir 0700, Windows ACL), atomic-rename + advisory lock, **service owns writes** (installer
  calls a `client add` the service applies); revoke/rotate → **immediate lane teardown
  (N5) + grant revocation**; in the S5 reload set; list/revoke/rotate operator routes
  enumerated in P1.
- **S-unit systemd unit hardening:** `LimitNOFILE`, `TasksMax`, `MemoryMax`,
  `Type=notify`/`NotifyAccess`, `Restart=on-failure`, `OOMScoreAdjust`; doctor reports
  effective-vs-configured caps; launchd/Windows equivalents. (64+ lane-threads vs default
  `user.slice` limits would silently throttle N4.)
- **S-sbom JS CycloneDX SBOM** (from the SPA lockfile) merged into the release SBOM +
  added as cosign/attest subjects (today's SBOM is Rust-only → supply-chain claim false).
- **S-cfg Extract the config-ops backend** (draft→strict-validate→redacted-diff→atomic-
  rename+backup→reload/S5) into **rc1** so E5 `setup --write` doesn't depend on rc2's W2.

### Marginals (best-engineering — fold at beading)
§4↔§5 DAG fixes (N0a ─► {N0,N3,N6}; N0 ─► {N1,N2,N7}; N5 dep N1,N4); orphans (A8─►E2/E4;
W1─►W9; C1/C2─►C5─►W7); A7/A7b add N4/N5 typed-error variants + re-baseline
`oraclemcp-error`; new config fields (`monitor_profile`,`dashboard_ddl_workbench`,
`dashboard_workbench`) = `schema_version` bump + migration note (G2/W2/W4/W8);
`oracle_capabilities` (server-direct path) must report the **calling lane's**
level/profile/DB; G2 upgrade note covers per-lane `switch_profile` + N8-fail-closed +
lane-bound tokens; honesty-grep must scan `server.json` ("safe-by-default" wording);
toolchain pin consistency (now + Node); **SSE GET auth** = SameSite=Strict cookie +
**mandatory** Origin + `guard_http_request` + subject-verified `Last-Event-ID` (EventSource
can't send bearer/CSRF); **local-pairing trust root** = 0600 token in `$XDG_RUNTIME_DIR`,
≤60s single-use ticket exchanged for the HttpOnly cookie then invalidated (no token-in-URL
persistence; `Referrer-Policy: no-referrer`); classifier **workbench fallback** =
step-up-to-Admin on an unknown verb; cred→Subject re-verified **per request** (never
session-id-alone); per-target binary-size budget; pin Node + `npm ci` for reproducible
attestation; preflight gates (embedded dist present + content-hash, `package-lock.json`,
no `git:`/`file:` JS deps, `npm audit` high/critical, `.crate` size); H7 rollback realities
(npm `unpublish` unavailable → `deprecate` + move `latest` dist-tag; winget/brew lag).

### Decisions (this round)
- **D12** panic = `unwind` + per-lane `catch_unwind` (see §3 D12) — applied default.
- **D13** dashboard features (see §3 D13, as later refined by CX-3 + the 2026-06-30 resolution):
  **`dashboard-api` default-on-but-inert; `dashboard-bundle` NOT default** (product artifacts ship
  it; `cargo install` is bundle-free) — *supersedes this round's earlier "default-on" wording.*

### Protocol journaling-agent residuals (R1-R9 — the WP-P transport is unbuildable as-is)
*The operator surface needs a transport/router redesign, not just streaming SSE.*
- **FN0 (STRUCTURAL → WP-P, before P1/FN1) Transport/router redesign.** Today: a flat
  exact-match ladder (`path != "/mcp" → 404`, `http.rs:1279`), the **query string is
  discarded** (`split('?').next()`, `:1780`; `HttpRequest` has no query field), and the
  tool call runs **synchronously inside the POST handler** (`connection: close`, no GET
  stream, no result buffer). Add: a router with **precedence** — typed-404 API routes vs
  SPA history-fallback `index.html`, so a typo'd `/operator/v1` route does **not** return
  200 HTML (R1); **query-string parsing** for `/operator/v1` + P1b cursor + W5 filters
  (R6); and move tool execution **off the POST handler onto the lane thread with a result
  buffer/stream** so N5 "disconnect≠cancel + reconnect/resume" has a substrate (R3 — ties
  to the N0a connection↔lane handoff + FN1).
- **N-S7 (CRITICAL security → WP-N) Bind MCP-session-id to the verified Subject.** Today
  `HttpSessionStore` is a bare `HashSet<String>` and the bearer is validated independently
  of session membership (R2) → any valid bearer can present **another** principal's
  `mcp-session-id` and both checks pass = **cross-principal lane hijack**. Every stateful
  request must assert `lane.subject == request.subject`; never session-id-alone.
- **P1c hardening (R4/R5):** execute must consult the **durable audit chain** (`sql_sha256`
  + grant id) before commit to prevent **double-execute across restart** (the in-memory
  ledger doesn't survive a crash — "re-preview is safe" is false for already-committed
  DML); define idempotency-key derivation for **non-SQL** actions (set-level/
  switch-profile) with a generation/sequence component.
- **Marginals:** content-type/`Accept` negotiation + 406 (R7); `DELETE` on a stateless
  server → 405 not a false 202 (R8); the SSE event envelope must carry
  `event_seq/event_id/lane_id/subject_id_hash/redaction_level/schema_version` (positional
  ids today) + boundary-validate `structuredContent` against `output_schema` (R9).

### Concurrency journaling-agent residuals (C-1-C-6 — thread-per-lane vs central LeaseManager)
*Key refinement: a lane's connection is **reactor-affine to its own thread**, so EVERY op
on it (rollback, terminate, reap, switch) must be marshaled to the owning lane thread via
a control channel — a central manager must NOT touch conns directly.*
- **C-arch (STRUCTURAL → WP-N N0a) LaneRuntime = a registry of lane HANDLES (mailboxes),
  not a map of connections.** Each lane = an OS thread owning {runtime, reactor, conn,
  lease, level, grants} + a **control mailbox**. The shipped, now-deleted `LeaseManager`'s
  single `Mutex<HashMap<.., Arc<AsyncMutex<Lease>>>>` with reactor-affine conns (historical
  `crates/oraclemcp-db/src/lease.rs:185`) is **structurally incompatible** with per-lane
  reactors: `reap_expired`/`release` clone the arcs and force-rollback with **one foreign
  `cx`**, driving conn futures on a reactor that never registered them (C-2). Redesign:
  the central registry holds only handles; all conn ops are **messages to the owning lane
  thread** (C-2/C-3).
- **C-1 (STRUCTURAL) Idle/abandoned-lane reaping.** The former deleted
  `reap_expired` path (historical `crates/oraclemcp-db/src/lease.rs:447`) has
  **zero production callers**; expiry is lazy. With N5 (disconnect≠cancel), an abandoned
  dirty lease holds its txn + row locks until process exit. Design: a **watchdog** sends a
  `terminate`/`timeout` message to the lane's mailbox; a lane **parked in a DB call** is
  unblocked by the existing call-timeout/OCI-break (B1); a lane **parked idle** wakes on
  its mailbox. (A central reaper touching the conn is the C-2 bug.)
- **C-3 (STRUCTURAL) `DELETE MCP-Session-Id`** must be a message to the owning lane thread
  (rollback runs there) — never a force_rollback on the accept thread.
- **C-4 (STRUCTURAL) `Lease` needs an epoch/generation + lane/subject id.** The monotonic
  value A6/K2/K3 grant-invalidation compares against didn't exist on the former `Lease`
  (historical `crates/oraclemcp-db/src/lease.rs:144`, later deleted by B14b); add it and
  **bind grants to it** (closes the check-vs-use window on the ceiling).
- **C-5 (STRUCTURAL) `switch_profile` = an atomic conn-swap state machine.** A lease pins
  one non-optional conn for life; N1's per-lane switch must **acquire the new profile's
  permit/conn before releasing the old** (or represent a 'switching' lane state), rolling
  back to the old on `AtCapacity` — never strand the lane connection-less. Aligns with K1
  'permit released exactly once.'
- **C-6 (MARGINAL) Cross-thread cancel of a parked `block_on`.** Confirm asupersync can
  wake a lane parked in `block_on` of a `!Send` future from another thread (the control
  mailbox + OCI-break are the likely mechanism); flagged pending that capability check.

### Codex cross-model triangulation (verdict: needs-changes → all adopted)
*Codex (read-only, code-grounded) independently CONFIRMED the panel's load-bearing
findings — retire confirm-MAC (incl. the compat `{sql,token}` path), session-id must
never select a lane alone, compile/patch need audit, N0a is a transport/runtime rewrite —
and added refinements adopted as the best decisions. Cross-model consensus: HIGH.*
- **CX-1 Read path is NOT a shared pool.** Reactor-affine conns can't cross lane runtimes
  → reads run via **read-worker lanes (own reactor+conn) / per-reactor shards**, not one
  shared `OraclePool`. (Fixed in N0a; D5/N6 read "pool" = read-worker lanes.)
- **CX-2 Panic ≠ rollback.** After a lane panic: **quarantine + revoke grants + drop conn
  + audit `unknown_discarded`** — no rollback promise. (Fixed in D12.)
- **CX-3 D13 split:** `dashboard-api` (Rust-only, default-able) vs `dashboard-bundle`
  (SPA, NOT default; release/Docker only) → source builds stay Node-free. (Fixed in D13.)
- **CX-4 Capacity at the transport layer.** The operator reserve + caps must be enforced
  **before transport-worker allocation** (accept threads, SSE subscribers, lane threads,
  fds), not only before DB sessions — else an HTTP/SSE flood starves the operator lane
  without opening any Oracle session. (Strengthens N4+ / the marginal SSE-cap item.)
- **CX-5** retire the deterministic confirm path **including** the compat `{sql,token}`
  acceptance — not just rebind it. (Strengthens N-S1.)
Codex's top concerns mirror the panel's: read-pool/reactor contradiction; confirm/
session/audit gaps; transport-level capacity + cross-thread cancel proof. **Two models +
a 5-lens panel + GPT Pro now agree on the architecture and the open risks.**

---

## 4-AS. Asupersync leverage — use the native primitives, stop hand-rolling

*Question: are we leveraging asupersync fully? **Answer: NO.** oraclemcp uses it as
executor + `cx` (110×) + `cx::cap` capability narrowing + `time::timeout`; the 0.6.0
LaneRuntime **hand-rolls exactly what asupersync 0.3.4 provides natively and more
correctly.** Verified present in the pinned 0.3.4: `actor`/`gen_server`/`supervision`/
`spork`/`monitor`/`link`, `cancel` (request→drain→finalize), `channel`
(mpsc/oneshot/watch/**tracked**), `scope`+`obligation`, `lab`+DPOR/fault-injection, a
**multi-threaded work-stealing runtime** (`worker_threads`, 3-lane priority),
`evidence`/`observability`, plus the `cx::cap` narrowing we already use in A9.*

> **⚠️ NAME RECONCILIATION (v3.18 — read with Appendix A.11).** Several primitive *names* used in §4-AS
> and §4-AS.2 below were loose; **Appendix A.11 is authoritative** against verified 0.3.4 source. The
> *directives stand*; the *APIs* are corrected there: **`Pool`/`GenericPool` does NOT exist** (per-DB
> ceiling = `channel::mpsc` token-bucket + `combinator::bulkhead`; DL-7 fixed); **`epoch_tracker` ≠
> lane-generation** (use a plain monotonic `u64`); **`mask()` = `cx.masked` / `combinator::commit_section`**;
> **"tracked_channel"/"tracked_oneshot" = the two-phase `Sender::reserve(cx)→SendPermit`** obligation send.

**Leverage directives (fold into WP-N/WP-P/N9 — best-engineering; reshapes the beads):**
| The plan hand-rolls… | Use natively instead |
|---|---|
| lane mailbox + connection↔lane handoff + result stream/resume | `channel` mpsc/oneshot/watch + **`tracked_channel`/`tracked_oneshot`** (cancel-correct, obligation-tracked, no silent drop) |
| watchdog reaper + lane lifecycle + restart/poison | `supervision` + `gen_server`/`actor` + `monitor`/`link` (restart policy, supervised mailbox, death monitors) |
| N5 disconnect≠cancel / DELETE / C-6 cross-thread cancel / B1c poison | the **`cancel`** first-class protocol (request→drain→finalize, never a silent drop) + `obligation` |
| lane lifecycle / rollback-on-cancel / grant-consumed-once | `Scope`/regions + `obligation` (two-phase effects, finalize-on-cancel) — owned work, no detached tasks |
| N9 lane state-machine (K1-K5) + concurrency-contract interleavings | **`lab` + DPOR / fault-injection** (the exact pattern asupersync uses for its own `cancel`/`channel`/`actor` metamorphic suites) — deterministic, exhaustive |
| per-lane capability bounds | extend `cx::cap` narrowing (A9) **per lane** → capability-secure lanes |
| per-lane forensic audit | `evidence`/`monitor` alongside the hash-chain |

**Two structural reframes for N0a:**
1. **Runtime topology, corrected.** "asupersync is current-thread-only" is **FALSE** — it
   ships a **multi-threaded work-stealing scheduler** (`worker_threads`). Replace today's
   "one shared current-thread dispatch runtime + `block_on` from N connection threads"
   with a **multi-thread runtime for the `Send` transport layer** (HTTP accept / operator
   API / SSE) **+ per-lane current-thread runtimes only for the `!Send` Oracle-driver
   work**, bridged by `channel`. Thread-per-lane still holds for the `!Send` DB conns; the
   transport gets the MT runtime — cleaner and native vs block_on-from-many-threads.
2. **LaneRuntime = a supervised *Send control handle* + a thread-pinned DB loop**
   (Codex-verified correction: asupersync `Actor`/`GenServer` require `Send + 'static`
   state + `Send` messages/futures, so they **CANNOT own the `!Send` Oracle connection**).
   Working shape: the MT runtime owns transport; a **Send `LaneHandle`** (registry entry)
   holds only {mailbox `Sender`, generation, cancel handle, join handle, status} and MAY
   be supervised by `gen_server`/`supervision`; **each lane is its own OS thread running a
   manual `Runtime::block_on` loop** (block_on accepts `!Send` futures) that **owns the
   connection**, takes `Send` commands over `channel`, replies via `Send` oneshots/tracked
   oneshots. **Sharp rule: the Oracle connection NEVER leaves the lane thread; DB work is
   NEVER run through `Scope::spawn`/`Actor`/`GenServer` (all `Send`-bound).** (`spawn_local`/
   `LocalStoredTask` also allow `!Send` futures but need a local scheduler — the manual
   block_on loop is the least-ambiguous shape.)

**Net:** building WP-N on asupersync's `supervision`/`channel`/`cancel`/`scope`/`lab`
surfaces is **more correct (cancel-correct, obligation-tracked, supervised), less code,
and better-tested (DPOR)** than hand-rolling — and it's what the runtime is *for*. This is
the single biggest leverage gain available; it should reshape WP-N's beads (the N0a
handoff, N5 lifecycle, C-arch mailboxes, N9 tests all become "consume the native
primitive," not "build one"). It does NOT change the safety contract — it strengthens it.

**Codex triangulation of §4-AS (source-verified; all applied):** verdict — substantially
correct, with these fixes folded in: (a) the **actor caveat** above (supervised Send
handle + thread-pinned `block_on` lane loop; conn never leaves the thread); (b) **soften
"DPOR"** — `lab` ships deterministic scheduling + await-point cancellation injection +
chaos, but the explorer is currently **seed-sweep** ("true DPOR" backtracking/sleep-sets
is upstream future work), so the N9 interleaving suite uses lab **injection + seed-sweep +
our own state-machine assertions**, not exhaustive DPOR; (c) **C-6 confirmed** — `cancel`
wakes *idle* lanes (parked in `block_on` on `mpsc::recv`; `mpsc::Sender::wake_receiver`
for out-of-band), but a lane **inside a blocking Oracle call** can only be interrupted by
**driver-level OCI break / call-timeout / socket close** (then treat the conn as suspect →
rollback/discard) — asupersync handles idle/async, **B1/B1c handle in-flight**.
**Overlooked native leverage to adopt:** `combinator::{bracket` (conn acquire/use/release),
`bulkhead` (per-lane admission/isolation), `circuit_breaker` (poisoned-profile handling),
`rate_limit` (per-caller limiting — **revives deferred k6q.11**), `select`, `timeout}`;
**`epoch_tracker`** for **lane generation / grant-invalidation (directly answers C-4)**;
`deadline_monitor` + `obligation::eprocess` for stuck-lane *evidence*; `evidence` ledger to
*augment* (not replace) the audit hash-chain; `mpsc::Sender::wake_receiver` as the idle-lane
wake primitive.

### 4-AS.2 Second leverage pass — semantics + app-topology (LEVERAGE-PLAYBOOK / BUDGET-OUTCOME-CAPABILITIES / SUPERVISION-OTP)

*The first pass got the **runtime mechanics** right (channels/cancel/supervision/scope/lab/
combinator/epoch_tracker). This pass adds the layer the playbook calls the real win:
**Budget, Outcome and capabilities are the application's semantic contract, and a long-lived
service is an `AppSpec` supervision tree — not `RuntimeBuilder + block_on`.** All directives
below strengthen the fail-closed contract; none weakens it.*

| Net-new leverage | Directive (fold into the noted WP) | Why it's better than the current plan |
|---|---|---|
| **AppSpec is the app boundary** | **WP-S/WP-N:** model the always-on service as an `AppSpec` supervision tree (root region), not a bare `RuntimeBuilder+block_on`. Children: transport (HTTP/SSE accept), lane-registry/supervisor, audit-chain writer, metrics/health collector, dashboard-API. Hold the `AppHandle` as an **obligation** — graceful shutdown (S5) = `AppHandle::stop` then `join`, never drop. | Deterministic start order, root-budget propagation, registry capability injection, explicit lifecycle — replaces hand-rolled startup/shutdown sequencing and "silent leak on drop." |
| **RestartPolicy encodes dependency shape** | **WP-N:** lanes are independent → **`OneForOne`**. Where a child must come up before dependents (audit-writer before transport accepts; registry before lanes) → **`RestForOne`**. Reserve `OneForAll` only for genuinely shared critical state. `SupervisionStrategy` (what happens to the failed child) is a *separate* decision from `RestartPolicy` (what happens to siblings) — encode both, don't fake either with manual restart loops. | Makes "why did lane X restart before Y?" answerable from artifacts; removes the hand-rolled watchdog/reaper entirely. |
| **Lane registry = registry capability + name leases** | **WP-N (C-arch):** the per-principal lane registry is registry-capability **name leases** (injected via `AppSpec`/`Cx`), not an ambient `HashMap`. Names clean up deterministically on lane death; resolve with `stop_and_release()`/`abort_lease()`. The leased entry is the **Send `LaneHandle`** (mailbox+gen+cancel+status), never the `!Send` conn — consistent with 4-AS reframe #2. | No ambient global service locator; deterministic name cleanup on crash/shutdown; aligns the registry with the supervised topology. |
| **Outcome<T,E> is four-valued — preserve it to the edge** | **WP-P/WP-N:** lane→dispatch→transport carry `Outcome` (`Ok<Err<Cancelled<Panicked` severity lattice), collapsing **only** at the MCP/HTTP policy boundary: `Cancelled→499`, `Panicked→500`/page supervision, `Err→` domain error. Do **not** flatten to `Result<_,String>` at the first adapter. | `Cancelled` (client gone / shutdown / timeout) is not an error — it changes audit, retry, and drain behavior; `Panicked` must page, not look like a routine failure. |
| **CancelReason is structured — record it** | **WP-N/WP-G:** thread `CancelReason` {`User`(client DELETE/disconnect, N5), `Timeout`(call-timeout, B1), `Shutdown`(drain, S5), `RaceLost`, `FailFast`, `ParentCancelled`} into the **audit hash-chain** and the dashboard. `Shutdown` ⇒ stop acquiring new work + bounded cleanup; `Timeout` ⇒ mark conn suspect (B1c). | Turns N5 "disconnect ≠ cancel" and B1 timeouts into typed, audited, policy-routable events instead of generic failures. |
| **Budget.meet() algebra replaces ad-hoc timeouts** | **WP-B (reshape #4):** each request's effective `Budget` = `meet(service-root, per-profile-ceiling, per-request-deadline)` with **deadline + poll-quota + cost-quota**, propagated to children (tighter, never `INFINITE`). The fetch-loop/commit/rollback bound (D7 #4) becomes budget exhaustion, not a bare timer. | Budget propagation is *correctness*, not tuning; one algebra covers call-timeout, total-request bound, and fetch-loop bound that #4 currently treats as three separate knobs. |
| **mask() + bounded budget for finalizers (safety-critical)** | **WP-N/WP-B:** run **rollback-by-default** and **audit-chain commit** as `mask()`ed finalize sections with a short bounded cleanup budget, so cleanup **completes deterministically even under `Shutdown`/cancel**. Masking is *only* for these narrow finalize edges — never wide business logic. | Directly protects the fail-closed + rollback + hash-chain invariants against being interrupted mid-finalize by a shutdown/timeout cancel. |
| **Obligation-tracked protocol edges** | **WP-N:** dispatch→lane mailbox uses **reserve/commit** (tracked) sends so a cancelled request leaves no half-sent command; the **per-DB connection ceiling** is a **permit-backed semaphore/pool** (never hold a permit across an unrelated await); choose the lane-mailbox **`CastOverflowPolicy`** deliberately (bounded queue → backpressure/`429`, not silent drop or unbounded growth). | "Must-send/must-release/must-unregister" become enforced obligations; the per-DB ceiling invariant gets a release-correct primitive instead of a manual counter. |
| **ServiceBuilder ingress stack** | **WP-N/WP-P transport:** wrap the HTTP/operator ingress in `ServiceBuilder` layers — `concurrency_limit` (per principal), `load_shed` (overload), `rate_limit` (revives k6q.11), `timeout` — instead of hand-rolled admission. Complements per-lane `bulkhead`/`circuit_breaker` from pass 1. | Backpressure and failure-domain isolation become explicit, composable, and testable at the boundary. |
| **Capability least-privilege, precisely** | **WP-N/classifier:** the fail-closed SQL classifier is **pure → `cap::None`/no `Cx`** (no spawn/io/random/remote reachable from the security decision); the lane handler receives a **narrowed `Cx`** (only the effects it needs — typically time + the lane's own io, never `REMOTE`). Widening is compile-time rejected. | Makes least-privilege structural (type-system-enforced), not documentation — hardens the security core against an accidental effect from the wrong layer. |
| **Forensic oracles as the N9 quality bar** | **WP-N N9:** the deterministic suite asserts **quiescence** (no leaked obligations at end), runs the **obligation-leak** + **futurelock** oracles, and on failure emits **crashpack + seed** ("can replay the bad run" = quality bar). Augments the lab injection/seed-sweep already in §4-AS. | Catches lane/mailbox leaks and futurelocks the state-machine assertions alone would miss; every red test ships a replayable artifact. |

**Deliberately N/A (recorded so the omission is intentional, per "no silent caps"):** `hedge`/
`quorum` (single Oracle backend per profile — nothing to race/duplicate); `remote`/
`distributed`/saga, RaptorQ, QUIC/H3, Browser Edition, messaging integrations (playbook §9
"do not lead with these unless required" — 0.6.0 doesn't). Revisit only if read-replica
fan-out or multi-node operation is ever in scope.

**Net (pass 2):** WP-N/WP-S graduate from "tasks + channels" to a **supervised `AppSpec`
application** whose **Budget/Outcome/Capability** carry the safety contract end-to-end. This
is additive to pass 1 and reshapes beads in WP-S (AppSpec topology + AppHandle obligation),
WP-N (RestartPolicy, name-leases, reserve/commit mailbox, permit-backed ceiling, masked
finalizers, narrowed Cx), WP-B (Budget.meet replaces #4's three timers), WP-P (Outcome to
the edge), and N9 (quiescence/leak/futurelock oracles + crashpacks).

---

## 4-SK. Skill-informed hardening (applied in depth, 2026-06-30)

*Four skills run against the plan and codebase ground-truth — `deadlock-finder-and-fixer`,
`mcp-server-design`, `agent-ergonomics-and-intuitiveness-maximization-for-cli-tools`,
`world-class-doctor-mode-for-cli-tools`. Each subsection is actionable: concrete beads,
tests, CI lints, and code rules to fold at beading. None weakens the fail-closed safety
invariant — several strengthen it.*

### 4-SK.1 Deadlock / concurrency hardening (deadlock-finder-and-fixer + its ASUPERSYNC cookbook)

*The skill's 9-class taxonomy, run against WP-N (MT transport + per-lane `block_on` threads
+ mailboxes + registry/lease/grant/audit locks + cancel/epoch). The asupersync cookbook's
core insight: most classes are **structurally prevented** IF the primitives are used
correctly — so these directives are mostly "use the native primitive + add the deterministic
oracle test," not "add a lock."*

- **DL-1 (Class 2 — reconcile `block_on` with the `!Send` conn; IMPORTANT).** The skill flags
  `block_on` and "`RuntimeBuilder+block_on` as the final architecture" as anti-patterns. This
  does **not** overturn §4-AS reframe #2 — it sharpens it. The `!Send` Oracle conn cannot live
  in a `Send` `GenServer`/`Actor`/`Scope::spawn`, so it must be hosted by **either** (a) a
  dedicated OS thread running its own current-thread `Runtime::block_on` loop, **or** (b)
  `spawn_local`/`LocalStoredTask` on a per-lane local scheduler. The real Class-2 hazard is
  `block_on` **nested inside an async task / on a runtime worker thread** — so the rule is:
  the lane's `block_on` is the **outermost** call on a **dedicated** lane thread, never nested,
  never on a transport worker. The lane thread is a **supervised worker under `AppSpec`**
  (supervisor owns spawn/restart + the `Send` LaneHandle); `block_on` is the local `!Send`
  execution bridge, *not* the app architecture (AppSpec is). **Bead (Phase 0 spike):** prototype
  (a) vs (b), pick the least-ambiguous `!Send`-correct bridge, document it with a `SAFETY:`
  comment on the lane-loop entry.
- **DL-2 (Class 2 — transport must never block on a lane reply).** The MT transport awaits lane
  replies via async `oneshot.recv(cx)` / session reply — never `block_on`, never a synchronous
  blocking wait on a worker thread (that starves the transport runtime and reads as a hang).
  Mailbox send is two-phase `reserve(cx)`→`send`; a full bounded mailbox is **backpressure →
  busy/429**, never an unbounded block. **Test (N9):** `transport-stays-responsive-while-lane-
  blocked-in-DB` — one lane in a long DB call must not stall the accept loop or sibling lanes.
- **DL-3 (Class 2 — no inter-lane cycle, by construction).** Lanes never message each other;
  transport→lane is one-way commands + a reply oneshot; the registry/supervisor is the only
  fan-in. This makes a channel/JoinHandle cycle structurally impossible. **Invariant + grep-lint:**
  no lane module imports another lane's `Sender`.
- **DL-4 (Class 1 — canonical lock order).** Define oraclemcp's total lock rank and assert
  ascending acquisition in debug builds, with `SAFETY:` comments on each lock decl:
  **`Config(watch, lock-free read) → Registry → Lane(status) → Lease → Grants → Audit-chain →
  Metadata-cache`.** Hard rule: **never hold the Registry lock across a lane send** — copy the
  `Send` LaneHandle out, drop the registry lock, then `reserve/send` (the "registry holds only
  handles" design already enables this; codify it). Prefer the `actor`/`GenServer` ownership
  model so most "shared state" becomes single-owner mailboxes with **no lock-order graph at
  all**; keep locks only where genuinely shared (config via `watch`, audit-chain via a single
  writer). **Test (N9):** an AB-BA attempt between Registry and Lane is unconstructible.
- **DL-5 (Class 8 — poisoning, interacts with D12 `unwind`).** D12 reverses 0.4.0
  `panic=abort`→`unwind`+per-lane `catch_unwind`, which reintroduces `std::sync::Mutex`
  poisoning risk. Directives: (a) per-lane `catch_unwind` at the loop boundary maps a panic to
  `Outcome::Panicked` → supervisor **quarantines + restarts** the lane (CX-2); (b) use
  `parking_lot::Mutex` (non-poisoning) or asupersync `Mutex` (configurable
  `ObligationLeakResponse`) for shared locks — **never `std::sync::Mutex`**; (c) the
  **audit-chain writer is transaction-style** (build the entry in a local, append-and-swap)
  so a panic mid-append can't corrupt the hash-chain — protects **N-S2**. **Test:**
  panic-injection mid-audit-append leaves the chain valid + verifiable.
- **DL-6 (Class 9 — lost wakeup on cancel/epoch → level-triggered).** Cancelling an idle lane
  parked on `mpsc::recv` must use **level-triggered desired-state** (a cancel/shutdown flag in
  the LaneHandle, re-read after each `recv`/on wake), not an edge-triggered notify that can be
  lost if it lands just before the lane parks. `mpsc::Sender::wake_receiver` wakes the parked
  lane; epoch generation published `Release`/read `Acquire` (or rely on the channel's
  happens-before). asupersync channels already do waker-dedup + capacity-recheck (lost-wakeup-
  safe); the app rule is "store desired state, recompute on wake." **Test:**
  cancel-issued-one-step-before-park is still observed.
- **DL-7 (Class 3 — livelock; upgrade the per-DB ceiling primitive).** Poisoned-profile
  `circuit_breaker` (§4-AS) stops retry storms; the accept loop backs off on `EAGAIN`. **⚠️ CORRECTED
  (v3.18, Appendix A.11): asupersync ships NO public `Pool`/`GenericPool` in 0.3.4** (the only `pool`
  is the internal HTTP keep-alive one). Build the per-DB ceiling from **`combinator::bulkhead`**
  (obligation-tracked permits — checkout-leak *is* detected; `try_acquire(weight)->Option<Permit>`,
  released on drop) **backed by a `channel::mpsc` token bucket** for the conn slots, replacing
  §4-AS.2's raw "permit-backed semaphore"; add per-caller `combinator::rate_limit`. The operator/doctor
  reserved lane uses **fair/queued admission** so a read-flood can't starve it (refines N4). **Test:**
  `read-flood-doesn't-starve-operator-lane` + the bulkhead permit-leak oracle (Appendix B.5/B.11).
- **DL-8 (validation = lab oracles, the loom-equivalent).** N9 runs under `LabRuntime` with the
  **quiescence oracle** (deadlock detector: all-blocked-no-progress), **obligation-leak oracle**,
  **loser-drain oracle**, **progress-certificate**, and treats `FuturelockViolation` /
  `RegionCloseTimeout` as hard failures. `ObligationLeakResponse::Panic` in lab/CI; `Log`+
  threshold-escalate in production. Determinism hygiene: `cx.now()` / `cx.random_u64()` /
  `DetHashMap` / `VirtualTcp` (no wall-clock/ambient-rand/real-net in lab tests). The explorer
  is **seed-sweep, not full-DPOR** (Codex-verified, §4-AS) — so widen seed coverage **and**
  hand-author adversarial interleavings for the DL-4/DL-3/DL-6 cases above; the oracles fire on
  whatever is explored.
- **DL-9 (The Fourth Instance — `concurrency-audit` CI lint).** Add a CI job (companion to the
  §4-R `web-build` job) enforcing the asupersync audit greps as gates: `block_on` outside the
  one sanctioned lane-bridge module → **fail**; `tokio::spawn`/`std::sync::Mutex` in core →
  **fail**; `unbounded`/`mpsc::unbounded` channel → **fail** (every queue bounded); a lane
  module importing another lane's `Sender` → **fail** (DL-3); loops missing `cx.checkpoint()`
  in lane/handler modules → **warn+review**; `ObligationLeak|FuturelockViolation|
  RegionCloseTimeout` in `cargo test` output → **fail**. Rationale: every concurrency bug is a
  sample from a distribution — the lint mechanically enforces "find the fourth instance" each PR.
- **DL-10 (cross-link to doctor + dashboard).** asupersync's **Spectral Health Monitor**
  (early-deadlock warning over the live wait graph: none/watch/warning/critical) +
  `TaskInspector` + `CancellationExplanation` feed **`om doctor`** (§4-SK.4) and the dashboard
  health panel (W3/W4) — deadlock early-warning becomes an operator-visible signal, not a
  postmortem.

### 4-SK.2 MCP server design — agent theory-of-mind for the tool + operator protocol (mcp-server-design)

*The skill's one rule — "make the wrong thing impossible and the right thing obvious" — maps
directly onto a fail-closed Oracle server. The big shift: a refusal is a **teaching moment**,
and the safe set of tools should be **structurally scoped to the caller's authority**. One
hard deviation is recorded (MCP-13): the skill's "forgive by default / auto-correct" yields to
our safety invariant wherever a correction would cross a safety boundary.*

- **MCP-1 (educational structured refusals — HIGH value, safety-aligned).** Today the
  fail-closed classifier refuses non-`READ_ONLY` SQL. Make every refusal a **structured,
  recoverable error** that teaches the *legitimate* path (never a bypass): `{error_type:
  "SQL_NOT_ALLOWED_AT_LEVEL", message, recoverable:true, data:{detected_category:"DML|DDL|…",
  current_level, required_level, profile_max_level, how_to_escalate:"oracle_set_session_level →
  preview → confirm-token", suggested_tool_calls:[…]}}`. If `required_level > profile_max_level`
  (or `protected`), say so plainly ("this profile cannot exceed READ_ONLY") — do **not** hint a
  workaround. Turns the safety wall into a guide. **Bead → WP-P + tool layer.**
- **MCP-2 (confirm-token theory-of-mind).** Agents will lose/replay/stale tokens or skip
  preview. The N3 grant store / N-S1 confirm-MAC rejections become structured:
  `{TOKEN_EXPIRED | TOKEN_ALREADY_USED | TOKEN_SQL_OR_LEVEL_CHANGED}`, each with
  `data.fix_hint:"re-run the tool with confirm=false to get a fresh preview+token"`. **Bead →
  WP-P/N3/N-S1.**
- **MCP-3 (capability-gated `tools/list` — HIGH value, safety-aligned, ~70% context cut).**
  The **effective tool set is a function of the authenticated Subject's effective ceiling**
  (D11 + ladder). A `READ_ONLY`/`protected` profile must not even *see* `oracle_execute /
  _compile_object / _create_or_replace / _patch_source` in `tools/list` — uncallable tools are
  hidden, which (a) cuts agent context ~70% and (b) makes the wrong thing structurally invisible
  (Principle #1). This is the agent-facing analogue of `cap::None`/Cx-narrowing (§4-AS.2). **Bead
  → WP-P** (tools/list derives from Subject ceiling + negotiated transport).
- **MCP-4 (Do/Don't + Discovery in every tool schema; lint it).** Every tool description carries
  *Discovery* (find profiles → `resource://oracle/profiles`; find current level → `om doctor` /
  session resource), *When-to-use / NOT-for* (`oracle_query` is NOT for DML → escalate then
  `oracle_execute`), *Do/Don't*, JSON-RPC *Examples*, *Common-mistakes*, *Idempotency*,
  *Edge-cases*. Extend the **A7b output-schema gate** into a **tool-doc lint** asserting these
  sections exist. **Bead → A7b + WP-P.**
- **MCP-5 (discovery resources — the "where do I find the value?" layer).** Expose MCP
  **resources**, not just tools: `resource://oracle/profiles` (names, max_level, protected),
  `resource://oracle/session` (Subject, current level, TTL, active grants),
  `resource://oracle/capabilities` (effective tool set + *why* each is/ isn't available),
  `resource://oracle/health` (lane/pool/circuit status — cross-link doctor). Same data feeds the
  dashboard (one protocol, many frontends). **Bead → WP-P/WP-W.**
- **MCP-6 (escalation macro — flag-gated, gate-preserving).** Optional
  `oracle_begin_write_session(profile, level, reason)` macro bundling
  set_level→preview→{token, TTL, next_actions}. **It returns the token + preview; it does NOT
  auto-confirm** (auto-confirm would collapse the step-up — forbidden by the confirm-gate). Off
  by default; behind a flag. **Bead → WP-P (deferred-default).**
- **MCP-7 (`next_actions` on every result).** Query → ["refine…","oracle_explain_plan for
  cost"]; refusal → the escalation path; post-escalation → newly-available tools + revert
  deadline. **Bead → WP-P.**
- **MCP-10 (defense-in-depth at the protocol edge).** Beyond the SQL classifier, validate/
  sanitize protocol args: placeholder detection (`YOUR_PROFILE`, `$DSN`), bind-name validation,
  reject embedded NULs/control chars. Pairs with **testing-fuzzing** on the decoder. **Bead →
  WP-P + WP-G.**
- **MCP-11/12 (observability + idempotency).** Per-tool-call tracking {tool, level, profile,
  Subject, duration, Outcome incl. `CancelReason`} → doctor + W3; slow-call threshold = a health
  signal. `tools/list`, session-create, profile-select are idempotent; concurrent identical
  session-create returns the existing session (IntegrityError-idempotency). **Bead → W3/W5/P1c.**
- **MCP-13 (DEVIATION — coerce cosmetic, strict on safety).** The skill defaults to "forgive /
  auto-correct." oraclemcp **coerces only safety-neutral input** (whitespace, profile-name case,
  timestamp formats, a trailing `;`) and is **strict-always** on anything touching the
  classifier or level: never auto-escalate, never auto-rewrite SQL to "make it safe." Record this
  as the deliberate override of the skill's default by AGENTS.md's safety invariant. **Bead →
  WP-P (documented mode policy).**
- **MCP-14 (MCP-spec compliance — version negotiate + `tools/list_changed`).** Initialize
  handshake advertises protocol-version + capabilities (pairs with P1 schema-first). When the
  effective tool set changes (after escalation or TTL revert), emit **`tools/list_changed`** so
  clients refetch — the capability-gated list (MCP-3) stays truthful in real time. **Bead →
  WP-P/N5.**

### 4-SK.3 Agent ergonomics for the `om` CLI + surfaces (agent-ergonomics-and-intuitiveness-maximization-for-cli-tools)

*Adaptation note: the skill's default outcome is an *applied audit* (score → fix → re-score)
on a **built** CLI. `om` and the dashboard don't exist yet, so the correct use here is to
fold the skill's **kernel (19 axioms) + 11-dimension rubric + Polish Bar + operator stacks**
into WP-E/WP-W/WP-P beads as **design requirements + release acceptance tests** — the CLI is
born ergonomic. No audit-workspace scaffold, no branch (AGENTS.md governs branches in this
repo; there is nothing built to score yet). Each item below is a Polish-Bar gate for
`v0.6.0`.*

- **ERG-1 (Axiom 0 + 15 — first-try, no TUI-on-bare-invocation).** Bare `om`, `om --help`,
  `om help <sub>` each print useful triage/help and **exit** — never launch a TUI, never block
  on stdin (already aligned: no TUI in 0.6.0). Operators guess `om status` / `om doctor` /
  `om serve`; those must "just work" or redirect with a hint. **Gate → WP-E.**
- **ERG-2 (Axiom 4 — stdout=data, stderr=diagnostics).** Every `om` subcommand: structured
  result → stdout; logs/progress/spinners → stderr. `om status --json | jq …` works with no
  `grep -v`. Foundational for the dashboard + automation. **Gate → WP-E/WP-W.**
- **ERG-3 (Axiom 5 — documented exit-code dictionary).** `om` exit codes are a published
  dictionary, not vibes: `0`=ok, `1`=user-input-error, `2`=safety-block (refused escalation /
  classifier reject), `3`=tool-environment (no service / can't connect), `4`=upstream (Oracle
  error), `5`=conflict (lane/lease/ceiling). Surfaced in `--help` + `om capabilities --json`.
  Mirrors the structured error taxonomy from §4-SK.2. **Gate → WP-E/WP-P.**
- **ERG-4 (Axioms 8/9 — `--json` everywhere + `capabilities` + `robot-docs`).** Every read-side
  `om` command has `--json`. Add **`om capabilities --json`** (version, contract/protocol
  versions, command list, exit-code + env-var dictionaries, feature flags incl. dashboard
  on/off) and **`om robot-docs guide`** (paste-ready in-tool handbook — no external doc lookup).
  Cheap, outsized leverage. **Gate → WP-E.**
- **ERG-5 (Axiom 10 + Stack A — the mega-command = `om doctor`).** `om doctor --json` is the
  canonical TRIAGE/DIAGNOSE mega-command: one round-trip returns `{health(lanes/pool/circuit/
  spectral-monitor), effective-level-per-profile, config-validity, auth-honesty, next_actions}`.
  This is the **convergence point** of DL-10 (spectral deadlock warning) + §4-SK.4 (doctor) +
  MCP-5 (`resource://oracle/health`). **Gate → WP-G/doctor.**
- **ERG-6 (Axiom 6/7 + Stack C — error pedagogy + intent inference).** Every `om` error names
  (a) what failed, (b) where, (c) the **exact** command to run instead — e.g. `om attach` with
  no service → "no oraclemcp service running. Start it: `om serve` (foreground) or
  `om service install` (persistent)." Levenshtein-1 typo correction on subcommands/flags
  (`om statsu` → "did you mean `om status`?"). **Gate → WP-E.**
- **ERG-7 (Axiom 11 + Stack D — dangerous-op gating + safe alternative).** Mutating `om` ops
  (service uninstall, config write, credential rotate/revoke, force-release-lane) require
  explicit `--yes`/`--confirm` **and** name a safe alternative (`--dry-run`/`--plan`/`--diff`).
  Aligns with AGENTS.md irreversible-action gating; W2's draft/validate/atomic/rollback gets a
  surfaced `--dry-run`. **Gate → WP-E/WP-W.**
- **ERG-8 (Axioms 12/13 — determinism + env conventions).** `om --json` output deterministic
  (stable ordering; timestamps in fields, not prose; honor `SOURCE_DATE_EPOCH` in tests). Honor
  `NO_COLOR`/`CI`/`TERM=dumb`/non-TTY (no ANSI / no spinner in piped output) — extends the
  installer's gum/ANSI-fallback discipline to `om` runtime output. **Gate → WP-E.**
- **ERG-9 (Axiom 14 — never silent-fail).** Every `om` failure → stderr message + non-zero
  exit. A no-rows query is `exit 0` + `[]`; a failure is `exit ≥1` + stderr. Never "exit 0,
  empty output." **Gate → WP-E/WP-P.**
- **ERG-10 (Axioms 16/17 — Polish-Bar drift guards as CI).** Turn the Polish Bar into release
  acceptance tests: golden tests pinning `om --help` footers + `capabilities --json` schema +
  exit-code dictionary; `verify-stdout-stderr-split` / `verify-determinism` /
  `verify-non-tty-discipline` checks. Run them in CI alongside DL-9's `concurrency-audit` and
  the §4-R `web-build` job — one **agent-ergonomics drift guard** gate. **Gate → WP-G/CI.**
- **ERG-11 (Variant I — MCP↔CLI↔dashboard parity matrix).** oraclemcp has three faces (MCP
  tools, `om`, dashboard). Ship a **surface-parity matrix** (MCP tool ↔ `om` subcommand ↔
  dashboard view) as a release artifact; every divergence is intentional + documented (e.g.
  `service install` is operator-only, never an MCP tool — by design; live SQL is the Workbench,
  not an MCP tool). Operationalizes D2 "one protocol, many frontends" and prevents face-drift.
  **Gate → WP-P/WP-G.**
- **ERG-12 (unifying theme — self-describing, no out-of-band docs).** Across all faces the
  contract is readable *from the tool*: agents read `resource://oracle/capabilities` (MCP-5);
  operators/agents read `om capabilities --json` / `om robot-docs guide` (ERG-4). Nobody has to
  memorize or look up the contract. This is the single thread tying §4-SK.2 + §4-SK.3 together.

### 4-SK.4 World-class `om doctor` (world-class-doctor-mode-for-cli-tools)

*`om doctor` was already the agent-ergonomics mega-command (ERG-5) and the concurrency-health
window (DL-10). This skill makes it a *contract with a future agent who has no context and one
shot to make the service work again*: detect-then-fix, backup-before-mutate, single chokepoint,
reversible, idempotent, crash- and concurrency-safe, offline-by-default. The hard
specialization for a **fail-closed Oracle server**: the doctor's write scope is **service-local
state only** — it must never touch Oracle, never weaken the classifier, never rewrite the audit
chain.*

- **DOC-1 (the surface).** Wire the canonical doctor verbs on `om`: `om doctor` (read-only
  default = the mega-command), `--json`, `--fix`, `--dry-run --fix`, `--explain <id>`,
  `undo <run-id>` / `undo latest`, `capabilities --json`, `robot-docs`, `--robot-triage`, `ls`,
  `--only=<subsystem>`, `gc --before <date> --yes`. Exit codes extend ERG-3: `0` healthy, `1`
  findings, `2` partial-fix, `3` fix-failed-rolled-back, `4` refused-unsafe, `5` concurrency-
  lost, `6` online-required. **Gate → WP-G/doctor.**
- **DOC-2 (detect-then-fix + single `mutate()` chokepoint).** Detectors are **pure** (no
  writes) — mandatory for a fail-closed server. Every repair write flows through one `mutate()`
  that: writes a **verbatim backup** to `.doctor/runs/<run-id>/backups/`, records before/after
  SHA-256 in `actions.jsonl`, holds the service lock, and does atomic write-tmp-then-rename.
  This is the **same transaction discipline** as the audit-writer (DL-5) and obeys the lock
  order (DL-4) — the doctor rides WP-N's primitives, it doesn't invent its own. **Gate → WP-G.**
- **DOC-3 (SCOPE — HARD non-goal: the doctor never touches Oracle or the classifier).** The
  doctor's writable set is **service-local only**: config files, lane/lease runtime state,
  lock/pidfile, systemd/launchd unit, credential-store file perms, `.doctor/` artifacts,
  embedded-SPA cache. It **refuses (exit 4)** anything that would touch the Oracle DB, rewrite
  the audit hash-chain, raise a profile's `max_level`, make a `protected` profile writable, or
  alter the classifier. `capabilities --json` publishes the exact writable path set; anything
  outside → exit 4. **This is the fail-closed invariant applied to self-repair — record it as a
  hard non-goal.** **Gate → WP-G + §2 non-goals.**
- **DOC-4 (reversibility + AGENTS.md RULE 1 = quarantine, never delete).** `om doctor undo
  <run-id>` restores byte-for-byte from backups. Per AGENTS.md RULE 1: **no file deletion** in
  diagnose/fix/undo — a stale/corrupt file is **moved** to `.doctor/runs/<run-id>/quarantine/`
  (`Op::Rename`), never erased. Retention cleanup is the separate double-gated `om doctor gc
  --before <date> --yes`, never part of `--fix`. **Gate → WP-G.**
- **DOC-5 (audit chain is detect-only — never "repaired"; security-critical).** The
  `oraclemcp-audit` hash-chain is append-only + tamper-evident. The doctor **detects** chain
  breaks (cites the exact broken link by sequence + hash, exit 1 finding) but **never rewrites
  the chain** (rewriting would destroy the tamper-evidence that is its entire purpose). The only
  permitted action is to **quarantine a corrupt tail** (move, not delete) and start a new
  verified segment with a recorded discontinuity marker. Cross-link **N-S2 / DL-5**. **Gate →
  WP-G/WP-N.**
- **DOC-6 (idempotent + crash-recoverable + concurrency-safe — reuse WP-N).** `--fix` twice →
  second run "no actions, exit 0"; SIGKILL mid-fix → next run completes or aborts cleanly (no
  torn writes, no orphan `.tmp`); two doctors → one wins the service lock, the other exits 5.
  All three **reuse the lane/lease lock + asupersync supervision/obligation machinery** from
  WP-N — same lock order (DL-4), same transaction style (DL-5). **Gate → WP-G/WP-N.**
- **DOC-7 (offline-by-default; Oracle connectivity is an `--online` probe).** Default `om
  doctor` runs fully offline (service-local state, effective caps, config validity) so an agent
  in a sandbox **without DB creds** can still self-diagnose. Oracle connectivity / wallet / TLS
  / IAM / TCPS checks are `--online` (opt-in) and consume the **driver 0.5.1 typed
  auth-capability surface** (WP-A): "can this profile actually connect with its configured auth
  method?" — folds the wallet/IAM/TCPS diagnostics the 0.5.0 scope wanted into the doctor.
  **Gate → WP-G/WP-A.**
- **DOC-8 (absorb the manual runbooks — Pattern 10).** Convert the rollback runbook + ops docs
  into (detector, fixer, fixture, test) tuples: stale-lock-after-crash → detect+fix;
  config-stranded-the-service (W2) → detect invalid committed config + offer rollback-to-
  last-good; credential-store perms wrong → detect+`chmod 600`; orphaned lane thread → detect+
  reap via supervisor. Demote each markdown runbook to "run `om doctor --fix` first." **Gate →
  WP-G/WP-S.**
- **DOC-9 (the doctor IS the WP-N health window — convergence with DL-10/ERG-5).** `om doctor`'s
  health section surfaces the asupersync **Spectral Health Monitor** (none/watch/warning/
  critical over the live wait graph), per-lane states (`TaskInspector`), pool/circuit/bulkhead
  status, epoch generation, and obligation-leak counts — the operator-facing window into WP-N
  concurrency health, in one mega-command call. Same data feeds `resource://oracle/health`
  (MCP-5) and the dashboard health panel (W3/W4). **Gate → WP-G/WP-N/WP-W.**
- **DOC-10 (fixtures + the unified release-acceptance CI gate).** Each repair gets a fixture
  (`tests/doctor_fixtures/<fm>/`) + round-trip test (corrupt → `--fix` → healthy → `undo` →
  byte-identical). The doctor Polish Bar (detect-then-fix, single chokepoint, backups,
  reversible, idempotent, crash/concurrency-safe, offline-default, no destructive shell) becomes
  CI gates that **join** DL-9 `concurrency-audit` + ERG-10 agent-ergonomics drift-guard + §4-R
  `web-build` as the single **release-acceptance CI suite**. **Gate → WP-G/WP-H/CI.**
- **DOC-11 (scored doctor feeds RC gating).** The doctor ships scored (10 dims) with a per-run
  scorecard + `scorecard_history.jsonl`; the D1 RC gates may require a doctor maturity threshold
  before an rc cut. **Gate → D1/WP-H (DoD).**

---

## 4-WD. Dashboard / React SPA — design (collaborative; COMPLETE 2026-06-30)

*Built interactively with the operator, plan-space + sketch-first. **COMPLETE:** shape + nav
(§4-WD.1), Workbench (§4-WD.2), Change-Review board (§4-WD.3), persistence (§4-WD.4), per-view
specs (§4-WD.5), real-time/SSE model (§4-WD.6), identity & signatures (§4-WD.7), skinnable
architecture (§4-WD.8). Remaining per-view visual polish is implementation-level (beads).*

### 4-WD.1 Shape & navigation (R1/R2 — locked)
- **Shape = Mission Control** (ops/control-plane first). Home leads with **live sessions** —
  which agent · which profile/DB · operating level · current activity — an active-sessions
  summary band on top, expand-to-toggle per-session detail, plus overview (health, recent
  privileged actions). The control-plane is the wedge; the workbench is a co-equal destination,
  not the home. [R1]
- **Nav = 8 destinations, phased across the release train (D1) — all in this plan, beaded
  together:** **Overview · Sessions · Workbench · Schema · Audit · Capacity · Settings · Doctor.**
  **0.6.0** = the read-only control plane (**Overview · Sessions · Audit · Doctor**, 2D);
  **0.6.1** = **Workbench · Schema · Capacity · Settings** (the interactive/query views,
  `dashboard_workbench`-gated); **0.6.2** = the PR-board + the 3D Orrery skin. The skinnable seam
  (D16) + nav shell ship in 0.6.0 so later views slot in without rework. [R2]
- One-protocol-many-frontends (D2): every panel reads the same `resource://oracle/*` + operator
  protocol the MCP/`om` faces use — the dashboard is "just another client."

### 4-WD.2 Workbench (W8) — a *governed PL/SQL IDE* for the human-in-the-loop
**Purpose (operator-clarified):** the Workbench is the **human power-editor** — SQL-Navigator-
class manual editing across packages / functions / triggers / views / tables (incl. directly
updating a value in a queried table) — **not** an agent surface and **not** a raw terminal. The
thesis: **no fail-closed exception is needed; the guard becomes the feature.** [Operator agreed
— stated explicitly here per request.]

**Why it's safe by construction (no system break, no exception):**
- the human is just another authenticated Subject on its **own HTTP lane** (D4/D11/WP-N) — the
  elevated level lives only on that lane; agents' lanes are untouched; no global state flip.
- the **per-lane pinned connection** holds the interactive transaction across edit → review →
  commit/rollback, isolated to that lane (a feature of the lane model, not a workaround).
- the **classifier still gates every statement** at the lane's current level; the human steps up
  via the ladder (preview → confirm-token → TTL window), can't exceed the profile's `max_level`,
  and `protected` profiles stay READ_ONLY.
- every edit lands in the **audit hash-chain**.
- Net: the Workbench is *safer AND more powerful* than SQL Navigator (which offers no preview/
  diff/audit/undo by default).

**WD-RULE-1 — transaction state must be labeled unambiguously (answers "applied, but
revertible — is it applied?").** Two distinct apply semantics; the UI must never blur them:
- **DML** → "**Applied (uncommitted)**": visible *in your session only*, not to others; revertible
  via **Rollback** **for the in-session transaction**; **auto-reverts at TTL expiry**; durable only
  on explicit **Commit**. **Honest scope (C2 — Codex):** Rollback does **NOT** undo autonomous
  transactions (`PRAGMA AUTONOMOUS_TRANSACTION`), `sequence.NEXTVAL` draws, or external side
  effects (`UTL_HTTP`/`UTL_FILE`/`DBMS_PIPE`/side-effecting triggers). The UI labels rollback as
  **"session-transaction only"** and, when the classifier / plsql-intelligence detects a statement
  that may trigger such effects, **warns before apply** — it never claims "fully revertible."
- **DDL** → "**Applied (committed — Oracle commits DDL immediately)**": live *now*, no transaction
  rollback. **Snapshot-undo is scoped (C3 — Codex):** "**Revert**" = re-apply the **prior source
  snapshot**, offered **only for source-replaceable objects** (PL/SQL packages/procedures/
  functions/triggers/types + views). **Destructive / non-source DDL** (`DROP`/`TRUNCATE`/
  `ALTER … DROP`/data-affecting table ops) is **NOT snapshot-undoable** — the UI shows **"no
  automatic undo,"** requires an extra explicit confirm, and never offers a false "Revert." Prior
  source is captured before every source-replaceable DDL apply (DOC-2/DOC-4).
  The status chip states exactly which: `Applied (uncommitted — Rollback to undo)` /
  `Applied (committed — Revert re-applies prior source)` / `Applied (committed — NO automatic undo)`.

**WD-DEC-A (resolves R3a):** browser **writes/DDL = ON via the ladder, behind a separate opt-in
flag**, for operator Subjects, on profiles whose `max_level` permits, **never `protected`**.
**WD-DEC-B (R3b):** operator force-actions on other sessions — **yes (gated + audited)**; made
natural by the propose/approve model below (detailed in §4-WD.3).

**0.6.0 Workbench feature scope (operator-decided):**
| # | Feature | 0.6.0? |
|---|---------|--------|
| 1 | **Governed edit loop:** preview → diff → step-up(TTL) → apply → audit → revert (DML Rollback / DDL snapshot re-apply); persistent open-txn + TTL banner | **IN (core)** |
| 2 | **plsql-intelligence wired in** (now **fully offline** → consumable in-process): go-to-def, find-usages, dependency graph, lint, refactor across objects | **IN** (sibling integration) |
| 3 | **Change-Review board ("PR for PL/SQL")** — propose → review(diff) → approve → apply; **per profile/DB**; Git+Cursor-informed (designed in §4-WD.3) | **IN** (0.6.2 train) |
| 4 | Blast-radius guardrails **(safety gate, not just informational)**: **affected-row COUNT = a DML release gate** (warns/blocks on mass or no-WHERE updates), recompile-invalidates-N, lock/blocker notice | **IN** |
| 5 | Object version history + one-click revert (falls out of #1 snapshots) | **IN** |
| 5b | Schema diff (object/schema across profiles or versions) + migration export (applied changes → re-runnable script) | **IN (confirmed)** |
| 6 | Live compile + error navigation (reuses `oracle_compile_object`, same as the MCP path) | **IN** |
| 12 | **Global DB search across all object types** with type toggles (tables/views/triggers/indexes/packages/functions/sequences/types/…) | **IN** |
| 8 | SQL/PLSQL formatter/beautifier | **Backlog** — verify plsql-intelligence provides one when wiring #2; cheap promotion if so |
| 11 | **EXPLAIN-plan** preview for DML before apply (the affected-row *count* safety gate is #4/IN; only the richer EXPLAIN-plan view is deferred) | **Backlog** |
| 13 | Multi-tab object editor | **Backlog** |
| 9/10/15 | read-side AI assist · 4-eyes PROD approval (pairs with #3) · auto re-query after edit | later / folded into #3 |

Deferred (future releases): PL/SQL step debugger; Edition-Based Redefinition "edit in a private
edition first" sandbox; Oracle Flashback time-travel for data.

**Scope note:** wiring **plsql-intelligence** into 0.6.0 (#2) is a new cross-repo integration —
the shared MCP/PL/SQL core the two repos converge on (see sibling repo). It must remain pure-
Rust + offline (no new network dep) to respect the thin-native line + boundary lints. Add a
dependency/feature bead under WP-W/WP-A at conversion.

### 4-WD.3 Change-Review board ("PR for PL/SQL") — designed (ships in the 0.6.2 train)
*Decision: IN 0.6.0. Grounded in **Git** (proposal/diff/review/state machine) + **Cursor**
(inline per-hunk accept/reject, AI-proposed diffs). Scoped **per profile/database** (operator).*
- **Unit = Change Proposal (CP)**, **keyed by (profile/DB, author)** where author = an agent or
  a human; **multiple named CPs per (profile, author)** are allowed. Each CP has a stable id
  (`cp-204`) + a human name auto-suggested from the change ("Fix rounding in `PKG_BILLING`"),
  renameable. A CP contains ≥1 object edit (DDL) and/or data change (DML), each with a diff +
  description. **One CP = one profile** (no cross-DB); promotion to another env = a *new* CP via
  migration export (5b). Multiple CPs by the same author on the same profile are independent
  unless explicitly sequenced. [operator: per-agent-per-profile, named, toggle-to-view]
- **Creators:** an **agent** (via MCP) whose change needs human sign-off (above its level, or
  policy-routed) creates a CP in `proposed` and **never self-applies**; a **human** can draft a
  CP instead of applying immediately.
- **Scope & view (resolves "where reviews surface"):** CPs surface in **Mission Control** —
  from a live session/agent you **toggle into "its proposals,"** plus a global **Reviews** filter
  grouping `profile → author` with status badges (proposed/approved/applied/rejected). Per D5:
  the operator / review-authority sees all CPs; an author sees its own CPs' status.
- **Review UI:** Git-like object list + unified/side-by-side diff + status; Cursor-like inline
  accept/reject per hunk + comments; impact/blast-radius inline (#4).
- **Apply:** reviewer (operator Subject), optional **4-eyes** (#10), applies → each change runs
  the **governed edit loop** (classifier + escalation + audit + snapshot-undo).
- **Lifecycle:** `proposed → (changes-requested) → approved → applied (revertible) / rejected`;
  the whole lifecycle is in the audit chain. Promotion to another env = a **new CP** via
  migration export (5b); never cross-DB in one CP.
- **`proposed` CPs are stateless** — a CP is data on disk (§4-WD.4); a lane is acquired only at
  apply.

**Apply flow — RESOLVED (the three open questions):**
- **(a) Granularity & honest atomicity.** Apply unit = **per-object** (DDL) / **per-statement or
  grouped lane-transaction** (DML) — forced by Oracle (`CREATE OR REPLACE` rewrites a whole
  object; **every DDL auto-commits**). **Per-hunk** (Cursor-style accept/reject) is a
  *compose/review* affordance that builds the final object source — **NOT** an apply unit.
  **Atomicity stated honestly:** DML in one lane txn = atomic (commit/rollback together);
  **multiple DDL objects cannot be one transaction** → apply is **sequential,
  stop-on-first-failure**, reporting succeeded-(already-committed) vs not, with **per-object
  Revert** via source snapshots (WD-RULE-1). The UI never promises all-or-nothing it can't
  deliver. Reviewer may apply the **whole CP or a subset**; each change item carries its own
  status (pending/applied/failed/reverted) and CP status is derived (`proposed → approved →
  partially-applied → applied / rejected`). Apply runs the governed edit loop once: acquire
  operator lane → escalate to the needed level for a TTL window → apply each item in order (audit
  + DDL-snapshot each) → DML commit/rollback at the end.
  **SEC-1 (security-audit, Axiom 7 — recovery path = shadow codebase):** apply **re-classifies +
  re-checks level/grants/Subject at apply time** — it **never trusts the stored proposal's
  classification/verdict** (a CP is agent-authored and sits on disk; a stale or crafted verdict
  must not bypass the guard). Same rule for every recovery path: migration runner, `om restore`,
  audit-replay all re-enforce classifier + level + audit + idempotency.
- **(b) DML proposal = parameterized SQL + captured binds** (never literal-concatenated):
  `UPDATE … SET salary=:1 WHERE emp_id=:2` + binds `[8500,101]`. Safe (binds, no injection),
  correctly typed (respects NUMBER→string / TSTZ fidelity, WP-C #3), reproducible, re-bindable
  for migration export (5b). Reviewer sees **both** template and values; the **classifier
  classifies the template** (binds don't change READ_ONLY-vs-DML); affected-rows / blast-radius
  (#4) is computed **with binds**. **Grid edits** auto-generate the parameterized statement keyed
  on the table's **primary/unique key**; no unique key (or a predicate hitting >1 row) → the
  guard (#4) warns/blocks before staging.
- **(c) Notifications = ride existing channels, no new infra.** Operator: real-time over the
  dashboard SSE/watch stream — a **Reviews badge + count** + toast on new CP / state change.
  Agents (authors): CP status **queryable** via `resource://oracle/proposals[/<id>]` (MCP-5) +
  a **best-effort MCP server→client notification** on state change (MCP-14 style), with
  **polling the resource as the reliable fallback** (stateless agents re-query). **External**
  (email/Slack/webhook) = **backlog** for 0.6.0. Every CP transition is in the **audit chain** —
  notifications are a convenience layer over a durable record.

### 4-WD.4 Persistence & storage — where state lives (D14)

**DECISION D14 — files-first, pure-Rust-only; never bundle SQLite.** (Cross-cutting: also
governs audit, config, doctor, grants — surfaced in §3 as D14.)

**Why not SQLite:** `rusqlite`/bundled-SQLite links **libsqlite3 (C)** and needs a **C compiler
at build** + `unsafe` FFI — that directly violates oraclemcp's core property (AGENTS.md: "the
default build is pure Rust … does not require … a C toolchain"; every crate
`#![forbid(unsafe_code)]`). Reintroducing a C dep to store *our own metadata* would regress the
thin-native line we migrated to. If a transactional embedded store is ever truly needed, use a
**pure-Rust** one (`redb`), never a C-backed one — and only once Tier 2 outgrows files.

**Existing pattern (verified in code):** the audit hash-chain is already an **append-only JSONL
file** (fsync-before-execute, HMAC chain, out-of-band, tamper-evident — `oraclemcp-audit`). The
architecture already chose files for the most critical durable thing; we extend that.

**Tiered model:**
| Tier | Storage | Holds |
|------|---------|-------|
| 0 — ephemeral (RAM) | none | live lane/session state, **grants + idempotency ledger** (in-memory; audit chain is the durable record), metrics **live** ring-buffer (W3), pairing token (`$XDG_RUNTIME_DIR`) |
| 1 — append-only / content-addressed files | files (write-once) | **audit hash-chain** (keep as-is — a DB would break append-only/tamper-evidence), **doctor run artifacts** (`.doctor/runs/`), **DDL source snapshots** (content-addressed blobs, git-object style — backs WD-RULE-1 undo + version history); **metric history** (append-only per-day files, downsample-on-read, prunable by retention) |
| 2 — structured, mutable, queryable | **files + manifest now**; pure-Rust `redb` only if it outgrows files | **Change Proposals** (state machine, comments, per profile/author), **version-history index**, per-client cred records (hashed), saved queries |
| config | TOML files (W2 draft→validate→atomic→rollback) | profiles, policy (max_level/protected), service config — **inspectable files**, never hidden in a DB |

**0.6.0 verdict: files are enough — SQLite would be over-engineering AND a regression.** Volumes
are operator-scale. A CP = one atomic JSON (write-tmp-then-rename, the doctor `mutate()`
discipline); the index rebuilds on startup (or a small manifest); concurrency = the existing
single-writer service lock. Zero new deps, fully inspectable/greppable/backupable. **Trigger to
revisit:** if CP/history query volume or concurrent-reviewer needs outgrow files → adopt `redb`
(pure-Rust ACID), still never SQLite.

**The senior call — "do we need a DB, even for future additions?" No.** This is *heterogeneous*
data; the anti-pattern would be forcing it into one store. A DB is a **worse** fit for most of
it: it weakens the append-only audit chain's tamper-evidence, hides editable config, and adds
nothing to content-addressed snapshots. **Future-proofing = a `Store` trait seam (D15), not a
pre-built DB:** all persistence goes through a `Store` trait, so if a future feature genuinely
needs SQL-shaped querying we swap the files impl for pure-Rust `redb` behind the trait with
**zero caller churn** — the *option* of a DB is kept for free without paying for it now.
**Decision rule — adopt an embedded DB only when (none true for 0.6.0):** (a) multi-node /
shared state across processes (we're single-node per service); (b) complex ad-hoc relational
queries over large mutable data (ours is small + simple); (c) high-write time-series with
retention/rollup (→ that's Prometheus — *export*, don't embed a TSDB); (d) concurrent
multi-writer with complex transactions (we're single-writer via the service lock). Until one is
met, files are **correct**, not merely adequate — and SQLite stays out regardless (C dep).

**On-disk layout (XDG / OS-native):** state under `$XDG_STATE_HOME/oraclemcp/` (Linux) /
`~/Library/Application Support/oraclemcp/` (macOS): `audit/` (chain), `objects/<hash>` (source
snapshots), `proposals/<profile>/<author>/<cp-id>.json` (CPs — **the path is the per-profile/
per-author keying** from §4-WD.3), `config/*.toml`, `creds/` (hashed); ephemeral runtime
(tokens/socket) under `$XDG_RUNTIME_DIR/oraclemcp/`; doctor artifacts under `.doctor/`. All
per-profile data is namespaced by profile.

### 4-WD.5 Per-view specs (the 7 non-Workbench views)

*All views are clients of the same versioned protocol + `resource://oracle/*` (D2/D15 — no
frontend-specific business logic). Real-time panels ride SSE/`watch`; the rest are
request/response (TanStack Query). The 3 forks marked inline are all **RESOLVED** (FORK-1/2/3).*

- **① Overview (home).** *Purpose:* at-a-glance health + the live fleet (the daily driver,
  §4-WD.1). *Panels:* top summary band (sessions/agents/profiles counts · spectral health
  none/watch/warning/critical · capacity gauge · audit-chain ✓) → live-sessions list w/
  expand-detail → recent privileged actions (audit tail) → alerts + pending-Reviews count.
  *Real-time:* SSE (sessions, health, capacity, audit tail). *Actions:* jump to a session / CP.
  *Source:* `resource://oracle/health` + sessions stream + audit tail + proposals count. Fixed
  layout (no per-user customization in 0.6.0).
- **② Sessions (the control-plane wedge).** *Purpose:* full live control plane; drill-in +
  operator actions + history (Flow B). *Panels:* filter/sort session list (subject · transport ·
  profile · level · lane-state · current statement+elapsed · grant+TTL · capacity share) →
  drill-in detail → per-subject history. *Real-time:* SSE (statement/elapsed/state/TTL).
  *Actions (R3b = yes, gated+audited):* revoke grant · drain lane · force-release · watch (live
  tail). *Source:* sessions/lanes resource + watch. **[FORK 1 — RESOLVED (revised per Codex/I3)]:** the operator
  (review-authority) sees the full **SQL text** across the fleet, but **bind values are redacted by
  default** and shown only via an explicit **audited "reveal"** (resolves the **N-S6 / §7-DoD**
  conflict — binds are where sensitive data lives, and the reveal trail is itself a security
  feature; operator can still see everything, one audited click away). **Scoped non-operators see
  only their own** (D5). Implemented via the **`RedactionPolicy` seam defaulting to redact-binds**
  (D15) — a deployment can widen (trusted) or tighten (stricter PII) by config. v$session metadata
  via monitor-profile. *(Operator: revisit in production if too strict.)*
- **③ Schema (Oracle object browser).** *Purpose:* read-only explorer (tables/views/indexes/
  packages/procedures/functions/triggers/sequences/types) + object detail (columns, DDL,
  dependencies, find-usages) + the global search (#12, all types, toggleable). *Panels:* object
  tree → object detail → search. *Real-time:* mostly request/response (cache-backed, C5/W7;
  invalidate on DDL apply). *Actions:* open-in-Workbench · view DDL · find-usages · dependencies
  (no edits here). *Source:* read-only dictionary tools + metadata cache + plsql-intelligence.
  Shares the browser component with the Workbench sidebar (one component, two mounts — D15).
- **④ Audit (governance, tamper-evident).** *Purpose:* render the hash-chain. *Panels:* timeline
  (who/what/when/level/profile/outcome+`CancelReason`/object) · **chain-verify status** (✓ / ⚠
  break@seq N — DOC-5 detect-only) · filter (subject/profile/level/time/outcome/object) ·
  drill-to-evidence (full record + diff for edits + linked CP) · export. *Real-time:* live tail
  (SSE) + on-demand verify. *Actions:* verify · export · filter — **never edit/delete**
  (append-only). *Source:* the audit JSONL chain + verify. Export follows the active `RedactionPolicy` (FORK-1
  default = SQL text with **bind values redacted**; an **audited** operator reveal/override
  includes binds).
- **⑤ Capacity (metrics/ops).** *Purpose:* throughput · latency p50/p95/p99 · per-DB ceiling
  utilization · pool/bulkhead/circuit state · rate-limit/backpressure counters · lane epoch.
  *Panels:* time-series charts + gauges + counters. *Real-time:* SSE from the in-memory metrics
  ring-buffer (D14 Tier-0). *Actions:* none destructive (adaptive-cap targets live in Settings).
  *Source:* telemetry (W3). **[FORK 2 — RESOLVED]:** durable metric history =
  **append-only metric files we write ourselves** (roll per day; downsample on read), in 0.6.0,
  **self-contained — no DB, no Prometheus** (consistent with D14: it's files like everything
  else; metric volume ≈ a few MB/month). The live view reads the in-memory ring; trend charts
  read the files; old metric files are **prunable by a retention setting** (operational data —
  unlike the audit chain, never deleted). **OTLP/Prometheus export stays a free, OPTIONAL bonus**
  for orgs that already run a metrics stack — never required. (**redb/SQLite NOT adopted**; redb
  stays only a D14 escape hatch we don't need at this volume.) Durable *action* history is already
  the audit chain.
- **⑥ Settings (config/policy/creds/auth).** *Purpose:* config + policy + credentials + auth +
  flags. *Panels:* profiles & policy (max_level; `protected` ceiling immutable) · config editor
  (W2 draft→validate→atomic→rollback + diff) · credentials (per-client scoped: list/issue/rotate/
  revoke — E4/W10) · dashboard auth/pairing · feature flags (workbench, workbench-write,
  dashboard-bundle status). *Real-time:* request/response (config reload = W2). *Actions
  (dangerous, ERG-7 gated + audited):* edit config (dry-run/diff/confirm) · policy change · cred
  lifecycle. *Source:* config + cred store + policy. **[FORK 3 — RESOLVED (operator)]:**
  these are oraclemcp's **own per-client HTTP-access credentials** (E4/W10 — NOT Oracle DB
  creds). The dashboard manages credential **lifecycle + metadata** (list/issue/rotate/revoke,
  who-has-what, last-used), but **secret material is NEVER rendered in the browser** — a
  freshly-issued secret is delivered out-of-band via one-time pickup (`om creds show <id>` / a
  written 0600 file); the UI shows only "issued — retrieve via `om`." Honors D10.
- **⑦ Doctor (health/self-repair).** *Purpose:* render `om doctor` (§4-SK.4). *Panels:* findings
  (severity + the exact fix) · health detail (lanes/pool/circuit/spectral — doctor-framed) ·
  connectivity probes (`--online`: wallet/IAM/TCPS per profile, via 0.5.1 typed auth) · run
  history (`.doctor/runs`). *Real-time:* on-demand run + live health stream. *Actions:* run
  doctor (read-only) · run `--fix` (operator-gated; shows dry-run plan first, then backup+undo
  per DOC) · undo a run · view artifacts. *Source:* the doctor subsystem + `resource://oracle/
  health`. (`--fix` obeys DOC-3 scope: never touches Oracle/classifier/max_level.)

**Cross-view component reuse (D15):** the object browser (Schema ↔ Workbench), the diff viewer
(Workbench ↔ Audit ↔ Change-Review), the session row (Overview ↔ Sessions), and the health panel
(Overview ↔ Capacity ↔ Doctor) are **single shared components mounted in multiple views** — not
re-implementations. Adding a panel/column once surfaces it everywhere.

### 4-WD.6 Real-time data model & transport (SSE + POST)
- **Transport = SSE (server→client) + plain POST (client→server commands).** Already the plan's
  "static + SSE + POST" (§1). **No WebSocket** — we never need client→server streaming (commands
  are discrete POSTs: escalate, apply, operator actions); SSE's built-in auto-reconnect +
  `Last-Event-ID` is the exact fit and avoids WS-upgrade complexity on the asupersync HTTP server.
- **One multiplexed SSE connection per authenticated dashboard session**, server-filtered by the
  Subject's authorization (D5 — operator sees the fleet; a scoped principal sees only its own).
  Topics are event types on the one stream (one connection, one auth/lifecycle).
- **Push (SSE) vs pull (request/response):** *push* — `session_state`, `health`/spectral,
  `capacity_tick`, `audit_append`, `cp_event`, `lane_event`, `heartbeat`. *pull (TanStack Query)*
  — schema browser, object detail/DDL, search, config, version history, **metric history** (range
  reads over the append-only files, FORK-2), audit history (beyond the live tail), CP detail/diff.
- **Server-side = asupersync `watch` + `broadcast` (the §4-AS leverage, not hand-rolled pub/sub):**
  current-state topics (health, session-list snapshot, capacity gauge) ride **`watch`** (latest-
  value: snapshot on connect + deltas on change); event-log topics (audit appends, CP/lane events)
  ride **`broadcast`**. The SSE handler is just a subscriber that serializes to the stream.
- **Backpressure (bounded; never blocks another lane):** per-connection bounded buffer. `watch`
  topics **coalesce** (latest-wins → slow clients skip intermediate states, no buildup);
  `broadcast` overflow sends a **`gap` marker** ("missed N — refetch") instead of blocking — the
  client then pulls the missed range via request/response. (§4-AS.2 bounded-mailbox/CastOverflow
  discipline applied to the fan-out.)
- **Quiet by default (event-driven, not poll):** stream **state changes, not clock ticks** — TTL
  countdowns and elapsed timers run **client-side** from a start timestamp; the server pushes
  authoritative state on change + a low-frequency heartbeat (level-triggered desired-state, DL-6).
- **Reconnect:** EventSource auto-reconnect + **`Last-Event-ID`** → the server **replays**
  audit/CP events since that id (from the append-only files) and **resends the snapshot** for
  `watch` topics. No lost events, no full-page reload.
- **Stream auth (tightened per Codex I8/I9):** same-origin **httpOnly + SameSite session cookie**
  (D10 pairing→session) — EventSource can't set an `Authorization` header, so cookie auth is the
  fit. The SSE **GET** is validated like every other request: **Origin/Host check** + `Sec-Fetch-
  Site=same-origin` (with an Origin-allow-list fallback for clients that omit `Sec-Fetch-*`),
  **no CORS** (same-origin only). The **`Last-Event-ID` replay cursor is subject-bound** — a
  client can only resume *its own* event stream; cursors are validated against the session Subject
  so no one can replay another Subject's events by guessing an id. The stream is scoped per Subject
  (D5).
- **The one-time pairing ticket URL is a *bootstrap secret* (resolves the D10 "no secrets in
  URLs" tension):** it is short-TTL, single-use (exchanged once for the session cookie), marked
  `Referrer-Policy: no-referrer`, never logged, and never reused — it is the *only* sanctioned
  secret-in-URL, classified explicitly as a bootstrap credential, not a bearer token.
- **Cache coherence:** SSE events **invalidate** the matching TanStack Query caches (a
  `schema_changed` after a DDL apply invalidates schema/object queries; a `cp_event` invalidates
  the proposals list) — pulled data stays fresh with zero polling.

### 4-WD.7 Identity & signatures — "Ground Control" (APPROVED)
- **Concept = "Ground Control"** — Apollo-era mission control for your data-cosmos. Serious +
  awesome + *instantly legible*; authentic (a fail-closed multi-agent DB control plane literally
  is ground control).
- **Hero = the Orrery (full 3D, three.js / react-three-fiber + leva):** profiles/DBs as bodies,
  connected agents as **orbiting craft** (orbit/motion = activity, color = clearance, pulse =
  live statement), the operating-level ladder = the scene's light spectrum, the audit chain = a
  luminous trail, a GO/NO-GO = a visible burn/hold.
- **Signatures:** **GO / NO-GO** (the universal safety verb — giant green/red verdict + plain-
  English reason on every action; turns the fail-closed guard into the beloved ritual); **the
  Clearance Ladder** (a launch-readiness gauge for `READ_ONLY→ADMIN`, everywhere); **the Countdown**
  (T-minus on TTL/elevation windows, auto-revert); **the Logbook** (tamper-evident audit as a
  flight recorder + verify-seal).
- **5 legibility principles (the "serious, not a game" guarantee):** (1) fixed visual **grammar**
  (position=structure, color=clearance, motion=activity, glow=health); (2) **calm by default,
  alert on exception**; (3) the 3D is **framed by plain-language chrome** (a status band —
  "3 DBs · 4 agents · all GO · nominal" — + a persistent legend + a 2D toggle always one click
  away); (4) **progressive disclosure** (glance→state, click→detail, drill→session); (5)
  **instrument-grade restraint** (telemetry motion, professional palette, precise type). Plus a
  one-time **"power-on" orientation** that labels the parts on first load.
- **Craft:** our own small DS on shadcn/Radix/Tailwind tokens; a **bespoke clearance token
  model**; an **art-display face** (mid-century NASA-signage feel) + JetBrains/Berkeley mono for
  data/SQL; tasteful **CRT/phosphor + panel-grain** texture (command-deck, not Greek-stone);
  **GSAP locked** [operator-confirmed] — GreenSock Animation Platform, the pro JS animation
  library Hermes ships (`gsap ^3.15.0`); **100% free since 2025** (Webflow) for commercial use,
  but its **GreenSock "No-Charge" license is non-OSI** (no reselling GSAP / no GSAP-competitor —
  neither applies to us). Compliance (Codex I10): **add GSAP to the `deny.toml` allow-list** (as
  the project already does for the OpenAI/Anthropic rider) **+ a NOTICE/distribution line.**
  Split: **Framer `motion` (MIT) for ordinary component motion; GSAP for the Orrery's signature/
  showcase animation** — same split as Hermes. Dark-default + themes.
- **Mandatory 2D fallback** (a11y / no-WebGL / headless) — a **peer renderer** of the same data,
  never a special-case hack (also our own "never WebGL-only" rule).

### 4-WD.8 Skinnable, future-ready presentation architecture (D16)
*Operator directive: architect the whole visual system — including the 3D Orrery — to be
replaceable later and extensible ("skins"/"templates"). D15 applied to the frontend. Justified by
**present** needs, not speculation: the mandatory a11y/no-WebGL fallback is a **2nd renderer** on
day one and light/dark/colorblind are **multiple themes** on day one → extract the seam at 2+ real
cases. We build the contract + two renderers + the theme system; we do **not** build a runtime
plugin host (the deferred ambitious version, behind the seam).*

**Three layers, separated hard:**
1. **Semantic view-model (shared, stable).** Pure transforms from the protocol/`resource://
   oracle/*` (D2) → presentation-neutral typed facts: `FleetVM`, `SessionVM`, `AuditVM`,
   `ClearanceVM`, `GoNoGoVerdict` (`{clearance: READ_WRITE, status: working, activity: 0.7,
   health: nominal}`). No colors/DOM/three.js. Unit-tested once, skin-agnostic; the reuse point
   for any future non-web frontend.
2. **Skin (swappable).** A `Skin` = a **named preset binding {a Theme} + {a renderer choice per
   swappable surface} + {optional component overrides}** — *mostly declarative*, not a 40-component
   reimplementation; the base skin provides everything, a new skin inherits + overrides only what
   it wants. A skin takes view-models in, emits **semantic events out** (`onSelectSession`,
   `onRequestEscalate`) — **never business logic** (the app handles the classifier/apply).
3. **Theme (cheapest axis).** Typed tokens (clearance palette, type, texture, motion) → emitted
   as **CSS custom properties** (the verified Hermes ThemeProvider pattern) **and fed to the
   WebGL scene as uniforms** so the 3D respects the active theme. Most "re-skins" are just a new
   Theme — near-zero code.

**Renderer seam (the heavier axis):** hero surfaces go through a `BigBoardRenderer` contract —
`OrreryRenderer` (three.js) / `Board2DRenderer` (Canvas/SVG) / `TableRenderer` (a11y fallback) —
chosen by skin **and capability** (WebGL? reduced-motion? a11y mode?). The fallback is a **peer
renderer of the same `FleetVM`**, not a hack.

**3D quarantine:** three.js / r3f / leva live **only inside `OrreryRenderer`** (+ its shaders/
assets), **lazy-loaded / code-split** — the app never imports three; non-Orrery skins/builds pay
nothing; swapping three.js for another engine later touches only that module. (Pairs with D13:
the Orrery could even be its own sub-feature so a minimal build ships the 2D skin only.)

**Guards (so extensibility doesn't rot):**
- **Grammar is a contract, not a skin choice** — position=structure, color=clearance,
  motion=activity, GO/NO-GO, the ladder are fixed in the design-language spec + typed view-model;
  a skin maps them to visuals but **cannot redefine their meaning** → first-glance comprehension
  holds across every skin.
- **Skins are pure presentation** — enforced by the D15 dep-direction lint (skin modules import
  contract/view-model types only, never app/business/protocol) → a skin can't bypass the
  fail-closed guard.
- **Skin-conformance test (CI)** — every skin renders every surface for a fixed view-model
  fixture + provides every required signature component (type-checked + runtime check); the
  2D/table skin is golden/snapshot-tested (deterministic), the 3D is smoke + visual; each skin
  passes the a11y suite (a 3D skin must ship its fallback). Joins the release-acceptance CI.

**0.6.0 = built-in, build-time, code-split skins** (base 2D + Ground Control/Orrery 3D), selected
by config + user pref, lazy-loaded. **Runtime/third-party skins deferred** (YAGNI) — the seam
supports them, but they need a CSS/sandbox **security review** (arbitrary UI JS in a guarded
console); decision-rule: add only on real third-party-author demand. This is D15 for the
frontend, generalizing D2 to **"one view-model, many skins."**

---

## 4-CX. Codex triangulation — hardening (2026-06-30)

*A Codex (`gpt-5.5`) read-only adversarial review of the whole plan (multi-model-triangulation).
Disposition of all 18 findings below; inline fixes were applied where noted, and the remaining
design-gap directives are captured here (like §4-AS/§4-SK) to fold at beading.*

### 4-CX.1 New design-gap directives (fold into the noted WP)
- **CX-C1 (CRITICAL — cross-restart idempotency durability).** Grants/idempotency are in-memory
  (D14/N3), so a *committed* DML + service restart + client retry could **double-execute** (P1c
  admits this). **Directive:** add a **durable write-ahead intent record** — before executing any
  committing tool, append an `intent{idempotency_key, subject, lane, sql_hash, ts}` to a durable
  store (the audit chain / an append-only intents file); on restart, an unresolved intent ⇒ treat
  as **in-doubt → poison/quarantine + surface, never silently re-execute**. If we instead accept
  at-least-once, **document it explicitly**. **Bead → WP-N (N3/P1c) + WP-G.**
- **CX-C4 (read-worker lanes scoping).** N0a's read-worker lanes (CX-1) must not become a
  cross-principal pool. **Directive:** a read lane is **per (Subject, profile, DB)**; DB-native
  observation is self-lane or `monitor_profile` only (D5); every read lane carries the owning
  **Subject** for audit/fairness. No shared read pool that could mix principals. **Bead → WP-N N0a.**
- **CX-I5 (file-storage crash/concurrency/security contract).** D14/§4-WD.4 needs an explicit
  contract: **atomic write-tmp-then-rename + fsync(file) + fsync(dir)**; the single-writer
  **service lock** is mandatory for every mutation; **crash recovery** (skip/repair a torn tail,
  rebuild the index); **retention/rotation** for prunable data (metrics; never audit); and
  **path safety — never interpolate untrusted `profile`/`author` names into paths; use
  sanitized, length-bounded, or content-**hashed** IDs** (the `proposals/<profile>/<author>/…`
  layout is otherwise a traversal vector). **Bead → WP-S/WP-W + WP-G (security).**
- **CX-I6 (Phase-0 capacity spike — release-blocker).** The 16/8/64 caps (N4) and "51 lanes" (UX)
  are unproven for thread-per-lane. **Directive:** a measured Phase-0 spike derives defaults from
  real **Oracle sessions, fds, systemd `TasksMax`, per-thread stack memory, and tail latency**;
  the shipped defaults must cite that measurement. **Bead → WP-N (Phase-0) / DoD.**
- **CX-I7 (Phase-0 panic-isolation prototype — release-blocker).** D12 reverses `panic=abort`
  to `panic=unwind`. **Directive:** prototype `catch_unwind` + Drop + quarantine +
  audit around the lane `block_on` loop and **prove** containment (a lane panic doesn't abort
  siblings; the conn is dropped/quarantined; `unknown_discarded` is audited) **before** relying on
  it. **Bead → WP-N (Phase-0) / DoD.**
- **CX-Q1 (asupersync API appendix). ✅ RESOLVED (v3.18 → Appendix A).** The plan named many primitives
  (`watch`/`broadcast`/`Pool`/`bulkhead`/`circuit_breaker`/`epoch_tracker`/`cancel`/`supervision`/`lab`…)
  and once drifted (DPOR→seed-sweep). **Appendix A** now lists the exact import path + signature + a
  5-line prototype per release-blocking primitive, **source-verified against asupersync 0.3.4** (`file:line`
  cited), split baseline-vs-new. **It caught 5 name-vs-reality corrections** (Appendix A.11): `Pool`/
  `GenericPool` is **absent** (ceiling = `channel::mpsc`+`bulkhead`; **DL-7 fixed inline below**);
  `epoch_tracker` is mis-named for lane-generation (= a plain `u64`); `mask()`→`cx.masked`/
  `commit_section`; "tracked_channel"→`reserve`/`SendPermit`; `current_thread`≈2 OS threads/lane (CX-I6).
  Beads now cite Appendix A ids, not names. **Bead → WP-N.**
- *(Inline-fixed elsewhere: **CX-C2/C3** honest DML/DDL revert scope → WD-RULE-1; **CX-I8/I9** SSE
  Origin/Sec-Fetch + subject-bound replay + ticket-as-bootstrap-secret → §4-WD.6; **CX-I3**
  redact-binds-by-default + audited reveal → §4-WD.5 FORK-1.)*

### 4-CX.2 Disposition of all 18 Codex findings
| ID | Severity | Disposition |
|----|----------|-------------|
| C1 idempotency durability | CRITICAL | **Fix** → CX-C1 (write-ahead intent) |
| C2 DML "fully revertible" overclaim | CRITICAL | **Fixed** inline (WD-RULE-1 honest scope) |
| C3 DDL snapshot-undo too broad | CRITICAL | **Fixed** inline (WD-RULE-1 source-replaceable only) |
| C4 read-worker lane scoping | CRITICAL→tightened | **Fix** → CX-C4 |
| C5 not buildable as one 0.6.0 | CRITICAL | **Operator decision** → D1 **release train** 0.6.0/0.6.1/0.6.2 (one plan, no deferral) |
| I1 stale ground-truth (oracledb already 0.5.1) | IMPORTANT | **Fixed** inline (§1.2 refresh; WP-A re-scoped to validation) |
| I2 §4-R "default-on" vs D13 | IMPORTANT | **Fixed** inline (§4-R Decisions) |
| I3 redaction default vs N-S6 | IMPORTANT | **Fixed** → redact-binds-by-default + audited reveal (operator-confirmed) |
| I4 affected-row gate vs backlog | IMPORTANT | **Fixed** inline (count = IN gate; EXPLAIN-plan = backlog) |
| I5 file-storage contract | IMPORTANT | **Fix** → CX-I5 |
| I6 capacity numbers unproven | IMPORTANT | **Fix** → CX-I6 Phase-0 spike |
| I7 panic isolation unproven | IMPORTANT | **Fix** → CX-I7 Phase-0 prototype |
| I8 SSE security exactness | IMPORTANT | **Fixed** inline (§4-WD.6) |
| I9 ticket-URL vs no-secrets-in-URLs | IMPORTANT | **Fixed** inline (§4-WD.6 bootstrap-secret) |
| I10 GSAP license | IMPORTANT | **Operator: keep GSAP** + deny.toml allow-list + NOTICE (§4-WD.7) |
| I11 3D Orrery too central | IMPORTANT | **Operator: 3D default, 2D fallback** (already mitigated by D16 + mandatory 2D) |
| M1 §4-WD "in progress" stale | MINOR | **Fixed** inline (headers → complete) |
| Q1 asupersync API appendix | QUESTION | **✅ Fixed** → CX-Q1 → **Appendix A** (v3.18; +5 corrections, DL-7 fixed) |

**Codex overall:** internally consistent after these fixes, technically sound, buildable **as a
release train** (not one mega-0.6.0). Top residual risks Codex named: (1) thread-per-lane capacity
+ panic isolation are unproven → CX-I6/I7 Phase-0 spikes; (2) durable idempotency across restart →
CX-C1; (3) scope realism → resolved by D1's train.

---

## 4-GT. Ground-truth refresh + the 6 pre-bead gaps (2026-06-30)

*Empirical pass with `codebase-archaeology` (both repos) + `oracle` (the classifier). Resolves
the 6 gaps the operator + I flagged before beading. **Two findings reshape the plan's mental
model:** the fail-closed **guard already ships (0.4.1)**, and plsql-intelligence already has a
**designed seam** into it.*

### 4-GT.1 Gap 1 — oraclemcp ground-truth (refreshed against the moved repo)
- **Version = 0.4.1** (all crates); **`oracledb = "=0.5.1"` already pinned**; `panic = "unwind"`
  is now the CX-I7 lane-containment profile. So **§0/§1 "0.4.0 → upgrade to 0.5.1" was stale** — fixed.
- **The fail-closed core is SHIPPED** in **`crates/oraclemcp-guard`**: `classifier.rs` (104 KB),
  `levels.rs` (the `OperatingLevel` ladder + `DangerLevel`), `purity.rs` (3-valued purity),
  `policy.rs` (schema policy), `stepup.rs` (confirm-token step-up), `token.rs` (`AllowOnceStore`
  single-use grants), `enforcement.rs` — with adversarial-corpus + proptest + admin-DCL-fail-closed
  tests. **Mental-model correction:** WP-N does **not** build the classifier/ladder/grants — those
  exist; **WP-N builds the per-lane LANE layer *on top of* the existing guard** (lane owns
  {conn, lease, level, grants, budget, audit, cancel}; the guard is reused per-lane). Beads must
  say "wire the existing guard per-lane," not "implement the guard."
- **#4 may be partly done:** `timeout_ms` is already threaded through `collect_all_rows`/
  `fetch_cursor`/`read_lob` (`connection.rs`). **WP-B re-scoped:** verify per-batch enforcement +
  the shared-layer default + bounded ROLLBACK actually land; don't re-implement plumbing that
  exists. **WP-A = validation** (pin already landed). **Action:** re-verify #4 + #3 (`OracleCell`)
  state at beading; the §1.2 facts are now flagged.

### 4-GT.2 Gap 2 — classifier Oracle-semantics completeness (mature; one open tightening)
The classifier is **Oracle-aware and fail-closed** already: `DangerLevel` = **Safe** (proven
read-only SELECT/WITH, `DBMS_OUTPUT`), **Guarded** (INSERT/UPDATE-with-WHERE/MERGE/CTAS/`FOR
UPDATE`/COMMIT/EXPLAIN PLAN), **Destructive** (DROP/TRUNCATE/no-WHERE DML/GRANT/REVOKE/`CREATE OR
REPLACE`), **Forbidden** (string-concat dynamic SQL / `UTL_FILE` write / outbound network /
unconditional DDL-in-PLSQL / **unbalanced multi-statement batch — fail-closed on desync**).
FLASHBACK, autonomous txns, anonymous blocks, `EXECUTE IMMEDIATE` are modeled. `purity.rs`:
**only `ProvenReadOnly` clears to `Safe`; `Unknown` → side-effecting.** **Verdict: no classifier
hole found** (Codex C2/C3 were *workbench-revert* semantics, already fixed in WD-RULE-1). **The one
open item is the `SELECT`-side-effect tightening** — today a UDF-free SELECT stays `Safe` under the
default no-engine oracle (`Unknown` permissive *for SELECT only*); tightening it to fail-closed-on-
`Unknown` is **deferred until a real `SideEffectOracle` is bound** → that's Gap 6. **Bead:** add a
classifier-conformance corpus row per construct above; land the SELECT tightening *with* the engine
binding.

### 4-GT.3 Gap 6 — plsql-intelligence ground-truth + baking-in (the integration contract)
- **Ground-truth:** sibling repo **v0.7.0**, ~21 crates; **every engine crate is pure** (no
  `tokio`/`reqwest`/`hyper`/`axum`/`asupersync`/`oracledb`) → **consumable as plain library deps
  without tripping oraclemcp's no-tokio/asupersync boundary lint.** License `Apache-2.0 OR MIT`
  (already deny-allowed). [[sibling-plsql-intelligence]]
- **Two integration surfaces:**
  1. **The classifier's `SideEffectOracle` port (SAFETY CORE — highest value).** `purity.rs`
     already declares the seam; **plsql-intelligence binds the real purity oracle** over its
     `plsql-depgraph` + `plsql-lineage::column_writers` + the **trigger/VPD (`DBMS_RLS`) walk** →
     upgrades the classifier from syntactic + `Unknown`-fail-closed to **semantically-proven
     read-only** (fewer false refusals; catches SELECT side-effects via triggers/RLS the SQL never
     names) **and unlocks the Gap-2 SELECT tightening.** This is the deepest, most valuable bake-in.
  2. **The Workbench IDE features (0.6.1):** go-to-def, find-usages, dependency graph, lint
     (`plsql-sast`), refactor — consume `plsql-core/ir/parser-antlr/depgraph/symbols/lineage/sast`.
- **Contract:** pin `plsql-intelligence = "0.7.x"` (workspace dep); consume engine crates **only**
  (never `plsql-mcp`/`plsql-store` daemon/`plsql-doc` serve — oraclemcp has its own MCP/asupersync
  layer); bind the `SideEffectOracle` from oraclemcp's consumer side (the documented seam). **Train:
  the `SideEffectOracle` binding is 0.6.0-eligible** (it's the safety core, pure deps) — pull it
  forward if cheap; the Workbench features are 0.6.1. **Bead → WP-A/WP-N (oracle binding) + WP-W (IDE).**

### 4-GT.4 Gap 3 — operator-authority model (→ D17)
**D17:** "operator" is an **authority capability above a regular authenticated Subject** (D11),
required for: fleet-wide view, force-actions on other lanes (R3b), bind **reveal** (FORK-1), CP
approve/apply + 4-eyes, `om doctor --fix`, config/cred management. It is **never self-claimed** —
sources: the **loopback OS-user / local-pairing owner** (single-operator default) **or** an explicit
**operator allow-list** of verified Subject stable-ids / OAuth subs / mTLS fps in config. **Binary
for 0.6.0** (operator vs scoped principal); fine-grained operator-RBAC stays a **deferred non-goal**
(N4). Every operator action is **audited under the Subject**; a scoped principal can never escalate
to operator. Resolves R3b / FORK-1-reveal / CP-approval / doctor-fix / fleet-view consistently.

### 4-GT.5 Gap 4 — secrets-storage mechanism (→ D18)
**D18:** **Oracle DB credentials are external references, never stored by oraclemcp.** The profile
config holds a **reference** — an **env-var name**, a **file path** (wallet dir / key file), or an
**OS-keyring** entry — resolved at connect time via a **`SecretResolver` seam** (D15; future
vault/OCI-secrets backends plug in). The raw secret never enters oraclemcp's config file, **audit
chain, logs, telemetry, protocol, or UI** (N-S6 redaction newtypes enforce non-serialization).
Per-client **HTTP-access** creds (E4/W10) are **hashed at rest, shown once**; the dashboard manages
their lifecycle/metadata but **never renders secret material** (FORK-3). **Bead → WP-S/WP-G + WP-E.**

### 4-GT.6 Gap 5 — migration + backup/restore
- **0.4.x → 0.6.0 migration:** config is **additive/schema-first** (D15); the audit-chain JSONL is
  **append-only + format-versioned** (the existing chain continues; a `format_version` guards any
  change — never rewrite, DOC-5); new state dirs (`$XDG_STATE_HOME/oraclemcp`) are created on first
  run; **`om doctor` detects a legacy layout and offers migration**; an **upgrade note** (G2/N7)
  documents it. All file formats follow the same additive discipline (D15) so each train upgrades
  in place.
- **Backup/restore:** state is files (D14) → **`om backup` = snapshot `$XDG_STATE_HOME/oraclemcp`
  + config** (consistent: take the service lock / drain S5 first); **`om restore` = stop → restore
  dir → start**; the audit hash-chain lets restore **verify integrity**. Metrics files are prunable
  by retention (CX-I5); the audit chain is never pruned. **Bead → WP-S/WP-G.**

**Net:** all 6 gaps resolved or precisely scoped. The biggest positive surprise — the guard ships
already and plsql-intelligence has a ready safety seam — means **WP-N is a lane layer over an
existing classifier, and the deepest plsql-intelligence bake-in (the purity oracle) is a 0.6.0-
eligible safety upgrade, not just a 0.6.1 IDE nicety.**

---

## 4-RS. Final plan-space passes — reality-check + security-audit (2026-06-30)

### 4-RS.1 Reality-check (reality-check-for-project) — verdict: shippable; 4 steers
**Vision coverage complete:** every vision goal (G1–G7 + "interactive always-on / many DBs
isolated / many frontends / Subject-rooted audit & capacity") maps to a WP — no NO_BEAD-style
vision gap. The **train + the guard-already-ships finding make 0.6.0 genuinely shippable** (it's a
lane layer over an existing classifier + protocol + service + installer + read-only dashboard +
driver validation — bounded, not "3–4 releases"). **Steers (fold at beading):**
1. **WP-N is the long pole** — front-load **N0a** + the Phase-0 spikes (CX-I6/I7); keep 0.6.0 from
   ballooning (don't pull 0.6.1 forward except the cheap plsql-int purity-oracle binding).
2. **plsql-intelligence purity-oracle binding is NON-BLOCKING for 0.6.0** — the classifier is
   fail-closed (`Unknown`) without it; if the cross-repo binding slips, 0.6.0 still ships safe.
3. **Expectation-set:** 0.6.0 = **always-on + read-only control plane**; the SQL-Navigator-class
   **editing Workbench is 0.6.1**; the PR-board + 3D Orrery are 0.6.2. The title's "Interactive"
   lands *across the train*.
4. Companion **test beads** for every implementation bead (the reality-check + idea-wizard
   discipline) — N9/conformance/golden/skin/doctor-fixture already specified; ensure each WP-N/P/
   S/W bead names its test.

### 4-RS.2 Security-audit (security-audit-for-saas) — design strongly fail-closed; 7 hardening adds
*Applied the 10-axiom kernel + operators to the plan's security posture. The fail-closed core
(classifier `Unknown`→side-effecting, poison/quarantine, protected-pinned-READ_ONLY, single-use
lane-bound grants, derived-not-supplied Subject, no-auth=single-anonymous-lane) holds up well.
Adds:*
- **SEC-1 (Axiom 7 — recovery paths re-enforce; the one real gap).** **CP-apply re-classifies +
  re-checks level/grants/Subject at apply time; never trusts the stored proposal's verdict**
  (fixed inline in §4-WD.3). Generalize: migration runner, `om restore`, audit-replay, and the
  doctor all re-enforce classifier + level + audit + idempotency — recovery paths are a shadow
  codebase. **Bead → WP-W (CP-apply) + WP-S/WP-G.**
- **SEC-2 (Axiom 3 — normalize before validate).** The classifier **normalizes before classifying**
  (strip/normalize comments, case, unicode, whitespace, quoted identifiers) — the canonical form is
  the boundary. The adversarial corpus **must include normalization-bypass cases** (`/**/SELECT`,
  mixed-case, unicode look-alikes, comment-injection). Make it an explicit guard invariant. **Bead
  → WP-N (guard corpus).**
- **SEC-3 (Axiom 1 — no fail-open).** **Audit-write failure ⇒ fail-closed: refuse the privileged
  action.** The audit sink already fsyncs *before* the statement executes; state the contract so no
  future change makes audit best-effort. Likewise: `SideEffectOracle` unavailable ⇒ `Unknown` ⇒
  fail-closed; at-capacity ⇒ `AtCapacity` refuse; Redis/cache N/A (in-memory). **Bead → WP-N/WP-G.**
- **SEC-4 (Axiom 4 — self-heal down, never up).** The doctor, TTL revert, and any reconciliation
  **never re-grant, re-elevate, or un-revoke** — privilege drift always decays to READ_ONLY.
  **Bead → WP-G (doctor) / WP-N.**
- **SEC-5 (Axiom 8 — enumerate every surface).** Ship a **surface inventory + per-surface authn/
  gating** assertion: `/mcp`, `/operator/v1`, SSE GET, dashboard POSTs, the pairing endpoint,
  cred-issuance, CP-apply, config-reload, **OTLP/metrics export**, `/readyz`, the `om` CLI,
  installer/npx. **OTLP export + `/readyz` must not leak** (D5 monitor-scope; no v$session/metadata
  on an unauth surface). **Bead → WP-P/WP-G + the ERG-11 parity matrix.**
- **SEC-6 (Axiom 5 — every error is an oracle).** Auth/pairing failures are **uniform** (no
  client-id/profile enumeration oracle, no timing oracle); the MCP-1 educational refusals are fine
  for an *authenticated* caller but **must not reveal another tenant's profile/object existence** to
  a scoped principal. **Bead → WP-P.**
- **SEC-7 (Axiom 10 — multi-tenant isolation, belt-and-suspenders).** Isolation = the **lane model**
  (structural: per-Subject conn/level/grants; registry holds only handles) **+** the per-lane
  classifier **+** per-Subject audit. The **operator fleet-view is the only cross-principal path**
  (D17-gated + bind-redaction). **N9-K5** proves no cross-lane leak; add a 2-Subject test fixture.
  **Bead → WP-N (N9-K5).**

**Net:** no architectural security flaw; the adds are explicit invariants (SEC-2/3/4/6/7) + one
real correctness requirement (SEC-1 recovery-path re-validation). All fold into existing WPs.

---

## 5. Dependency DAG (summary)

```
A1 ─┬ A2 ─ C1            C0 ─ C1 ─ C2 ─ C3 ─ C4 ─ C4b ; C5
    ├ A3,A4,A5,A6
    ├ C0
    ├ B1 ─ B1b,B1c,B2 ─ B4    (B3 independent)
    └ R1 ─ R2 ─ R3 ─ R4
A0 ─────────────────────────► E2,E3,E7

WP-N:  N8 ─► N0a ─► N0 ─► {N1,N2,N3,N6,N7} ; N1 ─ N4 ─ N5 ; (N9 over N0a-N7)
N* ─► P1 ─► {P1b, P1c}        (P2 deferred)
P1 ─► S1 ─ S2,S3,S4,S5
P1 ─► W0 ─ W1 ─ {W2..W8,W10} ; W8 also needs WP-B,WP-C ; W8b ← W8,W5

A2,A3,A4,A6,C0,C1,C2,C3,R1,R2,N1,N2,N3,P1 ─► A7,A7b (api-lock + schemas, last)
E1 ─ E2,E3 ─ E4,E5,E6,E8 ; E1 ─ F1,F2,F3 ; S1 ─ E2
A7,WP-B,WP-C,WP-R,WP-N,WP-P,WP-S,WP-W,WP-E ─► G* ─ H1 ─ H2 ─ H3 ─ {H4,H5,F4} ; H1 ─ H7 ; H3 ─ H6
```
No cycles. **WP-N (esp. N0a + N3) is the foundation** — WP-P/S/W sit on it. stdio is
outside the graph. RC gates: alpha={WP-N/N9}, rc1={WP-P,WP-S,WP-E}, rc2={WP-W}.
**Note:** the `W0–W10` nodes predate §4-WD; at beading **WP-W expands to carry §4-WD.1–.8**
(Orrery/3D + skins, PR-board, plsql-intelligence wiring, global search, version history, SSE
model) — new W-beads hanging off the same `P1 ─► W0 ─► …` root, no new cross-WP edges.
**Release train (D1) maps onto this DAG:** **0.6.0** = WP-A/B/C/R/N/P/S/E/F/G-core/H + read-only
dashboard (Overview/Sessions/Audit/Doctor, 2D); **0.6.1** = Workbench + plsql-intelligence + full
views; **0.6.2** = PR-board + 3D Orrery skin + migration export. Same graph, sequenced delivery —
all beaded together. **Phase-0 spikes (CX-I6 capacity, CX-I7 panic) gate 0.6.0.**

---

## 6. UX
- **stdio (unchanged):** agent spawns `oraclemcp serve` → own process/DB/level.
- **http service:** `oraclemcp service install` (with `--service`/consent) → always-on
  (systemd+linger); agents connect over HTTP, **each in its own lane**; the human opens
  the **web dashboard** (`om dashboard`; `om` = short CLI alias). 50 agents on 50 DBs +
  a human = 51 isolated lanes.
- **Install:** `curl … | bash` / `irm … | iex` / `cargo binstall` /
  `brew` / `winget` / Docker. (npm/npx channel excluded from 0.6.x.)

## 7. Definition of Done (gates — cumulative across the D1 release train)
> **Train scoping (D1):** the list below is the **cumulative** Definition of Done for the whole
> plan. Each train ships its slice: **0.6.0** must pass items 1–3, 5–10 **plus the Phase-0 gates**
> (capacity + panic + durable idempotency) and the **read-only dashboard** subset of item 4;
> **0.6.1** adds the Workbench + full-views gates in item 4; **0.6.2** adds the PR-board + Orrery.
> The fail-closed safety core (items 1–2) ships **whole in 0.6.0** and is never partial.
> **Each gate below is operationalized by the named tests in Appendix B** (per-WP acceptance-test specs,
> by modality, mapped to the real test files); **Appendix A** is the verified asupersync API every WP-N
> bead cites. The unified **release-acceptance CI suite** (Appendix B.12) is the machine gate.
1. **#2/#3/#4/#5 closed**; invariant intact; no agent-facing `call_routine` (R3 lint,
   both crates); **no caller-supplied identity affects audit/grants/capacity** (N7 neg
   test); **legacy confirm-MAC retired — the server-side grant is the only confirm path
   (N-S1); every committing tool incl. compile/patch appends audit (N-S2); monitor/
   `v$session` SQL is read-classified + audited (N-S3); all new surfaces redact
   allow-list-first (N-S6)**.
2. **WP-N: the full N9 contract passes** (A–K incl. grant non-replay + generation
   binding, MCP-lifecycle J, capacity+operator-reserve D, state-machine K). N8 guard
   present until N0a-N3 land. Set in stone — any N9 regression blocks release.
   **Phase-0 gates (Codex, block 0.6.0): (a) measured capacity spike** justifying the
   16/8/64 defaults (CX-I6); **(b) panic-isolation prototype** proving `catch_unwind`/drop/
   quarantine/audit containment (CX-I7); **(c) durable write-ahead idempotency** so a
   committed DML cannot double-execute across restart (CX-C1).
3. WP-P versioned + **schema-first** (generated schemas, fixtures validated in CI);
   idempotency ledger (P1c); loopback-default + browser-auth model.
4. Web dashboard: browser-safe auth (CSRF/Origin/CSP/cookie/no-localStorage tests);
   config **draft/apply** (atomic + reload-drain); dashboards/health/audit(+DB
   evidence); **Safe SQL Workbench gated behind `dashboard_workbench`** with no-bypass +
   audit/idempotency tests — **if it misses the bar, the dashboard ships without it,
   unadvertised.** Per-client credential revoke/rotate (W10). **Skinnable arch (D16): skin-
   conformance test green + mandatory 2D/no-WebGL fallback + a11y suite; Orrery 3D
   lazy-loaded/code-split (bundle-size budget); credential secrets never rendered in the browser.**
5. Service: reboot-surviving (linger); `/readyz`+sd_notify; single-instance; loopback;
   **safe config reload/drain** (S5).
6. Driver `=0.5.1`; seam green; api-lock re-baselined last; **all changed public MCP
   tools + operator routes have output schemas + schema-validation tests**.
7. Installer: shellcheck/PSSA + CI smoke (built artifact); SHA256 + cosign +
   **provenance**; **no service/client mutation without `--service`/consent**;
   **per-client scoped credentials** (no shared bearer); npx no postinstall side
   effects; uninstall reverses all; triples match assets.
8. Matrix 7 targets incl. aarch64-musl (musl static-verified), signed, SBOM'd; no
   git/path deps; conformance 100%; **live-XE incl. multi-lane**; perf re-measured.
9. README one-liner-first; CHANGELOG + upgrade note; threat-model (per-lane, Subject,
   browser, no-PTY, installer) + SECURITY/config current; honesty-grep green.
10. server.json version+identifier + schema-validate; clean-machine e2e; rollback ready.

## 8. Risks & mitigations
| Risk | Mitigation |
|---|---|
| Lane treated as just a lease (cross-leak) | N0a `LaneRuntime`/`LaneContext`; K5 test |
| Single global dispatch executor bottleneck | N0a forces explicit runtime topology; N6; N9-C1 |
| Caller-supplied identity spoof (`agent_identity`) | D11 Subject; N7 negative test; ignore arg labels |
| Grant replay / double-execute | N3 single-use server-side grants + P1c idempotency; A4/A6/G4 |
| Disconnect rolls back a valid long op | N5 MCP semantics (disconnect≠cancel; DELETE/cancel explicit) |
| Browser-origin attack on loopback dashboard | D10 pairing+CSRF+Origin+CSP+cookie; W1 tests |
| Shared bearer destroys audit | E4 per-client scoped creds + W10 revoke/rotate |
| Capacity DoS / no operator lane under load | N4 adaptive caps + reserved operator/doctor lanes; D5 |
| Uncertain DB outcome reused | B1c poison/quarantine + revoke grants |
| Config write strands the service | W2 draft/validate/atomic/rollback + S5 drain |
| v$session metadata leak | D5 monitor_profile/self-lane + redaction; degrade gracefully |
| Unfinished workbench delays the safety core | D1 RC gates; W8 behind `dashboard_workbench` flag |
| stdio regression | N10; F1/F2 golden + coexist tests |
| 3D Orrery unavailable (no WebGL/headless) or bloats the bundle | D16 mandatory 2D fallback (peer renderer) + capability detection; lazy-load/code-split + D13 bundle-size budget; three.js quarantined in OrreryRenderer |
| Visual identity hard to change later | D16 skinnable seam (view-model/skin/theme/renderer); grammar is a contract; skin-conformance CI |

## 9. Decisions — RESOLVED (2026-06-29)
0.6.0 · React/Vite SPA (TanStack+shadcn, embedded, no runtime Node) · `om` + npm
`oraclemcp` · **audit = verified Subject** (no `HumanOperator`, no self-supplied id) ·
capacity = two-tier **16/8/64 ceilings, adaptive + operator-reserved** · Homebrew +
winget (Scoop dropped), Docker amd64-only · **no TUI in 0.6.0** (ftui deferred) · attach
= loopback TCP only (UDS deferred) · per-client scoped credentials (no shared bearer) ·
service/registration **explicit-consent** · Safe SQL Workbench (not a terminal),
flag-gated.

**Added 2026-06-30 (D13-resolution → D16 + §4-WD):** dashboard ships **full in product
artifacts**, `dashboard-api` default-on-but-inert, **feature-powerset CI** · **D14 persistence =
files-first, pure-Rust, never SQLite** (metrics = live ring + append-only history files; redb only
behind the `Store` seam if ever needed) · **D15 design-for-cheap-change enforced** (deps-inward,
trait-seams, arch-fitness CI, every-bead DoD) · **D16 skinnable dashboard** (view-model / skin /
theme / renderer). Dashboard (§4-WD): **Mission-Control** shape · **8 views phased across the
train** (0.6.0 read-only core · 0.6.1 Workbench/views · 0.6.2 PR-board/Orrery) ·
Workbench = **governed PL/SQL IDE** (writes via the ladder behind an opt-in flag, never
`protected`; WD-RULE-1 DML-uncommitted vs DDL-snapshot-undo) · **"PR for PL/SQL"** Change-Review
board (per profile/author) · real-time = **SSE + watch/broadcast** · identity **"Ground Control" +
Orrery (full 3D three.js, GSAP locked)** with a **mandatory 2D fallback** · per-client HTTP-cred
**secrets never rendered in the browser**.

**Added 2026-06-30 (Codex triangulation → §4-CX):** **D1 = a release train 0.6.0→0.6.1→0.6.2**
(one plan, beaded together, built continuously, **no deferral**) · **redact bind values by
default + audited operator reveal** (revises FORK-1; reconciles N-S6/DoD) · **GSAP kept**
(deny.toml allow-list + NOTICE) · **3D Orrery default / 2D fallback** · honest DML/DDL revert
scope (WD-RULE-1) · ground-truth refreshed (**oracledb already `=0.5.1`**, WP-A = validation) ·
Phase-0 **capacity + panic** spikes and **durable write-ahead idempotency** are 0.6.0 DoD gates.

## 10. Beads conversion plan
Epic `oraclemcp-060-epic`; sub-epics (a,b,c,r,**n**,**p**,s,w,e,f,g,h — no wp-t); deps
from §5; self-contained beads; `br sync --flush-only` before committing `.beads/`.
`…-wp-h` blocked-by §7 DoD beads. **WP-N (N0a/N3/N9) gets the most granular beads + the
hardest review.** Deferred idea beads (status=deferred): ftui TUI, operator UDS socket.
Run idea-wizard Phase 5 only after steady-state. **D15 (cheap-change) is mandatory in every
implementation bead's DoD** — name the applicable rule (trait seam / deps-inward / pinned
contract test) per bead; the arch-fitness lint + feature-powerset + the release-acceptance CI
suite are themselves beads under WP-G/WP-H. **Dashboard beads (WP-W) carry §4-WD.1–.8** (shape/nav,
Workbench, PR-board, persistence, per-view specs, SSE model, identity, skinnable arch); the 3 forks
(FORK-1/2/3) are **resolved** (§4-WD.5, v3.14). **D16 (skinnable) is mandatory in WP-W bead DoD** —
view-model/skin/theme separation, 3D quarantined, skin-conformance + 2D-fallback + a11y tests.
**Appendix A + B are now beading inputs:** every WP-N/P/S bead **cites the verified asupersync API by
Appendix-A id** (e.g. "lane mailbox = A.3; per-DB ceiling = A.9 `bulkhead`, NOT `Pool`") so implementers
reach for the real API; every implementation bead carries its **Appendix-B test bead** as a DoD-edge
dependency, tagged by modality + the real file it extends. The release-acceptance CI suite (Appendix
B.12) + the Phase-0 spikes (B.5) are themselves beads under WP-G/WP-H/WP-N.

## 11. Review log
- **Round 0 (v1):** initial one-big-release structure.
- **Round 1 (v2):** grounded the session model in code; added WP-N + WP-P; web
  dashboard primary; stdio untouched.
- **Round 1.1–1.2 (v2.1/v2.2):** web stack locked (React/Vite); N9 contract set in
  stone; all operator decisions resolved (web-only, capacity A, UDS/TUI deferred,
  login audit, Homebrew+winget).
- **Round 2 (v3, this revision) — GPT-Pro extended-reasoning review integrated (20
  patches):** LaneRuntime/LaneContext (N0a) above the lease; **authenticated Subject**
  (D11) replacing caller-supplied identity; **single-use lane-bound grant store** (N3)
  + idempotency ledger (P1c); MCP Streamable-HTTP lifecycle semantics (N5, J-tests);
  **adaptive caps + operator reserve** (N4, kept the operator's 16/8/64 as ceilings,
  not GPT's 4/4/32); **poison/quarantine** (B1c); monitor-profile-scoped observability
  (D5/W4); **browser-safe dashboard** (D10/W1); **per-client scoped credentials +
  revocation** (E4/W10) replacing the shared bearer; **schema-first operator protocol**
  (P1/P1b) + output-schema release gate (A7b/C4b); **Safe SQL Workbench** (W8/W8b)
  replacing the "live console"; metadata cache (C5/W7); transactional config + safe
  reload (W2/S5); DB-native audit evidence (N7/W5/G9); deterministic lane state-machine
  tests (N9-K); RC gates (D1); explicit-consent + provenance installer (D8/E2/F2);
  closed #5 bookkeeping. **Author's adjustments to GPT Pro:** kept user-chosen capacity
  numbers as the ceiling (adaptivity layered on); verified #5 exists before referencing.
- **Round 3 (v3.1, this revision) — inline self-review (5 lenses; the multi-agent
  panel hit the account spend limit and returned no findings, so the author ran it
  inline).** Verdict: **no correctness showstopper; foundation feasible.** Applied:
  **thread-per-lane topology** (resolves the asupersync concurrency crux — non-`Send`
  futures moot, proven by the load/soak per-client pattern); **no-auth = single
  anonymous lane** (multi-lane requires auth); **in-memory grant/idempotency store
  with the audit chain as the durable record**. Refinements to fold at beading: mTLS
  cert-fp as a Subject source; N9 tests `scope-cannot-raise-ceiling` +
  `read-flood-doesn't-starve-stateful`; per-lane/per-Subject telemetry tagging (W3
  metric source); G2 upgrade note for per-lane `switch_profile`; per-client creds
  stored **hashed** (shown once); winget 'submit, may land post-tag'; npx wrapper via
  **npm provenance** + verifies the binary's cosign sig; A7b depends on P1;
  embedded-SPA binary-size check in preflight. **Operator decision: NO scope deferral
  — everything stays in 0.6.0** (the recommended 0.6.1 cut list was declined).
- **Round 4 (v3.2, this revision) — multi-agent panel, 3 of 5 reviewers completed**
  (installer/ops, feasibility/DAG, security; the other 2 — concurrency, protocol — hit
  the account spend limit twice and were restarted with **disk-journaling + resume + no
  sub-spawn** to survive resets). All findings code-verified. **Verdict: architecture
  sound, but v3 was incomplete on safety + infrastructure.** Integrated into §4-R: 6
  safety beads (incl. **CRITICAL** N-S1 retire-confirm-MAC + N-S2 audit-all-committing-
  tools), 3 missing-foundation nodes (streaming SSE, Subject-aware audit rebuild,
  per-lane telemetry), the **N0a split** (transport/runtime rewrite + connection↔lane
  handoff — the real long pole), accept-layer bound, config-ops extraction, `web-build`
  CI, JS SBOM, per-client cred store, systemd hardening, + ~20 marginals + DAG fixes.
  Decisions **D12** (panic=unwind + per-lane catch_unwind) and **D13** (dashboard =
  default-on cargo feature) applied as best-engineering defaults.
- **Round 4 — COMPLETE (5/5 lenses).** The 2 journaling reviewers landed (journaling +
  resume survived the spend-limit resets): **protocol R1-R9** (transport/router redesign
  FN0; session↔Subject binding N-S7; durable idempotency) and **concurrency C-1-C-6**
  (the **LaneRuntime = registry of mailbox-handles, not a map of connections** refinement;
  connection reactor-affinity → all conn-ops marshaled to the owning lane thread;
  watchdog reaping; lease epoch; switch-profile conn-swap state machine). All integrated
  in §4-R. **Key architectural output:** the lane is an OS thread owning {runtime, reactor,
  conn, lease, level, grants} + a control mailbox; the central registry holds only handles.
- **Round 5 (v3.3) — Codex cross-model triangulation (multi-model-triangulation skill).**
  Codex `exec` (read-only, code-grounded) independently reviewed the plan + decisions →
  verdict needs-changes, **converging with the panel** and adding CX-1..CX-5 (read-worker
  lanes not a shared pool; panic=quarantine-not-rollback; dashboard-api/-bundle split;
  transport-layer capacity reserve; retire confirm compat path) — all adopted (§4-R
  Codex block; D12/D13/N0a fixed). Consensus: HIGH.
- **Verdict — review-complete, beadable.** Architecture sound and now safety-complete;
  **GPT Pro + a 5-lens code-verified panel + a Codex cross-model triangulation (all
  converging, consensus HIGH) passed.** Remaining is execution discipline, not redesign. The panel reframed 0.6.0 as "3-4 releases' worth" — all-in per operator; the
  Phase 0-4 build order is the schedule discipline. **Next: convert to the
  `oraclemcp-060-epic` bead graph (idea-wizard Phase 5, `br`), front-loading WP-N safety +
  the foundations.**
- **Round 6 (v3.5) — asupersync leverage assessment (asupersync-mega-skill) + Codex
  triangulation.** Found oraclemcp under-leverages its base runtime; added **§4-AS** —
  build WP-N on native `channel`/`cancel`/`supervision`/`scope`/`lab`/`combinator`/
  `epoch_tracker` instead of hand-rolling, MT-runtime-for-transport + per-lane
  current-thread DB loops. Codex correction folded in: `Actor`/`GenServer` are `Send`-
  bound → lane = supervised **Send `LaneHandle`** + thread-pinned `block_on` loop owning
  the `!Send` conn; conn never leaves the thread; DPOR softened to lab injection +
  seed-sweep; C-6 (idle vs in-flight cancel) confirmed.
- **Round 7 (v3.6) — asupersync leverage, second pass (LEVERAGE-PLAYBOOK / BUDGET-
  OUTCOME-CAPABILITIES / SUPERVISION-OTP deep read).** Added **§4-AS.2**: the semantic +
  app-topology layer pass 1 missed — **AppSpec/supervision tree** (not bare
  `RuntimeBuilder+block_on`) with `RestartPolicy` (OneForOne lanes / RestForOne ordered
  children) + registry **name-leases** for the lane registry + `AppHandle`-as-obligation
  shutdown; **Outcome four-valued** preserved to the MCP/HTTP edge + structured
  **`CancelReason`** recorded in the audit chain; **`Budget.meet()`** (deadline+poll+cost)
  replacing #4's three ad-hoc timers; **`mask()`+bounded budget** for the rollback/audit-
  commit finalizers (protects fail-closed+rollback under shutdown cancel); obligation-
  tracked **reserve/commit** mailbox + **permit-backed** per-DB ceiling + deliberate
  `CastOverflowPolicy`; **`ServiceBuilder`** ingress (concurrency_limit/load_shed/
  rate_limit/timeout); **`cap::None`** pure classifier + narrowed lane `Cx`; N9
  **quiescence/obligation-leak/futurelock** oracles + crashpack/seed artifacts. Recorded
  deliberate N/A: hedge/quorum/remote/RaptorQ/QUIC/Browser (single backend, not in scope).
  Additive — strengthens the safety contract, no redesign.
- **Round 8 (v3.7) — four skills applied in depth → §4-SK skill-informed hardening.**
  Operator ran `deadlock-finder-and-fixer`, `mcp-server-design`,
  `agent-ergonomics-and-intuitiveness-maximization-for-cli-tools`, and
  `world-class-doctor-mode-for-cli-tools` against the plan + code ground-truth. Added **§4-SK**
  with four subsections of actionable beads/tests/CI-lints/code-rules: **§4-SK.1 (DL-1..DL-10)**
  — reconciled `block_on` with the `!Send` lane (supervised dedicated thread, never nested),
  canonical lock order Config→Registry→Lane→Lease→Grants→Audit→Metadata, level-triggered
  cancel (no lost wakeups), parking_lot/transaction-style to avoid D12-unwind poisoning,
  Pool+bulkhead+rate_limit per-DB ceiling (upgrades §4-AS.2's raw semaphore), lab quiescence/
  leak/futurelock oracles for N9, `concurrency-audit` CI lint (The Fourth Instance);
  **§4-SK.2 (MCP-1..MCP-14)** — educational structured refusals, capability-gated `tools/list`
  by effective ceiling + `tools/list_changed`, discovery resources, escalation macro that never
  auto-confirms, DEVIATION MCP-13 (coerce cosmetic / strict on safety overrides the skill's
  forgive-by-default); **§4-SK.3 (ERG-1..ERG-12)** — `om` Polish-Bar gates (stdout=data, exit-
  code dict, `--json` everywhere, `capabilities`/`robot-docs`, error pedagogy, dangerous-op
  gating, determinism, never-silent-fail), MCP↔CLI↔dashboard parity matrix, agent-ergonomics
  drift-guard CI; **§4-SK.4 (DOC-1..DOC-11)** — scoped self-repair (HARD non-goal: never touch
  Oracle / classifier / max_level), audit-chain **detect-only never repaired**, RULE-1
  quarantine-not-delete, offline-default + `--online` connectivity via 0.5.1 typed auth,
  `om doctor` = the WP-N spectral/lane health window, unified **release-acceptance CI** (DL-9 +
  ERG-10 + DOC-10 + §4-R web-build). All additive; reinforces — does not weaken — the fail-
  closed safety invariant (DOC-3/DOC-5/MCP-13 are new safety strengtheners).
- **Round 9 (v3.8) — dashboard design, collaborative (idea-wizard, sketch-first) → §4-WD.**
  Built interactively with the operator. **Locked:** R1 shape = **Mission Control** (home leads
  with live sessions: agent · profile/DB · level · activity + summary band + expand-detail); R2
  nav = **all 8 views in 0.6.0** (Overview/Sessions/Workbench/Schema/Audit/Capacity/Settings/
  Doctor; Workbench flag-gated). **Workbench reframed as a governed PL/SQL IDE** for the
  human-in-the-loop (SQL-Navigator-class), with the key thesis **no fail-closed exception —
  the guard is the feature** (lane isolation + pinned-conn interactive txn + classifier + ladder
  + audit + snapshot-undo make it safer *and* more powerful than SQL Navigator). **WD-RULE-1**:
  DML = "Applied (uncommitted, Rollback/TTL-auto-revert)" vs DDL = "Applied (committed; Revert
  re-applies prior source snapshot)" — UI must label which, always. **Decided IN 0.6.0:**
  governed edit loop, **plsql-intelligence wired in (now offline)**, **Change-Review board "PR
  for PL/SQL"** (per profile/DB, Git+Cursor-informed — detailed design next), lightweight
  blast-radius guardrails, object version-history+revert, live compile, **global DB search (all
  object types, toggle)**. **Proposed-in (confirm):** schema diff + migration export. **Backlog:**
  formatter (verify plsql-intelligence), EXPLAIN/affected-rows, multi-tab editor. **Resolved:**
  R3a → browser writes/DDL on via the ladder behind an opt-in flag (operator Subject, per-profile
  max_level, never protected); R3b → operator force-actions yes (gated+audited). **Still open:**
  the PR-board detailed flow, visual style (R4), per-view specs, real-time data model.
- **Round 10 (v3.9) — persistence decision (D14) + PR-board scoping locked.** Operator asked
  "SQLite, disk, or am I overcomplicating?" Verified the codebase: **zero embedded-DB deps;
  audit chain is already append-only JSONL**. Decision **D14 + §4-WD.4**: **files-first,
  pure-Rust-only, never SQLite** (rusqlite = C dep + C toolchain + unsafe FFI → violates
  AGENTS.md pure-Rust/no-C + forbid-unsafe). Tiered model: RAM (grants/idempotency/metrics) ·
  append-only/content-addressed files (audit chain, doctor artifacts, **DDL source snapshots**)
  · files+manifest for structured/queryable (CPs, version-history index) → pure-Rust `redb`
  only if it outgrows files. On-disk layout under `$XDG_STATE_HOME/oraclemcp/`. **PR-board
  scoping locked:** keyed **(profile, author=agent|human)**, multiple **named** CPs, surfaced in
  Mission Control (toggle into an agent's proposals) + a global Reviews filter; one CP = one
  profile; D5 visibility; `proposed` CPs are **stateless on disk** (lane acquired only at apply).
  **5b confirmed IN** (schema diff + migration export).
- **Round 11 (v3.10) — PR-board apply-flow resolved (§4-WD.3).** **(a)** apply unit = per-object
  (DDL) / per-statement-or-grouped-txn (DML), forced by Oracle (DDL auto-commits); per-hunk =
  compose/review only; **honest atomicity** — multi-DDL is sequential/stop-on-failure + per-object
  snapshot-revert (no false all-or-nothing); subset-apply allowed, per-item status, derived CP
  state. **(b)** agent DML proposals stored as **parameterized SQL + captured binds** (never
  literals; classifier classifies the template; grid edits auto-key on PK; guard blocks
  no-unique-key). **(c)** notifications ride existing channels — operator via dashboard SSE
  (Reviews badge/toast), agents via `resource://oracle/proposals` poll + best-effort MCP
  notification; external (email/Slack/webhook) = backlog; audit chain records every transition.
- **Round 12 (v3.11) — D15 (cheap-change principles, enforced) + §4-WD.5 (all 7 per-view
  specs).** Operator directive: correct coding patterns/principles from the start so later
  extension/refactor is cheap. Captured as **D15** (deps-point-inward clean-architecture;
  trait-seams exactly where change is expected [storage/transport/classifier/doctor/object-
  handlers]; one-core-many-faces; schema-first additive; pure domain + single-owner state;
  tests-pin-contracts as the refactor safety net; no compat shims) — **enforced** via an
  arch-fitness lint in the release-acceptance CI + named in every bead's DoD. **§4-WD.5** specs
  Overview/Sessions/Schema/Audit/Capacity/Settings/Doctor (purpose · panels · real-time vs
  request · operator actions · source) + cross-view shared components. **3 forks flagged for
  operator:** FORK-1 Sessions/Audit binds-redaction (recommend: SQL text visible to operator,
  binds redacted-by-default w/ audited reveal); FORK-2 Capacity metrics retention (recommend:
  in-memory window + OTLP/Prometheus export, no in-app TSDB); FORK-3 Settings credential
  issuance (recommend: lifecycle/metadata in UI, **secret never rendered in browser**, one-time
  pickup via `om`).
- **Round 13 (v3.12) — 3 dashboard forks resolved + persistence senior call.** **FORK-1:**
  operator (review-authority) **sees everything** (full SQL + binds; simpler than redaction);
  scoped non-operators see only their own (D5); redaction = a **default-off `RedactionPolicy`
  seam** (D15), not built for 0.6.0. **FORK-2:** metrics = **in-memory live window + OTLP/
  Prometheus export**, **no in-app TSDB**; behind the telemetry/`Store` seam so redb rollups can
  be added later only if a zero-external-tooling appliance requirement emerges; durable *action*
  history is already the audit chain. **FORK-3:** these are oraclemcp's **own per-client HTTP
  creds** (not Oracle DB creds) — lifecycle/metadata in UI, **secret never rendered in browser**,
  one-time pickup via `om`. **D14 strengthened with the senior answer:** no DB needed even for
  future additions — heterogeneous data behind a **`Store` trait seam** (swap files→pure-Rust
  `redb` with zero caller churn if ever needed) + an explicit **decision-rule** for when an
  embedded DB is warranted (multi-node / complex relational / high-write TSDB→Prometheus /
  multi-writer-txns — none true for 0.6.0). SQLite stays out regardless (C dep).
- **Round 14 (v3.13) — FORK-2 corrected to files (operator caught an inconsistency).** The prior
  round drifted toward redb-for-metrics, which contradicted D14's files-first stance. Corrected:
  **durable metric history = append-only metric files we write ourselves** (roll per day,
  downsample on read, prunable by retention) — self-contained, no DB, no Prometheus, consistent
  with "it's all files." OTLP/Prometheus export stays a free OPTIONAL bonus. **redb/SQLite NOT
  adopted**; redb remains only the named D14 escape hatch (not needed at metric volume ≈ few
  MB/month). It is now literally files all the way down: audit · config · snapshots · proposals ·
  metrics.
- **Round 15 (v3.14) — DASHBOARD DESIGN COMPLETE (§4-WD.6/.7/.8 + D16).** **§4-WD.6** real-time:
  SSE (server→client) + POST (commands), one multiplexed stream, server-side asupersync
  `watch`+`broadcast`, bounded backpressure w/ gap-markers, client-side timers, Last-Event-ID
  resume, cookie auth, SSE-invalidates-Query cache. **§4-WD.7** identity **"Ground Control"** —
  Apollo mission-control; hero = the **Orrery** (full 3D three.js/r3f); signatures **GO/NO-GO**,
  **Clearance Ladder**, **Countdown**, **Logbook**; 5 legibility principles (fixed grammar /
  calm-by-default / plain-language chrome / progressive disclosure / instrument-grade restraint)
  + power-on orientation; **GSAP locked** (Hermes parity → deny.toml allow-list); art-display
  type + CRT/phosphor texture; mandatory **2D fallback**. **§4-WD.8 + D16** skinnable architecture
  (operator directive): view-model (shared) / **skin** (named preset = theme + per-surface
  renderer choice + overrides; pure presentation) / **theme** (CSS vars + WebGL uniforms);
  `BigBoardRenderer` seam (Orrery↔2D↔table by capability); **three.js quarantined** in
  OrreryRenderer (lazy/code-split); **grammar is a contract** across skins; skins-pure dep-lint +
  skin-conformance CI; built-in code-split skins in 0.6.0, runtime/third-party skins deferred
  (security review). Justified by present needs (a11y fallback = 2nd renderer + light/dark/
  colorblind = multiple themes → seam built at 2+ real cases, not speculative).
  **Hermes research (research-software):** confirmed its recipe = own DS (`@nous-research/ui`,
  LENS_N themes) + bespoke fg/mid/bg token model + art-display fonts + grain + real 3D (r3f/
  three) + gsap/motion + xterm + QR pairing; "rough surfaces" = grain overlay + 3D PBR roughness.
  We took the *technique*, not the look.
- **Round 16 (v3.14, fixes-only) — fresh-eyes consistency pass (operator-requested).** Full
  reread; fixed 8 drift items, no decisions changed: (1) stale status-block tail ("panel loop
  pending" → review-complete) + skills list refreshed; (2) added non-goal **N13** (doctor
  self-repair never touches Oracle/audit-chain/classifier/`max_level` — the DOC-3 promise to §2);
  (3) **D14** metrics corrected to live-ring **+ durable append-only files** (had said
  "in-memory only", contradicting FORK-2); (4) §4-WD.5 intro ("forks flagged"→resolved) +
  Audit-export reconciled to FORK-1 ("operator sees everything / redaction default-off"); (5)
  **§9** updated with the 2026-06-30 resolutions (D13-res, D14–D16, full dashboard); (6) **§10**
  WP-W refs → §4-WD.1–.8 and forks marked resolved + D16 in WP-W DoD; (7) **§5 DAG** note that
  W0–W10 predate §4-WD (WP-W expands at beading); (8) **§7 DoD** + **§8 risks** extended for the
  skinnable arch + 3D/WebGL fallback. Pure hygiene — plan stays steady-state.
- **Round 17 (v3.15) — Codex cross-model triangulation (multi-model-triangulation) → §4-CX.**
  Codex `gpt-5.5` ran a read-only adversarial review of the whole plan + AGENTS.md + `crates/`
  (first run hung on stdin — a background-pipe issue — fixed with `< /dev/null` + relaunch).
  18 findings (5 CRITICAL / 11 IMPORTANT / 1 MINOR / 1 QUESTION), all verified by the author.
  **Operator decisions:** **C5 → D1 release train** 0.6.0→0.6.1→0.6.2 (one plan, beaded together,
  built continuously, NO deferral — answers "not buildable as one 0.6.0" without cutting scope);
  **I3 → redact-binds-by-default + audited reveal** (reconciles FORK-1 with N-S6/DoD); **I10 →
  keep GSAP** (deny.toml allow-list + NOTICE); **I11 → 3D Orrery default, 2D fallback** (already
  mitigated). **Correctness fixes (inline):** C2 honest DML rollback scope (autonomous txn/
  sequence/triggers/external escape), C3 DDL snapshot-undo restricted to source-replaceable
  objects, I1 ground-truth refresh (oracledb already `=0.5.1`; WP-A re-scoped to validation), I2
  §4-R "default-on" superseded, I4 affected-row-count = the IN gate, I8/I9 SSE Origin/subject-
  bound-replay + ticket-as-bootstrap-secret, M1 §4-WD "in progress" → complete. **New directives
  (§4-CX.1):** CX-C1 durable write-ahead idempotency, CX-C4 read-lane per-Subject scoping, CX-I5
  file-storage fsync/lock/recovery/**path-safety**, CX-I6 Phase-0 capacity spike, CX-I7 Phase-0
  panic-isolation prototype, CX-Q1 asupersync API appendix. Phase-0 spikes + durable idempotency
  are now §7 DoD gates for 0.6.0. Codex verdict: consistent + buildable **as a release train**.
- **Round 18 (v3.15, fixes-only) — propagate the D1 release-train + finish the consistency pass.**
  The train (Round 17) left "all in 0.6.0" contradictions; fixed: §0 "one release"→train; §2 G6 +
  WP-A "driver baked-in"→"already pinned; validation" (I1); §4-WD.1 "8 views ALL in 0.6.0"→**phased
  across the train** (0.6.0 read-only core / 0.6.1 Workbench+views / 0.6.2 PR-board+Orrery); §7 DoD
  header→**cumulative across the train** with the 0.6.0 slice spelled out; §9 dashboard line→phased.
  No decisions changed. **Gap analysis (this round):** core is self-contained + decided-upfront;
  flagged thin/undiscussed areas for follow-up — **(1) ground-truth refresh (I1), (2) classifier
  Oracle-semantics completeness, (3) operator-authority model, (4) secrets-storage mechanism, (5)
  migration/backup story.** Recommended plan-space skill passes: `oracle` (classifier), 
  `codebase-archaeology` (ground-truth), `reality-check-for-project` (train scope),
  `security-audit-for-saas` (authz/secrets).
- **Round 19 (v3.16) — ground-truth refresh + 6 pre-bead gaps resolved → §4-GT** (`codebase-
  archaeology` both repos + `oracle` the classifier). **Empirical findings reshape the model:**
  (gap 1) repo at **0.4.1**, `oracledb` **already =0.5.1**, and **the fail-closed guard already
  ships** (`oraclemcp-guard`: classifier/levels/purity/stepup/token) → **WP-N is a lane layer over
  the existing guard, not a new classifier**; `#4` `timeout_ms` already threaded (WP-B partly done).
  (gap 2) classifier is **mature + Oracle-aware** (DangerLevel Safe/Guarded/Destructive/Forbidden;
  MERGE/CTAS/FOR-UPDATE/FLASHBACK/anonymous/dynamic-SQL/UTL_FILE/autonomous modeled; 3-valued purity,
  Unknown→side-effecting) — no hole; one open **SELECT-side-effect tightening** gated on the engine
  oracle. (gap 6) plsql-intelligence **v0.7.0, ~21 pure engine crates (no tokio/net)** → clean
  bake-in; **two surfaces:** the **`SideEffectOracle` purity port** (safety core; the seam already
  exists in `purity.rs`; 0.6.0-eligible) + the **Workbench IDE** (0.6.1); consume engine crates
  only. (gap 3) **D17** operator-authority = config allow-list above the Subject, binary, audited.
  (gap 4) **D18** Oracle secrets = external refs (env/file/keyring) via a `SecretResolver` seam,
  never persisted/logged/rendered. (gap 5) migration = additive/versioned formats + doctor-assisted;
  backup = `om backup`/`restore` over the state dir. Net: all 6 resolved; the guard-already-ships +
  ready purity-seam are positive surprises that simplify WP-N and elevate the plsql-intelligence
  bake-in to a safety upgrade.
- **Round 20 (v3.17) — final plan-space passes → §4-RS** (`reality-check-for-project` +
  `security-audit-for-saas`). **Reality-check:** vision fully covered (every goal → a WP, no
  NO_BEAD gap); 0.6.0 shippable (lane-over-existing-guard + protocol + service + installer +
  read-only dashboard); 4 steers — front-load N0a + Phase-0; plsql-int oracle non-blocking for
  0.6.0; 0.6.0 = always-on + read-only control plane (editing = 0.6.1); per-bead test companions.
  **Security-audit (10-axiom kernel):** design strongly fail-closed; 7 adds — **SEC-1 (real gap)
  CP-apply/recovery-paths re-classify + re-check at apply, never trust the stored verdict** (fixed
  inline §4-WD.3); SEC-2 normalize-before-classify (+ adversarial corpus); SEC-3 audit-write-fail =
  fail-closed; SEC-4 self-heal-down-never-up (no re-grant/re-elevate); SEC-5 surface inventory +
  per-surface authn (OTLP/`/readyz` must not leak); SEC-6 uniform auth errors / no cross-tenant
  oracle; SEC-7 multi-tenant isolation = lane model + classifier + audit, operator fleet-view the
  only cross-principal path (N9-K5 + 2-Subject fixture). No architectural flaw; all fold into WPs.
- **Round 21 (v3.18) — CX-Q1 asupersync API appendix + per-WP acceptance-test specs (this revision).**
  Resolved the last two open plan-space items with **source-verified evidence** (`asupersync-mega-skill`
  + two `Explore` extractions against the actual `asupersync-0.3.4` and `rust-oracledb` 0.5.1 source,
  cited `file:line`; testing discipline from `testing-metamorphic` / `testing-conformance-harnesses` /
  `testing-real-service-e2e-no-mocks` / `testing-golden-artifacts` / `testing-fuzzing`; `ab-testing`
  triaged **N/A** = product experimentation). Added **Appendix A** (the verified asupersync 0.3.4 API
  surface per release-blocking primitive — import path + signature + 5-line prototype, baseline-vs-new)
  and **Appendix B** (per-WP acceptance-test specs mapped onto the real test files). **Five
  evidence-backed corrections** surfaced by CX-Q1 (names that don't match 0.3.4 reality): (1)
  **`asupersync::Pool`/`GenericPool` does NOT exist** → DL-7's per-DB ceiling is `channel::mpsc`
  token-pool + `combinator::bulkhead`, not a built-in pool (DL-7 fixed inline); (2) **`epoch_tracker`
  is mis-named for lane-generation** — the real `runtime::epoch_tracker` is a scheduler health monitor
  and `asupersync::epoch` is the ATP data layer; lane generation = a plain monotonic `u64` (DL-6
  ordering) → C-4 reconciled; (3) **`mask()` → `cx.masked(f)` + `combinator::commit_section`** for
  deterministic finalizers; (4) **"tracked_channel" → the two-phase `Sender::reserve(cx)→SendPermit`**
  obligation token; (5) **`RuntimeBuilder::current_thread()` still spawns one worker OS thread** (=
  `new().worker_threads(1)`) → a thread-per-lane lane ≈ **2 OS threads**, which CX-I6 must budget.
  Confirmed-correct as written: `Outcome` four-valued + `Try`, `Budget::meet`, `CancelKind` (full
  11-variant enum captured), supervision (`AppSpec`/`SupervisorBuilder`/`SupervisionStrategy`/
  `RestartPolicy`/`BackoffStrategy`), registry **name-leases**, `combinator::{bracket,bulkhead,
  circuit_breaker,rate_limit,retry,timeout}`, `lab::{LabRuntime,DporExplorer,oracle::*}`, and the
  **Send/!Send lane seam** (`Runtime`+`RuntimeHandle` are `Send`; Send channels bridge to a dedicated
  OS thread running `block_on` over the `!Send` Oracle conn — `Scope::spawn_local` is the in-scheduler
  alternative). The corrections do **not** change the architecture (the §4-AS reframe #2 lane shape is
  confirmed) — they make the beads cite real APIs.
- **Round 21b (v3.18, fresh-eyes verification pass — operator-requested).** Re-read both appendices +
  cross-refs against the verified API surfaces and the real repo. Fixed: A.10 lane-seam prototype
  (bind `cx` once; `let mut conn` + `&mut conn` since oracledb conn methods are `&mut self`); A.7
  prototype (`ms()`/`secs()` → `Duration::from_millis/from_secs`); B.4 `OracleRoutineArg` compile-fail
  test relocated `oraclemcp-core`→**`oraclemcp-db`/tests/ui/** (adapter-layer type); B.1 connect-timeout
  row made precise (profile connect-timeout → DSN `transport_connect_timeout`; per-op `Query::timeout` is
  the WP-B path); B.5 `phase0_panic_isolation` modality `L/E`→**`E`** (cross-OS-thread `catch_unwind`
  containment isn't a lab property); added a **central name-reconciliation banner at the head of §4-AS**
  so the inline `epoch_tracker`/`mask()`/"tracked_channel" mentions point to the authoritative A.11.
  **Added §B.13 — cross-cutting edge-case & negative-test catalog** (7 concerns: classifier
  monotonicity + reclassification-idempotence + adversarial corpus + SideEffectOracle-never-loosens MRs;
  serializer boundary values incl. NULL/empty/nested/cap±1/38-digit/±Inf/NaN/DST/nested-object-unsupported;
  lane lost-wakeup/permit-leak/lock-order/switch-at-capacity/abandoned-reap; protocol malformed/oversized/
  406/405/route-precedence/SSE-slow-drop; SEC-1 every-recovery-path-re-enforces; installer/doctor
  idempotency + tamper-detect-never-repair + exit-4; stdio byte-identical non-regression). No decisions
  changed; plan stays steady-state at v3.18.
- **Steady-state — PLAN-SPACE COMPLETE (v3.18).** dashboard COMPLETE; plan consistent, Codex-
  triangulated, train-propagated, ground-truth-refreshed, 6 gaps resolved, reality-checked +
  security-audited, **CX-Q1 API appendix (A) + per-WP acceptance-test specs (B) written against
  verified source**. **Next: convert to the `oraclemcp-060-epic` bead graph** (idea-wizard Phase 5) —
  0.6.0/0.6.1/0.6.2 beaded together, Phase-0 spikes (CX-I6/I7) + N0a front-loaded, SEC-1..7 + CX-*
  folded into WP DoDs, each bead citing Appendix A APIs + carrying its Appendix B test companion —
  awaiting operator go-ahead.

---

## Appendix A — asupersync 0.3.4 API reference (resolves CX-Q1)

*Source-verified against `asupersync-0.3.4/src/` (registry checkout) on 2026-06-30; every signature
below was read from the actual source, `file:line` cited where load-bearing. Pinned in `Cargo.toml`:
`asupersync = { version = "0.3.4", default-features = false, features = ["metrics"] }` — the nightly
pin (`try_trait_v2` + residual) exists because of `Outcome`'s `Try` impl (A.7). **Recommendation: hard-pin
`=0.3.4`** at beading given the nightly-feature coupling. Legend: ✅ **baseline** (already used today,
the A9 surface) · ➕ **new for WP-N** · ⚠️ **reconcile** (plan named it loosely) · ❌ **absent** (named
but not in 0.3.4 — build it).*

**Baseline today (verified by grep):** oraclemcp uses `asupersync::Cx` (38 sites), `runtime::RuntimeBuilder::current_thread`
+ `runtime::reactor::create_reactor`, `sync::Mutex`, `time::{timeout,sleep}`, `cx::{SubsetOf,HasSpawn,
HasRemote,HasRandom,CapSetRuntimeMask}` (capability narrowing — A9), and `observability::*` (OTLP). It does
**not** yet touch `channel`/`cancel`/`supervision`/`scope`/`combinator`/`lab` — that is precisely WP-N's adoption.

### A.1 Bootstrap & runtime topology  ✅ baseline / ➕ MT-transport
- **Path:** `asupersync::runtime::{RuntimeBuilder, Runtime, RuntimeHandle, JoinHandle}` (`runtime/mod.rs:186`).
- **Signatures** (`runtime/builder.rs`): `RuntimeBuilder::new()` (4 workers) · `::current_thread()` (= `new().worker_threads(1)`
  — **still one worker OS thread**, `:2974`) · `::multi_thread()` · `.worker_threads(n)` · `.thread_name_prefix(..)`
  · `.build() -> Result<Runtime, Error>` (`:3018`). `Runtime::handle() -> RuntimeHandle` (`:3200`, **`Send+Sync`**),
  `Runtime::block_on<F: Future>(&self, F) -> F::Output` (`:3214`, polls on the **calling** thread). `RuntimeHandle::spawn<F: Future+Send+'static>(&self,F) -> JoinHandle<F::Output>` (`:3546`), `::spawn_with_cx`, `::spawn_blocking`.
- **WP-N use:** **MT runtime for the `Send` transport** (HTTP accept / operator API / SSE); **per-lane `current_thread` runtime
  on a dedicated OS thread** for the `!Send` Oracle work (A.10). Caveat: lane ≈ 2 OS threads (worker + the block_on driver) → CX-I6.
```rust
use asupersync::runtime::RuntimeBuilder;
let transport = RuntimeBuilder::multi_thread().worker_threads(4).build()?; // Send transport layer
let handle = transport.handle();                                          // Send; move anywhere
transport.block_on(async { /* accept loop; dispatch to lanes via channels */ });
```

### A.2 Context, regions, capabilities  ✅ baseline (A9)
- **Path:** `asupersync::{Cx, Scope}` (`lib.rs:384`); `asupersync::cx::{CapMask, HasIo, HasRandom, HasRemote, HasSpawn, HasTime, AllCaps, NoCaps, SubsetOf}`.
- **Signatures** (`cx/cx.rs`): `Cx<Caps=cap::All>` is **`Send+Sync`** (`:200`). `cx.checkpoint() -> Result<(), Error>` (`:1723`, yields + observes cancel + budget),
  `cx.is_cancel_requested() -> bool` (`:1678`), `cx.cancel_reason() -> Option<CancelReason>` (`:2767`), `cx.budget() -> Budget` (`:1607`),
  `cx.now() -> Time` (`:2006`, needs `HasTime`), `cx.trace(&str)` (`:2285`), `cx.restrict::<NewCaps>() -> Cx<NewCaps>` (`:751`),
  `cx.masked<F,R>(&self,F)->R` (`:2238`), `cx.scope() -> Scope<'static>` (`:3061`). Test-only ctors (`Cx::for_testing/for_request`) require `--features test-internals`.
- **WP-N use:** the fail-closed classifier stays **pure** (`cap::None`, no `Cx`); each lane handler gets a **narrowed `Cx`** (time + own io, never `HasRemote`/`HasSpawn`). The `widen_narrowed_cx_rejected.rs`/`read_handler_cannot_spawn_or_remote.rs` compile-fail tests already pin this — extend per-lane.
```rust
async fn lane_handler(cx: &asupersync::Cx) -> asupersync::Outcome<Row, DbErr> {
    cx.checkpoint()?;                 // Err -> Cancelled via Try on cancel/budget
    cx.trace("lane: classify+execute");
    asupersync::Outcome::ok(/* row */)
}
```

### A.3 Channels (the lane mailbox + reply substrate)  ➕ new
- **Path:** `asupersync::channel::{mpsc, oneshot, broadcast, watch}` (`channel/mod.rs`).
- **mpsc** (`channel/mpsc.rs`): `mpsc::channel<T>(capacity: usize) -> (Sender<T>, Receiver<T>)` (`:348`, **bounded**). `Sender` is **`Send+Sync`** (T:Send); `Sender::reserve(&self,&Cx) -> Reserve` then `SendPermit::send(self,T) -> Outcome<(),SendError<T>>` = the **two-phase obligation-tracked send** (this is the plan's "tracked_channel"); `Sender::try_send`, `try_reserve`, `send_evict_oldest`. `Receiver` is **`Send` (not `Sync`)**: `recv(&mut self,&Cx)`, `try_recv() -> Result<T,RecvError>`.
- **oneshot** (`channel/oneshot.rs:293`): `oneshot::channel<T>() -> (Sender<T>,Receiver<T>)`; `Sender::send_blocking(self,T)` (no `Cx`) — the reply path from the lane thread.
- **watch** (`channel/watch.rs:347`): `watch::channel<T>(initial) -> (Sender,Receiver)`; `Sender::send(&self,T)`, `Receiver::changed(&mut,&Cx)`, `borrow_and_update()` — config/health fan-out (§4-WD.6 real-time model).
- **broadcast** (`channel/broadcast.rs:190`): `broadcast::channel<T:Clone>(cap) -> (..)`, `Receiver::recv` returns `TryRecvError::Lagged(u64)` — the SSE event fan-out + bounded-ring/gap-marker (FN1).
- **WP-N use:** transport→lane = `mpsc` of `{command, oneshot reply}`; choose a **bounded** capacity → full mailbox is **backpressure/429** (`CastOverflowPolicy`), never unbounded (DL-9 lint forbids `unbounded`). SSE/watch drive §4-WD.6.
```rust
use asupersync::channel::{mpsc, oneshot};
struct Cmd { sql: String, reply: oneshot::Sender<Outcome<Rows, DbErr>> }
let (tx, mut rx) = mpsc::channel::<Cmd>(32);              // tx: Send -> registry LaneHandle
let permit = tx.reserve(cx).await?;                       // Phase 1: obligation acquired
permit.send(Cmd { sql, reply });                          // Phase 2: infallible commit
```

### A.4 Cancellation (record the reason)  ➕ new
- **Path:** `asupersync::{CancelReason, CancelKind}` (`lib.rs:414`; `types/cancel.rs`).
- **`CancelKind`** (`:263`) — **11 variants**: `User, Timeout, Deadline, PollQuota, CostBudget, FailFast, RaceLost, ParentCancelled, ResourceUnavailable, Shutdown, LinkedExit` (`severity()->u8`). **`CancelReason`** (`:521`) carries `{kind, origin_region, origin_task, timestamp, message, cause, truncated}` with ctors `::user/timeout/deadline/shutdown/...` and `.with_cause`.
- **Flow:** request via `cx.cancel_with(kind,msg)`/`cancel_fast(kind)`; observe via `checkpoint()?` (→ `Outcome::Cancelled`) or `is_cancel_requested()`; introspect via `cancel_reason()` / `cancel_chain()`.
- **WP-N use (§4-AS.2):** map N5 disconnect/DELETE → `User`, B1 call-timeout → `Timeout`, S5 drain → `Shutdown`; **record `CancelKind` into the audit hash-chain**; `Timeout` ⇒ mark conn suspect (B1c). `Cancelled ≠ error` — distinct severity, distinct audit/retry/drain handling.

### A.5 Budget & A.6 Outcome  ✅ Budget exists / ➕ four-valued use
- **Budget** (`types/budget.rs:149`, `Copy`): `{deadline:Option<Time>, poll_quota:u32, cost_quota:Option<u64>, priority:u8}`; `Budget::{INFINITE, ZERO, MINIMAL}`; `.with_timeout(now,dur)` (`:301`), `.with_deadline_secs`, `.with_poll_quota`; **`.meet(other)` = `.combine()`** (deadline=min, quotas=min, priority=max, `:405`); `.is_exhausted()`. **WP-B reshape #4:** effective `Budget = root.meet(profile_ceiling).meet(request_deadline)` — one algebra replaces the three ad-hoc #4 timers.
- **Outcome** (`types/outcome.rs:216`): `enum Outcome<T,E>{ Ok(T), Err(E), Cancelled(CancelReason), Panicked(PanicPayload) }`; `severity()` lattice `Ok<Err<Cancelled<Panicked`; `Try`/`FromResidual` via `feature(try_trait_v2)` (`:103`, the nightly pin) → `?` short-circuits all three non-Ok arms. **WP-P:** carry `Outcome` lane→dispatch→edge; collapse **only** at the HTTP boundary (`Cancelled→499`, `Panicked→500`+page, `Err→`domain). Never flatten to `Result<_,String>` at the first adapter.

### A.7 Supervision / app topology  ➕ new
- **Path:** `asupersync::spork::{app, supervisor, gen_server, registry, monitor, link}` + `asupersync::actor::Actor`; `asupersync::spork::prelude::*`.
- **`AppSpec`** (`app.rs:307`): `::new(name)`, `.with_budget`, `.with_registry(RegistryHandle)`, `.with_restart_policy`, `.child(ChildSpec)`, `.start(..) -> Result<AppHandle,..>` (`:407`). **`AppHandle::stop(&mut,&mut RuntimeState) -> Result<StoppedApp,..>`** (`:516`) + `.join()` — graceful S5 shutdown = `stop` then `join`, hold the handle as an **obligation**, never drop.
- **`ChildSpec`** (`supervision.rs:611`): `::new(name, start: impl ChildStart)`, `.with_restart(SupervisionStrategy)`, `.depends_on(name)`, `.with_registration(NameRegistrationPolicy)`. **`SupervisionStrategy`** (`:194`) = `Stop | Restart(RestartConfig) | Escalate` (what happens to the **failed** child). **`RestartPolicy`** (`:383`) = `OneForOne | OneForAll | RestForOne` (what happens to **siblings**) — *separate* decisions, encode both. **`RestartConfig`** = `{max_restarts, window, backoff: BackoffStrategy}` where `BackoffStrategy::Exponential{initial,max,multiplier}`.
- **Actor/GenServer caveat (load-bearing):** `Actor` (`actor.rs:185`) and `GenServer` (`gen_server.rs:501`) require **`Send + 'static`** state + `Send` messages → they **CANNOT own the `!Send` Oracle conn**. They supervise the **`Send` `LaneHandle`** only. `GenServer::cast_overflow_policy() -> CastOverflowPolicy` (default `Reject`) — choose deliberately (bounded backpressure).
- **WP-N use:** service = `AppSpec` tree (transport / lane-registry-supervisor / audit-writer / metrics / dashboard-API); lanes = `OneForOne`; ordered children (audit-writer before transport) = `RestForOne`.
```rust
use asupersync::spork::prelude::*;
let app = AppSpec::new("oraclemcp")
    .with_restart_policy(RestartPolicy::RestForOne)               // audit-writer before transport
    .child(ChildSpec::new("lane-registry", LaneRegistry::start)
        .with_restart(SupervisionStrategy::Restart(
            RestartConfig::new(3, Duration::from_secs(60))
                .with_backoff(BackoffStrategy::Exponential{ initial: Duration::from_millis(100), max: Duration::from_secs(10), multiplier: 2.0 }))));
```

### A.8 Registry name-leases (the lane registry)  ➕ new
- **Path:** `asupersync::spork::registry::{NameRegistry, RegistryHandle, NameLease, NamePermit}` (also `asupersync::cx::{NameRegistry,RegistryHandle,NameLease}`).
- **WP-N use (C-arch):** the per-principal lane registry is **registry-capability name leases** injected via `AppSpec`/`Cx`, not an ambient `HashMap`. The leased entry is the **`Send` `LaneHandle`** `{mpsc::Sender, generation:u64, cancel, JoinHandle, status}` — never the `!Send` conn. Names clean up deterministically on lane death (`stop_and_release()`/`abort_lease()`). **Lane generation = a plain monotonic `u64` on the LaneHandle** (published `Release`, read `Acquire`, DL-6) — *not* `epoch_tracker` (see A.11).

### A.9 Combinators  ➕ new
- **Path:** `asupersync::combinator::{bracket, bracket_move, commit_section, try_commit_section, Bulkhead, BulkheadPolicy, CircuitBreaker, CircuitBreakerPolicy, RateLimiter, RateLimitPolicy, retry, Retry, RetryPolicy, Timeout}` (`combinator/mod.rs`).
- **`bracket(acquire, use, release)`** (`bracket.rs:412`) → conn acquire/use/release (rollback-on-fail). **`commit_section(cx, max_polls, fut)`** (`bracket.rs:492`) / `try_commit_section` → **deterministic finalizers** (run rollback + audit-append to completion ignoring cancel for `max_polls`) — this is the real "masked finalizer" (A.11). **`Bulkhead::new(BulkheadPolicy::concurrency(n))`** + `try_acquire(weight)->Option<BulkheadPermit>` → per-lane admission/isolation + the **per-DB ceiling**. **`CircuitBreaker`** (state `Closed|Open|HalfOpen`) → poisoned-profile handling. **`RateLimiter`** (`TokenBucket|LeakyBucket|FixedWindow|SlidingWindow`) → per-caller limit (revives k6q.11). Note: rate-limit/timeout APIs take `now: Time` (from `cx.now()`).
```rust
use asupersync::combinator::{Bulkhead, BulkheadPolicy};
let db_ceiling = Bulkhead::new(BulkheadPolicy::concurrency(8)); // per-profile stateful cap
let permit = db_ceiling.try_acquire(1).ok_or(AtCapacity)?;      // acquire BEFORE opening a conn
// ... run lane work ...; permit released on drop (obligation-tracked)
```

### A.10 The Send/!Send lane seam (assembled)  ➕ the core architecture
asupersync ships **no `LocalSet`/`current_thread::spawn`/thread-per-conn executor**. The two real mechanisms:
1. **`Scope::spawn_local<F:FnOnce(Cx)->Fut + 'static, Fut:Future+'static>`** (`scope.rs:629`, **no `Send` on F/Fut**; `Fut::Output:Send`) — `!Send` future pinned to a *scheduler worker thread* (not isolated; blocks that worker if it blocks).
2. **Dedicated OS thread + moved `Runtime` + Send channels (the chosen WP-N shape, §4-AS reframe #2):** `Runtime` and `RuntimeHandle` are **`Send`**; `mpsc`/`oneshot` senders are **`Send`**. Spawn an OS thread, move a `current_thread` runtime in, `block_on` a loop that **owns** the `!Send` conn and services `Send` commands. **Sharp rule:** the conn never leaves the thread; DB work never goes through `Scope::spawn`/`Actor`/`GenServer` (all `Send`-bound).
```rust
use asupersync::{runtime::RuntimeBuilder, channel::{mpsc, oneshot}};
let (tx, mut rx) = mpsc::channel::<Cmd>(32);                  // tx: Send -> LaneHandle in the registry
std::thread::spawn(move || {
    let rt = RuntimeBuilder::current_thread().build().unwrap();
    let mut conn = open_oracle_conn();                        // !Send — lives only here
    rt.block_on(async move {
        let cx = Cx::current().expect("block_on installs a current Cx"); // bind once
        while let Ok(cmd) = rx.recv(&cx).await {              // Send Cmd crossed in
            let out = run_guarded(&mut conn, cmd.sql).await;  // &mut: oracledb conn methods are &mut self
            let _ = cmd.reply.send_blocking(out);             // Send reply back out
        }
    });
});
```
**C-6 (verified):** an *idle* lane parked on `rx.recv` is woken cross-thread by the channel (`mpsc::Sender::wake_receiver`); a lane *inside a blocking Oracle call* is interrupted only by driver OCI-break/call-timeout/socket-close (then quarantine, B1/B1c). asupersync handles idle/async; B1/B1c handle in-flight.

### A.11 Plan-primitive reconciliation (names → 0.3.4 reality)
| Plan said (§4-AS/§4-AS.2/§4-SK.1) | 0.3.4 reality | Action |
|---|---|---|
| `Pool`/`GenericPool` for the per-DB ceiling (DL-7) | ❌ **no public generic pool** in 0.3.4 (`http::pool` is internal HTTP keep-alive only) | Build the ceiling from `channel::mpsc` (token bucket) **+ `combinator::bulkhead`** (obligation-tracked permits, leak-detected). **DL-7 fixed inline.** |
| `epoch_tracker` for lane generation / grant-invalidation (C-4) | ⚠️ `runtime::epoch_tracker::EpochConsistencyTracker` = scheduler-module health monitor; `asupersync::epoch` = ATP data-layer protocol — **neither is a lane counter** | Lane generation = a **plain monotonic `u64`** on the `LaneHandle` (Release/Acquire, DL-6); bind grants to it (C-4 still satisfied). |
| `mask()` finalizers | ⚠️ method is `cx.masked(f)` (`cx/cx.rs:2238`); deterministic finalize = `combinator::commit_section(cx, max_polls, fut)` + `Budget::MINIMAL` | Use `commit_section`/`cx.masked` for rollback + audit-append under shutdown/cancel. |
| `tracked_channel`/`tracked_oneshot` | ⚠️ no type by that name; the obligation-tracked send = `Sender::reserve(cx) -> SendPermit` then `permit.send(v)` | Use `reserve`/`SendPermit` (mpsc/oneshot/broadcast all have it). |
| `RuntimeBuilder::current_thread` = "current-thread, 1 OS thread" | ⚠️ `= new().worker_threads(1)` — **spawns 1 worker OS thread**; `block_on` adds the calling/driver thread | Budget **≈2 OS threads per lane** in the CX-I6 capacity spike. |
| DPOR (N9 explorer) | ⚠️ `lab::DporExplorer` exists but is **seed-sweep**, not full backtracking (already softened in §4-AS) | N9 = lab injection + seed-sweep + hand-authored interleavings + the oracles (A: confirmed). |
| `Outcome`/`Budget.meet`/supervision/`CancelKind`/name-leases/`bracket`/`bulkhead`/`circuit_breaker`/`rate_limit`/`AppSpec` | ✅ **all present as named** (signatures above) | Adopt as written. |
| `hedge`/`quorum`/`remote`/RaptorQ/QUIC | ✅ present but **deliberately N/A** (single Oracle backend) | Recorded omission stands. |

**Release-blocking subset (must be cited correctly in beads):** A.1 (MT-transport + per-lane runtime), A.3 (mpsc/oneshot mailbox), A.4 (CancelKind in audit), A.6 (Outcome to edge), A.7 (AppSpec + RestartPolicy), A.8 (name-leases + `u64` generation), A.9 (`bulkhead` ceiling + `circuit_breaker` + `commit_section` finalizers), A.10 (the lane seam), A.13 (lab oracles for N9). Everything else (rate_limit/retry/broadcast/watch) is accretive, not blocking.

### A.12 time  ✅ baseline
`asupersync::time::{timeout(now,dur,fut), timeout_at(deadline,fut), sleep(now,dur), with_timeout(cx,dur,fut), interval}` (`time/mod.rs`). Already used in `readiness.rs`; reused for lane idle-TTL + the FN1 SSE keepalive.

### A.13 lab (the N9 substrate)  ➕ new
`asupersync::lab::{LabRuntime (!Send), LabConfig, DporExplorer, FuzzHarness, DualRunHarness, oracle::{OracleSuite, QuiescenceOracle, DeterminismOracle, ...}}`. Determinism hygiene: `cx.now()`/`cx.random_u64()` (no wall-clock/ambient-rand). N9-K (state machine) + the concurrency contract run here; the **quiescence / obligation-leak / futurelock** oracles are the quality bar (§4-AS.2); on failure emit crashpack + seed.

---

## Appendix B — Per-WP acceptance-test specs

*Every implementation bead ships a **test companion** (reality-check + idea-wizard discipline). This appendix
maps each WP to named tests, tagged by **modality**, mapped to the **real test file each extends** (verified to
exist), with the **release gate** it satisfies. It does not duplicate the WP-N **N9 contract** (§WP-N, set in
stone) — it references it and adds the asupersync-primitive-level + Phase-0 tests around it.*

**Modality legend.** `U`=unit · `P`=property (proptest) · `F`=fuzz/differential (`testing-fuzzing`) · `MR`=metamorphic
(`testing-metamorphic`) · `C`=conformance/spec-derived + coverage-matrix (`testing-conformance-harnesses`) ·
`G`=golden artifact + provenance (`testing-golden-artifacts`) · `L`=lab-deterministic (asupersync `lab` + oracles) ·
`E`=real-service e2e, no mocks (`testing-real-service-e2e-no-mocks`) · `Web`=browser e2e (`e2e-testing-for-webapps`).
**`ab-testing` = N/A** (it is product A/B experimentation: Next.js/GA4/Bayesian — not differential testing; the
differential discipline we need comes from `C`+`G`).

**Global test-discipline invariants (apply to every WP):**
1. **Coverage accounting** (`C`): conformance suites enumerate MUST/SHOULD clauses; **MUST ≥ 0.95** to ship; intentional
   gaps are `XFAIL` in a `DISCREPANCIES.md`, never `SKIP`; goldens/fixtures record **provenance** (generator + version + cmd).
2. **Mock-risk matrix** (`E`): any path scoring **Impact×Risk ≥ 8** (cross-lane isolation, commit/rollback, grant
   consumption, audit-append, credential issuance) is **mock-free** — real Oracle 23ai / real files. Deterministic
   model tests (`L`) may use an in-repo **trait double** (`oracledb_contract.rs`'s `OracleBackend` fake) for
   interleavings, but the headline isolation/commit claims must also have an `E` test on real 23ai.
3. **Structured JSON-line logging** in every concurrency/e2e test (lane/subject/SID/profile/level/grant/outcome) so a CI
   failure is replayable (N9 already mandates this; extend to E/Web).
4. **Prod-safety guards** (`E`): live tests are env-gated (`ORACLEMCP_TEST_*` / `ORACLEMCP_LIVE_XE=1`); never touch a
   non-test DB; installer/service tests run against `--offline` built artifacts in throwaway scopes.
5. **The classifier is the security oracle** — its tests are `F`(differential fuzz) + `MR`(normalize-invariance) + `P`,
   never example-only; they derive from the spec/domain, **never from the classifier's own code** (anti-tautology).

### B.1 WP-A — Driver 0.5.1 validation
| Test | Mode | Extends / new file | Asserts (evidence) | Gate |
|---|---|---|---|---|
| `pin_is_0_5_1_and_seam_intact` | U/C | `Cargo.lock` + `scripts/oraclemcp_driver_seam_lint.sh` | lock = `=0.5.1`; driver adapter stays one seam file | DoD-6 |
| `tstz_round_trips_with_offset` | MR/G | `type_fidelity.rs` + `oracledb_contract.rs::contract_type_tstz` (new) | **invertive MR:** bind `DateTime<FixedOffset>` → fetch `QueryValue::TimestampTz{…,offset_minutes}` → equal **incl. offset** (0.5.1 no longer drops it); golden fixture | #5 close |
| `tstz_live` | E | `live_oracle.rs` (`--features live-xe`) | real 23ai `TIMESTAMP WITH TIME ZONE` fidelity | G6 |
| `auth_capability_matrix_is_thin_and_redaction_safe` | C/G | new `crates/oraclemcp/tests/doctor_auth.rs` | doctor renders `AuthCapabilities::THIN` (password/proxy/iam=Supported; external/kerberos/radius=UnsupportedInThin) as a **structured, secret-free** diagnostic; telemetry test = no secret fields | A3 |
| `wallet_unsupported_format_is_structured_no_path_leak` | U/G | `doctor_auth.rs` | `WalletError::UnsupportedFormat{format}` → typed diagnostic; **no wallet path** in output (redaction) | A4 |
| `iam_token_over_non_tcps_is_refused_fail_closed` | U | `connection.rs` (exists — extend) | `with_access_token` over non-TCPS → `AccessTokenRequiresTcps` before I/O | A5 |
| `connect_timeout_threads_to_driver` | U/C | `example_config_parses.rs` + `oracledb_contract.rs` | profile connect-timeout → driver DSN `transport_connect_timeout` (default 20s, bounds the full handshake in 0.5.1); `call_timeout_seconds`/`timeout_seconds` → per-op `Query::timeout` (the WP-B path); `=0` → doctor warn | A6 |
| `output_schema_validates_structuredContent` | C | `mcp_conformance.rs` (A7b) | every changed tool's `structuredContent` validates against its `outputSchema` (contract Pattern 5 + round-trip) | A7b |
| `om_alias_argv0_aware` | G | `cli.rs` | `om`/`om dashboard` behave as `oraclemcp`; golden help footer | A8 |

### B.2 WP-B — Timeout hardening + poison/quarantine (#4)
| Test | Mode | Extends / new file | Asserts | Gate |
|---|---|---|---|---|
| `budget_meet_replaces_three_timers` | U/P | `cancel_correctness.rs` | effective `Budget = root.meet(ceiling).meet(deadline)`; call-timeout + total-request + fetch-loop bound all derive from one budget (A.5) | B1 |
| `fetch_loop_is_bounded_per_batch` | P | `oracledb_contract.rs` (FakeBackend) + `live_oracle.rs` | a slow continuation fetch → typed `CallTimeout`, never unbounded (B1b) | B1b |
| `poisoned_conn_is_never_reused` | L/E | `chaos.rs` (db) + `load_soak.rs` | inject timeout / network-error / rollback-failure → `conn.connection_disposition()==Dead` → dropped, grants revoked, audit outcome class ∈ {`rolled_back`,`discarded_uncommitted`,`commit_in_doubt`,`unknown_discarded`} (B1c) | B1c |
| `commit_in_doubt_marks_quarantine` | L | `cancel_correctness.rs` | drain-fail after timeout → `ConnectionClosed`(lost) → quarantine + `commit_in_doubt` audit | B1c |
| `dirty_discard_no_pool_return` | U/E | `chaos.rs` (db) | a cancelled/failed pooled call is discarded, not returned idle (B2) | B2/#4 close |

### B.3 WP-C — Non-lossy serialization (#3)
| Test | Mode | Extends / new file | Asserts | Gate |
|---|---|---|---|---|
| `number_is_lossless_string` / `nls_invariance` | MR/G | `type_fidelity.rs` (exist) | NUMBER→string by default; **equivalence MR:** value identical under `ALTER SESSION` NLS changes | (regression) |
| `structured_carrier_round_trips_array_json_vector_tstz` | MR/G/C | `type_fidelity.rs` + `oracledb_contract.rs::contract_type_*` (new) | **invertive MR** serialize→parse→equal for `Array`/`Json(OsonValue)`/`Vector(Dense/Sparse)`/`TimestampTz`; golden fixtures (C4b) + published JSON schema (C) | C1/C4b |
| `object_identity_marker_never_silent` | U/G | `oracledb_contract.rs::contract_type_unsupported_*` (exists — extend) | UDT → `(schema,type_name)` + typed-unsupported marker; nested → explicit `UnsupportedFeature`, **never silent flatten** (driver has no `Opaque` variant → oraclemcp owns the marker) | C2 |
| `serialization_contract_version_present_and_consumed` | C | `mcp_conformance.rs` + W7 cache test | `OracleCell` carries a contract-version tag; cache key includes it (C5) | C5 |

### B.4 WP-R — Routine execution (#2)
| Test | Mode | Extends / new file | Asserts | Gate |
|---|---|---|---|---|
| `routine_arg_is_not_deserialize` | U(compile-fail) | new `crates/oraclemcp-db/tests/ui/` (trybuild, modeled on oraclemcp-core's `capability_compile_fail.rs`; `OracleRoutineArg` is an adapter-layer type) | `OracleRoutineArg` wraps `BindValue::{Output,ReturnOutput,ObjectOutput}` and does **not** impl `Deserialize` (R1; driver confirms no serde bound) | R1 |
| `call_routine_out_bind_order_deterministic` | U/E | `oracledb_contract.rs` (FakeBackend) + `live_oracle.rs` | OUT/IN-OUT retrieved via `ExecuteOutcome::out_binds()` in declared positional order; COMMIT caveat documented | R2 |
| `call_routine_absent_from_agent_surface` | C(grep-lint) | `honesty_grep.rs` (extend) | `call_routine` symbol absent from `oraclemcp` **and** `oraclemcp-core` public surface (R3 — no agent tool) | R3/#2 close |

### B.5 WP-N — Per-principal LaneRuntime (FOUNDATION)
*The acceptance contract **is N9** (§WP-N, A–K, set in stone) across `tests/{chaos,load_soak,cancel_correctness,
live_oracle,trust_safety}.rs` + new `tests/{lane_state_machine,concurrency_contract,multi_lane_live_xe}.rs`. This
table adds the **primitive-level + Phase-0 + security-corpus** tests that wrap it.*
| Test | Mode | File | Asserts | Gate |
|---|---|---|---|---|
| N9 A–K (full contract) | L/E | `lane_state_machine.rs`(L,no-Oracle) · `concurrency_contract.rs`(L,mock) · `multi_lane_live_xe.rs`(E,real 23ai, 2 DBs) | every N9 invariant (isolation/level/grant-non-replay/generation-binding/capacity/lifecycle/audit/MCP-compliance/state-machine K1-K5) | DoD-2 (any regression blocks release) |
| `lab_quiescence_obligation_leak_futurelock` | L | `concurrency_contract.rs` | asupersync `oracle::{QuiescenceOracle, obligation-leak, futurelock}` clean at end; `FuturelockViolation`/`RegionCloseTimeout` = hard fail; red test ships crashpack+seed (A.13) | DoD-2 |
| `transport_responsive_while_lane_blocked_in_db` | L/E | `multi_lane_live_xe.rs` | DL-2: one lane in a long DB call does not stall accept loop or siblings (MT transport never `block_on`s a lane reply) | DoD-2 |
| `classifier_normalize_invariance` | MR/F | `adversarial_corpus.rs` + `fuzz/fuzz_targets/classify_fuzz.rs` | **equivalence MR (SEC-2):** `classify(normalize(x)) == classify(x)` for comment/case/unicode/whitespace/quoted-id transforms; corpus includes `/**/SELECT`, mixed-case, unicode look-alikes; differential fuzz | DoD-1 (SEC-2) |
| `confirm_mac_retired_cross_lane_recompute_rejected` | U/E | `trust_safety.rs` + remove `dispatch/mod.rs::confirmation_mac` | N-S1: legacy deterministic MAC gone; a lane cannot recompute another lane's confirm; server-side single-use grant is the only path | DoD-1 (N-S1) |
| `grant_single_use_lane_bound_generation_bound` | U/P | `token_security.rs` (`AllowOnceStore`) extended | N3/A4/A6: grant consumed once; rejected for another Subject/lane, after `switch_profile`, after level/profile generation change | DoD-2 |
| `every_committing_tool_audits` | U/E | `trust_safety.rs` | N-S2: `oracle_execute`/`compile_object`/`patch_source` each append an audit record (audit = durable record) | DoD-1 (N-S2) |
| `phase0_capacity_spike` | E | new `tests/phase0_capacity.rs` (`--ignored`, measured) | **CX-I6 release-blocker:** derive 16/8/64 defaults from real Oracle sessions + fds + `TasksMax` + per-thread stack (≈2 threads/lane, A.11) + tail latency; shipped defaults cite the measurement | DoD-2 Phase-0 |
| `phase0_panic_isolation` | E | `tests/phase0_panic.rs` + `chaos.rs` | **CX-I7 release-blocker:** `catch_unwind`+Drop+quarantine+audit around the lane `block_on` loop; a lane panic does not abort siblings (real multi-thread, not lab — `catch_unwind` containment is cross-OS-thread); conn dropped; `unknown_discarded` audited (D12/CX-2) | DoD-2 Phase-0 |
| `durable_write_ahead_idempotency_across_restart` | E | `multi_lane_live_xe.rs` | **CX-C1 release-blocker:** committed DML + restart + retry consults the durable audit chain (`sql_sha256`+grant) → no double-execute (P1c/N-M7) | DoD-2 Phase-0 |

### B.6 WP-P — Operator protocol (versioned, schema-first)
| Test | Mode | Extends / new file | Asserts | Gate |
|---|---|---|---|---|
| `mcp_and_operator_v1_conformance_matrix` | C | `mcp_conformance.rs` (extend the `RequirementLevel::{Must,Should}` matrix with `/operator/v1`) | spec-derived MUST/SHOULD per route/event; **MUST ≥ 0.95**; `MCP-Protocol-Version`/`MCP-Session-Id` missing/unsupported → typed 400; `DISCREPANCIES.md` | DoD-3 |
| `ui_fixtures_validate_against_rust_schema` | C/G | `tests/golden/` (captured fixtures) | generated `operator.schema.json` + route/event schemas validate captured fixtures (contract Pattern 5); event envelope carries `event_seq/event_id/lane_id/subject_id_hash/redaction_level/schema_version` | DoD-3 (A7b/R9) |
| `sse_replay_never_crosses_lane` | P/E | `e2e_http_oauth.rs` (extend) | P1b: `Last-Event-ID` resumes within the bounded ring; **never** replays another subject/lane; payloads redacted | DoD-3 |
| `idempotency_key_dedup_and_no_cross_restart_double_execute` | E | `multi_lane_live_xe.rs` | P1c + CX-C1: same key → recorded outcome / typed in-progress; different key can't reuse a consumed grant; durable across restart | DoD-3 |
| `session_id_bound_to_subject` | U/E | `trust_safety.rs` | N-S7: a valid bearer presenting another principal's `mcp-session-id` is rejected (`lane.subject == request.subject`) | DoD-1/3 |

### B.7 WP-S — Persistent always-on service
| Test | Mode | Extends / new file | Asserts | Gate |
|---|---|---|---|---|
| `appspec_topology_starts_in_dep_order_and_drains` | L | new `tests/service_topology.rs` | A.7: `RestForOne` brings audit-writer before transport; `AppHandle::stop`→`join` drains in bounded time, audit uncorrupted (N9-K4) | DoD-5 |
| `service_lifecycle_e2e` | E | new `tests/service_e2e.rs` (`--ignored`; systemd-user/launchd/win) | `service install/uninstall/status/logs/restart`; `sd_notify(READY=1)`→`/readyz`; single-instance guard fails closed (no takeover) | DoD-5 |
| `safe_config_reload_drains_not_drops` | E | `service_e2e.rs` | S5: reload keeps active lanes unless a profile changed incompatibly; removed/changed profiles **drain** (no new lanes) | DoD-5 |
| `file_store_atomic_fsync_lock_path_safe` | U/P | new `tests/file_store.rs` | CX-I5: write-tmp→rename + fsync(file)+fsync(dir); single-writer lock; torn-tail recovery; **no untrusted name in a path** (hashed IDs) | DoD-5 (CX-I5) |
| `backup_restore_verifies_audit_chain` | E | `file_store.rs` | §4-GT.6: `om backup`/`restore` over `$XDG_STATE_HOME/oraclemcp`; restore re-verifies the hash-chain; SEC-1 recovery-path re-enforce | DoD-5 |

### B.8 WP-W — Web dashboard
| Test | Mode | Extends / new file | Asserts | Gate |
|---|---|---|---|---|
| `embedded_bundle_served_and_audited` | U/Web | new `crates/oraclemcp/tests/dashboard_e2e.rs` | W0: `rust-embed` serves the SPA over asupersync HTTP; `npm audit`+lockfile/SBOM in CI (E0) | DoD-4 |
| `malicious_page_cannot_trigger_gated_action` | E/Web | `e2e_http_oauth.rs` + `dashboard_e2e.rs` | W1/D10: CSRF + Origin/Host + HttpOnly/SameSite cookie + CSP/frame-ancestors; **no token in localStorage**; cross-origin POST to `127.0.0.1` refused | DoD-4 |
| `config_draft_apply_atomic_rollback` | E | `dashboard_e2e.rs` + `file_store.rs` | W2: stage→strict-validate→redacted-diff→atomic-rename+backup→reload(S5); rollback restores+revalidates; **no secret shown/stored** | DoD-4 |
| `workbench_no_bypass_guard_is_the_feature` | C/MR/E | `trust_safety.rs` + `dashboard_e2e.rs` | W8: all four modes route through the **same** classifier→ceiling→preview/confirm→audit path agents use; **equivalence MR:** workbench-classify == agent-classify for identical SQL; DDL only with `dashboard_ddl_workbench`; no raw PTY | DoD-4 (behind `dashboard_workbench`) |
| `cp_apply_reclassifies_never_trusts_stored_verdict` | E | `dashboard_e2e.rs` | **SEC-1:** Change-Review apply re-classifies + re-checks level/grants/Subject at apply time | DoD-4 (SEC-1) |
| `skin_conformance_2d_fallback_a11y` | Web/C | `dashboard_e2e.rs` | D16: grammar-is-a-contract across skins; mandatory **2D/no-WebGL** fallback renders; a11y suite passes; Orrery 3D lazy-loaded within bundle-size budget; **credential secret never rendered** | DoD-4 |
| `audit_proof_bundle_is_redacted_and_exportable` | C/Web | `crates/oraclemcp-core/src/http.rs` + `dashboard_e2e.rs` | W8b: audit-tail `export=proof-bundle` emits `oraclemcp.audit.proof-bundle.v1` with subject hashes, SQL hashes, DB evidence, chain/signature metadata, and no raw SQL, bind values, subject ids, or secrets; dashboard exposes the export without a second data path | DoD-4/W8b |
| `client_credentials_screen_is_redacted_and_isolated` | C/Web | `crates/oraclemcp-core/src/http.rs` + `dashboard_e2e.rs` | W10: dashboard lists per-client MCP credentials with scopes, last-use metadata, and source address; rotate/revoke one client closes only that principal's lanes/grants; list/revoke never return bearer/hash/salt; rotate returns the new bearer once | DoD-4/W10 |

### B.9 WP-E — Installer (broad, explicit-consent)
| Test | Mode | Extends / new file | Asserts | Gate |
|---|---|---|---|---|
| `installer_lint_and_offline_smoke` | E | new `tests/installer_smoke.rs` + CI (`installer-workmanship`) | E2/E3/E7: shellcheck/PSSA clean; installs the **built** artifact via `--offline`; **no service/client mutation without `--service`/consent**; dry-run prints every file/unit | DoD-7 |
| `per_client_scoped_creds_isolated` | E | `client_credentials.rs` + `http.rs` + `e2e_http_oauth.rs` | E4: each client = unique id + scoped bearer; revoke/rotate one **without** affecting others; no secret after creation; operator rotate/revoke closes the mutated principal's sessions/grants | DoD-7 |
| `cosign_and_provenance_verify` | E | `installer_smoke.rs` | SHA256 + cosign verify-blob **+verify-attestation**; triples match assets | DoD-7 |

### B.10 WP-F — Distribution channels
| Test | Mode | Extends / new file | Asserts | Gate |
|---|---|---|---|---|
| `npx_verifies_binary_no_postinstall_side_effects` | E | `installer_smoke.rs` | F2: npm `oraclemcp` downloads + verifies SHA256/signature, runs stdio; **no `postinstall` service/client mutation** | DoD-7 |
| `binstall_brew_winget_metadata_valid` | U/C | `tests/dist_metadata.rs` (new) | F1/F3: cargo-binstall metadata, Homebrew tap, winget manifest parse + triples match | DoD-8 |
| `docker_and_registry_at_0_6_0` | E | release CI | F4: amd64 image + MCP-registry `server.json` schema-validate | DoD-8/10 |

### B.11 WP-G — Hardening & docs
| Test | Mode | Extends / new file | Asserts | Gate |
|---|---|---|---|---|
| `surface_inventory_authn_no_leak` | C/E | new `tests/surface_inventory.rs` | **SEC-5:** every surface (`/mcp`, `/operator/v1`, SSE GET, dashboard POSTs, pairing, cred-issuance, CP-apply, config-reload, **OTLP/metrics**, `/readyz`, `om`, installer/npx) has asserted authn/gating; **OTLP + `/readyz` leak nothing** (no v$session/metadata on unauth surfaces) | DoD-9 (SEC-5) |
| `uniform_auth_errors_no_enumeration_oracle` | U/E | `e2e_http_oauth.rs` | **SEC-6:** auth/pairing failures uniform (no client-id/profile enumeration, no timing oracle); MCP-1 educational refusals don't reveal another tenant's profile/object existence to a scoped principal | DoD-9 (SEC-6) |
| `honesty_grep_green_incl_server_json` | C | `honesty_grep.rs` (extend to `server.json`) | G3: no over-claiming framing anywhere | DoD-9 |
| `conformance_100_and_goldens_reblessed` | C/G | `mcp_conformance.rs` + `tests/golden/` | G4: conformance MUST=100%; goldens reviewed via `UPDATE_GOLDENS` diff | DoD-8 |
| `audit_verify_with_db_evidence` | E | `multi_lane_live_xe.rs` | G9: `audit verify --with-db-evidence` correlates audit seqs with Oracle session tags (monitor/self-lane); degraded report when no privilege | DoD-9 |
| `self_heal_down_never_up` | U/L | `tests/doctor_scope.rs` | **SEC-4:** doctor/TTL-revert/reconciliation never re-grant/re-elevate/un-revoke; drift decays to READ_ONLY; `om doctor --fix` never touches Oracle/audit-chain/classifier/`max_level` (DOC-3/N13) | DoD-9 (SEC-4) |

### B.12 WP-H — Release cut
| Test | Mode | Extends / new file | Asserts | Gate |
|---|---|---|---|---|
| `release_acceptance_ci_suite` | C/L | CI (the unified suite) | H2: DL-9 `concurrency-audit` lint (no `block_on` outside the lane bridge, no `tokio::spawn`/`std::sync::Mutex` in core, no `unbounded`, no cross-lane `Sender` import, no `ObligationLeak`/`FuturelockViolation` in test output) + ERG-10 ergonomics drift-guard + DOC-10 doctor fixtures + E0 web-build + **feature-powerset** (`{none·dashboard-api·dashboard-bundle}`×`dashboard_workbench`) + **arch-fitness** (deps-point-inward, D15) | DoD-1..10 |
| `output_schema_and_server_json_validate` | C | `mcp_conformance.rs` + release CI | H2: all changed public tools/operator routes have output schemas + schema-validation; `server.json` schema-validates | DoD-6/10 |
| `clean_machine_e2e_reboot_to_two_agents_two_dbs` | E | new `tests/clean_machine_e2e.rs` (`--ignored`) | H5: reboot → service already running (linger) → `om dashboard` → two agents on two DBs + human workbench, concurrent/isolated (the headline, no mocks) | DoD-10 |
| `rollback_runbook_dry_run` | E | `clean_machine_e2e.rs` | H7: yank + prerelease/delete GH release + GHCR `:latest` + `server.json`; npm `deprecate`+move `latest` (no unpublish); winget/brew lag documented | DoD-10 |

### B.13 Cross-cutting edge-case & negative-test catalog (added v3.18)
*Beyond the per-WP happy/contract rows above, these edge + negative cases harden the highest-risk surfaces.
Each is a named test extending the listed file and is itself a bead test-companion. Grouped by concern; the
modality is implied by the concern + parenthetical.*

**1. Classifier — the security oracle (`adversarial_corpus.rs` + `proptest_invariants.rs` + `fuzz/fuzz_targets/classify_fuzz.rs`):**
- **`classifier_danger_monotonic_under_danger_adding_transforms`** (inclusive MR): `danger(T(sql)) ≥ danger(sql)` for danger-adding `T` — append `FOR UPDATE`, wrap in an anonymous `BEGIN…END;`, append `;DROP…`, add a writing CTE/subquery. A transform may **only raise** the level, never lower it (fail-closed-preserving).
- **`classifier_reclassification_is_idempotent`** (SEC-1/SEC-2): `classify(sql) == classify(normalize(sql))` *and* classify on the normalized form is idempotent — the formal basis for "re-classify at apply, never trust the stored verdict."
- **adversarial corpus rows:** `q'[…]'`/`Q'{…}'` alt-quoting, `N'…'`/`U&'…'` literals, full-width / zero-width / RTL-override keywords, nested `/* /* */`, optimizer hints `/*+ … */`, a `--` line comment eating the newline, a terminator `;` inside a string/quoted identifier, unbalanced quote/comment → **Forbidden (desync fail-closed)**.
- **`sideeffect_oracle_binding_never_loosens`** (Gap-2 MR): binding the real plsql-intelligence oracle never turns a refusal into an admission unless it *proves* read-only; a SELECT over a side-effecting trigger/VPD/UDF flips `Safe→side-effecting`; oracle-unavailable ⇒ `Unknown` ⇒ fail-closed (SEC-3).

**2. Serializer boundary values — invertive-MR edges (`type_fidelity.rs` + `oracledb_contract.rs::contract_type_*` + goldens):**
- NULL for **every** type; empty `Array`; nested `Array`; `Vector::Sparse` with zero indices; `Json` at the depth cap **and** cap+1 (off-by-one); CLOB at the byte cap and cap+1 (truncation flag set); BLOB base64 across `len % 3 ∈ {0,1,2}`; NUMBER 38-digit precision + negative scale + leading/trailing zeros (lossless string); `BinaryDouble` ±Inf/NaN/−0.0; `IntervalDS`/`IntervalYM`; `TimestampTz` at offset 0 / ±14:00 / 9-digit fractional seconds / a DST boundary; an object with a **nested** object/collection → explicit `UnsupportedFeature` (never a silent flatten); REF CURSOR + implicit-result-set row/byte/depth/count caps all enforced.

**3. Lane concurrency — negative/edge beyond N9 A–K (`concurrency_contract.rs` + `lane_state_machine.rs`, lab):**
- **`lost_wakeup_cancel_one_step_before_park`** (DL-6): a cancel issued one step before the lane parks on `recv` is still observed (level-triggered desired-state, re-read on wake).
- **`bulkhead_permit_released_exactly_once_on_panic`** (DL-7): a panic mid-acquire/mid-use releases the permit exactly once — the obligation-leak oracle catches a leak or double-release.
- **`registry_lane_lock_order_ab_ba_unconstructible`** (DL-4): the AB-BA Registry↔Lane acquisition cannot be built (debug rank assert; registry lock never held across a lane send).
- **`switch_profile_at_capacity_keeps_old_conn`** (C-5): acquire-new-before-release-old; on `AtCapacity` the lane retains its old conn (never stranded connection-less) and generation still increments (K2).
- **`abandoned_dirty_lane_reaped_via_mailbox`** (C-1): the watchdog terminates an idle dirty lane by **messaging it** (the reaper never touches the conn); row locks released.

**4. Protocol — negative/edge (`mcp_conformance.rs` + `e2e_http_oauth.rs`; FN0 / R-series):**
- malformed JSON-RPC frame → typed error, **no panic**; oversized body → bounded reject; `Accept`/content-type mismatch → **406** (R7); `DELETE` on a stateless server → **405**, not a false 202 (R8); unknown route → typed-404 **API** vs SPA history-fallback `index.html` (R1 precedence — a typo'd `/operator/v1` must not return 200 HTML); query-string parsed for `/operator/v1` cursor + W5 filters (R6); SSE slow-consumer → bounded-ring **drop + gap-marker** (FN1), never an unbounded buffer.

**5. Recovery paths — SEC-1 shadow codebase (parametrized, `file_store.rs` + `multi_lane_live_xe.rs`):**
- **`every_recovery_path_re_enforces`** — one parametrized test proves CP-apply (W8), the migration runner, `om restore`, audit-replay, and config-reload each **re-run** classifier + level + grant + audit + idempotency; **none trusts a stored verdict** (Axiom 7).

**6. Installer / doctor edges (`installer_smoke.rs` + `doctor_scope.rs`):**
- install **idempotency** (re-install over an existing install is a no-op-or-upgrade, never duplicate units); uninstall reverses **every** touched file/unit; `--offline` with a missing bundle → typed error (never a silent partial install); Rosetta / musl-static detection; doctor detects a **legacy state layout** and offers migration; **audit-chain tamper → detected, never repaired** (DOC-5); a doctor out-of-scope op → **exit 4** (N13).

**7. stdio non-regression (N10 / F1 — `e2e_stdio.rs` + `golden_behavior.rs`):**
- stdio behaves **byte-identical to 0.4.0** (golden); http + stdio coexist with zero interference (F2); **no** lane/Subject/registry machinery is reachable from the stdio path.

**Beading note:** each row above becomes a **test bead** depended-on by its implementation bead (DoD edge), tagged with
its modality + the real file it extends. The `E`/`Web` rows are `--ignored`/env-gated so the default `cargo test`
stays Oracle-free (DoD-8). Appendix A primitives are cited by id (e.g. "lane mailbox = A.3") in WP-N beads so the
implementer reaches for the verified API, not the name.
