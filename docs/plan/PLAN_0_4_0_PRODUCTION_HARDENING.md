# oraclemcp 0.4.0 — Production Hardening Plan

> Status: **DRAFT for bead conversion** (Round 1 complete — 4-reviewer adversarial round
> folded in; Round 2 / Codex complete; see §14). Author: planning session
> 2026-06-19. Source of truth is the code; this plan is grounded in a 2026-06-18/19
> multi-agent research pass (5 peer-MCP reports + oracledb-1.0 + asupersync-audit
> reports) and direct code verification. Convert to beads only after review rounds
> reach steady state (see §13). Do not lose features in refinement (idea-wizard
> Phase 6 rule).

---

## 1. Executive summary

0.3.0 shipped the thin-native Asupersync migration and far more (HTTP OAuth/TLS
wired into the binary, MCP resources/prompts served, tool annotations +
`outputSchema`, `statement_cache_size` applied, NUMBER→string guarantee). **0.4.0
is the production-hardening release: make `oraclemcp` credible for adoption by
large enterprises**, without overclaiming.

The release theme is **honest production-readiness**: higher DB concurrency +
cooperative cancellation (async DB), enterprise auth that is now unblocked (OCI IAM
token), defense-in-depth + DBA-grade read-only diagnostics, and the supply-chain /
observability / audit posture that
procurement teams require — while telling the truth about the parts that are *not*
1.0-frozen (the nightly toolchain and the 0.x upstreams).

**Architectural chain (the defining frame for 0.4.0):**
```
oracledb (pure-Rust thin driver)
  └─▶ oraclemcp  — governed, least-privilege Oracle MCP (read-only default; just-in-time, break-glass escalation up to Admin; audit wiring lands in WP-A8) + the `oraclemcp-db` connectivity layer  ← THE shared foundation
        └─▶ plsql-intelligence (plsql-mcp) — consumes `oraclemcp-db` for live DB access,
                                             adds the offline PL/SQL analyzers
```
Consequence: **`oraclemcp-db` is the canonical shared Oracle-connectivity crate for
the whole family**, not just this binary's internal detail. plsql-intelligence will
depend on it directly (no fork — confirmed with the plsql side). So a first-class
0.4.0 goal is to **make `oraclemcp-db` "perfect"**: a clean, documented, stable
*public* API — its API quality and stability now matter as much as its behavior,
because a second product builds on it.

**This release is explicitly `0.4.0`, not `1.0.0`.** See §11 for why and the gated
path to a future 1.0.

### Positioning — the enterprise story (canonical language; WP-F1 uses this)

We never call oraclemcp "read-only" — it isn't. The accurate and *stronger* framing
names the category enterprises already fund: **Privileged Access Management (PAM)
discipline for AI-to-Oracle access** — least privilege, just-in-time elevation,
break-glass with audit.

> **Identity:** *Governed, least-privilege Oracle access for AI agents.*
> **Tagline:** *Least privilege by default; fail-closed, break-glass escalation — auditable by design.*

Pillars (the enterprise story):
- **Default-deny, fail-closed classification.** Every statement is parsed and
  classified *before* it reaches Oracle; anything not provably within the current
  level is refused. A SELECT can never silently become a DELETE.
- **Least privilege by default.** Sessions start read-only; more is possible only when
  a profile explicitly grants a higher ceiling.
- **Just-in-time, break-glass escalation.** Elevation to write/DDL/admin is explicit,
  preview-then-confirm (single-use token), time-boxed, DML rollback-by-default —
  privilege is *borrowed, not held*.
- **Policy ceilings you cannot exceed.** Per-profile `max_level` is an immutable cap;
  production (`protected`) profiles are pinned; OAuth scopes can only *narrow*
  authority, never widen it.
- **Tamper-evident audit (0.4.0 deliverable, WP-A8 — NOT yet wired in the served
  binary today).** The hash-chained, fsync-before-execute `oraclemcp-audit` ledger
  exists, but `oracle_execute` does not yet append to it; 0.4.0 wires it into every
  privileged/escalation action and adds a keyed MAC + a `verify` tool. **Do not claim
  this in present tense until WP-A8 lands** (§4 item 7, E1/E2/E3).
- **Defense in depth.** Classifier + level gate + level-aware `SET TRANSACTION READ
  ONLY` + recommended least-privilege DB user + scope ceilings — independent,
  fail-closed layers.

Word discipline — **avoid**: "read-only", "can't write", "safe by construction".
**Prefer**: "governed", "least-privilege", "policy-bounded", "just-in-time /
break-glass elevation", "fail-closed / default-deny", "auditable by design
(tamper-evident audit once WP-A8 ships)", "defense in depth", "PAM for AI agents
(single-principal-per-process today)".

---

## 2. The honest production thesis (grounded, with corrections)

These four facts were verified against the actual `rust-oracledb` and `asupersync`
sources and reshape the plan. They are load-bearing; do not let refinement rounds
quietly revert them.

1. **Nightly stays — for the foreseeable future.** `oracledb`'s `docs/ROAD_TO_1_0.md`
   **ADR-0001** keeps asupersync + the pinned nightly through *its* 1.0 (revisited only
   on documented review triggers; a stable backend is not ruled out, but not planned).
   asupersync needs nightly only for two feature gates
   (`try_trait_v2` + `try_trait_v2_residual`) powering `?` on its `Outcome` type
   (`asupersync/src/lib.rs:52-53`, `src/types/outcome.rs:694,718,730`). **"Move to
   stable Rust" is OUT.** The enterprise framing is: *nightly is build-time only and
   invisible to anyone running the static binary* — we sell reproducible/pinned/
   documented-bump nightly, not stable-rustc.
2. **The two upstreams behave very differently — do NOT lump them.**
   - **`oracledb` *will* contract its API at 0.3.0 (not 1.0) — but 0.3.0 has NOT
     shipped (still 0.2.2) and the gate is ADVISORY until it does.** Per `ROAD_TO_1_0`
     **v3.3** **ADR-0002**, `cargo-semver-checks` runs *advisory* during 0.3.0
     development and flips to **blocking** the moment 0.3.0 ships (its API becomes the
     baseline); thereafter growth is overwhelmingly additive (Oracle's protocol is
     backward-compatible) and intentional breaks need a minor bump (0.4.0+) + a baseline
     refresh. **1.0 is a maturity *and* compatibility milestone.** So *once 0.3.0 ships*
     we pin **`^0.3`** (0.3.x patch-safe); **today we pin `oracledb` exactly** (0.2.2,
     pre-contract). The SemVer tooling is PROVEN runnable under the pinned nightly
     (R3/R10) so the contract is *enforceable* — but it is **not yet active**.
   - **`asupersync` is the volatile one** — a 0.x crate on a standard Cargo SemVer
     policy (a breaking change is allowed in each minor, `0.(x+1).0`), shipping
     frequently (~15 releases Feb–Jun 2026, ~9 days apart) with **no 1.0/API freeze**
     and an unpinned-nightly MSRV. **Lock it exactly via `Cargo.lock`** and budget a
     migration pass per minor bump.
3. **"Fully audited" is overstated — be honest.** asupersync's audit is a
   *self-administered* regime (extensive property tests; a loom / Lean / TLA+ regime
   *claimed in the README* but whose loom tests, `.lean` proofs, and `.tla` specs are
   **not shipped in the published 0.3.4 crate** — only prose + a Rust TLA+ export
   surface; no miri infra), and is **not an external/third-party security audit**; its
   API-audit doc (`docs/api_audit.md`) isn't even shipped, and 0.3.4 was published
   `dirty:true`. (These specifics *strengthen* our thesis.) We therefore lead with
   `oraclemcp`'s **own** test/audit posture + supply-chain attestation, and
   **commission our own security audit** — we do not borrow an upstream "audited"
   claim we cannot substantiate.
4. **Two big wins are unblocked NOW (not gated on 1.0):**
   - Native **async, `Cx`-first `Connection`** API exists in `oracledb` source
     (`Connection::connect(cx,…)` lib.rs:1349, `execute_query(&mut self, cx,…)`
     lib.rs:2469). (The closed bead `au9` is the native thin-I/O *transport* slice,
     not the Connection API itself.) `BlockingConnection` is just a thin facade →
     we can drop the per-connection `Mutex` + per-call `block_on` wrapper, enabling
     many in-flight round-trips per runtime + cooperative cancellation (not net-new
     parallelism — the server is already OS-thread-per-connection; see WP-B rationale).
   - **OCI IAM database-token auth** exists (closed upstream bead `rust-oracledb-5bh`;
     `ConnectOptions::with_access_token` lib.rs:1100, redacted `AccessToken` newtype,
     refuses non-TCPS with `Error::AccessTokenRequiresTcps` lib.rs:727).

**The one risk to actively manage:** `oracledb` collapses **19 `execute_query*`
variants → four operation-specific request types (query / execute / execute_many /
register), per `ROAD_TO_1_0` W1-T3 — explicitly NOT a single mega-builder** (and it
has zero `#[non_exhaustive]` today). **This cut-over lands at `oracledb` 0.3.0 — the
W2-T1 migration release in which oraclemcp is a *named* first-party consumer that
migrates — NOT a vague "before 1.0" event.** We build the B2 adapter seam *first* so
that migration is a one-file change, then pin `^0.3` under oracledb's blocking SemVer
contract.

**Relationship to `oracledb` 0.3.0 — design for it, but do NOT assume it exists yet.**
oraclemcp 0.4.0 ships **fully on the current `oracledb` 0.2.2**. The 0.3.0 features we
plan to *consume, not rebuild* — the four-op API, typed errors
(`connection_disposition()`/`retry_hint()`/`Error::kind()`), wire-level
**`ProtocolLimits`/`ResourceLimit`** (W1-T5), and redacted pool metrics (W1-T6) — are
**DESIGNED but NOT BUILT**: every implementing bead is OPEN, `oracledb` Wave 1 has just
begun (only W1-T1.1 in-progress), and a workspace grep for `connection_disposition` /
`retry_hint` / `ProtocolLimits` / `ResourceLimit` returns **zero hits**. **0.3.0 has no
date.** So all "consume" items are **post-0.3.0 deferred upgrades**, each carrying its
upstream bead id as a blocker (W1-T5.x, W1-T6.x, W2-T1.x) — *not* 0.4.0 work. Today the
B2 adapter maps against the **actual 0.2.2 error surface** — `ora_code()`,
`is_connection_lost()`, `is_transient()`, `is_retryable()` (`oracledb/src/lib.rs:787/
848/870/882`) — and pool dirty-discard uses those, with `connection_disposition()` a
documented post-0.3.0 refinement.
**Coordination (load-bearing, not optional):** oraclemcp's migration to the four
families is itself a **publish-blocker for `oracledb` 0.3.0** — upstream bead **W2-T1.3**
("Migrate oraclemcp to the four operation families", owner durakovic), whose acceptance
is "oraclemcp builds + its W3-E7 contract suite passes." So B2 must deliver a
**pre-flighted migration against an `oracledb` 0.3.0 RC / git-pin**, driven by
`oracledb`'s published `docs/MIGRATING-0.3.md` (W2-T1.6). The deprecated old-name shims
ship **only in 0.3.0** and are removed before `oracledb` 1.0.0-rc.1 — so oraclemcp must
migrate **fully** at 0.3.0 adoption, never lean on shims. The **"direct oraclemcp
contract suite" lives in the `oracledb` repo** (W3-E7.3, owner durakovic, run on
`oracledb`'s RC SHA); oraclemcp must provide/maintain that contract surface — a
reciprocal cross-repo release gate, not an afterthought.

**Stays fail-closed / out of our control — and OUT of `oracledb`'s 1.0 roadmap
(Group-A):** passwordless/external wallet auth (`o0b`), Kerberos/RADIUS + a unifying
typed `AuthMode` (`qm4`); IAM *resource-principal request-signing* (`cco`, only
db-token strings exist). **But wallet support is NOT all-or-nothing:** unencrypted
`ewallet.pem`, `cwallet.sso`, and `wallet_password` **already work** in the pinned
driver — only encrypted-PEM / standalone-`.p12` are the `x1p` gap. So doctor (A2/A5)
must report the working wallet modes as **supported**, not blanket fail-closed.

---

## 3. Current state (what **oraclemcp** 0.3.0 already shipped — do not re-do)

(Note: this is *oraclemcp's* shipped 0.3.0 — distinct from the *`oracledb`* driver's
upcoming 0.3.0 migration discussed in §2.) Verified via CHANGELOG `[0.3.0]` and code.
Already done, **out of 0.4.0 scope**:
HTTP Host/Origin allowlists + OAuth issuer/resource/scope validation + protected-
resource metadata + rustls TLS/mTLS in the binary; MCP `resources/list|templates/
list|read` and `prompts/list|get` served; explicit tool titles + annotations
(readOnly/destructive/idempotent/openWorld); `outputSchema` for `oracle_query`/
`query`/`oracle_explain_plan` (NUMBER stays lossless string); thin profile coverage
(proxy/wallet/TLS DN-SNI/app-context/SDU/DRCP/edition); bounded DBMS_OUTPUT;
`statement_cache_size` now reaches the driver; forbidden-dependency CI gate; the
`oracle_session` deliberate-non-wire decision; NUMBER→string differential guarantee.

Baseline crate map (the engine-free spine, also consumed by `plsql-mcp`):
`oraclemcp-error`, `-telemetry`, `-audit`, `-guard`, `-config`, `-db`, `-auth`,
`-core`, and the `oraclemcp` binary. All `#![forbid(unsafe_code)]`, `panic=abort`,
nightly-2026-05-11.

---

## 4. Non-negotiable invariants (carry forward; never weaken)

1. **Fail-closed guard + guarded operating-level ladder (NOT read-only-only).** Every
   raw statement is classified before any I/O. oraclemcp exposes a ladder
   `ReadOnly < ReadWrite < Ddl < Admin`: read-only is the DEFAULT and the cap for
   unconfigured/`protected` profiles, but a profile's `max_level` may permit
   **confirmation-gated escalation up to Admin** (preview→token step-up, TTL-bounded
   elevation, classifier still gating every statement at the *current* level, DML
   rollback-by-default, `protected` profiles pinned immutable, OAuth scopes that only
   *lower*). Every privileged action is **meant to** land in the audit hash-chain —
   but that wiring does not exist in the served binary yet and is a 0.4.0 deliverable
   (WP-A8); do not assert it as current. The invariant to preserve is this whole guard
   — never bypass the classifier or the level gate, never exceed a profile's
   `max_level`, never make a protected profile writable, never auto-commit. (This
   server is *guarded*, not read-only; see README §"operating levels" and
   `oraclemcp-guard/src/levels.rs`.)
2. **NUMBER→string lossless by default** (float opt-in only).
3. **`#![forbid(unsafe_code)]`** in every crate; engine-free one-way crate DAG
   (boundary lint); no thick mode / Instant Client / Tokio / rmcp / Axum / Hyper /
   r2d2.
4. **Session-lease invariant** — one physical session, forced rollback on
   expiry/release; dirty connections discarded from the pool.
5. **Secrets never logged**; doctor/error output sanitized; allow-token ≠ control.
6. **Shared-spine discipline** — features intended for both binaries live in the
   `oraclemcp-*` spine so `plsql-mcp` inherits them. (`oraclemcp` keeps read-only as
   its *default* posture — not a hard limit; it has the guarded ladder, §4 item 1.)
7. **Honesty guardrails (new for 0.4.0)** — public docs/marketing MUST NOT claim:
   "stable Rust" / "independently audited dependencies" / "1.0-frozen API" for the
   nightly/asupersync/oracledb stack; **"read-only only" / "cannot write"** (it ships a
   confirmation-gated escalation ladder up to Admin, §4 item 1); **"tamper-evident
   audit" / "fully audited" / "every action audited"** until WP-A8 wires + signs the
   served audit path (E1/E2); nor **imply per-caller authority** — today it is
   single-principal-per-process (one profile chosen at start), not per-identity RBAC
   (E9, §11). Position the *guardrails*, not the absence of capability. Enforced by a
   mechanical **honesty-grep DoD gate** (§8 item 8) that fails on "safe-by-default",
   "read-only binary", "fully audited", or un-caveated "PAM"; the doc sweep
   (`README.md` + `docs/behavior-inventory.md`) is WP-F1. Claims must be substantiable
   (§10, §11).

---

## 5. Scope — IN vs OUT for 0.4.0

All four chosen work-streams are IN. Ergonomics + finish-proto fold in as low-cost
adds. Everything else is explicitly deferred with a reason.

### IN (the release)
- **WP-A** Trust & safety depth + enterprise auth (OCI IAM token) + audit-wiring (A8) +
  compile-time capability narrowing (A9).
- **WP-B** Async DB migration + driver-adapter seam + net load/shutdown soak gate.
- **WP-C** Read-only DBA diagnostic suite (health + top-queries + preflight).
- **WP-D** Production ops & supply-chain (observability, SBOM/provenance/signing,
  nightly re-pin runbook + multi-nightly CI, hardening/threat-model docs, security
  audit, live-latency perf evidence, ADRs, severity policy + exact-SHA qualification).
- **WP-E** Ergonomics & finish-proto (pagination, export-to-resource + result-link,
  unified `search_objects`, connection-scope isolation, progress/list_changed,
  completions, `resources/subscribe`).
- **WP-F** Positioning docs (with §4 item 7 honesty guardrails).

### OUT (post-0.4.0 / blocked; keep as deferred beads with reasons)
| Item | Why out |
|------|---------|
| Passwordless/external wallet auth | Upstream `oracledb` `o0b` open/unimplemented |
| Kerberos / RADIUS auth | Upstream `oracledb` `qm4` open; keep fail-closed; only adopt typed `UnsupportedAuthMode` classification when it lands (WP-A5) |
| IAM resource-principal request-signing | Upstream `oracledb` `cco` open (only db-token strings exist) |
| SQL/Index advisor (`DBMS_ADVISOR`/`DBMS_SQLTUNE`) | **DECISION 2026-06-19: OUT.** These are paid Oracle **Tuning/Diagnostics Pack** features the *customer* licenses from Oracle; invoking them creates silent license liability for the customer (Oracle LMS audits `DBA_FEATURE_USAGE_STATISTICS`). oraclemcp **never invokes a paid-pack feature** — `doctor` only *detects & reports* pack licensing (WP-C C9), consistent with the existing `awr.rs` AWR→Statspack gating. No advisor tool ships. |
| Segment/space advisor | P3, licensing-adjacent; post-0.4.0 |
| Schema-context / RAG retrieval tool | P3, larger design; post-0.4.0 |
| Hypothetical-index what-if (INVISIBLE indexes) | Needs CREATE/DROP INDEX — a **DDL-level** operation, which oraclemcp *does* support via escalation; deferred on **priority** (P3), not capability. Post-0.4.0, gated at the `DDL` operating level. |
| Async/background long-query (task id + poll) | P3; only if users hit the configurable call-timeout ceiling |
| Elicitation confirm-UI | P3; keep bespoke OOB step-up; only non-sensitive confirmations ever |
| Move to stable Rust | Blocked by `oracledb` ADR-0001 upstream (see §2 item 1) — nightly stays through its 1.0 |
| Per-caller identity→profile RBAC | post-0.4.0; today **single-principal-per-process** (one `--profile` at start). OAuth scopes already *narrow* the level, but binding the authenticated caller (`sub`) to a profile/credential is future (E9, §11) |
| Per-caller request-rate / query-cost limiting | post-0.4.0; today the boundary is admission-concurrency caps + the configurable per-profile call timeout (hard ceiling 3600s) + row(≤5000)/body(1 MiB) caps — no req/sec throttle, no plan-cost budget (E10, §10) |
| Result-set PII redaction/masking | rows return unmasked; defer to DB-side VPD / Oracle Data Redaction at the connected user (E11) — operator responsibility, with an honesty note in docs |

---

## 6. Work packages

Each WP lists: rationale, tasks (with the verified code area), acceptance criteria
(incl. tests with structured logging), and dependencies. Effort S/M/L is rough.

> **ID convention (avoid the E# collision):** bare `A#/B#/C#/D#/E#/F#` are WP **task**
> IDs (defined in this section). In *parenthetical citations* elsewhere, `E1–E11` and
> `T1–T7` are **review-round finding** IDs (rev-ent / rev-tech) and `R2-xx` are Codex's;
> they are NOT WP-E tasks. (E.g. "A8 … fixes E1/E2" = the *audit* findings, not the
> WP-E `resources/subscribe`/`pagination` tasks.)

### WP-A — Trust & safety depth + enterprise auth
*Rationale:* oraclemcp's core differentiator is its **guardrails on an
escalation-capable server** — a fail-closed classifier + a confirmation-gated
operating-level ladder (`ReadOnly→ReadWrite→DDL→Admin`, per-profile ceiling,
TTL-bounded step-up, DML rollback-by-default) + a tamper-evident audit hash-chain
(the ledger crate exists; WP-A8 wires it into the served path) — NOT "it can't write." No official Oracle MCP offers *provable, ceiling-bounded,
auditable* privileged access; SQLcl delegates to DB privileges with no classifier,
genai-toolbox is a flippable Query-vs-Exec flag with no parser. Big enterprises buy
that guardrail story + cloud auth. This WP hardens it: defense-in-depth at the
read-only level, auditability of every privileged action, and enterprise cloud auth.

- **A1 (M)** **Lazy, per-statement read-only backstop** (defense-in-depth; this is
  *layer B* — *layer A*, the real boundary, is the least-priv DB user in A2). Before
  each statement on the **pinned lease/primary session**, if
  `effective_level()==ReadOnly` ensure `SET TRANSACTION READ ONLY` is in force, else
  ensure it's lifted. It is **not** a connect-time one-shot: `SET TRANSACTION READ
  ONLY` is **transaction-scoped** (ends at the next COMMIT/ROLLBACK), and
  `effective_level()` can drop to ReadOnly **silently** when an elevation TTL window
  expires (`guard/levels.rs` — there is no de-escalation *event* to hook), so it must
  be re-asserted at the start of every read transaction (post-commit/rollback/
  lease-reset). **Scope:** the pinned lease/primary session ONLY — it is *incoherent on
  the stateless metadata pool* (different physical session per checkout), which relies
  on A2's read-only user instead. **Caveat:** best-effort — does not stop
  autonomous-transaction side effects (that's the classifier's + A2's job). *Area:*
  `oraclemcp-db/src/connection.rs` (lease/txn path), dispatch. *AC:* at ReadOnly a
  classifier-bypassing write is refused by the DB **even after a prior COMMIT/ROLLBACK
  cycle** and after a silent elevation-window expiry; after a confirmed escalation the
  same write succeeds; backstop re-asserted on return to ReadOnly.
- **A2 (S)** Read-only proxy-user/role posture: `doctor` reports whether the
  connected principal can write and warns; README documents the recommended
  least-privilege grant set. *Area:* `oraclemcp-core/src/doctor.rs`.
- **A3 (M)** Per-statement audit marker comment
  `/* oraclemcp llm=<model> profile=<name> tool=<tool> */` prepended to every
  executed statement (SQLcl-style; greppable in `V$SQL`/ASH without trusting the
  client). **Classify the MARKED text, not the bare SQL** — the live pipeline
  classifies the exact text it executes (`dispatch/mod.rs` `classify(&args.sql)`), so
  prepend the comment first, then classify the marked text and confirm the SAME
  decision (executed text == classified text, preserving §4 item 1). Leak no secrets;
  the A8 audit digest covers the marked text actually sent. *AC:* live test shows the
  marker in `V$SQL`; unit test asserts the marked SQL yields the same classifier
  verdict as the bare SQL; an adversarial/fuzz case proves the marker can't be an
  injection vector (e.g. a forged `*/` in `<model>`).
- **A4 (M)** Dynamic `V$SESSION` MODULE/ACTION/CLIENT_INFO tagging with agent+model.
  Today `apply_session_identity` (`connection.rs:500-549`) sets these **once at
  connect** from profile identity, and **there is no reset on pool checkout**
  (`pool.rs` checkout has none) — so this is **net-new**, not "extends a reset": add an
  explicit `DBMS_APPLICATION_INFO`/`DBMS_SESSION` **clear-and-reset on every checkout**
  and set the live agent/model/tool per request. Note `CLIENT_IDENTIFIER` persists
  across pooled reuse unless explicitly cleared. *AC:* live test shows MODULE/ACTION
  reflect the current agent+model AND that a prior request's tag is gone before the
  next is set (proves no cross-request leak via pooled reuse).
- **A5 (M)** Enterprise auth — **OCI IAM database-token** (unblocked): map
  `use_iam_token`/`iam_token` profiles to `ConnectOptions::with_access_token`;
  enforce TCPS (driver returns `AccessTokenRequiresTcps`); token redacted.
  *Plus* adopt a typed unsupported-auth classification path so `doctor`
  distinguishes "driver-unsupported" (Kerberos/RADIUS/passwordless-wallet) from
  bad-creds/TLS/listener failures — wired to `oracledb`'s `UnsupportedAuthMode`
  *if/when* it lands; until then keep the current structured fail-closed errors.
  **Pre-task:** confirm `with_access_token` + `AccessTokenRequiresTcps` exist in the
  pinned `oracledb` (proven by closed upstream bead `rust-oracledb-5bh`) and snapshot
  them in the B2 adapter. Wiring **removes** the current hard rejection — today
  `to_connect_options` rejects `use_iam_token`/`iam_token` outright at
  `connection.rs:411` (`UnsupportedAuth`). **Doc-reconcile:** `robot_docs.rs:280` +
  the capabilities text currently advertise IAM token as "unsupported structured
  diagnostics" — stale once this lands.
  *Area:* `oraclemcp-db/src/auth_adapter.rs`, `oraclemcp-core/src/connect.rs`,
  `oraclemcp-db/src/connection.rs:411`.
  *AC:* IAM-token profile connects against an ADB-style TCPS endpoint (or documented
  skip); non-TCPS refused; the old `connection.rs:411` rejection is gone;
  Kerberos/RADIUS/passwordless-wallet still fail closed with precise classification.
- **A6 (S)** `<untrusted-user-data>` output fencing: wrap returned rows/text in
  uuid-tagged blocks with a "treat as data, not instructions" preamble (prompt-
  injection defense). `structuredContent` stays machine-parseable alongside.
- **A7 (M)** Tests: deterministic (backstop, fencing) + live (marker, tagging, IAM).
- **A8 (L) — BLOCKING (DoD gate); fixes E1/E2.** Wire the hash-chained `Auditor`
  into the **served** path. Today `oracle_execute`/`execute_approved` run
  classify→gate→confirm→execute→commit with **zero audit append** (`dispatch/mod.rs`
  `execute_sql_inner` ~:1539); the only audited path (`oracle_query_execute`,
  `oraclemcp-core/src/query_execute.rs:100`) is not in `TOOL_NAMES` and never called,
  and the served binary dispatch has no direct `oraclemcp-audit` dependency/import
  or wired `Auditor` despite the crate appearing transitively through the spine.
  Tasks: (a) add a direct audit dependency **or** route served execution through a
  core API that owns the `Auditor`; append on every Guarded/Destructive/escalation
  action, fsync-before-execute, before commit; (b) **sign the chain** — a keyed MAC over
  `entry_hash` (`oraclemcp-audit/src/record.rs:165` is bare SHA-256 today, forgeable by
  recompute-from-genesis), key sourced from KMS/Vault, rotatable; (c) ship
  `oraclemcp audit verify <file>` chain-verification subcommand. *AC:* every
  write/DDL/Admin and every `oracle_set_session_level` escalation produces a signed
  audit record provable by `audit verify`; a tamper (in-place edit OR full
  recompute-without-key) is detected; deterministic + live tests. **Until A8 lands,
  the audit positioning claims in §1/§4 item 1 are struck.** *(Pairs with D2 shipping +
  D5 threat model.)*
- **A9 (M)** **Compile-time capability narrowing** (asupersync `cap` model;
  defense-in-depth *above* the runtime operating-level ceiling). Narrow the `Cx`
  capability row `[SPAWN,TIME,RANDOM,IO,REMOTE]` at the dispatch boundary so a read-path
  tool **structurally cannot** spawn, do remote, or use ambient randomness — only the
  effects it needs (TIME + the DB I/O path). Use `SubsetOf` monotone narrowing (widening
  is compile-time rejected; marker traits are sealed). *Why:* makes least-authority part
  of the type system, not just runtime policy — a buggy/forged higher-effect call won't
  compile. *Area:* `oraclemcp-core` dispatch / `Cx` plumbing. *AC:* read tools receive a
  narrowed `Cx` (no `SPAWN`/`REMOTE`/`RANDOM`); a compile-fail fixture proves a read
  handler cannot spawn or do remote I/O. **Caveat:** stays *under* the fail-closed
  classifier + operating-level gate (those remain the primary boundary); this is
  structural reinforcement, not a replacement.

### WP-B — Async DB migration + adapter seam + load evidence
*Rationale:* the win is **not** "adds concurrency the server lacks" — the HTTP server
already runs OS-thread-per-connection. It is removing the **per-connection
`Mutex<oracledb::Connection>` + the per-call blocking-runtime (`block_on`) wrapper**,
enabling many in-flight DB round-trips per asupersync runtime and **cooperative
cancellation** (today a blocked round-trip can't be cancelled cleanly). The adapter
seam de-risks the upstream execute-API churn; load/soak evidence (B3) measures *that*
win, not phantom parallelism, and closes our own + asupersync's net evidence gap.
**Convergence note (§12):** because `plsql-catalog` will adopt `oraclemcp-db`
post-0.4.0, design the new async `OracleConnection` trait as the **canonical,
published, documented** Oracle-connectivity API — free of `oraclemcp`-binary-specific
assumptions, so the sibling can consume it cleanly.

- **B1 (L)** Migrate the DB trait from `BlockingConnection` (per-call runtime +
  `block_on` + ambient-`Cx` lookup) to the native async `Connection`
  (`conn.execute_query(&cx,…).await`). Remove the `build_io_runtime()`/`block_on`
  wrapper; keep one asupersync runtime. *Area:* `oraclemcp-db/src/connection.rs`
  (`db_checkpointed`, `RustOracleConnection`), `pool.rs`, `query.rs`, and the
  then-present `lease.rs` (later deleted by B14b as a dead subsystem).
  **Decision (2026-06-19): the FULL migration is in 0.4.0 — not split.** No
  partial/seam-only fallback; the entire DB path becomes async in this release.
  **Upside beyond removing the mutex/`block_on`:** async unlocks oracledb's zero-copy
  `_ref` *borrowed-fetch* family (`fetch_rows_ref` / `for_each_row_ref`), which IS
  async-only because the returned borrow of the connection buffer can't cross
  `block_on` (W1-T8) — unavailable on `BlockingConnection` today. (Direct-path is
  *already* on the blocking facade via `block_on` and returns owned results, so async
  does **not** unlock it — corrected vs an earlier draft.) **Outcome
  discipline (asupersync):** preserve `Cancelled`/`Panicked` distinctly — do NOT flatten
  to `Err` early; map at the MCP boundary (`Cancelled`→TIMEOUT/cancel, `Panicked`→
  connection Dead + heavier evidence). Never hold the session-lease across an indefinite
  await. *Tradeoff accepted:* this migrates the adapter internals twice (async now vs
  the 19-variant API; four-op API at oracledb 0.3.0 via the B2 seam) — worth it for the
  async win now, given 0.3.0 has no date.
  *AC:* all DB calls are `async`/`&Cx`; **complete test coverage** — unit +
  chaos/cancellation (all green) + live-XE; no `block_on` anywhere in the DB path
  (grep-verified); pool dirty-discard correct — **post-oracledb-0.3.0, consume
  `connection_disposition()`** to recover Reusable sessions rather than discard-on-any-error.
- **B2 (M)** Internal **driver-adapter seam**: one module wraps every `oracledb`
  call (connect, the `execute_query*` family, fetch, LOB, cursor, auth). All of
  `oraclemcp` calls *our* adapter, never `oracledb` directly. *Rationale:* when
  upstream collapses 19 `execute_query*` → four operation-specific request types
  (query/execute/execute_many/register, per `ROAD_TO_1_0` W1-T3) (and given zero
  `#[non_exhaustive]`), the churn touches one file. **That cut-over is the named
  `oracledb` 0.3.0 / W2-T1 migration** (oraclemcp is a listed first-party consumer);
  after it, pin `^0.3` under oracledb's blocking SemVer contract. The adapter is also
  where we consume oracledb's typed errors/`connection_disposition()` (W1-T6) and
  surface `ResourceLimit` (W1-T5) once 0.3.0 lands. **0.3.0 cut-over scope — ALL of
  this churn funnels through this one seam** (per ROAD_TO_1_0 v3.3): (i) method-name
  consolidation (four families); (ii) **single absolute op-deadline** replacing
  per-call `timeout_ms` (W1-T3 principle 7 — a `Duration` translated once, tighter `Cx`
  deadline wins; B3 latency baselines re-validate); (iii) **accessor-based** result/
  metadata types + selective `#[non_exhaustive]` value/open enums (W1-T4) — the adapter
  must use accessors + `as_*`/wildcard arms, never exhaustive `match` on
  `oracledb::{BindValue,QueryValue,Error}`; (iv) **module/re-export path moves** (W1-T9
  — single canonical path / possible prelude); (v) **deprecated old-name shims ship
  only in 0.3.0 and are removed before oracledb 1.0.0-rc.1** — migrate FULLY, never lean
  on shims. Drive the cut-over from `oracledb`'s `docs/MIGRATING-0.3.md` (W2-T1.6) so no
  capability is silently dropped; the migration is a **publish-blocker for oracledb
  0.3.0** (W2-T1.3, §2). *AC:* `grep` proves no `oracledb::` call outside the adapter;
  a comment block documents the 0.3.0 cut-over plan; pin `oracledb` exactly (today) /
  `^0.3` (post-0.3.0); the no-`oracledb::`-outside-adapter grep is a pre-0.3.0 readiness
  gate.
- **B3 (M)** Net **load + shutdown soak** evidence as a release gate: high-
  concurrency query load test + sustained graceful-shutdown soak under
  cancellation, with structured metrics, recorded in `docs/performance-footprint.md`
  (incl. the **live Oracle latency p50/p95/p99** numbers currently omitted).
  Closes asupersync's documented net load/shutdown evidence gap for our usage.
  *AC:* documented load/soak run with no leaked sessions, bounded latency, clean
  drain; numbers committed.
- **B4 (S)** Connection-pool tuning + failover posture review for the async path
  (RAC/ADB awareness, acquire-timeout, dirty-discard under async cancellation). NOTE:
  oracledb 0.3.0 flips its OWN pool async-native (`acquire(&self, cx, AcquireOptions)`,
  `PoolEngine` → `pub(crate)`, Drop-enqueued return + `release(&Cx).await`, region-owned
  reaper — W1-T7). **Decision:** oraclemcp keeps **its own** bounded pool in
  `oraclemcp-db` and consumes single async `Connection`s — so it does NOT inherit
  oracledb's pool-shape change; revisit only if we ever adopt `oracledb::Pool` (then it
  routes through B2).
- **B5 (M)** **Make `oraclemcp-db` the canonical shared foundation** (the whole
  point of the chain in §1). Treat its public API as a product, not an internal
  detail: minimal/clean public surface for the async `OracleConnection` trait + types
  (no `oraclemcp`-binary-specific leakage), full rustdoc with examples, a
  `cargo public-api` snapshot locked in CI to catch unintended breaks, an explicit
  semver/stability note in the crate README, and confirmation it builds/links
  standalone (it is already published via `publish_crates.sh`). *AC:* `cargo doc` has
  no missing-docs on public items; `cargo public-api` snapshot committed + CI-checked;
  a smoke crate outside the workspace can depend on `oraclemcp-db` and run a query;
  no **binary-specific** types appear in `oraclemcp-db`'s public API. NOTE: the public
  API already (intentionally) re-exports the published spine deps `oraclemcp-error`
  (`lib.rs:82 pub use oraclemcp_error as error_envelope`) and uses
  `oraclemcp-guard::MonotonicDeadline` — these are accepted published-spine deps (the
  whole family pins them); the `cargo public-api` snapshot **locks them in** so the
  break-detection is meaningful, rather than pretending the surface is dependency-free.
  **Upgrade (oracledb-proven):** `cargo public-api` AND `cargo-semver-checks 0.48.0`
  both run cleanly under `nightly-2026-05-11` (oracledb R3/R10) — so adopt
  **`cargo-semver-checks`** for `oraclemcp-db` (a real SemVer contract for the shared
  foundation, mirroring oracledb ADR-0002), not merely a public-api snapshot. Pin and
  install the exact `cargo-public-api` tool in CI/preflight; it is not guaranteed to
  exist in local pinned-nightly environments.
- **B6 (S)** Adopt asupersync **`Budget`** (deadline + poll/cost quota + priority, with
  `meet()` propagation) for per-request bounds instead of only the configurable per-profile call timeout, and
  give cleanup/finalizers a short *bounded* budget. Partly addresses E10's per-request
  cost bound (per-*caller* rate-limiting still needs caller→profile binding, §11).

### WP-C — Read-only DBA diagnostic suite *(oraclemcp spine now; does NOT auto-inherit to plsql-mcp — shared only after post-0.4.0 convergence, §12)*
*Rationale:* the Postgres-MCP-Pro-style differentiator; pure read-only `V$`/`DBA_*`
value DBAs love. **Build in the oraclemcp spine** (`oraclemcp-db` + registry/dispatch)
because this is the same place `awr.rs::top_sql_query` already lives. `plsql-mcp`
does **not** inherit WP-C automatically today: it currently consumes the published
`oraclemcp-core`/`-error`/`-guard` spine and uses its own `plsql_catalog::OracleConnection`;
WP-C becomes shared for `plsql-mcp` only after the future convergence described in §12.

- **C1 (M)** `oracle_db_health` tool framework: `health_type='all'` or comma list;
  read-only; aggregates per-subcheck findings with severity + source view; privilege
  degradation `DBA_*→ALL_*`. *Area:* `oraclemcp-db` + registry/dispatch.
- **C2–C7 (S each, depend C1)** Subchecks: invalid objects (`DBA_OBJECTS`),
  unusable/unused indexes (`DBA_INDEXES`/`V$OBJECT_USAGE`), tablespace+UNDO headroom
  (`DBA_TABLESPACE_USAGE_METRICS`), sequence-ceiling exhaustion (`DBA_SEQUENCES`),
  disabled/NOVALIDATE constraints (`DBA_CONSTRAINTS`), buffer-cache hit
  (`V$BUFFER_POOL_STATISTICS`/`V$SYSSTAT`). Each view name is a claim to verify
  live against 23ai during implementation.
- **C8 (M)** `oracle_top_queries`: **surface the existing `awr.rs`**
  (`top_sql_query`, `DiagnosticsSource{AwrAsh,Statspack}`, `detect_statspack`,
  `select_diagnostics_source`) — rank by elapsed/CPU/buffer-gets/disk-reads + a
  5%-of-total mode over `V$SQL`/`V$SQLSTATS`; AWR (`DBA_HIST_*`) gated behind
  Diagnostics-Pack licensing, Statspack fallback, else structured-unavailable.
- **C9 (S)** Extend `doctor` with a privilege/feature preflight for the suite
  (`V$`/`DBA_*` access, pack licensing via `control_management_pack_access`).
  **Report-only**: it tells the operator which grants/packs are present or missing;
  it MUST NOT invoke any paid-pack feature (no `DBMS_SQLTUNE`/`DBMS_ADVISOR`, no AWR
  query unless Diagnostics Pack is confirmed licensed — mirror `awr.rs` gating).
- **C10 (M)** Tests: unit (SQL shape) + live (each subcheck, top-queries Statspack-
  fallback path, privilege degradation), structured logs, clean SKIP without Oracle.

### WP-D — Production ops & supply-chain
*Rationale:* the procurement-grade layer. This is what lets a big company's security/
platform team say yes.

- **D1 (M)** **Full OpenTelemetry observability** (decision 2026-06-19 — full, not
  a subset; approach settled 2026-06-19 — **adopt asupersync's own Tokio-free OTLP
  surface**, so the effort dropped from L to M):
  - **Traces** — OTLP export (HTTP/protobuf; gRPC intentionally absent — see
    Transport below); span tree per request →
    dispatch → classify → DB call → serialize, with attributes (tool, profile,
    operating level, row counts, cache hit, ORA code), secrets redacted; W3C
    trace-context propagation from the MCP client.
  - **Metrics** — OTLP: request count/duration histograms (p50/p95/p99),
    classifier-reject counter, pool saturation + checkout-wait, lease lifetime,
    DB-call latency, error-class counters.
  - **Logs** — structured logs exported via OTLP, correlated by trace id.
  - **Health** — `/healthz` (liveness) + `/readyz` (DB reachability) on the HTTP
    transport.
  - **Conventions/config** — OTel `db.*` semantic conventions where non-leaking;
    standard `OTEL_EXPORTER_OTLP_*` env + CLI/profile toggle; off by default; sampling.
  *Area:* `oraclemcp-telemetry` (the exporter/subscriber home — already hosts
  logging/health/metrics and notes the OTLP mapping in `metrics.rs`),
  `oraclemcp-core/src/http.rs` (health endpoints).
  **Layering — the OTLP exporter is NOT in the driver (answers "should OTLP live in
  the thin driver?" → no):** the thin `oracledb` driver ALREADY emits per-round-trip
  `tracing` spans (connect/execute/fetch) behind an optional, **zero-cost-when-off**
  `tracing` feature (`oracledb/src/obs.rs`, bead `rust-oracledb-lv6`); the default
  build compiles in nothing. A low-level driver must emit via the runtime-agnostic
  `tracing` facade and let the *application* export — it must not bundle a telemetry
  backend. So oraclemcp enables `oracledb`'s `tracing` feature (DB-call spans flow in
  for free) and owns the OTLP **exporter** in `oraclemcp-telemetry`. **Two tiers (be
  explicit):** (a) oracledb **0.2.2 already** emits per-round-trip connect/execute/fetch
  spans behind its `tracing` feature (lv6, shipped) — consume these NOW; (b) oracledb's
  W1-T6 redacted **pool metrics + cancel-phase + connection_disposition** signals are
  NOT in 0.2.2 and arrive only with the 0.3.0 migration — gate those D1 attributes
  behind 0.3.0 adoption, don't assume them in the 0.4.0-on-0.2.2 build. Either way, **Consume
  oracledb's W1-T6 redacted tracing + pool metrics** (post-0.3.0) rather than
  re-instrumenting the DB layer — no double-instrumentation. Bonus: shared-foundation
  win — once plsql-mcp converges on `oraclemcp-db`/`-telemetry` (§12), it inherits both
  the driver spans and the exporter.
  **Approach (settled — reuse asupersync primitives; do NOT build transport/retry/
  queueing from scratch):** asupersync already ships a Tokio-free OTLP HTTP/protobuf surface behind its
  **`metrics`** cargo feature (`observability::otel`):
  `OtlpHttpExporter::send_otlp_protobuf(cx, bytes)` sends over asupersync's own HTTP/1
  client + runtime (no tokio/reqwest/hyper); prost-encoded messages; `W3CTraceContext`
  extract/inject; a metrics registry (`Counter`/`Gauge`/`Histogram`); bearer/api-key
  auth, gzip (`compression` feature), retry/backoff. Wire it via
  `asupersync = { version = "0.3.4", default-features = false, features = ["metrics"] }`
  (+ optional `"compression"`).
  - **Logs** — **turnkey** (`OtlpLogsHttpExporter` + `LogsSnapshot::to_otlp_protobuf`).
  - **Metrics + traces** — no production pre-wired HTTP exporter for these two. The
    reusable production pieces are the generic `OtlpHttpExporter`, `MetricsSnapshot`,
    `LoadSheddingExporter`, and trace-side `TraceExporter`/`LoadSheddingTraceExporter`;
    asupersync's richer metrics/trace proto request builders are `cfg(test|fuzz)` +
    `opentelemetry-proto`, so they are **NOT reachable from a `metrics`-only prod build**.
    oraclemcp therefore **owns its prod protobuf mapping** (either small local prost
    `ExportMetricsServiceRequest`/`ExportTraceServiceRequest` structs following
    asupersync's `otlp_logs_proto`, or an upstreamed production builder that preserves
    the no-tonic/no-tokio graph), then sends bytes through `send_otlp_protobuf`. Build a
    full **`tracing_subscriber::Layer` → trace batch bridge** (span open/close,
    field+timing capture, attribute mapping, secret redaction, W3C trace/span-ID
    threading, batching) and wrap traces with asupersync's `LoadSheddingTraceExporter`
    instead of inventing a second backpressure queue. This bridge is a real component,
    not a shim — the **heavy end of M, plausibly L**.
    **Split at bead conversion** into: logs-wiring, metrics-encoder, trace-bridge,
    health-endpoints.
  - **Health** — expose `/healthz` + `/readyz` on oraclemcp's existing asupersync HTTP
    server, backed by asupersync health reports + a DB-reachability probe.
  - **Transport** — HTTP/protobuf only (gRPC intentionally absent; `tonic` would
    reintroduce tokio).
  **TRAP (load-bearing):** enable ONLY asupersync `metrics` (+ `compression`). Do NOT
  pull `opentelemetry-proto` with `gen-tonic-messages`, nor the opentelemetry SDK
  `rt-tokio` feature — either reintroduces `tonic → tokio` and fails the boundary lint
  (asupersync gates `opentelemetry-proto` behind its dev-only `fuzz` feature for
  exactly this reason). Empirically verified: `metrics`(+`compression`) yields a graph
  with **no tokio/reqwest/tonic/hyper**.
  *AC:* OTLP logs+metrics+traces reach a collector via asupersync's exporter; `/healthz`
  + `/readyz` live; `cargo tree -e normal -i tokio` and `-i reqwest` empty + boundary
  lint green; no secrets in telemetry; W3C context propagated from the MCP client. The
  exporter batch/flush loop is **region-owned with a bounded shutdown budget** (NOT a
  detached spawn — asupersync anti-pattern); **telemetry failure drops, never blocks
  the request path**. NOTE the exporter uses asupersync's *outbound* HTTP client (net is
  lane-specific, not blanket-GA) — validate it under sustained load (extend B3).
- **D2 (M)** Audit-log shipping **(depends on WP-A8 — needs a populated, signed
  ledger first)**: ship to an external WORM/SIEM target with at least one
  SIEM-native format (CEF/LEEF/OCSF/syslog — none exist today, `sink.rs` is local
  JSON-lines only); tamper-evidence preserved end-to-end. The `audit verify` tool
  (A8c) is the auditor-facing "prove it wasn't tampered" path and is a DoD gate.
- **D3 (M)** Supply-chain integrity: **SBOM (CycloneDX)** generated in CI; **build
  provenance (SLSA-style)** attestation; **signed releases** (cosign/sigstore) for
  binaries + Docker; `cargo deny`/`cargo vet` hardening. *Area:* `.github/workflows`.
- **D4 (S)** Nightly hardening: a documented **re-pin runbook** (`docs/toolchain.md`)
  + **multi-nightly early-warning CI** so the `nightly-2026-05-11` pin has a tracked,
  early-warned bump process (mirrors `oracledb` Wave 0 / W0-T2 — canary floating-nightly
  + `docs/toolchain.md`). Frame nightly as build-time-only.
  Add a **`cargo tree -i opentelemetry_sdk` feature-inspection check** to this job so an
  upstream `rt-tokio` default-feature flip (which would pull tokio via the D1 OTel deps)
  is caught early (T5) — complements the standing `-i tokio`/`-i reqwest` DoD gate.
- **D5 (M)** Security posture: **commission/perform an `oraclemcp` security audit**
  (threat model doc + the existing fuzz/adversarial-classifier/chaos suites as
  evidence) and publish a `SECURITY.md` + threat-model doc. This is *our* audit, not
  an upstream claim.
- **D6 (S)** Operational docs: deployment/hardening guide (k8s/Docker, least-priv
  user, read-only role, network posture), runbook, and the honest "build-time
  nightly" explainer.
- **D7 (S)** Live-latency perf evidence (coordinated with B3) added to
  `docs/performance-footprint.md`.
- **D8 (S)** **ADRs for load-bearing decisions** (mirror oracledb's `docs/adr/`
  discipline): record each as a file under `docs/adr/` with objective *review triggers* —
  at minimum: keep nightly/asupersync (build-time-only); converge plsql-mcp onto
  `oraclemcp-db`; audit-wiring (A8) is a blocking release gate; advisor stays OUT
  (licensing); ship 0.4.0 not 1.0; `oraclemcp-db` is the canonical shared foundation.
  *Why:* a decision with a written review trigger survives refinement rounds and agent
  turnover (this plan's §14 is the evidence). *AC:* `docs/adr/000N-*.md` committed, each
  with context + decision + review trigger.
- **D9 (S)** **Severity policy + exact-SHA release qualification** (mirror oracledb
  ADR-0003 + its §7 severity rules). (a) Severity policy for the D5 audit + the §9
  bug-hunt: **no open P0/P1, no untriaged finding; a P2 needs a fix or a signed
  exception** before tag. (b) The §8 DoD gates are certified by a **manual, exact-SHA
  qualification run on the frozen `v0.4.0` RC commit**; scheduled/CI runs on moving
  commits are *discovery* — any code change after the qualifying run → a new RC.
  *AC:* a committed exact-SHA evidence bundle for the RC; severity policy met.

### WP-E — Ergonomics & finish-proto (low-cost adds)
- **E1 (M)** `resources/subscribe` + `resources/updated` (finish the proto surface;
  back with `DBMS_CHANGE_NOTIFICATION` where available, else documented polling).
- **E2 (M)** Cursor pagination (opaque, tamper-evident) on `tools/list`,
  `resources/list`, and large reads.
- **E3 (M)** Export-to-resource for large results (CSV/JSON, `resource_link` + local
  file path; proper CSV escaping; access-controlled identically to the query) +
  **E3b** `resource_link` from `oracle_query` for oversized result sets.
- **E4 (M)** Unified `oracle_search_objects` with `detail_level` (names/summary/full;
  summary row-count from `ALL_TABLES.NUM_ROWS`, not `COUNT(*)`); keep existing
  describe tools for compat.
- **E5 (S)** Connection-scope isolation: `mcp_exposed` profile flag / allow-list (curate
  which profiles agents see) — multi-tenant friendly; complements per-DB ceiling.
- **E6 (S)** Polish: `notifications/progress` for long ops + `tools/list_changed` on
  operating-level change.
- **E7 (M)** `completion/complete` for resource-template params + tool args
  (owner→type→object), authz-scoped through the read path, capped at 100/response.

### WP-F — Positioning docs (honesty-guarded)
- **F1 (M)** Positioning docs, using the **canonical language in §1 "Positioning"**
  verbatim: lead with *"governed, least-privilege Oracle access for AI agents — PAM
  discipline for AI-to-Oracle"* and the six pillars. Concrete tasks:
  - **Sweep the existing docs off the stale read-only framing** (same stale-doc class
    Round 0.2 fixed in AGENTS.md): `README.md` hero alt-text + one-line description +
    the "Why oraclemcp" section still say *"safe-by-default" / "fail-closed by
    construction"*, and `docs/behavior-inventory.md:55` literally says *"This read-only
    binary"* (it also frames guarded-write orchestration as "out of the served
    surface" — false; `oracle_execute`/`execute_approved` are in `TOOL_NAMES`).
    Reconcile all of them to governed/least-privilege.
  - **Author the SQLcl/genai-toolbox comparison FRESH** — it does NOT exist yet (no
    such table or quote anywhere in the repo; it's deferred bead
    `oraclemcp-epic-positioning-9xe.2`, whose own draft still says
    "safe-by-construction…read-only" and must be rewritten per §4 item 7). oraclemcp is the
    only one offering *provable, ceiling-bounded, just-in-time, and (once A8) audited*
    privilege; SQLcl = privilege-delegated/no-classifier; genai-toolbox = Query-vs-Exec
    flag/no-parser. Plus NUMBER→string fidelity + single-binary deploy.
  **Honesty (§4 item 7):** no read-only-only / stable-Rust / independently-audited-deps /
  "fully audited" (until A8) claims; document the build-time-nightly reality plainly.

---

## 7. Cross-WP dependency graph

```
WP-B2 driver-adapter seam ──▶ WP-B1 async migration ──▶ WP-B3 load/soak gate
WP-A1 level-aware RO backstop ── shares the DB connect/exec path with ── WP-B1
                                 (sequence A1 with/after B1, not before)
WP-A5 IAM auth  ───────────────▶ (connect path; do after/with B2 seam to avoid churn)
WP-C1 health framework ──▶ C2..C7 subchecks ; C8 top_queries (surfaces awr.rs)
                          └──▶ C9 doctor preflight ──▶ (gates advisor, which is OUT)
WP-E export/result-link ──▶ needs served resources (already shipped in 0.3.0)
WP-D supply-chain/observability/docs: mostly independent; D7 ↔ B3 share perf numbers
Release gate (DoD §8) blocked-by: WP-A,B,C,D core tasks + B3 load evidence + D3 SBOM/signing + D5 audit
```
Ordering rationale: **B2 (adapter seam) goes first** so the async migration (B1) and
IAM auth (A5) land *through* the seam, isolating the upcoming `oracledb`
execute-API churn. Safety (A1/A3/A4/A6) can largely parallel B once the seam exists.
DBA suite (C) is independent of the async migration but should also call through the
seam. Supply-chain/observability/docs (D) parallelize throughout.

---

## 8. Definition of Done — 0.4.0 release gates

Certified by a **manual exact-SHA qualification run on the frozen RC** (D9), meeting the
D9 severity policy (no open P0/P1; P2 fixed-or-signed). All must be green/true before
tagging `v0.4.0`:
1. Standard gates: `fmt`, `clippy -D warnings`, `test --workspace`, `cargo deny`,
   boundary lint, sensitive-data lint — on pinned nightly.
2. `live-xe` suite green against 23ai (incl. new WP-A/WP-C live tests).
3. **B3 load + shutdown soak evidence** committed (no leaked sessions, bounded
   p50/p95/p99, clean drain).
4. Driver-adapter seam verified (no `oracledb::` calls outside the adapter).
5. **D3 supply-chain**: SBOM + provenance + signed binaries/Docker produced by CI.
6. **D5 security**: threat model + `SECURITY.md` published; fuzz/adversarial/chaos
   suites green as audit evidence.
7. MCP conformance matrix at 100% for the served surface (incl. new E-stream arms).
8. README/docs/package metadata/source docs pass the §4 item 7 honesty guardrails,
   enforced by a **mechanical honesty-grep gate** (fail the build on
   "safe-by-default", "read-only binary", "fully audited", or un-caveated "PAM"
   outside explicitly approved historical/negative-test contexts), plus
   `release_preflight.sh` version alignment.
9. Cross-repo check (lightweight — see §12): confirm B1/WP-C introduce no breaking
   change to the *published* `oraclemcp-core`/`-error`/`-guard` API that `plsql-mcp`
   consumes (or document the version bump). No `plsql-mcp` break is expected from B1
   (it depends on `oraclemcp-db` only *transitively*, under the frozen
   `oraclemcp-core` 0.1.0 pin). DB-layer convergence is out of scope. Also: B5's
   `oraclemcp-db` `cargo public-api` + `cargo-semver-checks` snapshot passes (tool
   installed/pinned per R2-05); and oraclemcp **provides/maintains the contract surface
   that oracledb's W3-E7.3 runs** (reciprocal gate — oraclemcp's four-family migration
   is a publish-blocker for oracledb 0.3.0, §2).
10. **Audit (WP-A8) wired + signed + verifiable** — every served write/DDL/Admin and
    `oracle_set_session_level` escalation produces a signed audit record;
    `oraclemcp audit verify` passes on the produced ledger; tamper (in-place edit OR
    recompute-without-key) is detected. Until this is true, the audit positioning in
    §1/§4 item 1 stays struck (E1/E2/E3).
11. **Severity policy met + exact-SHA qualification** (D9): the full gate is a manual
    run on the frozen RC commit; no open P0/P1, no untriaged finding, every P2 fixed or
    signed-exception. A code change after the qualifying run → a new RC.
12. **Capability narrowing (A9) holds**: a compile-fail fixture proves read-path handlers
    cannot spawn / do remote I/O.

---

## 9. Testing strategy (idea-wizard Phase 6 — do not omit)

- **Unit**: SQL shape, classifier, config mapping, adapter-seam boundary.
- **Golden/conformance**: new MCP arms (subscribe, pagination, completions) with
  structured transcripts; update `tests/conformance/COVERAGE.md`.
- **Deterministic asupersync (DPOR/LabRuntime)**: drive B1's async cancellation through
  `LabRuntime`/`DporExplorer` asserting the *ready-or-dead* invariant + cancel-correctness
  / obligation-leak oracles (the bug class ADR-0001 says single-threaded suites miss);
  plus read-only backstop, output fencing, pool dirty-discard. Consider **cassette replay**
  for deterministic CI without a live DB (mirrors oracledb W3-E6).
- **Live (`live-xe`)**: IAM token connect (TCPS), marker in `V$SQL`, MODULE/ACTION
  tagging, every DBA subcheck, top-queries Statspack fallback, privilege degradation.
- **Load/soak (B3)**: high-concurrency + sustained-shutdown, structured metrics.
- **Multi-pass bug-hunt**: ≥2 consecutive fresh-eyes passes with zero new in-scope
  findings (mirror oracledb W3-E8); triage by the D9 severity policy; per-pass log committed.
- All tests emit detailed structured logs; live tests SKIP loudly without Oracle.

---

## 10. Risks & mitigations

| Risk | Mitigation |
|------|------------|
| `oracledb` execute-API consolidation churn (19 `execute_query*` → four operation-specific request types per W1-T3; zero `#[non_exhaustive]`) | B2 seam isolates it; the cut-over is the **named oracledb 0.3.0 / W2-T1 migration** (oraclemcp is a listed consumer); pin exactly until 0.3.0, then `^0.3` under oracledb's blocking SemVer contract (ADR-0002) |
| D1 OTLP exporter rides asupersync's **outbound** HTTP client (net = lane-specific, not blanket-GA) | Validate the outbound client under sustained load (extend B3); telemetry failure drops (never blocks the request path); region-owned batch loop with bounded shutdown budget |
| Nightly re-pin breakage | `docs/toolchain.md` runbook + multi-nightly early-warning CI (D4) |
| Upstream `o0b`/`qm4`/`cco` never ship real support | Keep fail-closed; deliver precise classification, not fake support; they stay OUT |
| Tuning/Diagnostics-Pack licensing for advisor/AWR | AWR already gated→Statspack; advisor stays OUT; preflight (C9) reports licensing |
| Overclaiming "audited"/"stable" | §4 item 7 honesty guardrails enforced at the DoD doc gate (§8 item 8) |
| asupersync net primitives maturity | B3 load/soak evidence is the gate; primitives we use (`Cx`/`Semaphore`/`Notify`/`time::timeout`/`RuntimeBuilder`) are the "stabilize-first" surfaces |
| async migration regressions | B2 seam + chaos/cancellation tests must stay green; B1 behind the seam |
| No per-caller rate limiting / query-cost budget (enterprise DoS review will ask) | Document admission-concurrency caps + the configurable per-profile call timeout + row/body caps as the intentional boundary; per-caller throttle is post-0.4.0 — can't safely key on token `sub` yet (cardinality) (E10) |
| Audit positioning shipped before it's true | Struck from §1/§4 until WP-A8 wires + signs the served path; honesty-grep DoD gate (§8 item 8) enforces it (E1/E2) |

---

## 11. Why 0.4.0 (not 1.0.0), and the path to 1.0

0.4.0 because the foundation isn't frozen: both upstreams are 0.x with no API
freeze, the toolchain is nightly, and the only audits are self-administered. A 1.0
GA promise to enterprise procurement must be substantiable. **Seed 1.0 criteria**
(not committed here, but the honest gate):
- `oracledb` and `asupersync` reach their own 1.0 / API-freeze (or we vendor-pin
  with a documented support contract).
- An **external/third-party security audit** of `oraclemcp` (beyond D5's internal one).
- Sustained high-concurrency **load + soak evidence** at enterprise scale.
- A stable-Rust path *or* a formally documented, supported nightly-pin policy that
  enterprise platform teams accept.
- **Per-principal RBAC** — bind the authenticated caller (token `sub`) to a
  profile/credential. Today is single-principal-per-process (one `--profile` chosen at
  start); "PAM for AI agents" is per-*process*, not per-*identity*, until this lands
  (E9). Until then, docs must not imply per-caller authority (§4 item 7).

---

## 12. `plsql-mcp` coordination — actual coupling (corrected 2026-06-19)

The repos are **more decoupled than the README "superset" language implies.** Verified
against `plsql-intelligence`:
- `plsql-mcp` depends on only **three** published spine crates — `oraclemcp-core`,
  `oraclemcp-error`, `oraclemcp-guard` — pinned at **`0.1.0`** (old; `oraclemcp` is at
  0.3.0, so the shared spine has already drifted).
- `plsql-mcp` does **NOT** depend on `oraclemcp-db` **directly** — it directly deps
  only `oraclemcp-core`/`-error`/`-guard` @ `0.1.0`, and `oraclemcp-db` appears only
  *transitively* under that **frozen `oraclemcp-core` 0.1.0** pin (plsql `Cargo.lock`),
  so a new `oraclemcp-db` API cannot reach plsql until it bumps `oraclemcp-core`. It
  uses its **own** DB abstraction, **`plsql_catalog::OracleConnection`** (+
  `OracleBind`/`OracleRow`/`OracleBackend`/`OracleConnectionInfo`), forked from a common
  ancestor when the spine was extracted.

Consequences for 0.4.0:
- **The async migration (B1) does NOT break `plsql-mcp`** — it changes
  `oraclemcp-db`'s trait, which `plsql-mcp` does not consume. The earlier "cross-repo
  break" worry is **largely dissolved**; downgraded from a release gate to a note.
- **The DBA suite (WP-C) does NOT auto-inherit to `plsql-mcp`** — building it in
  `oraclemcp-db` does not propagate, because `plsql-mcp` uses `plsql_catalog`, not
  `oraclemcp-db`. (Correction to an earlier framing.) It is still **safe and
  non-conflicting**: DBA suite = live operational `V$`/`DBA_*` diagnostics;
  `plsql-mcp` = offline PL/SQL source semantics. Orthogonal. Build it freely in
  `oraclemcp`.
- Both binaries get the same fail-closed guard + operating-level ladder via the
  shared spine; the convergence is about the DB *connectivity* layer (`oraclemcp-db`),
  not the guard or the level model. `plsql-mcp` adds offline PL/SQL *intelligence* on
  top of shared connectivity.

**Strategic decision — COMMITTED 2026-06-19: CONVERGE on `oraclemcp-db`.** Two
parallel, drifting `OracleConnection` DB layers exist (`oraclemcp-db` vs
`plsql_catalog`) — but their live backends differ in **driver model**: `oraclemcp-db`
uses the pure-Rust **thin** `oracledb` crate, whereas `plsql-catalog`'s only implemented
live backend (`RustOracle`, behind the `oracle-driver`/`live-xe` features) is the
**THICK ODPI-C `oracle` 0.6.3 crate** (kubo's rust-oracle — requires Oracle Instant
Client; `OracleRs` is an unimplemented placeholder). **So convergence is a real
thick→thin driver swap for plsql, NOT a no-op** (correction: the thin-only invariant
*does* apply — oraclemcp-db stays engine-free thin, and plsql gives up its thick ODPI-C
path or keeps it as a separate non-default backend). `oraclemcp-db` is published. We
converge so the
safety-critical invariants (fail-closed guard, NUMBER→string, lease) live in **one
audited copy** and every 0.4.0 investment (async, IAM, DBA suite, safety backstop)
flows to `plsql-mcp`.
- **Direction:** `plsql-catalog`/`plsql-mcp` **adopt the published `oraclemcp-db`**
  and delete their fork (the superset depends on the core, never the reverse).
- **Timing:** *execute AFTER 0.4.0 ships* — converge onto a **stable** async
  `oraclemcp-db`, not a moving target.
- **Repo boundary (important):** `plsql-catalog` is **NOT in this repo** — it lives in
  `/home/durakovic/projects/plsql-intelligence`. The convergence *execution* (rewrite
  plsql onto `oraclemcp-db`, delete the fork) is entirely a `plsql-intelligence`-repo
  task and its bead belongs in **that** repo's tracker, **not** in oraclemcp's
  `.beads/`. In this 0.4.0 plan, convergence is **context only** — the sole in-repo
  obligation is to design `oraclemcp-db`'s async trait as the **canonical, published,
  documented** connectivity API (WP-B). Do **not** create a convergence-execution bead
  in this repo.

---

## 13. Process — review rounds before beads

Per planning-workflow, this draft (Round 1 done; Codex Round 2 complete) should survive
**multiple review rounds** to steady state before bead conversion (idea-wizard Phase 5).
Each round runs the validation loop: self-containment, dependency-graph (no cycles/
orphans), justification, steady-state. **Do not oversimplify or drop features in
refinement.**

When approved, convert to beads (`br` only): one epic per WP (A–F) plus a release
epic carrying the DoD gates; re-classify the existing deferred beads into IN
(restructure under the WP epics) vs OUT (keep deferred with the §5 reasons);
add the new enterprise beads from the **full current work-package inventory**
(A1–A9, B1–B6, C1–C10, D1–D9, E1–E7 **(incl. E3b)**, F1, plus release DoD gates). Keep **A8
audit-wiring** blocking. Split D1 at bead conversion into logs-wiring,
metrics-encoder, trace-bridge, and health-endpoints. When
re-classifying deferred beads, fix stale ones — e.g. `oraclemcp-epic-deferred-cyu.2`
("OCI IAM … BLOCKED upstream rust-oracledb-5bh") moves **IN under WP-A5** and drops
"BLOCKED" (5bh is now closed — C4). Verify each claim against code/live before closing,
mirror the dependency graph (§7), and validate with `br dep cycles` (must be empty).

---

## 14. Review-round ledger

- **Round 0 (2026-06-19):** initial draft from grounded research.
- **Round 0.1 (2026-06-19) — operator answers folded in:**
  - **RESOLVED (Q-b):** B1 async migration is the **FULL** migration in 0.4.0,
    completely tested — not split. (§6 WP-B1.)
  - **RESOLVED (Q-a):** D1 is **FULL OpenTelemetry** (traces + metrics + logs +
    health/readiness), with the load-bearing **Tokio-free OTLP exporter** constraint
    captured. (§6 WP-D1.)
  - **RESOLVED (Q-d):** cross-repo break **dissolved** — `plsql-mcp` does not depend
    on `oraclemcp-db`; it has its own `plsql_catalog` DB layer and pins the spine at
    0.1.0. §12 rewritten; the DB-layer-convergence question recorded as a separate
    future decision.
  - **RESOLVED (Q-c):** SQL/Index advisor stays **OUT** — `doctor` detects/reports
    pack licensing only; oraclemcp never invokes a paid-pack feature (matches the
    existing `awr.rs` model). (§5, §6 WP-C C9.)
  - **RESOLVED (convergence):** committed to **converge on `oraclemcp-db`**
    (`plsql-catalog` adopts it post-0.4.0); 0.4.0 designs the async trait as the
    canonical published API. (§12, §6 WP-B.)
  - **RESOLVED (Q-e):** D1 reuses **asupersync's `metrics`-feature `observability::otel`**
    (Tokio-free OTLP HTTP exporter, empirically verified no-tokio). Logs turnkey;
    traces+metrics need a thin oraclemcp encoder + a `tracing→OtlpSpan` bridge;
    `/healthz`+`/readyz` over the existing HTTP server. Effort M (was L). Trap: enable
    only `metrics` (+`compression`); never `gen-tonic-messages`/`rt-tokio`. (§6 WP-D1.)
- **Round 0.2 (2026-06-19) — safety-model correction (operator-flagged, important):**
  - oraclemcp is a **guarded, escalation-capable** MCP (ReadOnly *default* →
    confirmation-gated step-up to **Admin** when a profile's `max_level` permits),
    **NOT "read-only by construction".** Corrected §1 chain, §4 item 1 invariant, §4 item 7
    honesty, WP-A rationale, WP-A1 (now a *level-aware* backstop), §5 hypo-index OUT
    rationale, WP-F1 positioning.
  - **Root cause** (recorded so it doesn't recur): trusted a **stale `AGENTS.md`** line
    ("binary pins ReadOnly / step-up disabled / guarded-write not surfaced") plus a
    subagent misread of `SessionLevelState::new(ReadOnly, false)` (now `main.rs:304`;
    the plan earlier cited the stale `:245`; the `false` is `protected`, not "step-up
    disabled") — over the README and code, which
    clearly document the `READ_ONLY<READ_WRITE<DDL<ADMIN` ladder. **`AGENTS.md` safety
    section has been updated** to match the README + code.
  - **OTLP layering resolved:** the exporter lives in `oraclemcp-telemetry`, NOT the
    driver. `oracledb` already emits per-round-trip `tracing` spans behind its optional
    zero-cost `tracing` feature (`obs.rs`, bead `rust-oracledb-lv6`); oraclemcp just
    enables it and owns the exporter. (§6 WP-D1.)
  - **Round-0 status: COMPLETE.** Ready for adversarial review round(s) → bead
    conversion (this repo only).
- **Round 1 (2026-06-19) — 4-reviewer adversarial round (Claude, fresh eyes), every
  finding verified against code/sources. All folded in:**
  - **E1 (CRITICAL):** audit not wired into the served binary → added blocking **WP-A8**
    (wire + sign + `audit verify`) + DoD §8 item 10; struck present-tense audit claims
    from §1/§4 item 1; tagline → "auditable by design"; §4 item 7 forbids the claim until A8.
  - **A1 backstop (T1/T2/E5, High):** rewritten — lazy/per-statement off
    `effective_level()`, **pinned-lease-session only** (incoherent on the stateless
    pool), re-asserted per read-transaction (txn-scoped; TTL expiry is silent); layer A
    (least-priv user, A2) is the real boundary.
  - **Factual fixes:** mega-builder → four operation-specific request types (H2);
    "D1" → **ADR-0001**, "never stable" softened (H3); asupersync audit corrected — no
    miri, loom/Lean/TLA+ artifacts unshipped, drop "×124" (H4); F1 fabricated quote
    removed, doc sweep (README + `behavior-inventory.md:55`) added, comparison table
    authored **fresh** (H1/E4/C1).
  - **OTel (D1-2/D1-4/T5):** hand-roll prost (asupersync's encoders are fuzz-gated);
    the `tracing→OtlpSpan` bridge is a real Layer (heavy-M/L → split into sub-beads);
    added a `cargo tree -i opentelemetry_sdk` check to D4.
  - **Others:** B5 API AC accepts published spine deps + locks them in the snapshot
    (T4); B1 async-win reframed as "remove mutex+block_on", not new parallelism (T3);
    A4 reset is net-new (E8); A3 marker must be classified **as-sent** (E6); A5 cites
    `5bh` + deletes the `connection.rs:411` rejection + reconciles `robot_docs.rs:280`
    (E7/C3/T7); §12 transitive-dep precision (C2); OUT rows + risks for caller-RBAC
    (E9), rate-limiting (E10), PII masking (E11); §13 notes the `cyu.2` stale-title fix
    (C4); graph arrow redrawn (I3); stale `main.rs:245`→`:304`.
- **Round 1.1 polish (2026-06-19):** normalized all cross-refs to "§N item M" (I1);
  added effort labels to A6/A7/C10/E1–E7 (I2); refreshed the status header + §13 round
  state. No substantive change.
  - **Verdict (all four reviewers):** spine sound, no re-architecting; the above are
    citation/wording/scope corrections plus the one structural addition (A8).
  - **Next:** Codex independent review round (operator-driven), then bead conversion.
- **Round 1.2 (2026-06-19) — cross-validation vs `oracledb` ROAD_TO_1_0 v3.1 [STALE: actual roadmap is v3.3; reconciled in Round 3] +
  asupersync leverage (operator-requested). Corrections + additions folded in:**
  - **Reframed the oracledb milestone:** the execute-API cut-over + first-party
    migration is **oracledb 0.3.0 / W2-T1** (oraclemcp is named), not "before 1.0";
    oracledb **contracts its API at 0.3.0** (ADR-0002 blocking semver-checks) → pin
    `^0.3` after for 0.3.x patch safety; intentional breaking changes still require
    a minor bump + baseline refresh. Split §2 item 2 (oracledb=contracted vs
    asupersync=volatile). Fixed §2 risk para, §10 row, B2.
  - **Consume, don't rebuild:** added "Relationship to oracledb 0.3.0" — typed errors
    + `connection_disposition()` (W1-T6), `ProtocolLimits`/`ResourceLimit` (W1-T5),
    redacted driver tracing+pool metrics (W1-T6 → feed D1, no double-instrument);
    coordinate oracledb's "direct oraclemcp contract suite" (W3-E7).
  - **B5 upgrade:** `cargo public-api`+`cargo-semver-checks` PROVEN under the pin
    (oracledb R3/R10) → adopt semver-checks for `oraclemcp-db`.
  - **B1:** async unlocks zero-copy `_ref` borrowed-fetch (NOT direct-path — already on the blocking facade; corrected Round 1.4) (W1-T8); Outcome discipline
    (Cancelled/Panicked); consume `connection_disposition()` for pool recovery; double-
    migration tradeoff stated.
  - **asupersync leverage:** §9 DPOR/`LabRuntime` ready-or-dead + cassette replay;
    new **B6** (`Budget` per-request bounds); D1 region-owned exporter + outbound-HTTP
    risk row; D4 "WS1"→Wave 0/W0-T2.
  - **Flagged here, FOLDED IN Round 1.3 (below):** capability narrowing; ADR discipline
    + severity policy + exact-SHA release qualification.
- **Round 1.3 (2026-06-19) — operator said "in scope," folded in:**
  - **A9** compile-time capability narrowing (narrow the `Cx` cap row at dispatch;
    read paths structurally cannot spawn/remote) — defense-in-depth under the classifier.
  - **D8** ADRs for load-bearing decisions (`docs/adr/` + review triggers, mirroring
    oracledb).
  - **D9** severity policy (no open P0/P1; P2 fixed-or-signed) + **exact-SHA release
    qualification** on the frozen RC; §9 gains a ≥2-pass bug-hunt; §8 DoD gains items
    11–12; §5 IN updated for WP-A (A8/A9) and WP-D (D8/D9).
- **Round 2 (2026-06-19) — Codex independent adversarial verification.** Verified the
  load-bearing claims directly against oraclemcp source, the rust-oracledb roadmap/source,
  asupersync 0.3.4 source, and the sibling plsql-intelligence repo. The fixes above are
  folded in. **Verdict for bead conversion: GO after preserving the split/guards below.**

| ID | severity | location | issue | evidence(file:line) | proposed fix |
|---|---|---|---|---|---|
| R2-01 | High | WP-C heading/rationale | "plsql-mcp inherits" was false today and contradicted §12; it would create beads with a nonexistent cross-repo inheritance path. | `/home/durakovic/projects/plsql-intelligence/crates/plsql-mcp/Cargo.toml:28-36`; `/home/durakovic/projects/plsql-intelligence/crates/plsql-catalog/src/lib.rs:959-964`; `/home/durakovic/projects/plsql-intelligence/crates/plsql-mcp/src/query.rs:12-13`; `/home/durakovic/projects/plsql-intelligence/Cargo.toml:25-29` | Reworded WP-C as oraclemcp-spine work now, with plsql-mcp sharing only after future convergence. |
| R2-02 | Medium | §2 / Round 1.2 oracledb reframe | "`^0.3` and safe" / "additive-only" overclaimed the contract. The roadmap says blocking semver-checks prevents unintended patch breaks; intentional breaks are allowed with the correct minor bump and baseline update. | `/home/durakovic/projects/rust-oracledb/docs/ROAD_TO_1_0.md:14-23`; `/home/durakovic/projects/rust-oracledb/docs/ROAD_TO_1_0.md:46-59`; `/home/durakovic/projects/rust-oracledb/docs/ROAD_TO_1_0.md:471-486` | Reworded to 0.3.x patch safety under `^0.3`, not a promise that all future evolution is additive. |
| R2-03 | Medium | A8 audit wiring | The served `oracle_execute`/`execute_approved` path is unaudited, but "binary crate doesn't even depend on audit" was imprecise: there is no direct dependency/import or wired auditor in served dispatch, while `oraclemcp-audit` appears transitively through spine crates. | `crates/oraclemcp/src/registry.rs:18-26`; `crates/oraclemcp/src/registry.rs:769-773`; `crates/oraclemcp/src/dispatch/mod.rs:1539-1609`; `crates/oraclemcp-core/src/query_execute.rs:16-17`; `crates/oraclemcp-core/src/query_execute.rs:100-150`; `crates/oraclemcp/Cargo.toml:16-30`; `crates/oraclemcp-core/Cargo.toml:12-20` | Kept A8 blocking, but changed the task to add a direct audit dependency or route served execution through a core auditor-owned API. |
| R2-04 | Medium | D1 OpenTelemetry | D1 should consume the exact asupersync 0.3.4 surfaces: logs HTTP export and generic HTTP send are production-reachable; richer metrics/trace protobuf builders are test/fuzz-gated; trace queue/backpressure already exists as `TraceExporter`/`LoadSheddingTraceExporter`. | `/home/durakovic/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/asupersync-0.3.4/src/observability/otel.rs:1430-1488`; `/home/durakovic/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/asupersync-0.3.4/src/observability/otel.rs:1941-2174`; `/home/durakovic/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/asupersync-0.3.4/src/observability/otel.rs:7670-7682`; `/home/durakovic/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/asupersync-0.3.4/src/observability/otlp_trace_exporter.rs:389-426` | Reframed D1 as reuse of asupersync transport/retry/queueing plus local or upstreamed production protobuf mapping. |
| R2-05 | Medium | B5 API gates | `cargo-semver-checks 0.48.0` is installed, but `cargo public-api` is not available under the pinned nightly in this checkout. B5 needs an explicit tool install/version pin rather than assuming developer machines have it. | `rust-toolchain.toml:6-8`; `/home/durakovic/projects/rust-oracledb/docs/ROAD_TO_1_0.md:168-184`; command evidence: `cargo +nightly-2026-05-11 public-api --version` returned "no such command"; command evidence: `cargo semver-checks --version` returned `0.48.0` | Added an explicit CI/preflight install+pin requirement for `cargo-public-api`; keep semver-checks adoption. **(Round 3 update: `cargo-public-api` 0.52.0 is now installed locally and runs under the pin — the "no such command" evidence is stale; the install/pin-in-CI requirement still stands for fresh agent machines.)** |
| R2-06 | Medium | F1 / DoD honesty gate | The proposed honesty grep was too narrow. Current package metadata and source docs still contain "safe-by-default", and behavior inventory still says "read-only binary"; README/docs-only grep would miss release-visible claims. | `crates/oraclemcp/Cargo.toml:4`; `crates/oraclemcp/src/registry.rs:1-5`; `docs/behavior-inventory.md:55`; `README.md:2`; `README.md:15` | Expanded DoD gate to README/docs/package metadata/source docs, with allowed historical/negative-test contexts only. |
| R2-07 | High | §13 bead conversion | The conversion instruction was stale after Rounds 1.2/1.3; it omitted A9, B6, C10, D8/D9, E1-E7, F1, and release gates, risking dropped scope in beads. | intra-doc references (§6 WP-A/B/C/D/E, §13 inventory) — self-citation line numbers omitted as drift-prone | Replaced the partial list with the full inventory A1-A9, B1-B6, C1-C10, D1-D9, E1-E7, F1, plus release DoD gates; kept D1 split explicit. |

**Round 2 bead-readiness by WP:** A = GO (A8 remains blocking and must be first-class);
B = GO (B1 large but properly scoped; B5 must include tool install/pins; B6 real);
C = GO after the WP-C inheritance correction above; D = GO only if D1 is split into
logs/metrics/traces/health and keeps the no-tokio boundary; E = GO as individual
conformance beads; F = GO with expanded metadata/source-doc honesty sweep.

- **Round 3 (2026-06-20) — ULTRACODE workflow cross-validation vs `oracledb`
  ROAD_TO_1_0 v3.3 + its live beads + asupersync (46-agent verify workflow). 40 plan
  claims verified (35 ok / 2 stale / 3 wrong) + 8 internal, 10 completeness, 3 adversary
  findings. All folded in:**
  - **Biggest correction (adversary High):** oracledb 0.3.0's APIs (four-op,
    `connection_disposition`/`retry_hint`/`ProtocolLimits`/`ResourceLimit`) are
    **DESIGNED but NOT BUILT** — every bead OPEN, Wave 1 just begun, 0 source hits, no
    date. §2 reframed: 0.4.0 ships fully on 0.2.2's real surface (`ora_code()` /
    `is_connection_lost()` / `is_transient()` / `is_retryable()`); all "consume" items
    are post-0.3.0 deferred upgrades blocked on upstream beads; ADR-0002 gate is
    ADVISORY until 0.3.0 ships.
  - **plsql-catalog is THICK (C30):** its `RustOracle` backend is the ODPI-C `oracle`
    0.6.3 crate (needs Instant Client), not pure-Rust thin — §12 convergence is a real
    thick→thin swap, not a no-op.
  - **Factual fixes:** removed the fabricated "30s timeout" (×4 → configurable
    per-profile call timeout, 3600s ceiling); `oracle_code()`→`ora_code()`; dropped
    direct-path from B1's async-unlock (already on the blocking facade — C16); reworded
    asupersync's "disclaims back-compat/~biweekly" (C05 — it has a 0.x SemVer policy,
    ~9-day cadence); roadmap v3.1→v3.3.
  - **§1 chain "audited" overclaim** removed (audit lands in A8). **E1–E7 ID
    collision** resolved via a §6 ID-convention legend. **§13** inventory gains E3b.
  - **Completeness (B2/B4/D1/§2/§8):** B2 cut-over scope now enumerates the full 0.3.0
    churn (four-op + single op-deadline W1-T3 + accessor types W1-T4 + module paths
    W1-T9 + shim-expiry + `MIGRATING-0.3.md`); the migration is a **publish-blocker for
    oracledb 0.3.0** (W2-T1.3); B4 notes oracledb's async-native pool (we keep our own);
    D1 split into 0.2.2-spans-now vs 0.3.0-metrics-later; §2/§8 add the reciprocal
    **W3-E7 oraclemcp contract suite** (built in the oracledb repo); wallet OUT-row
    corrected (unencrypted `ewallet.pem`/`cwallet.sso`/`wallet_password` already work —
    `x1p` is only encrypted-PEM/`.p12`).
  - **Verdict: still GO** — no architectural change; the corrections sharpen the
    upstream-timing model (0.4.0 stands alone on 0.2.2; the 0.3.0 consumption is
    explicitly deferred and blocked on upstream beads).
