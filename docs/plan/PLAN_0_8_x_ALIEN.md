# Plan — the road from 0.8.x to the alien horizon

**Status:** DRAFT v1 (2026-07-09). Two-repo plan (`oraclemcp` server + `rust-oracledb`
driver). Cadence: **0.0.x increments** — every wave is a small, shippable patch bump,
never a big-bang. Nightly Rust + asupersync stay by doctrine (see §Doctrine).

> This is a first version to react to, not a frozen spec. Nothing here is beaded yet;
> the last section maps it onto the beads that already exist.

---

## 0. The honest reset

The 0.8.x release (driver `oracledb` 0.8.2, server `oraclemcp` 0.8.0) completed the
**correctness arc**: the driver passes python-oracledb's own 2,462-test suite, the guard
mutation-gate enforces at guard 91.5% / audit 95.7%, K10 row-by-row streaming landed
with the classifier provably in front. That is real and shipped.

**But a post-ship audit (QA100 / DRVQA25) found defects that override the celebration:**

- **6 × P0 guard/config bugs in the shipped server** — every one is a fail-*open* in the
  exact invariant that is the whole point of this project:
  - `[guard] Never default parsed-but-unmatched DDL to READ_WRITE`
  - `[guard] Enforce the ALTER SESSION allowlist on raw execution`
  - `[guard] Do not admit unproven view and policy side effects as read-only`
  - `[guard] Fail closed on opaque PL/SQL package calls`
  - `[guard] Forbid transaction control inside caller PL/SQL`
  - `[profiles] Switch from one immutable config generation`
- **45 × P1** security/correctness bugs (audit-chain rotation, HTTP deadlines, auth
  linearization, streaming SSE-ID honesty, byte caps, supply-chain pinning…).
- **1 × P1 driver bug in `OwnedRowStream`** — `[cursor] Release OwnedRowStream cursor
  state after continuation` (a real leak in the K10 feature just shipped).

**These bug campaigns (QA100 + DRVQA25) are already in progress on a parallel track and are
NOT this plan's execution scope.** This plan tracks them as a **hard dependency / gate**, not
as work to schedule here: the guard is the brand, so the alien arcs (§Arc A–E) do not get to
ship until the guard is provably sound again — but *fixing* it is owned elsewhere. Waves 0–1
below are therefore documented as the **precondition state** this plan waits on, kept for
sequencing and bead-mapping only.

**What THIS plan actually drives** (the parts not owned by the bug campaigns):
1. **Wave 2** — doc-truth pass + the `http.rs` de-monolith (the de-monolith is a precondition
   for Arcs C/D, so it's genuinely on the critical path to the horizon).
2. **The 0.9.x alien horizon** — Arcs A–E, gated on the parallel bug track reaching a sound guard.

---

## Doctrine (fixed constraints, not up for debate)

1. **Nightly + asupersync stay.** `try_trait_v2` is the price of the `Cx`/Scope/lab-runtime
   /cancel-correctness substrate — and that substrate is the *leverage* that makes Arc D
   (deterministic fault injection) and the whole streaming/cancellation story possible.
   We do not chase stable; we lean into what stable can't do.
2. **The guard never weakens.** Every classifier change is tighten-only, mutation-gated,
   and (eventually, Arc B) proof-carrying.
3. **`#![forbid(unsafe_code)]`**, structured logs, small reviewable edits, beads committed
   with code.
4. **Verified, not claimed.** Every performance/parity/safety assertion ships with its
   evidence artifact. That epistemic honesty is the differentiator — protect it.

---

## The waves

### Wave 0 — Safety patch · **server 0.8.1** · SHIP FIRST
The six P0s. Nothing else rides this train; it goes out the moment they're green.
- Fix all 6 P0 guard/config beads (QA100 P0 set).
- Each fix is a **tighten** with a new mutation-killing test + a differential-corpus entry
  proving the previously-admitted construct is now refused.
- Add a QA100-P0 regression suite so these classes can never regress.
- Gate: mutation-gate re-run stays ≥90% enforcing; D6.8-style mini-audit of the 6 fixes.

### Wave 1 — Security & correctness hardening · **server 0.8.2 → 0.8.4** · **driver 0.8.3**
The 45 P1s, batched into shippable patch releases by domain so each is reviewable:
- **0.8.2 (guard/query/streaming):** result byte-caps on first oversized row, SSE-ID
  honest resumability (finishes the K10 story properly), JSON-RPC validated before
  streaming dispatch, transaction-control + view/policy side-effect tightenings that
  weren't P0.
- **0.8.3 (audit/SIEM/supply-chain):** mixed-key audit rotation, RFC5424 injection guard,
  SIEM off the audit mutex + confidential-transport requirement, WORM-alias rejection,
  raw-literal removal from signed previews, workflow dependency pinning, installer
  checksum-binds-the-file.
- **0.8.4 (http/auth/lease/config):** absolute handshake/header/body deadlines, credential
  revocation linearized with lane admission, lease actions bound to their authenticated
  principal, config rollback compare-and-swap, cookies `Secure` on TLS, request-budget
  propagated into DB ops.
- **Driver 0.8.3:** the DRVQA25 P1 `OwnedRowStream` cursor-release leak + a sweep of the
  DRVQA25 direct hidden-bug campaign; L2 post-auth cassettes (`nnnz`) as the regression
  vehicle.

### Wave 2 — Truth in documentation + structural hygiene · both repos, patch-sized
The brand is *verified honesty*; stale strings are off-brand. Cheap, high-signal:
- **Driver README:** quickstart `oracledb = "0.5"` → `"0.8"`; feature/version table refresh;
  add the K10 `OwnedRowStream` row to the ledger.
- **Server README:** "asupersync 0.3.4" → 0.3.5 (two occurrences); confirm every `0.8.0`
  install string is intentional vs a version that should float.
- **AGENTS.md (both):** "oracledb 0.7.1" → 0.8.2; the driver AGENTS.md is still the `acfs`
  template — write the real one (architecture, three crates, the parity/fuzz/matrix gates).
- **Reconcile v0.8.0 history:** QA100 `.7` (reconstruct real release history), `.6` (sync
  dependency provenance + decoupled release-check docs), `.8`/`.10` (rollback runbook,
  tracker reconciliation).
- **Retire the plsql-mcp story:** the "two-binary family" framing across both READMEs +
  the `plsql-intelligence` feature docs now that plsql-mcp is tombstoned. Decide: keep the
  offline `oracle_plsql_*` engine (still valuable) but drop the "wire plsql-mcp" narrative.
- **De-monolith `http.rs`:** the 4 B6 extractions (serve/listen lifecycle, config assembly,
  file-backed stores, `/operator/v1` handlers). Now *more* than cleanup — it's the
  precondition for Arc C's subscription routes and Arc D's per-lane fault injection to be
  reviewable. Do it here, review-gated, isomorphic.

### Wave 3 — P2/P3 cleanup + driver performance backlog · patch train
- Server QA100 P2 (37) + P3 (8): pool RAII/leak-safety, pagination bound to catalog
  revision, dashboard store paging, telemetry attribute denial, backup/restore
  transactionality, the alpha subscription/IAM-refresh hardening. Batched by domain.
- Driver performance/ergonomics: Columnar VECTOR → Arrow fast path (`0mk`), pipelined
  executemany BatchWriter (`j1w`), cassette-replay deterministic CI (`1s2`), statement-shape
  cache + DDL self-heal (`8pp`/`dgi`), OOB instant cancellation (`cn4`), retry executor
  (`r9a`), scratch arenas (`8eo`), SODA-18c JSON_SERIALIZE gap (`soda-pre21c`), bind-count
  compile check (`mas`).
- **This is where the driver's own ROAD-to-1.0 track lives.** It is a *parallel* arc, not a
  blocker for the server; the server pins whatever driver patch it needs.

> Waves 0–3 clear the entire current backlog across both repos. Only then does the horizon open.

---

## The alien horizon — **server/driver 0.9.x** — what no database tool on Earth ships

Each arc is buildable on primitives *already in this codebase*. Each ships as its own 0.0.x
train once Waves 0–1 make the guard sound.

### Arc A — Time as a first-class dimension 🕰️  (leans on K9 `as_of` + K3 + the audit chain)
- **`oracle_diff(sql, scn_a, scn_b)`** — the same *proven-read* query at two SCNs, returned
  as a semantic row-level diff. "What changed in this view since yesterday" in one guarded
  call. Guard treats it as two reads; zero new admission surface.
- **SCN-stamped forensic replay** — stamp every audited read with its SCN; any audited read
  becomes *replayable at the SCN the agent saw*. Not "what the agent did" — a byte-identical
  reconstruction of **the world it decided on**. An AI-governance capability that exists
  nowhere.
- **Plan time-machine** — K3 cost extraction across SCNs: "this query's plan flipped ~SCN X,
  cost 2→19." Dashboard Orrery gains a **time scrubber**.

### Arc B — Proof-carrying access 📜  (leans on the classifier + audit hash-chain + Lean loops)
- **Verdict certificates** — the classifier emits a serialized derivation of *why* a
  statement is READ_ONLY (or refused), hashed into each audit record, re-checkable by an
  external verifier that never trusts the server.
- **Certificate transparency for DB actions** — periodically anchor the audit chain head
  into Sigstore/Rekor: tamper-evident against even the operator.
- **Lean-verified classifier core** — the endgame. Mutation testing proves the tests aren't
  placebo; a Lean proof proves the *prover can't be wrong*. The first formally-verified SQL
  safety gate. (We already run Lean conformance loops on asupersync — the muscle exists.)

### Arc C — The living database 🫀  (leans on the protocol layer's CQN + Arrow decode)
- **CQN → MCP subscriptions** — Oracle Continuous Query Notification wired to
  `resources/subscribe`: the database *pushes* changes to agents. "Notify me when any order
  > 10k appears" as a standing subscription. No MCP server does real-RDBMS change-push.
- **`oracle_orient`** — one round trip: schema map + FK topology + hot objects + data
  freshness + recent DDL. The database that explains itself to a newly-arrived agent.
- **Arrow-native results** — hand agents Arrow IPC (the driver already decodes columnar,
  −95% allocations) instead of JSON rows: the fastest path from Oracle to a DataFrame there is.

### Arc D — Editions as branches 🌿  (leans on edition selection + the Reviews board)
Edition-Based Redefinition has existed since 11gR2 and nobody tools it because the surface is
hostile. Fuse EBR with the Change-Proposal board: **every proposal applies into a new edition
(a branch); tests run against it; merge = flip the default edition; rollback = instant flip
back.** Zero-downtime PL/SQL deployment with pull-request semantics. Could be the product.

### Arc E — The deterministic universe 🎲  (leans on asupersync LabRuntime/DPOR + K6 cassettes)
- Run the whole server+driver stack in CI under **seeded fault injection** — every await
  point a candidate drop/delay/cancel, every failure reproducible by seed. FoundationDB-grade
  assurance.
- **`om incident capture`** — one command turns a production incident into a scrubbed,
  offline-replayable artifact. Bug reports that *run*.

### Arc F — AI-native / vector-semantic 🧠  (leans on 23ai AI Vector Search + the driver's VECTOR decode)
Oracle 23ai ships a native `VECTOR` type and AI Vector Search — and this driver *already
decodes VECTOR on the wire* (0mk makes it a contiguous f32/i8 buffer straight into Arrow).
Nobody has fused that with MCP. Do it:
- **`oracle_semantic_search(text|vector, over, k)`** — a first-class guarded tool over VECTOR
  columns (`VECTOR_DISTANCE` / approximate index), returning ranked rows. The agent does
  RAG *inside* the governed boundary instead of exfiltrating rows to an external store.
- **Embedding bridge** — accept a caller vector, or (opt-in) call the DB's own in-database
  ONNX embedding model, so the text→vector step never leaves Oracle.
- **Hybrid retrieval** — combine vector distance with the classifier-proven relational
  filter in one guarded query. The first *governed, wire-native, agent-facing* vector search
  on Oracle. This is the timeliest alien capability — 23ai + MCP is a market of one.

### Arc G — Query economics: cost as gas ⛽  (leans on K3 plan-cost extraction)
Agents write runaway full-scans. K3 already pulls optimizer cost/cardinality. Close the loop:
- **Pre-execution cost gate** — `oracle_query` estimates cost *before* running; a profile
  `max_query_cost` (or per-call budget) **refuses** a query whose plan cost exceeds the
  ceiling, with the plan and a suggested-index/rewrite hint instead of a 40-minute scan.
- **Cost-aware `EXPLAIN`-first mode** — an agent gets "this will scan 4B rows, cost 190k;
  add a predicate on `order_date`" as a structured refusal. Safety and performance fuse into
  one gate: the guard already refuses *unsafe* SQL; now it can refuse *ruinously expensive*
  SQL the same fail-closed way.

### Arc H — Federation across the lane fleet 🌐  (leans on the per-principal HTTP lanes)
The server already runs isolated per-principal lanes, each with its own Oracle connection.
Lift that to a fleet:
- **`oracle_orient --fleet`** — one call maps every configured profile: which schemas, which
  versions, freshness, drift. A single agent situational-awareness surface across prod /
  staging / shards.
- **Cross-DB `oracle_diff`** — the same proven-read run against two *databases*, semantic
  diff returned: "what differs between prod and staging in this view." Schema-drift and
  data-drift detection as a guarded call.
- **Fleet catalog** — a unified, redaction-safe object index across the fleet the agent can
  search once. (Every hop is still classifier-gated per lane; federation adds reach, never
  admission surface.)

### Arc I — The reversible workspace ⏪  (leans on rollback-by-default + savepoints + leases)
DML already rolls back by default and leases already savepoint. Make the whole session an
agent-visible **undo tree**:
- **Named checkpoints** — an agent marks a savepoint, does exploratory DML, and gets a
  structured "undo to checkpoint X" — a time-tree of its own uncommitted work.
- **Dry-run-then-commit as a first-class flow** — preview the row-level effect of a DML
  (affected rows, before/after) *inside* the rollback sandbox, then commit only the exact
  previewed change through the existing single-use grant. The agent sees consequences before
  they're durable. Destructive work becomes *inspectable* before it's real.

### Arc J — The self-teaching guard 📚  (leans on the classifier's structured refusals)
Every refusal already carries a class + suggestion. Turn that exhaust into an asset:
- **Refusal-as-lesson** — each `ForbiddenStatement`/`OperatingLevelTooLow` returns the exact
  *safe rewrite* (the read-only form, or the minimal step-up) plus a one-line "why," so the
  agent learns the governed idiom instead of retrying blindly.
- **The corpus** — accumulate (anonymized) refusal→rewrite pairs into a shipped benchmark:
  the first public dataset of "unsafe agent SQL and its governed correction." It feeds better
  suggestions, trains client-side guards, and *is a research artifact* about how agents try
  to break DB safety — data nobody else has.

### Arc K — Live, proven lineage 🧬  (leans on plsql-intelligence lineage + the live catalog)
The offline `oracle_plsql_lineage` computes column-level lineage from source. Fuse it with
the live catalog so lineage is *proven against the running database*, not just parsed:
- **`oracle_lineage(column)`** — "where does this column's data actually come from," verified
  now: source-derived edges cross-checked against live views/synonyms/grants, with a typed
  marker where the live catalog and the source disagree (a drift signal). Column-level,
  guarded, live-verified data lineage — the thing every data-governance team wants and no
  tool delivers honestly.

### Arc L — Ground Control, alive 🛰️  (the dashboard as the face of all the above)
The Orrery/Ground-Control identity already exists in the design. Make it the *live* union of
every arc: lanes as orbiting bodies, CQN subscriptions as streaming trails (Arc C), the SCN
**time-scrubber** dragging the whole view through history (Arc A), edition-branches rendered
as a git graph (Arc D), the reversible undo-tree as a visible branch you can walk back (Arc I),
query cost as the mass/heat of each body (Arc G), verdict certificates as inspectable proofs
on each action (Arc B). Not a dashboard — a *mission-control for a database that has become an
organism*. Mandatory 2D/no-WebGL fallback stays (accessibility is non-negotiable).

**Constellation shape (how the arcs group):**
- **I. Time & Memory** — A (time), and the SCN spine everything else stamps against.
- **II. Proof & Trust** — B (proof-carrying), J (self-teaching guard).
- **III. Living Database** — C (subscriptions/orient), F (vector-semantic), K (live lineage).
- **IV. Change as Code** — D (editions-as-branches), I (reversible workspace).
- **V. Economics & Determinism** — G (cost-gas), H (federation), E (deterministic universe).
- **The face** — L (Ground Control unites all of it visually).

**Arc dependencies:** A + C + F are largely independent and interleave first (fastest
"wow"-per-week). B's certificate layer wants the parallel-track audit hardening done. D + I
want the `http.rs` de-monolith (Wave 2). E is continuous once the first harness lands and pays
back across every other arc. L trails the others (it renders whatever has shipped). F (vector)
and G (cost) are the two I'd *lead* with after Wave 2 — highest novelty, both build directly on
already-shipped decode (0mk) and K3.

---

## Continuous excellence (the non-arc raises — always-on, between waves)

Not headline arcs, but the standard the project holds itself to; each ships as a patch when ready:
- **Performance continuation** — the driver's decode-tuning discipline (SIMD `simd-decode`,
  scratch arenas `8eo`, pipelined prefetch, columnar Arrow `0mk`) keeps going, every change
  byte-identical + microbenched + reverted-if-it-doesn't-measure (the existing bar).
- **Assurance deepening** — more cargo-fuzz targets, kani BMC coverage widening, mutation-gate
  floor ratcheting up over time, the Lean conformance loop reaching from asupersync into the
  guard (feeds Arc B).
- **Observability** — OpenTelemetry span coverage deepening, per-lane trace correlation, the
  metrics-history files feeding the Ground-Control view.
- **Operator UX** — `doctor` self-heal breadth, installer polish, the real-ADB sign-off
  harness graduating from operator-run to a documented CI lane once a non-customer ADB exists.
- **Driver → 1.0** — the ROAD-to-1.0 waves (qualification, freeze, RC) proceed on their own
  cadence; the server pins whatever driver patch it needs and never blocks on 1.0.

---

## Bead map (every open bead → a wave)

| Wave | Server (oraclemcp) | Driver (rust-oracledb) |
|---|---|---|
| **0 — 0.8.1 safety** | QA100 P0 ×6 (.80–.84, .58) | — |
| **1 — 0.8.2–0.8.4 / drv 0.8.3** | QA100 P1 ×45 (batched by domain) | DRVQA25 (`…hb`, `…hb.3` cursor); `nnnz` |
| **2 — docs + hygiene** | QA100 .6/.7/.8/.10; demonolith `qyqs`+.1–.4 | README/AGENTS doc-sync; ledger row for K10 |
| **3 — cleanup + perf** | QA100 P2 ×37 + P3 ×8 | `0mk` `j1w` `1s2` `8pp` `dgi` `cn4` `r9a` `8eo` `mas` `soda-pre21c` `mwu` `cco` `rsa-revisit` `kerberos-radius` |
| **0.9.x — alien arcs** | new beads: Arcs A–L (Time, Proof, Living-DB, Vector, Editions, Reversible, Self-teaching, Lineage, Cost, Federation, Determinism, Ground-Control) | new beads: CQN surface, Arrow IPC, SCN plumbing, VECTOR search primitives, in-DB embedding bridge |
| **housekeeping** | close legacy epics `iec3*` once children clear | close `road-to-1-0` waves as they ship; `57z` idea-wiz epic |

**Totals to burn down before the horizon:** server ~96 QA100 + 5 demonolith; driver ~2
DRVQA25 + ~14 ROAD/perf. All of it is Waves 0–3; none of it is invented — it already exists
in the trackers.

---

## Sequencing summary

**Parallel track (owned elsewhere, in progress — this plan only waits on it):**
- **0.8.1** P0 guard fixes → **0.8.2–0.8.4** (+ driver 0.8.3) P1 security train → P2/P3 cleanup.
  When this reaches a sound-guard state, the horizon gate opens.

**This plan's own track (drivable now / next):**
1. **Wave 2 — doc-truth + `http.rs` de-monolith.** Doc-truth is cheap and can start
   immediately (independent of the bug track). The de-monolith is review-gated, isomorphic,
   and unblocks Arcs C/D — it's the one structural item on the critical path to the horizon.
2. **0.9.x — the twelve arcs (A–L)**, each a shippable 0.0.x train, each opening only after the
   parallel bug track has the guard provably sound. Suggested lead order for maximum
   novelty-per-week on already-shipped primitives:
   **F (Vector) + G (Cost) first** (build straight on 0mk decode + K3), then
   **A (Time) + C (Living DB)** (build on K9 `as_of` + CQN), then
   **B (Proof) + J (Self-teaching)**, **D (Editions) + I (Reversible)**,
   **H (Federation) + E (Determinism)**, with **L (Ground Control)** rendering whatever has
   shipped along the way.

**Identity shift:** 0.8.x said *"provably as good as the reference, safely."* The alien
version says *"things the reference — and every database tool on Earth — cannot do at all."*
We have the substrate. Waves 0–3 make it trustworthy; 0.9.x makes it astonishing.
