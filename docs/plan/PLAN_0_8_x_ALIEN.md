# Plan — the road from 0.8.x to the alien horizon

**Status:** DRAFT v3 · steady-state · **+ Appendix I implementation specs** (2026-07-10). Two-repo
plan (`oraclemcp` server + `rust-oracledb` driver). Cadence: **0.0.x increments** — every wave is a small, shippable patch bump, never a
big-bang. Nightly Rust + asupersync stay by doctrine (see §Doctrine).

> **v3 changelog.** v2's grounding pass verified the *code* primitives. v3 integrates a
> four-lens adversarial review (guard-safety · architecture/beadability · Oracle-correctness ·
> product/sequencing) that found the *Oracle semantics* claimed on top of those primitives were
> in places wrong or overstated. Net changes: (1) the organizing thesis is now explicit — **the
> guard governs a new *dimension* of the interaction per release**; (2) two arcs added — **M
> governed egress** and **N policy-as-code** — because "admission governance without egress or
> policy governance is half a story"; (3) the lead pair is **G + A** (zero-gate, version-agnostic),
> not F (23ai-gated); (4) hard Oracle-correctness fixes (editions are a *linear* chain, not
> branches — ORA-38807; flashback is *data* reconstruction bounded by `UNDO_RETENTION` and broken
> by DDL — ORA-01466; CQN pushes *events*, not rows); (5) guard-safety fixes (Arc F must not admit
> `DBMS_VECTOR.*`; CQN registration is itself a gated privileged op); (6) every unfalsifiable
> superlative hedged to a knowledge-bounded claim. A third **verification round** (guard/Oracle
> re-check + consistency critic) then landed final polish and reached steady-state — most notably
> **correcting a Round-2 error**: the pre-execution cost gate (Arc G) must use `EXPLAIN PLAN FOR`
> (which optimizes without executing the target, behind the existing `allow_plan_table_write` gate),
> *not* `DBMS_XPLAN.DISPLAY_CURSOR` (which needs the statement already executed). Every load-bearing
> fact carries a source in §Grounding. Nothing is beaded yet.

---

## 0. The honest reset

The 0.8.x release (driver `oracledb` 0.8.2, server `oraclemcp` 0.8.0) completed the
**correctness arc**: the driver passes **2,462 of 2,578** python-oracledb reference thin-mode
tests (116 skips, each disproven, not hidden), the guard mutation-gate enforces at
**guard 91.5% / audit 95.7%** (threshold 90), and K10 row-by-row streaming landed with the
classifier provably in front. That is real and shipped.

**But a post-ship audit (QA100 / DRVQA25) found defects that override the celebration.** The
QA100 campaign (`oraclemcp-qa100-post-v080-audit-5u1n`) authored **100 tasks + 1 epic**; **96 are
still open**. Open work by priority: **7 P0 (the 6 below + `.28` in-progress) / 44 P1 / 37 P2 / 8 P3** (= 96). Of the **11 P0s authored**,
4 are already fixed and **1 more (`.28`, "Keep stale profile generations drained across later
reloads") is in-progress** — so the live P0 front is these 6:

- `.84 [guard] Never default parsed-but-unmatched DDL to READ_WRITE`
- `.83 [guard] Enforce the ALTER SESSION allowlist on raw execution`
- `.82 [guard] Do not admit unproven view and policy side effects as read-only`
- `.81 [guard] Fail closed on opaque PL/SQL package calls`
- `.80 [guard] Forbid transaction control inside caller PL/SQL`
- `.58 [profiles] Switch from one immutable config generation`

Every one is a fail-**open** in the exact invariant that is the whole point of this project.
Alongside them: **44 P1** security/correctness bugs; on the driver, **DRVQA25**
(`rust-oracledb-drvqa-2026-07-05hb`): `hb.1/2/4/5` closed, `hb.3` (real `OwnedRowStream`
cursor-release leak) and `hb.6` (K10 docs still future-tense) open.

**These bug campaigns are already in progress on a parallel track and are NOT this plan's
execution scope.** This plan tracks them as a **hard dependency / gate**: the guard is the brand,
so the alien arcs do not ship until the guard is provably sound again — but *fixing* it is owned
elsewhere. Waves 0–1 are documented as the **precondition state** this plan waits on.

**What THIS plan actually drives:**
1. **Wave 2** — the *remaining* doc-truth items + the `http/mod.rs` de-monolith (a precondition
   for Arcs C/D/E, genuinely on the critical path).
2. **The 0.9.x alien horizon** — the arcs below, gated on the parallel bug track reaching a sound
   guard, each built on a primitive verified to exist today (§Primitives ledger).

---

## Doctrine (fixed constraints, not up for debate)

1. **Nightly + asupersync stay.** `try_trait_v2` is the price of the `Cx`/Scope/LabRuntime/
   cancel-correctness substrate — the *leverage* that makes deterministic fault injection and the
   whole streaming/cancellation story possible. We lean into what stable can't do.
2. **The guard never admits the unproven.** The invariant is precise: the classifier never admits a
   construct it cannot *prove* safe. Constructs move from Guarded→Safe **only** by a reviewed,
   mutation-gated admission of a *proven-pure* builtin (e.g. `VECTOR_DISTANCE` in Arc F), and the one
   sanctioned runtime loosening lever is the **audited operator `allow_list`** (exact-SHA256). No
   arc, and no policy (Arc N), may add a second loosening path. Every change is mutation-gated and
   (eventually, Arc B) proof-carrying.
3. **No new admission surface (the arc-safety invariant).** Every new arc tool is either
   (a) classifier-gated exactly like `oracle_query` — prove `ProvenReadOnly` at the current level
   or be refused — or (b) routed through the existing step-up/single-use-grant path for anything
   above READ_ONLY. An arc may add *reach, richness, or speed*; never a way to reach Oracle that
   bypasses the classifier. **Corollary (SEC-1):** re-classify at the point of execution, never
   trust a stored verdict. **Corollary (SEC-3):** any arc that writes an audit/certificate/SCN
   record **fails closed on audit-write failure** — a read is refused, not run un-recorded.
   **Corollary (a privileged op is not always SQL):** operations issued as server-side API calls
   (CQN registration, `DBMS_FLASHBACK` session state, edition switch) are invisible to the
   text classifier and MUST be gated as first-class privileged actions in their own right.
4. **`#![forbid(unsafe_code)]`** (holds across all 9 crates today), structured logs, small
   reviewable edits, beads committed with code.
5. **Verified, not claimed — including no bare superlatives.** Every performance/parity/safety
   assertion ships with its evidence artifact; every load-bearing claim here carries a source in
   §Grounding. Unfalsifiable universal negatives ("no one else does X", "the first Y", "market of
   one") are **banned as flat fact** — hedge to a knowledge-bounded claim ("we're not aware of…")
   or delete. A brand built on verifiability cannot ship hype as truth.

---

## The organizing spine — the guard governs a new dimension per release

Every other database tool governs what an agent may *run*. The thesis of this project is bigger:
**we govern every *dimension* of the agent↔database interaction, and we prove each one.** The
alien horizon is that spine extended — the guard learning to govern one new dimension, or make one
new kind of read safe, per release. The differentiator is never the raw capability (vectors,
change-feeds, federation all exist elsewhere); it is always **"governed X"** — X inside a
fail-closed, audited, proof-carrying boundary.

The arcs group by what they add to that spine:

- **New governance dimensions** — the guard extends to a new axis of control:
  **G Cost · A Time · M Egress · B Proof · N Policy.**
- **New kinds of read the guard makes safe** — richer reach, same fail-closed admission:
  **C Living-DB · F Governed-RAG · K Lineage · H Fleet-reach · I Reversible-write-preview.**
- **A new governed write** — **D Editions** (linear PL/SQL staging).
- **Cross-cutting** — **E Determinism/incident-capture · J Self-teaching/corpus.**
- **The face** — **L** the Carved Light console, rendering whichever dimensions have shipped.

---

## Primitives ledger (what each arc actually leans on)

"Buildable on primitives *already in this codebase*" is only credible if the primitives are real
and correctly located. **Layer** matters — "the driver already does X" ≠ "the server already does
X". Evidence in §Grounding.

| Primitive | Layer | Status | Evidence | Arcs |
|---|---|---|---|---|
| VECTOR wire decode → `Vec<f32>`/`Vec<i8>` | driver | **EXISTS** | `oracledb-protocol/src/vector.rs:107`; `thin/fetch.rs:2221` | F |
| Columnar VECTOR → Arrow `FixedSizeList` fast path (`0mk`) | driver | **OPEN** (optional) | bead `rust-oracledb-0mk` | F (enhancer, not blocker) |
| CQN registration + EMON NOTIFY parse | driver | **EXISTS** | `oracledb/src/lib.rs:3397,4630`; `thin/subscr.rs`; pyshim `subscr.rs` | C |
| `as_of` (AS OF SCN/TIMESTAMP via DBMS_FLASHBACK bracket) — "K9" | **server** | **EXISTS** (session-state call) | `AsOf` @ `oraclemcp-db/src/query.rs:134`; teardown `connection.rs:779` | A, H |
| Optimizer plan-cost/cardinality — "K3" | **server** | **EXISTS** | `plan_cost_estimate`/`PlanCostSummary` @ `oraclemcp-db/src/intelligence.rs:1254` | G, A |
| Owning row-by-row stream — "K10" | driver+server | **EXISTS** (leak `hb.3` open) | `oracledb/src/row_stream.rs:106`; server `connection.rs:509` | C, L |
| Arrow decode → in-memory `RecordBatch` + C-Data PyCapsule | driver | **EXISTS** | `oracledb/src/arrow/mod.rs`; pyshim `arrow_capsule.rs` | C, F |
| Arrow **IPC** byte serialization (`arrow-ipc`) | driver | **NEW** (small) | absent — no `arrow-ipc` dep anywhere | C3 |
| Classifier + 3-valued purity + OperatingLevel ladder | guard | **EXISTS** | `oraclemcp-guard/src/{classifier,purity,levels}.rs` | ALL |
| Audit hash-chain (append-only) | guard/audit | **EXISTS** | `oraclemcp-audit`; dashboard `ChainStrip` | A, B |
| Structured refusals (class + suggestion) | guard | **EXISTS** | `oraclemcp-guard/src/rewrite.rs` | J, G |
| Offline PL/SQL lineage/engine (8 `oracle_plsql_*` tools) | **server** (feature-gated) | **EXISTS** | `crates/oraclemcp/src/plsql_tools.rs`, `plsql-*` =0.7.0, `#[cfg(feature="plsql-intelligence")]` | K |
| Per-principal isolated HTTP lanes (one Oracle conn each) | server | **EXISTS** | lane runtime; `http/mod.rs` | H, E |
| Rollback-by-default DML + lease savepoints + single-use grants | guard | **EXISTS** | `exec_grant.rs`, `stepup.rs` | I |
| Redaction — secrets/credentials/profile-output + principal-key only | server | **PARTIAL — no result-path masker** | `oraclemcp-auth/src/secrets.rs`; dispatch principal-key | M *builds* the masker; E/H/J reuse it |
| Operator authority / config allow-list above Subject (D17) | server | **EXISTS (seed)** | operator-authority config | N |
| asupersync LabRuntime / DPOR seeded scheduling | runtime | **substrate EXISTS; harness NEW** | asupersync 0.3.5 | E |
| Sigstore/Rekor transparency anchoring · Lean proof of purity core | external | **NEW** | not present | B2, B3 |

**Reading:** the "living database" arcs (C, F, A) rest on primitives that *already ship* — CQN and
VECTOR decode are further along than v1 assumed. The genuinely-new engineering is narrow and
named: Arrow-IPC emit (small), the fault harness (E), Rekor+Lean (B2/B3). No arc rests on a
fictional primitive. Two arcs (M, N) build on *seeds* (the redaction seam; the operator allow-list)
rather than finished capabilities — flagged honestly.

*Naming note: `K3`/`K6`/`K9`/`K10` are primitive **codenames** (plan-cost / cassettes / `as_of` /
row-stream) — distinct from **Arc K** (live lineage). §Grounding maps each.*

---

## The waves

### Wave 0 — Safety patch · **server 0.8.1** · SHIP FIRST *(parallel track — waited on, not driven here)*
The six open P0s. Nothing else rides this train.
- Fix `.58/.80/.81/.82/.83/.84` and land `.28`. Each fix is a **tighten** with a mutation-killing
  test + a differential-corpus entry proving the previously-admitted construct is now refused.
- Add a QA100-P0 regression suite. Gate: mutation-gate ≥90% enforcing; mini-audit of the 6 fixes.

### Wave 1 — Security & correctness hardening · **server 0.8.2 → 0.8.4** · **driver 0.8.3** *(parallel track)*
The 44 P1s, batched into shippable patch releases by domain (guard/query/streaming; audit/SIEM/
supply-chain; http/auth/lease/config). Driver 0.8.3: DRVQA25 `hb.3` cursor-release leak + the
DRVQA25 sweep; `nnnz` post-auth cassettes as the regression vehicle.

### Wave 2 — Truth in documentation + structural hygiene · both repos, patch-sized *(THIS PLAN DRIVES)*
Grounding found most of v1's doc-truth list was **already done** (2026-07-08) — so this wave is the
*remaining* items:
- **DONE (2026-07-08, verified):** server README asupersync 0.3.4→0.3.5 + `oracledb` 0.8.2 driver
  string; server AGENTS.md version sync; driver README quickstart `"0.5"`→`"0.8"`. *Do not
  re-chase — they no longer exist in the tree.*
- **Driver AGENTS.md rewrite:** still the generic `acfs` template — write the real one (three-crate
  architecture, parity/fuzz/matrix gates, the K10 stream contract).
- **K10 doc-truth (`hb.6`):** design doc + CHANGELOG still future-tense though K10 shipped in 0.8.2.
- **Retire the plsql-mcp *superset-binary* story:** drop the "wire the `plsql-mcp` superset"
  (G-CONSUMER) narrative from both READMEs/AGENTS. **Keep** the in-process, feature-gated
  `oracle_plsql_*` tools — real and shipped here (`plsql_tools.rs`), and Arc K depends on them.
- **Reconcile v0.8.0 history:** QA100 `.7/.6/.8/.10` (release history, dependency provenance,
  rollback runbook, tracker reconciliation).
- **De-monolith `http/mod.rs`:** the 4 B6 extractions (`qyqs.1`–`.4`). The file is **6358 lines**
  (3rd-largest in the workspace) — a genuine monolith. It is the precondition for Arc C's
  subscription routes and Arc E's per-lane fault injection to be reviewable. Review-gated, isomorphic.
- **Drop 3D / three.js from the dashboard:** `orrery3d` is optional; the default face is the 2D
  Carved Light console. Small bead (~5 files): flip `defaultBigBoard`→`board2d`; remove `three` +
  `@types/three`; strip the `orrery3d` entry from `presentation-model.ts`/`skin.tsx`/
  `conformance.test.tsx`; delete `orrery-renderer.tsx`. Keep the skin seam open. (Operator decision
  2026-07-10.)

### Wave 3 — P2/P3 cleanup + driver performance backlog · patch train *(parallel track + driver's own road)*
Server QA100 P2 (37) + P3 (8), batched by domain. Driver performance/ergonomics (all **open**):
`0mk j1w 1s2 8pp dgi cn4 r9a 8eo mas soda-pre21c-ap87 mwu cco rsa-marvin-revisit-hlgd
kerberos-radius-backends-bpsh`. **The driver's own ROAD-to-1.0 track lives here** — a *parallel*
arc, not a blocker; the server pins whatever driver patch it needs.

> Waves 0–3 clear the current backlog across both repos. **No arc hard-depends on Wave 3** — the
> perf beads (`0mk`, `cn4`) are *optional enhancers* of F/G, never prerequisites.

---

## The alien horizon — **server/driver 0.9.x**

Each arc ships as its own 0.0.x train once the guard is sound (§Gate). Each block is written to be
**beaded directly**: leans-on (verified), new surface, guard-safety verdict, dependencies, risks,
done-definition. Presented in the recommended lead order (§Sequencing), grouped by the spine.

## Dimension: Cost

### Arc G — Query economics: cost as gas ⛽  *(lead arc — zero-gate, version-agnostic)*
**Leans on:** server K3 plan-cost/cardinality (`oracle_explain_plan` → `plan_cost_estimate`).
**New surface:**
- Pre-execution cost gate — `oracle_query` estimates cost *before* running; a profile
  `max_query_cost` (or per-call budget) **refuses** a plan over the ceiling, returning the plan +
  a suggested-index/rewrite hint instead of a 40-minute scan.
- Cost-aware `EXPLAIN`-first mode — "this will scan 4B rows, est. cost 190k; add a predicate on
  `order_date`" as a *structured refusal*.
- (folded from review) Cumulative per-principal budget — an agent that has burned N cost-units this
  window is throttled, not just gated per query.
**Guard-safety:** a **second fail-closed gate composed with the first** — it only ever *adds* a
refusal; it can never admit what the classifier refused. **Cost-probe mechanism (corrected):**
`EXPLAIN PLAN FOR <stmt>` is the genuine *pre-execution* estimator — it optimizes the target
**without executing it** (no row scan); its only side effect is a write to `PLAN_TABLE` (typically a
session-private GTT). The guard already tiers it ReadWrite (`classifier.rs:1302`) behind the existing
`allow_plan_table_write` gate, so the cost gate runs the target's EXPLAIN through **that existing
governed path**, reads the cost, and refuses the *target* before executing it. It must **not** use
`DBMS_XPLAN.DISPLAY_CURSOR`/`V$SQL_PLAN` (an earlier proposal) — those introspect a cursor that has
**already been parsed/executed** and so cannot cost a novel statement pre-execution. A base object
whose VPD/policy purity is unproven is refused *before* the EXPLAIN (inherits the P0 `.82`
tightening) — hard-parsing fires policy functions.
**Depends on:** nothing new. **Unblocks:** Arc L cost badges. **Risks:** optimizer cost is an
*estimate* against *current statistics*, not portable across schemas — the ceiling is a
per-profile, **audited tripwire, never a guarantee**; stale stats → dynamic sampling → false
signal; adaptive plans/bind-peeking diverge from the estimate → pair with a runtime row-budget kill
(driver `cn4`). **DoD:** an over-ceiling plan is refused with plan+hint before execution via the
non-writing path; a cheap plan passes; the ceiling is per-profile and audited; a stale-stats case
is documented as a known false-signal.

## Dimension: Time

### Arc A — Time as a first-class dimension 🕰️  *(lead arc)*
**Leans on:** server `as_of` (K9 — AS OF SCN/TIMESTAMP), K3, the append-only audit chain.
**New surface:**
- `oracle_diff(sql, scn_a, scn_b)` — the *same proven-read* query at two SCNs, returned as a
  semantic row-level diff. Guard sees two independent reads; **zero new admission surface**.
- SCN-stamped forensic replay — stamp every audited read with the SCN it observed; any audited read
  becomes re-runnable *at the SCN the agent saw*. This reconstructs **the committed data the agent
  decided on** — an AI-governance capability we're not aware of any tool shipping.
- Plan time-machine — K3 across SCNs: "this query's plan flipped ~SCN X, cost 2→19." The console
  gains a **time-scrubber**.
**Guard-safety:** the `as_of` SCN must be applied as a **classified inline predicate / bind**, not
via an un-gated `DBMS_FLASHBACK.ENABLE` session call (today's K9 brackets the session — name and
gate that as a privileged op, or move to `AS OF SCN` inline syntax that the classifier sees).
Diff/replay compose reads; they never introduce an unclassified statement.
**Depends on:** nothing new. **Unblocks:** Arc L time-scrubber; Arc H cross-DB diff. **Risks
(honest scope):** flashback reconstructs *committed data* from **undo**, bounded by `UNDO_RETENTION`
+ undo-tablespace sizing (optionally `RETENTION GUARANTEE`), and by the SMON SCN↔time map (~5 days)
for *timestamp* flashback — **not** `DB_FLASHBACK_RETENTION_TARGET` (that governs the unrelated
Flashback *Database* feature). It **breaks after structural DDL** on the object → **ORA-01466**
(first-class typed refusal). Non-flashbackable objects (V$/dynamic views, external tables) are out
of scope. It is **not byte-identical**: identical bytes require a total `ORDER BY` + pinned NLS/
session settings; it restores *data*, not plan or session context. `ORA-01555`/`08180` →
"beyond-retention" typed refusal. **DoD:** `oracle_diff` over a synthetic 2-SCN fixture returns a
correct add/remove/change set; replay reproduces the observed *data*; a post-DDL SCN and a
beyond-retention SCN each return typed refusals with tests.

## Dimension: Egress *(new)*

### Arc M — Governed egress: the guard on the way out 🛡️  *(new arc — the missing half)*
The guard today governs what an agent may *do*; nothing governs what an agent may *see*. An agent
blocked from `DELETE` can still read raw PII into a context window it doesn't control. Arc M makes
governed egress a **first-class, proof-carrying capability** on the result path — elevating the
existing defensive redaction seam into a real dimension.
**Leans on:** the **result-path masker is net-new.** Today's redaction covers only secrets/
credentials/profile output + the principal key (`oraclemcp-auth/src/secrets.rs`), *not* query
result data — so Arc M builds the server-side result masker (the only layer that can do
mask-unknown-by-default + join-consistent salted tokenization); optionally with Oracle-native
`DBMS_REDACT`/VPD/RLS as an additional in-database enforcement tier
(privileged per-object policy objects; **Data Redaction needs the Advanced Security option** — the
arc must acknowledge the setup/license, and these are *not* interchangeable with the server seam).
**New surface:**
- Column-level masking / tokenization on results (**server seam**) — an agent queries sensitive
  columns and receives consistently masked or salted-tokenized values, **mask-unknown-by-default
  (fail-closed)**, per-profile, audited, and proof-carrying (the mask decision hashes into the audit
  chain, feeding Arc B1).
- Row-level scoping — VPD/RLS predicates (Oracle-native) or a seam-applied predicate on the proven
  read so a principal never receives rows outside its policy.
**Guard-safety:** this is a *tightening on egress* — it can only ever *remove* data from a result,
never add admission. Mask-unknown-by-default means an unclassified column is masked, not leaked
(the egress analogue of fail-closed). Consistency (same value → same token) must not leak the
plaintext via a join/oracle attack — tokens are per-profile salted, documented.
**Depends on:** nothing new (redaction seam exists). **Unblocks:** Arc B1 (mask certificate), Arc F
(search over tokenized vectors), Arc H (fleet catalog respects egress), Arc J/E (capture/corpus reuse
the masker), and the Arc L mask badge. **Risks:** masking that is inconsistent breaks agent joins;
masking that is *too* consistent enables inference — the salting/scope model is the core design
decision. Format-preserving masks can still leak via distribution. **DoD:** a query over a masked column returns tokens with a
mask-decision certificate; an unconfigured sensitive column is masked-by-default; an RLS-scoped read
omits out-of-policy rows; a test asserts no plaintext leaks through a self-join.

## Dimension: Proof

### Arc B — Proof-carrying access 📜  *(split into three shippable trains)*
**Leans on:** the classifier, the audit hash-chain, the existing Lean muscle on asupersync.

**B1 — Verdict certificates (server).** The classifier emits a serialized *derivation* of why a
statement is `ProvenReadOnly` (or refused), hashed into each audit record, re-checkable by an
external verifier that never trusts the server. **Certificate schema (sketch, to firm up before
beading):** `{ stmt_digest, level, verdict, derivation:[{rule_id, matched_construct}],
classifier_version, corpus_gen, observed_scn, bound_audit_hash }` — the verifier replays the
derivation steps against the statement and checks `bound_audit_hash` ties the cert to the exact
audit record. **Redaction:** the derivation MUST pass the Arc-M/redaction seam — no raw SQL, binds,
or schema identifiers cross the boundary (anchoring the chain *head* hash is fine; publishing raw
derivations is not). **DoD:** an external verifier re-derives a sample verdict from its certificate
with zero server trust.

**B2 — Certificate transparency (external, async).** Periodically anchor the audit-chain *head*
into Sigstore/Rekor. **Honest scope:** this gives *retroactive* tamper-evidence — an inclusion
proof against a signed checkpoint shows a head existed at a time, **given an independent party
retained that checkpoint**. It does *not* stop an operator who controls the server from anchoring a
doctored chain, nor from withholding the proof. Anchoring is **async and non-blocking to
admission** — a Rekor outage must never gate a query. **DoD:** the chain head appears in Rekor with
an offline-checkable inclusion proof.

**B3 — Lean-verified purity core (research, long-horizon).** A Lean proof of the **purity core
only** (not the whole classifier). **Honest scope:** this proves the *abstract purity model* sound;
the deployed Rust classifier is tied to it by **conformance tests, not verified extraction** —
"verified spec + tested implementation," not "verified binary." As far as we know this would be the
first formally-specified SQL-safety purity core; state it that way. **DoD:** the purity core's key
lemma is Lean-proved and a conformance test pins the Rust implementation to the model.

**Guard-safety (all three):** strengthens the guard by construction; adds no execution path. B1's
certificate MUST be emitted *inside* the same classify call that gates execution (SEC-1), so it can
never describe a different decision than the one enforced; audit-write failure fails closed (SEC-3).
**Depends on:** parallel-track 0.8.3 audit hardening (rotation/WORM) for B1/B2 so the chain we
anchor is sound. **Unblocks:** Arc L proof-inspector.

## Dimension: Policy *(new)*

### Arc N — Policy-as-code: the programmable guard 📐  *(new arc)*
The guard is one-size-fits-all; there is no operator-authored declarative policy ("principal X may
never touch schema HR"; "table Y is append-only"; "no `DELETE` without a PK-hitting `WHERE`"). Arc
N is "OPA/Rego for SQL" — the guard's biggest *product* limitation removed.
**Leans on:** this is **largely net-new.** The existing `OperatorAuthorityPolicy` (D17,
`oraclemcp-core/src/admin_auth.rs`) governs *who counts as the operator* (a subject allow-list for
privileged actions) — a thin seed, not a per-principal SQL-restriction policy. Note the guard already
has **one deliberate loosening lever** (the audited operator `allow_list`, `classifier.rs`); N sits
*above* the classifier and must never become a second one.
**New surface:** a declarative, versioned, audited policy layer evaluated **above** the base
classifier, per profile/principal. **Strictly tighten-only / monotone:** a policy returns `Deny` or
`Narrow` over the base verdict, **never `Allow-beyond-base`** — `final = base ∧ policy`. A `Narrow`
that only lowers the verdict/level is safely monotone; a `Narrow` that **rewrites the SQL** (adds a
predicate / RLS clause) produces a *different statement* that MUST re-enter the classifier (SEC-1)
before execution. Every policy decision is proof-carrying (feeds B1) and self-teaching (feeds J).
**Guard-safety:** the load-bearing invariant is that N is a **monotone tightening operator** —
enforced structurally (return type `Deny | Narrow`, no `Allow`), with a test that no policy can admit
a statement the classifier refuses and that any narrowing rewrite is re-classified.
**Depends on / first bead:** a **policy-language design + D17-reuse spike** (grammar, predicate
vocabulary, the `Deny`/`Narrow`-only return type, whether `Narrow` may rewrite SQL) — this gates the
rest of N. **Unblocks:** per-deployment tailoring; the Arc L policy-narrowing badge. **Risks:**
expressiveness vs. safety — rich enough to be useful, provably unable to loosen. **DoD:** an operator
policy narrows a principal's admitted set; a malformed/loosening policy is rejected at load; a
SQL-rewriting `Narrow` is re-classified; a test proves composition is monotone.

## Kinds of read the guard makes safe

### Arc C — The living database 🫀  *(split C1/C2/C3)*
**Leans on:** the driver's **already-shipped** CQN (`subscribe_register`/`register_query`, EMON
NOTIFY parser, pyshim callbacks) + Arrow decode. *The v1 "wire CQN in the driver" premise was
wrong.* The real work is server-side, and it splits cleanly:

**C1 — CQN → MCP subscriptions.** Fan the driver's existing change-notification callbacks out to
MCP `resources/subscribe`. **Honest CQN semantics:** CQN pushes change *events* (object-level by
default, or affected ROWIDs under query-result-change registration) — **not row data**; the agent
re-reads the proven scope to fetch rows. Delivery is **best-effort and coalesced by default (may
drop on failure/overflow); durable at-least-once requires RELIABLE QoS.** Registration requires the
**CHANGE NOTIFICATION** system privilege (an operator prerequisite).
**Guard-safety (critical):** CQN **registration is itself a privileged op** the text classifier
never sees — gate it as a first-class action (its own capability + step-up, the second EMON
connection accounted against the per-DB ceiling). Require **QUERY-level** registration bound to the
proven predicate; **refuse OBJECT-level** registration (object-level fires on any base-table DML, so
the feed would reveal mutations to rows the proven read's `WHERE` excludes — a scope leak). The feed
then delivers change events → governed re-reads, inheriting the query's verdict, never widening it.

**C2 — `oracle_orient` (shared node).** One round trip: schema map + FK topology + hot objects +
data freshness + recent DDL. The database that explains itself to a newly-arrived agent. This is a
bundle of individually-classified dictionary reads. **It is a shared dependency of H and K** — beaded
as its own node, not buried in C.

**C3 — Arrow-native results.** Hand agents **Arrow IPC** instead of JSON rows. The driver decodes
into `RecordBatch` today; **emitting Arrow IPC bytes is NEW driver work** (add `arrow-ipc`,
serialize the existing batch) **plus a server driver-pin bump** — an explicit cross-repo edge:
`drv:arrow-ipc-emit` → `srv:pin-driver-arrow` → `C3`. Arrow IPC is an encoding of already-admitted
rows (and must pass Arc-M egress before leaving the host).
**Depends on:** `http/mod.rs` de-monolith (reviewable subscription routes). **Unblocks:** Arc L live
feed; Arc H fleet orient (via C2); Arc K lineage (via C2's shared catalog snapshot). **DoD:** a
QUERY-level subscription over a synthetic table delivers a coalesced change event within the ceiling
and object-level is refused; `oracle_orient` returns a stable snapshot; an Arrow-IPC result
round-trips into a DataFrame.

### Arc F — Governed RAG / vector-semantic 🧠  *(23ai-gated — second wave, not lead)*
Vector search is table-stakes (pgvector, etc.); **the novelty is the guard, not the vectors** —
sell it as *governed RAG*, the only fail-closed, audited semantic-search surface over Oracle 23ai
in-DB vectors we're aware of. **Leans on:** 23ai `VECTOR` + AI Vector Search + the driver's shipped
VECTOR wire decode (`vector.rs`). The columnar Arrow fast path (`0mk`) is an optional enhancer.
**New surface:**
- `oracle_semantic_search(text|vector, over, k)` — a guarded tool over VECTOR columns
  (`VECTOR_DISTANCE` / approximate HNSW-IVF index), returning ranked rows: RAG *inside* the governed
  boundary instead of exfiltrating rows to an external store.
- Embedding bridge — accept a **caller-provided vector** (always safe), or the SQL operator
  `VECTOR_EMBEDDING(model USING text)` bound to a **verified in-DB ONNX model** so text→vector never
  leaves Oracle.
- Hybrid retrieval — vector distance combined with a classifier-proven relational filter in one
  guarded query.
**Guard-safety (critical — this was the #1 danger in review):** admit **only `VECTOR_DISTANCE`**
(documented pure, deterministic math) to the proven-pure builtin set, via a **reviewed,
mutation-gated builtin admission** — the one sanctioned way the classifier moves a *proven-pure*
construct to Safe (Doctrine #2), never an admission of anything unproven. (Verified: today the
classifier treats `VECTOR_DISTANCE` as a non-builtin call → `Unknown` → Guarded, so this is a
deliberate, test-gated change, not an already-open hole.) **Keep all `DBMS_VECTOR.*` package calls
fail-closed** — `DBMS_VECTOR.UTL_TO_EMBEDDING` can name a REST provider and issue `UTL_HTTP` egress,
exfiltrating governed data *under a green read-only verdict*; it is a qualified package call the
classifier already refuses. The SQL operator `VECTOR_EMBEDDING(model USING …)` runs an **in-database
ONNX model with no network by construction** — but the classifier cannot verify *from text* that the
*named* model is a loaded, trusted local model, so it is **fail-closed by default** and admitted
read-only only when bound to a verified in-DB model. A caller-provided vector is always safe. **Capability probe** checks `COMPATIBLE ≥ 23.4` **and** an ONNX model pre-loaded via
`DBMS_VECTOR.LOAD_ONNX_MODEL` — not merely "server is 23ai." **Depends on:** a 23ai CI lane
(gvenzl 23ai `free` container — a prerequisite bead). **Unblocks:** Arc L cluster panel. **Risks:**
approximate-index staleness; 23ai-only surface (degrade to typed refusal on 18c/21c, never a silent
full scan — that's Arc G's job to refuse). **DoD:** semantic search returns correct top-k over a
synthetic VECTOR fixture *on the 23ai lane*; the same call on 18c/21c returns a typed capability
refusal; `VECTOR_DISTANCE` is admitted with a mutation test while `DBMS_VECTOR.UTL_TO_EMBEDDING`
stays refused (tested).

### Arc K — Live, proven lineage 🧬
**Leans on:** the **in-repo, feature-gated** offline PL/SQL engine — `oracle_plsql_lineage` + 7
sibling tools already compile into *this* server behind `#[cfg(feature="plsql-intelligence")]`
(`plsql_tools.rs`, `plsql-*` =0.7.0) — fused with the live catalog (Arc C2 orient snapshot).
**New surface:** `oracle_lineage(column)` — "where does this column's data actually come from,"
verified now: source-derived edges cross-checked against live views/synonyms/grants, with a typed
marker where catalog and source disagree (a drift signal). **Decomposes into:** source-derived edges
· live-catalog cross-check · typed drift markers · wrapped/obfuscated-body partial-lineage gap
(labeled, not failed).
**Guard-safety:** dictionary + already-fetched static source reads; no new admission surface. **One
caveat:** never resolve references via `DBMS_UTILITY.EXPAND_SQL_TEXT` (recursive parse fires policy
functions) — stays a pure read only if it doesn't.
**Depends on:** Arc C2 (`oracle_orient` shared snapshot); a **`--features plsql-intelligence` CI
lane** (prerequisite if not already in the matrix). **Unblocks:** governance story; feeds Arc L.
**Risks:** source-vs-catalog disagreement is the *feature* — model drift as typed markers, never a
hard failure. **DoD:** `oracle_lineage` returns column edges for a synthetic view chain and flags an
injected source/catalog drift, under the feature lane.

### Arc H — Fleet reach: A + C at fleet scale 🌐
Derivative by design — H adds *reach*, not a new capability class; it is A (diff) + C (orient) lifted
across the per-principal lane fleet. **Leans on:** the server's existing isolated lanes + Arc A
`as_of` + Arc C2 `oracle_orient`. **New surface:** `oracle_orient --fleet` (map every profile:
schemas, versions, freshness, drift); cross-DB `oracle_diff` (same proven-read against two
databases, semantic diff); a unified, **egress-safe** fleet catalog searched once.
**Guard-safety:** every hop is still classifier-gated per lane; federation adds reach, never
admission surface. Arc M egress applies to the unified catalog so cross-DB search can't leak an
object a principal shouldn't see. **Depends on:** Arc A + Arc C2 (+ Arc M for the catalog).
**Unblocks:** fleet view in Arc L. **Risks:** partial-fleet failure (one DB unreachable) degrades to
a per-DB `UNREACHABLE`/`FAIL-CLOSED` status (the console already models this), never a whole-call
failure or a silently-missing DB. **DoD:** a 2-profile synthetic fleet returns a per-DB orient with
one DB unreachable; cross-DB diff returns a semantic delta; catalog search respects egress.

### Arc I — The reversible workspace ⏪
**Leans on:** rollback-by-default DML + lease savepoints + single-use grants (all exist).
**New surface:** named checkpoints (mark a savepoint, do exploratory DML, get a structured "undo to
checkpoint X" — a time-tree of uncommitted work); dry-run-then-commit (preview a DML's row-level
effect *inside* the rollback sandbox, then commit only the exact previewed change through the
single-use grant).
**Guard-safety:** all within the current transaction/rollback sandbox + the existing grant path;
commit re-classifies the exact statement (SEC-1), never trusting the previewed verdict. *(Verified
safe in review: `exec_grant.rs` single-use/digest/binding/generation/level all checked; the
classifier already emits `non_transactional_effect`.)* **Depends on:** nothing new. **Unblocks:**
Arc L undo-tree. **Risks:** autonomous transactions, sequences (`NEXTVAL`), triggers **escape
rollback** — the preview MUST label effects it cannot undo (this is the class of the closed P0
`.79`). **DoD:** checkpoint→exploratory-DML→undo restores state; preview shows before/after for a
reversible DML and a labeled "cannot-undo" for a sequence-touching one; commit re-classifies.

## A new governed write

### Arc D — Editions as a linear PL/SQL staging chain 🌿  *(highest novelty, highest honesty risk)*
Edition-Based Redefinition (since 11gR2) is powerful and barely tooled. **Honest mechanism (this was
a hard factual error in v1):** editions form a **strictly linear inheritance chain — an edition has
at most one child** (a second child of the same parent raises **ORA-38807**). So this is **not**
git-style branching and **not** a DAG. Arc D models a **single-writer linear staging workflow**:
propose → apply into the one child edition → test against it → flip the default edition → retire the
old one. At most one open proposal holds the live child edition at a time.
**Leans on:** EBR + the Reviews / Change-Proposal board + the step-up/grant path. **New surface:** a
proposal applies into the child edition; tests run against it; **merge = flip the default edition;
rollback = re-flip.** Zero-downtime PL/SQL deployment with pull-request *semantics* (linear, not
branched).
**Guard-safety (fixed leveling):** creating/altering an edition is DDL (existing DDL step-up +
single-use grant), but **merge = `ALTER DATABASE DEFAULT EDITION` = ADMIN** — require ADMIN step-up,
not DDL. Per-session test uses `ALTER SESSION SET EDITION`, which must route through the **P0 `.83`
ALTER SESSION allowlist** (today it hits the un-allowlisted catch-all). No edition op bypasses the
ladder. **Honest limits:** EBR only covers **editionable object types** (views, synonyms, PL/SQL) —
**tables/data are NOT editioned**; the tool must state precisely what a "stage" does and does not
isolate. Flipping the default edition redirects **new sessions only** — in-flight sessions keep
theirs, so rollback is not a global instant undo. Crossedition triggers / the editioning-view
pattern for table change are **out of first scope** (named in Non-goals).
**Depends on:** `http/mod.rs` de-monolith; the Reviews board (exists). **Unblocks:** Arc L linear
edition *timeline* (not a git graph). **DoD:** a proposal applies into the child edition, tests run,
merge flips the default (ADMIN-gated, audited), rollback re-flips; a non-editionable change is
refused with a typed "not editionable" explanation; a second concurrent proposal is refused with a
typed "one child edition" explanation (ORA-38807 surfaced honestly, not hit raw).

## Cross-cutting

### Arc E — Deterministic replay & incident capture 🎲  *(reframed — the harness is infra; the arc is capture)*
Seeded fault-injection-in-CI is **serious-infra best practice** (FoundationDB, TigerBeetle,
Antithesis all ship this class) — so the fault harness itself belongs in **Continuous excellence**,
not the headline. The genuinely user-facing, market-differentiating piece is **`om incident
capture`**: one command turns a production incident into a **scrubbed, offline-replayable artifact**
— a bug report that *runs*. **Leans on:** asupersync LabRuntime/DPOR (substrate) + K6 cassettes +
per-principal lanes. **Guard-safety:** a test/observability harness; no runtime admission path.
`om incident capture` **must scrub** binds/literals/identifiers through the Arc-M/redaction seam
before any artifact leaves the host (confidentiality invariant) — that scrub is the arc's core gate.
**Depends on:** `http/mod.rs` de-monolith (per-lane injection points). **Risks:** DPOR state-space
explosion — bound with depth/seed budgets; target the highest-value interleavings (lane
switch-at-cap, permit leak, lost wakeup), not exhaustive search. **DoD:** a known concurrency bug is
reproduced from a seed (in the CI harness); `om incident capture` produces a scrubbed artifact that
replays offline and contains no raw identifier (asserted by a test).

### Arc J — The self-teaching guard & refusal corpus 📚  *(reframed — the corpus is the arc)*
Structured refusals (class + suggestion) **already ship** in `rewrite.rs`, so "refusal-as-lesson" is
polish on an existing surface → folded into Continuous excellence. The novel, ship-worthy deliverable
is **the corpus**: accumulate (redacted) refusal→rewrite pairs into a shipped benchmark — a public
dataset of "unsafe agent SQL and its governed correction," feeding better suggestions, training
client-side guards, and serving as a research artifact on how agents try to break DB safety.
**Leans on:** the classifier's structured refusals + the Arc-M/redaction seam. **Guard-safety:**
read-only exhaust; the corpus **must** run through redaction before it ships (no binds, no
identifiers). Every *suggested* rewrite must itself pass the classifier before it's offered (never
teach an unproven statement). **Depends on:** nothing new. **Unblocks:** better suggestions
everywhere; a public artifact. **DoD:** a refused statement returns a classifier-proven safe
rewrite; the shipped corpus contains zero raw identifiers (asserted by a test).

## The face

### Arc L — the Carved Light console, alive 🛰️  (extend the dashboard that already ships)
> **Grounding note.** The default face is the **Carved Light operator console** (the console
> codename in the shipped `web/src` is "Carved Light"; **"ADYTON" is the design-source codename**
> from `todelete/claude_design_extracted/ADYTON …v5 (Carved Light)` and does **not** appear in the
> code). NOT a 3D orrery, NOT the retired "Ground Control / Apollo" 0.6.0 naming. Verified in
> `web/src`: Carved Light tokens, the **Clearance Ladder** (I·II·III·IV, clearance-colored — RO
> sage · RW gold · DDL copper · ADMIN rust), the **BigBoard** renderer set (`board2d`/`table`/
> `orrery3d`), the **GO/NO-GO** verdict (`GoNoGoVerdict = "GO" | "NO-GO" | "SYNC"`), the DB/profile
> cards, the live classifier feed (PASS / HELD / SEAL), snapshots + revert, and the append-only
> audit **CHAIN** ribbon (`ChainStrip`). Views: Overview, Sessions, Health, Capacity, Config,
> Clients, Audit, Explorer, Reviews, Workbench, Doctor.

> **Decision — 3D / three.js dropped for now (planned, not yet executed).** `orrery3d` is only
> *one optional BigBoard renderer* behind the skin seam; the mandatory face has always been 2D. See
> Wave 2. The seam stays open, so a 3D renderer can return later as a lazy, opt-in module.

Arc L makes the *existing 2D console* the live union of every dimension — each shipped arc adds one
**independent console affordance** (beaded separately, each depending on exactly its one source arc
+ the `assertDashboardSkinConformance` test), under a thin L epic that does **not** wait on all arcs
(so L "renders whatever has shipped," per its DoD):
- CQN change events → governed re-reads in the live classifier feed (Arc C1);
- an SCN **time-scrubber** dragging the console through history (Arc A);
- the edition **linear timeline** on the Reviews board — *not* a git graph (Arc D);
- the reversible undo-tree as a walkable branch off each snapshot (Arc I);
- query cost as a gas/heat badge on each gated statement (Arc G);
- egress masks shown as a lock badge on masked columns (Arc M);
- verdict certificates as inspectable proofs on each GO/NO-GO action (Arc B1);
- vector-neighborhoods as a cluster panel in Explorer (Arc F);
- a fleet map with per-DB reachability/drift status (Arc H);
- a column-lineage / drift view in Explorer (Arc K);
- policy narrowings surfaced on the profile cards (Arc N).

**Guard-safety:** a read-only *view* over the operator API; privileged actions only via the existing
GO/NO-GO single-use step-up. Everything renders in the 2D console (accessibility and no-WebGL are
non-negotiable). **DoD:** each affordance has a 2D console surface + a `board2d`/`table` fallback
passing `assertDashboardSkinConformance`, and ships with its source arc.

---

## Dependency DAG (what unblocks what)

```
                         ┌──────────────────────────────────────────────┐
PARALLEL BUG TRACK ─────►│  GATE: guard-sound  (Waves 0–1 + mutation≥90) │◄── every arc's sole upstream
(QA100 P0/P1, DRVQA25)   └──────────────────────────────────────────────┘
                                              │
Wave-2 http de-monolith ──────────────► gates C1, D, E  (only INFRA prereq this plan owns)
Wave-2 23ai CI lane ──────────────────► gates F (positive path)
Wave-2 plsql-intelligence CI lane ────► gates K

LEAD (zero new deps, version-agnostic):   G (cost) ,  A (time)
                                                       │
                                          A ──┐        │
shared node:  C2 oracle_orient ───────────────┼───► H (fleet = A + C2 + M)
                                          C2 ──┘   └─► K (lineage, + feature lane)

C1 CQN subs ──(needs de-monolith)       C3 Arrow-IPC ◄── drv:arrow-ipc-emit ► srv:pin-driver-arrow
redaction SEAM (primitive) ──► used by F, J, E, B1 (defensive)   [NOT an Arc-M edge]
M egress (arc) ──────────────► H  (fleet catalog needs real masking)
B1 cert ──(needs 0.8.3 audit)──► B2 Rekor          B3 Lean — independent, non-blocking research
N policy ──(D17 seed, tighten-only)     F (23ai) , I (no deps) , D (needs de-monolith, ADMIN flip)

E (incident-capture; harness→Continuous-excellence)   J (corpus; refusal-rewrite→Continuous-exc.)
   └─ E,J "unblock everything" is PROSE, not a DAG edge (do not materialize as blocks)

ALL shipped arcs ──► L affordances (each →its ONE source arc; L epic does NOT gate on all)
```

**Critical-path reading:** the only *infrastructure* prereq this plan owns is the Wave-2
`http/mod.rs` de-monolith (gates C1, D, E). **Additionally H depends on A + C2 + M, and K on C2** —
genuine arc→arc (second-wave) prereqs. F, G, A, I, J, M, N have no arc→arc deps of their own — F, J,
E, and B1 use the pre-existing redaction *seam* (a shipped primitive), **not** Arc M; only H
hard-depends on Arc M (its fleet catalog needs real masking). No cycle exists (H→A, H→C2, H→M, K→C2,
B2→B1, and L→all are the only cross-arc edges; none back-edge — M and the leads are pure sources, L is
the sole sink). Two CI-lane prereqs (23ai for F's positive path, `plsql-intelligence` for K) and one
cross-repo pin edge (C3) are explicit nodes above.

---

## Guard-safety analysis (the arc-safety invariant, per arc)

Doctrine #3: no arc may add admission surface. Verdict per arc:

| Arc | New execution path? | How it stays fail-closed |
|---|---|---|
| G Cost | No (adds a refusal) | 2nd fail-closed gate; `EXPLAIN PLAN FOR` (optimizes, target not executed) via the existing `allow_plan_table_write` gate; policy-unproven → refuse |
| A Time | No | `as_of` as a *classified* predicate (not un-gated `DBMS_FLASHBACK` session call); diff/replay compose reads |
| M Egress | No (removes data) | Tightening on the result path; mask-unknown-by-default; salted per-profile tokens |
| B Proof | No | Cert emitted inside the gating classify call (SEC-1); audit-write-fail = closed (SEC-3) |
| N Policy | No | **Monotone tightening operator** over base verdict; can `Deny`/`Narrow`, never `Allow-beyond-base` |
| C Living | **Yes (registration)** | CQN register is a gated privileged op (own capability + step-up, ceiling-counted); QUERY-level only, OBJECT-level refused |
| F RAG | No | Only pure `VECTOR_DISTANCE` admitted; **`DBMS_VECTOR.*` fail-closed** (UTL_HTTP egress); embedding only via verified local ONNX model |
| K Lineage | No | Dictionary + static source reads; never `EXPAND_SQL_TEXT` (fires policies) |
| H Fleet | No | Per-lane classification unchanged; Arc M egress on the unified catalog |
| I Reversible | Yes (commit) | Rollback sandbox + single-use grant; re-classify at commit (SEC-1); labels un-undoable effects |
| D Editions | Yes (DDL + **ADMIN** flip) | DDL step-up for editions; **ADMIN** step-up for the default-edition flip; `ALTER SESSION SET EDITION` via the P0 `.83` allowlist |
| E Determinism | No | Test/observability harness; capture scrubs through the redaction seam |
| J Self-teach | No | Read-only exhaust; suggested rewrites must themselves pass the classifier; corpus redacted |
| L Console | No | Read-only view; privileged actions only via GO/NO-GO step-up |

Three arcs touch write/DDL/registration paths (C, D, I). All are routed through *existing* step-up/
grant/first-class-privileged machinery, add no bypass, and re-classify at execution. Everything else
is read-composition or a tightening.

---

## Risks & open questions register

1. **Flashback (Arc A/H).** Depth bounded by `UNDO_RETENTION` + undo sizing (not
   `DB_FLASHBACK_RETENTION_TARGET`). **DDL-since-SCN → ORA-01466 typed refusal** (first-class).
   Non-flashbackable objects out of scope. Not byte-identical without total `ORDER BY` + pinned NLS.
2. **CQN (Arc C1).** Events not rows; best-effort/coalesced (RELIABLE QoS for durable); needs
   CHANGE NOTIFICATION privilege; registration is a gated privileged op; QUERY-level only. *Open:*
   per-principal subscription cap and how the 2nd EMON connection counts against the ceiling.
3. **Editions (Arc D).** Linear chain, one child (ORA-38807) — not branches; flip redirects new
   sessions only; editionable objects only. *Open:* is the editioning-view pattern ever in scope?
4. **23ai (Arc F).** Requires `COMPATIBLE ≥ 23.4` + a pre-loaded ONNX model; probe checks both.
   *Open:* the exact capability-detection probe and the 18c/21c degrade message.
5. **Cost (Arc G).** Estimate against current stats, not portable across schemas — audited tripwire,
   not a guarantee. *Open:* pair with runtime row-budget kill (`cn4`)?
6. **Egress (Arc M).** Consistency vs. inference trade-off; salting/scope model is the core design
   decision; format-preserving masks can leak via distribution.
7. **Policy (Arc N).** Must be a provably monotone tightening; expressiveness vs. safety. *Open:*
   confirm the D17 operator-authority config isn't already partly this.
8. **Proof (Arc B).** Rekor = *retroactive* evidence given a retained checkpoint (async, never gates
   admission); Lean proves the *model*, tied to Rust by conformance tests, not extraction.
9. **DPOR (Arc E).** Bounded/targeted interleavings only.
10. **The redaction/egress seam is the single most safety-critical shared component** — it gates
    Arc M, Arc E capture, Arc H catalog, Arc J corpus, Arc B derivations, and Arc C3/F exports. On by
    default for anything that leaves the host.

---

## Non-goals (explicitly out of the horizon's first scope)

- **No new database engine, no thick-mode, no C dependency.** Pure-Rust thin line stays.
- **No table/data editioning in Arc D** (editionable objects only; no crossedition triggers /
  editioning-view table change in the first cut).
- **No git-style branching of editions** (Oracle can't — linear chain only).
- **No `DBMS_VECTOR.*` admission in Arc F** (egress risk; fail-closed).
- **No policy that can *loosen* the base classifier** (Arc N is tighten-only).
- **No runtime 3rd-party dashboard skins** (built-in skins only; seam stays open).
- **No Lean proof of the *whole* classifier** in the first Arc-B cut (purity core only).
- **No exhaustive DPOR** (bounded, targeted interleavings only).
- **No live-ADB/OCI in CI** until a non-customer ADB exists (operator-gated harness stays).

---

## Continuous excellence (the non-arc raises — always-on, between waves)

- **Performance continuation** — the driver's decode-tuning discipline (SIMD `simd-decode`, scratch
  arenas `8eo`, pipelined prefetch, columnar Arrow `0mk`), every change byte-identical + microbenched
  + reverted-if-it-doesn't-measure.
- **Assurance deepening** — more cargo-fuzz targets, kani BMC widening, mutation-gate floor
  ratcheting up, the Lean conformance loop reaching from asupersync into the guard (feeds Arc B3),
  **and the seeded fault-injection harness** (reframed out of Arc E — infra best-practice, not a
  headline).
- **Self-teaching polish** — refusal→safe-rewrite suggestions (reframed out of Arc J; the shipped
  surface already carries class + suggestion).
- **Observability** — OpenTelemetry span coverage, per-lane trace correlation, metrics-history files
  feeding the Carved Light console.
- **Operator UX** — `doctor` self-heal breadth, installer polish, the real-ADB sign-off harness
  graduating to a documented CI lane once a non-customer ADB exists.
- **Driver → 1.0** — the ROAD-to-1.0 waves proceed on their own cadence; the server pins whatever
  driver patch it needs and never blocks on 1.0.

---

## Bead map (every open bead → a wave)

| Wave | Server (oraclemcp) | Driver (rust-oracledb) |
|---|---|---|
| **0 — 0.8.1 safety** | QA100 P0 ×6 (`.58/.80/.81/.82/.83/.84`) + `.28` | — |
| **1 — 0.8.2–0.8.4 / drv 0.8.3** | QA100 P1 ×44 (batched) | DRVQA25 `hb.3`; `nnnz` cassettes |
| **2 — docs + hygiene** | demonolith `qyqs`+`.1`–`.4`; QA100 `.6/.7/.8/.10`; drop-3D web bead; 23ai CI lane; plsql-intelligence CI lane | driver AGENTS rewrite; K10 doc-truth `hb.6` |
| **3 — cleanup + perf** | QA100 P2 ×37 + P3 ×8 | `0mk j1w 1s2 8pp dgi cn4 r9a 8eo mas soda-pre21c-ap87 mwu cco rsa-marvin-revisit-hlgd kerberos-radius-backends-bpsh` |
| **GATE** | **new: `guard-sound` gate bead** (closes when Waves 0–1 land + mutation≥90 re-verified); root epic `oraclemcp-epic-09x-alien` | — |
| **0.9.x — arcs** | new beads: G · A · M · B1/B2/B3 · N · C1/C2(orient, shared)/C3 · F · K · H · I · D · E · J · L (per-affordance beads) | new beads: `arrow-ipc-emit` (C3) + server `pin-driver-arrow`; optional `0mk` (F) |
| **housekeeping** | close legacy epics `iec3*` once children clear | close `road-to-1-0` waves; `57z` idea-wiz epic |

**What the horizon needs from the driver:** far less than v1 assumed. CQN, VECTOR decode, row
streaming, Arrow decode all ship today; the only new *driver* line items are **Arrow-IPC
serialization** (C3) and the optional **`0mk`** fast path (F). Everything else is server-side surface
over primitives that exist. **Every arc's sole upstream is the `guard-sound` gate** — beading that
one node turns "is the guard sound yet?" into a single `br dep` check instead of a hand-audit of the
QA100 epic.

**Totals to burn down before the horizon:** server ~96 QA100 open + 5 demonolith; driver ~2 DRVQA25
open + ~14 ROAD/perf. All Waves 0–3; none invented — it exists in the trackers.

---

## Sequencing summary

**Parallel track (owned elsewhere — this plan waits on it):** 0.8.1 P0 → 0.8.2–0.8.4 (+ driver
0.8.3) P1 → P2/P3. When it reaches a sound-guard state, the **`guard-sound` gate** closes and the
horizon opens.

**This plan's own track (drivable now / next):**
1. **Wave 2 — remaining doc-truth + `http/mod.rs` de-monolith + drop-3D + the two CI lanes (23ai,
   plsql-intelligence).** The doc items are cheap and independent of the bug track. The de-monolith
   is review-gated, isomorphic, and unblocks C1/D/E — the one structural item on the critical path.
2. **0.9.x — the arcs**, each a shippable 0.0.x train, each opening only after the `guard-sound`
   gate. Recommended lead order (novelty-per-week × trust, on already-shipped primitives):
   **G (Cost) + A (Time) first** — zero-gate, version-agnostic, and the *purest* expression of the
   spine (the guard governing a new dimension); then **C (Living-DB) + F (governed RAG)** once the
   de-monolith and 23ai lane are in; then **M (Egress) + N (Policy)**, **B (Proof) + J (Corpus)**,
   **D (Editions) + I (Reversible)**, **H (Fleet) + E (Incident-capture)**, with **L** rendering
   whatever has shipped. *(F is deliberately not the lead: it is the only early arc with a hard
   runtime gate — 23ai — so leading with it would blank for most of the 19c/21c installed base.)*

**Identity shift:** 0.8.x said *"provably as good as the reference, safely."* The alien version
says: *every other tool governs what an agent may run; **we govern every dimension — admission,
cost, time, egress, proof, and policy — and we prove each one.*** We have the substrate. Waves 0–3
make it trustworthy; 0.9.x makes it astonishing.

---

## Grounding & sources of truth

This plan follows Doctrine #5. The v2 grounding pass (two per-repo code+beads agents) and the v3
four-lens adversarial review (guard · architecture · Oracle-correctness · product) verified every
load-bearing claim. Load-bearing facts and where they were verified:

| Claim | Verdict | Source |
|---|---|---|
| VECTOR decodes on the wire | EXISTS | `oracledb-protocol/src/vector.rs:107`; `thin/fetch.rs:2221` |
| `0mk` columnar VECTOR fast path | OPEN (optional) | bead `rust-oracledb-0mk` |
| CQN registration + EMON parse in driver | EXISTS | `oracledb/src/lib.rs:3397,4630`; `thin/subscr.rs` |
| CQN pushes *events* (object/ROWID), best-effort unless RELIABLE; needs CHANGE NOTIFICATION priv | CORRECTED | Oracle docs (Continuous Query Notification) |
| Arrow decode to `RecordBatch`/C-Data; **no** Arrow IPC | EXISTS / IPC absent | `oracledb/src/arrow/mod.rs`; no `arrow-ipc` dep |
| `as_of` via DBMS_FLASHBACK bracket — server ("K9") | EXISTS (session-state call) | `AsOf` @ `oraclemcp-db/src/query.rs:134`; teardown `connection.rs:779` |
| Flashback = *data* from undo; `UNDO_RETENTION` (not `DB_FLASHBACK_RETENTION_TARGET`); DDL→ORA-01466 | CORRECTED | Oracle Flashback Query docs |
| plan-cost/cardinality — server ("K3") | EXISTS | `plan_cost_estimate`/`PlanCostSummary` @ `oraclemcp-db/src/intelligence.rs:1254` |
| `EXPLAIN PLAN FOR` optimizes without executing target; PLAN_TABLE write is session-GTT, tiered ReadWrite, gated by `allow_plan_table_write` | CONFIRMED | `classifier.rs:1302`; `oraclemcp-db/src/intelligence.rs:1216` |
| `DBMS_VECTOR.UTL_TO_EMBEDDING` can egress via UTL_HTTP → must stay fail-closed | CONFIRMED | Oracle `DBMS_VECTOR` docs; classifier UTL_HTTP-forbidden |
| Editions: linear chain, one child (ORA-38807); flip redirects new sessions | CORRECTED | Oracle EBR docs; ORA-38807 |
| `ALTER DATABASE DEFAULT EDITION` tiered Admin | CONFIRMED | `classifier.rs:255` (LEADING_ADMIN_VERBS) |
| K10 `OwnedRowStream` | EXISTS; leak `hb.3` open | `oracledb/src/row_stream.rs:106`; server `connection.rs:509` |
| Guard classifier/purity/ladder + mutation gate 91.5/95.7 | EXISTS | `oraclemcp-guard/src/*`; `docs/quality/mutation-safety.md:3` |
| `#![forbid(unsafe_code)]` workspace-wide (9/9) | EXISTS | each crate `lib.rs` |
| 52 tools incl. `oracle_query`/`explain_plan`/`execute` | EXISTS | `crates/oraclemcp/src/registry.rs:18` |
| In-repo feature-gated PL/SQL lineage (8 tools) | EXISTS | `plsql_tools.rs`; `plsql-*` =0.7.0 |
| Dashboard = Carved Light console (no "ADYTON" in code) | EXISTS / name corrected | `web/src/app/{skin,presentation-model,App}.tsx` |
| `http/mod.rs` monolith, 6358 lines | EXISTS | `crates/oraclemcp-core/src/http/mod.rs` |
| QA100 open 6/44/37/8 (11 P0 authored, `.28` in-progress) | CORRECTED | `.beads/issues.jsonl`, epic `…-5u1n` |
| Prescribed doc-truth strings already fixed | CONFIRMED | absent in README/AGENTS (2026-07-08) |
| DRVQA25 `hb.1/2/4/5` closed, `hb.3/hb.6` open | CONFIRMED | driver `.beads/` `…drvqa-2026-07-05hb` |
| driver 0.8.2 / asupersync 0.3.5 / 2462-of-2578 parity | **REAL BUT AS-OF, NOT "CONFIRMED"** (corrected 2026-07-16, bead `oraclemcp-udu6`) | The count is **2578 collected / 2462 passed / 116 skipped / 0 regressions / 0 missing**, measured **2026-06-22T18:28:26Z at driver SHA `b4a0cd3e`** (`docs/qualification/1.0.0-rc.1/SUMMARY.md`). It has **not** been re-derived since, and the driver's own `docs/RELEASE_CERTIFICATION.md` says in terms: *"Do not represent these counts as a fresh 0.8.3 reference run."* The original citations (`Cargo.toml`, `README.md:49`, `PARITY_SKIPS.md:18`) prove the number is **written down**, not that it is **current** — which is how a row for driver *0.8.2* came to read as confirmation for the shipping driver. The full suite is not a CI gate (`_quality.yml`'s "parity coverage" is a version-gate drift check, not a re-derivation), so it cannot self-refresh. Methodology remains sound: skips are decided by the reference suite's own `conftest.py` before driver code runs, so none can hide an engine defect. |
| Redaction today = secrets/profile-output + principal-key only (**no result masker**); operator allow-list (D17) = thin seed for N | CORRECTED | `oraclemcp-auth/src/secrets.rs`; `admin_auth.rs` |

Anything a future agent finds load-bearing and *not* in this table must be verified and added before
it is allowed to shape a bead.

---

# Appendix I — Per-arc implementation specs (bead-ready → implementation-ready)

The arc blocks above are the *roadmap*; this appendix is the *precision layer* — enough that beading
is mechanical and each child bead is implementable without asking the operator. **Every open design
fork is resolved here (with rationale); where a genuine spike is unavoidable, the spike is written as
a self-contained first bead with a defined output contract.** All file paths and patterns are
grounded against the current tree (conventions verified 2026-07-10).

## I.0 — Shared conventions (the templates every arc reuses)

**Add a read tool `oracle_x`** (5 edits): (1) `crates/oraclemcp/src/registry.rs` — add `"oracle_x"`
to `TOOL_NAMES` (bump the `[&str; N]` count; order is asserted by `registry.rs:1344`) and a
`registry.register(ToolDescriptor::new("oracle_x", ToolTier::FoundationLiveDb, "summary")
.with_input_schema(object_schema(json!({…}), &["req"])).with_output_schema(x_output_schema()))`
block in `tool_registry()`; (2) `crates/oraclemcp/src/dispatch/args.rs` — `#[derive(Deserialize)]
pub(super) struct XArgs {…}` (optionals `#[serde(default)]`, compat keys `alias="…"`); (3)
`crates/oraclemcp/src/dispatch/mod.rs` — a `"oracle_x" => { let a: XArgs = parse_args(name,args)?; …
Ok(json!({…})) }` arm in the `match tool` at `mod.rs:7102`, and add `"oracle_x"` to
`generated_read_tool` (`mod.rs:3930`); (4) `crates/oraclemcp-db/src/intelligence.rs` — `pub async fn
x_query(cx:&Cx, conn:&dyn OracleConnection, …) -> Result<Vec<OracleRow>, DbError>` with positional
`:1,:2` binds, upper-cased idents, `OracleBind::Null` for absent optionals, a `ROWNUM <=` cap; call
it from the arm via `guarded_metadata_conn`; (5) tests (below).
**Guard change:** add a proven-pure builtin at `classifier.rs:748` `BUILTINS` (lowercase); make a
package Forbidden via `PLSQL_SIDE_EFFECT_MARKERS` `classifier.rs:150` (block-scope) or
`ClassifierConfig::with_block_pattern`. **Profile knob:** add a field to `ConnectionProfile`
(`oraclemcp-config/src/profile.rs:485`, `#[serde(deny_unknown_fields)]` so it's mandatory) + its
`Debug` impl (`:593`) + `ProfileMetadata` (`:800`).
**Tests:** classifier unit — `classify(sql)` helper (`classifier.rs:1879`), assert `.danger` /
`.required_level` / `.reason_category`; regression — add `(sql, min_danger)` to `CORPUS`
(`adversarial_corpus.rs:15`, asserts `≥`) plus an `assert_eq!` for exact refusal; async unit —
`run_with_cx(|cx| async move {…})` (**asupersync, never tokio**), mock via `impl OracleConnection`
`#[async_trait(?Send)]` (copy `NRowMock`, `query.rs:321`); live — `#[cfg(feature="live-xe")] mod
live` + `connect_or_skip` (`oracledb_contract.rs:919`), env `ORACLEMCP_TEST_DSN/_USER/_PASSWORD`,
gvenzl matrix 18/21/23 (`scripts/e2e/oracle_version_matrix.sh`), synthetic TLS CN
`oracle-test.invalid`. **Dashboard affordance:** view-model in `web/src/app/presentation-model.ts`,
fetch `operatorGet("/operator/v1/x")` in `operator-client.ts`, `useQuery` in `App.tsx`, a renderer in
`skin.tsx` emitting `data-*` grammar attrs, an `it()` in `conformance.test.tsx`.

## I.1 — Lead arcs (near implementation-ready)

### Arc G — Cost gate
- **Decisions.** (a) `max_query_cost` is a **per-profile** ceiling (config), with an **optional
  per-call `max_query_cost` override that may only lower it** (never raise). (b) On a **null cost**
  (`PlanCostSummary.total_cost: Option<i64>` is None under dynamic sampling), **fail closed** — refuse
  with `cost_unavailable` rather than admit. (c) The cumulative per-principal budget is a **separate
  follow-up bead** (windowed counter in state files); the pre-exec gate ships first. (d) The
  "suggested index/rewrite hint" first cut = **the plan's own `access_predicates`/`filter_predicates`
  columns**, not a new optimizer — echo them; a real advisor is a later bead.
- **Mechanism.** Reuse `plan_cost_estimate`/`PlanCostSummary` (`oraclemcp-db/src/intelligence.rs:1254`)
  via `EXPLAIN PLAN FOR <stmt>` behind the existing `allow_plan_table_write` gate (target is optimized,
  **not executed**). In the `oracle_query` handler (`mod.rs:6983`), after `ensure_read_only` passes and
  before running, if the active profile has `max_query_cost` and `summary.total_cost > ceiling`,
  return an `ErrorEnvelope::new(ErrorClass::…, "estimated cost N exceeds ceiling")` carrying the plan.
- **Files.** `profile.rs` (`max_query_cost: Option<u64>` +Debug +ProfileMetadata); `mod.rs`
  `oracle_query` arm (the gate); `args.rs` `QueryArgs` (+ optional `max_query_cost`); refusal payload
  builder. No new tool, no registry change.
- **Tests.** Unit: a `PlanCostSummary{total_cost:Some(190000)}` over a ceiling → refusal; `Some(2)` →
  pass; `None` → refusal. Live: an intentionally-costly synthetic query over the ceiling refuses
  pre-execution.
- **Beads (4).** G.1 profile+arg `max_query_cost`; G.2 the pre-exec gate + null-cost-closed;
  G.3 refusal payload (plan + predicate hints); G.4 cumulative per-principal budget (follow-up).

### Arc C3 — Arrow-IPC results
- **Decisions.** Transport = **base64-encoded Arrow IPC stream** in a JSON field `arrow_ipc_b64`
  (MCP tool responses are JSON; a binary MCP resource is a later option). Opt-in via a `format:"arrow"`
  arg on `oracle_query` (default stays JSON rows).
- **Mechanism.** Driver: add `arrow-ipc` dep to `rust-oracledb`, serialize the existing `RecordBatch`
  (`oracledb/src/arrow/mod.rs`) with `StreamWriter`. Server: bump the `oracledb` pin, and in the query
  path emit `arrow_ipc_b64` when requested (after Arc-M egress).
- **Files.** driver `crates/oracledb/Cargo.toml` + `src/arrow/`; server `Cargo.toml` pin; `args.rs`
  `QueryArgs.format`; `mod.rs` query arm.
- **Tests.** Driver: round-trip a `RecordBatch` → IPC → `arrow-ipc` reader. Server unit: `format:"arrow"`
  returns decodable bytes. Live: a real query in Arrow mode decodes into the same rows as JSON mode.
- **Beads (3, cross-repo).** C3.1 `drv:arrow-ipc-emit` (driver); C3.2 `srv:pin-driver-arrow`;
  C3.3 `format:"arrow"` on `oracle_query` (+ Arc-M egress applied first).

### Arc F — Governed RAG
- **Decisions.** (a) Admit `VECTOR_DISTANCE` only (add `"vector_distance"` to `BUILTINS`
  `classifier.rs:748`); (b) `DBMS_VECTOR.*` stays refused — additionally add `"DBMS_VECTOR"` to
  `PLSQL_SIDE_EFFECT_MARKERS` (`classifier.rs:150`) so a PL/SQL-block form is **Forbidden**, not just
  Guarded; (c) capability probe = `SELECT value FROM v$parameter WHERE name='compatible'` ≥ 23.4 **and**
  a `USER_MINING_MODELS`/ONNX-model presence check; degrade → typed `requires_23ai` refusal.
- **Tool.** `oracle_semantic_search` — input `{ "over": {"owner?","table","column"}, "query_text?":
  string, "query_vector?": number[], "k": integer(1..1000), "metric?": "COSINE|EUCLIDEAN|DOT",
  "filter?": string(proven-read predicate) }` (exactly one of `query_text`/`query_vector` required);
  output `{ "rows":[…], "metric", "k", "used_index": bool }`.
- **SQL template.** `SELECT <cols> FROM <owner.table> [WHERE <proven filter>] ORDER BY
  VECTOR_DISTANCE(<column>, :qv, <metric>) FETCH FIRST :k ROWS ONLY` — `:qv` is the caller vector, or
  `VECTOR_EMBEDDING(<model> USING :qt)` when `query_text` + a verified in-DB model.
- **Files.** registry (+`oracle_semantic_search`), args (`SemanticSearchArgs`), dispatch arm,
  `intelligence.rs` `semantic_search_query`, `classifier.rs` (BUILTINS + marker), a 23ai capability
  probe helper.
- **Tests.** Classifier: `SELECT VECTOR_DISTANCE(a,b) FROM t` → Safe; `…DBMS_VECTOR.UTL_TO_EMBEDDING…`
  → Forbidden (both to `CORPUS` + an `assert_eq!`). Live (23ai lane only): top-k over a synthetic
  `VECTOR` fixture; the same call on 18c/21c → `requires_23ai`.
- **Beads (5).** F.1 BUILTINS admit + DBMS_VECTOR forbid + corpus/tests; F.2 `oracle_semantic_search`
  tool + SQL; F.3 capability probe + degrade; F.4 the **23ai CI lane** prerequisite
  (gvenzl `oracle-free:23-slim`); F.5 hybrid filter (proven predicate + distance).

### Arc D — Editions (linear staging)
- **Decisions.** (a) An "edition proposal" is a new file-backed record on the existing Reviews board
  (files-not-DB): `{proposal_id, profile, child_edition, base_edition, objects[], status}`. (b) The
  child-edition create SQL = `CREATE EDITION <e> AS CHILD OF <base>`; a **second concurrent proposal is
  refused** by checking the one-child rule *before* issuing (surfacing ORA-38807 as a typed refusal,
  not raw). (c) `EDITION` must be **added to `ALTER_SESSION_ALLOWLIST`** (`enforcement.rs:60`) so per-
  session testing works — after the P0 `.83` allowlist fix lands. (d) merge = `ALTER DATABASE DEFAULT
  EDITION = <e>` requires **ADMIN** step-up; create/alter = DDL step-up. (e) "tests run against it" =
  the operator-supplied test SQL run under `ALTER SESSION SET EDITION=<e>`; no test framework invented.
- **Files.** Reviews board store (`http/mod.rs` file-backed stores, post-de-monolith); a new
  `oracle_edition_*` tool family (propose/test/merge/rollback) via the standard tool template;
  `enforcement.rs` allowlist; step-up levels in the merge handler.
- **Tests.** Classifier: `ALTER DATABASE DEFAULT EDITION = x` → Admin (already; add to `CORPUS`);
  `ALTER SESSION SET EDITION = x` → allowed only post-allowlist-fix. Live (matrix): propose→test→merge
  →rollback on a synthetic editionable view; a non-editionable table change → typed refusal; a 2nd
  proposal → `one_child_edition` refusal.
- **Beads (5).** D.1 `EDITION` allowlist (gated on `.83`); D.2 edition lifecycle SQL + one-child guard;
  D.3 proposal record + Reviews board wiring; D.4 merge ADMIN step-up + rollback; D.5 editionable-only
  refusal + tests.

### Arc L — Console affordances
- **Decisions.** Each affordance = one `presentation-model.ts` view-model + one `skin.tsx` renderer
  emitting `data-*` grammar attrs + one `operator-client.ts` fetch + one `App.tsx` `useQuery` + one
  `conformance.test.tsx` `it()`. Under a thin `L-epic` that does **not** gate on all arcs — each
  affordance bead depends only on its source arc + `assertDashboardSkinConformance`.
- **Beads (per affordance, ships with its arc).** L.G cost badge; L.A time-scrubber; L.C1 live CQN
  feed; L.D edition linear-timeline; L.I undo-tree; L.M mask badge; L.B1 proof inspector; L.F cluster
  panel; L.H fleet map; L.K lineage/drift view; L.N policy-narrowing badge. Each: add the view-model,
  the renderer `data-*` axis, the `/operator/v1/*` fetch, and the conformance assertion.

## I.2 — One-decision arcs (fork resolved here)

### Arc A — Time
- **Decisions.** (a) **Keep the shipped K9 `DBMS_FLASHBACK` session-bracket** (`connection.rs:779`,
  `AsOf` `query.rs:134`) — do **not** rewrite to inline `AS OF SCN` (sqlparser 0.62 won't reliably
  parse it → would fail-closed to Guarded). Safety: the bracket is server-issued *around a
  classifier-proven read*, and is treated as an **internal privileged mechanism** the caller can only
  parameterize by SCN — the wrapped SELECT is still fully classified. (b) `oracle_diff` row alignment:
  **by primary key** when the object has one (from `all_constraints`), else **full-row hash set-diff**
  reporting add/remove only (no "change" without a key). (c) **Plan-time-machine is a stretch bead** —
  costing a plan at a historical SCN needs AWR/`DBA_HIST_SQL_PLAN` (Diagnostics Pack, **licensed**);
  flag the license and ship data-diff + replay first.
- **Tool.** `oracle_diff` — input `{ "sql": string(proven read), "scn_a": integer, "scn_b": integer,
  "key?": string[] }`; output `{ "added":[…], "removed":[…], "changed":[{key,before,after}], "keyed":
  bool }`. Beyond-retention (`ORA-01555/08180`) and post-DDL (`ORA-01466`) → typed refusals.
- **Files.** registry (+`oracle_diff`), args, dispatch arm (runs the same `read_query_as_of` twice at
  `scn_a`/`scn_b`, diffs in Rust), `intelligence.rs` diff helper; audit record gains an `observed_scn`
  field for replay.
- **Tests.** Unit: two canned row-sets → correct add/remove/change; keyless → add/remove only. Live:
  a synthetic table changed between two SCNs diffs correctly; a post-DDL SCN → `ORA-01466` typed
  refusal; a beyond-retention SCN → typed refusal.
- **Beads (4).** A.1 `oracle_diff` + PK/hash alignment; A.2 retention/DDL typed refusals; A.3
  audit `observed_scn` stamp + replay; A.4 plan-time-machine (license-gated stretch).

### Arc C1 — CQN subscriptions
- **Decisions.** (a) Registration is a **first-class privileged op** — a new capability gated by
  step-up, not classified SQL; (b) **QUERY-level only** (`register_query`), **OBJECT-level refused**;
  (c) each subscription's EMON connection **counts as one connection against the per-DB ceiling**;
  (d) per-principal cap = a new profile `max_subscriptions: Option<u32>` (default 4).
- **Surface.** MCP `resources/subscribe` over a proven read; the driver's `subscribe_register`/
  `register_query` (`oracledb/src/lib.rs:3397,4630`) fan callbacks to the client as change *events*
  (agent re-reads the proven scope). Contract: **best-effort, coalesced** (RELIABLE QoS optional).
- **Files.** `http/mod.rs` subscription routes (post-de-monolith); a subscription registry in state
  files; `profile.rs` `max_subscriptions`; the privileged-op gate.
- **Beads (4).** C1.1 privileged-registration gate + step-up; C1.2 QUERY-level register + OBJECT-level
  refuse; C1.3 EMON connection accounting + `max_subscriptions`; C1.4 `resources/subscribe` fan-out.

### Arc C2 — `oracle_orient` (shared catalog snapshot)  *(H and K depend on this)*
- **Decisions.** One tool returning a stable orientation snapshot assembled from individually-classified
  dictionary reads; cacheable per (profile, catalog-revision). It is currently only roadmap prose and
  **unshipped** — this block makes it beadable because H (`oracle_orient --fleet`) and K (lineage
  cross-check) both hard-depend on it.
- **Tool.** `oracle_orient` — input `{ "owner?": string, "include?": ["schema","fks","hot","freshness",
  "ddl"] }` (default all); output `{ "schema":[{owner,object,type}], "fks":[{child,parent,columns}],
  "hot_objects":[{owner,object,inserts,updates,deletes}], "freshness":{…}, "recent_ddl":[{owner,object,
  last_ddl_time}] }`.
- **SQL (each a classified dict read via `guarded_metadata_conn`).** schema/type: `ALL_OBJECTS`; FK
  topology: `ALL_CONSTRAINTS` (R↔P join) + `ALL_CONS_COLUMNS`; hot/freshness: `ALL_TAB_MODIFICATIONS`;
  recent DDL: `ALL_OBJECTS.LAST_DDL_TIME`. All bound, idents upper-cased, `ROWNUM <=` capped.
- **Files.** registry (+`oracle_orient`), args (`OrientArgs`), dispatch arm + `generated_read_tool`,
  `intelligence.rs` `orient_schema`/`orient_fks`/`orient_hot`/`orient_ddl` helpers.
- **Tests.** Unit: mock rows → assembled snapshot. Live: snapshot over a synthetic schema.
- **Beads (4).** C2.1 schema map + FK topology; C2.2 hot/freshness (`ALL_TAB_MODIFICATIONS`); C2.3
  recent DDL; C2.4 assemble tool + snapshot cache.

### Arc I — Reversible workspace
- **Decisions.** Named checkpoints = **native Oracle `SAVEPOINT <name>`** within the lease's existing
  transaction; undo = `ROLLBACK TO SAVEPOINT <name>` (a labeled-linear tree, not a DAG). Preview =
  run the DML in the sandbox → capture affected rows (count + `RETURNING` where available) → `ROLLBACK
  TO SAVEPOINT` → present → **commit re-runs and re-classifies** (SEC-1) through the existing single-use
  grant (`exec_grant.rs`). Un-undoable effects (sequences/triggers/autonomous txns) are **labeled** via
  the classifier's existing `non_transactional_effect`.
- **Tools.** `oracle_checkpoint {name}`, `oracle_undo_to {name}`, `oracle_preview_dml {sql, binds}`.
- **Files.** registry (+3 tools), args, dispatch arms (SAVEPOINT/ROLLBACK issued on the pinned session),
  reuse `exec_grant.rs` for commit.
- **Beads (3).** I.1 checkpoint/undo (SAVEPOINT); I.2 preview (sandbox→rollback→present); I.3
  commit-re-classify + cannot-undo labels.

### Arc K — Live lineage
- **Decisions.** Cross-check algorithm: for each source-derived edge (from the in-repo
  `oracle_plsql_lineage`), resolve the target against the live catalog — `verified` if object+column
  present, `drift:missing` if absent, `drift:type_mismatch` if the column type differs; **wrapped
  bodies → `partial` (labeled)**. Never `DBMS_UTILITY.EXPAND_SQL_TEXT` (fires policies). K runs under a
  **`--features plsql-intelligence` CI lane** (prerequisite bead).
- **Tool.** `oracle_lineage` — input `{ "owner?","object","column" }`; output `{ "edges":[{from,to,
  status:"verified|drift:missing|drift:type_mismatch|partial"}] }`.
- **Files.** registry (+`oracle_lineage`), args, dispatch arm (calls `plsql_lineage::dependencies` +
  live catalog reads via `guarded_metadata_conn`), `intelligence.rs` catalog cross-check.
- **Beads (4).** K.1 `--features plsql-intelligence` CI lane; K.2 source edges via existing engine;
  K.3 live cross-check + drift typing; K.4 wrapped-body `partial` labeling + tests.

## I.3 — Spike-first arcs (design resolved to a self-contained first bead)

### Arc M — Governed egress
- **First bead (M.0, design spike) — output contract:** a written masking-policy schema + token
  function. **Resolved direction:** the masker is a **server-side result transformer** (net-new; no
  result masking exists today, `oraclemcp-auth/src/secrets.rs` is secret-only); policy =
  `{ column_match:{schema?,table?,column|tag}, action:"mask|tokenize|null", }` per profile;
  tokenize = `HMAC(profile_salt, plaintext)` truncated (format-preserving optional); `profile_salt`
  stored per-profile in state files (files-not-DB); **mask-unknown-default** = any column tagged
  sensitive-or-unlisted is masked. Optional Oracle-native `DBMS_REDACT`/VPD tier is a **separate
  licensed** bead (Advanced Security).
- **Beads (5).** M.0 spike (schema + token fn); M.1 result transformer in the query path (before
  serialize); M.2 mask-decision certificate (feeds B1); M.3 mask-unknown-default policy loader; M.4
  optional `DBMS_REDACT`/VPD tier (licensed).

### Arc N — Policy-as-code
- **First bead (N.0, design spike) — output contract:** the policy grammar. **Resolved direction:**
  a small **declarative TOML rule list** (not a DSL) reusing the config machinery — rule =
  `{ match:{schema?,object?,verb?,principal?}, effect:"Deny"|"RequireLevel:<L>"|"RequirePredicate:
  <sql_fragment>" }`; evaluated **after** base classification as `final = base ∧ policy`; a
  `RequirePredicate` rewrite **re-enters the classifier (SEC-1)**; return type is `Deny | Narrow` only
  (**no `Allow`** — structurally monotone). D17 `OperatorAuthorityPolicy` is a thin seed (identity
  only), not reused for SQL rules.
- **Beads (5).** N.0 spike (grammar + monotone return type); N.1 rule loader (`deny_unknown_fields`
  TOML) + load-time loosening rejection; N.2 evaluator `base ∧ policy`; N.3 `RequirePredicate`
  re-classification; N.4 monotonicity property test.

### Arc B — Proof-carrying (B1/B2/B3)
- **B1 first move — resolve the cert grammar.** Extend `GuardDecision` (`classifier.rs`) to emit
  `derivation: Vec<DerivationStep{ rule_id: &str, construct: String }>` using the classifier's existing
  R-numbered rules (R15 etc.); cert = `{ stmt_digest, level, verdict, derivation, classifier_version,
  observed_scn, bound_audit_hash }`; the verifier is a **standalone Rust lib/bin re-running the same
  ruleset**. Cert passes the Arc-M/redaction seam before leaving the host.
- **Beads.** B1.0 DerivationStep schema + rule-id registry (spike); B1.1 emit-inside-classify (SEC-1) +
  hash into audit (SEC-3 fail-closed); B1.2 external verifier; B2.1 Rekor async anchor (non-blocking);
  B3.1 Lean purity-core proof (research; conformance-tested, not extracted).

### Arc E — Determinism / incident capture
- **First bead (E.0) — artifact manifest schema.** `om incident capture` bundle = a dir of
  `{ manifest.json (seed, lane-ids, versions), cassettes/ (K6 format), config.redacted.toml,
  audit-tail.redacted.jsonl }`; `om incident replay <bundle>` runs under `LabRuntimeTarget` with the
  seed. All bundle contents pass the Arc-M/redaction seam (asserted by a test).
- **Beads (4).** E.0 manifest schema; E.1 `capture` (bundle + redaction gate); E.2 `replay` under
  LabRuntime; E.3 the fault-injection CI harness (moves to Continuous-excellence, seed-reproduces-bug).

### Arc J — Refusal→rewrite corpus
- **Decisions.** The refusal→safe-rewrite *suggestion* already ships (`rewrite.rs`) → reframed to
  Continuous-excellence; the shippable arc is the **corpus artifact** — a file-backed, append-only,
  redacted dataset of refusal→rewrite pairs.
- **Artifact schema (JSONL).** `{ id, refused_sql_redacted, refusal_class, suggested_rewrite_redacted,
  why }` — every text field passes the Arc-M/redaction seam (no binds, no schema identifiers); dedup by
  content hash.
- **Files.** a corpus writer hooked at the refusal site (where `ForbiddenStatement`/
  `OperatingLevelTooLow` are produced in dispatch) appending to a state file; a dataset export path;
  the suggested rewrite must itself pass `classify` before it is offered/recorded.
- **Tests.** A refused statement records a classifier-proven rewrite; a test asserts the shipped corpus
  contains zero raw identifiers.
- **Beads (3).** J.1 corpus record schema + redaction; J.2 append-on-refusal writer (rewrite
  re-classified); J.3 dataset export + zero-identifier test.

### Arc H — Fleet reach
- **No new decision** — H is A.1 (`oracle_diff`) + C2 (`oracle_orient`) + M (egress) aggregated across
  the per-principal lane fleet; partial-fleet failure → per-DB `UNREACHABLE` status.
- **Beads (3, gated on A+C2+M).** H.1 `oracle_orient --fleet` (map every profile, per-DB status);
  H.2 cross-DB `oracle_diff`; H.3 egress-safe unified fleet catalog.

**Readiness after this appendix:** the I.1 arcs (G, C3, F, D, L) are implementation-ready (schemas +
files + tests specified); the I.2 arcs (A, C1, **C2**, I, K) are implementation-ready with any
architecture fork resolved; the I.3 arcs (M, N, B, E, **J**) each have a self-contained first bead (a
design spike with a defined output contract), and H is a pure aggregation of A + C2 + M — so **all 14
arcs (18 sub-arcs incl. B1/B2/B3, C1/C2/C3) are covered and no arc requires an operator decision to
begin.** Beading follows the `br` template in AGENTS.md: root epic
`oraclemcp-epic-09x-alien`, the `guard-sound` gate as every arc's upstream, then the child beads above
with their stated deps.
