# PLAN — oraclemcp 0.10.0 / driver 0.9.0: field-hardening, self-sufficient testing, OCI

**Version:** v5 (v2: review round 1 — CI-red ground truth → Workstream Z, P2 tail → Workstream P, P1-2 grounded, 17/17 Appendix-A claims re-verified. v3: inferred-sibling sweep S1–S15 → §A.10, new B14/B15/B16. v4: **Workstream R — the Local Integrator Rig**. v5: **operator rulings recorded on every open decision** (marked "OPERATOR RULING (2026-07-20)" inline), Z1 RESOLVED in-session — root cause was CI shallow checkout, `codex/d2-completion` landed as `5a52bf6`+`3f057e2`, `ci.yml` fetch-depth fixed — and the driver bug-bead un-deferral ruling folded as G12). **Date:** 2026-07-20.
**Owner:** lead orchestrator. **Release is operator-gated** — agents never tag or publish.
**v7 delta (2026-07-21):** the Z2 fresh mutation campaign is **DEFERRED OUT of 0.10.0** (operator
ruling) — a seal binds to a SHA and would re-stale on every safety-crate fix, so it is produced once
on the release candidate. **Deferring the campaign does NOT defer green-main:** the per-push
`E_STALE_SEAL` check is gated behind `ALLOW_STALE_MUTATION_SEAL=1`, set in `ci.yml` only (development
CI), so per-push CI is fully green with a loud deferral warning — while the release path
(`release.yml`/`docker.yml`/`publish-mcp.yml`) does **not** set it, so an actual release still
hard-fails without a fresh seal (§Z2, §9.2).
**v8 delta (2026-07-21, later the same day — external review + ground-truth refresh):**
(1) **Z2 clarified — OPERATOR RULING: mutation work must never stall the train, period** — neither
development pushes nor the release; the v7 "release path still hard-fails" residue is superseded:
`ALLOW_STALE_MUTATION_SEAL=1` now also set on the release path (loud warning), the seal is
**advisory this train** and accrues from the bounded nightly shard rotation (§Z2 clarification —
including the honest terminology note: mutation testing ≠ fuzzing; the fuzz lanes are unaffected).
(2) **Ground truth refreshed:** push CI on `main` is GREEN again from `a04f68b` (the v7 flag works),
and the **Windows lane is green on HEAD** — Z3's red did not reproduce (flake confirmed); `vzui`
stays in scope via G13. (3) **Two NEW scheduled-lane front-page reds found and owned: Z5** (the new
Fuzz Campaign's first-ever run fails on a cargo-fuzz musl-target infra defect — zero crashes) and
**Z6** (the nightly Mutation Safety rotation fails `E_OOM_MUTANT` on resource-capped shards); both
fixed in the same session (fuzz `--target` pin; `MUTATION_OOM_POLICY=warn` void-shard policy on the
rotation only, attestation-honest). (4) **No-stall riders:** G6 (elapsed-evidence streak) and B13a's
cannot-reproduce residue are pre-authorized RC deferrals, exempt from the publish-sink ancestry
(§10). (5) **A5 pairing-page implementation pinned** to `Referrer-Policy: same-origin` on that one
page (a `pairing.js` would abandon the advertised script-free property). (6) **B11 rider:**
release-note the `oracle_capabilities` compact default — it changes the mandated first call.
**v9 correction (2026-07-22):** the server side of this train is **0.10.0, not
0.9.1**. `cargo-semver-checks` found major public-API findings against the
published 0.9.0 server crates after the intended lease-removal and metadata
bounding changes, so the artifact shipped as 0.10.0. This is a naming
correction to keep the plan/tracker train name aligned with the shipped
artifact; it does not change Cargo version metadata.

**How to use this document.** It is written to be self-contained: an agent that has never seen this
project should be able to pick any task here and implement it without asking a human. Every task names
its blocking dependencies, its acceptance criteria, and *why* it exists. It is ONE file: the plan body decides scope, ordering and
acceptance; **Appendix A** carries the code-level evidence (`file:line`, root causes, minimal fixes)
for every field finding, and **Appendix B** is the traceability matrix. Nothing outside this document
is required to start work.

---

## 1. Ground truth (verified 2026-07-20, not assumed)

### 1.1 Repository state
| | oraclemcp | rust-oracledb (driver) |
|---|---|---|
| Released | 0.9.0 (2026-07-18) | 0.8.4 (2026-07-18) |
| `main` HEAD | `6519a57` (docs-only since `5058690`) | `537373a` |
| Full local gate | clippy ✅ + `cargo test --workspace` ✅ | clippy ✅ + tests ✅ + `gen_baseline.sh --check` ✅ |
| **Remote CI on `main`** | **RED on every push since `6da3997`** (last green `46e53c3`) — §A.9, **Workstream Z**. *(v8 refresh: push CI GREEN again from `a04f68b`, Windows lane included; residual reds are two scheduled lanes → Z5/Z6)* | **GREEN** (Required + CI + live version matrix + Kani) |
| Test binaries | — | 169 across both repos, **0 failures** |

**CI honesty note.** The driver push at `d99927d` went **red** (2 of 25 checks): `required/quality-contracts`
failed its *Baseline drift check* (`docs/baseline` stale after the TLS + pyshim commits) and the
aggregate quality job reported `failed=1` behind it. Cause: the pre-push gate ran clippy + tests but
omitted `scripts/gen_baseline.sh --check`. Fixed and pushed as `537373a`. **Rule added:**
`gen_baseline.sh --check` is mandatory in the driver's pre-push gate (see §9.1).

**Public-surface delta from that regen: `oracledb` went 908 → 915 public source items** (the new
stage-aware TLS types). This has a release consequence — see §7.

**oraclemcp CI honesty note (review round 1).** The SERVER's remote CI has been **red on every push
since `6da3997`** (last green `46e53c3`, 06:34 2026-07-20) — three root causes, all diagnosed in §A.9
and owned by **Workstream Z**: (1) bead-close evidence on `main` citing commits that exist only on
**unpushed local `codex/*` branches** (`SOURCE_SHA_ABSENT` × 15+ hard findings in CI, **0 locally** —
the local gate resolves the SHAs through local branches, so it structurally cannot see this class);
(2) a stale committed mutation seal (`E_STALE_SEAL`), failing **two** jobs; (3) a new Windows-lane
failure on the HEAD run. The "full local gate ✅" row above is true and insufficient.

### 1.2 Bead inventory (oraclemcp `.beads/issues.jsonl`, 51 open/in_progress)
| Group | Count | Disposition in this plan |
|---|---:|---|
| F-LOW children `7.11.1..20` (P3 real defects, `file:line` specified) | 20 | Workstream G3 — triaged, not all in 0.10.0 |
| Epics (close as children drain) | 11 | Bookkeeping; close at the end |
| Work beads | 11 | Workstreams G1/G2/G4–G9 + H (bead `13`) |
| Cluster I — OCI Always-Free e2e | 4 | **Workstream F (in scope)** |
| Cluster J — GCP/Vertex launch | 5 | **DEFERRED by operator — out of scope** |

Driver beads (**corrected in review round 1**): the driver tracker holds **83 deferred, 0 open** —
including `rust-oracledb-4sfc` (retry-masking; §4.B5) and `rust-oracledb-s0se` (close_notify;
§A.6.11), both currently `deferred` with **uncommitted close-evidence files already sitting in the
driver working tree** (`tests/artifacts/evidence/closes/…` — see Z4). All other deferred driver beads
stay deferred (operator ruling); the obsolete patch-named driver release beads are
retitled per §7 at bead conversion. Also relevant: deferred server bead `oraclemcp-vzui` (Windows
`file_store` durable-state "Access is denied") — see Z3.

The 11 work beads: `plan-bead-graph-lint-eshv` (P0), `13` release train (P1, versions now fixed: driver 0.9.0 / server 0.10.0), `5.2` D2 coverage
ratchet (P1), `8.1` G1 IAM subject-mapping (P1), `4.3` C3 stash triage, `4.5` C5 moves/renames,
`4.6` C6 de-monolith, `5.4` D4 fuzz shard (reopened for a cold-start proof), `8.2` G2 Live-nightly
streak, `12.3` K3 attestation lanes (P3), `izk5` stale driver-version comment (P3).

### 1.3 Local environment — better than assumed
**Oracle containers already exist on this machine**, which removes the largest cost from Workstream D:

- running: `oracle-xe21-1520` (`gvenzl/oracle-xe:21-slim`), `oracle-xe18-1518` (`gvenzl/oracle-xe:18-slim`),
  `rust-oracledb-free` (`gvenzl/oracle-free:23-slim`), `plsql-intelligence-xe`
- cached images: `gvenzl/oracle-xe:11/18/21-slim`, `gvenzl/oracle-free:23-slim`,
  `oraclelinux9-instantclient:23`

**OCI: ✅ authenticated (2026-07-20).** `~/.oci/config` written against the existing API key; `oci iam
region list` returns 44 regions; **zero-cost baseline asserted — 0 Autonomous DBs** in both
the CI compartment and root. **Cluster I (Workstream F) is unblocked.** See §4.F0 for the two traps hit
(user-OCID-in-tenancy-field, and empty-list vs broken-query).

### 1.4 Field input
Round-3 field test against **0.9.0**: **5 P0 adoption blockers, 14 punch-list P1** (plus two
unnumbered body-level P1s, folded into B11 and B13), **13 P2** (P2-2 was retracted by the tester; the
12 active ones plus four unnumbered P2/P3-grade findings are enumerated in **Workstream P** so this
file stays self-contained), against a product whose CI was fully green. Raw round is quarantined
(`livesting-*/`, gitignored, constitution #9); the scrubbed code-level grounding is **Appendix A**.
**Grounding is now complete for every finding, P1-2 included** (§A.6.8, review round 1).

**Artifacts received** (all quarantined): the report itself; the refusal-corpus export (23 redacted
records); a deterministic incident bundle (manifest, redacted config, cassette) whose **0-byte
redacted audit tail independently corroborates P1-9**. **Not delivered**, although the report's own
artifact table names them as keep-worthy: the corrected multi-profile config, the working OCI config,
and the wallet dir with the added public root. **OPERATOR RULING (2026-07-20): these are not
available at this time — everything we have is the quarantined folder; the plan proceeds without
them.** The §A.2.7 H1-vs-H2 diagnosis therefore rests on D3/D9's synthetic VPD fixture plus A1e's
shipped visibility, which was the design intent anyway.
One report-internal inconsistency, recorded so nobody retraces it: a late "authentication modes"
matrix claims mTLS / control-listener / OAuth were "not tested", but the findings sections that DID
test them are authoritative — the matrix is a mid-round draft remnant.

---

## 2. Objectives and non-goals

### Objectives
1. **Make the product adoptable.** Every P0 blocker fixed or explicitly, honestly deferred with a reason.
2. **Stop shipping features that cannot be reached from outside the repo** (§3).
3. **Become self-sufficient in testing** — reproduce the field's finding classes on this machine, so a
   production field test is a confirmation, not a discovery mechanism.
4. **Drain the backlog** — all remaining beads except Cluster J and the deliberately-deferred
   driver feature beads (G12's ruling: bugs/fixes/parity never stay deferred; features may),
   including the OCI campaign.
5. **Cut one coordinated release** carrying all of it.

### Non-goals
- **Cluster J (GCP/Vertex launch)** — deferred by the operator.
- **Fixing the customer's database or diagnosing their VPD policy.** We ship *visibility* (§4.A1), not a
  remote diagnosis.
- **A rewrite of the OAuth verifier** — it is correct (§A.5.2); this is documentation + diagnostics.
- **Runtime third-party dashboard skins**, engine bake-in, and other 0.6.x-era deferrals stay deferred.

---

## 3. The organizing insight (why this plan is shaped as it is)

Three independent investigations converged on one structural defect:

> **Tests construct the client side using the same internal helper the server side consumes.**

mTLS (`format!("mtls:{}", cert_fingerprint_sha256(..))`), OAuth (in-module `mint()` + in-module HMAC),
stdio init token (tests interpolate the `INIT_TOKEN_META_KEY` constant), session statements (assert the
builder's output, never open a connection), and the dashboard (tests assert the very `no-referrer`
policy that breaks browsers). Each proves **round-trip self-consistency**; none proves **external
reachability**. That is how 169 green test binaries coexisted with four transport-auth features an
integrator could not use.

**Consequence for this plan:** fixing the individual bugs is *necessary but insufficient*. Workstream C
(wire-contract fixtures) is what stops the class from recurring, and it is cheap and offline. A
surprising number of the field findings were catchable without a database at all — which *narrows* what
the live environment must cover (§4.D).

**Test-shape rules** (§A.8) become binding repo policy and go into AGENTS.md.

Review round 1 found the same defect one level up, in our own process: the bead-close-evidence gate
passed **locally** while failing in CI. The final diagnosis (Z1, resolved): the cited SHAs were all
main-reachable — CI's **shallow checkout** simply could not see them; the local/full-history view
and the CI/depth-1 view were two different repositories pretending to be one. The rule earns a
place beside §A.8 regardless: **close evidence must cite commits reachable from `origin/main`**, and
the gate that checks it must run against full history (fixed in `ci.yml`).

**The consolidated runtime view (operator question, 2026-07-20: "is this all over the place?").**
The C/D/E/R/F workstream split is the **construction** view — it exists so the work beads cleanly
(who builds which asset). At **runtime** there are exactly TWO surfaces, and only two:

| Surface | What runs there | Trigger | Weight |
|---|---|---|---|
| **CI** (stays as it is today — already made lightweight) | required lanes (fmt/clippy/tests/deny/lints/goldens) **+ C's wire-contract fixtures** (they are plain `cargo test`s — zero new CI weight) + the existing scheduled advisory lanes (mutation-shard rotation, live nightly, driver version matrix) | every push / nightly | light, required-lanes-only heartbeat preserved |
| **The rig** (`scripts/rig/rig.sh` — THE single local entry point) | everything live, as tiers: `--tier live` = D's environment + E's white-box e2e suites; `--tier integrator` = R1–R4 (+ R5-lite on an RC); `--tier oci` = F (operator-gated) | operator / nightly-optional / pre-release | heavy, never able to red the front page |

**Consolidation rule (binding):** no new standalone test harness is ever added — everything live
runs THROUGH `rig.sh`. D1's up/down IS the rig's L1; E's suites execute inside the rig's
environment as its white-box tier (`scripts/e2e/run_all.sh` is invoked by the rig, not run beside
it); F is the rig's cloud tier. Existing scripts get absorbed or invoked, never duplicated. So the
operator's mental model is exactly right and is now the contract: **local vs CI** — five
workstreams of construction, two surfaces of operation.

---

## 4. Workstreams

Priority notation: **[P0]** blocks the release; **[P1]** should ship; **[P2]** ship if it lands cleanly.

### Workstream Z — restore oraclemcp `main` to green [P0 — do this FIRST]
*oraclemcp remote CI is red on every push since `6da3997`; the driver is green. §A.9 is the evidence
base. Nothing else in this plan can show honest green until Z lands (constitution #2).*

- **Z1 [P0] — ✅ RESOLVED in-session (2026-07-20 evening, operator ruling A2: "resolve now").**
  The investigation inverted the v2 diagnosis: **every one of the 10 evidence-cited SHAs is
  main-reachable** (`git merge-base --is-ancestor` sweep) — the `SOURCE_SHA_ABSENT` red was the
  audit job's **shallow checkout** (`actions/checkout` default depth-1 in the `boundary` job), which
  cannot resolve commits older than HEAD. Fixed: `fetch-depth: 0` on that job's checkout (with an
  explanatory comment). Branch verification via `git cherry`: **five of six wave branches are 100%
  patch-equivalent to `main`** (rebase-twins; the "84 commits" were already pushed);
  `codex/d2-completion-20260720` held the only two real unmerged commits — `fecfa06` (guard: ALTER
  SESSION structural clause parsing, a strict tightening, reviewed) and `e11632a` (D2 independent
  per-crate mutation floors, bead `5.2`) — **landed as `5a52bf6` + `3f057e2`** (linearized on push;
  patch-identical to the branch commits, verified via `git cherry`).
  Remaining Z1 tail: branch deletion is operator-gated (RULE 1) — branches left in place.
  **Rule (stays; goes into AGENTS.md alongside §A.8):** close evidence must cite commits **reachable
  from `origin/main`** at close time — the shallow-checkout episode proves the reachability check
  must also run against a full-history view.
- **Z2 [DEFERRED OUT OF 0.10.0 — OPERATOR RULING (2026-07-21)]. The fresh five-surface mutation
  campaign is removed from this plan's scope entirely.** Rationale (recorded): a mutation seal binds
  to an exact source SHA, and this plan's A/B workstreams change the safety crates (guard, audit, db,
  dispatch) repeatedly — so a seal produced now would be re-staled by the first safety-crate fix and
  re-run at the release candidate anyway. Producing a ~12-hour throwaway seal ahead of the fixes is
  effort in the wrong order. **The mutation seal is a release-gate concern, produced once on the RC
  after the safety-crate changes land — that work is out of THIS train** (like Cluster J). A partial
  attempt on 2026-07-21 (guard + audit shards computed via Codex Spark) is abandoned; its scattered
  artifacts and the `oraclemcp-z2-mutation` worktree are throwaway.
  **Green-main is preserved (operator ruling 2026-07-21: "deferring Z2 does not mean deferring
  green").** The per-push `E_STALE_SEAL` failure in `mutation_safety_gate.sh` (both `check-report`
  and `check-floor-report`) is gated behind **`ALLOW_STALE_MUTATION_SEAL`**, set in **`ci.yml` only**
  (development CI) — so the coverage-ratchet, release-preflight, and heartbeat jobs go **green** with
  a loud `WARNING E_STALE_SEAL deferred` line, not red. This is **not gate surgery to hide a gap**:
  the flag is deliberately **absent** from the release path (`release.yml`, `docker.yml`,
  `publish-mcp.yml`), so an actual `vX.Y.Z` release still hard-fails without a fresh seal — the seal
  is simply enforced **at the release candidate, where it belongs**, instead of blocking every
  development push. Producing the RC seal (and re-adding it to the local pre-push gate) is the
  deferred follow-up.
  **Z2 CLARIFICATION — OPERATOR RULING (2026-07-21, v8, supersedes the release-path residue
  above): mutation work must NEVER stall the train — neither development pushes nor the release.**
  A day-scale five-surface campaign on the critical path is a no-go anywhere. Implementation:
  `ALLOW_STALE_MUTATION_SEAL=1` is now also set on the release path (`release.yml`, `docker.yml`,
  `publish-mcp.yml`) with the same loud warning — the seal is **advisory for this train**, and seal
  evidence accrues from the bounded nightly shard rotation (≤32 mutants/shard, minutes each) or an
  optional RC-time background campaign that gates nothing. Honesty preserved, for the record:
  (a) **mutation testing is not fuzzing** — it measures test-suite strength by mutating our source;
  the fuzz lanes (robustness against hostile input — the actual runtime-safety gate) are unaffected
  and keep running (Z5); deferring the seal does not make the shipped binary less safe, it defers a
  *measurement* of test quality; (b) stale/errored evidence can never enter a seal
  (`migrate_mutation_result.py` stays strict), the changed-line coverage ratchet still gates, and
  every required lane still gates; (c) the warning stays loud on every surface that reads the
  marker. The RC-seal follow-up bead remains open but is **not** a publish-sink ancestor (§10).
- **Z3 [P1→P0-disposition] — the Windows workspace lane. OPERATOR RULING (2026-07-20): MUST be
  fixed — re-deferral is off the table.** "Rust workspace (Windows) → cargo test workspace on
  Windows" went red on the `6519a57` run (previous run green; only docs commits in between ⇒ flake or
  environment). Pull logs when available (job conclusion beats truncated logs), rerun once; if it
  reproduces, first suspect deferred bead `oraclemcp-vzui` (Windows `file_store` durable-state
  "Access is denied") — **un-defer it and fix** (also mandated by the G12 ruling: bugs do not stay
  deferred).
  **✅ RESOLVED (v8, 2026-07-21): did not reproduce** — the Windows lane is green on the subsequent
  push runs including HEAD `a04f68b` (verified via check-runs, not truncated logs). Flake confirmed;
  no code change was needed for the lane itself. `vzui` (the real Windows durable-state bug) stays
  in scope via G13's must-fix list — Z3's resolution does not close it.
- **Z5 [P0-frontpage, v8] — the new Fuzz Campaign workflow red (infra, zero crashes).** The
  workflow's first-ever scheduled run (2026-07-21 06:15) failed all 5 targets identically at BUILD:
  `sanitizer is incompatible with statically linked libc` + `can't find crate for std` for
  `x86_64-unknown-linux-musl`. Root cause: `taiki-e/install-action` delivers a prebuilt,
  musl-linked `cargo-fuzz`, and cargo-fuzz defaults `--target` to the triple *it* was built for —
  so the fuzz build silently targeted musl, where ASan cannot link. **Fix (landed with v8): pin
  `--target x86_64-unknown-linux-gnu` on the `cargo fuzz run` line** (`.github/workflows/fuzz.yml`).
  No fuzz target crashed; no corpus finding exists. Also committed: the refreshed
  `crates/oraclemcp-guard/fuzz/Cargo.lock` (new guard deps from the alter-session work) so the
  scheduled lane builds deterministically. Acceptance: a dispatched Fuzz Campaign run completes
  green on all 5 targets.
- **Z6 [P0-frontpage, v8] — nightly Mutation Safety rotation red on resource-capped shards.** The
  2026-07-21 05:29 scheduled run failed 6 of 10 shard jobs with
  `E_OOM_MUTANT: … observed oom_kill delta 1; graded ERRORED, never caught`
  (`mutation_safety_gate.sh`, run-shard cgroup accounting) — a mutant hit the deliberate 6G
  `MUTATION_MEMMAX` cap; the gate correctly refused to grade it and then, incorrectly for a
  sampling rotation, failed the whole lane. **Fix (landed with v8): `MUTATION_OOM_POLICY=warn` on
  the scheduled-shard job ONLY** — a resource-capped shard is recorded `errored` in its integrity
  sidecar (so `migrate_mutation_result.py` still rejects it from any seal), emits a loud
  `WARNING … shard VOID` line, exports `shard_void=1`, and the attestation step is skipped for it
  (never a `complete=PASS` attestation for a shard that did not complete). Seal campaigns, manual
  dispatches, and local runs keep the strict fail default. Honesty unchanged; only the nightly
  front-page red is removed — per the §Z2 clarification ruling.
- **Z4 [P1] — driver-side bookkeeping.** The driver tree holds **uncommitted** close-evidence files
  for `4sfc` and `s0se` (`tests/artifacts/evidence/closes/…`) and four local agent branches whose
  content is already merged to `main` (§A.9). Commit the evidence through the guarded close flow once
  B5 / §A.6.11 verification passes. Do not delete branches without explicit operator approval.

**Acceptance (v8):** every check-run on both repos' front-page HEAD green — required lanes AND the
scheduled stamps (see `frontpage-green-mechanics`); bead-evidence audit **0 hard findings in CI**.
The formerly-excluded `E_STALE_SEAL` trio is now green-with-loud-warning everywhere (§Z2
clarification — the seal is advisory this train), and the two scheduled-lane reds are owned by
Z5/Z6 with landed fixes; nothing on the front page is an "accepted red" anymore.

### Workstream A — P0 adoption blockers

#### A1 [P0] Make row-level security visible; stop silent-empty reads
*Field: P0-4. §A.2.3, §A.2.4, §A.2.5, §A.2.7.*

The field symptom (VPD-protected objects read as empty) decomposes into four defects. **The tester's own
root cause was wrong** — session statements *are* applied to the serving connection (§A.2.1). Ship
the general fix regardless of what the customer's database turns out to be doing.

- **A1a — close the fail-open in the VPD refusal gate.** `catalog_resolver.rs:351-363` treats an empty
  `ALL_POLICIES` probe as "no policy", indistinguishable from "cannot see policy metadata", so a gate
  meant to **refuse** VPD objects silently **passes** them. Probe `ALL_POLICIES` readability once per
  session; if blind, return `Unknown` (refuse). *~10 lines.*
  **Why:** a fail-open inside a fail-closed system is the class AGENTS.md forbids. This is the single
  most important line-count-to-value fix in the plan.
  **Blast radius:** deployments whose DB user lacks catalog visibility begin refusing instead of
  silently emptying. Strictly more correct, but user-visible — gate behind a release note.
  **Test (offline):** mock-conn test where the policy probe returns empty *because of privilege*.
  **Sibling (round-2 sweep, §A.10): the VIRTUAL-COLUMN gate has the identical fail-open** —
  `catalog_resolver.rs:364-376` probes `ALL_TAB_COLS … virtual_column='YES'` and treats empty as
  "no virtual columns"; a principal blind to the table's columns silently passes a gate meant to
  catch function-based virtual columns (user PL/SQL invoked by a plain fetch). Fix BOTH probes with
  the same rule: an empty result from a visibility-filtered dictionary view yields `Unknown`
  (refuse), never `ProvenReadOnly`. All other resolver probes verified fail-closed (§A.10).
- **A1b — fix the session-setup ordering.** Emit `SET TRANSACTION READ ONLY` **after**
  `trusted_session_statements`, re-asserting the backstop immediately after (`connect.rs:306-335`).
  Today, on `protected`/READ_ONLY profiles — the posture the README recommends — trusted setup runs
  inside an open read-only transaction, so table-backed VPD setup is impossible by construction.
  **Test (offline, one line):** `connect.rs:831-857` already asserts the built statement list but uses a
  profile *without* `protected`. Add the same assertion for `protected = true`.
- **A1c — never lose `columns` on an empty result.** Populate `QueryPageBuilder.columns` from statement
  describe metadata at construction rather than from the first row (`query.rs:487-519`).
  **Watch:** golden/snapshot tests may pin `columns: []`. **Test:** unit test, zero pushes.
- **A1d — `oracle_describe` must not fail silently.** Return a structured not-found/not-visible instead
  of `Ok(vec![])` (`intelligence.rs:1349-1367`); handle quoted lower-case identifiers rather than
  blanket `to_ascii_uppercase()`.
- **A1e — surface RLS in `doctor` and in results.** Report VPD policies affecting the configured schema;
  flag policy-protected results so a filtered read is never indistinguishable from an empty table.
  **Why:** this is the fix that survives regardless of which hypothesis (H1/H2) the customer's database
  confirms.
- **A1f — fix the wrong docs.** `robot_docs.rs:412` and `:574` claim login setup "remains on the
  pinned main session"; the code applies session statements on **every** pool connect (§A.2.1,
  re-verified). Correct both sites while in this area.

**Depends on:** none. **Unblocks:** the field's top blocker.
**Diagnostic to ship alongside (no code change needed to run):** the server already has
`SESSION_CONTEXT_SQL` and `SESSION_ROLES_SQL` (`catalog_resolver.rs:31-36`) — expose them via `doctor`
so an operator can diff principal/roles between two clients and settle H1 immediately.

#### A2 [P0] `setup --write` must work, and the state-store lock must explain itself
*Field: P0-1 + P1-13. §A.1.*

**These are one bug.** `FileStore::acquire_service_owner` takes a **process-wide exclusive flock over the
entire state store**; both `setup --write` (`config_ops.rs:325-332`) and the credential CLI
(`client_credentials.rs:319-322`) call it, so neither works while a server runs. The real
`FileStoreError::Locked` ("file-store service lock is already held") is **discarded** by a catch-all
match arm emitting a fixed `ORACLEMCP_SETUP_WRITE_FAILED` (`main.rs:4609-4616`) — which is why `--json`
and `RUST_LOG=debug` added nothing.

- **A2a [P0] — stop discarding the error.** Map `FileStoreError::Locked` to a distinct code
  (e.g. `ORACLEMCP_STATE_STORE_LOCKED`) whose message names the holding service and the remedy. *One
  match arm.* This alone converts an unsolvable mystery into a 10-second fix for the user.
  **Siblings (round-2 sweep, §A.10) — fix all four sites with the same pattern:** the `_ =>` arm at
  `main.rs:4613` collapses five distinct, individually-actionable preview-flow variants
  (`PreviewRequired` / `InvalidPreviewToken` / `PreviewExpired` / `PreviewDraftChanged` /
  `PreviewConfirmationRequired`, `config_ops.rs:60-73`) into the same generic code; the incident trio
  `main.rs:5313/:5375/:5408` reports config-load, disk/IO, and missing-file failures as policy
  "refusals" ("invalid or unsafe bundle" for a path typo). The correct pattern already exists
  in-repo: `client_credential_error_message` (`main.rs:5987-5994`) special-cases `Locked` then
  preserves the inner error text — copy it.
- **A2b [P1] — `clients issue` must print a usable revocation command.** When a service lock is
  detected, emit the **HTTP** form (`/operator/v1/client-credentials/revoke`) rather than a CLI command
  that cannot run (`main.rs:5843`).
- **A2c [P2] — lock granularity.** Per-operation locks, or let the running service serve config and
  credential mutations. **Must include reload**: `clients.json` is read once at open with no watch
  (`client_credentials.rs:339`), so out-of-process mutation would not propagate anyway. Larger change;
  ship only if A2a/A2b land early.

**Test (offline):** start a server, then run `setup --write` and `clients revoke`, and assert a
*specific, actionable* error. No such test exists today.

#### A3 [P0] Flashback must not permanently quarantine the pool
*Field: P0-2. §A.6.1.*

No pre-flight privilege probe exists. A principal without `EXECUTE ON DBMS_FLASHBACK` enters the path,
fails at `DBMS_FLASHBACK.DISABLE` (`PLS-00201`), and the connection is **structurally and permanently**
quarantined (`query.rs:380-399`; pinned by `quarantined_thin_connection_refuses_subsequent_use`). At
READ_ONLY — the recommended posture — this is a remote DoS via `oracle_query{as_of}` **and**
`oracle_diff{scn_a,scn_b}`.

- **A3a** — probe the capability **before** the point of no return; return the existing typed
  `FLASHBACK_CAPABILITY_UNAVAILABLE` without touching session state.
- **A3b** — distinguish "optional feature cleanly refused before any state change" from "teardown could
  not prove the session clean". **Keep the quarantine for the latter** — it is correct fail-closed
  behaviour; a session whose teardown failed may still hold a stale snapshot.
- **A3c** — self-recycle a poisoned session. Today `next_steps` tells clients to "acquire a fresh
  connection", which **no MCP client can do**. **Same missing capability as A4e (§A.6.9): today the
  ONLY recovery is an explicit profile switch — build the recycle path once, use it for both.**

#### A4 [P0] A pooled connection that dies while idle must be replaced
*Field: P0-5. §A.6.3 (corrected twice — read §A.6.3 before implementing).*

oraclemcp does **not** use the driver's pool; it has its own (`oraclemcp-db/src/pool.rs`). That pool has
`ping`/`has_broken` but calls `has_broken` **only on the return path** (`pool.rs:405-420`) — there is
**no validate-on-checkout**, so a connection that died while idle is handed to the next caller and the
first query fails with a raw `Broken pipe (os error 32)`.

- **A4a** — validate (or evict) on **checkout**. Reference shape: the driver's own `_check_connection`
  (`oracledb/src/pool/engine.rs:35-90`, default `ping_interval_secs: 60`).
- **A4b** — retry once on a fresh connection after a transport I/O error. **Round-2 sweep facts
  (§A.10):** the retry machinery already exists but is DEAD (`RetryPolicy`/`is_transient_error`,
  `resilience.rs:17`, zero call sites) — wire it rather than building new; and the server keeps
  THREE hand-rolled, mutually-disagreeing connection-lost lists (`oraclemcp-error/src/lib.rs:450-485`,
  `oraclemcp-db/src/error.rs:413-430`, `resilience.rs:17`) while the driver already exports the
  correct broader set (`CONNECTION_LOST_ORA_CODES` incl. 28/1012/2396/3135, `recovery.rs:546-547`,
  `Error::is_connection_lost()`). **Unify on the driver's classification.** Today ORA-03135, 02396,
  00028, 01012 and raw broken-pipe are all non-retryable `CONNECTION_FAILED`; worse, 02396 + 00028 +
  broken-pipe are also missing from the lease discard-markers (`error.rs:636-651`) so a **dead
  LEASED session is retained and reused** — a live bug beyond messaging. ORA-04068 is misclassified
  entirely (package-state reset: the connection is fine, a plain re-call succeeds; today it says
  `CONNECTION_FAILED` and points at a fresh connection — the wrong remedy).
- **A4c** — `oracle_connection_info` must do a **real round trip** (it returned `connected:true` with
  every liveness field null — mechanism found: `connected: true` is set unconditionally whenever
  `describe()` returns Ok, `dispatch/mod.rs:11063-11073`, even when every liveness field is null);
  `doctor` must not show a green check for a dead pool. **And the startup banner must stop lying:**
  `live-db: true` is a **compile-time constant** (`const LIVE_DB: bool = true`, `main.rs:110`,
  printed at `:4115/:4119` and echoed in capabilities) — a build-capability flag masquerading as
  runtime state. Rename it (`built-with-live-db`) or bind it to the readiness probe.
- **A4d** — stop leaking raw driver errors to callers; map to typed envelopes.
- **ANSWERED (review round 1, §A.6.9): the pinned session is NOT pooled.** It is a single long-lived
  connection with no liveness path, whose only recovery today is an explicit profile switch. A4a fixes
  only the stateless/pool surface — **the field's P0-5 symptom ran on the pinned path.**
- **A4e — pinned-session liveness/reconnect (the primary fix).** Cheap pre-use ping after idle (or
  reconnect on transport I/O error), then transparently reopen: re-apply session setup, re-arm the
  read-only backstop, re-resolve `CURRENT_SCHEMA` (the Arc-N cache), and clear the quarantine through
  the same audited path a profile switch uses (§A.6.9). **Build once, share with A3c.** D5 validates
  both surfaces (kill the pinned session AND an idle pooled one). Infrastructure hint (round-2
  sweep): a background DB pinger already exists and is verified honest — the readiness prober
  (`readiness.rs:33-116`, 5s interval, fail-closed default, drives `/readyz` correctly) — reuse its
  pattern (or its signal) rather than inventing a new liveness loop.

#### A5 [P0] The dashboard must work in a browser
*Field: P0-3. §A.6.2.*

The pairing page emits `Referrer-Policy: no-referrer` (header **and** meta, `http/mod.rs:1260`), so a
form POST carries `Origin: null`, which `dashboard_same_origin_required` refuses at **four** sites
(`http/mod.rs:1392/1400/1413/1421`) — hence `--http-allowed-origin null` does not help. `curl` passed
because it sends no referrer policy. **The tests assert the breaking policy** (`tests_dashboard.rs:25/467/480`).

**Sibling sweep (review round 2) — the breakage is dashboard-WIDE, not pairing-only.**
`with_dashboard_security_headers` (`http/mod.rs:1458-1464`) stamps `referrer-policy: no-referrer` on
**every** dashboard response (12 call sites), and `enforce_dashboard_post_headers`
(`http/mod.rs:1387-1405`) rejects an empty or non-matching `Origin` **before** it ever consults
`sec-fetch-site` (which real browsers send and which would pass). Under the same Fetch-spec
mechanics, therefore, **every browser POST to the authenticated dashboard — Workbench, Reviews,
every action route — fails exactly like pairing did**; the field never observed it only because
P0-3 blocked entry, and `curl` cannot observe it at all. Fixing the pairing page alone would ship a
dashboard that pairs and then still cannot do anything.

- **Option (a) [not chosen — the ruling below selected (c); kept for the decision record]:** switch the **site-wide** `with_dashboard_security_headers` helper to
  `Referrer-Policy: same-origin` (not just the pairing page — the sweep above shows every dashboard
  POST is affected). CSP already carries `form-action 'self'`.
- **Option (b):** accept `Origin: null` when `sec-fetch-site: same-origin` is present (re-order the
  checks in `enforce_dashboard_post_headers` so the modern, spec-reliable signal can vouch), plus the
  loopback + one-time-code rule for the pairing endpoint specifically.
- **OPERATOR RULING (2026-07-20): best engineering option, informed by MCP Agent Mail
  (Dicklesworthstone's Rust implementation). DECIDED — option (c), "fetch-first", which neither (a)
  nor (b) named.** The reference study (repo `mcp_agent_mail_rust`, evidence in the study report)
  showed agent mail never hits `Origin: null` because its dashboard mutates exclusively via
  same-origin `fetch()` + `Content-Type: application/json` — no form-navigation POSTs exist — with
  a layered CSRF check (`mail_csrf_reject_reason`: POST + require `application/json` as the primary
  gate + Origin/Referer-if-present-must-be-same-origin). **The precise mechanism (verified against
  the Fetch spec, correcting one detail of the study):** the Origin header on *non-CORS* requests
  (form navigations) is serialized to `null` under `no-referrer`, while *CORS-mode* requests —
  default-mode `fetch()` — always carry the real Origin regardless of referrer policy. That is
  exactly why the pairing FORM broke and why fetch-based flows don't. Decision:
  1. All mutating dashboard routes require `Content-Type: application/json` (new primary CSRF
     layer, copied from agent mail) and are invoked via **default-mode `fetch()`** (never form
     navigation, never `mode:'same-origin'`/`'no-cors'`) so the real Origin is structurally
     guaranteed.
  2. The **strict Origin requirement stays** — stricter than agent mail, deliberately: our
     dashboard auth is an ambient HttpOnly cookie, theirs is a stateless bearer; ambient
     credentials demand a hard Origin gate. **Literal `Origin: null` is never accepted** (agent
     mail's `origin_is_trusted` also rejects it — an opaque-origin signal a fail-closed tool must
     not trust).
  3. The pairing page (script-free by design): either a tiny same-origin `pairing.js` doing the
     fetch POST (CSP `script-src 'self'` already permits it), or that single page switches to
     `Referrer-Policy: same-origin` so its form POST carries a real Origin — implementer's choice,
     both fail-closed; our pairing URL is deliberately secret-free, so `same-origin` leaks nothing
     (agent mail keeps `no-referrer` only because their token rides the URL — ours does not).
     **v8 PIN: the `Referrer-Policy: same-origin` variant, that one page only.** A `pairing.js`
     would silently abandon the "script-free form" property the README advertises (an
     honesty-in-shipping cost), adds a JS surface to the one page designed not to have one, and
     buys nothing the header change doesn't. The rest of the dashboard keeps `no-referrer` —
     fetch-first (point 1) carries a real Origin regardless of referrer policy.
  4. `Sec-Fetch-Site` stays a positive-only, never-required signal.
  R3's browser lane asserts the whole matrix (form-vs-fetch, pairing, authenticated action POST);
  the security review documents points 1–4 in
  [`docs/dashboard-origin-threat-model-addendum.md`](../dashboard-origin-threat-model-addendum.md).
- Either way, **all four check sites must agree**, and the tests asserting `no-referrer` must be updated
  deliberately with a recorded rationale — not silently.
- **Security review required** (this is an auth surface): document why the chosen option does not weaken
  the fail-closed posture.
- **Test:** a real headless-browser flow (the repo already installs Chromium for the K2 e2e lane) that
  **pairs AND then performs an authenticated dashboard action POST** — pairing alone would have passed
  while the rest of the dashboard stayed broken; `curl` structurally cannot make either assertion.

---

### Workstream B — P1 findings

#### B1 [P1] mTLS / control listener: normalize at enforcement
*Field: P1-10. §A.5.1. **Highest-value P1** — a headline 0.9.0 feature that cannot serve a request.*

Root cause is **normalize-on-validate vs exact-match-on-enforce**: `admin_auth.rs:102-107` compares with
raw `==`, while `client_fingerprints` accepts three spellings and the control-listener precondition
check normalizes both sides. A config with `allowed_subjects = ["mtls:AABB…"]` validates, starts, logs
"control transport enabled", and silently RSTs every request. (My initial Winsock hypothesis was
**refuted** — `restore_accepted_socket_blocking` is correctly applied to all three accept loops.)

- **B1a** — normalize at enforcement for `mtls:` subjects (reuse `normalize_cert_fingerprint`), or
  normalize at load (`main.rs:3352-3357`). **Prefer normalize-at-load** so the stored value and the
  runtime key are identical, and validation cannot pass a value enforcement will reject.
  Round-2 sweep sharpened the anchor: the validator itself normalizes via
  `normalize_sha256_fingerprint` (`oraclemcp-config/src/lib.rs:648-660`) while the build path stores
  trim-only (`main.rs:3355-3360`) — so BOTH case and the `sha256:` prefix diverge, and both are
  default openssl renderings. **The correct symmetric pattern already exists in-repo:**
  `MtlsClientRegistry` normalizes on store AND lookup (`http/config.rs:92/:107`) — copy it. See B15
  for the other config fields with the same asymmetry.
- **B1b** — promote the drop log from `debug!` to `warn!` including the **computed** fingerprint and the
  reason (`serve.rs:238/259`). `computed mtls:sha256:aabb… not in allowed_subjects` is a 30-second fix
  for an operator.
- **B1c** — raise or document the 1-second control ingress budget (`serve.rs:46`, `:649-653`); it is an
  independent second path to the same silent reset and makes `openssl s_client` probing impossible.
- **B1d** — the *main*-listener reset could not be confirmed with the tester. **OPERATOR RULING
  (2026-07-20): the tester/channel is not available at this time** — so the rig answers it
  ourselves: R1's HTTP lane and R3's browser lane exercise the main listener with registered and
  unregistered principals and assert typed 403/429 responses, never silent resets. No silent-drop
  path was found in code (unregistered fingerprint → 403; operator-authority failure → typed
  response); treat the field report's main-listener claim as unconfirmed until R1/R3 prove it.

**Unblocks B4** (online credential revocation is reachable only through this listener).

#### B2 [P1] OAuth: document the contract, widen the diagnostic
*Field: P1-11. §A.5.2. **Not a code defect** — the verifier is correct.*

Two undocumented requirements make it near-unsatisfiable by hand: the HMAC key is the **raw UTF-8 bytes
of a secret *reference*** (`main.rs:3321` — no base64/hex decode, ≥32 chars), and RFC 9068 claims
`iss`/`sub`/`client_id`/`jti`/`iat` are all required (`oauth_rs.rs:155-165`).

- **B2a** — document the full passing contract (header `typ: at+jwt`, the six required claims, `aud`
  string-or-array, `scope` or `scp`, non-empty `required_scopes`).
- **B2b** — widen `error_description` in the `www-authenticate` header (which already exists,
  `http/mod.rs:627-648`) so Malformed / BadSignature / AudienceMismatch / UntrustedIssuer / Expired are
  distinguishable.
- **B2c [P2]** — `oraclemcp doctor oauth --token <jwt>` printing the specific `TokenError`.

#### B3 [P1] stdio init token: make it discoverable
*Field: P1-12. §A.5.3. Pure discoverability failure.*

The path is `params._meta["oraclemcp/initToken"]` — the key contains a **slash**, is unguessable, and has
**zero documentation hits** anywhere. Decisive evidence it was never found: the tester always got
`Missing`, never `Mismatch`.

- Document the exact JSON path; put the literal path into the error text (`init_token.rs:36`); note that
  a non-string value also yields `Missing`.
- **Sibling (review round 2):** the `setup` payload's `secure_stdio` snippet (`main.rs:4447-4451`)
  actively recommends this flow while providing only the server half (`ORACLEMCP_STDIO_TOKEN`) — and
  mainstream MCP clients have no configuration surface for injecting `params._meta` into
  `initialize` at all. The documentation must name which clients CAN supply it and exactly how (or
  ship a thin client-side wrapper that injects it), or the snippet must stop advertising a flow that
  cannot be completed. A security feature that can be enabled but not used reads as protection while
  providing none — the tester's words, now with the snippet as the delivery vector.

#### B4 [P1] Credential lifecycle without downtime
*Field: P1-13. §A.5.4. **Premise partly refuted** — the online route already exists.*

`/operator/v1/client-credentials/{list,rotate,revoke}` (`operator.rs:691-693`) is already implemented and
already tears down live sessions on mutation. It was unreachable **only because B1 blocked the control
listener**. → **Fix B1, document the endpoints, and A2b prints the right command.** No new machinery.

#### B5 [P1] Driver: terminal errors must not be retried — **verify, then close**
*Field: P1-3. §A.6.5. **Believed already closed** by `880134e`, now on driver `main`.*

That commit made the failover boundary **stage-aware**: the post-configuration error type "deliberately
has no configuration/auth/wallet variants", and all deterministic TLS configuration is validated before
any transport attempt, so terminal errors are *structurally* unable to enter the retry loop.

- **Action:** reproduce the field symptom locally (§4.D TCPS lane) — a cert `UnknownIssuer` under stock
  `retry_count=20` must now surface in ~1s, not as `call timeout of 20000 ms exceeded`. Then **close
  driver bead `rust-oracledb-4sfc`** with landed evidence. Note (review round 1): `4sfc` is currently
  `deferred`, not closed, and an **uncommitted** close-evidence file for it already sits in the driver
  working tree — reconcile via Z4 rather than re-authoring evidence.
- **Do not re-implement.** This is the one finding where the plan's scope *shrinks*.

#### B6 [P1] Driver: trust the wallet **and** the platform roots
*Field: P1-2. §A.6.8 — **grounded and confirmed in review round 1: a real reference-parity bug.
Implement directly** (the "ground it first" step is done; full evidence incl. the reference's own
behavior is in §A.6.8).*

- **B6a** — union the trust anchors in `build_client_config` (`tls.rs:297-300`): seed with system
  roots, extend with wallet CAs, keep the empty-set guard — the wallet stays authoritative (always
  included), public-root validation is restored, matching python-oracledb 4.0.1's
  `create_default_context()` + `load_verify_locations()` exactly. Lives in the deterministic pre-dial
  prepare stage (`prepare_tls_handshake`), so trust failures remain typed config errors, never
  timeouts.
- **B6b — RULING RECORDED (2026-07-20, "best engineering decision" delegated): adopt
  `rustls-native-certs`** for true platform-store parity on Linux/macOS/Windows (the reference loads
  the platform store everywhere via `create_default_context()`), keep the existing Unix bundle-file
  reads as fallback, and honor `SSL_CERT_FILE`/`SSL_CERT_DIR` overrides (reference parity AND the
  hermetic-test seam D6 needs). New dependency goes through the cargo-deny review like any other.
  Rationale: a driver whose no-wallet TCPS path has ZERO trust anchors on Windows is a worse defect
  than one small, ecosystem-standard dependency.
- **B6c — OPERATOR RULING (2026-07-20): strict python-oracledb parity, NO `trust_store` knob.**
  System roots are always unioned with wallet CAs, exactly like the reference; no wallet-only mode
  is added. Anyone needing a private-CA-only posture controls the OS trust store, as they would with
  the reference client.
- **Regression:** F4 (a real publicly-signed ADB endpoint — the field's actual failure) + a D6 local
  lane with a synthetic "public" root injected via B6b's override. Today's lane only exercises the
  self-signed-ADB-CA chain.

#### B7 [P1] Session teardown: stop leaking session records
*Field: P1-8. §A.6.6. Confirmed: **no teardown counterpart exists**.*

Three connect-side hooks (`login_statements`, `login_script`, `trusted_session_statements`) have no
logoff counterpart anywhere in the codebase.

- **B7a** — add `logoff_statements` / `session_release_statements` executed before a pooled session is
  released and before process exit (including SIGTERM).
- **B7c (round-2 sweep — the structural root cause, do this FIRST):** the `OracleConnection` trait
  has **no close/logoff/disconnect method at all** (`connection.rs:934-1221`; zero close call sites
  across oraclemcp-db), so a clean Oracle logoff is impossible through the abstraction. Confirmed
  consequences: `oracle_switch_profile` drops the old pinned conn + stateless pool by move-assign
  (`dispatch/mod.rs:11802-11803`, no logoff); SIGTERM/clean shutdown only stops the pinger
  (`main.rs:3886/:4039`) and drops everything (`OraclePool` has no Drop/close/drain). Add
  `close()` to the trait (delegating to the driver's verified `Connection::close` → close_notify
  path, §A.6.11) and call it at: profile switch, process exit/SIGTERM, and pool eviction. B7a's
  hooks then run inside it.
- **B7b** — ensure a **clean logical Oracle logoff** so `AFTER LOGOFF` triggers fire. **Driver half
  RESOLVED in review round 1 (§A.6.11): close_notify IS sent on the normal close path**, deliberately
  skipped only when the peer already hard-closed — `s0se` needs only its evidence commit + guarded
  close (Z4). The remaining investigation is **entirely server-side**: confirm oraclemcp actually
  calls `Connection::close` on the pinned AND the pooled connections at clean exit **and** on SIGTERM
  (the field saw leaks on both); D7's `AFTER LOGOFF` lane proves it either way.

#### B8 [P1] Audit: doctor must stop lying
*Field: P1-9. §A.6.7. **The audit design is correct and fail-closed** — doctor misreports it.*

No key + read-only-everywhere ⇒ `Ok(None)`, no auditor (and if writes *are* reachable without a key the
server **refuses to start**). Nothing that can mutate is silently unaudited.

- **B8a [P0-for-honesty]** — doctor must report `audit: DISABLED (no signing key configured; profile is
  read-only everywhere reachable)` instead of a check-mark plus a path for an auditor that was never
  constructed (`crates/oraclemcp-core/src/doctor.rs` — layout fields `:396-404`; the audit logic at
  `:781-868` reasons about file paths and legacy→XDG migration only and **never calls `build_auditor`**;
  path + line spans re-verified in review round 1).
- **B8b** — document a concrete `[audit]` block; there is no example anywhere in the README.
- **B8c — RULING RECORDED (2026-07-20, "best engineering decision for agents AND humans"
  delegated): YES — an unsigned local refusal/security-event trail is ON by default** whenever the
  signed audit chain is off (no key + read-only-everywhere): a separate `refusals.jsonl` (never the
  `audit.jsonl` name), first record and doctor both stating plainly UNSIGNED — NOT TAMPER-EVIDENT,
  with an `[audit] unsigned_refusal_log = false` opt-out. Doctor reports
  `audit: DISABLED · unsigned refusal trail: ACTIVE at <path>`. Rationale: the field's 15 blocked
  statements were exactly the evidence an operator wanted and got nothing; agents get the same
  signal via the refusal corpus. Honest labeling keeps it from masquerading as the signed chain.
  **Reference study CONFIRMED the posture** (agent mail's always-on durable record — the git-backed
  archive — is entirely unsigned; cryptographic signing exists only at its optional export/share
  boundary; observability is never gated on a key). Our two refinements stand: honest per-entry
  authenticity labeling, and the signed chain remains the higher tier when a key exists — the
  unsigned log is the floor, not a replacement.
- **B8d — the doctor asserts-vs-observes sweep (round 2, §A.10).** Beyond check 13: **check 12
  (`check_call_timeout`, `doctor.rs:2428-2524`) reports keepalive/timeouts as Pass derived purely
  from CONFIG**, while doctor's own check 15 (`:2532-2537`) states the driver leaves
  `expire_time`/keepalive "parsed but not yet wired" — a green the runtime contradicts. **First
  verify which side is stale**: driver GH#14 closed in 0.8.4, so check 15's claim may itself be
  outdated (the izk5 class); then either make check 12 observe (probe the socket option / driver
  state) or mark it config-derived. Also: check 13 (`check_state_layout`, layout fields at
  `doctor.rs:396-404`, audit-path logic at `:781-868` — the same site B8a targets) asserts
  audit-in-place from paths; checks 1 and 2 are Pass from a compile flag
  and `Path::is_dir()` respectively — reword so a ✓ never reads as more than what was observed.
  Checks verified genuinely observing: 3, 10, 11, 14, 15.

#### B9 [P1] Proxy-auth syntax: accept or explain `user[schema]` — BOTH repos
*Field: P1-1. §A.6.4. Confirmed absent in the server — and (review round 1) **confirmed a driver
parity gap too**: python-oracledb desugars the bracket form inside `ConnectParams` itself
(`impl/base/connect_params.pyx:511-516`, documented at `connect_params.py:121-123`), while our driver
only offers the explicit `with_proxy_user` API (`crates/oracledb/src/lib.rs:2488`; wire support
exists, `oracledb-protocol/src/thin/auth.rs:204-235`) and performs no bracket parsing.*

Every Oracle client accepts `username = 'user[schema]'`; oraclemcp passes it through literally →
`ORA-01017`, indistinguishable from a wrong password. All 13 of the operator's real profiles used it, so
**nothing authenticated out of the box**.

- **B9a (server)** — detect `^(.+)\[(.+)\]$` at config load and either auto-desugar into
  `[profiles.proxy_auth]` (keeps validation + redaction typed) or fail fast naming the correct shape.
- **B9b (driver, parity)** — desugar `user[target]` in the driver's username handling exactly like
  the reference, keeping the explicit API authoritative when both are supplied (explicit wins,
  conflict = typed config error). This stands on its own for library users regardless of B9a.
- Rider (the round's related LOW finding): `setup`'s output never shows how to configure proxy auth
  at all — add the `[profiles.proxy_auth]` shape to the setup templates.

#### B10 [P1] The misleading-message sweep
*The round's dominant theme, and per the tester the highest value-per-line change available.*

Beyond the individually-tracked items, sweep for "correct behaviour reported through a misleading
message":
- a typo'd table/column reported as `FORBIDDEN_STATEMENT` "could not prove this statement safe" instead
  of "relation X does not exist or is not visible to this principal" (**P1-4**) — agents conclude they
  are policy-blocked and try to escalate;
- `ORA-31603` surfaced as `CONNECTION_FAILED`;
- refusals that name no sanctioned alternative (**P1-6**): all raw-SQL view access is refused at
  READ_ONLY, but `next_steps` never mentions `oracle_schema_inspect`, `oracle_list_schemas`,
  `oracle_db_health`, `oracle_capabilities`. **Turn a wall into a redirect.** (Refusing raw-SQL view
  access at READ_ONLY is itself by design — views can hide unproven function calls — and stays; the
  fix here is the message, deliberately.)
- **P1-7** — `setup`'s HTTP onboarding line omits the mandatory auth header: the printed
  `claude mcp add … --transport http <url>` cannot connect while the same output block issues the
  bearer two lines above. Source site found in review round 2: the `claude_mcp_add` array in the
  setup payload (`main.rs:4456`) carries no `--header`. Emit
  `--header "Authorization: Bearer <token>"`, and add a `client_command`
  field to `clients issue --json` beside the existing `revocation_command`/`rotation_command`.
  **Sibling in the same payload:** the `secure_stdio` snippet (`main.rs:4447-4451`) configures the
  SERVER side of the init token and offers no client-side mechanism whatsoever (see B3) — the
  printed "secure" path cannot be completed by a mainstream MCP client as written. Fix both under
  one rule, pinned by fixture **C9**: *every printed onboarding snippet must work verbatim under the
  auth mode it claims to configure.*
- **one error grammar (unnumbered P2)** — under HTTP, `oracle_connection_info` returned bare prose
  ("Unable to connect…") with no envelope, no `error_class`, no `next_steps` — evidently from the
  transport layer — while sibling tool calls in the same batch succeeded; the tool the server
  nominates for diagnosing connection trouble was the only thing that failed. Error shapes must be
  uniform across transport and tool layers (ties to A4c).
- the transient-driver-error mis-remediation (B13b) rides this sweep.

#### B11 [P1] The orientation trio must be capped: `oracle_orient`, `oracle_capabilities`, `get_schema`
*Field: P1-5 plus the round's unnumbered "P1-x". The tester's framing is systemic and worth keeping
verbatim in spirit: **the three tools an agent reaches for first to orient itself are the three
largest responses in the product.***

- `oracle_orient` returns ~344 KB (~86k tokens) by default with **no `max_rows`/byte cap**, mostly
  INDEX rows (`fleet=true` multiplies it).
- `oracle_capabilities` is **58.5 KB** — and the server's own `instructions` field tells every fresh
  agent to call it first, so the mandated first action can consume a fifth of a small context window.
- `get_schema` ≈ 67 KB with no arguments.

Apply the capping `oracle_query` already has; default the schema projection to TABLE/VIEW/PACKAGE;
return a truncation marker plus a cursor; give `capabilities` a compact default with a `detail_level`
escape hatch. The fix pattern already exists in-product: `oracle_search_objects`'
`detail_level:"names"` is what the field's subagent praised as "the right first move".
**v8 rider:** the `oracle_capabilities` compact default changes the response of the **mandated
first call** every fresh agent makes (the server's own `instructions` field sends them there) —
release-note it alongside A1a's blast-radius note, and keep `detail_level:"full"` returning the
pre-0.10.0 shape so pinned clients have a one-flag escape.

**Round-2 caps matrix (§A.10) — extend the same treatment to the uncapped metadata tools:**
`oracle_compile_errors` is UNCAPPED and schema-wide when `name` is omitted
(`intelligence.rs:1438-1441`); `oracle_describe`'s constraints join is UNCAPPED
(`intelligence.rs:1355-1394`); `oracle_plscope_inspect` returns full identifier/statement arrays
uncapped (`plscope.rs:138-139/:167-168`); and `oracle_get_ddl` is **silently LOSSY** — a hard
4000-byte `DBMS_LOB.SUBSTR` slice (`intelligence.rs:1413-1414`) truncates large DDL (any partitioned
table) with **no truncation flag and no continuation** — silent data loss on a metadata tool, the
worst variant of this class. The `max_result_bytes` backstop covers only the query/sample data path
(`dispatch/mod.rs:3227/:3495`). Verified already capped: `search_objects` (100 default, ≤5000),
`db_health` (bounded by construction), `get_source`/`search_source` (their knobs).

#### B12 [P1] PL/SQL purity: make read-only functions reachable
*Field: P1-14. §A.3. Fully by design today.*

`routine_purity` defaults to `Unknown` for **every** routine; Oracle purity metadata is **never**
consulted; there is no allowlist or knob. A signed custom tool wrapping a pure function is rejected on
classification grounds **and takes the server down** (`main.rs:3515-3522` → `ExitCode::from(2)`).

- **B12a** — operator-declared **pure-function allowlist** feeding a `SideEffectOracle` on
  `DEFAULT_CLASSIFIER`. This is the seam's intended use and needs no engine. **The guard stays
  tighten-only: an allowlist is operator authority, never an automatic inference.**
- **B12b** — pass the profile's **real ceiling** to custom-tool loading (`main.rs:1349/1357/1366`
  hard-code `ReadOnly`).
- **B12c — RULING RECORDED (2026-07-20; operator leaned skip-and-warn, reasoning requested and
  recorded): default becomes SKIP-AND-WARN, uniformly.** An invalid custom tool is not loaded (that
  alone is fail-closed — skipping never grants anything); the server keeps serving. Loudness is the
  contract: a prominent stderr warning per skipped tool, doctor reports each skipped tool + reason
  as a warn/fail, `oracle_capabilities` carries a `skipped_custom_tools` list so AGENTS see it too,
  and signature-verification failures are additionally recorded as security events on the B8c trail
  (tamper evidence must never be silent). `--strict-custom-tools` restores fail-fast for operators
  who want a bad file to stop the world. Rationale: one malformed tool file taking down the whole
  server for every client (the field outage) is an availability failure of a non-critical component;
  the guard's tighten-only philosophy is untouched because a skipped tool grants nothing.
  **Reference study CONFIRMED the shape** (agent mail: per-item collect-and-continue preflight,
  configurable Warn/Abort/AutoRepair posture defaulting to Warn, an invalid posture value itself
  failing safe-and-alive with a warning, runtime bad input → structured error, server stays up).
  One deliberate divergence, kept: agent mail warns-and-continues even on genuine security
  boundaries; we stay fail-fast for security-critical invariants — skip-and-warn applies to
  config-quality failures only.
- **B12d [P2]** — consult Oracle purity metadata (`DETERMINISTIC`, `ALL_PROCEDURES`) as *evidence*
  feeding the oracle. Design carefully: `DETERMINISTIC` is a developer assertion, not a proof.

#### B13 [P1] Driver: transient "unknown TTC message type 129" mid-session
*Field: unnumbered body-level P1 from the round's independent subagent. Flagged by the tester as **the
same error family as Round 1's P0 (`type 11`)** — that class is not fully eliminated; it now appears
transiently mid-session rather than at connect. Added in review round 1; absent from plan v1.*

A metadata read failed with `CONNECTION_FAILED: query: unknown TTC message type 129 at position 35`;
the **identical call succeeded on retry** with nothing changed. Three defects in one event: a
transient wire condition, misclassified as durable (`CONNECTION_FAILED` implies a dead connection and
nothing suggests retrying), with wire internals leaked into agent-facing text, and a suggested remedy
(`oracle_connection_info`) that itself failed (see B10's grammar bullet).

- **B13a (driver)** — investigate: which server message can legitimately appear mid-stream carrying
  type 129 (out-of-band break/marker handling? an unconsumed trailer?); attempt a repro in the D lanes
  (long-lived session + concurrent metadata reads across all three container generations); capture
  with `ORACLEDB_TRACE_QUERY=1`; fix the decode path or classify the condition as retryable at the
  protocol layer. **Reference cross-check (review round 1):** python-oracledb also hard-errors on an
  unknown protocol message type (`errors.py:811`, "internal error: unknown protocol message type"),
  so the target is our **desync source** (residual bytes read as a message type), not graceful
  handling of 129 — diff our dispatch against the reference's messages/base.pyx at the same read
  position. If it cannot be reproduced locally, record that honestly and keep the bead open —
  do not close on "cannot reproduce" alone (constitution #2). **v8 no-stall rider (operator
  ruling 2026-07-21, §Z2 clarification):** if still unreproduced after the D-lane attempts by RC
  time, the open investigation bead converts to a **pre-authorized operator deferral** and is NOT
  a publish-sink ancestor (§10) — an unreproducible transient must not stall the tag. B13b (the
  server-side classification/envelope fix) is independent of the repro and stays in-train.
- **B13b (server)** — independent of the driver outcome, the server must classify this as
  transient/retryable, retry once on a fresh round trip (rides A4b), and map it to a typed envelope
  instead of leaking `unknown TTC message type N` (rides A4d).

#### B14 [P1] DRCP `purity=reuse`: clear-before-set, and delete the dead lease subsystem
*Round-2 sweep (§A.10). Security-relevant: cross-tenant identity bleed on pooled server sessions.
Not a field finding — the field never exercised DRCP — which is exactly why it belongs here.*

With `[profiles.drcp] purity = "reuse"` (the DEFAULT — `drcp.rs:38-45`, `profile.rs:257-258`), the
server session handed back may still carry a prior client's `CLIENT_IDENTIFIER` / `MODULE` /
app-context. B14a moved the required clear-before-set sequence into the wired
`apply_session_identity` connection path. B14b then removed the unregistered,
test-only session subsystem, leaving that connection
path as the only identity setup mechanism.

- **B14a** — clear-before-set unconditionally on every connect; `CLIENT_IDENTIFIER` is a canonical
  VPD key.
- **B14b — completed** — removed the unregistered, test-only lease subsystem after confirming it
  had no dispatch or registry entry.
- **Test:** D-lane DRCP fixture — two profiles alternating on a pooled server session, asserting no
  identity/context bleed.

#### B15 [P1] HTTP-guard normalization: the rest of the B1 class
*Round-2 sweep (§A.10). Same defect shape as B1 (validate-side and enforce-side disagree), different
fields — all shipping today.*

- **B15a `allowed_origins`** — the allowlist branch compares the FULL origin string exactly
  (`http_guard.rs:125`) while a normalization helper (`origin_authority`, `:91-96`) exists but is
  applied **only to the loopback branch**. Browsers send lowercase, no-default-port, no-trailing-slash
  serialized origins — so operator values like an uppercase host, a trailing slash, or an explicit
  `:443` validate and never match. Normalize both sides with the existing helper.
- **B15b `allowed_hosts`** — loopback path lowercases (`http_guard.rs:85`) but the operator allowlist
  compares case-sensitively (`:137`); `Host` is case-insensitive per RFC. Casefold at comparison.
- **B15c** — weak sibling everywhere: `validate_non_empty_list`/`validate_required_string`
  (`oraclemcp-config/src/lib.rs:883-901`) trim for the emptiness CHECK but store verbatim, so
  whitespace survives into exact-match enforcement across all list fields. Trim on store.
- Verified SAFE in the same sweep (do not churn): issuer/aud exact-match (RFC-correct), scopes
  (case-sensitive per RFC 6749), client_id/bearer (machine-generated, constant-time), profile-name
  lookups (symmetric, fail-closed).

#### B16 [P1] OCI IAM token lifecycle: wire the driver's `TokenSource` seam; stop embedding a one-shot token
*Round-2/3 sweep (§A.10 S15). The field never tested IAM auth (its own auth matrix marks it "not
tested"), so this class was structurally invisible to the round — exactly the kind of sibling the
sweep exists to catch.*

The reference refreshes expired tokens automatically: `access_token` accepts `str | 2-tuple |
Callable`, and the callable is **re-invoked whenever the stored token is expired**
(`connect_params.py:64/:140`; `impl/base/connect_params.pyx:227-233` — expired + no callable ⇒
error). Our **driver has full parity machinery already shipped**: static `with_access_token`
(`lib.rs:2308`), PoP `with_access_token_and_key` (`:2326`), and a pluggable **`TokenSource`** trait
with async `get_token` + typed redacted `Error::TokenSource` (`lib.rs:1805/:1379-1383`).

**The server bypasses the seam:** `inject_iam_token` runs once during `ResolvedProfile` construction
(`main.rs:870-880`) and embeds a static token string into the connect options; the pool manager
holds those options for its whole lifetime (`pool.rs:42`), so **every later pool-member open,
discarded-member replacement, or A4e reconnect reuses the stale token** — OCI database tokens live
~1 hour, after which every new physical connection fails auth (an ORA-01017-class error with no
hint the token expired). Compounding honesty defect: `doctor.rs:2394-2395` prints "it is re-read on
every connect" — true of the resolver's *intent* (`iam_token.rs:706` "re-read fresh on every
connect"), false of the wiring — the S12 assert-vs-observe class again.

- **B16a** — implement `TokenSource` over the existing hardened resolver (`iam_token.rs`
  env/file/exec sources, keeping the exec sandboxing/caps) and pass it through the driver seam
  instead of a one-shot injected string; delete the one-shot path.
- **B16b** — fix the doctor text (or better: make it observe — report the token source *kind* and
  when it was last successfully invoked).
- **B16c (driver)** — the `TokenSource` docs advertise refresh-on-rejection, but the implementation
  makes a single `get_token` call per connect with no expiry inspection and no retry-on-auth-reject
  (`lib.rs:2902-2907`). Implement the advertised behavior or correct the docs — the seam's contract
  must be honest before the server builds on it.
- **Test:** offline — a `token_exec` source backed by a counter file, assert the source is invoked
  per physical connect (pool grow + reconnect), not once; live acceptance of a rotated token needs
  ADB → rides F2.

---

### Workstream P — the P2 tail, enumerated [P2 — ship-if-clean]
*Plan v1's traceability row said "P2-1..P2-13 → B10 / G-tail", which pointed at the quarantined
report — a self-containedness violation. Enumerated here, scrubbed. **P2-2 ("the startup banner never
confirms TLS") was retracted by the tester — no action, listed so nobody chases it.** Dispositions:
[fix] code, [doc] documentation, [verify] verify-then-close.*

- **P2-1 [doc]** — Claude Code over HTTPS with a self-signed/private CA needs `NODE_EXTRA_CA_CERTS`;
  the failure is a bare "Failed to connect". One README line under the TLS section.
- **P2-3 [fix]** — `current_database` redacts 19 fields **including `current_schema` and
  `service_name`** — the answers the tool exists to give. Field cost: the subagent had to pass
  `owner` explicitly on every single call because "defaults to current schema when available" was
  never available. Add a loopback/stdio opt-out or a narrower default redaction set; keep
  redaction-by-default for remote transports.
- **P2-4 [verify]** — default `use_sni = true` rejected Oracle's ADB SNI routing token (the
  service-form token with underscores and a numeric version suffix) as an invalid rustls DNS name,
  failing a stock ADB wallet out of the box. **The driver fix already shipped in 0.8.4** — §A.6.10
  has the sites and the two open leads (carve-out predicate; the server's wallet-implies-SNI
  default). Verify-then-close in D6/F, not new machinery.
- **P2-5 [fix]** — config-load failures are reported under doctor's "Connectivity" check, sending
  users to debug firewalls/DSNs. File them under a config check.
- **P2-6 [doc/fix]** — `--allow-no-auth` help says "stdio … development only" but it also gates
  HTTP. Make the help text match the behavior.
- **P2-7 [doc]** — one `serve` instance per state directory at any port: reasonable, but
  undocumented; "one profile per box" surprises operators. Document it where `serve` is introduced.
- **P2-8 [doc/fix]** — `serve` opens **2** Oracle sessions while reporting
  `connection_strategy: single_session`. Not a leak (proven in the field) — it is the pinned +
  stateless pair (§A.6.9). Document the expected session footprint, point at the pool knob, and make
  the reported strategy honest.
- **P2-9 [fix]** — stale-lock reclaim leaks a raw `kill: (<pid>): No such process` line to stderr.
  Capture it.
- **P2-10 [fix]** — `setup --discover` prints a "fastest path" that non-interactive runs cannot use
  without `--discover-tns`/`--yes` (say so in the printed line); `sh install.sh` dies under dash with
  a cryptic `set -o pipefail` error — detect a non-bash interpreter and say "run with bash".
- **P2-11 [fix]** — `oracle_semantic_search`'s documented typed `requires_23ai` refusal is masked by
  the resolver's generic `FORBIDDEN_STATEMENT` on pre-23ai servers. Let the typed refusal through.
- **P2-12 [doc]** — `base=` does not cap a child at its parent's `max_level`, and a README sentence
  reads as though it does; a reader could build a READ_ONLY base as a safety net that isn't one.
  Probably intended (config is operator-owned): **clarify the doc; do NOT silently change inheritance
  semantics** — that would be a behavior change needing its own review.
- **P2-13 [fix]** — `sign-tool` says "copy each signature into its matching `[[tool]]` block", but
  appending at end-of-file silently lands it inside a trailing `[[tool.params]]` block. Add
  `--write`/`--in-place`.
- **P-U1 [fix]** (unnumbered) — `oracle_search_source` has `max_rows` but no
  `max_line_chars`/`context_chars`; source with 2000+-character generated lines produced ~25 KB of
  noise for one search. Add a line-length cap — for a source-grep tool it is the most obvious missing
  parameter.
- **P-U2 [fix]** (unnumbered) — `oracle_get_source` cannot fetch a line range although
  `oracle_search_source` returns exact line numbers; `max_chars` truncates from the top, so reading a
  function deep in a large package body means guessing a byte budget. Add `from_line`/`to_line` —
  the two tools are designed to be used together.
- **P-U3 [fix]** (unnumbered, MEDIUM in the round) — the dashboard 403 is bare text while every other
  error is a structured JSON envelope. Unify; rides A5's dashboard work.
- **P-U4 [verify]** (unnumbered) — legacy-3DES `ewallet.pem` (`pbeWithSHA1And3-KeyTripleDES-CBC`)
  still reported `KeyDecrypt` in the field, although driver 0.8.4's release scope included legacy-3DES
  decrypt with committed synthetic fixtures. Cosmetic in the field (the `cwallet.sso` auto-login
  fallthrough works and is the intended path) but a truth-in-shipping question: run the committed
  3DES fixture through the **server's** wallet path (doctor + connect), not only the driver's own
  unit test — either the driver fixture is self-consistent-but-unreachable (§3's class, again) or the
  server's wallet diagnostics bypass the driver's decryptor. §A.6.12. D6 rider.
- **P-U5 [doc]** (sibling sweep, review round 2) — the wallet support table is STALE and
  **understates** shipped behavior: `README.md:994`/`:1221` and `docs/configuration.md:421` claim
  `cwallet.sso` is "recognized and reported with structured wallet diagnostics" (diagnostic-only),
  but `oraclemcp-db/src/oci.rs` treats it as a first-class working mode (`mode: "cwallet.sso"`,
  `oci.rs:340`; required-files probe `:33`) and the field used `cwallet.sso` as **the working OCI
  path**. Pre-0.8.4 wording — refresh the truth table (and re-check `ewallet.p12`'s row while
  there).
- **P-U6 [fix/doc]** (rig design review) — no `Strict-Transport-Security` header is emitted
  anywhere. When native TLS is active on a **non-loopback** listener, emit HSTS (never on loopback
  HTTP — pinning localhost breaks local dev). One header, standard posture.

---

### Workstream C — Wire-contract fixtures (the anti-recurrence pillar)
*[P0 for the release's credibility. Cheap and mostly offline — C1–C3, C5–C8 need no database; C4
(headless browser) and C9 (snippet-truth) run against a live `serve` and are implemented by the rig's
R3/R1 lanes. §5 ordering rule 1 ("failing fixture first") applies to the offline members; C4/C9's
"before" proof is the rig demonstrating the field failure against today's `main`.]*

**Rule:** where a contract crosses a process or wire boundary, at least one test must use a **literal,
externally-authored** value committed as an opaque string — never a value produced by the same helper
the server consumes.

- **C1** — **OAuth**: commit a literal JWT + literal secret generated **once by an external tool**
  (jwt.io / PyJWT), asserting acceptance; plus negatives (wrong `typ`, missing `client_id`, missing
  `jti`, base64'd key) each asserting a *distinct* error.
- **C2** — **stdio init token**: a raw literal `initialize` JSON frame containing
  `params._meta["oraclemcp/initToken"]`, parsed from a string constant, not built with the key constant.
- **C3** — **mTLS allow-list**: an operator-style hand-written `allowed_subjects` entry (uppercase, bare
  hex, `sha256:`-prefixed) asserted to match a real certificate's runtime principal key — the exact axis
  B1 breaks on. Plus a unit test that all three accepted spellings authorize.
- **C4** — **dashboard**: a real headless-browser flow (Chromium already available in CI) that pairs
  **and then performs an authenticated dashboard action POST**, asserting 200s rather than resets —
  the assertions `curl` structurally cannot make, covering both the pairing instance (P0-3) and the
  dashboard-wide sibling (§4.A5 sweep note).
- **C5** — **session-setup ordering**: assert the built statement list for **each profile posture**
  (`protected = true` and `false`), catching A1b offline.
- **C6** — **CLI vs running server**: with a server running, assert `setup --write` and `clients revoke`
  produce specific actionable errors (catches A2a).
- **C7** — **`QueryPageBuilder` with zero rows** asserts `columns` is populated (catches A1c).
- **C8** — **blind-catalog mock**: the policy probe AND the virtual-column probe each return empty
  *because of privilege*; assert refusal, not pass-through, for both (catches A1a and its
  virtual-column twin).
- **C9** — **snippet truth**: every onboarding snippet `setup` prints (`claude_mcp_json`,
  `codex_config_toml`, `secure_stdio`, `http_client_credentials.claude_mcp_add` — `main.rs:4434-4459`)
  is executed **verbatim** against a live server configured with the auth mode the snippet claims,
  asserting a completed MCP `initialize` (catches P1-7 and its `secure_stdio` sibling; the class rule:
  a printed command is a contract, and today none of them is ever executed by any test).

**Acceptance:** C1–C9 all fail against today's `main` and pass after Workstreams A/B. That two-sided
proof is the deliverable — a fixture that never failed proves nothing.

---

### Workstream D — Local live-test environment
*[P0. Depends on: nothing. §1.3 shows most of it already exists.]*

**Purpose:** reproduce the field's finding classes here, so a production round confirms rather than
discovers. **Deliberately smaller than first imagined** — the grounding showed most findings are
catchable offline (Workstream C). The live lane is needed for a specific short list.

- **D1 — one-command harness** over the already-present containers (`xe18`, `xe21`, `free23`): up/down,
  readiness wait, deterministic teardown, seeded fixture schema. Reuse the existing live-test plumbing;
  do not invent a parallel one.
- **D2 — seeded capability fixtures** covering the surface the field exercised: typed decode, LOB, REF
  CURSOR, SODA (23ai), XA/TPC, VECTOR (23ai), DBMS_OUTPUT, edition, statement cache.
- **D3 — a VPD/RLS fixture** (the field's top blocker): a schema with a policy-protected table, a
  principal that **can** see `ALL_POLICIES` and one that **cannot**, and a synonym over a protected base
  object. This is what settles §A.2.7's H1 vs H2 and validates A1a/A1e.
- **D4 — a privilege-matrix fixture**: a principal **without** `EXECUTE ON DBMS_FLASHBACK` (validates
  A3), and one without catalog visibility (validates A1a).
- **D5 — an idle-connection lane**: hold a pooled connection, kill it server-side, and assert recovery
  (validates A4, and settles whether the pinned session is pooled).
- **D6 — a local TCPS/TLS lane with synthetic wallets.** The driver already has synthetic-wallet + local
  rustls TCPS machinery — **reuse it**. Validates B5 (P1-3 symptom) and B6.
- **D7 — a session-lifecycle lane**: an `AFTER LOGOFF` trigger writing to a table, asserting sessions
  close logically (validates B7 and driver `s0se`).
- **D8 — doctor-style preflight**: refuse to run with a clear message if Docker/images/ports are missing.
- **D9 — realistic schema + data (rig rider). RULING RECORDED (2026-07-20, "best engineering
  decision" delegated): VENDOR it** — vendor `oracle-samples/db-sample-schemas`
  (**verified MIT-licensed** — pin the upstream commit, copy its LICENSE; HR/CO/SH) and layer the
  synthetic governance fixtures on top, since the sample schemas ship **no** VPD/RLS: D3's
  policy-protected table + synonym-over-protected-base + the two catalog-visibility principals, the
  proxy `CONNECT THROUGH` pair (`bootstrap_live_schema.sh:60-63` already has one), and D7's
  `AFTER LOGOFF` trigger. Field-shaped data without a byte of customer data (constitution #9).
- **D10 — idle-kill against the REAL pool (rig rider)**: the kill-session mechanics exist
  (`bootstrap_live_schema.sh:41-43`); wire them against the server's own checkout path
  (`pool.rs:471-483`) AND the pinned session, asserting replace-on-checkout / reconnect instead of
  silent reuse — validates A4a/A4e end to end.
- **D11 [P1] — the 19c version-branch parity ledger + 19c-caps offline lanes (operator question,
  2026-07-20: "any way except live testing?"). Yes — three ways, two of them offline:**
  1. **The ledger (subagent sweep, driver repo).** The vendored reference encodes every
     version-dependent behavior as explicit branches: server-version comparisons, capability
     constants (`TNS_CCAP_*`/`TNS_RCAP_*`) and their gating versions, feature floors (JSON 21c;
     fast-auth / END_OF_RESPONSE / VECTOR / OSON-improvements 23ai; OOB; sessionless TPC …).
     Sweep `reference/python-oracledb/src/oracledb/impl/thin/` for EVERY such branch and produce
     `docs/PARITY_VERSIONS.md`: {reference `file:line`, version/cap gate, behavior on each side of
     the gate, our driver's `file:line` or **MISSING**, disposition}. Every divergence becomes a
     fix bead or a documented deviation — this is the "sniff out the if/elses" the field's 19c gap
     demands, and it needs no server at all.
  2. **19c-caps offline lanes.** Derive a **19c capability mask** from the ledger and drive it
     through machinery the driver already has: `.tns-cassette` record/replay exchanges shaped to a
     19c handshake, and the differential fuzz oracle (our decoder vs the reference's on identical
     bytes) fed 19c-caps-profile corpora. Proves our branch SELECTION matches the reference's for a
     19c-shaped server. Honest bound, stated: cassettes prove decode/branch behavior, not full
     live-session semantics.
  3. **Live 19c may be free after all** — see the F2 rider below (Always-Free ADB version choice).
  **Parity-claim scope, stated honestly:** the existing headline claim (2462/2578 of the
  reference's own suite) is behavioral parity **on 23ai**; version confidence today rests on the
  4-generation matrix (11-inverted/18/21/23) bracketing 19c. The ledger converts that bracket
  argument into an enumerated, per-branch proof — which is the strongest 19c statement possible
  without a 19c server, and composes with rider 3 when it lands.

**Hard constraints:** zero-cost (constitution #10); **synthetic data only** — no live-OCI or customer
identifiers ever (constitution #9); containers are ephemeral and torn down deterministically.

**Acceptance:** a single documented command brings the lane up, runs the live suite across all three
generations, and tears down; every finding class in D3–D7 reproduces **before** its fix and passes after.

---

### Workstream E — Cross-repo end-to-end suite
*[P1. Depends on: D.]*

True end-to-end across both repos: **MCP client → oraclemcp (stdio *and* http/SSE) → guard/classifier →
oraclemcp-db → oracledb driver → real Oracle container.**

- **E1** — the **operating-level ladder** end to end: `READ_ONLY → READ_WRITE → DDL → ADMIN`, including
  preview→confirm-token step-up, TTL-bounded elevation, `protected` profiles pinned at READ_ONLY with an
  immutable ceiling, DML rolling back by default, and OAuth scopes that can only *lower* the level.
- **E2** — **SEC-1**: every recovery/apply path re-classifies and re-checks; a stored verdict is never
  trusted. Assert this on each recovery path, not once.
- **E3** — the **audit hash-chain** records every privileged action, and `audit verify` detects tail
  truncation (exercise the anchor sidecar).
- **E4** — the **operator/dashboard HTTP surface** including the pairing flow (browser-based, per C4).
  **Implemented by the rig's R3 lane — build once there, do not duplicate.**
- **E5** — **failure/recovery paths**: killed connections, refused optional features, expired elevation,
  revoked credentials mid-session.
- **E6** — emit **signed attestations** from e2e runs (ties to K1–K3 already landed) so an e2e result is
  evidence, not a claim.

Build on the existing `e2e_harness` and golden-artifact discipline rather than duplicating them.

---

### Workstream R — Local Integrator Rig [P1; R3 is P0 — C4/E4 already commit to it]
*Operator-initiated, deep-designed 2026-07-20. Depends on: C (fixture rules), D (containers +
fixtures). **The gap it closes, proven:** no external MCP client has EVER driven the shipped
artifact — every "e2e" we own frames JSON-RPC with our own helpers (`scripts/e2e/offline_stdio.sh:34`
is literally `cargo test --test e2e_stdio`; `served_console.sh:106` spawns the real binary but
asserts through the web app's own parsers; repo-wide grep for any external MCP client: zero hits).
The rig makes US the field tester, so a production round becomes a confirmation, not a discovery.*

Six layers, one command (`scripts/rig/rig.sh up|run|report|down`; `rig doctor` preflight = D8):
**L1 DB** — the containers already running on this machine (xe18:1518, xe21:1520, free23:1522 —
`living_db.sh:67-74`; readiness via driver `container.sh` log sentinel). **L2 schema+data** — D9.
**L3 server-under-test = the ARTIFACT** — installed via the real installer, configured via real
`setup --discover`/`--write`, run as the real systemd `--user` service, never `cargo run`; the
snippets `setup` prints (`main.rs:4434-4459`) are the literal harness inputs (C9, live). **L4
harness** — PRIMARY: `@modelcontextprotocol/inspector --cli` plus a ~120-line committed raw
JSON-RPC probe (shares NO code with the server or `e2e_harness.rs` — enforced by a boundary lint),
both fed from hand-authored `mcp.json`, over stdio AND Streamable HTTP; SECONDARY: R5. **L5
browser** — Playwright/Chromium against a live `serve` listener (the existing `web/e2e` Playwright
config targets `vite preview` and validates none of the Rust security surface — this lane is new).
**L6 report** — field-shaped punch list built on the existing `scripts/e2e/lib.sh` JSON-line logger,
scrubbed by the existing secret/sensitive-data lints.

- **R1 [P1] — external-client reachability.** Inspector + probe complete `initialize`, `tools/list`,
  and a governed read over BOTH transports against the installed binary, from literal
  externally-authored configs. Must demonstrably fail against today's `main` where the field said it
  fails (two-sided proof, same rule as C).
- **R2 [P1] — tool-surface sweep with wire assertions.** Every advertised tool across the posture
  matrix {read_only, protected, proxy_auth, pooled, drcp}; write tools through the real
  preview→grant→apply gate. Tool counts derive from `registry.rs:18-81` (**34 canonical + 25 compat
  aliases**, +9 `oracle_plsql_*` builds — note: earlier "43 tools + 13 aliases" phrasing was the
  FIELD's sweep scope, not the registry; R2 asserts `oracle_capabilities` == `TOOL_NAMES` to pin
  runtime-vs-source drift mechanically). Three wire-only assertions per response: (1) well-formed
  envelope / `outputSchema` validation — every error is a known-class `ErrorEnvelope`; (2)
  **serialized-byte budget** (catches S11/B11, including the honest-truncation flag on `get_ddl`);
  (3) refusal-grammar uniformity — every refusal carries a `structured_reason` with a known
  category, and the same construct yields the same category across tools.
- **R3 [P0] — browser lane against live `serve`.** Chromium pairs (POST → 303 → `/`), performs an
  authenticated operator action POST asserting **200, not 403** (S2's assertion), and holds an
  `/operator/v1/events` SSE subscription with Last-Event-ID resume. **This IS C4's and E4's
  implementation — build once here.**
- **R4 [P1] — round-N report + refusal-corpus regression gate.** `rig report` emits scrubbed
  `findings.jsonl`/`.md` in the field punch-list shape; diffs the refusal-corpus export against the
  committed baseline — a category change or a newly-ALLOWED construct is itself a finding.
- **R5 [P1, in-train as R5-LITE]. OPERATOR RULING (2026-07-20): option 2 — R5-lite via Codex Spark
  on the release candidate, baked into the train.** One operator-gated
  `codex exec -m gpt-5.3-codex-spark` session (a proven headless-Codex launch shape — near-zero Claude usage)
  drives the INSTALLED release-candidate server over stdio AND Streamable HTTP from a literal
  hand-authored config, through a fixed prompt list covering orientation → schema exploration →
  governed read → refusal → error-recovery; the full transcript feeds R4's round-N report. This is
  the only lane that discovers agent-ERGONOMICS defects (the 344 KB-orientation class) — a
  deterministic sweep asserts what we thought to check; a real agent stumbles into what we didn't.
  Runs as part of §9.2 release acceptance (item 11). The FULL R5 matrix (real `claude -p`,
  opencode, multi-harness) stays deferred to the next train alongside the browser-auth matrix.
- **Failure-injection lanes** (via D10 + B16's test): idle-session kill → P0-5/A4; privilege revoke
  mid-run → P0-2/A3 + A1a; container restart → S3/reconnect honesty; token expiry (30-second-`exp`
  JWT via `token_exec`, held across a pool checkout) → B16; credential rotation → B4. The idle-kill
  and token-expiry lanes are the two no unit test can reach — they need a live DB plus elapsed time.

**Isolation contract (host safety — added on operator question, 2026-07-20).** The rig must never
risk this machine. Two tiers:
- **Tier A (default, nearly all lanes): disposable pseudo-home.** One throwaway root per run
  (`target/rig-home-<runid>/`) with `HOME` + all `XDG_*` + `PATH` redirected into it; the installer
  runs with `--prefix` inside it (the product's own config-discovery order — `$ORACLEMCP_CONFIG` →
  `$XDG_CONFIG_HOME` — makes the redirection airtight for config/state/audit/credentials/tickets);
  `serve` runs as a rig-supervised foreground child on rig-chosen loopback ports, never as a host
  service. Per-run state dirs mean the product's own instance lock prevents any collision with a
  real install. Teardown kills the process group, removes the root, and runs a **host-hygiene
  assertion** — real `~/.config/oraclemcp` untouched, no new user systemd units, `git status`
  clean — so non-contamination is itself a failing-able test. This is honest black-box fidelity:
  a real integrator on a locked-down host uses `--prefix` + XDG overrides identically, and the
  P0-1/P1-7/doctor classes reproduce unchanged in a pseudo-home. (`installer_e2e.rs` already
  drives the installer against temp prefixes; the serve-attach live-test pattern already
  supervises a spawned server — Tier A is wiring, not invention.)
- **Tier B (the genuinely invasive lanes only): systemd-capable throwaway container.**
  `service install/uninstall/restart/backup/restore`, `self-update`, the uninstaller, and
  `doctor --fix` run inside a disposable OS container (the cached `oraclelinux9` image) joined to
  the DB containers' Docker network — the host service manager is never touched; on the host those
  commands are exercised only via their `--dry-run` forms (the product's own preview-first
  contract). Worst case in Tier B is deleting the container, which is normal teardown.

**Placement: Tier-3 operator/nightly lane, NEVER required CI** (same posture as F3) — the rig must
not be able to red the front page; the required-lanes-only heartbeat is preserved.
**Phasing:** 0.10.0 = R1 + R2 (free23 lane) + R3 + R4 + D9, **plus R5-lite on the release candidate**
(in-train per the 2026-07-20 ruling). Deferred: the multi-generation sweep matrix, the FULL R5
harness matrix (`claude -p` / opencode), the HTTPS+mTLS+OAuth browser matrix (needs B1/B15 landed
first), chaos beyond idle-kill/token-expiry.
**Open items (recorded, non-blocking):** inspector-CLI flag surface not build-verified (fallback:
lean on the probe); `claude -p` headless behavior on this box unverified (harmless: R5-lite uses
the proven `codex exec` launch shape, and the `claude -p` lane sits in the deferred FULL matrix);
sample CO schema on xe18 unverified (worst case the realistic-data lane runs free23/xe21 only).
**Acceptance:** one documented command brings the rig up on this machine and produces a round-N
report; R1/R3 demonstrably fail against today's `main` and pass after the A/B fixes; zero customer
identifiers in any rig artifact (F5's scanner runs on rig output too).

---

### Workstream F — OCI Always-Free campaign (Cluster I)
*[P1. **Blocked on F0 — operator action.**]*

- **F0 — ✅ DONE (2026-07-20). OCI CLI authenticated on this machine.** `oci setup config` written to
  `~/.oci/config` (perms 600) against the existing key `~/.oci/oraclemcp_adb_api_key.pem`
  (fingerprint verified to match the key registered in the console). One trap hit and fixed: the first run put a **user OCID into the
  `tenancy` field**, producing a `NotAuthenticated` 401 that looks exactly like an unregistered key —
  check OCID *types* (`ocid1.user` vs `ocid1.tenancy`) before suspecting the key.
  Verified: `oci iam region list` → 44 regions.

  **Zero-cost baseline asserted (constitution #10):** Autonomous DB count is **0** in both the
  dedicated CI compartment and the root compartment.

  **Gotcha to reuse — the check needs a control.** The OCI CLI omits the `data` key entirely when a
  list is empty, so `--query 'length(data)'` *errors* rather than printing `0`, which is
  indistinguishable from a broken query or a permissions failure. Correct form:
  ```sh
  OUT=$(oci db autonomous-database list --compartment-id "$CID" --all 2>/dev/null)
  [ -z "$OUT" ] && N=0 || N=$(printf '%s' "$OUT" | jq '(.data // []) | length')
  ```
  and **always run a control query against a resource known to be non-empty** (e.g. compartment list
  → 1) in the same invocation, so "empty" is proven distinct from "broken".

  Env-file note — **OPERATOR RULING (2026-07-20): "figure it out" — no operator action needed.**
  `~/.oci/oraclemcp-adb.env` is still the unfilled `<...>` template that
  `scripts/e2e/oci_adb_terraform.sh` sources; at F1 start the agent fills it **itself** from data
  already on this machine: `~/.oci/config` (tenancy/user/region/key) plus the compartment OCID from
  the existing tfstate backup (the same source the zero-cost check uses). Values stay local; none
  enter committed artifacts (constitution #9, F5 guard).
- **F1 (bead `10.1`)** — Always-Free provisioning + **teardown-as-incident** harness. Teardown failure is
  treated as an incident, not a warning — an orphaned ADB is a cost event.
- **F2 (bead `10.2`)** — capability sweep: open, exercise the full tool surface, close.
  **19c rider (2026-07-20, ties to D11):** Always-Free ADB has historically offered a **database
  version choice (19c or 23ai)** at provisioning. VERIFY at F1 provision time whether 19c is
  selectable in our home region; if yes, provision the F2 sweep instance as **19c** — the field's
  actual version — turning the 19c gap into a zero-cost LIVE lane; run a second (or re-provisioned)
  sweep on 23ai for the feature-floor surface. If 19c is no longer offered, fall back to 23ai and
  note it; the documented operator-run OCR 19c-EE container remains the manual alternative.
- **F3 (bead `10.4`)** — wire the OCI e2e into a **Tier-3 operator-gated lane** (never automatic).
- **F4** — validate **B6** against a real DigiCert-signed ADB endpoint (the field's actual failure), not
  only the self-signed-ADB-CA chain. Also verify **P2-4** (§A.6.10) on the same endpoint.
- **F5 (bead `10.3` — was missing from plan v1)** — the OCI-artifact confidentiality guard: a
  secret-scan/redaction check wired into the OCI lane so a run **cannot commit live identifiers**
  (OCIDs, tenancy/compartment names, IPs, wallet secrets, tokens). Acceptance: the scan blocks a
  fixture containing a live-shaped OCID; synthetic fixtures pass. Treat as part of F1's DoD — a
  provisioning harness without this guard is incomplete (constitution #9).

**Hard constraint: zero-cost / Always-Free only** (constitution #10) — verified per-run via the
authoritative AVAILABLE=0 check before and after every run.

---

### Workstream G — Remaining beads

- **G1 [P1] `8.1` IAM subject-mapping config** (`he7t` residual) — last product gap from the OCI/IAM work.
- **G2 [P1] `5.2` D2 coverage ratchet — changed-line leg only in 0.10.0; mutation-floor leg DEFERRED
  with Z2.** The changed-line-coverage leg (coverage on modified `src/*.rs` lines gated at the crate
  floor) stays in scope. The per-crate **mutation kill-rate floor** leg depends on the
  `check-floor-report` seal, which requires the fresh campaign now deferred (§Z2) — so it defers to
  the release-candidate seal work. Deliberately **not** a naive never-decrease total. Builds on the
  D1 baselines already landed (server 88.68% lines, driver 80.08%).
- **G3 [P2] F-LOW children `7.11.1..20`** — 20 grounded defects with `file:line`. **Triage, don't
  bulk-fix.** Prioritise those that intersect this plan's themes:
  - `7.11.14` CC1 operator idempotency lease has no `Drop` cleanup → a panic strands the key
  - `7.11.15` CC2 one global `Condvar` → `notify_all` wakes every SSE waiter (thundering herd)
  - `7.11.16` AU2 CEF escaping misses U+2028/U+2029 → audit-record line-splitting forgery vector
  - `7.11.19` CF3 doctor atomic-install TOCTOU rename race
  - `7.11.5` DK2 driver spawns one detached OS thread per TIMEDWAIT acquire
  - `7.11.3` DC7 `u64 as u16` session-serial wrap (70000 → 4464) weakens cancel correctness
  The rest ship as capacity allows; each is independently closable.
- **G4 [P2] janitor** — `4.3` C3 stash triage (preserve-first: classify and keep as patches; drop only
  what is provably empty), `4.5` C5 tracked moves/renames, `4.6` C6 de-monolith + max-file-size ratchet
  (**land the ratchet; split only the safest file** — a wholesale split does not belong in a release train).
- **G5 [P2] `5.4` D4** — reopened for a cold-start proof that was blocked in the previous environment;
  re-attempt with the local harness.
- **G6 [P2] `8.2` G2 Live-nightly green streak** — the fix is already on `main`; a *streak* accrues over
  days, so this bead closes on elapsed evidence, not on a code change. **Do not close it early.**
  **v8 no-stall rider (operator ruling 2026-07-21):** the streak clock is already running (the fix
  is on `main` and the nightly lane fires unattended); if the streak window has not elapsed by RC
  time, G6 closes on elapsed evidence **after** publish — it is NOT a publish-sink ancestor (§10).
  Wall-clock evidence must never hold the tag.
- **G7 [P3] `12.3` K3** — wire attestation into coverage/mutation/invariant lanes (K1/K2 landed).
- **G8 [P3] `izk5`** — `doctor.rs` wallet-variant comments cite a stale `=0.7.4` driver.
- **G9 [P0-hygiene] `plan-bead-graph-lint-eshv`** — lint normalized plan-to-bead graphs before promotion.
  **Run it on this plan's own bead conversion (§10)** — it exists precisely for this moment.
- **G10** — driver `s0se` (close_notify) — **driver side resolved (§A.6.11)**; remaining work is the
  Z4 evidence commit + guarded close, plus B7's server-side half.
- **G11** — close the 11 epics once their children drain; Cluster B (`.3`) already has zero open children
  and is closable after review.
- **G12 [P1] — driver bug-bead un-deferral. OPERATOR RULING (2026-07-20): among the driver's 83
  deferred beads, only FEATURES (and deliberate better-than-original enhancements) stay deferred;
  everything bug/fix/parity-shaped joins the 0.9.0 train.** Census by type: 16 `bug`-typed beads
  (the un-defer list below expands two of them — `dc5-py5` and `dk1-dk2` — into their paired sub-fixes,
  and folds two adjacent `task`-typed items, `retry-leading-comment-contract` and `upstream-sync-….3`,
  which are parity work), 10 features,
  10 epics, 5 chores, 42 tasks (process — stay deferred as the "deferred for good reason" class).
  The 16 bugs split three ways:
  - **Already in-train:** `4sfc` (B5 verify+close), `s0se` (§A.6.11 + Z4 evidence commit).
  - **Already IMPLEMENTED on driver `main`, bead left deferred → verify + guarded-close with
    evidence:** `dc1` arrow-TSTZ (`3dbb72b`), `dc2`+`dc3` DSN cert-DN pin / DN_MATCH=OFF
    (`be26a50`), `dc4` configured TLS timeout (`abc4dd3`), `py1` NUMBER scale (`25ee76e`).
  - **Un-defer and implement:** `dc5-py5` sub-minute offsets + negative interval fractions, `dc6`
    Arrow NUMBER sentinel, `dk1-dk2` pool close races + per-waiter OS threads, `pr1` lone-quote bind
    panic-free, `py2` Decimal exact bind, `py3` bigint exact bind, `py4` GIL around blocking I/O,
    `retry-leading-comment-contract`, and `upstream-sync-….3` proxy bracket parsing — **which IS
    B9b's bead; do not create a duplicate.**
  Features verified staying deferred: `1s2`, `8eo`, `8pp`, `cco`, `cn4`, `dgi`, `j1w`,
  `kerberos-radius`, `nnnz`, `upstream-sync-….9` (security-gated legacy verifier).
- **G13 [P1] — server deferred-bug dedup (same ruling, server side).** The server holds 13 deferred
  bugs; most are **consolidated duplicates of the OPEN F-LOW `7.11.x` children already in G3**
  (cc1-cc2 ↔ 7.11.14/15, cf3 ↔ 7.11.19, di4 ↔ 7.11.7, g1-vector ↔ 7.11.10, au-hardening ↔ 7.11.16-17,
  db-value-fidelity ↔ 7.11.13, di2/di5 ↔ 7.11.6/8). At bead conversion: dedup to ONE canonical per
  defect (keep the 7.11.x child, close the deferred twin as duplicate-of). Genuinely new, pulled in
  per the ruling: `met-…-na6y` (metric label cardinality), `di1-…-h0d4` (terminal held-effect
  retry), `he7t` (IAM subject-mapping ORA-01017 — it is G1's residual anyway), `vzui` (rides Z3,
  must-fix).

---

### Workstream H — Release train
*[Depends on: everything above. Bead `13`. **Operator-gated.**]*

See §7 for the version decision, §9 for the gate.

**OPERATOR RULING (2026-07-20): publishing is the LAST bead, full stop.** The two publish beads —
driver **0.9.0** and server **0.10.0** — are the bead graph's terminal sinks: **every other bead in
the converted graph is their ancestor** (directly or transitively). Nothing tags, nothing
publishes, until all P0/P1 work, the rig's §9.2 acceptance run, and every non-deferred bead are
done. §10's conversion requirements enforce this structurally.

---

## 5. Sequencing and dependencies

```
Z (restore main to green: Z1 ✅, Z2 seal ADVISORY, Z3 ✅ flake, Z4 driver bookkeeping,
   Z5 fuzz-lane musl fix ✅, Z6 mutation-OOM policy ✅)
        │  ← precedes everything below; Z1/Z3/Z5/Z6 DONE, Z2 advisory (§Z2 clarification)
        ┌─ C (wire-contract fixtures) ──────────────┐  offline, start immediately
        │                                            │
F0 (operator: OCI auth) ─────────────┐               ▼
        │                            │        A1..A5, B1..B16, P  ── fixes
        ▼                            │               │
   D (local environment) ────────────┼───────────────┤
        │                            │               ▼
        │                            └────────► E (cross-repo e2e) + R (integrator rig)
        ▼                                            │
   F (OCI campaign, Cluster I) ──────────────────────┤
                                                     ▼
                              G (remaining beads) ─► H (release cut)
```

**Critical path:** `D → E/R → H`. **Z (CI green) precedes everything** — a red `main` makes every later
green claim dishonest (constitution #2); Z1/Z3/Z5/Z6 are DONE; Z2 (the mutation seal) is ADVISORY
this train (§Z2 clarification) — the `E_STALE_SEAL` checks are green-with-loud-warning on every
surface, and no front-page red is an "accepted state" anymore.
**C is off the critical path and should start first among the build work** — it is offline, cheap,
and its failures define "done" for A/B. **F is parallel** and gated only on F0 (done).

**Ordering rules:**
0. **Z first** — do not stack fix commits onto a red `main`; every push until Z lands reds the front page.
1. **C before A/B where possible** — write the failing fixture first, then fix. Two-sided proof.
2. **B1 before B4** — online revocation is unreachable until the control listener works.
3. **A1a is the single highest-priority code change** (fail-open in a fail-closed system).
4. **D3/D4/D5 before finalising A1/A3** — they settle the remaining open questions Appendix A flags
   (A4's pinned-vs-pooled question is already answered — §A.6.9 — so A4/A4e can start immediately).
5. **B5 and P2-4 are verify-then-close, not implement** (§A.6.5, §A.6.10). **B6 is
   implement-directly** — its grounding is complete (§A.6.8).
6. **G4 (janitor) last** — it is conflict-heavy and must not disturb a release-candidate tree.

---

## 6. What must not regress

The field report is explicit that several things are best-in-class. Any fix that costs one of these is a
bad trade:

- the **fail-closed guard** (15/15 adversarial statements blocked against a principal holding
  `ALTER SYSTEM` and `DROP ANY TABLE`)
- the installer **dry-run**, and the honest verification posture
- **credential issuance**
- **config/argument error messages** and `setup --discover` reporting
- **connect-failure envelopes**, the **refusal corpus**
- the **Python-MCP compatibility surface** (all 13 Python-MCP aliases — a subset of the registry's 25
  compat aliases per R2) and **multi-profile exposure** (13 profiles)
- the **audit design's fail-closed refusal to start** when writes are reachable without a key

Add regression coverage for anything above that a planned change comes near.

---

## 7. Release-scope decision (operator ruling recorded 2026-07-20)

Bead `13` originally specified **strictly patch**: `cargo-semver-checks` must stay at patch, and if it flags minor
the change is reworked patch-safe or held — never silently bumped. The server-side result was later corrected by semver evidence rather than preference.

**Complication discovered today:** the driver's public source inventory went **908 → 915** items with the
stage-aware TLS work already on `main`. Added public API is *minor*-compatible, not patch.

**OPERATOR DECISION (2026-07-20): driver → `0.9.0`, server → `0.9.1`.**
**CORRECTION (2026-07-22): driver remains `0.9.0`, server train name is `0.10.0`.**

- **Driver `0.8.4 → 0.9.0`** — a **minor** bump. This is the honest call: the stage-aware TLS work
  already on `main` grew the public source inventory 908 → 915, and this plan adds more (B6 platform
  trust anchors, B7 teardown hooks). A minor bump removes the incentive to contort real improvements
  into patch-safe shapes.
- **Server `0.9.0 → 0.10.0`** — a semver-required minor bump. `cargo-semver-checks`
  found public-API major findings against published 0.9.0 after the intended
  lease-subsystem removal and metadata-bounding changes. On a 0.x line, those
  findings force the minor position; the shipped artifact is therefore 0.10.0.

**Consequences, and they are deliberate:**
1. Bead `13`'s original "STRICTLY patch, rework or hold if semver-checks flags minor" constraint is
   **superseded for the driver** by the 2026-07-20 ruling and **superseded for
   the server** by the 2026-07-22 semver evidence. Future scope discipline
   still applies: the rename does not authorize unrelated API churn.
2. `cargo-semver-checks` still runs on both, but its role changes: for the driver it **documents** the
   surface delta (and must show no *breaking* change — 0.9.0 is minor, not major). For the server it
   forced the correction from 0.9.1 to 0.10.0.
3. The server's `oracledb` dependency pin moves to `=0.9.0`; the release-surface sync check and the
   driver-version references (bead `izk5`, `doctor.rs` comments) must be updated in the same train.
   Bead titles still carrying obsolete patch-train names are retitled to the
   ruled versions during bead conversion (§10).
4. **Any breaking change in the driver is out of scope.** 0.9.0 is additive-only. If something requires
   a break, it waits for 1.0 (the `road-to-1-0` line, still deferred).

---

## 8. Risks

| Risk | Mitigation |
|---|---|
| **A1a turns silent-empty into visible refusals** in deployments with restricted catalog visibility | Release-note it prominently; consider a one-release warn-then-refuse period |
| **A5 weakens a security surface** if `Origin: null` is accepted too broadly | Option (c) fetch-first (ruled §4.A5): mutating routes require `Content-Type: application/json` + default-mode `fetch()` (real Origin structurally guaranteed) behind the retained hard Origin gate; literal `Origin: null` is never accepted; written security review required; pairing URL stays secret-free |
| **B12a widens what the guard admits** | Operator-declared allowlist only; never automatic inference; guard stays tighten-only; audit every admitted routine |
| **The customer's VPD issue is H1 (a privilege difference), not our bug** | A1e ships value either way — visibility is the deliverable, not a remote diagnosis |
| **Local containers drift from the field's 19c** | The field DB is 19c; we have 18/21/23. Document the gap; do not claim 19c coverage we lack |
| **OCI cost** | Always-Free only, verified AVAILABLE=0 before and after each run; teardown-as-incident (F1) |
| **Scope is large for one release** | P0/P1 gate the cut; P2/P3 ship if clean. Land complete, not sliced (constitution #11) |
| **cosign/attest v4 majors** (from Dependabot #19) live on tag-only paths CI cannot exercise | The first release run is the only proof — watch it deliberately |
| **B6 broadens trust** (system roots trusted alongside a private-CA wallet) | It restores reference parity, the wallet stays included, and no accept-all mode exists or is added; record the B6c knob decision either way |
| **The advisory mutation seal (§Z2 clarification) could hide a test-quality gap** | The seal is a *measurement* of test-suite strength, not a runtime-safety property — the shipped binary is no less safe for its absence (mutation ≠ fuzzing; the fuzz lanes still run, Z5). Compensating controls: the bounded nightly shard rotation keeps sampling every scope; `migrate_mutation_result.py` still rejects stale/errored evidence from any future seal; the changed-line coverage ratchet and all required lanes still gate; the warning is loud on every surface. The RC-seal bead stays open, off the critical path |

---

## 9. Definition of done

### 9.1 Pre-push gate (both repos) — mandatory, no partial gates
Learned twice this week the hard way (a ci.yml comment broke `release_surface_sync_check`; a stale
`docs/baseline` reddened the driver push):

**oraclemcp:** `cargo fmt --all -- --check` · `cargo clippy --workspace --all-targets -- -D warnings`
(+ the two `dashboard-bundle` invocations) · `cargo test --workspace` · `cargo deny check` ·
`check_entry_trace_contract.sh` · `ci_taxonomy.py --check` (+ crate-copy sync) ·
`release_surface_sync_check.sh` · honesty/provenance/concurrency lints ·
`check_bead_close_evidence.sh` · **evidence-SHA reachability from `origin/main`** (Z1's rule; plain
local resolution is exactly how §A.9's red slipped past the local gate). *(The `mutation_safety_gate.sh`
seal-freshness check is intentionally NOT in this gate — Z2 is deferred, so the stale seal is an
accepted state until the release candidate; re-adding this check is part of the deferred RC seal work.)*
**driver:** fmt · clippy · tests · **`scripts/gen_baseline.sh --check`** · `verify_required_local.py`.
Heavy builds go through `scripts/build_lease.sh` with a dedicated `CARGO_TARGET_DIR` (the build-lease
guard enforces this via `scripts/check_build_lease.sh` / the repo-local Cargo compiler wrapper — which
blocked the orchestrator's own build tonight, correctly).

### 9.2 Release acceptance
1. All **P0** items closed or explicitly deferred **with an operator-recorded reason**.
2. **C1–C9** demonstrably failed before their fixes and pass after.
3. The **local environment (D)** reproduces D3–D7's finding classes and passes post-fix.
4. **E** green across all three container generations.
5. **F** green, or explicitly deferred if F0 does not happen.
6. Every bead closed carries **landed evidence** passing `check_bead_close_evidence.sh` with **0 hard
   findings** (the guard already rejected six different evidence defects this week — respect it).
7. **Both repos' front pages fully green** — measured as *every check-run on the HEAD commit*, not
   run conclusions (see `frontpage-green-mechanics`). The `E_STALE_SEAL`-derived checks
   (coverage-ratchet, release-preflight, heartbeat) are green via `ALLOW_STALE_MUTATION_SEAL` with
   a loud warning on **every** surface, per-push and release alike — the seal is advisory this
   train (§Z2 clarification, operator ruling 2026-07-21). The scheduled Fuzz Campaign and Mutation
   Safety rotation lanes are green under the Z5/Z6 fixes.
8. `cargo-semver-checks` result recorded and the version decision (§7) made on its evidence.
9. **The operator pushes the tag.** Agents never tag or publish.
10. **Workstream Z landed first and stayed landed** — oraclemcp `main` fully green (bead-evidence
    audit 0 hard **in CI**, Windows lane resolved, Z5/Z6 scheduled lanes green; the mutation seal
    advisory everywhere via `ALLOW_STALE_MUTATION_SEAL`, §Z2 clarification) before any A/B fix is
    claimed done, and kept green at every subsequent push.
11. **The rig ran on the release candidate** — R1–R4 executed against the RC build, **plus the
    R5-lite Codex-Spark agent session** (operator-gated, per the 2026-07-20 ruling); the round-N
    report contains no untriaged P0/P1 finding (findings either fixed in-train or operator-deferred
    with a recorded reason).

---

## 10. Conversion to beads

Convert this plan with the beads workflow, then **run `plan-bead-graph-lint-eshv` (G9) on the result** —
it exists exactly for this. **OPERATOR RULING (2026-07-20): conversion starts only on an explicit
operator "go" — do not ask for it; wait for it.** Requirements:
- every task self-contained (no need to re-read this plan), citing its Appendix A `§` for `file:line`;
- dependency edges per §5, especially `Z → everything`, `C → A/B`, `B1 → B4`, `D → E/R → H`,
  `F0 → F`, `D9/D10 → R`, `R3 → C4/E4`;
- each bead names its acceptance test, and for a fix bead, the fixture that must fail first;
- **no bead closes without landed evidence** (§9.2 item 6), and evidence SHAs must be reachable from
  `origin/main` (Z1's rule);
- Workstream P converts to **individually-closable** P2/P3 beads — no umbrella bead;
- bead titles still carrying obsolete patch-train names are retitled per §7;
- G12's driver bug beads are un-deferred (not re-created) and G13's server duplicates are
  dedup-closed against their `7.11.x` canonicals — one bead per defect, ever;
- **the two publish beads (driver 0.9.0, server 0.10.0) are the graph's terminal sinks** — every
  other non-deferred bead is made their ancestor, so `br ready` can never surface publishing while
  anything else is open (operator ruling 2026-07-20; G9's lint verifies the sink property).
  **v8 sink exceptions (operator no-stall ruling 2026-07-21):** exactly three beads are NOT sink
  ancestors — **G6** (elapsed-evidence streak; closes post-publish if the window has not elapsed),
  **B13a's residual investigation** (if unreproduced by RC — B13b stays an ancestor), and the
  **RC mutation-seal bead** (§Z2 clarification: advisory). Each carries the recorded ruling in its
  body so the exemption is auditable, and G9's lint allowlists exactly these three;
- Cluster J beads are **not** touched (Cluster J = the GCP/Vertex launch campaign: ADK/Gemini demo,
  evidence bundle, site page, launch video, coordination — deferred by operator ruling).

---

# Appendix A — Code-level grounding (the evidence base)

Every field finding mapped to an exact code site, root cause, minimal fix, and the test that would
have caught it. **This appendix is normative for `file:line`, root causes and minimal fixes**; the
body of the plan above is normative for scope, ordering and acceptance.

**Provenance.** The source is an operator live-test round held in a gitignored quarantine
(`livesting-*/`, constitution #9) — verified untracked and never committed. This appendix is
**scrubbed**: no customer schema names, database identifiers, usernames, hosts, regions, tenancy
names or package names appear. Where the report named a customer object, this text says "the field
schema" or "a customer package".

**Grounding is complete for every finding, P1-2 included** (§A.6.8; completed in review round 1,
which also re-verified every code-level claim in this appendix at HEAD — §A.7 item 11).

---

## A.0. The systemic finding (most important)

Three independent investigations converged on one structural defect in how this repo tests:

> **Tests construct the client side using the same internal helper the server side consumes.**

| Area | The self-reference | Consequence |
|---|---|---|
| mTLS allow-list | test builds `format!("mtls:{}", cert_fingerprint_sha256(...))`, which already returns `sha256:<lowerhex>` | never exercises an operator-authored spelling |
| OAuth | every test token minted by the in-module `mint()` + in-module `hmac_sha256`/`b64url_encode` | proves internal consistency; cannot prove an external client can mint an acceptable token |
| stdio init token | tests interpolate the `INIT_TOKEN_META_KEY` **constant** | would pass identically if the key were renamed to something undiscoverable |
| session statements | `connect.rs:831-857` asserts on `build_session_context(...)` output; never opens a connection | the `protected`-profile ordering interaction (§A.2.2) is structurally unexercised |

Each proves **round-trip self-consistency**; none proves **external reachability**.
GroundAuth's summary: *"Every feature works; none is reachable from outside the repo."*

This is why 169 green test binaries coexisted with four transport-auth features an integrator could
not use, and it is the strongest argument for the two new pillars in the plan:

1. **Wire-contract fixtures** — literal JWTs minted by an external tool, literal `initialize` JSON
   frames, hand-spelled uppercase fingerprint allow-lists, committed as opaque strings. They pin the
   *contract*, not the round trip. Cheap, offline, and would have caught 3 of 4 transport findings.
2. **A local live environment** — for the classes that genuinely need a database (§A.2, §A.3).

---

## A.1. Unification: one lock causes both P0-1 and P1-13

`FileStore::acquire_service_owner` (`crates/oraclemcp-core/src/file_store.rs:232-256`) takes a
**process-wide exclusive advisory `flock` on a single `SERVICE_LOCK_FILE`**, covering the **entire**
state store, held for the server's whole lifetime, acquired non-blocking:

```rust
match file.try_lock() {
    Ok(()) => {}
    Err(TryLockError::WouldBlock) => return Err(FileStoreError::Locked),   // file_store.rs:249
```

Both of these call it:

- **P0-1 `setup --write`** → `ConfigOpsBackend::open_default()` → `Self::open(...)` →
  `store.acquire_service_owner("config-ops")` (`crates/oraclemcp-core/src/config_ops.rs:325-332`),
  reached from `setup_apply_config` / `setup_apply_discovery_config`
  (`crates/oraclemcp/src/main.rs:4541`, `:4536-4545`).
- **P1-13 credential rotate/revoke/list** → `ClientCredentialStore::open` →
  `acquire_service_owner` (`crates/oraclemcp-core/src/client_credentials.rs:319-322`); the server
  holds it from startup via `open_with_owner` (`main.rs:3651-3663`), CLI uses `open_default`
  (`main.rs:5815`).

**Therefore `setup --write` cannot work while any oraclemcp service is running.** The field tester ran
a server throughout the round (HTTP/dashboard/transport testing), which is why *every* mode failed —
non-interactive, under a PTY, via `--discover`, to fresh paths, to `$HOME`.

### Why the error says nothing
`crates/oraclemcp/src/main.rs:4609-4616` collapses the real cause to a fixed string **and discards the
inner error** (`_` bindings):

```rust
ConfigOpsError::FileStore(_) | ConfigOpsError::Io(_) => ("ORACLEMCP_SETUP_WRITE_FAILED", "config workflow failed before completion"),
_ => ("ORACLEMCP_SETUP_WRITE_FAILED", "config workflow failed before completion"),
```

The discarded variant is `FileStoreError::Locked`, whose own text is *"file-store service lock is
already held"* (`file_store.rs:47-48`) — i.e. the product knew the exact answer and threw it away.
This is why `--json` and `RUST_LOG=debug` added nothing.

### Fix (smallest first)
1. **Stop discarding the error.** Map `FileStoreError::Locked` to a distinct code
   (`ORACLEMCP_STATE_STORE_LOCKED`) whose message names the running service and the remedy. One match arm.
2. **`clients issue` should emit the HTTP form** of `revocation_command` when a service lock is
   detected (see §A.5.4 — the online route already exists).
3. **Lock granularity** (larger, optional): per-operation locks, or let the running service serve
   config/credential mutations. Note `clients.json` is loaded **once** at open
   (`client_credentials.rs:339`) with no reload/watch, so out-of-process mutation would not propagate
   to a running server anyway — granularity work must include reload.
4. **Comment nit while in the file** (review round 1): the comment at `file_store.rs:261` calls the
   lock "shared"; `try_lock()` at `:247-249` is exclusive. Fix the comment.

### Test that would have caught it
A CLI-vs-running-server collision test: start a server, then run `setup --write` and
`clients revoke` and assert on a *specific, actionable* error. **None exists** — all store tests run
offline with no contention; operator-API tests call handlers in-process.

---

## A.2. P0-4 "VPD-protected objects read as EMPTY" — four defects, and the report's root cause is wrong

### A.2.1 REFUTED: session statements are NOT run on a different session
Single production construction site `crates/oraclemcp-core/src/connect.rs:224`; statements assembled
`connect.rs:306-335`, carried on `options.session_statements` (`connect.rs:274`), applied inside
`connect()` on the very connection returned (`crates/oraclemcp-db/src/connection.rs:1584-1587`, which
becomes the returned connection at `:1589-1592`). Every pooled connection uses that path
(`crates/oraclemcp-db/src/pool.rs:50-52`, pre-opened `pool.rs:269`). `Pool::with_conn`
(`pool.rs:369-433`) saves/restores only deadline and quota — **no session reset**.

Setup failures are **not** swallowed: `connection.rs:1586` → `redact_session_setup_result(...)?`
(`connection.rs:2005-2027`) rewrites the message but still returns `Err`. Fail-closed.

**Docs are wrong, though:** `crates/oraclemcp/src/robot_docs.rs:412` and `:574` claim login setup
"remains on the pinned main session", implying pool reads skip it. The code applies it on every pool
connect. Fix the docs.

### A.2.2 VERIFIED ORDERING DEFECT — `SET TRANSACTION READ ONLY` precedes trusted setup
`connect.rs:306-335` builds, in order:
1. `read_only_setup_statements(ReadOnly)` → `SET TRANSACTION READ ONLY`
   (`connect.rs:312-318`; definition `crates/oraclemcp-guard/src/enforcement.rs:48-54`)
2. `login_statements` (`:319`) → 3. `login_script` (`:324`) → 4. `trusted_session_statements` (`:329`)

On any `protected` / READ_ONLY-ceiling profile — **precisely the posture the README recommends** — the
operator's trusted setup runs **inside an already-open read-only transaction**. Any trusted statement
performing DML raises `ORA-01456`, so table-backed / "secure application context" VPD setup is
**impossible by construction**.

The field report treated a `ORA-20980` return-code probe as proof the setup **ran**; it may equally be
proof it **failed** (a package wrapping its body in an exception handler and re-raising via
`RAISE_APPLICATION_ERROR`).

**Fix:** emit `SET TRANSACTION READ ONLY` **after** `trusted_session_statements`, re-asserting the
backstop immediately afterwards. Narrow blast radius; matches what "trusted" implies.

**Offline test that catches it today, in one line:** `connect.rs:831-857` already asserts the built
statement list — but uses a profile **without** `protected`, so the read-only statement is absent.
Add the same assertion for a `protected = true` profile.

### A.2.3 VERIFIED FAIL-OPEN in the VPD refusal gate (security-relevant)
Intent (`crates/oraclemcp/src/dispatch/mod.rs:1907-1911`): served reads "must refuse views, SELECT VPD
policies, virtual columns, remote objects".

Implementation `crates/oraclemcp-db/src/catalog_resolver.rs:336-379`; probe SQL `:65-67`:

```sql
SELECT policy_name FROM all_policies
 WHERE object_owner=:1 AND object_name=:2 AND enable='YES' AND sel='YES' AND ROWNUM<=1
```

`catalog_resolver.rs:361` — `if !policies.is_empty() { return Unknown }`.

**An empty probe result is treated as "no VPD policy" — indistinguishable from "this principal cannot
see policy metadata."** If the DB user is blind to `ALL_POLICIES`, a gate designed to **refuse** VPD
objects silently **passes** them: the query reaches Oracle, VPD empties it, and the caller gets
`0 rows, exit-success`.

This is a **genuine fail-open inside a fail-closed system** — the exact class AGENTS.md forbids.

**Fix (~10 lines at `catalog_resolver.rs:351-363`):** probe `ALL_POLICIES` readability once per
session; if blind, return `Unknown` (refuse) rather than "no policy".
**Blast radius:** deployments whose DB user lacks catalog visibility begin refusing instead of
silently emptying — strictly more correct, but surfaces as new errors in the field. Gate and announce.

### A.2.4 VERIFIED: zero rows drops `columns` (independent bug)
`crates/oraclemcp-db/src/query.rs:487-519`. `columns: Vec::new()` at `:492`, populated **only** inside
`push_with_options`, gated on the first row:

```rust
if self.column_cache.is_none() {
    self.columns = row.columns.iter().map(|(name,_)| name.clone()).collect();  // query.rs:512-513
```

Zero rows ⇒ never called ⇒ `columns` stays empty. Derived from the first row, **never from statement
describe metadata**. Compounds P0-4 exactly as the tester suspected: an emptied result also loses its
schema, so an agent cannot distinguish "no matching rows" from "wrong object / no access".

**Fix:** populate from statement describe metadata at construction. **Check golden/snapshot tests that
may pin `columns: []`.**
**Test:** unit test on `QueryPageBuilder` with zero pushes — offline, trivial.

### A.2.5 `oracle_describe` is catalog-based, so VPD cannot empty it
`crates/oraclemcp-db/src/intelligence.rs:1349-1367` reads `ALL_TAB_COLUMNS`; constraints `:1376-1385`
over `ALL_CONSTRAINTS` ⨝ `ALL_CONS_COLUMNS`; owner/table `to_ascii_uppercase()` (`:1362-1363`).

Therefore `{"columns":[],"constraints":[]}` does **not** indicate a VPD-context problem — it indicates
the object is **not visible in `ALL_TAB_COLUMNS`** for the computed `(owner, table_name)`. Also
**fail-silent**: not-found returns `Ok(vec![])` (empty success, not an error). An unresolved synonym
name likewise returns empty, and `to_ascii_uppercase()` silently misses quoted lower-case identifiers.

**Fix:** return a structured not-found / not-visible instead of `Ok(vec![])`.

### A.2.6 RESOLVED: CLIENT_IDENTIFIER clobber

The former test-only lease path was deleted. The wired connection path now clears
identity before applying the active profile, so a reused DRCP session cannot retain
a prior profile's `CLIENT_IDENTIFIER`.

### A.2.7 Ranked hypotheses for the field symptom
| # | Hypothesis | Confidence | Decided by |
|---|---|---|---|
| H1 | **The two clients are not the same Oracle principal** (user or enabled roles). Explains VPD emptiness **and** empty describe with one cause, since data-VPD cannot empty `ALL_TAB_COLUMNS`. | High | live `SESSION_USER` + `SESSION_ROLES` diff |
| H2 | **VPD gate fails open** on a blind `ALL_POLICIES` probe (§A.2.3) → executed and silently emptied instead of refused. Explains `0 rows, exit-success` rather than an error. | High | `ALL_POLICIES` visibility |
| H3 | **Ordering defect** (§A.2.2) → `ORA-01456`, plausibly surfacing as the observed error. | Med-High | does the customer package perform DML |
| H4 | **Per-request `ROLLBACK`** (§A.2.8) undoes table-backed/global context. | Medium | same as H3 |
| H5 | CLIENT_IDENTIFIER clobber (§A.2.6) | Low — no prod caller | ruled out |

H1 and H2 are **complementary, not competing**; together they explain every symptom without assuming
anything about the customer's package.

**Cheapest decisive next step (no code change):** the server already ships the diagnostics —
`SESSION_CONTEXT_SQL` (`catalog_resolver.rs:31-33`: `SESSION_USER` / `CURRENT_SCHEMA` /
`CURRENT_EDITION_NAME`) and `SESSION_ROLES_SQL` (`:35-36`). Run both through each client and diff →
settles H1 immediately. Add an `ALL_POLICIES` probe → settles H2.

### A.2.8 What resets state between setup and query
`crates/oraclemcp/src/dispatch/read_only_backstop.rs:40-46`: `ensure_armed` issues **`ROLLBACK`** then
`SET TRANSACTION READ ONLY` **before every READ_ONLY request**. `DBMS_SESSION.SET_CONTEXT` on a plain
namespace survives; table-backed / global context does not. Scoped to the pinned session
(`read_only_backstop.rs:29-33`).

Two connection surfaces exist (`dispatch/mod.rs:499-500`): pinned `conn` vs `stateless_conn`
(metadata), selected at `:12355-12359`. `oracle_query` → pinned; `oracle_describe` → **stateless when
`[profiles.pool]` is set**. Same options, **divergent transaction state** — worth pinning in tests.

---

## A.3. P1-14 — the PL/SQL function surface is unusable at READ_ONLY (fully by design)

- `crates/oraclemcp-guard/src/purity.rs:80-104` — `routine_purity` **defaults to `Purity::Unknown`**
  for every routine (doc `:77-79`: "a guard with no engine bound treats every user-defined routine as
  side-effecting").
- `purity.rs:71-73` — `permits_safe()` is true only for `ProvenReadOnly`.
- `crates/oraclemcp-guard/src/classifier.rs:3034-3037` — `all_proven = calls.iter().all(...)`;
  `:3067` — not pure ⇒ Guarded/READ_WRITE; `:3376`/`:3388` — default oracle is `UnknownOracle`.

**Oracle purity metadata is NEVER consulted** — no query anywhere reads `DETERMINISTIC`,
`ALL_PROCEDURES`, or `USER_PROCEDURES` for purity. **No operator allowlist and no config knob** exist
(grepped `oraclemcp-config/src` + `oraclemcp-guard/src`).

Real oracles exist but never cover caller SQL:
- `dispatch/mod.rs:1913-1915` — `DEFAULT_CLASSIFIER` (caller SQL) binds **no** oracle.
- `dispatch/mod.rs:1920-1937` — `GeneratedReadPurityOracle`: **3-entry hardcoded allowlist**
  (`DBMS_LOB.SUBSTR`, `DBMS_METADATA.GET_DDL`, `DBMS_XPLAN.DISPLAY`), server-generated SQL only.
- `crates/oraclemcp/src/plsql_tools.rs:271-272` — a real `PlsqlSideEffectOracle`, but only via
  `from_analysis_run(run)`; not on the `oracle_query` path.

### Why a signed custom tool refuses to load AND stops startup
1. `crates/oraclemcp/src/main.rs:1338` — `Classifier::new(ClassifierConfig::new())`, **no purity
   oracle** ⇒ a function call in a SELECT classifies READ_WRITE.
2. `main.rs:1349`, `:1357`, `:1366` — `max_level` is **hard-coded to `OperatingLevel::ReadOnly`**,
   ignoring the profile's real ceiling.
3. `crates/oraclemcp-core/src/custom_tools.rs:436-442` — `effective > max_level` ⇒ `LoadError::OverCeiling`.
4. `custom_tools.rs:451-458` — `load_tools` is **fail-fast** (`.map(..).collect::<Result<_,_>>()`
   short-circuits); doc `:449-450`: "the first refusal aborts the load".
5. `main.rs:1368` — `?` propagates; **`main.rs:3515-3522`** emits
   `ORACLEMCP_CUSTOM_TOOLS_INVALID` and returns **`ExitCode::from(2)` — the server does not start.**

**Signing is orthogonal**: verification happens in `load_tools_for_profile`
(`main.rs:1346`/`:1354`); `classify_at_load` (`custom_tools.rs:413-447`) runs independently, so a
**validly signed tool is still rejected on classification grounds** — signing buys authenticity, never
privilege. Form B (`call=`) is rejected outright (`custom_tools.rs:104-109`). No knob makes load
failures non-fatal.

### Fix options
(a) An **operator-declared pure-function allowlist** feeding a `SideEffectOracle` on
`DEFAULT_CLASSIFIER` — the seam's intended use, needs no engine.
(b) Pass the **profile's real ceiling** at `main.rs:1349/1357/1366`.
(c) Decide whether one bad tool should remain fatal — a `--skip-invalid-tools` posture with loud
reporting would have kept the field server running.
**Untested today:** no test loads a custom tool against a non-READ_ONLY ceiling, because the ceiling
parameter is hard-coded.

---

## A.4. P0-5 — a pooled connection that dies while idle is never replaced

**The driver already has the machinery; the server never arms it.**

Driver side (`crates/oracledb/src/pool/engine.rs:35-90`) implements reference `_check_connection`:
validate a candidate pulled from the free list, schedule a ping, or drop it. Knobs exist on
`crates/oracledb/src/pool.rs:178-193` (`ping_interval_secs`, `with_ping_interval_secs`,
`ping_timeout_ms`, `with_ping_timeout_ms`); the reaper pings via
`inner.backend.ping_connection(&conn.conn, ping_timeout_ms)` (`engine.rs:647`).

Semantics (`engine.rs:55-62`):
```rust
let requires_ping = if ping_interval == 0 { true }                                   // always ping
    else if ping_interval > 0 { conn.time_returned.elapsed() > interval }            // ping if idle
    else { false };                                                                  // NEVER ping
```

**`grep -rn 'ping_interval' oraclemcp/crates/` returns nothing** — the server never sets it. So the
effective behaviour depends entirely on the driver default; if that default is negative, **liveness
validation is never armed**, which matches the field symptom exactly (doctor reports keepalive
disabled + unbounded idle reads, yet shows a green check).

### Fix
Arm validation from the server: set a sane `ping_interval_secs` (and `ping_timeout_ms`) by default;
expose both in `[profiles.pool]`; retry once on a fresh connection after a transport I/O error; make
`oracle_connection_info` perform a **real round trip** (it returned `connected:true` with every
liveness field null); stop leaking raw driver errors (`Broken pipe (os error 32)`) to callers.

**RESOLVED — do not implement from this section alone; §A.6.3 and §A.6.9 supersede it.** The driver's
default is `ping_interval_secs: 60` (validation IS armed by default — in the **driver's** pool), but
oraclemcp does not use the driver's pool at all: it has its own (§A.6.3), and `oracle_query` runs on a
pinned connection outside even that (§A.6.9). The "server never arms it" framing above is therefore
the wrong lens — kept only as the investigation record. P0-2's grounding is complete in §A.6.1 (no
pre-flight probe; quarantine structural and permanent).

---

## A.5. Transport-auth cluster (P1-10 .. P1-13)

**None of the pre-baseline commits touched any of these paths** — `serve.rs`, `tls.rs`,
`admin_auth.rs`, `oauth_rs.rs`, `init_token.rs`, `client_credentials.rs`, `oraclemcp-config/src/lib.rs`
were all untouched. Nothing in flight addressed them.

### A.5.1 P1-10 mTLS / control listener — VERIFIED, root cause found
**The Winsock/non-blocking hypothesis is REFUTED.** `restore_accepted_socket_blocking`
(`crates/oraclemcp-core/src/http/serve.rs:396-398`) **is** called on all three accept loops —
`serve.rs:89` (HTTP), `:172` (HTTPS), `:237` (**control**). Not that family.

**The reset is designed behaviour.** `serve.rs:474-552` (`handle_control_tls_connection`) runs three
authorization gates **before** `StreamOwned::new` (`:539`) and before `send_close_notify` (`:549`),
each early-returning on a raw `TcpStream`:
- `:493-502` no peer cert → `PermissionDenied`
- `:503-511` fingerprint not in `mtls_clients` → `PermissionDenied`
- `:512-520` cert not operator-authorized → `PermissionDenied`

Dropping the raw `TcpStream` with the client's request bytes unread in the kernel receive buffer makes
the kernel emit **RST, not FIN** → `openssl errno=104`. The only log is `tracing::debug!`
(`serve.rs:259`), invisible at default level. Handshake completes → request reset → nothing logged.
Asserted verbatim in `crates/oraclemcp-core/src/http/tests_serve_tls.rs:596-600`.

**Root cause — normalize-on-validate vs exact-match-on-enforce.**
`crates/oraclemcp-core/src/admin_auth.rs:102-107` compares with a raw `==`:
```rust
.any(|allowed| allowed == principal_key)   // no normalization
```
- Runtime principal key is always `mtls:sha256:<64 lowercase hex>` (`http/mod.rs:682-690`, from
  `http/config.rs:106-112`).
- `http.operator.allowed_subjects` passes through **verbatim** (`crates/oraclemcp/src/main.rs:3352-3357`);
  its only validation checks for a colon (`oraclemcp-config/src/lib.rs:756-772`).
- But `http.mtls.client_fingerprints` accepts **three** spellings — bare hex, `sha256:`-prefixed, any
  case (`oraclemcp-config/src/lib.rs:845-849`, duplicated at `http/mod.rs:682-686`).
- And the control-listener precondition check **normalizes both sides** before comparing
  (`oraclemcp-config/src/lib.rs:648-660`).

So this config validates cleanly, starts, logs "control transport enabled", and silently resets every
request:
```toml
[http.mtls]
client_fingerprints = ["AABB…"]       # bare uppercase — accepted
[http.operator]
allowed_subjects    = ["mtls:AABB…"]  # validation PASSES (it normalizes)
```
Runtime: `"mtls:AABB…" != "mtls:sha256:aabb…"`. **Only the exact literal
`mtls:sha256:<lowercase hex>` works, and nothing says so.**

**Second, independent path to the same symptom:** a **1-second** control ingress budget
(`serve.rs:46`, `:649-653`, `CONTROL_PROBE_INGRESS_TIMEOUT`) covers header *and* body, and its timeout
also returns `Err` from `handle_stream` (`:680`) → identical silent reset. Hand-probing with
`openssl s_client` can therefore never succeed.

**Useful discriminator:** control-probe permits reach only `Observability` (`GET /healthz`|`/readyz`)
or `OperatorApi`; everything else → **429** (`http/mod.rs:962-983`, asserted `tests_serve_tls.rs:572-581`).
So **429 = past auth; reset = not past auth.**

**Fixes:** (1) normalize at enforcement in `admin_auth.rs:102-107` for `mtls:` subjects (reuse
`normalize_cert_fingerprint`), or normalize at load in `main.rs:3352-3357`; (2) promote
`serve.rs:238/259` debug → `warn!` including the **computed** fingerprint and the reason —
`computed mtls:sha256:aabb… not in allowed_subjects` is a 30-second operator fix; (3) raise or
document the 1s budget.

**Main listener: UNCERTAIN, likely misattributed.** Unregistered fingerprint → **403
`mtls_client_not_registered`** (`http/mod.rs:576-582`, asserted `tests_serve_tls.rs:334-360`);
operator-authority failure → `operator_authority_required_response()` (`:1047-1052`). No silent-drop
path found. Ask the tester whether that was truly a reset or a 403/429.

### A.5.2 P1-11 OAuth HS256 — REFUTED as a code defect
Verifier `crates/oraclemcp-auth/src/oauth_rs.rs:127-193` is correct and thorough. Two **undocumented**
requirements make it near-unsatisfiable by hand:

1. **The key is raw UTF-8 bytes** — `crates/oraclemcp/src/main.rs:3321`:
   `Hs256Verifier::new(secret.expose().as_bytes().to_vec())`. **No base64, no hex decode.** And the
   field is a secret *reference* (`env:` / `file:` / `literal:`), so passing the secret value directly
   makes the key the literal string `env:MYSECRET`. Must be ≥32 characters.
2. **RFC 9068 claims are required but invisible in the error** — `oauth_rs.rs:155-165` rejects with a
   bare `Malformed` unless `iss`, `sub`, `client_id`, `jti` are all non-empty strings and `iat` is a
   number. `client_id`/`jti` are routinely omitted by hand-built tokens.

Full passing contract: header `{"alg":"HS256","typ":"at+jwt"}` (`typ` mandatory, `:134`, `:285-287`;
plain `"JWT"` rejected); claims `iss` (exact vs `allowed_issuers`), `aud` (string or array, exact vs
`http.oauth.resource`), `sub`, `client_id`, `jti`, `iat` (number), `exp` (> now), optional `nbf`, and
`scope` (space-delimited string, checked first) **or** `scp` (array) — both work (`:316-327`).
`required_scopes` cannot be empty (`oraclemcp-config/src/lib.rs:826-842`), so every token must carry a scope.

**Partially refuted "bare 401":** `http/mod.rs:627-648` **does** emit `www-authenticate` carrying an
error code; the body is `b"unauthorized"` (`:645`), which is what the tester saw. The diagnostic is
header-only and coarse — `token_error_code` collapses Malformed / BadSignature / AudienceMismatch /
UntrustedIssuer / Expired into one code.

**Fix:** document the contract; widen `error_description`; consider
`oraclemcp doctor oauth --token <jwt>` printing the specific `TokenError`.
**Test:** a committed literal JWT + literal secret generated **once by an external tool**.

### A.5.3 P1-12 stdio init token — VERIFIED, pure discoverability failure
Exact path: **`params._meta["oraclemcp/initToken"]`** (string).
- Constant `INIT_TOKEN_META_KEY` — `crates/oraclemcp-core/src/server.rs:37`
- Extraction — `server.rs:1541-1544` (`params` → `_meta` → key → `as_str()`)
- Validation — `crates/oraclemcp-core/src/init_token.rs:57-66`, constant-time (`:73-82`); expected
  value from `$ORACLEMCP_STDIO_TOKEN` (`:12`, `:47-53`) or `--stdio-token` (`main.rs:165`).

**Why tokens "carrying it" still failed:** the key contains a **slash** — unguessable. Decisive
evidence: the tester always got `Missing` (`init_token.rs:36`), never `Mismatch` (`:39`), proving the
extractor never found a value at that path. (A non-string value also yields `Missing` via `as_str`.)

**Documentation: ZERO hits** for `oraclemcp/initToken` across `README.md`, `docs/`, `robot_docs.rs`,
`oraclemcp.example.toml` — it exists only in Rust source.

**Fix:** document the path; put the literal `params._meta["oraclemcp/initToken"]` into the error text
at `init_token.rs:36`; add a test built from a raw literal JSON string.

### A.5.4 P1-13 credential lifecycle — cause verified, premise PARTLY REFUTED
Lockout cause is §1. **But online revocation ALREADY EXISTS** —
`crates/oraclemcp-core/src/http/operator.rs:691-693`:
```
/operator/v1/client-credentials           (list)
/operator/v1/client-credentials/rotate
/operator/v1/client-credentials/revoke
```
handled at `operator.rs:836` → `handle_operator_client_credentials_route` (`:2726`). `OperatorApi` is
one of the two route classes the control listener permits (`http/mod.rs:976`), and the in-process path
already tears down live sessions on mutation (`close_http_principal_sessions`, `serve.rs:328-354`).

**So no-downtime revocation is supported — it was unreachable only because P1-10 blocked the control
listener.** Fixing P1-10 unblocks P1-13.

The misleading string: `main.rs:5843` emits
`"revocation_command": ["oraclemcp","clients","revoke",<client_id>]` with no warning that it needs a
stopped service and no mention of the online route.

**Caveat:** `clients.json` is loaded **once** at open (`client_credentials.rs:339`) into a
`Mutex<ClientCredentialFile>` (`:306`) with no reload/watch/mtime check — so even without the lock, an
out-of-process revoke would **not** propagate to a running server until restart.

---

## A.6. Remaining findings — grounded

### A.6.1 P0-2 flashback quarantine — VERIFIED, and **there is no pre-flight privilege probe**

The teardown-failure path, `crates/oraclemcp-db/src/query.rs:380-399`:

```rust
(disable, rollback) => {
    ...
    if let Err(disable_err) = disable { cleanup_failures.push(format!("DBMS_FLASHBACK.DISABLE failed: {disable_err}")); }
    if let Err(rollback_err) = rollback { cleanup_failures.push(format!("final rollback failed: {rollback_err}")); }
    Err(DbError::Quarantined {
        outcome: QuarantineOutcome::UnknownDiscarded,
        message: format!("{primary}; teardown could not prove the session clean: {}", cleanup_failures.join("; ")),
    })
}
```

The quarantine is then **structural and permanent** for that connection: the slot carries
`quarantine_reason` and every later operation fails — pinned by
`crates/oraclemcp-db/src/connection.rs` test `quarantined_thin_connection_refuses_subsequent_use`
(asserts `ping` returns `DbError::Quarantined { UnknownDiscarded, "flashback teardown failed" }`).

**No capability/privilege probe runs before entering the path.** The flashback block
(`query.rs:271-320`) rolls back (Oracle refuses `ENABLE` inside a transaction, `ORA-08183`), enables,
reads, then always tears down. `ErrorClass::FlashbackCapabilityUnavailable` /
`FLASHBACK_CAPABILITY_UNAVAILABLE` (`crates/oraclemcp-error/src/lib.rs:88`, `:778-779`) is a
**classification of an error that already happened**, not a pre-flight check. So a principal without
`EXECUTE ON DBMS_FLASHBACK` reaches `DISABLE`, fails `PLS-00201`, and the session is poisoned.

**The quarantine itself is defensible** — a session whose teardown could not be proven clean might
still be reading a stale snapshot, so refusing it is fail-closed. The defect is that a **deterministic,
knowable, cleanly-refused optional feature** is indistinguishable from a genuine teardown fault.

**Fix (in order):** (a) probe `EXECUTE ON DBMS_FLASHBACK` (or attempt `ENABLE` and classify its
refusal) **before** the point of no return, returning the typed
`FLASHBACK_CAPABILITY_UNAVAILABLE` without touching the session; (b) distinguish "feature refused
before any state change" from "teardown could not prove clean" and never quarantine the former;
(c) self-recycle a poisoned session — today `next_steps` tells clients to "acquire a fresh
connection", which **no MCP client can do**. Note both entry points: `oracle_query{as_of}` and
`oracle_diff{scn_a,scn_b}`.

### A.6.2 P0-3 dashboard `Origin: null` — VERIFIED, and the tests pin the breakage

- `Referrer-Policy: no-referrer` is emitted as **both** a header and a meta tag —
  `crates/oraclemcp-core/src/http/mod.rs:1260` (`<meta name="referrer" content="no-referrer">`).
- `dashboard_same_origin_required` is checked at **four** sites — `http/mod.rs:1392`, `:1400`,
  `:1413`, `:1421` — which is why clearing the generic origin filter with
  `--http-allowed-origin null` still fails: a second check refuses independently.
- **The tests assert the very policy that breaks browsers**: `tests_dashboard.rs:25`
  (`assert_eq!(pair.header("referrer-policy"), Some("no-referrer"))`), `:467`, `:480`, and `:341`
  asserts the `dashboard_same_origin_required` refusal. The suite is internally consistent and
  browser-blind — the same self-referential class as §A.0, and precisely why `curl` passed testing.

**Fix options:** (a) switch the pairing page to `Referrer-Policy: same-origin` (CSP already carries
`form-action 'self'`), or (b) accept `Origin: null` **only** for this endpoint when `Host` is loopback
and the one-time pairing code is valid — the code is the real authenticator. Either way the four
check sites must agree, and the tests asserting `no-referrer` must be updated deliberately, not
silently.

### A.6.3 P0-5 — CORRECTION: the server has its own pool, and it validates on **return**, not checkout

Two corrections to earlier notes in this appendix:

1. The **driver** default is `ping_interval_secs: 60` (`crates/oracledb/src/pool.rs:105`, `:120`) —
   validation is armed by default there, so "the server never arms it" was **wrong**.
2. **oraclemcp does not use the driver's pool.** `crates/oraclemcp-db/src/pool.rs` is its own
   implementation (`PoolState { idle: Vec<RustOracleConnection>, .. }`, `:186-187`).

The server pool *does* have liveness primitives — `conn.ping(cx)` (`pool.rs:58`) and
`has_broken` (`:61-62`) — **but `has_broken` is called on the RETURN path, after the call completes**
(`pool.rs:405-420`):

```rust
let result = f(cx, checkout.connection()).await;      // the call already ran
let broken = should_discard_after_call(&result, || false);
let broken = if broken { true } else { self.manager.has_broken(cx, checkout.connection()).await };
checkout.finish(broken || restore_error.is_some())?;
```

**There is no validate-on-checkout.** A connection that dies *while idle in the idle set* is handed
straight to the next caller, so the first query after an idle period always hits the dead socket and
surfaces the raw `Broken pipe (os error 32)`.

**Fix:** validate (or evict) on **checkout**, not only on return — the driver's own
`_check_connection` (`oracledb/src/pool/engine.rs:35-90`) is the reference shape; retry once on a
fresh connection after a transport I/O error; make `oracle_connection_info` perform a real round trip
(it reported `connected:true` with every liveness field null); stop leaking raw driver errors.

**RESOLVED — §A.6.9:** the pinned session is a single long-lived connection **outside** the pool,
with no validation path and no same-session recovery. The checkout fix alone is NOT sufficient; A4e
is required and is the primary fix for the field symptom.

### A.6.4 P1-1 `user[schema]` proxy syntax — VERIFIED absent in the server, AND a driver parity gap
`crates/oraclemcp-core/src/connect.rs:84-101` requires an explicit `[profiles.proxy_auth]` block with
non-empty `proxy_user` and `target_schema`, and additionally requires `username` to **match**
`proxy_user` when both are set. **No `user[schema]` detection exists anywhere in config parsing** —
the string is passed through literally and Oracle answers `ORA-01017`, indistinguishable from a wrong
password.

**Reference cross-check (review round 1):** python-oracledb 4.0.1 desugars the bracket form in
`ConnectParams` itself — `reference/python-oracledb/src/oracledb/impl/base/connect_params.pyx:511-516`
("string may be in the form user[proxy_user]"; split at the bracket), documented at
`connect_params.py:121-123`, recomposed at `:452-453`. Our driver has the **wire** support
(`oracledb-protocol/src/thin/auth.rs:190-235`, comment citing the reference's messages/auth.pyx) and
an explicit `with_proxy_user` API (`crates/oracledb/src/lib.rs:2488-2494`), but **no bracket
desugaring anywhere in `ConnectOptions`** — so a library user porting from the reference silently
gets `ORA-01017` too. That makes P1-1 a two-repo fix (B9a server + B9b driver parity).

**Fix:** B9a — detect `^(.+)\[(.+)\]$` at config load and either auto-desugar into `proxy_auth` or
fail fast naming the correct shape; B9b — reference-parity desugaring in the driver. Cheap, and it
was the single reason none of the operator's real profiles authenticated out of the box.

### A.6.5 P1-3 driver retry-masking — **LARGELY CLOSED by pushed commit `880134e`**
`880134e` ("fix(tls): fail fast on configuration errors", now on driver `main` @ `d99927d`) rewrites
the failover boundary to be **stage-aware**. From its own diff:

- a distinct post-configuration failure type whose doc states: *"The type deliberately has no
  configuration/auth/wallet variants: every value is therefore safe to aggregate and retry against the
  next address."*
- *"Only errors constructible inside `dial` can reach the failover loop. Configuration/auth errors
  remain ordinary `Error` values and have no [path in]."*
- all deterministic TLS configuration (client-config construction, wallet key validation, SNI
  decision) is validated **before** any transport attempt, so it *"fails closed here without consuming
  failover retries or the call budget."*

That is exactly the P1-3 prescription — retryable vs terminal separated **at the type level**, so a
terminal error is now *structurally incapable* of being retried into a generic timeout. `d99927d`
("test(tls): prove configuration errors precede public dial") adds the proof.

**Reference cross-check (review round 1):** python-oracledb has the SAME masking behavior we fixed —
its retry loop (`reference/python-oracledb/src/oracledb/impl/thin/connection.pyx:449-467`) swallows
every per-address exception until the very last attempt of the last address (`raise_exc` only on the
final iteration), TLS-terminal errors included; the field never saw it there only because
system-root trust made the handshake succeed (§A.6.8). So our stage-aware fix is a **deliberate,
strictly-better deviation from the reference**, not a parity regression — record it in the parity
deviations ledger (docs/PARITY_SKIPS.md conventions) so a future parity audit doesn't "fix" it back.

**Consequence for the plan:** P1-3 and driver bead `rust-oracledb-4sfc` are believed closed by work
already on `main`. **Verify before closing the bead**: confirm the specific field symptom (a cert
`UnknownIssuer` under stock `retry_count=20`) now surfaces in ~1s rather than as
`call timeout of 20000 ms exceeded`. This is a local-environment test (§ local TCPS lane), not a
production one.

### A.6.6 P1-8 session-record leak — VERIFIED: no teardown counterpart exists
Searched `connect.rs`, `oraclemcp-db/src/pool.rs`, and `oraclemcp-db/src/connection.rs` for any
logoff / logout / session-release / teardown hook. **The only "teardown" in the codebase is the
flashback window teardown** (`connection.rs:1231`, `:6233`) — unrelated. There is **no**
`logoff_statements` / `session_release_statements` counterpart to the three connect-side hooks
(`login_statements`, `login_script`, `trusted_session_statements`).

**Fix:** add a teardown hook executed before a pooled session is released and before process exit, and
ensure a clean logical Oracle logoff so `AFTER LOGOFF` triggers fire. Cross-check driver bead
`rust-oracledb-s0se` (close_notify): if sessions end by abrupt transport close rather than a logical
logoff, the trigger never runs regardless of a hook — both halves may be needed.

### A.6.7 P1-9 audit chain wrote nothing — ANSWERED: **by design**, but doctor misreports it
`crates/oraclemcp/src/main.rs:1630-1655`:

```rust
let Some(keyring) = keyring else {
    if write_reachable {                      // reachable_ceiling > READ_ONLY
        return Err(("ORACLEMCP_AUDIT_KEY_REQUIRED", "...refusing to start..."));
    }
    // Read-only everywhere reachable: no writes/escalations can occur, so no auditor needed.
    return Ok(None);                          // ← no auditor at all
};
```

So: **no `[audit]` key + a profile that is READ_ONLY everywhere reachable ⇒ `Ok(None)` ⇒ no auditor**.
The field profile was pinned `max_level = READ_ONLY` with no audit key, so no `audit.jsonl` was ever
created and the 15 blocked statements were never recorded.

**The design is genuinely fail-closed and good**: if writes *are* reachable without a signing key the
server **refuses to start** (`ORACLEMCP_AUDIT_KEY_REQUIRED`). Nothing is silently unaudited that could
mutate.

**The real defect is the doctor report.** Doctor check 13 shows ✓ and prints an audit path for an
auditor that was **never constructed**. Verified sites (review round 1 — note the correct crate):
`crates/oraclemcp-core/src/doctor.rs`, layout fields `:396-404` (`legacy_audit_path`,
`current_audit_path`, `audit_path_configured`); the audit logic at `:781-868` reasons about file
paths and legacy→XDG migration only and **never calls `build_auditor`**, so doctor cannot know
whether an auditor exists. That is a **gate that lies**, the class AGENTS.md forbids.

**Fix:** (a) doctor must report `audit: DISABLED (no signing key configured; profile is read-only
everywhere reachable)` instead of ✓-with-a-path; (b) document a concrete `[audit]` block (there is no
example anywhere in the README); (c) **product decision**: whether refusals should still be recorded
on a local unsigned trail even when no writes are possible — the tester's point that "silently
recording nothing is a weaker default than operators will assume" is fair, since the 15 refusals were
exactly the evidence an operator would want.

### A.6.8 P1-2 driver wallet-only trust store — GROUNDED AND CONFIRMED (review round 1): a real reference-parity bug

**The bug.** `crates/oracledb/src/tls.rs:297-300` (`build_client_config`) selects trust anchors as an
either/or:

```rust
let trust_anchor_ders: Vec<Vec<u8>> = match &params.wallet {
    Some(w) if !w.ca_certificates.is_empty() => w.ca_certificates.clone(), // wallet ONLY
    _ => load_system_roots(),                                              // system ONLY
};
```

Wallet present ⇒ wallet CAs only, platform roots excluded — never the union. Those anchors are the
entire trust set handed to the verifier (`tls.rs:309-315`); chain validation runs against exactly them
(`OracleServerCertVerifier::verify_server_cert`, `tls.rs:141-169`). The comment at `:294-296` claims
`ssl.create_default_context()` parity, but only the no-wallet branch reaches system roots.
`load_system_roots()` (`tls.rs:364-384`) hand-reads well-known **Unix** CA-bundle paths — empty on
Windows, no macOS keychain, and it ignores `SSL_CERT_FILE` (also the testability gap B6b closes).
Neither `webpki-roots` nor `rustls-native-certs` is a dependency (root `Cargo.toml:30-41`, absent
from `Cargo.lock`).

**The reference does the union** (python-oracledb 4.0.1, vendored at
`reference/python-oracledb/src/oracledb/impl/thin/transport.pyx`): `create_ssl_context` always loads
platform roots first (`ssl.create_default_context()`, `:135-138`; macOS keychain extras `:148-155`),
then `load_verify_locations(ewallet.pem)` **adds** the wallet CAs (`:161-168`). Reference trust set =
system roots ∪ wallet CAs — exactly why the reference client connected to the field's ADB endpoint
with the same wallet while we failed `UnknownIssuer`, and why dropping the missing public root into
the wallet dir fixed us.

**Field mechanics (scrubbed).** ADB endpoints present either Oracle's self-signed ADB-CA chain
(anchored by the downloaded wallet — the implementer's free-tier lane, which is why it always passed)
or a publicly-signed chain whose root the downloaded wallet does not carry (the field's region). A
wallet-only store can never verify the second kind; the driver's `UnknownIssuer` was *correct* for
the trust set it built — the defect is the trust set.

**Fix, stage, knobs** — see B6 (union in `build_client_config`; pre-dial prepare stage via
`prepare_tls_handshake`, `tls.rs:759-789`, so failures stay typed config errors). Existing knobs
(`resolve_tls_params`, `tls.rs:415-448`): `ssl_server_dn_match` (false skips only the post-handshake
identity match, never chain validation — audited WARN at `:428-441`), `ssl_server_cert_dn`,
`use_sni`. There is **no accept-all/danger mode** — keep it that way. The `SYSTEM` wallet-location
sentinel ("use OS store") is already handled (`oracledb-protocol/src/tls/wallet.rs:281-286`).

### A.6.9 The pinned session is NOT pooled (answers §A.6.3's open question; drives A4e/A3c)

`oracle_query` selects the pinned connection at `dispatch/mod.rs:12355`
(`state.conn.as_ref()`); it is `DispatcherState.conn: Box<dyn OracleConnection>`
(`dispatch/mod.rs:499`) — a single owned connection created once at startup and moved into the
dispatcher (constructors `:1047`/`:1108`/`:1146`, stored at `:1160`). The oraclemcp-db pool feeds
only `stateless_conn` (`:500`; selection `:12356-12359`, falling back to the pinned conn when
absent).

**No per-request liveness exists on the pinned path** — no ping/validate before use (contrast
`pool.rs:418`: return-path only, stateless conns only). A torn or cancelled round trip sets a
`ConnectionQuarantine` marker (`dispatch/mod.rs:539`) that **fail-closes** subsequent requests — a
refusal mechanism, not a reconnect. The pinned connection is re-established **only via an explicit
profile switch** (`state.conn = conn` at `:11802`, quarantine cleared at `:11786`, schema/level/
grants reset in the same commit).

**Consequences:** (1) A4a fixes only the stateless surface — the field's P0-5 ran on the pinned
path; (2) A4e (pinned liveness/reconnect with session-setup re-application, backstop re-arming,
`CURRENT_SCHEMA` re-resolution, audited quarantine clear) is the primary fix; (3) A3c's
"self-recycle a poisoned session" is the **same** missing capability — build once; (4) this explains
P2-8's "2 sessions vs `single_session`" observation.

### A.6.10 P2-4 ADB SNI routing token — the driver fix ALREADY SHIPPED; find why the field still failed

Driver `main` **and tag v0.8.4** (commit `0a1c7c6`) contain the fix the tester proposed: `decide_sni`
(`crates/oracledb/src/tls.rs:732-755`) sends an SNI only when rustls-valid, and for OCI ADB endpoints
falls back to sending the **descriptor host** as SNI (`is_oci_adb_endpoint`, `tls.rs:710-716`) — the
post-handshake DN/name match stays authoritative either way. A non-encodable token under
`use_sni=true` otherwise fails closed with typed `Error::UnsupportedSni` (pinned by tests — no silent
degrade).

Yet the field on 0.9.0 (pins `=0.8.4`) still got "use_sni=true cannot be honored… not a valid rustls
DNS name". Two leads to verify in D6/F4: (a) whether `is_oci_adb_endpoint`'s predicate missed the
field's host/service shape; (b) the **server** force-defaults `use_sni=true` whenever
`wallet_location` is set (`crates/oraclemcp-db/src/connection.rs:1863-1867`) while the driver's own
default sends no SNI — decide that server default deliberately. Verify-then-close.

**OPERATOR RULING (2026-07-20): "python-oracledb parity, fully done this time, completely and
utterly."** Concretely that means ALL of: (1) run down why the 0.8.4 carve-out did not engage in the
field (predicate verify); (2) flip the server's wallet-implies-SNI default OFF (align with driver +
reference opt-in — this is what makes a stock ADB wallet work out of the box); (3) record the one
structural parity limit honestly in the parity-deviations ledger: rustls's `ServerName` cannot carry
Oracle's routing token, so `use_sni=true` sends the host (handshake completes; Oracle's
one-negotiation-fast-path routing benefit is forgone — a documented performance nuance, not a
functional gap); (4) F4 regression on a real publicly-signed ADB endpoint. No half state survives
the train.

**Reference cross-check (review round 1) — corrects the field report's premise.** python-oracledb
does **not** send the host as SNI: it computes the Oracle service-form token
(`_calc_sni_data`, `reference/python-oracledb/src/oracledb/impl/thin/transport.pyx:47-59`:
`S{len}.{service_name}[.T1.{type}].V3.{version}`) and passes it as `server_hostname` when
`description.use_sni` is set (`:182-183`, used at `:266`/`:294`) — CPython's ssl accepts an
arbitrary ASCII token there, which is how Oracle's SNI fast-path routing (skipping one TLS
negotiation) works. rustls's `ServerName` type structurally cannot carry that token (underscores /
numeric labels fail its DNS-name grammar), so **true reference parity is impossible without patching
rustls**; the 0.8.4 host-as-SNI carve-out completes the handshake but does NOT trigger Oracle's
routing fast-path (a benign performance loss, worth one doc sentence). Sharpened conclusion for lead
(b): the server's wallet-implies-`use_sni=true` default is more aggressive than BOTH the driver
default and the reference's opt-in — flip it to omit/`false` so a stock ADB wallet works out of the
box, and let operators opt in explicitly.

### A.6.11 Driver close_notify (bead `s0se`) — VERIFIED: no driver gap; B7 moves server-side

The normal close path sends TLS close_notify: `Connection::close` (`crates/oracledb/src/lib.rs:7749`)
→ `finish_session_close` (`:756-783`) → `shutdown_write` (`:781`) → `shutdown_write_shared`
(`:9182-9189`) → transport write-half `poll_shutdown` (`transport.rs:255-263`, TLS arm `:260`) →
asupersync `TlsStream::poll_shutdown` → `send_close_notify()` (asupersync-0.3.9
`src/tls/stream.rs:631-660`, send at `:638`). The rollback-timeout path also shuts down the write
half (`lib.rs:7762`). The only skip is the intentional terminal peer-hard-close disposition
(`lib.rs:769-771`; asupersync no-ops on a terminal stream, `stream.rs:632-634`) — correct, since the
peer already closed the socket; that hardening IS what `s0se`'s merged work delivered.

**Consequence for B7/P1-8:** the session-record leak cannot be blamed on missing close_notify. The
open question is whether the **server** ever invokes `Connection::close` on its pinned and pooled
connections at clean exit and on SIGTERM (the field saw leaks on both) — plus the B7a hooks. `s0se`
itself: evidence commit + guarded close only (Z4).

### A.6.12 Legacy-3DES `ewallet.pem` — field still reports KeyDecrypt despite 0.8.4 shipping 3DES support

The field round (server 0.9.0 = driver 0.8.4) still recorded password-protected `ewallet.pem` →
`KeyDecrypt` on a legacy `pbeWithSHA1And3-KeyTripleDES-CBC` PKCS#12 key. Cosmetic in the field — the
`cwallet.sso` auto-login fallthrough works and is the intended path; it only downgraded a doctor
check to a warning. But 0.8.4's release scope included legacy-3DES decrypt with committed synthetic
fixtures, so this is a truth-in-shipping question: **verify by running the committed 3DES fixture
through the SERVER's wallet path** (doctor + connect), not only the driver's own unit test. Either
the driver fixture is self-consistent-but-unreachable (§A.0's class, once more) or the server's
wallet diagnostics bypass the driver's decryptor. Workstream P item P-U4; D6 rider.

---

## A.7. Plan implications (summary)

1. **P0-1 and P1-13 are one fix** (§A.1) — error mapping first, lock granularity second.
2. **P0-4 is four fixes** (§A.2), of which the **fail-open VPD gate** (§A.2.3) is a security defect and the
   **ordering defect** (§A.2.2) is catchable offline in one line today.
3. **P1-10 unblocks P1-13** (§A.5.1, §A.5.4) — sequence them together.
4. **P1-11 is documentation + diagnostics**, not a verifier rewrite (§A.5.2).
5. **P0-5 is a missing validate-on-checkout in the server's OWN pool** (§A.6.3) — not driver config, and
   not missing machinery: `has_broken` exists but runs only on return.
6. **P1-3 is believed already closed** by work now on driver `main` (§A.6.5) — verify the field symptom
   locally, then close driver bead `rust-oracledb-4sfc`. This is the one finding the release scope
   shrinks by.
7. **P0-2 needs a pre-flight capability probe** (§A.6.1); the quarantine itself is correct and should stay.
8. **P1-9 is a doctor honesty fix, not an audit engine fix** (§A.6.7) — the audit design is fail-closed
   and correct; doctor lies about it. Plus one product decision on recording refusals.
9. **The dominant theme of the whole round** — correct behaviour reported through a misleading message —
   is cheap to fix and, per the tester, would return more value per line changed than any 0.8.0/0.9.0
   feature. Every § here has a concrete instance: locked store → "config workflow failed"; unnormalized
   fingerprint → silent RST; missing `_meta` key → "token missing"; no EXECUTE privilege → permanent
   pool quarantine; blind catalog → silently empty reads.
10. **Wire-contract fixtures + a local live environment** are the structural answer to §A.0; without them
    this class recurs no matter how many of the above we fix. Note how many findings turned out to be
    catchable **offline**: §A.2.2 (one assertion), §A.2.4 (unit test), §A.2.3 (mock-conn test), §A.5.1/§A.5.2/§A.5.3
    (literal fixtures), §A.1 (CLI-vs-running-server test). The live environment is needed for a smaller
    set than it first appeared — mainly §A.2.7 (H1/H2 principal + catalog visibility), §A.6.5 (P1-3
    symptom), §A.6.6 (logoff triggers), and the A4e/D5 pinned-session lane (§A.6.9 settled the
    architecture question offline; D5 proves the fix).
11. **Review round 1 (2026-07-20) independently re-verified all 17 code-level claims in this appendix
    at HEAD — every `file:line` current, zero contradictions** — and resolved the three open
    questions: P1-2 grounded and confirmed (§A.6.8), the pinned session is not pooled (§A.6.9),
    close_notify has no driver gap (§A.6.11). New evidence sections added in that round: §A.6.10
    (the SNI fix already shipped — verify why it did not engage), §A.6.12 (3DES verify), §A.9
    (CI-red root causes). Scope deltas: B6 implement-directly; B5 + P2-4 verify-then-close; B7
    server-side only; A4 pinned-first.
12. **Reference cross-checks (review round 1, vendored python-oracledb 4.0.1)** informed four driver
    verdicts: P1-1 is ALSO a driver parity gap (reference desugars `user[…]` in ConnectParams —
    §A.6.4, new B9b); the reference sends the Oracle SNI **token**, not the host, which rustls
    structurally cannot carry — the field report's parity premise was wrong, and the server's
    wallet-implies-SNI default should flip (§A.6.10); the reference retries terminal TLS errors too,
    so B5's stage-aware fix is a deliberate strictly-better deviation to record in the parity ledger
    (§A.6.5); the reference also hard-errors on unknown message types, so B13 targets our desync
    source, not graceful handling (B13a). P1-2's union fix is straight reference parity (§A.6.8).

## A.8. Test-shape rules this round earned

Distilled for the plan and for AGENTS.md:

1. **Never build a test's client side with the helper the server side consumes.** Where a contract
   crosses a process/wire boundary, at least one test must use a **literal, externally-authored**
   value (a committed JWT string, a raw JSON frame, a hand-typed fingerprint).
2. **Any config field with more than one accepted spelling must be tested in its ugliest accepted
   spelling** (uppercase, unprefixed, whitespace) — normalization asymmetry is invisible otherwise (§A.5.1).
3. **A gate that reports health must observe the thing it reports on**, never infer it from
   configuration (§A.6.7 doctor vs `build_auditor`).
4. **An empty result from a privileged catalog query is not evidence of absence** — distinguish "no
   rows" from "cannot see" before making a security decision on it (§A.2.3).
5. **Ordering of session-setup statements is part of the contract** — assert the built list for each
   profile *posture* (protected / unprotected), not just the default (§A.2.2).
6. **Resource validation belongs on checkout, not only on return** (§A.6.3).
7. **Close evidence must cite commits reachable from `origin/main`** — a SHA that resolves only via a
   local branch is invisible to CI and to every other machine (§A.9, Z1). The local gate's pass is
   not evidence; reachability from the shared remote is.

---

## A.9. CI-red grounding (Workstream Z's evidence base)

Verified 2026-07-20, review round 1.

**Timeline.** Last green oraclemcp CI on `main`: `46e53c3` (06:34). Every run since `6da3997` (13:41)
red: `6da3997`, `5058690`, `6c0d5fb`, `f9a9679`, `6519a57`. Driver `main` green at `537373a`
(Required + CI + live version matrix + Kani).

**Failing jobs (run on `6519a57`).**
1. *"engine-free boundary + surface + driver-seam + honesty + conformance accounting"* → step
   "bead close evidence (native policy + post-close binding)".
2. *"changed-line coverage + mutation floor"* → step "Ratchet changed-line coverage against the
   change base".
3. *"release metadata sync"* → `scripts/release_preflight.sh`.
4. *"Rust workspace (Windows)"* → "cargo test workspace on Windows" — **new on this run**; the
   previous run's Windows lane was green on a docs-only delta (⇒ flake or environment; logs were
   unavailable at review time — only the generic exit-1 annotation).

**Mechanism ① — RESOLVED (the v2 hypothesis was wrong in the right direction).**
`SOURCE_SHA_ABSENT` hard findings for ≥15 beads. The v2 read ("SHAs exist only on unpushed
branches") was **refuted by the Z1 investigation**: a `git merge-base --is-ancestor` sweep over every
cited SHA showed **all 10 unique SHAs main-reachable**. The real cause: the `boundary` job's
`actions/checkout` had no `fetch-depth`, so its depth-1 clone could not resolve any commit older
than HEAD — the audit was auditing against a one-commit repository. Fixed by `fetch-depth: 0` (+
comment) in the same session. Branch census (`git cherry` vs `origin/main`): five of six wave
branches 100% patch-equivalent (rebase-twins — the wave's work had already been pushed via rebased
`main`); only `codex/d2-completion-20260720` carried real work (`fecfa06` guard tightening +
`e11632a` D2 floors), landed as `5a52bf6`+`3f057e2` (linearized on push). Local
`check_bead_close_evidence.sh` reported **0 hard,
227 advisory** throughout — correct, since it sees full history; the "local gate can't catch it"
lesson still stands, inverted: gate environments must match on HISTORY VISIBILITY, not only on
checks.

**Mechanism ②③** — both jobs run the mutation gate, which reads the committed marker:
`marker v=2 source=4dca0b2… scopes=guard,audit files=27 mutants=1889 shards=3/3 status=stale` →
`E_STALE_SEAL: committed mutation marker status=stale; a fresh complete five-surface campaign is
required` (`scripts/mutation_safety_gate.sh`). **Disposition: DEFERRED (§Z2, operator ruling
2026-07-21)** — the fresh seal is produced once on the release candidate, not in 0.10.0. Per-push CI
goes green via `ALLOW_STALE_MUTATION_SEAL` (set in `ci.yml` only, loud warning); the release path
never sets it, so an actual release still enforces a fresh seal.

**Driver working tree** — untracked `tests/artifacts/evidence/closes/rust-oracledb-4sfc.json` and
`…-s0se.json`; local agent branches `agent-d4-completion`, `agent-d5-recovery`,
`agent-pyshim-recovery` each 1 ahead with content already on `main` (same-message rebase duplicates;
the pyshim branch diffs empty against `main`), `agent-s0se-completion-20260720` 0 ahead (fully
merged). The local driver branch is named `master`, tracking `origin/main`, in sync.

---

## A.10. Inferred-sibling sweep (review round 2) — method and verdicts

**Method.** Every field finding was treated as an *instance of a defect class*, and both codebases
were swept for uncaught members of each class — because a field round samples instances, it does not
enumerate classes, and unswept siblings become the next round's discoveries. Classes swept:
blind-catalog fail-open (A1a's shape), assert-instead-of-observe (B8a's shape), swallowed-error
catch-alls (A2a's shape), normalize-on-validate vs exact-match-on-enforce (B1's shape),
terminal/transient conflation (B5/B13's shape), session-lifecycle asymmetry (B7's shape), unbounded
responses (B11's shape), broken printed onboarding (P1-7's shape), docs contradicting code (P2-6's
shape).

**Confirmed siblings (all folded into their workstream homes):**

| # | Sibling | Site | Folded into |
|---|---|---|---|
| S1 | Virtual-column gate: empty probe = "no virtual columns" (twin of the VPD gate) | `catalog_resolver.rs:364-376` | A1a, C8 |
| S2 | Dashboard-wide `no-referrer` → every browser POST 403s, not just pairing | `http/mod.rs:1458-1464`, `:1387-1405` | A5, C4 |
| S3 | Banner `live-db: true` is a compile-time const; `connected:true` set on any describe-Ok | `main.rs:110/:4115/:4119`; `dispatch/mod.rs:11063-11073` | A4c |
| S4 | Three divergent connection-lost lists; driver's correct set unused; 02396/00028/broken-pipe missing from lease discard-markers → **dead leased session reused**; ORA-04068 wrong-remedy | `oraclemcp-error/lib.rs:450-485`, `oraclemcp-db/error.rs:413-430/:636-651`, `resilience.rs:17` vs driver `recovery.rs:546-547` | A4b |
| S5 | Latent dead retry machinery (`RetryPolicy` zero call sites) | `resilience.rs:17` | A4b |
| S6 | `OracleConnection` trait has NO close(); switch_profile + shutdown DROP connections, never log off | `connection.rs:934-1221`; `dispatch/mod.rs:11802-11803`; `main.rs:3886/:4039` | B7c |
| S7 | DRCP `purity=reuse` identity bleed: wired path never clears-before-set; safe machinery is unwired dead code | `connection.rs:1897-1954`; former `crates/oraclemcp-db/src/lease.rs:68-102` (dead, deleted by B14b) | B14 |
| S8 | `allowed_origins` normalization applied only to loopback branch; `allowed_hosts` case-sensitive; trim-on-validate-only | `http_guard.rs:125/:91-96/:137/:85`; config `lib.rs:883-901` | B15 |
| S9 | `allowed_subjects` anchor worse than v1 stated: validator normalizes, build stores raw; symmetric pattern exists in `MtlsClientRegistry` | `lib.rs:648-660`, `main.rs:3355-3360` vs `http/config.rs:92/:107` | B1a |
| S10 | Catch-all collapses: 5 preview-flow variants; incident trio reports IO as policy refusals | `main.rs:4613/:5313/:5375/:5408` | A2a |
| S11 | Uncapped metadata tools; `get_ddl` silently truncates at 4000 bytes, no flag | `intelligence.rs:1438-1441/:1355-1394/:1413-1414`; `plscope.rs:138-168` | B11 |
| S12 | Doctor check 12 asserts keepalive/timeouts from config (contradicted by its own check 15 / driver state — verify which is stale, GH#14 closed in 0.8.4); checks 1/2 pass on compile-flag / `is_dir()` | `doctor.rs:2428-2524/:2532-2537/:1043-1097` | B8d |
| S13 | Onboarding snippets never executed by any test: header-less `claude_mcp_add`; `secure_stdio` has no client half | `main.rs:4434-4459` | B10 (P1-7), B3, C9 |
| S14 | Wallet docs claim `cwallet.sso` diagnostic-only; code + field say first-class | `README.md:994/:1221`, `configuration.md:421` vs `oci.rs:33/:340` | P-U5 |
| S15 | IAM token resolved ONCE at profile resolution, embedded static; pool re-opens/reconnects reuse the stale token; driver's `TokenSource` refresh seam (reference-parity with the callable, `connect_params.pyx:227-233`) exists but is unwired by the server; doctor claims "re-read on every connect" | `main.rs:870-880`, `pool.rs:42`, driver `lib.rs:1805/:2308/:2326`, `doctor.rs:2394-2395` | B16 |

**Verified SAFE in the same sweep (do not churn):** `/healthz`+`/readyz` (cached-observed, fail-closed
default, background pinger — `readiness.rs:33-116`, `http/mod.rs:1621-1665`); all other resolver
probes (object/synonym/db-link/arguments/column-conflict/session-context/roles) fail closed;
issuer/aud/scopes/client_id/profile-name comparisons; the stateless pool's discard-on-error
(`pool.rs:746-751`); doctor checks 3/10/11/14/15 genuinely observe.

**Correct in-repo patterns to copy (named so fixes converge):** `MtlsClientRegistry`'s symmetric
normalization (B1a/B15); `client_credential_error_message`'s preserve-inner-error (A2a); the
readiness prober's observe-and-cache honesty (A4c/A4e); `oracle_search_objects`' `detail_level`
(B11); the driver's `CONNECTION_LOST_ORA_CODES` + `is_connection_lost()` (A4b).

---

# Appendix B — traceability

| Field finding | Plan item | Appendix A |
|---|---|---|
| P0-1 `setup --write` | A2 | §A.1 |
| P0-2 flashback quarantine | A3 | §A.6.1 |
| P0-3 dashboard | A5 | §A.6.2 |
| P0-4 VPD silent-empty | A1 | §A.2 |
| P0-5 idle connection | A4 | §A.6.3 |
| P1-1 proxy syntax | B9a (server) + B9b (driver parity) | §A.6.4 |
| P1-2 wallet trust store | B6 | §A.6.8 (grounded + confirmed) |
| P1-3 retry masking | B5 (verify+close) | §A.6.5 |
| P1-4 typo → security refusal | B10 | — |
| P1-5 `oracle_orient` size | B11 | — |
| P1-6 refusal names no alternative | B10 | — |
| P1-7 setup HTTP onboarding header | B10 | — |
| P1-8 session leak | B7 | §A.6.6 |
| P1-9 audit wrote nothing | B8 | §A.6.7 |
| P1-10 mTLS | B1 | §A.5.1 |
| P1-11 OAuth | B2 | §A.5.2 |
| P1-12 stdio token | B3 | §A.5.3 |
| P1-13 credential lifecycle | B4 | §A.5.4 |
| P1-14 PL/SQL purity | B12 | §A.3 |
| P1-x `oracle_capabilities` 58.5 KB (unnumbered) | B11 | — |
| P1-x transient TTC type 129 (unnumbered) | B13 | — |
| P2-1 NODE_EXTRA_CA_CERTS doc | P | — |
| P2-2 (retracted by the tester) | none | — |
| P2-3 `current_database` over-redaction | P | — |
| P2-4 ADB SNI routing token | P (verify-then-close) | §A.6.10 |
| P2-5 config errors filed under Connectivity | P | — |
| P2-6 `--allow-no-auth` help text | P | — |
| P2-7 one `serve` per state dir | P | — |
| P2-8 2 sessions vs `single_session` | P | §A.6.9 |
| P2-9 stale-lock `kill` stderr leak | P | — |
| P2-10 discover flags + dash installer | P | — |
| P2-11 `requires_23ai` refusal masked | P | — |
| P2-12 `base=` ceiling doc | P | — |
| P2-13 `sign-tool` placement footgun | P | — |
| P2-x `oracle_search_source` line cap (unnumbered) | P-U1 | — |
| P2-x `oracle_get_source` line range (unnumbered) | P-U2 | — |
| P2-x error-grammar uniformity (unnumbered) | B10 | — |
| P2-x dashboard 403 bare text (unnumbered) | P-U3 (rides A5) | — |
| P3-x `setup` shows no proxy-auth help (unnumbered) | B9 rider | — |
| wallet legacy-3DES KeyDecrypt (unnumbered) | P-U4 (verify) | §A.6.12 |
| CI red on `main` (process, not a field finding) | Z | §A.9 |
| S1 virtual-column gate fail-open (sweep) | A1a / C8 | §A.10 |
| S2 dashboard-wide browser breakage (sweep) | A5 / C4 | §A.10 |
| S3 banner + `connected:true` honesty (sweep) | A4c | §A.10 |
| S4/S5 connection-lost classification + dead-lease reuse (sweep) | A4b | §A.10 |
| S6 no close() on the connection trait (sweep) | B7c | §A.10 |
| S7 DRCP reuse identity bleed (sweep) | B14 | §A.10 |
| S8/S9 guard-field normalization (sweep) | B15 / B1a | §A.10 |
| S10 catch-all error collapses (sweep) | A2a | §A.10 |
| S11 metadata caps + lossy `get_ddl` (sweep) | B11 | §A.10 |
| S12 doctor asserts-from-config (sweep) | B8d | §A.10 |
| S13 onboarding snippets never executed (sweep) | B10 / B3 / C9 | §A.10 |
| S14 stale wallet docs (sweep) | P-U5 | §A.10 |
| S15 IAM token no-refresh / unwired TokenSource seam (sweep) | B16 | §A.10 |
