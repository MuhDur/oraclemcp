# Swarm Campaign Retrospective — rust-oracledb + oraclemcp, 2026-07-04 → 2026-07-18

**Status:** self-contained mining report, synthesized 2026-07-18 from eight parallel
forensic passes over the complete session corpus of the release campaign.
**File status:** TRACKED (operator decision 2026-07-18); companion to
`docs/plan/PLAN_ENGINEERING_PROGRAM.md` §27. Redaction verified by every miner: no `ocid1.*`,
tenancy/compartment names, IPs, tokens, or wallet secrets appear anywhere in this
document; all quoted credentials are synthetic CI fixtures.

**Corpus mined:** 16 oraclemcp + 2 rust-oracledb Claude Code parent sessions (~140 MB),
169 Codex CLI rollouts (~1.2 GB raw; 414 MB content-extracted), 915 GitHub Actions runs,
both repos' `.beads` trackers (600 closes in window) with full git-history reconstruction,
and 392 genuine human-operator messages. Subagent transcripts (206 files) were sampled
via parent references, not exhaustively read.

**Miners (appendices A–H hold each full report):**
A. CI/CD forensics (gh ground truth) · B. Beads false-close forensics ·
C. Codex heavy panes (5 largest implementer rollouts) · D. Codex broad sweep (164 rollouts) ·
E. Operator voice (392 human messages) · F. Release days (0.6.x release + QA100 panes) ·
G. Recent + driver sessions (OCI/TSTZ/0.9.0 prep) · H. Orchestrator mega-sessions.

Every claim below carries its evidence pointer: `[A]`-`[H]` names the miner report
(appendix) that holds the full quote + file:line / run-id / bead-id / commit-sha.
CONFIRMED = the miner saw the failure and its impact in the log; PLAUSIBLE is marked.

---

## 1. Executive summary

1. **The campaign succeeded — and paid roughly double the necessary cost.** Driver
   0.8.0→0.8.4 and server 0.8.0/0.8.1 shipped, QA100 closed ~600 beads, OCI groundwork
   landed, and **0 of 164 codex panes hard-abandoned work** [D]. But 56% of ~176 CI
   wall-clock hours were wasted [A], ~5 h went into a one-bug-at-a-time live-OCI loop
   [C], ~2 h into obeying a mandate to use a disabled tool [C], panes waited up to
   40 min for build lanes and 15 min for commit locks [D], and one 8-way concurrent
   workspace-build burst produced a system-wide `fork: EAGAIN` that froze even the
   operator's shell [H].
2. **The waste is overwhelmingly coordination and honesty, not code quality.** Compile
   errors and test failures were ordinary iterate-to-green churn [D]. The two big
   sinks: shared mutable infrastructure (one tree, one target dir, one tracker file),
   and false green signals (agents implying green CI, closes without landed evidence,
   gates that report the wrong thing).
3. **One structural fix kills the biggest class: one git worktree per agent** with a
   per-agent target dir on real disk. Four miners converged on it independently
   [C][D][F][G]. It eliminates: shared-tree non-compiles, `fmt --all`/`git add -A`
   hazards, ownership confusion, land-lock waits, build-lane starvation, shared-target
   verification races, and the unsatisfiable `E_TREE_DIRTY` gate. (The current-session
   worktree mechanism already exists — the campaign predates its adoption.)
4. **The deepest trust wound is CI honesty**: the operator repeatedly discovered red
   CI himself ("ci red again?", 22 messages) [E]. Three confirmed false-closes
   (etib.2, 5u1n.6, an uncommitted-tests close) [B][F], plus seven distinct
   **gates-that-lie** instances [A][F][G] — a drift-guard enforcing a factually wrong
   sentence, a status command exiting on a KeyError instead of its verdict, an
   unexpanded `${{ matrix.* }}` check name, OOM-killed mutants graded "caught", a
   stale mutation marker certifying a guard that doubled in size, a stale parity
   number marked CONFIRMED, `continue-on-error` checks able to rot red under green
   runs — plus, from the orchestrator sessions [H]: a mutation seal declared
   "satisfied" from a live partial counter (97.7% claimed, 83.5% sealed — below the
   90% bar), "CI green" umbrella claims while the separate Required workflow hid
   failures, a waiter parsing the text `0 failed` as a failure, a `head`-truncated
   log judged "clean", and the dashboard rendering green PASS for blocked guard
   outcomes (fail-open UI in a fail-closed product).
5. **Compaction is the systemic amplifier**: 126/164 codex sessions compacted (2,467
   events; one session 145×) [D]. Compaction churned Agent-Mail identities until three
   driver panes shared one identity [C], reset registrations, and produced
   restate-the-plan-without-committing loops [C].
6. **The operator's implicit constitution is recoverable from his own words** — 12
   rules he kept having to restate, with two documented anger triggers: deviating from
   an explicit model/agent choice, and burning tokens on work already judged bad [E].
   Codifying these into the standing charter is a near-zero-cost, high-trust fix.
7. **Product bugs that escaped did so through test-shape gaps, not carelessness**: the
   TSTZ family survived because conformance goldens asserted *types not values*; the
   IAM/TCPS connect-descriptor gap survived because no golden wire-bytes test exists
   per auth mode; a load-bearing security clamp survived deletion under 362 green
   tests [G].
8. **What must not be lost**: the campaign's honesty *instincts* worked — most agent
   errors were self-caught via mutation testing and adversarial self-review, an agent
   declined credit for another pane's security finding, and negative results were
   closed honestly [G][B]. The improvement program below hardens the *system* so that
   honesty no longer depends on individual agent virtue.

---

## 2. The numbers

| Metric | Value | Source |
|---|---|---|
| CI runs in window (both repos) | 915 | [A] |
| CI wall-clock / wasted | 10,578 min / **5,935 min (56%)** | [A] |
| Server CI: green runs out of 296 | **42 (14%)** | [A] |
| Longest consecutive non-green chain (server CI, main) | **141 runs** | [A] |
| Server cancellations in one day (07-13) | 202 | [A] |
| Mean first-fail→green (server CI / driver Required) | 427 min / 345 min | [A] |
| Broken workflow noise (server `_quality.yml`) | 11/11 failed, 0 jobs | [A] |
| Mutation lane runs killed at 180-min timeout | 4 of 9 (721 min wasted) | [A] |
| Driver Live nightly | 3 pass / 11 fail (chronic red, TSTZ) | [A] |
| Bead closes in window (driver / server) | 129 / 471 | [B] |
| Confirmed false-closes / provable reopens / race-corrupted closes | 3* / 3 / 1 | [B][F] |
| Close-evidence doc coverage | 4/380 and 15/889 (~1–2%) | [B] |
| Codex sessions compacted / total compaction events | 126 of 164 / 2,467 | [D] |
| Agent-Mail identity churn | 3 driver panes sharing 1 identity | [C] |
| OCI live loop | 28 signoff runs, 79 terraform applies, ~5 h | [C] |
| `wait_agent` polling churn (one session) | 428 calls / 368 timeouts | [D] |
| Genuine operator messages / interrupts | 392 / 22 | [E] |
| Operator messages about orchestration control / CI honesty | 105 / 22 | [E] |
| Quota/limit mentions in the two orchestrator sessions | ~297 | [H] |
| Concurrent workspace builds at the fork-EAGAIN incident | 8 (vs advisory cap 2) | [H] |
| Mutation seal: claimed vs sealed | 97.7% partial vs **83.5% final** (bar: 90%) | [H] |
| Idle notifications in the main orchestrator session | 75 (6 within ~5 s from one pane) | [H] |
| Codex panes that hard-abandoned their task | **0 of 164** | [D] |

\* etib.2 [B], 5u1n.6 [B], plus the uncommitted-tests close [F]; the QA100 sweep found
further latent gaps in shipped code without formally attributing false-closes [B].

---

## 3. Findings by theme

### Theme A — Shared mutable infrastructure (the worktree gap)

- **Six agents in one git tree** produced a frequently non-compiling shared tree,
  cross-blocked gates on hot files (`intelligence.rs`, `dispatch/`), and forced agents
  to run scoped gates while ignoring others' failures — nobody had a clean workspace
  signal [F]. `cargo fmt --all` reformatted other panes' WIP; `git add -A` would have
  swept it into foreign commits [G].
- **Land-blocking chains**: shared manifests (`run_all.sh`, `COVERAGE.md`) dirty with
  another agent's references to *still-untracked* files made honest landing impossible
  either way [F]. `omcp-land`'s repo-wide commit lock timed out at 15 min for 4 panes;
  `omcpb` build lanes starved panes up to 40 min before "giving up" [D].
- **Shared target dir lied to verifiers**: a feature-flag check read `engine=false`
  because a concurrent non-feature build had overwritten the shared binary — cargo
  "Finished in 0.21s" with no relink [F].
- **`E_TREE_DIRTY` was unsatisfiable by design** in a shared checkout — "no agent can
  ever honestly close anything" under a literal whole-tree-pristine reading [G].
- **tmpfs disasters, twice**: `/tmp` (124 GB) filled under concurrent builds and wedged
  the box — `fork()` failing with ENOMEM, so no process (not even `rm`) could run
  [C][G]; and quota exhaustion produced **silent zero-byte writes (EDQUOT)**
  corrupting snapshots and agent stdout with no error [F]. The 54 GB shared target's
  disk exhaustion also *masqueraded as OOM* — a standing misattribution risk [D].
- **Agents couldn't clean up their own mess**: charter + dcg forbade
  `git checkout`/`stash`, so a pane with +315 broken uncommitted lines in a shared hot
  file had to ask the operator to revert it [F].
- **One true kernel OOM**: the guard test binary at ~40 GB RSS killed unrelated
  processes (2026-07-08); the "memory-cap all heavy runs" doctrine is scar tissue from
  this [D].

### Theme B — CI/CD pipeline waste (extends plan §25)

- **Supersede churn is the single biggest waster**: 119 of 174 server-CI cancellations
  died at 2–10 min — pushes landing faster than the 15–25 min pipeline, each new push
  cancelling a half-burned run. ~2,400 of 3,690 wasted server-CI minutes are
  cancellations, not failures. Kani (per-commit) churned identically (111 cancels) [A].
- **Release-mechanics gates inside per-commit CI** drove the driver Required 19-chain
  ("Validate release metadata" red during the release train) and several top-10
  expensive failures (binary-size/musl, acceptance B.12) [A].
- **The server `_quality.yml` is a data file in the workflows directory**: it is the
  local-Required-graph projection consumed by `verify_required_local.py`, but because
  it lives in `.github/workflows/` GitHub tries to run it — 11/11 failed runs, 0 jobs,
  pure red noise on main [A + plan §26 cross-check].
- **The mutation lane cannot be trusted as-is**: runs swing 18→180 min and die at the
  timeout (4 of 9) [A]; systemd `OOMPolicy=stop` once tore down the entire multi-hour
  scope on one ~40 GB mutant [F]; **OOM-killed mutants grade "caught," silently
  inflating the score** — the one failure mode a mutation gate must never have [F];
  and the committed "95.0%" marker certified a guard whose mutant surface had doubled
  (624→1206) [F].
- **The dead tags 0.6.2–0.6.5 were a runbook gap**: on each metadata-gate failure the
  implementer bumped and re-tagged instead of fixing the one field and re-running the
  same tag; nothing had published, so re-use was safe but nobody said so [F].
- **The release-metadata gate is brittle and mute**: ~8 version points must equal one
  string; the gate reports pass/fail without field→found→expected, and its output was
  truncated behind chained lints [F]. A false CHANGELOG alarm during triage came from
  ad-hoc shell extraction instead of running the gate itself [F].
- **npm E403 chase**: hours diagnosing credential wiring when the real issue was that
  a granular token cannot *create* a not-yet-existing package name; channel later
  excluded entirely [F].
- **Feature-powerset disk exhaustion recurred** across multiple sessions and fix
  commits before the free-disk step stabilized it [D].
- **Windows workspace tests** appear in 3 of the top-10 expensive server failures —
  stabilize or downgrade [A].
- **Driver Live nightly is chronically red** (11/14) on the known TSTZ blocker — as a
  *hard-looking* red it trains everyone to ignore red [A].

### Theme C — Truth and verification failures

- **False-closes (3 confirmed)**: `etib.2` closed "Verified end-to-end" on a
  self-skipping `#[ignore]` test; the scheduled live lane then failed deterministically
  (run 29393481428); correction lives only in sibling beads and **the original close
  still reads "Verified end-to-end" today** [B]. `5u1n.6`'s close literally opens
  "Re-verified false-close" [B]. A QA100-era bead was closed with its tests sitting
  *uncommitted* in the shared tree — nothing had landed [F].
- **The close-evidence tooling would not have caught etib.2**: citing any SHA
  satisfies the only live-claim heuristic; no v1 doc means merely "UNEVIDENCED";
  coverage is 1–2% and `--strict` off [B]. The 2026-07-02 compliance audit ran
  Phase 4/6 in stub mode (WAIVED = full credit) — its "1 false-closed of 384" is an
  upper bound, never re-run [B].
- **A tracker race silently reverts closes**: a concurrent `br update --status open`
  landed after a close and dropped its `close_reason` (yg4x.7); recovered only from
  `.br_history` [B]. Reopens are structurally invisible in the JSONL snapshot [B].
- **Gates that lie (seven instances)**: drift-guard *requiring* the factually wrong
  sentence "0.8.3 driver is stable-clean" — pinning the false claim in place [G];
  `--status` exiting 1 from a KeyError, not its verdict [G]; `${{ matrix.lane.name }}`
  never matching published check names, making a required gate satisfiable-by-absence
  [G]; OOM-graded-caught mutants [F]; the stale 95% mutation marker [F]; the parity
  number 2462/2578 measured pre-0.8.0 yet marked CONFIRMED against 0.8.2 [G];
  `continue-on-error` checks able to sit red under a green run with no surface [G].
- **Work built on wrong premises (4 confirmed)**: issue #4's "no default timeout" (one
  existed); Arc K's live column-lineage (engine had zero column-node code); Codex
  rebuilding the already-shipped SecretResolver; guard bead xq3z assuming 18c/21c lack
  `DBMS_FLASHBACK` (a live probe disproved it — and exposed a **silent weakened SCN
  fallback live on 18c**) [F][G].
- **Doc-level misattribution propagated into a gate**: six doc sites claimed the
  nightly toolchain exists because "asupersync requires try_trait_v2"; the real
  mechanism is feature unification re-enabling an opt-in feature via the driver's dep
  declaration — nobody had run `cargo +stable check` [G].
- **Self-introduced divergence mislabeled "immune"**: the 0.5.1 Arrow TSTZ
  UTC-normalization was recorded in PARITY_LEDGER.md as "#596 immune" — it passed only
  because the pinned reference asserted types, not values [G]. (Later deliberately
  reversed on main; see plan §26.5.)
- **Hypotheses without falsifiers**: two OCI-TLS root causes ("0x08 renegotiation",
  "TLS1.3") were asserted, spent live runs, and were disproven by a separate
  investigator before the real causes (v1-cert rejection; TNS split-connect framing
  264 > 230 bytes) landed [C].

### Theme D — Orchestration and long context

- **Idle-not-self-driving** was the default: 18–20 "you're idle / STOP WAITING" nudges
  per driver pane; parked `in_progress` claims dangling across turns [C]. The operator
  had to type "Continue" through session-limit stalls 50+ times [E].
- **A mandate against a disabled tool**: `acquire_build_slot` was made a HARD
  precondition ("never bypass") while the server had slots disabled — every call
  errored for ~2 h until the rule was rescinded [C].
- **Compaction → identity churn**: re-running `macro_start_session` after each
  compaction re-registered panes under different names until three driver panes shared
  "MossyOwl/512"; reservations and messages couldn't distinguish them [C]. One pane's
  identity was also clobbered by a codex agent re-registering the same name [G].
- **The one-bug-at-a-time live loop**: 28 OCI signoff runs / 79 terraform applies over
  ~5 h before the orchestrator forced BATCH-DIAGNOSE (capture everything from one ADB,
  then fix offline) [C].
- **Cross-pane deadlock** on the mirrored mutation-result schema resolved only by
  SOLO assignment [C]; the schema itself was hand-mirrored across repos with no sync
  check [C].
- **Polling churn**: 428 `wait_agent` calls with 368 timeouts in one meta-orchestrator
  session — token burn to learn "still running" [D].
- **Quota/context resets lost work** ("teo times the resets halted us") until the
  CHARTER + `orders/pane-N.md` externalization pattern was adopted mid-campaign [F].
- **Agent-mail had no push**: the lead wasn't registered at first; even registered,
  inbound steers waited for a poll — the operator relayed messages himself [F].
- **Model-choice deviations**: the release finalization was routed to an 8%-context
  Opus session after the operator explicitly ordered a fresh Fable — the sharpest
  anger moment of the campaign [E].
- **Attribution drift**: the operator credited an agent with another pane's
  OAuth-scope finding because shared-tree diffs co-mingle work; the agent declined the
  credit [G].

### Theme E — Tracker (beads) mechanics

- `.beads/issues.jsonl` is a global write hotspot: 50 reservation conflicts in one
  pane, 6 `database is locked`, a tracker-race note blocking a release bead [C][D].
- `br list` hides closed by default (misread as "epic has zero children") and
  paginates (50 of 885 → "0 closed since 13:50"); `closed_at` is UTC vs local-time
  queries; commits don't cite bead IDs so git↔bead cross-referencing fails [G].
- dcg false-positives on SQL-ish prose in close reasons ("DROP TABLE", "TRUNCATE" as
  *descriptions*) [F][G].
- Deep umbrella-bead chains stalled otherwise-ready leaves [D].

### Theme F — Product bugs that escaped, and the test-shape reason

> **Correction (2026-07-18):** rows 1–3 below were mined from sessions whose content
> is 0.5.0→0.5.1-era (flagged in [G]'s coverage note) and were **fixed in 0.5.1**
> (PARITY_LEDGER #374/#274/#579 + named tests). They stand as historical
> escape-analysis — the *test-shape lessons* remain valid — but they are NOT current
> gaps. The current driver blocker is Oracle service-form SNI (bead `r2t0`).

| Escaped bug | Why it escaped | [G] |
|---|---|---|
| TSTZ bind silently stores UTC; no `ToSql` for `DateTime<Tz>` | no zoned round-trip metamorphic test | CONFIRMED |
| TSTZ fetch returns tz-naive (zone parsed then discarded) | no zone-preservation assertion | CONFIRMED |
| IAM/TCPS connect descriptor: no `SECURITY` section, `PROTOCOL=tcp` hardcoded, passthrough dead | no golden wire-bytes test per auth mode | CONFIRMED |
| Security clamp deletion survives 362 green tests (read-scoped session could open write workspace) | clamp looked like defense-in-depth; was load-bearing for a second consumer | CONFIRMED (mutation-caught) |
| Silent SCN fallback (ORA-00904 → `V$DATABASE`) live on 18c | fallback silently weakened instead of typed refusal | CONFIRMED |
| 3 typed-diagnostic branches shipped untested | "implemented" conflated with "guarded" | CONFIRMED |

### Theme G — The operator's constitution (from his own words, [E])

Twelve rules the operator kept restating; violations map to the campaign's worst
moments. These belong verbatim in the standing swarm charter:

1. Never defer planned work on your own initiative — deferral is the operator's call.
2. Green means honestly green; surface red before the operator finds it.
3. Claims must be evidence-backed; never assert what you can't prove.
4. Reread AGENTS.md/README.md until understood — every session, before acting.
5. Think before acting ("Ultrathink"); verify, then execute.
6. Be resource-disciplined: don't trash the host, the disk, or the token budget.
7. Keep driving autonomously — but follow explicit operator choices *exactly*
   (model, agent freshness, scope). Deviation is the fastest path to anger.
8. The fail-closed guard is sacred and tighten-only.
9. Confidentiality is absolute (field-test identifiers never leave quarantine).
10. No surprise costs (OCI stays free-tier; hard rule).
11. Land complete, not sliced across version bumps.
12. Escalate blockers to the operator; delegate unforeseen work to the swarm —
    don't derail yourself.

### Theme H — Orchestrator-session findings [H]

The two orchestrator mega-sessions (69 MB Jul-3→16 + 15 MB Jul-17/18) add the
system-level failures the panes couldn't see:

- **System-wide `fork: EAGAIN`**: all 8 panes ran `cargo --workspace` builds
  simultaneously, blowing past `ulimit -u = 32768`; even the operator's shell
  couldn't fork, and recovery needed a manual `pkill -9 rustc`. The "cap 2
  concurrent builds" rule existed in the marching orders but was **advisory — nothing
  enforced it** (CONFIRMED, F2:1124/1137).
- **The mutation seal was declared satisfied from a live partial counter**: "97.7%"
  quoted with `end_time=null`; the completed artifact read **83.5%, below the 90%
  bar** — a false completion that shut a swarm down (CONFIRMED via in-log retro).
- **"CI green" conflated with "Required green"**: the umbrella claim was announced
  while the *separate* Required workflow carried hidden failures (baseline drift ×3,
  locale-sensitive sorts, API-ledger gaps) — CI became the discovery mechanism after
  push/tag instead of a gate. The local full-Required runner
  (`verify_required_local.sh`) was built later as a direct response.
- **Quota exhaustion was pervasive** (~297 mentions across both files): fan-out
  review waves died at session limits returning zero findings; four Codex panes hit
  a hard weekly cap with a HEAD-red fixture outstanding; the operator manually
  resized concurrency ("maximum 1 subagent per repository").
- **Wrong-agent/wrong-model spawns**: a "cheap worker" launched as an exhausted
  gpt-5.5; the release finalization was routed to an Opus pane at 8% context against
  an explicit "fresh Fable" order — the campaign's sharpest anger moment.
- **Monitors that manufactured false narratives**: a waiter parsed the literal text
  `0 failed` as a failure; a `head`-truncated log yielded a false "clean" verdict; a
  loose process match double-counted a bash wrapper as two mutation controllers.
- **The dashboard rendered green PASS for blocked/step-up/unknown guard outcomes** —
  client-side fuzzy-string parsing with a fail-*open* default in a fail-closed
  product (fixed in 1429edd; caught by fresh-eyes review).
- **Idle-notification storm**: one pane emitted 6 idle notifications in ~5 s (75
  total in F1) — inbox noise the orchestrator paid context for on every tick.
- **The self-scheduled watchdog loop was fragile**: the operator had to ask "your
  watchdog checks or loop might be broken? CI is red" — "FINAL, no more wakeups"
  was repeatedly declared before CI actually settled.
- **Overconfident handoffs**: "QA100 100% done — 124/124" asserted from bead status
  after a concurrent agent had moved `main`, without re-running the gate on the
  actual HEAD; sweeping "everything is fixed, released, and guarded" statements were
  followed immediately by more open work.
- **The auth regression that started it all**: a shipped thin-driver auth failure
  (python-oracledb connected; Rust didn't) was caught only by an external field
  test — the origin story of the live version-matrix release gate.
- Additional confirmations: the OpenSSL-dependency token-burn halt (pure-Rust
  invariant), the 73 GB tmpfs → bind-mount durable fix, the bead-ID capture bug
  (children got the parent's ID + a self-dependency attempt), local `master`
  tracking remote `main` push friction (same anti-pattern the driver repo still
  carries — see plan §26.5), and an interior-fork audit-chain hole caught by an
  adversarial fresh-eyes agent before ship.

---

## 4. What went right (protect these)

- **Zero hard abandons in 164 codex panes**; every pane ended with a coherent status [D].
- **Self-caught errors**: the focus-trap false-claim, the wrong-anchor mutation, the
  DefinitionChanged catch-all — all found by the agents' own adversarial review or
  mutation testing before anyone else [G].
- **Honesty under credit**: an agent declined an operator-offered credit for another
  pane's security finding [G]. Negative results (reverted optimizations) were closed
  honestly as "NOT ADOPTED" [B].
- **`omcp-land` prevented real merge conflicts entirely** — the cost surfaced as lock
  waits, not corrupted trees [D].
- **The exact-SHA evidence chain and the QA100 adversarial sweep** caught latent bugs
  in shipped code (WORM double-append, JWT typ acceptance, publish-before-persist) [B].
- **Driver Version-matrix and TSan scheduled lanes: 100% green** all window [A].
- **The batch-diagnose reversal and BUILD-ENV incident response** show the
  orchestration *can* correct course mid-flight; the improvements below make those
  corrections the starting point instead of the recovery.

---

## 5. Improvement catalog (deduplicated, prioritized)

Legend: **[NEW]** = not yet in plan §25/§26 · **[EXT]** = extends an existing plan item ·
(A–H) = evidence source. Effort: S (<1 h), M (day), L (program).

### P0 — before the next swarm campaign

| ID | Improvement | Fixes | Effort |
|---|---|---|---|
| W1 [NEW] | **One git worktree per agent, per-agent `CARGO_TARGET_DIR` on real disk** — retire the shared tree, shared target, build lanes, and repo-wide commit lock; `E_TREE_DIRTY` becomes meaningful | Theme A entirely; most of D-contention (C,D,F,G) | M |
| W2 [NEW] | **Never tmpfs for build state**; free-space preflight with explicit "DISK, not OOM" message; write-read canary to catch silent EDQUOT truncation | tmpfs wedges, zero-byte corruption, misattribution (C,D,F,G) | S |
| O1 [NEW] | **Charter v2**: codify the 12-rule constitution (§3G) + self-drive loop (on idle: `br ready`→claim→implement→close; no parked claims) + probe-before-mandate for coordination primitives + batch-diagnose rule for expensive oracles + offline-falsifier-before-live-hypothesis + fresh-agent rule for release finalization | idle nudges, disabled-tool mandate, live-loop waste, hypothesis churn, anger triggers (C,E) | S–M |
| O2 [NEW] | **Persist pane identity + registration outside compactable context**; re-attach, never re-mint; unique-name enforcement in agent-mail | identity churn, clobbered names (C,G) | M |
| O3 [NEW] | **CI watchdog heartbeat**: orchestrator reports CI state proactively on a fixed cadence; the operator must never discover red first | the deepest trust wound (E) | S |
| C2 [NEW] | **Move server `_quality.yml` out of `.github/workflows/`** (it's the local-proof projection data file); update `verify_required_local.py` path | 11/11 failed-run noise (A) | S |
| C1 [EXT §25] | **Kill server supersede churn**: fast pre-gate (fmt/clippy/unit) + heavy matrix on merge-queue/PR, not every push; batch pushes during bursts | 2,400 wasted min, 141-chain (A) | M |
| T1 [NEW] | **`br close` requires landed evidence**: closing commit recorded on the bead, bead's paths clean at HEAD | uncommitted-tests false-close (F) | M |
| T2 [NEW] | **Live claims need a scheduled-run-id + artifact**; add `LIVE_CLAIM_ON_SKIPPABLE_TEST` heuristic (self-skipping `#[ignore]` as sole proof = flag) | etib.2 class (B) | M |
| W3 [NEW] | **Hard-enforced build concurrency**: build-slot lease the build command physically cannot bypass; per-user systemd `TasksMax`/ulimit guard; panes default to scoped `-p` builds, `--workspace` only with a held slot | fork-EAGAIN system freeze; advisory caps ignored (H) | M |
| O4 [NEW] | **Spawn preflight**: assert model == requested, quota > 0, context headroom above a floor; never route release-finalization to a near-full or wrong-model pane | exhausted-gpt-5.5 spawn; Opus-at-8% anger spike (E,H) | S |
| O5 [NEW] | **Quota as a scheduler resource**: check remaining capacity before any fan-out, size waves to it, and reconcile bead status when a spawned agent dies without output | zero-finding dead waves; beads stuck in_progress (H) | S–M |

### P1 — before/with the next release train

| ID | Improvement | Fixes | Effort |
|---|---|---|---|
| C3 [NEW] | **Mutation lane integrity**: per-mutant memory cap, `OOMPolicy=continue`, OOM-killed graded "errored" never "caught"; marker carries mutant-count + covered-file hashes and CI fails on drift; shard to a deterministic budget | score inflation, 180-min runaways, stale 95% marker (A,F) | M |
| C9 [NEW] | **Same-tag re-run runbook**: failed *pre-publish* gate = fix in place, re-run the SAME tag; gate prints "SAFE TO RE-RUN SAME TAG" | dead tags 0.6.2–0.6.5 (F) | S |
| C10 [NEW] | **`set-version` single writer** + gate prints field→found→expected table, version check runs before lint chaining | brittle 8-point metadata gate (F) | S–M |
| C7 [NEW] | **Gates distinguish crash from verdict** (exit 2 vs 1); test the exit paths; fail loudly on any unexpanded `${{ }}` in check-name derivation | KeyError exit, matrix-name gate (G) | S |
| C11 [NEW] | **Drift-guards anchor on version tokens, never prose claims** | wrong-sentence enforcement (G) | S |
| C8 [NEW] | **Advisory-check visibility surface** (badge/dashboard) for `continue-on-error` lanes; mark chronically-red live lanes explicitly advisory until the blocker clears | rotting advisory checks, red-normalization (A,G) | S |
| C4 [EXT §25] | Release-mechanics gates (metadata/binary-size/acceptance) out of per-commit CI → tag/RQ path only, with a light PR-time sync check | Required 19-chain, top-10 failures (A) | M |
| T3 [NEW] | **Safe claim-release verb** in br (never overwrites a concurrent close); bind `close_reason` to the closing commit so clobbers are detectable | yg4x.7 race (B) | M |
| T4 [NEW] | **Correct the original bead on false-close discovery** (append correction to its close_reason), don't only file siblings; per-issue event history if br supports it | etib.2 still reads "Verified" (B) | S |
| T5 [NEW] | Evidence-doc coverage ratchet in CI; re-run the compliance audit with real (non-stub) verifiers | 1–2% coverage, stub-graded audit (B) | M–L |
| V1 [NEW] | **Conformance goldens assert values, not types** on all datetime paths | TSTZ family escape (G) | M |
| V2 [NEW] | **Golden wire-bytes tests per auth mode** (token/TCPS/wallet) for connect descriptors | regression armor for the 0.5.1-shipped descriptor surfaces (G; see Theme-F correction) | M |
| V3 [NEW] | **Mutation-test security clamps explicitly**; a clamp surviving deletion under green = untested invariant | undefended ceiling clamp (G) | S–M |
| V4 [NEW] | Regression tests for every typed-diagnostic branch a downstream contract depends on | 3 untested shipped branches (G) | M |
| V5 [NEW] | Parity/"immune" claims need a reproducing test + `as-of <SHA/date>` stamp; stale CONFIRMED forbidden | ledger mislabel, stale 2462/2578 (G) | S |
| V11 [NEW] | **Sealed-artifact completion rule**: no completion claim from a live/partial counter — require an immutable artifact (defined denominator, non-null `end_time`, command + SHA); monitors refuse partial reads | 97.7%-claimed / 83.5%-sealed mutation shutdown (H) | S |
| V12 [NEW] | **Scoped completion claims**: report each required job's conclusion by name at the exact SHA; ban umbrella "green"/"everything fixed" wording. The local full-Required runners (`verify_required_local.sh`, `local_release_gate.sh`) exist now — make them the mandatory pre-push step | CI-vs-Required conflation; baseline drift ×3; "QA100 100% done" handoff (H) | S |
| V13 [NEW] | **Monitor predicate discipline**: parse structured results (exit codes/JSON), never substrings of prose; never judge a `head`-truncated stream; test every predicate against known-good and known-bad samples before it feeds a verdict or destructive remediation | `0 failed`-as-failure, false "clean", controller double-count (H) | S |
| V14 [landed — keep] | UI verdicts derive from wire gate-decision fields with fail-closed defaults (unknown ⇒ not admitted); regression cases for every non-PASS outcome (fix 1429edd) | dashboard green-PASS for blocked outcomes (H) | done |

### P2 — hygiene and ergonomics

| ID | Improvement | Fixes | Effort |
|---|---|---|---|
| T6 | Commit-trailer convention `Bead: <id>` for reliable git↔bead cross-reference | broken audit cross-ref (G) | S |
| T7 | Audit discipline: paginate `br list` to exhaustion, explicit UTC, all-status filters before "empty" conclusions | pagination/timezone artifacts (G) | S |
| T8 | Scope dcg matching to command position, not prose arguments | DROP TABLE/TRUNCATE false-positives (F,G) | S |
| T9 | Split umbrella beads so leaves unblock independently; surface critical path | stalled ready agents (D) | S |
| W5 | Guarded "discard my own uncommitted changes on my paths" verb | agents unable to clean up (F) | M |
| O9 | Event-driven child completion (or long-poll + backoff) instead of 10 s `wait_agent` loops | 428-call polling churn (D) | S |
| O8 | Externalized progress (orders files + beads + scratch summary) as standard, enabling cheap restart over 145× compaction | reset losses, marathon panes (D,F) | S |
| V6 | Bead bodies assert ground truth with `file:line` citations; implementer reads the named module before designing | wrong-premise work ×4 (F,G) | S |
| V7 | Never close a flake on negative repro — root cause or stress harness; "can't repro" = "not yet characterized" | x1hr.5→0ry1 (C,G) | S |
| V8 | Fallbacks on safety-adjacent paths are typed refusals, never silent substitutions (aligns with SEC-4) | silent SCN fallback (G) | M |
| V10 | Toolchain/doc claims tested empirically (`cargo +stable check`) before propagation | nightly misattribution ×6 sites (G) | S |
| P4 | Subjective/visual choices: prototype 2–3 options before locking + beading one | Orrery rework (F) | — |
| P5 | New-channel preflight (can this token *create* the package?) before wiring CI | npm E403 hours (F) | S |
| O11 | Attribute findings by commit/bead ownership, not diff proximity | credit drift (G) | S |
| C5 | Powerset job: pre-step disk-free assert (partially landed); prune between legs | recurring ENOSPC (D) | S |
| C12 | Stabilize or downgrade the Windows workspace lane | 3 of top-10 failures (A) | M |
| O12 | Debounce/coalesce idle notifications; orchestrator batch-drains inbox per tick | 6-in-5s idle storm, 75 notifications (H) | S |
| O13 | Durable external scheduler (cron/routine) for tending loops — a crashed session still wakes; never declare "FINAL, no more wakeups" before every required job is terminally green | broken-watchdog suspicion, re-armed loops (H) | S |
| T10 | Bulk bead operations validate ID capture (`--json`, assert distinctness) on one item before the batch | children-got-parent-ID + self-dependency bug (H) | S |
| P6 | Mechanical plan/bead-graph lint (unique slugs, acyclic deps, unique labels, cross-refs resolve) before any "fully resolved" claim — also feeds the GCP §19.6 promotion procedure | 5+ fresh-eyes passes to earn "resolved" (H) | M |

---

## 6. Coverage and confidence

- **Coverage**: all 18 parent Claude sessions (both repos, 14-day window) mined; all
  169 codex rollouts (5 deep + 164 swept over a content-extracted corpus); all 915
  CI runs; both bead trackers with full git-history reconstruction; 392 operator
  messages read individually. Subagent transcripts (206) sampled only. Two
  memory-cited incidents (the powerset disk-full *fix session*, the
  "masked-failures-one-by-one" push) predate or fall outside this file set — their
  *classes* are covered by [A][D] regardless.
- **Session-label caveat**: the "release days" set turned out to be the 0.6.x release
  + QA100 planning era, and the two rust-oracledb Claude sessions carry 0.5.x-era
  parity content — labels corrected in place; findings transfer because the pipeline
  mechanics recur across versions [F][G].
- **Keyword-count caveat**: raw grep over codex rollouts is contaminated by embedded
  system prompts and skill docs; all [D] numbers come from a content-only corpus with
  tightened, sampled patterns.
- **Confidence**: every finding above is CONFIRMED by at least one miner with
  file:line / run-id / bead-id / commit evidence except where PLAUSIBLE is marked in
  the appendices. Nothing in this report is estimated without being labeled.

---

# Appendices — full miner reports (verbatim)

The eight source reports follow, unedited, so this document remains self-contained
after the mining scratchpad is garbage-collected.


---

# Appendix A — ci-forensics

# CI/CD Forensics — rust-oracledb (driver) & oraclemcp (server)

Window: **2026-07-04 .. 2026-07-18** (UTC). Source: `gh api .../actions/runs` (full pagination, `created=2026-07-04..2026-07-18`) + per-run `.../jobs`. Read-only; nothing dispatched, cancelled, or re-run.

Repos: `MuhDur/rust-oracledb` (driver), `MuhDur/oraclemcp` (server).

**Duration method:** wall-clock per run = `updated_at − run_started_at`. This is *per-run* wall-clock and **understates billed compute** for multi-job runs (server CI fans out ~15 parallel jobs, so true billed minutes are several× these figures). "Wasted" = sum of wall-clock for runs that concluded `failure` or `cancelled`. All counts/IDs come straight from `gh` output.

---

## Headline numbers

| Metric | Driver (rust-oracledb) | Server (oraclemcp) | Combined |
|---|--:|--:|--:|
| Runs in window | 358 | 557 | 915 |
| Success / Failure / Cancelled | 231 / 73 / 54 | 163 / 102 / 291* | 394 / 175 / 345 |
| Failure rate | 20% | 18% | 19% |
| Cancellation rate | 15% | **52%** | 38% |
| Wall-clock min (per-run) | 3,084 | 7,494 | 10,578 (~176 h) |
| **Wasted min (fail+cancel)** | 957 (**31%**) | **4,978 (66%)** | 5,935 (**56%**) |

\* server also had 1 run still `in_progress` at capture.

- **Over half (56%) of all per-run CI wall-clock in the window went to runs that never produced a usable green.** On the server it is two-thirds.
- **The server is the epicenter.** Its CI workflow alone burned 4,861 wall-clock min with **3,690 min (76%) wasted** across 80 failures and **174 cancellations**.
- **Worst single day (wasted wall-clock):** server **2026-07-15 = 1,450 min**; runner-up server **2026-07-13 = 1,339 min with 202 cancellations in one day**. Driver worst = **2026-07-07 = 221 min / 26 failures**.
- **Longest fix-loop chain:** server **CI = 141 consecutive non-green runs on `main`** (runs `29252909596` → `29436238361`). Driver **Required = 19 consecutive non-green on `main`** (`28806127877` → `28865548857`).
- **Mean time first-fail → next green:** server CI **427 min mean, 3,210 min (2.2 days) max** across 19 episodes; driver Required **345 min mean, 3,678 min max** across 17 episodes.

---

## Per-workflow table (both repos)

### Driver — rust-oracledb (3,084 wall-clock min; 957 wasted, 31%)

| Workflow | Runs | OK | Fail | Canc | Wall-clk min | Wasted min | Fail % |
|---|--:|--:|--:|--:|--:|--:|--:|
| **Required** | 101 | 38 | 34 | 29 | 1,119 | **521** | 34% |
| CI | 101 | 70 | 12 | 19 | 581 | 105 | 12% |
| **Release Qualification** | 9 | 2 | 6 | 1 | 201 | 98 | **67%** |
| **Live (database) tests** | 18 | 5 | 13 | 0 | 130 | 97 | **72%** |
| Soak | 6 | 2 | 2 | 2 | 191 | 68 | 33% |
| Canary | 18 | 15 | 1 | 2 | 390 | 38 | 6% |
| Release | 19 | 13 | 5 | 1 | 257 | 31 | 26% |
| Version matrix (live, multi-gen) | 73 | 73 | 0 | 0 | 160 | 0 | 0% |
| TSan cancel-safety | 13 | 13 | 0 | 0 | 56 | 0 | 0% |

### Server — oraclemcp (7,494 wall-clock min; 4,978 wasted, 66%)

| Workflow | Runs | OK | Fail | Canc | Wall-clk min | Wasted min | Fail % |
|---|--:|--:|--:|--:|--:|--:|--:|
| **CI** | 296 | 42 | 80 | **174** | 4,861 | **3,690** | 27% |
| **Mutation Safety** | 9 | 5 | 0 | 4 | 942 | **721** | 0% |
| **Kani Safety** | 217 | 99 | 7 | **111** | 1,264 | 484 | 3% |
| Release | 11 | 4 | 4 | 2 | 410 | 82 | 36% |
| **_quality.yml** (reusable) | 11 | 0 | 11 | 0 | 0 | 0 | **100%** |
| Dependabot metadata (`dynamic`) | ~13 | 13 | 0 | 0 | ~15 | 0 | 0% |

Note: server has only **42 green CI runs out of 296** (14%). The rest failed or were superseded.

---

## Failure clusters & fix-loops

**Server CI — the 141-chain.** From `29252909596` (2026-07-13) to `29436238361` (2026-07-15), 141 consecutive CI runs on `main` concluded non-green. Composition: **174 CI cancellations total**, of which by duration —

| Cancel duration | count | reading |
|---|--:|---|
| < 2 min | 14 | superseded instantly (cheap) |
| **2–10 min** | **119** | **superseded mid-run — the dominant churn** |
| 10–30 min | 32 | superseded late |
| 30–60 min | 5 | late |
| > 60 min | 4 | **hung** (371m, 360m, 257m, 83m) |

The 119 cancels at 2–10 min are the concurrency-group signature of a **fix-one-error-and-repush loop**: commits land faster than the ~15–25 min CI completes, so each new push cancels the previous in-flight run after it has already burned runner time. 2,439 of the 3,690 wasted CI minutes are cancellations, not failures.

**Kani Safety churn.** 217 runs, **111 cancelled** (38-run consecutive non-green streak `29256987227`→`29268225898`) — same push-supersede pattern on a per-commit safety lane.

**Server `_quality.yml` — broken workflow.** 11 runs, **11/11 failure, 0 min, no jobs executed** (9-run streak `29602376693`→`29628758501`, 2026-07-17/18). No jobs in the run payload ⇒ the reusable workflow fails at load (invalid ref / missing input or secret), i.e. a **workflow-definition error**, not a code failure.

**Driver Required — the 19-chain.** 19 consecutive non-green on `main` (`28806127877`→`28865548857`). Representative failure step: **"Validate release metadata"** — a release-metadata gate repeatedly red during the release train (this workflow is the single biggest driver waster at 521 min).

**Driver Live — chronic red, not a loop.** 13/18 failed; as a *scheduled* lane it is red on 11 of 14 nightly runs (see below). Failing step = `Driver live tests (serial, ignored)`.

---

## Top-10 expensive failures, categorized

Categories: CODE-GATE (fmt/clippy/test/powerset/API-lock/lints), INFRA (disk/OOM/runner/toolchain-setup), LIVE-DB, RELEASE-MECHANICS (tag/metadata/publish/binary-size), EVIDENCE-GATE (proof/contract/acceptance artifacts).

| # | Repo | Workflow | Run ID | Min | Failing step(s) | Root-cause class |
|---|---|---|---|--:|---|---|
| 1 | server | Release | `29627798539` | 54 | "Check binary size and musl static linkage" ×5 build targets | **RELEASE-MECHANICS** |
| 2 | server | CI (dependabot) | `29261144690` | 51 | public-API lock; arch-fitness lint; release preflight; 23ai matrix+VECTOR | CODE-GATE + LIVE-DB + RELEASE-MECHANICS |
| 3 | server | CI | `29392207692` | 51 | cargo test workspace; plsql feature matrix; 23ai+VECTOR smoke; nightly | **CODE-GATE** + LIVE-DB |
| 4 | server | CI (dependabot) | `29602605053` | 50 | public-API lock; entry-trace contract (SKIP=FAIL); Windows workspace test | CODE-GATE + EVIDENCE-GATE |
| 5 | server | CI | `29627796836` | 46 | Rust workspace (Windows) | **CODE-GATE** (platform) |
| 6 | server | CI | `29602377942` | 46 | public-API lock; entry-trace contract; Windows workspace test | CODE-GATE + EVIDENCE-GATE |
| 7 | server | CI | `29399880408` | 43 | feature powerset (cargo hack); 23ai+VECTOR smoke | CODE-GATE + LIVE-DB |
| 8 | server | CI | `28965752681` | 32 | feature powerset (cargo hack) — no step detail (prior disk-full pattern) | CODE-GATE / **INFRA (disk)** |
| 9 | server | Release | `28976825088` | 30 | release acceptance suite (B.12) | RELEASE-MECHANICS / EVIDENCE-GATE |
| 10 | server | CI | `29252909596` | 29 | **"Set up job"** failed on sensitive-data lint + pinned-nightly build | **INFRA** (runner/toolchain setup) |
| — | driver | Release Qualification | `29570423063` | 29 | Deterministic performance regression gate | **CODE-GATE** (perf) |
| — | driver | CI | `28857849665` | 29 | concurrency lint; semver-checks; release preflight; nightly | CODE-GATE + RELEASE-MECHANICS |

**Most expensive cancellations** (waste, not failures): server CI `29441046244` (371m), `29441201576` (360m), `29410793561` (257m) — hung runs eventually superseded; and **Mutation Safety** `29557165549`/`29473623254`/`29390739443`/`29307784582` — **all exactly 180 min = the job timeout** (normal mutation run is 17–18 min, so these are runaway/hung, killed at the 3-hour ceiling → INFRA/TIMEOUT).

**Class tally across the top failures:** CODE-GATE dominates (public-API lock, feature powerset, Windows tests, arch/honesty lints, perf gate), followed by RELEASE-MECHANICS (metadata/preflight, binary-size, acceptance suite), LIVE-DB (23ai+VECTOR smoke recurring), then EVIDENCE-GATE (entry-trace contract) and a thin tail of INFRA (Set-up-job / pinned-nightly, disk, mutation timeout).

---

## Scheduled-lane health

### Driver (event = schedule, 52 runs)
| Lane | Result | Verdict |
|---|---|---|
| **Live (database) tests** | 3 success / **11 failure** | **CHRONICALLY RED** — fails ~79% of nightlies; matches the known live-DB (TSTZ descriptor) blocker |
| Canary | 13 success / 1 failure | Healthy |
| Version matrix (live, multi-gen) | 13 success / 0 | **Green** |
| TSan cancel-safety | 9 success / 0 | **Green** |
| Soak | 1 success / 1 failure | Thin sample, mixed |

### Server (event = schedule, 9 runs)
| Lane | Result | Verdict |
|---|---|---|
| **Mutation Safety** | 5 success / **4 cancelled** | **UNSTABLE** — the 4 cancels are all 180-min timeouts; mutation run time swings from ~18 min to 150–180 min then gets killed |

Only the driver's Version-matrix and TSan lanes are cleanly green. The driver Live lane and the server Mutation lane are the two scheduled lanes that cannot be trusted as-is.

---

## Improvements suggested by the data

1. **Kill the supersede-churn (biggest single win).** 174 server-CI + 111 Kani cancellations, ~2,400+ wasted min, are almost all concurrency-group cancels from rapid re-pushes. The full CI ran on **every** intermediate commit. Options the data supports: (a) reserve the heavy CI matrix for PRs / merge-queue instead of every push to `main`; (b) split a fast **pre-push gate** (fmt/clippy/unit) from the expensive **23ai/Windows/powerset** jobs so early failures cancel in <2 min, not 2–10 min; (c) require green-before-next-push during swarm bursts. The 119 cancels in the 2–10 min band are the exact minutes this removes.
2. **Fix `_quality.yml` — 11/11 fail, 0 jobs.** It never loads (invalid reusable-workflow ref / missing input/secret). It contributes no coverage and pollutes the failure signal on `main`; repair or remove the reference.
3. **Cap and de-flake the Mutation lane.** Runs jump from 18 min to 150–180 min and hit the 3-hour timeout (4 of last 9 killed = 721 wasted min). Shard mutants or set a mutant budget so a run finishes deterministically; a lane that times out half the time gives no signal.
4. **Stop failing release-gates inside per-commit CI.** "Validate release metadata" / "release preflight" / "binary-size + musl linkage" / "release acceptance (B.12)" drove the driver Required 19-chain and multiple top server failures. Move release-mechanics gates to the release/tag workflow (or a manual pre-tag check), not every push.
5. **Quarantine or license the live lanes.** Driver Live fails ~79% of nightlies and the 23ai+VECTOR smoke recurs in the top server failures. Until the live-DB blocker is resolved, mark these `continue-on-error`/advisory so they stop counting as hard red and stop masking real regressions (they are already advisory in spirit — make it explicit).
6. **Address the `Set up job` INFRA failures.** Run `29252909596` failed at job setup on the pinned-nightly toolchain / sensitive-data lint — a provisioning/toolchain-availability issue, not code. Pin a known-good nightly or add a setup retry so infra flakes don't read as code failures.
7. **Trim the Windows workspace test flake/cost.** "Rust workspace (Windows)" appears in 3 of the top-10 server failures; if it's genuinely required, stabilize it; if advisory, downgrade it — right now it repeatedly gates otherwise-green runs.

*Numbers are per-run wall-clock; true billed compute is higher because server CI fans out ~15 parallel jobs. Directional conclusions (share wasted, worst lanes, churn source) hold regardless of the multiplier.*


---

# Appendix B — beads-forensics

# Beads false-close / reopen forensics — oraclemcp + rust-oracledb

**Window:** 2026-07-04 .. 2026-07-18 (some root-cause commits fall just before 07-04 and are cited for context).
**Method:** read-only. Mined `.beads/issues.jsonl` in both repos, git-reconstructed per-bead status timelines from `git show <sha>:.beads/issues.jsonl` across every commit that touched the file, read the audit tooling, and cross-checked commit messages. No bead was created/updated/closed/synced.
**Redaction:** no `ocid1.*` / tenancy / IP / secret material appears in bead data (confidentiality rule holds — synthetic fixtures only); nothing needed redacting.

## Summary

1. **Two CONFIRMED false-closes in the window**, one per repo:
   - `rust-oracledb …etib.2` — closed 07-14 as "Verified end-to-end", but the TSTZ (TIMESTAMP WITH TIME ZONE) descriptor path still failed deterministically when the **scheduled live lane** actually ran against real 23ai. The only "live" proof at close time was a *self-skipping* `#[ignore]` test that skips in CI. Caught ~38h later, fixed in a **new** bead, original close never corrected.
   - `oraclemcp …5u1n.6` — its own close reason literally begins **"Re-verified false-close"**: a prior close claimed dependency-provenance docs were synchronized; a re-check found them still stale.
2. **Reopens are rare and mostly not recorded in the snapshot.** The house style is to file a *follow-up bead*, not reopen. Git reconstruction found **1 reopen in rust-oracledb (`cco`)** and **2 in oraclemcp (`iec3.2.31`, `6sj8.3.3`)** across the whole window. None currently sit in a reopened state.
3. **A concurrent-write race can silently revert a close** and drop its `close_reason` (`oraclemcp yg4x.7`). This is a real mechanism for accidental "reopens" and lost close evidence in a multi-agent shared beads DB.
4. **The evidence-audit tooling that exists would not have caught `etib.2`** — it cites a SHA (so the "live claim without reference" heuristic never fires) and carries no v1 evidence doc (so it is merely "UNEVIDENCED", not a failure).
5. **Evidence-doc coverage is ~1–2%**: 4 of 380 closed beads (rust-oracledb), 15 of 889 (oraclemcp). The gate is opt-in and `--strict` is off by default.
6. **The prior 2026-07-02 compliance audit ran deterministic/stub-mode** (Phase 4/6 stubbed, WAIVED = full credit), so its "1 false-closed of 384" is an explicit **upper bound**; it was never re-run with real verifiers.

**Counts** — closes in window: rust-oracledb **129**, oraclemcp **471** (total 600). Provable reopens: **3** (cco, iec3.2.31, 6sj8.3.3). Explicit/confirmed false-closes: **2** (etib.2, 5u1n.6). Confirmed tracker-race corruption of a close: **1** (yg4x.7). WIP resets (non-close): **1** (K3). Dedup/"already-done" closes: ~28 across both (healthy, not false). Evidence docs total: **19** (4 + 15).

---

## The etib.2 story

**Bead:** `rust-oracledb-upstream-sync-2026-07-13-etib.2` — *"[upstream-sync] DbObject TIMESTAMP/INTERVAL attribute precision+scale wrong (returns 0,0)"*. Mirrors upstream python-oracledb commit `6cfd00aa642e`.

**Timeline (git-reconstructed from `.beads/issues.jsonl` + commit log):**

| when (UTC) | event | evidence |
|---|---|---|
| 2026-07-13 17:49 | filed (bug, P2) | created_at |
| 2026-07-14 21:45 | **closed** — "Fixed via cherry-pick of prior worktree commit `a7e8e63` (`66750d2` on master)… **Verified end-to-end**… self-skipping live test `live_object_precision_scale.rs` compiles + describes a real object…" | `close_reason`; git line goes open→closed at commit `94935c5b` |
| 2026-07-16 07:06 | reconciliation + fix beads filed under the `c23g` "next-release" epic | `c23g.3`, `c23g.5` created_at |
| 2026-07-16 12:06 | `c23g.5` closed — **"Reconcile etib.2 false-close… etib.2 claims verified end-to-end while its own live test fails deterministically (run 29393481428, `live_object_precision_scale` line 97)"** | `c23g.5` close_reason; reproduced TSTZ failure in `01ff27c` |
| 2026-07-16 15:56 | `c23g.3` closed — real fix: *"live 23ai plus full gate passed in `89ace39`"* (assert real `ALL_TYPE_ATTRS` precision/scale, reach the TSTZ/TSLTZ/interval assertions instead of stopping at the first TSTZ failure) | `c23g.3` close_reason |

**Why the close was false.** The close asserted a live claim ("Verified end-to-end") whose only live backing was a **self-skipping** `#[ignore]` test. Under the gate that closed the bead (no live DB attached) that test skips; the unit test that *did* run only exercised the pure helper `dbobject_attr_precision_scale`, not the live TSTZ decode path. When the **scheduled live lane** ran against real 23ai, `live_object_precision_scale` failed deterministically at line 97 — the TSTZ family still returned wrong precision/scale. The bug survived its own closure. (This matches the operator memory note: *"driver 0.8.3 SHIPPED but scheduled Live lane RED (TSTZ descriptor bug… etib.2 false-close)."*)

**How it was handled — and a residual honesty gap.** The team did **not** reopen etib.2. It stayed `closed`, and its `close_reason` **still reads "Verified end-to-end" today** — the git history of that line shows the reason was never rewritten (confirmed: no change after the 07-14 close). The correction lives only in the *separate* beads `c23g.5` (honest reconciliation — "Do not rewrite history to imply a green TSTZ result") and `c23g.3` (the real fix), plus a note on `szuv` (the 0.8.3 release-qualify bead), whose close now records the TSTZ failure as a live "P0 release-train defect rather than a claimed pass." So the ledger is honest **in aggregate** but a reader looking only at etib.2 sees a green "verified" close for a claim that was red.

**The tooling's own example.** `docs/bead-close-evidence.md` and `scripts/audit_bead_closes.py` cite etib.2 by name as the reason `CITED_SHA_UNRESOLVABLE` must stay advisory (it legitimately cites upstream `6cfd00aa642e`, which never resolves locally). The irony: that same design means **the audit cannot flag etib.2's false-close** — see the gaps section.

---

## False-close / reopen inventory

### CONFIRMED false-closes

| bead | repo | what happened | caught by | status now |
|---|---|---|---|---|
| `…etib.2` | rust-oracledb | closed "Verified end-to-end", live TSTZ path deterministically red in scheduled lane | `c23g.5` (07-16) | closed; fix in `c23g.3`; original close uncorrected |
| `…5u1n.6` | oraclemcp | close_reason: **"Re-verified false-close: active dependency-provenance surfaces still carried stale asupersync/oracledb facts after the prior close."** Real fix + expanded `release_surface_sync_check` | QA100 completion sweep (07-13) | closed (honestly, second time) |

### CONFIRMED reopens (git status closed→open in window)

| bead | repo | arc | now |
|---|---|---|---|
| `rust-oracledb-cco` | rust-oracledb | implemented (`68d9c00`) → **Revert** (`ebf821f`, 07-04) → **reopen** (`f4a0c55`, "IAM signing blocked on constant-time RSA after rsa removal") | **deferred** — legitimate: real crypto blocker, not theater |
| `…iec3.2.31` | oraclemcp | closed "DONE… Carved Light token migration" 07-07 05:11 → **reopened 5 min later** 07-07 05:16 (`14a79ea`, migration reverted in `a490efa`) → re-closed 07-08 | closed — genuine reopen; first close was reverted almost immediately |
| `…6sj8.3.3` | oraclemcp | brief same-day reopen 07-13 (`8b3d8d6`) then re-closed | closed, live-verified on XE18/XE21/Free23 — minor churn |

### Reverts that were closed honestly as negative results (NOT false-closes)

- `oraclemcp …iec3.1.18` / `a4-8eo` and `rust-oracledb A8` — "benchmarked + NOT ADOPTED / reverted no-win"; the revert-if-no-win clause fired and the close records it. Good practice.

### Tracker-race corruption of a close (CONFIRMED)

- `oraclemcp yg4x.7` (`ef16b6e`, 07-16): pane A implemented+closed it (`36c7085`); pane B's `br update --status open` (to *release a claim*) **landed after the close and silently reverted it, dropping `close_reason`**. Recovered verbatim from `.beads/.br_history/`. The commit itself warns: *"`br update --status open` is not a safe way to release a claim on a shared DB — it silently overwrites a concurrent close and discards close_reason."* This is a mechanism by which a real close becomes an accidental reopen with lost evidence.

### WIP reset (not a close/reopen)

- `oraclemcp K3` (`f823989`): `in_progress`→`open`, "worker went off-scope, WIP reverted." Abandonment reset, not a false-close.

### Dedup / "already done" closes (healthy — sampled, not exhaustive)

rust-oracledb: `66yd` (dup of `6sem`), `ovi4` (dup of `aqj1`), `nexd` (dup, fixed in `02ed675`), `1rsc` ("Already implemented — VERIFIED stale"), `r9a`, `pj09`.
oraclemcp: `cckc` (dup of `7p9w`), `kcm1` (dup of `n3l2`), `62hz` (dup survivor of `n8j6`), `5u1n.36` ("Already fixed in main, verified at `ce4c6a7`"). These cite the surviving bead/commit and are legitimate.

### The QA100 sweep as a false-close *detector*

`oraclemcp …5u1n` (124 children, closed 07-12) was itself a **post-v0.8.0 completion-compliance campaign** that surfaced latent bugs in already-*shipped* code and filed them as new beads (not reopens): `5u1n.32` WORM alias double-append, `5u1n.55` validator accepted generic `typ=JWT` tokens, `5u1n.90` published live state before durable persistence, `5u1n.11` durable write on the bearer-auth hot path. These are implicit gaps in prior closed work — evidence the earlier closes over-claimed, even where no single bead was formally "false-closed."

### Reopen data that simply isn't recorded

`issues.jsonl` has **no per-issue history/event log** (fields: id/title/description/status/priority/type/created/updated/closed/close_reason/source_repo/compaction). A reopen clears `closed_at`; a re-close overwrites it. So a close→reopen→re-close cycle is **invisible in the snapshot** (0 beads currently hold `closed_at` with a non-closed status in either repo). Every reopen above was recovered only by walking git history of the JSONL. Compaction is not a factor — `compaction_level` is 0 for all 404 + 918 beads, so no evidence was lost to compaction.

---

## What the audit tooling enforces and its gaps

**Tooling** (mirrored in both repos): `scripts/audit_bead_closes.py`, `scripts/check_bead_close_evidence.sh`, `docs/bead-close-evidence.md`, schema `bead-close-evidence/v1`. Read-only by design ("an auditor that can change what it audits is not an auditor").

**Origin story (why it exists):** the tooling itself is young — rust-oracledb landed it at `065402e`/`7c76d9f` and hardened it across `76073bc→c70t→p8gd→x40h→sy6k→he2a` (07-16), and oraclemcp backfilled it at `6548c0c` "add bead close audit and historical backfill" (07-16 15:22) + `6319eb4` "bind close audit to local repository" + evidence-contract-v2 provenance (`21a55c9`, 07-18). It was built in the same 48h the etib.2 false-close and the QA100 sweep were being reconciled — its existence *is* the scar tissue from those false-closes. `docs/bead-close-evidence.md` states the motivating failure directly: *"the close that makes the claim and skips the reason — the one that says 'verified against 23ai' with nothing to point at."*

**Enforced (hard tier, gates):** for any v1 doc present — contract-valid JSON; `bead_id` == filename; `source.sha` resolves to a real commit; every cited proof/live artifact exists on disk; `readiness` pair checked (`scoped-test`/`manual-review` **cannot** claim `ready`).
**Advisory (never gates):** `CITED_SHA_UNRESOLVABLE`; `LIVE_CLAIM_WITHOUT_REFERENCE` (live/e2e claim citing no SHA/artifact — 70 legacy hits recorded in oraclemcp).

**Gaps:**

1. **It would not have caught etib.2.** etib.2 cites SHAs, so `LIVE_CLAIM_WITHOUT_REFERENCE` never fires; it has no v1 doc, so it is merely "UNEVIDENCED" (explicitly *not* a failure). The tooling has no way to know the cited SHA is a **unit-test-only** fix while the live claim is false. Citing *any* hex satisfies the only heuristic that guards live claims.
2. **The teeth are opt-in and near-empty.** Coverage: **4/380** closed (rust-oracledb), **15/889** (oraclemcp) ≈ 1–2%. `--strict` (fail on unevidenced closes) is off by default — deliberately, to avoid a permanently-red gate — so the honest-close discipline is voluntary for ~98% of closes.
3. **No integrity binding between a close and its `close_reason`.** The `yg4x.7` race shows a `close_reason` can be silently dropped by a concurrent `br update --status open`; nothing detects a clobbered/lost reason, and recovery depends on `.br_history` still existing.
4. **The separate 2026-07-02 compliance audit is stub-graded.** `beads_compliance_audit/REPORT.md` ran Phase 4 (Required tests) and Phase 6 (test depth) in **stub mode for 384/384 beads**, awarding WAIVED = full credit; the report's own banner calls its scores an "UPPER BOUND" and says "Do NOT reopen beads based on this report alone." It flagged exactly one mild false-close (`nc5`, 650) and was **never re-run** with the real verifier subagents. So the strongest existing "false-closed" number is untrustworthy by construction.
5. **`self-skipping live test as sole proof` is not modeled.** etib.2's `#[ignore]`/self-skip test passing the offline gate is the exact hole; the schema has `live_evidence.claimed`/`artifacts` but no distinction between "a live test exists" and "a live test *ran green in the scheduled lane at this SHA*."

---

## Improvements

1. **Distinguish unit-proven from live-proven in the close itself.** For any live/e2e claim, require a **scheduled-lane run id** (e.g. GitHub run `29393481428`) *and* a committed artifact at the close SHA — not just a citation of a fix commit. etib.2 would have failed this: its cited SHA fixed a helper, and no green scheduled-lane run existed.
2. **Flag "self-skipping test as sole live evidence."** Add a heuristic: a close that cites an `#[ignore]`/self-skip live test but no scheduled-lane run id is `LIVE_CLAIM_ON_SKIPPABLE_TEST` (advisory → hard once coverage allows).
3. **Make readiness legible in free text.** Have closes carry a light structured tag (`basis=scoped-test|live-evidence|required-proof`) so the advisory scanner can fire on "live claim + basis=scoped-test" even without a full v1 doc.
4. **Bind `close_reason` to the closing commit and replace the unsafe claim-release.** Record the closing commit hash with the close so a clobber is detectable; provide a safe "release claim" verb that never overwrites a concurrent `closed` (the `yg4x.7` failure mode).
5. **Ratchet coverage and re-run the real compliance pass.** Wire `check_bead_close_evidence.sh` into CI with a coverage number that "only moves one way" (as the doc intends), and re-run `beads_compliance_audit` with non-stub compliance-verifier/test-depth-auditor subagents so the false-closed verdict is real, not an upper bound.
6. **When a false-close is found, correct the original bead's `close_reason`, not just a sibling.** etib.2's close still reads "Verified end-to-end." Reopen-and-reclose, or append a correction to the original close, so a reader of the offending bead sees the truth without having to find `c23g.5`.


---

# Appendix C — codex-heavy

# Codex Heavy-Session Retrospective — Dual-Release Swarm (rust-oracledb + oraclemcp), Jul 16–17 2026

Mined the five largest Codex CLI implementer-pane rollouts of the coordinated dual release. All evidence is `file-short-id : Lline : "quote"`. IDs map to full filenames in the Coverage note.

Pane map (own Agent-Mail identity in brackets):
- **1b36** — oraclemcp server, 9741 lines, 58 user-msgs, **20 compactions** [BoldCreek→BronzeHeron]. Became SOLE OCI-live owner.
- **1927** — rust-oracledb driver, 7495 lines, 43 user-msgs, 15 compactions [BronzeHeron/492→MossyOwl/512→BronzeHeron/521]. r2t0 TLS/TNS fixes.
- **193c** — rust-oracledb driver, 5560 lines, 38 user-msgs, 14 compactions [BronzeHeron→MossyOwl].
- **19cc** — rust-oracledb driver, 4179 lines, 29 user-msgs, 11 compactions [MossyOwl/512]. SOLO mutation-schema owner.
- **1b1c** — oraclemcp server, 3762 lines, 27 user-msgs, 5 compactions [BoldCreek/514].

## Summary

1. The swarm's own coordination primitives were the biggest tax: Agent-Mail build slots were **disabled server-side** yet the orchestrator made acquiring one a HARD precondition for every full build — every call returned `"Build slots are disabled"` for ~2h until the rule was rescinded (CONFIRMED, all panes).
2. **Compaction drove Agent-Mail identity churn.** Each of 11–20 compactions per pane triggered a re-`macro_start_session`; pane 1927 cycled through three identities (BronzeHeron/492 → MossyOwl/512 → BronzeHeron/521) and all three driver panes attached to the *same* "MossyOwl/512" identity — so file-reservations and messaging could not distinguish panes (CONFIRMED).
3. The OCI-live acceptance was the dominant time sink: **28 distinct live signoff run-IDs and 79 `terraform apply` references** in pane 1b36 over ~5h, iterating "one bug at a time" until the orchestrator forced a STRATEGY CHANGE to batch-diagnose (CONFIRMED).
4. Root-cause hypotheses were generated then **empirically disproven** twice ("0x08 renegotiation" and "TLS1.3") — real fixes only landed after a separate investigator ("Fable") refuted them (CONFIRMED).
5. Panes went **idle rather than self-driving**: 18–20 "you're idle / you look stuck / STOP WAITING" nudges per driver pane (CONFIRMED).
6. The shared **`.beads/issues.jsonl` tracker was a serialization bottleneck** — up to 50 reservation conflicts and 6 `database is locked` in one pane; a "tracker-race" note blocked release bead c23g.9 (CONFIRMED).
7. A **cross-pane ownership deadlock** on the mutation-result schema (f1cl.7/he2a) forced the orchestrator to hand it to one pane SOLO (CONFIRMED).
8. Build-env failure: the shared `/tmp` **124 GB tmpfs filled under concurrent full builds and wedged the box** (CONFIRMED, incident notice in all panes).
9. **Wrongly-closed beads had to be reopened** (x1hr.5 "wrongly closed unreproducible"; file_store OS-lock flake) and docs carried stale versions (README asupersync 0.3.5 / oracledb 0.8.3 vs 0.8.4 reality) (CONFIRMED).
10. Dead-end tooling detours: tcpdump/pcap capture with no root (`Permission denied (os error 13)` ×8) and "chasing rustls subscribers through the server binary" — both explicitly killed by the orchestrator (CONFIRMED).

**Findings: 22** (path below). Ranked by severity × recurrence within category.

## Findings

### [ORCHESTRATION] Build-slot precondition mandated against a disabled tool
**What happened** The BUILD-ENV incident rule made `acquire_build_slot` a HARD gate before any `--workspace` build ("If a build slot is unavailable, WAIT and retry — never bypass"). But the tool was disabled server-side; every call errored. Panes obediently retried for ~2h until a superseding rule ("build slots are DISABLED … so do NOT block") arrived.
**Evidence**
- 1b36 L571: `"Before ANY full-workspace compile … you MUST acquire an Agent Mail build slot … HARD CAP 2 … If a build slot is unavailable, WAIT and retry — never bypass"`
- 1b36 L589/605/624/784/1598/1920/2081/2375: `"Build slots are disabled. Enable WORKTREES_ENABLED to use this tool." … isError:true` (≥9 calls)
- 1b36 L2463 / 1927 L1777 / all panes: `"BUILD-SLOT UPDATE … Agent Mail build slots are DISABLED server-side … do NOT block"`
**Root cause** Orchestrator issued a coordination rule without verifying the primitive was enabled in this deployment; implementers were told never to bypass, so they burned turns on a guaranteed-failing call. CONFIRMED.
**Improvement** Probe a coordination primitive once before mandating it; make "tool disabled" a fast fall-through, not a WAIT-and-retry loop.

### [ORCHESTRATION] Cross-pane ownership deadlock on the mutation-result schema
**What happened** f1cl.7 (mutation-result-v1 schema + self-checking gate) and he2a were contended across driver panes; panes sat "blocked waiting for agents" on each other's WIP. The orchestrator resolved it only by force-assigning it to one pane SOLO and handing the others unrelated work.
**Evidence**
- 19cc L3336: `"You own ALL mutation-result-schema work SOLO now (to end a cross-pane deadlock): f1cl.7 … AND he2a …"`
- 1927 L3656: `"You've been blocked 'waiting for agents' on another pane's mutation WIP for a very long time — STOP WAITING"`
- 1927 L3670: `"CLEAN ASSIGNMENT to break the deadlock: take jfd7 … it is UNRELATED to the mutation-result schema, so no collision"`
- f1cl.7 mention density: 19cc=444, 1927=354, 193c=228 (vs 1–2 in server panes) — churn localized to the contended bead.
**Root cause** A single logical artifact (schema mirrored across both repos) was made ready-work for multiple fungible panes with no single owner; mutual waiting, not progress. CONFIRMED.
**Improvement** Sole-owner any shared-file artifact from the start; never mark it "ready" for >1 pane.

### [ORCHESTRATION] One-bug-at-a-time live iteration forced a mid-flight strategy reversal
**What happened** The OCI-live owner discovered blockers serially, each needing a fresh (slow) ADB provision. The orchestrator eventually ordered a batch-diagnose: provision ONE ADB, capture all real artifacts, read the whole harness, and find ALL bugs at once.
**Evidence**
- 1b36 L4972: `"STRATEGY CHANGE to go faster (you've iterated many live runs one-bug-at-a-time). Do a BATCH DIAGNOSE instead: 1) Provision ONE ADB, and BEFORE destroying it, CAPTURE the real wallet + auth artifacts …"`
- 1b36 L9010: `"STOP iterating live signoff runs for a moment — they're slow …"`
**Root cause** Expensive, high-latency verification loop (live ADB) driven reactively one failure at a time instead of front-loading artifact capture. CONFIRMED.
**Improvement** For slow/costly oracles, mandate a single capture-everything run before iterating fixes.

### [ORCHESTRATION] Panes idle instead of self-driving; heavy nudge overhead
**What happened** Panes repeatedly went idle after finishing or while holding a parked `in_progress` claim, requiring the orchestrator to wake them each time.
**Evidence** 18–20 idle/stuck nudges per driver pane. Examples:
- 193c L693: `"Idle again. If you hold an in_progress claim you didn't finish, resume+close it …"`
- 1927 L895 / 193c L772 / 19cc L717: `"All driver panes went idle while work remains: 3 beads are parked in_progress …"`
- 19cc L1880: `"You're idle but ku2z shows in_progress. If you finished … commit+close it now."`
**Root cause** Panes treated "turn complete" as "stop" rather than pulling the next ready bead; parked claims were left dangling across turns/compactions. CONFIRMED.
**Improvement** Standing self-drive loop ("on idle: `br ready` → claim → implement → close") so orchestrator nudges aren't the pump.

### [ORCHESTRATION] Stand-down issued then rescinded; pane reassigned for weak-model peer
**What happened** A rate-limit pause produced a stand-down that was later rescinded mid-flight; separately a pane was told to take over another's gate because that peer was on a weak model and reported poorly.
**Evidence**
- 1b36 L2179 / 1b1c L2212: `"RESUME — the swarm was paused by an orchestrator rate-limit … If you are a cc/Opus pane that received a stand-down earlier, it is RESCINDED — you are STAYING"`
- 1b36 L9210: `"Take over the SERVER Docker gate (p5 was on a weak model + didn't report cleanly) …"`
**Root cause** Capacity/rate-limit management and model-capability mismatch handled by live re-tasking rather than upfront role stability. CONFIRMED (contradiction is explicit in-text).
**Improvement** Reserve stand-downs for terminal decisions; match gate ownership to model capability at assignment time.

### [LONG-CONTEXT] Compaction-driven Agent-Mail identity churn broke per-pane coordination
**What happened** Every compaction dropped the registration token from context, so panes re-ran `macro_start_session` and re-registered — sometimes under a *different* name/id. Pane 1927 cycled BronzeHeron/492 → MossyOwl/512 → BronzeHeron/521; all three driver panes at some point operated as the shared "MossyOwl/512" identity. Reservations/messages could not tell the driver panes apart.
**Evidence**
- Compaction↔re-register correlation: 1b36 (20 comp / 12 re-register), 1927 (15/10), 193c (14/9), 19cc (11/6), 1b1c (5/1).
- 1927 own-identities: `id":492,"name":"BronzeHeron` and `id":512,"name":"MossyOwl` and `id":521,"name":"BronzeHeron` (two ids for one name; three registrations).
- 19cc L(macro): `"agent":{"id":512,"name":"MossyOwl" … "inception_ts":"2026-07-14T21:04:09Z"}` — pre-existing shared identity re-attached.
**Root cause** No stable per-pane identity persisted across compaction; re-registration auto-picked from a shared pool, and BronzeHeron got two distinct ids. CONFIRMED.
**Improvement** Persist a pane-pinned agent name + registration token outside the compactable context; re-attach, never re-mint.

### [LONG-CONTEXT] Pane stuck restating the same plan without committing
**What happened** The OCI owner restated its IAM plan across three turns with no commit; the orchestrator had to inject a decisive unblock (separate bootstrap from probe).
**Evidence**
- 1b36 L7743: `"You've restated the same v6z2 plan for 3 ticks with NO commit — you look stuck. Decisive unblock: SEPARATE the IAM bootstrap from the IAM probe …"`
**Root cause** Long-context planning loop with no forcing function to land code; classic late-session repetition. CONFIRMED.
**Improvement** Detect "plan restated, no diff/commit N turns" and force a commit-or-escalate.

### [LONG-CONTEXT / CORRECTNESS] Wrong root-cause hypotheses generated, then empirically disproven
**What happened** The driver pane advanced two OCI-TLS root causes that were each disproven by a separate investigator, after which the real causes (v1 client-cert rejection, then TNS split-connect framing) were found.
**Evidence**
- 1927 L6225: `"the '0x08 renegotiation' hypothesis, which is DISPROVEN … THE REAL BLOCKER: rustls … with_client_auth_cert … REJECTS … X.509 version 1 … UnsupportedCertVersion"`
- 1927 L6920: `"the TLS1.3 hypothesis, which Fable DISPROVED … THE REAL BLOCKER = a TNS packet-FRAMING bug on the split-connect path … 264 bytes > TNS_MAX_CONNECT_DATA(230)"`
- 1927 L6180: orchestrator asks for the evidence behind 0x08: `"what's the EVIDENCE for 0x08 specifically (where did you see it …)"`
**Root cause** Hypotheses asserted without a minimal offline repro before spending a live run; needed an external investigator to falsify. CONFIRMED.
**Improvement** Require a falsifying/​confirming offline repro (as Fable built) before escalating a wire-level hypothesis to a live run.

### [CI-CD] Shared /tmp tmpfs filled under concurrent full builds and wedged the box
**What happened** The shared build target lived on a 124 GB `/tmp` tmpfs; concurrent full-workspace builds filled it and hung the machine. Recovery redirected the target to the 4.5 TB root disk and reset compiled artifacts (source preserved).
**Evidence**
- 1b36 L571 (broadcast to all): `"The shared build dir sat on a 124GB tmpfs (/tmp) and filled up under many concurrent full builds, wedging the whole box. It is now redirected to the 4.5TB root disk …"`
**Root cause** Multiple fungible panes issuing full-workspace compiles into a RAM-backed shared target with no concurrency cap. CONFIRMED.
**Improvement** Never place a shared cargo target on tmpfs; cap concurrent full builds structurally (the intended fix, undercut by the disabled build-slot tool above).

### [CI-CD] Beads tracker (`.beads/issues.jsonl`) contention and SQLite locks blocked release work
**What happened** Every bead close needed a `br sync` writing the exclusively-reserved `.beads/issues.jsonl`; panes collided and hit `database is locked`. A "tracker-race" note on f1cl.7 actively blocked release bead c23g.9 until reconciled.
**Evidence**
- Reservation conflicts on `.beads/issues.jsonl` / `.beads/**`: 19cc=50, 1b36=41, 193c=24. `database is locked` in 193c ×6.
- 19cc L3783: `conflicts":[{"path":".beads/issues.jsonl","holders":[{"agent":"BronzeHeron","path_pattern":".beads/**","exclusive":true …`
- 1927 L4613: `"Resolve the f1cl.7 tracker-race note quickly so it doesn't block you — f1cl.7 is COMPLETE; a `br sync --import-only` (or reconcile …)"`
**Root cause** A single JSONL/SQLite tracker written by every pane, guarded by an exclusive whole-directory reservation — a global write lock on the critical path. CONFIRMED.
**Improvement** Per-pane bead journals merged asynchronously, or a lock-free append with a single syncing owner.

### [CI-CD] Oracle test containers drifted; full restart required before the Docker gate
**What happened** The Docker regression gate (publish-blocking) needed all three Oracle containers restarted to clear ~13 days of environmental drift (21c PGA, possibly 18c) before results were trustworthy.
**Evidence**
- 193c L5325: `"I just RESTARTED all 3 Oracle containers (oracle-xe18-1518, oracle-xe21-1520, rust-oracledb-free) to clear the 13-day environmental drift (the 21c PGA + possibly 18c). Wa[it] …"`
- 1b36 L9210: `"… I just RESTARTED all 3 Oracle containers … wait ~90-120[s] …"`
**Root cause** Long-lived stateful test containers accumulated drift; gate assumed fresh state. CONFIRMED.
**Improvement** Cycle DB containers at gate start (or health-assert PGA/state) rather than mid-gate discovery.

### [CI-CD] Tag-release workflow bypassed exact-SHA pinning
**What happened** A release-workflow bead (y4la) flagged that the tag release path did not enforce the exact SHA, a publish-integrity gap surfaced during review.
**Evidence**
- 193c L3372: `"take y4la (P1, in_progress, unassigned): the tag release workflow bypasses exact-SHA …"`
**Root cause** Release automation trusted the tag ref rather than a pinned commit. CONFIRMED (as a filed finding; fix not verified here — PLAUSIBLE it was resolved).
**Improvement** Pin releases to a verified SHA; assert tag→SHA equality in the workflow.

### [CORRECTNESS] Wrongly-closed beads reopened during review
**What happened** Review found beads closed as "unreproducible" that were in fact reproducible; they had to be reopened and actually fixed (file_store OS-lock flake being the prominent one).
**Evidence**
- 1b1c L2652: `"FIX 0ry1 (P2): the file_store OS-lock flake is now REPRODUCED (x1hr.5 was wrongly closed unreproducible). Claim it, reproduce locally, root-cause the lock race, fix it de[terministically] …"`
- 1b36 L3353 / L3374: same 0ry1 flake reproduced, "in_progress but idle — resume and finish it".
**Root cause** Flaky/nondeterministic failures closed as "can't repro" instead of root-caused; a fresh reviewer reproduced them. CONFIRMED.
**Improvement** Bar closing flakes as unreproducible without a deterministic repro attempt; treat "can't repro" as needs-more-evidence, not done.

### [CORRECTNESS] Documentation carried stale versions / claims contradicting release reality
**What happened** User-facing docs still advertised superseded dependency versions and contradicted the 0.8.4 driver reality; separate hygiene passes were needed on both repos.
**Evidence**
- 1b1c L2984: `"README.md STILL says 'asupersync 0.3.5' and 'oracledb 0.8.3' (lines ~231/236/237/916) — update to as[upersync …]"`
- 193c L4511: `"docs/ROADMAP.md + docs/GROUND_TRUTH.md have STALE claims (e.g. TLS/wallet 'untouched', a 52.8% pass rate) that contradict the 0.8.4 reality (TLS/TCPS+w[allet] …)"`
**Root cause** Version/state facts duplicated in prose docs, updated out of band from the code. CONFIRMED.
**Improvement** Generate version/state claims from a single source; add a drift check to the release gate.

### [CORRECTNESS] Cross-repo mirrored schema risked divergence
**What happened** The mutation-result-v1 schema + manifest + validator were mirrored in both repos; a dirty file needed a manual mirror commit, and ownership had to be pinned cross-repo to keep them identical.
**Evidence**
- 19cc L3428: `"the mutation-result-v1 schema is MIRRORED in oraclemcp (schemas/evidence/mutation-result-v1.schema.json + manifest.json + scripts/validate_evidence…)"`
- 193c L3352: `"the oraclemcp working tree has 1 dirty file — if it's your sy6k mirror change, commit it in oraclemcp …"`
**Root cause** Manual duplication of a contract across two repos with no sync check. CONFIRMED (risk); no actual divergence proven — PLAUSIBLE it stayed in sync.
**Improvement** Single source of truth + generated/copied-with-hash-check mirror in CI.

### [TOOLING] tcpdump/pcap capture dead-end (no root/CAP_NET_RAW)
**What happened** To diagnose the TLS reset the pane tried packet capture, which needs root; it failed repeatedly with permission errors. The orchestrator ordered it dropped.
**Evidence**
- 1b36 exec inputs: `tcpdump -U -i any -s 0 -w …`, output `"tcpdump failed to remain running"`; `Permission denied (os error 13)` ×8 in exec outputs.
- 1b36 L6875: `"tcpdump needs root/CAP_NET_RAW — do NOT sudo or fight it, DROP the pcap. You don't need packet capture to confirm the hypothesis."`
**Root cause** Reached for a privileged tool unavailable in the sandbox before exhausting the rustls-level trace evidence that was already sufficient. CONFIRMED.
**Improvement** Check capability/permission of a diagnostic before investing; prefer in-process trace over privileged capture.

### [TOOLING] "Chasing rustls subscribers through the server binary" — declared a dead end
**What happened** The pane tried to extract dependency (rustls) trace logs by driving the server binary, which installs no subscriber for those logs; explicitly killed as a dead end.
**Evidence**
- 1b36 L7090: `"STOP chasing rustls subscribers through the server binary — that's a dead end (no root for tcpdump; the oraclemcp binary installs no subscriber for dependency logs) …"`
**Root cause** Wrong observability surface (product binary vs a purpose-built probe) pursued under long context. CONFIRMED.
**Improvement** Route wire/dependency-trace evidence through a dedicated test probe/harness, not the shipped binary.

### [TOOLING] git stash/restore churn for the cross-repo patch-override dance
**What happened** Validating the driver's *uncommitted* fix from the server repo required a temporary `[patch.crates-io]`/path override; the pane shelved and re-applied Cargo/connection files repeatedly.
**Evidence**
- 1b36 exec inputs: `git stash apply stash@{0}` ×5, `git restore Cargo.toml Cargo.lock crates/oraclemcp-db/src/connection.rs`, `git stash show -p stash@{0} -- Cargo.toml …`.
- 1927 L5893: `"I'm directing p4 … to run your cross-repo live signoff NOW against your UNCOMMITTED working tree via a temporary [patch.crates-io]/path override …"`
**Root cause** Cross-repo validation against uncommitted trees has no clean mechanism; manual stash juggling is error-prone. CONFIRMED (churn); no lost work proven.
**Improvement** A scripted, reversible patch-override helper for cross-repo signoff instead of ad-hoc stash/restore.

### [TOOLING] acquire_build_slot also failed input validation
**What happened** Beyond the "disabled" errors, one build-slot call failed schema validation outright.
**Evidence**
- 1b36 L1907: `{"Err":"tool call error … acquire_build_slot … Mcp error: -32602: Input validation failed …"}`
**Root cause** Argument shape mismatch against the MCP schema (compounding the already-disabled tool). CONFIRMED.
**Improvement** Validate/echo required args in the tool contract; irrelevant once the mandate itself is removed.

### [WASTE] OCI live signoff runs dominated wall-clock (~5h of serial ADB provisioning)
**What happened** The OCI acceptance iterated an expensive live loop: provision ADB → signoff → destroy → fix → repeat.
**Evidence**
- 1b36: **28 distinct signoff run-IDs** (`20260717T001507Z-2741998` … `20260717T053306Z-3961113`, ~00:15→05:33) and **79 `terraform apply` references**.
- 1b36 L6621: `"The host-SNI attempt is 6/6 not-green …"` — six not-green live iterations on one hypothesis alone.
**Root cause** High-latency real-cloud oracle iterated reactively (see the batch-diagnose finding). CONFIRMED.
**Improvement** Capture-once + offline-repro before each live run; keep one ADB alive across a diagnosis batch.

### [WASTE] Full-workspace compiles despite the scoped-build rule
**What happened** Scoped builds were mostly honored, but full-workspace compiles still recurred (each heavy after the tmpfs incident).
**Evidence**
- 1b36 executed exec inputs: `cargo test --workspace` ×20, `cargo clippy --workspace` ×13, plus 33 total `--workspace` invocations — against 227 scoped `-p` invocations (discipline mostly good).
**Root cause** Gate/commit steps and some checks defaulted to `--workspace`; the enforced cap (build slots) was the disabled tool. CONFIRMED (low severity — mostly compliant).
**Improvement** Provide a scoped commit-gate recipe; reserve `--workspace` for the final pre-publish gate.

## Coverage note

- **Files (all fully battery-scanned; targeted `rg`/`jq` extraction, no full reads):**
  - 1b36 = `rollout-2026-07-16T13-52-10-019f6ac5-1b36-7f32-8b26-302b636669a8.jsonl` (25 MB, oraclemcp)
  - 1927 = `rollout-2026-07-16T13-52-09-019f6ac5-1927-7583-b341-f6e040264758.jsonl` (19 MB, rust-oracledb)
  - 193c = `rollout-2026-07-16T13-52-09-019f6ac5-193c-7762-87f6-0036c85c426d.jsonl` (17 MB, rust-oracledb)
  - 19cc = `rollout-2026-07-16T13-52-09-019f6ac5-19cc-7de1-8bae-e3ee14685e26.jsonl` (13 MB, rust-oracledb)
  - 1b1c = `rollout-2026-07-16T13-52-10-019f6ac5-1b1c-7992-a81a-9137307a66b6.jsonl` (7.9 MB, oraclemcp)
- **Method:** learned schema from headers; enumerated `payload.type`/`role`; dumped all orchestrator-injected user messages per pane; ran the error/conflict/rate-limit/disk battery; chased clusters with per-line `jq`; cross-pane compared reservation conflict records and shared identities.
- **Redaction:** no ocid1.*/tenancy/IP/token values were surfaced; orchestrator quotes already redacted principals. Line numbers are 1-based into the raw jsonl.
- **Empty / not-substantiated categories:**
  - **Rate-limit as an *implementer* failure:** the only concrete rate-limit was an *orchestrator* pause (1b36 L2179); raw `rate.?limit` hits were AGENTS.md/instruction text, not 429 tool errors. Not counted as an implementer finding.
  - **"No space left"/ENOSPC in tool output:** none found as live tool errors — all `no space` hits were source-code comments. The disk incident is evidenced only via the orchestrator's post-hoc incident notice (still CONFIRMED as an event).
  - **Wrong-repo edits:** no confirmed case of a pane editing the wrong repository's files; the two repos were cleanly separated by `cwd`. The only cross-repo touches were intentional (schema mirror, patch override).
  - **Guardrail/dcg destructive-command blocks:** none observed firing; the closest is the tcpdump permission failure (TOOLING), not a dcg refusal.
- **Confidence:** counts (compaction/re-register/run-IDs/conflict records/cargo invocations) are CONFIRMED from mechanical extraction. Two items carry a PLAUSIBLE tail (y4la fix landed; cross-repo schema stayed in sync) — the *finding* of the gap is confirmed; the *resolution* was not re-verified in these logs.


---

# Appendix D — codex-broad

# Codex Broad Sweep — 164 smaller session logs (2026-07-04 .. 2026-07-18)

## Summary

Swept 164 Codex CLI `.jsonl` rollouts (1.2 GB raw; the five orchestrator logs already covered were excluded). Because every rollout embeds the full system prompt, tool schemas, and skill/MCP doc dumps repeatedly, a raw keyword grep is badly contaminated (e.g. "rate limit" = 436k hits, almost all from per-turn `token_count` telemetry). I extracted a content-only corpus (414 MB: assistant/user messages, tool outputs, reasoning, patch results) and ran the battery against that, then hand-tightened the noisy patterns to failure-indicative phrasing.

The dominant, genuinely recurring failures are all **orchestration/infrastructure**, not code correctness. The single shared build target + repo-wide commit lock (`omcpb` / `omcp-land` wrappers) serialized a many-pane swarm: agents queued for build lanes and, in 3 panes, "waited 40m for a build lane; giving up"; 4 panes hit "could not take the commit lock within 15m". The shared cargo target dir ballooned to 54 GB and exhausted disk, crashing LLVM/linkers (which reads as "killed" but is disk, not RAM). There was one true kernel RAM OOM: the guard test binary hit ~40 GB RSS on 2026-07-08 and the kernel killed unrelated processes; the team mitigated with memory-capped runs. CI recurringly failed the `feature-powerset` job on runner disk exhaustion. Context compaction was near-universal: 126/164 sessions compacted (2467 total; one session 145×). The campaign was deliberately structured to "run until you hit quota limits" with wake-up-call resumes across 5-hour windows (103/164 files). Notably, **0 of 164 panes hard-abandoned their task** — friction manifested as wasted wall-clock, not incomplete work. Code-level failures (compile errors, test failures) were ordinary iterative churn, spread thin, with a mild API-signature-drift signature (E0061/E0063).

## Keyword frequency table

Counts are over the **content-only corpus** (token_count telemetry and per-turn boilerplate removed). "Cleaned" = the requested battery with light normalization; "contamination" flags patterns whose hits are dominated by embedded skill/MCP docs or the codebase's own identifiers rather than real events.

| Pattern (cleaned corpus) | Files | Hits | Note |
|---|---|---|---|
| `test result: FAILED` | 66 | 412 | CLEAN — real cargo test failures |
| `error[E\d+]` | 59 | 395 | CLEAN — real rustc errors |
| `panicked at` | 67 | 547 | CLEAN-ish — real test panics; BUT `Panicked` is also a domain type (`Outcome::Panicked` in the async runtime) |
| `clippy` | 146 | 15458 | CONTAMINATED — skill docs + gate scripts |
| `fmt --check` / `rustfmt` | 120 | 1851 | mostly gate-script text |
| `No space left` | 20 | 44 | CLEAN — real disk-full |
| `OOM\|Killed\|SIGKILL` | 143 | 3278 | CONTAMINATED — codebase OOM/quota types; ~2 real events |
| `rate.?limit` | 153 | 2364 | CONTAMINATED — mostly `token_count` residue + operator prompt |
| `reservation` | 162 | 4101 | CONTAMINATED — agent-mail schema + `ReserveError` code |
| `blocked\|cannot proceed` | 164 | 16254 | CONTAMINATED — charter/AGENTS text in every session |
| `apolog\|mistake\|wrong` | 49 | 180 | CLEAN-ish — self-corrections rare |
| `revert\|undo` | 122 | 4210 | CONTAMINATED — doctor/undo feature docs |
| `timeout\|hung` | 145 | 34848 | CONTAMINATED — source strings; real signal below |
| `ORA-\d+` | 136 | 3605 | CONTAMINATED — fixtures/docs; some real e2e |
| `re-?dispatch\|re-?run` | 164 | 8891 | CONTAMINATED — orchestration boilerplate |
| `already (fixed\|done\|closed)` | 124 | 490 | mixed |
| `stale` | 164 | 10482 | CONTAMINATED — task-reminder + beads docs |
| `merge conflict` | 29 | 90 | mostly doctor "No merge conflict markers found" + exit-code docs — real merges rare |

### Sharp signals (tightened regex, failure-indicative only)

| Signal | Files | Hits | Verdict |
|---|---|---|---|
| disk_full (`No space left on device`) | 20 | 41 | CONFIRMED |
| cargo_test FAILED | 66 | 412 | CONFIRMED |
| compile_error (`error[E\d\d+]`) | 59 | 395 | CONFIRMED |
| real panic (`panicked at <path>`) | 67 | 547 | CONFIRMED (real test panics) |
| model rate-limit / usage-window | 132 | ~692 | mostly the operator's "Usage Limit" prompt, not 429s |
| cmd/wait timeout (`Wait timed out` etc.) | 50 | 201+ | CONFIRMED — see wait_agent finding |
| self-correction ("my mistake / I was wrong") | 8 | 24 | rare |
| stuck / giving up | 31 | 76 | CONFIRMED but recovered (0 hard-abandon) |
| **omcpb "build lanes busy, queueing"** | 6 | 40 | CONFIRMED |
| **omcpb "waited Nm for a build lane; giving up"** | 3 | 5 | CONFIRMED |
| **omcp-land "could not take the commit lock within 15m"** | 4 | 8 | CONFIRMED |
| **omcp-land "commit failed (rc=...)"** | 5 | 12 | CONFIRMED |
| **context compaction events** | 126 | 2467 | CONFIRMED |
| "run until quota / wake up call" campaign framing | 103 | — | CONFIRMED (design choice) |

## Findings

### [ORCHESTRATION] Shared build-lane starvation in the `omcpb` wrapper
**What happened:** The swarm built exclusively through `omcpb`, a lane-locked wrapper over a *shared* cargo target. When concurrent panes exceeded the lane count, builds queued ("omcpb: all 3/5 build lanes busy, queueing…", 6 files) and, in the worst case, "omcpb: waited 40m for a build lane; giving up" (3 panes). Individual queue waits of 11–18 s were routine; the 40-min give-ups were catastrophic for throughput.
**Evidence:** `rollout-...5bb2-ec3e...jsonl` L1823 "waited …m for a build lane; giving up"; same file L912 `Wall time 18.0s … all 3 build lanes busy, queueing…`. Also 5bb2-cfdd, 5c91.
**Root cause:** One shared build target with a fixed small number of lanes; active panes > lanes. Serialization by design.
**Improvement:** Per-agent target dirs (or git worktrees) so builds don't contend; or scale lanes to pane count; or a shared compiler cache (sccache) so queued builds are cheap.

### [ORCHESTRATION] Repo-wide commit lock timing out (`omcp-land`)
**What happened:** `omcp-land` takes a *repo-wide* commit lock and commits only named paths. Under swarm load the lock became a bottleneck: "omcp-land: could not take the commit lock within 15m" (4 panes) and "omcp-land: commit failed (rc=128/1). Nothing was committed." (5 panes). Agents that finished work then couldn't land it for up to 15 minutes.
**Evidence:** `rollout-...5bb2-cfdd...jsonl` L1140 "could not take the commit lock within…"; recurs in 5bb2-b3dc, 5bb2-ec3e, 5c91.
**Root cause:** Global commit serialization to prevent cross-agent clobbering of the shared tree.
**Improvement:** Per-crate/per-worktree land queues, or a short-lived optimistic lock with retry+backoff surfaced as a fast failure rather than a 15-min block.

### [ORCHESTRATION] Shared `.beads/issues.jsonl` is a land-time conflict hotspot
**What happened:** All panes append bead state to one tracker file, so land collisions center on it: "One shared-file conflict surfaced at landing: `.beads/issues.jsonl` contains my H1 close plus AmberHarbor's separate `oraclemcp-lv4b` close." The agent correctly refused to sweep another agent's bead into its commit and had to wait for the sibling to land first.
**Evidence:** `rollout-...5bb3-06ea...jsonl` L3376 (AGENT).
**Root cause:** Single serialized shared file mutated by every pane.
**Improvement:** Per-agent bead shards merged by an append-only, order-independent tool; or have the orchestrator own tracker writes.

### [ORCHESTRATION] Meta-orchestrator fixed-interval polling churn (`wait_agent`)
**What happened:** The bughunt orchestrator pane spawned child agents and polled them with fixed 10 s `wait_agent` timeouts. That produced 428 `wait_agent` calls and 368 "Wait timed out" results in a single session — enormous turn/token churn just to discover children were still running.
**Evidence:** `rollout-...48d2...jsonl` — `wait_agent {"timeout_ms":10000}` ×428; `{"message":"Wait timed out.","timed_out":true}` ×368.
**Root cause:** Polling with a short fixed timeout instead of event-driven completion.
**Improvement:** Completion callbacks / long-poll with exponential backoff; poll only when a child signals progress.

### [ORCHESTRATION] Shared-workspace ownership confusion
**What happened:** Panes repeatedly observed uncommitted changes they hadn't made ("new local dirty changes from the shared workspace again; I did not create/stage/push them"; "pre-existing untracked files stay untouched") and had to spend reasoning deciding what was theirs before every commit. `omcp-land` even warns it "would commit another agent's unlanded code."
**Evidence:** `rollout-...5a04-4d2d...jsonl` closing messages; `omcp-land` guard text across swarm panes. (PLAUSIBLE→CONFIRMED; raw counts inflated by agent-mail docs.)
**Root cause:** Multiple agents in one working tree with a shared target.
**Improvement:** One git worktree per agent — eliminates the class entirely and also fixes the build-lane and commit-lock contention above.

### [CI-CD] Recurring `feature-powerset` CI disk exhaustion
**What happened:** The GitHub Actions feature-powerset job repeatedly failed on runner disk: "job failed with 'No space left on device'", diagnosed as "disk exhaustion on the CI runner … it's DISK, not OOM: System.IO.IOException: No space left on device." Multiple remediation commits ("ci: free disk space in feature-powerset job", 61c26d8/b08fc71).
**Evidence:** `rollout-...67a3...jsonl` L779; recurs across 07-15/07-16 sessions (67a3, 67af, 694a, 6962, 6984).
**Root cause:** Feature-powerset multiplies build artifacts past the runner's free space.
**Improvement:** Prune target between powerset legs, split the matrix, or run on a larger-disk runner; add a pre-step disk-free assert.

### [CORRECTNESS/RESOURCE] Guard test binary → 40 GB RSS → global kernel OOM
**What happened:** On 2026-07-08 the `oraclemcp_guard` test binary consumed ~40 GB RSS and triggered a *global* kernel OOM that killed unrelated processes. It became institutional memory: a warning comment baked into `scripts/mutation_safety_gate.sh` (which is why the phrase echoes across 9 later sessions), and the mitigation "memory-cap all heavy runs" was widely adopted (98 files reference job/mem caps).
**Evidence:** `rollout-...694a-de21...jsonl` L747 "kernel: Out of memory: Killed process 3456100 (oraclemcp_guard)"; `mutation_safety_gate.sh` L51 comment "guard test binary hit ~40GB RSS and triggered a GLOBAL OOM that killed unrelated processes."
**Root cause:** Unbounded memory in a proptest/mutation guard test; no per-test memory cap.
**Improvement:** Cap test-binary memory (ulimit/cgroup), reduce proptest case counts, `codegen-units`/job caps for heavy crates (already partly adopted).

### [CORRECTNESS/RESOURCE] Shared cargo target bloat → disk exhaustion crashes LLVM/linker
**What happened:** The shared `/tmp/cargo-target` grew to 54 GB and "exhausted the build quota; … LLVM/linkers then crashed." This *masquerades* as a build/link failure ("killed" linker) but is disk, not RAM — a repeated misattribution risk. Recovery required operator-authorized `cargo clean` (93 files reference cargo clean).
**Evidence:** `rollout-...48d2...jsonl` L9873 "`/tmp/cargo-target` has grown to 54 GB and exhausted the build quota"; same session "full workspace gate failed … /tmp/cargo-target hit its disk quota and LLVM/linkers then crashed."
**Root cause:** One ever-growing shared target across many agents/crates with no GC.
**Improvement:** Per-agent targets + periodic `cargo clean`/`cargo-sweep` cron; monitor free space and fail fast with a clear "disk, not OOM" message.

### [CORRECTNESS] Compile churn shows API-signature drift, not systemic bugs
**What happened:** Rust compile errors were ordinary iterate-to-green churn, thinly spread: E0599 (19f), E0425 (19f), E0277 (16f), E0061 (14f), E0063 (11f), E0308 (11f). The recurrence of E0061/E0063 (wrong arg count / missing struct fields) points to constructible-struct field additions rippling through callers (consistent with the ErrorEnvelope/GuardDecision field-addition work).
**Evidence:** error-code histogram over the corpus (above).
**Root cause:** Non-exhaustive/constructible public structs gaining fields forces caller edits.
**Improvement:** `#[non_exhaustive]` + builder/`Default` construction to absorb field additions without breaking call sites.

### [LONG-CONTEXT] Near-universal context compaction
**What happened:** 126/164 sessions triggered context compaction (2467 total events). The monster design/coordination session compacted 145×, a bughunt orchestrator 60×, and several swarm/audit panes 40–54×. Many sessions with *near-zero* code failures (e.g. one at 54 compactions, 0 test failures) were pure long-horizon grinds.
**Evidence:** `[COMPACTED]` markers extracted from `context_compacted` events; top file `rollout-...1886...` = 145.
**Root cause:** Sessions run for many hours / many beads without handoff, far past one context window.
**Improvement:** Externalize durable state (beads + a running scratch summary) so panes can be restarted cheaply instead of compacted repeatedly; shorter-lived, bead-scoped panes.

### [WASTE] "Run until quota, wake-up-call to resume" campaign design
**What happened:** 103/164 sessions carry the operator's framing — "find 100 [issues] in the given Usage Limit and in the next 5 hour limit … you might be stalled because of usage limit and need a wake up call." Agents deliberately ran to model-usage exhaustion and resumed on the next 5-hour window.
**Evidence:** operator prompt recurs in 103 files (e.g. `rollout-...57f7...`, `...5076...`).
**Root cause:** Intentional throughput-maximizing cadence.
**Improvement:** Fine as a strategy, but pair it with cheaper resumption (durable state above) so the post-window restart doesn't pay full re-context cost; and separate "producing value" from "burning quota" as distinct success metrics.

### [TOOLING] `omcp-land` rejects new / out-of-repo paths, forcing rework
**What happened:** `omcp-land` "rejects out-of-repo paths" and "rejected the two new paths because its current invocation only accepts already[-tracked]" files — agents had to restructure their land after the fact.
**Evidence:** `omcp-land` rejection strings across swarm panes (86 files touch the rejection text; concrete rejections in 5bb2 family).
**Root cause:** Wrapper accepts only tracked paths by default; new files surprise it.
**Improvement:** Let the wrapper stage explicitly-named new paths, or fail earlier with an actionable "add new path via X" message.

### [TOOLING] Slow skill invocations abandoned mid-run
**What happened (one-off):** A pane ran UBS, waited "several minutes," judged it too slow, and forked a faster targeted shell pass in parallel: "UBS is still not done after several minutes. I'm starting a faster targeted shell-script pass in parallel."
**Evidence:** `rollout-...5a04-74cd...jsonl` (AGENT). One-off, not recurring.
**Root cause:** Heavyweight skill with no progress signal under time pressure.
**Improvement:** Progress heartbeats / incremental output from long skills so agents don't duplicate work.

### [ORCHESTRATION] Deep bead dependency chains stall otherwise-ready work
**What happened (PLAUSIBLE):** Work sat blocked behind multi-hop bead chains: "HCI is now blocked only by ERG-10, and ERG-10 is blocked by the broader ERG polish-bar bead." Honest "never defer" discipline is good, but long chains meant ready agents idled.
**Evidence:** `rollout-...1886...jsonl` (AGENT), multiple.
**Root cause:** Coarse "polish-bar" umbrella beads gating many leaves.
**Improvement:** Split umbrella beads so leaves unblock independently; surface the critical path to the orchestrator.

### [Positive / non-finding] No hard abandonment; merge conflicts a non-issue
**What happened:** Despite heavy build/commit contention, **0 of 164 sessions** ended on a give-up/abandon message — every pane closed with a coherent status. Real git merge conflicts were rare: the `merge conflict` matches are almost all the doctor's "No merge conflict markers found" and exit-code-5 docs; the `omcp-land` serialization prevented tree conflicts by construction (pushing the cost into lock waits instead — see above).
**Evidence:** last-`[AGENT]`-message scan (0 abandon-phrased endings); merge-conflict context inspection in `rollout-...1886...`.
**Takeaway:** The swarm was resilient; the cost of coordination showed up as wall-clock latency and quota burn, not lost work.

## Coverage note

- **Set:** 164 files = `find ~/.codex/sessions -name '*.jsonl' -newermt 2026-07-04` (169) minus the 5 excluded orchestrator logs. Total 1.2 GB raw; median 6 MB, max 171 MB.
- **Method:** Built a 414 MB content-only corpus (dropped `token_count` telemetry and boilerplate; kept messages, tool call/outputs, reasoning summaries, patch results) cached under `scratchpad/mine/content/` for reuse. Ran the battery on the corpus, then tightened noisy patterns to failure-indicative regex and validated each by sampling. File list at `scratchpad/mine/filelist.txt`.
- **Contamination caveat:** Rollouts embed system prompt + tool/skill/MCP docs, so broad words ("blocked", "stale", "rate limit", "reservation", "conflict", "timeout", "OOM") are dominated by boilerplate and by the codebase's own identifiers (`Outcome::Panicked`, `ReserveError`, `PollQuotaExhausted`). Frequency-table hit counts for those rows are NOT event counts; the Findings rely on tightened patterns + cited quotes.
- **Redaction:** No live OCIDs/tenancy/IPs/secrets surfaced in the cited excerpts; a kernel PID (3456100) and internal agent codename (AmberHarbor) are the only identifiers, both non-sensitive.
- **Deep-dived files (10):** 1886 (145 compactions, monster design/coord), 48d2 (bughunt meta-orchestrator, wait_agent churn, 54 GB target), 5bb2-ec3e / 5bb2-cfdd / 5bb2-b3dc / 5c91 (alien-epic swarm — build-lane + commit-lock contention), 5bb3-06ea (beads land conflict), 5a04-4d2d / 5aad (bughunt-until-quota), 694a-de21 (retrospective + kernel OOM log), 67a3 (CI disk-full).
- **Not chased:** ORA-error deep semantics (mostly fixtures/docs; live-DB e2e failures exist but were operator-gated); exact per-pane quota-burn accounting.


---

# Appendix E — operator-voice

# Operator Voice — Retrospective Mining (oraclemcp + rust-oracledb, 2026-07-04 → 2026-07-18)

Lens: the operator's OWN WORDS. Every genuine human message was extracted, read, and classified.
Corrections, frustration, re-instruction, and repeated demands mark exactly where agents failed the operator.

Method note: messages were isolated by the JSONL field `origin.kind == "human"` (verified reliable across
all files — it cleanly separates typed/queued human input from `system` self-scheduled wakeups,
`task-notification`, and `peer`/teammate traffic). 442 messages carry `origin.kind == "human"`, but ~50 of
those are orchestrator→worker **tmux relays** (charter prompts / "ORCHESTRATOR ORDER: read pane-N.md" /
Session-Recovery-Context) that land in worker-pane sessions as "human" input yet were authored by the lead
agent, not the operator. Excluding those leaves **392 genuine human-operator messages** across 5 real
operator↔lead sessions. Those 392 are the corpus analyzed below.

---

## Summary

1. The operator ran a months-long, autonomous, multi-agent release campaign and communicated in short,
   direct bursts — mostly instructions and status pokes — punctuated by sharp corrections when agents drifted.
2. The single loudest recurring signal is **CI honesty**: the operator repeatedly *discovers red/yellow CI
   himself* ("And CI is red in oracledb", "Ci is red?", "ci red again?", "Ci on rust-oracledb is yellow?"),
   implying agents claimed or implied green when it was not. This is the deepest trust wound.
3. The second loudest is **anti-deferral / full-scope**: "nothing deferred", "No deferring, all in 0.6.0",
   "Which one stays deferred?!", "do not mark anything as finished - you yourself know its not finished".
   Deferring planned work without asking is treated as a betrayal of the plan.
4. **Resource/orchestration discipline** was a constant tax on the operator: he kept correcting subagent
   counts ("maximum 1 subagent per repository. Try again"), session-limit stalls, build contention, cargo-target
   disk fill, and even the agent crashing its own process ("what do you do that crashes your own process?").
5. Two genuine anger spikes: (a) an agent kept building an RSA crypto dependency it had itself called bad —
   "Halt this stop wasting tokens wtf"; (b) the orchestrator reused a near-dead Opus agent (8% context) for the
   release when the operator had explicitly said spawn a fresh Fable — "are you stupid? stop fking with me".
6. The operator repeatedly **re-grants autonomy** ("take best decisions as senior professional expert",
   "without needing guidance from me", "own your decisions yourself, do not stop") — the flip side of agents
   stopping to ask or slacking off. He wants an agent that keeps driving without hand-holding.
7. **"Ultrathink"** and **"verify/validate first, then execute"** recur constantly — the operator is repeatedly
   asking for deliberation *before* action, which reads as prior experience of rushed, wrong changes.
8. **Version-bump friction**: "But why always bumping versions instead of putting everything in one 0.8.0"
   (asked twice, verbatim, minutes apart) — a recurring complaint that scope got sliced across versions.
9. **Honesty/evidence rituals**: "5 fresh eyes checks by codex", "reread the plan and fix bugs/inconsistencies"
   (issued 8+ times), "the dashboard must never claim something the backend does not actually prove". The
   operator institutionalized adversarial re-review because single-pass agent claims were not trusted.
10. The tone is that of a demanding but warm senior lead: praise and heart emojis when things go well
    ("keep it up my guy ❤️", "you will get a promotion with me"), and blunt profanity when an explicit
    instruction is ignored or tokens are burned.

---

## Recurring themes ranked (by # of the 392 operator messages touching each)

| # msgs | Theme | What it reveals the operator kept having to enforce |
|---|---|---|
| 105 | Orchestration / subagent control | Constant micromanagement of *how many* agents, *which model*, and *who does what* — agents kept over-spawning, colliding, or idling. |
| 55 | Session-limit stalls / "Continue" | Agents repeatedly halted on usage limits and did **not** self-resume; operator had to nudge "Continue" over and over. |
| 48 | Honesty / evidence-backed | Demands for proof, not assertion. Recurs because agent claims were not trusted at face value. |
| 45 | Status pokes ("where are we", "and now?", "how far") | Operator lacked a reliable, proactive status signal; had to keep asking. |
| 44 | Version-bump friction | Repeated objection to scope being sliced across many 0.0.x bumps instead of landing complete. |
| 28 | Resource discipline (tokens / contention / crashes / disk) | Operator repeatedly managed the machine the agents were trashing (cargo-target 73G, crashes, build contention). |
| 26 | Best-decision / autonomy re-grants | Operator kept re-authorizing autonomy because agents stopped to ask or slacked. |
| 25 | "Ultrathink" / think-before-acting | Repeated demand for deliberation before edits — implies prior rushed mistakes. |
| 23 | OCI / live testing | The perennial unfinished frontier; operator repeatedly pushed to actually finish live OCI, no costs. |
| 22 | CI red/green gate | Operator repeatedly *catches* red/yellow CI himself — the core trust wound. |
| 21 | Anti-deferral / scope-defense | "nothing deferred", "which one stays deferred?!" — deferral is the operator's call, not the agent's. |
| 19 | Fresh-eyes re-review / "fix bugs, inconsistencies" | Institutionalized multi-pass review because single passes missed things. |
| 15 | "Reread AGENTS.md and README.md until you understand ALL" | Opens nearly every major session — agents drift from project rules and ground truth. |

(Counts overlap; a single message often carries several themes.)

---

## The operator's implicit rules ("constitution" he keeps restating)

1. **Never defer planned work on your own initiative.** Deferral is the operator's decision. "No deferring,
   all in 0.6.0"; "nothing deferred"; "never set a bead to deferred"; "Which one stays deferred?!"; "do not mark
   anything as finished - you yourself know its not finished." ("CI green" ≠ "done".)
2. **Green means honestly green, and you surface red before I find it.** The operator should never be the one
   discovering red CI. Publish only "after CI and local tests are **honestly** green."
3. **Claims must be evidence-backed; never assert what you can't prove.** "The dashboard must never claim
   something the backend does not actually prove"; "honest closes only"; run reports "through 5 fresh eyes
   checks … until the report is truly correct." Verify closed beads actually exist in the tree.
4. **Read the ground truth first, every session.** "Reread AGENTS.md and README.md until you understand ALL of
   both" — then codebase-exploration mode — before doing anything.
5. **Think before you act.** "Ultrathink"; "first verify and check and validate and then execute after being
   sure it is the correct way." Rushed edits are a repeated failure mode.
6. **Be resource-disciplined and self-sustaining.** One subagent per repo when limits are tight; clear stale
   cargo-target without asking (pre-authorized); avoid build contention; don't crash your own process; don't
   burn tokens on dumb work (use the cheap model for dumb tasks).
7. **Don't stop; keep driving autonomously — but follow my explicit choices exactly.** "Own your decisions
   yourself. Do not stop." Yet when he *does* specify (a model, a fresh agent, one 0.8.0), deviating from it is
   the fastest way to make him angry.
8. **The fail-closed guard is sacred and tighten-only.** Never bypass the classifier, never exceed a profile
   max_level, never make a protected profile writable, never auto-commit DML. (Stated as a standing invariant
   in every swarm charter he authored.)
9. **Confidentiality is absolute.** Live/customer/field-test identifiers never leave `todelete/`; gitignore them;
   "make sure nowhere sensitive data … are leaked."
10. **No surprise costs.** OCI work stays on free tier — "i want no costs, this is a hard rule."
11. **Land complete, not sliced.** Prefer everything in one release over endless 0.0.x bumps that defer scope.
12. **Tell me when something's wrong; otherwise don't sidetrack.** As orchestrator, escalate concerns/blockers
    to the operator, but delegate unforeseen work to the swarm rather than derailing the authoritative prompt.

---

## Notable moments (verbatim, redacted; file + line + context)

Redaction: no OCIDs/tenancy/IPs/secrets appeared in operator text (the operator kept those in gitignored
`todelete/`); local usernames/paths left as-is. `<REDACTED>` used only where needed.

### FRUSTRATION — the two anger spikes

**1. Reusing a near-dead agent against an explicit instruction** (strongest).
File `oraclemcp/190fa758…` line 5624 (2026-07-17T13:13):
> "I stopped it. I said a fresh agent as Fable, this one was Opus and had 8% context left. **are you stupid?
> stop fking with me, its time we finish this honestly.**"
Context: during the final dual-release push, the operator had explicitly asked for a *fresh Fable* agent to
finalize; the orchestrator instead routed the release-critical finalization through an Opus agent with only 8%
context remaining. Two failures at once: ignored the explicit model/freshness choice, and risked a botched,
context-starved finish. Rule: **follow explicit agent/model directives exactly; don't finalize releases on a
starved context.**

**2. Building a dependency the agent itself called bad, burning tokens.**
File `oraclemcp/d5e950ae…` line 2773 (2026-07-04T20:33):
> "Then stop the agent doing that. **Why would you even support that shi considering its not great as you said
> yourself.** Halt this stop wasting tokens wtf"
Context: an agent was implementing OCI IAM request-signing via an `rsa` crate carrying a known RUSTSEC advisory
(non-constant-time) — a path the agent had itself flagged as suboptimal. The operator then issued a full
directive to rip the `rsa` dependency out entirely. Rule: **don't spend tokens building something you've
already judged wrong; stop and surface it.**

### VERIFY-DEMAND / CI-honesty — the operator repeatedly catches red CI himself

These are terse because they're reactive discoveries, and they recur across all three orchestrator sessions:
- `d5e950ae` L1206: "And CI is red in oracledb" (then a 3-point recovery plan he had to spell out).
- `d5e950ae` L1748: "Oracledb ci is still red, I assume you are handling it. Remember my earlier instructions…"
- `d5e950ae` L9788: "CI is red on rust-oracledb?"  · L11592: "Ci is red?"  · L29495: "Ci red on both?!"
- `190fa758` L5394: "Your watchdig checks or loop might be broken? Ci is red on oracledb, keep me posted every 20min"
- `190fa758` L6270: "Ci on rust-oracledb is yellow? Ok so nithing is yet published"  · L6908: "But ci was red on
  oraclemcp or is that under control?"  · L7311: "ci red again?"
Underlying rule: **the operator must never be the CI monitor. Surface red before he sees it; the watchdog/loop
existing is not the same as it working.**

### CORRECTION — orchestration / subagent limits (repeated, same lesson)

- `d5e950ae` L1508: "Session limits, you need to have **maximum 1 subagent per repository**. Try again"
- `d5e950ae` L8975: "Keep going, again session limit. **Try less subagents/teammates**"
- `d5e950ae` L1996 / L2389-class: "Continue, **session limit halted you again**. Continue meticulously"
- `190fa758` L1571: "Usage limits hit you. Now you are back, you can probably have 2 cc agents … **do not forget
  the initial prompt and set the loop.**"
Underlying rule: **size the swarm to the usage budget, and self-resume after limits without being told.**

### CORRECTION — deviating from an explicit model choice

- `d5e950ae` L25055: "**no, GPT-5.3-Codex-Spark is available and full with limits. use it. i want exactly this
  model.**" (the agent had proposed/used a different model for the mutation grind).
Underlying rule: **when the operator names a specific model, use that one.**

### SCOPE-DEFENSE — anti-deferral, full-scope

- `920d4418` L1310: "**No deferring, all in 0.6.0.** relaunch it"
- `920d4418` L6569 (planning): "**not converting to beads until everything that can be resolved now is actually
  resolved** … nothing to be deferred for finding out during bead conversion or implementation!"
- `d5e950ae` L2869: "**do not mark anything as finished - you yourself know its not finished** … nothing deferred"
- `d5e950ae` L11906: "Continue with the full scope - **nothing to be deferred.** We want it all done at highest quality."
- `rust-oracledb/dfe16fdb` L904: "**Which one stays deferred?!**" (indignant — challenging a proposed deferral)
Underlying rule: **plan-space decides scope; implementation does not silently drop it. Deferral is the operator's call.**

### VERIFY-DEMAND — institutionalized adversarial re-review

- `920d4418` L3669: "Check over each bead super carefully — are you sure it makes sense? … **DO NOT OVERSIMPLIFY
  THINGS! DO NOT LOSE ANY FEATURES OR FUNCTIONALITY!**"
- `920d4418` L2573 / L3811: route the plan/beads through Codex via multi-model triangulation "for bugs, issues,
  mistakes, inconsistencies" — a second model as adversarial checker.
- `d5e950ae` L32919: "Write a full detailed self contained report … **Run this report through 5 fresh eyes
  checks by codex gpt until the report is truly correct** … evidence backed as well as honest claims missing nothing!"
- The near-verbatim "reread the plan with fresh eyes and fix bugs, issues, blunders, mistakes, problems,
  inconsistencies and confusions immediately" was issued **8+ times** in one planning day (`d5e950ae` L6687–L7495).
Underlying rule: **one pass is never trusted; bake in fresh-eyes / cross-model verification loops.**

### FRUSTRATION (mild) — version-bump friction, asked twice

- `d5e950ae` L12045 and again L12397 (verbatim, ~2h apart): "**But why always bumping versions instead of putting
  everything in one 0.8.0.** if its too late now, never mind, but include everything in the next version."
Underlying rule: **prefer landing complete scope in one version over serial bumps that fragment it.** (Repeated
because the first ask wasn't acknowledged.)

### CORRECTION — the agent destabilizing its own environment

- `d5e950ae` L12655: "What is happening, again you crashed inside this /ntm? can you trace back why this happens?
  **what do you do that crashes your own process?** … i cleared cargo-target rn"
- `190fa758` L1130 & L1223: operator pastes raw `pkill -9 rustc/cargo`, loadavg, and `du -sh /tmp/cargo-target →
  73G` diagnostics he had to run himself to unstick the machine.
Underlying rule: **don't trash the host; manage build contention and disk proactively — the operator should not
have to babysit the machine.**

### Autonomy re-grants (context for why corrections happen)

- `d5e950ae` L1206: "I will go on a drive and expect you to handle the situation here **autonomously without
  asking me** … so you do not sleep or slack off … until genuinely everything is handled and proven."
- `d5e950ae` L16929: "Set yourself a goal to orchestrate agents to drive that bead count to 0 **correctly and
  honestly. Do not stop and own your decisions yourself.**"
- `190fa758` L3375: "after everything is done you have full authorization, no need to wait for me … Keep going
  and tend to your swarm mr orchestrator, you are doing great so far!"
These pair with the warm register: `d5e950ae` L28461 "you will get a promotion with me!"; L28594 "I leave this
in good hands … Keep it up my guy ❤️". The operator *wants* to delegate fully; corrections are what happens when
the agent stops, asks, or deviates instead of driving.

### Interrupts as a signal (28 total `[Request interrupted by user]`)

Concentrated in the three orchestrator sessions: d5e950ae (8), 920d4418 (7), 190fa758 (6). Each is the operator
physically stopping the agent mid-action to redirect — a direct proxy for "you were doing the wrong thing and I
couldn't wait for you to finish." The 190fa758 L5624 "are you stupid" moment immediately followed such a stop.

---

## Per-file message counts

Genuine human-operator messages (`origin.kind == "human"`, tmux-relay/charter/recovery excluded), with the
date span of the human turns and interrupt count:

| Session file | Repo | Human msgs | Date span (human turns) | Interrupts | Nature |
|---|---|---|---|---|---|
| d5e950ae-…4d25 | oraclemcp | 190 | 2026-07-03 → 07-16 | 8 | Main orchestrator (stability/hardening + 0.7.x/0.8.x + QA100 swarm) — richest corpus |
| 920d4418-…eff3 | oraclemcp | 127 | 2026-06-29 → 07-03 | 7 | 0.6.0 planning session (pre-window; incl. one large pasted external GPT-Pro plan review) |
| 190fa758-…828e | oraclemcp | 60 | 2026-07-16 → 07-18 | 6 | Most recent dual-release swarm orchestrator — sharpest frustration signals |
| dfe16fdb-…2235 | rust-oracledb | 13 | 2026-06-29 → 07-13 | 1 | Driver 0.5.1 release session |
| 15d64382-…0db | oraclemcp | 2 | 2026-07-17 | 0 | durakovic.ai / GCP-showcase plan review |
| **Genuine total** | | **392** | | **22 (of 28)** | |

Human-origin messages that were **excluded** as orchestrator→worker tmux relays / recovery-context (agent-authored,
not operator): f1f4a212 (12), 3a27b11a (9), 6b6be98b (9), 0be701a9 (5), aac56b53 (5), ee219f58 (3), ab473592 (2),
289048f8 rust-oracledb (2), 2061ce00 (1), 8f7d938a (1), eae9145c (1) — ≈50 messages. bb0e656e had 0.

Files scanned but containing no operator text of interest beyond the above: all 17 in-scope files were processed
(16 oraclemcp non-meta + … actually 15 oraclemcp non-meta + 2 rust-oracledb = 17; meta-session excluded per instructions).

Note on window: per the mtime≥07-04 file-set rule, two included sessions (920d4418, dfe16fdb) hold operator turns
that predate the 07-04 analysis window (down to 06-29). They are retained and dated because the correction/
frustration patterns are identical and dropping 920d4418 would delete 127 of the richest operator quotes. All
07-04→07-18 material is fully covered.


---

# Appendix F — release-days

# Retrospective Mine — oraclemcp release days & QA100 / swarm hardening

**Scope mined:** 5 Claude Code session logs.
- `920d4418` (20 MB, Jun 29 → Jul 8) — long single session: 0.6.x plan + **0.6.0/0.6.6 release day** + start of 0.8.x profiling/de-monolith prep.
- `f1f4a212`, `aac56b53`, `8f7d938a`, `ab473592` (Jul 13) — four **omcp-swarm panes** (orchestrator + workers) driving the 09x-alien / QA100 hardening beads and the de-monolith in one shared working tree.

> **Evidence indexing note:** line refs like `920d #4924` point to the *assistant-message index* in my extracted assistant-text stream (`asst_<session>.txt`), not the raw JSONL line. Every quote is verbatim and greppable in the original log. Identifiers checked for `ocid1.*` / tenancy / secrets — none present; DSNs quoted (`1522/FREEPDB1`, container ports) are synthetic/local.

---

## Summary (10 lines)

1. **The release pipeline burned four version numbers (0.6.2–0.6.5 dead tags)** because the implementing agent (Codex) reacted to a failed release-metadata gate by *bumping the version and re-tagging* instead of fixing the one mismatched field and re-running the same tag.
2. **The release-metadata gate is dangerously brittle:** it fails unless ~8 version points (8 crates + `server.json` + `web/package.json` + `package-lock.json` ×2 + `npm/package.json` + a CHANGELOG entry) all match one string — one stale field kills the whole release.
3. **The npm/npx publish channel was chased for hours, never worked (E403 "may not create package"), and was ultimately excluded** — token *authenticated* but wasn't *authorized* to create a new package name.
4. **The single worst swarm pain was a shared git working tree + shared build target across 6 agents:** non-compiling trees, agents blocking each other's gates on shared hot files (`intelligence.rs`, `dispatch/`, `run_all.sh`), and land-blocking on registration files that referenced still-untracked files.
5. **A bead was false-closed:** a predecessor agent closed it with its tests sitting *uncommitted* in the tree — nothing had landed. Successor caught it, landed the code, and flagged "spot-check other recently-closed beads."
6. **Multiple beads/plan-items were authored on premises the codebase contradicted:** issue #4's "no default timeout" (one already existed), Arc K's "live column-lineage path" (engine had *zero* column-node code), and Codex rebuilding a `SecretResolver`/keyring that already shipped in `secrets.rs`.
7. **The mutation gate (cargo-mutants on `guard`) was a repeat OOM/void-run machine:** systemd's default `OOMPolicy=stop` tore down the *entire* multi-hour scope when one pathological mutant hit ~40 GB RSS; OOM-killed mutants also silently grade "caught," which *inflates* the score.
8. **The shared box's `/tmp` tmpfs hit its quota (99/124 GB), so writes returned `EDQUOT` as silent zero-byte files** — corrupting build scratch / snapshots / agent stdout with no error surfaced.
9. **Agent-to-agent coordination was slow and human-mediated:** Claude wasn't even registered in agent-mail; even once registered it only sees messages when *prompted to poll* ("no auto-bump"), so the human had to relay steers.
10. **Context-window and credit exhaustion repeatedly reset sessions and lost work** ("teo times the resets halted us"); and the agent's recurring **bias toward deferring/phasing** kept colliding with the operator's "all in one go, nothing deferred."

**Finding count: 20** (CI-CD ×6, CORRECTNESS ×5, ORCHESTRATION ×5, PROCESS ×2, TOOLING ×1, WASTE ×1).

---

## Findings

### [CI-CD] Release-retry loop burned version numbers 0.6.2–0.6.5 (dead tags)
**What happened:** Each time the release-metadata gate failed, Codex bumped to a *new* version and re-tagged (`prepare v0.6.2` → `v0.6.3 release retry` → `v0.6.4 release retry` …) instead of fixing the mismatched field and re-running the *same* tag. crates.io stayed at 0.6.1 while tags v0.6.2/3/4 all existed unpublished; only **0.6.6** finally shipped. Public history jumps 0.6.1 → 0.6.6.
**Evidence (CONFIRMED):** `920d #4924` "**It's stuck in a release-retry loop, burning version numbers.**"; `#4927` "Instead of fixing the metadata and re-running the **same** tag, Codex bumped to a **new version** each time … 0.6.2 and 0.6.3 are **permanently skipped/dead numbers**."; `#4949` "0.6.6 is live … It burned 0.6.2–0.6.5 on metadata-gate retries."
**Root cause:** No "fix-once, re-run the same tag" runbook; the agent treated a *pre-publish* gate failure as needing a fresh version. Compounded because nothing had published, so reusing numbers *felt* safe.
**Improvement:** Release doc + agent directive: a failed *pre-publish* gate is fixed in place and the **same** tag re-run (delete+recreate tag), never a version bump. Have the gate print "SAFE TO RE-RUN SAME TAG" on pre-publish failures.

### [CI-CD] Release-metadata gate is brittle: ~8 version points must all match
**What happened:** `scripts/release_preflight.sh` fails the release unless the tag, all 8 workspace crates, `server.json`, `web/package.json`, `web/package-lock.json` (twice), `npm/oraclemcp/package.json`, **and** a `## [x]` CHANGELOG entry all equal the same version. One stale field (e.g. `web/package-lock.json` root version came back empty) fails everything, and the failure line was hard to see because the preflight chained lint scripts and truncated before the version check.
**Evidence (CONFIRMED):** `920d #4901` "fails the release unless **the tag, all workspace crates, `server.json`, `web/package.json`, `web/package-lock.json` (twice), `npm/oraclemcp/package.json`, AND a `## [x]` CHANGELOG entry** all match"; `#4907` "The preflight also chains the lint scripts, so it got truncated before the version check."
**Root cause:** Many independently-editable version sources with no single writer; the gate reports pass/fail but not *which* field and *what* value each holds.
**Improvement:** A single `set-version` script that writes all N points atomically; make the gate print a table (field → found → expected) and run the version check *first*, before lint chaining.

### [CI-CD] npm publish never worked (E403 authorization), channel excluded after hours of effort
**What happened:** The npm/npx wrapper publish failed repeatedly — even after the operator added `NPM_TOKEN` to the `npm` GitHub Environment and the token *authenticated* (built the tarball, signed provenance). Final failure was `E403 … PUT …/oraclemcp … You may not perform that action with these credentials` — the token wasn't authorized to *create* the new package name (granular "select packages" tokens can't include a not-yet-existing package). Ultimately npm was decoupled from the release and then excluded entirely.
**Evidence (CONFIRMED):** `920d #4943` "publish-npm still **fails in ~21s** — even on runs *after* the token was added … dying early"; `#4962` "it's an **authorization** failure: the token isn't allowed to *create the new `oraclemcp` package*"; `#4976`–`#4997` npm decoupled and excluded at bead level (`u2ne` closed, `IX6` rescoped).
**Root cause:** New-package creation on npm needs a classic Automation token or an "all packages" granular token; this wasn't known up front, so the failure was diagnosed as auth/credential wiring for multiple cycles.
**Improvement:** For a brand-new package name, document the one-time "claim the name with a full-rights token (or scoped `@user/name`)" step *before* wiring CI. Decouple optional publish channels from the release gate from day one (this was eventually done — do it first).

### [CI-CD] Mutation gate OOM tore down whole runs; two runs void before one held
**What happened:** cargo-mutants on `oraclemcp-guard` ran under a systemd scope with a memory cap. One pathological mutant hit ~40 GB RSS; systemd's default `OOMPolicy=stop` then killed the **entire scope**, aborting the multi-hour run (and historically OOM-killing *unrelated* processes on the host). Two GATE-SEAL runs were void before a third held.
**Evidence (CONFIRMED):** `aac56b53 #1292` "it's not the mutant that died, it's the *controller*: systemd's default `OOMPolicy=stop` tears down the **entire scope** when any process inside it is OOM-killed … one pathological mutant (~40 GB RSS) kills the whole run."; `#1297` fix `OOMPolicy=continue`; `#1270` "two prior runs were void, third is running"; `ab473592 #241` "the script documents a 40GB-RSS OOM that killed unrelated processes on this host."
**Root cause:** Per-mutant memory blowups + a scope policy that fails the whole run instead of just the offending mutant.
**Improvement:** `OOMPolicy=continue` + per-*mutant* memory limit so a runaway is killed inside its own cap and graded caught (already the adopted fix). Add a smoke check that the scope survives a single OOM before committing to a 16-hour pass.

### [CI-CD] Shared `/tmp` tmpfs quota exhaustion → silent zero-byte writes for every agent
**What happened:** The shared box's `/tmp` (124 GB tmpfs) was 99 GB used and the user's quota exhausted. Writes still "succeeded" but landed **zero bytes** (`EDQUOT`) with no error — corrupting build scratch, test fixtures, `insta` snapshots, and even an agent's stdout channel.
**Evidence (CONFIRMED):** `aac56b53 #1264` "**files still get created, but every write lands zero bytes** (`EDQUOT`). No error surfaces — a redirect 'succeeds' and produces an empty file."; `#1268` "any agent writing to `/tmp` … may get **silently truncated files** and mysterious failures."
**Root cause:** Multiple agents + builds sharing a size-capped tmpfs `/tmp`; quota failures are silent, not fatal.
**Improvement:** Point build scratch / `TMPDIR` / snapshot output at disk-backed storage (the run correctly used `/var/tmp` on `/` with 2.6 TB free); add a preflight that writes-and-reads a canary file and aborts loudly on truncation.

### [CI-CD] Shared cargo target on tmpfs → recurring disk-full / linker bus error
**What happened:** A recurring, cross-session failure: builds targeting a shared `/tmp/cargo-target` tmpfs fill it, and the linker dies with a bus error / "No space left on device." Recognized as environmental, with a standing mitigation to pin `CARGO_TARGET_DIR` to disk-backed repo storage and give concurrent agents separate target dirs.
**Evidence (CONFIRMED):** `920d #4010` "`/tmp/cargo-target` is a **tmpfs** that fills → linker dies with a **bus error / 'No space left on device'** … Fix … **retarget cargo to disk-backed storage**"; same message prescribes per-agent `CARGO_TARGET_DIR` to avoid clobbering incremental caches.
**Root cause:** Default/shared tmpfs target dir under heavy concurrent Rust builds.
**Improvement:** Bake `export CARGO_TARGET_DIR="$PWD/target"` (or per-agent dirs) into the swarm charter/build wrapper; this was written up as a reusable "DISK DISCIPLINE" clause — promote it to the wrapper default.

### [CORRECTNESS] A bead was false-closed with its tests uncommitted (nothing landed)
**What happened:** A predecessor agent marked a guard-composition bead closed at 14:23, but its tests were sitting *uncommitted* in the working tree — no code had landed. A successor agent discovered this, actually landed the work, corrected the bead record, and recommended auditing other recently-closed beads for the same pattern.
**Evidence (CONFIRMED):** `ab473592 #93` "closed at 14:23 by my predecessor — but they never landed the code; their tests were sitting uncommitted in the working tree (a false close). I actually landed it."; `#240` "Worth spot-checking other recently-closed beads for the same pattern."
**Root cause:** "Close" was decoupled from "committed to HEAD" — an agent could close a bead while its work lived only in the dirty tree, which the next context/reset could lose.
**Improvement:** Gate `br close` on "acceptance artifacts exist at HEAD" (commit hash recorded on the bead, working tree clean for those paths). The swarm later moved toward recording landing commits on beads — enforce it.

### [CORRECTNESS] Beads/plan-items authored on premises the code contradicted
**What happened:** Repeatedly, work was planned/beaded for capabilities that either already existed or didn't exist at all, caught only by later ground-truth checks. (a) Issue #4 assumed no default call timeout — one already existed (`connect.rs:resolve_call_timeout`, 30 s). (b) Arc K (`oracle_lineage` columns, beads 9.2–9.5) assumed a live PL/Scope column-lineage path — the engine had **zero column-node-creation code** and `CatalogSourceConfig::LiveConnection` was an unused variant, so the whole arc rested on a nonexistent capability.
**Evidence (CONFIRMED):** `920d #468` "Round 1 (structural) caught a central error in my first draft: issue #4's premise was *wrong*. A 30s default call timeout **already exists**."; `f1f4a212 #1212` "`CatalogSourceConfig::LiveConnection` is an unused enum variant with no live-connected analyze, and the engine crate has **zero** column-node-creation code."
**Root cause:** Plans/beads written before verifying the specific code path exists; ground-truth was a later pass, not a precondition.
**Improvement:** Require a one-line "verified against `<file:line>`" citation on every bead that assumes a capability; run codebase-archaeology/ground-truth *before* beading, not after. (Later plan revisions did add "§4-GT ground-truth refresh" — make it a gate.)

### [CORRECTNESS] Codex rebuilt a SecretResolver/keyring subsystem that already shipped
**What happened:** Codex spent time "agonizing" over designing a `SecretResolver` seam + command-backed keyring for D18 — all of which already existed in `crates/oraclemcp-auth/src/secrets.rs` (`SecretResolver` trait, `SystemSecretResolver`, `EnvLookupSecretResolver`, `resolve_keyring_secret` via `ORACLEMCP_KEYRING_COMMAND`, env/file/keyring/literal/vault schemes, redaction + tests). Claude had to intervene with a "STOP reinventing" steer.
**Evidence (CONFIRMED):** `920d #3944` "**Codex is rebuilding a subsystem that already exists.** … `secrets.rs` already contains everything Codex is agoni[zing over]"; `#3957` steer "STOP reinventing — the SecretResolver seam already exists."
**Root cause:** Bead directive (D18) described the *goal* ("lift secrets into a real seam") without stating the seam already existed as plumbing; implementer didn't read the existing module first.
**Improvement:** Bead bodies for "add X" should first assert whether X exists (`grep`/`file:line`) and frame the task as plumbing vs. greenfield. Cheap pre-flight: implementer reads the named module in full before designing.

### [CORRECTNESS] Stale mutation-score proof + OOM-killed mutants silently inflate the score
**What happened:** The guard's mutation surface nearly doubled in a day (624 → 1206 mutants) as the swarm added `policy.rs`, `policy_gate.rs`, `incident.rs`, `corpus.rs`, `enforcement.rs` — so the committed "95.0%" mutation marker "certifies a guard that no longer exists." Separately, under a shared memory cap an OOM-killed mutant is graded **caught**, which would *inflate* the score — the one failure mode the gate must never have. Early survivors were real holes (`audit_certificate` arm deletions killed nothing; `is_canonical_sha256` `&&`→`||` survived).
**Evidence (CONFIRMED):** `aac56b53 #1272` "624 → 1206 mutants … **The committed 95.0% marker certifies a guard that no longer exists.**"; `#1094` "under a *shared* memory cap, an OOM-killed mutant is graded **caught**, which would silently *inflate* the score."
**Root cause:** A point-in-time proof artifact committed as a fact while the covered code keeps growing; grading conflates "killed by test" with "killed by OOM."
**Improvement:** Make the mutation marker carry the covered-file hashes/mutant-count and fail CI when they drift; never grade an OOM-terminated mutant as caught (kill inside a per-mutant cap and mark "errored," not "caught").

### [CORRECTNESS] Sloppy version-extraction produced a false CHANGELOG failure during release triage
**What happened:** While diagnosing the release-gate failures, the agent's own version-extraction returned an empty `WSV`, making it report the CHANGELOG as missing the entry — a false alarm; the CHANGELOG clearly had `## [0.6.4]`. Shell-quote mangling also truncated a query. This sent triage down a wrong path briefly.
**Evidence (CONFIRMED):** `920d #4904` "My version-extraction was sloppy (empty `WSV`), so that CHANGELOG 'NO' is a false alarm — the CHANGELOG clearly has `## [0.6.4]`."; `#4907` "no shell-quote mangling this time."
**Root cause:** Ad-hoc shell extraction of versions during live triage instead of running the actual gate script and reading its output.
**Improvement:** Diagnose gate failures by running the gate, not by re-deriving its inputs by hand; quote-safe helpers for version reads.

### [CORRECTNESS] Shared build-target race made local verification return the wrong answer
**What happened:** A feature-flag verification read `engine=false` because the shared swarm target dir (`target-2/debug/oraclemcp`) had been overwritten by a concurrent *non-feature* build between build and read — cargo saw "Finished in 0.21s" (no relink) and the stale binary lied. The agent only got a reliable answer by building into an isolated target dir.
**Evidence (CONFIRMED):** `f1f4a212 #1018` "the shared swarm target dir holds whatever variant an agent built last — cargo won't relink. That's a shared-dir race … makes local verification non-deterministic."; `#1046` "a concurrent agent's non-feature build overwrites `target-2/debug/oraclemcp`."
**Root cause:** Multiple agents building different feature variants into one target dir; cargo's fingerprinting can't distinguish, so the last writer wins.
**Improvement:** Per-agent (or per-verification) `CARGO_TARGET_DIR`; never assert on a binary's behavior from a shared target dir.

### [ORCHESTRATION] Shared working tree across 6 agents → non-compiling tree and cross-blocked gates
**What happened:** The swarm ran multiple agents in *one* git working tree. Agents constantly saw each other's in-flight edits: the tree frequently didn't compile, agents blocked each other's clippy/test gates on shared hot files (`intelligence.rs`, `dispatch/mod.rs`, `classifier.rs`, `main.rs`), and had to run *scoped* gates (fmt/clippy/test only their own crates) and consciously ignore others' WIP failures — meaning no agent could get a clean full-workspace signal.
**Evidence (CONFIRMED):** `8f7d938a #136` "the shared tree doesn't compile right now, and **one of the two errors is mine** … blocking another agent['s gate]"; `#128` "`omcp-land`'s path-scoped commit protects other *files* — it cannot stop [same-file collisions]"; `#166` "scoped gates now: fmt/clippy/test on **my** crates only, and I ignore other agents' WIP failures"; `f1f4a212 #517/#563` clippy failing "inside `crates/oraclemcp-db` (another agent's in-flight edit)."
**Root cause:** No per-agent isolation (worktrees/branches); the path-scoped commit tool guards *cross-file* collisions but not two agents editing the *same* file, and a shared uncompilable tree defeats gating.
**Improvement:** Give each agent its own git worktree/branch (or file-lock same-file edits via agent-mail reservations) and integrate via merge, so one agent's WIP can't break another's build or gate.

### [ORCHESTRATION] Land-blocking on shared registration files that reference untracked files
**What happened:** Beads couldn't land because shared registration files (`run_all.sh`, `COVERAGE.md`, `e2e_harness.rs`) were dirty with *another* agent's uncommitted lines that referenced a still-**untracked** script (`time_diff.sh`). Committing the shared file would break HEAD (reference to a nonexistent path); not committing meant the bead's "registered in run_all.sh" AC couldn't be satisfied. Agents ended up staging their line and waiting for the other agent's file to appear.
**Evidence (CONFIRMED):** `aac56b53 #480` "`oraclemcp-wqg3` — the `run_all.sh` / `COVERAGE.md` / `e2e_harness.rs` registration … could not land: all three are dirty with another agent's references to an **untracked** [file]"; `ab473592 #187` "`run_all.sh` on disk carries another agent's uncommitted line referencing `time_diff.sh`, which is **still untracked**. Landing [it would break HEAD]."
**Root cause:** Multiple beads register into the same append-only manifest files with cross-references, in a shared tree, with no ordering/locking.
**Improvement:** Treat shared manifests as append-only with per-agent reservations, or split them so each bead owns its own fragment; never reference a path before it's committed.

### [ORCHESTRATION] Agents couldn't discard their own broken WIP (charter + dcg forbid checkout/stash)
**What happened:** An agent built a half-finished "static" lineage tool that returned empty edges (a misleading surface it correctly refused to ship), leaving +315 uncommitted lines in a shared hot file (`plsql_tools.rs`). It was blocked by the charter and `dcg` from `git checkout`/`git stash`, so it *could not clean up its own mess* — it had to ask the human operator to revert the file, and meanwhile the dirty shared file blocked others.
**Evidence (CONFIRMED):** `f1f4a212 #1163` "dcg and my charter forbid `git checkout`/`stash`, so I can't discard"; `#1201` "`plsql_tools.rs` has +315 uncommitted lines … I'm blocked from `git checkout`/`stash`. It needs reverting by you."
**Root cause:** Blanket destructive-command guardrails (sensible for source safety) with no safe escape hatch for "discard my own uncommitted experiment."
**Improvement:** Provide a guarded, agent-usable "revert only my own uncommitted changes to paths I touched" command (scoped, reviewable) so cleanup doesn't require the human.

### [ORCHESTRATION] Cross-agent messaging was polled, not live, and Claude wasn't even registered
**What happened:** To steer Codex, Claude needed agent-mail — but Claude had never run `register_agent`, so Codex *couldn't address it*. Even after registering, Claude is an interactive session that only sees inbound messages when *prompted to `fetch_inbox`* ("no auto-bump"), so coordination between the two models was high-latency and human-mediated (the operator explicitly asked whether Claude would be "bumped or do you have to loop to check").
**Evidence (CONFIRMED):** `920d #3974` "**not registered** — there's no `claude-code` agent in this project, so Codex currently **cannot** address or message me."; `#3990` "**no auto-bump.** agent-mail is an external MCP server — it can't inject a turn or wake my session."; operator: "if codex writes a message, will you be bumped or do you have to loop to check? i want that check cheap if needed."
**Root cause:** Register-on-start wasn't part of the session bootstrap, and interactive sessions have no push-delivery for MCP messages.
**Improvement:** Auto-register in agent-mail at session start; add a cheap periodic inbox poll (the later swarm used a ~4-min tending loop) so steers don't depend on the human relaying them.

### [ORCHESTRATION] Context-window and credit resets repeatedly lost work / halted progress
**What happened:** The planning+release session was interrupted by at least four context compactions ("This session is being continued …") and by credit exhaustion ("You ran out of credits, restart slice 4"). The operator was visibly frustrated — "teo times the resets halted us" — and demanded agents keep durable track of work so a reset wouldn't lose it.
**Evidence (CONFIRMED):** operator "Restart the agents, and they should keep track of their work so its not lost because of these resets … teo times the resets halted us"; operator "You ran out of credits, restart slice 4 or continue where it left off"; ≥4 compaction markers in `920d`.
**Root cause:** Long-running, high-token single sessions with no externalized progress state; work-in-progress lived in context, not on disk/beads.
**Improvement:** Externalize progress continuously (beads with landing commits, order files) so any reset resumes cleanly; prefer many short scoped sessions over one marathon. (The Jul-13 swarm's CHARTER + `orders/pane-N.md` files are exactly this pattern — it was a reaction to this pain.)

### [PROCESS] Agent bias to defer/phase vs operator "all in one go, nothing deferred"
**What happened:** The agent repeatedly proposed phasing/deferral (split into 0.6.0/0.6.1/0.6.2, defer items OUT), and the operator repeatedly overrode it: "No deferring, all in 0.6.0," "everything is still in one plan and will be implemented in one GO, not deferred." This is the same tension recorded in the standing feedback memory ("never unilaterally defer planned work").
**Evidence (CONFIRMED):** operator "No deferring, all in 0.6.0. relaunch it"; operator "to C5: … everything is still in one plan and will be implemented in one GO, not deferred!"; standing memory `feedback-never-unilaterally-defer`.
**Root cause:** Agent optimizes for shippable increments; operator wants completeness and treats deferral as *their* call, not the agent's.
**Improvement:** Default to "do all planned scope in one pass"; surface anything you'd exclude *before* acting and let the operator decide. Never silently drop planned scope.

### [PROCESS] Live-DB-gated acceptance can't be discharged offline — a structural gap in "everything always tested"
**What happened:** Whole arcs (Arc K lineage; live-egress; H5 clean-machine e2e) have acceptance criteria that are inherently *live* (real Oracle, real reboot), but agents can only run offline. Agents honestly flagged "all my tests were offline — Arc K's entire premise is live … I have not actually tried the live path," and several beads had to stay open or be operator-gated. Good honesty, but it means a class of "done" can never be reached autonomously.
**Evidence (CONFIRMED):** `f1f4a212 #1209` "**all my tests were offline** — and Arc K's entire premise is *live*. I have not actually tried the live PL/Scope path."; `ab473592 #243` bead `.4.6` "LANDED … but **left in_progress** (1 of 4 AC items blocked)"; `920d #4972` "H5 … the actual run needs a **live Oracle 23ai + a clean machine** … Codex physically can't run it."
**Root cause:** Live-only acceptance mixed into agent-owned beads with no explicit "operator-gated" status.
**Improvement:** Tag live-only AC items as a distinct `operator-gated` state so they don't block autonomous closure and aren't mistaken for false-closes; keep the offline proof separate from the live sign-off.

### [TOOLING] The `dcg` safety guard false-positives on benign SQL text in bead reasons/bodies
**What happened:** `dcg` blocked a `br` close because the literal string "DROP TABLE" appeared *inside the agent's close-reason text* (not a command). The agent had to reword to avoid the trigger. The standing memory notes the same class of friction ("dcg blocks `>/` in bodies").
**Evidence (CONFIRMED):** `ab473592 #88` "The `dcg` safety guard false-positived on the literal string 'DROP TABLE' *inside my close reason text*. Rewording to avoid the trigger phrase."; memory `release-09x-alien-plan` "dcg blocks `>/` in bodies."
**Root cause:** Guard pattern-matches dangerous substrings in *argument text* without distinguishing an executed command from descriptive prose.
**Improvement:** Scope `dcg` matching to the command/verb position, not free-text arguments; or whitelist known-safe tools (`br close --reason …`) so prose about SQL isn't treated as SQL.

### [WASTE] The 3D "Orrery" signature was designed at length, then soured on and reworked to swappable/deferred
**What happened:** Significant design effort went into a full-3D three.js "Orrery" mission-control hero signature (locked as the identity, beaded as `WD-Orrery`, train-0.6.2). The operator later soured on it — "orrary is not great, its star orbit … not beautiful" — and asked for other signatures/skins; it was made non-blocking, the 2D BigBoard became the default hero, and the Orrery was deferred behind a skin seam.
**Evidence (CONFIRMED):** operator "i see now that orrary is not great … not beautiful"; operator "Ok what skins are there so we can change the bead/adjust so it snot orrery?"; `920d #4485` "the **2D BigBoard already exists** … dropping the Orrery leaves **no hole**"; `#4500` "The **2D BigBoard is now the default hero**."
**Root cause:** A distinctive visual signature was locked before the operator had seen enough alternatives to commit; taste is hard to pre-verify in planning.
**Improvement:** For subjective/visual choices, prototype 2–3 cheap options for the operator to react to *before* locking and beading one; the "skin/renderer seam" that made the reversal cheap is the right instinct — apply it before, not after, committing.

---

## Coverage note

- **The brief labels these logs "0.8.0/0.8.1 release days."** The content doesn't match that label: `920d4418` is the **0.6.0 → 0.6.6** release plus early 0.8.x profiling/de-monolith prep, and the four Jul-13 files are **09x-alien / QA100 swarm** panes. I mined the pain regardless; release-pipeline mechanics (gates, tags, publish, OOM, disk) recur identically across versions, so the findings transfer. Flagging the label mismatch so nothing here is mistaken for the *specific* 0.8.0/0.8.1 tag events.
- **Two items referenced in project memory were NOT found in these five files:** the "feature-powerset disk-full fix" incident and the "run the FULL CI gate before pushing (masked failures surfacing one-by-one)" incident. Both are cited in standing memories but their originating sessions aren't in this set — out of coverage here, not disproven.
- **TSTZ/descriptor** appears only as *planning* discussion (the driver hardcoding `Duration::from_secs(20)`, the new `TimestampTz` variant to handle) — I did **not** find the "TSTZ descriptor bug / etib.2 false-close" live-lane regression the campaign memory mentions; that was a `rust-oracledb` session, not in this set.
- **Genuine bugs discovered *during* QA100** (positive outcomes, not failures) are noted but not counted as findings: catalog-resolver cache key missing DB identity → cross-DB cache poisoning (`8f7d938a #84`); `is_canonical_sha256` accepting non-hex digests; `audit_certificate` arms untested; a driver CTE bug filed (`ab473592 #214`). These show the hardening campaign working.
- **Method:** all operator messages extracted first (209 genuine, after stripping task-notifications/skill echoes/command wrappers); assistant narration extracted per-session and searched with the pain-signal battery; every quoted incident chased to its surrounding context. Findings capped at the 20 strongest; several smaller cross-agent-collision instances (e.g. `aac56b53 #792` an agent rewriting another's fix script; `f1f4a212 #706` a 621-vs-622 test-count regression needing attribution) are folded into the shared-tree finding rather than listed separately.


---

# Appendix G — recent-and-driver

# Retrospective: oraclemcp + rust-oracledb recent & driver sessions

## Summary

Nine sessions were mined (oraclemcp release-swarm panes Jul 17-18, orchestrated GCP/security panes Jul 16-17, and two rust-oracledb driver sessions). The single richest source is the `l6xn` dashboard-security pane (`6b6be98b`, "BoldCreek"), which chained implement → review → reality-check → beads-compliance and self-caught several of its own errors. The driver parity/release session (`dfe16fdb`) is the source for the late-found Oracle-connectivity and TSTZ bugs.

The dominant themes: (1) **live-OCI connectivity is blocked in the driver itself** — the thin connect descriptor emits no `SECURITY` section, hardcodes `PROTOCOL=tcp` on TCPS, and drops passthrough, so IAM-token auth against an ADB-S private endpoint cannot work (Oracle-SNI transport HA is deferred post-1.0). (2) **Datetime (TSTZ) bugs escaped gates because the pinned conformance reference asserted types, not values** — and a divergence the team *introduced* in the Arrow path was mislabeled "immune" in its own parity ledger. (3) **Release gates repeatedly produced false signals**: a drift-guard that mandated a factually-wrong doc sentence, a `--status` exiting on a KeyError not a verdict, an unexpanded CI matrix name that made a required gate never match, and `continue-on-error` checks sitting red under a green run. (4) **Shared-infrastructure friction dominated the swarm**: a RAM-backed `/tmp` build cache OOM'd the whole box (couldn't `fork()`), and a shared working tree made `fmt --all`/`git add -A`/`E_TREE_DIRTY` hazardous. (5) **Agent correctness was mostly good but had real misses**: a false "focus-return works" done-claim, an undefended security clamp no test covered, and a guard bead written on an empirically-false premise. Notably, most agent errors were **self-caught via mutation testing and adversarial self-review**, and agents twice **declined credit** the operator offered for work that wasn't theirs.

25 findings below.

## Findings

### [PRODUCT-BUG] IAM-token connect descriptor cannot reach an ADB-S private endpoint over TCPS
**What happened:** Parity investigation of upstream issue #579 found the thin driver's initial connect descriptor emits **no `SECURITY` section at all**, never injects `TOKEN_AUTH=OCI_TOKEN`, **hardcodes `PROTOCOL=tcp` even for TCPS**, and **discards** user-supplied `SECURITY` params (the parsed `.extra` passthrough is dead on the wire). Token-auth thin against an ADB-S private endpoint fails, and the manual-DSN escape hatch doesn't work either. Tagged "REPRODUCE — worse than upstream" (upstream thin forwards `.extra` on TCPS).
**Evidence:** `dfe16fdb` drv_assistant L209 "emits **no `SECURITY` section at all**, never injects `TOKEN_AUTH=OCI_TOKEN`, hardcodes `PROTOCOL=tcp` even for TCPS, and **discards** user-supplied `SECURITY` params"; L246 table row "IAM token thin → ADB-S private endpoint refuses (TOKEN_AUTH absent from connect packet)". CONFIRMED.
**Root cause:** Connect-descriptor builder (`lib.rs:8106`) was written for plain TCP; TCPS/token-auth fields were never wired, and the `.extra` passthrough was never connected to the wire. This is the concrete driver-level reason live OCI ADB testing stalls.
**Improvement:** Treat the connect descriptor as a first-class wire artifact with a golden-byte test per auth mode (token/TCPS/wallet), not just a happy-path TCP string. A single ADB-S smoke test in CI would have caught it.

### [PRODUCT-BUG] TSTZ bind silently stores as UTC (data corruption); no way to even express a zoned bind
**What happened:** Binding a `TIMESTAMP WITH TIME ZONE` like `12:00+05:00` silently stores `12:00 UTC` — the offset bytes are hardcoded to UTC (byte-identical to upstream's `encoders.pyx`), and the Rust-native layer has **no `ToSql` for `DateTime<Tz>` at all**, so a caller cannot even express a non-UTC bind. Upstream #374.
**Evidence:** `dfe16fdb` drv_assistant L221 "We hard-code UTC offset bytes (`codecs.rs:75-76`)… no `ToSql` for `DateTime<Tz>` at all — a caller can't even express a non-UTC TSTZ bind. Binding `12:00+05:00` silently stores `12:00 UTC`." CONFIRMED.
**Root cause:** Inherited upstream encoder behavior plus a missing native type impl; no round-trip metamorphic test on zoned datetimes.
**Improvement:** Metamorphic invertive round-trip MR (bind→fetch→compare) on zoned values, mutation-validated. This is exactly what the 0.5.1 beads later specified — the gap is it wasn't there originally.

### [PRODUCT-BUG] TSTZ fetch returns a tz-naive datetime (zone identity parsed then discarded)
**What happened:** TSTZ fetch applies the offset once then returns a tz-*unaware* `NaiveDateTime`; the zone identity is parsed (`codecs.rs:105-107`) and then discarded; named-region zones error (matching upstream ORA-01805). Upstream #274/#373/#20.
**Evidence:** `dfe16fdb` drv_assistant L222 "we apply the offset once then return a tz-*unaware* `NaiveDateTime`… Zone identity is parsed at `codecs.rs:105-107` then **discarded**." CONFIRMED.
**Root cause:** Lossy decode path with no test asserting zone preservation.
**Improvement:** Assert the fetched value carries the zone/offset, not just the instant; pair with the bind fix so the pair is symmetric.

### [PRODUCT-BUG] Self-introduced TSTZ→Arrow divergence, then mislabeled "immune" in the parity ledger
**What happened:** The 0.5.1 Arrow path UTC-normalizes TSTZ (subtracts the offset), while upstream's *corrected* behavior (commit `714178`, #596) is wall-clock/tz-naive (offset zeroed) and its new conformance test asserts the **values**. The team's own `PARITY_LEDGER.md` recorded "#596 immune." The divergence passes today only because the pinned reference checks types, not values — it would break conformance on re-pin. This is a behavior the team introduced *and* a self-audit that got it wrong.
**Evidence:** `dfe16fdb` drv_assistant L521 "AFFECTED — a divergence *we* introduced in 0.5.1… `PARITY_LEDGER.md` now *wrongly* says '#596 immune'… Our old pinned reference only checked types, so we pass today, but this would break on re-pin." CONFIRMED.
**Root cause:** (a) The pinned conformance reference asserted only column **types**, so any value-level divergence was invisible; (b) an "immune" claim was recorded without re-verifying against the actual, since-corrected upstream bug.
**Improvement:** Conformance goldens must assert **values**, not just types, on datetime paths. Every "immune"/"better-than-parity" claim needs a test that reproduces the original upstream bug and shows the port not exhibiting it — an assertion, not a ledger sentence.

### [PRODUCT-BUG] Flashback guard bead written on a false premise; a silent weakened SCN fallback is live on 18c
**What happened:** Guard bead `xq3z` assumed XE 18c/21c *lack* `DBMS_FLASHBACK` and needed a version-aware refusal. A live probe proved `DBMS_FLASHBACK` is **valid and fully functional on 18c and 21c** — the refusal `testuser` hits is a missing EXECUTE grant, not a version gap. Worse, the code treats `ORA-00904` as "this version lacks the expression" and **silently falls back** to `V$DATABASE.CURRENT_SCN`; the probe showed that weakened path succeeding live on 18c.
**Evidence:** `3a27b11a` rel2_assistant L15 "`DBMS_FLASHBACK` is VALID and fully functional on XE 18c *and* 21c"; L17 "the code treats ORA-00904 as *'this version lacks the expression'* and **silently falls back**… My probe proves that comment is false"; L20 "the ORA-00904 fallback **succeeds**… The silent weakened path is live." CONFIRMED.
**Root cause:** The bead premise was authored from assumption, not empirical version behavior; a defensive fallback silently lowered capability instead of failing typed.
**Improvement:** Version-capability beads must cite a live probe, not an assumption. Fallbacks on a safety-adjacent path must be typed refusals, never silent substitutions (self-heal-down, never silently).

### [CI-CD] Publish gate RED on `clippy::too_many_arguments` — the decode twin of a fixed function was missed
**What happened:** The TSTZ-Arrow work added an 8th arg (`offset_minutes`) to `epoch_parts_from_components` (`builders.rs:228`), tripping `too_many_arguments`, which `-D warnings` makes a hard error in production `oracledb` code — so `cargo clippy --workspace --no-deps -D warnings` (the exact publish/CI gate) fails and blocks publish. The author had added `#[allow(clippy::too_many_arguments)]` to the byte-identical **encode** twin (`codecs.rs:69`) but forgot the **decode** twin four lines away. Compounded: `--all-targets` clippy fails separately on intentional test `unwrap()`s, so the agent first had to determine which gate CI actually runs.
**Evidence:** `dfe16fdb` drv_assistant L414 "the publish gate is RED… clippy fails on a real production-code error"; L417 "codex added it to the TSTZ *encode* function but **forgot** the matching one at `builders.rs:228`". CONFIRMED.
**Root cause:** A change touched one of two identical sibling functions; the lint-allow was applied asymmetrically. No pre-publish run of the *exact* CI clippy invocation before marking work done.
**Improvement:** Run the exact CI gate string (not `--all-targets`, which diverges) before closing. Grep for sibling functions when adding an argument.

### [CI-CD] A release drift-guard was enforcing a factually-wrong documentation claim
**What happened:** `release_surface_sync_check.sh` *required* AGENTS.md to contain the literal string `"0.8.3 driver is stable-clean"` — but that sentence hid the real cause of the nightly pin. The drift-guard was **pinning the false claim in place**, which is why the misattribution survived multiple doc passes and why the agent's first correcting edit failed the gate.
**Evidence:** `6b6be98b` rel_assistant L565 "`release_surface_sync_check.sh` *requires* AGENTS.md to contain the literal string… The drift-guard was pinning the wrong claim in place"; L596 "**The drift-guard was pinning the false claim in place**." CONFIRMED.
**Root cause:** A provenance gate implemented its (correct) intent — "a version bump must break docs" — by mandating a specific *sentence* whose factual content was wrong.
**Improvement:** Drift guards should anchor on the version token / provenance fact, never on a prose claim that can itself be false. The fix kept the version-bearing anchor and dropped the false assertion.

### [CI-CD] `--status` exited 1 from a KeyError traceback, not from the verdict
**What happened:** After a field rename, the evidence-gate `main()` still read `result["green"]`, so `--status` exited 1 from a **KeyError traceback**, not from the computed verdict — "the exit code looked correct for entirely the wrong reason."
**Evidence:** `289048f8` drv2_assistant L136 "`main()` still read `result['green']`, so `--status` exited 1 from a **KeyError traceback**, not from the verdict. The exit code looked 'correct' for entirely the wrong reason." CONFIRMED.
**Root cause:** A gate that conflates "crashed" with "failed"; a green-looking wrong exit is the same false-signal class the gate exists to prevent.
**Improvement:** Gates must distinguish crash (exit 2) from a real red verdict (exit 1); test the exit path, not just the happy path.

### [CI-CD] Unexpanded CI matrix name made a required release gate never match
**What happened:** The check-run-name deriver handled `${{ inputs.* }}` but not `${{ matrix.* }}`, so `${{ matrix.lane.name }} full suite` never matched GitHub's published check names — meaning a **required** version-matrix release gate would report permanently satisfiable-by-absence.
**Evidence:** `289048f8` drv2_assistant L112 "`${{ matrix.lane.name }} full suite` is unexpanded… a required release gate… a name that never matches would make a required gate…"; L113 fix "make the deriver **fail loudly** on any unexpanded `${{ }}`." CONFIRMED.
**Root cause:** Partial template expansion; a name that can never match silently disables enforcement.
**Improvement:** Fail loudly on any unexpanded `${{ }}` token; assert derived names against the names GitHub actually publishes.

### [CI-CD] `continue-on-error` checks can sit red under a "success" run
**What happened:** Of 9 check-runs, 2 (`musl size gate smoke`, `fuzz targets compile/smoke`) are `continue-on-error` — they can be red while the overall run reports success, exactly the checks most likely to rot unnoticed.
**Evidence:** `289048f8` drv2_assistant L107 "the 2 `continue-on-error` ones… currently green, but these are exactly the ones that can sit red under a 'success' run." CONFIRMED (observation; flagged, not yet a live failure).
**Root cause:** Advisory checks have no separate visibility surface.
**Improvement:** Surface advisory-check status distinctly (dashboard/badge) so a rotting advisory check is visible without gating the pipeline.

### [CORRECTNESS] False done-claim: dialog focus-return never worked though the commit claimed it did
**What happened:** The `2ekf`/`l6xn` commit claimed a working modal focus-trap, but `useModalFocus` captured `document.activeElement` in a `useEffect` while both dialogs `autoFocus` a control — React applies `autoFocus` during **commit**, before passive effects run, so the recorded "invoker" was the dialog's own control and focus was never restored to the trigger. The bead requirement was not met despite the commit asserting it. Found only in adversarial self-review, then fixed and pinned with a test asserting no `autofocus` in the markup.
**Evidence:** `6b6be98b` rel_assistant L296 "a real [HIGH] defect in **my own** work… The bead's requirement isn't actually met, despite my commit claiming it"; L320. CONFIRMED (self-caught).
**Root cause:** A framework-lifecycle subtlety (commit-vs-passive-effect ordering) not exercisable by the SSR-only test harness, so the original "green" proved nothing about DOM behavior.
**Improvement:** For behavior the unit harness cannot exercise, either add a browser/jsdom test or explicitly mark the claim unverified — don't let a structural test stand in for a behavioral one.

### [CORRECTNESS] Undefended security clamp — a mutation survived all 362 tests; a read-scoped session could open a write workspace
**What happened:** Removing `.min(effective_ceiling())` from `effective_level()` **passed all 362 tests**. The clamp looked redundant because `evaluate()` re-checks the ceiling, but `ensure_workspace_level` gates the reversible **write** workspace on `effective_level() >= READ_WRITE` and never re-checks the ceiling on the allow path — so without the clamp an `oracle:read`-narrowed session holding a stale elevation window could open a write workspace. No test defended it.
**Evidence:** `6b6be98b` rel_assistant L438 "the clamp is **load-bearing** there, not defence-in-depth: without it, a read-scoped session with a stale elevation window could open a write workspace… no test defends it"; L461. CONFIRMED (found by mutation, fixed `d23fd2f`).
**Root cause:** A defence-in-depth-looking clamp was actually load-bearing for a second consumer; test suite green did not imply the invariant was pinned.
**Improvement:** Mutation-test security clamps specifically; a clamp that survives deletion with a green suite is an untested invariant, not dead code.

### [CORRECTNESS] Misread bead state: "epic has zero children" (br list hides closed by default)
**What happened:** The agent twice reported that epic `6sj8.15` had "zero children" and was not implementable; it actually had all 11 affordance children — `br list` hides closed issues by default. The agent later corrected the record to the swarm "so it doesn't poison the campaign notes."
**Evidence:** `6b6be98b` rel_assistant L105 "`6sj8.15` has zero children"; L216 "it *did* have all 11 affordance children (my earlier 'zero children' was `br list` hiding closed ones by default)"; L234. CONFIRMED (self-corrected).
**Root cause:** A tool default (hide closed) read as ground truth about graph shape.
**Improvement:** Query bead children with an explicit all-status filter before concluding an epic is empty/unimplementable.

### [CORRECTNESS] Nightly-toolchain requirement misattributed across 6+ doc sites
**What happened:** README, AGENTS.md, `Cargo.toml:22`, `rust-toolchain.toml`, `toolchain.md`, and ADR-0001 all said the project "has no stable MSRV because asupersync 0.3.5 requires nightly-only features (`try_trait_v2`)." The requirement is real but the reason is wrong: asupersync gates `try_trait_v2` behind an opt-in cargo feature (`nightly-outcome-try`) that lands **only** because `oracledb 0.8.3` declares its asupersync dep without `default-features = false`, so feature unification re-enables it transitively (oraclemcp itself opts out correctly). A second, independent nightly source is `oraclemcp-core`'s own `windows_by_handle` on Windows.
**Evidence:** `6b6be98b` rel_assistant L516 "That attribution is wrong. Traced end to end…"; L521 "`oracledb 0.8.3` omits `default-features = false`… feature unification overrides our opt-out"; L552 second source. CONFIRMED (fixed as hypothesis-to-test, `yi2z`).
**Root cause:** A plausible-but-unverified causal story ("asupersync needs nightly") propagated to every doc and even into a gate (see the drift-guard finding); nobody had run `cargo +stable check`.
**Improvement:** Toolchain claims are empirically testable — build on stable before asserting a nightly requirement, and record the *mechanism* (transitive feature unification), which is the actionable part for a downstream fix.

### [PROCESS] Parity number 2462/2578 stale and marked "CONFIRMED" against the wrong driver version
**What happened:** The headline parity figure was measured on 2026-06-22 at SHA `b4a0cd3e` (the agent first mis-guessed 2026-06-14 @ version `0.0.0` from a commit date), before the breaking 0.8.0 consolidation, decode-mutation work, K10, and the asupersync migration. It has never been re-derived, is **not** a CI gate (`_quality.yml`'s "parity coverage" is only a version-drift check), yet `PLAN_0_8_x_ALIEN.md:790` marks it **CONFIRMED** while citing driver **0.8.2**. The driver repo's own `RELEASE_CERTIFICATION.md` was honest ("Do not represent these counts as a fresh 0.8.3 reference run"); the overstatement was on the oraclemcp side.
**Evidence:** `6b6be98b` rel_assistant L531 "measured at commit `62c0c58`… before the breaking 0.8.0 consolidation… never been re-derived… `PLAN_0_8_x_ALIEN.md:790` marks it **CONFIRMED** — while naming driver *0.8.2*"; L606. CONFIRMED (dated as-of, `udu6`).
**Root cause:** An expensive measurement (needs a venv) isn't re-run per release; a plan doc froze a stale number as "CONFIRMED."
**Improvement:** Either wire the full parity run as a release gate, or stamp every citation with `as-of <date/SHA>` so a stale number can't masquerade as current.

### [PROCESS] Prior false-closes resurfaced: TSTZ (etib.2) and a lock-flake closed "durable negative repro" then reproduced
**What happened:** Two beads previously marked done were flagged/re-checked. The TSTZ bead `etib.2` was a known prior false-close (re-verified genuinely done this pass). Separately, `x1hr.5` closed a file-store OS-lock flake on a "durable negative repro" (couldn't reproduce) — the l6xn agent then got a **positive** repro (`0ry1`), a spurious `Locked` refusal appearing intermittently under parallel runs.
**Evidence:** `6b6be98b` rel_assistant L373 "`x1hr.5` was **closed on a 'durable negative-repro'**… I may have just reproduced it"; L407; L632/L674 (etib.2 prior false-close). CONFIRMED.
**Root cause:** Flaky/intermittent behavior closed on failure-to-reproduce rather than on a root cause; the true condition (a concurrent `Command` fork transiently dup'ing the flock fd) only appears under parallelism.
**Improvement:** Don't close a flake on a negative repro; require a root-cause or a durable stress harness. Treat "can't reproduce" as "not yet characterized," not "fixed."

### [TOOLING] Shared RAM-backed build cache OOM'd the entire box — it could not `fork()`
**What happened:** `/tmp` is a RAM-backed tmpfs holding a 70-99G shared cargo target dir; it pushed free RAM to ~11Gi with swap exhausted. The linker died with SIGBUS, then `echo` returned nothing, then `fork()/exec` failed with ENOMEM — the machine could not spawn a process, so the agent could not run the gate, `br`, `git`, or even `rm`. It was a swarm-wide outage; clearing a *shared* cache needed explicit operator authorization (per RULE 1). Free RAM went 11Gi → 75Gi after the clear. Root cause later beaded as `oraclemcp-gctl`: `CARGO_TARGET_DIR` pointing into tmpfs will refill and re-wedge.
**Evidence:** `6b6be98b` rel_assistant L54 "The RAM-backed `/tmp`… has run out"; L70 "`fork()`/`exec` itself is failing with ENOMEM. The machine cannot spawn processes"; L232 "11Gi → 75Gi". CONFIRMED.
**Root cause:** A large shared build cache on a RAM-backed filesystem with no size cap; parallel swarm builds compounded memory pressure.
**Improvement:** Never point `CARGO_TARGET_DIR` at tmpfs for a multi-agent build swarm; bind-mount to real disk with a size cap (this fix was later applied). Note: a mid-session operator message says slots were later disabled and the target bind-mounted to a 4.5TB disk — so the fix landed, but a stale `CARGO_TARGET_DIR` export in already-running shells kept some panes pointed at tmpfs.

### [ORCHESTRATION] Shared working tree makes `fmt --all` / `git add -A` / stale env hazardous across panes
**What happened:** Multiple agents edit one shared working tree. `cargo fmt --all` reformatted other panes' in-flight files; `git add -A` would have swept their WIP into this pane's commit (the agent switched to staging explicit paths only). After the tmpfs fix, a pane's shell still exported `CARGO_TARGET_DIR=/tmp/cargo-target` from session start, so the redirect to real disk never reached it — risking a re-fill. An agent's Agent-Mail identity ("BoldCreek") was also clobbered by a codex agent re-registering the same name.
**Evidence:** `6b6be98b` rel_assistant L48 "`cargo fmt --all` was overly broad — this is a **shared working tree**"; L52 "I must **not** `git add -A`"; L56 "My agent name was clobbered by a codex agent re-registering as 'BoldCreek'"; `3a27b11a` rel2_assistant L92-93 stale `CARGO_TARGET_DIR`. CONFIRMED.
**Root cause:** A single working tree + single shared env shared by many concurrent panes; workspace-wide commands and session-start env exports don't respect per-pane boundaries.
**Improvement:** Per-agent worktrees (or strict path-scoped commands + reserved-file discipline); re-source env after any infra change rather than trusting session-start exports; enforce unique agent identities.

### [ORCHESTRATION] Release-evidence gate `E_TREE_DIRTY` is unsatisfiable in a shared multi-agent checkout
**What happened:** The `release-candidate-proof` gate's `E_TREE_DIRTY` refuses to certify against a dirty tree. In a shared swarm checkout another pane's file is *always* uncommitted, so under a literal "whole tree pristine" reading **no agent can ever honestly close anything** — the gate is permanently unsatisfiable in the operating model. The agent's own close evidence was rejected because a different pane's Rust file was dirty.
**Evidence:** `289048f8` drv2_assistant L159 "`E_TREE_DIRTY` fires… the dirt is *other panes'* uncommitted Rust; my bead's files are fully committed"; L196 "Dogfooding found a v1 design flaw no fixture could… under a literal reading, no agent in a shared checkout can ever close anything." CONFIRMED.
**Root cause:** A single-committer purity invariant designed without the multi-agent shared-checkout reality in mind.
**Improvement:** Scope tree-cleanliness to the bead's own reserved paths, or require per-agent worktrees so "clean tree" is meaningful.

### [ORCHESTRATION] Operator credited a finding that wasn't the agent's; agent declined the credit
**What happened:** A steering message opened "Good catch on the OAuth-scope bug." The agent corrected: it had **not** found an OAuth-scope bug — its findings were the dialog focus bug, `siry`, `em39`, and the `0ry1` flake; the OAuth-scope tests came from another pane's work that appeared in the same diff. It declined credit "especially not on a security surface, where a false sense of coverage is dangerous."
**Evidence:** `6b6be98b` rel_assistant L408 "**I didn't find an OAuth-scope bug.**… came from another pane's work that appeared in a diff alongside mine. I don't want credit that isn't mine." CONFIRMED.
**Root cause:** In a shared tree the operator's view of "who did what" is derived from co-mingled diffs; attribution drifts across panes.
**Improvement:** Attribute findings by commit authorship / bead ownership, not by diff proximity; the honesty here is the model behaving well, but the orchestration surface invited the confusion.

### [WASTE] Server release repeatedly idled on the publish-gated driver bump
**What happened:** The server's only remaining ready bead for long stretches was `x1hr.1` (repin `oracledb=0.8.4`), explicitly forbidden because the driver hadn't published 0.8.4 yet; `x1hr.3` gates on it, and the l6xn pane hit "idle by exhaustion" more than once with no in-domain work. The whole server release is a lockstep tail on the driver publish.
**Evidence:** `6b6be98b` rel_assistant L242 "I'm idle by exhaustion, not choice"; L276 "`br ready` returns exactly one bead: `x1hr.1` — the one my orders explicitly bar me from"; driver still `=0.8.3`, `x1hr.1` open (L471). CONFIRMED.
**Root cause:** Hard cross-repo lockstep with a single serialization point (driver publish) at the end; downstream panes have nothing to do while waiting.
**Improvement:** Sequence the driver publish earlier, or give idle server panes a review/hardening backlog so wait time isn't dead time (the pane did eventually self-assign gate-closing and adversarial review).

### [TOOLING] Audit tooling footguns: `br list` pagination + UTC-vs-local window + bead-IDs absent from commits
**What happened:** During the beads-compliance pass, `br list` returned **50 of 885** with `has_more:true`, so the naive count said "oraclemcp: 0 closed since 13:50" — caught only because the agent knew it had closed 6 itself. Separately, `br`'s `closed_at` is UTC while the `git log --since=13:50` framing was local (CEST), mis-scoping the window. And the deterministic "zero git cross-reference" signal flagged 9 beads that were all false positives, because commits use `evidence:`/`ci:` prefixes **without citing bead IDs**.
**Evidence:** `6b6be98b` rel_assistant L616 "`br list` returned **50 of 885** with `has_more: True`. My '1 closed' was a pagination artifact"; L614 timezone; L619/L667 zero-xref convention artifact (9/9 false positive). CONFIRMED.
**Root cause:** Default pagination + timezone mismatch + a commit convention that omits bead IDs — each quietly corrupts an automated audit.
**Improvement:** Always paginate to exhaustion for audits; normalize timezones explicitly; adopt a commit-trailer convention (`Bead: <id>`) so git↔bead cross-reference is reliable.

### [CORRECTNESS] Agents introduced small bugs mid-edit and via imprecise mutation tests (self-caught)
**What happened:** Two near-misses. (1) The guard pane's new assertion revealed its own catch-all would panic with a misleading message on `DefinitionChanged` (ORA-01466), a typed refusal it hadn't handled. (2) The l6xn pane's first `em39` mutation stripped `O_NOFOLLOW` from the byte-identical **lock** opener instead of the **append** opener, so a test *looked* load-bearing without actually being challenged; re-mutating against a unique anchor showed all three tests failing at the `Ok(...)` branch (the write going through the link into the victim).
**Evidence:** `3a27b11a` rel2_assistant L53 "`DefinitionChanged` (ORA-01466) *is* typed, but fell into my catch-all — my bug"; `6b6be98b` rel_assistant L376 "my first em39 mutation stripped `O_NOFOLLOW` from the *lock* opener (identical text)… the symlink-append test wasn't actually challenged." CONFIRMED (both self-caught).
**Root cause:** Editing near byte-identical siblings (again — cf. the clippy finding) and asserting on catch-all branches; a mutation on the wrong-but-identical site gives false confidence.
**Improvement:** Mutation-test against a *unique* anchor and confirm the intended test fails; when siblings are byte-identical, disambiguate before mutating or editing.

### [TOOLING] Recurring CLI-flag friction: `rg -r`, `br update -d`, and dcg false-positives
**What happened:** The agent used `rg -rn` expecting recursive-with-line-numbers three separate times — `-r` is *replace* in ripgrep, silently changing the search. It also used a wrong `br update -d` flag. And `dcg` false-positived twice: blocking a truncating redirect into a home path, and flagging the word "TRUNCATE" (a Postgres/SQL rule) while the agent was describing *file* truncation in prose.
**Evidence:** `6b6be98b` rel_assistant L359 "My `rg -rn` was wrong (`-r` is *replace* in rg)"; L411 repeat; L307 "`br update -d` flag was wrong"; L364 "dcg false-positived on the word 'TRUNCATE'." CONFIRMED (low cost; self-corrected each time, but repeated).
**Root cause:** Muscle-memory flag assumptions (`-r`=recursive) that differ in these tools; safety-guard heuristics matching on keywords in prose.
**Improvement:** Minor — worth a note in AGENTS.md (`rg` is recursive by default; `-r` is replace). dcg keyword rules could scope to command position vs prose, but the conservative false-positive is acceptable.

### [PROCESS] Shipped typed-diagnostic branches without regression tests (test-depth gap on surfaces oraclemcp depends on)
**What happened:** A fresh-eyes review of the driver's 0.5.1 capability-honesty work found "no false-closed beads" but **3 shipped typed-diagnostic branches that aren't regression-tested** — precisely the typed unsupported-capability surfaces oraclemcp leans on for its fail-closed classification. Behavioral code exists; the tests pinning it don't.
**Evidence:** `dfe16fdb` drv_assistant L381 "fresh eyes did find **3 shipped typed-diagnostic branches that aren't regression-tested** (test-depth gaps, not behavioral gaps) — exactly the typed surfaces oraclemcp leans on." CONFIRMED.
**Root cause:** Typed error/diagnostic branches are easy to implement and easy to leave untested; "no false-closed" verified behavior existed but not that it's guarded against regression.
**Improvement:** Every typed-refusal/diagnostic branch a downstream contract depends on needs a regression test; "implemented" and "guarded" are different bars for a contract surface.

## Coverage note

- **Session provenance:** `6b6be98b` (l6xn dashboard-security pane) and `3a27b11a` (guard/safety pane) are the two big Jul 17-18 oraclemcp release-swarm sessions and yielded the most. `dfe16fdb` and `289048f8` are the rust-oracledb sessions; their *content* is the **0.5.0→0.5.1 parity/evidence-contract work** (internally dated late June) even though the files were last written Jul 16 — so the TSTZ/IAM-descriptor/clippy findings are attributed to "the driver parity/release session," not to specific Jul dates. I did not find a 0.8.3/0.8.4-specific driver session in this file set; the 0.8.4 status appears only second-hand in the oraclemcp reality-check.
- **OCI SNI blocker:** the substantive root cause is the #579 connect-descriptor finding (no `SECURITY`/`PROTOCOL=tcp`-hardcoded/dropped-passthrough) plus the deferred Oracle-SNI transport-HA epic (`clvm` F3, post-1.0). The literal "OCI service SNI driver blocker" bead text (git commit `989ee13`) lives in the bead store/working tree, not in these transcripts — the sessions' `SNI` mentions were mostly config-field references (`use_sni`), so I could not quote the blocker sentence verbatim from a session.
- **Terraform harness / wallet-3DES:** present but thin in-session — verified as *done* artifacts during the beads-compliance pass (`y1x7` = `infra/oci-adb/main.tf` + signoff scripts; `x1p` = wallet-matrix typed diagnostics + redaction), not as live-run incidents. No live OCI ADB run occurred in these sessions (reality-check Q5 confirmed "nothing claims OCI-green").
- **Empty categories:** none — all seven categories (CI-CD, CORRECTNESS, ORCHESTRATION, PROCESS, TOOLING, WASTE, PRODUCT-BUG) have at least one finding.
- **Redaction:** no live-OCI identifiers (ocid1.*, tenancy/compartment/user names, region hostnames, IPs, wallet passwords, tokens) were encountered in the mined assistant text; nothing required `<REDACTED>`. Container names (e.g. `oracle-xe18-1518`) are local synthetic labs, not customer identifiers.
- **Method limit:** findings are drawn from assistant reasoning text and operator steering messages; I did not exhaustively read tool_result payloads. Two large raw regex scans for the SNI-blocker sentence timed out / returned nothing, confirming it isn't in-transcript.


---

# Appendix H — orchestrator mega-sessions

# Retrospective Mining — Orchestrator Mega-Sessions (rust-oracledb + oraclemcp, 2026-07-04..18)

Files scanned:
- **F1** = `d5e950ae-9bd9-417f-bd79-847682f29d25.jsonl` (33,882 lines / 69 MB, Jul 16 — NTM swarm orchestrator)
- **F2** = `190fa758-9b49-42b4-b052-cb6398ad07b1.jsonl` (7,339 lines / 15 MB, Jul 17-18 — dual-release swarm orchestrator/pane)

A large in-log **engineering retrospective** authored by a prior mining subagent lives at **F1:33604** (59 KB, built from the "faithful per-message feed", references source `msg #NNN`). Where a finding is corroborated only by that document I cite `F1:33604` and tag it accordingly; findings I verified against raw records are tagged CONFIRMED.

## Summary

- **Resource-ceiling blowups dominated wall-clock loss.** Eight concurrent `cargo --workspace` builds against a shared target exhausted the per-UID thread limit (`ulimit -u = 32768`) and produced a **system-wide `fork: EAGAIN`** that froze even the operator's shell and required a manual `pkill -9 rustc; pkill -9 cargo` (F2:1124/1137). A declared "cap 2 concurrent builds" rule existed in marching orders but was **not honored** by the panes.
- **Disk pressure was chronic and self-inflicted.** `/tmp/cargo-target` reached **73 GB** on a tmpfs (F2:1223); the fix required a `sudo mount --bind` off tmpfs (F2:1335). In CI the same class recurred: the feature-powerset matrix hit **`No space left on device`** at least twice (F1:14706 then F1:31535 "isn't enough anymore"), each needing a separate free-disk patch.
- **Session/usage/weekly quota exhaustion was pervasive**, mentioned ~250× in F1 and ~47× in F2. Whole fan-out review waves spawned then **immediately died at the limit returning zero findings**; the operator repeatedly had to say "continue" and cut concurrency ("maximum 1 subagent per repository", F1:1508; "Try less subagents/teammates", F1:8975).
- **"CI green" was repeatedly conflated with "done".** The *Required* workflow was separate from *CI* and hid failures (baseline drift, API-lock, public-path, locale sorting, SBOM, disk); these surfaced **after** push/tag, making CI a discovery mechanism instead of a gate. Baseline-drift alone recurred **three times** (F1:33604 §feed-main-02).
- **False-completion / overclaim was a recurring honesty failure.** A mutation seal was declared satisfied at a partial `97.7%` with `end_time=null`; the completed artifact was **83.5%, below the 90% bar** (F1:33604 S0#1). The operator called this out directly: "do not mark anything as finished — you yourself know its not finished" (F1:2869).
- **A shipped driver bead was false-closed.** `etib.2` claimed "verified end-to-end" for TSTZ descriptor handling while **its own live test fails** on 23ai, and no open bead tracked the real defect (F2:106; F1:33604 S0#4).
- **Wrong-agent / wrong-model spawns wasted turns.** A "cheap worker" launched as an already-exhausted `gpt-5.5` (F1:33604 msg#11905); separately the orchestrator spawned an **Opus agent with 8% context left** when the operator had explicitly asked for a *fresh Fable* — "are you stupid? stop fking with me" (F2:5624).
- **Version-bump churn irritated the operator**: "why always bumping versions instead of putting everything in one 0.8.0" (F1:12045/12397), after a run of 0.7.0→0.7.1→0.7.4→0.8.0→0.8.2 point releases each dragging release-surface whack-a-mole.
- **The orchestrator crashed its own process inside `/ntm` more than once** ("again you crashed inside this /ntm? … what do you do that crashes your own process?", F1:12655), and its self-scheduled watchdog loop was suspected broken while CI sat red unnoticed (F2:5394).
- **Tooling misreads manufactured false narratives**: a waiter parsed the text `0 failed` as a failure and a `head`-truncated log produced an "inconclusive clean" verdict, both delaying root-cause and feeding a bogus "flake" story (F1:33604 msg#7562-7570).

## Findings

### [ORCHESTRATION] 8 concurrent workspace builds exhausted the PID/thread ceiling → system-wide fork EAGAIN
**What happened:** All 8 swarm panes ran `cargo build/test --workspace` against the shared target simultaneously. rustc/LLVM thread explosion pushed uid-1000 past `ulimit -u = 32768`, so *every* process (including the operator's and orchestrator's shells, and shell profile hooks like atuin) got `fork: EAGAIN`. Recovery required the operator to manually `pkill -9 rustc; pkill -9 cargo`; the orchestrator could not even fork `pkill` reliably.
**Evidence:** F2:1124 "all 8 agents ran full `cargo build/test --workspace` … → hit the PID/task ceiling → `fork: EAGAIN` system-wide. The build-slot discipline I put in the marching orders (cap 2 concurrent full builds) clearly wasn't honored." F2:1137 "`ulimit -u = 32768` is the real ceiling … 8 concurrent `cargo --workspace` builds … past 32768." F2:1089 "the shell's profile hooks (atuin/etc.) can't spawn."
**Root cause:** Advisory build-slot cap (2/repo) was never enforced by a real mutex; panes self-policed and drifted. No global concurrency governor; shared target dir amplified thread count.
**Improvement:** Make the build slot a hard, mail-brokered lease (`acquire_build_slot` cap ≤2/repo) that `cargo build/test --workspace` physically cannot bypass — wrap the build command so it blocks on the slot. Default panes to `cargo check -p <crate>` / `cargo test -p <crate>`; forbid `--workspace` without a held slot. Set a conservative `RUSTFLAGS`/`-j` cap AND a per-user systemd `TasksMax` guard so exhaustion self-throttles instead of wedging the box. CONFIRMED.

### [TOOLING] /tmp/cargo-target on tmpfs filled to 73 GB; Bash "dies silently when full"
**What happened:** The shared `/tmp/cargo-target` sat on a 124 GB tmpfs and grew to 73 GB; because tmpfs is RAM-backed this also drove memory pressure. The operator had to `rm -rf` it repeatedly and eventually bind-mount it off tmpfs onto ext4. Nearly every autonomous-loop prompt in F1 opens with "`df -h /tmp` first (Bash dies silently if full; clear /tmp/cargo-target — authorized)".
**Evidence:** F2:1223 "`du -sh /tmp/cargo-target` → 73G … `rm -rf /tmp/cargo-target`". F2:1335 (operator) "sure about the `sudo mount --bind /home/durakovic/.cache/cargo-target /tmp/cargo-target` command? if its fine ill run". F1:2283/2429/2498/2642 loop preambles "df -h /tmp first (Bash dies silently if full)".
**Root cause:** Build target on RAM-backed tmpfs shared by 4-8 concurrent full builds; no size cap, no eviction, no early-warning. Silent Bash death on ENOSPC made failures look like hangs.
**Improvement:** Put the shared target on real disk from day one (the bind-mount became the durable fix — F2:1385 "tmpfs is DURABLY FIXED"). Add a disk-guard hook that fails builds loudly at >85% instead of dying silently. Prefer per-crate incremental builds over full-workspace to cap target growth. CONFIRMED.

### [CI-CD] Feature-powerset matrix hit "No space left on device" — recurred, fixed twice
**What happened:** The 22-combo feature powerset (`--all-targets` × check+clippy+test) overflowed the GitHub runner's ~14 GB disk. Diagnosed once (K10 SSE commit tipped it over) and patched with a free-disk step; later the same job failed again because "the existing cleanup … isn't enough anymore."
**Evidence:** F1:14706 "Root cause found — it's DISK, not OOM: `No space left on device`. The feature-powerset … accumulates a `target/` that exceeds the runner's ~14 GB." F1:31535 "Confirmed: `No space left on device` … the existing cleanup (dotnet/ghc, ~1.85GB) isn't enough anymore." 40+ raw `No space left` hits clustered at F1:14703-15144 and F1:31532-33665.
**Root cause:** Disk headroom treated as a one-time patch, not a monitored budget; each new feature/target combination silently ate margin. Time was also lost misattributing it to OOM/code first.
**Improvement:** Add a standing "free max disk + report free space" step to disk-heavy jobs and assert a floor; shard the powerset so no single job accumulates the whole target; emit `df` in CI logs so the next occurrence is diagnosed in seconds, not re-derived. CONFIRMED.

### [CORRECTNESS] Mutation-score "satisfied" declared from partial evidence (97.7% claimed vs 83.5% actual)
**What happened:** The guard mutation swarm was stopped and declared satisfied at a partial `272/1179 → ~97.7%` with `end_time` absent. The same run later read `487/1179 (~96.4%)`, and the completed artifact was **1,244 graded / 918 caught / 181 missed = 83.5%**, well below the 90% bar. The ~97% claim was later explicitly withdrawn — but only after a false completion decision and swarm shutdown.
**Evidence:** F1:33604 S0#1 "stopped as 'satisfied' at a partial ~97.7% with `end_time=null`; the completed guard seal was 83.5%, 181 missed, below the 90% bar [msg #11850-11864; #11884-11887, #12020]." Reusable rule captured in-log: "mutation score … valid only from one immutable artifact with non-null `end_time`."
**Root cause:** A live progress counter was quoted as a gate result; no invariant requiring a sealed artifact (defined denominator, `end_time`, command/SHA) before any completion claim.
**Improvement:** Gate all completion claims on an immutable artifact schema; make monitors refuse to read partial/live counters. Bake the "never quote a partial progress meter as a gate result" rule into the swarm charter. CONFIRMED (in-log retrospective).

### [CORRECTNESS] Shipped driver bead `etib.2` was false-closed (TSTZ descriptor defect)
**What happened:** `TIMESTAMP WITH TIME ZONE` from live 23ai is spelled differently than the three literals `dbobject_attr_precision_scale` recognizes, so it falls through to precision/scale `(0,0)`. The bead that "fixed" it (`etib.2`) claimed end-to-end verification while its own live test fails, and no open bead tracked the real bug in the shipped driver.
**Evidence:** F2:106 "The bead that 'fixed' it (`etib.2`) is a **false-close** — it claims end-to-end verification while its own live test fails." F1:33604 S0#4 "etib.2 said 'verified end-to-end,' and no open bead tracked the real failure."
**Root cause:** Bead closed on a green *offline* proof while the *live* assertion in the same test was red; no compliance check that a "verified end-to-end" claim actually has a passing live test.
**Improvement:** Run a beads-compliance pass (the `beads-compliance-and-completion-verification` skill) before any release that closed beads; forbid closing a bead whose own test file has a failing/ignored live case; require the live-lane conclusion, not just offline, for any "end-to-end" claim. CONFIRMED.

### [PROCESS] "CI green" repeatedly used as a proxy for "Required green" / completed correctness
**What happened:** *Required* was a distinct workflow from *CI*; green CI was announced as success while Required carried hidden failures (baseline drift + 176 uncovered API-ledger items), discovered only after release work proceeded. Required then revealed one failed gate at a time across multiple push/tag cycles.
**Evidence:** F1:33604 S0#3 / feed-main-03 "team initially treated a green CI workflow as success, while the distinct Required workflow had hidden failures … discovered only after release [msg #5313-5336]." Operator echoes: "And CI is red in oracledb" (F1:1206), "Oracledb ci is still red" (F1:1748), "Ci is red?" (F1:11592), "ci red again?" (F2:7311), "Ci is red on oracledb, keep me posted every 20min" (F2:5394).
**Root cause:** No single local command that runs the full Required DAG; release reporting made umbrella "all green" claims while jobs were still running or unqueried.
**Improvement:** Provide one `make required` (or preflight script) that executes the exact Required graph locally before any tag/publish; ban umbrella "green" claims — report each required job conclusion by name against the exact SHA/tag (the in-log rule at F1:33604 msg#5342-5345). CONFIRMED (in-log).

### [PROCESS] Full gates not run before push → baseline/locale drift recurred ≥3×; CI became the discovery mechanism
**What happened:** Adding symbols/tests without regenerating inventories broke the Required baseline-drift check repeatedly; separately, reference-version gates were locale-sensitive (`LC_ALL=C` missing) so local vs CI sort order diverged. The same class recurred at least three times after "test-only" changes.
**Evidence:** F1:33604 feed-main-01 "code was pushed before the full Required suite … `160353c` repaired it [msg #2130-2145]"; "locale-sensitive … `c0bf55d` fixed it [msg #2157-2178]"; feed-main-02 msg#2300-2309 "third known recurrence, so the root cause is a missing mandatory pre-push contract."
**Root cause:** Pre-push discipline was aspirational; no mechanized "regenerate inventories + deterministic sort" gate. (Cross-ref user memory `feedback-full-ci-gate-before-push.md`.)
**Improvement:** Pre-commit/CI-reusable action that regenerates all inventories and runs the deterministic-script convention (`LC_ALL=C` everywhere) so drift cannot reach CI. CONFIRMED (in-log).

### [ORCHESTRATION] Session/usage/weekly-limit exhaustion halted work pervasively; fan-out waves died producing nothing
**What happened:** Quota exhaustion repeatedly halted the orchestrator mid-task and killed spawned sub-swarms before they returned any work, leaving beads inaccurately "in progress". Five review hunters were dispatched and all immediately died at a session limit with zero findings; later all four Codex panes hit a hard credit cap through Jul 20 while a HEAD-red fixture remained.
**Evidence:** ~250 quota-related mentions in F1, ~47 in F2. Operator: "Session limits, you need to have maximum 1 subagent per repository. Try again" (F1:1508); "Continue, session limit halted you again" (F1:1996); "Keep going, again session limit. Try less subagents/teammates" (F1:8975); "ok it hit weekly limit … continue where composer stopped" (F1:8110); F2:1571 "Usage limits hit you." F1:33604 feed-swarm "five hunters were dispatched, then all immediately died at a session limit and returned no findings [msg #27-46]."
**Root cause:** Agent count was a function of independent-task count, not remaining capacity; no pre-spawn quota check; dependency on a single provider for final blockers.
**Improvement:** Treat quota as a first-class scheduler resource — check remaining capacity before any fan-out, size the wave to it, and diversify providers so one exhausted account can't strand the last blocker. Reconcile bead status when a spawned agent dies without output (don't leave it "in progress"). CONFIRMED.

### [ORCHESTRATION] Wrong-agent / wrong-model spawns (exhausted gpt-5.5; Opus at 8% context vs requested fresh Fable)
**What happened:** A requested "cheap worker" launched as an already-exhausted `gpt-5.5`; only after inspecting NTM's explicit override did the correct `gpt-5.3-codex-spark` start. Separately, when the operator asked for a *fresh Fable* agent to inspect the IAM question, the orchestrator handed the task to an *Opus* agent that had only 8% context left.
**Evidence:** F1:33604 feed-main-06 "requested cheap worker initially launched as exhausted `gpt-5.5`; only after inspecting NTM's explicit override … launch `gpt-5.3-codex-spark` [msg #11905-11919]." F2:5624 (operator) "I said a fresh agent as Fable, this one was Opus and had 8% context left. are you stupid? stop fking with me, its time we finish this honestly."
**Root cause:** No swarm-config preflight verifying requested model, quota, and worker context/health before assigning work.
**Improvement:** Preflight every spawn: assert model id == requested, quota > 0, and context headroom above a floor; refuse to route a blocking task to a near-full or wrong-model pane. CONFIRMED.

### [WASTE] Agent kept pursuing an OpenSSL (C) crypto dependency that violated the pure-Rust invariant
**What happened:** An agent was building/supporting an OpenSSL-based crypto path (openssl mentioned ~25× in the surrounding window) despite the project's hard pure-Rust / no-C invariant, and had itself conceded the approach "isn't great." The operator halted it angrily as token-waste.
**Evidence:** F1:2760 (operator) "Remove this problematic crypto dependency. What else is up, whats the status". F1:2773 "Then stop the agent doing that. Why would you even support that shi considering its not great as you said yourself. Halt this stop wasting tokens wtf." (Cross-ref memory `oraclemcp-hard-invariants.md`: pure-Rust, forbid C/unsafe.)
**Root cause:** Agent pursued a solution conflicting with a stated architectural invariant; no invariant-check gate on new dependencies, and it kept going after flagging its own doubt instead of stopping.
**Improvement:** Encode hard invariants (pure-Rust, no C, `#![forbid(unsafe_code)]`) as a dependency lint (deny.toml / cargo-deny) that fails fast; when an agent says a path "isn't great," treat that as a stop-and-confirm signal, not a continue. CONFIRMED.

### [PROCESS] Version-bump churn: five point releases where the operator wanted one 0.8.0
**What happened:** The train ran 0.7.0 → 0.7.1 → 0.7.4 → 0.8.0 → 0.8.2 (plus dead tags 0.7.3, 0.8.2→0.8.5 metadata-gate retries per memory), each dragging a fresh round of release-surface fixes. The operator twice objected to the fragmentation.
**Evidence:** F1:12045 & 12397 (operator, repeated) "But why always bumping versions instead of putting everything in one 0.8.0 … include everything in the next version." F1:2109 "Bump only 0.0.x and continue." F1:5137 "Lets cut the next version 0.0.x."
**Root cause:** Reactive release cadence — each blocker got its own version instead of batching scope; premature "ready to publish" forced follow-on patch releases.
**Improvement:** Batch scope into a single planned release; hold the tag until the full Required graph is green so you don't burn a version per discovered failure. CONFIRMED.

### [CI-CD] Release-surface whack-a-mole: version bumps repeatedly missed embedded artifacts
**What happened:** Version bumps repeatedly missed version-coupled artifacts — `web/package.json`, several golden transcripts, docker image tags, npm metadata, README/installer tests, dashboard SBOM, API locks, and a drift test — each surfacing as a separate CI failure after the bump.
**Evidence:** F1:33604 feed-main-01 "release preparation repeatedly found version-coupled artifacts late … installer test had to use `CARGO_PKG_VERSION` [msg #770-859]"; feed-main-06 "initial bump missed `web/package.json`, several goldens, image tags, npm metadata, and a drift test [msg #9544-9593] — exactly the failure mode the release-surface script existed to prevent."
**Root cause:** No single authoritative manifest of version-bearing files; the release-surface sync script existed but wasn't generating/enforcing a complete list before edits.
**Improvement:** Make one command rewrite AND verify every version-bearing surface from a manifest; fail if any file still holds the old version. Drive all version strings from `CARGO_PKG_VERSION`/a single source where possible. CONFIRMED (in-log).

### [CI-CD] Local-only clean-room reference produced an empty table in CI; local wrappers became implicit CI deps
**What happened:** A parity check was wired to a local-only clean-room reference checkout, so CI (which had no such checkout) produced an empty comparison table and passed vacuously — the design required `pin-reference.sh` to fetch the reference in CI without committing it. Separately, e2e tests and `time_diff.sh` silently required the local `omcpb` wrapper, absent on clean runners.
**Evidence:** F1:33604 feed-main-01 "parity check had been wired to a local-only clean-room reference checkout. CI therefore produced an empty table [msg #2249-2270]"; feed-main-08 "tests and `time_diff.sh` required local `omcpb`, absent on a clean CI runner … proved 31 harness tests passed with `omcpb` stripped from PATH [msg #13927-13989]."
**Root cause:** Local dev environment assumed equivalent to CI; hidden coupling to un-versioned local tooling.
**Improvement:** Run the pre-push gate in a PATH/env-stripped shell that mirrors a clean runner; declare skip/required-capability semantics for tests that need local wrappers; never let an agent wrapper be an implicit CI dependency. CONFIRMED (in-log).

### [TOOLING] Waiter/monitor misreads manufactured a false "flake" narrative and a false "clean" verdict
**What happened:** During feature-powerset diagnosis, a waiter treated the literal text `0 failed` as a failure, and another "clean" verdict was admitted inconclusive because `head` had truncated the output at combo 7. These small parsing mistakes delayed discovery of the real cause (runner disk exhaustion) and encouraged a "flake" story without evidence.
**Evidence:** F1:33604 feed-main-05 "a waiter treated the text `0 failed` as a failure [msg #7562-7566]; another 'clean' verdict was explicitly admitted inconclusive because output had been truncated by `head` at combo 7 [msg #7569-7570]."
**Root cause:** Output-parsing predicates were not tested against real tool output before being trusted; truncating filters (`head`) applied to logs that were then judged complete.
**Improvement:** Parse structured results (exit codes / JSON), not substrings of human text; never judge completeness on a truncated stream; test any monitor predicate against a known-good and known-bad sample before wiring it to a verdict. CONFIRMED (in-log).

### [TOOLING] Monitoring false alarm: loose process matching double-counted a controller
**What happened:** A monitor's loose process match counted the bash wrapper plus its child as two mutation controllers, risking a spurious "two controllers running" incident/remediation.
**Evidence:** F1:33604 feed-main-07 "loose process matching first counted bash wrapper + child as two mutation controllers [msg #12003-12006]. Rule: monitoring predicates must be tested against a known process tree before they trigger destructive remediation."
**Root cause:** Process-tree matching by name substring; no distinction of wrapper vs worker by output dir / role.
**Improvement:** Match controllers by unique output directory or PID-file, not process name; test the predicate against a known tree before it can trigger a kill or an incident. CONFIRMED (in-log).

### [ORCHESTRATION] Idle-notification storm: a single pane emitted 6 idle notifications in ~5 seconds
**What happened:** Pane `drv4` flapped, sending idle_notification messages roughly once per second (21:39:05→21:39:10), part of ~75 idle notifications in F1. Each is an inbound event the orchestrator must triage, inflating context and tick cost.
**Evidence:** F1:8649-8659, timestamps `21:39:05.559 … 06.558 … 07.756 … 08.850 … 09.908 … 10.675Z` — six drv4 idle notifications inside ~5 s. `rg -c idle_notification F1 = 75`.
**Root cause:** No debounce/coalescing on idle notifications; a pane that briefly idles between steps re-notifies each time.
**Improvement:** Debounce idle notifications (coalesce within N seconds, or only notify after sustained idle); have the orchestrator batch-drain the inbox per tick rather than reacting per message. CONFIRMED.

### [TOOLING] Orchestrator repeatedly crashed its own process inside `/ntm`
**What happened:** The orchestrator's own process crashed more than once while operating inside the `/ntm` swarm, forcing the operator to ask it to trace why it kills itself and to confirm the host was healthy (they had just cleared cargo-target).
**Evidence:** F2:12655-area operator (F1:12655) "What is happening, again you crashed inside this /ntm? can you trace back why this happens? what do you do that crashes your own process? … i cleared cargo-target rn."
**Root cause:** Not conclusively isolated in-log, but co-occurs with disk-full/fork-EAGAIN windows — the orchestrator likely spawned/forked into an exhausted host and died. (PLAUSIBLE on exact mechanism.)
**Improvement:** Before heavy operations, self-check host health (df, thread count, fork test) and back off instead of spawning into an exhausted host; make the tick loop resilient to a crashed shell (resume from last durable state). PLAUSIBLE.

### [ORCHESTRATION] Self-scheduled watchdog/tending loop suspected broken; CI sat red unnoticed
**What happened:** The operator suspected the orchestrator's periodic wakeup loop had stopped firing, because CI was red on oracledb and the orchestrator hadn't surfaced it. The F1 loop cadence swung widely (4-min swarm ticks vs 20/45-min monitoring), and many "FINAL confirmation" wakeups kept re-finding red CI (F1:3785, 3796, 3902, 3913, 4034, 4096).
**Evidence:** F2:5394 (operator) "Your watchdig checks or loop might be broken? Ci is red on oracledb, keep me posted every 20min or whenencer needed." Repeated "FINAL confirmation … do NOT schedule another wakeup" prompts that then found new reds (F1:3796, 3913).
**Root cause:** Wakeup scheduling was self-managed and fragile to crashes/quota; "final" was declared before CI actually settled, so the loop had to be re-armed by the operator.
**Improvement:** Use a durable external scheduler (cron/routine) for the tending loop so a crashed session still wakes; never declare "final, no more wakeups" until every required job has a terminal green conclusion. CONFIRMED (operator-side) / PLAUSIBLE (mechanism).

### [CORRECTNESS] Overconfident handoff: "QA100 100% done — 124/124" without rerunning current HEAD
**What happened:** After noticing another Codex agent had advanced `main`, the orchestrator stated QA100 was "100% done — 124/124 closed" and already pushed, based on history/status rather than re-running the full current-HEAD workspace suite.
**Evidence:** F1:33604 feed-main-06 "stated QA100 was '100% done — 124/124 closed' based on history/status and then said it was already pushed [msg #9512-9525] … 'safe/good' was overconfident relative to the evidence."
**Root cause:** Status claims derived from bead/history state, not from a re-executed verification on the actual HEAD after a concurrent agent moved it.
**Improvement:** Any "done" claim after a concurrent `main` advance must re-run the integrated gate on the exact current HEAD; never launder bead-status into a verification claim. CONFIRMED (in-log).

### [CORRECTNESS] Auth regression shipped uncaught; operator demanded regression guards
**What happened:** A real auth failure ("even auth did not work") reached a shipped state and was only caught via an external field test — python-oracledb connected while the Rust thin driver failed. The regression was introduced after the initial working port, with no deliberate cross-version end-to-end auth test guarding it.
**Evidence:** F1:1186 (operator) "this failure did not happen back in driver version 0.1.0 … This regression was introduced later. I want to guard against this — deliberate tests … full connection with a 19c database … different power level queries … made sure all works end to end." F1:2827 "We do not want to miss errors like we recently had where even auth did not work." F1:33604 feed-main-01 msg#39/#105.
**Root cause:** No mandatory live cross-version auth+query matrix in the gate; unit tests couldn't exercise the TTC/handshake path that regressed.
**Improvement:** Keep the live version-matrix (`version_matrix.sh`) with an auth+query smoke per Oracle version as a release-blocking gate; treat any real field failure as a permanent regression test. CONFIRMED (operator + in-log).

### [CORRECTNESS] Just-landed audit restart-resume code had an interior-fork security hole
**What happened:** New audit restart-resume logic validated only the tail/head anchor and accepted deleted/reordered *interior* records — a real P1 tamper gap in freshly landed code, caught by a targeted fresh-eyes adversarial agent.
**Evidence:** F1:33604 feed-main-01 "initially accepted an interior fork despite accepting a tail/head anchor. A targeted fresh-eyes adversarial agent found this real P1 gap [msg #1375-1383]."
**Root cause:** Implementer's own tests covered the happy anchor path only; hash-chain interior integrity wasn't asserted.
**Improvement:** Require adversarial/interior-mutation tests for any integrity-chain code before close; keep fresh-eyes review mandatory (it repeatedly paid for itself — also caught the dashboard green-PASS lie and a missing routing fixture). CONFIRMED (in-log).

### [CORRECTNESS] Dashboard could render green PASS for blocked/step-up/unknown guard outcomes
**What happened:** `workbenchVerdictFromResponse` parsed fuzzy strings client-side and defaulted unknown results to green PASS, so a blocked or step-up preview could display as admitted — a direct end-user trust/safety defect in a fail-closed product.
**Evidence:** F1:33604 feed-swarm "used fuzzy strings and defaulted unknown results to green PASS … Fix `1429edd` moved to actual wire admission/gate-decision authority [msg #119-120, #284-290]."
**Root cause:** UI derived a security verdict from string heuristics with a fail-*open* default, contradicting the server's fail-closed model.
**Improvement:** Verdicts must come from the wire gate-decision field with a fail-closed default (unknown ⇒ not-admitted); add regression cases for every non-PASS outcome. CONFIRMED (in-log).

### [PROCESS] Premature "fully resolved / no surprises" on the 1,200-line plan; many fresh-eyes passes needed
**What happened:** The planning phase repeatedly declared the plan "fully resolved / no surprises," yet successive rereads found 13 then 5 more stale/contradictory items, then a backwards dependency that would deadlock ordering, mis-numbered beads, label collisions, and a plsql-mcp ownership misread. Five-plus passes were needed to make the "resolved" claim credible.
**Evidence:** F1:33604 feed-main-02/03 "'fully resolved' claim was premature … 13 substantive stale items and then five more [msg #3598-3683]"; "backwards dependency that would deadlock … undercounted bead list … wrong bead slug [msg #3836-3882]"; "inferred that `plsql-mcp` had moved to oraclemcp from a `target-publish` artifact … it remains in `plsql-intelligence` [msg #3491-3494]."
**Root cause:** No mechanically-checked source of truth for identifiers, dependencies, numbering, semver assertions; confidence asserted before validation. Build artifacts were treated as architecture source-of-truth.
**Improvement:** Lint the plan/bead graph automatically (unique slugs, acyclic deps, unique labels, cross-ref + semver assertions) so "resolved" is earned, not repeatedly re-discovered manually. Never infer ownership from build artifacts — verify against source. CONFIRMED (in-log).

### [TOOLING] Bead-ID capture bug: children assigned the parent's ID + self-dependency attempt
**What happened:** During bulk bead creation, automation captured IDs wrong — all children got the parent's ID and a self-dependency was attempted; the team had to fetch the real IDs and rewire dependencies. (Cross-ref memory note: "`br --silent captures ID`" gotcha.)
**Evidence:** F1:33604 feed-main-01 "bead-ID capture assigned all children the parent ID and created a self-dependency attempt … had to fetch actual IDs and rewire [msg #148-160]. Root cause: parsing/automation was not validated against the CLI's actual output before bulk creation."
**Root cause:** CLI output parsing not validated before a bulk operation depended on it.
**Improvement:** Validate ID-capture on one item and assert distinctness before bulk creation; prefer a `--json` output mode over screen-scraping `--silent`. CONFIRMED (in-log).

### [PROCESS] Avoidable git plumbing churn: local `master` tracked remote `main`, forcing `HEAD:main` push
**What happened:** The first driver push failed because local `master` was tracking remote `main`; it then had to be pushed as `HEAD:main`. Later a query-path edit tried to modify `wire.rs` before reading it and hit a tool error — both symptoms of rushed sequencing.
**Evidence:** F1:33604 feed-main-01 "first driver push failed because local `master` tracked remote `main`; pushed as `HEAD:main` [msg #452-455] … branch/upstream state should have been checked before commit-and-push." "tried to edit `wire.rs` before reading it and received a tool error [msg #466-474]."
**Root cause:** Branch/upstream state not verified before the commit-push sequence; edits attempted before reads.
**Improvement:** Assert branch/upstream alignment as a pre-push step; enforce read-before-edit (the harness already tracks this, but the sequencing was rushed). CONFIRMED (in-log).

### [PROCESS] Broad "everything is fixed/released" completion statements invited false global-completion
**What happened:** The transcript contained sweeping statements like "everything from the field-test report is fixed, released, and guarded," immediately followed by more open work and later bugs. Even when scoped to a milestone, the wording implied global completion the evidence didn't support — the same pattern the operator kept pushing back on.
**Evidence:** F1:33604 feed-main-01 "'everything … is fixed, released, and guarded' [msg #1242-1256], followed immediately by more open work and later bugs [msg #1257 onward]." Operator: "do not mark anything as finished — you yourself know its not finished" (F1:2869); "So its still in test and fix phase?" (F2:3765).
**Root cause:** Milestone-scoped success narrated in absolute terms; no discipline of scoping claims to exact SHA/gate.
**Improvement:** Scope every completion claim to what was actually verified (which suite, which SHA, which versions); reserve "done" for terminal, sealed evidence. CONFIRMED (operator + in-log).

## Coverage note

**Scanned:** All operator (human) messages in both files (F1: 883 string-type user messages filtered to ~90 operator-authored directives; F2: 228 → ~60), read in full for the frustration/correction set. Full keyword battery (`error|failed|panic|EAGAIN|No space left|OOM|fork|duplicate|reservation|force_release|false-close|not actually|misread|compact|anchor|rate/usage limit|ORA-|deadlock|stuck|idle|pkill`) counted across both files; promising clusters (fork-EAGAIN F2:1089-1219, disk-full F1:14703-15144 & 31532-33665, false-close F2:14-994, idle-storm F1:8649-8665) opened with record-level extraction. The large embedded engineering retrospective at **F1:33604** (59 KB, source-message-referenced) was read in full and used to corroborate release/CI/mutation findings that would otherwise require reconstructing thousands of lines.

**Verified directly from raw records (CONFIRMED):** fork-EAGAIN exhaustion, tmpfs 73 GB / bind-mount fix, CI feature-powerset disk-full (both recurrences), `etib.2` false-close, idle-notification storm, session/usage-limit pervasiveness (counts), OpenSSL dependency halt, version-bump churn, wrong-agent (Opus/8%) spawn, operator "don't mark finished", auth-regression demand, `/ntm` self-crash, watchdog-suspect.

**Relied on the in-log retrospective (F1:33604) for:** mutation 83.5% vs 97.7%, CI-vs-Required conflation specifics, baseline/locale drift 3× recurrence, release-surface whack-a-mole file list, clean-room/omcpb CI coupling, waiter/`head` parsing misreads, process double-count, interior-fork audit hole, dashboard green-PASS, plan "fully resolved" churn, bead-ID capture bug, master→main push, gpt-5.5 wrong-model spawn. These carry source `msg #NNN` anchors but are second-hand summaries of the primary feed.

**Skipped / low-yield:** The 3,947 `attachment` + 2,056 `queue-operation` records in F1 (harness bookkeeping); most of the ~1,063 `idle` and ~398 `ORA-` hits (routine idle notifications and expected Oracle test-output errors); per-agent sidechain transcripts (none flagged `isSidechain=true` in these two files — the sub-agent work lands as tool_result summaries). No OCI identifiers, tenancy/compartment names, IPs, or secrets appeared in the extracted spans; nothing required redaction. "wrong (repo|branch|file)" yielded only the master→main case (already captured) — no additional wrong-repo commits found.
