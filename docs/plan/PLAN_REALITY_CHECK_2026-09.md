# Reality Check + Bridge Plan — oraclemcp, 2026-09-04

> **Status:** BEADED — ambition rounds 1–3 + plan-space refinement rounds r1–r5 applied (see §8); implementation-ready via `br ready`. Confidentiality-clean (no
> live-OCI/customer identifiers, constitution #9). Wording follows
> `PLAN_ENGINEERING_PROGRAM.md` §3.4 (no "first/only"; every claim carries evidence).
> **Code = ground truth for where we ARE; README + plans = the measuring stick for where we
> promised to BE.** Every status below was measured on this machine on 2026-09-04 at
> `HEAD e23eab59`. This file is revised in place by later rounds; it is the single plan.

---

## 0. TL;DR (the brutally honest picture)

**The product works.** A debug build of `HEAD` served real MCP over stdio *and* Streamable HTTP
against a live Oracle 23ai lab: `SELECT 1` returned `{"ONE":"1"}` (NUMBER-as-string invariant
held), `DELETE FROM dual` was refused `OPERATING_LEVEL_TOO_LOW`, the dashboard and operator API
failed closed (401/400) without pairing, `readyz` reported `db_reachable=true`. 22 of 23 required
CI lanes are green, `tsc` is clean, vitest is 240/240, every static lint passes, and the
"alien horizon" (14 governance arcs — cost, time, egress, proof, policy, CQN/orient/Arrow,
vector search, lineage, fleet, reversible workspace, editions, incident capture, refusal corpus,
console) is **implemented and closed with live-matrix evidence** (all July 2026).

**But the project is not where its own documents say it is, in six ways:**

| # | Reality | Severity |
|---|---|---|
| 1 | **The driver we ship on is discontinued by its own author** (`oraclemcp-driver-cx` README, 2026-08-06: "won't get further development — use Oracle's official driver"). Oracle's official `oracledb` (26.0.0-beta.2, 2026-08-20) is pure-Rust, **synchronous, Tokio-free, stable-Rust 1.89**, UPL/Apache. The dual-backend epic that answers this (`nhteq.3–.6`) has **zero progress since 2026-07-30**. README/AGENTS still present driver-cx as the live foundation without disclosing the freeze. | **Critical (strategic)** |
| 2 | **`main` has been red for a month.** Last push CI on `HEAD` (2026-08-03): 1 failure — `Rust workspace (Windows)` (audit-DACL tests; three in-progress beads `xuaea`/`8n02c`/`sd39s`). The scheduled heartbeat has failed every ~4 h since. **80 commits sit unreleased since v0.10.0** (2026-07-27) with an empty `CHANGELOG [Unreleased]`. No commit since 2026-08-03. | **Critical (process)** |
| 3 | **The shipped differentiators are invisible to users.** The registry serves 35 canonical tools; the README table documents **25**; `oraclemcp robot-docs guide` (the in-binary agent guide) mentions **0** of the 10 governance tools (`oracle_diff`, `oracle_orient`, `oracle_checkpoint`, `oracle_undo_to`, `oracle_preview_dml`, `oracle_semantic_search`, `oracle_top_queries`, `oracle_plan_timeline`, `oracle_db_health`, `oracle_search_objects`); `configuration.md`/example TOML carry none of the Arc-G/N/A/C knobs; `SECURITY.md` still says "0.6.x current"; the README says completions are not advertised (they are). The "we govern every dimension" identity shift (PLAN_0_8_x_ALIEN) never reached a user-facing surface. | **Major (vision delivery)** |
| 4 | **Three distribution promises are not real.** Homebrew tap repo does not exist (formula only as a release asset); winget manifest was never submitted (asset only); the documented `ghcr.io/muhdur/oraclemcp:plsql-intelligence-latest` image has **never been published under any tag**; `oraclemcp-verifier` (the external verdict-certificate verifier, ADR-0010) is **not on crates.io**. | **Major (shipped reality)** |
| 5 | **Proof is going stale.** The 18c/21c/23ai live matrices that proved the arcs ran in July on lab lanes that **no longer exist on this host** (the rig never creates them; it delegated to the now-discontinued driver repo's container script). The OCI Always-Free ADB lane has **never been dispatched**. No field round on 0.10.0 exists (round 3 tested 0.9.0). The mutation seal is `status=stale` by design (advisory). | **Major (proof)** |
| 6 | **The tracker is not honest both ways.** 3 false-open beads (the 0.10.0 publish sink and its train epics — 0.10.0 shipped); **100 deferred** beads of which 72 were parked on 2026-07-18 as a plan-import with no per-bead operator ruling recorded, ≥2 are already overtaken by shipped arcs (`k6q.12` masking → Arc M; `k6q.15` query-cost → Arc G), and one is a **bug** deferred against the standing "bugs never stay deferred" ruling (`yb7m`). | **Major (ledger)** |

**Would completing every open/in-progress bead close the gap? No.** The 30 open/in-progress
beads cover the Windows red, the driver qualification, OCI e2e, and a few CI items. They do
**not** cover: driver-discontinuation disclosure + decision, the release of the 80 commits,
any of the documentation/vision-communication gap, Homebrew/winget/plsql-image/verifier
publication, lab-lane restoration, a 0.10.0 field round, tracker reconciliation, or the
`om dashboard` listener-discovery defect. Those are `NO_BEAD` gaps and are the point of this plan.

**The R1 thesis (what changed from R0):** R0 listed fixes. R1 turns every gap *class* into a
mechanism that cannot silently recur — drift becomes a red lane, not a reality-check finding:
docs generated from the registry and config schema; channels that are only documented when a
verifier proves them; a release-debt clock; lanes the repo owns; a ruling-lint for deferrals;
and the driver decision produced as a signed, re-runnable **backend-qualification** evidence
document rather than a judgment call.

**The R2 thesis:** apply the product's own thesis — *don't trust claims, verify them* — to the
project itself, end to end: every README claim carries a verifier (claims ledger), the two
backends are compared by metamorphic relations rather than by reading their docs, every release
publishes ONE evidence manifest whose single hash covers SBOM, provenance, test attestation,
backend qualification and gate status, and the field feeds the guard (selftest → refusal
corpus). R2 also adds what an implementer needs to start tomorrow: four parallel tracks with a
hot-file conflict map, a scope-cut ladder, and numeric exit criteria per bridge item (§9).

---

## 1. Ground truth (verified 2026-09-04, not assumed)

### 1.1 Repository and release state
- `HEAD e23eab59` (2026-08-03, "chore(beads): record Windows ACL decision"); branch `main`;
  1 uncommitted edit (`web/e2e/test-attestation-verifier.spec.ts`, +7 lines, action-ticket stub).
- **80 commits since `v0.10.0`** (tag 2026-07-27); workspace still `0.10.0`; `CHANGELOG.md`
  `[Unreleased]` empty. Commit mix since tag: 15 chore, 10 test, 10 fix, 2 feat, 2 docs,
  ~40 dashboard-UX-repair / bug-hunt / evidence commits.
- crates.io: 9 crates at 0.10.0 (`oraclemcp`, `-core`, `-db`, `-guard`, `-audit`, `-auth`,
  `-config`, `-error`, `-telemetry`); **`oraclemcp-verifier` does not exist on crates.io**
  (no `publish = false`, not in `scripts/publish_crates.sh`).
- GHCR: `ghcr.io/muhdur/oraclemcp:{latest,0.10.0}` present; **no `plsql-intelligence*` tag at
  any version** (`docker.yml` is manual; last run 2026-06-08).
- MCP registry: `io.github.MuhDur/oraclemcp` **0.10.0 = latest** (published 2026-07-27).
- GitHub release v0.10.0: 7-target archives + `.sha256` + `.sig`/`.crt` + `.sigstore.json` +
  `.attestation.sigstore.json` + SBOM + `oraclemcp.rb` + winget YAMLs. **No tap repo**
  (`MuhDur/homebrew-oraclemcp` → 404); **no winget-pkgs manifest** (`manifests/m/MuhDur/oraclemcp` → 404).
- Installer: `bash install.sh --dry-run` and `--uninstall --dry-run` behave as documented (musl
  auto-target, verify posture `prefer`, cosign absent → visible skip).
- Driver: workspace pins `oraclemcp-driver-cx = "=0.9.2"`; crates.io has 0.9.3 (2026-08-06,
  docs-only republish carrying the **discontinued** disclaimer). Sibling repo
  `rust-oracledb` `origin/main` = "republish oraclemcp-driver-cx 0.9.3 (docs-only,
  discontinued-disclaimer README)". Oracle's official `oracledb` 26.0.0-beta.2
  (github.com/oracle/rust-oracledb, 2026-08-20): `rust_version=1.89`, license
  `UPL-1.0 OR Apache-2.0`, normal deps `aes cbc pbkdf2 pkcs8 rustls webpki-roots chrono rand
  sha2 uuid whoami base16ct base64ct` (**no tokio**), optional `arrow-array/arrow-schema`.

### 1.2 CI truth (`gh`, not inferred)
- Last push run on `HEAD` (30798466772): **22 success / 1 failure** — `Rust workspace (Windows)`,
  step `cargo test workspace on Windows`. Previous push (5de96f98) failed the same job.
- `CI Heartbeat` ("watch required + scheduled lanes"): **failure** on every schedule since at least
  2026-09-03 (24 red check-runs on `HEAD`).
- Scheduled: `Mutation Safety` green (2026-09-04), `Fuzz Campaign` green (2026-09-04), `loom`
  green (2026-08-30), `kani-safety` green (2026-08-24, PR). `oci-adb.yml`: **never run**.
  `release.yml`: last 2026-07-26 (success after one failure). `publish-npm.yml`: dormant, failing
  when dispatched (2026-07-02) — README says no npm channel; `npm/` (v0.9.0 wrapper) sits untracked.
- Open PR: Dependabot #24 (github-actions weekly group, 2026-08-24). Open issues: 0.

### 1.3 Local measurement (this host, `HEAD`, debug build, `CARGO_TARGET_DIR=target/`)
- `cargo build -p oraclemcp` OK. `oraclemcp 0.10.0`; subcommands: `serve info doctor profiles
  capabilities completions service clients dashboard robot-docs setup self-update sign-tool
  audit incident refusal-corpus`.
- Static lints: honesty-grep OK, fixture-lint OK (288 files), agent-surface OK, driver-seam OK
  (`connection.rs` only), release-surface OK (server 0.10.0 / driver 0.9.2 / runtime 0.3.9).
- Web: `tsc --noEmit` clean; `vitest run` **240 passed, 7 skipped** (23 files).
- **Stub scan:** 0 `todo!()`/`unimplemented!()` in production source; 1 `TODO(simplify)`; the
  only "stub" is the deliberate offline stub connection. No placeholder code found.
- **Runtime surface:** registry = 34 canonical + `oracle_capabilities` = **35**; + 25 compatibility
  aliases (server log: "59 tools"). `tools/list` at `READ_ONLY` advertises **27 `oracle_*` + 16
  aliases = 43** — tools requiring `READ_WRITE`/`DDL` (`oracle_execute`, `oracle_explain_plan`,
  `oracle_compile_object`, `oracle_create_or_replace`, `oracle_patch_source`,
  `oracle_checkpoint`, `oracle_undo_to`, `oracle_preview_dml` + their aliases) are hidden by
  `descriptor_visible_for_surface` until the level allows them (by design; still callable →
  typed refusal). Every advertised tool carries annotations. `initialize` advertises
  `completions`, `prompts`, `resources`, `tools` and `mcp_protocol_version 2025-11-25`.
- **Offline (no profile):** `serve` OK; `oracle_query` → `CONNECTION_FAILED` envelope;
  `oracle_capabilities` → structured error with `next_steps` (the documented degraded contract);
  `doctor` exit 2 (Connectivity fail, expected without a profile).
- **Live (gvenzl `oracle-free:23-slim` on 127.0.0.1:1521/FREEPDB1, `SYSTEM`, profile capped
  `READ_ONLY`):** `doctor --online` 17 checks — pass except `11 Write posture = warn` (SYSTEM can
  write; correct) and `17 = warn`; stdio `SELECT 1 AS ONE FROM dual` → `row_count 1`,
  `{"ONE":"1"}`; `oracle_execute DELETE FROM dual` → `OPERATING_LEVEL_TOO_LOW`; HTTP
  `--listen 127.0.0.1:7093 --allow-no-auth`: `healthz/readyz/metrics` 200 (`db_reachable:true`),
  `/mcp initialize` 200 with capabilities+instructions, `tools/list` 43, guarded query over HTTP
  → 1 row; `GET /dashboard/` **401** (unpaired), `GET /dashboard/pair?ticket=x` **400**
  (refused, not consumed), `GET /operator/v1/health` **401**.
- **Defect found:** `oraclemcp --json dashboard` ignores the live instance recorded in
  `service-instance.json` (which `service status` reads correctly: `listen 127.0.0.1:7094`) and
  probes the hard-coded default `http://127.0.0.1:7070` →
  `ORACLEMCP_DASHBOARD_SERVICE_UNREACHABLE`. The README's `om dashboard` one-liner works only on
  the default port unless `--url` is passed.
- **Lab lanes:** `oracle-xe18-1518`, `oracle-xe21-1520`, free23-1522 — **absent** on this host
  (`docker ps -a`); `scripts/rig/oracle_l1.sh` "intentionally never creates" them and shells out
  to `$DRIVER_ROOT/scripts/container.sh` in the discontinued driver checkout.

### 1.4 Tracker truth (`.beads/issues.jsonl`, 1478 records; `br doctor` = degraded/healthy JSONL)
- **1333 closed · 100 deferred · 26 open · 4 in_progress · 15 tombstone.** `br ready` = 4.
  `bv --robot-insights` cycles: none.
- Open epics (9): `eng-program-bp8ia` (+`.5`, `.10`, `.12`), `091-train-root-jp5k9`,
  `091-ws-g-backlog-drain-97sut`, `driver-cx-oracle-dual-backend-nhteq`,
  `f-server-bughunt-fixes-fusa` (+`.1`, all 119 children closed).
- In progress (4): `xuaea` (P0 Windows ACL provenance), `8n02c` (Windows WORM parent), `sd39s`
  (Windows audit owner proof), `bp8ia.5.6` (mutation shard planning).
- Open tasks (22): `nhteq.3–.6` (driver qualification/backend/selection/proof), `bp8ia.10.1–.4`
  (OCI I1–I4), `091-f4-real-adb-b6-jm290`, `bp8ia.5.4` (fuzz shard/RQ prep), `bp8ia.12.3` (K3),
  `bp8ia.13` (**false-open**: publish 0.10.0), `dapll` (driver-side CI, cross-repo), `1efki`
  (container dependency closure), `bipdv` (446 G target/worktree prune), `ysvhx` (cosign v3),
  `nn3ne` (P3 read-purity scope note).
- Deferred (100): 72 `plan:ep260718` imports (clusters a/b/c/d/e/g/h/i/k, parked 2026-07-18,
  notes = plan citations only, **no ruling text**); 15 `040-epic-deferred-k6q.*` "OUT" items
  with explicit resume triggers (2026-07-08 recheck); 6 Cluster J (operator-deferred, ruling
  recorded 2026-07-22); 3 `060` (Orrery 3D, UDS socket, TUI); `09x M4` licensed tier;
  `yb7m` (**P2 bug**); `multiagent-orchestration-controls`.
- Evidence: 415 guarded close-evidence files under `tests/artifacts/evidence/closes/`.

---

## 2. Vision Checklist

Sources: `README.md` (public promise, 1465 lines), `AGENTS.md`, `PLAN_0_8_x_ALIEN.md`
(0.9.x identity), `PLAN_0_9_1_FIELD_HARDENING.md` (0.10.0 scope), `PLAN_ENGINEERING_PROGRAM.md`
§1–3/§27–33 (program), ADRs 0001–0012, CHANGELOG.

Status key: WORKING · PARTIAL · STUB · UNPROVEN · NOT_STARTED · REGRESSED · NO_BEAD · WRONG_APPROACH.

| # | Goal (testable) | Source | Status | Severity | Bead coverage | Evidence |
|---|---|---|---|---|---|---|
| V1 | Fail-closed guard + ladder `READ_ONLY<READ_WRITE<DDL<ADMIN`; reads admit only proven read-only; execute rolls back by default; preview-derived single-use grants; TTL elevation ≤ `max_level`; protected profiles immutable; SEC-1 re-classify at apply | README "Why", "Safety model"; AGENTS "safety invariant" | **WORKING** | — | closed (QA100, 09x.16 gate) | live: DELETE refused; guard tests + metamorphic + fuzz (green 09-04) + kani; mutation legacy guard 92.6/audit 96.9 (seal `stale`, advisory) |
| V2 | One-line install/update (Linux/macOS), PowerShell (Windows), SHA-256 + cosign posture, air-gap `--offline --trusted-root`, `self-update`, uninstall, `om` alias, completions | README "Install" | **WORKING** | — | closed (install-update-oneliner-buhn) | local dry-runs; CI `installer`, `windows-installer` green; assets present. Open: `ysvhx` cosign v3 migration |
| V3 | Zero-config `setup --discover` (consent-gated TNS scan, READ_ONLY profiles, no secrets) | README "Zero-config onboarding" | **WORKING** (CI-tested; not exercised live here) | — | closed (onboard-tns-discovery-gwkg) | `crates/oraclemcp-config/src/discovery/*` + tests |
| V4 | Always-on service (systemd/launchd/Windows), backup/restore, online client-credential lifecycle | README "service" | **WORKING** | — | closed (WP-S) | `service status --json` OK locally; tests |
| V5 | Browser dashboard: secret-free pairing, HttpOnly/SameSite cookie, CSRF + action tickets, Workbench (opt-in), Reviews/Change Proposals, source history, global search, snapshot diff export | README "dashboard" | **PARTIAL** (server WORKING; `om dashboard` CLI defect) | Minor | **NO_BEAD** for the CLI defect | 401/400 fail-closed verified; Playwright e2e in CI; `dashboard` ignores `service-instance.json` (§1.3) |
| V6 | Two transports: stdio + Streamable HTTP; per-client bearers, OAuth (RFC 9068), mTLS fingerprints, control listener, rate limits, capacity admission | README "Two transports", "OAuth" | **WORKING** (lab); **UNPROVEN in the field on 0.10.0** | Major | closed (WS-A/B) | HTTP smoke green; goldens; field round 3 (0.9.0) found transport-auth defects → fixed in 0.10.0 with rig proof; **no field round 4** |
| V7 | Distribution: crates.io (all crates), GHCR, MCP registry, `cargo binstall`, Homebrew, winget, plsql-intelligence image | README "Other release channels", "Docker" | **PARTIAL** | Major | **NO_BEAD** | crates 9/10 (verifier missing); GHCR core ✓; registry ✓; binstall metadata ✓; **brew tap NOT_STARTED; winget NOT_STARTED; plsql image NOT published** |
| V8 | Oracle versions/modes: 23ai tested; EZConnect/TNS; TCPS/wallet (pem/sso/p12); IAM pre-fetched token over TCPS; proxy; DRCP; standby | README "Supported Oracle versions" | **WORKING** (23ai per-PR); **UNPROVEN** currently for 18c/21c and real ADB on 0.10.0 | Major | open: I1–I4, F4 | `oracle-free23` CI lane green; 18/21 lanes absent on host; `oci-adb.yml` never run; ADB connect OBSERVED in field round 3 (0.9.0) |
| V9 | Agent-first UX: real JSON Schemas, MCP annotations, `oracle_capabilities`, resources, prompts, `robot-docs guide`, structured `ErrorEnvelope` | README "Why"; behavior-inventory | **PARTIAL** | Major | **NO_BEAD** | code WORKING (43/43 annotated); **docs stale**: README table 25/35 tools; robot-docs 0/10 new tools; README "completions not advertised" wrong; `configuration.md` lacks Arc knobs; `SECURITY.md` 0.6.x; `comparison.md` old driver name |
| V10 | Operator-defined TOML tools with HMAC v2 signing, protected-profile enforcement | README "Operator-defined read-only tools" | **WORKING** (tests) | — | closed | `custom_tools.rs` + startup fail-closed (0.10.0 CHANGELOG) |
| V11 | Offline behavior: `serve`/`capabilities`/`doctor` work without DB; tool calls return envelopes, never crash | README "Offline behavior" | **WORKING** | — | closed | §1.3 offline smoke |
| V12 | Signed hash-chained audit (HMAC, v6 redaction), unsigned refusal floor, `audit verify`, WORM/SIEM shipping, Rekor anchoring | README "Signed audit…"; ADR-0003; Arc B2 | **REGRESSED on Windows** (Linux WORKING) | Critical (CI) | in_progress `xuaea`/`8n02c`/`sd39s` | Windows `cargo test` red since 2026-08-03; Linux tests green |
| V13 | Durable write intents, idempotency index, `commit_in_doubt` quarantine, fail-closed restart | README "Execution grants…" | **WORKING** | — | closed | `write_intent.rs` + dispatch tests |
| V14 | `--features plsql-intelligence`: `oracle_plsql_*` offline tools, Workbench IDE panel, dedicated image | README "PL/SQL intelligence" | **PARTIAL** | Major | **NO_BEAD** | CI `plsql-intelligence` matrix green; **image never published** (V7) |
| V15 | Pure Rust, `#![forbid(unsafe_code)]`, engine-free boundary, Tokio-free runtime (asupersync) | README; AGENTS; ALIEN doctrine | **WORKING** | — | closed | boundary/arch/seam lints green |
| V16 | Build toolchain: pinned nightly documented as build-time-only; stable MSRV "not possible" while driver-cx forces `nightly-outcome-try`; Windows `windows_by_handle` | README "Limitations"; `docs/toolchain.md`; `k6q.14` (deferred) | **Documented limitation — trigger now met** | Minor→Major (opportunity) | deferred `k6q.14` (stale trigger) | Oracle driver is stable-clean and Tokio-free; dropping driver-cx removes reason 1 |
| V17 | **0.9.x alien horizon** — G cost gate, A time (`as_of`/`oracle_diff`/`oracle_plan_timeline`), M egress masking (ADR-0008), B proof certificates + verifier + Rekor + Lean, N policy-as-code (ADR-0009), C living-DB (CQN, `oracle_orient`, Arrow IPC), F governed vector search, K lineage, H fleet, I reversible workspace (`checkpoint`/`undo_to`/`preview_dml`), D editions, E incident capture (ADR-0011), J refusal corpus, L console affordances | `PLAN_0_8_x_ALIEN.md`; ADRs 0008–0011 | **WORKING (July evidence)**; **UNPROVEN since** for the live matrices; **undocumented** | Major (proof + communication) | closed (09x.*, 88 beads) | tools present in registry + served; e2e scripts registered (`cost_gate.sh`, `time_diff.sh`, `served_egress.sh`, `sql_policy.sh`, `fleet.sh`, `reversible.sh`, `living_db.sh`, `governed_rag`, `live_lineage`, `incident.sh`, `refusal_corpus.sh`, `verdict_certificate.sh`); web view-models + 240 vitest; README/robot-docs silent (V9) |
| V18 | 0.10.0 field hardening: P0/P1 fixed, wire-contract fixtures C1–C9, rig R0–R5, e2e E1–E6, live env D1–D10 | `PLAN_0_9_1` | **WORKING**; field re-validation **NOT DONE** | Major (proof) | closed (091-ws-*); train epics false-open | 0.10.0 shipped; round 3 was on 0.9.0 |
| V19 | Engineering program clusters A–K | `PLAN_ENGINEERING_PROGRAM` §33 | A–C,E–H closed; **D partial** (5.4 open, 5.6 in progress); **I open** (OCI, 0 runs); J operator-deferred; **K partial** | Major (I), Minor (K) | open `bp8ia.5.4/.5.6/.10.*/.12.3` | §1.4 |
| V20 | Verifiable test attestation (`test-attestation/v1`) bound to releases | §32.3; ADR-0012 | **PARTIAL — blocked on operator secret** | Minor | open K3; deferred `k-server-*` | signed lane refuses until `ENABLE_TEST_ATTESTATION` + `ORACLEMCP_TEST_ATTESTATION_KEY` exist (`docs/operations.md` §6.7) |
| V21 | GCP/Vertex demo → site → video → launch | §1–24 | **DEFERRED by operator (recorded)** | — | deferred `bp8ia.11.*` | ruling 2026-07-22 |
| V22 | **Driver foundation**: "pure-Rust thin `oraclemcp-driver-cx`" today; explicit second backend once Oracle's driver qualifies; no silent fallback | README; AGENTS; `nhteq` epic | **WRONG_APPROACH risk / NOT_STARTED** | **Critical** | open `nhteq.3–.6` (no progress) | driver discontinued 2026-08-06; official driver beta 2026-08-20; README/AGENTS undisclosed |
| V23 | Repo/process health: honestly green `main`, land-complete releases, evidence-backed tracker, disciplined disk/worktrees | AGENTS constitution #2/#11/#3/#6 | **REGRESSED** | Major | partial (`bipdv`) | red `main` 1 month; 80 unreleased commits; 3 false-open; 100 deferred w/o rulings; 16 worktrees/17 stashes/24 branches/~446 G; untracked residue |
| V24 | "All versions green" — every live suite green across 18c/21c/23ai, nothing deferred | operator standing goal (memory) | **UNPROVEN now** | Major | NO_BEAD for lane restoration + nightly matrix | last matrix runs July; lanes absent; matrix manual-only |
| V25 | Windows is a supported platform (installer, service, durable state, audit DACL hardening) | README (PowerShell installer, Windows service); CHANGELOG 0.10.0 | **REGRESSED** (only red lane; three audit-ACL beads in flight) | Major | in_progress (3) | §1.2; 2026-07 "Windows lane green" memory shows this lane flips red repeatedly |

**Vision delivery:** 11 of 25 goals fully WORKING with current evidence; 7 PARTIAL/UNPROVEN;
3 REGRESSED; 1 NOT_STARTED/WRONG_APPROACH-risk (the driver); 1 operator-deferred; 2 documented
limitations/opportunities. **Bead completion 90 % (1333/1478) ≠ vision delivery** — the seven
`NO_BEAD` rows above are the bead-completion illusion in action.

---

## 3. Gap analysis (detailed)

### Gap G1 — Driver foundation discontinued; second backend not started — **Critical**
**Promise:** README: "Live database access is built in through the pure-Rust thin
`oraclemcp-driver-cx` driver"; `nhteq` epic: "the Oracle driver is the broad supported backend
once proven. No automatic cross-driver fallback."
**Reality:** driver-cx README (crates.io 0.9.3, 2026-08-06): *"Status: discontinued … won't get
further development — for new work, use Oracle's official driver."* The server pins `=0.9.2`.
Oracle's `oracledb` 26.0.0-beta.2 is sync, Tokio-free, stable-Rust, `arrow` feature; API shape
(blocking calls, break/timeout semantics, CQN, wallets, IAM tokens, DRCP, proxy) **unqualified**
against the 285-fn `OracleConnection` seam. `nhteq.3–.6` untouched since 2026-07-30. README,
AGENTS, `docs/toolchain.md`, `comparison.md` do not disclose the freeze.
**Why it matters:** a governed DB server whose only wire driver is frozen accumulates
unpatchable protocol/TLS debt (rustls/aes/pbkdf2 advisories will surface in `cargo deny`), and
Oracle 26ai features land only in the official driver. It also holds the nightly pin hostage (V16).
**Bead coverage:** PARTIAL (`nhteq.3–.6` exist). **Missing:** disclosure/honesty; contract-suite
rebinding to two backends; sync-driver-inside-async-lane cancellation design; license/deny
allow-list; stable-Rust spike; migration + rollback plan for the pin; freshness gate for the
frozen driver; a security-maintenance policy for the frozen driver's own dependency tree.
**Dependency concentration (R2):** the server's two load-bearing runtime dependencies —
`asupersync` (0.3.9, the Tokio-free runtime) and `oraclemcp-driver-cx` — are both in-house
crates; one is now frozen. This plan does not question the asupersync doctrine (ALIEN §Doctrine
#1), but it records the concentration as a risk with a dated re-review (§7) so it is a decision,
not an accident.

### Gap G2 — `main` red for a month; 80 commits unreleased — **Critical (process)**
**Promise:** constitution #2 "green means honestly green", #11 "land complete", release flow.
**Reality:** §1.2. Three Windows audit beads in progress; the heartbeat lane is red 24×; no
0.10.1. **Bead coverage:** the fix beads exist; **no bead** for the release itself, the CHANGELOG,
or the heartbeat-green acceptance. **Class-level cause (R1):** nothing measures *release debt*
(unreleased commits × days) and nothing forces the CHANGELOG to keep pace with `git log`.

### Gap G3 — Shipped governance dimensions are undocumented — **Major (vision communication)**
**Promise:** README "Agent-first UX", "Tools" table, `robot-docs guide` "compact in-binary guide
for agents"; ALIEN plan "identity shift: we govern every dimension".
**Reality:** 10 served tools absent from the README table and from the agent guide; Arc knobs
(`max_query_cost`, SQL policy grammar, result-mask policy, `max_subscriptions`, `as_of`,
`format=arrow`, `hold`) absent from `configuration.md`/`oraclemcp.example.toml` (masking/policy
have partial mentions); README claims completions not advertised (server advertises them);
`SECURITY.md` supported line 0.6.x; `comparison.md` names the old driver and omits Oracle's own
MCP and driver; `docs/review/gate-status.md` dated 2026-07-22. **Bead coverage: NONE**
(`c-server-readme-split` deferred is adjacent, not the same). **Class-level cause (R1):** the
tool table, the agent guide, and the config reference are hand-written copies of machine truth
(registry, config structs) with no drift gate — every arc that shipped in July drifted them.

### Gap G4 — Distribution promises not real — **Major (shipped reality)**
Homebrew tap repo absent; winget never submitted; plsql-intelligence image never pushed (README
gives copy-paste `docker run` lines for it); `oraclemcp-verifier` unpublished while ADR-0010/§B
present it as the external verifier. **Bead coverage: NONE.** **Class-level cause (R1):** the
release acceptance suite verifies artifacts it *produces*, never channels it *documents*.

### Gap G5 — Proof decay: lab lanes gone, OCI lane never run, no field round on 0.10.0, stale seals — **Major (proof)**
Lab lanes absent (rig depends on a discontinued repo's container script); `oci-adb.yml` 0
runs; I1–I4/F4 open; mutation marker `status=stale`; `gate-status.md` stale; field round 3
was 0.9.0. **Bead coverage: PARTIAL** (I1–I4, F4, 5.6). **Missing:** lane restoration inside
this repo, a scheduled Tier-2 version matrix, a mutation re-seal campaign, a 0.10.x field-round
kit (operator-run, confidentiality-safe). **Class-level cause (R1):** live proof is manual and
host-bound; when the host changed, the proof silently expired.

### Gap G6 — Tracker honesty (both directions) — **Major (ledger)**
False-open: `bp8ia.13`, `091-train-root-jp5k9`, `091-ws-g-backlog-drain-97sut`. Deferred
without ruling: 72 plan-imports. Overtaken deferred: `k6q.12` (Arc M shipped server-side
masking, ADR-0008), `k6q.15` (Arc G shipped per-call + durable per-principal cost budgets),
`k6q.3`/`k6q.10` partially (Arc F / Arc N). Deferred bug: `yb7m`. Dependabot #24 unmerged.
**Bead coverage: NONE.** **Class-level cause (R1):** `deferred` is a free status; nothing
requires a ruling, and nothing forbids deferring a `bug`.

### Gap G7 — Repo hygiene — **Minor**
16 worktrees, 17 stashes, 24 branches, ~446 G ignored `target/`, untracked `npm/`, `refactor/`,
`web/playwright-report/`, dormant `publish-npm.yml`, 1 uncommitted web spec edit.
**Bead coverage:** `bipdv` (open, needs operator deletion approval per RULE 1); `c-server-*`
janitor beads deferred.

### Gap G8 — `om dashboard` does not discover the live listener — **Minor (UX defect)**
§1.3. README presents `om dashboard` as the pairing entry point. **Bead coverage: NONE.**

### Gap G9 — Test attestation signed lane blocked on operator provisioning — **Minor**
ADR-0012 / `docs/operations.md` §6.7. **Bead coverage:** K3 open (depends on it).

### Gap G10 — Monoliths — **Minor (deliberate, deferred cluster C)**
`dispatch/mod.rs` 15,178 lines (ratchet 15,829), `connection.rs` 9,115, `main.rs` 7,269,
`classifier.rs` 7,677 (safety-critical, leave), `App.tsx` 8,978. Ratchet exists; splits deferred.
**Ruling needed, not work.**

### Gap G11 — Quality-system blind spots (TRI-3 versioned-contract migrations, TRI-6 error-path matrix, flake discipline, TRI-4 redefined) — **Minor→Major over time**
Deferred cluster H. TRI-4 (driver↔server bidirectional contract) is now **moot as written**
(driver discontinued) and must be **re-scoped as the backend-conformance suite of G1**.

### Gap G12 — Windows regresses repeatedly — **Major (platform)** *(added R1)*
The 2026-07 Windows-lane recovery and the current red are the same class: audit/durable-state
file-identity + DACL semantics have no Windows-specific proof tier, so each hardening step
re-breaks the lane and is discovered by CI rather than by a local proof. **Bead coverage:** the
three in-flight fixes only.

---

## 4. Bridge plan (ordered by vision impact)

### B1 — Driver strategy: disclose, qualify as evidence, decide, unlock stable Rust (closes G1, G11/TRI-4, V16, V22) — XL
**Current:** pinned discontinued driver; 4 open qualification beads with no work.
**Target:** an evidence-backed operator decision between (a) Oracle official driver as default
with driver-cx as optional feature, (b) driver-cx default + Oracle backend optional, (c) status
quo with a dated re-review — plus honest docs in every case — where the evidence is a
**re-runnable, signed `backend-qualification/v1` document**, not a judgment call.
**Plan:**
1. **B1.1 Disclosure now (S):** README "Source builds"/"Limitations"/"Supported Oracle versions",
   AGENTS.md preamble, `docs/toolchain.md`, `docs/comparison.md`: driver-cx is frozen upstream
   (dated), what that means (security-only maintenance; no new protocol features), and that
   Oracle's official driver is under qualification with a link to the evidence document once it
   exists. Honesty-grep stays green; a test pins the disclosure sentence so it cannot be lost.
2. **B1.2 Backend-conformance suite (M):** rebind `crates/oraclemcp-db/tests/oracledb_contract.rs`
   into a backend-agnostic suite executed against BOTH backends behind `OracleConnection`
   (connect/identity; binds/types incl. NUMBER-as-string, TSTZ, VECTOR/JSON/LOB; execute
   rollback-default; commit/rollback; timeout/cancel/break; uncertain-session quarantine;
   streaming/`OwnedRowStream`; wallets/TCPS/SNI; IAM token; proxy; DRCP; CQN; Arrow; session
   identity; `DBMS_OUTPUT`). Each row emits a typed `SUPPORTED | UNSUPPORTED | BLOCKED` verdict
   with evidence; the suite writes `backend-qualification/v1` JSON (schema in a new ADR-0013),
   signed through the ADR-0012 attestation action when the secret exists, unsigned-but-labelled
   otherwise. This makes `nhteq.3` concrete and reusable for every future driver bump.
   **R2 — the suite is metamorphic, not documentary:** `crates/oraclemcp-db/tests/backend_metamorphic.rs`
   drives BOTH adapters with the same statement corpus (the guard's adversarial corpus + the
   type-fidelity fixtures) and asserts relations rather than reading driver docs:
   `MR-SER` serialized rows byte-identical across backends (NUMBER-as-string, TSTZ offsets,
   NULL, LOB caps, nested cursors); `MR-ERR` the same Oracle error yields the same
   `ErrorEnvelope` class + ORA code; `MR-CANCEL` a cancelled call leaves the session in the same
   typed state (`rolled_back | commit_in_doubt | unknown_discarded`); `MR-AUDIT` identical audit
   record shape (backend named in a new `backend` field, everything else equal); `MR-TLS` the
   same wallet/trust-union inputs produce the same accept/refuse outcome (B6 trust-union parity
   from PLAN_0_9_1); `MR-IDENT` connect-time identity fields (`program`, `machine`, `os_user`;
   note the official driver's `whoami` dependency) are set from profile config, never from the
   host by default. Each violated relation is a finding with a typed verdict, not a test
   failure to "fix later".
3. **B1.3 Sync-in-async design spike (M):** the official driver is blocking; lanes already own an
   OS thread + current-thread runtime. Decide between (i) blocking calls on the lane thread with
   the driver's own call timeout / break as the cancel primitive and (ii) a bounded driver-island
   thread per lane with a `Cx`-observed join. Prove cancellation cleanliness, `commit_in_doubt`,
   and `call_timeout_seconds` semantics with the existing `cancel_correctness.rs` shape; the
   spike's output is the `nhteq.4` design section, not code. **R3:** option (ii) is modelled in
   `loom` before it is built (the repo already runs `loom.yml`): the lane thread, the driver
   island, the `Cx` cancel edge, and the quarantine decision are the four actors; the model must
   show no lost wakeup, no double-use of a session after cancel, and a bounded join — the same
   lost-wakeup class that hung the shipping spool in 0.9.x.
4. **B1.4 Capability lattice (M):** each backend declares a typed `BackendCapabilities` set;
   tool visibility becomes `visible(tool, level, backend_caps, server_features)`; unsupported
   operations refuse with a typed `UNSUPPORTED_IN_BACKEND` envelope naming the backend and the
   alternative; `doctor`/`info`/`oracle_capabilities` report the active backend and its matrix.
   No silent fallback (epic doctrine).
5. **B1.5 License/deny + boundary (S):** allow `UPL-1.0` in `deny.toml`; boundary lint proves no
   Tokio enters with the Oracle backend enabled; the driver-seam lint learns the second adapter
   file (still exactly one file per backend).
6. **B1.6 Selection + packaging (`nhteq.5`) and dual proof + default decision (`nhteq.6`)** as
   specified; **kill-switch rule:** whichever backend becomes default, the other remains
   selectable (`backend = "…"`) for at least one minor line; the decision record cites the
   qualification document by hash.
7. **B1.7 Frozen-driver posture (S):** a scheduled `cargo deny advisories` lane scoped to the
   driver-cx subtree with a dated allowance; a security-only maintenance policy for driver-cx
   (published 0.9.x patch for dependency CVEs only) recorded in `docs/toolchain.md`.
8. **B1.8 Stable-Rust spike (S):** with driver-cx behind a feature, measure whether
   `nightly-outcome-try` still unifies in; for Windows, evaluate replacing `windows_by_handle`
   with a dependency crate exposing `number_of_links` (our crates stay `forbid(unsafe_code)`;
   a dependency's internal `unsafe` is already the norm for rustls etc.) — candidate:
   `winapi-util::file::information(&handle).number_of_links()` (stable, widely used); the
   `file_store` hard-link refusal and the audit-sink file-identity check are the only two call
   sites. Re-trigger `k6q.14` with the measured result (yes/no + why), and if yes, add a
   `stable` CI lane before switching `rust-toolchain.toml`.
**Success:** conformance matrix committed as evidence; `nhteq.6` decision recorded; README
truthful; `cargo deny` green; stable-toolchain build result recorded.
**Would beads close it?** Partially → new beads B1.1–B1.5, B1.7, B1.8 (+ tests); wire to
`nhteq.3–.6`.

### B2 — Restore green, ship 0.10.1, and install a release-debt clock (closes G2, V12, V23) — M
1. Finish `xuaea`/`8n02c`/`sd39s` with hosted Windows proof (already their acceptance).
2. **B2.2 Heartbeat-green acceptance:** three consecutive green scheduled heartbeats on `main`
   after the Windows fix lands; the bead closes on that elapsed evidence only.
3. **B2.3 CHANGELOG reconstruction:** `[Unreleased]` rebuilt from the 80 commits (Security /
   Fixed / Added / Changed), then a **changelog-pace lint**: if `git log v<last>..HEAD` contains
   `feat|fix|security` subjects and `[Unreleased]` is empty, the boundary job fails.
4. **B2.4 Release 0.10.1** through the normal tag pipeline (operator tags): pre-tag rehearsal
   dispatch; D3.2 local-gate proof for the RC SHA; `ysvhx` decided (keep v2 pin or migrate)
   before the tag; release acceptance extended by B4's channel verifiers.
5. **B2.5 Release-debt clock:** a scheduled lane computes (commits since last tag, days since
   last tag) and fails the heartbeat above a budget (default 40 commits or 21 days) — the
   number becomes a Ground-Control tile via the existing CI-lane-health panel.
6. **B2.6 Dependabot #24:** merge after the rehearsal proves the actions bump; first release run
   watched deliberately (tag-only paths).
7. **B2.7 One release-evidence manifest (R2):** `release-evidence/v1` — a JSON manifest listing
   the SBOM, the build provenance bundle, the test-attestation status/document, the
   `backend-qualification/v1` document, the D3.2 local-gate proof and the regenerated
   gate-status, each by SHA-256; the manifest itself is cosign-signed as a release asset and its
   digest is anchored through the existing Rekor audit-head path (Arc B2 machinery). A user or
   auditor verifies ONE hash. `docs/operations.md` §6 gains a five-line "verify everything"
   recipe; `scripts/verify_release_exact_sha.py` consumes the manifest. **R3:** the manifest is
   a Merkle tree over its entries (leaf = SHA-256 of each artifact + role), so a verifier can
   check ONE artifact with an inclusion path without downloading the rest — the same primitive
   the audit chain's Rekor anchoring already uses offline (`oraclemcp-audit` inclusion-proof
   verification boundary, Arc B2.4).
**Would beads close it?** Partially → new B2.2–B2.7.

### B3 — Make the shipped dimensions visible: registry-as-source-of-truth docs (closes G3, V9, V17 communication) — M
1. **B3.1 README "Governed dimensions":** one section that states the identity shift in the
   §3.4 voice (no superlatives) — cost, time, egress, proof, policy, living-DB, vector, lineage,
   fleet, reversible workspace, editions, incident capture, refusal corpus, console — each 3
   lines + tool names + the config knob + the e2e script that proves it; complete the Tools table
   (35) and aliases (25); state the level-gated visibility rule; fix the completions sentence.
2. **B3.2 Generated tool docs + drift gate:** `oraclemcp robot-docs tools --markdown` renders
   the canonical table from `tool_registry()`; the README table is fenced
   `<!-- generated:tools -->…<!-- /generated -->`; a boundary-job test regenerates and diffs;
   `robot-docs guide` embeds the same rendering so the agent guide can never lag the registry.
3. **B3.3 Generated config reference + drift gate:** `oraclemcp robot-docs config --markdown`
   walks the `deny_unknown_fields` config types (serde-reflection through a small `ConfigDoc`
   derive or a hand-kept key list guarded by a completeness test) and renders `configuration.md`'s
   field table + `oraclemcp.example.toml`'s commented defaults; drift = red boundary job.
   **R3 — completeness by construction:** a property test generates, from the config types, one
   TOML document that sets EVERY key (with `deny_unknown_fields` rejecting anything undocumented
   and round-tripping through `serde`), then asserts the documented key set equals the parsed
   key set. Documentation completeness becomes a set equality, not a reviewer's memory.
4. **B3.4 Truth refresh:** `SECURITY.md` supported line (0.10.x current); `docs/comparison.md`
   (driver freeze, Oracle's official MCP server and official driver as neighbours, dated);
   `docs/review/gate-status.md` regenerated by a script at `HEAD` with the 9-gate sweep.
5. **B3.5 Refusal catalogue:** `ReasonCategory`/error classes → one generated page ("why was I
   refused, what next") reusing the `ErrorEnvelope` `next_actions`; linked from the README.
6. **B3.6 Claims ledger (R2):** `docs/claims.md` (generated from a small TOML, `claims.toml`):
   every load-bearing README/docs claim → its §3.4 label (`VERIFIED | OBSERVED |
   SUPPORTED_UPSTREAM | PLANNED | NOT_TESTED`) → the exact command/lane/artifact that verifies
   it (e.g. "23ai tested" → `ci.yml:oracle-free23`; "Homebrew" → B4.5 verifier; "TCPS/wallet
   pem/sso/p12" → `live_oracle` wallet cases; "no npm channel" → `installer_e2e::npm_release_channel_is_retired`).
   The honesty-grep evolves from a forbidden-phrase list into a **claims-have-verifiers** check:
   a README claim tagged in `claims.toml` with no verifier, or a verifier lane that is not
   green at the release SHA, fails release acceptance. This is the mechanism behind G3/G4 as a
   class — a claim without a verifier cannot ship.
**Would beads close it?** No existing bead → new B3.1–B3.6 (+ drift tests).

### B4 — Every documented channel is verified or not documented (closes G4, V7, V14) — M
1. **B4.1 Homebrew:** create `MuhDur/homebrew-oraclemcp`; `release.yml` pushes the rendered
   formula (scoped token); release acceptance runs `brew install MuhDur/oraclemcp/oraclemcp` on
   the macOS runner and `oraclemcp --version` must match the tag.
2. **B4.2 winget:** `wingetcreate` submission step (or a documented manual PR) per release;
   README wording remains "pending" until the first merged manifest; a scheduled check flips the
   README sentence via B3's generated block only when `winget show` resolves.
3. **B4.3 plsql-intelligence image:** build/push `:<version>-plsql-intelligence` +
   `:plsql-intelligence-latest` from `release.yml`; acceptance runs
   `docker run … --json info` and asserts `engine=true`.
4. **B4.4 `oraclemcp-verifier`:** publish it (add to `publish_crates.sh` ordering, API lock) —
   or set `publish = false` and route verification through the `oraclemcp` binary — one truth,
   with `cargo install oraclemcp-verifier` (or its documented absence) in the acceptance suite.
5. **B4.5 Channel-truth gate:** the release acceptance suite fails when README documents a
   channel with no green verifier step — the mechanism that prevents G4's class.
**Would beads close it?** No existing bead → new B4.1–B4.5.

### B5 — Restore and mechanize proof (closes G5, V8, V18, V24) — L
1. **B5.1 Lab lanes owned by this repo:** `scripts/rig/oracle_l1.sh up` creates gvenzl XE 18 /
   XE 21 / FREE 23ai lanes when absent (idempotent, pinned image digests, documented ports,
   throwaway principals), removing the dependency on the discontinued driver repo's
   `container.sh`; `rig.sh doctor` reports lane presence/health.
2. **B5.2 Tier-2 nightly version matrix in CI:** `oracle_version_matrix.sh --log` + the arc
   matrices (`cost_gate`, `time_diff`, `served_egress`, `sql_policy`, `fleet`, `reversible`,
   `living_db`, `governed_rag`, `live_lineage`) with typed skips per lane; results as exact-SHA
   evidence the release consumer reads; the heartbeat watches it. Per-PR keeps the single
   free23 lane.
3. **B5.3 OCI:** run I1–I4 + F4 as specified (agent-runnable within the free-tier guardrails;
   F5 confidentiality guard is part of I1's DoD; AVAILABLE=0 asserted before/after).
4. **B5.4 Mutation re-seal:** after `bp8ia.5.6`, a fresh complete OOM-free five-scope campaign
   replaces `status=stale`; the marker's `status=enforcing` becomes a release-preflight input again.
5. **B5.5 `oraclemcp selftest` — the field-round kit as a product feature:** package the rig's
   `tool_surface_sweep.py`, doctor, refusal probes and the wire-contract fixtures as an in-binary,
   operator-run, redacted, signed round report (`selftest-report/v1`, reusing ADR-0011 redaction
   and ADR-0012 signing). Goal from PLAN_0_9_1 §2: a field test becomes a confirmation, not a
   discovery mechanism; the operator runs it against the real environment and shares only the
   redacted report. **R2 flywheel:** every refusal the selftest observes is exported through the
   existing redacted refusal-corpus writer (Arc J, `refusal_corpus_gate.py`) so a field round
   grows the guard's adversarial corpus without ever carrying a customer identifier; the round
   report lists corpus deltas by content-ID only.
6. **B5.6 Proof-freshness tile (R2):** the Ground-Control CI-lane-health panel shows, per proof
   (nightly matrix, mutation seal, OCI signoff, field round), the SHA it was last green at and
   its age; the heartbeat reds when any proof is older than its tier's budget (matrix 7 d,
   seal 30 d, OCI 90 d, field round per release). Proof decay becomes visible, not discovered.
7. **B5.7 Flake discipline by sequential testing (R3, closes TRI-7):** instead of the OCI/live
   lanes' fixed "retry 15×20 s" (which masks propagation failures and burns runs), a lane that
   fails is re-run under Wald's Sequential Probability Ratio Test with explicit α/β and a hard
   cap: the outcome is typed `FLAKY(p̂, n)` or `BROKEN` or `INFRA_SKIP`, never a green after a
   lucky retry. Quarantined lanes expire (14 d) and re-block on recovery (plan §27.6 item 4).
   Deliverable: `scripts/ci/sprt_rerun.py` + the three typed outcomes in `ci_taxonomy`.
**Would beads close it?** Partially → new B5.1, B5.2, B5.4, B5.5, B5.6, B5.7; existing I1–I4/F4/5.6.

### B6 — Tracker reconciliation + a ruling-lint (closes G6) — S
1. **B6.1** Close the 3 false-open beads with landed evidence (release run 2026-07-26 + tag).
2. **B6.2 Ruling table** for the 100 deferred beads: for each → `overtaken-by <bead>` (close as
   duplicate with the shipped bead + a test name), `keep-deferred (operator ruling + trigger)`,
   or `un-defer into <epic>`; presented to the operator; agents never decide (constitution #1).
   `yb7m` (bug) → un-defer proposal. **R2 packet format:** each row is a decision packet —
   bead, title, cluster, evidence for "overtaken" (shipped bead + test name) or the recorded
   trigger, recommended ruling, and the exact `br` command that applies it; the operator answers
   per row or per cluster. Ruling note grammar (machine-checkable by B6.3):
   `ruling: <operator> <YYYY-MM-DD> <keep|overtaken-by:<id>|undefer:<epic>> trigger=<text>`.
3. **B6.3 Ruling-lint:** `scripts/bead_tracker_guard.sh` (or a `bv`/JSONL lint in the boundary
   job) fails when a `deferred` bead lacks a `ruling:` note (who/when/trigger) and when any
   `type=bug` is `deferred` — mechanizing constitution #1.
4. **B6.4** Merge/close Dependabot #24 (B2.6); commit or drop the stray web spec edit.
**Would beads close it?** No → new B6.1–B6.4.

### B7 — Hygiene (closes G7) — S, operator-gated deletions
`bipdv` inventory → operator approves → prune; retire `npm/`, `publish-npm.yml`, `refactor/`
artifacts (RULE 1: exact in-session command); stash triage preserve-first; a scheduled
disk/worktree report tile (reuse the CI-lane-health panel) so bulk is visible before it is 446 G.

### B8 — `om dashboard` listener discovery (closes G8) — S
Read `service-instance.json` from the state root first; fall back to `--url`/default; the typed
error names both candidates. Test: pairing succeeds against a non-default port without `--url`;
`service status` and `dashboard` share one discovery helper.

### B9 — Attestation provisioning runbook (closes G9) — S (operator action)
One bead listing the two settings, the verifier trust-policy handoff, and the acceptance
(K3 lane emits a signed document; K2 verifies it in the browser).

### B10 — Windows proof tier (closes G12, V25) — M *(added R1)*
1. A Windows-only test tier (`docs/test-tiers.md`) for file identity, DACL/owner proofs, durable
   state, and audit sink parents, runnable locally on a Windows runner and in `windows-rust`.
2. A `windows-durable-state` release-acceptance step (install → service → audit append →
   `audit verify` on Windows) so a Windows regression blocks a tag, not just a heartbeat.

### B11 — Rulings for G10/G11 — operator decisions, recorded in B6's table.

### Dependency sketch
```
B2.1 Windows fixes ─▶ B2.2 heartbeat green ─▶ B2.4 0.10.1 ◀─ B2.3 CHANGELOG ◀─ B3.2/B3.3 gates (docs frozen truthful)
B2.4 ─▶ B4.1/B4.2/B4.3/B4.4 (channels ride the release) ─▶ B4.5 gate
B1.1 disclosure (now) ─▶ B1.2 conformance ─▶ B1.3 spike ─▶ B1.4 lattice ─▶ nhteq.4 ─▶ B1.5 ─▶ nhteq.5 ─▶ nhteq.6 ─▶ B1.8 stable spike
B1.7 frozen-driver posture: anytime
B5.1 lanes ─▶ B5.2 nightly matrix ─▶ (B5.4 re-seal after bp8ia.5.6) ; B5.5 selftest ─▶ field round 4 (operator) ; B5.3 OCI after I1
B6 anytime (S) ; B7 after operator ack ; B8 anytime ; B9 operator ; B10 with B2.1
```

### Verification plan (after bridge work)
- V1/V12/V25: full workspace gate green on Linux **and** Windows; heartbeat green ×3; Windows
  acceptance step green on the next tag.
- V7: `brew install MuhDur/oraclemcp/oraclemcp`, `winget install --id MuhDur.oraclemcp`,
  `docker run ghcr.io/muhdur/oraclemcp:plsql-intelligence-latest --json info`, `cargo install
  oraclemcp-verifier` (or documented absence) — each a recorded acceptance step.
- V9/V17: the boundary job fails if any registry tool or config key is missing from the docs.
- V8/V24: nightly matrix evidence for 18c/21c/23ai at the current SHA; OCI signoff artifact
  (synthetic evidence only).
- V22: `backend-qualification/v1` committed; decision record; `cargo deny` green; stable-build
  result recorded.
- V23: `br list --status open` contains no shipped work; every deferred bead carries a ruling;
  the ruling-lint and release-debt clock are green.

---

## 5. Bead map (Phase 3a DONE 2026-09-04 — created through `br`, 54 beads, 59 blocking edges, no cycles)

Root epic **`oraclemcp-2q4em`**; sub-epics `.1`–`.10` = B1…B10; tasks/tests below. Existing open
beads are linked by blocking edges, never duplicated: `nhteq.3` ← B1.2; `nhteq.4` ← B1.3, B1.4;
`nhteq.5` ← B1.4, B1.5; `nhteq.6` ← B1.2t; B1.8 ← `nhteq.5`; B2.2 ← `xuaea`, `8n02c`, `sd39s`;
B2.6 ← `ysvhx`; B5.4 ← `bp8ia.5.6`; B7 ← `bipdv`; K3 (`bp8ia.12.3`) ← B9.

| Plan item | Bead |
|---|---|
| root | `oraclemcp-2q4em` |
| B1 | `oraclemcp-2q4em.1` |
| B1.1 | `oraclemcp-2q4em.1.1` |
| B1.2 | `oraclemcp-2q4em.1.2` |
| B1.3 | `oraclemcp-2q4em.1.3` |
| B1.4 | `oraclemcp-2q4em.1.4` |
| B1.4t | `oraclemcp-2q4em.1.5` |
| B1.2t | `oraclemcp-2q4em.1.6` |
| B1.5 | `oraclemcp-2q4em.1.7` |
| B1.7 | `oraclemcp-2q4em.1.8` |
| B1.8 | `oraclemcp-2q4em.1.9` |
| B2 | `oraclemcp-2q4em.2` |
| B2.2 | `oraclemcp-2q4em.2.1` |
| B2.3 | `oraclemcp-2q4em.2.2` |
| B2.3t | `oraclemcp-2q4em.2.3` |
| B2.5 | `oraclemcp-2q4em.2.4` |
| B2.6 | `oraclemcp-2q4em.2.5` |
| B2.7 | `oraclemcp-2q4em.2.6` |
| B2.7t | `oraclemcp-2q4em.2.7` |
| B2.4 | `oraclemcp-2q4em.2.8` |
| B3 | `oraclemcp-2q4em.3` |
| B3.2 | `oraclemcp-2q4em.3.1` |
| B3.3 | `oraclemcp-2q4em.3.2` |
| B3.1 | `oraclemcp-2q4em.3.3` |
| B3.4 | `oraclemcp-2q4em.3.4` |
| B3.5 | `oraclemcp-2q4em.3.5` |
| B3.6 | `oraclemcp-2q4em.3.6` |
| B4 | `oraclemcp-2q4em.4` |
| B4.1 | `oraclemcp-2q4em.4.1` |
| B4.2 | `oraclemcp-2q4em.4.2` |
| B4.3 | `oraclemcp-2q4em.4.3` |
| B4.4 | `oraclemcp-2q4em.4.4` |
| B4.5 | `oraclemcp-2q4em.4.5` |
| B5 | `oraclemcp-2q4em.5` |
| B5.1 | `oraclemcp-2q4em.5.1` |
| B5.2 | `oraclemcp-2q4em.5.2` |
| B5.4 | `oraclemcp-2q4em.5.3` |
| B5.5 | `oraclemcp-2q4em.5.4` |
| B5.5t | `oraclemcp-2q4em.5.5` |
| B5.6 | `oraclemcp-2q4em.5.6` |
| B5.7 | `oraclemcp-2q4em.5.7` |
| B5.7t | `oraclemcp-2q4em.5.8` |
| B6 | `oraclemcp-2q4em.6` |
| B6.1 | `oraclemcp-2q4em.6.1` |
| B6.2 | `oraclemcp-2q4em.6.2` |
| B6.3 | `oraclemcp-2q4em.6.3` |
| B6.3t | `oraclemcp-2q4em.6.4` |
| B6.4 | `oraclemcp-2q4em.6.5` |
| B7 | `oraclemcp-2q4em.7` |
| B8 | `oraclemcp-2q4em.8` |
| B9 | `oraclemcp-2q4em.9` |
| B10 | `oraclemcp-2q4em.10` |
| B10.1 | `oraclemcp-2q4em.10.1` |
| B10.2 | `oraclemcp-2q4em.10.2` |

`br ready` after creation: B1.1, B1.2, B1.7, B2.3, B2.5, B2.7, B3.2, B3.3, B3.4, B3.5, B3.6, B4.1,
B4.2, B4.3, B4.4, B5.1, B5.4-blocked-on-5.6, B6.1, B6.2, B8, B9 (see `br ready --json`).

---

## 6. Explicitly NOT in this plan (operator-owned or deferred with a ruling)
- Cluster J (GCP/Vertex/site/video/launch) — ruled deferred 2026-07-22.
- Orrery 3D, UDS operator socket, TUI — ruled deferred (0.6.x).
- The field round-4 execution itself against the operator's environment — operator-run; this
  plan only ships the kit (B5.5).

---

## 7. Risks
| Risk | Mitigation |
|---|---|
| Oracle's driver is beta; its API may move | Pin exact; B1.2 re-runs per bump; no silent fallback; kill-switch minor |
| Blocking driver inside async lanes hides cancellation | B1.3 proves cancel/timeout/quarantine before any default flip |
| Doc generation from registry degrades prose | Generate tables only; prose stays hand-written; drift test is name-level |
| Lane restoration pulls large images on CI | Nightly Tier-2 only; digests pinned; per-PR keeps the single free23 lane |
| Tracker reconciliation closes work that is not done | Every close cites evidence; "overtaken" requires the shipped bead + a test name |
| Release-debt clock nags without authority | It only reds the heartbeat; tagging stays operator-gated |
| Channel verifiers make releases slower/flakier | Verifiers run post-publish in acceptance, are retry-safe, and never block crates.io |
| Runtime dependency concentration (asupersync + driver-cx both in-house; one frozen) | Recorded as a decision with a dated re-review (2026-12) in `docs/toolchain.md`; B1 removes the driver half; asupersync stays by doctrine |
| Claims ledger becomes a second README to maintain | It is a TOML index of ~40 claims, generated to Markdown; a claim without a verifier is the failure mode we want to see |
| Metamorphic suite needs both backends compiled | Feature-gated; runs in the `feature-powerset` job for the dual-feature combo only |

---

## 9. Execution view (R2) — tracks, hot files, scope ladder, exit metrics

### 9.1 Four parallel tracks (swarm-safe: no shared hot file within a wave)
| Track | Owns | Hot files | Notes |
|---|---|---|---|
| T-GREEN (release) | B2.1–B2.7, B10, B8 | `crates/oraclemcp-audit/src/*` (Windows), `crates/oraclemcp/src/main.rs` (dashboard discovery), `.github/workflows/*`, `CHANGELOG.md` | first to land; nothing else touches workflows until B2.4 tags |
| T-DRIVER | B1.1–B1.8, `nhteq.3–.6` | `crates/oraclemcp-db/src/connection.rs` (+ one new adapter file), `crates/oraclemcp-db/tests/*`, `deny.toml`, `docs/toolchain.md` | B1.4 lattice touches `crates/oraclemcp-core/src/server.rs` + `crates/oraclemcp/src/registry.rs` → sequence after B3.2 |
| T-DOCS (truth) | B3.1–B3.6, B4.1–B4.5, B6.1–B6.4 | `README.md`, `docs/*`, `crates/oraclemcp/src/robot_docs.rs`, `crates/oraclemcp/src/registry.rs` (render fn only), `scripts/*lint*.sh`, `.beads/` | B3.2 lands before B1.4 (shared `registry.rs`) |
| T-PROOF | B5.1–B5.6, B9, `bp8ia.10.*`, `091-f4` | `scripts/rig/*`, `scripts/e2e/*`, `docs/test-tiers.md`, `web/src/app/ci-lane-health-panel.tsx` | nightly matrix lane added to workflows only after B2.4 (workflow freeze) |

### 9.2 Release trains
- **0.10.1** (T-GREEN + T-DOCS): green Windows, heartbeat ×3, CHANGELOG, disclosure (B1.1),
  docs drift gates (B3.2/B3.3), README dimensions (B3.1), dashboard discovery (B8), channels
  (B4.1–B4.4) riding the tag, evidence manifest (B2.7), tracker reconciliation (B6). No public API
  change → patch (semver-checks gates).
- **0.11.0** (T-DRIVER + T-PROOF): backend qualification document, capability lattice, backend
  selection + Oracle backend (additive API → minor), nightly matrix + proof tile, selftest,
  OCI signoff, mutation re-seal, stable-Rust result. The default-backend decision (`nhteq.6`) is
  the train's gate; a default flip is announced one minor ahead (kill-switch rule).

### 9.3 Scope-cut ladder (operator chooses; nothing is cut by agents)
- L0 full program. L1 cut B5.5 `selftest` (keep the kit as rig scripts). L2 cut B1.8 stable-Rust
  spike and B5.6 proof tile. L3 cut winget (B4.2) and the claims ledger (B3.6) — keep the drift
  gates. **Emergency floor:** B2.1–B2.4 (green + 0.10.1), B1.1 (disclosure), B6.1 (false-open
  closes), B8 (dashboard discovery).

### 9.4 Exit metrics (numbers, not adjectives)
| Item | Metric at exit |
|---|---|
| B2 | heartbeat green ≥3 consecutive; release debt ≤ 40 commits / ≤ 21 days; `[Unreleased]` non-empty whenever debt > 0 |
| B3 | registry↔README↔robot-docs drift = 0 (CI); config keys documented = 100 % (CI); claims with verifiers = 100 % of tagged claims |
| B4 | documented channels verified at tag = 4/4 (brew, winget-or-pending, plsql image, verifier crate-or-documented) |
| B1 | `backend-qualification/v1` rows with typed verdicts = 100 % of `OracleConnection` requirements; metamorphic relations violated = 0 or each has a bead; decision record cites the document hash |
| B5 | nightly matrix green on 3/3 lanes for 7 consecutive days at a current SHA; mutation marker `status=enforcing`; OCI signoff artifact present (synthetic); selftest report produced from a lab profile |
| B6 | open beads with shipped work = 0; deferred beads without `ruling:` = 0; `type=bug ∧ deferred` = 0 |
| B10 | Windows acceptance step green on the next tag |

---

## 8. Round log
- **R0 (2026-09-04):** initial reality check + bridge plan from measured ground truth.
- **R1 (2026-09-04, "decent start but barely scratches the surface"):** every gap now names its
  *class-level cause* and a mechanism that prevents recurrence (drift gates for tool/config
  docs, channel-truth gate, release-debt clock + changelog-pace lint, ruling-lint for deferrals,
  repo-owned lab lanes + nightly matrix, Windows proof tier); the driver decision became a
  signed, re-runnable `backend-qualification/v1` evidence product with a capability lattice and
  a kill-switch rule; added G12/B10 (Windows) and V25; added B1.7 frozen-driver posture, B5.5
  `selftest` as the field-round kit, B3.5 refusal catalogue, B7 disk tile.
- **R2 (2026-09-04, "a lot better but STILL a far cry from OPTIMAL"):** applied the product
  thesis to the project: B3.6 claims ledger (claims-have-verifiers replaces the phrase blacklist),
  B1.2 became a metamorphic cross-backend suite (MR-SER/ERR/CANCEL/AUDIT/TLS/IDENT), B2.7 one
  signed `release-evidence/v1` manifest anchored via Rekor, B5.5 selftest→refusal-corpus
  flywheel, B5.6 proof-freshness tile with per-tier age budgets, B6.2 decision packets with a
  machine-checkable ruling grammar, B1.8 concrete Windows stable path, dependency-concentration
  risk recorded, and §9 (tracks + hot-file map, release trains 0.10.1/0.11.0, scope-cut ladder,
  numeric exit metrics).
- **R3 (2026-09-04, "RUMINATE — what technique gives real alpha here"):** four additions, each
  reusing a proof/verification lane the repo already runs, none decorative: Kani proof of the
  visibility/capability lattice (monotone + sound), a `loom` model of the sync-driver island
  before it is built, config-documentation completeness as a generated-TOML set equality,
  SPRT-based flake classification with typed outcomes, and a Merkle-structured release manifest
  with inclusion proofs. **Deliberately NOT added** (doctrine #5, "verified not claimed; no
  esoterica for its own sake"): differential wire-fuzzing between the two drivers (Oracle's
  driver exposes no sans-I/O decoder to fuzz against), a second classifier proof engine, and any
  performance claim without a measurement artifact.
- **Phase 3a (2026-09-04):** 54 beads created through `br` under root `oraclemcp-2q4em` (§5); 59
  blocking edges incl. links into `nhteq.3–.6`, the three Windows fixes, `ysvhx`, `bp8ia.5.6`, `bipdv`,
  K3; `br dep cycles` clean; JSONL flushed.
- **Refinement r1 (graph):** removed I1→B5.7 (SPRT must never block OCI) and B4.5→B3.6 (the L3-cuttable
  claims ledger must not gate the channel-truth gate); added B2.4→B4.5 (channels are verified AT the
  0.10.1 tag). Added `doctor` "Driver posture" + `info.driver_posture` to B1.1 (users learn the freeze
  from the binary, not only the README).
- **Refinement r2 (tests + logging):** explicit negative fixtures / dry-run contract tests / JSON-line
  logging added to B1.5, B1.7, B3.4, B5.1, B5.2, B6.2 (every implementation bead now names its proof).
- **Refinement r3 (user value):** B8 reports which listener it paired with; B5.5 gains `--offline` and
  `--compare` (diffable field rounds without a database); B3.1 opens with the READ_ONLY-vs-elevated
  tools/list example and links the refusal catalogue.
- **Refinement r4 (one bead per defect):** recorded supersession/overlap against existing deferred beads
  so B6.2's packet can rule instead of duplicating: B1.2 ⊃ TRI-4 provider/consumer beads; B5.7 ⊃
  flake-discipline `izpb6`; B7 coordinates the three janitor beads; B6.3 vs tracker-audit `0hug`; B2.4
  notes the rehearsal bead `6pk1` is overtaken; B1.8 is the re-trigger of `k6q.14`.
- **Refinement r5 (convergence):** re-read of all 54 bodies found no lost feature from §4, no bead without
  acceptance criteria, no dependency cycle, and no new gap → refinement stopped (skill stop rule).
