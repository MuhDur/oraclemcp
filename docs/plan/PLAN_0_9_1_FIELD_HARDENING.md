# PLAN — oraclemcp 0.9.1 / driver 0.9.0: field-hardening, self-sufficient testing, OCI

**Version:** v1 (pre-review). **Date:** 2026-07-20.
**Owner:** lead orchestrator. **Release is operator-gated** — agents never tag or publish.

**How to use this document.** It is written to be self-contained: an agent that has never seen this
project should be able to pick any task here and implement it without asking a human. Every task names
its blocking dependencies, its acceptance criteria, and *why* it exists. Code-level evidence for the
field findings lives in the companion annex **`docs/plan/GROUNDING_ROUND3_FINDINGS.md`** — that annex
is normative for `file:line`, root causes, and minimal fixes; this plan is normative for scope,
ordering, and acceptance.

---

## 1. Ground truth (verified 2026-07-20, not assumed)

### 1.1 Repository state
| | oraclemcp | rust-oracledb (driver) |
|---|---|---|
| Released | 0.9.0 (2026-07-18) | 0.8.4 (2026-07-18) |
| `main` HEAD | `5058690` | `537373a` |
| Full local gate | clippy ✅ + `cargo test --workspace` ✅ | clippy ✅ + tests ✅ + `gen_baseline.sh --check` ✅ |
| Test binaries | — | 169 across both repos, **0 failures** |

**CI honesty note.** The driver push at `d99927d` went **red** (2 of 25 checks): `required/quality-contracts`
failed its *Baseline drift check* (`docs/baseline` stale after the TLS + pyshim commits) and the
aggregate quality job reported `failed=1` behind it. Cause: the pre-push gate ran clippy + tests but
omitted `scripts/gen_baseline.sh --check`. Fixed and pushed as `537373a`. **Rule added:**
`gen_baseline.sh --check` is mandatory in the driver's pre-push gate (see §9.1).

**Public-surface delta from that regen: `oracledb` went 908 → 915 public source items** (the new
stage-aware TLS types). This has a release consequence — see §7.

### 1.2 Bead inventory (oraclemcp `.beads/issues.jsonl`, 51 open/in_progress)
| Group | Count | Disposition in this plan |
|---|---:|---|
| F-LOW children `7.11.1..20` (P3 real defects, `file:line` specified) | 20 | Workstream G3 — triaged, not all in 0.9.1 |
| Epics (close as children drain) | 11 | Bookkeeping; close at the end |
| Work beads | 11 | Workstreams G1/G2/G4 |
| Cluster I — OCI Always-Free e2e | 4 | **Workstream F (in scope)** |
| Cluster J — GCP/Vertex launch | 5 | **DEFERRED by operator — out of scope** |

Driver beads: `rust-oracledb-4sfc` (**believed closed** — see §4.B5) and `rust-oracledb-s0se`
(close_notify; relates to P1-8). 21 further driver beads are `deferred` and stay deferred.

The 11 work beads: `plan-bead-graph-lint-eshv` (P0), `13` release train (P1, versions now fixed: driver 0.9.0 / server 0.9.1), `5.2` D2 coverage
ratchet (P1), `8.1` G1 IAM subject-mapping (P1), `4.3` C3 stash triage, `4.5` C5 moves/renames,
`4.6` C6 de-monolith, `5.4` D4 fuzz shard (reopened for a cold-start proof), `8.2` G2 Live-nightly
streak, `12.3` K3 attestation lanes (P3), `izk5` stale driver-version comment (P3).

### 1.3 Local environment — better than assumed
**Oracle containers already exist on this machine**, which removes the largest cost from Workstream D:

- running: `oracle-xe21-1520` (`gvenzl/oracle-xe:21-slim`), `oracle-xe18-1518` (`gvenzl/oracle-xe:18-slim`),
  `rust-oracledb-free` (`gvenzl/oracle-free:23-slim`), `plsql-intelligence-xe`
- cached images: `gvenzl/oracle-xe:11/18/21-slim`, `gvenzl/oracle-free:23-slim`,
  `oraclelinux9-instantclient:23`

**OCI:** `~/.oci/oraclemcp_adb_api_key.pem` and `~/.oci/oraclemcp-adb.env` exist; **`~/.oci/config` is
ABSENT**, and `~/bin/oci` is installed. → **Operator action required (§4.F0)**: authenticate the OCI CLI
on this machine. Until then Cluster I cannot start. Everything else in this plan proceeds without it.

### 1.4 Field input
Round-3 field test against **0.9.0**: **5 P0 adoption blockers, 14 P1, 13 P2**, against a product whose
CI was fully green. Raw round is quarantined (`livesting-*/`, gitignored, constitution #9); the scrubbed
code-level grounding is the annex. **Grounding is complete for every finding except P1-2.**

---

## 2. Objectives and non-goals

### Objectives
1. **Make the product adoptable.** Every P0 blocker fixed or explicitly, honestly deferred with a reason.
2. **Stop shipping features that cannot be reached from outside the repo** (§3).
3. **Become self-sufficient in testing** — reproduce the field's finding classes on this machine, so a
   production field test is a confirmation, not a discovery mechanism.
4. **Drain the backlog** — all remaining beads except Cluster J, including the OCI campaign.
5. **Cut one coordinated release** carrying all of it.

### Non-goals
- **Cluster J (GCP/Vertex launch)** — deferred by the operator.
- **Fixing the customer's database or diagnosing their VPD policy.** We ship *visibility* (§4.A1), not a
  remote diagnosis.
- **A rewrite of the OAuth verifier** — it is correct (annex §5.2); this is documentation + diagnostics.
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

**§8 test-shape rules** (from the annex) become binding repo policy and go into AGENTS.md.

---

## 4. Workstreams

Priority notation: **[P0]** blocks the release; **[P1]** should ship; **[P2]** ship if it lands cleanly.

### Workstream A — P0 adoption blockers

#### A1 [P0] Make row-level security visible; stop silent-empty reads
*Field: P0-4. Annex §2.3, §2.4, §2.5, §2.7.*

The field symptom (VPD-protected objects read as empty) decomposes into four defects. **The tester's own
root cause was wrong** — session statements *are* applied to the serving connection (annex §2.1). Ship
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

**Depends on:** none. **Unblocks:** the field's top blocker.
**Diagnostic to ship alongside (no code change needed to run):** the server already has
`SESSION_CONTEXT_SQL` and `SESSION_ROLES_SQL` (`catalog_resolver.rs:31-36`) — expose them via `doctor`
so an operator can diff principal/roles between two clients and settle H1 immediately.

#### A2 [P0] `setup --write` must work, and the state-store lock must explain itself
*Field: P0-1 + P1-13. Annex §1.*

**These are one bug.** `FileStore::acquire_service_owner` takes a **process-wide exclusive flock over the
entire state store**; both `setup --write` (`config_ops.rs:325-332`) and the credential CLI
(`client_credentials.rs:319-322`) call it, so neither works while a server runs. The real
`FileStoreError::Locked` ("file-store service lock is already held") is **discarded** by a catch-all
match arm emitting a fixed `ORACLEMCP_SETUP_WRITE_FAILED` (`main.rs:4609-4616`) — which is why `--json`
and `RUST_LOG=debug` added nothing.

- **A2a [P0] — stop discarding the error.** Map `FileStoreError::Locked` to a distinct code
  (e.g. `ORACLEMCP_STATE_STORE_LOCKED`) whose message names the holding service and the remedy. *One
  match arm.* This alone converts an unsolvable mystery into a 10-second fix for the user.
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
*Field: P0-2. Annex §6.1.*

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
  connection", which **no MCP client can do**.

#### A4 [P0] A pooled connection that dies while idle must be replaced
*Field: P0-5. Annex §6.3 (corrected twice — read it before implementing).*

oraclemcp does **not** use the driver's pool; it has its own (`oraclemcp-db/src/pool.rs`). That pool has
`ping`/`has_broken` but calls `has_broken` **only on the return path** (`pool.rs:405-420`) — there is
**no validate-on-checkout**, so a connection that died while idle is handed to the next caller and the
first query fails with a raw `Broken pipe (os error 32)`.

- **A4a** — validate (or evict) on **checkout**. Reference shape: the driver's own `_check_connection`
  (`oracledb/src/pool/engine.rs:35-90`, default `ping_interval_secs: 60`).
- **A4b** — retry once on a fresh connection after a transport I/O error.
- **A4c** — `oracle_connection_info` must do a **real round trip** (it returned `connected:true` with
  every liveness field null); `doctor` must not show a green check for a dead pool.
- **A4d** — stop leaking raw driver errors to callers; map to typed envelopes.
- **Open question for §4.D:** whether the *pinned* session (which `oracle_query` uses, annex §2.8) is
  pooled at all. If it is a single long-lived connection outside the pool, A4a is insufficient and it
  needs its own liveness/reconnect path. **Settle this in the local environment before implementing.**

#### A5 [P0] The dashboard must work in a browser
*Field: P0-3. Annex §6.2.*

The pairing page emits `Referrer-Policy: no-referrer` (header **and** meta, `http/mod.rs:1260`), so a
form POST carries `Origin: null`, which `dashboard_same_origin_required` refuses at **four** sites
(`http/mod.rs:1392/1400/1413/1421`) — hence `--http-allowed-origin null` does not help. `curl` passed
because it sends no referrer policy. **The tests assert the breaking policy** (`tests_dashboard.rs:25/467/480`).

- **Option (a), preferred:** use `Referrer-Policy: same-origin` for the pairing page. CSP already carries
  `form-action 'self'`.
- **Option (b):** accept `Origin: null` for this endpoint **only** when `Host` is loopback and the
  one-time pairing code is valid (the code is the real authenticator).
- Either way, **all four check sites must agree**, and the tests asserting `no-referrer` must be updated
  deliberately with a recorded rationale — not silently.
- **Security review required** (this is an auth surface): document why the chosen option does not weaken
  the fail-closed posture.
- **Test:** a real headless-browser POST (the repo already installs Chromium for the K2 e2e lane), not curl.

---

### Workstream B — P1 findings

#### B1 [P1] mTLS / control listener: normalize at enforcement
*Field: P1-10. Annex §5.1. **Highest-value P1** — a headline 0.9.0 feature that cannot serve a request.*

Root cause is **normalize-on-validate vs exact-match-on-enforce**: `admin_auth.rs:102-107` compares with
raw `==`, while `client_fingerprints` accepts three spellings and the control-listener precondition
check normalizes both sides. A config with `allowed_subjects = ["mtls:AABB…"]` validates, starts, logs
"control transport enabled", and silently RSTs every request. (My initial Winsock hypothesis was
**refuted** — `restore_accepted_socket_blocking` is correctly applied to all three accept loops.)

- **B1a** — normalize at enforcement for `mtls:` subjects (reuse `normalize_cert_fingerprint`), or
  normalize at load (`main.rs:3352-3357`). **Prefer normalize-at-load** so the stored value and the
  runtime key are identical, and validation cannot pass a value enforcement will reject.
- **B1b** — promote the drop log from `debug!` to `warn!` including the **computed** fingerprint and the
  reason (`serve.rs:238/259`). `computed mtls:sha256:aabb… not in allowed_subjects` is a 30-second fix
  for an operator.
- **B1c** — raise or document the 1-second control ingress budget (`serve.rs:46`, `:649-653`); it is an
  independent second path to the same silent reset and makes `openssl s_client` probing impossible.
- **B1d** — confirm with the tester whether the *main* listener reset was real; no silent-drop path was
  found there (unregistered fingerprint → 403; operator-authority failure → typed response).

**Unblocks B4** (online credential revocation is reachable only through this listener).

#### B2 [P1] OAuth: document the contract, widen the diagnostic
*Field: P1-11. Annex §5.2. **Not a code defect** — the verifier is correct.*

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
*Field: P1-12. Annex §5.3. Pure discoverability failure.*

The path is `params._meta["oraclemcp/initToken"]` — the key contains a **slash**, is unguessable, and has
**zero documentation hits** anywhere. Decisive evidence it was never found: the tester always got
`Missing`, never `Mismatch`.

- Document the exact JSON path; put the literal path into the error text (`init_token.rs:36`); note that
  a non-string value also yields `Missing`.

#### B4 [P1] Credential lifecycle without downtime
*Field: P1-13. Annex §5.4. **Premise partly refuted** — the online route already exists.*

`/operator/v1/client-credentials/{list,rotate,revoke}` (`operator.rs:691-693`) is already implemented and
already tears down live sessions on mutation. It was unreachable **only because B1 blocked the control
listener**. → **Fix B1, document the endpoints, and A2b prints the right command.** No new machinery.

#### B5 [P1] Driver: terminal errors must not be retried — **verify, then close**
*Field: P1-3. Annex §6.5. **Believed already closed** by `880134e`, now on driver `main`.*

That commit made the failover boundary **stage-aware**: the post-configuration error type "deliberately
has no configuration/auth/wallet variants", and all deterministic TLS configuration is validated before
any transport attempt, so terminal errors are *structurally* unable to enter the retry loop.

- **Action:** reproduce the field symptom locally (§4.D TCPS lane) — a cert `UnknownIssuer` under stock
  `retry_count=20` must now surface in ~1s, not as `call timeout of 20000 ms exceeded`. Then **close
  driver bead `rust-oracledb-4sfc`** with landed evidence.
- **Do not re-implement.** This is the one finding where the plan's scope *shrinks*.

#### B6 [P1] Driver: trust the wallet **and** the platform roots
*Field: P1-2. **The one finding still ungrounded — annex §6.8.***

Field evidence is strong (copying a DigiCert Global Root G2 PEM into the wallet dir made an ADB endpoint
connect). **First task is to ground it**: confirm the rustls trust anchors are wallet-only, name the
site, and state the security argument for adding platform roots while keeping the wallet authoritative.
Then implement, and add a **DigiCert-signed ADB endpoint** to regression — today's lane only exercises
the self-signed-ADB-CA chain.

#### B7 [P1] Session teardown: stop leaking session records
*Field: P1-8. Annex §6.6. Confirmed: **no teardown counterpart exists**.*

Three connect-side hooks (`login_statements`, `login_script`, `trusted_session_statements`) have no
logoff counterpart anywhere in the codebase.

- **B7a** — add `logoff_statements` / `session_release_statements` executed before a pooled session is
  released and before process exit (including SIGTERM).
- **B7b** — ensure a **clean logical Oracle logoff** so `AFTER LOGOFF` triggers fire. Cross-check driver
  bead `rust-oracledb-s0se` (missing `close_notify`): if sessions end by abrupt transport close, the
  trigger never runs regardless of a hook — **both halves may be required**. Treat B7b and `s0se` as one
  investigation.

#### B8 [P1] Audit: doctor must stop lying
*Field: P1-9. Annex §6.7. **The audit design is correct and fail-closed** — doctor misreports it.*

No key + read-only-everywhere ⇒ `Ok(None)`, no auditor (and if writes *are* reachable without a key the
server **refuses to start**). Nothing that can mutate is silently unaudited.

- **B8a [P0-for-honesty]** — doctor must report `audit: DISABLED (no signing key configured; profile is
  read-only everywhere reachable)` instead of a check-mark plus a path for an auditor that was never
  constructed (`doctor.rs:396-404` reasons about paths without consulting `build_auditor`).
- **B8b** — document a concrete `[audit]` block; there is no example anywhere in the README.
- **B8c — product decision (operator):** should refusals be recorded on a local unsigned trail even when
  no writes are possible? The 15 blocked statements were exactly the evidence an operator would want,
  and "silently recording nothing is a weaker default than operators will assume."

#### B9 [P1] Proxy-auth syntax: accept or explain `user[schema]`
*Field: P1-1. Annex §6.4. Confirmed absent.*

Every Oracle client accepts `username = 'user[schema]'`; oraclemcp passes it through literally →
`ORA-01017`, indistinguishable from a wrong password. All 13 of the operator's real profiles used it, so
**nothing authenticated out of the box**. Detect `^(.+)\[(.+)\]$` at config load and either auto-desugar
into `[profiles.proxy_auth]` or fail fast naming the correct shape.

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
  `oracle_db_health`, `oracle_capabilities`. **Turn a wall into a redirect.**

#### B11 [P1] `oracle_orient` must be capped
*Field: P1-5.* Returns ~344 KB (~86k tokens) by default with **no `max_rows`/byte cap**, mostly INDEX
rows — on the tool named for agent orientation (`get_schema` ≈ 67 KB; `fleet=true` multiplies it). Apply
the capping `oracle_query` already has; default the schema projection to TABLE/VIEW/PACKAGE; return a
truncation marker plus a cursor.

#### B12 [P1] PL/SQL purity: make read-only functions reachable
*Field: P1-14. Annex §3. Fully by design today.*

`routine_purity` defaults to `Unknown` for **every** routine; Oracle purity metadata is **never**
consulted; there is no allowlist or knob. A signed custom tool wrapping a pure function is rejected on
classification grounds **and takes the server down** (`main.rs:3515-3522` → `ExitCode::from(2)`).

- **B12a** — operator-declared **pure-function allowlist** feeding a `SideEffectOracle` on
  `DEFAULT_CLASSIFIER`. This is the seam's intended use and needs no engine. **The guard stays
  tighten-only: an allowlist is operator authority, never an automatic inference.**
- **B12b** — pass the profile's **real ceiling** to custom-tool loading (`main.rs:1349/1357/1366`
  hard-code `ReadOnly`).
- **B12c** — decide whether one bad tool should remain fatal; a `--skip-invalid-tools` posture with loud
  reporting would have kept the field server running.
- **B12d [P2]** — consult Oracle purity metadata (`DETERMINISTIC`, `ALL_PROCEDURES`) as *evidence*
  feeding the oracle. Design carefully: `DETERMINISTIC` is a developer assertion, not a proof.

---

### Workstream C — Wire-contract fixtures (the anti-recurrence pillar)
*[P0 for the release's credibility. Cheap, entirely offline, no database.]*

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
- **C4** — **dashboard**: a real headless-browser form POST (Chromium already available in CI), asserting
  a 200 rather than a reset — the assertion `curl` structurally cannot make.
- **C5** — **session-setup ordering**: assert the built statement list for **each profile posture**
  (`protected = true` and `false`), catching A1b offline.
- **C6** — **CLI vs running server**: with a server running, assert `setup --write` and `clients revoke`
  produce specific actionable errors (catches A2a).
- **C7** — **`QueryPageBuilder` with zero rows** asserts `columns` is populated (catches A1c).
- **C8** — **blind-catalog mock**: policy probe returns empty *because of privilege*; assert refusal, not
  pass-through (catches A1a).

**Acceptance:** C1–C8 all fail against today's `main` and pass after Workstreams A/B. That two-sided
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
  object. This is what settles annex H1 vs H2 and validates A1a/A1e.
- **D4 — a privilege-matrix fixture**: a principal **without** `EXECUTE ON DBMS_FLASHBACK` (validates
  A3), and one without catalog visibility (validates A1a).
- **D5 — an idle-connection lane**: hold a pooled connection, kill it server-side, and assert recovery
  (validates A4, and settles whether the pinned session is pooled).
- **D6 — a local TCPS/TLS lane with synthetic wallets.** The driver already has synthetic-wallet + local
  rustls TCPS machinery — **reuse it**. Validates B5 (P1-3 symptom) and B6.
- **D7 — a session-lifecycle lane**: an `AFTER LOGOFF` trigger writing to a table, asserting sessions
  close logically (validates B7 and driver `s0se`).
- **D8 — doctor-style preflight**: refuse to run with a clear message if Docker/images/ports are missing.

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
- **E5** — **failure/recovery paths**: killed connections, refused optional features, expired elevation,
  revoked credentials mid-session.
- **E6** — emit **signed attestations** from e2e runs (ties to K1–K3 already landed) so an e2e result is
  evidence, not a claim.

Build on the existing `e2e_harness` and golden-artifact discipline rather than duplicating them.

---

### Workstream F — OCI Always-Free campaign (Cluster I)
*[P1. **Blocked on F0 — operator action.**]*

- **F0 — [OPERATOR] authenticate the OCI CLI on this machine.** `~/.oci/config` is absent; the API key
  (`~/.oci/oraclemcp_adb_api_key.pem`) and harness env (`~/.oci/oraclemcp-adb.env`) exist and `~/bin/oci`
  is installed. Nothing in Cluster I can start until `oci` can authenticate. **Everything else in this
  plan proceeds without it.**
- **F1 (bead `10.1`)** — Always-Free provisioning + **teardown-as-incident** harness. Teardown failure is
  treated as an incident, not a warning — an orphaned ADB is a cost event.
- **F2 (bead `10.2`)** — capability sweep: open, exercise the full tool surface, close.
- **F3 (bead `10.4`)** — wire the OCI e2e into a **Tier-3 operator-gated lane** (never automatic).
- **F4** — validate **B6** against a real DigiCert-signed ADB endpoint (the field's actual failure), not
  only the self-signed-ADB-CA chain.

**Hard constraint: zero-cost / Always-Free only** (constitution #10) — verified per-run via the
authoritative AVAILABLE=0 check before and after every run.

---

### Workstream G — Remaining beads

- **G1 [P1] `8.1` IAM subject-mapping config** (`he7t` residual) — last product gap from the OCI/IAM work.
- **G2 [P1] `5.2` D2 coverage ratchet** — changed-line coverage + per-crate mutation floor on
  guard/audit/db, per plan §32.2 TRI-1. Deliberately **not** a naive never-decrease total. Builds on the
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
- **G7 [P3] `12.3` K3** — wire attestation into coverage/mutation/invariant lanes (K1/K2 landed).
- **G8 [P3] `izk5`** — `doctor.rs` wallet-variant comments cite a stale `=0.7.4` driver.
- **G9 [P0-hygiene] `plan-bead-graph-lint-eshv`** — lint normalized plan-to-bead graphs before promotion.
  **Run it on this plan's own bead conversion (§10)** — it exists precisely for this moment.
- **G10** — driver `s0se` (close_notify) — merge into B7b as one investigation.
- **G11** — close the 11 epics once their children drain; Cluster B (`.3`) already has zero open children
  and is closable after review.

---

### Workstream H — Release train
*[Depends on: everything above. Bead `13`. **Operator-gated.**]*

See §7 for the version decision, §9 for the gate.

---

## 5. Sequencing and dependencies

```
        ┌─ C (wire-contract fixtures) ──────────────┐  offline, start immediately
        │                                            │
F0 (operator: OCI auth) ─────────────┐               ▼
        │                            │        A1..A5, B1..B12  ── fixes
        ▼                            │               │
   D (local environment) ────────────┼───────────────┤
        │                            │               ▼
        │                            └────────► E (cross-repo e2e)
        ▼                                            │
   F (OCI campaign, Cluster I) ──────────────────────┤
                                                     ▼
                              G (remaining beads) ─► H (release cut)
```

**Critical path:** `D → E → H`. **C is off the critical path and should start first** — it is offline,
cheap, and its failures define "done" for A/B. **F is parallel** and gated only on F0.

**Ordering rules:**
1. **C before A/B where possible** — write the failing fixture first, then fix. Two-sided proof.
2. **B1 before B4** — online revocation is unreachable until the control listener works.
3. **A1a is the single highest-priority code change** (fail-open in a fail-closed system).
4. **D3/D4/D5 before finalising A1/A3/A4** — they settle the open questions the annex flags.
5. **B5 is verify-then-close, not implement.**
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
- the **Python-MCP compatibility surface** (all 13 aliases) and **multi-profile exposure** (13 profiles)
- the **audit design's fail-closed refusal to start** when writes are reachable without a key

Add regression coverage for anything above that a planned change comes near.

---

## 7. Release-scope decision (needs an operator ruling)

Bead `13` specifies **strictly patch**: `cargo-semver-checks` must stay at patch, and if it flags minor
the change is reworked patch-safe or held — never silently bumped.

**Complication discovered today:** the driver's public source inventory went **908 → 915** items with the
stage-aware TLS work already on `main`. Added public API is *minor*-compatible, not patch.

**OPERATOR DECISION (2026-07-20): driver → `0.9.0`, server → `0.9.1`.**

- **Driver `0.8.4 → 0.9.0`** — a **minor** bump. This is the honest call: the stage-aware TLS work
  already on `main` grew the public source inventory 908 → 915, and this plan adds more (B6 platform
  trust anchors, B7 teardown hooks). A minor bump removes the incentive to contort real improvements
  into patch-safe shapes.
- **Server `0.9.0 → 0.9.1`** — `+0.0.1` as instructed.

**Consequences, and they are deliberate:**
1. Bead `13`'s original "STRICTLY patch, rework or hold if semver-checks flags minor" constraint is
   **superseded for the driver** by this ruling. It still applies to the **server**: if a server change
   forces a minor, it is reworked patch-safe or held — the server is `+0.0.1`.
2. `cargo-semver-checks` still runs on both, but its role changes: for the driver it **documents** the
   surface delta (and must show no *breaking* change — 0.9.0 is minor, not major); for the server it
   **gates**.
3. The server's `oracledb` dependency pin moves to `=0.9.0`; the release-surface sync check and the
   driver-version references (bead `izk5`, `doctor.rs` comments) must be updated in the same train.
4. **Any breaking change in the driver is out of scope.** 0.9.0 is additive-only. If something requires
   a break, it waits for 1.0 (the `road-to-1-0` line, still deferred).

---

## 8. Risks

| Risk | Mitigation |
|---|---|
| **A1a turns silent-empty into visible refusals** in deployments with restricted catalog visibility | Release-note it prominently; consider a one-release warn-then-refuse period |
| **A5 weakens a security surface** if `Origin: null` is accepted too broadly | Prefer option (a) `same-origin`; require a written security review; keep the one-time code as the authenticator |
| **B12a widens what the guard admits** | Operator-declared allowlist only; never automatic inference; guard stays tighten-only; audit every admitted routine |
| **The customer's VPD issue is H1 (a privilege difference), not our bug** | A1e ships value either way — visibility is the deliverable, not a remote diagnosis |
| **Local containers drift from the field's 19c** | The field DB is 19c; we have 18/21/23. Document the gap; do not claim 19c coverage we lack |
| **OCI cost** | Always-Free only, verified AVAILABLE=0 before and after each run; teardown-as-incident (F1) |
| **Scope is large for one release** | P0/P1 gate the cut; P2/P3 ship if clean. Land complete, not sliced (constitution #11) |
| **cosign/attest v4 majors** (from Dependabot #19) live on tag-only paths CI cannot exercise | The first release run is the only proof — watch it deliberately |

---

## 9. Definition of done

### 9.1 Pre-push gate (both repos) — mandatory, no partial gates
Learned twice this week the hard way (a ci.yml comment broke `release_surface_sync_check`; a stale
`docs/baseline` reddened the driver push):

**oraclemcp:** `cargo fmt --all -- --check` · `cargo clippy --workspace --all-targets -- -D warnings`
(+ the two `dashboard-bundle` invocations) · `cargo test --workspace` · `cargo deny check` ·
`check_entry_trace_contract.sh` · `ci_taxonomy.py --check` (+ crate-copy sync) ·
`release_surface_sync_check.sh` · honesty/provenance/concurrency lints ·
`check_bead_close_evidence.sh`.
**driver:** fmt · clippy · tests · **`scripts/gen_baseline.sh --check`** · `verify_required_local.py`.
Heavy builds go through `scripts/build_lease.sh` with a dedicated `CARGO_TARGET_DIR` (E1's guard
enforces this — it blocked the orchestrator's own build, correctly).

### 9.2 Release acceptance
1. All **P0** items closed or explicitly deferred **with an operator-recorded reason**.
2. **C1–C8** demonstrably failed before their fixes and pass after.
3. The **local environment (D)** reproduces D3–D7's finding classes and passes post-fix.
4. **E** green across all three container generations.
5. **F** green, or explicitly deferred if F0 does not happen.
6. Every bead closed carries **landed evidence** passing `check_bead_close_evidence.sh` with **0 hard
   findings** (the guard already rejected six different evidence defects this week — respect it).
7. **Both repos' front pages green** — measured as *every check-run on the HEAD commit*, not run
   conclusions (see `frontpage-green-mechanics`).
8. `cargo-semver-checks` result recorded and the version decision (§7) made on its evidence.
9. **The operator pushes the tag.** Agents never tag or publish.

---

## 10. Conversion to beads

Convert this plan with the beads workflow, then **run `plan-bead-graph-lint-eshv` (G9) on the result** —
it exists exactly for this. Requirements:
- every task self-contained (no need to re-read this plan), citing its annex `§` for `file:line`;
- dependency edges per §5, especially `C → A/B`, `B1 → B4`, `D → E → H`, `F0 → F`;
- each bead names its acceptance test, and for a fix bead, the fixture that must fail first;
- **no bead closes without landed evidence** (§9.2 item 6);
- Cluster J beads are **not** touched.

---

## Appendix — traceability

| Field finding | Plan item | Annex |
|---|---|---|
| P0-1 `setup --write` | A2 | §1 |
| P0-2 flashback quarantine | A3 | §6.1 |
| P0-3 dashboard | A5 | §6.2 |
| P0-4 VPD silent-empty | A1 | §2 |
| P0-5 idle connection | A4 | §6.3 |
| P1-1 proxy syntax | B9 | §6.4 |
| P1-2 wallet trust store | B6 | §6.8 (ungrounded) |
| P1-3 retry masking | B5 (verify+close) | §6.5 |
| P1-4 typo → security refusal | B10 | — |
| P1-5 `oracle_orient` size | B11 | — |
| P1-6 refusal names no alternative | B10 | — |
| P1-7 setup HTTP onboarding header | B10 | — |
| P1-8 session leak | B7 | §6.6 |
| P1-9 audit wrote nothing | B8 | §6.7 |
| P1-10 mTLS | B1 | §5.1 |
| P1-11 OAuth | B2 | §5.2 |
| P1-12 stdio token | B3 | §5.3 |
| P1-13 credential lifecycle | B4 | §5.4 |
| P1-14 PL/SQL purity | B12 | §3 |
| P2-1..P2-13 | B10 / G-tail | — |
