# PLAN — oraclemcp 0.9.1 / driver 0.9.0: field-hardening, self-sufficient testing, OCI

**Version:** v1 (pre-review). **Date:** 2026-07-20.
**Owner:** lead orchestrator. **Release is operator-gated** — agents never tag or publish.

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

**OCI: ✅ authenticated (2026-07-20).** `~/.oci/config` written against the existing API key; `oci iam
region list` returns 44 regions; **zero-cost baseline asserted — 0 Autonomous DBs** in both
the CI compartment and root. **Cluster I (Workstream F) is unblocked.** See §4.F0 for the two traps hit
(user-OCID-in-tenancy-field, and empty-list vs broken-query).

### 1.4 Field input
Round-3 field test against **0.9.0**: **5 P0 adoption blockers, 14 P1, 13 P2**, against a product whose
CI was fully green. Raw round is quarantined (`livesting-*/`, gitignored, constitution #9); the scrubbed code-level
grounding is **Appendix A**. **Grounding is complete for every finding except P1-2.**

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

---

## 4. Workstreams

Priority notation: **[P0]** blocks the release; **[P1]** should ship; **[P2]** ship if it lands cleanly.

### Workstream A — P0 adoption blockers

#### A1 [P0] Make row-level security visible; stop silent-empty reads
*Field: P0-4. §A.2.3, §2.4, §2.5, §2.7.*

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
  connection", which **no MCP client can do**.

#### A4 [P0] A pooled connection that dies while idle must be replaced
*Field: P0-5. §A.6.3 (corrected twice — read §A.6.3 before implementing).*

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
- **Open question for §4.D:** whether the *pinned* session (which `oracle_query` uses, §A.2.8) is
  pooled at all. If it is a single long-lived connection outside the pool, A4a is insufficient and it
  needs its own liveness/reconnect path. **Settle this in the local environment before implementing.**

#### A5 [P0] The dashboard must work in a browser
*Field: P0-3. §A.6.2.*

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
*Field: P1-10. §A.5.1. **Highest-value P1** — a headline 0.9.0 feature that cannot serve a request.*

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
  driver bead `rust-oracledb-4sfc`** with landed evidence.
- **Do not re-implement.** This is the one finding where the plan's scope *shrinks*.

#### B6 [P1] Driver: trust the wallet **and** the platform roots
*Field: P1-2. **The one finding still ungrounded — §A.6.8.***

Field evidence is strong (copying a DigiCert Global Root G2 PEM into the wallet dir made an ADB endpoint
connect). **First task is to ground it**: confirm the rustls trust anchors are wallet-only, name the
site, and state the security argument for adding platform roots while keeping the wallet authoritative.
Then implement, and add a **DigiCert-signed ADB endpoint** to regression — today's lane only exercises
the self-signed-ADB-CA chain.

#### B7 [P1] Session teardown: stop leaking session records
*Field: P1-8. §A.6.6. Confirmed: **no teardown counterpart exists**.*

Three connect-side hooks (`login_statements`, `login_script`, `trusted_session_statements`) have no
logoff counterpart anywhere in the codebase.

- **B7a** — add `logoff_statements` / `session_release_statements` executed before a pooled session is
  released and before process exit (including SIGTERM).
- **B7b** — ensure a **clean logical Oracle logoff** so `AFTER LOGOFF` triggers fire. Cross-check driver
  bead `rust-oracledb-s0se` (missing `close_notify`): if sessions end by abrupt transport close, the
  trigger never runs regardless of a hook — **both halves may be required**. Treat B7b and `s0se` as one
  investigation.

#### B8 [P1] Audit: doctor must stop lying
*Field: P1-9. §A.6.7. **The audit design is correct and fail-closed** — doctor misreports it.*

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
*Field: P1-1. §A.6.4. Confirmed absent.*

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
*Field: P1-14. §A.3. Fully by design today.*

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

  Remaining operator nicety (not blocking): `~/.oci/oraclemcp-adb.env` is still the unfilled template
  with `<...>` placeholders; `scripts/e2e/oci_adb_terraform.sh` sources it, so F1 will need it filled.
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
4. **D3/D4/D5 before finalising A1/A3/A4** — they settle the open questions Appendix A flags.
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

## 7. Release-scope decision (operator ruling recorded 2026-07-20)

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
- every task self-contained (no need to re-read this plan), citing its Appendix A `§` for `file:line`;
- dependency edges per §5, especially `C → A/B`, `B1 → B4`, `D → E → H`, `F0 → F`;
- each bead names its acceptance test, and for a fix bead, the fixture that must fail first;
- **no bead closes without landed evidence** (§9.2 item 6);
- Cluster J beads are **not** touched.

---


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

**Grounding is complete for every finding except P1-2** (§A.6.8).

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

### A.2.6 LATENT (ruled out for this round): CLIENT_IDENTIFIER clobber
`crates/oraclemcp-db/src/lease.rs:271-283` inverts the order — login statements (`:271-273`) then
`session_tag_statements` (`:281-283`), whose first element is `DBMS_SESSION.CLEAR_IDENTIFIER`
(`lease.rs:83-85`) followed by `SET_IDENTIFIER` (`:98`). `CLIENT_IDENTIFIER` is *the* canonical Oracle
key for pooled-application VPD.
**But `LeaseManager::acquire` has no production caller** — every call site is a test. Real latent bug;
not this field symptom. (Contrast the safe path: `apply_session_identity` runs *before*
`session_statements` — `connection.rs:1580` vs `:1584`.)

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

**TODO (not yet grounded):** confirm the driver's default `ping_interval_secs` value, and complete
P0-2 (flashback quarantine) grounding — specifically whether the capability probe happens **before**
the point of no return, and where a cleanly-refused optional feature becomes a discarded connection.

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

**Still open:** whether the *pinned* session (which `oracle_query` uses — see §A.2.8) is pooled at all,
or is a single long-lived connection with no validation path. That determines whether the checkout fix
alone is sufficient. Needs the local environment to settle.

### A.6.4 P1-1 `user[schema]` proxy syntax — VERIFIED absent
`crates/oraclemcp-core/src/connect.rs:84-101` requires an explicit `[profiles.proxy_auth]` block with
non-empty `proxy_user` and `target_schema`, and additionally requires `username` to **match**
`proxy_user` when both are set. **No `user[schema]` detection exists anywhere in config parsing** —
the string is passed through literally and Oracle answers `ORA-01017`, indistinguishable from a wrong
password.

**Fix:** detect `^(.+)\[(.+)\]$` at config load and either auto-desugar into `proxy_auth` or fail fast
naming the correct shape. Cheap, and it was the single reason none of the operator's real profiles
authenticated out of the box.

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
auditor that was **never constructed** — it reasons about paths (`doctor.rs:396-404`:
`legacy_audit_path`, `current_audit_path`, `audit_path_configured`) without knowing whether
`build_auditor` returned `Some`. That is a **gate that lies**, the class AGENTS.md forbids.

**Fix:** (a) doctor must report `audit: DISABLED (no signing key configured; profile is read-only
everywhere reachable)` instead of ✓-with-a-path; (b) document a concrete `[audit]` block (there is no
example anywhere in the README); (c) **product decision**: whether refusals should still be recorded
on a local unsigned trail even when no writes are possible — the tester's point that "silently
recording nothing is a weaker default than operators will assume" is fair, since the 15 refusals were
exactly the evidence an operator would want.

### A.6.8 P1-2 driver wallet-only trust store — NOT YET GROUNDED
The one item still unverified. Needs: confirmation that the rustls trust anchors are built from the
wallet only (platform roots excluded), the exact site in the driver's TLS/wallet path, and the minimal
change to add platform roots while keeping the wallet authoritative — plus the security argument for
doing so. The field fix (copying a DigiCert Global Root G2 PEM into the wallet dir as `ewallet.pem`)
made an ADB endpoint connect, which is strong evidence the claim is correct.

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
    set than it first appeared — mainly §A.2.7 (H1/H2 principal + catalog visibility), §A.6.3 (pinned vs
    pooled), §A.6.5 (P1-3 symptom), and §A.6.6 (logoff triggers).

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

---

# Appendix B — traceability

| Field finding | Plan item | Appendix A |
|---|---|---|
| P0-1 `setup --write` | A2 | §A.1 |
| P0-2 flashback quarantine | A3 | §A.6.1 |
| P0-3 dashboard | A5 | §A.6.2 |
| P0-4 VPD silent-empty | A1 | §A.2 |
| P0-5 idle connection | A4 | §A.6.3 |
| P1-1 proxy syntax | B9 | §A.6.4 |
| P1-2 wallet trust store | B6 | §A.6.8 (ungrounded) |
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
| P2-1..P2-13 | B10 / G-tail | — |
