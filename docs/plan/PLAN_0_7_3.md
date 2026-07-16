# PLAN 0.7.3 — "Autonomous-Everything": OCI, Parity, Hardening, Design

> **Cross-repo release plan** spanning `oracledb` (the pure-Rust thin driver, repo
> `rust-oracledb`) and `oraclemcp` (the governed Oracle MCP server). Both ship in
> lockstep as a content-heavy **+0.0.1 → 0.7.3** (semver-patch by our convention,
> "major again" in ambition). This is **not** 1.0 — the driver's Road-to-1.0 epic
> stays operator-gated.
>
> **Status:** DRAFT v11 (2026-07-06) — **STEADY-STATE + skill-hardened**. **v11: K9 redesigned to a
> structured `as_of` param (classifier untouched — removes the only safety-critical flag), and four
> skill lenses folded in — D6.6 optimization discipline (`extreme-software-optimization`: baseline→
> profile→isomorphism-proof→committed regression gate), D6.7 kani BMC on the classifier's safety helpers
> + audit chain (`lean-formal-feedback-loop`, tier-C), D6.8 pre-tag security audit (`codebase-audit`, gates the tag),
> and golden discipline (`testing-golden-artifacts`) folded into D6.3.** v8 added §D6 (quality/test-hardening) + A7/A8 from a `mock-code-finder` scan.
> v9 added **Part K** (`idea-wizard`, 11 accretive items). **v10 code-validated all of Part K** (3
> agents, every item grounded in `file:line`): re-tiered by real effort (K1/K7 → medium), and
> **surfaced + designed out two surprises** — K6's cassette-capture secret footgun (now a mandatory
> scrub+refuse gate) and K9's `sqlparser`-can't-parse-flashback (**resolved by a redesign — a structured
> `as_of` param on `oracle_query`; the classifier is never touched**) — and confirmed K10 is `x3s`-gated.
> Zero new deps across K. Grounded in: round-2
> field test + full bead/GitHub/cass inventory + code-validation passes (`file:line`,
> spot-checked 17/17 accurate) + **three review rounds** (R1 lenses/Appendix H, R2
> completeness+OMCP-deep-dive+bead-DAG/§D4+Appendix I, R3 consistency+red-team/§D5) +
> **four resolution spikes** (C1 wallet-gen tested live, XA already-shipped, A3.0 FFI
> not-a-risk, plsql-mcp consumer investigated). **Every open decision resolved** — F.2
> lockstep 0.7.3 · F.3 local pre-tag gate (§D3.2) · F.4 full differentiator set (only CQN out)
> · F.5 **XA already shipped/tested**, CQN deferred · F.6 **one theme (Carved Light + Vale)**
> · F.7/F.8 everything + plsql-routine · F.9 plsql-intelligence→0.7.1. Red-team risks R3/R5/R9
> resolved outright; R1/R6 are spec-complete (exact test + command given) — the code is their
> proof. Confidentiality (I1) locked. **Nothing left to discover at bead-time or implementation.**
> Ready to convert to beads (Appendix I); sprint leads with the §D5 gates (A2.2 first).

---

## 0. Governing principles (read first — they decide everything below)

### 0.1 The inclusion gate: autonomous testability
Operator directive: **fold in everything we can live-verify automatically and
autonomously in our own e2e / version-matrix tests — breadth does not matter, the
autonomous test is the price of admission.**

Concretely, a feature or fix is IN this release iff it satisfies **all** of:
1. It can be exercised end-to-end by an unattended `cargo test` / `scripts/*` run
   against resources we control (the gvenzl Oracle Docker lanes 18c/21c/23ai, a
   local TCPS listener, synthetic fixtures) — no human in the loop, no licensed
   Oracle feature, no external cloud dependency at CI time.
2. Its test is deterministic (or made deterministic via cassette/seeded replay).
3. It carries **no confidential data** (see §0.2).

Anything that *cannot* be autonomously tested today is **either** (a) deferred with
a one-line reason, **or** (b) preceded by a task that *builds* the missing
autonomous test harness first (this is exactly what we do for OCI — see Part C).

### 0.2 Confidentiality invariant (HARD — never violate)
The round-2 field test ran against a real, confidential customer environment. Its
identifiers (hostnames, DB/service names, schema/user names, proxy identities,
wallet OCIDs, IP ranges, the field-notes files themselves) are **highly
confidential** and must never appear in any committed artifact — not in code,
tests, cassettes, fixtures, beads, commit messages, docs, or this plan.

- `/todelete/` (round-2 + round-1 field notes) is gitignored (`.gitignore:55`),
  untracked, and must stay that way. Do not `git add` it. Do not copy its
  identifiers anywhere.
- **All** OCI autonomous tests use synthetic, self-generated, throwaway wallets /
  certs / tokens with fictional DNs and throwaway passwords (see Part C).
- The confidential ADB may be used by the operator for a **final manual smoke**
  only, out-of-band, never captured into a committed artifact.
- **New CI lint (C4):** a `scripts/secret_scan.sh` that greps the whole tracked
  tree for the forbidden token patterns and fails the build if any appear. This
  operationalizes the rule so a future agent physically cannot leak them.

### 0.3 Cross-repo ordering and the release gate
`oraclemcp` pins `oracledb` at an exact `=0.7.3`. Therefore:
1. **Driver first.** `oracledb 0.7.3` is developed, matrix-gated, and published.
2. **Server adopts.** `oraclemcp 0.7.3` bumps the exact pin, adopts the new driver
   surface through the single driver-seam file (`oraclemcp-db/src/connection.rs`),
   and builds the server-side features on top.
3. **Driver release gate (unchanged):** a green full version-matrix artifact
   (`tests/artifacts/version_matrix/results-<sha>.json`) must be committed for the
   release SHA; `release_matrix_gate.sh` + `release_preflight.sh` enforce it.

### 0.4 Non-negotiable invariants carried from both AGENTS.md / memory
- **Fail-closed guard may only ever be TIGHTENED, never loosened.** Every new
  execution/recovery/apply path re-classifies and re-checks at the point of action
  (SEC-1); a stored verdict is never an authorization input.
- `#![forbid(unsafe_code)]` in every published crate (driver + server). No `unsafe`.
- Pure-Rust only; no C toolchain, no Instant Client, no bundled SQLite/rusqlite.
- Files-first persistence; append-only audit hash-chain; no database.
- Driver adapter confined to the single seam file; `oraclemcp_driver_seam_lint.sh`
  stays green.
- No compat shims / v2 clones; migrate callers and delete old code.
- Every code change: `fmt`, `clippy -D warnings`, `cargo deny`, api-lock /
  public-api baseline regen, goldens byte-identical where applicable.

---

## 1. Where we are (grounded baseline, 2026-07-06)

### 1.1 `oracledb` (driver) — 0.7.2, effectively 1.0.0-rc.1
- Pure-Rust thin TNS/TTC driver; passes **2462/2578** of python-oracledb's own
  thin-mode suite (116 skips all proven forced by thin-mode contract, 0 hiding a
  defect, 0 regressions). API frozen, conformance clean.
- 20 cargo-fuzz targets, differential fuzz oracle vs python-oracledb, BoundedReader
  OOM-closed by construction.
- Version-matrix gate live: xe11 (refusal lane) / xe18 / xe21 / free23.
- Wallet crypto: `cwallet.sso`, modern `ewallet.p12` (PBES2/PBKDF2/AES-CBC),
  encrypted/plain `ewallet.pem` all ship in **every** build (the `experimental`
  gate is now a no-op). **Legacy 3DES PKCS12 (OID 1.2.840.113549.1.12.1.3) fails
  closed** — this is the real OCI gap.
- IAM: pre-supplied token path (`with_access_token`, TCPS-guarded) implemented;
  request-signing (`cco`) reverted over RSA Marvin (RUSTSEC-2023-0071).
- Road-to-1.0 epic (`llv`, Waves 0–4) cut to rc.1; publish gated on `vm2f`
  ("oraclemcp production validation") — which round-2 just delivered live on the
  real 19c fleet. **We deliberately do not cut 1.0 this cycle.**

### 1.2 `oraclemcp` (server) — 0.7.2
- 8-crate engine-free DAG + binary + embedded React dashboard (`web/`).
  error → telemetry/audit → guard → config/db → auth → core → binary.
- Fail-closed classifier proven airtight in round-2: **12/12 adversarial writes
  blocked against a DBA-privileged account, legit reads pass** — the core safety
  claim is real.
- P0 pre-23ai TTC handshake **fixed and proven live on the real 19c fleet**
  (`ORA-01017` reached = full handshake + auth path works).
- Open trackers: 1 ready bead (`demonolith-http-qyqs`, split the 11.5k-LOC
  `http.rs`), 1 GitHub issue (#6 doctor trio-stack provenance), 13 deferred `k6q`
  beads + a few `060` UX deferrals (3D Orrery `f4xo.8.15`, TUI `8.22`, operator
  UDS `6.9`).

### 1.3 The round-2 field-test punch list (this release's raw material)
> Note: these round-2 dashboard findings labelled **D1/D3/D4/D5** (D = *dashboard/HTTP*, from the
> field notes; D2 was retracted) are **distinct from** the Part-D sections **§D1–§D6** (D = the
> plan part). The server fixes for them live in B3.
| Ref | Severity | Finding | Owner |
|---|---|---|---|
| OCI-1 | HIGH | Stock OCI ADB wallet won't connect on default build — **legacy-3DES PKCS12** key rejected; `cwallet.sso` auto-login not preferred/verified against real OCI-console wallets. python-oracledb connects via `cwallet.sso`. | driver → server |
| OCI-2 | NIT | `tnsnames.ora` alias not resolved via `TNS_ADMIN` (full descriptor worked). | server |
| D1 | HIGH (UX) | `om dashboard` prints a live-looking pairing URL when **no HTTP service is running** → "can't reach this page". | server |
| D3 | BUG | `ORACLEMCP_HTTP_ALLOW_REMOTE=1` is **broken** — the `ORACLEMCP_*` config-override parser rejects it as an unknown field, so non-loopback bind is currently impossible; no `[http] allow_remote` file equivalent exists. | server |
| D4 | ROBUSTNESS | Stale `service-instance.json` lock (dead pid) blocks `serve --listen` restart after kill/SIGTERM. | server |
| D5 | NOTE | `/readyz` returns 503 without a live DB (correct, document it). | server |
| GH#14 | HIGH | Driver connect ignores parsed `EXPIRE_TIME` (keepalive) + `TRANSPORT/TCP_CONNECT_TIMEOUT`; no read-inactivity deadline → **half-open/idle connections hang forever** (reported downstream in this stack). | driver |

---

## PART A — DRIVER (`oracledb` 0.7.3)

> Sequencing within Part A (see the §D1 DAG): **Part C (OCI harness) + A1 (hardening) start
> first**; **A4 Tier-1 differentiators run in parallel from day 1** (fully offline, no
> C-dependency); A2/A3 (OCI features) ride on C; A4 Tier-2 needs live lanes; A5 (matrix gate)
> is last before publish.

### A1. Stability & hardening (production bugs first)

#### A1.1 — GH#14: connect/idle timeouts + TCP keepalive  ·  HIGH  ·  effort M
**Problem.** The driver hardcodes a 20s connect timeout and has **no read-inactivity
deadline**; `EXPIRE_TIME` / `TRANSPORT_CONNECT_TIMEOUT` are parsed but never used in
the driver layer. A half-open/idle server parks a future in `read_exact` forever
(CLOSE_WAIT, no error surface) — reported downstream in this stack.
**Change sites (cited).**
- `crates/oracledb/src/lib.rs:9390` — `transport_connect_timeout_duration()` hardcodes
  `20.0` (test pin `lib.rs:10007`).
- `crates/oracledb/src/lib.rs:2420` — `TcpStream::connect_timeout(...)` application point.
- `crates/oracledb/src/lib.rs:9247` & `:9264` — `receive_packet` header/payload
  `read_exact` with **no deadline** (the hang).
- `crates/oracledb/src/lib.rs:1709-1773` — `ConnectOptions` struct: **no** timeout
  fields; `new()` initializers at `:1808-1835`.
- `EXPIRE_TIME` parsed at `oracledb-protocol/.../connectstring/{easy_connect.rs:496,
  builders.rs:190, mod.rs:256}` — **zero** uses in the driver (verified).
**Change.** Add additive `ConnectOptions.connect_timeout: Option<Duration>` +
`inactivity_timeout: Option<Duration>` + `with_connect_timeout` / `with_inactivity_timeout`;
thread `connect_timeout` into `:9390`/`:2420`; wrap `:9247`/`:9264` reads in
`time::timeout(remaining_deadline, …)` → structured `Error` (retryable/
connection-lost classified); set `SO_KEEPALIVE` (+ interval from `EXPIRE_TIME`) on the
socket in `transport.rs` after creation.
**Autonomous test.** A local TCP listener with three modes — (a) accept-then-stall,
(b) half-open (accept, partial send, silence), (c) never-accept — asserts each returns
the right structured error within the deadline; `getsockopt` asserts keepalive is set.
No Oracle. **Deps:** none. Unblocks server B1 timeout config surface.

#### A1.2 — Finish `p5h` (in progress)  ·  P2  ·  autonomous
Property-based FromSql/ToSql round-trip: metamorphic `encode→decode == v`;
precision-loss lossiness proofs. Pure/offline. **Deps:** none.

#### A1.3 — Verify-and-close stale bug beads  ·  P3  ·  autonomous
`ezxs` (AQ RAW/JSON dequeue truncation) and `ygws` (SODA mixed-case quoting) were
fixed in the E8 campaign but never closed. **Re-verify** each with a regression test
on the matrix; close only on green. Do not assume-close.

#### A1.4 — forbid-unsafe / Miri / fuzz sweep  ·  P2  ·  autonomous
Run the UB/unsafe audit lane; extend the 20-target fuzz corpus toward every new A4
decode surface (VECTOR columnar, streaming framing, LOB streaming); keep the
python-oracledb differential oracle green. **Deps:** A4 items land their surfaces first.

### A2. OCI wallet — close the field-test gap (driver-owned)

#### A2.1 — Legacy 3DES PKCS12 decryption  ·  HIGH  ·  effort M (~220 LoC)
**Problem.** The stock OCI-console ADB wallet's key uses `pbeWithSHAAnd3-KeyTripleDES-CBC`
(OID `1.2.840.113549.1.12.1.3`); the driver fail-closes on it.
**Change sites (cited).** Rejection at `oracledb-protocol/src/tls/pfx.rs:256` in
`derive_pbes2()` (only `OID_PBES2` accepted; error type `WalletError::Pkcs12`). All
supporting plumbing already exists: PBKDF2 (`pfx.rs:283-318`), AES-CBC decrypt
(`aes_cbc_decrypt` `pfx.rs:398`), PRF SHA1/SHA256. RustCrypto deps present: `aes`,
`cbc`, `pbkdf2`, `hmac`, `sha1`, `sha2`, `der`. **Only missing:** the `des` crate.
**Change.** Add `des = "0.7"` to the workspace `Cargo.toml`; in `derive_pbes2()` accept
OID `…12.1.3` → route to a new `pbes1_derive_3des()` (PKCS#12 PBE KDF, SHA1 implicit,
salt+iterations, no PRF); generalize `aes_cbc_decrypt` → `symmetric_cbc_decrypt(oid,
key,iv,ct)` with a 3DES (24-byte key) arm. Keep fail-closed + the exemplary typed error
for anything still unsupported (RC2, scrypt).
**Autonomous test.** Part-C synthetic `ewallet_3des_openssl.p12` (the exact `…12.1.3` shape):
assert pre-support → `Pkcs12` error naming the OID; post-support → decrypts to the
expected key/cert. Offline. (The sso-fallthrough scenario is A2.2, using the *existing* real
`cwallet.sso` fixture.)

#### A2.2 — `cwallet.sso` fallthrough (THE day-one linchpin)  ·  HIGH  ·  effort S
> All three reviews flagged this as the make-or-break item for day-one OCI. It is
> **not** just preference tuning — it is the exact round-2 failure and must be coded
> and tested against the exact field scenario.

**Reality (validated).** Selection order at `crates/oracledb/src/tls.rs:366`
(`load_wallet`: pem → p12+pw → cwallet.sso → typed error) with tests at `tls.rs:616`/`:631`.
SSO parse at `sso.rs:200`. **But there is NO fallthrough:** if the higher-precedence pem
(`:373`) or p12 (`:377`) fails to *decrypt*, `load_wallet` returns the error immediately —
it never tries the `cwallet.sso` that would have worked. **This is precisely the round-2
failure:** an `ewallet.pem` with a legacy-3DES key was tried first, failed, and the valid
`cwallet.sso` was never reached. python-oracledb sidesteps this by using `cwallet.sso`.
**Change.**
- (a) Add/confirm a typed `WalletError::UnsupportedCipher` (distinct from
  `PasswordRequired`/`KeyDecrypt`) so the caller can distinguish "can't decrypt this
  wallet" from "wrong input".
- (b) In `load_wallet`, when a higher-precedence wallet is **undecryptable** (unsupported
  cipher **or** wrong password) **and** a valid `cwallet.sso` auto-login exists in the dir,
  **fall through to the SSO wallet** instead of returning the error. Make this an explicit,
  documented, tested policy.
- (c) Use the **existing real committed `cwallet.sso` fixture** (orapki is absent, so we don't
  generate a new one — see C1); if a real OCI-console `cwallet.sso` sample is later available,
  add it as an extra fixture.
**Deps:** C1 (fixtures), A2.1 (so 3DES p12 is *also* directly usable).
**Autonomous tests (must reproduce the exact field pattern).**
- **Positive:** a wallet dir with a legacy-3DES `ewallet.pem` (undecryptable) **and** the
  existing real `cwallet.sso` → `load_wallet` succeeds via the SSO fallthrough (the round-2 repro).
- **Negative (no masking):** a dir with **only** an undecryptable pem (no sso) → the
  original typed error is **preserved**, not swallowed.

#### A2.3 — Autonomous validation
Offline wallet-parse tests over the Part-C synthetic matrix (modern PBES2 p12,
legacy-3DES p12, cwallet.sso auto-login + OCI-variant, encrypted/plain pem) + an
end-to-end TCPS handshake (Part-C local rustls lane) using a synthetic wallet. Zero
secrets, zero real ADB.

### A3. OCI IAM token source seam  ·  P2  ·  effort M (~150 LoC)
**Reality (validated).** Static token path exists: `AccessToken(String)`
(`lib.rs:1531`), `with_access_token` (`lib.rs:1908`), wired as `AUTH_TOKEN` via
`build_fast_auth_token_payload` (`lib.rs:2648`, never traced). Guards:
`Error::AccessTokenRequiresTcps` over plain TCP (`lib.rs:2636`) **and**
`Error::FastAuthRequired` — so **token auth requires TCPS + fast-auth (23ai+)**. No
pluggable/refreshable source exists.
**A3.0 — FFI feasibility: RESOLVED (spike investigated, dropped as unnecessary).** The
red-team's "async-trait-across-FFI" worry (R3) is **not a real risk**: `oracledb-pyshim` never
exposes a token parameter and **Python never implements `TokenSource`** — only the Rust caller
(oraclemcp) does. `Arc<dyn TokenSource>` is `Clone`-safe (refcount bump) so `ConnectOptions`
`#[derive(Clone)]` (`lib.rs:1708`) + pyshim's `options.clone()` (`conn.rs:1208/361`) are
unchanged; `get_token().await` runs inside the spawned OS thread (`async_bridge.rs:195`) with no
Python on the stack. **No pyshim change; no spike; build A3 directly.**
**Change (exact, from the spike).** Add:
```rust
pub trait TokenSource: Send + Sync {
    fn get_token(&self) -> Pin<Box<dyn Future<Output = Result<String, TokenSourceError>> + Send + '_>>;
}
#[derive(Clone)] #[non_exhaustive]
pub enum TokenSourceError { Exec(String), Invalid(String), Timeout(String), Other(String) }
// Debug/Display for TokenSourceError are REDACTED (never print the token).
```
+ `ConnectOptions.token_source: Option<Arc<dyn TokenSource>>` + `with_token_source(src)` (sets
`auth_mode = IamToken`); in the auth flow (`lib.rs:2632`) prefer `token_source.get_token().await?`
over the static `access_token` (static wins if both set). No OCI SDK dependency — the caller
(oraclemcp B2.2) supplies it. Keeps the `AccessTokenRequiresTcps` + `FastAuthRequired` guards.
**Autonomous tests.** (1) A mock `TokenSource` returns a throwaway JWT-shaped token: assert
it is sent as `AUTH_TOKEN` over the Part-C C2 TCPS lane. (2) **New driver-layer test:** a
token over plain TCP is **refused** (`Error::AccessTokenRequiresTcps`) — the reviewers noted
this fail-closed check is tested at the *server* layer but not the *driver* layer. No
request-signing (RSA Marvin — keep `rsa-marvin-revisit-hlgd` open). **Deps:** C2/C3 (no A3.0 — dropped).

### A4. "Beat python-oracledb" differentiators (fold in all autonomously-testable)
Every item = implement + an autonomous e2e test. Byte-identical-to-reference where a
reference path exists; perf items revert if they don't measure; correctness items
diverge-checked. Grouped by testability (validated per bead).

**Tier-1 — fully autonomous, no live server (cassette / loopback / proptest / alloc-count):**
| Bead | P | Feature | Autonomous test |
|---|---|---|---|
| `x3s` | 1 | Async streaming row `Stream` / lending iterator over borrowed batches; constant memory + backpressure | 300k-row fetch under an allocation/peak-RSS bound; rows byte-identical to `collect`; cancel-mid-stream leaves clean conn (negative control) |
| `j1w` | 1 | Pipelined `executemany` `BatchWriter` + typed `Vec<BatchError>` continuation | seeded batch DML w/ deliberate mid-batch errors; assert continuation + per-row error map + rollback |
| `0mk` | 1 | Columnar VECTOR fast path → Arrow `FixedSizeList` (f32/i8 contiguous) | VECTOR round-trip; byte-identical to row path; Arrow schema asserted (loopback/cassette) |
| `1s2` | 1 | Cassette-replay deterministic CI — replay reference suite offline, zero container | CI job replays committed cassettes green (force-multiplier for all autonomous testing) |
| `cn4` | 2 | OOB instant query cancel (true out-of-band break) | long op → cancel → fast break + clean reuse; negative control no-cancel (loopback seam) |
| `8pp`+`dgi` | 2 | Cross-connection statement-shape cache + invalidation under concurrent DDL (self-heal) | prepared reuse across conns while concurrent DDL changes shape; assert self-heal, no stale decode |
| `8eo` | 3 | Per-connection encode/decode scratch arenas (bind-buffer pooling) | microbench win + byte-identical wire; revert if no measured win |
| `p5h` | 2 | (see A1.2) proptest FromSql/ToSql | metamorphic round-trip |
| `plsql-routine-call-api-ycih` | 2 | High-level PL/SQL routine call API in the **driver** (`oracledb`: `RoutineBind`/`RoutineCall`, OUT/IN OUT/return) — GH#13. **Note:** `oraclemcp-db` already ships `call_routine` over the driver's `execute_raw` (`connection.rs:3798`); this makes it a *driver-native* API so oraclemcp-db's wrapper becomes a thin pass-through (API-completeness, not a blocker) | async+blocking mirrors, typed unsupported-value errors, loopback + live return/OUT/IN-OUT |

**Tier-2 — needs a live matrix lane (record→replay or direct):**
| Bead | P | Feature | Autonomous test | Lane |
|---|---|---|---|---|
| `h74` | 2 | Thin-mode SODA breadth | reference `test_3300`/`test_3400` pass **unskipped** | free23 (21c+); xe21 |
| `soda-pre21c-ap87` | 2 | Gate SODA on <21c with proof (18c lacks `JSON_SERIALIZE`/`USER_SODA_COLLECTIONS`) | assert `live_soda` gated + documented, never silently skipped | xe18 |
| `bbx` | 3 | Lazy LOB streaming reader/writer (AsyncRead/AsyncWrite); BLOB v1 (+ CLOB UTF-16 boundary) | large BLOB stream round-trip; CLOB boundary-split codepoint test | xe21/free23 |
| `r9a` | 3 | Retry executor over ORA taxonomy + idempotency gating | idempotency-gating logic unit-tested; retry-on-transient via server-side session kill | all (unit+live) |
| `nnnz` | 3 | L2 post-auth cassettes beyond typed query → LOB/AQ/DPL (record on free23, replay offline) | per-version offline replay, secret-scanned | record free23 → offline |

**ASSESSED — dispositions (each item's fate + reason):**
- **CQN / `conn.subscribe()`** — **DEFERRED**: server-push change notification; no deterministic
  autonomous harness; transitively blocks one AQ test (`test_2720`). The only differentiator that
  fails the autonomous-test gate.
- **XA / TPC** — **already fully shipped + tested** (34 reference tests, 3-version matrix,
  golden wire; pre-23ai fixed 0.7.2/`hkwd`). NOT deferred — see §F.5. Optional Rust-native
  discoverability test only.
- **Named-region `TIMESTAMP WITH TIME ZONE`** — inherited thin-protocol limit; track
  `mwu` (python-oracledb #592 / ORA-24964).
- **`qm4` typed AuthMode** (Kerberos/RADIUS placeholders → `UnsupportedAuthMode`) — ship
  the typed surface only if trivially unit-testable; real backends stay post-1.0 (`bpsh`).

### A5. Version matrix + release gate extensions
- **A5.1** Extend `examples/matrix_full.rs` + `version_matrix.sh full` so each new
  A4 capability is value-asserted per generation (VECTOR/SODA on 23ai/21c;
  streaming/executemany/LOB/cancel/retry across 18c/21c/23ai).
- **A5.2** Add the **OCI TCPS lane** (Part C: local TLS listener + synthetic
  wallet) to the matrix so wallet + DN-match + token paths are exercised
  autonomously and secret-free.
- **A5.3** `release_matrix_gate.sh` produces the green `results-<sha>.json` for the
  release SHA; `release_preflight.sh` rejects a tag without it.

### A6. `oracledb::VERSION` public const  ·  P3  ·  effort XS
Add/verify a public `pub const VERSION: &str` in the driver (needed by server doctor
#6 B5 to report the *real* driver version, not `env!` of the wrong crate). Autonomous
test asserts it equals the crate version. **Deps:** none.

### A7. Close the pyshim conformance edges (`p5o`)  ·  P2  ·  effort M
**Found by the mock-code scan.** `oracledb-pyshim` (the PyO3 harness that drives python-oracledb's
own suite) has **6–10 `not_implemented` shim edges** (tracked bead `p5o`, listed in
`docs/RELEASE_CERTIFICATION.md`): cursor-in-cursor value conversion (`convert.rs:1325`), LOB value
conversion (`:1343`), DbObject value conversion (`:1379`), object DML `RETURNING` projection
metadata (`var.rs:936`), quoted-identifier edge (`pyutil.rs:229`), persistent-LOB write
(`lob.rs:206`). These are **not** in the published crates, but each is a spot where a reference
test can't be driven → a forced skip. **Change:** route each edge through the `oracledb` crate
(the shim help-text already says "M1+ must route this through the oracledb crate"). **Why it
matters:** tightens conformance — fewer forced skips in the 2578-test suite (moves items out of
the 116). **Autonomous test:** the corresponding reference tests pass **unskipped**; add each to
the parity-coverage gate. **Deps:** none. *(Fail-closed catch-alls for `#[non_exhaustive]` enum
variants are intentional — do NOT "complete" those.)*

### A8. Enable pipelining (built-but-flagged-off)  ·  P2  ·  effort M
**Found by the mock-code scan.** Pipelining (execute a batch of N independent statements in **one**
round trip) is **implemented on the wire but disabled**: `supports_pipelining()` (`lib.rs:2877`)
returns `self.supports_end_of_response` and the sequential runner is forced pending the **per-op
result-materialization (buffering) layer** (per `RELEASE_CERTIFICATION.md:77`). It's a genuine
"beat python-oracledb" differentiator (README already advertises it) sitting dormant. **Change:**
wire the per-op result buffering so pipelining actually engages when the server supports it.
**Autonomous test:** a 10-statement batch collapses to **1 round trip** (assert round-trip count
via a counting transport / cassette), results byte-identical to sequential; GIL-free concurrent
batches don't serialize. Fits A4's differentiator theme. **Deps:** none (independent driver feature);
**A5 then adds a pipelining value-assert on free23** (so `A5-matrix` deps A8, not the reverse).
*(This is a real feature-enable, not a stub-completion — the code exists.)*

### G-CONSUMER. Downstream `plsql-mcp` consumer wiring (cross-repo)  ·  operator-requested
**Reality (investigated):** `plsql-mcp` lives at **`plsql-intelligence/crates/plsql-mcp`** and
reaches Oracle via the shared `oraclemcp-db` seam. It currently **hand-rolls PL/SQL blocks over
`conn.execute`/`conn.query_rows`** with positional binds (no typed OUT/IN-OUT/return). The
high-level `call_routine` (+`OracleRoutineArg`/`ExecuteOutcome`) **already exists in
`oraclemcp-db`** — so the consumer can adopt it directly.
- **The task:** swap plsql-mcp's hand-rolled routine calls onto `oraclemcp-db::call_routine`;
  bump its `oraclemcp-db`/`oracledb` pins to `=0.7.3`; add its own autonomous test (loopback +
  a live PL/SQL routine call with return/OUT/IN-OUT binds). Internal-only change → **plsql-intelligence
  bumps to `0.7.1`** (F.9), MCP tool surface unchanged.
- **Repo boundary:** lands in **`plsql-intelligence`** (its own `.beads` tracker), sequenced
  *after* the oraclemcp 0.7.3 publish. Never touches oraclemcp's agent surface (`honesty_grep`
  keeps `call_routine` adapter-internal). **Deps:** the published `oraclemcp-db` 0.7.3 (which
  already carries `call_routine`); optionally A4 `plsql-routine` if adopting the *driver-native*
  API instead. Sequenced after the oraclemcp 0.7.3 publish (§B1).

---

## PART B — SERVER (`oraclemcp` 0.7.3)

### B1. Adopt driver 0.7.3  ·  effort S
Bump `oracledb`/`oracledb-protocol` `=0.7.2` → `=0.7.3` in the single driver seam
(`oraclemcp-db/src/connection.rs`); update `pin_is_0_7_x_and_seam_intact` + Cargo.lock.
Surface the GH#14 driver knobs as validated `[profiles.*]` fields
(connect/read-inactivity timeouts + keepalive/`EXPIRE_TIME`), safe defaults, reported
by `doctor`. Closes the GH#14 class at the server. **Deps:** A1.1, A5 (driver published).

### B2. OCI end-to-end (server) — unblocks `k6q.9`
- **B2.1 — Adopt driver wallet fixes.** A stock OCI ADB wallet connects end-to-end;
  update the `doctor` wallet truth-table (legacy-3DES `ewallet.p12` + `cwallet.sso`
  now supported). Closes round-2 OCI-1. **Change site:** wallet posture in the doctor
  write-posture check (`doctor.rs`), driver hand-off in `connection.rs`. **Deps:** A2.
- **B2.2 — IAM token source (unblock `k6q.9`).** The "upstream-blocked" note is **stale**
  (`with_access_token` exists). **Reality:** a server-side `IamTokenSource` trait already
  exists (`oraclemcp-db/src/oci.rs:282`, `fn fetch(&self) -> Result<IamToken, OciError>`) —
  pure/safe; only production impls are missing. **Change sites (cited):**
  `connection.rs:687-714` (IAM validation), `:733-734` (`with_access_token` wire), tests
  `:4473-4512`. Add `[profiles.oci] use_iam_token` + token-source impls (env / file /
  OCI-CLI exec) → driver A3 `with_token_source`; keep non-TCPS refusal green.
  **⚠ SECURITY (from review — the exec impl is a command-injection surface):** the exec
  variant MUST use `std::process::Command` with an **argument array** (never `sh -c` / a
  shell string); **validate** the returned token (trim, JWT/JSON shape, max length);
  **fail closed** if exec fails or returns garbage (never fall back to plaintext auth); and
  **fuzz** the token-source boundary with malformed responses. **Ship as beta:** the
  autonomous mock-token wire/refusal tests are the gate; real-cloud OCI-IAM acceptance is
  an operator smoke (no CI cloud creds). **Deps:** A3, C3.
- **B2.3 — OCI-2: `TNS_ADMIN` alias resolution.** **Change site (cited):**
  `oraclemcp-db/src/oci.rs:150-157` (`AdbConnectInfo.alias`), `:206-216` (bare alias
  detected but **not resolved**). Add `tns_admin_lookup(alias)` reading
  `TNS_ADMIN`/profile `tns_admin` → `tnsnames.ora`; structured error if dir/alias
  missing. So `connect_string = "<alias>"` works like Instant-Client. **Deps:** none.
- **B2.4 — Autonomous test.** Server-level OCI connect against the Part-C C2 lane
  (synthetic wallet, secret-free). Operator does the real-ADB smoke out-of-band.

### B3. Dashboard / HTTP hardening (round-2 D-findings)
- **B3.1 — D1 (dead pairing URL).** **Change sites (cited):** `main.rs:3026-3050`
  (`run_dashboard_cmd` → `mint_dashboard_pairing_ticket` at
  `dashboard_auth.rs:278-327`, minted unconditionally), `--url` at `main.rs:200-206`.
  Insert a HEAD/GET probe of `--url` (short timeout) before minting; if nothing
  answers, refuse with an actionable message ("no oraclemcp HTTP service at … — start
  it with `service install` / `serve --listen …`") and **do not persist a ticket**. Test.
- **B3.2 — D3 (`ORACLEMCP_HTTP_ALLOW_REMOTE` broken).** **Root cause (cited):** the env
  var is read directly at serve time (`main.rs:2640-2642`) and gates the bind
  (`:2996-3010`), but the generic Figment `ORACLEMCP_*` parser rejects it as an unknown
  key (`oraclemcp-config/lib.rs:600-606` merge; `:43-75` `IGNORED_ENV_KEYS`; `:240-284`
  `HttpConfig`). **Fix (preferred):** add a first-class `[http] allow_remote: bool`
  field to `HttpConfig` (default false) + accept the env alias (add to
  `IGNORED_ENV_KEYS` so Figment stops rejecting it). Test: non-loopback bind succeeds
  only when set, fails closed otherwise. **Deps:** none.
- **B3.3 — D4 (stale service lock).** **Change sites (cited):**
  `service_lifecycle.rs:212-218` (metadata carries `pid`), `:1600-1640` (AlreadyExists
  refusal → `ORACLEMCP_SERVICE_ALREADY_RUNNING`), `:1691-1722`
  (`discover_service_instance_at`). Add a pid-liveness check after discovery; if the
  recorded pid is dead, auto-clear the stale lock (or `service --clear-lock`), keep
  printing the lock path. Test both SIGKILL and clean-SIGTERM leave-behind. **Deps:** none.
- **B3.4 — D5.** Document `/readyz` 503-without-live-DB semantics in
  `docs/operations.md` (no code change).

### B4. Design & UX — implement the **OMCP Operator Console** design system
> **Input received:** the operator's Fable/Claude-Design export
> (`todelete/Claude_design.zip`, gitignored, confidentiality-scanned clean) is the
> **OMCP Operator Console** — a fully-realized, product-aligned mission-control
> design. It lands on the existing `web/` SPA + `web/src/app/orrery-renderer.tsx`.
> The full token/grammar spec is in **Appendix G** so beads are self-contained
> without the (gitignored) archive. "We want it to look and vibe like this design."
>
> **Why this is a perfect fit:** OMCP's grammar is literally oraclemcp's domain
> model — the I·II·III·IV ladder *is* the operating-level ladder; the GUARDED
> ACTION NO-GO/HOLD-FOR-GO panel *is* the preview→confirm step-up; the CHAIN strip
> *is* the audit hash-chain; CLASSIFIER-LIVE *is* the guard decision stream. This
> is not decoration bolted on; it is the safety model made legible.

**Validated implementation reality (Round-2 deep-dive — B4 is lower-risk than it looks):**
- The **skin/theme/renderer seam already exists** (`web/src/app/skin.tsx`: `DashboardSkin`,
  `assertDashboardSkinConformance` at `:222`, `board2d`/`table`/`orrery3d` renderers with a
  fail-closed fallback chain, `REQUIRED_THEME_MODES`). B4.2 is a **refactor** of the single
  `GROUND_CONTROL` skin into the OMCP skin — **one theme (Carved Light) in 0.7.3** (the seam
  supports more later; see B4.2/F.6) — **not** greenfield architecture.
- **6 of the 7 surfaces already exist and are wired** to `/operator/v1` routes — only
  **Profile-cards (Surface 2) is net-new**; the Orrery (`orrery-renderer.tsx`) is currently a
  **2D stub** (no three.js) to build out. Per-surface status + route below.
- **Fonts** self-host with plain `@font-face` under `web/public/fonts/` (no `font-src` CSP
  issue); **three.js + GSAP** bundle under the existing strict CSP (`http/mod.rs:2027-2029`,
  `script-src 'self'`, no `unsafe-eval`) — **no CSP loosening** (validated).
- **Effort:** ~18–22 dev-days — the single largest work-package; start it day 1, gate only its
  *contract* tests (grammar/conformance/fallback/offline-fonts), not visual polish.

**Surface → existing component + server route + status** (deep-dive cites):
| # | Surface | Component (`web/src/app/App.tsx`) | Server route | Status |
|---|---|---|---|---|
| 1 | Status bar | `GroundControlStrip` (:338) | `/operator/v1/health`, `/metrics` | re-skin |
| 2 | **Profile cards** | — | `/operator/v1/schema` (augment: posture+reachability) | **NEW** |
| 3 | AGENTS / LANES | `SessionLaneTable` (:745) | `/operator/v1/active-lanes` | re-skin |
| 4 | CLASSIFIER-LIVE | `OperatorEventLogPanel` (:2410) | `/operator/v1/events` (SSE) | re-skin → I·II·III·IV spine |
| 5 | GUARDED ACTION | `SessionLevelControlPanel` (:883) | `/operator/v1/session/set-level` | re-skin + client countdown |
| 6 | SNAPSHOTS | `ReviewsPage` (:2317) | `/operator/v1/change-proposals`, `/source-history` | re-skin + review/revert detail |
| 7 | CHAIN | `GroundControlStrip` logbook (:391) | `/operator/v1/audit-tail` | re-skin → dedicated strip |

- **B4.1 — Design tokens + type + self-hosted fonts.** Encode the Appendix-G
  palette and type scale as the web/ design-token layer (CSS custom properties /
  Tailwind theme). **Self-host** EB Garamond + IBM Plex Mono as bundled WOFF2
  (no `fonts.googleapis.com` runtime call — the operator console must work
  offline/air-gapped and make no third-party requests). deny.toml / CSP updated.
- **B4.2 — Skinnable architecture (memory D16).** Implement the OMCP look as a
  **skin** over the existing view-models via the view-model / skin / theme /
  renderer seam: grammar-is-a-contract; three.js quarantined in the Orrery renderer
  (lazy/code-split); skins-pure dep-lint + conformance CI; **mandatory 2D fallback**.
  **Ship exactly ONE theme in 0.7.3: Carved Light** — the near-black palette (Appendix
  G.3) with the cinematic **mountain "Vale" (Parnassus) backdrop**. The other design-archive
  variants (Parnassus/Generative Vale/Photo Vale/base) are **NOT shipped** — the theme seam
  stays so they *can* be added later, but only Carved Light is wired and tested now.
- **B4.3 — The seven console surfaces (OMCP grammar → real guarded routes).**
  Every surface renders live server state and drives the *same* guarded action
  routes agents use (server derives Subject from the transport principal; the
  browser never supplies it; no fail-closed exception):
  1. **Status bar** — "FAIL-CLOSED · ALL LANES NOMINAL", lane/prod/held counts,
     live UTC clock (from server health/readiness + telemetry).
  2. **Profile cards** — one per connection profile: reachability, ceiling badge
     (I/II/III/IV filled squares), posture (protected/standby/staging/DR),
     `read_only_standby`. Feeds from `oracle_list_profiles` + doctor posture.
  3. **AGENTS / LANES — live sessions** — per-principal isolated lanes (own Oracle
     connection, level, grants, cancellation, audit) with a per-lane kill-switch.
  4. **CLASSIFIER-LIVE ladder** — the I·II·III·IV spine with the streaming verdict
     log (PASS / REFUSED·exceeds-ceiling / HOLD-FOR-GO) via SSE; "every statement
     provably gated before it touches the wire."
  5. **GUARDED ACTION** — the step-up/confirm panel: pending statement, classifier
     verdict, countdown-to-expiry, **NO-GO / HOLD-FOR-GO** (maps to
     `oracle_preview_sql` → single-use grant → `oracle_execute` /
     `oracle_set_session_level`; re-classifies at apply, SEC-1).
  6. **SNAPSHOTS** — source-history / change-proposal REVIEW · REVERT (a revert
     drafts a normal DDL Change Proposal; never bypasses review/confirm/ceiling).
  7. **CHAIN** — the audit hash-chain strip: "✓ INTACT · height … · verified … ago"
     (from `oraclemcp-audit` verify).
- **B4.4 — Workbench + Explorer depth (memory §4-WD.5).** Deepen the editor
  (classify-preview-execute), Explorer global search
  (`oracle_search_objects`/`oracle_search_source`), and the Reviews change-proposal
  board — all in the OMCP grammar, all through guarded routes. Browser-originated
  DDL/Admin apply stays release-gated per current policy.
- **B4.5 — Orrery hero (IN — full depth per operator decision H12).** Build/polish the
  three.js `orrery-renderer.tsx` celestial hero this cycle, integrated with the OMCP
  design over the cinematic mountain "Vale" (Parnassus) backdrop. Keep it **code-split**
  and behind the **mandatory 2D/static-backdrop fallback** so a reduced-motion or
  low-power client still boots instantly (the fallback is non-negotiable even though the
  hero is fully built). CSP stays strict (three.js/GSAP bundled/self-hosted, no external
  fetch, no `unsafe-eval` — validated against `http/mod.rs:2027-2029`; H11).
- **B4.6 — Autonomous test.** `web` build green; existing `dashboard_e2e.rs`
  pairing flow; a **skin conformance test** (every view-model renders in the
  **Carved Light** theme **and** the mandatory 2D fallback; grammar contract holds);
  a **no-external-request test** (no `googleapis`/CDN reference in the built bundle);
  SBOM regenerates. Visual polish is operator-reviewed; the *contract* (routes, guards,
  fallback, offline-fonts) is autonomously tested.

### B5. Doctor trio-stack provenance (GitHub #6)  ·  P3  ·  autonomous
**Change sites (cited):** `doctor.rs:486-504` (`DoctorReport`), `:966-990` (`run_doctor`
checks vector). Add `check_trio_stack()`.
**⚠ Review catch — the driver version:** `env!("CARGO_PKG_VERSION")` resolves to
*oraclemcp-db's* version, **not** the driver's. To report the real `oracledb` version,
**define/verify a public `oracledb::VERSION` const** in the driver (add it in Part A if
absent) and have doctor read it; the autonomous test asserts doctor's reported driver
version equals the pinned `=0.7.3`.
- **B5.1 — plsql-intelligence detection contract.** Doctor must safely report whether
  `plsql-intelligence` is present (compile-time feature gate / optional import) — assert
  **both** present and absent render correctly without crashing or leaking.
- Report: `oraclemcp-db` version, `oracledb` version (via the const), build driver-line
  ("thin oracledb 0.7.3"), upstream issue URLs, plsql-intelligence status; `capabilities`
  documents detector IDs; drift tracked. Tests assert issue URLs remain while issues open.
  Offline. **Deps:** B1, + the driver `VERSION` const (Part A).

### B6. Code quality — de-monolith `http/mod.rs` (`demonolith-http-qyqs`)  ·  P3
**Reality (validated):** `http.rs` is **already** `http/mod.rs` (5,924 LOC) with
`request_target.rs`, `sse_writer.rs`, `wire.rs`, `tests.rs` (184 KB) already split — the
risky atomic rename + path-contract migration is **done**. Remaining: extract further
modules from the 5.9k-LOC `mod.rs` (`serve`, `config`, `stores`, `operator/`, the
security-scanned inline tests). Each extraction gated on build+test+**byte-identical
goldens**+clippy-no-grow+forbid-unsafe, and must preserve the tested path/text contract
(`include_str!`, `dashboard_e2e.rs` scanning, threat-model / behavior-inventory pins).
Lower risk than originally scoped. **Deps:** none (but coordinate with B3/B4 HTTP edits).

### B7. Deferred `k6q` items — triggers re-evaluated
- **In:** `k6q.9` (IAM) → B2.2. Re-classify the stale "upstream-blocked" notes on
  `k6q.7`/`k6q.8`/`k6q.9` against current driver reality.
- **Stays deferred (reasons):** `k6q.1/.2` advisors (licensed), `k6q.3` RAG,
  `k6q.4` hypothetical-index, `k6q.6` elicitation UI, `k6q.10` per-caller RBAC,
  `k6q.12` PII masking, `k6q.15` query-cost budgets (not in-theme / not
  autonomously testable this cycle), `k6q.14` stable Rust (**blocked by asupersync
  nightly `try_trait_v2`, not the driver**), `k6q.7`/`k6q.8` external-wallet /
  Kerberos/RADIUS (thin-mode / upstream boundary).

---

## PART C — SHARED: the autonomous, secret-free OCI test harness (new capability)

> The answer to "find a way to test OCI autonomously." A **prerequisite** for
> A2/A3/B2 and the single most reusable deliverable of the release. Everything is
> committed, deterministic, secret-free. Grounded in the validated code reality: the
> wallet layer is pure/offline (fully autonomous); a local rustls TLS listener
> harness **already exists** (`crates/oracledb/tests/tls_handshake.rs`); **gvenzl
> images cannot do TCPS out of the box** (no orapki/Java/openssl, only TCP 1521
> published) — so a real DB-query-over-TCPS runs in the **local pre-tag gate (§D3.2)**,
> not CI, never a silent gap.

**The four OCI layers and how each is covered (day-one honesty):**

| Layer | What | Coverage | Autonomy |
|---|---|---|---|
| **1. Wallet parse/decrypt** (the field-test blocker) | 3DES/PBES2 p12, cwallet.sso, pem | C1 synthetic-wallet offline parse tests (extend `tls_wallet.rs`) | **100% autonomous, offline** |
| **2. TCPS handshake + DN/SAN match + trust precedence + mTLS** | client TLS path | C2 extends the existing `tls_handshake.rs` rustls listener w/ synthetic wallets | **100% autonomous, offline** |
| **3. Token wire path + non-TCPS refusal** | IAM `AUTH_TOKEN` framing | C3 mock token over the C2 lane; assert `AUTH_TOKEN` + `AccessTokenRequiresTcps` | **100% autonomous, offline** |
| **3b. Real DB query over TCPS** (gold standard) | full stack vs a real Oracle over TLS | **local pre-tag gate (§D3.2)** — scripted, runs before tag, commits a secret-scanned proof | local-gate (not CI); enforced by preflight |
| **4. Real-cloud IAM token acceptance** | a real OCI IAM token accepted by a real ADB | operator manual smoke only (no CI can hold OCI cloud creds without leaking/depending) | operator-gated, documented |

- **C1 — Synthetic wallet fixtures + generator (`scripts/gen_test_wallets.sh`).**
  **Validated live (OpenSSL 3.5.5, orapki absent):** the generator produces a matrix of
  throwaway wallets — fictional DN `CN=oracle-test.invalid`, throwaway password — committed under
  `crates/oracledb/tests/fixtures/tls/synthetic/`:
  - modern PBES2/PBKDF2/AES-CBC `ewallet.p12` — `openssl pkcs12 -export` (default). ✅ works.
  - **legacy 3DES `ewallet.p12`** — **exact command:** `openssl pkcs12 -export -certpbe
    PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -legacy …`. Confirmed: `PBE-SHA1-3DES` =
    `pbeWithSHA1And3-KeyTripleDES-CBC` = OID **`1.2.840.113549.1.12.1.3`** (the *exact* field-test
    OID). **Requires the `-legacy` provider flag** on OpenSSL 3.x (3DES PBE is legacy-only). ✅.
  - `cwallet.sso` auto-login — **orapki is unavailable**, so DO NOT try to generate one. **Reuse the
    existing real committed fixture `cwallet_orapki.sso`** (already in the driver's fixtures). The
    A2.2 fallthrough test combines a *synthetic legacy-3DES p12/pem* with that *existing real sso*.
  - encrypted + plaintext `ewallet.pem` (note: `openssl rsa -des3` on 3.x emits **PBES2**, not
    legacy PBES1 — already supported; the legacy case is the p12 above).
  - **DETERMINISM (resolved, red-team R5):** PKCS12 uses a random salt/IV → fixtures are **NOT
    byte-reproducible**. So **commit the fixture bytes ONCE**; tests assert the wallet **decrypts to
    the expected key/cert**, never byte-identity. CI needs no `openssl` (only the regen script does).
  Extends the existing fixture set (`tls_wallet.rs` already covers ~30 wallets). Drives A2.1/A2.2 +
  server B2.1 doctor wallet tests.
- **C2 — Local TCPS lane (extend the existing harness).** Extend
  `crates/oracledb/tests/tls_handshake.rs` (a rustls server on `127.0.0.1:0`, already
  proving handshake + DN/SAN match + mTLS + round-trip) with the C1 synthetic wallets
  and the token path. Covers OCI Layer 2 fully offline. **No new infra.**
- **C3 — Mock IAM token source.** A local provider returns a throwaway JWT-shaped
  token; drives A3 / B2.2 over the C2 lane (`AUTH_TOKEN` + non-TCPS refusal). No real IAM.
- **C4 — Confidentiality secret-scan lint (`scripts/secret_scan.sh`, both repos)  ·
  RELEASE BLOCKER.** All three reviews flagged this as a must-have-before-merge. Greps the
  entire tracked tree (code/tests/fixtures/**cassettes**/docs/beads JSONL) for forbidden
  confidential token patterns; fails CI on any hit. Wired into `_quality.yml` + release
  preflight (`release_preflight.sh`). The technical enforcement of §0.2. The exact pattern
  list lives in a **gitignored operator file** the lint reads (so the patterns themselves
  are never published). Per operator (I1), that file MUST enumerate **(1) every literal
  identifier appearing under `todelete/`** and **(2) the confidential customer-codename
  family** (the name + its `*`-prefixed schema/user variants) — these literals appear ONLY
  in that gitignored file, never in the plan/code/beads/commits/messages. Plus broad
  **structural** patterns that can't match public content (e.g. `CN=.*\.oraclecloud\.com`,
  wallet-OCID shapes, RFC1918 ranges in fixtures).
  - **Self-test (required):** a test that intentionally plants a forbidden pattern in a
    scratch file and asserts the lint **fails** — proving the gate actually catches leaks.
  - Complements the driver's existing cassette sanitization gate (which already refuses to
    write a cassette containing known auth-field names). Re-scan the current tree + any new
    cassettes/fixtures/golden doctor outputs before cutting 0.7.3.
- **C5 — Real-Oracle-over-TCPS: handled by the local pre-tag gate (§D3.2).** *(F.3 resolved:
  the custom pre-baked TCPS gvenzl image is **dropped** — its infra cost isn't justified.)* The
  real-query-over-TLS+wallet check runs in `scripts/local_release_gate.sh` (against a locally
  TLS-configured Oracle or the real ADB), writes a **secret-scanned committed proof**, and
  `release_preflight.sh` enforces the proof exists before tag. Layers 1–3 (C1–C3) remain the
  CI-autonomous gate; §D3.2 covers Layer 3b + the real-ADB / real-IAM operator smokes.
- **C6 — doctor-output secret audit (new, from review).** Audit `doctor.rs` error paths
  for credential echo (failed wallet-password / failed token-refresh could leak the
  secret into a message); add explicit redaction using the existing `RedactedSecret`
  pattern; a golden doctor-output committed as a fixture must be secret-scan-clean.

---

## PART D — Cross-cutting: sequencing, DAG, quality gates

### D1. Dependency DAG (build order)  ·  ★ = critical path
```
 ★ C1 synthetic wallets (FIRST — blocks A2/C2/C3) ─┐
   C4 secret-scan lint (independent, land early)   │
                                                    ▼
 ★ A1.1 GH#14 timeouts ──┐        ★ A2.1 3DES ─► ★ A2.2 sso-fallthrough (day-one linchpin)
   A1.2 p5h              │                    │        │
   A1.3 ezxs/ygws        │        C2 TCPS lane (extends tls_handshake.rs) ◄─ C1
   A1.4 fuzz (after A4)  │                    │        │
                         │        A3 IAM TokenSource (no spike — R3 resolved) + C3 mock token (A3's test fixture)
   ── A4 Tier-1 (x3s,j1w,0mk,1s2,cn4,8pp+dgi,8eo,p5h,plsql-routine):
      PARALLEL with C & A1, no live server, no C-dependency ──
   ── A4 Tier-2 (h74,soda-pre21c,bbx,r9a,nnnz): need a live matrix lane ──
                         │                    │        │
                         └──────────┬─────────┴────────┘
                                    ▼
                   ★ A5 matrix gate + results-<sha>.json  → publish oracledb 0.7.3
                                    ▼
   ★ B1 adopt =0.7.3 ─► B2 OCI e2e (needs A2/A3) ─► B3 dashboard/HTTP fixes
      B5 doctor #6 ─► B6 de-monolith ─► B4 design/UX (re-skin existing views)
                                    ▼            → publish oraclemcp 0.7.3 (lockstep)
                              0.7.3 shipped (both repos)
```
- **★ Critical path:** C1 → A2.1 → A2.2 → A5 → B1 → B2 → release. Everything else fans
  out around it.
- **C1 is the single first prerequisite** (all three reviews agreed): the synthetic
  wallets block A2 tests, C2, and C3. Build + commit + secret-scan them first.
- **A4 Tier-1 (9 items) run PARALLEL with C and A1** — they are fully offline
  (cassette/loopback/proptest/alloc-count) and do **not** depend on the OCI harness.
  Only A4 Tier-2 needs a live lane. (Corrected from earlier draft.)
- **A1.4 fuzz** runs *after* the A4 decode surfaces land (it fuzzes them).
- B-side work is largely serialized behind the driver publish (B1 needs `=0.7.3`), but
  **B3 (dashboard/HTTP), B5 (doctor #6 offline), and B6 (de-monolith) have no driver
  dependency and can start immediately** in parallel with the driver track. B4 design
  can start on the existing views; its *contract* tests gate the release, not visual polish.
- **Not drawn above (all fan out around the spine, none on the critical path):**
  **A6** (`oracledb::VERSION` const — blocks B5), **A7** (pyshim edges — independent),
  **A8** (enable pipelining — independent; A5 asserts it); **§D6** test-hardening (cross-cutting,
  gated by DoD item 7 — D6.4 mutation gate runs nightly/local); **Part K** (accretive — K.1 gates
  the release, K.2 first-to-slip; K9 redesigned (structured `as_of` param — no classifier change), K10
  is `x3s`-gated); the **§D3.2 local
  pre-tag gate** + operator smokes run before the tag.

### D2. Definition of Done (every task)
1. Autonomous test green on the relevant lane (or the harness that makes it
   autonomous is built as part of the task).
2. `secret_scan.sh` green — no confidential leak.
3. `fmt` + `clippy -D warnings` + `cargo deny` + forbid-unsafe.
4. Goldens byte-identical where applicable; public-api / api-lock baseline regen &
   reviewed; driver-seam lint green (server).
5. Fail-closed guard only tightened, never loosened; new apply/recovery paths
   re-classify at the point of action.
6. Bead closed with `.beads/` committed alongside the code.
7. **(§D6)** Ships with its *strongest available* oracle (differential > metamorphic >
   round-trip > crash); any metamorphic relation is **mutation-validated**; new fixtures/
   cassettes carry `PROVENANCE.md`; any divergence is **XFAIL-tracked, never silent-SKIP**;
   new untrusted-decode surfaces have a fuzz target and new concurrent paths a TSan run.

### D3. Release checklist (both repos)
- Driver: green full version-matrix artifact committed for the release SHA →
  `release_preflight.sh` passes → tag `v0.7.3` → publish crates + GitHub.
- Server: bump `=0.7.3` pin + all version-embedded surfaces (Cargo×9+lock,
  server.json + GHCR tag, web+npm package.json/lock, dashboard bundle + SBOM,
  README/docs/install.sh, golden stdio fixtures `serverInfo.version`,
  driver-seam pin test) → preflight → tag → publish crates + GitHub + GHCR +
  MCP registry.

### D3.2. Local pre-tag release-gate tier (operator-requested)
Some checks need resources CI can't/shouldn't hold (a TLS-configured Oracle, the real ADB,
cloud IAM creds, a licensed feature). Rather than a custom CI image (infra cost) or an ad-hoc
smoke (informal), formalize a **local pre-tag gate** — the same pattern the driver already uses
(`release_matrix_gate.sh` → committed `results-<sha>.json`, enforced by `release_preflight.sh`).
- **`scripts/local_release_gate.sh`** (or extend the matrix gate): the operator/dev runs it
  **before tagging**; it exercises the heavy checks and writes a **sanitized, secret-scanned,
  committed proof** (`tests/artifacts/local_gate/results-<sha>.json`) with **no confidential data**
  (pass/fail + non-secret facts only; `secret_scan.sh` runs over it before commit).
- **CI enforces the proof exists** for the release SHA (`release_preflight.sh`), but does not run
  the heavy test itself — CI stays fast and credential-free.
- **Covers:** real-query-over-TCPS (F.3), the real-ADB wallet + real OCI-IAM acceptance smokes
  (§0.2 / C5-smoke), and — if the F.5 spike says yes — a local XA/TPC test. CI-autonomous
  Layers 1–3 remain the *primary* gate; this tier is the belt-and-suspenders for the un-CI-able slice.
- **Tiering (for reference):** offline/unit (CI, every commit) → integration (CI containers) →
  e2e/live matrix (CI/nightly) → **local pre-tag gate (this tier)** → operator smoke → post-release.

### D4. Round-2 completeness additions (new tasks, tests, docs, depth)
New/expanded items surfaced by the Round-2 completeness critic + implementability pass.

**New tasks (fold into beads)** — *the `D3.1` / `D7`–`D10` labels here are bead ids, **not**
Part-D sub-sections (§D1–§D6):*
- **D3.1 — Release-surface audit + sync-check script.** Enumerate *all* version-pinned
  files (the workspace root + every crate `Cargo.toml` + `Cargo.lock`, `server.json` L6,
  `web/package.json` + lock, `npm/*/package.json`, GHCR tag, README/docs/`install.sh`,
  `CHANGELOG.md`, golden stdio fixtures, dashboard SBOM, the `pin_is_0_7_x` seam test) and a
  script that verifies they all read `0.7.3` before tag. (Prevents the mid-publish version drift
  the 0.7.2 release hit.)
- **D10 — Release-ordering gate.** `release_preflight.sh` (server) must verify `oracledb`
  is **already published to crates.io** at the exact pinned `=0.7.3` and fail otherwise —
  enforces §0.3 driver-first ordering mechanically.
- **C5-smoke — Operator smoke sign-off (P1 deliverable), runs inside the §D3.2 local gate.**
  Explicit checklist + evidence format for the un-automatable gates: real-ADB wallet connect
  (TCPS), real OCI-IAM token acceptance; recorded out-of-band, never committed (§0.2).
- **upgrade-doc — `docs/upgrading-to-0.7.3.md`.** New `[profiles.*]` timeout/keepalive fields,
  `[http] allow_remote`, OCI IAM token-source, TNS alias resolution, streaming opt-in.
  *(renamed from "D6" to avoid colliding with the §D6 quality section.)*
- **A4.1 — Telemetry for new surfaces.** `tracing`/metrics for x3s (rows/s, backpressure),
  j1w (per-row errors, continuation), 8pp (cache hit/miss, invalidation), bbx (chunk/UTF-16).
- **A6 — `oracledb::VERSION` const** (already added; blocks B5).
- **D7/D8/D9 — ops docs:** downgrade runbook (0.7.3→0.7.2 config compat), feature-rollout
  defaults (streaming/cache/allow_remote defaults + opt-in paths), backup/restore notes
  (IAM tokens session-scoped, streaming in-flight-only).
- **Docs to update:** `threat-model.md` (allow_remote boundary + token-source exec safety),
  `configuration.md` (3 new timeout fields), `operations.md` (`/readyz`, service-lock,
  OCI), `behavior-inventory.md` (streaming/batch/LOB surfaces).

**New tests (must exist):**
- **SEC-1 reclass-at-apply (P1):** two-lane test — Lane A previews DDL + gets a grant;
  Lane B lowers the session level; Lane A execute → **re-classified → REFUSED** (exceeds
  ceiling), *not* honored from the stored grant. The explicit SEC-1 proof.
- **B2.2 token-source exec-fuzz:** malformed tokens (null bytes, >64k, invalid UTF-8, bad
  base64, injection strings) all fail closed; never a shell.
- **A1.1 timeout×keepalive interaction:** `inactivity_timeout=5s`, `EXPIRE_TIME=30s`,
  server silent → 5s deadline fires (not a 30s hang); keepalive success *resets* the
  deadline.
- **cn4 cross-lane cancel isolation:** cancel mid-stream on Lane A never stalls/corrupts
  Lane B's concurrent read.
- **B3.2 loopback boundary:** IPv4 `127.0.0.1` + IPv6 `::1` always bind; `0.0.0.0` +
  `allow_remote=false` still refuses non-loopback clients.
- **A2.2 negative control:** undecryptable-pem-only (no sso) → the *exact* typed error
  (`UnsupportedCipher` naming the OID) is preserved; must **not** mention sso fallthrough.

**Depth refinements (make shallow tasks implementation-ready — fold into task bodies):**
- **A1.1:** fields `connect_timeout: Option<Duration>`, `inactivity_timeout: Option<Duration>`;
  default `inactivity_timeout` = **operator-set, propose 300s**; keepalive interval derived
  from `EXPIRE_TIME`; timeout applies to CONNECT + ACCEPT + all post-auth data reads;
  enumerate **all** `read_exact` sites in the framing layer, not just `:9247/:9264`.
- **A2.2 policy (decision tree):** try pem → on `UnsupportedCipher` **fall through** to sso;
  on `PasswordRequired`/wrong-password with a valid auto-login sso present, **also fall
  through** (sso is an independent valid credential — matches python-oracledb) **but log a
  warning** naming the skipped wallet; if no sso, preserve the original error. Precedence:
  pem → p12(+pw) → cwallet.sso.
- **A3:** `pub trait TokenSource: Send + Sync { fn get_token(&self) -> BoxFuture<Result<String,
  TokenSourceError>>; }`; `TokenSourceError` = `Exec|Invalid|Timeout|Other` (all redacted);
  token never in Debug; called once at connect, again only on auth-fail.
- **B2.2:** env var `ORACLEMCP_IAM_TOKEN` / `[profiles.oci].token_env`; file variant
  re-reads per `get_token`; exec = arg-array, 5s timeout, output trimmed, max 64k,
  base64url charset; driver checks JWT `exp`, doctor warns if <5min.
- **B5:** `check_trio_stack()` → JSON `{oraclemcp_version, oraclemcp_db_version,
  oracledb_version, driver_line:"thin oracledb 0.7.3", plsql_intelligence:"present|absent"}`;
  version mismatch = **WARN** (not FAIL, for downgrade); golden doctor output committed +
  regression-asserted.
- **B3.1:** probe = `GET {url}/readyz`, 2s timeout, no redirect-follow; refuse + no ticket on
  failure. **B3.3:** pid-liveness via `kill(pid,0)`==ESRCH → `unlink` the stale lock, retry.

### D5. Risk register + week-1 validation gates (Round-3 red-team)
The plan's biggest risks are *assumptions that stay unproven until coded*. Each must be
validated **in week 1**, before dependent work proceeds — with a defined fallback. Order the
sprint so these de-risk first.

| # | Risk (assumption) | Week-1 gate (prove it early) | Fallback if it fails |
|---|---|---|---|
| R1 | **A2.2 sso-fallthrough** actually fires for the exact field scenario (3DES pem + valid sso) | Code A2.1 then A2.2 FIRST; **block on the exact-scenario positive test** (+ negative no-mask test); require fixture/cassette evidence in PR, not just code inspection | No workaround — pause release, root-cause. This is *the* day-one gate |
| R2 | **C4 secret-scan patterns are complete** (gitignored list could miss a class) | Operator provides the **final pattern list before coding**; add C4 self-test to CI (not just release time); **run the lint over THIS plan + the whole tree before tag** | If a class is later found: update patterns, re-scan old tags; never "fix in 0.7.4" |
| R3 | **Async `TokenSource` across `oracledb-pyshim` FFI** | ✅ **RESOLVED (spike done, §A3):** not a real risk — Python never implements the trait; `Arc<dyn TokenSource>` is Clone-safe; pyshim untouched. Spike dropped; build A3 directly with the given signature. | n/a — resolved (fallback would've been static-token-only) |
| R4 | **B4 fits ~18–22 days** and three.js/GSAP pass the strict CSP | Baseline the **contract tests** (grammar/conformance/2D-fallback/offline-fonts) as a spike NOW; **test three.js+GSAP under the exact CSP** before B4.5 | Operator chose "everything," so *don't pre-cut*; but if schedule slips >3d, contingency cut order: Orrery motion polish → deep Profile-cards depth → Workbench extras. Gate on **function**, not visual polish |
| R5 | **C1 wallet generation feasible/deterministic?** | ✅ **RESOLVED (tested live, §C1):** OpenSSL 3.5.5 generates the exact `…12.1.3` legacy-3DES p12 via `-certpbe/-keypbe PBE-SHA1-3DES -legacy`; PKCS12 is **not** byte-deterministic (random salt) → **commit fixtures once, assert decrypt not bytes**; orapki absent → reuse the real committed `cwallet.sso`. No open risk. | n/a — resolved |
| R6 | **Streaming/cancel is cancel-safe** across concurrent lanes (no deadlock/corruption) | Implement the **concurrent-cancel isolation test early**; review against **asupersync's** cancellation model — *this stack is asupersync, not Tokio* — using the deadlock-finder + asupersync skills | Mark streaming **beta** in release notes; bound look-ahead; single-writer where unproven |
| R7 | **Token-exec validation is airtight** (injection/garbage) | Spec token strictly (validate JWT via a lib; ≤64k; no null/control bytes; check `exp`); **proptest/cargo-fuzz** the boundary; security-review the PR | Fail-closed on any parse/exec error; never fall back to password auth |
| R8 | **Tier-2 matrix lanes are up at tag time** | Pre-record **cassettes** for Tier-2 (h74/soda/bbx/nnnz) during dev so CI can replay if a live lane is down | Descope the affected Tier-2 item to 0.7.4; keep Tier-1 (offline) as the gate |
| R9 | **G-CONSUMER API shape fits `plsql-mcp`** | Design-review the driver `RoutineCall` API with the consumer **before finalizing A4** | Adjust API pre-publish (cheap); consumer wiring is post-publish anyway |

**Shippability verdict (red-team, post-spike):** YES as one 0.7.3, *aggressive but defensible* (~80–110 dev-days over 2–3 weeks with the parallelization in D1). R3 (FFI), R5 (wallet-gen), R9 (consumer API) **resolved outright**; R8 (Tier-2 lanes) has a cassette mitigation; R2 patterns operator-provided (I1); R4 CSP confirmed OK (three.js r150+/GSAP3 eval-free under `script-src 'self'`). **Only R1 (A2.2 fallthrough) + R6 (streaming cancel-safety) remain code-time — both spec-complete** (exact fixture command, test, and cancel-review approach given), i.e. the *first implementation steps*, not open questions. Operator chose full scope (F.7/F.8); cut candidates are contingency only.

### D6. Quality & test-hardening workstream (mock-finder + testing-skill lenses)
Both codebases were scanned with `mock-code-finder`: **zero `todo!()`/`unimplemented!()`/
`panic!("not implemented")` in core; no hidden stubs; the fail-closed "unsupported" returns are
intentional safety design, not debt.** So this workstream is about **proving the NEW code's quality
with the strongest available oracles** (per `testing-conformance-harnesses` / `-fuzzing` /
`-metamorphic`), not cleaning debt.

- **D6.1 — Metamorphic property tests, mutation-validated (safety core + differentiators).**
  Most new work has a *metamorphic relation* that's a far stronger oracle than "looks right".
  Implement as property tests (`proptest`) and **validate each by mutation** (plant a bug; the MR
  must catch it, else it's placebo → drop/strengthen; kill-rate ≥80% on the planted set).
  - **Classifier (`oraclemcp-guard`, SAFETY-CRITICAL):** `classify(normalize(sql)) == classify(sql)`
    (whitespace/comment/case/quote/newline invariance); **monotonicity** (only ever tightens);
    **reclassification-idempotence**; "a proven-read `SELECT` can never become a write." (Formalizes
    the memory's classifier-monotonicity / reclass MRs.)
  - **Differentiators (equivalence MRs):** `collect(stream(q)) == fetch_all(q)` (x3s);
    columnar-decode == row-decode (0mk); cached-prepare == fresh-prepare incl. after concurrent DDL
    (8pp/dgi); `executemany(N) == N×execute` (j1w); `idempotent-retry(N) == execute-once` (r9a).
  - **NUMBER→string serializer:** round-trip `decode(encode(v))==v`; scale/precision boundary
    invariance; locale-independence.
- **D6.2 — Fuzzing hardening (per `testing-fuzzing`).**
  - **Per-surface, structure-aware targets** for every new untrusted-decode boundary — VECTOR
    columnar (0mk), streaming framing (x3s), LOB streaming (bbx) — each with the **strongest oracle**
    (differential vs row-path / round-trip), not crash-only. Extends the 20-target corpus; exec/s
    ≥1000; every crash → committed regression test. (The concrete form of A1.4.)
  - **TSan concurrency campaign (NEW):** run the new concurrent paths — x3s look-ahead, 8pp/dgi
    cross-connection statement-shape cache, cn4 OOB cancel — under **ThreadSanitizer** (archetype-7).
    **This is the deterministic proof for red-team R6 (cancel-safety)** — reviewed with the
    deadlock-finder + asupersync skills (asupersync model, *not* Tokio).
  - **Differential-fuzz-after-optimization:** for perf items (0mk / 8eo / decode-tuning), fuzz
    `original` vs `optimized` on identical bytes and assert equal — proves no correctness regression.
  - **secret-scan the fuzz corpora + all committed test artifacts** (extends C4); `cargo tree`
    proves no fuzz deps in the release build.
- **D6.3 — Conformance rigor (per `testing-conformance-harnesses`).**
  - **Per-feature coverage-accounting matrix** (MUST/SHOULD × tested × passing × score; ≥0.95 on
    MUST) generated in CI → a `COVERAGE.md` compliance report extending the version-matrix.
  - **Fixture/cassette `PROVENANCE.md`:** every C1 synthetic wallet (the exact openssl `-legacy`
    command + version), the reused real `cwallet.sso` (orapki version), and every 1s2/nnnz cassette +
    golden — generated-with + exact-command + git-ref. Kills the "regenerated later, why different?"
    failure mode.
  - **`DISCREPANCIES.md` + XFAIL-not-SKIP:** formalize the 116 parity skips + named-region-TZ +
    thin-SODA edges + the A7 shim edges as **XFAIL-tracked** divergences (id, ACCEPTED/WILL-FIX,
    affected tests, review date), surfaced in the compliance report. No silent SKIP.
  - **Golden discipline (per `testing-golden-artifacts`):** the snapshot surfaces (stdio
    `serverInfo`/goldens, `capabilities` JSON, C6 doctor output, dashboard bundle/SBOM) adopt
    `insta` + a **shared `Scrubber`** (timestamps/UUIDs/durations/SCN/paths canonicalized — so a
    golden can never itself become a secret-leak or a flake), the `UPDATE_GOLDENS` → `git diff` →
    review → commit workflow, `.gitignore *.actual`, and **CI fails on any un-approved golden diff**.
- **D6.4 — Mutation-testing gate on the safety-critical crates (`cargo-mutants`).** Run on
  `oraclemcp-guard` (classifier), `oraclemcp-audit` (hash-chain), and the driver's decode boundary;
  require **kill-rate ≥90%** on guard/audit; surviving mutants triaged (new test, or documented
  equivalent). THE proof the safety tests aren't placebo. Slow → nightly + the local pre-tag gate
  (§D3.2), not every PR.
- **D6.5 — Stub-edge remediation (from the scan):** A7 (pyshim edges) + A8 (pipelining) on the
  driver; the `dispatch/mod.rs:4442` `AuditCtx` refactor on the server (opportunistic, arg-count
  quality); orrery3d = B4.5. Both codebases confirmed otherwise stub-free — this workstream is
  **proactive, not remedial**.
- **D6.6 — Optimization discipline (per `extreme-software-optimization`).** The perf differentiators
  (`x3s`, `0mk`, `8eo`, `A8` pipelining, decode-tuning) don't ship on "feels faster." Each follows the
  loop: **baseline** (`criterion`/`hyperfine`, p50/p95/p99 + allocs) → **profile** (`cargo flamegraph`,
  hotspot in top-5) → **isomorphism proof** (byte-identical wire/rows vs the pre-opt path — the driver
  already requires this) → **one lever per commit** → **commit the baseline number as a CI regression
  gate** (revert if it doesn't beat threshold — the README already reverted two non-winning candidates).
  Pairs with the D6.2 differential-fuzz-after-optimization (correctness) — this adds the *measured-win*
  half. Opportunity score ≥ 2.0 or it's not worth the risk.
- **D6.7 — Formal assurance on the safety core (per `lean-formal-feedback-loop`, tier-C).** The
  classifier and audit chain are the highest-assurance targets. Beyond D6.1 (metamorphic) + D6.4
  (mutation), add **bounded model checking with `kani`** (assurance tier C) on the **self-contained,
  BMC-tractable** safety helpers: the operating-level lattice (`READ_ONLY < READ_WRITE < DDL < ADMIN` is
  total + monotone), the *danger-marker → required-level* mapping (`marker ⟹ required_level ≥ the marker's
  floor`), and the audit-chain step (append-only + each record's MAC verifies against its predecessor).
  **Scope note (feasibility):** BMC of the *end-to-end* `classify()` over arbitrary SQL is intractable —
  it runs through `sqlparser`; that end-to-end property stays covered by D6.1 + D6.4, and kani adds a proof
  floor under the small critical helpers those tests exercise. `kani` is a **dev/CI verifier** — its CBMC
  backend is external tooling, exactly like cargo-fuzz's libFuzzer (D6.2); it never ships in the crates, so
  the pure-Rust / `forbid(unsafe)` posture of the published artifacts is unaffected. Full deductive proof
  (tier E / Lean) is out of scope. The mathematical backstop under the fail-closed thesis. *(K9's redesign
  means the flashback path needs **no** new proof — the classifier is unchanged.)*
- **D6.8 — Security-domain audit before tag (per `codebase-audit`).** A focused **security audit of the
  0.7.3 diff's new attack surface** (token-source exec, `allow_remote`, cassette-capture, the `as_of`
  param, the dashboard's guarded routes) using the domain-audit prompt → findings with `file:line` +
  severity + fix → criticals become P0 beads that block the tag. Distinct from the 3-lens *review* round
  (which spanned the plan); this is a code-level audit of what was actually built. A CLI/API sub-audit
  (doctor/dashboard discoverability, `ErrorEnvelope` ergonomics) is a nice-to-have follow-up.

> **DoD addendum (folds into D2):** every new feature ships with (1) its *strongest available*
> oracle test (differential > MR > round-trip > crash), (2) mutation-validation for any MR, (3)
> fixture provenance, and (4) XFAIL-not-SKIP for any divergence. **Perf features additionally carry a
> committed baseline + isomorphism proof (D6.6); the safety core carries the D6.7 kani checks; the
> release is gated by the D6.8 security audit.**

---

## PART K — Accretive additions (idea-wizard, **code-validated** — no surprises)
Generated via `idea-wizard`, then **validated against the real code by three agents** — every item
is now grounded in `file:line` with its exact change surface, validated effort, dependencies, an
autonomous test, and its **resolved surprise/risk**. Validation **re-tiered** the set (two first-guess
"cheap" items — K1, K7 — are actually medium), surfaced two real gotchas (K6 secret-safety, K9
parser/prover) — both designed out below — and confirmed K10's `x3s`-gating. Each ships under the
§D6 DoD. **Fail-closed invariant preserved in every item:** all are additive/observational — including
**K9 (redesigned): a structured `as_of` param whose base SELECT is proven read-only by the *unchanged*
classifier, with the server applying the flashback. The safety-critical prover is never modified.**

### K.1 — Genuinely cheap, ride on planned work (XS–S) — release-gating
- **K2 — Live server-capability probe in `oracle_capabilities`** · S.
  *Enabling:* driver exposes `server_version_tuple()`/`sdu()`/`supports_pipelining()`/`supports_oob()`
  (public); `protocol_version` + `supports_fast_auth` are internal (`oracledb-protocol/.../thin/types.rs`
  `AcceptInfo`). Server: `oraclemcp-core/src/capabilities.rs:71`, `server.rs:593`.
  *Change:* driver adds ~5 `pub` accessors + version-gated helpers (`supports_vector/json/boolean/soda`
  derived from the version tuple — **no round-trip**); server adds a `ServerFeatures` block (edition +
  partitioning via one privilege-degradable dictionary query, the rest version-derived).
  *Effort:* driver XS (0.5d) + server S. *Risk:* none — graceful omit on low privilege.
  *Test:* per lane (xe18/xe21/free23) the probe matches the generation.
- **K3 — Optimizer cost/cardinality in explain** · S.
  *Enabling:* `oraclemcp-db/src/intelligence.rs:1074` (`explain_plan` reads `DBMS_XPLAN.DISPLAY`);
  already gated by `allow_plan_table_write`.
  *Change:* after `EXPLAIN PLAN`, `SELECT id,cost,cardinality,bytes FROM plan_table ORDER BY id` →
  a structured `cost_estimate` block in the tool JSON (`dispatch/mod.rs:6139`). Costs are **relative**
  (document it). *Risk:* PLAN_TABLE overwrite within a session (acceptable); 11g-safe.
  *Test:* an expensive full-scan surfaces a high estimate; a PK lookup a low one.
- **K4 — Classifier-decision metrics** · S.
  *Enabling:* `oraclemcp-telemetry/src/metrics.rs:61` (`lane_blocked`), OTLP export
  `otlp/metrics.rs:89`, `metrics_is_blocked()` already keys on `ErrorClass`; `GuardDecision`
  (`oraclemcp-guard/src/classifier.rs:46`) carries `required_level`.
  *Change:* add **bounded** `reason_class` + `operating_level` labels to the blocked counter + export.
  *Risk:* none — observational; a broken meter cannot weaken the guard.
  *Test:* increments on a blocked write + an allowed read.
- **K5 — Normalized SQL fingerprint in audit** · S.
  *Enabling:* normalizer exists (`normalized_sha256()` `classifier.rs:105`, `sql_digest()`
  `token.rs:50`); `AuditRecord` (`oraclemcp-audit/src/record.rs:225`) stores an *exact* hash + preview.
  *Change:* add **hash-only** `sql_normalized_sha256` (**no new preview** — avoids any added literal
  exposure); audit hash-chain **v4** bump (v1–v3 records stay valid). *Risk:* none.
  *Test:* two whitespace/case variants share the fingerprint; v3 records still verify.
- **K11 — DDL blast-radius / dependents preview** · S (direct dependents; the optional transitive
  closure is an M add-on).
  *Enabling:* `oraclemcp-db/src/catalog_extract.rs:81` (Dependencies rowset); the
  `create_or_replace_inner`/`patch_source` previews (`dispatch/mod.rs:4460` / `:4134`) already carry
  the detected object.
  *Change:* `probe_dependents()` → read-only `ALL_DEPENDENCIES` query (**no DDL gate**); add a
  `dependents{count,objects,at_risk_of_invalid}` block to the preview. Direct dependents first;
  transitive closure optional (documented as a known limit, as is dynamic-SQL). Privilege-degradable.
  *Test:* replacing a package body previews the dependent views/procs that will go INVALID.

### K.2 — Accretive, validated-medium (M) — IN per "everything"; first-to-slip order if the sprint tightens
- **K1 — Wallet/cert-expiry warnings in doctor** · M *(revised up from XS)*.
  **Surprise:** the driver's `WalletContents` returns **DER bytes only — no x509 validity dates**.
  *Change:* driver adds `CertMetadata{not_before,not_after}` parsed via the **already-present `der`
  crate** (no new dep), exposed on `Connection`; server doctor (`doctor.rs:1109`) adds
  `expires_at`/`days_until_expiry` + a warn threshold. Offline (no DB). Silent-skip non-cert files.
  *Test:* a C1 synthetic wallet minted with short validity → warning; healthy → none.
- **K6 — `.tns-cassette` support-capture** · M · **secret-safety is a hard prerequisite**.
  **Surprise:** the general `CassetteRecorder` (`transport.rs:307`) records the **auth phase**
  (verifier / session-key / tokens) with **no sanitization** — a naive `ORACLEDB_CAPTURE` would leak
  secrets. *Resolution (mandatory):* env-gate `ORACLEDB_CAPTURE=<path>` at connect; **scrub auth-phase
  frames + run `scan_for_secret_fields()` (port `SECRET_FIELD_NAMES` from `version_cassettes.rs:253`)
  as a refuse-on-secret gate before writing**; ship a **self-test that plants a secret and asserts the
  write is refused**. Capture is never exposed without the gate. Ties to C4/C6.
  *Test:* capture a query failure → secret-scan passes over the artifact; offline replay reproduces it;
  the plant-a-secret test refuses to write.
- **K7 — Bind-literal rewrite hint** · M *(revised up from S)*.
  *Enabling:* the `sqlparser` tokenizer is already used (`classifier.rs:172` / `:754`); **no literal
  extraction yet**. *Change:* `suggest_parameterized_form()` — tokenize, find Number/String/Hex/National
  literals at **safe positions** (not `FROM` / function-name / DDL-column), suggest `:paramN`, cap ~10;
  surface in `ErrorEnvelope.next_steps`. Real work = safe-position filtering (VALUES lists, OR-chains).
  Hint-only — no guard risk. *Test:* `WHERE id = 42` → suggests `:id`; a literal inside a quoted
  identifier is untouched.
- **K8 — "Why blocked + minimal safe rewrite" coach** · M · *most agent-accretive* · **additive API**.
  *Enabling:* `GuardDecision` (`classifier.rs:46`) has `danger`/`required_level`/`reason`(string);
  `ErrorEnvelope` (`oraclemcp-error/src/lib.rs:111`) has `suggested_tool`/`next_steps` but **no
  structured reason**. *Change:* add a `reason_category` enum + `offending_construct` to `GuardDecision`;
  add `StructuredReason` to the **`#[non_exhaustive]`** `ErrorEnvelope` (**additive & non-breaking →
  patch-compatible with the 0.7.3 / 0.x bump; requires an api-lock / public-api baseline rebaseline**);
  wire `dispatch` gate-error/preview (`mod.rs:2047`/`:2123`)
  to populate it + compute the minimal rewrite; emit both structured + legacy string for a grace period.
  **Caveat:** some refusals (unbalanced `BEGIN/END`) have *no* minimal rewrite → fall back to
  `suggested_tool`. *Test:* each refusal class returns a valid minimal safe alternative (or a
  `suggested_tool` when none exists).
- **K9 — Flashback / AS-OF read mode** · M · **redesigned → NO classifier change, low-risk**.
  **Surprise:** `sqlparser 0.62` can't parse Oracle `AS OF SCN/TIMESTAMP` / `VERSIONS BETWEEN`, so *raw*
  flashback SELECTs are currently over-refused (parser can't prove → fail-closed). **Design (revised for
  safety):** do **not** teach the classifier to prove raw flashback SQL — that would modify the
  safety-critical prover. Instead add a **structured `as_of: {scn|timestamp}` parameter** to
  `oracle_query`: the agent passes a *normal* SELECT + an `as_of` value; the server proves the base SELECT
  read-only via the **existing, unchanged** classifier, then applies the flashback itself — either by
  appending `AS OF SCN :scn` to the proven query's table refs, or via a bounded
  `DBMS_FLASHBACK.ENABLE_AT_SYSTEM_CHANGE_NUMBER(:scn)` … `DISABLE` around it. `AS OF` cannot turn a read
  into a write, so the result stays provably read-only — **the classifier's prover is never touched, and
  no new proof obligation is created** (this is what removes the safety-critical flag). Bonus: better
  ergonomics — agents pass an SCN, not hand-written flashback SQL. FLASHBACK privilege is enforced by
  Oracle at execution (`ORA-01031` = correct fail-closed). **Deps:** B1. *Test:* `oracle_query(sql=SELECT…,
  as_of=SCN n)` on 21c/23ai returns the historical snapshot, classified READ_ONLY; the base SELECT
  classifies **identically** with/without `as_of`; a non-read base SELECT is still refused *before* any
  flashback is applied.
- **K10 — Streaming query results over MCP** · M · **gated on A4 `x3s`**.
  *Enabling:* `QueryArgs.cursor` + `read_query()` OFFSET/FETCH stateless pagination already exist
  (`dispatch/args.rs:8`, `oraclemcp-db/src/query.rs:88`); HTTP SSE exists (`http/mod.rs:5428`); the
  driver async `Stream` (`x3s`) is not yet landed (A4). *Change:* **Phase 1 (now)** — expose the
  existing cursor pagination as "incremental fetch"; **Phase 2 (post-`x3s`)** — pipe the driver `Stream`
  → SSE chunks, add a `streaming` param, advertise streaming in `oracle_capabilities`' tool-surface
  section (distinct from K2's `ServerFeatures`). Backpressure via the asupersync budget.
  **Deps: `a4-x3s`, B1.** *Test:* a large read returns bounded pages + a cursor;
  resume yields the next page byte-identical to a full fetch; (post-x3s) SSE streams row-by-row.

**Honest scope note (post-validation).** Validation moved **K1 and K7 up to medium**, surfaced the
**K9 parser/prover risk** and the **K6 secret footgun** (both now designed out), and confirmed **K10 is
`x3s`-gated**. **K.1 (K2/K3/K4/K5/K11)** are the genuine no-brainers and gate the release; **K.2
(K1/K6/K7/K8/K9/K10)** are IN per "everything," and — if the sprint tightens — slip to 0.7.4 in the
order **K10 → K1 → K7 → K6 → K8 → K9**. *(K9 was safety-critical under its first design; the redesign —
a structured `as_of` param, classifier untouched — makes it ordinary low-risk work.)* Zero new
dependencies across all of K. Beads in Appendix I.

---

## PART E — Out of scope / deferred (with reasons)
- **Driver 1.0 publish** — stays operator-gated; this cycle hardens toward it.
- **IAM request-signing** (instance/resource principal) — blocked on constant-time
  RSA (RUSTSEC-2023-0071); watch `rsa-marvin-revisit-hlgd`.
- **Kerberos / RADIUS / external-wallet passwordless** — thin-mode / upstream
  boundary (`k6q.7/.8`, driver `bpsh/o0b/qm4`).
- **CQN server-push** (not deterministically testable) and **named-region TZ** (thin-protocol
  limit, watch `mwu`) — deferred with reasons. *(XA/TPC is NOT deferred — already fully
  shipped + tested; see §F.5.)*
- **oraclemcp advisors / RAG / RBAC / PII masking / query-cost budgets** — not
  in-theme or not autonomously testable this cycle (`k6q.1–.6,.10,.12,.15`).
- **Move to stable Rust** — blocked by asupersync nightly features (`k6q.14`).
- **`plsql-intelligence` engine work** — lives in its own repo; oraclemcp stays
  engine-free (only the doctor provenance #6 touches the boundary here).

---

## PART F — Pre-beading decisions (all 9 RESOLVED)
1. ~~Fable design export location~~ — **RESOLVED.** OMCP Operator Console
   (`todelete/Claude_design.zip`); spec folded into B4 + Appendix G.
2. ~~oraclemcp version~~ — **RESOLVED: lockstep `0.7.3`** (both repos +0.0.1, exact pin
   `=0.7.3`), matching every prior release. Not 1.0.
3. ~~C5 real-Oracle-over-TCPS lane~~ — **RESOLVED: no custom CI image — use the local
   pre-tag gate (§D3.2).** Layers 1–3 stay CI-autonomous; the real-query-over-TCPS check runs
   in the scripted **local release gate** before tagging and writes a secret-scanned committed
   proof (`release_preflight.sh` enforces it). Best DevOps fit: gated + repeatable + proven,
   without custom-image infra. `C5-tcps-image` bead → dropped; `C5-smoke` folds into D3.2.
4. ~~A4 scope~~ — **RESOLVED: the full autonomously-testable differentiator set is IN**
   (all Tier-1 + Tier-2 items). The only differentiator OUT is **CQN** (fails the autonomous-test
   gate); **XA/TPC is already shipped (§F.5) → IN**, not deferred. Nothing else deferred.
5. ~~CQN vs XA~~ — **RESOLVED (spike done).** **CQN → defer** (server-push async notification
   isn't deterministic even locally; large post-1.0 feature). **XA/TPC → ALREADY SHIPPED, not a
   gap:** `tpc_begin/end/prepare/commit/rollback` exist on Connection + BlockingConnection + pyshim
   (`lib.rs:3567-3716`), **34 reference tests pass** (17 sync `test_4400` + 17 async `test_7400`)
   across xe18/xe21/free23, golden wire tests (`tpc_golden.rs`), pre-23ai fixed in 0.7.2 (bead
   `hkwd`). Autonomously testable single-RM on one container — no external TM. **0.7.3 action:**
   note it in release notes; **optionally** add a Rust-native discoverability test
   `live_tpc_single_rm.rs` (~150 LoC, free23+xe21) — not required, not blocking.
6. ~~OMCP themes~~ — **RESOLVED: exactly ONE theme — Carved Light** (near-black) with the
   mountain "Vale" backdrop. No other themes in 0.7.3 (the seam stays for later). Console
   name = OMCP; the Carved Light look = the design archive's v5 variant.
7. ~~B4 scope~~ — **RESOLVED: everything in 0.7.3, but ONE theme.** All 7 console surfaces
   built to full depth + the **single Carved Light theme** (mountain Vale backdrop) + the
   Orrery hero polish land this cycle. No other themes; no fast-follow deferral of the
   surfaces. (Scope acknowledged as large; schedule risk accepted deliberately.)
8. ~~`plsql-routine-call-api`~~ — **RESOLVED: keep + do the downstream consumer work.**
   Implement the driver `RoutineCall`/`RoutineBind` API (A4) **and** wire the `plsql-mcp`
   consumer that needs it (GH#13) — see the new cross-repo task **G-CONSUMER** (Part A).
9. ~~Third repo (`plsql-intelligence`) beads / version bump~~ — **RESOLVED (investigated).**
   `plsql-mcp` **lives in `plsql-intelligence/crates/plsql-mcp`** (confirmed — an earlier
   "moved to oraclemcp" reading was a `target-publish` artifact). Repo at 0.7.0, SemVer, live
   `.beads`. **Key finding:** the high-level routine API **already exists in `oraclemcp-db`**
   (`call_routine` + `OracleRoutineArg` + `ExecuteOutcome`, `connection.rs:368/3798`, exported
   `lib.rs:92`) — so plsql-mcp today hand-rolls PL/SQL blocks over `execute`/`query_rows` and can
   adopt `call_routine` directly. **G-CONSUMER = swap plsql-mcp's hand-rolled routine calls onto
   `oraclemcp-db::call_routine` + bump its `oraclemcp-db`/`oracledb` pins to `=0.7.3`.** This is
   an **internal-only** change (plsql-mcp's MCP tool surface is unchanged) → **plsql-intelligence
   bumps to `0.7.1`** (pre-1.0 patch: dependency + behavior change, no public-surface break).

---

## APPENDIX G — OMCP Operator Console design system (self-contained spec)

> Source: operator's Fable/Claude-Design export (gitignored). This appendix is the
> canonical, secret-free spec so implementation beads need nothing else. The visual
> reference screenshots live under the gitignored archive; do not commit them.

### G.1 Identity & concept
**OMCP** (the operator console for oraclemcp) is a cinematic, Delphic-flavored
mission-control. The wordmark is `◇ OMCP` with `ORACLEMCP · OPERATOR CONSOLE`. The
aesthetic keeps the oracle motif as *vibe*, not name: near-black "carved light"
over a misty mountain (Parnassus/"Vale") backdrop, classical serif + monospace,
warm gold & copper on charcoal, mythological code-names for lanes/agents. The
safety model is the UI: nothing is decoration — every element is a live projection
of the guard, the ladder, the grants, and the audit chain.

### G.2 Typography (self-hosted WOFF2 — no CDN at runtime)
- **Display / serif:** **EB Garamond** — weights 400/500/600, italic 400/500.
  Used for headings, the I·II·III·IV numerals, section labels (small-caps,
  letter-spaced), and the mythic lane/agent names.
- **Monospace:** **IBM Plex Mono** — 400/500/600. All data, SQL, verdicts, hashes,
  badges, timers, the CHAIN strip.

### G.3 Palette (v5 "Carved Light" — the only theme shipped in 0.7.3)
| Role | Hex |
|---|---|
| Base (deepest bg) | `#0c0b09` |
| Surface / elevated | `#1e1913`, `#282119`, `#2b261b` |
| Border / hairline | `#4a4230` |
| Text — bright | `#f2ecdc` |
| Text — primary | `#e9e2d0` |
| Text — secondary | `#c9c0ac`, `#b3a992` |
| Text — muted / labels | `#9c927b`, `#918770` |
| **Accent — gold** (primary, PASS-adjacent, headings) | `#c7a34a` |
| **Accent — copper** (active / warning / GO-warm) | `#d97748` |
| **Danger — rust** (NO-GO / destructive / DDL-danger) | `#c25048` |
| **Safe — sage** (PASS / read-only nominal) | `#8ea98c` |

**Theme (0.7.3 ships exactly one): Carved Light** — the near-black palette above with the
cinematic **"Vale" mountain photographic backdrop** (Mt. Parnassus, the Delphic mountain). The
other design-archive **theme variants** — Parnassus, Generative Vale, Photo Vale, base — are
**not shipped**. *(Note: the "Parnassus" **theme variant** is a distinct lighter treatment, not
the Vale mountain backdrop that Carved Light itself uses.)* The theme seam remains so they can
be added later. The mandatory 2D fallback is theme-independent.

### G.4 Grammar → product mapping (the contract every skin honors)
| OMCP element | oraclemcp reality | Data source |
|---|---|---|
| `◇ OMCP` header + `FAIL-CLOSED · ALL LANES NOMINAL` + UTC clock | server posture + health | telemetry / health |
| `IV / III / II / I` serif ladder | `ADMIN / DDL / READ_WRITE / READ_ONLY` operating levels | guard |
| Profile cards (ATLAS-PRIME, THEBES-RO, …) + ceiling badges ▪▪▫▫ + posture | connection profiles, `max_level`, reachability, `read_only_standby`, protected | `oracle_list_profiles`, doctor |
| AGENTS column (pythia-scout, hermes-migrator, …) | active MCP client sessions | core session registry |
| LANES · LIVE SESSIONS (isolated conn · own grants · own kill-switch) | per-principal HTTP lanes | lane runtime |
| CLASSIFIER-LIVE log (PASS / REFUSED·exceeds-ceiling / HOLD-FOR-GO + gates) | streamed guard decisions | guard + SSE |
| GUARDED ACTION panel · countdown · NO-GO / HOLD-FOR-GO | preview→confirm step-up | `oracle_preview_sql` → grant → `oracle_execute`/`set_session_level` |
| SNAPSHOTS · REVIEW / REVERT | source-history / change proposals | operator source-history |
| CHAIN strip · ✓ INTACT · height · verified Ns ago | audit hash-chain | `oraclemcp-audit` verify |

> The placeholder names in the design (ATLAS-PRIME, pythia-scout, SNAP-0142, etc.)
> are illustrative only — the console renders the operator's **real** profile/lane
> names at runtime. **Never** hard-code the design's sample names, and never render
> confidential names into any committed fixture/screenshot/test.

### G.5 Implementation notes
- The design ships as HTML/CSS reference (EB Garamond + IBM Plex Mono, the palette
  above, a 3-column mission-control grid: AGENTS | ladder+log | GUARDED
  ACTION/SNAPSHOTS, with status bar on top and CHAIN on the bottom). Translate to
  the React/Tailwind component set already in `web/src/components` + `web/src/app`.
- Backdrop: a static, optimized "Vale" mountain image (self-hosted, compressed) as
  the default hero; the three.js Orrery is the optional animated variant behind the
  fallback.
- Accessibility: the 2D fallback must be fully usable without the backdrop/motion;
  respect `prefers-reduced-motion`; maintain contrast on the near-black theme.

---

## APPENDIX H — Review Round 1 dispositions (3 adversarial lenses)

Three independent reviewers (architecture/DAG, autonomous-test/day-one,
security/confidentiality) read v3 against the real repos. Consolidated findings +
disposition. **Convergence:** all three independently flagged the `cwallet.sso`
fallthrough (A2.2) and the C4 secret-scan as the top items.

| # | Finding | Severity | Disposition | Where folded |
|---|---|---|---|---|
| H1 | **A2.2 has no fallthrough** — `load_wallet` returns on first wallet's decrypt failure; this IS the round-2 failure (3DES pem tried before working sso) | HIGH | **ACCEPT** — elevated to HIGH "day-one linchpin"; added typed `UnsupportedCipher` + explicit fallthrough + exact-scenario positive test + no-masking negative test | A2.2 |
| H2 | **C1 synthetic wallets are the true first prerequisite** (block A2/C2/C3) | HIGH | **ACCEPT** — C1 marked FIRST; DAG critical path starts at C1 | Part C intro, D1 |
| H3 | **DAG wrongly puts Tier-1 A4 downstream of C** — they're fully offline, run parallel | MED | **ACCEPT** — DAG redrawn; Tier-1 parallel with C/A1; ★ critical-path legend added | D1 |
| H4 | **D3 fix incomplete** — needs BOTH `[http] allow_remote` field AND `IGNORED_ENV_KEYS` entry | HIGH | **ACCEPT** — B3.2 already names both; made unmissable | B3.2 |
| H5 | **Doctor #6 version bug** — `env!(CARGO_PKG_VERSION)` = oraclemcp-db's, not driver's | MED | **ACCEPT** — need `oracledb::VERSION` const; doctor reads it; test asserts `=0.7.3` | B5 |
| H6 | **A3 TokenSource async-trait/pyshim FFI unvalidated** | MED | **ACCEPT** — added A3.0 FFI spike (do first) | A3 |
| H7 | **Token-source exec = command-injection surface** | HIGH | **ACCEPT** — B2.2 now mandates `Command` arg-array (no `sh -c`), token validation, fail-closed, fuzz | B2.2 |
| H8 | **C4 secret-scan doesn't exist; confidentiality unmitigated at CI** | HIGH | **ACCEPT** — C4 = RELEASE BLOCKER + self-test (intentional-leak→fail) + cassette scan | C4 |
| H9 | **Doctor output could echo secrets** (failed wallet-pw/token) | MED | **ACCEPT** — new C6 doctor-output secret audit + redaction + golden scan | C4/C6 |
| H10 | **Driver-layer IAM non-TCPS refusal test missing** (only server-layer exists) | MED | **ACCEPT** — added as an A3 autonomous test | A3 |
| H11 | **New deps (`des`, three.js/GSAP) need advisory + CSP review** | LOW-MED | **ACCEPT** — `cargo deny` after `des`; CSP stays strict (`script-src 'self'`, no `unsafe-eval`); three.js/GSAP bundled/self-hosted, no CSP loosening (validated: CSP at `http/mod.rs:2027-2029` already blocks external) | B4.1, D2 |
| H12 | **B4 scope too big** — 5 themes + 7 fully-built surfaces | HIGH | **OPERATOR DECISION → everything in 0.7.3, but ONE theme.** All 7 surfaces (full depth) + the single **Carved Light** theme + Orrery hero polish; other themes dropped. Schedule risk accepted. (Mitigate: start day 1 in parallel, gate only *contract* tests, not visual polish.) | B4, Part F.6/F.7 |
| H13 | **`plsql-routine-call-api` has no agent caller** (internal driver feature for plsql-mcp / GH#13) | MED | **OPERATOR DECISION → keep + downstream consumer work.** Driver API in A4 + wire the `plsql-mcp` consumer (GH#13) as cross-repo task G-CONSUMER; still never agent-facing in oraclemcp | A4, Part A G-CONSUMER, Part F.8 |
| H14 | **ezxs/ygws under-specified** (no bead bodies/lanes) | MED | **ACCEPT (at bead time)** — `br show ezxs/ygws` to extract bodies + lanes when converting to beads | A1.3 |
| H15 | **C5 real-Oracle-over-TCPS ambiguous** — gvenzl can't do TCPS OOTB | LOW | **ACCEPT** — C5 explicitly optional/post-gate; Layers 1–3 are the release gate; Layer 3b = custom image (stretch) OR operator smoke | Part C, F.3 |
| H16 | **IAM real-cloud acceptance can't be autonomous** | — | **ACCEPT** — IAM ships **beta**: mock-token wire/refusal autonomous; real acceptance = operator smoke | A3, B2.2 |
| — | SEC-1 re-classify-at-apply; IAM dual-layer TCPS; token redaction; strict CSP; no-unsafe; cargo-deny | GREEN | **verified compliant** — no change needed | — |

**New/changed tasks created by this round:** A3.0 (FFI spike), B5.1 (plsql-intel
detection), C6 (doctor secret audit), the C4 self-test, the driver-layer IAM refusal
test, the `oracledb::VERSION` const (Part A). **Two items need an operator decision**
(H12 B4 scope, H13 plsql-routine) — see Part F.

**Verdict:** plan is grounded, cites real code correctly, and is now near steady-state.
The only true day-one risk is A2.2 (coded + tested against the exact field scenario) —
now the top-ranked item.

---

## APPENDIX I — Proposed bead DAG (~80 beads incl. §D6 + Part K, ready to convert)

Validated structure for converting this plan to beads across the trackers. No cycles.
All cited `file:line` refs spot-checked accurate (17/17). Slugs are indicative.

**★ Critical path:** `C1 → A2.1 → A2.2 → C2 → A2.3 → A5-gate → publish-oracledb-073 →
B1 → B2.2 → B2.4 → b4-contract-tests → publish-oraclemcp-073`.

### Driver (`rust-oracledb` tracker)
```
Shared/harness (tag in both repos):
  C1-gen-wallets       task    synthetic wallet generator + fixtures            deps: —          ★FIRST
  C4-secret-scan       task    confidentiality lint + self-test                 deps: —
  C2-tcps-lane         feature extend tls_handshake.rs (C1 wallets + token)     deps: C1,A2.1,A2.2
  C3-mock-iam          feature mock IAM token source                            deps: C2
  C6-doctor-redaction  feature doctor error-path secret audit                   deps: —

Hardening:
  A1.1-timeouts        feature GH#14 connect/idle/keepalive                     deps: —          ★ blocks A5,B1
  A1.2-p5h             feature FromSql/ToSql proptests                          deps: —
  A1.3-bugfix-verify   task    ezxs/ygws re-verify + close                      deps: — (live)
  A1.4-fuzz-unsafe     feature miri + fuzz new A4 surfaces (VECTOR/stream/LOB)  deps: a4-0mk,a4-x3s,a4-bbx (surfaces land first)
  A6-version-const     chore   pub const oracledb::VERSION                      deps: —          blocks B5

OCI:
  A2.1-3des            feature legacy 3DES PKCS12 decrypt (+des crate)          deps: C1         ★
  A2.2-sso-fallthrough feature cwallet.sso fallthrough (day-one linchpin)       deps: C1,A2.1    ★ blocks B2.1
  A2.3-oci-validation  feature offline wallet + TCPS handshake tests            deps: C2,A2.1,A2.2
  A3-token-source      feature TokenSource trait (sig fixed §A3) + driver-layer refusal test  deps: C2,C3  blocks B2.2  (A3.0 spike dropped — R3 resolved)

Mock-scan finds (both codebases otherwise stub-free):
  A7-pyshim-edges      feature route p5o not_implemented shim edges → crate (unskip reference tests)  deps: —
  A8-enable-pipelining feature wire per-op result buffering; supports_pipelining()=true; 1-round-trip test  deps: —  (A5-matrix asserts it)

Differentiators — Tier-1 (parallel, offline):
  a4-x3s a4-j1w a4-0mk a4-1s2 a4-cn4 a4-8pp(+dgi) a4-8eo a4-plsql-routine       deps: — (each)
Differentiators — Tier-2 (live lane):
  a4-h74-soda a4-soda-pre21c a4-bbx a4-r9a a4-nnnz(deps a4-1s2)                 deps: — (live)

Quality & test-hardening (§D6 — shared, tag both repos):
  D6.1-metamorphic     feature classifier + differentiator MRs (proptest), mutation-validated  deps: guard + each differentiator
  D6.2-fuzz-hardening  feature per-surface structure-aware targets + TSan concurrency campaign (R6) + diff-fuzz-after-opt  deps: a4-0mk,a4-x3s,a4-bbx,a4-8pp,cn4
  D6.3-conformance     feature per-feature coverage matrix + PROVENANCE.md + DISCREPANCIES.md/XFAIL  deps: A5,C1
  D6.4-mutation-gate   task    cargo-mutants ≥90% kill on guard+audit+decode; nightly + local gate  deps: D6.1
  D6.6-optim-discipline feature criterion baseline + flamegraph + isomorphism proof + committed regression gate per perf bead  deps: a4-x3s,a4-0mk,a4-8eo,A8
  D6.7-kani-assurance  feature kani BMC on BMC-tractable safety helpers (level-lattice, marker→level map, audit-chain step); end-to-end stays on D6.1+D6.4; kani=dev/CI tool (CBMC backend, never shipped)  deps: D6.1
  D6.8-security-audit  task    security-domain audit of the 0.7.3 new attack surface; criticals→P0 beads that block tag  deps: B2,B3,b4-contract-tests,K6,K8,K9

Gate + publish:
  A5-matrix-extend     feature matrix_full.rs + version_matrix.sh per-feature   deps: A1.1, all-A4, A8
  A5-oci-lane          feature OCI TCPS matrix lane                             deps: C1,C2,A2,A3
  A5-gate              task    results-<sha>.json + preflight                   deps: A5-*, C4
  publish-oracledb-073 chore   tag v0.7.3, crates.io + GitHub                   deps: A5-gate    blocks B1
```

### Server (`oraclemcp` tracker)
```
  B1-adopt-073         task    pin =0.7.3, timeout config fields                deps: publish-oracledb-073
  B2.1-wallet-posture  feature adopt wallet fixes + doctor truth-table          deps: B1,A2
  B2.2-iam-impl        feature env/file/exec token-source (+exec-fuzz)          deps: B1,A3,C3
  B2.3-tns-alias       feature TNS_ADMIN alias resolution                       deps: —
  B2.4-oci-e2e         feature server OCI e2e over C2 lane                      deps: B2.1-.3,C2
  B3.1-pairing-probe   feature D1 probe-before-mint                             deps: —
  B3.2-allow-remote    feature D3 [http] allow_remote + IGNORED_ENV_KEYS        deps: —
  B3.3-stale-lock      feature D4 pid-liveness auto-clear                       deps: —
  B3.4-readyz-docs     task    D5 operations.md                                 deps: —
  sec1-reclass-apply   task    two-lane re-classify-at-apply proof              deps: B1
  B5-doctor-trio       feature #6 trio-stack (+A6 const)                        deps: B1,A6
  B5.1-plsql-detect    feature plsql-intelligence present/absent                deps: B5-doctor-trio
  B6-extract-*         feature de-monolith http/mod.rs (serve/config/stores/operator) deps: — (×4)
  b4-design-tokens b4-fonts b4-skinnable-arch                                   deps: chain
  b4-surfaces-{profiles(NEW),status,lanes,ladder,action,snapshots,chain}        deps: b4-skinnable-arch
  b4-orrery-hero       feature three.js + GSAP + 2D fallback                    deps: b4-skinnable-arch
  b4-contract-tests    feature conformance + offline-fonts + no-ext-request     deps: b4-surfaces-*
  D3.1-release-audit   task    version-surface sync-check (all ~12 pinned files) deps: —
  D10-release-order    task    server preflight verifies driver published       deps: —
  upgrade-doc          task    docs/upgrading-to-0.7.3.md (renamed from D6 — avoids §D6 collision)  deps: B1,B2,B3
  D7-downgrade D8-rollout D9-backup  task  ops docs (compat/defaults/DR)         deps: —
  publish-oraclemcp-073 chore  tag v0.7.3 → crates + GHCR + MCP registry        deps: B1,B2,B3,b4-contract-tests,B5,B6,C4,D3.1,D3.2-local-gate,D6.4,D6.8-security-audit,D10,K2,K3,K4,K5,K11  (release gates D3.1/D3.2/D6.4/D6.8/D10; K.1 cheap tier gates; K.2 medium targeted-in but not hard-gating — slip order in Part K)

Accretive additions (Part K — code-validated; zero new deps):
  # K.1 cheap (release-gating):
  K2-server-cap-probe  feature +driver pub accessors (protocol_version/fast_auth/supports_*) ; server ServerFeatures block  deps: B1  · S
  K3-preview-cost      feature explain_plan → cost/cardinality/bytes block (plan_table select)  deps: B1  · S
  K4-classifier-metrics feature reason_class+level labels on lane_blocked + OTLP export          deps: —   · S
  K5-sql-fingerprint   feature hash-only sql_normalized_sha256 in AuditRecord; hash-chain v4     deps: —   · S
  K11-ddl-blast-radius feature probe_dependents() ALL_DEPENDENCIES block in CoR/patch preview    deps: B1  · S–M
  # K.2 medium (IN per "everything"; slip order K10→K1→K7→K6→K8→K9 if tight):
  K1-cert-expiry-warn  feature DRIVER CertMetadata via existing der crate + Connection accessor; server doctor warn  deps: B2.1  · M
  K6-cassette-capture  feature DRIVER ORACLEDB_CAPTURE + MANDATORY scrub+scan_for_secret_fields gate + plant-secret self-test  deps: C4  · M
  K7-bind-literal-hint feature suggest_parameterized_form() (safe-position filtering), surface in next_steps  deps: —   · M
  K8-blocked-coach     feature GuardDecision reason_category + ErrorEnvelope StructuredReason (additive #[non_exhaustive] → api-lock rebaseline; patch-compatible)  deps: —   · M
  K9-flashback-read    feature structured as_of param on oracle_query; server applies flashback to a proven-read base; classifier UNCHANGED  deps: B1  · M
  K10-stream-over-mcp  feature phase1 cursor incremental now; phase2 driver Stream→SSE post-x3s  deps: a4-x3s, B1  · M

Local pre-tag gate (§D3.2) + operator sign-off (not CI code beads):
  D3.2-local-gate      task    scripts/local_release_gate.sh: real-query-over-TCPS + secret-scanned committed proof; preflight enforces it   deps: C1,C2
  C5-smoke             task    real-ADB TCPS + real OCI-IAM acceptance sign-off (runs in the local gate; evidence never committed)  deps: publish-*
  (C5-tcps-image custom-image bead DROPPED — F.3.)
Naming note: `G-CONSUMER` is a cross-repo task label (the `G-` is just the slug prefix — it is NOT related to Appendix G, the design spec).
```

### Cross-repo (`plsql-intelligence` tracker — F.9 resolved → bump to 0.7.1)
```
  G-CONSUMER            feature  swap plsql-mcp's hand-rolled blocks onto oraclemcp-db::call_routine; bump oraclemcp-db/oracledb pins =0.7.3; bump plsql-intelligence 0.7.0→0.7.1   deps: publish-oraclemcp-073
```
*Beading note:* per `beads-workflow`, create with `br`, self-contained bodies citing the
`file:line` change-sites from Parts A–C + the per-task autonomous tests (§D4), then polish 6+
rounds to steady-state. `br dep cycles` must be empty; `bv --robot-insights` for health.

---

*End of DRAFT v8 — STEADY-STATE, FULLY RESOLVED + quality-hardened. Three review rounds (R1/H,
R2/§D4+Appendix I, R3/§D5) + four resolution spikes (C1 wallet-gen, XA, A3.0 FFI, plsql consumer)
+ a mock-code-finder scan of both repos (clean) + the conformance/fuzzing/metamorphic testing
lenses (→ §D6, A7, A8) integrated. All Part F items resolved. Grounded (file:line spot-checks
accurate), self-contained, implementation-ready. Convert to beads (Appendix I) — sprint leads with
the §D5 gates (A2.2 fallthrough first) and the D6.4 mutation gate proving the safety tests real.*
