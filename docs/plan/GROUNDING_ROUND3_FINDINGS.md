# Round-3 field-test findings — code-level grounding annex

**Status:** grounding complete for P0-1, P0-4, P0-5, P1-10..P1-14; partial for P0-2, P0-3, P1-1..P1-3, P1-8, P1-9.
**Purpose:** map every field-test finding to an exact code site, root cause, minimal fix, and the test that
would have caught it — so the 0.9.1 / 0.8.5 plan is built on verified facts rather than claims.

**Provenance.** The source report is an operator live-test round held in a gitignored quarantine
(`livesting-*/`, AGENTS.md constitution #9). **This document is deliberately scrubbed**: no customer
schema names, database identifiers, usernames, hosts, regions, or package names appear here. Where the
report named a customer object, this annex says "the field schema" or "a customer package".

**Baseline at time of grounding:** oraclemcp `main` @ `6da3997`, driver `main` @ `d99927d` — both pushed
after a full green gate (clippy + tests, both repos, 169 test binaries, 0 failures).

---

## 0. The systemic finding (most important)

Three independent investigations converged on one structural defect in how this repo tests:

> **Tests construct the client side using the same internal helper the server side consumes.**

| Area | The self-reference | Consequence |
|---|---|---|
| mTLS allow-list | test builds `format!("mtls:{}", cert_fingerprint_sha256(...))`, which already returns `sha256:<lowerhex>` | never exercises an operator-authored spelling |
| OAuth | every test token minted by the in-module `mint()` + in-module `hmac_sha256`/`b64url_encode` | proves internal consistency; cannot prove an external client can mint an acceptable token |
| stdio init token | tests interpolate the `INIT_TOKEN_META_KEY` **constant** | would pass identically if the key were renamed to something undiscoverable |
| session statements | `connect.rs:831-857` asserts on `build_session_context(...)` output; never opens a connection | the `protected`-profile ordering interaction (§2.2) is structurally unexercised |

Each proves **round-trip self-consistency**; none proves **external reachability**.
GroundAuth's summary: *"Every feature works; none is reachable from outside the repo."*

This is why 169 green test binaries coexisted with four transport-auth features an integrator could
not use, and it is the strongest argument for the two new pillars in the plan:

1. **Wire-contract fixtures** — literal JWTs minted by an external tool, literal `initialize` JSON
   frames, hand-spelled uppercase fingerprint allow-lists, committed as opaque strings. They pin the
   *contract*, not the round trip. Cheap, offline, and would have caught 3 of 4 transport findings.
2. **A local live environment** — for the classes that genuinely need a database (§2, §3).

---

## 1. Unification: one lock causes both P0-1 and P1-13

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
   detected (see §5.4 — the online route already exists).
3. **Lock granularity** (larger, optional): per-operation locks, or let the running service serve
   config/credential mutations. Note `clients.json` is loaded **once** at open
   (`client_credentials.rs:339`) with no reload/watch, so out-of-process mutation would not propagate
   to a running server anyway — granularity work must include reload.

### Test that would have caught it
A CLI-vs-running-server collision test: start a server, then run `setup --write` and
`clients revoke` and assert on a *specific, actionable* error. **None exists** — all store tests run
offline with no contention; operator-API tests call handlers in-process.

---

## 2. P0-4 "VPD-protected objects read as EMPTY" — four defects, and the report's root cause is wrong

### 2.1 REFUTED: session statements are NOT run on a different session
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

### 2.2 VERIFIED ORDERING DEFECT — `SET TRANSACTION READ ONLY` precedes trusted setup
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

### 2.3 VERIFIED FAIL-OPEN in the VPD refusal gate (security-relevant)
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

### 2.4 VERIFIED: zero rows drops `columns` (independent bug)
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

### 2.5 `oracle_describe` is catalog-based, so VPD cannot empty it
`crates/oraclemcp-db/src/intelligence.rs:1349-1367` reads `ALL_TAB_COLUMNS`; constraints `:1376-1385`
over `ALL_CONSTRAINTS` ⨝ `ALL_CONS_COLUMNS`; owner/table `to_ascii_uppercase()` (`:1362-1363`).

Therefore `{"columns":[],"constraints":[]}` does **not** indicate a VPD-context problem — it indicates
the object is **not visible in `ALL_TAB_COLUMNS`** for the computed `(owner, table_name)`. Also
**fail-silent**: not-found returns `Ok(vec![])` (empty success, not an error). An unresolved synonym
name likewise returns empty, and `to_ascii_uppercase()` silently misses quoted lower-case identifiers.

**Fix:** return a structured not-found / not-visible instead of `Ok(vec![])`.

### 2.6 LATENT (ruled out for this round): CLIENT_IDENTIFIER clobber
`crates/oraclemcp-db/src/lease.rs:271-283` inverts the order — login statements (`:271-273`) then
`session_tag_statements` (`:281-283`), whose first element is `DBMS_SESSION.CLEAR_IDENTIFIER`
(`lease.rs:83-85`) followed by `SET_IDENTIFIER` (`:98`). `CLIENT_IDENTIFIER` is *the* canonical Oracle
key for pooled-application VPD.
**But `LeaseManager::acquire` has no production caller** — every call site is a test. Real latent bug;
not this field symptom. (Contrast the safe path: `apply_session_identity` runs *before*
`session_statements` — `connection.rs:1580` vs `:1584`.)

### 2.7 Ranked hypotheses for the field symptom
| # | Hypothesis | Confidence | Decided by |
|---|---|---|---|
| H1 | **The two clients are not the same Oracle principal** (user or enabled roles). Explains VPD emptiness **and** empty describe with one cause, since data-VPD cannot empty `ALL_TAB_COLUMNS`. | High | live `SESSION_USER` + `SESSION_ROLES` diff |
| H2 | **VPD gate fails open** on a blind `ALL_POLICIES` probe (§2.3) → executed and silently emptied instead of refused. Explains `0 rows, exit-success` rather than an error. | High | `ALL_POLICIES` visibility |
| H3 | **Ordering defect** (§2.2) → `ORA-01456`, plausibly surfacing as the observed error. | Med-High | does the customer package perform DML |
| H4 | **Per-request `ROLLBACK`** (§2.8) undoes table-backed/global context. | Medium | same as H3 |
| H5 | CLIENT_IDENTIFIER clobber (§2.6) | Low — no prod caller | ruled out |

H1 and H2 are **complementary, not competing**; together they explain every symptom without assuming
anything about the customer's package.

**Cheapest decisive next step (no code change):** the server already ships the diagnostics —
`SESSION_CONTEXT_SQL` (`catalog_resolver.rs:31-33`: `SESSION_USER` / `CURRENT_SCHEMA` /
`CURRENT_EDITION_NAME`) and `SESSION_ROLES_SQL` (`:35-36`). Run both through each client and diff →
settles H1 immediately. Add an `ALL_POLICIES` probe → settles H2.

### 2.8 What resets state between setup and query
`crates/oraclemcp/src/dispatch/read_only_backstop.rs:40-46`: `ensure_armed` issues **`ROLLBACK`** then
`SET TRANSACTION READ ONLY` **before every READ_ONLY request**. `DBMS_SESSION.SET_CONTEXT` on a plain
namespace survives; table-backed / global context does not. Scoped to the pinned session
(`read_only_backstop.rs:29-33`).

Two connection surfaces exist (`dispatch/mod.rs:499-500`): pinned `conn` vs `stateless_conn`
(metadata), selected at `:12355-12359`. `oracle_query` → pinned; `oracle_describe` → **stateless when
`[profiles.pool]` is set**. Same options, **divergent transaction state** — worth pinning in tests.

---

## 3. P1-14 — the PL/SQL function surface is unusable at READ_ONLY (fully by design)

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

## 4. P0-5 — a pooled connection that dies while idle is never replaced

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

## 5. Transport-auth cluster (P1-10 .. P1-13)

**None of the pre-baseline commits touched any of these paths** — `serve.rs`, `tls.rs`,
`admin_auth.rs`, `oauth_rs.rs`, `init_token.rs`, `client_credentials.rs`, `oraclemcp-config/src/lib.rs`
were all untouched. Nothing in flight addressed them.

### 5.1 P1-10 mTLS / control listener — VERIFIED, root cause found
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

### 5.2 P1-11 OAuth HS256 — REFUTED as a code defect
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

### 5.3 P1-12 stdio init token — VERIFIED, pure discoverability failure
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

### 5.4 P1-13 credential lifecycle — cause verified, premise PARTLY REFUTED
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

## 6. Still to ground (carry into the plan)

| Finding | What is missing |
|---|---|
| **P0-2** flashback quarantine | Is the capability probe before or after the point of no return? Exact site where a cleanly-refused optional feature becomes a discarded connection. |
| **P0-3** dashboard `Origin: null` | Where `Referrer-Policy: no-referrer` is set; the second `dashboard_same_origin_required` check; the minimal change that accepts `Origin: null` on loopback + valid one-time code **without weakening the fail-closed posture**. |
| **P1-1** `user[schema]` proxy syntax | Where `username` is parsed; where to add desugaring or a fail-fast diagnostic. |
| **P1-2** driver wallet-only trust store | Confirm platform roots excluded; minimal change to add them while keeping the wallet authoritative. |
| **P1-3** terminal errors retried into a timeout | **Do pushed driver commits `880134e` ("fail fast on configuration errors") + `d99927d` ("prove configuration errors precede public dial") already close this and driver bead `rust-oracledb-4sfc`?** Highest-value open question — it changes release scope. |
| **P1-8** session-record leak | Confirm no logoff/teardown counterpart to the connect-side hooks; abrupt transport close vs missing logical Oracle logoff (cross-check driver bead `rust-oracledb-s0se`). |
| **P1-9** audit chain wrote nothing | Exact condition under which the audit sink silently no-ops, and why doctor check 13 reports healthy — i.e. whether doctor prints an audit path it never verified (**a "gate that lies"**). |
| **P0-5** | Driver default `ping_interval_secs`. |

---

## 7. Plan implications (summary)

1. **P0-1 and P1-13 are one fix** (§1) — error mapping first, lock granularity second.
2. **P0-4 is four fixes** (§2), of which the **fail-open VPD gate** (§2.3) is a security defect and the
   **ordering defect** (§2.2) is catchable offline in one line today.
3. **P1-10 unblocks P1-13** (§5.1, §5.4) — sequence them together.
4. **P1-11 is documentation + diagnostics**, not a verifier rewrite (§5.2).
5. **P0-5 is configuration, not new machinery** (§4) — the driver already validates on checkout.
6. **The dominant theme of the whole round** — correct behaviour reported through a misleading message —
   is cheap to fix and, per the tester, would return more value per line changed than any 0.8.0/0.9.0
   feature. Every §here has a concrete instance.
7. **Wire-contract fixtures + a local live environment** are the structural answer to §0; without them
   this class recurs no matter how many of the above we fix.
