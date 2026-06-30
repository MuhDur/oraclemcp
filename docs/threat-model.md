# Threat Model — oraclemcp

This is *our own* security audit of `oraclemcp`, not an upstream claim. It is the
threat-model half of the D5 release gate: it enumerates the assets, the threats
against them, the mitigation that holds each threat in check, and — crucially —
the **committed test suite that keeps that mitigation honest**. Every mitigation
below names a file path you can run.

`oraclemcp` is **governed and least-privilege**: a fail-closed SQL classifier
gates an explicit operating-level ladder (`READ_ONLY < READ_WRITE < DDL <
ADMIN`), read-only by default and escalation-capable only through a single-use
confirmation-grant step-up bounded by each profile's ceiling. The model below
assumes the *agent driving the server is semi-trusted* — it may emit a statement
it believes is a read which, through injection or its own error, expresses a
write or an escalation. The defender's job is defense in depth so no single
misconfiguration is catastrophic.

Companion documents: the deployment-time controls checklist is
[`hardening.md`](hardening.md); the reporting policy and supported versions are
in the repo-root [`SECURITY.md`](../SECURITY.md); the architecture decisions are
the [ADRs](adr/); release-blocking severity is defined in
[`severity-policy.md`](severity-policy.md).

## Assets

| Asset | Why it matters |
|---|---|
| **A1 — the Oracle database and its data** | The system of record. Unauthorized writes (DML/DDL/DCL) or reads beyond the agent's remit are the primary harm. |
| **A2 — connection credentials and secrets** | DB credentials, OAuth HS256 secret, the audit signing key, SIEM tokens. Leakage enables impersonation or audit forgery. |
| **A3 — the audit chain** | The tamper-evident record of every privileged action. Its integrity is what lets an operator *prove* what ran. |
| **A4 — the agent's reasoning context** | Untrusted row data flowing back to the agent could carry injected instructions (prompt injection). |

## Trust boundaries

1. **Agent ⇄ server** — the MCP transport (stdio: the parent process is the
   trust boundary; HTTP: OAuth-enforced, fails closed without auth or an
   explicit dev opt-in).
2. **Server ⇄ Oracle** — the driver-adapter seam ([ADR 0002](adr/0002-driver-adapter-seam.md));
   all SQL crosses the classifier first.
3. **Server ⇄ audit destination** — the out-of-band signed log, optionally
   shipped to an external WORM/SIEM.
4. **Operator ⇄ config** — profiles, ceilings, secrets, and signed custom tools.

## Threats, mitigations, and evidence

STRIDE tags: **S**poofing, **T**ampering, **R**epudiation, **I**nformation
disclosure, **D**enial of service, **E**levation of privilege.

### T1 — Classifier bypass / over-acceptance (T, E; asset A1)

*Threat.* A crafted statement (comment tricks, multi-statement, quoting games,
`ALTER SESSION` smuggling) is misclassified as a read and runs at a level it
should not.

*Mitigation.* The classifier is **fail-closed**: anything it cannot prove
read-only at the current level is treated as dangerous. The `ALTER SESSION SET`
allowlist validator never over-accepts. See
[ADR 0004](adr/0004-governed-operating-level-ladder.md).

*Evidence (green; CI):*
- `crates/oraclemcp-guard/tests/adversarial_corpus.rs` — adversarial bypass
  corpus (comment/quote/multi-statement tricks).
- `crates/oraclemcp-guard/tests/proptest_invariants.rs` — property-based
  invariants (every classified statement carries a coherent required level;
  determinism).
- `crates/oraclemcp-guard/tests/admin_dcl_fail_closed.rs` — DCL/admin shapes
  fail closed.
- `crates/oraclemcp-guard/fuzz/fuzz_targets/classify_fuzz.rs` — libFuzzer target:
  arbitrary input never panics; `Forbidden` carries no runnable level;
  classification is deterministic.
- `crates/oraclemcp-guard/fuzz/fuzz_targets/alter_session_parse.rs` —
  **differential** fuzz target: the allowlist validator never clears a statement
  whose assigned-parameter set escapes an independent quote-aware scan.

> Fuzzing gate: the targets **compile in CI** (`fuzz-build` job in
> `.github/workflows/ci.yml`) and ship a committed seed corpus. A long fuzzing
> *campaign* is operator/CI-scheduled, not asserted here — compile + the seed is
> the gate, and a divergence found by the differential target is a REPORT
> signal, not a silent fix.

### T2 — Privilege escalation past the profile ceiling (E; assets A1, A2)

*Threat.* A client coerces the server above the profile's `max_level`, or a
read-only-standby profile is elevated.

*Mitigation.* The operating-level ladder is capped by each profile's `max_level`;
escalation requires a TTL-bounded single-use confirmation grant (no out-of-band device 2FA);
`protected` profiles are pinned at `READ_ONLY`; OAuth scopes can only *lower* the
effective ceiling; A9 capability narrowing reduces the surface to the read path.
A1's least-privilege DB account is the backstop ([ADR 0004](adr/0004-governed-operating-level-ladder.md)).

*Evidence (green; CI):*
- `crates/oraclemcp-guard/tests/token_security.rs` — confirmation-grant
  security (TTL, single-use, binding).
- `crates/oraclemcp-db/tests/privilege_degradation.rs` — degrade-on-loss-of-
  privilege behavior.
- `crates/oraclemcp-core/src/capability.rs` (`narrow_to_read_path`,
  `requires_privileged_effect`) with its unit tests — capability narrowing.

### T3 — SQL injection via tool parameters (T, E; asset A1)

*Threat.* Bind values or identifiers injected through tool parameters change the
statement's meaning.

*Mitigation.* Bind-first execution; identifier validation
(`is_simple_identifier`) on the audit/unified path; the classifier runs on the
*exact* SQL bytes. Custom tools are classified at load and only loaded if proven
`READ_ONLY`, and (on `protected` profiles) must carry a valid HMAC signature.

*Evidence (green; CI):*
- `crates/oraclemcp-audit/src/unified.rs` tests
  (`identifier_validation_rejects_injection`, `policy_rejects_bad_identifiers`,
  `trail_query_is_bind_first`).
- `crates/oraclemcp-core/src/custom_tools.rs` — `classify_at_load` /
  `enforce_signature` with unit tests.

### T4 — Cancellation-torn commit (T, D; assets A1, A3)

*Threat.* A lease expiry, client cancel, or shutdown mid-transaction leaves a
partially-applied write committed, or commits a preview that should have rolled
back.

*Mitigation.* Structured cancellation through the asupersync `Cx`; on
shutdown/lease-drain every open transaction is force-rolled-back; preview DML is
`SAVEPOINT → DML → ROLLBACK TO SAVEPOINT` and never commits. Served committing
tools (`oracle_execute`, `oracle_compile_object`, `oracle_create_or_replace`,
`oracle_patch_source`) append the audit record before database mutation and fail
closed if that durable append fails (at-least-once log, at-most-once execute).

*Evidence (green; CI):*
- `crates/oraclemcp-db/tests/cancel_correctness.rs` — B1 cancel correctness.
- `crates/oraclemcp-db/tests/chaos.rs` and `crates/oraclemcp-core/tests/chaos.rs`
  — chaos/cancel-under-load (no torn commit, clean drain).
- `crates/oraclemcp-db/tests/load_soak.rs` — the offline net-load + shutdown soak
  asserting zero-leaked-sessions / clean-drain / bounded / no-torn-commit.
- `crates/oraclemcp/src/dispatch/tests.rs::audit_wiring` — served
  execute/compile/patch dispatch appends Pending then signed outcome, and audit
  write failure refuses compile/patch before DB execution.
- `crates/oraclemcp/src/dispatch/tests.rs::lifecycle_close_rolls_back_and_revokes_execution_grants`
  — lane close rolls back, revokes stale execution grants, and records a
  hash-covered structured close reason.

### T5 — Audit forgery / repudiation (T, R; asset A3)

*Threat.* An actor with write access to the audit log edits a record, reorders
the chain, or recomputes hashes from genesis to hide an action.

*Mitigation.* The log is **hash-chained and HMAC-SHA256-signed**: `entry_hash`
covers the seq + content + `prev_hash` (catches in-place edits and reorders),
and the keyed MAC over `entry_hash` (which a forger without the key cannot
reproduce) catches a recompute-from-genesis forgery. The monotonic `seq`, not
the wall clock, is the order key. `oraclemcp audit verify` re-walks and checks
all three. Optional WORM/SIEM shipping (D2) makes tampering detectable at an
independent destination ([ADR 0003](adr/0003-keyed-mac-audit-chain.md)).

*Evidence (green; CI):*
- `crates/oraclemcp-audit/src/record.rs` tests (in-place edit detected;
  `sql_preview` forgery detected; recompute-from-genesis caught by the MAC;
  wrong key fails).
- `crates/oraclemcp-audit/src/verify.rs` tests (hash-link / monotonic-seq /
  keyed-MAC verification; rotated keys verify end to end).
- `crates/oraclemcp-audit/src/shipping.rs` tests (forwarded/WORM stream
  re-verifies; a forwarding failure never loses the local durable record; local
  fsync failure skips forwarding).

### T6 — Secret leakage via logs / telemetry / errors (I; asset A2)

*Threat.* A bind value, password, wallet secret, or token ends up in a log line,
an OTLP export, or an agent-facing error.

*Mitigation.* The audit record stores only the SQL **SHA-256 + a truncated
preview**, never bind values. `OracleBind` and `OracleConnectionInfo` have
redacting `Debug` implementations plus explicit redacted serializers for
audit/proof/log/protocol surfaces. Telemetry redaction drops sensitive keys and
redacts secret-shaped values before export. Secrets are resolved from
`env:`/`file:`/`keyring:` refs (dev-only `literal:` is rejected on `protected` profiles;
`vault:` is a future fail-closed backend seam).
`SigningKey` redacts its bytes in `Debug`.

*Evidence (green; CI):*
- `crates/oraclemcp-telemetry/src/otlp/redact.rs` and the logs-redaction tests in
  `crates/oraclemcp-telemetry/src/otlp/logs.rs`
  (`secret_attributes_are_dropped_and_bodies_redacted`).
- `scripts/sensitive_data_lint.sh` — repo-level sensitive-data lint.
- `crates/oraclemcp-db/src/types.rs` — redaction newtypes and sentinel tests for
  bind values plus connection identity/topology fields.
- `crates/oraclemcp-audit/src/record.rs` —
  `record_hashes_and_previews_without_storing_sql_verbatim`.

### T7 — Prompt injection via row data (T; asset A4)

*Threat.* Untrusted database content (a column value) carries instructions that
the agent re-interprets as its own directive.

*Mitigation.* Output fencing (A6) wraps returned row data so it is presented as
data, not instructions, and the trust-block injector marks the boundary.

*Evidence (green; CI):*
- `crates/oraclemcp-core/src/fence.rs` with its unit tests — output fencing.

### T8 — Transport spoofing / unauthenticated access (S, E; assets A1, A2)

*Threat.* An unauthenticated or spoofed caller reaches `/mcp` over HTTP.

*Mitigation.* The HTTP listener **fails closed**: it will not bind without OAuth
2.1 bearer enforcement or an explicit `--allow-no-auth` dev opt-in; non-loopback
binds require `ORACLEMCP_HTTP_ALLOW_REMOTE=1`; `Host`/`Origin` allowlists; native
rustls TLS and optional mTLS. stdio's trust boundary is the parent process.

*Evidence (green; CI):*
- `crates/oraclemcp-core/src/http.rs` (OAuth enforcement, scope grants,
  readiness) with its unit tests.
- `crates/oraclemcp-core/src/tls.rs` — TLS/mTLS material handling with tests.
- `crates/oraclemcp/src/main.rs` startup fail-closed checks (HTTP without auth is
  refused).

### T9 — Resource exhaustion / DoS (D; asset A1)

*Threat.* Unbounded sessions, runaway queries, or telemetry backpressure starve
the server or the database.

*Mitigation.* Per-DB session ceiling and lease accounting; request budgets and
timeouts; the OTLP export pump is bounded with newest-drop load shedding and a
bounded shutdown budget (telemetry failure never blocks the request path).

*Evidence (green; CI):*
- `crates/oraclemcp-db/tests/load_soak.rs` — bounded / zero-leak invariants.
- `crates/oraclemcp-core/src/request_budget.rs` — request budget with tests.
- `crates/oraclemcp-telemetry/src/otlp/pump.rs` —
  `submit_is_non_blocking_and_shutdown_is_bounded`, `overflow_drops_newest_and_counts`.

### T10 — Cross-profile exposure (I, E; assets A1, A2)

*Threat.* The agent reaches a connection profile the operator did not intend to
surface — an operator-only or privileged target — by enumerating, switching to,
searching, or completing its name through the served surface.

*Mitigation.* E5 connection-scope isolation: a profile can be scoped out of the
agent-facing surface with `mcp_exposed = false` (a **per-profile opt-out** —
profiles are exposed by default; only an explicit `false` hides one). A hidden
profile is invisible to every served path — `oracle_list_profiles`,
`oracle_switch_profile`, `oracle_search_objects`, and `completion/complete` — so
a hidden or guessed name fails closed identically (the served lookup goes through
`mcp_profile`, which returns `None` for a non-exposed profile). One profile's
setting never affects another's, and the operator/CLI still sees every profile.

Exposure is a **visibility/scoping convenience, not the access boundary.** The
enforced bound on what a reachable profile can do remains the operating-level
ladder — `max_level` / `protected` (pinned `READ_ONLY`) / `read_only_standby` /
the underlying least-privilege DB account / the fail-closed classifier (T1, T2).
So hide the privileged target *and* keep it genuinely least-privileged; do not
treat `mcp_exposed` as a substitute for a low `max_level`. A behavior-neutral
startup line (`MCP exposing N profile(s): …`, to stderr) lets the operator
confirm at a glance which profiles — and ceilings — the agent can reach.

*Evidence (green; CI):*
- `crates/oraclemcp-config/src/lib.rs` tests
  (`mcp_exposure_defaults_open_and_hides_only_explicit_false`,
  `mcp_exposure_has_no_global_flip`, `mcp_exposed_inherits_through_base`) — the
  default-open opt-out, the no-global-flip invariant, and inheritance.
- `crates/oraclemcp-config/tests/example_config_parses.rs` — the shipped worked
  example (an exposed read-only profile beside a hidden privileged one) parses,
  validates, and the served list omits the hidden profile.

## Evidence summary — run it yourself

```sh
# Adversarial classifier + token + invariant suites (T1, T2, T3)
cargo test -p oraclemcp-guard

# Cancellation / chaos / soak (T4, T9)
cargo test -p oraclemcp-db   --test cancel_correctness --test chaos \
                             --test privilege_degradation --test load_soak
cargo test -p oraclemcp-core --test chaos

# Audit forgery + shipping tamper-evidence (T5)
cargo test -p oraclemcp-audit

# Fuzz targets COMPILE (T1) — the CI gate; a campaign is operator-run
cargo +nightly fuzz build --target x86_64-unknown-linux-gnu   # in crates/oraclemcp-guard
```

## Release gate status

Per the [severity policy](severity-policy.md), this audit is a release gate: no
open P0/P1 against the threats above, and any P2 must be fixed or carry a signed
exception. The mitigations are each backed by a green, committed suite (paths
above). The only deliberately *operator/CI-run* (not asserted-here) items are
(a) a long-running fuzz **campaign** beyond compile + the seed corpus, and
(b) live-database latency/chaos against a real 23ai, which is captured by the
`live-xe` harness and recorded in [`performance-footprint.md`](performance-footprint.md).
