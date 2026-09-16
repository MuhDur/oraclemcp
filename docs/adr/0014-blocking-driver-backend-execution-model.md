# ADR 0014 — Synchronous Oracle backend uses a quarantining connection actor

## Status

Accepted. The feature-gated official-driver adapter and its acquisition router
are implemented; cross-backend parity remains the gate for any default flip.

## Context

Oracle's official `oracledb` 26.0.0-beta.3 driver is synchronous, while the
`OracleConnection` seam is asynchronous and `Cx`-first. The per-principal
Asupersync lane must not block its executor thread on an Oracle round trip.
There is no Tokio or `spawn_blocking` escape hatch in this architecture.

## Decision

Each official-driver physical connection will be created and owned by one
dedicated OS thread. The async adapter sends owned requests through a bounded
Asupersync `mpsc` mailbox and awaits an Asupersync `oneshot` reply. The
connection itself, raw driver values, and all synchronous calls remain on that
actor thread; `Cx` never crosses the thread boundary.

The adapter carries the earlier of the caller's `Cx` and per-request absolute
deadlines into each request. Immediately before the synchronous operation, the
actor samples the remaining duration and tightens the driver's call timeout to
the minimum of that fresh value and the configured profile cap. It checks the
absolute deadline before and after the synchronous operation. A caller
cancellation, expired deadline, dropped reply receiver, actor stop, or any
uncertain post-call state permanently quarantines that physical session as
`unknown_discarded`; it cannot re-enter a pool. Streaming already uses a bounded pull cursor: each
`next_row` request crosses the actor's bounded mailbox and returns at most one
owned row through its oneshot reply, so the caller controls backpressure without
the synchronous cursor or an unbounded row queue leaving the actor.
Explicit connection close is a terminal actor operation. An unrecovered row
stream's destructor cannot await, so it synchronously quarantines the session
and makes a best-effort bounded discard wakeup; whether that wakeup enqueues or
finds a command already queued, the actor drops its thread-owned resource and
exits without reusing the session.
The actor boundary catches a panic from its synchronous factory/runtime/command
path, quarantines the session, and lets the owner thread retire instead of
unwinding through a caller-facing runtime.

Automatic driver-cx fallback is restricted to connection acquisition. It may
select driver-cx directly for unsupported authentication, or retry one failed
official-driver connection establishment with driver-cx for compatible basic or
PEM authentication. It never retries a statement or transfers an opened
session across drivers.

## Evidence

`crates/oraclemcp-db/src/oracledb_actor.rs`, behind the optional `oracledb`
feature, proves the actor boundary with a non-`Send` fake connection. Its unit
tests prove dedicated-thread ownership, absolute-deadline refusal before a
blocking call, fresh deadline-budget sampling after mailbox queueing,
cancellation/reply-drop quarantine, and uncertain-error discard with no future
reuse. `oracledb_backend.rs` confines real synchronous driver calls, values,
and cursors to that actor. It additionally proves explicit terminal disposal
drops the resource and joins the actor, and that dropping an official row stream
quarantines, stops, and refuses reuse of its owner actor without a blocking
destructor. A blocking-call panic regression proves the same quarantine, thread
retirement, and no-reuse outcome.

`connection.rs` owns a small typed backend registry. In an `oracledb` feature
build, password/PEM acquisition tries the official backend first; IAM tokens,
external/proxy auth, and `cwallet.sso` auto-login select driver-cx directly.
Only a typed official acquisition gap (`unsupported_auth` or
`unsupported_feature`) can make one logged, fresh driver-cx connect attempt.
There is no fallback after a session has been returned, and no statement is
retried or migrated across drivers. Without the feature, the registry contains
only driver-cx and the connect path is unchanged.

This is native-thread evidence, not a Loom proof. Loom cannot model the
opaque Asupersync channel implementation together with its runtime-owned OS
thread; the later B1.3 proof must add a finite model around the actor state
machine before that bead can close.

## Consequences

- The default build does not enable or compile the official driver.
- The optional feature pins `oracledb` exactly at `26.0.0-beta.3`.
- The feature-gated backend selection is acquisition-only; the fail-closed SQL
  guard, operating-level ladder, transaction cleanup, and audit chain are
  unchanged and remain above the connection seam.
- The fail-closed SQL guard, operating-level ladder, rollback default,
  protected-profile clamp, OAuth scope reduction, audit chain, and
  NUMBER-to-string invariant stay above the future adapter and are unchanged.

## Retiring driver-cx after parity approval

After the operator accepts the cross-backend conformance evidence and signs
off on a default flip, retire driver-cx from selection by removing its one
`CONNECTION_BACKEND_REGISTRY` registration and the adjacent acquisition-only
fallback branch in `connection.rs`. No SQL/transaction call site may change:
they already consume the selected `OracleConnection` without knowing its
driver. Keep the existing driver-cx adapter until its remaining non-selector
capabilities (including the cx-only pool and CQN) have separately reached
official-driver parity; remove those registrations deliberately rather than
inventing statement-level fallback.

## Default-flip proposal — not approved

This is a decision record for the operator, not an authorization to change
Cargo defaults. `oracledb` stays opt-in and `driver-cx` remains the default
build/runtime until every criterion below is met and the operator explicitly
accepts the evidence.

### What a flip would mean

The proposed flip is **only** that a build including the official-driver
feature prefers the official adapter for its supported connection acquisitions.
It does not authorize a statement retry, an in-session migration, or an
unconditional driver-cx removal. The router remains acquisition-only:

| Authentication/configuration | Current route | Evidence needed before a flip |
| --- | --- | --- |
| Basic username/password | Official first when `oracledb` is enabled | Direct dual-backend local-lab proof for connect, query, transaction, errors, and close; password profile matrix evidence |
| TLS/TCPS with PEM wallet | Official first when `oracledb` is enabled | The same direct dual-backend proof against a PEM wallet/SNI/DN-match lab profile |
| OCI IAM / Autonomous DB token | driver-cx directly | Keep this route; it is outside official-driver capability until independently qualified |
| `cwallet.sso` auto-login | driver-cx directly | Keep this route; it is outside official-driver capability until independently qualified |
| External/proxy or other driver-cx-only auth | driver-cx directly | Keep this route; no silent degradation to password auth |

The feature-off registry contains only driver-cx. Therefore a flip must not
claim feature-off behavior changed; its regression criterion is that the
feature-off tests still exercise the existing driver-cx-only path unchanged.

### Required evidence

1. Both feature states pass the scoped `oraclemcp-db` suite, including the
   router/fallback tests and the deterministic official-driver type tests. The
   feature-off result is a compatibility requirement, not a lower bar.
2. The feature-on deterministic suite proves `NUMBER` is formatted directly
   from `OracleNumber` as the exact decimal string; it must never decode NUMBER
   through `f64`. It also proves the official VECTOR mapper emits the existing
   dense/sparse structured-cell contract and TSTZ bind/format handling preserves
   its offset.
3. A captured, explicitly opted-in local Free23 lab run of
   `cross_backend_parity` passes with both adapters connected directly using
   basic authentication. It compares the observable serialized result of a
   38-digit NUMBER, TSTZ, dense VECTOR, sparse VECTOR, missing-object error
   envelope, and DDL/DML rollback/commit sequence. The test is intentionally
   `#[ignore]`: selecting it without `ORACLEMCP_DUAL_BACKEND_LAB=1` and all
   local-lab credentials fails rather than converting absent infrastructure
   into a passing claim.
4. The analogous TCPS + PEM-wallet lab run passes, including the configured
   SNI and certificate-DN posture. The test record must identify the local
   lab/version and command, but never put a live OCI/customer identifier or
   secret in a tracked artifact.
5. The bounded live matrix records the remaining shared-trait semantics:
   timeout/cancel with uncertain-session quarantine, owned streaming/LOB
   recovery, close, identity, and the supported optional capability set. Each
   row must be `SUPPORTED`, `UNSUPPORTED(reason)`, or `BLOCKED(reason)`; an
   unrun case is `BLOCKED`, never implied supported.
6. Required gates remain green: formatting, scoped lint/test lanes, release
   surface synchronization, and the required feature-off lane. Advisory
   Windows, mutation, changed-line coverage, public-API, and PL/SQL lanes stay
   advisory by operator decision.

### Current evidence and residual risks

On 2026-09-16, the explicitly selected local Free23 basic-auth run passed
against independent driver-cx and official connections. It proved session
identity, exact NUMBER/TSTZ serialization, dense and sparse VECTOR
serialization, missing-object error-envelope parity, and classified
DDL/DML rollback/commit behavior. The target creates and drops uniquely named
local VECTOR tables; it does not credit an absent pre-seeded fixture. This is
one basic-auth row, not a qualified matrix. TCPS + PEM remains live-required
and uncredited.

The Free23 run closed the observed VECTOR gap
(`oraclemcp-xoflp.1.3`) and exposed/fixed the beta driver's malformed
negative-minute timestamp display in the adapter. The actor-admission timeout
gap (`oraclemcp-xoflp.1.4`) is resolved: the actor samples the copied absolute
deadline immediately before dispatch, and the adapter can only tighten the
existing driver timeout. The deterministic queued-command regression asserts
that time spent in the bounded mailbox is deducted before the driver sees its
timeout.
The actor-lifecycle gap (`oraclemcp-xoflp.1.5`) is resolved: explicit close is
terminal, while an unrecovered official stream uses a nonblocking drop
disposition that quarantines and retires the actor. Unit regressions prove the
resource is dropped, the thread joins, and subsequent actor calls are refused.
The actor-startup gap (`oraclemcp-xoflp.1.10`) is resolved: native thread
creation is fallible and reports a stable redacted `DbError::Connect` rather
than panicking. The injected launcher-failure regression proves that no actor
handle escapes and the thread-confined resource factory is never run.
The DATE/plain-TIMESTAMP adapter gap (`oraclemcp-xoflp.1.8`) is resolved:
the official column type selects zone-less component formatting for DATE and
plain TIMESTAMP, while LTZ/TSTZ retain their offset-bearing representation.
Deterministic adapter and public-serialization regressions prove that a
zero-valued internal offset cannot fabricate UTC. The separate live basic-auth
parity row is present but remains required evidence until its ignored Free23
lab target is explicitly run.
The following review findings remain default-flip blockers until independently
resolved and tested:

- `oraclemcp-xoflp.1.6`: the pinned `26.0.0-beta.3` source invokes blocking
  `TcpStream::connect` for initial and redirected connections before a
  `Connection` exists. Its `tcp_connect_timeout` field is unused and its public
  `set_call_timeout` arrives only after connection establishment. Safe Rust
  cannot cancel or join a stalled foreign connect thread, so a watchdog would
  violate the no-thread-leak contract. An upstream driver fix or an approved
  replacement version is required before this blocker can close.

The pinned official driver is also `26.0.0-beta.3`; the beta API/version risk
remains a release-signoff consideration even if all behavioral rows pass.

### Retire path after a future approval

Once the operator approves an official-first default and every direct
driver-cx capability has an official replacement, removal remains localized:
delete the driver-cx registration in `CONNECTION_BACKEND_REGISTRY`, delete the
adjacent acquisition-only fallback branch, remove the driver-cx dependency and
feature wiring, then run the same contract matrix. No query, execute,
transaction, guard, audit, or dispatch call site should change. Until IAM,
auto-login wallets, CQN/pool behavior, and other driver-cx-only capabilities
are separately qualified, a default flip is not a driver-cx retirement.
