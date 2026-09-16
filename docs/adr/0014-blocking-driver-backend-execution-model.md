# ADR 0014 — Synchronous Oracle backend uses a quarantining connection actor

## Status

Accepted. The feature-gated official-driver adapter and its acquisition router
are implemented. On 2026-09-16 the operator approved an official-primary
default for capable password and PEM-wallet acquisitions, subject to the
remaining explicit safety and live-parity blockers below. That approval does
not permit a deadline/thread-leak exception, a statement retry, or removal of
the permanent driver-cx routes.

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

## Permanent driver-cx fallback

Driver-cx is intentionally permanent in this design. It remains the direct
backend for IAM/OCI-ADB tokens and `cwallet.sso` auto-login, and the one fresh,
logged acquisition fallback when a capable official connection has a typed
driver gap. The router registration and its adjacent fallback branch therefore
must remain after the default flip. There is no Tier-3 driver-cx retirement
plan in this ADR; any future removal needs a new operator decision after every
direct and fallback capability has an official replacement.

## Default flip — operator-approved, implementation gated

The 2026-09-16 operator direction authorizes changing the default after the
remaining safety and live-parity blockers are actually closed. `oracledb`
remains opt-in in the current tree until that implementation commit lands;
the criteria below are landing gates, not a second request for authorization.

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
identity; exact NUMBER, TSTZ, DATE, and plain-TIMESTAMP serialization; dense
and sparse VECTOR serialization; missing-object error-envelope parity; and
classified DDL/DML rollback/commit behavior. In particular, DATE remained
`2026-06-01T12:00:00` and plain TIMESTAMP remained
`2026-06-01T12:00:00.123456789`, with no fabricated UTC suffix. The target
creates and drops uniquely named local VECTOR tables; it does not credit an
absent pre-seeded fixture. This is one basic-auth row, not a qualified matrix.
TCPS + PEM remains live-required and uncredited.

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
parity row has now passed against the local Free23 fixture.
The following review findings remain default-flip blockers until independently
resolved and tested:

- `oraclemcp-xoflp.1.6`: the pinned `26.0.0-beta.3` source invokes blocking
  `TcpStream::connect` for initial and redirected connections before a
  `Connection` exists. Its `tcp_connect_timeout` field is unused and its public
  `set_call_timeout` arrives only after connection establishment. Safe Rust
  cannot cancel or join a stalled foreign connect thread, so a watchdog would
  violate the no-thread-leak contract. An upstream driver fix or an approved
  replacement version is required before this blocker can close.

- `oraclemcp-xoflp.4.8`: the feature-gated ignored TCPS + `ewallet.pem` parity
  target compiles and refuses an auto-login wallet, but no explicit PEM-only
  TCPS lab credentials are available on this host. It needs one opted-in
  direct driver-cx/official connect, ping, identity, and close run before the
  password+PEM default scope is fully evidenced.

The pinned official driver is also `26.0.0-beta.3`; the beta API/version risk
remains a release-signoff consideration even if all behavioral rows pass.

### Connection-establishment mitigation decision

The following alternatives address only the synchronous initial connect/TLS
handshake gap in the pinned official driver. None authorizes statement retry,
session migration, or a change to the existing feature-off driver-cx path.

1. **Keep driver-cx default until upstream supplies a bounded official
   connect/handshake (recommended).** Keep `oracledb` feature-gated and
   opt-in; do not make it the default selection while `TcpStream::connect` can
   outlive the request. An upstream version is acceptable only when its public
   configuration demonstrably bounds initial and redirected TCP plus TLS
   handshake work before a `Connection` exists, and a regression proves an
   expired/cancelled attempt retires its actor without leaving a session
   reusable. This is the safest option: the default continues to use the
   existing driver-cx transport timeout, and the official path remains an
   explicit preview rather than a process-wide availability risk.

2. **Flip behind a bounded official-connect thread pool.** This is feasible,
   but it is a containment mechanism rather than cancellation. A future
   implementation must use one process-global pool with exactly **two**
   in-flight official-connect permits, acquired through a Cx-aware bounded
   wait of at most **250 ms**. A caller that cannot acquire a permit in that
   time may make one fresh driver-cx acquisition attempt only if its original
   absolute Cx deadline is still live; an already-expired caller returns
   cancellation and never starts fallback work. Once an official connect has
   started, its permit is held until that native thread actually returns and
   its actor is retired/reaped—never when the caller times out or drops its
   reply. Thus a black-holed network can strand at most two native threads
   process-wide; all later capable acquisitions immediately take the
   backpressure/fallback path instead of spawning more. An eventually
   successful abandoned attempt must close/discard before releasing its slot,
   and no reply from it may publish a session. This option would require a new
   supervisor/reaper, an explicit typed `official_connect_capacity` fallback
   reason, and deterministic tests for permit exhaustion, deadline-before-
   fallback, abandoned-success discard, and slot release after thread exit.
   It does **not** satisfy the present no-thread-leak ideal; it merely caps the
   resource cost, so it needs a separate operator decision.

3. **Flip and accept the residual stall risk.** Every capable acquisition can
   currently spawn a new native actor before entering unbounded TCP/TLS work.
   A route or handshake black hole can therefore accumulate threads, their
   stacks and sockets, and later-completing unactioned sessions under normal
   connection pressure. Caller cancellation protects neither process capacity
   nor actor retirement. This has the largest availability blast radius and
   contradicts this ADR's quarantine/no-leak objective; it is documented only
   as an explicit risk acceptance, not an engineering recommendation.

No option has been implemented by this ADR update. Until an operator selects a
different option and its dedicated proof suite lands, option 1 governs: the
default remains driver-cx, and TCPS + PEM remains live-required rather than
credited from the compiled ignored test.

### No retirement path in the approved flip

The approved default flip deliberately keeps the driver-cx registration,
IAM/cwallet routes, and acquisition-only fallback branch. No query, execute,
transaction, guard, audit, or dispatch call site should change. A future
driver-cx retirement would be a separate proposal, not an implication of this
default flip.
