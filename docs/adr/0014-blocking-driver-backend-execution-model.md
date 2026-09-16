# ADR 0014 — Synchronous Oracle backend uses a quarantining connection actor

## Status

Accepted. The feature-gated official-driver adapter and its acquisition router
are implemented. On 2026-09-16 the operator superseded the proposed default
flip: driver-cx remains the safe primary, while the official driver remains an
actively tried, bounded alternate for capable password and PEM-wallet
acquisitions. The decision does not permit a deadline/thread-leak exception, a
statement retry, or removal of the permanent driver-cx routes.

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
After an actor sends an operation reply, it waits for the caller's one-shot
completion acknowledgement before admitting another mailbox command. A healthy
caller acknowledges only after its post-completion `Cx` checkpoint; a cancelled
or dropped caller closes the acknowledgement, quarantining and retiring the
actor before a queued second operation can execute.
Explicit connection close is a terminal actor operation. An unrecovered row
stream's destructor cannot await, so it synchronously quarantines the session
and makes a best-effort bounded discard wakeup; whether that wakeup enqueues or
finds a command already queued, the actor drops its thread-owned resource and
exits without reusing the session.
The actor boundary catches a panic from its synchronous factory/runtime/command
path, quarantines the session, and lets the owner thread retire instead of
unwinding through a caller-facing runtime.

Automatic cross-driver routing is restricted to connection acquisition.
Driver-cx is the primary acquisition for every capability. For compatible basic
or PEM authentication only, a driver-cx acquisition error may make one guarded
official-driver alternate attempt and, if that alternate fails, one fresh
driver-cx fallback attempt. IAM/OCI-ADB tokens, `cwallet.sso` auto-login,
external/proxy, and other driver-cx-only authentication never reach the
official adapter. The router never retries a statement or transfers an opened
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
`cancelled_completed_reply_never_admits_a_queued_second_caller` proves the
completion acknowledgement closes the former reply-to-next-admission race: the
cancelled first caller quarantines the actor, the queued second caller does not
execute, and it observes the quarantined outcome.

`connection.rs` owns a small typed backend registry. In an `oracledb` feature
build, driver-cx is first for every acquisition. A compatible password/PEM
driver-cx error may use the registry's official alternate; that alternate
enters `OfficialOracleConnection::connect` only through the bounded guard
below. An alternate failure gets exactly one fresh driver-cx acquisition while
the caller remains live. IAM tokens, external/proxy auth, and `cwallet.sso`
auto-login have no official registration and therefore select driver-cx only.
The official adapter independently re-checks for `cwallet.sso` on its owner
thread immediately before it builds an official configuration, so a wallet that
changes after selection is refused at the consumption boundary rather than
being silently treated as PEM-capable.
`late_cwallet_appearance_refuses_official_config_before_consumption` proves a
directory observed as PEM-eligible at selection is rejected when
`cwallet.sso` appears before official configuration consumption.
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

Driver-cx is intentionally permanent in this design. It is the default primary
for every connection and the direct-only backend for IAM/OCI-ADB tokens and
`cwallet.sso` auto-login. It is also the single fresh, logged safety fallback
when the guarded official alternate cannot be used. The router registration and
its adjacent fallback branch must remain. There is no Tier-3 driver-cx
retirement plan in this ADR; any future removal needs a new operator decision
after every direct and fallback capability has an official replacement.

## Active dual-driver disposition

The 2026-09-16 decision keeps `oracledb` opt-in at compile time and keeps
driver-cx first when that feature is enabled. The official driver is not
shelved: a compatible driver-cx acquisition error actively tries it through
the bounded connection guard. This does not authorize a statement retry, an
in-session migration, or driver-cx removal. The router remains
acquisition-only:

| Authentication/configuration | Current route | Evidence status |
| --- | --- | --- |
| Basic username/password | driver-cx primary; guarded official alternate after a driver-cx acquisition error | Direct dual-backend local-lab proof for connect, query, transaction, errors, and close; password profile matrix evidence |
| TLS/TCPS with PEM wallet | driver-cx primary; guarded official alternate after a driver-cx acquisition error | The same direct dual-backend proof against a PEM wallet/SNI/DN-match lab profile remains live-required |
| OCI IAM / Autonomous DB token | driver-cx directly | Keep this route; it is outside official-driver capability until independently qualified |
| `cwallet.sso` auto-login | driver-cx directly | Keep this route; it is outside official-driver capability until independently qualified |
| External/proxy or other driver-cx-only auth | driver-cx directly | Keep this route; no silent degradation to password auth |

The feature-off registry contains only driver-cx. Its regression criterion is
that it continues to exercise the existing driver-cx-only path unchanged.

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
The following residual limits remain explicitly tracked:

- `oraclemcp-xoflp.1.6`: the pinned `26.0.0-beta.3` source invokes blocking
  `TcpStream::connect` for initial and redirected connections before a
  `Connection` exists. Its `tcp_connect_timeout` field is unused and its public
  `set_call_timeout` arrives only after connection establishment. Safe Rust
  cannot cancel or join a stalled foreign connect thread. The bounded guard
  below contains that beta limitation at the router boundary; it does not make
  the upstream call cancellable. An upstream driver fix or replacement version
  remains the only way to close the underlying driver finding.

- `oraclemcp-xoflp.4.8`: the feature-gated ignored TCPS + `ewallet.pem` parity
  target compiles and refuses an auto-login wallet, but no explicit PEM-only
  TCPS lab credentials are available on this host. It needs one opted-in
  direct driver-cx/official connect, ping, identity, and close run before the
  password+PEM default scope is fully evidenced.

The pinned official driver is also `26.0.0-beta.3`; the beta API/version risk
remains a release-signoff consideration even if all behavioral rows pass.

### Bounded official-connect guard — implemented operator decision

The guard is one process-global, Cx-aware semaphore with exactly **two** slots.
An official alternate waits for a slot for at most **250 ms**, further limited
by the caller's remaining absolute `Cx` deadline. An exhausted guard is a
bounded acquisition failure: the router records the reason and makes the one
fresh driver-cx safety fallback only while the caller remains live. It never
starts a third official actor.

The slot moves into the actor resource before `oracledb::connect` begins. It is
released immediately after a successful connection plus required session setup
has been installed, so healthy open official sessions do not consume guard
capacity. A failed, cancelled, or reply-dropped initial connection retains its
slot until the actor has discarded its resource and the native thread has
actually retired. The worst case is therefore at most **two** stranded native
official-connect threads process-wide (and their associated stack/socket
resources), never one per request. Later capable requests wait no more than
the 250 ms boundary before taking the driver-cx safety path. This is bounded
containment, not a claim that beta.3's initial connect is cancellable.

Deterministic native-thread regressions fill both sides of that contract: the
two-slot saturation test proves no third stalled actor starts and that retiring
the simulated stalls restores the exact baseline; router tests prove the
driver-cx-primary, official-alternate, and one-fresh-driver-cx sequence. No
query, execute, transaction, guard, audit, or dispatch call site changes.
