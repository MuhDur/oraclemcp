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

The adapter copies the caller's absolute `Cx` deadline into each request. The
actor checks it before and after the synchronous operation. The concrete
adapter will also tighten the driver's call timeout to the minimum of the
profile cap and remaining request deadline. A caller cancellation, expired
deadline, dropped reply receiver, actor stop, or any uncertain post-call state
permanently quarantines that physical session as `unknown_discarded`; it cannot
re-enter a pool. A bounded actor-to-caller stream channel will provide cursor
backpressure in the later streaming implementation.

Automatic driver-cx fallback is restricted to connection acquisition. It may
select driver-cx directly for unsupported authentication, or retry one failed
official-driver connection establishment with driver-cx for compatible basic or
PEM authentication. It never retries a statement or transfers an opened
session across drivers.

## Evidence

`crates/oraclemcp-db/src/oracledb_actor.rs`, behind the optional `oracledb`
feature, proves the actor boundary with a non-`Send` fake connection. Its unit
tests prove dedicated-thread ownership, absolute-deadline refusal before a
blocking call, cancellation/reply-drop quarantine, and uncertain-error discard
with no future reuse. `oracledb_backend.rs` confines real synchronous driver
calls, values, and cursors to that actor.

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
