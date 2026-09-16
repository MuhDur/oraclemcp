# ADR 0014 — Synchronous Oracle backend uses a quarantining connection actor

## Status

Accepted for the actor-bridge spike; the actual official-driver adapter remains
under qualification.

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

## Evidence in this increment

`crates/oraclemcp-db/src/oracledb_actor.rs`, behind the optional `oracledb`
feature, proves the actor boundary with a non-`Send` fake connection. Its unit
tests prove dedicated-thread ownership, absolute-deadline refusal before a
blocking call, and cancellation/reply-drop quarantine with no future reuse.
The bridge uses Asupersync's bounded `mpsc` and `oneshot` directly.

This is native-thread evidence, not a Loom proof. Loom cannot model the
opaque Asupersync channel implementation together with its runtime-owned OS
thread; the later B1.3 proof must add a finite model around the actor state
machine before that bead can close.

## Consequences

- The default build does not enable or compile the official driver.
- The optional feature pins `oracledb` exactly at `26.0.0-beta.3`.
- No SQL, type conversion, connection configuration, fallback routing, or
  `OracleConnection` implementation is introduced by this spike.
- The fail-closed SQL guard, operating-level ladder, rollback default,
  protected-profile clamp, OAuth scope reduction, audit chain, and
  NUMBER-to-string invariant stay above the future adapter and are unchanged.
