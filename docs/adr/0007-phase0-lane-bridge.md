# ADR 0007: Phase-0 Lane Bridge For Non-Send Oracle Sessions

## Status

Accepted for the 0.6.0 WP-N / N0a implementation.

## Context

The 0.6.0 always-on work moves `oraclemcp` from one shared dispatch runtime and
one shared dispatcher state toward per-principal HTTP lanes. The Oracle driver
path is intentionally non-Send: connection ownership, transaction state,
rollback defaults, and the SQL guard must stay on one lane and must not be
polled by arbitrary transport workers.

DL-1 compared two candidate bridges for the non-Send lane boundary:

1. A dedicated OS thread per lane, with a current-thread asupersync runtime and
   an outermost `Runtime::block_on` loop that owns the non-Send connection.
2. `Scope::spawn_local` / `LocalStoredTask` on an asupersync local scheduler.

The real deadlock hazard is not `block_on` by itself. The hazard is nested
`block_on`: calling it from inside an async task, a scheduler worker, or a
transport runtime worker while the work being awaited needs that same runtime
to make progress.

## Prototype Evidence

Executable evidence lives in
`crates/oraclemcp-core/tests/lane_bridge_phase0.rs`.

`dedicated_thread_block_on_lane_keeps_non_send_connection_thread_local` creates a
non-Send `Rc<RefCell<_>>` Oracle-like connection on a named lane thread, drives
64 mailbox operations through bounded asupersync `mpsc`, replies through
oneshot `send_blocking`, and asserts all operations run on the lane owner
thread, not the caller thread. The test emits an NDJSON measurement event with
the candidate name, operation count, elapsed nanoseconds, owner thread, caller
thread, and verdict.

`spawn_local_bridge_requires_private_scheduler_context_from_consumer_code`
attempts the local-task candidate from this repository as a normal asupersync
consumer. The non-Send future compiles, but `spawn_local` returns
`LocalSchedulerUnavailable` because the required local scheduler TLS guards are
crate-private inside asupersync. The test asserts rollback of local task storage
and emits an NDJSON measurement event with the observed error and verdict.

## Decision

N0a will use the dedicated lane thread bridge.

Each lane owns:

- one OS thread,
- one asupersync current-thread runtime with an explicit native reactor,
- one outermost lane loop entered by `Runtime::block_on`,
- the lane-local Oracle connection/session state,
- a bounded command mailbox and oneshot replies for callers.

SAFETY: the lane `block_on` is the outermost call on the dedicated lane thread.
It is never invoked from an async task, a transport worker, or another runtime
worker. The non-Send connection is constructed inside the lane loop and never
crosses the mailbox boundary. The mailbox carries only Send command envelopes;
callers await replies on their own runtime instead of synchronously blocking a
worker thread.

`spawn_local` is rejected for N0a. It remains a valid asupersync internal
building block, but from `oraclemcp` it does not provide an independent
supervision, reactor, teardown, or panic-quarantine boundary. It also requires
private scheduler TLS that this repository cannot install without coupling to
asupersync internals.

## Consequences

The per-lane design is explicit and slightly heavier than local tasks, but it
matches the driver isolation requirement and gives N0a a clear ownership model:
lane handle outside, Oracle session inside.

N0a should avoid per-call runtime construction and nested `block_on`. It should
model requests as mailbox commands and keep driver calls inside the lane loop.
Cancellation, capacity, durable idempotency, and panic isolation can then wrap
the mailbox and lane supervisor rather than trying to make non-Send futures
portable across workers.

## Review Trigger

Revisit this ADR only if asupersync exposes a public local-scheduler owner API
that lets a consumer create an isolated non-Send lane with explicit reactor
ownership, bounded mailbox ingress, supervised teardown, and panic isolation
without private TLS access.
