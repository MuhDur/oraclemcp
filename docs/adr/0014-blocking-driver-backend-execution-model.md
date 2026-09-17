# ADR 0014 — Synchronous Oracle backend uses a quarantining connection actor

## Status

Accepted. The official-driver adapter and its acquisition router are compiled
into shipped builds. On 2026-09-16 the operator superseded the proposed default
flip, and on 2026-09-17 explicitly accepted the beta-in-every-build tradeoff:
driver-cx remains the safe primary, while the experimental, reduced-capability
official driver remains an actively tried, bounded alternate for password
acquisitions without a mutable wallet-directory configuration. The decision does not permit a
deadline/thread-leak exception, a statement retry, or removal of the permanent
driver-cx routes.

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
That acknowledgement wait is bounded by the copied absolute request deadline,
or by a fixed 250 ms grace when the request has no deadline. A live-but-never-
polled caller therefore cannot retain the session or owner thread indefinitely:
expiry drops the acknowledgement receiver, quarantines the session, and retires
the actor before any queued operation can execute.
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
password authentication without a mutable wallet directory only, a **raw
socket/auth acquisition failure before a driver-cx session exists** may make one
guarded official-driver alternate attempt. Only a **raw acquisition failure
inside that official alternate, before it has performed post-connect setup**,
may make one fresh driver-cx fallback attempt. Identity setup, canonical NLS
setup, and configured session-statement failures are post-session failures:
they propagate from the single driver-cx attempt and never start the official
driver or a fresh driver-cx retry. Official timeout/NLS/session-setup failures
likewise propagate after the official attempt and never open a new driver-cx
session. IAM/OCI-ADB tokens, `cwallet.sso` auto-login, all mutable
wallet-directory configurations, external/proxy, and other driver-cx-only
authentication never reach the official adapter. The router never retries a
statement or transfers an opened session across drivers.

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
`withheld_live_completion_ack_quarantines_and_retires_actor_within_grace`
proves the complementary liveness case: a live caller that retains but never
polls its acknowledgement sender causes bounded quarantine/thread retirement,
and a queued second command never executes.

`connection.rs` owns a small typed backend registry. In an `oracledb` feature
build, driver-cx is first for every acquisition. A password acquisition without
a mutable wallet directory may use the registry's official alternate; that
alternate enters `OfficialOracleConnection::connect` only through the bounded
guard below. An alternate failure gets exactly one fresh driver-cx acquisition
while the caller remains live. IAM tokens, external/proxy auth, and
`cwallet.sso` auto-login have no official registration and therefore select
driver-cx only. The registry also marks `PemWallet` unsupported by the official
alternate: the beta driver consumes a mutable wallet-directory pathname, which
cannot be bound to immutable, verified PEM material. Thus no late
`cwallet.sso` appearance or directory replacement can be passed to the
official alternate.
`late_auto_login_wallet_appearance_never_reaches_official_alternate` mutates a
wallet after the registry's PEM classification but before the primary
connection attempt returns; the only recorded attempt is driver-cx.
`driver_cx_post_session_setup_failures_never_attempt_the_official_alternate`
injects each post-session phase (identity, canonical NLS, and configured session
statement) and proves its original error propagates after exactly one driver-cx
attempt. `official_post_connect_setup_failures_never_retry_driver_cx` injects
canonical-NLS and configured-session-statement errors after official connect and
proves the sequence stops at driver-cx then official. `driver_cx_connect_error_tries_guarded_official_alternate_for_capable_auth`
retains the complementary raw-acquisition alternate proof.
There is no fallback after a session has been returned, and no statement is
retried or migrated across drivers. Without the feature, the registry contains
only driver-cx and the connect path is unchanged.

This is native-thread evidence, not a Loom proof. Loom cannot model the
opaque Asupersync channel implementation together with its runtime-owned OS
thread; the later B1.3 proof must add a finite model around the actor state
machine before that bead can close.

### Build-cost measurement (2026-09-17)

The accepted beta-in-every-build cost was measured on this Linux build host
with fresh, dedicated target directories. The baseline used the same `HEAD`
source archive and `dashboard-bundle` release command without `oracledb`; the
candidate added the default-compiled adapter. The Docker measurements used
isolated BuildKit contexts assembled from that same baseline, with only the B1
manifest/Dockerfile overlays, so concurrent workspace edits were excluded.
They are local release-engineering measurements, not a portability or release
SLA claim.

| Measurement | Baseline | Default-compiled official adapter | Delta |
| --- | ---: | ---: | ---: |
| Native release build wall time | 268.64 s | 436.21 s | +167.57 s (+62.4%) |
| Native `oraclemcp` binary | 45,590,008 bytes | 47,526,472 bytes | +1,936,464 bytes (+4.25%) |
| Fresh native target directory | 1,413,970,742 bytes | 1,499,917,941 bytes | +85,947,199 bytes (+6.08%) |
| Docker `runtime` image | 285,780,680 bytes | 287,721,936 bytes | +1,941,256 bytes (+0.68%) |
| Docker image build wall time | 189.05 s | 191.47 s | +2.42 s (+1.28%) |

## Consequences

- The default build compiles the official adapter, pinned exactly at
  `oracledb` `26.0.0-beta.3`; this is a supply-chain and binary-size tradeoff,
  not a primary-routing flip.
- The acquisition-only backend selection is unchanged; the fail-closed SQL
  guard, operating-level ladder, rollback default, protected-profile clamp,
  OAuth scope reduction, transaction cleanup, audit chain, and NUMBER-to-string
  invariant are unchanged and remain above the connection seam.

## Permanent driver-cx fallback

Driver-cx is intentionally permanent in this design. It is the default primary
for every connection and the direct-only backend for IAM/OCI-ADB tokens and
`cwallet.sso` auto-login. It is also the single fresh, logged safety fallback
after a **raw pre-session** failure in the guarded official alternate. The
router registration and its adjacent fallback branch must remain. There is no Tier-3 driver-cx
retirement plan in this ADR; any future removal needs a new operator decision
after every direct and fallback capability has an official replacement.

The selection seam is nevertheless deliberately local: the typed
`CONNECTION_BACKEND_REGISTRY` plus the adjacent acquisition-only alternate
branch are the only cross-driver routing site. If a future operator decision
authorizes a capability change, it is one registration/one branch change rather
than scattered backend conditionals. That is a reversible routing path, not a
claim that the permanent driver-cx implementation may now be deleted.

## Active dual-driver disposition

The 2026-09-17 decision compiles `oracledb` into the default build while keeping
driver-cx first for every route. The official adapter is experimental and
reduced-capability, not a primary backend: it is tried only after a compatible
password-only **raw acquisition** failure and only through the bounded
connection guard. Mutable wallet directories stay driver-cx-only until their
consumption can be immutable and verified. This does not authorize a statement
retry, an in-session migration, or driver-cx removal.

The official session is deliberately reduced-capability. It fails closed rather
than emulating or reconnecting through another driver for `call_routine`, named
bind APIs, DBMS_OUTPUT, or LOB/JSON/INTERVAL column materialization. Those
operations remain driver-cx-only until the official adapter has explicit,
independently tested support.

The router remains acquisition-only:

| Authentication/configuration | Current route | Evidence status |
| --- | --- | --- |
| Basic username/password | driver-cx primary; guarded official alternate only after a raw pre-session driver-cx acquisition error | Deterministic router/adapter tests; a separately reported manual, non-CI Free23 lab observation is not a reproducible release-parity artifact |
| TLS/TCPS with PEM wallet | driver-cx directly | Mutable wallet directories are excluded from the official alternate pending an immutable verified-consumption design; direct adapter parity remains live-required but does not license routing |
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
3. `cross_backend_parity` is an explicitly opted-in local Free23 lab target for
   direct basic-auth adapter comparison. It is compiled only with
   `oracledb,live-xe`, is intentionally `#[ignore]`, requires
   `ORACLEMCP_DUAL_BACKEND_LAB=1` plus local credentials, and is not invoked by
   CI or a repository script. When independently run, it compares a 38-digit
   NUMBER, TSTZ, dense/sparse VECTOR, a missing-object error envelope, and a
   DDL/DML rollback/commit sequence. It contains no PL/SQL scenario. Missing
   infrastructure refuses the explicitly selected test; it never converts an
   absent lab into a passing claim.
4. **The sole remaining live-required item** is the direct TCPS + PEM-wallet
   adapter-parity run. The target requires an explicit TCPS endpoint and proves
   direct adapter connect, ping, identity, and close parity. It is technical
   parity evidence only: until immutable wallet consumption
   exists, the registry must continue to route mutable wallet directories to
   driver-cx. Run the ignored target only in the credentialed lab, without
   recording its values in a tracked artifact:

   ```text
   ORACLEMCP_DUAL_BACKEND_TCPS_PEM_LAB=1 \\
   ORACLEMCP_TCPS_PEM_DSN=<tcps-connect-string> \\
   ORACLEMCP_TCPS_PEM_USER=<username> \\
   ORACLEMCP_TCPS_PEM_PASSWORD=<password> \\
   ORACLEMCP_TCPS_PEM_WALLET_LOCATION=<pem-wallet-directory> \\
   cargo test -p oraclemcp-db --features oracledb,live-xe \\
     --test cross_backend_parity live_cross_backend_tcps_pem_connection_parity -- --ignored --exact
   ```

   Set `ORACLEMCP_TCPS_PEM_WALLET_PASSWORD` as well when the PEM wallet needs
   one. The target requires `ewallet.pem`, rejects `cwallet.sso`, and rejects a
   non-TCPS endpoint. Record only the local lab/version, command shape, and
   pass/fail result.
5. The completed bounded matrix records timeout/cancel with uncertain-session
   quarantine, owned streaming/LOB recovery, close, identity, and the supported
   optional capability set. No row is implicitly credited from a fixture; the
   TCPS + PEM run above is the only remaining live-required row.
6. Required gates remain green: formatting, scoped lint/test lanes, release
   surface synchronization, and the required feature-off lane. Advisory
   Windows, mutation, changed-line coverage, public-API, and PL/SQL lanes stay
   advisory by operator decision.

### Current evidence and residual risks

Operator prose on 2026-09-16 reported a manually selected local Free23
basic-auth observation using independent driver-cx and official connections.
The repository has no committed machine-readable result, CI log, or replayable
credentialed artifact for that observation, so it is **not** reproducible
release-parity evidence. The ignored `cross_backend_parity` target above is the
available manual lab harness; it does not exercise PL/SQL. Its described
scenarios include session identity; exact NUMBER, TSTZ, DATE, and
plain-TIMESTAMP serialization; dense/sparse VECTOR serialization;
missing-object error envelopes; and classified DDL/DML rollback/commit behavior.
In particular, its expected DATE is `2026-06-01T12:00:00` and plain TIMESTAMP
is `2026-06-01T12:00:00.123456789`, with no fabricated UTC suffix. The target
creates and drops uniquely named local VECTOR tables; it does not credit an
absent pre-seeded fixture. TCPS + PEM direct-adapter parity remains
live-required and uncredited; mutable-wallet production routing remains
driver-cx-only even after a technical parity row passes.

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
zero-valued internal offset cannot fabricate UTC. The separate basic-auth
parity report is manual, non-CI operator context rather than a reproducible
release-evidence row.
The completion-acknowledgement liveness gap (`oraclemcp-xoflp.1.12`) is
resolved: no-deadline requests receive a fixed 250 ms acknowledgement grace,
deadline-bearing requests use their copied remaining absolute deadline, and a
withheld live acknowledgement deterministically quarantines/drops the resource
before a queued second call can execute. The mutable-wallet TOCTOU gap
(`oraclemcp-xoflp.1.11`) is resolved at the production routing boundary by
excluding every mutable wallet-directory capability from the official
registration; direct adapter qualification cannot re-enable that path without
an immutable verified-consumption design and a new review.
The acquisition-boundary gaps (`oraclemcp-xoflp.1.13`,
`oraclemcp-xoflp.1.14`) are resolved: the typed factory labels failures as raw
acquisition, driver-cx identity/canonical-NLS/configured-statement setup, or
official post-connect setup. Only raw acquisition can cross a backend boundary.
The regressions inject every post-session driver-cx phase plus official canonical
NLS/configured-statement failures and prove the original error returns without a
second session under another backend.
The following residual limits remain explicitly tracked:

- `oraclemcp-xoflp.1.6`: the pinned `26.0.0-beta.3` source invokes blocking
  `TcpStream::connect` for initial and redirected connections before a
  `Connection` exists. Its `tcp_connect_timeout` field is unused and its public
  `set_call_timeout` arrives only after connection establishment. Safe Rust
  cannot cancel or join a stalled foreign connect thread. The bounded guard
  below contains that beta limitation at the router boundary; it does not make
  the upstream call cancellable. An upstream driver fix or replacement version
  remains the only way to close the underlying driver finding.

- `oraclemcp-xoflp.4.8`: the ignored TCPS + `ewallet.pem` parity target compiles
  and refuses an auto-login wallet, but no explicit PEM-only
  TCPS lab credentials are available on this host. It needs one opted-in
  direct driver-cx/official connect, ping, identity, and close run before the
  direct adapter mapping is fully evidenced. This is the **sole remaining
  live-required item**; use the exact command in Required evidence above. It
  does not make the mutable wallet directory eligible for production official
  routing.

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

Deterministic native-thread regressions fill both sides of that contract:
`bounded_connect_guard_caps_stalled_actors_and_recovers_every_slot` proves no
third stalled actor starts and that retiring the simulated stalls restores the
exact baseline; `successful_official_setup_releases_its_connect_guard_slot` and
`actor_spawn_failure_returns_the_reserved_connect_guard_slot` cover the healthy
and spawn-failure releases. `exhausted_official_connect_guard_falls_back_to_driver_cx_once`
proves the driver-cx-primary, official-alternate, and one-fresh-driver-cx
sequence. No query, execute, transaction, guard, audit, or dispatch call site
changes.
