# Seeded lane fault injection

Arc E3 exercises the server-side stateful-lane lifecycle under asupersync's
deterministic `LabRuntime`. It needs no Oracle database, connection string,
credential, or network target. The runner is intentionally **not** an optional
live-suite shortcut: if the Lab harness cannot start or one assertion fails, it
fails; it does not report a skip.

Run the acceptance scenario with:

```bash
bash scripts/e2e/seeded_fault_injection.sh --log
```

`scripts/e2e/run_all.sh` dispatches the same scenario. The test command is
scoped to `oraclemcp-core` and is built only through `omcpb`.

## Scope and bounds

The production lane owns a thread-pinned `!Send` Oracle connection, so it
cannot be moved into `LabRuntime`. The harness instead drives the real
`AdmissionController` used by server lane allocation and models the exact
terminal ownership transitions around it. This proves the server's fail-closed
capacity behavior without pretending that an offline Lab run is a live Oracle
proof.

Each named await candidate is run with all three fault actions:

| Target | Drop | Delay | Cancel | Required result |
| --- | --- | --- | --- | --- |
| `lane-switch-at-cap` | old lane releases before replacement | second lane refuses at cap | second lane refuses and original permit releases | no unbounded replacement |
| `permit-release` | terminal drop returns capacity | delayed terminal drop returns capacity | cancelled terminal drop returns capacity | no permit leak |
| `lost-wakeup` | close state survives | state is re-read after a delayed park | state is re-read after cancel | idle close is level-triggered |

The DPOR-style search is bounded to eight schedules and 256 steps per schedule.
The fixed seed, target, action, and event transcript are emitted as
`ARC_E_FAULT_REPRO` test output; a failing run can therefore be replayed from
the same seed without using ambient time or randomness.

## Seeded-fault proof

The integration test contains two explicit test-only mutations: a terminal
permit leak and a missed post-wake close check. Each is required to be detected
by the real admission ledger and then reproduced byte-for-byte from the fixed
seed before the test passes. The normal path is separately required to leave
`global_in_use == 0` for every target/action combination. This keeps the test
honest: it proves that the invariant can catch its named failure, not merely
that a happy-path schedule completes.
