# Kani Safety Proofs

D6.7 adds bounded model checking for the small safety helpers that are suitable
for Kani. End-to-end SQL classification over arbitrary SQL stays covered by the
metamorphic and mutation gates; it is intentionally not modeled here because it
routes through `sqlparser` and is not a tractable BMC target.

## Proof Harnesses

- `oraclemcp-guard::levels::kani_proofs::operating_level_lattice_is_total_and_monotone`
  proves the `READ_ONLY < READ_WRITE < DDL < ADMIN` order is total, monotone
  against an independent rank function, and stable through `all()` and
  `as_str()`/`parse()`.
- `oraclemcp-guard::levels::kani_proofs::danger_marker_default_required_level_has_floor`
  proves every dispatchable danger marker maps to at least its required
  operating-level floor, while `FORBIDDEN` maps to no level.
- `oraclemcp-guard::levels::kani_proofs::session_gate_never_allows_below_required_level`
  proves `SessionLevelState::evaluate` does not return `Allow` unless the
  required level is within both the effective ceiling and current effective
  level.
- `oraclemcp-audit::record::kani_proofs::signed_chain_step_links_successor_to_predecessor_and_mac_verifies`
  proves a signed audit successor links to its predecessor by sequence and
  `prev_hash`, and both records verify their keyed MAC with production
  `signature_is_valid`. The fixed vectors keep Kani focused on the chain-step
  relation; full `chained_signed` construction remains pinned by the audit unit
  tests and D6.4 mutation gate.

## Local Verification

Run date: 2026-07-08

Command shape:

```bash
export CARGO_TARGET_DIR=/home/durakovic/.cache/cargo-target-server
export CARGO_BUILD_JOBS=16
cargo kani -p oraclemcp-guard --harness operating_level_lattice_is_total_and_monotone --default-unwind 16
cargo kani -p oraclemcp-guard --harness danger_marker_default_required_level_has_floor --default-unwind 16
cargo kani -p oraclemcp-guard --harness session_gate_never_allows_below_required_level --default-unwind 16
RUSTFLAGS='--cfg sha2_backend="soft" --cfg sha2_backend_soft="compact"' \
  cargo kani -p oraclemcp-audit --harness signed_chain_step_links_successor_to_predecessor_and_mac_verifies --default-unwind 128
```

Results:

| Crate | Harness | Result |
| --- | --- | --- |
| `oraclemcp-guard` | `operating_level_lattice_is_total_and_monotone` | verified |
| `oraclemcp-guard` | `danger_marker_default_required_level_has_floor` | verified |
| `oraclemcp-guard` | `session_gate_never_allows_below_required_level` | verified |
| `oraclemcp-audit` | `signed_chain_step_links_successor_to_predecessor_and_mac_verifies` | verified |

The audit proof uses SHA-2's software backend for the verifier run. The first
local attempt with the default x86 runtime-dispatched backend reached the
`cpuid` inline-assembly path in `sha2`, which Kani cannot model. The committed
workflow therefore selects the software backend only for the audit harness; this
does not change production build settings.
