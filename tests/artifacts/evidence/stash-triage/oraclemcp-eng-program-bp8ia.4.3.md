# C3 Stash Triage

Generated at: 2026-07-22T10:54:48Z

Scope: oraclemcp stash stack only. The sibling driver repository is out of
scope. The top pane-parked stash with message `park peer beads export hunks
during ws-b close` was excluded from the C3 set after the operator warned that
stash indices shifted.

No stash was dropped, applied, popped, cleared, or otherwise removed. Removal
awaits explicit operator authorization under AGENTS.md Rule 1.

Verdicts are keyed by stash message text, not by unstable `stash@{N}` indices.

1. `On worktree-agent-a9e28af8b04423ab6: d4-server-preserve-before-h6-20260720` - ALREADY LANDED - Fuzz CI taxonomy entries are already in HEAD/history at `a4fec26d` / `cb7ddfa0`.
2. `WIP on release/v0.9.0: 6aa3174 test: align wallet mode expectations with driver support` - OBSOLETE - Old `Cargo.lock` churn from a release branch; current lock/published-driver state supersedes it.
3. `On main: temporary OCI IAM local-driver overlay after subject-mapping revalidation` - OBSOLETE - Local `rust-oracledb` path override, dead by current policy.
4. `On main: temporary final OCI classic-IAM local driver override` - OBSOLETE - Local-driver override, dead by current policy.
5. `On main: temporary v6z2 local driver OCI override` - OBSOLETE - Local-driver override, dead by current policy.
6. `On main: temporary r2t0 OCI Legacy16 trace local-driver override` - OBSOLETE - Local-driver override, dead by current policy.
7. `On main: temporary r2t0 OCI revalidation StaticClientCert local-driver override` - OBSOLETE - Local-driver override, dead by current policy.
8. `On main: temporary r2t0 OCI diagnostics local-driver override and RUST_LOG pass-through` - OBSOLETE - Local-driver override dominates; any useful diagnostics need fresh work, not this stash.
9. `On main: temporary r2t0 local-driver OCI validation full retry` - OBSOLETE - Local-driver override, dead by current policy.
10. `On main: temporary r2t0 local-driver OCI validation` - OBSOLETE - Local-driver override, dead by current policy.
11. `On main: K3-worker-offscope-wip-5c01862` - ALREADY LANDED - Live `oracle_lineage` catalog cross-check symbols are in current tree/history at `70e744a9`.
12. `WIP on main: 5c01862 chore(beads): close GATE-SEAL .16` - ALREADY LANDED - README release-version docs were landed/refined later at `828955d5`, `be525cea`, and `7ea7659a`.
13. `On main: w10 bead export not committed` - ALREADY LANDED - w10/w5/w6b bead close exports are already reflected in the current tracker.
14. `On main: w5 bead export not committed` - ALREADY LANDED - w5/w6b bead close exports are already reflected in the current tracker.
15. `On main: w6b bead export not committed` - ALREADY LANDED - w6b bead close export is already reflected in the current tracker.
