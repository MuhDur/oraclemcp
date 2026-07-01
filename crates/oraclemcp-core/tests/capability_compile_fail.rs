//! A9 release gate: compile-fail proofs that the read-path capability narrowing
//! is enforced by the type system, not merely by convention.
//!
//! Four fixtures (`tests/ui/*.rs`) must FAIL to compile:
//!
//! 1. `read_handler_cannot_spawn_or_remote.rs` — a read handler holding a
//!    `Cx<ReadPathCaps>` cannot perform a remote / ambient-randomness effect:
//!    the asupersync effect accessors are gated on the `HasRemote` / `HasRandom`
//!    markers, which `ReadPathCaps` does not implement, and the crate's
//!    `requires_privileged_effect` bound rejects the read row outright.
//!
//! 2. `widen_narrowed_cx_rejected.rs` — an attempt to WIDEN a narrowed
//!    `Cx<ReadPathCaps>` back to a row that re-adds SPAWN/REMOTE is rejected by
//!    `Cx::restrict`'s `SubsetOf` bound (SubsetOf monotonicity — the
//!    load-bearing safety property).
//!
//! 3. `lane_context_cannot_spawn_or_remote.rs` — the lane shell's `Cx<LaneCaps>`
//!    has the same structural no-REMOTE/no-privileged-effect guarantee.
//!
//! 4. `lane_context_cannot_widen.rs` — a lane-narrowed context cannot widen back
//!    to full authority.
//!
//! These run only on the host toolchain (trybuild invokes `rustc`), so the test
//! is a single entry point that lets trybuild discover the fixtures and compare
//! their stderr against the checked-in expectations.

#[test]
fn capability_narrowing_is_compile_time_enforced() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/read_handler_cannot_spawn_or_remote.rs");
    t.compile_fail("tests/ui/widen_narrowed_cx_rejected.rs");
    t.compile_fail("tests/ui/lane_context_cannot_spawn_or_remote.rs");
    t.compile_fail("tests/ui/lane_context_cannot_widen.rs");
}
