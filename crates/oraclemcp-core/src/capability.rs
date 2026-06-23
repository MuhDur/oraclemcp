//! Compile-time capability narrowing for read-path tool handlers (A9; plan §8
//! release gate). Defense-in-depth ABOVE the runtime operating-level ceiling and
//! the fail-closed SQL classifier — structural reinforcement, never a
//! replacement for them.
//!
//! # What this provides
//!
//! Asupersync represents a context's effects as a type-level capability row
//! `[SPAWN, TIME, RANDOM, IO, REMOTE]` ([`asupersync::cx::CapSet`]). The
//! [`asupersync::cx::SubsetOf`] relation is the pointwise `≤` ordering on rows:
//! narrowing (dropping capabilities) is allowed, **widening (gaining one) is a
//! compile-time error** because the sealed bit-ordering has no `(true, false)`
//! impl. The per-effect marker traits ([`asupersync::cx::HasSpawn`],
//! [`HasRemote`](asupersync::cx::HasRemote), [`HasRandom`](asupersync::cx::HasRandom),
//! …) are sealed, so no external type can forge a capability.
//!
//! A read-path handler is handed a context narrowed to [`ReadPathCaps`] — only
//! `TIME` (deadlines/timeouts) and `IO` (the database round-trip). It carries
//! **no** `SPAWN`, `REMOTE`, or `RANDOM` bit. Because the gated effect accessors
//! (`Cx::remote`, the random APIs, …) are bounded on the corresponding `Has*`
//! marker, a `Cx<ReadPathCaps>` **structurally cannot** name a remote or
//! ambient-randomness effect: the call does not type-check.
//!
//! # Compile-time-guaranteed vs runtime-enforced
//!
//! - **Compile-time-guaranteed (this module + asupersync's type system):**
//!   1. A `Cx<ReadPathCaps>` cannot call a `Cx` effect accessor gated on
//!      [`HasRemote`](asupersync::cx::HasRemote) or
//!      [`HasRandom`](asupersync::cx::HasRandom) (no remote, no ambient
//!      randomness) — proven by the `ui/read_handler_cannot_spawn_or_remote.rs`
//!      compile-fail fixture.
//!   2. A narrowed [`ReadPathCaps`] context cannot be **widened** back to a row
//!      that re-adds `SPAWN`/`REMOTE`/`RANDOM` — `Cx::restrict` requires
//!      `SubsetOf`, and widening has no impl (monotonicity). Proven by the
//!      `ui/widen_narrowed_cx_rejected.rs` compile-fail fixture.
//!   3. Any effect this crate models behind the sealed [`PrivilegedEffect`]
//!      marker (spawn / remote / privileged) requires a capability row that
//!      [`ReadPathCaps`] is not — calling [`requires_privileged_effect`] with a
//!      read context does not type-check.
//!
//! - **Runtime-enforced (the primary boundary, unchanged):** which *statements*
//!   a session may run is decided by the fail-closed classifier + the
//!   `OperatingLevel` ceiling in `oraclemcp-guard`. The capability row does not
//!   classify SQL; it removes *ambient process effects* from the read path so a
//!   read handler cannot, e.g., spawn a remote task even if a future code path
//!   tried to. Caveat: in the pinned asupersync 0.3.4, `Scope::spawn` is generic
//!   over the caller's caps and is **not** yet gated on
//!   [`HasSpawn`](asupersync::cx::HasSpawn); the `SPAWN=false` bit is enforced
//!   structurally here (the read Cx is never handed a `Scope`, and widening to
//!   re-add `SPAWN` is rejected), and the monotonicity property is the
//!   load-bearing compile-time guarantee. `REMOTE` and `RANDOM` are gated by the
//!   driver's own accessors today.

use asupersync::Cx;
use asupersync::cx::{CapSet, HasRemote, SubsetOf};

/// The capability row a read-path tool handler runs under: `TIME` + `IO` only.
///
/// Row `[SPAWN=false, TIME=true, RANDOM=false, IO=true, REMOTE=false]`. A read
/// handler needs timeouts (`TIME`) and the database round-trip (`IO`); it has no
/// business spawning tasks, reaching a remote runtime, or drawing ambient
/// randomness, so those bits are off. This is [`asupersync::cx::SubsetOf`] the
/// full row, so narrowing to it always type-checks; the reverse never does.
pub type ReadPathCaps = CapSet<false, true, false, true, false>;

/// Narrow a full-authority context to the read-path capability row.
///
/// This is a zero-cost, type-level restriction (`Cx::restrict`): it shares the
/// same underlying runtime context but removes the `SPAWN`/`REMOTE`/`RANDOM`
/// effects from the type, so a read handler given the result cannot name them.
/// The `Caps: SubsetOf<...>`-style direction is enforced by `restrict` itself —
/// you can only ever narrow.
#[must_use]
pub fn narrow_to_read_path<Caps>(cx: &Cx<Caps>) -> Cx<ReadPathCaps>
where
    ReadPathCaps: SubsetOf<Caps>,
{
    cx.restrict::<ReadPathCaps>()
}

mod sealed {
    /// Sealed so no external crate can claim an effect is "privileged" (or not).
    pub trait Sealed {}
}

/// A sealed marker for a capability row that is allowed to perform a privileged
/// process effect (spawning, remote dispatch, or anything above the read path).
///
/// It is implemented only for rows that carry the `REMOTE` bit — the strongest
/// of the privileged effects and the one asupersync gates structurally — so
/// [`requires_privileged_effect`] can be called only with a context that proves,
/// in its type, that it holds that authority. A [`ReadPathCaps`] context does
/// not implement this trait, so a read handler cannot call it: the bound fails
/// to resolve at compile time.
pub trait PrivilegedEffect: sealed::Sealed {}

impl<Caps> sealed::Sealed for Caps where Caps: HasRemote {}
impl<Caps> PrivilegedEffect for Caps where Caps: HasRemote {}

/// A stand-in for any privileged process effect a *write/admin*-path handler may
/// legitimately perform (spawn / remote / privileged dispatch). The `Caps:
/// PrivilegedEffect` bound makes it **uncallable** from a read-path context: a
/// `Cx<ReadPathCaps>` does not satisfy the bound, so the call does not compile.
///
/// This is the type-level dual of the runtime level gate: the runtime gate
/// refuses a privileged *statement*; this refuses a privileged *effect* on the
/// read path before any statement is even formed.
pub fn requires_privileged_effect<Caps>(_cx: &Cx<Caps>)
where
    Caps: PrivilegedEffect,
{
    // Intentionally empty: the value is in the *bound*, which a read context
    // cannot satisfy. Nothing here runs in the read path by construction.
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::cx::{AllCaps, HasIo, HasRandom, HasSpawn, HasTime, NoCaps, SubsetOf};

    // Type-level (compile-time) witnesses. A function bounded on a trait that
    // `ReadPathCaps` does NOT implement could not even be named here; these
    // assertions therefore PROVE the positive shape of the row, and the
    // trybuild ui/ fixtures prove the negative (that the missing bits cannot be
    // recovered or used).

    fn assert_subset<Sub: SubsetOf<Super>, Super>() {}
    fn assert_has_time<C: HasTime>() {}
    fn assert_has_io<C: HasIo>() {}

    /// `ReadPathCaps` keeps exactly TIME + IO, and is a `SubsetOf` the full row
    /// (so narrowing to it from full authority always type-checks). Down-lattice
    /// narrowing to `NoCaps` is also a subset relation.
    #[test]
    fn read_path_row_is_time_io_and_a_subset_of_all() {
        assert_has_time::<ReadPathCaps>();
        assert_has_io::<ReadPathCaps>();
        // ReadPathCaps ⊆ AllCaps (narrowing is allowed); NoCaps ⊆ ReadPathCaps.
        assert_subset::<ReadPathCaps, AllCaps>();
        assert_subset::<NoCaps, ReadPathCaps>();
        // Reflexive.
        assert_subset::<ReadPathCaps, ReadPathCaps>();
    }

    /// `narrow_to_read_path`'s bound resolves for any source row that is a
    /// superset of the read path (witnessed here for the full row). The monotone
    /// direction is enforced by `Cx::restrict`'s `SubsetOf` bound; the reverse
    /// (widening) is the compile-fail fixture `ui/widen_narrowed_cx_*`.
    #[test]
    fn narrow_helper_is_well_typed_for_supersets() {
        // Type-level witness that `narrow_to_read_path` resolves for the full
        // row — i.e. `ReadPathCaps: SubsetOf<AllCaps>` holds, which is exactly
        // the bound on the helper. (We assert the bound rather than construct a
        // full context, to avoid pulling asupersync's `test-internals` feature
        // into the lib build; the compile-fail fixtures use `for_testing`.)
        fn witness(cx: &Cx<AllCaps>) -> Cx<ReadPathCaps> {
            narrow_to_read_path(cx)
        }
        // Take it as a fn pointer so the type-level bound is actually checked
        // (and the helper is not dead code).
        let _witness: fn(&Cx<AllCaps>) -> Cx<ReadPathCaps> = witness;

        // A real runtime context can be narrowed down to NoCaps (the floor),
        // exercising the actual `restrict` call path monotonically.
        let none = Cx::<NoCaps>::detached_cancel_context();
        let _floor: Cx<NoCaps> = none.restrict::<NoCaps>();
    }

    /// `PrivilegedEffect` is implemented for rows carrying REMOTE and NOT for the
    /// read-path row — the compile-time gate behind `requires_privileged_effect`.
    #[test]
    fn privileged_effect_marker_tracks_remote_and_spawn_rows() {
        fn assert_privileged<C: PrivilegedEffect>() {}
        fn assert_has_spawn<C: HasSpawn>() {}
        fn assert_has_random<C: HasRandom>() {}
        // A full-authority row is privileged and carries spawn + random.
        assert_privileged::<AllCaps>();
        assert_has_spawn::<AllCaps>();
        assert_has_random::<AllCaps>();
        // ReadPathCaps is deliberately NOT asserted privileged / spawn / random
        // here — that negative is proven at the build boundary by the trybuild
        // ui/ fixtures (a runtime test cannot express "does not implement").
    }
}
