//! A9 compile-fail fixture: a lane shell holding `Cx<LaneCaps>` cannot perform
//! remote / privileged effects. This is the per-lane counterpart to the
//! read-path handler proof.

use asupersync::Cx;
use oraclemcp_core::capability::{LaneCaps, narrow_to_lane, requires_privileged_effect};

fn lane_shell(cx: &Cx<LaneCaps>) {
    // The lane shell may drive cancellation/time and its own mailbox IO, but it
    // must not be able to reach remote/privileged process effects.
    requires_privileged_effect(cx);
    let _ = cx.remote();
}

fn main() {
    let full = Cx::<asupersync::cx::AllCaps>::for_testing();
    let lane = narrow_to_lane(&full);
    lane_shell(&lane);
}
