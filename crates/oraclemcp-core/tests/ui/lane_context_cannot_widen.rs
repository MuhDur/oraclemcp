//! A9 compile-fail fixture: once the lane shell receives `Cx<LaneCaps>`, it
//! cannot widen back to full authority.

use asupersync::Cx;
use asupersync::cx::AllCaps;
use oraclemcp_core::capability::{LaneCaps, narrow_to_lane};

fn main() {
    let full = Cx::<AllCaps>::for_testing();
    let lane: Cx<LaneCaps> = narrow_to_lane(&full);

    // WIDENING: re-add SPAWN/REMOTE/RANDOM. `Cx::restrict` permits only
    // monotone narrowing, so `AllCaps: SubsetOf<LaneCaps>` is unsatisfied.
    let _widened: Cx<AllCaps> = lane.restrict::<AllCaps>();
}
