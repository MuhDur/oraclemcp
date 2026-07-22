#[cfg(debug_assertions)]
use std::cell::Cell;

// DL-4 canonical lock rank for the served lane path:
// Config watch snapshot/read -> lifecycle generation -> lane registry -> lane handle/status ->
// lease state -> grants -> audit-chain writer -> metadata cache.
//
// The high-risk AB-BA edge is Registry -> Lane mailbox. The registry may copy
// or insert `LaneRuntime` handles, but it must not dispatch, surface-state, or
// close a lane while the registry guard is held. The debug rank below makes
// that edge executable in tests.
#[cfg(debug_assertions)]
thread_local! {
    static LANE_REGISTRY_LOCK_DEPTH: Cell<usize> = const { Cell::new(0) };
}

#[cfg(debug_assertions)]
pub(super) fn enter_lane_registry_lock() {
    LANE_REGISTRY_LOCK_DEPTH.with(|depth| depth.set(depth.get() + 1));
}

#[cfg(debug_assertions)]
pub(super) fn exit_lane_registry_lock() {
    LANE_REGISTRY_LOCK_DEPTH.with(|depth| {
        let current = depth.get();
        debug_assert!(current > 0, "lane registry lock depth underflow");
        depth.set(current.saturating_sub(1));
    });
}

#[cfg(debug_assertions)]
fn lane_registry_lock_held() -> bool {
    LANE_REGISTRY_LOCK_DEPTH.with(|depth| depth.get() > 0)
}

#[cfg(debug_assertions)]
pub(super) fn assert_no_lane_registry_lock(operation: &str) {
    debug_assert!(
        !lane_registry_lock_held(),
        "{operation} while holding the lane registry lock violates DL-4"
    );
}

#[cfg(not(debug_assertions))]
pub(super) fn assert_no_lane_registry_lock(_operation: &str) {}
