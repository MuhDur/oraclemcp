//! A9 compile-fail fixture: SubsetOf MONOTONICITY (the load-bearing safety
//! property). Once a context is narrowed to `ReadPathCaps`, it cannot be WIDENED
//! back to a row that re-adds SPAWN/REMOTE/RANDOM.
//!
//! `Cx::restrict::<NewCaps>()` requires `NewCaps: SubsetOf<Caps>`. Widening from
//! the read row to the full row needs `AllCaps: SubsetOf<ReadPathCaps>`, which
//! does NOT hold — the sealed bit-ordering has no `(true, false)` impl, so the
//! compiler rejects any attempt to gain a capability the context does not have.

use asupersync::Cx;
use asupersync::cx::AllCaps;
use oraclemcp_core::capability::{ReadPathCaps, narrow_to_read_path};

fn main() {
    let full = Cx::<AllCaps>::for_testing();
    let read: Cx<ReadPathCaps> = narrow_to_read_path(&full);

    // WIDENING: re-add SPAWN/REMOTE/RANDOM by restricting back to AllCaps. This
    // requires `AllCaps: SubsetOf<ReadPathCaps>`, which is not implemented —
    // monotone narrowing only ever drops capabilities, never adds them.
    let _widened: Cx<AllCaps> = read.restrict::<AllCaps>();
}
