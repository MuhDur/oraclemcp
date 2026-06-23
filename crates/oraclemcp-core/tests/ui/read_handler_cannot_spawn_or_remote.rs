//! A9 compile-fail fixture: a read-path handler holding a `Cx<ReadPathCaps>`
//! (TIME + IO only) STRUCTURALLY cannot perform a remote / privileged effect.
//!
//! `ReadPathCaps` does not implement `HasRemote` (the REMOTE bit is off), so the
//! `Cx::remote` accessor's `Caps: HasRemote` bound is unsatisfied, and the
//! crate's `requires_privileged_effect` bound (`Caps: PrivilegedEffect`) cannot
//! be met by the read row. Both lines below must fail to compile.

use asupersync::Cx;
use oraclemcp_core::capability::{ReadPathCaps, narrow_to_read_path, requires_privileged_effect};

fn read_handler(cx: &Cx<ReadPathCaps>) {
    // A read handler must not be able to perform a privileged process effect
    // (spawn / remote / privileged dispatch). The `PrivilegedEffect` bound is
    // not implemented for the read-path row, so this does not type-check.
    requires_privileged_effect(cx);

    // Nor can it name the gated remote-execution accessor: `Cx::remote` requires
    // `Caps: HasRemote`, which `ReadPathCaps` does not implement.
    let _ = cx.remote();
}

fn main() {
    // A full-authority context, narrowed to the read path before reaching the
    // handler (this is exactly what the dispatch boundary does for read tools).
    let full = Cx::<asupersync::cx::AllCaps>::for_testing();
    let read = narrow_to_read_path(&full);
    read_handler(&read);
}
