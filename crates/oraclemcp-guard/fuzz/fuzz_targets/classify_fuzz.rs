#![no_main]
//! Fuzz the fail-closed classifier (bead T-CORPUS / 6.2): arbitrary input must
//! never panic, and the fail-closed invariants must hold for every input.
//!
//! Run: `cargo +nightly fuzz run classify_fuzz` (from crates/oraclemcp-guard).

use libfuzzer_sys::fuzz_target;
use oraclemcp_guard::{Classifier, DangerLevel};

fuzz_target!(|data: &[u8]| {
    let Ok(sql) = std::str::from_utf8(data) else {
        return;
    };
    let decision = Classifier::default().classify(sql);
    // Invariant 1: Forbidden carries no runnable level.
    if decision.danger == DangerLevel::Forbidden {
        assert!(decision.required_level.is_none(), "Forbidden must have no required_level");
    } else {
        assert!(decision.required_level.is_some(), "non-Forbidden must have a required_level");
    }
    // Invariant 2: re-classifying the same input is deterministic.
    let again = Classifier::default().classify(sql);
    assert_eq!(decision.danger, again.danger, "classification must be deterministic");
});
