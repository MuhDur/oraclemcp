//! Thin driver posture probe for `oraclemcp doctor`.
//!
//! The DB driver is pure Rust and always compiled into the binary; no Oracle
//! Instant Client, ODPI-C library, or C toolchain is required.

use serde::{Deserialize, Serialize};

/// Whether the thin Oracle driver is compiled into this build.
#[must_use]
pub fn oracle_driver_compiled() -> bool {
    true
}

/// The thin-driver runtime posture.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleDriverPosture {
    /// Whether the thin driver is compiled in (live-DB capable).
    pub driver_compiled: bool,
    /// Whether a native Oracle client library is required at runtime.
    pub native_client_required: bool,
    /// Always false for this thin-native binary; retained in the diagnostic
    /// shape so older automation can tell thick mode is unavailable.
    pub thick_mode_enabled: bool,
    /// A human-readable note / next step.
    pub note: String,
}

/// Probe thin driver posture without touching the host environment.
#[must_use]
pub fn detect_oracle_driver() -> OracleDriverPosture {
    OracleDriverPosture {
        driver_compiled: true,
        native_client_required: false,
        thick_mode_enabled: false,
        note: "thin oracledb driver compiled; Oracle Instant Client is not required".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posture_reflects_driver_compilation() {
        let posture = detect_oracle_driver();
        assert!(posture.driver_compiled);
        assert!(!posture.native_client_required);
        assert!(!posture.thick_mode_enabled);
        assert!(posture.note.contains("Instant Client is not required"));
    }
}
