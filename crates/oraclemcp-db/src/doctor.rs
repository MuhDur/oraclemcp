//! Thin driver posture probe (plan §13 `oraclemcp doctor` check 1).
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
pub struct InstantClientPosture {
    /// Whether the thin driver is compiled in (live-DB capable).
    pub driver_compiled: bool,
    /// Whether a `libclntsh` shared object was located on the library path.
    /// Thin mode does not require this and always reports `false`.
    pub libclntsh_found: bool,
    /// The directory the library was found in, if any. Thin mode does not scan.
    pub search_dir: Option<String>,
    /// A best-effort version hint parsed from the directory name. Thin mode
    /// does not scan.
    pub version_hint: Option<String>,
    /// A human-readable note / next step.
    pub note: String,
}

/// Probe thin driver posture without touching the host environment.
#[must_use]
pub fn detect_instant_client() -> InstantClientPosture {
    InstantClientPosture {
        driver_compiled: true,
        libclntsh_found: false,
        search_dir: None,
        version_hint: None,
        note: "thin oracledb driver compiled; Oracle Instant Client is not required".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posture_reflects_driver_compilation() {
        let posture = detect_instant_client();
        assert!(posture.driver_compiled);
        assert!(!posture.libclntsh_found);
        assert!(posture.note.contains("Instant Client is not required"));
    }
}
