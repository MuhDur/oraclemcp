//! Instant Client posture probe (plan §13 `oraclemcp doctor` check 1).
//!
//! Offline-safe: detects whether `libclntsh` (the thick-mode runtime ODPI-C
//! `dlopen`s) is resolvable, without requiring a live database. P1-DOC composes
//! this into the full nine-check doctor.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Whether the `oracle-driver` feature is compiled into this build.
#[must_use]
pub fn oracle_driver_compiled() -> bool {
    cfg!(feature = "oracle-driver")
}

/// The Instant Client runtime posture.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstantClientPosture {
    /// Whether the `oracle-driver` feature is compiled in (live-DB capable).
    pub driver_compiled: bool,
    /// Whether a `libclntsh` shared object was located on the library path.
    pub libclntsh_found: bool,
    /// The directory the library was found in, if any.
    pub search_dir: Option<String>,
    /// A best-effort version hint parsed from the directory name
    /// (`instantclient_23_7` → `23.7`).
    pub version_hint: Option<String>,
    /// A human-readable note / next step.
    pub note: String,
}

/// Probe the Instant Client posture by scanning `LD_LIBRARY_PATH` (and common
/// fallbacks) for a directory containing `libclntsh.so*`.
#[must_use]
pub fn detect_instant_client() -> InstantClientPosture {
    let driver_compiled = oracle_driver_compiled();
    if !driver_compiled {
        return InstantClientPosture {
            driver_compiled: false,
            libclntsh_found: false,
            search_dir: None,
            version_hint: None,
            note: "offline build (oracle-driver off): no Instant Client required".to_owned(),
        };
    }

    let mut dirs: Vec<String> = Vec::new();
    if let Ok(path) = std::env::var("LD_LIBRARY_PATH") {
        dirs.extend(path.split(':').filter(|s| !s.is_empty()).map(str::to_owned));
    }
    // Common default install locations.
    dirs.extend(
        ["/usr/lib/oracle", "/opt/oracle", "/usr/local/lib"]
            .iter()
            .map(|s| (*s).to_owned()),
    );

    for dir in &dirs {
        if let Some((found_dir, version)) = scan_dir_for_libclntsh(Path::new(dir)) {
            return InstantClientPosture {
                driver_compiled: true,
                libclntsh_found: true,
                search_dir: Some(found_dir),
                version_hint: version,
                note: "Instant Client resolvable".to_owned(),
            };
        }
    }

    InstantClientPosture {
        driver_compiled: true,
        libclntsh_found: false,
        search_dir: None,
        version_hint: None,
        note: "libclntsh not found on LD_LIBRARY_PATH; install Oracle Instant Client (Basic/Basic Light) and point LD_LIBRARY_PATH at it".to_owned(),
    }
}

/// If `dir` (or a single-level `instantclient*` subdir) contains a
/// `libclntsh.so*`, return its directory and a version hint from the dir name.
fn scan_dir_for_libclntsh(dir: &Path) -> Option<(String, Option<String>)> {
    if dir_has_libclntsh(dir) {
        return Some((dir.display().to_string(), version_from_dir_name(dir)));
    }
    // One level of `instantclient*` subdirectories (a common layout).
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.to_ascii_lowercase().starts_with("instantclient") && dir_has_libclntsh(&p) {
                return Some((p.display().to_string(), version_from_dir_name(&p)));
            }
        }
    }
    None
}

fn dir_has_libclntsh(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        e.file_name()
            .to_str()
            .is_some_and(|n| n.starts_with("libclntsh.so"))
    })
}

/// `instantclient_23_7` → `Some("23.7")`.
fn version_from_dir_name(dir: &Path) -> Option<String> {
    let name = dir.file_name()?.to_str()?.to_ascii_lowercase();
    let rest = name.strip_prefix("instantclient_")?;
    Some(rest.replace('_', "."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posture_reflects_driver_compilation() {
        let posture = detect_instant_client();
        assert_eq!(posture.driver_compiled, cfg!(feature = "oracle-driver"));
        if !posture.driver_compiled {
            assert!(!posture.libclntsh_found);
        }
    }

    #[test]
    fn version_parsing() {
        assert_eq!(
            version_from_dir_name(Path::new("/tmp/instantclient_23_7")),
            Some("23.7".to_owned())
        );
        assert_eq!(version_from_dir_name(Path::new("/tmp/lib")), None);
    }
}
