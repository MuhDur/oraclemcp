//! Shared helpers for the integration-test binaries.

use std::path::PathBuf;

/// Resolve a usable `bash` binary.
///
/// On Windows, a bare `Command::new("bash")` resolves to
/// `C:\Windows\System32\bash.exe` — the WSL launcher — which on the GitHub
/// windows runners has **no distribution installed** and exits 1
/// (`Windows Subsystem for Linux has no installed distributions`) *without ever
/// running the script*. Every `bash`-shelling e2e test would then fail for a
/// reason that has nothing to do with the code under test. Prefer Git Bash,
/// which the runners ship, before falling back to the bare name (correct on
/// Unix, where `bash` on `PATH` is the real shell).
#[must_use]
pub fn bash_bin() -> PathBuf {
    #[cfg(windows)]
    {
        for candidate in [
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files\Git\usr\bin\bash.exe",
        ] {
            let path = std::path::Path::new(candidate);
            if path.exists() {
                return path.to_path_buf();
            }
        }
    }
    PathBuf::from("bash")
}
