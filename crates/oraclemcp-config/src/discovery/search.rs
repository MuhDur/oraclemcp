//! TNS search-path resolver (design spec §A; `docs/tns-discovery-onboarding.md`).
//!
//! Enumerates the candidate directories that may hold a `tnsnames.ora`, in the
//! precedence Oracle Net and the wrapper script imply, and returns a
//! **de-duplicated, ordered** report with a per-candidate status + note.
//! Discovery degrades gracefully: a missing directory is reported (not an
//! error) and a permission-denied directory is skipped-with-note (never a hard
//! failure).
//!
//! Pure `std::env` + `std::fs`, no driver calls — trivially unit-testable and
//! cross-platform (the platform-specific default dirs are guarded behind `cfg`).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Where a candidate directory came from (for the operator report).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateSource {
    /// `$TNS_ADMIN` — the canonical Oracle Net override.
    TnsAdmin,
    /// `$ORACLE_HOME/network/admin` — the classic client/server layout.
    OracleHome,
    /// `~/.config/oraclemcp/network` — the wrapper default (`ORACLE_NET_HOME`).
    WrapperNetHome,
    /// `~` — the user's home directory.
    Home,
    /// `/etc` — a common system-wide location (Unix).
    Etc,
    /// A common Instant Client `network/admin` directory (platform-guarded).
    InstantClient,
    /// The current working directory — last resort.
    CurrentDir,
}

impl CandidateSource {
    /// A short, stable label for reports.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            CandidateSource::TnsAdmin => "TNS_ADMIN",
            CandidateSource::OracleHome => "ORACLE_HOME/network/admin",
            CandidateSource::WrapperNetHome => "~/.config/oraclemcp/network",
            CandidateSource::Home => "~",
            CandidateSource::Etc => "/etc",
            CandidateSource::InstantClient => "Instant Client",
            CandidateSource::CurrentDir => "current directory",
        }
    }
}

/// The disposition of a single candidate directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateStatus {
    /// The directory exists and is readable.
    Exists,
    /// The directory does not exist (or the path is not a directory).
    Missing,
    /// The directory exists but could not be read (permission denied, etc.).
    Skipped,
}

/// One candidate directory that may contain a `tnsnames.ora`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TnsCandidateDir {
    /// The path as derived, for display (not necessarily canonical).
    pub path: PathBuf,
    /// The canonical path when it resolved, else `None` (missing/unreadable).
    pub canonical: Option<PathBuf>,
    /// Where this candidate came from.
    pub source: CandidateSource,
    /// `exists` / `missing` / `skipped`.
    pub status: CandidateStatus,
    /// Whether a `tnsnames.ora` file is present (only meaningful when readable).
    pub has_tnsnames_ora: bool,
    /// Human-readable note (e.g. `permission denied`, `no tnsnames.ora`).
    pub note: String,
}

impl TnsCandidateDir {
    /// Whether the directory exists and was readable.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.status == CandidateStatus::Exists
    }
}

/// The inputs the resolver reads, injectable so tests never mutate process env.
#[derive(Clone, Debug, Default)]
pub struct DiscoveryEnv {
    /// `$TNS_ADMIN`.
    pub tns_admin: Option<PathBuf>,
    /// `$ORACLE_HOME`.
    pub oracle_home: Option<PathBuf>,
    /// The user's home directory (`$HOME`, or `%USERPROFILE%` on Windows).
    pub home: Option<PathBuf>,
    /// The current working directory.
    pub current_dir: Option<PathBuf>,
}

impl DiscoveryEnv {
    /// Read the discovery inputs from the real process environment. An unset
    /// variable simply drops that candidate — never a panic.
    #[must_use]
    pub fn from_system() -> Self {
        DiscoveryEnv {
            tns_admin: std::env::var_os("TNS_ADMIN").map(PathBuf::from),
            oracle_home: std::env::var_os("ORACLE_HOME").map(PathBuf::from),
            home: system_home_dir(),
            current_dir: std::env::current_dir().ok(),
        }
    }
}

/// The user's home directory from the environment, pure `std` (no `dirs`).
fn system_home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

/// Resolve the candidate `tnsnames.ora` directories from the real environment.
///
/// Convenience wrapper over [`resolve_candidate_dirs_with`] using
/// [`DiscoveryEnv::from_system`].
#[must_use]
pub fn resolve_candidate_dirs() -> Vec<TnsCandidateDir> {
    resolve_candidate_dirs_with(&DiscoveryEnv::from_system())
}

/// Resolve the candidate directories from an injected environment.
///
/// The returned list is in precedence order and de-duplicated by canonical path
/// (a symlinked or repeated directory is scanned once; the highest-precedence
/// occurrence wins). Missing candidates are still reported so the operator sees
/// every place a `tnsnames.ora` was — or was not — found.
#[must_use]
pub fn resolve_candidate_dirs_with(env: &DiscoveryEnv) -> Vec<TnsCandidateDir> {
    let mut raw: Vec<(PathBuf, CandidateSource)> = Vec::new();

    if let Some(tns_admin) = &env.tns_admin {
        raw.push((tns_admin.clone(), CandidateSource::TnsAdmin));
    }
    if let Some(oracle_home) = &env.oracle_home {
        raw.push((
            oracle_home.join("network").join("admin"),
            CandidateSource::OracleHome,
        ));
    }
    if let Some(home) = &env.home {
        raw.push((
            home.join(".config").join("oraclemcp").join("network"),
            CandidateSource::WrapperNetHome,
        ));
        raw.push((home.clone(), CandidateSource::Home));
    }
    #[cfg(unix)]
    {
        raw.push((PathBuf::from("/etc"), CandidateSource::Etc));
    }
    for dir in instant_client_dirs(env) {
        raw.push((dir, CandidateSource::InstantClient));
    }
    if let Some(cwd) = &env.current_dir {
        raw.push((cwd.clone(), CandidateSource::CurrentDir));
    }

    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut out: Vec<TnsCandidateDir> = Vec::with_capacity(raw.len());
    for (path, source) in raw {
        let probed = probe_dir(&path);
        // De-dup key: the canonical path when it resolved, else the display
        // path. Two different display paths that canonicalize to the same real
        // directory collapse to the highest-precedence occurrence.
        let key = probed.canonical.clone().unwrap_or_else(|| path.clone());
        if !seen.insert(key) {
            continue;
        }
        out.push(TnsCandidateDir {
            path,
            canonical: probed.canonical,
            source,
            status: probed.status,
            has_tnsnames_ora: probed.has_tnsnames_ora,
            note: probed.note,
        });
    }
    out
}

/// Best-effort, platform-guarded Instant Client `network/admin` directories.
///
/// Instant Client installs are version-stamped, so we read one level of
/// sub-directories under a few well-known bases and probe their
/// `network/admin` (and `client64/lib/network/admin`) paths. Unreadable or
/// missing bases are silently skipped here; the resulting candidates are probed
/// (and reported) like any other.
fn instant_client_dirs(_env: &DiscoveryEnv) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let bases = ["/opt/oracle", "/usr/lib/oracle", "/usr/local/oracle"];
        for base in bases {
            let base = Path::new(base);
            let Ok(entries) = std::fs::read_dir(base) else {
                continue;
            };
            for entry in entries.flatten() {
                let child = entry.path();
                if child.is_dir() {
                    dirs.push(child.join("network").join("admin"));
                    dirs.push(
                        child
                            .join("client64")
                            .join("lib")
                            .join("network")
                            .join("admin"),
                    );
                }
            }
        }
    }

    #[cfg(windows)]
    {
        let base = Path::new("C:\\oracle");
        if let Ok(entries) = std::fs::read_dir(base) {
            for entry in entries.flatten() {
                let child = entry.path();
                if child.is_dir() {
                    dirs.push(child.join("network").join("admin"));
                }
            }
        }
    }

    dirs
}

/// The raw probe result for one candidate path.
struct Probe {
    status: CandidateStatus,
    canonical: Option<PathBuf>,
    has_tnsnames_ora: bool,
    note: String,
}

/// Probe a candidate directory with `std::fs` only. Never errors: a missing or
/// unreadable directory yields a status + note, not a failure.
fn probe_dir(path: &Path) -> Probe {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_dir() => match std::fs::read_dir(path) {
            Ok(_) => {
                let has_tns = path.join("tnsnames.ora").is_file();
                Probe {
                    status: CandidateStatus::Exists,
                    canonical: std::fs::canonicalize(path).ok(),
                    has_tnsnames_ora: has_tns,
                    note: if has_tns {
                        "tnsnames.ora present".to_owned()
                    } else {
                        "no tnsnames.ora".to_owned()
                    },
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => Probe {
                status: CandidateStatus::Skipped,
                canonical: None,
                has_tnsnames_ora: false,
                note: "permission denied".to_owned(),
            },
            Err(err) => Probe {
                status: CandidateStatus::Skipped,
                canonical: None,
                has_tnsnames_ora: false,
                note: format!("unreadable: {err}"),
            },
        },
        Ok(_) => Probe {
            status: CandidateStatus::Missing,
            canonical: None,
            has_tnsnames_ora: false,
            note: "not a directory".to_owned(),
        },
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => Probe {
            status: CandidateStatus::Skipped,
            canonical: None,
            has_tnsnames_ora: false,
            note: "permission denied".to_owned(),
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Probe {
            status: CandidateStatus::Missing,
            canonical: None,
            has_tnsnames_ora: false,
            note: "does not exist".to_owned(),
        },
        Err(err) => Probe {
            status: CandidateStatus::Skipped,
            canonical: None,
            has_tnsnames_ora: false,
            note: format!("unreadable: {err}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn env_with_tns_admin(dir: &Path) -> DiscoveryEnv {
        DiscoveryEnv {
            tns_admin: Some(dir.to_path_buf()),
            ..DiscoveryEnv::default()
        }
    }

    #[test]
    fn tns_admin_override_is_reported_first() {
        let tmp = TempDir::new().expect("tempdir");
        fs::write(
            tmp.path().join("tnsnames.ora"),
            b"ALIAS = (DESCRIPTION=())\n",
        )
        .expect("write tnsnames.ora");

        let report = resolve_candidate_dirs_with(&env_with_tns_admin(tmp.path()));

        let first = report.first().expect("at least one candidate");
        assert_eq!(first.source, CandidateSource::TnsAdmin);
        assert!(first.exists());
        assert!(first.has_tnsnames_ora, "the temp dir has a tnsnames.ora");
        assert_eq!(
            first.canonical.as_deref(),
            Some(fs::canonicalize(tmp.path()).unwrap().as_path())
        );
    }

    #[test]
    fn duplicates_collapse_to_highest_precedence() {
        let tmp = TempDir::new().expect("tempdir");
        // TNS_ADMIN and the current dir both point at the SAME directory.
        let env = DiscoveryEnv {
            tns_admin: Some(tmp.path().to_path_buf()),
            current_dir: Some(tmp.path().to_path_buf()),
            ..DiscoveryEnv::default()
        };

        let report = resolve_candidate_dirs_with(&env);

        let hits: Vec<_> = report
            .iter()
            .filter(|c| {
                c.canonical.as_deref() == Some(fs::canonicalize(tmp.path()).unwrap().as_path())
            })
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "the shared directory is scanned exactly once"
        );
        assert_eq!(
            hits[0].source,
            CandidateSource::TnsAdmin,
            "the highest-precedence occurrence wins"
        );
        assert!(
            !report
                .iter()
                .any(|c| c.source == CandidateSource::CurrentDir),
            "the lower-precedence duplicate is dropped"
        );
    }

    #[test]
    fn missing_candidate_is_reported_with_exists_false() {
        let tmp = TempDir::new().expect("tempdir");
        let missing = tmp.path().join("no-such-oracle-home");
        let env = DiscoveryEnv {
            oracle_home: Some(missing.clone()),
            ..DiscoveryEnv::default()
        };

        let report = resolve_candidate_dirs_with(&env);

        let oh = report
            .iter()
            .find(|c| c.source == CandidateSource::OracleHome)
            .expect("ORACLE_HOME candidate is present in the report");
        assert!(
            !oh.exists(),
            "a non-existent candidate is reported, exists=false"
        );
        assert_eq!(oh.status, CandidateStatus::Missing);
        assert_eq!(oh.path, missing.join("network").join("admin"));
        assert!(oh.canonical.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_dir_is_skipped_not_fatal() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().expect("tempdir");
        let locked = tmp.path().join("locked");
        fs::create_dir(&locked).expect("create locked dir");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("chmod 000");

        // If we can still read it (e.g. running as root), we cannot simulate a
        // permission-denied directory; skip the assertion rather than fail.
        let readable_as_root = fs::read_dir(&locked).is_ok();

        let env = env_with_tns_admin(&locked);
        // Must not panic / abort regardless.
        let report = resolve_candidate_dirs_with(&env);
        let candidate = report
            .iter()
            .find(|c| c.source == CandidateSource::TnsAdmin)
            .expect("the locked dir is still reported");

        if !readable_as_root {
            assert_eq!(candidate.status, CandidateStatus::Skipped);
            assert_eq!(candidate.note, "permission denied");
            assert!(!candidate.exists());
        }

        // Restore permissions so the TempDir can clean itself up.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).expect("restore chmod");
    }

    #[test]
    fn empty_environment_never_panics() {
        // No TNS_ADMIN, no ORACLE_HOME, no HOME, no cwd.
        let report = resolve_candidate_dirs_with(&DiscoveryEnv::default());
        // On Unix `/etc` is always a candidate; on all platforms this must not
        // panic and must return without any env-derived candidates.
        assert!(
            report
                .iter()
                .all(|c| !matches!(c.source, CandidateSource::TnsAdmin | CandidateSource::Home)),
            "no env-derived candidates when the environment is empty"
        );
        #[cfg(unix)]
        assert!(
            report.iter().any(|c| c.source == CandidateSource::Etc),
            "/etc is a platform default candidate on Unix"
        );
    }

    #[test]
    fn precedence_order_is_stable() {
        let tmp = TempDir::new().expect("tempdir");
        let tns = tmp.path().join("tns");
        let net = tmp
            .path()
            .join("home")
            .join(".config")
            .join("oraclemcp")
            .join("network");
        fs::create_dir_all(&tns).unwrap();
        fs::create_dir_all(&net).unwrap();
        let env = DiscoveryEnv {
            tns_admin: Some(tns.clone()),
            home: Some(tmp.path().join("home")),
            current_dir: Some(tmp.path().to_path_buf()),
            ..DiscoveryEnv::default()
        };

        let report = resolve_candidate_dirs_with(&env);
        let order: Vec<CandidateSource> = report.iter().map(|c| c.source).collect();

        let pos = |src: CandidateSource| order.iter().position(|&s| s == src);
        // TNS_ADMIN before the wrapper net-home before Home before cwd.
        assert!(pos(CandidateSource::TnsAdmin) < pos(CandidateSource::WrapperNetHome));
        assert!(pos(CandidateSource::WrapperNetHome) < pos(CandidateSource::Home));
        assert!(pos(CandidateSource::Home) < pos(CandidateSource::CurrentDir));
    }
}
