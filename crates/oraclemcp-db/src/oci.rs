//! OCI / Oracle Cloud (Autonomous DB) connectivity hardening (plan §9.1; bead
//! P1-11 / oracle-qmwz.2.11; A5). This is **hop-2** (Oracle Net), independent of
//! the MCP transport. Thin mode handles TCPS/wallet location directly where the
//! published driver supports it. The adapter can carry an OCI IAM database token
//! to the pinned driver (`ConnectOptions::with_access_token`, sent as
//! `AUTH_TOKEN` only over TCPS, fail-closed on a plaintext transport) **when one
//! is injected** — but no production code injects a token today. The token
//! source ([`IamTokenSource`] / [`ensure_fresh_token`]) is a **fail-closed seam
//! pending a production OCI SDK backend**: the only implementations that ship are
//! test mocks, and `use_iam_token` without an injected token returns a precise
//! setup error rather than connecting. This layer hardens the cloud edge:
//!
//! - **Wallet discovery** — validate a downloaded ADB wallet directory has the
//!   files mTLS auto-login needs (`cwallet.sso` + `tnsnames.ora`) and surface its
//!   service aliases (`*_high` / `*_medium` / `*_low`).
//! - **ADB connect-string validation** — accept `tcps://…` (TLS), full TLS
//!   descriptors, and bare wallet aliases; **reject plaintext `tcp`** for ADB
//!   (cloud requires TLS/mTLS).
//! - **IAM token refresh (seam)** — pure expiry/skew decision logic for a
//!   database-token (OCI IAM) refresh, ready for a production source. The OCI SDK
//!   call is an injected edge dependency ([`IamTokenSource`]) with **no shipping
//!   implementation**; if one is wired, the resulting token is carried in
//!   [`OracleConnectOptions::iam_token`](crate::OracleConnectOptions) and the B2
//!   adapter sends it via `with_access_token` (TCPS-enforced).
//! - **Cloud status** — a summary `oracle_capabilities` can surface.
//!
//! The parsing/validation/refresh logic is pure (FS-free) so it is fully
//! unit-testable; [`discover_wallet`] is the thin filesystem wrapper.

use std::path::{Path, PathBuf};

/// Files that mTLS auto-login (`cwallet.sso`) needs in a wallet directory.
const REQUIRED_WALLET_FILES: &[&str] = &["cwallet.sso", "tnsnames.ora"];

/// Why an OCI/ADB connectivity step failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OciError {
    /// The wallet directory does not exist.
    #[error("wallet directory does not exist: {0}")]
    WalletDirMissing(String),
    /// The wallet directory is missing files mTLS auto-login requires.
    #[error("wallet at {dir} is incomplete; missing: {missing:?}")]
    WalletIncomplete {
        /// The wallet directory.
        dir: String,
        /// The required files that were not found.
        missing: Vec<&'static str>,
    },
    /// The connect string is not valid for Autonomous DB.
    #[error("invalid ADB connect string: {0}")]
    InvalidAdbConnectString(String),
    /// An IAM database token has expired and no refresher is available.
    #[error("IAM database token expired")]
    TokenExpired,
}

/// What a wallet directory contains.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletContents {
    /// The wallet directory.
    pub dir: PathBuf,
    /// `cwallet.sso` present (auto-login SSO wallet — mTLS without a password).
    pub has_sso: bool,
    /// `ewallet.p12` present (password-protected wallet).
    pub has_p12: bool,
    /// `tnsnames.ora` present.
    pub has_tnsnames: bool,
    /// `sqlnet.ora` present.
    pub has_sqlnet: bool,
    /// Service aliases parsed from `tnsnames.ora` (e.g. `mydb_high`).
    pub aliases: Vec<String>,
}

/// Classify a wallet from the list of filenames present + optional `tnsnames.ora`
/// content. Pure (no filesystem) — the testable core of [`discover_wallet`].
pub fn classify_wallet(
    dir: &Path,
    present_files: &[String],
    tnsnames: Option<&str>,
) -> Result<WalletContents, OciError> {
    let has = |name: &str| present_files.iter().any(|f| f.eq_ignore_ascii_case(name));
    let contents = WalletContents {
        dir: dir.to_path_buf(),
        has_sso: has("cwallet.sso"),
        has_p12: has("ewallet.p12"),
        has_tnsnames: has("tnsnames.ora"),
        has_sqlnet: has("sqlnet.ora"),
        aliases: tnsnames.map(parse_tnsnames_aliases).unwrap_or_default(),
    };
    let missing: Vec<&'static str> = REQUIRED_WALLET_FILES
        .iter()
        .copied()
        .filter(|f| !present_files.iter().any(|p| p.eq_ignore_ascii_case(f)))
        .collect();
    if !missing.is_empty() {
        return Err(OciError::WalletIncomplete {
            dir: dir.display().to_string(),
            missing,
        });
    }
    Ok(contents)
}

/// Discover + validate an ADB wallet directory (the FS wrapper over
/// [`classify_wallet`]).
pub fn discover_wallet(dir: &Path) -> Result<WalletContents, OciError> {
    if !dir.is_dir() {
        return Err(OciError::WalletDirMissing(dir.display().to_string()));
    }
    let mut present = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            if let Some(name) = e.file_name().to_str() {
                present.push(name.to_owned());
            }
        }
    }
    let tnsnames = std::fs::read_to_string(dir.join("tnsnames.ora")).ok();
    classify_wallet(dir, &present, tnsnames.as_deref())
}

/// Parse service aliases from `tnsnames.ora`: identifiers at column 0 followed
/// by `=` (the start of a connect descriptor or alias list).
fn parse_tnsnames_aliases(content: &str) -> Vec<String> {
    let mut aliases = Vec::new();
    for line in content.lines() {
        // Aliases begin at column 0 (descriptor continuation lines are indented).
        if line.starts_with(|c: char| c.is_whitespace()) || line.trim_start().starts_with('#') {
            continue;
        }
        if let Some((lhs, _)) = line.split_once('=') {
            let name = lhs.trim();
            if !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
            {
                aliases.push(name.to_owned());
            }
        }
    }
    aliases
}

/// What an ADB connect string resolves to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdbConnectInfo {
    /// Uses TLS/mTLS (`tcps`).
    pub uses_tls: bool,
    /// `wallet_location` from the connect string, if embedded.
    pub wallet_location: Option<String>,
    /// A bare tnsnames alias (resolved via `TNS_ADMIN`/wallet), if that form.
    pub alias: Option<String>,
    /// A full connect descriptor (`(DESCRIPTION=…)`), if that form.
    pub descriptor: bool,
}

/// Validate an Autonomous DB connect string. Accepts `tcps://…`, a full TLS
/// descriptor, or a bare wallet alias; rejects plaintext `tcp` (ADB requires TLS).
pub fn validate_adb_connect_string(s: &str) -> Result<AdbConnectInfo, OciError> {
    let t = s.trim();
    if t.is_empty() {
        return Err(OciError::InvalidAdbConnectString("empty".to_owned()));
    }
    let lower = t.to_ascii_lowercase();

    // Full connect descriptor: (DESCRIPTION=(ADDRESS=(PROTOCOL=tcps)...)).
    if lower.starts_with("(description") || lower.contains("(address") {
        // Tolerate conventional Oracle Net spacing: (PROTOCOL = TCPS). Match the
        // protocol against a whitespace-stripped copy so `PROTOCOL = TCPS` is
        // accepted as TLS and `PROTOCOL = TCP` is still rejected as plaintext.
        let compact: String = lower.chars().filter(|c| !c.is_whitespace()).collect();
        let uses_tls = compact.contains("protocol=tcps");
        if !uses_tls {
            return Err(OciError::InvalidAdbConnectString(
                "ADB descriptor must use PROTOCOL=TCPS (TLS)".to_owned(),
            ));
        }
        return Ok(AdbConnectInfo {
            uses_tls: true,
            // Preserve the original case of the extracted path (case-sensitive
            // filesystems): wallet_param lowercases internally only to locate the
            // `wallet_location=` needle, so pass the case-preserving `t`.
            wallet_location: wallet_param(t),
            alias: None,
            descriptor: true,
        });
    }

    // URL form.
    if lower.starts_with("tcps://") {
        return Ok(AdbConnectInfo {
            uses_tls: true,
            wallet_location: wallet_param(t),
            alias: None,
            descriptor: false,
        });
    }
    if lower.starts_with("tcp://") {
        return Err(OciError::InvalidAdbConnectString(
            "plaintext tcp:// is not allowed for ADB — use tcps:// (TLS)".to_owned(),
        ));
    }

    // Bare alias (no scheme, no descriptor) — resolved via TNS_ADMIN/wallet.
    if t.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        return Ok(AdbConnectInfo {
            uses_tls: true,
            wallet_location: None,
            alias: Some(t.to_owned()),
            descriptor: false,
        });
    }

    // An EZConnect host:port/service without TLS is not acceptable for ADB.
    Err(OciError::InvalidAdbConnectString(
        "expected tcps://…, a TLS descriptor, or a wallet alias".to_owned(),
    ))
}

/// Extract a `wallet_location=` value from a connect string, if present.
///
/// Quote-aware: if the value is quoted (`wallet_location="/opt/My Wallet"`), the
/// path is read to the matching closing quote so interior spaces are preserved;
/// otherwise the value terminates on a delimiter or whitespace.
fn wallet_param(s: &str) -> Option<String> {
    let needle = "wallet_location=";
    let idx = s.to_ascii_lowercase().find(needle)? + needle.len();
    let rest = &s[idx..];
    let v = match rest.chars().next() {
        // Quoted value: read to the matching closing quote (interior spaces kept).
        Some(q @ ('"' | '\'')) => {
            let body = &rest[q.len_utf8()..];
            let end = body.find(q).unwrap_or(body.len());
            &body[..end]
        }
        // Unquoted value: terminate on a delimiter or whitespace.
        _ => {
            let end = rest
                .find(|c: char| matches!(c, '&' | ')' | '?') || c.is_whitespace())
                .unwrap_or(rest.len());
            rest[..end].trim_matches(|c| c == '"' || c == '\'')
        }
    };
    (!v.is_empty()).then(|| v.to_owned())
}

/// An OCI IAM database token with its expiry (Unix seconds).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IamToken {
    /// The opaque database token.
    pub token: String,
    /// Expiry, Unix seconds.
    pub expires_at_unix: i64,
}

impl IamToken {
    /// Whether the token has expired at `now_unix`.
    #[must_use]
    pub fn is_expired(&self, now_unix: i64) -> bool {
        now_unix >= self.expires_at_unix
    }

    /// Whether the token should be refreshed (expires within `skew_secs`).
    ///
    /// An already-expired token **always** needs refresh, regardless of the skew
    /// value — a negative or misconfigured `skew_secs` must never let an expired
    /// token read as fresh (the historical `now_unix + skew_secs` bug, which both
    /// reused expired tokens under a negative skew and could overflow `i64`). The
    /// proactive window clamps the skew nonnegative (a negative skew is
    /// meaningless — it would ask to refresh *after* expiry) and adds saturating,
    /// so a large `now_unix`/`skew_secs` can never wrap a "needs refresh" into a
    /// "fresh".
    #[must_use]
    pub fn needs_refresh(&self, now_unix: i64, skew_secs: i64) -> bool {
        if self.is_expired(now_unix) {
            return true;
        }
        let skew = skew_secs.max(0);
        now_unix.saturating_add(skew) >= self.expires_at_unix
    }
}

/// Injection seam for an OCI IAM database-token source (the OCI SDK call,
/// supplied at the edge).
///
/// **Fail-closed seam pending a production backend.** No production
/// implementation ships — the only impls in-tree are test mocks — so the IAM
/// token path is inert until an embedder wires a real source. With
/// `use_iam_token` set but no source/token injected, the adapter returns a setup
/// error rather than attempting a connect.
pub trait IamTokenSource {
    /// Obtain a current database token from the (injected) source.
    fn fetch(&self) -> Result<IamToken, OciError>;
}

/// Pure refresh decision: return a token that is fresh at `now_unix` — reuse
/// `current` if it does not need refresh, else ask `source` for a new one.
/// Proactive (skew-based) refresh is intended to avoid mid-session `ORA-`
/// token-expiry failures **once a production [`IamTokenSource`] is wired**; this
/// function is the decision logic only and ships with no production source.
pub fn ensure_fresh_token(
    current: Option<&IamToken>,
    source: &dyn IamTokenSource,
    now_unix: i64,
    skew_secs: i64,
) -> Result<IamToken, OciError> {
    match current {
        Some(tok) if !tok.needs_refresh(now_unix, skew_secs) => Ok(tok.clone()),
        _ => source.fetch(),
    }
}

/// A wallet auth mode this default thin-driver build reports to doctor, with a
/// one-line note. The pinned driver recognizes multiple wallet artifacts, but
/// this workspace does not enable the driver's `experimental` feature and the
/// driver explicitly rejects standalone `ewallet.p12`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WalletMode {
    /// The wallet artifact / mode (e.g. `cwallet.sso`).
    pub mode: &'static str,
    /// Whether this default build can load it directly.
    pub supported: bool,
    /// A short operator note.
    pub note: &'static str,
}

/// The wallet auth modes this default build can consume directly.
#[must_use]
pub fn supported_wallet_modes() -> &'static [WalletMode] {
    &[
        WalletMode {
            mode: "ewallet.pem",
            supported: true,
            note: "unencrypted PEM wallet (no wallet password required)",
        },
        WalletMode {
            mode: "cwallet.sso",
            supported: false,
            note: "recognized, but the driver's experimental SSO parser is not enabled in this build",
        },
        WalletMode {
            mode: "ewallet.p12",
            supported: false,
            note: "standalone PKCS#12 wallet is recognized but deferred; convert to ewallet.pem",
        },
    ]
}

/// A non-secret cloud-connectivity summary for `oracle_capabilities`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CloudStatus {
    /// Auth mode in use: `wallet`, `iam_token`, or `none`.
    pub mode: String,
    /// Whether the target is Autonomous DB (TLS connect detected).
    pub autonomous: bool,
    /// The wallet directory, if any (non-secret path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_dir: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn complete_wallet_classifies_and_parses_aliases() {
        let tns = "mydb_high = (description=(address=(protocol=tcps)(port=1522)))\n\
                   mydb_low = (description=(address=(protocol=tcps)))\n\
                   # a comment\n\
                       (continuation = indented, ignored)\n";
        let w = classify_wallet(
            Path::new("/w"),
            &files(&["cwallet.sso", "tnsnames.ora", "sqlnet.ora", "ewallet.p12"]),
            Some(tns),
        )
        .expect("complete");
        assert!(w.has_sso && w.has_tnsnames && w.has_sqlnet && w.has_p12);
        assert_eq!(
            w.aliases,
            vec!["mydb_high".to_owned(), "mydb_low".to_owned()]
        );
    }

    #[test]
    fn wallet_missing_sso_is_incomplete() {
        let err = classify_wallet(Path::new("/w"), &files(&["tnsnames.ora"]), None).unwrap_err();
        assert_eq!(
            err,
            OciError::WalletIncomplete {
                dir: "/w".to_owned(),
                missing: vec!["cwallet.sso"]
            }
        );
    }

    #[test]
    fn discover_missing_dir_errors() {
        let err = discover_wallet(Path::new("/no/such/wallet/dir/xyz")).unwrap_err();
        assert!(matches!(err, OciError::WalletDirMissing(_)));
    }

    #[test]
    fn adb_connect_string_forms() {
        // tcps URL with wallet_location.
        let i = validate_adb_connect_string(
            "tcps://adb.eu.oraclecloud.com:1522/svc?wallet_location=/w",
        )
        .expect("tcps ok");
        assert!(i.uses_tls && !i.descriptor);
        assert_eq!(i.wallet_location.as_deref(), Some("/w"));
        // Full TLS descriptor.
        let i = validate_adb_connect_string(
            "(description=(address=(protocol=tcps)(host=adb)(port=1522))(connect_data=(service_name=svc)))",
        )
        .expect("descriptor ok");
        assert!(i.uses_tls && i.descriptor);
        // Bare wallet alias.
        let i = validate_adb_connect_string("mydb_high").expect("alias ok");
        assert_eq!(i.alias.as_deref(), Some("mydb_high"));
    }

    #[test]
    fn descriptor_wallet_location_preserves_case() {
        // oracle-ajm2.12: the descriptor branch must keep the original path case
        // (case-sensitive Linux mTLS auto-login) — not fold to lowercase.
        let i = validate_adb_connect_string(
            "(description=(address=(protocol=tcps)(host=h)(port=1522))(connect_data=(service_name=svc))(wallet_location=/home/Oracle/Wallet))",
        )
        .expect("descriptor with wallet_location ok");
        assert!(i.uses_tls && i.descriptor);
        assert_eq!(i.wallet_location.as_deref(), Some("/home/Oracle/Wallet"));
    }

    #[test]
    fn spaced_descriptor_tls_check_is_whitespace_tolerant() {
        // oracle-ajm2.13 (trigger 1): conventional Oracle Net spacing must not
        // cause a legitimate TLS descriptor to be rejected as plaintext.
        let i = validate_adb_connect_string(
            "(DESCRIPTION = (ADDRESS = (PROTOCOL = TCPS)(HOST = adb)(PORT = 1522)))",
        )
        .expect("spaced TCPS descriptor accepted as TLS");
        assert!(i.uses_tls && i.descriptor);
        // ...but a spaced plaintext descriptor is still rejected (fail-closed).
        assert!(matches!(
            validate_adb_connect_string("(DESCRIPTION = (ADDRESS = (PROTOCOL = TCP)(HOST = h)))"),
            Err(OciError::InvalidAdbConnectString(_))
        ));
    }

    #[test]
    fn quoted_wallet_location_with_space_round_trips() {
        // oracle-ajm2.13 (trigger 2): a quoted wallet path containing a space
        // must not be truncated at the first space.
        let i = validate_adb_connect_string(
            "tcps://adb.eu.oraclecloud.com:1522/svc?wallet_location=\"/opt/My Wallet/dir\"",
        )
        .expect("quoted wallet path ok");
        assert_eq!(i.wallet_location.as_deref(), Some("/opt/My Wallet/dir"));
        // Unquoted values still terminate on whitespace / delimiters.
        let i = validate_adb_connect_string(
            "tcps://adb.eu.oraclecloud.com:1522/svc?wallet_location=/w&foo=bar",
        )
        .expect("unquoted wallet path ok");
        assert_eq!(i.wallet_location.as_deref(), Some("/w"));
    }

    #[test]
    fn plaintext_tcp_is_rejected_for_adb() {
        assert!(matches!(
            validate_adb_connect_string("tcp://adb:1521/svc"),
            Err(OciError::InvalidAdbConnectString(_))
        ));
        assert!(matches!(
            validate_adb_connect_string("(description=(address=(protocol=tcp)(host=h)))"),
            Err(OciError::InvalidAdbConnectString(_))
        ));
        assert!(matches!(
            validate_adb_connect_string("   "),
            Err(OciError::InvalidAdbConnectString(_))
        ));
    }

    #[test]
    fn supported_wallet_modes_report_default_build_truth() {
        // A4: the default build consumes ewallet.pem directly and gives typed
        // diagnostics for recognized wallet artifacts the driver cannot load.
        let modes = supported_wallet_modes();
        for needle in ["ewallet.pem", "cwallet.sso", "ewallet.p12"] {
            let mode = modes
                .iter()
                .find(|m| m.mode == needle)
                .unwrap_or_else(|| panic!("{needle} mode reported"));
            assert_eq!(mode.supported, needle == "ewallet.pem", "{needle}");
        }
    }

    #[test]
    fn iam_token_refresh_logic() {
        let tok = IamToken {
            token: "t".to_owned(),
            expires_at_unix: 1000,
        };
        assert!(!tok.is_expired(999));
        assert!(tok.is_expired(1000));
        // Within the 60s skew -> needs refresh.
        assert!(tok.needs_refresh(950, 60));
        // Plenty of headroom -> no refresh.
        assert!(!tok.needs_refresh(900, 60));
    }

    #[test]
    fn needs_refresh_expired_token_always_refreshes_regardless_of_skew_sign() {
        let tok = IamToken {
            token: "t".to_owned(),
            expires_at_unix: 1000,
        };
        // Already expired: a negative/misconfigured skew must NOT make it read as
        // fresh (the historical `now + skew >= expires` bug: 1500 + -1000 = 500 <
        // 1000 wrongly reported "fresh" and reused an expired token).
        assert!(tok.is_expired(1500));
        assert!(
            tok.needs_refresh(1500, -1000),
            "an expired token needs refresh even under a negative skew"
        );
        assert!(
            tok.needs_refresh(1000, -1000),
            "at exact expiry a negative skew must not defer refresh"
        );
        // Not yet expired + negative skew: the skew clamps to 0, so the decision
        // reduces to the expiry check (still valid -> no refresh).
        assert!(!tok.needs_refresh(900, -1000));
    }

    #[test]
    fn needs_refresh_saturates_instead_of_overflowing() {
        let tok = IamToken {
            token: "t".to_owned(),
            expires_at_unix: i64::MAX,
        };
        // now + skew would overflow i64; saturating_add pins it at i64::MAX, which
        // meets the ceiling -> refresh, and crucially does not panic/wrap.
        assert!(tok.needs_refresh(i64::MAX - 1, i64::MAX));
    }

    #[test]
    fn ensure_fresh_token_never_reuses_an_expired_token_under_negative_skew() {
        let src = CountingSource {
            calls: std::cell::Cell::new(0),
        };
        let expired = IamToken {
            token: "old".to_owned(),
            expires_at_unix: 1000,
        };
        // Expired at now=2000 with a hostile negative skew: must fetch a fresh
        // token, never reuse the expired one.
        let t = ensure_fresh_token(Some(&expired), &src, 2000, -5000).unwrap();
        assert_eq!(t.token, "fresh");
        assert_eq!(src.calls.get(), 1);
    }

    struct CountingSource {
        calls: std::cell::Cell<u32>,
    }
    impl IamTokenSource for CountingSource {
        fn fetch(&self) -> Result<IamToken, OciError> {
            self.calls.set(self.calls.get() + 1);
            Ok(IamToken {
                token: "fresh".to_owned(),
                expires_at_unix: 10_000,
            })
        }
    }

    #[test]
    fn ensure_fresh_token_reuses_then_refreshes() {
        let src = CountingSource {
            calls: std::cell::Cell::new(0),
        };
        let current = IamToken {
            token: "old".to_owned(),
            expires_at_unix: 1000,
        };
        // Fresh enough -> reused, no fetch.
        let t = ensure_fresh_token(Some(&current), &src, 900, 60).unwrap();
        assert_eq!(t.token, "old");
        assert_eq!(src.calls.get(), 0);
        // Near expiry -> fetched.
        let t = ensure_fresh_token(Some(&current), &src, 950, 60).unwrap();
        assert_eq!(t.token, "fresh");
        assert_eq!(src.calls.get(), 1);
        // No current token -> fetched.
        let _ = ensure_fresh_token(None, &src, 0, 60).unwrap();
        assert_eq!(src.calls.get(), 2);
    }
}
