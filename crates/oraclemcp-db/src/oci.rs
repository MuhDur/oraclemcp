//! OCI / Oracle Cloud (Autonomous DB) connectivity hardening (plan §9.1; bead
//! P1-11 / oracle-qmwz.2.11). This is **hop-2** (Oracle Net), independent of the
//! MCP transport. Thick-mode ODPI-C natively connects to OCI-hosted Oracle and
//! Autonomous DB; no special driver path. P0-3 gave basic connect — this layer
//! hardens the cloud edge:
//!
//! - **Wallet discovery** — validate a downloaded ADB wallet directory has the
//!   files mTLS auto-login needs (`cwallet.sso` + `tnsnames.ora`) and surface its
//!   service aliases (`*_high` / `*_medium` / `*_low`).
//! - **ADB connect-string validation** — accept `tcps://…` (TLS), full TLS
//!   descriptors, and bare wallet aliases; **reject plaintext `tcp`** for ADB
//!   (cloud requires TLS/mTLS).
//! - **IAM token refresh** — a database-token (OCI IAM) refresh seam on a
//!   monotonic-skew expiry check; the actual OCI SDK call is injected at the edge.
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
        let uses_tls = lower.contains("protocol=tcps");
        if !uses_tls {
            return Err(OciError::InvalidAdbConnectString(
                "ADB descriptor must use PROTOCOL=TCPS (TLS)".to_owned(),
            ));
        }
        return Ok(AdbConnectInfo {
            uses_tls: true,
            wallet_location: wallet_param(&lower),
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
fn wallet_param(s: &str) -> Option<String> {
    let needle = "wallet_location=";
    let idx = s.to_ascii_lowercase().find(needle)? + needle.len();
    let rest = &s[idx..];
    let end = rest.find(['&', ')', '?', ' ']).unwrap_or(rest.len());
    let v = rest[..end].trim_matches(|c| c == '"' || c == '\'');
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
    #[must_use]
    pub fn needs_refresh(&self, now_unix: i64, skew_secs: i64) -> bool {
        now_unix + skew_secs >= self.expires_at_unix
    }
}

/// Fetches a fresh OCI IAM database token (the OCI SDK call, injected at the edge).
pub trait IamTokenSource {
    /// Obtain a current database token.
    fn fetch(&self) -> Result<IamToken, OciError>;
}

/// Return a token that is fresh at `now_unix`: reuse `current` if it does not
/// need refresh, else fetch a new one. Proactive refresh avoids mid-session
/// `ORA-` token-expiry failures.
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
