//! `tnsnames.ora` parse adapter (TNS-onboarding bead `.3`; design spec §B/§F,
//! `docs/tns-discovery-onboarding.md`).
//!
//! A thin adapter over the **upstream** sans-I/O tnsnames reader
//! `oracledb_protocol::net::connectstring::tnsnames::TnsnamesReader`. It parses
//! a directory's `tnsnames.ora`, following `IFILE` includes, and returns one
//! entry per net-service — the alias, the raw connect descriptor, and
//! best-effort connection *hints* (host / port / service / protocol / wallet)
//! used only for the human discovery report and for choosing env-var names. The
//! upstream reader already handles `IFILE` includes, include-cycle detection,
//! comma-separated multi-line alias lists, upper-casing, and
//! last-definition-wins, so this crate never hand-rolls a TNS parser.
//!
//! # Driver seam
//!
//! The driver-adapter seam (`scripts/oraclemcp_driver_seam_lint.sh`; the
//! `driver_seam` test in `connection.rs`) forbids the driver-crate `::` path
//! (the `oracledb` crate followed by `::`) anywhere outside `connection.rs`.
//! This module deliberately depends on the underlying **`oracledb-protocol`**
//! crate directly and imports via the `oracledb_protocol::` path, which does NOT
//! match that seam pattern (the `_` breaks the adjacency the pattern requires).
//! `oracledb-protocol` is pinned to `=0.5.1`, the exact version `oracledb 0.5.1`
//! already resolves, and is pure encode/decode (no async runtime), so the driver
//! seam stays confined to `connection.rs` and the engine-free boundary holds.
//! The `seam_smoke` test below asserts this module names no driver-crate `::`
//! path.
//!
//! # Secrets
//!
//! `tnsnames.ora` descriptors do not carry the database password, but as a
//! forward guard the raw descriptor is redacted from [`TnsNetService`]'s `Debug`
//! (length only) so a descriptor that ever embeds a credential cannot leak into
//! a log or report.

use std::path::{Path, PathBuf};

use oracledb_protocol::net::connectstring::tnsnames::TnsnamesReader;

/// Best-effort connection hints extracted from a net-service descriptor.
///
/// These drive the human discovery report and the choice of env-var names; the
/// synthesized profile `connect_string` still stores the alias or a normalized
/// EZConnect (per the synthesis bead), not these hints.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TnsDescriptorHints {
    /// Transport protocol when explicit (`TCP` / `TCPS` from a descriptor's
    /// `(PROTOCOL=…)`, or a `scheme://` on an easy-connect string). `None` for a
    /// plain EZConnect with no scheme.
    pub protocol: Option<String>,
    /// Host, when extractable.
    pub host: Option<String>,
    /// Port, when extractable and a valid `u16`.
    pub port: Option<u16>,
    /// Service name (a descriptor's `SERVICE_NAME`, else `SID`, or the
    /// easy-connect service segment).
    pub service_name: Option<String>,
    /// Wallet directory hint for TCPS (a descriptor's `MY_WALLET_DIRECTORY` /
    /// `WALLET_LOCATION` / `DIRECTORY`, or an easy-connect `?wallet_location=…`).
    pub wallet_location: Option<String>,
}

/// One resolved net-service from a `tnsnames.ora`.
#[derive(Clone, PartialEq, Eq)]
pub struct TnsNetService {
    /// The alias, upper-cased exactly as Oracle Net stores it.
    pub service_name: String,
    /// The raw connect descriptor / easy-connect string, as returned by the
    /// upstream reader. Redacted from `Debug`; never logged verbatim.
    pub descriptor: String,
    /// Best-effort extracted connection hints.
    pub hints: TnsDescriptorHints,
}

impl std::fmt::Debug for TnsNetService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the raw descriptor (a forward secret guard); surface only the
        // alias, the non-sensitive hints, and the descriptor length.
        f.debug_struct("TnsNetService")
            .field("service_name", &self.service_name)
            .field(
                "descriptor",
                &format_args!("<{} bytes>", self.descriptor.len()),
            )
            .field("hints", &self.hints)
            .finish()
    }
}

/// The result of parsing a directory's `tnsnames.ora`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TnsParseResult {
    /// The primary `tnsnames.ora` path, when one was read.
    pub file_name: Option<PathBuf>,
    /// Resolved net-services, in first-seen order (last-definition-wins already
    /// applied by the upstream reader).
    pub services: Vec<TnsNetService>,
    /// Non-fatal notes (e.g. a missing `tnsnames.ora`).
    pub notes: Vec<String>,
}

/// A structured `tnsnames.ora` parse failure (never a panic).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TnsParseError {
    /// The upstream reader failed — a permission error, a missing `IFILE`
    /// target, or an `IFILE` include cycle. The upstream message is preserved.
    #[error("failed to read tnsnames.ora under {dir}: {message}")]
    Read {
        /// The directory whose `tnsnames.ora` was being read.
        dir: PathBuf,
        /// The upstream failure message (from `ProtocolError`).
        message: String,
    },
}

/// Parse the `tnsnames.ora` in `config_dir`, following `IFILE` includes.
///
/// - A **missing** `tnsnames.ora` yields an empty result plus a note (not an
///   error).
/// - An `IFILE` include **cycle** (or an unreadable file / missing include)
///   returns a structured [`TnsParseError::Read`], never a panic.
///
/// # Errors
///
/// Returns [`TnsParseError::Read`] when the upstream reader fails on an existing
/// `tnsnames.ora` (permission denied, missing `IFILE`, or include cycle).
pub fn parse_tnsnames_dir(config_dir: &Path) -> Result<TnsParseResult, TnsParseError> {
    let primary = config_dir.join("tnsnames.ora");
    if !primary.is_file() {
        return Ok(TnsParseResult {
            file_name: None,
            services: Vec::new(),
            notes: vec![format!("no tnsnames.ora in {}", config_dir.display())],
        });
    }

    let reader = TnsnamesReader::read(config_dir).map_err(|err| TnsParseError::Read {
        dir: config_dir.to_path_buf(),
        message: err.to_string(),
    })?;

    let services = reader
        .service_names()
        .into_iter()
        .map(|name| {
            let descriptor = reader.get(&name).unwrap_or_default().to_owned();
            let hints = extract_hints(&descriptor);
            TnsNetService {
                service_name: name,
                descriptor,
                hints,
            }
        })
        .collect();

    Ok(TnsParseResult {
        file_name: Some(reader.file_name().to_path_buf()),
        services,
        notes: Vec::new(),
    })
}

/// Best-effort hint extraction from a raw descriptor / easy-connect string.
#[must_use]
pub fn extract_hints(descriptor: &str) -> TnsDescriptorHints {
    let trimmed = descriptor.trim_start();
    if trimmed.starts_with('(') {
        extract_from_descriptor(descriptor)
    } else {
        extract_from_easy_connect(trimmed)
    }
}

/// Extract hints from a parenthesized TNS connect descriptor.
fn extract_from_descriptor(descriptor: &str) -> TnsDescriptorHints {
    TnsDescriptorHints {
        protocol: leaf_param(descriptor, "PROTOCOL").map(|p| p.to_ascii_uppercase()),
        host: leaf_param(descriptor, "HOST"),
        port: leaf_param(descriptor, "PORT").and_then(|p| p.parse::<u16>().ok()),
        service_name: leaf_param(descriptor, "SERVICE_NAME")
            .or_else(|| leaf_param(descriptor, "SID")),
        wallet_location: leaf_param(descriptor, "MY_WALLET_DIRECTORY")
            .or_else(|| leaf_param(descriptor, "WALLET_LOCATION"))
            .or_else(|| leaf_param(descriptor, "DIRECTORY")),
    }
}

/// Find the value of a leaf descriptor parameter `(KEY = value)`,
/// case-insensitively, returning the trimmed value up to the next `(` or `)`.
fn leaf_param(hay: &str, key: &str) -> Option<String> {
    let upper = hay.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    // `to_ascii_uppercase` preserves byte length, so indices align with `hay`.
    let needle = format!("({}", key.to_ascii_uppercase());
    let mut from = 0usize;
    while let Some(rel) = upper[from..].find(&needle) {
        let after_key = from + rel + needle.len();
        let mut i = after_key;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'=' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] != b')' && bytes[j] != b'(' {
                j += 1;
            }
            let value = hay[i + 1..j].trim().trim_matches('"').trim();
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
        from = after_key;
    }
    None
}

/// Extract hints from an easy-connect string
/// (`[scheme://]host:port/service[?params]`).
fn extract_from_easy_connect(input: &str) -> TnsDescriptorHints {
    let mut hints = TnsDescriptorHints::default();
    let mut rest = input.trim();

    if let Some(idx) = rest.find("://") {
        let scheme = rest[..idx].trim();
        if !scheme.is_empty() {
            hints.protocol = Some(scheme.to_ascii_uppercase());
        }
        rest = &rest[idx + 3..];
    }

    if let Some(qidx) = rest.find('?') {
        for kv in rest[qidx + 1..].split('&') {
            if let Some((k, v)) = kv.split_once('=')
                && k.trim().eq_ignore_ascii_case("wallet_location")
                && !v.trim().is_empty()
            {
                hints.wallet_location = Some(v.trim().to_owned());
            }
        }
        rest = &rest[..qidx];
    }

    let (hostport, service) = match rest.split_once('/') {
        Some((hp, svc)) => (hp.trim(), Some(svc.trim())),
        None => (rest.trim(), None),
    };

    if let Some(svc) = service {
        // Strip any trailing `/instance` or `:server` role segment.
        let svc = svc.split(['/', ':']).next().unwrap_or(svc).trim();
        if !svc.is_empty() {
            hints.service_name = Some(svc.to_owned());
        }
    }

    if let Some((host, port)) = hostport.rsplit_once(':') {
        let host = host.trim().trim_matches(['[', ']']);
        if !host.is_empty() {
            hints.host = Some(host.to_owned());
        }
        if let Ok(port) = port.trim().parse::<u16>() {
            hints.port = Some(port);
        }
    } else if !hostport.is_empty() {
        hints.host = Some(hostport.to_owned());
    }

    hints
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed canonical fixture tree (design spec §F), at
    /// `<workspace>/tests/fixtures/tns`.
    fn fixtures_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("tests")
            .join("fixtures")
            .join("tns")
    }

    fn service<'a>(result: &'a TnsParseResult, name: &str) -> &'a TnsNetService {
        result
            .services
            .iter()
            .find(|s| s.service_name == name)
            .unwrap_or_else(|| panic!("net-service {name} present"))
    }

    #[test]
    fn primary_fixture_enumerates_expected_services() {
        let result = parse_tnsnames_dir(&fixtures_root()).expect("primary fixture parses");

        // Four aliases, in first-seen order; last-definition-wins collapses the
        // duplicate, and the IFILE-included alias is present.
        let names: Vec<&str> = result
            .services
            .iter()
            .map(|s| s.service_name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["PRIMARY_TCPS", "EZ_PLAIN", "DUP_ALIAS", "INCLUDED_ONE"],
            "service_names count + order are fixed by the design spec §F.2"
        );
        assert_eq!(result.services.len(), 4);
        assert!(result.file_name.is_some());
        assert!(result.notes.is_empty());
    }

    #[test]
    fn tcps_descriptor_hints_incl_wallet() {
        let result = parse_tnsnames_dir(&fixtures_root()).expect("parse");
        let s = service(&result, "PRIMARY_TCPS");
        assert_eq!(s.hints.protocol.as_deref(), Some("TCPS"));
        assert_eq!(s.hints.host.as_deref(), Some("tcps.example.com"));
        assert_eq!(s.hints.port, Some(2484));
        assert_eq!(s.hints.service_name.as_deref(), Some("PRIMARY.example.com"));
        assert_eq!(
            s.hints.wallet_location.as_deref(),
            Some("/etc/oracle/wallet/primary")
        );
    }

    #[test]
    fn ez_connect_hints_have_no_protocol() {
        let result = parse_tnsnames_dir(&fixtures_root()).expect("parse");
        let s = service(&result, "EZ_PLAIN");
        assert_eq!(s.hints.protocol, None, "plain EZConnect has no scheme");
        assert_eq!(s.hints.host.as_deref(), Some("ez.example.com"));
        assert_eq!(s.hints.port, Some(1521));
        assert_eq!(s.hints.service_name.as_deref(), Some("EZSERVICE"));
        assert_eq!(s.hints.wallet_location, None);
    }

    #[test]
    fn duplicate_alias_takes_last_definition() {
        let result = parse_tnsnames_dir(&fixtures_root()).expect("parse");
        let s = service(&result, "DUP_ALIAS");
        // The second (post-IFILE) definition wins: new.example.com / NEW / 1522.
        assert_eq!(s.hints.protocol.as_deref(), Some("TCP"));
        assert_eq!(s.hints.host.as_deref(), Some("new.example.com"));
        assert_eq!(s.hints.port, Some(1522));
        assert_eq!(s.hints.service_name.as_deref(), Some("NEW.example.com"));
    }

    #[test]
    fn ifile_included_alias_is_followed() {
        let result = parse_tnsnames_dir(&fixtures_root()).expect("parse");
        let s = service(&result, "INCLUDED_ONE");
        assert_eq!(s.hints.host.as_deref(), Some("inc.example.com"));
        assert_eq!(s.hints.port, Some(1521));
        assert_eq!(
            s.hints.service_name.as_deref(),
            Some("INCLUDED.example.com")
        );
    }

    #[test]
    fn include_cycle_returns_structured_error_not_panic() {
        let err = parse_tnsnames_dir(&fixtures_root().join("cycle"))
            .expect_err("an IFILE include cycle is a structured error");
        let TnsParseError::Read { dir, message } = err;
        assert!(dir.ends_with("cycle"));
        assert!(
            message.contains("cycle"),
            "the upstream cycle diagnostic is preserved, got: {message}"
        );
    }

    #[test]
    fn missing_file_is_empty_result_with_note() {
        let tmp = std::env::temp_dir().join(format!(
            "oraclemcp_tns_missing_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).expect("mkdir");
        let result = parse_tnsnames_dir(&tmp).expect("missing file is not an error");
        assert!(result.services.is_empty());
        assert!(result.file_name.is_none());
        assert_eq!(result.notes.len(), 1);
        assert!(result.notes[0].contains("no tnsnames.ora"));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn debug_redacts_raw_descriptor() {
        let svc = TnsNetService {
            service_name: "X".to_owned(),
            descriptor: "(DESCRIPTION=(SECRET=hunter2))".to_owned(),
            hints: TnsDescriptorHints::default(),
        };
        let rendered = format!("{svc:?}");
        assert!(
            !rendered.contains("hunter2"),
            "raw descriptor must be redacted"
        );
        assert!(
            rendered.contains("bytes"),
            "descriptor shown as a byte length"
        );
    }

    /// Seam-lint smoke: this adapter reuses the upstream `oracledb_protocol`
    /// crate and names NO driver-crate `::` path (which would leak the seam that
    /// `scripts/oraclemcp_driver_seam_lint.sh` and the `connection.rs`
    /// `driver_seam` test enforce).
    #[test]
    fn seam_smoke_uses_protocol_crate_not_driver_path() {
        let source = include_str!("tns.rs");
        let driver = "oracledb";
        assert!(
            source.contains("oracledb_protocol::net::connectstring::tnsnames::TnsnamesReader"),
            "the adapter must reuse the upstream TnsnamesReader via oracledb_protocol"
        );
        // Mirror the seam pattern: the driver crate name followed (after
        // optional whitespace) by `::`. `oracledb_protocol::` never matches
        // because the `_` breaks the adjacency.
        for (n, line) in source.lines().enumerate() {
            let mut from = 0;
            while let Some(rel) = line[from..].find(driver) {
                let start = from + rel;
                let mut after = start + driver.len();
                let bytes = line.as_bytes();
                while after < bytes.len() && bytes[after].is_ascii_whitespace() {
                    after += 1;
                }
                assert!(
                    !line[after..].starts_with("::"),
                    "line {} names a driver-crate path: {}",
                    n + 1,
                    line.trim()
                );
                from = start + driver.len();
            }
        }
    }
}
