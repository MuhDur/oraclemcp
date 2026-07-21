//! The backend-independent [`OracleConnection`] trait and the thin
//! [`oracledb`]-backed [`RustOracleConnection`].
//!
//! The trait is `async` and `Cx`-first (B1): every method takes an explicit
//! `&asupersync::Cx`, so cancellation and the deadline/budget travel with the
//! call. Each round trip is bracketed by explicit `Cx` checkpoints (the
//! native-async driver also checkpoints `cx` internally).
//!
//! # Driver-adapter seam (B2; plan §8 release gate)
//!
//! This file is **the adapter** — the single, enforced isolation boundary for
//! the `oracledb` driver. Every real `oracledb::` call (connect, the
//! `execute_raw` execute path, fetch, LOB, REF CURSOR, auth, commit/rollback,
//! ping, error sanitization) lives here and nowhere else. The rest of the
//! workspace talks to Oracle exclusively through the [`OracleConnection`] trait
//! and the `oraclemcp-db` public surface; no other crate or module names an
//! `oracledb::` path. References to `oracledb` elsewhere are intentionally only
//! doc-links and human-readable driver descriptions (no driver calls).
//!
//! Isolating the driver here meant the `oracledb` 0.2.2 -> 0.5.x cut-over touched
//! exactly this one file: the removed `execute_query*` initial-execute family
//! collapsed onto the retained low-level `Connection::execute_raw` (same
//! `QueryResult`, same prefetch + optional per-call timeout, still composing with
//! the fetch primitives below); `QueryValue`/`BindValue` became
//! `#[non_exhaustive]`; and `oracledb::ConnectOptions` field reads moved to
//! getters. Error classification stays string-based
//! (`oraclemcp_error::parse_ora_code`) and the driver `Error` type is consumed
//! generically via [`Display`](std::fmt::Display) in `sanitize_driver_error`, so
//! no exhaustive match on the driver `Error` type exists to break; the one
//! exhaustive `QueryValue` match carries a fail-safe wildcard arm for any future
//! `#[non_exhaustive]` value kind.
//!
//! The seam is mechanically enforced two ways, both of which must keep passing:
//! - `scripts/oraclemcp_driver_seam_lint.sh` (wired into `.github/workflows/ci.yml`)
//!   fails if an `oracledb::` driver path appears outside this file.
//! - the `driver_seam` test module below greps the crate sources for the same
//!   invariant, so `cargo test` catches a leak even without the shell script.
//!
//! Both enforcers share one allowlist: this file is the only adapter site. If a
//! new legitimate `oracledb::` site is ever needed, it must be added to both the
//! shell lint's `ADAPTER_ALLOWLIST` and the test's `ADAPTER_ALLOWLIST`, with an
//! inline justification.

use crate::error::DbError;
use crate::serialize::SerializeOptions;
use crate::types::{
    OracleBackend, OracleBind, OracleCell, OracleConnectOptions, OracleConnectionInfo, OracleRow,
};
use asupersync::sync::Mutex as AsyncMutex;
use asupersync::{Budget, Cx, Time};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[cfg(feature = "test-utils")]
use std::collections::VecDeque;
use std::path::PathBuf;
#[cfg(feature = "test-utils")]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const CLEANUP_MASKED_POLLS: u32 = 100;
/// C1.4 owns the notification receiver and explicit deregistration, so a
/// standing query subscription has no server-side expiry. The subscription
/// registry accounts its EMON connection before the receiver is opened.
const CQN_SUBSCRIPTION_TIMEOUT_SECONDS: u32 = 0;

/// Opaque Oracle identity for one QUERY-level CQN registration.
///
/// This type contains no callback payload, rowids, or query rows. The adapter
/// retains the driver callback identity separately so only adapter cleanup can
/// use it; client-facing code must route a later event through a governed
/// re-read.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CqnQueryRegistration {
    registration_id: u64,
    query_id: u64,
}

impl CqnQueryRegistration {
    /// Build opaque QUERY-registration metadata for an alternate backend.
    ///
    /// This constructor is not an authorization decision. Server code obtains
    /// a usable source only after the CQN gate has re-classified and audited
    /// the query immediately before the driver effect.
    #[must_use]
    pub const fn new(registration_id: u64, query_id: u64) -> Self {
        CqnQueryRegistration {
            registration_id,
            query_id,
        }
    }

    /// Oracle's opaque subscription registration id.
    #[must_use]
    pub const fn registration_id(self) -> u64 {
        self.registration_id
    }

    /// Oracle's opaque registered-query id.
    #[must_use]
    pub const fn query_id(self) -> u64 {
        self.query_id
    }
}

impl std::fmt::Debug for CqnQueryRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CqnQueryRegistration")
            .field("registration_id", &self.registration_id)
            .field("query_id", &self.query_id)
            .finish()
    }
}

/// A driver-delivered CQN notification reduced to its registration identity.
///
/// The adapter deliberately discards Oracle's notification payload (including
/// table names, rowids, and query metadata) before it crosses into core. A
/// registration identity can only wake the already-bound MCP resource; it is
/// neither query data nor an authorization input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CqnDriverNotification {
    registration_id: u64,
}

impl CqnDriverNotification {
    /// Build a notification for one opaque registration identity.
    ///
    /// This is evidence of a callback, not a capability: the core fan-out
    /// accepts it only when it matches a previously registered QUERY-level
    /// source, and it emits only a resource-update event.
    #[must_use]
    pub const fn for_registration(registration_id: u64) -> Self {
        CqnDriverNotification { registration_id }
    }

    /// Oracle's opaque registration id associated with this callback.
    #[must_use]
    pub const fn registration_id(self) -> u64 {
        self.registration_id
    }
}

/// Result of one bounded EMON receive attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CqnNotificationOutcome {
    /// Oracle delivered a notification for a QUERY-level registration.
    Event(CqnDriverNotification),
    /// No notification arrived during the bounded receive window.
    TimedOut,
    /// The EMON stream closed and must not be treated as a successful update.
    Closed,
}

/// A privately-owned EMON notification receiver for one registered query.
///
/// Receivers never expose raw Oracle notification payloads. Their caller must
/// route an [`CqnDriverNotification`] through core's URI-only, coalescing
/// fan-out, where clients are required to re-read through the normal guard and
/// egress path.
#[async_trait(?Send)]
pub trait CqnNotificationReceiver {
    /// Receive one bounded notification outcome.
    async fn next_notification(&mut self, cx: &Cx) -> Result<CqnNotificationOutcome, DbError>;
}

/// The pinned thin `oracledb` driver's own version string, read from the driver
/// crate's [`oracledb::VERSION`] const (its `CARGO_PKG_VERSION`, resolved at the
/// driver's compile). Re-exported from this adapter — the ONE seam allowed to
/// name an `oracledb::` path — so consumers (e.g. `oraclemcp doctor`'s trio-stack
/// provenance) can report the *driver's* version without reaching for
/// `env!("CARGO_PKG_VERSION")`, which would resolve to the wrong crate. Because
/// the whole workspace pins `oracledb = "=0.8.4"`, this is `"0.8.4"`.
pub const DRIVER_VERSION: &str = oracledb::VERSION;

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResolvedConnectTarget {
    connect_string: String,
    uses_tcps: bool,
}

/// The directory whose `tnsnames.ora` resolves a bare connect alias: the
/// `TNS_ADMIN` environment variable when set, else the profile's wallet
/// directory (an OCI wallet ships its `tnsnames.ora` alongside `cwallet.sso`).
///
/// Only the *value* of `TNS_ADMIN` is read; the library never mutates it (that
/// would require `unsafe` `std::env::set_var` under edition 2024, which is
/// forbidden workspace-wide).
fn tns_admin_dir(opts: &OracleConnectOptions) -> Option<PathBuf> {
    if let Some(value) = std::env::var_os("TNS_ADMIN") {
        let dir = PathBuf::from(value);
        if !dir.as_os_str().is_empty() {
            return Some(dir);
        }
    }
    opts.wallet_location.clone()
}

/// Resolve a bare `tnsnames.ora` alias in `connect_string` to its full connect
/// descriptor via `TNS_ADMIN` / the wallet directory. Descriptors, URLs, and
/// EZConnect strings are already concrete and pass through unchanged.
fn resolve_tns_connect_string(opts: &OracleConnectOptions) -> Result<String, DbError> {
    let raw = opts.connect_string.trim();
    if raw.is_empty()
        || raw.starts_with('(')
        || raw.contains("://")
        || raw.contains('/')
        || raw.contains(':')
        || !raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    {
        return Ok(opts.connect_string.clone());
    }
    let Some(dir) = tns_admin_dir(opts) else {
        return Ok(opts.connect_string.clone());
    };
    match crate::tns::resolve_alias(&dir, raw) {
        Ok(Some(descriptor)) => Ok(descriptor),
        Ok(None) => Ok(opts.connect_string.clone()),
        Err(err) => Err(DbError::Connect(err.to_string())),
    }
}

/// Resolve the actual connect target and bind its transport proof to the same
/// first-address selection model used by the pinned thin driver.
fn resolve_selected_connect_target(
    opts: &OracleConnectOptions,
) -> Result<ResolvedConnectTarget, DbError> {
    let connect_string = resolve_tns_connect_string(opts)?;
    let descriptor = oracledb_protocol::net::connectstring::parse(&connect_string)
        .map_err(|err| DbError::Connect(err.to_string()))?
        .ok_or_else(|| {
            DbError::Connect(
                "Oracle Net alias could not be resolved to a concrete connect endpoint".to_owned(),
            )
        })?;
    let address = descriptor.first_address().ok_or_else(|| {
        DbError::Connect(
            "Oracle Net connect descriptor defines no usable endpoint (HOST is required)"
                .to_owned(),
        )
    })?;
    Ok(ResolvedConnectTarget {
        connect_string,
        uses_tcps: address.protocol.is_tls(),
    })
}

/// Return whether the concrete endpoint selected by the thin driver's Oracle
/// Net model uses TCPS.
///
/// Bare aliases are resolved through `TNS_ADMIN` or the configured wallet
/// directory first. The connect string is then parsed by the same
/// `oracledb-protocol` parser used by the pinned driver, and the first usable
/// address supplies the transport protocol. Wallet and certificate settings
/// are trust material only; they never turn a TCP address into TCPS.
///
/// # Errors
///
/// Returns [`DbError::Connect`] when an alias cannot be resolved, the connect
/// string is malformed, or it defines no usable endpoint. Credential sources
/// should treat every such error as a fail-closed transport result.
pub fn selected_endpoint_uses_tcps(opts: &OracleConnectOptions) -> Result<bool, DbError> {
    resolve_selected_connect_target(opts).map(|target| target.uses_tcps)
}

/// The X.509 validity window of a single wallet certificate, in Unix-epoch
/// seconds (K1; iec3.6.6). Server-owned mirror of the driver's
/// [`oracledb_protocol::tls::wallet::CertMetadata`] so no driver type crosses
/// the adapter seam. Both fields are seconds since 1970-01-01T00:00:00Z (UTC),
/// the form the certificate's `notBefore`/`notAfter` decode to — plain seconds
/// keep this trivially comparable against the current time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletCertValidity {
    /// `notBefore`: Unix-epoch seconds at/after which the certificate is valid.
    pub not_before: i64,
    /// `notAfter`: Unix-epoch seconds after which the certificate is expired.
    pub not_after: i64,
}

/// Offline cert-expiry probe (K1; iec3.6.6): parse the certificates in the
/// wallet directory `dir` and return each certificate's validity window.
///
/// This is the adapter seam for the driver's
/// [`WalletContents::certificate_metadata()`](oracledb_protocol::tls::wallet::WalletContents::certificate_metadata):
/// it maps every driver [`CertMetadata`](oracledb_protocol::tls::wallet::CertMetadata)
/// onto the server-owned [`WalletCertValidity`], so no driver type leaks past
/// this file. The wallet's own auto-login/primary precedence is honoured — the
/// first wallet file that parses end to end (`ewallet.pem` → password-bearing
/// `ewallet.p12` → `cwallet.sso`) supplies the certificates; a non-certificate
/// or unparseable DER entry is silently skipped by the driver's
/// `certificate_metadata()`.
///
/// Purely offline — it reads and parses the wallet files' bytes; it never opens
/// a DB connection or touches the network. Returns an empty vector when no
/// wallet file parses (there are then no certificates to age-check). Never
/// surfaces a wallet path, password, or key material.
#[must_use]
pub fn wallet_certificate_validity(
    dir: &std::path::Path,
    password: Option<&str>,
) -> Vec<WalletCertValidity> {
    use oracledb_protocol::tls::sso::parse_cwallet_sso;
    use oracledb_protocol::tls::wallet::{
        p12_wallet_path, parse_ewallet_p12, parse_ewallet_pem, pem_wallet_path, sso_wallet_path,
    };

    // Precedence: the first wallet file that parses to usable contents supplies
    // the certificates (mirrors the driver's wallet precedence). A
    // password-less `ewallet.p12` is never selected as primary — matching
    // `load_wallet`'s `have_p12 && password.is_some()`.
    let contents = std::fs::read(pem_wallet_path(dir))
        .ok()
        .and_then(|bytes| parse_ewallet_pem(&bytes, password).ok())
        .or_else(|| {
            if password.is_some() {
                std::fs::read(p12_wallet_path(dir))
                    .ok()
                    .and_then(|bytes| parse_ewallet_p12(&bytes, password).ok())
            } else {
                None
            }
        })
        .or_else(|| {
            std::fs::read(sso_wallet_path(dir))
                .ok()
                .and_then(|bytes| parse_cwallet_sso(&bytes).ok())
        });

    match contents {
        Some(contents) => contents
            .certificate_metadata()
            .into_iter()
            .map(|m| WalletCertValidity {
                not_before: m.not_before,
                not_after: m.not_after,
            })
            .collect(),
        None => Vec::new(),
    }
}

/// Which wallet file in a wallet directory won the precedence chain. Server-owned
/// mirror of the driver's [`oracledb::WalletFile`] so no driver type crosses the
/// adapter seam (iec3.2.35).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletFileChoice {
    /// `ewallet.pem` (PEM trust anchors + optional client identity).
    Pem,
    /// `ewallet.p12` (password-bearing PKCS#12 wallet).
    P12,
    /// `cwallet.sso` (SSO auto-login wallet).
    Sso,
}

impl WalletFileChoice {
    /// The on-disk file name of this wallet file.
    #[must_use]
    pub fn file_name(self) -> &'static str {
        use oracledb_protocol::tls::wallet::{
            P12_WALLET_FILE_NAME, PEM_WALLET_FILE_NAME, SSO_WALLET_FILE_NAME,
        };
        match self {
            WalletFileChoice::Pem => PEM_WALLET_FILE_NAME,
            WalletFileChoice::P12 => P12_WALLET_FILE_NAME,
            WalletFileChoice::Sso => SSO_WALLET_FILE_NAME,
        }
    }
}

/// The authoritative wallet-precedence outcome the driver's resolver returns
/// (iec3.2.35). Server-owned mirror of the driver's [`oracledb::WalletResolution`]
/// — the drift-free source of truth the doctor's own posture inference is
/// cross-checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletResolutionReport {
    /// The wallet file that supplied the resolved identity.
    pub chosen: WalletFileChoice,
    /// The primary wallet the driver attempted before any fallthrough, or `None`
    /// when the auto-login `cwallet.sso` was chosen directly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempted_primary: Option<WalletFileChoice>,
    /// `true` when the primary was present-but-unusable and resolution fell
    /// through to the auto-login `cwallet.sso`.
    pub fell_through: bool,
    /// Whether the attempted primary's failure was fallthrough-eligible.
    pub fallthrough_eligible: bool,
}

/// Secret-free class of a wallet-resolution failure (iec3.2.35). Mirrors the
/// driver's [`oracledb_protocol::tls::wallet::WalletError`] variant that
/// [`resolve_wallet_choice`] surfaced on the error path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletResolveError {
    /// No wallet file was present in the directory.
    FileMissing,
    /// A wallet file could not be read.
    Io,
    /// `ewallet.pem` was malformed.
    Pem,
    /// The wallet held no usable trust-anchor certificate.
    NoCertificates,
    /// `cwallet.sso` parsing failed.
    Sso,
    /// `cwallet.sso` parsing is not enabled in this build.
    SsoNotEnabled,
    /// A PKCS#12 (`ewallet.p12`) container failed to parse or decrypt.
    Pkcs12,
    /// An encrypted private key could not be decrypted (wrong/missing password
    /// or unsupported scheme).
    KeyDecrypt,
    /// The wallet requires a password that was not supplied.
    PasswordRequired,
    /// A recognized wallet file used an unsupported format.
    UnsupportedFormat,
    /// A forward-compatible wallet error class not otherwise mapped.
    Other,
}

/// Resolve which wallet file in `dir` wins the driver's precedence chain, via
/// the driver's public [`oracledb::resolve_wallet`] (iec3.2.35).
///
/// This is the adapter seam over the driver's own resolver — the same decision a
/// live connection makes, without the parsed key material. The doctor's offline
/// posture probe re-derives this precedence with the driver's sans-I/O parsers
/// (it needs the specific `WalletError` class the resolver discards on a
/// successful fallthrough, and it must distinguish "no wallet files" from a
/// hard failure); this seam lets a cross-check test pin that inference against
/// the driver's authoritative outcome so the two can never drift.
///
/// Purely offline — the driver's resolver reads and parses the wallet files but
/// opens no connection. The `Err` path maps the typed driver
/// [`WalletError`](oracledb_protocol::tls::wallet::WalletError) onto the
/// secret-free [`WalletResolveError`]; no wallet path, password, or key material
/// is ever surfaced.
pub fn resolve_wallet_choice(
    dir: &std::path::Path,
    password: Option<&str>,
) -> Result<WalletResolutionReport, WalletResolveError> {
    fn map_file(file: oracledb::WalletFile) -> WalletFileChoice {
        match file {
            oracledb::WalletFile::Pem => WalletFileChoice::Pem,
            oracledb::WalletFile::P12 => WalletFileChoice::P12,
            oracledb::WalletFile::Sso => WalletFileChoice::Sso,
        }
    }
    fn map_err(err: &oracledb_protocol::tls::wallet::WalletError) -> WalletResolveError {
        use oracledb_protocol::tls::wallet::WalletError;
        match err {
            WalletError::FileMissing(_) => WalletResolveError::FileMissing,
            WalletError::Io { .. } => WalletResolveError::Io,
            WalletError::Pem(_) => WalletResolveError::Pem,
            WalletError::NoCertificates => WalletResolveError::NoCertificates,
            WalletError::Sso(_) => WalletResolveError::Sso,
            WalletError::SsoNotEnabled => WalletResolveError::SsoNotEnabled,
            WalletError::Pkcs12(_) => WalletResolveError::Pkcs12,
            WalletError::KeyDecrypt(_) => WalletResolveError::KeyDecrypt,
            WalletError::PasswordRequired { .. } => WalletResolveError::PasswordRequired,
            WalletError::UnsupportedFormat { .. } => WalletResolveError::UnsupportedFormat,
            // The driver's `WalletError` is `#[non_exhaustive]`.
            _ => WalletResolveError::Other,
        }
    }

    match oracledb::resolve_wallet(dir, password) {
        Ok(res) => Ok(WalletResolutionReport {
            chosen: map_file(res.chosen),
            attempted_primary: res.attempted_primary.map(map_file),
            fell_through: res.fell_through,
            fallthrough_eligible: res.fallthrough_eligible,
        }),
        Err(oracledb::Error::Wallet(w)) => Err(map_err(&w)),
        Err(_) => Err(WalletResolveError::Other),
    }
}

/// Map an asupersync cancellation/budget checkpoint failure to the
/// timeout-class [`DbError::Cancelled`]. Used as the explicit before/after
/// cancellation boundary around every native-async driver round trip; the
/// driver itself also checkpoints `cx` internally, so a cancelled call is
/// observed either here or inside the driver and never silently completes.
///
/// Generic over the `Cx` capability row (A9): a read handler running under a
/// narrowed `Cx<ReadPathCaps>` checkpoints identically to one under the full
/// row, since cancellation/budget state lives on `Cx` independent of the effect
/// capabilities. This is the single crate-wide checkpoint helper; `query.rs`,
/// `lease.rs`, and `pool.rs` all route through it.
pub(crate) fn db_checkpoint<Caps>(cx: &Cx<Caps>, phase: &'static str) -> Result<(), DbError> {
    cx.checkpoint_with(phase)
        .map_err(|err| DbError::Cancelled(format!("{phase}: {err}")))
}

/// Shared application-level poll/cost allowance for one database request.
///
/// Asupersync's `Budget` is still the source of the initial limits and absolute
/// deadline, but its nonzero quota fields are not self-decrementing. This
/// handle supplies the explicit accounting seam used by dispatch and by every
/// thin-driver wire boundary. Clones share the same atomics, so nested helpers,
/// health subchecks, fetch loops, and row streams cannot reset the allowance.
#[derive(Clone, Debug)]
pub struct DbRequestQuota {
    inner: Arc<DbRequestQuotaInner>,
}

#[derive(Debug)]
struct DbRequestQuotaInner {
    polls_remaining: AtomicU32,
    // `u64::MAX` is the unbounded sentinel.
    cost_remaining: AtomicU64,
}

impl DbRequestQuota {
    /// Seed a shared allowance from an Asupersync budget snapshot.
    #[must_use]
    pub fn new(budget: Budget) -> Self {
        Self {
            inner: Arc::new(DbRequestQuotaInner {
                polls_remaining: AtomicU32::new(budget.poll_quota),
                cost_remaining: AtomicU64::new(budget.cost_quota.unwrap_or(u64::MAX)),
            }),
        }
    }

    /// Tighten the remaining allowance without ever replenishing it.
    pub fn tighten(&self, budget: Budget) {
        self.inner
            .polls_remaining
            .fetch_min(budget.poll_quota, Ordering::AcqRel);
        if let Some(limit) = budget.cost_quota {
            self.inner.cost_remaining.fetch_min(limit, Ordering::AcqRel);
        }
    }

    /// Remaining shared cooperative checkpoints.
    #[must_use]
    pub fn polls_remaining(&self) -> u32 {
        self.inner.polls_remaining.load(Ordering::Acquire)
    }

    /// Remaining shared cost units, or `None` when cost is unbounded.
    #[must_use]
    pub fn cost_remaining(&self) -> Option<u64> {
        match self.inner.cost_remaining.load(Ordering::Acquire) {
            u64::MAX => None,
            remaining => Some(remaining),
        }
    }

    /// Whether two handles charge the exact same request allowance.
    #[must_use]
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Charge one cooperative checkpoint.
    ///
    /// # Errors
    /// Returns [`DbError::Cancelled`] before the protected operation when the
    /// shared poll or cost allowance is exhausted.
    pub fn consume_checkpoint(&self, phase: &'static str) -> Result<(), DbError> {
        if self
            .inner
            .polls_remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            })
            .is_err()
        {
            return Err(DbError::Cancelled(format!(
                "{phase}: request poll quota exhausted"
            )));
        }

        if self
            .inner
            .cost_remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                if remaining == u64::MAX {
                    Some(u64::MAX)
                } else {
                    remaining.checked_sub(1)
                }
            })
            .is_err()
        {
            return Err(DbError::Cancelled(format!(
                "{phase}: request cost quota exhausted"
            )));
        }
        Ok(())
    }
}

/// Bounded `DBMS_OUTPUT` lines captured from a single Oracle session.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbmsOutput {
    /// The captured `DBMS_OUTPUT` lines, in emission order.
    pub lines: Vec<String>,
    /// Number of lines captured (`lines.len()`).
    pub line_count: usize,
    /// Total character count across all captured lines.
    pub char_count: usize,
    /// Whether the line or character cap stopped the drain before exhaustion.
    pub truncated: bool,
}

/// Adapter-layer PL/SQL routine argument for IN, OUT, IN-OUT, and return values.
///
/// This type is intentionally **not** deserializable: routine execution is an
/// internal adapter capability, not an agent-facing tool argument surface. It
/// wraps the thin driver's bind variants privately so callers can mix ordinary
/// input binds with output slots without exposing driver types across the
/// public API.
#[derive(Clone, PartialEq)]
pub struct OracleRoutineArg {
    bind: oracledb::protocol::thin::BindValue,
}

impl OracleRoutineArg {
    /// Build an input-only routine argument.
    #[must_use]
    pub fn input(value: OracleBind) -> Self {
        Self {
            bind: oracle_bind_to_driver(&value),
        }
    }

    /// Build a scalar OUT or IN-OUT argument. The pinned driver has no separate
    /// IN-OUT bind variant; its `Output` bind covers both cases.
    #[must_use]
    pub fn output(ora_type_num: u8, csfrm: u8, buffer_size: u32) -> Self {
        Self {
            bind: oracledb::protocol::thin::BindValue::Output {
                ora_type_num,
                csfrm,
                buffer_size,
            },
        }
    }

    /// Build a scalar return-value argument.
    ///
    /// Oracle routine function returns are bound by placing a normal output bind
    /// at the return position (usually `:1 := fn(...)`). The driver's
    /// `ReturnOutput` variant is for DML `RETURNING` shapes, not this routine
    /// adapter path.
    #[must_use]
    pub fn return_output(ora_type_num: u8, csfrm: u8, buffer_size: u32) -> Self {
        Self {
            bind: oracledb::protocol::thin::BindValue::Output {
                ora_type_num,
                csfrm,
                buffer_size,
            },
        }
    }

    /// Build an object OUT or IN-OUT argument.
    ///
    /// `oid` and `version` are the Oracle object type identity metadata already
    /// discovered by the adapter before routine execution.
    #[must_use]
    pub fn object_output(
        schema: String,
        type_name: String,
        oid: Vec<u8>,
        version: u32,
        buffer_size: u32,
    ) -> Self {
        Self::object_output_inner(schema, type_name, oid, version, buffer_size, false)
    }

    /// Build an object return-value argument.
    ///
    /// `oid` and `version` are the Oracle object type identity metadata already
    /// discovered by the adapter before routine execution.
    #[must_use]
    pub fn object_return_output(
        schema: String,
        type_name: String,
        oid: Vec<u8>,
        version: u32,
        buffer_size: u32,
    ) -> Self {
        Self::object_output_inner(schema, type_name, oid, version, buffer_size, true)
    }

    fn object_output_inner(
        schema: String,
        type_name: String,
        oid: Vec<u8>,
        version: u32,
        buffer_size: u32,
        is_return: bool,
    ) -> Self {
        Self {
            bind: oracledb::protocol::thin::BindValue::ObjectOutput {
                schema,
                type_name,
                oid,
                version,
                buffer_size,
                is_return,
            },
        }
    }

    pub(crate) fn into_driver_bind(self) -> oracledb::protocol::thin::BindValue {
        self.bind
    }

    fn is_output_bind(&self) -> bool {
        matches!(
            self.bind,
            oracledb::protocol::thin::BindValue::Output { .. }
                | oracledb::protocol::thin::BindValue::ReturnOutput { .. }
                | oracledb::protocol::thin::BindValue::ObjectOutput { .. }
        )
    }
}

impl std::fmt::Debug for OracleRoutineArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OracleRoutineArg")
            .field("kind", &self.bind.variant_name())
            .field("value", &"<driver-output-bind>")
            .finish()
    }
}

fn oracle_bind_to_driver(bind: &OracleBind) -> oracledb::protocol::thin::BindValue {
    match bind {
        OracleBind::Null => oracledb::protocol::thin::BindValue::Null,
        OracleBind::String(value) => oracledb::protocol::thin::BindValue::Text(value.clone()),
        OracleBind::I64(value) => oracledb::protocol::thin::BindValue::Number(value.to_string()),
        OracleBind::F64(value) => oracledb::protocol::thin::BindValue::BinaryDouble(*value),
        OracleBind::Bool(value) => {
            oracledb::protocol::thin::BindValue::Number(if *value { "1" } else { "0" }.to_owned())
        }
        OracleBind::TimestampTz {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanosecond,
            offset_minutes,
        } => oracledb::protocol::thin::BindValue::TimestampTz {
            year: *year,
            month: *month,
            day: *day,
            hour: *hour,
            minute: *minute,
            second: *second,
            nanosecond: *nanosecond,
            offset_minutes: *offset_minutes,
        },
    }
}

/// Result of adapter-internal PL/SQL routine execution.
///
/// Routine execution is deliberately a DB-crate adapter capability, not an
/// agent-facing tool. OUT, IN-OUT, and return values are exposed as
/// [`OracleCell`]s in the same positional order as the caller-declared
/// [`OracleRoutineArg`] list, independent of the driver's raw OUT-bind return
/// order.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExecuteOutcome {
    rows_affected: u64,
    out_binds: Vec<OracleCell>,
}

impl ExecuteOutcome {
    /// Build an execution outcome from an affected-row count and already
    /// ordered OUT-bind cells.
    #[must_use]
    pub fn new(rows_affected: u64, out_binds: Vec<OracleCell>) -> Self {
        Self {
            rows_affected,
            out_binds,
        }
    }

    /// Rows affected as reported by Oracle for the executed PL/SQL block.
    #[must_use]
    pub const fn rows_affected(&self) -> u64 {
        self.rows_affected
    }

    /// OUT, IN-OUT, and return values in declared routine-argument order.
    #[must_use]
    pub fn out_binds(&self) -> &[OracleCell] {
        &self.out_binds
    }

    /// Consume the outcome and return its ordered OUT-bind cells.
    #[must_use]
    pub fn into_out_binds(self) -> Vec<OracleCell> {
        self.out_binds
    }
}

/// Result of starting an owned row stream for `oracle_query`.
///
/// `Stream` means the DB seam can serialize rows byte-identically without
/// connection-owned side reads. `Fallback` means the statement is proven read
/// and the connection has already been recovered, but the caller must use the
/// existing cursor-chunked path to preserve complex value behavior.
pub enum QueryRowStreamStart {
    /// The statement can be delivered row-by-row through the owned stream.
    Stream(QueryRowStream),
    /// The statement is proven read-only but needs cursor-chunked delivery to
    /// preserve complex value materialization.
    Fallback {
        /// Plain operator-facing reason for choosing the chunked fallback.
        reason: String,
    },
}

/// Server-owned row stream facade over the driver-owned stream.
///
/// This type deliberately hides `oracledb::OwnedRowStream` outside this file:
/// callers get serialized `OracleRow`s and an explicit recovery method, never
/// the driver stream itself.
pub struct QueryRowStream {
    inner: QueryRowStreamInner,
}

enum QueryRowStreamInner {
    Driver(Box<driver::RustOracleRowStream>),
    #[cfg(feature = "test-utils")]
    StaticRows(StaticQueryRowStream),
}

#[cfg(feature = "test-utils")]
struct StaticQueryRowStream {
    columns: Vec<String>,
    rows: VecDeque<OracleRow>,
    recovered: Option<Arc<AtomicUsize>>,
}

impl QueryRowStream {
    fn new(inner: driver::RustOracleRowStream) -> Self {
        Self {
            inner: QueryRowStreamInner::Driver(Box::new(inner)),
        }
    }

    /// Construct an in-memory stream for higher-level dispatcher tests.
    ///
    /// Production callers should never use this; it exists so crates above the
    /// DB seam can prove row-frame delivery and cancellation without naming the
    /// driver-owned stream type.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    #[must_use]
    pub fn from_static_rows_for_testing(
        columns: Vec<String>,
        rows: Vec<OracleRow>,
        recovered: Option<Arc<AtomicUsize>>,
    ) -> Self {
        Self {
            inner: QueryRowStreamInner::StaticRows(StaticQueryRowStream {
                columns,
                rows: rows.into(),
                recovered,
            }),
        }
    }

    /// Column names in select-list order.
    #[must_use]
    pub fn columns(&self) -> &[String] {
        match &self.inner {
            QueryRowStreamInner::Driver(inner) => inner.columns(),
            #[cfg(feature = "test-utils")]
            QueryRowStreamInner::StaticRows(inner) => &inner.columns,
        }
    }

    /// Fetch and serialize the next row, or `None` when the stream is drained.
    pub async fn next_row(&mut self, cx: &Cx) -> Result<Option<OracleRow>, DbError> {
        match &mut self.inner {
            QueryRowStreamInner::Driver(inner) => inner.next_row(cx).await,
            #[cfg(feature = "test-utils")]
            QueryRowStreamInner::StaticRows(inner) => {
                db_checkpoint(cx, "oracle_db.query_row_stream.static.next")?;
                Ok(inner.rows.pop_front())
            }
        }
    }

    /// Recover the owned connection back into the connection slot.
    pub async fn recover(self, cx: &Cx) -> Result<(), DbError> {
        match self.inner {
            QueryRowStreamInner::Driver(inner) => inner.recover(cx).await,
            #[cfg(feature = "test-utils")]
            QueryRowStreamInner::StaticRows(inner) => {
                if let Some(recovered) = inner.recovered {
                    recovered.fetch_add(1, Ordering::SeqCst);
                }
                db_checkpoint(cx, "oracle_db.query_row_stream.static.recovered")?;
                Ok(())
            }
        }
    }
}

/// An async, `Cx`-first Oracle connection (B1).
///
/// Every method is `async` and takes an explicit `&Cx` so cancellation and the
/// deadline/budget travel with the call: the native-async `oracledb` driver
/// checkpoints `cx` on every round trip, and this trait adds explicit
/// before/after `db_checkpoint` boundaries so a cancelled call is mapped to
/// the timeout-class [`DbError::Cancelled`] and never silently completes.
///
/// The trait is made object-safe with `async_trait` in `?Send` mode: the
/// MCP dispatch runtime is a single current-thread Asupersync runtime
/// (`oraclemcp-core/src/server.rs`) and no dispatch future is ever spawned
/// across OS threads, so the boxed method futures do not need to be `Send`.
/// This keeps `&dyn OracleConnection` / `Box<dyn OracleConnection>` usable
/// everywhere while letting an implementation hold an Asupersync `Mutex` guard
/// (which is `!Send`) across an `.await`.
#[async_trait(?Send)]
pub trait OracleConnection: Send + Sync {
    /// The backend in use.
    fn backend(&self) -> OracleBackend;
    /// Round-trip the server to confirm liveness (`SELECT 1 FROM dual`).
    async fn ping(&self, cx: &Cx) -> Result<(), DbError>;
    /// Best-effort connection metadata (version, role/open-mode, schema).
    async fn describe(&self, cx: &Cx) -> Result<OracleConnectionInfo, DbError>;
    /// Run a query, binding `binds` positionally (`:1`, `:2`, …). Values are
    /// always bound, never interpolated.
    async fn query_rows(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError>;
    /// Run a query with serialization caps available to the backend. Backends
    /// that materialize driver-side locators should use these caps; backends
    /// without locator values can fall back to [`OracleConnection::query_rows`].
    async fn query_rows_with_serialize_options(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
        serialize_opts: &SerializeOptions,
    ) -> Result<Vec<OracleRow>, DbError> {
        let _ = serialize_opts;
        self.query_rows(cx, sql, binds).await
    }
    /// Fetch and serialize one bounded positional-bind page without retaining
    /// materialized rows outside the page byte budget. `None` asks the caller
    /// to use the compatibility `query_rows` path for backends that do not yet
    /// implement bounded paging.
    async fn query_bounded_page(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
        caps: crate::query::QueryCaps,
        offset: usize,
        serialize_opts: &SerializeOptions,
    ) -> Result<Option<crate::query::QueryResponse>, DbError> {
        let _ = (cx, sql, binds, caps, offset, serialize_opts);
        Ok(None)
    }
    /// Start a row-by-row stream for a proven read. Backends that cannot return
    /// an owned stream should fail explicitly so callers can retain the existing
    /// chunked streaming path.
    async fn query_row_stream(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
        arraysize: usize,
        serialize_opts: &SerializeOptions,
    ) -> Result<QueryRowStreamStart, DbError> {
        let _ = (cx, sql, binds, arraysize, serialize_opts);
        Err(DbError::UnsupportedFeature(
            "owned row streaming is not supported by this Oracle backend".to_owned(),
        ))
    }
    /// Run a query, binding `binds` by name (`:name`). Values are always bound,
    /// never interpolated. Backends that cannot bind by name should fail
    /// explicitly instead of trying to rewrite SQL.
    async fn query_rows_named(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[(String, OracleBind)],
    ) -> Result<Vec<OracleRow>, DbError> {
        let _ = (cx, sql, binds);
        Err(DbError::Query(
            "named binds are not supported by this Oracle backend".to_owned(),
        ))
    }
    /// Run a named-bind query with serialization caps available to the backend.
    async fn query_rows_named_with_serialize_options(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[(String, OracleBind)],
        serialize_opts: &SerializeOptions,
    ) -> Result<Vec<OracleRow>, DbError> {
        let _ = serialize_opts;
        self.query_rows_named(cx, sql, binds).await
    }
    /// Named-bind counterpart of [`OracleConnection::query_bounded_page`].
    async fn query_bounded_page_named(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[(String, OracleBind)],
        caps: crate::query::QueryCaps,
        offset: usize,
        serialize_opts: &SerializeOptions,
    ) -> Result<Option<crate::query::QueryResponse>, DbError> {
        let _ = (cx, sql, binds, caps, offset, serialize_opts);
        Ok(None)
    }
    /// Run a DML/DDL statement; returns rows affected (`SQL%ROWCOUNT`).
    ///
    /// If this observes cancellation after Oracle has returned success, callers
    /// must treat the session as dirty and run cleanup rollback/discard logic.
    async fn execute(&self, cx: &Cx, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError>;

    /// Create an Oracle CQN registration for exactly one already-proven query.
    ///
    /// This adapter issues only query-result-change registration and never
    /// requests object-wide events or rowids. It is deliberately not an
    /// agent-facing admission surface: callers must have just re-run their
    /// profile, classifier, step-up, and audit gate before calling it.
    async fn register_cqn_query(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<CqnQueryRegistration, DbError> {
        let _ = (cx, sql, binds);
        Err(DbError::UnsupportedFeature(
            "query-level CQN registration is not supported by this Oracle backend".to_owned(),
        ))
    }

    /// Deregister a query-level CQN subscription previously returned by
    /// [`OracleConnection::register_cqn_query`].
    ///
    /// This is adapter cleanup, not a client-controlled action. Backends that
    /// cannot retain the driver-owned callback identity fail explicitly.
    async fn unregister_cqn_query(
        &self,
        cx: &Cx,
        registration: CqnQueryRegistration,
    ) -> Result<(), DbError> {
        let _ = (cx, registration);
        Err(DbError::UnsupportedFeature(
            "query-level CQN deregistration is not supported by this Oracle backend".to_owned(),
        ))
    }

    /// Open the separate EMON connection that receives callbacks for one
    /// already-registered QUERY-level subscription.
    ///
    /// This is adapter plumbing, never an agent-facing admission surface. The
    /// caller must have first obtained the registration through the CQN gate
    /// and admitted the subscription through the per-principal/per-DB registry
    /// before opening this second connection.
    async fn open_cqn_notification_receiver(
        &self,
        cx: &Cx,
        registration: CqnQueryRegistration,
    ) -> Result<Box<dyn CqnNotificationReceiver>, DbError> {
        let _ = (cx, registration);
        Err(DbError::UnsupportedFeature(
            "CQN EMON notification receivers are not supported by this Oracle backend".to_owned(),
        ))
    }

    /// Execute an adapter-internal PL/SQL routine block with positional OUT,
    /// IN-OUT, or return bind slots.
    ///
    /// This is intentionally not an agent-facing routine tool. The caller
    /// supplies the exact PL/SQL block and a positional [`OracleRoutineArg`]
    /// list; returned OUT cells are ordered by that list, not by the driver's
    /// raw OUT-bind vector. A called routine may execute `COMMIT` internally;
    /// callers that need transactional guarantees must account for that Oracle
    /// behavior before invoking this adapter path.
    async fn call_routine(
        &self,
        cx: &Cx,
        plsql_block: &str,
        args: &[OracleRoutineArg],
    ) -> Result<ExecuteOutcome, DbError> {
        let _ = (cx, plsql_block, args);
        Err(DbError::Execute(
            "routine execution is not supported by this Oracle backend".to_owned(),
        ))
    }

    /// Current Oracle per-round-trip call timeout, when supported by the backend.
    fn call_timeout(&self) -> Result<Option<Duration>, DbError> {
        Ok(None)
    }

    /// Set the Oracle per-round-trip call timeout. `None` disables it.
    fn set_call_timeout(&self, timeout: Option<Duration>) -> Result<(), DbError> {
        let _ = timeout;
        Ok(())
    }

    /// Current absolute deadline for the whole request using this connection.
    ///
    /// This is separate from [`OracleConnection::call_timeout`]: the latter is
    /// a relative cap applied afresh to each Oracle round trip, while this
    /// deadline is anchored once at request admission and must only shrink as
    /// a multi-round-trip request progresses. Backends that do not support an
    /// adapter-owned absolute deadline may retain the default `None` value.
    fn request_deadline(&self, cx: &Cx) -> Result<Option<Time>, DbError> {
        let _ = cx;
        Ok(None)
    }

    /// Set the absolute whole-request deadline used to cap every subsequent
    /// Oracle round trip. `None` clears the request-scoped cap.
    ///
    /// Callers must scope changes and restore the previous value on drop. A
    /// cleanup/finalizer may temporarily replace an expired request deadline
    /// with its own fresh bounded deadline so rollback and session teardown are
    /// not skipped merely because the primary request budget elapsed.
    fn set_request_deadline(&self, cx: &Cx, deadline: Option<Time>) -> Result<(), DbError> {
        let _ = (cx, deadline);
        Ok(())
    }

    /// Current shared application-level request quota, when supported.
    fn request_quota(&self, cx: &Cx) -> Result<Option<DbRequestQuota>, DbError> {
        let _ = cx;
        Ok(None)
    }

    /// Install or clear the shared application-level request quota.
    ///
    /// Like [`OracleConnection::set_request_deadline`], callers must scope this
    /// setting and restore the prior handle. Cleanup deliberately clears the
    /// primary quota and uses its own fresh bounded allowance.
    fn set_request_quota(&self, cx: &Cx, quota: Option<DbRequestQuota>) -> Result<(), DbError> {
        let _ = (cx, quota);
        Ok(())
    }

    /// Enable `DBMS_OUTPUT` for this session. `buffer_bytes` is passed through
    /// to Oracle; callers should keep it bounded.
    async fn enable_dbms_output(&self, cx: &Cx, buffer_bytes: Option<u32>) -> Result<(), DbError> {
        match buffer_bytes {
            Some(bytes) => self
                .execute(
                    cx,
                    "BEGIN DBMS_OUTPUT.ENABLE(:1); END;",
                    &[OracleBind::I64(i64::from(bytes))],
                )
                .await
                .map(|_| ()),
            None => self
                .execute(cx, "BEGIN DBMS_OUTPUT.ENABLE(NULL); END;", &[])
                .await
                .map(|_| ()),
        }
    }

    /// Drain `DBMS_OUTPUT` from this session, bounded by line and character
    /// limits. Backends without output-bind support must fail explicitly.
    async fn read_dbms_output(
        &self,
        cx: &Cx,
        max_lines: usize,
        max_chars: usize,
    ) -> Result<DbmsOutput, DbError> {
        let _ = (cx, max_lines, max_chars);
        Err(DbError::Execute(
            "DBMS_OUTPUT capture is not supported by this Oracle backend".to_owned(),
        ))
    }

    /// Commit the current transaction on this session. There is intentionally
    /// no post-commit checkpoint: once Oracle commits, cancellation cannot
    /// undo it.
    async fn commit(&self, cx: &Cx) -> Result<(), DbError>;

    /// Roll back the current transaction on this session.
    async fn rollback(&self, cx: &Cx) -> Result<(), DbError>;

    /// Log off and close this physical Oracle session.
    ///
    /// Lifecycle owners call this after their rollback/finalization work rather
    /// than relying on Rust drop. The thin implementation delegates to the
    /// driver's consuming logical-logoff path; lightweight test backends may
    /// retain this no-op default when they do not own a physical session.
    async fn close(&self, cx: &Cx) -> Result<(), DbError> {
        let _ = cx;
        Ok(())
    }

    /// Tear down any `DBMS_FLASHBACK` session read-snapshot window (K9).
    ///
    /// This is **cleanup**: like [`OracleConnection::rollback`], the primary
    /// backend issues it WITHOUT an adapter-level pre-checkpoint, so a cancelled
    /// flashback read still reaches the driver and leaves the pinned session in
    /// normal (current-SCN) read mode — never stranded reading a stale snapshot.
    /// `DBMS_FLASHBACK.DISABLE` is idempotent (a no-op when flashback is not
    /// enabled), so this is safe to call unconditionally. The default impl runs
    /// it through [`OracleConnection::execute`]; backends that pre-checkpoint
    /// `execute` should override this to skip that checkpoint (cleanup must not
    /// be skipped on cancellation).
    async fn flashback_disable(&self, cx: &Cx) -> Result<(), DbError> {
        self.execute(cx, DBMS_FLASHBACK_DISABLE, &[] as &[OracleBind])
            .await
            .map(|_| ())
    }

    /// Run a query expecting at most one row.
    async fn query_optional_row(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Option<OracleRow>, DbError> {
        Ok(self.query_rows(cx, sql, binds).await?.into_iter().next())
    }
}

/// The idempotent teardown for a `DBMS_FLASHBACK` session read-snapshot window
/// (K9). A no-op when flashback is not enabled, so it is safe to call
/// unconditionally as cleanup.
pub(crate) const DBMS_FLASHBACK_DISABLE: &str = "BEGIN DBMS_FLASHBACK.DISABLE; END;";

/// Thin pure-Rust Oracle connection wrapper over the native-async
/// [`oracledb::Connection`] (B1).
///
/// The driver connection lives behind an Asupersync [`AsyncMutex`] so its
/// `&mut self` round trips can be driven by `&self` trait methods while
/// staying cancellation-safe: the guard is async-aware and may be held across
/// an `.await` (unlike `std::sync::Mutex`, which would be a deadlock/cancel
/// hazard). The connection is single-owner per lease and the server is
/// OS-thread-per-connection, so the mutex never actually contends — it is the
/// interior-mutability primitive, not a concurrency throttle. The
/// `BlockingConnection` facade (and its per-call `build_io_runtime` +
/// `block_on`) is gone: every round trip runs on the one ambient Asupersync
/// runtime.
pub struct RustOracleConnection {
    opts: OracleConnectOptions,
    inner: Arc<AsyncMutex<RustOracleConnectionSlot>>,
    /// Relative per-round-trip timeout plus the absolute whole-request
    /// deadline. A plain `std::sync::Mutex` is fine here: it is only ever
    /// locked-and-dropped synchronously (never held across an `.await`), so it
    /// cannot deadlock the cooperative scheduler. Keeping both limits behind
    /// one lock also makes each wire-call snapshot internally coherent.
    wire_limits: Mutex<WireLimits>,
    /// Driver callback identities, keyed by registration id, kept private so
    /// only adapter cleanup can use them. No CQN payload crosses this boundary.
    cqn_client_ids: Mutex<HashMap<u64, Vec<u8>>>,
}

#[derive(Clone, Debug, Default)]
struct WireLimits {
    call_timeout: Option<Duration>,
    request_deadline: Option<Time>,
    request_quota: Option<DbRequestQuota>,
}

impl WireLimits {
    fn effective_timeout_ms(&self, cx: &Cx, phase: &'static str) -> Result<Option<u32>, DbError> {
        if let Some(quota) = &self.request_quota {
            quota.consume_checkpoint(phase)?;
        }
        self.effective_timeout_ms_at(cx.now(), cx.budget().deadline, phase)
    }

    fn effective_timeout_ms_at(
        &self,
        now: Time,
        cx_deadline: Option<Time>,
        phase: &'static str,
    ) -> Result<Option<u32>, DbError> {
        let mut remaining = self.call_timeout;
        for (kind, deadline) in [("request", self.request_deadline), ("context", cx_deadline)] {
            let Some(deadline) = deadline else {
                continue;
            };
            if now >= deadline {
                return Err(DbError::Cancelled(format!(
                    "{phase}: {kind} deadline exceeded"
                )));
            }
            let until_deadline =
                Duration::from_nanos(deadline.as_nanos().saturating_sub(now.as_nanos()));
            remaining = Some(remaining.map_or(until_deadline, |cap| cap.min(until_deadline)));
        }
        Ok(remaining.map(duration_to_millis))
    }

    /// A cleanup round trip must not inherit the request/caller deadline that
    /// caused cleanup to run. It gets one fresh short ceiling, still tightened
    /// by any operator-configured per-wire cap.
    fn cleanup_timeout_ms(self) -> u32 {
        duration_to_millis(
            self.call_timeout
                .map_or(CLEANUP_TIMEOUT, |timeout| timeout.min(CLEANUP_TIMEOUT)),
        )
    }
}

struct RustOracleConnectionSlot {
    connection: Option<oracledb::Connection>,
    quarantine_reason: Option<String>,
}

struct RustOracleConnectionGuard<'a> {
    guard: asupersync::sync::MutexGuard<'a, RustOracleConnectionSlot>,
}

impl RustOracleConnectionGuard<'_> {
    /// Permanently remove a connection whose cleanup boundary failed. Merely
    /// returning an uncertain error is not sufficient for a pinned session:
    /// the same adapter could otherwise be called again after the caller lost
    /// the diagnostic. Dropping the driver connection makes reuse impossible,
    /// while the retained reason keeps subsequent failures structural.
    fn quarantine(mut self, reason: String) {
        self.guard.quarantine_reason = Some(reason);
        drop(self.guard.connection.take());
    }
}

async fn quarantine_connection_slot(
    inner: &Arc<AsyncMutex<RustOracleConnectionSlot>>,
    cx: &Cx,
    reason: String,
) -> DbError {
    let mut guard = match inner.lock(cx).await {
        Ok(guard) => guard,
        Err(err) => return DbError::Internal(format!("thin connection lock failed: {err}")),
    };
    let reason = guard.quarantine_reason.get_or_insert(reason).clone();
    drop(guard.connection.take());
    DbError::Quarantined {
        outcome: crate::error::QuarantineOutcome::UnknownDiscarded,
        message: reason,
    }
}

impl std::ops::Deref for RustOracleConnectionGuard<'_> {
    type Target = oracledb::Connection;

    fn deref(&self) -> &Self::Target {
        self.guard
            .connection
            .as_ref()
            .expect("thin connection slot must be occupied while borrowed")
    }
}

impl std::ops::DerefMut for RustOracleConnectionGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.guard
            .connection
            .as_mut()
            .expect("thin connection slot must be occupied while mutably borrowed")
    }
}

impl RustOracleConnection {
    /// Open a thin-mode connection per `opts`.
    pub async fn connect(cx: &Cx, opts: OracleConnectOptions) -> Result<Self, DbError> {
        driver::connect(cx, opts).await
    }

    async fn lock_inner(&self, cx: &Cx) -> Result<RustOracleConnectionGuard<'_>, DbError> {
        let guard = self
            .inner
            .lock(cx)
            .await
            .map_err(|err| DbError::Internal(format!("thin connection lock failed: {err}")))?;
        if let Some(reason) = guard.quarantine_reason.as_deref() {
            return Err(DbError::Quarantined {
                outcome: crate::error::QuarantineOutcome::UnknownDiscarded,
                message: reason.to_owned(),
            });
        }
        if guard.connection.is_none() {
            return Err(DbError::Internal(
                "thin connection is temporarily unavailable while an owned row stream is active"
                    .to_owned(),
            ));
        }
        Ok(RustOracleConnectionGuard { guard })
    }

    fn wire_limits(&self) -> Result<WireLimits, DbError> {
        self.wire_limits
            .lock()
            .map(|limits| limits.clone())
            .map_err(|err| DbError::Internal(format!("wire-limits lock poisoned: {err}")))
    }

    /// The options this connection was opened with.
    #[must_use]
    pub fn options(&self) -> &OracleConnectOptions {
        &self.opts
    }

    async fn take_connection(&self, cx: &Cx) -> Result<oracledb::Connection, DbError> {
        let mut guard = self
            .inner
            .lock(cx)
            .await
            .map_err(|err| DbError::Internal(format!("thin connection lock failed: {err}")))?;
        if let Some(reason) = guard.quarantine_reason.as_deref() {
            return Err(DbError::Quarantined {
                outcome: crate::error::QuarantineOutcome::UnknownDiscarded,
                message: reason.to_owned(),
            });
        }
        guard.connection.take().ok_or_else(|| {
            DbError::Internal("thin connection is already owned by an active row stream".to_owned())
        })
    }

    async fn replace_connection(
        &self,
        cx: &Cx,
        connection: oracledb::Connection,
    ) -> Result<(), DbError> {
        let mut guard = self
            .inner
            .lock(cx)
            .await
            .map_err(|err| DbError::Internal(format!("thin connection lock failed: {err}")))?;
        if let Some(reason) = guard.quarantine_reason.as_deref() {
            return Err(DbError::Quarantined {
                outcome: crate::error::QuarantineOutcome::UnknownDiscarded,
                message: reason.to_owned(),
            });
        }
        if guard.connection.is_some() {
            let reason =
                "thin connection slot was unexpectedly occupied during row-stream recovery"
                    .to_owned();
            guard.quarantine_reason = Some(reason.clone());
            drop(guard.connection.take());
            return Err(DbError::Quarantined {
                outcome: crate::error::QuarantineOutcome::UnknownDiscarded,
                message: reason,
            });
        }
        guard.connection = Some(connection);
        Ok(())
    }

    async fn query_first_row(&self, cx: &Cx, sql: &str) -> Result<Option<OracleRow>, DbError> {
        Ok(self.query_rows(cx, sql, &[]).await?.into_iter().next())
    }

    async fn describe_first_row(&self, cx: &Cx, sql: &str) -> Result<Option<OracleRow>, DbError> {
        degrade_describe_probe(self.query_first_row(cx, sql).await)
    }
}

/// Preserve cancellation and connection uncertainty from an observational
/// metadata probe while retaining `describe`'s best-effort contract for an
/// ordinary Oracle query/privilege failure. Other structural failures are not
/// proven safe to ignore and therefore propagate as well.
fn degrade_describe_probe<T>(result: Result<Option<T>, DbError>) -> Result<Option<T>, DbError> {
    match result {
        Err(error @ DbError::Query(_)) if !error.is_uncertain_session_state() => Ok(None),
        result => result,
    }
}

fn duration_to_millis(duration: Duration) -> u32 {
    // Oracle's public timeout is integer milliseconds and treats zero as
    // unbounded. Round a positive sub-millisecond remainder up so an absolute
    // deadline can never accidentally disable the timeout at its boundary.
    let millis = duration
        .as_nanos()
        .saturating_add(999_999)
        .checked_div(1_000_000)
        .unwrap_or(u128::MAX)
        .min(u128::from(u32::MAX));
    u32::try_from(millis).unwrap_or(u32::MAX)
}

mod driver {
    use super::{
        CqnDriverNotification, CqnNotificationOutcome, CqnNotificationReceiver,
        CqnQueryRegistration, DbmsOutput, ExecuteOutcome, OracleRoutineArg, QueryRowStream,
        QueryRowStreamStart, RustOracleConnection, oracle_bind_to_driver,
    };
    use crate::auth_adapter::AuthAdapter;
    use crate::error::{ConnectFailureKind, DbError};
    use crate::query::{QueryCaps, QueryPageBuilder, QueryPagePush, QueryResponse};
    use crate::serialize::{SerializeOptions, StructuredDecodeCaps, json_byte_len};
    use crate::types::{
        OracleBind, OracleCell, OracleConnectOptions, OracleConnectionInfo, OracleNestedResult,
        OracleRow, OracleSessionIdentity,
    };
    use asupersync::Cx;
    use asupersync::combinator::try_commit_section;
    use asupersync::sync::Mutex as AsyncMutex;
    use futures_core::Stream;
    use oracledb::protocol::thin::{CursorValue, LobValue, ObjectValue};
    use oracledb::protocol::{
        ClientIdentity,
        oson::OsonValue,
        thin::{
            BindValue, CS_FORM_IMPLICIT, ColumnMetadata, ExecuteOptions, ORA_TYPE_NUM_BFILE,
            ORA_TYPE_NUM_BINARY_DOUBLE, ORA_TYPE_NUM_BINARY_FLOAT, ORA_TYPE_NUM_BINARY_INTEGER,
            ORA_TYPE_NUM_BLOB, ORA_TYPE_NUM_BOOLEAN, ORA_TYPE_NUM_CHAR, ORA_TYPE_NUM_CLOB,
            ORA_TYPE_NUM_CURSOR, ORA_TYPE_NUM_DATE, ORA_TYPE_NUM_INTERVAL_DS,
            ORA_TYPE_NUM_INTERVAL_YM, ORA_TYPE_NUM_JSON, ORA_TYPE_NUM_LONG, ORA_TYPE_NUM_LONG_RAW,
            ORA_TYPE_NUM_NUMBER, ORA_TYPE_NUM_OBJECT, ORA_TYPE_NUM_RAW, ORA_TYPE_NUM_ROWID,
            ORA_TYPE_NUM_TIMESTAMP, ORA_TYPE_NUM_TIMESTAMP_LTZ, ORA_TYPE_NUM_TIMESTAMP_TZ,
            ORA_TYPE_NUM_UROWID, ORA_TYPE_NUM_VARCHAR, ORA_TYPE_NUM_VECTOR, QueryResult,
            QueryValue, SUBSCR_QOS_QUERY, TNS_SUBSCR_NAMESPACE_DBCHANGE, decode_lob_text,
        },
        vector::{Vector, VectorValues},
    };
    use oraclemcp_error::parse_ora_code;
    use serde_json::{Number, Value, json};
    use std::collections::HashMap;
    use std::fmt::Display;
    use std::future::{Future, poll_fn};
    use std::num::NonZeroU32;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex as SyncMutex};
    use std::time::Duration;

    const FETCH_BATCH_ROWS: u32 = 512;
    pub(super) const BOUNDED_PAGE_FETCH_ROWS: u32 = 1;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct LobReadLimits {
        max_lob_chars: usize,
        max_blob_bytes: usize,
    }

    impl From<&SerializeOptions> for LobReadLimits {
        fn from(opts: &SerializeOptions) -> Self {
            Self {
                max_lob_chars: opts.max_lob_chars,
                max_blob_bytes: opts.max_blob_bytes,
            }
        }
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct LobReadData {
        data: Option<Vec<u8>>,
    }

    /// One separately authenticated EMON connection. The raw notification
    /// record stays entirely inside the driver adapter; callers receive only
    /// the registration id needed for URI-bound core fan-out.
    struct DriverCqnNotificationReceiver {
        registration_id: u64,
        opts: OracleConnectOptions,
        connection: oracledb::Connection,
    }

    #[async_trait::async_trait(?Send)]
    impl CqnNotificationReceiver for DriverCqnNotificationReceiver {
        async fn next_notification(&mut self, cx: &Cx) -> Result<CqnNotificationOutcome, DbError> {
            match self
                .connection
                .recv_notification(
                    cx,
                    TNS_SUBSCR_NAMESPACE_DBCHANGE,
                    SUBSCR_QOS_QUERY,
                    Duration::from_secs(1),
                )
                .await
                .map_err(|err| driver_query_error(err, &self.opts, None))?
            {
                // Deliberately discard every decoded record field: QUERY CQN
                // may contain table names, rowids, or query metadata, none of
                // which may enter the core or client-facing surfaces.
                oracledb::NotificationOutcome::Record(_) => Ok(CqnNotificationOutcome::Event(
                    CqnDriverNotification::for_registration(self.registration_id),
                )),
                oracledb::NotificationOutcome::TimedOut => Ok(CqnNotificationOutcome::TimedOut),
                oracledb::NotificationOutcome::Closed => Ok(CqnNotificationOutcome::Closed),
                // Future driver outcomes must never fabricate an update.
                _ => Ok(CqnNotificationOutcome::Closed),
            }
        }
    }

    pub(super) async fn connect(
        cx: &Cx,
        opts: OracleConnectOptions,
    ) -> Result<RustOracleConnection, DbError> {
        let mut inner = oracledb::Connection::connect(cx, to_connect_options(&opts)?)
            .await
            .map_err(|err| connect_error_to_db_error(&err, &opts))?;
        apply_session_identity(cx, &mut inner, opts.session_identity.as_ref(), &opts).await?;
        for stmt in crate::serialize::canonical_nls_statements() {
            execute_raw(cx, &mut inner, stmt, &[], &opts, "connect").await?;
        }
        for (index, stmt) in opts.session_statements.iter().enumerate() {
            let result = execute_raw(cx, &mut inner, stmt, &[], &opts, "session setup").await;
            redact_session_setup_result(result, index + 1)?;
        }
        let call_timeout = opts.call_timeout;
        Ok(RustOracleConnection {
            opts,
            inner: Arc::new(AsyncMutex::new(super::RustOracleConnectionSlot {
                connection: Some(inner),
                quarantine_reason: None,
            })),
            wire_limits: SyncMutex::new(super::WireLimits {
                call_timeout,
                request_deadline: None,
                request_quota: None,
            }),
            cqn_client_ids: SyncMutex::new(HashMap::new()),
        })
    }

    async fn open_cqn_notification_receiver(
        cx: &Cx,
        adapter: &RustOracleConnection,
        registration: CqnQueryRegistration,
    ) -> Result<Box<dyn CqnNotificationReceiver>, DbError> {
        let client_id = adapter
            .cqn_client_ids
            .lock()
            .map_err(|err| DbError::Internal(format!("CQN registration lock poisoned: {err}")))?
            .get(&registration.registration_id())
            .cloned()
            .ok_or_else(|| {
                DbError::UnsupportedFeature(
                    "CQN registration has no driver-owned callback identity for EMON".to_owned(),
                )
            })?;
        let options = to_connect_options(&adapter.opts)?.with_server_type_emon(true);
        let mut connection = oracledb::Connection::connect(cx, options)
            .await
            .map_err(|err| connect_error_to_db_error(&err, &adapter.opts))?;
        connection
            .notify_register(cx, &client_id)
            .await
            .map_err(|err| driver_query_error(err, &adapter.opts, None))?;
        Ok(Box::new(DriverCqnNotificationReceiver {
            registration_id: registration.registration_id(),
            opts: adapter.opts.clone(),
            connection,
        }))
    }

    fn format_transport_connect_timeout(timeout: Duration) -> String {
        if timeout.subsec_millis() == 0 {
            timeout.as_secs().max(1).to_string()
        } else {
            format!("{}ms", timeout.as_millis().max(1))
        }
    }

    fn connect_string_with_transport_timeout(
        connect_string: &str,
        timeout: Option<Duration>,
    ) -> Result<String, DbError> {
        let Some(timeout) = timeout.filter(|timeout| !timeout.is_zero()) else {
            return Ok(connect_string.to_owned());
        };
        if connect_string.trim_start().starts_with('(') {
            return Err(DbError::UnsupportedAuth(
                "connect_timeout_seconds cannot be injected into a full Oracle Net descriptor; \
                 set TRANSPORT_CONNECT_TIMEOUT inside the descriptor instead"
                    .to_owned(),
            ));
        }
        let lower = connect_string.to_ascii_lowercase();
        if lower.contains("transport_connect_timeout=") || lower.contains("tcp_connect_timeout=") {
            return Err(DbError::UnsupportedAuth(
                "connect_timeout_seconds conflicts with an existing transport_connect_timeout \
                 value in connect_string; configure it in only one place"
                    .to_owned(),
            ));
        }
        let separator = if connect_string.contains('?') {
            '&'
        } else {
            '?'
        };
        Ok(format!(
            "{}{}transport_connect_timeout={}",
            connect_string,
            separator,
            format_transport_connect_timeout(timeout)
        ))
    }

    /// Inject Oracle's `EXPIRE_TIME` dead-connection-detection probe interval
    /// (MINUTES) into an EZConnect-style connect string as `expire_time=N`. The
    /// thin driver has no `ConnectOptions` setter for EXPIRE_TIME, so — exactly
    /// like `connect_string_with_transport_timeout` — we splice it into the
    /// connect-string query. Refuses a full Oracle-Net descriptor (set
    /// `EXPIRE_TIME` inside it instead) and refuses to shadow an `expire_time`
    /// already present in the string.
    fn connect_string_with_expire_time(
        connect_string: &str,
        keepalive_minutes: Option<u64>,
    ) -> Result<String, DbError> {
        let Some(minutes) = keepalive_minutes.filter(|&minutes| minutes > 0) else {
            return Ok(connect_string.to_owned());
        };
        if connect_string.trim_start().starts_with('(') {
            return Err(DbError::UnsupportedAuth(
                "keepalive_minutes cannot be injected into a full Oracle Net descriptor; \
                 set EXPIRE_TIME inside the descriptor instead"
                    .to_owned(),
            ));
        }
        let lower = connect_string.to_ascii_lowercase();
        if lower.contains("expire_time=") {
            return Err(DbError::UnsupportedAuth(
                "keepalive_minutes conflicts with an existing expire_time value in \
                 connect_string; configure it in only one place"
                    .to_owned(),
            ));
        }
        let separator = if connect_string.contains('?') {
            '&'
        } else {
            '?'
        };
        Ok(format!("{connect_string}{separator}expire_time={minutes}"))
    }

    pub(super) fn to_connect_options(
        opts: &OracleConnectOptions,
    ) -> Result<oracledb::ConnectOptions, DbError> {
        opts.auth_adapter
            .validate()
            .map_err(|err| DbError::UnsupportedAuth(err.to_string()))?;
        // Enterprise auth modes the published thin driver cannot satisfy. These
        // are DRIVER-UNSUPPORTED, distinct from a bad credential, a TLS/wallet
        // failure, or a listener error — the doctor classifies them apart.
        match &opts.auth_adapter {
            AuthAdapter::Kerberos { .. } => {
                return Err(DbError::UnsupportedAuth(
                    "Kerberos authentication is not supported by the published thin driver yet"
                        .to_owned(),
                ));
            }
            AuthAdapter::Radius => {
                return Err(DbError::UnsupportedAuth(
                    "RADIUS/native MFA authentication is not supported by the published thin driver yet"
                        .to_owned(),
                ));
            }
            AuthAdapter::External => {
                return Err(DbError::UnsupportedAuth(
                    "external/wallet auth without username and password is not supported by the published thin driver yet"
                        .to_owned(),
                ));
            }
            AuthAdapter::Password | AuthAdapter::Proxy { .. } => {}
        }
        if opts.external_auth {
            return Err(DbError::UnsupportedAuth(
                "external/wallet auth without username and password is not supported by the published thin driver yet"
                    .to_owned(),
            ));
        }
        // Resolve a bare tnsnames.ora alias to its full descriptor up front
        // (B2.3): the driver treats an unresolved alias as "resolve separately",
        // so a bare alias would otherwise fail late. Doing it here also lets the
        // TCPS transport check below see the resolved (possibly `PROTOCOL=TCPS`)
        // descriptor.
        let selected_target = super::resolve_selected_connect_target(opts)?;
        // OCI IAM database-token auth. The pinned driver DOES support it via
        // `ConnectOptions::with_access_token` (the token is sent as `AUTH_TOKEN`
        // with no password verifier). It is only wireable once a token has been
        // fetched from OCI IAM; `use_iam_token` without a token means the
        // token-source seam (oraclemcp_db::IamTokenSource / ensure_fresh_token)
        // has not run yet — a setup error, not a driver-unsupported one.
        let iam_token = match (opts.use_iam_token, opts.iam_token.as_deref()) {
            (_, Some(token)) => Some(token),
            (true, None) => {
                return Err(DbError::UnsupportedAuth(
                    "OCI IAM database-token auth is configured (use_iam_token) but no token was \
                     fetched; obtain one via the IAM token source before connecting"
                        .to_owned(),
                ));
            }
            (false, None) => None,
        };
        // A database access token must never travel in clear text. Fail closed
        // on a non-TCPS transport BEFORE we hand the token to the driver (the
        // driver also rejects this, but defense-in-depth keeps the token off a
        // plaintext socket and gives a precise typed error).
        if iam_token.is_some() && !selected_target.uses_tcps {
            return Err(DbError::UnsupportedAuth(
                "OCI IAM database-token auth requires a TLS (TCPS) transport; use a tcps:// \
                 connect string or a descriptor whose selected address uses PROTOCOL=TCPS"
                    .to_owned(),
            ));
        }
        let user = opts.username.as_deref().ok_or_else(|| {
            DbError::UnsupportedAuth("thin mode currently requires an explicit username".to_owned())
        })?;
        // Token auth carries the credential in the token itself, so no password
        // is required (or used) when an IAM token is present.
        let password = match iam_token {
            Some(_) => "",
            None => opts.password.as_deref().ok_or_else(|| {
                DbError::UnsupportedAuth(
                    "thin mode currently requires an explicit password".to_owned(),
                )
            })?,
        };
        let identity = client_identity(opts.session_identity.as_ref())?;
        // Both the Oracle Net transport-connect timeout and the EXPIRE_TIME
        // dead-connection-detection interval are connect-string knobs (the thin
        // driver has no ConnectOptions setter for either), so chain both
        // injections onto the resolved string before building the options.
        let connect_string = connect_string_with_transport_timeout(
            &selected_target.connect_string,
            opts.connect_timeout,
        )?;
        let connect_string =
            connect_string_with_expire_time(&connect_string, opts.keepalive_minutes)?;
        let mut connect_options =
            oracledb::ConnectOptions::new(&connect_string, user, password, identity);
        if let Some(token) = iam_token {
            // OCI IAM *database* tokens are proof-of-possession: when the profile
            // resolved the bound private key, wire it through so the driver signs
            // the auth header (`AUTH_HEADER`/`AUTH_SIGNATURE`). Without the key the
            // database refuses the bearer token with ORA-01017; a plain OAuth2
            // bearer token has no key and uses the token-only path.
            connect_options = match opts.iam_token_private_key.as_deref() {
                Some(private_key) => connect_options
                    .with_access_token_and_key(token.to_owned(), private_key.to_owned()),
                None => connect_options.with_access_token(token.to_owned()),
            };
        }
        // session_identity.edition must be sent during authentication so no user
        // SQL runs under the default edition before the requested edition applies.
        if let Some(edition) = opts
            .session_identity
            .as_ref()
            .and_then(|identity| identity.edition.as_deref())
        {
            connect_options = connect_options.with_edition(edition.to_owned());
        }
        if !opts.app_context.is_empty() {
            connect_options = connect_options.with_app_context(opts.app_context.clone());
        }
        if let Some(sdu) = opts.sdu {
            connect_options = connect_options.with_sdu(sdu);
        }
        if let Some(statement_cache_size) = opts.statement_cache_size {
            connect_options =
                connect_options.with_statement_cache_size(statement_cache_size as usize);
        }
        // Per-read inactivity deadline on an established session. Unlike the
        // connect-string timeouts above, the thin driver exposes a builder
        // setter (a consuming `-> Self`), so chain it like the other options.
        if let Some(inactivity_timeout) = opts.inactivity_timeout {
            connect_options = connect_options.with_inactivity_timeout(inactivity_timeout);
        }
        if let Some(proxy_user) = opts.auth_adapter.proxy_connect_user() {
            connect_options = connect_options.with_proxy_user(Some(proxy_user));
        }
        if let Some(wallet) = &opts.wallet_location {
            connect_options = connect_options.with_wallet_location(wallet.display().to_string());
        }
        if let Some(wallet_password) = &opts.wallet_password {
            connect_options = connect_options.with_wallet_password(wallet_password.clone());
        }
        if let Some(enabled) = opts.ssl_server_dn_match {
            connect_options = connect_options.with_ssl_server_dn_match(enabled);
        }
        if let Some(dn) = &opts.ssl_server_cert_dn {
            connect_options = connect_options.with_ssl_server_cert_dn(dn.clone());
        }
        if let Some(use_sni) = opts.use_sni {
            connect_options = connect_options.with_use_sni(use_sni);
        } else if opts.wallet_location.is_some() {
            connect_options = connect_options.with_use_sni(true);
        }
        Ok(connect_options)
    }

    fn client_identity(
        identity: Option<&OracleSessionIdentity>,
    ) -> Result<ClientIdentity, DbError> {
        let program = identity
            .and_then(|value| value.program.as_deref())
            .or_else(|| identity.and_then(|value| value.module.as_deref()))
            .unwrap_or("oraclemcp");
        let terminal = identity
            .and_then(|value| value.terminal.as_deref())
            .or_else(|| identity.and_then(|value| value.client_identifier.as_deref()))
            .unwrap_or("oraclemcp");
        let driver_name = identity
            .and_then(|value| value.driver_name.as_deref())
            .unwrap_or("oraclemcp-thin");
        let machine = identity
            .and_then(|value| value.machine.clone())
            .unwrap_or_else(|| {
                std::env::var("HOSTNAME").unwrap_or_else(|_| "oraclemcp".to_owned())
            });
        let osuser = identity
            .and_then(|value| value.os_user.clone())
            .unwrap_or_else(|| std::env::var("USER").unwrap_or_else(|_| "oraclemcp".to_owned()));
        ClientIdentity::new(program, machine, osuser, terminal, driver_name)
            .map_err(|err| DbError::Connect(err.to_string()))
    }

    async fn apply_session_identity(
        cx: &Cx,
        inner: &mut oracledb::Connection,
        identity: Option<&OracleSessionIdentity>,
        opts: &OracleConnectOptions,
    ) -> Result<(), DbError> {
        let Some(identity) = identity.filter(|identity| !identity.is_empty()) else {
            return Ok(());
        };
        if let Some(module) = identity.module.as_deref() {
            let action = identity.action.as_deref().unwrap_or("");
            execute_raw(
                cx,
                inner,
                "BEGIN DBMS_APPLICATION_INFO.SET_MODULE(:1, :2); END;",
                &[
                    BindValue::Text(module.to_owned()),
                    BindValue::Text(action.to_owned()),
                ],
                opts,
                "session identity",
            )
            .await?;
        } else if let Some(action) = identity.action.as_deref() {
            execute_raw(
                cx,
                inner,
                "BEGIN DBMS_APPLICATION_INFO.SET_ACTION(:1); END;",
                &[BindValue::Text(action.to_owned())],
                opts,
                "session identity",
            )
            .await?;
        }
        if let Some(client_identifier) = identity.client_identifier.as_deref() {
            execute_raw(
                cx,
                inner,
                "BEGIN DBMS_SESSION.SET_IDENTIFIER(:1); END;",
                &[BindValue::Text(client_identifier.to_owned())],
                opts,
                "session identity",
            )
            .await?;
        }
        if let Some(client_info) = identity.client_info.as_deref() {
            execute_raw(
                cx,
                inner,
                "BEGIN DBMS_APPLICATION_INFO.SET_CLIENT_INFO(:1); END;",
                &[BindValue::Text(client_info.to_owned())],
                opts,
                "session identity",
            )
            .await?;
        }
        Ok(())
    }

    fn to_bind(bind: &OracleBind) -> BindValue {
        oracle_bind_to_driver(bind)
    }

    async fn execute_raw(
        cx: &Cx,
        inner: &mut oracledb::Connection,
        sql: &str,
        binds: &[BindValue],
        opts: &OracleConnectOptions,
        context: &'static str,
    ) -> Result<QueryResult, DbError> {
        // oracledb 0.5.x removed the 0.2.2 `execute_query_with_binds` family;
        // `Connection::execute_raw` is the retained low-level entry that returns the
        // same `QueryResult` and composes with the fetch primitives below. `bind_rows`
        // is positional array DML — one inner row applies our binds in a single round
        // trip, and an empty slice runs `sql` once with no binds.
        let bind_rows: Vec<Vec<BindValue>> = if binds.is_empty() {
            Vec::new()
        } else {
            vec![binds.to_vec()]
        };
        let timeout_ms = super::WireLimits {
            call_timeout: opts.call_timeout,
            request_deadline: None,
            request_quota: None,
        }
        .effective_timeout_ms(cx, context)?;
        inner
            .execute_raw(
                cx,
                sql,
                0,
                &bind_rows,
                ExecuteOptions::default(),
                timeout_ms,
            )
            .await
            .map_err(|err| driver_execute_error(err, opts, context))
    }

    /// Convert a trusted, profile-owned session statement failure into the
    /// only detail that may cross the connection boundary: its 1-based ordinal
    /// and Oracle error code. The statement text and the driver's server detail
    /// are deliberately discarded wholesale. Exact-value scrubbing is not
    /// sufficient here because trusted PL/SQL can synthesize a message that
    /// contains a literal, application-context value, or derived secret.
    pub(super) fn redact_session_setup_result<T>(
        result: Result<T, DbError>,
        statement_ordinal: usize,
    ) -> Result<T, DbError> {
        match result {
            Ok(value) => Ok(value),
            Err(DbError::Execute(message)) => {
                let detail = match parse_ora_code(&message) {
                    Some(code) => format!(
                        "session setup statement {statement_ordinal} failed (ORA-{code:05}); server detail suppressed"
                    ),
                    None => format!(
                        "session setup statement {statement_ordinal} failed; server detail suppressed"
                    ),
                };
                Err(DbError::Execute(detail))
            }
            // Deadline/quota cancellation occurs before the driver sees SQL,
            // so it contains no server-echoed statement detail and must retain
            // its structural cancellation class for fail-fast propagation.
            Err(error) => Err(error),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_with_timeout(
        cx: &Cx,
        inner: &mut oracledb::Connection,
        sql: &str,
        prefetch_rows: u32,
        binds: &[BindValue],
        limits: super::WireLimits,
        opts: &OracleConnectOptions,
        context: &'static str,
    ) -> Result<QueryResult, DbError> {
        let bind_rows: Vec<Vec<BindValue>> = if binds.is_empty() {
            Vec::new()
        } else {
            vec![binds.to_vec()]
        };
        let timeout_ms = limits.effective_timeout_ms(cx, context)?;
        inner
            .execute_raw(
                cx,
                sql,
                prefetch_rows,
                &bind_rows,
                ExecuteOptions::default(),
                timeout_ms,
            )
            .await
            .map_err(|err| driver_query_error(err, opts, Some(context)))
    }

    pub(super) fn prefetch_rows_for_statement(sql: &str) -> u32 {
        if sql
            .trim_start()
            .split(|ch: char| !ch.is_ascii_alphabetic())
            .next()
            .is_some_and(|keyword| keyword.eq_ignore_ascii_case("select"))
        {
            FETCH_BATCH_ROWS
        } else {
            0
        }
    }

    fn output_value(result: &QueryResult, bind_index: usize) -> Option<&QueryValue> {
        result
            .out_values
            .iter()
            .find_map(|(index, value)| (*index == bind_index).then_some(value.as_ref()).flatten())
    }

    fn output_value_entry(result: &QueryResult, bind_index: usize) -> Option<Option<&QueryValue>> {
        result
            .out_values
            .iter()
            .find_map(|(index, value)| (*index == bind_index).then_some(value.as_ref()))
    }

    pub(super) fn ordered_routine_out_values(
        result: &QueryResult,
        args: &[OracleRoutineArg],
    ) -> Result<Vec<Option<QueryValue>>, DbError> {
        args.iter()
            .enumerate()
            .filter_map(|(index, arg)| arg.is_output_bind().then_some(index))
            .map(|index| {
                output_value_entry(result, index)
                    .map(|value| value.cloned())
                    .ok_or_else(|| {
                        DbError::Execute(format!(
                            "routine OUT bind at position {} was not returned by the driver",
                            index + 1
                        ))
                    })
            })
            .collect()
    }

    fn routine_arg_metadata(index: usize, arg: &OracleRoutineArg) -> ColumnMetadata {
        let name = format!("OUT_{}", index + 1);
        match &arg.bind {
            BindValue::Output {
                ora_type_num,
                csfrm,
                buffer_size,
            }
            | BindValue::ReturnOutput {
                ora_type_num,
                csfrm,
                buffer_size,
            } => ColumnMetadata::new(name, *ora_type_num)
                .with_csfrm(*csfrm)
                .with_buffer_size(*buffer_size)
                .with_max_size(*buffer_size),
            BindValue::ObjectOutput {
                schema,
                type_name,
                buffer_size,
                ..
            } => ColumnMetadata::new(name, ORA_TYPE_NUM_OBJECT)
                .with_csfrm(CS_FORM_IMPLICIT)
                .with_buffer_size(*buffer_size)
                .with_max_size(*buffer_size)
                .with_object_schema(Some(schema.clone()))
                .with_object_type_name(Some(type_name.clone())),
            other => unreachable!(
                "OracleRoutineArg must wrap only output bind variants, got {}",
                other.variant_name()
            ),
        }
    }

    async fn routine_out_binds(
        cx: &Cx,
        inner: &mut oracledb::Connection,
        result: &QueryResult,
        args: &[OracleRoutineArg],
        opts: &OracleConnectOptions,
        serialize_opts: &SerializeOptions,
        limits: super::WireLimits,
    ) -> Result<Vec<OracleCell>, DbError> {
        let output_args: Vec<(usize, &OracleRoutineArg)> = args
            .iter()
            .enumerate()
            .filter(|(_, arg)| arg.is_output_bind())
            .collect();
        let ordered = ordered_routine_out_values(result, args)?;
        let mut out = Vec::with_capacity(output_args.len());
        for ((index, arg), value) in output_args.into_iter().zip(ordered) {
            let metadata = routine_arg_metadata(index, arg);
            out.push(
                value_to_cell(
                    cx,
                    inner,
                    &metadata,
                    value,
                    opts,
                    serialize_opts,
                    limits.clone(),
                    0,
                )
                .await?,
            );
        }
        Ok(out)
    }

    fn order_named_binds_for_driver(
        sql: &str,
        named: Vec<(String, BindValue)>,
    ) -> Result<Vec<BindValue>, DbError> {
        let order = placeholder_order(sql);
        let mut remaining = named;
        let mut out = Vec::with_capacity(remaining.len());
        let mut missing = Vec::new();
        for placeholder in &order {
            if let Some(pos) = remaining
                .iter()
                .position(|(name, _)| name_matches(name, placeholder))
            {
                let (_, value) = remaining.remove(pos);
                out.push(value);
            } else {
                missing.push(placeholder.clone());
            }
        }
        if !missing.is_empty() || !remaining.is_empty() {
            return Err(DbError::NamedBindMismatch {
                missing,
                unexpected: remaining.into_iter().map(|(name, _)| name).collect(),
            });
        }
        Ok(out)
    }

    fn name_matches(supplied: &str, scanned: &str) -> bool {
        supplied
            .trim_start_matches(':')
            .eq_ignore_ascii_case(scanned.trim_start_matches(':'))
    }

    fn placeholder_order(sql: &str) -> Vec<String> {
        let bytes = sql.as_bytes();
        let mut seen: Vec<String> = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'\'' => {
                    i += 1;
                    while i < bytes.len() {
                        if bytes[i] == b'\'' {
                            if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                                i += 2;
                                continue;
                            }
                            i += 1;
                            break;
                        }
                        i += 1;
                    }
                }
                b'"' => {
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'"' {
                        i += 1;
                    }
                    i = i.saturating_add(1);
                }
                b'-' if i + 1 < bytes.len() && bytes[i + 1] == b'-' => {
                    while i < bytes.len() && bytes[i] != b'\n' {
                        i += 1;
                    }
                }
                b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                    i += 2;
                    while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                        i += 1;
                    }
                    i = i.saturating_add(2).min(bytes.len());
                }
                b':' => {
                    let start = i + 1;
                    let mut j = start;
                    while j < bytes.len()
                        && (bytes[j].is_ascii_alphanumeric()
                            || bytes[j] == b'_'
                            || bytes[j] == b'$')
                    {
                        j += 1;
                    }
                    if j > start {
                        let name = sql[start..j].to_owned();
                        if !seen.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
                            seen.push(name);
                        }
                    }
                    i = j;
                }
                _ => i += 1,
            }
        }
        seen
    }

    async fn collect_all_rows(
        cx: &Cx,
        inner: &mut oracledb::Connection,
        mut result: QueryResult,
        opts: &OracleConnectOptions,
        serialize_opts: &SerializeOptions,
        limits: super::WireLimits,
    ) -> Result<Vec<OracleRow>, DbError> {
        let cursor_id = result.cursor_id;
        let implicit_resultsets = result.implicit_resultsets.take();
        let mut columns = result.columns.clone();
        let mut rows = std::mem::take(&mut result.rows);
        let mut previous_row = rows.last().cloned();
        let has_parent_result = !columns.is_empty();
        if has_parent_result
            && rows.is_empty()
            && cursor_id != 0
            && columns_require_define(&columns)
        {
            let timeout_ms =
                match limits.effective_timeout_ms(cx, "oracle_db.query_rows.define_fetch") {
                    Ok(timeout_ms) => timeout_ms,
                    Err(err) => {
                        inner.release_cursor(cursor_id);
                        return Err(err);
                    }
                };
            let fetch_result = bounded_fetch_batch(
                timeout_ms,
                inner.define_and_fetch_rows_with_columns(
                    cx,
                    cursor_id,
                    FETCH_BATCH_ROWS,
                    &columns,
                    None,
                ),
            )
            .await;
            let fetched = match resolve_fetch_batch(cx, inner, fetch_result, opts).await {
                Ok(fetched) => fetched,
                Err(err) => {
                    inner.release_cursor(cursor_id);
                    return Err(err);
                }
            };
            if !fetched.columns.is_empty() {
                columns = fetched.columns.clone();
            }
            previous_row = fetched.rows.last().cloned();
            rows.extend(fetched.rows);
            result.more_rows = fetched.more_rows;
        }
        while has_parent_result && result.more_rows && cursor_id != 0 {
            let timeout_ms = match limits.effective_timeout_ms(cx, "oracle_db.query_rows.fetch") {
                Ok(timeout_ms) => timeout_ms,
                Err(err) => {
                    inner.release_cursor(cursor_id);
                    return Err(err);
                }
            };
            let fetch_result = if columns_require_define(&columns) {
                bounded_fetch_batch(
                    timeout_ms,
                    inner.define_and_fetch_rows_with_columns(
                        cx,
                        cursor_id,
                        FETCH_BATCH_ROWS,
                        &columns,
                        previous_row.as_deref(),
                    ),
                )
                .await
            } else {
                bounded_fetch_batch(
                    timeout_ms,
                    inner.fetch_rows_with_columns(
                        cx,
                        cursor_id,
                        FETCH_BATCH_ROWS,
                        &columns,
                        previous_row.as_deref(),
                    ),
                )
                .await
            };
            let fetched = match resolve_fetch_batch(cx, inner, fetch_result, opts).await {
                Ok(fetched) => fetched,
                Err(err) => {
                    inner.release_cursor(cursor_id);
                    return Err(err);
                }
            };
            if !fetched.columns.is_empty() {
                columns = fetched.columns.clone();
            }
            previous_row = fetched.rows.last().cloned();
            rows.extend(fetched.rows);
            result.more_rows = fetched.more_rows;
        }
        let mut converted = rows_to_oracle_rows(
            cx,
            inner,
            &columns,
            rows,
            opts,
            serialize_opts,
            limits.clone(),
            0,
        )
        .await?;
        if let Some(implicit_resultsets) = implicit_resultsets
            && let Some(row) = implicit_resultsets_to_row(
                cx,
                inner,
                implicit_resultsets,
                opts,
                serialize_opts,
                limits,
            )
            .await?
        {
            converted.push(row);
        }
        if cursor_id != 0 {
            inner.release_cursor(cursor_id);
        }
        Ok(converted)
    }

    #[allow(clippy::too_many_arguments)]
    async fn collect_bounded_query_page(
        cx: &Cx,
        inner: &mut oracledb::Connection,
        mut result: QueryResult,
        opts: &OracleConnectOptions,
        serialize_opts: &SerializeOptions,
        limits: super::WireLimits,
        caps: QueryCaps,
        offset: usize,
    ) -> Result<QueryResponse, DbError> {
        use std::collections::VecDeque;

        let cursor_id = result.cursor_id;
        let collected = async {
            if result.implicit_resultsets.is_some() {
                return Err(DbError::UnsupportedFeature(
                    "bounded SELECT paging does not admit implicit result sets".to_owned(),
                ));
            }
            let mut columns = result.columns.clone();
            let mut rows: VecDeque<_> = std::mem::take(&mut result.rows).into();
            let mut previous_row = rows.back().cloned();
            let has_parent_result = !columns.is_empty();
            let column_names = columns
                .iter()
                .map(|column| column.name().to_owned())
                .collect();
            let mut builder = QueryPageBuilder::new(caps, offset, column_names);

            if has_parent_result
                && rows.is_empty()
                && cursor_id != 0
                && columns_require_define(&columns)
            {
                let timeout_ms =
                    limits.effective_timeout_ms(cx, "oracle_db.query_bounded_page.define_fetch")?;
                let fetch = bounded_fetch_batch(
                    timeout_ms,
                    inner.define_and_fetch_rows_with_columns(
                        cx,
                        cursor_id,
                        BOUNDED_PAGE_FETCH_ROWS,
                        &columns,
                        None,
                    ),
                )
                .await;
                let fetched = resolve_fetch_batch(cx, inner, fetch, opts).await?;
                if !fetched.columns.is_empty() {
                    columns = fetched.columns.clone();
                }
                previous_row = fetched.rows.last().cloned();
                rows.extend(fetched.rows);
                result.more_rows = fetched.more_rows;
            }

            loop {
                while let Some(row) = rows.pop_front() {
                    previous_row = Some(row);
                    let row_serialize_opts =
                        bounded_cell_options(serialize_opts, caps.max_result_bytes);
                    let row = row_to_oracle_row(
                        cx,
                        inner,
                        &columns,
                        previous_row
                            .as_deref()
                            .expect("current row is retained as the duplicate-column seed"),
                        opts,
                        &row_serialize_opts,
                        limits.clone(),
                        0,
                    )
                    .await?;
                    if builder.push_with_options(cx, &row, &row_serialize_opts)?
                        == QueryPagePush::ByteLimit
                    {
                        return builder.finish(cx, true);
                    }
                    if builder.row_count() >= caps.max_rows {
                        return builder.finish(cx, !rows.is_empty() || result.more_rows);
                    }
                }

                if !has_parent_result || !result.more_rows || cursor_id == 0 {
                    return builder.finish(cx, false);
                }
                let timeout_ms =
                    limits.effective_timeout_ms(cx, "oracle_db.query_bounded_page.fetch")?;
                let fetch = if columns_require_define(&columns) {
                    bounded_fetch_batch(
                        timeout_ms,
                        inner.define_and_fetch_rows_with_columns(
                            cx,
                            cursor_id,
                            BOUNDED_PAGE_FETCH_ROWS,
                            &columns,
                            previous_row.as_deref(),
                        ),
                    )
                    .await
                } else {
                    bounded_fetch_batch(
                        timeout_ms,
                        inner.fetch_rows_with_columns(
                            cx,
                            cursor_id,
                            BOUNDED_PAGE_FETCH_ROWS,
                            &columns,
                            previous_row.as_deref(),
                        ),
                    )
                    .await
                };
                let fetched = resolve_fetch_batch(cx, inner, fetch, opts).await?;
                if !fetched.columns.is_empty() {
                    columns = fetched.columns.clone();
                }
                previous_row = fetched.rows.last().cloned();
                rows.extend(fetched.rows);
                result.more_rows = fetched.more_rows;
            }
        }
        .await;
        if cursor_id != 0 {
            inner.release_cursor(cursor_id);
        }
        collected
    }

    pub(super) fn bounded_cell_options(
        base: &SerializeOptions,
        page_bytes: usize,
    ) -> SerializeOptions {
        let max_text_chars = Some(
            base.max_text_chars
                .map_or(page_bytes, |cap| cap.min(page_bytes)),
        );
        let max_blob_bytes = base.max_blob_bytes.min(page_bytes.saturating_mul(3) / 4);
        SerializeOptions {
            numbers_as_float: base.numbers_as_float,
            max_text_chars,
            max_lob_chars: base.max_lob_chars.min(page_bytes),
            max_blob_bytes,
            max_nested_cursor_rows: base.max_nested_cursor_rows,
            max_nested_cursor_cells: base.max_nested_cursor_cells,
            max_nested_cursor_bytes: base.max_nested_cursor_bytes.min(page_bytes),
            max_nested_cursor_depth: base.max_nested_cursor_depth,
            structured_decode_caps: StructuredDecodeCaps::new(
                base.structured_decode_caps.max_rows,
                base.structured_decode_caps.max_cells,
                base.structured_decode_caps.max_bytes.min(page_bytes),
                base.structured_decode_caps.max_depth,
            ),
            result_masking: base.result_masking.clone(),
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum FetchBatchError<E> {
        Driver(E),
        Timeout(u32),
    }

    pub(super) async fn bounded_fetch_batch<T, E, Fut>(
        timeout_ms: Option<u32>,
        future: Fut,
    ) -> Result<T, FetchBatchError<E>>
    where
        Fut: Future<Output = Result<T, E>>,
    {
        let Some(timeout_ms) = timeout_ms.filter(|value| *value > 0) else {
            return future.await.map_err(FetchBatchError::Driver);
        };
        match asupersync::time::timeout(
            asupersync::time::wall_now(),
            Duration::from_millis(u64::from(timeout_ms)),
            future,
        )
        .await
        {
            Ok(result) => result.map_err(FetchBatchError::Driver),
            Err(_) => Err(FetchBatchError::Timeout(timeout_ms)),
        }
    }

    async fn bounded_recovery_cancel(
        cx: &Cx,
        inner: &mut oracledb::Connection,
        opts: &OracleConnectOptions,
        context: &'static str,
    ) -> Result<(), String> {
        let timeout_ms = super::duration_to_millis(super::CLEANUP_TIMEOUT);
        let result = try_commit_section(cx, super::CLEANUP_MASKED_POLLS, async {
            bounded_fetch_batch(Some(timeout_ms), inner.cancel(cx)).await
        })
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(FetchBatchError::Driver(error)) => Err(format!(
                "{context} recovery failed: {}",
                sanitize_driver_error(error, opts)
            )),
            Err(FetchBatchError::Timeout(_)) => Err(format!(
                "{context} recovery exceeded its independent {timeout_ms} ms cleanup deadline"
            )),
        }
    }

    async fn resolve_fetch_batch<T>(
        cx: &Cx,
        inner: &mut oracledb::Connection,
        result: Result<T, FetchBatchError<oracledb::Error>>,
        opts: &OracleConnectOptions,
    ) -> Result<T, DbError> {
        match result {
            Ok(value) => Ok(value),
            Err(FetchBatchError::Driver(err)) => Err(driver_query_error(err, opts, None)),
            Err(FetchBatchError::Timeout(timeout_ms)) => {
                match bounded_recovery_cancel(cx, inner, opts, "fetch loop").await {
                    Ok(()) => Err(fetch_batch_call_timeout(timeout_ms)),
                    // Recovery cancel failed: the session is definitively dirty. Use
                    // the structurally-uncertain `Cancelled` variant so quarantine
                    // never rides on message-text matching.
                    Err(error) => Err(DbError::Cancelled(format!(
                        "fetch loop: call timeout of {timeout_ms} ms exceeded; {error}"
                    ))),
                }
            }
        }
    }

    async fn resolve_execute_round_trip<T>(
        cx: &Cx,
        inner: &mut oracledb::Connection,
        result: Result<T, FetchBatchError<oracledb::Error>>,
        opts: &OracleConnectOptions,
        context: &'static str,
    ) -> Result<T, DbError> {
        match result {
            Ok(value) => Ok(value),
            Err(FetchBatchError::Driver(err)) => Err(driver_execute_error(err, opts, context)),
            Err(FetchBatchError::Timeout(timeout_ms)) => {
                match bounded_recovery_cancel(cx, inner, opts, context).await {
                    Ok(()) => Err(DbError::Cancelled(format!(
                        "{context}: call timeout of {timeout_ms} ms exceeded"
                    ))),
                    Err(error) => Err(DbError::Cancelled(format!(
                        "{context}: call timeout of {timeout_ms} ms exceeded; {error}"
                    ))),
                }
            }
        }
    }

    /// A per-batch call timeout in the fetch loop. After the timeout we issue an
    /// out-of-band `cancel` to the driver, which leaves the session in an
    /// **uncertain** state (a cursor may be partially drained). Return the
    /// structural [`DbError::Cancelled`] variant — `is_uncertain_session_state`
    /// then flags it fail-closed from the error *kind*, never from the message
    /// wording, so editing this literal can never silently un-quarantine a
    /// mid-timeout session.
    pub(super) fn fetch_batch_call_timeout(timeout_ms: u32) -> DbError {
        DbError::Cancelled(format!(
            "fetch loop: call timeout of {timeout_ms} ms exceeded"
        ))
    }

    fn columns_require_define(columns: &[ColumnMetadata]) -> bool {
        columns.iter().any(|column| {
            matches!(
                column.ora_type_num(),
                ORA_TYPE_NUM_CLOB | ORA_TYPE_NUM_BLOB | ORA_TYPE_NUM_VECTOR | ORA_TYPE_NUM_JSON
            )
        })
    }

    fn row_stream_chunked_fallback_reason(columns: &[ColumnMetadata]) -> Option<String> {
        let column = columns.iter().find(|column| {
            matches!(
                column.ora_type_num(),
                ORA_TYPE_NUM_CURSOR | ORA_TYPE_NUM_CLOB | ORA_TYPE_NUM_BLOB | ORA_TYPE_NUM_BFILE
            )
        })?;
        Some(format!(
            "column {} has Oracle type {}; cursor-chunked streaming preserves connection-owned materialization",
            column.name(),
            oracle_type_name(column)
        ))
    }

    async fn replace_connection_slot(
        inner: &Arc<AsyncMutex<super::RustOracleConnectionSlot>>,
        cx: &Cx,
        connection: oracledb::Connection,
    ) -> Result<(), DbError> {
        let mut guard = inner
            .lock(cx)
            .await
            .map_err(|err| DbError::Internal(format!("thin connection lock failed: {err}")))?;
        if let Some(reason) = guard.quarantine_reason.as_deref() {
            return Err(DbError::Quarantined {
                outcome: crate::error::QuarantineOutcome::UnknownDiscarded,
                message: reason.to_owned(),
            });
        }
        if guard.connection.is_some() {
            let reason =
                "thin connection slot was unexpectedly occupied during row-stream recovery"
                    .to_owned();
            guard.quarantine_reason = Some(reason.clone());
            drop(guard.connection.take());
            return Err(DbError::Quarantined {
                outcome: crate::error::QuarantineOutcome::UnknownDiscarded,
                message: reason,
            });
        }
        guard.connection = Some(connection);
        Ok(())
    }

    pub(super) struct RustOracleRowStream {
        inner: Arc<AsyncMutex<super::RustOracleConnectionSlot>>,
        opts: OracleConnectOptions,
        stream: Option<oracledb::OwnedRowStream>,
        metadata: Vec<ColumnMetadata>,
        columns: Vec<String>,
        serialize_opts: SerializeOptions,
        limits: super::WireLimits,
    }

    /// One leading sign, absolute components — the canonical Oracle text form for
    /// an INTERVAL DAY TO SECOND value (bead F-LOW DB4).
    ///
    /// Every component the driver hands us is `i32`, and a negative interval
    /// arrives with its components individually signed. Interpolating them
    /// directly produced embedded minus signs — `-1 -2:00:00.000000000`, and
    /// `{fseconds:09}` on a negative value renders `-00000001` — which no Oracle
    /// client can read back.
    ///
    /// An Oracle interval is wholly negative or wholly positive, so mixed signs
    /// are not a formatting question, they are an invalid value. `None` says
    /// exactly that and callers surface a typed marker instead of inventing text.
    pub(crate) fn interval_ds_parts(
        days: i32,
        hours: i32,
        minutes: i32,
        seconds: i32,
        fseconds: i32,
    ) -> Option<(&'static str, u32, u32, u32, u32, u32)> {
        let components = [days, hours, minutes, seconds, fseconds];
        let negative = components.iter().any(|component| *component < 0);
        let positive = components.iter().any(|component| *component > 0);
        if negative && positive {
            return None;
        }
        Some((
            if negative { "-" } else { "" },
            days.unsigned_abs(),
            hours.unsigned_abs(),
            minutes.unsigned_abs(),
            seconds.unsigned_abs(),
            fseconds.unsigned_abs(),
        ))
    }

    /// `[-]D HH:MM:SS.FFFFFFFFF`. A positive or zero interval renders exactly as
    /// it always did, so existing output is unchanged.
    pub(crate) fn format_interval_ds(
        days: i32,
        hours: i32,
        minutes: i32,
        seconds: i32,
        fseconds: i32,
    ) -> Option<String> {
        let (sign, days, hours, minutes, seconds, fseconds) =
            interval_ds_parts(days, hours, minutes, seconds, fseconds)?;
        Some(format!(
            "{sign}{days} {hours:02}:{minutes:02}:{seconds:02}.{fseconds:09}"
        ))
    }

    /// ISO-8601 duration form used by the OSON path: the sign leads the whole
    /// duration (`-P1DT2H3M4.000000000S`), never an individual component.
    pub(crate) fn format_interval_ds_iso(
        days: i32,
        hours: i32,
        minutes: i32,
        seconds: i32,
        fseconds: i32,
    ) -> Option<String> {
        let (sign, days, hours, minutes, seconds, fseconds) =
            interval_ds_parts(days, hours, minutes, seconds, fseconds)?;
        Some(format!(
            "{sign}P{days}DT{hours}H{minutes}M{seconds}.{fseconds:09}S"
        ))
    }

    /// The typed refusal for an interval whose components disagree in sign.
    pub(crate) fn interval_ds_mixed_sign_marker(
        days: i32,
        hours: i32,
        minutes: i32,
        seconds: i32,
        fseconds: i32,
    ) -> Value {
        json!({
            "kind": "unsupported",
            "unsupported": "oracle_value",
            "oracle_value_kind": "IntervalDS",
            "value": null,
            "days": days,
            "hours": hours,
            "minutes": minutes,
            "seconds": seconds,
            "fseconds": fseconds,
            "warning": "INTERVAL DAY TO SECOND components disagree in sign; an Oracle interval is wholly positive or wholly negative, so no canonical text exists"
        })
    }
    impl RustOracleRowStream {
        #[must_use]
        pub(super) fn columns(&self) -> &[String] {
            &self.columns
        }

        pub(super) async fn next_row(&mut self, cx: &Cx) -> Result<Option<OracleRow>, DbError> {
            super::db_checkpoint(cx, "oracle_db.query_row_stream.next.before")?;
            let timeout_ms = self
                .limits
                .effective_timeout_ms(cx, "oracle_db.query_row_stream.next")?;
            let stream = self.stream.as_mut().ok_or_else(|| {
                DbError::Internal("owned row stream has already been recovered".to_owned())
            })?;
            let next = match bounded_fetch_batch(timeout_ms, async {
                Ok::<_, std::convert::Infallible>(
                    poll_fn(|task_cx| Stream::poll_next(Pin::new(&mut *stream), task_cx)).await,
                )
            })
            .await
            {
                Ok(next) => next,
                Err(FetchBatchError::Driver(never)) => match never {},
                Err(FetchBatchError::Timeout(timeout_ms)) => {
                    return Err(DbError::Cancelled(format!(
                        "owned row stream: call timeout of {timeout_ms} ms exceeded"
                    )));
                }
            };
            let Some(row) = next else {
                super::db_checkpoint(cx, "oracle_db.query_row_stream.next.eof")?;
                return Ok(None);
            };
            let row = row.map_err(|err| driver_query_error(err, &self.opts, None))?;
            let row = owned_row_to_oracle_row(&self.metadata, row, &self.serialize_opts)?;
            super::db_checkpoint(cx, "oracle_db.query_row_stream.next.after")?;
            Ok(Some(row))
        }

        pub(super) async fn recover(mut self, cx: &Cx) -> Result<(), DbError> {
            try_commit_section(cx, super::CLEANUP_MASKED_POLLS, async {
                let stream = self.stream.take().ok_or_else(|| {
                    DbError::Internal("owned row stream has already been recovered".to_owned())
                })?;
                let connection = match stream.into_connection().await {
                    Ok(connection) => connection,
                    Err(err) => {
                        return Err(super::quarantine_connection_slot(
                            &self.inner,
                            cx,
                            format!(
                                "owned row stream could not recover its connection: {}",
                                sanitize_driver_error(err, &self.opts)
                            ),
                        )
                        .await);
                    }
                };
                replace_connection_slot(&self.inner, cx, connection).await?;
                super::db_checkpoint(cx, "oracle_db.query_row_stream.recovered")?;
                Ok(())
            })
            .await
        }
    }

    fn owned_row_to_oracle_row(
        columns: &[ColumnMetadata],
        row: Vec<Option<QueryValue>>,
        serialize_opts: &SerializeOptions,
    ) -> Result<OracleRow, DbError> {
        let mut cells = Vec::with_capacity(columns.len());
        for (idx, meta) in columns.iter().enumerate() {
            let value = row.get(idx).cloned().flatten();
            cells.push((
                meta.name().to_owned(),
                owned_value_to_cell(meta, value, serialize_opts)?,
            ));
        }
        Ok(OracleRow { columns: cells })
    }

    fn owned_value_to_cell(
        meta: &ColumnMetadata,
        value: Option<QueryValue>,
        serialize_opts: &SerializeOptions,
    ) -> Result<OracleCell, DbError> {
        let oracle_type = oracle_type_name(meta);
        let cell = match value {
            None => OracleCell::new(oracle_type, None),
            Some(
                QueryValue::Text(value)
                | QueryValue::Rowid(value)
                | QueryValue::BinaryDouble(value),
            ) => OracleCell::new(oracle_type, Some(value)),
            Some(QueryValue::TextRaw { bytes, .. } | QueryValue::Raw(bytes)) => {
                OracleCell::binary(oracle_type, bytes)
            }
            Some(QueryValue::Number(value)) => {
                OracleCell::new(oracle_type, Some(value.to_canonical_string()))
            }
            Some(QueryValue::Boolean(value)) => OracleCell::new(
                oracle_type,
                Some(if value { "true" } else { "false" }.to_owned()),
            ),
            Some(QueryValue::DateTime {
                year,
                month,
                day,
                hour,
                minute,
                second,
                nanosecond,
            }) => OracleCell::new(
                oracle_type,
                Some(format_datetime(
                    year, month, day, hour, minute, second, nanosecond,
                )),
            ),
            Some(QueryValue::TimestampTz {
                year,
                month,
                day,
                hour,
                minute,
                second,
                nanosecond,
                offset_minutes,
            }) => OracleCell::new(
                oracle_type,
                Some(format_timestamp_tz(
                    year,
                    month,
                    day,
                    hour,
                    minute,
                    second,
                    nanosecond,
                    offset_minutes,
                )),
            ),
            Some(QueryValue::IntervalDS {
                days,
                hours,
                minutes,
                seconds,
                fseconds,
            }) => OracleCell::new(
                oracle_type,
                format_interval_ds(days, hours, minutes, seconds, fseconds),
            ),
            Some(QueryValue::IntervalYM { years, months }) => {
                OracleCell::new(oracle_type, Some(format!("{years}-{months}")))
            }
            Some(QueryValue::Object(value)) => {
                OracleCell::structured(oracle_type, structured_object_marker(&value))
            }
            Some(QueryValue::Vector(value)) => OracleCell::structured(
                oracle_type,
                structured_vector_with_caps(&value, serialize_opts.structured_decode_caps),
            ),
            Some(QueryValue::Json(value)) => OracleCell::structured(
                oracle_type,
                structured_json_value(&value, serialize_opts.structured_decode_caps),
            ),
            Some(QueryValue::Array(values)) => OracleCell::structured(
                oracle_type,
                structured_array_with_caps(&values, serialize_opts.structured_decode_caps),
            ),
            Some(QueryValue::Cursor(_) | QueryValue::Lob(_)) => {
                return Err(DbError::UnsupportedFeature(format!(
                    "owned row streaming cannot materialize {} without the driver connection; \
                     use cursor-chunked streaming fallback",
                    oracle_type
                )));
            }
            Some(value) => OracleCell::structured(
                oracle_type,
                structured_query_value_with_caps(&value, serialize_opts.structured_decode_caps),
            ),
        };
        Ok(cell)
    }

    // Async recursion (cursor cells nest result sets) is boxed to keep the
    // future `Sized`.
    #[allow(clippy::too_many_arguments)]
    fn rows_to_oracle_rows<'a>(
        cx: &'a Cx,
        inner: &'a mut oracledb::Connection,
        columns: &'a [ColumnMetadata],
        rows: Vec<Vec<Option<QueryValue>>>,
        opts: &'a OracleConnectOptions,
        serialize_opts: &'a SerializeOptions,
        limits: super::WireLimits,
        depth: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<OracleRow>, DbError>> + 'a>>
    {
        Box::pin(async move {
            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                out.push(
                    row_to_oracle_row(
                        cx,
                        inner,
                        columns,
                        &row,
                        opts,
                        serialize_opts,
                        limits.clone(),
                        depth,
                    )
                    .await?,
                );
            }
            Ok(out)
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn row_to_oracle_row<'a>(
        cx: &'a Cx,
        inner: &'a mut oracledb::Connection,
        columns: &'a [ColumnMetadata],
        row: &'a [Option<QueryValue>],
        opts: &'a OracleConnectOptions,
        serialize_opts: &'a SerializeOptions,
        limits: super::WireLimits,
        depth: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<OracleRow, DbError>> + 'a>> {
        Box::pin(async move {
            let mut cells = Vec::with_capacity(columns.len());
            for (idx, meta) in columns.iter().enumerate() {
                let value = row.get(idx).and_then(Option::as_ref);
                let oracle_type = oracle_type_name(meta);
                let bounded_cell = match value {
                    Some(QueryValue::Text(value) | QueryValue::Rowid(value)) => Some(
                        bounded_text_cell(oracle_type, value, serialize_opts.max_text_chars),
                    ),
                    Some(QueryValue::TextRaw { bytes, .. } | QueryValue::Raw(bytes)) => Some(
                        bounded_binary_cell(oracle_type, bytes, serialize_opts.max_blob_bytes),
                    ),
                    Some(QueryValue::Object(value)) => Some(OracleCell::structured(
                        oracle_type,
                        structured_object_marker(value),
                    )),
                    Some(QueryValue::Vector(value)) => Some(OracleCell::structured(
                        oracle_type,
                        structured_vector_with_caps(value, serialize_opts.structured_decode_caps),
                    )),
                    Some(QueryValue::Json(value)) => Some(OracleCell::structured(
                        oracle_type,
                        structured_json_value(value, serialize_opts.structured_decode_caps),
                    )),
                    Some(QueryValue::Array(values)) => Some(OracleCell::structured(
                        oracle_type,
                        structured_array_with_caps(values, serialize_opts.structured_decode_caps),
                    )),
                    _ => None,
                };
                cells.push((
                    meta.name().to_owned(),
                    match bounded_cell {
                        Some(cell) => cell,
                        None => {
                            value_to_cell(
                                cx,
                                inner,
                                meta,
                                value.cloned(),
                                opts,
                                serialize_opts,
                                limits.clone(),
                                depth,
                            )
                            .await?
                        }
                    },
                ));
            }
            Ok(OracleRow { columns: cells })
        })
    }

    pub(super) fn bounded_text_cell(
        oracle_type: String,
        value: &str,
        max_chars: Option<usize>,
    ) -> OracleCell {
        let source_length = value.chars().count();
        let stored = max_chars
            .filter(|cap| source_length > *cap)
            .map_or_else(|| value.to_owned(), |cap| value.chars().take(cap).collect());
        let mut cell = OracleCell::new(oracle_type, Some(stored));
        cell.source_length = Some(source_length);
        cell
    }

    pub(super) fn bounded_binary_cell(
        oracle_type: String,
        bytes: &[u8],
        max_bytes: usize,
    ) -> OracleCell {
        let source_length = bytes.len();
        let mut cell =
            OracleCell::binary(oracle_type, bytes[..source_length.min(max_bytes)].to_vec());
        cell.source_length = Some(source_length);
        cell
    }

    #[allow(clippy::too_many_arguments)]
    fn value_to_cell<'a>(
        cx: &'a Cx,
        inner: &'a mut oracledb::Connection,
        meta: &'a ColumnMetadata,
        value: Option<QueryValue>,
        opts: &'a OracleConnectOptions,
        serialize_opts: &'a SerializeOptions,
        limits: super::WireLimits,
        depth: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<OracleCell, DbError>> + 'a>>
    {
        Box::pin(async move {
            let oracle_type = oracle_type_name(meta);
            let cell = match value {
                None => OracleCell::new(oracle_type, None),
                Some(
                    QueryValue::Text(value)
                    | QueryValue::Rowid(value)
                    | QueryValue::BinaryDouble(value),
                ) => OracleCell::new(oracle_type, Some(value)),
                Some(QueryValue::TextRaw { bytes, .. } | QueryValue::Raw(bytes)) => {
                    OracleCell::binary(oracle_type, bytes)
                }
                Some(QueryValue::Number(value)) => {
                    OracleCell::new(oracle_type, Some(value.to_canonical_string()))
                }
                Some(QueryValue::Boolean(value)) => OracleCell::new(
                    oracle_type,
                    Some(if value { "true" } else { "false" }.to_owned()),
                ),
                Some(QueryValue::DateTime {
                    year,
                    month,
                    day,
                    hour,
                    minute,
                    second,
                    nanosecond,
                }) => OracleCell::new(
                    oracle_type,
                    Some(format_datetime(
                        year, month, day, hour, minute, second, nanosecond,
                    )),
                ),
                Some(QueryValue::TimestampTz {
                    year,
                    month,
                    day,
                    hour,
                    minute,
                    second,
                    nanosecond,
                    offset_minutes,
                }) => OracleCell::new(
                    oracle_type,
                    Some(format_timestamp_tz(
                        year,
                        month,
                        day,
                        hour,
                        minute,
                        second,
                        nanosecond,
                        offset_minutes,
                    )),
                ),
                Some(QueryValue::IntervalDS {
                    days,
                    hours,
                    minutes,
                    seconds,
                    fseconds,
                }) => OracleCell::new(
                    oracle_type,
                    format_interval_ds(days, hours, minutes, seconds, fseconds),
                ),
                Some(QueryValue::IntervalYM { years, months }) => {
                    OracleCell::new(oracle_type, Some(format!("{years}-{months}")))
                }
                Some(QueryValue::Cursor(cursor)) => {
                    return materialize_cursor_cell(
                        cx,
                        inner,
                        oracle_type,
                        &cursor,
                        opts,
                        serialize_opts,
                        limits,
                        depth,
                    )
                    .await;
                }
                Some(QueryValue::Object(value)) => {
                    OracleCell::structured(oracle_type, structured_object_marker(&value))
                }
                Some(QueryValue::Lob(value)) => {
                    let lob_limits = LobReadLimits::from(serialize_opts);
                    // The native-async LOB read happens HERE, before the pure
                    // `materialize_lob_cell` runs: `read_lob_plan` computes the one
                    // `(offset, amount)` the materializer would have requested, we
                    // read it on the async driver once, and hand the materializer a
                    // sync closure that just replays the captured bytes. This keeps
                    // `materialize_lob_cell` (and its unit tests) callback-shaped
                    // and pure while the actual round trip is `.await`-ed.
                    let prefetched = match read_lob_plan(&value, lob_limits) {
                        Some((offset, amount)) => {
                            let timeout_ms =
                                limits.effective_timeout_ms(cx, "oracle_db.query_rows.lob_read")?;
                            inner
                                .read_lob_with_timeout(
                                    cx,
                                    &value.locator,
                                    offset,
                                    amount,
                                    timeout_ms,
                                )
                                .await
                                .map(|result| result.data.unwrap_or_default())
                                .map_err(|err| {
                                    driver_query_error(err, opts, Some("LOB locator read failed"))
                                })?
                        }
                        None => Vec::new(),
                    };
                    let mut read_lob = |_locator: &[u8], _offset: u64, _amount: u64| {
                        Ok(LobReadData {
                            data: Some(prefetched.clone()),
                        })
                    };
                    return materialize_lob_cell(oracle_type, &value, lob_limits, &mut read_lob);
                }
                Some(QueryValue::Vector(value)) => OracleCell::structured(
                    oracle_type,
                    structured_vector_with_caps(&value, serialize_opts.structured_decode_caps),
                ),
                Some(QueryValue::Json(value)) => OracleCell::structured(
                    oracle_type,
                    structured_json_value(&value, serialize_opts.structured_decode_caps),
                ),
                Some(QueryValue::Array(values)) => OracleCell::structured(
                    oracle_type,
                    structured_array_with_caps(&values, serialize_opts.structured_decode_caps),
                ),
                // `QueryValue` is `#[non_exhaustive]` as of oracledb 0.5.x. Every wire
                // value kind that exists today is handled explicitly above; this arm
                // fails SAFE on any future kind with a clearly-marked, non-silent
                // placeholder — never a silent wrong value (cf. the NUMBER→string
                // invariant). Unreachable against the current driver.
                Some(value) => OracleCell::structured(
                    oracle_type,
                    structured_query_value_with_caps(&value, serialize_opts.structured_decode_caps),
                ),
            };
            Ok(cell)
        })
    }

    #[derive(Clone, Copy, Debug)]
    struct StructuredDecodeBudget {
        caps: StructuredDecodeCaps,
        cells: usize,
    }

    impl StructuredDecodeBudget {
        fn new(caps: StructuredDecodeCaps) -> Self {
            Self { caps, cells: 0 }
        }

        fn enter(&mut self, kind: &str, depth: usize) -> Result<(), Value> {
            if depth > self.caps.max_depth {
                return Err(structured_decode_cap_marker(
                    kind,
                    "depth",
                    self.caps.max_depth,
                ));
            }
            if self.cells >= self.caps.max_cells {
                return Err(structured_decode_cap_marker(
                    kind,
                    "cell",
                    self.caps.max_cells,
                ));
            }
            self.cells += 1;
            Ok(())
        }

        fn reserve_cells(&mut self, kind: &str, additional: usize) -> Result<(), Value> {
            if additional > self.caps.max_cells.saturating_sub(self.cells) {
                return Err(structured_decode_cap_marker(
                    kind,
                    "cell",
                    self.caps.max_cells,
                ));
            }
            self.cells += additional;
            Ok(())
        }

        fn check_rows(&self, kind: &str, rows: usize) -> Result<(), Value> {
            if rows > self.caps.max_rows {
                Err(structured_decode_cap_marker(
                    kind,
                    "row",
                    self.caps.max_rows,
                ))
            } else {
                Ok(())
            }
        }

        fn check_bytes(&self, kind: &str, value: Value) -> Value {
            if json_byte_len(&value) > self.caps.max_bytes {
                structured_decode_cap_marker(kind, "byte", self.caps.max_bytes)
            } else {
                value
            }
        }

        fn check_raw_bytes(&self, kind: &str, byte_len: usize) -> Result<(), Value> {
            if byte_len > self.caps.max_bytes {
                Err(structured_decode_cap_marker(
                    kind,
                    "byte",
                    self.caps.max_bytes,
                ))
            } else {
                Ok(())
            }
        }
    }

    #[cfg(test)]
    fn structured_array(values: &[Option<QueryValue>]) -> Value {
        structured_array_with_caps(values, StructuredDecodeCaps::DEFAULT)
    }

    fn structured_array_with_caps(
        values: &[Option<QueryValue>],
        caps: StructuredDecodeCaps,
    ) -> Value {
        let mut budget = StructuredDecodeBudget::new(caps);
        structured_array_with_budget(values, &mut budget, 0)
    }

    fn structured_array_with_budget(
        values: &[Option<QueryValue>],
        budget: &mut StructuredDecodeBudget,
        depth: usize,
    ) -> Value {
        if let Err(marker) = budget.enter("Array", depth) {
            return marker;
        }
        if let Err(marker) = budget.check_rows("Array", values.len()) {
            return marker;
        }
        let value = json!({
            "kind": "array",
            "items": values
                .iter()
                .map(|value| structured_optional_query_value_with_budget(value.as_ref(), budget, depth + 1))
                .collect::<Vec<_>>()
        });
        budget.check_bytes("Array", value)
    }

    fn structured_optional_query_value_with_budget(
        value: Option<&QueryValue>,
        budget: &mut StructuredDecodeBudget,
        depth: usize,
    ) -> Value {
        value.map_or(Value::Null, |value| {
            structured_query_value_with_budget(value, budget, depth)
        })
    }

    fn structured_query_value_with_caps(value: &QueryValue, caps: StructuredDecodeCaps) -> Value {
        let mut budget = StructuredDecodeBudget::new(caps);
        structured_query_value_with_budget(value, &mut budget, 0)
    }

    fn structured_query_value_with_budget(
        value: &QueryValue,
        budget: &mut StructuredDecodeBudget,
        depth: usize,
    ) -> Value {
        match value {
            QueryValue::Text(text) => {
                if let Err(marker) = budget.enter("Text", depth) {
                    return marker;
                }
                if let Err(marker) = budget.check_raw_bytes("Text", text.len()) {
                    return marker;
                }
                budget.check_bytes("Text", json!({ "kind": "text", "value": text }))
            }
            QueryValue::TextRaw { bytes, csfrm } => {
                if let Err(marker) = budget.enter("TextRaw", depth) {
                    return marker;
                }
                if let Err(marker) = budget.check_raw_bytes("TextRaw", bytes.len()) {
                    return marker;
                }
                budget.check_bytes(
                    "TextRaw",
                    json!({
                        "kind": "text_raw",
                        "encoding": "hex",
                        "data": hex_encode(bytes),
                        "byte_length": bytes.len(),
                        "csfrm": csfrm
                    }),
                )
            }
            QueryValue::Raw(bytes) => {
                if let Err(marker) = budget.enter("Raw", depth) {
                    return marker;
                }
                if let Err(marker) = budget.check_raw_bytes("Raw", bytes.len()) {
                    return marker;
                }
                budget.check_bytes(
                    "Raw",
                    json!({
                        "kind": "raw",
                        "encoding": "hex",
                        "data": hex_encode(bytes),
                        "byte_length": bytes.len()
                    }),
                )
            }
            QueryValue::Rowid(text) => {
                if let Err(marker) = budget.enter("Rowid", depth) {
                    return marker;
                }
                if let Err(marker) = budget.check_raw_bytes("Rowid", text.len()) {
                    return marker;
                }
                budget.check_bytes("Rowid", json!({ "kind": "rowid", "value": text }))
            }
            QueryValue::BinaryDouble(text) => {
                if let Err(marker) = budget.enter("BinaryDouble", depth) {
                    return marker;
                }
                if let Err(marker) = budget.check_raw_bytes("BinaryDouble", text.len()) {
                    return marker;
                }
                budget.check_bytes(
                    "BinaryDouble",
                    json!({ "kind": "binary_double", "value": text }),
                )
            }
            QueryValue::IntervalDS {
                days,
                hours,
                minutes,
                seconds,
                fseconds,
            } => {
                if let Err(marker) = budget.enter("IntervalDS", depth) {
                    return marker;
                }
                let Some(text) = format_interval_ds(*days, *hours, *minutes, *seconds, *fseconds)
                else {
                    return interval_ds_mixed_sign_marker(
                        *days, *hours, *minutes, *seconds, *fseconds,
                    );
                };
                budget.check_bytes(
                    "IntervalDS",
                    json!({
                        "kind": "interval_ds",
                        "value": text,
                        "days": days,
                        "hours": hours,
                        "minutes": minutes,
                        "seconds": seconds,
                        "fseconds": fseconds
                    }),
                )
            }
            QueryValue::IntervalYM { years, months } => {
                if let Err(marker) = budget.enter("IntervalYM", depth) {
                    return marker;
                }
                budget.check_bytes(
                    "IntervalYM",
                    json!({
                        "kind": "interval_ym",
                        "value": format!("{years}-{months}"),
                        "years": years,
                        "months": months
                    }),
                )
            }
            QueryValue::Number(number) => {
                if let Err(marker) = budget.enter("Number", depth) {
                    return marker;
                }
                budget.check_bytes(
                    "Number",
                    json!({ "kind": "number", "value": number.to_canonical_string() }),
                )
            }
            QueryValue::Boolean(value) => {
                if let Err(marker) = budget.enter("Boolean", depth) {
                    return marker;
                }
                budget.check_bytes("Boolean", json!({ "kind": "boolean", "value": value }))
            }
            QueryValue::DateTime {
                year,
                month,
                day,
                hour,
                minute,
                second,
                nanosecond,
            } => {
                if let Err(marker) = budget.enter("DateTime", depth) {
                    return marker;
                }
                budget.check_bytes(
                    "DateTime",
                    json!({
                        "kind": "datetime",
                        "value": format_datetime(
                            *year,
                            *month,
                            *day,
                            *hour,
                            *minute,
                            *second,
                            *nanosecond
                        ),
                        "year": year,
                        "month": month,
                        "day": day,
                        "hour": hour,
                        "minute": minute,
                        "second": second,
                        "nanosecond": nanosecond
                    }),
                )
            }
            QueryValue::TimestampTz {
                year,
                month,
                day,
                hour,
                minute,
                second,
                nanosecond,
                offset_minutes,
            } => {
                if let Err(marker) = budget.enter("TimestampTz", depth) {
                    return marker;
                }
                budget.check_bytes(
                    "TimestampTz",
                    json!({
                        "kind": "timestamp_tz",
                        "value": format_timestamp_tz(
                            *year,
                            *month,
                            *day,
                            *hour,
                            *minute,
                            *second,
                            *nanosecond,
                            *offset_minutes
                        ),
                        "year": year,
                        "month": month,
                        "day": day,
                        "hour": hour,
                        "minute": minute,
                        "second": second,
                        "nanosecond": nanosecond,
                        "offset_minutes": offset_minutes
                    }),
                )
            }
            QueryValue::Vector(vector) => structured_vector_with_budget(vector, budget, depth),
            QueryValue::Json(value) => {
                if let Err(marker) = budget.enter("Json", depth) {
                    return marker;
                }
                let decoded = structured_oson_value_with_budget(value, budget, depth + 1);
                budget.check_bytes("Json", json!({ "kind": "json", "value": decoded }))
            }
            QueryValue::Array(values) => structured_array_with_budget(values, budget, depth),
            QueryValue::Object(value) => {
                if let Err(marker) = budget.enter("Object", depth) {
                    return marker;
                }
                budget.check_bytes("Object", structured_object_marker(value))
            }
            QueryValue::Cursor(_) | QueryValue::Lob(_) => {
                if let Err(marker) = budget.enter(value.variant_name(), depth) {
                    return marker;
                }
                budget.check_bytes(
                    value.variant_name(),
                    structured_unsupported(value.variant_name()),
                )
            }
            _ => {
                if let Err(marker) = budget.enter(value.variant_name(), depth) {
                    return marker;
                }
                budget.check_bytes(
                    value.variant_name(),
                    structured_unsupported(value.variant_name()),
                )
            }
        }
    }

    fn structured_json_value(value: &OsonValue, caps: StructuredDecodeCaps) -> Value {
        let mut budget = StructuredDecodeBudget::new(caps);
        if let Err(marker) = budget.enter("Json", 0) {
            return marker;
        }
        let decoded = structured_oson_value_with_budget(value, &mut budget, 1);
        budget.check_bytes("Json", json!({ "kind": "json", "value": decoded }))
    }

    #[cfg(test)]
    fn structured_oson_value(value: &OsonValue) -> Value {
        structured_oson_value_with_caps(value, StructuredDecodeCaps::DEFAULT)
    }

    #[cfg(test)]
    fn structured_oson_value_with_caps(value: &OsonValue, caps: StructuredDecodeCaps) -> Value {
        let mut budget = StructuredDecodeBudget::new(caps);
        structured_oson_value_with_budget(value, &mut budget, 0)
    }

    fn structured_oson_value_with_budget(
        value: &OsonValue,
        budget: &mut StructuredDecodeBudget,
        depth: usize,
    ) -> Value {
        match value {
            OsonValue::Null => {
                if let Err(marker) = budget.enter("Null", depth) {
                    return marker;
                }
                budget.check_bytes("Null", json!({ "kind": "null" }))
            }
            OsonValue::Bool(value) => {
                if let Err(marker) = budget.enter("Boolean", depth) {
                    return marker;
                }
                budget.check_bytes("Boolean", json!({ "kind": "boolean", "value": value }))
            }
            OsonValue::Number(text) => {
                if let Err(marker) = budget.enter("Number", depth) {
                    return marker;
                }
                if let Err(marker) = budget.check_raw_bytes("Number", text.len()) {
                    return marker;
                }
                budget.check_bytes("Number", json!({ "kind": "number", "value": text }))
            }
            OsonValue::BinaryFloat(value) => {
                if let Err(marker) = budget.enter("BinaryFloat", depth) {
                    return marker;
                }
                budget.check_bytes(
                    "BinaryFloat",
                    json!({ "kind": "binary_float", "value": json_number_or_string(f64::from(*value)) }),
                )
            }
            OsonValue::BinaryDouble(value) => {
                if let Err(marker) = budget.enter("BinaryDouble", depth) {
                    return marker;
                }
                budget.check_bytes(
                    "BinaryDouble",
                    json!({ "kind": "binary_double", "value": json_number_or_string(*value) }),
                )
            }
            OsonValue::String(text) => {
                if let Err(marker) = budget.enter("String", depth) {
                    return marker;
                }
                if let Err(marker) = budget.check_raw_bytes("String", text.len()) {
                    return marker;
                }
                budget.check_bytes("String", json!({ "kind": "string", "value": text }))
            }
            OsonValue::Raw(bytes) => {
                if let Err(marker) = budget.enter("Raw", depth) {
                    return marker;
                }
                if let Err(marker) = budget.check_raw_bytes("Raw", bytes.len()) {
                    return marker;
                }
                budget.check_bytes(
                    "Raw",
                    json!({
                        "kind": "raw",
                        "encoding": "hex",
                        "data": hex_encode(bytes),
                        "byte_length": bytes.len()
                    }),
                )
            }
            OsonValue::DateTime {
                year,
                month,
                day,
                hour,
                minute,
                second,
                nanosecond,
            } => {
                if let Err(marker) = budget.enter("DateTime", depth) {
                    return marker;
                }
                budget.check_bytes(
                    "DateTime",
                    json!({
                        "kind": "datetime",
                        "value": format_datetime(
                            *year,
                            *month,
                            *day,
                            *hour,
                            *minute,
                            *second,
                            *nanosecond
                        ),
                        "year": year,
                        "month": month,
                        "day": day,
                        "hour": hour,
                        "minute": minute,
                        "second": second,
                        "nanosecond": nanosecond
                    }),
                )
            }
            OsonValue::IntervalDS {
                days,
                hours,
                minutes,
                seconds,
                fseconds,
            } => {
                if let Err(marker) = budget.enter("IntervalDS", depth) {
                    return marker;
                }
                let Some(text) =
                    format_interval_ds_iso(*days, *hours, *minutes, *seconds, *fseconds)
                else {
                    return interval_ds_mixed_sign_marker(
                        *days, *hours, *minutes, *seconds, *fseconds,
                    );
                };
                budget.check_bytes(
                    "IntervalDS",
                    json!({
                        "kind": "interval_ds",
                        "value": text,
                        "days": days,
                        "hours": hours,
                        "minutes": minutes,
                        "seconds": seconds,
                        "fseconds": fseconds
                    }),
                )
            }
            OsonValue::Vector(vector) => structured_vector_with_budget(vector, budget, depth),
            OsonValue::Array(items) => {
                if let Err(marker) = budget.enter("Array", depth) {
                    return marker;
                }
                if let Err(marker) = budget.check_rows("Array", items.len()) {
                    return marker;
                }
                let value = json!({
                    "kind": "array",
                    "items": items
                        .iter()
                        .map(|value| structured_oson_value_with_budget(value, budget, depth + 1))
                        .collect::<Vec<_>>()
                });
                budget.check_bytes("Array", value)
            }
            OsonValue::Object(entries) => {
                if let Err(marker) = budget.enter("Object", depth) {
                    return marker;
                }
                if let Err(marker) = budget.check_rows("Object", entries.len()) {
                    return marker;
                }
                let value = json!({
                    "kind": "object",
                    "entries": entries
                        .iter()
                        .map(|(key, value)| {
                            json!({ "key": key, "value": structured_oson_value_with_budget(value, budget, depth + 1) })
                        })
                        .collect::<Vec<_>>()
                });
                budget.check_bytes("Object", value)
            }
        }
    }

    #[cfg(test)]
    fn structured_vector(vector: &Vector) -> Value {
        let mut budget = StructuredDecodeBudget::new(StructuredDecodeCaps::DEFAULT);
        structured_vector_with_budget(vector, &mut budget, 0)
    }

    fn structured_vector_with_caps(vector: &Vector, caps: StructuredDecodeCaps) -> Value {
        let mut budget = StructuredDecodeBudget::new(caps);
        structured_vector_with_budget(vector, &mut budget, 0)
    }

    fn structured_vector_with_budget(
        vector: &Vector,
        budget: &mut StructuredDecodeBudget,
        depth: usize,
    ) -> Value {
        if let Err(marker) = budget.enter("Vector", depth) {
            return marker;
        }
        if let Err(marker) = budget.reserve_cells("Vector", vector_value_count(vector)) {
            return marker;
        }
        let value = match vector {
            Vector::Dense(values) => {
                let (format, values) = structured_vector_values(values);
                json!({
                    "kind": "vector",
                    "storage": "dense",
                    "format": format,
                    "values": values
                })
            }
            Vector::Sparse {
                num_dimensions,
                indices,
                values,
            } => {
                let (format, values) = structured_vector_values(values);
                json!({
                    "kind": "vector",
                    "storage": "sparse",
                    "format": format,
                    "num_dimensions": num_dimensions,
                    "indices": indices,
                    "values": values
                })
            }
        };
        budget.check_bytes("Vector", value)
    }

    fn vector_value_count(vector: &Vector) -> usize {
        match vector {
            Vector::Dense(values) | Vector::Sparse { values, .. } => match values {
                VectorValues::Float32(values) => values.len(),
                VectorValues::Float64(values) => values.len(),
                VectorValues::Int8(values) => values.len(),
                VectorValues::Binary(values) => values.len(),
            },
        }
    }

    fn structured_decode_cap_marker(kind: &str, cap: &str, limit: usize) -> Value {
        json!({
            "kind": "unsupported",
            "unsupported": "oracle_value",
            "oracle_value_kind": kind,
            "value": null,
            "warning": format!(
                "Oracle value exceeded structured {cap} decode cap ({limit}); set deep_decode=true or lower selectivity to inspect more"
            )
        })
    }

    fn structured_vector_values(values: &VectorValues) -> (&'static str, Value) {
        match values {
            VectorValues::Float32(values) => (
                "float32",
                Value::Array(
                    values
                        .iter()
                        .map(|value| json_number_or_string(f64::from(*value)))
                        .collect(),
                ),
            ),
            VectorValues::Float64(values) => (
                "float64",
                Value::Array(
                    values
                        .iter()
                        .map(|value| json_number_or_string(*value))
                        .collect(),
                ),
            ),
            VectorValues::Int8(values) => (
                "int8",
                Value::Array(values.iter().map(|value| json!(*value)).collect()),
            ),
            VectorValues::Binary(values) => (
                "binary",
                Value::Array(values.iter().map(|value| json!(*value)).collect()),
            ),
        }
    }

    fn structured_unsupported(kind: &str) -> Value {
        json!({
            "kind": "unsupported",
            "unsupported": "oracle_value",
            "oracle_value_kind": kind,
            "value": null,
            "warning": "Oracle value kind is not structurally serialized yet"
        })
    }

    fn structured_object_marker(value: &ObjectValue) -> Value {
        json!({
            "kind": "unsupported",
            "unsupported": "oracle_object",
            "oracle_value_kind": "Object",
            "schema": value.schema.as_deref(),
            "type_name": value.type_name.as_deref(),
            "packed_byte_length": value.packed_data.len(),
            "value": null,
            "warning": "Oracle object/UDT values are not decoded by default"
        })
    }

    fn json_number_or_string(value: f64) -> Value {
        Number::from_f64(value).map_or_else(|| Value::String(value.to_string()), Value::Number)
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    fn implicit_resultsets_to_row<'a>(
        cx: &'a Cx,
        inner: &'a mut oracledb::Connection,
        values: Vec<QueryValue>,
        opts: &'a OracleConnectOptions,
        serialize_opts: &'a SerializeOptions,
        limits: super::WireLimits,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<OracleRow>, DbError>> + 'a>>
    {
        Box::pin(async move {
            let mut columns = Vec::with_capacity(values.len());
            for (idx, value) in values.into_iter().enumerate() {
                let name = format!("IMPLICIT_RESULT_{}", idx + 1);
                let cell = match value {
                    QueryValue::Cursor(cursor) => {
                        materialize_cursor_cell(
                            cx,
                            inner,
                            "REF CURSOR".to_owned(),
                            &cursor,
                            opts,
                            serialize_opts,
                            limits.clone(),
                            0,
                        )
                        .await?
                    }
                    other => OracleCell::new(
                        "VARCHAR2",
                        Some(format!(
                            "<unsupported implicit resultset value {}: {other:?}>",
                            idx + 1
                        )),
                    ),
                };
                columns.push((name, cell));
            }
            if columns.is_empty() {
                Ok(None)
            } else {
                Ok(Some(OracleRow { columns }))
            }
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn materialize_cursor_cell<'a>(
        cx: &'a Cx,
        inner: &'a mut oracledb::Connection,
        oracle_type: String,
        cursor: &'a CursorValue,
        opts: &'a OracleConnectOptions,
        serialize_opts: &'a SerializeOptions,
        limits: super::WireLimits,
        depth: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<OracleCell, DbError>> + 'a>>
    {
        Box::pin(async move {
            if depth >= serialize_opts.max_nested_cursor_depth {
                inner.release_cursor(cursor.cursor_id);
                return Ok(OracleCell::nested_result(
                    oracle_type,
                    OracleNestedResult {
                        columns: cursor_column_names(&cursor.columns),
                        truncated: true,
                        ..Default::default()
                    },
                ));
            }
            let (row_cap, fetch_limit, cell_limited) = cursor_caps(cursor, serialize_opts);
            let timeout_ms =
                match limits.effective_timeout_ms(cx, "oracle_db.query_rows.ref_cursor_fetch") {
                    Ok(timeout_ms) => timeout_ms,
                    Err(err) => {
                        inner.release_cursor(cursor.cursor_id);
                        return Err(err);
                    }
                };
            let fetch_result =
                bounded_fetch_batch(timeout_ms, inner.fetch_cursor(cx, cursor, fetch_limit)).await;
            let result = match resolve_fetch_batch(cx, inner, fetch_result, opts).await {
                Ok(result) => result,
                Err(err) => {
                    inner.release_cursor(cursor.cursor_id);
                    return Err(match err {
                        DbError::Query(message) => {
                            DbError::Query(format!("REF CURSOR fetch failed: {message}"))
                        }
                        other => other,
                    });
                }
            };
            let mut rows = result.rows;
            let fetched_count = rows.len().min(row_cap);
            let row_limited = rows.len() > row_cap;
            rows.truncate(row_cap);
            let columns = if result.columns.is_empty() {
                cursor.columns.clone()
            } else {
                result.columns
            };
            let nested_rows = rows_to_oracle_rows(
                cx,
                inner,
                &columns,
                rows,
                opts,
                serialize_opts,
                limits.clone(),
                depth + 1,
            )
            .await?;
            Ok(OracleCell::nested_result(
                oracle_type,
                OracleNestedResult {
                    columns: cursor_column_names(&columns),
                    row_count: nested_rows.len(),
                    fetched_count,
                    rows: nested_rows,
                    truncated: row_limited || cell_limited,
                },
            ))
        })
    }

    fn cursor_caps(cursor: &CursorValue, opts: &SerializeOptions) -> (usize, usize, bool) {
        let column_count = cursor.columns.len().max(1);
        let rows_by_cells = opts.max_nested_cursor_cells / column_count;
        let row_cap = opts.max_nested_cursor_rows.min(rows_by_cells);
        let cell_limited = row_cap < opts.max_nested_cursor_rows;
        let fetch_limit = row_cap.saturating_add(1).max(1);
        (row_cap, fetch_limit, cell_limited)
    }

    fn cursor_column_names(columns: &[ColumnMetadata]) -> Vec<String> {
        columns
            .iter()
            .map(|column| column.name().to_owned())
            .collect()
    }

    fn materialize_lob_cell(
        oracle_type: String,
        lob: &LobValue,
        limits: LobReadLimits,
        read_lob: &mut impl FnMut(&[u8], u64, u64) -> Result<LobReadData, DbError>,
    ) -> Result<OracleCell, DbError> {
        match lob.ora_type_num {
            ORA_TYPE_NUM_CLOB => materialize_text_lob(oracle_type, lob, limits, read_lob),
            ORA_TYPE_NUM_BLOB => materialize_binary_lob(
                oracle_type,
                lob,
                Some(lob.size),
                limits.max_blob_bytes,
                read_lob,
            ),
            ORA_TYPE_NUM_BFILE => {
                materialize_binary_lob(oracle_type, lob, None, limits.max_blob_bytes, read_lob)
            }
            other => Err(DbError::Query(format!(
                "unsupported LOB locator type ORA_TYPE_{other}"
            ))),
        }
    }

    fn materialize_text_lob(
        oracle_type: String,
        lob: &LobValue,
        limits: LobReadLimits,
        read_lob: &mut impl FnMut(&[u8], u64, u64) -> Result<LobReadData, DbError>,
    ) -> Result<OracleCell, DbError> {
        let source_length = saturating_usize(lob.size);
        let amount = known_lob_read_amount(lob.size, limits.max_lob_chars);
        let data = read_lob_bytes(lob, amount, read_lob)?;
        let text = if data.is_empty() {
            String::new()
        } else {
            decode_lob_text(&data, lob.csfrm, Some(&lob.locator))
                .map_err(|err| DbError::Query(format!("LOB text decode failed: {err}")))?
        };
        Ok(OracleCell::new(oracle_type, Some(text)).with_source_length(source_length))
    }

    fn materialize_binary_lob(
        oracle_type: String,
        lob: &LobValue,
        known_size: Option<u64>,
        cap: usize,
        read_lob: &mut impl FnMut(&[u8], u64, u64) -> Result<LobReadData, DbError>,
    ) -> Result<OracleCell, DbError> {
        let amount = known_size.map_or_else(
            || unknown_lob_read_amount(cap),
            |size| known_lob_read_amount(size, cap),
        );
        let data = read_lob_bytes(lob, amount, read_lob)?;
        let mut cell = OracleCell::binary(oracle_type, data);
        if let Some(source_length) = known_size.map(saturating_usize) {
            cell = cell.with_source_length(source_length);
        }
        Ok(cell)
    }

    fn read_lob_bytes(
        lob: &LobValue,
        amount: u64,
        read_lob: &mut impl FnMut(&[u8], u64, u64) -> Result<LobReadData, DbError>,
    ) -> Result<Vec<u8>, DbError> {
        if amount == 0 {
            return Ok(Vec::new());
        }
        Ok(read_lob(&lob.locator, 1, amount)?.data.unwrap_or_default())
    }

    /// The single `(offset, amount)` the `materialize_lob_cell` family would
    /// request for `lob` under `limits`, or `None` when no read is needed
    /// (amount `0` — an empty LOB). Mirrors the amount logic of
    /// `materialize_text_lob` (CLOB) and `materialize_binary_lob` (BLOB/BFILE)
    /// so the native-async read can be hoisted ahead of the pure materializer.
    fn read_lob_plan(lob: &LobValue, limits: LobReadLimits) -> Option<(u64, u64)> {
        let amount = match lob.ora_type_num {
            ORA_TYPE_NUM_CLOB => known_lob_read_amount(lob.size, limits.max_lob_chars),
            ORA_TYPE_NUM_BLOB => known_lob_read_amount(lob.size, limits.max_blob_bytes),
            ORA_TYPE_NUM_BFILE => unknown_lob_read_amount(limits.max_blob_bytes),
            // Unsupported subtypes never read; `materialize_lob_cell` errors.
            _ => 0,
        };
        (amount != 0).then_some((1, amount))
    }

    fn known_lob_read_amount(size: u64, cap: usize) -> u64 {
        size.min(u64::try_from(cap).unwrap_or(u64::MAX))
    }

    fn unknown_lob_read_amount(cap: usize) -> u64 {
        u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1)
    }

    fn saturating_usize(value: u64) -> usize {
        usize::try_from(value).unwrap_or(usize::MAX)
    }

    #[cfg(test)]
    #[allow(clippy::items_after_test_module)]
    mod lob_tests {
        use super::*;
        use crate::serialize::serialize_cell;
        use oracledb::protocol::{
            oson::OsonValue,
            thin::{CS_FORM_IMPLICIT, ORA_TYPE_NUM_RAW, image_begin, image_finalize},
            vector::{Vector, VectorValues},
        };
        use oracledb::{CollectionElement, ObjectAttribute, ObjectType, decode_object};
        use serde_json::json;

        fn lob(ora_type_num: u8, size: u64) -> LobValue {
            LobValue {
                ora_type_num,
                csfrm: CS_FORM_IMPLICIT,
                locator: vec![7; 40],
                size,
                chunk_size: 8192,
            }
        }

        fn cursor(column_count: usize) -> CursorValue {
            CursorValue {
                columns: (0..column_count)
                    .map(|idx| ColumnMetadata::new(format!("C{idx}"), 0))
                    .collect(),
                cursor_id: 42,
            }
        }

        #[cfg(feature = "live-xe")]
        fn live_opts_from_env() -> Option<OracleConnectOptions> {
            Some(OracleConnectOptions {
                connect_string: std::env::var("ORACLEMCP_TEST_DSN").ok()?,
                username: Some(std::env::var("ORACLEMCP_TEST_USER").ok()?),
                password: Some(std::env::var("ORACLEMCP_TEST_PASSWORD").ok()?),
                ..Default::default()
            })
        }

        #[test]
        fn cursor_caps_enforce_rows_and_cells_with_sentinel_fetch() {
            let opts = SerializeOptions {
                max_nested_cursor_rows: 10,
                max_nested_cursor_cells: 12,
                ..Default::default()
            };

            assert_eq!(cursor_caps(&cursor(2), &opts), (6, 7, true));
            assert_eq!(cursor_caps(&cursor(1), &opts), (10, 11, false));
        }

        #[test]
        fn named_binds_are_ordered_by_first_real_placeholder() {
            let ordered = order_named_binds_for_driver(
                "select ':ignored' as s, :a, :b, :a from dual -- :commented\n\
                 where c = :c /* :also_ignored */ and quoted = \":identifier\"",
                vec![
                    (":C".to_owned(), BindValue::Text("three".to_owned())),
                    (":B".to_owned(), BindValue::Number("2".to_owned())),
                    ("a".to_owned(), BindValue::Number("1".to_owned())),
                ],
            )
            .expect("out-of-order named binds should be ordered");

            assert_eq!(ordered.len(), 3);
            assert!(matches!(&ordered[0], BindValue::Number(value) if value == "1"));
            assert!(matches!(&ordered[1], BindValue::Number(value) if value == "2"));
            assert!(matches!(&ordered[2], BindValue::Text(value) if value == "three"));
        }

        #[test]
        fn named_bind_ordering_rejects_missing_and_unexpected_names() {
            let missing_and_unexpected = order_named_binds_for_driver(
                "select :a, :b from dual",
                vec![
                    (":a".to_owned(), BindValue::Number("1".to_owned())),
                    (":unused".to_owned(), BindValue::Number("2".to_owned())),
                ],
            )
            .expect_err("named binds must match placeholders exactly");
            assert!(matches!(
                missing_and_unexpected,
                DbError::NamedBindMismatch { missing, unexpected }
                    if missing == ["b"] && unexpected == [":unused"]
            ));

            let unexpected = order_named_binds_for_driver(
                "select :a from dual",
                vec![
                    (":a".to_owned(), BindValue::Number("1".to_owned())),
                    (":unused".to_owned(), BindValue::Number("2".to_owned())),
                ],
            )
            .expect_err("an extra named bind must not be appended positionally");
            assert!(matches!(
                unexpected,
                DbError::NamedBindMismatch { missing, unexpected }
                    if missing.is_empty() && unexpected == [":unused"]
            ));
        }

        #[test]
        fn structured_array_round_trips_nested_values_without_lossy_text() {
            let value = structured_array(&[
                None,
                Some(QueryValue::number_from_text(
                    "99999999999999999999999999999999999999",
                    true,
                )),
                Some(QueryValue::TimestampTz {
                    year: 2026,
                    month: 6,
                    day: 29,
                    hour: 12,
                    minute: 34,
                    second: 56,
                    nanosecond: 987_654_321,
                    offset_minutes: -330,
                }),
                Some(QueryValue::Array(vec![Some(QueryValue::Boolean(true))])),
            ]);
            let expected = json!({
                "kind": "array",
                "items": [
                    null,
                    {
                        "kind": "number",
                        "value": "99999999999999999999999999999999999999"
                    },
                    {
                        "kind": "timestamp_tz",
                        "value": "2026-06-29 12:34:56.987654321 -05:30",
                        "year": 2026,
                        "month": 6,
                        "day": 29,
                        "hour": 12,
                        "minute": 34,
                        "second": 56,
                        "nanosecond": 987654321,
                        "offset_minutes": -330
                    },
                    {
                        "kind": "array",
                        "items": [{ "kind": "boolean", "value": true }]
                    }
                ]
            });

            assert_eq!(value, expected);
            let encoded = serde_json::to_string(&value).expect("structured array serializes");
            let decoded: serde_json::Value =
                serde_json::from_str(&encoded).expect("structured array parses");
            assert_eq!(decoded, expected);
            assert_eq!(
                structured_array(&[]),
                json!({ "kind": "array", "items": [] })
            );
        }

        fn assert_structured_cap_marker(
            value: &Value,
            oracle_value_kind: &str,
            cap: &str,
            limit: usize,
        ) {
            assert_eq!(value["kind"], json!("unsupported"));
            assert_eq!(value["unsupported"], json!("oracle_value"));
            assert_eq!(value["oracle_value_kind"], json!(oracle_value_kind));
            assert_eq!(value["value"], Value::Null);
            let warning = value["warning"]
                .as_str()
                .expect("cap marker warning is text");
            assert!(
                warning.contains(&format!("structured {cap} decode cap ({limit})")),
                "unexpected cap warning: {warning}"
            );
        }

        #[test]
        fn structured_decode_caps_enforce_rows_and_cells_at_boundary() {
            let values = [
                Some(QueryValue::Boolean(true)),
                Some(QueryValue::Boolean(false)),
            ];

            let row_capped =
                structured_array_with_caps(&values, StructuredDecodeCaps::new(1, 10, 1_000, 8));
            assert_structured_cap_marker(&row_capped, "Array", "row", 1);

            let row_exact =
                structured_array_with_caps(&values, StructuredDecodeCaps::new(2, 10, 1_000, 8));
            assert_eq!(row_exact["items"].as_array().expect("array items").len(), 2);

            let cell_capped =
                structured_array_with_caps(&values, StructuredDecodeCaps::new(2, 2, 1_000, 8));
            assert_eq!(
                cell_capped["items"][0],
                json!({ "kind": "boolean", "value": true })
            );
            assert_structured_cap_marker(&cell_capped["items"][1], "Boolean", "cell", 2);

            let cell_exact =
                structured_array_with_caps(&values, StructuredDecodeCaps::new(2, 3, 1_000, 8));
            assert_eq!(
                cell_exact,
                json!({
                    "kind": "array",
                    "items": [
                        { "kind": "boolean", "value": true },
                        { "kind": "boolean", "value": false }
                    ]
                })
            );
        }

        #[test]
        fn structured_decode_caps_enforce_depth_and_bytes_at_boundary() {
            let nested = [Some(QueryValue::Array(vec![Some(QueryValue::Boolean(
                true,
            ))]))];

            let depth_capped =
                structured_array_with_caps(&nested, StructuredDecodeCaps::new(10, 10, 1_000, 1));
            assert_structured_cap_marker(
                &depth_capped["items"][0]["items"][0],
                "Boolean",
                "depth",
                1,
            );

            let depth_exact =
                structured_array_with_caps(&nested, StructuredDecodeCaps::new(10, 10, 1_000, 2));
            assert_eq!(
                depth_exact["items"][0]["items"][0],
                json!({ "kind": "boolean", "value": true })
            );

            let text = OsonValue::String("abcdef".to_owned());
            let full = structured_oson_value_with_caps(
                &text,
                StructuredDecodeCaps::new(10, 10, usize::MAX, 8),
            );
            let full_len = crate::serialize::json_byte_len(&full);
            let byte_capped = structured_oson_value_with_caps(
                &text,
                StructuredDecodeCaps::new(10, 10, full_len - 1, 8),
            );
            assert_structured_cap_marker(&byte_capped, "String", "byte", full_len - 1);

            let byte_exact = structured_oson_value_with_caps(
                &text,
                StructuredDecodeCaps::new(10, 10, full_len, 8),
            );
            assert_eq!(byte_exact, full);
        }

        #[test]
        fn structured_oson_keeps_non_json_scalars_typed() {
            let value = structured_oson_value(&OsonValue::Object(vec![
                (
                    "wide_number".to_owned(),
                    OsonValue::Number("1.234567890123456789".to_owned()),
                ),
                ("raw".to_owned(), OsonValue::Raw(vec![0xde, 0xad])),
                (
                    "when".to_owned(),
                    OsonValue::DateTime {
                        year: 2026,
                        month: 6,
                        day: 30,
                        hour: 21,
                        minute: 24,
                        second: 5,
                        nanosecond: 123_456_789,
                    },
                ),
                (
                    "embedded_vector".to_owned(),
                    OsonValue::Vector(Vector::Dense(VectorValues::Int8(vec![-1, 0, 127]))),
                ),
            ]));

            assert_eq!(
                value,
                json!({
                    "kind": "object",
                    "entries": [
                        {
                            "key": "wide_number",
                            "value": {
                                "kind": "number",
                                "value": "1.234567890123456789"
                            }
                        },
                        {
                            "key": "raw",
                            "value": {
                                "kind": "raw",
                                "encoding": "hex",
                                "data": "dead",
                                "byte_length": 2
                            }
                        },
                        {
                            "key": "when",
                            "value": {
                                "kind": "datetime",
                                "value": "2026-06-30 21:24:05.123456789",
                                "year": 2026,
                                "month": 6,
                                "day": 30,
                                "hour": 21,
                                "minute": 24,
                                "second": 5,
                                "nanosecond": 123456789
                            }
                        },
                        {
                            "key": "embedded_vector",
                            "value": {
                                "kind": "vector",
                                "storage": "dense",
                                "format": "int8",
                                "values": [-1, 0, 127]
                            }
                        }
                    ]
                })
            );
        }

        #[test]
        fn structured_vector_covers_dense_sparse_and_binary_formats() {
            assert_eq!(
                structured_vector(&Vector::Dense(VectorValues::Float32(vec![1.25, -2.5]))),
                json!({
                    "kind": "vector",
                    "storage": "dense",
                    "format": "float32",
                    "values": [1.25, -2.5]
                })
            );
            assert_eq!(
                structured_vector(&Vector::Dense(VectorValues::Float64(vec![3.5, 4.25]))),
                json!({
                    "kind": "vector",
                    "storage": "dense",
                    "format": "float64",
                    "values": [3.5, 4.25]
                })
            );
            assert_eq!(
                structured_vector(&Vector::Dense(VectorValues::Binary(vec![0xaa, 0x55]))),
                json!({
                    "kind": "vector",
                    "storage": "dense",
                    "format": "binary",
                    "values": [170, 85]
                })
            );
            assert_eq!(
                structured_vector(&Vector::Sparse {
                    num_dimensions: 4,
                    indices: vec![0, 3],
                    values: VectorValues::Float64(vec![1.0, -1.5]),
                }),
                json!({
                    "kind": "vector",
                    "storage": "sparse",
                    "format": "float64",
                    "num_dimensions": 4,
                    "indices": [0, 3],
                    "values": [1.0, -1.5]
                })
            );
        }

        #[test]
        fn object_value_marker_preserves_identity_without_packed_bytes() {
            let object = ObjectValue {
                schema: Some("HR".to_owned()),
                type_name: Some("ADDRESS_T".to_owned()),
                packed_data: vec![0xde, 0xad, 0xbe, 0xef],
            };
            let marker = structured_object_marker(&object);
            let expected = json!({
                "kind": "unsupported",
                "unsupported": "oracle_object",
                "oracle_value_kind": "Object",
                "schema": "HR",
                "type_name": "ADDRESS_T",
                "packed_byte_length": 4,
                "value": null,
                "warning": "Oracle object/UDT values are not decoded by default"
            });
            assert_eq!(marker, expected);
            assert!(
                !marker.to_string().contains("deadbeef"),
                "packed object bytes must not be dumped into the public marker"
            );

            let nested = structured_array(&[Some(QueryValue::Object(Box::new(object)))]);
            assert_eq!(nested["items"][0], expected);
        }

        #[test]
        fn decode_object_reports_nested_shapes_as_unsupported_feature() {
            let mut image = image_begin(false);
            image_finalize(&mut image).expect("object image finalizes");
            let value = ObjectValue {
                schema: Some("HR".to_owned()),
                type_name: Some("OUTER_T".to_owned()),
                packed_data: image,
            };
            let object_type = ObjectType {
                schema: "HR".to_owned(),
                name: "OUTER_T".to_owned(),
                attributes: vec![ObjectAttribute {
                    name: "CHILD".to_owned(),
                    type_name: "CHILD_T".to_owned(),
                    type_owner: Some("HR".to_owned()),
                }],
                collection_element: None,
            };
            let err = decode_object(&value, &object_type)
                .expect_err("nested object attributes are intentionally unsupported");
            assert!(
                err.to_string()
                    .contains("nested object/collection attribute is not decodable yet"),
                "unexpected error: {err}"
            );

            let mut image = image_begin(true);
            image_finalize(&mut image).expect("collection image finalizes");
            let value = ObjectValue {
                schema: Some("HR".to_owned()),
                type_name: Some("CHILD_TAB".to_owned()),
                packed_data: image,
            };
            let collection_type = ObjectType {
                schema: "HR".to_owned(),
                name: "CHILD_TAB".to_owned(),
                attributes: Vec::new(),
                collection_element: Some(CollectionElement {
                    type_name: "CHILD_T".to_owned(),
                    type_owner: Some("HR".to_owned()),
                }),
            };
            let err = decode_object(&value, &collection_type)
                .expect_err("nested collection elements are intentionally unsupported");
            assert!(
                err.to_string().contains(
                    "collection of nested object/collection elements is not decodable yet"
                ),
                "unexpected error: {err}"
            );
        }

        #[cfg(feature = "live-xe")]
        #[test]
        fn cursor_fetch_failure_leaves_connection_usable() {
            use asupersync::runtime::RuntimeBuilder;
            let Some(opts) = live_opts_from_env() else {
                eprintln!(
                    "[live-xe] SKIP cursor_fetch_failure_leaves_connection_usable: set ORACLEMCP_TEST_*"
                );
                return;
            };
            // Live test does real socket I/O, so the runtime needs a reactor (release-gre.16).
            let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
            let runtime = RuntimeBuilder::current_thread()
                .with_reactor(reactor)
                .build()
                .expect("current-thread runtime");
            runtime.block_on(async {
                let cx = asupersync::Cx::current().expect("block_on installs a current Cx");
                let mut inner = match oracledb::Connection::connect(
                    &cx,
                    to_connect_options(&opts).expect("connect options"),
                )
                .await
                {
                    Ok(conn) => conn,
                    Err(err) => {
                        eprintln!(
                            "[live-xe] SKIP cursor_fetch_failure_leaves_connection_usable: no reachable Oracle ({})",
                            sanitize_driver_error(err, &opts)
                        );
                        return;
                    }
                };
                let mut invalid_cursor = cursor(1);
                invalid_cursor.cursor_id = u32::MAX;

                let err = materialize_cursor_cell(
                    &cx,
                    &mut inner,
                    "REF CURSOR".to_owned(),
                    &invalid_cursor,
                    &opts,
                    &SerializeOptions::default(),
                    super::super::WireLimits::default(),
                    0,
                )
                .await
                .expect_err("invalid cursor id should fail");

                assert!(
                    err.to_string().contains("REF CURSOR fetch failed"),
                    "unexpected error: {err}"
                );
                let probe = inner
                    .execute_raw(&cx, "SELECT 1 AS n FROM dual", 1, &[], ExecuteOptions::default(), None)
                    .await
                    .expect("connection remains usable after cursor fetch failure");
                let n = probe.rows[0][0]
                    .as_ref()
                    .and_then(QueryValue::as_i64)
                    .expect("numeric probe cell");
                assert_eq!(n, 1);
            });
        }

        #[cfg(feature = "live-xe")]
        #[test]
        fn live_fetch_loop_is_bounded_per_batch() {
            use asupersync::runtime::RuntimeBuilder;
            let Some(opts) = live_opts_from_env() else {
                eprintln!(
                    "[live-xe] SKIP live_fetch_loop_is_bounded_per_batch: set ORACLEMCP_TEST_*"
                );
                return;
            };
            let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
            let runtime = RuntimeBuilder::current_thread()
                .with_reactor(reactor)
                .build()
                .expect("current-thread runtime");
            runtime.block_on(async {
                let cx = asupersync::Cx::current().expect("block_on installs a current Cx");
                let mut inner = match oracledb::Connection::connect(
                    &cx,
                    to_connect_options(&opts).expect("connect options"),
                )
                .await
                {
                    Ok(conn) => conn,
                    Err(err) => {
                        eprintln!(
                            "[live-xe] SKIP live_fetch_loop_is_bounded_per_batch: no reachable Oracle ({})",
                            sanitize_driver_error(err, &opts)
                        );
                        return;
                    }
                };
                let pipe = format!(
                    "ORACLEMCP_FETCH_TIMEOUT_{}_{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |duration| duration.as_nanos())
                );
                let sql = format!(
                    "SELECT CASE WHEN level = 1 THEN 0 ELSE DBMS_PIPE.RECEIVE_MESSAGE('{pipe}', 2) END AS status \
                     FROM dual CONNECT BY level <= 2"
                );
                let result = match inner
                    .execute_raw(&cx, &sql, 1, &[], ExecuteOptions::default(), None)
                    .await
                {
                    Ok(result) => result,
                    Err(err) => {
                        eprintln!(
                            "[live-xe] SKIP live_fetch_loop_is_bounded_per_batch: DBMS_PIPE unavailable or query rejected ({})",
                            sanitize_driver_error(err, &opts)
                        );
                        return;
                    }
                };
                if !result.more_rows || result.cursor_id == 0 {
                    eprintln!(
                        "[live-xe] SKIP live_fetch_loop_is_bounded_per_batch: fixture query did not produce a continuation fetch"
                    );
                    return;
                }

                let err = collect_all_rows(
                    &cx,
                    &mut inner,
                    result,
                    &opts,
                    &SerializeOptions::default(),
                    super::super::WireLimits {
                        call_timeout: Some(Duration::from_millis(10)),
                        request_deadline: None,
                        request_quota: None,
                    },
                )
                .await
                .expect_err("slow continuation fetch must time out");
                assert!(
                    err.to_string().contains("call timeout"),
                    "unexpected fetch-loop error: {err}"
                );

                let probe = inner
                    .execute_raw(
                        &cx,
                        "SELECT 1 AS n FROM dual",
                        1,
                        &[],
                        ExecuteOptions::default(),
                        None,
                    )
                    .await
                    .expect("connection remains usable after fetch timeout recovery");
                let n = probe.rows[0][0]
                    .as_ref()
                    .and_then(QueryValue::as_i64)
                    .expect("numeric probe cell");
                assert_eq!(n, 1);
            });
        }

        #[test]
        fn materializes_clob_locator_as_text() {
            let lob = lob(ORA_TYPE_NUM_CLOB, 5);
            let mut calls = Vec::new();
            let mut read_lob = |locator: &[u8], offset: u64, amount: u64| {
                assert_eq!(locator, lob.locator.as_slice());
                calls.push((offset, amount));
                Ok(LobReadData {
                    data: Some(b"hello".to_vec()),
                })
            };

            let cell = materialize_lob_cell(
                "CLOB".to_owned(),
                &lob,
                LobReadLimits {
                    max_lob_chars: 32,
                    max_blob_bytes: 1024,
                },
                &mut read_lob,
            )
            .expect("clob materialized");

            assert_eq!(cell.text(), Some("hello"));
            assert_eq!(cell.source_length, Some(5));
            assert_eq!(calls, vec![(1, 5)]);
        }

        #[test]
        fn materializes_blob_locator_as_binary() {
            let lob = lob(ORA_TYPE_NUM_BLOB, 3);
            let mut read_lob = |_locator: &[u8], offset: u64, amount: u64| {
                assert_eq!((offset, amount), (1, 3));
                Ok(LobReadData {
                    data: Some(vec![1, 2, 3]),
                })
            };

            let cell = materialize_lob_cell(
                "BLOB".to_owned(),
                &lob,
                LobReadLimits {
                    max_lob_chars: 32,
                    max_blob_bytes: 1024,
                },
                &mut read_lob,
            )
            .expect("blob materialized");

            assert_eq!(cell.bytes.as_deref(), Some([1, 2, 3].as_slice()));
            assert_eq!(cell.source_length, Some(3));
        }

        #[test]
        fn null_clob_cell_serializes_as_null() {
            let cell = OracleCell::new("CLOB", None);

            assert_eq!(
                serialize_cell(&cell, &SerializeOptions::default()),
                serde_json::Value::Null
            );
        }

        #[test]
        fn clob_locator_read_is_bounded_and_reports_full_length() {
            let lob = lob(ORA_TYPE_NUM_CLOB, 100);
            let mut read_lob = |_locator: &[u8], offset: u64, amount: u64| {
                assert_eq!((offset, amount), (1, 4));
                Ok(LobReadData {
                    data: Some(b"abcd".to_vec()),
                })
            };

            let cell = materialize_lob_cell(
                "CLOB".to_owned(),
                &lob,
                LobReadLimits {
                    max_lob_chars: 4,
                    max_blob_bytes: 1024,
                },
                &mut read_lob,
            )
            .expect("clob materialized");
            let rendered = serialize_cell(
                &cell,
                &SerializeOptions {
                    max_lob_chars: 4,
                    ..Default::default()
                },
            );

            assert_eq!(
                rendered,
                json!({ "value": "abcd", "truncated": true, "char_length": 100 })
            );
        }

        #[test]
        fn bfile_locator_read_is_bounded_when_size_is_unknown() {
            let lob = lob(ORA_TYPE_NUM_BFILE, 0);
            let mut read_lob = |_locator: &[u8], offset: u64, amount: u64| {
                assert_eq!((offset, amount), (1, 3));
                Ok(LobReadData {
                    data: Some(vec![1, 2, 3]),
                })
            };

            let cell = materialize_lob_cell(
                "BFILE".to_owned(),
                &lob,
                LobReadLimits {
                    max_lob_chars: 32,
                    max_blob_bytes: 2,
                },
                &mut read_lob,
            )
            .expect("bfile materialized");
            let rendered = serialize_cell(
                &cell,
                &SerializeOptions {
                    max_blob_bytes: 2,
                    ..Default::default()
                },
            );

            assert_eq!(rendered["byte_length"], json!(3));
            assert_eq!(rendered["truncated"], json!(true));
        }

        #[test]
        fn locator_read_failure_is_structured() {
            let lob = lob(ORA_TYPE_NUM_CLOB, 8);
            let mut read_lob = |_locator: &[u8], _offset: u64, _amount: u64| {
                Err(DbError::Query("read failed".to_owned()))
            };

            let err = materialize_lob_cell(
                "CLOB".to_owned(),
                &lob,
                LobReadLimits {
                    max_lob_chars: 4,
                    max_blob_bytes: 1024,
                },
                &mut read_lob,
            )
            .expect_err("read failure should propagate");

            assert!(err.to_string().contains("read failed"));
        }

        #[test]
        fn unsupported_lob_subtype_is_explicit_error() {
            let lob = lob(ORA_TYPE_NUM_RAW, 8);
            let mut attempted_read = false;
            let mut read_lob = |_locator: &[u8], _offset: u64, _amount: u64| {
                attempted_read = true;
                Err(DbError::Query(
                    "unsupported subtype test closure invoked".to_owned(),
                ))
            };

            let err = materialize_lob_cell(
                "RAW".to_owned(),
                &lob,
                LobReadLimits {
                    max_lob_chars: 4,
                    max_blob_bytes: 1024,
                },
                &mut read_lob,
            )
            .expect_err("unsupported subtype");

            assert!(
                err.to_string()
                    .contains("unsupported LOB locator type ORA_TYPE_23")
            );
            assert!(
                !attempted_read,
                "unsupported LOB subtype must fail before reading locator data"
            );
        }

        #[test]
        fn timestamp_tz_formatter_preserves_numeric_offset() {
            assert_eq!(
                super::format_timestamp_tz(2026, 6, 29, 12, 34, 56, 987_654_321, -330),
                "2026-06-29 12:34:56.987654321 -05:30"
            );
            assert_eq!(
                super::format_timestamp_tz(2026, 6, 29, 12, 34, 56, 0, 345),
                "2026-06-29 12:34:56 +05:45"
            );
        }
    }

    fn format_datetime(
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        nanosecond: u32,
    ) -> String {
        if nanosecond == 0 {
            format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
        } else {
            format!(
                "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{nanosecond:09}"
            )
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn format_timestamp_tz(
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        nanosecond: u32,
        offset_minutes: i32,
    ) -> String {
        let sign = if offset_minutes < 0 { '-' } else { '+' };
        let offset_abs = i64::from(offset_minutes).abs();
        let offset_hours = offset_abs / 60;
        let offset_mins = offset_abs % 60;
        format!(
            "{} {sign}{offset_hours:02}:{offset_mins:02}",
            format_datetime(year, month, day, hour, minute, second, nanosecond)
        )
    }

    fn oracle_type_name(meta: &ColumnMetadata) -> String {
        let base = match meta.ora_type_num() {
            ORA_TYPE_NUM_VARCHAR => "VARCHAR2",
            ORA_TYPE_NUM_NUMBER => "NUMBER",
            ORA_TYPE_NUM_BINARY_INTEGER => "BINARY_INTEGER",
            ORA_TYPE_NUM_LONG => "LONG",
            ORA_TYPE_NUM_ROWID => "ROWID",
            ORA_TYPE_NUM_DATE => "DATE",
            ORA_TYPE_NUM_RAW => "RAW",
            ORA_TYPE_NUM_BINARY_FLOAT => "BINARY_FLOAT",
            ORA_TYPE_NUM_BINARY_DOUBLE => "BINARY_DOUBLE",
            ORA_TYPE_NUM_BOOLEAN => "BOOLEAN",
            ORA_TYPE_NUM_CURSOR => "CURSOR",
            ORA_TYPE_NUM_LONG_RAW => "LONG RAW",
            ORA_TYPE_NUM_CHAR => "CHAR",
            ORA_TYPE_NUM_CLOB => "CLOB",
            ORA_TYPE_NUM_BLOB => "BLOB",
            ORA_TYPE_NUM_BFILE => "BFILE",
            ORA_TYPE_NUM_OBJECT => "OBJECT",
            ORA_TYPE_NUM_JSON => "JSON",
            ORA_TYPE_NUM_TIMESTAMP => "TIMESTAMP",
            ORA_TYPE_NUM_TIMESTAMP_TZ => "TIMESTAMP WITH TIME ZONE",
            ORA_TYPE_NUM_INTERVAL_DS => "INTERVAL DAY TO SECOND",
            ORA_TYPE_NUM_INTERVAL_YM => "INTERVAL YEAR TO MONTH",
            ORA_TYPE_NUM_UROWID => "UROWID",
            ORA_TYPE_NUM_TIMESTAMP_LTZ => "TIMESTAMP WITH LOCAL TIME ZONE",
            ORA_TYPE_NUM_VECTOR => "VECTOR",
            other => return format!("ORA_TYPE_{other}"),
        };
        if meta.is_json() && base != "JSON" {
            "JSON".to_owned()
        } else {
            base.to_owned()
        }
    }

    const REDACTED: &str = "<redacted>";

    /// Minimum length for the case-insensitive, token-boundary identifier pass.
    /// Anything shorter is redacted only by exact (case-sensitive) substring so a
    /// 1-2 char token can never scrub swathes of unrelated prose.
    const CI_MIN_IDENTIFIER_LEN: usize = 3;

    /// An ASCII byte that can appear inside an Oracle/SQL identifier or a
    /// hostname label. Used as the token boundary for [`redact_identifier_ci`]:
    /// a match only counts when neither neighbour is one of these, so redacting
    /// `SYS` never touches `SYSDATE` and redacting `1521` never touches `215210`.
    fn is_identifier_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b == b'#'
    }

    /// Case-insensitively remove every **token-boundary** occurrence of `needle`
    /// from `haystack`. Oracle upper-cases unquoted identifiers, so a lower-case
    /// schema/service/host in the profile re-appears upper-cased in an `ORA-`
    /// server message; matching ASCII-case-insensitively closes that leak. The
    /// boundary check keeps the pass from over-redacting unrelated text.
    fn redact_identifier_ci(haystack: &str, needle: &str) -> String {
        // Too short to fold casing safely: fall back to an exact (casing-precise)
        // substring pass, which cannot over-match on a short common word.
        if needle.len() < CI_MIN_IDENTIFIER_LEN {
            return haystack.replace(needle, REDACTED);
        }
        // `to_ascii_lowercase` preserves byte length (only ASCII A-Z change), so
        // byte indices computed on the lower-cased copies align with `haystack`.
        let hay_lower = haystack.to_ascii_lowercase();
        let needle_lower = needle.to_ascii_lowercase();
        let hay_bytes = hay_lower.as_bytes();
        let mut out = String::with_capacity(haystack.len());
        let mut last = 0usize;
        let mut search = 0usize;
        while let Some(rel) = hay_lower[search..].find(&needle_lower) {
            let start = search + rel;
            let end = start + needle_lower.len();
            let before_boundary = start == 0 || !is_identifier_byte(hay_bytes[start - 1]);
            let after_boundary = end == hay_bytes.len() || !is_identifier_byte(hay_bytes[end]);
            if before_boundary && after_boundary {
                out.push_str(&haystack[last..start]);
                out.push_str(REDACTED);
                last = end;
                search = end;
            } else {
                // Overlapping/embedded occurrence: advance one byte and retry.
                search = start + 1;
            }
        }
        out.push_str(&haystack[last..]);
        out
    }

    /// Redact every operator-facing rendering of a driver error.
    ///
    /// Two passes, each fail-closed:
    ///  1. **Exact secrets** — high-entropy or free-form material (passwords,
    ///     tokens, wallet paths/passwords, the full connect string, cert DN,
    ///     app-context + session-identity values) removed verbatim. Longest
    ///     first, so a superstring is scrubbed before any of its substrings.
    ///  2. **Topology identifiers** — the host, port, service name (decomposed
    ///     from the connect string) and the username/schema, removed
    ///     case-insensitively on token boundaries. This closes the two leaks the
    ///     verbatim pass alone misses: a *decomposed* connect string (an `ORA-`
    ///     message that names only the host, or only the service) and an
    ///     Oracle-**upper-cased** identifier that no longer byte-matches the
    ///     lower-case profile value.
    pub(super) fn sanitize_driver_error(err: impl Display, opts: &OracleConnectOptions) -> String {
        let mut message = err.to_string();

        // --- Pass 1: exact, case-sensitive secrets -------------------------
        let mut exact_secrets = vec![opts.connect_string.clone()];
        if let Some(password) = &opts.password {
            exact_secrets.push(password.clone());
        }
        if let Some(token) = &opts.iam_token {
            exact_secrets.push(token.clone());
        }
        if let Some(wallet) = &opts.wallet_location {
            exact_secrets.push(wallet.display().to_string());
        }
        if let Some(wallet_password) = &opts.wallet_password {
            exact_secrets.push(wallet_password.clone());
        }
        if let Some(dn) = &opts.ssl_server_cert_dn {
            exact_secrets.push(dn.clone());
        }
        for (namespace, key, value) in &opts.app_context {
            exact_secrets.push(namespace.clone());
            exact_secrets.push(key.clone());
            exact_secrets.push(value.clone());
        }
        exact_secrets.extend(
            opts.auth_adapter
                .sensitive_values()
                .into_iter()
                .map(ToOwned::to_owned),
        );
        if let Some(identity) = &opts.session_identity {
            for value in [
                &identity.edition,
                &identity.program,
                &identity.machine,
                &identity.os_user,
                &identity.terminal,
                &identity.module,
                &identity.action,
                &identity.client_identifier,
                &identity.client_info,
                &identity.driver_name,
            ]
            .into_iter()
            .flatten()
            {
                exact_secrets.push(value.clone());
            }
        }
        exact_secrets.sort_by_key(|value| std::cmp::Reverse(value.len()));
        for secret in exact_secrets.iter().filter(|value| !value.is_empty()) {
            message = message.replace(secret.as_str(), REDACTED);
        }

        // --- Pass 2: decomposed / upper-cased topology identifiers ---------
        let mut identifiers: Vec<String> = Vec::new();
        if let Some(username) = &opts.username {
            identifiers.push(username.clone());
        }
        let hints = crate::tns::extract_hints(&opts.connect_string);
        if let Some(host) = hints.host {
            identifiers.push(host);
        }
        if let Some(service) = hints.service_name {
            identifiers.push(service);
        }
        if let Some(port) = hints.port {
            identifiers.push(port.to_string());
        }
        identifiers.sort_by_key(|value| std::cmp::Reverse(value.len()));
        for identifier in identifiers.iter().filter(|value| !value.is_empty()) {
            message = redact_identifier_ci(&message, identifier);
        }
        message
    }

    /// Convert a driver execution error without erasing its connection-lost
    /// disposition. The driver's public predicate covers both its curated ORA
    /// set and raw I/O / `ConnectionClosed` failures, which cannot be recovered
    /// from a sanitized display string alone.
    pub(super) fn driver_query_error(
        err: oracledb::Error,
        opts: &OracleConnectOptions,
        context: Option<&str>,
    ) -> DbError {
        // TTC message type 129 is a transient protocol desynchronization in
        // the metadata/direct-path response family. The pinned driver raises
        // it as `ProtocolError::UnknownMessageType` but deliberately reports
        // that variant as reusable; the server must discard this session so
        // the pool can perform its single fresh-connection retry.
        let lost = err.is_connection_lost() || is_transient_ttc_129(&err);
        let detail = sanitize_driver_error(err, opts);
        let message = match context {
            Some(context) => format!("{context}: {detail}"),
            None => detail,
        };
        if lost {
            DbError::ConnectionLost(message)
        } else {
            DbError::Query(message)
        }
    }

    fn is_transient_ttc_129(error: &oracledb::Error) -> bool {
        matches!(
            error,
            oracledb::Error::Protocol(oracledb::protocol::ProtocolError::UnknownMessageType {
                message_type: 129,
                ..
            })
        )
    }

    /// Execute-path counterpart to [`driver_query_error`]. Non-lost errors
    /// retain the execute context; a structurally lost connection remains a
    /// `ConnectionLost` so pool/lease cleanup cannot mistake it for ordinary
    /// statement failure.
    pub(super) fn driver_execute_error(
        err: oracledb::Error,
        opts: &OracleConnectOptions,
        context: &str,
    ) -> DbError {
        match driver_query_error(err, opts, Some(context)) {
            DbError::Query(message) => DbError::Execute(message),
            other => other,
        }
    }

    /// Extract the `ERR=` code from a TNS listener refuse payload, e.g.
    /// `(DESCRIPTION=(TMP=)(VSNNUM=...)(ERR=12514)(ERROR_STACK=...))`.
    pub(super) fn parse_listener_refuse_code(payload: &str) -> Option<u32> {
        let start = payload.find("(ERR=")? + "(ERR=".len();
        let digits: String = payload[start..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse().ok()
    }

    /// Classify a driver connect/handshake failure into the driver-agnostic
    /// [`ConnectFailureKind`]. This function is the **only** place that reads
    /// `oracledb::Error` connect variants — everything downstream (envelope
    /// rendering, doctor guidance) works from the structured kind. `None`
    /// means "no handshake-specific classification" and the caller keeps the
    /// plain `DbError::Connect` path (wallet errors deliberately stay there:
    /// their existing diagnostics are already precise).
    pub(super) fn classify_connect_failure(err: &oracledb::Error) -> Option<ConnectFailureKind> {
        match err {
            oracledb::Error::UnexpectedPacket(packet_type) => {
                Some(ConnectFailureKind::UnexpectedTnsPacket {
                    packet_type: *packet_type,
                })
            }
            oracledb::Error::ConnectResendLoop(rounds) => {
                Some(ConnectFailureKind::ConnectResendLoop { rounds: *rounds })
            }
            oracledb::Error::FastAuthRequired => Some(ConnectFailureKind::FastAuthNotAdvertised),
            oracledb::Error::RedirectUnsupported => {
                Some(ConnectFailureKind::ListenerRedirectUnsupported)
            }
            oracledb::Error::ListenerRefused(payload) => {
                Some(ConnectFailureKind::ListenerRefused {
                    err_code: parse_listener_refuse_code(payload),
                })
            }
            oracledb::Error::Protocol(protocol) => match protocol {
                oracledb::protocol::ProtocolError::UnsupportedVersion {
                    version,
                    minimum: _,
                } => Some(ConnectFailureKind::ServerGenerationUnsupported {
                    tns_version: Some(*version),
                }),
                oracledb::protocol::ProtocolError::UnsupportedFeature(feature) => {
                    Some(ConnectFailureKind::UnsupportedWireFeature {
                        feature: (*feature).to_owned(),
                    })
                }
                // Any other protocol-layer failure during connect is, by
                // construction, a handshake-phase framing/decode problem —
                // name the phase honestly instead of leaking a bare driver
                // string (the field bug: "unknown TTC message type 11" was a
                // network-layer TNS packet misread as application-layer TTC).
                oracledb::protocol::ProtocolError::TruncatedHeader { .. }
                | oracledb::protocol::ProtocolError::InvalidPacketLength { .. }
                | oracledb::protocol::ProtocolError::IncompletePacket { .. }
                | oracledb::protocol::ProtocolError::PacketTooLarge { .. }
                | oracledb::protocol::ProtocolError::UnknownMessageType { .. }
                | oracledb::protocol::ProtocolError::TtcDecode(_)
                | oracledb::protocol::ProtocolError::InvalidServerResponse => {
                    Some(ConnectFailureKind::HandshakeProtocol)
                }
                _ => None,
            },
            _ => None,
        }
    }

    /// Map a driver connect failure to a [`DbError`]: structured
    /// [`DbError::ConnectHandshake`] when the failure classifies, the plain
    /// sanitized [`DbError::Connect`] otherwise (both fail closed; the
    /// envelope layer guarantees `next_steps` either way).
    pub(super) fn connect_error_to_db_error(
        err: &oracledb::Error,
        opts: &OracleConnectOptions,
    ) -> DbError {
        let message = sanitize_driver_error(err, opts);
        match classify_connect_failure(err) {
            Some(kind) => DbError::ConnectHandshake { kind, message },
            None => DbError::Connect(message),
        }
    }

    #[async_trait::async_trait(?Send)]
    impl super::OracleConnection for RustOracleConnection {
        fn backend(&self) -> crate::types::OracleBackend {
            crate::types::OracleBackend::RustOracle
        }

        async fn close(&self, cx: &Cx) -> Result<(), DbError> {
            // Logical logoff is terminal cleanup. Mask a cancelled request so
            // the driver's consuming close path still gets its bounded chance
            // to roll back, send LOGOFF, and emit TLS close_notify.
            try_commit_section(cx, super::CLEANUP_MASKED_POLLS, async {
                let connection = {
                    let mut slot = self.inner.lock(cx).await.map_err(|err| {
                        DbError::Internal(format!("thin connection lock failed: {err}"))
                    })?;
                    if let Some(reason) = slot.quarantine_reason.as_deref() {
                        return Err(DbError::Quarantined {
                            outcome: crate::error::QuarantineOutcome::UnknownDiscarded,
                            message: reason.to_owned(),
                        });
                    }
                    slot.connection.take().ok_or_else(|| {
                        DbError::Internal(
                            "thin connection is unavailable for logical close".to_owned(),
                        )
                    })?
                };

                let result = connection
                    .close(cx)
                    .await
                    .map_err(|err| driver_query_error(err, &self.opts, None));

                let mut slot = self.inner.lock(cx).await.map_err(|err| {
                    DbError::Internal(format!("thin connection lock failed: {err}"))
                })?;
                match result {
                    Ok(()) => {
                        slot.quarantine_reason = Some(
                            "thin connection was closed by explicit logical logoff".to_owned(),
                        );
                        Ok(())
                    }
                    Err(error) => {
                        slot.quarantine_reason = Some(format!(
                            "logical close consumed the thin connection after an error: {error}"
                        ));
                        Err(error)
                    }
                }
            })
            .await
        }

        async fn ping(&self, cx: &Cx) -> Result<(), DbError> {
            super::db_checkpoint(cx, "oracle_db.ping.before")?;
            let limits = self.wire_limits()?;
            let mut inner = self.lock_inner(cx).await?;
            let timeout = limits.effective_timeout_ms(cx, "oracle_db.ping")?;
            let result = match timeout {
                Some(timeout) => inner.ping_with_timeout(cx, timeout).await,
                None => inner.ping(cx).await,
            }
            .map_err(|err| driver_query_error(err, &self.opts, None));
            drop(inner);
            super::db_checkpoint(cx, "oracle_db.ping.after")?;
            result
        }

        async fn describe(&self, cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            super::db_checkpoint(cx, "oracle_db.describe.before")?;
            let mut info = OracleConnectionInfo {
                backend: Some(crate::types::OracleBackend::RustOracle),
                connection_strategy: Some("single_session".to_owned()),
                ..Default::default()
            };
            if let Some(r) = self
                .describe_first_row(
                    cx,
                    "SELECT version_full FROM product_component_version WHERE rownum = 1",
                )
                .await?
            {
                info.server_version = r.text("VERSION_FULL").map(str::to_owned);
            }
            if let Some(r) = self
                .describe_first_row(
                    cx,
                    "SELECT database_role, open_mode, db_unique_name FROM v$database",
                )
                .await?
            {
                info.database_role = r.text("DATABASE_ROLE").map(str::to_owned);
                info.open_mode = r.text("OPEN_MODE").map(str::to_owned);
                info.db_unique_name = r.text("DB_UNIQUE_NAME").map(str::to_owned);
            }
            if let Some(r) = self
                .describe_first_row(cx, "SELECT instance_name FROM v$instance")
                .await?
            {
                info.instance_name = r.text("INSTANCE_NAME").map(str::to_owned);
            }
            if let Some(r) = self
                .describe_first_row(
                    cx,
                    "SELECT \
                    SYS_CONTEXT('USERENV','CURRENT_SCHEMA') AS current_schema, \
                    SYS_CONTEXT('USERENV','CURRENT_EDITION_NAME') AS current_edition, \
                    SYS_CONTEXT('USERENV','SESSION_USER') AS session_user, \
                    SYS_CONTEXT('USERENV','CURRENT_USER') AS current_user, \
                    SYS_CONTEXT('USERENV','PROXY_USER') AS proxy_user, \
                    SYS_CONTEXT('USERENV','SID') AS sid, \
                    SYS_CONTEXT('USERENV','SERVICE_NAME') AS service_name, \
                    SYS_CONTEXT('USERENV','MODULE') AS module, \
                    SYS_CONTEXT('USERENV','ACTION') AS session_action, \
                    SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER') AS client_identifier, \
                    SYS_CONTEXT('USERENV','CLIENT_INFO') AS client_info, \
                    SYS_CONTEXT('USERENV','OS_USER') AS os_user, \
                    SYS_CONTEXT('USERENV','HOST') AS host, \
                    SYS_CONTEXT('USERENV','TERMINAL') AS terminal \
                 FROM dual",
                )
                .await?
            {
                info.current_schema = r.text("CURRENT_SCHEMA").map(str::to_owned);
                info.current_edition = r.text("CURRENT_EDITION").map(str::to_owned);
                info.session_user = r.text("SESSION_USER").map(str::to_owned);
                info.current_user = r.text("CURRENT_USER").map(str::to_owned);
                info.proxy_user = r.text("PROXY_USER").map(str::to_owned);
                info.sid = r.text("SID").map(str::to_owned);
                info.service_name = r.text("SERVICE_NAME").map(str::to_owned);
                info.module = r.text("MODULE").map(str::to_owned);
                info.action = r.text("SESSION_ACTION").map(str::to_owned);
                info.client_identifier = r.text("CLIENT_IDENTIFIER").map(str::to_owned);
                info.client_info = r.text("CLIENT_INFO").map(str::to_owned);
                info.os_user = r.text("OS_USER").map(str::to_owned);
                info.host = r.text("HOST").map(str::to_owned);
                info.terminal = r.text("TERMINAL").map(str::to_owned);
            }
            if let Some(r) = self
                .describe_first_row(
                    cx,
                    "SELECT sid, serial# AS serial_number, service_name, osuser, machine, terminal, program \
                 FROM v$session \
                 WHERE sid = TO_NUMBER(SYS_CONTEXT('USERENV','SID')) \
                 FETCH FIRST 1 ROWS ONLY",
                )
                .await?
            {
                info.sid = r.text("SID").map(str::to_owned).or_else(|| info.sid.take());
                info.serial_number = r.text("SERIAL_NUMBER").map(str::to_owned);
                info.service_name = r
                    .text("SERVICE_NAME")
                    .map(str::to_owned)
                    .or_else(|| info.service_name.take());
                info.os_user = r
                    .text("OSUSER")
                    .map(str::to_owned)
                    .or_else(|| info.os_user.take());
                info.machine = r.text("MACHINE").map(str::to_owned);
                info.terminal = r
                    .text("TERMINAL")
                    .map(str::to_owned)
                    .or_else(|| info.terminal.take());
                info.program = r.text("PROGRAM").map(str::to_owned);
            }
            if let Some(r) = self
                .describe_first_row(
                    cx,
                    "SELECT client_driver \
                 FROM v$session_connect_info \
                 WHERE sid = TO_NUMBER(SYS_CONTEXT('USERENV','SID')) \
                   AND client_driver IS NOT NULL \
                 FETCH FIRST 1 ROWS ONLY",
                )
                .await?
            {
                info.client_driver = r.text("CLIENT_DRIVER").map(str::to_owned);
            }
            // K2: additive, observational server-capability probe. The
            // fail-closed guard is UNTOUCHED — this only reports what the thin
            // driver negotiated, best-effort version-derived inferences, and (if
            // the account has the privilege) edition/partitioning.
            //
            // Driver-negotiated facts come straight from the thin driver's own
            // synchronous accessors on the wrapped `oracledb::Connection` — the
            // ONE seam allowed to name that type. The short lock scope is dropped
            // before the dictionary round-trip below (which re-locks `inner`), so
            // it never deadlocks. If the lock cannot be taken the whole block is
            // simply omitted (`None`) rather than fabricated.
            let driver_facts = match self.lock_inner(cx).await {
                Ok(inner) => Some((
                    inner.server_version_tuple(),
                    inner.sdu(),
                    inner.supports_pipelining(),
                    inner.supports_oob(),
                    inner.protocol_version(),
                    inner.supports_fast_auth(),
                )),
                Err(_) => None,
            };
            if let Some((
                version_tuple,
                sdu,
                supports_pipelining,
                supports_oob,
                protocol_version,
                supports_fast_auth,
            )) = driver_facts
            {
                // ONE privilege-degradable dictionary query for edition +
                // partitioning. `product_component_version` is broadly readable;
                // `v$option` needs a catalog grant, so a low-privilege account
                // fails the whole statement. Ordinary query/privilege errors
                // degrade both fields to `None`; cancellation or connection
                // uncertainty still fails `describe` so the owner can discard
                // the session instead of reusing an indeterminate connection.
                let (edition, partitioning) = match self
                    .describe_first_row(
                        cx,
                        // `product` is the edition/product descriptor, e.g.
                        // "Oracle Database 21c Enterprise Edition" or the newer
                        // "Oracle AI Database 26ai Free" — match "%DATABASE%"
                        // (not "Oracle Database%") so both namings are captured.
                        "SELECT \
                         (SELECT product FROM product_component_version \
                            WHERE UPPER(product) LIKE '%DATABASE%' AND rownum = 1) AS edition, \
                         (SELECT value FROM v$option \
                            WHERE parameter = 'Partitioning') AS partitioning \
                         FROM dual",
                    )
                    .await?
                {
                    Some(r) => (
                        r.text("EDITION").map(str::to_owned),
                        r.text("PARTITIONING")
                            .map(|value| value.eq_ignore_ascii_case("TRUE")),
                    ),
                    None => (None, None),
                };
                let native_redaction =
                    crate::native_redaction::probe_native_redaction(cx, self).await?;
                info.server_features = Some(
                    crate::server_features::ServerFeatures::from_probe(
                        version_tuple,
                        sdu,
                        supports_pipelining,
                        supports_oob,
                        edition,
                        partitioning,
                        Some(protocol_version),
                        Some(supports_fast_auth),
                    )
                    .with_native_redaction(native_redaction),
                );
            }
            super::db_checkpoint(cx, "oracle_db.describe.after")?;
            Ok(info.with_read_only_status())
        }

        async fn query_rows(
            &self,
            cx: &Cx,
            sql: &str,
            binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.query_rows_with_serialize_options(cx, sql, binds, &SerializeOptions::default())
                .await
        }

        async fn query_rows_with_serialize_options(
            &self,
            cx: &Cx,
            sql: &str,
            binds: &[OracleBind],
            serialize_opts: &SerializeOptions,
        ) -> Result<Vec<OracleRow>, DbError> {
            super::db_checkpoint(cx, "oracle_db.query_rows.before")?;
            let binds: Vec<BindValue> = binds.iter().map(to_bind).collect();
            let limits = self.wire_limits()?;
            let mut inner = self.lock_inner(cx).await?;
            let result = execute_with_timeout(
                cx,
                &mut inner,
                sql,
                prefetch_rows_for_statement(sql),
                &binds,
                limits.clone(),
                &self.opts,
                "query",
            )
            .await?;
            let rows = collect_all_rows(cx, &mut inner, result, &self.opts, serialize_opts, limits)
                .await?;
            drop(inner);
            super::db_checkpoint(cx, "oracle_db.query_rows.after")?;
            Ok(rows)
        }

        async fn query_bounded_page(
            &self,
            cx: &Cx,
            sql: &str,
            binds: &[OracleBind],
            caps: crate::query::QueryCaps,
            offset: usize,
            serialize_opts: &SerializeOptions,
        ) -> Result<Option<crate::query::QueryResponse>, DbError> {
            super::db_checkpoint(cx, "oracle_db.query_bounded_page.before")?;
            let binds: Vec<BindValue> = binds.iter().map(to_bind).collect();
            let limits = self.wire_limits()?;
            let mut inner = self.lock_inner(cx).await?;
            let result = execute_with_timeout(
                cx,
                &mut inner,
                sql,
                BOUNDED_PAGE_FETCH_ROWS,
                &binds,
                limits.clone(),
                &self.opts,
                "bounded query",
            )
            .await?;
            let page = collect_bounded_query_page(
                cx,
                &mut inner,
                result,
                &self.opts,
                serialize_opts,
                limits,
                caps,
                offset,
            )
            .await?;
            drop(inner);
            super::db_checkpoint(cx, "oracle_db.query_bounded_page.after")?;
            Ok(Some(page))
        }

        async fn query_row_stream(
            &self,
            cx: &Cx,
            sql: &str,
            binds: &[OracleBind],
            arraysize: usize,
            serialize_opts: &SerializeOptions,
        ) -> Result<QueryRowStreamStart, DbError> {
            super::db_checkpoint(cx, "oracle_db.query_row_stream.before")?;
            let driver_binds: Vec<BindValue> = binds.iter().map(to_bind).collect();
            let arraysize = arraysize.clamp(1, u32::MAX as usize) as u32;
            let arraysize = NonZeroU32::new(arraysize).expect("arraysize clamped to non-zero");
            let limits = self.wire_limits()?;
            let timeout_ms = limits.effective_timeout_ms(cx, "oracle_db.query_row_stream.start")?;
            let connection = self.take_connection(cx).await?;
            let mut query = oracledb::Query::new(sql)
                .bind(&driver_binds)
                .arraysize(arraysize)
                .prefetch(arraysize.get());
            if let Some(timeout_ms) = timeout_ms {
                query = query.timeout(Duration::from_millis(u64::from(timeout_ms)));
            }
            let stream = match connection.into_row_stream(cx, query).await {
                Ok(stream) => stream,
                Err(err) => {
                    return Err(super::quarantine_connection_slot(
                        &self.inner,
                        cx,
                        format!(
                            "owned row stream failed before the connection could be recovered: {}",
                            sanitize_driver_error(err, &self.opts)
                        ),
                    )
                    .await);
                }
            };
            let metadata = stream.columns().to_vec();
            if let Some(reason) = row_stream_chunked_fallback_reason(&metadata) {
                let connection = match stream.into_connection().await {
                    Ok(connection) => connection,
                    Err(err) => {
                        return Err(super::quarantine_connection_slot(
                            &self.inner,
                            cx,
                            format!(
                                "owned row stream could not recover for chunked fallback: {}",
                                sanitize_driver_error(err, &self.opts)
                            ),
                        )
                        .await);
                    }
                };
                self.replace_connection(cx, connection).await?;
                super::db_checkpoint(cx, "oracle_db.query_row_stream.fallback")?;
                return Ok(QueryRowStreamStart::Fallback { reason });
            }
            let columns = metadata
                .iter()
                .map(|column| column.name().to_owned())
                .collect();
            Ok(QueryRowStreamStart::Stream(QueryRowStream::new(
                RustOracleRowStream {
                    inner: Arc::clone(&self.inner),
                    opts: self.opts.clone(),
                    stream: Some(stream),
                    metadata,
                    columns,
                    serialize_opts: serialize_opts.clone(),
                    limits,
                },
            )))
        }

        async fn query_rows_named(
            &self,
            cx: &Cx,
            sql: &str,
            binds: &[(String, OracleBind)],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.query_rows_named_with_serialize_options(
                cx,
                sql,
                binds,
                &SerializeOptions::default(),
            )
            .await
        }

        async fn query_rows_named_with_serialize_options(
            &self,
            cx: &Cx,
            sql: &str,
            binds: &[(String, OracleBind)],
            serialize_opts: &SerializeOptions,
        ) -> Result<Vec<OracleRow>, DbError> {
            super::db_checkpoint(cx, "oracle_db.query_rows_named.before")?;
            let binds: Vec<(String, BindValue)> = binds
                .iter()
                .map(|(name, bind)| (name.clone(), to_bind(bind)))
                .collect();
            let ordered_binds = order_named_binds_for_driver(sql, binds)?;
            let limits = self.wire_limits()?;
            let mut inner = self.lock_inner(cx).await?;
            let result = execute_with_timeout(
                cx,
                &mut inner,
                sql,
                prefetch_rows_for_statement(sql),
                &ordered_binds,
                limits.clone(),
                &self.opts,
                "query named",
            )
            .await?;
            let rows = collect_all_rows(cx, &mut inner, result, &self.opts, serialize_opts, limits)
                .await?;
            drop(inner);
            super::db_checkpoint(cx, "oracle_db.query_rows_named.after")?;
            Ok(rows)
        }

        async fn query_bounded_page_named(
            &self,
            cx: &Cx,
            sql: &str,
            binds: &[(String, OracleBind)],
            caps: crate::query::QueryCaps,
            offset: usize,
            serialize_opts: &SerializeOptions,
        ) -> Result<Option<crate::query::QueryResponse>, DbError> {
            super::db_checkpoint(cx, "oracle_db.query_bounded_page_named.before")?;
            let binds: Vec<(String, BindValue)> = binds
                .iter()
                .map(|(name, bind)| (name.clone(), to_bind(bind)))
                .collect();
            let ordered_binds = order_named_binds_for_driver(sql, binds)?;
            let limits = self.wire_limits()?;
            let mut inner = self.lock_inner(cx).await?;
            let result = execute_with_timeout(
                cx,
                &mut inner,
                sql,
                BOUNDED_PAGE_FETCH_ROWS,
                &ordered_binds,
                limits.clone(),
                &self.opts,
                "bounded named query",
            )
            .await?;
            let page = collect_bounded_query_page(
                cx,
                &mut inner,
                result,
                &self.opts,
                serialize_opts,
                limits,
                caps,
                offset,
            )
            .await?;
            drop(inner);
            super::db_checkpoint(cx, "oracle_db.query_bounded_page_named.after")?;
            Ok(Some(page))
        }

        async fn execute(&self, cx: &Cx, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError> {
            super::db_checkpoint(cx, "oracle_db.execute.before")?;
            let binds: Vec<BindValue> = binds.iter().map(to_bind).collect();
            let limits = self.wire_limits()?;
            let mut inner = self.lock_inner(cx).await?;
            let result = execute_with_timeout(
                cx, &mut inner, sql, 0, &binds, limits, &self.opts, "execute",
            )
            .await
            .map_err(|err| match err {
                DbError::Query(msg) => DbError::Execute(msg),
                other => other,
            })?;
            drop(inner);
            super::db_checkpoint(cx, "oracle_db.execute.after")?;
            Ok(result.row_count)
        }

        async fn register_cqn_query(
            &self,
            cx: &Cx,
            sql: &str,
            binds: &[OracleBind],
        ) -> Result<super::CqnQueryRegistration, DbError> {
            super::db_checkpoint(cx, "oracle_db.cqn_register_query.before")?;
            let binds: Vec<BindValue> = binds.iter().map(to_bind).collect();
            let limits = self.wire_limits()?;
            // `subscribe_register` / `register_query` receive the request Cx
            // directly. Sampling the effective limit here preserves the shared
            // quota/deadline accounting even though this driver API does not
            // expose a separate per-call timeout argument.
            let _driver_call_timeout =
                limits.effective_timeout_ms(cx, "oracle_db.cqn_register_query.subscribe")?;
            let mut inner = self.lock_inner(cx).await?;
            let subscription = inner
                .subscribe_register(
                    cx,
                    TNS_SUBSCR_NAMESPACE_DBCHANGE,
                    None,
                    SUBSCR_QOS_QUERY,
                    0,
                    super::CQN_SUBSCRIPTION_TIMEOUT_SECONDS,
                    0,
                    0,
                    0,
                )
                .await
                .map_err(|err| driver_query_error(err, &self.opts, None))?;
            let Some(client_id) = subscription.client_id else {
                // QUERY CQN must return the EMON callback identity; without it
                // the adapter cannot open or later cleanly tear down the
                // second connection.
                return Err(DbError::UnsupportedFeature(
                    "CQN registration did not return the callback identity required for safe cleanup"
                        .to_owned(),
                ));
            };
            let registration_id = subscription.registration_id;
            let registered = inner
                .register_query(
                    cx,
                    oracledb::Registration::new(sql, registration_id).bind(binds.as_slice()),
                )
                .await
                .map_err(|err| driver_query_error(err, &self.opts, None));
            let query_id = match registered {
                Ok(registered) => registered.query_id().ok_or_else(|| {
                    DbError::UnsupportedFeature(
                        "CQN QUERY registration did not return a query identity".to_owned(),
                    )
                }),
                Err(error) => Err(error),
            };
            let query_id = match query_id {
                Ok(query_id) => query_id,
                Err(error) => {
                    let cleanup = inner
                        .subscribe_unregister(
                            cx,
                            registration_id,
                            &client_id,
                            TNS_SUBSCR_NAMESPACE_DBCHANGE,
                            None,
                            SUBSCR_QOS_QUERY,
                            0,
                            super::CQN_SUBSCRIPTION_TIMEOUT_SECONDS,
                            0,
                            0,
                            0,
                        )
                        .await;
                    if let Err(cleanup_error) = cleanup {
                        tracing::warn!(
                            error = %sanitize_driver_error(cleanup_error, &self.opts),
                            "CQN query registration failed and cleanup could not be confirmed"
                        );
                    }
                    return Err(error);
                }
            };
            drop(inner);
            super::db_checkpoint(cx, "oracle_db.cqn_register_query.after")?;
            self.cqn_client_ids
                .lock()
                .map_err(|err| DbError::Internal(format!("CQN registration lock poisoned: {err}")))?
                .insert(registration_id, client_id);
            Ok(super::CqnQueryRegistration::new(registration_id, query_id))
        }

        async fn unregister_cqn_query(
            &self,
            cx: &Cx,
            registration: super::CqnQueryRegistration,
        ) -> Result<(), DbError> {
            super::db_checkpoint(cx, "oracle_db.cqn_unregister_query.before")?;
            let registration_id = registration.registration_id();
            let client_id = self
                .cqn_client_ids
                .lock()
                .map_err(|err| DbError::Internal(format!("CQN registration lock poisoned: {err}")))?
                .get(&registration_id)
                .cloned()
                .ok_or_else(|| {
                    DbError::UnsupportedFeature(
                        "CQN registration has no driver-owned callback identity for cleanup"
                            .to_owned(),
                    )
                })?;
            let limits = self.wire_limits()?;
            let _driver_call_timeout =
                limits.effective_timeout_ms(cx, "oracle_db.cqn_unregister_query")?;
            let mut inner = self.lock_inner(cx).await?;
            inner
                .subscribe_unregister(
                    cx,
                    registration_id,
                    &client_id,
                    TNS_SUBSCR_NAMESPACE_DBCHANGE,
                    None,
                    SUBSCR_QOS_QUERY,
                    0,
                    super::CQN_SUBSCRIPTION_TIMEOUT_SECONDS,
                    0,
                    0,
                    0,
                )
                .await
                .map_err(|err| driver_query_error(err, &self.opts, None))?;
            drop(inner);
            super::db_checkpoint(cx, "oracle_db.cqn_unregister_query.after")?;
            self.cqn_client_ids
                .lock()
                .map_err(|err| DbError::Internal(format!("CQN registration lock poisoned: {err}")))?
                .remove(&registration_id);
            Ok(())
        }

        async fn open_cqn_notification_receiver(
            &self,
            cx: &Cx,
            registration: super::CqnQueryRegistration,
        ) -> Result<Box<dyn super::CqnNotificationReceiver>, DbError> {
            super::db_checkpoint(cx, "oracle_db.cqn_open_emon.before")?;
            let receiver = open_cqn_notification_receiver(cx, self, registration).await?;
            super::db_checkpoint(cx, "oracle_db.cqn_open_emon.after")?;
            Ok(receiver)
        }

        async fn call_routine(
            &self,
            cx: &Cx,
            plsql_block: &str,
            args: &[OracleRoutineArg],
        ) -> Result<ExecuteOutcome, DbError> {
            super::db_checkpoint(cx, "oracle_db.call_routine.before")?;
            let binds: Vec<BindValue> = args
                .iter()
                .cloned()
                .map(OracleRoutineArg::into_driver_bind)
                .collect();
            let limits = self.wire_limits()?;
            let serialize_opts = SerializeOptions::default();
            let mut inner = self.lock_inner(cx).await?;
            let result = execute_with_timeout(
                cx,
                &mut inner,
                plsql_block,
                0,
                &binds,
                limits.clone(),
                &self.opts,
                "routine",
            )
            .await
            .map_err(|err| match err {
                DbError::Query(msg) => DbError::Execute(msg),
                other => other,
            })?;
            let rows_affected = result.row_count;
            let out_binds = routine_out_binds(
                cx,
                &mut inner,
                &result,
                args,
                &self.opts,
                &serialize_opts,
                limits,
            )
            .await?;
            drop(inner);
            super::db_checkpoint(cx, "oracle_db.call_routine.after")?;
            Ok(ExecuteOutcome::new(rows_affected, out_binds))
        }

        fn call_timeout(&self) -> Result<Option<std::time::Duration>, DbError> {
            self.wire_limits
                .lock()
                .map(|limits| limits.call_timeout)
                .map_err(|err| DbError::Internal(format!("wire-limits lock poisoned: {err}")))
        }

        fn set_call_timeout(&self, timeout: Option<std::time::Duration>) -> Result<(), DbError> {
            let mut guard = self
                .wire_limits
                .lock()
                .map_err(|err| DbError::Internal(format!("wire-limits lock poisoned: {err}")))?;
            guard.call_timeout = timeout;
            Ok(())
        }

        fn request_deadline(&self, cx: &Cx) -> Result<Option<asupersync::Time>, DbError> {
            let _ = cx;
            self.wire_limits
                .lock()
                .map(|limits| limits.request_deadline)
                .map_err(|err| DbError::Internal(format!("wire-limits lock poisoned: {err}")))
        }

        fn set_request_deadline(
            &self,
            cx: &Cx,
            deadline: Option<asupersync::Time>,
        ) -> Result<(), DbError> {
            let _ = cx;
            let mut guard = self
                .wire_limits
                .lock()
                .map_err(|err| DbError::Internal(format!("wire-limits lock poisoned: {err}")))?;
            guard.request_deadline = deadline;
            Ok(())
        }

        fn request_quota(&self, cx: &Cx) -> Result<Option<super::DbRequestQuota>, DbError> {
            let _ = cx;
            self.wire_limits
                .lock()
                .map(|limits| limits.request_quota.clone())
                .map_err(|err| DbError::Internal(format!("wire-limits lock poisoned: {err}")))
        }

        fn set_request_quota(
            &self,
            cx: &Cx,
            quota: Option<super::DbRequestQuota>,
        ) -> Result<(), DbError> {
            let _ = cx;
            let mut guard = self
                .wire_limits
                .lock()
                .map_err(|err| DbError::Internal(format!("wire-limits lock poisoned: {err}")))?;
            guard.request_quota = quota;
            Ok(())
        }

        async fn read_dbms_output(
            &self,
            cx: &Cx,
            max_lines: usize,
            max_chars: usize,
        ) -> Result<DbmsOutput, DbError> {
            super::db_checkpoint(cx, "oracle_db.read_dbms_output.before")?;
            let limits = self.wire_limits()?;
            let mut lines = Vec::new();
            let mut char_count = 0usize;
            let mut truncated = false;
            let mut inner = self.lock_inner(cx).await?;
            for _ in 0..max_lines {
                let timeout =
                    limits.effective_timeout_ms(cx, "oracle_db.read_dbms_output.get_line")?;
                let result = inner
                    .execute_raw(
                        cx,
                        "BEGIN DBMS_OUTPUT.GET_LINE(:1, :2); END;",
                        0,
                        &[vec![
                            BindValue::Output {
                                ora_type_num: ORA_TYPE_NUM_VARCHAR,
                                csfrm: CS_FORM_IMPLICIT,
                                buffer_size: 32_767,
                            },
                            BindValue::Output {
                                ora_type_num: ORA_TYPE_NUM_NUMBER,
                                csfrm: CS_FORM_IMPLICIT,
                                buffer_size: 22,
                            },
                        ]],
                        ExecuteOptions::default(),
                        timeout,
                    )
                    .await
                    .map_err(|err| match driver_query_error(err, &self.opts, None) {
                        DbError::Query(message) => DbError::Execute(message),
                        other => other,
                    })?;
                let status = output_value(&result, 1)
                    .and_then(QueryValue::as_i64)
                    .ok_or_else(|| {
                        DbError::Execute(
                            "DBMS_OUTPUT.GET_LINE did not return a numeric status".to_owned(),
                        )
                    })?;
                if status != 0 {
                    break;
                }
                let line = match output_value(&result, 0) {
                    Some(QueryValue::Text(value) | QueryValue::Rowid(value)) => value.to_owned(),
                    Some(QueryValue::Number(value)) => value.to_canonical_string(),
                    Some(value) => format!("{value:?}"),
                    None => String::new(),
                };
                let next_count = char_count.saturating_add(line.chars().count());
                if next_count > max_chars {
                    truncated = true;
                    break;
                }
                char_count = next_count;
                lines.push(line);
            }
            if lines.len() == max_lines {
                truncated = true;
            }
            drop(inner);
            super::db_checkpoint(cx, "oracle_db.read_dbms_output.after")?;
            Ok(DbmsOutput {
                line_count: lines.len(),
                lines,
                char_count,
                truncated,
            })
        }

        async fn commit(&self, cx: &Cx) -> Result<(), DbError> {
            // No post-commit checkpoint: once Oracle commits, cancellation
            // cannot undo it.
            super::db_checkpoint(cx, "oracle_db.commit.before")?;
            let limits = self.wire_limits()?;
            let mut inner = self.lock_inner(cx).await?;
            let timeout = limits.effective_timeout_ms(cx, "oracle_db.commit")?;
            let result = bounded_fetch_batch(timeout, inner.commit(cx)).await;
            resolve_execute_round_trip(cx, &mut inner, result, &self.opts, "commit").await
        }

        async fn rollback(&self, cx: &Cx) -> Result<(), DbError> {
            // Rollback is a finalizer. Mask the dead request's cancellation for
            // a bounded number of polls and use a fresh five-second wire cap;
            // inheriting the expired request deadline would skip the cleanup
            // that makes this pinned session safe to reuse.
            try_commit_section(cx, super::CLEANUP_MASKED_POLLS, async {
                let limits = self.wire_limits()?;
                let mut inner = self.lock_inner(cx).await?;
                let timeout = Some(limits.cleanup_timeout_ms());
                let result = bounded_fetch_batch(timeout, inner.rollback(cx)).await;
                match resolve_execute_round_trip(cx, &mut inner, result, &self.opts, "rollback")
                    .await
                {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        let message = format!(
                            "rollback cleanup failed; the thin connection was discarded: {error}"
                        );
                        inner.quarantine(message.clone());
                        Err(DbError::Quarantined {
                            outcome: crate::error::QuarantineOutcome::UnknownDiscarded,
                            message,
                        })
                    }
                }
            })
            .await
        }

        async fn flashback_disable(&self, cx: &Cx) -> Result<(), DbError> {
            // Cleanup, exactly like `rollback`: NO adapter-level pre-checkpoint,
            // so a cancelled flashback read still reaches the driver and tears
            // the `DBMS_FLASHBACK` window down (the default `execute`-based impl
            // would pre-checkpoint and, under cancellation, skip the DISABLE —
            // leaving the pinned session reading a stale snapshot). The wire
            // round trip stays bounded by the configured Oracle call timeout.
            try_commit_section(cx, super::CLEANUP_MASKED_POLLS, async {
                let timeout = Some(self.wire_limits()?.cleanup_timeout_ms());
                let mut inner = self.lock_inner(cx).await?;
                let result = inner
                    .execute_raw(
                        cx,
                        super::DBMS_FLASHBACK_DISABLE,
                        0,
                        &[],
                        ExecuteOptions::default(),
                        timeout,
                    )
                    .await;
                match result {
                    Ok(_) => Ok(()),
                    Err(error) => {
                        let message = format!(
                            "DBMS_FLASHBACK.DISABLE cleanup failed; the thin connection was discarded: {}",
                            sanitize_driver_error(error, &self.opts)
                        );
                        inner.quarantine(message.clone());
                        Err(DbError::Quarantined {
                            outcome: crate::error::QuarantineOutcome::UnknownDiscarded,
                            message,
                        })
                    }
                }
            })
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_adapter::AuthAdapter;
    use crate::types::OracleSessionIdentity;
    use asupersync::runtime::RuntimeBuilder;

    #[test]
    fn bounded_page_cell_options_cap_every_expandable_cell_to_one_page() {
        assert_eq!(
            driver::BOUNDED_PAGE_FETCH_ROWS,
            1,
            "the driver may retain only the current Oracle row"
        );
        let base = SerializeOptions {
            max_text_chars: None,
            max_lob_chars: usize::MAX,
            max_blob_bytes: usize::MAX,
            max_nested_cursor_bytes: usize::MAX,
            structured_decode_caps: crate::serialize::StructuredDecodeCaps::new(
                usize::MAX,
                usize::MAX,
                usize::MAX,
                usize::MAX,
            ),
            ..SerializeOptions::default()
        };
        let bounded = driver::bounded_cell_options(&base, 1_024);
        assert_eq!(bounded.max_text_chars, Some(1_024));
        assert_eq!(bounded.max_lob_chars, 1_024);
        assert_eq!(bounded.max_blob_bytes, 768);
        assert_eq!(bounded.max_nested_cursor_bytes, 1_024);
        assert_eq!(bounded.structured_decode_caps.max_bytes, 1_024);
        assert_eq!(bounded.max_nested_cursor_rows, base.max_nested_cursor_rows);
        assert_eq!(
            bounded.max_nested_cursor_cells,
            base.max_nested_cursor_cells
        );

        let text = driver::bounded_text_cell(
            "VARCHAR2".to_owned(),
            &"x".repeat(4_096),
            bounded.max_text_chars,
        );
        assert_eq!(text.text().map(str::len), Some(1_024));
        assert_eq!(text.source_length, Some(4_096));
        assert_eq!(
            crate::serialize::serialize_cell(&text, &bounded),
            serde_json::json!({
                "value": "x".repeat(1_024),
                "truncated": true,
                "char_length": 4_096
            })
        );

        let binary = driver::bounded_binary_cell("RAW".to_owned(), &vec![7; 4_096], 768);
        assert_eq!(binary.bytes.as_ref().map(Vec::len), Some(768));
        assert_eq!(binary.source_length, Some(4_096));
    }

    #[test]
    fn thin_mode_rejects_external_auth_before_connecting() {
        let opts = crate::types::OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            external_auth: true,
            ..Default::default()
        };
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        let result = runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            RustOracleConnection::connect(&cx, opts).await
        });
        assert!(matches!(result, Err(DbError::UnsupportedAuth(_))));
    }

    #[test]
    fn duration_to_millis_saturates() {
        assert_eq!(duration_to_millis(Duration::from_millis(42)), 42);
        assert_eq!(duration_to_millis(Duration::from_nanos(1)), 1);
        assert_eq!(duration_to_millis(Duration::from_micros(1_001)), 2);
        assert_eq!(duration_to_millis(Duration::from_secs(u64::MAX)), u32::MAX);
    }

    #[test]
    fn describe_probe_propagates_structural_cancellation() {
        let error = degrade_describe_probe::<OracleRow>(Err(DbError::Cancelled(
            "describe probe request deadline exceeded".to_owned(),
        )))
        .expect_err("cancellation cannot become absent metadata");

        assert!(matches!(error, DbError::Cancelled(_)), "{error:?}");
        assert!(error.is_uncertain_session_state());
    }

    #[test]
    fn describe_probe_propagates_uncertain_oracle_disconnect() {
        let error = degrade_describe_probe::<OracleRow>(Err(DbError::Query(
            "ORA-03113: end-of-file on communication channel".to_owned(),
        )))
        .expect_err("a lost connection cannot become absent metadata");

        assert!(matches!(error, DbError::Query(_)), "{error:?}");
        assert!(error.is_uncertain_session_state());
    }

    #[test]
    fn describe_probe_degrades_ordinary_dictionary_access_error() {
        let row = degrade_describe_probe::<OracleRow>(Err(DbError::Query(
            "ORA-00942: table or view does not exist".to_owned(),
        )))
        .expect("ordinary metadata privilege failures remain best-effort");

        assert!(row.is_none());
    }

    #[test]
    fn describe_probe_does_not_hide_non_query_adapter_failure() {
        let error = degrade_describe_probe::<OracleRow>(Err(DbError::Internal(
            "thin connection lock failed".to_owned(),
        )))
        .expect_err("an adapter failure is not a proven privilege miss");

        assert!(matches!(error, DbError::Internal(_)), "{error:?}");
    }

    #[test]
    fn quarantined_thin_connection_refuses_subsequent_use() {
        use asupersync::runtime::RuntimeBuilder;

        let conn = RustOracleConnection {
            opts: OracleConnectOptions::default(),
            inner: Arc::new(AsyncMutex::new(RustOracleConnectionSlot {
                connection: None,
                quarantine_reason: Some("flashback teardown failed".to_owned()),
            })),
            wire_limits: Mutex::new(WireLimits::default()),
            cqn_client_ids: Mutex::new(HashMap::new()),
        };
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        let error = runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            conn.ping(&cx)
                .await
                .expect_err("quarantined connection cannot serve a later DB operation")
        });

        assert!(
            matches!(
                error,
                DbError::Quarantined {
                    outcome: crate::error::QuarantineOutcome::UnknownDiscarded,
                    ref message,
                } if message == "flashback teardown failed"
            ),
            "subsequent use remains structurally quarantined: {error:?}"
        );
    }

    #[test]
    fn owned_stream_recovery_failure_persists_quarantine_for_later_calls() {
        use asupersync::runtime::RuntimeBuilder;

        let inner = Arc::new(AsyncMutex::new(RustOracleConnectionSlot {
            connection: None,
            quarantine_reason: None,
        }));
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        let (first, repeated) = runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            let first = quarantine_connection_slot(
                &inner,
                &cx,
                "owned row stream could not recover its connection: injected failure".to_owned(),
            )
            .await;
            let conn = RustOracleConnection {
                opts: OracleConnectOptions::default(),
                inner: Arc::clone(&inner),
                wire_limits: Mutex::new(WireLimits::default()),
                cqn_client_ids: Mutex::new(HashMap::new()),
            };
            let repeated = match conn.lock_inner(&cx).await {
                Ok(_) => panic!("a recovery failure must not restore the connection slot"),
                Err(error) => error,
            };
            (first, repeated)
        });

        for error in [first, repeated] {
            assert!(
                matches!(
                    error,
                    DbError::Quarantined {
                        outcome: crate::error::QuarantineOutcome::UnknownDiscarded,
                        ref message,
                    } if message == "owned row stream could not recover its connection: injected failure"
                ),
                "recovery failure must remain typed quarantine, never temporary unavailability: {error:?}"
            );
        }
    }

    #[test]
    fn wire_limits_recompute_one_absolute_deadline_per_round_trip() {
        let start = Time::from_secs(100);
        let limits = WireLimits {
            call_timeout: Some(Duration::from_secs(30)),
            request_deadline: Some(start + Duration::from_secs(10)),
            request_quota: None,
        };

        assert_eq!(
            limits
                .effective_timeout_ms_at(start, Some(start + Duration::from_secs(20)), "test",)
                .expect("initial wire limit"),
            Some(10_000),
        );
        assert_eq!(
            limits
                .effective_timeout_ms_at(
                    start + Duration::from_secs(6),
                    Some(start + Duration::from_secs(20)),
                    "test",
                )
                .expect("later wire limit"),
            Some(4_000),
        );
    }

    #[test]
    fn two_sixty_ms_round_trips_share_one_hundred_ms_ceiling() {
        let start = Time::from_secs(100);
        let limits = WireLimits {
            call_timeout: Some(Duration::from_millis(60)),
            request_deadline: Some(start + Duration::from_millis(100)),
            request_quota: None,
        };

        assert_eq!(
            limits
                .effective_timeout_ms_at(start, None, "first operation")
                .expect("first operation starts with its 60ms per-wire cap"),
            Some(60),
        );
        assert_eq!(
            limits
                .effective_timeout_ms_at(
                    start + Duration::from_millis(60),
                    None,
                    "second operation",
                )
                .expect("second operation inherits only the request remainder"),
            Some(40),
            "the second round trip must not receive a fresh 60ms window",
        );
        let error = limits
            .effective_timeout_ms_at(
                start + Duration::from_millis(100),
                None,
                "second operation completion",
            )
            .expect_err("the shared 100ms request ceiling is terminal");
        assert!(matches!(error, DbError::Cancelled(_)));
        assert!(error.to_string().contains("request deadline"));
    }

    #[test]
    fn wire_limits_take_tightest_relative_request_and_context_cap() {
        let now = Time::from_secs(50);
        let limits = WireLimits {
            call_timeout: Some(Duration::from_secs(8)),
            request_deadline: Some(now + Duration::from_secs(6)),
            request_quota: None,
        };

        assert_eq!(
            limits
                .effective_timeout_ms_at(now, Some(now + Duration::from_millis(2_500)), "test",)
                .expect("context deadline is tightest"),
            Some(2_500),
        );
        assert_eq!(
            WireLimits::default()
                .effective_timeout_ms_at(now, None, "test")
                .expect("unbounded limits"),
            None,
        );
    }

    #[test]
    fn expired_deadlines_fail_closed_instead_of_becoming_unbounded() {
        let now = Time::from_secs(75);
        let request_expired = WireLimits {
            call_timeout: None,
            request_deadline: Some(now),
            request_quota: None,
        }
        .effective_timeout_ms_at(now, None, "request phase")
        .expect_err("expired request deadline");
        assert!(matches!(request_expired, DbError::Cancelled(_)));
        assert!(request_expired.to_string().contains("request deadline"));

        let context_expired = WireLimits::default()
            .effective_timeout_ms_at(now, Some(now), "context phase")
            .expect_err("expired context deadline");
        assert!(matches!(context_expired, DbError::Cancelled(_)));
        assert!(context_expired.to_string().contains("context deadline"));
    }

    #[test]
    fn fresh_cleanup_limits_can_replace_an_expired_request() {
        let now = Time::from_secs(200);
        let expired = WireLimits {
            call_timeout: Some(Duration::from_secs(30)),
            request_deadline: Some(Time::from_secs(199)),
            request_quota: None,
        };
        assert!(
            expired
                .effective_timeout_ms_at(now, Some(now), "primary")
                .is_err()
        );

        let cleanup = WireLimits {
            request_deadline: Some(now + Duration::from_secs(2)),
            ..expired.clone()
        };
        assert_eq!(
            cleanup
                .effective_timeout_ms_at(now, Some(now + Duration::from_secs(3)), "cleanup",)
                .expect("fresh cleanup deadline"),
            Some(2_000),
        );

        // Restoring the primary snapshot re-establishes its expired boundary;
        // a cleanup override cannot accidentally make the next request looser.
        assert!(
            expired
                .effective_timeout_ms_at(now, Some(now), "restored primary")
                .is_err()
        );
    }

    #[test]
    fn cleanup_timeout_is_fresh_bounded_and_ignores_expired_request_deadline() {
        let expired_request = WireLimits {
            call_timeout: Some(Duration::from_secs(30)),
            request_deadline: Some(Time::from_secs(99)),
            request_quota: None,
        };
        assert_eq!(
            expired_request.cleanup_timeout_ms(),
            5_000,
            "cleanup gets a fresh five-second ceiling instead of the dead request deadline"
        );

        let tighter_operator_cap = WireLimits {
            call_timeout: Some(Duration::from_millis(750)),
            request_deadline: Some(Time::from_secs(99)),
            request_quota: None,
        };
        assert_eq!(
            tighter_operator_cap.cleanup_timeout_ms(),
            750,
            "cleanup never widens an existing per-wire cap"
        );
    }

    #[test]
    fn every_wire_timeout_snapshot_charges_the_shared_request_quota() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            let quota = DbRequestQuota::new(Budget::new().with_poll_quota(1));
            let limits = WireLimits {
                request_quota: Some(quota),
                ..WireLimits::default()
            };

            assert_eq!(
                limits
                    .effective_timeout_ms(&cx, "first wire operation")
                    .expect("first wire operation is admitted"),
                None
            );
            let error = limits
                .effective_timeout_ms(&cx, "second wire operation")
                .expect_err("the second operation must not reset the shared quota");
            assert!(matches!(error, DbError::Cancelled(_)));
            assert!(error.to_string().contains("poll quota"));
        });
    }

    #[test]
    fn routine_arg_wraps_driver_output_variants() {
        match OracleRoutineArg::output(1, 2, 3).into_driver_bind() {
            oracledb::protocol::thin::BindValue::Output {
                ora_type_num,
                csfrm,
                buffer_size,
            } => {
                assert_eq!((ora_type_num, csfrm, buffer_size), (1, 2, 3));
            }
            other => panic!("expected Output bind, got {}", other.variant_name()),
        }

        match OracleRoutineArg::return_output(4, 5, 6).into_driver_bind() {
            oracledb::protocol::thin::BindValue::Output {
                ora_type_num,
                csfrm,
                buffer_size,
            } => {
                assert_eq!((ora_type_num, csfrm, buffer_size), (4, 5, 6));
            }
            other => panic!("expected Output bind, got {}", other.variant_name()),
        }

        match OracleRoutineArg::object_output(
            "APP".to_owned(),
            "OBJ_T".to_owned(),
            vec![1, 2, 3],
            7,
            8,
        )
        .into_driver_bind()
        {
            oracledb::protocol::thin::BindValue::ObjectOutput {
                schema,
                type_name,
                oid,
                version,
                buffer_size,
                is_return,
            } => {
                assert_eq!(schema, "APP");
                assert_eq!(type_name, "OBJ_T");
                assert_eq!(oid, vec![1, 2, 3]);
                assert_eq!((version, buffer_size, is_return), (7, 8, false));
            }
            other => panic!("expected ObjectOutput bind, got {}", other.variant_name()),
        }

        match OracleRoutineArg::object_return_output(
            "APP".to_owned(),
            "OBJ_T".to_owned(),
            vec![4, 5, 6],
            9,
            10,
        )
        .into_driver_bind()
        {
            oracledb::protocol::thin::BindValue::ObjectOutput {
                schema,
                type_name,
                oid,
                version,
                buffer_size,
                is_return,
            } => {
                assert_eq!(schema, "APP");
                assert_eq!(type_name, "OBJ_T");
                assert_eq!(oid, vec![4, 5, 6]);
                assert_eq!((version, buffer_size, is_return), (9, 10, true));
            }
            other => panic!("expected ObjectOutput bind, got {}", other.variant_name()),
        }
    }

    #[test]
    fn routine_out_values_follow_declared_order() {
        let result = oracledb::protocol::thin::QueryResult {
            out_values: vec![
                (
                    0,
                    Some(oracledb::protocol::thin::QueryValue::number_from_text(
                        "42", true,
                    )),
                ),
                (
                    2,
                    Some(oracledb::protocol::thin::QueryValue::Text(
                        "first".to_owned(),
                    )),
                ),
            ],
            ..Default::default()
        };

        let args = [
            OracleRoutineArg::return_output(1, 1, 32_767),
            OracleRoutineArg::input(OracleBind::String("ignored input".to_owned())),
            OracleRoutineArg::output(2, 1, 22),
        ];

        let ordered = driver::ordered_routine_out_values(&result, &args).expect("ordered values");
        assert_eq!(
            ordered,
            vec![
                Some(oracledb::protocol::thin::QueryValue::number_from_text(
                    "42", true
                )),
                Some(oracledb::protocol::thin::QueryValue::Text(
                    "first".to_owned()
                )),
            ]
        );

        let missing = oracledb::protocol::thin::QueryResult {
            out_values: vec![(0, None)],
            ..Default::default()
        };
        let err = driver::ordered_routine_out_values(
            &missing,
            &[
                OracleRoutineArg::input(OracleBind::String("ignored input".to_owned())),
                OracleRoutineArg::output(1, 1, 32_767),
            ],
        )
        .expect_err("missing declared out bind is an adapter error");
        assert!(
            matches!(err, DbError::Execute(ref msg) if msg.contains("position 2")),
            "{err:?}"
        );
    }

    #[test]
    fn prefetch_rows_only_for_select_statements() {
        assert_eq!(
            driver::prefetch_rows_for_statement("SELECT 1 FROM dual"),
            512
        );
        assert_eq!(
            driver::prefetch_rows_for_statement("  \nselect * from dual"),
            512
        );
        assert_eq!(
            driver::prefetch_rows_for_statement("BEGIN DBMS_SQL.RETURN_RESULT(NULL); END;"),
            0
        );
        assert_eq!(
            driver::prefetch_rows_for_statement("DECLARE rc SYS_REFCURSOR; BEGIN NULL; END;"),
            0
        );
    }

    #[test]
    fn fetch_loop_is_bounded_per_batch() {
        fn block_on_without_runtime<F: std::future::Future>(future: F) -> F::Output {
            let waker = std::task::Waker::noop().clone();
            let mut cx = std::task::Context::from_waker(&waker);
            let mut future = std::pin::pin!(future);
            loop {
                match future.as_mut().poll(&mut cx) {
                    std::task::Poll::Ready(output) => return output,
                    std::task::Poll::Pending => std::thread::sleep(Duration::from_millis(1)),
                }
            }
        }

        let err = block_on_without_runtime(driver::bounded_fetch_batch(
            Some(1),
            std::future::pending::<Result<(), ()>>(),
        ));

        assert_eq!(err, Err(driver::FetchBatchError::Timeout(1)));
    }

    #[test]
    fn fetch_loop_timeout_is_uncertain_session_state() {
        let err = driver::fetch_batch_call_timeout(25);

        assert!(err.is_uncertain_session_state(), "{err}");
        assert!(err.to_string().contains("call timeout of 25 ms exceeded"));
    }

    #[test]
    fn thin_connect_options_use_explicit_client_identity_fields() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("app".to_owned()),
            password: Some("secret".to_owned()),
            session_identity: Some(OracleSessionIdentity {
                program: Some("profile-program".to_owned()),
                machine: Some("profile-machine".to_owned()),
                os_user: Some("profile-os-user".to_owned()),
                terminal: Some("profile-terminal".to_owned()),
                module: Some("session-module".to_owned()),
                client_identifier: Some("session-client-id".to_owned()),
                driver_name: Some("profile-driver".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.identity().program, "profile-program");
        assert_eq!(connect.identity().machine, "profile-machine");
        assert_eq!(connect.identity().osuser, "profile-os-user");
        assert_eq!(connect.identity().terminal, "profile-terminal");
        assert_eq!(connect.identity().driver_name, "profile-driver");
    }

    #[test]
    fn thin_connect_options_keep_legacy_identity_fallbacks() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("app".to_owned()),
            password: Some("secret".to_owned()),
            session_identity: Some(OracleSessionIdentity {
                module: Some("legacy-module-program".to_owned()),
                client_identifier: Some("legacy-client-terminal".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.identity().program, "legacy-module-program");
        assert_eq!(connect.identity().terminal, "legacy-client-terminal");
        assert_eq!(connect.identity().driver_name, "oraclemcp-thin");
        assert!(!connect.identity().machine.is_empty());
        assert!(!connect.identity().osuser.is_empty());
    }

    #[test]
    fn thin_connect_options_apply_explicit_tls_fields() {
        let opts = OracleConnectOptions {
            connect_string: "tcps://adb.example.com/service".to_owned(),
            username: Some("app".to_owned()),
            password: Some("secret".to_owned()),
            wallet_location: Some("/wallets/private".into()),
            wallet_password: Some("wallet-secret".to_owned()),
            ssl_server_dn_match: Some(false),
            ssl_server_cert_dn: Some("CN=db.example.com,O=Example,C=US".to_owned()),
            use_sni: Some(false),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.wallet_location(), Some("/wallets/private"));
        assert_eq!(connect.wallet_password(), Some("wallet-secret"));
        assert!(!connect.ssl_server_dn_match());
        assert_eq!(
            connect.ssl_server_cert_dn(),
            Some("CN=db.example.com,O=Example,C=US")
        );
        assert!(!connect.use_sni());
    }

    #[test]
    fn thin_connect_options_keep_wallet_sni_default() {
        let opts = OracleConnectOptions {
            connect_string: "tcps://adb.example.com/service".to_owned(),
            username: Some("app".to_owned()),
            password: Some("secret".to_owned()),
            wallet_location: Some("/wallets/private".into()),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.wallet_location(), Some("/wallets/private"));
        assert!(
            connect.use_sni(),
            "existing wallet profiles default to SNI on"
        );
        assert!(connect.ssl_server_dn_match());
        assert_eq!(connect.wallet_password(), None);
        assert_eq!(connect.ssl_server_cert_dn(), None);
    }

    #[test]
    fn thin_connect_options_apply_proxy_auth() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("MCP_PROXY".to_owned()),
            password: Some("proxy-secret".to_owned()),
            auth_adapter: AuthAdapter::Proxy {
                proxy_user: "MCP_PROXY".to_owned(),
                target_schema: "APP_OWNER".to_owned(),
            },
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.user(), "MCP_PROXY");
        assert_eq!(connect.proxy_user(), Some("APP_OWNER"));
    }

    #[test]
    fn thin_connect_options_apply_app_context_in_order() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            app_context: vec![
                (
                    "ORACLEMCP_CTX".to_owned(),
                    "tenant_id".to_owned(),
                    "tenant-123".to_owned(),
                ),
                (
                    "ORACLEMCP_CTX".to_owned(),
                    "request_id".to_owned(),
                    "req-456".to_owned(),
                ),
            ],
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.app_context(), opts.app_context.as_slice());
    }

    #[test]
    fn thin_connect_options_apply_sdu_when_configured() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            sdu: Some(32_768),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.sdu(), 32_768u16);
    }

    #[test]
    fn thin_connect_options_keep_driver_default_sdu_when_unset() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.sdu(), 8192u16);
    }

    #[test]
    fn thin_connect_options_apply_statement_cache_size_when_configured() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            statement_cache_size: Some(128),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.statement_cache_size(), 128);
    }

    #[test]
    fn thin_connect_options_keep_driver_default_statement_cache_when_unset() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.statement_cache_size(), 20);
    }

    #[test]
    fn thin_connect_options_apply_transport_connect_timeout() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            connect_timeout: Some(Duration::from_secs(7)),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(
            connect.connect_string(),
            "localhost:1521/FREEPDB1?transport_connect_timeout=7"
        );
    }

    #[test]
    fn thin_connect_options_append_transport_connect_timeout_to_existing_query() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1?expire_time=5".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            connect_timeout: Some(Duration::from_secs(9)),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(
            connect.connect_string(),
            "localhost:1521/FREEPDB1?expire_time=5&transport_connect_timeout=9"
        );
    }

    #[test]
    fn thin_connect_options_reject_ambiguous_connect_timeout_sources() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1?transport_connect_timeout=3".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            connect_timeout: Some(Duration::from_secs(9)),
            ..Default::default()
        };

        let err = driver::to_connect_options(&opts).expect_err("conflicting timeout sources");
        assert!(matches!(err, DbError::UnsupportedAuth(_)));
        assert!(err.to_string().contains("conflicts"), "{err}");
    }

    #[test]
    fn thin_connect_options_reject_descriptor_connect_timeout_injection() {
        let opts = OracleConnectOptions {
            connect_string: "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=svc)))"
                .to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            connect_timeout: Some(Duration::from_secs(9)),
            ..Default::default()
        };

        let err = driver::to_connect_options(&opts).expect_err("descriptor injection refused");
        assert!(matches!(err, DbError::UnsupportedAuth(_)));
        assert!(err.to_string().contains("descriptor"), "{err}");
    }

    #[test]
    fn thin_connect_options_apply_expire_time() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            keepalive_minutes: Some(10),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(
            connect.connect_string(),
            "localhost:1521/FREEPDB1?expire_time=10"
        );
    }

    #[test]
    fn thin_connect_options_apply_expire_time_and_transport_timeout_together() {
        // Both connect-string knobs chain: transport_connect_timeout first, then
        // expire_time appended with `&` onto the now-present query.
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            connect_timeout: Some(Duration::from_secs(7)),
            keepalive_minutes: Some(10),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(
            connect.connect_string(),
            "localhost:1521/FREEPDB1?transport_connect_timeout=7&expire_time=10"
        );
    }

    #[test]
    fn thin_connect_options_apply_inactivity_timeout() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            inactivity_timeout: Some(Duration::from_secs(300)),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        // The inactivity deadline reaches the driver's ConnectOptions verbatim.
        assert_eq!(connect.inactivity_timeout(), Some(Duration::from_secs(300)));
    }

    #[test]
    fn thin_connect_options_reject_conflicting_expire_time() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1?expire_time=5".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            keepalive_minutes: Some(10),
            ..Default::default()
        };

        let err = driver::to_connect_options(&opts).expect_err("conflicting expire_time sources");
        assert!(matches!(err, DbError::UnsupportedAuth(_)));
        assert!(err.to_string().contains("conflicts"), "{err}");
    }

    #[test]
    fn thin_connect_options_reject_descriptor_expire_time_injection() {
        let opts = OracleConnectOptions {
            connect_string: "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=svc)))"
                .to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            keepalive_minutes: Some(10),
            ..Default::default()
        };

        let err = driver::to_connect_options(&opts).expect_err("descriptor injection refused");
        assert!(matches!(err, DbError::UnsupportedAuth(_)));
        assert!(err.to_string().contains("descriptor"), "{err}");
    }

    #[test]
    fn thin_connect_options_apply_edition_when_configured() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            session_identity: Some(OracleSessionIdentity {
                edition: Some("E_TEST".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.edition(), Some("E_TEST"));
    }

    #[test]
    fn thin_connect_options_reject_unsupported_enterprise_auth() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            auth_adapter: AuthAdapter::Radius,
            ..Default::default()
        };

        let err = driver::to_connect_options(&opts).expect_err("unsupported");
        assert!(matches!(err, DbError::UnsupportedAuth(_)));
        assert!(err.to_string().contains("RADIUS/native MFA"));
    }

    #[test]
    fn iam_token_over_tcps_is_wired_through_with_access_token() {
        // A5: the pinned driver supports OCI IAM database-token auth. With a
        // fetched token and a TCPS transport, to_connect_options succeeds and
        // sets the driver's access token (no password is required or used).
        let opts = OracleConnectOptions {
            connect_string: "tcps://adb.eu.oraclecloud.com:1522/svc_high".to_owned(),
            username: Some("APP_USER".to_owned()),
            password: None,
            use_iam_token: true,
            iam_token: Some("iam.jwt.token".to_owned()),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("iam token connect options");
        assert!(
            connect.access_token().is_some(),
            "the IAM token must be wired through with_access_token"
        );
        // The token must never leak through Debug.
        let rendered = format!("{:?}", connect.access_token());
        assert!(!rendered.contains("iam.jwt.token"), "{rendered}");
    }

    #[test]
    fn iam_token_over_non_tcps_is_refused_fail_closed() {
        // A5: an IAM token must never travel over a plaintext transport. We fail
        // closed BEFORE handing the token to the driver.
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("APP_USER".to_owned()),
            use_iam_token: true,
            iam_token: Some("iam.jwt.token".to_owned()),
            ..Default::default()
        };

        let err = driver::to_connect_options(&opts).expect_err("non-tcps token refused");
        assert!(matches!(err, DbError::UnsupportedAuth(_)));
        assert!(err.to_string().contains("TLS (TCPS)"), "{err}");
        // The refusal must not echo the token.
        assert!(!err.to_string().contains("iam.jwt.token"), "{err}");
    }

    #[test]
    fn wallet_does_not_upgrade_a_plaintext_iam_endpoint() {
        let opts = OracleConnectOptions {
            connect_string: "db.example:1521/svc".to_owned(),
            username: Some("APP_USER".to_owned()),
            wallet_location: Some(tns_fixtures_dir()),
            iam_token: Some("iam.jwt.token".to_owned()),
            ..Default::default()
        };

        let err = driver::to_connect_options(&opts).expect_err("TCP stays plaintext");
        assert!(matches!(err, DbError::UnsupportedAuth(_)), "{err}");
        assert!(err.to_string().contains("TLS (TCPS)"), "{err}");
    }

    /// The committed `tnsnames.ora` fixture tree (design spec §F), used here to
    /// exercise server-side alias resolution (B2.3).
    fn tns_fixtures_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("tests")
            .join("fixtures")
            .join("tns")
    }

    #[test]
    fn bare_alias_resolves_to_descriptor_via_wallet_tnsnames() {
        // Skip if the ambient environment sets TNS_ADMIN (it would take priority
        // over the wallet dir and make the assertion env-dependent).
        if std::env::var_os("TNS_ADMIN").is_some() {
            return;
        }
        // A bare alias (round-2 OCI-2: this previously failed to resolve) is
        // expanded to its full descriptor from the wallet directory's
        // tnsnames.ora before the string reaches the driver.
        let opts = OracleConnectOptions {
            connect_string: "primary_tcps".to_owned(),
            username: Some("APP_USER".to_owned()),
            password: Some("pw".to_owned()),
            wallet_location: Some(tns_fixtures_dir()),
            ..Default::default()
        };
        let connect = driver::to_connect_options(&opts).expect("alias resolves");
        let cs = connect.connect_string();
        assert!(
            cs.contains("tcps.example.com") && cs.contains("2484"),
            "the bare alias resolved to the PRIMARY_TCPS descriptor, got: {cs}"
        );
    }

    #[test]
    fn selected_transport_matches_the_drivers_first_address_model() {
        let tcp_first = OracleConnectOptions {
            connect_string: "(DESCRIPTION=(ADDRESS_LIST=\
                (ADDRESS=(PROTOCOL=TCP)(HOST=plain)(PORT=1521))\
                (ADDRESS=(PROTOCOL=TCPS)(HOST=secure)(PORT=2484)))\
                (CONNECT_DATA=(SERVICE_NAME=svc)))"
                .to_owned(),
            wallet_location: Some(tns_fixtures_dir()),
            ..Default::default()
        };
        assert!(!selected_endpoint_uses_tcps(&tcp_first).expect("descriptor parses"));

        let tcps_first = OracleConnectOptions {
            connect_string: "(DESCRIPTION=(ADDRESS_LIST=\
                (ADDRESS=(PROTOCOL=TCPS)(HOST=secure)(PORT=2484))\
                (ADDRESS=(PROTOCOL=TCP)(HOST=plain)(PORT=1521)))\
                (CONNECT_DATA=(SERVICE_NAME=svc)))"
                .to_owned(),
            ..Default::default()
        };
        assert!(selected_endpoint_uses_tcps(&tcps_first).expect("descriptor parses"));
    }

    #[test]
    fn selected_transport_resolves_tns_alias_before_classification() {
        if std::env::var_os("TNS_ADMIN").is_some() {
            return;
        }
        let tcps = OracleConnectOptions {
            connect_string: "primary_tcps".to_owned(),
            wallet_location: Some(tns_fixtures_dir()),
            ..Default::default()
        };
        assert!(selected_endpoint_uses_tcps(&tcps).expect("TCPS alias resolves"));

        let tcp = OracleConnectOptions {
            connect_string: "ez_plain".to_owned(),
            wallet_location: Some(tns_fixtures_dir()),
            ..Default::default()
        };
        assert!(!selected_endpoint_uses_tcps(&tcp).expect("TCP alias resolves"));
    }

    #[test]
    fn selected_transport_fails_closed_for_missing_or_malformed_targets() {
        if std::env::var_os("TNS_ADMIN").is_some() {
            return;
        }
        let missing = OracleConnectOptions {
            connect_string: "does_not_exist".to_owned(),
            wallet_location: Some(tns_fixtures_dir()),
            ..Default::default()
        };
        assert!(selected_endpoint_uses_tcps(&missing).is_err());

        let malformed = OracleConnectOptions {
            connect_string: "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST=broken)".to_owned(),
            ..Default::default()
        };
        assert!(selected_endpoint_uses_tcps(&malformed).is_err());
    }

    #[test]
    fn full_descriptor_connect_string_is_used_verbatim() {
        // A full descriptor must still work unchanged even with a wallet set.
        let descriptor = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db.example)(PORT=1521))\
             (CONNECT_DATA=(SERVICE_NAME=svc)))";
        let opts = OracleConnectOptions {
            connect_string: descriptor.to_owned(),
            username: Some("APP_USER".to_owned()),
            password: Some("pw".to_owned()),
            wallet_location: Some(tns_fixtures_dir()),
            ..Default::default()
        };
        let connect = driver::to_connect_options(&opts).expect("descriptor options");
        assert_eq!(connect.connect_string(), descriptor);
    }

    #[test]
    fn missing_alias_fails_with_actionable_error() {
        if std::env::var_os("TNS_ADMIN").is_some() {
            return;
        }
        let opts = OracleConnectOptions {
            connect_string: "does_not_exist".to_owned(),
            username: Some("APP_USER".to_owned()),
            password: Some("pw".to_owned()),
            wallet_location: Some(tns_fixtures_dir()),
            ..Default::default()
        };
        let err = driver::to_connect_options(&opts).expect_err("missing alias is refused");
        assert!(matches!(err, DbError::Connect(_)), "{err}");
        let msg = err.to_string();
        assert!(msg.contains("does_not_exist"), "names the alias: {msg}");
        assert!(
            msg.contains("available aliases") && msg.contains("PRIMARY_TCPS"),
            "lists what IS available: {msg}"
        );
    }

    #[test]
    fn malformed_alias_source_fails_without_panic() {
        if std::env::var_os("TNS_ADMIN").is_some() {
            return;
        }
        // A bare alias against a directory whose tnsnames.ora has an IFILE cycle
        // surfaces a clear connect error, never a panic.
        let opts = OracleConnectOptions {
            connect_string: "anything".to_owned(),
            username: Some("APP_USER".to_owned()),
            password: Some("pw".to_owned()),
            wallet_location: Some(tns_fixtures_dir().join("cycle")),
            ..Default::default()
        };
        let err = driver::to_connect_options(&opts).expect_err("malformed source is refused");
        assert!(matches!(err, DbError::Connect(_)), "{err}");
    }

    #[test]
    fn ez_connect_with_wallet_is_not_treated_as_alias() {
        // A host:port/service EZConnect string carries a `/` and `:`, so it is
        // never mistaken for a bare alias even when a wallet dir is present.
        let opts = OracleConnectOptions {
            connect_string: "db.example:1521/svc".to_owned(),
            username: Some("APP_USER".to_owned()),
            password: Some("pw".to_owned()),
            wallet_location: Some(tns_fixtures_dir()),
            ..Default::default()
        };
        let connect = driver::to_connect_options(&opts).expect("ezconnect options");
        assert_eq!(connect.connect_string(), "db.example:1521/svc");
    }

    #[test]
    fn use_iam_token_without_a_fetched_token_is_a_setup_error() {
        // use_iam_token set but no token fetched yet: a setup error pointing at
        // the IAM token-source seam, NOT a driver-unsupported error.
        let opts = OracleConnectOptions {
            connect_string: "tcps://adb.eu.oraclecloud.com:1522/svc_high".to_owned(),
            username: Some("APP_USER".to_owned()),
            use_iam_token: true,
            iam_token: None,
            ..Default::default()
        };

        let err = driver::to_connect_options(&opts).expect_err("no token fetched");
        assert!(matches!(err, DbError::UnsupportedAuth(_)));
        assert!(err.to_string().contains("no token was fetched"), "{err}");
    }

    #[test]
    fn driver_error_redaction_removes_connect_material() {
        let opts = OracleConnectOptions {
            connect_string: "dbhost:1521/private_service".to_owned(),
            username: Some("app_user".to_owned()),
            password: Some("super_secret".to_owned()),
            auth_adapter: AuthAdapter::Proxy {
                proxy_user: "MCP_PROXY".to_owned(),
                target_schema: "APP_OWNER".to_owned(),
            },
            wallet_location: Some("/wallets/private".into()),
            wallet_password: Some("wallet_secret".to_owned()),
            ssl_server_cert_dn: Some("CN=private-db,O=Example,C=US".to_owned()),
            iam_token: Some("iam.jwt.token".to_owned()),
            app_context: vec![(
                "private-namespace".to_owned(),
                "private-key".to_owned(),
                "private-value".to_owned(),
            )],
            session_identity: Some(OracleSessionIdentity {
                program: Some("private-program".to_owned()),
                machine: Some("private-machine".to_owned()),
                os_user: Some("private-os-user".to_owned()),
                terminal: Some("private-terminal".to_owned()),
                module: Some("private-module".to_owned()),
                action: Some("private-action".to_owned()),
                client_identifier: Some("private-client-id".to_owned()),
                client_info: Some("private-client-info".to_owned()),
                driver_name: Some("private-driver".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let redacted = driver::sanitize_driver_error(
            "connect app_user/super_secret@dbhost:1521/private_service proxy MCP_PROXY APP_OWNER with /wallets/private \
             wallet_secret CN=private-db,O=Example,C=US and iam.jwt.token failed for private-program private-machine private-os-user \
             private-terminal private-module private-action private-client-id private-client-info \
             private-driver private-namespace private-key private-value",
            &opts,
        );
        for forbidden in [
            "app_user",
            "super_secret",
            "MCP_PROXY",
            "APP_OWNER",
            "dbhost:1521/private_service",
            "/wallets/private",
            "wallet_secret",
            "CN=private-db",
            "iam.jwt.token",
            "private-program",
            "private-machine",
            "private-os-user",
            "private-terminal",
            "private-module",
            "private-action",
            "private-client-id",
            "private-client-info",
            "private-driver",
            "private-namespace",
            "private-key",
            "private-value",
        ] {
            assert!(!redacted.contains(forbidden), "{redacted}");
        }
        assert!(redacted.contains("<redacted>"));
    }

    #[test]
    fn session_setup_errors_discard_sql_and_server_detail_but_keep_code_and_ordinal() {
        const SECRET: &str = "qa47-session-token-must-never-render";
        const SQL: &str =
            "BEGIN raise_application_error(-20000, 'qa47-session-token-must-never-render'); END;";
        let raw = DbError::Execute(format!(
            "session setup: ORA-20000: {SECRET}\nORA-06512: at line 1; SQL={SQL}"
        ));

        let error = driver::redact_session_setup_result::<()>(Err(raw), 2)
            .expect_err("the second trusted statement must remain a failure");
        let rendered = error.to_string();
        assert!(
            rendered.contains("session setup statement 2 failed"),
            "{rendered}"
        );
        assert!(rendered.contains("ORA-20000"), "{rendered}");
        assert!(rendered.contains("server detail suppressed"), "{rendered}");
        assert!(!rendered.contains(SECRET), "secret leaked: {rendered}");
        assert!(!rendered.contains(SQL), "statement leaked: {rendered}");
        assert!(
            !rendered.contains("ORA-06512"),
            "server detail leaked: {rendered}"
        );

        let envelope = error.into_envelope();
        assert_eq!(envelope.ora_code, Some(20_000));
        assert_eq!(
            envelope.error_class,
            oraclemcp_error::ErrorClass::ConnectionFailed
        );
        let json = envelope.to_json().to_string();
        assert!(!json.contains(SECRET), "doctor/tool JSON leaked: {json}");
        assert!(!json.contains(SQL), "doctor/tool JSON leaked SQL: {json}");
    }

    #[test]
    fn session_setup_redaction_preserves_known_class_and_success() {
        let error = driver::redact_session_setup_result::<()>(
            Err(DbError::Execute(
                "session setup: ORA-01031: qa47-private-context".to_owned(),
            )),
            1,
        )
        .expect_err("insufficient privilege remains a failure");
        let envelope = error.into_envelope();
        assert_eq!(envelope.ora_code, Some(1_031));
        assert_eq!(
            envelope.error_class,
            oraclemcp_error::ErrorClass::InsufficientPrivilege
        );
        assert!(!envelope.message.contains("qa47-private-context"));

        let success = driver::redact_session_setup_result::<u64>(Ok(7), 3)
            .expect("successful setup is unchanged");
        assert_eq!(success, 7);
    }

    #[test]
    fn session_setup_errors_without_an_oracle_code_still_suppress_detail() {
        let error = driver::redact_session_setup_result::<()>(
            Err(DbError::Execute(
                "driver rejected qa47-non-oracle-secret".to_owned(),
            )),
            4,
        )
        .expect_err("driver failure remains a failure");
        let rendered = error.to_string();
        assert!(
            rendered.contains("session setup statement 4 failed"),
            "{rendered}"
        );
        assert!(!rendered.contains("qa47-non-oracle-secret"), "{rendered}");
        assert_eq!(error.into_envelope().ora_code, None);
    }

    #[test]
    fn session_setup_redaction_preserves_structural_cancellation() {
        let error = driver::redact_session_setup_result::<()>(
            Err(DbError::Cancelled(
                "session setup: request deadline exceeded".to_owned(),
            )),
            1,
        )
        .expect_err("cancelled setup remains cancelled");
        assert!(matches!(error, DbError::Cancelled(_)), "{error:?}");
        assert_eq!(
            error.into_envelope().error_class,
            oraclemcp_error::ErrorClass::Timeout
        );
    }

    // --- structured / decomposed / upper-cased redaction (bead p0sd) ------
    //
    // Exact-substring redaction alone leaks a *decomposed* connect string (an
    // `ORA-` message naming only the host, or only the service) and an
    // Oracle-**upper-cased** identifier. These pin the structured pass.

    fn ezconnect_opts() -> OracleConnectOptions {
        OracleConnectOptions {
            connect_string: "db.internal.example:1599/appsvc".to_owned(),
            username: Some("appschema".to_owned()),
            password: Some("hunter2pw".to_owned()),
            ..Default::default()
        }
    }

    #[test]
    fn redaction_scrubs_decomposed_host_alone() {
        let out = driver::sanitize_driver_error(
            "ORA-12545: Connect failed because host db.internal.example is unreachable",
            &ezconnect_opts(),
        );
        assert!(!out.contains("db.internal.example"), "{out}");
        assert!(out.contains("<redacted>"), "{out}");
    }

    #[test]
    fn redaction_scrubs_decomposed_port_alone() {
        let out = driver::sanitize_driver_error(
            "TNS listener on port 1599 refused the request",
            &ezconnect_opts(),
        );
        assert!(!out.contains("1599"), "{out}");
        assert!(out.contains("<redacted>"), "{out}");
    }

    #[test]
    fn redaction_scrubs_decomposed_service_alone() {
        let out = driver::sanitize_driver_error(
            "ORA-12514: listener does not currently know of service appsvc",
            &ezconnect_opts(),
        );
        assert!(!out.contains("appsvc"), "{out}");
        assert!(out.contains("<redacted>"), "{out}");
    }

    #[test]
    fn redaction_scrubs_oracle_uppercased_service_and_schema() {
        // Oracle upper-cases unquoted identifiers, so the lower-case profile
        // values re-appear as APPSVC / APPSCHEMA in the server message.
        let out = driver::sanitize_driver_error(
            "ORA-12514: TNS:listener does not currently know of service APPSVC \
             requested for schema APPSCHEMA",
            &ezconnect_opts(),
        );
        assert!(!out.contains("APPSVC"), "{out}");
        assert!(!out.contains("APPSCHEMA"), "{out}");
        assert!(out.contains("<redacted>"), "{out}");
    }

    #[test]
    fn redaction_scrubs_full_connect_string_verbatim() {
        let out = driver::sanitize_driver_error(
            "failed to connect to db.internal.example:1599/appsvc as appschema",
            &ezconnect_opts(),
        );
        for leak in [
            "db.internal.example",
            "1599",
            "appsvc",
            "appschema",
            "db.internal.example:1599/appsvc",
        ] {
            assert!(!out.contains(leak), "leaked {leak}: {out}");
        }
    }

    #[test]
    fn redaction_does_not_over_scrub_a_benign_message() {
        // No secret component appears here — the message must pass through
        // byte-for-byte, and the short-identifier boundary rule must not fire.
        let benign = "ORA-00942: table or view does not exist";
        let out = driver::sanitize_driver_error(benign, &ezconnect_opts());
        assert_eq!(out, benign, "benign message was altered: {out}");
    }

    #[test]
    fn redaction_boundary_rule_spares_embedded_lookalikes() {
        // Service "appsvc" / port "1599" as *substrings* of longer tokens must
        // survive; only whole-token matches are topology leaks.
        let opts = ezconnect_opts();
        let out =
            driver::sanitize_driver_error("note: myappsvcx and 15990 are unrelated tokens", &opts);
        assert!(
            out.contains("myappsvcx"),
            "over-redacted a superstring: {out}"
        );
        assert!(out.contains("15990"), "over-redacted a superstring: {out}");
        assert!(!out.contains("<redacted>"), "{out}");
    }

    #[test]
    fn redaction_handles_tns_descriptor_connect_string() {
        let opts = OracleConnectOptions {
            connect_string:
                "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=vault-db.example)(PORT=2484))\
                 (CONNECT_DATA=(SERVICE_NAME=vaultsvc)))"
                    .to_owned(),
            username: Some("vaultuser".to_owned()),
            ..Default::default()
        };
        let out = driver::sanitize_driver_error(
            "ORA-12514 for VAULTSVC on VAULT-DB.EXAMPLE:2484 user VAULTUSER",
            &opts,
        );
        for leak in ["VAULTSVC", "VAULT-DB.EXAMPLE", "2484", "VAULTUSER"] {
            assert!(!out.contains(leak), "leaked {leak}: {out}");
        }
    }

    #[test]
    fn fetch_call_timeout_is_structurally_uncertain_not_marker_dependent() {
        // Regression guard for the marker-fragility half of bead p0sd: the
        // in-house call-timeout path must flag uncertain session state from the
        // error *kind*, independent of the message wording.
        let err = driver::fetch_batch_call_timeout(25);
        assert!(matches!(err, DbError::Cancelled(_)), "{err:?}");
        assert!(err.is_uncertain_session_state(), "{err}");
    }

    #[test]
    fn driver_connection_lost_taxonomy_reaches_the_db_error_boundary() {
        let opts = ezconnect_opts();
        for code in oraclemcp_error::CONNECTION_LOST_ORA_CODES {
            let err = oracledb::Error::Protocol(oracledb::protocol::ProtocolError::ServerError(
                format!("ORA-{code:05}: synthetic connection loss"),
            ));
            assert!(
                err.is_connection_lost(),
                "pinned driver must classify ORA-{code:05} as connection-lost"
            );
            let mapped = driver::driver_query_error(err, &opts, None);
            assert!(
                matches!(mapped, DbError::ConnectionLost(_)),
                "adapter must retain the driver's connection-lost disposition for ORA-{code:05}"
            );
        }

        let io = oracledb::Error::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "synthetic broken pipe",
        ));
        assert!(io.is_connection_lost());
        assert!(matches!(
            driver::driver_query_error(io, &opts, None),
            DbError::ConnectionLost(_)
        ));

        let execute_io = oracledb::Error::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "synthetic broken pipe",
        ));
        assert!(matches!(
            driver::driver_execute_error(execute_io, &opts, "synthetic execute"),
            DbError::ConnectionLost(_)
        ));
    }

    #[test]
    fn ttc_129_is_promoted_to_fresh_connection_retry() {
        let opts = ezconnect_opts();
        let err =
            oracledb::Error::Protocol(oracledb::protocol::ProtocolError::UnknownMessageType {
                message_type: 129,
                position: 35,
            });
        assert!(
            !err.is_connection_lost(),
            "driver exposes TTC-129 as reusable"
        );
        let mapped = driver::driver_query_error(err, &opts, Some("metadata probe"));
        assert!(matches!(mapped, DbError::ConnectionLost(_)));
        assert!(mapped.is_uncertain_session_state());
        let envelope = mapped.into_envelope();
        assert_eq!(envelope.error_class, oraclemcp_error::ErrorClass::Transient);
        assert!(envelope.error_class.is_retryable());
        assert!(envelope.message.contains("detail suppressed"));
        assert!(!envelope.message.contains("TTC"));
    }

    // --- connect/handshake failure classification (bead bhw6.2) -----------
    //
    // These construct real `oracledb::Error` connect variants and assert the
    // seam maps each to the driver-agnostic `ConnectFailureKind`, so an
    // opaque driver string can never again ship as the whole diagnosis.

    use crate::error::ConnectFailureKind;

    #[test]
    fn classify_unexpected_packet_maps_to_unexpected_tns_packet() {
        let kind = driver::classify_connect_failure(&oracledb::Error::UnexpectedPacket(11));
        assert_eq!(
            kind,
            Some(ConnectFailureKind::UnexpectedTnsPacket { packet_type: 11 })
        );
    }

    #[test]
    fn classify_connect_resend_loop_carries_rounds() {
        let kind = driver::classify_connect_failure(&oracledb::Error::ConnectResendLoop(5));
        assert_eq!(
            kind,
            Some(ConnectFailureKind::ConnectResendLoop { rounds: 5 })
        );
    }

    #[test]
    fn classify_fast_auth_required_maps_to_token_auth_on_old_server() {
        let kind = driver::classify_connect_failure(&oracledb::Error::FastAuthRequired);
        assert_eq!(kind, Some(ConnectFailureKind::FastAuthNotAdvertised));
    }

    #[test]
    fn classify_redirect_unsupported_maps_to_listener_redirect() {
        let kind = driver::classify_connect_failure(&oracledb::Error::RedirectUnsupported);
        assert_eq!(kind, Some(ConnectFailureKind::ListenerRedirectUnsupported));
    }

    #[test]
    fn classify_listener_refused_extracts_the_err_code() {
        let payload = "(DESCRIPTION=(TMP=)(VSNNUM=301989888)(ERR=12514)(ERROR_STACK=(ERROR=(CODE=12514)(EMFI=4))))";
        let kind =
            driver::classify_connect_failure(&oracledb::Error::ListenerRefused(payload.to_owned()));
        assert_eq!(
            kind,
            Some(ConnectFailureKind::ListenerRefused {
                err_code: Some(12514),
            })
        );
    }

    #[test]
    fn classify_listener_refused_without_code_still_classifies() {
        let kind = driver::classify_connect_failure(&oracledb::Error::ListenerRefused(
            "connection refused".to_owned(),
        ));
        assert_eq!(
            kind,
            Some(ConnectFailureKind::ListenerRefused { err_code: None })
        );
    }

    #[test]
    fn classify_unsupported_tns_version_maps_to_server_generation() {
        let kind = driver::classify_connect_failure(&oracledb::Error::Protocol(
            oracledb::protocol::ProtocolError::UnsupportedVersion {
                version: 298,
                minimum: 315,
            },
        ));
        assert_eq!(
            kind,
            Some(ConnectFailureKind::ServerGenerationUnsupported {
                tns_version: Some(298),
            })
        );
    }

    #[test]
    fn classify_unsupported_feature_names_the_feature() {
        let kind = driver::classify_connect_failure(&oracledb::Error::Protocol(
            oracledb::protocol::ProtocolError::UnsupportedFeature(
                "Native Network Encryption and Data Integrity",
            ),
        ));
        assert_eq!(
            kind,
            Some(ConnectFailureKind::UnsupportedWireFeature {
                feature: "Native Network Encryption and Data Integrity".to_owned(),
            })
        );
    }

    #[test]
    fn classify_unknown_ttc_message_type_is_a_handshake_protocol_error() {
        // The field bug: this exact driver error surfaced raw, naming the TTC
        // application layer while the failing byte was a network-layer TNS
        // packet. It must classify as a handshake-phase protocol error.
        let kind = driver::classify_connect_failure(&oracledb::Error::Protocol(
            oracledb::protocol::ProtocolError::UnknownMessageType {
                message_type: 11,
                position: 4,
            },
        ));
        assert_eq!(kind, Some(ConnectFailureKind::HandshakeProtocol));
    }

    #[test]
    fn classify_wallet_error_keeps_the_plain_connect_path() {
        // Wallet diagnostics are already precise; they stay on DbError::Connect.
        let err =
            oracledb::Error::Wallet(oracledb::protocol::tls::wallet::WalletError::NoCertificates);
        assert_eq!(driver::classify_connect_failure(&err), None);
    }

    #[test]
    fn parse_listener_refuse_code_handles_absent_and_malformed_codes() {
        assert_eq!(
            driver::parse_listener_refuse_code("(ERR=12505)"),
            Some(12505)
        );
        assert_eq!(driver::parse_listener_refuse_code("(ERR=)"), None);
        assert_eq!(driver::parse_listener_refuse_code("no code here"), None);
    }

    #[test]
    fn connect_error_to_db_error_sanitizes_and_classifies() {
        let opts = crate::types::OracleConnectOptions {
            connect_string: "dbhost:1521/private_service".to_owned(),
            ..Default::default()
        };
        let err = oracledb::Error::ListenerRefused(
            "(ERR=12514) for dbhost:1521/private_service".to_owned(),
        );
        let mapped = driver::connect_error_to_db_error(&err, &opts);
        match mapped {
            DbError::ConnectHandshake { kind, message } => {
                assert_eq!(
                    kind,
                    ConnectFailureKind::ListenerRefused {
                        err_code: Some(12514),
                    }
                );
                assert!(!message.contains("private_service"), "{message}");
                assert!(message.contains("<redacted>"), "{message}");
            }
            other => panic!("expected ConnectHandshake, got {other:?}"),
        }
    }
}

/// Rust-level guard for the driver-adapter seam (B2; plan §8 release gate).
///
/// Mirrors `scripts/oraclemcp_driver_seam_lint.sh` so `cargo test` catches an
/// `oracledb::` driver call that leaks outside the adapter even when the shell
/// lint is not run. The two enforcers share one allowlist: this file is the
/// only adapter site. Add a new legitimate `oracledb::` site to BOTH the shell
/// lint's `ADAPTER_ALLOWLIST` and `ADAPTER_ALLOWLIST` below, with a
/// justification.
#[cfg(test)]
mod driver_seam {
    use std::path::{Path, PathBuf};

    /// Workspace-relative paths that ARE the adapter — the only sources allowed
    /// to name an `oracledb::` driver path.
    const ADAPTER_ALLOWLIST: &[&str] = &[
        // B2 adapter: wraps the whole oracledb driver surface.
        "crates/oraclemcp-db/src/connection.rs",
    ];

    /// Walk to the workspace root from this crate's manifest dir
    /// (`.../crates/oraclemcp-db` -> `...`).
    fn workspace_root() -> PathBuf {
        let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        crate_dir
            .parent() // crates/
            .and_then(Path::parent) // workspace root
            .expect("crate manifest dir has a workspace root two levels up")
            .to_path_buf()
    }

    fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(dir).expect("read source directory for seam lint");
        for entry in entries {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    fn string_field(line: &str, field: &str) -> Option<String> {
        let trimmed = line.trim();
        let rest = trimmed.strip_prefix(field)?.trim_start();
        let value = rest.strip_prefix('=')?.trim_start();
        let value = value.strip_prefix('"')?;
        let (value, _) = value.split_once('"')?;
        Some(value.to_owned())
    }

    fn lock_package_versions(lock: &str, package: &str) -> Vec<String> {
        let mut versions = Vec::new();
        let mut current_name: Option<String> = None;
        let mut current_version: Option<String> = None;

        for line in lock.lines().chain(std::iter::once("[[package]]")) {
            if line.trim() == "[[package]]" {
                if current_name.as_deref() == Some(package)
                    && let Some(version) = current_version.take()
                {
                    versions.push(version);
                }
                current_name = None;
                current_version = None;
                continue;
            }
            if current_name.is_none() {
                current_name = string_field(line, "name");
            }
            if current_version.is_none() {
                current_version = string_field(line, "version");
            }
        }

        versions
    }

    #[test]
    fn pin_is_0_8_4_and_seam_intact() {
        let root = workspace_root();
        let manifest =
            std::fs::read_to_string(root.join("Cargo.toml")).expect("read workspace Cargo.toml");
        assert!(
            manifest.contains(r#"oracledb = { version = "=0.8.4", default-features = false }"#),
            "workspace Cargo.toml must keep the oracledb dependency exactly pinned at =0.8.4"
        );

        let lock = std::fs::read_to_string(root.join("Cargo.lock")).expect("read Cargo.lock");
        assert_eq!(
            lock_package_versions(&lock, "oracledb"),
            vec!["0.8.4".to_owned()],
            "Cargo.lock must resolve exactly one oracledb package at 0.8.4"
        );
        assert_eq!(
            lock_package_versions(&lock, "oracledb-protocol"),
            vec!["0.8.4".to_owned()],
            "Cargo.lock must resolve the matching oracledb-protocol 0.8.4 package"
        );

        assert_eq!(
            ADAPTER_ALLOWLIST,
            ["crates/oraclemcp-db/src/connection.rs"],
            "the driver adapter seam must remain a single source file"
        );
    }

    #[test]
    fn upstream_expire_time_gap_is_parse_visible() {
        let descriptor = oracledb::protocol::net::EasyConnect::parse_descriptor(
            "dbhost:1521/FREEPDB1?expire_time=7&transport_connect_timeout=2.5",
        )
        .expect("extended Easy Connect string should parse");
        let desc = descriptor.first_description();

        assert_eq!(
            desc.expire_time, 7,
            "rust-oracledb#14 remains an upstream runtime keepalive wiring issue, not a parser loss"
        );
        assert!((desc.tcp_connect_timeout - 2.5).abs() < 1e-9);
    }

    /// True iff `line` names the DRIVER crate path `oracledb::` (and not the
    /// workspace crate `oraclemcp_db::`). Requires a non-identifier char (or
    /// start of line) to the left of `oracledb`, then optional whitespace, then
    /// `::` — matching the shell lint's `(^|[^A-Za-z0-9_])oracledb[[:space:]]*::`.
    fn names_driver_path(line: &str) -> bool {
        let bytes = line.as_bytes();
        let mut search_from = 0;
        while let Some(rel) = line[search_from..].find("oracledb") {
            let start = search_from + rel;
            let left_ok = start == 0 || {
                let c = bytes[start - 1];
                !(c.is_ascii_alphanumeric() || c == b'_')
            };
            if left_ok {
                // Skip past "oracledb" and any whitespace, expect "::".
                let mut idx = start + "oracledb".len();
                while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                    idx += 1;
                }
                if line[idx..].starts_with("::") {
                    return true;
                }
            }
            search_from = start + "oracledb".len();
        }
        false
    }

    #[test]
    fn no_oracledb_driver_call_outside_adapter() {
        let root = workspace_root();
        let crates_dir = root.join("crates");
        let mut files = Vec::new();
        collect_rs_files(&crates_dir, &mut files);
        files.sort();
        assert!(!files.is_empty(), "no crate sources found under crates/");

        let mut violations: Vec<String> = Vec::new();
        for file in &files {
            let rel = file
                .strip_prefix(&root)
                .expect("file under workspace root")
                .to_string_lossy()
                .replace('\\', "/");
            if ADAPTER_ALLOWLIST.contains(&rel.as_str()) {
                continue;
            }
            let contents = std::fs::read_to_string(file).expect("read Rust source for seam lint");
            for (n, line) in contents.lines().enumerate() {
                if names_driver_path(line) {
                    violations.push(format!("{rel}:{}: {}", n + 1, line.trim()));
                }
            }
        }

        assert!(
            violations.is_empty(),
            "oracledb:: driver path(s) leaked outside the adapter \
             ({:?}); move them behind an OracleConnection / adapter method, or \
             add a legitimate new adapter site to ADAPTER_ALLOWLIST here AND in \
             scripts/oraclemcp_driver_seam_lint.sh:\n{}",
            ADAPTER_ALLOWLIST,
            violations.join("\n"),
        );
    }

    #[test]
    fn pattern_distinguishes_driver_from_workspace_crate() {
        // The DRIVER crate path is a violation.
        assert!(names_driver_path("use oracledb::Connection;"));
        assert!(names_driver_path("    inner: Mutex<oracledb::Connection>,"));
        assert!(names_driver_path(
            "oracledb :: BlockingConnection::connect(x)"
        ));
        // The workspace crate `oraclemcp_db::` is NOT a violation.
        assert!(!names_driver_path("use oraclemcp_db::OracleCell;"));
        assert!(!names_driver_path(
            "let x = oraclemcp_db::serialize_cell(c, o);"
        ));
        // A bare mention of the word without a `::` path is fine.
        assert!(!names_driver_path(
            "//! the thin oracledb-backed connection"
        ));
        assert!(!names_driver_path(
            r#""driver": "pure-Rust oracledb thin driver""#
        ));
    }

    /// True iff `line` is a real `block_on(` CALL (not a doc-comment mention).
    fn names_block_on_call(line: &str) -> bool {
        let trimmed = line.trim_start();
        // Skip doc/line comments — they may legitimately mention `block_on`.
        if trimmed.starts_with("//") {
            return false;
        }
        line.contains("block_on(")
    }

    /// B1 cancel-correctness invariant: NO `block_on` anywhere in the per-call
    /// DB path. The async migration removed the per-call `block_on` (the old
    /// `BlockingConnection` facade); every DB round trip now runs on the one
    /// ambient Asupersync runtime via `.await`. The only legitimate `block_on`s
    /// in these sources are inside `#[cfg(test)]` modules (test harness bridges
    /// that drive an async body on a one-shot runtime). This test fails if a
    /// `block_on(` call appears in PRODUCTION code under the DB-path source
    /// trees, so a regression can never silently reintroduce the per-call
    /// blocking bridge.
    #[test]
    fn no_block_on_in_db_path() {
        let root = workspace_root();
        // The per-call DB path: the canonical DB crate and the dispatcher (which
        // threads `cx` into every DB round trip). Connection ESTABLISHMENT lives
        // in `crates/oraclemcp/src/main.rs` (a one-shot startup `block_on`,
        // explicitly NOT the per-call path) and is intentionally not scanned.
        let db_path_dirs = [
            root.join("crates/oraclemcp-db/src"),
            root.join("crates/oraclemcp/src/dispatch"),
        ];
        let mut files = Vec::new();
        for dir in &db_path_dirs {
            collect_rs_files(dir, &mut files);
        }
        files.sort();
        assert!(!files.is_empty(), "no DB-path sources found");

        let mut violations: Vec<String> = Vec::new();
        for file in &files {
            let rel = file
                .strip_prefix(&root)
                .expect("file under workspace root")
                .to_string_lossy()
                .replace('\\', "/");
            // Whole `*/tests.rs` files (and `*/tests/*.rs`) are `#[cfg(test)]`
            // modules wired in by `mod tests;` — test-only by construction.
            if rel.ends_with("/tests.rs") || rel.contains("/tests/") {
                continue;
            }
            let contents = std::fs::read_to_string(file).expect("read Rust source for seam lint");

            // Track whether the current line is inside a `#[cfg(test)]` module by
            // brace depth: when a `mod ... {` follows a `#[cfg(test)]` attribute,
            // everything until its matching close brace is test-only.
            let mut depth: i32 = 0;
            let mut test_mod_depth: Option<i32> = None;
            let mut pending_cfg_test = false;
            for (n, line) in contents.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("#[cfg(test)]") {
                    pending_cfg_test = true;
                }
                let opens = line.matches('{').count() as i32;
                let closes = line.matches('}').count() as i32;
                // A `mod NAME {` opening right after a `#[cfg(test)]` attribute
                // starts the test region at the depth just before this brace.
                if pending_cfg_test && trimmed.starts_with("mod ") && opens > 0 {
                    test_mod_depth = Some(depth);
                    pending_cfg_test = false;
                } else if !trimmed.is_empty() && !trimmed.starts_with("#[") {
                    // Any other non-attribute line clears a dangling cfg(test).
                    pending_cfg_test = false;
                }
                let in_test = test_mod_depth.is_some_and(|d| depth > d);
                // A `// block-on-boundary:` marker (on the line or within the few
                // lines above, e.g. above the `RuntimeBuilder` chain) exempts the
                // sync→async dispatch ENTRY shims (driven on a one-shot runtime
                // once per tool call for non-server/test callers) — these are NOT
                // the per-call DB round-trip path the invariant targets.
                let all_lines: Vec<&str> = contents.lines().collect();
                let lookback_start = n.saturating_sub(8);
                let boundary_marker = all_lines[lookback_start..=n]
                    .iter()
                    .any(|l| l.contains("block-on-boundary:"));
                if !in_test && !boundary_marker && names_block_on_call(line) {
                    violations.push(format!("{rel}:{}: {}", n + 1, line.trim()));
                }
                depth += opens - closes;
                if let Some(d) = test_mod_depth
                    && depth <= d
                {
                    test_mod_depth = None;
                }
            }
        }

        assert!(
            violations.is_empty(),
            "B1: `block_on` found in the production DB path — the async migration \
             removed the per-call blocking bridge; every DB round trip must run \
             on the ambient runtime via `.await`. Offending sites:\n{}",
            violations.join("\n"),
        );
    }
}

#[cfg(test)]
mod interval_ds_canonical_tests {
    use super::driver::{
        format_interval_ds, format_interval_ds_iso, interval_ds_mixed_sign_marker,
    };

    /// Negative acceptance for bead F-LOW DB4: a minus sign may lead the value,
    /// and may appear nowhere else. Before the canonical formatter each
    /// component was interpolated independently, so a negative interval
    /// rendered `-1 -2:-3:-4.-00000005` — text no Oracle client can read back.
    #[test]
    fn a_negative_interval_carries_exactly_one_leading_sign() {
        let text = format_interval_ds(-1, -2, -3, -4, -5).expect("wholly negative is valid");
        assert_eq!(text, "-1 02:03:04.000000005");
        assert_eq!(text.matches('-').count(), 1, "one sign only: {text}");

        let iso = format_interval_ds_iso(-1, -2, -3, -4, -5).expect("wholly negative is valid");
        assert_eq!(iso, "-P1DT2H3M4.000000005S");
        assert_eq!(iso.matches('-').count(), 1, "one sign only: {iso}");
    }

    /// The sub-day-only case the finding names: days is zero, the rest negative.
    #[test]
    fn a_negative_sub_day_interval_has_no_embedded_sign() {
        let text = format_interval_ds(0, 0, 0, 0, -1).expect("wholly negative is valid");
        assert_eq!(text, "-0 00:00:00.000000001");
        assert!(
            !text[1..].contains('-'),
            "the fseconds field must not carry its own sign: {text}"
        );
    }

    /// Positive acceptance: positive and zero intervals render exactly as they
    /// did before, so no existing output moved.
    #[test]
    fn positive_and_zero_intervals_are_byte_identical_to_the_previous_format() {
        assert_eq!(
            format_interval_ds(1, 2, 3, 4, 5).expect("positive is valid"),
            format!("{} {:02}:{:02}:{:02}.{:09}", 1, 2, 3, 4, 5)
        );
        assert_eq!(
            format_interval_ds(0, 0, 0, 0, 0).expect("zero is valid"),
            format!("{} {:02}:{:02}:{:02}.{:09}", 0, 0, 0, 0, 0)
        );
        assert_eq!(
            format_interval_ds_iso(1, 2, 3, 4, 5).expect("positive is valid"),
            format!("P{}DT{}H{}M{}.{:09}S", 1, 2, 3, 4, 5)
        );
    }

    /// Mixed signs are an invalid Oracle value, not a formatting choice: the
    /// serializers must fail typed rather than emit text that reads as a
    /// different interval than the one the database holds.
    #[test]
    fn mixed_sign_components_fail_typed_instead_of_rendering_text() {
        assert!(format_interval_ds(1, -2, 0, 0, 0).is_none());
        assert!(format_interval_ds_iso(-1, 2, 0, 0, 0).is_none());

        let marker = interval_ds_mixed_sign_marker(1, -2, 0, 0, 0);
        assert_eq!(marker["kind"], "unsupported");
        assert_eq!(marker["oracle_value_kind"], "IntervalDS");
        assert!(marker["value"].is_null(), "no invented text: {marker}");
        assert_eq!(marker["days"], 1, "the typed numeric fields are preserved");
        assert_eq!(marker["hours"], -2, "including their original signs");
    }

    /// i32::MIN has no positive counterpart; `unsigned_abs` is why this does not
    /// panic in a release build or wrap in a debug one.
    #[test]
    fn the_most_negative_component_does_not_overflow() {
        let text = format_interval_ds(i32::MIN, 0, 0, 0, 0).expect("wholly negative is valid");
        assert_eq!(text, "-2147483648 00:00:00.000000000");
    }
}
