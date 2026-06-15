//! Backend-independent value, row, and connect-option types (plan §5.2).
//!
//! These are deliberately driver-free at the boundary. P0-3 fetches cells as
//! nullable text plus the Oracle type name; the deterministic NUMBER→string /
//! ISO-8601 / NLS serializer (P0-5) builds the precise JSON mapping on top.

use std::{path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};

/// The connectivity backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OracleBackend {
    /// The pure-Rust `oracledb` thin driver.
    RustOracle,
}

impl std::fmt::Display for OracleBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OracleBackend::RustOracle => f.write_str("oracledb-thin"),
        }
    }
}

/// A bind value. Agent argument values are **always** bound, never interpolated
/// into SQL text (plan §9.2 — no injection through parameters).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleBind {
    /// SQL NULL.
    Null,
    /// A string / VARCHAR2 bind.
    String(String),
    /// An integer bind.
    I64(i64),
    /// A floating-point bind.
    F64(f64),
    /// A boolean bind (mapped to 1/0 for pre-23ai).
    Bool(bool),
}

impl From<&str> for OracleBind {
    fn from(s: &str) -> Self {
        OracleBind::String(s.to_owned())
    }
}
impl From<String> for OracleBind {
    fn from(s: String) -> Self {
        OracleBind::String(s)
    }
}
impl From<i64> for OracleBind {
    fn from(v: i64) -> Self {
        OracleBind::I64(v)
    }
}
impl From<i32> for OracleBind {
    fn from(v: i32) -> Self {
        OracleBind::I64(i64::from(v))
    }
}
impl From<f64> for OracleBind {
    fn from(v: f64) -> Self {
        OracleBind::F64(v)
    }
}
impl From<bool> for OracleBind {
    fn from(v: bool) -> Self {
        OracleBind::Bool(v)
    }
}

/// A single result cell: the Oracle column type name plus its value rendered as
/// nullable text (the canonical JSON mapping is applied by the P0-5 serializer).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleCell {
    /// The Oracle column type name (e.g. `"NUMBER"`, `"VARCHAR2"`, `"DATE"`).
    pub oracle_type: String,
    /// The value as text, or `None` for SQL NULL.
    pub value: Option<String>,
    /// Raw bytes for binary columns (BLOB / RAW) fetched in binary mode; the
    /// serializer base64-encodes these. `None` for text/NULL cells.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<Vec<u8>>,
}

impl OracleCell {
    /// Construct a text cell.
    #[must_use]
    pub fn new(oracle_type: impl Into<String>, value: Option<String>) -> Self {
        OracleCell {
            oracle_type: oracle_type.into(),
            value,
            bytes: None,
        }
    }

    /// Construct a binary cell carrying raw bytes (BLOB / RAW).
    #[must_use]
    pub fn binary(oracle_type: impl Into<String>, bytes: Vec<u8>) -> Self {
        OracleCell {
            oracle_type: oracle_type.into(),
            value: None,
            bytes: Some(bytes),
        }
    }

    /// The text value, or `None` if SQL NULL.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

/// One result row: ordered `(column_name, cell)` pairs. Column names are
/// upper-cased by Oracle unless quoted; lookups are case-insensitive.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleRow {
    /// The cells, in select-list order.
    pub columns: Vec<(String, OracleCell)>,
}

impl OracleRow {
    /// Find a cell by (case-insensitive) column name.
    #[must_use]
    pub fn cell(&self, name: &str) -> Option<&OracleCell> {
        self.columns
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, c)| c)
    }

    /// The text of a named column, or `None` if absent / NULL.
    #[must_use]
    pub fn text(&self, name: &str) -> Option<&str> {
        self.cell(name).and_then(OracleCell::text)
    }

    /// Parse a named column as `i64` (best-effort).
    #[must_use]
    pub fn parse_i64(&self, name: &str) -> Option<i64> {
        self.text(name).and_then(|s| s.trim().parse::<i64>().ok())
    }
}

/// Describes a live connection (used by `describe`, standby detection §5.8,
/// and `doctor`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleConnectionInfo {
    /// The backend in use.
    #[serde(default)]
    pub backend: Option<OracleBackend>,
    /// The Oracle server version banner.
    pub server_version: Option<String>,
    /// `V$DATABASE.DATABASE_ROLE` (e.g. `PRIMARY`, `PHYSICAL STANDBY`).
    pub database_role: Option<String>,
    /// `V$DATABASE.OPEN_MODE` (e.g. `READ WRITE`, `READ ONLY`).
    pub open_mode: Option<String>,
    /// Derived from `database_role` / `open_mode`: true when the database role
    /// or open mode indicates a physically read-only target. This does not
    /// describe profile ceilings or user grants.
    #[serde(default)]
    pub read_only: bool,
    /// Machine-readable reason for `read_only = true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_reason: Option<String>,
    /// The current schema (`SYS_CONTEXT('USERENV','CURRENT_SCHEMA')`).
    pub current_schema: Option<String>,
    /// The current edition (`SYS_CONTEXT('USERENV','CURRENT_EDITION_NAME')`).
    #[serde(default)]
    pub current_edition: Option<String>,
    /// Oracle session user (`SYS_CONTEXT('USERENV','SESSION_USER')`).
    #[serde(default)]
    pub session_user: Option<String>,
    /// Oracle current user (`SYS_CONTEXT('USERENV','CURRENT_USER')`).
    #[serde(default)]
    pub current_user: Option<String>,
    /// Oracle module (`SYS_CONTEXT('USERENV','MODULE')`).
    #[serde(default)]
    pub module: Option<String>,
    /// Oracle action (`SYS_CONTEXT('USERENV','ACTION')`).
    #[serde(default)]
    pub action: Option<String>,
    /// Oracle client identifier (`SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER')`).
    #[serde(default)]
    pub client_identifier: Option<String>,
    /// Oracle client info (`SYS_CONTEXT('USERENV','CLIENT_INFO')`).
    #[serde(default)]
    pub client_info: Option<String>,
    /// Client OS user as reported by Oracle session context or V$SESSION.
    #[serde(default)]
    pub os_user: Option<String>,
    /// Client host as reported by Oracle session context.
    #[serde(default)]
    pub host: Option<String>,
    /// Client machine as reported by V$SESSION, when visible.
    #[serde(default)]
    pub machine: Option<String>,
    /// Client terminal as reported by Oracle session context or V$SESSION.
    #[serde(default)]
    pub terminal: Option<String>,
    /// Client program as reported by V$SESSION, when visible.
    #[serde(default)]
    pub program: Option<String>,
    /// Client driver as reported by V$SESSION_CONNECT_INFO, when visible.
    #[serde(default)]
    pub client_driver: Option<String>,
}

impl OracleConnectionInfo {
    /// Whether this connection is a physically read-only standby (§5.8): a
    /// non-primary role or a read-only open mode.
    #[must_use]
    pub fn is_read_only_standby(&self) -> bool {
        self.read_only_status().0
    }

    /// Derived database read-only status and a compact reason when true.
    ///
    /// `open_mode` is Oracle's authoritative writability signal: a database open
    /// `READ WRITE` accepts writes even on a non-primary role (e.g. a snapshot
    /// standby), so it is never read-only. Only when the database is not open
    /// read-write do we treat a non-primary role or a `READ ONLY` open mode as
    /// read-only.
    #[must_use]
    pub fn read_only_status(&self) -> (bool, Option<String>) {
        let open_read_write = self
            .open_mode
            .as_deref()
            .is_some_and(|m| m.to_ascii_uppercase().contains("READ WRITE"));
        if !open_read_write {
            if let Some(role) = self.database_role.as_deref()
                && !role.eq_ignore_ascii_case("PRIMARY")
            {
                return (true, Some("database_role_not_primary".to_owned()));
            }
            if let Some(open_mode) = self.open_mode.as_deref()
                && open_mode.to_ascii_uppercase().contains("READ ONLY")
            {
                return (true, Some("open_mode_read_only".to_owned()));
            }
        }
        (false, None)
    }

    /// Populate the serialized read-only fields from role/open-mode metadata.
    #[must_use]
    pub fn with_read_only_status(mut self) -> Self {
        let (read_only, reason) = self.read_only_status();
        self.read_only = read_only;
        self.read_only_reason = reason;
        self
    }
}

/// End-to-end session identity applied to each physical Oracle connection.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleSessionIdentity {
    /// Optional Oracle edition for Edition-Based Redefinition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edition: Option<String>,
    /// Oracle module (`SYS_CONTEXT('USERENV','MODULE')`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// Oracle action (`SYS_CONTEXT('USERENV','ACTION')`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Oracle client identifier (`SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER')`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_identifier: Option<String>,
    /// Oracle client info (`SYS_CONTEXT('USERENV','CLIENT_INFO')`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_info: Option<String>,
    /// Driver name shown by Oracle connection-info views where supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_name: Option<String>,
}

impl OracleSessionIdentity {
    /// Whether no identity fields were configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.edition.is_none()
            && self.module.is_none()
            && self.action.is_none()
            && self.client_identifier.is_none()
            && self.client_info.is_none()
            && self.driver_name.is_none()
    }
}

/// Options for opening a physical Oracle connection. Credentials are referenced
/// here transiently; the full secrets-backend + zeroize discipline (§6.5) lands
/// with the auth layer.
///
/// `Debug` is hand-written: connect material must never reach a log or panic
/// message in plaintext, so values render as redaction markers while preserving
/// presence/absence.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct OracleConnectOptions {
    /// Oracle Net connect identifier (EZConnect / EZConnect-Plus / TNS alias).
    pub connect_string: String,
    /// Username, or `None` for wallet / external / OS / IAM auth.
    pub username: Option<String>,
    /// Password, or `None` for non-password auth. (Plaintext only transiently;
    /// the secrets layer keeps it zeroized end-to-end.)
    pub password: Option<String>,
    /// Use external / wallet auth (`/@alias`) rather than a password.
    pub external_auth: bool,
    /// Cloud wallet directory; folded into an EZConnect-Plus descriptor so the
    /// library never has to mutate `TNS_ADMIN` (which would require `unsafe`
    /// `std::env::set_var` under edition 2024 — forbidden workspace-wide).
    pub wallet_location: Option<PathBuf>,
    /// Authenticate with an OCI IAM database token (P1-11 hardens this path).
    pub use_iam_token: bool,
    /// A pre-fetched OCI IAM database token, when `use_iam_token` is set.
    pub iam_token: Option<String>,
    /// Optional profile-driven session identity.
    pub session_identity: Option<OracleSessionIdentity>,
    /// Optional Oracle per-round-trip call timeout.
    pub call_timeout: Option<Duration>,
    /// Extra guarded session setup statements to run after canonical NLS setup.
    pub session_statements: Vec<String>,
}

impl std::fmt::Debug for OracleConnectOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Presence is preserved (`Some`/`None`) but the secret value is never rendered.
        let redact = |secret: &Option<String>| secret.as_ref().map(|_| "<redacted>");
        let redact_path = |path: &Option<PathBuf>| path.as_ref().map(|_| "<redacted>");
        let connect_string = if self.connect_string.is_empty() {
            None
        } else {
            Some("<redacted>")
        };
        f.debug_struct("OracleConnectOptions")
            .field("connect_string", &connect_string)
            .field("username", &redact(&self.username))
            .field("password", &redact(&self.password))
            .field("external_auth", &self.external_auth)
            .field("wallet_location", &redact_path(&self.wallet_location))
            .field("use_iam_token", &self.use_iam_token)
            .field("iam_token", &redact(&self.iam_token))
            .field("session_identity", &self.session_identity)
            .field("call_timeout", &self.call_timeout)
            .field("session_statements", &self.session_statements)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_from_conversions() {
        assert_eq!(OracleBind::from("x"), OracleBind::String("x".to_owned()));
        assert_eq!(OracleBind::from(5i32), OracleBind::I64(5));
        assert_eq!(OracleBind::from(true), OracleBind::Bool(true));
    }

    #[test]
    fn row_lookup_is_case_insensitive() {
        let row = OracleRow {
            columns: vec![
                (
                    "ID".to_owned(),
                    OracleCell::new("NUMBER", Some("42".to_owned())),
                ),
                ("NAME".to_owned(), OracleCell::new("VARCHAR2", None)),
            ],
        };
        assert_eq!(row.text("id"), Some("42"));
        assert_eq!(row.parse_i64("Id"), Some(42));
        assert_eq!(row.text("name"), None); // NULL
        assert!(row.cell("missing").is_none());
    }

    #[test]
    fn standby_detection() {
        let primary = OracleConnectionInfo {
            database_role: Some("PRIMARY".to_owned()),
            open_mode: Some("READ WRITE".to_owned()),
            ..Default::default()
        };
        assert!(!primary.is_read_only_standby());
        let primary = primary.with_read_only_status();
        assert!(!primary.read_only);
        assert_eq!(primary.read_only_reason, None);

        let standby = OracleConnectionInfo {
            database_role: Some("PHYSICAL STANDBY".to_owned()),
            open_mode: Some("READ ONLY".to_owned()),
            ..Default::default()
        };
        assert!(standby.is_read_only_standby());
        let standby = standby.with_read_only_status();
        assert!(standby.read_only);
        assert_eq!(
            standby.read_only_reason.as_deref(),
            Some("database_role_not_primary")
        );

        let ro_primary = OracleConnectionInfo {
            database_role: Some("PRIMARY".to_owned()),
            open_mode: Some("READ ONLY".to_owned()),
            ..Default::default()
        };
        assert!(ro_primary.is_read_only_standby());
        let ro_primary = ro_primary.with_read_only_status();
        assert!(ro_primary.read_only);
        assert_eq!(
            ro_primary.read_only_reason.as_deref(),
            Some("open_mode_read_only")
        );

        // A snapshot standby is open READ WRITE and physically writable, so it
        // must not be reported read-only despite the non-primary role.
        let snapshot = OracleConnectionInfo {
            database_role: Some("SNAPSHOT STANDBY".to_owned()),
            open_mode: Some("READ WRITE".to_owned()),
            ..Default::default()
        };
        assert!(!snapshot.is_read_only_standby());
        let snapshot = snapshot.with_read_only_status();
        assert!(!snapshot.read_only);
        assert_eq!(snapshot.read_only_reason, None);
    }

    #[test]
    fn debug_redacts_connect_material() {
        let opts = OracleConnectOptions {
            connect_string: "host:1521/svc".to_owned(),
            username: Some("scott".to_owned()),
            password: Some("hunter2-SUPER-SECRET".to_owned()),
            wallet_location: Some("/home/scott/private-wallet".into()),
            use_iam_token: true,
            iam_token: Some("eyJ-IAM-TOKEN-VALUE".to_owned()),
            ..Default::default()
        };
        let rendered = format!("{opts:?}");
        assert!(
            !rendered.contains("host:1521/svc"),
            "connect string leaked: {rendered}"
        );
        assert!(!rendered.contains("scott"), "username leaked: {rendered}");
        assert!(
            !rendered.contains("hunter2-SUPER-SECRET"),
            "password leaked: {rendered}"
        );
        assert!(
            !rendered.contains("/home/scott/private-wallet"),
            "wallet path leaked: {rendered}"
        );
        assert!(
            !rendered.contains("eyJ-IAM-TOKEN-VALUE"),
            "iam_token leaked: {rendered}"
        );
        assert!(rendered.contains("<redacted>"));
        // Presence is preserved without exposing values.
        assert!(rendered.contains("connect_string"));
        assert!(rendered.contains("username: Some"));
        assert!(rendered.contains("password: Some"));
        assert!(rendered.contains("wallet_location: Some"));
        assert!(rendered.contains("iam_token: Some"));
    }

    #[test]
    fn debug_renders_absent_secrets_as_none() {
        let opts = OracleConnectOptions::default();
        let rendered = format!("{opts:?}");
        assert!(rendered.contains("connect_string: None"));
        assert!(rendered.contains("password: None"));
        assert!(rendered.contains("iam_token: None"));
        assert!(!rendered.contains("<redacted>"));
    }
}
