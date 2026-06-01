//! Backend-independent value, row, and connect-option types (plan §5.2).
//!
//! These are deliberately driver-free so the offline build (no `oracle-driver`)
//! still compiles the full type surface. P0-3 fetches cells as nullable text
//! plus the Oracle type name; the deterministic NUMBER→string / ISO-8601 / NLS
//! serializer (P0-5) builds the precise JSON mapping on top.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The connectivity backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OracleBackend {
    /// The `oracle` crate (kubo/rust-oracle) over ODPI-C / Instant Client.
    RustOracle,
}

impl std::fmt::Display for OracleBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OracleBackend::RustOracle => f.write_str("rust-oracle"),
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
}

impl OracleCell {
    /// Construct a cell.
    #[must_use]
    pub fn new(oracle_type: impl Into<String>, value: Option<String>) -> Self {
        OracleCell {
            oracle_type: oracle_type.into(),
            value,
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
    /// The current schema (`SYS_CONTEXT('USERENV','CURRENT_SCHEMA')`).
    pub current_schema: Option<String>,
}

impl OracleConnectionInfo {
    /// Whether this connection is a physically read-only standby (§5.8): a
    /// non-primary role or a read-only open mode.
    #[must_use]
    pub fn is_read_only_standby(&self) -> bool {
        let role_standby = self
            .database_role
            .as_deref()
            .is_some_and(|r| !r.eq_ignore_ascii_case("PRIMARY"));
        let mode_ro = self
            .open_mode
            .as_deref()
            .is_some_and(|m| m.to_ascii_uppercase().contains("READ ONLY"));
        role_standby || mode_ro
    }
}

/// Options for opening a physical Oracle connection. Credentials are referenced
/// here transiently; the full secrets-backend + zeroize discipline (§6.5) lands
/// with the auth layer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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

        let standby = OracleConnectionInfo {
            database_role: Some("PHYSICAL STANDBY".to_owned()),
            open_mode: Some("READ ONLY".to_owned()),
            ..Default::default()
        };
        assert!(standby.is_read_only_standby());

        let ro_primary = OracleConnectionInfo {
            database_role: Some("PRIMARY".to_owned()),
            open_mode: Some("READ ONLY".to_owned()),
            ..Default::default()
        };
        assert!(ro_primary.is_read_only_standby());
    }
}
