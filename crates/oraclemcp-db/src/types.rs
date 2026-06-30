//! Backend-independent value, row, and connect-option types (plan §5.2).
//!
//! These are deliberately driver-free at the boundary. P0-3 fetches cells as
//! nullable text plus the Oracle type name; the deterministic NUMBER→string /
//! ISO-8601 / NLS serializer (P0-5) builds the precise JSON mapping on top.

use std::{fmt, path::PathBuf, time::Duration};

use serde::ser::{SerializeSeq, SerializeStruct};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth_adapter::AuthAdapter;

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
#[derive(Clone, PartialEq, Serialize, Deserialize)]
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
    /// `TIMESTAMP WITH TIME ZONE`, preserving the numeric UTC offset.
    TimestampTz {
        /// Calendar year.
        year: i32,
        /// Calendar month, 1-12.
        month: u8,
        /// Calendar day, 1-31.
        day: u8,
        /// Hour, 0-23.
        hour: u8,
        /// Minute, 0-59.
        minute: u8,
        /// Second, 0-59.
        second: u8,
        /// Fractional second in nanoseconds.
        nanosecond: u32,
        /// UTC offset in minutes, e.g. `-330` for `-05:30`.
        offset_minutes: i32,
    },
}

impl OracleBind {
    /// The bind variant without its value. This is safe for logs, audit
    /// metadata, telemetry, and proof bundles.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            OracleBind::Null => "null",
            OracleBind::String(_) => "string",
            OracleBind::I64(_) => "i64",
            OracleBind::F64(_) => "f64",
            OracleBind::Bool(_) => "bool",
            OracleBind::TimestampTz { .. } => "timestamp_tz",
        }
    }

    /// Return a wrapper that serializes and formats this bind without exposing
    /// its value.
    #[must_use]
    pub const fn redacted(&self) -> RedactedOracleBind<'_> {
        RedactedOracleBind(self)
    }
}

impl fmt::Debug for OracleBind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(f)
    }
}

/// Redacting formatter/serializer for a single Oracle bind value.
#[derive(Clone, Copy)]
pub struct RedactedOracleBind<'a>(&'a OracleBind);

impl fmt::Debug for RedactedOracleBind<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OracleBind")
            .field("kind", &self.0.kind())
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Serialize for RedactedOracleBind<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("RedactedOracleBind", 2)?;
        state.serialize_field("kind", self.0.kind())?;
        state.serialize_field("redacted", &true)?;
        state.end()
    }
}

/// Redacting formatter/serializer for positional bind lists.
#[derive(Clone, Copy)]
pub struct RedactedOracleBinds<'a>(&'a [OracleBind]);

/// Return a wrapper that serializes and formats positional binds without
/// exposing their values.
#[must_use]
pub const fn redacted_oracle_binds(binds: &[OracleBind]) -> RedactedOracleBinds<'_> {
    RedactedOracleBinds(binds)
}

impl fmt::Debug for RedactedOracleBinds<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(OracleBind::redacted))
            .finish()
    }
}

impl Serialize for RedactedOracleBinds<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for bind in self.0 {
            seq.serialize_element(&bind.redacted())?;
        }
        seq.end()
    }
}

/// Redacting formatter/serializer for named bind lists.
#[derive(Clone, Copy)]
pub struct RedactedNamedOracleBinds<'a>(&'a [(String, OracleBind)]);

/// Return a wrapper that serializes and formats named binds without exposing
/// their values.
#[must_use]
pub const fn redacted_named_oracle_binds(
    binds: &[(String, OracleBind)],
) -> RedactedNamedOracleBinds<'_> {
    RedactedNamedOracleBinds(binds)
}

struct RedactedNamedBindEntry<'a> {
    name: &'a str,
    bind: &'a OracleBind,
}

impl fmt::Debug for RedactedNamedBindEntry<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OracleBind")
            .field("name", &self.name)
            .field("kind", &self.bind.kind())
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Serialize for RedactedNamedBindEntry<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("RedactedNamedOracleBind", 3)?;
        state.serialize_field("name", self.name)?;
        state.serialize_field("kind", self.bind.kind())?;
        state.serialize_field("redacted", &true)?;
        state.end()
    }
}

impl fmt::Debug for RedactedNamedOracleBinds<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(
                self.0
                    .iter()
                    .map(|(name, bind)| RedactedNamedBindEntry { name, bind }),
            )
            .finish()
    }
}

impl Serialize for RedactedNamedOracleBinds<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for (name, bind) in self.0 {
            seq.serialize_element(&RedactedNamedBindEntry { name, bind })?;
        }
        seq.end()
    }
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

/// Current contract version for structured [`OracleCell`] payloads.
///
/// Cache keys for metadata/schema consumers include this value so a structured
/// serialization shape bump invalidates stale cached views deterministically.
pub const ORACLE_CELL_STRUCTURED_CONTRACT_VERSION: u16 = 1;

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
    /// Structured JSON payload for typed non-scalar values. When present, the
    /// serializer emits this value verbatim instead of flattening through text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured: Option<Value>,
    /// Contract version of the structured payload, present only when
    /// [`OracleCell::structured`] constructs the cell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_contract_version: Option<u16>,
    /// Internal full-source length hint for bounded LOB reads: characters for
    /// CLOB/NCLOB text, bytes for binary LOBs. It is folded into serialized
    /// truncation metadata instead of exposed directly.
    #[serde(skip)]
    pub source_length: Option<usize>,
    /// Nested REF CURSOR / implicit result-set payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nested_result: Option<Box<OracleNestedResult>>,
}

impl OracleCell {
    /// Construct a text cell.
    #[must_use]
    pub fn new(oracle_type: impl Into<String>, value: Option<String>) -> Self {
        OracleCell {
            oracle_type: oracle_type.into(),
            value,
            bytes: None,
            structured: None,
            structured_contract_version: None,
            source_length: None,
            nested_result: None,
        }
    }

    /// Construct a binary cell carrying raw bytes (BLOB / RAW).
    #[must_use]
    pub fn binary(oracle_type: impl Into<String>, bytes: Vec<u8>) -> Self {
        OracleCell {
            oracle_type: oracle_type.into(),
            value: None,
            bytes: Some(bytes),
            structured: None,
            structured_contract_version: None,
            source_length: None,
            nested_result: None,
        }
    }

    /// Construct a cell carrying a structured JSON representation.
    #[must_use]
    pub fn structured(oracle_type: impl Into<String>, value: Value) -> Self {
        OracleCell {
            oracle_type: oracle_type.into(),
            value: None,
            bytes: None,
            structured: Some(value),
            structured_contract_version: Some(ORACLE_CELL_STRUCTURED_CONTRACT_VERSION),
            source_length: None,
            nested_result: None,
        }
    }

    /// Construct a nested result-set cell.
    #[must_use]
    pub fn nested_result(oracle_type: impl Into<String>, result: OracleNestedResult) -> Self {
        OracleCell {
            oracle_type: oracle_type.into(),
            value: None,
            bytes: None,
            structured: None,
            structured_contract_version: None,
            source_length: None,
            nested_result: Some(Box::new(result)),
        }
    }

    /// The text value, or `None` if SQL NULL.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        self.value.as_deref()
    }

    /// Attach the original LOB length when the stored value is a capped prefix.
    #[must_use]
    pub fn with_source_length(mut self, source_length: usize) -> Self {
        self.source_length = Some(source_length);
        self
    }
}

/// A bounded nested result set from a REF CURSOR or implicit result.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleNestedResult {
    /// Child cursor columns in select-list order.
    pub columns: Vec<String>,
    /// Fetched child rows, already capped by the backend.
    pub rows: Vec<OracleRow>,
    /// Rows returned after serialization caps are applied.
    pub row_count: usize,
    /// Rows fetched from the child cursor before serialization byte caps.
    pub fetched_count: usize,
    /// Whether row, cell, byte, or nesting caps stopped materialization.
    pub truncated: bool,
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
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleConnectionInfo {
    /// The backend in use.
    #[serde(default)]
    pub backend: Option<OracleBackend>,
    /// Runtime connection strategy, e.g. `single_session` or `hybrid_pool`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_strategy: Option<String>,
    /// Number of currently open stateless read-pool connections, when pooled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_open_connections: Option<u32>,
    /// The Oracle server version banner.
    pub server_version: Option<String>,
    /// `V$DATABASE.DATABASE_ROLE` (e.g. `PRIMARY`, `PHYSICAL STANDBY`).
    pub database_role: Option<String>,
    /// `V$DATABASE.OPEN_MODE` (e.g. `READ WRITE`, `READ ONLY`).
    pub open_mode: Option<String>,
    /// `V$DATABASE.DB_UNIQUE_NAME`, when visible.
    #[serde(default)]
    pub db_unique_name: Option<String>,
    /// Current service name, when visible.
    #[serde(default)]
    pub service_name: Option<String>,
    /// Current instance name, when visible.
    #[serde(default)]
    pub instance_name: Option<String>,
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
    /// Oracle proxy user (`SYS_CONTEXT('USERENV','PROXY_USER')`), when proxy
    /// authentication is in effect.
    #[serde(default)]
    pub proxy_user: Option<String>,
    /// Current Oracle session id (`V$SESSION.SID`), when visible.
    #[serde(default)]
    pub sid: Option<String>,
    /// Current Oracle session serial number (`V$SESSION.SERIAL#`), when visible.
    #[serde(default)]
    pub serial_number: Option<String>,
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
    /// Return a wrapper that serializes and formats only allow-listed connection
    /// metadata. Session identity and client topology values are represented as
    /// redacted field names, never as values.
    #[must_use]
    pub const fn redacted(&self) -> RedactedOracleConnectionInfo<'_> {
        RedactedOracleConnectionInfo(self)
    }

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

impl fmt::Debug for OracleConnectionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(f)
    }
}

/// Redacting formatter/serializer for live Oracle connection metadata.
#[derive(Clone, Copy)]
pub struct RedactedOracleConnectionInfo<'a>(&'a OracleConnectionInfo);

type ConnectionInfoRedactionPredicate = fn(&OracleConnectionInfo) -> bool;
type ConnectionInfoRedactionField = (&'static str, ConnectionInfoRedactionPredicate);

const CONNECTION_INFO_REDACTED_FIELDS: [ConnectionInfoRedactionField; 20] = [
    ("db_unique_name", |info| info.db_unique_name.is_some()),
    ("service_name", |info| info.service_name.is_some()),
    ("instance_name", |info| info.instance_name.is_some()),
    ("current_schema", |info| info.current_schema.is_some()),
    ("current_edition", |info| info.current_edition.is_some()),
    ("session_user", |info| info.session_user.is_some()),
    ("current_user", |info| info.current_user.is_some()),
    ("proxy_user", |info| info.proxy_user.is_some()),
    ("sid", |info| info.sid.is_some()),
    ("serial_number", |info| info.serial_number.is_some()),
    ("module", |info| info.module.is_some()),
    ("action", |info| info.action.is_some()),
    ("client_identifier", |info| info.client_identifier.is_some()),
    ("client_info", |info| info.client_info.is_some()),
    ("os_user", |info| info.os_user.is_some()),
    ("host", |info| info.host.is_some()),
    ("machine", |info| info.machine.is_some()),
    ("terminal", |info| info.terminal.is_some()),
    ("program", |info| info.program.is_some()),
    ("client_driver", |info| info.client_driver.is_some()),
];

impl RedactedOracleConnectionInfo<'_> {
    fn redacted_fields(&self) -> Vec<&'static str> {
        CONNECTION_INFO_REDACTED_FIELDS
            .iter()
            .filter_map(|(field, has_value)| has_value(self.0).then_some(*field))
            .collect()
    }
}

impl fmt::Debug for RedactedOracleConnectionInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let info = self.0;
        f.debug_struct("OracleConnectionInfo")
            .field("backend", &info.backend)
            .field("connection_strategy", &info.connection_strategy)
            .field("pool_open_connections", &info.pool_open_connections)
            .field("server_version", &info.server_version)
            .field("database_role", &info.database_role)
            .field("open_mode", &info.open_mode)
            .field("read_only", &info.read_only)
            .field("read_only_reason", &info.read_only_reason)
            .field("redacted_fields", &self.redacted_fields())
            .finish()
    }
}

impl Serialize for RedactedOracleConnectionInfo<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let info = self.0;
        let redacted_fields = self.redacted_fields();
        let mut state = serializer.serialize_struct("RedactedOracleConnectionInfo", 9)?;
        state.serialize_field("backend", &info.backend)?;
        state.serialize_field("connection_strategy", &info.connection_strategy)?;
        state.serialize_field("pool_open_connections", &info.pool_open_connections)?;
        state.serialize_field("server_version", &info.server_version)?;
        state.serialize_field("database_role", &info.database_role)?;
        state.serialize_field("open_mode", &info.open_mode)?;
        state.serialize_field("read_only", &info.read_only)?;
        state.serialize_field("read_only_reason", &info.read_only_reason)?;
        state.serialize_field("redacted_fields", &redacted_fields)?;
        state.end()
    }
}

/// End-to-end session identity applied to each physical Oracle connection.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleSessionIdentity {
    /// Optional Oracle edition for Edition-Based Redefinition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edition: Option<String>,
    /// Connect-time client program recorded by Oracle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    /// Connect-time client machine recorded by Oracle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    /// Connect-time operating-system user recorded by Oracle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_user: Option<String>,
    /// Connect-time terminal recorded by Oracle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<String>,
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
            && self.program.is_none()
            && self.machine.is_none()
            && self.os_user.is_none()
            && self.terminal.is_none()
            && self.module.is_none()
            && self.action.is_none()
            && self.client_identifier.is_none()
            && self.client_info.is_none()
            && self.driver_name.is_none()
    }
}

/// Default Oracle call timeout for direct `oraclemcp-db` callers.
///
/// Profile-backed callers resolve the same 30-second default through
/// `oraclemcp-core`; this shared-layer default protects consumers that build
/// [`OracleConnectOptions`] directly with [`Default::default`].
pub const DEFAULT_ORACLE_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Options for opening a physical Oracle connection. Credentials and
/// profile-owned setup statements may be present transiently after secret
/// resolution; `Debug` must never expose their values.
///
/// `Debug` is hand-written: connect material must never reach a log or panic
/// message in plaintext, so values render as redaction markers while preserving
/// presence/absence.
#[derive(Clone, PartialEq, Eq)]
pub struct OracleConnectOptions {
    /// Oracle Net connect identifier (EZConnect / EZConnect-Plus / TNS alias).
    pub connect_string: String,
    /// Username, or `None` for wallet / external / OS / IAM auth.
    pub username: Option<String>,
    /// Password, or `None` for non-password auth. Plaintext is resolved by the
    /// caller and must never be logged.
    pub password: Option<String>,
    /// Enterprise authentication mode. Password is the default; proxy auth is
    /// supported by the thin driver and still authenticates with `password`.
    pub auth_adapter: AuthAdapter,
    /// Use external / wallet auth (`/@alias`) rather than a password.
    pub external_auth: bool,
    /// Cloud wallet directory; folded into an EZConnect-Plus descriptor so the
    /// library never has to mutate `TNS_ADMIN` (which would require `unsafe`
    /// `std::env::set_var` under edition 2024 — forbidden workspace-wide).
    pub wallet_location: Option<PathBuf>,
    /// Password for encrypted TCPS wallets. Plaintext only transiently after
    /// resolving `wallet_password_ref`; never sourced directly from profile TOML.
    pub wallet_password: Option<String>,
    /// Override Oracle server-DN match. `None` keeps the driver's default.
    pub ssl_server_dn_match: Option<bool>,
    /// Explicit expected server certificate DN. Treated as topology-sensitive.
    pub ssl_server_cert_dn: Option<String>,
    /// Override Oracle TCPS SNI behavior. `None` preserves oraclemcp defaults.
    pub use_sni: Option<bool>,
    /// Authenticate with an OCI IAM database token (P1-11 hardens this path).
    pub use_iam_token: bool,
    /// A pre-fetched OCI IAM database token, when `use_iam_token` is set.
    pub iam_token: Option<String>,
    /// Optional profile-driven session identity.
    pub session_identity: Option<OracleSessionIdentity>,
    /// Application-context triples applied by the thin driver during logon.
    pub app_context: Vec<(String, String, String)>,
    /// Optional Session Data Unit request size. `None` keeps the driver's default.
    pub sdu: Option<u32>,
    /// Optional statement-cache size. `None` keeps the driver's default.
    pub statement_cache_size: Option<u32>,
    /// Oracle per-round-trip call timeout. Defaults to
    /// [`DEFAULT_ORACLE_CALL_TIMEOUT`]; set `None` only for an explicit
    /// operator-controlled opt-out.
    pub call_timeout: Option<Duration>,
    /// Extra guarded session setup statements to run after canonical NLS setup.
    pub session_statements: Vec<String>,
}

impl Default for OracleConnectOptions {
    fn default() -> Self {
        Self {
            connect_string: String::new(),
            username: None,
            password: None,
            auth_adapter: AuthAdapter::default(),
            external_auth: false,
            wallet_location: None,
            wallet_password: None,
            ssl_server_dn_match: None,
            ssl_server_cert_dn: None,
            use_sni: None,
            use_iam_token: false,
            iam_token: None,
            session_identity: None,
            app_context: Vec::new(),
            sdu: None,
            statement_cache_size: None,
            call_timeout: Some(DEFAULT_ORACLE_CALL_TIMEOUT),
            session_statements: Vec::new(),
        }
    }
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
        let session_identity = self.session_identity.as_ref().map(|_| "<redacted>");
        let app_context_count = self.app_context.len();
        let session_statement_count = self.session_statements.len();
        f.debug_struct("OracleConnectOptions")
            .field("connect_string", &connect_string)
            .field("username", &redact(&self.username))
            .field("password", &redact(&self.password))
            .field("auth_adapter", &self.auth_adapter)
            .field("external_auth", &self.external_auth)
            .field("wallet_location", &redact_path(&self.wallet_location))
            .field("wallet_password", &redact(&self.wallet_password))
            .field("ssl_server_dn_match", &self.ssl_server_dn_match)
            .field("ssl_server_cert_dn", &redact(&self.ssl_server_cert_dn))
            .field("use_sni", &self.use_sni)
            .field("use_iam_token", &self.use_iam_token)
            .field("iam_token", &redact(&self.iam_token))
            .field("session_identity", &session_identity)
            .field("app_context_count", &app_context_count)
            .field("sdu", &self.sdu)
            .field("statement_cache_size", &self.statement_cache_size)
            .field("call_timeout", &self.call_timeout)
            .field("session_statement_count", &session_statement_count)
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
    fn bind_debug_and_redacted_json_never_expose_values() {
        let binds = vec![
            OracleBind::String("n-s6-bind-secret-not-in-rendered-surfaces".to_owned()),
            OracleBind::I64(987_654_321),
            OracleBind::F64(12345.6789),
            OracleBind::Bool(false),
            OracleBind::TimestampTz {
                year: 2026,
                month: 6,
                day: 29,
                hour: 12,
                minute: 34,
                second: 56,
                nanosecond: 987_654_321,
                offset_minutes: -330,
            },
            OracleBind::Null,
        ];
        let rendered_debug = format!("{binds:?}");
        let rendered_json = serde_json::to_string(&redacted_oracle_binds(&binds))
            .expect("redacted positional binds serialize");
        let named_binds = vec![("p_payload".to_owned(), binds[0].clone())];
        let rendered_named_debug = format!("{:?}", redacted_named_oracle_binds(&named_binds));
        let rendered_named_json = serde_json::to_string(&redacted_named_oracle_binds(&named_binds))
            .expect("redacted named binds serialize");
        let rendered = format!(
            "{rendered_debug}\n{rendered_json}\n{rendered_named_debug}\n{rendered_named_json}"
        );

        for forbidden in [
            "n-s6-bind-secret-not-in-rendered-surfaces",
            "987654321",
            "12345.6789",
            "false",
            "2026",
            "-330",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "{forbidden} leaked: {rendered}"
            );
        }
        for kind in ["string", "i64", "f64", "bool", "timestamp_tz", "null"] {
            assert!(rendered.contains(kind), "{kind} missing from {rendered}");
        }
        assert!(rendered.contains("<redacted>"));
        assert!(rendered_json.contains("\"redacted\":true"));
    }

    #[test]
    fn connection_info_debug_and_redacted_json_are_allowlist_first() {
        let info = OracleConnectionInfo {
            backend: Some(OracleBackend::RustOracle),
            connection_strategy: Some("hybrid_pool".to_owned()),
            pool_open_connections: Some(3),
            server_version: Some("Oracle Database 23ai Free".to_owned()),
            database_role: Some("PRIMARY".to_owned()),
            open_mode: Some("READ WRITE".to_owned()),
            db_unique_name: Some("N_S6_DB_UNIQUE_NAME_SECRET".to_owned()),
            service_name: Some("N_S6_SERVICE_NAME_SECRET".to_owned()),
            instance_name: Some("N_S6_INSTANCE_NAME_SECRET".to_owned()),
            read_only: false,
            read_only_reason: None,
            current_schema: Some("N_S6_CURRENT_SCHEMA_SECRET".to_owned()),
            current_edition: Some("N_S6_EDITION_SECRET".to_owned()),
            session_user: Some("N_S6_SESSION_USER_SECRET".to_owned()),
            current_user: Some("N_S6_CURRENT_USER_SECRET".to_owned()),
            proxy_user: Some("N_S6_PROXY_USER_SECRET".to_owned()),
            sid: Some("N_S6_SID_SECRET".to_owned()),
            serial_number: Some("N_S6_SERIAL_NUMBER_SECRET".to_owned()),
            module: Some("N_S6_MODULE_SECRET".to_owned()),
            action: Some("N_S6_ACTION_SECRET".to_owned()),
            client_identifier: Some("N_S6_CLIENT_IDENTIFIER_SECRET".to_owned()),
            client_info: Some("N_S6_CLIENT_INFO_SECRET".to_owned()),
            os_user: Some("N_S6_OS_USER_SECRET".to_owned()),
            host: Some("N_S6_HOST_SECRET".to_owned()),
            machine: Some("N_S6_MACHINE_SECRET".to_owned()),
            terminal: Some("N_S6_TERMINAL_SECRET".to_owned()),
            program: Some("N_S6_PROGRAM_SECRET".to_owned()),
            client_driver: Some("N_S6_CLIENT_DRIVER_SECRET".to_owned()),
        };
        let rendered_debug = format!("{info:?}");
        let rendered_json =
            serde_json::to_string(&info.redacted()).expect("redacted connection info serializes");
        let rendered = format!("{rendered_debug}\n{rendered_json}");

        for forbidden in [
            "N_S6_CURRENT_SCHEMA_SECRET",
            "N_S6_EDITION_SECRET",
            "N_S6_SESSION_USER_SECRET",
            "N_S6_CURRENT_USER_SECRET",
            "N_S6_PROXY_USER_SECRET",
            "N_S6_SID_SECRET",
            "N_S6_SERIAL_NUMBER_SECRET",
            "N_S6_DB_UNIQUE_NAME_SECRET",
            "N_S6_SERVICE_NAME_SECRET",
            "N_S6_INSTANCE_NAME_SECRET",
            "N_S6_MODULE_SECRET",
            "N_S6_ACTION_SECRET",
            "N_S6_CLIENT_IDENTIFIER_SECRET",
            "N_S6_CLIENT_INFO_SECRET",
            "N_S6_OS_USER_SECRET",
            "N_S6_HOST_SECRET",
            "N_S6_MACHINE_SECRET",
            "N_S6_TERMINAL_SECRET",
            "N_S6_PROGRAM_SECRET",
            "N_S6_CLIENT_DRIVER_SECRET",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "{forbidden} leaked: {rendered}"
            );
        }
        for allowed in [
            "hybrid_pool",
            "Oracle Database 23ai Free",
            "PRIMARY",
            "READ WRITE",
            "pool_open_connections",
            "read_only",
        ] {
            assert!(
                rendered.contains(allowed),
                "{allowed} missing from {rendered}"
            );
        }
        for redacted_field in [
            "db_unique_name",
            "service_name",
            "instance_name",
            "current_schema",
            "current_edition",
            "session_user",
            "current_user",
            "proxy_user",
            "sid",
            "serial_number",
            "module",
            "action",
            "client_identifier",
            "client_info",
            "os_user",
            "host",
            "machine",
            "terminal",
            "program",
            "client_driver",
        ] {
            assert!(
                rendered_json.contains(redacted_field),
                "{redacted_field} missing from {rendered_json}"
            );
        }
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
            auth_adapter: AuthAdapter::Proxy {
                proxy_user: "MCP_PROXY".to_owned(),
                target_schema: "APP_OWNER".to_owned(),
            },
            wallet_location: Some("/home/scott/private-wallet".into()),
            wallet_password: Some("wallet-password-SUPER-SECRET".to_owned()),
            ssl_server_dn_match: Some(false),
            ssl_server_cert_dn: Some("CN=private-db,O=Example,C=US".to_owned()),
            use_sni: Some(false),
            use_iam_token: true,
            iam_token: Some("eyJ-IAM-TOKEN-VALUE".to_owned()),
            app_context: vec![(
                "private-namespace".to_owned(),
                "private-key".to_owned(),
                "private-value".to_owned(),
            )],
            sdu: Some(32_768),
            session_statements: vec![
                "BEGIN DBMS_SESSION.SET_CONTEXT('PRIVATE_NS','TOKEN','secret-token'); END;"
                    .to_owned(),
            ],
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
            !rendered.contains("MCP_PROXY") && !rendered.contains("APP_OWNER"),
            "proxy auth leaked: {rendered}"
        );
        assert!(
            !rendered.contains("/home/scott/private-wallet"),
            "wallet path leaked: {rendered}"
        );
        assert!(
            !rendered.contains("wallet-password-SUPER-SECRET"),
            "wallet password leaked: {rendered}"
        );
        assert!(
            !rendered.contains("CN=private-db"),
            "server DN leaked: {rendered}"
        );
        assert!(
            !rendered.contains("eyJ-IAM-TOKEN-VALUE"),
            "iam_token leaked: {rendered}"
        );
        assert!(
            !rendered.contains("private-namespace")
                && !rendered.contains("private-key")
                && !rendered.contains("private-value"),
            "app_context leaked: {rendered}"
        );
        assert!(
            !rendered.contains("secret-token") && !rendered.contains("PRIVATE_NS"),
            "session statement leaked: {rendered}"
        );
        assert!(rendered.contains("<redacted>"));
        // Presence is preserved without exposing values.
        assert!(rendered.contains("connect_string"));
        assert!(rendered.contains("username: Some"));
        assert!(rendered.contains("password: Some"));
        assert!(rendered.contains("auth_adapter"));
        assert!(rendered.contains("AuthAdapter::Proxy"));
        assert!(rendered.contains("wallet_location: Some"));
        assert!(rendered.contains("wallet_password: Some"));
        assert!(rendered.contains("ssl_server_dn_match: Some"));
        assert!(rendered.contains("ssl_server_cert_dn: Some"));
        assert!(rendered.contains("use_sni: Some"));
        assert!(rendered.contains("iam_token: Some"));
        assert!(rendered.contains("app_context_count: 1"));
        assert!(rendered.contains("sdu: Some(32768)"));
        assert!(rendered.contains("session_statement_count: 1"));
    }

    #[test]
    fn debug_renders_absent_secrets_as_none() {
        let opts = OracleConnectOptions::default();
        let rendered = format!("{opts:?}");
        assert!(rendered.contains("connect_string: None"));
        assert!(rendered.contains("password: None"));
        assert!(rendered.contains("wallet_password: None"));
        assert!(rendered.contains("ssl_server_cert_dn: None"));
        assert!(rendered.contains("iam_token: None"));
        assert!(rendered.contains("app_context_count: 0"));
        assert!(rendered.contains("sdu: None"));
        assert!(rendered.contains("session_statement_count: 0"));
        assert!(!rendered.contains("<redacted>"));
    }

    #[test]
    fn default_connect_options_bound_oracle_calls() {
        assert_eq!(
            OracleConnectOptions::default().call_timeout,
            Some(DEFAULT_ORACLE_CALL_TIMEOUT)
        );
    }

    #[test]
    fn debug_redacts_session_identity_values() {
        let opts = OracleConnectOptions {
            session_identity: Some(OracleSessionIdentity {
                program: Some("private-program".to_owned()),
                machine: Some("private-machine".to_owned()),
                os_user: Some("private-os-user".to_owned()),
                terminal: Some("private-terminal".to_owned()),
                module: Some("private-module".to_owned()),
                client_identifier: Some("private-client-id".to_owned()),
                client_info: Some("private-client-info".to_owned()),
                driver_name: Some("private-driver".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let rendered = format!("{opts:?}");
        for forbidden in [
            "private-program",
            "private-machine",
            "private-os-user",
            "private-terminal",
            "private-module",
            "private-client-id",
            "private-client-info",
            "private-driver",
        ] {
            assert!(!rendered.contains(forbidden), "{rendered}");
        }
        assert!(rendered.contains("session_identity: Some"));
        assert!(rendered.contains("<redacted>"));
    }
}
