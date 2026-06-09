#![forbid(unsafe_code)]

//! Oracle connectivity for the `oraclemcp` server (plan §4.3, §5.1, §5.2; bead
//! P0-3).
//!
//! Layers:
//! - [`OracleConnection`] — the backend-independent sync connection trait, with
//!   the `oracle`-crate-backed [`RustOracleConnection`].
//! - `OraclePool` — an `r2d2` pool behind a `tokio::task::spawn_blocking`
//!   boundary so DB I/O never blocks the async executor and an
//!   `oracle::Connection` is never held across an `.await` (`oracle-driver`).
//! - [`detect_instant_client`] — the offline-safe Instant Client posture probe
//!   for `doctor`.
//!
//! The session-lease primitive (P0-4) and the deterministic NUMBER→string /
//! ISO-8601 / NLS serializer (P0-5) build on these.

mod auth_adapter;
mod awr;
mod connection;
mod doctor;
mod drcp;
mod error;
mod intelligence;
mod lease;
mod oci;
mod plscope;
mod privileges;
mod query;
mod schema_diff;
mod serialize;
mod standby;
mod types;

#[cfg(feature = "oracle-driver")]
mod pool;

pub use auth_adapter::{AuthAdapter, AuthAdapterError};
pub use awr::{DiagnosticsSource, detect_statspack, select_diagnostics_source, top_sql_query};
pub use connection::{OracleConnection, RustOracleConnection};
pub use doctor::{InstantClientPosture, detect_instant_client, oracle_driver_compiled};
pub use drcp::{DrcpConfig, SessionPurity};
pub use error::DbError;
pub use intelligence::{
    IndexDescription, LobText, SourceText, TriggerDescription, ViewDescription, compile_errors,
    describe_columns, describe_index, describe_trigger, describe_view, explain_plan, get_ddl,
    get_source, is_ddl_object_type, list_objects, normalize_source_object_type, read_lob,
    sample_rows, search_source,
};
pub use lease::{LeaseId, LeaseInfo, LeaseManager, PreviewImpact, require_lease_id};
pub use oci::{
    AdbConnectInfo, CloudStatus, IamToken, IamTokenSource, OciError, WalletContents,
    classify_wallet, discover_wallet, ensure_fresh_token, validate_adb_connect_string,
};
pub use plscope::{
    PlscopeIdentifier, PlscopeStatement, execute_immediate_audit, find_unused_declarations,
    plscope_identifiers, plscope_statements, recompile_with_plscope_statements,
};
pub use privileges::{
    DictionaryTier, PrivilegeProfile, ToolRequirement, probe_privileges, requirement_matrix,
};
pub use query::{QueryCaps, QueryResponse, cursor_to_offset, paginated_sql, read_query};
pub use schema_diff::{
    ChangeKind, MigrationStep, SchemaDiff, SchemaObject, SchemaSnapshot, StepKind, compare_schemas,
    migration_plan,
};
pub use serialize::{
    SerializeOptions, TypeRepr, base64_encode, canonical_nls_statements, canonicalize_datetime,
    classify_type, serialize_cell, serialize_row,
};
pub use standby::{StandbyStatus, detect_standby};
pub use types::{
    OracleBackend, OracleBind, OracleCell, OracleConnectOptions, OracleConnectionInfo, OracleRow,
};

#[cfg(feature = "oracle-driver")]
pub use pool::{OracleConnectionManager, OraclePool, PoolSettings};

/// Re-export the shared agent-facing error envelope.
pub use oraclemcp_error as error_envelope;
