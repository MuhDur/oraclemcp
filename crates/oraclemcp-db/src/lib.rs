#![forbid(unsafe_code)]
// The canonical shared foundation (ADR-0006) is a product API: every public
// item carries rustdoc, enforced here so the surface never silently grows an
// undocumented item.
#![deny(missing_docs)]

//! Oracle connectivity for the `oraclemcp` server (plan §4.3, §5.1, §5.2; bead
//! P0-3) — and the **canonical shared Oracle foundation** for the two-binary
//! family (ADR-0006).
//!
//! # Canonical foundation (ADR-0006)
//!
//! `oraclemcp-db` is the single, deliberately-governed home for the
//! correctness-critical Oracle layer that both `oraclemcp` and the sibling
//! PL/SQL-intelligence superset (`plsql-mcp`) build on: thin connectivity, the
//! NLS-stable serializer with NUMBER→string fidelity, dictionary operations,
//! session leases, and the connection pool. `plsql-mcp` converges onto this
//! crate (and the other engine-free spine crates `oraclemcp-error` /
//! `oraclemcp-guard`) rather than carrying its own copies; its added value
//! (offline PL/SQL parse/analyze, lineage, SAST) layers *on top*. Because this
//! surface has two consumers, the public API below is treated as a product: it
//! is snapshot-locked in CI (`cargo public-api` baseline +
//! `cargo semver-checks`, see ADR-0002) so an unintended breaking change is
//! caught before it reaches `plsql-mcp`.
//!
//! The crate imports **no** PL/SQL analysis engine — the one-way engine-free
//! dependency boundary CI enforces (`scripts/oraclemcp_boundary_lint.sh`).
//!
//! # Layers
//!
//! - [`OracleConnection`] — the backend-independent connection trait, with the
//!   thin [`oracledb`]-backed [`RustOracleConnection`]. The trait is `async`
//!   and `Cx`-first (B1): every method takes an explicit `&asupersync::Cx` so
//!   cancellation and the deadline/budget travel with the call, and each round
//!   trip is bracketed by explicit `Cx` checkpoints (the native-async
//!   [`oracledb`] driver also checkpoints `cx` internally). Every real
//!   [`oracledb`] driver call is confined to the adapter seam (`connection.rs`,
//!   ADR-0002), so no driver type leaks into this public surface — callers
//!   depend only on the `oraclemcp-db` types below.
//! - [`OraclePool`] — a bounded pure-Rust thin session pool.
//! - [`detect_oracle_driver`] — thin-driver posture data for `doctor`; thin
//!   mode never requires Instant Client.
//!
//! The session-lease primitive (P0-4) and the deterministic NUMBER→string /
//! ISO-8601 / NLS serializer (P0-5) build on these.
//!
//! # Stability
//!
//! The crate follows SemVer once published. The accepted published-spine
//! dependency on `oraclemcp-error` is part of the locked surface, not pretended
//! away: it is re-exported as [`error_envelope`] and its [`ErrorEnvelope`]
//! type appears in return positions (e.g. [`DbError::into_envelope`]), so a
//! breaking bump to it is a deliberate, snapshot-visible change. The
//! `oraclemcp-guard` dependency is internal (the pool consumes its validators)
//! and intentionally does **not** appear in this public surface. See
//! `README.md` for the API-stability note and the baseline-refresh procedure.
//!
//! [`ErrorEnvelope`]: oraclemcp_error::ErrorEnvelope

mod auth_adapter;
mod awr;
mod catalog_extract;
mod connection;
mod doctor;
mod drcp;
mod error;
mod health;
mod intelligence;
mod lease;
mod oci;
mod plscope;
mod privileges;
mod query;
mod schema_diff;
mod serialize;
mod standby;
mod tns;
mod types;

mod pool;

pub use auth_adapter::{AuthAdapter, AuthAdapterError};
pub use awr::{
    DiagnosticsSource, TopSqlMetric, detect_diagnostics_pack, detect_statspack,
    resolve_top_sql_source, select_diagnostics_source, top_sql_query,
};
pub use catalog_extract::{
    CatalogExtractReport, CatalogExtractRequest, CatalogExtractWarning, CatalogRowBatch,
    CatalogRowSetName, CatalogSchemaFilter, catalog_extract_rowsets, extract_catalog_rowsets,
};
pub use connection::{
    DbmsOutput, ExecuteOutcome, OracleConnection, OracleRoutineArg, RustOracleConnection,
};
pub use doctor::{OracleDriverPosture, detect_oracle_driver, oracle_driver_compiled};
pub use drcp::{DrcpConfig, SessionPurity};
pub use error::{CONNECT_TRACE_NEXT_STEP, ConnectFailureKind, DbError, QuarantineOutcome};
pub use health::{
    Finding, HealthSubcheck, ParsedHealthRequest, PreflightReport, Severity, SubcheckPreflight,
    ViewTier, buffer_cache_hit_ratio_sql, detect_view_tier, disabled_constraints_sql,
    invalid_objects_sql, parse_health_request, preflight, run_health, sequence_ceiling_sql,
    tablespace_usage_sql, unusable_indexes_sql,
};
pub use intelligence::{
    IndexDescription, LobText, SearchColumn, SearchDetailLevel, SearchIndex, SearchObject,
    SourceText, TriggerDescription, ViewDescription, compile_errors, describe_columns,
    describe_constraints, describe_index, describe_trigger, describe_view, explain_plan, get_ddl,
    get_source, get_sources_by_name, is_ddl_object_type, list_objects, list_schemas,
    list_source_types, normalize_source_object_type, read_lob, sample_rows, search_objects,
    search_source,
};
pub use lease::{LeaseId, LeaseInfo, LeaseManager, PreviewImpact, require_lease_id};
pub use oci::{
    AdbConnectInfo, CloudStatus, IamToken, IamTokenSource, OciError, WalletContents, WalletMode,
    classify_wallet, discover_wallet, ensure_fresh_token, supported_wallet_modes,
    validate_adb_connect_string,
};
pub use plscope::{
    PlscopeIdentifier, PlscopeStatement, compile_object_statements, execute_immediate_audit,
    find_unused_declarations, plscope_identifiers, plscope_statements,
    recompile_with_plscope_statements,
};
pub use privileges::{
    DictionaryTier, PrivilegeProfile, ToolRequirement, WritePosture, probe_privileges,
    probe_write_posture, requirement_matrix,
};
pub use query::{
    QueryCaps, QueryResponse, cursor_to_offset, paginated_sql, read_query, read_query_named,
};
pub use schema_diff::{
    ChangeKind, MigrationStep, SchemaDiff, SchemaObject, SchemaSnapshot, StepKind, compare_schemas,
    migration_plan,
};
pub use serialize::{
    OracleMetadataCacheKey, SerializeOptions, StructuredDecodeCaps, TypeRepr, base64_encode,
    canonical_nls_statements, canonicalize_datetime, classify_type, serialize_cell, serialize_row,
};
pub use standby::{StandbyStatus, detect_standby};
pub use tns::{
    TnsDescriptorHints, TnsNetService, TnsParseError, TnsParseResult, extract_hints,
    parse_tnsnames_dir,
};
pub use types::{
    DEFAULT_ORACLE_CALL_TIMEOUT, ORACLE_CELL_STRUCTURED_CONTRACT_VERSION, OracleBackend,
    OracleBind, OracleCell, OracleConnectOptions, OracleConnectionInfo, OracleRow,
    OracleSessionIdentity, RedactedNamedOracleBinds, RedactedOracleBind, RedactedOracleBinds,
    RedactedOracleConnectionInfo, redacted_named_oracle_binds, redacted_oracle_binds,
};

pub use pool::{OracleConnectionManager, OraclePool, PoolMetrics, PoolSettings};

/// Re-export the shared agent-facing error envelope.
pub use oraclemcp_error as error_envelope;
