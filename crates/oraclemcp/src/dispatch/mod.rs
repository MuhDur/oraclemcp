//! The synchronous tool dispatcher wiring the advertised read-only tool surface
//! ([`crate::registry`]) to the engine-free `oraclemcp-db` dictionary ops.
//!
//! [`OracleDispatcher`] implements [`oraclemcp_core::ToolDispatch`]: the server
//! passes an explicit Asupersync [`Cx`](asupersync::Cx) at the dispatch boundary.
//! The DB-facing work remains synchronous for this slice and guards the single
//! connection with a `std::sync::Mutex`. Every arm deserializes a small args
//! struct, runs the matching `oraclemcp_db` op against the connection, and maps
//! the result to JSON; a [`oraclemcp_db::DbError`] becomes the agent-facing
//! [`ErrorEnvelope`] via `DbError::into_envelope`. The `oracle_capabilities`
//! discovery tool is answered by the server itself and never reaches here.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock, Mutex as SyncMutex};
use std::time::{Duration, Instant};

use asupersync::sync::Mutex as AsyncMutex;
use asupersync::{Budget, CancelReason, Cx, Outcome};
use oraclemcp_audit::{
    AuditCancel, AuditDecision, AuditEntryDraft, AuditOutcome, AuditSubject, Auditor, DbEvidence,
};
use oraclemcp_auth::apply_oauth_scopes;
use oraclemcp_config::{ConfigReloadPlan, OracleMcpConfig};
use oraclemcp_core::{
    ConnectionStatus, CustomToolCatalog, CustomToolExecutor, DEFAULT_REQUEST_TIMEOUT,
    DispatchCloseFuture, DispatchCloseReason, DispatchContext, DispatchFuture, McpSurfaceDetail,
    McpSurfaceFuture, McpSurfaceState, RequestBudget, ToolBody, ToolDispatch, ToolStreamFrame,
    ToolStreamSender, WriteIntent, WriteIntentDetails, WriteIntentError, WriteIntentLog,
    WriteIntentOutcome, execute_custom_tool, narrow_to_read_path, sign_token, verify_token,
};
use oraclemcp_db::SearchDetailLevel;
use oraclemcp_db::{
    AsOf, DbError, DbmsOutput, DependentObject, DependentsProbe, OracleBackend, OracleBind,
    OracleConnection, OracleConnectionInfo, OracleRow, QuarantineOutcome, QueryCaps,
    QueryRowStream, QueryRowStreamStart, SerializeOptions, StructuredDecodeCaps, compile_errors,
    compile_object_statements, describe_columns, describe_constraints, describe_index,
    describe_trigger, describe_view, execute_immediate_audit, explain_plan,
    find_unused_declarations, get_ddl, get_source, get_sources_by_name, list_objects, list_schemas,
    paginated_sql, plan_cost_estimate, plscope_identifiers, plscope_statements, probe_dependents,
    read_lob, read_query, read_query_as_of, read_query_named, sample_rows, search_objects,
    search_source, serialize_row,
};
use oraclemcp_error::{ErrorClass, ErrorEnvelope, ReasonCategory, StructuredReason};
use oraclemcp_guard::{
    Classifier, ClassifierConfig, DangerLevel, EscalationError, ExecGrantBinding, ExecGrantError,
    ExecGrantStore, GuardDecision, LevelDecision, ObjectRef, OperatingLevel, Purity,
    SessionLevelState, SideEffectOracle, StageA, stage_a,
};
use serde::Deserialize;
use serde_json::{Value, json};

/// Default cap on `oracle_search_source` result rows when the caller omits it.
const DEFAULT_SEARCH_MAX_ROWS: usize = 200;
/// Hard cap on `oracle_search_source` for a single call.
const MAX_SEARCH_MAX_ROWS: usize = 5_000;
/// Default cap on `oracle_get_source` source text when the caller omits it.
const DEFAULT_SOURCE_MAX_CHARS: usize = 1_000_000;
/// Cap on before/after snippets in `oracle_patch_source` previews.
const DEFAULT_PATCH_PREVIEW_CHARS: usize = 1_000;
/// Cap on direct dependents listed in a DDL preview's blast-radius block. The
/// probe is observational enrichment, so it is bounded rather than paginated.
const DEFAULT_DEPENDENTS_PREVIEW_MAX: usize = 200;
/// Default cap on `oracle_schema_inspect` result rows when the caller omits it.
const DEFAULT_SCHEMA_INSPECT_MAX_ROWS: usize = 500;
/// Hard cap on `oracle_schema_inspect` for a single call.
const MAX_SCHEMA_INSPECT_MAX_ROWS: usize = 5_000;
/// Default cap on `oracle_search_objects` result rows when the caller omits it.
/// Lower than schema_inspect because each result is enriched per detail level.
const DEFAULT_SEARCH_OBJECTS_MAX_ROWS: usize = 100;
/// Hard cap on `oracle_search_objects` for a single call.
const MAX_SEARCH_OBJECTS_MAX_ROWS: usize = 5_000;
/// Default cap on `oracle_list_schemas` result rows when the caller omits it.
const DEFAULT_SCHEMA_LIST_MAX_ROWS: usize = 200;
/// Hard cap on `oracle_list_schemas` for a single call.
const MAX_SCHEMA_LIST_MAX_ROWS: usize = 5_000;
/// Default cap on `oracle_sample_rows` when the caller omits it.
const DEFAULT_SAMPLE_MAX_ROWS: usize = 50;
/// Hard cap on `oracle_sample_rows` for a single call.
const MAX_SAMPLE_MAX_ROWS: usize = 1_000;
/// Default cap on `oracle_read_clob` text when the caller omits it.
const DEFAULT_LOB_MAX_CHARS: usize = 1_000_000;
/// Hard cap on `oracle_query` rows per page when a caller supplies max_rows/limit.
const MAX_QUERY_MAX_ROWS: usize = 5_000;
/// Hard cap on serialized bytes per `oracle_query` page.
const MAX_QUERY_RESULT_BYTES: usize = 25 * 1024 * 1024;
/// Hard cap on rows materialized into a single `oracle_query` export resource
/// (E3/E3b). Bounds the work + memory of one export independent of the inline
/// page cap; rows beyond this are dropped and the export is marked truncated.
const MAX_QUERY_EXPORT_ROWS: usize = 100_000;
/// K10: hard cap on total rows a single streaming (`streaming=true`)
/// `oracle_query` walks the cursor for. Bounds the work + memory of one
/// streamed response; beyond it the final chunk carries a resume cursor and the
/// response is flagged `truncated` so the caller can continue with the cursor.
const MAX_QUERY_STREAM_ROWS: usize = 50_000;
/// Hard cap on text/CLOB characters materialized by a single query cell.
const MAX_QUERY_TEXT_CHARS: usize = 1_000_000;
/// Hard cap on BLOB bytes materialized by a single query cell.
const MAX_QUERY_BLOB_BYTES: usize = 5 * 1024 * 1024;
/// Hard cap on direct entries decoded from one structured ARRAY/JSON node.
const MAX_QUERY_STRUCTURED_ROWS: usize = StructuredDecodeCaps::DEEP.max_rows;
/// Hard cap on structured nodes decoded from one structured cell.
const MAX_QUERY_STRUCTURED_CELLS: usize = StructuredDecodeCaps::DEEP.max_cells;
/// Hard cap on compact JSON bytes decoded from one structured node.
const MAX_QUERY_STRUCTURED_BYTES: usize = StructuredDecodeCaps::DEEP.max_bytes;
/// Hard cap on structured ARRAY/JSON recursion depth.
const MAX_QUERY_STRUCTURED_DEPTH: usize = StructuredDecodeCaps::DEEP.max_depth;
/// Default temporary session elevation window for `oracle_set_session_level`.
const DEFAULT_SESSION_LEVEL_TTL_SECONDS: u64 = 900;
/// Hard cap for one temporary session elevation window.
const MAX_SESSION_LEVEL_TTL_SECONDS: u64 = 3_600;
/// Default cap on DBMS_OUTPUT lines captured by `oracle_execute`.
const DEFAULT_DBMS_OUTPUT_MAX_LINES: usize = 200;
/// Hard cap on DBMS_OUTPUT lines captured by `oracle_execute`.
const MAX_DBMS_OUTPUT_MAX_LINES: usize = 5_000;
/// Default cap on DBMS_OUTPUT characters captured by `oracle_execute`.
const DEFAULT_DBMS_OUTPUT_MAX_CHARS: usize = 200_000;
/// Hard cap on DBMS_OUTPUT characters captured by `oracle_execute`.
const MAX_DBMS_OUTPUT_MAX_CHARS: usize = 1_000_000;
/// Hard cap on the Oracle-side DBMS_OUTPUT buffer requested for a capture.
const MAX_DBMS_OUTPUT_BUFFER_BYTES: usize = 1_000_000;
/// Compatibility TTL for `preview_sql` -> `execute_approved` cached grants.
const EXECUTE_APPROVED_TOKEN_TTL_SECONDS: u64 = 300;
/// Hard cap on remembered compatibility grants in one server process.
const MAX_EXECUTE_APPROVED_TOKENS: usize = 128;
/// Tamper-token scope for signed execution grant references.
const EXECUTE_GRANT_TOKEN_SCOPE: &str = "grant:execute";
/// Hard cap on remembered source patch previews in one server process.
const MAX_PATCH_PREVIEWS: usize = 128;
/// Hard cap on per-call Oracle round-trip timeout overrides.
const MAX_CALL_TIMEOUT_SECONDS: u64 = 3_600;

/// Reconnect callback used by `oracle_switch_profile`. Async + `Cx`-first (B1):
/// opening a connection is a native-async DB round trip, so the connector
/// returns a boxed future awaited on the dispatch runtime.
pub type ProfileConnector = dyn for<'a> Fn(
        &'a Cx,
        &'a str,
    )
        -> Pin<Box<dyn Future<Output = Result<Box<dyn OracleConnection>, DbError>> + 'a>>
    + Send
    + Sync
    + 'static;

/// Optional stateless metadata-read connector used when a profile configures a
/// local client-side pool. Async + `Cx`-first (B1).
pub type ProfileStatelessConnector = dyn for<'a> Fn(
        &'a Cx,
        &'a str,
    ) -> Pin<
        Box<dyn Future<Output = Result<Option<Box<dyn OracleConnection>>, DbError>> + 'a>,
    > + Send
    + Sync
    + 'static;

/// Profile-scoped custom-tool loader used by `oracle_switch_profile`.
pub type CustomToolLoader = dyn Fn(Option<&str>, &SessionLevelState) -> Result<CustomToolCatalog, ErrorEnvelope>
    + Send
    + Sync
    + 'static;

/// Initial connection and profile-switch connector for the optional stateless
/// metadata-read pool.
pub struct StatelessReadStrategy {
    conn: Option<Box<dyn OracleConnection>>,
    connector: Option<Arc<ProfileStatelessConnector>>,
}

impl StatelessReadStrategy {
    /// Disable the stateless metadata-read path.
    #[must_use]
    pub fn none() -> Self {
        Self {
            conn: None,
            connector: None,
        }
    }

    /// Configure the initial stateless connection and profile-switch connector.
    #[must_use]
    pub fn new(
        conn: Option<Box<dyn OracleConnection>>,
        connector: Option<Arc<ProfileStatelessConnector>>,
    ) -> Self {
        Self { conn, connector }
    }
}

fn default_read_only_level() -> SessionLevelState {
    SessionLevelState::new(OperatingLevel::ReadOnly, false)
}

#[derive(Clone)]
struct ProfileDispatchPolicy {
    level: SessionLevelState,
    request_timeout: Option<Duration>,
}

struct PreparedProfileSwitch {
    profile: String,
    conn: Box<dyn OracleConnection>,
    stateless_conn: Option<Box<dyn OracleConnection>>,
    level: SessionLevelState,
    request_timeout: Option<Duration>,
    custom_catalog: CustomToolCatalog,
    response: Value,
}

fn default_dispatch_policy() -> ProfileDispatchPolicy {
    ProfileDispatchPolicy {
        level: default_read_only_level(),
        request_timeout: Some(DEFAULT_REQUEST_TIMEOUT),
    }
}

fn profile_request_timeout(call_timeout_seconds: Option<u64>) -> Option<Duration> {
    match call_timeout_seconds {
        None => Some(DEFAULT_REQUEST_TIMEOUT),
        Some(0) => None,
        Some(seconds) => Some(Duration::from_secs(seconds)),
    }
}

fn profile_dispatch_policy(profile: &str) -> ProfileDispatchPolicy {
    OracleMcpConfig::load(None)
        .ok()
        .and_then(|cfg| {
            cfg.profile(profile).map(|profile| ProfileDispatchPolicy {
                level: oraclemcp_core::session_level_state(profile, false),
                request_timeout: profile_request_timeout(profile.call_timeout_seconds),
            })
        })
        .unwrap_or_else(default_dispatch_policy)
}

struct DispatcherState {
    conn: Box<dyn OracleConnection>,
    stateless_conn: Option<Box<dyn OracleConnection>>,
    active_profile: Option<String>,
    level: SessionLevelState,
    custom_catalog: CustomToolCatalog,
    execute_grants: ExecGrantStore,
    grant_generation: u64,
    execute_approved_tokens: HashMap<String, ExecuteApprovedGrant>,
    patch_previews: HashMap<String, PatchPreviewEntry>,
    /// A1: lazy read-only transaction backstop for the pinned/primary session.
    /// Scoped to `conn` only (the stateless metadata pool relies on the
    /// least-privilege DB user, A2). Re-asserted at the start of every read
    /// transaction; disarmed by a gated write and reset on a profile switch.
    read_only_backstop: ReadOnlyBackstop,
}

#[derive(Clone, Debug)]
struct ConnectionQuarantine {
    outcome: AuditOutcome,
    message: String,
}

struct ExecuteApprovedGrant {
    sql: String,
    required_level: OperatingLevel,
    active_profile: Option<String>,
    expires_at: Instant,
}

#[derive(Clone, Debug)]
struct PatchPreviewEntry {
    active_profile: Option<String>,
    owner: String,
    name: String,
    object_type: String,
    patched_ddl: String,
    tool_name: String,
    created_at: Instant,
}

/// The dispatcher: owns the live connection behind an Asupersync [`AsyncMutex`]
/// so the now-async dispatch can hold the guard across a native-async DB round
/// trip (cancellation-safe; a `std::sync::Mutex` would be a deadlock/cancel
/// hazard across `.await`). The connection is still single-owner per dispatch
/// and never shared across threads without serialization.
pub struct OracleDispatcher {
    state: AsyncMutex<DispatcherState>,
    request_timeout: SyncMutex<Option<Duration>>,
    quarantine: SyncMutex<Option<ConnectionQuarantine>>,
    connector: Option<Arc<ProfileConnector>>,
    stateless_connector: Option<Arc<ProfileStatelessConnector>>,
    custom_loader: Option<Arc<CustomToolLoader>>,
    /// Out-of-band, hash-chained, keyed-MAC auditor. Constructed once in server
    /// wiring; `None` only when no operating level above ReadOnly is reachable
    /// (so no write/escalation can ever occur). Every Guarded/Destructive write
    /// (`oracle_execute`/`execute_approved`) and every `oracle_set_session_level`
    /// escalation appends a record here.
    auditor: Option<Arc<Auditor>>,
    /// Server-derived subject used when a request has no transport principal
    /// (stdio/direct dispatch) and for lifecycle records that do not carry a
    /// request context.
    default_audit_subject: AuditSubject,
    /// Shared store for materialized large-result exports (E3). When set,
    /// oversized `oracle_query` results are exported to `oracle-export://{id}`
    /// and a `resource_link` is returned instead of inlining (E3b). `None`
    /// disables the export arm (results are inlined / row-capped as before).
    exports: Option<Arc<oraclemcp_core::ExportRegistry>>,
    /// E5 connection-scope isolation: which profiles the served surface may
    /// reach (switch/list/search/complete). Defaults to [`McpExposurePolicy::AllowAll`];
    /// the served binary installs an explicit allow-list snapshotted from the
    /// `mcp_exposed` config flags.
    mcp_exposure: McpExposurePolicy,
    /// S5 config reload/drain gate: profiles marked draining are omitted from
    /// runtime discovery, cannot be switched into, and cannot keep accepting
    /// non-diagnostic work on already-active lanes.
    profile_drain: ProfileDrainState,
    /// E6 server-initiated notifications hub, shared with the server. When set,
    /// a successful `oracle_switch_profile` enqueues `notifications/tools/list_changed`
    /// because the switch may change the profile-scoped custom-tool catalog (and
    /// thus the served tool set). `None` disables that signal (focused tests).
    notifications: Option<Arc<oraclemcp_core::NotificationHub>>,
    /// Durable write-ahead idempotency ledger for committing tools (CX-C1).
    write_intents: Option<Arc<WriteIntentLog>>,
}

impl OracleDispatcher {
    /// Build a dispatcher over an open (or stub) connection.
    pub fn new(conn: Box<dyn OracleConnection>) -> Self {
        Self::new_with_profile(conn, None)
    }

    /// Build a dispatcher with a known active profile name.
    pub fn new_with_profile(
        conn: Box<dyn OracleConnection>,
        active_profile: Option<String>,
    ) -> Self {
        Self::new_with_profile_level(conn, active_profile, default_read_only_level())
    }

    /// Build a dispatcher with a known active profile and policy level.
    pub fn new_with_profile_level(
        conn: Box<dyn OracleConnection>,
        active_profile: Option<String>,
        level: SessionLevelState,
    ) -> Self {
        OracleDispatcher {
            state: AsyncMutex::new(DispatcherState {
                conn,
                stateless_conn: None,
                active_profile,
                level,
                custom_catalog: CustomToolCatalog::default(),
                execute_grants: ExecGrantStore::new(),
                grant_generation: 1,
                execute_approved_tokens: HashMap::new(),
                patch_previews: HashMap::new(),
                read_only_backstop: ReadOnlyBackstop::new(),
            }),
            request_timeout: SyncMutex::new(Some(DEFAULT_REQUEST_TIMEOUT)),
            quarantine: SyncMutex::new(None),
            connector: None,
            stateless_connector: None,
            custom_loader: None,
            auditor: None,
            default_audit_subject: process_audit_subject(),
            exports: None,
            mcp_exposure: McpExposurePolicy::default(),
            profile_drain: ProfileDrainState::default(),
            notifications: None,
            write_intents: None,
        }
    }

    /// Build a dispatcher that can reconnect to other configured profiles.
    pub fn new_switchable(
        conn: Box<dyn OracleConnection>,
        active_profile: Option<String>,
        level: SessionLevelState,
        connector: Arc<ProfileConnector>,
    ) -> Self {
        Self::new_switchable_with_custom_tools(
            conn,
            active_profile,
            level,
            connector,
            CustomToolCatalog::default(),
            None,
        )
    }

    /// Build a switchable dispatcher with a profile-scoped custom-tool catalog.
    pub fn new_switchable_with_custom_tools(
        conn: Box<dyn OracleConnection>,
        active_profile: Option<String>,
        level: SessionLevelState,
        connector: Arc<ProfileConnector>,
        custom_catalog: CustomToolCatalog,
        custom_loader: Option<Arc<CustomToolLoader>>,
    ) -> Self {
        Self::new_switchable_with_custom_tools_and_stateless(
            conn,
            active_profile,
            level,
            connector,
            StatelessReadStrategy::none(),
            custom_catalog,
            custom_loader,
        )
    }

    /// Build a switchable dispatcher with a separate stateless metadata-read
    /// connection path for profile-backed pools.
    pub fn new_switchable_with_custom_tools_and_stateless(
        conn: Box<dyn OracleConnection>,
        active_profile: Option<String>,
        level: SessionLevelState,
        connector: Arc<ProfileConnector>,
        stateless: StatelessReadStrategy,
        custom_catalog: CustomToolCatalog,
        custom_loader: Option<Arc<CustomToolLoader>>,
    ) -> Self {
        OracleDispatcher {
            state: AsyncMutex::new(DispatcherState {
                conn,
                stateless_conn: stateless.conn,
                active_profile,
                level,
                custom_catalog,
                execute_grants: ExecGrantStore::new(),
                grant_generation: 1,
                execute_approved_tokens: HashMap::new(),
                patch_previews: HashMap::new(),
                read_only_backstop: ReadOnlyBackstop::new(),
            }),
            request_timeout: SyncMutex::new(Some(DEFAULT_REQUEST_TIMEOUT)),
            quarantine: SyncMutex::new(None),
            connector: Some(connector),
            stateless_connector: stateless.connector,
            custom_loader,
            auditor: None,
            default_audit_subject: process_audit_subject(),
            exports: None,
            mcp_exposure: McpExposurePolicy::default(),
            profile_drain: ProfileDrainState::default(),
            notifications: None,
            write_intents: None,
        }
    }

    /// Attach the shared E6 notification hub (builder). The server wiring shares
    /// the same hub it gave `OracleMcpServer::with_notifications`, so a profile
    /// switch here enqueues `notifications/tools/list_changed` that the transport
    /// flushes.
    #[must_use]
    pub fn with_notifications(
        mut self,
        notifications: Arc<oraclemcp_core::NotificationHub>,
    ) -> Self {
        self.notifications = Some(notifications);
        self
    }

    /// Install the E5 connection-scope isolation policy (builder). The served
    /// binary calls this with the allow-list snapshotted from the `mcp_exposed`
    /// config flags so a non-exposed profile is never switchable, listable,
    /// searchable, or completable by the agent.
    #[must_use]
    pub fn with_mcp_exposure(mut self, exposure: McpExposurePolicy) -> Self {
        self.mcp_exposure = exposure;
        self
    }

    /// Install the shared S5 profile-drain state (builder). Reload controllers
    /// update this gate after validating a config diff; dispatch consults it
    /// before any target profile reconnect or active-lane work.
    #[must_use]
    pub fn with_profile_drain_state(mut self, state: ProfileDrainState) -> Self {
        self.profile_drain = state;
        self
    }

    /// Attach the out-of-band auditor (builder; consumes and returns `self`).
    /// The server wiring constructs the auditor once and attaches it here so
    /// every served write/escalation is recorded on the hash-chained, signed
    /// log.
    #[must_use]
    pub fn with_auditor(mut self, auditor: Arc<Auditor>) -> Self {
        self.auditor = Some(auditor);
        self
    }

    /// Install the server-derived subject used for lifecycle records and
    /// request contexts without an explicit transport principal.
    #[must_use]
    pub fn with_default_audit_subject(mut self, subject: AuditSubject) -> Self {
        self.default_audit_subject = subject;
        self
    }

    /// Attach the shared durable write-intent ledger. The served binary opens
    /// and recovers this once, then shares it across dispatchers and lanes.
    #[must_use]
    pub fn with_write_intent_log(mut self, write_intents: Arc<WriteIntentLog>) -> Self {
        self.write_intents = Some(write_intents);
        self
    }

    /// Attach the shared export registry (E3/E3b; builder). When set, oversized
    /// `oracle_query` results are materialized as an `oracle-export://{id}`
    /// resource and returned as a `resource_link` instead of being inlined.
    #[must_use]
    pub fn with_exports(mut self, exports: Arc<oraclemcp_core::ExportRegistry>) -> Self {
        self.exports = Some(exports);
        self
    }

    /// Install the active profile's resolved request timeout.
    ///
    /// `None` is an explicit operator opt-out from the driver call timeout; the
    /// request-budget layer still applies its own 30-second default.
    #[must_use]
    pub fn with_request_timeout(self, request_timeout: Option<Duration>) -> Self {
        self.set_request_timeout(request_timeout)
            .expect("request-timeout mutex is healthy during construction");
        self
    }

    fn request_timeout(&self) -> Result<Option<Duration>, ErrorEnvelope> {
        self.request_timeout
            .lock()
            .map(|guard| *guard)
            .map_err(|err| {
                ErrorEnvelope::new(
                    ErrorClass::Internal,
                    format!("request-timeout mutex lock failed: {err}"),
                )
            })
    }

    fn set_request_timeout(&self, request_timeout: Option<Duration>) -> Result<(), ErrorEnvelope> {
        let mut guard = self.request_timeout.lock().map_err(|err| {
            ErrorEnvelope::new(
                ErrorClass::Internal,
                format!("request-timeout mutex lock failed: {err}"),
            )
        })?;
        *guard = request_timeout;
        Ok(())
    }

    fn connection_quarantine(&self) -> Result<Option<ConnectionQuarantine>, ErrorEnvelope> {
        self.quarantine
            .lock()
            .map(|guard| guard.clone())
            .map_err(|err| {
                ErrorEnvelope::new(
                    ErrorClass::Internal,
                    format!("connection-quarantine mutex lock failed: {err}"),
                )
            })
    }

    fn clear_connection_quarantine(&self) -> Result<(), ErrorEnvelope> {
        let mut guard = self.quarantine.lock().map_err(|err| {
            ErrorEnvelope::new(
                ErrorClass::Internal,
                format!("connection-quarantine mutex lock failed: {err}"),
            )
        })?;
        *guard = None;
        Ok(())
    }

    fn dispatch_request_budget(&self, cx: &Cx) -> Result<RequestBudget, ErrorEnvelope> {
        let timeout = self.request_timeout()?;
        let budget = RequestBudget::from_call_timeout(cx.now(), timeout).meet(cx.budget());
        budget.enforce(cx).map_err(DbError::into_envelope)?;
        Ok(budget)
    }
}

/// The process-wide default SQL classifier (empty `ClassifierConfig`, the
/// fail-closed `UnknownOracle`). `Classifier::classify` takes `&self` and is
/// pure given a fixed config + oracle, so every request arm can share one
/// instance instead of rebuilding `Classifier::new(ClassifierConfig::new())`
/// (which allocates a fresh `Arc<UnknownOracle>`) on each call. Behavior is
/// identical — the same statement yields the same `GuardDecision` — this only
/// drops the per-call allocation on the gate hot path. Allow/block-list
/// configs are not used on this served surface, so the empty config is the one
/// every existing site already constructed.
static DEFAULT_CLASSIFIER: LazyLock<Classifier> =
    LazyLock::new(|| Classifier::new(ClassifierConfig::new()));

/// Classifier used for server-generated read SQL. It is deliberately separate
/// from [`DEFAULT_CLASSIFIER`] so only this internal surface gets a tiny purity
/// oracle for Oracle-owned read-only package routines used by dictionary tools.
static GENERATED_READ_CLASSIFIER: LazyLock<Classifier> = LazyLock::new(|| {
    Classifier::new(ClassifierConfig::new()).with_oracle(Arc::new(GeneratedReadPurityOracle))
});

struct GeneratedReadPurityOracle;

impl SideEffectOracle for GeneratedReadPurityOracle {
    fn routine_purity(&self, routine: &ObjectRef) -> Purity {
        let schema = routine.schema.as_deref().unwrap_or("").to_ascii_uppercase();
        let name = routine.name.to_ascii_uppercase();
        match (schema.as_str(), name.as_str()) {
            ("DBMS_LOB", "SUBSTR") | ("DBMS_METADATA", "GET_DDL") | ("DBMS_XPLAN", "DISPLAY") => {
                Purity::ProvenReadOnly
            }
            _ => Purity::Unknown,
        }
    }
}

/// Serialize a slice of rows to a JSON array via the canonical row serializer.
fn rows_to_json(rows: &[oraclemcp_db::OracleRow]) -> Value {
    let opts = SerializeOptions::default();
    Value::Array(rows.iter().map(|r| serialize_row(r, &opts)).collect())
}

async fn send_stream_frame(cx: &Cx, frames: &ToolStreamSender, frame: ToolStreamFrame) -> bool {
    frames.send(cx, frame).await.is_ok()
}

/// The agent-facing `oracle_list_profiles` response (E5). Only profiles the
/// dispatcher's [`McpExposurePolicy`] admits are surfaced — a non-exposed
/// profile is omitted entirely (not redacted), so an agent never learns it
/// exists. The CLI/operator path uses `cfg.list_profiles()` directly and still
/// sees every profile.
fn profiles_response(
    cfg: &OracleMcpConfig,
    exposure: &McpExposurePolicy,
    drain: &ProfileDrainState,
) -> Value {
    let profiles: Vec<_> = cfg
        .list_profiles()
        .into_iter()
        .filter(|metadata| {
            exposure.is_exposed(&metadata.name) && !drain.is_draining(&metadata.name)
        })
        .collect();
    json!({ "profiles": profiles })
}

/// Fail-closed envelope (E5) for a profile that is not exposed to the MCP
/// surface. Deliberately indistinguishable from an unknown profile so a guessed
/// non-exposed name leaks nothing: same class, same message, no acknowledgement
/// that the name happens to match a hidden profile.
fn profile_not_available(profile: &str) -> ErrorEnvelope {
    invalid_args(format!(
        "connection profile `{profile}` is not available on this MCP server"
    ))
    .with_suggested_tool("oracle_list_profiles")
    .with_next_step("call oracle_list_profiles to see the profiles this server exposes")
}

/// Fail-closed envelope for profiles drained by an accepted config reload.
pub fn profile_draining_error(profile: &str) -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorClass::RuntimeStateRequired,
        format!("connection profile `{profile}` is draining after config reload"),
    )
    .with_suggested_tool("oracle_list_profiles")
    .with_next_step("open a new lane on a listed profile")
    .with_next_step("delete this MCP session to close a lane pinned to the drained profile")
}

/// Shared hot-reload drain gate for profile-scoped dispatch.
#[derive(Clone, Default)]
pub struct ProfileDrainState {
    profiles: Arc<SyncMutex<HashSet<String>>>,
}

impl std::fmt::Debug for ProfileDrainState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileDrainState")
            .field("profiles", &self.draining_profiles())
            .finish()
    }
}

impl ProfileDrainState {
    /// Create an empty drain gate.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the draining profile set atomically.
    pub fn replace_draining_profiles<I, S>(&self, profiles: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut guard = self.profiles.lock().unwrap_or_else(|err| err.into_inner());
        *guard = profiles.into_iter().map(Into::into).collect();
    }

    /// Apply the drain set from a validated config reload plan.
    pub fn apply_config_reload_plan(&self, plan: &ConfigReloadPlan) {
        self.replace_draining_profiles(plan.draining_profiles());
    }

    /// Whether a profile is currently draining. A poisoned lock fails closed.
    #[must_use]
    pub fn is_draining(&self, profile: &str) -> bool {
        self.profiles
            .lock()
            .map(|profiles| profiles.contains(profile))
            .unwrap_or(true)
    }

    /// Sorted draining profile names for diagnostics and tests.
    #[must_use]
    pub fn draining_profiles(&self) -> Vec<String> {
        let mut profiles: Vec<_> = self
            .profiles
            .lock()
            .map(|profiles| profiles.iter().cloned().collect())
            .unwrap_or_default();
        profiles.sort();
        profiles
    }
}

/// The E5 connection-scope isolation policy: which profiles the *served*
/// surface may switch to / list / search / complete. The operator's startup
/// `--profile` choice is authoritative and out of scope here; this governs only
/// what the agent can reach at runtime.
#[derive(Clone, Debug, Default)]
pub enum McpExposurePolicy {
    /// No isolation configured: every profile in the config is reachable. This
    /// is the default for focused dispatcher construction and tests; the served
    /// binary always installs an explicit [`Self::AllowList`].
    #[default]
    AllowAll,
    /// Only these profile names (the exposed set — every profile except those
    /// hidden with `mcp_exposed = false`, snapshotted at server-wiring time) are
    /// reachable by the agent. Any name not in this set is invisible and
    /// non-switchable.
    AllowList(std::collections::HashSet<String>),
}

impl McpExposurePolicy {
    /// Build the exposure policy from config (E5), per-profile opt-out. The
    /// served binary calls this once with the loaded config.
    ///
    /// A profile is reachable by the agent UNLESS it sets `mcp_exposed = false`.
    /// When nothing is hidden (the common case) that is exactly
    /// [`Self::AllowAll`]; otherwise the exposed (non-hidden) set is snapshotted
    /// as an [`Self::AllowList`] so the hidden profiles are unreachable. One
    /// profile's flag never changes another's exposure (no global activation).
    #[must_use]
    pub fn from_config(cfg: &OracleMcpConfig) -> Self {
        if cfg.profiles.iter().all(|p| p.mcp_exposed()) {
            return McpExposurePolicy::AllowAll;
        }
        McpExposurePolicy::AllowList(
            cfg.list_mcp_profiles()
                .into_iter()
                .map(|metadata| metadata.name)
                .collect(),
        )
    }

    /// Whether `profile` is reachable by the served surface under this policy.
    #[must_use]
    pub fn is_exposed(&self, profile: &str) -> bool {
        match self {
            McpExposurePolicy::AllowAll => true,
            McpExposurePolicy::AllowList(names) => names.contains(profile),
        }
    }
}

fn optional_row_to_json(row: Option<&oraclemcp_db::OracleRow>) -> Value {
    let opts = SerializeOptions::default();
    row.map(|r| serialize_row(r, &opts)).unwrap_or(Value::Null)
}

/// K9: validate the STRUCTURED `as_of` argument and translate it into a
/// [`oraclemcp_db::AsOf`] flashback target. Exactly one of `scn` / `timestamp`
/// must be set; both-set, or an empty `{}` (neither set), is a hard
/// `InvalidArguments` refusal returned BEFORE any classification or I/O. The
/// value never enters the classifier input (the base SELECT is classified
/// unchanged) and never enters SQL text (it is bound at execution).
fn query_as_of_from_args(arg: Option<&AsOfArg>) -> Result<Option<AsOf>, ErrorEnvelope> {
    let Some(arg) = arg else {
        return Ok(None);
    };
    let timestamp = arg
        .timestamp
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match (arg.scn, timestamp) {
        (Some(_), Some(_)) => Err(invalid_args(
            "as_of accepts exactly one of `scn` or `timestamp`, not both",
        )),
        (None, None) => Err(invalid_args(
            "as_of requires one of `scn` (a system change number) or `timestamp` \
             (\"YYYY-MM-DD HH24:MI:SS\")",
        )),
        (Some(scn), None) => Ok(Some(AsOf::Scn(scn))),
        (None, Some(ts)) => Ok(Some(AsOf::Timestamp(ts.to_owned()))),
    }
}

fn query_caps_from_args(args: &QueryArgs) -> QueryCaps {
    let defaults = QueryCaps::default();
    QueryCaps {
        max_rows: args
            .max_rows
            .unwrap_or(defaults.max_rows)
            .clamp(1, MAX_QUERY_MAX_ROWS),
        max_result_bytes: args
            .max_result_bytes
            .unwrap_or(defaults.max_result_bytes)
            .clamp(1, MAX_QUERY_RESULT_BYTES),
    }
}

fn query_serialize_options_from_args(args: &QueryArgs) -> SerializeOptions {
    let defaults = SerializeOptions::default();
    SerializeOptions {
        numbers_as_float: args.numbers_as_float.unwrap_or(defaults.numbers_as_float),
        max_text_chars: args.max_col_width.map(|n| n.clamp(1, MAX_QUERY_TEXT_CHARS)),
        max_lob_chars: args
            .max_lob_chars
            .unwrap_or(defaults.max_lob_chars)
            .clamp(1, MAX_QUERY_TEXT_CHARS),
        max_blob_bytes: args
            .max_blob_bytes
            .unwrap_or(defaults.max_blob_bytes)
            .clamp(1, MAX_QUERY_BLOB_BYTES),
        structured_decode_caps: query_structured_decode_caps_from_args(args),
        ..defaults
    }
}

fn query_structured_decode_caps_from_args(args: &QueryArgs) -> StructuredDecodeCaps {
    let defaults = if args.deep_decode {
        StructuredDecodeCaps::deep()
    } else {
        StructuredDecodeCaps::default()
    };
    let ceiling = if args.deep_decode {
        StructuredDecodeCaps::deep()
    } else {
        StructuredDecodeCaps::default()
    };

    StructuredDecodeCaps {
        max_rows: args
            .max_structured_rows
            .unwrap_or(defaults.max_rows)
            .clamp(1, ceiling.max_rows.min(MAX_QUERY_STRUCTURED_ROWS)),
        max_cells: args
            .max_structured_cells
            .unwrap_or(defaults.max_cells)
            .clamp(1, ceiling.max_cells.min(MAX_QUERY_STRUCTURED_CELLS)),
        max_bytes: args
            .max_structured_bytes
            .unwrap_or(defaults.max_bytes)
            .clamp(1, ceiling.max_bytes.min(MAX_QUERY_STRUCTURED_BYTES)),
        max_depth: args
            .max_structured_depth
            .unwrap_or(defaults.max_depth)
            .clamp(1, ceiling.max_depth.min(MAX_QUERY_STRUCTURED_DEPTH)),
    }
}

/// Tamper-token scope for `oracle_query` pagination cursors (E2).
const QUERY_CURSOR_SCOPE: &str = "cursor:query";

/// Stable per-query binding for an `oracle_query` pagination cursor: the SHA-256
/// of the EXACT executed SQL plus the active profile. A cursor minted for one
/// statement/profile must not let a client page a *different* statement, so the
/// offset is signed against this context (E2). The bind values are deliberately
/// NOT part of the binding — a cursor is bound to the statement shape, and the
/// caller resupplies binds with the next page exactly as MCP cursor pagination
/// expects.
fn query_cursor_binding(sql: &str, active_profile: Option<&str>) -> String {
    let sql_hash = oraclemcp_audit::sha256_hex(sql.as_bytes());
    format!("{sql_hash}|{}", active_profile.unwrap_or(""))
}

/// Decode a client-supplied opaque `oracle_query` cursor to a raw offset for
/// this exact statement/profile. Absent cursor starts at offset 0; a present
/// cursor that is forged, edited, or minted for a different statement/profile
/// is a hard `InvalidArguments` error (fail closed), never a silent reset.
fn decode_query_cursor(
    cursor: Option<&str>,
    sql: &str,
    active_profile: Option<&str>,
) -> Result<usize, ErrorEnvelope> {
    let Some(cursor) = non_empty_arg(cursor.map(str::to_owned)) else {
        return Ok(0);
    };
    let binding = query_cursor_binding(sql, active_profile);
    let payload = oraclemcp_core::verify_token(QUERY_CURSOR_SCOPE, &cursor, &[&binding])
        .ok_or_else(|| {
            invalid_args(
                "invalid or tampered oracle_query pagination cursor (it does not match this statement)",
            )
            .with_next_step("re-run oracle_query without a cursor to restart from the first page")
        })?;
    payload
        .parse::<usize>()
        .map_err(|_| invalid_args("invalid oracle_query pagination cursor payload"))
}

/// Sign one raw next-page offset as an opaque, tamper-evident cursor bound to
/// this statement/profile (E2). The single sealing primitive shared by the
/// inline-page path ([`reseal_query_cursor`]) and the streaming path
/// ([`OracleMcpDispatcher::stream_query_response`]) so a streamed chunk's cursor
/// is byte-identical to the one a paginated caller would receive.
fn seal_raw_query_cursor(offset: &str, sql: &str, active_profile: Option<&str>) -> String {
    let binding = query_cursor_binding(sql, active_profile);
    oraclemcp_core::sign_token(QUERY_CURSOR_SCOPE, offset, &[&binding])
}

/// Re-sign a raw next-page offset from [`read_query`] as an opaque,
/// tamper-evident cursor bound to this statement/profile. Replaces the raw
/// `next_cursor` offset in the serialized response (E2).
fn reseal_query_cursor(mut response: Value, sql: &str, active_profile: Option<&str>) -> Value {
    let Some(offset) = response
        .get("next_cursor")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return response;
    };
    let sealed = seal_raw_query_cursor(&offset, sql, active_profile);
    if let Value::Object(map) = &mut response {
        map.insert("next_cursor".to_owned(), Value::String(sealed));
    }
    response
}

/// Stringify one serialized query cell for an export. NUMBER/text cells are
/// already strings; everything else (booleans, the truncated-LOB object, nested
/// arrays) renders to its compact JSON so the export is lossless and unambiguous.
fn export_cell_string(cell: &Value) -> String {
    match cell {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Convert a [`oraclemcp_db::QueryResponse`]-shaped JSON value into
/// `(columns, string-cell rows)` for export materialization. Rows are objects
/// keyed by column name; cells are pulled in `columns` order.
fn query_value_to_export_rows(response: &Value) -> (Vec<String>, Vec<Vec<String>>) {
    let columns: Vec<String> = response
        .get("columns")
        .and_then(Value::as_array)
        .map(|cols| {
            cols.iter()
                .filter_map(|c| c.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let rows: Vec<Vec<String>> = response
        .get("rows")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|row| {
                    columns
                        .iter()
                        .map(|col| row.get(col).map(export_cell_string).unwrap_or_default())
                        .collect()
                })
                .collect()
        })
        .unwrap_or_default();
    (columns, rows)
}

/// E3/E3b: materialize the bounded full result of a read query as an
/// `oracle-export://{id}` resource and return a `resource_link` result (no
/// inlined rows). Fetches up to [`MAX_QUERY_EXPORT_ROWS`] at `offset`; rows
/// beyond that are dropped and the export is flagged truncated with a next hint.
#[allow(clippy::too_many_arguments)]
async fn export_query_to_resource(
    cx: &Cx,
    conn: &dyn OracleConnection,
    executed_sql: &str,
    a: &QueryArgs,
    binds: &[OracleBind],
    offset: usize,
    active_profile: Option<&str>,
    export_scopes: Option<&[String]>,
    exports: Option<&oraclemcp_core::ExportRegistry>,
    as_of: Option<&AsOf>,
) -> Result<Value, ErrorEnvelope> {
    let format = oraclemcp_core::ExportFormat::parse(a.export_format.as_deref())
        .ok_or_else(|| invalid_args("export_format must be \"csv\" or \"json\""))?;
    let Some(exports) = exports else {
        return Err(ErrorEnvelope::new(
            ErrorClass::RuntimeStateRequired,
            "result export is not enabled in this server instance",
        )
        .with_next_step("retry without export=true to page the result inline"));
    };

    // Fetch up to the export ceiling in one window. The byte cap is raised to
    // the export ceiling so the row cap (not the inline byte cap) governs.
    let caps = QueryCaps {
        max_rows: MAX_QUERY_EXPORT_ROWS,
        max_result_bytes: oraclemcp_core::export::MAX_EXPORT_BYTES,
    };
    let serialize_opts = query_serialize_options_from_args(a);
    // K9: an export honors the flashback target too — the SAME proven SQL is
    // materialized as of the requested snapshot.
    let response = match as_of {
        Some(as_of) => {
            read_query_as_of(
                cx,
                conn,
                executed_sql,
                binds,
                caps,
                offset,
                &serialize_opts,
                as_of,
            )
            .await
        }
        None => read_query(cx, conn, executed_sql, binds, caps, offset, &serialize_opts).await,
    }
    .map_err(DbError::into_envelope)?;
    let response_value = serde_json::to_value(&response).unwrap_or(Value::Null);
    let more_rows = response.truncated;
    let next_cursor = response.next_cursor.as_deref().map(|offset| {
        let binding = query_cursor_binding(&a.sql, active_profile);
        oraclemcp_core::sign_token(QUERY_CURSOR_SCOPE, offset, &[&binding])
    });

    let (columns, rows) = query_value_to_export_rows(&response_value);
    let access = oraclemcp_core::ExportAccess::new(active_profile, export_scopes);
    let handle = exports.create(
        &columns,
        &rows,
        format,
        access,
        oraclemcp_core::export::DEFAULT_EXPORT_TTL,
    );

    tracing::info!(
        export_uri = %handle.uri,
        format = ?handle.format,
        rows = handle.row_count,
        bytes = handle.byte_size,
        truncated = handle.truncated || more_rows,
        profile = active_profile.unwrap_or(""),
        "oracle_query materialized a large result as an export resource"
    );

    Ok(json!({
        "export": {
            "uri": handle.uri,
            "mime_type": handle.mime_type,
            "format": match handle.format {
                oraclemcp_core::ExportFormat::Csv => "csv",
                oraclemcp_core::ExportFormat::Json => "json",
            },
            "byte_size": handle.byte_size,
            "row_count": handle.row_count,
            "truncated": handle.truncated || more_rows,
        },
        "resource_link": {
            "type": "resource_link",
            "uri": handle.uri,
            "name": "oracle_query export",
            "mimeType": handle.mime_type,
            "description": "Materialized query result. Fetch with resources/read; access-controlled to this session and expires.",
        },
        "columns": columns,
        "row_count": handle.row_count,
        "inlined": false,
        "next_cursor": next_cursor,
        "next_step": if handle.truncated || more_rows {
            "The export was capped; re-run with the returned next_cursor to export the next window."
        } else {
            "Fetch the full result via resources/read on the export uri."
        },
    }))
}

fn call_timeout_duration(seconds: Option<u64>) -> Result<Option<Duration>, ErrorEnvelope> {
    let Some(seconds) = seconds else {
        return Ok(None);
    };
    if seconds == 0 {
        return Err(invalid_args(
            "timeout_seconds must be at least 1 when provided",
        ));
    }
    Ok(Some(Duration::from_secs(
        seconds.min(MAX_CALL_TIMEOUT_SECONDS),
    )))
}

/// Apply the per-call Oracle round-trip timeout around an async DB body.
///
/// `set_call_timeout` / `call_timeout` are synchronous interior-mutability
/// accessors (no `.await`), so the timeout is set, the future `f` is awaited,
/// and the previous value is restored — even on error/cancel.
async fn with_call_timeout<T, Fut>(
    cx: &Cx,
    conn: &dyn OracleConnection,
    request_budget: RequestBudget,
    timeout_seconds: Option<u64>,
    f: impl FnOnce() -> Fut,
) -> Result<T, ErrorEnvelope>
where
    Fut: Future<Output = Result<T, ErrorEnvelope>>,
{
    dispatch_checkpoint(cx, "oraclemcp.dispatch.call_timeout.before")?;
    let timeout = call_timeout_duration(timeout_seconds)?;
    let request_budget = match timeout {
        Some(timeout) => request_budget.meet(Budget::new().with_timeout(cx.now(), timeout)),
        None => request_budget,
    };
    request_budget.enforce(cx).map_err(DbError::into_envelope)?;
    let Some(timeout) = timeout else {
        let result = f().await;
        let budget_after = request_budget.enforce(cx).map_err(DbError::into_envelope);
        return match (result, budget_after) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(err), _) => Err(err),
            (Ok(_), Err(err)) => Err(err),
        };
    };
    let previous = conn.call_timeout().map_err(DbError::into_envelope)?;
    let effective_timeout = previous.map_or(timeout, |current| current.min(timeout));
    conn.set_call_timeout(Some(effective_timeout))
        .map_err(DbError::into_envelope)?;
    let result = f().await;
    let budget_after = request_budget.enforce(cx).map_err(DbError::into_envelope);
    let restore = conn
        .set_call_timeout(previous)
        .map_err(DbError::into_envelope);
    match (result, budget_after, restore) {
        (Ok(value), Ok(()), Ok(())) => Ok(value),
        (Err(err), _, _) => Err(err),
        (Ok(_), Err(err), _) => Err(err),
        (Ok(_), Ok(()), Err(err)) => Err(err),
    }
}

/// Cancellation/budget checkpoint. Generic over the capability row so it can be
/// driven by the narrowed read-path context (`ReadPathCaps`) as well as the full
/// row — checkpointing only observes TIME/cancellation, never an effect bit.
fn dispatch_checkpoint<Caps>(cx: &Cx<Caps>, phase: &'static str) -> Result<(), ErrorEnvelope> {
    cx.checkpoint_with(phase).map_err(|err| {
        ErrorEnvelope::new(ErrorClass::Timeout, format!("tool call cancelled: {err}"))
    })
}

async fn describe_conn(
    cx: &Cx,
    conn: &dyn OracleConnection,
) -> Result<OracleConnectionInfo, DbError> {
    conn.describe(cx).await
}

async fn execute_conn(
    cx: &Cx,
    conn: &dyn OracleConnection,
    sql: &str,
    binds: &[OracleBind],
) -> Result<u64, DbError> {
    conn.execute(cx, sql, binds).await
}

async fn commit_conn(cx: &Cx, conn: &dyn OracleConnection) -> Result<(), DbError> {
    conn.commit(cx).await
}

async fn enable_dbms_output_conn(
    cx: &Cx,
    conn: &dyn OracleConnection,
    buffer_bytes: Option<u32>,
) -> Result<(), DbError> {
    conn.enable_dbms_output(cx, buffer_bytes).await
}

async fn read_dbms_output_conn(
    cx: &Cx,
    conn: &dyn OracleConnection,
    max_lines: usize,
    max_chars: usize,
) -> Result<DbmsOutput, DbError> {
    conn.read_dbms_output(cx, max_lines, max_chars).await
}

mod args;
use args::*;

mod audit_marker;
use audit_marker::with_audit_marker;

mod read_only_backstop;
use read_only_backstop::ReadOnlyBackstop;

mod metadata_cache_key;
use metadata_cache_key::metadata_cache_key_json;

/// Map a JSON value to an [`OracleBind`]. Agent argument values are always
/// bound, never interpolated. Unsupported JSON (arrays/objects) is an
/// `InvalidArguments` error rather than a silent coercion.
fn json_to_bind(v: &Value) -> Result<OracleBind, ErrorEnvelope> {
    match v {
        Value::Null => Ok(OracleBind::Null),
        Value::Bool(b) => Ok(OracleBind::Bool(*b)),
        Value::String(s) => Ok(OracleBind::String(s.clone())),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(OracleBind::I64(i))
            } else if let Some(f) = n.as_f64() {
                Ok(OracleBind::F64(f))
            } else {
                Err(invalid_args(format!("unsupported numeric bind: {n}")))
            }
        }
        other => Err(invalid_args(format!(
            "bind values must be string/number/bool/null, got: {other}"
        ))),
    }
}

/// Build an `InvalidArguments` envelope (malformed args / unknown tool).
fn invalid_args(message: impl Into<String>) -> ErrorEnvelope {
    ErrorEnvelope::new(ErrorClass::InvalidArguments, message)
}

/// Deserialize a tool's args struct, mapping a serde error to a structured
/// `InvalidArguments` envelope (never a panic).
fn parse_args<T: for<'de> Deserialize<'de>>(tool: &str, args: Value) -> Result<T, ErrorEnvelope> {
    // An MCP client may legally omit `arguments`; the transport maps that to
    // `Value::Null`, which `from_value` rejects even for all-optional structs.
    let args = match args {
        Value::Null => Value::Object(serde_json::Map::new()),
        other => other,
    };
    serde_json::from_value(args)
        .map_err(|e| invalid_args(format!("invalid arguments for {tool}: {e}")))
}

fn ensure_no_args(tool: &str, args: Value) -> Result<(), ErrorEnvelope> {
    match args {
        Value::Object(map) if map.is_empty() => Ok(()),
        Value::Null => Ok(()),
        other => Err(invalid_args(format!(
            "invalid arguments for {tool}: expected an empty object, got {other}"
        ))),
    }
}

fn non_empty_arg(value: Option<String>) -> Option<String> {
    value.and_then(|v| {
        let trimmed = v.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

async fn owner_or_current_cx(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<String>,
) -> Result<String, DbError> {
    match non_empty_arg(owner) {
        Some(owner) => Ok(owner.to_ascii_uppercase()),
        None => {
            let info = describe_conn(cx, conn).await?;
            info.current_schema
                .map(|owner| owner.to_ascii_uppercase())
                .ok_or_else(|| {
                    DbError::Query(
                        "owner is required because current_schema could not be detected".to_owned(),
                    )
                })
        }
    }
}

fn required_non_empty_arg(
    tool: &str,
    field: &str,
    value: Option<String>,
) -> Result<String, ErrorEnvelope> {
    non_empty_arg(value).ok_or_else(|| {
        invalid_args(format!(
            "invalid arguments for {tool}: missing required `{field}`"
        ))
    })
}

fn required_switch_profile_arg(tool: &str, value: Option<String>) -> Result<String, ErrorEnvelope> {
    non_empty_arg(value).ok_or_else(|| {
        invalid_args(format!(
            "invalid arguments for {tool}: provide `profile` or compatibility alias `db`"
        ))
        .with_suggested_tool("oracle_list_profiles")
        .with_next_step("call oracle_list_profiles to inspect configured profile names")
        .with_next_step(
            "call oracle_switch_profile with {\"profile\":\"<name>\"} or {\"db\":\"<name>\"}",
        )
    })
}

fn split_qualified_name(
    value: &str,
    label: &str,
) -> Result<(Option<String>, String), ErrorEnvelope> {
    let value = value.trim();
    if value.is_empty() {
        return Err(invalid_args(format!("{label} must not be empty")));
    }
    let parts: Vec<&str> = value.split('.').collect();
    match parts.as_slice() {
        [name] if !name.trim().is_empty() => Ok((None, name.trim().to_owned())),
        [owner, name] if !owner.trim().is_empty() && !name.trim().is_empty() => {
            Ok((Some(owner.trim().to_owned()), name.trim().to_owned()))
        }
        _ => Err(invalid_args(format!(
            "{label} must be an unquoted name or OWNER.NAME"
        ))),
    }
}

async fn owner_and_name_arg(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<String>,
    name: String,
    label: &str,
) -> Result<(String, String), ErrorEnvelope> {
    let explicit_owner = non_empty_arg(owner);
    let (qualified_owner, object_name) = split_qualified_name(&name, label)?;
    let owner = match (explicit_owner, qualified_owner) {
        (Some(explicit), Some(qualified)) if !explicit.eq_ignore_ascii_case(&qualified) => {
            return Err(invalid_args(format!(
                "conflicting owner arguments: owner={explicit:?}, {label}={name:?}"
            )));
        }
        (Some(explicit), _) => explicit,
        (None, Some(qualified)) => qualified,
        (None, None) => owner_or_current_cx(cx, conn, None)
            .await
            .map_err(DbError::into_envelope)?,
    };
    Ok((owner.to_ascii_uppercase(), object_name.to_ascii_uppercase()))
}

/// The fail-closed read-only gate for tools that accept a raw caller SQL
/// statement (`oracle_query`, plus the inner SQL of `oracle_explain_plan`).
/// Every such statement is run through the `oraclemcp-guard` classifier and
/// refused — *before* it can reach Oracle — unless the guard proves it needs no
/// more than `READ_ONLY`. Writes, DDL/DCL, and any `Forbidden` construct
/// (multi-statement batch, string-concat dynamic SQL, an unproven function call
/// in a SELECT, …) are rejected with a structured envelope. Proven read-only
/// `SELECT`/`WITH` and dictionary introspection pass.
fn ensure_read_only(sql: &str) -> Result<(), ErrorEnvelope> {
    ensure_read_only_decision(DEFAULT_CLASSIFIER.classify(sql))
        .map_err(|envelope| attach_parameterization_hint(envelope, sql))
}

/// K7: if a refused statement carries inline literals at bind-safe positions,
/// append a concrete "parameterize these literals" next step. Purely additive
/// coaching — it never changes the class or the refusal, only the guidance —
/// and it is skipped when there is nothing bind-safe to suggest.
fn attach_parameterization_hint(envelope: ErrorEnvelope, sql: &str) -> ErrorEnvelope {
    if !matches!(
        envelope.error_class,
        ErrorClass::ForbiddenStatement | ErrorClass::OperatingLevelTooLow
    ) {
        return envelope;
    }
    match oraclemcp_guard::suggest_parameterized_form(sql) {
        Some(rewrite) => envelope.with_next_step(format!(
            "parameterize inline literals to enable cursor sharing and avoid literal exposure, \
             e.g. `{rewrite}`"
        )),
        None => envelope,
    }
}

fn ensure_read_only_decision(decision: GuardDecision) -> Result<(), ErrorEnvelope> {
    // A session whose ceiling is READ_ONLY: `gate` returns `Allow` only for
    // statements the guard proved read-only; everything else is `Blocked` or
    // `RequireStepUp`, both of which this (step-up-less) server rejects.
    let session = SessionLevelState::new(OperatingLevel::ReadOnly, false);
    if matches!(decision.gate(&session), LevelDecision::Allow) {
        return Ok(());
    }
    // `Forbidden` (never dispatchable at any level) vs. merely needs-a-higher-
    // level — surfaced as distinct, machine-stable error classes.
    let class = if decision.required_level.is_none() {
        ErrorClass::ForbiddenStatement
    } else {
        ErrorClass::OperatingLevelTooLow
    };
    // K8: build the structured "why blocked + minimal safe rewrite" reason from
    // the decision before we consume its fields for the legacy next step.
    let structured = structured_reason_for(&decision, class);
    Err(ErrorEnvelope::new(
        class,
        format!(
            "read-only server refused this statement: {}",
            decision.reason
        ),
    )
    .with_structured_reason(structured)
    .with_next_step(decision.safe_alternative.unwrap_or_else(|| {
        "this server accepts only read-only statements — SELECT/WITH plus the \
         dictionary tools (oracle_schema_inspect, oracle_describe, oracle_get_ddl, \
         oracle_get_source, oracle_describe_index, oracle_describe_trigger, \
         oracle_describe_view, oracle_sample_rows, oracle_read_clob, \
         oracle_compile_errors, oracle_search_source, oracle_plscope_inspect)"
            .to_owned()
    })))
}

/// K8: translate a refusing [`GuardDecision`] into the structured reason carried
/// on the error envelope — the machine-stable category, the offending construct,
/// the required level (for a level gate), and the *minimal* rewrite that would
/// make the statement acceptable. Some refusals (an unbalanced block, dynamic
/// SQL) have no minimal rewrite; the agent should then fall back to
/// `suggested_tool`. Purely additive: it reads the decision, never alters it.
fn structured_reason_for(decision: &GuardDecision, class: ErrorClass) -> StructuredReason {
    let category = decision.reason_category.unwrap_or(ReasonCategory::Other);
    let mut reason = StructuredReason::new(category);
    if let Some(construct) = &decision.offending_construct {
        reason = reason.with_offending_construct(construct.clone());
    }
    // The required operating level is only meaningful for a level gate.
    if class == ErrorClass::OperatingLevelTooLow
        && let Some(level) = decision.required_level
    {
        reason = reason.with_required_level(level.as_str());
    }
    if let Some(rewrite) = minimal_rewrite_for(decision) {
        reason = reason.with_minimal_rewrite(rewrite);
    }
    reason
}

/// The smallest edit that would make a refused statement acceptable, or `None`
/// when no minimal rewrite exists (fall back to `suggested_tool`).
fn minimal_rewrite_for(decision: &GuardDecision) -> Option<String> {
    match decision.reason_category {
        Some(ReasonCategory::MultiStatementBatch) => Some(
            "submit each statement in its own oracle_query / oracle_execute call so the \
             classifier can level them individually"
                .to_owned(),
        ),
        // A benign PL/SQL block carries its own packaging suggestion.
        Some(ReasonCategory::PlSqlBlock) => decision.safe_alternative.clone(),
        // A well-formed write/DDL that only needs a higher level: the minimal
        // change is to run it at that level (surfaced via `required_level`).
        Some(ReasonCategory::RequiresHigherLevel) => decision.required_level.map(|level| {
            format!(
                "run this at operating level {} (oracle_set_session_level), or issue a read instead",
                level.as_str()
            )
        }),
        // Dynamic SQL, unbalanced blocks, block-list hits, and unproven
        // side-effects have no single safe rewrite.
        _ => None,
    }
}

fn explain_plan_gate_error(gate: LevelDecision, session: &SessionLevelState) -> ErrorEnvelope {
    gate_error(
        gate,
        session,
        &GateErrorLabels {
            subject: "oracle_explain_plan PLAN_TABLE diagnostic write",
            step_up_tool: "oracle_set_session_level",
            step_up_inspect_step: "call oracle_set_session_level without execute=true to preview a READ_WRITE elevation",
            step_up_elevation_step: "retry oracle_explain_plan with allow_plan_table_write=true only after the session is at READ_WRITE",
            ceiling_step: "choose a profile whose max_level permits READ_WRITE, or use DBMS_XPLAN.DISPLAY_CURSOR against an existing cursor",
            policy_denied_message: "oracle_explain_plan PLAN_TABLE diagnostic write is blocked by policy",
            internal_message: "oracle_explain_plan gate produced an unexpected decision",
        },
        None,
    )
}

fn ensure_explain_plan_write_allowed(
    args: &ExplainPlanArgs,
    session: &SessionLevelState,
) -> Result<(), ErrorEnvelope> {
    if args.read_only_standby {
        return Err(ErrorEnvelope::new(
            ErrorClass::PolicyDenied,
            "oracle_explain_plan writes PLAN_TABLE and is disabled on a read-only standby",
        )
        .with_next_step("use DBMS_XPLAN.DISPLAY_CURSOR against an existing cursor instead"));
    }

    if !args.allow_plan_table_write {
        return Err(ErrorEnvelope::new(
            ErrorClass::PolicyDenied,
            "oracle_explain_plan writes PLAN_TABLE; pass allow_plan_table_write=true only when a diagnostic write is acceptable",
        )
        .with_suggested_tool("oracle_set_session_level")
        .with_next_step("call oracle_preview_sql first if you only need to verify the inner SQL is read-only")
        .with_next_step("for primary databases where PLAN_TABLE writes are acceptable, elevate to READ_WRITE and retry with allow_plan_table_write=true"));
    }

    let gate = session.evaluate(Some(OperatingLevel::ReadWrite));
    if matches!(gate, LevelDecision::Allow) {
        Ok(())
    } else {
        Err(explain_plan_gate_error(gate, session))
    }
}

fn execute_grant_token_fields(
    binding: &ExecGrantBinding,
    active_profile: Option<&str>,
    required_level: OperatingLevel,
) -> Vec<String> {
    vec![
        active_profile.unwrap_or("").to_owned(),
        binding.session_id.clone(),
        binding.lane_id.clone(),
        binding.subject_id.clone(),
        binding.generation.to_string(),
        required_level.as_str().to_owned(),
    ]
}

fn sign_execute_grant_reference(
    raw_grant_id: &str,
    binding: &ExecGrantBinding,
    active_profile: Option<&str>,
    required_level: OperatingLevel,
) -> String {
    let fields = execute_grant_token_fields(binding, active_profile, required_level);
    let refs = fields.iter().map(String::as_str).collect::<Vec<_>>();
    sign_token(EXECUTE_GRANT_TOKEN_SCOPE, raw_grant_id, &refs)
}

fn verify_execute_grant_reference(
    token: &str,
    binding: &ExecGrantBinding,
    active_profile: Option<&str>,
    required_level: OperatingLevel,
) -> Option<String> {
    let fields = execute_grant_token_fields(binding, active_profile, required_level);
    let refs = fields.iter().map(String::as_str).collect::<Vec<_>>();
    verify_token(EXECUTE_GRANT_TOKEN_SCOPE, token, &refs)
}

fn issue_confirmation_grant(
    grants: &ExecGrantStore,
    binding: &ExecGrantBinding,
    active_profile: Option<&str>,
    material: &str,
    required_level: OperatingLevel,
) -> String {
    let raw = grants.issue(
        material,
        binding.clone(),
        required_level,
        Duration::from_secs(EXECUTE_APPROVED_TOKEN_TTL_SECONDS),
    );
    sign_execute_grant_reference(&raw, binding, active_profile, required_level)
}

struct ConfirmationGrantRequest<'a> {
    material: &'a str,
    required_level: OperatingLevel,
    active_profile: Option<&'a str>,
    grants: &'a ExecGrantStore,
    binding: &'a ExecGrantBinding,
    confirm: Option<&'a str>,
    challenge_message: &'static str,
    suggested_tool: &'a str,
    next_step: &'static str,
}

fn consume_confirmation_grant(
    request: ConfirmationGrantRequest<'_>,
) -> Result<String, ErrorEnvelope> {
    let Some(confirm) = request
        .confirm
        .and_then(|value| non_empty_arg(Some(value.to_owned())))
    else {
        return Err(
            ErrorEnvelope::new(ErrorClass::ChallengeRequired, request.challenge_message)
                .with_suggested_tool(request.suggested_tool)
                .with_next_step(request.next_step),
        );
    };
    let raw_id = verify_execute_grant_reference(
        &confirm,
        request.binding,
        request.active_profile,
        request.required_level,
    )
    .ok_or_else(|| {
        ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            "confirmation grant is invalid for this statement, lane, principal, generation, or active profile",
        )
        .with_suggested_tool(request.suggested_tool)
        .with_next_step(request.next_step)
    })?;
    request
        .grants
        .consume(
            &raw_id,
            request.material,
            request.binding,
            request.required_level,
        )
        .map(|_| raw_id)
        .map_err(|e| confirmation_grant_error(e, request.suggested_tool, request.next_step))
}

fn confirmation_grant_error(
    e: ExecGrantError,
    suggested_tool: &str,
    next_step: &'static str,
) -> ErrorEnvelope {
    match e {
        ExecGrantError::Unknown => ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            "confirmation grant is unknown or already used; preview again",
        )
        .with_suggested_tool(suggested_tool)
        .with_next_step(next_step),
        ExecGrantError::Expired => ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            "confirmation grant expired; preview again",
        )
        .with_suggested_tool(suggested_tool)
        .with_next_step(next_step),
        ExecGrantError::DigestMismatch => ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            "confirmation grant belongs to a different statement or action",
        )
        .with_suggested_tool(suggested_tool)
        .with_next_step(next_step),
        ExecGrantError::SessionMismatch => ErrorEnvelope::new(
            ErrorClass::RuntimeStateRequired,
            "confirmation grant belongs to a different MCP session",
        ),
        ExecGrantError::LaneMismatch => ErrorEnvelope::new(
            ErrorClass::RuntimeStateRequired,
            "confirmation grant belongs to a different dispatch lane",
        ),
        ExecGrantError::SubjectMismatch => ErrorEnvelope::new(
            ErrorClass::RuntimeStateRequired,
            "confirmation grant belongs to a different principal",
        ),
        ExecGrantError::GenerationMismatch { presented, granted } => ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            format!(
                "confirmation grant was minted for generation {granted}, but current generation is {presented}"
            ),
        )
        .with_suggested_tool(suggested_tool)
        .with_next_step(next_step),
        ExecGrantError::LevelExceedsGrant { requested, granted } => ErrorEnvelope::new(
            ErrorClass::OperatingLevelTooLow,
            format!(
                "requested level {} exceeds the granted level {}",
                requested.as_str(),
                granted.as_str()
            ),
        ),
        _ => ErrorEnvelope::new(ErrorClass::ChallengeRequired, "confirmation grant rejected")
            .with_suggested_tool(suggested_tool)
            .with_next_step(next_step),
    }
}

fn session_level_view(session: &SessionLevelState) -> Value {
    json!({
        "current_level": session.effective_level(),
        "profile_ceiling": session.effective_ceiling(),
        "max_level": session.max_level(),
        "protected": session.is_protected(),
        "has_active_elevation": session.has_active_elevation(),
    })
}

fn parse_session_level(tool: &str, raw: &str) -> Result<OperatingLevel, ErrorEnvelope> {
    OperatingLevel::parse(raw).ok_or_else(|| {
        invalid_args(format!(
            "invalid arguments for {tool}: unknown operating level {:?}; use READ_ONLY, READ_WRITE, DDL, or ADMIN",
            raw.trim()
        ))
        .with_next_step("call oracle_set_session_level with level=\"READ_WRITE\", \"DDL\", \"ADMIN\", or \"READ_ONLY\"")
    })
}

fn ttl_from_session_level_args(args: &SetSessionLevelArgs) -> Result<u64, ErrorEnvelope> {
    let ttl = args
        .ttl_seconds
        .unwrap_or(DEFAULT_SESSION_LEVEL_TTL_SECONDS);
    if ttl == 0 || ttl > MAX_SESSION_LEVEL_TTL_SECONDS {
        return Err(invalid_args(format!(
            "ttl_seconds must be between 1 and {MAX_SESSION_LEVEL_TTL_SECONDS}"
        )));
    }
    Ok(ttl)
}

fn normalized_session_level_action(invoked_as: &str, args: &SetSessionLevelArgs) -> String {
    if invoked_as == "disable_writes" {
        return "drop".to_owned();
    }
    args.action
        .as_deref()
        .unwrap_or(if args.execute { "apply" } else { "preview" })
        .trim()
        .to_ascii_lowercase()
}

fn session_level_grant_material(target: OperatingLevel, ttl_seconds: u64) -> String {
    format!("session-level:{}:{ttl_seconds}", target.as_str())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GrantVerification {
    Required,
    AlreadyVerified,
}

#[derive(Clone, Copy)]
struct SessionGrantContext<'a> {
    active_profile: Option<&'a str>,
    grants: &'a ExecGrantStore,
    binding: &'a ExecGrantBinding,
}

fn session_level_gate_json(session: &SessionLevelState, target: OperatingLevel) -> Value {
    match session.evaluate(Some(target)) {
        LevelDecision::Allow => json!({
            "decision": "allow",
        }),
        LevelDecision::RequireStepUp { target } => json!({
            "decision": "require_step_up",
            "target": target,
        }),
        LevelDecision::Blocked { reason } => match reason {
            oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling } => json!({
                "decision": "blocked",
                "reason": {
                    "type": "exceeds_ceiling",
                    "required": required,
                    "ceiling": ceiling,
                },
            }),
            oraclemcp_guard::BlockReason::Forbidden => json!({
                "decision": "blocked",
                "reason": { "type": "forbidden" },
            }),
            _ => json!({
                "decision": "blocked",
                "reason": { "type": "unknown" },
            }),
        },
        _ => json!({
            "decision": "unknown",
        }),
    }
}

fn session_level_gate_error(session: &SessionLevelState, target: OperatingLevel) -> ErrorEnvelope {
    match session.evaluate(Some(target)) {
        LevelDecision::Blocked {
            reason: oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling },
        } => ErrorEnvelope::new(
            ErrorClass::OperatingLevelTooLow,
            format!(
                "session level {} exceeds the active profile ceiling {}",
                required.as_str(),
                ceiling.as_str()
            ),
        )
        .with_suggested_tool("oracle_list_profiles")
        .with_next_step("choose a profile whose max_level permits the requested operation"),
        LevelDecision::Blocked { .. } => {
            ErrorEnvelope::new(ErrorClass::PolicyDenied, "session level change is blocked")
        }
        LevelDecision::RequireStepUp { target } => ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            format!(
                "session level elevation to {} requires the single-use confirmation grant returned by oracle_set_session_level preview",
                target.as_str()
            ),
        )
        .with_suggested_tool("oracle_set_session_level")
        .with_next_step("call oracle_set_session_level without execute=true, then pass confirmation.confirm as confirm"),
        LevelDecision::Allow => ErrorEnvelope::new(
            ErrorClass::Internal,
            "session level gate unexpectedly allowed a failed request",
        ),
        _ => ErrorEnvelope::new(
            ErrorClass::Internal,
            "session level gate produced an unexpected decision",
        ),
    }
}

fn escalation_error_to_envelope(e: EscalationError) -> ErrorEnvelope {
    match e {
        EscalationError::ExceedsCeiling { requested, ceiling } => ErrorEnvelope::new(
            ErrorClass::OperatingLevelTooLow,
            format!(
                "cannot elevate to {} because the active profile ceiling is {}",
                requested.as_str(),
                ceiling.as_str()
            ),
        )
        .with_suggested_tool("oracle_list_profiles")
        .with_next_step("choose a profile whose max_level permits the requested operation"),
        _ => ErrorEnvelope::new(ErrorClass::PolicyDenied, "session level elevation rejected"),
    }
}

fn scoped_session_level(
    session: &SessionLevelState,
    context: DispatchContext<'_>,
) -> SessionLevelState {
    let mut scoped = session.clone();
    if let Some(grant) = context.scope_grant() {
        let scopes = grant.0.iter().map(String::as_str).collect::<Vec<_>>();
        apply_oauth_scopes(&mut scoped, &scopes);
    }
    scoped
}

fn session_level_response_changed(response: &Value) -> bool {
    response
        .get("changed")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && !response
            .get("preview")
            .and_then(Value::as_bool)
            .unwrap_or(false)
}

fn set_session_level_with_scope(
    stored_session: &mut SessionLevelState,
    scoped_session: &SessionLevelState,
    grant_ctx: SessionGrantContext<'_>,
    invoked_as: &str,
    args: SetSessionLevelArgs,
    scoped: bool,
) -> Result<Value, ErrorEnvelope> {
    if !scoped {
        return set_session_level(
            stored_session,
            grant_ctx,
            invoked_as,
            args,
            GrantVerification::Required,
        );
    }
    let mut request_session = scoped_session.clone();
    let response = set_session_level(
        &mut request_session,
        grant_ctx,
        invoked_as,
        args.clone(),
        GrantVerification::Required,
    )?;
    if session_level_response_changed(&response) {
        set_session_level(
            stored_session,
            grant_ctx,
            invoked_as,
            args,
            GrantVerification::AlreadyVerified,
        )?;
    }
    Ok(response)
}

fn set_session_level(
    session: &mut SessionLevelState,
    grant_ctx: SessionGrantContext<'_>,
    invoked_as: &str,
    args: SetSessionLevelArgs,
    verification: GrantVerification,
) -> Result<Value, ErrorEnvelope> {
    let action = normalized_session_level_action(invoked_as, &args);
    if matches!(
        action.as_str(),
        "status" | "get" | "show" | "inspect" | "current"
    ) {
        return Ok(json!({
            "changed": false,
            "preview": false,
            "action": "status",
            "session": session_level_view(session),
        }));
    }
    if matches!(
        action.as_str(),
        "drop" | "de_escalate" | "de-escalate" | "disable" | "read_only"
    ) {
        session.drop_elevation();
        session
            .set_current_level(OperatingLevel::ReadOnly)
            .map_err(escalation_error_to_envelope)?;
        return Ok(json!({
            "changed": true,
            "preview": false,
            "action": "drop",
            "target_level": OperatingLevel::ReadOnly,
            "session": session_level_view(session),
            "next_actions": [
                {
                    "intent": "run_reads_only",
                    "tool": "oracle_query",
                    "args": { "sql": "SELECT 1 FROM dual" }
                }
            ],
        }));
    }
    if !matches!(action.as_str(), "preview" | "apply" | "execute") {
        return Err(invalid_args(format!(
            "invalid arguments for {invoked_as}: action must be preview, apply, drop, or status"
        )));
    }

    let ttl_seconds = ttl_from_session_level_args(&args)?;
    let target = if invoked_as == "enable_writes" {
        OperatingLevel::ReadWrite
    } else {
        let raw = required_non_empty_arg(invoked_as, "level", args.level)?;
        parse_session_level(invoked_as, &raw)?
    };
    if target == OperatingLevel::ReadOnly {
        session.drop_elevation();
        session
            .set_current_level(OperatingLevel::ReadOnly)
            .map_err(escalation_error_to_envelope)?;
        return Ok(json!({
            "changed": true,
            "preview": false,
            "action": "drop",
            "target_level": OperatingLevel::ReadOnly,
            "session": session_level_view(session),
        }));
    }

    let current = session.effective_level();
    if target < current {
        if action == "preview" {
            return Ok(json!({
                "changed": false,
                "preview": true,
                "action": "preview",
                "target_level": target,
                "session": session_level_view(session),
                "gate": {
                    "decision": "allow_lowering",
                    "from": current,
                    "to": target,
                },
                "confirmation": Value::Null,
                "next_actions": [
                    {
                        "intent": "apply_session_level_lowering",
                        "tool": "oracle_set_session_level",
                        "args": { "level": target, "action": "apply" }
                    }
                ],
            }));
        }
        session.drop_elevation();
        session
            .set_current_level(target)
            .map_err(escalation_error_to_envelope)?;
        return Ok(json!({
            "changed": true,
            "preview": false,
            "action": "apply",
            "target_level": target,
            "session": session_level_view(session),
            "next_actions": [
                {
                    "intent": "drop_session_level",
                    "tool": "oracle_set_session_level",
                    "args": { "action": "drop" }
                }
            ],
        }));
    }

    let gate = session.evaluate(Some(target));
    let grant_material = session_level_grant_material(target, ttl_seconds);
    let confirm = matches!(gate, LevelDecision::RequireStepUp { .. }).then(|| {
        issue_confirmation_grant(
            grant_ctx.grants,
            grant_ctx.binding,
            grant_ctx.active_profile,
            &grant_material,
            target,
        )
    });
    let next_actions = match gate {
        LevelDecision::Allow => json!([
            {
                "intent": "continue",
                "message": "The active session already permits this level."
            }
        ]),
        LevelDecision::RequireStepUp { .. } => json!([
            {
                "intent": "apply_session_level",
                "tool": invoked_as,
                "args": {
                    "level": target,
                    "ttl_seconds": ttl_seconds,
                    "execute": true,
                    "confirm": confirm.clone()
                }
            },
            {
                "intent": "drop_session_level",
                "tool": "oracle_set_session_level",
                "args": { "action": "drop" }
            }
        ]),
        LevelDecision::Blocked { .. } => json!([
            {
                "intent": "choose_different_profile",
                "tool": "oracle_list_profiles",
                "args": {},
                "required_level": target,
                "current_ceiling": session.effective_ceiling()
            }
        ]),
        _ => Value::Array(Vec::new()),
    };

    if action == "preview" {
        return Ok(json!({
            "changed": false,
            "preview": true,
            "action": "preview",
            "target_level": target,
            "ttl_seconds": ttl_seconds,
            "session": session_level_view(session),
            "gate": session_level_gate_json(session, target),
            "confirmation": if matches!(gate, LevelDecision::RequireStepUp { .. }) {
                json!({
                    "tool": invoked_as,
                    "confirm": confirm.clone().expect("step-up gate minted a confirmation grant"),
                    "execute": true,
                    "ttl_seconds": ttl_seconds,
                    "target_level": target,
                    "note": "Pass confirm only when you intend to temporarily elevate this active session within the profile ceiling."
                })
            } else {
                Value::Null
            },
            "next_actions": next_actions,
        }));
    }

    match gate {
        LevelDecision::Allow => Ok(json!({
            "changed": false,
            "preview": false,
            "action": "apply",
            "target_level": target,
            "ttl_seconds": ttl_seconds,
            "session": session_level_view(session),
            "message": "The active session already permits this level.",
        })),
        LevelDecision::RequireStepUp { .. } => {
            if verification == GrantVerification::Required {
                consume_confirmation_grant(ConfirmationGrantRequest {
                    material: &grant_material,
                    required_level: target,
                    active_profile: grant_ctx.active_profile,
                    grants: grant_ctx.grants,
                    binding: grant_ctx.binding,
                    confirm: args.confirm.as_deref(),
                    challenge_message: "session level elevation requires the single-use confirmation grant returned by oracle_set_session_level preview",
                    suggested_tool: "oracle_set_session_level",
                    next_step: "call oracle_set_session_level without execute=true, then pass confirmation.confirm as confirm",
                })?;
            }
            session
                .escalate_window(target, Duration::from_secs(ttl_seconds))
                .map_err(escalation_error_to_envelope)?;
            Ok(json!({
                "changed": true,
                "preview": false,
                "action": "apply",
                "target_level": target,
                "ttl_seconds": ttl_seconds,
                "session": session_level_view(session),
                "next_actions": [
                    {
                        "intent": "drop_session_level",
                        "tool": "oracle_set_session_level",
                        "args": { "action": "drop" }
                    }
                ],
            }))
        }
        LevelDecision::Blocked { .. } => Err(session_level_gate_error(session, target)),
        _ => Err(ErrorEnvelope::new(
            ErrorClass::Internal,
            "session level gate produced an unexpected decision",
        )),
    }
}

fn execute_confirmation_json(
    required_level: Option<OperatingLevel>,
    gate: &LevelDecision,
    confirm: Option<&str>,
) -> Value {
    let Some(required_level) = required_level else {
        return Value::Null;
    };
    let Some(confirm) = confirm else {
        return Value::Null;
    };
    if required_level <= OperatingLevel::ReadOnly || !matches!(gate, LevelDecision::Allow) {
        return Value::Null;
    }
    json!({
        "tool": "oracle_execute",
        "confirm": confirm,
        "commit": true,
        "required_level": required_level,
        "note": "Pass confirm only when you intend to commit this exact statement on this active profile.",
    })
}

// The RequireStepUp and ExceedsCeiling next_actions arms are identical across
// every builder (preview/compile/create-or-replace/patch); only the Allow arm
// and the Forbidden message vary per tool.
fn push_step_up_actions(actions: &mut Vec<Value>, target: &OperatingLevel) {
    actions.push(json!({
        "intent": "preview_session_level_step_up",
        "tool": "oracle_set_session_level",
        "args": { "level": target, "ttl_seconds": DEFAULT_SESSION_LEVEL_TTL_SECONDS },
        "required_level": target,
    }));
    actions.push(json!({
        "intent": "choose_different_profile",
        "tool": "oracle_list_profiles",
        "args": {},
        "required_level": target,
    }));
}

fn push_exceeds_ceiling_action(
    actions: &mut Vec<Value>,
    required: &OperatingLevel,
    ceiling: &OperatingLevel,
) {
    actions.push(json!({
        "intent": "choose_different_profile",
        "tool": "oracle_list_profiles",
        "args": {},
        "required_level": required,
        "current_ceiling": ceiling,
    }));
}

fn preview_next_actions(
    sql: &str,
    decision: &GuardDecision,
    gate: &LevelDecision,
    confirm: Option<&str>,
) -> Value {
    let mut actions: Vec<Value> = Vec::new();
    match gate {
        LevelDecision::Allow => match decision.required_level {
            Some(level) if level <= OperatingLevel::ReadOnly => {
                actions.push(json!({
                    "intent": "run_read",
                    "tool": "oracle_query",
                    "args": { "sql": sql, "binds": [] },
                }));
            }
            Some(level) if level < OperatingLevel::Ddl => {
                actions.push(json!({
                    "intent": "rollback_preview",
                    "tool": "oracle_execute",
                    "args": { "sql": sql, "binds": [], "commit": false },
                }));
                if let Some(confirm) = confirm {
                    actions.push(json!({
                        "intent": "commit",
                        "tool": "oracle_execute",
                        "args": { "sql": sql, "binds": [], "commit": true, "confirm": confirm },
                    }));
                }
            }
            Some(_) => {
                if let Some(confirm) = confirm {
                    actions.push(json!({
                        "intent": "commit_ddl_or_admin",
                        "tool": "oracle_execute",
                        "args": { "sql": sql, "binds": [], "commit": true, "confirm": confirm },
                    }));
                }
            }
            None => {}
        },
        LevelDecision::RequireStepUp { target } => push_step_up_actions(&mut actions, target),
        LevelDecision::Blocked { reason } => match reason {
            oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling } => {
                push_exceeds_ceiling_action(&mut actions, required, ceiling);
            }
            oraclemcp_guard::BlockReason::Forbidden => {
                actions.push(json!({
                    "intent": "rewrite_sql",
                    "message": decision.safe_alternative.clone().unwrap_or_else(|| {
                        "rewrite as a simpler single statement or use a dedicated safe tool".to_owned()
                    }),
                }));
            }
            _ => {}
        },
        _ => {}
    }
    Value::Array(actions)
}

// Per-tool copy for the shared gate-error builder. The execute and compile tools
// share the gate-decision dispatch but differ in subject noun and remediation text.
struct GateErrorLabels {
    subject: &'static str,
    step_up_tool: &'static str,
    step_up_inspect_step: &'static str,
    step_up_elevation_step: &'static str,
    ceiling_step: &'static str,
    policy_denied_message: &'static str,
    internal_message: &'static str,
}

// `decision` is Some only on the execute path, where a Forbidden gate carries a
// classifier reason and safe-alternative; the compile path never produces a
// Forbidden gate, so it passes None and Forbidden falls through to PolicyDenied.
fn gate_error(
    gate: LevelDecision,
    session: &SessionLevelState,
    labels: &GateErrorLabels,
    decision: Option<&GuardDecision>,
) -> ErrorEnvelope {
    match gate {
        LevelDecision::RequireStepUp { target } => ErrorEnvelope::new(
            ErrorClass::OperatingLevelTooLow,
            format!(
                "{} requires {} but the active session level is {}",
                labels.subject,
                target.as_str(),
                session.effective_level().as_str()
            ),
        )
        .with_suggested_tool(labels.step_up_tool)
        .with_next_step(labels.step_up_inspect_step)
        .with_next_step(labels.step_up_elevation_step),
        LevelDecision::Blocked { reason } => match reason {
            oraclemcp_guard::BlockReason::Forbidden if decision.is_some() => {
                let decision = decision.expect("decision is Some in this arm");
                ErrorEnvelope::new(
                    ErrorClass::ForbiddenStatement,
                    format!(
                        "{} is forbidden by the SQL classifier: {}",
                        labels.subject, decision.reason
                    ),
                )
                .with_next_step(decision.safe_alternative.clone().unwrap_or_else(
                    || "rewrite the statement as a simpler, single SQL statement".to_owned(),
                ))
            }
            oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling } => {
                ErrorEnvelope::new(
                    ErrorClass::OperatingLevelTooLow,
                    format!(
                        "{} requires {} but the active profile ceiling is {}",
                        labels.subject,
                        required.as_str(),
                        ceiling.as_str()
                    ),
                )
                .with_suggested_tool("oracle_list_profiles")
                .with_next_step(labels.ceiling_step)
            }
            _ => ErrorEnvelope::new(ErrorClass::PolicyDenied, labels.policy_denied_message),
        },
        _ => ErrorEnvelope::new(ErrorClass::Internal, labels.internal_message),
    }
}

fn execute_gate_error(
    decision: &GuardDecision,
    gate: LevelDecision,
    session: &SessionLevelState,
) -> ErrorEnvelope {
    gate_error(
        gate,
        session,
        &GateErrorLabels {
            subject: "statement",
            step_up_tool: "oracle_preview_sql",
            step_up_inspect_step: "call oracle_preview_sql to inspect the required level and profile ceiling",
            step_up_elevation_step: "call oracle_set_session_level to preview a temporary elevation, or keep the profile read-only",
            ceiling_step: "choose a profile whose max_level permits the statement",
            policy_denied_message: "statement is blocked by policy",
            internal_message: "execute gate produced an unexpected decision",
        },
        Some(decision),
    )
}

fn consume_execute_confirmation(
    sql: &str,
    required_level: OperatingLevel,
    active_profile: Option<&str>,
    grants: &ExecGrantStore,
    binding: &ExecGrantBinding,
    confirm: Option<&str>,
) -> Result<String, ErrorEnvelope> {
    consume_confirmation_grant(ConfirmationGrantRequest {
        material: sql,
        required_level,
        active_profile,
        grants,
        binding,
        confirm,
        challenge_message: "commit requires the execution grant from oracle_preview_sql for this exact statement, lane, principal, and active profile",
        suggested_tool: "oracle_preview_sql",
        next_step: "call oracle_preview_sql with the exact sql, then pass execute_confirmation.confirm as confirm",
    })
}

fn dbms_output_limits(args: &ExecuteArgs) -> (usize, usize, u32) {
    let max_lines = args
        .dbms_output_max_lines
        .unwrap_or(DEFAULT_DBMS_OUTPUT_MAX_LINES)
        .clamp(1, MAX_DBMS_OUTPUT_MAX_LINES);
    let max_chars = args
        .dbms_output_max_chars
        .unwrap_or(DEFAULT_DBMS_OUTPUT_MAX_CHARS)
        .clamp(1, MAX_DBMS_OUTPUT_MAX_CHARS);
    let buffer_bytes = max_chars
        .saturating_mul(4)
        .clamp(2_000, MAX_DBMS_OUTPUT_BUFFER_BYTES) as u32;
    (max_lines, max_chars, buffer_bytes)
}

fn dbms_output_json(out: &DbmsOutput, max_lines: usize, max_chars: usize) -> Value {
    json!({
        "enabled": true,
        "lines": out.lines.clone(),
        "line_count": out.line_count,
        "char_count": out.char_count,
        "max_lines": max_lines,
        "max_chars": max_chars,
        "truncated": out.truncated,
    })
}

fn prune_execute_approved_tokens(state: &mut DispatcherState) {
    let now = Instant::now();
    state
        .execute_approved_tokens
        .retain(|_, grant| grant.expires_at > now);
    while state.execute_approved_tokens.len() >= MAX_EXECUTE_APPROVED_TOKENS {
        let Some(key) = state.execute_approved_tokens.keys().next().cloned() else {
            break;
        };
        state.execute_approved_tokens.remove(&key);
    }
}

fn remember_execute_approved_token(state: &mut DispatcherState, sql: &str, preview: &Value) {
    let Some(confirm) = preview
        .pointer("/execute_confirmation/confirm")
        .and_then(Value::as_str)
    else {
        return;
    };
    let Some(required_level) = preview
        .pointer("/execute_confirmation/required_level")
        .and_then(Value::as_str)
        .and_then(OperatingLevel::parse)
    else {
        return;
    };
    prune_execute_approved_tokens(state);
    state.execute_approved_tokens.insert(
        confirm.to_owned(),
        ExecuteApprovedGrant {
            sql: sql.to_owned(),
            required_level,
            active_profile: state.active_profile.clone(),
            expires_at: Instant::now() + Duration::from_secs(EXECUTE_APPROVED_TOKEN_TTL_SECONDS),
        },
    );
}

fn execute_approved_args(
    state: &mut DispatcherState,
    session: &SessionLevelState,
    args: ExecuteApprovedArgs,
) -> Result<ExecuteArgs, ErrorEnvelope> {
    let timeout_seconds = args.timeout_seconds;
    // Compatibility aliases inherit the canonical oracle_execute safety
    // default: omitting commit always means rollback-preview for DML. A preview
    // grant proves which SQL was reviewed; it is not implicit commit intent.
    let commit = args.commit.unwrap_or(false);
    if args.save_output.is_some() {
        return Err(invalid_args(
            "execute_approved does not write DBMS_OUTPUT to files; set capture_dbms_output=true and read dbms_output.lines from the tool result",
        )
        .with_suggested_tool("oracle_execute"));
    }

    let token = args.token.filter(|s| !s.trim().is_empty()).ok_or_else(|| {
        invalid_args("execute_approved requires token from preview_sql")
            .with_suggested_tool("preview_sql")
            .with_next_step("call preview_sql with the SQL statement, then pass execute_confirmation.confirm as token")
    })?;
    if let Some(sql) = args.sql.filter(|s| !s.trim().is_empty()) {
        return Ok(ExecuteArgs {
            sql,
            binds: Vec::new(),
            commit,
            confirm: Some(token),
            capture_dbms_output: args.capture_dbms_output,
            dbms_output_max_lines: args.dbms_output_max_lines,
            dbms_output_max_chars: args.dbms_output_max_chars,
            timeout_seconds,
        });
    }

    prune_execute_approved_tokens(state);
    let Some(grant) = state.execute_approved_tokens.remove(&token) else {
        return Err(ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            "execute_approved token is unknown or expired in this server process",
        )
        .with_suggested_tool("preview_sql")
        .with_next_step("call preview_sql again, then call execute_approved with the returned token within five minutes")
        .with_next_step("or call oracle_execute with sql, commit=true, and confirm"));
    };

    if grant.active_profile != state.active_profile {
        return Err(ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            "execute_approved token belongs to a different active profile",
        )
        .with_suggested_tool("preview_sql")
        .with_next_step(
            "switch back to the previewed profile or preview the SQL again on the active profile",
        ));
    }
    if session.evaluate(Some(grant.required_level)) != LevelDecision::Allow {
        return Err(execute_gate_error(
            &DEFAULT_CLASSIFIER.classify(&grant.sql),
            session.evaluate(Some(grant.required_level)),
            session,
        ));
    }

    Ok(ExecuteArgs {
        sql: grant.sql,
        binds: Vec::new(),
        commit,
        confirm: Some(token),
        capture_dbms_output: args.capture_dbms_output,
        dbms_output_max_lines: args.dbms_output_max_lines,
        dbms_output_max_chars: args.dbms_output_max_chars,
        timeout_seconds,
    })
}

/// An RFC-3339-ish UTC timestamp for audit records (display/forensics only; the
/// monotonic seq is the chain's order key, so a coarse clock string suffices and
/// we avoid a date-formatting dependency).
fn audit_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{secs}")
}

/// Map an `oraclemcp-audit` error to an agent-facing envelope. A failed audit
/// append is fail-closed: the served call errors and the statement does NOT run.
fn audit_error_to_envelope(e: oraclemcp_audit::AuditError) -> ErrorEnvelope {
    ErrorEnvelope::new(ErrorClass::Internal, format!("audit append failed: {e}"))
}

fn process_audit_subject() -> AuditSubject {
    AuditSubject::new("process", "stdio").with_authn_method("process")
}

fn audit_subject_from_principal_key(principal_key: &str) -> AuditSubject {
    if principal_key == "anonymous-http" {
        return AuditSubject::new("anonymous-http", "server-derived").with_authn_method("none");
    }
    let (kind, stable_id) = principal_key
        .split_once(':')
        .filter(|(kind, stable_id)| !kind.is_empty() && !stable_id.is_empty())
        .unwrap_or(("principal", principal_key));
    let authn_method = match kind {
        "oauth" => "oauth",
        "mtls" | "cert" => "mtls",
        "process" => "process",
        _ => "server",
    };
    AuditSubject::new(kind, stable_id).with_authn_method(authn_method)
}

/// The server-controlled subject recorded in the audit chain. Transports attach
/// a validated, redacted principal key; stdio/direct calls use the dispatcher
/// fallback. Tool arguments are deliberately ignored.
fn audit_subject(context: DispatchContext<'_>, fallback: &AuditSubject) -> AuditSubject {
    context
        .principal_key()
        .map(audit_subject_from_principal_key)
        .unwrap_or_else(|| fallback.clone())
}

fn grant_binding_for_context(
    state: &DispatcherState,
    context: DispatchContext<'_>,
) -> ExecGrantBinding {
    let session_id = context.http_session_id().unwrap_or("process");
    let lane_id = context.lane_id().unwrap_or(session_id);
    let subject_id = context.principal_key().unwrap_or("process");
    ExecGrantBinding::new(session_id, lane_id, subject_id, state.grant_generation)
}

/// The audit-sink bundle threaded through the execute-path tools: the optional
/// out-of-band [`Auditor`] and the server-controlled `subject` recorded
/// on every entry. Bundling these two always-paired values keeps the
/// execute/create-or-replace/deploy-DDL signatures under the argument-count
/// limit (so no `#[allow(clippy::too_many_arguments)]` is needed) without
/// changing any behavior — every consumer reads the same two fields.
#[derive(Clone, Copy)]
struct AuditCtx<'a> {
    auditor: Option<&'a Auditor>,
    subject: &'a AuditSubject,
}

#[derive(Clone, Copy)]
struct AuditEntryCtx<'a> {
    auditor: Option<&'a Auditor>,
    subject: &'a AuditSubject,
    db_evidence: Option<&'a DbEvidence>,
}

#[derive(Clone, Copy)]
struct DbToolCtx<'a> {
    cx: &'a Cx,
    conn: &'a dyn OracleConnection,
    request_budget: RequestBudget,
    active_profile: Option<&'a str>,
    session: &'a SessionLevelState,
    execute_grants: &'a ExecGrantStore,
    grant_binding: &'a ExecGrantBinding,
    write_intents: Option<&'a WriteIntentLog>,
    audit: AuditCtx<'a>,
    quarantine: &'a SyncMutex<Option<ConnectionQuarantine>>,
}

/// Build an audit draft for a served committing tool at a known danger level.
fn audit_draft(
    ctx: AuditEntryCtx<'_>,
    tool: &str,
    sql: &str,
    danger_level: &str,
    rows_affected: Option<u64>,
    outcome: AuditOutcome,
) -> AuditEntryDraft {
    AuditEntryDraft {
        subject: ctx.subject.clone(),
        db_evidence: ctx.db_evidence.cloned(),
        cancel: None,
        tool: tool.to_owned(),
        sql: sql.to_owned(),
        danger_level: danger_level.to_owned(),
        decision: AuditDecision::Allowed,
        rows_affected,
        outcome,
    }
}

fn present(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.trim().is_empty())
}

fn db_evidence_from_connection_info(info: OracleConnectionInfo) -> DbEvidence {
    DbEvidence {
        availability: Some("captured".to_owned()),
        db_unique_name: present(info.db_unique_name),
        service_name: present(info.service_name),
        instance_name: present(info.instance_name),
        session_user: present(info.session_user),
        current_user: present(info.current_user),
        proxy_user: present(info.proxy_user),
        current_schema: present(info.current_schema),
        sid: present(info.sid),
        serial_number: present(info.serial_number),
        client_identifier: present(info.client_identifier),
        module: present(info.module),
        action: present(info.action),
        database_role: present(info.database_role),
        open_mode: present(info.open_mode),
    }
}

async fn collect_audit_db_evidence(
    cx: &Cx,
    auditor: Option<&Auditor>,
    conn: &dyn OracleConnection,
) -> Option<DbEvidence> {
    auditor?;
    match conn.describe(cx).await {
        Ok(info) => Some(db_evidence_from_connection_info(info)),
        Err(_) => Some(DbEvidence::unavailable("describe_failed")),
    }
}

fn audit_danger_string(danger: DangerLevel) -> String {
    serde_json::to_value(danger)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "UNKNOWN".to_owned())
}

/// Durably append one execute-path audit entry when an auditor is configured.
/// Fail-closed: a failed append surfaces as an [`ErrorEnvelope`] so the call
/// errors rather than proceeding un-audited. No-op when `auditor` is `None`.
fn append_audit(
    ctx: AuditEntryCtx<'_>,
    tool: &str,
    sql: &str,
    danger_level: &str,
    rows_affected: Option<u64>,
    outcome: AuditOutcome,
) -> Result<(), ErrorEnvelope> {
    if let Some(auditor) = ctx.auditor {
        let draft = audit_draft(ctx, tool, sql, danger_level, rows_affected, outcome);
        auditor
            .append(&draft, audit_timestamp(), true)
            .map_err(audit_error_to_envelope)?;
    }
    Ok(())
}

fn system_generated_read_subject() -> AuditSubject {
    AuditSubject::new("system", "generated-read").with_authn_method("server")
}

fn db_internal_from_envelope(err: ErrorEnvelope) -> DbError {
    DbError::Internal(format!("{:?}: {}", err.error_class, err.message))
}

fn normalized_generated_sql(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase()
}

fn generated_read_sql_is_allowlisted(sql: &str) -> bool {
    let normalized = normalized_generated_sql(sql);
    if normalized.contains(';') || !normalized.starts_with("SELECT ") {
        return false;
    }

    const ALLOWED_SURFACE_TOKENS: &[&str] = &[
        " FROM ALL_",
        " JOIN ALL_",
        " FROM DBA_",
        " JOIN DBA_",
        " FROM USER_",
        " JOIN USER_",
        " FROM V$",
        " JOIN V$",
        " FROM GV$",
        " JOIN GV$",
        " FROM PERFSTAT.",
        " JOIN PERFSTAT.",
        " FROM STATS$",
        " JOIN STATS$",
        " DBMS_LOB.SUBSTR(",
        " DBMS_METADATA.GET_DDL(",
        " TABLE(DBMS_XPLAN.DISPLAY",
    ];
    if ALLOWED_SURFACE_TOKENS
        .iter()
        .any(|token| normalized.contains(token))
    {
        return true;
    }

    let sample_shape = normalized.starts_with("SELECT * FROM (SELECT * FROM ")
        && normalized.ends_with(") WHERE ROWNUM <= :1");
    let lob_lookup_shape = normalized.contains(" AS LOB_VALUE FROM ")
        && normalized.ends_with(" = :1 FETCH FIRST 1 ROW ONLY");
    sample_shape || lob_lookup_shape
}

fn ensure_generated_read_sql_allowed(sql: &str) -> Result<DangerLevel, ErrorEnvelope> {
    let baseline = GENERATED_READ_CLASSIFIER.classify(sql);
    if matches!(baseline.danger, DangerLevel::Forbidden) {
        return ensure_read_only_decision(baseline).map(|()| DangerLevel::Safe);
    }
    if !generated_read_sql_is_allowlisted(sql) {
        return Err(ErrorEnvelope::new(
            ErrorClass::PolicyDenied,
            "server-generated read SQL is not on the built-in metadata/monitor allowlist",
        )
        .with_next_step(
            "route ad-hoc SQL through oracle_query so the caller-supplied SQL gate owns it",
        ));
    }
    if ensure_read_only_decision(baseline.clone()).is_ok() {
        return Ok(baseline.danger);
    }
    let decision = Classifier::new(ClassifierConfig::new().with_allow(sql))
        .with_oracle(Arc::new(GeneratedReadPurityOracle))
        .classify(sql);
    let danger = decision.danger;
    ensure_read_only_decision(decision)?;
    Ok(danger)
}

fn generated_read_tool(tool: &str) -> bool {
    matches!(
        tool,
        "oracle_schema_inspect"
            | "oracle_search_objects"
            | "oracle_list_schemas"
            | "oracle_describe"
            | "oracle_describe_index"
            | "oracle_describe_trigger"
            | "oracle_describe_view"
            | "oracle_get_ddl"
            | "oracle_get_source"
            | "oracle_sample_rows"
            | "oracle_top_queries"
            | "oracle_db_health"
            | "oracle_read_clob"
            | "oracle_compile_errors"
            | "oracle_search_source"
            | "oracle_plscope_inspect"
    )
}

fn generated_read_uses_primary_session(tool: &str) -> bool {
    matches!(
        tool,
        "oracle_sample_rows" | "oracle_top_queries" | "oracle_db_health" | "oracle_read_clob"
    )
}

/// Whether a tool can run on a stateless read-worker lane instead of the
/// control/session lane.
///
/// This is deliberately narrower than "read-only": caller SQL, LOB reads,
/// samples, health/top-query diagnostics, and anything needing the pinned
/// session stay on the control lane. The worker set is for generated metadata
/// reads that can safely use a separate per-subject/profile connection.
#[must_use]
pub fn stateless_read_worker_tool(name: &str) -> bool {
    let tool = canonical_tool_name(name);
    generated_read_tool(tool) && !generated_read_uses_primary_session(tool)
}

#[derive(Clone, Copy)]
struct GeneratedReadAuditCtx<'a> {
    entry: AuditEntryCtx<'a>,
    tool: &'a str,
}

struct GuardedGeneratedReadConn<'a> {
    inner: &'a dyn OracleConnection,
    audit: GeneratedReadAuditCtx<'a>,
}

impl GuardedGeneratedReadConn<'_> {
    fn before_query(&self, sql: &str) -> Result<String, DbError> {
        let danger = ensure_generated_read_sql_allowed(sql).map_err(db_internal_from_envelope)?;
        let danger = audit_danger_string(danger);
        append_audit(
            self.audit.entry,
            self.audit.tool,
            sql,
            &danger,
            None,
            AuditOutcome::Pending,
        )
        .map_err(db_internal_from_envelope)?;
        Ok(danger)
    }

    fn after_query(&self, sql: &str, danger: &str, outcome: AuditOutcome) -> Result<(), DbError> {
        append_audit(
            self.audit.entry,
            self.audit.tool,
            sql,
            danger,
            None,
            outcome,
        )
        .map_err(db_internal_from_envelope)
    }
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for GuardedGeneratedReadConn<'_> {
    fn backend(&self) -> OracleBackend {
        self.inner.backend()
    }

    async fn ping(&self, cx: &Cx) -> Result<(), DbError> {
        self.inner.ping(cx).await
    }

    async fn describe(&self, cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        self.inner.describe(cx).await
    }

    async fn query_rows(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        let danger = self.before_query(sql)?;
        match self.inner.query_rows(cx, sql, binds).await {
            Ok(rows) => {
                self.after_query(sql, &danger, AuditOutcome::Succeeded)?;
                Ok(rows)
            }
            Err(err) => {
                self.after_query(sql, &danger, AuditOutcome::Failed)?;
                Err(err)
            }
        }
    }

    async fn query_rows_with_serialize_options(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
        serialize_opts: &SerializeOptions,
    ) -> Result<Vec<OracleRow>, DbError> {
        let danger = self.before_query(sql)?;
        match self
            .inner
            .query_rows_with_serialize_options(cx, sql, binds, serialize_opts)
            .await
        {
            Ok(rows) => {
                self.after_query(sql, &danger, AuditOutcome::Succeeded)?;
                Ok(rows)
            }
            Err(err) => {
                self.after_query(sql, &danger, AuditOutcome::Failed)?;
                Err(err)
            }
        }
    }

    async fn query_rows_named(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[(String, OracleBind)],
    ) -> Result<Vec<OracleRow>, DbError> {
        let danger = self.before_query(sql)?;
        match self.inner.query_rows_named(cx, sql, binds).await {
            Ok(rows) => {
                self.after_query(sql, &danger, AuditOutcome::Succeeded)?;
                Ok(rows)
            }
            Err(err) => {
                self.after_query(sql, &danger, AuditOutcome::Failed)?;
                Err(err)
            }
        }
    }

    async fn query_rows_named_with_serialize_options(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[(String, OracleBind)],
        serialize_opts: &SerializeOptions,
    ) -> Result<Vec<OracleRow>, DbError> {
        let danger = self.before_query(sql)?;
        match self
            .inner
            .query_rows_named_with_serialize_options(cx, sql, binds, serialize_opts)
            .await
        {
            Ok(rows) => {
                self.after_query(sql, &danger, AuditOutcome::Succeeded)?;
                Ok(rows)
            }
            Err(err) => {
                self.after_query(sql, &danger, AuditOutcome::Failed)?;
                Err(err)
            }
        }
    }

    async fn query_optional_row(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Option<OracleRow>, DbError> {
        let danger = self.before_query(sql)?;
        match self.inner.query_optional_row(cx, sql, binds).await {
            Ok(row) => {
                self.after_query(sql, &danger, AuditOutcome::Succeeded)?;
                Ok(row)
            }
            Err(err) => {
                self.after_query(sql, &danger, AuditOutcome::Failed)?;
                Err(err)
            }
        }
    }

    async fn execute(&self, _cx: &Cx, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
        Err(DbError::Internal(
            "generated-read connection refuses execute on a read-only tool path".to_owned(),
        ))
    }

    fn call_timeout(&self) -> Result<Option<Duration>, DbError> {
        self.inner.call_timeout()
    }

    fn set_call_timeout(&self, timeout: Option<Duration>) -> Result<(), DbError> {
        self.inner.set_call_timeout(timeout)
    }

    async fn commit(&self, cx: &Cx) -> Result<(), DbError> {
        self.inner.commit(cx).await
    }

    async fn rollback(&self, cx: &Cx) -> Result<(), DbError> {
        self.inner.rollback(cx).await
    }
}

fn close_reason_cancel(reason: DispatchCloseReason) -> AuditCancel {
    let kind = match reason {
        DispatchCloseReason::SessionDelete | DispatchCloseReason::OperatorCancel => "User",
        DispatchCloseReason::Timeout => "Timeout",
        DispatchCloseReason::ServerShutdown | DispatchCloseReason::RuntimeDrop => "Shutdown",
    };
    AuditCancel::new(kind, reason.as_str())
}

fn append_lifecycle_audit(
    auditor: Option<&Auditor>,
    subject: &AuditSubject,
    db_evidence: Option<&DbEvidence>,
    reason: DispatchCloseReason,
    outcome: AuditOutcome,
) -> Result<(), ErrorEnvelope> {
    if let Some(auditor) = auditor {
        let draft = AuditEntryDraft {
            subject: subject.clone(),
            db_evidence: db_evidence.cloned(),
            cancel: Some(close_reason_cancel(reason)),
            tool: "lane_lifecycle".to_owned(),
            sql: "LANE_CLOSE".to_owned(),
            danger_level: "LIFECYCLE".to_owned(),
            decision: AuditDecision::Allowed,
            rows_affected: None,
            outcome,
        };
        auditor
            .append(&draft, audit_timestamp(), true)
            .map_err(audit_error_to_envelope)?;
    }
    Ok(())
}

fn write_intent_error_to_envelope(e: WriteIntentError) -> ErrorEnvelope {
    let error_class = match &e {
        WriteIntentError::AlreadyResolved { .. } | WriteIntentError::IdempotencyConflict { .. } => {
            ErrorClass::RuntimeStateRequired
        }
        _ => ErrorClass::Internal,
    };
    let next_step = match &e {
        WriteIntentError::AlreadyResolved { .. } => {
            "do not replay this confirmation grant; inspect the prior durable write-intent/audit outcome"
        }
        WriteIntentError::IdempotencyConflict { .. } => {
            "do not reuse a confirmation grant for different SQL; preview the intended statement again"
        }
        _ => "do not retry non-idempotent work until the durable intent log is healthy",
    };
    ErrorEnvelope::new(error_class, format!("write-intent operation failed: {e}"))
        .with_next_step(next_step)
}

fn append_write_intent(
    ctx: &DbToolCtx<'_>,
    tool: &str,
    sql: &str,
    required_level: OperatingLevel,
    idempotency_key_material: &str,
) -> Result<Option<String>, ErrorEnvelope> {
    let Some(log) = ctx.write_intents else {
        return Ok(None);
    };
    let subject = ctx.audit.subject.legacy_agent_identity();
    let intent = WriteIntent::new(WriteIntentDetails {
        idempotency_key_material,
        subject: &subject,
        active_profile: ctx.active_profile,
        tool,
        sql,
        required_level,
        binding: ctx.grant_binding,
    });
    log.append_pending(intent)
        .map(Some)
        .map_err(write_intent_error_to_envelope)
}

fn resolve_write_intent(
    ctx: &DbToolCtx<'_>,
    intent_id: Option<&str>,
    outcome: WriteIntentOutcome,
) -> Result<(), ErrorEnvelope> {
    let (Some(log), Some(intent_id)) = (ctx.write_intents, intent_id) else {
        return Ok(());
    };
    log.resolve(intent_id, outcome)
        .map_err(write_intent_error_to_envelope)
}

fn resolve_write_intent_after_db(
    ctx: &DbToolCtx<'_>,
    intent_id: Option<&str>,
    outcome: WriteIntentOutcome,
    boundary: &str,
) -> Result<(), ErrorEnvelope> {
    if let Err(err) = resolve_write_intent(ctx, intent_id, outcome) {
        let message = format!(
            "{boundary}; durable write-intent resolution failed: {}",
            err.message
        );
        mark_connection_quarantined(
            ctx.quarantine,
            AuditOutcome::UnknownDiscarded,
            message.clone(),
        )?;
        return Err(
            quarantined_db_error(QuarantineOutcome::UnknownDiscarded, message).into_envelope(),
        );
    }
    Ok(())
}

fn audit_outcome_label(outcome: AuditOutcome) -> &'static str {
    match outcome {
        AuditOutcome::Pending => "pending",
        AuditOutcome::Succeeded => "succeeded",
        AuditOutcome::Failed => "failed",
        AuditOutcome::RolledBack => "rolled_back",
        AuditOutcome::DiscardedUncommitted => "discarded_uncommitted",
        AuditOutcome::CommitInDoubt => "commit_in_doubt",
        AuditOutcome::UnknownDiscarded => "unknown_discarded",
        _ => "unknown",
    }
}

fn mark_connection_quarantined(
    quarantine: &SyncMutex<Option<ConnectionQuarantine>>,
    outcome: AuditOutcome,
    message: impl Into<String>,
) -> Result<(), ErrorEnvelope> {
    let mut guard = quarantine.lock().map_err(|err| {
        ErrorEnvelope::new(
            ErrorClass::Internal,
            format!("connection-quarantine mutex lock failed: {err}"),
        )
    })?;
    *guard = Some(ConnectionQuarantine {
        outcome,
        message: message.into(),
    });
    Ok(())
}

fn quarantined_db_error(outcome: QuarantineOutcome, message: impl Into<String>) -> DbError {
    DbError::Quarantined {
        outcome,
        message: message.into(),
    }
}

async fn execute_sql(
    ctx: DbToolCtx<'_>,
    audit_tool: &str,
    args: ExecuteArgs,
) -> Result<Value, ErrorEnvelope> {
    let timeout_seconds = args.timeout_seconds;
    with_call_timeout(
        ctx.cx,
        ctx.conn,
        ctx.request_budget,
        timeout_seconds,
        || execute_sql_inner(ctx, audit_tool, args),
    )
    .await
}

async fn execute_sql_inner(
    ctx: DbToolCtx<'_>,
    audit_tool: &str,
    args: ExecuteArgs,
) -> Result<Value, ErrorEnvelope> {
    let cx = ctx.cx;
    let conn = ctx.conn;
    let active_profile = ctx.active_profile;
    let session = ctx.session;
    let audit = ctx.audit;
    let decision = DEFAULT_CLASSIFIER.classify(&args.sql);
    let gate = decision.gate(session);
    if !matches!(gate, LevelDecision::Allow) {
        return Err(execute_gate_error(&decision, gate, session));
    }

    let required_level = decision.required_level.ok_or_else(|| {
        ErrorEnvelope::new(
            ErrorClass::ForbiddenStatement,
            format!(
                "statement is forbidden by the SQL classifier: {}",
                decision.reason
            ),
        )
    })?;
    if required_level <= OperatingLevel::ReadOnly {
        return Err(invalid_args(
            "oracle_execute is for non-read statements; use oracle_query for SELECT/WITH",
        )
        .with_suggested_tool("oracle_query"));
    }
    if required_level >= OperatingLevel::Ddl && !args.commit {
        return Err(ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            "DDL/Admin statements cannot be rollback-previewed by Oracle; commit=true and confirm are required",
        )
        .with_suggested_tool("oracle_preview_sql")
        .with_next_step("call oracle_preview_sql and pass execute_confirmation.confirm to oracle_execute with commit=true"));
    }
    let commit_idempotency_key = if args.commit {
        Some(consume_execute_confirmation(
            &args.sql,
            required_level,
            active_profile,
            ctx.execute_grants,
            ctx.grant_binding,
            args.confirm.as_deref(),
        )?)
    } else {
        None
    };

    let binds = args
        .binds
        .iter()
        .map(json_to_bind)
        .collect::<Result<Vec<_>, _>>()?;

    // A3: prepend the per-statement audit marker. The gate/confirmation above ran
    // on the bare SQL (the text the agent previewed/confirmed); `with_audit_marker`
    // re-classifies the marked text and adopts it ONLY when its verdict is
    // identical to the bare verdict (else it returns the bare SQL), so the text we
    // are about to execute carries the SAME, already-gated classification. We
    // additionally assert that here — defense in depth — and fail closed on any
    // divergence so a marker can never change what runs. The marked text is what
    // we execute AND what the audit log records (A8 digest covers the real text).
    let executed_sql = with_audit_marker(&args.sql, active_profile, audit_tool);
    if DEFAULT_CLASSIFIER.classify(&executed_sql) != decision {
        return Err(ErrorEnvelope::new(
            ErrorClass::Internal,
            "audit marker changed the classifier verdict; refusing to execute",
        ));
    }

    // The audited danger tier (SAFE/GUARDED/DESTRUCTIVE) as a string; reads were
    // rejected above, so this is always a Guarded/Destructive write/DDL/Admin.
    let danger_str = audit_danger_string(decision.danger);
    let write_intent_id = match commit_idempotency_key.as_deref() {
        Some(key) => append_write_intent(&ctx, audit_tool, &executed_sql, required_level, key)?,
        None => None,
    };
    let db_evidence = collect_audit_db_evidence(cx, audit.auditor, conn).await;
    let audit_entry = AuditEntryCtx {
        auditor: audit.auditor,
        subject: audit.subject,
        db_evidence: db_evidence.as_ref(),
    };

    // fsync-before-execute (§5.13): durably log the approved statement BEFORE it
    // runs so a crash between here and the execute leaves the log written and the
    // database untouched. A failed durable append fails the call closed.
    if let Err(err) = append_audit(
        audit_entry,
        audit_tool,
        &executed_sql,
        &danger_str,
        None,
        AuditOutcome::Pending,
    ) {
        resolve_write_intent(
            &ctx,
            write_intent_id.as_deref(),
            WriteIntentOutcome::AbortedBeforeExecute,
        )?;
        return Err(err);
    }

    let dbms_output_limits = if args.capture_dbms_output {
        let (max_lines, max_chars, buffer_bytes) = dbms_output_limits(&args);
        enable_dbms_output_conn(cx, conn, Some(buffer_bytes))
            .await
            .map_err(DbError::into_envelope)?;
        Some((max_lines, max_chars))
    } else {
        None
    };
    let rows_affected = match execute_conn(cx, conn, &executed_sql, &binds).await {
        Ok(rows) => rows,
        Err(e) => {
            let rollback = conn.rollback(cx).await;
            let outcome = if rollback.is_ok() {
                AuditOutcome::RolledBack
            } else {
                mark_connection_quarantined(
                    ctx.quarantine,
                    AuditOutcome::UnknownDiscarded,
                    format!("execute failed and rollback cleanup failed: {e}"),
                )?;
                AuditOutcome::UnknownDiscarded
            };
            if e.is_uncertain_session_state() && rollback.is_ok() {
                mark_connection_quarantined(
                    ctx.quarantine,
                    AuditOutcome::RolledBack,
                    format!(
                        "execute failed after an uncertain DB boundary; rollback succeeded: {e}"
                    ),
                )?;
            }
            // Durably log the failed outcome before propagating.
            append_audit(
                audit_entry,
                audit_tool,
                &executed_sql,
                &danger_str,
                None,
                outcome,
            )?;
            if outcome == AuditOutcome::RolledBack {
                resolve_write_intent_after_db(
                    &ctx,
                    write_intent_id.as_deref(),
                    WriteIntentOutcome::RolledBack,
                    "execute failed and rollback completed",
                )?;
            }
            if let Err(cleanup_err) = rollback {
                return Err(quarantined_db_error(
                    QuarantineOutcome::UnknownDiscarded,
                    format!("execute failed and rollback cleanup failed: {cleanup_err}"),
                )
                .into_envelope());
            }
            return Err(DbError::into_envelope(e));
        }
    };
    if args.commit {
        if let Err(e) = commit_conn(cx, conn).await {
            mark_connection_quarantined(
                ctx.quarantine,
                AuditOutcome::CommitInDoubt,
                format!("commit failed after {rows_affected} affected row(s): {e}"),
            )?;
            append_audit(
                audit_entry,
                audit_tool,
                &executed_sql,
                &danger_str,
                Some(rows_affected),
                AuditOutcome::CommitInDoubt,
            )?;
            return Err(quarantined_db_error(
                QuarantineOutcome::CommitInDoubt,
                format!("commit failed after {rows_affected} affected row(s): {e}"),
            )
            .into_envelope());
        }
    } else {
        if let Err(e) = conn.rollback(cx).await {
            mark_connection_quarantined(
                ctx.quarantine,
                AuditOutcome::UnknownDiscarded,
                format!(
                    "rollback preview cleanup failed after {rows_affected} affected row(s): {e}"
                ),
            )?;
            append_audit(
                audit_entry,
                audit_tool,
                &executed_sql,
                &danger_str,
                Some(rows_affected),
                AuditOutcome::UnknownDiscarded,
            )?;
            return Err(quarantined_db_error(
                QuarantineOutcome::UnknownDiscarded,
                format!(
                    "rollback preview cleanup failed after {rows_affected} affected row(s): {e}"
                ),
            )
            .into_envelope());
        }
    }

    // Durably log the successful (committed or rolled-back-preview) outcome.
    let outcome = if args.commit {
        AuditOutcome::Succeeded
    } else {
        AuditOutcome::RolledBack
    };
    append_audit(
        audit_entry,
        audit_tool,
        &executed_sql,
        &danger_str,
        Some(rows_affected),
        outcome,
    )?;
    if args.commit {
        resolve_write_intent_after_db(
            &ctx,
            write_intent_id.as_deref(),
            WriteIntentOutcome::Succeeded,
            "commit completed",
        )?;
    }
    let dbms_output = match dbms_output_limits {
        Some((max_lines, max_chars)) => Some(
            read_dbms_output_conn(cx, conn, max_lines, max_chars)
                .await
                .map_err(DbError::into_envelope)
                .map(|out| dbms_output_json(&out, max_lines, max_chars))?,
        ),
        None => None,
    };

    let mut response = json!({
        "executed": true,
        "committed": args.commit,
        "rolled_back": !args.commit,
        "rows_affected": rows_affected,
        "required_level": required_level,
        "danger": decision.danger,
        "objects_affected": decision.objects_affected,
        "reason": decision.reason,
    });
    if let Some(dbms_output) = dbms_output {
        response["dbms_output"] = dbms_output;
    }
    Ok(response)
}

fn normalize_compile_type_for_wire(object_type: &str) -> String {
    object_type.trim().replace('_', " ").to_ascii_uppercase()
}

fn gate_decision_json(gate: &LevelDecision) -> (&'static str, Value, Value) {
    match gate {
        LevelDecision::Allow => ("allow", Value::Null, Value::Null),
        LevelDecision::RequireStepUp { target } => ("require_step_up", Value::Null, json!(target)),
        LevelDecision::Blocked { reason } => {
            let reason = match reason {
                oraclemcp_guard::BlockReason::Forbidden => json!({ "type": "forbidden" }),
                oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling } => {
                    json!({
                        "type": "exceeds_ceiling",
                        "required": required,
                        "ceiling": ceiling,
                    })
                }
                _ => json!({ "type": "unknown" }),
            };
            ("blocked", reason, Value::Null)
        }
        _ => ("unknown", Value::Null, Value::Null),
    }
}

fn compile_gate_error(gate: LevelDecision, session: &SessionLevelState) -> ErrorEnvelope {
    gate_error(
        gate,
        session,
        &GateErrorLabels {
            subject: "compile",
            step_up_tool: "oracle_compile_object",
            step_up_inspect_step: "call oracle_compile_object without execute=true to inspect the required level and confirmation grant",
            step_up_elevation_step: "call oracle_set_session_level with level=\"DDL\" to preview a temporary elevation, or keep the profile read-only",
            ceiling_step: "choose a profile whose max_level permits DDL",
            policy_denied_message: "compile is blocked by policy",
            internal_message: "compile gate produced an unexpected decision",
        },
        None,
    )
}

fn classify_compile_statements(statements: &[String]) -> Result<DangerLevel, ErrorEnvelope> {
    let mut danger = DangerLevel::Safe;
    for statement in statements {
        let decision = DEFAULT_CLASSIFIER.classify(statement);
        let Some(required_level) = decision.required_level else {
            return Err(ErrorEnvelope::new(
                ErrorClass::ForbiddenStatement,
                format!(
                    "generated compile statement is forbidden by the SQL classifier: {}",
                    decision.reason
                ),
            ));
        };
        if required_level > OperatingLevel::Ddl {
            return Err(ErrorEnvelope::new(
                ErrorClass::ForbiddenStatement,
                format!(
                    "generated compile statement unexpectedly requires {}; refusing",
                    required_level.as_str()
                ),
            ));
        }
        danger = danger.max(decision.danger);
    }
    Ok(danger)
}

fn compile_next_actions(
    gate: &LevelDecision,
    owner: &str,
    name: &str,
    object_type: &str,
    plscope: bool,
    warnings: bool,
    confirm: Option<&str>,
) -> Value {
    let mut actions = Vec::new();
    match gate {
        LevelDecision::Allow => {
            if let Some(confirm) = confirm {
                actions.push(json!({
                    "intent": "compile",
                    "tool": "oracle_compile_object",
                    "args": {
                        "owner": owner,
                        "name": name,
                        "object_type": object_type,
                        "plscope": plscope,
                        "warnings": warnings,
                        "execute": true,
                        "confirm": confirm,
                    },
                }));
            }
        }
        LevelDecision::RequireStepUp { target } => push_step_up_actions(&mut actions, target),
        LevelDecision::Blocked {
            reason: oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling },
        } => push_exceeds_ceiling_action(&mut actions, required, ceiling),
        LevelDecision::Blocked { .. } => {}
        _ => {}
    }
    Value::Array(actions)
}

fn compile_diagnostic_counts(errors: &[oraclemcp_db::OracleRow]) -> (usize, usize) {
    let error_count = errors
        .iter()
        .filter(|row| {
            row.text("ATTRIBUTE")
                .is_some_and(|attr| attr.eq_ignore_ascii_case("ERROR"))
        })
        .count();
    let warning_count = errors.len().saturating_sub(error_count);
    (error_count, warning_count)
}

async fn compile_object(
    ctx: DbToolCtx<'_>,
    tool_name: &str,
    args: CompileObjectArgs,
) -> Result<Value, ErrorEnvelope> {
    let timeout_seconds = args.timeout_seconds;
    with_call_timeout(
        ctx.cx,
        ctx.conn,
        ctx.request_budget,
        timeout_seconds,
        || compile_object_inner(ctx, tool_name, args),
    )
    .await
}

async fn compile_object_inner(
    ctx: DbToolCtx<'_>,
    tool_name: &str,
    args: CompileObjectArgs,
) -> Result<Value, ErrorEnvelope> {
    let cx = ctx.cx;
    let conn = ctx.conn;
    let active_profile = ctx.active_profile;
    let session = ctx.session;
    let audit = ctx.audit;
    let object_name = required_non_empty_arg(tool_name, "name", args.name)?;
    let (owner, object_name) =
        owner_and_name_arg(cx, conn, args.owner, object_name, "name").await?;
    let object_type = normalize_compile_type_for_wire(&args.object_type);
    let warnings = args.warnings || tool_name == "compile_with_warnings";
    let mut statements =
        compile_object_statements(&object_type, &owner, &object_name, args.plscope)
            .map_err(DbError::into_envelope)?;
    if warnings {
        statements.insert(
            0,
            "ALTER SESSION SET PLSQL_WARNINGS = 'ENABLE:ALL'".to_owned(),
        );
    }
    let compile_danger = classify_compile_statements(&statements)?;
    let gate = session.evaluate(Some(OperatingLevel::Ddl));
    let (gate_decision, blocked_reason, step_up_target) = gate_decision_json(&gate);
    let audited_sql = statements.join(";\n");
    let confirm = matches!(gate, LevelDecision::Allow).then(|| {
        issue_confirmation_grant(
            ctx.execute_grants,
            ctx.grant_binding,
            active_profile,
            &audited_sql,
            OperatingLevel::Ddl,
        )
    });

    let preview = || {
        json!({
            "compiled": false,
            "preview": true,
            "owner": owner,
            "name": object_name,
            "object_type": object_type,
            "plscope": args.plscope,
            "warnings": warnings,
            "required_level": OperatingLevel::Ddl,
            "session_level": session.effective_level(),
            "profile_ceiling": session.effective_ceiling(),
            "gate_decision": gate_decision,
            "blocked_reason": blocked_reason,
            "step_up_target": step_up_target,
            "statements": statements,
            "confirmation": confirmation_block(tool_name, confirm.as_deref(), None),
            "next_actions": compile_next_actions(
                &gate,
                &owner,
                &object_name,
                &object_type,
                args.plscope,
                warnings,
                confirm.as_deref(),
            ),
        })
    };

    if !args.execute {
        return Ok(preview());
    }
    if !matches!(gate, LevelDecision::Allow) {
        return Err(compile_gate_error(gate, session));
    }
    let raw_confirm = consume_confirmation_grant(ConfirmationGrantRequest {
        material: &audited_sql,
        required_level: OperatingLevel::Ddl,
        active_profile,
        grants: ctx.execute_grants,
        binding: ctx.grant_binding,
        confirm: args.confirm.as_deref(),
        challenge_message: "compile requires the single-use confirmation grant from a preview of this exact object/profile/options",
        suggested_tool: "oracle_compile_object",
        next_step: "call oracle_compile_object without execute=true, then pass confirmation.confirm with execute=true",
    })?;

    let danger_str = audit_danger_string(compile_danger);
    let write_intent_id = append_write_intent(
        &ctx,
        tool_name,
        &audited_sql,
        OperatingLevel::Ddl,
        &raw_confirm,
    )?;
    let db_evidence = collect_audit_db_evidence(cx, audit.auditor, conn).await;
    let audit_entry = AuditEntryCtx {
        auditor: audit.auditor,
        subject: audit.subject,
        db_evidence: db_evidence.as_ref(),
    };
    if let Err(err) = append_audit(
        audit_entry,
        tool_name,
        &audited_sql,
        &danger_str,
        None,
        AuditOutcome::Pending,
    ) {
        resolve_write_intent(
            &ctx,
            write_intent_id.as_deref(),
            WriteIntentOutcome::AbortedBeforeExecute,
        )?;
        return Err(err);
    }
    let mut rows_affected = Vec::with_capacity(statements.len());
    for stmt in &statements {
        match execute_conn(cx, conn, stmt, &[]).await {
            Ok(rows) => rows_affected.push(rows),
            Err(e) => {
                let outcome = if e.is_uncertain_session_state() {
                    mark_connection_quarantined(
                        ctx.quarantine,
                        AuditOutcome::UnknownDiscarded,
                        format!("compile execution failed after an uncertain DB boundary: {e}"),
                    )?;
                    AuditOutcome::UnknownDiscarded
                } else {
                    AuditOutcome::Failed
                };
                append_audit(
                    audit_entry,
                    tool_name,
                    &audited_sql,
                    &danger_str,
                    None,
                    outcome,
                )?;
                if outcome == AuditOutcome::Failed {
                    resolve_write_intent_after_db(
                        &ctx,
                        write_intent_id.as_deref(),
                        WriteIntentOutcome::Failed,
                        "compile execution failed before a commit boundary",
                    )?;
                }
                return Err(DbError::into_envelope(e));
            }
        }
    }
    let rows_affected_total = rows_affected.iter().copied().sum::<u64>();
    append_audit(
        audit_entry,
        tool_name,
        &audited_sql,
        &danger_str,
        Some(rows_affected_total),
        AuditOutcome::Succeeded,
    )?;
    resolve_write_intent_after_db(
        &ctx,
        write_intent_id.as_deref(),
        WriteIntentOutcome::Succeeded,
        "compile execution completed",
    )?;
    dispatch_checkpoint(cx, "oraclemcp.dispatch.compile_errors.before")?;
    let errors = compile_errors(cx, conn, &owner, Some(&object_name))
        .await
        .map_err(DbError::into_envelope)?;
    dispatch_checkpoint(cx, "oraclemcp.dispatch.compile_errors.after")?;
    let (error_count, warning_count) = compile_diagnostic_counts(&errors);
    Ok(json!({
        "compiled": true,
        "preview": false,
        "owner": owner,
        "name": object_name,
        "object_type": object_type,
        "plscope": args.plscope,
        "warnings": warnings,
        "required_level": OperatingLevel::Ddl,
        "statements_executed": statements,
        "rows_affected": rows_affected,
        "errors": rows_to_json(&errors),
        "diagnostic_count": errors.len(),
        "error_count": error_count,
        "warning_count": warning_count,
    }))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceObjectHint {
    owner: String,
    name: String,
    object_type: String,
}

fn is_simple_source_name(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    let second = parts.next();
    if parts.next().is_some() {
        return false;
    }
    let valid_part = |part: &str| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '#'))
    };
    valid_part(first) && second.is_none_or(valid_part)
}

fn clean_source_name_token(raw: &str) -> Option<String> {
    let token = raw
        .split('(')
        .next()
        .unwrap_or(raw)
        .trim()
        .trim_end_matches(';')
        .trim_matches('"');
    if is_simple_source_name(token) {
        Some(token.to_owned())
    } else {
        None
    }
}

async fn detect_create_or_replace_object(
    cx: &Cx,
    conn: &dyn OracleConnection,
    source: &str,
) -> Option<SourceObjectHint> {
    let words: Vec<&str> = source.split_whitespace().collect();
    if words.len() < 4
        || !words[0].eq_ignore_ascii_case("CREATE")
        || !words[1].eq_ignore_ascii_case("OR")
        || !words[2].eq_ignore_ascii_case("REPLACE")
    {
        return None;
    }

    let mut idx = 3;
    while matches!(
        words.get(idx).map(|w| w.to_ascii_uppercase()).as_deref(),
        Some("EDITIONABLE" | "NONEDITIONABLE" | "FORCE" | "NOFORCE")
    ) {
        idx += 1;
    }

    let first = words.get(idx)?.to_ascii_uppercase();
    let (object_type, name_idx) = match first.as_str() {
        "PACKAGE"
            if words
                .get(idx + 1)
                .is_some_and(|w| w.eq_ignore_ascii_case("BODY")) =>
        {
            ("PACKAGE BODY".to_owned(), idx + 2)
        }
        "TYPE"
            if words
                .get(idx + 1)
                .is_some_and(|w| w.eq_ignore_ascii_case("BODY")) =>
        {
            ("TYPE BODY".to_owned(), idx + 2)
        }
        "PACKAGE" | "PROCEDURE" | "FUNCTION" | "TRIGGER" | "TYPE" | "VIEW" => (first, idx + 1),
        _ => return None,
    };
    let name = clean_source_name_token(words.get(name_idx)?)?;
    let (owner, name) = owner_and_name_arg(cx, conn, None, name, "name")
        .await
        .ok()?;
    Some(SourceObjectHint {
        owner,
        name,
        object_type,
    })
}

// Preview-side confirmation block shared by the create-or-replace and patch
// previews; `note` is omitted (compile preview) or carried verbatim.
fn confirmation_block(tool: &str, confirm: Option<&str>, note: Option<&str>) -> Value {
    confirm.map_or(Value::Null, |confirm| {
        let mut block = json!({
            "tool": tool,
            "execute": true,
            "confirm": confirm,
        });
        if let (Value::Object(map), Some(note)) = (&mut block, note) {
            map.insert("note".to_owned(), json!(note));
        }
        block
    })
}

fn source_preview_json(source: &str, max_chars: usize) -> Value {
    let mut preview = String::new();
    let mut truncated = false;
    for (idx, ch) in source.chars().enumerate() {
        if idx >= max_chars {
            truncated = true;
            break;
        }
        preview.push(ch);
    }
    json!({
        "text": preview,
        "truncated": truncated,
        "max_chars": max_chars,
    })
}

fn detected_object_json(hint: Option<&SourceObjectHint>) -> Value {
    hint.map(|hint| {
        json!({
            "owner": hint.owner,
            "name": hint.name,
            "object_type": hint.object_type,
        })
    })
    .unwrap_or(Value::Null)
}

fn dependent_object_json(dep: &DependentObject) -> Value {
    json!({
        "owner": dep.owner,
        "name": dep.name,
        "type": dep.object_type,
    })
}

/// The blast-radius block for a DDL preview: the direct (one-hop) dependents of
/// the target object plus the invalidatable subset. Pure over a
/// [`DependentsProbe`] so it is unit-testable offline. Returns the `(key,
/// value)` pair to splice into the preview object — either the `dependents`
/// block, or a `dependents_unavailable` reason when the dictionary probe
/// degraded. Additive: never touches the classifier, gate, or ladder.
fn dependents_preview_entry(probe: &DependentsProbe) -> (&'static str, Value) {
    match probe {
        DependentsProbe::Available { direct } => {
            let objects: Vec<Value> = direct.iter().map(dependent_object_json).collect();
            let at_risk: Vec<Value> = direct
                .iter()
                .filter(|dep| dep.is_invalidatable())
                .map(dependent_object_json)
                .collect();
            (
                "dependents",
                json!({
                    "count": direct.len(),
                    "objects": objects,
                    "at_risk_of_invalid": at_risk,
                    "note": "direct dependents only (one hop from ALL_DEPENDENCIES); \
                             transitive closure and dynamic-SQL (EXECUTE IMMEDIATE) references \
                             are not shown, and objects outside this session's dictionary \
                             visibility are omitted. at_risk_of_invalid is a best-effort static \
                             estimate of which dependents a replace would mark INVALID.",
                }),
            )
        }
        DependentsProbe::Unavailable { reason } => {
            ("dependents_unavailable", json!({ "reason": reason }))
        }
    }
}

/// Splice the dependents blast-radius block into a preview object in place.
/// No-op if `preview` is not a JSON object (previews always are).
fn merge_dependents_preview(preview: &mut Value, probe: &DependentsProbe) {
    if let Value::Object(map) = preview {
        let (key, value) = dependents_preview_entry(probe);
        map.insert(key.to_owned(), value);
    }
}

fn create_or_replace_next_actions(
    gate: &LevelDecision,
    source: &str,
    required_level: Option<OperatingLevel>,
    confirm: Option<&str>,
) -> Value {
    let mut actions = Vec::new();
    match gate {
        LevelDecision::Allow => {
            if let Some(confirm) = confirm {
                actions.push(json!({
                    "intent": "apply_create_or_replace",
                    "tool": "oracle_create_or_replace",
                    "args": {
                        "source_code": source,
                        "execute": true,
                        "confirm": confirm,
                    },
                }));
            }
        }
        LevelDecision::RequireStepUp { target } => push_step_up_actions(&mut actions, target),
        LevelDecision::Blocked { reason } => match reason {
            oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling } => {
                push_exceeds_ceiling_action(&mut actions, required, ceiling);
            }
            oraclemcp_guard::BlockReason::Forbidden => {
                actions.push(json!({
                    "intent": "rewrite_source",
                    "message": "submit one plain CREATE OR REPLACE statement without dynamic SQL or extra statements",
                }));
            }
            _ => {}
        },
        _ => {}
    }
    if matches!(gate, LevelDecision::Allow)
        && required_level.is_some_and(|l| l < OperatingLevel::Ddl)
    {
        actions.push(json!({
            "intent": "use_general_execute",
            "tool": "oracle_preview_sql",
            "args": { "sql": source },
        }));
    }
    Value::Array(actions)
}

fn create_or_replace_source_arg(
    tool_name: &str,
    value: Option<String>,
) -> Result<String, ErrorEnvelope> {
    let source = required_non_empty_arg(tool_name, "source_code", value)?;
    let normalized = source.trim_start();
    let upper = normalized.to_ascii_uppercase();
    if !upper.starts_with("CREATE OR REPLACE ") {
        return Err(invalid_args(format!(
            "invalid arguments for {tool_name}: source_code must start with CREATE OR REPLACE"
        ))
        .with_next_step("pass one full CREATE OR REPLACE statement, or use oracle_preview_sql/oracle_execute for other SQL"));
    }
    Ok(source)
}

#[derive(Clone, Debug)]
struct PatchSourceDocument {
    text: String,
    source_kind: &'static str,
    line_count: Option<usize>,
    char_count: usize,
}

fn normalize_patch_object_type(
    tool_name: &str,
    value: Option<String>,
) -> Result<String, ErrorEnvelope> {
    let value = non_empty_arg(value).or_else(|| match tool_name {
        "patch_package" => Some("PACKAGE BODY".to_owned()),
        "patch_view" => Some("VIEW".to_owned()),
        _ => None,
    });
    let Some(value) = value else {
        return Err(invalid_args(format!(
            "invalid arguments for {tool_name}: missing required `object_type`"
        ))
        .with_next_step(
            "use PACKAGE, PACKAGE_BODY, PROCEDURE, FUNCTION, TRIGGER, TYPE, TYPE_BODY, or VIEW",
        ));
    };
    let normalized = value.trim().to_ascii_uppercase().replace('_', " ");
    match normalized.as_str() {
        "PACKAGE" | "PROCEDURE" | "FUNCTION" | "TRIGGER" | "TYPE" | "VIEW" => Ok(normalized),
        "PACKAGE BODY" | "TYPE BODY" => Ok(normalized),
        _ => Err(invalid_args(format!(
            "invalid arguments for {tool_name}: unsupported object_type {value:?}"
        ))
        .with_next_step(
            "use PACKAGE, PACKAGE_BODY, PROCEDURE, FUNCTION, TRIGGER, TYPE, TYPE_BODY, or VIEW",
        )),
    }
}

fn required_patch_old_text(
    tool_name: &str,
    value: Option<String>,
) -> Result<String, ErrorEnvelope> {
    match value {
        Some(value) if !value.is_empty() => Ok(value),
        _ => Err(invalid_args(format!(
            "invalid arguments for {tool_name}: missing required non-empty `old_text`"
        ))),
    }
}

fn required_patch_new_text(
    tool_name: &str,
    value: Option<String>,
) -> Result<String, ErrorEnvelope> {
    value.ok_or_else(|| {
        invalid_args(format!(
            "invalid arguments for {tool_name}: missing required `new_text`"
        ))
    })
}

async fn fetch_patch_source_document(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
    object_type: &str,
    max_chars: usize,
) -> Result<PatchSourceDocument, ErrorEnvelope> {
    if object_type == "VIEW" {
        dispatch_checkpoint(cx, "oraclemcp.dispatch.patch.get_ddl.before")?;
        let ddl = get_ddl(cx, conn, "VIEW", owner, name)
            .await
            .map_err(DbError::into_envelope)?
            .ok_or_else(|| {
                ErrorEnvelope::new(
                    ErrorClass::ObjectNotFound,
                    format!("VIEW {owner}.{name} is not visible to this session"),
                )
                .with_suggested_tool("oracle_get_ddl")
            })?;
        dispatch_checkpoint(cx, "oraclemcp.dispatch.patch.get_ddl.after")?;
        return Ok(PatchSourceDocument {
            char_count: ddl.chars().count(),
            text: ddl,
            source_kind: "dbms_metadata",
            line_count: None,
        });
    }

    dispatch_checkpoint(cx, "oraclemcp.dispatch.patch.get_source.before")?;
    let source = get_source(cx, conn, owner, name, object_type, max_chars)
        .await
        .map_err(DbError::into_envelope)?;
    dispatch_checkpoint(cx, "oraclemcp.dispatch.patch.get_source.after")?;
    if source.line_count == 0 {
        return Err(ErrorEnvelope::new(
            ErrorClass::ObjectNotFound,
            format!("{object_type} {owner}.{name} source is not visible to this session"),
        )
        .with_suggested_tool("oracle_get_source"));
    }
    if source.truncated {
        return Err(invalid_args(format!(
            "source for {owner}.{name} was truncated at {max_chars} characters; refusing to patch partial source"
        ))
        .with_suggested_tool("oracle_get_source")
        .with_next_step("raise max_chars and preview the patch again"));
    }
    Ok(PatchSourceDocument {
        text: source.source,
        source_kind: "all_source",
        line_count: Some(source.line_count),
        char_count: source.char_count,
    })
}

fn find_unique_patch_match(
    source: &str,
    old_text: &str,
    tool_name: &str,
) -> Result<usize, ErrorEnvelope> {
    let mut matches = source.match_indices(old_text);
    let Some((first_idx, _)) = matches.next() else {
        return Err(ErrorEnvelope::new(
            ErrorClass::ObjectNotFound,
            "old_text was not found exactly in the current source",
        )
        .with_suggested_tool("oracle_get_source")
        .with_next_step("fetch the current source and pass an exact old_text slice"));
    };
    if matches.next().is_some() {
        return Err(invalid_args(format!(
            "invalid arguments for {tool_name}: old_text matches more than once; include more surrounding context"
        ))
        .with_suggested_tool("oracle_get_source"));
    }
    Ok(first_idx)
}

fn create_or_replace_ddl_from_source(source: &str) -> String {
    if source
        .trim_start()
        .to_ascii_uppercase()
        .starts_with("CREATE OR REPLACE ")
    {
        source.to_owned()
    } else {
        format!("CREATE OR REPLACE {source}")
    }
}

fn line_number_at(source: &str, byte_idx: usize) -> usize {
    source[..byte_idx].bytes().filter(|b| *b == b'\n').count() + 1
}

fn logical_line_count(value: &str) -> usize {
    if value.is_empty() {
        0
    } else {
        value.lines().count().max(1)
    }
}

fn patch_diff_json(source: &str, match_idx: usize, old_text: &str, new_text: &str) -> Value {
    json!({
        "format": "exact-replacement",
        "start_line": line_number_at(source, match_idx),
        "old_line_count": logical_line_count(old_text),
        "new_line_count": logical_line_count(new_text),
        "old_preview": source_preview_json(old_text, DEFAULT_PATCH_PREVIEW_CHARS),
        "new_preview": source_preview_json(new_text, DEFAULT_PATCH_PREVIEW_CHARS),
    })
}

fn patch_next_actions(
    tool_name: &str,
    gate: &LevelDecision,
    identity: (&str, &str, &str),
    patch: (&str, &str),
    max_chars: usize,
    confirm: Option<&str>,
) -> Value {
    let (owner, name, object_type) = identity;
    let (old_text, new_text) = patch;
    let mut actions = Vec::new();
    match gate {
        LevelDecision::Allow => {
            if let Some(confirm) = confirm {
                actions.push(json!({
                    "intent": "apply_source_patch",
                    "tool": tool_name,
                    "args": {
                        "owner": owner,
                        "name": name,
                        "object_type": object_type,
                        "old_text": old_text,
                        "new_text": new_text,
                        "max_chars": max_chars,
                        "execute": true,
                        "confirm": confirm,
                    },
                }));
            }
        }
        LevelDecision::RequireStepUp { target } => push_step_up_actions(&mut actions, target),
        LevelDecision::Blocked { reason } => match reason {
            oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling } => {
                push_exceeds_ceiling_action(&mut actions, required, ceiling);
            }
            oraclemcp_guard::BlockReason::Forbidden => {
                actions.push(json!({
                    "intent": "adjust_patch",
                    "message": "patch result must be one plain CREATE OR REPLACE statement without dynamic SQL or extra statements",
                }));
            }
            _ => {}
        },
        _ => {}
    }
    Value::Array(actions)
}

fn is_patch_body_object_type(object_type: &str) -> bool {
    matches!(object_type, "PACKAGE BODY" | "TYPE BODY")
}

fn contains_patch_side_effect_marker(source: &str) -> bool {
    // Reuse the guard's comment-stripping, token-aware Stage-A scan instead of a
    // hand-rolled substring match: a comment wedged between the two keywords of a
    // multi-word marker (`EXECUTE/**/IMMEDIATE`) defeats a plain `.contains`, but
    // not the canonicalized scan. Avoids drifting from the guard's marker set.
    matches!(
        stage_a(source, &ClassifierConfig::new()),
        StageA::PlSqlBlock {
            dangerous: true,
            ..
        } | StageA::BlockListed(_)
    )
}

fn patch_preview_key(active_profile: Option<&str>, owner: &str, name: &str) -> String {
    format!(
        "{}\0{}\0{}",
        active_profile.unwrap_or(""),
        owner.to_ascii_uppercase(),
        name.to_ascii_uppercase()
    )
}

fn remember_patch_preview(state: &mut DispatcherState, entry: PatchPreviewEntry) {
    if state.patch_previews.len() >= MAX_PATCH_PREVIEWS
        && let Some(oldest_key) = state
            .patch_previews
            .iter()
            .min_by_key(|(_, entry)| entry.created_at)
            .map(|(key, _)| key.clone())
    {
        state.patch_previews.remove(&oldest_key);
    }
    let key = patch_preview_key(entry.active_profile.as_deref(), &entry.owner, &entry.name);
    state.patch_previews.insert(key, entry);
}

fn read_patch_preview(
    state: &DispatcherState,
    tool_name: &str,
    args: ReadPatchPreviewArgs,
) -> Result<Value, ErrorEnvelope> {
    let max_chars = args.max_chars.unwrap_or(100_000).clamp(1, 10_000_000);
    let active_profile = state.active_profile.as_deref();
    if let Some(name) = non_empty_arg(args.name) {
        let (_owner, name) = split_qualified_name(&name, "name")?;
        let wanted_name = name.to_ascii_uppercase();
        let mut matches = state
            .patch_previews
            .values()
            .filter(|entry| {
                entry.active_profile.as_deref() == active_profile && entry.name == wanted_name
            })
            .cloned()
            .collect::<Vec<_>>();
        matches.sort_by_key(|entry| entry.created_at);
        let Some(entry) = matches.pop() else {
            return Err(ErrorEnvelope::new(
                ErrorClass::ObjectNotFound,
                "no source patch preview is remembered for that object in the active profile",
            )
            .with_suggested_tool("oracle_patch_source")
            .with_next_step(
                "rerun oracle_patch_source, patch_package, or patch_view without execute=true",
            ));
        };
        return Ok(json!({
            "preview_available": true,
            "compatibility_tool": tool_name,
            "source": "in_memory_patch_preview",
            "active_profile": active_profile,
            "owner": entry.owner,
            "name": entry.name,
            "object_type": entry.object_type,
            "patch_tool": entry.tool_name,
            "ddl_char_count": entry.patched_ddl.chars().count(),
            "ddl_preview": source_preview_json(&entry.patched_ddl, max_chars),
            "next_actions": [
                {
                    "intent": "apply_source_patch",
                    "tool": entry.tool_name,
                    "message": "rerun the same patch tool with execute=true and the confirmation grant from its preview"
                }
            ],
        }));
    }

    let mut entries = state
        .patch_previews
        .values()
        .filter(|entry| entry.active_profile.as_deref() == active_profile)
        .map(|entry| {
            json!({
                "owner": entry.owner,
                "name": entry.name,
                "object_type": entry.object_type,
                "patch_tool": entry.tool_name,
                "ddl_char_count": entry.patched_ddl.chars().count(),
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| {
        a["name"]
            .as_str()
            .unwrap_or_default()
            .cmp(b["name"].as_str().unwrap_or_default())
    });
    Ok(json!({
        "preview_available": !entries.is_empty(),
        "compatibility_tool": tool_name,
        "source": "in_memory_patch_preview",
        "active_profile": active_profile,
        "preview_count": entries.len(),
        "previews": entries,
        "next_actions": if entries.is_empty() {
            json!([
                {
                    "intent": "create_source_patch_preview",
                    "tool": "oracle_patch_source",
                    "message": "run oracle_patch_source, patch_package, or patch_view without execute=true"
                }
            ])
        } else {
            json!([
                {
                    "intent": "read_one_preview",
                    "tool": "read_patch_preview",
                    "args": { "name": "<object_name>" }
                }
            ])
        },
    }))
}

async fn patch_source(
    ctx: DbToolCtx<'_>,
    tool_name: &str,
    args: PatchSourceArgs,
) -> Result<(Value, Option<PatchPreviewEntry>), ErrorEnvelope> {
    let timeout_seconds = args.timeout_seconds;
    with_call_timeout(
        ctx.cx,
        ctx.conn,
        ctx.request_budget,
        timeout_seconds,
        || patch_source_inner(ctx, tool_name, args),
    )
    .await
}

async fn patch_source_inner(
    ctx: DbToolCtx<'_>,
    tool_name: &str,
    args: PatchSourceArgs,
) -> Result<(Value, Option<PatchPreviewEntry>), ErrorEnvelope> {
    let cx = ctx.cx;
    let conn = ctx.conn;
    let active_profile = ctx.active_profile;
    let session = ctx.session;
    let audit = ctx.audit;
    let object_name = required_non_empty_arg(tool_name, "name", args.name)?;
    let object_type = normalize_patch_object_type(tool_name, args.object_type)?;
    let old_text = required_patch_old_text(tool_name, args.old_text)?;
    let new_text = required_patch_new_text(tool_name, args.new_text)?;
    let max_chars = args.max_chars.unwrap_or(DEFAULT_SOURCE_MAX_CHARS).max(1);
    let (owner, object_name) =
        owner_and_name_arg(cx, conn, args.owner, object_name, "name").await?;
    let document =
        fetch_patch_source_document(cx, conn, &owner, &object_name, &object_type, max_chars)
            .await?;
    let match_idx = find_unique_patch_match(&document.text, &old_text, tool_name)?;
    let mut patched_source = document.text.clone();
    patched_source.replace_range(match_idx..match_idx + old_text.len(), &new_text);
    let patched_ddl = if object_type == "VIEW" {
        patched_source.clone()
    } else {
        create_or_replace_ddl_from_source(&patched_source)
    };
    let patched_ddl = create_or_replace_source_arg(tool_name, Some(patched_ddl))?;
    let decision = DEFAULT_CLASSIFIER.classify(&patched_ddl);
    let classifier_gate = decision.gate(session);
    let classifier_forbidden = matches!(
        &classifier_gate,
        LevelDecision::Blocked {
            reason: oraclemcp_guard::BlockReason::Forbidden
        }
    );
    let body_balance_override = classifier_forbidden
        && is_patch_body_object_type(&object_type)
        && !contains_patch_side_effect_marker(&patched_ddl);
    let patch_required_level = if decision.required_level.is_some() || body_balance_override {
        Some(OperatingLevel::Ddl)
    } else {
        None
    };
    let patch_guard_note = body_balance_override.then_some(
        "generic classifier could not balance a stored package/type body; patch path enforced DDL gate and side-effect marker scan",
    );
    let gate = if classifier_forbidden && !body_balance_override {
        classifier_gate
    } else {
        session.evaluate(patch_required_level)
    };
    let (gate_decision, blocked_reason, step_up_target) = gate_decision_json(&gate);
    let confirm = match (patch_required_level, &gate) {
        (Some(level), LevelDecision::Allow) => Some(issue_confirmation_grant(
            ctx.execute_grants,
            ctx.grant_binding,
            active_profile,
            &patched_ddl,
            level,
        )),
        _ => None,
    };

    if !args.execute {
        let preview_entry = confirm.as_ref().map(|_| PatchPreviewEntry {
            active_profile: active_profile.map(str::to_owned),
            owner: owner.clone(),
            name: object_name.clone(),
            object_type: object_type.clone(),
            patched_ddl: patched_ddl.clone(),
            tool_name: tool_name.to_owned(),
            created_at: Instant::now(),
        });
        let mut preview = json!({
            "applied": false,
            "preview": true,
            "owner": owner,
            "name": object_name,
            "object_type": object_type,
            "source_kind": document.source_kind,
            "line_count": document.line_count,
            "char_count": document.char_count,
            "match_count": 1,
            "diff": patch_diff_json(&document.text, match_idx, &old_text, &new_text),
            "patched_source_preview": source_preview_json(&patched_source, DEFAULT_PATCH_PREVIEW_CHARS),
            "patched_ddl_preview": source_preview_json(&patched_ddl, DEFAULT_PATCH_PREVIEW_CHARS),
            "danger": decision.danger,
            "required_level": patch_required_level,
            "session_level": session.effective_level(),
            "profile_ceiling": session.effective_ceiling(),
            "gate_decision": gate_decision,
            "blocked_reason": blocked_reason,
            "step_up_target": step_up_target,
            "reason": decision.reason,
            "patch_guard_note": patch_guard_note,
            "confirmation": confirmation_block(
                tool_name,
                confirm.as_deref(),
                Some("Pass confirm only when you intend to apply this exact source patch on this active profile."),
            ),
            "next_actions": patch_next_actions(
                tool_name,
                &gate,
                (&owner, &object_name, &object_type),
                (&old_text, &new_text),
                max_chars,
                confirm.as_deref(),
            ),
        });
        // Additive blast-radius enrichment: a read-only ALL_DEPENDENCIES probe of
        // the object being patched. Observational only — never affects the gate,
        // classifier, or ladder. Degrades in place if the probe cannot run.
        let probe = probe_dependents(
            cx,
            conn,
            &owner,
            &object_name,
            DEFAULT_DEPENDENTS_PREVIEW_MAX,
        )
        .await;
        merge_dependents_preview(&mut preview, &probe);
        return Ok((preview, preview_entry));
    }

    if !matches!(gate, LevelDecision::Allow) {
        return Err(execute_gate_error(&decision, gate, session));
    }
    let required_level = patch_required_level.ok_or_else(|| {
        ErrorEnvelope::new(
            ErrorClass::Internal,
            "patch confirmation was verified without a required operating level",
        )
    })?;
    let raw_confirm = consume_confirmation_grant(ConfirmationGrantRequest {
        material: &patched_ddl,
        required_level,
        active_profile,
        grants: ctx.execute_grants,
        binding: ctx.grant_binding,
        confirm: args.confirm.as_deref(),
        challenge_message: "source patch requires the single-use confirmation grant from a preview of this exact object/profile/patch",
        suggested_tool: tool_name,
        next_step: "call the patch tool without execute=true, then pass confirmation.confirm with execute=true",
    })?;

    let danger_str = audit_danger_string(decision.danger);
    let write_intent_id =
        append_write_intent(&ctx, tool_name, &patched_ddl, required_level, &raw_confirm)?;
    let db_evidence = collect_audit_db_evidence(cx, audit.auditor, conn).await;
    let audit_entry = AuditEntryCtx {
        auditor: audit.auditor,
        subject: audit.subject,
        db_evidence: db_evidence.as_ref(),
    };
    if let Err(err) = append_audit(
        audit_entry,
        tool_name,
        &patched_ddl,
        &danger_str,
        None,
        AuditOutcome::Pending,
    ) {
        resolve_write_intent(
            &ctx,
            write_intent_id.as_deref(),
            WriteIntentOutcome::AbortedBeforeExecute,
        )?;
        return Err(err);
    }
    let rows_affected = match execute_conn(cx, conn, &patched_ddl, &[]).await {
        Ok(rows) => rows,
        Err(e) => {
            let rollback = conn.rollback(cx).await;
            let outcome = if rollback.is_ok() {
                AuditOutcome::RolledBack
            } else {
                mark_connection_quarantined(
                    ctx.quarantine,
                    AuditOutcome::UnknownDiscarded,
                    format!("patch execution failed and rollback cleanup failed: {e}"),
                )?;
                AuditOutcome::UnknownDiscarded
            };
            append_audit(
                audit_entry,
                tool_name,
                &patched_ddl,
                &danger_str,
                None,
                outcome,
            )?;
            if outcome == AuditOutcome::RolledBack {
                resolve_write_intent_after_db(
                    &ctx,
                    write_intent_id.as_deref(),
                    WriteIntentOutcome::RolledBack,
                    "patch execution failed and rollback completed",
                )?;
            }
            if let Err(cleanup_err) = rollback {
                return Err(quarantined_db_error(
                    QuarantineOutcome::UnknownDiscarded,
                    format!("patch execution failed and rollback cleanup failed: {cleanup_err}"),
                )
                .into_envelope());
            }
            return Err(DbError::into_envelope(e));
        }
    };
    if let Err(e) = commit_conn(cx, conn).await {
        mark_connection_quarantined(
            ctx.quarantine,
            AuditOutcome::CommitInDoubt,
            format!("patch commit failed after {rows_affected} affected row(s): {e}"),
        )?;
        append_audit(
            audit_entry,
            tool_name,
            &patched_ddl,
            &danger_str,
            Some(rows_affected),
            AuditOutcome::CommitInDoubt,
        )?;
        return Err(quarantined_db_error(
            QuarantineOutcome::CommitInDoubt,
            format!("patch commit failed after {rows_affected} affected row(s): {e}"),
        )
        .into_envelope());
    }
    append_audit(
        audit_entry,
        tool_name,
        &patched_ddl,
        &danger_str,
        Some(rows_affected),
        AuditOutcome::Succeeded,
    )?;
    resolve_write_intent_after_db(
        &ctx,
        write_intent_id.as_deref(),
        WriteIntentOutcome::Succeeded,
        "patch commit completed",
    )?;
    let include_errors = args.include_errors.unwrap_or(true);
    let errors = if include_errors {
        dispatch_checkpoint(cx, "oraclemcp.dispatch.patch.compile_errors.before")?;
        Some(
            compile_errors(cx, conn, &owner, Some(&object_name))
                .await
                .map_err(DbError::into_envelope)?,
        )
    } else {
        None
    };
    if include_errors {
        dispatch_checkpoint(cx, "oraclemcp.dispatch.patch.compile_errors.after")?;
    }
    Ok((
        json!({
            "applied": true,
            "preview": false,
            "executed": true,
            "committed": true,
            "rows_affected": rows_affected,
            "patch_tool": tool_name,
            "owner": owner,
            "name": object_name,
            "object_type": object_type,
            "source_kind": document.source_kind,
            "required_level": OperatingLevel::Ddl,
            "danger": decision.danger,
            "objects_affected": decision.objects_affected,
            "reason": decision.reason,
            "patch_guard_note": patch_guard_note,
            "diff": patch_diff_json(&document.text, match_idx, &old_text, &new_text),
            "errors": errors.as_ref().map(|rows| rows_to_json(rows)),
            "error_count": errors.as_ref().map(Vec::len),
        }),
        None,
    ))
}

// Audit context (auditor + subject) is threaded through the DDL path so
// every CREATE OR REPLACE is hash-chained (A8). TODO(simplify): bundle the audit
// context into an `AuditCtx` to drop back under the arg-count lint.
async fn create_or_replace(
    ctx: DbToolCtx<'_>,
    tool_name: &str,
    args: CreateOrReplaceArgs,
) -> Result<Value, ErrorEnvelope> {
    let timeout_seconds = args.timeout_seconds;
    with_call_timeout(
        ctx.cx,
        ctx.conn,
        ctx.request_budget,
        timeout_seconds,
        || create_or_replace_inner(ctx, tool_name, args),
    )
    .await
}

async fn create_or_replace_inner(
    ctx: DbToolCtx<'_>,
    tool_name: &str,
    args: CreateOrReplaceArgs,
) -> Result<Value, ErrorEnvelope> {
    let cx = ctx.cx;
    let conn = ctx.conn;
    let active_profile = ctx.active_profile;
    let session = ctx.session;
    let source = create_or_replace_source_arg(tool_name, args.source_code)?;
    let decision = DEFAULT_CLASSIFIER.classify(&source);
    let gate = decision.gate(session);
    let (gate_decision, blocked_reason, step_up_target) = gate_decision_json(&gate);
    let detected = detect_create_or_replace_object(cx, conn, &source).await;
    let confirm = match (args.execute, decision.required_level, &gate) {
        (false, Some(level), LevelDecision::Allow) if level >= OperatingLevel::Ddl => {
            let raw = ctx.execute_grants.issue(
                &source,
                ctx.grant_binding.clone(),
                level,
                Duration::from_secs(EXECUTE_APPROVED_TOKEN_TTL_SECONDS),
            );
            Some(sign_execute_grant_reference(
                &raw,
                ctx.grant_binding,
                active_profile,
                level,
            ))
        }
        _ => None,
    };

    if !args.execute {
        let mut preview = json!({
            "applied": false,
            "preview": true,
            "source_preview": source_preview_json(&source, 500),
            "detected_object": detected_object_json(detected.as_ref()),
            "danger": decision.danger,
            "required_level": decision.required_level,
            "session_level": session.effective_level(),
            "profile_ceiling": session.effective_ceiling(),
            "gate_decision": gate_decision,
            "blocked_reason": blocked_reason,
            "step_up_target": step_up_target,
            "reason": decision.reason,
            "confirmation": confirmation_block(
                "oracle_create_or_replace",
                confirm.as_deref(),
                Some("Pass confirm only when you intend to apply this exact CREATE OR REPLACE statement on this active profile."),
            ),
            "next_actions": create_or_replace_next_actions(
                &gate,
                &source,
                decision.required_level,
                confirm.as_deref(),
            ),
        });
        // Additive blast-radius enrichment: a read-only ALL_DEPENDENCIES probe of
        // the detected target. Observational only — it never affects the gate,
        // classifier, or ladder above. Degrades in place if the probe cannot run.
        if let Some(hint) = detected.as_ref() {
            let probe = probe_dependents(
                cx,
                conn,
                &hint.owner,
                &hint.name,
                DEFAULT_DEPENDENTS_PREVIEW_MAX,
            )
            .await;
            merge_dependents_preview(&mut preview, &probe);
        }
        return Ok(preview);
    }

    if !matches!(gate, LevelDecision::Allow) {
        return Err(execute_gate_error(&decision, gate, session));
    }
    let mut executed = execute_sql(
        ctx,
        canonical_tool_name(tool_name),
        ExecuteArgs {
            sql: source.clone(),
            binds: Vec::new(),
            commit: true,
            confirm: args.confirm,
            capture_dbms_output: false,
            dbms_output_max_lines: None,
            dbms_output_max_chars: None,
            timeout_seconds: args.timeout_seconds,
        },
    )
    .await?;
    let include_errors = args.include_errors.unwrap_or(true);
    if let Value::Object(map) = &mut executed {
        map.insert("applied".to_owned(), json!(true));
        map.insert("preview".to_owned(), json!(false));
        map.insert(
            "detected_object".to_owned(),
            detected_object_json(detected.as_ref()),
        );
        if include_errors {
            if let Some(hint) = detected.as_ref() {
                dispatch_checkpoint(
                    cx,
                    "oraclemcp.dispatch.create_or_replace.compile_errors.before",
                )?;
                let errors = compile_errors(cx, conn, &hint.owner, Some(&hint.name))
                    .await
                    .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(
                    cx,
                    "oraclemcp.dispatch.create_or_replace.compile_errors.after",
                )?;
                map.insert("errors".to_owned(), rows_to_json(&errors));
                map.insert("error_count".to_owned(), json!(errors.len()));
            } else {
                map.insert("errors".to_owned(), Value::Null);
                map.insert("error_count".to_owned(), Value::Null);
                map.insert(
                    "error_lookup_note".to_owned(),
                    json!("object name could not be inferred from the source"),
                );
            }
        }
    }
    Ok(executed)
}

async fn deploy_ddl(ctx: DbToolCtx<'_>, args: DeployDdlArgs) -> Result<Value, ErrorEnvelope> {
    let timeout_seconds = args.timeout_seconds;
    with_call_timeout(
        ctx.cx,
        ctx.conn,
        ctx.request_budget,
        timeout_seconds,
        || deploy_ddl_inner(ctx, args),
    )
    .await
}

async fn deploy_ddl_inner(ctx: DbToolCtx<'_>, args: DeployDdlArgs) -> Result<Value, ErrorEnvelope> {
    let active_profile = ctx.active_profile;
    let session = ctx.session;
    let ddl = required_non_empty_arg("deploy_ddl", "ddl", args.ddl)?;
    let deploy_name = non_empty_arg(args.name);
    let wait_seconds = args.wait_seconds.unwrap_or(0);
    if ddl
        .trim_start()
        .to_ascii_uppercase()
        .starts_with("CREATE OR REPLACE ")
    {
        let mut out = create_or_replace(
            ctx,
            "deploy_ddl",
            CreateOrReplaceArgs {
                source_code: Some(ddl),
                execute: args.execute,
                confirm: args.confirm,
                include_errors: args.include_errors,
                timeout_seconds: args.timeout_seconds,
            },
        )
        .await?;
        if let Value::Object(map) = &mut out {
            map.insert("deploy_name".to_owned(), json!(deploy_name));
            map.insert("wait_seconds".to_owned(), json!(wait_seconds));
            map.insert("compatibility_tool".to_owned(), json!("deploy_ddl"));
        }
        return Ok(out);
    }

    let decision = DEFAULT_CLASSIFIER.classify(&ddl);
    let required_level = decision.required_level.ok_or_else(|| {
        ErrorEnvelope::new(
            ErrorClass::ForbiddenStatement,
            format!(
                "statement is forbidden by the SQL classifier: {}",
                decision.reason
            ),
        )
    })?;
    if required_level < OperatingLevel::Ddl {
        return Err(invalid_args(
            "deploy_ddl is for DDL statements; use oracle_preview_sql/oracle_execute for DML",
        )
        .with_suggested_tool("oracle_preview_sql"));
    }

    if !args.execute {
        let mut preview = preview_sql(
            &ddl,
            session,
            active_profile,
            ctx.execute_grants,
            ctx.grant_binding,
        );
        if let Value::Object(map) = &mut preview {
            map.insert("preview".to_owned(), json!(true));
            map.insert("applied".to_owned(), json!(false));
            map.insert("deploy_name".to_owned(), json!(deploy_name));
            map.insert("wait_seconds".to_owned(), json!(wait_seconds));
            map.insert("source_preview".to_owned(), source_preview_json(&ddl, 500));
            map.insert("compatibility_tool".to_owned(), json!("deploy_ddl"));
            if let Some(confirm) = map
                .get("execute_confirmation")
                .and_then(|v| v.get("confirm"))
                .and_then(Value::as_str)
                .map(str::to_owned)
            {
                map.insert(
                    "confirmation".to_owned(),
                    json!({
                        "tool": "deploy_ddl",
                        "execute": true,
                        "confirm": confirm,
                        "note": "Pass confirm only when you intend to apply this exact DDL statement on this active profile."
                    }),
                );
            }
        }
        return Ok(preview);
    }

    let mut out = execute_sql(
        ctx,
        "deploy_ddl",
        ExecuteArgs {
            sql: ddl,
            binds: Vec::new(),
            commit: true,
            confirm: args.confirm,
            capture_dbms_output: false,
            dbms_output_max_lines: None,
            dbms_output_max_chars: None,
            timeout_seconds: args.timeout_seconds,
        },
    )
    .await?;
    if let Value::Object(map) = &mut out {
        map.insert("applied".to_owned(), json!(true));
        map.insert("preview".to_owned(), json!(false));
        map.insert("deploy_name".to_owned(), json!(deploy_name));
        map.insert("wait_seconds".to_owned(), json!(wait_seconds));
        map.insert("compatibility_tool".to_owned(), json!("deploy_ddl"));
    }
    Ok(out)
}

struct ReadOnlyCustomToolExecutor<'a> {
    cx: &'a Cx,
    conn: &'a dyn OracleConnection,
}

#[async_trait::async_trait(?Send)]
impl CustomToolExecutor for ReadOnlyCustomToolExecutor<'_> {
    async fn run(
        &self,
        body: ToolBody<'_>,
        level: OperatingLevel,
        binds: &[(String, OracleBind)],
    ) -> Result<Value, ErrorEnvelope> {
        if level > OperatingLevel::ReadOnly {
            return Err(ErrorEnvelope::new(
                ErrorClass::OperatingLevelTooLow,
                format!(
                    "custom tool requires {} but this server executes only READ_ONLY custom tools",
                    level.as_str()
                ),
            )
            .with_next_step(
                "move write or DDL workflows behind a separate guarded execution service",
            ));
        }

        let sql = match body {
            ToolBody::InlineSql(sql) => sql.to_owned(),
            ToolBody::PackageCall(call) => format!("SELECT {call} AS VALUE FROM dual"),
        };
        ensure_read_only(&sql)?;
        // A9: operator-defined read tools also narrow the handler context to the
        // read-path capability row. The cancellation checkpoint runs under the
        // narrowed `read_cx`; only the locked, object-safe `OracleConnection`
        // round trip takes the full `cx` (the one documented IO exception).
        let read_cx = narrow_to_read_path(self.cx);
        dispatch_checkpoint(&read_cx, "oraclemcp.dispatch.custom_read.before")?;
        read_query_named(
            self.cx,
            self.conn,
            &sql,
            binds,
            QueryCaps::default(),
            0,
            &SerializeOptions::default(),
        )
        .await
        .map(|resp| serde_json::to_value(resp).unwrap_or(Value::Null))
        .map_err(DbError::into_envelope)
    }
}

fn preview_sql(
    sql: &str,
    session: &SessionLevelState,
    active_profile: Option<&str>,
    grants: &ExecGrantStore,
    binding: &ExecGrantBinding,
) -> Value {
    let decision = DEFAULT_CLASSIFIER.classify(sql);
    let gate = decision.gate(session);
    let (gate_decision, blocked_reason, step_up_target) = match gate {
        LevelDecision::Allow => ("allow", Value::Null, Value::Null),
        LevelDecision::RequireStepUp { target } => ("require_step_up", Value::Null, json!(target)),
        LevelDecision::Blocked { reason } => {
            let reason = match reason {
                oraclemcp_guard::BlockReason::Forbidden => {
                    json!({ "type": "forbidden" })
                }
                oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling } => {
                    json!({
                        "type": "exceeds_ceiling",
                        "required": required,
                        "ceiling": ceiling,
                    })
                }
                _ => json!({ "type": "unknown" }),
            };
            ("blocked", reason, Value::Null)
        }
        _ => ("unknown", Value::Null, Value::Null),
    };
    let execute_confirm = match (decision.required_level, &gate) {
        (Some(level), LevelDecision::Allow) if level > OperatingLevel::ReadOnly => {
            grants.purge_expired();
            let raw = grants.issue(
                sql,
                binding.clone(),
                level,
                Duration::from_secs(EXECUTE_APPROVED_TOKEN_TTL_SECONDS),
            );
            Some(sign_execute_grant_reference(
                &raw,
                binding,
                active_profile,
                level,
            ))
        }
        _ => None,
    };

    json!({
        "danger": decision.danger,
        "required_level": decision.required_level,
        "allowed_on_read_only": matches!(
            decision.gate(&SessionLevelState::new(OperatingLevel::ReadOnly, false)),
            LevelDecision::Allow
        ),
        "session_level": session.effective_level(),
        "profile_ceiling": session.effective_ceiling(),
        "protected": session.is_protected(),
        "gate_decision": gate_decision,
        "blocked_reason": blocked_reason,
        "step_up_target": step_up_target,
        "objects_affected": decision.objects_affected,
        "reason": decision.reason,
        "safe_alternative": decision.safe_alternative,
        "execute_confirmation": execute_confirmation_json(
            decision.required_level,
            &gate,
            execute_confirm.as_deref(),
        ),
        "next_actions": preview_next_actions(sql, &decision, &gate, execute_confirm.as_deref()),
    })
}

fn connection_info_json(
    active_profile: Option<String>,
    info: Result<OracleConnectionInfo, DbError>,
) -> Value {
    match info {
        Ok(info) => json!({
            "metadata_cache_key": metadata_cache_key_json(active_profile.as_deref(), &info),
            "active_profile": active_profile,
            "connected": true,
            "connection": info.redacted(),
        }),
        Err(err) => {
            let mut next_actions = vec![json!({
                "intent": "inspect_profiles",
                "tool": "oracle_list_profiles",
                "args": {},
            })];
            let doctor_args = match active_profile.as_deref() {
                Some(profile) => json!(["--json", "doctor", "--online", "--profile", profile]),
                None => json!(["--json", "doctor"]),
            };
            next_actions.push(json!({
                "intent": "run_cli_doctor",
                "command": "oraclemcp",
                "args": doctor_args,
            }));

            json!({
                "active_profile": active_profile,
                "connected": false,
                "connection": Value::Null,
                "connection_error": err
                    .into_envelope()
                    .with_suggested_tool("oracle_list_profiles")
                    .to_json(),
                "next_actions": next_actions,
            })
        }
    }
}

async fn connection_strategy_json(cx: &Cx, conn: &dyn OracleConnection) -> Value {
    match describe_conn(cx, conn).await {
        Ok(info) => json!({
            "connected": true,
            "strategy": info.connection_strategy,
            "pool_open_connections": info.pool_open_connections,
        }),
        Err(err) => json!({
            "connected": false,
            "connection_error": err.into_envelope(),
        }),
    }
}

fn canonical_tool_name(name: &str) -> &str {
    match name {
        "current_database" => "oracle_connection_info",
        "switch_database" => "oracle_switch_profile",
        "enable_writes" | "disable_writes" => "oracle_set_session_level",
        "query" => "oracle_query",
        "list_objects" => "oracle_schema_inspect",
        "list_schemas" => "oracle_list_schemas",
        "get_schema" => "oracle_schema_inspect",
        "compile_object" | "compile_with_warnings" => "oracle_compile_object",
        "create_or_replace" => "oracle_create_or_replace",
        "patch_package" | "patch_view" => "oracle_patch_source",
        "execute_approved" => "execute_approved",
        "deploy_ddl" => "deploy_ddl",
        "describe_table" => "oracle_describe",
        "describe_index" => "oracle_describe_index",
        "describe_trigger" => "oracle_describe_trigger",
        "describe_view" => "oracle_describe_view",
        "get_ddl" => "oracle_get_ddl",
        "get_object_source" => "oracle_get_source",
        "get_errors" => "oracle_compile_errors",
        "get_clob" => "oracle_read_clob",
        "preview_sql" => "oracle_preview_sql",
        other => other,
    }
}

impl ToolDispatch for OracleDispatcher {
    fn dispatch<'a>(
        &'a self,
        cx: &'a Cx,
        context: DispatchContext<'a>,
        name: &'a str,
        args: Value,
    ) -> DispatchFuture<'a> {
        Box::pin(async move {
            if cx.checkpoint().is_err() {
                return Outcome::Cancelled(
                    cx.cancel_reason().unwrap_or_else(CancelReason::timeout),
                );
            }
            let result = self.dispatch_with_cx_inner(cx, context, name, args).await;
            if cx.is_cancel_requested() {
                Outcome::Cancelled(cx.cancel_reason().unwrap_or_else(CancelReason::timeout))
            } else {
                result.into()
            }
        })
    }

    fn dispatch_stream<'a>(
        &'a self,
        cx: &'a Cx,
        context: DispatchContext<'a>,
        name: &'a str,
        args: Value,
        frames: ToolStreamSender,
    ) -> DispatchFuture<'a> {
        Box::pin(async move {
            if cx.checkpoint().is_err() {
                return Outcome::Cancelled(
                    cx.cancel_reason().unwrap_or_else(CancelReason::timeout),
                );
            }
            let result = if canonical_tool_name(name) == "oracle_query" {
                self.dispatch_query_stream_with_cx(cx, context, name, args, frames)
                    .await
            } else {
                self.dispatch_with_cx_inner(cx, context, name, args).await
            };
            if cx.is_cancel_requested() {
                Outcome::Cancelled(cx.cancel_reason().unwrap_or_else(CancelReason::timeout))
            } else {
                result.into()
            }
        })
    }

    fn close<'a>(&'a self, cx: &'a Cx, reason: DispatchCloseReason) -> DispatchCloseFuture<'a> {
        Box::pin(async move { self.close_with_cx(reason, cx).await })
    }

    fn mcp_surface_state<'a>(
        &'a self,
        cx: &'a Cx,
        context: DispatchContext<'a>,
        detail: McpSurfaceDetail,
    ) -> McpSurfaceFuture<'a> {
        Box::pin(async move {
            if cx.checkpoint().is_err() {
                return Outcome::Cancelled(
                    cx.cancel_reason().unwrap_or_else(CancelReason::timeout),
                );
            }
            match self.surface_state_with_cx(cx, context, detail).await {
                Ok(surface) => Outcome::Ok(Some(surface)),
                Err(envelope) => Outcome::Err(envelope),
            }
        })
    }
}

/// `oracle_query` request, parsed and classified ONCE up front (A3/perf).
///
/// The dispatcher previously parsed `QueryArgs` twice and ran the
/// mark+classify pipeline on each of the read-only backstop path and the read
/// handler path — six classifier runs per call, all under the held
/// per-connection lock. This carries the single parse, the single marked
/// `executed_sql` (classified == executed), and the single read-only gate
/// result so both paths reuse them. Behavior is identical to the prior code.
struct QueryPrepared {
    args: QueryArgs,
    /// The audit-marked SQL actually executed (== the text that was classified).
    executed_sql: String,
    /// The read-only gate verdict for `executed_sql`, computed once.
    gate: Result<(), ErrorEnvelope>,
    /// K9: the validated flashback target (if any). It is NOT part of the
    /// classifier input or the executed SQL text — the proven `executed_sql`
    /// runs unchanged inside a `DBMS_FLASHBACK` session window when this is set.
    as_of: Option<AsOf>,
}

struct QueryRowStreamPlan {
    stream: QueryRowStream,
    columns: Vec<String>,
    cursor_sql: String,
    active_profile: Option<String>,
    start_offset: usize,
    serialize_opts: SerializeOptions,
    request_budget: RequestBudget,
}

enum QueryStreamDelivery {
    Rows(Box<QueryRowStreamPlan>),
    Chunked(Value),
}

impl OracleDispatcher {
    fn stream_db_error_envelope(&self, err: DbError) -> ErrorEnvelope {
        let uncertain = err.is_uncertain_session_state();
        let message = err.to_string();
        if uncertain
            && let Err(envelope) = mark_connection_quarantined(
                &self.quarantine,
                AuditOutcome::UnknownDiscarded,
                message,
            )
        {
            return envelope;
        }
        DbError::into_envelope(err)
    }

    /// Synchronous concrete dispatch used by focused dispatcher tests and the
    /// non-Cx convenience callers. Builds a one-shot current-thread Asupersync
    /// runtime to drive the now-async dispatch and obtain a request `Cx`.
    pub fn dispatch(&self, name: &str, args: Value) -> Result<Value, ErrorEnvelope> {
        self.dispatch_blocking(DispatchContext::default(), name, args)
    }

    /// Synchronous concrete dispatch with an explicit Asupersync cancellation
    /// context. DB-backed tool arms classify/gate input before calling Cx-aware
    /// DB methods.
    pub fn dispatch_with_cx(
        &self,
        cx: &Cx,
        name: &str,
        args: Value,
    ) -> Result<Value, ErrorEnvelope> {
        // Drive the async body to completion on a one-shot current-thread
        // runtime, but thread the CALLER's `cx` (clone) through — its
        // cancellation/budget state is the contract the dispatch must honor (a
        // fresh runtime's ambient Cx would lose a pre-cancelled request).
        let caller_cx = cx.clone();
        // block-on-boundary: sync->async dispatch ENTRY shim (not the per-call
        // DB round-trip path). The server's real entry is the async
        // `ToolDispatch::dispatch` which is `.await`-ed on the dispatch runtime;
        // this sync wrapper exists only for non-server/test callers.
        // A reactor is required for the async `oracledb` driver's socket I/O
        // (release-gre.16).
        let reactor = asupersync::runtime::reactor::create_reactor()
            .expect("native reactor for dispatch I/O");
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(reactor)
            .build()
            .expect("current-thread runtime")
            // block-on-boundary: one-shot dispatch ENTRY runtime (release-gre.16).
            .block_on(async move {
                self.dispatch_with_cx_inner(&caller_cx, DispatchContext::default(), name, args)
                    .await
            })
    }

    /// Synchronous concrete dispatch with a transport authorization context.
    pub fn dispatch_with_context(
        &self,
        name: &str,
        args: Value,
        context: DispatchContext<'_>,
    ) -> Result<Value, ErrorEnvelope> {
        self.dispatch_blocking(context, name, args)
    }

    /// Drive the async dispatch to completion on a one-shot current-thread
    /// runtime, supplying the installed request `Cx`.
    fn dispatch_blocking(
        &self,
        context: DispatchContext<'_>,
        name: &str,
        args: Value,
    ) -> Result<Value, ErrorEnvelope> {
        // block-on-boundary: sync->async dispatch ENTRY shim (not the per-call
        // DB round-trip path); see `dispatch_with_cx`.
        // A reactor is required for the async `oracledb` driver's socket I/O
        // (release-gre.16).
        let reactor = asupersync::runtime::reactor::create_reactor()
            .expect("native reactor for dispatch I/O");
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(reactor)
            .build()
            .expect("current-thread runtime")
            // block-on-boundary: one-shot dispatch ENTRY runtime (release-gre.16).
            .block_on(async move {
                let cx = Cx::current().expect("block_on installs a request Cx");
                self.dispatch_with_cx_inner(&cx, context, name, args).await
            })
    }

    async fn close_with_cx(
        &self,
        reason: DispatchCloseReason,
        cx: &Cx,
    ) -> Result<(), ErrorEnvelope> {
        let mut state = self.state.lock(cx).await.map_err(|_| {
            ErrorEnvelope::new(ErrorClass::Internal, "connection mutex lock failed")
        })?;
        let active_profile = state.active_profile.clone();
        let subject = self.default_audit_subject.clone();
        state.level.drop_elevation();
        state.grant_generation = state.grant_generation.saturating_add(1);
        state.execute_grants.clear();
        state.execute_approved_tokens.clear();
        state.patch_previews.clear();
        state.read_only_backstop.reset();

        let db_evidence =
            collect_audit_db_evidence(cx, self.auditor.as_deref(), state.conn.as_ref()).await;
        let rollback_result = state.conn.rollback(cx).await;
        let outcome = match rollback_result {
            Ok(()) => AuditOutcome::RolledBack,
            Err(err) => {
                mark_connection_quarantined(
                    &self.quarantine,
                    AuditOutcome::UnknownDiscarded,
                    format!(
                        "lane close rollback failed for reason {}: {err}",
                        reason.as_str()
                    ),
                )?;
                AuditOutcome::UnknownDiscarded
            }
        };

        append_lifecycle_audit(
            self.auditor.as_deref(),
            &subject,
            db_evidence.as_ref(),
            reason,
            outcome,
        )?;

        tracing::info!(
            close_reason = reason.as_str(),
            active_profile = active_profile.as_deref().unwrap_or(""),
            outcome = audit_outcome_label(outcome),
            "stateful Oracle dispatcher lifecycle cleanup completed"
        );
        Ok(())
    }

    async fn surface_state_with_cx(
        &self,
        cx: &Cx,
        context: DispatchContext<'_>,
        detail: McpSurfaceDetail,
    ) -> Result<McpSurfaceState, ErrorEnvelope> {
        let state = self.state.lock(cx).await.map_err(|_| {
            ErrorEnvelope::new(ErrorClass::Internal, "connection mutex lock failed")
        })?;
        let scoped_level = scoped_session_level(&state.level, context);
        let active_profile = state.active_profile.clone();
        let mut connection = ConnectionStatus {
            connected: false,
            profile: active_profile.clone(),
            server_version: None,
            read_only_standby: false,
            server_features: None,
        };
        if detail == McpSurfaceDetail::Connection
            && let Ok(info) = describe_conn(cx, state.conn.as_ref()).await
        {
            connection.connected = true;
            connection.read_only_standby = info.is_read_only_standby();
            connection.server_version = info.server_version;
            // K2: additive server-capability block. `describe` populates it only
            // for a live thin connection, so mocks/degraded backends leave it
            // `None` and the field is omitted from the report.
            connection.server_features = info.server_features;
        }
        Ok(McpSurfaceState {
            current_level: scoped_level.effective_level(),
            effective_ceiling: scoped_level.effective_ceiling(),
            max_level: scoped_level.max_level(),
            protected: scoped_level.is_protected(),
            active_profile,
            connection,
        })
    }

    async fn dispatch_with_cx_inner(
        &self,
        cx: &Cx,
        context: DispatchContext<'_>,
        name: &str,
        args: Value,
    ) -> Result<Value, ErrorEnvelope> {
        let request_budget = self.dispatch_request_budget(cx)?;
        let tool = canonical_tool_name(name);
        if tool == "oracle_switch_profile" {
            let a: SwitchProfileArgs = parse_args(name, args)?;
            let profile = required_switch_profile_arg(name, a.profile)?;
            // E5 connection-scope isolation: the served surface may only switch
            // to a profile the operator flagged `mcp_exposed`. A non-exposed or
            // unknown name is rejected here, BEFORE the connector ever resolves
            // the profile's credentials/DSN, with an envelope that does not
            // reveal whether the guessed name matched a hidden profile.
            if !self.mcp_exposure.is_exposed(&profile) {
                return Err(profile_not_available(&profile));
            }
            if self.profile_drain.is_draining(&profile) {
                return Err(profile_draining_error(&profile));
            }
            let Some(connector) = &self.connector else {
                return Err(ErrorEnvelope::new(
                    ErrorClass::RuntimeStateRequired,
                    "profile switching is unavailable in this server instance",
                )
                .with_next_step("restart the server with `oraclemcp serve --profile <name>`"));
            };

            let conn = connector(cx, &profile)
                .await
                .map_err(DbError::into_envelope)?;
            let stateless_conn = match &self.stateless_connector {
                Some(connector) => connector(cx, &profile)
                    .await
                    .map_err(DbError::into_envelope)?,
                None => None,
            };
            let mut response = connection_info_json(
                Some(profile.clone()),
                describe_conn(cx, conn.as_ref()).await,
            );
            if let Value::Object(map) = &mut response
                && let Some(stateless_conn) = stateless_conn.as_ref()
            {
                map.insert(
                    "stateless_read_connection".to_owned(),
                    connection_strategy_json(cx, stateless_conn.as_ref()).await,
                );
            }
            request_budget.enforce(cx).map_err(DbError::into_envelope)?;
            let new_policy = profile_dispatch_policy(&profile);
            let new_level = new_policy.level;
            let new_custom_catalog = match &self.custom_loader {
                Some(loader) => loader(Some(&profile), &new_level)?,
                None => CustomToolCatalog::default(),
            };
            let prepared = PreparedProfileSwitch {
                profile,
                conn,
                stateless_conn,
                level: new_level,
                request_timeout: new_policy.request_timeout,
                custom_catalog: new_custom_catalog,
                response,
            };
            // C-5: every capacity-, metadata-, and config-dependent operation
            // above runs before this commit point. The critical section below
            // performs only ownership swaps after its fallible mutex updates
            // succeed, so BUSY/AT_CAPACITY during preparation cannot strand the
            // lane connection-less or overwrite the old profile.
            let mut state = self.state.lock(cx).await.map_err(|_| {
                ErrorEnvelope::new(ErrorClass::Internal, "connection mutex lock failed")
            })?;
            let old_request_timeout = self.request_timeout()?;
            self.set_request_timeout(prepared.request_timeout)?;
            if let Err(err) = self.clear_connection_quarantine() {
                let _ = self.set_request_timeout(old_request_timeout);
                return Err(err);
            }
            let PreparedProfileSwitch {
                profile,
                conn,
                stateless_conn,
                level,
                custom_catalog,
                mut response,
                ..
            } = prepared;
            state.conn = conn;
            state.stateless_conn = stateless_conn;
            state.active_profile = Some(profile.clone());
            state.level = level;
            state.custom_catalog = custom_catalog;
            state.grant_generation = state.grant_generation.saturating_add(1);
            state.execute_grants.clear();
            state.execute_approved_tokens.clear();
            state.patch_previews.clear();
            // A1: the pinned session was replaced; the new session's transaction
            // is fresh, so re-assert the read-only backstop on its first read.
            state.read_only_backstop.reset();
            if let Value::Object(map) = &mut response {
                map.insert(
                    "custom_tool_count".to_owned(),
                    json!(state.custom_catalog.len()),
                );
            }
            drop(state);
            // E6: the switch may have changed the profile-scoped custom-tool
            // catalog (and thus the served tool set), so signal the client to
            // re-fetch `tools/list`. Enqueued on the shared hub; flushed by the
            // transport after this response.
            if let Some(notifications) = &self.notifications {
                notifications.enqueue_tools_list_changed();
            }
            return Ok(response);
        }

        if let Some(quarantine) = self.connection_quarantine()? {
            return Err(ErrorEnvelope::new(
                ErrorClass::RuntimeStateRequired,
                format!(
                    "active Oracle connection is quarantined after {}: {}",
                    audit_outcome_label(quarantine.outcome),
                    quarantine.message
                ),
            )
            .with_next_step("switch to a fresh profile connection or restart the server")
            .with_next_step(
                "do not retry non-idempotent work until the database outcome is verified",
            ));
        }

        // The async mutex serializes dispatch over the single connection and is
        // safe to hold across the DB `.await`s below (the dispatch future is
        // `!Send` and never spawned cross-thread). A lock failure surfaces as an
        // Internal error rather than a panic.
        let mut state = self.state.lock(cx).await.map_err(|_| {
            ErrorEnvelope::new(ErrorClass::Internal, "connection mutex lock failed")
        })?;
        let request_subject = audit_subject(context, &self.default_audit_subject);
        let scoped_level = scoped_session_level(&state.level, context);
        let scoped = context.scope_grant().is_some();
        if tool != "oracle_list_profiles"
            && tool != "oracle_connection_info"
            && let Some(active_profile) = state.active_profile.as_deref()
            && self.profile_drain.is_draining(active_profile)
        {
            return Err(profile_draining_error(active_profile));
        }
        if tool == "oracle_set_session_level" {
            let a: SetSessionLevelArgs = parse_args(name, args)?;
            let active_profile = state.active_profile.clone();
            let grant_binding = grant_binding_for_context(&state, context);
            let before = state.level.effective_level();
            let result = {
                let DispatcherState {
                    level,
                    execute_grants,
                    ..
                } = &mut *state;
                set_session_level_with_scope(
                    level,
                    &scoped_level,
                    SessionGrantContext {
                        active_profile: active_profile.as_deref(),
                        grants: execute_grants,
                        binding: &grant_binding,
                    },
                    name,
                    a,
                    scoped,
                )
            };
            let mut changed = false;
            let after = state.level.effective_level();
            if let Ok(value) = &result {
                changed = value.get("changed").and_then(Value::as_bool) == Some(true);
                if changed {
                    state.grant_generation = state.grant_generation.saturating_add(1);
                    state.execute_grants.clear();
                    state.execute_approved_tokens.clear();
                }
            }
            // Audit a successful level INCREASE (step-up approval). De-escalation
            // and status reads are not escalations and are not chained.
            if changed
                && after > before
                && let Some(auditor) = self.auditor.as_deref()
            {
                let after = state.level.effective_level();
                let subject = request_subject.clone();
                let db_evidence =
                    collect_audit_db_evidence(cx, Some(auditor), state.conn.as_ref()).await;
                let draft = AuditEntryDraft {
                    subject,
                    db_evidence,
                    cancel: None,
                    tool: "oracle_set_session_level".to_owned(),
                    sql: format!("ESCALATE {} -> {}", before.as_str(), after.as_str()),
                    danger_level: after.as_str().to_owned(),
                    decision: AuditDecision::StepUpRequired,
                    rows_affected: None,
                    outcome: AuditOutcome::Succeeded,
                };
                auditor
                    .append(&draft, audit_timestamp(), true)
                    .map_err(audit_error_to_envelope)?;
            }
            return result;
        }
        if tool == "oracle_preview_sql" {
            let a: PreviewSqlArgs = parse_args(name, args)?;
            let binding = grant_binding_for_context(&state, context);
            let preview = preview_sql(
                &a.sql,
                &scoped_level,
                state.active_profile.as_deref(),
                &state.execute_grants,
                &binding,
            );
            remember_execute_approved_token(&mut state, &a.sql, &preview);
            return Ok(preview);
        }
        if tool == "execute_approved" {
            let a: ExecuteApprovedArgs = parse_args(name, args)?;
            let execute_args = execute_approved_args(&mut state, &scoped_level, a)?;
            let active_profile = state.active_profile.clone();
            let subject = request_subject.clone();
            let grant_binding = grant_binding_for_context(&state, context);
            // A1: a gated write commits/rolls back the pinned session's
            // transaction, so disarm the read-only backstop before it runs (the
            // authorized write must never be refused with ORA-01456) and let the
            // next read re-assert it on the fresh transaction.
            state.read_only_backstop.disarm();
            let conn: &dyn OracleConnection = state.conn.as_ref();
            let audit = AuditCtx {
                auditor: self.auditor.as_deref(),
                subject: &subject,
            };
            let tool_ctx = DbToolCtx {
                cx,
                conn,
                request_budget,
                active_profile: active_profile.as_deref(),
                session: &scoped_level,
                execute_grants: &state.execute_grants,
                grant_binding: &grant_binding,
                write_intents: self.write_intents.as_deref(),
                audit,
                quarantine: &self.quarantine,
            };
            return execute_sql(tool_ctx, "oracle_execute", execute_args).await;
        }
        if tool == "deploy_ddl" {
            let a: DeployDdlArgs = parse_args(name, args)?;
            let active_profile = state.active_profile.clone();
            let subject = request_subject.clone();
            let grant_binding = grant_binding_for_context(&state, context);
            // A1: see execute_approved — disarm before a gated write/DDL.
            state.read_only_backstop.disarm();
            let conn: &dyn OracleConnection = state.conn.as_ref();
            let audit = AuditCtx {
                auditor: self.auditor.as_deref(),
                subject: &subject,
            };
            let tool_ctx = DbToolCtx {
                cx,
                conn,
                request_budget,
                active_profile: active_profile.as_deref(),
                session: &scoped_level,
                execute_grants: &state.execute_grants,
                grant_binding: &grant_binding,
                write_intents: self.write_intents.as_deref(),
                audit,
                quarantine: &self.quarantine,
            };
            return deploy_ddl(tool_ctx, a).await;
        }
        if tool == "read_patch_preview" {
            let a: ReadPatchPreviewArgs = parse_args(name, args)?;
            return read_patch_preview(&state, name, a);
        }
        // A1: the remaining write-class tools (oracle_execute and the DDL/source
        // mutators) run a gated write on the pinned session that commits or rolls
        // back, ending the read-only transaction. Disarm the backstop BEFORE the
        // immutable `conn` borrow below so the authorized write is not refused
        // with ORA-01456 and the next read re-asserts the backstop afresh. Pure
        // read/dictionary tools leave the backstop untouched (the read arm arms
        // it lazily). This is the only place the pinned session is mutated, so it
        // is the precise transaction boundary.
        if matches!(
            tool,
            "oracle_execute"
                | "oracle_compile_object"
                | "oracle_create_or_replace"
                | "oracle_patch_source"
        ) {
            state.read_only_backstop.disarm();
        }
        // A3/perf: oracle_query is handled here as a dedicated early-return arm
        // (like the write-class tools above) so its args are parsed ONCE and the
        // mark+classify pipeline runs ONCE. The prior code parsed `QueryArgs`
        // twice and marked/classified the same SQL on both the backstop path and
        // the read path — six classifier runs per call under the held
        // per-connection lock. Here we parse once, compute the single marked
        // `executed_sql` (classified == executed) and its single read-only gate
        // verdict, and reuse them for both the backstop and the read. Behavior
        // is identical; the conditional `args` move is confined to this diverging
        // branch, so `args` stays owned for the non-query match below.
        if tool == "oracle_query" {
            let prepared = {
                let parsed = parse_args::<QueryArgs>(name, args)?;
                // K9: validate the STRUCTURED as_of one-of and build the
                // flashback target BEFORE any classification or I/O (both-set /
                // empty -> typed refusal). The base SELECT below is classified
                // UNCHANGED — as_of never enters the classifier input, it only
                // selects WHICH committed snapshot the proven read observes.
                let as_of = query_as_of_from_args(parsed.as_of.as_ref())?;
                let executed_sql =
                    with_audit_marker(&parsed.sql, state.active_profile.as_deref(), "oracle_query");
                let gate = ensure_read_only(&executed_sql);
                QueryPrepared {
                    args: parsed,
                    executed_sql,
                    gate,
                    as_of,
                }
            };

            // A1: lazily ensure SET TRANSACTION READ ONLY is in force so a
            // MISCLASSIFIED write would still hit ORA-01456 from the engine.
            // `ensure_armed` is a no-op when the effective level is above
            // READ_ONLY (a write may be authorized) or when already armed (no
            // per-read round trip), and it fails closed if the statement cannot
            // apply.
            //
            // Guard-before-I/O: consult the single read-only gate computed above
            // and only arm when it passes. A refused statement therefore never
            // issues the backstop round trip (or any DB I/O); the read below
            // reuses the same verdict to surface the identical structured
            // refusal. The arm uses a disjoint &mut split of the guard's fields.
            if prepared.gate.is_ok() {
                if prepared.as_of.is_some() {
                    // K9: a flashback read cannot coexist with the SET
                    // TRANSACTION READ ONLY backstop — Oracle refuses
                    // DBMS_FLASHBACK.ENABLE inside a transaction (ORA-08183,
                    // verified live). The flashback wrapper (`read_query_as_of`)
                    // owns the session snapshot, and Oracle itself refuses DML
                    // while flashback is enabled, so layer B is preserved by a
                    // different DB mechanism. Reset the belief so the NEXT
                    // non-flashback read re-arms SET TRANSACTION READ ONLY on a
                    // fresh transaction (the wrapper rolls back the session, so
                    // any previously-armed read-only transaction is gone).
                    state.read_only_backstop.disarm();
                } else {
                    let DispatcherState {
                        conn,
                        read_only_backstop,
                        ..
                    } = &mut *state;
                    // Consult the effective level that governs THIS request
                    // (scoped_level folds in any OAuth scope, which can only
                    // LOWER the level — so this arms at least as often as the
                    // unscoped level, never less).
                    read_only_backstop
                        .ensure_armed(cx, conn.as_ref(), &scoped_level)
                        .await?;
                }
            }

            let active_profile = state.active_profile.clone();
            // E3/E3b: resolve the export access context (scope fingerprint)
            // before the immutable conn borrow / read closure.
            let export_scopes = context.scope_grant().map(|grant| grant.0.clone());
            let conn: &dyn OracleConnection = state.conn.as_ref();
            return self
                .run_prepared_query(
                    cx,
                    conn,
                    request_budget,
                    active_profile,
                    export_scopes,
                    prepared,
                )
                .await;
        }
        let generated_read = generated_read_tool(tool);
        if generated_read
            && (generated_read_uses_primary_session(tool) || state.stateless_conn.is_none())
        {
            let DispatcherState {
                conn,
                read_only_backstop,
                ..
            } = &mut *state;
            read_only_backstop
                .ensure_armed(cx, conn.as_ref(), &scoped_level)
                .await?;
        }

        let conn: &dyn OracleConnection = state.conn.as_ref();
        let metadata_conn: &dyn OracleConnection = state
            .stateless_conn
            .as_deref()
            .unwrap_or_else(|| state.conn.as_ref());
        let generated_read_subject = system_generated_read_subject();
        let generated_read_db_evidence = if generated_read {
            collect_audit_db_evidence(cx, self.auditor.as_deref(), conn).await
        } else {
            None
        };
        let generated_read_audit = GeneratedReadAuditCtx {
            entry: AuditEntryCtx {
                auditor: self.auditor.as_deref(),
                subject: &generated_read_subject,
                db_evidence: generated_read_db_evidence.as_ref(),
            },
            tool,
        };
        let guarded_conn = GuardedGeneratedReadConn {
            inner: conn,
            audit: generated_read_audit,
        };
        let guarded_metadata_conn = GuardedGeneratedReadConn {
            inner: metadata_conn,
            audit: generated_read_audit,
        };

        let result: Result<Value, ErrorEnvelope> = match tool {
            #[cfg(feature = "plsql-intelligence")]
            tool if crate::plsql_tools::is_static_tool(tool) => {
                crate::plsql_tools::dispatch_static(tool, args)
            }
            #[cfg(feature = "plsql-intelligence")]
            "oracle_plsql_live_snapshot" | "oracle_plsql_blast_radius" => {
                return crate::plsql_tools::dispatch_live(cx, metadata_conn, tool, args).await;
            }
            "oracle_execute" => {
                let a: ExecuteArgs = parse_args(name, args)?;
                let subject = request_subject.clone();
                let grant_binding = grant_binding_for_context(&state, context);
                let audit = AuditCtx {
                    auditor: self.auditor.as_deref(),
                    subject: &subject,
                };
                let tool_ctx = DbToolCtx {
                    cx,
                    conn,
                    request_budget,
                    active_profile: state.active_profile.as_deref(),
                    session: &scoped_level,
                    execute_grants: &state.execute_grants,
                    grant_binding: &grant_binding,
                    write_intents: self.write_intents.as_deref(),
                    audit,
                    quarantine: &self.quarantine,
                };
                return execute_sql(tool_ctx, "oracle_execute", a).await;
            }
            "oracle_compile_object" => {
                let a: CompileObjectArgs = parse_args(name, args)?;
                let subject = request_subject.clone();
                let grant_binding = grant_binding_for_context(&state, context);
                let audit = AuditCtx {
                    auditor: self.auditor.as_deref(),
                    subject: &subject,
                };
                let tool_ctx = DbToolCtx {
                    cx,
                    conn,
                    request_budget,
                    active_profile: state.active_profile.as_deref(),
                    session: &scoped_level,
                    execute_grants: &state.execute_grants,
                    grant_binding: &grant_binding,
                    write_intents: self.write_intents.as_deref(),
                    audit,
                    quarantine: &self.quarantine,
                };
                return compile_object(tool_ctx, name, a).await;
            }
            "oracle_create_or_replace" => {
                let a: CreateOrReplaceArgs = parse_args(name, args)?;
                let subject = request_subject.clone();
                let grant_binding = grant_binding_for_context(&state, context);
                let audit = AuditCtx {
                    auditor: self.auditor.as_deref(),
                    subject: &subject,
                };
                let tool_ctx = DbToolCtx {
                    cx,
                    conn,
                    request_budget,
                    active_profile: state.active_profile.as_deref(),
                    session: &scoped_level,
                    execute_grants: &state.execute_grants,
                    grant_binding: &grant_binding,
                    write_intents: self.write_intents.as_deref(),
                    audit,
                    quarantine: &self.quarantine,
                };
                return create_or_replace(tool_ctx, name, a).await;
            }
            "oracle_patch_source" => {
                let a: PatchSourceArgs = parse_args(name, args)?;
                let subject = request_subject.clone();
                let grant_binding = grant_binding_for_context(&state, context);
                let audit = AuditCtx {
                    auditor: self.auditor.as_deref(),
                    subject: &subject,
                };
                let tool_ctx = DbToolCtx {
                    cx,
                    conn,
                    request_budget,
                    active_profile: state.active_profile.as_deref(),
                    session: &scoped_level,
                    execute_grants: &state.execute_grants,
                    grant_binding: &grant_binding,
                    write_intents: self.write_intents.as_deref(),
                    audit,
                    quarantine: &self.quarantine,
                };
                let (value, preview_entry) = patch_source(tool_ctx, name, a).await?;
                if let Some(preview_entry) = preview_entry {
                    remember_patch_preview(&mut state, preview_entry);
                }
                return Ok(value);
            }
            "oracle_list_profiles" => {
                ensure_no_args(name, args)?;
                OracleMcpConfig::load(None)
                    .map(|cfg| profiles_response(&cfg, &self.mcp_exposure, &self.profile_drain))
                    .map_err(|e| {
                        DbError::UnsupportedAuth(format!("config load failed: {e}")).into_envelope()
                    })
            }
            "oracle_connection_info" => {
                ensure_no_args(name, args)?;
                let mut value = connection_info_json(
                    state.active_profile.clone(),
                    describe_conn(cx, conn).await,
                );
                if let Value::Object(map) = &mut value
                    && let Some(stateless_conn) = state.stateless_conn.as_ref()
                {
                    map.insert(
                        "stateless_read_connection".to_owned(),
                        connection_strategy_json(cx, stateless_conn.as_ref()).await,
                    );
                }
                Ok(value)
            }
            "oracle_schema_inspect" => {
                let a: SchemaInspectArgs = parse_args(name, args)?;
                let owner_arg = non_empty_arg(a.owner);
                let object_type = non_empty_arg(a.object_type);
                let name_like = non_empty_arg(a.name_like);
                let max_rows = a
                    .max_rows
                    .unwrap_or(DEFAULT_SCHEMA_INSPECT_MAX_ROWS)
                    .clamp(1, MAX_SCHEMA_INSPECT_MAX_ROWS);
                let owner_filter: Option<String> = match owner_arg.as_deref() {
                    Some("*") => None,
                    Some(owner) => Some(owner.to_owned()),
                    None => {
                        let info = describe_conn(cx, metadata_conn)
                            .await
                            .map_err(DbError::into_envelope)?;
                        Some(
                            info.current_schema
                                .ok_or_else(|| {
                                    DbError::Query(
                                        "owner is required because current_schema could not be detected"
                                            .to_owned(),
                                    )
                                })
                                .map_err(DbError::into_envelope)?,
                        )
                    }
                };
                dispatch_checkpoint(cx, "oraclemcp.dispatch.schema_inspect.before")?;
                let rows = list_objects(
                    cx,
                    &guarded_metadata_conn,
                    owner_filter.as_deref(),
                    object_type.as_deref(),
                    name_like.as_deref(),
                    max_rows,
                )
                .await
                .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.schema_inspect.after")?;
                Ok(json!({
                    "objects": rows_to_json(&rows),
                    "owner": owner_filter.as_deref().unwrap_or("*"),
                    "object_type": object_type,
                    "name_like": name_like,
                    "max_rows": max_rows,
                    "truncated": rows.len() == max_rows,
                }))
            }
            "oracle_search_objects" => {
                // E4: unified read-only object search/inspection. Read-only
                // dictionary surface (ALL_OBJECTS/ALL_TABLES/ALL_TAB_COLUMNS/…),
                // so it takes the read-path narrowed capability row like the
                // other dictionary tools and never executes caller SQL.
                let a: SearchObjectsArgs = parse_args(name, args)?;
                let detail =
                    SearchDetailLevel::parse(a.detail_level.as_deref()).ok_or_else(|| {
                        invalid_args("detail_level must be one of: names, summary, standard, full")
                    })?;
                let owner_arg = non_empty_arg(a.owner);
                let object_type = non_empty_arg(a.object_type);
                let name_like = non_empty_arg(a.name_like);
                let max_rows = a
                    .max_rows
                    .unwrap_or(DEFAULT_SEARCH_OBJECTS_MAX_ROWS)
                    .clamp(1, MAX_SEARCH_OBJECTS_MAX_ROWS);
                let owner_filter: Option<String> = match owner_arg.as_deref() {
                    Some("*") => None,
                    Some(owner) => Some(owner.to_owned()),
                    None => {
                        let info = describe_conn(cx, metadata_conn)
                            .await
                            .map_err(DbError::into_envelope)?;
                        Some(
                            info.current_schema
                                .ok_or_else(|| {
                                    DbError::Query(
                                        "owner is required because current_schema could not be detected"
                                            .to_owned(),
                                    )
                                })
                                .map_err(DbError::into_envelope)?,
                        )
                    }
                };
                // A9: the dispatch-level handler work (cancellation checkpoints)
                // runs under the narrowed read-path row — no SPAWN / REMOTE /
                // RANDOM is reachable here.
                let read_cx = narrow_to_read_path(cx);
                dispatch_checkpoint(&read_cx, "oraclemcp.dispatch.search_objects.before")?;
                // The DB round trip is the single documented IO exception: the
                // object-safe, API-locked `OracleConnection` trait takes `&Cx`
                // (the full row) because the native driver needs `IO`, so the
                // round trip itself is handed the full `cx`. `ReadPathCaps` does
                // carry `IO`, but the locked trait cannot be made generic without
                // breaking object safety — narrowing therefore applies to the
                // handler scaffolding, and the IO call is the explicit exception.
                let results = search_objects(
                    cx,
                    &guarded_metadata_conn,
                    owner_filter.as_deref(),
                    object_type.as_deref(),
                    name_like.as_deref(),
                    detail,
                    max_rows,
                )
                .await
                .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(&read_cx, "oraclemcp.dispatch.search_objects.after")?;
                Ok(json!({
                    "owner": owner_filter.as_deref().unwrap_or("*"),
                    "object_type": object_type,
                    "name_like": name_like,
                    "detail_level": detail.as_str(),
                    "count": results.len(),
                    "results": results,
                    "max_rows": max_rows,
                    "truncated": results.len() == max_rows,
                }))
            }
            "oracle_list_schemas" => {
                let a: ListSchemasArgs = parse_args(name, args)?;
                let name_like = non_empty_arg(a.name_like);
                let max_rows = a
                    .max_rows
                    .unwrap_or(DEFAULT_SCHEMA_LIST_MAX_ROWS)
                    .clamp(1, MAX_SCHEMA_LIST_MAX_ROWS);
                dispatch_checkpoint(cx, "oraclemcp.dispatch.list_schemas.before")?;
                let rows = list_schemas(cx, &guarded_metadata_conn, name_like.as_deref(), max_rows)
                    .await
                    .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.list_schemas.after")?;
                Ok(json!({
                    "schemas": rows_to_json(&rows),
                    "name_like": name_like,
                    "max_rows": max_rows,
                    "truncated": rows.len() == max_rows,
                }))
            }
            "oracle_describe" => {
                let a: DescribeArgs = parse_args(name, args)?;
                let table = required_non_empty_arg(name, "table", a.table)?;
                let (owner, table) =
                    owner_and_name_arg(cx, metadata_conn, a.owner, table, "table").await?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.describe_columns.before")?;
                let columns = describe_columns(cx, &guarded_metadata_conn, &owner, &table)
                    .await
                    .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.describe_constraints.before")?;
                let constraints = describe_constraints(cx, &guarded_metadata_conn, &owner, &table)
                    .await
                    .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.describe_constraints.after")?;
                Ok(json!({
                    "owner": owner,
                    "table": table,
                    "columns": rows_to_json(&columns),
                    "constraints": rows_to_json(&constraints),
                }))
            }
            "oracle_describe_index" => {
                let a: DescribeIndexArgs = parse_args(name, args)?;
                let (owner, object_name) =
                    owner_and_name_arg(cx, metadata_conn, a.owner, a.name, "index").await?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.describe_index.before")?;
                let desc = describe_index(cx, &guarded_metadata_conn, &owner, &object_name)
                    .await
                    .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.describe_index.after")?;
                Ok(json!({
                    "owner": owner,
                    "name": object_name,
                    "index": optional_row_to_json(desc.metadata.as_ref()),
                    "columns": rows_to_json(&desc.columns),
                    "expressions": rows_to_json(&desc.expressions),
                }))
            }
            "oracle_describe_trigger" => {
                let a: DescribeTriggerArgs = parse_args(name, args)?;
                let (owner, object_name) =
                    owner_and_name_arg(cx, metadata_conn, a.owner, a.name, "trigger").await?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.describe_trigger.before")?;
                let desc = describe_trigger(cx, &guarded_metadata_conn, &owner, &object_name)
                    .await
                    .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.describe_trigger.after")?;
                Ok(json!({
                    "owner": owner,
                    "name": object_name,
                    "trigger": optional_row_to_json(desc.metadata.as_ref()),
                }))
            }
            "oracle_describe_view" => {
                let a: DescribeViewArgs = parse_args(name, args)?;
                let (owner, object_name) =
                    owner_and_name_arg(cx, metadata_conn, a.owner, a.name, "view").await?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.describe_view.before")?;
                let desc = describe_view(cx, &guarded_metadata_conn, &owner, &object_name)
                    .await
                    .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.describe_view.after")?;
                Ok(json!({
                    "owner": owner,
                    "name": object_name,
                    "view": optional_row_to_json(desc.metadata.as_ref()),
                    "columns": rows_to_json(&desc.columns),
                }))
            }
            "oracle_get_ddl" => {
                let a: GetDdlArgs = parse_args(name, args)?;
                let (owner, object_name) =
                    owner_and_name_arg(cx, metadata_conn, a.owner, a.name, "name").await?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.get_ddl.before")?;
                let ddl = get_ddl(
                    cx,
                    &guarded_metadata_conn,
                    &a.object_type,
                    &owner,
                    &object_name,
                )
                .await
                .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.get_ddl.after")?;
                Ok(json!({ "owner": owner, "name": object_name, "ddl": ddl }))
            }
            "oracle_get_source" => {
                let a: GetSourceArgs = parse_args(name, args)?;
                let max_chars = a.max_chars.unwrap_or(DEFAULT_SOURCE_MAX_CHARS);
                let (owner, object_name) =
                    owner_and_name_arg(cx, metadata_conn, a.owner, a.name, "name").await?;
                match a.object_type.as_deref().filter(|s| !s.trim().is_empty()) {
                    Some(object_type) => {
                        dispatch_checkpoint(cx, "oraclemcp.dispatch.get_source.before")?;
                        let source = get_source(
                            cx,
                            &guarded_metadata_conn,
                            &owner,
                            &object_name,
                            object_type,
                            max_chars,
                        )
                        .await
                        .map_err(DbError::into_envelope)?;
                        dispatch_checkpoint(cx, "oraclemcp.dispatch.get_source.after")?;
                        Ok(json!({ "source": source }))
                    }
                    None => {
                        dispatch_checkpoint(cx, "oraclemcp.dispatch.get_sources_by_name.before")?;
                        let sources = get_sources_by_name(
                            cx,
                            &guarded_metadata_conn,
                            &owner,
                            &object_name,
                            max_chars,
                        )
                        .await
                        .map_err(DbError::into_envelope)?;
                        dispatch_checkpoint(cx, "oraclemcp.dispatch.get_sources_by_name.after")?;
                        Ok(json!({
                            "owner": owner,
                            "name": object_name,
                            "source_count": sources.len(),
                            "sources": sources,
                        }))
                    }
                }
            }
            "oracle_sample_rows" => {
                let a: SampleRowsArgs = parse_args(name, args)?;
                let max_rows = a
                    .max_rows
                    .unwrap_or(DEFAULT_SAMPLE_MAX_ROWS)
                    .clamp(1, MAX_SAMPLE_MAX_ROWS);
                let (owner, table) =
                    owner_and_name_arg(cx, conn, a.owner, a.table, "table").await?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.sample_rows.before")?;
                let rows = sample_rows(cx, &guarded_conn, &owner, &table, max_rows)
                    .await
                    .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.sample_rows.after")?;
                Ok(
                    json!({ "owner": owner, "table": table, "rows": rows_to_json(&rows), "row_count": rows.len() }),
                )
            }
            "oracle_top_queries" => {
                let a: TopQueriesArgs = parse_args(name, args)?;
                let metric = match a.metric.as_deref() {
                    None => oraclemcp_db::TopSqlMetric::Elapsed,
                    Some(raw) => oraclemcp_db::TopSqlMetric::parse(raw).ok_or_else(|| {
                        invalid_args(format!(
                            "unknown metric '{raw}': use elapsed, cpu, buffer_gets, or disk_reads"
                        ))
                    })?,
                };
                let top_n = a.top_n.unwrap_or(20);
                let min_pct = a.min_pct_of_total;
                let historical = a.historical;
                let timeout_seconds = a.timeout_seconds;
                // Read-only diagnostic: resolve the source (free live cursor cache
                // by default; AWR only when the Diagnostics Pack is licensed, else
                // Statspack, else a structured-unavailable error), build the ranked
                // SQL, and run it as a bounded read.
                return with_call_timeout(cx, conn, request_budget, timeout_seconds, || async {
                    let source =
                        oraclemcp_db::resolve_top_sql_source(cx, &guarded_conn, historical).await;
                    let sql = oraclemcp_db::top_sql_query(source, metric, top_n, min_pct)?;
                    let rows = guarded_conn
                        .query_rows(cx, &sql, &[])
                        .await
                        .map_err(DbError::into_envelope)?;
                    Ok(json!({
                        "source": serde_json::to_value(source).unwrap_or(Value::Null),
                        "metric": serde_json::to_value(metric).unwrap_or(Value::Null),
                        "rows": rows_to_json(&rows),
                        "row_count": rows.len(),
                    }))
                })
                .await;
            }
            "oracle_db_health" => {
                let a: DbHealthArgs = parse_args(name, args)?;
                let request =
                    oraclemcp_db::parse_health_request(a.health_type.as_deref().unwrap_or("all"));
                let timeout_seconds = a.timeout_seconds;
                // Read-only DBA health suite: each requested subcheck runs a pure
                // V$/DBA_*/ALL_* read with DBA_*->ALL_* privilege degradation, and
                // any per-subcheck failure becomes a structured `skipped` finding
                // rather than failing the whole call. Unknown subcheck names are
                // reported, never fatal.
                return with_call_timeout(cx, conn, request_budget, timeout_seconds, || async {
                    let findings =
                        oraclemcp_db::run_health(cx, &guarded_conn, &request.subchecks).await;
                    let checks_run: Vec<&str> = findings
                        .iter()
                        .filter(|f| {
                            f.detail.get("status").and_then(Value::as_str) != Some("skipped")
                        })
                        .map(|f| f.subcheck.name())
                        .collect();
                    let checks_skipped: Vec<&str> = findings
                        .iter()
                        .filter(|f| {
                            f.detail.get("status").and_then(Value::as_str) == Some("skipped")
                        })
                        .map(|f| f.subcheck.name())
                        .collect();
                    Ok(json!({
                        "findings": serde_json::to_value(&findings).unwrap_or(Value::Null),
                        "checks_run": checks_run,
                        "checks_skipped": checks_skipped,
                        "unknown_checks": request.unknown,
                    }))
                })
                .await;
            }
            "oracle_read_clob" => {
                let a: ReadClobArgs = parse_args(name, args)?;
                let max_chars = a.max_chars.unwrap_or(DEFAULT_LOB_MAX_CHARS);
                let (owner, table) =
                    owner_and_name_arg(cx, conn, a.owner, a.table, "table").await?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.read_lob.before")?;
                let clob = read_lob(
                    cx,
                    &guarded_conn,
                    &owner,
                    &table,
                    &a.clob_column,
                    &a.pk_column,
                    &a.pk_value,
                    max_chars,
                )
                .await
                .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.read_lob.after")?;
                Ok(json!({ "clob": clob }))
            }
            "oracle_compile_errors" => {
                let a: CompileErrorsArgs = parse_args(name, args)?;
                let object_name = non_empty_arg(a.name);
                match object_name {
                    Some(object_name) => {
                        let (owner, object_name) =
                            owner_and_name_arg(cx, metadata_conn, a.owner, object_name, "name")
                                .await?;
                        dispatch_checkpoint(cx, "oraclemcp.dispatch.compile_errors.before")?;
                        let rows =
                            compile_errors(cx, &guarded_metadata_conn, &owner, Some(&object_name))
                                .await
                                .map_err(DbError::into_envelope)?;
                        dispatch_checkpoint(cx, "oraclemcp.dispatch.compile_errors.after")?;
                        Ok(
                            json!({ "owner": owner, "name": object_name, "errors": rows_to_json(&rows) }),
                        )
                    }
                    None => {
                        let owner = owner_or_current_cx(cx, metadata_conn, a.owner)
                            .await
                            .map_err(DbError::into_envelope)?;
                        dispatch_checkpoint(cx, "oraclemcp.dispatch.compile_errors.before")?;
                        let rows = compile_errors(cx, &guarded_metadata_conn, &owner, None)
                            .await
                            .map_err(DbError::into_envelope)?;
                        dispatch_checkpoint(cx, "oraclemcp.dispatch.compile_errors.after")?;
                        Ok(json!({ "owner": owner, "errors": rows_to_json(&rows) }))
                    }
                }
            }
            "oracle_search_source" => {
                let a: SearchSourceArgs = parse_args(name, args)?;
                let max_rows = a
                    .max_rows
                    .unwrap_or(DEFAULT_SEARCH_MAX_ROWS)
                    .clamp(1, MAX_SEARCH_MAX_ROWS);
                let requested_owner = non_empty_arg(a.owner);
                let owner = match requested_owner.as_deref() {
                    Some("*") => None,
                    Some(owner) => Some(owner.to_ascii_uppercase()),
                    None => Some(
                        owner_or_current_cx(cx, metadata_conn, None)
                            .await
                            .map_err(DbError::into_envelope)?,
                    ),
                };
                let object_type = non_empty_arg(a.object_type);
                let name_like = non_empty_arg(a.name_like);
                dispatch_checkpoint(cx, "oraclemcp.dispatch.search_source.before")?;
                let rows = search_source(
                    cx,
                    &guarded_metadata_conn,
                    owner.as_deref(),
                    &a.needle,
                    object_type.as_deref(),
                    name_like.as_deref(),
                    max_rows,
                )
                .await
                .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.search_source.after")?;
                Ok(json!({
                    "owner": owner.as_deref().unwrap_or("*"),
                    "object_type": object_type,
                    "name_like": name_like,
                    "max_rows": max_rows,
                    "matches": rows_to_json(&rows),
                }))
            }
            "oracle_plscope_inspect" => {
                let a: PlscopeInspectArgs = parse_args(name, args)?;
                let object_name = required_non_empty_arg(name, "name", a.name)?;
                let (owner, object_name) =
                    owner_and_name_arg(cx, metadata_conn, a.owner, object_name, "name").await?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.plscope_identifiers.before")?;
                let identifiers =
                    plscope_identifiers(cx, &guarded_metadata_conn, &owner, &object_name)
                        .await
                        .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.plscope_identifiers.after")?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.plscope_statements.before")?;
                let statements =
                    plscope_statements(cx, &guarded_metadata_conn, &owner, &object_name)
                        .await
                        .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.plscope_statements.after")?;
                let unused_declarations = find_unused_declarations(&identifiers);
                let dynamic_sql_lines = execute_immediate_audit(&statements);
                Ok(json!({
                    "owner": owner,
                    "name": object_name,
                    "identifier_count": identifiers.len(),
                    "statement_count": statements.len(),
                    "unused_declarations": unused_declarations,
                    "dynamic_sql_lines": dynamic_sql_lines,
                    "identifiers": identifiers,
                    "statements": statements,
                }))
            }
            "oracle_explain_plan" => {
                let a: ExplainPlanArgs = parse_args(name, args)?;
                ensure_read_only(&a.sql)?;
                ensure_explain_plan_write_allowed(&a, &scoped_level)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.explain_plan.before")?;
                let rows = explain_plan(cx, conn, &a.sql, a.read_only_standby)
                    .await
                    .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.explain_plan.after")?;
                let mut response = json!({
                    "plan": rows_to_json(&rows),
                    "diagnostic_write": {
                        "statement": "EXPLAIN PLAN",
                        "writes": "PLAN_TABLE",
                        "required_level": OperatingLevel::ReadWrite,
                        "explicitly_allowed": a.allow_plan_table_write,
                    },
                });
                // ADDITIVE / observational: surface the optimizer's relative
                // cost/cardinality for the plan we just wrote. A missing cost
                // column, table, or plan (ancient/RULE-mode DBs) degrades to an
                // omitted block with a note — it must never fail the EXPLAIN.
                match plan_cost_estimate(cx, conn).await {
                    Ok(Some(estimate)) => {
                        if let Ok(value) = serde_json::to_value(&estimate) {
                            response["cost_estimate"] = value;
                        }
                    }
                    Ok(None) => {
                        response["cost_estimate_unavailable"] = json!(
                            "PLAN_TABLE returned no scoped plan-root (id=0) row for a cost estimate"
                        );
                    }
                    Err(err) => {
                        response["cost_estimate_unavailable"] =
                            json!(format!("cost estimate unavailable: {err}"));
                    }
                }
                Ok(response)
            }
            other => {
                if let Some(loaded) = state.custom_catalog.get(other) {
                    let executor = ReadOnlyCustomToolExecutor { cx, conn };
                    return execute_custom_tool(loaded, &args, &executor).await;
                }
                return Err(invalid_args(format!(
                    "unknown tool: {other:?} (call oracle_capabilities for the tool surface)"
                )));
            }
        };

        result
    }

    /// Run an oracle_query whose args were parsed and whose SQL was marked +
    /// classified ONCE up front (see `QueryPrepared`). Reuses the prepared
    /// `executed_sql` and `gate` instead of re-parsing/re-marking/re-classifying
    /// — behavior is identical to the prior inline arm, with one classify run.
    async fn run_prepared_query(
        &self,
        cx: &Cx,
        conn: &dyn OracleConnection,
        request_budget: RequestBudget,
        active_profile: Option<String>,
        export_scopes: Option<Vec<String>>,
        prepared: QueryPrepared,
    ) -> Result<Value, ErrorEnvelope> {
        let QueryPrepared {
            args: a,
            executed_sql,
            gate,
            as_of,
        } = prepared;
        let timeout_seconds = a.timeout_seconds;
        let exports = self.exports.clone();
        // A9: narrow the handler context to the read-path capability row
        // (TIME + IO; no SPAWN / REMOTE / RANDOM). The pure handler work below —
        // gate, bind conversion, cursor decode, serialization — runs under this
        // narrowed row; only the locked DB round trip (`OracleConnection` is
        // object-safe and takes the full `&Cx`) is handed the full `cx`, the one
        // documented IO exception.
        let read_cx = narrow_to_read_path(cx);
        with_call_timeout(cx, conn, request_budget, timeout_seconds, || async {
            dispatch_checkpoint(&read_cx, "oraclemcp.dispatch.query.before")?;
            // The read-only gate was computed ONCE up front (classified ==
            // executed); reuse the same verdict here. `executed_sql` is the
            // marked text that gate was computed against.
            gate?;
            let binds = a
                .binds
                .iter()
                .map(json_to_bind)
                .collect::<Result<Vec<_>, _>>()?;
            // E2: the page cursor is an opaque, tamper-evident token bound to
            // THIS statement + active profile, decoded to a raw offset here (a
            // forged/cross-statement cursor fails closed).
            let offset =
                decode_query_cursor(a.cursor.as_deref(), &a.sql, active_profile.as_deref())?;
            // K10: streaming delivery. The classifier already proved this read
            // (`gate?` above); streaming only changes how the SAME rows are
            // DELIVERED — as an ordered, resumable `chunks` array driven by
            // successive cursor pages, byte-identical to a manual cursor resume.
            if a.streaming {
                if a.export {
                    return Err(invalid_args(
                        "streaming and export are mutually exclusive: choose incremental \
                         chunks (streaming=true) OR a single export resource (export=true)",
                    )
                    .with_next_step("re-run with exactly one of streaming / export"));
                }
                if as_of.is_some() {
                    return Err(invalid_args(
                        "streaming and as_of are mutually exclusive: a flashback read is \
                         delivered as a single page — resume it with the returned cursor",
                    )
                    .with_next_step("drop streaming, or page the as_of read with cursor"));
                }
                let caps = query_caps_from_args(&a);
                let serialize_opts = query_serialize_options_from_args(&a);
                return Self::stream_query_response(
                    cx,
                    conn,
                    &executed_sql,
                    &a.sql,
                    &binds,
                    caps,
                    offset,
                    &serialize_opts,
                    active_profile.as_deref(),
                )
                .await;
            }
            // E3b: when the caller opts into export, materialize the bounded full
            // result as an oracle-export://{id} resource and return a
            // resource_link instead of inlining the rows.
            if a.export {
                return export_query_to_resource(
                    cx,
                    conn,
                    &executed_sql,
                    &a,
                    &binds,
                    offset,
                    active_profile.as_deref(),
                    export_scopes.as_deref(),
                    exports.as_deref(),
                    as_of.as_ref(),
                )
                .await;
            }
            // K9: when a flashback target is set, run the SAME proven SQL inside
            // a bounded DBMS_FLASHBACK window (`read_query_as_of`); otherwise the
            // plain read path. Both take the identical proven `executed_sql`.
            let caps = query_caps_from_args(&a);
            let serialize_opts = query_serialize_options_from_args(&a);
            let read = match as_of.as_ref() {
                Some(as_of) => {
                    read_query_as_of(
                        cx,
                        conn,
                        &executed_sql,
                        &binds,
                        caps,
                        offset,
                        &serialize_opts,
                        as_of,
                    )
                    .await
                }
                None => {
                    read_query(
                        cx,
                        conn,
                        &executed_sql,
                        &binds,
                        caps,
                        offset,
                        &serialize_opts,
                    )
                    .await
                }
            };
            read.map(|resp| serde_json::to_value(resp).unwrap_or(Value::Null))
                .map(|resp| reseal_query_cursor(resp, &a.sql, active_profile.as_deref()))
                .map_err(DbError::into_envelope)
        })
        .await
    }

    async fn dispatch_query_stream_with_cx(
        &self,
        cx: &Cx,
        context: DispatchContext<'_>,
        name: &str,
        args: Value,
        frames: ToolStreamSender,
    ) -> Result<Value, ErrorEnvelope> {
        let request_budget = self.dispatch_request_budget(cx)?;
        if let Some(quarantine) = self.connection_quarantine()? {
            return Err(ErrorEnvelope::new(
                ErrorClass::RuntimeStateRequired,
                format!(
                    "database session is quarantined after an uncertain outcome ({outcome}): {message}",
                    outcome = audit_outcome_label(quarantine.outcome),
                    message = quarantine.message
                ),
            )
            .with_next_step("switch to a fresh profile connection or restart the server")
            .with_next_step(
                "do not retry non-idempotent work until the database outcome is verified",
            ));
        }

        let delivery = {
            let mut state = self.state.lock(cx).await.map_err(|_| {
                ErrorEnvelope::new(ErrorClass::Internal, "connection mutex lock failed")
            })?;
            let scoped_level = scoped_session_level(&state.level, context);
            if let Some(active_profile) = state.active_profile.as_deref()
                && self.profile_drain.is_draining(active_profile)
            {
                return Err(profile_draining_error(active_profile));
            }
            let prepared = {
                let parsed = parse_args::<QueryArgs>(name, args)?;
                if !parsed.streaming {
                    return Err(invalid_args(
                        "streaming dispatch requires oracle_query streaming=true",
                    ));
                }
                let as_of = query_as_of_from_args(parsed.as_of.as_ref())?;
                let executed_sql =
                    with_audit_marker(&parsed.sql, state.active_profile.as_deref(), "oracle_query");
                let gate = ensure_read_only(&executed_sql);
                QueryPrepared {
                    args: parsed,
                    executed_sql,
                    gate,
                    as_of,
                }
            };

            if prepared.gate.is_ok() {
                if prepared.as_of.is_some() {
                    state.read_only_backstop.disarm();
                } else {
                    let DispatcherState {
                        conn,
                        read_only_backstop,
                        ..
                    } = &mut *state;
                    read_only_backstop
                        .ensure_armed(cx, conn.as_ref(), &scoped_level)
                        .await?;
                }
            }

            let active_profile = state.active_profile.clone();
            let conn: &dyn OracleConnection = state.conn.as_ref();
            self.prepare_query_stream_delivery(cx, conn, request_budget, active_profile, prepared)
                .await?
        };

        match delivery {
            QueryStreamDelivery::Rows(plan) => self.drive_query_row_stream(cx, *plan, frames).await,
            QueryStreamDelivery::Chunked(response) => {
                Self::emit_chunked_stream_frames(cx, response, frames).await
            }
        }
    }

    async fn prepare_query_stream_delivery(
        &self,
        cx: &Cx,
        conn: &dyn OracleConnection,
        request_budget: RequestBudget,
        active_profile: Option<String>,
        prepared: QueryPrepared,
    ) -> Result<QueryStreamDelivery, ErrorEnvelope> {
        let QueryPrepared {
            args: a,
            executed_sql,
            gate,
            as_of,
        } = prepared;
        dispatch_checkpoint(cx, "oraclemcp.dispatch.query.row_stream.before")?;
        gate?;
        let binds = a
            .binds
            .iter()
            .map(json_to_bind)
            .collect::<Result<Vec<_>, _>>()?;
        let offset = decode_query_cursor(a.cursor.as_deref(), &a.sql, active_profile.as_deref())?;
        if a.export {
            return Err(invalid_args(
                "streaming and export are mutually exclusive: choose incremental \
                 delivery (streaming=true) OR a single export resource (export=true)",
            )
            .with_next_step("re-run with exactly one of streaming / export"));
        }
        if as_of.is_some() {
            return Err(invalid_args(
                "streaming and as_of are mutually exclusive: a flashback read is \
                 delivered as a single page — resume it with the returned cursor",
            )
            .with_next_step("drop streaming, or page the as_of read with cursor"));
        }
        let caps = query_caps_from_args(&a);
        let serialize_opts = query_serialize_options_from_args(&a);
        let timeout = call_timeout_duration(a.timeout_seconds)?;
        let stream_budget = match timeout {
            Some(timeout) => request_budget.meet(Budget::new().with_timeout(cx.now(), timeout)),
            None => request_budget,
        };
        stream_budget.enforce(cx).map_err(DbError::into_envelope)?;
        let previous_timeout = conn.call_timeout().map_err(DbError::into_envelope)?;
        let effective_timeout =
            timeout.map(|timeout| previous_timeout.map_or(timeout, |current| current.min(timeout)));
        if let Some(timeout) = effective_timeout {
            conn.set_call_timeout(Some(timeout))
                .map_err(DbError::into_envelope)?;
        }
        let fetch_rows = MAX_QUERY_STREAM_ROWS.saturating_add(1);
        let wrapped_sql = paginated_sql(&executed_sql, offset, fetch_rows);
        let stream_start = conn
            .query_row_stream(
                cx,
                &wrapped_sql,
                &binds,
                caps.max_rows.max(1),
                &serialize_opts,
            )
            .await
            .map_err(|err| self.stream_db_error_envelope(err));
        let restore = conn
            .set_call_timeout(previous_timeout)
            .map_err(DbError::into_envelope);
        let stream_start = match (stream_start, restore) {
            (Ok(value), Ok(())) => value,
            (Err(err), _) => return Err(err),
            (Ok(QueryRowStreamStart::Stream(stream)), Err(err)) => {
                stream
                    .recover(cx)
                    .await
                    .map_err(|recover_err| self.stream_db_error_envelope(recover_err))?;
                return Err(err);
            }
            (Ok(_), Err(err)) => return Err(err),
        };
        match stream_start {
            QueryRowStreamStart::Stream(stream) => {
                let columns = stream.columns().to_vec();
                Ok(QueryStreamDelivery::Rows(Box::new(QueryRowStreamPlan {
                    stream,
                    columns,
                    cursor_sql: a.sql,
                    active_profile,
                    start_offset: offset,
                    serialize_opts,
                    request_budget: stream_budget,
                })))
            }
            QueryRowStreamStart::Fallback { reason } => {
                tracing::debug!(
                    fallback_reason = %reason,
                    "oracle_query row streaming fell back to cursor chunks"
                );
                let response = Self::stream_query_response(
                    cx,
                    conn,
                    &executed_sql,
                    &a.sql,
                    &binds,
                    caps,
                    offset,
                    &serialize_opts,
                    active_profile.as_deref(),
                )
                .await?;
                Ok(QueryStreamDelivery::Chunked(response))
            }
        }
    }

    async fn drive_query_row_stream(
        &self,
        cx: &Cx,
        mut plan: QueryRowStreamPlan,
        frames: ToolStreamSender,
    ) -> Result<Value, ErrorEnvelope> {
        let mut row_count = 0usize;
        let mut total_bytes = 0usize;
        let mut truncated = false;
        let mut disconnected = false;
        let mut failure: Option<ErrorEnvelope> = None;
        loop {
            if let Err(err) = plan
                .request_budget
                .enforce(cx)
                .map_err(DbError::into_envelope)
            {
                failure = Some(err);
                break;
            }
            let next = plan
                .stream
                .next_row(cx)
                .await
                .map_err(|err| self.stream_db_error_envelope(err));
            let row = match next {
                Ok(Some(row)) => row,
                Ok(None) => break,
                Err(err) => {
                    failure = Some(err);
                    break;
                }
            };
            if row_count >= MAX_QUERY_STREAM_ROWS {
                truncated = true;
                break;
            }
            let row_json = serialize_row(&row, &plan.serialize_opts);
            total_bytes = total_bytes.saturating_add(
                serde_json::to_vec(&row_json)
                    .map(|bytes| bytes.len())
                    .unwrap_or(0),
            );
            let seq = u64::try_from(row_count).unwrap_or(u64::MAX);
            if !send_stream_frame(cx, &frames, ToolStreamFrame::Row { seq, row: row_json }).await {
                disconnected = true;
                break;
            }
            row_count = row_count.saturating_add(1);
        }
        let recover = plan
            .stream
            .recover(cx)
            .await
            .map_err(|err| self.stream_db_error_envelope(err));
        recover?;
        if let Some(err) = failure {
            return Err(err);
        }
        if disconnected {
            return Err(ErrorEnvelope::new(
                ErrorClass::Timeout,
                "stream receiver disconnected before oracle_query row streaming completed",
            ));
        }
        let next_cursor = if truncated {
            Value::String(seal_raw_query_cursor(
                &(plan.start_offset + row_count).to_string(),
                &plan.cursor_sql,
                plan.active_profile.as_deref(),
            ))
        } else {
            Value::Null
        };
        Ok(json!({
            "streaming": true,
            "streaming_mode": "rows",
            "columns": plan.columns,
            "row_count": row_count,
            "total_bytes": total_bytes,
            "truncated": truncated,
            "next_cursor": next_cursor,
        }))
    }

    async fn emit_chunked_stream_frames(
        cx: &Cx,
        response: Value,
        frames: ToolStreamSender,
    ) -> Result<Value, ErrorEnvelope> {
        if let Some(chunks) = response.get("chunks").and_then(Value::as_array) {
            for (idx, chunk) in chunks.iter().enumerate() {
                let seq = chunk
                    .get("seq")
                    .and_then(Value::as_u64)
                    .unwrap_or(idx as u64);
                if !send_stream_frame(
                    cx,
                    &frames,
                    ToolStreamFrame::Chunk {
                        seq,
                        chunk: chunk.clone(),
                    },
                )
                .await
                {
                    return Err(ErrorEnvelope::new(
                        ErrorClass::Timeout,
                        "stream receiver disconnected before oracle_query chunk fallback completed",
                    ));
                }
            }
        }
        Ok(response)
    }

    /// K10: deliver a proven read as an ordered, resumable `chunks` array —
    /// streaming delivery of `oracle_query`. Each chunk is one [`read_query`]
    /// cursor page, so a chunk's rows are BYTE-IDENTICAL to the page a caller
    /// would get by resuming with the previous chunk's `next_cursor`; streaming
    /// changes DELIVERY, never the proven-read bytes, and the classifier is
    /// untouched (the read was already gated in `run_prepared_query`).
    ///
    /// Backpressure / budget: every chunk boundary re-checkpoints `cx`, so the
    /// request deadline + cancellation (the asupersync budget carried on `cx`)
    /// stop the walk between pages — a cancelled or expired stream never keeps
    /// fetching. Bounded by [`MAX_QUERY_STREAM_ROWS`]: at the cap the final chunk
    /// carries a resume cursor and the response is flagged `truncated`.
    ///
    /// Over the HTTP/SSE transport the assembled `chunks` are re-emitted as
    /// individual `event: chunk` SSE frames by the transport layer
    /// (`oraclemcp_core::http`); over stdio/JSON the same `chunks` array is the
    /// inline incremental-delivery contract.
    #[allow(clippy::too_many_arguments)]
    async fn stream_query_response(
        cx: &Cx,
        conn: &dyn OracleConnection,
        executed_sql: &str,
        cursor_sql: &str,
        binds: &[OracleBind],
        caps: QueryCaps,
        start_offset: usize,
        serialize_opts: &SerializeOptions,
        active_profile: Option<&str>,
    ) -> Result<Value, ErrorEnvelope> {
        let page_rows = caps.max_rows.max(1);
        let max_chunks = MAX_QUERY_STREAM_ROWS.div_ceil(page_rows).max(1);
        let mut offset = start_offset;
        let mut chunks: Vec<Value> = Vec::new();
        let mut columns: Vec<String> = Vec::new();
        let mut total_rows = 0usize;
        let mut truncated = false;
        let mut final_cursor = Value::Null;
        for seq in 0..max_chunks {
            // Budget/cancellation checkpoint at every chunk boundary — the
            // backpressure signal for the walk (A9-narrowed cx is sufficient;
            // only the DB round trip inside read_query needs the full row).
            dispatch_checkpoint(cx, "oraclemcp.dispatch.query.stream.chunk")?;
            let page = read_query(cx, conn, executed_sql, binds, caps, offset, serialize_opts)
                .await
                .map_err(DbError::into_envelope)?;
            if seq == 0 {
                columns = page.columns.clone();
            }
            let more = page.truncated;
            let reached_cap = seq + 1 >= max_chunks;
            let last = !more || reached_cap;
            total_rows += page.row_count;
            // Re-seal the raw next offset as the tamper-evident cursor a
            // paginated caller would receive (E2); present only when more rows
            // remain. On the final chunk this doubles as the resume cursor.
            let sealed_next = page
                .next_cursor
                .as_deref()
                .map(|raw| Value::String(seal_raw_query_cursor(raw, cursor_sql, active_profile)))
                .unwrap_or(Value::Null);
            let next_offset = offset + page.row_count;
            chunks.push(json!({
                "seq": seq,
                "rows": page.rows,
                "row_count": page.row_count,
                "total_bytes": page.total_bytes,
                "next_cursor": sealed_next.clone(),
                "last": last,
            }));
            if last {
                truncated = more;
                final_cursor = sealed_next;
                break;
            }
            offset = next_offset;
        }
        let chunk_count = chunks.len();
        Ok(json!({
            "streaming": true,
            "columns": columns,
            "chunks": chunks,
            "chunk_count": chunk_count,
            "row_count": total_rows,
            "truncated": truncated,
            "next_cursor": final_cursor,
        }))
    }
}

#[cfg(test)]
mod tests;
