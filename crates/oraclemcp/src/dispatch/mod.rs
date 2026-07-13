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

use asupersync::combinator::try_commit_section;
use asupersync::sync::Mutex as AsyncMutex;
use asupersync::{Budget, CancelReason, Cx, Outcome, Time};
use oraclemcp_audit::{
    AuditCancel, AuditDecision, AuditEntryDraft, AuditOutcome, AuditResultMaskingAction,
    AuditResultMaskingCertificate, AuditResultMaskingColumnDecision, AuditResultMaskingSource,
    AuditSubject, Auditor, DbEvidence,
};
use oraclemcp_auth::apply_oauth_scopes;
use oraclemcp_config::{
    ConfigReloadPlan, ConnectionProfile, OracleMcpConfig, ProfileMetadata, ReloadProfileAction,
    ReloadProfileReason,
};
use oraclemcp_core::{
    CLEANUP_POLL_QUOTA, ConnectionStatus, CustomToolCatalog, CustomToolExecutor,
    DEFAULT_REQUEST_TIMEOUT, DispatchCloseFuture, DispatchCloseReason, DispatchContext,
    DispatchFuture, McpSurfaceDetail, McpSurfaceFuture, McpSurfaceState, McpToolCatalogSnapshot,
    RequestBudget, ToolBody, ToolDispatch, ToolRegistry, ToolStreamFrame, ToolStreamSender,
    WriteIntent, WriteIntentDetails, WriteIntentError, WriteIntentLog, WriteIntentOutcome,
    execute_custom_tool, narrow_to_read_path, sign_token, verify_token,
};
use oraclemcp_db::SearchDetailLevel;
use oraclemcp_db::{
    AsOf, CatalogInvalidation, DbError, DbRequestQuota, DbmsOutput, DependentObject,
    DependentsProbe, IncomparableMaskedColumn, MaskComparabilityBreak, OracleBackend, OracleBind,
    OracleCatalogResolverCache, OracleCell, OracleConnection, OracleConnectionInfo, OracleRow,
    OrientForeignKey, OrientHotObject, OrientRecentDdlObject, OrientSchemaObject, PlanCostEstimate,
    QuarantineOutcome, QueryCaps, QueryDiffSource, QueryResponse, QueryRowStream,
    QueryRowStreamStart, ResultColumnMatch, ResultMaskingAction, ResultMaskingCertificate,
    ResultMaskingDecisionAction, ResultMaskingDecisionSource, ResultMaskingPolicy,
    ResultMaskingRule, SearchObject, SerializeOptions, StructuredDecodeCaps, compile_errors,
    compile_object_statements, describe_columns, describe_constraints, describe_index,
    describe_trigger, describe_view, diff_query_responses, execute_immediate_audit, explain_plan,
    find_unused_declarations, get_ddl, get_source, get_sources_by_name,
    incomparable_masked_columns, list_objects, list_schemas, orient_fks, orient_hot_objects,
    orient_recent_ddl, orient_schema, paginated_sql, plan_cost_estimate, plscope_identifiers,
    plscope_statements, primary_key_columns, probe_dependents, read_lob, read_query,
    read_query_as_of, read_query_named, resolved_relations_read_purity, sample_rows,
    search_objects, search_source, serialize_row,
};
use oraclemcp_error::{
    ErrorClass, ErrorEnvelope, OptimizerPlanRow, QueryCostRefusal, ReasonCategory, StructuredReason,
};
use oraclemcp_guard::{
    CatalogObjectKind, CatalogResolver, Classifier, ClassifierConfig, DangerLevel, EscalationError,
    ExecGrantBinding, ExecGrantError, ExecGrantStore, GuardDecision, LevelDecision, ObjectRef,
    OperatingLevel, Purity, Resolution, ResolvedObject, SessionLevelState, SideEffectOracle,
    semantic_read_plan,
};
use serde::{Deserialize, Serialize};
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
/// Audit description for the synthetic, merged rows emitted by the fleet
/// catalog. The underlying dictionary reads remain parameterized `ALL_*`
/// reads in `search_objects`; this label binds the egress certificate to the
/// aggregate surface without recording caller filters as faux SQL.
const FLEET_CATALOG_AUDIT_SQL: &str = "GENERATED FLEET CATALOG SEARCH";
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
/// Each orient snapshot is four bounded dictionary reads; cap retained profiles,
/// catalog revisions, and owner scopes so an agent cannot turn selector caching
/// into an unbounded in-process store.
const MAX_ORIENT_SNAPSHOT_CACHE_ENTRIES: usize = 32;
/// Each component of an orient snapshot is independently bounded in the DB
/// layer. This fixed tool-level cap makes a cache entry stable across callers.
const ORIENT_SNAPSHOT_MAX_ROWS: usize = 500;
/// Hard cap on per-call Oracle round-trip timeout overrides.
const MAX_CALL_TIMEOUT_SECONDS: u64 = 3_600;

/// Reconnect callback used by `oracle_switch_profile`. Async + `Cx`-first (B1):
/// opening a connection is a native-async DB round trip, so the connector
/// returns a boxed future awaited on the dispatch runtime.
pub type ProfileConnector = dyn for<'a> Fn(
        &'a Cx,
        &'a ProfileGenerationLease,
    ) -> Pin<Box<dyn Future<Output = Result<ProfileConnectionBundle, DbError>> + 'a>>
    + Sync
    + Send
    + 'static;

/// Primary and stateless connections opened from one resolved profile value.
pub struct ProfileConnectionBundle {
    session: Box<dyn OracleConnection>,
    stateless: Option<Box<dyn OracleConnection>>,
}

impl ProfileConnectionBundle {
    /// Build a connection bundle whose members share one resolved credential,
    /// target, pool, and session-option snapshot.
    #[must_use]
    pub fn new(
        session: Box<dyn OracleConnection>,
        stateless: Option<Box<dyn OracleConnection>>,
    ) -> Self {
        Self { session, stateless }
    }

    fn into_parts(self) -> (Box<dyn OracleConnection>, Option<Box<dyn OracleConnection>>) {
        (self.session, self.stateless)
    }
}

/// Profile-scoped custom-tool loader used by `oracle_switch_profile`.
pub type CustomToolLoader = dyn Fn(&ProfileGenerationLease, &SessionLevelState) -> Result<CustomToolCatalog, ErrorEnvelope>
    + Send
    + Sync
    + 'static;

/// Initial connection and profile-switch connector for the optional stateless
/// metadata-read pool.
pub struct StatelessReadStrategy {
    conn: Option<Box<dyn OracleConnection>>,
}

impl StatelessReadStrategy {
    /// Disable the stateless metadata-read path.
    #[must_use]
    pub fn none() -> Self {
        Self { conn: None }
    }

    /// Configure the initial stateless connection. Profile switches receive a
    /// complete primary/stateless bundle from [`ProfileConnector`].
    #[must_use]
    pub fn new(conn: Option<Box<dyn OracleConnection>>) -> Self {
        Self { conn }
    }
}

fn default_read_only_level() -> SessionLevelState {
    SessionLevelState::new(OperatingLevel::ReadOnly, false)
}

#[derive(Clone)]
struct ProfileDispatchPolicy {
    level: SessionLevelState,
    request_timeout: Option<Duration>,
    max_query_cost: Option<u64>,
    result_masking: Option<ResultMaskingPolicy>,
}

struct PreparedProfileSwitch {
    profile: String,
    profile_generation: ProfileGenerationLease,
    conn: Box<dyn OracleConnection>,
    stateless_conn: Option<Box<dyn OracleConnection>>,
    level: SessionLevelState,
    request_timeout: Option<Duration>,
    max_query_cost: Option<u64>,
    result_masking: Option<ResultMaskingPolicy>,
    custom_catalog: CustomToolCatalog,
    response: Value,
}

fn profile_request_timeout(call_timeout_seconds: Option<u64>) -> Option<Duration> {
    match call_timeout_seconds {
        None => Some(DEFAULT_REQUEST_TIMEOUT),
        Some(0) => None,
        Some(seconds) => Some(Duration::from_secs(seconds)),
    }
}

fn standalone_read_only_policy() -> ProfileDispatchPolicy {
    ProfileDispatchPolicy {
        level: default_read_only_level(),
        request_timeout: Some(DEFAULT_REQUEST_TIMEOUT),
        max_query_cost: None,
        result_masking: None,
    }
}

/// Convert the validated profile config DTO into the DB-layer result masking
/// transformer. Tokenization salt material is resolved by the later salt-store
/// seam; until then tokenize rules degrade fail-closed to `mask` in
/// `oraclemcp-db`.
#[must_use]
pub fn result_masking_policy_from_profile(
    profile: &ConnectionProfile,
) -> Option<ResultMaskingPolicy> {
    let masking = profile.masking.as_ref()?;
    let rules = masking
        .rules
        .iter()
        .map(|rule| {
            let mut column_match = ResultColumnMatch {
                schema: rule.column_match.schema.clone(),
                table: rule.column_match.table.clone(),
                column: rule.column_match.column.clone(),
                tag: rule.column_match.tag.clone(),
            };
            if let Some(schema) = column_match.schema.as_mut() {
                *schema = schema.trim().to_owned();
            }
            if let Some(table) = column_match.table.as_mut() {
                *table = table.trim().to_owned();
            }
            if let Some(column) = column_match.column.as_mut() {
                *column = column.trim().to_owned();
            }
            if let Some(tag) = column_match.tag.as_mut() {
                *tag = tag.trim().to_owned();
            }
            ResultMaskingRule {
                column_match,
                action: match rule.action {
                    oraclemcp_config::ResultMaskingActionConfig::Mask => ResultMaskingAction::Mask,
                    oraclemcp_config::ResultMaskingActionConfig::Tokenize => {
                        ResultMaskingAction::Tokenize
                    }
                    oraclemcp_config::ResultMaskingActionConfig::Null => ResultMaskingAction::Null,
                },
                tag: rule.tag.as_ref().map(|tag| tag.trim().to_owned()),
            }
        })
        .collect();
    Some(ResultMaskingPolicy::new(rules, masking.mask_unknown_default).with_profile(&profile.name))
}

fn profile_dispatch_policy(
    lease: &ProfileGenerationLease,
) -> Result<ProfileDispatchPolicy, ErrorEnvelope> {
    let Some(profile) = lease
        .config()
        .and_then(|config| config.profile(lease.profile()))
    else {
        if !lease.snapshot_required {
            // The public standalone dispatcher constructors are intentionally
            // config-free: their caller supplies the connector and they pin
            // every switched profile to a conservative immutable READ_ONLY
            // policy. The served binary always installs `from_config`, where
            // a missing profile is a fail-closed generation mismatch.
            return Ok(standalone_read_only_policy());
        }
        return Err(ErrorEnvelope::new(
            ErrorClass::RuntimeStateRequired,
            format!(
                "accepted config snapshot has no profile `{}` for generation {}",
                lease.profile(),
                lease.generation()
            ),
        ));
    };
    Ok(ProfileDispatchPolicy {
        level: oraclemcp_core::session_level_state(profile, false),
        request_timeout: profile_request_timeout(profile.call_timeout_seconds),
        max_query_cost: profile.max_query_cost,
        result_masking: result_masking_policy_from_profile(profile),
    })
}

#[derive(Clone, Debug)]
struct ActiveCustomCatalog {
    generation: u64,
    catalog: Arc<CustomToolCatalog>,
    descriptors: Arc<[oraclemcp_core::ToolDescriptor]>,
}

impl ActiveCustomCatalog {
    fn new(generation: u64, catalog: CustomToolCatalog) -> Self {
        let mut registry = ToolRegistry::new();
        catalog.register_first_class(&mut registry);
        Self {
            generation,
            catalog: Arc::new(catalog),
            descriptors: registry.tools.into(),
        }
    }

    fn snapshot(&self) -> McpToolCatalogSnapshot {
        McpToolCatalogSnapshot {
            generation: self.generation,
            tools: Arc::clone(&self.descriptors),
        }
    }
}

struct DispatcherState {
    conn: Box<dyn OracleConnection>,
    stateless_conn: Option<Box<dyn OracleConnection>>,
    active_profile: Option<String>,
    profile_generation: Option<ProfileGenerationLease>,
    level: SessionLevelState,
    custom_catalog: ActiveCustomCatalog,
    execute_grants: ExecGrantStore,
    grant_generation: u64,
    execute_approved_tokens: HashMap<String, ExecuteApprovedGrant>,
    patch_previews: HashMap<String, PatchPreviewEntry>,
    /// Generation-scoped dictionary evidence for this lane/profile sequence.
    /// Profile switches advance rather than replace it, so an old context can
    /// never become current again after reconnecting to another session.
    catalog_cache: OracleCatalogResolverCache,
    /// C2: complete orient snapshots partitioned by the profile, catalog
    /// generation, and normalized requested owner. The generation is advanced
    /// before every uncertain DDL/session-context mutation, so stale snapshots
    /// are never reused as current catalog evidence.
    orient_snapshots: SyncMutex<HashMap<OrientSnapshotCacheKey, OrientSnapshot>>,
    /// A1: fresh-per-request read-only transaction backstop for the
    /// pinned/primary session.
    /// Scoped to `conn` only (the stateless metadata pool relies on the
    /// least-privilege DB user, A2). Each READ_ONLY request starts a fresh,
    /// engine-enforced transaction; it is disarmed by a gated write and reset
    /// on a profile switch.
    read_only_backstop: ReadOnlyBackstop,
    /// Arc I: the pinned session's reversible workspace — the live
    /// `SAVEPOINT` stack behind `oracle_checkpoint` / `oracle_undo_to`, and the
    /// held-work count that makes every committing operation refuse while it is
    /// open. Cleared at every transaction boundary the dispatcher issues.
    checkpoints: CheckpointWorkspace,
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

/// The cache identity for one C2 orientation snapshot.
///
/// `catalog_revision` is the resolver cache's monotonic generation. It advances
/// before DDL, session context changes, and reconnects, so it is impossible to
/// retrieve a snapshot from an older catalog as though it were current.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct OrientSnapshotCacheKey {
    profile: Option<String>,
    catalog_revision: u64,
    owner: Option<String>,
}

/// The complete internal orientation snapshot. Selectors project this single
/// value after it is cached; they never create independently stale fragments.
#[derive(Clone, Debug)]
struct OrientSnapshot {
    owner: Option<String>,
    catalog_revision: u64,
    schema: Vec<OrientSchemaObject>,
    fks: Vec<OrientForeignKey>,
    hot_objects: Vec<OrientHotObject>,
    freshness: OrientFreshness,
    recent_ddl: Vec<OrientRecentDdlObject>,
}

/// One profile's result while assembling a federated orientation snapshot.
///
/// This deliberately keeps successful evidence separate from terminal lane
/// status until every agent-visible profile has been attempted. A fleet call
/// must never turn one unavailable database into either a whole-call failure
/// or an absent profile that looks like a clean result.
#[derive(Clone, Debug)]
struct FleetOrientEvidence {
    connection: OracleConnectionInfo,
    snapshot: OrientSnapshot,
}

/// Terminal result for one profile while assembling fleet orientation.
#[derive(Clone, Debug)]
enum FleetOrientLane {
    Reachable {
        profile: String,
        evidence: Box<FleetOrientEvidence>,
    },
    Unreachable {
        profile: String,
    },
    FailClosed {
        profile: String,
        reason: &'static str,
    },
}

/// One profile's egress-filtered contribution to the merged fleet object
/// index. This is intentionally not a lane-status enum: a catalog response
/// must not expose a roster, a reachable-count, or a missing-profile signal.
/// The caller sees only object rows it is authorized to receive.
#[derive(Clone, Debug)]
struct FleetCatalogProfileResult {
    profile: String,
    results: Vec<Value>,
    mask_certificate: Option<ResultMaskingCertificate>,
    truncated: bool,
}

/// Inputs for one source-profile read while building the egress-safe catalog.
/// Keeping this request together makes it harder to accidentally use an active
/// session's filter, budget, or subject for a transient fleet connection.
struct FleetCatalogRequest<'a> {
    profile: String,
    owner: Option<&'a str>,
    object_type: Option<&'a str>,
    name_like: Option<&'a str>,
    max_rows: usize,
    request_budget: &'a RequestBudget,
    subject: &'a AuditSubject,
}

/// Deterministic freshness summary derived from the bounded dictionary reads.
#[derive(Clone, Debug, Serialize)]
struct OrientFreshness {
    catalog_revision: u64,
    latest_dml_time: Option<String>,
    latest_ddl_time: Option<String>,
    hot_object_count: usize,
}

/// C2 output selector. The default is intentionally the complete snapshot.
#[derive(Clone, Copy, Debug)]
struct OrientInclude {
    schema: bool,
    fks: bool,
    hot: bool,
    freshness: bool,
    ddl: bool,
}

impl OrientInclude {
    const fn all() -> Self {
        Self {
            schema: true,
            fks: true,
            hot: true,
            freshness: true,
            ddl: true,
        }
    }

    fn parse(include: &[String]) -> Result<Self, ErrorEnvelope> {
        if include.is_empty() {
            return Ok(Self::all());
        }
        let mut selected = Self {
            schema: false,
            fks: false,
            hot: false,
            freshness: false,
            ddl: false,
        };
        for section in include {
            match section.to_ascii_lowercase().as_str() {
                "schema" => selected.schema = true,
                "fks" => selected.fks = true,
                "hot" => selected.hot = true,
                "freshness" => selected.freshness = true,
                "ddl" => selected.ddl = true,
                _ => {
                    return Err(invalid_args(
                        "include entries must be one of: schema, fks, hot, freshness, ddl",
                    ));
                }
            }
        }
        Ok(selected)
    }
}

fn orient_owner_arg(owner: Option<String>) -> Result<Option<String>, ErrorEnvelope> {
    match non_empty_arg(owner).as_deref() {
        None | Some("*") => Ok(None),
        Some(owner) => Ok(Some(owner.to_ascii_uppercase())),
    }
}

async fn load_orient_snapshot(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    catalog_revision: u64,
) -> Result<OrientSnapshot, DbError> {
    let schema = orient_schema(cx, conn, owner, ORIENT_SNAPSHOT_MAX_ROWS).await?;
    let fks = orient_fks(cx, conn, owner, ORIENT_SNAPSHOT_MAX_ROWS).await?;
    let hot_objects = orient_hot_objects(cx, conn, owner, ORIENT_SNAPSHOT_MAX_ROWS).await?;
    let recent_ddl = orient_recent_ddl(cx, conn, owner, ORIENT_SNAPSHOT_MAX_ROWS).await?;
    let freshness = OrientFreshness {
        catalog_revision,
        latest_dml_time: hot_objects
            .iter()
            .filter_map(|object| object.last_modified.clone())
            .max(),
        latest_ddl_time: recent_ddl
            .iter()
            .filter_map(|object| object.last_ddl_time.clone())
            .max(),
        hot_object_count: hot_objects.len(),
    };
    Ok(OrientSnapshot {
        owner: owner.map(str::to_owned),
        catalog_revision,
        schema,
        fks,
        hot_objects,
        freshness,
        recent_ddl,
    })
}

fn orient_snapshot_response(snapshot: &OrientSnapshot, include: &OrientInclude) -> Value {
    let mut response = serde_json::Map::from_iter([
        (
            "owner".to_owned(),
            json!(snapshot.owner.as_deref().unwrap_or("*")),
        ),
        (
            "catalog_revision".to_owned(),
            json!(snapshot.catalog_revision),
        ),
    ]);
    if include.schema {
        response.insert("schema".to_owned(), json!(&snapshot.schema));
    }
    if include.fks {
        response.insert("fks".to_owned(), json!(&snapshot.fks));
    }
    if include.hot {
        response.insert("hot_objects".to_owned(), json!(&snapshot.hot_objects));
    }
    if include.freshness {
        response.insert("freshness".to_owned(), json!(&snapshot.freshness));
    }
    if include.ddl {
        response.insert("recent_ddl".to_owned(), json!(&snapshot.recent_ddl));
    }
    Value::Object(response)
}

fn fleet_orient_component_matches<T: Serialize>(left: &T, right: &T) -> bool {
    serde_json::to_value(left).ok() == serde_json::to_value(right).ok()
}

fn fleet_orient_drift(
    profile: &str,
    snapshot: &OrientSnapshot,
    connection: &OracleConnectionInfo,
    baseline: Option<(&str, &OrientSnapshot, &OracleConnectionInfo)>,
) -> Value {
    let Some((baseline_profile, baseline_snapshot, baseline_connection)) = baseline else {
        return json!({
            "baseline_profile": profile,
            "schema_changed": false,
            "foreign_keys_changed": false,
            "freshness_changed": false,
            "recent_ddl_changed": false,
            "server_version_changed": false,
        });
    };

    json!({
        "baseline_profile": baseline_profile,
        "schema_changed": !fleet_orient_component_matches(&snapshot.schema, &baseline_snapshot.schema),
        "foreign_keys_changed": !fleet_orient_component_matches(&snapshot.fks, &baseline_snapshot.fks),
        "freshness_changed": !fleet_orient_component_matches(&snapshot.freshness, &baseline_snapshot.freshness),
        "recent_ddl_changed": !fleet_orient_component_matches(&snapshot.recent_ddl, &baseline_snapshot.recent_ddl),
        "server_version_changed": connection.server_version != baseline_connection.server_version,
    })
}

fn fleet_orient_response(lanes: Vec<FleetOrientLane>, include: &OrientInclude) -> Value {
    let total_profiles = lanes.len();
    let mut reachable = 0_usize;
    let mut unreachable = 0_usize;
    let mut fail_closed = 0_usize;
    let mut baseline: Option<(String, OrientSnapshot, OracleConnectionInfo)> = None;
    let mut profiles = Vec::with_capacity(total_profiles);

    for lane in lanes {
        match lane {
            FleetOrientLane::Reachable { profile, evidence } => {
                let FleetOrientEvidence {
                    connection,
                    snapshot,
                } = *evidence;
                let drift = fleet_orient_drift(
                    &profile,
                    &snapshot,
                    &connection,
                    baseline
                        .as_ref()
                        .map(|(name, snapshot, connection)| (name.as_str(), snapshot, connection)),
                );
                if baseline.is_none() {
                    baseline = Some((profile.clone(), snapshot.clone(), connection.clone()));
                }
                reachable = reachable.saturating_add(1);
                profiles.push(json!({
                    "profile": profile,
                    "status": "REACHABLE",
                    "connection": connection.redacted(),
                    "orient": orient_snapshot_response(&snapshot, include),
                    "drift": drift,
                }));
            }
            FleetOrientLane::Unreachable { profile } => {
                unreachable = unreachable.saturating_add(1);
                profiles.push(json!({
                    "profile": profile,
                    "status": "UNREACHABLE",
                    "error": {
                        "code": "UNREACHABLE",
                        "message": "profile connection or orientation metadata is unavailable",
                    },
                }));
            }
            FleetOrientLane::FailClosed { profile, reason } => {
                fail_closed = fail_closed.saturating_add(1);
                profiles.push(json!({
                    "profile": profile,
                    "status": "FAIL_CLOSED",
                    "error": {
                        "code": "FAIL_CLOSED",
                        "message": reason,
                    },
                }));
            }
        }
    }

    json!({
        "profiles": profiles,
        "summary": {
            "profile_count": total_profiles,
            "reachable_count": reachable,
            "unreachable_count": unreachable,
            "fail_closed_count": fail_closed,
        },
    })
}

/// Build the fixed, names-only dictionary result shape that crosses the fleet
/// aggregation boundary. Applying Arc M here (rather than after the JSON has
/// been merged) keeps every source row under the policy of the profile that
/// produced it.
fn fleet_catalog_source_row(object: &SearchObject) -> OracleRow {
    OracleRow {
        columns: vec![
            (
                "OWNER".to_owned(),
                OracleCell::new("VARCHAR2", Some(object.owner.clone())),
            ),
            (
                "OBJECT_NAME".to_owned(),
                OracleCell::new("VARCHAR2", Some(object.object_name.clone())),
            ),
            (
                "OBJECT_TYPE".to_owned(),
                OracleCell::new("VARCHAR2", Some(object.object_type.clone())),
            ),
            (
                "STATUS".to_owned(),
                OracleCell::new("VARCHAR2", object.status.clone()),
            ),
        ],
    }
}

fn fleet_catalog_result_row(
    profile: &str,
    object: &SearchObject,
    result_masking: Option<&ResultMaskingPolicy>,
) -> Value {
    let row = fleet_catalog_source_row(object);
    let serialized = serialize_row(
        &row,
        &SerializeOptions {
            result_masking: result_masking.cloned(),
            ..Default::default()
        },
    );
    json!({
        "profile": profile,
        "owner": serialized["OWNER"].clone(),
        "object_name": serialized["OBJECT_NAME"].clone(),
        "object_type": serialized["OBJECT_TYPE"].clone(),
        "status": serialized["STATUS"].clone(),
    })
}

fn fleet_catalog_response(
    lanes: Vec<FleetCatalogProfileResult>,
    owner: Option<&str>,
    object_type: Option<&str>,
    name_like: Option<&str>,
    max_rows: usize,
) -> Value {
    let mut results = Vec::new();
    let mut mask_certificates = Vec::new();
    let mut truncated = false;
    for lane in lanes {
        truncated |= lane.truncated;
        if !lane.results.is_empty() {
            if let Some(certificate) = lane.mask_certificate {
                mask_certificates.push(json!({
                    "profile": lane.profile,
                    "certificate": certificate,
                }));
            }
            results.extend(lane.results);
        }
    }

    json!({
        "fleet": true,
        "owner": owner.unwrap_or("*"),
        "object_type": object_type,
        "name_like": name_like,
        "detail_level": "names",
        "count": results.len(),
        "results": results,
        "mask_certificates": mask_certificates,
        "max_rows": max_rows,
        "truncated": truncated,
    })
}

/// The dispatcher: owns the live connection behind an Asupersync [`AsyncMutex`]
/// so the now-async dispatch can hold the guard across a native-async DB round
/// trip (cancellation-safe; a `std::sync::Mutex` would be a deadlock/cancel
/// hazard across `.await`). The connection is still single-owner per dispatch
/// and never shared across threads without serialization.
pub struct OracleDispatcher {
    state: AsyncMutex<DispatcherState>,
    request_timeout: SyncMutex<Option<Duration>>,
    max_query_cost: SyncMutex<Option<u64>>,
    result_masking: SyncMutex<Option<ResultMaskingPolicy>>,
    quarantine: SyncMutex<Option<ConnectionQuarantine>>,
    connector: Option<Arc<ProfileConnector>>,
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
    /// the served binary installs a startup snapshot and [`ProfileDrainState`]
    /// overlays exposure transitions from every accepted live reload.
    mcp_exposure: McpExposurePolicy,
    /// S5 config reload/drain gate: profiles marked draining are omitted from
    /// runtime discovery, cannot be switched into, and cannot keep accepting
    /// non-diagnostic work on already-active lanes.
    profile_drain: ProfileDrainState,
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
        let profile_drain = ProfileDrainState::default();
        let profile_generation = active_profile
            .as_deref()
            .and_then(|profile| profile_drain.bind_existing_profile(profile));
        OracleDispatcher {
            state: AsyncMutex::new(DispatcherState {
                conn,
                stateless_conn: None,
                active_profile,
                profile_generation,
                level,
                custom_catalog: ActiveCustomCatalog::new(1, CustomToolCatalog::default()),
                execute_grants: ExecGrantStore::new(),
                grant_generation: 1,
                execute_approved_tokens: HashMap::new(),
                patch_previews: HashMap::new(),
                catalog_cache: OracleCatalogResolverCache::new(),
                orient_snapshots: SyncMutex::new(HashMap::new()),
                read_only_backstop: ReadOnlyBackstop::new(),
                checkpoints: CheckpointWorkspace::new(),
            }),
            request_timeout: SyncMutex::new(Some(DEFAULT_REQUEST_TIMEOUT)),
            max_query_cost: SyncMutex::new(None),
            result_masking: SyncMutex::new(None),
            quarantine: SyncMutex::new(None),
            connector: None,
            custom_loader: None,
            auditor: None,
            default_audit_subject: process_audit_subject(),
            exports: None,
            mcp_exposure: McpExposurePolicy::default(),
            profile_drain,
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
        let profile_drain = ProfileDrainState::default();
        let profile_generation = active_profile
            .as_deref()
            .and_then(|profile| profile_drain.bind_existing_profile(profile));
        OracleDispatcher {
            state: AsyncMutex::new(DispatcherState {
                conn,
                stateless_conn: stateless.conn,
                active_profile,
                profile_generation,
                level,
                custom_catalog: ActiveCustomCatalog::new(1, custom_catalog),
                execute_grants: ExecGrantStore::new(),
                grant_generation: 1,
                execute_approved_tokens: HashMap::new(),
                patch_previews: HashMap::new(),
                catalog_cache: OracleCatalogResolverCache::new(),
                orient_snapshots: SyncMutex::new(HashMap::new()),
                read_only_backstop: ReadOnlyBackstop::new(),
                checkpoints: CheckpointWorkspace::new(),
            }),
            request_timeout: SyncMutex::new(Some(DEFAULT_REQUEST_TIMEOUT)),
            max_query_cost: SyncMutex::new(None),
            result_masking: SyncMutex::new(None),
            quarantine: SyncMutex::new(None),
            connector: Some(connector),
            custom_loader,
            auditor: None,
            default_audit_subject: process_audit_subject(),
            exports: None,
            mcp_exposure: McpExposurePolicy::default(),
            profile_drain,
            write_intents: None,
        }
    }

    /// Install the E5 connection-scope isolation policy (builder). The served
    /// binary calls this with the startup `mcp_exposed` snapshot. The shared
    /// reload state overlays later exposure changes so a hidden profile stays
    /// non-switchable, non-listable, non-searchable, and non-completable.
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
        if let Ok(dispatcher_state) = self.state.get_mut() {
            dispatcher_state.profile_generation = dispatcher_state
                .active_profile
                .as_deref()
                .and_then(|profile| state.bind_existing_profile(profile));
            self.profile_drain = state;
        }
        self
    }

    /// Install the shared reload state together with the generation reservation
    /// captured before an asynchronous connection open. This prevents a lane
    /// from binding a connection prepared from generation N to generation N+1.
    #[must_use = "a stale generation bind error must be handled"]
    pub fn with_profile_generation_lease(
        mut self,
        state: ProfileDrainState,
        lease: ProfileGenerationLease,
    ) -> Result<Self, ErrorEnvelope> {
        let profile = lease.profile().to_owned();
        let generation = lease.generation();
        if !lease.belongs_to(&state) {
            return Err(profile_draining_error(&profile));
        }
        let dispatcher_state = self.state.get_mut().map_err(|_| {
            ErrorEnvelope::new(ErrorClass::Internal, "connection mutex lock failed")
        })?;
        if dispatcher_state.active_profile.as_deref() != Some(profile.as_str()) {
            return Err(profile_draining_error(&profile));
        }

        // Discard the standalone constructor's placeholder lease before
        // entering the shared generation lock. The accepted lease itself stays
        // outside the closure until the commit succeeds, so an error cannot run
        // its Drop implementation while the same lifecycle mutex is held.
        dispatcher_state.profile_generation.take();
        let mut pending = Some(lease);
        state
            .commit_generation(&profile, generation, || {
                dispatcher_state.profile_generation = pending.take();
            })
            .map_err(|()| profile_draining_error(&profile))?;
        self.profile_drain = state;
        Ok(self)
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

    /// Install the active profile's resolved `oracle_query` cost ceiling.
    #[must_use]
    pub fn with_max_query_cost(self, max_query_cost: Option<u64>) -> Self {
        self.set_max_query_cost(max_query_cost)
            .expect("max-query-cost mutex is healthy during construction");
        self
    }

    /// Install the active profile's result masking policy.
    #[must_use]
    pub fn with_result_masking_policy(self, result_masking: Option<ResultMaskingPolicy>) -> Self {
        self.set_result_masking_policy(result_masking)
            .expect("result-masking mutex is healthy during construction");
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

    fn max_query_cost(&self) -> Result<Option<u64>, ErrorEnvelope> {
        self.max_query_cost
            .lock()
            .map(|guard| *guard)
            .map_err(|err| {
                ErrorEnvelope::new(
                    ErrorClass::Internal,
                    format!("max-query-cost mutex lock failed: {err}"),
                )
            })
    }

    fn set_max_query_cost(&self, max_query_cost: Option<u64>) -> Result<(), ErrorEnvelope> {
        let mut guard = self.max_query_cost.lock().map_err(|err| {
            ErrorEnvelope::new(
                ErrorClass::Internal,
                format!("max-query-cost mutex lock failed: {err}"),
            )
        })?;
        *guard = max_query_cost;
        Ok(())
    }

    fn result_masking_policy(&self) -> Result<Option<ResultMaskingPolicy>, ErrorEnvelope> {
        self.result_masking
            .lock()
            .map(|guard| guard.clone())
            .map_err(|err| {
                ErrorEnvelope::new(
                    ErrorClass::Internal,
                    format!("result-masking mutex lock failed: {err}"),
                )
            })
    }

    fn set_result_masking_policy(
        &self,
        result_masking: Option<ResultMaskingPolicy>,
    ) -> Result<(), ErrorEnvelope> {
        let mut guard = self.result_masking.lock().map_err(|err| {
            ErrorEnvelope::new(
                ErrorClass::Internal,
                format!("result-masking mutex lock failed: {err}"),
            )
        })?;
        *guard = result_masking;
        Ok(())
    }

    /// Read one C2 orientation snapshot from an MCP-visible profile without
    /// installing that profile into the caller's session lane.
    ///
    /// Fleet orientation adds only independent reach. It repeats the profile
    /// admission and per-connection limit installation used by profile switches
    /// and cross-database diff, while preserving the caller's pinned session,
    /// transaction, catalog cache, and quarantine state. Every failure stays
    /// attached to this one profile in the returned lane status.
    async fn read_orient_lane_from_profile(
        &self,
        cx: &Cx,
        profile: String,
        owner: Option<&str>,
        request_budget: &RequestBudget,
    ) -> FleetOrientLane {
        let lease = match self
            .profile_drain
            .admit_mcp_profile(&profile, self.mcp_exposure.is_exposed(&profile))
        {
            ProfileGenerationAdmission::Ready(lease) => lease,
            ProfileGenerationAdmission::NotExposed => {
                return FleetOrientLane::FailClosed {
                    profile,
                    reason: "profile is no longer exposed to this MCP caller",
                };
            }
            ProfileGenerationAdmission::Draining => {
                return FleetOrientLane::FailClosed {
                    profile,
                    reason: "profile is draining and cannot accept a fleet read",
                };
            }
        };
        let Some(connector) = &self.connector else {
            return FleetOrientLane::FailClosed {
                profile,
                reason: "fleet orientation is unavailable in this server instance",
            };
        };
        let policy = match profile_dispatch_policy(&lease) {
            Ok(policy) => policy,
            Err(_) => {
                return FleetOrientLane::FailClosed {
                    profile,
                    reason: "accepted profile policy is unavailable",
                };
            }
        };
        let (conn, _stateless) = match connector(cx, &lease).await {
            Ok(bundle) => bundle.into_parts(),
            Err(_) => return FleetOrientLane::Unreachable { profile },
        };
        let limits = match ConnectionLimitGuard::install(
            cx,
            conn.as_ref(),
            None,
            policy.request_timeout,
            request_budget.deadline(),
            Some(request_budget.db_quota()),
        ) {
            Ok(limits) => limits,
            Err(_) => return FleetOrientLane::Unreachable { profile },
        };

        let orient = async {
            let observed = ReadUncertaintyConn {
                inner: conn.as_ref(),
                quarantine: None,
            };
            let connection = describe_conn(cx, &observed).await?;
            let catalog_revision = OracleCatalogResolverCache::new().generation().0;
            let snapshot = load_orient_snapshot(cx, &observed, owner, catalog_revision).await?;
            Ok::<_, DbError>((connection, snapshot))
        }
        .await;
        let restore = limits.restore();

        match (orient, restore) {
            (Ok((connection, snapshot)), Ok(())) => FleetOrientLane::Reachable {
                profile,
                evidence: Box::new(FleetOrientEvidence {
                    connection,
                    snapshot,
                }),
            },
            _ => FleetOrientLane::Unreachable { profile },
        }
    }

    /// Search one profile's names-only catalog contribution without installing
    /// it into the caller's session lane.
    ///
    /// This is intentionally stricter than fleet orientation: profiles that
    /// cannot be admitted, connected, or audit-bound are absent from the
    /// *merged index*. Exposing a lane roster or a per-profile object count
    /// would let a caller distinguish a forbidden profile from an absent one.
    /// The profile is admitted before its connector is touched, and its own Arc
    /// M policy serializes the source row before any fleet aggregation occurs.
    async fn read_fleet_catalog_profile(
        &self,
        cx: &Cx,
        request: FleetCatalogRequest<'_>,
    ) -> Option<FleetCatalogProfileResult> {
        let FleetCatalogRequest {
            profile,
            owner,
            object_type,
            name_like,
            max_rows,
            request_budget,
            subject,
        } = request;
        let lease = match self
            .profile_drain
            .admit_mcp_profile(&profile, self.mcp_exposure.is_exposed(&profile))
        {
            ProfileGenerationAdmission::Ready(lease) => lease,
            ProfileGenerationAdmission::NotExposed | ProfileGenerationAdmission::Draining => {
                return None;
            }
        };
        let connector = self.connector.as_ref()?;
        let policy = profile_dispatch_policy(&lease).ok()?;
        let (conn, _stateless) = connector(cx, &lease).await.ok()?.into_parts();
        let limits = ConnectionLimitGuard::install(
            cx,
            conn.as_ref(),
            None,
            policy.request_timeout,
            request_budget.deadline(),
            Some(request_budget.db_quota()),
        )
        .ok()?;

        let catalog = async {
            let observed = ReadUncertaintyConn {
                inner: conn.as_ref(),
                quarantine: None,
            };
            let objects = search_objects(
                cx,
                &observed,
                owner,
                object_type,
                name_like,
                SearchDetailLevel::Names,
                max_rows,
            )
            .await?;
            let source_row = objects.first().map(fleet_catalog_source_row);
            let mut audit_response = QueryResponse {
                columns: source_row
                    .as_ref()
                    .map(|row| row.columns.iter().map(|(name, _)| name.clone()).collect())
                    .unwrap_or_default(),
                rows: Vec::new(),
                row_count: objects.len(),
                truncated: objects.len() == max_rows,
                next_cursor: None,
                total_bytes: 0,
                mask_certificate: source_row.as_ref().and_then(|row| {
                    policy
                        .result_masking
                        .as_ref()
                        .and_then(|masking| masking.certificate_for_row(row))
                }),
            };
            bind_result_masking_audit(
                cx,
                &observed,
                self.auditor.as_deref(),
                subject,
                "oracle_search_objects",
                FLEET_CATALOG_AUDIT_SQL,
                &mut audit_response,
            )
            .await
            .map_err(db_internal_from_envelope)?;
            Ok::<_, DbError>(FleetCatalogProfileResult {
                profile,
                results: objects
                    .iter()
                    .map(|object| {
                        fleet_catalog_result_row(
                            lease.profile(),
                            object,
                            policy.result_masking.as_ref(),
                        )
                    })
                    .collect(),
                mask_certificate: audit_response.mask_certificate,
                truncated: audit_response.truncated,
            })
        }
        .await;
        let restore = limits.restore();
        match (catalog, restore) {
            (Ok(result), Ok(())) => Some(result),
            _ => None,
        }
    }

    /// Read one side of a cross-database `oracle_diff` from a named profile, on
    /// a connection opened and closed inside this call.
    ///
    /// Arc H adds *reach*, never admission surface. Every guard the caller would
    /// meet on the way to this database through `oracle_switch_profile` is met
    /// here, in the same order:
    ///
    /// 1. **Exposure (E5).** The profile is admitted through
    ///    [`ProfileDrainState::admit_mcp_profile`] before its credentials are
    ///    resolved, so a diff can never reach a profile the caller could not
    ///    switch to, and a hidden name is refused without revealing that it
    ///    exists.
    /// 2. **Its own catalog.** The statement is re-resolved and re-classified
    ///    against *this* database with a fresh
    ///    [`OracleCatalogResolverCache`]. The cache key carries no database
    ///    identity, so reusing the pinned session's cache would resolve this
    ///    database's SQL against the other one's objects — the same text can name
    ///    different objects here.
    /// 3. **Its own egress policy.** Rows are masked under this profile's
    ///    masking policy, not the active session's.
    ///
    /// The connection is transient: it is never installed in `DispatcherState`,
    /// so the pinned session, its transaction, and its quarantine are untouched.
    /// It is deliberately *not* wired to `self.quarantine` — a failure on the
    /// database being compared against must not poison the caller's own session.
    async fn read_diff_side_from_profile(
        &self,
        cx: &Cx,
        request: DiffSideRequest<'_>,
    ) -> Result<DiffSideRead, ErrorEnvelope> {
        let DiffSideRequest {
            side,
            profile,
            sql,
            binds,
            caps,
            scn,
            serialize_defaults,
            subject,
            budget,
            infer_key,
        } = request;

        let lease = match self
            .profile_drain
            .admit_mcp_profile(profile, self.mcp_exposure.is_exposed(profile))
        {
            ProfileGenerationAdmission::Ready(lease) => lease,
            ProfileGenerationAdmission::NotExposed => {
                return Err(diff_side_failure(
                    side,
                    profile,
                    profile_not_available(profile),
                ));
            }
            ProfileGenerationAdmission::Draining => {
                return Err(diff_side_failure(
                    side,
                    profile,
                    profile_draining_error(profile),
                ));
            }
        };
        let Some(connector) = &self.connector else {
            return Err(diff_side_failure(
                side,
                profile,
                ErrorEnvelope::new(
                    ErrorClass::RuntimeStateRequired,
                    "cross-database diff is unavailable in this server instance",
                )
                .with_next_step("restart the server with `oraclemcp serve --profile <name>`"),
            ));
        };
        let policy = profile_dispatch_policy(&lease)
            .map_err(|error| diff_side_failure(side, profile, error))?;
        let (conn, _stateless) = connector(cx, &lease)
            .await
            .map_err(|error| diff_side_failure(side, profile, DbError::into_envelope(error)))?
            .into_parts();

        let limits = ConnectionLimitGuard::install(
            cx,
            conn.as_ref(),
            None,
            None,
            budget.deadline(),
            Some(budget.db_quota()),
        )
        .map_err(|error| diff_side_failure(side, profile, DbError::into_envelope(error)))?;

        // Everything fallible below runs inside this block so the connection's
        // request limits are always restored, whatever the outcome.
        let read = async {
            let observed = ReadUncertaintyConn {
                inner: conn.as_ref(),
                quarantine: None,
            };
            let executed_sql = with_audit_marker(sql, Some(profile), "oracle_diff");
            let catalog_cache = OracleCatalogResolverCache::new();
            let relations =
                resolve_read_only_relations(cx, &observed, &catalog_cache, &executed_sql).await?;
            let inferred_key = if infer_key {
                inferred_diff_key_columns(cx, &observed, &relations).await?
            } else {
                Vec::new()
            };
            let serialize_opts = SerializeOptions {
                result_masking: policy.result_masking.clone(),
                ..serialize_defaults
            };
            let mut response = match scn {
                Some(scn) => {
                    read_query_as_of(
                        cx,
                        &observed,
                        &executed_sql,
                        binds,
                        caps,
                        0,
                        &serialize_opts,
                        &AsOf::Scn(scn),
                    )
                    .await
                }
                None => {
                    read_query(
                        cx,
                        &observed,
                        &executed_sql,
                        binds,
                        caps,
                        0,
                        &serialize_opts,
                    )
                    .await
                }
            }
            .map_err(DbError::into_envelope)?;
            bind_result_masking_audit(
                cx,
                &observed,
                self.auditor.as_deref(),
                subject,
                "oracle_diff",
                &executed_sql,
                &mut response,
            )
            .await?;
            Ok(DiffSideRead {
                response,
                inferred_key,
            })
        }
        .await
        .map_err(|error| diff_side_failure(side, profile, error));

        // Restore before surfacing the read outcome: a restore failure on a
        // connection we are about to drop must not mask the real error.
        let restore = limits
            .restore()
            .map_err(|error| diff_side_failure(side, profile, DbError::into_envelope(error)));
        let read = read?;
        restore?;
        Ok(read)
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

    fn dispatch_request_budget(
        &self,
        cx: &Cx,
        context: DispatchContext<'_>,
    ) -> Result<RequestBudget, ErrorEnvelope> {
        let timeout = self.request_timeout()?;
        let admitted_at = context.admitted_at().unwrap_or_else(|| cx.now());
        let budget = if let Some(lane_budget) = context.request_budget() {
            lane_budget.tighten_timeout(timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT))
        } else {
            let caller_budget = context.caller_budget().unwrap_or_else(|| cx.budget());
            RequestBudget::from_call_timeout(admitted_at, timeout).meet(caller_budget)
        };
        budget.enforce(cx).map_err(DbError::into_envelope)?;
        Ok(budget)
    }
}

/// The process-wide default SQL classifier for **caller-supplied** SQL (the
/// fail-closed `UnknownOracle`). `Classifier::classify` takes `&self` and is
/// pure given a fixed config + oracle, so every request arm can share one
/// instance instead of rebuilding it on each call.
///
/// The served surface opts into the `.102` qualified-paren-less-callable guard:
/// Oracle invokes a zero-arg function with no parentheses, so
/// `SELECT app_admin.run_ddl FROM dual` *runs* `run_ddl`, but the `ident(`-only
/// UDF scan reads it as a column reference and clears it to Safe. The guard
/// forces a `SELECT` carrying a qualified identifier in value position whose
/// qualifier is not an exact relation/alias in the current or correlated scope to
/// `≥ Guarded` (so this READ_ONLY-ceilinged gate refuses it). It is surgical —
/// an in-scope `alias.column` reference is never flagged.
///
/// This shared classifier is only the first, text-local phase of the served raw
/// read gate. Bead .82 is closed by the follow-up `ensure_resolved_read_only`
/// phase: served `oracle_query`, `oracle_explain_plan`, and custom read-only
/// tools must resolve live catalog dependencies and refuse views, SELECT VPD
/// policies, virtual columns, remote objects, ambiguous values, and every other
/// unproven relation before caller SQL reaches Oracle. Allow/block-list configs
/// are not used on this served surface.
static DEFAULT_CLASSIFIER: LazyLock<Classifier> = LazyLock::new(|| {
    Classifier::new(ClassifierConfig::new().with_unresolved_qualified_calls_guarded())
});

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
    exposure: &McpExposurePolicy,
    drain: &ProfileDrainState,
) -> Result<Value, ErrorEnvelope> {
    drain
        .mcp_profiles_snapshot(exposure)
        .map(|profiles| json!({ "profiles": profiles }))
        .ok_or_else(|| {
            DbError::UnsupportedAuth("accepted runtime config snapshot is unavailable".to_owned())
                .into_envelope()
        })
}

/// Fail-closed envelope (E5) for a profile that is not exposed to the MCP
/// surface. Deliberately indistinguishable from an unknown profile so a guessed
/// non-exposed name leaks nothing: same class, same message, no acknowledgement
/// that the name happens to match a hidden profile.
pub fn profile_not_available(profile: &str) -> ErrorEnvelope {
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

fn profile_generation_inactive_error(profile: &str) -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorClass::RuntimeStateRequired,
        format!(
            "connection lane for profile `{profile}` no longer owns an active profile generation"
        ),
    )
    .with_next_step("open a new MCP session to create a fresh profile-generation lane")
}

/// Shared hot-reload drain gate for profile-scoped dispatch.
#[derive(Clone, Default)]
pub struct ProfileDrainState {
    inner: Arc<SyncMutex<ProfileDrainInner>>,
}

#[derive(Debug)]
struct ProfileDrainInner {
    profiles: HashMap<String, ProfileLifecycle>,
    accepted_config: Option<Arc<OracleMcpConfig>>,
    snapshot_required: bool,
}

impl Default for ProfileDrainInner {
    fn default() -> Self {
        Self {
            profiles: HashMap::new(),
            accepted_config: Some(Arc::new(OracleMcpConfig::default())),
            snapshot_required: false,
        }
    }
}

#[derive(Debug)]
struct ProfileLifecycle {
    current_generation: Option<u64>,
    last_generation: u64,
    live_generations: HashMap<u64, usize>,
    manually_drained: HashSet<u64>,
    mcp_exposed: Option<bool>,
}

impl ProfileLifecycle {
    fn initial() -> Self {
        Self {
            current_generation: Some(1),
            last_generation: 1,
            live_generations: HashMap::new(),
            manually_drained: HashSet::new(),
            mcp_exposed: None,
        }
    }

    fn advance_generation(&mut self) {
        self.current_generation = self.last_generation.checked_add(1).inspect(|next| {
            self.last_generation = *next;
        });
    }

    fn current_is_draining(&self) -> bool {
        self.current_generation
            .is_none_or(|generation| self.manually_drained.contains(&generation))
    }

    fn has_live_stale_generation(&self) -> bool {
        self.live_generations
            .keys()
            .any(|generation| Some(*generation) != self.current_generation)
    }
}

/// One live lane's binding to the exact profile generation it opened from.
/// Dropping the lease releases that generation's lifecycle reference.
pub struct ProfileGenerationLease {
    state: ProfileDrainState,
    profile: String,
    generation: u64,
    config: Option<Arc<OracleMcpConfig>>,
    snapshot_required: bool,
}

impl std::fmt::Debug for ProfileGenerationLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileGenerationLease")
            .field("profile", &self.profile)
            .field("generation", &self.generation)
            .field("draining", &self.is_draining())
            .finish()
    }
}

impl ProfileGenerationLease {
    /// Profile name bound by this lease.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Monotone generation number bound by this lease.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Immutable accepted configuration snapshot captured atomically with this
    /// generation reservation. Production leases always carry one; focused
    /// dispatcher tests built without service config may omit it.
    #[must_use]
    pub fn config(&self) -> Option<&OracleMcpConfig> {
        self.config.as_deref()
    }

    /// Whether this lease is no longer the admitted current generation.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.state
            .generation_is_draining(&self.profile, self.generation)
    }

    fn belongs_to(&self, state: &ProfileDrainState) -> bool {
        Arc::ptr_eq(&self.state.inner, &state.inner)
    }
}

impl Drop for ProfileGenerationLease {
    fn drop(&mut self) {
        self.state
            .release_generation(&self.profile, self.generation);
    }
}

/// Result of atomically checking MCP exposure and reserving a current profile
/// generation for a new lane or profile switch.
#[derive(Debug)]
pub enum ProfileGenerationAdmission {
    /// The profile is exposed and its current generation is reserved.
    Ready(ProfileGenerationLease),
    /// The profile is hidden from the MCP surface.
    NotExposed,
    /// No current usable generation exists (removed, drained, or lock poison).
    Draining,
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

    /// Create the runtime gate from the one configuration snapshot accepted at
    /// process startup. Later hot reloads replace this snapshot only inside the
    /// same mutex critical section that advances profile generations.
    #[must_use]
    pub fn from_config(config: OracleMcpConfig) -> Self {
        Self {
            inner: Arc::new(SyncMutex::new(ProfileDrainInner {
                profiles: HashMap::new(),
                accepted_config: Some(Arc::new(config)),
                snapshot_required: true,
            })),
        }
    }

    /// Return the exact configuration generation currently accepted by the
    /// live service. A missing snapshot or poisoned lifecycle lock fails
    /// closed; serving paths must never compensate by re-reading the file.
    #[must_use]
    pub fn accepted_config(&self) -> Option<Arc<OracleMcpConfig>> {
        self.inner
            .lock()
            .ok()
            .and_then(|guard| guard.accepted_config.clone())
    }

    /// Return agent-visible profile metadata from one linearized generation
    /// snapshot. Config contents, exposure overrides, and generation usability
    /// are all examined while holding the same lifecycle lock.
    #[must_use]
    pub fn mcp_profiles_snapshot(
        &self,
        exposure: &McpExposurePolicy,
    ) -> Option<Vec<ProfileMetadata>> {
        let guard = self.inner.lock().ok()?;
        let config = guard.accepted_config.as_deref()?;
        Some(
            config
                .list_profiles()
                .into_iter()
                .filter(|metadata| {
                    let startup_exposed = exposure.is_exposed(&metadata.name);
                    let Some(lifecycle) = guard.profiles.get(&metadata.name) else {
                        return startup_exposed;
                    };
                    lifecycle.mcp_exposed.unwrap_or(startup_exposed)
                        && !lifecycle.current_is_draining()
                })
                .collect(),
        )
    }

    /// Return every agent-visible configured profile for a fleet operation.
    ///
    /// Unlike [`Self::mcp_profiles_snapshot`], this retains a profile that is
    /// currently draining. The caller still has to admit each lane below, but
    /// retaining it here lets a fleet response report `FAIL_CLOSED` rather than
    /// silently omit a database the caller was just permitted to observe.
    #[must_use]
    pub fn mcp_fleet_profiles_snapshot(
        &self,
        exposure: &McpExposurePolicy,
    ) -> Option<Vec<ProfileMetadata>> {
        let guard = self.inner.lock().ok()?;
        let config = guard.accepted_config.as_deref()?;
        Some(
            config
                .list_profiles()
                .into_iter()
                .filter(|metadata| {
                    let startup_exposed = exposure.is_exposed(&metadata.name);
                    guard
                        .profiles
                        .get(&metadata.name)
                        .and_then(|lifecycle| lifecycle.mcp_exposed)
                        .unwrap_or(startup_exposed)
                })
                .collect(),
        )
    }

    /// Replace the explicitly drained current-generation set atomically.
    /// Config reloads use [`Self::apply_config_reload_plan`] instead so retired
    /// generations remain monotone across later adjacent reloads.
    pub fn replace_draining_profiles<I, S>(&self, profiles: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let requested: HashSet<String> = profiles.into_iter().map(Into::into).collect();
        let mut guard = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        for lifecycle in guard.profiles.values_mut() {
            lifecycle.manually_drained.clear();
        }
        for profile in requested {
            let lifecycle = guard
                .profiles
                .entry(profile)
                .or_insert_with(ProfileLifecycle::initial);
            if let Some(generation) = lifecycle.current_generation {
                lifecycle.manually_drained.insert(generation);
            }
        }
    }

    /// Apply a validated config transition atomically. Incompatible or removed
    /// generations are retired; later Retain decisions never reauthorize them.
    /// A replacement profile receives a fresh generation that new lanes may
    /// reserve while old live generations continue draining.
    pub fn apply_config_reload_plan(
        &self,
        plan: &ConfigReloadPlan,
        expected: &OracleMcpConfig,
        next: &OracleMcpConfig,
    ) -> Result<(), &'static str> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "profile generation state lock is poisoned")?;
        if let Some(current) = guard.accepted_config.as_deref()
            && current != expected
        {
            return Err("reload base does not match the accepted config generation");
        }
        if ConfigReloadPlan::between(expected, next) != *plan {
            return Err("reload plan does not match its exact config snapshots");
        }
        if !plan.hot_reloadable {
            return Err("reload plan requires a service restart");
        }
        for decision in &plan.profiles {
            let existed = guard.profiles.contains_key(&decision.profile);
            let lifecycle = guard
                .profiles
                .entry(decision.profile.clone())
                .or_insert_with(ProfileLifecycle::initial);
            if decision.mcp_exposure_changed || matches!(decision.action, ReloadProfileAction::Add)
            {
                lifecycle.mcp_exposed = decision.next_mcp_exposed;
            }
            match (decision.action, decision.reason) {
                (ReloadProfileAction::Retain, _) => {}
                (ReloadProfileAction::Add, _) if !existed => {}
                (ReloadProfileAction::Add, _) => lifecycle.advance_generation(),
                (ReloadProfileAction::Drain, ReloadProfileReason::Removed) => {
                    lifecycle.current_generation = None;
                }
                (ReloadProfileAction::Drain, _) => lifecycle.advance_generation(),
            }
        }
        guard.accepted_config = Some(Arc::new(next.clone()));
        Ok(())
    }

    /// Atomically check effective MCP exposure and reserve the current
    /// generation for a new lane. `startup_exposed` is the immutable startup
    /// policy fallback until the first applied reload supplies a live value.
    #[must_use]
    pub fn admit_mcp_profile(
        &self,
        profile: &str,
        startup_exposed: bool,
    ) -> ProfileGenerationAdmission {
        let Ok(mut guard) = self.inner.lock() else {
            return ProfileGenerationAdmission::Draining;
        };
        let config = guard.accepted_config.clone();
        let snapshot_required = guard.snapshot_required;
        if snapshot_required
            && config
                .as_deref()
                .and_then(|accepted| accepted.profile(profile))
                .is_none()
        {
            return ProfileGenerationAdmission::NotExposed;
        }
        if let Some(lifecycle) = guard.profiles.get(profile) {
            if !lifecycle.mcp_exposed.unwrap_or(startup_exposed) {
                return ProfileGenerationAdmission::NotExposed;
            }
        } else if !startup_exposed {
            // Refuse hidden/unknown guesses before allocating lifecycle state.
            return ProfileGenerationAdmission::NotExposed;
        }
        let lifecycle = guard
            .profiles
            .entry(profile.to_owned())
            .or_insert_with(ProfileLifecycle::initial);
        let Some(generation) = lifecycle.current_generation else {
            return ProfileGenerationAdmission::Draining;
        };
        if lifecycle.manually_drained.contains(&generation) {
            return ProfileGenerationAdmission::Draining;
        }
        let live = lifecycle.live_generations.entry(generation).or_default();
        *live = live.saturating_add(1);
        ProfileGenerationAdmission::Ready(ProfileGenerationLease {
            state: self.clone(),
            profile: profile.to_owned(),
            generation,
            config,
            snapshot_required,
        })
    }

    fn bind_existing_profile(&self, profile: &str) -> Option<ProfileGenerationLease> {
        let mut guard = self.inner.lock().ok()?;
        let config = guard.accepted_config.clone();
        let snapshot_required = guard.snapshot_required;
        if snapshot_required
            && config
                .as_deref()
                .and_then(|accepted| accepted.profile(profile))
                .is_none()
        {
            return None;
        }
        let lifecycle = guard
            .profiles
            .entry(profile.to_owned())
            .or_insert_with(ProfileLifecycle::initial);
        let generation = lifecycle.current_generation?;
        let live = lifecycle.live_generations.entry(generation).or_default();
        *live = live.saturating_add(1);
        Some(ProfileGenerationLease {
            state: self.clone(),
            profile: profile.to_owned(),
            generation,
            config,
            snapshot_required,
        })
    }

    /// Effective MCP exposure after live reload overrides the startup policy.
    #[must_use]
    pub fn is_mcp_exposed(&self, profile: &str, startup_exposed: bool) -> bool {
        self.inner.lock().is_ok_and(|guard| {
            guard
                .profiles
                .get(profile)
                .and_then(|lifecycle| lifecycle.mcp_exposed)
                .unwrap_or(startup_exposed)
        })
    }

    /// Whether a profile is both exposed and backed by an admitted current
    /// generation. Exposure and generation are read from one mutex snapshot so
    /// a concurrent visible-to-hidden reload cannot splice the old exposure
    /// value together with the new non-draining generation.
    #[must_use]
    pub fn is_mcp_available(&self, profile: &str, startup_exposed: bool) -> bool {
        self.inner.lock().is_ok_and(|guard| {
            let Some(lifecycle) = guard.profiles.get(profile) else {
                return startup_exposed;
            };
            lifecycle.mcp_exposed.unwrap_or(startup_exposed) && !lifecycle.current_is_draining()
        })
    }

    /// Whether the current generation cannot admit a new lane. A poisoned lock
    /// fails closed.
    #[must_use]
    pub fn is_draining(&self, profile: &str) -> bool {
        self.inner
            .lock()
            .map(|guard| {
                guard
                    .profiles
                    .get(profile)
                    .is_some_and(ProfileLifecycle::current_is_draining)
            })
            .unwrap_or(true)
    }

    fn generation_is_draining(&self, profile: &str, generation: u64) -> bool {
        self.inner
            .lock()
            .map(|guard| {
                guard.profiles.get(profile).is_none_or(|lifecycle| {
                    lifecycle.current_generation != Some(generation)
                        || lifecycle.manually_drained.contains(&generation)
                })
            })
            .unwrap_or(true)
    }

    fn commit_generation<T>(
        &self,
        profile: &str,
        generation: u64,
        commit: impl FnOnce() -> T,
    ) -> Result<T, ()> {
        let guard = self.inner.lock().map_err(|_| ())?;
        let lifecycle = guard.profiles.get(profile).ok_or(())?;
        if lifecycle.current_generation != Some(generation)
            || lifecycle.manually_drained.contains(&generation)
        {
            return Err(());
        }
        Ok(commit())
    }

    fn release_generation(&self, profile: &str, generation: u64) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        let Some(lifecycle) = guard.profiles.get_mut(profile) else {
            return;
        };
        let Some(count) = lifecycle.live_generations.get_mut(&generation) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            lifecycle.live_generations.remove(&generation);
            lifecycle.manually_drained.remove(&generation);
        }
    }

    /// Sorted profiles with at least one live retired generation or an
    /// explicitly drained current generation.
    #[must_use]
    pub fn draining_profiles(&self) -> Vec<String> {
        let mut profiles = self
            .inner
            .lock()
            .map(|guard| {
                guard
                    .profiles
                    .iter()
                    .filter(|(_, lifecycle)| {
                        (lifecycle.current_is_draining() && !lifecycle.live_generations.is_empty())
                            || lifecycle.has_live_stale_generation()
                    })
                    .map(|(profile, _)| profile.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        profiles.sort();
        profiles
    }
}

#[cfg(test)]
mod profile_drain_state_tests {
    use super::*;

    #[test]
    fn incompatible_generation_stays_drained_after_later_retain_reload() {
        let admin = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod"
            description = "initial"
            connect_string = "prod:1521/svc"
            max_level = "ADMIN"
            "#,
        )
        .expect("initial config");
        let lowered = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod"
            description = "initial"
            connect_string = "prod:1521/svc"
            max_level = "READ_ONLY"
            "#,
        )
        .expect("lowered config");
        let relabelled = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod"
            description = "harmless metadata edit"
            connect_string = "prod:1521/svc"
            max_level = "READ_ONLY"
            "#,
        )
        .expect("metadata-only config");

        let drain = ProfileDrainState::from_config(admin.clone());
        let old_admin = match drain.admit_mcp_profile("prod", true) {
            ProfileGenerationAdmission::Ready(lease) => lease,
            other => panic!("initial generation was not admitted: {other:?}"),
        };
        drain
            .apply_config_reload_plan(
                &ConfigReloadPlan::between(&admin, &lowered),
                &admin,
                &lowered,
            )
            .expect("lowering reload applies");
        assert!(old_admin.is_draining());
        let current_read_only = match drain.admit_mcp_profile("prod", true) {
            ProfileGenerationAdmission::Ready(lease) => lease,
            other => panic!("replacement generation was not admitted: {other:?}"),
        };
        assert_ne!(old_admin.generation(), current_read_only.generation());
        assert!(!current_read_only.is_draining());

        drain
            .apply_config_reload_plan(
                &ConfigReloadPlan::between(&lowered, &relabelled),
                &lowered,
                &relabelled,
            )
            .expect("metadata reload applies");
        assert!(
            old_admin.is_draining(),
            "a later compatible reload must not revive the older ADMIN generation"
        );
        assert!(
            !current_read_only.is_draining(),
            "the compatible current READ_ONLY generation remains admitted"
        );

        drain
            .apply_config_reload_plan(
                &ConfigReloadPlan::between(&relabelled, &relabelled),
                &relabelled,
                &relabelled,
            )
            .expect("no-op reload applies");
        assert!(
            old_admin.is_draining(),
            "a later no-op reload must not revive the older ADMIN generation"
        );
        assert!(
            !current_read_only.is_draining(),
            "the current READ_ONLY generation survives a no-op reload"
        );
        assert_eq!(drain.draining_profiles(), vec!["prod"]);

        drop(old_admin);
        assert!(
            drain.draining_profiles().is_empty(),
            "closing the last old-generation lane clears only that stale generation"
        );
    }

    #[test]
    fn removed_then_readded_name_never_reuses_the_removed_generation() {
        let present = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod"
            connect_string = "old:1521/svc"
            "#,
        )
        .expect("present config");
        let removed = OracleMcpConfig::from_toml_str("").expect("empty config");
        let readded = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod"
            connect_string = "new:1521/svc"
            "#,
        )
        .expect("readded config");
        let drain = ProfileDrainState::from_config(present.clone());
        let removed_generation = match drain.admit_mcp_profile("prod", true) {
            ProfileGenerationAdmission::Ready(lease) => lease,
            other => panic!("initial generation was not admitted: {other:?}"),
        };

        drain
            .apply_config_reload_plan(
                &ConfigReloadPlan::between(&present, &removed),
                &present,
                &removed,
            )
            .expect("removal applies");
        assert!(removed_generation.is_draining());
        assert!(matches!(
            drain.admit_mcp_profile("prod", true),
            ProfileGenerationAdmission::NotExposed
        ));

        drain
            .apply_config_reload_plan(
                &ConfigReloadPlan::between(&removed, &readded),
                &removed,
                &readded,
            )
            .expect("re-add applies");
        let readded_generation = match drain.admit_mcp_profile("prod", true) {
            ProfileGenerationAdmission::Ready(lease) => lease,
            other => panic!("readded generation was not admitted: {other:?}"),
        };
        assert_ne!(
            removed_generation.generation(),
            readded_generation.generation()
        );
        assert!(removed_generation.is_draining());
        assert!(!readded_generation.is_draining());
    }

    #[test]
    fn exposure_removal_survives_unrelated_reloads_and_hides_current_generation() {
        let visible = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod"
            description = "visible"
            connect_string = "prod:1521/svc"
            mcp_exposed = true
            "#,
        )
        .expect("visible config");
        let hidden = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod"
            description = "visible"
            connect_string = "prod:1521/svc"
            mcp_exposed = false
            "#,
        )
        .expect("hidden config");
        let relabelled_hidden = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod"
            description = "still hidden"
            connect_string = "prod:1521/svc"
            mcp_exposed = false
            "#,
        )
        .expect("relabelled hidden config");
        let drain = ProfileDrainState::from_config(visible.clone());
        let visible_generation = match drain.admit_mcp_profile("prod", true) {
            ProfileGenerationAdmission::Ready(lease) => lease,
            other => panic!("visible generation was not admitted: {other:?}"),
        };

        drain
            .apply_config_reload_plan(
                &ConfigReloadPlan::between(&visible, &hidden),
                &visible,
                &hidden,
            )
            .expect("exposure removal applies");
        assert!(visible_generation.is_draining());
        assert!(!drain.is_mcp_exposed("prod", true));
        assert!(
            !drain.is_draining("prod"),
            "the replacement generation is usable; exposure alone must hide it"
        );
        assert!(!drain.is_mcp_available("prod", true));
        assert!(matches!(
            drain.admit_mcp_profile("prod", true),
            ProfileGenerationAdmission::NotExposed
        ));

        drain
            .apply_config_reload_plan(
                &ConfigReloadPlan::between(&hidden, &relabelled_hidden),
                &hidden,
                &relabelled_hidden,
            )
            .expect("hidden metadata reload applies");
        assert!(visible_generation.is_draining());
        assert!(!drain.is_mcp_exposed("prod", true));
        let listed = profiles_response(&McpExposurePolicy::AllowAll, &drain)
            .expect("accepted profile snapshot");
        assert_eq!(listed["profiles"], json!([]));
    }

    #[test]
    fn retain_reload_does_not_revoke_operator_selected_initially_hidden_profile() {
        let hidden = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "operator_only"
            description = "before"
            connect_string = "prod:1521/svc"
            mcp_exposed = false
            "#,
        )
        .expect("hidden config");
        let relabelled = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "operator_only"
            description = "after"
            connect_string = "prod:1521/svc"
            mcp_exposed = false
            "#,
        )
        .expect("relabelled hidden config");
        let drain = ProfileDrainState::from_config(hidden.clone());

        drain
            .apply_config_reload_plan(
                &ConfigReloadPlan::between(&hidden, &relabelled),
                &hidden,
                &relabelled,
            )
            .expect("metadata reload applies");

        assert!(
            drain.is_mcp_exposed("operator_only", true),
            "operator-selected startup fallback remains authoritative"
        );
        assert!(
            !drain.is_mcp_exposed("operator_only", false),
            "MCP switch/list fallback remains hidden"
        );
        assert!(matches!(
            drain.admit_mcp_profile("operator_only", true),
            ProfileGenerationAdmission::Ready(_)
        ));
    }

    #[test]
    fn stale_generation_cannot_cross_the_atomic_switch_commit_point() {
        let before = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod"
            connect_string = "old:1521/svc"
            "#,
        )
        .expect("before config");
        let after = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod"
            connect_string = "new:1521/svc"
            "#,
        )
        .expect("after config");
        let drain = ProfileDrainState::from_config(before.clone());
        let prepared = match drain.admit_mcp_profile("prod", true) {
            ProfileGenerationAdmission::Ready(lease) => lease,
            other => panic!("initial generation was not admitted: {other:?}"),
        };
        drain
            .apply_config_reload_plan(&ConfigReloadPlan::between(&before, &after), &before, &after)
            .expect("replacement applies");

        let mut committed = false;
        assert!(
            drain
                .commit_generation("prod", prepared.generation(), || committed = true)
                .is_err()
        );
        assert!(
            !committed,
            "stale preparation must not run its commit closure"
        );
    }

    #[test]
    fn rollback_transition_allocates_another_generation_without_reviving_older_lanes() {
        let old = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod"
            connect_string = "old:1521/svc"
            max_level = "ADMIN"
            "#,
        )
        .expect("old config");
        let replacement = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod"
            connect_string = "replacement:1521/svc"
            max_level = "ADMIN"
            "#,
        )
        .expect("replacement config");
        let drain = ProfileDrainState::from_config(old.clone());
        let generation_one = match drain.admit_mcp_profile("prod", true) {
            ProfileGenerationAdmission::Ready(lease) => lease,
            other => panic!("initial generation was not admitted: {other:?}"),
        };
        drain
            .apply_config_reload_plan(
                &ConfigReloadPlan::between(&old, &replacement),
                &old,
                &replacement,
            )
            .expect("replacement applies");
        let generation_two = match drain.admit_mcp_profile("prod", true) {
            ProfileGenerationAdmission::Ready(lease) => lease,
            other => panic!("lowered generation was not admitted: {other:?}"),
        };

        drain
            .apply_config_reload_plan(
                &ConfigReloadPlan::between(&replacement, &old),
                &replacement,
                &old,
            )
            .expect("rollback applies");
        let generation_three = match drain.admit_mcp_profile("prod", true) {
            ProfileGenerationAdmission::Ready(lease) => lease,
            other => panic!("rollback generation was not admitted: {other:?}"),
        };

        assert!(generation_one.is_draining());
        assert!(generation_two.is_draining());
        assert!(!generation_three.is_draining());
        assert!(generation_one.generation() < generation_two.generation());
        assert!(generation_two.generation() < generation_three.generation());

        drop(generation_one);
        assert_eq!(
            drain.draining_profiles(),
            vec!["prod"],
            "closing generation one cannot clear the still-live stale generation two"
        );
        drop(generation_two);
        assert!(
            drain.draining_profiles().is_empty(),
            "only the final stale generation close clears the draining diagnostic"
        );
        assert!(!generation_three.is_draining());
    }

    #[test]
    fn reload_and_switch_commit_have_one_generation_linearization_point() {
        let before = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod"
            connect_string = "old:1521/svc"
            "#,
        )
        .expect("before config");
        let after = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod"
            connect_string = "new:1521/svc"
            "#,
        )
        .expect("after config");
        let plan = ConfigReloadPlan::between(&before, &after);
        let drain = ProfileDrainState::from_config(before.clone());
        let prepared = match drain.admit_mcp_profile("prod", true) {
            ProfileGenerationAdmission::Ready(lease) => lease,
            other => panic!("initial generation was not admitted: {other:?}"),
        };
        let generation = prepared.generation();
        let commit_state = drain.clone();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let commit = std::thread::spawn(move || {
            commit_state
                .commit_generation("prod", generation, || {
                    entered_tx.send(()).expect("announce commit lock");
                    release_rx.recv().expect("release commit lock");
                })
                .expect("generation is current before reload")
        });
        entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("commit reached its generation-locked critical section");
        assert!(matches!(
            drain.inner.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));

        let reload_state = drain.clone();
        let reload = std::thread::spawn(move || {
            reload_state.apply_config_reload_plan(&plan, &before, &after)
        });
        release_tx.send(()).expect("release commit");
        commit.join().expect("commit thread");
        reload
            .join()
            .expect("reload thread")
            .expect("reload applies");

        assert!(
            prepared.is_draining(),
            "reload linearized after the completed commit and retired its generation"
        );
    }

    #[test]
    fn stale_coarse_reload_plan_cannot_replace_the_accepted_snapshot() {
        let config = |connect_string: &str| {
            OracleMcpConfig::from_toml_str(&format!(
                r#"
                [[profiles]]
                name = "prod"
                connect_string = "{connect_string}"
                "#
            ))
            .expect("config")
        };
        let a = config("a:1521/svc");
        let b = config("b:1521/svc");
        let c = config("c:1521/svc");
        let state = ProfileDrainState::from_config(a.clone());

        let error = state
            .apply_config_reload_plan(&ConfigReloadPlan::between(&b, &c), &b, &c)
            .expect_err("B to C is stale while A is accepted");
        assert!(error.contains("reload base"), "{error}");
        assert_eq!(
            state
                .accepted_config()
                .expect("accepted A")
                .profile("prod")
                .and_then(|profile| profile.connect_string.as_deref()),
            Some("a:1521/svc")
        );

        state
            .apply_config_reload_plan(&ConfigReloadPlan::between(&a, &b), &a, &b)
            .expect("A to B applies");
        let error = state
            .apply_config_reload_plan(&ConfigReloadPlan::between(&a, &c), &a, &c)
            .expect_err("stale A to C cannot overwrite accepted B");
        assert!(error.contains("reload base"), "{error}");
        assert_eq!(
            state
                .accepted_config()
                .expect("accepted B")
                .profile("prod")
                .and_then(|profile| profile.connect_string.as_deref()),
            Some("b:1521/svc")
        );
    }

    #[test]
    fn lifecycle_state_rejects_restart_required_authority_expansion() {
        let read_only = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod"
            connect_string = "prod:1521/svc"
            max_level = "READ_ONLY"
            "#,
        )
        .expect("read-only config");
        let admin = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod"
            connect_string = "prod:1521/svc"
            max_level = "ADMIN"
            "#,
        )
        .expect("admin config");
        let state = ProfileDrainState::from_config(read_only.clone());
        let original = match state.admit_mcp_profile("prod", true) {
            ProfileGenerationAdmission::Ready(lease) => lease,
            other => panic!("initial generation was not admitted: {other:?}"),
        };
        let plan = ConfigReloadPlan::between(&read_only, &admin);
        assert!(!plan.hot_reloadable);

        let error = state
            .apply_config_reload_plan(&plan, &read_only, &admin)
            .expect_err("restart-required authority expansion must fail closed");
        assert!(error.contains("requires a service restart"), "{error}");
        assert!(!original.is_draining());
        assert_eq!(
            state
                .accepted_config()
                .expect("read-only snapshot remains accepted")
                .profile("prod")
                .expect("prod profile")
                .max_level(),
            OperatingLevel::ReadOnly
        );
    }

    #[test]
    fn unknown_profile_guesses_never_allocate_lifecycle_state() {
        let config = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "known"
            connect_string = "known:1521/svc"
            "#,
        )
        .expect("config");
        let state = ProfileDrainState::from_config(config);
        assert_eq!(state.inner.lock().expect("state lock").profiles.len(), 0);

        for index in 0..1_000 {
            let guessed = format!("unknown-{index}");
            assert!(matches!(
                state.admit_mcp_profile(&guessed, true),
                ProfileGenerationAdmission::NotExposed
            ));
            assert!(state.bind_existing_profile(&guessed).is_none());
        }

        assert_eq!(
            state.inner.lock().expect("state lock").profiles.len(),
            0,
            "untrusted profile names must not grow the lifecycle map"
        );
    }

    #[test]
    fn poisoned_generation_lock_rejects_reload_and_fails_closed() {
        let config = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod"
            connect_string = "prod:1521/svc"
            "#,
        )
        .expect("config");
        let next = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod"
            connect_string = "replacement:1521/svc"
            "#,
        )
        .expect("next config");
        let state = ProfileDrainState::from_config(config.clone());
        let lease = match state.admit_mcp_profile("prod", true) {
            ProfileGenerationAdmission::Ready(lease) => lease,
            other => panic!("initial generation was not admitted: {other:?}"),
        };
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = state.commit_generation("prod", lease.generation(), || {
                panic!("poison generation lock for regression");
            });
        }));
        assert!(poisoned.is_err());

        let error = state
            .apply_config_reload_plan(&ConfigReloadPlan::between(&config, &next), &config, &next)
            .expect_err("poisoned state must reject live reload");
        assert!(error.contains("lock is poisoned"), "{error}");
        assert!(state.accepted_config().is_none());
        assert!(state.is_draining("prod"));
    }

    #[test]
    fn competing_reloads_from_one_base_have_exactly_one_winner() {
        let config = |connect_string: &str| {
            OracleMcpConfig::from_toml_str(&format!(
                r#"
                [[profiles]]
                name = "prod"
                connect_string = "{connect_string}"
                "#
            ))
            .expect("config")
        };
        let a = config("a:1521/svc");
        let b = config("b:1521/svc");
        let c = config("c:1521/svc");
        let state = ProfileDrainState::from_config(a.clone());
        let old = match state.admit_mcp_profile("prod", true) {
            ProfileGenerationAdmission::Ready(lease) => lease,
            other => panic!("initial generation was not admitted: {other:?}"),
        };
        let barrier = Arc::new(std::sync::Barrier::new(3));

        let spawn_reload = |next: OracleMcpConfig| {
            let state = state.clone();
            let expected = a.clone();
            let plan = ConfigReloadPlan::between(&expected, &next);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                state.apply_config_reload_plan(&plan, &expected, &next)
            })
        };
        let to_b = spawn_reload(b);
        let to_c = spawn_reload(c);
        barrier.wait();
        let results = [
            to_b.join().expect("B reload thread"),
            to_c.join().expect("C reload thread"),
        ];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        assert!(old.is_draining());
        let current = match state.admit_mcp_profile("prod", true) {
            ProfileGenerationAdmission::Ready(lease) => lease,
            other => panic!("winning generation was not admitted: {other:?}"),
        };
        assert_eq!(current.generation(), old.generation() + 1);
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
    /// Only these profile names (the startup exposed set — every profile except
    /// those hidden with `mcp_exposed = false`) are reachable by the agent until
    /// live generation state overlays a later exposure transition.
    AllowList(std::collections::HashSet<String>),
}

impl McpExposurePolicy {
    /// Build the startup exposure policy from config (E5), per-profile opt-out.
    /// Accepted reload plans update exposure through [`ProfileDrainState`].
    ///
    /// A profile is reachable by the agent UNLESS it sets `mcp_exposed = false`.
    /// When nothing is hidden (the common case) that is exactly
    /// [`Self::AllowAll`]; otherwise the exposed (non-hidden) startup set is an
    /// [`Self::AllowList`] so the hidden profiles are unreachable. One
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

fn diff_query_caps_from_args(args: &DiffArgs) -> QueryCaps {
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

fn effective_query_cost_limit(
    profile_max_query_cost: Option<u64>,
    per_call_max_query_cost: Option<u64>,
) -> Option<u64> {
    match (profile_max_query_cost, per_call_max_query_cost) {
        (Some(profile), Some(per_call)) => Some(profile.min(per_call)),
        (Some(profile), None) => Some(profile),
        (None, Some(per_call)) => Some(per_call),
        (None, None) => None,
    }
}

fn query_budget_with_cost_limit(
    request_budget: RequestBudget,
    profile_max_query_cost: Option<u64>,
    per_call_max_query_cost: Option<u64>,
) -> RequestBudget {
    match effective_query_cost_limit(profile_max_query_cost, per_call_max_query_cost) {
        Some(cost_limit) => request_budget.meet(Budget::new().with_cost_quota(cost_limit)),
        None => request_budget,
    }
}

fn query_cost_unavailable(reason: impl Into<String>) -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorClass::PolicyDenied,
        format!(
            "oracle_query cost gate refused before execution: cost_unavailable ({})",
            reason.into()
        ),
    )
    .with_suggested_tool("oracle_explain_plan")
    .with_next_step("refresh optimizer statistics or retry without max_query_cost only if an unbounded read is acceptable")
}

const QUERY_COST_REFUSAL_PLAN_ROW_LIMIT: usize = 25;
const QUERY_COST_REFUSAL_HINT_LIMIT: usize = 8;
const QUERY_COST_REFUSAL_TEXT_LIMIT: usize = 512;

fn query_cost_exceeded(
    estimate: &PlanCostEstimate,
    observed_cost: u64,
    max_query_cost: u64,
) -> ErrorEnvelope {
    let detail = query_cost_refusal_detail(estimate, observed_cost, max_query_cost);
    let reason = StructuredReason::new(ReasonCategory::CostBudgetExceeded)
        .with_minimal_rewrite("tighten the WHERE clause, add a narrower predicate, or ask for a lower-cardinality page")
        .with_query_cost_refusal(detail);
    ErrorEnvelope::new(
        ErrorClass::PolicyDenied,
        format!(
            "oracle_query cost gate refused before execution: query_cost_exceeded (estimated total_cost {observed_cost} exceeds max_query_cost {max_query_cost})"
        ),
    )
    .with_suggested_tool("oracle_explain_plan")
    .with_structured_reason(reason)
    .with_next_step("tighten the WHERE clause, add a narrower predicate, or ask for a lower-cardinality page")
}

fn query_cost_refusal_detail(
    estimate: &PlanCostEstimate,
    observed_cost: u64,
    max_query_cost: u64,
) -> QueryCostRefusal {
    let plan_rows = estimate
        .rows
        .iter()
        .take(QUERY_COST_REFUSAL_PLAN_ROW_LIMIT)
        .map(|row| OptimizerPlanRow {
            id: row.id,
            operation: row.operation.as_deref().map(sanitize_plan_text),
            options: row.options.as_deref().map(sanitize_plan_text),
            object_owner: row.object_owner.as_deref().map(sanitize_plan_text),
            object_name: row.object_name.as_deref().map(sanitize_plan_text),
            cost: row.cost,
            cardinality: row.cardinality,
            bytes: row.bytes,
            access_predicates: row.access_predicates.as_deref().map(sanitize_plan_text),
            filter_predicates: row.filter_predicates.as_deref().map(sanitize_plan_text),
        })
        .collect();
    QueryCostRefusal {
        estimated_cost: observed_cost,
        max_query_cost,
        plan_rows,
        predicate_hints: query_cost_predicate_hints(estimate),
        note: estimate.note.clone(),
    }
}

fn query_cost_predicate_hints(estimate: &PlanCostEstimate) -> Vec<String> {
    let mut hints = Vec::new();
    for row in &estimate.rows {
        for (kind, predicate) in [
            ("access", row.access_predicates.as_deref()),
            ("filter", row.filter_predicates.as_deref()),
        ] {
            let Some(predicate) = predicate else {
                continue;
            };
            let predicate = sanitize_plan_text(predicate);
            if predicate.is_empty() {
                continue;
            }
            let mut location = format!("line {}", row.id);
            if let Some(operation) = row.operation.as_deref().map(sanitize_plan_text)
                && !operation.is_empty()
            {
                location.push(' ');
                location.push_str(&operation);
            }
            if let Some(options) = row.options.as_deref().map(sanitize_plan_text)
                && !options.is_empty()
            {
                location.push(' ');
                location.push_str(&options);
            }
            if let Some(object_name) = row.object_name.as_deref().map(sanitize_plan_text)
                && !object_name.is_empty()
            {
                location.push_str(" on ");
                if let Some(owner) = row.object_owner.as_deref().map(sanitize_plan_text)
                    && !owner.is_empty()
                {
                    location.push_str(&owner);
                    location.push('.');
                }
                location.push_str(&object_name);
            }
            hints.push(format!(
                "{location} has {kind} predicate {predicate}; tighten a selective predicate or add/support an index for that predicate"
            ));
            if hints.len() >= QUERY_COST_REFUSAL_HINT_LIMIT {
                return hints;
            }
        }
    }
    hints
}

fn sanitize_plan_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len().min(QUERY_COST_REFUSAL_TEXT_LIMIT));
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if out.chars().count() >= QUERY_COST_REFUSAL_TEXT_LIMIT {
            out.push('…');
            break;
        }
        match ch {
            '\'' => {
                out.push_str("'<redacted>'");
                while let Some(next) = chars.next() {
                    if next == '\'' {
                        if chars.next_if_eq(&'\'').is_some() {
                            continue;
                        }
                        break;
                    }
                }
            }
            '"' => {
                out.push('"');
                for next in chars.by_ref() {
                    out.push(next);
                    if next == '"' {
                        break;
                    }
                }
            }
            digit if digit.is_ascii_digit() => {
                out.push_str("<number>");
                while matches!(chars.peek(), Some(next) if next.is_ascii_digit() || *next == '.') {
                    chars.next();
                }
            }
            other => out.push(other),
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

struct QueryCostGateCtx<'a> {
    cx: &'a Cx,
    conn: &'a dyn OracleConnection,
    read_only_backstop: &'a mut ReadOnlyBackstop,
    checkpoints: &'a CheckpointWorkspace,
    session: &'a SessionLevelState,
    request_budget: &'a RequestBudget,
    quarantine: &'a SyncMutex<Option<ConnectionQuarantine>>,
}

async fn enforce_query_cost_gate(
    ctx: QueryCostGateCtx<'_>,
    args: &QueryArgs,
    executed_sql: &str,
    max_query_cost: Option<u64>,
) -> Result<(), ErrorEnvelope> {
    let Some(max_query_cost) = max_query_cost else {
        return Ok(());
    };
    ensure_query_cost_plan_write_allowed(args, ctx.session)?;
    // The cost estimate writes PLAN_TABLE and rolls the transaction back to
    // clean it up — which would erase the reversible workspace's savepoints and
    // every statement held above them (Arc I).
    ensure_workspace_closed(
        ctx.checkpoints,
        "oracle_query cost estimation (its PLAN_TABLE cleanup rolls the transaction back)",
    )?;
    if let Err(error) = ctx
        .read_only_backstop
        .clear_before_write(ctx.cx, ctx.conn)
        .await
    {
        let message = format!(
            "could not end the armed read-only transaction before oracle_query cost estimation; the query was not executed and the session was quarantined: {error}"
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
    ctx.request_budget
        .enforce(ctx.cx)
        .map_err(DbError::into_envelope)?;

    if let Err(primary) = explain_plan(ctx.cx, ctx.conn, executed_sql, args.read_only_standby).await
    {
        if let Err(cleanup_err) = rollback_conn_cleanup(ctx.cx, ctx.conn).await {
            let message = format!(
                "oracle_query cost estimation failed and PLAN_TABLE rollback cleanup failed: {cleanup_err}"
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
        return Err(DbError::into_envelope(primary));
    }
    ctx.request_budget
        .enforce(ctx.cx)
        .map_err(DbError::into_envelope)?;

    let decision = match plan_cost_estimate(ctx.cx, ctx.conn).await {
        Ok(Some(estimate)) => match estimate.summary.total_cost {
            Some(total_cost) => match u64::try_from(total_cost) {
                Ok(observed) if observed <= max_query_cost => Ok(()),
                Ok(observed) => Err(query_cost_exceeded(&estimate, observed, max_query_cost)),
                Err(_) => Err(query_cost_unavailable(format!(
                    "PLAN_TABLE root total_cost was negative: {total_cost}"
                ))),
            },
            None => Err(query_cost_unavailable(
                "PLAN_TABLE root total_cost was NULL",
            )),
        },
        Ok(None) => Err(query_cost_unavailable(
            "PLAN_TABLE returned no scoped plan-root (id=0) row",
        )),
        Err(err) => Err(query_cost_unavailable(format!(
            "PLAN_TABLE cost estimate query failed: {err}"
        ))),
    };

    if let Err(cleanup_err) = rollback_conn_cleanup(ctx.cx, ctx.conn).await {
        let message = format!(
            "oracle_query cost estimation completed, but PLAN_TABLE rollback cleanup failed: {cleanup_err}"
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
    ctx.request_budget
        .enforce(ctx.cx)
        .map_err(DbError::into_envelope)?;
    decision
}

#[cfg(test)]
fn query_serialize_options_from_args(args: &QueryArgs) -> SerializeOptions {
    query_serialize_options_from_args_with_policy(args, None)
}

fn query_serialize_options_from_args_with_policy(
    args: &QueryArgs,
    result_masking: Option<&ResultMaskingPolicy>,
) -> SerializeOptions {
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
        result_masking: result_masking.cloned(),
        ..defaults
    }
}

fn diff_serialize_options_from_args_with_policy(
    args: &DiffArgs,
    result_masking: Option<&ResultMaskingPolicy>,
) -> SerializeOptions {
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
        result_masking: result_masking.cloned(),
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
    export_access: &QueryExportAccess,
    exports: Option<&oraclemcp_core::ExportRegistry>,
    as_of: Option<&AsOf>,
    result_masking: Option<&ResultMaskingPolicy>,
    auditor: Option<&Auditor>,
    audit_subject: &AuditSubject,
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
    let serialize_opts = query_serialize_options_from_args_with_policy(a, result_masking);
    // K9: an export honors the flashback target too — the SAME proven SQL is
    // materialized as of the requested snapshot.
    let mut response = match as_of {
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
    bind_result_masking_audit(
        cx,
        conn,
        auditor,
        audit_subject,
        "oracle_query",
        executed_sql,
        &mut response,
    )
    .await?;
    let response_value = serde_json::to_value(&response).unwrap_or(Value::Null);
    let more_rows = response.truncated;
    let next_cursor = response.next_cursor.as_deref().map(|offset| {
        let binding = query_cursor_binding(&a.sql, active_profile);
        oraclemcp_core::sign_token(QUERY_CURSOR_SCOPE, offset, &[&binding])
    });

    let (columns, rows) = query_value_to_export_rows(&response_value);
    let access = oraclemcp_core::ExportAccess::new(
        active_profile,
        &export_access.principal_key,
        export_access.scopes.as_deref(),
    );
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
            "description": "Materialized query result. Fetch with resources/read; bound to the originating principal and exact scope grant, and expires.",
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompletionPolicy {
    /// The body is a read or preview. A deadline observed after it completes
    /// still wins because replay cannot duplicate a persistent effect.
    EnforceDeadlineAfterBody,
    /// A successful body proves a persistent effect completed. A deadline
    /// observed afterwards is reported in-band, never as a retryable timeout.
    PreserveSuccessfulEffect,
}

/// Synchronous scope guard for connection-local wire limits.
///
/// `Drop` is the cancellation/panic backstop. Normal completion calls
/// [`Self::restore`] so restoration failures can quarantine the session.
struct ConnectionLimitGuard<'a> {
    cx: &'a Cx,
    conn: &'a dyn OracleConnection,
    quarantine: Option<&'a SyncMutex<Option<ConnectionQuarantine>>>,
    previous_call_timeout: Option<Duration>,
    previous_request_deadline: Option<Time>,
    previous_request_quota: Option<DbRequestQuota>,
    call_timeout_changed: bool,
    request_deadline_changed: bool,
    request_quota_changed: bool,
    active: bool,
}

impl<'a> ConnectionLimitGuard<'a> {
    fn install(
        cx: &'a Cx,
        conn: &'a dyn OracleConnection,
        quarantine: Option<&'a SyncMutex<Option<ConnectionQuarantine>>>,
        call_timeout: Option<Duration>,
        request_deadline: Option<Time>,
        request_quota: Option<DbRequestQuota>,
    ) -> Result<Self, DbError> {
        let previous_call_timeout = conn.call_timeout()?;
        let previous_request_deadline = conn.request_deadline(cx)?;
        let previous_request_quota = conn.request_quota(cx)?;
        let effective_call_timeout = match (previous_call_timeout, call_timeout) {
            (Some(previous), Some(requested)) => Some(previous.min(requested)),
            (previous, None) => previous,
            (None, requested) => requested,
        };
        let effective_request_deadline = match (previous_request_deadline, request_deadline) {
            (Some(previous), Some(requested)) => Some(previous.min(requested)),
            (previous, None) => previous,
            (None, requested) => requested,
        };
        // A nested scope must never replace an already-installed shared quota
        // with a fresh counter. The outer handle already represents the
        // tighter inherited request and is retained until its owner restores.
        let effective_request_quota = previous_request_quota.clone().or(request_quota);

        let call_timeout_changed = effective_call_timeout != previous_call_timeout;
        let request_deadline_changed = effective_request_deadline != previous_request_deadline;
        let request_quota_changed = match (&previous_request_quota, &effective_request_quota) {
            (Some(previous), Some(requested)) => !previous.ptr_eq(requested),
            (None, None) => false,
            _ => true,
        };
        if call_timeout_changed {
            conn.set_call_timeout(effective_call_timeout)?;
        }
        if request_deadline_changed
            && let Err(err) = conn.set_request_deadline(cx, effective_request_deadline)
        {
            if call_timeout_changed
                && let Err(restore_err) = conn.set_call_timeout(previous_call_timeout)
            {
                record_limit_restore_uncertainty(
                    quarantine,
                    "request-deadline installation failed and call-timeout rollback failed",
                    &restore_err,
                );
                return Err(DbError::Internal(format!(
                    "request-deadline installation failed: {err}; call-timeout rollback also failed: {restore_err}"
                )));
            }
            return Err(err);
        }
        if request_quota_changed
            && let Err(err) = conn.set_request_quota(cx, effective_request_quota)
        {
            let mut restore_errors = Vec::new();
            if request_deadline_changed
                && let Err(restore_err) = conn.set_request_deadline(cx, previous_request_deadline)
            {
                restore_errors.push(format!("request deadline: {restore_err}"));
            }
            if call_timeout_changed
                && let Err(restore_err) = conn.set_call_timeout(previous_call_timeout)
            {
                restore_errors.push(format!("call timeout: {restore_err}"));
            }
            if !restore_errors.is_empty() {
                let restore_summary = restore_errors.join("; ");
                record_limit_restore_uncertainty(
                    quarantine,
                    "request-quota installation failed and prior limits could not be restored",
                    &DbError::Internal(restore_summary.clone()),
                );
                return Err(DbError::Internal(format!(
                    "request-quota installation failed: {err}; limit rollback also failed: {restore_summary}"
                )));
            }
            return Err(err);
        }
        Ok(Self {
            cx,
            conn,
            quarantine,
            previous_call_timeout,
            previous_request_deadline,
            previous_request_quota,
            call_timeout_changed,
            request_deadline_changed,
            request_quota_changed,
            active: true,
        })
    }

    fn restore(mut self) -> Result<(), DbError> {
        let quota_restore = if self.request_quota_changed {
            self.conn
                .set_request_quota(self.cx, self.previous_request_quota.clone())
        } else {
            Ok(())
        };
        let deadline_restore = if self.request_deadline_changed {
            self.conn
                .set_request_deadline(self.cx, self.previous_request_deadline)
        } else {
            Ok(())
        };
        let timeout_restore = if self.call_timeout_changed {
            self.conn.set_call_timeout(self.previous_call_timeout)
        } else {
            Ok(())
        };
        self.active = false;
        quota_restore.and(deadline_restore).and(timeout_restore)
    }
}

impl Drop for ConnectionLimitGuard<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut restore_errors = Vec::new();
        if self.request_quota_changed
            && let Err(err) = self
                .conn
                .set_request_quota(self.cx, self.previous_request_quota.clone())
        {
            tracing::error!(error = %err, "failed to restore Oracle request quota during drop");
            restore_errors.push(format!("request quota: {err}"));
        }
        if self.request_deadline_changed
            && let Err(err) = self
                .conn
                .set_request_deadline(self.cx, self.previous_request_deadline)
        {
            tracing::error!(error = %err, "failed to restore Oracle request deadline during drop");
            restore_errors.push(format!("request deadline: {err}"));
        }
        if self.call_timeout_changed
            && let Err(err) = self.conn.set_call_timeout(self.previous_call_timeout)
        {
            tracing::error!(error = %err, "failed to restore Oracle call timeout during drop");
            restore_errors.push(format!("call timeout: {err}"));
        }
        if !restore_errors.is_empty() {
            record_limit_restore_uncertainty(
                self.quarantine,
                "request-limit guard was dropped before explicit finalization",
                &DbError::Internal(restore_errors.join("; ")),
            );
        }
    }
}

fn record_limit_restore_uncertainty(
    quarantine: Option<&SyncMutex<Option<ConnectionQuarantine>>>,
    context: &str,
    error: &DbError,
) {
    let message = format!("{context}: {error}");
    tracing::error!(error = %error, context, "Oracle request limits are in an uncertain state");
    if let Some(quarantine) = quarantine
        && let Err(mark_error) =
            mark_connection_quarantined(quarantine, AuditOutcome::UnknownDiscarded, message)
    {
        tracing::error!(error = %mark_error.message, "failed to quarantine uncertain Oracle request limits");
    }
}

fn limit_restore_failure(
    quarantine: &SyncMutex<Option<ConnectionQuarantine>>,
    effect_succeeded: bool,
    err: DbError,
) -> ErrorEnvelope {
    let outcome = if effect_succeeded {
        AuditOutcome::Succeeded
    } else {
        AuditOutcome::UnknownDiscarded
    };
    let message = if effect_succeeded {
        format!(
            "database effect succeeded, but request-limit finalization failed; do not retry the operation: {err}"
        )
    } else {
        format!(
            "request completed, but connection request-limit restoration failed; the session was quarantined: {err}"
        )
    };
    if let Err(lock_err) = mark_connection_quarantined(quarantine, outcome, message.clone()) {
        return lock_err;
    }
    ErrorEnvelope::new(ErrorClass::RuntimeStateRequired, message)
        .with_next_step("switch to a fresh profile connection or restart the server")
        .with_next_step(if effect_succeeded {
            "verify the completed database effect before issuing any retry"
        } else {
            "do not reuse the quarantined session"
        })
}

trait DeadlineAnnotation {
    fn annotate_deadline_after_effect(&mut self);
}

impl DeadlineAnnotation for Value {
    fn annotate_deadline_after_effect(&mut self) {
        if let Value::Object(map) = self {
            map.insert(
                "deadline_observed_after_effect".to_owned(),
                Value::Bool(true),
            );
            map.insert(
                "deadline_note".to_owned(),
                json!("the requested effect completed; do not retry solely because the request deadline elapsed during finalization"),
            );
        }
    }
}

impl DeadlineAnnotation for (Value, Option<PatchPreviewEntry>) {
    fn annotate_deadline_after_effect(&mut self) {
        self.0.annotate_deadline_after_effect();
    }
}

/// Apply one absolute whole-request deadline plus an optional relative Oracle
/// round-trip cap around an async DB body.
async fn with_call_timeout<T, Fut>(
    cx: &Cx,
    conn: &dyn OracleConnection,
    quarantine: &SyncMutex<Option<ConnectionQuarantine>>,
    request_budget: RequestBudget,
    timeout_seconds: Option<u64>,
    completion: CompletionPolicy,
    f: impl FnOnce() -> Fut,
) -> Result<T, ErrorEnvelope>
where
    T: DeadlineAnnotation,
    Fut: Future<Output = Result<T, ErrorEnvelope>>,
{
    dispatch_checkpoint(cx, "oraclemcp.dispatch.call_timeout.before")?;
    let timeout = call_timeout_duration(timeout_seconds)?;
    let request_budget = match timeout {
        Some(timeout) => request_budget.tighten_timeout(timeout),
        None => request_budget,
    };
    request_budget.enforce(cx).map_err(DbError::into_envelope)?;
    let limits = ConnectionLimitGuard::install(
        cx,
        conn,
        Some(quarantine),
        timeout,
        request_budget.deadline(),
        Some(request_budget.db_quota()),
    )
    .map_err(DbError::into_envelope)?;
    let result = f().await;
    let budget_after = request_budget.enforce(cx).map_err(DbError::into_envelope);
    let restore_error = limits.restore().err();

    // The body error is primary. In particular, a structured quarantined
    // CommitInDoubt/UnknownDiscarded result must never be overwritten by a late
    // timeout or a secondary local restoration error.
    let mut value = match result {
        Ok(value) => value,
        Err(primary) => {
            if let Some(restore_err) = restore_error.as_ref() {
                let _ = mark_connection_quarantined(
                    quarantine,
                    AuditOutcome::UnknownDiscarded,
                    format!(
                        "database operation failed and request-limit restoration also failed: {restore_err}"
                    ),
                );
            }
            return Err(primary);
        }
    };
    if let Some(err) = restore_error {
        return Err(limit_restore_failure(
            quarantine,
            completion == CompletionPolicy::PreserveSuccessfulEffect,
            err,
        ));
    }
    match budget_after {
        Ok(()) => Ok(value),
        Err(err) if completion == CompletionPolicy::PreserveSuccessfulEffect => {
            value.annotate_deadline_after_effect();
            tracing::warn!(error = %err.message, "request deadline observed after a completed database effect");
            Ok(value)
        }
        Err(err) => Err(err),
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

async fn run_cleanup_with_budget<T, Fut>(
    cx: &Cx,
    cleanup_budget: &RequestBudget,
    future: Fut,
) -> Result<T, DbError>
where
    Fut: Future<Output = Result<T, DbError>>,
{
    let mut masked = std::pin::pin!(try_commit_section(cx, CLEANUP_POLL_QUOTA, future));
    let driven = std::future::poll_fn(|task_cx| {
        // Cleanup intentionally ignores the dead primary Cx cancellation, but
        // charges a fresh independent application quota and deadline.
        if let Err(error) = cleanup_budget.enforce_at(cx.now()) {
            return std::task::Poll::Ready(Err(error));
        }
        masked.as_mut().poll(task_cx)
    });
    match cleanup_budget.deadline() {
        Some(deadline) => asupersync::time::timeout_at(deadline, driven)
            .await
            .map_err(|_| {
                DbError::Cancelled(
                    "cleanup finalizer exceeded its fresh bounded deadline".to_owned(),
                )
            })?,
        None => driven.await,
    }
}

/// Run rollback as a bounded cancellation-masked finalizer. The real thin
/// adapter additionally applies its independent five-second wire ceiling; the
/// mask also keeps cancellation-aware test/backends from skipping cleanup.
async fn rollback_conn_cleanup(cx: &Cx, conn: &dyn OracleConnection) -> Result<(), DbError> {
    let cleanup_budget = RequestBudget::fresh_cleanup(cx.now());
    run_cleanup_with_budget(cx, &cleanup_budget, conn.rollback(cx)).await
}

async fn recover_row_stream_cleanup(cx: &Cx, stream: QueryRowStream) -> Result<(), DbError> {
    let cleanup_budget = RequestBudget::fresh_cleanup(cx.now());
    run_cleanup_with_budget(cx, &cleanup_budget, stream.recover(cx)).await
}

async fn ensure_read_only_backstop_bounded(
    cx: &Cx,
    conn: &dyn OracleConnection,
    backstop: &mut read_only_backstop::ReadOnlyBackstop,
    checkpoints: &CheckpointWorkspace,
    level: &SessionLevelState,
    request_budget: &RequestBudget,
    quarantine: &SyncMutex<Option<ConnectionQuarantine>>,
) -> Result<(), ErrorEnvelope> {
    request_budget.enforce(cx).map_err(DbError::into_envelope)?;
    let limits = ConnectionLimitGuard::install(
        cx,
        conn,
        Some(quarantine),
        None,
        request_budget.deadline(),
        Some(request_budget.db_quota()),
    )
    .map_err(DbError::into_envelope)?;
    let result = backstop.ensure_armed(cx, conn, level).await;
    // Arc I: re-arming rolled the transaction back, so Oracle erased every
    // savepoint and every held statement with it. Drop the workspace belief
    // before anything can read it back as still-live.
    if matches!(result, Ok(true)) {
        checkpoints.clear();
    }
    let budget_after = request_budget.enforce(cx).map_err(DbError::into_envelope);
    let restore_error = limits.restore().err();
    if let Err(primary) = result {
        if let Some(restore_err) = restore_error {
            let _ = mark_connection_quarantined(
                quarantine,
                AuditOutcome::UnknownDiscarded,
                format!(
                    "read-only transaction backstop failed and request-limit restoration also failed: {restore_err}"
                ),
            );
        }
        return Err(primary);
    }
    if let Some(restore_err) = restore_error {
        return Err(limit_restore_failure(quarantine, false, restore_err));
    }
    budget_after
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

mod workspace;
use workspace::CheckpointWorkspace;

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

struct ResolvedStatementPurity(Purity);

impl SideEffectOracle for ResolvedStatementPurity {
    fn statement_purity(&self, _base_objects: &[ObjectRef]) -> Purity {
        self.0
    }
}

fn unresolved_semantic_read(reason: &'static str) -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorClass::ForbiddenStatement,
        format!("read-only server could not prove this statement safe: {reason}"),
    )
    .with_structured_reason(
        StructuredReason::new(ReasonCategory::UnprovenSideEffect)
            .with_offending_construct("unresolved semantic read dependency"),
    )
    .with_next_step(
        "query an ordinary table using explicit table aliases and real columns; views, VPD-protected tables, virtual columns, remote objects, ambiguous names, and unrepresented query scopes are refused",
    )
}

/// Resolve every caller-controlled read dependency against the exact live
/// session before the submitted statement can execute. Dictionary lookup is
/// observational I/O; the caller's SQL remains untouched until this returns.
async fn ensure_resolved_read_only(
    cx: &Cx,
    conn: &dyn OracleConnection,
    cache: &OracleCatalogResolverCache,
    sql: &str,
) -> Result<(), ErrorEnvelope> {
    resolve_read_only_relations(cx, conn, cache, sql)
        .await
        .map(|_| ())
}

async fn resolve_read_only_relations(
    cx: &Cx,
    conn: &dyn OracleConnection,
    cache: &OracleCatalogResolverCache,
    sql: &str,
) -> Result<Vec<ResolvedObject>, ErrorEnvelope> {
    ensure_read_only(sql)?;
    let plan = semantic_read_plan(sql)
        .ok_or_else(|| unresolved_semantic_read("query scope is not exactly representable"))?;
    cache.invalidate(CatalogInvalidation::SemanticProofRefresh);
    let mut names = plan.relations.clone();
    names.extend(plan.values.iter().cloned());
    let context = cache
        .preload(cx, conn, &names, plan.statement_scope)
        .await
        .map_err(DbError::into_envelope)?;

    let mut relations = Vec::with_capacity(plan.relations.len());
    for name in &plan.relations {
        let Resolution::Resolved(object) = cache.resolve(name, &context) else {
            return Err(unresolved_semantic_read(
                "a relation has no unique local catalog identity",
            ));
        };
        relations.push(*object);
    }
    for name in &plan.values {
        let Resolution::Resolved(object) = cache.resolve(name, &context) else {
            return Err(unresolved_semantic_read(
                "a value identifier is not a unique column",
            ));
        };
        if object.kind != CatalogObjectKind::Column {
            return Err(unresolved_semantic_read(
                "a value identifier resolves to executable code rather than a column",
            ));
        }
    }

    let purity = resolved_relations_read_purity(cx, conn, &relations)
        .await
        .map_err(DbError::into_envelope)?;
    if !purity.permits_safe() {
        return Err(unresolved_semantic_read(
            "a relation can invoke an unproven view, policy, or virtual-column dependency",
        ));
    }
    let decision =
        Classifier::new(ClassifierConfig::new().with_unresolved_qualified_calls_guarded())
            .with_oracle(Arc::new(ResolvedStatementPurity(purity)))
            .with_statement_unknown_guarded()
            .classify(sql);
    ensure_read_only_decision(decision)
        .map_err(|error| attach_parameterization_hint(error, sql))?;
    Ok(relations)
}

fn normalize_diff_key_columns(raw: Vec<String>) -> Result<Vec<String>, ErrorEnvelope> {
    let mut columns = Vec::<String>::new();
    for column in raw {
        let column = column.trim();
        if column.is_empty() {
            return Err(invalid_args(
                "oracle_diff key columns must be non-empty strings",
            ));
        }
        if !columns
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(column))
        {
            columns.push(column.to_owned());
        }
    }
    Ok(columns)
}

async fn inferred_diff_key_columns(
    cx: &Cx,
    metadata_conn: &dyn OracleConnection,
    relations: &[ResolvedObject],
) -> Result<Vec<String>, ErrorEnvelope> {
    let [relation] = relations else {
        return Ok(Vec::new());
    };
    if relation.kind != CatalogObjectKind::Table || relation.db_link.is_some() {
        return Ok(Vec::new());
    }
    primary_key_columns(cx, metadata_conn, &relation.owner, &relation.name)
        .await
        .map_err(DbError::into_envelope)
}

/// Which two sides `oracle_diff` compares.
///
/// The alignment maths is the same either way; only where each page is read
/// from changes. Time compares one database against itself at two SCNs; Fleet
/// compares two databases (Arc H) — the same proven read, classified and masked
/// independently under each profile.
enum DiffMode {
    /// The pinned session at two system change numbers.
    Time { scn_a: u64, scn_b: u64 },
    /// Two configured profiles, each optionally pinned to its own SCN.
    Fleet {
        profile_a: String,
        scn_a: Option<u64>,
        profile_b: String,
        scn_b: Option<u64>,
    },
}

/// One side of a diff, named for refusals and provenance.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DiffSide {
    A,
    B,
}

/// One page of a cross-database diff, to be read from `profile`.
struct DiffSideRequest<'a> {
    side: DiffSide,
    profile: &'a str,
    sql: &'a str,
    binds: &'a [OracleBind],
    caps: QueryCaps,
    /// Pin this side to a flashback read, or read the current committed state.
    scn: Option<u64>,
    /// Serializer options for the call, minus the masking policy: that is taken
    /// from the side's own profile, never the active session's.
    serialize_defaults: SerializeOptions,
    subject: &'a AuditSubject,
    budget: &'a RequestBudget,
    /// Infer the row key from this side's primary key. Only side A does this;
    /// both sides must align on one key, and it is side A's shape that names it.
    infer_key: bool,
}

/// What one side of a cross-database diff returned.
struct DiffSideRead {
    response: QueryResponse,
    inferred_key: Vec<String>,
}

impl DiffSide {
    fn label(self) -> &'static str {
        match self {
            DiffSide::A => "a",
            DiffSide::B => "b",
        }
    }
}

fn diff_scn_at_least_one(scn: Option<u64>, arg: &str) -> Result<Option<u64>, ErrorEnvelope> {
    if scn == Some(0) {
        return Err(invalid_args(format!("oracle_diff {arg} must be >= 1")));
    }
    Ok(scn)
}

/// Decide which two sides the call compares, and reject an ambiguous request.
///
/// A half-specified fleet diff is refused rather than silently falling back to a
/// same-database read: an agent that names one profile clearly meant to compare
/// two databases, and quietly comparing the active one twice would answer a
/// question nobody asked.
fn diff_mode_from_args(args: &DiffArgs) -> Result<DiffMode, ErrorEnvelope> {
    let scn_a = diff_scn_at_least_one(args.scn_a, "scn_a")?;
    let scn_b = diff_scn_at_least_one(args.scn_b, "scn_b")?;
    match (args.profile_a.as_deref(), args.profile_b.as_deref()) {
        (None, None) => {
            let (Some(scn_a), Some(scn_b)) = (scn_a, scn_b) else {
                return Err(invalid_args(
                    "oracle_diff needs either scn_a and scn_b (compare one database at two SCNs) \
                     or profile_a and profile_b (compare two databases)",
                ));
            };
            Ok(DiffMode::Time { scn_a, scn_b })
        }
        (Some(profile_a), Some(profile_b)) => {
            let profile_a = profile_a.trim();
            let profile_b = profile_b.trim();
            if profile_a.is_empty() || profile_b.is_empty() {
                return Err(invalid_args(
                    "oracle_diff profile_a and profile_b must be non-empty profile names",
                ));
            }
            if profile_a.eq_ignore_ascii_case(profile_b) && scn_a == scn_b {
                return Err(invalid_args(
                    "oracle_diff was asked to compare a database against itself at the same point \
                     in time; name two profiles, or two SCNs, so the delta can mean something",
                ));
            }
            Ok(DiffMode::Fleet {
                profile_a: profile_a.to_owned(),
                scn_a,
                profile_b: profile_b.to_owned(),
                scn_b,
            })
        }
        _ => Err(invalid_args(
            "oracle_diff cross-database mode needs both profile_a and profile_b",
        )),
    }
}

/// Name the side and profile a cross-database failure came from.
///
/// A cross-database diff cannot degrade to a partial answer: if one database is
/// unreachable there is no delta to report, and an empty delta would assert that
/// the two databases agree. So the whole call fails, saying exactly which side
/// failed and why.
fn diff_side_failure(side: DiffSide, profile: &str, error: ErrorEnvelope) -> ErrorEnvelope {
    let mut error = error;
    error.message = format!(
        "oracle_diff side {} (profile `{profile}`) failed, so no delta can be reported: {}",
        side.label(),
        error.message
    );
    error
}

/// Refuse a cross-database diff whose two sides do not return the same columns.
fn diff_shape_mismatch(
    profile_a: &str,
    columns_a: &[String],
    profile_b: &str,
    columns_b: &[String],
) -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorClass::InvalidArguments,
        format!(
            "oracle_diff cannot compare two databases whose result shapes differ: \
             `{profile_a}` returned [{}] and `{profile_b}` returned [{}]",
            columns_a.join(", "),
            columns_b.join(", "),
        ),
    )
    .with_next_step(
        "project the columns explicitly in the SELECT so both databases return the same shape, \
         or reconcile the schema drift between the two profiles",
    )
}

/// Render one incomparable column as `COLUMN (why)` for a refusal message.
fn incomparable_column_detail(entry: &IncomparableMaskedColumn) -> String {
    let reason = match &entry.reason {
        MaskComparabilityBreak::ValueDestroyed { action } => format!(
            "both profiles apply {}, which collapses distinct values",
            masking_action_label(*action)
        ),
        MaskComparabilityBreak::ActionMismatch { a, b } => format!(
            "masking policy has drifted: `{}` on side a, `{}` on side b",
            masking_action_label(*a),
            masking_action_label(*b)
        ),
        MaskComparabilityBreak::SaltMismatch { a, b } => match (a, b) {
            (Some(a), Some(b)) => format!("tokenized under different salts (`{a}` vs `{b}`)"),
            _ => "tokenized without an active salt on both sides".to_owned(),
        },
        MaskComparabilityBreak::DecisionMissing => {
            "the mask certificate carries no decision for this column".to_owned()
        }
        // A masking break we do not have words for yet is still a break: refuse
        // it rather than describe it away.
        _ => "the egress mask does not preserve equality for this column".to_owned(),
    };
    format!("{} ({reason})", entry.column)
}

fn masking_action_label(action: ResultMaskingDecisionAction) -> &'static str {
    match action {
        ResultMaskingDecisionAction::Pass => "pass",
        ResultMaskingDecisionAction::Mask => "mask",
        ResultMaskingDecisionAction::Tokenize => "tokenize",
        ResultMaskingDecisionAction::Null => "null",
        _ => "an unrecognized masking action",
    }
}

/// Refuse a cross-database diff whose masked columns cannot be soundly compared.
///
/// Egress masking is applied per profile, and the diff compares the **masked**
/// rows — plaintext of a masked column never enters the comparison. That only
/// proves anything when the masked form preserves equality (both sides pass, or
/// both tokenize under one salt). Otherwise the honest answer is a refusal: a
/// `mask`ed column collapses every value to the same marker, so comparing it
/// would report "unchanged" for rows that really differ.
fn diff_incomparable_masking(
    profile_a: &str,
    profile_b: &str,
    incomparable: &[IncomparableMaskedColumn],
) -> ErrorEnvelope {
    let columns = incomparable
        .iter()
        .map(incomparable_column_detail)
        .collect::<Vec<_>>()
        .join("; ");
    ErrorEnvelope::new(
        ErrorClass::PolicyDenied,
        format!(
            "oracle_diff cannot compare masked columns across `{profile_a}` and `{profile_b}`: \
             the egress mask does not preserve equality for {columns}. A delta over these columns \
             would be wrong, not merely redacted",
        ),
    )
    .with_next_step(
        "select only columns both profiles pass through, or give the two profiles one shared \
         tokenization salt so equal values tokenize equally",
    )
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
        Some(ReasonCategory::TransactionControl) => decision.safe_alternative.clone(),
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

fn query_cost_plan_gate_error(gate: LevelDecision, session: &SessionLevelState) -> ErrorEnvelope {
    gate_error(
        gate,
        session,
        &GateErrorLabels {
            subject: "oracle_query cost gate PLAN_TABLE diagnostic write",
            step_up_tool: "oracle_set_session_level",
            step_up_inspect_step: "call oracle_set_session_level without execute=true to preview a READ_WRITE elevation",
            step_up_elevation_step: "retry oracle_query with allow_plan_table_write=true only after the session is at READ_WRITE",
            ceiling_step: "choose a profile whose max_level permits READ_WRITE, or remove max_query_cost so oracle_query does not need a PLAN_TABLE diagnostic write",
            policy_denied_message: "oracle_query cost gate PLAN_TABLE diagnostic write is blocked by policy",
            internal_message: "oracle_query cost gate produced an unexpected PLAN_TABLE gate decision",
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

fn ensure_query_cost_plan_write_allowed(
    args: &QueryArgs,
    session: &SessionLevelState,
) -> Result<(), ErrorEnvelope> {
    if args.read_only_standby {
        return Err(ErrorEnvelope::new(
            ErrorClass::PolicyDenied,
            "oracle_query max_query_cost requires EXPLAIN PLAN, which writes PLAN_TABLE and is disabled on a read-only standby",
        )
        .with_next_step("remove max_query_cost for this call/profile, or use DBMS_XPLAN.DISPLAY_CURSOR against an existing cursor"));
    }

    if !args.allow_plan_table_write {
        return Err(ErrorEnvelope::new(
            ErrorClass::PolicyDenied,
            "oracle_query max_query_cost requires EXPLAIN PLAN, which writes PLAN_TABLE; pass allow_plan_table_write=true only when a diagnostic write is acceptable",
        )
        .with_suggested_tool("oracle_set_session_level")
        .with_next_step("call oracle_preview_sql first if you only need to verify the SQL is read-only")
        .with_next_step("for primary databases where PLAN_TABLE writes are acceptable, elevate to READ_WRITE and retry oracle_query with allow_plan_table_write=true"));
    }

    let gate = session.evaluate(Some(OperatingLevel::ReadWrite));
    if matches!(gate, LevelDecision::Allow) {
        Ok(())
    } else {
        Err(query_cost_plan_gate_error(gate, session))
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
    decision: &GuardDecision,
    gate: &LevelDecision,
    confirm: Option<&str>,
) -> Value {
    if decision.query_effect_requires_fetch {
        return Value::Null;
    }
    let Some(required_level) = decision.required_level else {
        return Value::Null;
    };
    let Some(confirm) = confirm else {
        return Value::Null;
    };
    if required_level <= OperatingLevel::ReadOnly || !matches!(gate, LevelDecision::Allow) {
        return Value::Null;
    }
    if decision.non_transactional_effect && required_level < OperatingLevel::Ddl {
        json!({
            "tool": "oracle_execute",
            "confirm": confirm,
            "commit": false,
            "required_level": required_level,
            "note": "This statement has a permanent or session-persistent effect even though the surrounding transaction is rolled back; pass confirm only when you intend that effect.",
        })
    } else {
        json!({
            "tool": "oracle_execute",
            "confirm": confirm,
            "commit": true,
            "required_level": required_level,
            "note": "Pass confirm only when you intend to commit this exact statement on this active profile.",
        })
    }
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
        LevelDecision::Allow if decision.query_effect_requires_fetch => {
            actions.push(json!({
                "intent": "rewrite_sql",
                "message": "Query-shaped NEXTVAL is refused because oracle_execute does not fetch query rows; use NEXTVAL inside governed DML or PL/SQL instead."
            }));
        }
        LevelDecision::Allow => match decision.required_level {
            Some(level) if level <= OperatingLevel::ReadOnly => {
                actions.push(json!({
                    "intent": "run_read",
                    "tool": "oracle_query",
                    "args": { "sql": sql, "binds": [] },
                }));
            }
            Some(level) if level < OperatingLevel::Ddl => {
                if decision.non_transactional_effect {
                    if let Some(confirm) = confirm {
                        actions.push(json!({
                            "intent": "execute_non_transactional_effect",
                            "tool": "oracle_execute",
                            "args": {
                                "sql": sql,
                                "binds": [],
                                "commit": false,
                                "confirm": confirm,
                            },
                            "note": "The surrounding transaction rolls back, but this statement's non-transactional effect persists.",
                        }));
                    }
                } else {
                    actions.push(json!({
                        "intent": "rollback_preview",
                        "tool": "oracle_execute",
                        "args": { "sql": sql, "binds": [], "commit": false },
                    }));
                }
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
    non_transactional_effect: bool,
) -> Result<String, ErrorEnvelope> {
    let (challenge_message, next_step) = if non_transactional_effect {
        (
            "the statement has a non-transactional effect that persists even when rollback is requested; execution requires the single-use grant from oracle_preview_sql",
            "call oracle_preview_sql with the exact sql, then pass execute_confirmation.confirm; commit=false still rolls back any surrounding transactional work",
        )
    } else {
        (
            "commit requires the execution grant from oracle_preview_sql for this exact statement, lane, principal, and active profile",
            "call oracle_preview_sql with the exact sql, then pass execute_confirmation.confirm as confirm",
        )
    };
    consume_confirmation_grant(ConfirmationGrantRequest {
        material: sql,
        required_level,
        active_profile,
        grants,
        binding,
        confirm,
        challenge_message,
        suggested_tool: "oracle_preview_sql",
        next_step,
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
            // The compat alias replays a previewed statement; the reversible
            // workspace is offered on oracle_execute only.
            hold: false,
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
        hold: false,
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

#[derive(Clone)]
struct DbToolCtx<'a> {
    cx: &'a Cx,
    conn: &'a dyn OracleConnection,
    read_only_backstop: &'a ReadOnlyBackstop,
    /// Arc I: the pinned session's reversible workspace. Every write path
    /// consults it before committing and clears it at its transaction boundary.
    checkpoints: &'a CheckpointWorkspace,
    request_budget: RequestBudget,
    active_profile: Option<&'a str>,
    session: &'a SessionLevelState,
    execute_grants: &'a ExecGrantStore,
    grant_binding: &'a ExecGrantBinding,
    write_intents: Option<&'a WriteIntentLog>,
    catalog_cache: &'a OracleCatalogResolverCache,
    audit: AuditCtx<'a>,
    quarantine: &'a SyncMutex<Option<ConnectionQuarantine>>,
}

/// End the real Oracle read-only transaction before the first governed write.
///
/// `ReadOnlyBackstop::disarm` alone cannot change Oracle transaction state. A
/// failed rollback means the session cannot prove whether it crossed the
/// boundary, so fail before executing the approved statement and quarantine it.
async fn clear_read_only_transaction_before_write(
    ctx: &DbToolCtx<'_>,
) -> Result<(), ErrorEnvelope> {
    match ctx
        .read_only_backstop
        .clear_before_write(ctx.cx, ctx.conn)
        .await
    {
        // A disarmed backstop crosses no transaction boundary — and a held
        // statement's whole point is to land inside the transaction the
        // workspace's savepoints live in, so this must not touch them.
        Ok(false) => {}
        // It rolled back, so Oracle erased every savepoint with the
        // transaction (Arc I). The belief must never outlive them.
        Ok(true) => ctx.checkpoints.clear(),
        Err(error) => {
            let message = format!(
                "could not end the armed read-only transaction before the governed write; the approved statement was not executed and the session was quarantined: {error}"
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
    }
    // The rollback finalizer deliberately has a fresh cleanup budget. Re-check
    // the original request after it completes so a slow transition cannot let
    // the approved effect start after the caller's total budget expired.
    ctx.request_budget
        .enforce(ctx.cx)
        .map_err(DbError::into_envelope)
}

/// Arc I: refuse an operation that would end the pinned transaction while the
/// reversible workspace is open.
///
/// Two different failures hide behind one rule:
///
/// - **Safety.** `COMMIT` is transaction-wide. A held statement never passed the
///   single-use grant (it is reversible, so it does not need one), and Oracle
///   commits DDL/Admin *implicitly*. Without this refusal, an agent could hold
///   arbitrary ungranted DML and then ride any confirmed statement's commit into
///   permanence — the guard's "never auto-commit DML" invariant, defeated by the
///   transaction's own semantics rather than by a classifier gap.
/// - **Honesty.** The diagnostic paths whose cleanup rolls the transaction back
///   (EXPLAIN PLAN / `PLAN_TABLE` cost estimation, the flashback session reset)
///   would silently destroy held work and erase every savepoint. Refusing beats
///   discarding an agent's uncommitted work without telling it.
///
/// Committing held work needs a gate that re-classifies the exact statements at
/// commit time (SEC-1); until that lands, the only way out of the workspace is
/// `oracle_undo_to`.
fn ensure_workspace_closed(
    workspace: &CheckpointWorkspace,
    operation: &str,
) -> Result<(), ErrorEnvelope> {
    if !workspace.is_open() {
        return Ok(());
    }
    let held = workspace.held_statements();
    Err(ErrorEnvelope::new(
        ErrorClass::PolicyDenied,
        format!(
            "{operation} would end the transaction, and the reversible workspace is open with {held} held statement(s) across {} live checkpoint(s); held work is uncommitted and must not be committed or silently discarded by another operation",
            workspace.view()["checkpoints"]
                .as_array()
                .map_or(0, Vec::len)
        ),
    )
    .with_suggested_tool("oracle_undo_to")
    .with_next_step(
        "call oracle_undo_to with a checkpoint to walk the held work back, or with no name to discard the whole workspace",
    )
    .with_next_step("then retry this call on the closed workspace"))
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
        result_masking: None,
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

/// Collect identity evidence for a read path without erasing an uncertain
/// session boundary. Ordinary metadata/privilege failures remain observational
/// and degrade to an unavailable marker; cancellation or connection ambiguity
/// must stop the active call so its ownership-aware wrapper can quarantine the
/// retained physical session.
async fn collect_read_audit_db_evidence(
    cx: &Cx,
    auditor: Option<&Auditor>,
    conn: &dyn OracleConnection,
) -> Result<Option<DbEvidence>, ErrorEnvelope> {
    let Some(_) = auditor else {
        return Ok(None);
    };
    match conn.describe(cx).await {
        Ok(info) => Ok(Some(db_evidence_from_connection_info(info))),
        Err(err) if err.is_uncertain_session_state() => Err(DbError::into_envelope(err)),
        Err(_) => Ok(Some(DbEvidence::unavailable("describe_failed"))),
    }
}

/// Mutation preflight may degrade an ordinary metadata/privilege failure, but
/// cancellation or a structurally uncertain session cannot be relabelled as
/// harmless "evidence unavailable" and followed by a write.
async fn collect_effect_audit_db_evidence(
    ctx: &DbToolCtx<'_>,
) -> Result<Option<DbEvidence>, ErrorEnvelope> {
    collect_effect_audit_db_evidence_for_conn(ctx.cx, ctx.audit.auditor, ctx.conn, ctx.quarantine)
        .await
}

async fn collect_effect_audit_db_evidence_for_conn(
    cx: &Cx,
    auditor: Option<&Auditor>,
    conn: &dyn OracleConnection,
    quarantine: &SyncMutex<Option<ConnectionQuarantine>>,
) -> Result<Option<DbEvidence>, ErrorEnvelope> {
    let Some(_) = auditor else {
        return Ok(None);
    };
    match conn.describe(cx).await {
        Ok(info) => Ok(Some(db_evidence_from_connection_info(info))),
        Err(err) if err.is_uncertain_session_state() => {
            let message = format!(
                "database audit-evidence preflight failed at an uncertain boundary; no statement was executed: {err}"
            );
            mark_connection_quarantined(
                quarantine,
                AuditOutcome::UnknownDiscarded,
                message.clone(),
            )?;
            Err(quarantined_db_error(QuarantineOutcome::UnknownDiscarded, message).into_envelope())
        }
        Err(_) => Ok(Some(DbEvidence::unavailable("describe_failed"))),
    }
}

/// Capture pre-effect audit identity under the same absolute request deadline
/// and shared quota as the operation it governs. This is needed by early
/// session-state arms, which return before the dispatch-wide connection guards
/// are installed.
async fn collect_effect_audit_db_evidence_bounded(
    cx: &Cx,
    auditor: Option<&Auditor>,
    conn: &dyn OracleConnection,
    request_budget: &RequestBudget,
    quarantine: &SyncMutex<Option<ConnectionQuarantine>>,
) -> Result<Option<DbEvidence>, ErrorEnvelope> {
    if auditor.is_none() {
        return Ok(None);
    }
    request_budget.enforce(cx).map_err(DbError::into_envelope)?;
    let limits = ConnectionLimitGuard::install(
        cx,
        conn,
        Some(quarantine),
        None,
        request_budget.deadline(),
        Some(request_budget.db_quota()),
    )
    .map_err(DbError::into_envelope)?;
    let result = collect_effect_audit_db_evidence_for_conn(cx, auditor, conn, quarantine).await;
    let budget_after = request_budget.enforce(cx).map_err(DbError::into_envelope);
    let restore_error = limits.restore().err();

    let evidence = match result {
        Ok(evidence) => evidence,
        Err(primary) => {
            if let Some(restore_error) = restore_error {
                let _ = mark_connection_quarantined(
                    quarantine,
                    AuditOutcome::UnknownDiscarded,
                    format!(
                        "audit-evidence preflight failed and request-limit restoration also failed: {restore_error}"
                    ),
                );
            }
            return Err(primary);
        }
    };
    if let Some(restore_error) = restore_error {
        return Err(limit_restore_failure(quarantine, false, restore_error));
    }
    budget_after?;
    Ok(evidence)
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
    append_audit_with_observed_scn(ctx, tool, sql, danger_level, rows_affected, outcome, None)
}

/// Durably append one audit entry, optionally binding it to an observed read
/// snapshot. The normal execute paths deliberately pass `None`; only read
/// paths may supply an SCN.
fn append_audit_with_observed_scn(
    ctx: AuditEntryCtx<'_>,
    tool: &str,
    sql: &str,
    danger_level: &str,
    rows_affected: Option<u64>,
    outcome: AuditOutcome,
    observed_scn: Option<u64>,
) -> Result<(), ErrorEnvelope> {
    if let Some(auditor) = ctx.auditor {
        let draft = audit_draft(ctx, tool, sql, danger_level, rows_affected, outcome);
        auditor
            .append_correlated_with_observed_scn(
                &draft,
                audit_timestamp(),
                true,
                None,
                observed_scn,
            )
            .map_err(audit_error_to_envelope)?;
    }
    Ok(())
}

fn audit_masking_action(action: ResultMaskingDecisionAction) -> AuditResultMaskingAction {
    match action {
        ResultMaskingDecisionAction::Pass => AuditResultMaskingAction::Pass,
        ResultMaskingDecisionAction::Mask => AuditResultMaskingAction::Mask,
        ResultMaskingDecisionAction::Tokenize => AuditResultMaskingAction::Tokenize,
        ResultMaskingDecisionAction::Null => AuditResultMaskingAction::Null,
        _ => AuditResultMaskingAction::Mask,
    }
}

fn audit_masking_source(source: ResultMaskingDecisionSource) -> AuditResultMaskingSource {
    match source {
        ResultMaskingDecisionSource::Rule => AuditResultMaskingSource::Rule,
        ResultMaskingDecisionSource::MaskUnknownDefault => {
            AuditResultMaskingSource::MaskUnknownDefault
        }
        ResultMaskingDecisionSource::Pass => AuditResultMaskingSource::Pass,
        _ => AuditResultMaskingSource::MaskUnknownDefault,
    }
}

fn audit_result_masking_certificate(
    certificate: &ResultMaskingCertificate,
) -> AuditResultMaskingCertificate {
    AuditResultMaskingCertificate {
        schema_version: certificate.schema_version,
        profile: certificate.profile.clone(),
        policy_id: certificate.policy_id.clone(),
        decisions: certificate
            .decisions
            .iter()
            .map(|decision| AuditResultMaskingColumnDecision {
                column: decision.column.clone(),
                oracle_type: decision.oracle_type.clone(),
                action: audit_masking_action(decision.action),
                source: audit_masking_source(decision.source),
                rule_index: decision.rule_index,
                rule_tag: decision.rule_tag.clone(),
                salt_id: decision.salt_id.clone(),
            })
            .collect(),
    }
}

/// Durably record one phase of an `oracle_query` read with its replay SCN.
///
/// The pending record is written before the data query is issued, so an audit
/// failure refuses the agent-visible read. The terminal record binds any result
/// masking certificate to the same replayable snapshot before rows leave the
/// process.
fn append_query_read_audit(
    ctx: AuditEntryCtx<'_>,
    tool: &str,
    sql: &str,
    observed_scn: u64,
    outcome: AuditOutcome,
    response: Option<&mut QueryResponse>,
) -> Result<(), ErrorEnvelope> {
    let Some(auditor) = ctx.auditor else {
        return Ok(());
    };
    let result_masking = response.as_ref().and_then(|response| {
        response
            .mask_certificate
            .as_ref()
            .map(audit_result_masking_certificate)
    });
    let rows_affected = response.as_ref().map(|response| response.row_count as u64);
    let draft = AuditEntryDraft {
        subject: ctx.subject.clone(),
        db_evidence: ctx.db_evidence.cloned(),
        cancel: None,
        result_masking,
        tool: tool.to_owned(),
        sql: sql.to_owned(),
        danger_level: "READ_ONLY".to_owned(),
        decision: AuditDecision::Allowed,
        rows_affected,
        outcome,
    };
    let record = auditor
        .append_correlated_with_observed_scn(
            &draft,
            audit_timestamp(),
            true,
            None,
            Some(observed_scn),
        )
        .map_err(audit_error_to_envelope)?;
    if let Some(certificate) = response.and_then(|response| response.mask_certificate.as_mut()) {
        certificate.audit_entry_hash = Some(record.entry_hash);
    }
    Ok(())
}

/// Bind a masking certificate for read paths that materialize a result before
/// this dispatcher can establish a replay SCN (for example an export or a
/// two-sided diff). These paths retain their existing fail-closed certificate
/// contract; the ordinary `oracle_query` path uses [`append_query_read_audit`]
/// above, which records both phases with the exact SCN.
fn append_result_masking_audit(
    ctx: AuditEntryCtx<'_>,
    tool: &str,
    sql: &str,
    response: &mut QueryResponse,
) -> Result<(), ErrorEnvelope> {
    let Some(certificate) = response.mask_certificate.as_mut() else {
        return Ok(());
    };
    let Some(auditor) = ctx.auditor else {
        return Err(ErrorEnvelope::new(
            ErrorClass::RuntimeStateRequired,
            "result masking is active but no audit sink is configured; refusing to return a \
             masked result without hash-chain binding",
        )
        .with_next_step("configure audit logging, or disable result masking for this profile"));
    };
    let draft = AuditEntryDraft {
        subject: ctx.subject.clone(),
        db_evidence: ctx.db_evidence.cloned(),
        cancel: None,
        result_masking: Some(audit_result_masking_certificate(certificate)),
        tool: tool.to_owned(),
        sql: sql.to_owned(),
        danger_level: "READ_ONLY".to_owned(),
        decision: AuditDecision::Allowed,
        rows_affected: Some(response.row_count as u64),
        outcome: AuditOutcome::Succeeded,
    };
    let record = auditor
        .append(&draft, audit_timestamp(), true)
        .map_err(audit_error_to_envelope)?;
    certificate.audit_entry_hash = Some(record.entry_hash);
    Ok(())
}

async fn bind_result_masking_audit(
    cx: &Cx,
    conn: &dyn OracleConnection,
    auditor: Option<&Auditor>,
    subject: &AuditSubject,
    tool: &str,
    sql: &str,
    response: &mut QueryResponse,
) -> Result<(), ErrorEnvelope> {
    if response.mask_certificate.is_none() {
        return Ok(());
    }
    let Some(auditor) = auditor else {
        return append_result_masking_audit(
            AuditEntryCtx {
                auditor: None,
                subject,
                db_evidence: None,
            },
            tool,
            sql,
            response,
        );
    };
    let db_evidence = collect_read_audit_db_evidence(cx, Some(auditor), conn).await?;
    append_result_masking_audit(
        AuditEntryCtx {
            auditor: Some(auditor),
            subject,
            db_evidence: db_evidence.as_ref(),
        },
        tool,
        sql,
        response,
    )
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
            | "oracle_orient"
            | "oracle_list_schemas"
            | "oracle_describe"
            | "oracle_describe_index"
            | "oracle_describe_trigger"
            | "oracle_describe_view"
            | "oracle_get_ddl"
            | "oracle_get_source"
            | "oracle_sample_rows"
            | "oracle_top_queries"
            | "oracle_plan_timeline"
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
        "oracle_sample_rows"
            | "oracle_top_queries"
            | "oracle_plan_timeline"
            | "oracle_db_health"
            | "oracle_read_clob"
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

/// Observe read failures at the connection-ownership boundary.
///
/// A dispatcher-owned primary connection is retained across calls, so an
/// uncertain read failure must quarantine that physical session. A stateless
/// [`OraclePool`] owns and dirty-discards the failed checkout itself; poisoning
/// the dispatcher's unrelated primary session would be both unnecessary and
/// incorrect. Keeping that distinction in this decorator prevents individual
/// read helpers from silently choosing different reuse semantics.
struct ReadUncertaintyConn<'a> {
    inner: &'a dyn OracleConnection,
    quarantine: Option<&'a SyncMutex<Option<ConnectionQuarantine>>>,
}

impl ReadUncertaintyConn<'_> {
    fn observe<T>(&self, operation: &str, result: Result<T, DbError>) -> Result<T, DbError> {
        let Err(err) = result else {
            return result;
        };
        if err.is_uncertain_session_state()
            && let Some(quarantine) = self.quarantine
            && let Err(mark_err) = mark_connection_quarantined(
                quarantine,
                AuditOutcome::UnknownDiscarded,
                format!("{operation} failed at an uncertain read boundary: {err}"),
            )
        {
            return Err(db_internal_from_envelope(mark_err));
        }
        Err(err)
    }
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for ReadUncertaintyConn<'_> {
    fn backend(&self) -> OracleBackend {
        self.inner.backend()
    }

    async fn ping(&self, cx: &Cx) -> Result<(), DbError> {
        self.observe("database ping", self.inner.ping(cx).await)
    }

    async fn describe(&self, cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        self.observe("database describe", self.inner.describe(cx).await)
    }

    async fn query_rows(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        self.observe("query", self.inner.query_rows(cx, sql, binds).await)
    }

    async fn query_rows_with_serialize_options(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
        serialize_opts: &SerializeOptions,
    ) -> Result<Vec<OracleRow>, DbError> {
        self.observe(
            "query",
            self.inner
                .query_rows_with_serialize_options(cx, sql, binds, serialize_opts)
                .await,
        )
    }

    async fn query_row_stream(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
        arraysize: usize,
        serialize_opts: &SerializeOptions,
    ) -> Result<QueryRowStreamStart, DbError> {
        self.observe(
            "row stream startup",
            self.inner
                .query_row_stream(cx, sql, binds, arraysize, serialize_opts)
                .await,
        )
    }

    async fn query_rows_named(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[(String, OracleBind)],
    ) -> Result<Vec<OracleRow>, DbError> {
        self.observe(
            "named-bind query",
            self.inner.query_rows_named(cx, sql, binds).await,
        )
    }

    async fn query_rows_named_with_serialize_options(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[(String, OracleBind)],
        serialize_opts: &SerializeOptions,
    ) -> Result<Vec<OracleRow>, DbError> {
        self.observe(
            "named-bind query",
            self.inner
                .query_rows_named_with_serialize_options(cx, sql, binds, serialize_opts)
                .await,
        )
    }

    async fn query_optional_row(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Option<OracleRow>, DbError> {
        self.observe(
            "optional-row query",
            self.inner.query_optional_row(cx, sql, binds).await,
        )
    }

    async fn execute(&self, cx: &Cx, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError> {
        self.inner.execute(cx, sql, binds).await
    }

    async fn commit(&self, cx: &Cx) -> Result<(), DbError> {
        self.inner.commit(cx).await
    }

    async fn rollback(&self, cx: &Cx) -> Result<(), DbError> {
        self.inner.rollback(cx).await
    }

    fn call_timeout(&self) -> Result<Option<Duration>, DbError> {
        self.inner.call_timeout()
    }

    fn set_call_timeout(&self, timeout: Option<Duration>) -> Result<(), DbError> {
        self.inner.set_call_timeout(timeout)
    }

    fn request_deadline(&self, cx: &Cx) -> Result<Option<Time>, DbError> {
        self.inner.request_deadline(cx)
    }

    fn set_request_deadline(&self, cx: &Cx, deadline: Option<Time>) -> Result<(), DbError> {
        self.inner.set_request_deadline(cx, deadline)
    }

    fn request_quota(&self, cx: &Cx) -> Result<Option<DbRequestQuota>, DbError> {
        self.inner.request_quota(cx)
    }

    fn set_request_quota(&self, cx: &Cx, quota: Option<DbRequestQuota>) -> Result<(), DbError> {
        self.inner.set_request_quota(cx, quota)
    }

    async fn flashback_disable(&self, cx: &Cx) -> Result<(), DbError> {
        self.inner.flashback_disable(cx).await
    }
}

impl GuardedGeneratedReadConn<'_> {
    async fn before_query(&self, cx: &Cx, sql: &str) -> Result<(String, Option<u64>), DbError> {
        let danger = ensure_generated_read_sql_allowed(sql).map_err(db_internal_from_envelope)?;
        let danger = audit_danger_string(danger);
        let observed_scn = match self.audit.entry.auditor {
            Some(_) => Some(AsOf::current_system_change_number(cx, self.inner).await?),
            None => None,
        };
        append_audit_with_observed_scn(
            self.audit.entry,
            self.audit.tool,
            sql,
            &danger,
            None,
            AuditOutcome::Pending,
            observed_scn,
        )
        .map_err(db_internal_from_envelope)?;
        Ok((danger, observed_scn))
    }

    fn after_query(
        &self,
        sql: &str,
        danger: &str,
        outcome: AuditOutcome,
        observed_scn: Option<u64>,
    ) -> Result<(), DbError> {
        append_audit_with_observed_scn(
            self.audit.entry,
            self.audit.tool,
            sql,
            danger,
            None,
            outcome,
            observed_scn,
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
        let (danger, observed_scn) = self.before_query(cx, sql).await?;
        match self.inner.query_rows(cx, sql, binds).await {
            Ok(rows) => {
                self.after_query(sql, &danger, AuditOutcome::Succeeded, observed_scn)?;
                Ok(rows)
            }
            Err(err) => {
                self.after_query(sql, &danger, AuditOutcome::Failed, observed_scn)?;
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
        let (danger, observed_scn) = self.before_query(cx, sql).await?;
        match self
            .inner
            .query_rows_with_serialize_options(cx, sql, binds, serialize_opts)
            .await
        {
            Ok(rows) => {
                self.after_query(sql, &danger, AuditOutcome::Succeeded, observed_scn)?;
                Ok(rows)
            }
            Err(err) => {
                self.after_query(sql, &danger, AuditOutcome::Failed, observed_scn)?;
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
        let (danger, observed_scn) = self.before_query(cx, sql).await?;
        match self.inner.query_rows_named(cx, sql, binds).await {
            Ok(rows) => {
                self.after_query(sql, &danger, AuditOutcome::Succeeded, observed_scn)?;
                Ok(rows)
            }
            Err(err) => {
                self.after_query(sql, &danger, AuditOutcome::Failed, observed_scn)?;
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
        let (danger, observed_scn) = self.before_query(cx, sql).await?;
        match self
            .inner
            .query_rows_named_with_serialize_options(cx, sql, binds, serialize_opts)
            .await
        {
            Ok(rows) => {
                self.after_query(sql, &danger, AuditOutcome::Succeeded, observed_scn)?;
                Ok(rows)
            }
            Err(err) => {
                self.after_query(sql, &danger, AuditOutcome::Failed, observed_scn)?;
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
        let (danger, observed_scn) = self.before_query(cx, sql).await?;
        match self.inner.query_optional_row(cx, sql, binds).await {
            Ok(row) => {
                self.after_query(sql, &danger, AuditOutcome::Succeeded, observed_scn)?;
                Ok(row)
            }
            Err(err) => {
                self.after_query(sql, &danger, AuditOutcome::Failed, observed_scn)?;
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
        DispatchCloseReason::Timeout | DispatchCloseReason::RequestFinalizationTimeout => "Timeout",
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
            result_masking: None,
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
    db_outcome: AuditOutcome,
    boundary: &str,
) -> Result<(), ErrorEnvelope> {
    if let Err(err) = resolve_write_intent(ctx, intent_id, outcome) {
        let message = format!(
            "{boundary}; database outcome is {}, but durable write-intent resolution failed; do not retry the database operation: {}",
            audit_outcome_label(db_outcome),
            err.message
        );
        mark_connection_quarantined(ctx.quarantine, db_outcome, message.clone())?;
        return Err(
            ErrorEnvelope::new(ErrorClass::RuntimeStateRequired, message)
                .with_next_step("switch to a fresh profile connection or restart the server")
                .with_next_step("verify the recorded database outcome before issuing any retry"),
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
        AuditOutcome::HeldUncommitted => "held_uncommitted",
        AuditOutcome::DiscardedUncommitted => "discarded_uncommitted",
        AuditOutcome::CommitInDoubt => "commit_in_doubt",
        AuditOutcome::UnknownDiscarded => "unknown_discarded",
        _ => "unknown",
    }
}

fn append_terminal_audit(
    ctx: &DbToolCtx<'_>,
    audit_entry: AuditEntryCtx<'_>,
    tool: &str,
    sql: &str,
    danger_level: &str,
    rows_affected: Option<u64>,
    outcome: AuditOutcome,
) -> Result<(), ErrorEnvelope> {
    if let Err(err) = append_audit(audit_entry, tool, sql, danger_level, rows_affected, outcome) {
        let message = format!(
            "database outcome is {}, but mandatory terminal audit finalization failed; do not retry the database operation: {}",
            audit_outcome_label(outcome),
            err.message
        );
        mark_connection_quarantined(ctx.quarantine, outcome, message.clone())?;
        return Err(
            ErrorEnvelope::new(ErrorClass::RuntimeStateRequired, message)
                .with_next_step("switch to a fresh profile connection or restart the server")
                .with_next_step(
                    "verify the database outcome and repair the audit sink before retrying",
                ),
        );
    }
    Ok(())
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
    let message = message.into();
    if let Some(existing) = guard.as_mut() {
        let preserve_existing = match existing.outcome {
            // These outcomes all forbid retry and carry stronger/more specific
            // terminal knowledge than a later cleanup, restore, or audit-sink
            // failure. Never downgrade them with a secondary `Failed` or
            // `RolledBack` classification.
            AuditOutcome::CommitInDoubt | AuditOutcome::Succeeded => true,
            AuditOutcome::UnknownDiscarded => outcome != AuditOutcome::CommitInDoubt,
            _ => false,
        };
        if preserve_existing {
            existing
                .message
                .push_str(&format!("; additional quarantine evidence: {message}"));
            return Ok(());
        }
    }
    *guard = Some(ConnectionQuarantine { outcome, message });
    Ok(())
}

fn quarantined_db_error(outcome: QuarantineOutcome, message: impl Into<String>) -> DbError {
    DbError::Quarantined {
        outcome,
        message: message.into(),
    }
}

/// Classify why a statement invalidates dictionary resolution evidence.
///
/// Every DDL/Admin call advances the generation regardless of this label. The
/// narrower reasons also identify lower-level session-context mutations (for
/// example `CURRENT_SCHEMA`) that must invalidate without a DDL floor.
fn catalog_invalidation_for_sql(sql: &str) -> CatalogInvalidation {
    let sql = sql.trim_start().to_ascii_uppercase();
    if sql.starts_with("ALTER SESSION") && sql.contains("CURRENT_SCHEMA") {
        CatalogInvalidation::CurrentSchema
    } else if sql.starts_with("ALTER SESSION") && sql.contains("EDITION") {
        CatalogInvalidation::Edition
    } else if sql.contains("SYNONYM") {
        CatalogInvalidation::Synonym
    } else if sql.starts_with("SET ROLE") || sql.starts_with("GRANT ") || sql.starts_with("REVOKE ")
    {
        CatalogInvalidation::Roles
    } else if sql.contains("PACKAGE") || sql.contains(" TYPE ") {
        CatalogInvalidation::Package
    } else if sql.contains("PROCEDURE") || sql.contains("FUNCTION") {
        CatalogInvalidation::Overload
    } else {
        CatalogInvalidation::Ddl
    }
}

fn catalog_invalidation_for_object_type(object_type: &str) -> CatalogInvalidation {
    match object_type {
        "PACKAGE" | "PACKAGE BODY" | "TYPE" | "TYPE BODY" => CatalogInvalidation::Package,
        "PROCEDURE" | "FUNCTION" => CatalogInvalidation::Overload,
        _ => CatalogInvalidation::Ddl,
    }
}

fn quarantine_uncertain_optional_diagnostic(
    quarantine: &SyncMutex<Option<ConnectionQuarantine>>,
    label: &str,
    completed_outcome: AuditOutcome,
    err: &DbError,
) {
    if !err.is_uncertain_session_state() {
        return;
    }
    let message = format!(
        "database outcome is {}, but optional {label} failed at an uncertain session boundary: {err}",
        audit_outcome_label(completed_outcome)
    );
    if let Err(lock_err) = mark_connection_quarantined(quarantine, completed_outcome, message) {
        tracing::error!(error = %lock_err.message, "could not record quarantine after optional diagnostic failure");
    }
}

/// The reversible workspace is a *write* surface: it only exists to make DML
/// undoable, so it needs the same `READ_WRITE` floor the DML does. A `protected`
/// or `READ_ONLY`-ceilinged profile can never open one.
fn ensure_workspace_level(session: &SessionLevelState, tool: &str) -> Result<(), ErrorEnvelope> {
    if session.effective_level() >= OperatingLevel::ReadWrite {
        return Ok(());
    }
    let ceiling = session.effective_ceiling();
    let mut envelope = ErrorEnvelope::new(
        ErrorClass::OperatingLevelTooLow,
        format!(
            "{tool} needs READ_WRITE — the reversible workspace exists to make DML undoable — and this session is at {}",
            session.effective_level().as_str()
        ),
    );
    if ceiling < OperatingLevel::ReadWrite {
        envelope.message.push_str(&format!(
            "; the profile ceiling {} cannot be raised",
            ceiling.as_str()
        ));
        return Err(envelope);
    }
    Err(envelope
        .with_suggested_tool("oracle_set_session_level")
        .with_next_step("elevate with oracle_set_session_level to READ_WRITE, then retry"))
}

/// Run one server-generated transaction-control statement on the pinned session,
/// bracketed by the same durable pre/post audit records the governed write path
/// uses. `SAVEPOINT` / `ROLLBACK TO SAVEPOINT` are the statements the classifier
/// refuses from callers precisely because the server owns them; when the server
/// issues one, the audit chain must still show it.
async fn run_workspace_statement(
    ctx: &DbToolCtx<'_>,
    tool: &str,
    statement: &str,
) -> Result<(), ErrorEnvelope> {
    let danger = audit_danger_string(DangerLevel::Guarded);
    let db_evidence = collect_effect_audit_db_evidence(ctx).await?;
    let audit_entry = AuditEntryCtx {
        auditor: ctx.audit.auditor,
        subject: ctx.audit.subject,
        db_evidence: db_evidence.as_ref(),
    };
    append_audit(
        audit_entry,
        tool,
        statement,
        &danger,
        None,
        AuditOutcome::Pending,
    )?;
    match execute_conn(ctx.cx, ctx.conn, statement, &[] as &[OracleBind]).await {
        Ok(_) => {
            append_terminal_audit(
                ctx,
                audit_entry,
                tool,
                statement,
                &danger,
                None,
                AuditOutcome::Succeeded,
            )?;
            Ok(())
        }
        Err(error) => {
            // An uncertain boundary means we cannot prove whether Oracle moved
            // the savepoint stack, so the session is no longer trustworthy.
            let outcome = if error.is_uncertain_session_state() {
                mark_connection_quarantined(
                    ctx.quarantine,
                    AuditOutcome::UnknownDiscarded,
                    format!("{tool} failed at an uncertain database boundary: {error}"),
                )?;
                AuditOutcome::UnknownDiscarded
            } else {
                AuditOutcome::Failed
            };
            let terminal =
                append_terminal_audit(ctx, audit_entry, tool, statement, &danger, None, outcome);
            if outcome == AuditOutcome::Failed {
                terminal?;
                return Err(DbError::into_envelope(error));
            }
            if let Err(audit_error) = terminal {
                tracing::error!(error = %audit_error.message, "terminal audit failed after an uncertain workspace statement");
            }
            Err(quarantined_db_error(
                QuarantineOutcome::UnknownDiscarded,
                format!("{tool} failed at an uncertain database boundary: {error}"),
            )
            .into_envelope())
        }
    }
}

/// `oracle_checkpoint` — establish a named `SAVEPOINT` on the pinned session,
/// opening (or extending) the reversible workspace.
async fn open_checkpoint(ctx: DbToolCtx<'_>, args: CheckpointArgs) -> Result<Value, ErrorEnvelope> {
    let name = workspace::validated_checkpoint_name(&args.name)?;
    ensure_workspace_level(ctx.session, "oracle_checkpoint")?;
    // Refuse duplicates and the stack cap before any database I/O.
    ctx.checkpoints.check_can_open(&name)?;
    // A savepoint is a write on the transaction. If an earlier read left this
    // session inside `SET TRANSACTION READ ONLY`, end that transaction first —
    // exactly as the governed write path does — or Oracle refuses the savepoint.
    clear_read_only_transaction_before_write(&ctx).await?;
    let statement = workspace::savepoint_statement(&name);
    run_workspace_statement(&ctx, "oracle_checkpoint", &statement).await?;
    // Oracle accepted it; only now is the checkpoint real.
    ctx.checkpoints.commit_open(&name);
    Ok(json!({
        "checkpoint": name,
        "statement": statement,
        "workspace": ctx.checkpoints.view(),
        "next_step": "run reversible DML with oracle_execute hold=true, then oracle_undo_to to walk it back",
    }))
}

/// `oracle_undo_to` — `ROLLBACK TO SAVEPOINT <name>`, or a full rollback that
/// discards the whole workspace when no name is given. Undo never commits.
async fn undo_to_checkpoint(ctx: DbToolCtx<'_>, args: UndoToArgs) -> Result<Value, ErrorEnvelope> {
    // Deliberately NO operating-level gate. Undo only ever *removes* effects, and
    // an elevation window can expire while work is held — refusing to let the
    // agent walk its own uncommitted work back would strand it above a workspace
    // it can no longer close. Lowering is always safe; that principle holds here.
    let Some(raw_name) = args.name else {
        // No target: discard the whole workspace with a full ROLLBACK. This is
        // the agent's way out — it undoes every held statement and releases
        // every checkpoint, which is what re-opens the committing paths.
        let discarded = ctx.checkpoints.held_statements();
        let released = ctx.checkpoints.view()["checkpoints"].clone();
        run_workspace_statement(&ctx, "oracle_undo_to", "ROLLBACK").await?;
        ctx.checkpoints.clear();
        return Ok(json!({
            "undone_to": Value::Null,
            "statement": "ROLLBACK",
            "discarded_statements": discarded,
            "released_checkpoints": released,
            "workspace": ctx.checkpoints.view(),
            "next_step": "the workspace is closed; committing operations are available again",
        }));
    };
    let name = workspace::validated_checkpoint_name(&raw_name)?;
    // Plan first: an unknown checkpoint is refused before any database I/O, and
    // the stack is only truncated once Oracle has accepted the rollback.
    let summary = ctx.checkpoints.plan_undo_to(&name)?;
    let statement = workspace::undo_statement(&name);
    run_workspace_statement(&ctx, "oracle_undo_to", &statement).await?;
    ctx.checkpoints.commit_undo_to(&name);
    Ok(json!({
        "undone_to": name,
        "statement": statement,
        "discarded_statements": summary.discarded_statements,
        "released_checkpoints": summary.released_checkpoints,
        "workspace": ctx.checkpoints.view(),
    }))
}

/// `oracle_preview_dml` — the dry run (Arc I / bead `.11.2`).
///
/// The sandbox is a savepoint the *server* owns: `SAVEPOINT OMCP_PREVIEW_DML` →
/// witness read → the DML → witness read → `ROLLBACK TO SAVEPOINT
/// OMCP_PREVIEW_DML`. Because the sandbox savepoint is the newest one, rolling
/// back to it restores the exact pre-preview state and leaves an agent's own
/// checkpoints — and any work held above them — untouched. When no workspace is
/// open the transaction is then ended outright, exactly as a `commit=false`
/// execute does, so a dry run never leaves an open transaction behind.
///
/// Three properties make this honest:
///
/// - **A dry run must not cause what it cannot undo.** A statement the classifier
///   proves has a non-transactional effect (sequence `NEXTVAL`) is *refused*, not
///   executed, and returned labeled `cannot_undo`. Autonomous transactions and
///   triggers can escape rollback without being provable from the text; the
///   response says so rather than implying a guarantee we cannot make.
/// - **The preview grants nothing.** It mints no confirmation and consumes none.
///   Committing the change afterwards goes through `oracle_execute`, which
///   re-classifies and re-gates the exact statement (SEC-1) — a previewed verdict
///   is never trusted at commit time.
/// - **The witness is a real read.** It is proven read-only by the same
///   classifier as `oracle_query`, so "before/after" is never a hole through
///   which unproven SQL runs.
async fn preview_dml(ctx: DbToolCtx<'_>, args: PreviewDmlArgs) -> Result<Value, ErrorEnvelope> {
    let timeout_seconds = args.timeout_seconds;
    with_call_timeout(
        ctx.cx,
        ctx.conn,
        ctx.quarantine,
        ctx.request_budget.clone(),
        timeout_seconds,
        CompletionPolicy::EnforceDeadlineAfterBody,
        || preview_dml_inner(ctx, args),
    )
    .await
}

async fn preview_dml_inner(
    ctx: DbToolCtx<'_>,
    args: PreviewDmlArgs,
) -> Result<Value, ErrorEnvelope> {
    let cx = ctx.cx;
    let conn = ctx.conn;
    let decision = DEFAULT_CLASSIFIER.classify(&args.sql);
    let gate = decision.gate(ctx.session);
    if !matches!(gate, LevelDecision::Allow) {
        return Err(execute_gate_error(&decision, gate, ctx.session));
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
        return Err(
            invalid_args("oracle_preview_dml dry-runs a write; a read needs no sandbox")
                .with_suggested_tool("oracle_query"),
        );
    }
    if required_level >= OperatingLevel::Ddl {
        return Err(invalid_args(
            "DDL/Admin statements cannot be dry-run: Oracle commits them implicitly, so the sandbox could not roll them back",
        )
        .with_suggested_tool("oracle_preview_sql")
        .with_next_step(
            "use oracle_preview_sql to see the classifier verdict for DDL without executing anything",
        ));
    }
    // A dry run must not cause an effect it cannot take back. Refuse — and label
    // it — instead of advancing the sequence and calling the result a preview.
    if decision.non_transactional_effect || decision.query_effect_requires_fetch {
        return Ok(json!({
            "previewed": false,
            "reversible": false,
            "rolled_back": false,
            "committed": false,
            "cannot_undo": [decision.reason.clone()],
            "required_level": required_level,
            "danger": decision.danger,
            "objects_affected": decision.objects_affected,
            "reason": decision.reason,
            "next_step": "this statement was NOT executed: its effect escapes rollback, so no sandbox could undo it. Preview it with oracle_preview_sql and run it deliberately with oracle_execute once you accept the permanent effect",
        }));
    }
    ensure_workspace_level(ctx.session, "oracle_preview_dml")?;

    // The witness is an ordinary proven read — same classifier, same gate.
    let witness = match args
        .witness
        .as_deref()
        .map(str::trim)
        .filter(|w| !w.is_empty())
    {
        Some(witness) => {
            let marked = with_audit_marker(witness, ctx.active_profile, "oracle_preview_dml");
            ensure_resolved_read_only(cx, conn, ctx.catalog_cache, &marked).await?;
            let binds = args
                .witness_binds
                .iter()
                .map(json_to_bind)
                .collect::<Result<Vec<_>, _>>()?;
            Some((marked, binds))
        }
        None => None,
    };
    let binds = args
        .binds
        .iter()
        .map(json_to_bind)
        .collect::<Result<Vec<_>, _>>()?;
    let executed_sql = with_audit_marker(&args.sql, ctx.active_profile, "oracle_preview_dml");
    if DEFAULT_CLASSIFIER.classify(&executed_sql) != decision {
        return Err(ErrorEnvelope::new(
            ErrorClass::Internal,
            "audit marker changed the classifier verdict; refusing to execute",
        ));
    }
    let caps = QueryCaps {
        max_rows: args.max_rows.unwrap_or(QueryCaps::default().max_rows),
        ..QueryCaps::default()
    };

    // The sandbox is a write on the transaction: end any armed read-only one
    // first, exactly as the governed write path does.
    clear_read_only_transaction_before_write(&ctx).await?;
    let danger_str = audit_danger_string(decision.danger);
    let db_evidence = collect_effect_audit_db_evidence(&ctx).await?;
    let audit_entry = AuditEntryCtx {
        auditor: ctx.audit.auditor,
        subject: ctx.audit.subject,
        db_evidence: db_evidence.as_ref(),
    };
    // fsync-before-execute: the dry run really does run, so it is logged before
    // it can touch the database, and its rollback is logged after.
    append_audit(
        audit_entry,
        "oracle_preview_dml",
        &executed_sql,
        &danger_str,
        None,
        AuditOutcome::Pending,
    )?;

    let sandbox = workspace::savepoint_statement(workspace::PREVIEW_SANDBOX);
    if let Err(error) = execute_conn(cx, conn, &sandbox, &[] as &[OracleBind]).await {
        append_terminal_audit(
            &ctx,
            audit_entry,
            "oracle_preview_dml",
            &executed_sql,
            &danger_str,
            None,
            AuditOutcome::Failed,
        )?;
        return Err(DbError::into_envelope(error));
    }

    // Everything from here rolls back to the sandbox savepoint, whatever happens.
    let sandboxed = async {
        let before = match &witness {
            Some((sql, binds)) => Some(
                read_query(cx, conn, sql, binds, caps, 0, &SerializeOptions::default())
                    .await
                    .map_err(DbError::into_envelope)?,
            ),
            None => None,
        };
        let rows_affected = execute_conn(cx, conn, &executed_sql, &binds)
            .await
            .map_err(DbError::into_envelope)?;
        let after = match &witness {
            Some((sql, binds)) => Some(
                read_query(cx, conn, sql, binds, caps, 0, &SerializeOptions::default())
                    .await
                    .map_err(DbError::into_envelope)?,
            ),
            None => None,
        };
        Ok::<_, ErrorEnvelope>((before, rows_affected, after))
    }
    .await;

    // Undo the sandbox. This is the whole contract, so a failure here is a
    // quarantine: we could not prove the dry run left nothing behind.
    let undo = workspace::undo_statement(workspace::PREVIEW_SANDBOX);
    let undone = run_cleanup_with_budget(
        cx,
        &RequestBudget::fresh_cleanup(cx.now()),
        conn.execute(cx, &undo, &[] as &[OracleBind]),
    )
    .await;
    if let Err(error) = undone {
        let message = format!(
            "oracle_preview_dml could not roll its sandbox back, so its effect cannot be proven absent: {error}"
        );
        mark_connection_quarantined(
            ctx.quarantine,
            AuditOutcome::UnknownDiscarded,
            message.clone(),
        )?;
        if let Err(audit_error) = append_terminal_audit(
            &ctx,
            audit_entry,
            "oracle_preview_dml",
            &executed_sql,
            &danger_str,
            None,
            AuditOutcome::UnknownDiscarded,
        ) {
            tracing::error!(error = %audit_error.message, "terminal audit failed after an unrolled-back preview sandbox");
        }
        return Err(
            quarantined_db_error(QuarantineOutcome::UnknownDiscarded, message).into_envelope(),
        );
    }
    // With no workspace open there is nothing to preserve, so end the transaction
    // outright rather than leaving one open — the same posture a rollback-preview
    // execute leaves the session in.
    if !ctx.checkpoints.is_open()
        && let Err(error) = rollback_conn_cleanup(cx, conn).await
    {
        let message = format!(
            "oracle_preview_dml rolled its sandbox back, but could not end the transaction: {error}"
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

    let (before, rows_affected, after) = match sandboxed {
        Ok(result) => result,
        Err(error) => {
            append_terminal_audit(
                &ctx,
                audit_entry,
                "oracle_preview_dml",
                &executed_sql,
                &danger_str,
                None,
                AuditOutcome::Failed,
            )?;
            return Err(error);
        }
    };
    // The documented meaning of RolledBack is exactly this: a savepoint preview.
    append_terminal_audit(
        &ctx,
        audit_entry,
        "oracle_preview_dml",
        &executed_sql,
        &danger_str,
        Some(rows_affected),
        AuditOutcome::RolledBack,
    )?;

    let mut response = json!({
        "previewed": true,
        "reversible": true,
        "rolled_back": true,
        "committed": false,
        "rows_affected": rows_affected,
        "cannot_undo": Value::Array(Vec::new()),
        "required_level": required_level,
        "danger": decision.danger,
        "objects_affected": decision.objects_affected,
        "reason": decision.reason,
        "sandbox": sandbox,
        "next_step": "nothing was committed. To apply this exact change: oracle_preview_sql for its confirmation, then oracle_execute with commit=true — which re-classifies and re-gates the statement rather than trusting this preview",
        "caveat": "a trigger or an autonomous transaction fired by the target objects can commit independently of this rollback; the classifier flags only what it can prove from the statement text",
    });
    if let Some(before) = before {
        response["before"] = serde_json::to_value(&before).unwrap_or(Value::Null);
    }
    if let Some(after) = after {
        response["after"] = serde_json::to_value(&after).unwrap_or(Value::Null);
    }
    if witness.is_none() {
        response["next_actions"] = json!([{
            "intent": "see_the_rows_it_changes",
            "tool": "oracle_preview_dml",
            "args": { "sql": args.sql, "witness": "SELECT … FROM <table> WHERE <the rows this DML targets>" },
        }]);
    }
    Ok(response)
}

async fn execute_sql(
    ctx: DbToolCtx<'_>,
    audit_tool: &str,
    args: ExecuteArgs,
) -> Result<Value, ErrorEnvelope> {
    let timeout_seconds = args.timeout_seconds;
    let completion = if args.commit
        || args.hold
        || DEFAULT_CLASSIFIER
            .classify(&args.sql)
            .non_transactional_effect
    {
        // A held statement's effect survives the call inside the open
        // transaction (Arc I). A late deadline must not discard the fact that it
        // ran — the workspace, and the agent's undo stack, now depend on it.
        CompletionPolicy::PreserveSuccessfulEffect
    } else {
        CompletionPolicy::EnforceDeadlineAfterBody
    };
    with_call_timeout(
        ctx.cx,
        ctx.conn,
        ctx.quarantine,
        ctx.request_budget.clone(),
        timeout_seconds,
        completion,
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
    if decision.query_effect_requires_fetch {
        return Err(invalid_args(
            "query-shaped sequence NEXTVAL is refused: oracle_execute does not fetch query rows and therefore cannot prove that the permanent sequence effect occurred",
        )
        .with_next_step(
            "use NEXTVAL inside a governed DML or PL/SQL statement, then preview and confirm that exact statement",
        ));
    }
    // Arc I: hold = "leave this effect pending inside the reversible workspace".
    // It only means something with a checkpoint to undo to, it can never apply
    // to a statement Oracle commits implicitly, and it is the opposite of a
    // commit — each of those is a refusal, before any grant is consumed.
    if args.hold {
        if args.commit {
            return Err(invalid_args(
                "hold and commit are mutually exclusive: hold leaves the statement pending in the reversible workspace, commit makes it durable",
            ));
        }
        if required_level >= OperatingLevel::Ddl {
            return Err(invalid_args(
                "DDL/Admin statements cannot be held: Oracle commits them implicitly, so no checkpoint could undo them",
            )
            .with_next_step(
                "hold is for reversible DML; run DDL with commit=true on a closed workspace",
            ));
        }
        if decision.non_transactional_effect {
            return Err(invalid_args(
                "this statement cannot be held: its effect escapes rollback (for example a sequence NEXTVAL), so no checkpoint could undo it",
            )
            .with_next_step(
                "the reversible workspace only holds fully undoable DML; run this statement with commit=true and its confirmation on a closed workspace",
            ));
        }
        if !ctx.checkpoints.is_open() {
            return Err(invalid_args(
                "hold requires an open reversible workspace: without a checkpoint there is nothing to undo the held statement back to",
            )
            .with_suggested_tool("oracle_checkpoint")
            .with_next_step("call oracle_checkpoint to establish a checkpoint, then retry with hold=true"));
        }
    }
    if required_level >= OperatingLevel::Ddl && !args.commit {
        return Err(ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            "DDL/Admin statements cannot be rollback-previewed by Oracle; commit=true and confirm are required",
        )
        .with_suggested_tool("oracle_preview_sql")
        .with_next_step("call oracle_preview_sql and pass execute_confirmation.confirm to oracle_execute with commit=true"));
    }
    // A COMMIT is transaction-wide, and Oracle commits DDL/Admin implicitly:
    // either would durably persist every statement held in an open workspace,
    // none of which passed the single-use grant. Refuse before the grant is
    // consumed so a refusal never burns the agent's confirmation.
    if args.commit || required_level >= OperatingLevel::Ddl {
        ensure_workspace_closed(
            ctx.checkpoints,
            if args.commit {
                "committing this statement"
            } else {
                "this DDL/Admin statement (Oracle commits it implicitly)"
            },
        )?;
    }
    // A rollback-preview normally needs no per-statement confirmation because
    // Oracle can undo its effects. Sequence NEXTVAL is the exception: it
    // advances independently of transaction rollback, so it must consume the
    // same exact-SQL, single-use grant as a commit even when `commit=false`.
    let confirmation_required = args.commit || decision.non_transactional_effect;
    let confirmation_idempotency_key = if confirmation_required {
        Some(consume_execute_confirmation(
            &args.sql,
            required_level,
            active_profile,
            ctx.execute_grants,
            ctx.grant_binding,
            args.confirm.as_deref(),
            decision.non_transactional_effect && !args.commit,
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

    // The read-only backstop is transaction-scoped in Oracle. A prior read can
    // leave this pinned session inside `SET TRANSACTION READ ONLY` even after a
    // later request elevates the operating level. End that real transaction
    // only after every classifier/gate/confirmation check has passed, but
    // before audit evidence, DBMS_OUTPUT setup, or the approved statement can
    // touch the database.
    clear_read_only_transaction_before_write(&ctx).await?;

    // The audited danger tier (SAFE/GUARDED/DESTRUCTIVE) as a string; reads were
    // rejected above, so this is always a Guarded/Destructive write/DDL/Admin.
    let danger_str = audit_danger_string(decision.danger);
    let write_intent_id = match confirmation_idempotency_key.as_deref() {
        Some(key) => append_write_intent(&ctx, audit_tool, &executed_sql, required_level, key)?,
        None => None,
    };
    let db_evidence = match collect_effect_audit_db_evidence(&ctx).await {
        Ok(evidence) => evidence,
        Err(primary) => {
            resolve_write_intent_after_db(
                &ctx,
                write_intent_id.as_deref(),
                WriteIntentOutcome::AbortedBeforeExecute,
                AuditOutcome::UnknownDiscarded,
                "audit-evidence preflight failed before execute",
            )?;
            return Err(primary);
        }
    };
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
        if let Err(error) = enable_dbms_output_conn(cx, conn, Some(buffer_bytes)).await {
            let outcome = if error.is_uncertain_session_state() {
                mark_connection_quarantined(
                    ctx.quarantine,
                    AuditOutcome::UnknownDiscarded,
                    format!(
                        "DBMS_OUTPUT setup failed at an uncertain boundary before the approved statement executed: {error}"
                    ),
                )?;
                AuditOutcome::UnknownDiscarded
            } else {
                AuditOutcome::Failed
            };
            let terminal_audit = append_terminal_audit(
                &ctx,
                audit_entry,
                audit_tool,
                &executed_sql,
                &danger_str,
                None,
                outcome,
            );
            if outcome == AuditOutcome::Failed {
                terminal_audit?;
            } else if let Err(audit_error) = terminal_audit {
                tracing::error!(error = %audit_error.message, "terminal audit failed after uncertain DBMS_OUTPUT setup");
            }
            resolve_write_intent_after_db(
                &ctx,
                write_intent_id.as_deref(),
                WriteIntentOutcome::AbortedBeforeExecute,
                outcome,
                "DBMS_OUTPUT setup failed before the approved statement executed",
            )?;
            if outcome == AuditOutcome::UnknownDiscarded {
                return Err(quarantined_db_error(
                    QuarantineOutcome::UnknownDiscarded,
                    format!(
                        "DBMS_OUTPUT setup failed at an uncertain boundary; the approved statement was not executed: {error}"
                    ),
                )
                .into_envelope());
            }
            return Err(DbError::into_envelope(error));
        }
        Some((max_lines, max_chars))
    } else {
        None
    };
    // Oracle DDL/Admin implicitly commits and can survive rollback even when
    // the adapter observes an error after the wire response. Treat that class
    // like explicit non-transactional effects for outcome accounting.
    let effect_may_survive_rollback =
        decision.non_transactional_effect || required_level >= OperatingLevel::Ddl;
    let invalidation = catalog_invalidation_for_sql(&args.sql);
    if required_level >= OperatingLevel::Ddl || invalidation != CatalogInvalidation::Ddl {
        // Invalidate before the wire call. Oracle DDL can commit implicitly and
        // session-context changes take effect on the live connection; an
        // adapter error may leave either effect uncertain. Waiting for success
        // could therefore preserve stale proof after a real mutation.
        ctx.catalog_cache.invalidate(invalidation);
    }
    let rows_affected = match execute_conn(cx, conn, &executed_sql, &binds).await {
        Ok(rows) => rows,
        Err(e) => {
            // Arc I: a held statement runs inside the agent's open workspace, and
            // `hold` already refused everything whose effect can escape rollback,
            // so Oracle's statement-level atomicity has undone this failed
            // statement completely. The surrounding transaction — its savepoints
            // and the work held above them — is intact and still the agent's to
            // undo. A full ROLLBACK here would destroy exactly what the agent
            // asked us to keep. Only an uncertain DB boundary forces one, because
            // then we cannot prove what the session did.
            if args.hold && !e.is_uncertain_session_state() {
                append_terminal_audit(
                    &ctx,
                    audit_entry,
                    audit_tool,
                    &executed_sql,
                    &danger_str,
                    None,
                    AuditOutcome::Failed,
                )?;
                resolve_write_intent(
                    &ctx,
                    write_intent_id.as_deref(),
                    WriteIntentOutcome::AbortedBeforeExecute,
                )?;
                return Err(DbError::into_envelope(e));
            }
            let rollback = rollback_conn_cleanup(cx, conn).await;
            if rollback.is_ok() {
                // The transaction ended, so Oracle erased every savepoint.
                ctx.checkpoints.clear();
            }
            let outcome = if rollback.is_ok() && !effect_may_survive_rollback {
                AuditOutcome::RolledBack
            } else {
                let message = if rollback.is_ok() {
                    format!(
                        "execute failed after a non-transactional effect may have occurred; rollback cannot establish its outcome: {e}"
                    )
                } else {
                    format!("execute failed and rollback cleanup failed: {e}")
                };
                mark_connection_quarantined(
                    ctx.quarantine,
                    AuditOutcome::UnknownDiscarded,
                    message,
                )?;
                AuditOutcome::UnknownDiscarded
            };
            if e.is_uncertain_session_state() && rollback.is_ok() && !effect_may_survive_rollback {
                mark_connection_quarantined(
                    ctx.quarantine,
                    AuditOutcome::RolledBack,
                    format!(
                        "execute failed after an uncertain DB boundary; rollback succeeded: {e}"
                    ),
                )?;
            }
            // Durably log the terminal DB outcome. If the audit sink is also
            // broken, an uncertain/quarantined DB result remains primary.
            let terminal_audit = append_terminal_audit(
                &ctx,
                audit_entry,
                audit_tool,
                &executed_sql,
                &danger_str,
                None,
                outcome,
            );
            if outcome == AuditOutcome::RolledBack {
                terminal_audit?;
                resolve_write_intent_after_db(
                    &ctx,
                    write_intent_id.as_deref(),
                    WriteIntentOutcome::RolledBack,
                    AuditOutcome::RolledBack,
                    "execute failed and rollback completed",
                )?;
            } else if let Err(audit_err) = terminal_audit {
                tracing::error!(error = %audit_err.message, "terminal audit failed after an uncertain execute outcome");
            }
            if let Err(cleanup_err) = rollback {
                return Err(quarantined_db_error(
                    QuarantineOutcome::UnknownDiscarded,
                    format!("execute failed and rollback cleanup failed: {cleanup_err}"),
                )
                .into_envelope());
            }
            if outcome == AuditOutcome::UnknownDiscarded {
                return Err(quarantined_db_error(
                    QuarantineOutcome::UnknownDiscarded,
                    format!(
                        "execute failed after a non-transactional or otherwise uncertain boundary; rollback could not prove the effect absent: {e}"
                    ),
                )
                .into_envelope());
            }
            return Err(DbError::into_envelope(e));
        }
    };
    if args.hold {
        // Arc I: the whole point — no COMMIT, no ROLLBACK. The effect stays
        // pending in the transaction, above the newest checkpoint, until the
        // agent undoes it (or the session/elevation ends and Oracle discards it).
        ctx.checkpoints.note_held_statement();
    } else if args.commit {
        if let Err(e) = commit_conn(cx, conn).await {
            mark_connection_quarantined(
                ctx.quarantine,
                AuditOutcome::CommitInDoubt,
                format!("commit failed after {rows_affected} affected row(s): {e}"),
            )?;
            if let Err(audit_err) = append_terminal_audit(
                &ctx,
                audit_entry,
                audit_tool,
                &executed_sql,
                &danger_str,
                Some(rows_affected),
                AuditOutcome::CommitInDoubt,
            ) {
                tracing::error!(error = %audit_err.message, "terminal audit failed after commit-in-doubt");
            }
            return Err(quarantined_db_error(
                QuarantineOutcome::CommitInDoubt,
                format!("commit failed after {rows_affected} affected row(s): {e}"),
            )
            .into_envelope());
        }
    } else {
        if let Err(e) = rollback_conn_cleanup(cx, conn).await {
            mark_connection_quarantined(
                ctx.quarantine,
                AuditOutcome::UnknownDiscarded,
                format!(
                    "rollback preview cleanup failed after {rows_affected} affected row(s): {e}"
                ),
            )?;
            if let Err(audit_err) = append_terminal_audit(
                &ctx,
                audit_entry,
                audit_tool,
                &executed_sql,
                &danger_str,
                Some(rows_affected),
                AuditOutcome::UnknownDiscarded,
            ) {
                tracing::error!(error = %audit_err.message, "terminal audit failed after rollback cleanup failure");
            }
            return Err(quarantined_db_error(
                QuarantineOutcome::UnknownDiscarded,
                format!(
                    "rollback preview cleanup failed after {rows_affected} affected row(s): {e}"
                ),
            )
            .into_envelope());
        }
    }
    if args.commit || !args.hold {
        // Either branch above ended the transaction, so Oracle erased every
        // savepoint. (The committing branch is only reachable on a closed
        // workspace; the rollback branch closes whatever was open.)
        ctx.checkpoints.clear();
    }

    // A confirmed non-transactional statement is a successful persistent
    // effect even when the surrounding transaction was rolled back. Recording
    // it as `RolledBack` would falsely imply that replay is safe. A held
    // statement is neither: it ran, nothing is durable, and nothing has been
    // undone yet — only the workspace's undo (or the session ending) will
    // decide, and until then no commit can reach it.
    let outcome = if args.commit || decision.non_transactional_effect {
        AuditOutcome::Succeeded
    } else if args.hold {
        AuditOutcome::HeldUncommitted
    } else {
        AuditOutcome::RolledBack
    };
    append_terminal_audit(
        &ctx,
        audit_entry,
        audit_tool,
        &executed_sql,
        &danger_str,
        Some(rows_affected),
        outcome,
    )?;
    if confirmation_required {
        resolve_write_intent_after_db(
            &ctx,
            write_intent_id.as_deref(),
            WriteIntentOutcome::Succeeded,
            outcome,
            if args.commit {
                "commit completed"
            } else {
                "confirmed non-transactional effect completed"
            },
        )?;
    }
    // DBMS_OUTPUT is optional diagnostics. Once commit/rollback, durable audit,
    // and write-intent resolution have completed, a late timeout while draining
    // lines must not replace the terminal mutation outcome with a retryable
    // error. Surface the diagnostic loss in-band instead.
    let (dbms_output, dbms_output_unavailable) = match dbms_output_limits {
        Some((max_lines, max_chars)) => {
            match read_dbms_output_conn(cx, conn, max_lines, max_chars).await {
                Ok(out) => (Some(dbms_output_json(&out, max_lines, max_chars)), None),
                Err(err) => {
                    quarantine_uncertain_optional_diagnostic(
                        ctx.quarantine,
                        "DBMS_OUTPUT drain",
                        outcome,
                        &err,
                    );
                    (
                        None,
                        Some(format!(
                            "DBMS_OUTPUT unavailable after the terminal database outcome: {err}"
                        )),
                    )
                }
            }
        }
        None => (None, None),
    };

    let mut response = json!({
        "executed": true,
        "committed": args.commit,
        "rolled_back": !args.commit && !args.hold,
        "rows_affected": rows_affected,
        "required_level": required_level,
        "danger": decision.danger,
        "non_transactional_effect": decision.non_transactional_effect,
        "objects_affected": decision.objects_affected,
        "reason": decision.reason,
    });
    // Arc I honesty (bead .11.3): `rolled_back: true` reports the TRANSACTION,
    // and on its own it reads as "nothing happened". For a statement whose effect
    // escapes rollback — a sequence NEXTVAL the classifier can prove, and by
    // nature an autonomous transaction or trigger it cannot — that reading is
    // false: the transaction went back, the effect did not. Say so in the same
    // words the dry run uses, so an agent never has to infer permanence from a
    // flag named after the transaction.
    if decision.non_transactional_effect && !args.commit {
        response["cannot_undo"] = json!([decision.reason]);
        response["fully_reverted"] = json!(false);
        response["next_step"] = json!(
            "the transaction was rolled back, but this statement's effect persists anyway — treat it as applied, not undone"
        );
    }
    if args.hold {
        response["held"] = json!(true);
        response["workspace"] = ctx.checkpoints.view();
        response["next_step"] = json!(
            "the effect is pending and undoable; call oracle_undo_to to walk it back. It cannot be committed while the workspace is open"
        );
    }
    if let Some(dbms_output) = dbms_output {
        response["dbms_output"] = dbms_output;
    }
    if let Some(reason) = dbms_output_unavailable {
        response["dbms_output_unavailable"] = json!(reason);
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
    let completion = if args.execute {
        CompletionPolicy::PreserveSuccessfulEffect
    } else {
        CompletionPolicy::EnforceDeadlineAfterBody
    };
    with_call_timeout(
        ctx.cx,
        ctx.conn,
        ctx.quarantine,
        ctx.request_budget.clone(),
        timeout_seconds,
        completion,
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
    let statements =
        compile_object_statements(&object_type, &owner, &object_name, args.plscope, warnings)
            .map_err(DbError::into_envelope)?;
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
    // Arc I: Oracle commits DDL implicitly, so this compile would durably
    // persist every statement held in an open reversible workspace — none of
    // which passed the single-use grant. Refuse before the grant is consumed.
    ensure_workspace_closed(
        ctx.checkpoints,
        "this compile (Oracle commits DDL implicitly)",
    )?;
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

    clear_read_only_transaction_before_write(&ctx).await?;

    let danger_str = audit_danger_string(compile_danger);
    let write_intent_id = append_write_intent(
        &ctx,
        tool_name,
        &audited_sql,
        OperatingLevel::Ddl,
        &raw_confirm,
    )?;
    let db_evidence = match collect_effect_audit_db_evidence(&ctx).await {
        Ok(evidence) => evidence,
        Err(primary) => {
            resolve_write_intent_after_db(
                &ctx,
                write_intent_id.as_deref(),
                WriteIntentOutcome::AbortedBeforeExecute,
                AuditOutcome::UnknownDiscarded,
                "audit-evidence preflight failed before compile",
            )?;
            return Err(primary);
        }
    };
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
    ctx.catalog_cache
        .invalidate(catalog_invalidation_for_object_type(&object_type));
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
                let terminal_audit = append_terminal_audit(
                    &ctx,
                    audit_entry,
                    tool_name,
                    &audited_sql,
                    &danger_str,
                    None,
                    outcome,
                );
                if outcome == AuditOutcome::Failed {
                    terminal_audit?;
                    resolve_write_intent_after_db(
                        &ctx,
                        write_intent_id.as_deref(),
                        WriteIntentOutcome::Failed,
                        AuditOutcome::Failed,
                        "compile execution failed before a commit boundary",
                    )?;
                } else if let Err(audit_err) = terminal_audit {
                    tracing::error!(error = %audit_err.message, "terminal audit failed after uncertain compile outcome");
                    return Err(quarantined_db_error(
                        QuarantineOutcome::UnknownDiscarded,
                        format!("compile execution failed after an uncertain DB boundary: {e}"),
                    )
                    .into_envelope());
                }
                return Err(DbError::into_envelope(e));
            }
        }
    }
    let rows_affected_total = rows_affected.iter().copied().sum::<u64>();
    append_terminal_audit(
        &ctx,
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
        AuditOutcome::Succeeded,
        "compile execution completed",
    )?;
    // DDL has already taken effect and its audit/intent are terminal. Compile
    // diagnostics are observational; deadline/cancellation here degrades the
    // response instead of turning a successful DDL into a retryable timeout.
    let diagnostics = async {
        dispatch_checkpoint(cx, "oraclemcp.dispatch.compile_errors.before")?;
        let errors = match compile_errors(cx, conn, &owner, Some(&object_name)).await {
            Ok(errors) => errors,
            Err(err) => {
                quarantine_uncertain_optional_diagnostic(
                    ctx.quarantine,
                    "compile diagnostics",
                    AuditOutcome::Succeeded,
                    &err,
                );
                return Err(DbError::into_envelope(err));
            }
        };
        dispatch_checkpoint(cx, "oraclemcp.dispatch.compile_errors.after")?;
        Ok::<_, ErrorEnvelope>(errors)
    }
    .await;
    let (errors, diagnostics_unavailable) = match diagnostics {
        Ok(errors) => (Some(errors), None),
        Err(err) => (
            None,
            Some(format!(
                "compile diagnostics unavailable after DDL completion: {}",
                err.message
            )),
        ),
    };
    let (error_count, warning_count) = errors
        .as_deref()
        .map(compile_diagnostic_counts)
        .unwrap_or((0, 0));
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
        "errors": errors.as_ref().map(|rows| rows_to_json(rows)),
        "diagnostic_count": errors.as_ref().map(Vec::len),
        "error_count": errors.as_ref().map(|_| error_count),
        "warning_count": errors.as_ref().map(|_| warning_count),
        "diagnostics_unavailable": diagnostics_unavailable,
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
    let completion = if args.execute {
        CompletionPolicy::PreserveSuccessfulEffect
    } else {
        CompletionPolicy::EnforceDeadlineAfterBody
    };
    with_call_timeout(
        ctx.cx,
        ctx.conn,
        ctx.quarantine,
        ctx.request_budget.clone(),
        timeout_seconds,
        completion,
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
    // Source patches and direct CREATE OR REPLACE now share the guard's
    // token-aware stored-unit shape analysis. There is no patch-only
    // "balanced enough" override: malformed nesting, trailing SQL, and every
    // dynamic side-effect marker receive the exact same fail-closed decision on
    // both paths.
    let patch_required_level = decision.required_level;
    let gate = decision.gate(session);
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
    // Arc I: the patch is DDL and Oracle commits it implicitly — it would carry
    // an open workspace's held, ungranted statements into permanence with it.
    ensure_workspace_closed(
        ctx.checkpoints,
        "this source patch (Oracle commits DDL implicitly)",
    )?;
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

    clear_read_only_transaction_before_write(&ctx).await?;

    let danger_str = audit_danger_string(decision.danger);
    let write_intent_id =
        append_write_intent(&ctx, tool_name, &patched_ddl, required_level, &raw_confirm)?;
    let db_evidence = match collect_effect_audit_db_evidence(&ctx).await {
        Ok(evidence) => evidence,
        Err(primary) => {
            resolve_write_intent_after_db(
                &ctx,
                write_intent_id.as_deref(),
                WriteIntentOutcome::AbortedBeforeExecute,
                AuditOutcome::UnknownDiscarded,
                "audit-evidence preflight failed before source patch",
            )?;
            return Err(primary);
        }
    };
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
    ctx.catalog_cache
        .invalidate(catalog_invalidation_for_sql(&patched_ddl));
    let rows_affected = match execute_conn(cx, conn, &patched_ddl, &[]).await {
        Ok(rows) => rows,
        Err(e) => {
            let rollback = rollback_conn_cleanup(cx, conn).await;
            let outcome = if !e.is_uncertain_session_state() && rollback.is_ok() {
                // A definite Oracle DDL failure means the requested object
                // change did not complete. It is Failed, never RolledBack:
                // Oracle DDL is not transactionally undoable.
                AuditOutcome::Failed
            } else {
                mark_connection_quarantined(
                    ctx.quarantine,
                    AuditOutcome::UnknownDiscarded,
                    if rollback.is_ok() {
                        format!(
                            "patch execution failed after an uncertain DDL boundary; rollback cannot prove the implicit-commit effect absent: {e}"
                        )
                    } else {
                        format!("patch execution failed and rollback cleanup failed: {e}")
                    },
                )?;
                AuditOutcome::UnknownDiscarded
            };
            let terminal_audit = append_terminal_audit(
                &ctx,
                audit_entry,
                tool_name,
                &patched_ddl,
                &danger_str,
                None,
                outcome,
            );
            if outcome == AuditOutcome::Failed {
                terminal_audit?;
                resolve_write_intent_after_db(
                    &ctx,
                    write_intent_id.as_deref(),
                    WriteIntentOutcome::Failed,
                    AuditOutcome::Failed,
                    "patch DDL failed before any persistent object change completed",
                )?;
            } else if let Err(audit_err) = terminal_audit {
                tracing::error!(error = %audit_err.message, "terminal audit failed after uncertain patch outcome");
            }
            if let Err(cleanup_err) = rollback {
                return Err(quarantined_db_error(
                    QuarantineOutcome::UnknownDiscarded,
                    format!("patch execution failed and rollback cleanup failed: {cleanup_err}"),
                )
                .into_envelope());
            }
            if outcome == AuditOutcome::UnknownDiscarded {
                return Err(quarantined_db_error(
                    QuarantineOutcome::UnknownDiscarded,
                    format!(
                        "patch execution crossed an uncertain DDL boundary; rollback cannot prove the implicit-commit effect absent: {e}"
                    ),
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
        if let Err(audit_err) = append_terminal_audit(
            &ctx,
            audit_entry,
            tool_name,
            &patched_ddl,
            &danger_str,
            Some(rows_affected),
            AuditOutcome::CommitInDoubt,
        ) {
            tracing::error!(error = %audit_err.message, "terminal audit failed after patch commit-in-doubt");
        }
        return Err(quarantined_db_error(
            QuarantineOutcome::CommitInDoubt,
            format!("patch commit failed after {rows_affected} affected row(s): {e}"),
        )
        .into_envelope());
    }
    append_terminal_audit(
        &ctx,
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
        AuditOutcome::Succeeded,
        "patch commit completed",
    )?;
    let include_errors = args.include_errors.unwrap_or(true);
    let diagnostics = if include_errors {
        async {
            dispatch_checkpoint(cx, "oraclemcp.dispatch.patch.compile_errors.before")?;
            let rows = match compile_errors(cx, conn, &owner, Some(&object_name)).await {
                Ok(rows) => rows,
                Err(err) => {
                    quarantine_uncertain_optional_diagnostic(
                        ctx.quarantine,
                        "patch compile diagnostics",
                        AuditOutcome::Succeeded,
                        &err,
                    );
                    return Err(DbError::into_envelope(err));
                }
            };
            dispatch_checkpoint(cx, "oraclemcp.dispatch.patch.compile_errors.after")?;
            Ok::<_, ErrorEnvelope>(rows)
        }
        .await
        .map(Some)
    } else {
        Ok(None)
    };
    let (errors, diagnostics_unavailable) = match diagnostics {
        Ok(errors) => (errors, None),
        Err(err) => (
            None,
            Some(format!(
                "compile diagnostics unavailable after patch commit: {}",
                err.message
            )),
        ),
    };
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
            "diff": patch_diff_json(&document.text, match_idx, &old_text, &new_text),
            "errors": errors.as_ref().map(|rows| rows_to_json(rows)),
            "error_count": errors.as_ref().map(Vec::len),
            "diagnostics_unavailable": diagnostics_unavailable,
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
    let completion = if args.execute {
        CompletionPolicy::PreserveSuccessfulEffect
    } else {
        CompletionPolicy::EnforceDeadlineAfterBody
    };
    with_call_timeout(
        ctx.cx,
        ctx.conn,
        ctx.quarantine,
        ctx.request_budget.clone(),
        timeout_seconds,
        completion,
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
    let diagnostic_quarantine = ctx.quarantine;
    let mut executed = execute_sql(
        ctx,
        canonical_tool_name(tool_name),
        ExecuteArgs {
            sql: source.clone(),
            binds: Vec::new(),
            commit: true,
            hold: false,
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
                let diagnostics = async {
                    dispatch_checkpoint(
                        cx,
                        "oraclemcp.dispatch.create_or_replace.compile_errors.before",
                    )?;
                    let errors = match compile_errors(cx, conn, &hint.owner, Some(&hint.name)).await
                    {
                        Ok(errors) => errors,
                        Err(err) => {
                            quarantine_uncertain_optional_diagnostic(
                                diagnostic_quarantine,
                                "CREATE OR REPLACE compile diagnostics",
                                AuditOutcome::Succeeded,
                                &err,
                            );
                            return Err(DbError::into_envelope(err));
                        }
                    };
                    dispatch_checkpoint(
                        cx,
                        "oraclemcp.dispatch.create_or_replace.compile_errors.after",
                    )?;
                    Ok::<_, ErrorEnvelope>(errors)
                }
                .await;
                match diagnostics {
                    Ok(errors) => {
                        map.insert("errors".to_owned(), rows_to_json(&errors));
                        map.insert("error_count".to_owned(), json!(errors.len()));
                    }
                    Err(err) => {
                        map.insert("errors".to_owned(), Value::Null);
                        map.insert("error_count".to_owned(), Value::Null);
                        map.insert(
                            "diagnostics_unavailable".to_owned(),
                            json!(format!(
                                "compile diagnostics unavailable after CREATE OR REPLACE commit: {}",
                                err.message
                            )),
                        );
                    }
                }
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
    let completion = if args.execute {
        CompletionPolicy::PreserveSuccessfulEffect
    } else {
        CompletionPolicy::EnforceDeadlineAfterBody
    };
    with_call_timeout(
        ctx.cx,
        ctx.conn,
        ctx.quarantine,
        ctx.request_budget.clone(),
        timeout_seconds,
        completion,
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
            hold: false,
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
    catalog_cache: &'a OracleCatalogResolverCache,
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

        // Only Form A reaches execution; Form B (`call = ...`) is rejected at
        // catalog load, so the body is always inline SQL (QA100 .65).
        let ToolBody::InlineSql(sql) = body;
        let sql = sql.to_owned();
        ensure_resolved_read_only(self.cx, self.conn, self.catalog_cache, &sql).await?;
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
            if decision.query_effect_requires_fetch {
                None
            } else {
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
            &decision,
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

/// Decide from the actual successful response, not just the tool name. The
/// same mutation tools also serve previews, and those must remain cancellable.
fn response_reports_terminal_effect(name: &str, value: &Value) -> bool {
    let bool_field = |field| value.get(field).and_then(Value::as_bool) == Some(true);
    match canonical_tool_name(name) {
        "oracle_switch_profile" => true,
        "oracle_set_session_level" => bool_field("changed"),
        "oracle_compile_object" => bool_field("compiled"),
        "oracle_patch_source" | "oracle_create_or_replace" | "deploy_ddl" => bool_field("applied"),
        "oracle_execute" | "execute_approved" => {
            bool_field("executed")
                && (bool_field("committed") || bool_field("non_transactional_effect"))
        }
        _ => false,
    }
}

impl ToolDispatch for OracleDispatcher {
    fn request_timeout_ceiling(&self) -> Result<Duration, ErrorEnvelope> {
        // `None` is the operator's driver-call-timeout opt-out; the documented
        // whole-request safety default remains active. A poisoned policy lock
        // fails before the lane polls any dispatcher work.
        Ok(self.request_timeout()?.unwrap_or(DEFAULT_REQUEST_TIMEOUT))
    }

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
            let terminal_result = match &result {
                Ok(value) => response_reports_terminal_effect(name, value),
                Err(_) => self.connection_quarantine().ok().flatten().is_some(),
            };
            if cx.is_cancel_requested() && !terminal_result {
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
            let terminal_result = match &result {
                Ok(value) => response_reports_terminal_effect(name, value),
                Err(_) => self.connection_quarantine().ok().flatten().is_some(),
            };
            if cx.is_cancel_requested() && !terminal_result {
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

/// Canonical export ownership copied out of the request context before the
/// dispatcher borrows its connection state across the async query path.
struct QueryExportAccess {
    principal_key: String,
    scopes: Option<Vec<String>>,
}

/// Runtime inputs for a prepared `oracle_query` execution. Kept bundled so the
/// read handler signature stays small as cross-cutting controls are added.
struct PreparedQueryRuntime<'a> {
    conn: &'a dyn OracleConnection,
    request_budget: RequestBudget,
    active_profile: Option<String>,
    export_access: QueryExportAccess,
    request_subject: AuditSubject,
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
        state
            .catalog_cache
            .invalidate(CatalogInvalidation::Reconnect);
        state.read_only_backstop.reset();

        if reason == DispatchCloseReason::RequestFinalizationTimeout {
            // The command's own terminal-finalization grace already expired.
            // Record the known-unknown outcome before attempting any more
            // Oracle I/O: a hung describe or rollback must not consume the
            // lane-close budget and erase the durable lifecycle evidence.
            let message =
                "request terminal finalization timed out; the lane was discarded and the database outcome requires verification"
                    .to_owned();
            mark_connection_quarantined(&self.quarantine, AuditOutcome::UnknownDiscarded, message)?;
            state.profile_generation.take();
            let unavailable_evidence = self
                .auditor
                .as_ref()
                .map(|_| DbEvidence::unavailable("request_finalization_timeout"));
            let audit_result = append_lifecycle_audit(
                self.auditor.as_deref(),
                &subject,
                unavailable_evidence.as_ref(),
                reason,
                AuditOutcome::UnknownDiscarded,
            );
            let rollback_result = rollback_conn_cleanup(cx, state.conn.as_ref()).await;
            match rollback_result {
                Ok(()) => tracing::info!(
                    close_reason = reason.as_str(),
                    active_profile = active_profile.as_deref().unwrap_or(""),
                    outcome = audit_outcome_label(AuditOutcome::UnknownDiscarded),
                    "bounded rollback completed after finalization timeout; prior DDL or commit remains outcome-unknown"
                ),
                Err(error) => {
                    mark_connection_quarantined(
                        &self.quarantine,
                        AuditOutcome::UnknownDiscarded,
                        format!(
                            "bounded rollback after request finalization timeout also failed: {error}"
                        ),
                    )?;
                    tracing::warn!(
                        close_reason = reason.as_str(),
                        active_profile = active_profile.as_deref().unwrap_or(""),
                        error = %error,
                        "bounded rollback failed after finalization timeout"
                    );
                }
            }
            audit_result?;
            return Ok(());
        }

        let db_evidence =
            collect_audit_db_evidence(cx, self.auditor.as_deref(), state.conn.as_ref()).await;
        let rollback_result = rollback_conn_cleanup(cx, state.conn.as_ref()).await;
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
        // Closing the lane is the lifecycle point at which its exact profile
        // generation stops contributing to drain diagnostics/refcounts.
        state.profile_generation.take();

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
        if detail == McpSurfaceDetail::Connection {
            let observed_conn = ReadUncertaintyConn {
                inner: state.conn.as_ref(),
                quarantine: Some(&self.quarantine),
            };
            match describe_conn(cx, &observed_conn).await {
                Ok(info) => {
                    connection.connected = true;
                    connection.read_only_standby = info.is_read_only_standby();
                    connection.server_version = info.server_version;
                    // K2: additive server-capability block. `describe` populates it only
                    // for a live thin connection, so mocks/degraded backends leave it
                    // `None` and the field is omitted from the report.
                    connection.server_features = info.server_features;
                }
                Err(err) if err.is_uncertain_session_state() => {
                    return Err(DbError::into_envelope(err));
                }
                Err(_) => {}
            }
        }
        Ok(McpSurfaceState {
            current_level: scoped_level.effective_level(),
            effective_ceiling: scoped_level.effective_ceiling(),
            max_level: scoped_level.max_level(),
            protected: scoped_level.is_protected(),
            active_profile,
            custom_catalog: state.custom_catalog.snapshot(),
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
        let mut request_budget = self.dispatch_request_budget(cx, context)?;
        if let Some(timeout_seconds) = args
            .get("timeout_seconds")
            .and_then(Value::as_u64)
            .filter(|seconds| *seconds > 0)
        {
            request_budget = request_budget.tighten_timeout(Duration::from_secs(
                timeout_seconds.min(MAX_CALL_TIMEOUT_SECONDS),
            ));
            request_budget.enforce(cx).map_err(DbError::into_envelope)?;
        }
        let tool = canonical_tool_name(name);
        if tool == "oracle_switch_profile" {
            {
                let state = self.state.lock(cx).await.map_err(|_| {
                    ErrorEnvelope::new(ErrorClass::Internal, "connection mutex lock failed")
                })?;
                if let Some(active_profile) = state.active_profile.as_deref()
                    && state.profile_generation.is_none()
                {
                    return Err(profile_generation_inactive_error(active_profile));
                }
            }
            let a: SwitchProfileArgs = parse_args(name, args)?;
            let profile = required_switch_profile_arg(name, a.profile)?;
            // E5 connection-scope isolation: the served surface may only switch
            // to a profile the operator flagged `mcp_exposed`. A non-exposed or
            // unknown name is rejected here, BEFORE the connector ever resolves
            // the profile's credentials/DSN, with an envelope that does not
            // reveal whether the guessed name matched a hidden profile.
            let profile_generation = match self
                .profile_drain
                .admit_mcp_profile(&profile, self.mcp_exposure.is_exposed(&profile))
            {
                ProfileGenerationAdmission::Ready(lease) => lease,
                ProfileGenerationAdmission::NotExposed => {
                    return Err(profile_not_available(&profile));
                }
                ProfileGenerationAdmission::Draining => {
                    return Err(profile_draining_error(&profile));
                }
            };
            let Some(connector) = &self.connector else {
                return Err(ErrorEnvelope::new(
                    ErrorClass::RuntimeStateRequired,
                    "profile switching is unavailable in this server instance",
                )
                .with_next_step("restart the server with `oraclemcp serve --profile <name>`"));
            };
            let (conn, stateless_conn) = connector(cx, &profile_generation)
                .await
                .map_err(DbError::into_envelope)?
                .into_parts();
            let primary_limits = ConnectionLimitGuard::install(
                cx,
                conn.as_ref(),
                None,
                None,
                request_budget.deadline(),
                Some(request_budget.db_quota()),
            )
            .map_err(DbError::into_envelope)?;
            let stateless_limits = match stateless_conn.as_deref() {
                Some(stateless) if !std::ptr::eq(conn.as_ref(), stateless) => Some(
                    ConnectionLimitGuard::install(
                        cx,
                        stateless,
                        None,
                        None,
                        request_budget.deadline(),
                        Some(request_budget.db_quota()),
                    )
                    .map_err(DbError::into_envelope)?,
                ),
                _ => None,
            };
            // Candidate metadata is normally best-effort, but an uncertain
            // primary describe means this newly opened physical session is not
            // safe to install. Defer the error until both request-limit guards
            // restore, then drop the whole candidate bundle without poisoning
            // the still-active dispatcher session.
            let mut response = match describe_conn(cx, conn.as_ref()).await {
                Err(err) if err.is_uncertain_session_state() => Err(err),
                result => Ok(connection_info_json(Some(profile.clone()), result)),
            };
            if let Ok(Value::Object(map)) = &mut response
                && let Some(stateless_conn) = stateless_conn.as_ref()
            {
                map.insert(
                    "stateless_read_connection".to_owned(),
                    connection_strategy_json(cx, stateless_conn.as_ref()).await,
                );
            }
            let budget_after_prepare = request_budget.enforce(cx).map_err(DbError::into_envelope);
            let stateless_restore = stateless_limits.and_then(|limits| limits.restore().err());
            let primary_restore = primary_limits.restore().err();
            if let Some(error) = stateless_restore.or(primary_restore) {
                return Err(DbError::into_envelope(error));
            }
            budget_after_prepare?;
            let response = response.map_err(DbError::into_envelope)?;
            let new_policy = profile_dispatch_policy(&profile_generation)?;
            let new_level = new_policy.level;
            let new_custom_catalog = match &self.custom_loader {
                Some(loader) => loader(&profile_generation, &new_level)?,
                None => CustomToolCatalog::default(),
            };
            let prepared = PreparedProfileSwitch {
                profile,
                profile_generation,
                conn,
                stateless_conn,
                level: new_level,
                request_timeout: new_policy.request_timeout,
                max_query_cost: new_policy.max_query_cost,
                result_masking: new_policy.result_masking,
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
            request_budget.enforce(cx).map_err(DbError::into_envelope)?;
            let old_request_timeout = self.request_timeout()?;
            let old_max_query_cost = self.max_query_cost()?;
            let old_result_masking = self.result_masking_policy()?;
            let PreparedProfileSwitch {
                profile,
                profile_generation,
                conn,
                stateless_conn,
                level,
                request_timeout,
                max_query_cost,
                result_masking,
                custom_catalog,
                mut response,
            } = prepared;
            let generation = profile_generation.generation();
            let custom_catalog = ActiveCustomCatalog::new(
                state.custom_catalog.generation.saturating_add(1),
                custom_catalog,
            );
            // Keep the lease outside the generation-locked closure until every
            // fallible setup step has succeeded. If the closure captured the
            // lease by value, an early `?` would drop it while
            // `commit_generation` still held the same profile mutex, and its
            // `Drop` implementation would deadlock trying to release the
            // generation reference.
            let mut pending_profile_generation = Some(profile_generation);
            let mut retired_generation = None;
            let mut response = self
                .profile_drain
                .commit_generation(&profile, generation, || {
                    self.set_request_timeout(request_timeout)?;
                    if let Err(err) = self.set_max_query_cost(max_query_cost) {
                        let _ = self.set_request_timeout(old_request_timeout);
                        return Err(err);
                    }
                    if let Err(err) = self.set_result_masking_policy(result_masking) {
                        let _ = self.set_request_timeout(old_request_timeout);
                        let _ = self.set_max_query_cost(old_max_query_cost);
                        return Err(err);
                    }
                    if let Err(err) = self.clear_connection_quarantine() {
                        let _ = self.set_request_timeout(old_request_timeout);
                        let _ = self.set_max_query_cost(old_max_query_cost);
                        let _ = self.set_result_masking_policy(old_result_masking);
                        return Err(err);
                    }
                    let profile_generation =
                        pending_profile_generation.take().ok_or_else(|| {
                            ErrorEnvelope::new(
                                ErrorClass::Internal,
                                "prepared profile generation was already consumed",
                            )
                        })?;
                    state.conn = conn;
                    state.stateless_conn = stateless_conn;
                    state.active_profile = Some(profile.clone());
                    retired_generation = state.profile_generation.replace(profile_generation);
                    state.level = level;
                    state.custom_catalog = custom_catalog;
                    state.grant_generation = state.grant_generation.saturating_add(1);
                    state.execute_grants.clear();
                    state.execute_approved_tokens.clear();
                    state.patch_previews.clear();
                    state
                        .catalog_cache
                        .invalidate(CatalogInvalidation::Reconnect);
                    // A1: the pinned session was replaced; the new session's
                    // transaction is fresh, so re-assert the read-only backstop
                    // on its first read.
                    state.read_only_backstop.reset();
                    // Arc I: the old physical session (and any uncommitted work
                    // held in it) is gone with it, so its savepoints are too.
                    state.checkpoints.clear();
                    if let Value::Object(map) = &mut response {
                        map.insert(
                            "custom_tool_count".to_owned(),
                            json!(state.custom_catalog.catalog.len()),
                        );
                        map.insert(
                            "custom_catalog_generation".to_owned(),
                            json!(state.custom_catalog.generation),
                        );
                        map.insert("profile_generation".to_owned(), json!(generation));
                    }
                    Ok(response)
                })
                .map_err(|()| profile_draining_error(&profile))??;
            drop(retired_generation);
            drop(state);
            if let Err(error) = request_budget.enforce(cx) {
                response.annotate_deadline_after_effect();
                tracing::warn!(
                    error = %error,
                    profile = profile.as_str(),
                    generation,
                    "request deadline observed after a completed profile switch"
                );
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
        // Mutex wait is part of the same total request budget. Re-check before
        // any arm can mint/consume authority or mutate lane-local state.
        request_budget.enforce(cx).map_err(DbError::into_envelope)?;
        let request_subject = audit_subject(context, &self.default_audit_subject);
        let scoped_level = scoped_session_level(&state.level, context);
        let scoped = context.scope_grant().is_some();
        if tool != "oracle_list_profiles"
            && tool != "oracle_connection_info"
            && let Some(active_profile) = state.active_profile.as_deref()
        {
            match state.profile_generation.as_ref() {
                None => return Err(profile_generation_inactive_error(active_profile)),
                Some(generation) if generation.is_draining() => {
                    return Err(profile_draining_error(active_profile));
                }
                Some(_) => {}
            }
        }
        if tool == "oracle_set_session_level" {
            let a: SetSessionLevelArgs = parse_args(name, args)?;
            let active_profile = state.active_profile.clone();
            let grant_binding = grant_binding_for_context(&state, context);
            let before = state.level.effective_level();
            request_budget.enforce(cx).map_err(DbError::into_envelope)?;

            // Prepare the transition on a detached state. The audit-evidence
            // lookup below is cancellable and the lane may drop this future at
            // its hard finalization bound; live authorization must therefore
            // remain untouched until every fallible/awaiting precondition has
            // completed. The submitted confirmation grant stays single-use if
            // preparation succeeds, even when later evidence/audit fails.
            let mut staged_level = state.level.clone();
            let mut value = set_session_level_with_scope(
                &mut staged_level,
                &scoped_level,
                SessionGrantContext {
                    active_profile: active_profile.as_deref(),
                    grants: &state.execute_grants,
                    binding: &grant_binding,
                },
                name,
                a,
                scoped,
            )?;
            let changed = value.get("changed").and_then(Value::as_bool) == Some(true);
            let after = staged_level.effective_level();
            let mut db_evidence = None;
            // Audit a successful level INCREASE (step-up approval). De-escalation
            // and status reads are not escalations and are not chained.
            if changed
                && after > before
                && let Some(auditor) = self.auditor.as_deref()
            {
                let subject = request_subject.clone();
                db_evidence = collect_effect_audit_db_evidence_bounded(
                    cx,
                    Some(auditor),
                    state.conn.as_ref(),
                    &request_budget,
                    &self.quarantine,
                )
                .await?;
                request_budget.enforce(cx).map_err(DbError::into_envelope)?;
                let draft = AuditEntryDraft {
                    subject,
                    db_evidence: db_evidence.clone(),
                    cancel: None,
                    result_masking: None,
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
            if changed {
                // Commit point: no await or fallible state operation may occur
                // between the live authorization swap and the response.
                state.level = staged_level;
                state.grant_generation = state.grant_generation.saturating_add(1);
                state.execute_grants.clear();
                state.execute_approved_tokens.clear();
                state.patch_previews.clear();
            }
            match request_budget.enforce(cx) {
                Ok(()) => {}
                Err(error) if changed => {
                    value.annotate_deadline_after_effect();
                    tracing::warn!(
                        error = %error,
                        before = before.as_str(),
                        after = after.as_str(),
                        evidence = db_evidence.is_some(),
                        "request deadline observed after a completed session-level transition"
                    );
                }
                Err(error) => return Err(DbError::into_envelope(error)),
            }
            return Ok(value);
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
            let conn: &dyn OracleConnection = state.conn.as_ref();
            let audit = AuditCtx {
                auditor: self.auditor.as_deref(),
                subject: &subject,
            };
            let tool_ctx = DbToolCtx {
                cx,
                conn,
                read_only_backstop: &state.read_only_backstop,
                checkpoints: &state.checkpoints,
                request_budget,
                active_profile: active_profile.as_deref(),
                session: &scoped_level,
                execute_grants: &state.execute_grants,
                grant_binding: &grant_binding,
                write_intents: self.write_intents.as_deref(),
                catalog_cache: &state.catalog_cache,
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
            let conn: &dyn OracleConnection = state.conn.as_ref();
            let audit = AuditCtx {
                auditor: self.auditor.as_deref(),
                subject: &subject,
            };
            let tool_ctx = DbToolCtx {
                cx,
                conn,
                read_only_backstop: &state.read_only_backstop,
                checkpoints: &state.checkpoints,
                request_budget,
                active_profile: active_profile.as_deref(),
                session: &scoped_level,
                execute_grants: &state.execute_grants,
                grant_binding: &grant_binding,
                write_intents: self.write_intents.as_deref(),
                catalog_cache: &state.catalog_cache,
                audit,
                quarantine: &self.quarantine,
            };
            return deploy_ddl(tool_ctx, a).await;
        }
        if tool == "read_patch_preview" {
            let a: ReadPatchPreviewArgs = parse_args(name, args)?;
            return read_patch_preview(&state, name, a);
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
                let _ = parsed
                    .binds
                    .iter()
                    .map(json_to_bind)
                    .collect::<Result<Vec<_>, _>>()?;
                if parsed.streaming && parsed.export {
                    return Err(invalid_args(
                        "streaming and export are mutually exclusive: choose incremental delivery OR a single export resource",
                    ));
                }
                if parsed.streaming && as_of.is_some() {
                    return Err(invalid_args(
                        "streaming and as_of are mutually exclusive: page the flashback read with its cursor",
                    ));
                }
                if as_of.is_some() {
                    // Arc I: DBMS_FLASHBACK cannot be enabled inside a
                    // transaction, so the flashback read resets the pinned
                    // session — erasing the reversible workspace's savepoints and
                    // every statement held above them.
                    ensure_workspace_closed(
                        &state.checkpoints,
                        "an as_of (flashback) read (it resets the session transaction)",
                    )?;
                }
                let executed_sql =
                    with_audit_marker(&parsed.sql, state.active_profile.as_deref(), "oracle_query");
                let gate = ensure_resolved_read_only(
                    cx,
                    state.conn.as_ref(),
                    &state.catalog_cache,
                    &executed_sql,
                )
                .await;
                QueryPrepared {
                    args: parsed,
                    executed_sql,
                    gate,
                    as_of,
                }
            };
            request_budget = query_budget_with_cost_limit(
                request_budget,
                self.max_query_cost()?,
                prepared.args.max_query_cost,
            );
            request_budget.enforce(cx).map_err(DbError::into_envelope)?;

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
                let cost_limit = effective_query_cost_limit(
                    self.max_query_cost()?,
                    prepared.args.max_query_cost,
                );
                let DispatcherState {
                    conn,
                    read_only_backstop,
                    checkpoints,
                    ..
                } = &mut *state;
                enforce_query_cost_gate(
                    QueryCostGateCtx {
                        cx,
                        conn: conn.as_ref(),
                        read_only_backstop,
                        checkpoints,
                        session: &scoped_level,
                        request_budget: &request_budget,
                        quarantine: &self.quarantine,
                    },
                    &prepared.args,
                    &prepared.executed_sql,
                    cost_limit,
                )
                .await?;
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
                    read_only_backstop.disarm();
                    // Arc I: the flashback wrapper rolls the session back, so
                    // Oracle erased every savepoint with it.
                    checkpoints.clear();
                } else {
                    // Consult the effective level that governs THIS request
                    // (scoped_level folds in any OAuth scope, which can only
                    // LOWER the level — so this arms at least as often as the
                    // unscoped level, never less).
                    ensure_read_only_backstop_bounded(
                        cx,
                        conn.as_ref(),
                        read_only_backstop,
                        checkpoints,
                        &scoped_level,
                        &request_budget,
                        &self.quarantine,
                    )
                    .await?;
                }
            }

            let active_profile = state.active_profile.clone();
            // E3/E3b: resolve immutable export ownership before the conn borrow
            // / read closure. HTTP supplies a canonical transport principal;
            // missing means the one-process stdio identity.
            let export_access = QueryExportAccess {
                principal_key: context
                    .principal_key()
                    .unwrap_or(oraclemcp_core::STDIO_EXPORT_PRINCIPAL)
                    .to_owned(),
                scopes: context.scope_grant().map(|grant| grant.0.clone()),
            };
            let conn: &dyn OracleConnection = state.conn.as_ref();
            return self
                .run_prepared_query(
                    cx,
                    PreparedQueryRuntime {
                        conn,
                        request_budget,
                        active_profile,
                        export_access,
                        request_subject: request_subject.clone(),
                    },
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
                checkpoints,
                ..
            } = &mut *state;
            ensure_read_only_backstop_bounded(
                cx,
                conn.as_ref(),
                read_only_backstop,
                checkpoints,
                &scoped_level,
                &request_budget,
                &self.quarantine,
            )
            .await?;
        }

        let conn: &dyn OracleConnection = state.conn.as_ref();
        let metadata_conn: &dyn OracleConnection = state
            .stateless_conn
            .as_deref()
            .unwrap_or_else(|| state.conn.as_ref());
        let final_budget = request_budget.clone();
        let primary_limits = ConnectionLimitGuard::install(
            cx,
            conn,
            Some(&self.quarantine),
            None,
            request_budget.deadline(),
            Some(request_budget.db_quota()),
        )
        .map_err(DbError::into_envelope)?;
        let metadata_limits = if std::ptr::eq(conn, metadata_conn) {
            None
        } else {
            Some(
                ConnectionLimitGuard::install(
                    cx,
                    metadata_conn,
                    None,
                    None,
                    request_budget.deadline(),
                    Some(request_budget.db_quota()),
                )
                .map_err(DbError::into_envelope)?,
            )
        };
        let observed_conn = ReadUncertaintyConn {
            inner: conn,
            quarantine: Some(&self.quarantine),
        };
        let observed_metadata_conn = ReadUncertaintyConn {
            inner: metadata_conn,
            quarantine: std::ptr::eq(conn, metadata_conn).then_some(&self.quarantine),
        };
        let generated_read_subject = system_generated_read_subject();
        let (generated_read_db_evidence, generated_read_evidence_error) = if generated_read {
            match collect_read_audit_db_evidence(cx, self.auditor.as_deref(), &observed_conn).await
            {
                Ok(evidence) => (evidence, None),
                Err(error) => (None, Some(error)),
            }
        } else {
            (None, None)
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
            inner: &observed_conn,
            audit: generated_read_audit,
        };
        let guarded_metadata_conn = GuardedGeneratedReadConn {
            inner: &observed_metadata_conn,
            audit: generated_read_audit,
        };

        let mut patch_preview_to_remember = None;
        let result: Result<Value, ErrorEnvelope> = async {
            if let Some(error) = generated_read_evidence_error {
                return Err(error);
            }
            match tool {
            #[cfg(feature = "plsql-intelligence")]
            tool if crate::plsql_tools::is_static_tool(tool) => {
                crate::plsql_tools::dispatch_static(tool, args)
            }
            #[cfg(feature = "plsql-intelligence")]
            "oracle_plsql_live_snapshot" | "oracle_plsql_blast_radius" => {
                return crate::plsql_tools::dispatch_live(cx, &observed_metadata_conn, tool, args)
                    .await;
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
                    read_only_backstop: &state.read_only_backstop,
                    checkpoints: &state.checkpoints,
                    request_budget,
                    active_profile: state.active_profile.as_deref(),
                    session: &scoped_level,
                    execute_grants: &state.execute_grants,
                    grant_binding: &grant_binding,
                    write_intents: self.write_intents.as_deref(),
                    catalog_cache: &state.catalog_cache,
                    audit,
                    quarantine: &self.quarantine,
                };
                return execute_sql(tool_ctx, "oracle_execute", a).await;
            }
            "oracle_checkpoint" => {
                let a: CheckpointArgs = parse_args(name, args)?;
                let subject = request_subject.clone();
                let grant_binding = grant_binding_for_context(&state, context);
                let audit = AuditCtx {
                    auditor: self.auditor.as_deref(),
                    subject: &subject,
                };
                let tool_ctx = DbToolCtx {
                    cx,
                    conn,
                    read_only_backstop: &state.read_only_backstop,
                    checkpoints: &state.checkpoints,
                    request_budget,
                    active_profile: state.active_profile.as_deref(),
                    session: &scoped_level,
                    execute_grants: &state.execute_grants,
                    grant_binding: &grant_binding,
                    write_intents: self.write_intents.as_deref(),
                    catalog_cache: &state.catalog_cache,
                    audit,
                    quarantine: &self.quarantine,
                };
                return open_checkpoint(tool_ctx, a).await;
            }
            "oracle_preview_dml" => {
                let a: PreviewDmlArgs = parse_args(name, args)?;
                let subject = request_subject.clone();
                let grant_binding = grant_binding_for_context(&state, context);
                let audit = AuditCtx {
                    auditor: self.auditor.as_deref(),
                    subject: &subject,
                };
                let tool_ctx = DbToolCtx {
                    cx,
                    conn,
                    read_only_backstop: &state.read_only_backstop,
                    checkpoints: &state.checkpoints,
                    request_budget,
                    active_profile: state.active_profile.as_deref(),
                    session: &scoped_level,
                    execute_grants: &state.execute_grants,
                    grant_binding: &grant_binding,
                    write_intents: self.write_intents.as_deref(),
                    catalog_cache: &state.catalog_cache,
                    audit,
                    quarantine: &self.quarantine,
                };
                return preview_dml(tool_ctx, a).await;
            }
            "oracle_undo_to" => {
                let a: UndoToArgs = parse_args(name, args)?;
                let subject = request_subject.clone();
                let grant_binding = grant_binding_for_context(&state, context);
                let audit = AuditCtx {
                    auditor: self.auditor.as_deref(),
                    subject: &subject,
                };
                let tool_ctx = DbToolCtx {
                    cx,
                    conn,
                    read_only_backstop: &state.read_only_backstop,
                    checkpoints: &state.checkpoints,
                    request_budget,
                    active_profile: state.active_profile.as_deref(),
                    session: &scoped_level,
                    execute_grants: &state.execute_grants,
                    grant_binding: &grant_binding,
                    write_intents: self.write_intents.as_deref(),
                    catalog_cache: &state.catalog_cache,
                    audit,
                    quarantine: &self.quarantine,
                };
                return undo_to_checkpoint(tool_ctx, a).await;
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
                    read_only_backstop: &state.read_only_backstop,
                    checkpoints: &state.checkpoints,
                    request_budget,
                    active_profile: state.active_profile.as_deref(),
                    session: &scoped_level,
                    execute_grants: &state.execute_grants,
                    grant_binding: &grant_binding,
                    write_intents: self.write_intents.as_deref(),
                    catalog_cache: &state.catalog_cache,
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
                    read_only_backstop: &state.read_only_backstop,
                    checkpoints: &state.checkpoints,
                    request_budget,
                    active_profile: state.active_profile.as_deref(),
                    session: &scoped_level,
                    execute_grants: &state.execute_grants,
                    grant_binding: &grant_binding,
                    write_intents: self.write_intents.as_deref(),
                    catalog_cache: &state.catalog_cache,
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
                    read_only_backstop: &state.read_only_backstop,
                    checkpoints: &state.checkpoints,
                    request_budget,
                    active_profile: state.active_profile.as_deref(),
                    session: &scoped_level,
                    execute_grants: &state.execute_grants,
                    grant_binding: &grant_binding,
                    write_intents: self.write_intents.as_deref(),
                    catalog_cache: &state.catalog_cache,
                    audit,
                    quarantine: &self.quarantine,
                };
                let (value, preview_entry) = patch_source(tool_ctx, name, a).await?;
                // Mutate the state-owned preview log only after the connection
                // borrows end and both request-limit guards restore explicitly.
                patch_preview_to_remember = preview_entry;
                Ok(value)
            }
            "oracle_list_profiles" => {
                ensure_no_args(name, args)?;
                profiles_response(&self.mcp_exposure, &self.profile_drain)
            }
            "oracle_connection_info" => {
                ensure_no_args(name, args)?;
                let mut value = match describe_conn(cx, &observed_conn).await {
                    Err(err) if err.is_uncertain_session_state() => {
                        return Err(DbError::into_envelope(err));
                    }
                    result => connection_info_json(state.active_profile.clone(), result),
                };
                if let Value::Object(map) = &mut value {
                    if let Some(generation) = state.profile_generation.as_ref() {
                        map.insert("profile_generation_active".to_owned(), json!(true));
                        map.insert(
                            "profile_generation".to_owned(),
                            json!(generation.generation()),
                        );
                        map.insert(
                            "profile_generation_draining".to_owned(),
                            json!(generation.is_draining()),
                        );
                    } else if state.active_profile.is_some() {
                        map.insert("profile_generation_active".to_owned(), json!(false));
                    }
                    if let Some(stateless_conn) = state.stateless_conn.as_ref() {
                        map.insert(
                            "stateless_read_connection".to_owned(),
                            connection_strategy_json(cx, stateless_conn.as_ref()).await,
                        );
                    }
                }
                Ok(value)
            }
            "oracle_diff" => {
                let a: DiffArgs = parse_args(name, args)?;
                let mode = diff_mode_from_args(&a)?;
                // Arc I: a flashback read resets the pinned session's
                // transaction, which erases the reversible workspace's savepoints
                // and every statement held above them. A cross-database diff
                // reads on its own transient connections and never touches the
                // pinned session, so it leaves the workspace intact.
                if matches!(mode, DiffMode::Time { .. }) {
                    ensure_workspace_closed(
                        &state.checkpoints,
                        "oracle_diff (its flashback read resets the session transaction)",
                    )?;
                }
                let timeout_seconds = a.timeout_seconds;
                let active_profile = state.active_profile.clone();
                with_call_timeout(
                    cx,
                    conn,
                    &self.quarantine,
                    final_budget.clone(),
                    timeout_seconds,
                    CompletionPolicy::EnforceDeadlineAfterBody,
                    || async {
                        let read_cx = narrow_to_read_path(cx);
                        dispatch_checkpoint(&read_cx, "oraclemcp.dispatch.diff.before")?;
                        let binds = a
                            .binds
                            .iter()
                            .map(json_to_bind)
                            .collect::<Result<Vec<_>, _>>()?;
                        let explicit_key = normalize_diff_key_columns(a.key.clone())?;
                        let caps = diff_query_caps_from_args(&a);

                        let (before, after, key_columns, source_a, source_b) = match &mode {
                            DiffMode::Time { scn_a, scn_b } => {
                                let executed_sql = with_audit_marker(
                                    &a.sql,
                                    active_profile.as_deref(),
                                    "oracle_diff",
                                );
                                let relations = resolve_read_only_relations(
                                    cx,
                                    &observed_conn,
                                    &state.catalog_cache,
                                    &executed_sql,
                                )
                                .await?;
                                let key_columns = if explicit_key.is_empty() {
                                    inferred_diff_key_columns(
                                        cx,
                                        &guarded_metadata_conn,
                                        &relations,
                                    )
                                    .await?
                                } else {
                                    explicit_key
                                };
                                let result_masking = self.result_masking_policy()?;
                                let serialize_opts = diff_serialize_options_from_args_with_policy(
                                    &a,
                                    result_masking.as_ref(),
                                );
                                let read_conn = ReadUncertaintyConn {
                                    inner: conn,
                                    quarantine: Some(&self.quarantine),
                                };
                                let mut before = read_query_as_of(
                                    cx,
                                    &read_conn,
                                    &executed_sql,
                                    &binds,
                                    caps,
                                    0,
                                    &serialize_opts,
                                    &AsOf::Scn(*scn_a),
                                )
                                .await
                                .map_err(DbError::into_envelope)?;
                                let mut after = read_query_as_of(
                                    cx,
                                    &read_conn,
                                    &executed_sql,
                                    &binds,
                                    caps,
                                    0,
                                    &serialize_opts,
                                    &AsOf::Scn(*scn_b),
                                )
                                .await
                                .map_err(DbError::into_envelope)?;
                                bind_result_masking_audit(
                                    cx,
                                    &read_conn,
                                    self.auditor.as_deref(),
                                    &request_subject,
                                    "oracle_diff",
                                    &executed_sql,
                                    &mut before,
                                )
                                .await?;
                                bind_result_masking_audit(
                                    cx,
                                    &read_conn,
                                    self.auditor.as_deref(),
                                    &request_subject,
                                    "oracle_diff",
                                    &executed_sql,
                                    &mut after,
                                )
                                .await?;
                                (
                                    before,
                                    after,
                                    key_columns,
                                    QueryDiffSource::scn(*scn_a),
                                    QueryDiffSource::scn(*scn_b),
                                )
                            }
                            DiffMode::Fleet {
                                profile_a,
                                scn_a,
                                profile_b,
                                scn_b,
                            } => {
                                let serialize_defaults =
                                    diff_serialize_options_from_args_with_policy(&a, None);
                                let side_a = self
                                    .read_diff_side_from_profile(
                                        cx,
                                        DiffSideRequest {
                                            side: DiffSide::A,
                                            profile: profile_a,
                                            sql: &a.sql,
                                            binds: &binds,
                                            caps,
                                            scn: *scn_a,
                                            serialize_defaults: serialize_defaults.clone(),
                                            subject: &request_subject,
                                            budget: &final_budget,
                                            infer_key: explicit_key.is_empty(),
                                        },
                                    )
                                    .await?;
                                let side_b = self
                                    .read_diff_side_from_profile(
                                        cx,
                                        DiffSideRequest {
                                            side: DiffSide::B,
                                            profile: profile_b,
                                            sql: &a.sql,
                                            binds: &binds,
                                            caps,
                                            scn: *scn_b,
                                            serialize_defaults,
                                            subject: &request_subject,
                                            budget: &final_budget,
                                            infer_key: false,
                                        },
                                    )
                                    .await?;
                                let before = side_a.response;
                                let after = side_b.response;
                                if !before.columns.is_empty()
                                    && !after.columns.is_empty()
                                    && before.columns != after.columns
                                {
                                    return Err(diff_shape_mismatch(
                                        profile_a,
                                        &before.columns,
                                        profile_b,
                                        &after.columns,
                                    ));
                                }
                                // Masked values are only ever tested for equality
                                // when both sides have rows. With one side empty
                                // every row of the other is a pure add/remove, so
                                // no masked value is compared and there is nothing
                                // to prove sound.
                                if before.row_count > 0 && after.row_count > 0 {
                                    let compared = if after.columns.is_empty() {
                                        &before.columns
                                    } else {
                                        &after.columns
                                    };
                                    let incomparable = incomparable_masked_columns(
                                        compared,
                                        before.mask_certificate.as_ref(),
                                        after.mask_certificate.as_ref(),
                                    );
                                    if !incomparable.is_empty() {
                                        return Err(diff_incomparable_masking(
                                            profile_a,
                                            profile_b,
                                            &incomparable,
                                        ));
                                    }
                                }
                                let key_columns = if explicit_key.is_empty() {
                                    side_a.inferred_key
                                } else {
                                    explicit_key
                                };
                                (
                                    before,
                                    after,
                                    key_columns,
                                    QueryDiffSource::profile(profile_a).at_scn(*scn_a),
                                    QueryDiffSource::profile(profile_b).at_scn(*scn_b),
                                )
                            }
                        };

                        let before_mask_certificate = before.mask_certificate.clone();
                        let after_mask_certificate = after.mask_certificate.clone();
                        let diff = diff_query_responses(&before, &after, &key_columns)
                            .map_err(|err| invalid_args(err.to_string()))?
                            .with_sources(source_a, source_b);
                        dispatch_checkpoint(&read_cx, "oraclemcp.dispatch.diff.after")?;
                        let mut value = serde_json::to_value(diff).map_err(|err| {
                            ErrorEnvelope::new(
                                ErrorClass::Internal,
                                format!("oracle_diff serialization failed: {err}"),
                            )
                        })?;
                        if (before_mask_certificate.is_some()
                            || after_mask_certificate.is_some())
                            && let Some(object) = value.as_object_mut()
                        {
                            object.insert(
                                "mask_certificates".to_owned(),
                                json!({
                                    "before": before_mask_certificate,
                                    "after": after_mask_certificate,
                                }),
                            );
                        }
                        Ok(value)
                    },
                )
                .await
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
                        let info = describe_conn(cx, &observed_metadata_conn)
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
                if a.fleet {
                    if detail != SearchDetailLevel::Names {
                        return Err(invalid_args(
                            "fleet catalog requires detail_level=names so every merged field is \
                             covered by its source profile's egress policy",
                        ));
                    }
                    let owner_filter = owner_arg
                        .as_deref()
                        .filter(|owner| *owner != "*")
                        .map(str::to_owned);
                    let profiles = self
                        .profile_drain
                        .mcp_profiles_snapshot(&self.mcp_exposure)
                        .ok_or_else(|| {
                            ErrorEnvelope::new(
                                ErrorClass::RuntimeStateRequired,
                                "accepted runtime config snapshot is unavailable",
                            )
                        })?;
                    if self.connector.is_none() {
                        return Err(ErrorEnvelope::new(
                            ErrorClass::RuntimeStateRequired,
                            "fleet catalog is unavailable in this server instance",
                        )
                        .with_next_step(
                            "restart the server with a configured profile connector",
                        ));
                    }
                    let read_cx = narrow_to_read_path(cx);
                    dispatch_checkpoint(&read_cx, "oraclemcp.dispatch.fleet_catalog.before")?;
                    let mut remaining = max_rows;
                    let mut lanes = Vec::new();
                    for profile in profiles {
                        if remaining == 0 {
                            break;
                        }
                        if let Some(lane) = self
                            .read_fleet_catalog_profile(
                                cx,
                                FleetCatalogRequest {
                                    profile: profile.name,
                                    owner: owner_filter.as_deref(),
                                    object_type: object_type.as_deref(),
                                    name_like: name_like.as_deref(),
                                    max_rows: remaining,
                                    request_budget: &request_budget,
                                    subject: &request_subject,
                                },
                            )
                            .await
                        {
                            remaining = remaining.saturating_sub(lane.results.len());
                            lanes.push(lane);
                        }
                    }
                    dispatch_checkpoint(&read_cx, "oraclemcp.dispatch.fleet_catalog.after")?;
                    return Ok(fleet_catalog_response(
                        lanes,
                        owner_filter.as_deref(),
                        object_type.as_deref(),
                        name_like.as_deref(),
                        max_rows,
                    ));
                }
                let owner_filter: Option<String> = match owner_arg.as_deref() {
                    Some("*") => None,
                    Some(owner) => Some(owner.to_owned()),
                    None => {
                        let info = describe_conn(cx, &observed_metadata_conn)
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
            "oracle_orient" => {
                let a: OrientArgs = parse_args(name, args)?;
                let owner = orient_owner_arg(a.owner)?;
                let include = OrientInclude::parse(&a.include)?;
                if a.fleet {
                    let profiles = self
                        .profile_drain
                        .mcp_fleet_profiles_snapshot(&self.mcp_exposure)
                        .ok_or_else(|| {
                            ErrorEnvelope::new(
                                ErrorClass::RuntimeStateRequired,
                                "accepted runtime config snapshot is unavailable",
                            )
                        })?;
                    let mut lanes = Vec::with_capacity(profiles.len());
                    for profile in profiles {
                        lanes.push(
                            self.read_orient_lane_from_profile(
                                cx,
                                profile.name,
                                owner.as_deref(),
                                &request_budget,
                            )
                            .await,
                        );
                    }
                    return Ok(fleet_orient_response(lanes, &include));
                }
                let catalog_revision = state.catalog_cache.generation().0;
                let cache_key = OrientSnapshotCacheKey {
                    profile: state.active_profile.clone(),
                    catalog_revision,
                    owner: owner.clone(),
                };
                let cached_snapshot = state
                    .orient_snapshots
                    .lock()
                    .map_err(|_| {
                        ErrorEnvelope::new(
                            ErrorClass::Internal,
                            "oracle_orient snapshot cache lock is poisoned",
                        )
                    })?
                    .get(&cache_key)
                    .cloned();
                let snapshot = if let Some(snapshot) = cached_snapshot {
                    snapshot.clone()
                } else {
                    dispatch_checkpoint(cx, "oraclemcp.dispatch.orient.before")?;
                    let snapshot = load_orient_snapshot(
                        cx,
                        &guarded_metadata_conn,
                        owner.as_deref(),
                        catalog_revision,
                    )
                    .await
                    .map_err(DbError::into_envelope)?;
                    dispatch_checkpoint(cx, "oraclemcp.dispatch.orient.after")?;
                    let mut snapshots = state.orient_snapshots.lock().map_err(|_| {
                        ErrorEnvelope::new(
                            ErrorClass::Internal,
                            "oracle_orient snapshot cache lock is poisoned",
                        )
                    })?;
                    if snapshots.len() >= MAX_ORIENT_SNAPSHOT_CACHE_ENTRIES {
                        snapshots.clear();
                    }
                    snapshots.insert(cache_key, snapshot.clone());
                    snapshot
                };
                Ok(orient_snapshot_response(&snapshot, &include))
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
                    owner_and_name_arg(cx, &observed_metadata_conn, a.owner, table, "table")
                        .await?;
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
                    owner_and_name_arg(cx, &observed_metadata_conn, a.owner, a.name, "index")
                        .await?;
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
                    owner_and_name_arg(cx, &observed_metadata_conn, a.owner, a.name, "trigger")
                        .await?;
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
                    owner_and_name_arg(cx, &observed_metadata_conn, a.owner, a.name, "view")
                        .await?;
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
                    owner_and_name_arg(cx, &observed_metadata_conn, a.owner, a.name, "name")
                        .await?;
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
                    owner_and_name_arg(cx, &observed_metadata_conn, a.owner, a.name, "name")
                        .await?;
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
                return with_call_timeout(
                    cx,
                    conn,
                    &self.quarantine,
                    request_budget,
                    timeout_seconds,
                    CompletionPolicy::EnforceDeadlineAfterBody,
                    || async {
                        let source =
                            oraclemcp_db::resolve_top_sql_source(cx, &guarded_conn, historical)
                                .await
                                .map_err(DbError::into_envelope)?;
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
                    },
                )
                .await;
            }
            "oracle_plan_timeline" => {
                let a: PlanTimelineArgs = parse_args(name, args)?;
                let sql_id = a.sql_id;
                let max_points = a.max_points.unwrap_or(100);
                let timeout_seconds = a.timeout_seconds;
                // AWR is a licensed historical source. The DB helper probes
                // control_management_pack_access before it can issue any
                // DBA_HIST_* statement, and returns a typed refusal when the
                // license cannot be positively established.
                return with_call_timeout(
                    cx,
                    conn,
                    &self.quarantine,
                    request_budget,
                    timeout_seconds,
                    CompletionPolicy::EnforceDeadlineAfterBody,
                    || async {
                        let timeline =
                            oraclemcp_db::plan_cost_timeline(cx, &guarded_conn, &sql_id, max_points)
                                .await?;
                        Ok(json!({
                            "sql_id": timeline.sql_id,
                            "points": timeline.points,
                            "note": timeline.note,
                        }))
                    },
                )
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
                return with_call_timeout(
                    cx,
                    conn,
                    &self.quarantine,
                    request_budget,
                    timeout_seconds,
                    CompletionPolicy::EnforceDeadlineAfterBody,
                    || async {
                    let findings = match oraclemcp_db::run_health(
                        cx,
                        &guarded_conn,
                        &request.subchecks,
                    )
                    .await
                    {
                        Ok(findings) => findings,
                        Err(err) => {
                            if err.is_uncertain_session_state() {
                                mark_connection_quarantined(
                                    &self.quarantine,
                                    AuditOutcome::UnknownDiscarded,
                                    format!(
                                        "oracle_db_health aborted at an uncertain database boundary: {err}"
                                    ),
                                )?;
                            }
                            return Err(DbError::into_envelope(err));
                        }
                    };
                    let checks_run: Vec<&str> = findings
                        .iter()
                        .filter(|f| {
                            f.detail.get("status").and_then(Value::as_str) == Some("ok")
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
                    let checks_failed: Vec<&str> = findings
                        .iter()
                        .filter(|f| {
                            f.detail.get("status").and_then(Value::as_str) == Some("failed")
                        })
                        .map(|f| f.subcheck.name())
                        .collect();
                    Ok(json!({
                        "findings": serde_json::to_value(&findings).unwrap_or(Value::Null),
                        "checks_run": checks_run,
                        "checks_skipped": checks_skipped,
                        "checks_failed": checks_failed,
                        "unknown_checks": request.unknown,
                    }))
                    },
                )
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
                            owner_and_name_arg(
                                cx,
                                &observed_metadata_conn,
                                a.owner,
                                object_name,
                                "name",
                            )
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
                        let owner = owner_or_current_cx(cx, &observed_metadata_conn, a.owner)
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
                        owner_or_current_cx(cx, &observed_metadata_conn, None)
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
                    owner_and_name_arg(
                        cx,
                        &observed_metadata_conn,
                        a.owner,
                        object_name,
                        "name",
                    )
                    .await?;
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
                // Arc I: EXPLAIN PLAN writes PLAN_TABLE and rolls the transaction
                // back to clean it up, erasing the reversible workspace with it.
                ensure_workspace_closed(
                    &state.checkpoints,
                    "oracle_explain_plan (its PLAN_TABLE cleanup rolls the transaction back)",
                )?;
                ensure_resolved_read_only(cx, conn, &state.catalog_cache, &a.sql).await?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.explain_plan.before")?;
                let rows = match explain_plan(cx, conn, &a.sql, a.read_only_standby).await {
                    Ok(rows) => rows,
                    Err(primary) => {
                        if let Err(cleanup_err) = rollback_conn_cleanup(cx, conn).await {
                            let message = format!(
                                "EXPLAIN PLAN failed and PLAN_TABLE rollback cleanup failed: {cleanup_err}"
                            );
                            mark_connection_quarantined(
                                &self.quarantine,
                                AuditOutcome::UnknownDiscarded,
                                message.clone(),
                            )?;
                            return Err(quarantined_db_error(
                                QuarantineOutcome::UnknownDiscarded,
                                message,
                            )
                            .into_envelope());
                        }
                        return Err(DbError::into_envelope(primary));
                    }
                };
                let mut response = json!({
                    "plan": rows_to_json(&rows),
                    "diagnostic_write": {
                        "statement": "EXPLAIN PLAN",
                        "writes": "PLAN_TABLE",
                        "required_level": OperatingLevel::ReadWrite,
                        "explicitly_allowed": a.allow_plan_table_write,
                        "rolled_back": true,
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
                if let Err(cleanup_err) = rollback_conn_cleanup(cx, conn).await {
                    let message = format!(
                        "EXPLAIN PLAN completed, but PLAN_TABLE rollback cleanup failed: {cleanup_err}"
                    );
                    mark_connection_quarantined(
                        &self.quarantine,
                        AuditOutcome::UnknownDiscarded,
                        message.clone(),
                    )?;
                    return Err(
                        quarantined_db_error(QuarantineOutcome::UnknownDiscarded, message)
                            .into_envelope(),
                    );
                }
                dispatch_checkpoint(cx, "oraclemcp.dispatch.explain_plan.after")?;
                Ok(response)
            }
            other => {
                if let Some(loaded) = state.custom_catalog.catalog.get(other) {
                    let executor = ReadOnlyCustomToolExecutor {
                        cx,
                        conn: &observed_conn,
                        catalog_cache: &state.catalog_cache,
                    };
                    execute_custom_tool(loaded, &args, &executor).await
                } else {
                    Err(invalid_args(format!(
                        "unknown tool: {other:?} (call oracle_capabilities for the tool surface)"
                    )))
                }
            }
            }
        }
        .await;

        let budget_after = final_budget.enforce(cx).map_err(DbError::into_envelope);
        let metadata_restore_error = metadata_limits.and_then(|limits| limits.restore().err());
        let primary_restore_error = primary_limits.restore().err();
        match result {
            Err(primary) => {
                if let Some(restore_err) = primary_restore_error {
                    let _ = mark_connection_quarantined(
                        &self.quarantine,
                        AuditOutcome::UnknownDiscarded,
                        format!(
                            "database operation failed and request-limit restoration also failed: {restore_err}"
                        ),
                    );
                }
                if let Some(restore_err) = metadata_restore_error {
                    tracing::warn!(
                        error = %restore_err,
                        "stateless read request-limit restoration also failed; the active primary session remains independent"
                    );
                }
                Err(primary)
            }
            Ok(mut value) => {
                let effect_succeeded = response_reports_terminal_effect(tool, &value);
                if let Some(restore_err) = primary_restore_error {
                    return Err(limit_restore_failure(
                        &self.quarantine,
                        effect_succeeded,
                        restore_err,
                    ));
                }
                if let Some(restore_err) = metadata_restore_error {
                    return Err(DbError::into_envelope(restore_err));
                }
                match budget_after {
                    Ok(()) => {
                        if let Some(preview_entry) = patch_preview_to_remember {
                            remember_patch_preview(&mut state, preview_entry);
                        }
                        Ok(value)
                    }
                    Err(err) if effect_succeeded => {
                        value.annotate_deadline_after_effect();
                        tracing::warn!(error = %err.message, "request deadline observed after a completed database effect");
                        Ok(value)
                    }
                    Err(err) => Err(err),
                }
            }
        }
    }

    /// Run an oracle_query whose args were parsed and whose SQL was marked +
    /// classified ONCE up front (see `QueryPrepared`). Reuses the prepared
    /// `executed_sql` and `gate` instead of re-parsing/re-marking/re-classifying
    /// — behavior is identical to the prior inline arm, with one classify run.
    async fn run_prepared_query(
        &self,
        cx: &Cx,
        runtime: PreparedQueryRuntime<'_>,
        prepared: QueryPrepared,
    ) -> Result<Value, ErrorEnvelope> {
        let PreparedQueryRuntime {
            conn,
            request_budget,
            active_profile,
            export_access,
            request_subject,
        } = runtime;
        let QueryPrepared {
            args: a,
            executed_sql,
            gate,
            as_of,
        } = prepared;
        let timeout_seconds = a.timeout_seconds;
        let exports = self.exports.clone();
        let body_budget = request_budget.clone();
        let read_conn = ReadUncertaintyConn {
            inner: conn,
            quarantine: Some(&self.quarantine),
        };
        // A9: narrow the handler context to the read-path capability row
        // (TIME + IO; no SPAWN / REMOTE / RANDOM). The pure handler work below —
        // gate, bind conversion, cursor decode, serialization — runs under this
        // narrowed row; only the locked DB round trip (`OracleConnection` is
        // object-safe and takes the full `&Cx`) is handed the full `cx`, the one
        // documented IO exception.
        let read_cx = narrow_to_read_path(cx);
        with_call_timeout(
            cx,
            conn,
            &self.quarantine,
            request_budget,
            timeout_seconds,
            CompletionPolicy::EnforceDeadlineAfterBody,
            || async {
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
                    let result_masking = self.result_masking_policy()?;
                    if result_masking.is_some() {
                        return Err(invalid_args(
                            "streaming masked query results is temporarily unavailable because \
                             mask-decision certificates must be audit-bound before rows leave the \
                             server",
                        )
                        .with_next_step(
                            "retry without streaming=true so the masked page can carry an audit-bound certificate",
                        ));
                    }
                    let serialize_opts =
                        query_serialize_options_from_args_with_policy(&a, result_masking.as_ref());
                    return Self::stream_query_response(
                        cx,
                        &read_conn,
                        &body_budget,
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
                    let result_masking = self.result_masking_policy()?;
                    return export_query_to_resource(
                        cx,
                        &read_conn,
                        &executed_sql,
                        &a,
                        &binds,
                        offset,
                        active_profile.as_deref(),
                        &export_access,
                        exports.as_deref(),
                        as_of.as_ref(),
                        result_masking.as_ref(),
                        self.auditor.as_deref(),
                        &request_subject,
                    )
                    .await;
                }
                // K9: when a flashback target is set, run the SAME proven SQL inside
                // a bounded DBMS_FLASHBACK window (`read_query_as_of`); otherwise the
                // plain read path. Both take the identical proven `executed_sql`.
                let caps = query_caps_from_args(&a);
                let result_masking = self.result_masking_policy()?;
                let serialize_opts =
                    query_serialize_options_from_args_with_policy(&a, result_masking.as_ref());
                let auditor = self.auditor.as_deref();
                if result_masking.is_some() && auditor.is_none() {
                    return Err(ErrorEnvelope::new(
                        ErrorClass::RuntimeStateRequired,
                        "result masking is active but no audit sink is configured; refusing to return a \
                         masked result without hash-chain binding",
                    )
                    .with_next_step(
                        "configure audit logging, or disable result masking for this profile",
                    ));
                }

                // Arc A3: when an audit sink is configured, capture the SCN
                // before the data query and persist a Pending record before
                // the query itself runs. On the normal path this is the first
                // SELECT in the already-armed read-only transaction, so later
                // reads share its consistent snapshot. For a structured
                // timestamp target, resolve Oracle's timestamp mapping once
                // and execute at that exact SCN instead of recording a lossy
                // wall-clock hint.
                let replay_target = if auditor.is_some() {
                    match as_of.as_ref() {
                        Some(as_of) => Some(AsOf::Scn(
                            as_of
                                .resolve_to_scn(cx, &read_conn)
                                .await
                                .map_err(DbError::into_envelope)?,
                        )),
                        None => None,
                    }
                } else {
                    None
                };
                let observed_scn = match (auditor, replay_target.as_ref()) {
                    (Some(_), Some(AsOf::Scn(scn))) => Some(*scn),
                    (Some(_), Some(AsOf::Timestamp(_))) => unreachable!(
                        "audited timestamp flashback targets are resolved to SCNs before execution"
                    ),
                    (Some(_), None) => Some(
                        AsOf::current_system_change_number(cx, &read_conn)
                            .await
                            .map_err(DbError::into_envelope)?,
                    ),
                    (None, _) => None,
                };
                let read_audit_evidence =
                    collect_read_audit_db_evidence(cx, auditor, &read_conn).await?;
                let read_audit = AuditEntryCtx {
                    auditor,
                    subject: &request_subject,
                    db_evidence: read_audit_evidence.as_ref(),
                };
                if let Some(observed_scn) = observed_scn {
                    append_query_read_audit(
                        read_audit,
                        "oracle_query",
                        &executed_sql,
                        observed_scn,
                        AuditOutcome::Pending,
                        None,
                    )?;
                }

                let effective_as_of = replay_target.as_ref().or(as_of.as_ref());
                let read = match effective_as_of {
                    Some(as_of) => {
                        read_query_as_of(
                            cx,
                            &read_conn,
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
                            &read_conn,
                            &executed_sql,
                            &binds,
                            caps,
                            offset,
                            &serialize_opts,
                        )
                        .await
                    }
                };
                let mut response = match read {
                    Ok(response) => response,
                    Err(error) => {
                        if let Some(observed_scn) = observed_scn {
                            append_query_read_audit(
                                read_audit,
                                "oracle_query",
                                &executed_sql,
                                observed_scn,
                                AuditOutcome::Failed,
                                None,
                            )?;
                        }
                        return Err(DbError::into_envelope(error));
                    }
                };
                if let Some(observed_scn) = observed_scn {
                    append_query_read_audit(
                        read_audit,
                        "oracle_query",
                        &executed_sql,
                        observed_scn,
                        AuditOutcome::Succeeded,
                        Some(&mut response),
                    )?;
                }
                let response = serde_json::to_value(response).unwrap_or(Value::Null);
                Ok(reseal_query_cursor(
                    response,
                    &a.sql,
                    active_profile.as_deref(),
                ))
            },
        )
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
        let mut request_budget = self.dispatch_request_budget(cx, context)?;
        if let Some(timeout_seconds) = args
            .get("timeout_seconds")
            .and_then(Value::as_u64)
            .filter(|seconds| *seconds > 0)
        {
            request_budget = request_budget.tighten_timeout(Duration::from_secs(
                timeout_seconds.min(MAX_CALL_TIMEOUT_SECONDS),
            ));
            request_budget.enforce(cx).map_err(DbError::into_envelope)?;
        }
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
            if let Some(active_profile) = state.active_profile.as_deref() {
                match state.profile_generation.as_ref() {
                    None => return Err(profile_generation_inactive_error(active_profile)),
                    Some(generation) if generation.is_draining() => {
                        return Err(profile_draining_error(active_profile));
                    }
                    Some(_) => {}
                }
            }
            let prepared = {
                let parsed = parse_args::<QueryArgs>(name, args)?;
                if !parsed.streaming {
                    return Err(invalid_args(
                        "streaming dispatch requires oracle_query streaming=true",
                    ));
                }
                let as_of = query_as_of_from_args(parsed.as_of.as_ref())?;
                let _ = parsed
                    .binds
                    .iter()
                    .map(json_to_bind)
                    .collect::<Result<Vec<_>, _>>()?;
                if parsed.export {
                    return Err(invalid_args(
                        "streaming and export are mutually exclusive: choose incremental delivery OR a single export resource",
                    ));
                }
                if as_of.is_some() {
                    return Err(invalid_args(
                        "streaming and as_of are mutually exclusive: page the flashback read with its cursor",
                    ));
                }
                let executed_sql =
                    with_audit_marker(&parsed.sql, state.active_profile.as_deref(), "oracle_query");
                let gate = ensure_resolved_read_only(
                    cx,
                    state.conn.as_ref(),
                    &state.catalog_cache,
                    &executed_sql,
                )
                .await;
                QueryPrepared {
                    args: parsed,
                    executed_sql,
                    gate,
                    as_of,
                }
            };
            request_budget = query_budget_with_cost_limit(
                request_budget,
                self.max_query_cost()?,
                prepared.args.max_query_cost,
            );
            request_budget.enforce(cx).map_err(DbError::into_envelope)?;

            if prepared.gate.is_ok() {
                let cost_limit = effective_query_cost_limit(
                    self.max_query_cost()?,
                    prepared.args.max_query_cost,
                );
                let DispatcherState {
                    conn,
                    read_only_backstop,
                    checkpoints,
                    ..
                } = &mut *state;
                enforce_query_cost_gate(
                    QueryCostGateCtx {
                        cx,
                        conn: conn.as_ref(),
                        read_only_backstop,
                        checkpoints,
                        session: &scoped_level,
                        request_budget: &request_budget,
                        quarantine: &self.quarantine,
                    },
                    &prepared.args,
                    &prepared.executed_sql,
                    cost_limit,
                )
                .await?;
                if prepared.as_of.is_some() {
                    read_only_backstop.disarm();
                    // Arc I: the flashback wrapper rolls the session back, so
                    // Oracle erased every savepoint with it.
                    checkpoints.clear();
                } else {
                    ensure_read_only_backstop_bounded(
                        cx,
                        conn.as_ref(),
                        read_only_backstop,
                        checkpoints,
                        &scoped_level,
                        &request_budget,
                        &self.quarantine,
                    )
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
        let result_masking = self.result_masking_policy()?;
        if result_masking.is_some() {
            return Err(invalid_args(
                "streaming masked query results is temporarily unavailable because \
                 mask-decision certificates must be audit-bound before rows leave the server",
            )
            .with_next_step(
                "retry without streaming=true so the masked page can carry an audit-bound certificate",
            ));
        }
        let serialize_opts =
            query_serialize_options_from_args_with_policy(&a, result_masking.as_ref());
        let timeout = call_timeout_duration(a.timeout_seconds)?;
        let stream_budget = match timeout {
            Some(timeout) => request_budget.tighten_timeout(timeout),
            None => request_budget,
        };
        stream_budget.enforce(cx).map_err(DbError::into_envelope)?;
        let limits = ConnectionLimitGuard::install(
            cx,
            conn,
            Some(&self.quarantine),
            timeout,
            stream_budget.deadline(),
            Some(stream_budget.db_quota()),
        )
        .map_err(DbError::into_envelope)?;
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
        let restore = limits.restore();
        let stream_start = match (stream_start, restore) {
            (Ok(value), Ok(())) => value,
            (Err(err), _) => return Err(err),
            (Ok(QueryRowStreamStart::Stream(stream)), Err(err)) => {
                recover_row_stream_cleanup(cx, stream)
                    .await
                    .map_err(|recover_err| self.stream_db_error_envelope(recover_err))?;
                return Err(limit_restore_failure(&self.quarantine, false, err));
            }
            (Ok(_), Err(err)) => {
                return Err(limit_restore_failure(&self.quarantine, false, err));
            }
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
                // `query_row_stream` returned after the first guard was
                // restored. Reinstall the exact same absolute deadline and
                // shared quota for the entire multi-page fallback; otherwise
                // every page would receive a fresh relative timeout.
                let fallback_limits = ConnectionLimitGuard::install(
                    cx,
                    conn,
                    Some(&self.quarantine),
                    timeout,
                    stream_budget.deadline(),
                    Some(stream_budget.db_quota()),
                )
                .map_err(DbError::into_envelope)?;
                let response = Self::stream_query_response(
                    cx,
                    conn,
                    &stream_budget,
                    &executed_sql,
                    &a.sql,
                    &binds,
                    caps,
                    offset,
                    &serialize_opts,
                    active_profile.as_deref(),
                )
                .await;
                let restore_error = fallback_limits.restore().err();
                let response = match response {
                    Ok(response) => response,
                    Err(primary) => {
                        if let Some(restore_error) = restore_error {
                            let _ = mark_connection_quarantined(
                                &self.quarantine,
                                AuditOutcome::UnknownDiscarded,
                                format!(
                                    "chunked stream fallback failed and request-limit restoration also failed: {restore_error}"
                                ),
                            );
                        }
                        return Err(primary);
                    }
                };
                if let Some(restore_error) = restore_error {
                    return Err(limit_restore_failure(
                        &self.quarantine,
                        false,
                        restore_error,
                    ));
                }
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
        let recover = recover_row_stream_cleanup(cx, plan.stream)
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
        request_budget: &RequestBudget,
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
            request_budget.enforce(cx).map_err(DbError::into_envelope)?;
            let page = read_query(cx, conn, executed_sql, binds, caps, offset, serialize_opts)
                .await
                .map_err(DbError::into_envelope)?;
            request_budget.enforce(cx).map_err(DbError::into_envelope)?;
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
