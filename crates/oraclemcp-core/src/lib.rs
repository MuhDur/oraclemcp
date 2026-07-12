#![recursion_limit = "256"]
#![forbid(unsafe_code)]
// ErrorEnvelope is the deliberate agent-facing error payload (§8.2); it is the
// `Err` of the dispatch contract throughout this crate. Boxing every
// `Result<_, ErrorEnvelope>` to satisfy `result_large_err` would add noise on
// cold error paths for no real benefit.
#![allow(clippy::result_large_err)]

//! The MCP protocol surface and tool-registry contract for the `oraclemcp`
//! server. In Phase A this hosts the JSON-RPC protocol, the loopback-safe
//! transports, the `ToolRegistry`/`Tool` contract, the trust-block injector
//! and the `doctor` report lifted from `plsql-mcp` (P0-0); P0-6 replaces the
//! native MCP protocol helpers and adds `oracle_capabilities`.
//!
//! Engine intelligence reaches this core by the engine-side code implementing
//! the registry's `Tool` contract — the core never reaches into engine
//! internals (the one-way boundary, §0 hard rule 1).

pub mod admin_auth;
pub mod admission;
pub mod audit_shipping;
pub mod capabilities;
pub mod capability;
pub mod change_proposal;
pub mod client_credentials;
pub mod config_ops;
pub mod connect;
pub mod custom_tools;
pub mod dashboard_auth;
mod dashboard_bundle;
pub mod doctor;
pub mod export;
pub mod fence;
pub mod file_store;
pub mod http;
pub mod iam_token;
pub mod init_token;
pub mod lane;
pub mod notifications;
pub mod operator_protocol;
pub mod pagination;
pub mod plugin;
pub mod query_execute;
pub mod redacted;
pub mod request_budget;
pub mod resilience;
pub mod resources;
mod schema_diff_export;
pub mod server;
pub mod service_app;
pub mod session_tool;
pub mod shutdown;
pub mod source_history;
pub mod subscriptions;
pub mod tamper_token;
pub mod tls;
pub mod tools;
pub mod trace;
pub mod write_intent;

pub use request_budget::{
    CLEANUP_POLL_QUOTA, DEFAULT_REQUEST_POLL_QUOTA, DEFAULT_REQUEST_TIMEOUT, RequestBudget,
};
pub use resilience::{
    CircuitBreaker, CircuitState, RetryPolicy, is_transient_error, run_with_timeout,
};
pub use server::{
    CAPABILITIES_TOOL, DispatchCloseFuture, DispatchCloseReason, DispatchContext, DispatchFuture,
    DispatchOutcome, DispatchReplyReceiver, DispatchStreamStartFuture, McpSurfaceDetail,
    McpSurfaceFuture, McpSurfaceOutcome, McpSurfaceState, McpToolCatalogSnapshot, OracleMcpServer,
    ToolDispatch, ToolStreamFrame, ToolStreamSender,
};
pub use shutdown::{CancelOutcome, ShutdownCoordinator, install_panic_hook};
pub use source_history::{
    SourceHistoryError, SourceHistoryFilter, SourceHistoryRevertRequest, SourceHistoryStore,
    SourceObjectTarget, SourceSnapshot, SourceSnapshotDraft, SourceSnapshotView,
    normalize_source_object_type, source_object_from_create_or_replace_sql,
};

pub use admin_auth::{
    AdminAssertionVerifier, AdminAuthError, AdminAuthPolicy, OperatorAuthorityPolicy,
    audit_subject_from_principal_key,
};
pub use admission::{AdmissionController, AdmissionPermit};
pub use audit_shipping::{SiemFormat, SiemHttpForwarder};
pub use capabilities::{
    CapabilitiesReport, ConnectionStatus, FeatureTiers, OperatingLevelReport, PROTOCOL_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS, ToolSurfaceFeatures,
};
pub use capability::{
    LaneCaps, PrivilegedEffect, ReadPathCaps, narrow_to_lane, narrow_to_read_path,
    requires_privileged_effect,
};
pub use change_proposal::{
    ChangeProposal, ChangeProposalApplyRequest, ChangeProposalApplyUnit, ChangeProposalAuthorKind,
    ChangeProposalClassifierView, ChangeProposalDraftOutcome, ChangeProposalDraftRequest,
    ChangeProposalError, ChangeProposalStatement, ChangeProposalStatementDraft,
    ChangeProposalStatementView, ChangeProposalStore, ChangeProposalView,
};
pub use client_credentials::{
    AuthenticatedClientCredential, ClientCredentialDurability, ClientCredentialError,
    ClientCredentialIssueRequest, ClientCredentialLifecycle, ClientCredentialStatus,
    ClientCredentialStore, ClientCredentialView, IssuedClientCredential, looks_like_client_bearer,
};
pub use config_ops::{
    ConfigApplyOutcome, ConfigApplyReport, ConfigDraftPlan, ConfigDraftPreview, ConfigFieldChange,
    ConfigOpsBackend, ConfigOpsError, ConfigOpsService, ConfigOpsStatus, ConfigRedactedDiff,
    ConfigReloadApplier, ConfigReloadApplyReport, ConfigReviewEvidence, ConfigReviewedDraftPreview,
    ConfigRollbackOutcome, ConfigRollbackReport,
};
pub use connect::{SessionContext, build_session_context, profile_to_options, session_level_state};
pub use custom_tools::{
    CustomToolCatalog, CustomToolDef, CustomToolExecutor, LoadError, LoadedTool, OutputMode,
    ParamDef, ParamType, RUN_NAMED_TOOL, ToolBody, bind_params, classify_at_load,
    enforce_signature, execute_custom_tool, load_tools, load_tools_for_profile, parse_tools_file,
    register_custom_tools, sign, verify_signature,
};
pub use dashboard_auth::{
    DASHBOARD_ACTION_TICKET_HEADER, DASHBOARD_CSRF_HEADER, DASHBOARD_HTTP_PROBE_PATH,
    DASHBOARD_HTTP_PROBE_TIMEOUT, DASHBOARD_PAIR_PATH, DASHBOARD_SESSION_COOKIE,
    DASHBOARD_SESSION_PATH, DashboardAuth, DashboardAuthError, DashboardPairingTicket,
    DashboardSessionView, default_dashboard_ticket_dir, mint_dashboard_pairing_ticket,
    probe_dashboard_http_service,
};
pub use doctor::{
    AuthModeClass, CheckResult, CheckStatus, DoctorAuthCapabilities, DoctorAuthModeCapability,
    DoctorAuthModeKind, DoctorAuthModeSupport, DoctorContext, DoctorFixOutcome, DoctorFixPolicy,
    DoctorFixRefusal, DoctorFixReport, DoctorLegacyStateMigrationPlan, DoctorLevelCaps,
    DoctorProfileCaps, DoctorReport, DoctorServiceUnitCaps, DoctorServiceUnitLimitCaps,
    DoctorStateLayout, apply_legacy_state_migration, classify_auth_mode, run_doctor,
};
pub use export::{
    ExportAccess, ExportContents, ExportFormat, ExportHandle, ExportRegistry,
    STDIO_EXPORT_PRINCIPAL, export_uri,
};
pub use file_store::{
    FileStore, FileStoreError, JsonlIndex, JsonlRecord, PruneReport, RecoveryReport,
    RetentionClass, ServiceOwner, StoreId,
};
pub use http::{
    EffectiveHttpScheme, HEALTHZ_PATH, HttpRequest, HttpResponse, HttpResultStore,
    HttpSessionLifecycle, HttpTransportConfig, MCP_PATH, METRICS_PATH, MtlsClientRegistry,
    OAuthEnforcement, OPERATOR_API_PREFIX, ObservabilityState, OperatorEventStore,
    OperatorIdempotencyLedger, PROTECTED_RESOURCE_METADATA_PATH, READYZ_PATH, ReadinessProbe,
    ScopeGrant, close_http_principal_sessions, handle_http_request, serve_http, serve_http_until,
    serve_https, serve_https_until,
};
pub use iam_token::{
    IAM_TOKEN_ENV, IamTokenError, ServerIamTokenSource, inject_iam_token, jwt_exp_unix,
};
pub use init_token::{InitTokenError, STDIO_TOKEN_ENV, StdioAuthPolicy};
pub use lane::{
    DEFAULT_LANE_MAILBOX_CAPACITY, LaneContext, LaneDispatchFactory, LaneDispatchFactoryBuilder,
    LaneRuntime, LaneRuntimeStatus, PreparedLaneDispatch, StatefulLaneDispatch,
    block_on_lane_bridge,
};
pub use notifications::{NotificationHub, progress_token_from_params};
pub use operator_protocol::{
    OPERATOR_PROTOCOL_VERSION, OPERATOR_REDACTION_LEVEL, OPERATOR_ROUTE_SPECS,
    OPERATOR_SCHEMA_VERSION, operator_schema_bundle, operator_subject_id_hash,
};
pub use plugin::{
    PluginCapability, PluginError, PluginManifest, PluginRequest, PluginResponse, SubprocessPlugin,
    check_capability,
};
pub use query_execute::{ExecuteParams, StatementExecutor, oracle_query_execute};
pub use resources::{
    PromptArg, PromptDef, PromptMessage, ResourceContents, ResourceProvider, ResourceTemplate,
    ResourceUri, prompt_catalog, read_resource, render_prompt, resource_templates,
};
pub use service_app::{
    SERVICE_APP_NAME, SERVICE_CHILD_AUDIT_CHAIN_WRITER, SERVICE_CHILD_DASHBOARD_API,
    SERVICE_CHILD_LANE_REGISTRY_SUPERVISOR, SERVICE_CHILD_METRICS_HEALTH_COLLECTOR,
    SERVICE_CHILD_TRANSPORT, ServiceAppChild, ServiceAppDoctorSnapshot, ServiceAppRuntime,
    ServiceAppStartError, ServiceAppStopError, ServiceCancellationDoctorSnapshot,
    ServiceCapsDoctorSnapshot, ServiceChildDoctorSnapshot, ServiceSpectralDoctorSnapshot,
    ServiceTaskDoctorSnapshot, ServiceTransport, oraclemcp_service_app_spec,
    service_app_doctor_snapshot, service_app_start_order, start_oraclemcp_service_app,
    start_oraclemcp_service_app_with_transport,
};
pub use session_tool::{LeaseAcquirer, SessionAction, SessionDeps, oracle_session};
pub use subscriptions::{PollingSource, SubscribeSource, SubscriptionHub, SubscriptionRegistry};
pub use tamper_token::{sign_token, verify_token};
pub use tls::{TlsError, TlsMaterial, TlsServerConfig, build_server_config, requires_mtls};
pub use tools::{ToolDescriptor, ToolRegistry, ToolTier};
pub use trace::TraceContext;
pub use write_intent::{
    WriteIntent, WriteIntentDetails, WriteIntentError, WriteIntentLog, WriteIntentOutcome,
};

/// Re-export the shared agent-facing error envelope.
pub use oraclemcp_error as error;
