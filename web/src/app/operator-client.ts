export type ProbeState = "loading" | "ok" | "warn" | "off";

export type ProbeKind = "public" | "operator";

export type ProbeDefinition = {
  id: string;
  label: string;
  path: string;
  kind: ProbeKind;
  group: "Runtime" | "Operator API";
};

export type ProbeResult = ProbeDefinition & {
  state: ProbeState;
  status: number | null;
  latencyMs: number | null;
  summary: string;
  detail: string;
  checkedAt: string;
};

export type DashboardActionTicket = {
  method: string;
  path: string;
  ticket: string;
};

export type DashboardSession = {
  csrf_token: string;
  csrf_header: string;
  action_ticket_header: string;
  expires_unix: number;
  action_tickets: DashboardActionTicket[];
};

export type OperatorResponse<T extends Record<string, unknown> = Record<string, unknown>> = {
  protocol_version: "operator.v1";
  schema_version: number;
  route: string;
  redaction_level: "operator_redacted";
  data: T;
};

export type WorkbenchMode = "classify_only" | "read_query" | "dml_preview_confirm" | "ddl_plan_confirm";

export type OperatingLevel = "READ_ONLY" | "READ_WRITE" | "DDL" | "ADMIN";

export type SessionLevelAction = "preview" | "apply" | "drop" | "status";

export type RequestCount = {
  tool: string;
  status: string;
  count: number;
};

export type HistogramSnapshot = {
  count: number;
  sum: number;
  max: number;
  mean: number;
};

export type LaneRequestCount = {
  lane_id: string;
  subject_id_hash: string;
  tool: string;
  status: string;
  count: number;
};

export type LaneBlockedCount = {
  lane_id: string;
  subject_id_hash: string;
  count: number;
};

export type LaneRequestDuration = {
  lane_id: string;
  subject_id_hash: string;
  tool: string;
  histogram: HistogramSnapshot;
};

export type ActiveLaneGauge = {
  lane_id: string;
  subject_id_hash: string;
  active: number;
};

export type ErrorCount = {
  ora_code: number;
  count: number;
};

export type MetricsSnapshot = {
  requests: RequestCount[];
  lane_requests?: LaneRequestCount[];
  lane_blocked?: LaneBlockedCount[];
  lane_request_duration_ms?: LaneRequestDuration[];
  errors: ErrorCount[];
  query_duration_ms: HistogramSnapshot;
  pool_wait_ms: HistogramSnapshot;
  pool_active_connections: number;
  active_lanes?: number;
  active_lane_gauges?: ActiveLaneGauge[];
};

export type CapacityLimitSource = {
  name: string;
  status: string;
  reason?: string;
  configured?: number;
  effective?: number;
};

export type CapacitySnapshot = {
  scope: string;
  subject: string;
  global_cap: number;
  regular_global_cap: number;
  regular_global_available: number;
  operator_reserved: number;
  doctor_reserved: number;
  per_subject_cap: number;
  per_subject_available: number;
  retry_after_ms: number;
};

export type OperatorCapacityData = {
  source: string;
  read_pool: {
    source: string;
    configured_per_profile: number;
    effective_per_profile: number;
    active: number;
    limit_sources: CapacityLimitSource[];
  };
  stateful_lanes: {
    source: string;
    configured: {
      global: number;
      per_subject: number;
      operator_reserved: number;
      doctor_reserved: number;
    };
    effective: CapacitySnapshot | null;
    active: number;
    regular_in_use: number;
    reserve: {
      operator: number;
      doctor: number;
      regular_global_cap: number;
    };
    at_capacity_events: number;
    retry_after_ms: number;
    limit_sources: CapacityLimitSource[];
  };
  idle_reaping: {
    enabled: boolean;
    ttl_seconds: number;
  };
};

export type OperatorMetricsData = {
  source: string;
  reason?: string;
  snapshot: MetricsSnapshot | null;
  capacity?: OperatorCapacityData | null;
};

export type OperatorHealthData = {
  source: string;
  liveness?: {
    status?: string;
    live?: boolean;
    ready?: boolean;
    version?: string | null;
  };
  readiness?: {
    status?: string;
    ready?: boolean;
    db_reachable?: boolean;
    draining?: boolean;
  };
};

export type ConfigProfileMetadata = {
  name: string;
  description?: string | null;
  is_default?: boolean;
  max_level?: string;
  default_level?: string;
  protected?: boolean;
  require_signed_tools?: boolean;
  read_only_standby?: boolean;
  mcp_exposed?: boolean;
  pool?: Record<string, unknown> | null;
};

export type ConfigOpsStatus = {
  target_path: string;
  target_exists: boolean;
  current_sha256: string;
  default_profile?: string | null;
  profiles: ConfigProfileMetadata[];
};

export type ConfigFieldChange = {
  path: string;
  before: unknown;
  after: unknown;
};

export type ConfigReloadDecision = {
  profile: string;
  action: string;
  reason: string;
};

export type ConfigReloadPlan = {
  hot_reloadable: boolean;
  restart_required: string[];
  profiles: ConfigReloadDecision[];
};

export type ConfigDraftPreview = {
  target_path: string;
  backup_path: string;
  original_existed: boolean;
  current_sha256: string;
  draft_sha256: string;
  redacted_diff: {
    changes: ConfigFieldChange[];
  };
  reload_plan: ConfigReloadPlan;
};

export type ConfigOpsStatusData = {
  source: string;
  status: ConfigOpsStatus;
};

export type ConfigDraftData = {
  source: string;
  preview: ConfigDraftPreview;
  redaction?: string;
};

export type ConfigApplyOutcome = {
  apply: {
    target_path: string;
    backup_path: string;
    original_existed: boolean;
    backup_sha256: string;
    applied_sha256: string;
    reload_plan: ConfigReloadPlan;
  };
  reload: {
    status: string;
    hot_reloadable: boolean;
    restart_required: string[];
    draining_profiles: string[];
    message: string;
  };
  rollback_id: string;
};

export type ConfigApplyData = {
  source: string;
  outcome: ConfigApplyOutcome;
  redaction?: string;
};

export type ConfigRollbackData = {
  source: string;
  outcome: {
    rollback: {
      target_path: string;
      backup_path: string;
      restored_sha256: string;
    };
    reload: ConfigApplyOutcome["reload"];
  };
};

export type ActiveLane = {
  lane_id: string;
  generation: number;
  status: string;
  subject_id_hash: string;
};

export type ActiveLanesData = {
  source: string;
  lanes: ActiveLane[];
};

export type OperatorEventEnvelope = {
  protocol_version: "operator.v1";
  schema_version: number;
  event_seq: number;
  event_id: string;
  lane_id: string;
  subject_id_hash: string;
  redaction_level: "operator_redacted";
  event_type: string;
  data: Record<string, unknown>;
};

export type ChangeProposalAuthorKind = "agent" | "human";

export type ChangeProposalApplyUnit = "read" | "dml" | "ddl";

export type ChangeProposalClassifierView = {
  required_level?: string | null;
  danger: string;
  reason: string;
};

export type ChangeProposalStatementView = {
  id: string;
  unit: ChangeProposalApplyUnit;
  sql_template: string;
  sql_sha256: string;
  bind_count: number;
  commit: boolean;
  capture_dbms_output: boolean;
  draft_verdict: ChangeProposalClassifierView;
  stored_verdict_present: boolean;
};

export type ChangeProposalView = {
  schema_version: number;
  id: string;
  profile: string;
  author: ChangeProposalAuthorKind;
  author_id_hash: string;
  title: string;
  created_at: string;
  updated_at: string;
  statement_count: number;
  statements: ChangeProposalStatementView[];
  stored_verdict_present: boolean;
};

export type ChangeProposalListData = {
  source: string;
  proposals: ChangeProposalView[];
};

export type ChangeProposalDraftStatement = {
  sql_template: string;
  binds?: unknown[];
  unit?: ChangeProposalApplyUnit;
  commit?: boolean;
  capture_dbms_output?: boolean;
  stored_verdict?: Record<string, unknown>;
};

export type ChangeProposalDraftRequest = {
  profile: string;
  author: ChangeProposalAuthorKind;
  title?: string;
  statements: ChangeProposalDraftStatement[];
  stored_verdict?: Record<string, unknown>;
};

export type ChangeProposalDraftData = {
  source: string;
  status: string;
  proposal: ChangeProposalView;
};

export type ChangeProposalApplyRequest = {
  proposalId: string;
  laneId?: string;
  confirm?: string;
  commit?: boolean;
};

export type ChangeProposalApplyData = {
  source: string;
  status: string;
  proposal: ChangeProposalView;
  lane_id?: string | null;
  atomicity?: Record<string, unknown>;
  results: Array<Record<string, unknown>>;
};

export type SourceSnapshotView = {
  schema_version: number;
  id: string;
  created_at: string;
  profile: string;
  owner: string;
  name: string;
  object_type: string;
  source_kind: string;
  source_sha256: string;
  source_lines: number;
  source_chars: number;
  proposal_id: string;
  statement_id: string;
  statement_sql_sha256: string;
  lane_id?: string | null;
  subject_id_hash: string;
};

export type SourceHistoryListData = {
  source: string;
  snapshots: SourceSnapshotView[];
  redaction?: string;
};

export type SourceHistoryRevertData = {
  source: string;
  status: string;
  snapshot: SourceSnapshotView;
  proposal: ChangeProposalView;
};

export type SchemaSnapshotObject = {
  object_type: string;
  name: string;
  ddl: string;
};

export type SchemaSnapshotInput = {
  objects: SchemaSnapshotObject[];
};

export type SchemaDiffObjectView = {
  kind: "added" | "dropped" | "changed";
  object_type: string;
  name: string;
  ddl_sha256: string;
  ddl_chars: number;
  source_replaceable: boolean;
};

export type SchemaDiffStepView = {
  order: number;
  kind: "create" | "replace" | "drop" | "manual_review";
  object_type: string;
  name: string;
  ddl_sha256: string;
  ddl_chars: number;
  executable: boolean;
  source_replaceable: boolean;
};

export type SchemaDiffExportData = {
  source: string;
  status: string;
  title: string;
  redaction: string;
  summary: {
    added: number;
    dropped: number;
    changed: number;
    migration_steps: number;
    executable_steps: number;
    manual_review_steps: number;
  };
  diff: {
    added: SchemaDiffObjectView[];
    dropped: SchemaDiffObjectView[];
    changed: SchemaDiffObjectView[];
  };
  migration_steps: SchemaDiffStepView[];
  migration_script_sha256: string;
  migration_script: string;
  proposal_statements: ChangeProposalDraftStatement[];
};

export type WorkbenchActionData = {
  status?: string;
  lane_id?: string | null;
  mcp_tool?: string;
  mcp_response?: unknown;
  idempotency?: Record<string, unknown>;
  error?: string;
  message?: string;
};

export const ORACLE_METADATA_SERIALIZATION_CONTRACT_VERSION = 1;

export type ExplorerDetailLevel = "names" | "summary" | "standard" | "full";

export type ExplorerCacheStatus = "hit" | "miss" | "stale" | "bypass";

export type ExplorerMetadataCacheKey = {
  db_fingerprint: string;
  profile: string;
  user: string;
  visible_schema: string;
  serialization_contract_version: number;
};

export type ExplorerCachedResult<T> = {
  value: T;
  status: ExplorerCacheStatus;
  bytes: number;
  cacheKey: string;
};

export type ExplorerConnectionData = WorkbenchActionData;

export type ExplorerSchemasRequest = {
  laneId?: string;
  nameLike?: string;
  maxRows: number;
};

export type ExplorerObjectsRequest = {
  laneId?: string;
  owner?: string;
  objectType?: string;
  nameLike?: string;
  detailLevel: ExplorerDetailLevel;
  maxRows: number;
};

export type ExplorerObjectRef = {
  owner: string;
  name: string;
  objectType: string;
};

export type ExplorerSourceRequest = ExplorerObjectRef & {
  laneId?: string;
  maxChars: number;
};

export type ExplorerSourceSearchRequest = {
  laneId?: string;
  owner?: string;
  objectType?: string;
  nameLike?: string;
  needle: string;
  maxRows: number;
};

export type WorkbenchSqlRequest = {
  sql: string;
  mode: WorkbenchMode;
  laneId?: string;
};

export type WorkbenchReadRequest = WorkbenchSqlRequest & {
  maxRows: number;
};

export type WorkbenchExecuteRequest = WorkbenchSqlRequest & {
  confirm?: string;
  commit: boolean;
  captureDbmsOutput: boolean;
};

export type WorkbenchPlsqlTool =
  | "oracle_plsql_parse"
  | "oracle_plsql_analyze"
  | "oracle_plsql_what_breaks"
  | "oracle_plsql_lineage"
  | "oracle_plsql_sast"
  | "oracle_plsql_doc";

export type WorkbenchPlsqlRequest = {
  laneId?: string;
  tool: WorkbenchPlsqlTool;
  arguments: Record<string, unknown>;
  idempotencyPrefix: string;
};

export type SessionLevelRequest = {
  laneId?: string;
  level?: OperatingLevel;
  ttlSeconds?: number;
  confirm?: string;
  action: SessionLevelAction;
};

export type AuditTailFilters = {
  limit: number;
  subjectIdHash: string;
  tool: string;
  dangerLevel: string;
  exportProofBundle: boolean;
};

export type AuditTailRecord = {
  schema_version: number;
  seq: number;
  timestamp: string;
  subject_id_hash: string;
  tool: string;
  danger_level: string;
  decision: string;
  outcome: string;
  rows_affected?: number | null;
  sql_sha256: string;
  sql_text?: Record<string, unknown>;
  db_evidence?: Record<string, unknown> | null;
  proof?: Record<string, unknown>;
  bind_values?: Record<string, unknown>;
};

export type AuditTailData = {
  source: string;
  reason?: string;
  limit: number;
  filters: Record<string, unknown>;
  scanned_records?: number;
  selected_records?: number;
  records: AuditTailRecord[];
  proof?: Record<string, unknown>;
  export?: Record<string, unknown> | null;
};

export type ClientCredentialStatus = "active" | "revoked";

export type ClientCredentialView = {
  client_id: string;
  label: string;
  scopes: string[];
  status: ClientCredentialStatus;
  subject_id_hash: string;
  generation: number;
  created_at: string;
  last_used_at?: string;
  last_source_addr?: string;
  rotated_at?: string;
  revoked_at?: string;
};

export type ClientCredentialsData = {
  source: string;
  error?: string;
  message?: string;
  clients: ClientCredentialView[];
  redaction?: string;
};

export type ClientCredentialLifecycle = {
  client_id: string;
  subject_id_hash: string;
  generation: number;
};

export type ClientCredentialRotateData = {
  source: string;
  status: "rotated";
  client: ClientCredentialView;
  bearer: string;
  bearer_shown_once: boolean;
  closed_principal: ClientCredentialLifecycle;
  closed_sessions: number;
  redaction: string;
};

export type ClientCredentialRevokeData = {
  source: string;
  status: "revoked";
  client?: ClientCredentialView | null;
  closed_principal: ClientCredentialLifecycle;
  closed_sessions: number;
  redaction: string;
};

export const overviewProbes: ProbeDefinition[] = [
  {
    id: "healthz",
    label: "Liveness",
    path: "/healthz",
    kind: "public",
    group: "Runtime"
  },
  {
    id: "readyz",
    label: "Readiness",
    path: "/readyz",
    kind: "public",
    group: "Runtime"
  },
  {
    id: "metrics",
    label: "Metrics",
    path: "/metrics",
    kind: "public",
    group: "Runtime"
  },
  {
    id: "dashboard-session",
    label: "Dashboard auth",
    path: "/dashboard/session",
    kind: "operator",
    group: "Operator API"
  },
  {
    id: "operator-schema",
    label: "Schema",
    path: "/operator/v1/schema",
    kind: "operator",
    group: "Operator API"
  },
  {
    id: "operator-health",
    label: "Health",
    path: "/operator/v1/health",
    kind: "operator",
    group: "Operator API"
  },
  {
    id: "operator-lanes",
    label: "Active lanes",
    path: "/operator/v1/active-lanes",
    kind: "operator",
    group: "Operator API"
  }
];

export const sessionsProbes = overviewProbes.filter((probe) =>
  ["operator-lanes", "operator-health"].includes(probe.id)
);

const operatorSchemaProbe = overviewProbes.find((probe) => probe.id === "operator-schema");

export const auditProbes: ProbeDefinition[] = [
  {
    id: "operator-audit-tail",
    label: "Audit tail",
    path: "/operator/v1/audit-tail",
    kind: "operator",
    group: "Operator API"
  },
  ...(operatorSchemaProbe ? [operatorSchemaProbe] : [])
];

export const doctorProbes = overviewProbes.filter((probe) =>
  ["healthz", "readyz", "operator-health"].includes(probe.id)
);

export function pendingProbe(definition: ProbeDefinition): ProbeResult {
  return {
    ...definition,
    state: "loading",
    status: null,
    latencyMs: null,
    summary: "checking",
    detail: "request in flight",
    checkedAt: new Date().toISOString()
  };
}

export async function fetchProbe(definition: ProbeDefinition): Promise<ProbeResult> {
  const startedAt = performance.now();
  try {
    const response = await fetch(definition.path, {
      headers: {
        accept: definition.path === "/metrics" ? "text/plain" : "application/json"
      },
      cache: "no-store",
      credentials: "same-origin"
    });
    const latencyMs = Math.max(0, Math.round(performance.now() - startedAt));
    const detail = await responseDetail(response);
    return {
      ...definition,
      state: stateForStatus(response.status, response.ok),
      status: response.status,
      latencyMs,
      summary: summaryForStatus(response.status, response.ok),
      detail,
      checkedAt: new Date().toISOString()
    };
  } catch (error) {
    return {
      ...definition,
      state: "warn",
      status: null,
      latencyMs: null,
      summary: "unreachable",
      detail: error instanceof Error ? error.message : "network failure",
      checkedAt: new Date().toISOString()
    };
  }
}

export async function fetchDashboardSession(): Promise<DashboardSession> {
  const response = await fetch("/dashboard/session", {
    headers: { accept: "application/json" },
    cache: "no-store",
    credentials: "same-origin"
  });
  return parseDashboardSession(response);
}

export async function fetchOperatorMetrics(): Promise<OperatorResponse<OperatorMetricsData>> {
  return operatorGet("/operator/v1/metrics");
}

export async function fetchOperatorHealth(): Promise<OperatorResponse<OperatorHealthData>> {
  return operatorGet("/operator/v1/health");
}

export async function fetchOperatorConfig(): Promise<OperatorResponse<ConfigOpsStatusData>> {
  return operatorGet("/operator/v1/config");
}

export async function fetchActiveLanes(): Promise<OperatorResponse<ActiveLanesData>> {
  return operatorGet("/operator/v1/active-lanes");
}

export async function fetchChangeProposals(): Promise<OperatorResponse<ChangeProposalListData>> {
  return operatorGet("/operator/v1/change-proposals");
}

export async function fetchSourceHistory(): Promise<OperatorResponse<SourceHistoryListData>> {
  return operatorGet("/operator/v1/source-history?max_rows=100");
}

export async function fetchClientCredentials(): Promise<OperatorResponse<ClientCredentialsData>> {
  return operatorGet("/operator/v1/client-credentials");
}

export async function rotateClientCredential(
  session: DashboardSession,
  clientId: string
): Promise<OperatorResponse<ClientCredentialRotateData>> {
  return operatorPost("/operator/v1/client-credentials/rotate", session, {
    client_id: clientId
  });
}

export async function revokeClientCredential(
  session: DashboardSession,
  clientId: string
): Promise<OperatorResponse<ClientCredentialRevokeData>> {
  return operatorPost("/operator/v1/client-credentials/revoke", session, {
    client_id: clientId
  });
}

export async function previewConfigDraft(
  session: DashboardSession,
  draftToml: string
): Promise<OperatorResponse<ConfigDraftData>> {
  return operatorPost("/operator/v1/config/draft", session, {
    draft_toml: draftToml
  });
}

export async function applyConfigDraft(
  session: DashboardSession,
  draftToml: string,
  expectedCurrentSha256: string
): Promise<OperatorResponse<ConfigApplyData>> {
  return operatorPost("/operator/v1/config/apply", session, {
    draft_toml: draftToml,
    expected_current_sha256: expectedCurrentSha256
  });
}

export async function rollbackConfigDraft(
  session: DashboardSession,
  rollbackId: string
): Promise<OperatorResponse<ConfigRollbackData>> {
  return operatorPost("/operator/v1/config/rollback", session, {
    rollback_id: rollbackId
  });
}

export async function draftChangeProposal(
  session: DashboardSession,
  request: ChangeProposalDraftRequest
): Promise<OperatorResponse<ChangeProposalDraftData>> {
  return operatorPost("/operator/v1/change-proposals/draft", session, {
    profile: request.profile,
    author: request.author,
    title: request.title,
    statements: request.statements,
    stored_verdict: request.stored_verdict
  });
}

export async function applyChangeProposal(
  session: DashboardSession,
  request: ChangeProposalApplyRequest
): Promise<OperatorResponse<ChangeProposalApplyData>> {
  return operatorPost("/operator/v1/change-proposals/apply", session, {
    proposal_id: request.proposalId,
    lane_id: laneIdValue(request.laneId),
    confirm: request.confirm?.trim() || undefined,
    commit: request.commit,
    idempotency_key: requestId("change-proposal-apply")
  });
}

export async function draftSourceHistoryRevert(
  session: DashboardSession,
  snapshotId: string,
  profile?: string
): Promise<OperatorResponse<SourceHistoryRevertData>> {
  return operatorPost("/operator/v1/source-history/revert", session, {
    snapshot_id: snapshotId,
    profile: optionalString(profile)
  });
}

export async function previewSchemaDiff(
  session: DashboardSession,
  before: SchemaSnapshotInput,
  after: SchemaSnapshotInput,
  title?: string
): Promise<OperatorResponse<SchemaDiffExportData>> {
  return operatorPost("/operator/v1/schema-diff", session, {
    before,
    after,
    title: title?.trim() || undefined
  });
}

export async function previewWorkbenchSql(
  session: DashboardSession,
  request: WorkbenchSqlRequest
): Promise<OperatorResponse<WorkbenchActionData>> {
  return operatorPost("/operator/v1/actions/preview", session, {
    idempotency_key: requestId("workbench-preview"),
    lane_id: laneIdValue(request.laneId),
    tool: "oracle_preview_sql",
    arguments: {
      sql: request.sql
    }
  });
}

export async function readWorkbenchSql(
  session: DashboardSession,
  request: WorkbenchReadRequest
): Promise<OperatorResponse<WorkbenchActionData>> {
  return operatorPost("/operator/v1/actions/execute", session, {
    idempotency_key: requestId("workbench-read"),
    lane_id: laneIdValue(request.laneId),
    tool: "oracle_query",
    arguments: {
      sql: request.sql,
      max_rows: request.maxRows
    }
  });
}

export async function executeWorkbenchSql(
  session: DashboardSession,
  request: WorkbenchExecuteRequest
): Promise<OperatorResponse<WorkbenchActionData>> {
  return operatorPost("/operator/v1/actions/execute", session, {
    idempotency_key: requestId(request.commit ? "workbench-commit" : "workbench-rollback-preview"),
    lane_id: laneIdValue(request.laneId),
    tool: "oracle_execute",
    arguments: {
      sql: request.sql,
      binds: [],
      commit: request.commit,
      confirm: request.confirm?.trim() || undefined,
      capture_dbms_output: request.captureDbmsOutput
    }
  });
}

export async function runWorkbenchPlsqlTool(
  session: DashboardSession,
  request: WorkbenchPlsqlRequest
): Promise<OperatorResponse<WorkbenchActionData>> {
  return operatorPost("/operator/v1/actions/execute", session, {
    idempotency_key: requestId(request.idempotencyPrefix),
    lane_id: laneIdValue(request.laneId),
    tool: request.tool,
    arguments: request.arguments
  });
}

export async function setSessionLevel(
  session: DashboardSession,
  request: SessionLevelRequest
): Promise<OperatorResponse<WorkbenchActionData>> {
  const argumentsBody: Record<string, unknown> = {
    action: request.action
  };
  if (request.action === "preview") {
    argumentsBody["execute"] = false;
  }
  if (request.action === "apply") {
    argumentsBody["execute"] = true;
  }
  if (request.action !== "drop" && request.level) {
    argumentsBody["level"] = request.level;
  }
  if (request.ttlSeconds && request.action !== "drop") {
    argumentsBody["ttl_seconds"] = request.ttlSeconds;
  }
  if (request.action !== "drop" && request.confirm?.trim()) {
    argumentsBody["confirm"] = request.confirm.trim();
  }
  return operatorPost("/operator/v1/session/set-level", session, {
    idempotency_key: requestId(`session-level-${request.action}`),
    lane_id: laneIdValue(request.laneId),
    arguments: argumentsBody
  });
}

export async function fetchExplorerConnection(
  session: DashboardSession,
  laneId?: string
): Promise<OperatorResponse<ExplorerConnectionData>> {
  return operatorPost("/operator/v1/actions/execute", session, {
    idempotency_key: requestId("explorer-connection"),
    lane_id: laneIdValue(laneId),
    tool: "oracle_connection_info",
    arguments: {}
  });
}

export async function fetchLaneCapabilities(
  session: DashboardSession,
  laneId?: string
): Promise<OperatorResponse<WorkbenchActionData>> {
  return operatorPost("/operator/v1/actions/execute", session, {
    idempotency_key: requestId("session-capabilities"),
    lane_id: laneIdValue(laneId),
    tool: "oracle_capabilities",
    arguments: {}
  });
}

export async function fetchExplorerSchemas(
  session: DashboardSession,
  request: ExplorerSchemasRequest
): Promise<OperatorResponse<WorkbenchActionData>> {
  return operatorPost("/operator/v1/actions/execute", session, {
    idempotency_key: requestId("explorer-schemas"),
    lane_id: laneIdValue(request.laneId),
    tool: "oracle_list_schemas",
    arguments: {
      name_like: optionalString(request.nameLike),
      max_rows: request.maxRows
    }
  });
}

export async function fetchExplorerObjects(
  session: DashboardSession,
  request: ExplorerObjectsRequest
): Promise<OperatorResponse<WorkbenchActionData>> {
  return operatorPost("/operator/v1/actions/execute", session, {
    idempotency_key: requestId("explorer-objects"),
    lane_id: laneIdValue(request.laneId),
    tool: "oracle_search_objects",
    arguments: {
      owner: optionalString(request.owner),
      object_type: optionalString(request.objectType),
      name_like: optionalString(request.nameLike),
      detail_level: request.detailLevel,
      max_rows: request.maxRows
    }
  });
}

export async function fetchExplorerDdl(
  session: DashboardSession,
  request: ExplorerObjectRef & { laneId?: string }
): Promise<OperatorResponse<WorkbenchActionData>> {
  return operatorPost("/operator/v1/actions/execute", session, {
    idempotency_key: requestId("explorer-ddl"),
    lane_id: laneIdValue(request.laneId),
    tool: "oracle_get_ddl",
    arguments: {
      owner: request.owner,
      name: request.name,
      object_type: ddlObjectType(request.objectType)
    }
  });
}

export async function fetchExplorerSource(
  session: DashboardSession,
  request: ExplorerSourceRequest
): Promise<OperatorResponse<WorkbenchActionData>> {
  return operatorPost("/operator/v1/actions/execute", session, {
    idempotency_key: requestId("explorer-source"),
    lane_id: laneIdValue(request.laneId),
    tool: "oracle_get_source",
    arguments: {
      owner: request.owner,
      name: request.name,
      object_type: sourceObjectType(request.objectType),
      max_chars: request.maxChars
    }
  });
}

export async function fetchExplorerSourceSearch(
  session: DashboardSession,
  request: ExplorerSourceSearchRequest
): Promise<OperatorResponse<WorkbenchActionData>> {
  return operatorPost("/operator/v1/actions/execute", session, {
    idempotency_key: requestId("explorer-source-search"),
    lane_id: laneIdValue(request.laneId),
    tool: "oracle_search_source",
    arguments: {
      owner: optionalString(request.owner),
      object_type: optionalString(request.objectType),
      name_like: optionalString(request.nameLike),
      needle: request.needle.trim(),
      max_rows: request.maxRows
    }
  });
}

export async function cachedExplorerMetadata<T>(
  scope: ExplorerMetadataCacheKey,
  slot: string,
  load: () => Promise<T>
): Promise<ExplorerCachedResult<T>> {
  const cacheKey = explorerCacheKey(scope, slot);
  const now = Date.now();
  const existing = explorerMetadataCache.get(cacheKey);
  if (existing) {
    if (existing.expiresAt > now) {
      existing.lastAccessed = now;
      return {
        value: existing.value as T,
        status: "hit",
        bytes: existing.bytes,
        cacheKey
      };
    }
    removeExplorerCacheEntry(cacheKey);
  }
  const value = await load();
  const bytes = approxJsonBytes(value);
  if (bytes > EXPLORER_METADATA_CACHE_MAX_BYTES) {
    return { value, status: "bypass", bytes, cacheKey };
  }
  explorerMetadataCache.set(cacheKey, {
    value,
    bytes,
    expiresAt: now + EXPLORER_METADATA_CACHE_TTL_MS,
    lastAccessed: now
  });
  explorerMetadataCacheBytes += bytes;
  trimExplorerMetadataCache();
  return { value, status: existing ? "stale" : "miss", bytes, cacheKey };
}

export function clearExplorerMetadataCache(): void {
  explorerMetadataCache.clear();
  explorerMetadataCacheBytes = 0;
}

export function explorerMetadataCacheSummary(): { entries: number; bytes: number } {
  trimExplorerMetadataCache();
  return {
    entries: explorerMetadataCache.size,
    bytes: explorerMetadataCacheBytes
  };
}

export async function fetchAuditTail(
  filters: AuditTailFilters
): Promise<OperatorResponse<AuditTailData>> {
  const params = new URLSearchParams();
  params.set("limit", String(filters.limit));
  setOptionalParam(params, "subject_id_hash", filters.subjectIdHash);
  setOptionalParam(params, "tool", filters.tool);
  setOptionalParam(params, "level", filters.dangerLevel);
  if (filters.exportProofBundle) {
    params.set("export", "proof-bundle");
  }
  const suffix = params.toString();
  const response = await fetch(`/operator/v1/audit-tail${suffix ? `?${suffix}` : ""}`, {
    headers: { accept: "application/json" },
    cache: "no-store",
    credentials: "same-origin"
  });
  const parsed = (await response.json()) as unknown;
  if (!response.ok) {
    throw new Error(errorMessage(parsed, response.status));
  }
  return parsed as OperatorResponse<AuditTailData>;
}

async function operatorGet<T extends Record<string, unknown>>(
  path: string
): Promise<OperatorResponse<T>> {
  const response = await fetch(path, {
    headers: { accept: "application/json" },
    cache: "no-store",
    credentials: "same-origin"
  });
  const parsed = (await response.json()) as unknown;
  if (!response.ok) {
    throw new Error(errorMessage(parsed, response.status));
  }
  return parsed as OperatorResponse<T>;
}

function setOptionalParam(params: URLSearchParams, key: string, value: string): void {
  const trimmed = value.trim();
  if (trimmed) {
    params.set(key, trimmed);
  }
}

function optionalString(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function stateForStatus(status: number, ok: boolean): ProbeState {
  if (ok) {
    return "ok";
  }
  if (status === 404) {
    return "off";
  }
  return "warn";
}

function summaryForStatus(status: number, ok: boolean): string {
  if (ok) {
    return "ok";
  }
  if (status === 404) {
    return "not mounted";
  }
  if (status === 401 || status === 403) {
    return "auth gated";
  }
  return `HTTP ${status}`;
}

async function responseDetail(response: Response): Promise<string> {
  const contentType = response.headers.get("content-type") ?? "";
  const body = await response.text();
  if (!body) {
    return response.statusText || "empty response";
  }
  if (contentType.includes("application/json")) {
    try {
      const parsed = JSON.parse(body) as unknown;
      if (parsed && typeof parsed === "object") {
        const object = parsed as Record<string, unknown>;
        if (typeof object["message"] === "string") {
          return object["message"];
        }
        if (typeof object["error"] === "string") {
          return object["error"];
        }
        if (typeof object["kind"] === "string") {
          return object["kind"];
        }
      }
    } catch {
      return body.slice(0, 160);
    }
  }
  return body.replace(/\s+/g, " ").trim().slice(0, 160);
}

async function parseDashboardSession(response: Response): Promise<DashboardSession> {
  const parsed = (await response.json()) as unknown;
  if (!response.ok) {
    throw new Error(errorMessage(parsed, response.status));
  }
  return parsed as DashboardSession;
}

async function operatorPost<T extends Record<string, unknown>>(
  path: string,
  session: DashboardSession,
  body: Record<string, unknown>
): Promise<OperatorResponse<T>> {
  const actionTicket = actionTicketFor(session, path);
  const headers: Record<string, string> = {
    accept: "application/json",
    "content-type": "application/json"
  };
  headers[session.csrf_header] = session.csrf_token;
  headers[session.action_ticket_header] = actionTicket;
  const response = await fetch(path, {
    method: "POST",
    headers,
    cache: "no-store",
    credentials: "same-origin",
    body: JSON.stringify(body)
  });
  const parsed = (await response.json()) as unknown;
  if (!response.ok) {
    throw new Error(errorMessage(parsed, response.status));
  }
  return parsed as OperatorResponse<T>;
}

function actionTicketFor(session: DashboardSession, path: string): string {
  const ticket = session.action_tickets.find(
    (candidate) => candidate.method === "POST" && candidate.path === path
  );
  if (!ticket) {
    throw new Error(`missing dashboard action ticket for ${path}`);
  }
  return ticket.ticket;
}

function laneIdValue(laneId: string | undefined): string | undefined {
  const trimmed = laneId?.trim();
  return trimmed ? trimmed : undefined;
}

function ddlObjectType(objectType: string): string {
  return objectType.trim().toUpperCase().replace(/\s+/g, "_");
}

function sourceObjectType(objectType: string): string | undefined {
  const normalized = objectType.trim().toUpperCase();
  if (!normalized || normalized === "VIEW") {
    return undefined;
  }
  return normalized;
}

type ExplorerMetadataCacheEntry = {
  value: unknown;
  bytes: number;
  expiresAt: number;
  lastAccessed: number;
};

const EXPLORER_METADATA_CACHE_TTL_MS = 60_000;
const EXPLORER_METADATA_CACHE_MAX_BYTES = 512_000;
const EXPLORER_METADATA_CACHE_MAX_ENTRIES = 64;
const explorerMetadataCache = new Map<string, ExplorerMetadataCacheEntry>();
let explorerMetadataCacheBytes = 0;

function explorerCacheKey(scope: ExplorerMetadataCacheKey, slot: string): string {
  return JSON.stringify({
    db_fingerprint: scope.db_fingerprint,
    profile: scope.profile,
    user: scope.user,
    visible_schema: scope.visible_schema,
    serialization_contract_version: scope.serialization_contract_version,
    slot
  });
}

function removeExplorerCacheEntry(cacheKey: string): void {
  const existing = explorerMetadataCache.get(cacheKey);
  if (!existing) {
    return;
  }
  explorerMetadataCache.delete(cacheKey);
  explorerMetadataCacheBytes = Math.max(0, explorerMetadataCacheBytes - existing.bytes);
}

function trimExplorerMetadataCache(): void {
  const now = Date.now();
  for (const [cacheKey, entry] of explorerMetadataCache) {
    if (entry.expiresAt <= now) {
      removeExplorerCacheEntry(cacheKey);
    }
  }
  while (
    explorerMetadataCache.size > EXPLORER_METADATA_CACHE_MAX_ENTRIES ||
    explorerMetadataCacheBytes > EXPLORER_METADATA_CACHE_MAX_BYTES
  ) {
    const oldest = [...explorerMetadataCache.entries()].sort(
      (a, b) => a[1].lastAccessed - b[1].lastAccessed
    )[0];
    if (!oldest) {
      break;
    }
    removeExplorerCacheEntry(oldest[0]);
  }
}

function approxJsonBytes(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

function requestId(prefix: string): string {
  if (typeof crypto.randomUUID === "function") {
    return `${prefix}:${crypto.randomUUID()}`;
  }
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return `${prefix}:${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function errorMessage(parsed: unknown, status: number): string {
  if (parsed && typeof parsed === "object") {
    const object = parsed as Record<string, unknown>;
    const data = object["data"];
    if (data && typeof data === "object") {
      const dataObject = data as Record<string, unknown>;
      if (typeof dataObject["message"] === "string") {
        return dataObject["message"];
      }
      if (typeof dataObject["error"] === "string") {
        return dataObject["error"];
      }
    }
    if (typeof object["message"] === "string") {
      return object["message"];
    }
    if (typeof object["error"] === "string") {
      return object["error"];
    }
  }
  return `HTTP ${status}`;
}
