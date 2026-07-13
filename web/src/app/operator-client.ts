import {
  driftSections,
  isRegisteredDerivationStep,
  type CostPlanRowViewModel,
  type ClearanceLevel,
  type CostCeilingSource,
  type CostRefusalInput,
  type FleetDbStatus,
  type FleetMapInput,
  type MaskAction,
  type MaskCertificateInput,
  type MaskSource,
  type PolicyTighteningInput,
  type VerdictKind,
  type VerdictProofCheckView,
  type VerdictProofInput
} from "./presentation-model";

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

export type OperatorOutcomeState = "success" | "refused" | "failed" | "partial";

export type OperatorOutcome = {
  state: OperatorOutcomeState;
  message: string;
  nextSteps: string[];
  errorClass: string | null;
};

const refusalErrorClasses = new Set([
  "CHALLENGE_REQUIRED",
  "FORBIDDEN_STATEMENT",
  "INSUFFICIENT_PRIVILEGE",
  "LEASE_REQUIRED",
  "OPERATING_LEVEL_TOO_LOW",
  "POLICY_DENIED",
  "RUNTIME_STATE_REQUIRED"
]);

/**
 * A transport-complete operator response whose operation did not succeed.
 *
 * JSON-RPC and MCP tool failures intentionally ride HTTP 200. Keeping the
 * decoded outcome and original redacted response on the error lets React Query
 * avoid success callbacks without throwing away the operator-facing detail.
 */
export class OperatorOutcomeError extends Error {
  readonly outcome: OperatorOutcome;
  readonly response: unknown;
  readonly httpStatus: number;

  constructor(outcome: OperatorOutcome, response: unknown, httpStatus: number) {
    super(outcome.message);
    this.name = "OperatorOutcomeError";
    this.outcome = outcome;
    this.response = response;
    this.httpStatus = httpStatus;
  }
}

export function operatorOutcomeFromError(error: unknown, fallback: string): OperatorOutcome {
  if (error instanceof OperatorOutcomeError) {
    return error.outcome;
  }
  return {
    state: "failed",
    message: error instanceof Error ? error.message : fallback,
    nextSteps: [],
    errorClass: null
  };
}

export function operatorResponseFromError<
  T extends Record<string, unknown> = Record<string, unknown>
>(error: unknown): OperatorResponse<T> | null {
  if (!(error instanceof OperatorOutcomeError) || !isOperatorResponse(error.response)) {
    return null;
  }
  return error.response as OperatorResponse<T>;
}

/** Decode transport, operator-domain, JSON-RPC, and MCP tool outcomes once. */
export function decodeOperatorOutcome(httpStatus: number, payload: unknown): OperatorOutcome {
  const envelope = recordValue(payload);
  const data = recordValue(envelope?.["data"]) ?? envelope;
  const route = stringValue(envelope?.["route"]);

  if (httpStatus < 200 || httpStatus >= 300) {
    const error = recordValue(data?.["error"]);
    const errorData = recordValue(error?.["data"]);
    const errorClass =
      stringValue(data?.["error_class"]) ?? stringValue(errorData?.["error_class"]);
    return outcome(
      httpStatus === 401 || httpStatus === 403 || isRefusalClass(errorClass)
        ? "refused"
        : "failed",
      messageFrom(data, `operator request failed with HTTP ${httpStatus}`),
      nextStepsFrom(data),
      errorClass
    );
  }

  if (!data) {
    return outcome("failed", "operator response was not a JSON object", [], null);
  }

  if (route === "/operator/v1/change-proposals/apply") {
    const status = stringValue(data["status"]);
    if (status === "stopped_on_failure") {
      const nested = firstFailedProposalOutcome(data);
      return outcome(
        "partial",
        nested
          ? `Change proposal stopped on a failed statement: ${nested.message}`
          : "Change proposal stopped on a failed statement",
        nested?.nextSteps ?? [],
        nested?.errorClass ?? null
      );
    }
    if (status && status !== "applied") {
      return outcome(
        "partial",
        messageFrom(data, `Change proposal did not complete (${status})`),
        nextStepsFrom(data),
        stringValue(data["error_class"])
      );
    }
  }

  const domainError = data["error"];
  if (domainError !== undefined && domainError !== null) {
    const errorClass = stringValue(data["error_class"]);
    return outcome(
      isRefusalClass(errorClass) ? "refused" : "failed",
      messageFrom(data, "operator action failed"),
      nextStepsFrom(data),
      errorClass
    );
  }

  const status = stringValue(data["status"]);
  if (status === "accepted") {
    return outcome(
      "partial",
      "Operator action was accepted but no terminal MCP result was returned",
      ["Wait for a terminal result before treating the operation as complete."],
      null
    );
  }

  if (Object.prototype.hasOwnProperty.call(data, "mcp_response")) {
    const mcpResponse = recordValue(data["mcp_response"]);
    if (!mcpResponse) {
      return outcome("failed", "forwarded operator action returned no MCP response", [], null);
    }
    return decodeMcpOutcome(mcpResponse);
  }

  return outcome("success", "Operation completed", [], null);
}

function decodeMcpOutcome(mcpResponse: Record<string, unknown>): OperatorOutcome {
  const rpcError = recordValue(mcpResponse["error"]);
  if (rpcError) {
    const rpcData = recordValue(rpcError["data"]);
    const errorClass = stringValue(rpcData?.["error_class"]);
    return outcome(
      isRefusalClass(errorClass) ? "refused" : "failed",
      stringValue(rpcError["message"]) ?? messageFrom(rpcData, "JSON-RPC request failed"),
      nextStepsFrom(rpcData),
      errorClass
    );
  }

  const result = recordValue(mcpResponse["result"]);
  if (!result) {
    return outcome("failed", "MCP response did not include a result", [], null);
  }
  if (result["isError"] === true) {
    const structured = recordValue(result["structuredContent"]) ?? result;
    const errorClass = stringValue(structured["error_class"]);
    return outcome(
      isRefusalClass(errorClass) ? "refused" : "failed",
      messageFrom(structured, "MCP tool call failed"),
      nextStepsFrom(structured),
      errorClass
    );
  }

  return outcome("success", "Operation completed", [], null);
}

function firstFailedProposalOutcome(data: Record<string, unknown>): OperatorOutcome | null {
  const results = Array.isArray(data["results"]) ? data["results"] : [];
  for (const item of results) {
    const result = recordValue(item);
    const actionResponse = result?.["action_response"];
    if (actionResponse === undefined) {
      continue;
    }
    const actionStatus = numberValue(result?.["action_status"]) ?? 200;
    const nested = decodeOperatorOutcome(actionStatus, actionResponse);
    if (nested.state !== "success") {
      return nested;
    }
  }
  return null;
}

function outcome(
  state: OperatorOutcomeState,
  message: string,
  nextSteps: string[],
  errorClass: string | null
): OperatorOutcome {
  return { state, message, nextSteps, errorClass };
}

function isRefusalClass(value: string | null): boolean {
  return value !== null && refusalErrorClasses.has(value);
}

function messageFrom(value: Record<string, unknown> | null, fallback: string): string {
  if (!value) {
    return fallback;
  }
  const message = stringValue(value["message"]);
  if (message) {
    return message;
  }
  const error = value["error"];
  if (typeof error === "string" && error.trim()) {
    return error;
  }
  const errorRecord = recordValue(error);
  return stringValue(errorRecord?.["message"]) ?? fallback;
}

function nextStepsFrom(value: Record<string, unknown> | null): string[] {
  if (!value) {
    return [];
  }
  const steps = Array.isArray(value["next_steps"])
    ? value["next_steps"].filter(
        (step): step is string => typeof step === "string" && Boolean(step.trim())
      )
    : [];
  const single = stringValue(value["next_step"]);
  if (single) {
    steps.push(single);
  }
  const suggestedTool = stringValue(value["suggested_tool"]);
  if (suggestedTool) {
    steps.push(`Use ${suggestedTool}.`);
  }
  return [...new Set(steps)];
}

function isOperatorResponse(value: unknown): value is OperatorResponse {
  const response = recordValue(value);
  return (
    response?.["protocol_version"] === "operator.v1" && recordValue(response["data"]) !== null
  );
}

function recordValue(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function numberValue(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

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
  // The profile's `oracle_query` cost ceiling, published by ProfileMetadata.
  // Absent/null means the profile declares none: the query cost gate is off for
  // it. That is a fact about the configuration, not a missing reading.
  max_query_cost?: number | null;
  call_timeout_seconds?: number | null;
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
  preview_token: string;
  preview_token_sha256: string;
  redacted_diff_sha256: string;
  preview_expires_unix: number;
  confirmation_required: boolean;
  confirmation_reasons: string[];
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
  review?: {
    preview_token_sha256: string;
    draft_sha256: string;
    redacted_diff_sha256: string;
  } | null;
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

export type LaneCancelData = {
  status: "terminated" | "already_closed";
  lane_id: string;
  lane_generation: number;
  reason: string;
  terminated: boolean;
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

// CLASSIFIER-LIVE ladder verdict, derived server-side from the redacted audit
// tail and streamed under the events snapshot `data.classifier`. Never carries
// SQL text or bind values — only the fingerprint and the derived verdict.
export type ClassifierLadderVerdictKind = "PASS" | "HOLD" | "REFUSED";

export type ClassifierLadderRung =
  | "PASS"
  | "HOLD-FOR-GO"
  | "REFUSED-exceeds-ceiling";

export type ClassifierVerdict = {
  seq: number;
  timestamp: string;
  subject_id_hash: string;
  tool: string;
  danger_level: string;
  decision: string;
  outcome: string;
  verdict: ClassifierLadderVerdictKind;
  ladder: ClassifierLadderRung;
  sql_sha256: string | null;
};

export type ClassifierLadderData = {
  source: "self_lane" | "unavailable";
  reason?: string;
  verdicts: ClassifierVerdict[];
};

export function parseClassifierLadder(
  event: OperatorEventEnvelope
): ClassifierLadderData | null {
  const classifier = event.data["classifier"];
  if (!classifier || typeof classifier !== "object") {
    return null;
  }
  return classifier as ClassifierLadderData;
}

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

// List projection carried by the polled board endpoint. It mirrors the full
// statement view but drops the `sql_template` body (fetched on selection via
// the by-id detail route) so list responses stay bounded.
export type ChangeProposalStatementListView = {
  id: string;
  unit: ChangeProposalApplyUnit;
  sql_sha256: string;
  bind_count: number;
  commit: boolean;
  capture_dbms_output: boolean;
  draft_verdict: ChangeProposalClassifierView;
  stored_verdict_present: boolean;
};

export type ChangeProposalListView = {
  schema_version: number;
  id: string;
  profile: string;
  author: ChangeProposalAuthorKind;
  author_id_hash: string;
  title: string;
  created_at: string;
  updated_at: string;
  statement_count: number;
  statements: ChangeProposalStatementListView[];
  stored_verdict_present: boolean;
};

export type ChangeProposalListData = {
  source: string;
  proposals: ChangeProposalListView[];
  nextCursor?: string | null;
};

// The by-id detail response restores the full statement bodies (with
// `sql_template`) that the list projection omits.
export type ChangeProposalDetailData = {
  source: string;
  proposal: ChangeProposalView;
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
  nextCursor?: string | null;
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
  correlation?: {
    request_sha256: string;
    parent_seq?: number | null;
  } | null;
  rows_affected?: number | null;
  sql_sha256: string;
  sql_text?: Record<string, unknown>;
  db_evidence?: Record<string, unknown> | null;
  proof?: Record<string, unknown>;
  bind_values?: Record<string, unknown>;
  // Present only on proof-carrying records (ADR 0010): the redacted verdict
  // certificate and the audit-covered hash of its core.
  verdict_certificate?: Record<string, unknown> | null;
  verdict_certificate_core_hash?: string | null;
};

/**
 * Collapse a completed two-phase operator request to its terminal row while
 * retaining an unmatched Pending row (for example after a crash). Proof
 * exports still contain every signed record; this is presentation-only action
 * counting for the timeline.
 */
export function coalesceAuditTimelineRecords(records: AuditTailRecord[]): AuditTailRecord[] {
  const pendingBySeq = new Map<number, AuditTailRecord>();
  for (const record of records) {
    if (record.outcome === "PENDING" && record.correlation?.parent_seq == null) {
      pendingBySeq.set(record.seq, record);
    }
  }
  const supersededPending = new Set<number>();
  for (const record of records) {
    const parentSeq = record.correlation?.parent_seq;
    if (typeof parentSeq !== "number") {
      continue;
    }
    const pending = pendingBySeq.get(parentSeq);
    if (
      pending?.correlation?.request_sha256 === record.correlation?.request_sha256
    ) {
      supersededPending.add(parentSeq);
    }
  }
  return records.filter((record) => !supersededPending.has(record.seq));
}

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

export async function cancelLane(
  session: DashboardSession,
  laneId: string
): Promise<OperatorResponse<LaneCancelData>> {
  return operatorPost("/operator/v1/lanes/cancel", session, {
    lane_id: laneId
  });
}

export async function fetchChangeProposals(
  cursor?: string
): Promise<OperatorResponse<ChangeProposalListData>> {
  const suffix = cursor ? `?cursor=${encodeURIComponent(cursor)}` : "";
  return operatorGet(`/operator/v1/change-proposals${suffix}`);
}

export async function fetchChangeProposalDetail(
  id: string
): Promise<OperatorResponse<ChangeProposalDetailData>> {
  return operatorGet(`/operator/v1/change-proposals/${encodeURIComponent(id)}`);
}

export async function fetchSourceHistory(
  cursor?: string
): Promise<OperatorResponse<SourceHistoryListData>> {
  const base = "/operator/v1/source-history?max_rows=100";
  const suffix = cursor ? `&cursor=${encodeURIComponent(cursor)}` : "";
  return operatorGet(`${base}${suffix}`);
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
  previewToken: string,
  expectedDraftSha256: string,
  confirmPreview: boolean
): Promise<OperatorResponse<ConfigApplyData>> {
  return operatorPost("/operator/v1/config/apply", session, {
    draft_toml: draftToml,
    preview_token: previewToken,
    expected_draft_sha256: expectedDraftSha256,
    confirm_preview: confirmPreview
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

  const pending = explorerMetadataCacheLoads.get(cacheKey);
  if (pending && pending.generation === explorerMetadataCacheGeneration) {
    return pending.promise as Promise<ExplorerCachedResult<T>>;
  }

  const generation = explorerMetadataCacheGeneration;
  const promise = (async (): Promise<ExplorerCachedResult<T>> => {
    const value = await load();
    const bytes = approxJsonBytes(value);
    if (bytes > EXPLORER_METADATA_CACHE_MAX_BYTES || generation !== explorerMetadataCacheGeneration) {
      return { value, status: "bypass", bytes, cacheKey };
    }

    const loadedAt = Date.now();
    removeExplorerCacheEntry(cacheKey);
    explorerMetadataCache.set(cacheKey, {
      value,
      bytes,
      expiresAt: loadedAt + EXPLORER_METADATA_CACHE_TTL_MS,
      lastAccessed: loadedAt
    });
    explorerMetadataCacheBytes += bytes;
    trimExplorerMetadataCache();
    return { value, status: existing ? "stale" : "miss", bytes, cacheKey };
  })();
  explorerMetadataCacheLoads.set(cacheKey, { generation, promise });

  try {
    return await promise;
  } finally {
    if (explorerMetadataCacheLoads.get(cacheKey)?.promise === promise) {
      explorerMetadataCacheLoads.delete(cacheKey);
    }
  }
}

export function clearExplorerMetadataCache(): void {
  explorerMetadataCacheGeneration += 1;
  explorerMetadataCache.clear();
  explorerMetadataCacheLoads.clear();
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

// ── Policy narrowing (Arc N) ─────────────────────────────────────────────────
// ADR 0009: the policy outcome is `Deny` or `Narrow` — there is deliberately no
// `Allow`. A narrowing carries the base (pre-policy) required level, the final
// level floor, the matched rule ids and any conjunctive predicates.
//
// NOTE: as of this commit the guard evaluates policies but dispatch does not yet
// attach the outcome to a tool response, so this parser returns null on today's
// responses and the badge reports "not reported" — never "no policy applied".
// The wire gap is tracked as its own bead.

const CLEARANCE_LEVELS: readonly ClearanceLevel[] = [
  "READ_ONLY",
  "READ_WRITE",
  "DDL",
  "ADMIN"
];

function clearanceLevel(value: unknown): ClearanceLevel | null {
  const level = typeof value === "string" ? value.toUpperCase() : "";
  return CLEARANCE_LEVELS.includes(level as ClearanceLevel) ? (level as ClearanceLevel) : null;
}

/** Find the policy outcome on a tool response or on a refusal envelope. */
export function parsePolicyTightening(source: unknown): PolicyTighteningInput | null {
  const payload = source instanceof OperatorOutcomeError ? source.response : source;
  const envelope = recordValue(payload);
  const data = recordValue(envelope?.["data"]) ?? envelope;
  const mcp = recordValue(data?.["mcp_response"]);
  const result = recordValue(mcp?.["result"]);
  const structured = structuredReasonOf(payload);
  const candidates = [
    recordValue(result?.["policy"]),
    recordValue(recordValue(result?.["structuredContent"])?.["policy"]),
    recordValue(structured?.["policy_tightening"]),
    recordValue(data?.["policy"])
  ];
  const policy = candidates.find((candidate) => candidate !== null) ?? null;
  if (!policy) {
    return null;
  }

  const denial = recordValue(policy["Deny"]) ?? recordValue(policy["deny"]);
  const matchedRuleIds = (value: unknown): string[] =>
    Array.isArray(value) ? value.filter((id): id is string => typeof id === "string") : [];
  if (denial) {
    return {
      effect: "Deny",
      reason: stringValue(denial["reason"]) ?? "policy denied the statement",
      matchedRuleIds: matchedRuleIds(denial["matched_rule_ids"])
    };
  }

  const narrowing = recordValue(policy["Narrow"]) ?? recordValue(policy["narrow"]);
  if (!narrowing) {
    return null;
  }
  const baseRequiredLevel = clearanceLevel(narrowing["base_required_level"]);
  const requiredLevel = clearanceLevel(narrowing["required_level"]);
  // A narrowing with no levels is not decodable, and the console will not guess
  // one: an invented base level would misreport what the policy took away.
  if (!baseRequiredLevel || !requiredLevel) {
    return null;
  }
  const predicates = Array.isArray(narrowing["predicates"])
    ? narrowing["predicates"].flatMap((raw) => {
        const predicate = recordValue(raw);
        const target = recordValue(predicate?.["target"]);
        const ruleId = stringValue(predicate?.["rule_id"]);
        const sqlFragment = stringValue(predicate?.["sql_fragment"]);
        if (!ruleId || !sqlFragment) {
          return [];
        }
        const schema = stringValue(target?.["schema"]);
        const object = stringValue(target?.["object"]);
        return [
          {
            ruleId,
            target: schema && object ? `${schema}.${object}` : (object ?? schema ?? "unspecified"),
            sqlFragment
          }
        ];
      })
    : [];
  return {
    effect: "Narrow",
    baseRequiredLevel,
    requiredLevel,
    matchedRuleIds: matchedRuleIds(narrowing["matched_rule_ids"]),
    predicates
  };
}

// ── Fleet map (Arc H) ────────────────────────────────────────────────────────
// `oracle_orient fleet=true` orients every MCP-visible profile independently and
// types each lane REACHABLE / UNREACHABLE / FAIL_CLOSED. A lane that failed is
// still a lane: the parser keeps it, with its error, exactly as the server sent it.

const FLEET_STATUSES: Readonly<Record<string, FleetDbStatus>> = {
  REACHABLE: "reachable",
  UNREACHABLE: "unreachable",
  FAIL_CLOSED: "fail_closed"
};

export type FleetMapRequest = {
  laneId?: string;
};

/** `oracle_orient` with `fleet: true` — one independent read per profile. */
export async function fetchFleetMap(
  session: DashboardSession,
  request: FleetMapRequest = {}
): Promise<OperatorResponse<WorkbenchActionData>> {
  return operatorPost("/operator/v1/actions/execute", session, {
    idempotency_key: requestId("fleet-orient"),
    lane_id: laneIdValue(request.laneId),
    tool: "oracle_orient",
    arguments: { fleet: true, include: ["schema", "freshness", "ddl"] }
  });
}

export function parseFleetMap(data: WorkbenchActionData | null): FleetMapInput {
  const payload = mcpPayload(data);
  const summaryRaw = recordValue(payload?.["summary"]);
  const summary = summaryRaw
    ? {
        profileCount: numberValue(summaryRaw["profile_count"]) ?? 0,
        reachableCount: numberValue(summaryRaw["reachable_count"]) ?? 0,
        unreachableCount: numberValue(summaryRaw["unreachable_count"]) ?? 0,
        failClosedCount: numberValue(summaryRaw["fail_closed_count"]) ?? 0
      }
    : null;

  const rawProfiles = Array.isArray(payload?.["profiles"]) ? payload["profiles"] : [];
  const profiles = rawProfiles.flatMap((raw) => {
    const entry = recordValue(raw);
    const profile = stringValue(entry?.["profile"]);
    const status = FLEET_STATUSES[stringValue(entry?.["status"]) ?? ""];
    if (!entry || !profile || !status) {
      return [];
    }
    const connection = recordValue(entry["connection"]);
    const error = recordValue(entry["error"]);
    const driftRaw = recordValue(entry["drift"]);
    const drift = driftRaw
      ? (() => {
          const flags = {
            schemaChanged: driftRaw["schema_changed"] === true,
            foreignKeysChanged: driftRaw["foreign_keys_changed"] === true,
            freshnessChanged: driftRaw["freshness_changed"] === true,
            recentDdlChanged: driftRaw["recent_ddl_changed"] === true
          };
          return {
            baselineProfile: stringValue(driftRaw["baseline_profile"]) ?? profile,
            ...flags,
            changedSections: driftSections(flags)
          };
        })()
      : null;
    return [
      {
        profile,
        status,
        serverVersion: stringValue(connection?.["server_version"]),
        databaseRole: stringValue(connection?.["database_role"]),
        openMode: stringValue(connection?.["open_mode"]),
        readOnly:
          typeof connection?.["read_only"] === "boolean"
            ? (connection["read_only"] as boolean)
            : null,
        poolOpenConnections: numberValue(connection?.["pool_open_connections"]),
        // A lane the server did not read has no drift to report; keep it null
        // rather than letting an absent block read as "no drift".
        drift: status === "reachable" ? drift : null,
        errorCode: stringValue(error?.["code"]),
        errorMessage: stringValue(error?.["message"])
      }
    ];
  });

  return { profiles, summary };
}

// ── Egress masking (Arc M) ───────────────────────────────────────────────────
// The mask certificate rides on the query page it governs, and only when the
// policy transformed at least one column. The console reports its absence as an
// absence of proof — never as "nothing was masked".

const MASK_ACTIONS: readonly MaskAction[] = ["pass", "mask", "tokenize", "null"];
const MASK_SOURCES: readonly MaskSource[] = ["rule", "mask_unknown_default", "pass"];

/** Read `mask_certificate` off a query page, or null when the page carries none. */
export function parseMaskCertificate(
  data: WorkbenchActionData | null
): MaskCertificateInput | null {
  const certificate = recordValue(mcpPayload(data)?.["mask_certificate"]);
  const policyId = stringValue(certificate?.["policy_id"]);
  if (!certificate || !policyId || !Array.isArray(certificate["decisions"])) {
    return null;
  }
  const decisions = certificate["decisions"].flatMap((raw) => {
    const decision = recordValue(raw);
    const column = stringValue(decision?.["column"]);
    const action = stringValue(decision?.["action"]);
    const source = stringValue(decision?.["source"]);
    // An unknown action or source is not decodable, and the console must not
    // guess: an undecodable decision would otherwise render as "passed".
    if (
      !decision ||
      !column ||
      !MASK_ACTIONS.includes(action as MaskAction) ||
      !MASK_SOURCES.includes(source as MaskSource)
    ) {
      return [];
    }
    return [
      {
        column,
        oracleType: stringValue(decision["oracle_type"]) ?? "UNKNOWN",
        action: action as MaskAction,
        source: source as MaskSource,
        ruleIndex: numberValue(decision["rule_index"]),
        ruleTag: stringValue(decision["rule_tag"]),
        saltId: stringValue(decision["salt_id"])
      }
    ];
  });
  return {
    policyId,
    profile: stringValue(certificate["profile"]),
    auditHash: stringValue(certificate["audit_entry_hash"]),
    decisions
  };
}

// ── SCN time-travel (Arc A) ──────────────────────────────────────────────────
// The flashback read is real and governed: the base SELECT is proven read-only
// first, then bounded in a DBMS_FLASHBACK window with the SCN bound, never
// interpolated. The server does not echo the SCN it read at, and no endpoint
// publishes the current SCN, so the console records exactly what it asked for
// and what came back.

export type AsOfTarget = { kind: "scn"; scn: number } | { kind: "timestamp"; timestamp: string };

export type QueryAsOfRequest = {
  laneId?: string;
  sql: string;
  maxRows: number;
  target: AsOfTarget;
};

export type QueryAsOfRead = {
  rowCount: number | null;
  truncated: boolean;
};

/** `oracle_query` with `as_of` — replay a proven SELECT at a past snapshot. */
export async function fetchQueryAsOf(
  session: DashboardSession,
  request: QueryAsOfRequest
): Promise<OperatorResponse<WorkbenchActionData>> {
  return operatorPost("/operator/v1/actions/execute", session, {
    idempotency_key: requestId("query-as-of"),
    lane_id: laneIdValue(request.laneId),
    tool: "oracle_query",
    arguments: {
      sql: request.sql,
      max_rows: request.maxRows,
      as_of:
        request.target.kind === "scn"
          ? { scn: request.target.scn }
          : { timestamp: request.target.timestamp }
    }
  });
}

/**
 * What the snapshot read returned. `row_count` is the only evidence the console
 * gets that the snapshot was actually readable — the response carries no SCN.
 */
export function parseQueryAsOf(data: WorkbenchActionData | null): QueryAsOfRead {
  const payload = mcpPayload(data);
  return {
    rowCount: numberValue(payload?.["row_count"]),
    truncated: payload?.["truncated"] === true
  };
}

// ── Cost/gas gate (Arc G) ────────────────────────────────────────────────────
// Two real sources, and nothing else: the `query_cost_refusal` block a cost
// refusal carries (estimate + the ceiling it broke), and the `cost_estimate`
// block `oracle_explain_plan` returns. The console never guesses a ceiling.

export type QueryCostRefusalWire = {
  estimated_cost: number;
  max_query_cost: number;
  plan_rows?: unknown[];
  predicate_hints?: unknown[];
  note?: string | null;
};

export type CostEstimateRead = {
  totalCost: number | null;
  unavailable: string | null;
  note: string | null;
  planRows: CostPlanRowViewModel[];
};

function planRowsFrom(rows: unknown): CostPlanRowViewModel[] {
  if (!Array.isArray(rows)) {
    return [];
  }
  return rows.flatMap((raw) => {
    const row = recordValue(raw);
    if (!row || typeof row["id"] !== "number") {
      return [];
    }
    const operation = [stringValue(row["operation"]), stringValue(row["options"])]
      .filter((part): part is string => Boolean(part))
      .join(" ");
    return [
      {
        id: row["id"],
        operation: operation || "(unnamed operation)",
        objectName: stringValue(row["object_name"]),
        cost: numberValue(row["cost"]),
        cardinality: numberValue(row["cardinality"])
      }
    ];
  });
}

function structuredReasonOf(payload: unknown): Record<string, unknown> | null {
  const envelope = recordValue(payload);
  const data = recordValue(envelope?.["data"]) ?? envelope;
  if (!data) {
    return null;
  }
  // An MCP tool refusal rides HTTP 200 as result.isError with the error envelope
  // in structuredContent; a JSON-RPC error carries it under error.data; an
  // operator-domain refusal puts it straight on `error`.
  const mcp = recordValue(data["mcp_response"]);
  const candidates = [
    recordValue(recordValue(mcp?.["result"])?.["structuredContent"]),
    recordValue(mcp?.["result"]),
    recordValue(recordValue(mcp?.["error"])?.["data"]),
    recordValue(data["error"]),
    data
  ];
  for (const candidate of candidates) {
    const reason = recordValue(candidate?.["structured_reason"]);
    if (reason) {
      return reason;
    }
  }
  return null;
}

/**
 * Pull the `query_cost_refusal` block out of whatever refused.
 *
 * Accepts an operator response or an `OperatorOutcomeError` — a cost refusal is
 * a `POLICY_DENIED` outcome, so React Query sees it as an error, not data.
 */
export function parseQueryCostRefusal(source: unknown): CostRefusalInput | null {
  const payload = source instanceof OperatorOutcomeError ? source.response : source;
  const refusal = recordValue(structuredReasonOf(payload)?.["query_cost_refusal"]);
  if (
    !refusal ||
    typeof refusal["estimated_cost"] !== "number" ||
    typeof refusal["max_query_cost"] !== "number"
  ) {
    return null;
  }
  return {
    estimatedCost: refusal["estimated_cost"],
    maxQueryCost: refusal["max_query_cost"],
    predicateHints: Array.isArray(refusal["predicate_hints"])
      ? refusal["predicate_hints"].filter((hint): hint is string => typeof hint === "string")
      : [],
    planRows: planRowsFrom(refusal["plan_rows"]),
    note: stringValue(refusal["note"])
  };
}

/** Read `cost_estimate` / `cost_estimate_unavailable` off an explain-plan run. */
export function parseCostEstimate(data: WorkbenchActionData | null): CostEstimateRead {
  const payload = mcpPayload(data);
  const unavailable = stringValue(payload?.["cost_estimate_unavailable"]);
  const estimate = recordValue(payload?.["cost_estimate"]);
  const summary = recordValue(estimate?.["summary"]);
  return {
    totalCost: numberValue(summary?.["total_cost"]),
    unavailable,
    note: stringValue(estimate?.["note"]),
    planRows: planRowsFrom(estimate?.["rows"])
  };
}

export type CostCeilingRead = {
  ceiling: number | null;
  source: CostCeilingSource;
  // True only when the config positively says this profile declares no ceiling.
  ungated: boolean;
};

/**
 * The `oracle_query` cost ceiling in force, read from the operator config.
 *
 * `/operator/v1/config` publishes every profile's `max_query_cost` (Rust:
 * `ProfileMetadata`), so the console does not have to wait for a refusal to
 * learn it. Three distinct answers, and the badge must not conflate them:
 * a number (this profile is gated at N), `ungated` (the profile declares no
 * ceiling — the gate is off), and "unknown" (we could not identify the active
 * profile, so we say nothing).
 */
export function profileCostCeiling(
  config: ConfigOpsStatusData | null,
  activeProfile: string | null
): CostCeilingRead {
  const profiles = config?.status?.profiles ?? [];
  const name = activeProfile ?? config?.status?.default_profile ?? null;
  const profile = name ? profiles.find((entry) => entry.name === name) : undefined;
  if (!profile) {
    return { ceiling: null, source: "unknown", ungated: false };
  }
  const ceiling = typeof profile.max_query_cost === "number" ? profile.max_query_cost : null;
  return {
    ceiling,
    source: ceiling === null ? "unknown" : "config",
    ungated: ceiling === null
  };
}

/** The active profile name, as reported by `oracle_connection_info`. */
export function parseActiveProfile(data: WorkbenchActionData | null): string | null {
  const connection = recordValue(mcpPayload(data)?.["connection"]);
  return stringValue(connection?.["profile"]);
}

export type QueryCostEstimateRequest = {
  laneId?: string;
  sql: string;
};

/**
 * `oracle_explain_plan` — the only way the console can price a statement before
 * running it. It is a governed diagnostic *write* (it writes PLAN_TABLE), so it
 * needs READ_WRITE plus `allow_plan_table_write`; at READ_ONLY the server
 * refuses, and the badge reports that refusal rather than pretending to a price.
 */
export async function fetchQueryCostEstimate(
  session: DashboardSession,
  request: QueryCostEstimateRequest
): Promise<OperatorResponse<WorkbenchActionData>> {
  return operatorPost("/operator/v1/actions/execute", session, {
    idempotency_key: requestId("query-cost-estimate"),
    lane_id: laneIdValue(request.laneId),
    tool: "oracle_explain_plan",
    arguments: {
      sql: request.sql,
      allow_plan_table_write: true
    }
  });
}

// ── Reversible undo-tree (Arc I) ─────────────────────────────────────────────
// The workspace lives on the pinned lane session, so its truth arrives on the
// tool responses that open, hold into, and unwind it. The console reads the
// server's own `workspace` view and its `cannot_undo` labels verbatim; it never
// infers reversibility from a flag named after the transaction.

export type WorkspaceView = {
  open: boolean;
  checkpoints: string[];
  heldStatements: number;
};

export type UndoOutcome = {
  workspace: WorkspaceView | null;
  // Verbatim `cannot_undo` reasons: the effect outlives the rollback.
  cannotUndo: string[];
  // `fully_reverted` from the response; null when the response never claimed it.
  fullyReverted: boolean | null;
  held: boolean;
  checkpoint: string | null;
  undoneTo: string | null;
  discardedStatements: number | null;
};

/** The MCP tool payload an operator action wraps. */
function mcpPayload(data: WorkbenchActionData | null | undefined): Record<string, unknown> | null {
  const response = data?.mcp_response;
  return response && typeof response === "object" ? (response as Record<string, unknown>) : null;
}

export function parseWorkspaceView(data: WorkbenchActionData | null): WorkspaceView | null {
  const workspace = mcpPayload(data)?.["workspace"];
  if (!workspace || typeof workspace !== "object") {
    return null;
  }
  const view = workspace as Record<string, unknown>;
  const checkpoints = Array.isArray(view["checkpoints"])
    ? (view["checkpoints"] as unknown[]).filter(
        (name): name is string => typeof name === "string"
      )
    : [];
  return {
    open: view["open"] === true,
    checkpoints,
    heldStatements: typeof view["held_statements"] === "number" ? view["held_statements"] : 0
  };
}

/**
 * Read the server's reversibility verdict for one action.
 *
 * `cannot_undo` is taken verbatim — it is the only place that says an effect
 * escapes the rollback (a sequence NEXTVAL, an autonomous transaction, a
 * trigger, non-source-replaceable DDL). An absent `fully_reverted` stays null:
 * the console must not read silence as "reverted".
 */
export function parseUndoOutcome(data: WorkbenchActionData | null): UndoOutcome {
  const payload = mcpPayload(data);
  const cannotUndo = Array.isArray(payload?.["cannot_undo"])
    ? (payload["cannot_undo"] as unknown[]).filter(
        (reason): reason is string => typeof reason === "string"
      )
    : [];
  const fullyReverted =
    typeof payload?.["fully_reverted"] === "boolean"
      ? (payload["fully_reverted"] as boolean)
      : payload === null
        ? null
        : cannotUndo.length > 0
          ? false
          : payload["rolled_back"] === true || payload["held"] === true
            ? true
            : null;
  return {
    workspace: parseWorkspaceView(data),
    cannotUndo,
    fullyReverted,
    held: payload?.["held"] === true,
    checkpoint: typeof payload?.["checkpoint"] === "string" ? payload["checkpoint"] : null,
    undoneTo: typeof payload?.["undone_to"] === "string" ? payload["undone_to"] : null,
    discardedStatements:
      typeof payload?.["discarded_statements"] === "number"
        ? (payload["discarded_statements"] as number)
        : null
  };
}

export type WorkspaceCheckpointRequest = {
  laneId?: string;
  name: string;
};

export type WorkspaceUndoRequest = {
  laneId?: string;
  // Omit to discard the whole workspace (a full ROLLBACK).
  name?: string;
};

export type WorkspaceHoldRequest = WorkbenchSqlRequest & {
  confirm?: string;
};

/** `oracle_checkpoint` — establish a named savepoint, opening the workspace. */
export async function establishCheckpoint(
  session: DashboardSession,
  request: WorkspaceCheckpointRequest
): Promise<OperatorResponse<WorkbenchActionData>> {
  return operatorPost("/operator/v1/actions/execute", session, {
    idempotency_key: requestId("workspace-checkpoint"),
    lane_id: laneIdValue(request.laneId),
    tool: "oracle_checkpoint",
    arguments: { name: request.name.trim() }
  });
}

/** `oracle_execute` with `hold=true` — leave the DML pending and undoable. */
export async function holdWorkbenchSql(
  session: DashboardSession,
  request: WorkspaceHoldRequest
): Promise<OperatorResponse<WorkbenchActionData>> {
  return operatorPost("/operator/v1/actions/execute", session, {
    idempotency_key: requestId("workspace-hold"),
    lane_id: laneIdValue(request.laneId),
    tool: "oracle_execute",
    arguments: {
      sql: request.sql,
      binds: [],
      hold: true,
      commit: false,
      confirm: request.confirm?.trim() || undefined
    }
  });
}

/** `oracle_undo_to` — roll back to a checkpoint, or discard the workspace. */
export async function undoToCheckpoint(
  session: DashboardSession,
  request: WorkspaceUndoRequest
): Promise<OperatorResponse<WorkbenchActionData>> {
  return operatorPost("/operator/v1/actions/execute", session, {
    idempotency_key: requestId("workspace-undo"),
    lane_id: laneIdValue(request.laneId),
    tool: "oracle_undo_to",
    arguments: request.name ? { name: request.name.trim() } : {}
  });
}

/** Audit outcomes the workspace produces. `HELD_UNCOMMITTED` is Arc I's own. */
export const WORKSPACE_TOOLS = ["oracle_checkpoint", "oracle_undo_to", "oracle_execute"] as const;

export type WorkspaceHistoryEntry = {
  seq: number;
  timestamp: string;
  tool: string;
  outcome: string;
  dangerLevel: string;
  sqlSha256: string;
};

export type WorkspaceHistoryData = {
  source: "self_lane" | "unavailable";
  reason?: string;
  entries: WorkspaceHistoryEntry[];
};

/**
 * Server-side evidence for the undo tree: the hash-chained audit records of the
 * workspace tools. `HELD_UNCOMMITTED` is durable proof that a statement is
 * pending and undoable; it is the audit chain, not the console, that says so.
 */
export async function fetchWorkspaceHistory(
  limit = 25
): Promise<OperatorResponse<WorkspaceHistoryData>> {
  const response = await fetchAuditTail({
    limit,
    subjectIdHash: "",
    tool: "",
    dangerLevel: "",
    exportProofBundle: false
  });
  const tail = response.data;
  if (tail.source !== "self_lane") {
    return {
      ...response,
      data: {
        source: "unavailable",
        reason: tail.reason ?? "audit tail provider is not available",
        entries: []
      }
    };
  }
  const workspaceTools = new Set<string>(WORKSPACE_TOOLS);
  const entries = tail.records
    .filter(
      (record) =>
        workspaceTools.has(record.tool) ||
        record.outcome === "HELD_UNCOMMITTED" ||
        record.outcome === "DISCARDED_UNCOMMITTED"
    )
    .map((record) => ({
      seq: record.seq,
      timestamp: record.timestamp,
      tool: record.tool,
      outcome: record.outcome,
      dangerLevel: record.danger_level,
      sqlSha256: record.sql_sha256
    }));
  return { ...response, data: { source: "self_lane", entries } };
}

// ── Verdict-proof inspector (Arc B1) ─────────────────────────────────────────
// The certificate (ADR 0010) rides on the audit record it is bound to, so the
// inspector reads the same redacted, hash-chained tail the Audit page reads —
// it never opens a second, less-guarded path to the guard's decisions.

export type VerdictCertificateWire = {
  stmt_digest: string;
  level: OperatingLevel | null;
  verdict: VerdictKind;
  derivation: { rule_id: string; construct: string }[];
  classifier_version: string;
  observed_scn: string | null;
  bound_audit_hash: string | null;
};

export type VerdictProof = VerdictProofInput & {
  certificate: VerdictCertificateWire;
};

export type VerdictProofData = {
  source: "self_lane" | "unavailable";
  reason?: string;
  // Records scanned that carried no certificate; certificates only appear on
  // proof-carrying records, so this is "not yet proof-carrying", not an error.
  uncertified: number;
  proofs: VerdictProof[];
};

function nestedStringField(value: unknown, key: string): string | null {
  if (!value || typeof value !== "object") {
    return null;
  }
  const field = (value as Record<string, unknown>)[key];
  return typeof field === "string" && field.length > 0 ? field : null;
}

function certificateFromRecord(record: AuditTailRecord): VerdictCertificateWire | null {
  const raw = record.verdict_certificate;
  if (!raw || typeof raw !== "object") {
    return null;
  }
  const candidate = raw as Partial<VerdictCertificateWire>;
  if (
    typeof candidate.stmt_digest !== "string" ||
    typeof candidate.verdict !== "string" ||
    typeof candidate.classifier_version !== "string" ||
    !Array.isArray(candidate.derivation)
  ) {
    return null;
  }
  return {
    stmt_digest: candidate.stmt_digest,
    level: (candidate.level ?? null) as OperatingLevel | null,
    verdict: candidate.verdict as VerdictKind,
    derivation: candidate.derivation
      .filter(
        (step): step is { rule_id: string; construct: string } =>
          !!step && typeof step.rule_id === "string" && typeof step.construct === "string"
      )
      .map((step) => ({ rule_id: step.rule_id, construct: step.construct })),
    classifier_version: candidate.classifier_version,
    observed_scn: typeof candidate.observed_scn === "string" ? candidate.observed_scn : null,
    bound_audit_hash:
      typeof candidate.bound_audit_hash === "string" ? candidate.bound_audit_hash : null
  };
}

/**
 * Re-derive the four checks a browser can make without the SQL bytes.
 *
 * The console does not trust a server-side "verified" flag: it compares the
 * certificate against the audit record it claims to be bound to. Replaying the
 * classifier over the statement bytes remains the standalone verifier's job
 * (`oraclemcp-verifier`); the SQL never leaves the host.
 */
export function verdictProofChecks(
  record: AuditTailRecord,
  certificate: VerdictCertificateWire,
  certHash: string
): VerdictProofCheckView[] {
  const entryHash = nestedStringField(record.proof, "entry_hash");
  const hashValid = !!record.proof && (record.proof as Record<string, unknown>)["hash_valid"] === true;
  const registered = certificate.derivation.filter((step) =>
    isRegisteredDerivationStep(step.rule_id, step.construct)
  ).length;
  const boundHash = certificate.bound_audit_hash;
  return [
    {
      id: "audit_binding",
      label: "Bound to audit entry",
      ok: boundHash !== null && entryHash !== null && boundHash === entryHash,
      detail:
        boundHash === null
          ? "certificate carries no bound_audit_hash"
          : entryHash === null
            ? "audit record exposes no entry_hash"
            : boundHash === entryHash
              ? "bound_audit_hash == record.entry_hash"
              : "bound_audit_hash does not match record.entry_hash"
    },
    {
      id: "statement_digest",
      label: "Statement digest",
      ok: certificate.stmt_digest === record.sql_sha256,
      detail:
        certificate.stmt_digest === record.sql_sha256
          ? "stmt_digest == record.sql_sha256"
          : "stmt_digest does not match the audited SQL digest"
    },
    {
      id: "rule_registry",
      label: "Rule registry",
      ok: certificate.derivation.length > 0 && registered === certificate.derivation.length,
      detail: `${registered} of ${certificate.derivation.length} derivation steps registered`
    },
    {
      id: "chain_hash",
      label: "Chain hash",
      ok: hashValid && certHash.length > 0,
      detail: !hashValid
        ? "audit record hash is not valid"
        : certHash.length === 0
          ? "audit record carries no certificate core hash"
          : "record hash is valid"
    }
  ];
}

/**
 * Project the proof-carrying records of an audit tail into inspectable proofs.
 * A record without a certificate is counted, never synthesized into one.
 */
export function parseVerdictProofs(data: AuditTailData | null): VerdictProofData {
  if (!data || data.source !== "self_lane") {
    return {
      source: "unavailable",
      reason: data?.reason ?? "audit tail provider is not available",
      uncertified: 0,
      proofs: []
    };
  }
  const proofs: VerdictProof[] = [];
  let uncertified = 0;
  for (const record of data.records) {
    const certificate = certificateFromRecord(record);
    if (!certificate) {
      uncertified += 1;
      continue;
    }
    const certHash = record.verdict_certificate_core_hash ?? "";
    proofs.push({
      seq: record.seq,
      timestamp: record.timestamp,
      tool: record.tool,
      subjectIdHash: record.subject_id_hash,
      certHash,
      auditHash: nestedStringField(record.proof, "entry_hash"),
      certificate,
      checks: verdictProofChecks(record, certificate, certHash)
    });
  }
  return { source: "self_lane", uncertified, proofs };
}

export async function fetchVerdictProofs(
  filters: AuditTailFilters
): Promise<OperatorResponse<VerdictProofData>> {
  const response = await fetchAuditTail(filters);
  return { ...response, data: parseVerdictProofs(response.data) };
}

// Per-path conditional-request cache. A polled GET revalidates with the
// last-seen ETag; an unchanged endpoint answers 304 and we reuse the cached,
// referentially-stable response so React skips re-rendering.
const operatorGetCache = new Map<string, { etag: string; value: unknown }>();

async function operatorGet<T extends Record<string, unknown>>(
  path: string
): Promise<OperatorResponse<T>> {
  const headers: Record<string, string> = { accept: "application/json" };
  const cached = operatorGetCache.get(path);
  if (cached) {
    headers["if-none-match"] = cached.etag;
  }
  const response = await fetch(path, {
    headers,
    cache: "no-store",
    credentials: "same-origin"
  });
  if (response.status === 304 && cached) {
    return cached.value as OperatorResponse<T>;
  }
  const parsed = (await response.json()) as unknown;
  const result = requireSuccessfulOperatorResponse<T>(response.status, parsed);
  const etag = response.headers.get("etag");
  if (etag) {
    operatorGetCache.set(path, { etag, value: result });
  }
  return result;
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
  return requireSuccessfulOperatorResponse<T>(response.status, parsed);
}

function requireSuccessfulOperatorResponse<T extends Record<string, unknown>>(
  httpStatus: number,
  parsed: unknown
): OperatorResponse<T> {
  const decoded = decodeOperatorOutcome(httpStatus, parsed);
  if (decoded.state !== "success") {
    throw new OperatorOutcomeError(decoded, parsed, httpStatus);
  }
  if (!isOperatorResponse(parsed)) {
    throw new OperatorOutcomeError(
      outcome("failed", "operator response did not match operator.v1", [], null),
      parsed,
      httpStatus
    );
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

type ExplorerMetadataCacheLoad = {
  generation: number;
  promise: Promise<ExplorerCachedResult<unknown>>;
};

const EXPLORER_METADATA_CACHE_TTL_MS = 60_000;
const EXPLORER_METADATA_CACHE_MAX_BYTES = 512_000;
const EXPLORER_METADATA_CACHE_MAX_ENTRIES = 64;
const explorerMetadataCache = new Map<string, ExplorerMetadataCacheEntry>();
const explorerMetadataCacheLoads = new Map<string, ExplorerMetadataCacheLoad>();
let explorerMetadataCacheBytes = 0;
let explorerMetadataCacheGeneration = 0;

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
