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

export type WorkbenchActionData = {
  status?: string;
  lane_id?: string | null;
  mcp_tool?: string;
  mcp_response?: unknown;
  idempotency?: Record<string, unknown>;
  error?: string;
  message?: string;
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

function setOptionalParam(params: URLSearchParams, key: string, value: string): void {
  const trimmed = value.trim();
  if (trimmed) {
    params.set(key, trimmed);
  }
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
