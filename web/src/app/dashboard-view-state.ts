import type { QueryClient } from "@tanstack/react-query";
import type {
  MetricsSnapshot,
  OperatorHealthData,
  OperatorResponse,
  DashboardSession,
  WorkbenchActionData
} from "./operator-client";

export type DashboardQueryStatus = "pending" | "error" | "success";
export type CollectionViewState = "pending" | "unavailable" | "empty" | "ready";

export function authoritativeQueryData<T>(
  status: DashboardQueryStatus,
  data: T | undefined
): T | undefined {
  return status === "success" ? data : undefined;
}

export function collectionViewState(
  status: DashboardQueryStatus,
  count: number
): CollectionViewState {
  if (status === "pending") {
    return "pending";
  }
  if (status === "error") {
    return "unavailable";
  }
  return count === 0 ? "empty" : "ready";
}

export function authoritativeMetric(
  status: DashboardQueryStatus,
  value: number | null | undefined
): number | "checking" | "unavailable" {
  if (status === "pending") {
    return "checking";
  }
  return status === "success" && value !== null && value !== undefined
    ? value
    : "unavailable";
}

export type LaneIdentity = {
  laneId: string;
  generation: number;
};

export type LaneLike = {
  lane_id: string;
  generation: number;
};

export type LaneSelectionDecision = {
  identity: LaneIdentity | null;
  invalidated: boolean;
};

export function laneIdentity(lane: LaneLike): LaneIdentity {
  return { laneId: lane.lane_id, generation: lane.generation };
}

export function sameLaneIdentity(
  left: LaneIdentity | null | undefined,
  right: LaneIdentity | null | undefined
): boolean {
  if (left === null || left === undefined || right === null || right === undefined) {
    return left === right;
  }
  return left.laneId === right.laneId && left.generation === right.generation;
}

export type ExactLaneSelection<T extends LaneLike> = {
  lane: T | null;
  invalidated: boolean;
};

/**
 * A selected operator session is its id and generation. A reused id must not
 * inherit authority, cached facts, or confirmation state from an older session.
 */
export function resolveExactLane<T extends LaneLike>(
  bound: LaneIdentity | null | undefined,
  lanes: readonly T[]
): ExactLaneSelection<T> {
  if (bound === null || bound === undefined) {
    return { lane: null, invalidated: false };
  }
  const lane = lanes.find(
    (candidate) =>
      candidate.lane_id === bound.laneId && candidate.generation === bound.generation
  );
  return lane ? { lane, invalidated: false } : { lane: null, invalidated: true };
}

/**
 * `undefined` is the initial, not-yet-bound state; `null` is an intentionally
 * cleared selection. Once bound, an id reused with another generation is never
 * silently accepted as the same logical session.
 */
export function reconcileLaneSelection(
  bound: LaneIdentity | null | undefined,
  requestedLaneId: string,
  lanes: readonly LaneLike[]
): LaneSelectionDecision {
  const requested = requestedLaneId
    ? lanes.find((lane) => lane.lane_id === requestedLaneId)
    : undefined;
  if (bound === undefined) {
    const initial = requested ?? (!requestedLaneId ? lanes[0] : undefined);
    return {
      identity: initial ? laneIdentity(initial) : null,
      invalidated: Boolean(requestedLaneId && !requested)
    };
  }
  if (bound === null) {
    return { identity: null, invalidated: false };
  }
  if (requestedLaneId && requestedLaneId !== bound.laneId) {
    return {
      identity: requested ? laneIdentity(requested) : null,
      invalidated: !requested
    };
  }
  const exact = lanes.find(
    (lane) => lane.lane_id === bound.laneId && lane.generation === bound.generation
  );
  return exact
    ? { identity: bound, invalidated: false }
    : { identity: null, invalidated: true };
}

export type ElevationRequestBinding = {
  lane: LaneIdentity;
  targetLevel: string;
  ttlSeconds: number;
  requestGeneration: number;
};

export type SessionLevelSummary = {
  action: string;
  preview: string;
  targetLevel: string;
  ttlSeconds: string;
  currentLevel: string;
  profileCeiling: string;
  gateDecision: string;
  confirm: string;
  elevationExpiresUnix: number | null;
};

export function sessionLevelSummary(
  response: OperatorResponse<WorkbenchActionData>
): SessionLevelSummary {
  const result = mcpResult(response.data.mcp_response);
  const record = isRecord(result) ? result : {};
  const session = isRecord(record["session"]) ? record["session"] : {};
  const gate = isRecord(record["gate"]) ? record["gate"] : {};
  return {
    action: stringValue(record["action"], "unknown"),
    preview: stringValue(record["preview"], "false"),
    targetLevel: stringValue(record["target_level"], "READ_ONLY"),
    ttlSeconds: stringValue(record["ttl_seconds"], "0"),
    currentLevel: stringValue(session["current_level"], "unknown"),
    profileCeiling: stringValue(session["profile_ceiling"], "unknown"),
    gateDecision: stringValue(gate["decision"], "not_required"),
    confirm: confirmationFromResult(record) ?? "none",
    elevationExpiresUnix: numberField(record, "elevation_expires_unix")
  };
}

export function elevationCompletionIsCurrent(
  request: ElevationRequestBinding,
  current: Omit<ElevationRequestBinding, "requestGeneration"> | null,
  latestRequestGeneration: number
): boolean {
  return Boolean(
    current &&
      request.requestGeneration === latestRequestGeneration &&
      sameLaneIdentity(request.lane, current.lane) &&
      request.targetLevel === current.targetLevel &&
      request.ttlSeconds === current.ttlSeconds
  );
}

export type LaneCancelNotice = {
  kind: "success" | "error";
  message: string;
};

export function laneCancelSuccess(laneId: string): LaneCancelNotice {
  return { kind: "success", message: `Session ${laneId} ended.` };
}

export function laneCancelFailure(error: unknown): LaneCancelNotice {
  const detail = error instanceof Error ? error.message : "lane cancel failed";
  return { kind: "error", message: `Session could not be ended: ${detail}` };
}

export type SourceAvailability = "pending" | "available" | "stale" | "unavailable";

export type ConnectionHealthSourceRow = {
  key: string;
  source: string;
  status: string;
  detail: string;
};

export type ConnectionNativeInfo = {
  source: string;
  connected: boolean;
  activeProfile: string;
  strategy: string;
  serverVersion: string;
  databaseRole: string;
  openMode: string;
  standby: string;
  writePosture: string;
  readOnlyReason: string;
  poolOpenConnections: number | null;
  error: string;
};

export type ConnectionHealthUiModel = {
  readiness: {
    availability: SourceAvailability;
    liveness: string;
    readiness: string;
    live: boolean;
    ready: boolean;
    dbReachable: boolean;
    draining: boolean;
  };
  pool: {
    availability: SourceAvailability;
    active: number | null;
    waitMeanMs: number | null;
    waitMaxMs: number | null;
    queryMeanMs: number | null;
    queryMaxMs: number | null;
  };
  db: ConnectionNativeInfo;
  dbAvailability: SourceAvailability;
  sources: ConnectionHealthSourceRow[];
};

export type HealthSourceDiagnostic = {
  availability: SourceAvailability;
  error: string | null;
};

export type HealthSourceDiagnostics = {
  health: HealthSourceDiagnostic;
  metrics: HealthSourceDiagnostic;
  connection: HealthSourceDiagnostic;
};

export function sourceAvailability(
  status: DashboardQueryStatus,
  hasData: boolean,
  isStale: boolean
): SourceAvailability {
  if (status === "error") {
    return hasData ? "stale" : "unavailable";
  }
  if (!hasData) {
    return status === "pending" ? "pending" : "unavailable";
  }
  return isStale ? "stale" : "available";
}

export function connectionHealthModel(
  health: OperatorHealthData | null,
  snapshot: MetricsSnapshot | null,
  connectionResponse: OperatorResponse<WorkbenchActionData> | undefined,
  diagnostics: HealthSourceDiagnostics
): ConnectionHealthUiModel {
  const healthUsable = sourceHasCachedFacts(diagnostics.health.availability);
  const metricsUsable = sourceHasCachedFacts(diagnostics.metrics.availability);
  const connectionUsable = sourceHasCachedFacts(diagnostics.connection.availability);
  const currentHealth = healthUsable ? health : null;
  const currentSnapshot = metricsUsable ? snapshot : null;
  const db = nativeConnectionInfo(
    connectionUsable ? connectionResponse : undefined,
    diagnostics.connection.error
  );
  const sources: ConnectionHealthSourceRow[] = [
    {
      key: "operator-health",
      source: "/operator/v1/health",
      status: healthSourceStatus(diagnostics.health),
      detail: healthSourceDetail(
        diagnostics.health,
        health?.readiness?.status ?? null,
        "health endpoint returned no readiness data"
      )
    },
    {
      key: "metrics",
      source: "/operator/v1/metrics",
      status: healthSourceStatus(diagnostics.metrics),
      detail: healthSourceDetail(
        diagnostics.metrics,
        snapshot ? "pool and latency gauges available" : null,
        "metrics endpoint returned no snapshot"
      )
    },
    {
      key: "db-native",
      source: "oracle_connection_info",
      status: healthSourceStatus(diagnostics.connection),
      detail: healthSourceDetail(
        diagnostics.connection,
        db.connected ? "redacted lane self-check available" : null,
        db.error
      )
    },
    {
      key: "write-posture",
      source: "write_posture",
      status: db.writePosture === "monitoring_unavailable" ? "monitoring_unavailable" : "applied",
      detail:
        db.writePosture === "monitoring_unavailable"
          ? "privilege posture is not surfaced by connection_info"
          : db.writePosture
    }
  ];
  return {
    readiness: {
      availability: diagnostics.health.availability,
      liveness: currentHealth?.liveness?.status ?? "unavailable",
      readiness: currentHealth?.readiness?.status ?? "unavailable",
      live: currentHealth?.liveness?.live === true,
      ready: currentHealth?.readiness?.ready === true,
      dbReachable: currentHealth?.readiness?.db_reachable === true,
      draining: currentHealth?.readiness?.draining === true
    },
    pool: {
      availability: diagnostics.metrics.availability,
      active: currentSnapshot?.pool_active_connections ?? null,
      waitMeanMs: currentSnapshot ? Math.round(currentSnapshot.pool_wait_ms.mean) : null,
      waitMaxMs: currentSnapshot?.pool_wait_ms.max ?? null,
      queryMeanMs: currentSnapshot ? Math.round(currentSnapshot.query_duration_ms.mean) : null,
      queryMaxMs: currentSnapshot?.query_duration_ms.max ?? null
    },
    db,
    dbAvailability: diagnostics.connection.availability,
    sources
  };
}

function sourceHasCachedFacts(availability: SourceAvailability): boolean {
  return availability === "available" || availability === "stale";
}

function healthSourceStatus(diagnostic: HealthSourceDiagnostic): string {
  switch (diagnostic.availability) {
    case "available":
      return "applied";
    case "stale":
      return "stale";
    case "unavailable":
      return diagnostic.error ? "error" : "monitoring_unavailable";
    case "pending":
      return "monitoring_unavailable";
  }
}

function healthSourceDetail(
  diagnostic: HealthSourceDiagnostic,
  availableDetail: string | null,
  unavailableDetail: string
): string {
  if (diagnostic.availability === "stale") {
    return diagnostic.error
      ? `stale after refresh failure: ${diagnostic.error}`
      : `stale: ${availableDetail ?? unavailableDetail}`;
  }
  if (diagnostic.error) {
    return diagnostic.error;
  }
  return availableDetail ?? unavailableDetail;
}

export function dashboardAuthorityIdentity(session: DashboardSession | undefined): string | null {
  if (!session) {
    return null;
  }
  const tickets = session.action_tickets
    .map((ticket) => [ticket.method, ticket.path, ticket.ticket] as const)
    .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
  return JSON.stringify([
    session.csrf_header,
    session.csrf_token,
    session.action_ticket_header,
    session.expires_unix,
    tickets
  ]);
}

export function nativeConnectionInfo(
  response: OperatorResponse<WorkbenchActionData> | undefined,
  connectionError: string | null
): ConnectionNativeInfo {
  const unavailable = (error: string): ConnectionNativeInfo => ({
    source: "monitoring_unavailable",
    connected: false,
    activeProfile: "unavailable",
    strategy: "monitoring_unavailable",
    serverVersion: "monitoring_unavailable",
    databaseRole: "monitoring_unavailable",
    openMode: "monitoring_unavailable",
    standby: "monitoring_unavailable",
    writePosture: "monitoring_unavailable",
    readOnlyReason: "monitoring_unavailable",
    poolOpenConnections: null,
    error
  });
  if (!response) {
    return unavailable(connectionError ?? "connection self-check pending");
  }
  const result = mcpResult(response.data.mcp_response);
  if (!isRecord(result)) {
    return unavailable(connectionError ?? "connection self-check returned no structured content");
  }
  const activeProfile = stringField(result, "active_profile", "unprofiled");
  if (result["connected"] !== true) {
    const errorClass = nestedString(result, ["connection_error", "error_class"]);
    const message = nestedString(result, ["connection_error", "message"]);
    return {
      ...unavailable(message ?? connectionError ?? "connection self-check degraded"),
      activeProfile,
      error: errorClass ?? message ?? connectionError ?? "connection self-check degraded"
    };
  }
  const connection = isRecord(result["connection"]) ? result["connection"] : {};
  const databaseRole = stringField(connection, "database_role", "monitoring_unavailable");
  const openMode = stringField(connection, "open_mode", "monitoring_unavailable");
  const readOnly = connection["read_only"] === true;
  const readOnlyReason = readOnly
    ? stringField(connection, "read_only_reason", "read_only")
    : "none";
  const roleKnown =
    databaseRole !== "monitoring_unavailable" || openMode !== "monitoring_unavailable";
  return {
    source: "lane_self_check",
    connected: true,
    activeProfile,
    strategy: stringField(connection, "connection_strategy", "single_session"),
    serverVersion: stringField(connection, "server_version", "monitoring_unavailable"),
    databaseRole,
    openMode,
    standby: readOnly ? readOnlyReason : roleKnown ? "no" : "monitoring_unavailable",
    writePosture: readOnly ? "database_read_only" : "monitoring_unavailable",
    readOnlyReason,
    poolOpenConnections: numberField(connection, "pool_open_connections"),
    error: "none"
  };
}

function mcpResult(value: unknown): unknown {
  if (!isRecord(value)) return null;
  const result = value["result"];
  return isRecord(result) && "structuredContent" in result
    ? result["structuredContent"]
    : result ?? null;
}

function nestedString(value: unknown, path: string[]): string | null {
  let current = value;
  for (const segment of path) {
    if (!isRecord(current)) return null;
    current = current[segment];
  }
  return typeof current === "string" ? current : null;
}

function stringField(record: Record<string, unknown>, key: string, fallback: string): string {
  const value = record[key];
  return typeof value === "string" && value.trim() ? value : fallback;
}

function numberField(record: Record<string, unknown>, key: string): number | null {
  const value = record[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function stringValue(value: unknown, fallback: string): string {
  return value === null || value === undefined || value === "" ? fallback : String(value);
}

function confirmationFromResult(result: Record<string, unknown>): string | null {
  for (const field of ["execute_confirmation", "confirmation"]) {
    const block = result[field];
    if (isRecord(block) && typeof block["confirm"] === "string") {
      return block["confirm"];
    }
  }
  return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function configurationAuthority(
  configStatus: DashboardQueryStatus,
  sessionStatus: DashboardQueryStatus
): { ready: boolean; state: "pending" | "unavailable" | "available" } {
  if (configStatus === "error" || sessionStatus === "error") {
    return { ready: false, state: "unavailable" };
  }
  if (configStatus !== "success" || sessionStatus !== "success") {
    return { ready: false, state: "pending" };
  }
  return { ready: true, state: "available" };
}

export function remainingSeconds(expiresUnix: number, nowMs = Date.now()): number {
  return Math.max(0, Math.ceil((expiresUnix * 1_000 - nowMs) / 1_000));
}

export function absoluteExpiryIsActive(expiresUnix: number, nowMs = Date.now()): boolean {
  return nowMs < expiresUnix * 1_000;
}

export function scheduleAbsoluteExpiry(
  expiresUnix: number,
  onExpire: () => void,
  now: () => number = Date.now
): () => void {
  const timer = globalThis.setTimeout(onExpire, Math.max(0, expiresUnix * 1_000 - now()));
  return () => globalThis.clearTimeout(timer);
}

export function scheduleDebouncedValue<T>(
  value: T,
  delayMs: number,
  publish: (value: T) => void
): () => void {
  const timer = globalThis.setTimeout(() => publish(value), Math.max(0, delayMs));
  return () => globalThis.clearTimeout(timer);
}

export const CLIENT_ROTATION_MUTATION_KEY = ["client-credentials", "rotate"] as const;

export function purgeClientRotationMutation(
  client: QueryClient,
  resetObserver: () => void
): void {
  resetObserver();
  const cache = client.getMutationCache();
  for (const mutation of cache.findAll({
    mutationKey: CLIENT_ROTATION_MUTATION_KEY,
    exact: true
  })) {
    cache.remove(mutation);
  }
}
