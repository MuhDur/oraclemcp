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
