import * as React from "react";
import { createRoot } from "react-dom/client";
import {
  createRootRoute,
  createRoute,
  createRouter,
  Link,
  Outlet,
  RouterProvider
} from "@tanstack/react-router";
import {
  QueryClient,
  QueryClientProvider,
  useMutation,
  useQueries,
  useQuery
} from "@tanstack/react-query";
import {
  type ColumnDef,
  flexRender,
  getCoreRowModel,
  useReactTable
} from "@tanstack/react-table";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Code2,
  Database,
  Download,
  FileClock,
  Gauge,
  Play,
  Radio,
  RefreshCcw,
  RotateCcw,
  Search,
  ShieldCheck,
  SquarePen,
  Stethoscope,
  Timer,
  Users,
  Wifi
} from "lucide-react";

import { Badge, Button, Surface } from "../components/ui/primitives";
import { cn } from "../lib/utils";
import {
  auditProbes,
  doctorProbes,
  executeWorkbenchSql,
  fetchActiveLanes,
  fetchDashboardSession,
  fetchOperatorMetrics,
  fetchProbe,
  overviewProbes,
  pendingProbe,
  previewWorkbenchSql,
  readWorkbenchSql,
  type OperatorResponse,
  type ProbeDefinition,
  type ProbeResult,
  type AuditTailData,
  type AuditTailFilters,
  type AuditTailRecord,
  type ActiveLane,
  type LaneRequestDuration,
  type MetricsSnapshot,
  type OperatorEventEnvelope,
  sessionsProbes,
  fetchAuditTail,
  type WorkbenchActionData,
  type WorkbenchMode
} from "./operator-client";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchInterval: 10_000,
      staleTime: 5_000,
      retry: 1
    }
  }
});

type NavItem = {
  to: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
};

const navItems: NavItem[] = [
  { to: "/", label: "Overview", icon: Activity },
  { to: "/sessions", label: "Sessions", icon: Database },
  { to: "/workbench", label: "Workbench", icon: SquarePen },
  { to: "/audit", label: "Audit", icon: FileClock },
  { to: "/doctor", label: "Doctor", icon: Stethoscope }
];

const rootRoute = createRootRoute({
  component: RootLayout
});

const overviewRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: OverviewPage
});

const sessionsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sessions",
  component: SessionsPage
});

const auditRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/audit",
  component: AuditPage
});

const workbenchRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/workbench",
  component: WorkbenchPage
});

const doctorRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/doctor",
  component: DoctorPage
});

const router = createRouter({
  routeTree: rootRoute.addChildren([
    overviewRoute,
    sessionsRoute,
    workbenchRoute,
    auditRoute,
    doctorRoute
  ])
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

export function bootstrapDashboard(element: HTMLElement): void {
  createRoot(element).render(
    <React.StrictMode>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </React.StrictMode>
  );
}

function RootLayout(): React.ReactElement {
  return (
    <div className="min-h-screen bg-[#f6f7f3] text-zinc-950">
      <div className="mx-auto flex w-full max-w-[1440px] flex-col gap-4 px-4 py-4 md:px-6 lg:flex-row lg:py-6">
        <aside className="flex shrink-0 flex-col gap-4 border-b border-zinc-200 pb-4 lg:w-64 lg:border-b-0 lg:border-r lg:pb-0 lg:pr-4">
          <div className="flex items-center gap-3">
            <div className="flex size-10 items-center justify-center rounded-lg bg-emerald-700 text-white">
              <ShieldCheck className="size-5" aria-hidden="true" />
            </div>
            <div>
              <p className="text-xs font-semibold uppercase text-zinc-500">Operator</p>
              <h1 className="text-xl font-bold tracking-normal">oraclemcp</h1>
            </div>
          </div>
          <nav className="flex gap-2 overflow-x-auto lg:flex-col" aria-label="dashboard">
            {navItems.map((item) => (
              <NavLink key={item.to} item={item} />
            ))}
          </nav>
        </aside>
        <main className="min-w-0 flex-1">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

function NavLink({ item }: { item: NavItem }): React.ReactElement {
  const Icon = item.icon;
  return (
    <Link
      to={item.to}
      className="inline-flex min-h-10 items-center gap-2 rounded-md px-3 py-2 text-sm font-semibold text-zinc-700 hover:bg-white hover:text-zinc-950 [&.active]:bg-white [&.active]:text-emerald-800 [&.active]:shadow-sm"
    >
      <Icon className="size-4" aria-hidden="true" />
      <span>{item.label}</span>
    </Link>
  );
}

function OverviewPage(): React.ReactElement {
  const metrics = useQuery({
    queryKey: ["operator-metrics"],
    queryFn: fetchOperatorMetrics,
    refetchInterval: 5_000
  });
  const activeLanes = useQuery({
    queryKey: ["active-lanes"],
    queryFn: fetchActiveLanes,
    refetchInterval: 5_000
  });
  const eventLog = useOperatorEventLog("operator");
  const snapshot = metrics.data?.data.snapshot ?? null;
  const lanes = activeLanes.data?.data.lanes ?? [];

  return (
    <PageFrame
      title="Overview"
      eyebrow="Mission Control"
      description="Runtime and operator protocol posture from the active service."
    >
      <div className="space-y-4">
        <OverviewMetricTiles
          snapshot={snapshot}
          lanes={lanes}
          pending={metrics.isFetching || activeLanes.isFetching}
        />
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(360px,0.85fr)]">
          <LaneMetricsPanel snapshot={snapshot} lanes={lanes} />
          <OperatorEventLogPanel status={eventLog.status} events={eventLog.events} />
        </div>
        <div className="grid gap-4 xl:grid-cols-[minmax(0,0.85fr)_minmax(360px,1.15fr)]">
          <ToolMetricsPanel snapshot={snapshot} />
          <ProbeDashboard probes={overviewProbes} compact />
        </div>
      </div>
    </PageFrame>
  );
}

function SessionsPage(): React.ReactElement {
  return (
    <PageFrame
      title="Sessions"
      eyebrow="Active Lanes"
      description="Lane state and operator health endpoints."
    >
      <ProbeDashboard probes={sessionsProbes} compact />
    </PageFrame>
  );
}

type EventStreamStatus = "connecting" | "live" | "reconnecting" | "closed";

function useOperatorEventLog(laneId: string): {
  status: EventStreamStatus;
  events: OperatorEventEnvelope[];
} {
  const [status, setStatus] = React.useState<EventStreamStatus>("connecting");
  const [events, setEvents] = React.useState<OperatorEventEnvelope[]>([]);

  React.useEffect(() => {
    let mounted = true;
    setStatus("connecting");
    const source = new EventSource(
      `/operator/v1/events?lane_id=${encodeURIComponent(laneId)}`,
      { withCredentials: true }
    );
    const handleEvent = (message: MessageEvent<string>): void => {
      const parsed = parseOperatorEvent(message.data);
      if (!mounted || !parsed) {
        return;
      }
      setStatus("live");
      setEvents((current) => [parsed, ...current].slice(0, 24));
      queryClient.invalidateQueries({ queryKey: ["operator-metrics"] });
      queryClient.invalidateQueries({ queryKey: ["active-lanes"] });
    };
    const handleSnapshot = handleEvent as EventListener;
    source.addEventListener("operator.snapshot", handleSnapshot);
    source.addEventListener("operator.stream_gap", handleSnapshot);
    source.onmessage = handleEvent;
    source.onerror = () => {
      if (!mounted) {
        return;
      }
      setStatus(source.readyState === EventSource.CLOSED ? "closed" : "reconnecting");
    };
    return () => {
      mounted = false;
      source.close();
    };
  }, [laneId]);

  return { status, events };
}

function OverviewMetricTiles({
  snapshot,
  lanes,
  pending
}: {
  snapshot: MetricsSnapshot | null;
  lanes: ActiveLane[];
  pending: boolean;
}): React.ReactElement {
  const summary = overviewSummary(snapshot, lanes);
  return (
    <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-6" aria-label="overview metrics">
      <MetricTile
        icon={Users}
        label="Active lanes"
        value={summary.activeLanes}
        suffix=""
        tone={summary.activeLanes > 0 ? "ok" : "off"}
        pending={pending}
      />
      <MetricTile
        icon={BarChart3}
        label="Tool calls"
        value={summary.totalRequests}
        suffix=""
        tone="info"
        pending={pending}
      />
      <MetricTile
        icon={AlertTriangle}
        label="Blocked"
        value={summary.blocked}
        suffix=""
        tone={summary.blocked > 0 ? "warn" : "ok"}
        pending={pending}
      />
      <MetricTile
        icon={Timer}
        label="MCP latency"
        value={summary.meanLatencyMs}
        suffix="ms"
        tone={summary.meanLatencyMs > 500 ? "warn" : "neutral"}
        pending={pending}
      />
      <MetricTile
        icon={Gauge}
        label="DB errors"
        value={summary.errors}
        suffix=""
        tone={summary.errors > 0 ? "warn" : "ok"}
        pending={pending}
      />
      <MetricTile
        icon={Database}
        label="Pool active"
        value={summary.poolActive}
        suffix=""
        tone="neutral"
        pending={pending}
      />
    </section>
  );
}

function MetricTile({
  icon: Icon,
  label,
  value,
  suffix,
  tone,
  pending
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: number;
  suffix: string;
  tone: "neutral" | "ok" | "warn" | "off" | "info";
  pending: boolean;
}): React.ReactElement {
  return (
    <Surface className="min-h-32 p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="flex size-9 items-center justify-center rounded-md border border-zinc-200 bg-zinc-50 text-zinc-700">
          <Icon className="size-4" aria-hidden="true" />
        </div>
        <Badge tone={pending ? "info" : tone}>{pending ? "sync" : tone}</Badge>
      </div>
      <p className="mt-4 text-sm font-semibold text-zinc-600">{label}</p>
      <strong className="mt-2 block text-3xl leading-none text-zinc-950">
        {formatNumber(value)}
        {suffix ? <span className="ml-1 text-base text-zinc-500">{suffix}</span> : null}
      </strong>
    </Surface>
  );
}

function LaneMetricsPanel({
  snapshot,
  lanes
}: {
  snapshot: MetricsSnapshot | null;
  lanes: ActiveLane[];
}): React.ReactElement {
  const rows = laneMetricRows(snapshot, lanes);
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={Radio}
        title="Lane Metrics"
        meta={`${rows.length} lanes`}
        tone={rows.length > 0 ? "ok" : "off"}
      />
      <div className="overflow-x-auto">
        <table className="w-full min-w-[780px] border-collapse text-left">
          <thead className="bg-zinc-50 text-xs uppercase text-zinc-500">
            <tr>
              <th className="px-4 py-3 font-bold">Lane</th>
              <th className="px-4 py-3 font-bold">Requests</th>
              <th className="px-4 py-3 font-bold">Blocked</th>
              <th className="px-4 py-3 font-bold">Latency</th>
              <th className="px-4 py-3 font-bold">State</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-100">
            {rows.length === 0 ? (
              <tr>
                <td className="px-4 py-8 text-center text-sm font-semibold text-zinc-500" colSpan={5}>
                  No lane metrics
                </td>
              </tr>
            ) : (
              rows.map((row) => (
                <tr key={`${row.laneId}:${row.subjectIdHash}`} className="bg-white">
                  <td className="px-4 py-4 align-top">
                    <p className="font-mono text-sm font-semibold text-zinc-950">{row.laneId}</p>
                    <p className="mt-1 break-all font-mono text-xs text-zinc-500">
                      {row.subjectIdHash}
                    </p>
                  </td>
                  <td className="px-4 py-4 align-top font-mono text-sm text-zinc-800">
                    {formatNumber(row.requests)}
                  </td>
                  <td className="px-4 py-4 align-top">
                    <Badge tone={row.blocked > 0 ? "warn" : "ok"}>{formatNumber(row.blocked)}</Badge>
                  </td>
                  <td className="px-4 py-4 align-top">
                    <div className="w-full max-w-[180px]">
                      <div className="h-2 rounded-full bg-zinc-100">
                        <div
                          className="h-2 rounded-full bg-sky-600"
                          style={{ width: `${latencyBarWidth(row.meanLatencyMs)}%` }}
                        />
                      </div>
                      <p className="mt-2 font-mono text-xs text-zinc-700">
                        {formatMs(row.meanLatencyMs)} avg · {formatMs(row.maxLatencyMs)} max
                      </p>
                    </div>
                  </td>
                  <td className="px-4 py-4 align-top">
                    <Badge tone={row.active ? "ok" : "off"}>{row.active ? "active" : "idle"}</Badge>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </Surface>
  );
}

function ToolMetricsPanel({
  snapshot
}: {
  snapshot: MetricsSnapshot | null;
}): React.ReactElement {
  const rows = [...(snapshot?.requests ?? [])].sort((a, b) => b.count - a.count).slice(0, 8);
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={Activity}
        title="Tool Metrics"
        meta={`${rows.length} series`}
        tone={rows.length > 0 ? "info" : "off"}
      />
      <div className="divide-y divide-zinc-100">
        {rows.length === 0 ? (
          <p className="px-4 py-8 text-center text-sm font-semibold text-zinc-500">No tool metrics</p>
        ) : (
          rows.map((row) => (
            <div key={`${row.tool}:${row.status}`} className="grid gap-3 px-4 py-3 sm:grid-cols-[minmax(0,1fr)_92px_72px] sm:items-center">
              <div className="min-w-0">
                <p className="truncate font-mono text-sm font-semibold text-zinc-950">{row.tool}</p>
                <p className="mt-1 text-xs text-zinc-500">{row.status}</p>
              </div>
              <div className="h-2 rounded-full bg-zinc-100">
                <div
                  className={cn("h-2 rounded-full", row.status === "ok" ? "bg-emerald-600" : "bg-amber-500")}
                  style={{ width: `${requestBarWidth(row.count, rows[0]?.count ?? 1)}%` }}
                />
              </div>
              <p className="font-mono text-sm font-semibold text-zinc-800">{formatNumber(row.count)}</p>
            </div>
          ))
        )}
      </div>
    </Surface>
  );
}

function OperatorEventLogPanel({
  status,
  events
}: {
  status: EventStreamStatus;
  events: OperatorEventEnvelope[];
}): React.ReactElement {
  return (
    <Surface className="overflow-hidden">
      <PanelHeader icon={Wifi} title="Event Log" meta={status} tone={eventStatusTone(status)} />
      <div className="max-h-[460px] divide-y divide-zinc-100 overflow-auto">
        {events.length === 0 ? (
          <p className="px-4 py-8 text-center text-sm font-semibold text-zinc-500">No events</p>
        ) : (
          events.map((event) => (
            <div key={event.event_id} className="px-4 py-3">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="font-mono text-sm font-semibold text-zinc-950">{event.event_id}</p>
                  <p className="mt-1 break-all font-mono text-xs text-zinc-500">
                    {event.subject_id_hash}
                  </p>
                </div>
                <Badge tone={event.event_type === "operator.stream_gap" ? "warn" : "info"}>
                  {event.event_type}
                </Badge>
              </div>
              <div className="mt-3 grid gap-2 sm:grid-cols-3">
                <EventFact label="Lane" value={event.lane_id} />
                <EventFact label="Active" value={eventMetric(event, "active_lanes")} />
                <EventFact label="Seq" value={event.event_seq} />
              </div>
            </div>
          ))
        )}
      </div>
    </Surface>
  );
}

function PanelHeader({
  icon: Icon,
  title,
  meta,
  tone
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  meta: string;
  tone: "neutral" | "ok" | "warn" | "off" | "info";
}): React.ReactElement {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-zinc-200 px-4 py-3">
      <div className="flex min-w-0 items-center gap-3">
        <div className="flex size-9 items-center justify-center rounded-md border border-zinc-200 bg-zinc-50 text-zinc-700">
          <Icon className="size-4" aria-hidden="true" />
        </div>
        <div className="min-w-0">
          <h3 className="truncate text-base font-bold text-zinc-950">{title}</h3>
          <p className="mt-1 truncate text-sm text-zinc-500">{meta}</p>
        </div>
      </div>
      <Badge tone={tone}>{tone}</Badge>
    </div>
  );
}

function EventFact({ label, value }: { label: string; value: unknown }): React.ReactElement {
  return (
    <div className="rounded-md border border-zinc-200 bg-zinc-50 p-2">
      <p className="text-xs font-bold uppercase text-zinc-500">{label}</p>
      <p className="mt-1 break-all font-mono text-xs text-zinc-900">{String(value ?? "...")}</p>
    </div>
  );
}

type OverviewSummary = {
  activeLanes: number;
  totalRequests: number;
  blocked: number;
  errors: number;
  meanLatencyMs: number;
  poolActive: number;
};

type LaneMetricRow = {
  laneId: string;
  subjectIdHash: string;
  requests: number;
  blocked: number;
  meanLatencyMs: number;
  maxLatencyMs: number;
  active: boolean;
};

function overviewSummary(snapshot: MetricsSnapshot | null, lanes: ActiveLane[]): OverviewSummary {
  const durations = snapshot?.lane_request_duration_ms ?? [];
  const latency = aggregateDurations(durations);
  return {
    activeLanes: snapshot?.active_lanes ?? lanes.length,
    totalRequests: sumCounts(snapshot?.requests ?? []),
    blocked: sumCounts(snapshot?.lane_blocked ?? []),
    errors: sumCounts(snapshot?.errors ?? []),
    meanLatencyMs: latency.mean,
    poolActive: snapshot?.pool_active_connections ?? 0
  };
}

function laneMetricRows(snapshot: MetricsSnapshot | null, lanes: ActiveLane[]): LaneMetricRow[] {
  const rows = new Map<string, LaneMetricRow>();
  const ensure = (laneId: string, subjectIdHash: string): LaneMetricRow => {
    const key = `${laneId}\u0000${subjectIdHash}`;
    const existing = rows.get(key);
    if (existing) {
      return existing;
    }
    const row: LaneMetricRow = {
      laneId,
      subjectIdHash,
      requests: 0,
      blocked: 0,
      meanLatencyMs: 0,
      maxLatencyMs: 0,
      active: false
    };
    rows.set(key, row);
    return row;
  };

  for (const lane of lanes) {
    const row = ensure(lane.lane_id, lane.subject_id_hash);
    row.active = lane.status === "active";
  }
  for (const gauge of snapshot?.active_lane_gauges ?? []) {
    const row = ensure(gauge.lane_id, gauge.subject_id_hash);
    row.active = gauge.active > 0;
  }
  for (const request of snapshot?.lane_requests ?? []) {
    const row = ensure(request.lane_id, request.subject_id_hash);
    row.requests += request.count;
  }
  for (const blocked of snapshot?.lane_blocked ?? []) {
    const row = ensure(blocked.lane_id, blocked.subject_id_hash);
    row.blocked += blocked.count;
  }
  const latencyByLane = new Map<string, ReturnType<typeof aggregateDurations>>();
  for (const duration of snapshot?.lane_request_duration_ms ?? []) {
    const key = `${duration.lane_id}\u0000${duration.subject_id_hash}`;
    const current = latencyByLane.get(key);
    const next = aggregateDurations([duration], current);
    latencyByLane.set(key, next);
  }
  for (const [key, latency] of latencyByLane) {
    const row = rows.get(key);
    if (row) {
      row.meanLatencyMs = latency.mean;
      row.maxLatencyMs = latency.max;
    }
  }
  return [...rows.values()].sort((a, b) => {
    if (a.active !== b.active) {
      return a.active ? -1 : 1;
    }
    return b.requests - a.requests || a.laneId.localeCompare(b.laneId);
  });
}

function aggregateDurations(
  durations: LaneRequestDuration[],
  base: { count: number; sum: number; max: number; mean: number } = {
    count: 0,
    sum: 0,
    max: 0,
    mean: 0
  }
): { count: number; sum: number; max: number; mean: number } {
  let count = base.count;
  let sum = base.sum;
  let max = base.max;
  for (const duration of durations) {
    count += duration.histogram.count;
    sum += duration.histogram.sum;
    max = Math.max(max, duration.histogram.max);
  }
  return {
    count,
    sum,
    max,
    mean: count === 0 ? 0 : Math.round(sum / count)
  };
}

function sumCounts(rows: Array<{ count: number }>): number {
  return rows.reduce((total, row) => total + row.count, 0);
}

function parseOperatorEvent(raw: string): OperatorEventEnvelope | null {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!isRecord(parsed)) {
      return null;
    }
    if (
      parsed["protocol_version"] !== "operator.v1" ||
      typeof parsed["event_id"] !== "string" ||
      typeof parsed["event_seq"] !== "number" ||
      typeof parsed["lane_id"] !== "string" ||
      typeof parsed["subject_id_hash"] !== "string" ||
      typeof parsed["event_type"] !== "string" ||
      !isRecord(parsed["data"])
    ) {
      return null;
    }
    return parsed as OperatorEventEnvelope;
  } catch {
    return null;
  }
}

function eventMetric(event: OperatorEventEnvelope, key: string): unknown {
  return event.data[key];
}

function eventStatusTone(status: EventStreamStatus): "neutral" | "ok" | "warn" | "off" | "info" {
  switch (status) {
    case "live":
      return "ok";
    case "reconnecting":
      return "warn";
    case "closed":
      return "off";
    case "connecting":
      return "info";
  }
}

function latencyBarWidth(ms: number): number {
  if (ms <= 0) {
    return 2;
  }
  return Math.min(100, Math.max(8, Math.round((ms / 1_000) * 100)));
}

function requestBarWidth(count: number, max: number): number {
  if (max <= 0) {
    return 2;
  }
  return Math.min(100, Math.max(8, Math.round((count / max) * 100)));
}

function formatMs(ms: number): string {
  return `${formatNumber(ms)}ms`;
}

function formatNumber(value: number): string {
  return new Intl.NumberFormat("en-US", { maximumFractionDigits: 0 }).format(value);
}

const workbenchModes: Array<{ id: WorkbenchMode; label: string }> = [
  { id: "classify_only", label: "Classify" },
  { id: "read_query", label: "Read" },
  { id: "dml_preview_confirm", label: "DML" },
  { id: "ddl_plan_confirm", label: "DDL" }
];

type WorkbenchAction = "preview" | "read" | "rollback_preview" | "commit";

type WorkbenchResult =
  | {
      state: "ok";
      label: string;
      response: OperatorResponse<WorkbenchActionData>;
    }
  | {
      state: "error";
      label: string;
      message: string;
    };

function WorkbenchPage(): React.ReactElement {
  const [mode, setMode] = React.useState<WorkbenchMode>("classify_only");
  const [sql, setSql] = React.useState("SELECT * FROM dual");
  const [laneId, setLaneId] = React.useState("");
  const [confirm, setConfirm] = React.useState("");
  const [maxRows, setMaxRows] = React.useState(100);
  const [captureDbmsOutput, setCaptureDbmsOutput] = React.useState(false);
  const [lastResult, setLastResult] = React.useState<WorkbenchResult | null>(null);

  const session = useQuery({
    queryKey: ["dashboard-session"],
    queryFn: fetchDashboardSession,
    staleTime: 60_000,
    refetchInterval: 60_000,
    retry: 1
  });

  const action = useMutation({
    mutationFn: async (kind: WorkbenchAction) => {
      if (!session.data) {
        throw new Error("dashboard session is not ready");
      }
      const request = { sql: sql.trim(), mode, laneId };
      if (kind === "preview") {
        return previewWorkbenchSql(session.data, request);
      }
      if (kind === "read") {
        return readWorkbenchSql(session.data, { ...request, maxRows });
      }
      return executeWorkbenchSql(session.data, {
        ...request,
        commit: kind === "commit",
        confirm,
        captureDbmsOutput
      });
    },
    onSuccess: (response, kind) => {
      setLastResult({ state: "ok", label: actionLabel(kind), response });
      const nextConfirm = confirmationFromResponse(response);
      if (nextConfirm) {
        setConfirm(nextConfirm);
      }
    },
    onError: (error, kind) => {
      setLastResult({
        state: "error",
        label: actionLabel(kind),
        message: error instanceof Error ? error.message : "operator action failed"
      });
    }
  });

  const canSubmit = sql.trim().length > 0 && session.status === "success" && !action.isPending;
  const confirmReady = confirm.trim().length > 0;
  const sessionTone = session.status === "success" ? "ok" : session.status === "error" ? "warn" : "info";

  return (
    <PageFrame
      title="Workbench"
      eyebrow="Guarded SQL"
      description="Human-in-the-loop SQL through the same classifier, lane gate, confirmation, and audit path as MCP tools."
    >
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(360px,0.85fr)]">
        <Surface className="p-4">
          <div className="flex flex-col gap-4">
            <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div className="flex flex-wrap gap-2" role="tablist" aria-label="workbench mode">
                {workbenchModes.map((item) => (
                  <Button
                    key={item.id}
                    type="button"
                    variant={mode === item.id ? "primary" : "secondary"}
                    onClick={() => setMode(item.id)}
                  >
                    {item.label}
                  </Button>
                ))}
              </div>
              <Badge tone={sessionTone}>
                {session.status === "success" ? "paired" : session.status === "error" ? "blocked" : "pairing"}
              </Badge>
            </div>

            <label className="block">
              <span className="mb-2 block text-sm font-bold text-zinc-700">SQL</span>
              <textarea
                className="min-h-[320px] w-full resize-y rounded-md border border-zinc-300 bg-zinc-950 p-3 font-mono text-sm leading-6 text-zinc-50 outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                spellCheck={false}
                value={sql}
                onChange={(event) => setSql(event.target.value)}
              />
            </label>

            <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_160px_180px]">
              <label className="block">
                <span className="mb-2 block text-sm font-bold text-zinc-700">Lane</span>
                <input
                  className="h-10 w-full rounded-md border border-zinc-300 px-3 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                  value={laneId}
                  onChange={(event) => setLaneId(event.target.value)}
                  placeholder="operator"
                />
              </label>
              <label className="block">
                <span className="mb-2 block text-sm font-bold text-zinc-700">Rows</span>
                <input
                  className="h-10 w-full rounded-md border border-zinc-300 px-3 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                  min={1}
                  max={5000}
                  type="number"
                  value={maxRows}
                  onChange={(event) => setMaxRows(clampRows(event.target.valueAsNumber))}
                />
              </label>
              <label className="flex min-h-10 items-end gap-2 pb-2 text-sm font-semibold text-zinc-700">
                <input
                  className="size-4 rounded border-zinc-300 text-emerald-700 focus:ring-emerald-600"
                  type="checkbox"
                  checked={captureDbmsOutput}
                  onChange={(event) => setCaptureDbmsOutput(event.target.checked)}
                />
                DBMS_OUTPUT
              </label>
            </div>

            <label className="block">
              <span className="mb-2 block text-sm font-bold text-zinc-700">Confirm</span>
              <input
                className="h-10 w-full rounded-md border border-zinc-300 px-3 font-mono text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                value={confirm}
                onChange={(event) => setConfirm(event.target.value)}
                placeholder="preview grant"
              />
            </label>

            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                variant="secondary"
                disabled={!canSubmit}
                onClick={() => action.mutate("preview")}
              >
                <Search className="size-4" aria-hidden="true" />
                Preview
              </Button>
              <Button
                type="button"
                variant="secondary"
                disabled={!canSubmit || mode !== "read_query"}
                onClick={() => action.mutate("read")}
              >
                <Play className="size-4" aria-hidden="true" />
                Run Read
              </Button>
              <Button
                type="button"
                variant="secondary"
                disabled={!canSubmit || mode !== "dml_preview_confirm"}
                onClick={() => action.mutate("rollback_preview")}
              >
                <RotateCcw className="size-4" aria-hidden="true" />
                Rollback Preview
              </Button>
              <Button
                type="button"
                variant="primary"
                disabled={!canSubmit || mode !== "dml_preview_confirm" || !confirmReady}
                onClick={() => action.mutate("commit")}
              >
                <CheckCircle2 className="size-4" aria-hidden="true" />
                Commit
              </Button>
            </div>
          </div>
        </Surface>

        <WorkbenchResultPanel result={lastResult} pending={action.isPending} />
      </div>
    </PageFrame>
  );
}

function AuditPage(): React.ReactElement {
  const [subjectIdHash, setSubjectIdHash] = React.useState("");
  const [tool, setTool] = React.useState("");
  const [dangerLevel, setDangerLevel] = React.useState("");
  const [limit, setLimit] = React.useState(50);
  const [exportProofBundle, setExportProofBundle] = React.useState(false);
  const filters = React.useMemo<AuditTailFilters>(
    () => ({
      limit,
      subjectIdHash,
      tool,
      dangerLevel,
      exportProofBundle
    }),
    [dangerLevel, exportProofBundle, limit, subjectIdHash, tool]
  );
  const auditTail = useQuery({
    queryKey: ["audit-tail", filters],
    queryFn: () => fetchAuditTail(filters)
  });
  const data = auditTail.data?.data ?? null;

  return (
    <PageFrame
      title="Audit"
      eyebrow="Hash Chain"
      description="Signed audit-chain timeline, DB evidence, filters, and redacted proof export."
    >
      <div className="space-y-4">
        <Surface className="p-4">
          <div className="grid gap-3 lg:grid-cols-[minmax(220px,1fr)_180px_160px_120px_auto_auto] lg:items-end">
            <label className="block">
              <span className="mb-2 block text-sm font-bold text-zinc-700">Subject Hash</span>
              <input
                className="h-10 w-full rounded-md border border-zinc-300 px-3 font-mono text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                value={subjectIdHash}
                onChange={(event) => setSubjectIdHash(event.target.value)}
                placeholder="subject-sha256:"
              />
            </label>
            <label className="block">
              <span className="mb-2 block text-sm font-bold text-zinc-700">Tool</span>
              <select
                className="h-10 w-full rounded-md border border-zinc-300 bg-white px-3 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                value={tool}
                onChange={(event) => setTool(event.target.value)}
              >
                <option value="">All</option>
                <option value="operator_api">operator_api</option>
                <option value="oracle_query">oracle_query</option>
                <option value="oracle_execute">oracle_execute</option>
                <option value="oracle_compile_object">compile_object</option>
                <option value="oracle_patch_source">patch_source</option>
                <option value="oracle_set_session_level">set_session_level</option>
              </select>
            </label>
            <label className="block">
              <span className="mb-2 block text-sm font-bold text-zinc-700">Level</span>
              <select
                className="h-10 w-full rounded-md border border-zinc-300 bg-white px-3 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                value={dangerLevel}
                onChange={(event) => setDangerLevel(event.target.value)}
              >
                <option value="">All</option>
                <option value="SAFE">SAFE</option>
                <option value="GUARDED">GUARDED</option>
                <option value="DESTRUCTIVE">DESTRUCTIVE</option>
                <option value="ADMIN">ADMIN</option>
              </select>
            </label>
            <label className="block">
              <span className="mb-2 block text-sm font-bold text-zinc-700">Limit</span>
              <input
                className="h-10 w-full rounded-md border border-zinc-300 px-3 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                min={1}
                max={200}
                type="number"
                value={limit}
                onChange={(event) => setLimit(clampAuditLimit(event.target.valueAsNumber))}
              />
            </label>
            <Button
              type="button"
              variant={exportProofBundle ? "primary" : "secondary"}
              onClick={() => setExportProofBundle((enabled) => !enabled)}
            >
              <Download className="size-4" aria-hidden="true" />
              Bundle
            </Button>
            <Button type="button" variant="ghost" onClick={() => auditTail.refetch()}>
              <RefreshCcw className="size-4" aria-hidden="true" />
              Refresh
            </Button>
          </div>
        </Surface>

        <AuditProofSummary
          data={data}
          pending={auditTail.isFetching}
          error={auditTail.error instanceof Error ? auditTail.error.message : null}
        />
        <AuditTimelineTable records={data?.records ?? []} />
        {exportProofBundle ? <AuditProofBundlePanel bundle={data?.export ?? null} /> : null}
        <ProbeDashboard probes={auditProbes} compact />
      </div>
    </PageFrame>
  );
}

function AuditProofSummary({
  data,
  pending,
  error
}: {
  data: AuditTailData | null;
  pending: boolean;
  error: string | null;
}): React.ReactElement {
  const chainStatus = nestedString(data?.proof, ["verification", "hash_chain", "status"]);
  const macStatus = nestedString(data?.proof, ["verification", "keyed_mac", "status"]);
  const chainTone = chainStatus === "ok" ? "ok" : chainStatus === "broken" ? "warn" : "off";
  return (
    <Surface className="p-4">
      <div className="grid gap-3 md:grid-cols-4">
        <AuditFactTile
          label="Chain"
          value={pending ? "checking" : chainStatus ?? data?.source ?? "unavailable"}
          tone={pending ? "info" : chainTone}
        />
        <AuditFactTile
          label="MAC"
          value={macStatus ?? "not checked"}
          tone={macStatus === "not_checked" ? "info" : "ok"}
        />
        <AuditFactTile
          label="Scanned"
          value={String(data?.scanned_records ?? 0)}
          tone="neutral"
        />
        <AuditFactTile
          label="Selected"
          value={String(data?.selected_records ?? data?.records.length ?? 0)}
          tone="neutral"
        />
      </div>
      {error ? (
        <p className="mt-3 rounded-md border border-amber-200 bg-amber-50 p-3 text-sm font-semibold text-amber-900">
          {error}
        </p>
      ) : null}
    </Surface>
  );
}

function AuditFactTile({
  label,
  value,
  tone
}: {
  label: string;
  value: string;
  tone: "neutral" | "ok" | "warn" | "off" | "info";
}): React.ReactElement {
  return (
    <div className="rounded-md border border-zinc-200 bg-zinc-50 p-3">
      <div className="flex items-start justify-between gap-2">
        <p className="text-xs font-bold uppercase text-zinc-500">{label}</p>
        <Badge tone={tone}>{tone}</Badge>
      </div>
      <p className="mt-3 break-all font-mono text-sm font-semibold text-zinc-950">{value}</p>
    </div>
  );
}

function AuditTimelineTable({ records }: { records: AuditTailRecord[] }): React.ReactElement {
  return (
    <Surface className="overflow-hidden">
      <div className="flex items-center justify-between gap-3 border-b border-zinc-200 px-4 py-3">
        <div>
          <h3 className="text-base font-bold text-zinc-950">Timeline</h3>
          <p className="mt-1 text-sm text-zinc-500">{records.length} records</p>
        </div>
        <Badge tone={records.length > 0 ? "ok" : "off"}>{records.length > 0 ? "ready" : "empty"}</Badge>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[1080px] border-collapse text-left">
          <thead className="bg-zinc-50 text-xs uppercase text-zinc-500">
            <tr>
              <th className="px-4 py-3 font-bold">Seq</th>
              <th className="px-4 py-3 font-bold">Time</th>
              <th className="px-4 py-3 font-bold">Tool</th>
              <th className="px-4 py-3 font-bold">SQL Hash</th>
              <th className="px-4 py-3 font-bold">DB Evidence</th>
              <th className="px-4 py-3 font-bold">Proof</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-100">
            {records.length === 0 ? (
              <tr>
                <td className="px-4 py-8 text-center text-sm font-semibold text-zinc-500" colSpan={6}>
                  No audit records
                </td>
              </tr>
            ) : (
              records.map((record) => (
                <tr key={`${record.seq}-${record.sql_sha256}`} className="bg-white">
                  <td className="px-4 py-4 align-top font-mono text-sm text-zinc-900">{record.seq}</td>
                  <td className="px-4 py-4 align-top text-sm text-zinc-700">
                    <p className="font-semibold text-zinc-900">{record.timestamp}</p>
                    <p className="mt-1 break-all font-mono text-xs text-zinc-500">
                      {record.subject_id_hash}
                    </p>
                  </td>
                  <td className="px-4 py-4 align-top text-sm">
                    <p className="font-semibold text-zinc-950">{record.tool}</p>
                    <div className="mt-2 flex flex-wrap gap-2">
                      <Badge tone="info">{record.danger_level}</Badge>
                      <Badge tone={record.outcome === "SUCCEEDED" ? "ok" : "warn"}>{record.outcome}</Badge>
                    </div>
                  </td>
                  <td className="px-4 py-4 align-top text-sm">
                    <p className="max-w-[360px] break-words font-mono text-xs leading-5 text-zinc-900">
                      {record.sql_sha256}
                    </p>
                    <p className="mt-2 text-xs font-semibold text-zinc-500">binds redacted</p>
                  </td>
                  <td className="px-4 py-4 align-top text-sm text-zinc-700">
                    <AuditEvidenceList evidence={record.db_evidence} />
                  </td>
                  <td className="px-4 py-4 align-top text-sm">
                    <AuditRecordProof proof={record.proof} />
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </Surface>
  );
}

function AuditEvidenceList({
  evidence
}: {
  evidence: AuditTailRecord["db_evidence"];
}): React.ReactElement {
  const entries = compactEvidence(evidence);
  if (entries.length === 0) {
    return <span className="text-zinc-500">unavailable</span>;
  }
  return (
    <dl className="grid gap-1">
      {entries.map(([key, value]) => (
        <div key={key} className="grid grid-cols-[96px_minmax(0,1fr)] gap-2">
          <dt className="text-xs font-bold uppercase text-zinc-500">{key}</dt>
          <dd className="break-all font-mono text-xs text-zinc-900">{String(value)}</dd>
        </div>
      ))}
    </dl>
  );
}

function AuditRecordProof({ proof }: { proof: AuditTailRecord["proof"] }): React.ReactElement {
  const hashValid = proof?.["hash_valid"] === true;
  return (
    <div className="space-y-2">
      <Badge tone={hashValid ? "ok" : "warn"}>{hashValid ? "hash ok" : "hash fail"}</Badge>
      <p className="break-all font-mono text-xs text-zinc-500">
        {shortHash(typeof proof?.["entry_hash"] === "string" ? proof["entry_hash"] : null)}
      </p>
      <p className="break-all font-mono text-xs text-zinc-500">
        {typeof proof?.["key_id"] === "string" ? proof["key_id"] : "unsigned"}
      </p>
    </div>
  );
}

function AuditProofBundlePanel({
  bundle
}: {
  bundle: Record<string, unknown> | null;
}): React.ReactElement {
  return (
    <Surface className="overflow-hidden">
      <div className="flex items-center justify-between gap-3 border-b border-zinc-200 px-4 py-3">
        <div>
          <h3 className="text-base font-bold text-zinc-950">Proof Bundle</h3>
          <p className="mt-1 text-sm text-zinc-500">
            {bundle ? String(bundle["format"] ?? "bundle") : "unavailable"}
          </p>
        </div>
        <Badge tone={bundle ? "ok" : "off"}>{bundle ? "export" : "empty"}</Badge>
      </div>
      <pre className="max-h-[460px] overflow-auto bg-zinc-950 p-4 text-xs leading-5 text-zinc-50">
        {bundle ? prettyJson(bundle) : "{}"}
      </pre>
    </Surface>
  );
}

function compactEvidence(evidence: AuditTailRecord["db_evidence"]): Array<[string, unknown]> {
  if (!isRecord(evidence)) {
    return [];
  }
  return [
    "availability",
    "db_unique_name",
    "service_name",
    "instance_name",
    "session_user",
    "current_user",
    "sid",
    "serial_number",
    "client_identifier"
  ]
    .map((key) => [key, evidence[key]] as [string, unknown])
    .filter(([, value]) => value !== null && value !== undefined && value !== "");
}

function nestedString(value: unknown, path: string[]): string | null {
  let current = value;
  for (const segment of path) {
    if (!isRecord(current)) {
      return null;
    }
    current = current[segment];
  }
  return typeof current === "string" ? current : null;
}

function shortHash(value: string | null): string {
  if (!value) {
    return "hash unavailable";
  }
  if (value.length <= 28) {
    return value;
  }
  return `${value.slice(0, 19)}...${value.slice(-8)}`;
}

function clampAuditLimit(value: number): number {
  if (!Number.isFinite(value)) {
    return 50;
  }
  return Math.min(200, Math.max(1, Math.trunc(value)));
}

function DoctorPage(): React.ReactElement {
  return (
    <PageFrame
      title="Doctor"
      eyebrow="Diagnostics"
      description="Service readiness and operator health."
    >
      <ProbeDashboard probes={doctorProbes} compact />
    </PageFrame>
  );
}

function PageFrame({
  eyebrow,
  title,
  description,
  children
}: {
  eyebrow: string;
  title: string;
  description: string;
  children: React.ReactNode;
}): React.ReactElement {
  return (
    <div className="space-y-4">
      <header className="flex flex-col gap-3 border-b border-zinc-200 pb-4 md:flex-row md:items-end md:justify-between">
        <div className="min-w-0">
          <p className="text-xs font-bold uppercase text-emerald-800">{eyebrow}</p>
          <h2 className="mt-1 text-3xl font-bold tracking-normal text-zinc-950">{title}</h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-zinc-600">{description}</p>
        </div>
        <Badge tone="info">operator.v1</Badge>
      </header>
      {children}
    </div>
  );
}

function ProbeDashboard({
  probes,
  compact = false
}: {
  probes: ProbeDefinition[];
  compact?: boolean;
}): React.ReactElement {
  const results = useProbeResults(probes);
  const summary = summarize(results);

  return (
    <div className="space-y-4">
      <section
        className={cn(
          "grid gap-3",
          compact ? "grid-cols-1 md:grid-cols-3" : "grid-cols-1 md:grid-cols-2 xl:grid-cols-4"
        )}
        aria-label="service summary"
      >
        <SummaryTile label="Healthy" value={summary.ok} tone="ok" />
        <SummaryTile label="Attention" value={summary.warn} tone="warn" />
        <SummaryTile label="Unmounted" value={summary.off} tone="off" />
        <SummaryTile label="Checking" value={summary.loading} tone="info" />
      </section>
      <EndpointTable rows={results} />
    </div>
  );
}

function useProbeResults(probes: ProbeDefinition[]): ProbeResult[] {
  const queries = useQueries({
    queries: probes.map((probe) => ({
      queryKey: ["operator-probe", probe.id],
      queryFn: () => fetchProbe(probe)
    }))
  });
  return queries.map((query, index) => query.data ?? pendingProbe(probes[index]));
}

function summarize(rows: ProbeResult[]): Record<ProbeResult["state"], number> {
  return rows.reduce<Record<ProbeResult["state"], number>>(
    (totals, row) => {
      totals[row.state] += 1;
      return totals;
    },
    { loading: 0, ok: 0, off: 0, warn: 0 }
  );
}

function SummaryTile({
  label,
  value,
  tone
}: {
  label: string;
  value: number;
  tone: "ok" | "warn" | "off" | "info";
}): React.ReactElement {
  return (
    <Surface className="min-h-28 p-4">
      <div className="flex items-start justify-between gap-3">
        <p className="text-sm font-semibold text-zinc-600">{label}</p>
        <Badge tone={tone}>{tone}</Badge>
      </div>
      <strong className="mt-5 block text-3xl leading-none text-zinc-950">{value}</strong>
    </Surface>
  );
}

function WorkbenchResultPanel({
  result,
  pending
}: {
  result: WorkbenchResult | null;
  pending: boolean;
}): React.ReactElement {
  const confirm = result?.state === "ok" ? confirmationFromResponse(result.response) : null;
  const facts = result?.state === "ok" ? factsFromResponse(result.response) : [];
  return (
    <Surface className="min-h-[520px] overflow-hidden">
      <div className="flex items-center justify-between gap-3 border-b border-zinc-200 px-4 py-3">
        <div className="min-w-0">
          <h3 className="flex items-center gap-2 text-base font-bold text-zinc-950">
            <Code2 className="size-4" aria-hidden="true" />
            Result
          </h3>
          <p className="mt-1 truncate text-sm text-zinc-500">
            {pending ? "request in flight" : result ? result.label : "idle"}
          </p>
        </div>
        <Badge tone={pending ? "info" : result?.state === "error" ? "warn" : result ? "ok" : "off"}>
          {pending ? "running" : result?.state ?? "empty"}
        </Badge>
      </div>
      <div className="space-y-4 p-4">
        {facts.length > 0 ? (
          <div className="grid gap-2 sm:grid-cols-2">
            {facts.map((fact) => (
              <div key={fact.label} className="rounded-md border border-zinc-200 bg-zinc-50 p-3">
                <p className="text-xs font-bold uppercase text-zinc-500">{fact.label}</p>
                <p className="mt-1 break-all font-mono text-xs text-zinc-900">{fact.value}</p>
              </div>
            ))}
          </div>
        ) : null}
        {confirm ? (
          <div className="rounded-md border border-emerald-200 bg-emerald-50 p-3">
            <p className="text-sm font-bold text-emerald-900">Execution Grant</p>
            <p className="mt-2 break-all font-mono text-xs text-emerald-900">{confirm}</p>
          </div>
        ) : null}
        {result?.state === "error" ? (
          <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm font-semibold text-amber-900">
            {result.message}
          </div>
        ) : (
          <pre className="max-h-[620px] overflow-auto rounded-md bg-zinc-950 p-3 text-xs leading-5 text-zinc-50">
            {result?.state === "ok" ? prettyJson(result.response) : "{}"}
          </pre>
        )}
      </div>
    </Surface>
  );
}

type WorkbenchFact = {
  label: string;
  value: string;
};

function factsFromResponse(response: OperatorResponse<WorkbenchActionData>): WorkbenchFact[] {
  const facts: WorkbenchFact[] = [];
  const result = mcpResult(response.data.mcp_response);
  const idempotency = response.data.idempotency;
  addFact(facts, "Tool", response.data.mcp_tool);
  if (isRecord(idempotency)) {
    addFact(facts, "Lane", idempotency["lane_id"]);
    addFact(facts, "Subject", idempotency["subject_id_hash"]);
    addFact(facts, "SQL", idempotency["sql_sha256"]);
    addFact(facts, "Audit", idempotency["operator_audit_seq"]);
  }
  if (isRecord(result)) {
    addFact(facts, "Required", result["required_level"]);
    addFact(facts, "Danger", result["danger"]);
    addFact(facts, "Rows", result["rows_affected"]);
    addFact(facts, "Committed", result["committed"]);
    addFact(facts, "Rolled Back", result["rolled_back"]);
    const nextActions = result["next_actions"];
    if (Array.isArray(nextActions)) {
      addFact(facts, "Next Actions", nextActions.length);
    }
  }
  return facts;
}

function addFact(facts: WorkbenchFact[], label: string, value: unknown): void {
  if (value === null || value === undefined || value === "") {
    return;
  }
  facts.push({ label, value: String(value) });
}

function actionLabel(action: WorkbenchAction): string {
  switch (action) {
    case "preview":
      return "Preview";
    case "read":
      return "Run Read";
    case "rollback_preview":
      return "Rollback Preview";
    case "commit":
      return "Commit";
  }
}

function confirmationFromResponse(response: OperatorResponse<WorkbenchActionData>): string | null {
  const result = mcpResult(response.data.mcp_response);
  if (!isRecord(result)) {
    return null;
  }
  for (const field of ["execute_confirmation", "confirmation"]) {
    const block = result[field];
    if (isRecord(block) && typeof block["confirm"] === "string") {
      return block["confirm"];
    }
  }
  return null;
}

function mcpResult(value: unknown): unknown {
  if (!isRecord(value)) {
    return null;
  }
  const result = value["result"];
  if (isRecord(result) && "structuredContent" in result) {
    return result["structuredContent"];
  }
  return result ?? null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function prettyJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function clampRows(value: number): number {
  if (!Number.isFinite(value)) {
    return 100;
  }
  return Math.min(5000, Math.max(1, Math.trunc(value)));
}

const columns: ColumnDef<ProbeResult>[] = [
  {
    header: "Endpoint",
    accessorKey: "label",
    cell: ({ row }) => (
      <div>
        <p className="font-semibold text-zinc-950">{row.original.label}</p>
        <p className="mt-1 break-all text-xs text-zinc-500">{row.original.path}</p>
      </div>
    )
  },
  {
    header: "Group",
    accessorKey: "group",
    cell: ({ row }) => <span className="text-zinc-700">{row.original.group}</span>
  },
  {
    header: "State",
    accessorKey: "state",
    cell: ({ row }) => <StateBadge state={row.original.state} />
  },
  {
    header: "Status",
    accessorKey: "summary",
    cell: ({ row }) => (
      <div>
        <p className="font-semibold text-zinc-900">{row.original.summary}</p>
        <p className="mt-1 line-clamp-2 text-xs text-zinc-500">{row.original.detail}</p>
      </div>
    )
  },
  {
    header: "Latency",
    accessorKey: "latencyMs",
    cell: ({ row }) => (
      <span className="font-mono text-sm text-zinc-700">
        {row.original.latencyMs === null ? "..." : `${row.original.latencyMs}ms`}
      </span>
    )
  }
];

function EndpointTable({ rows }: { rows: ProbeResult[] }): React.ReactElement {
  const table = useReactTable({
    data: rows,
    columns,
    getCoreRowModel: getCoreRowModel()
  });

  return (
    <Surface className="overflow-hidden">
      <div className="flex items-center justify-between gap-3 border-b border-zinc-200 px-4 py-3">
        <div>
          <h3 className="text-base font-bold text-zinc-950">Endpoint Matrix</h3>
          <p className="mt-1 text-sm text-zinc-500">Public and operator routes</p>
        </div>
        <Button variant="ghost" onClick={() => queryClient.invalidateQueries()}>
          <RefreshCcw className="size-4" aria-hidden="true" />
          Refresh
        </Button>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] border-collapse text-left">
          <thead className="bg-zinc-50 text-xs uppercase text-zinc-500">
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id}>
                {headerGroup.headers.map((header) => (
                  <th key={header.id} className="px-4 py-3 font-bold">
                    {flexRender(header.column.columnDef.header, header.getContext())}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody className="divide-y divide-zinc-100">
            {table.getRowModel().rows.map((row) => (
              <tr key={row.id} className="bg-white">
                {row.getVisibleCells().map((cell) => (
                  <td key={cell.id} className="px-4 py-4 align-top text-sm">
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Surface>
  );
}

function StateBadge({ state }: { state: ProbeResult["state"] }): React.ReactElement {
  const toneByState = {
    loading: "info",
    ok: "ok",
    off: "off",
    warn: "warn"
  } as const;

  return <Badge tone={toneByState[state]}>{state}</Badge>;
}
