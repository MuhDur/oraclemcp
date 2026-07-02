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
  Ban,
  BarChart3,
  CheckCircle2,
  Code2,
  Database,
  Download,
  FileClock,
  Gauge,
  GitPullRequest,
  KeyRound,
  Play,
  Radio,
  RefreshCcw,
  RotateCcw,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  SquarePen,
  Stethoscope,
  Timer,
  Users,
  Wifi
} from "lucide-react";

import { Badge, Button, Surface } from "../components/ui/primitives";
import { cn } from "../lib/utils";
import {
  BigBoardSurface,
  GROUND_CONTROL_SKIN,
  useDashboardCapabilities
} from "./skin";
import {
  CLEARANCE_LADDER,
  DASHBOARD_GRAMMAR,
  clampActivity,
  type FleetViewModel,
  type GoNoGoVerdict,
  type GroundControlViewModel,
  type HealthPosture,
  type SignatureViewModel
} from "./presentation-model";
import {
  auditProbes,
  applyChangeProposal,
  doctorProbes,
  draftChangeProposal,
  executeWorkbenchSql,
  applyConfigDraft,
  fetchActiveLanes,
  fetchClientCredentials,
  fetchDashboardSession,
  fetchChangeProposals,
  fetchOperatorConfig,
  fetchOperatorHealth,
  fetchOperatorMetrics,
  fetchProbe,
  overviewProbes,
  pendingProbe,
  previewConfigDraft,
  previewWorkbenchSql,
  readWorkbenchSql,
  revokeClientCredential,
  rotateClientCredential,
  runWorkbenchPlsqlTool,
  rollbackConfigDraft,
  setSessionLevel,
  type OperatorResponse,
  type ProbeDefinition,
  type ProbeResult,
  type AuditTailData,
  type AuditTailFilters,
  type AuditTailRecord,
  type ActiveLane,
  type CapacityLimitSource,
  type ChangeProposalApplyUnit,
  type ChangeProposalAuthorKind,
  type ChangeProposalView,
  type ClientCredentialRotateData,
  type ClientCredentialStatus,
  type ClientCredentialView,
  type ExplorerCacheStatus,
  type ExplorerDetailLevel,
  type ExplorerMetadataCacheKey,
  type ExplorerObjectRef,
  type LaneRequestDuration,
  type MetricsSnapshot,
  type OperatingLevel,
  type OperatorHealthData,
  type OperatorCapacityData,
  type OperatorEventEnvelope,
  type ConfigApplyData,
  type ConfigDraftPreview,
  type ConfigFieldChange,
  type ConfigOpsStatusData,
  sessionsProbes,
  cachedExplorerMetadata,
  clearExplorerMetadataCache,
  fetchAuditTail,
  fetchExplorerConnection,
  fetchExplorerDdl,
  fetchExplorerObjects,
  fetchExplorerSchemas,
  fetchExplorerSource,
  fetchExplorerSourceSearch,
  fetchLaneCapabilities,
  explorerMetadataCacheSummary,
  ORACLE_METADATA_SERIALIZATION_CONTRACT_VERSION,
  type WorkbenchActionData,
  type WorkbenchMode,
  type WorkbenchPlsqlTool
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
  { to: "/health", label: "Health", icon: CheckCircle2 },
  { to: "/capacity", label: "Capacity", icon: Gauge },
  { to: "/config", label: "Config", icon: SlidersHorizontal },
  { to: "/clients", label: "Clients", icon: KeyRound },
  { to: "/explorer", label: "Explorer", icon: Search },
  { to: "/reviews", label: "Reviews", icon: GitPullRequest },
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

const healthRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/health",
  component: HealthPage
});

const capacityRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/capacity",
  component: CapacityPage
});

const configRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/config",
  component: ConfigPage
});

const clientsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/clients",
  component: ClientsPage
});

const auditRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/audit",
  component: AuditPage
});

const explorerRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/explorer",
  component: ExplorerPage
});

const workbenchRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/workbench",
  component: WorkbenchPage
});

const reviewsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/reviews",
  component: ReviewsPage
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
    healthRoute,
    capacityRoute,
    configRoute,
    clientsRoute,
    explorerRoute,
    reviewsRoute,
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
  const skin = GROUND_CONTROL_SKIN;
  return (
    <div
      className={skin.layout.appShell}
      data-dashboard-skin={skin.name}
      data-dashboard-theme={skin.theme.name}
    >
      <div className={skin.layout.frame}>
        <aside className={skin.layout.sidebar}>
          <div className="flex items-center gap-3">
            <div className={skin.layout.logoMark}>
              <ShieldCheck className="size-5" aria-hidden="true" />
            </div>
            <div>
              <p className="text-xs font-semibold uppercase text-zinc-500">Ground Control</p>
              <h1 className="text-xl font-bold tracking-normal">oraclemcp</h1>
            </div>
          </div>
          <nav className={skin.layout.nav} aria-label="dashboard">
            {navItems.map((item) => (
              <NavLink key={item.to} item={item} skin={skin} />
            ))}
          </nav>
        </aside>
        <main className="min-w-0 flex-1 space-y-4">
          <GroundControlStrip />
          <Outlet />
        </main>
      </div>
    </div>
  );
}

function NavLink({
  item,
  skin
}: {
  item: NavItem;
  skin: typeof GROUND_CONTROL_SKIN;
}): React.ReactElement {
  const Icon = item.icon;
  return (
    <Link to={item.to} className={skin.layout.navLink}>
      <Icon className="size-4" aria-hidden="true" />
      <span>{item.label}</span>
    </Link>
  );
}

const logbookFilters: AuditTailFilters = {
  limit: 1,
  subjectIdHash: "",
  tool: "",
  dangerLevel: "",
  exportProofBundle: false
};

function GroundControlStrip(): React.ReactElement {
  const health = useQuery({
    queryKey: ["operator-health"],
    queryFn: fetchOperatorHealth,
    refetchInterval: 5_000
  });
  const metrics = useQuery({
    queryKey: ["operator-metrics"],
    queryFn: fetchOperatorMetrics,
    refetchInterval: 5_000
  });
  const logbook = useQuery({
    queryKey: ["audit-tail", "logbook"],
    queryFn: () => fetchAuditTail(logbookFilters),
    refetchInterval: 15_000
  });
  const readiness = health.data?.data.readiness;
  const go = readiness?.ready === true && readiness.db_reachable !== false;
  const snapshot = metrics.data?.data.snapshot ?? null;
  const activeLanes = snapshot?.active_lanes ?? 0;
  const blocked = sumCounts(snapshot?.lane_blocked ?? []);
  const chainStatus =
    nestedString(logbook.data?.data.proof, ["verification", "hash_chain", "status"]) ??
    logbook.data?.data.source ??
    "unavailable";
  const goValue: GoNoGoVerdict = health.isFetching && !health.data ? "SYNC" : go ? "GO" : "NO-GO";
  const model: GroundControlViewModel = {
    grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
    verdict: goValue,
    health: healthPosture(goValue, blocked),
    clearanceLadder: CLEARANCE_LADDER,
    clearanceStatus: {
      blocked,
      label: blocked > 0 ? "blocked" : "clear",
      tone: blocked > 0 ? "warn" : "ok"
    },
    signatures: [
      {
        id: "go_no_go",
        label: "GO/NO-GO",
        value: goValue,
        detail: readiness?.status ?? "unavailable",
        tone: go ? "ok" : health.isFetching ? "info" : "warn",
        activity: go ? 1 : 0
      },
      {
        id: "countdown",
        label: "Countdown",
        value: "idle",
        detail: `${formatNumber(activeLanes)} lanes`,
        tone: activeLanes > 0 ? "info" : "off",
        activity: activeLanes > 0 ? 0.5 : 0
      },
      {
        id: "logbook",
        label: "Logbook",
        value: chainStatus,
        detail: logbook.isFetching && !logbook.data ? "sync" : "audit",
        tone: chainStatus === "ok" ? "ok" : chainStatus === "broken" ? "warn" : "info",
        activity: logbook.isFetching ? 0.5 : 0
      }
    ] satisfies readonly SignatureViewModel[]
  };
  const GroundControl = GROUND_CONTROL_SKIN.renderers.GroundControl;
  return <GroundControl model={model} />;
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
  const reviews = useQuery({
    queryKey: ["change-proposals"],
    queryFn: fetchChangeProposals,
    refetchInterval: 15_000
  });
  const eventLog = useOperatorEventLog("operator");
  const snapshot = metrics.data?.data.snapshot ?? null;
  const lanes = activeLanes.data?.data.lanes ?? [];
  const pending = metrics.isFetching || activeLanes.isFetching;
  const capabilities = useDashboardCapabilities();
  const summary = overviewSummary(snapshot, lanes);
  const laneRows = laneMetricRows(snapshot, lanes);
  const fleet = fleetViewModel(summary, laneRows, pending);

  return (
    <PageFrame
      title="Overview"
      eyebrow="Mission Control"
      description="Runtime and operator protocol posture from the active service."
    >
      <div className="space-y-4">
        <BigBoardSurface capabilities={capabilities} model={fleet} skin={GROUND_CONTROL_SKIN} />
        <OverviewMetricTiles
          snapshot={snapshot}
          lanes={lanes}
          pending={pending}
        />
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(360px,0.85fr)]">
          <LaneMetricsPanel snapshot={snapshot} lanes={lanes} />
          <OperatorEventLogPanel status={eventLog.status} events={eventLog.events} />
        </div>
        <div className="grid gap-4 xl:grid-cols-[minmax(0,0.85fr)_minmax(360px,1.15fr)]">
          <ToolMetricsPanel snapshot={snapshot} />
          <OverviewReviewsPanel
            proposals={reviews.data?.data.proposals ?? []}
            pending={reviews.isFetching}
          />
        </div>
        <div className="grid gap-4 xl:grid-cols-[minmax(0,0.85fr)_minmax(360px,1.15fr)]">
          <ProbeDashboard probes={overviewProbes} compact />
          <Surface className="min-h-32 p-4">
            <div className="flex items-start justify-between gap-3">
              <p className="text-sm font-semibold text-zinc-600">Review Source</p>
              <Badge tone={reviews.isError ? "warn" : reviews.data ? "ok" : "info"}>
                {reviews.isError ? "blocked" : reviews.data ? "ready" : "sync"}
              </Badge>
            </div>
            <strong className="mt-5 block break-all font-mono text-sm leading-5 text-zinc-950">
              /operator/v1/change-proposals
            </strong>
          </Surface>
        </div>
      </div>
    </PageFrame>
  );
}

function SessionsPage(): React.ReactElement {
  const [selectedLaneId, setSelectedLaneId] = React.useState("");
  const [targetLevel, setTargetLevel] = React.useState<OperatingLevel>("READ_WRITE");
  const [ttlSeconds, setTtlSeconds] = React.useState(900);
  const [confirm, setConfirm] = React.useState("");
  const [lastResult, setLastResult] = React.useState<SessionLevelResult | null>(null);
  const capabilities = useDashboardCapabilities();
  const session = useQuery({
    queryKey: ["dashboard-session"],
    queryFn: fetchDashboardSession,
    staleTime: 60_000,
    refetchInterval: 60_000,
    retry: 1
  });
  const activeLanes = useQuery({
    queryKey: ["active-lanes"],
    queryFn: fetchActiveLanes,
    refetchInterval: 5_000
  });
  const metrics = useQuery({
    queryKey: ["operator-metrics"],
    queryFn: fetchOperatorMetrics,
    refetchInterval: 5_000
  });
  const lanes = activeLanes.data?.data.lanes ?? [];
  const selectedLane = lanes.find((lane) => lane.lane_id === selectedLaneId) ?? lanes[0] ?? null;
  const selectedLaneKey = selectedLane?.lane_id ?? "";
  const eventLog = useOperatorEventLog(selectedLaneKey || "operator");
  const selectedCapabilities = useQuery({
    queryKey: ["sessions", "capabilities", selectedLaneKey],
    queryFn: async () => {
      if (!session.data || !selectedLaneKey) {
        throw new Error("dashboard session is not ready");
      }
      return fetchLaneCapabilities(session.data, selectedLaneKey);
    },
    enabled: session.status === "success" && Boolean(selectedLaneKey),
    refetchInterval: 10_000,
    retry: 1
  });
  const selectedConnection = useQuery({
    queryKey: ["sessions", "connection", selectedLaneKey],
    queryFn: async () => {
      if (!session.data || !selectedLaneKey) {
        throw new Error("dashboard session is not ready");
      }
      return fetchExplorerConnection(session.data, selectedLaneKey);
    },
    enabled: session.status === "success" && Boolean(selectedLaneKey),
    refetchInterval: 10_000,
    retry: 1
  });

  React.useEffect(() => {
    if (!selectedLaneId && lanes.length > 0) {
      setSelectedLaneId(lanes[0].lane_id);
    }
  }, [lanes, selectedLaneId]);

  const levelMutation = useMutation({
    mutationFn: async (action: SessionLevelControlAction) => {
      if (!session.data) {
        throw new Error("dashboard session is not ready");
      }
      const laneId = selectedLane?.lane_id ?? selectedLaneId.trim();
      if (!laneId) {
        throw new Error("select an active lane");
      }
      return setSessionLevel(session.data, {
        laneId,
        level: targetLevel,
        ttlSeconds,
        confirm,
        action
      });
    },
    onSuccess: (response, action) => {
      setLastResult({ state: "ok", action, response });
      const nextConfirm = confirmationFromResponse(response);
      if (action === "preview") {
        setConfirm(nextConfirm ?? "");
      } else if (action === "apply" || action === "drop") {
        setConfirm("");
      }
      queryClient.invalidateQueries({ queryKey: ["active-lanes"] });
      queryClient.invalidateQueries({ queryKey: ["operator-metrics"] });
      queryClient.invalidateQueries({ queryKey: ["sessions", "capabilities", selectedLaneKey] });
    },
    onError: (error, action) => {
      setLastResult({
        state: "error",
        action,
        message: error instanceof Error ? error.message : "session level action failed"
      });
    }
  });

  const sessionTone =
    session.status === "success" ? "ok" : session.status === "error" ? "warn" : "info";
  const canAct = session.status === "success" && Boolean(selectedLane) && !levelMutation.isPending;
  const pending =
    activeLanes.isFetching ||
    metrics.isFetching ||
    session.isFetching ||
    selectedCapabilities.isFetching ||
    selectedConnection.isFetching ||
    levelMutation.isPending;
  const snapshot = metrics.data?.data.snapshot ?? null;
  const summary = overviewSummary(snapshot, lanes);
  const laneRows = sessionLaneRows(
    snapshot,
    lanes,
    selectedLaneKey,
    selectedCapabilities.data,
    selectedConnection.data
  );
  const fleet = fleetViewModel(summary, laneRows, pending);
  const groundControl = sessionGroundControlModel(summary, eventLog.status, pending);
  const selectedDetail = selectedLaneDetail(
    selectedLane,
    laneRows,
    selectedCapabilities.data,
    selectedConnection.data,
    selectedCapabilities.error instanceof Error ? selectedCapabilities.error.message : null,
    selectedConnection.error instanceof Error ? selectedConnection.error.message : null,
    eventLog.events
  );

  return (
    <PageFrame
      title="Sessions"
      eyebrow="Mission Control"
      description="Live lane state, activity, and per-lane clearance."
    >
      <div className="space-y-4">
        <SessionMissionHeader
          model={groundControl}
          summary={summary}
          eventStatus={eventLog.status}
          source={activeLanes.data?.data.source ?? "unavailable"}
          pending={pending}
        />
        <BigBoardSurface capabilities={capabilities} model={fleet} skin={GROUND_CONTROL_SKIN} />
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(360px,0.9fr)]">
          <SessionLaneTable
            rows={laneRows}
            selectedLaneId={selectedLane?.lane_id ?? selectedLaneId}
            pending={pending}
            onSelect={(laneId) => setSelectedLaneId(laneId)}
          />
          <div className="space-y-4">
            <SessionLaneDetailPanel detail={selectedDetail} />
            <SessionLevelControlPanel
              canAct={canAct}
              confirm={confirm}
              pending={pending}
              result={lastResult}
              selectedLane={selectedLane}
              sessionTone={sessionTone}
              targetLevel={targetLevel}
              ttlSeconds={ttlSeconds}
              onConfirmChange={setConfirm}
              onLevelChange={setTargetLevel}
              onTtlChange={setTtlSeconds}
              onAction={(action) => levelMutation.mutate(action)}
            />
          </div>
        </div>
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(360px,0.8fr)]">
          <OperatorEventLogPanel status={eventLog.status} events={eventLog.events} />
          <ProbeDashboard probes={sessionsProbes} compact />
        </div>
      </div>
    </PageFrame>
  );
}

type SessionLevelControlAction = "preview" | "apply" | "drop";

type SessionLevelResult =
  | {
      state: "ok";
      action: SessionLevelControlAction;
      response: OperatorResponse<WorkbenchActionData>;
    }
  | {
      state: "error";
      action: SessionLevelControlAction;
      message: string;
    };

const operatingLevels: OperatingLevel[] = ["READ_WRITE", "DDL", "ADMIN"];

type SessionLaneRow = LaneMetricRow & {
  generation: number;
  statusLabel: string;
  currentLevel: string;
  maxLevel: string;
  activeProfile: string;
  dbFingerprint: string;
  connected: string;
  selected: boolean;
};

type SessionLaneDetail = {
  laneId: string;
  subjectIdHash: string;
  generation: number;
  status: string;
  currentLevel: string;
  maxLevel: string;
  protectedProfile: string;
  activeProfile: string;
  dbFingerprint: string;
  visibleSchema: string;
  connected: string;
  connectionStrategy: string;
  serverVersion: string;
  databaseRole: string;
  openMode: string;
  requests: number;
  blocked: number;
  meanLatencyMs: number;
  maxLatencyMs: number;
  lastEvent: string;
  detailState: string;
};

type SessionCapabilitiesSummary = {
  currentLevel: string;
  maxLevel: string;
  protectedProfile: string;
  activeProfile: string;
  connected: string;
};

function SessionMissionHeader({
  model,
  summary,
  eventStatus,
  source,
  pending
}: {
  model: GroundControlViewModel;
  summary: OverviewSummary;
  eventStatus: EventStreamStatus;
  source: string;
  pending: boolean;
}): React.ReactElement {
  const GroundControl = GROUND_CONTROL_SKIN.renderers.GroundControl;
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(360px,0.9fr)_minmax(0,1.1fr)]">
      <GroundControl model={model} />
      <Surface className="overflow-hidden">
        <PanelHeader
          icon={Radio}
          title="Live Sessions"
          meta={pending ? "sync" : source}
          tone={pending ? "info" : summary.activeLanes > 0 ? "ok" : "off"}
        />
        <div className="grid gap-3 p-4 sm:grid-cols-2 xl:grid-cols-5">
          <CapacityFact label="Lanes" value={summary.activeLanes} />
          <CapacityFact label="Requests" value={summary.totalRequests} />
          <CapacityFact label="Blocked" value={summary.blocked} />
          <CapacityFact label="Errors" value={summary.errors} />
          <CapacityFact label="Events" value={eventStatus} mono />
        </div>
      </Surface>
    </div>
  );
}

function SessionLaneTable({
  rows,
  selectedLaneId,
  pending,
  onSelect
}: {
  rows: SessionLaneRow[];
  selectedLaneId: string;
  pending: boolean;
  onSelect: (laneId: string) => void;
}): React.ReactElement {
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={Database}
        title="Active Lanes"
        meta={pending ? "sync" : `${rows.length} lanes`}
        tone={pending ? "info" : rows.length > 0 ? "ok" : "off"}
      />
      <div className="overflow-x-auto">
        <table className="w-full min-w-[980px] border-collapse text-left">
          <thead className="bg-zinc-50 text-xs uppercase text-zinc-500">
            <tr>
              <th className="px-4 py-3 font-bold">Lane</th>
              <th className="px-4 py-3 font-bold">Agent</th>
              <th className="px-4 py-3 font-bold">Profile</th>
              <th className="px-4 py-3 font-bold">Level</th>
              <th className="px-4 py-3 font-bold">Activity</th>
              <th className="px-4 py-3 font-bold">Generation</th>
              <th className="px-4 py-3 font-bold">Detail</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-100">
            {rows.length === 0 ? (
              <tr>
                <td className="px-4 py-8 text-center text-sm font-semibold text-zinc-500" colSpan={7}>
                  No active lanes
                </td>
              </tr>
            ) : (
              rows.map((row) => {
                const selected = row.laneId === selectedLaneId;
                return (
                  <tr key={`${row.laneId}:${row.subjectIdHash}`} className={selected ? "bg-emerald-50" : "bg-white"}>
                    <td className="px-4 py-4 align-top font-mono text-sm font-semibold text-zinc-950">
                      <div className="flex flex-col gap-2">
                        <span>{row.laneId}</span>
                        <Badge tone={row.active ? "ok" : "off"}>{row.statusLabel}</Badge>
                      </div>
                    </td>
                    <td className="px-4 py-4 align-top">
                      <p className="max-w-[280px] break-all font-mono text-xs text-zinc-600">
                        {row.subjectIdHash}
                      </p>
                    </td>
                    <td className="px-4 py-4 align-top font-mono text-sm text-zinc-800">
                      <div className="max-w-[180px] break-all">{row.activeProfile}</div>
                      <p className="mt-1 max-w-[180px] break-all text-xs text-zinc-500">{row.dbFingerprint}</p>
                    </td>
                    <td className="px-4 py-4 align-top">
                      <span
                        className={cn(
                          "inline-flex rounded-md border px-2 py-1 font-mono text-xs font-bold",
                          sessionLevelBadgeClass(row.currentLevel)
                        )}
                      >
                        {row.currentLevel}
                      </span>
                      <p className="mt-1 font-mono text-xs text-zinc-500">max {row.maxLevel}</p>
                    </td>
                    <td className="px-4 py-4 align-top font-mono text-sm text-zinc-800">
                      <p>{formatNumber(row.requests)} req</p>
                      <p className="mt-1 text-xs text-zinc-500">
                        {formatNumber(row.blocked)} blocked · {Math.round(row.meanLatencyMs)} ms
                      </p>
                    </td>
                    <td className="px-4 py-4 align-top font-mono text-sm text-zinc-800">
                      {formatNumber(row.generation)}
                    </td>
                    <td className="px-4 py-4 align-top">
                      <Button
                        type="button"
                        variant={selected ? "primary" : "secondary"}
                        onClick={() => onSelect(row.laneId)}
                      >
                        <SlidersHorizontal className="size-4" aria-hidden="true" />
                        Expand
                      </Button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </Surface>
  );
}

function SessionLaneDetailPanel({
  detail
}: {
  detail: SessionLaneDetail | null;
}): React.ReactElement {
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={Activity}
        title="Lane Detail"
        meta={detail?.laneId ?? "no lane"}
        tone={detail ? "ok" : "off"}
      />
      <div className="grid gap-3 p-4 sm:grid-cols-2">
        <CapacityFact label="Lane" value={detail?.laneId ?? "none"} mono />
        <CapacityFact label="Agent" value={detail?.subjectIdHash ?? "none"} mono />
        <CapacityFact label="Profile" value={detail?.activeProfile ?? "unknown"} mono />
        <CapacityFact label="DB" value={detail?.dbFingerprint ?? "unknown"} mono />
        <CapacityFact label="Level" value={detail?.currentLevel ?? "unknown"} mono />
        <CapacityFact label="Ceiling" value={detail?.maxLevel ?? "unknown"} mono />
        <CapacityFact label="Protected" value={detail?.protectedProfile ?? "unknown"} mono />
        <CapacityFact label="Schema" value={detail?.visibleSchema ?? "unknown"} mono />
        <CapacityFact label="Connected" value={detail?.connected ?? "unknown"} mono />
        <CapacityFact label="Strategy" value={detail?.connectionStrategy ?? "unknown"} mono />
        <CapacityFact label="Server" value={detail?.serverVersion ?? "unknown"} mono />
        <CapacityFact label="Role" value={detail?.databaseRole ?? "unknown"} mono />
        <CapacityFact label="Open Mode" value={detail?.openMode ?? "unknown"} mono />
        <CapacityFact label="Requests" value={detail?.requests ?? 0} />
        <CapacityFact label="Blocked" value={detail?.blocked ?? 0} />
        <CapacityFact label="Mean Latency" value={`${Math.round(detail?.meanLatencyMs ?? 0)} ms`} mono />
        <CapacityFact label="Max Latency" value={`${Math.round(detail?.maxLatencyMs ?? 0)} ms`} mono />
        <CapacityFact label="Last Event" value={detail?.lastEvent ?? "none"} mono />
        <CapacityFact label="Detail State" value={detail?.detailState ?? "unknown"} mono />
      </div>
    </Surface>
  );
}

function SessionLevelControlPanel({
  canAct,
  confirm,
  pending,
  result,
  selectedLane,
  sessionTone,
  targetLevel,
  ttlSeconds,
  onConfirmChange,
  onLevelChange,
  onTtlChange,
  onAction
}: {
  canAct: boolean;
  confirm: string;
  pending: boolean;
  result: SessionLevelResult | null;
  selectedLane: ActiveLane | null;
  sessionTone: "neutral" | "ok" | "warn" | "off" | "info";
  targetLevel: OperatingLevel;
  ttlSeconds: number;
  onConfirmChange: (value: string) => void;
  onLevelChange: (value: OperatingLevel) => void;
  onTtlChange: (value: number) => void;
  onAction: (action: SessionLevelControlAction) => void;
}): React.ReactElement {
  const summary = result?.state === "ok" ? sessionLevelSummary(result.response) : null;
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={ShieldCheck}
        title="Operating Level"
        meta={selectedLane?.lane_id ?? "no lane"}
        tone={pending ? "info" : selectedLane ? sessionTone : "off"}
      />
      <div className="space-y-4 p-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <CapacityFact label="Lane" value={selectedLane?.lane_id ?? "none"} mono />
          <CapacityFact label="Generation" value={selectedLane?.generation ?? 0} />
          <CapacityFact label="Current" value={summary?.currentLevel ?? "unknown"} mono />
          <CapacityFact label="Ceiling" value={summary?.profileCeiling ?? "unknown"} mono />
        </div>
        <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_140px]">
          <label className="block">
            <span className="mb-2 block text-sm font-bold text-zinc-700">Target</span>
            <select
              className="h-10 w-full rounded-md border border-zinc-300 bg-white px-3 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
              value={targetLevel}
              onChange={(event) => onLevelChange(event.target.value as OperatingLevel)}
            >
              {operatingLevels.map((level) => (
                <option key={level} value={level}>
                  {level}
                </option>
              ))}
            </select>
          </label>
          <label className="block">
            <span className="mb-2 block text-sm font-bold text-zinc-700">TTL</span>
            <input
              className="h-10 w-full rounded-md border border-zinc-300 px-3 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
              type="number"
              min={1}
              max={3600}
              value={ttlSeconds}
              onChange={(event) => onTtlChange(clampTtl(event.target.valueAsNumber))}
            />
          </label>
        </div>
        <label className="block">
          <span className="mb-2 block text-sm font-bold text-zinc-700">Confirm</span>
          <input
            className="h-10 w-full rounded-md border border-zinc-300 px-3 font-mono text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
            value={confirm}
            onChange={(event) => onConfirmChange(event.target.value)}
            placeholder="preview grant"
          />
        </label>
        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="secondary" disabled={!canAct} onClick={() => onAction("preview")}>
            <Search className="size-4" aria-hidden="true" />
            Preview
          </Button>
          <Button
            type="button"
            variant="primary"
            disabled={!canAct || confirm.trim().length === 0}
            onClick={() => onAction("apply")}
          >
            <CheckCircle2 className="size-4" aria-hidden="true" />
            Elevate
          </Button>
          <Button type="button" variant="secondary" disabled={!canAct} onClick={() => onAction("drop")}>
            <RotateCcw className="size-4" aria-hidden="true" />
            Drop
          </Button>
        </div>
        {summary ? <SessionLevelSummaryPanel summary={summary} /> : null}
        {result?.state === "error" ? (
          <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm font-semibold text-amber-900">
            {result.message}
          </div>
        ) : null}
      </div>
    </Surface>
  );
}

type SessionLevelSummary = {
  action: string;
  preview: string;
  targetLevel: string;
  ttlSeconds: string;
  currentLevel: string;
  profileCeiling: string;
  gateDecision: string;
  confirm: string;
};

function SessionLevelSummaryPanel({
  summary
}: {
  summary: SessionLevelSummary;
}): React.ReactElement {
  return (
    <div className="grid gap-2 sm:grid-cols-2">
      <CapacityFact label="Action" value={summary.action} mono />
      <CapacityFact label="Preview" value={summary.preview} mono />
      <CapacityFact label="Target" value={summary.targetLevel} mono />
      <CapacityFact label="TTL" value={summary.ttlSeconds} mono />
      <CapacityFact label="Gate" value={summary.gateDecision} mono />
      <CapacityFact label="Confirm" value={summary.confirm} mono />
    </div>
  );
}

function HealthPage(): React.ReactElement {
  const health = useQuery({
    queryKey: ["operator-health"],
    queryFn: fetchOperatorHealth,
    refetchInterval: 5_000
  });
  const metrics = useQuery({
    queryKey: ["operator-metrics"],
    queryFn: fetchOperatorMetrics,
    refetchInterval: 5_000
  });
  const session = useQuery({
    queryKey: ["dashboard-session"],
    queryFn: fetchDashboardSession,
    staleTime: 60_000,
    refetchInterval: 60_000,
    retry: 1
  });
  const connection = useQuery({
    queryKey: ["health", "connection"],
    queryFn: async () => {
      if (!session.data) {
        throw new Error("dashboard session is not ready");
      }
      return fetchExplorerConnection(session.data);
    },
    enabled: session.status === "success",
    refetchInterval: 10_000,
    retry: 1
  });
  const model = connectionHealthModel(
    health.data?.data ?? null,
    metrics.data?.data.snapshot ?? null,
    connection.data,
    connection.error instanceof Error
      ? connection.error.message
      : session.error instanceof Error
        ? session.error.message
        : null
  );
  const pending = health.isFetching || metrics.isFetching || connection.isFetching;

  return (
    <PageFrame
      title="Health"
      eyebrow="Connection"
      description="Process readiness, pool latency, and redacted live database posture."
    >
      <div className="space-y-4">
        <HealthStatusTiles model={model} pending={pending} />
        <div className="grid gap-4 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
          <ServiceReadinessPanel model={model} />
          <DbNativeStatusPanel model={model} />
        </div>
        <div className="grid gap-4 xl:grid-cols-[minmax(0,0.8fr)_minmax(0,1.2fr)]">
          <PoolLatencyPanel model={model} />
          <HealthSourcePanel rows={model.sources} />
        </div>
      </div>
    </PageFrame>
  );
}

type ConnectionHealthSourceRow = {
  key: string;
  source: string;
  status: string;
  detail: string;
};

type ConnectionNativeInfo = {
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

type ConnectionHealthUiModel = {
  readiness: {
    liveness: string;
    readiness: string;
    live: boolean;
    ready: boolean;
    dbReachable: boolean;
    draining: boolean;
  };
  pool: {
    active: number;
    waitMeanMs: number;
    waitMaxMs: number;
    queryMeanMs: number;
    queryMaxMs: number;
  };
  db: ConnectionNativeInfo;
  sources: ConnectionHealthSourceRow[];
};

function HealthStatusTiles({
  model,
  pending
}: {
  model: ConnectionHealthUiModel;
  pending: boolean;
}): React.ReactElement {
  return (
    <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-4" aria-label="connection health">
      <HealthStatusTile
        icon={Activity}
        label="Liveness"
        value={model.readiness.liveness}
        meta={model.readiness.live ? "live" : "not live"}
        tone={model.readiness.live ? "ok" : "warn"}
        pending={pending}
      />
      <HealthStatusTile
        icon={CheckCircle2}
        label="Readiness"
        value={model.readiness.readiness}
        meta={model.readiness.ready ? "ready" : "unavailable"}
        tone={model.readiness.ready ? "ok" : "warn"}
        pending={pending}
      />
      <HealthStatusTile
        icon={Database}
        label="DB native"
        value={model.db.connected ? "connected" : "degraded"}
        meta={model.db.source}
        tone={model.db.connected ? "ok" : "info"}
        pending={pending}
      />
      <HealthStatusTile
        icon={ShieldCheck}
        label="Write posture"
        value={model.db.writePosture}
        meta={model.db.openMode}
        tone={model.db.writePosture === "database_read_only" ? "ok" : "info"}
        pending={pending}
      />
    </section>
  );
}

function ServiceReadinessPanel({ model }: { model: ConnectionHealthUiModel }): React.ReactElement {
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={Activity}
        title="Service Readiness"
        meta={model.readiness.ready ? "ready" : "unavailable"}
        tone={model.readiness.ready ? "ok" : "warn"}
      />
      <div className="grid gap-3 p-4 sm:grid-cols-2">
        <CapacityFact label="Liveness" value={model.readiness.liveness} mono />
        <CapacityFact label="Readiness" value={model.readiness.readiness} mono />
        <CapacityFact label="DB reachable" value={model.readiness.dbReachable ? "true" : "false"} mono />
        <CapacityFact label="Draining" value={model.readiness.draining ? "true" : "false"} mono />
      </div>
    </Surface>
  );
}

function DbNativeStatusPanel({ model }: { model: ConnectionHealthUiModel }): React.ReactElement {
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={Database}
        title="DB Native Status"
        meta={model.db.connected ? model.db.activeProfile : model.db.source}
        tone={model.db.connected ? "ok" : "info"}
      />
      <div className="grid gap-3 p-4 sm:grid-cols-3">
        <CapacityFact label="Role" value={model.db.databaseRole} mono />
        <CapacityFact label="Open mode" value={model.db.openMode} mono />
        <CapacityFact label="Standby" value={model.db.standby} mono />
        <CapacityFact label="Strategy" value={model.db.strategy} mono />
        <CapacityFact label="Pool open" value={model.db.poolOpenConnections ?? "unavailable"} />
        <CapacityFact label="Server" value={model.db.serverVersion} mono />
        <CapacityFact label="Profile" value={model.db.activeProfile} mono />
        <CapacityFact label="Read-only" value={model.db.readOnlyReason} mono />
        <CapacityFact label="Error" value={model.db.error} mono />
      </div>
    </Surface>
  );
}

function PoolLatencyPanel({ model }: { model: ConnectionHealthUiModel }): React.ReactElement {
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={Timer}
        title="Pool And Latency"
        meta={`${formatNumber(model.pool.active)} active`}
        tone={model.pool.waitMeanMs > 500 || model.pool.queryMeanMs > 500 ? "warn" : "ok"}
      />
      <div className="grid gap-3 p-4 sm:grid-cols-2">
        <CapacityFact label="Pool active" value={model.pool.active} />
        <CapacityFact label="Pool wait avg" value={`${formatNumber(model.pool.waitMeanMs)}ms`} mono />
        <CapacityFact label="Pool wait max" value={`${formatNumber(model.pool.waitMaxMs)}ms`} mono />
        <CapacityFact label="Query avg" value={`${formatNumber(model.pool.queryMeanMs)}ms`} mono />
        <CapacityFact label="Query max" value={`${formatNumber(model.pool.queryMaxMs)}ms`} mono />
      </div>
    </Surface>
  );
}

function HealthSourcePanel({
  rows
}: {
  rows: ConnectionHealthSourceRow[];
}): React.ReactElement {
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={Gauge}
        title="Health Sources"
        meta={`${rows.length} sources`}
        tone={rows.some((row) => row.status === "monitoring_unavailable") ? "info" : "ok"}
      />
      <div className="overflow-x-auto">
        <table className="w-full min-w-[680px] border-collapse text-left">
          <thead className="bg-zinc-50 text-xs uppercase text-zinc-500">
            <tr>
              <th className="px-4 py-3 font-bold">Source</th>
              <th className="px-4 py-3 font-bold">Status</th>
              <th className="px-4 py-3 font-bold">Detail</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-100">
            {rows.map((row) => (
              <tr key={row.key} className="bg-white">
                <td className="px-4 py-4 align-top font-mono text-sm font-semibold text-zinc-950">
                  {row.source}
                </td>
                <td className="px-4 py-4 align-top">
                  <Badge tone={limitStatusTone(row.status)}>{row.status}</Badge>
                </td>
                <td className="px-4 py-4 align-top text-sm text-zinc-600">{row.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Surface>
  );
}

function HealthStatusTile({
  icon: Icon,
  label,
  value,
  meta,
  tone,
  pending
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string;
  meta: string;
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
      <strong className="mt-2 block truncate text-2xl leading-tight text-zinc-950">{value}</strong>
      <p className="mt-2 truncate font-mono text-xs text-zinc-500">{meta}</p>
    </Surface>
  );
}

function CapacityPage(): React.ReactElement {
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
  const snapshot = metrics.data?.data.snapshot ?? null;
  const capacity = metrics.data?.data.capacity ?? null;
  const lanes = activeLanes.data?.data.lanes ?? [];
  const pending = metrics.isFetching || activeLanes.isFetching;
  const model = capacityModel(capacity, snapshot, lanes);

  return (
    <PageFrame
      title="Capacity"
      eyebrow="Admission"
      description="Effective read-pool and stateful-lane ceilings from the operator service."
    >
      <div className="space-y-4">
        <CapacityMetricTiles model={model} pending={pending} />
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <ReadPoolCapacityPanel model={model} />
          <StatefulCapacityPanel model={model} />
        </div>
        <div className="grid gap-4 xl:grid-cols-[minmax(320px,0.6fr)_minmax(0,1.4fr)]">
          <AtCapacityPanel model={model} />
          <CapacityLimitSourcesPanel rows={model.limitRows} />
        </div>
      </div>
    </PageFrame>
  );
}

function ConfigPage(): React.ReactElement {
  const [draftToml, setDraftToml] = React.useState("");
  const [preview, setPreview] = React.useState<ConfigDraftPreview | null>(null);
  const [applyOutcome, setApplyOutcome] = React.useState<ConfigApplyData | null>(null);
  const [lastError, setLastError] = React.useState<string | null>(null);
  const session = useQuery({
    queryKey: ["dashboard-session"],
    queryFn: fetchDashboardSession,
    staleTime: 60_000,
    refetchInterval: 60_000,
    retry: 1
  });
  const config = useQuery({
    queryKey: ["operator-config"],
    queryFn: fetchOperatorConfig,
    refetchInterval: 10_000
  });
  const status = config.data?.data ?? null;
  const activePreview = preview;
  const previewMutation = useMutation({
    mutationFn: async () => {
      if (!session.data) {
        throw new Error("dashboard session is not ready");
      }
      return previewConfigDraft(session.data, draftToml);
    },
    onSuccess: (response) => {
      setPreview(response.data.preview);
      setApplyOutcome(null);
      setLastError(null);
    },
    onError: (error) => {
      setLastError(error instanceof Error ? error.message : "preview failed");
    }
  });
  const applyMutation = useMutation({
    mutationFn: async () => {
      if (!session.data) {
        throw new Error("dashboard session is not ready");
      }
      const expected =
        activePreview?.current_sha256 ?? status?.status.current_sha256 ?? "";
      return applyConfigDraft(session.data, draftToml, expected);
    },
    onSuccess: (response) => {
      setApplyOutcome(response.data);
      setPreview(null);
      setLastError(null);
      queryClient.invalidateQueries({ queryKey: ["operator-config"] });
    },
    onError: (error) => {
      setLastError(error instanceof Error ? error.message : "apply failed");
    }
  });
  const rollbackMutation = useMutation({
    mutationFn: async (rollbackId: string) => {
      if (!session.data) {
        throw new Error("dashboard session is not ready");
      }
      return rollbackConfigDraft(session.data, rollbackId);
    },
    onSuccess: () => {
      setApplyOutcome(null);
      setPreview(null);
      setLastError(null);
      queryClient.invalidateQueries({ queryKey: ["operator-config"] });
    },
    onError: (error) => {
      setLastError(error instanceof Error ? error.message : "rollback failed");
    }
  });
  const canSubmit = draftToml.trim().length > 0 && session.status === "success";
  const busy =
    previewMutation.isPending || applyMutation.isPending || rollbackMutation.isPending;

  return (
    <PageFrame
      title="Config"
      eyebrow="Profiles"
      description="Redacted draft/apply workflow for the service profile file."
    >
      <div className="space-y-4">
        <ConfigStatusPanel data={status} pending={config.isFetching} />
        <Surface className="overflow-hidden">
          <PanelHeader
            icon={SlidersHorizontal}
            title="Draft"
            meta={session.status === "success" ? "session ready" : "session pending"}
            tone={session.status === "success" ? "ok" : "info"}
          />
          <div className="space-y-3 p-4">
            <textarea
              value={draftToml}
              onChange={(event) => setDraftToml(event.target.value)}
              spellCheck={false}
              className="min-h-72 w-full resize-y rounded-md border border-zinc-300 bg-white p-3 font-mono text-sm leading-6 text-zinc-950 outline-none focus:border-zinc-500 focus:ring-2 focus:ring-zinc-200"
              aria-label="Config draft TOML"
            />
            <div className="flex flex-wrap items-center gap-2">
              <Button
                type="button"
                variant="secondary"
                disabled={!canSubmit || busy}
                onClick={() => previewMutation.mutate()}
              >
                <RefreshCcw className="size-4" aria-hidden="true" />
                Preview
              </Button>
              <Button
                type="button"
                variant="primary"
                disabled={!canSubmit || busy}
                onClick={() => applyMutation.mutate()}
              >
                <Play className="size-4" aria-hidden="true" />
                Apply
              </Button>
              {applyOutcome ? (
                <Button
                  type="button"
                  variant="secondary"
                  disabled={busy}
                  onClick={() => rollbackMutation.mutate(applyOutcome.outcome.rollback_id)}
                >
                  <RotateCcw className="size-4" aria-hidden="true" />
                  Rollback
                </Button>
              ) : null}
              {lastError ? (
                <Badge tone="warn" className="max-w-full whitespace-normal break-all">
                  {lastError}
                </Badge>
              ) : null}
            </div>
          </div>
        </Surface>
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,0.8fr)]">
          <ConfigDiffPanel preview={preview} />
          <ConfigApplyPanel preview={preview} outcome={applyOutcome} />
        </div>
      </div>
    </PageFrame>
  );
}

function ConfigStatusPanel({
  data,
  pending
}: {
  data: ConfigOpsStatusData | null;
  pending: boolean;
}): React.ReactElement {
  const status = data?.status;
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={Database}
        title="Current Target"
        meta={status?.target_exists ? "configured" : "new file"}
        tone={pending ? "info" : status ? "ok" : "warn"}
      />
      <div className="grid gap-3 p-4 md:grid-cols-2 xl:grid-cols-4">
        <CapacityFact label="Target" value={status?.target_path ?? "unavailable"} mono />
        <CapacityFact label="Current SHA" value={shortHash(status?.current_sha256 ?? null)} mono />
        <CapacityFact label="Default" value={status?.default_profile ?? "none"} mono />
        <CapacityFact label="Profiles" value={status?.profiles.length ?? 0} />
      </div>
    </Surface>
  );
}

function ConfigDiffPanel({
  preview
}: {
  preview: ConfigDraftPreview | null;
}): React.ReactElement {
  const changes = preview?.redacted_diff.changes ?? [];
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={FileClock}
        title="Redacted Diff"
        meta={`${changes.length} changes`}
        tone={changes.length > 0 ? "info" : "off"}
      />
      <div className="overflow-x-auto">
        <table className="w-full min-w-[720px] border-collapse text-left">
          <thead className="bg-zinc-50 text-xs uppercase text-zinc-500">
            <tr>
              <th className="px-4 py-3 font-bold">Path</th>
              <th className="px-4 py-3 font-bold">Before</th>
              <th className="px-4 py-3 font-bold">After</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-100">
            {changes.length === 0 ? (
              <tr>
                <td className="px-4 py-4 text-sm text-zinc-500" colSpan={3}>
                  No preview
                </td>
              </tr>
            ) : (
              changes.map((change) => <ConfigDiffRow key={change.path} change={change} />)
            )}
          </tbody>
        </table>
      </div>
    </Surface>
  );
}

function ConfigDiffRow({ change }: { change: ConfigFieldChange }): React.ReactElement {
  return (
    <tr className="bg-white">
      <td className="px-4 py-4 align-top font-mono text-sm font-semibold text-zinc-950">
        {change.path}
      </td>
      <td className="px-4 py-4 align-top font-mono text-xs text-zinc-600">
        {compactJson(change.before)}
      </td>
      <td className="px-4 py-4 align-top font-mono text-xs text-zinc-600">
        {compactJson(change.after)}
      </td>
    </tr>
  );
}

function ConfigApplyPanel({
  preview,
  outcome
}: {
  preview: ConfigDraftPreview | null;
  outcome: ConfigApplyData | null;
}): React.ReactElement {
  const plan = outcome?.outcome.apply.reload_plan ?? preview?.reload_plan ?? null;
  const currentHash = preview?.current_sha256 ?? outcome?.outcome.apply.backup_sha256 ?? null;
  const draftHash = preview?.draft_sha256 ?? outcome?.outcome.apply.applied_sha256 ?? null;
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={ShieldCheck}
        title="Reload Plan"
        meta={outcome?.outcome.reload.status ?? (plan?.hot_reloadable ? "hot" : "restart")}
        tone={outcome ? reloadTone(outcome.outcome.reload.status) : plan?.hot_reloadable ? "ok" : "info"}
      />
      <div className="space-y-3 p-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <CapacityFact label="Current" value={shortHash(currentHash)} mono />
          <CapacityFact label="Draft" value={shortHash(draftHash)} mono />
          <CapacityFact label="Backup" value={outcome?.outcome.apply.backup_path ?? "pending"} mono />
          <CapacityFact label="Rollback" value={outcome?.outcome.rollback_id ?? "pending"} mono />
        </div>
        {plan ? (
          <div className="space-y-2">
            {plan.restart_required.length > 0 ? (
              <Badge tone="info">{plan.restart_required.join(", ")}</Badge>
            ) : (
              <Badge tone="ok">hot_reloadable</Badge>
            )}
            <div className="overflow-x-auto">
              <table className="w-full min-w-[420px] border-collapse text-left">
                <thead className="bg-zinc-50 text-xs uppercase text-zinc-500">
                  <tr>
                    <th className="px-3 py-2 font-bold">Profile</th>
                    <th className="px-3 py-2 font-bold">Action</th>
                    <th className="px-3 py-2 font-bold">Reason</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-100">
                  {plan.profiles.map((decision) => (
                    <tr key={decision.profile}>
                      <td className="px-3 py-3 font-mono text-sm font-semibold text-zinc-950">
                        {decision.profile}
                      </td>
                      <td className="px-3 py-3">
                        <Badge tone={decision.action === "drain" ? "warn" : "ok"}>
                          {decision.action}
                        </Badge>
                      </td>
                      <td className="px-3 py-3 font-mono text-xs text-zinc-600">
                        {decision.reason}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          <p className="text-sm text-zinc-500">No preview</p>
        )}
      </div>
    </Surface>
  );
}

function ClientsPage(): React.ReactElement {
  const [rotated, setRotated] = React.useState<ClientCredentialRotateData | null>(null);
  const [lastError, setLastError] = React.useState<string | null>(null);
  const session = useQuery({
    queryKey: ["dashboard-session"],
    queryFn: fetchDashboardSession,
    staleTime: 60_000,
    refetchInterval: 60_000,
    retry: 1
  });
  const clients = useQuery({
    queryKey: ["client-credentials"],
    queryFn: fetchClientCredentials,
    refetchInterval: 10_000
  });
  const rotateMutation = useMutation({
    mutationFn: async (client: ClientCredentialView) => {
      if (!session.data) {
        throw new Error("dashboard session is not ready");
      }
      return rotateClientCredential(session.data, client.client_id);
    },
    onSuccess: (response) => {
      setRotated(response.data);
      setLastError(null);
      queryClient.invalidateQueries({ queryKey: ["client-credentials"] });
    },
    onError: (error) => {
      setLastError(error instanceof Error ? error.message : "rotate failed");
    }
  });
  const revokeMutation = useMutation({
    mutationFn: async (client: ClientCredentialView) => {
      if (!session.data) {
        throw new Error("dashboard session is not ready");
      }
      return revokeClientCredential(session.data, client.client_id);
    },
    onSuccess: () => {
      setLastError(null);
      queryClient.invalidateQueries({ queryKey: ["client-credentials"] });
    },
    onError: (error) => {
      setLastError(error instanceof Error ? error.message : "revoke failed");
    }
  });
  const rows = clients.data?.data.clients ?? [];
  const busy = rotateMutation.isPending || revokeMutation.isPending;

  return (
    <PageFrame
      title="Clients"
      eyebrow="HTTP Auth"
      description="Service-owned MCP client credentials and their current lifecycle state."
    >
      <div className="space-y-4">
        <ClientCredentialSummary
          rows={rows}
          pending={clients.isFetching}
          source={clients.data?.data.source ?? (clients.isError ? "unavailable" : "pending")}
        />
        {rotated ? (
          <ClientCredentialBearerPanel rotated={rotated} onDismiss={() => setRotated(null)} />
        ) : null}
        <ClientCredentialTable
          rows={rows}
          sessionReady={session.status === "success"}
          pending={clients.isFetching}
          busy={busy}
          rotatingClientId={rotateMutation.variables?.client_id ?? null}
          revokingClientId={revokeMutation.variables?.client_id ?? null}
          onRotate={(client) => rotateMutation.mutate(client)}
          onRevoke={(client) => revokeMutation.mutate(client)}
        />
        {lastError || clients.isError ? (
          <Badge tone="warn" className="max-w-full whitespace-normal break-all">
            {lastError ?? (clients.error instanceof Error ? clients.error.message : "client credentials unavailable")}
          </Badge>
        ) : null}
      </div>
    </PageFrame>
  );
}

function ClientCredentialSummary({
  rows,
  pending,
  source
}: {
  rows: ClientCredentialView[];
  pending: boolean;
  source: string;
}): React.ReactElement {
  const active = rows.filter((client) => client.status === "active").length;
  const revoked = rows.filter((client) => client.status === "revoked").length;
  const used = rows.filter((client) => Boolean(client.last_used_at)).length;
  return (
    <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-4" aria-label="client credentials">
      <MetricTile icon={KeyRound} label="Registered" value={rows.length} suffix="" tone={rows.length > 0 ? "ok" : "off"} pending={pending} />
      <MetricTile icon={ShieldCheck} label="Active" value={active} suffix="" tone={active > 0 ? "ok" : "off"} pending={pending} />
      <MetricTile icon={Ban} label="Revoked" value={revoked} suffix="" tone={revoked > 0 ? "warn" : "ok"} pending={pending} />
      <MetricTile icon={Wifi} label="Used" value={used} suffix="" tone={source === "client_credentials" ? "info" : "off"} pending={pending} />
    </section>
  );
}

function ClientCredentialBearerPanel({
  rotated,
  onDismiss
}: {
  rotated: ClientCredentialRotateData;
  onDismiss: () => void;
}): React.ReactElement {
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={KeyRound}
        title="Rotated Bearer"
        meta={rotated.client.client_id}
        tone={rotated.bearer_shown_once ? "ok" : "warn"}
      />
      <div className="space-y-3 p-4">
        <div className="grid gap-3 sm:grid-cols-3">
          <CapacityFact label="Generation" value={rotated.client.generation} />
          <CapacityFact label="Closed" value={rotated.closed_sessions} />
          <CapacityFact label="Subject" value={shortHash(rotated.closed_principal.subject_id_hash)} mono />
        </div>
        <pre className="max-h-32 overflow-auto rounded-md bg-zinc-950 p-3 font-mono text-xs leading-5 text-zinc-50">
          {rotated.bearer}
        </pre>
        <Button type="button" variant="secondary" onClick={onDismiss}>
          <Ban className="size-4" aria-hidden="true" />
          Clear
        </Button>
      </div>
    </Surface>
  );
}

function ClientCredentialTable({
  rows,
  sessionReady,
  pending,
  busy,
  rotatingClientId,
  revokingClientId,
  onRotate,
  onRevoke
}: {
  rows: ClientCredentialView[];
  sessionReady: boolean;
  pending: boolean;
  busy: boolean;
  rotatingClientId: string | null;
  revokingClientId: string | null;
  onRotate: (client: ClientCredentialView) => void;
  onRevoke: (client: ClientCredentialView) => void;
}): React.ReactElement {
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={Users}
        title="Registered Clients"
        meta={`${rows.length} clients`}
        tone={pending ? "info" : rows.length > 0 ? "ok" : "off"}
      />
      <div className="overflow-x-auto">
        <table className="w-full min-w-[940px] border-collapse text-left">
          <thead className="bg-zinc-50 text-xs uppercase text-zinc-500">
            <tr>
              <th className="px-4 py-3 font-bold">Client</th>
              <th className="px-4 py-3 font-bold">Status</th>
              <th className="px-4 py-3 font-bold">Scopes</th>
              <th className="px-4 py-3 font-bold">Subject</th>
              <th className="px-4 py-3 font-bold">Last Used</th>
              <th className="px-4 py-3 font-bold">Source</th>
              <th className="px-4 py-3 font-bold">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-100">
            {rows.length === 0 ? (
              <tr>
                <td className="px-4 py-4 text-sm text-zinc-500" colSpan={7}>
                  No registered clients
                </td>
              </tr>
            ) : (
              rows.map((client) => (
                <ClientCredentialRow
                  key={client.client_id}
                  client={client}
                  sessionReady={sessionReady}
                  busy={busy}
                  rotating={rotatingClientId === client.client_id}
                  revoking={revokingClientId === client.client_id}
                  onRotate={onRotate}
                  onRevoke={onRevoke}
                />
              ))
            )}
          </tbody>
        </table>
      </div>
    </Surface>
  );
}

function ClientCredentialRow({
  client,
  sessionReady,
  busy,
  rotating,
  revoking,
  onRotate,
  onRevoke
}: {
  client: ClientCredentialView;
  sessionReady: boolean;
  busy: boolean;
  rotating: boolean;
  revoking: boolean;
  onRotate: (client: ClientCredentialView) => void;
  onRevoke: (client: ClientCredentialView) => void;
}): React.ReactElement {
  const disabled = busy || !sessionReady || client.status !== "active";
  return (
    <tr className="bg-white">
      <td className="px-4 py-4 align-top">
        <p className="font-mono text-sm font-semibold text-zinc-950">{client.client_id}</p>
        <p className="mt-1 truncate text-xs text-zinc-500">{client.label}</p>
      </td>
      <td className="px-4 py-4 align-top">
        <Badge tone={clientCredentialStatusTone(client.status)}>{client.status}</Badge>
        <p className="mt-2 font-mono text-xs text-zinc-500">gen {client.generation}</p>
      </td>
      <td className="px-4 py-4 align-top">
        <div className="flex flex-wrap gap-1">
          {client.scopes.map((scope) => (
            <Badge key={scope} tone="neutral">{scope}</Badge>
          ))}
        </div>
      </td>
      <td className="px-4 py-4 align-top font-mono text-xs text-zinc-600">
        {shortHash(client.subject_id_hash)}
      </td>
      <td className="px-4 py-4 align-top font-mono text-xs text-zinc-600">
        {client.last_used_at ?? "never"}
      </td>
      <td className="px-4 py-4 align-top font-mono text-xs text-zinc-600">
        {client.last_source_addr ?? "unseen"}
      </td>
      <td className="px-4 py-4 align-top">
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            variant="secondary"
            disabled={disabled}
            onClick={() => onRotate(client)}
          >
            <RotateCcw className="size-4" aria-hidden="true" />
            {rotating ? "Rotating" : "Rotate"}
          </Button>
          <Button
            type="button"
            variant="secondary"
            disabled={disabled}
            onClick={() => onRevoke(client)}
          >
            <Ban className="size-4" aria-hidden="true" />
            {revoking ? "Revoking" : "Revoke"}
          </Button>
        </div>
      </td>
    </tr>
  );
}

function clientCredentialStatusTone(
  status: ClientCredentialStatus
): "neutral" | "ok" | "warn" | "off" | "info" {
  return status === "active" ? "ok" : "off";
}

type CapacityLimitRow = {
  key: string;
  scope: "read_pool" | "stateful_lanes";
  source: CapacityLimitSource;
};

type CapacityUiModel = {
  read: {
    source: string;
    configured: number;
    effective: number;
    active: number;
  };
  stateful: {
    source: string;
    configuredGlobal: number;
    configuredPerSubject: number;
    effectiveGlobal: number;
    effectiveRegular: number;
    regularAvailable: number;
    regularInUse: number;
    active: number;
    perSubjectCap: number;
    perSubjectAvailable: number;
    operatorReserve: number;
    doctorReserve: number;
  };
  atCapacityEvents: number;
  retryAfterMs: number;
  idleReaping: {
    enabled: boolean;
    ttlSeconds: number;
  };
  limitRows: CapacityLimitRow[];
};

const CAPACITY_DEFAULTS = {
  readPerProfile: 16,
  statefulGlobal: 64,
  statefulPerSubject: 8,
  operatorReserve: 1,
  doctorReserve: 1,
  retryAfterMs: 250,
  idleTtlSeconds: 900
} as const;

function CapacityMetricTiles({
  model,
  pending
}: {
  model: CapacityUiModel;
  pending: boolean;
}): React.ReactElement {
  return (
    <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-4" aria-label="capacity metrics">
      <MetricTile
        icon={Database}
        label="Read active"
        value={model.read.active}
        suffix={`/${formatNumber(model.read.effective)}`}
        tone={capacityUsageTone(model.read.active, model.read.effective)}
        pending={pending}
      />
      <MetricTile
        icon={Radio}
        label="Lane active"
        value={model.stateful.active}
        suffix={`/${formatNumber(model.stateful.effectiveRegular)}`}
        tone={capacityUsageTone(model.stateful.active, model.stateful.effectiveRegular)}
        pending={pending}
      />
      <MetricTile
        icon={ShieldCheck}
        label="Reserve"
        value={model.stateful.operatorReserve + model.stateful.doctorReserve}
        suffix=""
        tone="info"
        pending={pending}
      />
      <MetricTile
        icon={AlertTriangle}
        label="AtCapacity"
        value={model.atCapacityEvents}
        suffix=""
        tone={model.atCapacityEvents > 0 ? "warn" : "ok"}
        pending={pending}
      />
    </section>
  );
}

function ReadPoolCapacityPanel({ model }: { model: CapacityUiModel }): React.ReactElement {
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={Database}
        title="Read Pool"
        meta={`${formatNumber(model.read.active)}/${formatNumber(model.read.effective)} active`}
        tone={capacityUsageTone(model.read.active, model.read.effective)}
      />
      <div className="space-y-4 p-4">
        <CapacityBar
          label="Active"
          value={model.read.active}
          max={model.read.effective}
          tone={capacityUsageTone(model.read.active, model.read.effective)}
        />
        <div className="grid gap-3 sm:grid-cols-3">
          <CapacityFact label="Configured" value={model.read.configured} />
          <CapacityFact label="Effective" value={model.read.effective} />
          <CapacityFact label="Source" value={model.read.source} mono />
        </div>
      </div>
    </Surface>
  );
}

function StatefulCapacityPanel({ model }: { model: CapacityUiModel }): React.ReactElement {
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={Radio}
        title="Stateful Lanes"
        meta={`${formatNumber(model.stateful.regularInUse)}/${formatNumber(model.stateful.effectiveRegular)} regular`}
        tone={capacityUsageTone(model.stateful.regularInUse, model.stateful.effectiveRegular)}
      />
      <div className="space-y-4 p-4">
        <CapacityBar
          label="Regular in use"
          value={model.stateful.regularInUse}
          max={model.stateful.effectiveRegular}
          tone={capacityUsageTone(model.stateful.regularInUse, model.stateful.effectiveRegular)}
        />
        <div className="grid gap-3 sm:grid-cols-3">
          <CapacityFact label="Configured" value={model.stateful.configuredGlobal} />
          <CapacityFact label="Effective" value={model.stateful.effectiveGlobal} />
          <CapacityFact label="Cfg subject" value={model.stateful.configuredPerSubject} />
          <CapacityFact label="Available" value={model.stateful.regularAvailable} />
          <CapacityFact label="Subject cap" value={model.stateful.perSubjectCap} />
          <CapacityFact label="Subject avail" value={model.stateful.perSubjectAvailable} />
          <CapacityFact label="Operator" value={model.stateful.operatorReserve} />
          <CapacityFact label="Doctor" value={model.stateful.doctorReserve} />
          <CapacityFact label="Source" value={model.stateful.source} mono />
        </div>
      </div>
    </Surface>
  );
}

function AtCapacityPanel({ model }: { model: CapacityUiModel }): React.ReactElement {
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={AlertTriangle}
        title="Backpressure"
        meta={`${formatNumber(model.retryAfterMs)}ms retry`}
        tone={model.atCapacityEvents > 0 ? "warn" : "ok"}
      />
      <div className="grid gap-3 p-4 sm:grid-cols-3 xl:grid-cols-1">
        <CapacityFact label="Events" value={model.atCapacityEvents} />
        <CapacityFact label="Retry" value={`${formatNumber(model.retryAfterMs)}ms`} mono />
        <CapacityFact
          label="Idle reap"
          value={model.idleReaping.enabled ? `${formatNumber(model.idleReaping.ttlSeconds)}s` : "off"}
          mono
        />
      </div>
    </Surface>
  );
}

function CapacityLimitSourcesPanel({
  rows
}: {
  rows: CapacityLimitRow[];
}): React.ReactElement {
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={Gauge}
        title="Limit Sources"
        meta={`${rows.length} checks`}
        tone={rows.some((row) => row.source.status === "monitoring_unavailable") ? "info" : "ok"}
      />
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] border-collapse text-left">
          <thead className="bg-zinc-50 text-xs uppercase text-zinc-500">
            <tr>
              <th className="px-4 py-3 font-bold">Surface</th>
              <th className="px-4 py-3 font-bold">Limit</th>
              <th className="px-4 py-3 font-bold">Status</th>
              <th className="px-4 py-3 font-bold">Configured</th>
              <th className="px-4 py-3 font-bold">Effective</th>
              <th className="px-4 py-3 font-bold">Reason</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-100">
            {rows.length === 0 ? (
              <tr>
                <td className="px-4 py-8 text-center text-sm font-semibold text-zinc-500" colSpan={6}>
                  No capacity sources
                </td>
              </tr>
            ) : (
              rows.map((row) => (
                <tr key={row.key} className="bg-white">
                  <td className="px-4 py-4 align-top font-mono text-sm text-zinc-800">
                    {row.scope}
                  </td>
                  <td className="px-4 py-4 align-top font-mono text-sm font-semibold text-zinc-950">
                    {row.source.name}
                  </td>
                  <td className="px-4 py-4 align-top">
                    <Badge tone={limitStatusTone(row.source.status)}>{row.source.status}</Badge>
                  </td>
                  <td className="px-4 py-4 align-top font-mono text-sm text-zinc-700">
                    {formatOptionalNumber(row.source.configured)}
                  </td>
                  <td className="px-4 py-4 align-top font-mono text-sm text-zinc-700">
                    {formatOptionalNumber(row.source.effective)}
                  </td>
                  <td className="px-4 py-4 align-top text-sm text-zinc-600">
                    {row.source.reason ?? ""}
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

function CapacityBar({
  label,
  value,
  max,
  tone
}: {
  label: string;
  value: number;
  max: number;
  tone: "neutral" | "ok" | "warn" | "off" | "info";
}): React.ReactElement {
  return (
    <div>
      <div className="mb-2 flex items-center justify-between gap-3">
        <p className="text-sm font-bold text-zinc-700">{label}</p>
        <p className="font-mono text-sm font-semibold text-zinc-900">
          {formatNumber(value)} / {formatNumber(max)}
        </p>
      </div>
      <div className="h-3 rounded-full bg-zinc-100">
        <div
          className={cn("h-3 rounded-full", capacityFillClass(tone))}
          style={{ width: `${capacityBarWidth(value, max)}%` }}
        />
      </div>
    </div>
  );
}

function CapacityFact({
  label,
  value,
  mono = false
}: {
  label: string;
  value: string | number;
  mono?: boolean;
}): React.ReactElement {
  return (
    <div className="rounded-md border border-zinc-200 bg-zinc-50 p-3">
      <p className="text-xs font-bold uppercase text-zinc-500">{label}</p>
      <p
        className={cn(
          "mt-2 break-all text-sm font-semibold text-zinc-950",
          mono ? "font-mono" : "font-sans"
        )}
      >
        {typeof value === "number" ? formatNumber(value) : value}
      </p>
    </div>
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

function OverviewReviewsPanel({
  proposals,
  pending
}: {
  proposals: ChangeProposalView[];
  pending: boolean;
}): React.ReactElement {
  const visible = proposals.slice(0, 3);
  return (
    <Surface className="overflow-hidden">
      <div className="flex items-center justify-between gap-3 border-b border-zinc-200 px-4 py-3">
        <div className="min-w-0">
          <h3 className="flex items-center gap-2 text-base font-bold text-zinc-950">
            <GitPullRequest className="size-4" aria-hidden="true" />
            Reviews
          </h3>
          <p className="mt-1 truncate text-sm text-zinc-500">
            {pending ? "sync" : `${formatNumber(proposals.length)} open`}
          </p>
        </div>
        <Link
          to="/reviews"
          className="inline-flex h-9 items-center justify-center gap-2 whitespace-nowrap rounded-md border border-zinc-300 bg-white px-3 text-sm font-semibold text-zinc-900 transition-colors hover:bg-zinc-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-500"
        >
          <Search className="size-4" aria-hidden="true" />
          Open
        </Link>
      </div>
      <div className="divide-y divide-zinc-200">
        {visible.length === 0 ? (
          <div className="px-4 py-6 text-sm font-semibold text-zinc-500">No proposals</div>
        ) : (
          visible.map((proposal) => (
            <div key={proposal.id} className="grid gap-2 px-4 py-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="min-w-0 truncate text-sm font-bold text-zinc-950">{proposal.title}</p>
                <Badge tone={proposal.stored_verdict_present ? "warn" : "ok"}>
                  {proposal.stored_verdict_present ? "stale verdict" : "fresh"}
                </Badge>
              </div>
              <div className="flex flex-wrap gap-2 text-xs font-semibold text-zinc-500">
                <span>{proposal.profile}</span>
                <span>{proposal.author}</span>
                <span>{formatNumber(proposal.statement_count)} stmt</span>
              </div>
            </div>
          ))
        )}
      </div>
    </Surface>
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

function connectionHealthModel(
  health: OperatorHealthData | null,
  snapshot: MetricsSnapshot | null,
  connection: OperatorResponse<WorkbenchActionData> | undefined,
  connectionError: string | null
): ConnectionHealthUiModel {
  const db = nativeConnectionInfo(connection, connectionError);
  const live = health?.liveness?.live === true;
  const ready = health?.readiness?.ready === true;
  const dbReachable = health?.readiness?.db_reachable === true;
  const draining = health?.readiness?.draining === true;
  const sources: ConnectionHealthSourceRow[] = [
    {
      key: "operator-health",
      source: "/operator/v1/health",
      status: health ? "applied" : "monitoring_unavailable",
      detail: health?.readiness?.status ?? "health endpoint has not returned"
    },
    {
      key: "metrics",
      source: "/operator/v1/metrics",
      status: snapshot ? "applied" : "monitoring_unavailable",
      detail: snapshot ? "pool and latency gauges available" : "metrics snapshot unavailable"
    },
    {
      key: "db-native",
      source: "oracle_connection_info",
      status: db.connected ? "applied" : "monitoring_unavailable",
      detail: db.connected ? "redacted lane self-check available" : db.error
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
      liveness: health?.liveness?.status ?? "unavailable",
      readiness: health?.readiness?.status ?? "unavailable",
      live,
      ready,
      dbReachable,
      draining
    },
    pool: {
      active: snapshot?.pool_active_connections ?? 0,
      waitMeanMs: Math.round(snapshot?.pool_wait_ms.mean ?? 0),
      waitMaxMs: snapshot?.pool_wait_ms.max ?? 0,
      queryMeanMs: Math.round(snapshot?.query_duration_ms.mean ?? 0),
      queryMaxMs: snapshot?.query_duration_ms.max ?? 0
    },
    db,
    sources
  };
}

function nativeConnectionInfo(
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
  const poolOpenConnections = numberField(connection, "pool_open_connections");

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
    poolOpenConnections,
    error: "none"
  };
}

function capacityModel(
  capacity: OperatorCapacityData | null,
  snapshot: MetricsSnapshot | null,
  lanes: ActiveLane[]
): CapacityUiModel {
  const configuredGlobal =
    capacity?.stateful_lanes.configured.global ?? CAPACITY_DEFAULTS.statefulGlobal;
  const operatorReserve =
    capacity?.stateful_lanes.reserve.operator ?? CAPACITY_DEFAULTS.operatorReserve;
  const doctorReserve =
    capacity?.stateful_lanes.reserve.doctor ?? CAPACITY_DEFAULTS.doctorReserve;
  const defaultRegular = Math.max(0, configuredGlobal - operatorReserve - doctorReserve);
  const effective = capacity?.stateful_lanes.effective ?? null;
  const effectiveRegular =
    effective?.regular_global_cap ??
    capacity?.stateful_lanes.reserve.regular_global_cap ??
    defaultRegular;
  const active = capacity?.stateful_lanes.active ?? snapshot?.active_lanes ?? lanes.length;
  const regularInUse =
    capacity?.stateful_lanes.regular_in_use ?? Math.min(active, effectiveRegular);
  const limitRows: CapacityLimitRow[] = [
    ...(capacity?.read_pool.limit_sources ?? []).map((source) => ({
      key: `read_pool:${source.name}`,
      scope: "read_pool" as const,
      source
    })),
    ...(capacity?.stateful_lanes.limit_sources ?? []).map((source) => ({
      key: `stateful_lanes:${source.name}`,
      scope: "stateful_lanes" as const,
      source
    }))
  ];

  return {
    read: {
      source: capacity?.read_pool.source ?? "monitoring_unavailable",
      configured: capacity?.read_pool.configured_per_profile ?? CAPACITY_DEFAULTS.readPerProfile,
      effective: capacity?.read_pool.effective_per_profile ?? CAPACITY_DEFAULTS.readPerProfile,
      active: capacity?.read_pool.active ?? snapshot?.pool_active_connections ?? 0
    },
    stateful: {
      source: capacity?.stateful_lanes.source ?? "monitoring_unavailable",
      configuredGlobal,
      configuredPerSubject:
        capacity?.stateful_lanes.configured.per_subject ?? CAPACITY_DEFAULTS.statefulPerSubject,
      effectiveGlobal: effective?.global_cap ?? configuredGlobal,
      effectiveRegular,
      regularAvailable:
        effective?.regular_global_available ?? Math.max(0, effectiveRegular - regularInUse),
      regularInUse,
      active,
      perSubjectCap: effective?.per_subject_cap ?? CAPACITY_DEFAULTS.statefulPerSubject,
      perSubjectAvailable:
        effective?.per_subject_available ?? CAPACITY_DEFAULTS.statefulPerSubject,
      operatorReserve,
      doctorReserve
    },
    atCapacityEvents:
      capacity?.stateful_lanes.at_capacity_events ?? atCapacityCountFromSnapshot(snapshot),
    retryAfterMs: capacity?.stateful_lanes.retry_after_ms ?? CAPACITY_DEFAULTS.retryAfterMs,
    idleReaping: {
      enabled: capacity?.idle_reaping.enabled ?? true,
      ttlSeconds: capacity?.idle_reaping.ttl_seconds ?? CAPACITY_DEFAULTS.idleTtlSeconds
    },
    limitRows
  };
}

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

function sessionLaneRows(
  snapshot: MetricsSnapshot | null,
  lanes: ActiveLane[],
  selectedLaneId: string,
  capabilities: OperatorResponse<WorkbenchActionData> | undefined,
  connection: OperatorResponse<WorkbenchActionData> | undefined
): SessionLaneRow[] {
  const metrics = laneMetricRows(snapshot, lanes);
  const laneById = new Map(lanes.map((lane) => [lane.lane_id, lane]));
  const selectedCapabilities = sessionCapabilitiesSummary(capabilities);
  const selectedConnection = nativeConnectionInfo(connection, null);
  const selectedCacheKey = metadataCacheKeyFromResponse(connection);
  return metrics.map((row) => {
    const lane = laneById.get(row.laneId);
    const selected = row.laneId === selectedLaneId;
    return {
      ...row,
      generation: lane?.generation ?? 0,
      statusLabel: lane?.status ?? (row.active ? "active" : "idle"),
      currentLevel: selected ? selectedCapabilities.currentLevel : "expand",
      maxLevel: selected ? selectedCapabilities.maxLevel : "inspect",
      activeProfile: selected
        ? selectedConnection.activeProfile || selectedCapabilities.activeProfile
        : "expand",
      dbFingerprint: selected ? selectedCacheKey?.db_fingerprint ?? "unknown" : "inspect",
      connected: selected ? selectedConnection.connected ? "yes" : selectedCapabilities.connected : "inspect",
      selected
    };
  });
}

function selectedLaneDetail(
  lane: ActiveLane | null,
  rows: SessionLaneRow[],
  capabilities: OperatorResponse<WorkbenchActionData> | undefined,
  connection: OperatorResponse<WorkbenchActionData> | undefined,
  capabilitiesError: string | null,
  connectionError: string | null,
  events: OperatorEventEnvelope[]
): SessionLaneDetail | null {
  if (!lane) {
    return null;
  }
  const row = rows.find((candidate) => candidate.laneId === lane.lane_id);
  const caps = sessionCapabilitiesSummary(capabilities);
  const db = nativeConnectionInfo(connection, connectionError);
  const cacheKey = metadataCacheKeyFromResponse(connection);
  return {
    laneId: lane.lane_id,
    subjectIdHash: lane.subject_id_hash,
    generation: lane.generation,
    status: lane.status,
    currentLevel: caps.currentLevel,
    maxLevel: caps.maxLevel,
    protectedProfile: caps.protectedProfile,
    activeProfile: db.activeProfile || caps.activeProfile,
    dbFingerprint: cacheKey?.db_fingerprint ?? "unknown",
    visibleSchema: cacheKey?.visible_schema ?? "unknown",
    connected: db.connected ? "yes" : caps.connected,
    connectionStrategy: db.strategy,
    serverVersion: db.serverVersion,
    databaseRole: db.databaseRole,
    openMode: db.openMode,
    requests: row?.requests ?? 0,
    blocked: row?.blocked ?? 0,
    meanLatencyMs: row?.meanLatencyMs ?? 0,
    maxLatencyMs: row?.maxLatencyMs ?? 0,
    lastEvent: events[0]?.event_type ?? "none",
    detailState: capabilitiesError ?? connectionError ?? db.error
  };
}

function sessionCapabilitiesSummary(
  response: OperatorResponse<WorkbenchActionData> | undefined
): SessionCapabilitiesSummary {
  const result = mcpResult(response?.data.mcp_response);
  const resultRecord = isRecord(result) ? result : {};
  const operating = isRecord(resultRecord["operating_level"])
    ? resultRecord["operating_level"]
    : {};
  const connection = isRecord(resultRecord["connection"]) ? resultRecord["connection"] : {};
  return {
    currentLevel: stringValue(operating["current"], "unknown"),
    maxLevel: stringValue(operating["max"], "unknown"),
    protectedProfile: stringValue(operating["protected"], "unknown"),
    activeProfile: stringValue(connection["profile"], "unknown"),
    connected: stringValue(connection["connected"], "unknown")
  };
}

function sessionGroundControlModel(
  summary: OverviewSummary,
  eventStatus: EventStreamStatus,
  pending: boolean
): GroundControlViewModel {
  const verdict: GoNoGoVerdict =
    pending ? "SYNC" : summary.blocked > 0 || summary.errors > 0 ? "NO-GO" : "GO";
  return {
    grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
    verdict,
    health: healthPosture(verdict, summary.blocked),
    clearanceLadder: CLEARANCE_LADDER,
    clearanceStatus: {
      blocked: summary.blocked,
      label: summary.blocked > 0 ? "blocked" : "clear",
      tone: summary.blocked > 0 ? "warn" : "ok"
    },
    signatures: [
      {
        id: "go_no_go",
        label: "GO/NO-GO",
        value: verdict,
        detail: summary.errors > 0 ? `${formatNumber(summary.errors)} errors` : "session board",
        tone: verdict === "GO" ? "ok" : verdict === "SYNC" ? "info" : "warn",
        activity: verdict === "GO" ? 1 : 0.25
      },
      {
        id: "countdown",
        label: "Countdown",
        value: summary.activeLanes > 0 ? "live" : "idle",
        detail: `${formatNumber(summary.activeLanes)} lanes`,
        tone: summary.activeLanes > 0 ? "info" : "off",
        activity: clampActivity(summary.activeLanes / 8)
      },
      {
        id: "logbook",
        label: "Logbook",
        value: eventStatus,
        detail: "SSE",
        tone: eventStatusTone(eventStatus),
        activity: eventStatus === "live" ? 1 : eventStatus === "connecting" ? 0.5 : 0
      }
    ] satisfies readonly SignatureViewModel[]
  };
}

function clearanceLevel(value: string): OperatingLevel {
  return value === "READ_WRITE" || value === "DDL" || value === "ADMIN" ? value : "READ_ONLY";
}

function sessionClearanceClass(level: OperatingLevel): string {
  switch (level) {
    case "READ_ONLY":
      return "border-emerald-200 bg-emerald-50 text-emerald-800";
    case "READ_WRITE":
      return "border-sky-200 bg-sky-50 text-sky-800";
    case "DDL":
      return "border-amber-200 bg-amber-50 text-amber-800";
    case "ADMIN":
      return "border-rose-200 bg-rose-50 text-rose-800";
  }
}

function sessionLevelBadgeClass(value: string): string {
  if (value === "READ_ONLY" || value === "READ_WRITE" || value === "DDL" || value === "ADMIN") {
    return sessionClearanceClass(clearanceLevel(value));
  }
  return "border-zinc-200 bg-zinc-50 text-zinc-600";
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

function atCapacityCountFromSnapshot(snapshot: MetricsSnapshot | null): number {
  return sumCounts((snapshot?.requests ?? []).filter((row) => row.status === "at_capacity"));
}

function healthPosture(verdict: GoNoGoVerdict, blocked: number): HealthPosture {
  if (verdict === "SYNC") {
    return "syncing";
  }
  if (verdict === "NO-GO" || blocked > 0) {
    return "blocked";
  }
  return "nominal";
}

function fleetViewModel(
  summary: OverviewSummary,
  rows: LaneMetricRow[],
  pending: boolean
): FleetViewModel {
  const verdict: GoNoGoVerdict =
    pending ? "SYNC" : summary.blocked > 0 || summary.errors > 0 ? "NO-GO" : "GO";
  const maxRequests = Math.max(1, ...rows.map((row) => row.requests));
  const activeRows = rows.filter((row) => row.active).length;
  return {
    grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
    verdict,
    health:
      verdict === "SYNC"
        ? "syncing"
        : verdict === "NO-GO"
          ? "blocked"
          : activeRows > 0
            ? "working"
            : "idle",
    activity: clampActivity(activeRows > 0 ? activeRows / Math.max(1, rows.length) : 0),
    totals: {
      activeLanes: summary.activeLanes,
      requests: summary.totalRequests,
      blocked: summary.blocked,
      errors: summary.errors,
      meanLatencyMs: summary.meanLatencyMs,
      poolActive: summary.poolActive
    },
    sessions: rows.slice(0, 9).map((row) => ({
      laneId: row.laneId,
      subjectIdHash: row.subjectIdHash,
      status: row.blocked > 0 ? "blocked" : row.active ? "working" : "idle",
      clearance: "READ_ONLY",
      activity: clampActivity(row.requests / maxRequests),
      requests: row.requests,
      blocked: row.blocked,
      latencyMs: Math.round(row.meanLatencyMs)
    }))
  };
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

function capacityBarWidth(value: number, max: number): number {
  if (max <= 0) {
    return 2;
  }
  return Math.min(100, Math.max(value > 0 ? 8 : 2, Math.round((value / max) * 100)));
}

function capacityUsageTone(
  value: number,
  max: number
): "neutral" | "ok" | "warn" | "off" | "info" {
  if (max <= 0) {
    return "off";
  }
  if (value >= max) {
    return "warn";
  }
  if (value / max >= 0.85) {
    return "info";
  }
  return value > 0 ? "ok" : "off";
}

function capacityFillClass(tone: "neutral" | "ok" | "warn" | "off" | "info"): string {
  switch (tone) {
    case "warn":
      return "bg-amber-500";
    case "info":
      return "bg-sky-600";
    case "ok":
      return "bg-emerald-600";
    case "off":
      return "bg-zinc-300";
    case "neutral":
      return "bg-zinc-500";
  }
}

function limitStatusTone(status: string): "neutral" | "ok" | "warn" | "off" | "info" {
  switch (status) {
    case "applied":
      return "ok";
    case "monitoring_unavailable":
      return "info";
    case "rejected":
    case "error":
      return "warn";
    default:
      return "neutral";
  }
}

function formatOptionalNumber(value: number | undefined): string {
  return typeof value === "number" && Number.isFinite(value) ? formatNumber(value) : "";
}

function stringField(
  record: Record<string, unknown>,
  key: string,
  fallback: string
): string {
  const value = record[key];
  return typeof value === "string" && value.trim().length > 0 ? value : fallback;
}

function numberField(record: Record<string, unknown>, key: string): number | null {
  const value = record[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function compactJson(value: unknown): string {
  if (value === null || typeof value === "undefined") {
    return "null";
  }
  if (typeof value === "string") {
    return value;
  }
  return JSON.stringify(value);
}

function reloadTone(status: string): "neutral" | "ok" | "warn" | "off" | "info" {
  switch (status) {
    case "applied":
      return "ok";
    case "restart_required":
    case "not_configured":
      return "info";
    default:
      return "neutral";
  }
}

function formatMs(ms: number): string {
  return `${formatNumber(ms)}ms`;
}

function formatNumber(value: number): string {
  return new Intl.NumberFormat("en-US", { maximumFractionDigits: 0 }).format(value);
}

const explorerDetailLevels: ExplorerDetailLevel[] = ["names", "summary", "standard", "full"];

const explorerObjectTypes = [
  "",
  "TABLE",
  "VIEW",
  "PACKAGE",
  "PACKAGE BODY",
  "PROCEDURE",
  "FUNCTION",
  "TRIGGER",
  "TYPE",
  "TYPE BODY",
  "SEQUENCE",
  "INDEX",
  "SYNONYM"
] as const;

const explorerSourceSearchTypes = [
  "",
  "PACKAGE",
  "PACKAGE BODY",
  "PROCEDURE",
  "FUNCTION",
  "TRIGGER",
  "TYPE",
  "TYPE BODY"
] as const;

type ExplorerSchemaRow = {
  schemaName: string;
  objectCount: string;
};

type ExplorerObjectRow = {
  owner: string;
  objectName: string;
  objectType: string;
  status: string;
  numRows: string;
  columnCount: string;
  lastAnalyzed: string;
  comment: string;
  raw: Record<string, unknown>;
};

type ExplorerSourceHitRow = {
  owner: string;
  name: string;
  objectType: string;
  line: string;
  text: string;
  raw: Record<string, unknown>;
};

type ExplorerGlobalSearchRequest = {
  needle: string;
  includeObjects: boolean;
  includeSource: boolean;
  allSchemas: boolean;
  sourceType: string;
};

type ExplorerDetailResult =
  | {
      state: "ok";
      kind: "ddl" | "source";
      ref: ExplorerObjectRef;
      response: OperatorResponse<WorkbenchActionData>;
      cacheStatus: ExplorerCacheStatus;
      bytes: number;
    }
  | {
      state: "error";
      kind: "ddl" | "source";
      ref: ExplorerObjectRef | null;
      message: string;
    };

function ExplorerPage(): React.ReactElement {
  const [laneId, setLaneId] = React.useState("");
  const [schemaFilter, setSchemaFilter] = React.useState("");
  const [owner, setOwner] = React.useState("");
  const [objectType, setObjectType] = React.useState("");
  const [nameLike, setNameLike] = React.useState("");
  const [detailLevel, setDetailLevel] = React.useState<ExplorerDetailLevel>("summary");
  const [maxRows, setMaxRows] = React.useState(100);
  const [maxChars, setMaxChars] = React.useState(40_000);
  const [selectedRef, setSelectedRef] = React.useState<ExplorerObjectRef | null>(null);
  const [detailResult, setDetailResult] = React.useState<ExplorerDetailResult | null>(null);
  const [globalSearchText, setGlobalSearchText] = React.useState("");
  const [globalIncludeObjects, setGlobalIncludeObjects] = React.useState(true);
  const [globalIncludeSource, setGlobalIncludeSource] = React.useState(true);
  const [globalAllSchemas, setGlobalAllSchemas] = React.useState(true);
  const [globalSourceType, setGlobalSourceType] = React.useState("");
  const [globalSearchRequest, setGlobalSearchRequest] =
    React.useState<ExplorerGlobalSearchRequest | null>(null);
  const [cacheVersion, setCacheVersion] = React.useState(0);

  const session = useQuery({
    queryKey: ["dashboard-session"],
    queryFn: fetchDashboardSession,
    staleTime: 60_000,
    refetchInterval: 60_000,
    retry: 1
  });
  const activeLanes = useQuery({
    queryKey: ["active-lanes"],
    queryFn: fetchActiveLanes,
    refetchInterval: 5_000
  });
  const lanes = activeLanes.data?.data.lanes ?? [];

  React.useEffect(() => {
    if (!laneId && lanes.length === 1) {
      setLaneId(lanes[0].lane_id);
    }
  }, [laneId, lanes]);

  React.useEffect(() => {
    clearExplorerMetadataCache();
    setCacheVersion((version) => version + 1);
    setSelectedRef(null);
    setDetailResult(null);
    setGlobalSearchRequest(null);
  }, [laneId]);

  React.useEffect(() => {
    setSelectedRef(null);
    setDetailResult(null);
  }, [detailLevel, nameLike, objectType, owner]);

  const connection = useQuery({
    queryKey: ["explorer", "connection", laneId],
    queryFn: async () => {
      if (!session.data) {
        throw new Error("dashboard session is not ready");
      }
      return fetchExplorerConnection(session.data, laneId);
    },
    enabled: session.status === "success",
    retry: 1
  });

  const baseCacheKey = metadataCacheKeyFromResponse(connection.data);
  const schemasScope = baseCacheKey ? explorerScopeForVisibleSchema(baseCacheKey, "*") : null;
  const objectScope = baseCacheKey
    ? explorerScopeForVisibleSchema(baseCacheKey, owner.trim() || baseCacheKey.visible_schema)
    : null;
  const globalScope =
    baseCacheKey && globalSearchRequest
      ? explorerScopeForVisibleSchema(
          baseCacheKey,
          globalSearchRequest.allSchemas ? "*" : owner.trim() || baseCacheKey.visible_schema
        )
      : null;

  const schemasQuery = useQuery({
    queryKey: [
      "explorer",
      "schemas",
      laneId,
      schemaFilter,
      maxRows,
      cacheScopeToken(schemasScope),
      cacheVersion
    ],
    queryFn: async () => {
      if (!session.data || !schemasScope) {
        throw new Error("explorer schema cache is not ready");
      }
      return cachedExplorerMetadata(
        schemasScope,
        JSON.stringify({
          tool: "oracle_list_schemas",
          name_like: schemaFilter.trim(),
          max_rows: maxRows
        }),
        () =>
          fetchExplorerSchemas(session.data, {
            laneId,
            nameLike: schemaFilter,
            maxRows
          })
      );
    },
    enabled: session.status === "success" && Boolean(schemasScope),
    retry: 1
  });

  const objectsQuery = useQuery({
    queryKey: [
      "explorer",
      "objects",
      laneId,
      owner,
      objectType,
      nameLike,
      detailLevel,
      maxRows,
      cacheScopeToken(objectScope),
      cacheVersion
    ],
    queryFn: async () => {
      if (!session.data || !objectScope) {
        throw new Error("explorer object cache is not ready");
      }
      return cachedExplorerMetadata(
        objectScope,
        JSON.stringify({
          tool: "oracle_search_objects",
          owner: owner.trim(),
          object_type: objectType,
          name_like: nameLike.trim(),
          detail_level: detailLevel,
          max_rows: maxRows
        }),
        () =>
          fetchExplorerObjects(session.data, {
            laneId,
            owner,
            objectType,
            nameLike,
            detailLevel,
            maxRows
          })
      );
    },
    enabled: session.status === "success" && Boolean(objectScope),
    retry: 1
  });

  const globalObjectsQuery = useQuery({
    queryKey: [
      "explorer",
      "global-objects",
      laneId,
      globalSearchRequest,
      cacheScopeToken(globalScope),
      cacheVersion
    ],
    queryFn: async () => {
      if (!session.data || !globalScope || !globalSearchRequest) {
        throw new Error("global object search is not ready");
      }
      const ownerFilter = globalSearchRequest.allSchemas ? "*" : owner.trim();
      const nameLike = `%${globalSearchRequest.needle}%`;
      return cachedExplorerMetadata(
        globalScope,
        JSON.stringify({
          tool: "oracle_search_objects",
          owner: ownerFilter,
          object_type: "",
          name_like: nameLike,
          detail_level: "summary",
          max_rows: maxRows
        }),
        () =>
          fetchExplorerObjects(session.data, {
            laneId,
            owner: ownerFilter,
            objectType: "",
            nameLike,
            detailLevel: "summary",
            maxRows
          })
      );
    },
    enabled:
      session.status === "success" &&
      Boolean(globalScope && globalSearchRequest?.includeObjects),
    retry: 1
  });

  const globalSourceQuery = useQuery({
    queryKey: [
      "explorer",
      "global-source",
      laneId,
      globalSearchRequest,
      cacheScopeToken(globalScope),
      cacheVersion
    ],
    queryFn: async () => {
      if (!session.data || !globalScope || !globalSearchRequest) {
        throw new Error("global source search is not ready");
      }
      const ownerFilter = globalSearchRequest.allSchemas ? "*" : owner.trim();
      return cachedExplorerMetadata(
        globalScope,
        JSON.stringify({
          tool: "oracle_search_source",
          owner: ownerFilter,
          object_type: globalSearchRequest.sourceType,
          needle: globalSearchRequest.needle,
          max_rows: maxRows
        }),
        () =>
          fetchExplorerSourceSearch(session.data, {
            laneId,
            owner: ownerFilter,
            objectType: globalSearchRequest.sourceType,
            needle: globalSearchRequest.needle,
            maxRows
          })
      );
    },
    enabled:
      session.status === "success" && Boolean(globalScope && globalSearchRequest?.includeSource),
    retry: 1
  });

  const detailMutation = useMutation({
    mutationFn: async ({ kind, ref }: { kind: "ddl" | "source"; ref: ExplorerObjectRef }) => {
      if (!session.data || !baseCacheKey) {
        throw new Error("explorer cache key is not ready");
      }
      const scope = explorerScopeForVisibleSchema(baseCacheKey, ref.owner);
      const slot = JSON.stringify({
        tool: kind === "ddl" ? "oracle_get_ddl" : "oracle_get_source",
        owner: ref.owner,
        name: ref.name,
        object_type: ref.objectType,
        max_chars: kind === "source" ? maxChars : undefined
      });
      const cached = await cachedExplorerMetadata(scope, slot, () =>
        kind === "ddl"
          ? fetchExplorerDdl(session.data, { ...ref, laneId })
          : fetchExplorerSource(session.data, { ...ref, laneId, maxChars })
      );
      return {
        state: "ok" as const,
        kind,
        ref,
        response: cached.value,
        cacheStatus: cached.status,
        bytes: cached.bytes
      };
    },
    onSuccess: (result) => {
      setDetailResult(result);
    },
    onError: (error, variables) => {
      setDetailResult({
        state: "error",
        kind: variables.kind,
        ref: variables.ref,
        message: error instanceof Error ? error.message : "metadata request failed"
      });
    }
  });

  const schemaRows = schemaRowsFromResponse(schemasQuery.data?.value);
  const objectRows = objectRowsFromResponse(objectsQuery.data?.value);
  const globalObjectRows = globalSearchRequest?.includeObjects
    ? objectRowsFromResponse(globalObjectsQuery.data?.value)
    : [];
  const globalSourceRows = globalSearchRequest?.includeSource
    ? sourceRowsFromResponse(globalSourceQuery.data?.value)
    : [];
  const selectedRow = selectedRef
    ? objectRows.find((row) => objectRefKey(rowRef(row)) === objectRefKey(selectedRef)) ?? null
    : null;
  const cacheSummary = explorerMetadataCacheSummary();
  const connected = connectedFromResponse(connection.data);
  const sessionTone =
    session.status === "success" ? "ok" : session.status === "error" ? "warn" : "info";

  const refreshExplorer = (): void => {
    clearExplorerMetadataCache();
    setCacheVersion((version) => version + 1);
    queryClient.invalidateQueries({ queryKey: ["explorer"] });
  };

  const selectRow = (row: ExplorerObjectRow): void => {
    const ref = rowRef(row);
    setSelectedRef(ref);
    setDetailResult(null);
  };
  const selectSourceHit = (row: ExplorerSourceHitRow): void => {
    setSelectedRef({
      owner: row.owner,
      name: row.name,
      objectType: row.objectType
    });
    setDetailResult(null);
  };
  const runGlobalSearch = (): void => {
    const needle = globalSearchText.trim();
    if (!needle || (!globalIncludeObjects && !globalIncludeSource)) {
      return;
    }
    setGlobalSearchRequest({
      needle,
      includeObjects: globalIncludeObjects,
      includeSource: globalIncludeSource,
      allSchemas: globalAllSchemas,
      sourceType: globalSourceType
    });
  };

  return (
    <PageFrame
      title="Explorer"
      eyebrow="Schema Metadata"
      description="Schema and object metadata through the guarded dictionary tools and bounded browser metadata cache."
    >
      <div className="space-y-4">
        <Surface className="p-4">
          <div className="grid gap-3 xl:grid-cols-[minmax(180px,0.9fr)_minmax(140px,0.7fr)_minmax(140px,0.7fr)_minmax(140px,0.7fr)_minmax(140px,0.7fr)_110px_auto] xl:items-end">
            <label className="block">
              <span className="mb-2 block text-sm font-bold text-zinc-700">Lane</span>
              <input
                className="h-10 w-full rounded-md border border-zinc-300 px-3 font-mono text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                value={laneId}
                onChange={(event) => setLaneId(event.target.value)}
                list="explorer-lanes"
                placeholder={lanes[0]?.lane_id ?? "operator"}
              />
              <datalist id="explorer-lanes">
                {lanes.map((lane) => (
                  <option key={lane.lane_id} value={lane.lane_id} />
                ))}
              </datalist>
            </label>
            <label className="block">
              <span className="mb-2 block text-sm font-bold text-zinc-700">Schema Filter</span>
              <input
                className="h-10 w-full rounded-md border border-zinc-300 px-3 font-mono text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                value={schemaFilter}
                onChange={(event) => setSchemaFilter(event.target.value)}
                placeholder="APP%"
              />
            </label>
            <label className="block">
              <span className="mb-2 block text-sm font-bold text-zinc-700">Schema</span>
              <select
                className="h-10 w-full rounded-md border border-zinc-300 bg-white px-3 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                value={owner}
                onChange={(event) => setOwner(event.target.value)}
              >
                <option value="">Current</option>
                <option value="*">All visible</option>
                {schemaRows.map((row) => (
                  <option key={row.schemaName} value={row.schemaName}>
                    {row.schemaName}
                  </option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="mb-2 block text-sm font-bold text-zinc-700">Type</span>
              <select
                className="h-10 w-full rounded-md border border-zinc-300 bg-white px-3 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                value={objectType}
                onChange={(event) => setObjectType(event.target.value)}
              >
                {explorerObjectTypes.map((type) => (
                  <option key={type || "all"} value={type}>
                    {type || "All"}
                  </option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="mb-2 block text-sm font-bold text-zinc-700">Name Like</span>
              <input
                className="h-10 w-full rounded-md border border-zinc-300 px-3 font-mono text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                value={nameLike}
                onChange={(event) => setNameLike(event.target.value)}
                placeholder="CUSTOMER%"
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
            <Button type="button" variant="ghost" onClick={refreshExplorer}>
              <RefreshCcw className="size-4" aria-hidden="true" />
              Refresh
            </Button>
          </div>
          <div className="mt-4 flex flex-wrap items-center gap-2">
            {explorerDetailLevels.map((level) => (
              <Button
                key={level}
                type="button"
                variant={detailLevel === level ? "primary" : "secondary"}
                onClick={() => setDetailLevel(level)}
              >
                {level}
              </Button>
            ))}
            <Badge tone={sessionTone}>
              {session.status === "success" ? "paired" : session.status === "error" ? "blocked" : "pairing"}
            </Badge>
            <Badge tone={connected ? "ok" : connection.isError ? "warn" : "info"}>
              {connected ? "connected" : connection.isError ? "blocked" : "sync"}
            </Badge>
            <Badge tone={cacheStatusTone(objectsQuery.data?.status ?? schemasQuery.data?.status)}>
              {objectsQuery.data?.status ?? schemasQuery.data?.status ?? "cold"}
            </Badge>
            <span className="font-mono text-xs font-semibold text-zinc-500">
              {cacheSummary.entries} entries · {formatBytes(cacheSummary.bytes)}
            </span>
          </div>
          {connection.error instanceof Error ? (
            <p className="mt-3 rounded-md border border-amber-200 bg-amber-50 p-3 text-sm font-semibold text-amber-900">
              {connection.error.message}
            </p>
          ) : null}
        </Surface>

        <ExplorerGlobalSearchPanel
          searchText={globalSearchText}
          includeObjects={globalIncludeObjects}
          includeSource={globalIncludeSource}
          allSchemas={globalAllSchemas}
          sourceType={globalSourceType}
          request={globalSearchRequest}
          objectRows={globalObjectRows}
          sourceRows={globalSourceRows}
          objectPending={globalObjectsQuery.isFetching}
          sourcePending={globalSourceQuery.isFetching}
          objectError={
            globalObjectsQuery.error instanceof Error ? globalObjectsQuery.error.message : null
          }
          sourceError={
            globalSourceQuery.error instanceof Error ? globalSourceQuery.error.message : null
          }
          objectCacheStatus={globalObjectsQuery.data?.status}
          sourceCacheStatus={globalSourceQuery.data?.status}
          canSearch={
            session.status === "success" &&
            globalSearchText.trim().length > 0 &&
            (globalIncludeObjects || globalIncludeSource)
          }
          onSearchTextChange={setGlobalSearchText}
          onIncludeObjectsChange={setGlobalIncludeObjects}
          onIncludeSourceChange={setGlobalIncludeSource}
          onAllSchemasChange={setGlobalAllSchemas}
          onSourceTypeChange={setGlobalSourceType}
          onSearch={runGlobalSearch}
          onSelectObject={selectRow}
          onSelectSource={selectSourceHit}
        />

        <div className="grid gap-4 xl:grid-cols-[minmax(260px,0.55fr)_minmax(0,1.45fr)]">
          <ExplorerSchemasPanel
            rows={schemaRows}
            selectedOwner={owner}
            pending={schemasQuery.isFetching}
            error={schemasQuery.error instanceof Error ? schemasQuery.error.message : null}
            onSelect={setOwner}
          />
          <ExplorerObjectsPanel
            rows={objectRows}
            selectedRef={selectedRef}
            pending={objectsQuery.isFetching}
            error={objectsQuery.error instanceof Error ? objectsQuery.error.message : null}
            onSelect={selectRow}
          />
        </div>

        <ExplorerObjectDetailPanel
          row={selectedRow}
          selectedRef={selectedRef}
          result={detailResult}
          pending={detailMutation.isPending}
          maxChars={maxChars}
          onMaxCharsChange={setMaxChars}
          onReadDdl={(ref) => detailMutation.mutate({ kind: "ddl", ref })}
          onReadSource={(ref) => detailMutation.mutate({ kind: "source", ref })}
        />
      </div>
    </PageFrame>
  );
}

function ExplorerGlobalSearchPanel({
  searchText,
  includeObjects,
  includeSource,
  allSchemas,
  sourceType,
  request,
  objectRows,
  sourceRows,
  objectPending,
  sourcePending,
  objectError,
  sourceError,
  objectCacheStatus,
  sourceCacheStatus,
  canSearch,
  onSearchTextChange,
  onIncludeObjectsChange,
  onIncludeSourceChange,
  onAllSchemasChange,
  onSourceTypeChange,
  onSearch,
  onSelectObject,
  onSelectSource
}: {
  searchText: string;
  includeObjects: boolean;
  includeSource: boolean;
  allSchemas: boolean;
  sourceType: string;
  request: ExplorerGlobalSearchRequest | null;
  objectRows: ExplorerObjectRow[];
  sourceRows: ExplorerSourceHitRow[];
  objectPending: boolean;
  sourcePending: boolean;
  objectError: string | null;
  sourceError: string | null;
  objectCacheStatus: ExplorerCacheStatus | undefined;
  sourceCacheStatus: ExplorerCacheStatus | undefined;
  canSearch: boolean;
  onSearchTextChange: (value: string) => void;
  onIncludeObjectsChange: (value: boolean) => void;
  onIncludeSourceChange: (value: boolean) => void;
  onAllSchemasChange: (value: boolean) => void;
  onSourceTypeChange: (value: string) => void;
  onSearch: () => void;
  onSelectObject: (row: ExplorerObjectRow) => void;
  onSelectSource: (row: ExplorerSourceHitRow) => void;
}): React.ReactElement {
  const pending = objectPending || sourcePending;
  const totalHits = objectRows.length + sourceRows.length;
  const tone = pending ? "info" : request ? (totalHits > 0 ? "ok" : "off") : "neutral";
  const objectCache = objectCacheStatus ?? "cold";
  const sourceCache = sourceCacheStatus ?? "cold";

  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={Search}
        title="Global Search"
        meta={pending ? "sync" : request ? `${totalHits} hits` : "idle"}
        tone={tone}
      />
      <div className="space-y-4 p-4">
        <div className="grid gap-3 xl:grid-cols-[minmax(260px,1fr)_180px_auto] xl:items-end">
          <label className="block">
            <span className="mb-2 block text-sm font-bold text-zinc-700">Needle</span>
            <input
              className="h-10 w-full rounded-md border border-zinc-300 px-3 font-mono text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
              value={searchText}
              onChange={(event) => onSearchTextChange(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && canSearch) {
                  onSearch();
                }
              }}
              placeholder="customer, commit, package"
            />
          </label>
          <label className="block">
            <span className="mb-2 block text-sm font-bold text-zinc-700">Source Type</span>
            <select
              className="h-10 w-full rounded-md border border-zinc-300 bg-white px-3 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200 disabled:bg-zinc-100 disabled:text-zinc-500"
              value={sourceType}
              disabled={!includeSource}
              onChange={(event) => onSourceTypeChange(event.target.value)}
            >
              {explorerSourceSearchTypes.map((type) => (
                <option key={type || "all-source"} value={type}>
                  {type || "All source"}
                </option>
              ))}
            </select>
          </label>
          <Button type="button" variant="primary" disabled={!canSearch} onClick={onSearch}>
            <Search className="size-4" aria-hidden="true" />
            Search
          </Button>
        </div>
        <div className="flex flex-wrap items-center gap-4">
          <label className="flex min-h-9 items-center gap-2 text-sm font-semibold text-zinc-700">
            <input
              className="size-4 rounded border-zinc-300 text-emerald-700 focus:ring-emerald-600"
              type="checkbox"
              checked={includeObjects}
              onChange={(event) => onIncludeObjectsChange(event.target.checked)}
            />
            Objects
          </label>
          <label className="flex min-h-9 items-center gap-2 text-sm font-semibold text-zinc-700">
            <input
              className="size-4 rounded border-zinc-300 text-emerald-700 focus:ring-emerald-600"
              type="checkbox"
              checked={includeSource}
              onChange={(event) => onIncludeSourceChange(event.target.checked)}
            />
            Source
          </label>
          <label className="flex min-h-9 items-center gap-2 text-sm font-semibold text-zinc-700">
            <input
              className="size-4 rounded border-zinc-300 text-emerald-700 focus:ring-emerald-600"
              type="checkbox"
              checked={allSchemas}
              onChange={(event) => onAllSchemasChange(event.target.checked)}
            />
            All visible schemas
          </label>
          <Badge tone={cacheStatusTone(objectCache)}>{`objects ${objectCache}`}</Badge>
          <Badge tone={cacheStatusTone(sourceCache)}>{`source ${sourceCache}`}</Badge>
        </div>
        {objectError ? <ErrorNotice message={objectError} /> : null}
        {sourceError ? <ErrorNotice message={sourceError} /> : null}
        <div className="grid gap-4 xl:grid-cols-2">
          <div className="overflow-hidden rounded-md border border-zinc-200">
            <div className="flex items-center justify-between gap-3 border-b border-zinc-200 bg-zinc-50 px-3 py-2">
              <span className="text-xs font-bold uppercase text-zinc-500">Object Matches</span>
              <Badge tone={includeObjects ? "ok" : "off"}>{objectRows.length}</Badge>
            </div>
            <div className="max-h-[360px] overflow-auto">
              {objectRows.length === 0 ? (
                <p className="px-3 py-6 text-sm font-semibold text-zinc-500">No objects</p>
              ) : (
                objectRows.map((row) => (
                  <button
                    key={objectRefKey(rowRef(row))}
                    type="button"
                    className="block w-full border-b border-zinc-100 px-3 py-3 text-left hover:bg-zinc-50"
                    onClick={() => onSelectObject(row)}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="min-w-0 truncate font-mono text-sm font-semibold text-zinc-950">
                        {row.objectName}
                      </span>
                      <Badge tone="neutral">{row.objectType}</Badge>
                    </div>
                    <p className="mt-1 font-mono text-xs text-zinc-500">{row.owner}</p>
                  </button>
                ))
              )}
            </div>
          </div>
          <div className="overflow-hidden rounded-md border border-zinc-200">
            <div className="flex items-center justify-between gap-3 border-b border-zinc-200 bg-zinc-50 px-3 py-2">
              <span className="text-xs font-bold uppercase text-zinc-500">Source Matches</span>
              <Badge tone={includeSource ? "ok" : "off"}>{sourceRows.length}</Badge>
            </div>
            <div className="max-h-[360px] overflow-auto">
              {sourceRows.length === 0 ? (
                <p className="px-3 py-6 text-sm font-semibold text-zinc-500">No source hits</p>
              ) : (
                sourceRows.map((row) => (
                  <button
                    key={`${row.owner}.${row.name}:${row.objectType}:${row.line}`}
                    type="button"
                    className="block w-full border-b border-zinc-100 px-3 py-3 text-left hover:bg-zinc-50"
                    onClick={() => onSelectSource(row)}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="min-w-0 truncate font-mono text-sm font-semibold text-zinc-950">
                        {row.name}
                      </span>
                      <span className="font-mono text-xs font-semibold text-zinc-500">
                        {row.objectType}:{row.line}
                      </span>
                    </div>
                    <p className="mt-1 font-mono text-xs text-zinc-500">{row.owner}</p>
                    <p className="mt-2 line-clamp-2 text-sm text-zinc-700">{row.text}</p>
                  </button>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </Surface>
  );
}

function ExplorerSchemasPanel({
  rows,
  selectedOwner,
  pending,
  error,
  onSelect
}: {
  rows: ExplorerSchemaRow[];
  selectedOwner: string;
  pending: boolean;
  error: string | null;
  onSelect: (owner: string) => void;
}): React.ReactElement {
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={Database}
        title="Schemas"
        meta={pending ? "sync" : `${rows.length} visible`}
        tone={pending ? "info" : rows.length > 0 ? "ok" : "off"}
      />
      {error ? <ErrorNotice message={error} /> : null}
      <div className="max-h-[520px] divide-y divide-zinc-100 overflow-auto">
        {rows.length === 0 ? (
          <p className="px-4 py-8 text-center text-sm font-semibold text-zinc-500">No schemas</p>
        ) : (
          rows.map((row) => {
            const selected = selectedOwner === row.schemaName;
            return (
              <button
                key={row.schemaName}
                type="button"
                className={cn(
                  "grid w-full grid-cols-[minmax(0,1fr)_80px] gap-3 px-4 py-3 text-left hover:bg-zinc-50",
                  selected ? "bg-emerald-50" : "bg-white"
                )}
                onClick={() => onSelect(row.schemaName)}
              >
                <span className="truncate font-mono text-sm font-semibold text-zinc-950">
                  {row.schemaName}
                </span>
                <span className="text-right font-mono text-sm text-zinc-700">
                  {row.objectCount}
                </span>
              </button>
            );
          })
        )}
      </div>
    </Surface>
  );
}

function ExplorerObjectsPanel({
  rows,
  selectedRef,
  pending,
  error,
  onSelect
}: {
  rows: ExplorerObjectRow[];
  selectedRef: ExplorerObjectRef | null;
  pending: boolean;
  error: string | null;
  onSelect: (row: ExplorerObjectRow) => void;
}): React.ReactElement {
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={Search}
        title="Objects"
        meta={pending ? "sync" : `${rows.length} objects`}
        tone={pending ? "info" : rows.length > 0 ? "ok" : "off"}
      />
      {error ? <ErrorNotice message={error} /> : null}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[980px] border-collapse text-left">
          <thead className="bg-zinc-50 text-xs uppercase text-zinc-500">
            <tr>
              <th className="px-4 py-3 font-bold">Object</th>
              <th className="px-4 py-3 font-bold">Type</th>
              <th className="px-4 py-3 font-bold">Status</th>
              <th className="px-4 py-3 font-bold">Rows</th>
              <th className="px-4 py-3 font-bold">Columns</th>
              <th className="px-4 py-3 font-bold">Analyzed</th>
              <th className="px-4 py-3 font-bold">Comment</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-100">
            {rows.length === 0 ? (
              <tr>
                <td className="px-4 py-8 text-center text-sm font-semibold text-zinc-500" colSpan={7}>
                  No objects
                </td>
              </tr>
            ) : (
              rows.map((row) => {
                const ref = rowRef(row);
                const selected = selectedRef && objectRefKey(selectedRef) === objectRefKey(ref);
                return (
                  <tr
                    key={objectRefKey(ref)}
                    className={cn("cursor-pointer", selected ? "bg-emerald-50" : "bg-white")}
                    onClick={() => onSelect(row)}
                  >
                    <td className="px-4 py-4 align-top">
                      <p className="font-mono text-sm font-semibold text-zinc-950">{row.objectName}</p>
                      <p className="mt-1 font-mono text-xs text-zinc-500">{row.owner}</p>
                    </td>
                    <td className="px-4 py-4 align-top font-mono text-sm text-zinc-800">
                      {row.objectType}
                    </td>
                    <td className="px-4 py-4 align-top">
                      <Badge tone={row.status === "INVALID" ? "warn" : row.status ? "ok" : "off"}>
                        {row.status || "..."}
                      </Badge>
                    </td>
                    <td className="px-4 py-4 align-top font-mono text-sm text-zinc-700">
                      {row.numRows}
                    </td>
                    <td className="px-4 py-4 align-top font-mono text-sm text-zinc-700">
                      {row.columnCount}
                    </td>
                    <td className="px-4 py-4 align-top font-mono text-xs text-zinc-700">
                      {row.lastAnalyzed}
                    </td>
                    <td className="max-w-[280px] px-4 py-4 align-top text-sm text-zinc-700">
                      <p className="line-clamp-2">{row.comment}</p>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </Surface>
  );
}

function ExplorerObjectDetailPanel({
  row,
  selectedRef,
  result,
  pending,
  maxChars,
  onMaxCharsChange,
  onReadDdl,
  onReadSource
}: {
  row: ExplorerObjectRow | null;
  selectedRef: ExplorerObjectRef | null;
  result: ExplorerDetailResult | null;
  pending: boolean;
  maxChars: number;
  onMaxCharsChange: (value: number) => void;
  onReadDdl: (ref: ExplorerObjectRef) => void;
  onReadSource: (ref: ExplorerObjectRef) => void;
}): React.ReactElement {
  const sourceAllowed = selectedRef ? canReadSource(selectedRef.objectType) : false;
  const detail = result?.state === "ok" ? mcpResult(result.response.data.mcp_response) : null;
  return (
    <Surface className="overflow-hidden">
      <div className="flex flex-col gap-3 border-b border-zinc-200 px-4 py-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="min-w-0">
          <h3 className="flex items-center gap-2 text-base font-bold text-zinc-950">
            <Code2 className="size-4" aria-hidden="true" />
            Object Detail
          </h3>
          <p className="mt-1 break-all font-mono text-sm text-zinc-500">
            {selectedRef ? objectRefKey(selectedRef) : "idle"}
          </p>
        </div>
        <div className="flex flex-wrap items-end gap-2">
          <label className="block">
            <span className="mb-1 block text-xs font-bold uppercase text-zinc-500">Chars</span>
            <input
              className="h-9 w-28 rounded-md border border-zinc-300 px-3 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
              min={1000}
              max={1000000}
              type="number"
              value={maxChars}
              onChange={(event) => onMaxCharsChange(clampChars(event.target.valueAsNumber))}
            />
          </label>
          <Button
            type="button"
            variant="secondary"
            disabled={!selectedRef || pending}
            onClick={() => selectedRef && onReadDdl(selectedRef)}
          >
            <Database className="size-4" aria-hidden="true" />
            DDL
          </Button>
          <Button
            type="button"
            variant="secondary"
            disabled={!selectedRef || !sourceAllowed || pending}
            onClick={() => selectedRef && onReadSource(selectedRef)}
          >
            <Code2 className="size-4" aria-hidden="true" />
            Source
          </Button>
          <Badge tone={pending ? "info" : result?.state === "error" ? "warn" : result ? "ok" : "off"}>
            {pending ? "loading" : result?.state ?? "empty"}
          </Badge>
        </div>
      </div>
      <div className="grid gap-4 p-4 xl:grid-cols-[minmax(0,0.65fr)_minmax(360px,1.35fr)]">
        <div className="space-y-3">
          <ExplorerFact label="Owner" value={selectedRef?.owner ?? "..."} />
          <ExplorerFact label="Name" value={selectedRef?.name ?? "..."} />
          <ExplorerFact label="Type" value={selectedRef?.objectType ?? "..."} />
          <ExplorerFact label="Status" value={row?.status || "..."} />
          <ExplorerFact label="Columns" value={row?.columnCount ?? "..."} />
          <ExplorerFact label="Rows" value={row?.numRows ?? "..."} />
          {result?.state === "ok" ? (
            <ExplorerFact
              label="Cache"
              value={`${result.cacheStatus} · ${formatBytes(result.bytes)}`}
            />
          ) : null}
        </div>
        {result?.state === "error" ? (
          <ErrorNotice message={result.message} />
        ) : (
          <pre className="max-h-[620px] overflow-auto rounded-md bg-zinc-950 p-3 text-xs leading-5 text-zinc-50">
            {detail ? prettyJson(detail) : "{}"}
          </pre>
        )}
      </div>
    </Surface>
  );
}

function ErrorNotice({ message }: { message: string }): React.ReactElement {
  return (
    <p className="m-4 rounded-md border border-amber-200 bg-amber-50 p-3 text-sm font-semibold text-amber-900">
      {message}
    </p>
  );
}

function ExplorerFact({ label, value }: { label: string; value: string }): React.ReactElement {
  return (
    <div className="rounded-md border border-zinc-200 bg-zinc-50 p-3">
      <p className="text-xs font-bold uppercase text-zinc-500">{label}</p>
      <p className="mt-1 break-all font-mono text-xs text-zinc-900">{value}</p>
    </div>
  );
}

function metadataCacheKeyFromResponse(
  response: OperatorResponse<WorkbenchActionData> | undefined
): ExplorerMetadataCacheKey | null {
  const result = mcpResult(response?.data.mcp_response);
  if (!isRecord(result) || !isRecord(result["metadata_cache_key"])) {
    return null;
  }
  const key = result["metadata_cache_key"];
  if (
    typeof key["db_fingerprint"] !== "string" ||
    typeof key["profile"] !== "string" ||
    typeof key["user"] !== "string" ||
    typeof key["visible_schema"] !== "string" ||
    typeof key["serialization_contract_version"] !== "number"
  ) {
    return null;
  }
  return {
    db_fingerprint: key["db_fingerprint"],
    profile: key["profile"],
    user: key["user"],
    visible_schema: key["visible_schema"],
    serialization_contract_version:
      key["serialization_contract_version"] || ORACLE_METADATA_SERIALIZATION_CONTRACT_VERSION
  };
}

function explorerScopeForVisibleSchema(
  key: ExplorerMetadataCacheKey,
  visibleSchema: string
): ExplorerMetadataCacheKey {
  return {
    ...key,
    visible_schema: visibleSchema.trim() || key.visible_schema || "*"
  };
}

function cacheScopeToken(scope: ExplorerMetadataCacheKey | null): string {
  return scope ? JSON.stringify(scope) : "pending";
}

function connectedFromResponse(response: OperatorResponse<WorkbenchActionData> | undefined): boolean {
  const result = mcpResult(response?.data.mcp_response);
  return isRecord(result) && result["connected"] === true;
}

function schemaRowsFromResponse(
  response: OperatorResponse<WorkbenchActionData> | undefined
): ExplorerSchemaRow[] {
  const result = mcpResult(response?.data.mcp_response);
  const schemas = isRecord(result) && Array.isArray(result["schemas"]) ? result["schemas"] : [];
  return schemas
    .filter(isRecord)
    .map((row) => ({
      schemaName: cellText(row, "SCHEMA_NAME") ?? cellText(row, "schema_name") ?? "",
      objectCount: cellText(row, "OBJECT_COUNT") ?? cellText(row, "object_count") ?? "0"
    }))
    .filter((row) => row.schemaName.length > 0);
}

function objectRowsFromResponse(
  response: OperatorResponse<WorkbenchActionData> | undefined
): ExplorerObjectRow[] {
  const result = mcpResult(response?.data.mcp_response);
  const objects = isRecord(result) && Array.isArray(result["results"]) ? result["results"] : [];
  return objects.filter(isRecord).map((row) => ({
    owner: cellText(row, "owner") ?? "",
    objectName: cellText(row, "object_name") ?? "",
    objectType: cellText(row, "object_type") ?? "",
    status: cellText(row, "status") ?? "",
    numRows: cellText(row, "num_rows") ?? "...",
    columnCount: cellText(row, "column_count") ?? "...",
    lastAnalyzed: cellText(row, "last_analyzed") ?? "...",
    comment: cellText(row, "comment") ?? "",
    raw: row
  }));
}

function sourceRowsFromResponse(
  response: OperatorResponse<WorkbenchActionData> | undefined
): ExplorerSourceHitRow[] {
  const result = mcpResult(response?.data.mcp_response);
  const matches = isRecord(result) && Array.isArray(result["matches"]) ? result["matches"] : [];
  return matches.filter(isRecord).map((row) => ({
    owner: cellText(row, "owner") ?? "",
    name: cellText(row, "name") ?? "",
    objectType: cellText(row, "type") ?? "",
    line: cellText(row, "line") ?? "...",
    text: cellText(row, "text") ?? "",
    raw: row
  }));
}

function rowRef(row: ExplorerObjectRow): ExplorerObjectRef {
  return {
    owner: row.owner,
    name: row.objectName,
    objectType: row.objectType
  };
}

function objectRefKey(ref: ExplorerObjectRef): string {
  return `${ref.owner}.${ref.name}:${ref.objectType}`;
}

function cellText(row: Record<string, unknown>, key: string): string | null {
  const value = row[key] ?? row[key.toUpperCase()] ?? row[key.toLowerCase()];
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (isRecord(value) && typeof value["value"] === "string") {
    return value["value"];
  }
  return null;
}

function canReadSource(objectType: string): boolean {
  return [
    "PACKAGE",
    "PACKAGE BODY",
    "PROCEDURE",
    "FUNCTION",
    "TRIGGER",
    "TYPE",
    "TYPE BODY"
  ].includes(objectType.toUpperCase());
}

function cacheStatusTone(
  status: ExplorerCacheStatus | "cold" | undefined
): "neutral" | "ok" | "warn" | "off" | "info" {
  switch (status) {
    case "hit":
      return "ok";
    case "stale":
    case "bypass":
      return "warn";
    case "miss":
      return "info";
    case "cold":
    case undefined:
      return "off";
  }
}

function formatBytes(value: number): string {
  if (value < 1024) {
    return `${value} B`;
  }
  if (value < 1024 * 1024) {
    return `${Math.round(value / 1024)} KiB`;
  }
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

function clampChars(value: number): number {
  if (!Number.isFinite(value)) {
    return 40_000;
  }
  return Math.min(1_000_000, Math.max(1_000, Math.trunc(value)));
}

const reviewUnits: Array<{ id: ChangeProposalApplyUnit; label: string }> = [
  { id: "dml", label: "DML" },
  { id: "ddl", label: "DDL" },
  { id: "read", label: "Read" }
];

type ReviewResult =
  | {
      state: "ok";
      label: string;
      response: unknown;
    }
  | {
      state: "error";
      label: string;
      message: string;
    };

function ReviewsPage(): React.ReactElement {
  const [filter, setFilter] = React.useState("");
  const [selectedId, setSelectedId] = React.useState("");
  const [profile, setProfile] = React.useState("prod");
  const [author, setAuthor] = React.useState<ChangeProposalAuthorKind>("agent");
  const [title, setTitle] = React.useState("Change proposal");
  const [unit, setUnit] = React.useState<ChangeProposalApplyUnit>("dml");
  const [sqlTemplate, setSqlTemplate] = React.useState(
    "UPDATE accounts SET status = :1 WHERE id = :2"
  );
  const [bindsJson, setBindsJson] = React.useState('[\"HOLD\", 42]');
  const [draftCommit, setDraftCommit] = React.useState(false);
  const [captureDbmsOutput, setCaptureDbmsOutput] = React.useState(false);
  const [laneId, setLaneId] = React.useState("");
  const [confirm, setConfirm] = React.useState("");
  const [applyCommit, setApplyCommit] = React.useState(true);
  const [lastResult, setLastResult] = React.useState<ReviewResult | null>(null);

  const session = useQuery({
    queryKey: ["dashboard-session"],
    queryFn: fetchDashboardSession,
    staleTime: 60_000,
    refetchInterval: 60_000,
    retry: 1
  });
  const proposalsQuery = useQuery({
    queryKey: ["change-proposals"],
    queryFn: fetchChangeProposals,
    refetchInterval: 10_000
  });
  const proposals = proposalsQuery.data?.data.proposals ?? [];
  const filtered = React.useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) {
      return proposals;
    }
    return proposals.filter((proposal) => proposalSearchText(proposal).includes(needle));
  }, [filter, proposals]);
  const selected =
    proposals.find((proposal) => proposal.id === selectedId) ?? filtered[0] ?? proposals[0] ?? null;
  const needsConfirm = selected?.statements.some((statement) => statement.unit !== "read") ?? false;

  React.useEffect(() => {
    if (!selectedId && filtered[0]) {
      setSelectedId(filtered[0].id);
    }
  }, [filtered, selectedId]);

  const draftMutation = useMutation({
    mutationFn: async () => {
      if (!session.data) {
        throw new Error("dashboard session is not ready");
      }
      const binds = parseBindsJson(bindsJson);
      return draftChangeProposal(session.data, {
        profile: profile.trim(),
        author,
        title: title.trim() || undefined,
        statements: [
          {
            sql_template: sqlTemplate.trim(),
            binds,
            unit,
            commit: draftCommit,
            capture_dbms_output: captureDbmsOutput
          }
        ]
      });
    },
    onSuccess: (response) => {
      setLastResult({ state: "ok", label: "Draft", response });
      setSelectedId(response.data.proposal.id);
      queryClient.invalidateQueries({ queryKey: ["change-proposals"] });
    },
    onError: (error) => {
      setLastResult({
        state: "error",
        label: "Draft",
        message: error instanceof Error ? error.message : "proposal draft failed"
      });
    }
  });

  const applyMutation = useMutation({
    mutationFn: async () => {
      if (!session.data) {
        throw new Error("dashboard session is not ready");
      }
      if (!selected) {
        throw new Error("select a proposal");
      }
      return applyChangeProposal(session.data, {
        proposalId: selected.id,
        laneId,
        confirm,
        commit: applyCommit
      });
    },
    onSuccess: (response) => {
      setLastResult({ state: "ok", label: "Apply", response });
      clearExplorerMetadataCache();
      queryClient.invalidateQueries({ queryKey: ["explorer"] });
      queryClient.invalidateQueries({ queryKey: ["operator-metrics"] });
      queryClient.invalidateQueries({ queryKey: ["audit-tail"] });
    },
    onError: (error) => {
      setLastResult({
        state: "error",
        label: "Apply",
        message: error instanceof Error ? error.message : "proposal apply failed"
      });
    }
  });

  const canDraft =
    session.status === "success" &&
    profile.trim().length > 0 &&
    sqlTemplate.trim().length > 0 &&
    !draftMutation.isPending;
  const canApply =
    session.status === "success" &&
    Boolean(selected) &&
    !applyMutation.isPending &&
    (!needsConfirm || confirm.trim().length > 0);

  return (
    <PageFrame
      title="Reviews"
      eyebrow="Change Review"
      description="Profile-scoped SQL proposals with apply-time guard checks."
    >
      <div className="grid gap-4 xl:grid-cols-[minmax(320px,0.8fr)_minmax(0,1.2fr)]">
        <Surface className="overflow-hidden">
          <div className="border-b border-zinc-200 p-4">
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0">
                <h3 className="flex items-center gap-2 text-base font-bold text-zinc-950">
                  <GitPullRequest className="size-4" aria-hidden="true" />
                  Proposals
                </h3>
                <p className="mt-1 truncate text-sm text-zinc-500">
                  {proposalsQuery.isFetching ? "sync" : `${formatNumber(filtered.length)} visible`}
                </p>
              </div>
              <Badge tone={proposalsQuery.isError ? "warn" : proposalsQuery.data ? "ok" : "info"}>
                {proposalsQuery.isError ? "blocked" : proposalsQuery.data ? "ready" : "sync"}
              </Badge>
            </div>
            <label className="mt-4 block">
              <span className="mb-2 block text-sm font-bold text-zinc-700">Filter</span>
              <input
                className="h-10 w-full rounded-md border border-zinc-300 px-3 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                value={filter}
                onChange={(event) => setFilter(event.target.value)}
                placeholder="profile, title, SQL"
              />
            </label>
          </div>
          <div className="max-h-[720px] overflow-auto">
            {filtered.length === 0 ? (
              <div className="px-4 py-8 text-sm font-semibold text-zinc-500">No proposals</div>
            ) : (
              filtered.map((proposal) => (
                <button
                  key={proposal.id}
                  type="button"
                  className={cn(
                    "block w-full border-b border-zinc-200 px-4 py-3 text-left transition-colors hover:bg-zinc-50",
                    selected?.id === proposal.id ? "bg-emerald-50" : "bg-white"
                  )}
                  onClick={() => setSelectedId(proposal.id)}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="min-w-0 truncate text-sm font-bold text-zinc-950">
                      {proposal.title}
                    </span>
                    <Badge tone={proposalLevelTone(proposal)}>{proposal.profile}</Badge>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-2 text-xs font-semibold text-zinc-500">
                    <span>{proposal.author}</span>
                    <span>{formatNumber(proposal.statement_count)} stmt</span>
                    <span>{proposal.updated_at}</span>
                  </div>
                </button>
              ))
            )}
          </div>
        </Surface>

        <div className="space-y-4">
          <Surface className="p-4">
            <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_180px]">
              <label className="block">
                <span className="mb-2 block text-sm font-bold text-zinc-700">Title</span>
                <input
                  className="h-10 w-full rounded-md border border-zinc-300 px-3 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                  value={title}
                  onChange={(event) => setTitle(event.target.value)}
                />
              </label>
              <label className="block">
                <span className="mb-2 block text-sm font-bold text-zinc-700">Profile</span>
                <input
                  className="h-10 w-full rounded-md border border-zinc-300 px-3 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                  value={profile}
                  onChange={(event) => setProfile(event.target.value)}
                />
              </label>
            </div>
            <div className="mt-4 flex flex-wrap gap-2" role="tablist" aria-label="proposal author">
              {(["agent", "human"] as ChangeProposalAuthorKind[]).map((item) => (
                <Button
                  key={item}
                  type="button"
                  variant={author === item ? "primary" : "secondary"}
                  onClick={() => setAuthor(item)}
                >
                  {item}
                </Button>
              ))}
            </div>
            <label className="mt-4 block">
              <span className="mb-2 block text-sm font-bold text-zinc-700">SQL Template</span>
              <textarea
                className="min-h-[220px] w-full resize-y rounded-md border border-zinc-300 bg-zinc-950 p-3 font-mono text-sm leading-6 text-zinc-50 outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                spellCheck={false}
                value={sqlTemplate}
                onChange={(event) => setSqlTemplate(event.target.value)}
              />
            </label>
            <label className="mt-4 block">
              <span className="mb-2 block text-sm font-bold text-zinc-700">Binds</span>
              <textarea
                className="min-h-[92px] w-full resize-y rounded-md border border-zinc-300 p-3 font-mono text-sm leading-5 outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                spellCheck={false}
                value={bindsJson}
                onChange={(event) => setBindsJson(event.target.value)}
              />
            </label>
            <div className="mt-4 flex flex-wrap items-center gap-3">
              <div className="flex flex-wrap gap-2" role="tablist" aria-label="proposal unit">
                {reviewUnits.map((item) => (
                  <Button
                    key={item.id}
                    type="button"
                    variant={unit === item.id ? "primary" : "secondary"}
                    onClick={() => setUnit(item.id)}
                  >
                    {item.label}
                  </Button>
                ))}
              </div>
              <label className="flex min-h-9 items-center gap-2 text-sm font-semibold text-zinc-700">
                <input
                  className="size-4 rounded border-zinc-300 text-emerald-700 focus:ring-emerald-600"
                  type="checkbox"
                  checked={draftCommit}
                  onChange={(event) => setDraftCommit(event.target.checked)}
                />
                Commit
              </label>
              <label className="flex min-h-9 items-center gap-2 text-sm font-semibold text-zinc-700">
                <input
                  className="size-4 rounded border-zinc-300 text-emerald-700 focus:ring-emerald-600"
                  type="checkbox"
                  checked={captureDbmsOutput}
                  onChange={(event) => setCaptureDbmsOutput(event.target.checked)}
                />
                DBMS_OUTPUT
              </label>
              <Button
                type="button"
                variant="primary"
                disabled={!canDraft}
                onClick={() => draftMutation.mutate()}
              >
                <GitPullRequest className="size-4" aria-hidden="true" />
                Draft
              </Button>
            </div>
          </Surface>

          <Surface className="p-4">
            <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
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
                <span className="mb-2 block text-sm font-bold text-zinc-700">Confirm</span>
                <input
                  className="h-10 w-full rounded-md border border-zinc-300 px-3 font-mono text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                  value={confirm}
                  onChange={(event) => setConfirm(event.target.value)}
                  placeholder="preview grant"
                />
              </label>
            </div>
            {selected ? <ProposalStatementTable proposal={selected} /> : null}
            <div className="mt-4 flex flex-wrap items-center gap-3">
              <label className="flex min-h-9 items-center gap-2 text-sm font-semibold text-zinc-700">
                <input
                  className="size-4 rounded border-zinc-300 text-emerald-700 focus:ring-emerald-600"
                  type="checkbox"
                  checked={applyCommit}
                  onChange={(event) => setApplyCommit(event.target.checked)}
                />
                Commit
              </label>
              <Button
                type="button"
                variant="primary"
                disabled={!canApply}
                onClick={() => applyMutation.mutate()}
              >
                <CheckCircle2 className="size-4" aria-hidden="true" />
                Apply
              </Button>
              <Badge tone={session.status === "success" ? "ok" : session.status === "error" ? "warn" : "info"}>
                {session.status === "success" ? "paired" : session.status === "error" ? "blocked" : "pairing"}
              </Badge>
            </div>
          </Surface>

          <ReviewResultPanel result={lastResult} pending={draftMutation.isPending || applyMutation.isPending} />
        </div>
      </div>
    </PageFrame>
  );
}

function ProposalStatementTable({ proposal }: { proposal: ChangeProposalView }): React.ReactElement {
  return (
    <div className="mt-4 overflow-hidden rounded-md border border-zinc-200">
      <table className="w-full border-collapse text-sm">
        <thead className="bg-zinc-50 text-left text-xs uppercase text-zinc-500">
          <tr>
            <th className="px-3 py-2 font-bold">Unit</th>
            <th className="px-3 py-2 font-bold">Template</th>
            <th className="px-3 py-2 font-bold">Level</th>
            <th className="px-3 py-2 font-bold">Binds</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-200">
          {proposal.statements.map((statement) => (
            <tr key={statement.id}>
              <td className="px-3 py-2">
                <Badge tone={statement.unit === "ddl" ? "warn" : statement.unit === "dml" ? "info" : "ok"}>
                  {statement.unit}
                </Badge>
              </td>
              <td className="max-w-[360px] truncate px-3 py-2 font-mono text-xs text-zinc-900">
                {statement.sql_template}
              </td>
              <td className="px-3 py-2 font-semibold text-zinc-700">
                {statement.draft_verdict.required_level ?? "none"}
              </td>
              <td className="px-3 py-2 font-semibold text-zinc-700">
                {formatNumber(statement.bind_count)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ReviewResultPanel({
  result,
  pending
}: {
  result: ReviewResult | null;
  pending: boolean;
}): React.ReactElement {
  return (
    <Surface className="overflow-hidden">
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
      <div className="p-4">
        {result?.state === "error" ? (
          <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm font-semibold text-amber-900">
            {result.message}
          </div>
        ) : (
          <pre className="max-h-[560px] overflow-auto rounded-md bg-zinc-950 p-3 text-xs leading-5 text-zinc-50">
            {result?.state === "ok" ? prettyJson(result.response) : "{}"}
          </pre>
        )}
      </div>
    </Surface>
  );
}

function parseBindsJson(text: string): unknown[] {
  const trimmed = text.trim();
  if (!trimmed) {
    return [];
  }
  const parsed = JSON.parse(trimmed) as unknown;
  if (!Array.isArray(parsed)) {
    throw new Error("binds must be a JSON array");
  }
  return parsed;
}

function proposalSearchText(proposal: ChangeProposalView): string {
  return [
    proposal.title,
    proposal.profile,
    proposal.author,
    proposal.id,
    ...proposal.statements.map((statement) => statement.sql_template)
  ]
    .join(" ")
    .toLowerCase();
}

function proposalLevelTone(proposal: ChangeProposalView): "neutral" | "ok" | "warn" | "off" | "info" {
  if (proposal.statements.some((statement) => statement.unit === "ddl")) {
    return "warn";
  }
  if (proposal.statements.some((statement) => statement.unit === "dml")) {
    return "info";
  }
  return "ok";
}

const workbenchModes: Array<{ id: WorkbenchMode; label: string }> = [
  { id: "classify_only", label: "Classify" },
  { id: "read_query", label: "Read" },
  { id: "dml_preview_confirm", label: "DML" },
  { id: "ddl_plan_confirm", label: "DDL" }
];

type WorkbenchAction = "preview" | "read" | "rollback_preview" | "commit";

type WorkbenchIdeAction = "parse" | "analyze" | "lineage" | "lint" | "docs" | "impact";

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

type PlsqlPosition = {
  line: number;
  column: number;
  offset: number;
};

type PlsqlSpan = {
  start: PlsqlPosition;
  end: PlsqlPosition;
};

type PlsqlDefinition = {
  name: string;
  kind: string;
  span: PlsqlSpan | null;
};

type IdentifierOccurrence = {
  offset: number;
  endOffset: number;
  line: number;
  column: number;
  preview: string;
};

type RefactorPreview = {
  occurrences: IdentifierOccurrence[];
  preview: string;
};

function WorkbenchPage(): React.ReactElement {
  const [mode, setMode] = React.useState<WorkbenchMode>("classify_only");
  const [sql, setSql] = React.useState("SELECT * FROM dual");
  const [laneId, setLaneId] = React.useState("");
  const [confirm, setConfirm] = React.useState("");
  const [maxRows, setMaxRows] = React.useState(100);
  const [captureDbmsOutput, setCaptureDbmsOutput] = React.useState(false);
  const [lastResult, setLastResult] = React.useState<WorkbenchResult | null>(null);
  const [lastIdeResult, setLastIdeResult] = React.useState<WorkbenchResult | null>(null);
  const [projectRoot, setProjectRoot] = React.useState("");
  const [plsqlTarget, setPlsqlTarget] = React.useState("");
  const [lineageDirection, setLineageDirection] = React.useState<
    "upstream" | "downstream" | "bidirectional"
  >("bidirectional");
  const [lineageDepth, setLineageDepth] = React.useState(2);
  const [identifier, setIdentifier] = React.useState("");
  const [replacement, setReplacement] = React.useState("");
  const [changesetJson, setChangesetJson] = React.useState(
    '{\n  "objects": [],\n  "unclassified_files": []\n}'
  );
  const sqlEditorRef = React.useRef<HTMLTextAreaElement | null>(null);

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
      if (kind === "commit") {
        clearExplorerMetadataCache();
        queryClient.invalidateQueries({ queryKey: ["explorer"] });
      }
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

  const ideAction = useMutation({
    mutationFn: async (kind: WorkbenchIdeAction) => {
      if (!session.data) {
        throw new Error("dashboard session is not ready");
      }
      const request = workbenchIdeRequest(kind, {
        source: sql,
        laneId,
        projectRoot,
        target: plsqlTarget,
        direction: lineageDirection,
        maxDepth: lineageDepth,
        changesetJson
      });
      return runWorkbenchPlsqlTool(session.data, request);
    },
    onSuccess: (response, kind) => {
      setLastIdeResult({ state: "ok", label: ideActionLabel(kind), response });
    },
    onError: (error, kind) => {
      setLastIdeResult({
        state: "error",
        label: ideActionLabel(kind),
        message: error instanceof Error ? error.message : "PL/SQL analysis failed"
      });
    }
  });

  const canSubmit = sql.trim().length > 0 && session.status === "success" && !action.isPending;
  const canRunIde =
    sql.trim().length > 0 && session.status === "success" && !ideAction.isPending;
  const confirmReady = confirm.trim().length > 0;
  const sessionTone = session.status === "success" ? "ok" : session.status === "error" ? "warn" : "info";
  const definitions =
    lastIdeResult?.state === "ok" && lastIdeResult.response.data.mcp_tool === "oracle_plsql_parse"
      ? plsqlDefinitionsFromResponse(lastIdeResult.response)
      : [];
  const usageRows = React.useMemo(
    () => identifierOccurrences(sql, identifier),
    [identifier, sql]
  );
  const refactorPreview = React.useMemo(
    () => buildRefactorPreview(sql, identifier, replacement),
    [identifier, replacement, sql]
  );
  const jumpToRange = React.useCallback((start: number, end: number) => {
    const editor = sqlEditorRef.current;
    if (!editor) {
      return;
    }
    editor.focus();
    editor.setSelectionRange(start, Math.max(start, end));
  }, []);
  const useSelectionAsIdentifier = React.useCallback(() => {
    const editor = sqlEditorRef.current;
    if (!editor) {
      return;
    }
    const selected = sql.slice(editor.selectionStart, editor.selectionEnd).trim();
    if (selected) {
      setIdentifier(selected);
      setPlsqlTarget(selected.toUpperCase());
    }
  }, [sql]);

  return (
    <PageFrame
      title="Workbench"
      eyebrow="Guarded SQL"
      description="Human-in-the-loop SQL through the same classifier, lane gate, confirmation, and audit path as MCP tools."
    >
      <div className="grid gap-4 2xl:grid-cols-[minmax(0,1.1fr)_minmax(340px,0.6fr)_minmax(360px,0.75fr)]">
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
                ref={sqlEditorRef}
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

        <WorkbenchIdePanel
          canRun={canRunIde}
          changesetJson={changesetJson}
          definitions={definitions}
          identifier={identifier}
          lineageDepth={lineageDepth}
          lineageDirection={lineageDirection}
          onJump={jumpToRange}
          onRun={(kind) => ideAction.mutate(kind)}
          onUseSelection={useSelectionAsIdentifier}
          pending={ideAction.isPending}
          projectRoot={projectRoot}
          refactorPreview={refactorPreview}
          replacement={replacement}
          result={lastIdeResult}
          target={plsqlTarget}
          usageRows={usageRows}
          setChangesetJson={setChangesetJson}
          setIdentifier={setIdentifier}
          setLineageDepth={setLineageDepth}
          setLineageDirection={setLineageDirection}
          setProjectRoot={setProjectRoot}
          setReplacement={setReplacement}
          setTarget={setPlsqlTarget}
        />

        <WorkbenchResultPanel result={lastResult} pending={action.isPending} />
      </div>
    </PageFrame>
  );
}

function WorkbenchIdePanel({
  canRun,
  changesetJson,
  definitions,
  identifier,
  lineageDepth,
  lineageDirection,
  onJump,
  onRun,
  onUseSelection,
  pending,
  projectRoot,
  refactorPreview,
  replacement,
  result,
  target,
  usageRows,
  setChangesetJson,
  setIdentifier,
  setLineageDepth,
  setLineageDirection,
  setProjectRoot,
  setReplacement,
  setTarget
}: {
  canRun: boolean;
  changesetJson: string;
  definitions: PlsqlDefinition[];
  identifier: string;
  lineageDepth: number;
  lineageDirection: "upstream" | "downstream" | "bidirectional";
  onJump: (start: number, end: number) => void;
  onRun: (kind: WorkbenchIdeAction) => void;
  onUseSelection: () => void;
  pending: boolean;
  projectRoot: string;
  refactorPreview: RefactorPreview;
  replacement: string;
  result: WorkbenchResult | null;
  target: string;
  usageRows: IdentifierOccurrence[];
  setChangesetJson: React.Dispatch<React.SetStateAction<string>>;
  setIdentifier: React.Dispatch<React.SetStateAction<string>>;
  setLineageDepth: React.Dispatch<React.SetStateAction<number>>;
  setLineageDirection: React.Dispatch<
    React.SetStateAction<"upstream" | "downstream" | "bidirectional">
  >;
  setProjectRoot: React.Dispatch<React.SetStateAction<string>>;
  setReplacement: React.Dispatch<React.SetStateAction<string>>;
  setTarget: React.Dispatch<React.SetStateAction<string>>;
}): React.ReactElement {
  const projectReady = canRun && projectRoot.trim().length > 0;
  const lineageReady = projectReady && target.trim().length > 0;
  return (
    <Surface className="min-h-[520px] overflow-hidden">
      <div className="flex items-center justify-between gap-3 border-b border-zinc-200 px-4 py-3">
        <div className="min-w-0">
          <h3 className="flex items-center gap-2 text-base font-bold text-zinc-950">
            <Code2 className="size-4" aria-hidden="true" />
            PL/SQL IDE
          </h3>
          <p className="mt-1 truncate text-sm text-zinc-500">
            {pending ? "analysis in flight" : result ? result.label : "idle"}
          </p>
        </div>
        <Badge tone={pending ? "info" : result?.state === "error" ? "warn" : result ? "ok" : "off"}>
          {pending ? "running" : result?.state ?? "empty"}
        </Badge>
      </div>

      <div className="space-y-4 p-4">
        <div className="grid gap-3">
          <label className="block">
            <span className="mb-2 block text-sm font-bold text-zinc-700">Project Root</span>
            <input
              className="h-10 w-full rounded-md border border-zinc-300 px-3 font-mono text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
              value={projectRoot}
              onChange={(event) => setProjectRoot(event.target.value)}
              placeholder="/path/to/plsql/project"
            />
          </label>
          <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_150px_110px]">
            <label className="block">
              <span className="mb-2 block text-sm font-bold text-zinc-700">Target</span>
              <input
                className="h-10 w-full rounded-md border border-zinc-300 px-3 font-mono text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                placeholder="APP.PACKAGE"
              />
            </label>
            <label className="block">
              <span className="mb-2 block text-sm font-bold text-zinc-700">Direction</span>
              <select
                className="h-10 w-full rounded-md border border-zinc-300 bg-white px-3 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                value={lineageDirection}
                onChange={(event) =>
                  setLineageDirection(
                    event.target.value as "upstream" | "downstream" | "bidirectional"
                  )
                }
              >
                <option value="bidirectional">Both</option>
                <option value="downstream">Downstream</option>
                <option value="upstream">Upstream</option>
              </select>
            </label>
            <label className="block">
              <span className="mb-2 block text-sm font-bold text-zinc-700">Depth</span>
              <input
                className="h-10 w-full rounded-md border border-zinc-300 px-3 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                min={0}
                max={20}
                type="number"
                value={lineageDepth}
                onChange={(event) => setLineageDepth(clampDepth(event.target.valueAsNumber))}
              />
            </label>
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="secondary" disabled={!canRun} onClick={() => onRun("parse")}>
            <Code2 className="size-4" aria-hidden="true" />
            Parse
          </Button>
          <Button type="button" variant="secondary" disabled={!canRun} onClick={() => onRun("docs")}>
            <FileClock className="size-4" aria-hidden="true" />
            Docs
          </Button>
          <Button
            type="button"
            variant="secondary"
            disabled={!projectReady}
            onClick={() => onRun("analyze")}
          >
            <RefreshCcw className="size-4" aria-hidden="true" />
            Analyze
          </Button>
          <Button
            type="button"
            variant="secondary"
            disabled={!lineageReady}
            onClick={() => onRun("lineage")}
          >
            <GitPullRequest className="size-4" aria-hidden="true" />
            Dependencies
          </Button>
          <Button
            type="button"
            variant="secondary"
            disabled={!projectReady}
            onClick={() => onRun("lint")}
          >
            <ShieldCheck className="size-4" aria-hidden="true" />
            Lint
          </Button>
          <Button type="button" variant="secondary" disabled={!canRun} onClick={() => onRun("impact")}>
            <AlertTriangle className="size-4" aria-hidden="true" />
            Impact
          </Button>
        </div>

        <label className="block">
          <span className="mb-2 block text-sm font-bold text-zinc-700">ChangeSet</span>
          <textarea
            className="min-h-24 w-full resize-y rounded-md border border-zinc-300 bg-zinc-50 p-3 font-mono text-xs leading-5 text-zinc-900 outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
            spellCheck={false}
            value={changesetJson}
            onChange={(event) => setChangesetJson(event.target.value)}
          />
        </label>

        <div className="rounded-md border border-zinc-200 bg-zinc-50 p-3">
          <div className="flex items-center justify-between gap-3">
            <h4 className="text-sm font-bold text-zinc-950">Definitions</h4>
            <Badge tone={definitions.length > 0 ? "ok" : "off"}>{definitions.length}</Badge>
          </div>
          <div className="mt-3 max-h-44 space-y-2 overflow-auto">
            {definitions.length === 0 ? (
              <p className="text-sm font-semibold text-zinc-500">No parsed definitions</p>
            ) : (
              definitions.map((definition, index) => (
                <button
                  key={`${definition.name}-${definition.kind}-${index}`}
                  className="flex w-full items-center justify-between gap-3 rounded-md border border-zinc-200 bg-white px-3 py-2 text-left text-sm hover:bg-zinc-100 disabled:cursor-not-allowed disabled:opacity-60"
                  type="button"
                  disabled={!definition.span}
                  onClick={() =>
                    definition.span
                      ? onJump(definition.span.start.offset, definition.span.end.offset)
                      : undefined
                  }
                >
                  <span className="min-w-0">
                    <span className="block truncate font-mono font-semibold text-zinc-950">
                      {definition.name || "anonymous"}
                    </span>
                    <span className="block text-xs font-semibold text-zinc-500">
                      {definition.span
                        ? `${definition.span.start.line}:${definition.span.start.column}`
                        : "span unavailable"}
                    </span>
                  </span>
                  <Badge tone="info">{definition.kind}</Badge>
                </button>
              ))
            )}
          </div>
        </div>

        <div className="rounded-md border border-zinc-200 bg-zinc-50 p-3">
          <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <label className="block">
              <span className="mb-2 block text-sm font-bold text-zinc-700">Identifier</span>
              <input
                className="h-10 w-full rounded-md border border-zinc-300 px-3 font-mono text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                value={identifier}
                onChange={(event) => setIdentifier(event.target.value)}
                placeholder="PKG_NAME"
              />
            </label>
            <label className="block">
              <span className="mb-2 block text-sm font-bold text-zinc-700">Rename To</span>
              <input
                className="h-10 w-full rounded-md border border-zinc-300 px-3 font-mono text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-200"
                value={replacement}
                onChange={(event) => setReplacement(event.target.value)}
                placeholder="PKG_NAME_V2"
              />
            </label>
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Button type="button" variant="ghost" onClick={onUseSelection}>
              <Search className="size-4" aria-hidden="true" />
              Selection
            </Button>
            <Badge tone={usageRows.length > 0 ? "ok" : "off"}>{usageRows.length} usages</Badge>
            <Badge tone={replacement.trim() ? "info" : "off"}>
              {replacement.trim() ? "preview" : "rename idle"}
            </Badge>
          </div>
          <div className="mt-3 max-h-36 space-y-2 overflow-auto">
            {usageRows.slice(0, 20).map((occurrence) => (
              <button
                key={`${occurrence.offset}-${occurrence.endOffset}`}
                className="block w-full rounded-md border border-zinc-200 bg-white px-3 py-2 text-left hover:bg-zinc-100"
                type="button"
                onClick={() => onJump(occurrence.offset, occurrence.endOffset)}
              >
                <span className="font-mono text-xs font-semibold text-zinc-500">
                  {occurrence.line}:{occurrence.column}
                </span>
                <span className="mt-1 block truncate font-mono text-xs text-zinc-900">
                  {occurrence.preview}
                </span>
              </button>
            ))}
          </div>
          <pre className="mt-3 max-h-40 overflow-auto rounded-md bg-zinc-950 p-3 text-xs leading-5 text-zinc-50">
            {refactorPreview.preview}
          </pre>
        </div>

        {result?.state === "error" ? (
          <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm font-semibold text-amber-900">
            {result.message}
          </div>
        ) : (
          <pre className="max-h-[360px] overflow-auto rounded-md bg-zinc-950 p-3 text-xs leading-5 text-zinc-50">
            {result?.state === "ok" ? prettyJson(result.response) : "{}"}
          </pre>
        )}
      </div>
    </Surface>
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

function sessionLevelSummary(response: OperatorResponse<WorkbenchActionData>): SessionLevelSummary {
  const result = mcpResult(response.data.mcp_response);
  const resultRecord = isRecord(result) ? result : {};
  const session = isRecord(resultRecord["session"]) ? resultRecord["session"] : {};
  const gate = isRecord(resultRecord["gate"]) ? resultRecord["gate"] : {};
  return {
    action: stringValue(resultRecord["action"], "unknown"),
    preview: stringValue(resultRecord["preview"], "false"),
    targetLevel: stringValue(resultRecord["target_level"], "READ_ONLY"),
    ttlSeconds: stringValue(resultRecord["ttl_seconds"], "0"),
    currentLevel: stringValue(session["current_level"], "unknown"),
    profileCeiling: stringValue(session["profile_ceiling"], "unknown"),
    gateDecision: stringValue(gate["decision"], "not_required"),
    confirm: confirmationFromResponse(response) ?? "none"
  };
}

function stringValue(value: unknown, fallback: string): string {
  if (value === null || value === undefined || value === "") {
    return fallback;
  }
  return String(value);
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

type WorkbenchIdeRequestInput = {
  source: string;
  laneId?: string;
  projectRoot: string;
  target: string;
  direction: "upstream" | "downstream" | "bidirectional";
  maxDepth: number;
  changesetJson: string;
};

function workbenchIdeRequest(
  action: WorkbenchIdeAction,
  input: WorkbenchIdeRequestInput
): {
  laneId?: string;
  tool: WorkbenchPlsqlTool;
  arguments: Record<string, unknown>;
  idempotencyPrefix: string;
} {
  const projectRoot = input.projectRoot.trim();
  const target = input.target.trim();
  switch (action) {
    case "parse":
      return {
        laneId: input.laneId,
        tool: "oracle_plsql_parse",
        arguments: { source: input.source },
        idempotencyPrefix: "workbench-plsql-parse"
      };
    case "docs":
      return {
        laneId: input.laneId,
        tool: "oracle_plsql_doc",
        arguments: { source: input.source, format: "json" },
        idempotencyPrefix: "workbench-plsql-doc"
      };
    case "analyze":
      if (!projectRoot) {
        throw new Error("project root is required");
      }
      return {
        laneId: input.laneId,
        tool: "oracle_plsql_analyze",
        arguments: { project_root: projectRoot },
        idempotencyPrefix: "workbench-plsql-analyze"
      };
    case "lineage":
      if (!projectRoot || !target) {
        throw new Error("project root and target are required");
      }
      return {
        laneId: input.laneId,
        tool: "oracle_plsql_lineage",
        arguments: {
          project_root: projectRoot,
          target,
          direction: input.direction,
          max_depth: input.maxDepth
        },
        idempotencyPrefix: "workbench-plsql-lineage"
      };
    case "lint":
      if (!projectRoot) {
        throw new Error("project root is required");
      }
      return {
        laneId: input.laneId,
        tool: "oracle_plsql_sast",
        arguments: { project_root: projectRoot, format: "json" },
        idempotencyPrefix: "workbench-plsql-sast"
      };
    case "impact":
      return {
        laneId: input.laneId,
        tool: "oracle_plsql_what_breaks",
        arguments: {
          changeset: parseChangeset(input.changesetJson),
          mode: "source_only"
        },
        idempotencyPrefix: "workbench-plsql-impact"
      };
  }
}

function parseChangeset(raw: string): Record<string, unknown> {
  const parsed = JSON.parse(raw) as unknown;
  if (!isRecord(parsed)) {
    throw new Error("changeset must be a JSON object");
  }
  return parsed;
}

function ideActionLabel(action: WorkbenchIdeAction): string {
  switch (action) {
    case "parse":
      return "Parse";
    case "analyze":
      return "Analyze";
    case "lineage":
      return "Dependencies";
    case "lint":
      return "Lint";
    case "docs":
      return "Docs";
    case "impact":
      return "Impact";
  }
}

function plsqlDefinitionsFromResponse(
  response: OperatorResponse<WorkbenchActionData>
): PlsqlDefinition[] {
  const result = mcpResult(response.data.mcp_response);
  if (!isRecord(result) || !Array.isArray(result["declarations"])) {
    return [];
  }
  return result["declarations"].flatMap((item): PlsqlDefinition[] => {
    if (!isRecord(item)) {
      return [];
    }
    return [
      {
        name: stringValue(item["name"], ""),
        kind: stringValue(item["kind"], "Unknown"),
        span: plsqlSpanFromValue(item["span"])
      }
    ];
  });
}

function plsqlSpanFromValue(value: unknown): PlsqlSpan | null {
  if (!isRecord(value)) {
    return null;
  }
  const start = plsqlPositionFromValue(value["start"]);
  const end = plsqlPositionFromValue(value["end"]);
  return start && end ? { start, end } : null;
}

function plsqlPositionFromValue(value: unknown): PlsqlPosition | null {
  if (!isRecord(value)) {
    return null;
  }
  const line = numberField(value, "line");
  const column = numberField(value, "column");
  const offset = numberField(value, "offset");
  if (line === null || column === null || offset === null) {
    return null;
  }
  return { line, column, offset };
}

function identifierOccurrences(source: string, identifier: string): IdentifierOccurrence[] {
  const needle = identifier.trim();
  if (!needle) {
    return [];
  }
  const lowerSource = source.toLocaleLowerCase();
  const lowerNeedle = needle.toLocaleLowerCase();
  const occurrences: IdentifierOccurrence[] = [];
  let cursor = 0;
  while (cursor < source.length) {
    const offset = lowerSource.indexOf(lowerNeedle, cursor);
    if (offset < 0) {
      break;
    }
    const endOffset = offset + needle.length;
    const before = offset > 0 ? source[offset - 1] : "";
    const after = endOffset < source.length ? source[endOffset] : "";
    if (!isPlsqlIdentifierChar(before) && !isPlsqlIdentifierChar(after)) {
      const location = sourceLocationAtOffset(source, offset);
      occurrences.push({
        offset,
        endOffset,
        line: location.line,
        column: location.column,
        preview: linePreviewAtOffset(source, offset)
      });
    }
    cursor = endOffset;
  }
  return occurrences;
}

function buildRefactorPreview(
  source: string,
  identifier: string,
  replacement: string
): RefactorPreview {
  const occurrences = identifierOccurrences(source, identifier);
  if (!identifier.trim() || !replacement.trim() || occurrences.length === 0) {
    return { occurrences, preview: "{}" };
  }
  let cursor = 0;
  const chunks: string[] = [];
  for (const occurrence of occurrences) {
    chunks.push(source.slice(cursor, occurrence.offset), replacement);
    cursor = occurrence.endOffset;
  }
  chunks.push(source.slice(cursor));
  const preview = chunks.join("");
  return {
    occurrences,
    preview: preview.length > 2400 ? `${preview.slice(0, 2400)}\n...` : preview
  };
}

function sourceLocationAtOffset(source: string, offset: number): { line: number; column: number } {
  let line = 1;
  let column = 1;
  const end = Math.min(Math.max(0, offset), source.length);
  for (let index = 0; index < end; index += 1) {
    if (source[index] === "\n") {
      line += 1;
      column = 1;
    } else {
      column += 1;
    }
  }
  return { line, column };
}

function linePreviewAtOffset(source: string, offset: number): string {
  const start = Math.max(0, source.lastIndexOf("\n", offset - 1) + 1);
  const endIndex = source.indexOf("\n", offset);
  const end = endIndex >= 0 ? endIndex : source.length;
  return source.slice(start, end).trim();
}

function isPlsqlIdentifierChar(value: string): boolean {
  if (!value) {
    return false;
  }
  const code = value.charCodeAt(0);
  return (
    (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    value === "_" ||
    value === "$" ||
    value === "#"
  );
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

function clampDepth(value: number): number {
  if (!Number.isFinite(value)) {
    return 2;
  }
  return Math.min(20, Math.max(0, Math.trunc(value)));
}

function clampTtl(value: number): number {
  if (!Number.isFinite(value)) {
    return 900;
  }
  return Math.min(3600, Math.max(1, Math.trunc(value)));
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
