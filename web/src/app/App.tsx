import * as React from "react";
import { createRoot } from "react-dom/client";
import {
  createRootRoute,
  createRoute,
  createRouter,
  Link,
  Outlet,
  RouterProvider,
  useBlocker,
  useNavigate,
  useSearch
} from "@tanstack/react-router";
import {
  QueryClientProvider,
  useMutation,
  useQuery
} from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
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
  Timer,
  Users,
  Wifi
} from "lucide-react";

import { Badge, Button, Surface } from "../components/ui/primitives";
import { cn } from "../lib/utils";
import { OMCP_SKIN } from "./skin";
import {
  CLEARANCE_LADDER,
  toMaskBadgeViewModel,
  toPolicyBadgeViewModel,
  toEditionTimelineViewModel,
  toVerdictProofViewModel,
  type DashboardTone,
} from "./presentation-model";
import {
  applyChangeProposal,
  draftSourceHistoryRevert,
  draftChangeProposal,
  executeWorkbenchSql,
  applyConfigDraft,
  cancelLane,
  coalesceAuditTimelineRecords,
  parseClassifierLadder,
  parseMaskCertificate,
  parsePolicyTightening,
  parseEditionProposals,
  parseVerdictProofs,
  fetchEditionProposals,
  type VerdictProofData,
  fetchActiveLanes,
  fetchClientCredentials,
  fetchDashboardSession,
  fetchChangeProposals,
  fetchChangeProposalDetail,
  fetchSourceHistory,
  fetchOperatorConfig,
  fetchOperatorHealth,
  fetchOperatorMetrics,
  previewConfigDraft,
  previewSchemaDiff,
  previewWorkbenchSql,
  readWorkbenchSql,
  revokeClientCredential,
  rotateClientCredential,
  runWorkbenchPlsqlTool,
  rollbackConfigDraft,
  setSessionLevel,
  type OperatorResponse,
  type AuditTailData,
  type AuditTailFilters,
  type AuditTailRecord,
  type ActiveLane,
  type ActiveLanesData,
  type CapacityLimitSource,
  type ChangeProposalListView,
  type ChangeProposalListData,
  type ChangeProposalView,
  type DashboardSession,
  type SchemaDiffExportData,
  type SchemaDiffObjectView,
  type SchemaDiffStepView,
  type SchemaSnapshotInput,
  type SourceSnapshotView,
  type SourceHistoryListData,
  type ClientCredentialRotateData,
  type ClientCredentialsData,
  type ClientCredentialStatus,
  type ClientCredentialView,
  type ExplorerCacheStatus,
  type ExplorerDetailLevel,
  type ExplorerMetadataCacheKey,
  type ExplorerObjectRef,
  type EditionProposalsData,
  type LaneRequestDuration,
  type MetricsSnapshot,
  type OperatingLevel,
  type OperatorHealthData,
  type OperatorCapacityData,
  type OperatorMetricsData,
  type OperatorEventEnvelope,
  type ClassifierLadderData,
  type ClassifierLadderVerdictKind,
  type ConfigApplyData,
  type ConfigDraftPreview,
  type ConfigFieldChange,
  type ConfigOpsStatusData,
  type ConfigProfileMetadata,
  cachedExplorerMetadata,
  clearExplorerMetadataCache,
  decodeOperatorOutcome,
  fetchAuditTail,
  fetchExplorerConnection,
  fetchExplorerDdl,
  fetchExplorerObjects,
  fetchExplorerSchemas,
  fetchExplorerSource,
  fetchExplorerSourceSearch,
  fetchLaneCapabilities,
  operatorOutcomeFromError,
  operatorResponseFromError,
  ORACLE_METADATA_SERIALIZATION_CONTRACT_VERSION,
  type OperatorOutcome,
  OperatorOutcomeError,
  type OperatorOutcomeState,
  type OperatorLaneTarget,
  type WorkbenchActionData,
  type WorkbenchMode,
  type WorkbenchPlsqlTool
} from "./operator-client";
import {
  BackgroundRefreshStatus,
  DashboardSessionBanner,
  LIVE_TELEMETRY_REFETCH_MS,
  createDashboardQueryClient,
  queryActivity,
  startOperatorEventStream,
  useDashboardAuthorityPurge,
  useAbsoluteExpiryCountdown,
  useDebouncedValue,
  type EventStreamStatus
} from "./dashboard-lifecycle";
import {
  CLIENT_ROTATION_MUTATION_KEY,
  absoluteExpiryIsActive,
  authoritativeQueryData,
  authoritativeMetric,
  collectionViewState,
  connectionHealthModel,
  configurationAuthority,
  dashboardAuthorityIdentity,
  elevationCompletionIsCurrent,
  laneCancelFailure,
  laneCancelSuccess,
  laneIdentity,
  nativeConnectionInfo,
  purgeClientRotationMutation,
  reconcileLaneSelection,
  resolveExactLane,
  sameLaneIdentity,
  sessionLevelSummary,
  sourceAvailability,
  type CollectionViewState,
  type ConnectionHealthSourceRow,
  type ConnectionHealthUiModel,
  type DashboardQueryStatus,
  type ElevationRequestBinding,
  type LaneCancelNotice,
  type LaneIdentity,
  type SessionLevelSummary
} from "./dashboard-view-state";

export {
  createDashboardQueryClient,
  dashboardSessionIsValidAt,
  expireDashboardAuthorityAfterSessionError,
  expireDashboardAuthority,
  LIVE_TELEMETRY_REFETCH_MS,
  queryActivity,
  startOperatorEventStream
} from "./dashboard-lifecycle";

const queryClient = createDashboardQueryClient();

const WHOLE_NUMBER_FORMATTER = new Intl.NumberFormat("en-US", { maximumFractionDigits: 0 });
const EMPTY_ACTIVE_LANES: ActiveLane[] = [];
const EMPTY_CHANGE_PROPOSALS: ChangeProposalListView[] = [];
const EMPTY_SOURCE_SNAPSHOTS: SourceSnapshotView[] = [];

export function authoritativeServerMode(
  status: DashboardQueryStatus,
  response: OperatorResponse<ActiveLanesData> | undefined
): boolean | null {
  return authoritativeQueryData(status, response)?.data.stateful ?? null;
}

function laneOptionValue(lane: ActiveLane): string {
  return JSON.stringify([lane.lane_id, lane.generation]);
}

function laneIdentityFromOption(
  lanes: readonly ActiveLane[],
  value: string
): LaneIdentity | null {
  const lane = lanes.find((candidate) => laneOptionValue(candidate) === value);
  return lane ? laneIdentity(lane) : null;
}

function laneOptionLabel(lane: ActiveLane): string {
  return `${lane.lane_id} | generation ${lane.generation} | ${lane.status} | ${shortHash(lane.subject_id_hash)}`;
}

type NavItem = {
  to: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
};

const navItems: NavItem[] = [
  { to: "/", label: "Dashboard", icon: Activity },
  { to: "/sessions", label: "Agent sessions", icon: Database },
  { to: "/health", label: "Connection", icon: CheckCircle2 },
  { to: "/explorer", label: "Database Explorer", icon: Search },
  { to: "/workbench", label: "SQL Workbench", icon: SquarePen },
  { to: "/reviews", label: "Change review", icon: GitPullRequest },
  { to: "/audit", label: "Audit trail", icon: FileClock },
  { to: "/capacity", label: "Resource limits", icon: Gauge },
  { to: "/config", label: "Profiles & settings", icon: SlidersHorizontal },
  { to: "/clients", label: "MCP clients", icon: KeyRound }
];

const rootRoute = createRootRoute({
  component: RootLayout
});

const overviewRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: OverviewPage
});

/**
 * Read one optional string search param, fail-soft. A deep link is a
 * convenience, so a junk value degrades to "no selection" rather than throwing
 * the operator to an error boundary. It is never an authorization input: the
 * server still decides what this subject may see.
 */
export function optionalSearchString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function optionalSearchGeneration(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

const sessionsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sessions",
  component: SessionsPage,
  validateSearch: (search: Record<string, unknown>): { lane?: string; generation?: number } => ({
    lane: optionalSearchString(search.lane),
    generation: optionalSearchGeneration(search.generation)
  })
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
  component: ExplorerPage,
  validateSearch: (search: Record<string, unknown>): { lane?: string; generation?: number } => ({
    lane: optionalSearchString(search.lane),
    generation: optionalSearchGeneration(search.generation)
  })
});

const workbenchRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/workbench",
  component: WorkbenchRoutePage
});

const reviewsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/reviews",
  component: ReviewsPage,
  validateSearch: (search: Record<string, unknown>): { id?: string } => ({
    id: optionalSearchString(search.id)
  })
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
    auditRoute
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
  const skin = OMCP_SKIN;
  const activeLanes = useQuery({
    queryKey: ["active-lanes"],
    queryFn: fetchActiveLanes,
    refetchInterval: LIVE_TELEMETRY_REFETCH_MS
  });
  const stateful = authoritativeServerMode(activeLanes.status, activeLanes.data) !== false;
  const operatorConfig = useQuery({
    queryKey: ["operator-config"],
    queryFn: fetchOperatorConfig,
    staleTime: 30_000
  });
  const workbenchEnabled = operatorConfig.data?.data.status.dashboard_workbench === true;
  const workbenchNavigationVisible = operatorConfig.status !== "success" || workbenchEnabled;
  const visibleNavItems = navItems.filter(
    (item) =>
      (stateful || item.to !== "/sessions") &&
      (workbenchNavigationVisible || item.to !== "/workbench")
  );
  return (
    <div
      className={skin.layout.appShell}
      data-dashboard-skin={skin.name}
      data-dashboard-theme={skin.theme.name}
    >
      {/* Ahead of the sidebar nav in tab order, so keyboard users can
          reach content without traversing it on every route. */}
      <a href="#main" className={skin.layout.skipLink} data-omcp-skip-link="main">
        Skip to main content
      </a>
      <div className={skin.layout.frame}>
        <aside className={skin.layout.sidebar}>
          <div className="flex items-center gap-3">
            <div className={skin.layout.logoMark}>
              <ShieldCheck className="size-5" aria-hidden="true" />
            </div>
            <div>
              <p className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
                Oracle MCP
              </p>
              <h1 className="font-serif text-xl font-semibold text-[var(--om-text-bright)]">Operator dashboard</h1>
            </div>
          </div>
          <nav className={skin.layout.nav} aria-label="dashboard">
            {visibleNavItems.map((item) => (
              <NavLink key={item.to} item={item} skin={skin} />
            ))}
          </nav>
        </aside>
        <main id="main" tabIndex={-1} className="min-w-0 flex-1 space-y-4">
          <DashboardSessionBanner client={queryClient} />
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
  skin: typeof OMCP_SKIN;
}): React.ReactElement {
  const Icon = item.icon;
  return (
    <Link to={item.to} className={skin.layout.navLink}>
      <Icon className="size-4" aria-hidden="true" />
      <span>{item.label}</span>
    </Link>
  );
}

function OverviewPage(): React.ReactElement {
  const session = useQuery({
    queryKey: ["dashboard-session"],
    queryFn: fetchDashboardSession,
    staleTime: 60_000,
    refetchInterval: 60_000,
    retry: 1
  });
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
  const activeLanes = useQuery({
    queryKey: ["active-lanes"],
    queryFn: fetchActiveLanes,
    refetchInterval: 5_000
  });
  const reviews = useQuery({
    queryKey: ["change-proposals"],
    queryFn: ({ signal }) => fetchChangeProposals(undefined, { signal })
  });
  const eventLog = useOperatorEventLog(
    undefined,
    session.status === "success" ? session.data : undefined
  );
  const snapshot = metrics.status === "success" ? metrics.data.data.snapshot : null;
  const lanes = activeLanes.status === "success" ? activeLanes.data.data.lanes : EMPTY_ACTIVE_LANES;
  const stateful = authoritativeServerMode(activeLanes.status, activeLanes.data) !== false;
  const activity = queryActivity(health, metrics, activeLanes);
  const pending = activity.blocking;
  const dataError = firstQueryError(health.error, metrics.error, activeLanes.error);
  const retryDashboardData = React.useCallback(() => {
    void health.refetch();
    void metrics.refetch();
    void activeLanes.refetch();
  }, [activeLanes, health, metrics]);

  return (
    <PageFrame
      title="Dashboard"
      eyebrow="Service overview"
      description="Current Oracle connection, active MCP clients, governed activity, and service counters."
    >
      <div className="space-y-4">
        <BackgroundRefreshStatus refreshing={activity.refreshing} />
        <OverviewServiceStatus
          health={health.status === "success" ? health.data.data : null}
          lanes={lanes}
          lanesStatus={activeLanes.status}
          stateful={stateful}
          snapshot={snapshot}
          pending={pending}
          error={dataError}
          checkedAt={Math.max(health.dataUpdatedAt, metrics.dataUpdatedAt, activeLanes.dataUpdatedAt)}
        />
        {dataError ? (
          <QueryErrorNotice
            title="Dashboard data is unavailable"
            error={dataError}
            retryLabel="Retry dashboard data"
            onRetry={retryDashboardData}
          />
        ) : null}
        <OverviewMetricTiles
          snapshot={snapshot}
          lanes={lanes}
          lanesStatus={activeLanes.status}
          metricsStatus={metrics.status}
          stateful={stateful}
          pending={pending}
        />
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(360px,0.85fr)]">
          <LaneMetricsPanel
            snapshot={snapshot}
            lanes={lanes}
            stateful={stateful}
            available={metrics.status === "success" && activeLanes.status === "success"}
          />
          <OverviewReviewsPanel
            proposals={reviews.data?.data.proposals ?? []}
            pending={reviews.isPending}
            error={reviews.error}
          />
        </div>
        <div className="grid gap-4 xl:grid-cols-[minmax(0,0.85fr)_minmax(360px,1.15fr)]">
          <ToolMetricsPanel snapshot={snapshot} />
          <OperatorEventLogPanel status={eventLog.status} events={eventLog.events} />
        </div>
      </div>
    </PageFrame>
  );
}

function OverviewServiceStatus({
  health,
  lanes,
  lanesStatus,
  stateful,
  snapshot,
  pending,
  error,
  checkedAt
}: {
  health: OperatorHealthData | null;
  lanes: ActiveLane[];
  lanesStatus: "pending" | "error" | "success";
  stateful: boolean;
  snapshot: MetricsSnapshot | null;
  pending: boolean;
  error: Error | null;
  checkedAt: number;
}): React.ReactElement {
  const readiness = health?.readiness;
  const serviceReady = readiness?.ready === true;
  const databaseReachable = readiness?.db_reachable === true;
  const state = error ? "unavailable" : pending && !health ? "checking" : serviceReady ? "ready" : "attention";
  return (
    <Surface className="overflow-hidden" aria-busy={pending}>
      <PanelHeader
        icon={Activity}
        title="Service status"
        meta={checkedAt > 0 ? `checked ${formatRelativeAge(checkedAt)}` : "not checked"}
        tone={error || (!pending && !serviceReady) ? "warn" : pending ? "info" : "ok"}
      />
      <div className="grid gap-3 p-4 sm:grid-cols-2 xl:grid-cols-5">
        <CapacityFact label="Service" value={state} />
        <CapacityFact
          label="Oracle database"
          value={error ? "unavailable" : databaseReachable ? "connected" : pending ? "checking" : "not reachable"}
        />
        <CapacityFact
          label={stateful ? "Active agent sessions" : "Connection mode"}
          value={stateful ? authoritativeMetric(lanesStatus, lanes.length) : "direct (stateless)"}
        />
        <CapacityFact
          label="Open pool connections"
          value={snapshot ? snapshot.pool_active_connections : "unavailable"}
        />
        <CapacityFact
          label="Policy refusals since start"
          value={snapshot ? sumCounts(snapshot.lane_blocked ?? []) : "unavailable"}
        />
      </div>
    </Surface>
  );
}

function SessionsPage(): React.ReactElement {
  const { lane = "", generation } = useSearch({ from: sessionsRoute.id });
  const activeLanes = useQuery({
    queryKey: ["active-lanes"],
    queryFn: fetchActiveLanes,
    refetchInterval: 5_000
  });
  const exactLane = activeLanes.status === "success"
    ? activeLanes.data.data.lanes.find((item) => item.lane_id === lane && item.generation === generation)
    : undefined;
  return <SessionsWorkspace key={exactLane ? JSON.stringify([lane, generation]) : "no-active-lane"} />;
}

export function combinedQueryStatus(
  ...statuses: DashboardQueryStatus[]
): DashboardQueryStatus {
  if (statuses.includes("error")) {
    return "error";
  }
  return statuses.includes("pending") ? "pending" : "success";
}

export function sessionAuthorityQueriesReady(
  metricsStatus: DashboardQueryStatus,
  capabilitiesStatus: DashboardQueryStatus,
  connectionStatus: DashboardQueryStatus
): boolean {
  return combinedQueryStatus(metricsStatus, capabilitiesStatus, connectionStatus) === "success";
}

function SessionsWorkspace(): React.ReactElement {
  // The selected lane lives in the URL so an operator can hand a colleague a
  // link to the exact lane they are looking at, and so reload/back keep it.
  const { lane: selectedLaneId = "", generation: selectedLaneGeneration } = useSearch({
    from: sessionsRoute.id
  });
  const navigate = useNavigate({ from: sessionsRoute.id });
  const setSelectedLane = React.useCallback(
    (identity: LaneIdentity | null) => {
      void navigate({
        search: {
          lane: identity?.laneId,
          generation: identity?.generation
        },
        replace: true
      });
    },
    [navigate]
  );
  const [targetLevel, setTargetLevel] = React.useState<OperatingLevel>("READ_WRITE");
  const [ttlSeconds, setTtlSeconds] = React.useState(900);
  const [confirm, setConfirm] = React.useState("");
  const [lastResult, setLastResult] = React.useState<SessionLevelResult | null>(null);
  const [cancelNotice, setCancelNotice] = React.useState<LaneCancelNotice | null>(null);
  const [pendingCancelLane, setPendingCancelLane] = React.useState<LaneIdentity | null>(null);
  const elevationRequestGeneration = React.useRef(0);
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
  const lanes = activeLanes.status === "success" ? activeLanes.data.data.lanes : EMPTY_ACTIVE_LANES;
  const serverMode = authoritativeServerMode(activeLanes.status, activeLanes.data);
  const requestedLane = selectedLaneId && selectedLaneGeneration !== undefined
    ? { laneId: selectedLaneId, generation: selectedLaneGeneration }
    : null;
  const selection = reconcileLaneSelection(requestedLane, selectedLaneId, lanes);
  const selectedLane = selection.identity
    ? lanes.find(
        (lane) =>
          lane.lane_id === selection.identity?.laneId &&
          lane.generation === selection.identity.generation
      ) ?? null
    : null;
  const selectedLaneKey = selectedLane?.lane_id ?? "";
  const selectedLaneTarget = selectedLane ? laneIdentity(selectedLane) : undefined;
  const invalidateElevationDraft = React.useCallback(() => {
    elevationRequestGeneration.current += 1;
    setConfirm("");
    setLastResult(null);
  }, []);
  const sessionAuthority = dashboardAuthorityIdentity(
    session.status === "success" ? session.data : undefined
  );
  const purgeSessionAuthorityState = React.useCallback(() => {
    invalidateElevationDraft();
    setCancelNotice(null);
    setPendingCancelLane(null);
  }, [invalidateElevationDraft]);
  useDashboardAuthorityPurge(sessionAuthority, purgeSessionAuthorityState);
  const currentElevationBindingRef = React.useRef<
    Omit<ElevationRequestBinding, "requestGeneration"> | null
  >(null);
  React.useLayoutEffect(() => {
    currentElevationBindingRef.current = selectedLane
      ? { lane: laneIdentity(selectedLane), targetLevel, ttlSeconds }
      : null;
  }, [selectedLane, targetLevel, ttlSeconds]);
  const eventLog = useOperatorEventLog(
    selectedLaneTarget,
    session.status === "success" ? session.data : undefined
  );
  const selectedCapabilities = useQuery({
    queryKey: [
      "sessions",
      "capabilities",
      selectedLaneTarget?.laneId ?? "none",
      selectedLaneTarget?.generation ?? 0
    ],
    queryFn: async ({ signal }) => {
      if (!session.data || !selectedLaneTarget) {
        throw new Error("dashboard session is not ready");
      }
      return fetchLaneCapabilities(session.data, selectedLaneTarget, { signal });
    },
    enabled: session.status === "success" && Boolean(selectedLaneTarget),
    refetchInterval: 10_000,
    retry: 1
  });
  const selectedConnection = useQuery({
    queryKey: [
      "sessions",
      "connection",
      selectedLaneTarget?.laneId ?? "none",
      selectedLaneTarget?.generation ?? 0
    ],
    queryFn: async ({ signal }) => {
      if (!session.data || !selectedLaneTarget) {
        throw new Error("dashboard session is not ready");
      }
      return fetchExplorerConnection(session.data, selectedLaneTarget, { signal });
    },
    enabled: session.status === "success" && Boolean(selectedLaneTarget),
    refetchInterval: 10_000,
    retry: 1
  });
  const metricsData = authoritativeMetricsData(metrics.status, metrics.data);
  const selectedCapabilitiesData = authoritativeQueryData(
    selectedCapabilities.status,
    selectedCapabilities.data
  );
  const selectedConnectionData = authoritativeQueryData(
    selectedConnection.status,
    selectedConnection.data
  );
  const authorityQueriesReady = sessionAuthorityQueriesReady(
    metrics.status,
    selectedCapabilities.status,
    selectedConnection.status
  );
  React.useEffect(() => {
    if (
      metrics.status === "error" ||
      selectedCapabilities.status === "error" ||
      selectedConnection.status === "error"
    ) {
      invalidateElevationDraft();
    }
  }, [
    invalidateElevationDraft,
    metrics.status,
    selectedCapabilities.status,
    selectedConnection.status
  ]);

  const levelMutation = useMutation({
    mutationFn: async (request: SessionLevelMutationRequest) => {
      if (!session.data || !sessionAuthority || request.authority !== sessionAuthority) {
        throw new Error("dashboard session is not ready");
      }
      return setSessionLevel(session.data, {
        lane: request.lane,
        level: request.targetLevel as OperatingLevel,
        ttlSeconds: request.ttlSeconds,
        confirm: request.confirm,
        action: request.action
      });
    },
    onSuccess: (response, request) => {
      if (request.authority !== sessionAuthority) {
        return;
      }
      queryClient.invalidateQueries({ queryKey: ["active-lanes"] });
      queryClient.invalidateQueries({ queryKey: ["operator-metrics"] });
      queryClient.invalidateQueries({
        queryKey: [
          "sessions",
          "capabilities",
          request.lane.laneId,
          request.lane.generation
        ]
      });
      if (!elevationCompletionIsCurrent(
        request,
        currentElevationBindingRef.current,
        elevationRequestGeneration.current
      )) {
        return;
      }
      const outcome = decodeOperatorOutcome(200, response);
      setLastResult({ state: outcome.state, action: request.action, response, outcome });
      const nextConfirm = confirmationFromResponse(response);
      if (request.action === "preview") {
        setConfirm(nextConfirm ?? "");
      } else {
        setConfirm("");
      }
    },
    onError: (error, request) => {
      if (request.authority !== sessionAuthority) {
        return;
      }
      if (!elevationCompletionIsCurrent(
        request,
        currentElevationBindingRef.current,
        elevationRequestGeneration.current
      )) {
        return;
      }
      const outcome = operatorOutcomeFromError(error, "session level action failed");
      setLastResult({
        state: outcome.state,
        action: request.action,
        response: operatorResponseFromError<WorkbenchActionData>(error),
        outcome
      });
    }
  });

  // Per-lane kill-switch. The cancel route is guarded server-side (the server
  // derives the Subject from the transport principal — the browser never supplies
  // it); the confirm here only guards against an accidental click.
  const cancelMutation = useMutation({
    mutationFn: async ({
      lane,
      authority: requestAuthority
    }: {
      lane: LaneIdentity;
      authority: string;
    }) => {
      if (!session.data || !sessionAuthority || requestAuthority !== sessionAuthority) {
        throw new Error("dashboard session is not ready");
      }
      return cancelLane(session.data, lane);
    },
    onSuccess: (_response, { lane, authority: requestAuthority }) => {
      if (requestAuthority !== sessionAuthority) {
        return;
      }
      setCancelNotice(laneCancelSuccess(lane.laneId));
      queryClient.invalidateQueries({ queryKey: ["active-lanes"] });
      queryClient.invalidateQueries({ queryKey: ["operator-metrics"] });
    },
    onError: (error, { authority: requestAuthority }) => {
      if (requestAuthority !== sessionAuthority) {
        return;
      }
      setCancelNotice(laneCancelFailure(error));
    }
  });

  // Ask through the console's own dialog rather than window.confirm, so the
  // prompt is styled, focus-managed, and assertable like every other gate.
  const requestCancelLane = (lane: LaneIdentity): void => {
    setPendingCancelLane(lane);
  };

  const confirmCancelLane = (): void => {
    const lane = pendingCancelLane;
    setPendingCancelLane(null);
    if (!lane) {
      return;
    }
    if (!lanes.some((item) => sameLaneIdentity(laneIdentity(item), lane))) {
      setCancelNotice(laneCancelFailure(new Error("session identity changed; review the list and retry")));
      return;
    }
    setCancelNotice(null);
    cancelMutation.mutate({ lane, authority: sessionAuthority ?? "" });
  };

  const sessionTone =
    session.status === "success" ? "ok" : session.status === "error" ? "warn" : "info";
  const canAct =
    session.status === "success" &&
    activeLanes.status === "success" &&
    authorityQueriesReady &&
    Boolean(selectedLane) &&
    !levelMutation.isPending;
  const activity = queryActivity(
    activeLanes,
    metrics,
    session,
    selectedCapabilities,
    selectedConnection
  );
  const pending = activity.blocking || levelMutation.isPending;
  const snapshot = metricsData?.snapshot ?? null;
  const summary = overviewSummary(snapshot, lanes);
  const laneRowsStatus = combinedQueryStatus(activeLanes.status, metrics.status);
  const laneRows = laneRowsStatus === "success"
    ? sessionLaneRows(
        snapshot,
        lanes,
        selectedLaneKey,
        selectedCapabilitiesData,
        selectedConnectionData
      )
    : [];
  const selectedDetail = selectedLaneDetail(
    selectedLane,
    laneRows,
    selectedCapabilitiesData,
    selectedConnectionData,
    metrics.error instanceof Error
      ? metrics.error.message
      : metrics.status === "success"
        ? null
        : "session metrics are unavailable",
    selectedCapabilities.error instanceof Error
      ? selectedCapabilities.error.message
      : selectedCapabilities.status === "success"
        ? null
        : "session capabilities are unavailable",
    selectedConnection.error instanceof Error
      ? selectedConnection.error.message
      : selectedConnection.status === "success"
        ? null
        : "database connection details are unavailable",
    eventLog.events
  );

  if (serverMode === false) {
    return (
      <PageFrame
        title="Agent sessions"
        eyebrow="Stateful HTTP is off"
        description="This server uses direct stateless requests, so it does not retain per-client sessions or temporary session controls."
      >
        <ConsolePanel className="p-4">
          <p className="text-sm leading-6 text-[var(--om-text)]" role="status">
            Session tracking is not applicable in stateless mode. Use Dashboard for service activity or SQL Workbench for the direct server profile.
          </p>
        </ConsolePanel>
      </PageFrame>
    );
  }

  return (
    <PageFrame
      title="Agent sessions"
      eyebrow="Connected MCP clients"
      description="Inspect active client sessions, their database profile, and temporary permission level."
    >
      <div className="space-y-4">
        <BackgroundRefreshStatus refreshing={activity.refreshing} />
        {activeLanes.error instanceof Error ? (
          <QueryErrorNotice
            title="Agent sessions are unavailable"
            error={activeLanes.error}
            retryLabel="Retry sessions"
            onRetry={() => void activeLanes.refetch()}
          />
        ) : null}
        {metrics.error instanceof Error ? (
          <QueryErrorNotice
            title="Session metrics are unavailable"
            error={metrics.error}
            retryLabel="Retry metrics"
            onRetry={() => void metrics.refetch()}
          />
        ) : null}
        {pendingCancelLane ? (
          <ConfirmDialog
            id="lane-cancel"
            title="End agent session"
            body={
              <>
                End session{" "}
                <span className="font-mono font-semibold text-[var(--om-text-bright)]">
                  {pendingCancelLane.laneId}
                </span>
                ? This closes its Oracle connection and revokes temporary grants.
              </>
            }
            confirmLabel="End session"
            busy={cancelMutation.isPending}
            onCancel={() => setPendingCancelLane(null)}
            onConfirm={confirmCancelLane}
          />
        ) : null}
        <SessionMissionHeader
          summary={summary}
          eventStatus={eventLog.status}
          source={authoritativeQueryData(activeLanes.status, activeLanes.data)?.data.source ?? "unavailable"}
          pending={pending}
          lanesStatus={activeLanes.status}
          metricsStatus={metrics.status === "success" && !snapshot ? "error" : metrics.status}
        />
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(360px,0.9fr)]">
          <SessionLaneTable
            rows={laneRows}
            selectedLaneId={selectedLane?.lane_id ?? ""}
            state={collectionViewState(laneRowsStatus, laneRows.length)}
            pending={pending}
            onSelect={(identity) => {
              invalidateElevationDraft();
              setSelectedLane(identity);
            }}
            onCancel={requestCancelLane}
            cancelPendingLaneId={cancelMutation.isPending ? cancelMutation.variables?.lane.laneId ?? null : null}
            cancelNotice={cancelNotice}
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
              onLevelChange={(level) => {
                invalidateElevationDraft();
                setTargetLevel(level);
              }}
              onTtlChange={(ttl) => {
                invalidateElevationDraft();
                setTtlSeconds(ttl);
              }}
              onAction={(action) => {
                const binding = currentElevationBindingRef.current;
                if (!binding) {
                  return;
                }
                const requestGeneration = elevationRequestGeneration.current + 1;
                elevationRequestGeneration.current = requestGeneration;
                if (action === "preview") {
                  setConfirm("");
                }
                levelMutation.mutate({
                  ...binding,
                  action,
                  confirm,
                  authority: sessionAuthority ?? "",
                  requestGeneration
                });
              }}
            />
          </div>
        </div>
        <OperatorEventLogPanel status={eventLog.status} events={eventLog.events} />
      </div>
    </PageFrame>
  );
}

type SessionLevelControlAction = "preview" | "apply" | "drop";

type SessionLevelMutationRequest = ElevationRequestBinding & {
  action: SessionLevelControlAction;
  confirm: string;
  authority: string;
};

type SessionLevelResult = {
  state: OperatorOutcomeState;
  action: SessionLevelControlAction;
  response: OperatorResponse<WorkbenchActionData> | null;
  outcome: OperatorOutcome;
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
  requests: number | null;
  blocked: number | null;
  meanLatencyMs: number | null;
  maxLatencyMs: number | null;
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
  summary,
  eventStatus,
  source,
  pending,
  lanesStatus,
  metricsStatus
}: {
  summary: OverviewSummary;
  eventStatus: EventStreamStatus;
  source: string;
  pending: boolean;
  lanesStatus: "pending" | "error" | "success";
  metricsStatus: "pending" | "error" | "success";
}): React.ReactElement {
  return (
      <Surface className="overflow-hidden" aria-busy={pending}>
        <PanelHeader
          icon={Radio}
          title="Active agent sessions"
          meta={pending ? "checking" : source}
          tone={lanesStatus === "error" ? "warn" : pending ? "info" : summary.activeLanes > 0 ? "ok" : "off"}
        />
        <div className="grid gap-3 p-4 sm:grid-cols-2 xl:grid-cols-5">
          <CapacityFact label="Sessions" value={authoritativeMetric(lanesStatus, summary.activeLanes)} />
          <CapacityFact label="Requests since start" value={authoritativeMetric(metricsStatus, summary.totalRequests)} />
          <CapacityFact label="Policy refusals since start" value={authoritativeMetric(metricsStatus, summary.blocked)} />
          <CapacityFact label="Errors since start" value={authoritativeMetric(metricsStatus, summary.errors)} />
          <CapacityFact label="Live updates" value={eventStatus} mono />
        </div>
      </Surface>
  );
}

function SessionLaneTable({
  rows,
  selectedLaneId,
  state,
  pending,
  onSelect,
  onCancel,
  cancelPendingLaneId,
  cancelNotice
}: {
  rows: SessionLaneRow[];
  selectedLaneId: string;
  state: CollectionViewState;
  pending: boolean;
  onSelect: (identity: LaneIdentity) => void;
  onCancel: (identity: LaneIdentity) => void;
  cancelPendingLaneId: string | null;
  cancelNotice: LaneCancelNotice | null;
}): React.ReactElement {
  return (
      <ConsolePanel>
      <ConsolePanelHeader
        icon={Database}
        title="Active agent sessions"
        meta={state === "unavailable" ? "unavailable" : pending ? "checking" : `${rows.length} sessions`}
        tone={state === "unavailable" ? "warn" : pending ? "info" : rows.length > 0 ? "ok" : "off"}
      />
      {cancelNotice ? (
        <p
          className={cn(
            "border-b border-[var(--om-border)] px-4 py-2 font-mono text-xs",
            cancelNotice.kind === "error" ? "text-[var(--om-rust)]" : "text-[var(--om-text-muted)]"
          )}
          role={cancelNotice.kind === "error" ? "alert" : "status"}
          aria-live="polite"
        >
          {cancelNotice.message}
        </p>
      ) : null}
      <div
        className="overflow-x-auto"
        role="region"
        aria-label="Active MCP client sessions"
        tabIndex={0}
      >
        <table className="w-full min-w-[920px] border-collapse text-left">
          <caption className="sr-only">Active MCP client sessions</caption>
          <thead className="bg-[var(--om-surface-muted)] text-2xs uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
            <tr>
              <th className="px-4 py-3 font-semibold">Session</th>
              <th className="px-4 py-3 font-semibold">Client identity</th>
              <th className="px-4 py-3 font-semibold">Database profile</th>
              <th className="px-4 py-3 font-semibold">Permission</th>
              <th className="px-4 py-3 font-semibold">Activity</th>
              <th className="px-4 py-3 font-semibold">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--om-border)]">
            {state !== "ready" ? (
              <tr>
                <td
                  className="px-4 py-8 text-center text-sm font-semibold text-[var(--om-text-muted)]"
                  colSpan={6}
                >
                  {state === "unavailable"
                    ? "Agent sessions are unavailable. Retry the sessions request."
                    : state === "pending"
                      ? "Loading agent sessions…"
                      : "No active agent sessions. Connect an MCP client to begin."}
                </td>
              </tr>
            ) : (
              rows.map((row) => {
                const selected = row.laneId === selectedLaneId;
                return (
                  <tr
                    key={`${row.laneId}:${row.generation}`}
                    className={
                      selected
                        ? "bg-[color-mix(in_srgb,var(--om-gold)_12%,transparent)]"
                        : "bg-transparent"
                    }
                    data-lane-selected={selected}
                  >
                    <td className="px-4 py-4 align-top font-mono text-sm font-semibold text-[var(--om-text-bright)]">
                      <div className="flex flex-col gap-2">
                        <span>{row.laneId}</span>
                        <Badge tone={row.active ? "ok" : "off"}>{row.statusLabel}</Badge>
                      </div>
                    </td>
                    <td className="px-4 py-4 align-top">
                      <p className="max-w-[280px] break-all font-mono text-xs text-[var(--om-text-muted)]">
                        {row.subjectIdHash}
                      </p>
                    </td>
                    <td className="px-4 py-4 align-top font-mono text-sm text-[var(--om-text)]">
                      <div className="max-w-[180px] break-all">{row.activeProfile}</div>
                      <p className="mt-1 max-w-[180px] break-all text-xs text-[var(--om-text-muted)]">
                        {row.dbFingerprint}
                      </p>
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
                      <p className="mt-1 font-mono text-xs text-[var(--om-text-muted)]">
                        max {row.maxLevel}
                      </p>
                    </td>
                    <td className="px-4 py-4 align-top font-mono text-sm text-[var(--om-text)]">
                      <p>{formatNumber(row.requests)} req</p>
                      <p className="mt-1 text-xs text-[var(--om-text-muted)]">
                        {formatNumber(row.blocked)} blocked · {Math.round(row.meanLatencyMs)} ms
                      </p>
                    </td>
                    <td className="px-4 py-4 align-top">
                      <div className="flex flex-wrap gap-2">
                        <Button
                          type="button"
                          variant={selected ? "primary" : "secondary"}
                          aria-label={`View details for session ${row.laneId}`}
                          aria-pressed={selected}
                          onClick={() => onSelect({ laneId: row.laneId, generation: row.generation })}
                        >
                          <SlidersHorizontal className="size-4" aria-hidden="true" />
                          View details
                        </Button>
                        <Button
                          type="button"
                          variant="secondary"
                          className="border-[color-mix(in_srgb,var(--om-rust)_55%,transparent)] text-[var(--om-rust)] hover:bg-[color-mix(in_srgb,var(--om-rust)_14%,transparent)]"
                          disabled={!row.active || cancelPendingLaneId === row.laneId}
                          title="End this agent session"
                          aria-label={`${cancelPendingLaneId === row.laneId ? "Ending" : "End"} session ${row.laneId}`}
                          onClick={() => onCancel({ laneId: row.laneId, generation: row.generation })}
                        >
                          <Ban className="size-4" aria-hidden="true" />
                          {cancelPendingLaneId === row.laneId ? "Ending…" : "End session"}
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </ConsolePanel>
  );
}

function SessionLaneDetailPanel({
  detail
}: {
  detail: SessionLaneDetail | null;
}): React.ReactElement {
  const unavailable = Boolean(detail && detail.detailState !== "none");
  return (
    <ConsolePanel>
      <ConsolePanelHeader
        icon={Activity}
        title="Session details"
        meta={detail?.laneId ?? "no session"}
        tone={unavailable ? "warn" : detail ? "ok" : "off"}
      />
      <div className="grid gap-3 p-4 sm:grid-cols-2">
        <ConsoleFact label="Session" value={detail?.laneId ?? "none"} mono />
        <ConsoleFact label="Client identity" value={detail?.subjectIdHash ?? "none"} mono />
        <ConsoleFact label="Profile" value={detail?.activeProfile ?? "unknown"} mono />
        <ConsoleFact label="DB" value={detail?.dbFingerprint ?? "unknown"} mono />
        <ConsoleFact label="Current permission" value={detail?.currentLevel ?? "unknown"} mono />
        <ConsoleFact label="Maximum permission" value={detail?.maxLevel ?? "unknown"} mono />
        <ConsoleFact label="Protected" value={detail?.protectedProfile ?? "unknown"} mono />
        <ConsoleFact label="Schema" value={detail?.visibleSchema ?? "unknown"} mono />
        <ConsoleFact label="Connected" value={detail?.connected ?? "unknown"} mono />
        <ConsoleFact label="Strategy" value={detail?.connectionStrategy ?? "unknown"} mono />
        <ConsoleFact label="Server" value={detail?.serverVersion ?? "unknown"} mono />
        <ConsoleFact label="Role" value={detail?.databaseRole ?? "unknown"} mono />
        <ConsoleFact label="Open Mode" value={detail?.openMode ?? "unknown"} mono />
        <ConsoleFact label="Requests" value={detail?.requests ?? "unavailable"} />
        <ConsoleFact label="Blocked" value={detail?.blocked ?? "unavailable"} />
        <ConsoleFact
          label="Mean Latency"
          value={detail?.meanLatencyMs == null ? "unavailable" : `${Math.round(detail.meanLatencyMs)} ms`}
          mono
        />
        <ConsoleFact
          label="Max Latency"
          value={detail?.maxLatencyMs == null ? "unavailable" : `${Math.round(detail.maxLatencyMs)} ms`}
          mono
        />
        <ConsoleFact label="Last Event" value={detail?.lastEvent ?? "none"} mono />
        <ConsoleFact label="Detail status" value={detail?.detailState ?? "unknown"} mono />
      </div>
    </ConsolePanel>
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
  onLevelChange: (value: OperatingLevel) => void;
  onTtlChange: (value: number) => void;
  onAction: (action: SessionLevelControlAction) => void;
}): React.ReactElement {
  const summary =
    result?.state === "success" && result.response
      ? sessionLevelSummary(result.response)
      : null;
  const inputClass =
    "min-h-11 w-full rounded-md border border-[var(--om-control-border)] bg-[var(--om-surface-muted)] px-3 text-sm text-[var(--om-text)] outline-none focus-visible:border-[var(--om-gold)] focus-visible:ring-2 focus-visible:ring-[color-mix(in_srgb,var(--om-gold)_35%,transparent)]";
  const labelClass = "mb-2 block text-sm font-semibold text-[var(--om-text)]";
  return (
    <ConsolePanel>
      <ConsolePanelHeader
        icon={ShieldCheck}
        title="Temporary permissions"
        meta={selectedLane?.lane_id ?? "no session"}
        tone={pending ? "info" : selectedLane ? sessionTone : "off"}
      />
      <div className="space-y-4 p-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <ConsoleFact label="Session" value={selectedLane?.lane_id ?? "none"} mono />
          <ConsoleFact label="Current permission" value={summary?.currentLevel ?? "read from session details"} mono />
          <ConsoleFact label="Maximum permission" value={summary?.profileCeiling ?? "read from profile"} mono />
          <ConsoleFact label="Confirmation" value={confirm ? "ready for this request" : "preview required"} />
        </div>
        <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_140px]">
          <label className="block">
            <span className={labelClass}>Requested permission</span>
            <select
              className={inputClass}
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
            <span className={labelClass}>Duration (seconds)</span>
            <input
              className={inputClass}
              type="number"
              min={1}
              max={3600}
              value={ttlSeconds}
              onChange={(event) => onTtlChange(clampTtl(event.target.valueAsNumber))}
            />
          </label>
        </div>
        <p className="text-sm leading-6 text-[var(--om-text-muted)]">
          Review the requested level first. The server returns a short-lived confirmation bound to this session, level, and duration; it is never editable here.
        </p>
        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="secondary" disabled={!canAct} onClick={() => onAction("preview")}>
            <Search className="size-4" aria-hidden="true" />
            Review elevation
          </Button>
          <Button
            type="button"
            variant="primary"
            disabled={!canAct || confirm.trim().length === 0}
            onClick={() => onAction("apply")}
          >
            <CheckCircle2 className="size-4" aria-hidden="true" />
            Apply temporary elevation
          </Button>
          <Button type="button" variant="secondary" disabled={!canAct} onClick={() => onAction("drop")}>
            <RotateCcw className="size-4" aria-hidden="true" />
            Return to read-only
          </Button>
        </div>
        {summary ? <ElevationCountdown summary={summary} /> : null}
        {summary ? <SessionLevelSummaryPanel summary={summary} /> : null}
        {result ? <OperatorOutcomeNotice outcome={result.outcome} /> : null}
      </div>
    </ConsolePanel>
  );
}

function ElevationCountdown({ summary }: { summary: SessionLevelSummary }): React.ReactElement | null {
  const remainingSec = useAbsoluteExpiryCountdown(summary.elevationExpiresUnix, () => undefined);
  if (remainingSec === null) {
    return null;
  }
  const live = remainingSec > 0;
  const minutes = Math.floor(remainingSec / 60);
  const seconds = remainingSec % 60;
  return (
    <div
      className={cn(
        "flex items-center justify-between gap-3 rounded-md border px-3 py-2",
        live
          ? "border-[color-mix(in_srgb,var(--om-gold)_45%,transparent)] bg-[color-mix(in_srgb,var(--om-gold)_12%,transparent)]"
          : "border-[color-mix(in_srgb,var(--om-rust)_45%,transparent)] bg-[color-mix(in_srgb,var(--om-rust)_12%,transparent)]"
      )}
      data-elevation-live={live}
    >
      <div className="flex items-center gap-2">
        <Timer className="size-4 text-[var(--om-text-muted)]" aria-hidden="true" />
        <span className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
          {live ? "Elevation window" : "Window closed"}
        </span>
      </div>
      <span
        className={cn(
          "font-mono text-sm font-bold tabular-nums",
          live ? "text-[var(--om-gold)]" : "text-[var(--om-rust)]"
        )}
      >
        {live ? `${minutes}:${String(seconds).padStart(2, "0")}` : "HOLD FOR GO"}
      </span>
    </div>
  );
}

function SessionLevelSummaryPanel({
  summary
}: {
  summary: SessionLevelSummary;
}): React.ReactElement {
  return (
    <div className="grid gap-2 sm:grid-cols-2">
      <ConsoleFact label="Action" value={summary.action} mono />
      <ConsoleFact label="Preview" value={summary.preview} mono />
      <ConsoleFact label="Target" value={summary.targetLevel} mono />
      <ConsoleFact label="TTL" value={summary.ttlSeconds} mono />
      <ConsoleFact label="Gate" value={summary.gateDecision} mono />
    </div>
  );
}

function HealthPage(): React.ReactElement {
  const [selectedLaneBinding, setSelectedLaneBinding] = React.useState<LaneIdentity | null>(null);
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
  const activeLanes = useQuery({
    queryKey: ["active-lanes"],
    queryFn: fetchActiveLanes,
    refetchInterval: 5_000
  });
  const lanes = activeLanes.status === "success" ? activeLanes.data.data.lanes : EMPTY_ACTIVE_LANES;
  const stateful = authoritativeServerMode(activeLanes.status, activeLanes.data) !== false;
  const laneSelection =
    stateful && activeLanes.status === "success"
      ? resolveExactLane(selectedLaneBinding, lanes)
      : { lane: null, invalidated: false };
  const selectedLane = laneSelection.lane ?? undefined;
  const connectionLane = selectedLane ? laneIdentity(selectedLane) : undefined;
  const connectionReady =
    activeLanes.status === "success" && (!stateful || Boolean(connectionLane));
  React.useEffect(() => {
    if (!stateful || activeLanes.status !== "success") {
      return;
    }
    if (laneSelection.invalidated) {
      setSelectedLaneBinding(null);
      return;
    }
    if (!selectedLaneBinding && lanes.length === 1) {
      setSelectedLaneBinding(laneIdentity(lanes[0]));
    }
  }, [activeLanes.status, laneSelection.invalidated, lanes, selectedLaneBinding, stateful]);
  const connection = useQuery({
    queryKey: [
      "health",
      "connection",
      connectionLane?.laneId ?? "stateless",
      connectionLane?.generation ?? 0
    ],
    queryFn: async ({ signal }) => {
      if (!session.data) {
        throw new Error("dashboard session is not ready");
      }
      return fetchExplorerConnection(session.data, connectionLane, { signal });
    },
    enabled: session.status === "success" && connectionReady,
    refetchInterval: 10_000,
    retry: 1
  });
  const connectionStatus =
    activeLanes.status === "error" || session.status === "error" ? "error" : connection.status;
  const model = connectionHealthModel(
    health.data?.data ?? null,
    metrics.data?.data.snapshot ?? null,
    connection.data,
    {
      health: {
        availability: sourceAvailability(health.status, Boolean(health.data), health.isStale),
        error: health.error instanceof Error ? health.error.message : null
      },
      metrics: {
        availability: sourceAvailability(
          metrics.status,
          Boolean(metrics.data?.data.snapshot),
          metrics.isStale
        ),
        error: metrics.error instanceof Error ? metrics.error.message : null
      },
      connection: {
        availability: sourceAvailability(
          connectionStatus,
          Boolean(connection.data),
          connection.isStale
        ),
        error:
          connection.error instanceof Error
            ? connection.error.message
            : activeLanes.error instanceof Error
              ? activeLanes.error.message
              : session.error instanceof Error
                ? session.error.message
                : null
      }
    }
  );
  const activity = queryActivity(health, metrics, activeLanes, connection);
  const pending = activity.blocking;

  return (
    <PageFrame
      title="Connection health"
      eyebrow="Service and Oracle database"
      description="See whether the server is ready, which database profile is connected, and where connection time is being spent."
    >
      <div className="space-y-4">
        <BackgroundRefreshStatus refreshing={activity.refreshing} />
        <ConsolePanel className="p-4">
          {stateful ? (
            <label className="block max-w-xl">
              <span className={OM_LABEL}>Agent session to inspect</span>
              <select
                className={cn(OM_INPUT, "font-mono")}
                value={selectedLane ? laneOptionValue(selectedLane) : ""}
                onChange={(event) =>
                  setSelectedLaneBinding(laneIdentityFromOption(lanes, event.target.value))
                }
                disabled={activeLanes.isPending || lanes.length === 0}
              >
                <option value="">Select a session</option>
                {lanes.map((lane) => (
                  <option key={`${lane.lane_id}:${lane.generation}`} value={laneOptionValue(lane)}>
                    {laneOptionLabel(lane)}
                  </option>
                ))}
              </select>
              {lanes.length === 0 && activeLanes.status === "success" ? (
                <span className="mt-2 block text-sm text-[var(--om-text-muted)]">
                  Connect an MCP client to inspect its session profile. Service readiness remains visible below.
                </span>
              ) : null}
            </label>
          ) : (
            <p className="text-sm text-[var(--om-text)]" role="status">
              Connection mode: <strong>direct server profile</strong>
            </p>
          )}
        </ConsolePanel>
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

function HealthStatusTiles({
  model,
  pending
}: {
  model: ConnectionHealthUiModel;
  pending: boolean;
}): React.ReactElement {
  const readinessCurrent = model.readiness.availability === "available";
  const dbCurrent = model.dbAvailability === "available";
  return (
    <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-4" aria-label="connection health">
      <HealthStatusTile
        icon={Activity}
        label="Liveness"
        value={healthFact(model.readiness.availability, model.readiness.liveness)}
        meta={readinessCurrent ? (model.readiness.live ? "live" : "not live") : model.readiness.availability}
        tone={readinessCurrent && model.readiness.live ? "ok" : "warn"}
        pending={pending}
      />
      <HealthStatusTile
        icon={CheckCircle2}
        label="Readiness"
        value={healthFact(model.readiness.availability, model.readiness.readiness)}
        meta={readinessCurrent ? (model.readiness.ready ? "ready" : "unavailable") : model.readiness.availability}
        tone={readinessCurrent && model.readiness.ready ? "ok" : "warn"}
        pending={pending}
      />
      <HealthStatusTile
        icon={Database}
        label="Oracle database"
        value={healthFact(model.dbAvailability, model.db.connected ? "connected" : "degraded")}
        meta={dbCurrent ? model.db.source : model.dbAvailability}
        tone={dbCurrent && model.db.connected ? "ok" : "info"}
        pending={pending}
      />
      <HealthStatusTile
        icon={ShieldCheck}
        label="Database write mode"
        value={healthFact(model.dbAvailability, model.db.writePosture)}
        meta={healthFact(model.dbAvailability, model.db.openMode)}
        tone={dbCurrent && model.db.writePosture === "database_read_only" ? "ok" : "info"}
        pending={pending}
      />
    </section>
  );
}

function ServiceReadinessPanel({ model }: { model: ConnectionHealthUiModel }): React.ReactElement {
  const current = model.readiness.availability === "available";
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={Activity}
        title="Service Readiness"
        meta={current ? (model.readiness.ready ? "ready" : "unavailable") : model.readiness.availability}
        tone={current && model.readiness.ready ? "ok" : "warn"}
      />
      <div className="grid gap-3 p-4 sm:grid-cols-2">
        <CapacityFact label="Liveness" value={healthFact(model.readiness.availability, model.readiness.liveness)} mono />
        <CapacityFact label="Readiness" value={healthFact(model.readiness.availability, model.readiness.readiness)} mono />
        <CapacityFact label="DB reachable" value={healthFact(model.readiness.availability, model.readiness.dbReachable ? "true" : "false")} mono />
        <CapacityFact label="Draining" value={healthFact(model.readiness.availability, model.readiness.draining ? "true" : "false")} mono />
      </div>
    </Surface>
  );
}

function DbNativeStatusPanel({ model }: { model: ConnectionHealthUiModel }): React.ReactElement {
  const current = model.dbAvailability === "available";
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={Database}
        title="DB Native Status"
        meta={current ? (model.db.connected ? model.db.activeProfile : model.db.source) : model.dbAvailability}
        tone={current && model.db.connected ? "ok" : "info"}
      />
      <div className="grid gap-3 p-4 sm:grid-cols-3">
        <CapacityFact label="Role" value={healthFact(model.dbAvailability, model.db.databaseRole)} mono />
        <CapacityFact label="Open mode" value={healthFact(model.dbAvailability, model.db.openMode)} mono />
        <CapacityFact label="Standby" value={healthFact(model.dbAvailability, model.db.standby)} mono />
        <CapacityFact label="Strategy" value={healthFact(model.dbAvailability, model.db.strategy)} mono />
        <CapacityFact label="Pool open" value={healthFact(model.dbAvailability, model.db.poolOpenConnections ?? "unavailable")} />
        <CapacityFact label="Server" value={healthFact(model.dbAvailability, model.db.serverVersion)} mono />
        <CapacityFact label="Profile" value={healthFact(model.dbAvailability, model.db.activeProfile)} mono />
        <CapacityFact label="Read-only" value={healthFact(model.dbAvailability, model.db.readOnlyReason)} mono />
        <CapacityFact label="Error" value={model.db.error} mono />
      </div>
    </Surface>
  );
}

function healthFact(
  availability: "pending" | "available" | "stale" | "unavailable",
  value: string | number
): string {
  if (availability === "pending") {
    return "checking";
  }
  if (availability === "unavailable") {
    return "unavailable";
  }
  return availability === "stale" ? `${value} (stale)` : String(value);
}

function formatHealthMetric(
  value: number | null,
  availability: "pending" | "available" | "stale" | "unavailable",
  suffix = ""
): string {
  return value === null ? healthFact(availability, "unavailable") : healthFact(availability, `${formatNumber(value)}${suffix}`);
}

function PoolLatencyPanel({ model }: { model: ConnectionHealthUiModel }): React.ReactElement {
  const metricsAvailable = model.pool.active !== null;
  const metricsCurrent = model.pool.availability === "available";
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={Timer}
        title="Pool And Latency"
        meta={metricsCurrent && metricsAvailable ? `${formatNumber(model.pool.active ?? 0)} active` : model.pool.availability}
        tone={!metricsCurrent || !metricsAvailable || (model.pool.waitMeanMs ?? 0) > 500 || (model.pool.queryMeanMs ?? 0) > 500 ? "warn" : "ok"}
      />
      <div className="grid gap-3 p-4 sm:grid-cols-2">
        <CapacityFact label="Pool active" value={formatHealthMetric(model.pool.active, model.pool.availability)} />
        <CapacityFact label="Pool wait avg" value={formatHealthMetric(model.pool.waitMeanMs, model.pool.availability, "ms")} mono />
        <CapacityFact label="Pool wait max" value={formatHealthMetric(model.pool.waitMaxMs, model.pool.availability, "ms")} mono />
        <CapacityFact label="Query avg" value={formatHealthMetric(model.pool.queryMeanMs, model.pool.availability, "ms")} mono />
        <CapacityFact label="Query max" value={formatHealthMetric(model.pool.queryMaxMs, model.pool.availability, "ms")} mono />
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
        tone={rows.some((row) => row.status !== "applied") ? "warn" : "ok"}
      />
      <div className="overflow-x-auto" role="region" aria-label="Health data sources" tabIndex={0}>
        <table className="w-full min-w-[680px] border-collapse text-left">
          <caption className="sr-only">Status of database and server health data sources</caption>
          <thead className="bg-[var(--om-surface-muted)] text-xs uppercase text-[var(--om-text-muted)]">
            <tr>
              <th className="px-4 py-3 font-bold">Source</th>
              <th className="px-4 py-3 font-bold">Status</th>
              <th className="px-4 py-3 font-bold">Detail</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--om-border)]">
            {rows.map((row) => (
              <tr key={row.key} className="bg-[var(--om-surface)]">
                <td className="px-4 py-4 align-top font-mono text-sm font-semibold text-[var(--om-text-bright)]">
                  {row.source}
                </td>
                <td className="px-4 py-4 align-top">
                  <Badge tone={limitStatusTone(row.status)}>{row.status}</Badge>
                </td>
                <td className="px-4 py-4 align-top text-sm text-[var(--om-text-muted)]">{row.detail}</td>
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
        <div className="flex size-9 items-center justify-center rounded-md border border-[var(--om-border)] bg-[var(--om-surface-muted)] text-[var(--om-text)]">
          <Icon className="size-4" aria-hidden="true" />
        </div>
        <Badge tone={pending ? "info" : tone}>{pending ? "sync" : tone}</Badge>
      </div>
      <p className="mt-4 text-sm font-semibold text-[var(--om-text-muted)]">{label}</p>
      <strong className="mt-2 block truncate text-2xl leading-tight text-[var(--om-text-bright)]">{value}</strong>
      <p className="mt-2 truncate font-mono text-xs text-[var(--om-text-muted)]">{meta}</p>
    </Surface>
  );
}

export function authoritativeMetricsData(
  status: DashboardQueryStatus,
  response: OperatorResponse<OperatorMetricsData> | undefined
): OperatorMetricsData | null {
  return authoritativeQueryData(status, response)?.data ?? null;
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
  const metricsData = authoritativeMetricsData(metrics.status, metrics.data);
  const snapshot = metricsData?.snapshot ?? null;
  const capacity = metricsData?.capacity ?? null;
  const lanes = activeLanes.status === "success" ? activeLanes.data.data.lanes : EMPTY_ACTIVE_LANES;
  const activity = queryActivity(metrics, activeLanes);
  const pending = activity.blocking;
  const model = capacity ? capacityModel(capacity, snapshot, lanes) : null;
  const error = firstQueryError(metrics.error, activeLanes.error);
  const retryCapacityData = React.useCallback(() => {
    void metrics.refetch();
    void activeLanes.refetch();
  }, [activeLanes, metrics]);

  return (
    <PageFrame
      title="Resource limits"
      eyebrow="Concurrency and admission"
      description="Understand current usage, configured ceilings, and when new database work will wait or be refused."
    >
      {model ? (
        <div className="space-y-4">
          <BackgroundRefreshStatus refreshing={activity.refreshing} />
          {error ? (
            <QueryErrorNotice
              title="Some resource-limit data is unavailable"
              error={error}
              retryLabel="Retry resource-limit data"
              onRetry={retryCapacityData}
            />
          ) : null}
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
      ) : (
        <ConsolePanel className="p-4" aria-busy={pending}>
          {error ? (
            <QueryErrorNotice
              title="Resource limits are unavailable"
              error={error}
              retryLabel="Retry resource-limit data"
              onRetry={retryCapacityData}
            />
          ) : (
            <p className="text-sm text-[var(--om-text-muted)]" role="status">
              Loading resource limits…
            </p>
          )}
        </ConsolePanel>
      )}
    </PageFrame>
  );
}

// The I·II·III·IV clearance spine as roman rank + matching --om clearance token,
// used by the Profile ceiling badge (color IS clearance, Appendix G).
const CEILING_ROMAN = ["I", "II", "III", "IV"] as const;
const CEILING_VARS = [
  "--om-clearance-read-only",
  "--om-clearance-read-write",
  "--om-clearance-ddl",
  "--om-clearance-admin"
] as const;

function ceilingOrdinal(level?: string): number {
  switch ((level ?? "").toUpperCase()) {
    case "ADMIN":
      return 3;
    case "DDL":
      return 2;
    case "READ_WRITE":
      return 1;
    default:
      return 0;
  }
}

// Four squares filled up to the profile's max_level; each filled square wears
// its own level's clearance color so the ceiling reads as a ramp.
function CeilingBadge({ maxLevel }: { maxLevel?: string }): React.ReactElement {
  const ceiling = ceilingOrdinal(maxLevel);
  return (
    <div
      className="flex items-center gap-1"
      role="img"
      aria-label={`ceiling ${maxLevel ?? "READ_ONLY"}`}
    >
      {CEILING_ROMAN.map((roman, index) => {
        const filled = index <= ceiling;
        const token = CEILING_VARS[index];
        return (
          <span
            key={roman}
            className="inline-flex size-5 items-center justify-center rounded-sm border font-mono text-2xs font-bold"
            style={{
              borderColor: filled ? `var(${token})` : "var(--om-border)",
              backgroundColor: filled
                ? `color-mix(in srgb, var(${token}) 22%, transparent)`
                : "transparent",
              color: filled ? `var(${token})` : "var(--om-text-muted)"
            }}
          >
            {roman}
          </span>
        );
      })}
    </div>
  );
}

function profilePosture(profile: ConfigProfileMetadata): { label: string; tone: DashboardTone } {
  if (profile.protected) {
    return { label: "PROTECTED", tone: "ok" };
  }
  if (profile.read_only_standby) {
    return { label: "STANDBY", tone: "info" };
  }
  return { label: "ACTIVE", tone: "neutral" };
}

// Per-profile reachability: only the active/default profile's connection is
// probed by /operator/v1/health (db_reachable). Non-default profiles are shown
// as "unprobed" rather than inferring a status we cannot assert.
function profileReachability(
  profile: ConfigProfileMetadata,
  dbReachable: boolean | undefined
): { label: string; tone: DashboardTone } {
  if (profile.is_default) {
    if (dbReachable === true) {
      return { label: "reachable", tone: "ok" };
    }
    if (dbReachable === false) {
      return { label: "unreachable", tone: "warn" };
    }
  }
  return { label: "unprobed", tone: "off" };
}

function ProfileCard({
  profile,
  dbReachable
}: {
  profile: ConfigProfileMetadata;
  dbReachable: boolean | undefined;
}): React.ReactElement {
  const posture = profilePosture(profile);
  const reach = profileReachability(profile, dbReachable);
  return (
    <div
      className="flex flex-col gap-3 rounded-lg border border-[var(--om-border)] bg-[var(--om-surface)] p-4 shadow-sm"
      data-profile-posture={posture.label.toLowerCase()}
      data-profile-ceiling={profile.max_level ?? "READ_ONLY"}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p
            className="truncate font-mono text-sm font-bold text-[var(--om-text-bright)]"
            title={profile.name}
          >
            {profile.name}
          </p>
          {profile.description ? (
            <p className="mt-0.5 truncate font-serif text-xs text-[var(--om-text-muted)]">
              {profile.description}
            </p>
          ) : null}
        </div>
        {profile.is_default ? <Badge tone="info">default</Badge> : null}
      </div>
      <div className="flex items-center justify-between gap-2">
        <span className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
          Ceiling
        </span>
        <CeilingBadge maxLevel={profile.max_level} />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={posture.tone}>{posture.label}</Badge>
        {profile.read_only_standby ? <Badge tone="info">read-only standby</Badge> : null}
        {profile.require_signed_tools ? <Badge tone="neutral">signed tools</Badge> : null}
      </div>
      <div className="mt-auto flex items-center justify-between gap-2 border-t border-[var(--om-border)] pt-2">
        <Badge tone={reach.tone}>{reach.label}</Badge>
        <div className="flex items-baseline gap-1.5">
          <span className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
            default
          </span>
          <span className="font-mono text-xs text-[var(--om-text)]">
            {profile.default_level ?? "READ_ONLY"}
          </span>
        </div>
      </div>
    </div>
  );
}

export function authoritativeProfileReachability(
  status: DashboardQueryStatus,
  response: OperatorResponse<OperatorHealthData> | undefined
): boolean | undefined {
  return authoritativeQueryData(status, response)?.data.readiness?.db_reachable;
}

// Profile cards (Appendix G, net-new surface): one Carved Light card per
// connection profile — reachability, ceiling ramp, posture, read-only-standby —
// fed from the live /operator/v1/config profile metadata plus /operator/v1/health
// for the active connection's reachability. No browser-supplied identity; the
// server derives everything from the transport principal.
function ProfileCards(): React.ReactElement {
  const config = useQuery({
    queryKey: ["operator-config"],
    queryFn: fetchOperatorConfig
  });
  const health = useQuery({
    queryKey: ["operator-health"],
    queryFn: fetchOperatorHealth,
    refetchInterval: 5_000
  });
  const configData = authoritativeQueryData(config.status, config.data)?.data;
  const profiles = configData?.status.profiles ?? [];
  const dbReachable = authoritativeProfileReachability(health.status, health.data);
  const source = configData?.source ?? "unavailable";
  return (
    <section aria-label="connection profiles" className="space-y-3">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Database className="size-4 text-[var(--om-text-muted)]" aria-hidden="true" />
          <h2 className="font-serif text-lg font-semibold text-[var(--om-text-bright)]">
            Connection Profiles
          </h2>
        </div>
        <Badge tone={config.isError ? "warn" : config.data ? "ok" : "info"}>
          {config.isError ? "blocked" : config.data ? source : "sync"}
        </Badge>
      </div>
      {health.error instanceof Error ? (
        <QueryErrorNotice
          title="Default profile reachability is unavailable"
          error={health.error}
          retryLabel="Retry reachability"
          onRetry={() => void health.refetch()}
        />
      ) : null}
      {config.isError ? (
        <QueryErrorNotice
          title="Connection profiles are unavailable"
          error={config.error instanceof Error ? config.error : new Error("profile request failed")}
          retryLabel="Retry profiles"
          onRetry={() => void config.refetch()}
        />
      ) : profiles.length === 0 ? (
        <div className="rounded-lg border border-dashed border-[var(--om-border)] bg-[var(--om-surface)] p-6 text-center">
          <p className="font-mono text-sm font-semibold text-[var(--om-text-bright)]">NO PROFILES</p>
          <p className="mt-1 text-sm text-[var(--om-text-muted)]">
            {config.isPending ? "syncing" : "none configured"}
          </p>
        </div>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {profiles.map((profile) => (
            <ProfileCard key={profile.name} profile={profile} dbReachable={dbReachable} />
          ))}
        </div>
      )}
    </section>
  );
}

function ConfigPage(): React.ReactElement {
  const [draftToml, setDraftToml] = React.useState("");
  const [preview, setPreview] = React.useState<ConfigDraftPreview | null>(null);
  const [applyOutcome, setApplyOutcome] = React.useState<ConfigApplyData | null>(null);
  const [appliedDraft, setAppliedDraft] = React.useState("");
  const [lastError, setLastError] = React.useState<string | null>(null);
  const [previewConfirmed, setPreviewConfirmed] = React.useState(false);
  const [rollbackPending, setRollbackPending] = React.useState(false);
  // Only the exact TOML that produced the last successful apply is saved.
  // Editing afterward must restore navigation protection even while the old
  // rollback receipt remains available.
  const draftGuard = useUnsavedChangesGuard(
    draftToml.trim().length > 0 && draftToml !== appliedDraft
  );
  const session = useQuery({
    queryKey: ["dashboard-session"],
    queryFn: fetchDashboardSession,
    staleTime: 60_000,
    refetchInterval: 60_000,
    retry: 1
  });
  const sessionAuthority = dashboardAuthorityIdentity(
    session.status === "success" ? session.data : undefined
  );
  const config = useQuery({
    queryKey: ["operator-config"],
    queryFn: fetchOperatorConfig
  });
  const status = config.data?.data ?? null;
  const authority = configurationAuthority(config.status, session.status);
  const previewRemaining = useAbsoluteExpiryCountdown(
    preview?.preview_expires_unix ?? null,
    () => {
      setPreview(null);
      setPreviewConfirmed(false);
      setLastError("Configuration preview expired. Preview the current draft again.");
    }
  );
  const activePreview = previewRemaining === 0 ? null : preview;
  const previewMutation = useMutation({
    mutationFn: async (requestAuthority: string) => {
      if (
        !session.data ||
        !config.data ||
        !sessionAuthority ||
        requestAuthority !== sessionAuthority
      ) {
        throw new Error("authoritative configuration state is not ready");
      }
      return previewConfigDraft(session.data, draftToml);
    },
    onSuccess: (response, requestAuthority) => {
      if (requestAuthority !== sessionAuthority) {
        return;
      }
      if (!absoluteExpiryIsActive(response.data.preview.preview_expires_unix)) {
        setPreview(null);
        setPreviewConfirmed(false);
        setLastError("Configuration preview expired before it arrived. Preview again.");
        return;
      }
      setPreview(response.data.preview);
      setPreviewConfirmed(false);
      setApplyOutcome(null);
      setLastError(null);
    },
    onError: (error, requestAuthority) => {
      if (requestAuthority !== sessionAuthority) {
        return;
      }
      setLastError(error instanceof Error ? error.message : "preview failed");
    }
  });
  const applyMutation = useMutation({
    mutationFn: async (requestAuthority: string) => {
      if (!session.data || !sessionAuthority || requestAuthority !== sessionAuthority) {
        throw new Error("dashboard session is not ready");
      }
      if (!activePreview) {
        throw new Error("preview the exact draft before applying");
      }
      if (!absoluteExpiryIsActive(activePreview.preview_expires_unix)) {
        throw new Error("configuration preview expired; preview the current draft again");
      }
      return applyConfigDraft(
        session.data,
        draftToml,
        activePreview.preview_token,
        activePreview.draft_sha256,
        previewConfirmed
      );
    },
    onSuccess: (response, requestAuthority) => {
      if (requestAuthority !== sessionAuthority) {
        return;
      }
      setApplyOutcome(response.data);
      setAppliedDraft(draftToml);
      setPreview(null);
      setPreviewConfirmed(false);
      setLastError(null);
      queryClient.invalidateQueries({ queryKey: ["operator-config"] });
    },
    onError: (error, requestAuthority) => {
      if (requestAuthority !== sessionAuthority) {
        return;
      }
      setLastError(error instanceof Error ? error.message : "apply failed");
    }
  });

  const rollbackMutation = useMutation({
    mutationFn: async ({
      rollbackId,
      authority: requestAuthority
    }: {
      rollbackId: string;
      authority: string;
    }) => {
      if (!session.data || !sessionAuthority || requestAuthority !== sessionAuthority) {
        throw new Error("dashboard session is not ready");
      }
      return rollbackConfigDraft(session.data, rollbackId);
    },
    onSuccess: (_response, { authority: requestAuthority }) => {
      if (requestAuthority !== sessionAuthority) {
        return;
      }
      setApplyOutcome(null);
      setAppliedDraft("");
      setPreview(null);
      setPreviewConfirmed(false);
      setLastError(null);
      queryClient.invalidateQueries({ queryKey: ["operator-config"] });
    },
    onError: (error, { authority: requestAuthority }) => {
      if (requestAuthority !== sessionAuthority) {
        return;
      }
      setLastError(error instanceof Error ? error.message : "rollback failed");
    }
  });
  const purgeConfigAuthorityState = React.useCallback(() => {
    setPreview(null);
    setPreviewConfirmed(false);
    setApplyOutcome(null);
    setRollbackPending(false);
    setLastError(null);
    previewMutation.reset();
    applyMutation.reset();
    rollbackMutation.reset();
  }, [applyMutation.reset, previewMutation.reset, rollbackMutation.reset]);
  useDashboardAuthorityPurge(sessionAuthority, purgeConfigAuthorityState);
  const canSubmit = draftToml.trim().length > 0 && authority.ready;
  const canApply =
    canSubmit &&
    activePreview !== null &&
    (!activePreview.confirmation_required || previewConfirmed);
  const busy =
    previewMutation.isPending || applyMutation.isPending || rollbackMutation.isPending;

  return (
    <PageFrame
      title="Profiles & settings"
      eyebrow="Database profiles"
      description="Review profile safety limits and preview any redacted configuration change before it is applied."
    >
      <div className="space-y-4">
        {draftGuard.status === "blocked" ? (
          <ConfirmDialog
            id="config-unsaved"
            title="Leave with an unapplied draft?"
            body="Your configuration draft has not been applied. Leaving this page discards it."
            confirmLabel="Leave and discard"
            onCancel={draftGuard.reset}
            onConfirm={draftGuard.proceed}
          />
        ) : null}
        <ProfileCards />
        {config.error instanceof Error ? (
          <QueryErrorNotice
            title="Configuration state is unavailable"
            error={config.error}
            retryLabel="Retry configuration"
            onRetry={() => void config.refetch()}
          />
        ) : null}
        {session.error instanceof Error ? (
          <QueryErrorNotice
            title="Dashboard authority is unavailable"
            error={session.error}
            retryLabel="Retry pairing state"
            onRetry={() => void session.refetch()}
          />
        ) : null}
        <ConfigStatusPanel data={status} state={config.status} />
        <Surface className="overflow-hidden">
          <PanelHeader
            icon={SlidersHorizontal}
            title="Draft"
            meta={authority.state === "available" ? "authoritative state loaded" : authority.state}
            tone={authority.state === "available" ? "ok" : authority.state === "unavailable" ? "warn" : "info"}
          />
          <div className="space-y-3 p-4">
            <textarea
              value={draftToml}
              onChange={(event) => {
                setDraftToml(event.target.value);
                setPreview(null);
                setPreviewConfirmed(false);
              }}
              spellCheck={false}
              className={cn(OM_TEXTAREA, "min-h-72 font-mono leading-6")}
              aria-label="Config draft TOML"
              disabled={!authority.ready || busy}
            />
            <div className="flex flex-wrap items-center gap-2">
              <Button
                type="button"
                variant="secondary"
                disabled={!canSubmit || busy}
                onClick={() => previewMutation.mutate(sessionAuthority ?? "")}
              >
                <RefreshCcw className="size-4" aria-hidden="true" />
                Preview
              </Button>
              <Button
                type="button"
                variant="primary"
                disabled={!canApply || busy}
                onClick={() => applyMutation.mutate(sessionAuthority ?? "")}
              >
                <Play className="size-4" aria-hidden="true" />
                Apply
              </Button>
              {activePreview?.confirmation_required ? (
                <label className={OM_CHECK_LABEL}>
                  <input
                    className={OM_CHECKBOX}
                    type="checkbox"
                    checked={previewConfirmed}
                    onChange={(event) => setPreviewConfirmed(event.target.checked)}
                  />
                  I reviewed the sensitive change: {activePreview.confirmation_reasons.join(", ")}
                </label>
              ) : null}
              {activePreview && previewRemaining !== null ? (
                <Badge tone={previewRemaining > 0 ? "info" : "warn"} role="status">
                  Preview valid for {previewRemaining} seconds
                </Badge>
              ) : null}
              {applyOutcome ? (
                <Button
                  type="button"
                  variant="secondary"
                  disabled={busy}
                  onClick={() => setRollbackPending(true)}
                >
                  <RotateCcw className="size-4" aria-hidden="true" />
                  Rollback
                </Button>
              ) : null}
              {applyOutcome && rollbackPending ? (
                <ConfirmDialog
                  id="config-rollback"
                  title="Roll back configuration"
                  body={
                    <>
                      Roll back the applied configuration change and restore rollback id{" "}
                      <span className="font-mono font-semibold text-[var(--om-text-bright)]">
                        {applyOutcome.outcome.rollback_id}
                      </span>
                      ?
                    </>
                  }
                  confirmLabel="Roll back"
                  busy={busy}
                  onCancel={() => setRollbackPending(false)}
                  onConfirm={() => {
                    setRollbackPending(false);
                    rollbackMutation.mutate({
                      rollbackId: applyOutcome.outcome.rollback_id,
                      authority: sessionAuthority ?? ""
                    });
                  }}
                />
              ) : null}
              {lastError ? (
                <Badge tone="warn" role="alert" className="max-w-full whitespace-normal break-all">
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
  state
}: {
  data: ConfigOpsStatusData | null;
  state: "pending" | "error" | "success";
}): React.ReactElement {
  const status = state === "success" ? data?.status : undefined;
  const unavailable = state === "pending" ? "checking" : "unavailable";
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={Database}
        title="Current Target"
        meta={status ? (status.target_exists ? "configured" : "new file") : unavailable}
        tone={state === "pending" ? "info" : status ? "ok" : "warn"}
      />
      <div className="grid gap-3 p-4 md:grid-cols-2 xl:grid-cols-5">
        <CapacityFact label="Target" value={status?.target_path ?? unavailable} mono />
        <CapacityFact label="Current SHA" value={status ? shortHash(status.current_sha256) : unavailable} mono />
        <CapacityFact label="Default" value={status?.default_profile ?? unavailable} mono />
        <CapacityFact label="Profiles" value={status?.profiles.length ?? unavailable} />
        <CapacityFact
          label="Browser SQL"
          value={status ? (status.dashboard_workbench ? "enabled" : "disabled") : unavailable}
        />
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
      <div className="overflow-x-auto" role="region" aria-label="Redacted configuration changes" tabIndex={0}>
        <table className="w-full min-w-[720px] border-collapse text-left">
          <caption className="sr-only">Redacted configuration changes in this preview</caption>
          <thead className="bg-[var(--om-surface-muted)] text-xs uppercase text-[var(--om-text-muted)]">
            <tr>
              <th className="px-4 py-3 font-bold">Path</th>
              <th className="px-4 py-3 font-bold">Before</th>
              <th className="px-4 py-3 font-bold">After</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--om-border)]">
            {changes.length === 0 ? (
              <tr>
                <td className="px-4 py-4 text-sm text-[var(--om-text-muted)]" colSpan={3}>
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
    <tr className="bg-[var(--om-surface)]">
      <td className="px-4 py-4 align-top font-mono text-sm font-semibold text-[var(--om-text-bright)]">
        {change.path}
      </td>
      <td className="px-4 py-4 align-top font-mono text-xs text-[var(--om-text-muted)]">
        {compactJson(change.before)}
      </td>
      <td className="px-4 py-4 align-top font-mono text-xs text-[var(--om-text-muted)]">
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
            <div className="overflow-x-auto" role="region" aria-label="Profile reload plan" tabIndex={0}>
              <table className="w-full min-w-[420px] border-collapse text-left">
                <caption className="sr-only">Reload action and reason for each database profile</caption>
                <thead className="bg-[var(--om-surface-muted)] text-xs uppercase text-[var(--om-text-muted)]">
                  <tr>
                    <th className="px-3 py-2 font-bold">Profile</th>
                    <th className="px-3 py-2 font-bold">Action</th>
                    <th className="px-3 py-2 font-bold">Reason</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--om-border)]">
                  {plan.profiles.map((decision) => (
                    <tr key={decision.profile}>
                      <td className="px-3 py-3 font-mono text-sm font-semibold text-[var(--om-text-bright)]">
                        {decision.profile}
                      </td>
                      <td className="px-3 py-3">
                        <Badge tone={decision.action === "drain" ? "warn" : "ok"}>
                          {decision.action}
                        </Badge>
                      </td>
                      <td className="px-3 py-3 font-mono text-xs text-[var(--om-text-muted)]">
                        {decision.reason}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          <p className="text-sm text-[var(--om-text-muted)]">No preview</p>
        )}
      </div>
    </Surface>
  );
}

export function authoritativeClientCredentials(
  status: DashboardQueryStatus,
  response: OperatorResponse<ClientCredentialsData> | undefined
): ClientCredentialsData | null {
  return authoritativeQueryData(status, response)?.data ?? null;
}

function ClientsPage(): React.ReactElement {
  const [rotated, setRotated] = React.useState<ClientCredentialRotateData | null>(null);
  const [lastError, setLastError] = React.useState<string | null>(null);
  const [lastNotice, setLastNotice] = React.useState<string | null>(null);
  const [lastWarning, setLastWarning] = React.useState<string | null>(null);
  const [pendingAction, setPendingAction] = React.useState<ClientCredentialPendingAction | null>(
    null
  );
  const [typedClientId, setTypedClientId] = React.useState("");
  const session = useQuery({
    queryKey: ["dashboard-session"],
    queryFn: fetchDashboardSession,
    staleTime: 60_000,
    refetchInterval: 60_000,
    retry: 1
  });
  const clients = useQuery({
    queryKey: ["client-credentials"],
    queryFn: fetchClientCredentials
  });
  const rotateMutation = useMutation({
    mutationKey: CLIENT_ROTATION_MUTATION_KEY,
    mutationFn: async (client: ClientCredentialView) => {
      if (session.status !== "success" || !session.data) {
        throw new Error("dashboard session is not ready");
      }
      return rotateClientCredential(session.data, client.client_id);
    },
    onSuccess: (response) => {
      setRotated(response.data);
      setLastError(null);
      setLastNotice(null);
      setLastWarning(null);
      queryClient.invalidateQueries({ queryKey: ["client-credentials"] });
    },
    onError: (error) => {
      setLastError(error instanceof Error ? error.message : "rotate failed");
    }
  });
  const resetRotation = rotateMutation.reset;
  const clearRotatedCredential = React.useCallback(() => {
    setRotated(null);
    purgeClientRotationMutation(queryClient, resetRotation);
  }, [resetRotation]);
  const sessionAuthority = dashboardAuthorityIdentity(
    session.status === "success" ? session.data : undefined
  );
  const priorSessionAuthority = React.useRef<string | null>(null);
  React.useEffect(() => {
    const changed = Boolean(
      priorSessionAuthority.current &&
      sessionAuthority &&
      priorSessionAuthority.current !== sessionAuthority
    );
    if (session.status !== "success" || changed) {
      clearRotatedCredential();
      setPendingAction(null);
      setTypedClientId("");
    }
    priorSessionAuthority.current = sessionAuthority;
  }, [clearRotatedCredential, session.status, sessionAuthority]);
  React.useEffect(
    () => () => purgeClientRotationMutation(queryClient, resetRotation),
    [resetRotation]
  );
  const revokeMutation = useMutation({
    mutationFn: async (client: ClientCredentialView) => {
      if (session.status !== "success" || !session.data) {
        throw new Error("dashboard session is not ready");
      }
      return revokeClientCredential(session.data, client.client_id);
    },
    onSuccess: (_response, client) => {
      setLastError(null);
      setLastNotice(`Client ${client.client_id} revoked.`);
      setLastWarning(_response.data.durability_warning ?? null);
      clearRotatedCredential();
      queryClient.invalidateQueries({ queryKey: ["client-credentials"] });
    },
    onError: (error) => {
      setLastError(error instanceof Error ? error.message : "revoke failed");
    }
  });
  const clientData = authoritativeClientCredentials(clients.status, clients.data);
  const rows = clientData?.clients ?? [];
  const clientState = collectionViewState(clients.status, rows.length);
  const busy = rotateMutation.isPending || revokeMutation.isPending;
  const requestAction = (
    kind: ClientCredentialPendingAction["kind"],
    client: ClientCredentialView
  ): void => {
    if (busy) {
      return;
    }
    setLastError(null);
    setLastNotice(null);
    setLastWarning(null);
    setTypedClientId("");
    setPendingAction({ kind, client });
  };
  const confirmAction = (): void => {
    const action = pendingAction;
    if (!action || busy || !clientCredentialConfirmationReady(action, typedClientId)) {
      return;
    }
    setPendingAction(null);
    setTypedClientId("");
    if (action.kind === "rotate") {
      clearRotatedCredential();
      rotateMutation.mutate(action.client);
    } else {
      revokeMutation.mutate(action.client);
    }
  };

  return (
    <PageFrame
      title="MCP clients"
      eyebrow="Client authentication"
      description="Rotate or revoke credentials used by MCP clients that connect to this server."
    >
      <div className="space-y-4">
        {clients.error instanceof Error ? (
          <QueryErrorNotice
            title="Client inventory is unavailable"
            error={clients.error}
            retryLabel="Retry clients"
            onRetry={() => void clients.refetch()}
          />
        ) : null}
        <ClientCredentialSummary
          rows={rows}
          state={clientState}
          source={clientData?.source ?? (clients.isError ? "unavailable" : "pending")}
        />
        {rotated ? (
          <ClientCredentialBearerPanel rotated={rotated} onDismiss={clearRotatedCredential} />
        ) : null}
        {pendingAction ? (
          <ClientCredentialConfirmationDialog
            action={pendingAction}
            busy={busy}
            typedClientId={typedClientId}
            onTypedClientId={setTypedClientId}
            onCancel={() => {
              setPendingAction(null);
              setTypedClientId("");
            }}
            onConfirm={confirmAction}
          />
        ) : null}
        <ClientCredentialTable
          rows={rows}
          sessionReady={session.status === "success"}
          state={clientState}
          busy={busy}
          rotatingClientId={rotateMutation.variables?.client_id ?? null}
          revokingClientId={revokeMutation.variables?.client_id ?? null}
          onRotate={(client) => requestAction("rotate", client)}
          onRevoke={(client) => requestAction("revoke", client)}
        />
        {lastNotice ? <Badge tone="ok" role="status">{lastNotice}</Badge> : null}
        {lastWarning ? (
          <Badge tone="warn" role="alert" className="max-w-full whitespace-normal">
            Credential change completed, but durability needs review: {lastWarning}
          </Badge>
        ) : null}
        {lastError ? (
          <Badge tone="warn" role="alert" className="max-w-full whitespace-normal break-all">
            {lastError}
          </Badge>
        ) : null}
      </div>
    </PageFrame>
  );
}

function ClientCredentialSummary({
  rows,
  state,
  source
}: {
  rows: ClientCredentialView[];
  state: CollectionViewState;
  source: string;
}): React.ReactElement {
  const active = rows.filter((client) => client.status === "active").length;
  const revoked = rows.filter((client) => client.status === "revoked").length;
  const used = rows.filter((client) => Boolean(client.last_used_at)).length;
  const value = (count: number): number | string =>
    state === "unavailable" ? "unavailable" : state === "pending" ? "checking" : count;
  const pending = state === "pending";
  return (
    <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-4" aria-label="client credentials">
      <MetricTile icon={KeyRound} label="Registered" value={value(rows.length)} suffix="" tone={rows.length > 0 ? "ok" : "off"} pending={pending} />
      <MetricTile icon={ShieldCheck} label="Active" value={value(active)} suffix="" tone={active > 0 ? "ok" : "off"} pending={pending} />
      <MetricTile icon={Ban} label="Revoked" value={value(revoked)} suffix="" tone={revoked > 0 ? "warn" : "ok"} pending={pending} />
      <MetricTile icon={Wifi} label="Used" value={value(used)} suffix="" tone={source === "client_credentials" ? "info" : "off"} pending={pending} />
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
  const [copyState, setCopyState] = React.useState<"idle" | "copied" | "failed">("idle");
  const copyBearer = async (): Promise<void> => {
    try {
      if (typeof navigator === "undefined" || !navigator.clipboard) {
        throw new Error("clipboard unavailable");
      }
      await navigator.clipboard.writeText(rotated.bearer);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  };
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={KeyRound}
        title="New one-time client bearer"
        meta={rotated.client.client_id}
        tone={rotated.bearer_shown_once ? "ok" : "warn"}
      />
      <div className="space-y-3 p-4">
        <p className="text-sm text-[var(--om-text)]" role="status" aria-live="polite">
          A new client credential was created. Its bearer is shown once below; copy it before clearing this panel.
        </p>
        {rotated.durability_warning ? (
          <p className="rounded-md border border-[var(--om-copper)] bg-[color-mix(in_srgb,var(--om-copper)_14%,transparent)] p-3 text-sm font-semibold text-[var(--om-text-bright)]" role="alert">
            Durability needs review: {rotated.durability_warning}
          </p>
        ) : null}
        <div className="grid gap-3 sm:grid-cols-3">
          <CapacityFact label="Generation" value={rotated.client.generation} />
          <CapacityFact label="Closed" value={rotated.closed_sessions} />
          <CapacityFact label="Durability" value={rotated.durability} mono />
        </div>
        <textarea
          className={cn(OM_TEXTAREA, "min-h-24 font-mono text-xs")}
          aria-label="New client bearer"
          readOnly
          value={rotated.bearer}
          onFocus={(event) => event.currentTarget.select()}
        />
        <p className="text-sm font-semibold text-[var(--om-text-muted)]">
          This replacement bearer is shown once. Copy it into the client configuration before clearing it from this screen.
        </p>
        {copyState === "failed" ? (
          <p className="text-sm text-[var(--om-rust)]" role="alert">
            Automatic copy is unavailable. Select the bearer field and copy it manually.
          </p>
        ) : null}
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            variant="secondary"
            onClick={() => void copyBearer()}
          >
            <KeyRound className="size-4" aria-hidden="true" />
            {copyState === "copied" ? "Copied" : "Copy bearer"}
          </Button>
          <Button type="button" variant="secondary" onClick={onDismiss}>
            <Ban className="size-4" aria-hidden="true" />
            Clear from screen
          </Button>
        </div>
      </div>
    </Surface>
  );
}

type ClientCredentialPendingAction = {
  kind: "rotate" | "revoke";
  client: ClientCredentialView;
};

export function clientCredentialConfirmationReady(
  action: ClientCredentialPendingAction,
  typedClientId: string
): boolean {
  return typedClientId === action.client.client_id;
}

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Own a modal's whole focus lifecycle: remember what opened it, move focus
 * inside, keep Tab within it, and hand focus back on close. `aria-modal` tells
 * assistive tech the rest of the page is inert; without a trap that is a
 * promise we do not keep.
 *
 * The hook does the initial focus itself, and the dialog's controls must NOT
 * use `autoFocus`. React applies `autoFocus` during commit, before a passive
 * effect runs — so a dialog that autofocused its own control would leave this
 * effect reading that control as the "invoker", and focus would never return
 * to the trigger.
 */
function useModalFocus<T extends HTMLElement>(): React.RefObject<T | null> {
  const ref = React.useRef<T | null>(null);
  React.useEffect(() => {
    const node = ref.current;
    if (!node) {
      return;
    }
    const invoker = document.activeElement as HTMLElement | null;
    const firstFocusable = node.querySelector<HTMLElement>(FOCUSABLE_SELECTOR);
    firstFocusable?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Tab") {
        return;
      }
      const items = Array.from(node.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR));
      if (items.length === 0) {
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement;
      if (event.shiftKey && (active === first || !node.contains(active))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    };
    node.addEventListener("keydown", onKeyDown);
    return () => {
      node.removeEventListener("keydown", onKeyDown);
      // Returning focus to the trigger keeps the keyboard user where they were,
      // instead of dumping them at the top of the document.
      if (invoker && typeof invoker.focus === "function" && document.contains(invoker)) {
        invoker.focus();
      }
    };
  }, []);
  return ref;
}

/**
 * The console's own confirmation dialog, for destructive actions that need a
 * deliberate second act but no typed-token ceremony. It replaces
 * `window.confirm`, which cannot be styled, focus-managed, or asserted in a
 * test — the backend step-up grant remains the real gate; this is misclick
 * protection.
 */
/** The SQL the Workbench opens with. Editor content equal to it is not the
 *  operator's work, so leaving with it untouched must not warn. */
const WORKBENCH_SQL_SEED = "SELECT * FROM dual";

/**
 * Warn before leaving a page that still holds unsaved work. Navigation within
 * the same route (selecting a lane, say) is never blocked — only actually
 * leaving. `enableBeforeUnload` covers the tab close and reload the router
 * cannot intercept itself.
 */
function useUnsavedChangesGuard(dirty: boolean) {
  return useBlocker({
    shouldBlockFn: ({ current, next }) => dirty && next.routeId !== current.routeId,
    enableBeforeUnload: () => dirty,
    withResolver: true
  });
}

export function ConfirmDialog({
  title,
  body,
  confirmLabel,
  busy = false,
  id,
  onCancel,
  onConfirm
}: {
  title: string;
  body: React.ReactNode;
  confirmLabel: string;
  busy?: boolean;
  id: string;
  onCancel: () => void;
  onConfirm: () => void;
}): React.ReactElement {
  const titleId = `${id}-confirm-title`;
  return (
    <ModalShell id={id} titleId={titleId} busy={busy} onCancel={onCancel}>
      <div data-omcp-dialog={id}>
        <h3 id={titleId} className="text-base font-semibold text-[var(--om-text-bright)]">
          {title}
        </h3>
        <p className="mt-2 text-sm text-[var(--om-text-muted)]">{body}</p>
        <div className="mt-4 flex flex-wrap gap-2">
          {/* No autoFocus: useModalFocus moves focus here itself, after it has
              recorded the trigger to return focus to. Cancel is first, so the
              safe choice is what receives focus. */}
          <Button type="button" variant="secondary" disabled={busy} onClick={onCancel}>
            Cancel
          </Button>
          <Button type="button" variant="primary" disabled={busy} onClick={onConfirm}>
            {busy ? "Working" : confirmLabel}
          </Button>
        </div>
      </div>
    </ModalShell>
  );
}

function ModalShell({
  id,
  titleId,
  busy,
  onCancel,
  children
}: {
  id: string;
  titleId: string;
  busy: boolean;
  onCancel: () => void;
  children: React.ReactNode;
}): React.ReactElement {
  const dialogRef = useModalFocus<HTMLDivElement>();
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-[color-mix(in_srgb,var(--om-bg)_80%,transparent)] p-4"
      data-omcp-dialog-backdrop={id}
    >
      <div
        ref={dialogRef}
        className="w-full max-w-lg rounded-md border border-[color-mix(in_srgb,var(--om-copper)_55%,transparent)] bg-[var(--om-surface)] p-4 shadow-lg"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onKeyDown={(event) => {
          if (event.key === "Escape" && !busy) onCancel();
        }}
      >
        {children}
      </div>
    </div>
  );
}

function ClientCredentialConfirmationDialog({
  action,
  busy,
  typedClientId,
  onTypedClientId,
  onCancel,
  onConfirm
}: {
  action: ClientCredentialPendingAction;
  busy: boolean;
  typedClientId: string;
  onTypedClientId: (value: string) => void;
  onCancel: () => void;
  onConfirm: () => void;
}): React.ReactElement {
  const destructiveLabel = action.kind === "rotate" ? "Rotate credential" : "Revoke credential";
  return (
    <ModalShell
      id="client-credential"
      titleId="client-credential-confirm-title"
      busy={busy}
      onCancel={onCancel}
    >
        <h3
          id="client-credential-confirm-title"
          className="text-base font-semibold text-[var(--om-text-bright)]"
        >
          {destructiveLabel}
        </h3>
        <p className="mt-2 text-sm text-[var(--om-text-muted)]">
          <span className="font-mono font-semibold text-[var(--om-text-bright)]">
            {action.client.client_id}
          </span>{" "}
          ({action.client.label}), generation {action.client.generation}, scopes{" "}
          {action.client.scopes.join(", ") || "none"}. This closes its active MCP sessions.
          {action.kind === "rotate"
            ? " The replacement bearer is shown once."
            : " Revocation cannot be undone."}
        </p>
        <label className="mt-3 block">
          <span className={OM_LABEL}>Type the exact client ID to confirm</span>
          {/* No autoFocus: useModalFocus focuses this (the first focusable)
              itself, after recording the trigger to return focus to. */}
          <input
            className={cn(OM_INPUT, "font-mono")}
            value={typedClientId}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => onTypedClientId(event.target.value)}
          />
        </label>
        <div className="mt-4 flex flex-wrap gap-2">
          <Button type="button" variant="secondary" disabled={busy} onClick={onCancel}>
            Cancel
          </Button>
          <Button
            type="button"
            variant="primary"
            disabled={busy || !clientCredentialConfirmationReady(action, typedClientId)}
            onClick={onConfirm}
          >
            {busy ? "Working" : destructiveLabel}
          </Button>
        </div>
    </ModalShell>
  );
}

function ClientCredentialTable({
  rows,
  sessionReady,
  state,
  busy,
  rotatingClientId,
  revokingClientId,
  onRotate,
  onRevoke
}: {
  rows: ClientCredentialView[];
  sessionReady: boolean;
  state: CollectionViewState;
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
        meta={state === "unavailable" ? "unavailable" : state === "pending" ? "checking" : `${rows.length} clients`}
        tone={state === "unavailable" ? "warn" : state === "pending" ? "info" : rows.length > 0 ? "ok" : "off"}
      />
      <div className="overflow-x-auto" role="region" aria-label="Registered MCP clients" tabIndex={0}>
        <table className="w-full min-w-[940px] border-collapse text-left">
          <caption className="sr-only">Registered MCP client credentials and actions</caption>
          <thead className="bg-[var(--om-surface-muted)] text-xs uppercase text-[var(--om-text-muted)]">
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
          <tbody className="divide-y divide-[var(--om-border)]">
            {state !== "ready" ? (
              <tr>
                <td className="px-4 py-4 text-sm text-[var(--om-text-muted)]" colSpan={7}>
                  {state === "unavailable"
                    ? "Client inventory is unavailable. Retry the client request."
                    : state === "pending"
                      ? "Loading registered clients…"
                      : "No registered clients"}
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
    <tr className="bg-[var(--om-surface)]">
      <td className="px-4 py-4 align-top">
        <p className="font-mono text-sm font-semibold text-[var(--om-text-bright)]">{client.client_id}</p>
        <p className="mt-1 truncate text-xs text-[var(--om-text-muted)]">{client.label}</p>
      </td>
      <td className="px-4 py-4 align-top">
        <Badge tone={clientCredentialStatusTone(client.status)}>{client.status}</Badge>
        <p className="mt-2 font-mono text-xs text-[var(--om-text-muted)]">gen {client.generation}</p>
      </td>
      <td className="px-4 py-4 align-top">
        <div className="flex flex-wrap gap-1">
          {client.scopes.map((scope) => (
            <Badge key={scope} tone="neutral">{scope}</Badge>
          ))}
        </div>
      </td>
      <td className="px-4 py-4 align-top font-mono text-xs text-[var(--om-text-muted)]">
        {shortHash(client.subject_id_hash)}
      </td>
      <td className="px-4 py-4 align-top font-mono text-xs text-[var(--om-text-muted)]">
        {client.last_used_at ?? "never"}
      </td>
      <td className="px-4 py-4 align-top font-mono text-xs text-[var(--om-text-muted)]">
        {client.last_source_addr ?? "unseen"}
      </td>
      <td className="px-4 py-4 align-top">
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            variant="secondary"
            disabled={disabled}
            aria-label={`${rotating ? "Rotating credential for" : "Rotate credential for"} ${client.client_id}`}
            onClick={() => onRotate(client)}
          >
            <RotateCcw className="size-4" aria-hidden="true" />
            {rotating ? "Rotating" : "Rotate"}
          </Button>
          <Button
            type="button"
            variant="secondary"
            disabled={disabled}
            aria-label={`${revoking ? "Revoking credential for" : "Revoke credential for"} ${client.client_id}`}
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
        label="Read connections"
        value={model.read.active}
        suffix={`/${formatNumber(model.read.effective)}`}
        tone={capacityUsageTone(model.read.active, model.read.effective)}
        pending={pending}
      />
      <MetricTile
        icon={Radio}
        label="Agent sessions"
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
        label="Capacity refusals"
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
        title="Read connections"
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
        title="Agent sessions"
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
          <CapacityFact label="Per-client configured" value={model.stateful.configuredPerSubject} />
          <CapacityFact label="Available" value={model.stateful.regularAvailable} />
          <CapacityFact label="Per-client cap" value={model.stateful.perSubjectCap} />
          <CapacityFact label="Per-client available" value={model.stateful.perSubjectAvailable} />
          <CapacityFact label="Dashboard reserve" value={model.stateful.operatorReserve} />
          <CapacityFact label="Diagnostics reserve" value={model.stateful.doctorReserve} />
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
      <div className="overflow-x-auto" role="region" aria-label="Resource limit sources" tabIndex={0}>
        <table className="w-full min-w-[760px] border-collapse text-left">
          <caption className="sr-only">Configured and effective database resource limits</caption>
          <thead className="bg-[var(--om-surface-muted)] text-xs uppercase text-[var(--om-text-muted)]">
            <tr>
              <th className="px-4 py-3 font-bold">Surface</th>
              <th className="px-4 py-3 font-bold">Limit</th>
              <th className="px-4 py-3 font-bold">Status</th>
              <th className="px-4 py-3 font-bold">Configured</th>
              <th className="px-4 py-3 font-bold">Effective</th>
              <th className="px-4 py-3 font-bold">Reason</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--om-border)]">
            {rows.length === 0 ? (
              <tr>
                <td className="px-4 py-8 text-center text-sm font-semibold text-[var(--om-text-muted)]" colSpan={6}>
                  No capacity sources
                </td>
              </tr>
            ) : (
              rows.map((row) => (
                <tr key={row.key} className="bg-[var(--om-surface)]">
                  <td className="px-4 py-4 align-top font-mono text-sm text-[var(--om-text)]">
                    {row.scope}
                  </td>
                  <td className="px-4 py-4 align-top font-mono text-sm font-semibold text-[var(--om-text-bright)]">
                    {row.source.name}
                  </td>
                  <td className="px-4 py-4 align-top">
                    <Badge tone={limitStatusTone(row.source.status)}>{row.source.status}</Badge>
                  </td>
                  <td className="px-4 py-4 align-top font-mono text-sm text-[var(--om-text)]">
                    {formatOptionalNumber(row.source.configured)}
                  </td>
                  <td className="px-4 py-4 align-top font-mono text-sm text-[var(--om-text)]">
                    {formatOptionalNumber(row.source.effective)}
                  </td>
                  <td className="px-4 py-4 align-top text-sm text-[var(--om-text-muted)]">
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
        <p className="text-sm font-bold text-[var(--om-text)]">{label}</p>
        <p className="font-mono text-sm font-semibold text-[var(--om-text-bright)]">
          {formatNumber(value)} / {formatNumber(max)}
        </p>
      </div>
      <div className="h-3 rounded-full bg-[var(--om-surface-elevated)]">
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
    <div className="rounded-md border border-[var(--om-border)] bg-[var(--om-surface-muted)] p-3">
      <p className="text-xs font-bold uppercase text-[var(--om-text-muted)]">{label}</p>
      <p
        className={cn(
          "mt-2 break-all text-sm font-semibold text-[var(--om-text-bright)]",
          mono ? "font-mono" : "font-sans"
        )}
      >
        {typeof value === "number" ? formatNumber(value) : value}
      </p>
    </div>
  );
}

function useOperatorEventLog(
  lane: OperatorLaneTarget | undefined,
  session?: DashboardSession
): {
  status: EventStreamStatus;
  events: OperatorEventEnvelope[];
} {
  const streamKey = JSON.stringify([
    lane?.laneId ?? "operator",
    lane?.generation ?? null,
    dashboardAuthorityIdentity(session)
  ]);
  const [streamStatus, setStreamStatus] = React.useState<{
    streamKey: string;
    status: EventStreamStatus;
  }>({ streamKey, status: "closed" });
  const [eventLog, setEventLog] = React.useState<{
    streamKey: string;
    events: OperatorEventEnvelope[];
  }>({ streamKey, events: [] });
  const status = streamStatus.streamKey === streamKey ? streamStatus.status : "closed";
  const events = eventLog.streamKey === streamKey ? eventLog.events : [];

  React.useEffect(() => {
    return startOperatorEventStream({
      lane,
      session,
      onStatus: (nextStatus) => setStreamStatus({ streamKey, status: nextStatus }),
      onEvent: (parsed) => {
        setEventLog((current) => ({
          streamKey,
          events: [
            parsed,
            ...(current.streamKey === streamKey ? current.events : [])
          ].slice(0, 24)
        }));
      },
      onInvalidate: () => {
        void queryClient.invalidateQueries({ queryKey: ["operator-metrics"] });
        void queryClient.invalidateQueries({ queryKey: ["active-lanes"] });
      }
    });
  }, [lane?.generation, lane?.laneId, session, streamKey]);

  return { status, events };
}

function OverviewMetricTiles({
  snapshot,
  lanes,
  lanesStatus,
  metricsStatus,
  stateful,
  pending
}: {
  snapshot: MetricsSnapshot | null;
  lanes: ActiveLane[];
  lanesStatus: "pending" | "error" | "success";
  metricsStatus: "pending" | "error" | "success";
  stateful: boolean;
  pending: boolean;
}): React.ReactElement {
  const summary = overviewSummary(snapshot, lanes);
  return (
    <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-6" aria-label="overview metrics">
      {stateful ? (
        <MetricTile
          icon={Users}
          label="Active agent sessions"
          value={authoritativeMetric(lanesStatus, summary.activeLanes)}
          suffix=""
          tone={lanesStatus === "success" && summary.activeLanes > 0 ? "ok" : "off"}
          pending={pending}
        />
      ) : null}
      <MetricTile
        icon={BarChart3}
        label="Tool calls since start"
        value={authoritativeMetric(metricsStatus, snapshot ? summary.totalRequests : null)}
        suffix=""
        tone={snapshot ? "info" : "off"}
        pending={pending}
      />
      <MetricTile
        icon={AlertTriangle}
        label="Policy refusals since start"
        value={snapshot ? summary.blocked : "unavailable"}
        suffix=""
        tone={snapshot ? (summary.blocked > 0 ? "warn" : "ok") : "off"}
        pending={pending}
      />
      <MetricTile
        icon={Timer}
        label="MCP latency"
        value={snapshot ? summary.meanLatencyMs : "unavailable"}
        suffix={snapshot ? "ms" : ""}
        tone={snapshot ? (summary.meanLatencyMs > 500 ? "warn" : "neutral") : "off"}
        pending={pending}
      />
      <MetricTile
        icon={Gauge}
        label="DB errors since start"
        value={snapshot ? summary.errors : "unavailable"}
        suffix=""
        tone={snapshot ? (summary.errors > 0 ? "warn" : "ok") : "off"}
        pending={pending}
      />
      <MetricTile
        icon={Database}
        label="Pool active"
        value={snapshot ? summary.poolActive : "unavailable"}
        suffix=""
        tone={snapshot ? "neutral" : "off"}
        pending={pending}
      />
    </section>
  );
}

function OverviewReviewsPanel({
  proposals,
  pending,
  error
}: {
  proposals: ChangeProposalListView[];
  pending: boolean;
  error: unknown;
}): React.ReactElement {
  const visible = proposals.slice(0, 3);
  return (
    <Surface className="overflow-hidden">
      <div className="flex items-center justify-between gap-3 border-b border-[var(--om-border)] px-4 py-3">
        <div className="min-w-0">
          <h3 className="flex items-center gap-2 text-base font-bold text-[var(--om-text-bright)]">
            <GitPullRequest className="size-4" aria-hidden="true" />
            Saved change plans
          </h3>
          <p className="mt-1 truncate text-sm text-[var(--om-text-muted)]">
            {pending ? "checking" : error ? "unavailable" : `${formatNumber(proposals.length)} saved`}
          </p>
        </div>
        <Link
          to="/reviews"
          className="inline-flex h-9 items-center justify-center gap-2 whitespace-nowrap rounded-md border border-[var(--om-border)] bg-[var(--om-surface)] px-3 text-sm font-semibold text-[var(--om-text-bright)] transition-colors hover:bg-[var(--om-surface-elevated)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--om-focus)]"
        >
          <Search className="size-4" aria-hidden="true" />
          Open
        </Link>
      </div>
      <div className="divide-y divide-[var(--om-border)]">
        {error ? (
          <div className="px-4 py-6 text-sm font-semibold text-[var(--om-rust)]" role="alert">
            Could not load saved change plans.
          </div>
        ) : visible.length === 0 ? (
          <div className="px-4 py-6 text-sm font-semibold text-[var(--om-text-muted)]">
            {pending ? "Loading saved change plans…" : "No saved change plans"}
          </div>
        ) : (
          visible.map((proposal) => (
            <div key={proposal.id} className="grid gap-2 px-4 py-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="min-w-0 truncate text-sm font-bold text-[var(--om-text-bright)]">{proposal.title}</p>
                <Badge tone={proposal.stored_verdict_present ? "warn" : "neutral"}>
                  {proposal.stored_verdict_present ? "preview must be refreshed" : "not yet previewed"}
                </Badge>
              </div>
              <div className="flex flex-wrap gap-2 text-xs font-semibold text-[var(--om-text-muted)]">
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
  value: number | string;
  suffix: string;
  tone: "neutral" | "ok" | "warn" | "off" | "info";
  pending: boolean;
}): React.ReactElement {
  return (
    <Surface className="min-h-32 p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="flex size-9 items-center justify-center rounded-md border border-[var(--om-border)] bg-[var(--om-surface-muted)] text-[var(--om-text)]">
          <Icon className="size-4" aria-hidden="true" />
        </div>
        <Badge tone={pending ? "info" : tone}>{pending ? "sync" : tone}</Badge>
      </div>
      <p className="mt-4 text-sm font-semibold text-[var(--om-text-muted)]">{label}</p>
      <strong
        className={cn(
          "mt-2 block leading-none text-[var(--om-text-bright)]",
          typeof value === "number" ? "text-3xl" : "text-lg"
        )}
      >
        {typeof value === "number" ? formatNumber(value) : value}
        {suffix ? <span className="ml-1 text-base text-[var(--om-text-muted)]">{suffix}</span> : null}
      </strong>
    </Surface>
  );
}

function LaneMetricsPanel({
  snapshot,
  lanes,
  stateful,
  available
}: {
  snapshot: MetricsSnapshot | null;
  lanes: ActiveLane[];
  stateful: boolean;
  available: boolean;
}): React.ReactElement {
  const rows = laneMetricRows(snapshot, lanes);
  return (
    <Surface className="overflow-hidden">
      <PanelHeader
        icon={Radio}
        title="Agent session activity"
        meta={snapshot ? `${rows.length} sessions` : "activity unavailable"}
        tone={snapshot && rows.length > 0 ? "ok" : "off"}
      />
      <div className="overflow-x-auto" role="region" aria-label="Agent session activity" tabIndex={0}>
        <table className="w-full min-w-[780px] border-collapse text-left">
          <caption className="sr-only">Activity and policy refusals for active MCP sessions</caption>
          <thead className="bg-[var(--om-surface-muted)] text-xs uppercase text-[var(--om-text-muted)]">
            <tr>
              <th className="px-4 py-3 font-bold">Session</th>
              <th className="px-4 py-3 font-bold">Requests</th>
              <th className="px-4 py-3 font-bold">Policy refusals</th>
              <th className="px-4 py-3 font-bold">Latency</th>
              <th className="px-4 py-3 font-bold">State</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--om-border)]">
            {rows.length === 0 ? (
              <tr>
                <td className="px-4 py-8 text-center text-sm font-semibold text-[var(--om-text-muted)]" colSpan={5}>
                  {!available
                    ? "Agent session activity is unavailable."
                    : stateful
                    ? "No active agent sessions. Connect an MCP client to begin."
                    : "Per-session activity is available only when stateful HTTP is enabled."}
                </td>
              </tr>
            ) : (
              rows.map((row) => (
                <tr key={`${row.laneId}:${row.subjectIdHash}`} className="bg-[var(--om-surface)]">
                  <td className="px-4 py-4 align-top">
                    <p className="font-mono text-sm font-semibold text-[var(--om-text-bright)]">{row.laneId}</p>
                    <p className="mt-1 break-all font-mono text-xs text-[var(--om-text-muted)]">
                      {row.subjectIdHash}
                    </p>
                  </td>
                  <td className="px-4 py-4 align-top font-mono text-sm text-[var(--om-text)]">
                    {snapshot ? formatNumber(row.requests) : "unavailable"}
                  </td>
                  <td className="px-4 py-4 align-top">
                    <Badge tone={snapshot ? (row.blocked > 0 ? "warn" : "ok") : "off"}>
                      {snapshot ? formatNumber(row.blocked) : "unavailable"}
                    </Badge>
                  </td>
                  <td className="px-4 py-4 align-top">
                    {snapshot ? (
                      <div className="w-full max-w-[180px]">
                        <div className="h-2 rounded-full bg-[var(--om-surface-elevated)]">
                          <div
                            className="h-2 rounded-full bg-sky-600"
                            style={{ width: `${latencyBarWidth(row.meanLatencyMs)}%` }}
                          />
                        </div>
                        <p className="mt-2 font-mono text-xs text-[var(--om-text)]">
                          {formatMs(row.meanLatencyMs)} avg · {formatMs(row.maxLatencyMs)} max
                        </p>
                      </div>
                    ) : (
                      <span className="text-sm text-[var(--om-text-muted)]">unavailable</span>
                    )}
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
        meta={snapshot ? `${rows.length} series` : "unavailable"}
        tone={snapshot && rows.length > 0 ? "info" : "off"}
      />
      <div className="divide-y divide-[var(--om-border)]">
        {rows.length === 0 ? (
          <p className="px-4 py-8 text-center text-sm font-semibold text-[var(--om-text-muted)]">
            {snapshot ? "No tool calls recorded." : "Tool metrics are unavailable."}
          </p>
        ) : (
          rows.map((row) => (
            <div key={`${row.tool}:${row.status}`} className="grid gap-3 px-4 py-3 sm:grid-cols-[minmax(0,1fr)_92px_72px] sm:items-center">
              <div className="min-w-0">
                <p className="truncate font-mono text-sm font-semibold text-[var(--om-text-bright)]">{row.tool}</p>
                <p className="mt-1 text-xs text-[var(--om-text-muted)]">{row.status}</p>
              </div>
              <div className="h-2 rounded-full bg-[var(--om-surface-elevated)]">
                <div
                  className={cn("h-2 rounded-full", row.status === "ok" ? "bg-[var(--om-gold)]" : "bg-[var(--om-copper)]")}
                  style={{ width: `${requestBarWidth(row.count, rows[0]?.count ?? 1)}%` }}
                />
              </div>
              <p className="font-mono text-sm font-semibold text-[var(--om-text)]">{formatNumber(row.count)}</p>
            </div>
          ))
        )}
      </div>
    </Surface>
  );
}

// The most recent classifier ladder snapshot carried on the events stream
// (server-derived from the redacted audit tail; no SQL text or bind values).
function latestClassifierLadder(events: OperatorEventEnvelope[]): ClassifierLadderData | null {
  for (const event of events) {
    const ladder = parseClassifierLadder(event);
    if (ladder) {
      return ladder;
    }
  }
  return null;
}

function classifierVerdictTone(verdict: ClassifierLadderVerdictKind): DashboardTone {
  switch (verdict) {
    case "PASS":
      return "ok";
    case "HOLD":
      return "info";
    case "REFUSED":
      return "warn";
  }
}

function OperatorEventLogPanel({
  status,
  events
}: {
  status: EventStreamStatus;
  events: OperatorEventEnvelope[];
}): React.ReactElement {
  const ladder = latestClassifierLadder(events);
  const verdicts = [...(ladder?.verdicts ?? [])].sort((a, b) => b.seq - a.seq);
  return (
    <ConsolePanel>
      <ConsolePanelHeader
        icon={Wifi}
        title="Recent governed activity"
        meta={verdicts.length > 0 ? `${verdicts.length} recent decisions · ${status}` : status}
        tone={eventStatusTone(status)}
      />
      <div className="border-b border-[var(--om-border)] px-4 py-3">
        <div className="flex items-center justify-between gap-3">
          <p className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
            Permission levels
          </p>
          <span className="text-2xs font-semibold text-[var(--om-text-muted)]">
            Every statement is checked by the server
          </span>
        </div>
        <div className="mt-2 flex items-stretch gap-1" aria-label="Permission levels">
          {CLEARANCE_LADDER.map((step) => (
            <div
              key={step.level}
              className={cn(
                "flex flex-1 items-center justify-center gap-2 rounded-md border px-2 py-1.5",
                sessionClearanceClass(step.level)
              )}
              data-clearance-level={step.level}
              data-clearance-ordinal={step.ordinal}
            >
              <span className="font-mono text-xs font-bold">{step.label}</span>
            </div>
          ))}
        </div>
      </div>
      <div
        className="max-h-[460px] divide-y divide-[var(--om-border)] overflow-auto"
        role="log"
        aria-live="polite"
        aria-label="recent governed activity"
      >
        {verdicts.length > 0 ? (
          verdicts.map((verdict) => (
            <div
              key={`${verdict.seq}:${verdict.timestamp}`}
              className="px-4 py-3"
              data-verdict={verdict.verdict}
              data-ladder={verdict.ladder}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge tone={classifierVerdictTone(verdict.verdict)}>{verdict.ladder}</Badge>
                    <span className="truncate font-mono text-sm font-semibold text-[var(--om-text-bright)]">
                      {verdict.tool}
                    </span>
                  </div>
                  <p className="mt-1 text-sm text-[var(--om-text-muted)]">
                    {verdict.decision} · {verdict.outcome} · {verdict.danger_level}
                  </p>
                </div>
              </div>
              <details className="mt-2 text-xs text-[var(--om-text-muted)]">
                <summary className="cursor-pointer font-semibold">Technical details</summary>
                <p className="mt-2 break-all font-mono">Client {verdict.subject_id_hash} · audit sequence {verdict.seq}</p>
              </details>
            </div>
          ))
        ) : events.length === 0 ? (
          <p className="px-4 py-8 text-center text-sm font-semibold text-[var(--om-text-muted)]">
            No governed activity has arrived yet.
          </p>
        ) : (
          events.map((event) => (
            <div key={event.event_id} className="px-4 py-3">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-[var(--om-text-bright)]">
                    Service status update
                  </p>
                </div>
                <Badge tone={event.event_type === "operator.stream_gap" ? "warn" : "info"}>
                  {event.event_type}
                </Badge>
              </div>
              <div className="mt-3 grid gap-2 sm:grid-cols-3">
                <EventFact label="Session" value={event.lane_id} />
                <EventFact label="Active sessions" value={eventMetric(event, "active_lanes")} />
                <EventFact label="Update" value={event.event_seq} />
              </div>
            </div>
          ))
        )}
      </div>
    </ConsolePanel>
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
    <div className="flex items-center justify-between gap-3 border-b border-[var(--om-border)] px-4 py-3">
      <div className="flex min-w-0 items-center gap-3">
        <div className="flex size-9 items-center justify-center rounded-md border border-[var(--om-border)] bg-[var(--om-surface-muted)] text-[var(--om-text)]">
          <Icon className="size-4" aria-hidden="true" />
        </div>
        <div className="min-w-0">
          <h3 className="truncate text-base font-bold text-[var(--om-text-bright)]">{title}</h3>
          <p className="mt-1 truncate text-sm text-[var(--om-text-muted)]">{meta}</p>
        </div>
      </div>
      <Badge tone={tone}>{tone}</Badge>
    </div>
  );
}

// Carved Light building blocks for the b4 operator surfaces. These mirror the
// shared light Surface/PanelHeader/CapacityFact but read the --om tokens, so a
// b4 surface renders as a self-contained near-black island without flipping the
// still-light primitives the rest of the console uses.
function ConsolePanel({
  className,
  children,
  ...rest
}: React.HTMLAttributes<HTMLElement>): React.ReactElement {
  return (
    <section
      className={cn(
        "overflow-hidden rounded-lg border border-[var(--om-border)] bg-[var(--om-surface)] shadow-sm",
        className
      )}
      {...rest}
    >
      {children}
    </section>
  );
}

function ConsolePanelHeader({
  icon: Icon,
  title,
  meta,
  tone,
  action
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  meta: string;
  tone: DashboardTone;
  action?: React.ReactNode;
}): React.ReactElement {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-[var(--om-border)] px-4 py-3">
      <div className="flex min-w-0 items-center gap-3">
        <div className="flex size-9 items-center justify-center rounded-md border border-[var(--om-border)] bg-[var(--om-surface-muted)] text-[var(--om-text-muted)]">
          <Icon className="size-4" aria-hidden="true" />
        </div>
        <div className="min-w-0">
          <h3 className="truncate text-base font-semibold text-[var(--om-text-bright)]">{title}</h3>
          <p className="mt-1 truncate text-sm text-[var(--om-text-muted)]">{meta}</p>
        </div>
      </div>
      {action ?? <Badge tone={tone}>{tone}</Badge>}
    </div>
  );
}

function ConsoleFact({
  label,
  value,
  mono = false
}: {
  label: string;
  value: string | number;
  mono?: boolean;
}): React.ReactElement {
  return (
    <div className="rounded-md border border-[var(--om-border)] bg-[var(--om-surface-muted)] p-3">
      <p className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
        {label}
      </p>
      <p
        className={cn(
          "mt-2 break-all text-sm font-semibold text-[var(--om-text-bright)]",
          mono ? "font-mono" : "font-sans"
        )}
      >
        {typeof value === "number" ? formatNumber(value) : value}
      </p>
    </div>
  );
}

// Shared Carved Light form/label classes for the b4 operator surfaces, so the
// inputs, textareas, and checkboxes read the --om tokens instead of the light
// zinc/emerald defaults the rest of the console still uses.
const OM_LABEL = "mb-2 block text-sm font-semibold text-[var(--om-text)]";
const OM_INPUT =
  "min-h-11 w-full rounded-md border border-[var(--om-control-border)] bg-[var(--om-surface-muted)] px-3 text-sm text-[var(--om-text)] outline-none focus-visible:border-[var(--om-gold)] focus-visible:ring-2 focus-visible:ring-[color-mix(in_srgb,var(--om-gold)_35%,transparent)]";
const OM_TEXTAREA =
  "w-full resize-y rounded-md border border-[var(--om-control-border)] bg-[var(--om-bg)] p-3 font-mono text-sm leading-6 text-[var(--om-text)] outline-none focus-visible:border-[var(--om-gold)] focus-visible:ring-2 focus-visible:ring-[color-mix(in_srgb,var(--om-gold)_35%,transparent)]";
const OM_CHECKBOX = "size-5 rounded border-[var(--om-control-border)] accent-[var(--om-gold)]";
const OM_CHECK_LABEL = "flex min-h-11 items-center gap-2 text-sm font-semibold text-[var(--om-text)]";
const OM_CODE = "overflow-auto rounded-md bg-[var(--om-bg)] p-3 text-xs leading-5 text-[var(--om-text)]";

function EventFact({ label, value }: { label: string; value: unknown }): React.ReactElement {
  return (
    <div className="rounded-md border border-[var(--om-border)] bg-[var(--om-surface-muted)] p-2">
      <p className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
        {label}
      </p>
      <p className="mt-1 break-all font-mono text-xs text-[var(--om-text)]">
        {String(value ?? "…")}
      </p>
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
  metricsError: string | null,
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
    requests: row?.requests ?? null,
    blocked: row?.blocked ?? null,
    meanLatencyMs: row?.meanLatencyMs ?? null,
    maxLatencyMs: row?.maxLatencyMs ?? null,
    lastEvent: events[0]?.event_type ?? "none",
    detailState: metricsError ?? capabilitiesError ?? connectionError ?? db.error
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

function clearanceLevel(value: string): OperatingLevel {
  return value === "READ_WRITE" || value === "DDL" || value === "ADMIN" ? value : "READ_ONLY";
}

// Color IS clearance (Appendix G): every level reads its own --om clearance
// token via color-mix, so the ramp holds on the near-black console and on any
// lighter fallback surface alike.
const SESSION_CLEARANCE_VAR: Record<OperatingLevel, string> = {
  READ_ONLY: "--om-clearance-read-only",
  READ_WRITE: "--om-clearance-read-write",
  DDL: "--om-clearance-ddl",
  ADMIN: "--om-clearance-admin"
};

function sessionClearanceClass(level: OperatingLevel): string {
  const token = SESSION_CLEARANCE_VAR[level];
  return `border-[color-mix(in_srgb,var(${token})_50%,transparent)] bg-[color-mix(in_srgb,var(${token})_14%,transparent)] text-[var(${token})]`;
}

function sessionLevelBadgeClass(value: string): string {
  if (value === "READ_ONLY" || value === "READ_WRITE" || value === "DDL" || value === "ADMIN") {
    return sessionClearanceClass(clearanceLevel(value));
  }
  return "border-[var(--om-border)] bg-[var(--om-surface-muted)] text-[var(--om-text-muted)]";
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
      return "bg-[var(--om-copper)]";
    case "info":
      return "bg-sky-600";
    case "ok":
      return "bg-[var(--om-gold)]";
    case "off":
      return "bg-[var(--om-border)]";
    case "neutral":
      return "bg-[var(--om-text-muted)]";
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
    case "stale":
      return "warn";
    default:
      return "neutral";
  }
}

function formatOptionalNumber(value: number | undefined): string {
  return typeof value === "number" && Number.isFinite(value) ? formatNumber(value) : "";
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
  return WHOLE_NUMBER_FORMATTER.format(value);
}

function firstQueryError(...errors: unknown[]): Error | null {
  const error = errors.find((value): value is Error => value instanceof Error);
  return error ?? null;
}

function formatRelativeAge(timestampMs: number): string {
  const seconds = Math.max(0, Math.floor((Date.now() - timestampMs) / 1_000));
  if (seconds < 5) {
    return "just now";
  }
  if (seconds < 60) {
    return `${seconds}s ago`;
  }
  return `${Math.floor(seconds / 60)}m ago`;
}

const explorerDetailLevels: ExplorerDetailLevel[] = ["names", "summary", "standard", "full"];

function explorerDetailLevelLabel(level: ExplorerDetailLevel): string {
  switch (level) {
    case "names":
      return "Names only";
    case "summary":
      return "Overview";
    case "standard":
      return "Columns";
    case "full":
      return "Columns + indexes";
  }
}

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

export type ExplorerObjectRow = {
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

export type ExplorerSourceHitRow = {
  owner: string;
  name: string;
  objectType: string;
  line: string;
  text: string;
  raw: Record<string, unknown>;
};

export type ExplorerGlobalSearchRequest = {
  readonly needle: string;
  readonly includeObjects: boolean;
  readonly includeSource: boolean;
  readonly allSchemas: boolean;
  readonly sourceType: string;
  readonly owner: string;
  readonly maxRows: number;
};

export type ExplorerRowsDecode<T> = {
  rows: T[];
  invalidCount: number;
};

type ExplorerDetailRequest = {
  kind: "ddl" | "source";
  ref: ExplorerObjectRef;
  lane?: OperatorLaneTarget;
  cacheKey: ExplorerMetadataCacheKey;
  maxChars: number;
  requestGeneration: number;
  identity: string;
};

type ExplorerDetailResult =
  | {
      state: "ok";
      kind: "ddl" | "source";
      ref: ExplorerObjectRef;
      response: OperatorResponse<WorkbenchActionData>;
      cacheStatus: ExplorerCacheStatus;
      bytes: number;
      requestGeneration: number;
      identity: string;
    }
  | {
      state: "error";
      kind: "ddl" | "source";
      ref: ExplorerObjectRef | null;
      message: string;
      requestGeneration: number;
      identity: string;
    };

export function createExplorerGlobalSearchRequest(
  input: ExplorerGlobalSearchRequest
): ExplorerGlobalSearchRequest {
  return Object.freeze({ ...input });
}

export function authoritativeExplorerValue<T>(
  status: DashboardQueryStatus,
  result: { value: T } | undefined
): T | undefined {
  return authoritativeQueryData(status, result)?.value;
}

export function authoritativeExplorerConnection(
  status: DashboardQueryStatus,
  response: OperatorResponse<WorkbenchActionData> | undefined
): OperatorResponse<WorkbenchActionData> | undefined {
  return authoritativeQueryData(status, response);
}

export function explorerSearchAuthorityReady(input: {
  includeObjects: boolean;
  includeSource: boolean;
}): boolean {
  return input.includeObjects || input.includeSource;
}

function ExplorerPage(): React.ReactElement {
  // The lane is the Explorer's identity — which database you are reading — so
  // it belongs in the URL. Text filters stay local and publish after a short
  // quiet period, while React Query aborts any superseded in-flight request.
  const { lane: requestedLaneId = "", generation: requestedLaneGeneration } = useSearch({
    from: explorerRoute.id
  });
  const explorerNavigate = useNavigate({ from: explorerRoute.id });
  const setExplorerLane = React.useCallback(
    (identity: LaneIdentity | null) => {
      void explorerNavigate({
        search: {
          lane: identity?.laneId,
          generation: identity?.generation
        },
        replace: true
      });
    },
    [explorerNavigate]
  );
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
  const detailRequestGeneration = React.useRef(0);
  const currentDetailIdentity = React.useRef<string | null>(null);
  const debouncedSchemaFilter = useDebouncedValue(schemaFilter);
  const debouncedNameLike = useDebouncedValue(nameLike);
  const clearExplorerDetailResult = React.useCallback(() => {
    detailRequestGeneration.current += 1;
    currentDetailIdentity.current = null;
    setDetailResult(null);
  }, []);
  const invalidateExplorerDetail = React.useCallback(() => {
    clearExplorerDetailResult();
    setSelectedRef(null);
  }, [clearExplorerDetailResult]);

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
  const lanes = activeLanes.status === "success" ? activeLanes.data.data.lanes : EMPTY_ACTIVE_LANES;
  const stateful = authoritativeServerMode(activeLanes.status, activeLanes.data) !== false;
  const requestedLane =
    requestedLaneId && requestedLaneGeneration !== undefined
      ? { laneId: requestedLaneId, generation: requestedLaneGeneration }
      : null;
  const laneSelection =
    stateful && activeLanes.status === "success"
      ? resolveExactLane(requestedLane, lanes)
      : { lane: null, invalidated: false };
  const selectedLane = laneSelection.lane ?? undefined;
  const explorerLane = selectedLane ? laneIdentity(selectedLane) : undefined;
  const connectionReady =
    activeLanes.status === "success" && (!stateful || Boolean(explorerLane));

  React.useEffect(() => {
    if (!stateful || activeLanes.status !== "success") {
      return;
    }
    if (laneSelection.invalidated) {
      setExplorerLane(null);
      return;
    }
    if (!requestedLaneId && requestedLaneGeneration === undefined && lanes.length === 1) {
      setExplorerLane(laneIdentity(lanes[0]));
    }
  }, [
    activeLanes.status,
    laneSelection.invalidated,
    lanes,
    requestedLaneGeneration,
    requestedLaneId,
    setExplorerLane,
    stateful
  ]);

  React.useEffect(() => {
    clearExplorerMetadataCache();
    setCacheVersion((version) => version + 1);
    invalidateExplorerDetail();
    setGlobalSearchRequest(null);
  }, [explorerLane?.generation, explorerLane?.laneId, invalidateExplorerDetail]);

  React.useEffect(() => {
    invalidateExplorerDetail();
  }, [debouncedNameLike, detailLevel, invalidateExplorerDetail, objectType, owner]);

  const connection = useQuery({
    queryKey: [
      "explorer",
      "connection",
      explorerLane?.laneId ?? "stateless",
      explorerLane?.generation ?? 0
    ],
    queryFn: async ({ signal }) => {
      if (!session.data) {
        throw new Error("dashboard session is not ready");
      }
      return fetchExplorerConnection(session.data, explorerLane, { signal });
    },
    enabled: session.status === "success" && connectionReady,
    retry: 1
  });

  const authoritativeConnection = authoritativeExplorerConnection(
    connection.status,
    connection.data
  );
  const baseCacheKey = metadataCacheKeyFromResponse(authoritativeConnection);
  const schemasScope = baseCacheKey ? explorerScopeForVisibleSchema(baseCacheKey, "*") : null;
  const objectScope = baseCacheKey
    ? explorerScopeForVisibleSchema(baseCacheKey, owner.trim() || baseCacheKey.visible_schema)
    : null;
  const globalScope =
    baseCacheKey && globalSearchRequest
      ? explorerScopeForVisibleSchema(
          baseCacheKey,
          globalSearchRequest.allSchemas
            ? "*"
            : globalSearchRequest.owner || baseCacheKey.visible_schema
        )
      : null;

  const schemasQuery = useQuery({
    queryKey: [
      "explorer",
      "schemas",
      explorerLane?.laneId ?? "stateless",
      explorerLane?.generation ?? 0,
      debouncedSchemaFilter,
      maxRows,
      cacheScopeToken(schemasScope),
      cacheVersion
    ],
    queryFn: async ({ signal }) => {
      if (!session.data || !schemasScope) {
        throw new Error("explorer schema cache is not ready");
      }
      return cachedExplorerMetadata(
        schemasScope,
        JSON.stringify({
          tool: "oracle_list_schemas",
          name_like: debouncedSchemaFilter.trim(),
          max_rows: maxRows
        }),
        () =>
          fetchExplorerSchemas(
            session.data,
            {
              lane: explorerLane,
              nameLike: debouncedSchemaFilter,
              maxRows
            },
            { signal }
          )
      );
    },
    enabled: session.status === "success" && Boolean(schemasScope),
    retry: 1
  });

  const objectsQuery = useQuery({
    queryKey: [
      "explorer",
      "objects",
      explorerLane?.laneId ?? "stateless",
      explorerLane?.generation ?? 0,
      owner,
      objectType,
      debouncedNameLike,
      detailLevel,
      maxRows,
      cacheScopeToken(objectScope),
      cacheVersion
    ],
    queryFn: async ({ signal }) => {
      if (!session.data || !objectScope) {
        throw new Error("explorer object cache is not ready");
      }
      return cachedExplorerMetadata(
        objectScope,
        JSON.stringify({
          tool: "oracle_search_objects",
          owner: owner.trim(),
          object_type: objectType,
          name_like: debouncedNameLike.trim(),
          detail_level: detailLevel,
          max_rows: maxRows
        }),
        () =>
          fetchExplorerObjects(
            session.data,
            {
              lane: explorerLane,
              owner,
              objectType,
              nameLike: debouncedNameLike,
              detailLevel,
              maxRows
            },
            { signal }
          )
      );
    },
    enabled: session.status === "success" && Boolean(objectScope),
    retry: 1
  });

  const globalObjectsQuery = useQuery({
    queryKey: [
      "explorer",
      "global-objects",
      explorerLane?.laneId ?? "stateless",
      explorerLane?.generation ?? 0,
      globalSearchRequest,
      cacheScopeToken(globalScope),
      cacheVersion
    ],
    queryFn: async ({ signal }) => {
      if (!session.data || !globalScope || !globalSearchRequest) {
        throw new Error("global object search is not ready");
      }
      const ownerFilter = globalSearchRequest.allSchemas ? "*" : globalSearchRequest.owner;
      const nameLike = `%${globalSearchRequest.needle}%`;
      return cachedExplorerMetadata(
        globalScope,
        JSON.stringify({
          tool: "oracle_search_objects",
          owner: ownerFilter,
          object_type: "",
          name_like: nameLike,
          detail_level: "summary",
          max_rows: globalSearchRequest.maxRows
        }),
        () =>
          fetchExplorerObjects(
            session.data,
            {
              lane: explorerLane,
              owner: ownerFilter,
              objectType: "",
              nameLike,
              detailLevel: "summary",
              maxRows: globalSearchRequest.maxRows
            },
            { signal }
          )
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
      explorerLane?.laneId ?? "stateless",
      explorerLane?.generation ?? 0,
      globalSearchRequest,
      cacheScopeToken(globalScope),
      cacheVersion
    ],
    queryFn: async ({ signal }) => {
      if (!session.data || !globalScope || !globalSearchRequest) {
        throw new Error("global source search is not ready");
      }
      const ownerFilter = globalSearchRequest.allSchemas ? "*" : globalSearchRequest.owner;
      return cachedExplorerMetadata(
        globalScope,
        JSON.stringify({
          tool: "oracle_search_source",
          owner: ownerFilter,
          object_type: globalSearchRequest.sourceType,
          needle: globalSearchRequest.needle,
          max_rows: globalSearchRequest.maxRows
        }),
        () =>
          fetchExplorerSourceSearch(
            session.data,
            {
              lane: explorerLane,
              owner: ownerFilter,
              objectType: globalSearchRequest.sourceType,
              needle: globalSearchRequest.needle,
              maxRows: globalSearchRequest.maxRows
            },
            { signal }
          )
      );
    },
    enabled:
      session.status === "success" && Boolean(globalScope && globalSearchRequest?.includeSource),
    retry: 1
  });

  React.useEffect(() => {
    if (
      connection.status === "error" ||
      objectsQuery.status === "error" ||
      globalObjectsQuery.status === "error" ||
      globalSourceQuery.status === "error"
    ) {
      invalidateExplorerDetail();
    }
  }, [
    connection.status,
    globalObjectsQuery.status,
    globalSourceQuery.status,
    invalidateExplorerDetail,
    objectsQuery.status
  ]);

  const detailMutation = useMutation({
    mutationFn: async (request: ExplorerDetailRequest) => {
      if (!session.data) {
        throw new Error("explorer cache key is not ready");
      }
      const scope = explorerScopeForVisibleSchema(request.cacheKey, request.ref.owner);
      const slot = JSON.stringify({
        tool: request.kind === "ddl" ? "oracle_get_ddl" : "oracle_get_source",
        owner: request.ref.owner,
        name: request.ref.name,
        object_type: request.ref.objectType,
        max_chars: request.kind === "source" ? request.maxChars : undefined
      });
      const cached = await cachedExplorerMetadata(scope, slot, () =>
        request.kind === "ddl"
          ? fetchExplorerDdl(session.data, { ...request.ref, lane: request.lane })
          : fetchExplorerSource(session.data, {
              ...request.ref,
              lane: request.lane,
              maxChars: request.maxChars
            })
      );
      return {
        state: "ok" as const,
        kind: request.kind,
        ref: request.ref,
        response: cached.value,
        cacheStatus: cached.status,
        bytes: cached.bytes,
        requestGeneration: request.requestGeneration,
        identity: request.identity
      };
    },
    onSuccess: (result) => {
      if (!explorerDetailCompletionIsCurrent(
        result,
        currentDetailIdentity.current,
        detailRequestGeneration.current
      )) {
        return;
      }
      setDetailResult(result);
    },
    onError: (error, request) => {
      if (!explorerDetailCompletionIsCurrent(
        request,
        currentDetailIdentity.current,
        detailRequestGeneration.current
      )) {
        return;
      }
      setDetailResult({
        state: "error",
        kind: request.kind,
        ref: request.ref,
        message: error instanceof Error ? error.message : "metadata request failed",
        requestGeneration: request.requestGeneration,
        identity: request.identity
      });
    }
  });

  const schemaValue = authoritativeExplorerValue(schemasQuery.status, schemasQuery.data);
  const objectValue = authoritativeExplorerValue(objectsQuery.status, objectsQuery.data);
  const globalObjectValue = authoritativeExplorerValue(
    globalObjectsQuery.status,
    globalObjectsQuery.data
  );
  const globalSourceValue = authoritativeExplorerValue(
    globalSourceQuery.status,
    globalSourceQuery.data
  );
  const schemaRows = schemaRowsFromResponse(schemaValue);
  const objectDecode = objectRowsFromResponse(objectValue);
  const objectRows = objectDecode.rows;
  const globalObjectDecode = globalSearchRequest?.includeObjects
    ? objectRowsFromResponse(globalObjectValue)
    : { rows: [], invalidCount: 0 };
  const globalObjectRows = globalObjectDecode.rows;
  const globalSourceDecode = globalSearchRequest?.includeSource
    ? sourceRowsFromResponse(globalSourceValue)
    : { rows: [], invalidCount: 0 };
  const globalSourceRows = globalSourceDecode.rows;
  const schemaLimit = explorerLimitFromResponse(schemaValue);
  const objectLimit = explorerLimitFromResponse(objectValue);
  const globalObjectLimit = explorerLimitFromResponse(globalObjectValue);
  const globalSourceLimit = explorerLimitFromResponse(globalSourceValue);
  const selectedRow = selectedRef
    ? objectRows.find((row) => objectRefKey(rowRef(row)) === objectRefKey(selectedRef)) ?? null
    : null;
  const selectedRefKey = selectedRef ? objectRefKey(selectedRef) : null;
  const selectedReferenceIsAuthoritative = Boolean(
    selectedRefKey &&
      (objectRows.some((row) => objectRefKey(rowRef(row)) === selectedRefKey) ||
        globalObjectRows.some((row) => objectRefKey(rowRef(row)) === selectedRefKey) ||
        globalSourceRows.some(
          (row) =>
            objectRefKey({ owner: row.owner, name: row.name, objectType: row.objectType }) ===
            selectedRefKey
        ))
  );
  const connected = connectedFromResponse(authoritativeConnection);
  const sessionTone =
    session.status === "success" ? "ok" : session.status === "error" ? "warn" : "info";

  const refreshExplorer = (): void => {
    clearExplorerMetadataCache();
    setCacheVersion((version) => version + 1);
    queryClient.invalidateQueries({ queryKey: ["explorer"] });
  };

  const selectRow = (row: ExplorerObjectRow): void => {
    const ref = rowRef(row);
    clearExplorerDetailResult();
    setSelectedRef(ref);
  };
  const selectSourceHit = (row: ExplorerSourceHitRow): void => {
    clearExplorerDetailResult();
    setSelectedRef({
      owner: row.owner,
      name: row.name,
      objectType: row.objectType
    });
  };
  const runGlobalSearch = (): void => {
    const needle = globalSearchText.trim();
    if (!needle || (!globalIncludeObjects && !globalIncludeSource)) {
      return;
    }
    setGlobalSearchRequest(createExplorerGlobalSearchRequest({
      needle,
      includeObjects: globalIncludeObjects,
      includeSource: globalIncludeSource,
      allSchemas: globalAllSchemas,
      sourceType: globalSourceType,
      owner: owner.trim(),
      maxRows
    }));
    if (globalIncludeObjects && globalObjectsQuery.isError) {
      void globalObjectsQuery.refetch();
    }
    if (globalIncludeSource && globalSourceQuery.isError) {
      void globalSourceQuery.refetch();
    }
  };
  const requestObjectDetail = (kind: "ddl" | "source", ref: ExplorerObjectRef): void => {
    if (!baseCacheKey || !selectedReferenceIsAuthoritative) {
      return;
    }
    const requestGeneration = detailRequestGeneration.current + 1;
    detailRequestGeneration.current = requestGeneration;
    const identity = explorerDetailRequestIdentity({
      kind,
      ref,
      lane: explorerLane,
      maxChars,
      requestGeneration
    });
    currentDetailIdentity.current = identity;
    setDetailResult(null);
    detailMutation.mutate({
      kind,
      ref,
      lane: explorerLane,
      cacheKey: baseCacheKey,
      maxChars,
      requestGeneration,
      identity
    });
  };

  return (
    <PageFrame
      title="Database Explorer"
      eyebrow="Your Oracle database"
      description="Browse visible schemas, find objects and source, and inspect definitions through the governed server connection."
    >
      <div className="space-y-4">
        <ConsolePanel className="p-4">
          <div className="grid gap-3 xl:grid-cols-[minmax(180px,0.9fr)_minmax(140px,0.7fr)_minmax(140px,0.7fr)_minmax(140px,0.7fr)_minmax(140px,0.7fr)_110px_auto] xl:items-end">
            {stateful ? (
              <label className="block">
                <span className={OM_LABEL}>Agent session</span>
                <select
                  className={cn(OM_INPUT, "font-mono")}
                  value={selectedLane ? laneOptionValue(selectedLane) : ""}
                  onChange={(event) =>
                    setExplorerLane(laneIdentityFromOption(lanes, event.target.value))
                  }
                  disabled={activeLanes.isPending || lanes.length === 0}
                >
                  <option value="">Select a session</option>
                  {lanes.map((lane) => (
                    <option key={`${lane.lane_id}:${lane.generation}`} value={laneOptionValue(lane)}>
                      {laneOptionLabel(lane)}
                    </option>
                  ))}
                </select>
              </label>
            ) : (
              <div>
                <span className={OM_LABEL}>Connection mode</span>
                <p className={cn(OM_INPUT, "flex items-center font-semibold")}>Direct server profile</p>
              </div>
            )}
            <label className="block">
              <span className={OM_LABEL}>Find schema</span>
              <input
                className={cn(OM_INPUT, "font-mono")}
                value={schemaFilter}
                onChange={(event) => setSchemaFilter(event.target.value)}
                placeholder="APP%"
              />
            </label>
            <label className="block">
              <span className={OM_LABEL}>Schema</span>
              <select
                className={OM_INPUT}
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
              <span className={OM_LABEL}>Type</span>
              <select
                className={OM_INPUT}
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
              <span className={OM_LABEL}>Object name pattern</span>
              <input
                className={cn(OM_INPUT, "font-mono")}
                value={nameLike}
                onChange={(event) => setNameLike(event.target.value)}
                placeholder="CUSTOMER%"
              />
            </label>
            <label className="block">
              <span className={OM_LABEL}>Maximum results</span>
              <input
                className={OM_INPUT}
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
          <div
            className="mt-4 flex flex-wrap items-center gap-2"
            role="group"
            aria-label="Object detail level"
          >
            {explorerDetailLevels.map((level) => (
              <Button
                key={level}
                type="button"
                variant={detailLevel === level ? "primary" : "secondary"}
                aria-pressed={detailLevel === level}
                onClick={() => setDetailLevel(level)}
              >
                {explorerDetailLevelLabel(level)}
              </Button>
            ))}
            <Badge tone={sessionTone}>
              {session.status === "success" ? "paired" : session.status === "error" ? "blocked" : "pairing"}
            </Badge>
            <Badge tone={connected ? "ok" : connection.isError || authoritativeConnection ? "warn" : "info"}>
              {connected ? "database connected" : connection.isError ? "connection failed" : authoritativeConnection ? "not connected" : connectionReady ? "checking connection" : stateful ? "select a session" : "checking transport"}
            </Badge>
          </div>
          {stateful && lanes.length === 0 && activeLanes.status === "success" ? (
            <p className="mt-3 rounded-md border border-[var(--om-control-border)] bg-[var(--om-surface-muted)] p-3 text-sm text-[var(--om-text)]" role="status">
              No active MCP sessions. Connect a client to this server, then return here to browse its database profile.
            </p>
          ) : connection.error instanceof Error ? (
            <p className="mt-3 rounded-md border border-[color-mix(in_srgb,var(--om-copper)_45%,transparent)] bg-[color-mix(in_srgb,var(--om-copper)_12%,transparent)] p-3 text-sm font-semibold text-[var(--om-copper)]">
              {connection.error.message}
            </p>
          ) : null}
        </ConsolePanel>

        <ExplorerGlobalSearchPanel
          searchText={globalSearchText}
          includeObjects={globalIncludeObjects}
          includeSource={globalIncludeSource}
          allSchemas={globalAllSchemas}
          sourceType={globalSourceType}
          request={globalSearchRequest}
          objectRows={globalObjectRows}
          sourceRows={globalSourceRows}
          objectPending={globalObjectsQuery.isPending}
          sourcePending={globalSourceQuery.isPending}
          objectError={
            globalObjectsQuery.error instanceof Error ? globalObjectsQuery.error.message : null
          }
          sourceError={
            globalSourceQuery.error instanceof Error ? globalSourceQuery.error.message : null
          }
          objectLimit={globalObjectLimit}
          sourceLimit={globalSourceLimit}
          invalidObjectRows={globalObjectDecode.invalidCount}
          invalidSourceRows={globalSourceDecode.invalidCount}
          canSearch={
            session.status === "success" &&
            connection.status === "success" &&
            connected &&
            explorerSearchAuthorityReady({
              includeObjects: globalIncludeObjects,
              includeSource: globalIncludeSource
            }) &&
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
            pending={schemasQuery.isPending}
            error={schemasQuery.error instanceof Error ? schemasQuery.error.message : null}
            limit={schemaLimit}
            onSelect={setOwner}
          />
          <ExplorerObjectsPanel
            rows={objectRows}
            invalidRows={objectDecode.invalidCount}
            selectedRef={selectedRef}
            pending={objectsQuery.isPending}
            error={objectsQuery.error instanceof Error ? objectsQuery.error.message : null}
            limit={objectLimit}
            onSelect={selectRow}
          />
        </div>

        <ExplorerObjectDetailPanel
          row={selectedRow}
          selectedRef={selectedRef}
          result={detailResult}
          pending={detailMutation.isPending}
          maxChars={maxChars}
          onMaxCharsChange={(value) => {
            clearExplorerDetailResult();
            setMaxChars(value);
          }}
          onReadDdl={(ref) => requestObjectDetail("ddl", ref)}
          onReadSource={(ref) => requestObjectDetail("source", ref)}
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
  objectLimit,
  sourceLimit,
  invalidObjectRows,
  invalidSourceRows,
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
  objectLimit: number | null;
  sourceLimit: number | null;
  invalidObjectRows: number;
  invalidSourceRows: number;
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
  // Both hit lists take the same up-to-5000 bound as the object table.
  const objectHitsRef = React.useRef<HTMLDivElement>(null);
  const sourceHitsRef = React.useRef<HTMLDivElement>(null);
  const objectHits = useWindowedRows(objectRows, objectHitsRef, ESTIMATED_HIT_PX);
  const sourceHits = useWindowedRows(sourceRows, sourceHitsRef, ESTIMATED_HIT_PX);

  return (
    <ConsolePanel>
      <ConsolePanelHeader
        icon={Search}
        title="Search names and source"
        meta={pending ? "searching" : request ? `${totalHits} matches` : "enter a search term"}
        tone={tone}
      />
      <div className="space-y-4 p-4" aria-busy={pending}>
        <div className="grid gap-3 xl:grid-cols-[minmax(260px,1fr)_180px_auto] xl:items-end">
          <label className="block">
            <span className={OM_LABEL}>Search term</span>
            <input
              className={cn(OM_INPUT, "font-mono")}
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
            <span className={OM_LABEL}>Source object type</span>
            <select
              className={cn(OM_INPUT, "disabled:opacity-50")}
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
          <label className={OM_CHECK_LABEL}>
            <input
              className={OM_CHECKBOX}
              type="checkbox"
              checked={includeObjects}
              onChange={(event) => onIncludeObjectsChange(event.target.checked)}
            />
            Objects
          </label>
          <label className={OM_CHECK_LABEL}>
            <input
              className={OM_CHECKBOX}
              type="checkbox"
              checked={includeSource}
              onChange={(event) => onIncludeSourceChange(event.target.checked)}
            />
            Source
          </label>
          <label className={OM_CHECK_LABEL}>
            <input
              className={OM_CHECKBOX}
              type="checkbox"
              checked={allSchemas}
              onChange={(event) => onAllSchemasChange(event.target.checked)}
            />
            All visible schemas
          </label>
        </div>
        {request ? (
          <div
            className="grid gap-2 rounded-md border border-[var(--om-border)] bg-[var(--om-surface-muted)] p-3 text-sm sm:grid-cols-2 xl:grid-cols-4"
            data-testid="explorer-submitted-criteria"
            role="status"
          >
            <ConsoleFact label="Submitted term" value={request.needle} mono />
            <ConsoleFact
              label="Submitted scope"
              value={request.allSchemas ? "all visible schemas" : request.owner || "current schema"}
            />
            <ConsoleFact
              label="Submitted targets"
              value={[
                request.includeObjects ? "objects" : null,
                request.includeSource ? "source" : null
              ]
                .filter(Boolean)
                .join(" + ")}
            />
            <ConsoleFact
              label="Submitted source type"
              value={request.includeSource ? request.sourceType || "all source" : "not requested"}
              mono
            />
          </div>
        ) : null}
        {objectError ? <ErrorNotice message={objectError} /> : null}
        {sourceError ? <ErrorNotice message={sourceError} /> : null}
        {invalidObjectRows + invalidSourceRows > 0 ? (
          <ErrorNotice
            message={`Ignored ${invalidObjectRows + invalidSourceRows} malformed search result row(s) with incomplete Oracle object identity.`}
          />
        ) : null}
        {objectLimit || sourceLimit ? (
          <p
            className="rounded-md border border-[var(--om-control-border)] bg-[var(--om-surface-muted)] p-3 text-sm font-semibold text-[var(--om-text)]"
            role="status"
          >
            The server result limit was reached
            {objectLimit && sourceLimit && objectLimit !== sourceLimit
              ? ` (${objectLimit} objects, ${sourceLimit} source matches)`
              : ` (${objectLimit ?? sourceLimit})`}
            . Narrow the search or raise Maximum results before treating this list as complete.
          </p>
        ) : null}
        <div className="grid gap-4 xl:grid-cols-2">
          <div className="overflow-hidden rounded-md border border-[var(--om-border)]">
            <div className="flex items-center justify-between gap-3 border-b border-[var(--om-border)] bg-[var(--om-surface-muted)] px-3 py-2">
              <span className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
                Object matches
              </span>
              <Badge tone={request?.includeObjects ? "ok" : "off"}>{objectRows.length}</Badge>
            </div>
            <div
              ref={objectHitsRef}
              className="max-h-[360px] overflow-auto"
              data-omcp-virtualized={objectHits.virtualize ? "object-hits" : undefined}
              role="region"
              aria-label="Object search matches"
              tabIndex={0}
            >
              {objectRows.length === 0 ? (
                <p className="px-3 py-6 text-sm font-semibold text-[var(--om-text-muted)]">
                  {pending
                    ? "Searching objects…"
                      : objectError
                        ? "Object search failed."
                        : request && !request.includeObjects
                          ? "Objects were not included in the submitted search."
                      : request
                        ? "No object names matched this search."
                        : "Run a search to find visible objects."}
                </p>
              ) : (
                <>
                  {objectHits.padTop > 0 ? (
                    <div aria-hidden="true" style={{ height: objectHits.padTop }} />
                  ) : null}
                  {objectHits.visible.map(({ row, index }) => (
                    <button
                      key={objectRefKey(rowRef(row))}
                      ref={objectHits.measure}
                      data-index={index}
                      type="button"
                      className="block min-h-11 w-full border-b border-[var(--om-border)] px-3 py-3 text-left hover:bg-[var(--om-surface-muted)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[var(--om-focus)]"
                      onClick={() => onSelectObject(row)}
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="min-w-0 truncate font-mono text-sm font-semibold text-[var(--om-text-bright)]">
                          {row.objectName}
                        </span>
                        <Badge tone="neutral">{row.objectType}</Badge>
                      </div>
                      <p className="mt-1 font-mono text-xs text-[var(--om-text-muted)]">
                        {row.owner}
                      </p>
                    </button>
                  ))}
                  {objectHits.padBottom > 0 ? (
                    <div aria-hidden="true" style={{ height: objectHits.padBottom }} />
                  ) : null}
                </>
              )}
            </div>
          </div>
          <div className="overflow-hidden rounded-md border border-[var(--om-border)]">
            <div className="flex items-center justify-between gap-3 border-b border-[var(--om-border)] bg-[var(--om-surface-muted)] px-3 py-2">
              <span className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
                Source matches
              </span>
              <Badge tone={request?.includeSource ? "ok" : "off"}>{sourceRows.length}</Badge>
            </div>
            <div
              ref={sourceHitsRef}
              className="max-h-[360px] overflow-auto"
              data-omcp-virtualized={sourceHits.virtualize ? "source-hits" : undefined}
              role="region"
              aria-label="Source search matches"
              tabIndex={0}
            >
              {sourceRows.length === 0 ? (
                <p className="px-3 py-6 text-sm font-semibold text-[var(--om-text-muted)]">
                  {pending
                    ? "Searching source…"
                      : sourceError
                        ? "Source search failed."
                        : request && !request.includeSource
                          ? "Source was not included in the submitted search."
                      : request
                        ? "No source text matched this search."
                        : "Run a search to find text in visible PL/SQL source."}
                </p>
              ) : (
                <>
                  {sourceHits.padTop > 0 ? (
                    <div aria-hidden="true" style={{ height: sourceHits.padTop }} />
                  ) : null}
                  {sourceHits.visible.map(({ row, index }) => (
                    <button
                      key={JSON.stringify([row.owner, row.name, row.objectType, row.line])}
                      ref={sourceHits.measure}
                      data-index={index}
                      type="button"
                      className="block min-h-11 w-full border-b border-[var(--om-border)] px-3 py-3 text-left hover:bg-[var(--om-surface-muted)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[var(--om-focus)]"
                      onClick={() => onSelectSource(row)}
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="min-w-0 truncate font-mono text-sm font-semibold text-[var(--om-text-bright)]">
                          {row.name}
                        </span>
                        <span className="font-mono text-xs font-semibold text-[var(--om-text-muted)]">
                          {row.objectType}:{row.line}
                        </span>
                      </div>
                      <p className="mt-1 font-mono text-xs text-[var(--om-text-muted)]">
                        {row.owner}
                      </p>
                      <p className="mt-2 line-clamp-2 text-sm text-[var(--om-text)]">{row.text}</p>
                    </button>
                  ))}
                  {sourceHits.padBottom > 0 ? (
                    <div aria-hidden="true" style={{ height: sourceHits.padBottom }} />
                  ) : null}
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </ConsolePanel>
  );
}

function ExplorerSchemasPanel({
  rows,
  selectedOwner,
  pending,
  error,
  limit,
  onSelect
}: {
  rows: ExplorerSchemaRow[];
  selectedOwner: string;
  pending: boolean;
  error: string | null;
  limit: number | null;
  onSelect: (owner: string) => void;
}): React.ReactElement {
  return (
    <ConsolePanel>
      <ConsolePanelHeader
        icon={Database}
        title="Schemas"
        meta={pending ? "loading" : `${rows.length} visible`}
        tone={pending ? "info" : rows.length > 0 ? "ok" : "off"}
      />
      {error ? <ErrorNotice message={error} /> : null}
      {limit ? <ExplorerLimitNotice limit={limit} noun="schemas" /> : null}
      <div className="max-h-[520px] divide-y divide-[var(--om-border)] overflow-auto" aria-busy={pending}>
        {rows.length === 0 ? (
          <p className="px-4 py-8 text-center text-sm font-semibold text-[var(--om-text-muted)]">
            {pending ? "Loading schemas…" : error ? "Schema list unavailable." : "No visible schemas match this filter."}
          </p>
        ) : (
          rows.map((row) => {
            const selected = selectedOwner === row.schemaName;
            return (
              <button
                key={row.schemaName}
                type="button"
                className={cn(
                  "grid min-h-11 w-full grid-cols-[minmax(0,1fr)_80px] gap-3 px-4 py-3 text-left hover:bg-[var(--om-surface-muted)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[var(--om-focus)]",
                  selected
                    ? "bg-[color-mix(in_srgb,var(--om-gold)_12%,transparent)]"
                    : "bg-transparent"
                )}
                aria-pressed={selected}
                onClick={() => onSelect(row.schemaName)}
              >
                <span className="truncate font-mono text-sm font-semibold text-[var(--om-text-bright)]">
                  {row.schemaName}
                </span>
                <span className="text-right font-mono text-sm text-[var(--om-text)]">
                  {row.objectCount}
                </span>
              </button>
            );
          })
        )}
      </div>
    </ConsolePanel>
  );
}

/** Above this many rows the object list is windowed. The Explorer's default
 *  page is 100, so ordinary use renders as it always did; only a deliberately
 *  large page (up to the permitted 5000) pays for virtualization. */
const VIRTUALIZE_ROW_THRESHOLD = 150;
/** Two-line object cell plus py-4; the virtualizer re-measures from the DOM. */
const ESTIMATED_ROW_PX = 73;
/** A global-search hit: one two-line button. */
const ESTIMATED_HIT_PX = 62;

/**
 * Window a long list against a scroll container.
 *
 * Fails safe by design: until the virtualizer has measured a live scroll
 * element — and if measurement ever fails outright — every row is returned. A
 * slow list is a nuisance; a blank one is a lie.
 */
function useWindowedRows<T>(
  rows: T[],
  scrollRef: React.RefObject<HTMLElement | null>,
  estimatePx: number
): {
  virtualize: boolean;
  measure: ((node: Element | null) => void) | undefined;
  visible: Array<{ row: T; index: number }>;
  padTop: number;
  padBottom: number;
} {
  const virtualize = rows.length > VIRTUALIZE_ROW_THRESHOLD;
  const virtualizer = useVirtualizer({
    count: virtualize ? rows.length : 0,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => estimatePx,
    overscan: 10
  });
  const items = virtualizer.getVirtualItems();
  const windowed = virtualize && items.length > 0;
  return {
    virtualize,
    measure: virtualize ? virtualizer.measureElement : undefined,
    visible: windowed
      ? items.map((item) => ({ row: rows[item.index], index: item.index }))
      : rows.map((row, index) => ({ row, index })),
    padTop: windowed ? items[0].start : 0,
    padBottom: windowed ? virtualizer.getTotalSize() - items[items.length - 1].end : 0
  };
}

function ExplorerObjectTableRow({
  row,
  index,
  selected,
  measure,
  onSelect
}: {
  row: ExplorerObjectRow;
  index: number;
  selected: boolean;
  measure?: (node: Element | null) => void;
  onSelect: (row: ExplorerObjectRow) => void;
}): React.ReactElement {
  return (
    <tr
      ref={measure}
      data-index={index}
      aria-rowindex={index + 2}
      className={cn(
        "",
        selected ? "bg-[color-mix(in_srgb,var(--om-gold)_12%,transparent)]" : "bg-transparent"
      )}
    >
      <td className="px-4 py-4 align-top">
        <button
          type="button"
          className="min-h-11 rounded px-2 text-left font-mono text-sm font-semibold text-[var(--om-text-bright)] hover:bg-[var(--om-surface-muted)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--om-focus)]"
          aria-label={`View details for ${row.owner}.${row.objectName} (${row.objectType})`}
          aria-pressed={selected}
          onClick={() => onSelect(row)}
        >
          {row.objectName}
        </button>
        <p className="mt-1 font-mono text-xs text-[var(--om-text-muted)]">{row.owner}</p>
      </td>
      <td className="px-4 py-4 align-top font-mono text-sm text-[var(--om-text)]">
        {row.objectType}
      </td>
      <td className="px-4 py-4 align-top">
        <Badge tone={row.status === "INVALID" ? "warn" : row.status ? "ok" : "off"}>
          {row.status || "Not reported"}
        </Badge>
      </td>
      <td className="px-4 py-4 align-top font-mono text-sm text-[var(--om-text)]">{row.numRows}</td>
      <td className="px-4 py-4 align-top font-mono text-sm text-[var(--om-text)]">
        {row.columnCount}
      </td>
      <td className="px-4 py-4 align-top font-mono text-xs text-[var(--om-text)]">
        {row.lastAnalyzed}
      </td>
      <td className="max-w-[280px] px-4 py-4 align-top text-sm text-[var(--om-text)]">
        <p className="line-clamp-2">{row.comment}</p>
      </td>
    </tr>
  );
}

export function ExplorerObjectsPanel({
  rows,
  invalidRows = 0,
  selectedRef,
  pending,
  error,
  limit = null,
  onSelect
}: {
  rows: ExplorerObjectRow[];
  invalidRows?: number;
  selectedRef: ExplorerObjectRef | null;
  pending: boolean;
  error: string | null;
  limit?: number | null;
  onSelect: (row: ExplorerObjectRow) => void;
}): React.ReactElement {
  const scrollRef = React.useRef<HTMLDivElement>(null);
  // Explorer permits up to 5000 rows; window them once the list is big enough
  // to matter.
  const {
    virtualize,
    measure,
    visible: visibleRows,
    padTop,
    padBottom
  } = useWindowedRows(rows, scrollRef, ESTIMATED_ROW_PX);
  return (
    <ConsolePanel>
      <ConsolePanelHeader
        icon={Search}
        title="Objects"
        meta={
          pending ? "loading" : `${rows.length} ${rows.length === 1 ? "object" : "objects"}`
        }
        tone={pending ? "info" : rows.length > 0 ? "ok" : "off"}
      />
      {error ? <ErrorNotice message={error} /> : null}
      {invalidRows > 0 ? (
        <ErrorNotice
          message={`Ignored ${invalidRows} malformed object row(s) with incomplete Oracle identity.`}
        />
      ) : null}
      {limit ? <ExplorerLimitNotice limit={limit} noun="objects" /> : null}
      <div
        ref={scrollRef}
        className={cn("overflow-x-auto", virtualize && "max-h-[70vh] overflow-y-auto")}
        data-omcp-virtualized={virtualize ? "objects" : undefined}
        aria-busy={pending}
        role="region"
        aria-label="Database objects"
        tabIndex={0}
      >
        <table
          className="w-full min-w-[980px] border-collapse text-left"
          aria-rowcount={rows.length + 1}
        >
          <caption className="sr-only">Objects visible through the selected MCP session</caption>
          <thead className="bg-[var(--om-surface-muted)] text-2xs uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
            <tr>
              <th className="px-4 py-3 font-semibold">Object</th>
              <th className="px-4 py-3 font-semibold">Type</th>
              <th className="px-4 py-3 font-semibold">Status</th>
              <th className="px-4 py-3 font-semibold">Estimated rows</th>
              <th className="px-4 py-3 font-semibold">Columns</th>
              <th className="px-4 py-3 font-semibold">Analyzed</th>
              <th className="px-4 py-3 font-semibold">Comment</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--om-border)]">
            {rows.length === 0 ? (
              <tr>
                <td
                  className="px-4 py-8 text-center text-sm font-semibold text-[var(--om-text-muted)]"
                  colSpan={7}
                >
                  {pending ? "Loading objects…" : error ? "Object list unavailable." : "No objects match the current filters."}
                </td>
              </tr>
            ) : (
              <>
                {padTop > 0 ? (
                  <tr aria-hidden="true">
                    <td colSpan={7} style={{ height: padTop }} />
                  </tr>
                ) : null}
                {visibleRows.map(({ row, index }) => {
                  const ref = rowRef(row);
                  const selected = selectedRef && objectRefKey(selectedRef) === objectRefKey(ref);
                  return (
                    <ExplorerObjectTableRow
                      key={objectRefKey(ref)}
                      row={row}
                      index={index}
                      selected={Boolean(selected)}
                      measure={measure}
                      onSelect={onSelect}
                    />
                  );
                })}
                {padBottom > 0 ? (
                  <tr aria-hidden="true">
                    <td colSpan={7} style={{ height: padBottom }} />
                  </tr>
                ) : null}
              </>
            )}
          </tbody>
        </table>
      </div>
    </ConsolePanel>
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
  const detailText = explorerDetailText(detail, result?.state === "ok" ? result.kind : null);
  return (
    <ConsolePanel>
      <div className="flex flex-col gap-3 border-b border-[var(--om-border)] px-4 py-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="min-w-0">
          <h3 className="flex items-center gap-2 text-base font-semibold text-[var(--om-text-bright)]">
            <Code2 className="size-4" aria-hidden="true" />
            Object details
          </h3>
          <p className="mt-1 break-all font-mono text-sm text-[var(--om-text-muted)]">
            {selectedRef ? objectRefLabel(selectedRef) : "Select an object to inspect it"}
          </p>
        </div>
        <div className="flex flex-wrap items-end gap-2">
          <Button
            type="button"
            variant="secondary"
            disabled={!selectedRef || pending}
            onClick={() => selectedRef && onReadDdl(selectedRef)}
          >
            <Database className="size-4" aria-hidden="true" />
            View creation DDL
          </Button>
          <Button
            type="button"
            variant="secondary"
            disabled={!selectedRef || !sourceAllowed || pending}
            onClick={() => selectedRef && onReadSource(selectedRef)}
          >
            <Code2 className="size-4" aria-hidden="true" />
            View source
          </Button>
          <Badge tone={pending ? "info" : result?.state === "error" ? "warn" : result ? "ok" : "off"}>
            {pending ? "loading" : result?.state ?? "empty"}
          </Badge>
        </div>
      </div>
      <details className="border-b border-[var(--om-border)] px-4 py-3">
        <summary className="cursor-pointer text-sm font-semibold text-[var(--om-text)]">Source options</summary>
        <label className="mt-3 block max-w-56">
          <span className={OM_LABEL}>Maximum source characters</span>
          <input
            className={OM_INPUT}
            min={1000}
            max={1000000}
            type="number"
            value={maxChars}
            onChange={(event) => onMaxCharsChange(clampChars(event.target.valueAsNumber))}
          />
        </label>
      </details>
      <div className="grid gap-4 p-4 xl:grid-cols-[minmax(0,0.65fr)_minmax(360px,1.35fr)]">
        <div className="space-y-3">
          <ExplorerFact label="Owner" value={selectedRef?.owner ?? "…"} />
          <ExplorerFact label="Name" value={selectedRef?.name ?? "…"} />
          <ExplorerFact label="Type" value={selectedRef?.objectType ?? "…"} />
          <ExplorerFact label="Status" value={row?.status || "…"} />
          <ExplorerFact label="Columns" value={row?.columnCount ?? "…"} />
          <ExplorerFact label="Estimated rows" value={row?.numRows ?? "Not analyzed"} />
        </div>
        {result?.state === "error" ? (
          <ErrorNotice message={result.message} />
        ) : detailText ? (
          <div className="min-w-0 space-y-3">
            <pre className={cn(OM_CODE, "max-h-[620px] whitespace-pre-wrap")}>{detailText}</pre>
            <details className="rounded-md border border-[var(--om-border)] p-3">
              <summary className="cursor-pointer text-sm font-semibold text-[var(--om-text)]">Technical metadata</summary>
              <pre className={cn(OM_CODE, "mt-3 max-h-[360px]")}>{prettyJson(detail)}</pre>
            </details>
          </div>
        ) : (
          <div className="rounded-md border border-[var(--om-border)] bg-[var(--om-surface-muted)] p-4 text-sm text-[var(--om-text-muted)]">
            {selectedRef
              ? pending
                ? "Loading object definition…"
                : "Choose View creation DDL or View source."
              : "Select an object from the table to view its definition."}
          </div>
        )}
      </div>
    </ConsolePanel>
  );
}

function explorerDetailText(detail: unknown, kind: "ddl" | "source" | null): string | null {
  if (!isRecord(detail) || !kind) {
    return null;
  }
  const candidates =
    kind === "ddl"
      ? [detail["ddl"], detail["definition"], detail["text"]]
      : [detail["source"], detail["source_text"], detail["text"]];
  for (const candidate of candidates) {
    if (typeof candidate === "string" && candidate.trim()) {
      return candidate;
    }
    if (Array.isArray(candidate)) {
      const lines = candidate.filter((line): line is string => typeof line === "string");
      if (lines.length > 0) {
        return lines.join("\n");
      }
    }
  }
  return null;
}

function ExplorerLimitNotice({
  limit,
  noun
}: {
  limit: number;
  noun: string;
}): React.ReactElement {
  return (
    <p
      className="border-b border-[var(--om-control-border)] bg-[var(--om-surface-muted)] px-4 py-3 text-sm font-semibold text-[var(--om-text)]"
      role="status"
    >
      Server limit reached at {formatNumber(limit)} {noun}. Narrow the filters or raise Maximum
      results before treating this list as complete.
    </p>
  );
}

function ErrorNotice({ message }: { message: string }): React.ReactElement {
  return (
    <p className="m-4 rounded-md border border-[color-mix(in_srgb,var(--om-copper)_45%,transparent)] bg-[color-mix(in_srgb,var(--om-copper)_12%,transparent)] p-3 text-sm font-semibold text-[var(--om-text-bright)]" role="alert">
      {message}
    </p>
  );
}

function ExplorerFact({ label, value }: { label: string; value: string }): React.ReactElement {
  return (
    <div className="rounded-md border border-[var(--om-border)] bg-[var(--om-surface-muted)] p-3">
      <p className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
        {label}
      </p>
      <p className="mt-1 break-all font-mono text-xs text-[var(--om-text-bright)]">{value}</p>
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

function explorerLimitFromResponse(
  response: OperatorResponse<WorkbenchActionData> | undefined
): number | null {
  const result = mcpResult(response?.data.mcp_response);
  if (!isRecord(result) || result["truncated"] !== true) {
    return null;
  }
  const maxRows = result["max_rows"];
  return typeof maxRows === "number" && Number.isFinite(maxRows) ? maxRows : 0;
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
): ExplorerRowsDecode<ExplorerObjectRow> {
  const result = mcpResult(response?.data.mcp_response);
  const objects = isRecord(result) && Array.isArray(result["results"]) ? result["results"] : [];
  return decodeExplorerObjectRows(objects);
}

function sourceRowsFromResponse(
  response: OperatorResponse<WorkbenchActionData> | undefined
): ExplorerRowsDecode<ExplorerSourceHitRow> {
  const result = mcpResult(response?.data.mcp_response);
  const matches = isRecord(result) && Array.isArray(result["matches"]) ? result["matches"] : [];
  return decodeExplorerSourceRows(matches);
}

function rowRef(row: ExplorerObjectRow): ExplorerObjectRef {
  return {
    owner: row.owner,
    name: row.objectName,
    objectType: row.objectType
  };
}

export function objectRefKey(ref: ExplorerObjectRef): string {
  return JSON.stringify([ref.owner, ref.name, ref.objectType]);
}

function objectRefLabel(ref: ExplorerObjectRef): string {
  return `${ref.owner}.${ref.name} (${ref.objectType})`;
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

export function decodeExplorerObjectRows(
  values: readonly unknown[]
): ExplorerRowsDecode<ExplorerObjectRow> {
  const rows: ExplorerObjectRow[] = [];
  let invalidCount = 0;
  for (const value of values) {
    if (!isRecord(value)) {
      invalidCount += 1;
      continue;
    }
    const owner = requiredIdentityCell(value, "owner");
    const objectName = requiredIdentityCell(value, "object_name");
    const objectType = requiredIdentityCell(value, "object_type");
    if (!owner || !objectName || !objectType) {
      invalidCount += 1;
      continue;
    }
    rows.push({
      owner,
      objectName,
      objectType,
      status: cellText(value, "status") ?? "",
      numRows: cellText(value, "num_rows") ?? "…",
      columnCount: cellText(value, "column_count") ?? "…",
      lastAnalyzed: cellText(value, "last_analyzed") ?? "…",
      comment: cellText(value, "comment") ?? "",
      raw: value
    });
  }
  return { rows, invalidCount };
}

export function decodeExplorerSourceRows(
  values: readonly unknown[]
): ExplorerRowsDecode<ExplorerSourceHitRow> {
  const rows: ExplorerSourceHitRow[] = [];
  let invalidCount = 0;
  for (const value of values) {
    if (!isRecord(value)) {
      invalidCount += 1;
      continue;
    }
    const owner = requiredIdentityCell(value, "owner");
    const name = requiredIdentityCell(value, "name");
    const objectType = requiredIdentityCell(value, "type");
    const line = requiredIdentityCell(value, "line");
    if (!owner || !name || !objectType || !line) {
      invalidCount += 1;
      continue;
    }
    rows.push({
      owner,
      name,
      objectType,
      line,
      text: cellText(value, "text") ?? "",
      raw: value
    });
  }
  return { rows, invalidCount };
}

function requiredIdentityCell(row: Record<string, unknown>, key: string): string | null {
  const value = cellText(row, key)?.trim();
  return value ? value : null;
}

export function explorerDetailRequestIdentity(input: {
  kind: "ddl" | "source";
  ref: ExplorerObjectRef;
  lane?: OperatorLaneTarget;
  maxChars: number;
  requestGeneration: number;
}): string {
  return JSON.stringify([
    input.lane?.laneId ?? "stateless",
    input.lane?.generation ?? 0,
    objectRefKey(input.ref),
    input.kind,
    input.kind === "source" ? input.maxChars : null,
    input.requestGeneration
  ]);
}

export function explorerDetailCompletionIsCurrent(
  completion: { identity: string; requestGeneration: number },
  currentIdentity: string | null,
  currentRequestGeneration: number
): boolean {
  return (
    completion.identity === currentIdentity &&
    completion.requestGeneration === currentRequestGeneration
  );
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

function clampChars(value: number): number {
  if (!Number.isFinite(value)) {
    return 40_000;
  }
  return Math.min(1_000_000, Math.max(1_000, Math.trunc(value)));
}

const EMPTY_SCHEMA_SNAPSHOT = JSON.stringify({ objects: [] }, null, 2);

type ReviewResult = {
  state: OperatorOutcomeState;
  label: string;
  response: unknown;
  outcome: OperatorOutcome;
};

function reviewSuccess(label: string, response: unknown): ReviewResult {
  const outcome = decodeOperatorOutcome(200, response);
  return { state: outcome.state, label, response, outcome };
}

function reviewFailure(label: string, error: unknown, fallback: string): ReviewResult {
  const outcome = operatorOutcomeFromError(error, fallback);
  return {
    state: outcome.state,
    label,
    response: operatorResponseFromError(error),
    outcome
  };
}

export function resolveReviewSelection(
  proposals: readonly ChangeProposalListView[],
  selectedId: string
): ChangeProposalListView | null {
  return selectedId
    ? proposals.find((proposal) => proposal.id === selectedId) ?? null
    : null;
}

export function visibleReviewProposals(
  filtered: readonly ChangeProposalListView[],
  selected: ChangeProposalListView | null
): ChangeProposalListView[] {
  if (!selected || filtered.some((proposal) => proposal.id === selected.id)) {
    return [...filtered];
  }
  return [selected, ...filtered];
}

export function reviewProposalRevisionIdentity(
  proposal: ChangeProposalView | null,
  lane: OperatorLaneTarget | undefined
): string | null {
  if (!proposal) {
    return null;
  }
  return JSON.stringify([
    proposal.id,
    proposal.updated_at,
    proposal.statements.map((statement) => [
      statement.id,
      statement.sql_sha256,
      statement.sql_template,
      statement.unit,
      statement.bind_count,
      statement.commit,
      statement.capture_dbms_output
    ]),
    lane?.laneId ?? "stateless",
    lane?.generation ?? 0
  ]);
}

export function reviewCompletionIsCurrent(
  requestIdentity: string,
  currentIdentity: string | null
): boolean {
  return requestIdentity === currentIdentity;
}

export function invalidReviewCursorError(error: unknown): boolean {
  if (!(error instanceof OperatorOutcomeError) || error.httpStatus !== 400) {
    return false;
  }
  const envelope = isRecord(error.response) ? error.response : null;
  const data = envelope && isRecord(envelope["data"]) ? envelope["data"] : envelope;
  const code = data && typeof data["error"] === "string" ? data["error"] : null;
  return code === "invalid_change_proposal" || code === "invalid_source_history_request";
}

export function consumedReviewGrantState(): { confirm: ""; acknowledged: false } {
  return { confirm: "", acknowledged: false };
}

export function reviewGrantReady(
  needsConfirm: boolean,
  confirm: string,
  acknowledged: boolean
): boolean {
  return !needsConfirm || (confirm.trim().length > 0 && acknowledged);
}

type ReviewPreviewRequest = {
  authority: string;
  identity: string;
  proposalId: string;
  lane?: OperatorLaneTarget;
  sql: string;
};

type ReviewApplyRequest = {
  authority: string;
  identity: string;
  proposalId: string;
  lane?: OperatorLaneTarget;
  confirm: string;
};

export function reviewsAuthoritativeState(input: {
  sessionStatus: DashboardQueryStatus;
  session: DashboardSession | undefined;
  proposalsStatus: DashboardQueryStatus;
  proposals: OperatorResponse<ChangeProposalListData> | undefined;
  historyStatus: DashboardQueryStatus;
  history: OperatorResponse<SourceHistoryListData> | undefined;
}): {
  session: DashboardSession | null;
  proposals: ChangeProposalListView[];
  proposalsNextCursor: string | null;
  snapshots: SourceSnapshotView[];
  historyNextCursor: string | null;
} {
  const session = authoritativeQueryData(input.sessionStatus, input.session) ?? null;
  const proposals = authoritativeQueryData(input.proposalsStatus, input.proposals)?.data;
  const history = authoritativeQueryData(input.historyStatus, input.history)?.data;
  return {
    session,
    proposals: proposals?.proposals ?? EMPTY_CHANGE_PROPOSALS,
    proposalsNextCursor: proposals?.nextCursor ?? null,
    snapshots: history?.snapshots ?? EMPTY_SOURCE_SNAPSHOTS,
    historyNextCursor: history?.nextCursor ?? null
  };
}

export function authoritativeReviewProfiles(
  status: DashboardQueryStatus,
  response: OperatorResponse<ConfigOpsStatusData> | undefined
): ConfigProfileMetadata[] {
  return authoritativeQueryData(status, response)?.data.status.profiles ?? [];
}

export function authoritativeReviewCapabilities(
  status: DashboardQueryStatus,
  response: OperatorResponse<WorkbenchActionData> | undefined
): OperatorResponse<WorkbenchActionData> | undefined {
  return authoritativeQueryData(status, response);
}

function ReviewsPage(): React.ReactElement {
  const [filter, setFilter] = React.useState("");
  // Which proposal you are reviewing is the page's identity, so it is linkable.
  const { id: selectedId = "" } = useSearch({ from: reviewsRoute.id });
  const reviewsNavigate = useNavigate({ from: reviewsRoute.id });
  const navigateSelectedId = React.useCallback(
    (next: string) => {
      void reviewsNavigate({ search: { id: next || undefined }, replace: true });
    },
    [reviewsNavigate]
  );
  const [profile, setProfile] = React.useState("");
  const [title, setTitle] = React.useState("Inspect database time");
  const [sqlTemplate, setSqlTemplate] = React.useState(
    "SELECT CURRENT_TIMESTAMP AS database_time FROM dual"
  );
  const [bindsJson, setBindsJson] = React.useState("[]");
  const [draftCommit, setDraftCommit] = React.useState(false);
  const [captureDbmsOutput, setCaptureDbmsOutput] = React.useState(false);
  const [selectedLaneBinding, setSelectedLaneBinding] = React.useState<LaneIdentity | null>(null);
  const [confirm, setConfirm] = React.useState("");
  const [applyAcknowledged, setApplyAcknowledged] = React.useState(false);
  const [lastResult, setLastResult] = React.useState<ReviewResult | null>(null);
  const [proposalsCursor, setProposalsCursor] = React.useState<string | undefined>(undefined);
  const [historyCursor, setHistoryCursor] = React.useState<string | undefined>(undefined);

  const session = useQuery({
    queryKey: ["dashboard-session"],
    queryFn: fetchDashboardSession,
    staleTime: 60_000,
    refetchInterval: 60_000,
    retry: 1
  });
  const proposalsQuery = useQuery({
    queryKey: ["change-proposals", proposalsCursor ?? "start"],
    queryFn: ({ signal }) => fetchChangeProposals(proposalsCursor, { signal })
  });
  const config = useQuery({
    queryKey: ["operator-config"],
    queryFn: fetchOperatorConfig,
    staleTime: 30_000
  });
  const activeLanes = useQuery({
    queryKey: ["active-lanes"],
    queryFn: fetchActiveLanes,
    refetchInterval: 5_000
  });
  const lanes = activeLanes.status === "success" ? activeLanes.data.data.lanes : EMPTY_ACTIVE_LANES;
  const stateful = authoritativeServerMode(activeLanes.status, activeLanes.data) !== false;
  const laneSelection =
    stateful && activeLanes.status === "success"
      ? resolveExactLane(selectedLaneBinding, lanes)
      : { lane: null, invalidated: false };
  const selectedLane = laneSelection.lane ?? undefined;
  const reviewLane = selectedLane ? laneIdentity(selectedLane) : undefined;
  const laneReady = activeLanes.status === "success" && (!stateful || Boolean(reviewLane));
  const sourceHistoryQuery = useQuery({
    queryKey: ["source-history", historyCursor ?? "start"],
    queryFn: ({ signal }) => fetchSourceHistory(historyCursor, { signal })
  });
  const authoritative = reviewsAuthoritativeState({
    sessionStatus: session.status,
    session: session.data,
    proposalsStatus: proposalsQuery.status,
    proposals: proposalsQuery.data,
    historyStatus: sourceHistoryQuery.status,
    history: sourceHistoryQuery.data
  });
  const { proposals, proposalsNextCursor, snapshots, historyNextCursor } = authoritative;
  const sessionAuthority = dashboardAuthorityIdentity(authoritative.session ?? undefined);
  const reviewProfiles = authoritativeReviewProfiles(config.status, config.data);
  const profileAvailable = reviewProfiles.some((item) => item.name === profile);
  React.useEffect(() => {
    if (profile && !profileAvailable) {
      setProfile("");
    }
  }, [profile, profileAvailable]);
  const filtered = React.useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) {
      return proposals;
    }
    return proposals.filter((proposal) => proposalSearchText(proposal).includes(needle));
  }, [filter, proposals]);
  const selected = resolveReviewSelection(proposals, selectedId);
  const visibleProposals = React.useMemo(
    () => visibleReviewProposals(filtered, selected),
    [filtered, selected]
  );
  const selectedOutsideFilter = Boolean(
    selected && !filtered.some((proposal) => proposal.id === selected.id)
  );
  const unresolvedSelectedId = Boolean(
    selectedId && proposalsQuery.status === "success" && !selected
  );
  const selectedProposalId = selected?.id ?? null;

  // The polled list omits sql_template bodies; fetch the full detail (with SQL
  // text) for the selected proposal on demand.
  const detailQuery = useQuery({
    queryKey: ["change-proposal-detail", selectedProposalId],
    queryFn: ({ signal }) => fetchChangeProposalDetail(selectedProposalId as string, { signal }),
    enabled: Boolean(selectedProposalId)
  });
  const selectedDetail =
    authoritativeQueryData(detailQuery.status, detailQuery.data)?.data.proposal ?? null;
  const reviewIdentity = reviewProposalRevisionIdentity(selectedDetail, reviewLane);
  const reviewIdentityRef = React.useRef(reviewIdentity);
  React.useLayoutEffect(() => {
    reviewIdentityRef.current = reviewIdentity;
  }, [reviewIdentity]);
  const consumeReviewGrant = React.useCallback(() => {
    const consumed = consumedReviewGrantState();
    setConfirm(consumed.confirm);
    setApplyAcknowledged(consumed.acknowledged);
  }, []);
  const invalidateReviewGrant = React.useCallback(() => {
    reviewIdentityRef.current = null;
    consumeReviewGrant();
  }, [consumeReviewGrant]);
  const setSelectedId = React.useCallback(
    (next: string) => {
      invalidateReviewGrant();
      navigateSelectedId(next);
    },
    [invalidateReviewGrant, navigateSelectedId]
  );
  const selectReviewLane = React.useCallback(
    (next: LaneIdentity | null) => {
      invalidateReviewGrant();
      setSelectedLaneBinding(next);
    },
    [invalidateReviewGrant]
  );
  React.useEffect(() => {
    if (laneSelection.invalidated) {
      invalidateReviewGrant();
      setSelectedLaneBinding(null);
    }
  }, [invalidateReviewGrant, laneSelection.invalidated]);
  const writeStatements = selectedDetail?.statements.filter((statement) => statement.unit !== "read") ?? [];
  const needsConfirm = writeStatements.length > 0;
  const hasDdl = selectedDetail?.statements.some((statement) => statement.unit === "ddl") ?? false;
  const hasHiddenBinds = selectedDetail?.statements.some((statement) => statement.bind_count > 0) ?? false;
  const laneCapabilities = useQuery({
    queryKey: [
      "reviews",
      "capabilities",
      reviewLane?.laneId ?? "stateless",
      reviewLane?.generation ?? 0
    ],
    queryFn: async ({ signal }) => {
      if (!session.data || !laneReady) {
        throw new Error("database connection is not ready");
      }
      return fetchLaneCapabilities(session.data, reviewLane, { signal });
    },
    enabled: session.status === "success" && laneReady,
    retry: 1
  });
  const selectedLaneCapabilities = authoritativeReviewCapabilities(
    laneCapabilities.status,
    laneCapabilities.data
  );
  const selectedLaneProfile = selectedLaneCapabilities
    ? sessionCapabilitiesSummary(selectedLaneCapabilities).activeProfile
    : "unknown";
  const profileMatches = Boolean(selectedDetail) && selectedLaneProfile === selectedDetail?.profile;

  React.useEffect(() => {
    if (laneCapabilities.status === "error") {
      invalidateReviewGrant();
    }
  }, [invalidateReviewGrant, laneCapabilities.status]);

  // An acknowledgement is about one specific proposal. Never let it carry over
  // to another revision, statement digest, SQL body, or lane generation.
  React.useEffect(() => {
    setApplyAcknowledged(false);
    setConfirm("");
  }, [reviewIdentity]);

  // Cursors are bound to the board revision; if the store changed under a held
  // cursor the server rejects it, so fall back to the first page.
  React.useEffect(() => {
    if (proposalsCursor && invalidReviewCursorError(proposalsQuery.error)) {
      setProposalsCursor(undefined);
    }
  }, [proposalsCursor, proposalsQuery.error]);
  React.useEffect(() => {
    if (historyCursor && invalidReviewCursorError(sourceHistoryQuery.error)) {
      setHistoryCursor(undefined);
    }
  }, [historyCursor, sourceHistoryQuery.error]);

  const draftMutation = useMutation({
    mutationFn: async (requestAuthority: string) => {
      if (
        !session.data ||
        !sessionAuthority ||
        requestAuthority !== sessionAuthority ||
        !profileAvailable
      ) {
        throw new Error("dashboard session is not ready");
      }
      const binds = parseBindsJson(bindsJson);
      return draftChangeProposal(session.data, {
        profile: profile.trim(),
        author: "human",
        title: title.trim() || undefined,
        statements: [
          {
            sql_template: sqlTemplate.trim(),
            binds,
            commit: draftCommit,
            capture_dbms_output: captureDbmsOutput
          }
        ]
      });
    },
    onSuccess: (response, requestAuthority) => {
      if (requestAuthority !== sessionAuthority) {
        return;
      }
      setLastResult(reviewSuccess("Draft", response));
      setSelectedId(response.data.proposal.id);
      setProposalsCursor(undefined);
      queryClient.invalidateQueries({ queryKey: ["change-proposals"] });
    },
    onError: (error, requestAuthority) => {
      if (requestAuthority !== sessionAuthority) {
        return;
      }
      setLastResult(reviewFailure("Draft", error, "proposal draft failed"));
    }
  });

  const applyMutation = useMutation({
    mutationFn: async (request: ReviewApplyRequest) => {
      if (
        !session.data ||
        !sessionAuthority ||
        request.authority !== sessionAuthority ||
        !reviewCompletionIsCurrent(request.identity, reviewIdentityRef.current)
      ) {
        throw new Error("dashboard session is not ready");
      }
      if (!laneReady) {
        throw new Error("select a proposal and ready database connection");
      }
      return applyChangeProposal(session.data, {
        proposalId: request.proposalId,
        lane: request.lane,
        confirm: request.confirm
      });
    },
    onMutate: consumeReviewGrant,
    onSuccess: (response, request) => {
      clearExplorerMetadataCache();
      queryClient.invalidateQueries({ queryKey: ["explorer"] });
      queryClient.invalidateQueries({ queryKey: ["operator-metrics"] });
      queryClient.invalidateQueries({ queryKey: ["audit-tail"] });
      queryClient.invalidateQueries({ queryKey: ["change-proposals"] });
      if (
        request.authority !== sessionAuthority ||
        !reviewCompletionIsCurrent(request.identity, reviewIdentityRef.current)
      ) {
        return;
      }
      setLastResult(reviewSuccess("Apply", response));
    },
    onError: (error, request) => {
      if (
        request.authority !== sessionAuthority ||
        !reviewCompletionIsCurrent(request.identity, reviewIdentityRef.current)
      ) {
        return;
      }
      setLastResult(reviewFailure("Apply", error, "proposal apply failed"));
    }
  });

  const previewSelectedMutation = useMutation({
    mutationFn: async (request: ReviewPreviewRequest) => {
      if (
        !session.data ||
        !sessionAuthority ||
        request.authority !== sessionAuthority ||
        !reviewCompletionIsCurrent(request.identity, reviewIdentityRef.current) ||
        !laneReady
      ) {
        throw new Error("select a loaded change plan and ready database connection");
      }
      return previewWorkbenchSql(session.data, {
        lane: request.lane,
        mode: "dml_preview_confirm",
        sql: request.sql
      });
    },
    onMutate: consumeReviewGrant,
    onSuccess: (response, request) => {
      if (
        request.authority !== sessionAuthority ||
        !reviewCompletionIsCurrent(request.identity, reviewIdentityRef.current)
      ) {
        return;
      }
      setConfirm(confirmationFromResponse(response) ?? "");
      setLastResult(reviewSuccess("Preview selected change", response));
    },
    onError: (error, request) => {
      if (
        request.authority !== sessionAuthority ||
        !reviewCompletionIsCurrent(request.identity, reviewIdentityRef.current)
      ) {
        return;
      }
      setLastResult(reviewFailure("Preview selected change", error, "change preview failed"));
    }
  });

  const revertMutation = useMutation({
    mutationFn: async ({
      snapshot,
      authority: requestAuthority
    }: {
      snapshot: SourceSnapshotView;
      authority: string;
    }) => {
      if (!session.data || !sessionAuthority || requestAuthority !== sessionAuthority) {
        throw new Error("dashboard session is not ready");
      }
      return draftSourceHistoryRevert(session.data, snapshot.id, snapshot.profile);
    },
    onSuccess: (response, { authority: requestAuthority }) => {
      if (requestAuthority !== sessionAuthority) {
        return;
      }
      setLastResult(reviewSuccess("Revert draft", response));
      setSelectedId(response.data.proposal.id);
      setProposalsCursor(undefined);
      queryClient.invalidateQueries({ queryKey: ["change-proposals"] });
    },
    onError: (error, { authority: requestAuthority }) => {
      if (requestAuthority !== sessionAuthority) {
        return;
      }
      setLastResult(reviewFailure("Revert draft", error, "revert draft failed"));
    }
  });
  const purgeReviewAuthorityState = React.useCallback(() => {
    setConfirm("");
    setApplyAcknowledged(false);
    setLastResult(null);
    draftMutation.reset();
    applyMutation.reset();
    previewSelectedMutation.reset();
    revertMutation.reset();
  }, [
    applyMutation.reset,
    draftMutation.reset,
    previewSelectedMutation.reset,
    revertMutation.reset
  ]);
  useDashboardAuthorityPurge(sessionAuthority, purgeReviewAuthorityState);

  const canDraft =
    session.status === "success" &&
    config.status === "success" &&
    profileAvailable &&
    sqlTemplate.trim().length > 0 &&
    !draftMutation.isPending;
  // Name the strongest thing this proposal does, so the acknowledgement says
  // what the operator is agreeing to rather than "are you sure?".
  const applyDangerSummary = React.useMemo(() => {
    const units = new Set(
      (selectedDetail?.statements ?? [])
        .filter((statement) => statement.unit !== "read")
        .map((statement) => statement.unit.toUpperCase())
    );
    return units.size > 0 ? Array.from(units).sort().join(" + ") : "non-read";
  }, [selectedDetail]);
  const canPreviewSelected =
    session.status === "success" &&
    detailQuery.status === "success" &&
    laneCapabilities.status === "success" &&
    Boolean(reviewIdentity && selectedDetail) &&
    laneReady &&
    profileMatches &&
    !hasHiddenBinds &&
    writeStatements.length === 1 &&
    writeStatements[0]?.unit === "dml" &&
    !applyMutation.isPending &&
    !previewSelectedMutation.isPending;
  const canApply =
    session.status === "success" &&
    detailQuery.status === "success" &&
    laneCapabilities.status === "success" &&
    Boolean(selected && selectedDetail && reviewIdentity) &&
    laneReady &&
    profileMatches &&
    !hasHiddenBinds &&
    !hasDdl &&
    writeStatements.length <= 1 &&
    !applyMutation.isPending &&
    !previewSelectedMutation.isPending &&
    reviewGrantReady(needsConfirm, confirm, applyAcknowledged);
  const previewSelectedChange = (): void => {
    if (
      !selectedDetail ||
      !reviewIdentity ||
      writeStatements.length !== 1 ||
      writeStatements[0].unit !== "dml"
    ) {
      return;
    }
    previewSelectedMutation.mutate({
      authority: sessionAuthority ?? "",
      identity: reviewIdentity,
      proposalId: selectedDetail.id,
      lane: reviewLane,
      sql: writeStatements[0].sql_template
    });
  };
  const applySelectedChange = (): void => {
    if (!selected || !reviewIdentity) {
      return;
    }
    applyMutation.mutate({
      authority: sessionAuthority ?? "",
      identity: reviewIdentity,
      proposalId: selected.id,
      lane: reviewLane,
      confirm
    });
  };

  return (
    <PageFrame
      title="Change review"
      eyebrow="Saved database changes"
      description="Inspect exact SQL, target the matching database profile, and let the server re-check every statement at apply time."
    >
      <div className="grid gap-4 xl:grid-cols-[minmax(320px,0.8fr)_minmax(0,1.2fr)]">
        <div className="space-y-4">
          <ConsolePanel>
            <div className="border-b border-[var(--om-border)] p-4">
              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <h3 className="flex items-center gap-2 text-base font-semibold text-[var(--om-text-bright)]">
                    <GitPullRequest className="size-4" aria-hidden="true" />
                    Saved change plans
                  </h3>
                  <p className="mt-1 truncate text-sm text-[var(--om-text-muted)]">
                    {proposalsQuery.isPending
                      ? "loading"
                      : `${formatNumber(filtered.length)} filter match(es)${selectedOutsideFilter ? " + selected" : ""}`}
                  </p>
                </div>
                <Badge tone={proposalsQuery.isError ? "warn" : proposalsQuery.data ? "ok" : "info"}>
                  {proposalsQuery.isError ? "unavailable" : proposalsQuery.data ? "loaded" : "loading"}
                </Badge>
              </div>
              <label className="mt-4 block">
                <span className={OM_LABEL}>Filter</span>
                <input
                  className={OM_INPUT}
                  value={filter}
                  onChange={(event) => setFilter(event.target.value)}
                  placeholder="profile, title, author, or digest"
                />
              </label>
            </div>
            <div className="max-h-[560px] overflow-auto">
              {visibleProposals.length === 0 ? (
                <div className="px-4 py-8 text-sm font-semibold text-[var(--om-text-muted)]">
                  {proposalsQuery.isPending
                    ? "Loading saved change plans…"
                    : proposalsQuery.isError
                      ? "Saved change plans are unavailable."
                      : filter.trim()
                        ? "No plans match this filter."
                        : "No saved change plans."}
                </div>
              ) : (
                visibleProposals.map((proposal) => (
                  <button
                    key={proposal.id}
                    type="button"
                    className={cn(
                      "block min-h-11 w-full border-b border-[var(--om-border)] px-4 py-3 text-left transition-colors hover:bg-[var(--om-surface-muted)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[var(--om-focus)]",
                      selected?.id === proposal.id
                        ? "bg-[color-mix(in_srgb,var(--om-gold)_12%,transparent)]"
                        : "bg-transparent"
                    )}
                    aria-pressed={selected?.id === proposal.id}
                    onClick={() => setSelectedId(proposal.id)}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="min-w-0 truncate text-sm font-semibold text-[var(--om-text-bright)]">
                        {proposal.title}
                      </span>
                      <Badge tone={proposalLevelTone(proposal)}>{proposal.profile}</Badge>
                    </div>
                    <div className="mt-2 flex flex-wrap gap-2 text-xs font-semibold text-[var(--om-text-muted)]">
                      <span>{proposal.author}</span>
                      <span>{formatNumber(proposal.statement_count)} stmt</span>
                      <span>{proposal.updated_at}</span>
                      {selectedOutsideFilter && selected?.id === proposal.id ? (
                        <span>selected outside filter</span>
                      ) : null}
                    </div>
                  </button>
                ))
              )}
            </div>
            {proposalsCursor || proposalsNextCursor ? (
              <ListPager
                atStart={!proposalsCursor}
                onFirst={() => setProposalsCursor(undefined)}
                onNext={
                  proposalsNextCursor
                    ? () => setProposalsCursor(proposalsNextCursor)
                    : undefined
                }
                pending={proposalsQuery.isPending}
              />
            ) : null}
          </ConsolePanel>
          <SourceHistoryPanel
            snapshots={snapshots}
            pending={sourceHistoryQuery.isPending || revertMutation.isPending}
            blocked={sourceHistoryQuery.isError}
            onDraftRevert={(snapshot) =>
              revertMutation.mutate({ snapshot, authority: sessionAuthority ?? "" })
            }
            atStart={!historyCursor}
            onFirst={() => setHistoryCursor(undefined)}
            onNext={
              historyNextCursor ? () => setHistoryCursor(historyNextCursor) : undefined
            }
            hasPager={Boolean(historyCursor || historyNextCursor)}
          />
          <SchemaDiffPanel
            session={authoritative.session}
            profile={profileAvailable ? profile : ""}
            onDrafted={(proposal, response) => {
              setLastResult(reviewSuccess("Migration draft", response));
              setSelectedId(proposal.id);
              setProposalsCursor(undefined);
              queryClient.invalidateQueries({ queryKey: ["change-proposals"] });
            }}
          />
        </div>

        <div className="space-y-4">
          {config.error instanceof Error ? (
            <QueryErrorNotice
              title="Review profiles are unavailable"
              error={config.error}
              retryLabel="Retry profiles"
              onRetry={() => void config.refetch()}
            />
          ) : null}
          <ConsolePanel className="p-4">
            <div className="mb-4">
              <h3 className="text-base font-semibold text-[var(--om-text-bright)]">Create a saved change plan</h3>
              <p className="mt-1 text-sm leading-6 text-[var(--om-text-muted)]">
                Plans created in this browser are recorded as human-authored. Saving a plan does not run SQL.
              </p>
            </div>
            <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_180px]">
              <label className="block">
                <span className={OM_LABEL}>Title</span>
                <input
                  className={OM_INPUT}
                  value={title}
                  onChange={(event) => setTitle(event.target.value)}
                />
              </label>
              <label className="block">
                <span className={OM_LABEL}>Profile</span>
                <select
                  className={OM_INPUT}
                  value={profile}
                  onChange={(event) => setProfile(event.target.value)}
                >
                  <option value="">Select a profile</option>
                  {reviewProfiles.map((item) => (
                    <option key={item.name} value={item.name}>
                      {item.name}{item.is_default ? " (default)" : ""}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <label className="mt-4 block">
              <span className={OM_LABEL}>SQL</span>
              <textarea
                className={cn(OM_TEXTAREA, "min-h-[220px]")}
                spellCheck={false}
                value={sqlTemplate}
                onChange={(event) => setSqlTemplate(event.target.value)}
              />
            </label>
            <label className="mt-4 block">
              <span className={OM_LABEL}>Bind values (JSON array)</span>
              <textarea
                className={cn(OM_TEXTAREA, "min-h-[92px] leading-5")}
                spellCheck={false}
                value={bindsJson}
                onChange={(event) => setBindsJson(event.target.value)}
              />
            </label>
            <div className="mt-4 flex flex-wrap items-center gap-3">
              <p className="max-w-xl text-sm leading-6 text-[var(--om-text-muted)]">
                The server classifies the SQL and assigns Read, DML, or DDL. This cannot be
                overridden in the browser.
              </p>
              <label className={OM_CHECK_LABEL}>
                <input
                  className={OM_CHECKBOX}
                  type="checkbox"
                  checked={draftCommit}
                  onChange={(event) => setDraftCommit(event.target.checked)}
                />
                Commit when applied
              </label>
              <label className={OM_CHECK_LABEL}>
                <input
                  className={OM_CHECKBOX}
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
                onClick={() => draftMutation.mutate(sessionAuthority ?? "")}
              >
                <GitPullRequest className="size-4" aria-hidden="true" />
                Save plan
              </Button>
            </div>
          </ConsolePanel>

          <ConsolePanel className="p-4">
            <div>
              <h3 className="text-base font-semibold text-[var(--om-text-bright)]">Review and apply</h3>
              <p className="mt-1 text-sm leading-6 text-[var(--om-text-muted)]">
                Apply is bound to a database connection whose active profile matches the saved plan.
              </p>
            </div>
            <div className="mt-4 grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              {stateful ? (
                <label className="block">
                  <span className={OM_LABEL}>Agent session</span>
                  <select
                    className={OM_INPUT}
                    value={selectedLane ? laneOptionValue(selectedLane) : ""}
                    onChange={(event) =>
                      selectReviewLane(laneIdentityFromOption(lanes, event.target.value))
                    }
                    disabled={activeLanes.isPending || lanes.length === 0}
                  >
                    <option value="">Select a session</option>
                    {lanes.map((lane) => (
                      <option key={`${lane.lane_id}:${lane.generation}`} value={laneOptionValue(lane)}>
                        {laneOptionLabel(lane)}
                      </option>
                    ))}
                  </select>
                </label>
              ) : (
                <div>
                  <span className={OM_LABEL}>Connection mode</span>
                  <p className={cn(OM_INPUT, "flex items-center font-semibold")}>Direct server profile</p>
                </div>
              )}
              <div className="grid grid-cols-2 gap-2">
                <ConsoleFact label="Plan profile" value={selectedDetail?.profile ?? "none"} mono />
                <ConsoleFact label="Connection profile" value={laneReady ? selectedLaneProfile : "select a session"} mono />
              </div>
            </div>
            {selected ? (
              selectedDetail ? (
                <ProposalStatementTable proposal={selectedDetail} />
              ) : (
                <p className="mt-4 text-sm font-semibold text-[var(--om-text-muted)]">
                  {detailQuery.isError
                    ? "statement detail unavailable"
                    : "loading statement detail…"}
                </p>
              )
            ) : null}
            {!selected ? (
              unresolvedSelectedId ? (
                <ErrorNotice message={`Change plan ${selectedId} was not found. No plan is selected and Apply remains disabled.`} />
              ) : (
                <p className="mt-4 text-sm text-[var(--om-text-muted)]">Select a saved change plan to review it.</p>
              )
            ) : detailQuery.isError ? (
              <ErrorNotice message="The exact statement detail is unavailable, so this plan cannot be applied." />
            ) : null}
            {reviewLane && selectedLaneCapabilities && !profileMatches ? (
              <ErrorNotice
                message={`This plan targets ${selectedDetail?.profile ?? "an unknown profile"}, but the selected session uses ${selectedLaneProfile}. Choose a matching session.`}
              />
            ) : null}
            {hasDdl ? (
              <ErrorNotice message="DDL plans are preview/export only in the browser. Apply them through an approved non-browser client with the required profile level." />
            ) : null}
            {hasHiddenBinds ? (
              <ErrorNotice message="This plan contains bind values that the redacted review record does not expose. Browser apply is disabled because those values cannot be reviewed here." />
            ) : null}
            {writeStatements.length > 1 ? (
              <ErrorNotice message="This plan contains multiple writes. Browser apply is disabled because confirmations are single-use and sequential execution could partially commit." />
            ) : null}
            {needsConfirm ? (
              // The grant auto-fills from the preview, so a non-empty confirm
              // field is not a deliberate act. Name what is about to change and
              // make the operator acknowledge it — the same pattern Config uses
              // for a sensitive draft. The server-side grant is still the gate.
              <label className={cn(OM_CHECK_LABEL, "mt-4")}>
                <input
                  className={OM_CHECKBOX}
                  type="checkbox"
                  checked={applyAcknowledged}
                  onChange={(event) => setApplyAcknowledged(event.target.checked)}
                />
                I reviewed the full {applyDangerSummary} statement, bind count, and saved commit setting for {selected?.profile ?? "this profile"}
              </label>
            ) : null}
            <div className="mt-4 flex flex-wrap items-center gap-3">
              {needsConfirm ? (
                <Button
                  type="button"
                  variant="secondary"
                  disabled={!canPreviewSelected}
                  onClick={previewSelectedChange}
                >
                  <Search className="size-4" aria-hidden="true" />
                  Preview selected change
                </Button>
              ) : null}
              <Button
                type="button"
                variant="primary"
                disabled={!canApply}
                onClick={applySelectedChange}
              >
                <CheckCircle2 className="size-4" aria-hidden="true" />
                Apply selected plan
              </Button>
              <Badge tone={confirm ? "ok" : needsConfirm ? "off" : "neutral"}>
                {confirm ? "confirmation ready" : needsConfirm ? "preview required" : "read-only plan"}
              </Badge>
              <Badge tone={session.status === "success" ? "ok" : session.status === "error" ? "warn" : "info"}>
                {session.status === "success" ? "paired" : session.status === "error" ? "blocked" : "pairing"}
              </Badge>
            </div>
          </ConsolePanel>

          <ReviewResultPanel
            result={lastResult}
            pending={draftMutation.isPending || applyMutation.isPending || previewSelectedMutation.isPending}
          />

          <details className="rounded-lg border border-[var(--om-border)] bg-[var(--om-surface)] p-4">
            <summary className="cursor-pointer font-semibold text-[var(--om-text-bright)]">
              Edition-based redefinition
            </summary>
            <div className="mt-4"><EditionTimelinePanel /></div>
          </details>
        </div>
      </div>
    </PageFrame>
  );
}

/**
 * The edition linear timeline (Arc D) on the Reviews board.
 *
 * Reads /operator/v1/edition-proposals and renders the base→child edition chain
 * as a straight timeline. A non-linear shape (a base with two children) is
 * flagged, never drawn as a line.
 */
export function authoritativeEditionData(
  status: DashboardQueryStatus,
  response: OperatorResponse<EditionProposalsData> | undefined
): EditionProposalsData | null {
  return authoritativeQueryData(status, response)?.data ?? null;
}

function EditionTimelinePanel(): React.ReactElement {
  const EditionTimeline = OMCP_SKIN.renderers.EditionTimeline;
  const editions = useQuery({
    queryKey: ["edition-proposals"],
    queryFn: fetchEditionProposals
  });
  const editionData = authoritativeEditionData(editions.status, editions.data);
  const model = toEditionTimelineViewModel(parseEditionProposals(editionData));
  return (
    <div className="space-y-3" data-testid="edition-timeline-panel">
      <p className="text-sm leading-6 text-[var(--om-text-muted)]">
        Optional Oracle Edition-Based Redefinition proposals for profiles that use editions.
      </p>
      {editionData ? (
        <EditionTimeline model={model} />
      ) : (
        <p className="text-sm text-[var(--om-text-muted)]">
          {editions.isPending
            ? "Loading edition proposals…"
            : editions.isError
              ? "Edition proposals are unavailable."
              : "No edition proposals are available."}
        </p>
      )}
    </div>
  );
}

function ListPager({
  atStart,
  onFirst,
  onNext,
  pending
}: {
  atStart: boolean;
  onFirst: () => void;
  onNext?: () => void;
  pending: boolean;
}): React.ReactElement {
  return (
    <div className="flex items-center justify-between gap-3 border-t border-[var(--om-border)] px-4 py-3">
      <Button type="button" variant="secondary" disabled={atStart || pending} onClick={onFirst}>
        First page
      </Button>
      <Button
        type="button"
        variant="secondary"
        disabled={!onNext || pending}
        onClick={() => onNext?.()}
      >
        Next page
      </Button>
    </div>
  );
}

function ProposalStatementTable({ proposal }: { proposal: ChangeProposalView }): React.ReactElement {
  return (
    <div
      className="mt-4 overflow-x-auto rounded-md border border-[var(--om-border)]"
      role="region"
      aria-label="Statements in selected change plan"
      tabIndex={0}
    >
      <table className="w-full min-w-[760px] border-collapse text-sm">
        <caption className="sr-only">Exact statements in the selected saved change plan</caption>
        <thead className="bg-[var(--om-surface-muted)] text-left text-2xs uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
          <tr>
            <th className="px-3 py-2 font-semibold">Unit</th>
            <th className="px-3 py-2 font-semibold">Exact SQL and digest</th>
            <th className="px-3 py-2 font-semibold">Required permission</th>
            <th className="px-3 py-2 font-semibold">Saved behavior</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--om-border)]">
          {proposal.statements.map((statement) => (
            <tr key={statement.id}>
              <td className="px-3 py-2">
                <Badge tone={statement.unit === "ddl" ? "warn" : statement.unit === "dml" ? "info" : "ok"}>
                  {statement.unit}
                </Badge>
              </td>
              <td className="max-w-[520px] px-3 py-2">
                <pre className="whitespace-pre-wrap break-words font-mono text-xs text-[var(--om-text-bright)]">{statement.sql_template}</pre>
                <p className="mt-2 break-all font-mono text-xs text-[var(--om-text-muted)]">SHA-256 {statement.sql_sha256}</p>
              </td>
              <td className="px-3 py-2 font-semibold text-[var(--om-text)]">
                {statement.draft_verdict.required_level ?? "none"}
              </td>
              <td className="px-3 py-2 text-xs text-[var(--om-text)]">
                <p>{formatNumber(statement.bind_count)} bind value(s)</p>
                <p className="mt-1">{statement.commit ? "commit" : "rollback after execution"}</p>
                <p className="mt-1">{statement.capture_dbms_output ? "capture DBMS_OUTPUT" : "no DBMS_OUTPUT"}</p>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function SourceHistoryPanel({
  snapshots,
  pending,
  blocked,
  onDraftRevert,
  atStart,
  onFirst,
  onNext,
  hasPager
}: {
  snapshots: SourceSnapshotView[];
  pending: boolean;
  blocked: boolean;
  onDraftRevert: (snapshot: SourceSnapshotView) => void;
  atStart: boolean;
  onFirst: () => void;
  onNext?: () => void;
  hasPager: boolean;
}): React.ReactElement {
  return (
    <ConsolePanel>
      <div className="flex items-center justify-between gap-3 border-b border-[var(--om-border)] px-4 py-3">
        <div className="min-w-0">
          <h3 className="flex items-center gap-2 text-base font-semibold text-[var(--om-text-bright)]">
            <FileClock className="size-4" aria-hidden="true" />
            Source history
          </h3>
          <p className="mt-1 truncate text-sm text-[var(--om-text-muted)]">
            {pending ? "loading" : `${formatNumber(snapshots.length)} snapshots`}
          </p>
        </div>
        <Badge tone={blocked ? "warn" : snapshots.length ? "ok" : "off"}>
          {blocked ? "blocked" : snapshots.length ? "ready" : "empty"}
        </Badge>
      </div>
      <div className="max-h-[320px] overflow-auto">
        {snapshots.length === 0 ? (
          <div className="px-4 py-6 text-sm font-semibold text-[var(--om-text-muted)]">
            {pending ? "Loading source snapshots…" : blocked ? "Source history is unavailable." : "No source snapshots have been recorded."}
          </div>
        ) : (
          snapshots.map((snapshot) => (
            <div
              key={`${snapshot.id}-${snapshot.statement_id}`}
              className="grid gap-3 border-b border-[var(--om-border)] px-4 py-3"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="truncate text-sm font-semibold text-[var(--om-text-bright)]">
                    {snapshot.owner}.{snapshot.name}
                  </p>
                  <div className="mt-2 flex flex-wrap gap-2 text-xs font-semibold text-[var(--om-text-muted)]">
                    <span>{snapshot.object_type}</span>
                    <span>{snapshot.profile}</span>
                    <span>{formatNumber(snapshot.source_lines)} lines</span>
                    <span>{snapshot.created_at}</span>
                  </div>
                </div>
                <Button
                  type="button"
                  variant="secondary"
                  disabled={pending || blocked}
                  onClick={() => onDraftRevert(snapshot)}
                  title="Create a restore plan without changing the database"
                >
                  <RotateCcw className="size-4" aria-hidden="true" />
                  Create restore plan
                </Button>
              </div>
              <p className="truncate font-mono text-xs text-[var(--om-text-muted)]">
                {snapshot.source_sha256}
              </p>
            </div>
          ))
        )}
      </div>
      {hasPager ? (
        <ListPager atStart={atStart} onFirst={onFirst} onNext={onNext} pending={pending} />
      ) : null}
    </ConsolePanel>
  );
}

export interface SchemaDiffPreviewBinding<T> {
  inputIdentity: string;
  data: T;
}

export function schemaDiffInputIdentity(
  title: string,
  beforeJson: string,
  afterJson: string
): string {
  return JSON.stringify([title, beforeJson, afterJson]);
}

export function currentSchemaDiffPreview<T>(
  binding: SchemaDiffPreviewBinding<T> | null,
  inputIdentity: string
): T | null {
  return binding?.inputIdentity === inputIdentity ? binding.data : null;
}

function SchemaDiffPanel({
  session,
  profile,
  onDrafted
}: {
  session: DashboardSession | null;
  profile: string;
  onDrafted: (proposal: ChangeProposalView, response: unknown) => void;
}): React.ReactElement {
  const [title, setTitle] = React.useState("Schema snapshot comparison");
  const [beforeJson, setBeforeJson] = React.useState(EMPTY_SCHEMA_SNAPSHOT);
  const [afterJson, setAfterJson] = React.useState(EMPTY_SCHEMA_SNAPSHOT);
  const [previewBinding, setPreviewBinding] = React.useState<
    SchemaDiffPreviewBinding<SchemaDiffExportData> | null
  >(null);
  const [lastError, setLastError] = React.useState<string | null>(null);
  const inputIdentity = schemaDiffInputIdentity(title, beforeJson, afterJson);
  const sessionAuthority = dashboardAuthorityIdentity(session ?? undefined);
  const authorityInputIdentity = JSON.stringify([sessionAuthority, inputIdentity]);
  const preview = currentSchemaDiffPreview(previewBinding, authorityInputIdentity);

  const previewMutation = useMutation({
    mutationFn: async (input: {
      title: string;
      beforeJson: string;
      afterJson: string;
      inputIdentity: string;
    }) => {
      if (!session) {
        throw new Error("dashboard session is not ready");
      }
      const before = parseSchemaSnapshotInput(input.beforeJson);
      const after = parseSchemaSnapshotInput(input.afterJson);
      return previewSchemaDiff(session, before, after, input.title);
    },
    onSuccess: (response, input) => {
      setPreviewBinding({ inputIdentity: input.inputIdentity, data: response.data });
      setLastError(null);
    },
    onError: (error) => {
      setLastError(error instanceof Error ? error.message : "schema diff preview failed");
    }
  });

  const draftMutation = useMutation({
    mutationFn: async () => {
      if (!session) {
        throw new Error("dashboard session is not ready");
      }
      if (!preview) {
        throw new Error("preview a schema diff first");
      }
      if (preview.proposal_statements.length === 0) {
        throw new Error("no executable migration steps to draft");
      }
      return draftChangeProposal(session, {
        profile: profile.trim(),
        author: "human",
        title: preview.title,
        statements: preview.proposal_statements
      });
    },
    onSuccess: (response) => {
      setLastError(null);
      queryClient.invalidateQueries({ queryKey: ["change-proposals"] });
      onDrafted(response.data.proposal, response);
    },
    onError: (error) => {
      setLastError(error instanceof Error ? error.message : "migration draft failed");
    }
  });
  const purgeSchemaDiffAuthorityState = React.useCallback(() => {
    setPreviewBinding(null);
    setLastError(null);
    previewMutation.reset();
    draftMutation.reset();
  }, [draftMutation.reset, previewMutation.reset]);
  useDashboardAuthorityPurge(sessionAuthority, purgeSchemaDiffAuthorityState);

  const busy = previewMutation.isPending || draftMutation.isPending;
  const canPreview = Boolean(session) && !busy;
  const canDraft =
    Boolean(session && profile.trim() && preview && preview.proposal_statements.length > 0) && !busy;

  return (
    <ConsolePanel>
      <div className="flex items-center justify-between gap-3 border-b border-[var(--om-border)] px-4 py-3">
        <div className="min-w-0">
          <h3 className="flex items-center gap-2 text-base font-semibold text-[var(--om-text-bright)]">
            <SquarePen className="size-4" aria-hidden="true" />
            Compare schema snapshots
          </h3>
          <p className="mt-1 truncate text-sm text-[var(--om-text-muted)]">
            {preview ? `${formatNumber(preview.summary.migration_steps)} steps` : "pasted JSON snapshots"}
          </p>
        </div>
        <Badge tone={preview ? "ok" : lastError ? "warn" : "off"}>
          {preview ? "previewed" : lastError ? "blocked" : "idle"}
        </Badge>
      </div>
      <div className="grid gap-3 p-4">
        <p className="text-sm leading-6 text-[var(--om-text-muted)]">
          Paste exported snapshots to compare them. This does not read either snapshot from the database. Generated DDL is preview/export only in the browser.
        </p>
        <label className="block">
          <span className={OM_LABEL}>Title</span>
          <input
            className={OM_INPUT}
            value={title}
            onChange={(event) => setTitle(event.target.value)}
          />
        </label>
        <div className="grid gap-3 lg:grid-cols-2">
          <label className="block">
            <span className={OM_LABEL}>Current snapshot JSON</span>
            <textarea
              className={cn(OM_TEXTAREA, "min-h-[180px] text-xs leading-5")}
              aria-label="schema diff before snapshot"
              spellCheck={false}
              value={beforeJson}
              onChange={(event) => setBeforeJson(event.target.value)}
            />
          </label>
          <label className="block">
            <span className={OM_LABEL}>Desired snapshot JSON</span>
            <textarea
              className={cn(OM_TEXTAREA, "min-h-[180px] text-xs leading-5")}
              aria-label="schema diff after snapshot"
              spellCheck={false}
              value={afterJson}
              onChange={(event) => setAfterJson(event.target.value)}
            />
          </label>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            type="button"
            variant="secondary"
            disabled={!canPreview}
            onClick={() =>
              previewMutation.mutate({
                title,
                beforeJson,
                afterJson,
                inputIdentity: authorityInputIdentity
              })
            }
          >
            <RefreshCcw className="size-4" aria-hidden="true" />
            Compare snapshots
          </Button>
          <Button
            type="button"
            variant="secondary"
            disabled={!preview || busy}
            onClick={() =>
              preview
                ? downloadTextFile(`${safeFilename(preview.title)}.sql`, preview.migration_script)
                : undefined
            }
          >
            <Download className="size-4" aria-hidden="true" />
            Export SQL
          </Button>
          <Button type="button" variant="primary" disabled={!canDraft} onClick={() => draftMutation.mutate()}>
            <GitPullRequest className="size-4" aria-hidden="true" />
            Save DDL plan
          </Button>
          {lastError ? (
            <Badge tone="warn" role="alert" className="max-w-full whitespace-normal break-all">
              {lastError}
            </Badge>
          ) : null}
        </div>
        {preview ? <SchemaDiffSummaryPanel preview={preview} /> : null}
      </div>
    </ConsolePanel>
  );
}

function SchemaDiffSummaryPanel({ preview }: { preview: SchemaDiffExportData }): React.ReactElement {
  return (
    <div className="grid gap-3">
      <div className="grid gap-2 sm:grid-cols-3">
        <ConsoleFact label="Added" value={preview.summary.added} />
        <ConsoleFact label="Changed" value={preview.summary.changed} />
        <ConsoleFact label="Dropped" value={preview.summary.dropped} />
      </div>
      <div className="grid gap-3 xl:grid-cols-[minmax(0,0.8fr)_minmax(0,1.2fr)]">
        <SchemaDiffObjectList title="Objects" objects={schemaDiffObjects(preview)} />
        <SchemaDiffStepTable steps={preview.migration_steps} />
      </div>
      <div className="grid gap-2 rounded-md border border-[var(--om-border)] bg-[var(--om-surface-muted)] p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="text-sm font-semibold text-[var(--om-text)]">Migration Script</span>
          <Badge tone="info">{shortHash(preview.migration_script_sha256)}</Badge>
        </div>
        <pre className={cn(OM_CODE, "max-h-[240px]")}>{preview.migration_script}</pre>
      </div>
    </div>
  );
}

function SchemaDiffObjectList({
  title,
  objects
}: {
  title: string;
  objects: SchemaDiffObjectView[];
}): React.ReactElement {
  return (
    <div className="overflow-hidden rounded-md border border-[var(--om-border)]">
      <div className="border-b border-[var(--om-border)] bg-[var(--om-surface-muted)] px-3 py-2 text-sm font-semibold text-[var(--om-text)]">
        {title}
      </div>
      <div className="max-h-[260px] divide-y divide-[var(--om-border)] overflow-auto">
        {objects.length === 0 ? (
          <div className="px-3 py-4 text-sm font-semibold text-[var(--om-text-muted)]">
            No object changes
          </div>
        ) : (
          objects.map((object) => (
            <div key={`${object.kind}:${object.object_type}:${object.name}`} className="grid gap-1 px-3 py-2">
              <div className="flex flex-wrap items-center gap-2">
                <Badge tone={object.kind === "dropped" ? "warn" : object.kind === "added" ? "ok" : "info"}>
                  {object.kind}
                </Badge>
                <span className="min-w-0 truncate font-mono text-sm font-semibold text-[var(--om-text-bright)]">
                  {object.object_type} {object.name}
                </span>
              </div>
              <p className="truncate font-mono text-xs text-[var(--om-text-muted)]">
                {shortHash(object.ddl_sha256)} · {formatNumber(object.ddl_chars)} chars
              </p>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function SchemaDiffStepTable({ steps }: { steps: SchemaDiffStepView[] }): React.ReactElement {
  return (
    <div className="overflow-hidden rounded-md border border-[var(--om-border)]">
      <div className="border-b border-[var(--om-border)] bg-[var(--om-surface-muted)] px-3 py-2 text-sm font-semibold text-[var(--om-text)]">
        Migration Steps
      </div>
      <div className="overflow-x-auto" role="region" aria-label="Migration steps" tabIndex={0}>
        <table className="w-full min-w-[560px] border-collapse text-left text-sm">
          <caption className="sr-only">Migration steps generated from the schema comparison</caption>
          <thead className="bg-[var(--om-surface)] text-2xs uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
            <tr>
              <th className="px-3 py-2 font-semibold">#</th>
              <th className="px-3 py-2 font-semibold">Kind</th>
              <th className="px-3 py-2 font-semibold">Object</th>
              <th className="px-3 py-2 font-semibold">Gate</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--om-border)]">
            {steps.map((step) => (
              <tr key={`${step.order}:${step.object_type}:${step.name}`}>
                <td className="px-3 py-2 font-mono text-xs text-[var(--om-text-muted)]">
                  {step.order + 1}
                </td>
                <td className="px-3 py-2">
                  <Badge tone={step.kind === "manual_review" ? "warn" : "info"}>{step.kind}</Badge>
                </td>
                <td className="px-3 py-2 font-mono text-xs font-semibold text-[var(--om-text-bright)]">
                  {step.object_type} {step.name}
                </td>
                <td className="px-3 py-2">
                  <Badge tone={step.executable ? "ok" : "warn"}>
                    {step.executable ? "proposal" : "review"}
                  </Badge>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function operatorOutcomeTone(
  state: OperatorOutcomeState
): "ok" | "warn" | "info" | "neutral" {
  switch (state) {
    case "success":
      return "ok";
    case "refused":
      return "info";
    case "partial":
      return "neutral";
    case "failed":
      return "warn";
  }
}

export function OperatorOutcomeNotice({
  outcome
}: {
  outcome: OperatorOutcome;
}): React.ReactElement {
  const tone = operatorOutcomeTone(outcome.state);
  const stateClass = {
    success:
      "border-[color-mix(in_srgb,var(--om-sage)_45%,transparent)] bg-[color-mix(in_srgb,var(--om-sage)_12%,transparent)] text-[var(--om-sage)]",
    refused:
      "border-[color-mix(in_srgb,var(--om-gold)_45%,transparent)] bg-[color-mix(in_srgb,var(--om-gold)_12%,transparent)] text-[var(--om-gold)]",
    partial:
      "border-[var(--om-border)] bg-[var(--om-surface-muted)] text-[var(--om-text-bright)]",
    failed:
      "border-[color-mix(in_srgb,var(--om-copper)_45%,transparent)] bg-[color-mix(in_srgb,var(--om-copper)_12%,transparent)] text-[var(--om-copper)]"
  }[outcome.state];
  return (
    <div
      className={cn("rounded-md border p-3", stateClass)}
      data-operator-outcome={outcome.state}
      data-outcome-tone={tone}
      role="status"
      aria-live="polite"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm font-semibold">{outcome.message}</p>
        <Badge tone={tone}>{outcome.state}</Badge>
      </div>
      {outcome.errorClass ? (
        <p className="mt-2 font-mono text-xs">{outcome.errorClass}</p>
      ) : null}
      {outcome.nextSteps.length > 0 ? (
        <div className="mt-3">
          <p className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)]">
            Next steps
          </p>
          <ul className="mt-1 list-disc space-y-1 pl-5 text-sm">
            {outcome.nextSteps.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ul>
        </div>
      ) : null}
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
    <ConsolePanel>
      <div className="flex items-center justify-between gap-3 border-b border-[var(--om-border)] px-4 py-3">
        <div className="min-w-0">
          <h3 className="flex items-center gap-2 text-base font-semibold text-[var(--om-text-bright)]">
            <Code2 className="size-4" aria-hidden="true" />
            Latest action
          </h3>
          <p className="mt-1 truncate text-sm text-[var(--om-text-muted)]">
            {pending ? "request in flight" : result ? result.label : "idle"}
          </p>
        </div>
        <Badge tone={pending ? "info" : result ? operatorOutcomeTone(result.state) : "off"}>
          {pending ? "running" : result?.state ?? "empty"}
        </Badge>
      </div>
      <div className="space-y-3 p-4">
        {result ? <OperatorOutcomeNotice outcome={result.outcome} /> : null}
        {result?.response ? (
          <details className="rounded-md border border-[var(--om-border)] p-3">
            <summary className="cursor-pointer text-sm font-semibold text-[var(--om-text)]">Technical response</summary>
            <pre className={cn(OM_CODE, "mt-3 max-h-[560px]")}>{prettyJson(result.response)}</pre>
          </details>
        ) : (
          <p className="text-sm text-[var(--om-text-muted)]">No review action has run yet.</p>
        )}
      </div>
    </ConsolePanel>
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

function parseSchemaSnapshotInput(text: string): SchemaSnapshotInput {
  const parsed = JSON.parse(text.trim()) as unknown;
  const candidate = Array.isArray(parsed) ? { objects: parsed } : parsed;
  if (!candidate || typeof candidate !== "object" || !Array.isArray((candidate as { objects?: unknown }).objects)) {
    throw new Error("schema snapshot must be an object with an objects array");
  }
  const objects = (candidate as { objects: unknown[] }).objects.map((item, index) => {
    if (!item || typeof item !== "object") {
      throw new Error(`schema snapshot object ${index + 1} must be an object`);
    }
    const object = item as Record<string, unknown>;
    return {
      object_type: requiredString(object.object_type, `objects[${index}].object_type`),
      name: requiredString(object.name, `objects[${index}].name`),
      ddl: requiredString(object.ddl, `objects[${index}].ddl`)
    };
  });
  return { objects };
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${field} must be a non-empty string`);
  }
  return value;
}

function schemaDiffObjects(preview: SchemaDiffExportData): SchemaDiffObjectView[] {
  return [...preview.diff.added, ...preview.diff.changed, ...preview.diff.dropped];
}

function downloadTextFile(filename: string, text: string): void {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function safeFilename(value: string): string {
  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return normalized || "schema-diff-migration";
}

function proposalSearchText(proposal: ChangeProposalListView): string {
  // The list projection omits sql_template bodies; search over the metadata and
  // the per-statement SQL digest instead. Full text is available in the detail
  // view fetched on selection.
  return [
    proposal.title,
    proposal.profile,
    proposal.author,
    proposal.id,
    ...proposal.statements.map((statement) => statement.sql_sha256)
  ]
    .join(" ")
    .toLowerCase();
}

function proposalLevelTone(
  proposal: ChangeProposalListView
): "neutral" | "ok" | "warn" | "off" | "info" {
  if (proposal.statements.some((statement) => statement.unit === "ddl")) {
    return "warn";
  }
  if (proposal.statements.some((statement) => statement.unit === "dml")) {
    return "info";
  }
  return "ok";
}

const workbenchModes: Array<{ id: WorkbenchMode; label: string }> = [
  { id: "classify_only", label: "Classify only" },
  { id: "read_query", label: "Read query" },
  { id: "dml_preview_confirm", label: "DML change" },
  { id: "ddl_plan_confirm", label: "DDL plan" }
];

type WorkbenchAction = "preview" | "read" | "rollback_preview" | "commit";

type WorkbenchSubmission = {
  kind: WorkbenchAction;
  identity: string;
  contextIdentity: string;
  sourceIdentity: string;
  authority: string;
  sql: string;
  mode: WorkbenchMode;
  lane?: OperatorLaneTarget;
  maxRows: number;
  confirm: string;
  captureDbmsOutput: boolean;
};

type WorkbenchIdeAction = "parse" | "analyze" | "lineage" | "lint" | "docs" | "impact";

type WorkbenchIdeSubmission = {
  kind: WorkbenchIdeAction;
  identity: string;
  contextIdentity: string;
  sourceIdentity: string;
  input: WorkbenchIdeRequestInput;
};

type WorkbenchResultBinding = {
  requestIdentity: string;
  contextIdentity: string;
  sourceIdentity: string;
};

type WorkbenchResult = {
  state: OperatorOutcomeState;
  label: string;
  response: OperatorResponse<WorkbenchActionData> | null;
  outcome: OperatorOutcome;
  binding: WorkbenchResultBinding;
};

export function workbenchSourceIdentity(source: string): string {
  return JSON.stringify([source]);
}

export function workbenchSourceIsDirty(
  source: string,
  lastSuccessfulSourceIdentity: string | null,
  seed = WORKBENCH_SQL_SEED
): boolean {
  if (source.trim().length === 0 || source === seed) {
    return false;
  }
  return workbenchSourceIdentity(source) !== lastSuccessfulSourceIdentity;
}

export function workbenchActionContextIdentity(input: {
  authority: string | null;
  source: string;
  mode: WorkbenchMode;
  lane?: OperatorLaneTarget;
  maxRows: number;
  captureDbmsOutput: boolean;
}): string {
  return JSON.stringify([
    input.authority,
    input.source,
    input.mode,
    input.lane?.laneId ?? "stateless",
    input.lane?.generation ?? 0,
    input.maxRows,
    input.captureDbmsOutput
  ]);
}

export function workbenchIdeInputIdentity(
  authority: string | null,
  input: WorkbenchIdeRequestInput
): string {
  return JSON.stringify([
    authority,
    input.source,
    input.lane?.laneId ?? "stateless",
    input.lane?.generation ?? 0,
    input.projectRoot,
    input.target,
    input.direction,
    input.maxDepth,
    input.changesetJson
  ]);
}

export function workbenchCompletionIsCurrent(
  binding: Pick<WorkbenchResultBinding, "requestIdentity" | "contextIdentity">,
  activeRequestIdentity: string | null,
  currentContextIdentity: string
): boolean {
  return (
    binding.requestIdentity === activeRequestIdentity &&
    binding.contextIdentity === currentContextIdentity
  );
}

export function workbenchRequestIdentity(
  contextIdentity: string,
  action: WorkbenchAction | WorkbenchIdeAction,
  generation: number
): string {
  return JSON.stringify([contextIdentity, action, generation]);
}

export function consumedWorkbenchConfirmationState(): { confirm: ""; acknowledged: false } {
  return { confirm: "", acknowledged: false };
}

function workbenchSuccess(
  label: string,
  response: OperatorResponse<WorkbenchActionData>,
  binding: WorkbenchResultBinding
): WorkbenchResult {
  const outcome = decodeOperatorOutcome(200, response);
  return { state: outcome.state, label, response, outcome, binding };
}

function workbenchFailure(
  label: string,
  error: unknown,
  fallback: string,
  binding: WorkbenchResultBinding
): WorkbenchResult {
  const outcome = operatorOutcomeFromError(error, fallback);
  return {
    state: outcome.state,
    label,
    response: operatorResponseFromError<WorkbenchActionData>(error),
    outcome,
    binding
  };
}

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
  error: string | null;
};

function WorkbenchRoutePage(): React.ReactElement {
  const config = useQuery({
    queryKey: ["operator-config"],
    queryFn: fetchOperatorConfig,
    staleTime: 30_000,
    retry: 1
  });
  const enabled =
    authoritativeQueryData(config.status, config.data)?.data.status.dashboard_workbench === true;

  if (!enabled) {
    return (
      <PageFrame
        title="SQL Workbench"
        eyebrow="Browser SQL"
        description="The server keeps browser-submitted SQL behind an explicit opt-in."
      >
        <Surface className="space-y-3 p-5" aria-busy={config.isPending}>
          <Badge tone={config.isError ? "warn" : config.isPending ? "info" : "off"}>
            {config.isError ? "setting unavailable" : config.isPending ? "checking setting" : "disabled"}
          </Badge>
          <h3 className="text-lg font-semibold text-[var(--om-text-bright)]">
            {config.isError
              ? "Browser SQL setting is unavailable"
              : config.isPending
                ? "Checking whether browser SQL is enabled…"
                : "Browser SQL is disabled on this server"}
          </h3>
          <p className="max-w-3xl text-sm leading-6 text-[var(--om-text)]">
            {config.isError
              ? "The dashboard could not verify the Workbench setting, so it is failing closed. Database Explorer remains available for governed metadata reads."
              : "Set [http].dashboard_workbench = true in Profiles & settings and restart the HTTP service to expose read, preview, and guarded DML controls. DDL and ADMIN actions remain blocked in the browser."}
          </p>
          {config.isError && config.error instanceof Error ? (
            <p className="text-sm text-[var(--om-text-muted)]">{config.error.message}</p>
          ) : null}
          {config.isError ? (
            <Button
              type="button"
              variant="secondary"
              disabled={config.isFetching}
              onClick={() => void config.refetch()}
            >
              <RefreshCcw className={config.isFetching ? "size-4 animate-spin" : "size-4"} aria-hidden="true" />
              {config.isFetching ? "Retrying setting" : "Retry setting"}
            </Button>
          ) : !config.isPending ? (
            <Link
              to="/config"
              className="inline-flex min-h-11 items-center rounded-md border border-[var(--om-control-border)] px-4 py-2 text-sm font-semibold text-[var(--om-text-bright)] hover:bg-[var(--om-surface-muted)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--om-focus)]"
            >
              Open Profiles &amp; settings
            </Link>
          ) : null}
        </Surface>
      </PageFrame>
    );
  }

  return <WorkbenchPage />;
}

function WorkbenchPage(): React.ReactElement {
  const [mode, setMode] = React.useState<WorkbenchMode>("read_query");
  const [sql, setSql] = React.useState(WORKBENCH_SQL_SEED);
  const [selectedLaneBinding, setSelectedLaneBinding] = React.useState<LaneIdentity | null>(null);
  const [confirm, setConfirm] = React.useState("");
  const [maxRows, setMaxRows] = React.useState(100);
  const [captureDbmsOutput, setCaptureDbmsOutput] = React.useState(false);
  const [lastResult, setLastResult] = React.useState<WorkbenchResult | null>(null);
  const [lastIdeResult, setLastIdeResult] = React.useState<WorkbenchResult | null>(null);
  const [showPlsqlTools, setShowPlsqlTools] = React.useState(false);
  const [projectRoot, setProjectRoot] = React.useState("");
  const [plsqlTarget, setPlsqlTarget] = React.useState("");
  const [lineageDirection, setLineageDirection] = React.useState<
    "upstream" | "downstream" | "bidirectional"
  >("bidirectional");
  const [lineageDepth, setLineageDepth] = React.useState(2);
  const [identifier, setIdentifier] = React.useState("");
  const [replacement, setReplacement] = React.useState("");
  const [lastSuccessfulSourceIdentity, setLastSuccessfulSourceIdentity] = React.useState<
    string | null
  >(null);
  // Only the operator's own SQL counts as unsaved work, never the opening seed.
  const sqlGuard = useUnsavedChangesGuard(
    workbenchSourceIsDirty(sql, lastSuccessfulSourceIdentity)
  );
  const [commitAcknowledged, setCommitAcknowledged] = React.useState(false);
  const session = useQuery({
    queryKey: ["dashboard-session"],
    queryFn: fetchDashboardSession,
    staleTime: 60_000,
    refetchInterval: 60_000,
    retry: 1
  });
  const sessionAuthority = dashboardAuthorityIdentity(
    session.status === "success" ? session.data : undefined
  );
  const [changesetJson, setChangesetJson] = React.useState(
    '{\n  "objects": [],\n  "unclassified_files": []\n}'
  );
  const sqlEditorRef = React.useRef<HTMLTextAreaElement | null>(null);

  const activeLanes = useQuery({
    queryKey: ["active-lanes"],
    queryFn: fetchActiveLanes,
    refetchInterval: 5_000
  });
  const lanes = activeLanes.status === "success" ? activeLanes.data.data.lanes : EMPTY_ACTIVE_LANES;
  const stateful = authoritativeServerMode(activeLanes.status, activeLanes.data) !== false;
  const laneSelection =
    stateful && activeLanes.status === "success"
      ? resolveExactLane(selectedLaneBinding, lanes)
      : { lane: null, invalidated: false };
  const selectedLane = laneSelection.lane ?? undefined;
  const workbenchLane = selectedLane ? laneIdentity(selectedLane) : undefined;
  const laneReady = activeLanes.status === "success" && (!stateful || Boolean(workbenchLane));
  React.useEffect(() => {
    if (laneSelection.invalidated) {
      setSelectedLaneBinding(null);
    }
  }, [laneSelection.invalidated]);
  const requestIdentity = workbenchActionContextIdentity({
    authority: sessionAuthority,
    source: sql,
    mode,
    lane: workbenchLane,
    maxRows,
    captureDbmsOutput
  });
  const requestIdentityRef = React.useRef(requestIdentity);
  const activeActionIdentityRef = React.useRef<string | null>(null);
  const actionRequestGenerationRef = React.useRef(0);
  const confirmationRef = React.useRef(confirm);
  const consumeWorkbenchConfirmation = React.useCallback(() => {
    const consumed = consumedWorkbenchConfirmationState();
    confirmationRef.current = consumed.confirm;
    setConfirm(consumed.confirm);
    setCommitAcknowledged(consumed.acknowledged);
  }, []);
  // An acknowledgement is about this exact statement on this exact lane. Edit
  // either and it must be re-earned, never inherited by different SQL.
  React.useLayoutEffect(() => {
    requestIdentityRef.current = requestIdentity;
    activeActionIdentityRef.current = null;
    consumeWorkbenchConfirmation();
    setLastResult(null);
  }, [consumeWorkbenchConfirmation, requestIdentity]);

  const ideInput: WorkbenchIdeRequestInput = {
    source: sql,
    lane: workbenchLane,
    projectRoot,
    target: plsqlTarget,
    direction: lineageDirection,
    maxDepth: lineageDepth,
    changesetJson
  };
  const ideInputIdentity = workbenchIdeInputIdentity(sessionAuthority, ideInput);
  const ideInputIdentityRef = React.useRef(ideInputIdentity);
  const activeIdeIdentityRef = React.useRef<string | null>(null);
  const ideRequestGenerationRef = React.useRef(0);
  React.useLayoutEffect(() => {
    ideInputIdentityRef.current = ideInputIdentity;
    activeIdeIdentityRef.current = null;
    setLastIdeResult(null);
  }, [ideInputIdentity]);

  const action = useMutation({
    mutationFn: async (submission: WorkbenchSubmission) => {
      if (
        !session.data ||
        submission.authority !== sessionAuthority ||
        !workbenchCompletionIsCurrent(
          { requestIdentity: submission.identity, contextIdentity: submission.contextIdentity },
          activeActionIdentityRef.current,
          requestIdentityRef.current
        ) ||
        (stateful && !submission.lane)
      ) {
        throw new Error("dashboard session is not ready");
      }
      const request = {
        sql: submission.sql,
        mode: submission.mode,
        lane: submission.lane
      };
      if (submission.kind === "preview") {
        return previewWorkbenchSql(session.data, request);
      }
      if (submission.kind === "read") {
        return readWorkbenchSql(session.data, { ...request, maxRows: submission.maxRows });
      }
      return executeWorkbenchSql(session.data, {
        ...request,
        commit: submission.kind === "commit",
        confirm: submission.confirm,
        captureDbmsOutput: submission.captureDbmsOutput
      });
    },
    onMutate: () => {
      consumeWorkbenchConfirmation();
      setLastResult(null);
    },
    onSuccess: (response, submission) => {
      const binding: WorkbenchResultBinding = {
        requestIdentity: submission.identity,
        contextIdentity: submission.contextIdentity,
        sourceIdentity: submission.sourceIdentity
      };
      if (
        !workbenchCompletionIsCurrent(
          binding,
          activeActionIdentityRef.current,
          requestIdentityRef.current
        )
      ) {
        return;
      }
      setLastResult(workbenchSuccess(actionLabel(submission.kind), response, binding));
      setLastSuccessfulSourceIdentity(submission.sourceIdentity);
      if (submission.kind === "commit") {
        clearExplorerMetadataCache();
        queryClient.invalidateQueries({ queryKey: ["explorer"] });
      }
      const nextConfirm = confirmationFromResponse(response);
      if (
        submission.kind === "preview" &&
        nextConfirm &&
        submission.identity === requestIdentityRef.current
      ) {
        confirmationRef.current = nextConfirm;
        setConfirm(nextConfirm);
      }
    },
    onError: (error, submission) => {
      const binding: WorkbenchResultBinding = {
        requestIdentity: submission.identity,
        contextIdentity: submission.contextIdentity,
        sourceIdentity: submission.sourceIdentity
      };
      if (
        !workbenchCompletionIsCurrent(
          binding,
          activeActionIdentityRef.current,
          requestIdentityRef.current
        )
      ) {
        return;
      }
      setLastResult(
        workbenchFailure(actionLabel(submission.kind), error, "operator action failed", binding)
      );
    }
  });

  const submitAction = (kind: WorkbenchAction): void => {
    actionRequestGenerationRef.current += 1;
    const identity = workbenchRequestIdentity(
      requestIdentity,
      kind,
      actionRequestGenerationRef.current
    );
    const submission: WorkbenchSubmission = {
      kind,
      identity,
      contextIdentity: requestIdentity,
      sourceIdentity: workbenchSourceIdentity(sql),
      authority: sessionAuthority ?? "",
      sql,
      mode,
      lane: workbenchLane,
      maxRows,
      confirm: confirmationRef.current,
      captureDbmsOutput
    };
    activeActionIdentityRef.current = identity;
    consumeWorkbenchConfirmation();
    action.mutate(submission);
  };

  const ideAction = useMutation({
    mutationFn: async (submission: WorkbenchIdeSubmission) => {
      if (
        !session.data ||
        !workbenchCompletionIsCurrent(
          { requestIdentity: submission.identity, contextIdentity: submission.contextIdentity },
          activeIdeIdentityRef.current,
          ideInputIdentityRef.current
        ) ||
        (stateful && !submission.input.lane)
      ) {
        throw new Error("dashboard session is not ready");
      }
      const request = workbenchIdeRequest(submission.kind, submission.input);
      return runWorkbenchPlsqlTool(session.data, request);
    },
    onMutate: () => {
      setLastIdeResult(null);
    },
    onSuccess: (response, submission) => {
      const binding: WorkbenchResultBinding = {
        requestIdentity: submission.identity,
        contextIdentity: submission.contextIdentity,
        sourceIdentity: submission.sourceIdentity
      };
      if (
        !workbenchCompletionIsCurrent(
          binding,
          activeIdeIdentityRef.current,
          ideInputIdentityRef.current
        )
      ) {
        return;
      }
      setLastIdeResult(workbenchSuccess(ideActionLabel(submission.kind), response, binding));
    },
    onError: (error, submission) => {
      const binding: WorkbenchResultBinding = {
        requestIdentity: submission.identity,
        contextIdentity: submission.contextIdentity,
        sourceIdentity: submission.sourceIdentity
      };
      if (
        !workbenchCompletionIsCurrent(
          binding,
          activeIdeIdentityRef.current,
          ideInputIdentityRef.current
        )
      ) {
        return;
      }
      setLastIdeResult(
        workbenchFailure(
          ideActionLabel(submission.kind),
          error,
          "PL/SQL analysis failed",
          binding
        )
      );
    }
  });
  const submitIdeAction = (kind: WorkbenchIdeAction): void => {
    ideRequestGenerationRef.current += 1;
    const identity = workbenchRequestIdentity(
      ideInputIdentity,
      kind,
      ideRequestGenerationRef.current
    );
    activeIdeIdentityRef.current = identity;
    ideAction.mutate({
      kind,
      identity,
      contextIdentity: ideInputIdentity,
      sourceIdentity: workbenchSourceIdentity(sql),
      input: { ...ideInput }
    });
  };
  const purgeWorkbenchAuthorityState = React.useCallback(() => {
    activeActionIdentityRef.current = null;
    activeIdeIdentityRef.current = null;
    consumeWorkbenchConfirmation();
    setLastResult(null);
    setLastIdeResult(null);
    setLastSuccessfulSourceIdentity(null);
    action.reset();
    ideAction.reset();
  }, [action.reset, consumeWorkbenchConfirmation, ideAction.reset]);
  useDashboardAuthorityPurge(sessionAuthority, purgeWorkbenchAuthorityState);

  const canSubmit =
    sql.trim().length > 0 &&
    laneReady &&
    session.status === "success" &&
    !action.isPending &&
    !ideAction.isPending;
  const canRunIde =
    sql.trim().length > 0 &&
    laneReady &&
    session.status === "success" &&
    !ideAction.isPending &&
    !action.isPending;
  const confirmReady =
    confirm.trim().length > 0 && requestIdentityRef.current === requestIdentity;
  const sessionTone = session.status === "success" ? "ok" : session.status === "error" ? "warn" : "info";
  const visibleWorkbenchResult =
    lastResult?.binding.contextIdentity === requestIdentity ? lastResult : null;
  const visibleIdeResult =
    lastIdeResult?.binding.contextIdentity === ideInputIdentity ? lastIdeResult : null;
  const definitions =
    visibleIdeResult?.state === "success" &&
    visibleIdeResult.response?.data.mcp_tool === "oracle_plsql_parse"
      ? plsqlDefinitionsFromResponse(visibleIdeResult.response)
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
      title="SQL Workbench"
      eyebrow="Guarded database access"
      description="Classify and run SQL through the same profile limits, confirmation grants, masking, and audit path as MCP clients."
    >
      {sqlGuard.status === "blocked" ? (
        <ConfirmDialog
          id="workbench-unsaved"
          title="Leave the Workbench?"
          body="The SQL editor differs from the latest successful Workbench action. Leaving this page discards those changes."
          confirmLabel="Leave and discard"
          onCancel={sqlGuard.reset}
          onConfirm={sqlGuard.proceed}
        />
      ) : null}
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(360px,0.9fr)]">
        <ConsolePanel className="p-4">
          <div className="flex flex-col gap-4">
            <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div className="flex flex-wrap gap-2" role="group" aria-label="workbench mode">
                {workbenchModes.map((item) => (
                  <Button
                    key={item.id}
                    type="button"
                    variant={mode === item.id ? "primary" : "secondary"}
                    aria-pressed={mode === item.id}
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
              <span className={OM_LABEL}>SQL</span>
              <textarea
                ref={sqlEditorRef}
                className={cn(OM_TEXTAREA, "min-h-[320px]")}
                spellCheck={false}
                value={sql}
                onChange={(event) => setSql(event.target.value)}
              />
            </label>

            <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_160px_180px]">
              {stateful ? (
                <label className="block">
                  <span className={OM_LABEL}>Agent session</span>
                  <select
                    className={OM_INPUT}
                    value={selectedLane ? laneOptionValue(selectedLane) : ""}
                    onChange={(event) =>
                      setSelectedLaneBinding(laneIdentityFromOption(lanes, event.target.value))
                    }
                    disabled={activeLanes.isPending || lanes.length === 0}
                  >
                    <option value="">Select a session</option>
                    {lanes.map((lane) => (
                      <option key={`${lane.lane_id}:${lane.generation}`} value={laneOptionValue(lane)}>
                        {laneOptionLabel(lane)}
                      </option>
                    ))}
                  </select>
                </label>
              ) : (
                <div>
                  <span className={OM_LABEL}>Connection mode</span>
                  <p className={cn(OM_INPUT, "flex items-center font-semibold")}>Direct server profile</p>
                </div>
              )}
              <label className="block">
                <span className={OM_LABEL}>Maximum rows</span>
                <input
                  className={OM_INPUT}
                  min={1}
                  max={5000}
                  type="number"
                  value={maxRows}
                  onChange={(event) => setMaxRows(clampRows(event.target.valueAsNumber))}
                />
              </label>
              <label className="flex min-h-10 items-end gap-2 pb-2 text-sm font-semibold text-[var(--om-text)]">
                <input
                  className={OM_CHECKBOX}
                  type="checkbox"
                  checked={captureDbmsOutput}
                  onChange={(event) => setCaptureDbmsOutput(event.target.checked)}
                />
                DBMS_OUTPUT
              </label>
            </div>

            {stateful && lanes.length === 0 && activeLanes.status === "success" ? (
              <p className="rounded-md border border-[var(--om-control-border)] bg-[var(--om-surface-muted)] p-3 text-sm text-[var(--om-text)]">
                No active MCP sessions. Connect a client before running database work.
              </p>
            ) : null}
            <p className="text-sm leading-6 text-[var(--om-text-muted)]">
              {confirmReady
                ? "A short-lived confirmation is ready for this exact SQL and session. It cannot be edited."
                : mode === "dml_preview_confirm"
                  ? "Preview this exact DML to obtain its short-lived confirmation."
                  : mode === "ddl_plan_confirm"
                    ? "Browser DDL is preview only. Apply through an approved non-browser client."
                    : "The server will classify this SQL again when it runs."}
            </p>

            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                variant="secondary"
                disabled={!canSubmit}
                onClick={() => submitAction("preview")}
              >
                <Search className="size-4" aria-hidden="true" />
                Preview SQL
              </Button>
              <Button
                type="button"
                variant="secondary"
                disabled={!canSubmit || mode !== "read_query"}
                onClick={() => submitAction("read")}
              >
                <Play className="size-4" aria-hidden="true" />
                Run query
              </Button>
              <Button
                type="button"
                variant="secondary"
                disabled={!canSubmit || mode !== "dml_preview_confirm" || !confirmReady}
                onClick={() => submitAction("rollback_preview")}
              >
                <RotateCcw className="size-4" aria-hidden="true" />
                Execute without commit
              </Button>
              <Button
                type="button"
                variant="primary"
                disabled={
                  !canSubmit ||
                  mode !== "dml_preview_confirm" ||
                  !confirmReady ||
                  !commitAcknowledged
                }
                onClick={() => submitAction("commit")}
              >
                <CheckCircle2 className="size-4" aria-hidden="true" />
                Commit change
              </Button>
            </div>
            {mode === "dml_preview_confirm" ? (
              // The grant auto-fills from the preview, so a populated confirm
              // field is not a decision. Name the durable effect and make the
              // operator agree to it; the server-side grant is still the gate.
              <label className={cn(OM_CHECK_LABEL, "mt-3")}>
                <input
                  className={OM_CHECKBOX}
                  type="checkbox"
                  checked={commitAcknowledged}
                  onChange={(event) => setCommitAcknowledged(event.target.checked)}
                />
                I reviewed this DML and intend to commit it durably to{" "}
                {selectedLane?.lane_id ?? (stateful ? "the selected session" : "the direct server connection")}
              </label>
            ) : null}
          </div>
        </ConsolePanel>

        <WorkbenchResultPanel result={visibleWorkbenchResult} pending={action.isPending} />
        <div className="space-y-4 xl:col-span-2">
          <Surface className="flex flex-wrap items-center justify-between gap-3 p-4">
            <div>
              <h3 className="font-semibold text-[var(--om-text-bright)]">Optional PL/SQL analysis</h3>
              <p className="mt-1 text-sm text-[var(--om-text-muted)]">
                Parse and analyze the editor contents when the server was built with PL/SQL intelligence.
              </p>
            </div>
            <Button
              type="button"
              variant="secondary"
              aria-expanded={showPlsqlTools}
              onClick={() => setShowPlsqlTools((shown) => !shown)}
            >
              {showPlsqlTools ? "Hide PL/SQL tools" : "Show PL/SQL tools"}
            </Button>
          </Surface>
          {showPlsqlTools ? (
            <WorkbenchIdePanel
              canRun={canRunIde}
              changesetJson={changesetJson}
              definitions={definitions}
              identifier={identifier}
              lineageDepth={lineageDepth}
              lineageDirection={lineageDirection}
              onJump={jumpToRange}
              onRun={submitIdeAction}
              onUseSelection={useSelectionAsIdentifier}
              pending={ideAction.isPending}
              projectRoot={projectRoot}
              refactorPreview={refactorPreview}
              replacement={replacement}
              result={visibleIdeResult}
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
          ) : null}
        </div>
      </div>
    </PageFrame>
  );
}

/**
 * The SCN time-scrubber (Arc A).
 *
 * Every mark on the axis is a snapshot the server actually served: the console
 * asks `oracle_query as_of`, and only a read that came back with rows becomes a
 * confirmed mark. A refused snapshot (no FLASHBACK privilege, a snapshot older
 * than undo retention) is kept on the list with its ORA- reason and is never
 * allowed to define the range. A timestamp pin is recorded as such, because
 * Oracle resolves it to an SCN the response never echoes.
 */
// Deliberately not mounted: the current response projection exposes only a row
// count, not the flashback result set a user would need to review.
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
    <ConsolePanel className="min-h-[520px]">
      <div className="flex items-center justify-between gap-3 border-b border-[var(--om-border)] px-4 py-3">
        <div className="min-w-0">
          <h3 className="flex items-center gap-2 text-base font-semibold text-[var(--om-text-bright)]">
            <Code2 className="size-4" aria-hidden="true" />
            PL/SQL analysis
          </h3>
          <p className="mt-1 truncate text-sm text-[var(--om-text-muted)]">
            {pending ? "analysis in flight" : result ? result.label : "idle"}
          </p>
        </div>
        <Badge tone={pending ? "info" : result ? operatorOutcomeTone(result.state) : "off"}>
          {pending ? "running" : result?.state ?? "empty"}
        </Badge>
      </div>

      <div className="space-y-4 p-4">
        <div className="grid gap-3">
          <label className="block">
            <span className={OM_LABEL}>Project path on the server host</span>
            <input
              className={cn(OM_INPUT, "font-mono")}
              value={projectRoot}
              onChange={(event) => setProjectRoot(event.target.value)}
              placeholder="/path/to/plsql/project"
            />
          </label>
          <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_150px_110px]">
            <label className="block">
              <span className={OM_LABEL}>Target</span>
              <input
                className={cn(OM_INPUT, "font-mono")}
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                placeholder="APP.PACKAGE"
              />
            </label>
            <label className="block">
              <span className={OM_LABEL}>Direction</span>
              <select
                className={OM_INPUT}
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
              <span className={OM_LABEL}>Depth</span>
              <input
                className={OM_INPUT}
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
          <span className={OM_LABEL}>ChangeSet</span>
          <textarea
            className={cn(OM_TEXTAREA, "min-h-24 text-xs leading-5")}
            spellCheck={false}
            value={changesetJson}
            onChange={(event) => setChangesetJson(event.target.value)}
          />
        </label>

        <div className="rounded-md border border-[var(--om-border)] bg-[var(--om-surface-muted)] p-3">
          <div className="flex items-center justify-between gap-3">
            <h4 className="text-sm font-semibold text-[var(--om-text-bright)]">Definitions</h4>
            <Badge tone={definitions.length > 0 ? "ok" : "off"}>{definitions.length}</Badge>
          </div>
          <div className="mt-3 max-h-44 space-y-2 overflow-auto">
            {definitions.length === 0 ? (
              <p className="text-sm font-semibold text-[var(--om-text-muted)]">
                No parsed definitions
              </p>
            ) : (
              definitions.map((definition) => (
                <button
                  key={`${definition.name}:${definition.kind}:${definition.span?.start.offset ?? "none"}:${definition.span?.end.offset ?? "none"}`}
                  className="flex w-full items-center justify-between gap-3 rounded-md border border-[var(--om-border)] bg-[var(--om-surface)] px-3 py-2 text-left text-sm hover:bg-[var(--om-surface-elevated)] disabled:cursor-not-allowed disabled:opacity-60"
                  type="button"
                  disabled={!definition.span}
                  onClick={() =>
                    definition.span
                      ? onJump(definition.span.start.offset, definition.span.end.offset)
                      : undefined
                  }
                >
                  <span className="min-w-0">
                    <span className="block truncate font-mono font-semibold text-[var(--om-text-bright)]">
                      {definition.name || "anonymous"}
                    </span>
                    <span className="block text-xs font-semibold text-[var(--om-text-muted)]">
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

        <div className="rounded-md border border-[var(--om-border)] bg-[var(--om-surface-muted)] p-3">
          <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <label className="block">
              <span className={OM_LABEL}>Text Find (Identifier Tokens)</span>
              <input
                className={cn(OM_INPUT, "font-mono")}
                value={identifier}
                onChange={(event) => setIdentifier(event.target.value)}
                placeholder="PKG_NAME"
              />
            </label>
            <label className="block">
              <span className={OM_LABEL}>Text Replace With</span>
              <input
                className={cn(OM_INPUT, "font-mono")}
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
            <Badge tone={usageRows.length > 0 ? "ok" : "off"}>{usageRows.length} text matches</Badge>
            <Badge tone={replacement.trim() && !refactorPreview.error ? "info" : "off"}>
              {replacement.trim() ? "text preview" : "replace idle"}
            </Badge>
          </div>
          <p className="mt-2 text-xs font-semibold text-[var(--om-text-muted)]">
            Lexical text replacement only. Comments and string literals are excluded; this does not
            claim scope-aware semantic usages.
          </p>
          {refactorPreview.error ? (
            <p className="mt-2 text-xs font-semibold text-[var(--om-copper)]" role="alert">
              {refactorPreview.error}
            </p>
          ) : null}
          <div className="mt-3 max-h-36 space-y-2 overflow-auto">
            {usageRows.slice(0, 20).map((occurrence) => (
              <button
                key={`${occurrence.offset}-${occurrence.endOffset}`}
                className="block w-full rounded-md border border-[var(--om-border)] bg-[var(--om-surface)] px-3 py-2 text-left hover:bg-[var(--om-surface-elevated)]"
                type="button"
                onClick={() => onJump(occurrence.offset, occurrence.endOffset)}
              >
                <span className="font-mono text-xs font-semibold text-[var(--om-text-muted)]">
                  {occurrence.line}:{occurrence.column}
                </span>
                <span className="mt-1 block truncate font-mono text-xs text-[var(--om-text-bright)]">
                  {occurrence.preview}
                </span>
              </button>
            ))}
          </div>
          <pre className={cn(OM_CODE, "mt-3 max-h-40")}>{refactorPreview.preview}</pre>
        </div>

        {result ? <OperatorOutcomeNotice outcome={result.outcome} /> : null}
        <pre className={cn(OM_CODE, "max-h-[360px]")}>
          {result?.response ? prettyJson(result.response) : "{}"}
        </pre>
      </div>
    </ConsolePanel>
  );
}

export type AuditFilterControlState = {
  draft: AuditTailFilters;
  applied: AuditTailFilters;
};

const DEFAULT_AUDIT_FILTERS: AuditTailFilters = Object.freeze({
  limit: 50,
  subjectIdHash: "",
  tool: "",
  dangerLevel: "",
  exportProofBundle: false
});

function snapshotAuditFilters(filters: AuditTailFilters): AuditTailFilters {
  return Object.freeze({ ...filters });
}

export function createAuditFilterControlState(): AuditFilterControlState {
  return {
    draft: snapshotAuditFilters(DEFAULT_AUDIT_FILTERS),
    applied: snapshotAuditFilters(DEFAULT_AUDIT_FILTERS)
  };
}

export function updateAuditFilterDraft(
  state: AuditFilterControlState,
  patch: Partial<AuditTailFilters>
): AuditFilterControlState {
  return { ...state, draft: snapshotAuditFilters({ ...state.draft, ...patch }) };
}

export function applyAuditFilterDraft(state: AuditFilterControlState): AuditFilterControlState {
  return { ...state, applied: snapshotAuditFilters(state.draft) };
}

function auditFiltersEqual(left: AuditTailFilters, right: AuditTailFilters): boolean {
  return (
    left.limit === right.limit &&
    left.subjectIdHash === right.subjectIdHash &&
    left.tool === right.tool &&
    left.dangerLevel === right.dangerLevel &&
    left.exportProofBundle === right.exportProofBundle
  );
}

function AuditPage(): React.ReactElement {
  const [filterState, setFilterState] = React.useState(createAuditFilterControlState);
  const { draft, applied } = filterState;
  const updateDraft = React.useCallback((patch: Partial<AuditTailFilters>) => {
    setFilterState((current) => updateAuditFilterDraft(current, patch));
  }, []);
  const auditTail = useQuery({
    queryKey: ["audit-tail", applied],
    queryFn: ({ signal }) => fetchAuditTail(applied, { signal })
  });
  const rawData = auditTail.status === "success" ? auditTail.data.data : null;
  const providerUnavailable = rawData?.source === "unavailable";
  const auditError =
    auditTail.error instanceof Error
      ? auditTail.error.message
      : providerUnavailable
        ? (rawData.reason ?? "Audit tail provider is unavailable.")
        : null;
  const data = providerUnavailable ? null : rawData;
  const verdictProofs = React.useMemo(() => parseVerdictProofs(data), [data]);

  return (
    <PageFrame
      title="Audit trail"
      eyebrow="Governed activity"
      description="Review redacted database actions, guard decisions, and hash-chain verification."
    >
      <div className="space-y-4">
        <Surface className="p-4" aria-busy={auditTail.isPending}>
          <div className="grid gap-3 lg:grid-cols-[minmax(220px,1fr)_180px_160px_120px_auto_auto_auto] lg:items-end">
            <label className="block">
              <span className="mb-2 block text-sm font-bold text-[var(--om-text)]">Client identity hash</span>
              <input
                className="min-h-11 w-full rounded-md border border-[var(--om-control-border)] px-3 font-mono text-sm outline-none focus-visible:border-[var(--om-focus)] focus-visible:ring-2 focus-visible:ring-[var(--om-focus)]"
                value={draft.subjectIdHash}
                onChange={(event) => updateDraft({ subjectIdHash: event.target.value })}
                placeholder="subject-sha256:"
              />
            </label>
            <label className="block">
              <span className="mb-2 block text-sm font-bold text-[var(--om-text)]">Tool</span>
              <select
                className="min-h-11 w-full rounded-md border border-[var(--om-control-border)] bg-[var(--om-surface)] px-3 text-sm outline-none focus-visible:border-[var(--om-focus)] focus-visible:ring-2 focus-visible:ring-[var(--om-focus)]"
                value={draft.tool}
                onChange={(event) => updateDraft({ tool: event.target.value })}
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
              <span className="mb-2 block text-sm font-bold text-[var(--om-text)]">Level</span>
              <select
                className="min-h-11 w-full rounded-md border border-[var(--om-control-border)] bg-[var(--om-surface)] px-3 text-sm outline-none focus-visible:border-[var(--om-focus)] focus-visible:ring-2 focus-visible:ring-[var(--om-focus)]"
                value={draft.dangerLevel}
                onChange={(event) => updateDraft({ dangerLevel: event.target.value })}
              >
                <option value="">All</option>
                <option value="SAFE">SAFE</option>
                <option value="GUARDED">GUARDED</option>
                <option value="DESTRUCTIVE">DESTRUCTIVE</option>
                <option value="ADMIN">ADMIN</option>
              </select>
            </label>
            <label className="block">
              <span className="mb-2 block text-sm font-bold text-[var(--om-text)]">Limit</span>
              <input
                className="min-h-11 w-full rounded-md border border-[var(--om-control-border)] px-3 text-sm outline-none focus-visible:border-[var(--om-focus)] focus-visible:ring-2 focus-visible:ring-[var(--om-focus)]"
                min={1}
                max={200}
                type="number"
                value={draft.limit}
                onChange={(event) => updateDraft({ limit: clampAuditLimit(event.target.valueAsNumber) })}
              />
            </label>
            <Button
              type="button"
              variant={draft.exportProofBundle ? "primary" : "secondary"}
              aria-pressed={draft.exportProofBundle}
              onClick={() => updateDraft({ exportProofBundle: !draft.exportProofBundle })}
            >
              <Download className="size-4" aria-hidden="true" />
              {draft.exportProofBundle ? "Exclude proof bundle" : "Include proof bundle"}
            </Button>
            <Button
              type="button"
              variant="primary"
              disabled={auditFiltersEqual(draft, applied)}
              onClick={() => setFilterState(applyAuditFilterDraft)}
            >
              <Search className="size-4" aria-hidden="true" />
              Apply filters
            </Button>
            <Button type="button" variant="ghost" onClick={() => auditTail.refetch()}>
              <RefreshCcw className="size-4" aria-hidden="true" />
              Refresh
            </Button>
          </div>
        </Surface>

        <AuditProofSummary
          data={data}
          pending={auditTail.isPending}
          error={auditError}
        />
        <AuditTimelineTable
          records={data?.records ?? null}
          pending={auditTail.isPending}
          error={auditError}
        />
        <VerdictProofInspectorPanel
          data={verdictProofs}
          pending={auditTail.isPending}
          error={auditError}
        />
        {applied.exportProofBundle ? (
          <AuditProofBundlePanel
            bundle={data?.export ?? null}
            pending={auditTail.isPending}
            error={auditError}
          />
        ) : null}
      </div>
    </PageFrame>
  );
}

/**
 * Verdict-proof inspector (Arc B1): why the guard admitted or refused each
 * proof-carrying statement, which registry rules fired, and whether the
 * certificate still verifies against the audit record it is bound to.
 */
function VerdictProofInspectorPanel({
  data,
  pending,
  error
}: {
  data: VerdictProofData | null;
  pending: boolean;
  error: string | null;
}): React.ReactElement {
  const VerdictProof = OMCP_SKIN.renderers.VerdictProof;
  const proofs = data?.proofs ?? [];
  const unavailable = Boolean(error) || data?.source === "unavailable";
  return (
    <Surface className="space-y-3 p-4" data-testid="verdict-proof-inspector">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-sm font-bold text-[var(--om-text-bright)]">Verdict Proofs</h2>
          <p className="text-xs text-[var(--om-text-muted)]">
            Redacted certificate fields and binding checks reported with the audit tail. Signing-key verification still requires the CLI.
          </p>
        </div>
        <Badge tone={unavailable ? "warn" : pending ? "info" : proofs.length > 0 ? "ok" : "off"}>
          {unavailable
            ? "unavailable"
            : pending
              ? "loading"
              : `${proofs.length} ${proofs.length === 1 ? "proof" : "proofs"}`}
        </Badge>
      </div>
      {error ? <p className="text-xs text-[var(--om-text-bright)]" role="alert">{error}</p> : null}
      {proofs.length === 0 ? (
        <p className="text-xs text-[var(--om-text-muted)]">
          {unavailable
            ? (data?.reason ?? "Audit tail provider is unavailable.")
            : pending
            ? "Loading verdict certificates…"
            : `No proof-carrying records in this window (${data?.uncertified ?? 0} record(s) without a certificate).`}
        </p>
      ) : (
        <div className="space-y-3">
          {proofs.map((proof) => (
            <VerdictProof key={proof.seq} model={toVerdictProofViewModel(proof)} />
          ))}
        </div>
      )}
    </Surface>
  );
}

export function AuditProofSummary({
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
  const macTone = macStatus === "ok" ? "ok" : macStatus === "not_checked" ? "info" : "off";
  const unavailable = !pending && (Boolean(error) || data === null);
  return (
    <Surface className="p-4">
      <div className="grid gap-3 md:grid-cols-4">
        <AuditFactTile
          label="Chain"
          value={pending ? "checking" : unavailable ? "unavailable" : chainStatus ?? data?.source ?? "unverified"}
          tone={pending ? "info" : unavailable ? "off" : chainTone}
        />
        <AuditFactTile
          label="MAC"
          value={pending ? "checking" : unavailable ? "unavailable" : macStatus ?? "not checked"}
          tone={pending ? "info" : unavailable ? "off" : macTone}
        />
        <AuditFactTile
          label="Scanned"
          value={pending ? "checking" : unavailable ? "unavailable" : data?.scanned_records == null ? "unavailable" : String(data.scanned_records)}
          tone="neutral"
        />
        <AuditFactTile
          label="Selected"
          value={pending ? "checking" : unavailable ? "unavailable" : String(data?.selected_records ?? data?.records.length ?? 0)}
          tone="neutral"
        />
      </div>
      {error ? (
        <p className="mt-3 rounded-md border border-[color-mix(in_srgb,var(--om-copper)_45%,transparent)] bg-[color-mix(in_srgb,var(--om-copper)_14%,transparent)] p-3 text-sm font-semibold text-[var(--om-text-bright)]" role="alert">
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
    <div className="rounded-md border border-[var(--om-border)] bg-[var(--om-surface-muted)] p-3">
      <div className="flex items-start justify-between gap-2">
        <p className="text-xs font-bold uppercase text-[var(--om-text-muted)]">{label}</p>
        <Badge tone={tone}>{tone}</Badge>
      </div>
      <p className="mt-3 break-all font-mono text-sm font-semibold text-[var(--om-text-bright)]">{value}</p>
    </div>
  );
}

export function AuditTimelineTable({
  records,
  pending,
  error
}: {
  records: AuditTailRecord[] | null;
  pending: boolean;
  error: string | null;
}): React.ReactElement {
  const actions = records ? coalesceAuditTimelineRecords(records) : [];
  const unavailable = !pending && (Boolean(error) || records === null);
  return (
    <Surface className="overflow-hidden">
      <div className="flex items-center justify-between gap-3 border-b border-[var(--om-border)] px-4 py-3">
        <div>
          <h3 className="text-base font-bold text-[var(--om-text-bright)]">Timeline</h3>
          <p className="mt-1 text-sm text-[var(--om-text-muted)]">
            {pending
              ? "Loading signed records…"
              : unavailable
                ? "Audit ledger unavailable"
                : `${actions.length} actions · ${records?.length ?? 0} signed records`}
          </p>
        </div>
        <Badge tone={unavailable ? "warn" : pending ? "info" : actions.length > 0 ? "ok" : "off"}>
          {unavailable ? "unavailable" : pending ? "loading" : actions.length > 0 ? "ready" : "empty"}
        </Badge>
      </div>
      <div className="overflow-x-auto" role="region" aria-label="Audit timeline" tabIndex={0}>
        <table className="w-full min-w-[1080px] border-collapse text-left">
          <caption className="sr-only">Redacted governed database actions and proof status</caption>
          <thead className="bg-[var(--om-surface-muted)] text-xs uppercase text-[var(--om-text-muted)]">
            <tr>
              <th className="px-4 py-3 font-bold">Seq</th>
              <th className="px-4 py-3 font-bold">Time</th>
              <th className="px-4 py-3 font-bold">Tool</th>
              <th className="px-4 py-3 font-bold">SQL Hash</th>
              <th className="px-4 py-3 font-bold">DB Evidence</th>
              <th className="px-4 py-3 font-bold">Proof</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--om-border)]">
            {pending || unavailable || actions.length === 0 ? (
              <tr>
                <td className="px-4 py-8 text-center text-sm font-semibold text-[var(--om-text-muted)]" colSpan={6}>
                  {pending
                    ? "Loading audit records…"
                    : unavailable
                      ? `Audit ledger unavailable${error ? `: ${error}` : "."}`
                      : "No audit records"}
                </td>
              </tr>
            ) : (
              actions.map((record) => (
                <tr key={`${record.seq}-${record.sql_sha256}`} className="bg-[var(--om-surface)]">
                  <td className="px-4 py-4 align-top font-mono text-sm text-[var(--om-text-bright)]">{record.seq}</td>
                  <td className="px-4 py-4 align-top text-sm text-[var(--om-text)]">
                    <p className="font-semibold text-[var(--om-text-bright)]">{record.timestamp}</p>
                    <p className="mt-1 break-all font-mono text-xs text-[var(--om-text-muted)]">
                      {record.subject_id_hash}
                    </p>
                  </td>
                  <td className="px-4 py-4 align-top text-sm">
                    <p className="font-semibold text-[var(--om-text-bright)]">{record.tool}</p>
                    <div className="mt-2 flex flex-wrap gap-2">
                      <Badge tone="info">{record.danger_level}</Badge>
                      <Badge tone={record.outcome === "SUCCEEDED" ? "ok" : record.outcome === "PENDING" ? "info" : "warn"}>
                        {record.outcome}
                      </Badge>
                      <Badge tone={record.decision === "BLOCKED" ? "warn" : "neutral"}>{record.decision}</Badge>
                    </div>
                    {record.correlation ? (
                      <p className="mt-2 font-mono text-xs text-[var(--om-text-muted)]">
                        {typeof record.correlation.parent_seq === "number"
                          ? `terminal for #${record.correlation.parent_seq}`
                          : "pending terminal outcome"}
                      </p>
                    ) : null}
                  </td>
                  <td className="px-4 py-4 align-top text-sm">
                    <p className="max-w-[360px] break-words font-mono text-xs leading-5 text-[var(--om-text-bright)]">
                      {record.sql_sha256}
                    </p>
                    <p className="mt-2 text-xs font-semibold text-[var(--om-text-muted)]">binds redacted</p>
                  </td>
                  <td className="px-4 py-4 align-top text-sm text-[var(--om-text)]">
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
    return <span className="text-[var(--om-text-muted)]">unavailable</span>;
  }
  return (
    <dl className="grid gap-1">
      {entries.map(([key, value]) => (
        <div key={key} className="grid grid-cols-[96px_minmax(0,1fr)] gap-2">
          <dt className="text-xs font-bold uppercase text-[var(--om-text-muted)]">{key}</dt>
          <dd className="break-all font-mono text-xs text-[var(--om-text-bright)]">{String(value)}</dd>
        </div>
      ))}
    </dl>
  );
}

export type AuditHashValidity = {
  label: "hash ok" | "hash fail" | "hash unverified";
  tone: "ok" | "warn" | "off";
  verified: boolean | null;
};

export function auditHashValidity(proof: AuditTailRecord["proof"]): AuditHashValidity {
  if (proof?.["hash_valid"] === true) {
    return { label: "hash ok", tone: "ok", verified: true };
  }
  if (proof?.["hash_valid"] === false) {
    return { label: "hash fail", tone: "warn", verified: false };
  }
  return { label: "hash unverified", tone: "off", verified: null };
}

export function AuditRecordProof({ proof }: { proof: AuditTailRecord["proof"] }): React.ReactElement {
  const validity = auditHashValidity(proof);
  return (
    <div className="space-y-2">
      <Badge tone={validity.tone}>{validity.label}</Badge>
      <p className="break-all font-mono text-xs text-[var(--om-text-muted)]">
        {shortHash(typeof proof?.["entry_hash"] === "string" ? proof["entry_hash"] : null)}
      </p>
      <p className="break-all font-mono text-xs text-[var(--om-text-muted)]">
        {typeof proof?.["key_id"] === "string" ? proof["key_id"] : "unsigned"}
      </p>
    </div>
  );
}

export function AuditProofBundlePanel({
  bundle,
  pending,
  error
}: {
  bundle: Record<string, unknown> | null;
  pending: boolean;
  error: string | null;
}): React.ReactElement {
  const unavailable = !pending && Boolean(error);
  return (
    <Surface className="overflow-hidden">
      <div className="flex items-center justify-between gap-3 border-b border-[var(--om-border)] px-4 py-3">
        <div>
          <h3 className="text-base font-bold text-[var(--om-text-bright)]">Proof Bundle</h3>
          <p className="mt-1 text-sm text-[var(--om-text-muted)]">
            {pending
              ? "Loading proof bundle…"
              : unavailable
                ? "Proof bundle unavailable"
                : bundle
                  ? String(bundle["format"] ?? "bundle")
                  : "No proof bundle returned"}
          </p>
        </div>
        <Badge tone={unavailable ? "warn" : pending ? "info" : bundle ? "ok" : "off"}>
          {unavailable ? "unavailable" : pending ? "loading" : bundle ? "export" : "empty"}
        </Badge>
      </div>
      <pre className="max-h-[460px] overflow-auto bg-[var(--om-surface-elevated)] p-4 text-xs leading-5 text-[var(--om-text-bright)]">
        {pending
          ? "Loading proof bundle…"
          : unavailable
            ? "Proof bundle unavailable."
            : bundle
              ? prettyJson(bundle)
              : "{}"}
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
  return `${value.slice(0, 19)}…${value.slice(-8)}`;
}

function clampAuditLimit(value: number): number {
  if (!Number.isFinite(value)) {
    return 50;
  }
  return Math.min(200, Math.max(1, Math.trunc(value)));
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
  const headingRef = React.useRef<HTMLHeadingElement | null>(null);
  React.useEffect(() => {
    document.title = `${title} · Oracle MCP`;
    headingRef.current?.focus();
  }, [title]);
  return (
    <div className="space-y-4">
      <header className="border-b border-[var(--om-border)] pb-4">
        <div className="min-w-0">
          <p className="text-xs font-bold uppercase text-[var(--om-gold)]">{eyebrow}</p>
          <h2 ref={headingRef} tabIndex={-1} className="mt-1 text-3xl font-bold tracking-normal text-[var(--om-text-bright)]">{title}</h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-[var(--om-text-muted)]">{description}</p>
        </div>
      </header>
      {children}
    </div>
  );
}

function QueryErrorNotice({
  title,
  error,
  retryLabel,
  onRetry
}: {
  title: string;
  error: Error;
  retryLabel?: string;
  onRetry?: () => void;
}): React.ReactElement {
  return (
    <div
      className="rounded-lg border border-[var(--om-rust)] bg-[color-mix(in_srgb,var(--om-rust)_12%,transparent)] p-4"
      role="alert"
    >
      <p className="font-semibold text-[var(--om-text-bright)]">{title}</p>
      <p className="mt-1 text-sm text-[var(--om-text-muted)]">{error.message}</p>
      {onRetry ? (
        <Button type="button" variant="secondary" className="mt-3" onClick={onRetry}>
          <RefreshCcw className="size-4" aria-hidden="true" />
          {retryLabel ?? "Retry"}
        </Button>
      ) : null}
    </div>
  );
}

function WorkbenchResultPanel({
  result,
  pending
}: {
  result: WorkbenchResult | null;
  pending: boolean;
}): React.ReactElement {
  const response = result?.response ?? null;
  const confirm = response ? confirmationFromResponse(response) : null;
  const facts = response ? factsFromResponse(response) : [];
  const verdict = response ? workbenchVerdictFromAction(response.data) : null;
  // Arc M: only a row-returning read has an egress decision to certify. On any
  // other tool there is nothing to say, so the badge is not rendered at all
  // rather than reporting a misleading "no certificate".
  const MaskBadge = OMCP_SKIN.renderers.MaskBadge;
  const maskBadge =
    response?.data.mcp_tool === "oracle_query"
      ? toMaskBadgeViewModel(parseMaskCertificate(response.data))
      : null;
  // Arc N: the policy verdict rides on whatever the server answered — the page
  // itself, or the refusal envelope. When no verdict is attached the badge says
  // "not reported"; it never reports the absence of a verdict as "no policy".
  const PolicyBadge = OMCP_SKIN.renderers.PolicyBadge;
  const policyBadge = result
    ? toPolicyBadgeViewModel(parsePolicyTightening(result.response))
    : null;
  const queryResult = response ? workbenchQueryResult(response) : null;
  return (
    <ConsolePanel className="min-h-[520px]">
      <div className="flex items-center justify-between gap-3 border-b border-[var(--om-border)] px-4 py-3">
        <div className="min-w-0">
          <h3 className="flex items-center gap-2 text-base font-semibold text-[var(--om-text-bright)]">
            <Code2 className="size-4" aria-hidden="true" />
            Query or change result
          </h3>
          <p className="mt-1 truncate text-sm text-[var(--om-text-muted)]">
            {pending ? "request in flight" : result ? result.label : "idle"}
          </p>
        </div>
        <Badge tone={pending ? "info" : result ? operatorOutcomeTone(result.state) : "off"}>
          {pending ? "running" : result?.state ?? "empty"}
        </Badge>
      </div>
      <div className="space-y-4 p-4">
        {verdict ? <WorkbenchVerdictBlock verdict={verdict} /> : null}
        {policyBadge ? <PolicyBadge model={policyBadge} /> : null}
        {maskBadge ? <MaskBadge model={maskBadge} /> : null}
        {queryResult ? <WorkbenchQueryTable result={queryResult} /> : null}
        {facts.length > 0 ? (
          <div className="grid gap-2 sm:grid-cols-2">
            {facts.map((fact) => (
              <div
                key={fact.label}
                className="rounded-md border border-[var(--om-border)] bg-[var(--om-surface-muted)] p-3"
              >
                <p className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
                  {fact.label}
                </p>
                <p className="mt-1 break-all font-mono text-xs text-[var(--om-text-bright)]">
                  {fact.value}
                </p>
              </div>
            ))}
          </div>
        ) : null}
        {confirm ? (
          <div className="rounded-md border border-[color-mix(in_srgb,var(--om-sage)_45%,transparent)] bg-[color-mix(in_srgb,var(--om-sage)_12%,transparent)] p-3">
            <p className="text-sm font-semibold text-[var(--om-sage)]">Confirmation ready for this exact request</p>
          </div>
        ) : null}
        {result ? <OperatorOutcomeNotice outcome={result.outcome} /> : null}
        {result?.response ? (
          <details className="rounded-md border border-[var(--om-border)] p-3">
            <summary className="cursor-pointer text-sm font-semibold text-[var(--om-text)]">Technical response</summary>
            <pre className={cn(OM_CODE, "mt-3 max-h-[620px]")}>{prettyJson(result.response)}</pre>
          </details>
        ) : (
          <p className="text-sm text-[var(--om-text-muted)]">Preview or run SQL to see its governed result.</p>
        )}
      </div>
    </ConsolePanel>
  );
}

type WorkbenchQueryView = {
  columns: string[];
  rows: Record<string, unknown>[];
  rowCount: number;
  truncated: boolean;
};

function workbenchQueryResult(
  response: OperatorResponse<WorkbenchActionData>
): WorkbenchQueryView | null {
  const payload = mcpResult(response.data.mcp_response);
  if (!isRecord(payload) || !Array.isArray(payload["rows"])) {
    return null;
  }
  const rows = payload["rows"].filter(isRecord);
  const reportedColumns = Array.isArray(payload["columns"])
    ? payload["columns"].filter((column): column is string => typeof column === "string")
    : [];
  const columns = reportedColumns.length > 0 ? reportedColumns : Object.keys(rows[0] ?? {});
  return {
    columns,
    rows,
    rowCount: typeof payload["row_count"] === "number" ? payload["row_count"] : rows.length,
    truncated: payload["truncated"] === true
  };
}

function WorkbenchQueryTable({ result }: { result: WorkbenchQueryView }): React.ReactElement {
  const visibleRows = keyedWorkbenchRows(result.rows.slice(0, 200));
  return (
    <div className="overflow-hidden rounded-md border border-[var(--om-border)]">
      <div className="border-b border-[var(--om-border)] bg-[var(--om-surface-muted)] px-3 py-2 text-sm text-[var(--om-text)]">
        {formatNumber(result.rowCount)} row(s)
        {result.truncated ? " · server limit reached" : ""}
        {result.rows.length > visibleRows.length ? ` · showing first ${visibleRows.length}` : ""}
      </div>
      <div
        className="max-h-[480px] overflow-auto"
        role="region"
        aria-label="Query results"
        tabIndex={0}
      >
        <table className="w-full min-w-max border-collapse text-left text-sm">
          <caption className="sr-only">Query results returned by Oracle after masking</caption>
          <thead className="sticky top-0 bg-[var(--om-surface-muted)] text-xs uppercase text-[var(--om-text-muted)]">
            <tr>
              {result.columns.map((column) => (
                <th key={column} className="border-b border-[var(--om-border)] px-3 py-2 font-semibold">{column}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--om-border)]">
            {visibleRows.map(({ key, row }) => (
              <tr key={key}>
                {result.columns.map((column) => (
                  <td key={column} className="max-w-[28rem] whitespace-pre-wrap break-words px-3 py-2 font-mono text-xs text-[var(--om-text)]">
                    {displayCell(row[column])}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function keyedWorkbenchRows(
  rows: Record<string, unknown>[]
): Array<{ key: string; row: Record<string, unknown> }> {
  const seen = new Map<string, number>();
  return rows.map((row) => {
    const serialized = JSON.stringify(row);
    const occurrence = (seen.get(serialized) ?? 0) + 1;
    seen.set(serialized, occurrence);
    return { key: `${serialized}:${occurrence}`, row };
  });
}

function displayCell(value: unknown): string {
  if (value === null) {
    return "NULL";
  }
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return JSON.stringify(value);
}

// The honest admission the guard proved for a workbench statement.
// `pass` is a genuine green light; every other state must never render as one.
export type WorkbenchVerdictStatus = "pass" | "step_up" | "refused" | "unknown";

export type WorkbenchVerdict = {
  status: WorkbenchVerdictStatus;
  refused: boolean;
  decision: string;
  danger: string;
  requiredLevel: string;
  reason: string | null;
  rewrite: string | null;
};

// The classifier verdict for a workbench statement, straight from the guarded
// response. A refused statement shows WHY (K8 structured reason) and, when the
// guard can name one, the minimal safe rewrite (K7 suggest_parameterized_form).
// Purely additive: fields absent from the response simply do not render.
export function workbenchVerdictFromAction(
  data: WorkbenchActionData | null
): WorkbenchVerdict | null {
  const result = mcpResult(data?.mcp_response);
  if (!isRecord(result)) {
    return null;
  }
  const danger = result["danger"];
  const requiredLevel = result["required_level"];
  const decision = result["decision"] ?? result["outcome"];
  const gate = result["gate_decision"];
  if (
    danger === undefined &&
    requiredLevel === undefined &&
    decision === undefined &&
    gate === undefined
  ) {
    return null;
  }
  const decisionText = stringValue(decision, "").toLowerCase();
  const dangerText = stringValue(danger, "").toLowerCase();
  const gateText = stringValue(gate, "").toLowerCase();
  // A statement that actually ran against Oracle was admitted; committed /
  // rolled_back / rows_affected is real wire evidence of admission, not a
  // default. A blocked or step-up statement never executes, so this cannot
  // manufacture a false pass.
  const executed =
    result["committed"] === true ||
    result["rolled_back"] === true ||
    typeof result["rows_affected"] === "number";
  // Honesty (bead oraclemcp-tmmi): gate_decision is the admission authority.
  // `danger` classifies the statement but does not admit it — only an explicit
  // allow, a classifier-proven SAFE read, or observed execution is a PASS. A
  // blocked/FORBIDDEN/deny is a refusal; require_step_up is pending, not
  // cleared; anything else fails closed to `unknown`. A green PASS is never
  // manufactured from an absent or unrecognized gate.
  const status: WorkbenchVerdictStatus =
    gateText === "blocked" ||
    dangerText === "forbidden" ||
    dangerText === "refused" ||
    dangerText === "blocked" ||
    decisionText.includes("refus") ||
    decisionText.includes("block") ||
    decisionText.includes("deny")
      ? "refused"
      : gateText === "require_step_up"
        ? "step_up"
        : gateText === "allow" ||
            gateText === "allow_lowering" ||
            dangerText === "safe" ||
            executed
          ? "pass"
          : "unknown";
  const reason = firstString(
    result["reason"],
    nestedString(result, ["reason", "message"]),
    nestedString(result, ["reason", "category"]),
    result["reason_category"],
    result["why_blocked"]
  );
  const rewrite = firstString(
    result["suggested_parameterized_form"],
    result["suggested_rewrite"],
    result["parameterized_form"]
  );
  return {
    status,
    refused: status === "refused",
    decision: stringValue(decision ?? gate, "n/a"),
    danger: stringValue(danger, "n/a"),
    requiredLevel: stringValue(requiredLevel, "n/a"),
    reason,
    rewrite
  };
}

function workbenchVerdictBadge(status: WorkbenchVerdictStatus): {
  tone: DashboardTone;
  label: string;
} {
  switch (status) {
    case "pass":
      return { tone: "ok", label: "PASS" };
    case "step_up":
      return { tone: "info", label: "STEP-UP REQUIRED" };
    case "refused":
      return { tone: "warn", label: "REFUSED" };
    case "unknown":
      return { tone: "off", label: "UNKNOWN" };
  }
}

function firstString(...values: unknown[]): string | null {
  for (const value of values) {
    if (typeof value === "string" && value.trim().length > 0) {
      return value;
    }
  }
  return null;
}

function WorkbenchVerdictBlock({ verdict }: { verdict: WorkbenchVerdict }): React.ReactElement {
  const { tone, label } = workbenchVerdictBadge(verdict.status);
  const affirmed = verdict.status === "pass";
  return (
    <div
      className={cn(
        "grid gap-2 rounded-md border p-3",
        affirmed
          ? "border-[color-mix(in_srgb,var(--om-sage)_45%,transparent)] bg-[color-mix(in_srgb,var(--om-sage)_10%,transparent)]"
          : "border-[color-mix(in_srgb,var(--om-copper)_45%,transparent)] bg-[color-mix(in_srgb,var(--om-copper)_10%,transparent)]"
      )}
      data-classifier-refused={verdict.refused}
      data-workbench-verdict={verdict.status}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
          Classifier Verdict
        </span>
        <Badge tone={tone}>{label}</Badge>
        <span className="font-mono text-xs text-[var(--om-text-muted)]">
          danger {verdict.danger} · needs {verdict.requiredLevel}
        </span>
      </div>
      {verdict.reason ? (
        <p className="text-sm font-semibold text-[var(--om-text-bright)]">{verdict.reason}</p>
      ) : null}
      {verdict.rewrite ? (
        <div>
          <p className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
            Minimal safe rewrite
          </p>
          <pre className={cn(OM_CODE, "mt-1 max-h-40 whitespace-pre-wrap")}>{verdict.rewrite}</pre>
        </div>
      ) : null}
    </div>
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
      return "Preview SQL";
    case "read":
      return "Run query";
    case "rollback_preview":
      return "Execute without commit";
    case "commit":
      return "Commit change";
  }
}

type WorkbenchIdeRequestInput = {
  source: string;
  lane?: OperatorLaneTarget;
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
  lane?: OperatorLaneTarget;
  tool: WorkbenchPlsqlTool;
  arguments: Record<string, unknown>;
  idempotencyPrefix: string;
} {
  const projectRoot = input.projectRoot.trim();
  const target = input.target.trim();
  switch (action) {
    case "parse":
      return {
        lane: input.lane,
        tool: "oracle_plsql_parse",
        arguments: { source: input.source },
        idempotencyPrefix: "workbench-plsql-parse"
      };
    case "docs":
      return {
        lane: input.lane,
        tool: "oracle_plsql_doc",
        arguments: { source: input.source, format: "json" },
        idempotencyPrefix: "workbench-plsql-doc"
      };
    case "analyze":
      if (!projectRoot) {
        throw new Error("project root is required");
      }
      return {
        lane: input.lane,
        tool: "oracle_plsql_analyze",
        arguments: { project_root: projectRoot },
        idempotencyPrefix: "workbench-plsql-analyze"
      };
    case "lineage":
      if (!projectRoot || !target) {
        throw new Error("project root and target are required");
      }
      return {
        lane: input.lane,
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
        lane: input.lane,
        tool: "oracle_plsql_sast",
        arguments: { project_root: projectRoot, format: "json" },
        idempotencyPrefix: "workbench-plsql-sast"
      };
    case "impact":
      return {
        lane: input.lane,
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

export function identifierOccurrences(source: string, identifier: string): IdentifierOccurrence[] {
  const needle = identifier.trim();
  const needleKind = oracleIdentifierKind(needle);
  if (!needleKind) {
    return [];
  }
  const occurrences: IdentifierOccurrence[] = [];
  let cursor = 0;
  while (cursor < source.length) {
    if (source.startsWith("--", cursor)) {
      cursor = skipUntil(source, cursor + 2, "\n");
      continue;
    }
    if (source.startsWith("/*", cursor)) {
      cursor = skipUntil(source, cursor + 2, "*/");
      continue;
    }
    if (
      (source[cursor] === "n" || source[cursor] === "N") &&
      (source[cursor + 1] === "q" || source[cursor + 1] === "Q") &&
      source[cursor + 2] === "'"
    ) {
      cursor = skipQQuotedLiteral(source, cursor + 1);
      continue;
    }
    if ((source[cursor] === "q" || source[cursor] === "Q") && source[cursor + 1] === "'") {
      cursor = skipQQuotedLiteral(source, cursor);
      continue;
    }
    if ((source[cursor] === "n" || source[cursor] === "N") && source[cursor + 1] === "'") {
      cursor = skipDelimitedIdentifierOrLiteral(source, cursor + 1, "'", true);
      continue;
    }
    if (source[cursor] === "'") {
      cursor = skipDelimitedIdentifierOrLiteral(source, cursor, "'", true);
      continue;
    }
    if (source[cursor] === '"') {
      const endOffset = skipDelimitedIdentifierOrLiteral(source, cursor, '"', true);
      if (needleKind === "quoted" && source.slice(cursor, endOffset) === needle) {
        occurrences.push(identifierOccurrence(source, cursor, endOffset));
      }
      cursor = endOffset;
      continue;
    }
    if (isPlsqlIdentifierChar(source[cursor])) {
      const offset = cursor;
      while (cursor < source.length && isPlsqlIdentifierChar(source[cursor])) {
        cursor += 1;
      }
      const token = source.slice(offset, cursor);
      if (needleKind === "unquoted" && token.toUpperCase() === needle.toUpperCase()) {
        occurrences.push(identifierOccurrence(source, offset, cursor));
      }
      continue;
    }
    cursor += 1;
  }
  return occurrences;
}

function identifierOccurrence(
  source: string,
  offset: number,
  endOffset: number
): IdentifierOccurrence {
      const location = sourceLocationAtOffset(source, offset);
  return {
    offset,
    endOffset,
    line: location.line,
    column: location.column,
    preview: linePreviewAtOffset(source, offset)
  };
}

function skipUntil(source: string, start: number, terminator: string): number {
  const found = source.indexOf(terminator, start);
  return found < 0 ? source.length : found + terminator.length;
}

function skipDelimitedIdentifierOrLiteral(
  source: string,
  start: number,
  delimiter: string,
  doubledEscape: boolean
): number {
  let cursor = start + 1;
  while (cursor < source.length) {
    if (source[cursor] !== delimiter) {
      cursor += 1;
      continue;
    }
    if (doubledEscape && source[cursor + 1] === delimiter) {
      cursor += 2;
      continue;
    }
    return cursor + 1;
  }
  return source.length;
}

function skipQQuotedLiteral(source: string, start: number): number {
  const opener = source[start + 2];
  if (!opener || /\s/.test(opener)) {
    return source.length;
  }
  const closer = ({ "[": "]", "(": ")", "{": "}", "<": ">" } as Record<string, string>)[
    opener
  ] ?? opener;
  return skipUntil(source, start + 3, `${closer}'`);
}

function oracleIdentifierKind(identifier: string): "quoted" | "unquoted" | null {
  if (/^[A-Za-z][A-Za-z0-9_$#]{0,127}$/.test(identifier)) {
    return "unquoted";
  }
  if (identifier.startsWith('"') && identifier.endsWith('"')) {
    const body = identifier.slice(1, -1);
    const decoded = body.replaceAll('""', '"');
    if (
      decoded.length > 0 &&
      decoded.length <= 128 &&
      !/[\r\n\0]/.test(decoded) &&
      body.replaceAll('""', "").includes('"') === false
    ) {
      return "quoted";
    }
  }
  return null;
}

export function buildRefactorPreview(
  source: string,
  identifier: string,
  replacement: string
): RefactorPreview {
  const needle = identifier.trim();
  const replacementIdentifier = replacement.trim();
  const occurrences = identifierOccurrences(source, needle);
  if (!needle || !replacementIdentifier) {
    return { occurrences, preview: "{}", error: null };
  }
  if (!oracleIdentifierKind(needle)) {
    return { occurrences: [], preview: "{}", error: "Find must be one valid Oracle identifier." };
  }
  if (!oracleIdentifierKind(replacementIdentifier)) {
    return {
      occurrences,
      preview: "{}",
      error: "Replacement must be one valid Oracle identifier."
    };
  }
  if (occurrences.length === 0) {
    return { occurrences, preview: "{}", error: null };
  }
  let cursor = 0;
  const chunks: string[] = [];
  for (const occurrence of occurrences) {
    chunks.push(source.slice(cursor, occurrence.offset), replacementIdentifier);
    cursor = occurrence.endOffset;
  }
  chunks.push(source.slice(cursor));
  const preview = chunks.join("");
  return {
    occurrences,
    preview: preview.length > 2400 ? `${preview.slice(0, 2400)}\n…` : preview,
    error: null
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
