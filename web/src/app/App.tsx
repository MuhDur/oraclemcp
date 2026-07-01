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
  CheckCircle2,
  Code2,
  Database,
  FileClock,
  Play,
  RefreshCcw,
  RotateCcw,
  Search,
  ShieldCheck,
  SquarePen,
  Stethoscope
} from "lucide-react";

import { Badge, Button, Surface } from "../components/ui/primitives";
import { cn } from "../lib/utils";
import {
  auditProbes,
  doctorProbes,
  executeWorkbenchSql,
  fetchDashboardSession,
  fetchProbe,
  overviewProbes,
  pendingProbe,
  previewWorkbenchSql,
  readWorkbenchSql,
  type OperatorResponse,
  type ProbeDefinition,
  type ProbeResult,
  sessionsProbes,
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
  return (
    <PageFrame
      title="Overview"
      eyebrow="Mission Control"
      description="Runtime and operator protocol posture from the active service."
    >
      <ProbeDashboard probes={overviewProbes} />
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
  return (
    <PageFrame
      title="Audit"
      eyebrow="Hash Chain"
      description="Audit route availability and schema posture."
    >
      <ProbeDashboard probes={auditProbes} compact />
    </PageFrame>
  );
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
