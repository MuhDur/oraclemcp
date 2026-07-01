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
import { QueryClient, QueryClientProvider, useQueries } from "@tanstack/react-query";
import {
  type ColumnDef,
  flexRender,
  getCoreRowModel,
  useReactTable
} from "@tanstack/react-table";
import {
  Activity,
  Database,
  FileClock,
  RefreshCcw,
  ShieldCheck,
  Stethoscope
} from "lucide-react";

import { Badge, Button, Surface } from "../components/ui/primitives";
import { cn } from "../lib/utils";
import {
  auditProbes,
  doctorProbes,
  fetchProbe,
  overviewProbes,
  pendingProbe,
  type ProbeDefinition,
  type ProbeResult,
  sessionsProbes
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

const doctorRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/doctor",
  component: DoctorPage
});

const router = createRouter({
  routeTree: rootRoute.addChildren([overviewRoute, sessionsRoute, auditRoute, doctorRoute])
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
