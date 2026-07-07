import * as React from "react";
import {
  Activity,
  AlertTriangle,
  FileClock,
  Gauge,
  ShieldCheck,
  Timer,
  Users
} from "lucide-react";

import { Badge, Surface } from "../components/ui/primitives";
import { cn } from "../lib/utils";
import {
  CLEARANCE_LADDER,
  DASHBOARD_GRAMMAR,
  REQUIRED_BIG_BOARD_RENDERERS,
  REQUIRED_THEME_MODES,
  type BigBoardRendererKind,
  type ClearanceLevel,
  type DashboardTone,
  type FleetSessionViewModel,
  type FleetViewModel,
  type GoNoGoVerdict,
  type GroundControlViewModel,
  type HealthPosture,
  type SignatureId,
  type SkinCapability,
  defaultSkinCapabilities,
  normalizeRendererChoice,
  skinContractFixture
} from "./presentation-model";

export type DashboardTheme = {
  name: string;
  modes: readonly string[];
  cssVars: Readonly<Record<`--om-${string}`, string>>;
  webglUniforms: Readonly<Record<ClearanceLevel, readonly [number, number, number]>>;
};

export type BigBoardRendererProps = {
  model: FleetViewModel;
  renderer: BigBoardRendererDefinition;
};

export type BigBoardRendererDefinition = {
  kind: BigBoardRendererKind;
  label: string;
  requiresWebGl: boolean;
  available: boolean;
  lazy: boolean;
  component:
    | React.ComponentType<BigBoardRendererProps>
    | React.LazyExoticComponent<React.ComponentType<BigBoardRendererProps>>;
};

export type DashboardSkin = {
  name: string;
  grammarVersion: typeof DASHBOARD_GRAMMAR.grammarVersion;
  theme: DashboardTheme;
  defaultBigBoard: BigBoardRendererKind;
  bigBoardRenderers: Readonly<Record<BigBoardRendererKind, BigBoardRendererDefinition>>;
  renderers: {
    GroundControl: React.ComponentType<{ model: GroundControlViewModel }>;
  };
  layout: {
    appShell: string;
    frame: string;
    sidebar: string;
    logoMark: string;
    nav: string;
    navLink: string;
  };
};

const orreryRenderer = React.lazy(() => import("./orrery-renderer"));

export const CARVED_LIGHT_THEME: DashboardTheme = {
  name: "carved-light",
  modes: REQUIRED_THEME_MODES,
  cssVars: {
    "--om-bg": "#0c0b09",
    "--om-text": "#e9e2d0",
    "--om-surface": "#1e1913",
    "--om-surface-muted": "#282119",
    "--om-border": "#4a4230",
    "--om-focus": "#c7a34a",
    "--om-clearance-read-only": "#8ea98c",
    "--om-clearance-read-write": "#c7a34a",
    "--om-clearance-ddl": "#d97748",
    "--om-clearance-admin": "#c25048",
    "--om-activity": "#d97748",
    "--om-grid": "#2b261b"
  },
  webglUniforms: {
    READ_ONLY: [0.557, 0.663, 0.549],
    READ_WRITE: [0.78, 0.639, 0.29],
    DDL: [0.851, 0.467, 0.282],
    ADMIN: [0.761, 0.314, 0.282]
  }
};

// The OMCP operator console ships exactly one theme (Carved Light) over the
// view-model / skin / theme / renderer seam. The seam (DashboardSkin,
// assertDashboardSkinConformance, the board2d/table/orrery3d renderer set,
// REQUIRED_THEME_MODES) stays open for future skins; 0.7.3 wires just this one.
export const OMCP_SKIN: DashboardSkin = {
  name: "omcp-carved-light",
  grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
  theme: CARVED_LIGHT_THEME,
  defaultBigBoard: "board2d",
  bigBoardRenderers: {
    board2d: {
      kind: "board2d",
      label: "2D Board",
      requiresWebGl: false,
      available: true,
      lazy: false,
      component: Board2DBigBoardRenderer
    },
    table: {
      kind: "table",
      label: "Table",
      requiresWebGl: false,
      available: true,
      lazy: false,
      component: TableBigBoardRenderer
    },
    orrery3d: {
      kind: "orrery3d",
      label: "Orrery 3D",
      requiresWebGl: true,
      available: false,
      lazy: true,
      component: orreryRenderer
    }
  },
  renderers: {
    GroundControl: GroundControl2DRenderer
  },
  layout: {
    appShell: "min-h-screen bg-[var(--om-bg)] text-[var(--om-text)]",
    frame: "mx-auto flex w-full max-w-[1440px] flex-col gap-4 px-4 py-4 md:px-6 lg:flex-row lg:py-6",
    sidebar:
      "flex shrink-0 flex-col gap-4 border-b border-[var(--om-border)] pb-4 lg:w-64 lg:border-b-0 lg:border-r lg:pb-0 lg:pr-4",
    logoMark:
      "flex size-10 items-center justify-center rounded-lg bg-[var(--om-clearance-read-only)] text-white",
    nav: "flex gap-2 overflow-x-auto lg:flex-col",
    navLink:
      "inline-flex min-h-10 items-center gap-2 rounded-md px-3 py-2 text-sm font-semibold text-zinc-700 hover:bg-white hover:text-zinc-950 [&.active]:bg-white [&.active]:text-emerald-800 [&.active]:shadow-sm"
  }
};

assertDashboardSkinConformance(OMCP_SKIN);

export function useDashboardCapabilities(): SkinCapability {
  const [capabilities, setCapabilities] = React.useState<SkinCapability>(() =>
    detectDashboardCapabilities()
  );

  React.useEffect(() => {
    const reducedMotion = mediaQuery("(prefers-reduced-motion: reduce)");
    const highContrast = mediaQuery("(prefers-contrast: more)");
    const forcedColors = mediaQuery("(forced-colors: active)");
    const update = (): void => setCapabilities(detectDashboardCapabilities());

    reducedMotion?.addEventListener("change", update);
    highContrast?.addEventListener("change", update);
    forcedColors?.addEventListener("change", update);
    return () => {
      reducedMotion?.removeEventListener("change", update);
      highContrast?.removeEventListener("change", update);
      forcedColors?.removeEventListener("change", update);
    };
  }, []);

  return capabilities;
}

export function BigBoardSurface({
  capabilities,
  model,
  skin
}: {
  capabilities: SkinCapability;
  model: FleetViewModel;
  skin: DashboardSkin;
}): React.ReactElement {
  const renderer = selectBigBoardRenderer(skin, capabilities);
  const Renderer = renderer.component;
  return (
    <React.Suspense fallback={<BigBoardFallback model={model} renderer={renderer} />}>
      <Renderer model={model} renderer={renderer} />
    </React.Suspense>
  );
}

export function selectBigBoardRenderer(
  skin: DashboardSkin,
  capabilities: SkinCapability
): BigBoardRendererDefinition {
  const kind = normalizeRendererChoice(
    skin.defaultBigBoard,
    capabilities,
    (candidate) => skin.bigBoardRenderers[candidate]?.available === true
  );
  return skin.bigBoardRenderers[kind];
}

export function detectDashboardCapabilities(): SkinCapability {
  if (typeof window === "undefined") {
    return defaultSkinCapabilities();
  }
  const forcedColors = window.matchMedia("(forced-colors: active)").matches;
  const highContrast = window.matchMedia("(prefers-contrast: more)").matches;
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  return {
    webgl: detectWebGl(),
    reducedMotion,
    highContrast,
    forcedColors,
    preferTable: forcedColors || highContrast
  };
}

export function assertDashboardSkinConformance(skin: DashboardSkin): void {
  const fixture = skinContractFixture();
  if (skin.grammarVersion !== DASHBOARD_GRAMMAR.grammarVersion) {
    throw new Error(`skin ${skin.name} has an unsupported grammar version`);
  }
  assertSameSet(
    REQUIRED_THEME_MODES,
    skin.theme.modes,
    `skin ${skin.name} theme mode coverage`
  );
  assertSameSet(
    REQUIRED_BIG_BOARD_RENDERERS,
    Object.keys(skin.bigBoardRenderers),
    `skin ${skin.name} big-board renderer coverage`
  );
  if (!skin.bigBoardRenderers.board2d.available || !skin.bigBoardRenderers.table.available) {
    throw new Error(`skin ${skin.name} must provide both 2D and table fallback renderers`);
  }
  if (skin.bigBoardRenderers.orrery3d.available && !skin.bigBoardRenderers.orrery3d.lazy) {
    throw new Error(`skin ${skin.name} must lazy-load the Orrery renderer`);
  }
  if (
    fixture.groundControl.clearanceLadder.map((step) => step.level).join(">") !==
    "READ_ONLY>READ_WRITE>DDL>ADMIN"
  ) {
    throw new Error("clearance ladder grammar changed");
  }
  if (fixture.fleet.sessions.some((session) => session.clearance !== "READ_ONLY")) {
    throw new Error("skin fixture must stay protected/read-only");
  }
}

function GroundControl2DRenderer({
  model
}: {
  model: GroundControlViewModel;
}): React.ReactElement {
  const goNoGo = model.signatures.find((signature) => signature.id === "go_no_go");
  const otherSignatures = model.signatures.filter((signature) => signature.id !== "go_no_go");
  return (
    <section
      className="grid gap-3 rounded-lg border border-[var(--om-border)] bg-[var(--om-surface)] px-4 py-3 shadow-sm xl:grid-cols-[minmax(150px,0.65fr)_minmax(360px,1.4fr)_minmax(140px,0.55fr)_minmax(170px,0.7fr)]"
      aria-label="ground control"
      data-grammar-version={model.grammarVersion}
      data-health={model.health}
      data-verdict={model.verdict}
    >
      {goNoGo ? <SignatureCell signature={goNoGo} /> : null}
      <div className="min-w-0 border-t border-zinc-100 pt-3 xl:border-l xl:border-t-0 xl:pl-4 xl:pt-0">
        <div className="flex items-center justify-between gap-3">
          <p className="text-xs font-bold uppercase text-zinc-500">Clearance Ladder</p>
          <Badge tone={model.clearanceStatus.tone}>{model.clearanceStatus.label}</Badge>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          {model.clearanceLadder.map((step) => (
            <span
              key={step.level}
              className={cn(
                "inline-flex h-7 items-center rounded-md border px-2 font-mono text-xs font-bold",
                clearanceClass(step.level)
              )}
              data-clearance-level={step.level}
              data-clearance-ordinal={step.ordinal}
            >
              {step.label}
            </span>
          ))}
        </div>
      </div>
      {otherSignatures.map((signature) => (
        <SignatureCell key={signature.id} signature={signature} />
      ))}
    </section>
  );
}

function SignatureCell({
  signature
}: {
  signature: {
    id: SignatureId;
    label: string;
    value: string;
    detail: string;
    tone: DashboardTone;
  };
}): React.ReactElement {
  const Icon = signatureIcon(signature.id);
  return (
    <div className="flex min-w-0 items-center gap-3 border-t border-zinc-100 pt-3 first:border-t-0 first:pt-0 xl:border-l xl:border-t-0 xl:pl-4 xl:pt-0 xl:first:border-l-0 xl:first:pl-0">
      <div className="flex size-10 shrink-0 items-center justify-center rounded-md border border-zinc-200 bg-zinc-50 text-zinc-700">
        <Icon className="size-5" aria-hidden="true" />
      </div>
      <div className="min-w-0">
        <p className="text-xs font-bold uppercase text-zinc-500">{signature.label}</p>
        <div className="mt-1 flex min-w-0 items-center gap-2">
          <p className="truncate font-mono text-sm font-bold text-zinc-950">{signature.value}</p>
          <Badge tone={signature.tone}>{signature.tone}</Badge>
        </div>
        <p className="mt-1 truncate text-xs font-semibold text-zinc-500">{signature.detail}</p>
      </div>
    </div>
  );
}

function Board2DBigBoardRenderer({
  model,
  renderer
}: BigBoardRendererProps): React.ReactElement {
  return (
    <Surface
      className="overflow-hidden border-[var(--om-border)]"
      aria-label="big board"
      data-renderer={renderer.kind}
      data-grammar-version={model.grammarVersion}
    >
      <div className="grid gap-4 p-4 xl:grid-cols-[minmax(260px,0.45fr)_minmax(0,1.55fr)]">
        <div className="min-w-0 rounded-md border border-zinc-200 bg-zinc-50 p-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="text-xs font-bold uppercase text-zinc-500">Big Board</p>
              <h2 className="mt-2 font-mono text-3xl font-bold leading-none text-zinc-950">
                {model.verdict}
              </h2>
            </div>
            <Badge tone={verdictTone(model.verdict)}>{renderer.label}</Badge>
          </div>
          <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-1">
            <BoardFact icon={Users} label="Active" value={model.totals.activeLanes} />
            <BoardFact icon={Activity} label="Requests" value={model.totals.requests} />
            <BoardFact icon={AlertTriangle} label="Blocked" value={model.totals.blocked} />
            <BoardFact icon={Gauge} label="Latency" value={`${model.totals.meanLatencyMs} ms`} />
          </div>
        </div>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {model.sessions.length === 0 ? (
            <div className="rounded-md border border-dashed border-zinc-300 bg-white p-4">
              <p className="font-mono text-sm font-bold text-zinc-950">NO ACTIVE LANES</p>
              <p className="mt-2 text-sm font-semibold text-zinc-500">idle</p>
            </div>
          ) : (
            model.sessions.map((session) => (
              <SessionBoardTile key={`${session.laneId}:${session.subjectIdHash}`} session={session} />
            ))
          )}
        </div>
      </div>
    </Surface>
  );
}

function TableBigBoardRenderer({
  model,
  renderer
}: BigBoardRendererProps): React.ReactElement {
  return (
    <Surface
      className="overflow-hidden border-[var(--om-border)]"
      aria-label="big board table"
      data-renderer={renderer.kind}
      data-grammar-version={model.grammarVersion}
    >
      <div className="flex items-center justify-between gap-3 border-b border-zinc-200 px-4 py-3">
        <div>
          <h2 className="text-base font-bold text-zinc-950">Big Board</h2>
          <p className="mt-1 text-sm text-zinc-500">{renderer.label}</p>
        </div>
        <Badge tone={verdictTone(model.verdict)}>{model.verdict}</Badge>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] border-collapse text-left">
          <thead className="bg-zinc-50 text-xs uppercase text-zinc-500">
            <tr>
              <th className="px-4 py-3 font-bold">Lane</th>
              <th className="px-4 py-3 font-bold">State</th>
              <th className="px-4 py-3 font-bold">Clearance</th>
              <th className="px-4 py-3 font-bold">Activity</th>
              <th className="px-4 py-3 font-bold">Requests</th>
              <th className="px-4 py-3 font-bold">Blocked</th>
              <th className="px-4 py-3 font-bold">Latency</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-100">
            {model.sessions.length === 0 ? (
              <tr>
                <td className="px-4 py-8 text-center text-sm font-semibold text-zinc-500" colSpan={7}>
                  No active lanes
                </td>
              </tr>
            ) : (
              model.sessions.map((session) => (
                <tr key={`${session.laneId}:${session.subjectIdHash}`} className="bg-white">
                  <td className="px-4 py-4 align-top">
                    <p className="font-mono text-sm font-semibold text-zinc-950">{session.laneId}</p>
                    <p className="mt-1 break-all font-mono text-xs text-zinc-500">
                      {session.subjectIdHash}
                    </p>
                  </td>
                  <td className="px-4 py-4 align-top">
                    <Badge tone={healthTone(session.status)}>{session.status}</Badge>
                  </td>
                  <td className="px-4 py-4 align-top">
                    <span
                      className={cn(
                        "inline-flex rounded-md border px-2 py-1 font-mono text-xs font-bold",
                        clearanceClass(session.clearance)
                      )}
                    >
                      {session.clearance}
                    </span>
                  </td>
                  <td className="px-4 py-4 align-top font-mono text-sm text-zinc-800">
                    {Math.round(session.activity * 100)}%
                  </td>
                  <td className="px-4 py-4 align-top font-mono text-sm text-zinc-800">
                    {session.requests}
                  </td>
                  <td className="px-4 py-4 align-top font-mono text-sm text-zinc-800">
                    {session.blocked}
                  </td>
                  <td className="px-4 py-4 align-top font-mono text-sm text-zinc-800">
                    {session.latencyMs} ms
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

function BigBoardFallback({ model, renderer }: BigBoardRendererProps): React.ReactElement {
  return <TableBigBoardRenderer model={model} renderer={{ ...renderer, kind: "table", label: "Table" }} />;
}

function SessionBoardTile({ session }: { session: FleetSessionViewModel }): React.ReactElement {
  return (
    <div
      className="min-w-0 rounded-md border border-zinc-200 bg-white p-4"
      data-clearance-level={session.clearance}
      data-health={session.status}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="truncate font-mono text-sm font-bold text-zinc-950">{session.laneId}</p>
          <p className="mt-1 break-all font-mono text-xs text-zinc-500">{session.subjectIdHash}</p>
        </div>
        <Badge tone={healthTone(session.status)}>{session.status}</Badge>
      </div>
      <div className="mt-4 h-2 rounded-full bg-zinc-100" aria-hidden="true">
        <div
          className="h-2 rounded-full bg-[var(--om-activity)]"
          style={{ width: `${Math.round(session.activity * 100)}%` }}
        />
      </div>
      <div className="mt-4 flex flex-wrap gap-2">
        <span
          className={cn(
            "rounded-md border px-2 py-1 font-mono text-xs font-bold",
            clearanceClass(session.clearance)
          )}
        >
          {session.clearance}
        </span>
        <Badge tone={session.blocked > 0 ? "warn" : "ok"}>{session.blocked} blocked</Badge>
        <Badge tone="info">{session.latencyMs} ms</Badge>
      </div>
    </div>
  );
}

function BoardFact({
  icon: Icon,
  label,
  value
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: number | string;
}): React.ReactElement {
  return (
    <div className="flex items-center gap-3">
      <div className="flex size-9 shrink-0 items-center justify-center rounded-md border border-zinc-200 bg-white text-zinc-700">
        <Icon className="size-4" aria-hidden="true" />
      </div>
      <div>
        <p className="text-xs font-bold uppercase text-zinc-500">{label}</p>
        <p className="mt-1 font-mono text-sm font-bold text-zinc-950">{value}</p>
      </div>
    </div>
  );
}

function clearanceClass(level: ClearanceLevel): string {
  switch (level) {
    case "READ_ONLY":
      return "border-emerald-200 bg-emerald-50 text-emerald-900";
    case "READ_WRITE":
      return "border-sky-200 bg-sky-50 text-sky-900";
    case "DDL":
      return "border-amber-200 bg-amber-50 text-amber-900";
    case "ADMIN":
      return "border-rose-200 bg-rose-50 text-rose-900";
  }
}

function signatureIcon(id: SignatureId): React.ComponentType<{ className?: string }> {
  switch (id) {
    case "go_no_go":
      return ShieldCheck;
    case "countdown":
      return Timer;
    case "logbook":
      return FileClock;
  }
}

function healthTone(health: HealthPosture): DashboardTone {
  switch (health) {
    case "nominal":
    case "working":
      return "ok";
    case "blocked":
      return "warn";
    case "syncing":
      return "info";
    case "idle":
      return "off";
  }
}

function verdictTone(verdict: GoNoGoVerdict): DashboardTone {
  switch (verdict) {
    case "GO":
      return "ok";
    case "NO-GO":
      return "warn";
    case "SYNC":
      return "info";
  }
}

function mediaQuery(query: string): MediaQueryList | null {
  return typeof window === "undefined" ? null : window.matchMedia(query);
}

function detectWebGl(): boolean {
  if (typeof document === "undefined") {
    return false;
  }
  const canvas = document.createElement("canvas");
  return Boolean(canvas.getContext("webgl2") ?? canvas.getContext("webgl"));
}

function assertSameSet(expected: readonly string[], actual: readonly string[], label: string): void {
  const expectedSorted = [...expected].sort().join("\0");
  const actualSorted = [...actual].sort().join("\0");
  if (expectedSorted !== actualSorted) {
    throw new Error(`${label} mismatch`);
  }
}

export { CLEARANCE_LADDER };
