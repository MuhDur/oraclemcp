import * as React from "react";
import {
  Activity,
  AlertTriangle,
  FileClock,
  Gauge,
  Link2,
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
  type GroundControlChain,
  type GroundControlViewModel,
  type HealthPosture,
  type CostBadgeViewModel,
  type FleetMapViewModel,
  type MaskBadgeViewModel,
  type VectorClusterViewModel,
  type EditionTimelineViewModel,
  type CqnChangeFeedViewModel,
  type ColumnLineageViewModel,
  type PolicyBadgeViewModel,
  type ScnScrubberViewModel,
  type SignatureId,
  type SkinCapability,
  type UndoTreeViewModel,
  type VerdictProofViewModel,
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
    VerdictProof: React.ComponentType<{ model: VerdictProofViewModel }>;
    CostBadge: React.ComponentType<{ model: CostBadgeViewModel }>;
    MaskBadge: React.ComponentType<{ model: MaskBadgeViewModel }>;
    FleetMap: React.ComponentType<{ model: FleetMapViewModel }>;
    PolicyBadge: React.ComponentType<{ model: PolicyBadgeViewModel }>;
    VectorCluster: React.ComponentType<{ model: VectorClusterViewModel }>;
    EditionTimeline: React.ComponentType<{ model: EditionTimelineViewModel }>;
    CqnChangeFeed: React.ComponentType<{ model: CqnChangeFeedViewModel }>;
    ColumnLineage: React.ComponentType<{ model: ColumnLineageViewModel }>;
    ScnScrubber: React.ComponentType<{
      model: ScnScrubberViewModel;
      onScrub?: (scn: number) => void;
    }>;
    UndoTree: React.ComponentType<{
      model: UndoTreeViewModel;
      // Offered only for a plainly reversible checkpoint; a partial rollback is a
      // separate, explicitly-labeled action, never a plain Undo.
      onUndo?: (checkpoint: string) => void;
      onPartialRollback?: (checkpoint: string) => void;
    }>;
  };
  layout: {
    appShell: string;
    frame: string;
    sidebar: string;
    logoMark: string;
    nav: string;
    navLink: string;
    /** Visually hidden until focused; every skin must keep it reachable. */
    skipLink: string;
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
  // The Orrery is the hero when WebGL is present and motion is allowed;
  // normalizeRendererChoice drops to the 2D board otherwise, so a reduced-motion
  // or low-power client still boots instantly on the mandatory fallback.
  defaultBigBoard: "orrery3d",
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
      available: true,
      lazy: true,
      component: orreryRenderer
    }
  },
  renderers: {
    GroundControl: GroundControl2DRenderer,
    VerdictProof: VerdictProofInspector,
    UndoTree: UndoTreeRenderer,
    CostBadge: CostBadgeRenderer,
    ScnScrubber: ScnScrubberRenderer,
    MaskBadge: MaskBadgeRenderer,
    FleetMap: FleetMapRenderer,
    VectorCluster: VectorClusterRenderer,
    EditionTimeline: EditionTimelineRenderer,
    CqnChangeFeed: CqnChangeFeedRenderer,
    ColumnLineage: ColumnLineageRenderer,
    PolicyBadge: PolicyBadgeRenderer
  },
  layout: {
    appShell: "min-h-screen bg-[var(--om-bg)] text-[var(--om-text)]",
    frame: "mx-auto flex w-full max-w-[1440px] flex-col gap-4 px-4 py-4 md:px-6 lg:flex-row lg:py-6",
    sidebar:
      "flex shrink-0 flex-col gap-4 border-b border-[var(--om-border)] pb-4 lg:w-64 lg:border-b-0 lg:border-r lg:pb-0 lg:pr-4",
    logoMark:
      "flex size-10 items-center justify-center rounded-lg bg-[var(--om-clearance-read-only)] text-[var(--om-bg)]",
    nav: "flex gap-2 overflow-x-auto lg:flex-col",
    navLink:
      "inline-flex min-h-10 items-center gap-2 rounded-md px-3 py-2 text-sm font-semibold text-[var(--om-text)] hover:bg-[var(--om-surface)] hover:text-[var(--om-text-bright)] [&.active]:bg-[var(--om-surface)] [&.active]:text-[var(--om-gold)] [&.active]:shadow-sm",
    skipLink:
      "sr-only focus-visible:not-sr-only focus-visible:absolute focus-visible:left-4 focus-visible:top-4 focus-visible:z-50 focus-visible:inline-flex focus-visible:min-h-10 focus-visible:items-center focus-visible:rounded-md focus-visible:bg-[var(--om-surface)] focus-visible:px-4 focus-visible:py-2 focus-visible:text-sm focus-visible:font-semibold focus-visible:text-[var(--om-gold)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--om-focus)]"
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

/**
 * The verdict-proof inspector (Arc B1).
 *
 * It answers three operator questions about one governed statement: was it
 * admitted or refused, which registry rules fired to get there, and does the
 * certificate actually verify against the audit record it names. The proof
 * badge is driven by the client-side checks, never by a server assertion, and
 * an unregistered rule id renders as unregistered rather than being hidden.
 */
export function VerdictProofInspector({
  model
}: {
  model: VerdictProofViewModel;
}): React.ReactElement {
  const verified = model.proofStatus === "verified";
  return (
    <section
      className="flex flex-col gap-3 rounded-lg border border-[var(--om-border)] bg-[var(--om-surface)] p-4 shadow-sm"
      aria-label={`verdict proof for audit record ${model.seq}`}
      data-grammar-version={model.grammarVersion}
      data-verdict={model.verdict}
      data-go-no-go={model.goNoGo}
      data-admitted={model.admitted ? "true" : "false"}
      data-proof-status={model.proofStatus}
      data-cert-hash={model.certHash}
      data-audit-hash={model.auditHash ?? ""}
      data-clearance-level={model.level ?? "NONE"}
      data-seq={model.seq}
    >
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          {verified ? (
            <ShieldCheck className="size-4 text-[var(--om-sage)]" aria-hidden="true" />
          ) : (
            <AlertTriangle className="size-4 text-[var(--om-copper)]" aria-hidden="true" />
          )}
          <span className="text-sm font-bold text-[var(--om-text-bright)]">
            {model.admitted ? "Admitted" : "Refused"}
          </span>
          <Badge tone={model.tone}>{model.verdict}</Badge>
          <span
            className="font-mono text-2xs uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]"
            data-testid="verdict-proof-level"
          >
            {model.level ?? "no level"}
          </span>
        </div>
        <span
          className={cn(
            "font-mono text-2xs uppercase tracking-[var(--tracking-label)]",
            verified ? "text-[var(--om-sage)]" : "text-[var(--om-copper)]"
          )}
        >
          proof {model.proofStatus}
        </span>
      </header>

      <dl className="grid gap-2 sm:grid-cols-2">
        <VerdictProofFact label="Certificate hash" value={model.certHash || "absent"} />
        <VerdictProofFact label="Bound audit entry" value={model.auditHash ?? "unbound"} />
        <VerdictProofFact label="Statement digest" value={model.stmtDigest} />
        <VerdictProofFact label="Classifier" value={model.classifierVersion} />
        {model.observedScn ? (
          <VerdictProofFact label="Observed SCN" value={model.observedScn} />
        ) : null}
        <VerdictProofFact label="Tool" value={model.tool} />
      </dl>

      <div>
        <p className="mb-2 text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
          Derivation
        </p>
        <ol className="flex flex-col gap-1">
          {model.derivation.map((step, index) => (
            <li
              key={`${step.ruleId}:${step.construct}:${index}`}
              className="flex items-center gap-2 rounded-md border border-[var(--om-border)] px-2 py-1"
              data-rule-id={step.ruleId}
              data-construct={step.construct}
              data-registered={step.registered ? "true" : "false"}
            >
              <span className="font-mono text-2xs font-bold text-[var(--om-gold)]">
                {step.ruleId}
              </span>
              <span className="font-mono text-2xs text-[var(--om-text)]">{step.construct}</span>
              {step.registered ? null : (
                <span className="font-mono text-2xs text-[var(--om-copper)]">unregistered</span>
              )}
            </li>
          ))}
        </ol>
      </div>

      <div>
        <p className="mb-2 text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
          Verification
        </p>
        <ul className="flex flex-col gap-1">
          {model.checks.map((check) => (
            <li
              key={check.id}
              className="flex items-center gap-2 text-xs"
              data-check-id={check.id}
              data-check-ok={check.ok ? "true" : "false"}
            >
              <Link2
                className={cn(
                  "size-3",
                  check.ok ? "text-[var(--om-sage)]" : "text-[var(--om-copper)]"
                )}
                aria-hidden="true"
              />
              <span className="font-semibold text-[var(--om-text-bright)]">{check.label}</span>
              <span className="text-[var(--om-text-muted)]">{check.detail}</span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

function VerdictProofFact({ label, value }: { label: string; value: string }): React.ReactElement {
  return (
    <div className="min-w-0">
      <dt className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
        {label}
      </dt>
      <dd className="truncate font-mono text-xs text-[var(--om-text)]" title={value}>
        {value}
      </dd>
    </div>
  );
}

/**
 * The policy-narrowing badge (Arc N).
 *
 * Policy is monotone — Deny or Narrow, never Allow — so the badge reads as
 * "what the policy took away": the level it narrowed FROM, the level it
 * narrowed TO, the rules that fired, and the predicates it bolted on. With no
 * policy verdict on the response the badge says `not_reported`, which is not a
 * claim that no policy applied.
 */
export function PolicyBadgeRenderer({
  model
}: {
  model: PolicyBadgeViewModel;
}): React.ReactElement {
  return (
    <section
      className={cn(
        "flex flex-col gap-2 rounded-lg border bg-[var(--om-surface)] p-4 shadow-sm",
        model.effect === "Deny"
          ? "border-[color-mix(in_srgb,var(--om-copper)_45%,transparent)]"
          : "border-[var(--om-border)]"
      )}
      aria-label="policy narrowing"
      data-grammar-version={model.grammarVersion}
      data-policy-status={model.status}
      data-policy-effect={model.effect ?? "not_reported"}
      data-narrowed-from={model.narrowedFrom ?? ""}
      data-narrowed-to={model.narrowedTo ?? ""}
      data-policy-narrowed={model.narrowed ? "true" : "false"}
      data-matched-rules={model.matchedRuleIds.length}
    >
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <ShieldCheck className="size-4 text-[var(--om-gold)]" aria-hidden="true" />
          <span className="text-sm font-bold text-[var(--om-text-bright)]">Policy</span>
          <Badge tone={model.tone}>{model.effect ?? "not reported"}</Badge>
        </div>
        {model.narrowedFrom && model.narrowedTo ? (
          <span
            className="font-mono text-2xs uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]"
            data-testid="policy-level-transition"
          >
            {model.narrowedFrom} → {model.narrowedTo}
          </span>
        ) : null}
      </header>

      <p className="text-sm font-semibold text-[var(--om-text-bright)]">{model.headline}</p>
      <p className="text-xs text-[var(--om-text-muted)]">{model.detail}</p>

      {model.matchedRuleIds.length > 0 ? (
        <ul className="flex flex-wrap gap-1">
          {model.matchedRuleIds.map((ruleId) => (
            <li
              key={ruleId}
              className="rounded-md border border-[var(--om-border)] px-2 py-1 font-mono text-2xs text-[var(--om-text)]"
              data-policy-rule-id={ruleId}
            >
              {ruleId}
            </li>
          ))}
        </ul>
      ) : null}

      {model.predicates.length > 0 ? (
        <ul className="flex flex-col gap-1">
          {model.predicates.map((predicate) => (
            <li
              key={`${predicate.ruleId}:${predicate.target}`}
              className="rounded-md border border-dashed border-[var(--om-border)] px-2 py-1"
              data-policy-predicate-rule={predicate.ruleId}
              data-policy-predicate-target={predicate.target}
            >
              <span className="font-mono text-2xs text-[var(--om-gold)]">{predicate.target}</span>{" "}
              <span className="font-mono text-2xs text-[var(--om-text)]">
                AND {predicate.sqlFragment}
              </span>
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}

/**
 * The fleet map (Arc H).
 *
 * One node per MCP-visible profile, including the ones the server could not
 * read. An unreachable database keeps its place on the map with its typed
 * status and error; it is never dropped, and it never renders "no drift",
 * because nothing was compared.
 */
export function FleetMapRenderer({ model }: { model: FleetMapViewModel }): React.ReactElement {
  return (
    <section
      className="flex flex-col gap-3 rounded-lg border border-[var(--om-border)] bg-[var(--om-surface)] p-4 shadow-sm"
      aria-label="fleet map"
      data-grammar-version={model.grammarVersion}
      data-profile-count={model.profileCount}
      data-reachable-count={model.reachableCount}
      data-unreachable-count={model.unreachableCount}
      data-fail-closed-count={model.failClosedCount}
      data-baseline-profile={model.baselineProfile ?? ""}
    >
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Users className="size-4 text-[var(--om-gold)]" aria-hidden="true" />
          <span className="text-sm font-bold text-[var(--om-text-bright)]">Fleet Map</span>
          <Badge tone={model.tone}>{model.headline}</Badge>
        </div>
        <span className="font-mono text-2xs text-[var(--om-text-muted)]">
          {model.driftedCount} drifted
          {model.baselineProfile ? ` vs ${model.baselineProfile}` : ""}
        </span>
      </header>
      <p className="text-xs text-[var(--om-text-muted)]">{model.detail}</p>

      <ul className="grid gap-2 sm:grid-cols-2">
        {model.nodes.map((node) => (
          <li
            key={node.dbId}
            className={cn(
              "flex flex-col gap-1 rounded-md border px-3 py-2",
              node.status === "reachable"
                ? "border-[var(--om-border)]"
                : "border-[color-mix(in_srgb,var(--om-copper)_45%,transparent)]"
            )}
            data-db-id={node.dbId}
            data-db-status={node.status}
            data-db-drift={
              node.drift === null ? "unknown" : node.drift.changedSections.length > 0 ? "drifted" : "none"
            }
            data-db-role={node.databaseRole ?? ""}
          >
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={node.tone}>{node.status}</Badge>
              <span className="truncate font-mono text-xs font-bold text-[var(--om-text-bright)]">
                {node.dbId}
              </span>
              {node.serverVersion ? (
                <span className="font-mono text-2xs text-[var(--om-text-muted)]">
                  {node.serverVersion}
                </span>
              ) : null}
            </div>
            <p className="text-2xs text-[var(--om-text-muted)]">{node.detail}</p>
            {node.status === "reachable" ? (
              <p className="font-mono text-2xs text-[var(--om-text-muted)]">
                {node.databaseRole ?? "role —"} · {node.openMode ?? "mode —"} ·{" "}
                {node.poolOpenConnections ?? 0} conn
              </p>
            ) : (
              <p className="font-mono text-2xs text-[var(--om-copper)]">
                {node.errorCode ?? "UNKNOWN"} · drift not evaluated
              </p>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

/**
 * The egress mask badge (Arc M).
 *
 * Per column: was it transformed on the way out, and which policy rule said so.
 * With no certificate the badge renders `no_certificate` — the server only
 * emits one when it transformed something, so silence proves nothing and the
 * badge refuses to render a reassuring "unmasked" row it cannot back.
 */
/**
 * The vector cluster panel (Arc F).
 *
 * Nearest neighbors from a guarded 23ai vector search, in the server's distance
 * order. The panel is honest about two things the backend does not give it: the
 * numeric distance (only the RANK is real, shown per neighbor) and the index use
 * (`null` = not reported, never inferred). A refused search — e.g. an unproven
 * filter predicate rejected as a data-egress bypass — shows the refusal, not an
 * empty cluster. A masked cell is never rendered as if it were the real value.
 */
export function VectorClusterRenderer({
  model
}: {
  model: VectorClusterViewModel;
}): React.ReactElement {
  return (
    <section
      className={cn(
        "flex flex-col gap-3 rounded-lg border bg-[var(--om-surface)] p-4 shadow-sm",
        model.status === "refused"
          ? "border-[color-mix(in_srgb,var(--om-copper)_45%,transparent)]"
          : "border-[var(--om-border)]"
      )}
      aria-label="vector cluster"
      data-grammar-version={model.grammarVersion}
      data-vector-status={model.status}
      data-metric={model.metric ?? "none"}
      data-k={model.k === null ? "unknown" : model.k}
      data-returned={model.returned}
      data-distance-reported={model.distanceReported ? "true" : "false"}
      data-used-index={model.usedIndex === null ? "not_reported" : model.usedIndex ? "true" : "false"}
      data-masked-columns={model.maskedColumns}
    >
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Activity className="size-4 text-[var(--om-gold)]" aria-hidden="true" />
          <span className="text-sm font-bold text-[var(--om-text-bright)]">Vector Cluster</span>
          <Badge tone={model.tone}>{model.metric ?? "no metric"}</Badge>
          {model.maskedColumns > 0 ? <Badge tone="warn">masked</Badge> : null}
        </div>
        <span className="font-mono text-2xs text-[var(--om-text-muted)]">
          k={model.k ?? "?"} · {model.returned} returned ·{" "}
          {model.usedIndex === null ? "index n/r" : model.usedIndex ? "indexed" : "no index"}
        </span>
      </header>

      <p className="text-sm font-semibold text-[var(--om-text-bright)]">{model.headline}</p>
      <p className="text-xs text-[var(--om-text-muted)]">{model.detail}</p>

      {model.status === "results" ? (
        <table className="w-full text-2xs" data-testid="vector-neighbors">
          <thead>
            <tr className="text-left text-[var(--om-text-muted)]">
              <th className="py-1 font-semibold">rank</th>
              {model.columns.map((column) => (
                <th key={column} className="py-1 font-semibold">
                  {column}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="font-mono">
            {model.neighbors.map((neighbor) => (
              <tr
                key={neighbor.rank}
                data-neighbor-rank={neighbor.rank}
                // The distance the server ordered by is not egressed, so the rank
                // IS the distance signal — monotonic non-decreasing by construction.
                data-neighbor-distance={neighbor.rank}
                data-neighbor-masked={neighbor.masked ? "true" : "false"}
              >
                <td className="py-1 text-[var(--om-text-muted)]">{neighbor.rank}</td>
                {neighbor.cells.map((cell, index) => (
                  <td key={`${neighbor.rank}:${index}`} className="py-1 text-[var(--om-text)]">
                    {cell}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </section>
  );
}

/**
 * The edition linear timeline (Arc D).
 *
 * Oracle editions are linear — each derives from exactly one parent — so the
 * Reviews board renders them as a straight timeline, not a git graph. A branch
 * (a base edition with two children) is flagged, never flattened into a line.
 */
export function EditionTimelineRenderer({
  model
}: {
  model: EditionTimelineViewModel;
}): React.ReactElement {
  return (
    <section
      className={cn(
        "flex flex-col gap-3 rounded-lg border bg-[var(--om-surface)] p-4 shadow-sm",
        model.linear
          ? "border-[var(--om-border)]"
          : "border-[color-mix(in_srgb,var(--om-copper)_45%,transparent)]"
      )}
      aria-label="edition timeline"
      data-grammar-version={model.grammarVersion}
      data-edition-linear={model.linear ? "true" : "false"}
      data-stage-count={model.stages.length}
      data-branch-count={model.branchedFrom.length}
    >
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <FileClock className="size-4 text-[var(--om-gold)]" aria-hidden="true" />
          <span className="text-sm font-bold text-[var(--om-text-bright)]">Edition Timeline</span>
          <Badge tone={model.tone}>{model.linear ? "linear" : "branched"}</Badge>
        </div>
        <span className="font-mono text-2xs text-[var(--om-text-muted)]">{model.headline}</span>
      </header>
      <p className="text-xs text-[var(--om-text-muted)]">{model.detail}</p>

      <ol className="flex flex-col gap-1">
        {model.stages.map((stage) => (
          <li
            key={stage.edition}
            className="flex flex-wrap items-center gap-2 rounded-md border border-[var(--om-border)] px-3 py-2"
            data-edition-stage={stage.edition}
            data-edition-parent={stage.parentEdition ?? ""}
            data-linear-order={stage.order}
            data-edition-status={stage.status ?? "none"}
          >
            <span className="font-mono text-2xs text-[var(--om-text-muted)]">#{stage.order}</span>
            {stage.parentEdition ? (
              <span className="font-mono text-2xs text-[var(--om-text-muted)]">
                {stage.parentEdition} →
              </span>
            ) : (
              <span className="font-mono text-2xs text-[var(--om-text-muted)]">root →</span>
            )}
            <span className="font-mono text-xs font-bold text-[var(--om-text-bright)]">
              {stage.edition}
            </span>
            {stage.status ? <Badge tone={stage.tone}>{stage.status}</Badge> : null}
            <span className="text-2xs text-[var(--om-text-muted)]">
              {stage.objectCount} object(s)
            </span>
          </li>
        ))}
      </ol>

      {!model.linear ? (
        <p className="text-2xs font-semibold text-[var(--om-copper)]">
          Branch points: {model.branchedFrom.join(", ")}
        </p>
      ) : null}
    </section>
  );
}

/**
 * The live CQN change feed (Arc C1).
 *
 * Each entry is a changed resource SCOPE — the proven query's resource URI, the
 * only thing a CQN callback is allowed to forward. Never row data, never an
 * object name, never a value. Repeat callbacks for one scope coalesce. When the
 * operator surface projects no feed, the panel says so rather than showing a
 * quiet, healthy stream.
 */
export function CqnChangeFeedRenderer({
  model
}: {
  model: CqnChangeFeedViewModel;
}): React.ReactElement {
  return (
    <section
      className="flex flex-col gap-3 rounded-lg border border-[var(--om-border)] bg-[var(--om-surface)] p-4 shadow-sm"
      aria-label="cqn change feed"
      data-grammar-version={model.grammarVersion}
      data-feed-status={model.status}
      data-event-count={model.events.length}
    >
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Activity className="size-4 text-[var(--om-gold)]" aria-hidden="true" />
          <span className="text-sm font-bold text-[var(--om-text-bright)]">Change Feed</span>
          <Badge tone={model.tone}>{model.status}</Badge>
        </div>
        <span className="font-mono text-2xs text-[var(--om-text-muted)]">{model.headline}</span>
      </header>
      <p className="text-xs text-[var(--om-text-muted)]">{model.detail}</p>

      {model.events.length > 0 ? (
        <ul className="flex flex-col gap-1">
          {model.events.map((event) => (
            <li
              key={event.eventId}
              className={cn(
                "flex flex-wrap items-center gap-2 rounded-md border px-3 py-2",
                event.scopeIsResource
                  ? "border-[var(--om-border)]"
                  : "border-[color-mix(in_srgb,var(--om-copper)_45%,transparent)]"
              )}
              data-change-event-id={event.eventId}
              data-change-scope={event.scope}
              data-coalesced={event.coalesced ? "true" : "false"}
              data-scope-is-resource={event.scopeIsResource ? "true" : "false"}
            >
              <Badge tone={event.coalesced ? "info" : "off"}>
                {event.coalesced ? `coalesced ×${event.count}` : "single"}
              </Badge>
              <span className="truncate font-mono text-2xs text-[var(--om-text)]" title={event.scope}>
                {event.scope}
              </span>
              {!event.scopeIsResource ? (
                <span className="font-mono text-2xs text-[var(--om-copper)]">
                  not a resource scope
                </span>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}

/**
 * The column-lineage / drift view (Arc K).
 *
 * Each source-derived column edge carries the typed status the backend assigned
 * after cross-checking the live catalog: verified, drift-missing,
 * drift-type-mismatch, or partial (a wrapped body). The console renders that
 * marker verbatim — it never upgrades a drift to verified — and reports "not
 * reported" when the lineage surface projected no edges.
 */
export function ColumnLineageRenderer({
  model
}: {
  model: ColumnLineageViewModel;
}): React.ReactElement {
  return (
    <section
      className={cn(
        "flex flex-col gap-3 rounded-lg border bg-[var(--om-surface)] p-4 shadow-sm",
        model.driftCount > 0
          ? "border-[color-mix(in_srgb,var(--om-copper)_45%,transparent)]"
          : "border-[var(--om-border)]"
      )}
      aria-label="column lineage"
      data-grammar-version={model.grammarVersion}
      data-lineage-status={model.status}
      data-edge-count={model.edges.length}
      data-verified-count={model.verifiedCount}
      data-drift-count={model.driftCount}
      data-partial-count={model.partialCount}
    >
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Link2 className="size-4 text-[var(--om-gold)]" aria-hidden="true" />
          <span className="text-sm font-bold text-[var(--om-text-bright)]">Column Lineage</span>
          <Badge tone={model.tone}>{model.status}</Badge>
        </div>
        <span className="font-mono text-2xs text-[var(--om-text-muted)]">{model.headline}</span>
      </header>
      <p className="text-xs text-[var(--om-text-muted)]">{model.detail}</p>

      {model.edges.length > 0 ? (
        <ul className="flex flex-col gap-1">
          {model.edges.map((edge) => (
            <li
              key={`${edge.from}->${edge.to}`}
              className={cn(
                "flex flex-wrap items-center gap-2 rounded-md border px-3 py-2",
                edge.status.startsWith("drift")
                  ? "border-[color-mix(in_srgb,var(--om-copper)_45%,transparent)]"
                  : "border-[var(--om-border)]"
              )}
              data-edge-status={edge.status}
              data-edge-from={edge.from}
              data-edge-to={edge.to}
            >
              <Badge tone={edge.tone}>{edge.status}</Badge>
              <span className="truncate font-mono text-2xs text-[var(--om-text)]">
                {edge.from} → {edge.to}
              </span>
              <span className="text-2xs text-[var(--om-text-muted)]">{edge.detail}</span>
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}

export function MaskBadgeRenderer({ model }: { model: MaskBadgeViewModel }): React.ReactElement {
  return (
    <section
      className="flex flex-col gap-3 rounded-lg border border-[var(--om-border)] bg-[var(--om-surface)] p-4 shadow-sm"
      aria-label="egress mask certificate"
      data-grammar-version={model.grammarVersion}
      data-mask-status={model.status}
      data-mask-policy-id={model.policyId ?? ""}
      data-mask-audit-hash={model.auditHash ?? ""}
      data-masked-columns={model.maskedColumns}
    >
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <ShieldCheck className="size-4 text-[var(--om-gold)]" aria-hidden="true" />
          <span className="text-sm font-bold text-[var(--om-text-bright)]">Egress Mask</span>
          <Badge tone={model.tone}>{model.status}</Badge>
        </div>
        <span className="truncate font-mono text-2xs text-[var(--om-text-muted)]">
          {model.policyId ? `policy ${model.policyId}` : "no policy certificate"}
          {model.profile ? ` · ${model.profile}` : ""}
        </span>
      </header>

      <p className="text-sm font-semibold text-[var(--om-text-bright)]">{model.headline}</p>
      <p className="text-xs text-[var(--om-text-muted)]">{model.detail}</p>

      {model.columns.length > 0 ? (
        <ul className="flex flex-col gap-1">
          {model.columns.map((column) => (
            <li
              key={column.column}
              className={cn(
                "flex flex-wrap items-center gap-2 rounded-md border px-2 py-1",
                column.masked
                  ? "border-[color-mix(in_srgb,var(--om-copper)_45%,transparent)]"
                  : "border-[var(--om-border)]"
              )}
              data-column={column.column}
              data-masked={column.masked ? "true" : "false"}
              data-mask-action={column.action}
              data-mask-source={column.source}
              data-mask-policy-id={model.policyId ?? ""}
              data-mask-rule-index={column.ruleIndex ?? ""}
            >
              <Badge tone={column.tone}>{column.action}</Badge>
              <span className="font-mono text-xs text-[var(--om-text)]">{column.column}</span>
              <span className="font-mono text-2xs text-[var(--om-text-muted)]">
                {column.oracleType}
              </span>
              <span className="text-2xs text-[var(--om-text-muted)]">{column.detail}</span>
              {column.saltId ? (
                <span className="font-mono text-2xs text-[var(--om-gold)]">
                  salt {column.saltId}
                </span>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}

/**
 * The SCN time-scrubber (Arc A).
 *
 * The slider exists only when the console has confirmed snapshots to slide
 * between; with no confirmed read there is no axis, and the scrubber says why
 * rather than drawing a fake timeline from 0 to "now".
 */
export function ScnScrubberRenderer({
  model,
  onScrub
}: {
  model: ScnScrubberViewModel;
  onScrub?: (scn: number) => void;
}): React.ReactElement {
  return (
    <section
      className="flex flex-col gap-3 rounded-lg border border-[var(--om-border)] bg-[var(--om-surface)] p-4 shadow-sm"
      aria-label="scn time scrubber"
      data-grammar-version={model.grammarVersion}
      data-scn-current={model.current === null ? "live" : model.current}
      data-scn-min={model.min === null ? "unknown" : model.min}
      data-scn-max={model.max === null ? "unknown" : model.max}
      data-scn-clamped={model.clamped ? "true" : "false"}
      data-scn-status={model.status}
      data-range-known={model.rangeKnown ? "true" : "false"}
    >
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Timer className="size-4 text-[var(--om-gold)]" aria-hidden="true" />
          <span className="text-sm font-bold text-[var(--om-text-bright)]">Time Scrubber</span>
          <Badge tone={model.tone}>{model.status}</Badge>
        </div>
        <span className="font-mono text-2xs tabular-nums text-[var(--om-text-muted)]">
          {model.min ?? "—"} … {model.max ?? "—"}
        </span>
      </header>

      <p className="text-sm font-semibold text-[var(--om-text-bright)]">{model.headline}</p>
      <p className="text-xs text-[var(--om-text-muted)]">{model.detail}</p>

      {model.rangeKnown && model.min !== null && model.max !== null ? (
        <input
          type="range"
          className="w-full"
          aria-label="system change number"
          min={model.min}
          max={model.max}
          value={model.current ?? model.max}
          onChange={(event) => onScrub?.(event.target.valueAsNumber)}
        />
      ) : null}

      <ol className="flex flex-col gap-1">
        {model.marks.map((mark) => (
          <li
            key={mark.id}
            className="flex flex-wrap items-center gap-2 rounded-md border border-[var(--om-border)] px-2 py-1"
            data-mark-scn={mark.scn === null ? "unreported" : mark.scn}
            data-mark-status={mark.status}
          >
            <Badge tone={mark.tone}>{mark.status}</Badge>
            <span className="font-mono text-2xs text-[var(--om-text)]">{mark.label}</span>
            <span className="text-2xs text-[var(--om-text-muted)]">{mark.detail}</span>
          </li>
        ))}
      </ol>
    </section>
  );
}

/**
 * The cost/gas badge (Arc G).
 *
 * A meter only when the server disclosed both numbers; otherwise the badge says
 * which one it does not have. `unknown` and `estimated` are not failures to
 * hide — they are the honest shape of a gate that prices on refusal.
 */
export function CostBadgeRenderer({ model }: { model: CostBadgeViewModel }): React.ReactElement {
  return (
    <section
      className={cn(
        "flex flex-col gap-2 rounded-lg border bg-[var(--om-surface)] p-4 shadow-sm",
        model.verdict === "refused"
          ? "border-[color-mix(in_srgb,var(--om-copper)_45%,transparent)]"
          : "border-[var(--om-border)]"
      )}
      aria-label="query cost gate"
      data-grammar-version={model.grammarVersion}
      data-cost-verdict={model.verdict}
      data-cost-estimate={model.estimate === null ? "unknown" : model.estimate}
      data-cost-ceiling={model.ceiling === null ? (model.verdict === "ungated" ? "none" : "undisclosed") : model.ceiling}
      data-cost-ceiling-source={model.ceilingSource}
      data-cost-ratio={model.ratio === null ? "" : model.ratio.toFixed(3)}
      data-hint-count={model.hints.length}
    >
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Gauge className="size-4 text-[var(--om-gold)]" aria-hidden="true" />
          <span className="text-sm font-bold text-[var(--om-text-bright)]">Cost Gate</span>
          <Badge tone={model.tone}>{model.verdict}</Badge>
        </div>
        <span className="font-mono text-2xs tabular-nums text-[var(--om-text-muted)]">
          {model.estimate === null ? "cost —" : `cost ${model.estimate}`}
          {" / "}
          {model.ceiling === null
            ? model.verdict === "ungated"
              ? "no ceiling configured"
              : "ceiling undisclosed"
            : `ceiling ${model.ceiling}`}
        </span>
      </header>

      <p className="text-sm font-semibold text-[var(--om-text-bright)]">{model.headline}</p>
      <p className="text-xs text-[var(--om-text-muted)]">{model.detail}</p>

      {model.ratio !== null ? (
        <div
          className="h-1.5 w-full overflow-hidden rounded-full bg-[var(--om-surface-muted)]"
          role="presentation"
        >
          <div
            className={cn(
              "h-full rounded-full",
              model.verdict === "refused" ? "bg-[var(--om-copper)]" : "bg-[var(--om-sage)]"
            )}
            style={{ width: `${Math.round(model.ratio * 100)}%` }}
          />
        </div>
      ) : null}

      {model.hints.length > 0 ? (
        <ul className="flex flex-col gap-1">
          {model.hints.map((hint) => (
            <li key={hint} className="font-mono text-2xs text-[var(--om-text)]" data-cost-hint="">
              {hint}
            </li>
          ))}
        </ul>
      ) : null}

      {model.planRows.length > 0 ? (
        <table className="w-full text-2xs" data-testid="cost-plan-rows">
          <thead>
            <tr className="text-left text-[var(--om-text-muted)]">
              <th className="py-1 font-semibold">#</th>
              <th className="py-1 font-semibold">Operation</th>
              <th className="py-1 font-semibold">Object</th>
              <th className="py-1 text-right font-semibold">Cost</th>
              <th className="py-1 text-right font-semibold">Rows</th>
            </tr>
          </thead>
          <tbody className="font-mono">
            {model.planRows.map((row) => (
              <tr key={row.id} data-plan-row-id={row.id} data-plan-row-cost={row.cost ?? ""}>
                <td className="py-1 text-[var(--om-text-muted)]">{row.id}</td>
                <td className="py-1 text-[var(--om-text)]">{row.operation}</td>
                <td className="py-1 text-[var(--om-text-muted)]">{row.objectName ?? "—"}</td>
                <td className="py-1 text-right tabular-nums text-[var(--om-text)]">
                  {row.cost ?? "—"}
                </td>
                <td className="py-1 text-right tabular-nums text-[var(--om-text-muted)]">
                  {row.cardinality ?? "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}

      {model.note ? (
        <p className="text-2xs italic text-[var(--om-text-muted)]">{model.note}</p>
      ) : null}
    </section>
  );
}

/**
 * The reversible undo-tree (Arc I).
 *
 * Walkable checkpoints, the work held above them, and — prominently — what a
 * rollback cannot take back. A node whose effect escapes the transaction gets
 * its server-issued reason and no Undo button; a checkpoint with escaped work
 * above it offers an explicitly-labeled *partial* rollback, never a plain Undo.
 */
export function UndoTreeRenderer({
  model,
  onUndo,
  onPartialRollback
}: {
  model: UndoTreeViewModel;
  onUndo?: (checkpoint: string) => void;
  onPartialRollback?: (checkpoint: string) => void;
}): React.ReactElement {
  return (
    <section
      className="flex flex-col gap-3 rounded-lg border border-[var(--om-border)] bg-[var(--om-surface)] p-4 shadow-sm"
      aria-label="reversible undo tree"
      data-grammar-version={model.grammarVersion}
      data-workspace-open={model.open ? "true" : "false"}
      data-held-statements={model.heldStatements}
      data-escaped-effects={model.escapedEffects}
    >
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <FileClock className="size-4 text-[var(--om-gold)]" aria-hidden="true" />
          <span className="text-sm font-bold text-[var(--om-text-bright)]">Undo Tree</span>
          <Badge tone={model.open ? "ok" : "off"}>{model.open ? "workspace open" : "closed"}</Badge>
        </div>
        <span className="font-mono text-2xs uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
          {model.heldStatements} held · {model.liveCheckpoints.length} checkpoint(s)
        </span>
      </header>

      {model.escapedEffects > 0 ? (
        <p
          className="flex items-start gap-2 rounded-md border border-[color-mix(in_srgb,var(--om-copper)_45%,transparent)] bg-[color-mix(in_srgb,var(--om-copper)_10%,transparent)] px-3 py-2 text-xs text-[var(--om-copper)]"
          data-testid="undo-tree-escape-banner"
        >
          <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
          <span>
            <strong className="font-bold">
              {model.escapedEffects} effect(s) cannot be undone.
            </strong>{" "}
            An undo restores the transaction, not these. Treat them as applied.
          </span>
        </p>
      ) : null}

      <ol className="flex flex-col gap-2">
        {model.nodes.map((node) => (
          <li
            key={node.id}
            className={cn(
              "flex flex-col gap-1 rounded-md border px-3 py-2",
              node.kind === "statement" ? "ml-4 border-dashed" : "border-solid",
              node.status === "escaped"
                ? "border-[color-mix(in_srgb,var(--om-copper)_45%,transparent)]"
                : "border-[var(--om-border)]"
            )}
            data-node-kind={node.kind}
            data-checkpoint-name={node.checkpointName ?? ""}
            data-node-status={node.status}
            data-undoable={node.undoable ? "true" : "false"}
            data-partial-undo={node.partialUndo ? "true" : "false"}
            data-cannot-undo-reason={node.cannotUndoReason ?? ""}
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex min-w-0 items-center gap-2">
                <Badge tone={node.tone}>{node.status}</Badge>
                <span className="truncate font-mono text-xs text-[var(--om-text)]" title={node.label}>
                  {node.label}
                </span>
              </div>
              {node.kind === "checkpoint" && node.undoable ? (
                <button
                  type="button"
                  className="inline-flex min-h-8 items-center rounded-md border border-[var(--om-border)] px-2 py-1 text-2xs font-semibold text-[var(--om-text-bright)] hover:bg-[var(--om-surface-muted)]"
                  onClick={() => onUndo?.(node.checkpointName ?? node.label)}
                >
                  Undo to checkpoint
                </button>
              ) : null}
              {node.kind === "checkpoint" && node.partialUndo ? (
                <button
                  type="button"
                  className="inline-flex min-h-8 items-center rounded-md border border-[color-mix(in_srgb,var(--om-copper)_45%,transparent)] px-2 py-1 text-2xs font-semibold text-[var(--om-copper)] hover:bg-[color-mix(in_srgb,var(--om-copper)_10%,transparent)]"
                  onClick={() => onPartialRollback?.(node.checkpointName ?? node.label)}
                  data-testid="undo-tree-partial-rollback"
                >
                  Partial rollback — cannot undo {model.escapedEffects} effect(s)
                </button>
              ) : null}
            </div>
            {node.cannotUndoReason ? (
              <p
                className={cn(
                  "text-2xs",
                  node.status === "escaped" || node.partialUndo
                    ? "font-semibold text-[var(--om-copper)]"
                    : "text-[var(--om-text-muted)]"
                )}
              >
                {node.status === "escaped" ? "CANNOT UNDO — " : ""}
                {node.cannotUndoReason}
              </p>
            ) : null}
          </li>
        ))}
      </ol>
    </section>
  );
}

export function assertDashboardSkinConformance(skin: DashboardSkin): void {
  const fixture = skinContractFixture();
  // A skip link is part of the grammar, not one skin's styling choice: it must
  // exist and must reveal itself on focus, or keyboard users are stranded
  // behind the sidebar nav on every route.
  if (!skin.layout.skipLink.trim()) {
    throw new Error(`skin ${skin.name} must provide a skip-to-main-content link class`);
  }
  if (!skin.layout.skipLink.includes("focus-visible:not-sr-only")) {
    throw new Error(`skin ${skin.name} skip link must become visible on keyboard focus`);
  }
  if (typeof skin.renderers.CostBadge !== "function") {
    throw new Error(`skin ${skin.name} must provide a cost-badge renderer`);
  }
  if (typeof skin.renderers.ScnScrubber !== "function") {
    throw new Error(`skin ${skin.name} must provide an SCN-scrubber renderer`);
  }
  if (typeof skin.renderers.MaskBadge !== "function") {
    throw new Error(`skin ${skin.name} must provide an egress-mask renderer`);
  }
  if (typeof skin.renderers.FleetMap !== "function") {
    throw new Error(`skin ${skin.name} must provide a fleet-map renderer`);
  }
  if (typeof skin.renderers.PolicyBadge !== "function") {
    throw new Error(`skin ${skin.name} must provide a policy-narrowing renderer`);
  }
  if (typeof skin.renderers.VectorCluster !== "function") {
    throw new Error(`skin ${skin.name} must provide a vector-cluster renderer`);
  }
  if (typeof skin.renderers.EditionTimeline !== "function") {
    throw new Error(`skin ${skin.name} must provide an edition-timeline renderer`);
  }
  if (typeof skin.renderers.CqnChangeFeed !== "function") {
    throw new Error(`skin ${skin.name} must provide a CQN change-feed renderer`);
  }
  if (typeof skin.renderers.ColumnLineage !== "function") {
    throw new Error(`skin ${skin.name} must provide a column-lineage renderer`);
  }
  // Every one of the four typed edge statuses must render, and a drift edge must
  // never be reported as verified.
  const lineage = fixture.columnLineage;
  const statuses = new Set(lineage.edges.map((edge) => edge.status));
  for (const required of ["verified", "drift-missing", "drift-type-mismatch", "partial"] as const) {
    if (!statuses.has(required)) {
      throw new Error(`column-lineage fixture must include a ${required} edge`);
    }
  }
  // A change scope is always a resource URI (the proven query), never an
  // object-level scope, and repeat callbacks for one scope must coalesce.
  const feed = fixture.cqnChangeFeed;
  if (feed.events.some((event) => !event.scopeIsResource)) {
    throw new Error("a CQN change scope must be a resource URI, never object-level");
  }
  if (!feed.events.some((event) => event.coalesced)) {
    throw new Error("the change-feed fixture must show a coalesced batch");
  }
  // A linear chain: every stage after the root names its single parent, and the
  // linear order is a strict 0..n sequence — never a branch/graph node.
  const timeline = fixture.editionTimeline;
  if (!timeline.linear || timeline.branchedFrom.length > 0) {
    throw new Error("edition-timeline fixture must be a linear chain");
  }
  timeline.stages.forEach((stage, index) => {
    if (stage.order !== index) {
      throw new Error("edition stages must be in strict linear order");
    }
    if (index > 0 && stage.parentEdition === null) {
      throw new Error("every non-root edition stage must name its single parent");
    }
  });
  // The neighbor distances (ranks) must be monotonic non-decreasing, and the
  // panel must never claim a numeric distance the server does not emit.
  const vector = fixture.vectorCluster;
  if (vector.distanceReported !== false) {
    throw new Error("the vector panel must not report a distance the server does not emit");
  }
  for (let i = 1; i < vector.neighbors.length; i++) {
    if (vector.neighbors[i].rank < vector.neighbors[i - 1].rank) {
      throw new Error("vector neighbor distances (ranks) must be monotonic non-decreasing");
    }
  }
  // Policy is monotone: a narrowing may only raise the level it started from.
  const policy = fixture.policyBadge;
  if (policy.effect !== "Narrow" || !policy.narrowedFrom || !policy.narrowedTo) {
    throw new Error("policy-badge fixture must be a narrowing that names both levels");
  }
  if (
    CLEARANCE_LADDER.findIndex((step) => step.level === policy.narrowedTo) <
    CLEARANCE_LADDER.findIndex((step) => step.level === policy.narrowedFrom)
  ) {
    throw new Error("a policy narrowing must never lower the required level");
  }
  // The fleet map must render every lane the server typed, including the ones it
  // could not read, and must never claim drift for a lane it never compared.
  const fleet = fixture.fleetMap;
  if (fleet.nodes.length !== fleet.profileCount) {
    throw new Error("fleet-map fixture drops a database node");
  }
  if (!fleet.nodes.some((node) => node.status === "unreachable")) {
    throw new Error("fleet-map fixture must keep an unreachable database on the map");
  }
  if (fleet.nodes.some((node) => node.status !== "reachable" && node.drift !== null)) {
    throw new Error("an unread lane must carry no drift verdict");
  }
  // A certified page must name the policy that made every decision, and a
  // transformed column must never render as passed-through.
  const mask = fixture.maskBadge;
  if (mask.status !== "certified" || !mask.policyId || mask.maskedColumns === 0) {
    throw new Error("mask-badge fixture must be a certified page with a transformed column");
  }
  if (mask.columns.some((column) => column.masked !== (column.action !== "pass"))) {
    throw new Error("a mask decision's action and masked flag disagree");
  }
  // The scrubbed SCN must always sit inside the confirmed range, and the range
  // must be built only from snapshots the server actually served.
  const scrubber = fixture.scnScrubber;
  if (
    scrubber.min === null ||
    scrubber.max === null ||
    scrubber.current === null ||
    scrubber.current < scrubber.min ||
    scrubber.current > scrubber.max
  ) {
    throw new Error("scn-scrubber fixture must clamp the current SCN inside its confirmed range");
  }
  if (scrubber.marks.some((mark) => mark.status === "refused" && mark.scn === scrubber.max)) {
    throw new Error("a refused snapshot must never define the scrubber range");
  }
  // A refused statement must carry BOTH numbers the server disclosed; a badge
  // that shows a verdict without its evidence is the failure mode here.
  if (
    fixture.costBadge.verdict !== "refused" ||
    fixture.costBadge.estimate === null ||
    fixture.costBadge.ceiling === null
  ) {
    throw new Error("cost-badge fixture must be a refusal carrying its estimate and ceiling");
  }
  if (typeof skin.renderers.UndoTree !== "function") {
    throw new Error(`skin ${skin.name} must provide an undo-tree renderer`);
  }
  // The undo-tree fixture pins the Arc I honesty rule: the sequence-touching
  // node is not undoable and says why, and the checkpoint above it degrades to
  // a partial rollback rather than promising a plain Undo.
  const escaped = fixture.undoTree.nodes.filter((node) => node.status === "escaped");
  if (escaped.length === 0 || escaped.some((node) => node.undoable || !node.cannotUndoReason)) {
    throw new Error("undo-tree fixture must carry a non-undoable node with a stated reason");
  }
  if (fixture.undoTree.nodes.some((node) => node.undoable && node.cannotUndoReason)) {
    throw new Error("an undoable node must not also carry a cannot-undo reason");
  }
  if (typeof skin.renderers.VerdictProof !== "function") {
    throw new Error(`skin ${skin.name} must provide a verdict-proof renderer`);
  }
  if (fixture.verdictProof.proofStatus !== "verified") {
    throw new Error("verdict-proof fixture must verify against its own registry and binding");
  }
  if (fixture.verdictProof.derivation.some((step) => !step.registered)) {
    throw new Error("verdict-proof fixture carries an unregistered rule id");
  }
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

// A live UTC wall-clock for the status strip. Client-derived (never a server
// round-trip); ticks once a second, cleaned up on unmount.
function useUtcClock(): string {
  const [now, setNow] = React.useState<Date>(() => new Date());
  React.useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 1_000);
    return () => window.clearInterval(id);
  }, []);
  return `${now.toISOString().slice(11, 19)} UTC`;
}

function defaultStatusHeadline(model: GroundControlViewModel): string {
  const posture = model.clearanceStatus.blocked > 0 ? "HOLD FOR GO" : "ALL LANES NOMINAL";
  switch (model.verdict) {
    case "GO":
      return `FAIL-CLOSED · ${posture}`;
    case "SYNC":
      return "FAIL-CLOSED · SYNCING";
    case "NO-GO":
      return "FAIL-CLOSED · NO-GO";
  }
}

function toneTextClass(tone: DashboardTone): string {
  switch (tone) {
    case "ok":
      return "text-[var(--om-sage)]";
    case "warn":
      return "text-[var(--om-copper)]";
    case "info":
      return "text-[var(--om-gold)]";
    case "off":
      return "text-[var(--om-text-muted)]";
    case "neutral":
      return "text-[var(--om-text-bright)]";
  }
}

// One divider-aware column of the status strip: stacked (top hairline) on
// narrow viewports, a row of left-hairline cells on wide ones.
function StripCell({
  children,
  className
}: {
  children: React.ReactNode;
  className?: string;
}): React.ReactElement {
  return (
    <div
      className={cn(
        "min-w-0 border-t border-[var(--om-border)] pt-3 first:border-t-0 first:pt-0 xl:flex-1 xl:border-l xl:border-t-0 xl:pl-4 xl:pt-0 xl:first:border-l-0 xl:first:pl-0",
        className
      )}
    >
      {children}
    </div>
  );
}

function StatusCount({
  label,
  value,
  tone = "neutral"
}: {
  label: string;
  value: number;
  tone?: DashboardTone;
}): React.ReactElement {
  return (
    <div className="inline-flex items-baseline gap-1.5">
      <span className={cn("font-mono text-sm font-bold tabular-nums", toneTextClass(tone))}>{value}</span>
      <span className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
        {label}
      </span>
    </div>
  );
}

function GroundControl2DRenderer({
  model
}: {
  model: GroundControlViewModel;
}): React.ReactElement {
  const clock = useUtcClock();
  const goNoGo = model.signatures.find((signature) => signature.id === "go_no_go");
  const otherSignatures = model.signatures.filter((signature) => signature.id !== "go_no_go");
  const statusHeadline = model.statusLine?.headline ?? defaultStatusHeadline(model);
  const statusTone =
    model.statusLine?.tone ??
    (model.verdict === "GO" ? "ok" : model.verdict === "SYNC" ? "info" : "warn");
  return (
    <section
      className="flex flex-col rounded-lg border border-[var(--om-border)] bg-[var(--om-surface)] px-4 py-3 shadow-sm xl:flex-row xl:items-stretch"
      aria-label="ground control"
      data-grammar-version={model.grammarVersion}
      data-health={model.health}
      data-verdict={model.verdict}
    >
      {/* Announce the fail-closed verdict to assistive tech. Kept separate from
          the per-second UTC clock below so the live region fires only on a
          GO/NO-GO change, not every tick. */}
      <span className="sr-only" role="status" aria-live="polite">
        Fail-closed guard status: {model.verdict}. {statusHeadline}.
      </span>
      {goNoGo ? (
        <StripCell className="xl:max-w-52">
          <SignatureCell signature={goNoGo} />
        </StripCell>
      ) : null}
      <StripCell className="xl:flex-[1.4]">
        <div className="flex items-center justify-between gap-3">
          <p className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
            Fail-Closed Guard
          </p>
          <span
            className="font-mono text-2xs tabular-nums text-[var(--om-text-muted)]"
            aria-label="coordinated universal time"
          >
            {clock}
          </span>
        </div>
        <p className={cn("mt-1 truncate font-serif text-lg font-semibold", toneTextClass(statusTone))}>
          {statusHeadline}
        </p>
        {model.counts ? (
          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
            <StatusCount label="Lanes" value={model.counts.lanes} />
            <StatusCount label="Prod" value={model.counts.prod} />
            <StatusCount
              label="Held"
              value={model.counts.held}
              tone={model.counts.held > 0 ? "warn" : "neutral"}
            />
          </div>
        ) : null}
      </StripCell>
      <StripCell>
        <div className="flex items-center justify-between gap-3">
          <p className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
            Clearance Ladder
          </p>
          <Badge tone={model.clearanceStatus.tone}>{model.clearanceStatus.label}</Badge>
        </div>
        <div className="mt-3 flex flex-wrap gap-1.5">
          {model.clearanceLadder.map((step) => (
            <span
              key={step.level}
              className={cn(
                "inline-flex h-7 min-w-8 items-center justify-center rounded-md border px-2 font-mono text-xs font-bold",
                clearanceClass(step.level)
              )}
              data-clearance-level={step.level}
              data-clearance-ordinal={step.ordinal}
              title={step.label}
            >
              {CLEARANCE_ROMAN[step.ordinal] ?? step.label}
            </span>
          ))}
        </div>
      </StripCell>
      {otherSignatures.map((signature) => (
        <StripCell key={signature.id}>
          <SignatureCell signature={signature} />
        </StripCell>
      ))}
    </section>
  );
}

// CHAIN — the audit hash-chain strip (Appendix G). A dedicated, always-visible
// band below Ground Control: INTACT / height / verified Ns ago, straight from
// the operator audit-tail verify. Tamper (broken) reads rust; a healthy chain
// reads sage. The "verified ago" ticks live off the last successful fetch.
export function ChainStrip({ chain }: { chain: GroundControlChain }): React.ReactElement {
  const nowMs = useClockTick();
  const tone: DashboardTone =
    chain.status === "intact"
      ? "ok"
      : chain.status === "broken"
        ? "warn"
        : chain.status === "syncing"
          ? "info"
          : "off";
  const headline =
    chain.status === "intact"
      ? "INTACT"
      : chain.status === "broken"
        ? "BROKEN"
        : chain.status === "syncing"
          ? "SYNCING"
          : "UNAVAILABLE";
  const verifiedAgo =
    chain.verifiedAtMs === null ? "—" : formatAgo(Math.max(0, nowMs - chain.verifiedAtMs));
  return (
    <section
      className="flex flex-wrap items-center gap-x-6 gap-y-2 rounded-lg border border-[var(--om-border)] bg-[var(--om-surface)] px-4 py-2.5 shadow-sm"
      aria-label="audit chain"
      data-chain-status={chain.status}
    >
      {/* Announce audit-chain tamper/verify state; a broken chain is a security
          event an operator must not miss. Separate from the ticking "verified
          ago" so the live region fires on a status change, not every tick. */}
      <span className="sr-only" role="status" aria-live="polite">
        Audit chain {headline}
        {chain.height === null ? "" : `, height ${chain.height}`}.
      </span>
      <div className="flex items-center gap-2.5">
        <Link2 className="size-4 text-[var(--om-text-muted)]" aria-hidden="true" />
        <span className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
          Chain
        </span>
        <span className={cn("font-mono text-sm font-bold", toneTextClass(tone))}>{headline}</span>
        <Badge tone={tone}>{chain.label}</Badge>
      </div>
      <div className="flex items-baseline gap-1.5">
        <span className="font-mono text-sm font-bold tabular-nums text-[var(--om-text-bright)]">
          {chain.height === null ? "—" : chain.height.toLocaleString()}
        </span>
        <span className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
          height
        </span>
      </div>
      <div className="flex items-baseline gap-1.5">
        <span className="font-mono text-sm tabular-nums text-[var(--om-text)]">{verifiedAgo}</span>
        <span className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
          verified ago
        </span>
      </div>
    </section>
  );
}

// A once-a-second tick used by the strips that render live elapsed time.
function useClockTick(): number {
  const [now, setNow] = React.useState<number>(() => Date.now());
  React.useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(id);
  }, []);
  return now;
}

function formatAgo(deltaMs: number): string {
  const seconds = Math.floor(deltaMs / 1_000);
  if (seconds < 60) {
    return `${seconds}s ago`;
  }
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `${minutes}m ago`;
  }
  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
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
    <div className="flex min-w-0 items-center gap-3">
      <div className="flex size-10 shrink-0 items-center justify-center rounded-md border border-[var(--om-border)] bg-[var(--om-surface-muted)] text-[var(--om-text-muted)]">
        <Icon className="size-5" aria-hidden="true" />
      </div>
      <div className="min-w-0">
        <p className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
          {signature.label}
        </p>
        <div className="mt-1 flex min-w-0 items-center gap-2">
          <p className="truncate font-mono text-sm font-bold text-[var(--om-text-bright)]">
            {signature.value}
          </p>
          <Badge tone={signature.tone}>{signature.tone}</Badge>
        </div>
        <p className="mt-1 truncate text-xs font-semibold text-[var(--om-text-muted)]">
          {signature.detail}
        </p>
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
        <div className="min-w-0 rounded-md border border-[var(--om-border)] bg-[var(--om-surface-muted)] p-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="text-xs font-bold uppercase text-[var(--om-text-muted)]">Big Board</p>
              <h2 className="mt-2 font-mono text-3xl font-bold leading-none text-[var(--om-text-bright)]">
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
            <div className="rounded-md border border-dashed border-[var(--om-border)] bg-[var(--om-surface)] p-4">
              <p className="font-mono text-sm font-bold text-[var(--om-text-bright)]">NO ACTIVE LANES</p>
              <p className="mt-2 text-sm font-semibold text-[var(--om-text-muted)]">idle</p>
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
      <div className="flex items-center justify-between gap-3 border-b border-[var(--om-border)] px-4 py-3">
        <div>
          <h2 className="text-base font-bold text-[var(--om-text-bright)]">Big Board</h2>
          <p className="mt-1 text-sm text-[var(--om-text-muted)]">{renderer.label}</p>
        </div>
        <Badge tone={verdictTone(model.verdict)}>{model.verdict}</Badge>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] border-collapse text-left">
          <thead className="bg-[var(--om-surface-muted)] text-xs uppercase text-[var(--om-text-muted)]">
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
          <tbody className="divide-y divide-[var(--om-border)]">
            {model.sessions.length === 0 ? (
              <tr>
                <td className="px-4 py-8 text-center text-sm font-semibold text-[var(--om-text-muted)]" colSpan={7}>
                  No active lanes
                </td>
              </tr>
            ) : (
              model.sessions.map((session) => (
                <tr key={`${session.laneId}:${session.subjectIdHash}`} className="bg-[var(--om-surface)]">
                  <td className="px-4 py-4 align-top">
                    <p className="font-mono text-sm font-semibold text-[var(--om-text-bright)]">{session.laneId}</p>
                    <p className="mt-1 break-all font-mono text-xs text-[var(--om-text-muted)]">
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
                  <td className="px-4 py-4 align-top font-mono text-sm text-[var(--om-text)]">
                    {Math.round(session.activity * 100)}%
                  </td>
                  <td className="px-4 py-4 align-top font-mono text-sm text-[var(--om-text)]">
                    {session.requests}
                  </td>
                  <td className="px-4 py-4 align-top font-mono text-sm text-[var(--om-text)]">
                    {session.blocked}
                  </td>
                  <td className="px-4 py-4 align-top font-mono text-sm text-[var(--om-text)]">
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
      className="min-w-0 rounded-md border border-[var(--om-border)] bg-[var(--om-surface)] p-4"
      data-clearance-level={session.clearance}
      data-health={session.status}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="truncate font-mono text-sm font-bold text-[var(--om-text-bright)]">{session.laneId}</p>
          <p className="mt-1 break-all font-mono text-xs text-[var(--om-text-muted)]">{session.subjectIdHash}</p>
        </div>
        <Badge tone={healthTone(session.status)}>{session.status}</Badge>
      </div>
      <div className="mt-4 h-2 rounded-full bg-[var(--om-surface-elevated)]" aria-hidden="true">
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
      <div className="flex size-9 shrink-0 items-center justify-center rounded-md border border-[var(--om-border)] bg-[var(--om-surface)] text-[var(--om-text)]">
        <Icon className="size-4" aria-hidden="true" />
      </div>
      <div>
        <p className="text-xs font-bold uppercase text-[var(--om-text-muted)]">{label}</p>
        <p className="mt-1 font-mono text-sm font-bold text-[var(--om-text-bright)]">{value}</p>
      </div>
    </div>
  );
}

// Color IS clearance (Appendix G grammar): every level reads its own --om
// clearance token — sage READ_ONLY, gold READ_WRITE, copper DDL, rust ADMIN —
// so the ramp is identical in Carved Light and the forced-colors fallback.
function clearanceClass(level: ClearanceLevel): string {
  const token = CLEARANCE_TOKEN[level];
  return `border-[color-mix(in_srgb,var(${token})_50%,transparent)] bg-[color-mix(in_srgb,var(${token})_14%,transparent)] text-[var(${token})]`;
}

const CLEARANCE_TOKEN: Record<ClearanceLevel, `--om-clearance-${string}`> = {
  READ_ONLY: "--om-clearance-read-only",
  READ_WRITE: "--om-clearance-read-write",
  DDL: "--om-clearance-ddl",
  ADMIN: "--om-clearance-admin"
};

// Roman-numeral rank for the I·II·III·IV clearance spine.
const CLEARANCE_ROMAN = ["I", "II", "III", "IV"] as const;

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
