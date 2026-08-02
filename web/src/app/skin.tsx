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

import { Badge } from "../components/ui/primitives";
import { cn } from "../lib/utils";
import {
  CLEARANCE_LADDER,
  DASHBOARD_GRAMMAR,
  REQUIRED_THEME_MODES,
  type ClearanceLevel,
  type DashboardTone,
  type GroundControlChain,
  type GroundControlViewModel,
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
  type UndoTreeViewModel,
  type VerdictProofViewModel
} from "./presentation-model";

export type DashboardTheme = {
  name: string;
  modes: readonly string[];
  cssVars: Readonly<Record<`--om-${string}`, string>>;
};

export type DashboardSkin = {
  name: string;
  grammarVersion: typeof DASHBOARD_GRAMMAR.grammarVersion;
  theme: DashboardTheme;
  renderers: {
    VerdictProof: React.ComponentType<{ model: VerdictProofViewModel }>;
    MaskBadge: React.ComponentType<{ model: MaskBadgeViewModel }>;
    PolicyBadge: React.ComponentType<{ model: PolicyBadgeViewModel }>;
    EditionTimeline: React.ComponentType<{ model: EditionTimelineViewModel }>;
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
  }
};

// The production skin names only renderers mounted by the end-user dashboard.
// Keeping retired experiments out of this object lets Rollup discard their
// implementation code even while repository policy keeps that source in place.
export const OMCP_SKIN: DashboardSkin = {
  name: "omcp-carved-light",
  grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
  theme: CARVED_LIGHT_THEME,
  renderers: {
    VerdictProof: VerdictProofInspector,
    MaskBadge: MaskBadgeRenderer,
    EditionTimeline: EditionTimelineRenderer,
    PolicyBadge: PolicyBadgeRenderer
  },
  layout: {
    appShell: "min-h-screen bg-[var(--om-bg)] text-[var(--om-text)]",
    frame: "mx-auto flex w-full max-w-[1440px] flex-col gap-4 px-4 py-4 md:px-6 lg:flex-row lg:py-6",
    sidebar:
      "flex shrink-0 flex-col gap-4 border-b border-[var(--om-border)] pb-4 lg:w-64 lg:border-b-0 lg:border-r lg:pb-0 lg:pr-4",
    logoMark:
      "flex size-10 items-center justify-center rounded-lg bg-[var(--om-clearance-read-only)] text-[var(--om-bg)]",
    nav: "grid grid-cols-2 gap-2 sm:grid-cols-3 lg:flex lg:flex-col",
    navLink:
      "inline-flex min-h-11 items-center gap-2 rounded-md px-3 py-2 text-sm font-semibold text-[var(--om-text)] hover:bg-[var(--om-surface)] hover:text-[var(--om-text-bright)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--om-focus)] [&[data-status=active]]:bg-[var(--om-surface)] [&[data-status=active]]:text-[var(--om-gold)] [&[data-status=active]]:shadow-sm",
    skipLink:
      "sr-only focus-visible:not-sr-only focus-visible:absolute focus-visible:left-4 focus-visible:top-4 focus-visible:z-50 focus-visible:inline-flex focus-visible:min-h-10 focus-visible:items-center focus-visible:rounded-md focus-visible:bg-[var(--om-surface)] focus-visible:px-4 focus-visible:py-2 focus-visible:text-sm focus-visible:font-semibold focus-visible:text-[var(--om-gold)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--om-focus)]"
  }
};

assertDashboardSkinConformance(OMCP_SKIN);

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
          {model.derivation.map((step) => (
            <li
              key={`${step.ruleId}:${step.construct}`}
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
          <Badge tone={model.tone}>{model.linear ? "linear" : "non-linear"}</Badge>
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

      {model.branchedFrom.length > 0 ? (
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
        model.driftCount > 0 || model.unverifiedCount > 0
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
      data-unverified-count={model.unverifiedCount}
      data-malformed-count={model.malformedCount}
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
          {model.edges.map((edge, index) => (
            <li
              key={JSON.stringify([edge.from, edge.to, edge.reportedStatus, index])}
              className={cn(
                "flex flex-wrap items-center gap-2 rounded-md border px-3 py-2",
                edge.status.startsWith("drift") || edge.status === "unverified"
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
  if (!skin.layout.skipLink.trim()) {
    throw new Error(`skin ${skin.name} must provide a skip-to-main-content link class`);
  }
  if (!skin.layout.skipLink.includes("focus-visible:not-sr-only")) {
    throw new Error(`skin ${skin.name} skip link must become visible on keyboard focus`);
  }
  if (skin.grammarVersion !== DASHBOARD_GRAMMAR.grammarVersion) {
    throw new Error(`skin ${skin.name} has an unsupported grammar version`);
  }
  assertSameSet(
    REQUIRED_THEME_MODES,
    skin.theme.modes,
    `skin ${skin.name} theme mode coverage`
  );
  const requiredRenderers = ["EditionTimeline", "MaskBadge", "PolicyBadge", "VerdictProof"];
  assertSameSet(requiredRenderers, Object.keys(skin.renderers), `skin ${skin.name} renderer coverage`);
  for (const renderer of requiredRenderers) {
    if (typeof skin.renderers[renderer as keyof DashboardSkin["renderers"]] !== "function") {
      throw new Error(`skin ${skin.name} must provide the ${renderer} renderer`);
    }
  }
  if (!skin.layout.navLink.includes("focus-visible")) {
    throw new Error(`skin ${skin.name} navigation links must expose a keyboard focus indicator`);
  }
  const requiredThemeTokens = [
    "--om-bg",
    "--om-text",
    "--om-focus",
    "--om-clearance-read-only",
    "--om-clearance-read-write",
    "--om-clearance-ddl",
    "--om-clearance-admin"
  ] as const;
  for (const token of requiredThemeTokens) {
    if (!/^#[0-9a-f]{6}$/i.test(skin.theme.cssVars[token] ?? "")) {
      throw new Error(`skin ${skin.name} must provide the ${token} color token`);
    }
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

export function GroundControl2DRenderer({
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

function assertSameSet(expected: readonly string[], actual: readonly string[], label: string): void {
  const expectedSorted = [...expected].sort().join("\0");
  const actualSorted = [...actual].sort().join("\0");
  if (expectedSorted !== actualSorted) {
    throw new Error(`${label} mismatch`);
  }
}

export { CLEARANCE_LADDER };
