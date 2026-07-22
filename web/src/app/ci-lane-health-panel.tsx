import * as React from "react";
import { Activity } from "lucide-react";

import { Badge, Surface } from "../components/ui/primitives";
import { cn } from "../lib/utils";
import type { DashboardTone } from "./presentation-model";
import type { CiLaneHealth, CiLaneHealthData } from "./operator-client";

export function CiLaneHealthPanel({
  data,
  pending,
  error
}: {
  data: CiLaneHealthData | null;
  pending: boolean;
  error: unknown;
}): React.ReactElement {
  const tone: DashboardTone = error
    ? "warn"
    : data?.summary.posture === "green"
      ? "ok"
      : data
        ? "warn"
        : pending
          ? "info"
          : "warn";
  const meta = error
    ? "unavailable"
    : data
      ? `${formatNumber(data.lanes.length)} watched · ${data.freshness}`
      : pending
        ? "sync"
        : "unavailable";
  const sourceMessage = error
    ? error instanceof Error
      ? error.message
      : "CI lane request failed"
    : data === null
      ? pending
        ? "Lane evidence is loading. No green claim is available yet."
        : "Lane evidence is unavailable. No green claim is available."
      : data.summary.posture === "green"
        ? "Every catalogued scheduled and advisory lane has fresh successful evidence."
        : data.summary.posture === "not_green"
          ? `${formatNumber(data.summary.not_green)} watched lane${data.summary.not_green === 1 ? " is" : "s are"} not green.`
          : "Lane evidence is incomplete, stale, or still refreshing. No all-green claim is available.";

  return (
    <Surface
      className="overflow-hidden"
      data-ci-lane-posture={data?.summary.posture ?? "unknown"}
      data-ci-lane-freshness={data?.freshness ?? "unavailable"}
    >
      <CiLanePanelHeader
        icon={Activity}
        title="CI Lane Health"
        meta={meta}
        tone={tone}
      />
      <div
        className={cn(
          "border-b px-4 py-3 text-sm font-semibold",
          tone === "ok"
            ? "border-[var(--om-border)] bg-[var(--om-surface-muted)] text-[var(--om-text)]"
            : "border-[var(--om-copper)]/40 bg-[var(--om-copper)]/10 text-[var(--om-text-bright)]"
        )}
        role={tone === "warn" ? "alert" : "status"}
      >
        {sourceMessage}
      </div>
      {data?.errors.length ? (
        <ul className="border-b border-[var(--om-border)] bg-[var(--om-surface-muted)] px-4 py-3 text-xs font-semibold text-[var(--om-text)]">
          {data.errors.map((message) => (
            <li key={message} className="break-words">Source: {message}</li>
          ))}
        </ul>
      ) : null}
      {data && data.lanes.length > 0 ? (
        <div
          className="grid gap-3 p-4 md:grid-cols-2"
          aria-label="scheduled and advisory CI lane health"
        >
          {data.lanes.map((lane) => (
            <CiLaneHealthCard key={`${lane.workflow_file}:${lane.check_name}`} data={data} lane={lane} />
          ))}
        </div>
      ) : (
        <p className="px-4 py-8 text-center text-sm font-semibold text-[var(--om-text-muted)]">
          {pending ? "Waiting for the lane catalog" : "No trustworthy lane catalog"}
        </p>
      )}
      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[var(--om-border)] px-4 py-3 text-xs font-semibold text-[var(--om-text-muted)]">
        <span>Source: {data?.repo ?? "unavailable"}</span>
        <span>Refreshed: {formatCiLaneTimestamp(data?.refreshed_at ?? null)}</span>
      </div>
    </Surface>
  );
}

function CiLaneHealthCard({
  data,
  lane
}: {
  data: CiLaneHealthData;
  lane: CiLaneHealth;
}): React.ReactElement {
  const tone: DashboardTone = lane.state === "success" ? "ok" : "warn";
  const conclusion =
    lane.state === "unknown"
      ? data.freshness === "fresh"
        ? "unknown"
        : data.freshness
      : lane.last_conclusion ?? "unknown";
  const streak = lane.streak.conclusion
    ? `${formatNumber(lane.streak.count)}${lane.streak.capped ? "+" : ""} × ${lane.streak.conclusion}`
    : "unavailable";
  return (
    <article
      className="rounded-md border border-[var(--om-border)] bg-[var(--om-surface)] p-4"
      data-ci-lane-name={lane.check_name}
      data-ci-lane-tier={lane.tier}
      data-ci-lane-state={lane.state}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="break-words text-sm font-bold text-[var(--om-text-bright)]">
            {lane.check_name}
          </p>
          <p className="mt-1 text-xs font-semibold text-[var(--om-text-muted)]">
            {lane.workflow} · {lane.event}
          </p>
        </div>
        <Badge tone={tone}>{conclusion}</Badge>
      </div>
      <dl className="mt-4 grid grid-cols-2 gap-3 text-xs">
        <div>
          <dt className="font-semibold uppercase tracking-wide text-[var(--om-text-muted)]">Tier</dt>
          <dd className="mt-1 font-mono font-semibold text-[var(--om-text)]">{lane.tier}</dd>
        </div>
        <div>
          <dt className="font-semibold uppercase tracking-wide text-[var(--om-text-muted)]">Streak</dt>
          <dd className="mt-1 font-mono font-semibold text-[var(--om-text)]">{streak}</dd>
        </div>
        <div>
          <dt className="font-semibold uppercase tracking-wide text-[var(--om-text-muted)]">Observed</dt>
          <dd className="mt-1 font-mono font-semibold text-[var(--om-text)]">
            {formatCiLaneTimestamp(lane.completed_at)}
          </dd>
        </div>
        <div>
          <dt className="font-semibold uppercase tracking-wide text-[var(--om-text-muted)]">Run</dt>
          <dd className="mt-1 font-mono font-semibold text-[var(--om-text)]">
            {lane.run_url && lane.run_id !== null ? (
              <a
                href={lane.run_url}
                target="_blank"
                rel="noreferrer"
                className="underline decoration-dotted underline-offset-2 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--om-focus)]"
              >
                #{lane.run_id}
              </a>
            ) : (
              "unavailable"
            )}
          </dd>
        </div>
      </dl>
      {lane.source_error ? (
        <p className="mt-3 break-words rounded border border-[var(--om-copper)]/40 bg-[var(--om-copper)]/10 px-2 py-2 text-xs font-semibold text-[var(--om-text-bright)]">
          {lane.source_error}
        </p>
      ) : null}
    </article>
  );
}

function CiLanePanelHeader({
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

function formatCiLaneTimestamp(value: string | null): string {
  if (!value) {
    return "unavailable";
  }
  const unix = /^unix:(\d+)$/.exec(value);
  if (unix) {
    const seconds = Number(unix[1]);
    return Number.isSafeInteger(seconds)
      ? new Date(seconds * 1000).toISOString().replace("T", " ").replace(".000Z", " UTC")
      : "unavailable";
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed)
    ? new Date(parsed).toISOString().replace("T", " ").replace(".000Z", " UTC")
    : "unavailable";
}

function formatNumber(value: number): string {
  return new Intl.NumberFormat("en-US", { maximumFractionDigits: 0 }).format(value);
}
