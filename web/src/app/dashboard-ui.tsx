import * as React from "react";

import { cn } from "../lib/utils";

const WHOLE_NUMBER_FORMATTER = new Intl.NumberFormat("en-US", { maximumFractionDigits: 0 });

export function formatNumber(value: number): string {
  return WHOLE_NUMBER_FORMATTER.format(value);
}

export function shortHash(value: string | null | undefined): string {
  if (!value) {
    return "hash unavailable";
  }
  if (value.length <= 28) {
    return value;
  }
  return `${value.slice(0, 19)}…${value.slice(-8)}`;
}

export function prettyJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

export const OM_LABEL = "mb-2 block text-sm font-semibold text-[var(--om-text)]";
export const OM_INPUT =
  "min-h-11 w-full rounded-md border border-[var(--om-control-border)] bg-[var(--om-surface-muted)] px-3 text-sm text-[var(--om-text)] outline-none focus-visible:border-[var(--om-gold)] focus-visible:ring-2 focus-visible:ring-[color-mix(in_srgb,var(--om-gold)_35%,transparent)]";
export const OM_TEXTAREA =
  "w-full resize-y rounded-md border border-[var(--om-control-border)] bg-[var(--om-bg)] p-3 font-mono text-sm leading-6 text-[var(--om-text)] outline-none focus-visible:border-[var(--om-gold)] focus-visible:ring-2 focus-visible:ring-[color-mix(in_srgb,var(--om-gold)_35%,transparent)]";
export const OM_CHECKBOX = "size-5 rounded border-[var(--om-control-border)] accent-[var(--om-gold)]";
export const OM_CHECK_LABEL = "flex min-h-11 items-center gap-2 text-sm font-semibold text-[var(--om-text)]";
export const OM_CODE = "overflow-auto rounded-md bg-[var(--om-bg)] p-3 text-xs leading-5 text-[var(--om-text)]";

export function ConsolePanel({
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

export function ConsoleFact({
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

export function PageFrame({
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
  React.useEffect(() => {
    document.title = `${title} · Oracle MCP`;
  }, [title]);
  return (
    <div className="space-y-4">
      <header className="border-b border-[var(--om-border)] pb-4">
        <div className="min-w-0">
          <p className="text-xs font-bold uppercase text-[var(--om-gold)]">{eyebrow}</p>
          <h2
            id="dashboard-page-title"
            tabIndex={-1}
            className="mt-1 text-3xl font-bold tracking-normal text-[var(--om-text-bright)] outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[var(--om-focus)]"
          >
            {title}
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-[var(--om-text-muted)]">{description}</p>
        </div>
      </header>
      {children}
    </div>
  );
}
