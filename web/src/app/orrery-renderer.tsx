import * as React from "react";

import { Badge, Surface } from "../components/ui/primitives";
import type { BigBoardRendererProps } from "./skin";

export default function OrreryRenderer({
  model,
  renderer
}: BigBoardRendererProps): React.ReactElement {
  return (
    <Surface
      className="overflow-hidden border-[var(--om-border)]"
      aria-label="big board orrery fallback"
      data-renderer={renderer.kind}
      data-grammar-version={model.grammarVersion}
    >
      <div className="flex flex-col gap-3 border-b border-zinc-200 px-4 py-3 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 className="text-base font-bold text-zinc-950">Big Board</h2>
          <p className="mt-1 text-sm text-zinc-500">Orrery</p>
        </div>
        <Badge tone="info">fallback</Badge>
      </div>
      <div className="grid gap-3 p-4 md:grid-cols-3">
        <OrreryFact label="Verdict" value={model.verdict} />
        <OrreryFact label="Active" value={model.totals.activeLanes} />
        <OrreryFact label="Requests" value={model.totals.requests} />
      </div>
    </Surface>
  );
}

function OrreryFact({
  label,
  value
}: {
  label: string;
  value: number | string;
}): React.ReactElement {
  return (
    <div className="rounded-md border border-zinc-200 bg-zinc-50 p-3">
      <p className="text-xs font-bold uppercase text-zinc-500">{label}</p>
      <p className="mt-2 font-mono text-sm font-bold text-zinc-950">{value}</p>
    </div>
  );
}
