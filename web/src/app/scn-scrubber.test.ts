import { describe, expect, it } from "vitest";

import {
  clampScn,
  toScnScrubberViewModel,
  type ScnMarkViewModel
} from "./presentation-model";
import { parseQueryAsOf, type WorkbenchActionData } from "./operator-client";

// Arc A time travel. `oracle_query as_of` is the only history the server offers
// the console: it publishes neither the current SCN nor the flashback retention
// window, so the scrubber's axis is exactly the snapshots that came back.

const confirmed = (scn: number): ScnMarkViewModel => ({
  id: `scn-${scn}`,
  scn,
  label: `SCN ${scn}`,
  status: "confirmed",
  detail: "42 row(s)",
  tone: "ok"
});

const refused = (scn: number): ScnMarkViewModel => ({
  id: `scn-${scn}`,
  scn,
  label: `SCN ${scn}`,
  status: "refused",
  detail: "ORA-01031: insufficient privileges",
  tone: "warn"
});

describe("as-of read", () => {
  it("reads the row count that proves the snapshot was served", () => {
    const data: WorkbenchActionData = {
      status: "ok",
      mcp_tool: "oracle_query",
      mcp_response: { row_count: 41, truncated: false, columns: ["ID"], rows: [] }
    };
    expect(parseQueryAsOf(data)).toEqual({ rowCount: 41, truncated: false });
    // The response carries no SCN — the console must not invent one.
    expect(Object.keys(data.mcp_response as object)).not.toContain("observed_scn");
  });

  it("reports no row count when nothing came back", () => {
    expect(parseQueryAsOf(null)).toEqual({ rowCount: null, truncated: false });
  });
});

describe("scn scrubber", () => {
  it("builds the range only from snapshots the server confirmed", () => {
    const model = toScnScrubberViewModel({
      current: 15_200_400,
      refusal: null,
      marks: [confirmed(15_200_000), confirmed(15_200_400), refused(15_900_000)]
    });
    expect(model.min).toBe(15_200_000);
    expect(model.max).toBe(15_200_400);
    expect(model.rangeKnown).toBe(true);
    expect(model.status).toBe("pinned");
    // The refused snapshot stays visible with its reason, but never widens the axis.
    expect(model.marks).toHaveLength(3);
    expect(model.max).toBeLessThan(15_900_000);
  });

  it("clamps a current SCN outside the confirmed range", () => {
    const model = toScnScrubberViewModel({
      current: 1,
      refusal: null,
      marks: [confirmed(100), confirmed(200)]
    });
    expect(model.current).toBe(100);
    expect(model.clamped).toBe(true);
    expect(model.position).toBe(0);
    expect(model.detail).toContain("clamped");
    expect(clampScn(500, 100, 200)).toBe(200);
    expect(clampScn(150, 100, 200)).toBe(150);
  });

  it("has no axis before any snapshot has been served", () => {
    const model = toScnScrubberViewModel({ current: null, marks: [], refusal: null });
    expect(model.rangeKnown).toBe(false);
    expect(model.min).toBeNull();
    expect(model.max).toBeNull();
    expect(model.position).toBeNull();
    expect(model.status).toBe("unavailable");
    expect(model.detail).toContain("publishes neither the current SCN");
  });

  it("surfaces a refused snapshot verbatim instead of a position", () => {
    const model = toScnScrubberViewModel({
      current: 15_900_000,
      refusal: "ORA-01031: insufficient privileges (the profile lacks FLASHBACK)",
      marks: [confirmed(15_200_000), refused(15_900_000)]
    });
    expect(model.status).toBe("refused");
    expect(model.detail).toContain("ORA-01031");
    // Clamped to the only confirmed snapshot — a refused SCN is not a position.
    expect(model.current).toBe(15_200_000);
    expect(model.tone).toBe("warn");
  });

  it("records a timestamp pin without pretending to know its SCN", () => {
    const model = toScnScrubberViewModel({
      current: null,
      refusal: null,
      marks: [
        confirmed(15_200_000),
        {
          id: "ts-1",
          scn: null,
          label: "2026-07-13 09:00:00",
          status: "timestamp",
          detail: "Oracle resolved this timestamp to an SCN it does not report back",
          tone: "info"
        }
      ]
    });
    // A timestamp mark has no SCN, so it neither moves nor widens the axis.
    expect(model.min).toBe(15_200_000);
    expect(model.max).toBe(15_200_000);
    expect(model.marks[1].scn).toBeNull();
    expect(model.status).toBe("idle");
  });

  it("puts a single confirmed snapshot at the end of its own axis", () => {
    const model = toScnScrubberViewModel({
      current: 500,
      refusal: null,
      marks: [confirmed(500)]
    });
    expect(model.min).toBe(500);
    expect(model.max).toBe(500);
    expect(model.position).toBe(1);
    expect(model.clamped).toBe(false);
  });
});
