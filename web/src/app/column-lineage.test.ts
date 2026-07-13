import { describe, expect, it } from "vitest";

import { isLineageEdgeStatus, toColumnLineageViewModel } from "./presentation-model";
import { parseColumnLineage, type WorkbenchActionData } from "./operator-client";

// Arc K column-lineage / drift. Each source-derived edge is cross-checked
// against the live catalog and carries a typed status: verified, drift-missing,
// drift-type-mismatch, or partial. The console renders the marker the backend
// assigned — a drift is never upgraded to verified — and reports "not reported"
// when the lineage surface projected nothing.

function action(mcp: Record<string, unknown>): WorkbenchActionData {
  return { status: "ok", mcp_tool: "oracle_lineage", mcp_response: mcp };
}

describe("column lineage parsing", () => {
  it("reads typed edges (from/to/status) off the tool response", () => {
    const input = parseColumnLineage(
      action({
        edges: [
          { from: "HR.V.C", to: "HR.T.C", status: "verified" },
          { source: "HR.V.D", target: "HR.T.D", edge_status: "drift-missing" }
        ]
      })
    );
    expect(input.edges).toHaveLength(2);
    expect(input.edges?.[0].status).toBe("verified");
    expect(input.edges?.[1].from).toBe("HR.V.D");
    expect(input.edges?.[1].status).toBe("drift-missing");
  });

  it("returns null edges when the response projects no lineage", () => {
    expect(parseColumnLineage(action({ found: false })).edges).toBeNull();
    expect(parseColumnLineage(null).edges).toBeNull();
  });
});

describe("column lineage view-model", () => {
  it("renders each typed status and counts verified/drift/partial", () => {
    const model = toColumnLineageViewModel({
      edges: [
        { from: "a", to: "b", status: "verified" },
        { from: "c", to: "d", status: "drift-missing" },
        { from: "e", to: "f", status: "drift-type-mismatch" },
        { from: "g", to: "h", status: "partial" }
      ]
    });
    expect(model.status).toBe("edges");
    expect(model.verifiedCount).toBe(1);
    expect(model.driftCount).toBe(2);
    expect(model.partialCount).toBe(1);
    expect(model.tone).toBe("warn");
  });

  it("never upgrades a drift edge to verified", () => {
    const model = toColumnLineageViewModel({
      edges: [{ from: "a", to: "b", status: "drift-type-mismatch" }]
    });
    expect(model.edges[0].status).toBe("drift-type-mismatch");
    expect(model.verifiedCount).toBe(0);
  });

  it("drops an edge whose status it cannot type, never showing it as verified", () => {
    expect(isLineageEdgeStatus("verified")).toBe(true);
    expect(isLineageEdgeStatus("mystery")).toBe(false);
    const model = toColumnLineageViewModel({
      edges: [
        { from: "a", to: "b", status: "mystery" },
        { from: "c", to: "d", status: "verified" }
      ]
    });
    expect(model.edges.map((e) => e.from)).toEqual(["c"]);
  });

  it("reports not_reported vs empty distinctly", () => {
    expect(toColumnLineageViewModel({ edges: null }).status).toBe("not_reported");
    expect(toColumnLineageViewModel({ edges: [] }).status).toBe("empty");
  });
});
