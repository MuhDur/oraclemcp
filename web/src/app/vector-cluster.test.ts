import { describe, expect, it } from "vitest";

import { toVectorClusterViewModel } from "./presentation-model";
import { parseVectorCluster, type WorkbenchActionData } from "./operator-client";

// Arc F vector cluster. oracle_semantic_search runs through the same policy /
// masking / audit path as oracle_query and orders neighbors by VECTOR_DISTANCE
// but never egresses the distance value. The console reflects exactly what the
// server emits — the rank (monotonic by construction), the mask certificate,
// and used_index=null when the server did not inspect a plan — and nothing more.

function action(mcp: Record<string, unknown>): WorkbenchActionData {
  return { status: "ok", mcp_tool: "oracle_semantic_search", mcp_response: mcp };
}

const MASK_CERT = {
  schema_version: 1,
  profile: "prod_read",
  policy_id: "sha256:policy",
  decisions: [
    { column: "DOC_ID", oracle_type: "NUMBER", action: "pass", source: "pass" },
    { column: "SECRET_NOTE", oracle_type: "VARCHAR2", action: "mask", source: "rule", rule_index: 0 }
  ]
};

describe("vector cluster parsing", () => {
  it("projects the k neighbors in the server's returned distance order", () => {
    const input = parseVectorCluster(
      action({
        metric: "COSINE",
        k: 3,
        used_index: null,
        columns: ["DOC_ID", "TITLE"],
        row_count: 3,
        rows: [
          { DOC_ID: 1001, TITLE: "A" },
          { DOC_ID: 1042, TITLE: "B" },
          { DOC_ID: 1099, TITLE: "C" }
        ]
      })
    );
    const model = toVectorClusterViewModel(input);
    expect(model.status).toBe("results");
    expect(model.metric).toBe("COSINE");
    expect(model.k).toBe(3);
    expect(model.returned).toBe(3);
    expect(model.neighbors.map((n) => n.rank)).toEqual([0, 1, 2]);
    // The distance is NOT egressed: the model never carries a numeric distance.
    expect(model.distanceReported).toBe(false);
    // Rows are rendered in column order.
    expect(model.neighbors[0].cells).toEqual(["1001", "A"]);
  });

  it("reflects masked columns and never surfaces a masked cell as real", () => {
    const model = toVectorClusterViewModel(
      parseVectorCluster(
        action({
          metric: "COSINE",
          k: 2,
          used_index: null,
          columns: ["DOC_ID", "SECRET_NOTE"],
          row_count: 2,
          rows: [
            { DOC_ID: 1001, SECRET_NOTE: "'?'" },
            { DOC_ID: 1042, SECRET_NOTE: "'?'" }
          ],
          mask_certificate: MASK_CERT
        })
      )
    );
    expect(model.maskedColumns).toBe(1);
    expect(model.maskPolicyId).toBe("sha256:policy");
    expect(model.neighbors.every((n) => n.masked)).toBe(true);
    expect(model.tone).toBe("warn");
  });

  it("passes used_index through as null (server did not inspect a plan), never inferred", () => {
    const model = toVectorClusterViewModel(
      parseVectorCluster(
        action({ metric: "DOT", k: 1, used_index: null, columns: ["ID"], rows: [{ ID: 1 }] })
      )
    );
    expect(model.usedIndex).toBeNull();

    const indexed = toVectorClusterViewModel(
      parseVectorCluster(
        action({ metric: "DOT", k: 1, used_index: true, columns: ["ID"], rows: [{ ID: 1 }] })
      )
    );
    expect(indexed.usedIndex).toBe(true);
  });

  it("shows a refusal (unproven filter predicate) rather than an empty cluster", () => {
    const model = toVectorClusterViewModel(
      parseVectorCluster(null, {
        state: "refused",
        message: "oracle_semantic_search filter is unavailable; refusing an unproven predicate",
        nextSteps: [],
        errorClass: "POLICY_DENIED"
      })
    );
    expect(model.status).toBe("refused");
    expect(model.refusalReason).toContain("refusing an unproven predicate");
    expect(model.neighbors).toHaveLength(0);
  });

  it("distinguishes an empty result from a refusal", () => {
    const model = toVectorClusterViewModel(
      parseVectorCluster(action({ metric: "COSINE", k: 10, used_index: null, columns: ["ID"], rows: [] }))
    );
    expect(model.status).toBe("empty");
    expect(model.returned).toBe(0);
    expect(model.refusalReason).toBeNull();
  });

  it("stays honest when the metric is not one it recognizes", () => {
    const model = toVectorClusterViewModel(
      parseVectorCluster(action({ metric: "MANHATTAN", k: 1, used_index: null, columns: ["ID"], rows: [{ ID: 1 }] }))
    );
    // An unknown metric is reported as null, not silently coerced.
    expect(model.metric).toBeNull();
  });
});
