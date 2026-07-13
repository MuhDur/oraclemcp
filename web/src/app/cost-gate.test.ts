import { describe, expect, it } from "vitest";

import { toCostBadgeViewModel } from "./presentation-model";
import {
  OperatorOutcomeError,
  parseCostEstimate,
  parseQueryCostRefusal,
  type WorkbenchActionData
} from "./operator-client";

// Arc G cost gate. Only two things price a statement: a `query_cost_refusal`
// block (estimate + the ceiling it broke) and `oracle_explain_plan`'s
// `cost_estimate`. The console reads those and nothing else.

const REFUSAL = {
  estimated_cost: 190_000,
  max_query_cost: 50_000,
  predicate_hints: ['line 2 TABLE ACCESS FULL: filter "SALARY">:B1'],
  plan_rows: [
    {
      id: 0,
      operation: "SELECT STATEMENT",
      cost: 190_000,
      cardinality: 4_200_000
    },
    {
      id: 2,
      operation: "TABLE ACCESS",
      options: "FULL",
      object_name: "EMPLOYEES",
      cost: 189_800,
      cardinality: 4_200_000
    }
  ],
  note: "optimizer costs are relative estimates, not runtime measurements"
};

function operatorResponse(data: Record<string, unknown>): Record<string, unknown> {
  return {
    protocol_version: "operator.v1",
    schema_version: 1,
    route: "/operator/v1/actions/execute",
    redaction_level: "operator_redacted",
    data
  };
}

/** A refused MCP tool call: HTTP 200, result.isError, envelope in structuredContent. */
function costRefusalResponse(): Record<string, unknown> {
  return operatorResponse({
    mcp_response: {
      result: {
        isError: true,
        structuredContent: {
          error_class: "POLICY_DENIED",
          message:
            "oracle_query cost gate refused before execution: query_cost_exceeded (estimated total_cost 190000 exceeds max_query_cost 50000)",
          structured_reason: {
            category: "COST_BUDGET_EXCEEDED",
            query_cost_refusal: REFUSAL
          }
        }
      }
    }
  });
}

describe("cost refusal parsing", () => {
  it("reads the estimate, ceiling, hints and plan rows off a refused tool call", () => {
    const refusal = parseQueryCostRefusal(costRefusalResponse());
    expect(refusal?.estimatedCost).toBe(190_000);
    expect(refusal?.maxQueryCost).toBe(50_000);
    expect(refusal?.predicateHints).toHaveLength(1);
    expect(refusal?.planRows.map((row) => row.id)).toEqual([0, 2]);
    // operation + options are joined the way the plan reads.
    expect(refusal?.planRows[1].operation).toBe("TABLE ACCESS FULL");
    expect(refusal?.planRows[1].objectName).toBe("EMPLOYEES");
    expect(refusal?.note).toContain("relative estimates");
  });

  it("reads a refusal that arrived as a thrown OperatorOutcomeError", () => {
    // A POLICY_DENIED outcome reaches React Query as an error, not as data.
    const error = new OperatorOutcomeError(
      {
        state: "refused",
        message: "cost gate refused",
        nextSteps: [],
        errorClass: "POLICY_DENIED"
      },
      costRefusalResponse(),
      200
    );
    expect(parseQueryCostRefusal(error)?.maxQueryCost).toBe(50_000);
  });

  it("returns null when nothing carried a cost refusal", () => {
    expect(parseQueryCostRefusal(null)).toBeNull();
    expect(parseQueryCostRefusal(operatorResponse({ mcp_response: { result: {} } }))).toBeNull();
    // A refusal for another reason is not a cost refusal.
    expect(
      parseQueryCostRefusal(
        operatorResponse({
          mcp_response: {
            result: {
              isError: true,
              structuredContent: {
                structured_reason: { category: "OPERATING_LEVEL_TOO_LOW" }
              }
            }
          }
        })
      )
    ).toBeNull();
  });
});

describe("explain-plan cost estimate", () => {
  const action = (mcp: Record<string, unknown>): WorkbenchActionData => ({
    status: "ok",
    mcp_tool: "oracle_explain_plan",
    mcp_response: mcp
  });

  it("reads total_cost and the plan rows", () => {
    const read = parseCostEstimate(
      action({
        cost_estimate: {
          summary: { total_cost: 1_200, total_cardinality: 90 },
          rows: [{ id: 0, operation: "SELECT STATEMENT", cost: 1_200, cardinality: 90 }],
          note: "optimizer costs are relative estimates"
        }
      })
    );
    expect(read.totalCost).toBe(1_200);
    expect(read.planRows).toHaveLength(1);
    expect(read.unavailable).toBeNull();
    expect(read.note).toContain("relative estimates");
  });

  it("surfaces cost_estimate_unavailable verbatim instead of a price", () => {
    const read = parseCostEstimate(
      action({ cost_estimate_unavailable: "PLAN_TABLE root total_cost was NULL" })
    );
    expect(read.totalCost).toBeNull();
    expect(read.unavailable).toBe("PLAN_TABLE root total_cost was NULL");

    const model = toCostBadgeViewModel({
      refusal: null,
      estimate: null,
      estimateUnavailable: read.unavailable,
      note: null,
      planRows: [],
      ceiling: null
    });
    expect(model.verdict).toBe("unavailable");
    expect(model.detail).toBe("PLAN_TABLE root total_cost was NULL");
    expect(model.estimate).toBeNull();
  });
});

describe("cost badge view-model", () => {
  it("prices a refusal with both numbers and a full meter", () => {
    const model = toCostBadgeViewModel({
      refusal: parseQueryCostRefusal(costRefusalResponse()),
      estimate: null,
      estimateUnavailable: null,
      note: null,
      planRows: [],
      ceiling: null
    });
    expect(model.verdict).toBe("refused");
    expect(model.estimate).toBe(190_000);
    expect(model.ceiling).toBe(50_000);
    expect(model.ratio).toBe(1);
    expect(model.headline).toContain("exceeds the ceiling");
    expect(model.tone).toBe("warn");
  });

  it("calls a statement within_ceiling only against a ceiling the server disclosed", () => {
    const undisclosed = toCostBadgeViewModel({
      refusal: null,
      estimate: 1_200,
      estimateUnavailable: null,
      note: null,
      planRows: [],
      ceiling: null
    });
    expect(undisclosed.verdict).toBe("estimated");
    expect(undisclosed.ceiling).toBeNull();
    expect(undisclosed.detail).toContain("only when the gate refuses");

    // Once a refusal has disclosed the ceiling, a later estimate can be judged.
    const disclosed = toCostBadgeViewModel({
      refusal: null,
      estimate: 1_200,
      estimateUnavailable: null,
      note: null,
      planRows: [],
      ceiling: 50_000
    });
    expect(disclosed.verdict).toBe("within_ceiling");
    expect(disclosed.ratio).toBeCloseTo(0.024, 3);
  });

  it("stays unknown when nothing has priced the statement", () => {
    const model = toCostBadgeViewModel({
      refusal: null,
      estimate: null,
      estimateUnavailable: null,
      note: null,
      planRows: [],
      ceiling: null
    });
    expect(model.verdict).toBe("unknown");
    expect(model.estimate).toBeNull();
    expect(model.ratio).toBeNull();
    expect(model.tone).toBe("off");
  });
});
