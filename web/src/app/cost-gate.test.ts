import { describe, expect, it } from "vitest";

import { toCostBadgeViewModel } from "./presentation-model";
import {
  OperatorOutcomeError,
  parseCostEstimate,
  parseQueryCostRefusal,
  profileCostCeiling,
  type ConfigOpsStatusData,
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

describe("configured cost ceiling (the ceiling is on the wire)", () => {
  // /operator/v1/config publishes every profile's max_query_cost (Rust:
  // ProfileMetadata). The console must read it there instead of waiting for the
  // gate to refuse something — by then the number is too late to be useful.
  const config = (
    profiles: { name: string; max_query_cost?: number | null }[],
    defaultProfile = "prod_read"
  ): ConfigOpsStatusData => ({
    source: "self_lane",
    status: {
      target_path: "/etc/oraclemcp/config.toml",
      target_exists: true,
      current_sha256: "sha256:cfg",
      default_profile: defaultProfile,
      profiles
    }
  });

  it("reads the active profile's ceiling straight from the config", () => {
    const read = profileCostCeiling(
      config([
        { name: "prod_read", max_query_cost: 50_000 },
        { name: "staging", max_query_cost: 1_000_000 }
      ]),
      "staging"
    );
    expect(read.ceiling).toBe(1_000_000);
    expect(read.source).toBe("config");
    expect(read.ungated).toBe(false);
  });

  it("falls back to the default profile when the active one is unknown", () => {
    const read = profileCostCeiling(config([{ name: "prod_read", max_query_cost: 50_000 }]), null);
    expect(read.ceiling).toBe(50_000);
    expect(read.source).toBe("config");
  });

  it("distinguishes 'no ceiling configured' from 'we do not know'", () => {
    // The profile exists and declares no max_query_cost: the gate is OFF for it.
    const ungated = profileCostCeiling(config([{ name: "prod_read" }]), "prod_read");
    expect(ungated.ceiling).toBeNull();
    expect(ungated.ungated).toBe(true);

    // The profile is not in the config at all: the console knows nothing, and
    // must not report that as "ungated".
    const unknown = profileCostCeiling(config([{ name: "prod_read" }]), "ghost_profile");
    expect(unknown.ceiling).toBeNull();
    expect(unknown.ungated).toBe(false);
    expect(unknown.source).toBe("unknown");

    // No config at all: same — unknown, not ungated.
    expect(profileCostCeiling(null, "prod_read")).toEqual({
      ceiling: null,
      source: "unknown",
      ungated: false
    });
  });

  it("shows the configured ceiling before anything has been priced", () => {
    const model = toCostBadgeViewModel({
      refusal: null,
      estimate: null,
      estimateUnavailable: null,
      note: null,
      planRows: [],
      ceiling: 50_000,
      ceilingSource: "config",
      ungated: false
    });
    // The regression this bead fixes: a numeric ceiling with NO refusal in play.
    expect(model.ceiling).toBe(50_000);
    expect(model.ceilingSource).toBe("config");
    expect(model.headline).toContain("Ceiling 50000");
  });

  it("judges an estimate against the configured ceiling, before the gate refuses", () => {
    const model = toCostBadgeViewModel({
      refusal: null,
      estimate: 1_200,
      estimateUnavailable: null,
      note: null,
      planRows: [],
      ceiling: 50_000,
      ceilingSource: "config",
      ungated: false
    });
    expect(model.verdict).toBe("within_ceiling");
    expect(model.ratio).toBeCloseTo(0.024, 3);
    expect(model.detail).toContain("profile configuration");
  });

  it("lets a lower refusal-disclosed ceiling win over the configured one", () => {
    // A per-call max_query_cost meets the profile ceiling with min(), so the
    // refusal's number is the effective one and may be lower than the config's.
    const model = toCostBadgeViewModel({
      refusal: parseQueryCostRefusal(costRefusalResponse()),
      estimate: null,
      estimateUnavailable: null,
      note: null,
      planRows: [],
      ceiling: 5_000_000,
      ceilingSource: "config",
      ungated: false
    });
    expect(model.verdict).toBe("refused");
    expect(model.ceiling).toBe(50_000);
    expect(model.ceilingSource).toBe("refusal");
  });

  it("reports an ungated profile as ungated, not as an unknown ceiling", () => {
    const model = toCostBadgeViewModel({
      refusal: null,
      estimate: null,
      estimateUnavailable: null,
      note: null,
      planRows: [],
      ceiling: null,
      ceilingSource: "unknown",
      ungated: true
    });
    expect(model.verdict).toBe("ungated");
    expect(model.headline).toBe("No cost ceiling configured");
    expect(model.detail).toContain("not cost-gated");
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

  it("calls a statement within_ceiling only against a ceiling actually in force", () => {
    // No ceiling known — neither from the config nor from a refusal. The badge
    // shows the price and says nothing about a budget it cannot see.
    const noCeiling = toCostBadgeViewModel({
      refusal: null,
      estimate: 1_200,
      estimateUnavailable: null,
      note: null,
      planRows: [],
      ceiling: null
    });
    expect(noCeiling.verdict).toBe("estimated");
    expect(noCeiling.ceiling).toBeNull();
    expect(noCeiling.ceilingSource).toBe("unknown");
    expect(noCeiling.ratio).toBeNull();

    // With a ceiling in force (config or refusal), the estimate can be judged.
    const judged = toCostBadgeViewModel({
      refusal: null,
      estimate: 1_200,
      estimateUnavailable: null,
      note: null,
      planRows: [],
      ceiling: 50_000
    });
    expect(judged.verdict).toBe("within_ceiling");
    expect(judged.ratio).toBeCloseTo(0.024, 3);
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
