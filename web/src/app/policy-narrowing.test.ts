import { describe, expect, it } from "vitest";

import { toPolicyBadgeViewModel } from "./presentation-model";
import { OperatorOutcomeError, parsePolicyTightening } from "./operator-client";

// Arc N policy narrowing (ADR 0009). The evaluator is monotone: `base AND
// policy`, with no Allow outcome. It can only Deny or Narrow — raise the
// required level and add conjunctive predicates — so the badge shows what the
// policy TOOK AWAY, and never reports a missing verdict as "no policy applied".

function operatorResponse(data: Record<string, unknown>): Record<string, unknown> {
  return {
    protocol_version: "operator.v1",
    schema_version: 1,
    route: "/operator/v1/actions/execute",
    redaction_level: "operator_redacted",
    data
  };
}

const NARROWING = {
  Narrow: {
    base_required_level: "READ_ONLY",
    required_level: "READ_WRITE",
    matched_rule_ids: ["hr-salary-guard", "tenant-scope"],
    predicates: [
      {
        rule_id: "tenant-scope",
        target: { schema: "HR", object: "EMPLOYEES" },
        sql_fragment: "TENANT_ID = SYS_CONTEXT('OMCP', 'TENANT')"
      }
    ]
  }
};

describe("policy tightening parsing", () => {
  it("reads a narrowing, its levels, rules and predicates off a tool result", () => {
    const tightening = parsePolicyTightening(
      operatorResponse({ mcp_response: { result: { policy: NARROWING } } })
    );
    expect(tightening?.effect).toBe("Narrow");
    if (tightening?.effect !== "Narrow") {
      throw new Error("expected a narrowing");
    }
    expect(tightening.baseRequiredLevel).toBe("READ_ONLY");
    expect(tightening.requiredLevel).toBe("READ_WRITE");
    expect(tightening.matchedRuleIds).toEqual(["hr-salary-guard", "tenant-scope"]);
    expect(tightening.predicates[0].target).toBe("HR.EMPLOYEES");
    expect(tightening.predicates[0].sqlFragment).toContain("TENANT_ID");
  });

  it("reads a denial off a refusal envelope thrown as an error", () => {
    const error = new OperatorOutcomeError(
      { state: "refused", message: "policy denied", nextSteps: [], errorClass: "POLICY_DENIED" },
      operatorResponse({
        mcp_response: {
          result: {
            isError: true,
            structuredContent: {
              error_class: "POLICY_DENIED",
              structured_reason: {
                policy_tightening: {
                  Deny: { reason: "matching_deny_rule", matched_rule_ids: ["no-prod-deletes"] }
                }
              }
            }
          }
        }
      }),
      200
    );
    const tightening = parsePolicyTightening(error);
    expect(tightening?.effect).toBe("Deny");
    if (tightening?.effect !== "Deny") {
      throw new Error("expected a denial");
    }
    expect(tightening.reason).toBe("matching_deny_rule");
    expect(tightening.matchedRuleIds).toEqual(["no-prod-deletes"]);
  });

  it("returns null when the response carries no policy verdict", () => {
    // Today's dispatch does not attach one; the badge must degrade honestly.
    expect(parsePolicyTightening(operatorResponse({ mcp_response: { result: {} } }))).toBeNull();
    expect(parsePolicyTightening(null)).toBeNull();
  });

  it("refuses to decode a narrowing whose levels it cannot read", () => {
    // Inventing a base level would misreport exactly what the policy took away.
    expect(
      parsePolicyTightening(
        operatorResponse({
          mcp_response: {
            result: { policy: { Narrow: { matched_rule_ids: ["x"], predicates: [] } } }
          }
        })
      )
    ).toBeNull();
  });
});

describe("policy badge view-model", () => {
  it("names the level the policy narrowed from and to", () => {
    const model = toPolicyBadgeViewModel(
      parsePolicyTightening(operatorResponse({ mcp_response: { result: { policy: NARROWING } } }))
    );
    expect(model.status).toBe("evaluated");
    expect(model.effect).toBe("Narrow");
    expect(model.narrowedFrom).toBe("READ_ONLY");
    expect(model.narrowedTo).toBe("READ_WRITE");
    expect(model.narrowed).toBe(true);
    expect(model.headline).toBe("Level raised READ_ONLY → READ_WRITE");
    expect(model.matchedRuleIds).toHaveLength(2);
    expect(model.predicates).toHaveLength(1);
  });

  it("reports a denial without pretending anything was narrowed", () => {
    const model = toPolicyBadgeViewModel({
      effect: "Deny",
      reason: "matching_deny_rule",
      matchedRuleIds: ["no-prod-deletes"]
    });
    expect(model.effect).toBe("Deny");
    expect(model.narrowedFrom).toBeNull();
    expect(model.narrowedTo).toBeNull();
    expect(model.narrowed).toBe(false);
    expect(model.denialReason).toBe("matching_deny_rule");
    expect(model.tone).toBe("warn");
  });

  it("reports a missing verdict as not-reported, never as 'no policy applied'", () => {
    const model = toPolicyBadgeViewModel(null);
    expect(model.status).toBe("not_reported");
    expect(model.effect).toBeNull();
    expect(model.narrowed).toBe(false);
    expect(model.headline).toBe("No policy evaluation reported");
    expect(model.detail).toContain("not a statement that no policy applied");
    expect(model.tone).toBe("off");
  });

  it("keeps an identity narrowing honest: evaluated, but nothing taken away", () => {
    const model = toPolicyBadgeViewModel({
      effect: "Narrow",
      baseRequiredLevel: "READ_WRITE",
      requiredLevel: "READ_WRITE",
      matchedRuleIds: [],
      predicates: []
    });
    expect(model.status).toBe("evaluated");
    expect(model.narrowed).toBe(false);
    expect(model.narrowedFrom).toBe("READ_WRITE");
    expect(model.headline).toContain("No policy constraint added");
    expect(model.tone).toBe("ok");
  });

  it("counts a predicate-only narrowing as a narrowing even at the same level", () => {
    const model = toPolicyBadgeViewModel({
      effect: "Narrow",
      baseRequiredLevel: "READ_ONLY",
      requiredLevel: "READ_ONLY",
      matchedRuleIds: ["tenant-scope"],
      predicates: [
        {
          ruleId: "tenant-scope",
          target: "HR.EMPLOYEES",
          sqlFragment: "TENANT_ID = SYS_CONTEXT('OMCP', 'TENANT')"
        }
      ]
    });
    expect(model.narrowed).toBe(true);
    expect(model.narrowedFrom).toBe("READ_ONLY");
    expect(model.narrowedTo).toBe("READ_ONLY");
    expect(model.headline).toBe("Narrowed at READ_ONLY");
  });
});
