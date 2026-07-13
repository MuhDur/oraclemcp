import { describe, expect, it } from "vitest";

import { toEditionTimelineViewModel } from "./presentation-model";
import { parseEditionProposals, type EditionProposalsData } from "./operator-client";

// Arc D edition timeline. Oracle editions are linear (each child has exactly one
// parent base_edition). The console orders the proposal chain into a straight
// timeline and flags any non-linear shape rather than flattening it.

function data(proposals: EditionProposalsData["proposals"]): EditionProposalsData {
  return { source: "self_lane", proposals };
}

describe("edition proposal parsing", () => {
  it("reads base->child edges and drops rows missing either edition", () => {
    const input = parseEditionProposals(
      data([
        {
          proposal_id: "p1",
          base_edition: "ORA$BASE",
          child_edition: "REVIEW_1",
          status: "reviewing",
          objects: ["HR.EMP", "HR.DEPT"]
        },
        // Malformed: missing child edition — dropped, never guessed.
        {
          proposal_id: "p2",
          base_edition: "REVIEW_1",
          child_edition: "",
          status: "requested"
        }
      ])
    );
    expect(input).toHaveLength(1);
    expect(input[0].baseEdition).toBe("ORA$BASE");
    expect(input[0].childEdition).toBe("REVIEW_1");
    expect(input[0].objectCount).toBe(2);
    expect(input[0].status).toBe("reviewing");
  });

  it("reports an unknown status as null, never coerced", () => {
    const input = parseEditionProposals(
      data([
        {
          proposal_id: "p1",
          base_edition: "ORA$BASE",
          child_edition: "REVIEW_1",
          status: "merged" as never
        }
      ])
    );
    expect(input[0].status).toBeNull();
  });
});

describe("edition timeline view-model", () => {
  it("orders a chain into strict linear stages", () => {
    const model = toEditionTimelineViewModel([
      { proposalId: "b", baseEdition: "REVIEW_1", childEdition: "REVIEW_2", status: "requested", objectCount: 1 },
      { proposalId: "a", baseEdition: "ORA$BASE", childEdition: "REVIEW_1", status: "reviewing", objectCount: 2 }
    ]);
    expect(model.linear).toBe(true);
    expect(model.stages.map((s) => s.edition)).toEqual(["ORA$BASE", "REVIEW_1", "REVIEW_2"]);
    expect(model.stages.map((s) => s.order)).toEqual([0, 1, 2]);
    expect(model.stages[0].parentEdition).toBeNull();
    expect(model.stages[1].parentEdition).toBe("ORA$BASE");
    expect(model.stages[2].parentEdition).toBe("REVIEW_1");
    expect(model.branchedFrom).toEqual([]);
  });

  it("flags a branch (a base with two children) as non-linear", () => {
    const model = toEditionTimelineViewModel([
      { proposalId: "a", baseEdition: "ORA$BASE", childEdition: "LEFT", status: "requested", objectCount: 1 },
      { proposalId: "b", baseEdition: "ORA$BASE", childEdition: "RIGHT", status: "requested", objectCount: 1 }
    ]);
    expect(model.linear).toBe(false);
    expect(model.branchedFrom).toEqual(["ORA$BASE"]);
    expect(model.headline).toContain("Non-linear");
  });

  it("reports an empty board without inventing a chain", () => {
    const model = toEditionTimelineViewModel([]);
    expect(model.stages).toHaveLength(0);
    expect(model.linear).toBe(true);
    expect(model.headline).toBe("No edition proposals");
    expect(model.tone).toBe("off");
  });
});
