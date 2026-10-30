import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { toEditionTimelineViewModel } from "./presentation-model";
import { parseEditionProposals, type EditionProposalsData } from "./operator-client";
import { EditionTimelineRenderer } from "./skin";

// Arc D edition timeline. Oracle editions are linear (each child has exactly one
// parent base_edition). The console orders the proposal chain into a straight
// timeline and flags any non-linear shape rather than flattening it.

function data(proposals: Array<Pick<EditionProposalsData["proposals"][number],
  "proposal_id" | "parent_edition" | "child_edition" | "status"> & { objects?: string[] }>): EditionProposalsData {
  return { source: "self_lane", proposals: proposals.map((proposal) => ({
    schema_version: 3 as const,
    proposal_revision: proposal.status === "reviewing" ? 3 : 0,
    stage_revision: proposal.status === "reviewing" ? 1 : 0,
    verification_revision: proposal.status === "reviewing" ? 1 : null,
    review_revision: proposal.status === "reviewing" ? 1 : null,
    expires_at: 2_000_000_000,
    database_identity: proposal.status === "reviewing"
      ? { db_unique_name: "SYNTHETIC_DB", dbid: "42", container_uid: "9001" }
      : null,
    ...proposal
  })) };
}

describe("edition proposal parsing", () => {
  it("prompts retirement for expired requests while preserving the topology", () => {
    const model = toEditionTimelineViewModel([
      { proposalId: "expired", baseEdition: "ORA$BASE", childEdition: "EXPIRED_CHILD", status: "expired", objectCount: 0 }
    ]);
    expect(model.linear).toBe(true);
    expect(model.tone).toBe("warn");
    expect(model.detail).toContain("retire their child editions: EXPIRED_CHILD");
  });
  it("reads base->child edges and drops rows missing either edition", () => {
    const input = parseEditionProposals(
      data([
        {
          proposal_id: "p1",
          parent_edition: "ORA$BASE",
          child_edition: "REVIEW_1",
          status: "reviewing",
          objects: ["HR.EMP", "HR.DEPT"]
        },
        // Malformed: missing child edition — dropped, never guessed.
        {
          proposal_id: "p2",
          parent_edition: "REVIEW_1",
          child_edition: "",
          status: "open"
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
          parent_edition: "ORA$BASE",
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
      { proposalId: "b", baseEdition: "REVIEW_1", childEdition: "REVIEW_2", status: "open", objectCount: 1 },
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
      { proposalId: "a", baseEdition: "ORA$BASE", childEdition: "LEFT", status: "open", objectCount: 1 },
      { proposalId: "b", baseEdition: "ORA$BASE", childEdition: "RIGHT", status: "open", objectCount: 1 }
    ]);
    expect(model.linear).toBe(false);
    expect(model.branchedFrom).toEqual(["ORA$BASE"]);
    expect(model.headline).toContain("Non-linear");
  });

  it("detects a two-node cycle and terminates with bounded stages", () => {
    const model = toEditionTimelineViewModel([
      { proposalId: "a", baseEdition: "A", childEdition: "B", status: "open", objectCount: 1 },
      { proposalId: "b", baseEdition: "B", childEdition: "A", status: "reviewing", objectCount: 1 }
    ]);

    expect(model.linear).toBe(false);
    expect(model.cycleEditions).toEqual(["A", "B"]);
    expect(model.stages.map((stage) => stage.edition)).toEqual(["A", "B"]);
    expect(model.warnings.join(" ")).toContain("Cycle detected");
    const markup = renderToStaticMarkup(EditionTimelineRenderer({ model }));
    expect(markup).toContain("non-linear");
    expect(markup).not.toContain("branched");
    expect(markup).not.toContain("Branch points:");
  });

  it("detects a self-cycle without looping", () => {
    const model = toEditionTimelineViewModel([
      { proposalId: "self", baseEdition: "A", childEdition: "A", status: "open", objectCount: 1 }
    ]);

    expect(model.linear).toBe(false);
    expect(model.cycleEditions).toEqual(["A"]);
    expect(model.stages).toHaveLength(1);
  });

  it("detects multiple parents and disconnected chains", () => {
    const multipleParents = toEditionTimelineViewModel([
      { proposalId: "a", baseEdition: "A", childEdition: "C", status: "open", objectCount: 1 },
      { proposalId: "b", baseEdition: "B", childEdition: "C", status: "open", objectCount: 1 }
    ]);
    const disconnected = toEditionTimelineViewModel([
      { proposalId: "a", baseEdition: "A", childEdition: "B", status: "open", objectCount: 1 },
      { proposalId: "b", baseEdition: "C", childEdition: "D", status: "open", objectCount: 1 }
    ]);

    expect(multipleParents.linear).toBe(false);
    expect(multipleParents.multipleParentEditions).toEqual(["C"]);
    expect(disconnected.linear).toBe(false);
    expect(disconnected.disconnectedComponents).toBe(2);
    expect(disconnected.stages.map((stage) => stage.edition)).toEqual(["A", "B", "C", "D"]);
    expect(disconnected.warnings.join(" ")).toContain("2 component(s)");
    const markup = renderToStaticMarkup(EditionTimelineRenderer({ model: disconnected }));
    expect(markup).toContain("non-linear");
    expect(markup).not.toContain("Branch points:");
  });

  it("reports an empty board without inventing a chain", () => {
    const model = toEditionTimelineViewModel([]);
    expect(model.stages).toHaveLength(0);
    expect(model.linear).toBe(true);
    expect(model.warnings).toEqual([]);
    expect(model.headline).toBe("No edition proposals");
    expect(model.tone).toBe("off");
  });
});
