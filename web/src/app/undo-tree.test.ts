import { describe, expect, it } from "vitest";

import { toUndoTreeViewModel, type UndoTreeEntry } from "./presentation-model";
import {
  parseUndoOutcome,
  parseWorkspaceView,
  type WorkbenchActionData
} from "./operator-client";

// Arc I undo-tree. The console reads the server's `workspace` view and its
// `cannot_undo` labels verbatim, and never offers an Undo for an effect the
// backend said a rollback cannot take back.

const SEQUENCE_REASON =
  "sequence.NEXTVAL: the sequence is advanced outside the transaction, so a rollback does not restore it";

function action(mcp: Record<string, unknown>): WorkbenchActionData {
  return { status: "ok", mcp_tool: "oracle_execute", mcp_response: mcp };
}

function checkpointEntry(name: string): UndoTreeEntry {
  return {
    id: `cp-${name}`,
    kind: "checkpoint",
    checkpointName: name,
    label: name,
    cannotUndo: [],
    fullyReverted: null
  };
}

describe("workspace response parsing", () => {
  it("reads the live workspace view off a tool response", () => {
    const view = parseWorkspaceView(
      action({
        checkpoint: "SP_A",
        workspace: { open: true, checkpoints: ["SP_A", "SP_B"], held_statements: 3 }
      })
    );
    expect(view).toEqual({ open: true, checkpoints: ["SP_A", "SP_B"], heldStatements: 3 });
  });

  it("carries cannot_undo verbatim and marks the statement not fully reverted", () => {
    const outcome = parseUndoOutcome(
      action({
        rolled_back: true,
        non_transactional_effect: true,
        cannot_undo: [SEQUENCE_REASON],
        fully_reverted: false
      })
    );
    expect(outcome.cannotUndo).toEqual([SEQUENCE_REASON]);
    expect(outcome.fullyReverted).toBe(false);
  });

  it("never reads silence as reverted", () => {
    // No rollback/hold claim and no fully_reverted field: the console has no
    // evidence either way, so it must not manufacture reversibility.
    expect(parseUndoOutcome(action({ committed: true })).fullyReverted).toBeNull();
    expect(parseUndoOutcome(null).fullyReverted).toBeNull();
    // A plainly rolled-back statement with no escape label is reverted.
    expect(parseUndoOutcome(action({ rolled_back: true })).fullyReverted).toBe(true);
    // A held statement is pending and undoable.
    expect(parseUndoOutcome(action({ held: true })).held).toBe(true);
  });

  it("reads the undo response's target and discarded count", () => {
    const outcome = parseUndoOutcome(
      action({
        undone_to: "SP_A",
        discarded_statements: 2,
        released_checkpoints: ["SP_B"],
        workspace: { open: true, checkpoints: ["SP_A"], held_statements: 0 }
      })
    );
    expect(outcome.undoneTo).toBe("SP_A");
    expect(outcome.discardedStatements).toBe(2);
    expect(outcome.workspace?.checkpoints).toEqual(["SP_A"]);
  });
});

describe("undo tree", () => {
  it("offers a plain undo only for a live checkpoint with reversible work above it", () => {
    const model = toUndoTreeViewModel({
      workspace: { open: true, checkpoints: ["SP_A"], heldStatements: 1 },
      entries: [
        checkpointEntry("SP_A"),
        {
          id: "st-1",
          kind: "statement",
          checkpointName: "SP_A",
          label: "UPDATE hr.employees SET salary = salary * 1.03",
          cannotUndo: [],
          fullyReverted: true
        }
      ]
    });
    expect(model.open).toBe(true);
    expect(model.escapedEffects).toBe(0);
    const [checkpoint, statement] = model.nodes;
    expect(checkpoint.undoable).toBe(true);
    expect(checkpoint.partialUndo).toBe(false);
    expect(checkpoint.cannotUndoReason).toBeNull();
    expect(statement.status).toBe("held");
    expect(statement.undoable).toBe(true);
  });

  it("refuses to call a sequence-touching statement undoable and states the reason", () => {
    const model = toUndoTreeViewModel({
      workspace: { open: true, checkpoints: ["SP_A"], heldStatements: 1 },
      entries: [
        checkpointEntry("SP_A"),
        {
          id: "st-1",
          kind: "statement",
          checkpointName: "SP_A",
          label: "INSERT INTO hr.audit_log VALUES (seq.NEXTVAL, …)",
          cannotUndo: [SEQUENCE_REASON],
          fullyReverted: false
        }
      ]
    });
    const statement = model.nodes[1];
    expect(statement.status).toBe("escaped");
    expect(statement.undoable).toBe(false);
    expect(statement.cannotUndoReason).toBe(SEQUENCE_REASON);
    expect(model.escapedEffects).toBe(1);

    // The checkpoint above it degrades to a partial rollback: rolling back to it
    // is still useful, but it is not a plain Undo and must not be sold as one.
    const checkpoint = model.nodes[0];
    expect(checkpoint.undoable).toBe(false);
    expect(checkpoint.partialUndo).toBe(true);
    expect(checkpoint.cannotUndoReason).toContain(SEQUENCE_REASON);
  });

  it("treats fully_reverted=false as an escape even with no cannot_undo text", () => {
    const model = toUndoTreeViewModel({
      workspace: { open: true, checkpoints: ["SP_A"], heldStatements: 1 },
      entries: [
        checkpointEntry("SP_A"),
        {
          id: "st-1",
          kind: "statement",
          checkpointName: "SP_A",
          label: "BEGIN autonomous_pkg.log; END;",
          cannotUndo: [],
          fullyReverted: false
        }
      ]
    });
    expect(model.nodes[1].undoable).toBe(false);
    expect(model.nodes[1].cannotUndoReason).toContain("not fully reverted");
  });

  it("marks a statement with no reversibility evidence unproven, never undoable", () => {
    const model = toUndoTreeViewModel({
      workspace: { open: true, checkpoints: ["SP_A"], heldStatements: 1 },
      entries: [
        checkpointEntry("SP_A"),
        {
          id: "st-1",
          kind: "statement",
          checkpointName: "SP_A",
          label: "statement observed in the audit chain",
          cannotUndo: [],
          fullyReverted: null
        }
      ]
    });
    expect(model.nodes[1].status).toBe("unproven");
    expect(model.nodes[1].undoable).toBe(false);
    expect(model.nodes[1].cannotUndoReason).toContain("no reversibility evidence");
  });

  it("never offers a checkpoint Oracle has released as an undo target", () => {
    const model = toUndoTreeViewModel({
      // SP_B is gone: an undo to SP_A erased it, or a transaction boundary did.
      workspace: { open: true, checkpoints: ["SP_A"], heldStatements: 0 },
      entries: [checkpointEntry("SP_A"), checkpointEntry("SP_B")]
    });
    const released = model.nodes[1];
    expect(released.status).toBe("released");
    expect(released.undoable).toBe(false);
    expect(released.cannotUndoReason).toContain("released this savepoint");
  });

  it("closes the tree when there is no workspace at all", () => {
    const model = toUndoTreeViewModel({ workspace: null, entries: [] });
    expect(model.open).toBe(false);
    expect(model.heldStatements).toBe(0);
    expect(model.liveCheckpoints).toEqual([]);
    expect(model.nodes).toEqual([]);
  });
});
