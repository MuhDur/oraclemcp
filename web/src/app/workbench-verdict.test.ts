import { describe, expect, it } from "vitest";

import { workbenchVerdictFromAction } from "./App";
import type { WorkbenchActionData } from "./operator-client";

// Arc L honesty: the Workbench "Classifier Verdict" badge must reflect the
// ACTUAL admission the guard proved on the wire. A statement the guard blocked
// or has not yet admitted must never render as a green PASS, and an absent
// verdict must render as unknown, never as pass (bead oraclemcp-tmmi).

// The served console forwards the tool's JSON-RPC result verbatim, so the
// verdict fields live under mcp_response.result.structuredContent (the same
// shape decodeOperatorOutcome and every App from* reader unwrap).
const action = (structured: Record<string, unknown>): WorkbenchActionData => ({
  status: "ok",
  mcp_tool: "oracle_execute",
  mcp_response: { result: { structuredContent: structured } }
});

describe("workbench classifier verdict honesty", () => {
  it("renders a gate_decision=blocked preview as refused, never pass", () => {
    const verdict = workbenchVerdictFromAction(
      action({
        danger: "DESTRUCTIVE",
        required_level: "DDL",
        gate_decision: "blocked",
        reason: "protected profile is read-only"
      })
    );
    expect(verdict?.status).toBe("refused");
    expect(verdict?.refused).toBe(true);
    expect(verdict?.status).not.toBe("pass");
  });

  it("treats a FORBIDDEN statement as refused", () => {
    const verdict = workbenchVerdictFromAction(
      action({ danger: "FORBIDDEN", gate_decision: "blocked" })
    );
    expect(verdict?.status).toBe("refused");
  });

  it("renders require_step_up as a step-up, never a green pass", () => {
    const verdict = workbenchVerdictFromAction(
      action({
        danger: "GUARDED",
        required_level: "READ_WRITE",
        gate_decision: "require_step_up"
      })
    );
    expect(verdict?.status).toBe("step_up");
    expect(verdict?.refused).toBe(false);
    expect(verdict?.status).not.toBe("pass");
  });

  it("renders an explicitly allowed statement as pass", () => {
    const verdict = workbenchVerdictFromAction(
      action({ danger: "SAFE", required_level: "READ_ONLY", gate_decision: "allow" })
    );
    expect(verdict?.status).toBe("pass");
  });

  it("treats a proven-SAFE statement with no gate as pass", () => {
    // SAFE is the classifier's proof of read-only admission at the default level.
    const verdict = workbenchVerdictFromAction(
      action({ danger: "SAFE", required_level: "READ_ONLY" })
    );
    expect(verdict?.status).toBe("pass");
  });

  it("treats an executed (rolled-back) statement as pass even without a gate", () => {
    // A statement that actually ran against Oracle was admitted; rolled_back /
    // rows_affected is real evidence of admission, not a default to pass.
    const verdict = workbenchVerdictFromAction(
      action({
        danger: "GUARDED",
        required_level: "READ_WRITE",
        rolled_back: true,
        committed: false,
        rows_affected: 4
      })
    );
    expect(verdict?.status).toBe("pass");
  });

  it("reports a DESTRUCTIVE danger with no recognized gate as unknown, never pass", () => {
    // The bug: a present-but-unproven verdict defaulted to a green PASS. It must
    // fail closed to unknown.
    const verdict = workbenchVerdictFromAction(
      action({ danger: "DESTRUCTIVE", required_level: "DDL" })
    );
    expect(verdict?.status).toBe("unknown");
    expect(verdict?.status).not.toBe("pass");
  });

  it("returns null when the response carries no verdict at all", () => {
    expect(workbenchVerdictFromAction(action({ row_count: 0, rows: [] }))).toBeNull();
    expect(workbenchVerdictFromAction(null)).toBeNull();
  });
});
