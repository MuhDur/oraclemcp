import { describe, expect, it } from "vitest";

import { toMaskBadgeViewModel } from "./presentation-model";
import { parseMaskCertificate, type WorkbenchActionData } from "./operator-client";

// Arc M egress masking. The mask certificate rides on the page it governs, and
// the server emits it ONLY when the policy transformed a column — so a page
// without one proves nothing, and the console must not claim otherwise.

const action = (mcp: Record<string, unknown>): WorkbenchActionData => ({
  status: "ok",
  mcp_tool: "oracle_query",
  mcp_response: mcp
});

const CERTIFICATE = {
  schema_version: 1,
  profile: "prod_read",
  policy_id: "sha256:policy",
  audit_entry_hash: "sha256:audit",
  decisions: [
    { column: "EMPLOYEE_ID", oracle_type: "NUMBER", action: "pass", source: "pass" },
    {
      column: "EMAIL",
      oracle_type: "VARCHAR2",
      action: "tokenize",
      source: "rule",
      rule_index: 0,
      rule_tag: "pii:email",
      salt_id: "salt-2026-07"
    },
    {
      column: "NOTES",
      oracle_type: "CLOB",
      action: "mask",
      source: "mask_unknown_default"
    }
  ]
};

describe("mask certificate parsing", () => {
  it("reads the policy, the audit binding and every column decision", () => {
    const certificate = parseMaskCertificate(action({ mask_certificate: CERTIFICATE }));
    expect(certificate?.policyId).toBe("sha256:policy");
    expect(certificate?.profile).toBe("prod_read");
    expect(certificate?.auditHash).toBe("sha256:audit");
    expect(certificate?.decisions.map((decision) => decision.column)).toEqual([
      "EMPLOYEE_ID",
      "EMAIL",
      "NOTES"
    ]);
    expect(certificate?.decisions[1].saltId).toBe("salt-2026-07");
    expect(certificate?.decisions[1].ruleIndex).toBe(0);
  });

  it("returns null when the page carries no certificate", () => {
    // The happy path of an unmasked page: no certificate at all.
    expect(parseMaskCertificate(action({ row_count: 3, rows: [] }))).toBeNull();
    expect(parseMaskCertificate(null)).toBeNull();
  });

  it("drops a decision whose action or source it cannot decode", () => {
    // Fail-closed: an unknown action must not silently render as "passed".
    const certificate = parseMaskCertificate(
      action({
        mask_certificate: {
          policy_id: "sha256:policy",
          decisions: [
            { column: "A", oracle_type: "NUMBER", action: "teleport", source: "rule" },
            { column: "B", oracle_type: "NUMBER", action: "pass", source: "pass" }
          ]
        }
      })
    );
    expect(certificate?.decisions.map((decision) => decision.column)).toEqual(["B"]);
  });
});

describe("mask badge view-model", () => {
  it("marks transformed columns masked and passed columns unmasked", () => {
    const model = toMaskBadgeViewModel(
      parseMaskCertificate(action({ mask_certificate: CERTIFICATE }))
    );
    expect(model.status).toBe("certified");
    expect(model.policyId).toBe("sha256:policy");
    expect(model.maskedColumns).toBe(2);
    expect(model.passedColumns).toBe(1);

    const byColumn = new Map(model.columns.map((column) => [column.column, column]));
    expect(byColumn.get("EMPLOYEE_ID")?.masked).toBe(false);
    expect(byColumn.get("EMAIL")?.masked).toBe(true);
    expect(byColumn.get("EMAIL")?.detail).toContain("pii:email");
    expect(byColumn.get("NOTES")?.masked).toBe(true);
    expect(byColumn.get("NOTES")?.detail).toContain("fail-closed");
    expect(model.tone).toBe("warn");
  });

  it("reports an absent certificate as absence of proof", () => {
    const model = toMaskBadgeViewModel(null);
    expect(model.status).toBe("no_certificate");
    expect(model.policyId).toBeNull();
    expect(model.columns).toHaveLength(0);
    expect(model.maskedColumns).toBe(0);
    expect(model.detail).toContain("only when the policy transformed a column");
    expect(model.detail).toContain("not proof that nothing was masked");
  });

  it("says so when a certificate is not yet bound to an audit entry", () => {
    const model = toMaskBadgeViewModel({
      policyId: "sha256:policy",
      profile: null,
      auditHash: null,
      decisions: [
        {
          column: "EMAIL",
          oracleType: "VARCHAR2",
          action: "mask",
          source: "rule",
          ruleIndex: 0,
          ruleTag: null,
          saltId: null
        }
      ]
    });
    expect(model.auditHash).toBeNull();
    expect(model.detail).toContain("not yet bound to an audit entry");
  });

  it("keeps an all-pass certificate honest: certified, zero masked", () => {
    const model = toMaskBadgeViewModel({
      policyId: "sha256:policy",
      profile: "dev",
      auditHash: "sha256:audit",
      decisions: [
        {
          column: "ID",
          oracleType: "NUMBER",
          action: "pass",
          source: "pass",
          ruleIndex: null,
          ruleTag: null,
          saltId: null
        }
      ]
    });
    expect(model.status).toBe("certified");
    expect(model.maskedColumns).toBe(0);
    expect(model.columns[0].masked).toBe(false);
    expect(model.tone).toBe("ok");
  });
});
