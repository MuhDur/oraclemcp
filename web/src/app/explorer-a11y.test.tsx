import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ExplorerObjectsPanel, type ExplorerObjectRow } from "./App";

// Explorer objects must be operable without a mouse. Keep the table semantic:
// a real button inside the object cell owns selection, focus, and keyboard
// activation instead of turning the whole row into a counterfeit control.

const row: ExplorerObjectRow = {
  owner: "HR",
  objectName: "EMPLOYEES",
  objectType: "TABLE",
  status: "VALID",
  numRows: "107",
  columnCount: "11",
  lastAnalyzed: "2026-07-01",
  comment: "",
  raw: {}
};

describe("Explorer object controls are keyboard-operable", () => {
  it("uses a native button with an unambiguous accessible name", () => {
    const markup = renderToStaticMarkup(
      <ExplorerObjectsPanel
        rows={[row]}
        selectedRef={null}
        pending={false}
        error={null}
        onSelect={() => {}}
      />
    );
    expect(markup).toContain('<button type="button"');
    expect(markup).toContain('aria-label="View details for HR.EMPLOYEES (TABLE)"');
    expect(markup).toContain('aria-pressed="false"');
    expect(markup).not.toContain('<tr role="button"');
  });

  it("reflects the selected row via aria-pressed", () => {
    const markup = renderToStaticMarkup(
      <ExplorerObjectsPanel
        rows={[row]}
        selectedRef={{ owner: "HR", name: "EMPLOYEES", objectType: "TABLE" }}
        pending={false}
        error={null}
        onSelect={() => {}}
      />
    );
    expect(markup).toContain('aria-pressed="true"');
  });
});
