import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ExplorerObjectsPanel, type ExplorerObjectRow } from "./App";

// 8fn2: Explorer object rows must be operable without a mouse. Each selectable
// row carries role=button, is focusable (tabindex=0), exposes its selection
// state (aria-pressed) and a label, and activates on Enter/Space. The DOM-event
// behavior is not unit-testable in this SSR/node harness, so this pins the
// accessible-name and focusability wiring the keyboard handler depends on.

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

describe("Explorer object rows are keyboard-operable", () => {
  it("marks each selectable row as a focusable button with an accessible name", () => {
    const markup = renderToStaticMarkup(
      <ExplorerObjectsPanel
        rows={[row]}
        selectedRef={null}
        pending={false}
        error={null}
        onSelect={() => {}}
      />
    );
    expect(markup).toContain('role="button"');
    expect(markup).toContain('tabindex="0"');
    expect(markup).toContain('aria-label="Select EMPLOYEES"');
    expect(markup).toContain('aria-pressed="false"');
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
