import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  ExplorerGlobalSearchPanel,
  ExplorerObjectsPanel,
  type ExplorerObjectRow,
  type ExplorerSourceHitRow
} from "./App";

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

const sourceRow: ExplorerSourceHitRow = {
  owner: "HR",
  name: "PAYROLL_API",
  objectType: "PACKAGE",
  line: "42",
  text: "procedure reconcile_payroll is",
  raw: {}
};

function renderGlobalSearchSelection(
  selectedRef: { owner: string; name: string; objectType: string } | null,
  selectedHitKey: string | null
): string {
  return renderToStaticMarkup(
    <ExplorerGlobalSearchPanel
      searchText="payroll"
      includeObjects
      includeSource
      allSchemas
      sourceType=""
      request={{
        needle: "payroll",
        includeObjects: true,
        includeSource: true,
        allSchemas: true,
        sourceType: "",
        owner: "",
        maxRows: 100
      }}
      objectRows={[row]}
      sourceRows={[sourceRow, { ...sourceRow, line: "43", text: "end reconcile_payroll;" }]}
      objectPending={false}
      sourcePending={false}
      objectError={null}
      sourceError={null}
      objectLimit={null}
      sourceLimit={null}
      invalidObjectRows={0}
      invalidSourceRows={0}
      selectedRef={selectedRef}
      selectedHitKey={selectedHitKey}
      canSearch
      onSearchTextChange={() => {}}
      onIncludeObjectsChange={() => {}}
      onIncludeSourceChange={() => {}}
      onAllSchemasChange={() => {}}
      onSourceTypeChange={() => {}}
      onSearch={() => {}}
      onSelectObject={() => {}}
      onSelectSource={() => {}}
    />
  );
}

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

  it("announces and marks the selected global object result", () => {
    const markup = renderGlobalSearchSelection(
      { owner: "HR", name: "EMPLOYEES", objectType: "TABLE" },
      `object:${JSON.stringify(["HR", "EMPLOYEES", "TABLE"])}`
    );

    expect(markup).toContain('aria-label="Select HR.EMPLOYEES (TABLE) for details"');
    expect(markup).toContain('data-selected="true"');
    expect(markup).toContain('Selected HR.EMPLOYEES (TABLE). Details are available below.');
    expect(markup.match(/aria-pressed="true"/g)).toHaveLength(1);
  });

  it("marks only the selected global source result when one object has multiple matches", () => {
    const markup = renderGlobalSearchSelection(
      { owner: "HR", name: "PAYROLL_API", objectType: "PACKAGE" },
      `source:${JSON.stringify(["HR", "PAYROLL_API", "PACKAGE", "42"])}`
    );

    expect(markup).toContain(
      'aria-label="Select HR.PAYROLL_API (PACKAGE, line 42) for details"'
    );
    expect(markup).toContain('Selected HR.PAYROLL_API (PACKAGE). Details are available below.');
    expect(markup.match(/aria-pressed="true"/g)).toHaveLength(1);
  });
});
