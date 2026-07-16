import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  ConfirmDialog,
  ExplorerObjectsPanel,
  optionalSearchString,
  type ExplorerObjectRow
} from "./App";
import { OMCP_SKIN, assertDashboardSkinConformance, type DashboardSkin } from "./skin";

function explorerRow(n: number): ExplorerObjectRow {
  return {
    owner: "HR",
    objectName: `OBJ_${n}`,
    objectType: "TABLE",
    status: "VALID",
    numRows: "1",
    columnCount: "1",
    lastAnalyzed: "2026-07-01",
    comment: "",
    raw: {}
  };
}

function explorerMarkup(count: number): string {
  return renderToStaticMarkup(
    <ExplorerObjectsPanel
      rows={Array.from({ length: count }, (_, i) => explorerRow(i))}
      selectedRef={null}
      pending={false}
      error={null}
      onSelect={() => {}}
    />
  );
}

// 2ekf: the Web Interface Guidelines polish pass. This harness renders to static
// markup, so — as explorer-a11y.test.tsx already notes — DOM-event behavior
// (the Tab focus trap, focus return) is not unit-testable here. These pin the
// structure and the skin contract those behaviors are built on.

describe("the console's own confirmation dialog", () => {
  const markup = renderToStaticMarkup(
    <ConfirmDialog
      id="lane-cancel"
      title="Cancel lane"
      body="This kills its Oracle session and grants."
      confirmLabel="Cancel lane"
      onCancel={() => {}}
      onConfirm={() => {}}
    />
  );

  it("is a labelled modal dialog, not a bare div", () => {
    expect(markup).toContain('role="dialog"');
    expect(markup).toContain('aria-modal="true"');
    // aria-modal is only honest with a backdrop covering what it claims is inert.
    expect(markup).toContain('data-omcp-dialog-backdrop="lane-cancel"');
    expect(markup).toContain('aria-labelledby="lane-cancel-confirm-title"');
    expect(markup).toContain('id="lane-cancel-confirm-title"');
  });

  it("offers a cancel alongside the destructive confirm", () => {
    expect(markup).toContain("Cancel lane");
    expect(markup).toContain("Cancel<");
  });

  it("renders the busy state instead of re-arming the confirm", () => {
    const busy = renderToStaticMarkup(
      <ConfirmDialog
        id="lane-cancel"
        title="Cancel lane"
        body="body"
        confirmLabel="Cancel lane"
        busy
        onCancel={() => {}}
        onConfirm={() => {}}
      />
    );
    expect(busy).toContain("Working");
    expect(busy).toContain("disabled");
  });
});

describe("the Explorer object list windows only when it is worth it", () => {
  it("renders an ordinary page in full, so it stays server-renderable", () => {
    // The default page is 100 rows. Windowing needs a live scroll element to
    // measure, which a server-rendered pass has none of — so an ordinary list
    // must not opt in, or it would render empty.
    const markup = explorerMarkup(100);
    expect(markup).not.toContain("data-omcp-virtualized");
    expect(markup).toContain("OBJ_0");
    expect(markup).toContain("OBJ_99");
  });

  it("marks a large page as windowed and gives it a scroll viewport", () => {
    const markup = explorerMarkup(1000);
    expect(markup).toContain('data-omcp-virtualized="objects"');
    expect(markup).toContain("overflow-y-auto");
  });

  it("shows every row until the virtualizer has measured, never a blank list", () => {
    // Before a scroll element exists to measure — and if measurement ever fails
    // — the panel must fall back to the whole list. A slow list is a nuisance;
    // a blank one is a lie. This harness has no layout, so it exercises exactly
    // that unmeasured path.
    const markup = explorerMarkup(1000);
    expect(markup).toContain("OBJ_0");
    expect(markup).toContain("OBJ_999");
  });

  it("keeps every row's accessible name and count honest at both sizes", () => {
    expect(explorerMarkup(100)).toContain('aria-label="Select OBJ_0"');
    // The header always states the true total, windowed or not.
    expect(explorerMarkup(1000)).toContain("1000 objects");
  });
});

describe("deep-link search params degrade instead of throwing", () => {
  it("accepts a real value", () => {
    expect(optionalSearchString("lane-7")).toBe("lane-7");
  });

  it("treats absent, empty, and non-string values as no selection", () => {
    // A deep link is a convenience, so junk in the URL must fall back to "no
    // selection" rather than throw the operator into an error boundary.
    for (const junk of [undefined, null, "", 42, {}, [], true]) {
      expect(optionalSearchString(junk)).toBeUndefined();
    }
  });
});

describe("the skip link is part of the skin grammar", () => {
  it("the shipped skin reveals its skip link on keyboard focus", () => {
    expect(OMCP_SKIN.layout.skipLink).toContain("sr-only");
    expect(OMCP_SKIN.layout.skipLink).toContain("focus-visible:not-sr-only");
    expect(() => assertDashboardSkinConformance(OMCP_SKIN)).not.toThrow();
  });

  it("a skin without a skip link fails conformance", () => {
    const skin: DashboardSkin = {
      ...OMCP_SKIN,
      layout: { ...OMCP_SKIN.layout, skipLink: "   " }
    };
    expect(() => assertDashboardSkinConformance(skin)).toThrow(/skip-to-main-content/);
  });

  it("a skip link that never becomes visible fails conformance", () => {
    const skin: DashboardSkin = {
      ...OMCP_SKIN,
      layout: { ...OMCP_SKIN.layout, skipLink: "sr-only" }
    };
    expect(() => assertDashboardSkinConformance(skin)).toThrow(/visible on keyboard focus/);
  });
});
