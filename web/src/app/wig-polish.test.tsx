import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ConfirmDialog } from "./App";
import { OMCP_SKIN, assertDashboardSkinConformance, type DashboardSkin } from "./skin";

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
