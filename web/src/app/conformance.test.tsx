import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  CLEARANCE_LADDER,
  DASHBOARD_GRAMMAR,
  REQUIRED_BIG_BOARD_RENDERERS,
  REQUIRED_THEME_MODES,
  defaultSkinCapabilities,
  skinContractFixture,
  type SkinCapability
} from "./presentation-model";
import {
  OMCP_SKIN,
  assertDashboardSkinConformance,
  selectBigBoardRenderer
} from "./skin";

// B4.6 skin-conformance contract (iec3.2.26). These gate the release: every
// view-model must render in the single shipped Carved Light theme AND resolve to
// the mandatory 2D/table fallback, and the OMCP grammar (the I-II-III-IV
// operating-level ladder, GO/NO-GO verdict) must hold unchanged.

const caps = (overrides: Partial<SkinCapability> = {}): SkinCapability => ({
  ...defaultSkinCapabilities(),
  ...overrides
});

describe("OMCP skin conformance", () => {
  it("passes the built-in conformance assertion", () => {
    expect(() => assertDashboardSkinConformance(OMCP_SKIN)).not.toThrow();
  });

  it("ships exactly the Carved Light theme with the --om clearance ramp", () => {
    expect(OMCP_SKIN.theme.name).toBe("carved-light");
    for (const level of ["read-only", "read-write", "ddl", "admin"] as const) {
      expect(OMCP_SKIN.theme.cssVars[`--om-clearance-${level}`]).toMatch(/^#/);
    }
    // A WebGL uniform per clearance level keeps the 3D and 2D skins in lockstep.
    expect(Object.keys(OMCP_SKIN.theme.webglUniforms).sort()).toEqual(
      ["ADMIN", "DDL", "READ_ONLY", "READ_WRITE"]
    );
  });

  it("covers every required theme mode and big-board renderer", () => {
    expect([...OMCP_SKIN.theme.modes].sort()).toEqual([...REQUIRED_THEME_MODES].sort());
    expect(Object.keys(OMCP_SKIN.bigBoardRenderers).sort()).toEqual(
      [...REQUIRED_BIG_BOARD_RENDERERS].sort()
    );
  });

  it("keeps the operating-level ladder grammar in order", () => {
    expect(CLEARANCE_LADDER.map((step) => step.level).join(">")).toBe(
      "READ_ONLY>READ_WRITE>DDL>ADMIN"
    );
    expect(DASHBOARD_GRAMMAR.meanings.color).toBe("clearance");
  });

  it("always resolves a working 2D fallback and never auto-selects WebGL", () => {
    // Both non-WebGL renderers must exist and be available.
    expect(OMCP_SKIN.bigBoardRenderers.board2d.available).toBe(true);
    expect(OMCP_SKIN.bigBoardRenderers.table.available).toBe(true);
    // Default: the 2D board.
    expect(selectBigBoardRenderer(OMCP_SKIN, caps()).kind).toBe("board2d");
    // Forced-colors / high-contrast: the table fallback.
    expect(selectBigBoardRenderer(OMCP_SKIN, caps({ forcedColors: true, preferTable: true })).kind).toBe(
      "table"
    );
    // Reduced motion with WebGL present still avoids the Orrery (unavailable + lazy).
    expect(
      selectBigBoardRenderer(OMCP_SKIN, caps({ webgl: true, reducedMotion: true })).kind
    ).not.toBe("orrery3d");
  });

  it("renders Ground Control in the Carved Light theme with the grammar intact", () => {
    const GroundControl = OMCP_SKIN.renderers.GroundControl;
    const markup = renderToStaticMarkup(
      <GroundControl model={skinContractFixture().groundControl} />
    );
    expect(markup).toContain('data-grammar-version="1"');
    expect(markup).toContain('data-verdict="GO"');
    for (const level of ["READ_ONLY", "READ_WRITE", "DDL", "ADMIN"]) {
      expect(markup).toContain(`data-clearance-level="${level}"`);
    }
  });

  it("renders both the 2D board and the table fallback for the fleet view-model", () => {
    const fleet = skinContractFixture().fleet;
    for (const kind of ["board2d", "table"] as const) {
      const renderer = OMCP_SKIN.bigBoardRenderers[kind];
      const Renderer = renderer.component;
      const markup = renderToStaticMarkup(<Renderer model={fleet} renderer={renderer} />);
      expect(markup).toContain(`data-renderer="${kind}"`);
      expect(markup).toContain('data-grammar-version="1"');
    }
  });
});
