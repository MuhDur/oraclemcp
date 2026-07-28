import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { OperatorOutcomeNotice } from "./App";
import { decodeOperatorOutcome } from "./operator-client";
import { ChainStrip } from "./skin";

// uc3z: the console's live, safety-critical status signals must be announced to
// assistive tech. Each carries an aria-live region so a screen-reader operator
// hears a GO→NO-GO flip, an audit-chain tamper, and every mutation outcome —
// without the per-second clock ticking into the same region.

describe("live status regions are announced", () => {
  it("announces an audit-chain tamper via an aria-live region", () => {
    const markup = renderToStaticMarkup(
      <ChainStrip
        chain={{ status: "broken", label: "tamper detected", height: 128, verifiedAtMs: null }}
      />
    );
    expect(markup).toContain('aria-live="polite"');
    // The announcement names the state, not only the visible badge.
    expect(markup).toContain("BROKEN");
  });

  it("announces an operator action outcome via an aria-live region", () => {
    const outcome = decodeOperatorOutcome(202, {
      route: "/operator/v1/actions/execute",
      data: { status: "accepted" }
    });
    const markup = renderToStaticMarkup(<OperatorOutcomeNotice outcome={outcome} />);
    expect(markup).toContain('aria-live="polite"');
    expect(markup).toContain('role="status"');
  });
});
