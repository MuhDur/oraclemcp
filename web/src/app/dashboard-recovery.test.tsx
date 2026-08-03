import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { QueryErrorNotice } from "./dashboard-recovery";

describe("dashboard recovery notices", () => {
  it("offers an immediate, named retry while a request is recoverable", () => {
    const markup = renderToStaticMarkup(
      <QueryErrorNotice
        title="Dashboard data is unavailable"
        error={new Error("temporary operator endpoint failure")}
        retryLabel="Retry dashboard data"
        onRetry={() => {}}
      />
    );

    expect(markup).toContain('role="alert"');
    expect(markup).toContain("Retry dashboard data");
    expect(markup).not.toMatch(/<button\b[^>]*\sdisabled(?:=| |>)/);
  });

  it("disables a retry while it is already in flight", () => {
    const markup = renderToStaticMarkup(
      <QueryErrorNotice
        title="Resource limits are unavailable"
        error={new Error("temporary metrics failure")}
        retryLabel="Retry resource-limit data"
        retryingLabel="Retrying resource-limit data"
        retrying
        onRetry={() => {}}
      />
    );

    expect(markup).toContain("Retrying resource-limit data");
    expect(markup).toMatch(/<button\b[^>]*\sdisabled=""/);
    expect(markup).toContain('aria-busy="true"');
    expect(markup).toContain("animate-spin");
  });
});
