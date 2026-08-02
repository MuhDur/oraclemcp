import { expect, test, type Page } from "@playwright/test";

type LayoutStubOptions = {
  populatedActivity?: boolean;
};

function operatorEnvelope(path: string, data: Record<string, unknown>): string {
  return JSON.stringify({
    protocol_version: "operator.v1",
    schema_version: 1,
    route: path,
    redaction_level: "operator_redacted",
    data
  });
}

async function stubLayoutDashboard(page: Page, options: LayoutStubOptions = {}): Promise<void> {
  const lane = {
    lane_id: "lane-operator-session",
    generation: 1,
    status: "active",
    subject_id_hash: "subject-sha256-test"
  };
  const snapshot = {
    requests: [],
    lane_requests: options.populatedActivity
      ? [{ lane_id: lane.lane_id, subject_id_hash: lane.subject_id_hash, tool: "oracle_query", status: "ok", count: 1 }]
      : [],
    lane_blocked: [],
    lane_request_duration_ms: [],
    errors: [],
    query_duration_ms: { count: 0, sum: 0, max: 0, mean: 0 },
    pool_wait_ms: { count: 0, sum: 0, max: 0, mean: 0 },
    pool_active_connections: 0
  };
  await page.route("**/dashboard/session", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        csrf_token: "csrf-test",
        csrf_header: "x-oraclemcp-csrf",
        action_ticket_header: "x-oraclemcp-action-ticket",
        expires_unix: 4_102_444_800,
        action_tickets: []
      })
    });
  });
  await page.route("**/operator/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/operator/v1/events") {
      await route.fulfill({ status: 204, body: "" });
      return;
    }
    const data =
      path === "/operator/v1/active-lanes"
        ? {
            source: options.populatedActivity ? "self_lane" : "unavailable",
            stateful: options.populatedActivity,
            lanes: options.populatedActivity ? [lane] : []
          }
        : path === "/operator/v1/metrics"
          ? { source: "self", snapshot, capacity: null }
          : path === "/operator/v1/audit-tail"
            ? { source: "audit", records: [] }
            : path === "/operator/v1/health"
              ? {
                  source: "self",
                  readiness: {
                    status: "ready",
                    ready: true,
                    db_reachable: true,
                    draining: false
                  }
                }
              : path === "/operator/v1/config"
                ? {
                    source: "config_ops",
                    status: {
                      target_path: "/config/profiles.toml",
                      target_exists: true,
                      current_sha256: "sha256:test",
                      default_profile: "dev_ro",
                      profiles: [],
                      dashboard_workbench: false
                    }
                  }
                : { source: "unavailable" };
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: operatorEnvelope(path, data)
    });
  });
}

test("Audit filters keep every command in view across desktop widths", async ({ page }) => {
  await stubLayoutDashboard(page);
  for (const width of [1024, 1440, 1600]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/audit");
    await expect(page.getByRole("heading", { name: "Audit trail", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Include proof bundle" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Apply filters" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Refresh" })).toBeVisible();
    const dimensions = await page.getByTestId("audit-filter-controls").evaluate((element) => ({
      cardClientWidth: element.clientWidth,
      cardScrollWidth: element.scrollWidth,
      documentClientWidth: document.documentElement.clientWidth,
      documentScrollWidth: document.documentElement.scrollWidth
    }));
    expect(dimensions.cardScrollWidth).toBeLessThanOrEqual(dimensions.cardClientWidth);
    expect(dimensions.documentScrollWidth).toBe(dimensions.documentClientWidth);
  }
});

test("empty activity fits the card at mobile width", async ({ page }) => {
  await stubLayoutDashboard(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");

  await expect(page.getByText("No active agent sessions. Connect an MCP client to begin.")).toBeVisible();
  const emptyRegion = page.getByRole("region", { name: "Agent session activity" });
  const emptyWidths = await emptyRegion.evaluate((element) => ({
    clientWidth: element.clientWidth,
    scrollWidth: element.scrollWidth
  }));
  expect(emptyWidths.scrollWidth).toBe(emptyWidths.clientWidth);
});

test("populated activity retains its labelled horizontal scroll region", async ({ page }) => {
  await stubLayoutDashboard(page, { populatedActivity: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  const populatedRegion = page.getByRole("region", { name: "Agent session activity" });
  await expect(page.getByText("lane-operator-session", { exact: true })).toBeVisible();
  await expect(populatedRegion).toBeVisible();
  const populatedWidths = await populatedRegion.evaluate((element) => ({
    clientWidth: element.clientWidth,
    scrollWidth: element.scrollWidth
  }));
  expect(populatedWidths.scrollWidth).toBeGreaterThan(populatedWidths.clientWidth);
});
