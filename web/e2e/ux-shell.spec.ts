import { expect, test, type Page } from "@playwright/test";

function operatorEnvelope(path: string, data: Record<string, unknown>): string {
  return JSON.stringify({
    protocol_version: "operator.v1",
    schema_version: 1,
    route: path,
    redaction_level: "operator_redacted",
    data
  });
}

async function stubShellDashboard(page: Page): Promise<void> {
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
        ? { source: "unavailable", stateful: false, lanes: [] }
        : path === "/operator/v1/config"
          ? {
              source: "config_ops",
              status: {
                target_path: "/config/profiles.toml",
                target_exists: true,
                current_sha256: "sha256:test",
                default_profile: "dev_ro",
                profiles: [{ name: "dev_ro", is_default: true, max_level: "READ_ONLY" }],
                dashboard_workbench: false
              }
            }
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
            : path === "/operator/v1/metrics"
              ? { source: "self", snapshot: null, capacity: null }
              : path === "/operator/v1/change-proposals"
                ? { source: "change_proposals", proposals: [], nextCursor: null }
                : { source: "unavailable" };
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: operatorEnvelope(path, data)
    });
  });
}

test("initial load keeps normal focus while route changes announce the page heading", async ({ page }) => {
  await stubShellDashboard(page);
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Dashboard", exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.activeElement?.id)).not.toBe("dashboard-page-title");

  await page.getByRole("link", { name: "Change review" }).click();
  await expect(page.getByRole("heading", { name: "Change review", exact: true })).toBeVisible();
  await expect.poll(() => page.evaluate(() => document.activeElement?.id)).toBe("dashboard-page-title");
});

test("the shell stays usable at 280px and keeps desktop navigation available while scrolling", async ({ page }) => {
  await stubShellDashboard(page);
  await page.setViewportSize({ width: 280, height: 720 });
  await page.goto("/");

  await expect(page.getByRole("link", { name: "View reviews" })).toBeVisible();
  const narrowMetrics = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
    reviewHeight: document.querySelector<HTMLAnchorElement>('a[href="/reviews"]')?.getBoundingClientRect().height
  }));
  expect(narrowMetrics.scrollWidth).toBe(narrowMetrics.clientWidth);
  expect(narrowMetrics.reviewHeight).toBeGreaterThanOrEqual(44);

  await page.setViewportSize({ width: 1440, height: 720 });
  await page.goto("/reviews");
  await page.evaluate(() => window.scrollTo(0, 600));
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(0);
  const sidebarY = await page.locator("aside").evaluate((element) => element.getBoundingClientRect().y);
  expect(sidebarY).toBeGreaterThanOrEqual(0);
});
