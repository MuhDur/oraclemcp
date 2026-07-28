import { expect, test, type Page } from "@playwright/test";

type DashboardStubOptions = {
  workbenchEnabled: boolean;
};

async function stubDashboard(page: Page, options: DashboardStubOptions): Promise<void> {
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
                dashboard_workbench: options.workbenchEnabled
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
      body: JSON.stringify({
        protocol_version: "operator.v1",
        schema_version: 1,
        route: path,
        redaction_level: "operator_redacted",
        data
      })
    });
  });
}

test("the shipped dashboard exposes database workflows, not repository tooling", async ({ page }) => {
  await stubDashboard(page, { workbenchEnabled: false });
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Dashboard", exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Database Explorer" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Change review" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Audit trail" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Agent sessions" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "SQL Workbench" })).toHaveCount(0);
  await expect(page.getByText("Attestations", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Ground Control", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Doctor", { exact: true })).toHaveCount(0);
});

test("a direct Workbench URL fails closed when browser SQL is disabled", async ({ page }) => {
  await stubDashboard(page, { workbenchEnabled: false });
  await page.goto("/workbench");

  await expect(page.getByRole("heading", { name: "SQL Workbench" })).toBeVisible();
  await expect(page.getByText("Browser SQL is disabled on this server")).toBeVisible();
  await expect(page.getByRole("button", { name: "Run query" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Open Profiles & settings" })).toBeVisible();
});

test("the Workbench appears only after the server reports the opt-in", async ({ page }) => {
  await stubDashboard(page, { workbenchEnabled: true });
  await page.goto("/workbench");

  await expect(page.getByRole("heading", { name: "SQL Workbench" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Run query" })).toBeVisible();
  await expect(page.getByRole("link", { name: "SQL Workbench" })).toBeVisible();
  await expect(page.getByText("Browser SQL is disabled on this server")).toHaveCount(0);
});
