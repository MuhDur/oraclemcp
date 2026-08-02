import { expect, test, type Page } from "@playwright/test";

type RecoveryStubOptions = {
  sessionFailures?: number;
  configStartsUnavailable?: boolean;
};

type RecoveryControls = {
  recoverConfig: () => void;
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

async function stubRecoveryDashboard(page: Page, options: RecoveryStubOptions): Promise<RecoveryControls> {
  let sessionAttempts = 0;
  let configAvailable = !options.configStartsUnavailable;
  await page.route("**/dashboard/session", async (route) => {
    sessionAttempts += 1;
    if (sessionAttempts <= (options.sessionFailures ?? 0)) {
      await route.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify({ error: "temporary pairing endpoint outage" })
      });
      return;
    }
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
    if (path === "/operator/v1/config") {
      if (!configAvailable) {
        await route.fulfill({
          status: 503,
          contentType: "application/json",
          body: JSON.stringify({ error: "temporary configuration outage" })
        });
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: operatorEnvelope(path, {
          source: "config_ops",
          status: {
            target_path: "/config/profiles.toml",
            target_exists: true,
            current_sha256: "sha256:test",
            default_profile: "dev_ro",
            profiles: [{ name: "dev_ro", is_default: true, max_level: "READ_ONLY" }],
            dashboard_workbench: true
          }
        })
      });
      return;
    }

    const data =
      path === "/operator/v1/active-lanes"
        ? { source: "unavailable", stateful: false, lanes: [] }
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

  return {
    recoverConfig: () => {
      configAvailable = true;
    }
  };
}

test("a dashboard session recovers from an operator-triggered retry", async ({ page }) => {
  await stubRecoveryDashboard(page, { sessionFailures: 2 });
  await page.goto("/");

  await expect(page.getByText("Dashboard session unavailable", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Retry dashboard session" }).click();

  await expect(page.getByText("Dashboard session unavailable", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Dashboard", exact: true })).toBeVisible();
});

test("a temporarily unavailable Workbench setting remains reachable and retryable", async ({ page }) => {
  const recovery = await stubRecoveryDashboard(page, { configStartsUnavailable: true });
  await page.goto("/workbench");

  await expect(page.getByText("Browser SQL setting is unavailable", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "SQL Workbench" })).toBeVisible();
  recovery.recoverConfig();
  await page.getByRole("button", { name: "Retry setting" }).click();

  await expect(page.getByRole("button", { name: "Run query" })).toBeVisible();
});
