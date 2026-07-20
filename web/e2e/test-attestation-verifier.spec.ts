import { mkdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { expect, test, type Page, type TestInfo } from "@playwright/test";

const fixturePath = resolve(
  process.cwd(),
  "../crates/oraclemcp-verifier/tests/fixtures/test-attestation-v1.golden.jsonl"
);
const golden = readFileSync(fixturePath, "utf8");
const trustedSecret = "0123456789abcdef0123456789abcdef";
const evidenceDir = resolve(process.cwd(), "../target/playwright/k2-evidence");

type BrowserDiagnostics = {
  consoleErrors: string[];
  pageErrors: string[];
};

function captureBrowserDiagnostics(page: Page): BrowserDiagnostics {
  const diagnostics: BrowserDiagnostics = { consoleErrors: [], pageErrors: [] };
  page.on("console", (message) => {
    if (message.type() === "error") {
      diagnostics.consoleErrors.push(message.text());
    }
  });
  page.on("pageerror", (error) => diagnostics.pageErrors.push(error.message));
  return diagnostics;
}

async function stubGroundControl(page: Page): Promise<void> {
  await page.route("**/operator/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const data = path.endsWith("/health")
      ? {
          source: "playwright",
          readiness: { status: "ready", ready: true, db_reachable: true, draining: false }
        }
      : path.endsWith("/metrics")
        ? { source: "playwright", snapshot: null }
        : {
            source: "playwright",
            limit: 1,
            filters: {},
            records: [],
            proof: { verification: { hash_chain: { status: "ok", last_seq: 0 } } }
          };
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

async function openVerifier(page: Page): Promise<BrowserDiagnostics> {
  const diagnostics = captureBrowserDiagnostics(page);
  await stubGroundControl(page);
  await page.goto("/attestations");
  await expect(page).toHaveURL(/\/attestations$/);
  await expect(page.getByRole("link", { name: "Attestations" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Test attestations" })).toBeVisible();
  await expect(page.getByTestId("verification-result")).toContainText("No verification result");
  return diagnostics;
}

async function assertBrowserClean(diagnostics: BrowserDiagnostics): Promise<void> {
  expect(diagnostics.consoleErrors, "browser console errors").toEqual([]);
  expect(diagnostics.pageErrors, "uncaught browser errors").toEqual([]);
}

async function captureEvidence(page: Page, testInfo: TestInfo, name: string): Promise<void> {
  mkdirSync(evidenceDir, { recursive: true });
  await page.getByRole("heading", { name: "Test attestations" }).scrollIntoViewIfNeeded();
  const screenshot = await page.screenshot({
    path: join(evidenceDir, `${name}.png`),
    fullPage: true
  });
  await testInfo.attach(name, { body: screenshot, contentType: "image/png" });
}

test("a third party verifies the Rust golden through real dashboard controls", async ({ page }, testInfo) => {
  const diagnostics = await openVerifier(page);

  await page.getByLabel("Attestation file").setInputFiles(fixturePath);
  await expect(page.getByLabel("Signed attestation JSONL")).toHaveValue(golden);
  await page.getByLabel("Trusted key ID").fill("test-attestation-key");
  await page.getByLabel("Trusted HMAC secret").fill(trustedSecret);
  await page.getByRole("button", { name: "Verify evidence" }).click();

  const result = page.getByTestId("verification-result");
  await expect(result).toContainText("VERIFIED PASS");
  await expect(result).toContainText("Signature verified; every named test passed");
  await expect(result).toContainText("mutation-safety");
  await expect(result.getByRole("list", { name: "Attested test outcomes" }).getByText("PASS")).toHaveCount(2);
  await expect(page.getByLabel("Trusted HMAC secret")).toHaveValue("");
  expect(await page.content()).not.toContain(trustedSecret);
  expect(
    await page.evaluate((secret) => {
      const values = [...Object.values(localStorage), ...Object.values(sessionStorage)];
      return values.some((value) => value.includes(secret));
    }, trustedSecret)
  ).toBe(false);

  const viewport = page.viewportSize();
  const bounds = await page.getByTestId("test-attestation-verifier").boundingBox();
  expect(viewport).not.toBeNull();
  expect(bounds).not.toBeNull();
  expect(bounds!.width).toBeLessThanOrEqual(viewport!.width);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await captureEvidence(page, testInfo, "verified-pass-dashboard");

  await page.setViewportSize({ width: 390, height: 844 });
  await result.scrollIntoViewIfNeeded();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await captureEvidence(page, testInfo, "verified-pass-mobile");
  await assertBrowserClean(diagnostics);
});

test("an edited outcome is visibly rejected and stale PASS cannot survive editing", async ({ page }, testInfo) => {
  const diagnostics = await openVerifier(page);
  const documentInput = page.getByLabel("Signed attestation JSONL");

  await documentInput.fill(golden);
  await page.getByLabel("Trusted key ID").fill("test-attestation-key");
  await page.getByLabel("Trusted HMAC secret").fill(trustedSecret);
  await page.getByRole("button", { name: "Verify evidence" }).click();
  await expect(page.getByTestId("verification-result")).toContainText("VERIFIED PASS");

  await documentInput.fill(golden.replace('"outcome":"PASS"', '"outcome":"FAIL"'));
  await expect(page.getByTestId("verification-result")).not.toContainText("VERIFIED PASS");
  await page.getByLabel("Trusted HMAC secret").fill(trustedSecret);
  await page.getByRole("button", { name: "Verify evidence" }).click();

  const rejection = page.getByRole("alert");
  await expect(rejection).toContainText("REJECTED");
  await expect(rejection).toContainText("PAYLOAD_DIGEST_MISMATCH");
  await expect(rejection).toContainText("No test outcome is trusted or presented as verified");
  await expect(rejection).not.toContainText("VERIFIED PASS");
  await captureEvidence(page, testInfo, "tampered-evidence-rejected");
  await assertBrowserClean(diagnostics);
});

test("missing independently trusted secret fails closed through the submit control", async ({ page }) => {
  const diagnostics = await openVerifier(page);

  await page.getByLabel("Signed attestation JSONL").fill(golden);
  await page.getByLabel("Trusted key ID").fill("test-attestation-key");
  await page.getByRole("button", { name: "Verify evidence" }).click();

  const rejection = page.getByRole("alert");
  await expect(rejection).toContainText("REJECTED");
  await expect(rejection).toContainText("MISSING_KEY");
  await expect(rejection).toContainText("independently supplied HMAC secret is required");
  await expect(rejection).not.toContainText("VERIFIED PASS");
  await assertBrowserClean(diagnostics);
});
