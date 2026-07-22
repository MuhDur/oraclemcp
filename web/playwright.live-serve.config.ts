import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  testMatch: "live-serve-browser.spec.ts",
  outputDir: "../target/playwright/live-serve",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: "line",
  use: {
    screenshot: "only-on-failure",
    trace: "retain-on-failure"
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] }
    }
  ]
});
