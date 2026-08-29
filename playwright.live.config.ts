import { defineConfig, devices } from "@playwright/test";

const liveUrl = process.env.RECALLOPS_LIVE_URL;
if (!liveUrl)
  throw new Error("RECALLOPS_LIVE_URL is required for public live assurance");

export default defineConfig({
  testDir: "tests/live-browser",
  outputDir: "artifacts/item10-live-browser/test-results",
  timeout: 180_000,
  expect: { timeout: 15_000 },
  workers: 1,
  retries: 0,
  reporter: [
    ["list"],
    [
      "json",
      { outputFile: "artifacts/item10-live-browser/playwright-results.json" },
    ],
  ],
  use: {
    ...devices["Desktop Chrome"],
    baseURL: liveUrl,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  projects: [
    { name: "public-chromium", use: { ...devices["Desktop Chrome"] } },
  ],
});
