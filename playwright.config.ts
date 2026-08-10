import { defineConfig, devices } from "@playwright/test";
import { existsSync } from "node:fs";

const localPython = process.platform === "win32" ? ".venv/Scripts/python.exe" : ".venv/bin/python";
const python =
  process.env.RECALLOPS_TEST_PYTHON ?? (existsSync(localPython) ? localPython : "python3");

export default defineConfig({
  testDir: "tests/browser",
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: process.env.CI ? [["line"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: "http://127.0.0.1:4173",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  webServer: {
    command: `${python} -m uvicorn recallops.api:create_app --factory --host 127.0.0.1 --port 4173`,
    url: "http://127.0.0.1:4173/",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    env: {
      RECALLOPS_STORE: "memory",
      RECALLOPS_AUTH_MODE: "demo",
      PYTHONPATH: "src",
    },
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
