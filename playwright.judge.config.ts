import { defineConfig, devices } from "@playwright/test";
import { existsSync } from "node:fs";

const localPython = process.platform === "win32" ? ".venv/Scripts/python.exe" : ".venv/bin/python";
const python = process.env.RECALLOPS_TEST_PYTHON ?? (existsSync(localPython) ? localPython : "python3");

export default defineConfig({
  testDir: "tests/judge-browser",
  workers: 1,
  reporter: "list",
  use: {
    ...devices["Desktop Chrome"],
    baseURL: "http://127.0.0.1:4175",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: {
    command: `${python} -m uvicorn recallops.api:create_app --factory --host 127.0.0.1 --port 4175`,
    url: "http://127.0.0.1:4175/",
    reuseExistingServer: false,
    timeout: 120_000,
    env: {
      RECALLOPS_STORE: "memory",
      RECALLOPS_AUTH_MODE: "judge",
      RECALLOPS_PUBLIC_ORIGIN: "http://127.0.0.1:4175",
      RECALLOPS_JUDGE_RATE_LIMIT_KEY: "browser-integration-rate-limit-key-with-enough-entropy",
      RECALLOPS_JUDGE_COOKIE_SECURE: "false",
      PYTHONPATH: "src",
    },
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
