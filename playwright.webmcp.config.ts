import { defineConfig, devices } from "@playwright/test";
import { existsSync } from "node:fs";

const localPython = process.platform === "win32" ? ".venv/Scripts/python.exe" : ".venv/bin/python";
const python = process.env.RECALLOPS_TEST_PYTHON ?? (existsSync(localPython) ? localPython : "python3");
const chromiumPath = process.env.WEBMCP_CHROMIUM_PATH ?? "/snap/bin/chromium";

export default defineConfig({
  testDir: "tests/webmcp-native",
  workers: 1,
  reporter: "list",
  use: {
    ...devices["Desktop Chrome"],
    baseURL: "http://127.0.0.1:4174",
    launchOptions: {
      executablePath: chromiumPath,
      args: ["--enable-features=WebMCP"],
    },
  },
  webServer: {
    command: `${python} -m uvicorn recallops.api:create_app --factory --host 127.0.0.1 --port 4174`,
    url: "http://127.0.0.1:4174/",
    reuseExistingServer: false,
    timeout: 120_000,
    env: {
      RECALLOPS_STORE: "memory",
      RECALLOPS_AUTH_MODE: "demo",
      PYTHONPATH: "src",
    },
  },
});
