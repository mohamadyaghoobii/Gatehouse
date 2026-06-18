import { defineConfig, devices } from "@playwright/test";

const WEB_URL = process.env.E2E_BASE_URL || "http://localhost:3000";

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  expect: { timeout: 7_000 },
  fullyParallel: true,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: WEB_URL,
    trace: "on-first-retry"
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: process.env.E2E_NO_SERVER
    ? undefined
    : [
        {
          command: "python -m uvicorn app.main:app --host 0.0.0.0 --port 8000",
          cwd: "../api",
          url: "http://localhost:8000/health",
          reuseExistingServer: !process.env.CI,
          timeout: 60_000
        },
        {
          command: "npm run dev",
          url: WEB_URL,
          reuseExistingServer: !process.env.CI,
          timeout: 120_000
        }
      ]
});
