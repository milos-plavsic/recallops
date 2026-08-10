import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

const selectedMemory = {
  rank_score: 0.842,
  semantic_similarity: 0.91,
  compatibility: 1,
  memory: {
    id: "00000000-0000-0000-0000-000000000001",
    outcome: "Connection pool tuning restored checkout latency",
    state: "active",
    valid: true,
  },
};

const successfulAnalysis = {
  incident_id: "00000000-0000-0000-0000-000000000010",
  diagnosis: "Checkout latency matches a previously recovered pool exhaustion incident.",
  confidence: 0.86,
  proposed_action: {
    command: "increase checkout pool size and observe latency",
    requires_approval: true,
    action_hash: "sha256:judge-action",
  },
  memories: [selectedMemory],
  retrieval_abstention_reasons: [],
  degraded_dependencies: [],
  candidate_decisions: [
    {
      memory_id: selectedMemory.memory.id,
      disposition: "selected",
      reasons: [],
    },
  ],
  agent_trace: [
    {
      sequence: 1,
      tool: "retrieve_memory",
      status: "completed",
      risk: "read_only",
      max_attempts: 2,
      timeout_seconds: 5,
    },
    {
      sequence: 2,
      tool: "propose_action",
      status: "completed",
      risk: "mutating_requires_approval",
      max_attempts: 1,
      timeout_seconds: 10,
    },
  ],
};

const abstainedAnalysis = {
  ...successfulAnalysis,
  incident_id: "00000000-0000-0000-0000-000000000011",
  diagnosis: "No compatible successful memory is safe to replay.",
  confidence: 0.28,
  proposed_action: {
    command: "collect read-only checkout diagnostics",
    requires_approval: false,
    action_hash: "sha256:diagnostic-action",
  },
  memories: [
    {
      ...selectedMemory,
      rank_score: 0.63,
      memory: {
        ...selectedMemory.memory,
        outcome: "Previous pool increase worsened connection churn",
      },
    },
  ],
  retrieval_abstention_reasons: ["no compatible successful memory met the safety threshold"],
  candidate_decisions: [
    {
      memory_id: selectedMemory.memory.id,
      disposition: "rejected",
      reasons: ["negative outcome evidence", "retrieval rank below safety threshold"],
    },
  ],
  agent_trace: [
    {
      sequence: 1,
      tool: "retrieve_memory",
      status: "abstained",
      risk: "read_only",
      max_attempts: 2,
      timeout_seconds: 5,
      degraded_reason: "no safe candidate",
    },
  ],
};

type Analysis = typeof successfulAnalysis;

async function mockApi(page: Page, analysis: Analysis = successfulAnalysis) {
  await page.route("**/v1/config", (route) =>
    route.fulfill({ json: { auth_required: false } }),
  );
  await page.route("**/ready", (route) => route.fulfill({ json: { status: "ready" } }));
  await page.route("**/v1/system/status", (route) =>
    route.fulfill({
      json: {
        store: "memory",
        reasoning_provider: "deterministic",
        embedding_provider: "deterministic",
        embedding_space: "deterministic-v1",
        evidence_archive_configured: false,
        auth_mode: "demo",
      },
    }),
  );
  await page.route("**/v1/evaluation", (route) =>
    route.fulfill({
      json: {
        passed: true,
        case_count: 6,
        recallops: {
          top1_safe_accuracy: 1,
          unsafe_selection_rate: 0,
          isolation_violations: 0,
          mean_reciprocal_rank: 1,
        },
        similarity_only: {
          top1_safe_accuracy: 0.5,
          unsafe_selection_rate: 0.5,
          isolation_violations: 0,
          mean_reciprocal_rank: 0.5,
        },
      },
    }),
  );
  await page.route("**/v1/incidents", async (route) => {
    if (route.request().method() === "POST") {
      await route.fulfill({ status: 201, json: analysis });
    } else {
      await route.continue();
    }
  });
}

test.describe("judge console", () => {
  test("renders truthful benchmark language and has no serious accessibility violations", async ({ page }) => {
    const consoleErrors: string[] = [];
    page.on("console", (message) => {
      if (message.type() === "error") consoleErrors.push(message.text());
    });
    await mockApi(page);
    await page.goto("/");

    await expect(page).toHaveTitle(/RecallOps/);
    await expect(page.getByText("Synthetic policy suite passing")).toBeVisible();
    await expect(page.getByText(/small, synthetic, deterministic policy regression set/)).toBeVisible();
    await expect(page.getByText(/not an end-to-end retrieval benchmark/)).toBeVisible();
    await expect(page.getByText("API and memory ready")).toBeVisible();
    expect(consoleErrors).toEqual([]);

    const results = await new AxeBuilder({ page }).analyze();
    const serious = results.violations.filter((violation) =>
      violation.impact === "critical" || violation.impact === "serious",
    );
    expect(serious, JSON.stringify(serious, null, 2)).toEqual([]);
  });

  test("supports keyboard navigation and renders the actual trace risk", async ({ page }) => {
    await mockApi(page);
    await page.goto("/");

    await page.keyboard.press("Tab");
    await expect(page.locator(".skip-link")).toBeFocused();
    await expect(page.getByRole("button", { name: "Analyze incident" })).toBeEnabled();
    await expect(page.getByLabel("Tenant")).toBeEditable();

    await page.getByRole("button", { name: "Analyze incident" }).click();
    await expect(page.getByRole("heading", { name: successfulAnalysis.diagnosis })).toBeVisible();
    await expect(page.getByText("mutating requires approval")).toBeVisible();
    await expect(page.getByText("read only")).toBeVisible();
    await expect(page.getByRole("button", { name: "Approve exact action" })).toBeEnabled();
    await expect(page.getByRole("button", { name: "Attest execution" })).toBeDisabled();
  });

  test("explains abstention and candidate rejection instead of presenting an unsafe action", async ({ page }) => {
    await mockApi(page, abstainedAnalysis);
    await page.goto("/");
    await page.getByRole("button", { name: "Analyze incident" }).click();

    await expect(page.getByRole("heading", { name: abstainedAnalysis.diagnosis })).toBeVisible();
    await expect(page.getByText("Abstained — no compatible successful memory")).toBeVisible();
    await page.getByText(/Candidate evidence and rejection reasons/).click();
    await expect(page.getByText(/negative outcome evidence/)).toBeVisible();
    await expect(page.getByText("read only")).toBeVisible();
    await expect(page.getByRole("button", { name: "Approve exact action" })).toBeDisabled();
  });
});
