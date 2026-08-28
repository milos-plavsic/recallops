import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

const selectedMemory = {
  rank_score: 0.842,
  semantic_similarity: 0.91,
  compatibility: 1,
  memory: {
    id: "00000000-0000-0000-0000-000000000001",
    source_incident_id: "00000000-0000-0000-0000-000000000099",
    reviewed_by: "reviewer-subject",
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
      evidence_refs: ["memory:00000000-0000-0000-0000-000000000001"],
    },
    {
      sequence: 2,
      tool: "propose_action",
      status: "completed",
      risk: "mutating_requires_approval",
      max_attempts: 1,
      timeout_seconds: 10,
      evidence_refs: ["urn:recallops:diagnostic:alarm:sanitized-proof"],
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

async function installWebMcpHarness(page: Page) {
  await page.addInitScript(() => {
    const tools = new Map<string, { definition: any; options: any }>();
    const modelContext = {
      async registerTool(definition: any, options: any = {}) {
        if (tools.has(definition.name)) throw new DOMException("duplicate tool", "InvalidStateError");
        if (options.signal?.aborted) throw new DOMException("registration aborted", "AbortError");
        tools.set(definition.name, { definition, options });
        options.signal?.addEventListener("abort", () => tools.delete(definition.name), { once: true });
      },
    };
    Object.defineProperty(document, "modelContext", { configurable: true, value: modelContext });
    Object.defineProperty(window, "__webmcpTools", { configurable: true, value: tools });
  });
}

async function mockApi(page: Page, analysis: Analysis = successfulAnalysis) {
  await page.route("**/v1/incidents/*/capabilities", (route) =>
    route.fulfill({ json: {
      workflow_id: analysis.incident_id,
      state: analysis.proposed_action.requires_approval ? "AWAITING_OPERATOR_APPROVAL" : "INVESTIGATING",
      epoch: 1,
      active: true,
      authority_owner: analysis.proposed_action.requires_approval ? "HUMAN_OPERATOR" : "AGENT",
      available_tools: analysis.proposed_action.requires_approval
        ? ["inspect_incident"]
        : ["inspect_incident", "propose_mitigation"],
      protected_tools: [],
    } }),
  );
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
    await expect(page.getByText("WebMCP unavailable · manual controls remain")).toBeVisible();
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
    await expect(page.getByText(/evidence: memory:00000000/)).toBeVisible();
    await page.getByText(/Candidate evidence and rejection reasons/).click();
    await expect(page.getByText(/Vector candidate 1 → POLICY SELECTED/)).toBeVisible();
    await expect(page.getByText(/learned memory 00000000 · source incident 00000000/)).toBeVisible();
    await expect(page.getByText(/independently reviewed yes/)).toBeVisible();
    await expect(page.getByText(/semantic similarity .* → governed rank/)).toBeVisible();
    await expect(page.getByRole("button", { name: "Approve exact action" })).toBeEnabled();
    await expect(page.getByRole("button", { name: "Attest execution" })).toBeDisabled();
  });

  test("explains abstention and candidate rejection instead of presenting an unsafe action", async ({ page }) => {
    await mockApi(page, abstainedAnalysis);
    await page.goto("/");
    await page.getByRole("button", { name: "Load safe-failure scenario" }).click();
    await expect(page.getByLabel("Version")).toHaveValue("2099.01");
    await expect(page.getByText(/incompatible memory cannot authorize an action/)).toBeVisible();
    await page.getByRole("button", { name: "Analyze incident" }).click();

    await expect(page.getByRole("heading", { name: abstainedAnalysis.diagnosis })).toBeVisible();
    await expect(page.getByText("Abstained — no compatible successful memory")).toBeVisible();
    await page.getByText(/Candidate evidence and rejection reasons/).click();
    await expect(page.getByText(/negative outcome evidence/)).toBeVisible();
    await expect(page.getByText("read only")).toBeVisible();
    await expect(page.getByRole("button", { name: "Approve exact action" })).toBeDisabled();
    await expect(page.locator("#webmcp-state")).toHaveText("INVESTIGATING");
  });

  test("completes the local governed-memory loop with distinct observer and reviewer identities", async ({ page }) => {
    await mockApi(page);
    const identities: Array<{ path: string; header: string | null; actor: string }> = [];
    await page.route("**/v1/incidents/*/approval", (route) =>
      route.fulfill({ json: { recorded: true } }),
    );
    await page.route("**/v1/incidents/*/execution", (route) =>
      route.fulfill({ status: 201, json: { recorded: true } }),
    );
    await page.route("**/v1/incidents/*/outcome", async (route) => {
      const body = route.request().postDataJSON();
      identities.push({
        path: "outcome",
        header: route.request().headers()["x-actor-id"] ?? null,
        actor: body.actor_id,
      });
      await route.fulfill({ status: 201, json: { id: "00000000-0000-0000-0000-000000000020" } });
    });
    await page.route("**/v1/memories/*/governance", async (route) => {
      const body = route.request().postDataJSON();
      identities.push({
        path: "governance",
        header: route.request().headers()["x-actor-id"] ?? null,
        actor: body.actor_id,
      });
      await route.fulfill({ json: { id: "00000000-0000-0000-0000-000000000020", state: "active" } });
    });
    await page.goto("/");

    await page.getByRole("button", { name: "Analyze incident" }).click();
    await page.getByRole("button", { name: "Approve exact action" }).click();
    await page.getByRole("button", { name: "Attest execution" }).click();
    await page.getByRole("button", { name: "Record successful outcome" }).click();
    await expect(page.getByText(/PENDING REVIEW · MEMORY 00000000/)).toBeVisible();
    await page.getByRole("button", { name: "Activate as reviewer" }).click();
    await expect(page.getByText(/ACTIVE MEMORY · 00000000/)).toBeVisible();

    expect(identities).toEqual([
      { path: "outcome", header: "demo-operator", actor: "demo-operator" },
      { path: "governance", header: "demo-reviewer", actor: "demo-reviewer" },
    ]);
  });

  test("contains long analysis evidence within a mobile viewport", async ({ page }) => {
    const longAnalysis = {
      ...successfulAnalysis,
      diagnosis: `${successfulAnalysis.diagnosis} ${"unbroken-evidence-token".repeat(40)}`,
    };
    await page.setViewportSize({ width: 390, height: 844 });
    await mockApi(page, longAnalysis);
    await page.goto("/");
    await page.getByRole("button", { name: "Analyze incident" }).click();
    await expect(page.getByRole("heading", { name: longAnalysis.diagnosis })).toBeVisible();

    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
    expect(overflow).toBeLessThanOrEqual(0);
  });

  test("registers native tools, exposes accurate annotations, and withdraws proposal authority", async ({ page }) => {
    await installWebMcpHarness(page);
    await mockApi(page);
    await page.goto("/");

    await expect(page.getByText("Native WebMCP active")).toBeVisible();
    await expect.poll(() => page.evaluate(() => Array.from((window as any).__webmcpTools.keys()).sort())).toEqual([
      "inspect_incident",
      "propose_mitigation",
    ]);

    const definitions = await page.evaluate(() =>
      Array.from((window as any).__webmcpTools.values()).map((entry: any) => ({
        name: entry.definition.name,
        annotations: entry.definition.annotations,
        schema: entry.definition.inputSchema,
      })),
    );
    expect(definitions).toEqual(expect.arrayContaining([
      expect.objectContaining({
        name: "inspect_incident",
        annotations: { readOnlyHint: true, untrustedContentHint: true },
        schema: expect.objectContaining({ additionalProperties: false }),
      }),
      expect.objectContaining({
        name: "propose_mitigation",
        annotations: { readOnlyHint: false, untrustedContentHint: true },
        schema: expect.objectContaining({ required: ["service", "service_version", "symptom"], additionalProperties: false }),
      }),
    ]));

    const inspection = await page.evaluate(async () => {
      const tool = (window as any).__webmcpTools.get("inspect_incident").definition;
      return JSON.parse((await tool.execute({})).content[0].text);
    });
    expect(inspection).toMatchObject({
      incident_id: null,
      service: "checkout",
      workflow_state: "INVESTIGATING",
      untrusted_fields: ["service", "service_version", "symptom"],
    });

    const proposal = await page.evaluate(async () => {
      const entry = (window as any).__webmcpTools.get("propose_mitigation");
      (window as any).__cachedProposalExecute = entry.definition.execute;
      const response = await entry.definition.execute({
        service: "checkout",
        service_version: "2026.07.31",
        symptom: "latency spike after connection pool exhaustion",
      });
      return JSON.parse(response.content[0].text);
    });
    expect(proposal).toMatchObject({
      incident_id: successfulAnalysis.incident_id,
      proposal_staged: true,
      requires_human_approval: true,
      proposed_action: { action_hash: "sha256:judge-action" },
    });

    await expect.poll(() => page.evaluate(() => Array.from((window as any).__webmcpTools.keys()))).toEqual(["inspect_incident"]);
    await expect(page.locator("#webmcp-state")).toHaveText("AWAITING_OPERATOR_APPROVAL");
    await expect(page.locator("#webmcp-epoch")).toHaveText("1");
    await expect(page.locator("#webmcp-authority")).toHaveText("HUMAN_OPERATOR");
    await expect(page.locator("#webmcp-withheld")).toContainText("propose_mitigation — unresolved proposal");
    await expect(page.locator("#webmcp-events")).toContainText("propose_mitigation withdrawn");

    const staleFailure = await page.evaluate(async () => {
      try {
        await (window as any).__cachedProposalExecute({ service: "checkout", service_version: "2026.07.31", symptom: "retry" });
        return "unexpected success";
      } catch (error) {
        return (error as Error).message;
      }
    });
    expect(staleFailure).toContain("unavailable in AWAITING_OPERATOR_APPROVAL");

    const registeredNames = await page.evaluate(() => Array.from((window as any).__webmcpTools.keys()));
    expect(registeredNames).not.toEqual(expect.arrayContaining([
      "approve_proposal",
      "apply_sandbox_mitigation",
      "retry_observation",
      "activate_memory",
      "reject_memory",
      "reset_demo",
    ]));
  });

  test("keeps investigation available when policy abstains from a mutating proposal", async ({ page }) => {
    await installWebMcpHarness(page);
    await mockApi(page, abstainedAnalysis);
    await page.goto("/");

    const result = await page.evaluate(async () => {
      const tool = (window as any).__webmcpTools.get("propose_mitigation").definition;
      const response = await tool.execute({
        service: "checkout",
        service_version: "2099.01",
        symptom: "latency spike with no compatible reviewed precedent",
      });
      return JSON.parse(response.content[0].text);
    });

    expect(result).toMatchObject({ proposal_staged: false, requires_human_approval: false });
    await expect.poll(() => page.evaluate(() => Array.from((window as any).__webmcpTools.keys()).sort())).toEqual([
      "inspect_incident",
      "propose_mitigation",
    ]);
    await expect(page.locator("#webmcp-state")).toHaveText("INVESTIGATING");
    await expect(page.locator("#webmcp-events")).toContainText("no mutating proposal staged");
  });
});
