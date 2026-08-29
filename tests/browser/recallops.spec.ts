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
    command: "reduce worker concurrency to 24 and recycle saturated connections",
    requires_approval: true,
    action_hash: "9e6e4ae5688cc8c38c60f730139bacc895a485eade9b28a154672b38b0e78be9",
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
    await expect(page.getByText("WebMCP unavailable · no fallback installed")).toBeVisible();
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
    await expect(page.getByRole("button", { name: "Apply sandbox mitigation" })).toBeDisabled();
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
    await installWebMcpHarness(page);
    await mockApi(page);
    const identities: Array<{ path: string; header: string | null; actor: string }> = [];
    let workflow = {
      workflow_id: successfulAnalysis.incident_id, state: "AWAITING_OPERATOR_APPROVAL", epoch: 1,
      active: true, authority_owner: "HUMAN_OPERATOR", available_tools: ["inspect_incident"], protected_tools: [],
    };
    await page.route("**/v1/incidents/*/capabilities", (route) => route.fulfill({ json: workflow }));
    await page.route("**/v1/incidents/*/approval", (route) => {
      workflow = {
        ...workflow, state: "APPROVED_AWAITING_EXECUTION", epoch: 2,
        authority_owner: "HUMAN_OPERATOR", available_tools: ["inspect_incident"],
      };
      return route.fulfill({ json: { recorded: true, workflow } });
    });
    await page.route("**/v1/incidents/*/sandbox-execution", async (route) => {
      const body = route.request().postDataJSON();
      identities.push({
        path: "sandbox",
        header: route.request().headers()["x-actor-id"] ?? null,
        actor: body.actor_id,
      });
      workflow = {
        ...workflow, state: "POSTCHECK_READY", epoch: 4, authority_owner: "AGENT",
        available_tools: ["inspect_incident", "record_postcheck_assessment"],
      };
      await route.fulfill({ status: 201, json: {
        execution: { id: "00000000-0000-0000-0000-000000000030" },
        observation: {
          id: "00000000-0000-0000-0000-000000000040",
          before: { latency_p95_ms: 1420, error_rate: 0.031 },
          after: { latency_p95_ms: 210, error_rate: 0.004 },
        },
        policy_verdict: { classification: "recovered", policy_version: "checkout-recovery-policy-v1" },
        workflow,
      } });
    });
    await page.route("**/v1/incidents/*/postcheck-assessment", async (route) => {
      identities.push({
        path: "assessment",
        header: route.request().headers()["x-actor-id"] ?? null,
        actor: "demo-agent",
      });
      workflow = {
        ...workflow, state: "PENDING_REVIEW", epoch: 5, authority_owner: "HUMAN_REVIEWER",
        available_tools: ["inspect_incident"],
      };
      await route.fulfill({ status: 201, json: {
        assessment: { classification: "recovered" },
        policy_verdict: { classification: "recovered" },
        memory: { id: "00000000-0000-0000-0000-000000000020", state: "pending_review", valid: false },
        workflow,
      } });
    });
    await page.route("**/v1/memories/*/governance", async (route) => {
      const body = route.request().postDataJSON();
      identities.push({
        path: "governance",
        header: route.request().headers()["x-actor-id"] ?? null,
        actor: body.actor_id,
      });
      workflow = {
        ...workflow, state: "REVIEWED", epoch: 6, authority_owner: "AGENT",
        available_tools: ["inspect_incident", "recall_reviewed_memory"],
      };
      await route.fulfill({ json: { id: "00000000-0000-0000-0000-000000000020", state: "active" } });
    });
    await page.goto("/");

    await page.getByRole("button", { name: "Analyze incident" }).click();
    await page.getByRole("button", { name: "Approve exact action" }).click();
    await page.getByRole("button", { name: "Apply sandbox mitigation" }).click();
    await expect.poll(() => page.evaluate(() => Array.from((window as any).__webmcpTools.keys()).sort())).toEqual([
      "inspect_incident", "record_postcheck_assessment",
    ]);
    await page.evaluate(async () => {
      const tool = (window as any).__webmcpTools.get("record_postcheck_assessment").definition;
      await tool.execute({
        observation_id: "00000000-0000-0000-0000-000000000040",
        classification: "recovered",
        rationale: "The bounded latency, error-rate, and saturation checks all recovered.",
      });
    });
    await expect(page.getByText(/PENDING REVIEW · MEMORY 00000000/)).toBeVisible();
    await page.getByRole("button", { name: "Activate as reviewer" }).click();
    await expect(page.getByText(/ACTIVE MEMORY · 00000000/)).toBeVisible();

    expect(identities).toEqual([
      { path: "sandbox", header: "demo-operator", actor: "demo-operator" },
      { path: "assessment", header: "demo-agent", actor: "demo-agent" },
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
      proposal_id: successfulAnalysis.incident_id,
      proposal_staged: true,
      requires_human_approval: true,
      proposal_digest: successfulAnalysis.proposed_action.action_hash,
    });

    await expect.poll(() => page.evaluate(() => Array.from((window as any).__webmcpTools.keys()))).toEqual(["inspect_incident"]);
    await expect(page.locator("#webmcp-state")).toHaveText("AWAITING_OPERATOR_APPROVAL");
    await expect(page.locator("#webmcp-epoch")).toHaveText("1");
    await expect(page.locator("#webmcp-authority")).toHaveText("HUMAN_OPERATOR");
    await expect(page.locator("#webmcp-withheld")).toContainText("propose_mitigation — withheld in AWAITING_OPERATOR_APPROVAL");
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

  test("discards a late registration when a newer manifest withdraws it", async ({ page }) => {
    await page.addInitScript(() => {
      const tools = new Map<string, { definition: any; options: any }>();
      const modelContext = {
        async registerTool(definition: any, options: any = {}) {
          if (definition.name === "propose_mitigation") {
            await new Promise((resolve) => setTimeout(resolve, 1000));
          }
          if (options.signal?.aborted) throw new DOMException("registration aborted", "AbortError");
          tools.set(definition.name, { definition, options });
          options.signal?.addEventListener("abort", () => tools.delete(definition.name), { once: true });
        },
      };
      Object.defineProperty(document, "modelContext", { configurable: true, value: modelContext });
      Object.defineProperty(window, "__webmcpTools", { configurable: true, value: tools });
    });
    await mockApi(page);
    await page.goto("/");
    await page.evaluate(() => window.dispatchEvent(new CustomEvent("recallops:webmcp-state", {
      detail: {
        phase: "AWAITING_OPERATOR_APPROVAL", epoch: 2,
        availableTools: ["inspect_incident"], authorityOwner: "HUMAN_OPERATOR",
      },
    })));
    await expect.poll(() => page.evaluate(() =>
      Array.from((window as any).__webmcpTools.keys()))).toEqual(["inspect_incident"]);
    await expect(page.locator("#webmcp-events")).toContainText("late registration discarded");
  });

  test("reconciles authoritative withdrawal when invocation is cancelled after receipt", async ({ page }) => {
    await installWebMcpHarness(page);
    await mockApi(page);
    let serverReceived = false;
    await page.addInitScript((incidentId) => sessionStorage.setItem("incident_id", incidentId), successfulAnalysis.incident_id);
    await page.unroute("**/v1/incidents/*/capabilities");
    await page.route("**/v1/incidents/*/capabilities", (route) => route.fulfill({ json: {
      workflow_id: successfulAnalysis.incident_id,
      state: serverReceived ? "AWAITING_OPERATOR_APPROVAL" : "INVESTIGATING",
      epoch: serverReceived ? 2 : 1,
      active: true,
      authority_owner: serverReceived ? "HUMAN_OPERATOR" : "AGENT",
      available_tools: serverReceived
        ? ["inspect_incident"] : ["inspect_incident", "propose_mitigation"],
      protected_tools: [],
    } }));
    await page.unroute("**/v1/incidents");
    await page.route("**/v1/incidents", async (route) => {
      serverReceived = true;
      await new Promise((resolve) => setTimeout(resolve, 100));
      await route.fulfill({ status: 201, json: successfulAnalysis }).catch(() => {});
    });
    await page.goto("/");
    const outcome = await page.evaluate(async () => {
      const tool = (window as any).__webmcpTools.get("propose_mitigation").definition;
      const controller = new AbortController();
      const pending = tool.execute({
        service: "checkout", service_version: "2026.07.31",
        symptom: "latency spike after connection pool exhaustion",
      }, { signal: controller.signal });
      setTimeout(() => controller.abort(), 20);
      try { await pending; return "unexpected success"; }
      catch (error) { return (error as Error).name; }
    });
    expect(serverReceived).toBe(true);
    expect(outcome).toBe("AbortError");
    await expect.poll(() => page.evaluate(() =>
      Array.from((window as any).__webmcpTools.keys()))).toEqual(["inspect_incident"]);
    await expect(page.locator("#webmcp-events")).toContainText("invocation cancelled; reconciling committed state");
  });
});

test("judge bootstrap is removed from the URL and WebMCP receives no CSRF authority", async ({ page }) => {
  await installWebMcpHarness(page);
  const proposalHeaders: Record<string, string>[] = [];
  let phase = "INVESTIGATING";
  await page.route("**/v1/config", (route) => route.fulfill({ json: {
    auth_required: false, auth_mode: "judge",
  } }));
  await page.route("**/v1/judge/session/exchange", (route) => route.fulfill({ json: {
    csrf_token: "synchronizer-token",
    identity: { subject: "judge-operator", tenant_id: "judge", roles: ["agent", "operator"] },
  } }));
  await page.route("**/v1/me", (route) => route.fulfill({ json: {
    subject: "judge-operator", tenant_id: "judge", roles: ["agent", "operator"],
  } }));
  await page.route("**/v1/operator/run", (route) => route.fulfill({ json: {
    run_id: "00000000-0000-0000-0000-000000000099", generation: 1,
    incident_id: successfulAnalysis.incident_id, status: "active", simulation: true,
  } }));
  await page.route("**/v1/operator/evidence", (route) => route.fulfill({ json: {
    immutable_observation: null, agent_assessment: null, policy_verdict: null,
    assessment_policy_agree: false, proposal_digest: null, memory: null,
  } }));
  await page.route("**/v1/webmcp/incident", (route) => route.fulfill({ json: {
    incident: { service: "checkout", service_version: "v1", symptom: "latency spike" },
    workflow: { state: phase, epoch: phase === "INVESTIGATING" ? 1 : 2 },
    authority_owner: phase === "INVESTIGATING" ? "AGENT" : "HUMAN_OPERATOR",
    available_tools: phase === "INVESTIGATING"
      ? ["inspect_incident", "propose_mitigation"] : ["inspect_incident"],
    candidates: [], untrusted_fields: ["incident.symptom"], trusted_fields: ["workflow"],
  } }));
  await page.route("**/ready", (route) => route.fulfill({ json: { status: "ready" } }));
  await page.route("**/v1/system/status", (route) => route.fulfill({ json: {
    store: "memory", reasoning_provider: "deterministic", embedding_provider: "deterministic",
    embedding_space: "deterministic-v1", evidence_archive_configured: false, auth_mode: "judge",
  } }));
  await page.route("**/v1/evaluation", (route) => route.fulfill({ json: {
    passed: true, case_count: 1,
    recallops: { top1_safe_accuracy: 1, unsafe_selection_rate: 0, isolation_violations: 0, mean_reciprocal_rank: 1 },
    similarity_only: { top1_safe_accuracy: 0, unsafe_selection_rate: 1, isolation_violations: 0, mean_reciprocal_rank: 0 },
  } }));
  await page.route("**/v1/webmcp/proposal", (route) => {
    proposalHeaders.push(route.request().headers());
    phase = "AWAITING_OPERATOR_APPROVAL";
    return route.fulfill({ status: 201, json: {
      proposal_id: successfulAnalysis.incident_id,
      proposal_digest: successfulAnalysis.proposed_action.action_hash,
      diagnosis: successfulAnalysis.diagnosis,
      action: { id: "checkout.reduce_concurrency_and_recycle.v1", risk_class: "mutating" },
      requires_human_approval: true, authority_owner: "HUMAN_OPERATOR", epoch: 2,
    } });
  });
  await page.route("**/v1/webmcp/capabilities", (route) => route.fulfill({ json: {
    run_id: "00000000-0000-0000-0000-000000000099", run_generation: 1,
    workflow_id: successfulAnalysis.incident_id, state: phase,
    epoch: phase === "INVESTIGATING" ? 1 : 2,
    authority_owner: phase === "INVESTIGATING" ? "AGENT" : "HUMAN_OPERATOR",
    available_tools: phase === "INVESTIGATING"
      ? ["inspect_incident", "propose_mitigation"] : ["inspect_incident"],
    withheld_tools: [], protected_operations: [], memory_governance_version: 0,
    capability_policy_version: "webmcp-capability-v1", build_sha: "test", etag: '"manifest"',
  } }));
  await page.route("**/v1/webmcp/activity", (route) => route.fulfill({ status: 202, json: { accepted: 1 } }));

  await page.goto("/#access=judge-bootstrap-secret");
  await expect(page).toHaveURL(/\/$/);
  await expect(page.locator("#auth-status")).toContainText("agent + operator · judge-op");
  await expect(page.locator("#webmcp-epoch")).toHaveText("1");
  await page.evaluate(async () => {
    const tools = (window as any).__webmcpTools as Map<string, any>;
    await tools.get("propose_mitigation").definition.execute({
      service: "checkout", service_version: "v1", symptom: "latency spike",
    });
  });

  expect(proposalHeaders).toHaveLength(1);
  expect(proposalHeaders[0]["x-csrf-token"]).toBeUndefined();
  expect(proposalHeaders[0]["x-roles"]).toBeUndefined();
  expect(proposalHeaders[0]["x-actor-id"]).toBeUndefined();
  expect(proposalHeaders[0]["if-match"]).toBe('"1:1"');
  expect(proposalHeaders[0]["idempotency-key"]).toBeTruthy();
  expect(await page.evaluate(() => sessionStorage.getItem("judge_csrf"))).toBe("synchronizer-token");
  expect(page.url()).not.toContain("judge-bootstrap-secret");
});
