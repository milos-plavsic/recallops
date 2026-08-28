import { expect, test } from "@playwright/test";

const analysis = {
  incident_id: "00000000-0000-0000-0000-000000000010",
  diagnosis: "Compatible reviewed memory supports a bounded pool-size mitigation.",
  confidence: 0.86,
  proposed_action: {
    name: "increase_pool_size",
    command: "increase checkout pool size and observe latency",
    risk: "mutating_requires_approval",
    rationale: "Compatible reviewed recovery evidence exists",
    requires_approval: true,
    action_hash: "sha256:native-webmcp-action",
  },
  memories: [],
  retrieval_abstention_reasons: [],
  degraded_dependencies: [],
  candidate_decisions: [],
  agent_trace: [],
};

test("Chromium discovers, invokes, and observes withdrawal of native tools", async ({ page, browserName }) => {
  test.skip(browserName !== "chromium", "WebMCP is currently exercised in Chromium");
  let proposalHeaders: Record<string, string> = {};
  await page.route("**/v1/config", (route) => route.fulfill({ json: { auth_required: false } }));
  await page.route("**/ready", (route) => route.fulfill({ json: { status: "ready" } }));
  await page.route("**/v1/system/status", (route) => route.fulfill({ json: {
    store: "memory", reasoning_provider: "deterministic", embedding_provider: "deterministic",
    embedding_space: "deterministic-v1", evidence_archive_configured: false, auth_mode: "demo",
  } }));
  await page.route("**/v1/evaluation", (route) => route.fulfill({ json: {
    passed: true, case_count: 1,
    recallops: { top1_safe_accuracy: 1, unsafe_selection_rate: 0, isolation_violations: 0, mean_reciprocal_rank: 1 },
    similarity_only: { top1_safe_accuracy: 0, unsafe_selection_rate: 1, isolation_violations: 0, mean_reciprocal_rank: 0 },
  } }));
  await page.route("**/v1/incidents", (route) => {
    proposalHeaders = route.request().headers();
    return route.fulfill({ status: 201, json: analysis });
  });
  await page.route("**/v1/incidents/*/capabilities", (route) => route.fulfill({ json: {
    workflow_id: analysis.incident_id,
    state: "AWAITING_OPERATOR_APPROVAL",
    epoch: 1,
    active: true,
    authority_owner: "HUMAN_OPERATOR",
    available_tools: ["inspect_incident"],
    protected_tools: [],
  } }));

  await page.goto("/");
  await expect(page.getByText("Native WebMCP active")).toBeVisible();

  const evidence = await page.evaluate(async () => {
    const context = (document as any).modelContext;
    const before = await context.getTools();
    const proposal = before.find((tool: any) => tool.name === "propose_mitigation");
    const raw = await context.executeTool(proposal, JSON.stringify({
      service: "checkout",
      service_version: "2026.07.31",
      symptom: "latency spike after connection pool exhaustion",
    }));
    await new Promise((resolve) => setTimeout(resolve, 100));
    const after = await context.getTools();
    return {
      before: before.map((tool: any) => ({
        name: tool.name,
        annotations: tool.annotations,
        inputSchema: JSON.parse(tool.inputSchema),
      })),
      result: JSON.parse(JSON.parse(raw).content[0].text),
      after: after.map((tool: any) => tool.name),
    };
  });

  expect(evidence.before.map((tool: any) => tool.name)).toEqual(["inspect_incident", "propose_mitigation"]);
  expect(evidence.before.find((tool: any) => tool.name === "inspect_incident").annotations).toMatchObject({
    readOnlyHint: true,
    untrustedContentHint: true,
  });
  expect(evidence.before.find((tool: any) => tool.name === "propose_mitigation").inputSchema).toMatchObject({
    required: ["service", "service_version", "symptom"],
    additionalProperties: false,
  });
  expect(evidence.result).toMatchObject({ proposal_staged: true, requires_human_approval: true });
  expect(evidence.after).toEqual(["inspect_incident"]);
  expect(proposalHeaders["x-recallops-channel"]).toBe("webmcp");
  expect(proposalHeaders["x-actor-id"]).toBe("demo-agent");
  expect(proposalHeaders["x-roles"]).toBe("agent");
  await expect(page.locator("#webmcp-state")).toHaveText("AWAITING_OPERATOR_APPROVAL");
  await expect(page.locator("#webmcp-epoch")).toHaveText("1");
  await expect(page.locator("#webmcp-authority")).toHaveText("HUMAN_OPERATOR");
});

test("native Chromium and the real server enforce the same authority boundary", async ({ page, request }) => {
  const operator = {
    "X-Tenant-ID": "native",
    "X-Actor-ID": "native-operator",
    "X-Roles": "operator",
    "X-RecallOps-Channel": "ui",
  };
  const seedPayload = {
    tenant_id: "native",
    service: "checkout",
    service_version: "v1",
    symptom: "latency spike after connection pool exhaustion",
    idempotency_key: `native-seed-${Date.now()}`,
  };
  const seededIncident = await request.post("/v1/incidents", { headers: operator, data: seedPayload });
  expect(seededIncident.status()).toBe(201);
  const seed = await seededIncident.json();
  expect(seed.proposed_action.requires_approval).toBe(false);

  const execution = await request.post(`/v1/incidents/${seed.incident_id}/execution`, {
    headers: { ...operator, "X-Workflow-Epoch": "1" },
    data: {
      tenant_id: "native",
      actor_id: "native-operator",
      action_hash: seed.proposed_action.action_hash,
      action_taken: seed.proposed_action.command,
      evidence_refs: ["native://seed/execution"],
    },
  });
  expect(execution.status()).toBe(201);
  const observation = await request.post(`/v1/incidents/${seed.incident_id}/outcome`, {
    headers: { ...operator, "X-Workflow-Epoch": "2" },
    data: {
      tenant_id: "native",
      actor_id: "native-operator",
      action_taken: seed.proposed_action.command,
      outcome: "latency recovered during the deterministic observation window",
      outcome_score: 1,
      confidence: 0.95,
    },
  });
  expect(observation.status()).toBe(201);
  const memory = await observation.json();
  const review = await request.post(`/v1/memories/${memory.id}/governance`, {
    headers: {
      "X-Tenant-ID": "native",
      "X-Actor-ID": "native-reviewer",
      "X-Roles": "reviewer",
      "X-RecallOps-Channel": "ui",
      "X-Workflow-Epoch": "3",
    },
    data: {
      tenant_id: "native",
      actor_id: "native-reviewer",
      action: "activate",
      reason: "independent deterministic seed review",
    },
  });
  expect(review.status()).toBe(200);

  await page.goto("/");
  await page.getByLabel("Tenant").fill("native");
  await expect(page.getByText("Native WebMCP active")).toBeVisible();
  const result = await page.evaluate(async () => {
    const context = (document as any).modelContext;
    const tools = await context.getTools();
    const proposal = tools.find((tool: any) => tool.name === "propose_mitigation");
    const raw = await context.executeTool(proposal, JSON.stringify({
      service: "checkout",
      service_version: "v1",
      symptom: "latency spike after connection pool exhaustion",
    }));
    await new Promise((resolve) => setTimeout(resolve, 100));
    return {
      payload: JSON.parse(JSON.parse(raw).content[0].text),
      tools: (await context.getTools()).map((tool: any) => tool.name),
    };
  });
  expect(result.payload).toMatchObject({ proposal_staged: true, requires_human_approval: true });
  expect(result.tools).toEqual(["inspect_incident"]);
  await expect(page.locator("#webmcp-state")).toHaveText("AWAITING_OPERATOR_APPROVAL");

  const bypass = await request.post(`/v1/incidents/${result.payload.incident_id}/approval`, {
    headers: {
      ...operator,
      "X-Actor-ID": "native-agent",
      "X-Roles": "agent,operator",
      "X-RecallOps-Channel": "webmcp",
      "X-Workflow-Epoch": "1",
    },
    data: {
      tenant_id: "native",
      actor_id: "native-agent",
      approved: true,
      reason: "this WebMCP authority bypass must fail",
    },
  });
  expect(bypass.status()).toBe(403);
});
