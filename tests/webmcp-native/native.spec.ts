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
  await page.route("**/v1/incidents", (route) => route.fulfill({ status: 201, json: analysis }));

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
  await expect(page.locator("#webmcp-state")).toHaveText("AWAITING_OPERATOR_APPROVAL");
  await expect(page.locator("#webmcp-authority")).toHaveText("HUMAN_OPERATOR");
});
