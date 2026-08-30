import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    const tools = new Map<string, { definition: any; options: any }>();
    Object.defineProperty(document, "modelContext", {
      configurable: true,
      value: {
        async registerTool(definition: any, options: any = {}) {
          if (options.signal?.aborted) throw new DOMException("registration aborted", "AbortError");
          tools.set(definition.name, { definition, options });
          options.signal?.addEventListener("abort", () => tools.delete(definition.name), { once: true });
        },
      },
    });
    Object.defineProperty(window, "__webmcpTools", { configurable: true, value: tools });
  });
});

test("a first-time judge completes the visible governed recurrence without documentation", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Investigate with agents/ })).toBeVisible();
  await expect(page.getByText("checkout-latency-42", { exact: false }).first()).toBeVisible();
  await expect(page.getByText("0.94 similarity")).toBeVisible();
  await expect(page.locator("#hero-agent-prompt")).toContainText("Do not authorize or execute");
  await expect.poll(() => page.evaluate(() =>
    Array.from((window as any).__webmcpTools.keys()))).toEqual([]);
  await page.getByRole("button", { name: "Start isolated judge scenario" }).click();

  await expect(page.locator("#webmcp-state")).toHaveText("INVESTIGATING");
  await expect(page.locator("#hero-rejected-score")).toHaveText("0.94 similarity");
  await expect(page.locator("#hero-rejected-memory")).toContainText("service_version_incompatible");
  await expect.poll(() => page.evaluate(() =>
    Array.from((window as any).__webmcpTools.keys()).sort())).toEqual([
      "inspect_incident", "propose_mitigation",
    ]);

  await page.evaluate(async () => {
    const tool = (window as any).__webmcpTools.get("propose_mitigation").definition;
    await tool.execute({
      service: "checkout",
      service_version: "v2.4.1",
      symptom: "checkout-latency-42: p95 latency and error rate exceed the sandbox SLO",
      rationale: "Select only the eligible reviewed memory.",
    });
  });
  await expect(page.locator("#webmcp-state")).toHaveText("AWAITING_OPERATOR_APPROVAL");
  await expect.poll(() => page.evaluate(() =>
    Array.from((window as any).__webmcpTools.keys()))).toEqual(["inspect_incident"]);
  await expect(page.locator("#authority-explanation")).toContainText("Only the authenticated operator");

  await page.getByRole("button", { name: "Approve exact action" }).click();
  await page.getByRole("button", { name: "Apply sandbox mitigation" }).click();
  await expect(page.locator("#webmcp-state")).toHaveText("POSTCHECK_READY");
  await expect(page.locator("#evidence-observation")).toContainText("1420 ms → 210 ms");
  await expect.poll(() => page.evaluate(() =>
    Array.from((window as any).__webmcpTools.keys()).sort())).toEqual([
      "inspect_incident", "record_postcheck_assessment",
    ]);

  await page.evaluate(async () => {
    const tool = (window as any).__webmcpTools.get("record_postcheck_assessment").definition;
    const observationId = sessionStorage.getItem("observation_id");
    await tool.execute({
      observation_id: observationId,
      classification: "recovered",
      rationale: "All immutable recovery checks satisfy the published policy.",
    });
  });
  await expect(page.locator("#webmcp-state")).toHaveText("PENDING_REVIEW");
  await expect(page.locator("#evidence-assessment")).toHaveText("recovered");
  await page.reload();
  await expect(page.locator("#webmcp-state")).toHaveText("PENDING_REVIEW");
  await expect(
    page.getByRole("button", { name: "Create independent reviewer handoff" }),
  ).toBeEnabled();
  await page.getByRole("button", { name: "Create independent reviewer handoff" }).click();
  const reviewerLink = page.getByRole("link", { name: "Open independent reviewer" });
  await expect(reviewerLink).toBeVisible();
  const reviewer = await page.context().newPage();
  await reviewer.goto(await reviewerLink.getAttribute("href") || "/reviewer");
  await expect(reviewer.getByText("zero agent tools", { exact: false })).toBeVisible();
  await expect(reviewer.locator("#reviewer-identity")).toContainText("separate from operator and agent");
  await reviewer.getByRole("button", { name: "Certify evidence" }).click();
  await expect(reviewer.locator("#review-status")).toContainText("never an agent tool");

  await expect.poll(async () => {
    await page.bringToFront();
    return page.locator("#webmcp-state").textContent();
  }, { timeout: 10_000 }).toBe("REVIEWED");
  await expect.poll(() => page.evaluate(() =>
    Array.from((window as any).__webmcpTools.keys()).sort())).toEqual([
      "inspect_incident", "recall_reviewed_memory",
    ]);
  await expect(page.locator("#receipt-proof")).toBeVisible();
  await expect(page.locator("#receipt-status")).toContainText("PROOF PENDING");
  await expect(page.locator("#receipt-chain li")).toHaveCount(7);
  await expect(page.locator("#receipt-limitations")).toContainText("does not prove external truth");
  await expect(page.locator("#receipt-download")).toBeHidden();
  await page.evaluate(async () => {
    const tool = (window as any).__webmcpTools.get("recall_reviewed_memory").definition;
    await tool.execute({});
  });
  await expect(page.locator("#recurrence-proof")).toBeVisible();
  await expect(page.locator("#recurrence-title")).toHaveText(
    "Independent review changed the evidence authority",
  );
  await expect(page.locator("#recurrence-before")).toContainText("evidence");
  await expect(page.locator("#recurrence-change")).toContainText(
    "bounded action remained stable",
  );
  await expect(page.locator("#live-proof-badge")).toHaveText("LIVE PROOF · PENDING");
  await expect(page.locator("#assurance-badge")).toHaveText("ASSURANCE · PENDING");
  await expect.poll(() => page.locator("#authority-events li").count()).toBeGreaterThanOrEqual(7);
  const authorityEvidence = await page.locator("#authority-events").textContent();
  expect(authorityEvidence).toContain("authority_commit");
  expect(authorityEvidence).toContain("INVESTIGATING → AWAITING_OPERATOR_APPROVAL");
  expect(authorityEvidence).toContain("PENDING_REVIEW → REVIEWED");

  const operatorA11y = await new AxeBuilder({ page }).analyze();
  const reviewerA11y = await new AxeBuilder({ page: reviewer }).analyze();
  expect(operatorA11y.violations.filter((item) => ["serious", "critical"].includes(item.impact || ""))).toEqual([]);
  expect(reviewerA11y.violations.filter((item) => ["serious", "critical"].includes(item.impact || ""))).toEqual([]);
});

test("the control room remains usable without horizontal overflow at constrained width", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  const layout = await page.evaluate(() => ({
    overflow: document.documentElement.scrollWidth - innerWidth,
    offenders: Array.from(document.querySelectorAll("body *"))
      .filter((element) => element.getBoundingClientRect().right > innerWidth)
      .slice(0, 8)
      .map((element) => ({
        tag: element.tagName,
        id: element.id,
        className: element.className,
        right: Math.round(element.getBoundingClientRect().right),
      })),
  }));
  expect(layout.overflow, JSON.stringify(layout.offenders, null, 2)).toBeLessThanOrEqual(0);
  await expect(page.locator("#hero-agent-prompt")).toBeVisible();
  await expect(page.getByRole("button", { name: "Start isolated judge scenario" })).toBeVisible();
});
