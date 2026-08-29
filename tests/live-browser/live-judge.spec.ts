import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { mkdir, writeFile } from "node:fs/promises";

const evidenceRoot = "artifacts/item10-live-browser";

test.beforeEach(async ({ context }) => {
  await context.addInitScript(() => {
    const tools = new Map<string, { definition: any; options: any }>();
    Object.defineProperty(document, "modelContext", {
      configurable: true,
      value: {
        async registerTool(definition: any, options: any = {}) {
          if (options.signal?.aborted) {
            throw new DOMException("registration aborted", "AbortError");
          }
          tools.set(definition.name, { definition, options });
          options.signal?.addEventListener(
            "abort",
            () => tools.delete(definition.name),
            { once: true },
          );
        },
      },
    });
    Object.defineProperty(window, "__webmcpTools", {
      configurable: true,
      value: tools,
    });
  });
});

test("public judge path produces a signed, downloadable authority bundle", async ({
  page,
}) => {
  await mkdir(evidenceRoot, { recursive: true });
  const browserErrors: string[] = [];
  page.on("pageerror", (error) => browserErrors.push(error.message));

  await page.goto("/", { waitUntil: "domcontentloaded" });
  await expect(page.locator("#health-label")).toHaveText(
    "API and memory ready",
  );
  await expect(
    page.getByText("No active judge run", { exact: false }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Start isolated judge scenario" })
    .click();
  await expect(page.locator("#webmcp-state")).toHaveText("INVESTIGATING");
  await expect
    .poll(() =>
      page.evaluate(() =>
        Array.from((window as any).__webmcpTools.keys()).sort(),
      ),
    )
    .toEqual(["inspect_incident", "propose_mitigation"]);
  await expect(page.locator("#hero-rejected-memory")).toContainText(
    "service_version_incompatible",
  );

  await page.evaluate(async () => {
    const tool = (window as any).__webmcpTools.get(
      "propose_mitigation",
    ).definition;
    await tool.execute({
      service: "checkout",
      service_version: "v2.4.1",
      symptom:
        "checkout-latency-42: p95 latency and error rate exceed the sandbox SLO",
      rationale:
        "Select only independently reviewed and policy-eligible evidence.",
    });
  });
  await expect(page.locator("#webmcp-state")).toHaveText(
    "AWAITING_OPERATOR_APPROVAL",
  );
  await expect
    .poll(() =>
      page.evaluate(() => Array.from((window as any).__webmcpTools.keys())),
    )
    .toEqual(["inspect_incident"]);
  await expect(page.locator("#webmcp-withheld")).toContainText(
    "approve_proposal — never exposed to agents",
  );

  await page.getByRole("button", { name: "Approve exact action" }).click();
  await page.getByRole("button", { name: "Apply sandbox mitigation" }).click();
  await expect(page.locator("#webmcp-state")).toHaveText("POSTCHECK_READY");
  await expect(page.locator("#evidence-observation")).toContainText(
    "1420 ms → 210 ms",
  );
  await expect
    .poll(() =>
      page.evaluate(() =>
        Array.from((window as any).__webmcpTools.keys()).sort(),
      ),
    )
    .toEqual(["inspect_incident", "record_postcheck_assessment"]);

  await page.evaluate(async () => {
    const tool = (window as any).__webmcpTools.get(
      "record_postcheck_assessment",
    ).definition;
    await tool.execute({
      observation_id: sessionStorage.getItem("observation_id"),
      classification: "not_recovered",
      rationale:
        "Deliberate disagreement retained separately from the policy verdict.",
    });
  });
  await expect(page.locator("#webmcp-state")).toHaveText("PENDING_REVIEW");
  await expect(page.locator("#evidence-assessment")).toHaveText(
    "not_recovered",
  );
  await expect(page.locator("#evidence-verdict")).toContainText("recovered");
  await expect
    .poll(() =>
      page.evaluate(() => Array.from((window as any).__webmcpTools.keys())),
    )
    .toEqual(["inspect_incident"]);

  await page
    .getByRole("button", { name: "Create independent reviewer handoff" })
    .click();
  const reviewerLink = page.getByRole("link", {
    name: "Open independent reviewer",
  });
  await expect(reviewerLink).toBeVisible();
  const reviewer = await page.context().newPage();
  await reviewer.goto((await reviewerLink.getAttribute("href")) || "/reviewer");
  await expect(
    reviewer.getByText("zero agent tools", { exact: false }),
  ).toBeVisible();
  await expect(reviewer.locator("#reviewer-identity")).toContainText(
    "separate from operator and agent",
  );
  await expect
    .poll(() =>
      reviewer.evaluate(() => Array.from((window as any).__webmcpTools.keys())),
    )
    .toEqual([]);
  await reviewer.getByRole("button", { name: "Certify evidence" }).click();
  await expect(reviewer.locator("#review-status")).toContainText(
    "never an agent tool",
  );

  await expect
    .poll(
      async () => {
        await page.bringToFront();
        return page.locator("#webmcp-state").textContent();
      },
      { timeout: 15_000 },
    )
    .toBe("REVIEWED");
  await page.evaluate(async () => {
    const tool = (window as any).__webmcpTools.get(
      "recall_reviewed_memory",
    ).definition;
    await tool.execute({});
  });
  await expect(page.locator("#recurrence-proof")).toBeVisible();

  await expect
    .poll(
      async () => {
        const response = await page.request.get("/v1/evidence/receipt");
        if (response.status() !== 200) return `HTTP ${response.status()}`;
        const body = await response.json();
        return body.receipt?.status ?? "receipt unavailable";
      },
      { timeout: 120_000, intervals: [2_000, 3_000, 5_000] },
    )
    .toBe("signed");
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.locator("#health-label")).toHaveText(
    "API and memory ready",
  );
  await expect(page.locator("#receipt-status")).toContainText("SIGNED");
  await expect(page.locator("#receipt-chain li")).toHaveCount(7);
  await expect(page.locator("#receipt-limitations")).toContainText(
    "does not prove external truth",
  );
  const bundleUrl = await page
    .locator("#receipt-download")
    .getAttribute("href");
  expect(bundleUrl).toBeTruthy();
  const bundle = await page.request.get(bundleUrl!);
  expect(bundle.status()).toBe(200);
  expect(bundle.headers()["content-type"]).toContain("application/zip");
  const bundleDigest = bundle.headers()["x-recallops-bundle-digest"];
  expect(bundleDigest).toMatch(/^[a-f0-9]{64}$/);
  await writeFile(`${evidenceRoot}/authority-bundle.zip`, await bundle.body());

  const operatorA11y = await new AxeBuilder({ page }).analyze();
  const reviewerA11y = await new AxeBuilder({ page: reviewer }).analyze();
  const severe = (result: typeof operatorA11y) =>
    result.violations.filter((item) =>
      ["serious", "critical"].includes(item.impact || ""),
    );
  expect(severe(operatorA11y)).toEqual([]);
  expect(severe(reviewerA11y)).toEqual([]);
  await page.screenshot({
    path: `${evidenceRoot}/operator-reviewed.png`,
    fullPage: true,
  });
  await reviewer.screenshot({
    path: `${evidenceRoot}/independent-reviewer.png`,
    fullPage: true,
  });
  await writeFile(
    `${evidenceRoot}/live-browser-proof.json`,
    `${JSON.stringify(
      {
        public_url: process.env.RECALLOPS_LIVE_URL,
        signed_receipt: true,
        credential_free_bundle_download: true,
        bundle_digest: bundleDigest,
        operator_serious_or_critical_accessibility_violations:
          severe(operatorA11y).length,
        reviewer_serious_or_critical_accessibility_violations:
          severe(reviewerA11y).length,
        browser_page_errors: browserErrors,
        passed: browserErrors.length === 0,
      },
      null,
      2,
    )}\n`,
  );
  expect(browserErrors).toEqual([]);
});

test("public narrow viewport has no horizontal overflow", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await expect(page.locator("#health-label")).toHaveText(
    "API and memory ready",
  );
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - innerWidth,
  );
  expect(overflow).toBeLessThanOrEqual(0);
  await expect(
    page.getByRole("button", { name: "Start isolated judge scenario" }),
  ).toBeVisible();
});
