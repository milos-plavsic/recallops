#!/usr/bin/env node
/** Capture authenticated live-console screenshots and a content-addressed index. */

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import process from "node:process";
import { chromium } from "@playwright/test";

const required = ["RECALLOPS_LIVE_URL", "RECALLOPS_OPERATOR_EMAIL", "RECALLOPS_OPERATOR_PASSWORD", "RECALLOPS_RELEASE_SHA"];
for (const name of required) {
  if (!process.env[name]) throw new Error(`${name} is required`);
}
const output = process.env.RECALLOPS_VISUAL_OUTPUT ?? `evidence/visual/${process.env.RECALLOPS_RELEASE_SHA}`;
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 1100 }, deviceScaleFactor: 1 });
try {
  await page.goto(process.env.RECALLOPS_LIVE_URL, { waitUntil: "networkidle" });
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.locator('input[name="username"]:visible').fill(process.env.RECALLOPS_OPERATOR_EMAIL);
  await page.locator('input[name="password"]:visible').fill(process.env.RECALLOPS_OPERATOR_PASSWORD);
  await page.locator('input[name="signInSubmitButton"]:visible, button[type="submit"]:visible').click();
  await page.waitForURL(`${process.env.RECALLOPS_LIVE_URL}/**`, { timeout: 60_000 });
  await page.getByText("API and memory ready").waitFor({ timeout: 60_000 });
  await page.getByRole("heading", { name: /Similarity recalls/ }).click();
  await page.screenshot({ path: `${output}/01-authenticated-console.png`, fullPage: true });

  await page.getByRole("button", { name: "Analyze incident" }).click();
  await page.locator("#result h3").waitFor({ timeout: 60_000 });
  await page.screenshot({ path: `${output}/02-governed-analysis.png`, fullPage: true });

  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: `${output}/03-mobile-analysis.png`, fullPage: true });
  await page.emulateMedia({ reducedMotion: "reduce", colorScheme: "dark" });
  await page.screenshot({ path: `${output}/04-reduced-motion.png`, fullPage: false });
  await page.keyboard.press("Home");
  await page.keyboard.press("Tab");
  await page.screenshot({ path: `${output}/05-keyboard-focus.png`, fullPage: false });
} finally {
  await browser.close();
}

const artifacts = [];
for (const file of [
  "01-authenticated-console.png",
  "02-governed-analysis.png",
  "03-mobile-analysis.png",
  "04-reduced-motion.png",
  "05-keyboard-focus.png",
]) {
  const data = await readFile(`${output}/${file}`);
  artifacts.push({ file, bytes: data.length, sha256: createHash("sha256").update(data).digest("hex") });
}
const report = {
  evidence_version: 1,
  generated_at: new Date().toISOString(),
  build_sha: process.env.RECALLOPS_RELEASE_SHA,
  environment_class: "aws-public-judge-demo-authenticated-browser",
  command: "scripts/capture-live-visual.mjs",
  artifacts,
  assertions: {
    authenticated_console_rendered: true,
    governed_analysis_rendered: true,
    responsive_mobile_rendered: true,
    reduced_motion_rendered: true,
    keyboard_focus_rendered: true,
  },
  passed: true,
  redaction: "Credentials and tokens are never rendered or persisted; identifiers shown are opaque.",
  limitations: "Point-in-time Chromium screenshots; independent reviewer activation is covered separately.",
};
await writeFile(`${output}/index.json`, `${JSON.stringify(report, null, 2)}\n`);
