#!/usr/bin/env node
/* Full public-path smoke with identity-drift and offline-bundle verification. */

import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const liveUrl = process.env.RECALLOPS_LIVE_URL;
const expectedReleaseId = process.env.RECALLOPS_EXPECTED_RELEASE_ID;
const expectedSourceSha = process.env.RECALLOPS_EXPECTED_SOURCE_SHA;
const registry = process.env.RECALLOPS_TRUSTED_KEYS ?? "tools/trusted-receipt-keys.json";
const output = process.env.RECALLOPS_SMOKE_OUTPUT ?? "artifacts/smoke-live.json";

if (!liveUrl || !expectedReleaseId || !expectedSourceSha) {
  throw new Error(
    "RECALLOPS_LIVE_URL, RECALLOPS_EXPECTED_RELEASE_ID, and " +
      "RECALLOPS_EXPECTED_SOURCE_SHA are required",
  );
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function releaseStatus() {
  const response = await fetch(`${liveUrl}/v1/release`, {
    headers: { accept: "application/json", "cache-control": "no-store" },
  });
  assert(response.ok, `release status returned HTTP ${response.status}`);
  const status = await response.json();
  assert(status.configured === true, "release evidence is not configured");
  assert(status.release_id === expectedReleaseId, "release ID drift detected");
  assert(status.source_sha === expectedSourceSha, "source SHA drift detected");
  assert(/^sha256:[a-f0-9]{64}$/.test(status.image_digest), "invalid image digest");
  return status;
}

const startedAt = new Date().toISOString();
const before = await releaseStatus();
const browser = spawnSync(
  "npx",
  ["playwright", "test", "--config", "playwright.live.config.ts"],
  {
    cwd: resolve("."),
    env: { ...process.env, RECALLOPS_LIVE_URL: liveUrl },
    encoding: "utf8",
    stdio: ["ignore", "inherit", "inherit"],
  },
);
assert(browser.status === 0, `public browser journey failed with exit ${browser.status}`);

const browserProof = JSON.parse(
  readFileSync("artifacts/item10-live-browser/live-browser-proof.json", "utf8"),
);
assert(browserProof.passed === true, "browser proof did not pass");
assert(browserProof.public_url === liveUrl, "browser proof URL drift detected");
assert(
  /^[a-f0-9]{64}$/.test(browserProof.bundle_digest),
  "browser proof omitted the bundle digest",
);

const bundleRoot = mkdtempSync(join(tmpdir(), "recallops-scheduled-smoke-"));
execFileSync(
  "unzip",
  ["-q", "artifacts/item10-live-browser/authority-bundle.zip", "-d", bundleRoot],
  { stdio: "ignore" },
);
const verifier = spawnSync(
  "node",
  [
    "tools/verify-authority-bundle.mjs",
    bundleRoot,
    "--registry",
    registry,
    "--bundle-digest",
    browserProof.bundle_digest,
  ],
  { encoding: "utf8" },
);
const verification = JSON.parse(verifier.stdout);
assert(verifier.status === 0 && verification.code === "VERIFIED", "offline verification failed");

const bundleRelease = JSON.parse(readFileSync(join(bundleRoot, "release.json"), "utf8"));
assert(bundleRelease.release_id === before.release_id, "bundle release ID drift detected");
assert(bundleRelease.source_sha === before.source_sha, "bundle source SHA drift detected");
assert(bundleRelease.image_digest === before.image_digest, "bundle image digest drift detected");
const after = await releaseStatus();
assert(JSON.stringify(before) === JSON.stringify(after), "release status changed during smoke");

const evidence = {
  schema_version: "recallops-scheduled-smoke-v1",
  started_at: startedAt,
  completed_at: new Date().toISOString(),
  public_url: liveUrl,
  release: {
    release_id: before.release_id,
    source_sha: before.source_sha,
    image_digest: before.image_digest,
  },
  assertions: {
    identity_stable_before_after: true,
    full_public_browser_journey: true,
    signed_receipt: browserProof.signed_receipt,
    credential_free_bundle_download: browserProof.credential_free_bundle_download,
    bundle_digest: browserProof.bundle_digest,
    offline_verifier_code: verification.code,
    authority_event_count: verification.event_count,
    serious_or_critical_accessibility_violations:
      browserProof.operator_serious_or_critical_accessibility_violations +
      browserProof.reviewer_serious_or_critical_accessibility_violations,
    browser_page_errors: browserProof.browser_page_errors,
    release_ready_at_capture: before.release_ready,
  },
  limitations:
    "Synthetic point-in-time smoke; workflow failure alerts operators but cannot finalize a proof gate.",
  passed: true,
};
writeFileSync(output, `${JSON.stringify(evidence, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
process.stdout.write(`${JSON.stringify(evidence)}\n`);
