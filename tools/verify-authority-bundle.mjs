#!/usr/bin/env node
/* Network-free RecallOps authority-bundle verifier. Node built-ins only. */

import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { resolve, relative, sep } from "node:path";

const VERSION = "authority-bundle-verifier-v1";
const MAX_BUNDLE = 8 * 1024 * 1024;
const MAX_FILE = 2 * 1024 * 1024;
const ALLOWED = [
  "README.md", "checksums.sha256", "claims.json", "evaluation/case.json",
  "evaluation/result.json", "events.ndjson", "evidence-index.jcs.json",
  "manifest.jcs.json", "policy/capability-policy.json",
  "policy/receipt-policy.json", "public.jwk.json", "receipt.jws", "release.json",
];
const AUXILIARY = [
  "public.jwk.json", "events.ndjson", "policy/capability-policy.json",
  "policy/receipt-policy.json", "evaluation/case.json", "evaluation/result.json",
  "release.json", "claims.json",
];
const CAPABILITIES = {
  ABSENT: [], INVESTIGATING: ["inspect_incident", "propose_mitigation"],
  AWAITING_OPERATOR_APPROVAL: ["inspect_incident"],
  APPROVED_AWAITING_EXECUTION: ["inspect_incident"],
  OBSERVING_POSTCHECK: ["inspect_incident"], POSTCHECK_READY: ["inspect_incident", "record_postcheck_assessment"],
  POSTCHECK_UNAVAILABLE: ["inspect_incident"], PENDING_REVIEW: ["inspect_incident"],
  REVIEWED: ["inspect_incident", "recall_reviewed_memory"],
};
const TRANSITIONS = new Set([
  "ABSENT>INVESTIGATING", "INVESTIGATING>AWAITING_OPERATOR_APPROVAL",
  "AWAITING_OPERATOR_APPROVAL>INVESTIGATING",
  "AWAITING_OPERATOR_APPROVAL>APPROVED_AWAITING_EXECUTION",
  "APPROVED_AWAITING_EXECUTION>OBSERVING_POSTCHECK",
  "OBSERVING_POSTCHECK>POSTCHECK_READY", "OBSERVING_POSTCHECK>POSTCHECK_UNAVAILABLE",
  "POSTCHECK_UNAVAILABLE>OBSERVING_POSTCHECK", "POSTCHECK_READY>PENDING_REVIEW",
  "PENDING_REVIEW>REVIEWED",
]);
const TRANSITION_ROLES = {
  "ABSENT>INVESTIGATING": "system",
  "INVESTIGATING>AWAITING_OPERATOR_APPROVAL": "agent",
  "AWAITING_OPERATOR_APPROVAL>INVESTIGATING": "operator",
  "AWAITING_OPERATOR_APPROVAL>APPROVED_AWAITING_EXECUTION": "operator",
  "APPROVED_AWAITING_EXECUTION>OBSERVING_POSTCHECK": "operator",
  "OBSERVING_POSTCHECK>POSTCHECK_READY": "system",
  "OBSERVING_POSTCHECK>POSTCHECK_UNAVAILABLE": "system",
  "POSTCHECK_UNAVAILABLE>OBSERVING_POSTCHECK": "operator",
  "POSTCHECK_READY>PENDING_REVIEW": "agent",
  "PENDING_REVIEW>REVIEWED": "reviewer",
};
const EVENT_KEYS = [
  "actor_role", "actor_subject", "build_sha", "capabilities_after", "capabilities_before",
  "channel", "display_summary", "epoch_after", "epoch_before", "event_hash", "event_id",
  "event_type", "object_digest", "object_id", "object_type", "outcome", "policy_version",
  "previous_event_hash", "reason_code", "recorded_at", "run_id", "sequence", "state_after",
  "state_before", "tenant_id", "workflow_id",
];

class Failure extends Error { constructor(code, message) { super(message); this.code = code; } }
const fail = (code, message) => { throw new Failure(code, message); };
const sha = (value) => createHash("sha256").update(value).digest("hex");
const contentDigest = (domain, value) => sha(Buffer.concat([Buffer.from(domain), Buffer.from("\0"), Buffer.from(canonical(value))]));
const b64u = (value) => Buffer.from(value).toString("base64url");
const fromB64u = (value, code = "E_JWS_ENCODING") => {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) fail(code, "non-canonical base64url");
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) fail(code, "non-canonical base64url");
  return decoded;
};

function scanNoDuplicateKeys(text) {
  let i = 0;
  const ws = () => { while (/\s/.test(text[i] ?? "")) i++; };
  const string = () => {
    if (text[i++] !== '"') fail("E_JSON", "expected string");
    let raw = '"';
    while (i < text.length) {
      const ch = text[i++]; raw += ch;
      if (ch === '"') break;
      if (ch === "\\") { if (i >= text.length) fail("E_JSON", "truncated escape"); raw += text[i++]; }
      else if (ch < " ") fail("E_JSON", "control character in string");
    }
    try { return JSON.parse(raw); } catch { fail("E_JSON", "invalid JSON string"); }
  };
  const value = () => {
    ws(); const ch = text[i];
    if (ch === "{") {
      i++; ws(); const keys = new Set();
      if (text[i] === "}") { i++; return; }
      while (true) {
        ws(); const key = string();
        if (keys.has(key)) fail("E_JSON_DUPLICATE", "duplicate JSON property"); keys.add(key);
        ws(); if (text[i++] !== ":") fail("E_JSON", "expected colon"); value(); ws();
        if (text[i] === "}") { i++; return; }
        if (text[i++] !== ",") fail("E_JSON", "expected comma");
      }
    }
    if (ch === "[") {
      i++; ws(); if (text[i] === "]") { i++; return; }
      while (true) { value(); ws(); if (text[i] === "]") { i++; return; } if (text[i++] !== ",") fail("E_JSON", "expected comma"); }
    }
    if (ch === '"') { string(); return; }
    const match = text.slice(i).match(/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/);
    if (!match) fail("E_JSON", "invalid JSON value");
    i += match[0].length;
  };
  value(); ws(); if (i !== text.length) fail("E_JSON", "trailing JSON data");
}

function canonical(value) {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") {
    for (let i = 0; i < value.length; i++) {
      const unit = value.charCodeAt(i);
      if (unit >= 0xd800 && unit <= 0xdbff) {
        const next = value.charCodeAt(++i);
        if (!(next >= 0xdc00 && next <= 0xdfff)) fail("E_IJSON", "unpaired Unicode surrogate");
      } else if (unit >= 0xdc00 && unit <= 0xdfff) fail("E_IJSON", "unpaired Unicode surrogate");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) fail("E_IJSON", "number outside I-JSON exact range");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  fail("E_IJSON", "unsupported JSON value");
}

function parseJson(bytes, { canonicalRequired = false, code = "E_JSON" } = {}) {
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) fail(code, "invalid UTF-8");
  scanNoDuplicateKeys(text);
  let parsed; try { parsed = JSON.parse(text); } catch { fail(code, "invalid JSON"); }
  const encoded = Buffer.from(canonical(parsed));
  if (canonicalRequired && !encoded.equals(bytes)) fail("E_CANONICAL", "JSON is not RFC 8785 canonical");
  return parsed;
}

function listFiles(root) {
  const result = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const absolute = resolve(dir, entry.name);
      if (entry.isSymbolicLink()) fail("E_FILE_SET", "symlinks are forbidden");
      if (entry.isDirectory()) walk(absolute);
      else if (entry.isFile()) result.push(relative(root, absolute).split(sep).join("/"));
      else fail("E_FILE_SET", "special files are forbidden");
    }
  };
  walk(root); return result.sort();
}

function readBounded(root) {
  const paths = listFiles(root);
  if (JSON.stringify(paths) !== JSON.stringify([...ALLOWED].sort())) fail("E_FILE_SET", "bundle file allowlist mismatch");
  let total = 0; const files = {};
  for (const path of paths) {
    const size = statSync(resolve(root, path)).size;
    if (size < 1 || size > MAX_FILE) fail("E_FILE_SIZE", `invalid size: ${path}`);
    total += size; if (total > MAX_BUNDLE) fail("E_BUNDLE_SIZE", "bundle exceeds size limit");
    files[path] = readFileSync(resolve(root, path));
  }
  return files;
}

function verifyChecksums(files, expectedDigest) {
  const lines = files["checksums.sha256"].toString("ascii").split("\n");
  if (lines.pop() !== "") fail("E_CHECKSUM_FORMAT", "checksum file needs final newline");
  const expectedPaths = ALLOWED.filter((path) => path !== "checksums.sha256").sort();
  if (lines.length !== expectedPaths.length) fail("E_CHECKSUM_SET", "checksum count mismatch");
  lines.forEach((line, index) => {
    const match = line.match(/^([a-f0-9]{64})  ([A-Za-z0-9._/-]+)$/);
    if (!match || match[2] !== expectedPaths[index]) fail("E_CHECKSUM_SET", "checksum order/path mismatch");
    if (sha(files[match[2]]) !== match[1]) fail("E_CHECKSUM_MISMATCH", `checksum mismatch: ${match[2]}`);
  });
  const digest = sha(Buffer.concat([Buffer.from("recallops-authority-bundle-v1\0"), files["checksums.sha256"]]));
  if (expectedDigest && digest !== expectedDigest) fail("E_BUNDLE_DIGEST", "external bundle digest mismatch");
  return digest;
}

function exactKeys(object, keys, code) {
  if (!object || Array.isArray(object) || typeof object !== "object" || JSON.stringify(Object.keys(object).sort()) !== JSON.stringify([...keys].sort())) fail(code, "object shape differs from frozen schema");
}

function verifyTrust(files, manifest, jws, registryPath) {
  const jwk = parseJson(files["public.jwk.json"], { canonicalRequired: true });
  exactKeys(jwk, ["crv", "kty", "x"], "E_JWK");
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || fromB64u(jwk.x, "E_JWK").length !== 32) fail("E_JWK", "not an exact Ed25519 JWK");
  const thumbprint = jwkThumbprint(jwk);
  if (thumbprint !== manifest.key_thumbprint) fail("E_KEY_BINDING", "JWK thumbprint differs from manifest");
  const registryBytes = readFileSync(registryPath);
  const registry = parseJson(registryBytes, { canonicalRequired: true, code: "E_TRUST_REGISTRY" });
  exactKeys(registry, ["keys", "registry_version", "transitions"], "E_TRUST_REGISTRY");
  if (registry.registry_version !== "trusted-receipt-keys-v1") fail("E_TRUST_REGISTRY", "registry version mismatch");
  validateTrustRegistry(registry);
  const pinned = registry.keys.find((key) => key.kid === thumbprint && key.status === "active" && key.release_ids.includes(manifest.release.release_id));
  if (!pinned || canonical(pinned.jwk) !== canonical(jwk)) fail("E_UNTRUSTED_KEY", "bundle key is not repository-pinned for release");
  const parts = jws.split("."); if (parts.length !== 3) fail("E_JWS_FORMAT", "JWS must have three segments");
  const headerBytes = fromB64u(parts[0]); const payload = fromB64u(parts[1]); const signature = fromB64u(parts[2]);
  const header = parseJson(headerBytes, { canonicalRequired: true });
  const expectedHeader = { alg: "Ed25519", kid: thumbprint, typ: "recallops-authority-receipt+jws", v: 1 };
  if (canonical(header) !== canonical(expectedHeader)) fail("E_JWS_HEADER", "protected header differs from frozen profile");
  if (!payload.equals(files["manifest.jcs.json"])) fail("E_JWS_PAYLOAD", "JWS payload differs from manifest file");
  if (signature.length !== 64) fail("E_SIGNATURE", "Ed25519 signature length is invalid");
  const raw = fromB64u(jwk.x, "E_JWK");
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
  const publicKey = createPublicKey({ key: spki, format: "der", type: "spki" });
  if (!verifySignature(null, Buffer.from(`${parts[0]}.${parts[1]}`), publicKey, signature)) fail("E_SIGNATURE", "Ed25519 signature verification failed");
  return thumbprint;
}

function jwkThumbprint(jwk) {
  exactKeys(jwk, ["crv", "kty", "x"], "E_JWK");
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || fromB64u(jwk.x, "E_JWK").length !== 32) fail("E_JWK", "not an exact Ed25519 JWK");
  return b64u(createHash("sha256").update(canonical({ crv: "Ed25519", kty: "OKP", x: jwk.x })).digest());
}

function verifyCompactWithJwk(compactJws, jwk, kid, typ) {
  const parts = compactJws.split("."); if (parts.length !== 3) fail("E_TRUST_TRANSITION", "transition JWS must have three segments");
  const header = parseJson(fromB64u(parts[0], "E_TRUST_TRANSITION"), { canonicalRequired: true });
  if (canonical(header) !== canonical({ alg: "Ed25519", kid, typ, v: 1 })) fail("E_TRUST_TRANSITION", "transition protected header mismatch");
  const signature = fromB64u(parts[2], "E_TRUST_TRANSITION");
  if (signature.length !== 64) fail("E_TRUST_TRANSITION", "transition signature length is invalid");
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), fromB64u(jwk.x, "E_JWK")]);
  const key = createPublicKey({ key: spki, format: "der", type: "spki" });
  if (!verifySignature(null, Buffer.from(`${parts[0]}.${parts[1]}`), key, signature)) fail("E_TRUST_TRANSITION", "transition signature is invalid");
  return parseJson(fromB64u(parts[1], "E_TRUST_TRANSITION"), { canonicalRequired: true });
}

function validateTrustRegistry(registry) {
  if (!Array.isArray(registry.keys) || !Array.isArray(registry.transitions)) fail("E_TRUST_REGISTRY", "registry arrays are invalid");
  const roots = registry.keys.filter((key) => key.trust === "repository_root");
  if (registry.keys.length && roots.length !== 1) fail("E_TRUST_REGISTRY", "registry requires one repository root");
  const byKid = new Map();
  for (const key of registry.keys) {
    exactKeys(key, ["jwk", "kid", "release_ids", "status", "trust"], "E_TRUST_REGISTRY");
    if (byKid.has(key.kid) || key.kid !== jwkThumbprint(key.jwk) || !["repository_root", "transition"].includes(key.trust) || !["active", "retired", "revoked"].includes(key.status) || !Array.isArray(key.release_ids) || !key.release_ids.length || new Set(key.release_ids).size !== key.release_ids.length) fail("E_TRUST_REGISTRY", "trusted key entry is invalid");
    byKid.set(key.kid, key);
  }
  const transitions = new Map();
  for (const transition of registry.transitions) {
    exactKeys(transition, ["from_kid", "to_kid", "transition_jws"], "E_TRUST_REGISTRY");
    if (transitions.has(transition.to_kid) || transition.from_kid === transition.to_kid) fail("E_TRUST_REGISTRY", "transition is duplicate or cyclic");
    transitions.set(transition.to_kid, transition);
  }
  const established = new Set(roots.map((key) => key.kid));
  const pending = new Set(registry.keys.filter((key) => key.trust === "transition").map((key) => key.kid));
  while (pending.size) {
    let progressed = false;
    for (const target of [...pending]) {
      const transition = transitions.get(target);
      if (!transition || !established.has(transition.from_kid)) continue;
      const predecessor = byKid.get(transition.from_kid), successor = byKid.get(target);
      if (!predecessor || !successor) fail("E_TRUST_TRANSITION", "transition references unknown key");
      const payload = verifyCompactWithJwk(transition.transition_jws, predecessor.jwk, predecessor.kid, "recallops-receipt-key-transition+jws");
      const expected = { from_kid: predecessor.kid, to_jwk_digest: contentDigest("recallops-public-jwk-v1", successor.jwk), to_kid: successor.kid, transition_version: "receipt-key-transition-v1" };
      if (canonical(payload) !== canonical(expected)) fail("E_TRUST_TRANSITION", "transition payload binding mismatch");
      established.add(target); pending.delete(target); progressed = true;
    }
    if (!progressed) fail("E_TRUST_TRANSITION", "transition chain is missing, cyclic, or untrusted");
  }
  if (transitions.size !== pending.size + registry.keys.filter((key) => key.trust === "transition").length) fail("E_TRUST_REGISTRY", "registry contains an unused transition");
}

function validateManifest(manifest) {
  exactKeys(manifest, [
    "asserted_signing_time", "capability_policy_version", "digests", "event_count", "evidence_index_digest",
    "expires_at", "final_disposition", "final_state", "first_epoch", "key_thumbprint",
    "last_epoch", "ledger_first_hash", "ledger_head_hash", "receipt_policy_version",
    "receipt_version", "release", "run_id", "scenario_version", "signing_algorithm", "subjects",
    "supersedes_receipt_id", "tenant_id_hash", "workflow_id",
  ], "E_MANIFEST_SCHEMA");
  exactKeys(manifest.digests, ["assessment", "execution", "memory", "observation", "policy_verdict", "proposal", "review"], "E_MANIFEST_SCHEMA");
  exactKeys(manifest.subjects, ["operator", "reviewer", "separated"], "E_MANIFEST_SCHEMA");
  exactKeys(manifest.release, ["claim_registry_digest", "evaluation_version", "image_digest", "release_id", "source_sha"], "E_MANIFEST_SCHEMA");
  const digestValues = [...Object.values(manifest.digests), manifest.evidence_index_digest, manifest.ledger_first_hash, manifest.ledger_head_hash, manifest.release.claim_registry_digest, manifest.tenant_id_hash];
  if (!digestValues.every((value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value))) fail("E_MANIFEST_SCHEMA", "manifest digest is invalid");
  if (manifest.receipt_version !== "authority-receipt-v1" || manifest.signing_algorithm !== "Ed25519" || !/^(0|[1-9]\d*)$/.test(manifest.first_epoch) || !/^[1-9]\d*$/.test(manifest.last_epoch) || !/^[1-9]\d*$/.test(manifest.event_count)) fail("E_MANIFEST_SCHEMA", "manifest profile identifier/counter is invalid");
  const issued = Date.parse(manifest.asserted_signing_time), expires = Date.parse(manifest.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued) fail("E_MANIFEST_TIME", "manifest asserted validity interval is invalid");
  if (!/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/.test(manifest.release.source_sha) || !/^sha256:[a-f0-9]{64}$/.test(manifest.release.image_digest) || !/^[A-Za-z0-9_-]{43}$/.test(manifest.key_thumbprint)) fail("E_MANIFEST_SCHEMA", "manifest release/key binding is invalid");
}

function hashEvent(previousHex, event) {
  const payload = { ...event }; delete payload.event_hash;
  return sha(Buffer.concat([Buffer.from("recallops-authority-event-v1\0"), Buffer.from(previousHex, "hex"), Buffer.from("\0"), Buffer.from(canonical(payload))]));
}
const same = (a, b) => canonical(a) === canonical(b);
function verifyEvents(files, manifest) {
  const rawLines = files["events.ndjson"].toString("utf8").split("\n");
  if (rawLines.pop() !== "" || rawLines.length === 0) fail("E_EVENT_FORMAT", "events need final newline and nonempty prefix");
  const events = rawLines.map((line) => parseJson(Buffer.from(line), { canonicalRequired: true }));
  let previous = "0".repeat(64); let operator = null; let reviewer = null; let timestamp = null;
  events.forEach((event, index) => {
    exactKeys(event, EVENT_KEYS, "E_EVENT_SCHEMA");
    const sequence = String(index + 1), beforeEpoch = String(index), afterEpoch = String(index + 1);
    if (event.sequence !== sequence || event.epoch_before !== beforeEpoch || event.epoch_after !== afterEpoch) fail("E_EVENT_SEQUENCE", "event sequence/epoch is not contiguous");
    if (event.outcome !== "accepted" || event.previous_event_hash !== previous || event.event_hash !== hashEvent(previous, event)) fail("E_EVENT_HASH", "event hash chain is invalid");
    if (index === 0 && (event.event_type !== "RUN_GENESIS" || event.state_before !== "ABSENT")) fail("E_EVENT_GENESIS", "event prefix lacks run genesis");
    const transition = `${event.state_before}>${event.state_after}`;
    if (!TRANSITIONS.has(transition)) fail("E_TRANSITION", "illegal state transition");
    if (!same(event.capabilities_before, CAPABILITIES[event.state_before]) || !same(event.capabilities_after, CAPABILITIES[event.state_after])) fail("E_CAPABILITY_POLICY", "event capabilities differ from frozen policy");
    const expectedChannel = { agent: "webmcp", operator: "ui", reviewer: "ui", system: "system" }[event.actor_role];
    if (!expectedChannel || event.channel !== expectedChannel) fail("E_ACTOR_CHANNEL", "actor role/channel mismatch");
    if (TRANSITION_ROLES[transition] !== event.actor_role) fail("E_ACTOR_AUTHORITY", "actor role is unauthorized for transition");
    const parsedTime = Date.parse(event.recorded_at);
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(event.recorded_at) || !Number.isFinite(parsedTime) || (timestamp !== null && parsedTime < timestamp)) fail("E_EVENT_TIME", "event time is invalid or regresses");
    timestamp = parsedTime;
    if (index && (event.state_before !== events[index - 1].state_after || !same(event.capabilities_before, events[index - 1].capabilities_after))) fail("E_EVENT_CONTINUITY", "state/capability gap");
    for (const field of ["run_id", "workflow_id", "policy_version", "build_sha"]) if (event[field] !== events[0][field]) fail("E_EVENT_BOUNDARY", `event ${field} changed`);
    if (event.actor_role === "operator") { if (operator && operator !== event.actor_subject) fail("E_SUBJECT_STABILITY", "operator subject changed"); operator = event.actor_subject; }
    if (event.actor_role === "reviewer") { if (reviewer && reviewer !== event.actor_subject) fail("E_SUBJECT_STABILITY", "reviewer subject changed"); reviewer = event.actor_subject; }
    previous = event.event_hash;
  });
  const first = events[0], last = events.at(-1);
  if (!operator || !reviewer || operator === reviewer) fail("E_SEPARATION", "operator/reviewer separation is absent");
  if (manifest.subjects?.separated !== true || !/^[a-f0-9]{64}$/.test(manifest.subjects.operator) || !/^[a-f0-9]{64}$/.test(manifest.subjects.reviewer) || manifest.subjects.operator === manifest.subjects.reviewer) fail("E_SEPARATION", "signed pseudonymous separation claim is invalid");
  const bindings = [
    ["AWAITING_OPERATOR_APPROVAL", manifest.digests.proposal, "proposal"],
    ["APPROVED_AWAITING_EXECUTION", manifest.digests.proposal, "proposal"],
    ["OBSERVING_POSTCHECK", contentDigest("recallops-execution-binding-v1", { execution: manifest.digests.execution, proposal: manifest.digests.proposal }), "execution_binding"],
    ["POSTCHECK_READY", contentDigest("recallops-observation-binding-v1", { execution: manifest.digests.execution, observation: manifest.digests.observation, policy_verdict: manifest.digests.policy_verdict }), "observation_binding"],
    ["PENDING_REVIEW", contentDigest("recallops-outcome-binding-v1", { assessment: manifest.digests.assessment, memory: manifest.digests.memory, observation: manifest.digests.observation, policy_verdict: manifest.digests.policy_verdict }), "outcome_binding"],
    ["REVIEWED", contentDigest("recallops-review-binding-v1", { disposition: sha(Buffer.from(manifest.final_disposition)), memory: manifest.digests.memory, review: manifest.digests.review }), "review_binding"],
  ];
  for (const [state, digest, type] of bindings) {
    const event = events.find((candidate) => candidate.state_after === state);
    if (!event || event.object_type !== type || event.object_digest !== digest) fail("E_CAUSAL_BINDING", `missing exact ${type} transition binding`);
  }
  if (String(events.length) !== manifest.event_count || manifest.ledger_first_hash !== first.event_hash || manifest.ledger_head_hash !== last.event_hash || manifest.final_state !== last.state_after || manifest.run_id !== first.run_id || manifest.workflow_id !== first.workflow_id) fail("E_LEDGER_BINDING", "manifest ledger binding mismatch");
  if (manifest.release.source_sha !== first.build_sha || manifest.capability_policy_version !== first.policy_version) fail("E_RELEASE_BINDING", "ledger release/policy mismatch");
  const tenantHash = contentDigest("recallops-receipt-tenant-v1", { run_id: first.run_id, tenant_id: first.tenant_id });
  if (tenantHash !== manifest.tenant_id_hash) fail("E_TENANT_BINDING", "tenant/run binding differs from receipt");
  if (manifest.final_state !== "REVIEWED" || !["certify", "reject", "quarantine"].includes(manifest.final_disposition)) fail("E_DISPOSITION", "final memory disposition is not governed");
  return events;
}

function verifyIndex(files, manifest) {
  const index = parseJson(files["evidence-index.jcs.json"], { canonicalRequired: true });
  exactKeys(index, ["entries", "index_version"], "E_INDEX_SCHEMA");
  if (index.index_version !== "authority-bundle-v1" || index.entries.length !== AUXILIARY.length) fail("E_INDEX_SCHEMA", "evidence index shape mismatch");
  if (sha(files["evidence-index.jcs.json"]) !== manifest.evidence_index_digest) fail("E_INDEX_BINDING", "signed evidence-index digest mismatch");
  index.entries.forEach((entry, i) => {
    exactKeys(entry, ["path", "sha256", "size"], "E_INDEX_SCHEMA");
    if (entry.path !== AUXILIARY[i] || entry.size !== files[entry.path].length || entry.sha256 !== sha(files[entry.path])) fail("E_EVIDENCE_DIGEST", `indexed evidence mismatch: ${entry.path}`);
  });
}

function verifyRelease(files, manifest, thumbprint) {
  const release = parseJson(files["release.json"], { canonicalRequired: true });
  const expected = {
    release_id: manifest.release.release_id, source_sha: manifest.release.source_sha,
    image_digest: manifest.release.image_digest, capability_policy_version: manifest.capability_policy_version,
    receipt_policy_version: manifest.receipt_policy_version, evaluation_version: manifest.release.evaluation_version,
    claim_registry_digest: manifest.release.claim_registry_digest, receipt_key_thumbprint: thumbprint,
  };
  if (canonical(release) !== canonical(expected)) fail("E_RELEASE_BINDING", "release identity differs from receipt");
  if (sha(files["claims.json"]) !== manifest.release.claim_registry_digest) fail("E_CLAIM_BINDING", "claim registry digest mismatch");
  const capability = parseJson(files["policy/capability-policy.json"], { canonicalRequired: true });
  const receiptPolicy = parseJson(files["policy/receipt-policy.json"], { canonicalRequired: true });
  const evaluationCase = parseJson(files["evaluation/case.json"]);
  const evaluationResult = parseJson(files["evaluation/result.json"]);
  parseJson(files["claims.json"], { canonicalRequired: true });
  const expectedCapabilities = Object.fromEntries(Object.entries(CAPABILITIES).filter(([state]) => state !== "ABSENT"));
  if (capability.policy_version !== manifest.capability_policy_version || !same(capability.capabilities, expectedCapabilities) || receiptPolicy.policy_version !== manifest.receipt_policy_version || receiptPolicy.algorithm !== "Ed25519" || receiptPolicy.trust_anchor !== "repository-pinned") fail("E_POLICY_BINDING", "policy content/version differs from frozen verifier policy");
  if (evaluationCase.evaluation_version !== manifest.release.evaluation_version || evaluationResult.evaluation_version !== manifest.release.evaluation_version) fail("E_EVALUATION_BINDING", "evaluation version differs from receipt");
}

function main() {
  const args = process.argv.slice(2); if (!args[0]) fail("E_USAGE", "usage: verifier <bundle-directory> [--registry path] [--bundle-digest hex]");
  const root = resolve(args[0]);
  const option = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
  const registryPath = resolve(option("--registry") ?? new URL("./trusted-receipt-keys.json", import.meta.url).pathname);
  const expectedDigest = option("--bundle-digest");
  if (expectedDigest && !/^[a-f0-9]{64}$/.test(expectedDigest)) fail("E_USAGE", "bundle digest must be lowercase SHA-256");
  const files = readBounded(root); const digest = verifyChecksums(files, expectedDigest);
  const manifest = parseJson(files["manifest.jcs.json"], { canonicalRequired: true });
  validateManifest(manifest);
  const receipt = files["receipt.jws"].toString("ascii");
  const thumbprint = verifyTrust(files, manifest, receipt, registryPath);
  verifyIndex(files, manifest); const events = verifyEvents(files, manifest); verifyRelease(files, manifest, thumbprint);
  process.stdout.write(`${JSON.stringify({ ok: true, code: "VERIFIED", verifier: VERSION, bundle_digest: digest, event_count: events.length, release_id: manifest.release.release_id })}\n`);
}

try { main(); } catch (error) {
  const failure = error instanceof Failure ? error : new Failure("E_INTERNAL", "bounded verifier failure");
  process.stdout.write(`${JSON.stringify({ ok: false, code: failure.code, verifier: VERSION, message: failure.message.slice(0, 180) })}\n`);
  process.exitCode = 1;
}
