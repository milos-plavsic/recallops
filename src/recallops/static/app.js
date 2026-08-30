const $ = (selector) => document.querySelector(selector);
const state = {
  incidentId: sessionStorage.getItem("incident_id"),
  memoryId: sessionStorage.getItem("memory_id"),
  observationId: sessionStorage.getItem("observation_id"),
  memoryDigest: sessionStorage.getItem("memory_digest"),
  action: null,
  key: null,
  config: null,
  identity: null,
  webmcpPhase: "SYNC_UNAVAILABLE",
  workflowEpoch: Number(sessionStorage.getItem("workflow_epoch") || "0"),
  runGeneration: Number(sessionStorage.getItem("run_generation") || "0"),
  manifestEtag: null,
  lastTimelineEpoch: 0,
  webmcpTools: [],
  authorityOwner: "UNKNOWN"
};

function setWebMcpPhase(phase, detail = {}) {
  state.webmcpPhase = phase;
  if (detail.epoch) state.workflowEpoch = Number(detail.epoch);
  if (detail.availableTools) state.webmcpTools = detail.availableTools;
  if (detail.authorityOwner) state.authorityOwner = detail.authorityOwner;
  sessionStorage.setItem("webmcp_phase", phase);
  sessionStorage.setItem("workflow_epoch", String(state.workflowEpoch));
  window.dispatchEvent(new CustomEvent("recallops:webmcp-state", { detail: {
    phase,
    epoch: state.workflowEpoch,
    availableTools: state.webmcpTools,
    authorityOwner: state.authorityOwner,
    ...detail
  } }));
}
function emitActivity(actor, message) {
  window.dispatchEvent(new CustomEvent("recallops:activity", { detail: { actor, message } }));
}

function percentage(value) { return `${Math.round(value * 100)}%`; }
function randomBase64Url(bytes = 32) {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...data)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function sha256(value) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}
function base64Url(data) {
  return btoa(String.fromCharCode(...data)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function accessToken() { return sessionStorage.getItem("access_token"); }
function protectedUiReady() {
  return state.config?.auth_mode !== "judge" || Boolean(sessionStorage.getItem("judge_csrf"));
}
function headers(actor = "demo-operator", roles = "operator", channel = "ui", epoch = null) {
  const token = accessToken() || $("#token").value.trim();
  const context = {
    "Content-Type": "application/json",
    "X-RecallOps-Channel": channel,
    ...(epoch ? { "X-Workflow-Epoch": String(epoch) } : {})
  };
  if (state.config?.auth_mode === "judge") {
    const csrf = sessionStorage.getItem("judge_csrf");
    return { ...context, ...(channel === "ui" && csrf ? { "X-CSRF-Token": csrf } : {}) };
  }
  return token ? { Authorization: `Bearer ${token}`, ...context } : {
    "X-Tenant-ID": $("#tenant").value,
    "X-Actor-ID": actor,
    "X-Roles": roles,
    ...context
  };
}
async function request(path, options = {}) {
  const response = await fetch(path, { ...options, headers: { "Accept": "application/json", ...(options.headers || {}) } });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || `Request failed (${response.status})`);
  }
  return response.json();
}
function showError(error) {
  $("#result").innerHTML = `<p class="risk"><b>Request stopped.</b><br>${escapeHtml(error.message)}<br><small>No further action is authorized. Reconcile authoritative state before retrying.</small></p>`;
}
function escapeHtml(value) {
  const node = document.createElement("span"); node.textContent = value; return node.innerHTML;
}
function shortId(value) { return String(value || "unknown").slice(0, 8); }
const exactAgentPrompt = "Find a safe response and stage it. Do not authorize or execute anything. Do not reuse any observed outcome until an independent reviewer approves it.";

function setText(selector, value) {
  const node = $(selector);
  if (node) node.textContent = String(value);
}

function renderInspection(inspection) {
  const incident = inspection.incident || {};
  setText("#judge-brief-title", String(incident.symptom || "checkout-latency-42").split(":", 1)[0]);
  setText("#judge-incident-summary", incident.symptom || "Bounded incident evidence unavailable.");
  const rejected = (inspection.candidates || []).find((candidate) => !candidate.eligible);
  if (rejected) {
    setText("#hero-rejected-score", `${Number(rejected.similarity).toFixed(2)} similarity`);
    setText("#hero-rejected-memory", `${shortId(rejected.memory_id)} · ${rejected.rejection_codes.join(" · ")}`);
  }
}

function authorityExplanation(phase) {
  const explanations = {
    INVESTIGATING: "The agent may inspect evidence and stage one bounded proposal. Approval and execution remain unavailable to it.",
    AWAITING_OPERATOR_APPROVAL: "Proposal authority has been withdrawn. Only the authenticated operator may approve or reject the exact digest.",
    APPROVED_AWAITING_EXECUTION: "Approval is bound to one proposal digest. Only the operator may apply the allowlisted sandbox action.",
    OBSERVING_POSTCHECK: "The system observer owns this transition. Neither agent nor operator may supply measurements.",
    POSTCHECK_READY: "The agent may assess the immutable observation. It cannot alter measurements or the policy verdict.",
    POSTCHECK_UNAVAILABLE: "Observation failed closed. No assessment tool or memory exists; only operator retry is permitted.",
    PENDING_REVIEW: "The memory is quarantined from retrieval. Only the independently authenticated reviewer may govern reuse.",
    REVIEWED: "Reviewed evidence is admissible for the compatible recurrence; reviewer authority remains unavailable to the agent.",
    SYNC_UNAVAILABLE: "Authoritative synchronization is unavailable. Agent and protected controls are withdrawn until reconciliation succeeds."
  };
  return explanations[phase] || "Protected transitions remain unavailable through WebMCP.";
}

function renderAuthorityChain(phase) {
  const order = ["INVESTIGATING", "AWAITING_OPERATOR_APPROVAL", "APPROVED_AWAITING_EXECUTION",
    "POSTCHECK_READY", "PENDING_REVIEW", "REVIEWED"];
  const current = Math.max(0, order.indexOf(phase));
  for (const [index, item] of Array.from(document.querySelectorAll("#authority-chain > li")).entries()) {
    item.classList.toggle("complete", index < current);
    item.classList.toggle("current", index === current);
  }
  setText("#authority-explanation", authorityExplanation(phase));
}

function syncProtectedControls(phase) {
  if (state.config?.auth_mode !== "judge") return;
  const protectedReady = protectedUiReady();
  const reviewerHandoffVisible = !$("#reviewer-link").hidden;
  $("#loop-actions").hidden = false;
  $("#approve").disabled = !protectedReady || phase !== "AWAITING_OPERATOR_APPROVAL" || !state.action;
  $("#reject-proposal").disabled = !protectedReady || phase !== "AWAITING_OPERATOR_APPROVAL" || !state.action;
  $("#execute").disabled = !protectedReady || phase !== "APPROVED_AWAITING_EXECUTION" || !state.action;
  $("#retry-observation").disabled = !protectedReady || phase !== "POSTCHECK_UNAVAILABLE";
  $("#review").textContent = reviewerHandoffVisible
    ? "Reviewer handoff created"
    : "Create independent reviewer handoff";
  $("#review").disabled = !protectedReady || phase !== "PENDING_REVIEW"
    || !state.memoryDigest || reviewerHandoffVisible;
  $("#review").hidden = phase === "REVIEWED";
  $("#observe").hidden = true;
  $("#recall").hidden = true;
  $("#reset-workflow").disabled = !protectedReady || phase === "SYNC_UNAVAILABLE";
}

function renderEvidence(observation, assessment = null, verdict = null) {
  if (!observation) return;
  $("#evidence-layers").hidden = false;
  setText("#evidence-observation", `${observation.before.latency_p95_ms} ms → ${observation.after.latency_p95_ms} ms · ${shortId(observation.id)}`);
  setText("#evidence-assessment", assessment ? assessment.classification : "Awaiting agent assessment");
  setText("#evidence-verdict", verdict ? `${verdict.classification} · ${verdict.policy_version}` : "Awaiting policy verdict");
  setText("#evidence-bindings", JSON.stringify({
    observation_id: observation.id,
    observation_digest: observation.observation_digest,
    execution_digest: observation.execution_digest,
    proposal_hash: observation.proposal_hash,
    agent_assessment: assessment ? {
      classification: assessment.classification,
      agent_subject: assessment.agent_subject,
      observation_digest: assessment.observation_digest
    } : null,
    policy_verdict: verdict ? {
      classification: verdict.classification,
      policy_version: verdict.policy_version,
      observation_digest: verdict.observation_digest,
      checks_passed: verdict.checks_passed,
      checks_failed: verdict.checks_failed
    } : null
  }, null, 2));
}

function renderRecurrence(result) {
  $("#recurrence-proof").hidden = false;
  const beforeId = shortId(result.pre_review_governed_memory_id);
  const afterId = shortId(result.governed_memory_id);
  setText("#recurrence-before", `${result.pre_review_governed_recommendation || "Abstained"} · evidence ${beforeId}`);
  setText("#recurrence-recommendation", `${result.governed_recommendation || "Abstained"} · evidence ${afterId}`);
  setText("#recurrence-change", result.change_explanation || "Authority comparison unavailable.");
  setText("#recurrence-title", result.reviewed_evidence_changed_authority
    ? "Independent review changed the evidence authority"
    : "Independent review preserved the evidence authority");
  $("#stage-recall").classList.add("active");
}

function renderReleaseStatus(release) {
  const renderGate = (selector, label, gate) => {
    const cryptographicallyComplete = gate.complete && release.signed_statement_verified;
    const badge = $(selector);
    badge.className = `readiness-badge ${cryptographicallyComplete ? "complete" : "pending"}`;
    const detail = cryptographicallyComplete
      ? "COMPLETE"
      : gate.status === "passing"
        ? "EVIDENCE PASSING · SIGNATURE PENDING"
        : gate.status.toUpperCase();
    badge.textContent = `${label} · ${detail}`;
  };
  renderGate("#live-proof-badge", "LIVE PROOF", release.live_proof);
  renderGate("#assurance-badge", "ASSURANCE", release.assurance);
}

async function refreshTimeline() {
  if (state.config?.auth_mode !== "judge") return;
  const result = await request("/v1/evidence/timeline");
  const entries = result.entries || [];
  const fragment = document.createDocumentFragment();
  for (const entry of entries) {
    const item = document.createElement("li");
    const timestamp = new Date(entry.recorded_at).toISOString();
    item.textContent = `${timestamp} · ${entry.evidence_class} · ${entry.display_summary}`;
    fragment.append(item);
  }
  $("#authority-events").replaceChildren(
    entries.length ? fragment : document.createTextNode("No persisted authority events yet.")
  );
  await refreshReceipt();
}

async function refreshReceipt() {
  const result = await request("/v1/evidence/receipt");
  if (!result.receipt) return;
  $("#receipt-proof").hidden = false;
  const receipt = result.receipt;
  const status = receipt.status === "signed"
    ? `SIGNED · ${receipt.signing_algorithm} · ${shortId(receipt.key_thumbprint)}`
    : receipt.status === "failed"
      ? `PROOF FAILED CLOSED · ${receipt.failure_code || "bounded dependency failure"}`
      : "PROOF PENDING · domain outcome is unchanged and no unsigned fallback exists";
  setText("#receipt-status", status);
  setText("#receipt-limitations", result.integrity_scope);
  const nodes = document.createDocumentFragment();
  for (const node of result.chain || []) {
    const item = document.createElement("li");
    const strong = document.createElement("strong");
    strong.textContent = `${node.sequence} · ${node.label}`;
    const detail = document.createElement("small");
    detail.textContent = `${node.authority_owner} → ${node.state} · event ${shortId(node.event_hash)}`;
    item.append(strong, detail);
    nodes.append(item);
  }
  $("#receipt-chain").replaceChildren(nodes);
  const download = $("#receipt-download");
  download.hidden = !result.public_bundle_url;
  if (result.public_bundle_url) download.href = result.public_bundle_url;
}

function enterReadOnlyDegraded() {
  setWebMcpPhase("SYNC_UNAVAILABLE", {
    availableTools: [], authorityOwner: "UNKNOWN"
  });
  for (const button of document.querySelectorAll("#loop-actions button")) button.disabled = true;
  $("#webmcp-status").textContent = "Authoritative sync unavailable · all tools withdrawn";
}
function traceEvidence(refs = []) {
  if (!refs.length) return "evidence: none recorded";
  return `evidence: ${refs.slice(0, 2).map((ref) => escapeHtml(String(ref).slice(0, 96))).join(" · ")}`;
}
function tenant() { return state.identity?.tenant_id || $("#tenant").value; }
function actor(demoActor = "demo-operator") { return state.identity?.subject || demoActor; }
function incidentPayload() {
  state.key ||= `judge-${Date.now()}`;
  return { tenant_id: tenant(), service: $("#service").value,
    service_version: $("#version").value, symptom: $("#symptom").value,
    idempotency_key: state.key };
}
function renderTrace(trace = []) {
  const steps = trace.map((step) => `<li class="trace-${escapeHtml(step.status)}">
    <span>${step.sequence}</span><b>${escapeHtml(step.tool.replaceAll("_", " "))}</b>
    <small>${escapeHtml(step.status)} · <span class="trace-risk">${escapeHtml(step.risk || "read_only").replaceAll("_", " ")}</span> · ≤${step.max_attempts} attempt${step.max_attempts === 1 ? "" : "s"}${step.timeout_seconds ? ` · ${step.timeout_seconds}s timeout` : ""}${step.degraded_reason ? ` · ${escapeHtml(step.degraded_reason)}` : ""}<br>${traceEvidence(step.evidence_refs)}</small>
  </li>`).join("");
  return `<details class="agent-trace" open><summary>Replayable agent trace (${trace.length} bounded step${trace.length === 1 ? "" : "s"})</summary><ol>${steps || "<li>No trace steps recorded</li>"}</ol></details>`;
}
function renderCandidates(memories = [], decisions = []) {
  if (!memories.length) return "<p class=\"muted\">No candidates survived the pre-ranking eligibility gates.</p>";
  return `<details class="candidates"><summary>Candidate evidence and rejection reasons (${memories.length})</summary><ol>${memories.map((item, index) => {
    const m = item.memory || {};
    const decision = decisions.find((candidate) => candidate.memory_id === m.id) || {};
    const selected = decision.disposition === "selected";
    const outcome = m.outcome || "outcome unavailable";
    const state = m.state || (m.valid === false ? "invalid" : "eligible");
    const why = selected ? "selected after policy ranking" : (decision.reasons || []).join(", ") || (index ? "ranked below selected candidate" : "eligible but policy abstained");
    const provenance = m.source_incident_id ? `learned memory ${shortId(m.id)} · source incident ${shortId(m.source_incident_id)} · independently reviewed ${m.reviewed_by ? "yes" : "no"}` : `seeded precedent ${shortId(m.id)}`;
    return `<li class="candidate ${selected ? "selected" : "rejected"}"><div><b>Vector candidate ${index + 1} → ${selected ? "POLICY SELECTED" : "POLICY REJECTED"}</b><span>${escapeHtml(outcome)}</span></div><small>${escapeHtml(provenance)}<br>semantic similarity ${(item.semantic_similarity ?? 0).toFixed(3)} → governed rank ${(item.rank_score ?? 0).toFixed(3)} · state ${escapeHtml(state)} · compatibility ${(item.compatibility ?? 0).toFixed(3)} · decision: ${escapeHtml(why)}</small></li>`;
  }).join("")}</ol></details>`;
}
function renderAnalysis(analysis) {
  const memory = analysis.retrieval_abstention_reasons.length ? null : analysis.memories[0];
  const degraded = analysis.degraded_dependencies.length ? analysis.degraded_dependencies.join(", ") : "none";
  const abstention = analysis.retrieval_abstention_reasons.length ? analysis.retrieval_abstention_reasons.join(", ") : "none";
  $("#result").innerHTML = `<span class="confidence">${Math.round(analysis.confidence * 100)}% CONFIDENCE · ${analysis.memories.length} GOVERNED CANDIDATES</span>
    <h3>${escapeHtml(analysis.diagnosis)}</h3><dl>
    <dt>Proposed action</dt><dd>${escapeHtml(analysis.proposed_action.command)}</dd>
    <dt>Safety gate</dt><dd class="${analysis.proposed_action.requires_approval ? "risk" : ""}">${analysis.proposed_action.requires_approval ? "Human approval required" : "Read-only; no approval required"}</dd>
    <dt>Governed decision</dt><dd>${memory ? `${escapeHtml(memory.memory.outcome)} · policy rank ${memory.rank_score.toFixed(3)}` : "Abstained — no compatible successful memory"}</dd>
    <dt>Retrieval abstention</dt><dd>${escapeHtml(abstention)}</dd>
    <dt>Degraded</dt><dd class="${analysis.degraded_dependencies.length ? "risk" : ""}">${escapeHtml(degraded)}</dd></dl>${renderCandidates(analysis.memories, analysis.candidate_decisions)}${renderTrace(analysis.agent_trace)}`;
  $("#loop-actions").hidden = false;
  state.action = analysis.proposed_action;
  $("#approve").disabled = !state.action.requires_approval;
  $("#execute").disabled = state.action.requires_approval;
  $("#observe").disabled = true;
}
function applyWorkflowManifest(manifest) {
  if (manifest.run_generation) {
    state.runGeneration = Number(manifest.run_generation);
    sessionStorage.setItem("run_generation", String(state.runGeneration));
  }
  state.manifestEtag = manifest.etag || state.manifestEtag;
  setWebMcpPhase(manifest.state, {
    epoch: manifest.epoch,
    availableTools: manifest.available_tools,
    authorityOwner: manifest.authority_owner
  });
  renderAuthorityChain(manifest.state);
  syncProtectedControls(manifest.state);
  if (manifest.epoch && Number(manifest.epoch) !== state.lastTimelineEpoch) {
    state.lastTimelineEpoch = Number(manifest.epoch);
    refreshTimeline().catch(() => {});
  }
  if (state.config?.auth_mode === "judge" && manifest.state === "REVIEWED") {
    $("#recall").hidden = true;
    $("#reviewer-link").hidden = true;
    $("#review").disabled = true;
  }
}
async function refreshWorkflow({ signal } = {}) {
  if (!state.incidentId) return null;
  try {
    if (state.config?.auth_mode === "judge") {
      const response = await fetch("/v1/webmcp/capabilities", {
        headers: {
          "Accept": "application/json",
          ...(state.manifestEtag ? { "If-None-Match": state.manifestEtag } : {})
        },
        signal
      });
      if (response.status === 304) return null;
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.detail || `Request failed (${response.status})`);
      }
      const manifest = await response.json();
      state.manifestEtag = response.headers.get("ETag") || manifest.etag || state.manifestEtag;
      applyWorkflowManifest(manifest);
      return manifest;
    }
    const path = `/v1/incidents/${state.incidentId}/capabilities`;
    const manifest = await request(path, {
      headers: headers("demo-agent", "agent", "webmcp"), signal
    });
    applyWorkflowManifest(manifest);
    return manifest;
  } catch (error) {
    if (error.name !== "AbortError") enterReadOnlyDegraded();
    throw error;
  }
}
async function runAnalysis(payload, { signal, channel = "ui", refresh = true } = {}) {
  $("#analyze").disabled = true; $("#analyze").setAttribute("aria-busy", "true"); $("#result").innerHTML = `<p class="muted loading">Embedding incident and applying governance gates…</p>`;
  try {
    const requestHeaders = channel === "webmcp"
      ? headers("demo-agent", "agent", "webmcp")
      : headers("demo-operator", "operator", "ui");
    const result = await request("/v1/incidents", { method: "POST", headers: requestHeaders, body: JSON.stringify(payload), signal });
    state.incidentId = result.incident_id; sessionStorage.setItem("incident_id", state.incidentId); renderAnalysis(result);
    if (refresh) await refreshWorkflow({ signal });
    return result;
  } finally {
    $("#analyze").disabled = false; $("#analyze").removeAttribute("aria-busy");
  }
}
async function analyze(event) {
  event?.preventDefault();
  try { await runAnalysis(incidentPayload()); } catch (error) { showError(error); }
}
async function approve() {
  try {
    const result = await request(`/v1/incidents/${state.incidentId}/approval`, { method: "POST", headers: headers("demo-operator", "operator", "ui", state.workflowEpoch), body: JSON.stringify({ tenant_id: tenant(), approved: true, actor_id: actor(), proposal_hash: state.action.action_hash, reason: "operator verified the exact proposal digest and current incident evidence" }) });
    $("#stage-approve").classList.add("active"); $("#approve").disabled = true; $("#execute").disabled = false;
    emitActivity("HUMAN", `approved exact proposal ${shortId(state.action.action_hash)}`);
    if (result.workflow) applyWorkflowManifest(result.workflow); else await refreshWorkflow();
  } catch (error) { showError(error); }
}
async function rejectProposal() {
  try {
    const result = await request(`/v1/incidents/${state.incidentId}/approval`, {
      method: "POST",
      headers: headers("demo-operator", "operator", "ui", state.workflowEpoch),
      body: JSON.stringify({
        tenant_id: tenant(), approved: false, actor_id: actor(),
        proposal_hash: state.action.action_hash,
        reason: "operator rejected the exact proposal digest"
      })
    });
    emitActivity("HUMAN", `rejected exact proposal ${shortId(state.action.action_hash)}`);
    state.action = null;
    if (result.workflow) applyWorkflowManifest(result.workflow); else await refreshWorkflow();
    $("#result").innerHTML = "<p>Proposal rejected. Investigation authority returned to the agent; no sandbox action occurred.</p>";
  } catch (error) { showError(error); }
}
async function execute() {
  try {
    const result = await request(`/v1/incidents/${state.incidentId}/sandbox-execution`, { method: "POST", headers: headers("demo-operator", "operator", "ui", state.workflowEpoch), body: JSON.stringify({ tenant_id: tenant(), actor_id: actor(), proposal_hash: state.action.action_hash, idempotency_key: `sandbox-${state.incidentId}` }) });
    state.observationId = result.observation.id;
    sessionStorage.setItem("observation_id", state.observationId);
    $("#stage-execute").classList.add("active"); $("#stage-observe").classList.add("active");
    $("#execute").disabled = true; $("#observe").disabled = true;
    emitActivity("HUMAN", `applied allowlisted sandbox action ${result.execution.action_id || "checkout action"}`);
    emitActivity("SYSTEM", `verified observation ${shortId(state.observationId)} · policy ${result.policy_verdict.classification}`);
    applyWorkflowManifest(result.workflow);
    renderEvidence(result.observation, null, result.policy_verdict);
    const before = result.observation.before; const after = result.observation.after;
    $("#result").innerHTML = `<span class="confidence">VERIFIED OBSERVATION · ${escapeHtml(shortId(state.observationId))}</span><h3>Sandbox mutation measured independently.</h3><dl><dt>Latency p95</dt><dd>${before.latency_p95_ms} ms → ${after.latency_p95_ms} ms</dd><dt>Error rate</dt><dd>${(before.error_rate * 100).toFixed(1)}% → ${(after.error_rate * 100).toFixed(1)}%</dd><dt>Policy verdict</dt><dd>${escapeHtml(result.policy_verdict.classification)} · ${escapeHtml(result.policy_verdict.policy_version)}</dd></dl><p>The agent can now assess this immutable observation. Its opinion cannot change the policy verdict.</p>`;
  } catch (error) {
    try {
      const manifest = await refreshWorkflow();
      if (manifest?.state === "POSTCHECK_UNAVAILABLE") $("#retry-observation").disabled = false;
    } catch (_refreshError) { /* preserve the original safe-failure message */ }
    showError(error);
  }
}
async function retryObservation() {
  try {
    const result = await request(`/v1/incidents/${state.incidentId}/postcheck-retry`, {
      method: "POST",
      headers: headers("demo-operator", "operator", "ui", state.workflowEpoch),
      body: JSON.stringify({ tenant_id: tenant(), actor_id: actor() })
    });
    state.observationId = result.observation.id;
    sessionStorage.setItem("observation_id", state.observationId);
    $("#retry-observation").disabled = true;
    emitActivity("SYSTEM", `verified observation retry ${shortId(state.observationId)} · policy ${result.policy_verdict.classification}`);
    applyWorkflowManifest(result.workflow);
    renderEvidence(result.observation, null, result.policy_verdict);
    const before = result.observation.before; const after = result.observation.after;
    $("#result").innerHTML = `<span class="confidence">VERIFIED OBSERVATION · ${escapeHtml(shortId(state.observationId))}</span><h3>Observation retry succeeded without repeating the mutation.</h3><dl><dt>Latency p95</dt><dd>${before.latency_p95_ms} ms → ${after.latency_p95_ms} ms</dd><dt>Policy verdict</dt><dd>${escapeHtml(result.policy_verdict.classification)}</dd></dl><p>The agent assessment capability is now available.</p>`;
  } catch (error) { showError(error); }
}
async function observe() {
  showError(new Error("Postcheck assessment is available only to the visiting agent through WebMCP."));
}
async function review() {
  try {
    if (state.config?.auth_mode === "judge") {
      if (!state.memoryDigest) throw new Error("review target digest is unavailable");
      const result = await request("/v1/operator/reviewer-handoff", {
        method: "POST",
        headers: headers(),
        body: JSON.stringify({ purpose: "initial_review", memory_digest: state.memoryDigest })
      });
      $("#reviewer-link").href = result.reviewer_url;
      $("#reviewer-link").hidden = false;
      $("#review").disabled = true;
      $("#review").textContent = "Reviewer handoff created";
      emitActivity("HUMAN", "operator issued a single-use independent reviewer handoff");
      return;
    }
    await request(`/v1/memories/${state.memoryId}/governance`, { method: "POST", headers: headers("demo-reviewer", "reviewer", "ui", state.workflowEpoch), body: JSON.stringify({ tenant_id: tenant(), actor_id: actor("demo-reviewer"), action: "activate", reason: "independent review confirmed the observed recovery window" }) });
    $("#stage-review").classList.add("active"); $("#recall").disabled = false; $("#review").disabled = true;
    await refreshWorkflow();
    emitActivity("HUMAN", `reviewer activated memory ${shortId(state.memoryId)}`);
    $("#result").innerHTML = `<span class="confidence">ACTIVE MEMORY · ${escapeHtml(shortId(state.memoryId))}</span><h3>Independent review completed.</h3><p>The same memory is now eligible for tenant-scoped retrieval and will decay with age without losing provenance.</p>`;
  } catch (error) { showError(error); }
}
async function recall() {
  state.key = `judge-recall-${Date.now()}`;
  await analyze(); $("#stage-recall").classList.add("active");
}
async function resetWorkflow() {
  try {
    if (state.config?.auth_mode === "judge") {
      const reset = await request("/v1/operator/run/reset", {
        method: "POST", headers: headers()
      });
      sessionStorage.setItem("judge_csrf", reset.csrf_token);
    } else if (state.incidentId && state.workflowEpoch) {
      await request(`/v1/incidents/${state.incidentId}/reset`, {
        method: "POST",
        headers: headers("demo-operator", "operator", "ui", state.workflowEpoch)
      });
    }
    for (const key of ["incident_id", "memory_id", "memory_digest", "observation_id", "webmcp_phase", "workflow_epoch"]) {
      sessionStorage.removeItem(key);
    }
    location.assign("/");
  } catch (error) { showError(error); }
}
function loadSafeFailure() {
  $("#version").value = "2099.01";
  $("#symptom").value = "latency spike with no compatible reviewed precedent";
  state.key = null;
  $("#result").innerHTML = `<p class="muted">Safe-failure scenario loaded. Analyze it to verify that incompatible memory cannot authorize an action.</p>`;
}
function boundedIncidentSnapshot() {
  return {
    incident_id: state.incidentId || null,
    service: $("#service").value.slice(0, 80),
    service_version: $("#version").value.slice(0, 80),
    symptom: $("#symptom").value.slice(0, 500),
    workflow_state: state.webmcpPhase,
    untrusted_fields: ["service", "service_version", "symptom"]
  };
}
async function inspectForWebMcp({ signal } = {}) {
  if (state.config?.auth_mode === "judge") {
    return request("/v1/webmcp/incident", { signal });
  }
  if (!state.incidentId) return boundedIncidentSnapshot();
  try {
    const incident = await request(`/v1/incidents/${state.incidentId}`, { headers: headers(), signal });
    return {
      ...boundedIncidentSnapshot(),
      status: String(incident.status || "unknown").slice(0, 80),
      diagnosis: String(incident.diagnosis || "").slice(0, 500)
    };
  } catch (error) {
    if (error.name === "AbortError") throw error;
    return { ...boundedIncidentSnapshot(), status: "snapshot_only" };
  }
}
async function proposeForWebMcp(input, { signal } = {}) {
  if (state.webmcpPhase !== "INVESTIGATING") throw new Error(`propose_mitigation is unavailable in ${state.webmcpPhase}`);
  const service = String(input?.service || "").trim();
  const serviceVersion = String(input?.service_version || "").trim();
  const symptom = String(input?.symptom || "").trim();
  if (!service || !serviceVersion || !symptom) throw new Error("service, service_version, and symptom are required");
  if (service.length > 80 || serviceVersion.length > 80 || symptom.length > 500) throw new Error("incident input exceeds its bounded schema");
  $("#service").value = service; $("#version").value = serviceVersion; $("#symptom").value = symptom;
  if (state.config?.auth_mode === "judge") {
    const idempotencyKey = `proposal-${randomBase64Url(24)}`;
    const result = await request("/v1/webmcp/proposal", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "If-Match": `"${state.runGeneration}:${state.workflowEpoch}"`,
        "Idempotency-Key": idempotencyKey
      },
      body: JSON.stringify({ service, service_version: serviceVersion, symptom,
        ...(input?.rationale ? { rationale: String(input.rationale).slice(0, 500) } : {}) }),
      signal
    });
    state.action = {
      action_hash: result.proposal_digest,
      requires_approval: true,
      name: result.action?.display_name,
      risk: result.action?.risk_class
    };
    $("#loop-actions").hidden = false;
    return result;
  }
  state.key = `webmcp-${Date.now()}-${randomBase64Url(12)}`;
  return runAnalysis(incidentPayload(), { signal, channel: "webmcp", refresh: false });
}

async function recordPostcheckForWebMcp(input, { signal } = {}) {
  if (state.webmcpPhase !== "POSTCHECK_READY") throw new Error(`record_postcheck_assessment is unavailable in ${state.webmcpPhase}`);
  const observationId = String(input?.observation_id || "").trim();
  const classification = String(input?.classification || "").trim();
  const rationale = String(input?.rationale || "").trim();
  if (!observationId || observationId !== state.observationId) throw new Error("observation_id is stale or mismatched");
  if (!["recovered", "not_recovered", "inconclusive"].includes(classification)) throw new Error("invalid assessment classification");
  if (rationale.length < 3 || rationale.length > 1000) throw new Error("rationale must contain 3 to 1000 characters");
  const judgeMode = state.config?.auth_mode === "judge";
  const result = await request(judgeMode ? "/v1/webmcp/assessment" : `/v1/incidents/${state.incidentId}/postcheck-assessment`, {
    method: "POST",
    headers: judgeMode ? {
      "Content-Type": "application/json",
      "If-Match": `"${state.runGeneration}:${state.workflowEpoch}"`,
      "Idempotency-Key": `assessment-${randomBase64Url(24)}`
    } : headers("demo-agent", "agent", "webmcp", state.workflowEpoch),
    body: JSON.stringify({ observation_id: observationId, classification, rationale }),
    signal
  });
  state.memoryId = result.memory.id;
  state.memoryDigest = result.memory.digest || result.memory.memory_digest || null;
  sessionStorage.setItem("memory_id", state.memoryId);
  if (state.memoryDigest) sessionStorage.setItem("memory_digest", state.memoryDigest);
  $("#review").disabled = false;
  if (judgeMode) $("#review").textContent = "Create independent reviewer handoff";
  const evidence = judgeMode
    ? await request("/v1/operator/evidence").catch(() => null)
    : null;
  if (evidence?.immutable_observation) {
    renderEvidence(evidence.immutable_observation, result.assessment, result.policy_verdict);
  }
  setText("#evidence-assessment", result.assessment.classification);
  setText("#evidence-verdict", `${result.policy_verdict.classification} · ${result.policy_verdict.policy_version || "policy"}`);
  $("#result").innerHTML = `<span class="confidence">PENDING REVIEW · MEMORY ${escapeHtml(shortId(state.memoryId))}</span><h3>Agent assessment recorded separately from policy.</h3><dl><dt>Agent assessment</dt><dd>${escapeHtml(result.assessment.classification)}</dd><dt>Policy verdict</dt><dd>${escapeHtml(result.policy_verdict.classification)}</dd></dl><p>The memory remains excluded from retrieval until an independent reviewer acts.</p>`;
  if (result.workflow) setTimeout(() => applyWorkflowManifest(result.workflow), 0);
  return result;
}

async function recallForWebMcp({ signal } = {}) {
  if (state.config?.auth_mode === "judge") {
    const result = await request("/v1/webmcp/recurrence", { signal });
    renderRecurrence(result);
    return result;
  }
  state.key = `webmcp-recurrence-${Date.now()}-${randomBase64Url(12)}`;
  const result = await runAnalysis(incidentPayload(), { signal, channel: "webmcp" });
  const selected = result.memories?.[0]?.memory;
  const recurrence = {
    scenario_id: "checkout-latency-43",
    service: $("#service").value,
    service_version: $("#version").value,
    governed_memory_id: selected?.id || null,
    governed_recommendation: selected?.action || "Abstained — no admissible reviewed memory",
    eligible_memory_ids: (result.memories || []).map((item) => item.memory.id).slice(0, 3),
    compatibility_policy_version: result.retrieval_policy_version
  };
  renderRecurrence(recurrence);
  return recurrence;
}

async function recordWebMcpActivity(items) {
  if (state.config?.auth_mode !== "judge" || !items.length) return;
  const clientKey = sessionStorage.getItem("webmcp_client_id") || randomBase64Url(24);
  sessionStorage.setItem("webmcp_client_id", clientKey);
  await request("/v1/webmcp/activity", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ client_instance_id: clientKey, items })
  });
}

window.recallOpsWebMcpHost = Object.freeze({
  getPhase: () => state.webmcpPhase,
  getCapabilities: () => [...state.webmcpTools],
  getAuthorityOwner: () => state.authorityOwner,
  inspectIncident: inspectForWebMcp,
  proposeMitigation: proposeForWebMcp,
  recordPostcheckAssessment: recordPostcheckForWebMcp,
  recallReviewedMemory: recallForWebMcp,
  recordActivity: recordWebMcpActivity,
  refreshWorkflow
});
async function signIn() {
  const verifier = randomBase64Url(64);
  sessionStorage.setItem("pkce_verifier", verifier);
  sessionStorage.setItem("oauth_state", randomBase64Url());
  const challenge = base64Url(await sha256(verifier));
  const query = new URLSearchParams({ response_type: "code", client_id: state.config.client_id,
    redirect_uri: state.config.redirect_url, scope: "openid", code_challenge_method: "S256",
    code_challenge: challenge, state: sessionStorage.getItem("oauth_state") });
  location.assign(`${state.config.authorization_url}?${query}`);
}
async function exchangeCode(code, returnedState) {
  if (!returnedState || returnedState !== sessionStorage.getItem("oauth_state")) throw new Error("OAuth state validation failed");
  const body = new URLSearchParams({ grant_type: "authorization_code", client_id: state.config.client_id,
    redirect_uri: state.config.redirect_url, code, code_verifier: sessionStorage.getItem("pkce_verifier") || "" });
  const response = await fetch(state.config.token_url, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
  if (!response.ok) throw new Error("OIDC code exchange failed");
  const tokens = await response.json();
  sessionStorage.setItem("access_token", tokens.access_token);
  history.replaceState({}, "", "/");
}
async function signOut() {
  if (state.config?.auth_mode === "judge") {
    await request("/v1/judge/session/logout", { method: "POST", headers: headers() });
    sessionStorage.removeItem("judge_csrf");
    location.assign("/");
    return;
  }
  sessionStorage.removeItem("access_token");
  state.identity = null;
  const query = new URLSearchParams({ client_id: state.config.client_id, logout_uri: state.config.redirect_url });
  location.assign(`${state.config.logout_url}?${query}`);
}
async function startJudgeScenario() {
  if (state.config?.auth_mode !== "judge") {
    location.hash = "#demo";
    return;
  }
  $("#start-judge").disabled = true;
  try {
    const started = await request("/v1/judge/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}"
    });
    sessionStorage.setItem("judge_csrf", started.csrf_token);
    location.reload();
  } catch (error) {
    $("#start-judge").disabled = false;
    showError(error);
  }
}
async function initialize() {
  try {
    state.config = await request("/v1/config");
    renderReleaseStatus(await request("/v1/release"));
    if (state.config.auth_mode !== "judge") {
      setWebMcpPhase("INVESTIGATING", {
        availableTools: ["inspect_incident", "propose_mitigation"],
        authorityOwner: "AGENT"
      });
    }
    const fragment = new URLSearchParams(location.hash.slice(1));
    if (state.config.auth_mode === "judge" && fragment.has("access")) {
      const bootstrapCode = fragment.get("access");
      history.replaceState({}, "", `${location.pathname}${location.search}`);
      const exchanged = await request("/v1/judge/session/exchange", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: bootstrapCode })
      });
      sessionStorage.setItem("judge_csrf", exchanged.csrf_token);
    }
    const query = new URLSearchParams(location.search);
    if (query.has("code")) await exchangeCode(query.get("code"), query.get("state"));
    if (state.config.auth_required || state.config.auth_mode === "judge") {
      $("#auth-controls").hidden = false; $("#token-details").hidden = true;
      if (state.config.auth_mode === "judge") {
        const identityResponse = await fetch("/v1/me", { headers: { Accept: "application/json" } });
        if (identityResponse.status === 401) {
          state.incidentId = null;
          for (const key of ["incident_id", "memory_id", "memory_digest", "observation_id", "run_generation"]) {
            sessionStorage.removeItem(key);
          }
          $("#auth-status").textContent = "No active judge run · start one isolated scenario";
          $("#signin").hidden = true; $("#signout").hidden = true;
          enterReadOnlyDegraded();
        } else if (!identityResponse.ok) {
          throw new Error(`Identity request failed (${identityResponse.status})`);
        } else {
          state.identity = await identityResponse.json();
        }
      } else if (accessToken()) {
        state.identity = await request("/v1/me", { headers: headers() });
      }
      if (state.identity) {
        $("#tenant").value = state.identity.tenant_id; $("#tenant").disabled = true;
        $("#auth-status").textContent = `${state.identity.roles.join(" + ")} · ${state.identity.subject.slice(0, 8)}`;
        $("#signin").hidden = true; $("#signout").hidden = false;
        const missingJudgeCsrf = state.config.auth_mode === "judge" && !protectedUiReady();
        $("#start-judge").hidden = state.config.auth_mode === "judge" && !missingJudgeCsrf;
        if (missingJudgeCsrf) {
          $("#auth-status").textContent = "Operator session restored read-only · protected token unavailable";
          $("#signout").hidden = true;
          $("#start-judge").disabled = false;
          $("#start-judge").textContent = "Start fresh isolated judge scenario";
        }
        if (state.config.auth_mode === "judge") {
          const run = await request("/v1/operator/run");
          state.incidentId = run.incident_id;
          state.runGeneration = Number(run.generation);
          sessionStorage.setItem("incident_id", state.incidentId);
          sessionStorage.setItem("run_generation", String(state.runGeneration));
          const inspected = await request("/v1/webmcp/incident");
          $("#service").value = inspected.incident.service;
          $("#version").value = inspected.incident.service_version;
          $("#symptom").value = inspected.incident.symptom;
          renderInspection(inspected);
          const evidence = await request("/v1/operator/evidence");
          if (evidence.proposal_digest) {
            state.action = { action_hash: evidence.proposal_digest, requires_approval: true };
          }
          if (evidence.memory) {
            state.memoryId = evidence.memory.id;
            state.memoryDigest = evidence.memory.digest;
            sessionStorage.setItem("memory_id", state.memoryId);
            sessionStorage.setItem("memory_digest", state.memoryDigest);
          }
          if (evidence.immutable_observation) {
            state.observationId = evidence.immutable_observation.id;
            sessionStorage.setItem("observation_id", state.observationId);
            renderEvidence(
              evidence.immutable_observation,
              evidence.agent_assessment,
              evidence.policy_verdict
            );
          }
        }
      }
    }
    await request("/ready"); $("#health-label").textContent = "API and memory ready";
    const system = await request("/v1/system/status");
    const configured = `${system.embedding_provider} embeddings · ${system.reasoning_provider} reasoning`;
    $("#provider-status").textContent = `${configured} · runtime success is reported per analysis`;
    const report = await request("/v1/evaluation");
    $("#recall-accuracy").textContent = percentage(report.recallops.top1_safe_accuracy);
    $("#baseline-accuracy").textContent = `similarity-only ${percentage(report.similarity_only.top1_safe_accuracy)}`;
    $("#recall-unsafe").textContent = percentage(report.recallops.unsafe_selection_rate);
    $("#baseline-unsafe").textContent = `similarity-only ${percentage(report.similarity_only.unsafe_selection_rate)}`;
    $("#isolation-count").textContent = report.recallops.isolation_violations;
    $("#recall-mrr").textContent = report.recallops.mean_reciprocal_rank.toFixed(2);
    $("#case-count").textContent = `${report.case_count} adversarial cases`;
    $("#benchmark-status").textContent = report.passed ? "Synthetic policy suite passing" : "Policy suite failed";
    $("#benchmark-status").title = `${report.case_count} deterministic cases; this is not an end-to-end provider benchmark`;
    if (state.incidentId) await refreshWorkflow();
    if (state.memoryId) { $("#loop-actions").hidden = false; $("#review").disabled = false; }
  } catch (error) { $("#health-label").textContent = "API unavailable"; $("#provider-status").textContent = "API/provider status unavailable"; showError(error); }
}
$("#incident-form").addEventListener("submit", analyze);
$("#safe-failure").addEventListener("click", loadSafeFailure);
$("#approve").addEventListener("click", approve); $("#reject-proposal").addEventListener("click", rejectProposal); $("#execute").addEventListener("click", execute); $("#observe").addEventListener("click", observe); $("#review").addEventListener("click", review); $("#recall").addEventListener("click", recall);
$("#signin").addEventListener("click", signIn); $("#signout").addEventListener("click", signOut);
$("#reset-workflow").addEventListener("click", resetWorkflow);
$("#retry-observation").addEventListener("click", retryObservation);
$("#start-judge").addEventListener("click", startJudgeScenario);
$("#copy-prompt").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(exactAgentPrompt);
    setText("#copy-status", "Exact agent prompt copied.");
  } catch (_error) {
    setText("#copy-status", exactAgentPrompt);
  }
});
setText("#agent-prompt", exactAgentPrompt);
setText("#hero-agent-prompt", exactAgentPrompt);
try {
  const reviewChannel = new BroadcastChannel("recallops-review");
  reviewChannel.addEventListener("message", () => refreshWorkflow().catch(() => {}));
} catch (_error) { /* conditional polling remains authoritative */ }
initialize();
