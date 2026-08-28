const $ = (selector) => document.querySelector(selector);
const state = {
  incidentId: sessionStorage.getItem("incident_id"),
  memoryId: sessionStorage.getItem("memory_id"),
  action: null,
  key: null,
  config: null,
  identity: null,
  webmcpPhase: sessionStorage.getItem("webmcp_phase") || "INVESTIGATING",
  workflowEpoch: Number(sessionStorage.getItem("workflow_epoch") || "0"),
  webmcpTools: ["inspect_incident", "propose_mitigation"],
  authorityOwner: "AGENT"
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
function headers(actor = "demo-operator", roles = "operator", channel = "ui", epoch = null) {
  const token = accessToken() || $("#token").value.trim();
  const context = {
    "Content-Type": "application/json",
    "X-RecallOps-Channel": channel,
    ...(epoch ? { "X-Workflow-Epoch": String(epoch) } : {})
  };
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
  $("#result").innerHTML = `<p class="risk"><b>Request stopped safely.</b><br>${escapeHtml(error.message)}<br><small>No action was executed. Check the provider/API status above and retry when ready.</small></p>`;
}
function escapeHtml(value) {
  const node = document.createElement("span"); node.textContent = value; return node.innerHTML;
}
function shortId(value) { return String(value || "unknown").slice(0, 8); }
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
  setWebMcpPhase(manifest.state, {
    epoch: manifest.epoch,
    availableTools: manifest.available_tools,
    authorityOwner: manifest.authority_owner
  });
}
async function refreshWorkflow({ signal } = {}) {
  if (!state.incidentId) return null;
  const manifest = await request(`/v1/incidents/${state.incidentId}/capabilities`, {
    headers: headers("demo-agent", "agent", "webmcp"), signal
  });
  applyWorkflowManifest(manifest);
  return manifest;
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
    const result = await request(`/v1/incidents/${state.incidentId}/approval`, { method: "POST", headers: headers("demo-operator", "operator", "ui", state.workflowEpoch), body: JSON.stringify({ tenant_id: tenant(), approved: true, actor_id: actor(), reason: "operator verified the exact action and current incident evidence" }) });
    $("#stage-approve").classList.add("active"); $("#approve").disabled = true; $("#execute").disabled = false;
    if (result.workflow) applyWorkflowManifest(result.workflow); else await refreshWorkflow();
  } catch (error) { showError(error); }
}
async function execute() {
  try {
    await request(`/v1/incidents/${state.incidentId}/execution`, { method: "POST", headers: headers("demo-operator", "operator", "ui", state.workflowEpoch), body: JSON.stringify({ tenant_id: tenant(), actor_id: actor(), action_hash: state.action.action_hash, action_taken: state.action.command, evidence_refs: [`urn:recallops:execution:${Date.now()}`] }) });
    $("#stage-execute").classList.add("active"); $("#execute").disabled = true; $("#observe").disabled = false;
    await refreshWorkflow();
  } catch (error) { showError(error); }
}
async function observe() {
  try {
    const result = await request(`/v1/incidents/${state.incidentId}/outcome`, { method: "POST", headers: headers("demo-operator", "operator", "ui", state.workflowEpoch), body: JSON.stringify({ tenant_id: tenant(), action_taken: state.action.command, outcome: "latency and error rate remained at baseline for the observation window", outcome_score: 1, confidence: .97, actor_id: actor("demo-operator") }) });
    state.memoryId = result.id; sessionStorage.setItem("memory_id", state.memoryId); $("#stage-observe").classList.add("active"); $("#review").disabled = false; $("#observe").disabled = true;
    await refreshWorkflow();
    $("#result").innerHTML = `<span class="confidence">PENDING REVIEW · MEMORY ${escapeHtml(shortId(state.memoryId))}</span><h3>Outcome captured, but excluded from retrieval.</h3><p>Sign out and enter with the reviewer identity. Four-eyes policy prevents the observer from activating their own evidence.</p>`;
  } catch (error) { showError(error); }
}
async function review() {
  try {
    await request(`/v1/memories/${state.memoryId}/governance`, { method: "POST", headers: headers("demo-reviewer", "reviewer", "ui", state.workflowEpoch), body: JSON.stringify({ tenant_id: tenant(), actor_id: "demo-reviewer", action: "activate", reason: "independent review confirmed the observed recovery window" }) });
    $("#stage-review").classList.add("active"); $("#recall").disabled = false; $("#review").disabled = true;
    await refreshWorkflow();
    $("#result").innerHTML = `<span class="confidence">ACTIVE MEMORY · ${escapeHtml(shortId(state.memoryId))}</span><h3>Independent review completed.</h3><p>The same memory is now eligible for tenant-scoped retrieval and will decay with age without losing provenance.</p>`;
  } catch (error) { showError(error); }
}
async function recall() {
  state.key = `judge-recall-${Date.now()}`;
  await analyze(); $("#stage-recall").classList.add("active");
}
async function resetWorkflow() {
  try {
    if (state.incidentId && state.workflowEpoch) {
      await request(`/v1/incidents/${state.incidentId}/reset`, {
        method: "POST",
        headers: headers("demo-operator", "operator", "ui", state.workflowEpoch)
      });
    }
    for (const key of ["incident_id", "memory_id", "webmcp_phase", "workflow_epoch"]) {
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
  state.key = `webmcp-${Date.now()}-${randomBase64Url(12)}`;
  return runAnalysis(incidentPayload(), { signal, channel: "webmcp", refresh: false });
}

window.recallOpsWebMcpHost = Object.freeze({
  getPhase: () => state.webmcpPhase,
  getCapabilities: () => [...state.webmcpTools],
  getAuthorityOwner: () => state.authorityOwner,
  inspectIncident: inspectForWebMcp,
  proposeMitigation: proposeForWebMcp,
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
function signOut() {
  sessionStorage.removeItem("access_token");
  state.identity = null;
  const query = new URLSearchParams({ client_id: state.config.client_id, logout_uri: state.config.redirect_url });
  location.assign(`${state.config.logout_url}?${query}`);
}
async function initialize() {
  try {
    state.config = await request("/v1/config");
    const query = new URLSearchParams(location.search);
    if (query.has("code")) await exchangeCode(query.get("code"), query.get("state"));
    if (state.config.auth_required) {
      $("#auth-controls").hidden = false; $("#token-details").hidden = true;
      if (accessToken()) {
        state.identity = await request("/v1/me", { headers: headers() });
        $("#tenant").value = state.identity.tenant_id; $("#tenant").disabled = true;
        $("#auth-status").textContent = `${state.identity.roles.join(" + ")} · ${state.identity.subject.slice(0, 8)}`;
        $("#signin").hidden = true; $("#signout").hidden = false;
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
$("#approve").addEventListener("click", approve); $("#execute").addEventListener("click", execute); $("#observe").addEventListener("click", observe); $("#review").addEventListener("click", review); $("#recall").addEventListener("click", recall);
$("#signin").addEventListener("click", signIn); $("#signout").addEventListener("click", signOut);
$("#reset-workflow").addEventListener("click", resetWorkflow);
initialize();
