const $ = (selector) => document.querySelector(selector);
const state = {
  incidentId: sessionStorage.getItem("incident_id"),
  memoryId: sessionStorage.getItem("memory_id"),
  action: null,
  key: null,
  config: null,
  identity: null
};

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
function headers(actor = "demo-operator") {
  const token = accessToken() || $("#token").value.trim();
  return token ? { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } : {
    "X-Tenant-ID": $("#tenant").value,
    "X-Actor-ID": actor,
    "X-Roles": "operator,reviewer",
    "Content-Type": "application/json"
  };
}
async function request(path, options = {}) {
  const response = await fetch(path, options);
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || `Request failed (${response.status})`);
  }
  return response.json();
}
function showError(error) {
  $("#result").innerHTML = `<p class="risk"><b>Request stopped safely.</b><br>${escapeHtml(error.message)}</p>`;
}
function escapeHtml(value) {
  const node = document.createElement("span"); node.textContent = value; return node.innerHTML;
}
function tenant() { return state.identity?.tenant_id || $("#tenant").value; }
function actor() { return state.identity?.subject || "demo-operator"; }
function incidentPayload() {
  state.key ||= `judge-${Date.now()}`;
  return { tenant_id: tenant(), service: $("#service").value,
    service_version: $("#version").value, symptom: $("#symptom").value,
    idempotency_key: state.key };
}
function renderAnalysis(analysis) {
  const memory = analysis.retrieval_abstention_reasons.length ? null : analysis.memories[0];
  const degraded = analysis.degraded_dependencies.length ? analysis.degraded_dependencies.join(", ") : "none";
  const abstention = analysis.retrieval_abstention_reasons.length ? analysis.retrieval_abstention_reasons.join(", ") : "none";
  $("#result").innerHTML = `<span class="confidence">${Math.round(analysis.confidence * 100)}% CONFIDENCE · ${analysis.memories.length} GOVERNED CANDIDATES</span>
    <h3>${escapeHtml(analysis.diagnosis)}</h3><dl>
    <dt>Proposed action</dt><dd>${escapeHtml(analysis.proposed_action.command)}</dd>
    <dt>Safety gate</dt><dd class="${analysis.proposed_action.requires_approval ? "risk" : ""}">${analysis.proposed_action.requires_approval ? "Human approval required" : "Read-only; no approval required"}</dd>
    <dt>Best memory</dt><dd>${memory ? `${escapeHtml(memory.memory.outcome)} · rank ${memory.rank_score.toFixed(3)}` : "Abstained — no compatible successful memory"}</dd>
    <dt>Retrieval abstention</dt><dd>${escapeHtml(abstention)}</dd>
    <dt>Degraded</dt><dd>${escapeHtml(degraded)}</dd></dl>`;
  $("#loop-actions").hidden = false;
  state.action = analysis.proposed_action;
  $("#approve").disabled = !state.action.requires_approval;
  $("#execute").disabled = state.action.requires_approval;
  $("#observe").disabled = true;
}
async function analyze(event) {
  event?.preventDefault(); $("#analyze").disabled = true;
  try {
    const result = await request("/v1/incidents", { method: "POST", headers: headers(), body: JSON.stringify(incidentPayload()) });
    state.incidentId = result.incident_id; sessionStorage.setItem("incident_id", state.incidentId); renderAnalysis(result);
  } catch (error) { showError(error); } finally { $("#analyze").disabled = false; }
}
async function approve() {
  try {
    await request(`/v1/incidents/${state.incidentId}/approval`, { method: "POST", headers: headers(), body: JSON.stringify({ tenant_id: tenant(), approved: true, actor_id: actor(), reason: "operator verified the exact action and current incident evidence" }) });
    $("#stage-approve").classList.add("active"); $("#approve").disabled = true; $("#execute").disabled = false;
  } catch (error) { showError(error); }
}
async function execute() {
  try {
    await request(`/v1/incidents/${state.incidentId}/execution`, { method: "POST", headers: headers(), body: JSON.stringify({ tenant_id: tenant(), actor_id: actor(), action_hash: state.action.action_hash, action_taken: state.action.command, evidence_refs: [`urn:recallops:execution:${Date.now()}`] }) });
    $("#stage-execute").classList.add("active"); $("#execute").disabled = true; $("#observe").disabled = false;
  } catch (error) { showError(error); }
}
async function observe() {
  try {
    const result = await request(`/v1/incidents/${state.incidentId}/outcome`, { method: "POST", headers: headers("demo-observer"), body: JSON.stringify({ tenant_id: tenant(), action_taken: state.action.command, outcome: "latency and error rate remained at baseline for the observation window", outcome_score: 1, confidence: .97, actor_id: actor() }) });
    state.memoryId = result.id; sessionStorage.setItem("memory_id", state.memoryId); $("#stage-observe").classList.add("active"); $("#review").disabled = false; $("#observe").disabled = true;
    $("#result").innerHTML = `<span class="confidence">PENDING REVIEW</span><h3>Outcome captured, but excluded from retrieval.</h3><p>Sign out and enter with the reviewer identity. Four-eyes policy prevents the observer from activating their own evidence.</p>`;
  } catch (error) { showError(error); }
}
async function review() {
  try {
    await request(`/v1/memories/${state.memoryId}/governance`, { method: "POST", headers: headers("demo-reviewer"), body: JSON.stringify({ tenant_id: tenant(), actor_id: actor(), action: "activate", reason: "independent review confirmed the observed recovery window" }) });
    $("#stage-review").classList.add("active"); $("#recall").disabled = false; $("#review").disabled = true;
    $("#result").innerHTML = `<span class="confidence">ACTIVE MEMORY</span><h3>Independent review completed.</h3><p>The evidence is now eligible for tenant-scoped retrieval and will decay with age without losing provenance.</p>`;
  } catch (error) { showError(error); }
}
async function recall() {
  state.key = `judge-recall-${Date.now()}`;
  await analyze(); $("#stage-recall").classList.add("active");
}
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
    await request("/health"); $("#health-label").textContent = "API healthy";
    const report = await request("/v1/evaluation");
    $("#recall-accuracy").textContent = percentage(report.recallops.top1_safe_accuracy);
    $("#baseline-accuracy").textContent = `similarity-only ${percentage(report.similarity_only.top1_safe_accuracy)}`;
    $("#recall-unsafe").textContent = percentage(report.recallops.unsafe_selection_rate);
    $("#baseline-unsafe").textContent = `similarity-only ${percentage(report.similarity_only.unsafe_selection_rate)}`;
    $("#isolation-count").textContent = report.recallops.isolation_violations;
    $("#recall-mrr").textContent = report.recallops.mean_reciprocal_rank.toFixed(2);
    $("#case-count").textContent = `${report.case_count} adversarial cases`;
    $("#benchmark-status").textContent = report.passed ? "CI gate passing" : "Evaluation failed";
    if (state.memoryId) { $("#loop-actions").hidden = false; $("#review").disabled = false; }
  } catch (error) { $("#health-label").textContent = "API unavailable"; showError(error); }
}
$("#incident-form").addEventListener("submit", analyze);
$("#approve").addEventListener("click", approve); $("#execute").addEventListener("click", execute); $("#observe").addEventListener("click", observe); $("#review").addEventListener("click", review); $("#recall").addEventListener("click", recall);
$("#signin").addEventListener("click", signIn); $("#signout").addEventListener("click", signOut);
initialize();
