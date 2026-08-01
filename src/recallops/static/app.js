const $ = (selector) => document.querySelector(selector);
const state = { incidentId: null, memoryId: null, key: null };

function percentage(value) { return `${Math.round(value * 100)}%`; }
function headers(actor = "demo-operator") {
  const token = $("#token").value.trim();
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
function incidentPayload() {
  state.key ||= `judge-${Date.now()}`;
  return { tenant_id: $("#tenant").value, service: $("#service").value,
    service_version: $("#version").value, symptom: $("#symptom").value,
    idempotency_key: state.key };
}
function renderAnalysis(analysis) {
  const memory = analysis.memories[0];
  const degraded = analysis.degraded_dependencies.length ? analysis.degraded_dependencies.join(", ") : "none";
  $("#result").innerHTML = `<span class="confidence">${Math.round(analysis.confidence * 100)}% CONFIDENCE · ${analysis.memories.length} ELIGIBLE MEMORIES</span>
    <h3>${escapeHtml(analysis.diagnosis)}</h3><dl>
    <dt>Proposed action</dt><dd>${escapeHtml(analysis.proposed_action.command)}</dd>
    <dt>Safety gate</dt><dd class="${analysis.proposed_action.requires_approval ? "risk" : ""}">${analysis.proposed_action.requires_approval ? "Human approval required" : "Read-only; no approval required"}</dd>
    <dt>Best memory</dt><dd>${memory ? `${escapeHtml(memory.memory.outcome)} · rank ${memory.rank_score.toFixed(3)}` : "Abstained — no compatible successful memory"}</dd>
    <dt>Degraded</dt><dd>${escapeHtml(degraded)}</dd></dl>`;
  $("#loop-actions").hidden = false;
}
async function analyze(event) {
  event?.preventDefault(); $("#analyze").disabled = true;
  try {
    const result = await request("/v1/incidents", { method: "POST", headers: headers(), body: JSON.stringify(incidentPayload()) });
    state.incidentId = result.incident_id; renderAnalysis(result);
  } catch (error) { showError(error); } finally { $("#analyze").disabled = false; }
}
async function observe() {
  try {
    const result = await request(`/v1/incidents/${state.incidentId}/outcome`, { method: "POST", headers: headers("demo-observer"), body: JSON.stringify({ tenant_id: $("#tenant").value, action_taken: "reduce worker concurrency to 24 and recycle saturated connections", outcome: "latency and error rate remained at baseline for the observation window", outcome_score: 1, confidence: .97, actor_id: "demo-observer" }) });
    state.memoryId = result.id; $("#stage-observe").classList.add("active"); $("#review").disabled = false; $("#observe").disabled = true;
    $("#result").innerHTML = `<span class="confidence">PENDING REVIEW</span><h3>Outcome captured, but excluded from retrieval.</h3><p>The observer cannot activate their own evidence. A distinct reviewer must attest it.</p>`;
  } catch (error) { showError(error); }
}
async function review() {
  try {
    await request(`/v1/memories/${state.memoryId}/governance`, { method: "POST", headers: headers("demo-reviewer"), body: JSON.stringify({ tenant_id: $("#tenant").value, actor_id: "demo-reviewer", action: "activate", reason: "independent review confirmed the observed recovery window" }) });
    $("#stage-review").classList.add("active"); $("#recall").disabled = false; $("#review").disabled = true;
    $("#result").innerHTML = `<span class="confidence">ACTIVE MEMORY</span><h3>Independent review completed.</h3><p>The evidence is now eligible for tenant-scoped retrieval and will decay with age without losing provenance.</p>`;
  } catch (error) { showError(error); }
}
async function recall() {
  state.key = `judge-recall-${Date.now()}`;
  await analyze(); $("#stage-recall").classList.add("active");
}
async function initialize() {
  try {
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
  } catch (error) { $("#health-label").textContent = "API unavailable"; }
}
$("#incident-form").addEventListener("submit", analyze);
$("#observe").addEventListener("click", observe); $("#review").addEventListener("click", review); $("#recall").addEventListener("click", recall);
initialize();
