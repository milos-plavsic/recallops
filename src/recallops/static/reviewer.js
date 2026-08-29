(() => {
  "use strict";

  const status = document.querySelector("#review-status");
  const packetNode = document.querySelector("#review-packet");
  const actions = document.querySelector("#review-actions");
  let csrf = null;
  let packet = null;

  function renderError(message) {
    status.textContent = `Review stopped safely: ${message}`;
    actions.hidden = true;
  }

  async function api(path, options = {}) {
    const response = await fetch(path, {
      ...options,
      headers: { Accept: "application/json", ...(options.headers || {}) }
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
    return body;
  }

  async function start() {
    const fragment = new URLSearchParams(location.hash.slice(1));
    const code = fragment.get("review");
    history.replaceState(null, "", `${location.pathname}${location.search}`);
    if (!code) throw new Error("review handoff is missing or expired");
    const exchange = await api("/v1/judge/reviewer-exchange", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: location.origin },
      body: JSON.stringify({ code })
    });
    csrf = exchange.csrf_token;
    packet = await api("/v1/reviewer/evidence");
    status.textContent = "Evidence loaded. Measurements, assessment, and verdict are read-only.";
    packetNode.textContent = JSON.stringify({
      immutable_observation: packet.immutable_observation,
      agent_assessment: packet.agent_assessment,
      policy_verdict: packet.policy_verdict,
      assessment_policy_agree: packet.assessment_policy_agree,
      memory: packet.memory
    }, null, 2);
    actions.hidden = packet.purpose !== "initial_review";
    for (const button of actions.querySelectorAll("button")) {
      button.disabled = !packet.allowed_dispositions.includes(button.dataset.decision);
    }
  }

  async function decide(decision) {
    if (!packet || !csrf) return;
    for (const button of actions.querySelectorAll("button")) button.disabled = true;
    const reason = decision === "certify"
      ? "EVIDENCE_ACCEPTED"
      : decision === "quarantine"
        ? "NEEDS_INVESTIGATION"
        : "INSUFFICIENT_EVIDENCE";
    try {
      await api("/v1/reviewer/disposition", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Origin: location.origin,
          "X-CSRF-Token": csrf,
          "If-Match": `"${packet.precondition.generation}:${packet.precondition.epoch}"`
        },
        body: JSON.stringify({
          decision,
          memory_digest: packet.memory.memory_digest,
          reason_code: reason,
          note: ""
        })
      });
      status.textContent = `Reviewer committed ${decision}. This authority was never an agent tool.`;
      actions.hidden = true;
    } catch (error) {
      renderError(error.message);
    }
  }

  actions.addEventListener("click", (event) => {
    const decision = event.target?.dataset?.decision;
    if (decision) decide(decision);
  });
  start().catch((error) => renderError(error.message));
})();
