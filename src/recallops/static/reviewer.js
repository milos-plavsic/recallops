(() => {
  "use strict";

  const status = document.querySelector("#review-status");
  const packetNode = document.querySelector("#review-packet");
  const actions = document.querySelector("#review-actions");
  let csrf = null;
  let packet = null;

  function evidenceCard(label, value, explanation) {
    const article = document.createElement("article");
    const heading = document.createElement("span");
    const record = document.createElement("pre");
    const note = document.createElement("small");
    heading.textContent = label;
    record.textContent = JSON.stringify(value, null, 2);
    record.tabIndex = 0;
    record.setAttribute("aria-label", `${label} scrollable record`);
    note.textContent = explanation;
    article.append(heading, record, note);
    return article;
  }

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
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code })
    });
    csrf = exchange.csrf_token;
    document.querySelector("#reviewer-identity").textContent =
      `Authenticated reviewer · ${exchange.identity.subject} · separate from operator and agent`;
    packet = await api("/v1/reviewer/evidence");
    status.textContent = "Evidence loaded. Measurements, assessment, and verdict are read-only.";
    packetNode.replaceChildren(
      evidenceCard("1 · IMMUTABLE MEASUREMENT", packet.immutable_observation,
        "The visiting agent cannot supply or rewrite these metrics."),
      evidenceCard("2 · ATTRIBUTABLE AGENT OPINION", packet.agent_assessment,
        "The assessment remains distinct even when it disagrees with policy."),
      evidenceCard("3 · INDEPENDENT POLICY VERDICT", packet.policy_verdict,
        "Review changes admissibility; it cannot relabel this verdict."),
      evidenceCard("BOUND PENDING MEMORY", packet.memory,
        `Assessment and policy agree: ${packet.assessment_policy_agree}. Retrieval remains blocked.`)
    );
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
      try { new BroadcastChannel("recallops-review").postMessage({ decision }); }
      catch (_error) { /* polling remains the authoritative synchronization path */ }
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
