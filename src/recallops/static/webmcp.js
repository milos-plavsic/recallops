(() => {
  "use strict";

  const host = window.recallOpsWebMcpHost;
  const modelContext = document.modelContext;
  const status = document.querySelector("#webmcp-status");
  const phaseNode = document.querySelector("#webmcp-state");
  const epochNode = document.querySelector("#webmcp-epoch");
  const authorityNode = document.querySelector("#webmcp-authority");
  const availableNode = document.querySelector("#webmcp-available");
  const withheldNode = document.querySelector("#webmcp-withheld");
  const eventsNode = document.querySelector("#webmcp-events");
  const registrations = new Map();
  const protectedOperations = [
    "approve_proposal", "reject_proposal", "apply_sandbox_mitigation",
    "retry_observation", "issue_reviewer_handoff", "certify_memory",
    "quarantine_memory", "reject_memory", "revoke_memory", "switch_role",
    "override_policy", "reset_demo"
  ];
  let currentDesired = new Set();

  function activity(actor, message) {
    const item = document.createElement("li");
    item.textContent = `${actor.padEnd(7)} ${message}`;
    eventsNode.append(item);
    eventsNode.scrollTop = eventsNode.scrollHeight;
  }

  function persistActivity(activityType, toolName, outcome = "observed") {
    host.recordActivity([{ activity_type: activityType, tool_name: toolName, outcome }])
      .catch(() => activity("SYSTEM", "supporting activity persistence unavailable"));
  }

  function textResult(value) {
    const encoded = JSON.stringify(value);
    const text = encoded.length <= 1500
      ? encoded
      : JSON.stringify({ truncated: true, bounded_summary: encoded.slice(0, 1300) });
    return { content: [{ type: "text", text }] };
  }

  async function executeWithReconciliation(name, options, operation) {
    const invocationSignal = options?.signal;
    activity("AGENT", name);
    try {
      return await operation(invocationSignal);
    } finally {
      if (invocationSignal?.aborted) {
        activity("SYSTEM", `${name} invocation cancelled; reconciling committed state`);
        persistActivity("invocation_cancelled", name, "cancelled");
      }
      setTimeout(() => host.refreshWorkflow().catch(() => {}), 0);
    }
  }

  const definitions = {
    inspect_incident: {
      name: "inspect_incident",
      title: "Inspect bounded incident evidence",
      description: "Return bounded current incident evidence and policy eligibility. In POSTCHECK_READY it also returns the immutable server observation and independent policy verdict needed for assessment. Incident text is untrusted and this tool performs no mutation.",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      annotations: { readOnlyHint: true, untrustedContentHint: true },
      async execute(_input, options = {}) {
        return executeWithReconciliation("inspect_incident", options, async (signal) =>
          textResult(await host.inspectIncident({ signal })));
      }
    },
    propose_mitigation: {
      name: "propose_mitigation",
      title: "Prepare one governed mitigation proposal",
      description: "Stage the exact bounded proposal for this incident. It cannot approve or execute and is withdrawn after a successful commit.",
      inputSchema: {
        type: "object",
        properties: {
          service: { type: "string", minLength: 1, maxLength: 80, description: "Exact affected service from incident evidence." },
          service_version: { type: "string", minLength: 1, maxLength: 80, description: "Exact deployed service version." },
          symptom: { type: "string", minLength: 3, maxLength: 500, description: "Exact untrusted incident symptom." },
          rationale: { type: "string", minLength: 3, maxLength: 500, description: "Optional untrusted proposal rationale." }
        },
        required: ["service", "service_version", "symptom"],
        additionalProperties: false
      },
      annotations: { readOnlyHint: false, untrustedContentHint: true },
      async execute(input, options = {}) {
        return executeWithReconciliation("propose_mitigation", options, async (signal) => {
          const result = await host.proposeMitigation(input, { signal });
          const digest = result.proposal_digest || result.proposed_action?.action_hash;
          const requiresApproval = Boolean(
            result.requires_human_approval ?? result.proposed_action?.requires_approval
          );
          activity("SYSTEM", requiresApproval
            ? `proposal ${String(digest).slice(0, 20)} staged; human authority required`
            : "no mutating proposal staged; investigation remains available");
          return textResult({
            proposal_staged: requiresApproval,
            proposal_id: result.proposal_id || result.incident_id,
            proposal_digest: digest,
            diagnosis: String(result.diagnosis).slice(0, 500),
            rationale: String(result.rationale || result.proposed_action?.rationale || "").slice(0, 500),
            action: result.action || {
              display_name: result.proposed_action?.name,
              risk_class: result.proposed_action?.risk
            },
            requires_human_approval: requiresApproval,
            authority_owner: result.authority_owner || (requiresApproval ? "HUMAN_OPERATOR" : "AGENT"),
            epoch: result.epoch
          });
        });
      }
    },
    record_postcheck_assessment: {
      name: "record_postcheck_assessment",
      title: "Assess one verified postcheck observation",
      description: "Record an agent opinion about immutable server evidence. It cannot submit metrics or verdicts and creates only pending review memory.",
      inputSchema: {
        type: "object",
        properties: {
          observation_id: { type: "string", format: "uuid", description: "Exact server-issued observation identifier." },
          classification: { type: "string", enum: ["recovered", "not_recovered", "inconclusive"] },
          rationale: { type: "string", minLength: 3, maxLength: 1000 }
        },
        required: ["observation_id", "classification", "rationale"],
        additionalProperties: false
      },
      annotations: { readOnlyHint: false, untrustedContentHint: true },
      async execute(input, options = {}) {
        return executeWithReconciliation("record_postcheck_assessment", options, async (signal) => {
          const result = await host.recordPostcheckAssessment(input, { signal });
          activity("SYSTEM", `memory ${String(result.memory.id).slice(0, 8)} pending independent review`);
          return textResult({
            assessment: {
              classification: result.assessment.classification,
              rationale: String(result.assessment.rationale || "").slice(0, 1000)
            },
            policy_verdict: {
              classification: result.policy_verdict.classification,
              policy_version: result.policy_verdict.policy_version,
              checks_passed: result.policy_verdict.checks_passed || [],
              checks_failed: result.policy_verdict.checks_failed || []
            },
            assessment_policy_agree: result.assessment_policy_agree,
            memory: {
              id: result.memory.id,
              digest: result.memory.digest,
              state: result.memory.state,
              retrievable: result.memory.retrievable ?? result.memory.valid ?? false,
              valid: result.memory.valid ?? false
            },
            independent_review_required: result.independent_review_required ?? true,
            authority_owner: result.authority_owner || "HUMAN_REVIEWER",
            epoch: result.epoch
          });
        });
      }
    },
    recall_reviewed_memory: {
      name: "recall_reviewed_memory",
      title: "Recall certified evidence for occurrence 43",
      description: "Evaluate the immutable compatible recurrence using only admissible reviewed memory and compare the selected evidence authority with the exact pre-review counterfactual. This tool performs no domain mutation.",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      annotations: { readOnlyHint: true, untrustedContentHint: true },
      async execute(_input, options = {}) {
        return executeWithReconciliation("recall_reviewed_memory", options, async (signal) =>
          textResult(await host.recallReviewedMemory({ signal })));
      }
    }
  };

  function desiredTools(serverTools = host.getCapabilities()) {
    return serverTools.filter((name) => Object.hasOwn(definitions, name));
  }

  function render(phase, serverTools) {
    const desired = desiredTools(serverTools);
    phaseNode.textContent = phase;
    epochNode.textContent = String(sessionStorage.getItem("workflow_epoch") || "—");
    authorityNode.textContent = host.getAuthorityOwner();
    availableNode.replaceChildren(...desired.map((name) => {
      const item = document.createElement("li"); item.textContent = name; return item;
    }));
    const unavailable = Object.keys(definitions)
      .filter((name) => !desired.includes(name))
      .map((name) => `${name} — withheld in ${phase}`);
    withheldNode.replaceChildren(...[...unavailable, ...protectedOperations.map((name) =>
      `${name} — never exposed to agents`)].map((label) => {
      const item = document.createElement("li"); item.textContent = label; return item;
    }));
  }

  async function reconcile(phase, serverTools = host.getCapabilities()) {
    render(phase, serverTools);
    if (!modelContext?.registerTool) {
      status.textContent = "WebMCP unavailable · no fallback installed";
      status.classList.add("neutral");
      const item = document.createElement("li");
      item.textContent = "Native WebMCP is not enabled in this browser";
      availableNode.replaceChildren(item);
      activity("SYSTEM", "native WebMCP unavailable; no polyfill installed");
      return;
    }

    status.textContent = "Native WebMCP active · synchronized to server manifest";
    const desired = new Set(desiredTools(serverTools));
    currentDesired = desired;
    for (const [name, registration] of registrations) {
      if (!desired.has(name)) {
        registration.abort();
        registrations.delete(name);
        activity("SYSTEM", `${name} withdrawn: ${phase}`);
        persistActivity("tool_withdrawn", name);
      }
    }
    for (const name of desired) {
      if (registrations.has(name)) continue;
      const registrationController = new AbortController();
      // Reserve before awaiting the browser. Concurrent authoritative refreshes must
      // observe one lifecycle owner rather than create duplicate native registrations.
      registrations.set(name, registrationController);
      try {
        await modelContext.registerTool(definitions[name], { signal: registrationController.signal });
        if (
          registrationController.signal.aborted
          || !currentDesired.has(name)
        ) {
          registrationController.abort();
          if (registrations.get(name) === registrationController) registrations.delete(name);
          activity("SYSTEM", `${name} late registration discarded`);
          continue;
        }
        activity("SYSTEM", `${name} registered`);
        persistActivity("tool_registered", name);
      } catch (error) {
        registrationController.abort();
        if (registrations.get(name) === registrationController) registrations.delete(name);
        if (!currentDesired.has(name)) {
          activity("SYSTEM", `${name} late registration discarded`);
        } else {
          status.textContent = `WebMCP registration failed: ${error.name || "Error"}`;
          activity("SYSTEM", `${name} registration failed closed`);
          persistActivity("registration_failed", name, "failed");
        }
      }
    }
  }

  window.addEventListener("recallops:webmcp-state", (event) =>
    reconcile(event.detail.phase, event.detail.availableTools));
  window.addEventListener("recallops:activity", (event) =>
    activity(event.detail.actor, event.detail.message));
  window.addEventListener("focus", () => host.refreshWorkflow().catch(() => {}));
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") host.refreshWorkflow().catch(() => {});
  });
  setInterval(() => {
    if (document.visibilityState === "visible") host.refreshWorkflow().catch(() => {});
  }, 5000);
  reconcile(host.getPhase(), host.getCapabilities());
})();
