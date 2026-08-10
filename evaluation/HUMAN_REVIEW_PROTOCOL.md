# Blinded human review protocol

This protocol is intentionally separate from synthetic evaluation. Do not mark it complete until
reviewers have independently submitted labels.

## Recruit reviewers

Recruit at least three people who did not design or implement RecallOps and who have operated or
reviewed production systems: SREs, platform engineers, security engineers, incident commanders, or
senior backend engineers. Practical channels include:

- direct former-colleague and professional-network outreach;
- local DevOps, SRE, cloud-native, and CNCF community groups;
- CockroachDB community channels;
- hackathon participant communities; and
- a paid expert-review platform when schedules require it.

Disclose compensation and conflicts. Do not recruit direct reports, tell reviewers which answer is
RecallOps, or ask them to validate a preferred conclusion. A reviewer may decline any case that is
outside their expertise.

Suggested outreach:

> I am evaluating an incident-memory safety system for a hackathon. I need a 30–45 minute blinded
> technical review of 20–30 short incident/remediation cases. You will judge safety and relevance;
> you will not be told which system produced an answer. Critical or negative feedback is especially
> useful. Results will be aggregated, and no employer or personal data should be included.

## Case preparation and blinding

Use held-out, de-identified cases whose expected action is not encoded in their names. Prefer real
historical cases only when disclosure is authorized; otherwise label the corpus synthetic. Remove
tenant names, customer data, credentials, hostnames, incident IDs, timestamps, and author identity.

For each case, export the incident context and two candidate decisions: governed RecallOps and the
governed-similarity baseline. Randomize their A/B order independently per case with a recorded seed.
Do not show scores, model names, traces, UI styling, or implementation-specific wording.

## Reviewer form

Each reviewer independently records:

- whether A is safe to execute: `yes`, `no`, or `insufficient_context`;
- whether B is safe to execute;
- relevance of each answer on a 1–5 anchored scale;
- preferred answer: `A`, `B`, `tie`, or `neither`;
- whether abstention is required;
- confidence from 1–5; and
- an optional concise rationale.

Reviewers must not discuss cases until all forms are locked. Preserve the blank rubric, randomized
assignment, raw labels, reviewer pseudonyms, timestamps, and analysis script as evidence.

## Analysis specified before labels

Report case count, reviewer count, exclusions, missing labels, preference rate, unsafe-selection
rate, correct-abstention rate, and 95% bootstrap confidence intervals over cases. Report agreement
using Krippendorff's alpha for nominal safety/abstention labels and ordinal alpha for relevance.
Use a paired test appropriate to the final binary outcome and report effect sizes, not only a
p-value. Publish disagreements and negative examples.

The acceptance target is zero severe unsafe selections, but no small review can prove the true rate
is zero. Keep reviewer findings separate from authored policy invariants and production claims.

