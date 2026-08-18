# Independent reviewer recruitment

Public volunteer intake: <https://github.com/milos-plavsic/recallops/issues/31>

Target: at least three eligible, independent reviewers with SRE, platform, incident-response,
security, or senior backend experience. Recruitment does not count as evidence; only locked,
independently submitted blinded labels do.

## Outreach routes

| Route | Destination | Suggested channel | Status |
| --- | --- | --- | --- |
| Local cloud-native | [Kubernetes Belgrade](https://www.meetup.com/kubernetes-belgrade/) / [Telegram](https://t.me/kubernetes_belgrade/82) | Group chat | Posted 2026-08-11; monitor replies |
| CNCF | [CNCF Slack](https://slack.cncf.io/) | [`#ai-sre`](https://cloud-native.slack.com/archives/C0B0KLC08VC/p1786400420820499) | Posted 2026-08-11; monitor replies |
| CNCF direct prospect | CNCF Slack | One private invitation to a member who publicly introduced himself as a cybersecurity professional with six years of experience | Sent and verified 2026-08-12; awaiting response; not confirmed |
| CNCF experienced prospects | CNCF Slack `#cncf-new-contributors` | Direct invitations to a Cloud & DevOps Engineer, a 15+ year Cloud Infrastructure Architect, an AI-agent security/eBPF contributor, and a backend/cloud-services engineer focused on distributed systems | Four DMs sent and verified 2026-08-12; one qualified candidate accepted and pseudonymous assignment `R01` was sent 2026-08-15; completion pending |
| CockroachDB | [Community Slack](https://cockroa.ch/slack) / [forum](https://forum.cockroachlabs.com/) | [`#hackathons`](https://cockroachdb.slack.com/archives/C0BGAEBTK1Q/p1786400751481369) | Posted 2026-08-11; monitor replies |
| Participant peers | CockroachDB Community Slack | Disclosed cross-review invitations following relevant public vector-index, Managed MCP security, and submission discussions | Three targeted invitations sent 2026-08-11; two declined on 2026-08-13 because of deadline/holiday availability; one has not responded; none confirmed |
| Hackathon | [Devpost Discussions](https://cockroachdb-ai.devpost.com/forum_topics/44757-independent-sre-reviewers-wanted-for-blinded-safety-evaluation) | New discussion topic | Posted 2026-08-11; monitor replies |
| Devpost peers | [Incident Commander](https://devpost.com/software/incident-commander-bt6zfh) and [SentinelAgent](https://devpost.com/software/sentinelagent-79qeux) | Project-specific disclosed cross-review invitations | Two comments posted 2026-08-11; awaiting responses; none confirmed |
| Direct qualified prospects | [AURA Memory](https://devpost.com/software/aura-memory), [OPERO](https://devpost.com/software/opero-c2qlh0), [IncidentBuddy](https://devpost.com/software/incidentbuddy), and [SupportTrace](https://devpost.com/software/supporttrace) | Individual Devpost comments to publicly listed hackathon participants selected for relevant security, SRE, Kubernetes/DevOps, or enterprise-architecture experience | Four tailored invitations posted 2026-08-12; awaiting responses; none confirmed |
| Expanded qualified cohort | [Drift](https://devpost.com/software/drift-agent-identity-authorization-platform), [City Sim Agent Benchmark](https://devpost.com/software/city-sim-agent-benchmark), [SAM Agent](https://devpost.com/software/self-evaluating-tracing-email-categorizer), [ASA](https://devpost.com/software/momentum-ai-hs2v8e), [One of One](https://devpost.com/software/one-of-one), [Theos](https://devpost.com/software/theos), [AgentWall](https://devpost.com/software/agent-wall-7u2640), [Security Runbook Agent](https://devpost.com/software/security-runbook-agent), [Vault Pilot](https://devpost.com/software/vault-pilot), and [ScentTrace](https://devpost.com/software/scenttrace) | Individual project comments to ten distinct public participants selected for cloud-platform, SRE, AWS/Terraform/MCP, MLOps, backend-security, human-approval, RBAC, or audit-evidence experience | Ten tailored invitations posted and verified 2026-08-12; awaiting responses; none confirmed |
| Third qualified cohort | [RescueNet AI](https://devpost.com/software/rescuenet-ai), [Flightcheck](https://devpost.com/software/flightcheck-an-agent-that-monitors-your-ai-agents), [Kumbh Safe](https://devpost.com/software/v0awsai), [Karma](https://devpost.com/software/karma-the-reincarnation-agent-for-deprecated-services), [MedScribe+](https://devpost.com/software/aws-nova-ai-hackathon-eaqy57), [Gasp](https://devpost.com/software/gasp), [URLPulse](https://devpost.com/software/urlpulse), [ResolveAI](https://devpost.com/software/resolveai-autonomous-incident-commander-for-slack), [Kingdom](https://devpost.com/software/kingdom-sxb14n), and [ContextBridge](https://devpost.com/software/contextbridge-institutional-memory-ai-agent) | Individual project comments to ten distinct public participants selected for incident response, agent observability, enterprise AI, cloud/backend engineering, chaos testing, security, or evidence-grounded memory experience | Ten tailored invitations posted and verified 2026-08-12; awaiting responses; none confirmed |
| Local DevOps | [DevOps Meetup Belgrade](https://www.meetup.com/belgrade-devops-meetup-group/) | Group discussion | No current organizer; low-priority fallback |

Do not post repeatedly, direct-message scraped member lists, or use technical support and project
issue trackers as advertising channels. One moderator-approved post per community is sufficient.

## Local / CNCF message

> Independent SRE reviewers wanted (30–45 min, asynchronous). I am evaluating RecallOps, a
> safety-gated incident-memory system, before a hackathon deadline. Reviewers independently label
> 20–30 randomized, de-identified A/B incident/remediation cases for safety, relevance, abstention,
> and confidence. You will not be told which system produced an answer; critical and negative
> findings are explicitly welcome. No employer or customer data, and no endorsement is requested.
> This is currently an uncompensated volunteer review. Details and private-contact option:
> https://github.com/milos-plavsic/recallops/issues/31

## CockroachDB message

> I am seeking independent SRE/platform reviewers for a blinded evaluation of RecallOps, an
> outcome-governed incident-memory system using CockroachDB. The review takes 30–45 minutes and
> uses randomized, de-identified A/B cases; database expertise is welcome but not required.
> Reviewers judge safety and relevance, and negative results will be retained. This is not a support
> request or a request to endorse the hackathon entry. Volunteer details:
> https://github.com/milos-plavsic/recallops/issues/31

## Hackathon message

> Cross-review request: I need three independent operations practitioners for a blinded safety
> evaluation of an incident-memory submission. Hackathon participants are welcome if they disclose
> the potential conflict; results will record conflicts and remain separate from authored tests.
> It is 20–30 randomized A/B cases, 30–45 minutes, uncompensated, and critical feedback is preferred.
> I am also willing to reciprocate with a clearly disclosed review after your labels are locked.
> Details: https://github.com/milos-plavsic/recallops/issues/31

## Completion ledger

Record only pseudonymous reviewer IDs in the repository. Keep contact details and any consent
records outside version control. For every candidate, record qualification, conflict disclosure,
packet version, assignment seed, sent time, received time, completeness, and exclusion reason in a
private operational ledger. Copy accepted labels into `evaluation/human_review_labels.csv` only
after validating the schema and removing identifying information.
