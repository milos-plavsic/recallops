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
| CockroachDB | [Community Slack](https://cockroa.ch/slack) / [forum](https://forum.cockroachlabs.com/) | [`#hackathons`](https://cockroachdb.slack.com/archives/C0BGAEBTK1Q/p1786400751481369) | Posted 2026-08-11; monitor replies |
| Hackathon | [Devpost Discussions](https://cockroachdb-ai.devpost.com/forum_topics/44757-independent-sre-reviewers-wanted-for-blinded-safety-evaluation) | New discussion topic | Posted 2026-08-11; monitor replies |
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
