# Submission readiness and rule compliance

Verified against the official rules and overview on 2026-08-10. The submission deadline is
2026-08-18 at 17:00 EDT. Re-check the [official rules](https://cockroachdb-ai.devpost.com/rules)
immediately before final submission because the organizer may amend them.

| Requirement | Evidence | Status |
| --- | --- | --- |
| New agentic application built during submission period | Git history and `docs/PROVENANCE.md` | Ready |
| CockroachDB is the persistent memory layer | `migrations/`, `store.py`, architecture ADR | Ready |
| At least two CockroachDB tools | Distributed Vector Indexing in application; pinned official `designing-application-transactions` Agent Skill attestation under `evidence/agent-skills/` | Ready; managed CockroachDB and source-review evidence captured |
| At least one AWS service meaningfully integrated | ECS agent runtime, versioned S3 evidence, API Gateway, Cognito, and CloudWatch | Ready; Bedrock is optional |
| Functional, consistently installable project | Docker one-command demo, checksum migrations, CI | Ready |
| Public open-source repository and visible license | `https://github.com/milos-plavsic/recallops`, MIT | Ready |
| Source, README, dependencies, examples, dataset, setup/run instructions | Repository root, `.env.example`, evaluation dataset, judge guide | Ready |
| Functional demo URL free for judges through judging | https://ltfrottcxj.execute-api.us-east-1.amazonaws.com | Ready; `/health`, `/ready`, build SHA, providers, and policy gate verified |
| English project description | `docs/JUDGE_GUIDE.md` submission narrative | Ready |
| Public YouTube/Vimeo demo under three minutes | `docs/JUDGE_GUIDE.md` video plan | **Pending recording/upload** |
| Video shows functioning project and CockroachDB memory | Shot plan explicitly includes live loop and memory layer | Pending video |
| Identify CockroachDB tools and actual use | `docs/COCKROACH_TOOLS.md` plus sanitized run artifacts | **Pending run artifacts** |
| Identify AWS services and actual use | `docs/AWS_DEPLOYMENT.md`, architecture | Ready |
| Architecture diagram | Console and `docs/ARCHITECTURE.md` Mermaid | Ready |
| Testing access/instructions | `docs/JUDGE_GUIDE.md`; credentials supplied separately from Git | **Verified with operator/reviewer browser flow** |
| No unauthorized copyrighted assets or secrets | Original HTML/CSS diagram, no music/assets, secret scanning checklist | Ready subject to final video review |
| Dependency vulnerability audit and SBOM | CI artifact plus zero-finding ECR scan and `docs/CONTAINER_SECURITY.md` | Ready; rescan at submission time |

## Final human gates

1. Confirm entrant age, geography, conflicts, team representative, and ownership.
2. Add the MIT license to GitHub’s About panel if GitHub does not display it.
3. Deploy the committed digest on AWS, configure DNS/TLS/OIDC, create judge accounts,
   and keep it free and reachable through 2026-09-15 17:00 EDT.
4. Record the scripted video, remove all secrets/third-party marks/music, caption it,
   upload publicly to YouTube or Vimeo, and verify duration is below 3:00.
5. Put the public repository URL, functional demo URL, video URL, English narrative,
   tools/services explanation, architecture image, and testing credentials into Devpost.
6. Run `./scripts/submission-audit.ps1 -DemoUrl … -VideoUrl …` from clean `main`.
7. Submit before the deadline, open the resulting submission in a private browser,
   and preserve screenshots/confirmation email as proof of receipt.

## Optional Bedrock limitation

Amazon Bedrock currently returns `authorizationStatus: NOT_AUTHORIZED` for Amazon-owned models.
This does not block eligibility: the released judge deployment uses deterministic providers on
ECS and meaningful S3, Cognito, API Gateway, and CloudWatch integrations. Do not describe Bedrock
as verified live unless `scripts/bedrock-readiness.ps1` passes and a real invocation succeeds. The
account evidence remains in `docs/AWS_ACCOUNT_BLOCKER.md` for transparency.
