# Submission readiness and rule compliance

Verified against the official rules on 2026-08-01. The submission deadline is
2026-08-18 at 17:00 EDT. Re-check the [official rules](https://cockroachdb-ai.devpost.com/rules)
immediately before final submission because the organizer may amend them.

| Requirement | Evidence | Status |
| --- | --- | --- |
| New agentic application built during submission period | Git history and `docs/PROVENANCE.md` | Ready |
| CockroachDB is the persistent memory layer | `migrations/`, `store.py`, architecture ADR | Ready |
| At least two CockroachDB tools | Distributed Vector Indexing in application; ccloud CLI proof and Managed MCP judge config in `docs/COCKROACH_TOOLS.md` | Ready |
| At least one AWS service meaningfully integrated | ECS, S3, API Gateway, Cognito, CloudWatch, and deployed Bedrock reasoning/embedding paths | **AWS runtime verified; Bedrock account authorization blocked** |
| Functional, consistently installable project | Docker one-command demo, checksum migrations, CI | Ready |
| Public open-source repository and visible license | `https://github.com/milos-plavsic/recallops`, MIT | Ready |
| Source, README, dependencies, examples, dataset, setup/run instructions | Repository root, `.env.example`, evaluation dataset, judge guide | Ready |
| Functional demo URL free for judges through judging | https://c1mmwo9632.execute-api.us-east-1.amazonaws.com | **Verified live; Bedrock-dependent paths abstain until account authorization is restored** |
| English project description | `docs/JUDGE_GUIDE.md` submission narrative | Ready |
| Public YouTube/Vimeo demo under three minutes | `docs/JUDGE_GUIDE.md` video plan | **Pending recording/upload** |
| Video shows functioning project and CockroachDB memory | Shot plan explicitly includes live loop and memory layer | Pending video |
| Identify CockroachDB tools and actual use | `docs/COCKROACH_TOOLS.md` | Ready |
| Identify AWS services and actual use | `docs/AWS_DEPLOYMENT.md`, architecture | Ready |
| Architecture diagram | Console and `docs/ARCHITECTURE.md` Mermaid | Ready |
| Testing access/instructions | `docs/JUDGE_GUIDE.md`; credentials supplied separately from Git | **Verified with operator/reviewer browser flow** |
| No unauthorized copyrighted assets or secrets | Original HTML/CSS diagram, no music/assets, secret scanning checklist | Ready subject to final video review |
| Dependency vulnerability audit and SBOM | CI runs pinned `pip-audit` and uploads CycloneDX JSON | Ready |

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

## Active external gate

Amazon Bedrock currently returns `authorizationStatus: NOT_AUTHORIZED` for Amazon-owned
models even when invoked as the account root. The same account is blocked from creating
CloudFront distributions as unverified. Do not describe Bedrock as verified live until
`scripts/bedrock-readiness.ps1` passes and a real invocation succeeds. The evidence and
support-case payload are recorded in `docs/AWS_ACCOUNT_BLOCKER.md`.
