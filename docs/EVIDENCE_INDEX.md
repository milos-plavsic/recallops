# Judge evidence index

This page maps each submission claim to the fastest visible proof and to its deeper reproducible
artifact. The public demo is the product proof; repository artifacts explain how to reproduce and
audit it. Release-stamped evidence is valid only when its SHA matches `/v1/system/status`.

| Claim | Fast proof | Reproducible proof | Honest boundary |
| --- | --- | --- | --- |
| The agent stores, retrieves, and acts on memory | Perform the full live lifecycle in the [judge guide](JUDGE_GUIDE.md), then show the same short memory ID as pending, active, and recalled | `tests/test_service.py` and `tests/integration/test_database_boundaries.py` | The proposed infrastructure action is operator-attested; RecallOps does not claim to execute it |
| CockroachDB is the persistent memory layer | Query the new memory and governance event live | [schema and migrations](../migrations), [database security](DATABASE_SECURITY.md), `evidence/end-to-end-cockroach/` | Row isolation is enforced by verified application identity plus composite constraints; native RLS is not claimed |
| Distributed Vector Indexing is used | Show the verified plan lines `vector search` and `memories@memories_embedding_v2` | `evidence/cockroach-query-plan/` and `scripts/cockroach-query-plan.ps1` | Optimizer choice can vary with row count and statistics; the artifact records its dataset and release |
| An official CockroachDB Agent Skill shaped the build | Show the pinned skill revision beside the three implemented transaction consequences | `evidence/agent-skills/` and [CockroachDB tools](COCKROACH_TOOLS.md) | The separate proposed safety skill is open-source work, not counted as an accepted official tool |
| AWS hosts and protects the public system | Open the public URL, switch Cognito identities, then show a stable ECS task, current CloudWatch signal, and versioned S3 object | `infra/aws/cloudformation.yaml`, `evidence/deployment/`, and `evidence/aws-security/` | Bedrock is optional and must not be described as active when status reports deterministic providers |
| Retrieval is governed, not similarity-authorized | Expand selected/rejected candidates; run **Load safe-failure scenario** to show abstention | `evaluation/`, `tests/test_retrieval.py`, and `tests/test_evaluation.py` | Authored deterministic cases prove policy invariants, not general model accuracy |
| Unsafe knowledge stops influencing decisions | Revoke an active memory and analyze again in a prepared proof environment | `test_revoked_memory_is_immediately_excluded_but_history_remains` | History remains auditable; only active retrieval eligibility is removed |
| Retries converge safely | Show one incident, execution, memory, and outbox result after the concurrency test | `test_cockroach_concurrency_converges_on_one_incident_execution_and_memory` | This is a bounded contention test, not an internet-scale load claim |
| Security claims are explicit | Point judges to the [threat model](THREAT_MODEL.md) and least-privilege database roles | CI security jobs, `evidence/container-security/`, and `evidence/supply-chain/` | Scanner findings inherited without a vendor fix are documented, not hidden or called remediated |
| The visible workflow is tested | Run the Chromium suite | `tests/browser/recallops.spec.ts` and CI Playwright artifacts | Browser fixtures test rendering and accessibility; backend integration gates remain separate |

## Release consistency gate

Before recording or submitting, verify all of the following refer to one commit:

1. GitHub's public default or submission branch contains the release commit.
2. `/v1/system/status` reports that exact full SHA.
3. The CockroachDB plan, deployment, security, evaluation, and visual artifacts are stored under or
   identify that SHA.
4. The public demo passes `/health`, `/ready`, the complete lifecycle, and the safe-abstention path.
5. The video description links the public demo, repository, and this index.

Older artifacts remain useful history but must not be presented as evidence for a newer deployment.
