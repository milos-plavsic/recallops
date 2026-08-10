# Container security

RecallOps uses a two-stage image. The pinned `python:3.12-slim` image builds the wheel and
native Python dependencies; the final image is the pinned distroless Debian 13 `cc` runtime.
Only `/usr/local`, the one required `libffi` runtime library, migrations, evaluation data, and
the CockroachDB CA certificate cross the stage boundary. The production image contains no
shell, package manager, Perl, GNU tar, or general-purpose administrative toolchain.

The final image runs as numeric user and group `65532:65532`. ECS additionally makes every
container root filesystem read-only, drops all Linux capabilities, and enables the minimal init
process. Fargate provides the workload boundary; the task is neither privileged nor connected
to host devices.

Both base images are pinned by digest in `Dockerfile`. A release is built once, tagged with the
full Git SHA, pushed to ECR, and deployed by the resulting ECR digest. This preserves a direct
chain from reviewed source to the running task and leaves the previous task definition available
for rollback.

## Verification

The hardened candidate was tested with a read-only root filesystem and `--cap-drop ALL`, then
passed the unit, type, lint, policy-evaluation, end-to-end retrieval, browser, Compose, and
CloudFormation validation gates. Native imports for Psycopg, Cryptography, Pydantic, and uvloop
were exercised in the final runtime image.

Amazon ECR basic scanning reported zero findings for candidate digest
`sha256:75e7bf8d16ba9fedff3e887050570b04aedf032ba69cecfcb7018b947a2ee729` on
2026-08-10. The preceding Debian slim runtime reported 4 critical, 8 high, and 5 medium
findings. Those findings were eliminated by removing unused runtime packages, not by deleting
package metadata or suppressing scanner results.

A CycloneDX 1.7 image SBOM was generated with Syft pinned at
`sha256:678bfa565b60f747aac0f8e964fe5588a24445b8d0a480e91f6efd70020dfbb0`.
CI also publishes the dependency SBOM as a build artifact. Scanner results are point-in-time
evidence, not a permanent claim: the image must be rescanned when vulnerability feeds change,
and base digests must be deliberately refreshed through the same test and deployment gates.

No VEX exception is required for this candidate because the authoritative ECR scan has no
findings. If a future scan reports an unfixed issue, record the affected package, reachable code
path, compensating controls, review date, and upstream fix status rather than applying a blanket
suppression.
