# Secure AWS deployment

> **Zero-spend release gate:** this project must not be deployed to a metered AWS service merely
> because credits are expected to cover it. Before provisioning, verify and retain sanitized
> evidence of an eligible `FREE` and `ACTIVE` account plan, sufficient active credits, expiry after
> the scheduled teardown plus safety margin, and service eligibility. AWS Budgets and cost alerts
> are delayed controls, not hard spending caps. If AWS cannot confirm zero payment-card exposure,
> deployment is blocked.

An earlier candidate account was retired from deployment after an Organizations setup changed it to
`PAID` and expired its Free Tier credit. Its single-account Organization was deleted, and both
orphaned IAM Identity Center multi-Region KMS keys were scheduled for deletion with the minimum
seven-day recovery window. AWS documents that customer-managed keys scheduled for deletion do not
incur key-storage charges. That account must never receive a RecallOps workload.

The active deployment account was independently verified on 2026-08-29 as standalone, `FREE`, and
`ACTIVE`, with USD 120 usable credits, no pre-existing metered workload, and a Free Plan expiration of
2027-02-28. AWS Organizations and organization-level IAM Identity Center are prohibited. GitHub
Actions obtains short-lived credentials through an IAM OIDC role bound to the repository's
immutable owner/repository subject, the `recallops-production` environment, and its `main`-only
deployment branch policy. The role has no general infrastructure permissions: it can publish only
to the `recallops` ECR repository, manage only `recallops-*` CloudFormation stacks, and pass only
the exact CloudFormation execution role. A USD 50 gross-cost monthly budget supplies early actual
and forecast alerts; the Free Plan remains the hard no-charge boundary.

Root has no access keys and is not used by the application or deployment workflow. The release uses
only scoped IAM credentials and does not represent account-root posture as an application security
control or hackathon proof claim.

RecallOps runs on ECS Fargate behind an HTTPS Application Load Balancer. AWS WAF
rate-limits abusive clients. Tasks run without public IP addresses, retrieve the
CockroachDB URL from Secrets Manager and write versioned evidence objects to a private S3 bucket.
Bedrock invocation permission is added only when a Bedrock provider is explicitly selected. CloudWatch
captures container logs, Container Insights, CPU alarms, target 5xx alarms, and unhealthy-target
alarms. Set `AlarmTopicArn` to deliver these alarms to a monitored SNS topic; an empty value keeps
them dashboard-visible only for local/demo stacks.

Evidence strength is not client-authoritative. `cloudwatch://alarm/<name>` references
must resolve server-side to exactly one alarm in `OK`, and
`s3://<configured-bucket>/<key>` must resolve to an existing evidence object.
Arbitrary HTTP references are rejected to avoid SSRF.

## Prerequisites

- A passed zero-spend release gate. The evidence must show account plan, plan state, remaining
  eligible credits, expiry, projected worst-case cost, safety margin, and teardown deadline. Values
  must come from AWS Billing or written AWS Support confirmation, not assumptions.
- Two public subnets for the ALB and two private subnets for Fargate, across at least
  two Availability Zones.
- Private-subnet egress through NAT. RecallOps needs outbound TLS to CockroachDB,
  ECR, CloudWatch Logs, Secrets Manager, S3, and its OIDC JWKS endpoint. A Bedrock-enabled
  deployment also needs Bedrock runtime access.
- An ACM certificate in the deployment region. Point the certificate's hostname to
  the emitted ALB DNS name after deployment.
- An OIDC application that emits access tokens with `custom:tenant_id` and
  `cognito:groups` claims. Self-registration must be disabled and tenant assignment
  controlled by an administrator.
- Four Secrets Manager secrets containing complete CockroachDB connection URLs: a LOGIN
  principal granted only `recallops_api`, a different LOGIN principal granted only
  `recallops_outbox`, a third LOGIN principal granted only `recallops_receipt`, and the
  migration-owner URL.
  The target `recallops` database must already exist; migrations own its schema, not
  cluster-level database provisioning. Confirm vector indexes are supported and
  enabled on the target cluster before deployment.
  Never place the URL in a CloudFormation parameter value or source file.
- Migrations create `NOLOGIN` privilege bundles but intentionally do not create credentialed
  users. Provision and grant the API, outbox, and receipt login principals using
  [`DATABASE_SECURITY.md`](DATABASE_SECURITY.md), then retain their URLs in separate secrets.
- Docker, Git, AWS CLI v2, and an authenticated AWS session.

## Deploy

Commit the release, then run:

```powershell
./scripts/deploy-aws.ps1 `
  -DatabaseUrlSecretArn 'arn:aws:secretsmanager:us-east-1:ACCOUNT:secret:recallops/database-…' `
  -OutboxDatabaseUrlSecretArn 'arn:aws:secretsmanager:us-east-1:ACCOUNT:secret:recallops/outbox-database-…' `
  -MigrationDatabaseUrlSecretArn 'arn:aws:secretsmanager:us-east-1:ACCOUNT:secret:recallops/migration-database-…' `
  -VpcId 'vpc-…' `
  -PublicSubnetIds 'subnet-public-a,subnet-public-b' `
  -PrivateSubnetIds 'subnet-private-a,subnet-private-b' `
  -CertificateArn 'arn:aws:acm:us-east-1:ACCOUNT:certificate/…' `
  -PublicHostname 'recallops.example.com' `
  -OidcIssuer 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_…' `
  -OidcAudience 'OIDC_APP_CLIENT_ID'
```

The default release uses deterministic reasoning and embeddings, so it has no model-service
availability dependency. To opt into Bedrock, pass `-ReasoningProvider bedrock`,
`-EmbeddingProvider bedrock`, and exact `-BedrockModelArns`. The task role receives
`bedrock:InvokeModel` only in that configuration.

The script rejects dirty worktrees, builds and pushes a Git-SHA-tagged image, resolves
its digest, deploys that immutable digest, and waits for ECS stability. Each task starts a
nonessential migrator with the owner secret; the API receives only its runtime secret and a
dedicated long-running outbox container receives only the outbox secret. Both wait for successful
migration before starting. A CockroachDB singleton row lock serializes each ordered migration;
every file commits separately so schema changes become public before a later file depends on
them. Applied migration checksums are immutable, and changing an
already-applied file fails startup instead of silently drifting the schema.

The final runtime is a digest-pinned distroless image. Every container uses numeric non-root user
`65532`, a read-only root filesystem, a minimal init process, and an empty Linux capability set.
See `docs/CONTAINER_SECURITY.md` for the image composition, scan evidence, and SBOM process.

## Operational checks

To enable bounded read-only diagnostics, set `RECALLOPS_DIAGNOSTIC_PROVIDER=aws` plus
`RECALLOPS_DIAGNOSTIC_ALARM_PREFIX`, `RECALLOPS_DIAGNOSTIC_ECS_CLUSTER`, and
`RECALLOPS_DIAGNOSTIC_ECS_SERVICE_PREFIX`; grant `cloudwatch:DescribeAlarms` and
`ecs:DescribeServices`. Names are derived as `<prefix>-<tenant>-<service>` and clients cannot
supply AWS identifiers. Leave the provider disabled if the deployment uses another naming
convention.

1. Confirm the HTTP endpoint redirects to HTTPS and TLS uses the intended hostname.
2. Run `recallops-db-verify` with the migration URL and retain its sanitized JSON report.
3. Confirm `/live` is healthy while protected endpoints reject missing tokens, then confirm
   `/ready` completes its bounded CockroachDB probe before accepting traffic.
4. Run the demo with two tenant tokens and verify cross-tenant access is denied.
5. Inspect WAF sampled requests, ECS Container Insights, log streams, and both alarms.
6. Set `AlarmTopicArn` and trigger a non-production alarm test; verify notification delivery.
7. Roll forward with a new commit. ECS automatically rolls back a deployment that
   cannot stabilize.

Private subnets and NAT gateways improve isolation but create fixed cost. For a
short-lived judging environment, shut down the stack after judging while retaining
the evidence bucket. Production deployments should use VPC endpoints where traffic
and NAT cost justify the additional resources and operational surface.

## Public judge demo

`infra/aws/public-demo.yaml` is a separate, lower-fixed-cost topology for a public
hackathon demonstration. API Gateway terminates managed HTTPS, applies route-level
throttling, and writes structured access logs. A private VPC Link is the only ingress
to an internal ALB. ECS tasks use public-subnet egress but accept traffic only from
the ALB security group. This avoids a purchased domain, ACM certificate, and NAT
gateway without exposing the origin.

The demo stack defaults to the same deterministic providers and idempotently seeds its three
governed memories in that embedding space before the API starts. ECS, S3, API Gateway, Cognito,
and CloudWatch remain meaningful AWS integrations. The stack also creates an administrator-only Cognito user pool, browser client
using authorization code plus PKCE, server-side tenant claim injection, and separate
operator and reviewer identities. Passwords are `NoEcho` parameters and are set by
a least-privilege custom resource; they are never committed. API payload identity is
derived from the verified access token, not from browser-controlled actor headers.

CloudFormation runs under `recallops-cloudformation-execution`, whose trust policy
admits only CloudFormation. `infra/aws/public-demo-execution-policy.json` contains
the bounded permissions required by this stack. The deploying principal needs only
stack lifecycle access and `iam:PassRole` for that service role.

The CockroachDB secret must retain `sslmode=verify-full` and point `sslrootcert` to
the runtime CA bundle (`/etc/ssl/certs/ca-certificates.crt` in the supplied image).
Validate the exact image before deployment:

```powershell
docker run --rm -e "RECALLOPS_DATABASE_URL=$databaseUrl" IMAGE_DIGEST recallops-migrate
```

Use `AWS::ApiGatewayV2` rather than CloudFront for the demo endpoint when an AWS
account is not verified to create CloudFront distributions. The production template
remains the preferred custom-domain topology with HTTPS ALB, WAF, private tasks, and
NAT or VPC endpoints.
