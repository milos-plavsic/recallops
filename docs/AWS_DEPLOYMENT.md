# Secure AWS deployment

RecallOps runs on ECS Fargate behind an HTTPS Application Load Balancer. AWS WAF
rate-limits abusive clients. Tasks run without public IP addresses, retrieve the
CockroachDB URL from Secrets Manager, invoke only explicitly permitted Bedrock model
resources, and write versioned evidence objects to a private S3 bucket. CloudWatch
captures container logs, Container Insights, CPU alarms, and target 5xx alarms.

## Prerequisites

- Two public subnets for the ALB and two private subnets for Fargate, across at least
  two Availability Zones.
- Private-subnet egress through NAT. RecallOps needs outbound TLS to CockroachDB,
  Bedrock, ECR, CloudWatch Logs, Secrets Manager, S3, and its OIDC JWKS endpoint.
- An ACM certificate in the deployment region. Point the certificate's hostname to
  the emitted ALB DNS name after deployment.
- An OIDC application that emits access tokens with `custom:tenant_id` and
  `cognito:groups` claims. Self-registration must be disabled and tenant assignment
  controlled by an administrator.
- A Secrets Manager secret whose value is the complete CockroachDB connection URL.
  The target `recallops` database must already exist; migrations own its schema, not
  cluster-level database provisioning. Confirm vector indexes are supported and
  enabled on the target cluster before deployment.
  Never place the URL in a CloudFormation parameter value or source file.
- Docker, Git, AWS CLI v2, and an authenticated AWS session.

## Deploy

Commit the release, then run:

```powershell
./scripts/deploy-aws.ps1 `
  -DatabaseUrlSecretArn 'arn:aws:secretsmanager:us-east-1:ACCOUNT:secret:recallops/database-…' `
  -VpcId 'vpc-…' `
  -PublicSubnetIds 'subnet-public-a,subnet-public-b' `
  -PrivateSubnetIds 'subnet-private-a,subnet-private-b' `
  -CertificateArn 'arn:aws:acm:us-east-1:ACCOUNT:certificate/…' `
  -PublicHostname 'recallops.example.com' `
  -OidcIssuer 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_…' `
  -OidcAudience 'OIDC_APP_CLIENT_ID' `
  -BedrockModelArns 'arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-lite-v1:0,arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-embed-text-v2:0'
```

The script rejects dirty worktrees, builds and pushes a Git-SHA-tagged image, resolves
its digest, deploys that immutable digest, and waits for ECS stability. Each task
applies ordered SQL migrations before serving traffic. Applied migration checksums
are immutable; changing an already-applied file fails startup instead of silently
drifting the schema.

## Operational checks

1. Confirm the HTTP endpoint redirects to HTTPS and TLS uses the intended hostname.
2. Confirm `/health` is healthy while protected endpoints reject missing tokens.
3. Run the demo with two tenant tokens and verify cross-tenant access is denied.
4. Inspect WAF sampled requests, ECS Container Insights, log streams, and both alarms.
5. Roll forward with a new commit. ECS automatically rolls back a deployment that
   cannot stabilize.

Private subnets and NAT gateways improve isolation but create fixed cost. For a
short-lived judging environment, shut down the stack after judging while retaining
the evidence bucket. Production deployments should use VPC endpoints where traffic
and NAT cost justify the additional resources and operational surface.
