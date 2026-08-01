# AWS account activation blocker

## Observed evidence

- AWS account: `778900739705`
- Primary deployment region: `us-east-1`
- Tested identities: deployment role and authenticated account root
- Tested models: `amazon.titan-embed-text-v2:0`,
  `amazon.titan-embed-g1-text-02`, and `amazon.nova-lite-v1:0`
- Tested regions: `us-east-1`, `us-east-2`, `us-west-2`, and `eu-central-1`
- Availability response: agreement, entitlement, and region are available while
  `authorizationStatus` is `NOT_AUTHORIZED`
- Runtime response: `ValidationException: Operation not allowed`
- Correlated account signal: CloudFront distribution creation reports that the account
  is not verified

Amazon models do not require an AWS Marketplace subscription. Root receives the same
result as the task role, and the failure spans regions. The evidence therefore isolates
the blocker to AWS account activation or service authorization rather than application
code, IAM allow policies, model identifiers, or regional availability.

## Support case

Create an **Account and billing support** case with this body:

> AWS account 778900739705 appears incompletely verified or restricted at the account
> level. Amazon Bedrock reports agreement AVAILABLE, authorization NOT_AUTHORIZED,
> entitlement AVAILABLE, and region AVAILABLE for Amazon-owned Titan and Nova models.
> Invocation returns `ValidationException: Operation not allowed`. This occurs for
> `amazon.titan-embed-text-v2:0`, `amazon.titan-embed-g1-text-02`, and
> `amazon.nova-lite-v1:0`, including with the account root and across us-east-1,
> us-east-2, us-west-2, and eu-central-1. CloudFront creation also reports that the
> account is not verified. Please complete or restore account verification and remove
> the account-level restriction preventing Bedrock foundation-model authorization and
> CloudFront distribution creation. Please confirm when the account is fully activated.

The Support API cannot create this case on the account's Basic Support plan; it returns
`SubscriptionRequiredException`. Submit it through the authenticated AWS Support Center.

## Recovery gate

Run:

```powershell
./scripts/bedrock-readiness.ps1 -Profile default -Region us-east-1
```

Do not re-embed production memory until this gate reports both configured models as
`AUTHORIZED`. After it passes, invoke both models, run `recallops-reembed`, verify that
no `legacy:unknown:v0` rows remain, and capture the end-to-end benchmark.
