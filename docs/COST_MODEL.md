# Cost and sustainability model

Estimate date: 2026-08-01. Region: `us-east-1`. Prices vary; verify in the
[AWS Pricing Calculator](https://calculator.aws/) before deployment. The model assumes
one continuously running 0.5-vCPU/1-GB Linux/x86 Fargate task, one low-traffic ALB, one
WAF web ACL with one custom rule, one NAT gateway, 730 hours/month, and negligible S3,
logs, and data transfer. CockroachDB Cloud and Bedrock are usage-dependent and excluded
from the fixed subtotal.

| Component | Approximate monthly cost | Driver |
| --- | ---: | --- |
| ECS Fargate task | $18 | 0.5 vCPU + 1 GB continuously |
| Application Load Balancer | $22+ | ALB hours plus low LCU consumption |
| AWS WAF | $6+ | one web ACL + one rule, then request charges |
| One NAT gateway | $33+ | hourly charge, before processed data |
| S3 and CloudWatch | <$5 at demo volume | stored bytes, requests, and log ingestion |
| **Fixed demo baseline** | **about $79–$85/month** | excludes Bedrock, CockroachDB, DNS, transfer, tax |

Two NAT gateways across Availability Zones add roughly another $33/month but remove a
single-AZ egress dependency. A judging environment should be created shortly before
evaluation and removed afterward; the retained S3 bucket must be deleted separately
when evidence is no longer needed. For production, compare NAT processing cost with
gateway/interface VPC endpoints. S3 gateway endpoints have no hourly or processing
charge, while interface endpoints add hourly ENI cost.

Bedrock cost scales with input/output tokens and embedding volume. RecallOps bounds
reasoning output to 300 tokens, retrieves at most five memories by default, and uses a
small Nova model. Measure real prompt tokens before forecasting. Fargate Spot is not
used for the single judging task because interruption risk outweighs its discount;
horizontal production workers with redundancy can revisit that choice.

Primary pricing references: [Fargate](https://aws.amazon.com/fargate/pricing/),
[Elastic Load Balancing](https://aws.amazon.com/elasticloadbalancing/pricing/),
[AWS WAF](https://aws.amazon.com/waf/pricing/),
[Amazon VPC/NAT](https://aws.amazon.com/vpc/pricing/), and
[Amazon Bedrock](https://aws.amazon.com/bedrock/pricing/).
