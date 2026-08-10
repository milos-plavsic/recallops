# Cost and sustainability model

The release evidence uses live AWS Price List API results and deployed dimensions rather than a
hand-maintained estimate. Reproduce it with:

```bash
uv run python scripts/capture-cost-evidence.py --release-sha "$(git rev-parse HEAD)" \
  --stack-name recallops-production --region us-east-1
```

The capture combines three different classes of data and keeps them distinct:

1. deployed dimensions from CloudFormation/ECS;
2. the previous 24 hours of API Gateway request and ALB consumed-LCU metrics; and
3. current public on-demand prices returned by the AWS Price List API.

For the August 10, 2026 capture, the deployed task is 0.5 vCPU and 1 GB. The measured monthly
subset is approximately `$34.45`: `$18.02` for one continuously running Fargate task, `$16.43`
for ALB hours, and less than one cent for the observed HTTP API request/LCU projection. This is a
low-traffic evidence environment, not a production forecast.

The deployed public-demo topology does **not** contain a NAT gateway or WAF. API Gateway provides
bounded route throttling, and the task currently receives a public IP for outbound managed-service
access. Earlier estimates that included NAT and WAF were structurally incorrect for this stack.

## Exclusions and decision use

The measured subset deliberately excludes CockroachDB Cloud, S3, CloudWatch Logs and alarms, data
transfer, support, tax, and optional Bedrock. Those costs must be added from actual bills or a
workload-specific forecast before a production decision. A 24-hour request sample is extrapolated
only to make assumptions inspectable; it is not represented as a bill.

At larger scale, compare the current always-on Fargate/ALB floor with a serverless ingress/runtime
design, but include cold-start, connection-pool, and long-running worker requirements. Do not use
Fargate Spot for the single judging task because there is no redundant task to absorb interruption.

Primary pricing sources are the AWS Price List API product terms for Amazon ECS/Fargate, Elastic
Load Balancing, and API Gateway. See the release-keyed `evidence/cost/` artifact for exact rates,
metric coverage, calculations, capture time, and exclusions.
