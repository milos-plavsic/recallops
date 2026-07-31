# Architecture decision record: outcome-conditioned memory

## Decision

Use CockroachDB as the single system of record for operational incident state, vector memories, approvals, and audit evidence. Rank retrieved memories using semantic similarity, observed outcome, service-version compatibility, and confidence.

## Why

A semantically similar remediation can be dangerous when it applies to another tenant or software version. Retrieval therefore cannot be the authorization mechanism. Tenant filtering occurs before ranking; invalid memories are excluded; compatibility affects rank; mutating actions require explicit approval.

Keeping operational rows and embeddings in one transactional database avoids consistency gaps between an incident record and a separate vector store. A tenant and service prefix on the vector index aligns index filtering with the dominant retrieval boundary.

## Alternatives

- Separate vector database: mature and flexible, but adds synchronization and operational failure modes without benefit to this scope.
- Conversation transcripts only: simple, but cannot represent outcomes, supersession, or authorization evidence safely.
- Fully autonomous remediation: compelling demo, but an unjustified security and reliability risk before allowlisted execution and postcondition verification exist.

## Current boundary

The MVP proposes and records decisions but does not execute mutations. AWS deployment automation, immutable S3 evidence, CloudWatch ingestion, and MCP/ccloud demonstrations are the next vertical increments.
