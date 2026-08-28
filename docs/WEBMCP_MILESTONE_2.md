# Milestone 2 Authoritative Workflow Core

**Status:** Complete and verified on 2026-08-28.

This increment moves capability selection from a browser-only phase flag to a
server-authoritative workflow record. It deliberately does not claim that a request header proves
human presence or that demo-mode identities are production authentication.

## Implemented security properties

- One explicit eight-state workflow model and a pure state-to-capability map.
- A monotonically increasing epoch on every state transition and reset invalidation.
- Conditional CockroachDB updates over tenant, workflow, active flag, expected state, and expected
  epoch. A stale transition updates no row and fails closed.
- Server-side role and channel checks for protected transitions.
- Different operator and reviewer subjects for review transitions.
- Protected-request validation before approval, execution, or outcome side effects.
- A server capability endpoint used by both the page inspector and native WebMCP registration.
- Abort-driven browser registration reconciliation after authoritative state changes.
- Reset invalidation removes every capability from the old workflow and advances its epoch.
- A tenant-bound database foreign key and least-privilege runtime grants for workflow rows.
- Bounded whole-transaction retries for CockroachDB `40001` serialization failures while retaining
  the database's default `SERIALIZABLE` isolation.
- Role-specific bootstrap codes stored only as configured SHA-256 digests.
- Opaque short-lived sessions stored only by hash in CockroachDB and delivered in `HttpOnly`,
  `SameSite=Strict`, production `Secure`, `__Host-` cookies.
- Exact-Origin validation, synchronizer CSRF tokens, HMAC-pseudonymous exchange throttling, and
  server-side logout revocation.
- Atomic proposal, approval, execution, outcome, and review transactions: the domain write and
  workflow epoch either commit together or both roll back.

The transaction retry policy follows CockroachDB's guidance to retry the complete transaction when
the client receives a serialization retry error:
<https://www.cockroachlabs.com/docs/stable/developer-basics.html#transaction-retries>.

## State and capability contract

| State | Server-authorized WebMCP capability names | Authority owner |
| --- | --- | --- |
| `INVESTIGATING` | `inspect_incident`, `propose_mitigation` | Agent |
| `AWAITING_OPERATOR_APPROVAL` | `inspect_incident` | Operator |
| `APPROVED_AWAITING_EXECUTION` | `inspect_incident` | Operator |
| `OBSERVING_POSTCHECK` | `inspect_incident` | System |
| `POSTCHECK_READY` | `inspect_incident`, `record_postcheck_assessment` | Agent |
| `POSTCHECK_UNAVAILABLE` | `inspect_incident` | Operator |
| `PENDING_REVIEW` | `inspect_incident` | Reviewer |
| `REVIEWED` | `inspect_incident`, `recall_reviewed_memory` | Governed memory |

Only `inspect_incident` and `propose_mitigation` are browser-implemented in this increment. The
server manifest already reserves the final tool surface, but the browser filters out any tool whose
implementation and tests do not yet exist.

## Verification record

| Check | Result |
| --- | --- |
| Python suite with CockroachDB integration enabled | `180 passed` |
| Real CockroachDB integration tests | `7 passed` |
| Concurrent incident replay | 16 calls converged to one incident, execution, memory, and outbox row |
| Concurrent workflow transition | Exactly 1 winner and 15 stale rejections |
| Direct database boundary verifier | 24 exact grants, 7 cross-tenant constraints, 9 denied operations |
| Browser, accessibility, fallback, auth, and lifecycle suite | `8 passed` |
| Native Chromium WebMCP suite | `2 passed` |
| Ruff over maintained source and tests | Passed |
| Strict mypy | Passed; 21 source files checked |

The native suite now includes a real FastAPI journey. It creates and independently reviews seed
evidence, invokes `propose_mitigation` through Chromium's native WebMCP implementation, observes the
server manifest withdraw the tool, and proves that a direct approval request labeled as WebMCP is
rejected.

The database contention test initially produced a real commit-time serialization failure. The
implementation was not weakened to `READ COMMITTED`; complete transactions now retry from fresh
snapshots with a bounded exponential backoff, and the contention suite passes on CockroachDB
`v26.2.1`.

Fault injection after an approval insert proves that both the approval and epoch remain unchanged
when the workflow update fails. A second fault injection after memory activation proves that the
memory stays `PENDING_REVIEW`, `valid=false`, no governance event is appended, and the workflow
remains at the prior epoch. These checks exercise rollback rather than inferring atomicity from code.

## Deliberate non-claims and later milestone work

- Demo authentication still accepts development identity headers and is not identity proof. The
  public judge path uses the separate `judge` authentication mode.
- Channel labels are policy context, not proof of physical human presence or a defense against
  arbitrary browser automation.
- The sandbox, observation provider, postcheck-assessment tool, reviewed-recall tool, event chain,
  and signed Authority Receipt belong to later milestones.

The later signed receipt will add an append-only event chain; it is not required for the transactional
authorization property proven here.
