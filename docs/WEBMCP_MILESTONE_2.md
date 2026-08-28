# Milestone 2 Authoritative Workflow Core

**Status:** Core complete and verified on 2026-08-28; judge-session authentication and
transactional event receipts remain open before the full milestone is accepted.

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
| Python suite with CockroachDB integration enabled | `171 passed` |
| Real CockroachDB integration tests | `4 passed` |
| Concurrent incident replay | 16 calls converged to one incident, execution, memory, and outbox row |
| Concurrent workflow transition | Exactly 1 winner and 15 stale rejections |
| Direct database boundary verifier | 18 exact grants, 7 cross-tenant constraints, 8 denied operations |
| Browser, accessibility, fallback, and lifecycle suite | `7 passed` |
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

## Deliberate non-claims and remaining acceptance work

- Demo authentication still accepts development identity headers. It tests authorization logic but
  does not prove identity. The public judge path still needs short-lived, server-issued operator and
  reviewer sessions, CSRF protection, Origin validation, and bootstrap-code rotation.
- Channel labels are policy context, not proof of physical human presence or a defense against
  arbitrary browser automation.
- Domain records and workflow epochs are fail-closed but are not yet committed in one shared SQL
  transaction. Approval, execution, and outcome validate before writing; a later epoch conflict
  withholds downstream capability. Review activation requires stronger transactional coupling
  before final acceptance because activation affects retrieval authority.
- The sandbox, observation provider, postcheck-assessment tool, reviewed-recall tool, event chain,
  and signed Authority Receipt belong to later milestones.

Milestone 2 should be marked fully complete only after session authentication and atomic protected
transition orchestration are implemented and tested against CockroachDB.
