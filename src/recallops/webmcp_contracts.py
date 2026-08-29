"""Frozen server and browser contracts for the four RecallOps WebMCP tools."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from recallops.domain import PostcheckClassification
from recallops.workflow import WorkflowState

WEBMCP_TOOL_NAMES = (
    "inspect_incident",
    "propose_mitigation",
    "record_postcheck_assessment",
    "recall_reviewed_memory",
)

PROTECTED_OPERATIONS = (
    "approve_proposal",
    "reject_proposal",
    "apply_sandbox_mitigation",
    "retry_observation",
    "issue_reviewer_handoff",
    "certify_memory",
    "quarantine_memory",
    "reject_memory",
    "revoke_memory",
    "switch_role",
    "override_policy",
    "reset_demo",
)


class WithheldTool(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    reason_code: str


class WebMcpManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: UUID
    run_generation: int = Field(gt=0)
    workflow_id: UUID
    state: WorkflowState
    epoch: int = Field(gt=0)
    authority_owner: str
    available_tools: tuple[str, ...]
    withheld_tools: tuple[WithheldTool, ...]
    protected_operations: tuple[str, ...] = PROTECTED_OPERATIONS
    memory_governance_version: int = Field(ge=0)
    capability_policy_version: str
    build_sha: str
    etag: str


class ProposalToolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service: str = Field(min_length=1, max_length=80)
    service_version: str = Field(min_length=1, max_length=80)
    symptom: str = Field(min_length=3, max_length=500)
    rationale: str | None = Field(default=None, min_length=3, max_length=500)


class AssessmentToolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observation_id: UUID
    classification: PostcheckClassification
    rationale: str = Field(min_length=3, max_length=1000)


class ActivityItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    activity_type: Literal[
        "tool_registered",
        "tool_withdrawn",
        "invocation_cancelled",
        "registration_failed",
    ]
    tool_name: Literal[
        "inspect_incident",
        "propose_mitigation",
        "record_postcheck_assessment",
        "recall_reviewed_memory",
    ]
    outcome: Literal["observed", "cancelled", "failed"]


class ActivityBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_instance_id: str = Field(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    items: list[ActivityItem] = Field(min_length=1, max_length=20)
