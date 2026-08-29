import hashlib
import hmac
import json
import math
import os
import secrets
import threading
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, cast
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from recallops.archive import NullEvidenceArchive, S3EvidenceArchive
from recallops.auth import (
    AuthenticationError,
    AuthorizationError,
    JudgeSessionAuthenticator,
    Principal,
    create_authenticator,
)
from recallops.canonical import content_digest
from recallops.config import Settings, get_settings
from recallops.diagnostics import (
    AwsCloudWatchAlarmInspector,
    AwsEcsDeploymentInspector,
    ReadOnlyDiagnosticTools,
)
from recallops.domain import (
    ApprovalRequest,
    CompatibilityPolicy,
    ExecutionAttestation,
    ExecutionAttestationRequest,
    GovernanceAction,
    HandoffPurpose,
    IncidentAnalysis,
    IncidentCreate,
    Memory,
    MemoryGovernanceRequest,
    MemoryOutcome,
    MemoryState,
    OutcomeObservation,
    PostcheckAssessment,
    PostcheckAssessmentRequest,
    PostcheckRetryRequest,
    RecurrenceView,
    ReviewerDispositionRequest,
    ReviewerHandoffRequest,
    ReviewerRevocationRequest,
    SandboxExecution,
    SandboxExecutionRequest,
)
from recallops.embedding import BedrockTitanEmbedder, DeterministicEmbedder
from recallops.evaluation import EvaluationReport, evaluate, load_dataset
from recallops.evidence import AwsEvidenceVerifier, ManualOnlyEvidenceVerifier
from recallops.ledger import (
    ActivityObservation,
    InMemoryAuthorityLedgerRepository,
    PostgresAuthorityLedgerRepository,
)
from recallops.public_bundles import PublicBundleService
from recallops.release_status import PublicReleaseStatus, ReleaseStatusService
from recallops.resilience import DependencyUnavailable
from recallops.sandbox import (
    SANDBOX_ACTION_COMMAND,
    CheckoutSandbox,
    DeterministicObservationProvider,
    ObservationProvider,
    SandboxPolicyError,
    evaluate_observation,
    policy_verdict_digest,
)
from recallops.service import (
    BedrockReasoner,
    DeterministicReasoner,
    IncidentService,
    IncidentWorkflowError,
)
from recallops.sessions import (
    InMemoryJudgeSessionRepository,
    JudgeRun,
    JudgeRunCapacityError,
    PostgresJudgeSessionRepository,
    ReviewHandoff,
)
from recallops.store import (
    InMemoryStore,
    MemoryGovernanceError,
    MemoryStore,
    PostgresStore,
    version_compatibility,
)
from recallops.webmcp_contracts import (
    PROTECTED_OPERATIONS,
    WEBMCP_TOOL_NAMES,
    ActivityBatch,
    AssessmentToolRequest,
    ProposalToolRequest,
    WebMcpManifest,
    WithheldTool,
)
from recallops.workflow import (
    InMemoryWorkflowRepository,
    PostgresWorkflowRepository,
    RequestChannel,
    WorkflowConflict,
    WorkflowCoordinator,
    WorkflowSnapshot,
    WorkflowState,
    authority_owner,
)


def create_app(
    settings: Settings | None = None,
    store: MemoryStore | None = None,
    *,
    checkout_sandbox: CheckoutSandbox | None = None,
    observation_provider: ObservationProvider | None = None,
    public_bundle_service: PublicBundleService | None = None,
    release_status_service: ReleaseStatusService | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    store = store or (
        PostgresStore(
            settings.database_url,
            settings.database_connect_timeout_seconds,
            settings.database_statement_timeout_seconds,
            settings.retrieval_candidate_multiplier,
        )
        if settings.store == "postgres"
        else InMemoryStore()
    )
    embedder = (
        BedrockTitanEmbedder(
            settings.aws_region,
            settings.bedrock_embedding_model_id,
            settings.provider_connect_timeout_seconds,
            settings.provider_read_timeout_seconds,
            settings.provider_max_attempts,
        )
        if settings.embedding_provider == "bedrock"
        else DeterministicEmbedder()
    )
    reasoner = (
        BedrockReasoner(
            settings.aws_region,
            settings.bedrock_model_id,
            settings.provider_connect_timeout_seconds,
            settings.provider_read_timeout_seconds,
            settings.provider_max_attempts,
        )
        if settings.reasoning_provider == "bedrock"
        else DeterministicReasoner()
    )
    archive = (
        S3EvidenceArchive(
            settings.aws_region,
            settings.evidence_bucket,
            settings.provider_connect_timeout_seconds,
            settings.provider_read_timeout_seconds,
            settings.provider_max_attempts,
        )
        if settings.evidence_bucket
        else NullEvidenceArchive()
    )
    evidence_verifier = (
        AwsEvidenceVerifier(
            settings.aws_region,
            settings.evidence_bucket,
            settings.provider_connect_timeout_seconds,
            settings.provider_read_timeout_seconds,
            settings.provider_max_attempts,
        )
        if settings.evidence_verifier == "aws"
        else ManualOnlyEvidenceVerifier()
    )
    diagnostic_tools = None
    if settings.diagnostic_provider == "aws":
        alarm_prefix = settings.diagnostic_alarm_prefix
        ecs_cluster = settings.diagnostic_ecs_cluster
        ecs_service_prefix = settings.diagnostic_ecs_service_prefix
        if alarm_prefix is None or ecs_cluster is None or ecs_service_prefix is None:
            raise ValueError("AWS diagnostics require alarm, cluster, and service prefixes")
        diagnostic_tools = ReadOnlyDiagnosticTools(
            alarms=AwsCloudWatchAlarmInspector(
                settings.aws_region,
                alarm_prefix,
                settings.provider_connect_timeout_seconds,
                settings.provider_read_timeout_seconds,
                settings.provider_max_attempts,
                max_alarms=settings.diagnostic_max_alarms,
            ),
            deployments=AwsEcsDeploymentInspector(
                settings.aws_region,
                ecs_cluster,
                ecs_service_prefix,
                settings.provider_connect_timeout_seconds,
                settings.provider_read_timeout_seconds,
                settings.provider_max_attempts,
                max_deployments=settings.diagnostic_max_deployments,
            ),
        )
    service = IncidentService(
        store,
        embedder,
        reasoner,
        settings.max_memories,
        archive,
        min_similarity=settings.retrieval_min_similarity,
        min_confidence=settings.retrieval_min_confidence,
        min_rank_score=settings.retrieval_min_rank_score,
        min_margin=settings.retrieval_min_margin,
        provider_max_attempts=settings.provider_max_attempts,
        provider_timeout_seconds=settings.provider_read_timeout_seconds,
        evidence_verifier=evidence_verifier,
        default_compatibility_policy=CompatibilityPolicy(settings.default_compatibility_policy),
        compatibility_policy_version=settings.compatibility_policy_version,
        memory_ttl_days=settings.memory_ttl_days,
        diagnostic_tools=diagnostic_tools,
    )
    judge_repository = (
        PostgresJudgeSessionRepository(store.pool)
        if isinstance(store, PostgresStore)
        else InMemoryJudgeSessionRepository()
    )
    authenticator = create_authenticator(settings, judge_repository)
    workflow_repository = (
        PostgresWorkflowRepository(
            settings.database_url,
            settings.database_connect_timeout_seconds,
            settings.database_statement_timeout_seconds,
        )
        if isinstance(store, PostgresStore)
        else InMemoryWorkflowRepository()
    )
    ledger_repository = (
        PostgresAuthorityLedgerRepository(store.pool)
        if isinstance(store, PostgresStore)
        else InMemoryAuthorityLedgerRepository()
    )
    workflows = WorkflowCoordinator(workflow_repository, ledger_repository)
    checkout_sandbox = checkout_sandbox or CheckoutSandbox()
    observation_provider = observation_provider or DeterministicObservationProvider()
    if public_bundle_service is None and settings.authority_bundle_bucket:
        if not isinstance(store, PostgresStore):
            raise ValueError("public authority bundles require the PostgreSQL store")
        public_bundle_service = PublicBundleService.aws(
            settings.database_url,
            settings.aws_region,
            settings.authority_bundle_bucket,
        )
    release_status_service = release_status_service or ReleaseStatusService.production(settings)
    authority_lock = threading.RLock()

    app = FastAPI(title="RecallOps", version="0.1.0", docs_url="/docs")
    app.state.store = store
    app.state.service = service
    app.state.workflows = workflows
    app.state.checkout_sandbox = checkout_sandbox
    app.state.observation_provider = observation_provider
    app.state.judge_repository = judge_repository
    app.state.ledger_repository = ledger_repository
    app.state.public_bundle_service = public_bundle_service
    app.state.release_status_service = release_status_service

    def authority_transaction(
        operation: Callable[[IncidentService, WorkflowCoordinator], object],
    ) -> object:
        if isinstance(store, PostgresStore):
            return store.atomic(
                lambda bound_store, connection: operation(
                    service.using_store(bound_store),
                    WorkflowCoordinator(
                        PostgresWorkflowRepository.from_connection(connection),
                        PostgresAuthorityLedgerRepository.from_connection(
                            connection, getattr(app.state, "ledger_fault_hook", None)
                        ),
                        getattr(app.state, "ledger_fault_hook", None),
                    ),
                )
            )
        with authority_lock:
            return operation(service, workflows)

    oidc_connect_origin = ""
    if settings.oidc_token_url:
        parsed_token_url = urlsplit(settings.oidc_token_url)
        oidc_connect_origin = f" {parsed_token_url.scheme}://{parsed_token_url.netloc}"

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
            f"connect-src 'self'{oidc_connect_origin}; form-action 'self'; "
            "img-src 'self' data:; "
            "object-src 'none'; script-src 'self'; style-src 'self'"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Origin-Agent-Cluster"] = "?1"
        response.headers["Permissions-Policy"] = (
            "tools=(self), camera=(), microphone=(), geolocation=()"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        if request.url.path.startswith("/v1/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def role_cookie_name(role: str) -> str:
        prefix = "__Host-" if settings.judge_cookie_secure else ""
        return f"{prefix}recallops_{role}"

    def set_role_cookie(response: Response, role: str, token: str) -> None:
        response.set_cookie(
            key=role_cookie_name(role),
            value=token,
            max_age=settings.judge_session_ttl_seconds,
            secure=settings.judge_cookie_secure,
            httponly=True,
            samesite="strict",
            path="/",
        )

    def principal(
        request: Request,
        authorization: str | None = Header(default=None),
        x_tenant_id: str | None = Header(default=None, max_length=80),
        x_actor_id: str | None = Header(default=None, max_length=200),
        x_roles: str | None = Header(default=None, max_length=500),
    ) -> Principal:
        # Judge cookies intentionally coexist. Authority is selected by the server route,
        # never by cookie order, a client-provided role, or a shared browser toggle.
        if settings.auth_mode == "judge":
            selected_role = (
                "reviewer" if request.url.path.startswith("/v1/reviewer/") else "operator"
            )
            session_cookie = request.cookies.get(role_cookie_name(selected_role))
        else:
            session_cookie = None
        try:
            return authenticator.authenticate(
                authorization, x_tenant_id, x_actor_id, x_roles, session_cookie
            )
        except AuthenticationError as error:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                str(error),
                headers={"WWW-Authenticate": "Bearer"},
            ) from error

    def require_role(identity: Principal, role: str) -> None:
        try:
            identity.require(role)
        except AuthorizationError as error:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(error)) from error

    AuthenticatedPrincipal = Annotated[Principal, Depends(principal)]

    def require_protected_request(
        request: Request, identity: Principal, csrf_token: str | None
    ) -> None:
        if settings.auth_mode != "judge":
            return
        if request.headers.get("origin") != settings.public_origin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "trusted Origin required")
        if not isinstance(authenticator, JudgeSessionAuthenticator):  # pragma: no cover
            # Construction binds judge mode to this authenticator; retain a fail-closed
            # invariant guard in case future dependency injection violates that contract.
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "judge auth unavailable")
        try:
            authenticator.validate_csrf(identity, csrf_token)
        except AuthorizationError as error:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(error)) from error

    @app.post("/v1/judge/session/logout")
    def logout_judge_session(
        request: Request,
        response: Response,
        identity: AuthenticatedPrincipal,
        x_csrf_token: str | None = Header(default=None, max_length=200),
    ) -> dict[str, bool]:
        if not isinstance(authenticator, JudgeSessionAuthenticator):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "judge sessions are not enabled")
        require_protected_request(request, identity, x_csrf_token)
        authenticator.revoke(identity)
        role = next(iter(identity.roles & {"operator", "reviewer"}))
        response.delete_cookie(
            key=role_cookie_name(role),
            secure=settings.judge_cookie_secure,
            httponly=True,
            samesite="strict",
            path="/",
        )
        return {"revoked": True}

    def run_payload(run: JudgeRun) -> dict[str, object]:
        return {
            "run_id": str(run.run_id),
            "generation": run.generation,
            "scenario_version": run.scenario_version,
            "incident_id": str(run.source_incident_id),
            "status": run.status,
            "expires_at": run.expires_at,
            "build_sha": run.build_sha,
            "capability_policy_version": run.capability_policy_version,
            "simulation": True,
        }

    def allocate_run(generation: int = 1) -> tuple[JudgeRun, str, str, Principal]:
        run_id = uuid4()
        tenant_id = f"judge_{run_id.hex[:24]}"
        operator_subject = f"operator_{secrets.token_hex(12)}"
        now = datetime.now(UTC)
        incident = IncidentCreate(
            tenant_id=tenant_id,
            service="checkout",
            service_version="v2.4.1",
            symptom="checkout-latency-42: p95 latency and error rate exceed the sandbox SLO",
            idempotency_key=f"scenario-{run_id.hex}",
        )
        incident_embedding = embedder.embed(f"checkout {incident.symptom}")
        incident_norm = math.sqrt(sum(value * value for value in incident_embedding))
        if incident_norm == 0:
            raise RuntimeError("judge incident embedding has zero magnitude")
        incident_unit = [value / incident_norm for value in incident_embedding]

        def fixture_embedding(similarity: float, label: str) -> list[float]:
            seed = embedder.embed(f"{label}:{run_id}")
            projection = sum(left * right for left, right in zip(incident_unit, seed, strict=True))
            orthogonal = [
                value - projection * base for value, base in zip(seed, incident_unit, strict=True)
            ]
            norm = math.sqrt(sum(value * value for value in orthogonal))
            if norm == 0:  # pragma: no cover - independent deterministic labels are non-collinear
                raise RuntimeError("judge similarity fixture is degenerate")
            residual = math.sqrt(1 - similarity * similarity)
            return [
                similarity * base + residual * value / norm
                for base, value in zip(incident_unit, orthogonal, strict=True)
            ]

        fixture_memories = (
            Memory(
                id=uuid5(NAMESPACE_URL, f"recallops:{run_id}:known-failure"),
                tenant_id=tenant_id,
                service="checkout",
                service_version="v1.9.8",
                symptom=incident.symptom,
                action="restart checkout workers without reducing concurrency",
                outcome="known failure: saturation immediately recurred",
                outcome_score=-1.0,
                confidence=0.99,
                state=MemoryState.ACTIVE,
                valid=True,
                reviewed_by="fixture-reviewer",
                reviewed_at=now - timedelta(days=14),
                expires_at=now + timedelta(days=settings.memory_ttl_days),
                embedding_space=embedder.space_id,
                embedding=fixture_embedding(0.94, "known-failure"),
                created_at=now - timedelta(days=14),
            ),
            Memory(
                id=uuid5(NAMESPACE_URL, f"recallops:{run_id}:compatible-success"),
                tenant_id=tenant_id,
                service="checkout",
                service_version=incident.service_version,
                symptom=incident.symptom,
                action=SANDBOX_ACTION_COMMAND,
                outcome="reviewed recovery without recurrence",
                outcome_score=1.0,
                confidence=0.96,
                state=MemoryState.ACTIVE,
                valid=True,
                reviewed_by="fixture-reviewer",
                reviewed_at=now - timedelta(days=21),
                expires_at=now + timedelta(days=settings.memory_ttl_days),
                embedding_space=embedder.space_id,
                embedding=fixture_embedding(0.81, "compatible-success"),
                created_at=now - timedelta(days=21),
            ),
        )

        def build_run(prepared: IncidentAnalysis) -> JudgeRun:
            return JudgeRun(
                run_id=run_id,
                tenant_id=tenant_id,
                generation=generation,
                scenario_version=settings.scenario_version,
                source_incident_id=prepared.incident_id,
                operator_subject=operator_subject,
                build_sha=settings.build_sha,
                capability_policy_version=settings.capability_policy_version,
                created_at=now,
                expires_at=now + timedelta(seconds=settings.judge_run_ttl_seconds),
            )

        if isinstance(store, PostgresStore):

            def persist(connection_store: PostgresStore, connection: object) -> JudgeRun:
                bound_service = service.using_store(connection_store)
                for memory in fixture_memories:
                    connection_store.add_memory(memory)
                prepared = bound_service.prepare_analysis(incident)
                run = build_run(prepared)
                saved = bound_service.persist_analysis(incident, prepared)
                bound_judges = PostgresJudgeSessionRepository.from_connection(connection)
                bound_judges.save_run(run, settings.judge_active_run_limit)
                bound_ledger = PostgresAuthorityLedgerRepository.from_connection(connection)
                initial_workflow = WorkflowCoordinator(
                    PostgresWorkflowRepository.from_connection(connection),
                    bound_ledger,
                ).ensure_for_analysis(
                    tenant_id, saved.incident_id, saved.proposed_action.action_hash, False
                )
                bound_ledger.append_genesis(initial_workflow)
                return run

            run = store.atomic(persist)
        else:
            with authority_lock:
                if judge_repository.active_run_count() >= settings.judge_active_run_limit:
                    raise JudgeRunCapacityError("judge scenario capacity reached")
                for memory in fixture_memories:
                    store.add_memory(memory)
                prepared = service.prepare_analysis(incident)
                run = build_run(prepared)
                saved = service.persist_analysis(incident, prepared)
                judge_repository.save_run(run, settings.judge_active_run_limit)
                cast(InMemoryAuthorityLedgerRepository, ledger_repository).bind_run(
                    tenant_id,
                    saved.incident_id,
                    run.run_id,
                    run.build_sha,
                    run.capability_policy_version,
                )
                initial_workflow = workflows.ensure_for_analysis(
                    tenant_id, saved.incident_id, saved.proposed_action.action_hash, False
                )
                ledger_repository.append_genesis(initial_workflow)

        if not isinstance(authenticator, JudgeSessionAuthenticator):  # pragma: no cover
            raise RuntimeError("judge authenticator unavailable")
        token, csrf, identity = authenticator.create_session(
            "operator",
            run_id=run.run_id,
            tenant_id=run.tenant_id,
            generation=run.generation,
            subject=run.operator_subject,
        )
        return run, token, csrf, identity

    @app.post("/v1/judge/runs", status_code=status.HTTP_201_CREATED)
    async def create_judge_run(request: Request, response: Response) -> dict[str, object]:
        if not isinstance(authenticator, JudgeSessionAuthenticator):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "judge runs are not enabled")
        if request.headers.get("origin") != settings.public_origin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "trusted Origin required")
        if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
            raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "JSON required")
        body = await request.json()
        if body not in ({}, None):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "judge run input must be empty")
        address = request.client.host if request.client is not None else "unknown"
        if not authenticator.consume_launch(address, settings.judge_run_launch_limit):
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "judge run launch rate limit exceeded",
                headers={"Retry-After": str(settings.judge_exchange_window_seconds)},
            )
        try:
            run, token, csrf, identity = allocate_run()
        except JudgeRunCapacityError as error:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "judge scenario capacity reached; retry after an active run expires",
                headers={"Retry-After": "60"},
            ) from error
        set_role_cookie(response, "operator", token)
        return {
            "run": run_payload(run),
            "csrf_token": csrf,
            "identity": {
                "subject": identity.subject,
                "roles": sorted(identity.roles),
                "auth_method": identity.auth_method,
            },
        }

    def current_run(identity: Principal) -> JudgeRun:
        if not isinstance(authenticator, JudgeSessionAuthenticator):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "judge runs are not enabled")
        if identity.run_id is None:  # pragma: no cover - judge sessions are schema-bound to runs
            raise HTTPException(status.HTTP_409_CONFLICT, "session is not bound to a judge run")
        run = judge_repository.get_run(identity.run_id)
        if (  # pragma: no cover - authenticator already enforces the same run binding
            run is None
            or run.tenant_id != identity.tenant_id
            or run.generation != identity.session_generation
            or run.status != "active"
        ):
            raise HTTPException(status.HTTP_409_CONFLICT, "judge run is no longer active")
        return run

    def run_memory(run: JudgeRun) -> Memory | None:
        if isinstance(store, InMemoryStore):
            return store.outcome_memories.get((run.tenant_id, run.source_incident_id))
        if isinstance(store, PostgresStore):
            with store.pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """SELECT id FROM memories WHERE tenant_id=%s AND source_incident_id=%s
                    ORDER BY created_at DESC, id DESC LIMIT 1""",
                    (run.tenant_id, run.source_incident_id),
                )
                row = cursor.fetchone()
            return (
                store.get_memory(UUID(str(dict(row)["id"])), run.tenant_id)
                if row is not None
                else None
            )
        return None  # pragma: no cover - create_app owns the supported store variants

    def webmcp_agent_subject(run: JudgeRun) -> str:
        """Return server-derived agent attribution, never the operator's cookie subject."""
        return f"webmcp_agent_{run.run_id.hex}"

    withheld_reasons = {
        "inspect_incident": "WORKFLOW_INACTIVE",
        "propose_mitigation": "PROPOSAL_NOT_AVAILABLE_IN_CURRENT_STATE",
        "record_postcheck_assessment": "VERIFIED_OBSERVATION_NOT_READY",
        "recall_reviewed_memory": "CERTIFIED_COMPATIBLE_MEMORY_NOT_AVAILABLE",
    }

    def webmcp_manifest(run: JudgeRun, snapshot: WorkflowSnapshot) -> WebMcpManifest:
        memory = run_memory(run)
        available = list(snapshot.available_tools)
        recall_eligible = bool(
            memory
            and memory.state is MemoryState.ACTIVE
            and memory.valid
            and memory.service == "checkout"
            and version_compatibility(
                memory.service_version,
                "v2.4.1",
                memory.compatibility_policy,
            )
            == 1.0
            and memory.outcome_semantics is not MemoryOutcome.INCONCLUSIVE
            and (memory.expires_at is None or memory.expires_at > datetime.now(UTC))
            and memory.superseded_at is None
            and memory.revoked_at is None
        )
        if "recall_reviewed_memory" in available and not recall_eligible:
            available.remove("recall_reviewed_memory")
        if not snapshot.active:
            available = []
        binding = {
            "run_id": str(run.run_id),
            "run_generation": str(run.generation),
            "workflow_id": str(snapshot.workflow_id),
            "epoch": str(snapshot.epoch),
            "memory_governance_version": str(memory.governance_version if memory else 0),
            "capability_policy_version": run.capability_policy_version,
        }
        etag = f'"{content_digest("recallops-webmcp-manifest-v1", binding)}"'
        return WebMcpManifest(
            run_id=run.run_id,
            run_generation=run.generation,
            workflow_id=snapshot.workflow_id,
            state=snapshot.state,
            epoch=snapshot.epoch,
            authority_owner="NONE" if not snapshot.active else authority_owner(snapshot.state),
            available_tools=tuple(available),
            withheld_tools=tuple(
                WithheldTool(name=name, reason_code=withheld_reasons[name])
                for name in WEBMCP_TOOL_NAMES
                if name not in available
            ),
            protected_operations=PROTECTED_OPERATIONS,
            memory_governance_version=memory.governance_version if memory else 0,
            capability_policy_version=run.capability_policy_version,
            build_sha=run.build_sha,
            etag=etag,
        )

    def require_webmcp_mutation(request: Request) -> None:
        if request.headers.get("origin") != settings.public_origin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "trusted Origin required")
        if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
            raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "JSON required")

    def require_idempotency_key(value: str | None) -> str:
        if value is None or not 16 <= len(value) <= 200:
            raise HTTPException(status.HTTP_428_PRECONDITION_REQUIRED, "Idempotency-Key required")
        return value

    webmcp_memory_results: dict[tuple[UUID, str, str], tuple[str, dict[str, object]]] = {}

    def idempotent_webmcp_mutation(
        run: JudgeRun,
        route: str,
        key: str,
        request_digest: str,
        operation: Callable[[IncidentService, WorkflowCoordinator], dict[str, object]],
    ) -> dict[str, object]:
        if isinstance(store, PostgresStore):

            def transact(bound_store: PostgresStore, connection: object) -> dict[str, object]:
                with cast(Any, connection).cursor() as cursor:
                    cursor.execute(
                        """INSERT INTO webmcp_idempotency
                        (run_id,tenant_id,route,idempotency_key,request_digest)
                        VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                        (run.run_id, run.tenant_id, route, key, request_digest),
                    )
                    cursor.execute(
                        """SELECT request_digest,response_payload FROM webmcp_idempotency
                        WHERE run_id=%s AND route=%s AND idempotency_key=%s FOR UPDATE""",
                        (run.run_id, route, key),
                    )
                    row = cursor.fetchone()
                    if row is None:  # pragma: no cover - insert/select share one transaction
                        raise RuntimeError("idempotency record unavailable")
                    existing = dict(row)
                    if not hmac.compare_digest(str(existing["request_digest"]), request_digest):
                        raise WorkflowConflict("idempotency key is bound to different input")
                    if existing["response_payload"] is not None:
                        return cast(dict[str, object], existing["response_payload"])
                    fault_hook = getattr(app.state, "ledger_fault_hook", None)
                    result = operation(
                        service.using_store(bound_store),
                        WorkflowCoordinator(
                            PostgresWorkflowRepository.from_connection(connection),
                            PostgresAuthorityLedgerRepository.from_connection(
                                connection, fault_hook
                            ),
                            fault_hook,
                        ),
                    )
                    encoded = cast(dict[str, object], jsonable_encoder(result))
                    cursor.execute(
                        """UPDATE webmcp_idempotency SET response_payload=%s::JSONB,
                        completed_at=now() WHERE run_id=%s AND route=%s AND idempotency_key=%s""",
                        (json.dumps(encoded), run.run_id, route, key),
                    )
                    return encoded

            return store.atomic(transact)
        memory_key = (run.run_id, route, key)
        with authority_lock:
            existing = webmcp_memory_results.get(memory_key)
            if existing is not None:
                if not hmac.compare_digest(existing[0], request_digest):
                    raise WorkflowConflict("idempotency key is bound to different input")
                return existing[1]
            result = cast(dict[str, object], jsonable_encoder(operation(service, workflows)))
            webmcp_memory_results[memory_key] = (request_digest, result)
            return result

    @app.get("/v1/operator/run")
    def get_operator_run(identity: AuthenticatedPrincipal) -> dict[str, object]:
        require_role(identity, "operator")
        return run_payload(current_run(identity))

    @app.get("/v1/operator/evidence")
    def get_operator_evidence(identity: AuthenticatedPrincipal) -> dict[str, object]:
        require_role(identity, "operator")
        run = current_run(identity)
        postcheck = service.get_postcheck(run.source_incident_id, run.tenant_id)
        assessment = service.get_postcheck_assessment(run.source_incident_id, run.tenant_id)
        workflow = workflows.get(run.source_incident_id, run.tenant_id)
        observation, verdict = postcheck if postcheck is not None else (None, None)
        memory = run_memory(run)
        return {
            "immutable_observation": observation,
            "agent_assessment": assessment,
            "policy_verdict": verdict,
            "assessment_policy_agree": (
                assessment is not None
                and verdict is not None
                and assessment.classification == verdict.classification
            ),
            "proposal_digest": workflow.proposal_hash if workflow is not None else None,
            "memory": (
                {
                    "id": str(memory.id),
                    "digest": memory.memory_digest,
                    "state": memory.state,
                    "retrievable": memory.state is MemoryState.ACTIVE and memory.valid,
                }
                if memory is not None
                else None
            ),
        }

    @app.get("/v1/evidence/timeline")
    def evidence_timeline(identity: AuthenticatedPrincipal) -> dict[str, object]:
        run = current_run(identity)
        entries = ledger_repository.timeline(run.run_id, run.tenant_id)
        return {
            "run_id": str(run.run_id),
            "ordering": "database recorded_at, then UUID",
            "authority_claim": (
                "Only authority_commit entries are receipt-capable; "
                "supporting_observation entries do not confer authority."
            ),
            "entries": entries,
        }

    @app.get("/v1/evidence/receipt")
    def evidence_receipt(identity: AuthenticatedPrincipal) -> dict[str, object]:
        run = current_run(identity)
        receipt = workflows.receipt_status(run.run_id, run.tenant_id)
        events = ledger_repository.list_events(run.run_id, run.tenant_id)
        target = receipt.target_sequence if receipt is not None else len(events)
        labels = {
            "RUN_GENESIS": "Evidence boundary created",
            "INVESTIGATING_TO_AWAITING_OPERATOR_APPROVAL": "Agent staged exact proposal",
            "AWAITING_OPERATOR_APPROVAL_TO_APPROVED_AWAITING_EXECUTION": (
                "Operator approved exact proposal"
            ),
            "APPROVED_AWAITING_EXECUTION_TO_OBSERVING_POSTCHECK": (
                "Operator applied allowlisted simulation"
            ),
            "OBSERVING_POSTCHECK_TO_POSTCHECK_READY": (
                "System recorded observation and policy verdict"
            ),
            "POSTCHECK_READY_TO_PENDING_REVIEW": ("Agent assessed evidence; memory quarantined"),
            "PENDING_REVIEW_TO_REVIEWED": "Independent reviewer governed reuse",
        }
        chain = [
            {
                "sequence": event.sequence,
                "label": labels.get(event.event_type, event.display_summary),
                "authority_owner": event.actor_role,
                "state": event.state_after,
                "object_type": event.object_type,
                "object_digest": event.object_digest,
                "event_hash": event.event_hash,
            }
            for event in events
            if event.sequence <= target
        ]
        return {
            "receipt": receipt,
            "chain": chain,
            "integrity_scope": (
                "A signed receipt proves integrity of the supplied accepted authority prefix. "
                "It does not prove external truth, physical identity, trusted time, denied-attempt "
                "completeness, or production-remediation safety."
            ),
            "public_bundle_url": (
                f"/public/evidence/{receipt.receipt_id}/authority-bundle.zip"
                if receipt is not None and receipt.public
                else None
            ),
        }

    @app.post("/v1/operator/run/reset", status_code=status.HTTP_201_CREATED)
    def reset_operator_run(
        request: Request,
        response: Response,
        identity: AuthenticatedPrincipal,
        x_csrf_token: str | None = Header(default=None, max_length=200),
    ) -> dict[str, object]:
        require_protected_request(request, identity, x_csrf_token)
        require_role(identity, "operator")
        old_run = current_run(identity)
        old_workflow = workflows.get(old_run.source_incident_id, old_run.tenant_id)
        if old_workflow is None:
            raise HTTPException(status.HTTP_409_CONFLICT, "judge workflow unavailable")

        if isinstance(store, PostgresStore):

            def reset_atomically(bound_store: PostgresStore, connection: object) -> bool:
                del bound_store
                bound_workflows = WorkflowCoordinator(
                    PostgresWorkflowRepository.from_connection(connection),
                    PostgresAuthorityLedgerRepository.from_connection(
                        connection, getattr(app.state, "ledger_fault_hook", None)
                    ),
                    getattr(app.state, "ledger_fault_hook", None),
                )
                changed = PostgresJudgeSessionRepository.from_connection(connection).reset_run(
                    old_run.run_id
                )
                if not changed:
                    return False
                bound_workflows.invalidate(
                    old_run.source_incident_id,
                    old_run.tenant_id,
                    old_workflow.epoch,
                    channel=RequestChannel.UI,
                    actor_subject=identity.subject,
                    role="operator",
                )
                return True

            reset_changed = store.atomic(reset_atomically)
        else:
            with authority_lock:
                reset_changed = judge_repository.reset_run(old_run.run_id)
                if reset_changed:
                    workflows.invalidate(
                        old_run.source_incident_id,
                        old_run.tenant_id,
                        old_workflow.epoch,
                        channel=RequestChannel.UI,
                        actor_subject=identity.subject,
                        role="operator",
                    )
        if not reset_changed:
            raise HTTPException(status.HTTP_409_CONFLICT, "judge run reset already resolved")
        run, token, csrf, _ = allocate_run(old_run.generation + 1)
        set_role_cookie(response, "operator", token)
        return {"run": run_payload(run), "csrf_token": csrf}

    def review_target(run: JudgeRun, purpose: str) -> Memory:
        snapshot = workflows.get(run.source_incident_id, run.tenant_id)
        expected_state = (
            WorkflowState.PENDING_REVIEW if purpose == "initial_review" else WorkflowState.REVIEWED
        )
        if snapshot is None or not snapshot.active or snapshot.state is not expected_state:
            raise HTTPException(status.HTTP_409_CONFLICT, "no reviewable evidence is ready")
        if isinstance(store, InMemoryStore):
            memory = store.outcome_memories.get((run.tenant_id, run.source_incident_id))
        elif isinstance(store, PostgresStore):
            with store.pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """SELECT id FROM memories WHERE tenant_id=%s AND source_incident_id=%s
                    ORDER BY created_at DESC LIMIT 1""",
                    (run.tenant_id, run.source_incident_id),
                )
                row = cursor.fetchone()
            memory = (
                store.get_memory(UUID(str(dict(row)["id"])), run.tenant_id)
                if row is not None
                else None
            )
        else:  # pragma: no cover - create_app constructs one of the supported stores
            memory = None
        if memory is None:
            raise HTTPException(status.HTTP_409_CONFLICT, "no reviewable evidence is ready")
        expected_memory_state = (
            MemoryState.PENDING_REVIEW if purpose == "initial_review" else MemoryState.ACTIVE
        )
        if memory.state is not expected_memory_state:
            raise HTTPException(status.HTTP_409_CONFLICT, "no reviewable evidence is ready")
        if purpose == HandoffPurpose.REVOCATION.value and (
            not memory.valid
            or memory.expires_at is not None
            and memory.expires_at <= datetime.now(UTC)
            or memory.superseded_at is not None
            or memory.revoked_at is not None
        ):
            raise HTTPException(status.HTTP_409_CONFLICT, "no reviewable evidence is ready")
        return memory

    @app.post("/v1/operator/reviewer-handoff", status_code=status.HTTP_201_CREATED)
    def create_reviewer_handoff(
        payload: ReviewerHandoffRequest,
        request: Request,
        identity: AuthenticatedPrincipal,
        x_csrf_token: str | None = Header(default=None, max_length=200),
    ) -> dict[str, object]:
        if not isinstance(authenticator, JudgeSessionAuthenticator):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "judge runs are not enabled")
        require_protected_request(request, identity, x_csrf_token)
        require_role(identity, "operator")
        run = current_run(identity)
        memory = review_target(run, payload.purpose.value)
        memory_digest = cast(str, memory.memory_digest)
        if not hmac.compare_digest(payload.memory_digest, memory_digest):
            raise HTTPException(status.HTTP_409_CONFLICT, "stale or mismatched memory digest")
        code = secrets.token_urlsafe(32)
        handoff = ReviewHandoff(
            code_hash=authenticator.digest(code),
            run_id=run.run_id,
            tenant_id=run.tenant_id,
            workflow_id=run.source_incident_id,
            memory_id=memory.id,
            memory_digest=memory_digest,
            purpose=payload.purpose.value,
            issued_by_subject=identity.subject,
            expires_at=datetime.now(UTC) + timedelta(seconds=settings.judge_handoff_ttl_seconds),
        )
        judge_repository.save_handoff(handoff)
        return {
            "reviewer_url": f"{settings.public_origin}/reviewer#review={code}",
            "expires_at": handoff.expires_at,
            "purpose": handoff.purpose,
        }

    @app.post("/v1/judge/reviewer-exchange")
    async def exchange_reviewer_handoff(request: Request, response: Response) -> dict[str, object]:
        if not isinstance(authenticator, JudgeSessionAuthenticator):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "judge runs are not enabled")
        if request.headers.get("origin") != settings.public_origin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "trusted Origin required")
        if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
            raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "JSON required")
        body = await request.json()
        code = body.get("code") if isinstance(body, dict) else None
        if not isinstance(code, str) or not 32 <= len(code) <= 128:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "review handoff is invalid or expired"
            )
        address = request.client.host if request.client is not None else "unknown"
        if not authenticator.consume_handoff_attempt(address):
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "review handoff exchange rate limit exceeded",
                headers={"Retry-After": str(settings.judge_exchange_window_seconds)},
            )
        handoff = judge_repository.consume_handoff(authenticator.digest(code))
        if handoff is None:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "review handoff is invalid or expired"
            )
        run = judge_repository.get_run(handoff.run_id)
        if run is None or run.status != "active":  # pragma: no cover - atomic consume guards this
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "review handoff is invalid or expired"
            )
        reviewer_subject = f"reviewer_{secrets.token_hex(12)}"
        if reviewer_subject in {  # pragma: no cover
            run.operator_subject,
            handoff.issued_by_subject,
        }:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "review identity unavailable")
        token, csrf, identity = authenticator.create_session(
            "reviewer",
            run_id=run.run_id,
            tenant_id=run.tenant_id,
            generation=run.generation,
            subject=reviewer_subject,
            review_handoff_hash=handoff.code_hash,
        )
        set_role_cookie(response, "reviewer", token)
        return {
            "csrf_token": csrf,
            "identity": {"subject": identity.subject, "roles": sorted(identity.roles)},
            "review": {
                "workflow_id": str(handoff.workflow_id),
                "memory_id": str(handoff.memory_id),
                "memory_digest": handoff.memory_digest,
                "purpose": handoff.purpose,
            },
        }

    def reviewer_scope(
        identity: Principal, expected_purpose: HandoffPurpose | None = None
    ) -> tuple[JudgeRun, ReviewHandoff, Memory]:
        require_role(identity, "reviewer")
        handoff_hash = identity.review_handoff_hash
        if handoff_hash is None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "reviewer handoff authority required")
        handoff = judge_repository.get_handoff(handoff_hash)
        now = datetime.now(UTC)
        if (
            handoff is None
            or handoff.consumed_at is None
            or handoff.revoked_at is not None
            or handoff.expires_at <= now
            or expected_purpose is not None
            and handoff.purpose != expected_purpose.value
        ):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "reviewer handoff is no longer valid")
        run = current_run(identity)
        if handoff.run_id != run.run_id or handoff.tenant_id != run.tenant_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "review evidence not found")
        memory = service.get_memory(handoff.memory_id, run.tenant_id)
        if (
            memory is None
            or memory.source_incident_id != handoff.workflow_id
            or memory.memory_digest is None
            or not hmac.compare_digest(memory.memory_digest, handoff.memory_digest)
        ):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "review evidence not found")
        if identity.subject in {
            run.operator_subject,
            handoff.issued_by_subject,
            memory.observed_by,
        }:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "independent reviewer required")
        return run, handoff, memory

    def require_if_match(request: Request, run: JudgeRun, workflow: WorkflowSnapshot) -> None:
        supplied = request.headers.get("if-match")
        if supplied is None:
            raise HTTPException(status.HTTP_428_PRECONDITION_REQUIRED, "If-Match required")
        expected = f'"{run.generation}:{workflow.epoch}"'
        if not hmac.compare_digest(supplied, expected):
            raise HTTPException(status.HTTP_412_PRECONDITION_FAILED, "stale workflow precondition")

    @app.get("/v1/reviewer/evidence")
    def get_reviewer_evidence(identity: AuthenticatedPrincipal) -> dict[str, object]:
        run, handoff, memory = reviewer_scope(identity)
        postcheck = service.get_postcheck(handoff.workflow_id, run.tenant_id)
        assessment = service.get_postcheck_assessment(handoff.workflow_id, run.tenant_id)
        observation, verdict = postcheck if postcheck is not None else (None, None)
        allowed = (
            ["quarantine", "reject"]
            if memory.outcome_semantics is MemoryOutcome.INCONCLUSIVE
            else ["certify", "quarantine", "reject"]
        )
        review_workflow = workflows.get(handoff.workflow_id, run.tenant_id)
        return {
            "purpose": handoff.purpose,
            "memory": memory.model_dump(mode="json", exclude={"embedding"}),
            "immutable_observation": observation,
            "agent_assessment": assessment,
            "policy_verdict": verdict,
            "assessment_policy_agree": (
                assessment is not None
                and verdict is not None
                and assessment.classification is verdict.classification
            ),
            "allowed_dispositions": allowed if handoff.purpose == "initial_review" else [],
            "precondition": {
                "generation": run.generation,
                "epoch": review_workflow.epoch if review_workflow is not None else None,
            },
        }

    @app.post("/v1/reviewer/disposition")
    def disposition_reviewer_evidence(
        payload: ReviewerDispositionRequest,
        request: Request,
        identity: AuthenticatedPrincipal,
        x_csrf_token: str | None = Header(default=None, max_length=200),
    ) -> dict[str, object]:
        require_protected_request(request, identity, x_csrf_token)
        run, handoff, scoped_memory = reviewer_scope(identity, HandoffPurpose.INITIAL_REVIEW)
        if not hmac.compare_digest(payload.memory_digest, handoff.memory_digest):
            raise HTTPException(status.HTTP_409_CONFLICT, "stale or mismatched memory digest")
        workflow = workflows.get(handoff.workflow_id, run.tenant_id)
        if workflow is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "review workflow not found")
        require_if_match(request, run, workflow)
        actions = {
            "certify": GovernanceAction.CERTIFY,
            "quarantine": GovernanceAction.QUARANTINE,
            "reject": GovernanceAction.REJECT,
        }
        governance = MemoryGovernanceRequest(
            tenant_id=run.tenant_id,
            actor_id=identity.subject,
            action=actions[payload.decision.value],
            reason=payload.note.strip() or payload.reason_code.value,
            reason_code=payload.reason_code,
        )

        def disposition_atomically(
            tx_service: IncidentService, tx_workflows: WorkflowCoordinator
        ) -> object:
            memory = tx_service.get_memory(scoped_memory.id, run.tenant_id)
            if (
                memory is None
                or memory.memory_digest is None
                or not hmac.compare_digest(memory.memory_digest, payload.memory_digest)
                or memory.state is not MemoryState.PENDING_REVIEW
            ):
                raise MemoryGovernanceError("review target is stale or unavailable")
            tx_workflows.validate_transition(
                handoff.workflow_id,
                run.tenant_id,
                workflow.epoch,
                WorkflowState.PENDING_REVIEW,
                channel=RequestChannel.UI,
                actor_subject=identity.subject,
                role="reviewer",
            )
            governed = tx_service.govern_memory(memory.id, governance)
            if governed is None:  # pragma: no cover - row is locked above
                raise MemoryGovernanceError("review target is unavailable")
            review_digest = content_digest(
                "recallops-review-decision-v1",
                {
                    "run_id": str(run.run_id),
                    "generation": str(run.generation),
                    "workflow_id": str(handoff.workflow_id),
                    "memory": payload.memory_digest,
                    "reviewer": identity.subject,
                    "decision": payload.decision.value,
                    "reason_code": payload.reason_code.value,
                    "note": payload.note,
                },
            )
            completed = tx_workflows.transition(
                handoff.workflow_id,
                run.tenant_id,
                workflow.epoch,
                WorkflowState.PENDING_REVIEW,
                WorkflowState.REVIEWED,
                channel=RequestChannel.UI,
                actor_subject=identity.subject,
                role="reviewer",
                reason_code=f"MEMORY_{payload.decision.value.upper()}",
                object_type="review_binding",
                object_id=review_digest,
                object_digest=content_digest(
                    "recallops-review-binding-v1",
                    {
                        "disposition": hashlib.sha256(
                            payload.decision.value.encode("ascii")
                        ).hexdigest(),
                        "memory": payload.memory_digest,
                        "review": review_digest,
                    },
                ),
            )
            receipt_id = tx_workflows.request_receipt(
                run.run_id,
                run.tenant_id,
                receipt_policy_version=settings.receipt_policy_version,
                image_digest=settings.release_image_digest,
                evaluation_version=settings.evaluation_version,
                synthetic=True,
                publish_public=True,
            )
            return {
                "memory": governed,
                "workflow": completed,
                "receipt": {"receipt_id": receipt_id, "status": "pending"},
            }

        try:
            return cast(dict[str, object], authority_transaction(disposition_atomically))
        except (MemoryGovernanceError, WorkflowConflict) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error

    @app.post("/v1/reviewer/revocation")
    def revoke_reviewer_evidence(
        payload: ReviewerRevocationRequest,
        request: Request,
        identity: AuthenticatedPrincipal,
        x_csrf_token: str | None = Header(default=None, max_length=200),
    ) -> dict[str, object]:
        require_protected_request(request, identity, x_csrf_token)
        run, handoff, scoped_memory = reviewer_scope(identity, HandoffPurpose.REVOCATION)
        if not hmac.compare_digest(payload.memory_digest, handoff.memory_digest):
            raise HTTPException(status.HTTP_409_CONFLICT, "stale or mismatched memory digest")
        workflow = workflows.get(handoff.workflow_id, run.tenant_id)
        if workflow is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "review workflow not found")
        require_if_match(request, run, workflow)
        governance = MemoryGovernanceRequest(
            tenant_id=run.tenant_id,
            actor_id=identity.subject,
            action=GovernanceAction.REVOKE,
            reason=payload.note.strip() or payload.reason_code.value,
            reason_code=payload.reason_code,
        )

        def revoke_atomically(
            tx_service: IncidentService, tx_workflows: WorkflowCoordinator
        ) -> object:
            current = tx_workflows.get(handoff.workflow_id, run.tenant_id)
            if (
                current is None
                or not current.active
                or current.state is not WorkflowState.REVIEWED
                or current.epoch != workflow.epoch
            ):
                raise WorkflowConflict("stale workflow state or epoch")
            memory = tx_service.get_memory(scoped_memory.id, run.tenant_id)
            if (
                memory is None
                or memory.memory_digest is None
                or not hmac.compare_digest(memory.memory_digest, payload.memory_digest)
                or memory.state is not MemoryState.ACTIVE
                or not memory.valid
                or memory.expires_at is not None
                and memory.expires_at <= datetime.now(UTC)
            ):
                raise MemoryGovernanceError("revocation target is stale or unavailable")
            governed = tx_service.govern_memory(memory.id, governance)
            if governed is None:  # pragma: no cover - row is locked above
                raise MemoryGovernanceError("revocation target is unavailable")
            return {"memory": governed, "workflow": current}

        try:
            return cast(dict[str, object], authority_transaction(revoke_atomically))
        except (MemoryGovernanceError, WorkflowConflict) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error

    def record_server_activity(
        run: JudgeRun,
        *,
        activity_type: str,
        tool_name: str,
        outcome: str,
        summary: str,
        actor_subject: str,
    ) -> None:
        try:
            ledger_repository.add_activity(
                ActivityObservation(
                    run_id=run.run_id,
                    tenant_id=run.tenant_id,
                    workflow_id=run.source_incident_id,
                    source="webmcp",
                    actor_subject=actor_subject,
                    activity_type=activity_type,
                    tool_name=tool_name,
                    outcome=outcome,
                    display_summary=summary[:240],
                    build_sha=run.build_sha,
                )
            )
        except Exception:
            # Supporting activity is deliberately not an authorization dependency.
            return

    @app.get("/v1/webmcp/capabilities", response_model=WebMcpManifest)
    def webmcp_capabilities(
        request: Request,
        response: Response,
        identity: AuthenticatedPrincipal,
    ) -> object:
        require_role(identity, "agent")
        run = current_run(identity)
        snapshot = workflows.get(run.source_incident_id, run.tenant_id)
        if snapshot is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "workflow not found")
        result = webmcp_manifest(run, snapshot)
        if request.headers.get("if-none-match") == result.etag:
            return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers={"ETag": result.etag})
        response.headers["ETag"] = result.etag
        return result

    @app.get("/v1/webmcp/incident")
    def inspect_webmcp_incident(identity: AuthenticatedPrincipal) -> dict[str, object]:
        require_role(identity, "agent")
        run = current_run(identity)
        incident = service.get_incident(run.source_incident_id, run.tenant_id)
        analysis = service.get_analysis(run.source_incident_id, run.tenant_id)
        snapshot = workflows.get(run.source_incident_id, run.tenant_id)
        if incident is None or analysis is None or snapshot is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
        manifest_value = webmcp_manifest(run, snapshot)
        decisions = {item.memory_id: item for item in analysis.candidate_decisions}
        candidates = []
        for retrieved in analysis.memories[:3]:
            decision = decisions.get(retrieved.memory.id)
            candidates.append(
                {
                    "memory_id": str(retrieved.memory.id),
                    "similarity": round(retrieved.semantic_similarity, 6),
                    "eligible": bool(decision and decision.disposition.value == "selected"),
                    "rejection_codes": [] if decision is None else decision.reasons[:5],
                    "service_version": retrieved.memory.service_version,
                    "outcome_semantics": retrieved.memory.outcome_semantics,
                    "state": retrieved.memory.state,
                }
            )
        candidates.sort(key=lambda item: cast(float, item["similarity"]), reverse=True)
        record_server_activity(
            run,
            activity_type="tool_invoked",
            tool_name="inspect_incident",
            outcome="observed",
            summary="Agent inspected bounded incident evidence",
            actor_subject=webmcp_agent_subject(run),
        )
        return {
            "incident": {
                "service": incident.service,
                "service_version": incident.service_version,
                "symptom": incident.symptom,
                "status": analysis.status,
            },
            "workflow": {"state": snapshot.state, "epoch": snapshot.epoch},
            "authority_owner": manifest_value.authority_owner,
            "available_tools": manifest_value.available_tools,
            "candidates": candidates,
            "trusted_fields": ["workflow", "authority_owner", "available_tools"],
            "untrusted_fields": [
                "incident.service",
                "incident.service_version",
                "incident.symptom",
            ],
            "build_sha": run.build_sha,
            "capability_policy_version": run.capability_policy_version,
        }

    @app.post("/v1/webmcp/proposal", status_code=status.HTTP_201_CREATED)
    def propose_webmcp_mitigation(
        payload: ProposalToolRequest,
        request: Request,
        identity: AuthenticatedPrincipal,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=200),
    ) -> dict[str, object]:
        require_webmcp_mutation(request)
        require_role(identity, "agent")
        run = current_run(identity)
        workflow = workflows.get(run.source_incident_id, run.tenant_id)
        incident = service.get_incident(run.source_incident_id, run.tenant_id)
        analysis = service.get_analysis(run.source_incident_id, run.tenant_id)
        if workflow is None or incident is None or analysis is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
        key = require_idempotency_key(idempotency_key)
        supplied_precondition = request.headers.get("if-match") or ""
        digest = content_digest(
            "recallops-webmcp-proposal-request-v1",
            {
                "run_id": str(run.run_id),
                "generation": str(run.generation),
                "workflow_id": str(run.source_incident_id),
                "precondition": supplied_precondition,
                **payload.model_dump(mode="json"),
            },
        )
        if (payload.service, payload.service_version, payload.symptom) != (
            incident.service,
            incident.service_version,
            incident.symptom,
        ):
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "proposal input does not match run evidence",
            )
        proposal_digest = analysis.proposed_action.action_hash
        if proposal_digest is None or not analysis.proposed_action.requires_approval:
            raise HTTPException(status.HTTP_409_CONFLICT, "bounded proposal is unavailable")

        def stage(
            tx_service: IncidentService, tx_workflows: WorkflowCoordinator
        ) -> dict[str, object]:
            del tx_service
            require_if_match(request, run, workflow)
            staged = tx_workflows.transition(
                run.source_incident_id,
                run.tenant_id,
                workflow.epoch,
                WorkflowState.INVESTIGATING,
                WorkflowState.AWAITING_OPERATOR_APPROVAL,
                channel=RequestChannel.WEBMCP,
                actor_subject=webmcp_agent_subject(run),
                role="agent",
                reason_code="PROPOSAL_STAGED",
                object_type="proposal",
                object_id=str(run.source_incident_id),
                object_digest=proposal_digest,
            )
            return {
                "proposal_id": str(run.source_incident_id),
                "proposal_digest": proposal_digest,
                "diagnosis": analysis.diagnosis[:500],
                "rationale": (payload.rationale or analysis.proposed_action.rationale)[:500],
                "action": {
                    "id": "checkout.reduce_concurrency_and_recycle.v1",
                    "display_name": analysis.proposed_action.name[:80],
                    "risk_class": analysis.proposed_action.risk,
                },
                "expires_at": run.expires_at,
                "requires_human_approval": True,
                "authority_owner": "HUMAN_OPERATOR",
                "epoch": staged.epoch,
            }

        try:
            result = idempotent_webmcp_mutation(run, "proposal", key, digest, stage)
        except WorkflowConflict as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        return result

    @app.post("/v1/webmcp/assessment", status_code=status.HTTP_201_CREATED)
    def assess_webmcp_postcheck(
        payload: AssessmentToolRequest,
        request: Request,
        identity: AuthenticatedPrincipal,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=200),
    ) -> dict[str, object]:
        require_webmcp_mutation(request)
        require_role(identity, "agent")
        run = current_run(identity)
        workflow = workflows.get(run.source_incident_id, run.tenant_id)
        result = service.get_postcheck(run.source_incident_id, run.tenant_id)
        if workflow is None or result is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "verified postcheck not found")
        observation, verdict = result
        if payload.observation_id != observation.id:
            raise HTTPException(status.HTTP_409_CONFLICT, "stale or mismatched observation")
        key = require_idempotency_key(idempotency_key)
        supplied_precondition = request.headers.get("if-match") or ""
        digest = content_digest(
            "recallops-webmcp-assessment-request-v1",
            {
                "run_id": str(run.run_id),
                "generation": str(run.generation),
                "workflow_id": str(run.source_incident_id),
                "precondition": supplied_precondition,
                **payload.model_dump(mode="json"),
            },
        )
        assessment = PostcheckAssessment(
            observation_id=observation.id,
            incident_id=run.source_incident_id,
            tenant_id=run.tenant_id,
            agent_subject=webmcp_agent_subject(run),
            classification=payload.classification,
            rationale=payload.rationale,
            observation_digest=observation.observation_digest,
        )
        try:
            memory = service.prepare_verified_outcome(
                run.source_incident_id, observation, verdict, assessment
            )
        except (DependencyUnavailable, IncidentWorkflowError) as error:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(error)) from error
        if memory is None or memory.memory_digest is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")

        def persist(
            tx_service: IncidentService, tx_workflows: WorkflowCoordinator
        ) -> dict[str, object]:
            require_if_match(request, run, workflow)
            recorded_assessment, recorded_memory = tx_service.persist_verified_outcome(
                assessment, memory
            )
            completed = tx_workflows.transition(
                run.source_incident_id,
                run.tenant_id,
                workflow.epoch,
                WorkflowState.POSTCHECK_READY,
                WorkflowState.PENDING_REVIEW,
                channel=RequestChannel.WEBMCP,
                actor_subject=webmcp_agent_subject(run),
                role="agent",
                reason_code="POSTCHECK_ASSESSMENT_RECORDED",
                object_type="outcome_binding",
                object_id=str(recorded_memory.id),
                object_digest=content_digest(
                    "recallops-outcome-binding-v1",
                    {
                        "assessment": cast(str, recorded_memory.assessment_digest),
                        "memory": cast(str, recorded_memory.memory_digest),
                        "observation": cast(str, recorded_memory.observation_digest),
                        "policy_verdict": cast(str, recorded_memory.verdict_digest),
                    },
                ),
            )
            return {
                "assessment": recorded_assessment,
                "policy_verdict": verdict,
                "assessment_policy_agree": (
                    recorded_assessment.classification is verdict.classification
                ),
                "memory": {
                    "id": str(recorded_memory.id),
                    "digest": recorded_memory.memory_digest,
                    "state": recorded_memory.state,
                    "retrievable": False,
                },
                "independent_review_required": True,
                "authority_owner": "HUMAN_REVIEWER",
                "epoch": completed.epoch,
            }

        try:
            return idempotent_webmcp_mutation(run, "assessment", key, digest, persist)
        except (IncidentWorkflowError, MemoryGovernanceError, WorkflowConflict) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error

    @app.get("/v1/webmcp/recurrence", response_model=RecurrenceView)
    def recall_recurrence(identity: AuthenticatedPrincipal) -> RecurrenceView:
        require_role(identity, "agent")
        run = current_run(identity)
        workflow = workflows.get(run.source_incident_id, run.tenant_id)
        if (
            workflow is None
            or "recall_reviewed_memory" not in webmcp_manifest(run, workflow).available_tools
        ):
            raise HTTPException(status.HTTP_409_CONFLICT, "reviewed recurrence is unavailable")
        recurrence = IncidentCreate(
            tenant_id=run.tenant_id,
            service="checkout",
            service_version="v2.4.1",
            symptom="checkout-latency-43: compatible recurrence of elevated p95 latency",
            idempotency_key=f"recurrence-{run.run_id.hex}",
        )
        result = service.recurrence_view(recurrence)
        record_server_activity(
            run,
            activity_type="tool_invoked",
            tool_name="recall_reviewed_memory",
            outcome="observed",
            summary="Agent evaluated immutable compatible recurrence",
            actor_subject=webmcp_agent_subject(run),
        )
        return result

    @app.post("/v1/webmcp/activity", status_code=status.HTTP_202_ACCEPTED)
    def record_webmcp_activity(
        payload: ActivityBatch,
        request: Request,
        identity: AuthenticatedPrincipal,
    ) -> dict[str, int]:
        require_webmcp_mutation(request)
        require_role(identity, "agent")
        run = current_run(identity)
        client_hash = hashlib.sha256(payload.client_instance_id.encode()).hexdigest()
        if not judge_repository.consume_attempt(f"activity:{run.run_id}:{client_hash}", 120, 60):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "activity rate limit exceeded")
        for item in payload.items:
            ledger_repository.add_activity(
                ActivityObservation(
                    run_id=run.run_id,
                    tenant_id=run.tenant_id,
                    workflow_id=run.source_incident_id,
                    source="browser",
                    actor_subject="browser-client",
                    activity_type=item.activity_type,
                    tool_name=item.tool_name,
                    outcome=item.outcome,
                    display_summary=(
                        f"Browser reports {item.tool_name} {item.activity_type.replace('_', ' ')}"
                    )[:240],
                    build_sha=run.build_sha,
                    client_instance_id_hash=client_hash,
                )
            )
        return {"accepted": len(payload.items)}

    def channel(value: str | None) -> RequestChannel:
        try:
            return RequestChannel(value or RequestChannel.UI)
        except ValueError as error:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid request channel") from error

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "alive"}

    @app.get("/ready")
    def ready(response: Response) -> dict[str, str]:
        try:
            available = store.ready()
        except Exception:  # readiness must not disclose database or credential details
            available = False
        if not available:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return {"status": "not_ready"}
        return {"status": "ready"}

    @app.get("/v1/system/status")
    def system_status() -> dict[str, str | bool | None]:
        return {
            "build_sha": os.getenv("RECALLOPS_BUILD_SHA"),
            "store": settings.store,
            "reasoning_provider": settings.reasoning_provider,
            "reasoning_model": (
                settings.bedrock_model_id if settings.reasoning_provider == "bedrock" else None
            ),
            "embedding_provider": settings.embedding_provider,
            "embedding_model": embedder.model,
            "embedding_space": embedder.space_id,
            "evidence_archive_configured": bool(settings.evidence_bucket),
            "auth_mode": settings.auth_mode,
            "bedrock_runtime_verified": None,
        }

    @app.get("/v1/evaluation", response_model=EvaluationReport)
    def evaluation_report() -> EvaluationReport:
        return evaluate(load_dataset(Path("evaluation/memory_cases.json")))

    @app.get("/v1/release", response_model=PublicReleaseStatus)
    def release_status() -> PublicReleaseStatus:
        return release_status_service.current()

    @app.get("/v1/config")
    def public_config() -> dict[str, str | bool | None]:
        return {
            "auth_required": settings.auth_mode == "oidc",
            "auth_mode": settings.auth_mode,
            "authorization_url": settings.oidc_authorization_url,
            "token_url": settings.oidc_token_url,
            "logout_url": settings.oidc_logout_url,
            "client_id": settings.oidc_audience,
            "redirect_url": settings.oidc_redirect_url,
        }

    @app.get("/v1/me")
    def current_identity(identity: AuthenticatedPrincipal) -> dict[str, object]:
        return {
            "subject": identity.subject,
            "tenant_id": identity.tenant_id,
            "roles": sorted(identity.roles),
        }

    @app.post(
        "/v1/incidents",
        response_model=IncidentAnalysis,
        response_model_exclude={"memories": {"__all__": {"memory": {"embedding"}}}},
        status_code=status.HTTP_201_CREATED,
    )
    def analyze(
        payload: IncidentCreate,
        identity: AuthenticatedPrincipal,
        x_recallops_channel: str | None = Header(default=None, max_length=20),
    ) -> IncidentAnalysis:
        if payload.tenant_id != identity.tenant_id:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "identity and payload tenant differ")
        request_channel = channel(x_recallops_channel)
        if request_channel is RequestChannel.WEBMCP and "agent" not in identity.roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "agent role required for WebMCP")
        prepared = service.prepare_analysis(payload)

        def persist_proposal(
            tx_service: IncidentService, tx_workflows: WorkflowCoordinator
        ) -> object:
            result = tx_service.persist_analysis(payload, prepared)
            tx_workflows.ensure_for_analysis(
                identity.tenant_id,
                result.incident_id,
                result.proposed_action.action_hash,
                result.proposed_action.requires_approval,
            )
            return result

        return cast(IncidentAnalysis, authority_transaction(persist_proposal))

    @app.get(
        "/v1/incidents/{incident_id}",
        response_model=IncidentAnalysis,
        response_model_exclude={"memories": {"__all__": {"memory": {"embedding"}}}},
    )
    def get_incident(incident_id: UUID, identity: AuthenticatedPrincipal) -> IncidentAnalysis:
        result = store.get_analysis(incident_id, identity.tenant_id)
        if result is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
        return result

    @app.get("/v1/incidents/{incident_id}/capabilities")
    def capabilities(incident_id: UUID, identity: AuthenticatedPrincipal) -> object:
        result = workflows.capability_manifest(incident_id, identity.tenant_id)
        if result is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "workflow not found")
        return result

    @app.post("/v1/incidents/{incident_id}/approval")
    def approve(
        incident_id: UUID,
        payload: ApprovalRequest,
        identity: AuthenticatedPrincipal,
        request: Request,
        x_workflow_epoch: int | None = Header(default=None, ge=1),
        x_recallops_channel: str | None = Header(default=None, max_length=20),
        x_csrf_token: str | None = Header(default=None, max_length=200),
    ) -> dict[str, object]:
        require_protected_request(request, identity, x_csrf_token)
        require_role(identity, "operator")
        if payload.tenant_id != identity.tenant_id or payload.actor_id != identity.subject:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "identity and payload actor differ")
        if channel(x_recallops_channel) is not RequestChannel.UI:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "protected transition is not authorized through WebMCP",
            )
        if workflows.get(incident_id, identity.tenant_id) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "incident or workflow not found")
        if x_workflow_epoch is None:
            raise HTTPException(status.HTTP_428_PRECONDITION_REQUIRED, "X-Workflow-Epoch required")

        def approve_atomically(
            tx_service: IncidentService, tx_workflows: WorkflowCoordinator
        ) -> object:
            tx_workflows.validate_transition(
                incident_id,
                identity.tenant_id,
                x_workflow_epoch,
                WorkflowState.AWAITING_OPERATOR_APPROVAL,
                channel=RequestChannel.UI,
                actor_subject=identity.subject,
                role="operator",
            )
            recorded = tx_service.decide_approval(incident_id, payload)
            if not recorded:
                raise LookupError("incident not found or already decided")
            workflow = tx_workflows.transition(
                incident_id,
                identity.tenant_id,
                x_workflow_epoch,
                WorkflowState.AWAITING_OPERATOR_APPROVAL,
                WorkflowState.APPROVED_AWAITING_EXECUTION
                if payload.approved
                else WorkflowState.INVESTIGATING,
                channel=RequestChannel.UI,
                actor_subject=identity.subject,
                role="operator",
                reason_code="PROPOSAL_APPROVED" if payload.approved else "PROPOSAL_REJECTED",
                object_type="proposal",
                object_id=str(incident_id),
                object_digest=payload.proposal_hash,
            )
            return {"recorded": True, "workflow": workflow}

        try:
            return cast(dict[str, object], authority_transaction(approve_atomically))
        except (IncidentWorkflowError, WorkflowConflict) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        except LookupError as error:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(error)) from error

    @app.post("/v1/incidents/{incident_id}/sandbox-execution", status_code=status.HTTP_201_CREATED)
    def apply_sandbox_mitigation(
        incident_id: UUID,
        payload: SandboxExecutionRequest,
        identity: AuthenticatedPrincipal,
        request: Request,
        x_workflow_epoch: int | None = Header(default=None, ge=1),
        x_recallops_channel: str | None = Header(default=None, max_length=20),
        x_csrf_token: str | None = Header(default=None, max_length=200),
    ) -> dict[str, object]:
        require_protected_request(request, identity, x_csrf_token)
        require_role(identity, "operator")
        if payload.tenant_id != identity.tenant_id or payload.actor_id != identity.subject:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "identity and payload actor differ")
        if channel(x_recallops_channel) is not RequestChannel.UI:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "protected transition is not authorized through WebMCP",
            )
        if x_workflow_epoch is None:
            raise HTTPException(status.HTTP_428_PRECONDITION_REQUIRED, "X-Workflow-Epoch required")
        analysis = store.get_analysis(incident_id, identity.tenant_id)
        if analysis is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
        try:
            prepared_execution = checkout_sandbox.prepare_execution(incident_id, analysis, payload)
        except SandboxPolicyError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error

        def execute_sandbox_atomically(
            tx_service: IncidentService, tx_workflows: WorkflowCoordinator
        ) -> object:
            current = tx_workflows.validate_transition(
                incident_id,
                identity.tenant_id,
                x_workflow_epoch,
                WorkflowState.APPROVED_AWAITING_EXECUTION,
                channel=RequestChannel.UI,
                actor_subject=identity.subject,
                role="operator",
            )
            approval = tx_service.get_approval(incident_id, identity.tenant_id)
            if (
                current.proposal_hash != payload.proposal_hash
                or approval is None
                or not approval.approved
                or approval.proposal_hash != payload.proposal_hash
            ):
                raise IncidentWorkflowError("approval is not bound to this proposal")
            execution = tx_service.persist_sandbox_execution(prepared_execution)
            workflow = tx_workflows.transition(
                incident_id,
                identity.tenant_id,
                x_workflow_epoch,
                WorkflowState.APPROVED_AWAITING_EXECUTION,
                WorkflowState.OBSERVING_POSTCHECK,
                channel=RequestChannel.UI,
                actor_subject=identity.subject,
                role="operator",
                reason_code="SANDBOX_EXECUTION_APPLIED",
                object_type="execution_binding",
                object_id=str(execution.id),
                object_digest=content_digest(
                    "recallops-execution-binding-v1",
                    {
                        "execution": execution.execution_digest,
                        "proposal": execution.proposal_hash,
                    },
                ),
            )
            return execution, workflow

        try:
            execution, observing = cast(
                tuple[SandboxExecution, WorkflowSnapshot],
                authority_transaction(execute_sandbox_atomically),
            )
        except (IncidentWorkflowError, MemoryGovernanceError, WorkflowConflict) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error

        try:
            observation = observation_provider.collect(execution)
        except DependencyUnavailable as error:

            def mark_unavailable(
                tx_service: IncidentService, tx_workflows: WorkflowCoordinator
            ) -> object:
                del tx_service
                return tx_workflows.transition(
                    incident_id,
                    identity.tenant_id,
                    observing.epoch,
                    WorkflowState.OBSERVING_POSTCHECK,
                    WorkflowState.POSTCHECK_UNAVAILABLE,
                    channel=RequestChannel.SYSTEM,
                    actor_subject="recallops-observer",
                    role="system",
                )

            try:
                authority_transaction(mark_unavailable)
            except WorkflowConflict as conflict:
                raise HTTPException(status.HTTP_409_CONFLICT, str(conflict)) from conflict
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                f"{error.dependency} unavailable; no observation or memory was created",
                headers={"Retry-After": "30"},
            ) from error

        verdict = evaluate_observation(observation)

        def record_observation_atomically(
            tx_service: IncidentService, tx_workflows: WorkflowCoordinator
        ) -> object:
            tx_workflows.validate_transition(
                incident_id,
                identity.tenant_id,
                observing.epoch,
                WorkflowState.OBSERVING_POSTCHECK,
                channel=RequestChannel.SYSTEM,
                actor_subject="recallops-observer",
                role="system",
            )
            recorded_observation, recorded_verdict = tx_service.persist_postcheck(
                observation, verdict
            )
            workflow = tx_workflows.transition(
                incident_id,
                identity.tenant_id,
                observing.epoch,
                WorkflowState.OBSERVING_POSTCHECK,
                WorkflowState.POSTCHECK_READY,
                channel=RequestChannel.SYSTEM,
                actor_subject="recallops-observer",
                role="system",
                reason_code="VERIFIED_OBSERVATION_RECORDED",
                object_type="observation_binding",
                object_id=str(recorded_observation.id),
                object_digest=content_digest(
                    "recallops-observation-binding-v1",
                    {
                        "execution": recorded_observation.execution_digest,
                        "observation": recorded_observation.observation_digest,
                        "policy_verdict": policy_verdict_digest(recorded_verdict),
                    },
                ),
            )
            return {
                "execution": execution,
                "observation": recorded_observation,
                "policy_verdict": recorded_verdict,
                "workflow": workflow,
            }

        try:
            return cast(dict[str, object], authority_transaction(record_observation_atomically))
        except (MemoryGovernanceError, WorkflowConflict) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error

    @app.post("/v1/incidents/{incident_id}/postcheck-retry")
    def retry_postcheck(
        incident_id: UUID,
        payload: PostcheckRetryRequest,
        identity: AuthenticatedPrincipal,
        request: Request,
        x_workflow_epoch: int | None = Header(default=None, ge=1),
        x_recallops_channel: str | None = Header(default=None, max_length=20),
        x_csrf_token: str | None = Header(default=None, max_length=200),
    ) -> dict[str, object]:
        require_protected_request(request, identity, x_csrf_token)
        require_role(identity, "operator")
        if payload.tenant_id != identity.tenant_id or payload.actor_id != identity.subject:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "identity and payload actor differ")
        if channel(x_recallops_channel) is not RequestChannel.UI:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "protected transition is not authorized through WebMCP",
            )
        if x_workflow_epoch is None:
            raise HTTPException(status.HTTP_428_PRECONDITION_REQUIRED, "X-Workflow-Epoch required")

        def start_retry_atomically(
            tx_service: IncidentService, tx_workflows: WorkflowCoordinator
        ) -> object:
            tx_workflows.validate_transition(
                incident_id,
                identity.tenant_id,
                x_workflow_epoch,
                WorkflowState.POSTCHECK_UNAVAILABLE,
                channel=RequestChannel.UI,
                actor_subject=identity.subject,
                role="operator",
            )
            execution = tx_service.get_sandbox_execution(incident_id, identity.tenant_id)
            if execution is None:
                raise LookupError("sandbox execution not found")
            workflow = tx_workflows.transition(
                incident_id,
                identity.tenant_id,
                x_workflow_epoch,
                WorkflowState.POSTCHECK_UNAVAILABLE,
                WorkflowState.OBSERVING_POSTCHECK,
                channel=RequestChannel.UI,
                actor_subject=identity.subject,
                role="operator",
            )
            return execution, workflow

        try:
            execution, observing = cast(
                tuple[SandboxExecution, WorkflowSnapshot],
                authority_transaction(start_retry_atomically),
            )
        except WorkflowConflict as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        except LookupError as error:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(error)) from error

        try:
            observation = observation_provider.collect(execution)
        except DependencyUnavailable as error:

            def retry_unavailable(
                tx_service: IncidentService, tx_workflows: WorkflowCoordinator
            ) -> object:
                del tx_service
                return tx_workflows.transition(
                    incident_id,
                    identity.tenant_id,
                    observing.epoch,
                    WorkflowState.OBSERVING_POSTCHECK,
                    WorkflowState.POSTCHECK_UNAVAILABLE,
                    channel=RequestChannel.SYSTEM,
                    actor_subject="recallops-observer",
                    role="system",
                )

            try:
                authority_transaction(retry_unavailable)
            except WorkflowConflict as conflict:
                raise HTTPException(status.HTTP_409_CONFLICT, str(conflict)) from conflict
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                f"{error.dependency} unavailable; no observation or memory was created",
                headers={"Retry-After": "30"},
            ) from error

        verdict = evaluate_observation(observation)

        def complete_retry_atomically(
            tx_service: IncidentService, tx_workflows: WorkflowCoordinator
        ) -> object:
            tx_workflows.validate_transition(
                incident_id,
                identity.tenant_id,
                observing.epoch,
                WorkflowState.OBSERVING_POSTCHECK,
                channel=RequestChannel.SYSTEM,
                actor_subject="recallops-observer",
                role="system",
            )
            recorded_observation, recorded_verdict = tx_service.persist_postcheck(
                observation, verdict
            )
            workflow = tx_workflows.transition(
                incident_id,
                identity.tenant_id,
                observing.epoch,
                WorkflowState.OBSERVING_POSTCHECK,
                WorkflowState.POSTCHECK_READY,
                channel=RequestChannel.SYSTEM,
                actor_subject="recallops-observer",
                role="system",
                reason_code="VERIFIED_OBSERVATION_RECORDED",
                object_type="observation_binding",
                object_id=str(recorded_observation.id),
                object_digest=content_digest(
                    "recallops-observation-binding-v1",
                    {
                        "execution": recorded_observation.execution_digest,
                        "observation": recorded_observation.observation_digest,
                        "policy_verdict": policy_verdict_digest(recorded_verdict),
                    },
                ),
            )
            return {
                "execution": execution,
                "observation": recorded_observation,
                "policy_verdict": recorded_verdict,
                "workflow": workflow,
            }

        try:
            return cast(dict[str, object], authority_transaction(complete_retry_atomically))
        except (MemoryGovernanceError, WorkflowConflict) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error

    @app.get("/v1/incidents/{incident_id}/postcheck")
    def get_postcheck(incident_id: UUID, identity: AuthenticatedPrincipal) -> dict[str, object]:
        result = service.get_postcheck(incident_id, identity.tenant_id)
        if result is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "postcheck not found")
        observation, verdict = result
        return {"observation": observation, "policy_verdict": verdict}

    @app.post("/v1/incidents/{incident_id}/postcheck-assessment", status_code=201)
    def record_postcheck_assessment(
        incident_id: UUID,
        payload: PostcheckAssessmentRequest,
        identity: AuthenticatedPrincipal,
        x_workflow_epoch: int | None = Header(default=None, ge=1),
        x_recallops_channel: str | None = Header(default=None, max_length=20),
    ) -> dict[str, object]:
        require_role(identity, "agent")
        if channel(x_recallops_channel) is not RequestChannel.WEBMCP:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "postcheck assessment is authorized only through WebMCP",
            )
        if x_workflow_epoch is None:
            raise HTTPException(status.HTTP_428_PRECONDITION_REQUIRED, "X-Workflow-Epoch required")
        result = service.get_postcheck(incident_id, identity.tenant_id)
        if result is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "postcheck not found")
        observation, verdict = result
        if payload.observation_id != observation.id:
            raise HTTPException(status.HTTP_409_CONFLICT, "stale or mismatched observation")
        assessment = PostcheckAssessment(
            observation_id=observation.id,
            incident_id=incident_id,
            tenant_id=identity.tenant_id,
            agent_subject=identity.subject,
            classification=payload.classification,
            rationale=payload.rationale,
            observation_digest=observation.observation_digest,
        )
        try:
            memory = service.prepare_verified_outcome(incident_id, observation, verdict, assessment)
        except DependencyUnavailable as error:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                f"{error.dependency} unavailable; assessment and memory were not persisted",
                headers={"Retry-After": "30"},
            ) from error
        except IncidentWorkflowError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        if memory is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")

        def assess_atomically(
            tx_service: IncidentService, tx_workflows: WorkflowCoordinator
        ) -> object:
            tx_workflows.validate_transition(
                incident_id,
                identity.tenant_id,
                x_workflow_epoch,
                WorkflowState.POSTCHECK_READY,
                channel=RequestChannel.WEBMCP,
                actor_subject=identity.subject,
                role="agent",
            )
            recorded_assessment, recorded_memory = tx_service.persist_verified_outcome(
                assessment, memory
            )
            workflow = tx_workflows.transition(
                incident_id,
                identity.tenant_id,
                x_workflow_epoch,
                WorkflowState.POSTCHECK_READY,
                WorkflowState.PENDING_REVIEW,
                channel=RequestChannel.WEBMCP,
                actor_subject=identity.subject,
                role="agent",
            )
            return {
                "assessment": recorded_assessment,
                "policy_verdict": verdict,
                "memory": recorded_memory,
                "workflow": workflow,
            }

        try:
            return cast(dict[str, object], authority_transaction(assess_atomically))
        except (IncidentWorkflowError, MemoryGovernanceError, WorkflowConflict) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error

    @app.post(
        "/v1/incidents/{incident_id}/execution",
        response_model=ExecutionAttestation,
        status_code=status.HTTP_201_CREATED,
    )
    def attest_execution(
        incident_id: UUID,
        payload: ExecutionAttestationRequest,
        identity: AuthenticatedPrincipal,
        request: Request,
        x_workflow_epoch: int | None = Header(default=None, ge=1),
        x_recallops_channel: str | None = Header(default=None, max_length=20),
        x_csrf_token: str | None = Header(default=None, max_length=200),
    ) -> ExecutionAttestation:
        if settings.auth_mode == "judge":
            raise HTTPException(
                status.HTTP_410_GONE,
                "manual execution attestation is disabled in the judge workflow",
            )
        require_protected_request(request, identity, x_csrf_token)
        require_role(identity, "operator")
        if payload.tenant_id != identity.tenant_id or payload.actor_id != identity.subject:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "identity and payload actor differ")
        if channel(x_recallops_channel) is not RequestChannel.UI:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "protected transition is not authorized through WebMCP",
            )
        if x_workflow_epoch is None:
            raise HTTPException(status.HTTP_428_PRECONDITION_REQUIRED, "X-Workflow-Epoch required")
        try:
            prepared_execution = service.prepare_execution(incident_id, payload)
        except DependencyUnavailable as error:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                f"{error.dependency} unavailable; execution was not attested",
                headers={"Retry-After": "30"},
            ) from error
        except IncidentWorkflowError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        if prepared_execution is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")

        def execute_atomically(
            tx_service: IncidentService, tx_workflows: WorkflowCoordinator
        ) -> object:
            current = tx_workflows.get(incident_id, identity.tenant_id)
            if current is None:
                raise LookupError("incident not found")
            if current.state not in {
                WorkflowState.INVESTIGATING,
                WorkflowState.APPROVED_AWAITING_EXECUTION,
            }:
                raise WorkflowConflict("execution is unavailable in this state")
            tx_workflows.validate_transition(
                incident_id,
                identity.tenant_id,
                x_workflow_epoch,
                current.state,
                channel=RequestChannel.UI,
                actor_subject=identity.subject,
                role="operator",
                allow_legacy_ui=True,
            )
            execution = tx_service.persist_execution(prepared_execution)
            tx_workflows.transition(
                incident_id,
                identity.tenant_id,
                x_workflow_epoch,
                current.state,
                WorkflowState.OBSERVING_POSTCHECK,
                channel=RequestChannel.UI,
                actor_subject=identity.subject,
                role="operator",
                allow_legacy_ui=True,
            )
            return execution

        try:
            return cast(ExecutionAttestation, authority_transaction(execute_atomically))
        except (IncidentWorkflowError, WorkflowConflict) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        except LookupError as error:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(error)) from error

    @app.post(
        "/v1/incidents/{incident_id}/outcome",
        response_model=Memory,
        response_model_exclude={"embedding"},
        status_code=status.HTTP_201_CREATED,
    )
    def observe_outcome(
        incident_id: UUID,
        payload: OutcomeObservation,
        identity: AuthenticatedPrincipal,
        request: Request,
        x_workflow_epoch: int | None = Header(default=None, ge=1),
        x_recallops_channel: str | None = Header(default=None, max_length=20),
        x_csrf_token: str | None = Header(default=None, max_length=200),
    ) -> Memory:
        if settings.auth_mode == "judge":
            raise HTTPException(
                status.HTTP_410_GONE,
                "operator-supplied outcomes are disabled in the judge workflow",
            )
        require_protected_request(request, identity, x_csrf_token)
        require_role(identity, "operator")
        if payload.tenant_id != identity.tenant_id or payload.actor_id != identity.subject:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "identity and payload actor differ")
        if channel(x_recallops_channel) is not RequestChannel.UI:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "protected transition is not authorized through WebMCP",
            )
        if workflows.get(incident_id, identity.tenant_id) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "incident or workflow not found")
        if x_workflow_epoch is None:
            raise HTTPException(status.HTTP_428_PRECONDITION_REQUIRED, "X-Workflow-Epoch required")
        try:
            prepared_memory = service.prepare_outcome(incident_id, payload)
        except DependencyUnavailable as error:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                f"{error.dependency} unavailable; outcome was not persisted",
                headers={"Retry-After": "30"},
            ) from error
        except IncidentWorkflowError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        if prepared_memory is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")

        def outcome_atomically(
            tx_service: IncidentService, tx_workflows: WorkflowCoordinator
        ) -> object:
            tx_workflows.validate_transition(
                incident_id,
                identity.tenant_id,
                x_workflow_epoch,
                WorkflowState.OBSERVING_POSTCHECK,
                channel=RequestChannel.SYSTEM,
                actor_subject="recallops-legacy-observer",
                role="system",
            )
            memory = tx_service.persist_outcome(prepared_memory)
            tx_workflows.transition(
                incident_id,
                identity.tenant_id,
                x_workflow_epoch,
                WorkflowState.OBSERVING_POSTCHECK,
                WorkflowState.PENDING_REVIEW,
                channel=RequestChannel.SYSTEM,
                actor_subject="recallops-legacy-observer",
                role="system",
            )
            return memory

        try:
            return cast(Memory, authority_transaction(outcome_atomically))
        except (IncidentWorkflowError, WorkflowConflict) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        except LookupError as error:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(error)) from error

    @app.post(
        "/v1/memories/{memory_id}/governance",
        response_model=Memory,
        response_model_exclude={"embedding"},
    )
    def govern_memory(
        memory_id: UUID,
        payload: MemoryGovernanceRequest,
        identity: AuthenticatedPrincipal,
        request: Request,
        x_workflow_epoch: int | None = Header(default=None, ge=1),
        x_recallops_channel: str | None = Header(default=None, max_length=20),
        x_csrf_token: str | None = Header(default=None, max_length=200),
    ) -> Memory:
        if settings.auth_mode == "judge":
            raise HTTPException(
                status.HTTP_410_GONE,
                "legacy memory governance is disabled in the judge workflow",
            )
        require_protected_request(request, identity, x_csrf_token)
        require_role(identity, "reviewer")
        if payload.tenant_id != identity.tenant_id or payload.actor_id != identity.subject:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "identity and payload actor differ")
        if channel(x_recallops_channel) is not RequestChannel.UI:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "protected transition is not authorized through WebMCP",
            )

        def govern_atomically(
            tx_service: IncidentService, tx_workflows: WorkflowCoordinator
        ) -> object:
            source = tx_service.get_memory(memory_id, identity.tenant_id)
            source_incident_id = source.source_incident_id if source is not None else None
            managed = (
                source_incident_id is not None
                and tx_workflows.get(source_incident_id, identity.tenant_id) is not None
            )
            if managed:
                if x_workflow_epoch is None:
                    raise PermissionError("X-Workflow-Epoch required")
                tx_workflows.validate_transition(
                    cast(UUID, source_incident_id),
                    identity.tenant_id,
                    x_workflow_epoch,
                    WorkflowState.PENDING_REVIEW,
                    channel=RequestChannel.UI,
                    actor_subject=identity.subject,
                    role="reviewer",
                )
            memory = tx_service.govern_memory(memory_id, payload)
            if memory is None:
                raise LookupError("memory not found")
            if managed:
                tx_workflows.transition(
                    cast(UUID, source_incident_id),
                    identity.tenant_id,
                    cast(int, x_workflow_epoch),
                    WorkflowState.PENDING_REVIEW,
                    WorkflowState.REVIEWED,
                    channel=RequestChannel.UI,
                    actor_subject=identity.subject,
                    role="reviewer",
                )
            return memory

        try:
            return cast(Memory, authority_transaction(govern_atomically))
        except (MemoryGovernanceError, WorkflowConflict) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        except PermissionError as error:
            raise HTTPException(status.HTTP_428_PRECONDITION_REQUIRED, str(error)) from error
        except LookupError as error:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(error)) from error

    @app.post("/v1/incidents/{incident_id}/reset")
    def reset_workflow(
        incident_id: UUID,
        identity: AuthenticatedPrincipal,
        request: Request,
        x_workflow_epoch: int = Header(ge=1),
        x_recallops_channel: str | None = Header(default=None, max_length=20),
        x_csrf_token: str | None = Header(default=None, max_length=200),
    ) -> object:
        require_protected_request(request, identity, x_csrf_token)
        require_role(identity, "operator")
        request_channel = channel(x_recallops_channel)
        if request_channel is not RequestChannel.UI:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "reset is not authorized through WebMCP",
            )
        try:

            def invalidate_atomically(
                tx_service: IncidentService, tx_workflows: WorkflowCoordinator
            ) -> object:
                del tx_service
                return tx_workflows.invalidate(
                    incident_id,
                    identity.tenant_id,
                    x_workflow_epoch,
                    channel=request_channel,
                    actor_subject=identity.subject,
                    role="operator",
                )

            return authority_transaction(invalidate_atomically)
        except WorkflowConflict as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error

    @app.get("/public/evidence/{receipt_id}/authority-bundle.zip", include_in_schema=False)
    def public_authority_bundle(receipt_id: UUID) -> Response:
        if public_bundle_service is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "finalized public receipt not found")
        try:
            result = public_bundle_service.download(receipt_id)
        except DependencyUnavailable as error:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "finalized authority bundle is temporarily unavailable",
                headers={"Retry-After": "30"},
            ) from error
        if result is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "finalized public receipt not found")
        archive, record = result
        return Response(
            content=archive,
            media_type="application/zip",
            headers={
                "Cache-Control": "public, max-age=31536000, immutable",
                "Content-Disposition": (
                    f'attachment; filename="recallops-authority-{receipt_id}.zip"'
                ),
                "ETag": f'"{record.bundle_digest}"',
                "X-RecallOps-Bundle-Digest": record.bundle_digest,
                "X-RecallOps-Source-SHA": record.source_sha,
                "X-RecallOps-Image-Digest": record.image_digest,
            },
        )

    static_directory = Path(__file__).with_name("static")

    @app.get("/", include_in_schema=False)
    def console() -> FileResponse:
        return FileResponse(static_directory / "index.html")

    @app.get("/reviewer", include_in_schema=False)
    def reviewer_console() -> FileResponse:
        return FileResponse(static_directory / "reviewer.html")

    app.mount("/assets", StaticFiles(directory=static_directory), name="assets")
    return app
