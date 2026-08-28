import os
import threading
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated, cast
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from recallops.archive import NullEvidenceArchive, S3EvidenceArchive
from recallops.auth import (
    AuthenticationError,
    AuthorizationError,
    JudgeRateLimitError,
    JudgeSessionAuthenticator,
    JudgeSessionError,
    Principal,
    create_authenticator,
)
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
    IncidentAnalysis,
    IncidentCreate,
    Memory,
    MemoryGovernanceRequest,
    OutcomeObservation,
    PostcheckAssessment,
    PostcheckAssessmentRequest,
    PostcheckRetryRequest,
    SandboxExecution,
    SandboxExecutionRequest,
)
from recallops.embedding import BedrockTitanEmbedder, DeterministicEmbedder
from recallops.evaluation import EvaluationReport, evaluate, load_dataset
from recallops.evidence import AwsEvidenceVerifier, ManualOnlyEvidenceVerifier
from recallops.resilience import DependencyUnavailable
from recallops.sandbox import (
    CheckoutSandbox,
    DeterministicObservationProvider,
    ObservationProvider,
    SandboxPolicyError,
    evaluate_observation,
)
from recallops.service import (
    BedrockReasoner,
    DeterministicReasoner,
    IncidentService,
    IncidentWorkflowError,
)
from recallops.sessions import InMemoryJudgeSessionRepository, PostgresJudgeSessionRepository
from recallops.store import InMemoryStore, MemoryGovernanceError, MemoryStore, PostgresStore
from recallops.workflow import (
    InMemoryWorkflowRepository,
    PostgresWorkflowRepository,
    RequestChannel,
    WorkflowConflict,
    WorkflowCoordinator,
    WorkflowSnapshot,
    WorkflowState,
)


def create_app(
    settings: Settings | None = None,
    store: MemoryStore | None = None,
    *,
    checkout_sandbox: CheckoutSandbox | None = None,
    observation_provider: ObservationProvider | None = None,
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
    workflows = WorkflowCoordinator(workflow_repository)
    checkout_sandbox = checkout_sandbox or CheckoutSandbox()
    observation_provider = observation_provider or DeterministicObservationProvider()
    authority_lock = threading.RLock()

    app = FastAPI(title="RecallOps", version="0.1.0", docs_url="/docs")
    app.state.store = store
    app.state.service = service
    app.state.workflows = workflows
    app.state.checkout_sandbox = checkout_sandbox
    app.state.observation_provider = observation_provider

    def authority_transaction(
        operation: Callable[[IncidentService, WorkflowCoordinator], object],
    ) -> object:
        if isinstance(store, PostgresStore):
            return store.atomic(
                lambda bound_store, connection: operation(
                    service.using_store(bound_store),
                    WorkflowCoordinator(PostgresWorkflowRepository.from_connection(connection)),
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

    def principal(
        request: Request,
        authorization: str | None = Header(default=None),
        x_tenant_id: str | None = Header(default=None, max_length=80),
        x_actor_id: str | None = Header(default=None, max_length=200),
        x_roles: str | None = Header(default=None, max_length=500),
    ) -> Principal:
        cookie_name = (
            "__Host-recallops_session" if settings.judge_cookie_secure else "recallops_session"
        )
        session_cookie = request.cookies.get(cookie_name)
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

    @app.post("/v1/judge/session/exchange")
    async def exchange_judge_session(request: Request, response: Response) -> dict[str, object]:
        if not isinstance(authenticator, JudgeSessionAuthenticator):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "judge sessions are not enabled")
        if request.headers.get("origin") != settings.public_origin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "trusted Origin required")
        body = await request.json()
        code = body.get("code") if isinstance(body, dict) else None
        if not isinstance(code, str) or not 16 <= len(code) <= 512:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "valid bootstrap code required")
        address = request.client.host if request.client is not None else "unknown"
        try:
            token, csrf, identity = authenticator.exchange(code, address)
        except JudgeRateLimitError as error:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS, str(error), headers={"Retry-After": "300"}
            ) from error
        except JudgeSessionError as error:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(error)) from error
        response.set_cookie(
            key=(
                "__Host-recallops_session" if settings.judge_cookie_secure else "recallops_session"
            ),
            value=token,
            max_age=settings.judge_session_ttl_seconds,
            secure=settings.judge_cookie_secure,
            httponly=True,
            samesite="strict",
            path="/",
        )
        return {
            "csrf_token": csrf,
            "identity": {
                "subject": identity.subject,
                "tenant_id": identity.tenant_id,
                "roles": sorted(identity.roles),
                "auth_method": identity.auth_method,
            },
        }

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
        response.delete_cookie(
            key=(
                "__Host-recallops_session" if settings.judge_cookie_secure else "recallops_session"
            ),
            secure=settings.judge_cookie_secure,
            httponly=True,
            samesite="strict",
            path="/",
        )
        return {"revoked": True}

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
            memory = service.prepare_verified_outcome(
                incident_id, observation, verdict, assessment
            )
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
            return workflows.invalidate(
                incident_id,
                identity.tenant_id,
                x_workflow_epoch,
                channel=request_channel,
                role="operator",
            )
        except WorkflowConflict as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error

    static_directory = Path(__file__).with_name("static")

    @app.get("/", include_in_schema=False)
    def console() -> FileResponse:
        return FileResponse(static_directory / "index.html")

    app.mount("/assets", StaticFiles(directory=static_directory), name="assets")
    return app
