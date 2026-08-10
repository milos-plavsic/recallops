import os
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from recallops.archive import NullEvidenceArchive, S3EvidenceArchive
from recallops.auth import (
    AuthenticationError,
    AuthorizationError,
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
)
from recallops.embedding import BedrockTitanEmbedder, DeterministicEmbedder
from recallops.evaluation import EvaluationReport, evaluate, load_dataset
from recallops.evidence import AwsEvidenceVerifier, ManualOnlyEvidenceVerifier
from recallops.resilience import DependencyUnavailable
from recallops.service import (
    BedrockReasoner,
    DeterministicReasoner,
    IncidentService,
    IncidentWorkflowError,
)
from recallops.store import InMemoryStore, MemoryGovernanceError, MemoryStore, PostgresStore


def create_app(settings: Settings | None = None, store: MemoryStore | None = None) -> FastAPI:
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
    authenticator = create_authenticator(settings)

    app = FastAPI(title="RecallOps", version="0.1.0", docs_url="/docs")
    app.state.store = store
    app.state.service = service

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
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        if request.url.path.startswith("/v1/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def principal(
        authorization: str | None = Header(default=None),
        x_tenant_id: str | None = Header(default=None, max_length=80),
        x_actor_id: str | None = Header(default=None, max_length=200),
        x_roles: str | None = Header(default=None, max_length=500),
    ) -> Principal:
        try:
            return authenticator.authenticate(authorization, x_tenant_id, x_actor_id, x_roles)
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
    def analyze(payload: IncidentCreate, identity: AuthenticatedPrincipal) -> IncidentAnalysis:
        if payload.tenant_id != identity.tenant_id:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "identity and payload tenant differ")
        return service.analyze(payload)

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

    @app.post("/v1/incidents/{incident_id}/approval")
    def approve(
        incident_id: UUID, payload: ApprovalRequest, identity: AuthenticatedPrincipal
    ) -> dict[str, bool]:
        require_role(identity, "operator")
        if payload.tenant_id != identity.tenant_id or payload.actor_id != identity.subject:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "identity and payload actor differ")
        try:
            recorded = service.decide_approval(incident_id, payload)
        except IncidentWorkflowError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        if not recorded:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found or already decided")
        return {"recorded": True}

    @app.post(
        "/v1/incidents/{incident_id}/execution",
        response_model=ExecutionAttestation,
        status_code=status.HTTP_201_CREATED,
    )
    def attest_execution(
        incident_id: UUID,
        payload: ExecutionAttestationRequest,
        identity: AuthenticatedPrincipal,
    ) -> ExecutionAttestation:
        require_role(identity, "operator")
        if payload.tenant_id != identity.tenant_id or payload.actor_id != identity.subject:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "identity and payload actor differ")
        try:
            execution = service.attest_execution(incident_id, payload)
        except DependencyUnavailable as error:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                f"{error.dependency} unavailable; execution was not attested",
                headers={"Retry-After": "30"},
            ) from error
        except IncidentWorkflowError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        if execution is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
        return execution

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
    ) -> Memory:
        require_role(identity, "operator")
        if payload.tenant_id != identity.tenant_id or payload.actor_id != identity.subject:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "identity and payload actor differ")
        try:
            memory = service.learn_outcome(incident_id, payload)
        except DependencyUnavailable as error:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                f"{error.dependency} unavailable; outcome was not persisted",
                headers={"Retry-After": "30"},
            ) from error
        except IncidentWorkflowError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        if memory is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
        return memory

    @app.post(
        "/v1/memories/{memory_id}/governance",
        response_model=Memory,
        response_model_exclude={"embedding"},
    )
    def govern_memory(
        memory_id: UUID,
        payload: MemoryGovernanceRequest,
        identity: AuthenticatedPrincipal,
    ) -> Memory:
        require_role(identity, "reviewer")
        if payload.tenant_id != identity.tenant_id or payload.actor_id != identity.subject:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "identity and payload actor differ")
        try:
            memory = service.govern_memory(memory_id, payload)
        except MemoryGovernanceError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        if memory is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "memory not found")
        return memory

    static_directory = Path(__file__).with_name("static")

    @app.get("/", include_in_schema=False)
    def console() -> FileResponse:
        return FileResponse(static_directory / "index.html")

    app.mount("/assets", StaticFiles(directory=static_directory), name="assets")
    return app
