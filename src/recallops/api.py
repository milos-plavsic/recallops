from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, status
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
from recallops.domain import (
    ApprovalRequest,
    IncidentAnalysis,
    IncidentCreate,
    Memory,
    MemoryGovernanceRequest,
    OutcomeObservation,
)
from recallops.embedding import BedrockTitanEmbedder, DeterministicEmbedder
from recallops.evaluation import EvaluationReport, evaluate, load_dataset
from recallops.service import BedrockReasoner, DeterministicReasoner, IncidentService
from recallops.store import InMemoryStore, MemoryGovernanceError, MemoryStore, PostgresStore


def create_app(settings: Settings | None = None, store: MemoryStore | None = None) -> FastAPI:
    settings = settings or get_settings()
    store = store or (
        PostgresStore(
            settings.database_url,
            settings.database_connect_timeout_seconds,
            settings.database_statement_timeout_seconds,
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
    service = IncidentService(store, embedder, reasoner, settings.max_memories, archive)
    authenticator = create_authenticator(settings)
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        del app
        yield
        if isinstance(store, PostgresStore):
            store.close()

    app = FastAPI(title="RecallOps", version="0.1.0", docs_url="/docs", lifespan=lifespan)
    app.state.store = store
    app.state.service = service

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

    @app.get("/v1/evaluation", response_model=EvaluationReport)
    def evaluation_report() -> EvaluationReport:
        return evaluate(load_dataset(Path("evaluation/memory_cases.json")))

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
    def get_incident(
        incident_id: UUID, identity: AuthenticatedPrincipal
    ) -> IncidentAnalysis:
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
        recorded = store.record_approval(
            incident_id,
            identity.tenant_id,
            identity.subject,
            payload.approved,
            payload.reason,
        )
        if not recorded:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found or already decided")
        return {"recorded": True}

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
        memory = service.learn_outcome(incident_id, payload)
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
