from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, status

from recallops.archive import NullEvidenceArchive, S3EvidenceArchive
from recallops.config import Settings, get_settings
from recallops.domain import ApprovalRequest, IncidentAnalysis, IncidentCreate
from recallops.embedding import BedrockTitanEmbedder, DeterministicEmbedder
from recallops.service import BedrockReasoner, DeterministicReasoner, IncidentService
from recallops.store import InMemoryStore, MemoryStore, PostgresStore


def create_app(settings: Settings | None = None, store: MemoryStore | None = None) -> FastAPI:
    settings = settings or get_settings()
    store = store or (
        PostgresStore(settings.database_url) if settings.store == "postgres" else InMemoryStore()
    )
    embedder = (
        BedrockTitanEmbedder(settings.aws_region, settings.bedrock_embedding_model_id)
        if settings.embedding_provider == "bedrock"
        else DeterministicEmbedder()
    )
    reasoner = (
        BedrockReasoner(settings.aws_region, settings.bedrock_model_id)
        if settings.reasoning_provider == "bedrock"
        else DeterministicReasoner()
    )
    archive = (
        S3EvidenceArchive(settings.aws_region, settings.evidence_bucket)
        if settings.evidence_bucket
        else NullEvidenceArchive()
    )
    service = IncidentService(store, embedder, reasoner, settings.max_memories, archive)
    app = FastAPI(title="RecallOps", version="0.1.0", docs_url="/docs")
    app.state.store = store
    app.state.service = service

    def tenant(x_tenant_id: str = Header(min_length=1, max_length=80)) -> str:
        return x_tenant_id

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post(
        "/v1/incidents",
        response_model=IncidentAnalysis,
        response_model_exclude={"memories": {"__all__": {"memory": {"embedding"}}}},
        status_code=status.HTTP_201_CREATED,
    )
    def analyze(payload: IncidentCreate, tenant_id: str = Depends(tenant)) -> IncidentAnalysis:
        if payload.tenant_id != tenant_id:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "tenant header and payload differ")
        return service.analyze(payload)

    @app.get(
        "/v1/incidents/{incident_id}",
        response_model=IncidentAnalysis,
        response_model_exclude={"memories": {"__all__": {"memory": {"embedding"}}}},
    )
    def get_incident(incident_id: UUID, tenant_id: str = Depends(tenant)) -> IncidentAnalysis:
        result = store.get_analysis(incident_id, tenant_id)
        if result is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
        return result

    @app.post("/v1/incidents/{incident_id}/approval")
    def approve(
        incident_id: UUID, payload: ApprovalRequest, tenant_id: str = Depends(tenant)
    ) -> dict[str, bool]:
        if payload.tenant_id != tenant_id:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "tenant header and payload differ")
        recorded = store.record_approval(
            incident_id, tenant_id, payload.actor_id, payload.approved, payload.reason
        )
        if not recorded:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found or already decided")
        return {"recorded": True}

    return app
