import hmac
import os
import secrets
import threading
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, cast
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
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
    InMemoryAuthorityLedgerRepository,
    PostgresAuthorityLedgerRepository,
)
from recallops.resilience import DependencyUnavailable
from recallops.sandbox import (
    SANDBOX_ACTION_COMMAND,
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
from recallops.sessions import (
    InMemoryJudgeSessionRepository,
    JudgeRun,
    JudgeRunCapacityError,
    PostgresJudgeSessionRepository,
    ReviewHandoff,
)
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
    authority_lock = threading.RLock()

    app = FastAPI(title="RecallOps", version="0.1.0", docs_url="/docs")
    app.state.store = store
    app.state.service = service
    app.state.workflows = workflows
    app.state.checkout_sandbox = checkout_sandbox
    app.state.observation_provider = observation_provider
    app.state.judge_repository = judge_repository
    app.state.ledger_repository = ledger_repository

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
                embedding=embedder.embed(f"checkout {incident.symptom}"),
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
                embedding=embedder.embed(f"checkout {incident.symptom}"),
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
                bound_judges.save_run(
                    run, settings.judge_active_run_limit
                )
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

    @app.get("/v1/operator/run")
    def get_operator_run(identity: AuthenticatedPrincipal) -> dict[str, object]:
        require_role(identity, "operator")
        return run_payload(current_run(identity))

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
            "reviewer_url": f"{settings.public_origin}/#review={code}",
            "expires_at": handoff.expires_at,
            "purpose": handoff.purpose,
        }

    @app.post("/v1/judge/reviewer-exchange")
    async def exchange_reviewer_handoff(request: Request, response: Response) -> dict[str, object]:
        if not isinstance(authenticator, JudgeSessionAuthenticator):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "judge runs are not enabled")
        if request.headers.get("origin") != settings.public_origin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "trusted Origin required")
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

    def require_if_match(
        request: Request, run: JudgeRun, workflow: WorkflowSnapshot
    ) -> None:
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
            completed = tx_workflows.transition(
                handoff.workflow_id,
                run.tenant_id,
                workflow.epoch,
                WorkflowState.PENDING_REVIEW,
                WorkflowState.REVIEWED,
                channel=RequestChannel.UI,
                actor_subject=identity.subject,
                role="reviewer",
            )
            return {"memory": governed, "workflow": completed}

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

    @app.get("/v1/webmcp/recurrence", response_model=RecurrenceView)
    def recall_recurrence(identity: AuthenticatedPrincipal) -> RecurrenceView:
        require_role(identity, "agent")
        run = current_run(identity)
        workflow = workflows.get(run.source_incident_id, run.tenant_id)
        if workflow is None or not workflow.active or workflow.state is not WorkflowState.REVIEWED:
            raise HTTPException(status.HTTP_409_CONFLICT, "reviewed recurrence is unavailable")
        recurrence = IncidentCreate(
            tenant_id=run.tenant_id,
            service="checkout",
            service_version="v2.4.1",
            symptom="checkout-latency-43: compatible recurrence of elevated p95 latency",
            idempotency_key=f"recurrence-{run.run_id.hex}",
        )
        return service.recurrence_view(recurrence)

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

    static_directory = Path(__file__).with_name("static")

    @app.get("/", include_in_schema=False)
    def console() -> FileResponse:
        return FileResponse(static_directory / "index.html")

    app.mount("/assets", StaticFiles(directory=static_directory), name="assets")
    return app
