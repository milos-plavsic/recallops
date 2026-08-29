import hashlib
import hmac
import secrets
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol, cast
from uuid import UUID

import jwt
from pydantic import BaseModel, Field

from recallops.config import Settings
from recallops.sessions import JudgeSession, JudgeSessionRepository


class AuthenticationError(ValueError):
    pass


class Principal(BaseModel):
    subject: str = Field(min_length=1, max_length=200)
    tenant_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_-]+$")
    roles: frozenset[str]
    auth_method: str = "header"
    session_hash: str | None = Field(default=None, exclude=True)
    csrf_hash: str | None = Field(default=None, exclude=True)
    run_id: UUID | None = None
    session_generation: int | None = None
    review_handoff_hash: str | None = Field(default=None, exclude=True)

    def require(self, role: str) -> None:
        if role not in self.roles:
            raise AuthorizationError(f"role required: {role}")


class AuthorizationError(ValueError):
    pass


class Authenticator(Protocol):
    def authenticate(
        self,
        authorization: str | None,
        tenant_header: str | None,
        actor_header: str | None,
        roles_header: str | None,
        session_cookie: str | None = None,
    ) -> Principal: ...


class DemoAuthenticator:
    def authenticate(
        self,
        authorization: str | None,
        tenant_header: str | None,
        actor_header: str | None,
        roles_header: str | None,
        session_cookie: str | None = None,
    ) -> Principal:
        del authorization, session_cookie
        if not tenant_header:
            raise AuthenticationError("X-Tenant-ID is required in demo auth mode")
        roles = frozenset(
            role.strip()
            for role in (roles_header or "operator,reviewer").split(",")
            if role.strip()
        )
        return Principal(
            subject=actor_header or "demo-operator",
            tenant_id=tenant_header,
            roles=roles,
        )


class SigningKeyClient(Protocol):
    def get_signing_key_from_jwt(self, token: str) -> Any: ...


class OidcAuthenticator:
    def __init__(
        self,
        settings: Settings,
        key_client_factory: Callable[[str], SigningKeyClient] | None = None,
    ) -> None:
        if not settings.oidc_issuer or not settings.oidc_audience:
            raise ValueError("OIDC issuer and audience are required when auth mode is oidc")
        self._issuer = settings.oidc_issuer.rstrip("/")
        self._audience = settings.oidc_audience
        self._tenant_claim = settings.oidc_tenant_claim
        self._roles_claim = settings.oidc_roles_claim
        self._leeway = settings.oidc_leeway_seconds
        self._max_token_age_seconds = settings.oidc_max_token_age_seconds
        factory = key_client_factory or (
            lambda uri: jwt.PyJWKClient(uri, cache_jwk_set=True, lifespan=300, timeout=5)
        )
        self._keys = factory(f"{self._issuer}/.well-known/jwks.json")

    def authenticate(
        self,
        authorization: str | None,
        tenant_header: str | None,
        actor_header: str | None,
        roles_header: str | None,
        session_cookie: str | None = None,
    ) -> Principal:
        del tenant_header, actor_header, roles_header, session_cookie
        if not authorization:
            raise AuthenticationError("Bearer token required")
        scheme, separator, token = authorization.partition(" ")
        if not separator or scheme.casefold() != "bearer" or not token.strip():
            raise AuthenticationError("Bearer token required")
        token = token.strip()
        try:
            signing_key = self._keys.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                issuer=self._issuer,
                leeway=self._leeway,
                options={
                    "require": ["exp", "iat", "iss", "sub", "token_use"],
                    "verify_aud": False,
                },
            )
        except jwt.PyJWTError as error:
            raise AuthenticationError("invalid bearer token") from error
        self._validate_client(claims)
        if claims.get("token_use") != "access":
            raise AuthenticationError("access token required")
        tenant_id = claims.get(self._tenant_claim)
        subject = claims.get("sub")
        if not isinstance(tenant_id, str) or not isinstance(subject, str):
            raise AuthenticationError("required identity claims missing")
        self._validate_token_age(claims)
        return Principal(
            subject=subject,
            tenant_id=tenant_id,
            roles=self._roles(claims.get(self._roles_claim)),
        )

    def _validate_client(self, claims: Mapping[str, Any]) -> None:
        claim = claims.get("client_id", claims.get("aud"))
        audiences = claim if isinstance(claim, list) else [claim]
        if not any(
            isinstance(candidate, str) and hmac.compare_digest(candidate, self._audience)
            for candidate in audiences
        ):
            raise AuthenticationError("token audience does not match this application")

    def _validate_token_age(self, claims: Mapping[str, Any]) -> None:
        issued_at = claims.get("iat")
        if not isinstance(issued_at, (int, float)) or isinstance(issued_at, bool):
            raise AuthenticationError("token issued-at claim is invalid")
        age = datetime.now(UTC).timestamp() - issued_at
        if age > self._max_token_age_seconds + self._leeway:
            raise AuthenticationError("access token is older than the allowed lifetime")

    @staticmethod
    def _roles(value: object) -> frozenset[str]:
        if isinstance(value, list) and all(isinstance(role, str) for role in value):
            return frozenset(value)
        if isinstance(value, str):
            return frozenset(role for role in value.split() if role)
        return frozenset()


class JudgeSessionError(AuthenticationError):
    pass


class JudgeSessionAuthenticator:
    def __init__(self, settings: Settings, repository: JudgeSessionRepository) -> None:
        if settings.judge_rate_limit_key is None:
            raise ValueError("judge rate-limit HMAC key is required in judge auth mode")
        self._ttl = settings.judge_session_ttl_seconds
        self._attempt_limit = settings.judge_exchange_attempt_limit
        self._attempt_window = settings.judge_exchange_window_seconds
        self._rate_key = settings.judge_rate_limit_key.get_secret_value().encode()
        self._repository = repository

    @staticmethod
    def digest(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    def create_session(
        self,
        role: str,
        *,
        run_id: UUID,
        tenant_id: str,
        generation: int,
        subject: str,
        review_handoff_hash: str | None = None,
    ) -> tuple[str, str, Principal]:
        if role not in {"operator", "reviewer"}:
            raise JudgeSessionError("invalid judge session role")
        if role == "reviewer":
            run = self._repository.get_run(run_id)
            if run is None or run.tenant_id != tenant_id or run.generation != generation:
                raise JudgeSessionError("judge run is invalid or expired")
            if hmac.compare_digest(run.operator_subject, subject):
                raise JudgeSessionError("reviewer subject must be independent")
            if review_handoff_hash is None:
                raise JudgeSessionError("reviewer session requires a consumed handoff")
        elif review_handoff_hash is not None:
            raise JudgeSessionError("operator session cannot carry reviewer authority")
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        session_hash = self.digest(token)
        session = JudgeSession(
            session_hash=session_hash,
            csrf_hash=self.digest(csrf),
            tenant_id=tenant_id,
            subject=subject,
            role=cast(Literal["operator", "reviewer"], role),
            run_id=run_id,
            session_generation=generation,
            review_handoff_hash=review_handoff_hash,
            expires_at=datetime.now(UTC) + timedelta(seconds=self._ttl),
        )
        self._repository.save(session)
        return token, csrf, self._principal(session)

    def consume_launch(self, client_address: str, limit: int) -> bool:
        client_hash = hmac.new(
            self._rate_key,
            f"judge-run-launch\0{client_address}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return self._repository.consume_attempt(client_hash, limit, self._attempt_window)

    def consume_handoff_attempt(self, client_address: str) -> bool:
        client_hash = hmac.new(
            self._rate_key,
            f"review-handoff\0{client_address}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return self._repository.consume_attempt(
            client_hash, self._attempt_limit, self._attempt_window
        )

    def authenticate(
        self,
        authorization: str | None,
        tenant_header: str | None,
        actor_header: str | None,
        roles_header: str | None,
        session_cookie: str | None = None,
    ) -> Principal:
        del authorization, tenant_header, actor_header, roles_header
        if not session_cookie:
            raise JudgeSessionError("judge session cookie required")
        session = self._repository.get(self.digest(session_cookie))
        if (
            session is None
            or session.revoked_at is not None
            or session.expires_at <= datetime.now(UTC)
        ):
            raise JudgeSessionError("judge session is invalid or expired")
        if not self._repository.run_is_current(
            session.run_id, session.tenant_id, session.session_generation
        ):
            raise JudgeSessionError("judge session is invalid or expired")
        return self._principal(session)

    def validate_csrf(self, principal: Principal, token: str | None) -> None:
        if (
            principal.csrf_hash is None
            or token is None
            or not hmac.compare_digest(principal.csrf_hash, self.digest(token))
        ):
            raise AuthorizationError("valid CSRF token required")

    def revoke(self, principal: Principal) -> None:
        if principal.session_hash is not None:
            self._repository.revoke(principal.session_hash)

    @staticmethod
    def _principal(session: JudgeSession) -> Principal:
        roles: set[str] = {session.role}
        if session.role == "operator":
            roles.add("agent")
        return Principal(
            subject=session.subject,
            tenant_id=session.tenant_id,
            roles=frozenset(roles),
            auth_method="judge_session",
            session_hash=session.session_hash,
            csrf_hash=session.csrf_hash,
            run_id=session.run_id,
            session_generation=session.session_generation,
            review_handoff_hash=session.review_handoff_hash,
        )


def create_authenticator(
    settings: Settings, judge_repository: JudgeSessionRepository | None = None
) -> Authenticator:
    if settings.auth_mode == "oidc":
        return OidcAuthenticator(settings)
    if settings.auth_mode == "judge":
        if judge_repository is None:
            raise ValueError("judge session repository is required in judge auth mode")
        return JudgeSessionAuthenticator(settings, judge_repository)
    return DemoAuthenticator()
