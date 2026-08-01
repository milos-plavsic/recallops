import hmac
from collections.abc import Callable, Mapping
from typing import Any, Protocol

import jwt
from pydantic import BaseModel, Field

from recallops.config import Settings


class AuthenticationError(ValueError):
    pass


class Principal(BaseModel):
    subject: str = Field(min_length=1, max_length=200)
    tenant_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_-]+$")
    roles: frozenset[str]

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
    ) -> Principal: ...


class DemoAuthenticator:
    def authenticate(
        self,
        authorization: str | None,
        tenant_header: str | None,
        actor_header: str | None,
        roles_header: str | None,
    ) -> Principal:
        del authorization
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
    ) -> Principal:
        del tenant_header, actor_header, roles_header
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

    @staticmethod
    def _roles(value: object) -> frozenset[str]:
        if isinstance(value, list) and all(isinstance(role, str) for role in value):
            return frozenset(value)
        if isinstance(value, str):
            return frozenset(role for role in value.split() if role)
        return frozenset()


def create_authenticator(settings: Settings) -> Authenticator:
    return OidcAuthenticator(settings) if settings.auth_mode == "oidc" else DemoAuthenticator()
