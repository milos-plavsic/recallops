from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from recallops.auth import AuthenticationError, OidcAuthenticator
from recallops.config import Settings


class StaticKeyClient:
    def __init__(self, public_key: object) -> None:
        self.public_key = public_key

    def get_signing_key_from_jwt(self, token: str) -> object:
        del token
        return SimpleNamespace(key=self.public_key)


def token(overrides: dict[str, object] | None = None) -> tuple[str, object]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "iss": "https://issuer.example",
        "sub": "operator-123",
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "token_use": "access",
        "client_id": "recallops-client",
        "tenant_id": "demo",
        "cognito:groups": ["operator", "reviewer"],
    }
    claims.update(overrides or {})
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test"}), (
        private_key.public_key()
    )


def authenticator(public_key: object) -> OidcAuthenticator:
    settings = Settings(
        auth_mode="oidc",
        oidc_issuer="https://issuer.example/",
        oidc_audience="recallops-client",
    )
    return OidcAuthenticator(settings, lambda uri: StaticKeyClient(public_key))


def test_oidc_authenticator_derives_identity_and_roles_from_verified_claims() -> None:
    encoded, public_key = token()
    principal = authenticator(public_key).authenticate(
        f"Bearer {encoded}", "attacker-tenant", "attacker", "admin"
    )
    assert principal.subject == "operator-123"
    assert principal.tenant_id == "demo"
    assert principal.roles == frozenset({"operator", "reviewer"})


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"client_id": "other-client"}, "audience"),
        ({"token_use": "id"}, "access token"),
        ({"tenant_id": None}, "identity claims"),
    ],
)
def test_oidc_authenticator_rejects_invalid_security_claims(
    overrides: dict[str, object], message: str
) -> None:
    encoded, public_key = token(overrides)
    with pytest.raises(AuthenticationError, match=message):
        authenticator(public_key).authenticate(f"Bearer {encoded}", None, None, None)


def test_oidc_authenticator_rejects_invalid_signature() -> None:
    encoded, _ = token()
    _, wrong_public_key = token()
    with pytest.raises(AuthenticationError, match="invalid bearer token"):
        authenticator(wrong_public_key).authenticate(f"Bearer {encoded}", None, None, None)
