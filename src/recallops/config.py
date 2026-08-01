from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RECALLOPS_", env_file=".env", extra="ignore")

    database_url: str = "postgresql://root@localhost:26257/recallops?sslmode=disable"
    store: Literal["memory", "postgres"] = "memory"
    aws_region: str = "us-east-1"
    reasoning_provider: Literal["deterministic", "bedrock"] = "deterministic"
    embedding_provider: Literal["deterministic", "bedrock"] = "deterministic"
    bedrock_model_id: str = "amazon.nova-lite-v1:0"
    bedrock_embedding_model_id: str = "amazon.titan-embed-text-v2:0"
    evidence_bucket: str | None = None
    log_level: str = "INFO"
    provider_connect_timeout_seconds: float = Field(default=2.0, gt=0, le=30)
    provider_read_timeout_seconds: float = Field(default=15.0, gt=0, le=120)
    provider_max_attempts: int = Field(default=3, ge=1, le=10)
    database_connect_timeout_seconds: int = Field(default=5, ge=1, le=30)
    database_statement_timeout_seconds: int = Field(default=15, ge=1, le=120)
    max_memories: int = Field(default=5, ge=1, le=20)
    auth_mode: Literal["demo", "oidc"] = "demo"
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_tenant_claim: str = "tenant_id"
    oidc_roles_claim: str = "cognito:groups"
    oidc_authorization_url: str | None = None
    oidc_token_url: str | None = None
    oidc_logout_url: str | None = None
    oidc_redirect_url: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
