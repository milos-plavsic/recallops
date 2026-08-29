from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
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
    evidence_verifier: Literal["manual_only", "aws"] = "manual_only"
    log_level: str = "INFO"
    provider_connect_timeout_seconds: float = Field(default=2.0, gt=0, le=30)
    provider_read_timeout_seconds: float = Field(default=15.0, gt=0, le=120)
    provider_max_attempts: int = Field(default=3, ge=1, le=10)
    database_connect_timeout_seconds: int = Field(default=5, ge=1, le=30)
    database_statement_timeout_seconds: int = Field(default=15, ge=1, le=120)
    max_memories: int = Field(default=5, ge=1, le=20)
    retrieval_min_similarity: float = Field(default=0.55, ge=-1, le=1)
    retrieval_min_confidence: float = Field(default=0.50, ge=0, le=1)
    retrieval_min_rank_score: float = Field(default=0.65, ge=-1, le=1)
    retrieval_min_margin: float = Field(default=0.03, ge=0, le=2)
    retrieval_candidate_multiplier: int = Field(default=8, ge=1, le=50)
    default_compatibility_policy: Literal["exact", "semver_patch", "semver_minor"] = "exact"
    compatibility_policy_version: str = Field(default="semver-v1", min_length=3, max_length=80)
    diagnostic_provider: Literal["none", "aws"] = "none"
    diagnostic_alarm_prefix: str | None = None
    diagnostic_ecs_cluster: str | None = None
    diagnostic_ecs_service_prefix: str | None = None
    diagnostic_max_alarms: int = Field(default=5, ge=1, le=20)
    diagnostic_max_deployments: int = Field(default=5, ge=1, le=20)
    auth_mode: Literal["demo", "oidc", "judge"] = "demo"
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_tenant_claim: str = "tenant_id"
    oidc_roles_claim: str = "cognito:groups"
    oidc_leeway_seconds: int = Field(default=30, ge=0, le=300)
    oidc_max_token_age_seconds: int = Field(default=3700, ge=60, le=86400)
    outbox_max_attempts: int = Field(default=8, ge=1, le=100)
    outbox_lease_seconds: int = Field(default=120, ge=30, le=900)
    oidc_authorization_url: str | None = None
    oidc_token_url: str | None = None
    oidc_logout_url: str | None = None
    oidc_redirect_url: str | None = None
    public_origin: str = "http://127.0.0.1:8000"
    judge_session_ttl_seconds: int = Field(default=3600, ge=300, le=86400)
    judge_exchange_attempt_limit: int = Field(default=8, ge=1, le=100)
    judge_exchange_window_seconds: int = Field(default=300, ge=60, le=3600)
    judge_rate_limit_key: SecretStr | None = None
    judge_cookie_secure: bool = True
    judge_run_ttl_seconds: int = Field(default=3600, ge=300, le=86400)
    judge_active_run_limit: int = Field(default=100, ge=1, le=10000)
    judge_run_launch_limit: int = Field(default=8, ge=1, le=100)
    judge_handoff_ttl_seconds: int = Field(default=300, ge=60, le=900)
    scenario_version: str = Field(default="checkout-latency-v1", min_length=3, max_length=80)
    build_sha: str = Field(default="development", min_length=3, max_length=80)
    capability_policy_version: str = Field(
        default="webmcp-capability-v1", min_length=3, max_length=80
    )
    memory_ttl_days: int = Field(default=180, ge=1, le=3650)
    receipt_kms_key_id: str | None = None
    receipt_release_id: str | None = Field(default=None, min_length=3, max_length=100)
    receipt_trusted_keys_path: Path = Path("tools/trusted-receipt-keys.json")
    receipt_policy_version: str = Field(
        default="authority-receipt-policy-v1", min_length=3, max_length=80
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
