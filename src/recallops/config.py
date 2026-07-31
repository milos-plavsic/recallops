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
    max_memories: int = Field(default=5, ge=1, le=20)


@lru_cache
def get_settings() -> Settings:
    return Settings()
