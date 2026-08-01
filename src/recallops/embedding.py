import hashlib
import json
import math
from typing import Protocol

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from recallops.resilience import DependencyUnavailable, aws_client_config


class Embedder(Protocol):
    @property
    def provider(self) -> str: ...

    @property
    def model(self) -> str: ...

    @property
    def schema_version(self) -> int: ...

    def embed(self, text: str) -> list[float]: ...

    @property
    def space_id(self) -> str: ...


class DeterministicEmbedder:
    dimensions = 1024
    provider = "deterministic"
    model = "sha256-feature-hash-1024"
    schema_version = 1

    @property
    def space_id(self) -> str:
        return f"{self.provider}:{self.model}:v{self.schema_version}"

    def embed(self, text: str) -> list[float]:
        values = [0.0] * self.dimensions
        tokens = text.casefold().split()
        for token in tokens:
            digest = hashlib.sha256(token.encode()).digest()
            index = int.from_bytes(digest[:4], "big") % self.dimensions
            values[index] += 1.0 if digest[4] % 2 else -1.0
        magnitude = math.sqrt(sum(value * value for value in values)) or 1.0
        return [value / magnitude for value in values]


class BedrockTitanEmbedder:
    provider = "bedrock"
    schema_version = 1

    def __init__(
        self,
        region: str,
        model_id: str,
        connect_timeout: float = 2.0,
        read_timeout: float = 15.0,
        max_attempts: int = 3,
    ) -> None:
        self._client = boto3.client(
            "bedrock-runtime",
            region_name=region,
            config=aws_client_config(connect_timeout, read_timeout, max_attempts),
        )
        self._model_id = model_id

    @property
    def model(self) -> str:
        return self._model_id

    @property
    def space_id(self) -> str:
        return f"{self.provider}:{self.model}:v{self.schema_version}"

    def embed(self, text: str) -> list[float]:
        try:
            response = self._client.invoke_model(
                modelId=self._model_id,
                contentType="application/json",
                accept="application/json",
                body=json.dumps({"inputText": text, "dimensions": 1024, "normalize": True}),
            )
            payload = json.loads(response["body"].read())
            embedding = [float(value) for value in payload["embedding"]]
            if len(embedding) != 1024:
                raise ValueError("unexpected embedding dimensions")
            return embedding
        except (BotoCoreError, ClientError, KeyError, TypeError, ValueError) as error:
            raise DependencyUnavailable("bedrock_embedding") from error
