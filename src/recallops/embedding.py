import hashlib
import json
import math
from typing import Protocol

import boto3


class Embedder(Protocol):
    def embed(self, text: str) -> list[float]: ...


class DeterministicEmbedder:
    dimensions = 1024

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
    def __init__(self, region: str, model_id: str) -> None:
        self._client = boto3.client("bedrock-runtime", region_name=region)
        self._model_id = model_id

    def embed(self, text: str) -> list[float]:
        response = self._client.invoke_model(
            modelId=self._model_id,
            contentType="application/json",
            accept="application/json",
            body=json.dumps({"inputText": text, "dimensions": 1024, "normalize": True}),
        )
        payload = json.loads(response["body"].read())
        return [float(value) for value in payload["embedding"]]
