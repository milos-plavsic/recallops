import io
import json
from typing import Any

import pytest
from botocore.exceptions import ClientError

from recallops import embedding
from recallops.embedding import BedrockTitanEmbedder, DeterministicEmbedder
from recallops.resilience import DependencyUnavailable


class BedrockClient:
    def __init__(self, payload: dict[str, Any] | None = None, fail: bool = False) -> None:
        self.payload = {"embedding": [0.0] * 1024} if payload is None else payload
        self.fail = fail
        self.request: dict[str, Any] = {}

    def invoke_model(self, **request: Any) -> dict[str, Any]:
        self.request = request
        if self.fail:
            raise ClientError({"Error": {"Code": "Denied", "Message": "no"}}, "InvokeModel")
        return {"body": io.BytesIO(json.dumps(self.payload).encode())}


def make_embedder(monkeypatch: pytest.MonkeyPatch, client: BedrockClient) -> BedrockTitanEmbedder:
    monkeypatch.setattr(embedding.boto3, "client", lambda *args, **kwargs: client)
    return BedrockTitanEmbedder("us-east-1", "model-id")


def test_deterministic_embedder_empty_and_repeatable_vectors() -> None:
    embedder = DeterministicEmbedder()
    assert embedder.space_id.endswith(":v1")
    assert embedder.embed("") == [0.0] * 1024
    first = embedder.embed("Checkout checkout")
    assert first == embedder.embed("checkout CHECKOUT")
    assert sum(value * value for value in first) == pytest.approx(1.0)


def test_bedrock_embedder_sends_bounded_request(monkeypatch: pytest.MonkeyPatch) -> None:
    client = BedrockClient()
    embedder = make_embedder(monkeypatch, client)
    assert embedder.model == "model-id"
    assert embedder.space_id == "bedrock:model-id:v1"
    assert embedder.embed("incident") == [0.0] * 1024
    assert json.loads(client.request["body"])["dimensions"] == 1024


@pytest.mark.parametrize(
    "client",
    [BedrockClient({"embedding": [0.0]}), BedrockClient({}), BedrockClient(fail=True)],
)
def test_bedrock_embedder_fails_closed(
    monkeypatch: pytest.MonkeyPatch, client: BedrockClient
) -> None:
    with pytest.raises(DependencyUnavailable, match="bedrock_embedding"):
        make_embedder(monkeypatch, client).embed("incident")
