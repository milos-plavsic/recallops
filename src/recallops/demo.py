from uuid import NAMESPACE_URL, uuid5

from recallops.config import get_settings
from recallops.domain import Memory
from recallops.embedding import BedrockTitanEmbedder, DeterministicEmbedder, Embedder
from recallops.store import PostgresStore


def seed_memories(store: PostgresStore, embedder: Embedder) -> None:
    scenarios = [
        (
            "2025.01",
            "checkout latency spike after connection pool exhaustion",
            "restart the entire checkout service",
            "temporary recovery followed by a second outage",
            -0.6,
            0.9,
        ),
        (
            "2026.07.31",
            "checkout latency spike after connection pool exhaustion",
            "reduce worker concurrency to 24 and recycle saturated connections",
            "latency recovered and error rate returned to baseline",
            1.0,
            0.96,
        ),
        (
            "2026.07.31",
            "checkout elevated errors caused by expired payment credentials",
            "rotate the payment provider credential",
            "authentication errors returned to baseline",
            1.0,
            0.98,
        ),
    ]
    for version, symptom, action, outcome, outcome_score, confidence in scenarios:
        store.add_memory(
            Memory(
                id=uuid5(NAMESPACE_URL, f"recallops:demo:{version}:{symptom}:{action}"),
                tenant_id="demo",
                service="checkout",
                service_version=version,
                symptom=symptom,
                action=action,
                outcome=outcome,
                outcome_score=outcome_score,
                confidence=confidence,
                embedding=embedder.embed(f"checkout {symptom}"),
            )
        )


def main() -> None:
    settings = get_settings()
    embedder: Embedder = (
        BedrockTitanEmbedder(settings.aws_region, settings.bedrock_embedding_model_id)
        if settings.embedding_provider == "bedrock"
        else DeterministicEmbedder()
    )
    store = PostgresStore(settings.database_url)
    try:
        seed_memories(store, embedder)
    finally:
        store.close()


if __name__ == "__main__":
    main()
