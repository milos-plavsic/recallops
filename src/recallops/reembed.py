import argparse
import os
from collections.abc import Callable
from typing import Any

import psycopg
from psycopg.rows import dict_row

from recallops.config import Settings
from recallops.embedding import BedrockTitanEmbedder, Embedder


def vector_literal(values: list[float]) -> str:
    return "[" + ",".join(f"{value:.9g}" for value in values) + "]"


def reembed_batch(
    database_url: str,
    embedder: Embedder,
    batch_size: int,
    connect: Callable[..., Any] = psycopg.connect,
) -> int:
    with connect(database_url, row_factory=dict_row) as connection, connection.cursor() as cursor:
        cursor.execute(
            """SELECT id, service, symptom FROM memories
            WHERE embedding_space = 'legacy:unknown:v0'
            ORDER BY created_at, id LIMIT %s""",
            (batch_size,),
        )
        rows = cursor.fetchall()

    updated = 0
    for row in rows:
        embedding = embedder.embed(f"{row['service']} {row['symptom']}")
        with connect(database_url) as connection, connection.cursor() as cursor:
            cursor.execute(
                """UPDATE memories SET embedding=%s::VECTOR, embedding_space=%s
                WHERE id=%s AND embedding_space='legacy:unknown:v0'""",
                (vector_literal(embedding), embedder.space_id, row["id"]),
            )
            updated += cursor.rowcount
    return updated


def count_legacy(database_url: str) -> int:
    with psycopg.connect(database_url) as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM memories WHERE embedding_space='legacy:unknown:v0'"
        )
        row = cursor.fetchone()
    assert row is not None
    return int(row[0])


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Safely re-embed quarantined legacy RecallOps memories"
    )
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--batch-size", type=int, default=25)
    arguments = parser.parse_args()
    if arguments.batch_size < 1 or arguments.batch_size > 100:
        parser.error("--batch-size must be between 1 and 100")

    settings = Settings()
    database_url = os.environ.get("RECALLOPS_DATABASE_URL", settings.database_url)
    remaining = count_legacy(database_url)
    if not arguments.apply:
        print(f"dry-run: {remaining} legacy memories require re-embedding")
        return

    embedder = BedrockTitanEmbedder(
        settings.aws_region,
        settings.bedrock_embedding_model_id,
        settings.provider_connect_timeout_seconds,
        settings.provider_read_timeout_seconds,
        settings.provider_max_attempts,
    )
    repaired = 0
    while remaining:
        changed = reembed_batch(database_url, embedder, arguments.batch_size)
        repaired += changed
        if changed == 0:
            raise RuntimeError("legacy memories remain but no compare-and-set update succeeded")
        remaining = count_legacy(database_url)
        print(f"re-embedded={repaired} remaining={remaining}")


if __name__ == "__main__":
    main()
