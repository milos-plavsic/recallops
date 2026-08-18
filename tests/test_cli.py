import sys
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from recallops import demo, main, migrate, outbox, reembed


def test_main_runs_uvicorn(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    monkeypatch.setattr(main.uvicorn, "run", lambda *args, **kwargs: calls.append((args, kwargs)))
    main.run()
    assert calls == [(('recallops.main:app',), {"host": "0.0.0.0", "port": 8080})]


@pytest.mark.parametrize("provider", ["deterministic", "bedrock"])
def test_demo_main_selects_embedder_and_closes_store(
    monkeypatch: pytest.MonkeyPatch, provider: str
) -> None:
    settings = SimpleNamespace(
        embedding_provider=provider,
        aws_region="us-east-1",
        bedrock_embedding_model_id="model",
        database_url="postgresql://db",
    )
    store = MagicMock()
    embedder = MagicMock(space_id="space")
    monkeypatch.setattr(demo, "get_settings", lambda: settings)
    monkeypatch.setattr(demo, "PostgresStore", lambda url: store)
    monkeypatch.setattr(demo, "BedrockTitanEmbedder", lambda *args: embedder)
    monkeypatch.setattr(demo, "DeterministicEmbedder", lambda: embedder)
    monkeypatch.setattr(demo, "seed_memories", lambda actual_store, actual_embedder: None)
    demo.main()
    store.close.assert_called_once_with()


def test_migrate_main_uses_environment_and_prints(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("RECALLOPS_DATABASE_URL", "postgresql://db")
    monkeypatch.setenv("RECALLOPS_MIGRATIONS_DIR", "/tmp/migrations")
    monkeypatch.setattr(migrate, "apply_migrations", lambda url, directory: ["001.sql"])
    migrate.main()
    assert capsys.readouterr().out == "applied 001.sql\n"


def reembed_settings() -> SimpleNamespace:
    return SimpleNamespace(
        database_url="postgresql://db",
        aws_region="us-east-1",
        bedrock_embedding_model_id="model",
        provider_connect_timeout_seconds=1,
        provider_read_timeout_seconds=2,
        provider_max_attempts=3,
    )


def test_reembed_count_rejects_missing_row(monkeypatch: pytest.MonkeyPatch) -> None:
    cursor = MagicMock()
    cursor.fetchone.return_value = None
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.cursor.return_value.__enter__.return_value = cursor
    monkeypatch.setattr(reembed.psycopg, "connect", lambda *args, **kwargs: connection)
    with pytest.raises(RuntimeError, match="no row"):
        reembed.count_legacy("postgresql://db")


def test_reembed_count_returns_integer(monkeypatch: pytest.MonkeyPatch) -> None:
    cursor = MagicMock()
    cursor.fetchone.return_value = (3,)
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.cursor.return_value.__enter__.return_value = cursor
    monkeypatch.setattr(reembed.psycopg, "connect", lambda *args, **kwargs: connection)
    assert reembed.count_legacy("postgresql://db") == 3


def test_reembed_main_dry_run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["recallops-reembed"])
    monkeypatch.setattr(reembed, "Settings", reembed_settings)
    monkeypatch.setattr(reembed, "count_legacy", lambda url: 2)
    reembed.main()
    assert "dry-run: 2" in capsys.readouterr().out


def test_reembed_main_applies_until_empty(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["recallops-reembed", "--apply", "--batch-size", "2"])
    monkeypatch.setattr(reembed, "Settings", reembed_settings)
    monkeypatch.setattr(reembed, "BedrockTitanEmbedder", lambda *args: MagicMock())
    remaining = iter([2, 0])
    monkeypatch.setattr(reembed, "count_legacy", lambda url: next(remaining))
    monkeypatch.setattr(reembed, "reembed_batch", lambda *args: 2)
    reembed.main()
    assert "re-embedded=2 remaining=0" in capsys.readouterr().out


def test_reembed_main_rejects_stalled_and_invalid_batches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reembed, "Settings", reembed_settings)
    monkeypatch.setattr(reembed, "BedrockTitanEmbedder", lambda *args: MagicMock())
    monkeypatch.setattr(reembed, "count_legacy", lambda url: 1)
    monkeypatch.setattr(reembed, "reembed_batch", lambda *args: 0)
    monkeypatch.setattr(sys, "argv", ["recallops-reembed", "--apply"])
    with pytest.raises(RuntimeError, match="no compare-and-set"):
        reembed.main()
    monkeypatch.setattr(sys, "argv", ["recallops-reembed", "--batch-size", "0"])
    with pytest.raises(SystemExit):
        reembed.main()


def outbox_settings(bucket: str | None = "bucket") -> SimpleNamespace:
    return SimpleNamespace(
        database_url="postgresql://db",
        evidence_bucket=bucket,
        aws_region="us-east-1",
        provider_connect_timeout_seconds=1,
        provider_read_timeout_seconds=2,
        provider_max_attempts=3,
        outbox_max_attempts=8,
        outbox_lease_seconds=120,
    )


def test_outbox_main_status_and_single_delivery(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(outbox, "Settings", outbox_settings)
    monkeypatch.setattr(outbox, "status", lambda url: {"pending": 0})
    monkeypatch.setattr(sys, "argv", ["recallops-outbox", "--status"])
    outbox.main()
    assert "pending" in capsys.readouterr().out

    monkeypatch.setattr(outbox, "S3EvidenceArchive", lambda *args: MagicMock())
    monkeypatch.setattr(outbox, "deliver_available", lambda *args: (1, 0))
    monkeypatch.setattr(sys, "argv", ["recallops-outbox", "--limit", "1"])
    outbox.main()
    assert "delivered=1 failed=0" in capsys.readouterr().out


def test_outbox_main_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(outbox, "Settings", lambda: outbox_settings(None))
    for args in (["--limit", "0"], ["--poll-seconds", "0"], []):
        monkeypatch.setattr(sys, "argv", ["recallops-outbox", *args])
        with pytest.raises(SystemExit):
            outbox.main()


def test_outbox_watch_sleeps_when_idle(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(outbox, "Settings", outbox_settings)
    monkeypatch.setattr(outbox, "S3EvidenceArchive", lambda *args: MagicMock())
    monkeypatch.setattr(outbox, "deliver_available", lambda *args: (0, 0))
    monkeypatch.setattr(sys, "argv", ["recallops-outbox", "--watch", "--poll-seconds", "1"])
    monkeypatch.setattr(
        outbox.time,
        "sleep",
        MagicMock(side_effect=RuntimeError("stop after proving idle polling")),
    )
    with pytest.raises(RuntimeError, match="idle polling"):
        outbox.main()
    outbox.time.sleep.assert_called_once_with(1.0)
