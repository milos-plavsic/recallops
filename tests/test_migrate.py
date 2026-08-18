import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import psycopg
import pytest

from recallops.migrate import apply_migrations


def test_applies_pending_migration(tmp_path: Path) -> None:
    migration = tmp_path / "001_start.sql"
    migration.write_text("CREATE TABLE example (id INT PRIMARY KEY);", encoding="utf-8")
    cursor = MagicMock()
    cursor.fetchone.return_value = None
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.cursor.return_value.__enter__.return_value = cursor

    with patch("recallops.migrate.psycopg.connect", return_value=connection):
        assert apply_migrations("postgresql://database", tmp_path) == ["001_start.sql"]

    assert any("CREATE TABLE example" in call.args[0] for call in cursor.execute.call_args_list)
    assert any("schema_migration_lock" in call.args[0] for call in cursor.execute.call_args_list)
    assert any("FOR UPDATE" in call.args[0] for call in cursor.execute.call_args_list)


def test_commits_each_migration_in_its_own_transaction(tmp_path: Path) -> None:
    (tmp_path / "001_table.sql").write_text("CREATE TABLE example (id INT);", encoding="utf-8")
    (tmp_path / "002_column.sql").write_text(
        "ALTER TABLE example ADD COLUMN value INT;", encoding="utf-8"
    )
    cursor = MagicMock()
    cursor.fetchone.return_value = None
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.cursor.return_value.__enter__.return_value = cursor

    with patch("recallops.migrate.psycopg.connect", return_value=connection):
        assert apply_migrations("postgresql://database", tmp_path) == [
            "001_table.sql",
            "002_column.sql",
        ]

    assert connection.transaction.call_count == 2


def test_rejects_modified_applied_migration(tmp_path: Path) -> None:
    migration = tmp_path / "001_start.sql"
    migration.write_text("SELECT 1;", encoding="utf-8")
    cursor = MagicMock()
    cursor.fetchone.return_value = ("wrong-digest",)
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.cursor.return_value.__enter__.return_value = cursor

    with (
        patch("recallops.migrate.psycopg.connect", return_value=connection),
        pytest.raises(RuntimeError, match="migration changed"),
    ):
        apply_migrations("postgresql://database", tmp_path)


def test_matching_applied_migration_is_skipped(tmp_path: Path) -> None:
    migration = tmp_path / "001_start.sql"
    migration.write_text("SELECT 1;", encoding="utf-8")
    cursor = MagicMock()
    cursor.fetchone.return_value = (hashlib.sha256(b"SELECT 1;").hexdigest(),)
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.cursor.return_value.__enter__.return_value = cursor
    with patch("recallops.migrate.psycopg.connect", return_value=connection):
        assert apply_migrations("postgresql://database", tmp_path) == []


def test_serialization_failure_retries_with_bounded_backoff(tmp_path: Path) -> None:
    (tmp_path / "001_start.sql").write_text("SELECT 1;", encoding="utf-8")
    cursor = MagicMock()
    failures = iter([psycopg.errors.SerializationFailure(), None])

    def execute(query: str, parameters: object = None) -> None:
        if "schema_migration_lock WHERE" in query:
            failure = next(failures)
            if failure is not None:
                raise failure

    cursor.execute.side_effect = execute
    cursor.fetchone.return_value = None
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.cursor.return_value.__enter__.return_value = cursor
    with (
        patch("recallops.migrate.psycopg.connect", return_value=connection),
        patch("recallops.migrate.time.sleep") as sleep,
    ):
        assert apply_migrations("postgresql://database", tmp_path) == ["001_start.sql"]
    sleep.assert_called_once_with(0.05)


def test_serialization_failure_stops_after_retry_budget(tmp_path: Path) -> None:
    (tmp_path / "001_start.sql").write_text("SELECT 1;", encoding="utf-8")
    cursor = MagicMock()

    def execute(query: str, parameters: object = None) -> None:
        if "schema_migration_lock WHERE" in query:
            raise psycopg.errors.SerializationFailure()

    cursor.execute.side_effect = execute
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.cursor.return_value.__enter__.return_value = cursor
    with (
        patch("recallops.migrate.psycopg.connect", return_value=connection),
        patch("recallops.migrate.time.sleep"),
        pytest.raises(psycopg.errors.SerializationFailure),
    ):
        apply_migrations("postgresql://database", tmp_path)
