from pathlib import Path
from unittest.mock import MagicMock, patch

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
