import hashlib
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import psycopg
import pytest
from pydantic import ValidationError

from recallops.migrate import (
    RELEASE_IDENTITY_ENVIRONMENT,
    apply_migrations,
    main,
    register_release_evidence,
    release_identity_from_environment,
)
from recallops.release_evidence import ReleaseIdentity


def release_identity() -> ReleaseIdentity:
    return ReleaseIdentity(
        release_id="webmcp-rc6",
        source_sha="a" * 40,
        image_digest=f"sha256:{'b' * 64}",
        capability_policy_version="webmcp-capability-v1",
        receipt_policy_version="authority-receipt-policy-v1",
        evaluation_version="governed-benchmark-v1",
        receipt_key_thumbprint="c" * 43,
    )


def release_environment() -> dict[str, str]:
    identity = release_identity().model_dump()
    return {
        environment_name: identity[field]
        for field, environment_name in RELEASE_IDENTITY_ENVIRONMENT.items()
    }


def connection_with_fetches(*fetches: object) -> tuple[MagicMock, MagicMock]:
    cursor = MagicMock()
    cursor.fetchone.side_effect = fetches
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.cursor.return_value.__enter__.return_value = cursor
    return connection, cursor


def test_release_identity_environment_is_optional() -> None:
    assert release_identity_from_environment({}) is None


def test_release_identity_environment_requires_every_field() -> None:
    environment = release_environment()
    del environment["RECALLOPS_RECEIPT_KEY_THUMBPRINT"]
    with pytest.raises(RuntimeError, match="RECALLOPS_RECEIPT_KEY_THUMBPRINT"):
        release_identity_from_environment(environment)


def test_release_identity_environment_validates_values() -> None:
    environment = release_environment()
    environment["RECALLOPS_BUILD_SHA"] = "not-a-sha"
    with pytest.raises(ValidationError):
        release_identity_from_environment(environment)


def test_registers_new_pending_release_identity() -> None:
    identity = release_identity()
    expected = tuple(identity.model_dump().values())
    connection, cursor = connection_with_fetches((identity.release_id,), expected)
    with patch("recallops.migrate.psycopg.connect", return_value=connection):
        assert register_release_evidence("postgresql://database", identity) is True
    insert = cursor.execute.call_args_list[0]
    assert "'pending','pending'" in insert.args[0]
    assert "ON CONFLICT (release_id) DO NOTHING" in insert.args[0]
    assert insert.args[1] == expected


def test_exact_release_identity_retry_is_idempotent() -> None:
    identity = release_identity()
    expected = tuple(identity.model_dump().values())
    connection, _ = connection_with_fetches(None, expected)
    with patch("recallops.migrate.psycopg.connect", return_value=connection):
        assert register_release_evidence("postgresql://database", identity) is False


@pytest.mark.parametrize(
    "actual",
    [
        None,
        ("different-release",) + tuple(release_identity().model_dump().values())[1:],
    ],
)
def test_release_identity_conflict_fails_closed(actual: object) -> None:
    identity = release_identity()
    connection, _ = connection_with_fetches(None, actual)
    with (
        patch("recallops.migrate.psycopg.connect", return_value=connection),
        pytest.raises(RuntimeError, match="immutable existing record"),
    ):
        register_release_evidence("postgresql://database", identity)


def test_release_registration_retries_serialization_with_fresh_connection() -> None:
    identity = release_identity()
    expected = tuple(identity.model_dump().values())
    failing, failing_cursor = connection_with_fetches()
    failing_cursor.execute.side_effect = psycopg.errors.SerializationFailure()
    succeeding, _ = connection_with_fetches((identity.release_id,), expected)
    with (
        patch("recallops.migrate.psycopg.connect", side_effect=[failing, succeeding]) as connect,
        patch("recallops.migrate.time.sleep") as sleep,
    ):
        assert register_release_evidence("postgresql://database", identity) is True
    assert connect.call_count == 2
    sleep.assert_called_once_with(0.05)


def test_release_registration_exhausts_serialization_retry_budget() -> None:
    identity = release_identity()
    connection, cursor = connection_with_fetches()
    cursor.execute.side_effect = psycopg.errors.SerializationFailure()
    with (
        patch("recallops.migrate.psycopg.connect", return_value=connection) as connect,
        patch("recallops.migrate.time.sleep") as sleep,
        pytest.raises(psycopg.errors.SerializationFailure),
    ):
        register_release_evidence("postgresql://database", identity)
    assert connect.call_count == 5
    assert [call.args[0] for call in sleep.call_args_list] == [0.05, 0.1, 0.2, 0.4]


def test_main_migrates_without_release_bootstrap(tmp_path: Path) -> None:
    environment = {
        "RECALLOPS_DATABASE_URL": "postgresql://database",
        "RECALLOPS_MIGRATIONS_DIR": str(tmp_path),
    }
    with (
        patch.dict(os.environ, environment, clear=True),
        patch("recallops.migrate.apply_migrations", return_value=[]),
        patch("recallops.migrate.register_release_evidence") as register,
    ):
        main()
    register.assert_not_called()


@pytest.mark.parametrize("inserted,word", [(True, "registered"), (False, "verified")])
def test_main_bootstraps_release_after_migrations(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], inserted: bool, word: str
) -> None:
    environment = release_environment() | {
        "RECALLOPS_DATABASE_URL": "postgresql://database",
        "RECALLOPS_MIGRATIONS_DIR": str(tmp_path),
    }
    with (
        patch.dict(os.environ, environment, clear=True),
        patch("recallops.migrate.apply_migrations", return_value=["030_receipts_release.sql"]),
        patch("recallops.migrate.register_release_evidence", return_value=inserted) as register,
    ):
        main()
    register.assert_called_once_with("postgresql://database", release_identity())
    assert capsys.readouterr().out.splitlines() == [
        "applied 030_receipts_release.sql",
        f"{word} release evidence webmcp-rc6",
    ]


def test_main_rejects_partial_identity_before_migrations(tmp_path: Path) -> None:
    environment = {
        "RECALLOPS_DATABASE_URL": "postgresql://database",
        "RECALLOPS_MIGRATIONS_DIR": str(tmp_path),
        "RECALLOPS_BUILD_SHA": "a" * 40,
    }
    with (
        patch.dict(os.environ, environment, clear=True),
        patch("recallops.migrate.apply_migrations") as migrate,
        pytest.raises(RuntimeError, match="bootstrap identity is incomplete"),
    ):
        main()
    migrate.assert_not_called()


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
