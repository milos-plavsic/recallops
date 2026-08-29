import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from recallops import db_verify


def cursor_with(rows: list[tuple[object, ...]]) -> MagicMock:
    cursor = MagicMock()
    cursor.fetchall.return_value = rows
    return cursor


def test_grant_and_role_drift_fail_closed() -> None:
    with pytest.raises(AssertionError, match="runtime grant drift"):
        db_verify._verify_exact_grants(cursor_with([]))
    unsafe_roles = [
        ("recallops_api", True, False, False, False),
        ("recallops_outbox", False, False, False, False),
    ]
    with pytest.raises(AssertionError, match="unsafe runtime role attributes"):
        db_verify._verify_role_attributes(cursor_with(unsafe_roles))


def routine_cursor(
    *,
    create_statement: str = "CREATE FUNCTION x() SECURITY DEFINER AS 'SELECT 1'",
    owners: list[tuple[object, ...]] | None = None,
    function_grants: list[tuple[object, ...]] | None = None,
    schema_grants: list[tuple[object, ...]] | None = None,
) -> MagicMock:
    cursor = MagicMock()
    cursor.fetchone.return_value = ("recallops_govern_memory", create_statement)
    cursor.fetchall.side_effect = [
        owners if owners is not None else [("recallops_governor",)],
        function_grants
        if function_grants is not None
        else [
            ("db", "public", 1, "signature", "recallops_api", "EXECUTE", False),
            ("db", "public", 1, "signature", "recallops_governor", "ALL", False),
        ],
        schema_grants
        if schema_grants is not None
        else [("db", "public", "recallops_governor", "USAGE", False)],
    ]
    return cursor


def test_governance_routine_metadata_is_verified_exactly() -> None:
    assert db_verify._verify_governance_routine(routine_cursor()) == {
        "name": "recallops_govern_memory",
        "owner": "recallops_governor",
        "security": "DEFINER",
        "api_execute_only": True,
        "public_execute": False,
        "governor_schema_create": False,
    }

    with pytest.raises(AssertionError, match="not SECURITY DEFINER"):
        db_verify._verify_governance_routine(
            routine_cursor(create_statement="CREATE FUNCTION x() SECURITY INVOKER")
        )
    with pytest.raises(AssertionError, match="unsafe governance routine owner"):
        db_verify._verify_governance_routine(routine_cursor(owners=[("root",)]))
    with pytest.raises(AssertionError, match="unsafe governance routine grants"):
        db_verify._verify_governance_routine(
            routine_cursor(
                function_grants=[
                    ("db", "public", 1, "signature", "public", "EXECUTE", False)
                ]
            )
        )
    with pytest.raises(AssertionError, match="unsafe governor schema grants"):
        db_verify._verify_governance_routine(
            routine_cursor(
                schema_grants=[
                    ("db", "public", "recallops_governor", "CREATE", False),
                    ("db", "public", "recallops_governor", "USAGE", False),
                ]
            )
        )


def test_expected_database_rejections_must_actually_reject(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = MagicMock()
    connection.transaction.return_value.__enter__.return_value = None
    connection.cursor.return_value.__enter__.return_value = MagicMock()
    with pytest.raises(AssertionError, match="unexpectedly passed"):
        db_verify._expect_fk_rejection(connection, "SELECT 1", (), "expected_fk")

    monkeypatch.setattr(db_verify.psycopg, "connect", lambda *args, **kwargs: connection)
    with pytest.raises(AssertionError, match="unexpectedly executed"):
        db_verify._expect_insufficient_privilege("postgres://test", "role", "SELECT 1")

    class FakeForeignKeyViolation(Exception):
        def __init__(self) -> None:
            self.diag = SimpleNamespace(constraint_name="wrong_fk")

    rejecting = MagicMock()
    rejecting.transaction.return_value.__enter__.return_value = None
    rejecting.cursor.return_value.__enter__.return_value.execute.side_effect = (
        FakeForeignKeyViolation()
    )
    monkeypatch.setattr(
        db_verify.psycopg.errors, "ForeignKeyViolation", FakeForeignKeyViolation
    )
    with pytest.raises(AssertionError, match="expected expected_fk, got wrong_fk"):
        db_verify._expect_fk_rejection(rejecting, "INSERT", (), "expected_fk")


def test_database_verifier_cli_writes_sanitized_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "report.json"
    report = {"schema": "test", "passed": True}
    monkeypatch.setattr(db_verify, "verify_database_boundaries", lambda url: report)
    monkeypatch.setattr(
        sys,
        "argv",
        ["recallops-db-verify", "--database-url", "postgres://test", "--output", str(output)],
    )
    db_verify.main()
    assert output.read_text(encoding="utf-8") == capsys.readouterr().out
    assert '"passed": true' in output.read_text(encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["recallops-db-verify", "--database-url", "postgres://test"])
    db_verify.main()
    assert '"passed": true' in capsys.readouterr().out


def test_database_verifier_cli_requires_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("RECALLOPS_DATABASE_URL", raising=False)
    monkeypatch.setattr(sys, "argv", ["recallops-db-verify"])
    with pytest.raises(SystemExit, match="2"):
        db_verify.main()
