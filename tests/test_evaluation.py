import json
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import recallops.evaluation as evaluation
from recallops.evaluation import (
    evaluate,
    load_dataset,
    load_end_to_end_dataset,
    run_end_to_end,
)


def test_recallops_outperforms_similarity_only_on_safety_cases() -> None:
    report = evaluate(load_dataset(Path("evaluation/memory_cases.json")))
    assert report.passed is True
    assert report.recallops.top1_safe_accuracy == 1.0
    assert report.recallops.unsafe_selection_rate == 0.0
    assert report.recallops.isolation_violations == 0
    assert report.accuracy_improvement > 0
    assert report.unsafe_selection_reduction > 0


def test_similarity_baseline_selects_known_unsafe_memories() -> None:
    report = evaluate(load_dataset(Path("evaluation/memory_cases.json")))
    assert report.similarity_only.unsafe_selection_rate > 0
    assert report.similarity_only.top1_safe_accuracy < 1.0


def test_committed_policy_artifact_cannot_drift_from_executable_suite() -> None:
    report = evaluate(load_dataset(Path("evaluation/memory_cases.json")))
    artifact = json.loads(
        Path("evaluation/policy_invariants.report.json").read_text(encoding="utf-8")
    )

    assert report.model_dump(mode="json") == artifact


def test_isolation_probe_is_not_tautological() -> None:
    report = evaluate(load_dataset(Path("evaluation/memory_cases.json")))

    assert report.similarity_only.isolation_violations == 1
    assert report.similarity_only.eligibility_violations == 2
    assert report.ablations["governed_similarity"].isolation_violations == 0


def test_end_to_end_suite_executes_real_service_and_store_path() -> None:
    report = run_end_to_end(load_end_to_end_dataset(Path("evaluation/end_to_end_cases.json")))

    assert report.passed is True
    assert report.metrics.top1_safe_accuracy == 1.0
    assert report.metrics.expected_memory_recall_at_k == 1.0
    assert report.metrics.correct_abstention_rate == 1.0
    assert report.metrics.isolation_violations == 0
    assert report.metrics.governance_violations == 0
    assert {case.name for case in report.cases} == {
        "successful_outcome_beats_identical_failure",
        "exact_version_lane_survives_obsolete_neighbours",
        "failure_only_forces_abstention",
        "tenant_and_governance_filters_execute_in_store",
        "ambiguous_successes_force_abstention",
        "weak_evidence_forces_abstention",
    }


def test_empty_inputs_have_explicit_zero_metrics() -> None:
    assert evaluation._select([], "recallops") is None
    assert evaluation._percentile([], 0.95) == 0.0
    incompatible = evaluation.Candidate(
        id="old",
        tenant_id="demo",
        state="active",
        valid=True,
        eligible=True,
        similarity=1.0,
        outcome_score=1.0,
        compatibility=0.5,
        confidence=1.0,
        unsafe=False,
    )
    assert evaluation._select([incompatible], "recallops") is None


def test_evaluation_cli_runs_both_modes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["recallops-evaluate", "--dataset", "evaluation/memory_cases.json"],
    )
    evaluation.main()
    assert '"passed": true' in capsys.readouterr().out

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "recallops-evaluate",
            "--mode",
            "end-to-end",
            "--end-to-end-dataset",
            "evaluation/end_to_end_cases.json",
        ],
    )
    evaluation.main()
    assert '"backend": "in_memory"' in capsys.readouterr().out


def test_evaluation_cli_database_lifecycle_and_failure_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[bool] = []

    class FakeStore:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def close(self) -> None:
            closed.append(True)

    report = SimpleNamespace(passed=True, model_dump=lambda: {"passed": True})
    monkeypatch.setattr(evaluation, "PostgresStore", FakeStore)
    monkeypatch.setattr(evaluation, "run_end_to_end", lambda *args, **kwargs: report)
    monkeypatch.setattr(
        sys,
        "argv",
        ["recallops-evaluate", "--mode", "end-to-end", "--database-url", "postgres://db"],
    )
    evaluation.main()
    assert closed == [True]

    failed = SimpleNamespace(passed=False, model_dump=lambda: {"passed": False})
    monkeypatch.setattr(evaluation, "evaluate", lambda dataset: failed)
    monkeypatch.setattr(sys, "argv", ["recallops-evaluate"])
    with pytest.raises(SystemExit, match="1"):
        evaluation.main()


def test_evaluation_module_entry_point(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["recallops.evaluation", "--dataset", "evaluation/memory_cases.json"],
    )
    runpy.run_path(str(evaluation.__file__), run_name="__main__")
