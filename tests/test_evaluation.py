from pathlib import Path

from recallops.evaluation import evaluate, load_dataset


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
