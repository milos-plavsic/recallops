import argparse
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from recallops.store import memory_rank_score


class Candidate(BaseModel):
    id: str
    similarity: float = Field(ge=-1, le=1)
    outcome_score: float = Field(ge=-1, le=1)
    confidence: float = Field(ge=0, le=1)
    compatibility: float = Field(ge=0, le=1)
    eligible: bool
    unsafe: bool

    @property
    def recallops_score(self) -> float:
        return memory_rank_score(
            self.similarity,
            self.outcome_score,
            self.compatibility,
            self.confidence,
        )


class EvaluationCase(BaseModel):
    name: str
    expected_memory_id: str | None
    candidates: list[Candidate] = Field(min_length=1)


class EvaluationDataset(BaseModel):
    schema_version: Literal[1]
    cases: list[EvaluationCase] = Field(min_length=1)


class PolicyMetrics(BaseModel):
    top1_safe_accuracy: float
    unsafe_selection_rate: float
    mean_reciprocal_rank: float
    isolation_violations: int


class EvaluationReport(BaseModel):
    dataset_schema_version: int
    case_count: int
    similarity_only: PolicyMetrics
    recallops: PolicyMetrics
    accuracy_improvement: float
    unsafe_selection_reduction: float
    passed: bool


def _rank(case: EvaluationCase, policy: Literal["similarity", "recallops"]) -> list[Candidate]:
    candidates = [candidate for candidate in case.candidates if candidate.eligible]
    key = (
        (lambda candidate: candidate.similarity)
        if policy == "similarity"
        else (lambda candidate: candidate.recallops_score)
    )
    return sorted(candidates, key=key, reverse=True)


def _select(
    ranked: list[Candidate], policy: Literal["similarity", "recallops"]
) -> Candidate | None:
    if not ranked:
        return None
    best = ranked[0]
    if policy == "recallops" and (best.compatibility < 1.0 or best.outcome_score <= 0):
        return None
    return best


def evaluate_policy(
    cases: list[EvaluationCase], policy: Literal["similarity", "recallops"]
) -> PolicyMetrics:
    correct = 0
    unsafe = 0
    reciprocal_ranks: list[float] = []
    isolation_violations = 0
    for case in cases:
        ranked = _rank(case, policy)
        selected = _select(ranked, policy)
        selected_id = selected.id if selected else None
        correct += selected_id == case.expected_memory_id
        unsafe += bool(selected and selected.unsafe)
        isolation_violations += bool(selected and not selected.eligible)
        if case.expected_memory_id is not None:
            position = next(
                (
                    index
                    for index, candidate in enumerate(ranked, start=1)
                    if candidate.id == case.expected_memory_id
                ),
                None,
            )
            reciprocal_ranks.append(1 / position if position else 0.0)
    count = len(cases)
    return PolicyMetrics(
        top1_safe_accuracy=correct / count,
        unsafe_selection_rate=unsafe / count,
        mean_reciprocal_rank=sum(reciprocal_ranks) / len(reciprocal_ranks),
        isolation_violations=isolation_violations,
    )


def evaluate(dataset: EvaluationDataset) -> EvaluationReport:
    baseline = evaluate_policy(dataset.cases, "similarity")
    recallops = evaluate_policy(dataset.cases, "recallops")
    return EvaluationReport(
        dataset_schema_version=dataset.schema_version,
        case_count=len(dataset.cases),
        similarity_only=baseline,
        recallops=recallops,
        accuracy_improvement=recallops.top1_safe_accuracy - baseline.top1_safe_accuracy,
        unsafe_selection_reduction=(
            baseline.unsafe_selection_rate - recallops.unsafe_selection_rate
        ),
        passed=(
            recallops.top1_safe_accuracy == 1.0
            and recallops.unsafe_selection_rate == 0.0
            and recallops.isolation_violations == 0
            and recallops.top1_safe_accuracy > baseline.top1_safe_accuracy
        ),
    )


def load_dataset(path: Path) -> EvaluationDataset:
    return EvaluationDataset.model_validate_json(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare RecallOps memory ranking with similarity RAG"
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path("evaluation/memory_cases.json"),
    )
    args = parser.parse_args()
    report = evaluate(load_dataset(args.dataset))
    print(json.dumps(report.model_dump(), indent=2, sort_keys=True))
    if not report.passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
