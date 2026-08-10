import argparse
import json
import os
import random
import time
from collections.abc import Callable
from pathlib import Path
from statistics import fmean
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from recallops.domain import IncidentCreate, Memory, MemoryState
from recallops.embedding import DeterministicEmbedder
from recallops.service import DeterministicReasoner, IncidentService
from recallops.store import InMemoryStore, MemoryStore, PostgresStore, memory_rank_score

PolicyName = Literal[
    "similarity",
    "governed_similarity",
    "outcome_aware",
    "outcome_compatibility",
    "recallops",
]


class Candidate(BaseModel):
    id: str
    similarity: float = Field(ge=-1, le=1)
    outcome_score: float = Field(ge=-1, le=1)
    confidence: float = Field(ge=0, le=1)
    compatibility: float = Field(ge=0, le=1)
    eligible: bool
    unsafe: bool
    boundary_violation: bool = False

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
    schema_version: Literal[2]
    suite_kind: Literal["synthetic_policy_invariants"]
    cases: list[EvaluationCase] = Field(min_length=1)


class PolicyMetrics(BaseModel):
    top1_safe_accuracy: float
    unsafe_selection_rate: float
    mean_reciprocal_rank: float
    isolation_violations: int
    eligibility_violations: int = 0
    selection_coverage: float = 0.0
    correct_abstention_rate: float = 0.0


class EvaluationReport(BaseModel):
    dataset_schema_version: int
    suite_kind: str
    case_count: int
    similarity_only: PolicyMetrics
    recallops: PolicyMetrics
    ablations: dict[str, PolicyMetrics]
    accuracy_improvement: float
    unsafe_selection_reduction: float
    passed: bool


def _score(candidate: Candidate, policy: PolicyName) -> float:
    if policy in {"similarity", "governed_similarity"}:
        return candidate.similarity
    if policy == "outcome_aware":
        return 0.7 * candidate.similarity + 0.3 * candidate.outcome_score
    if policy == "outcome_compatibility":
        return (
            0.6 * candidate.similarity
            + 0.25 * candidate.outcome_score
            + 0.15 * candidate.compatibility
        )
    return candidate.recallops_score


def _rank(case: EvaluationCase, policy: PolicyName) -> list[Candidate]:
    # The raw similarity control intentionally models an ungoverned vector lookup.
    # Every fair ablation uses the same eligibility filter as RecallOps.
    candidates = (
        case.candidates
        if policy == "similarity"
        else [candidate for candidate in case.candidates if candidate.eligible]
    )
    return sorted(
        candidates,
        key=lambda candidate: (_score(candidate, policy), candidate.id),
        reverse=True,
    )


def _select(ranked: list[Candidate], policy: PolicyName) -> Candidate | None:
    if not ranked:
        return None
    best = ranked[0]
    if (
        policy in {"outcome_aware", "outcome_compatibility", "recallops"}
        and best.outcome_score <= 0
    ):
        return None
    if policy in {"outcome_compatibility", "recallops"} and best.compatibility < 1.0:
        return None
    return best


def evaluate_policy(cases: list[EvaluationCase], policy: PolicyName) -> PolicyMetrics:
    correct = 0
    unsafe = 0
    selections = 0
    reciprocal_ranks: list[float] = []
    isolation_violations = 0
    eligibility_violations = 0
    abstentions = 0
    correct_abstentions = 0
    for case in cases:
        ranked = _rank(case, policy)
        selected = _select(ranked, policy)
        selected_id = selected.id if selected else None
        correct += selected_id == case.expected_memory_id
        selections += selected is not None
        unsafe += bool(selected and selected.unsafe)
        isolation_violations += bool(selected and selected.boundary_violation)
        eligibility_violations += bool(selected and not selected.eligible)
        if case.expected_memory_id is None:
            abstentions += 1
            correct_abstentions += selected is None
        else:
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
        mean_reciprocal_rank=fmean(reciprocal_ranks) if reciprocal_ranks else 0.0,
        isolation_violations=isolation_violations,
        eligibility_violations=eligibility_violations,
        selection_coverage=selections / count,
        correct_abstention_rate=(correct_abstentions / abstentions if abstentions else 1.0),
    )


def evaluate(dataset: EvaluationDataset) -> EvaluationReport:
    metrics = {
        policy: evaluate_policy(dataset.cases, policy)
        for policy in (
            "similarity",
            "governed_similarity",
            "outcome_aware",
            "outcome_compatibility",
            "recallops",
        )
    }
    baseline = metrics["similarity"]
    recallops = metrics["recallops"]
    return EvaluationReport(
        dataset_schema_version=dataset.schema_version,
        suite_kind=dataset.suite_kind,
        case_count=len(dataset.cases),
        similarity_only=baseline,
        recallops=recallops,
        ablations=metrics,
        accuracy_improvement=recallops.top1_safe_accuracy - baseline.top1_safe_accuracy,
        unsafe_selection_reduction=(
            baseline.unsafe_selection_rate - recallops.unsafe_selection_rate
        ),
        passed=(
            recallops.top1_safe_accuracy == 1.0
            and recallops.unsafe_selection_rate == 0.0
            and recallops.isolation_violations == 0
            and recallops.eligibility_violations == 0
            and recallops.top1_safe_accuracy > baseline.top1_safe_accuracy
        ),
    )


class BenchmarkMemory(BaseModel):
    name: str
    tenant_scope: Literal["same", "other"] = "same"
    service: str | None = None
    service_version: str
    symptom: str
    action: str
    outcome: str
    outcome_score: float = Field(ge=-1, le=1)
    confidence: float = Field(ge=0, le=1)
    state: MemoryState = MemoryState.ACTIVE
    valid: bool = True
    unsafe: bool = False


class EndToEndCase(BaseModel):
    name: str
    category: str = "unspecified"
    service: str
    service_version: str
    symptom: str
    expected_memory_name: str | None
    expected_abstention_reasons: list[str] = Field(default_factory=list)
    memories: list[BenchmarkMemory] = Field(min_length=1)


class EndToEndDataset(BaseModel):
    schema_version: Literal[1]
    suite_kind: Literal["end_to_end_retrieval"]
    cases: list[EndToEndCase] = Field(min_length=1)
    provenance: dict[str, str] = Field(default_factory=dict)


class EndToEndCaseResult(BaseModel):
    name: str
    category: str
    expected_memory_name: str | None
    selected_memory_name: str | None
    retrieved_memory_names: list[str]
    abstention_reasons: list[str]
    safe: bool
    correct: bool
    expected_abstention: bool
    selected_unsafe: bool
    decision_confidence: float = Field(ge=0, le=1)
    latency_ms: float


class ConfidenceInterval(BaseModel):
    lower: float
    upper: float


class CalibrationBin(BaseModel):
    lower: float
    upper: float
    count: int
    mean_confidence: float
    empirical_accuracy: float


class EndToEndMetrics(BaseModel):
    top1_safe_accuracy: float
    unsafe_selection_rate: float
    correct_abstention_rate: float
    abstention_precision: float
    abstention_recall: float
    expected_memory_recall_at_k: float
    isolation_violations: int
    governance_violations: int
    latency_mean_ms: float
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    brier_score: float
    expected_calibration_error: float
    calibration_bins: list[CalibrationBin]
    bootstrap_95pct: dict[str, ConfidenceInterval]


class EndToEndReport(BaseModel):
    dataset_schema_version: int
    suite_kind: str
    backend: str
    provenance: dict[str, str]
    case_count: int
    metrics: EndToEndMetrics
    cases: list[EndToEndCaseResult]
    passed: bool


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = round((len(ordered) - 1) * percentile)
    return ordered[index]


def _calibration(results: list[EndToEndCaseResult]) -> tuple[float, list[CalibrationBin]]:
    bins: list[CalibrationBin] = []
    weighted_gap = 0.0
    for index in range(10):
        lower = index / 10
        upper = (index + 1) / 10
        members = [
            result
            for result in results
            if lower <= result.decision_confidence <= upper
            and (index == 9 or result.decision_confidence < upper)
        ]
        if not members:
            continue
        mean_confidence = fmean(result.decision_confidence for result in members)
        empirical_accuracy = fmean(float(result.correct) for result in members)
        weighted_gap += len(members) * abs(mean_confidence - empirical_accuracy)
        bins.append(
            CalibrationBin(
                lower=lower,
                upper=upper,
                count=len(members),
                mean_confidence=mean_confidence,
                empirical_accuracy=empirical_accuracy,
            )
        )
    return weighted_gap / len(results), bins


def _bootstrap_intervals(
    results: list[EndToEndCaseResult], *, samples: int = 2000, seed: int = 20260810
) -> dict[str, ConfidenceInterval]:
    rng = random.Random(seed)
    estimates: dict[str, list[float]] = {
        "top1_safe_accuracy": [],
        "unsafe_selection_rate": [],
        "latency_p95_ms": [],
    }
    for _ in range(samples):
        sample = [rng.choice(results) for _ in results]
        estimates["top1_safe_accuracy"].append(fmean(float(item.correct) for item in sample))
        estimates["unsafe_selection_rate"].append(
            fmean(float(item.selected_unsafe) for item in sample)
        )
        estimates["latency_p95_ms"].append(
            _percentile([item.latency_ms for item in sample], 0.95)
        )
    return {
        name: ConfidenceInterval(
            lower=_percentile(values, 0.025),
            upper=_percentile(values, 0.975),
        )
        for name, values in estimates.items()
    }


def run_end_to_end(
    dataset: EndToEndDataset,
    *,
    store_factory: Callable[[], MemoryStore] | None = None,
    backend: str = "in_memory",
) -> EndToEndReport:
    """Exercise raw text through the actual embedder, store and service policy.

    A factory creates an isolated in-memory store per case. A database caller may
    return the same PostgresStore repeatedly because every case receives a unique
    tenant identifier. Database benchmarks must target a disposable migrated schema.
    """
    embedder = DeterministicEmbedder()
    factory = store_factory or InMemoryStore
    results: list[EndToEndCaseResult] = []
    isolation_violations = 0
    governance_violations = 0
    unsafe_selections = 0
    expected_retrieved = 0
    expected_count = 0
    abstention_count = 0
    correct_abstentions = 0
    run_id = uuid4().hex[:12]

    for index, case in enumerate(dataset.cases):
        store = factory()
        tenant = f"eval-{run_id}-{index}"
        other_tenant = f"eval-other-{run_id}-{index}"
        memory_ids: dict[str, object] = {}
        action_names: dict[str, str] = {}
        unsafe_actions: set[str] = set()
        for spec in case.memories:
            memory = Memory(
                tenant_id=tenant if spec.tenant_scope == "same" else other_tenant,
                service=spec.service or case.service,
                service_version=spec.service_version,
                symptom=spec.symptom,
                action=spec.action,
                outcome=spec.outcome,
                outcome_score=spec.outcome_score,
                confidence=spec.confidence,
                valid=spec.valid,
                state=spec.state,
                embedding_space=embedder.space_id,
                embedding=embedder.embed(f"{spec.service or case.service} {spec.symptom}"),
            )
            memory_ids[spec.name] = memory.id
            action_names[spec.action] = spec.name
            if spec.unsafe:
                unsafe_actions.add(spec.action)
            store.add_memory(memory)
        incident = IncidentCreate(
            tenant_id=tenant,
            service=case.service,
            service_version=case.service_version,
            symptom=case.symptom,
            idempotency_key=f"benchmark-{run_id}-{index}",
        )
        started = time.perf_counter()
        analysis = IncidentService(store, embedder, DeterministicReasoner()).analyze(incident)
        latency_ms = (time.perf_counter() - started) * 1000
        selected_name = (
            action_names.get(analysis.proposed_action.command)
            if analysis.proposed_action.requires_approval
            else None
        )
        retrieved_names = [
            next(name for name, memory_id in memory_ids.items() if memory_id == retrieved.memory.id)
            for retrieved in analysis.memories
        ]
        isolation_violations += sum(
            retrieved.memory.tenant_id != tenant for retrieved in analysis.memories
        )
        governance_violations += sum(
            not retrieved.memory.valid or retrieved.memory.state is not MemoryState.ACTIVE
            for retrieved in analysis.memories
        )
        unsafe = analysis.proposed_action.command in unsafe_actions
        unsafe_selections += unsafe
        if case.expected_memory_name is not None:
            expected_count += 1
            expected_retrieved += case.expected_memory_name in retrieved_names
        else:
            abstention_count += 1
            correct_abstentions += selected_name is None
        required_reasons_present = set(case.expected_abstention_reasons).issubset(
            analysis.retrieval_abstention_reasons
        )
        correct = selected_name == case.expected_memory_name and required_reasons_present
        results.append(
            EndToEndCaseResult(
                name=case.name,
                category=case.category,
                expected_memory_name=case.expected_memory_name,
                selected_memory_name=selected_name,
                retrieved_memory_names=retrieved_names,
                abstention_reasons=analysis.retrieval_abstention_reasons,
                safe=not unsafe,
                correct=correct,
                expected_abstention=case.expected_memory_name is None,
                selected_unsafe=unsafe,
                decision_confidence=(
                    analysis.confidence if selected_name is not None else 1 - analysis.confidence
                ),
                latency_ms=latency_ms,
            )
        )

    latencies = [result.latency_ms for result in results]
    count = len(results)
    predicted_abstentions = sum(result.selected_memory_name is None for result in results)
    true_positive_abstentions = sum(
        result.expected_abstention and result.selected_memory_name is None for result in results
    )
    calibration_error, calibration_bins = _calibration(results)
    metrics = EndToEndMetrics(
        top1_safe_accuracy=sum(result.correct for result in results) / count,
        unsafe_selection_rate=unsafe_selections / count,
        correct_abstention_rate=(
            correct_abstentions / abstention_count if abstention_count else 1.0
        ),
        abstention_precision=(
            true_positive_abstentions / predicted_abstentions if predicted_abstentions else 1.0
        ),
        abstention_recall=(
            true_positive_abstentions / abstention_count if abstention_count else 1.0
        ),
        expected_memory_recall_at_k=(
            expected_retrieved / expected_count if expected_count else 1.0
        ),
        isolation_violations=isolation_violations,
        governance_violations=governance_violations,
        latency_mean_ms=fmean(latencies),
        latency_p50_ms=_percentile(latencies, 0.50),
        latency_p95_ms=_percentile(latencies, 0.95),
        latency_p99_ms=_percentile(latencies, 0.99),
        brier_score=fmean(
            (result.decision_confidence - float(result.correct)) ** 2 for result in results
        ),
        expected_calibration_error=calibration_error,
        calibration_bins=calibration_bins,
        bootstrap_95pct=_bootstrap_intervals(results),
    )
    return EndToEndReport(
        dataset_schema_version=dataset.schema_version,
        suite_kind=dataset.suite_kind,
        backend=backend,
        provenance=dataset.provenance,
        case_count=count,
        metrics=metrics,
        cases=results,
        passed=(
            metrics.top1_safe_accuracy == 1.0
            and metrics.unsafe_selection_rate == 0.0
            and metrics.isolation_violations == 0
            and metrics.governance_violations == 0
            and metrics.expected_memory_recall_at_k == 1.0
        ),
    )


def load_dataset(path: Path) -> EvaluationDataset:
    return EvaluationDataset.model_validate_json(path.read_text(encoding="utf-8"))


def load_end_to_end_dataset(path: Path) -> EndToEndDataset:
    return EndToEndDataset.model_validate_json(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run RecallOps retrieval evaluation suites")
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path("evaluation/memory_cases.json"),
        help="synthetic policy-invariant dataset",
    )
    parser.add_argument(
        "--end-to-end-dataset",
        type=Path,
        default=Path("evaluation/end_to_end_cases.json"),
        help="raw-text end-to-end dataset",
    )
    parser.add_argument(
        "--mode",
        choices=("policy", "end-to-end"),
        default="policy",
    )
    parser.add_argument(
        "--database-url",
        default=os.getenv("RECALLOPS_EVAL_DATABASE_URL"),
        help="migrated disposable Cockroach/Postgres URL for end-to-end mode",
    )
    parser.add_argument("--candidate-multiplier", type=int, default=8)
    parser.add_argument(
        "--connect-timeout",
        type=int,
        default=30,
        help="database pool acquisition/connect timeout for evidence runs",
    )
    parser.add_argument(
        "--statement-timeout",
        type=int,
        default=60,
        help="database statement timeout for evidence runs",
    )
    args = parser.parse_args()
    if args.mode == "policy":
        report: EvaluationReport | EndToEndReport = evaluate(load_dataset(args.dataset))
    else:
        database_store = (
            PostgresStore(
                args.database_url,
                connect_timeout_seconds=args.connect_timeout,
                statement_timeout_seconds=args.statement_timeout,
                retrieval_candidate_multiplier=args.candidate_multiplier,
            )
            if args.database_url
            else None
        )
        try:
            report = run_end_to_end(
                load_end_to_end_dataset(args.end_to_end_dataset),
                store_factory=((lambda: database_store) if database_store is not None else None),
                backend="cockroach_postgres" if database_store is not None else "in_memory",
            )
        finally:
            if database_store is not None:
                database_store.close()
    print(json.dumps(report.model_dump(), indent=2, sort_keys=True))
    if not report.passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
