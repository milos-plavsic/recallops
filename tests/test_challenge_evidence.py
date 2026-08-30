import hashlib
import json
import subprocess
import sys
from pathlib import Path

from recallops.release_evidence import ASSURANCE_REQUIREMENTS, LIVE_REQUIREMENTS

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "generate-challenge-evidence.py"
SHA = "a" * 40
IMAGE = f"sha256:{'b' * 64}"
THUMBPRINT = "C" * 43


def run_generator(
    output: Path,
    attestations: Path | None = None,
    artifact_root: Path | None = None,
) -> dict[str, object]:
    command = [
        sys.executable,
        str(SCRIPT),
        "--release-id",
        "release-v1",
        "--source-sha",
        SHA,
        "--image-digest",
        IMAGE,
        "--key-thumbprint",
        THUMBPRINT,
        "--output-root",
        str(output),
    ]
    if attestations is not None:
        command.extend(["--attestations", str(attestations)])
    if artifact_root is not None:
        command.extend(["--artifact-root", str(artifact_root)])
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def attestation(kind: str, artifact_root: Path) -> dict[str, object]:
    relative = Path("raw") / f"{kind}.json"
    value = (json.dumps({"artifact_kind": kind, "passed": True}, sort_keys=True) + "\n").encode()
    target = artifact_root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(value)
    return {
        "artifact_kind": kind,
        "artifact_digest": hashlib.sha256(value).hexdigest(),
        "release_id": "release-v1",
        "source_sha": SHA,
        "image_digest": IMAGE,
        "passed": True,
        "path": relative.as_posix(),
    }


def test_generator_is_byte_identical_and_publishes_fair_bounded_evidence(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first_summary = run_generator(first)
    second_summary = run_generator(second)

    assert first_summary == second_summary
    assert tree_digest(first) == tree_digest(second)
    benchmark = json.loads((first / "evaluation" / "governed_benchmark.json").read_text())
    raw_cases = benchmark["cases"]
    results = benchmark["result"]
    headline = results["cases"][0]
    assert results["method"]["identical_inputs"] is True
    assert len(raw_cases) == 12
    assert headline["baseline_selected"] == "mem_47"
    assert headline["governed_selected"] == "mem_12"
    assert results["summary"]["governed_unsafe_selections"] == 0
    assert results["summary"]["governed_pending_leakage"] == 0
    assert results["summary"]["recurrence_evidence_authority_changed_after_review"] is True
    assert "recurrence_recommendation_changed_after_review" not in results["summary"]
    assert results["passed"] is True

    webmcp = json.loads((first / "evaluation" / "webmcp_cases.json").read_text())
    release_case = json.loads(
        (first / "artifacts" / "release" / "evaluation-case.jcs.json").read_text()
    )
    claims = json.loads((first / "evidence" / "claims.json").read_text())
    trace = json.loads((first / "evidence" / "requirements-trace.json").read_text())
    assert len(webmcp["cases"]) == 9
    assert release_case["evaluation_version"] == "governed-benchmark-v1"
    assert len(claims["claims"]) == 12
    assert len(trace["requirements"]) == 180
    assert all(item["claim_ids"] for item in trace["requirements"])
    assert {item["status"] for item in trace["requirements"]} == {"implemented"}
    assert not first_summary["live_proof_complete"]
    assert not first_summary["assurance_complete"]


def test_generator_completes_both_gates_only_from_exact_attestations(
    tmp_path: Path,
) -> None:
    attestations = tmp_path / "attestations.json"
    attestations.write_text(
        json.dumps(
            {
                "live": [attestation(kind, tmp_path) for kind in sorted(LIVE_REQUIREMENTS)],
                "assurance": [
                    attestation(kind, tmp_path) for kind in sorted(ASSURANCE_REQUIREMENTS)
                ],
            }
        )
    )
    complete = run_generator(tmp_path / "complete", attestations, tmp_path)
    assert complete["live_proof_complete"]
    assert complete["assurance_complete"]
    assert complete["release_ready"]

    payload = json.loads(attestations.read_text())
    payload["assurance"][0]["source_sha"] = "f" * 40
    attestations.write_text(json.dumps(payload))
    stale = run_generator(tmp_path / "stale", attestations, tmp_path)
    assert stale["live_proof_complete"]
    assert not stale["assurance_complete"]
    assert not stale["release_ready"]


def test_generator_rejects_missing_tampered_or_escaping_attestation_artifacts(
    tmp_path: Path,
) -> None:
    attestations = tmp_path / "attestations.json"
    record = attestation("deployed_journey", tmp_path)
    payload = {"live": [record], "assurance": []}
    attestations.write_text(json.dumps(payload))

    target = tmp_path / str(record["path"])
    target.write_text("tampered\n")
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--release-id",
            "release-v1",
            "--source-sha",
            SHA,
            "--image-digest",
            IMAGE,
            "--key-thumbprint",
            THUMBPRINT,
            "--attestations",
            str(attestations),
            "--artifact-root",
            str(tmp_path),
            "--output-root",
            str(tmp_path / "tampered"),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "digest does not match" in completed.stderr

    target.unlink()
    completed = subprocess.run(
        [*completed.args[:-1], str(tmp_path / "missing")],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "No such file" in completed.stderr

    outside = tmp_path.parent / "outside-gate-artifact.json"
    outside.write_text("outside\n")
    record["path"] = "../outside-gate-artifact.json"
    record["artifact_digest"] = hashlib.sha256(outside.read_bytes()).hexdigest()
    attestations.write_text(json.dumps(payload))
    completed = subprocess.run(
        [*completed.args[:-1], str(tmp_path / "escaping")],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "safe relative path" in completed.stderr
