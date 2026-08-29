import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from recallops.canonical import canonical_bytes
from recallops.release_evidence import ReleaseIdentity, ReleaseStatement

ROOT = Path(__file__).resolve().parents[1]


def script_module() -> ModuleType:
    path = ROOT / "scripts" / "sign-release-statement.py"
    spec = importlib.util.spec_from_file_location("sign_release_statement", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def statement() -> ReleaseStatement:
    return ReleaseStatement(
        identity=ReleaseIdentity(
            release_id="release-v1",
            source_sha="a" * 40,
            image_digest=f"sha256:{'b' * 64}",
            capability_policy_version="capability-v1",
            receipt_policy_version="receipt-v1",
            evaluation_version="evaluation-v1",
            receipt_key_thumbprint="C" * 43,
        ),
        live_proof_complete=False,
        live_proof_artifact_digest="d" * 64,
        assurance_complete=False,
        assurance_artifact_digest="e" * 64,
        release_ready=False,
    )


def test_release_statement_script_accepts_only_exact_canonical_payload(tmp_path: Path) -> None:
    module = script_module()
    expected = statement()
    canonical = tmp_path / "canonical.jcs.json"
    canonical.write_bytes(canonical_bytes(expected.model_dump(mode="json")))
    loaded, raw = module.load_canonical_statement(canonical)
    assert loaded == expected
    assert raw == canonical.read_bytes()

    noncanonical = tmp_path / "noncanonical.json"
    noncanonical.write_text(expected.model_dump_json(indent=2))
    with pytest.raises(ValueError, match="canonical"):
        module.load_canonical_statement(noncanonical)
