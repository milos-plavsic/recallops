#!/usr/bin/env python3
"""Run every fixed bundle through the network-free Node verifier."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=REPOSITORY / "artifacts" / "authority-vectors"
    )
    args = parser.parse_args()
    root = args.root.resolve()
    expected = json.loads((root / "expected-results.jcs.json").read_bytes())["vectors"]
    registry = root / "trusted-keys.jcs.json"
    results: dict[str, str] = {}
    for name, expectation in sorted(expected.items()):
        bundle = root / ("valid" if name == "valid" else f"tampered/{name}") / "authority-bundle"
        result = subprocess.run(
            [
                "node",
                "tools/verify-authority-bundle.mjs",
                str(bundle),
                "--registry",
                str(registry),
                "--bundle-digest",
                expectation["bundle_digest"],
            ],
            cwd=REPOSITORY,
            check=False,
            capture_output=True,
            text=True,
        )
        report = json.loads(result.stdout)
        expected_code = expectation["code"]
        if report.get("code") != expected_code or (name == "valid") != (result.returncode == 0):
            raise SystemExit(
                f"vector {name} expected {expected_code}, got {report.get('code')}"
            )
        results[name] = report["code"]
    print(json.dumps({"verified": len(results), "results": results}, sort_keys=True))


if __name__ == "__main__":
    main()
