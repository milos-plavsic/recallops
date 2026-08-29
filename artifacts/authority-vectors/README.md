# Fixed authority verifier vectors

These bundles are synthetic, deterministic, and signed only by the published test key. The key is
not a production trust root. Regenerate with `uv run python scripts/generate-authority-vectors.py`
and verify with `uv run python scripts/verify-authority-vectors.py`. The valid case must pass; every
tampered case must fail with the exact code in `expected-results.jcs.json`.
