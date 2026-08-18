# Mutation-testing evidence

RecallOps mutation-tests the decision, evidence-verification, and storage modules in addition to
requiring 100% statement and branch coverage. Run:

```bash
uv run mutmut run
uv run mutmut export-cicd-stats
```

The measured baseline killed 1,035 of 1,416 generated mutants (73.09%), with no timeouts,
untested mutants, suspicious exits, or skipped mutants. Surviving mutants are not represented as
passing behavior: they form an explicit test-improvement backlog. CI requires at least 70% and
publishes the machine-readable result for every run.

The mutation scope deliberately excludes generated surfaces, CLI wiring, and OIDC cryptographic
verification. Those remain covered by ordinary tests; the RSA library test is incompatible with
mutmut's import instrumentation. This limitation is stated instead of weakening the authentication
test or claiming a repository-wide mutation score.
