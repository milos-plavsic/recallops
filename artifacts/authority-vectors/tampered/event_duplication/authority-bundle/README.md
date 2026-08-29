# RecallOps authority bundle

Verify offline with the repository-pinned key registry:

    node tools/verify-authority-bundle.mjs <bundle-directory> --registry <trusted-keys.json>

The receipt proves integrity and the supplied accepted authority prefix. It does not prove
external truth, physical human identity, trusted time, completeness of denied attempts, or
production-remediation safety. The scenario and evaluation are synthetic.
