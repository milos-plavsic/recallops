# Live AWS receipt boundary proof

This directory preserves the intermediate item-8 proof that the production receipt path works
against real AWS KMS and versioned S3. It is not the final submission release and does not make the
Live proof or Assurance release gates complete.

Bound identity:

- source: `0ce35d4bbf7fe6519037c981bea6442010125fb2`
- immutable ECR image: `sha256:02842785eb4d0339a3f6e81c656c6802c394f32203d4cc85e37fe00bcd353cb6`
- repository-pinned key: `VIqQfWwrVJ8OqkQu974E2c8zdd0xw1f2W4YFkgEQCTE`
- receipt: `65df9b6d-390f-548e-ac0a-5a37fb130c99`
- bundle: `76314ee2d1cdad8cf7aaaad99db1d5254b92478744b7dff3383ef6270d0c762d`

The production worker performed a live `ED25519_SHA_512` KMS signature, locally verified the
returned signature, and wrote exact S3 version `OTVF8uUF_8RjdEoFzHDkv7K7.OJltR66` using
customer-managed KMS encryption and 14-day compliance-mode Object Lock. A fresh client with no
cookies downloaded that exact finalized synthetic bundle through the application route.

Verify the preserved downloaded bundle without network access or AWS credentials:

```bash
node tools/verify-authority-bundle.mjs \
  artifacts/aws/live-item8/authority-bundle \
  --registry tools/trusted-receipt-keys.json \
  --bundle-digest 76314ee2d1cdad8cf7aaaad99db1d5254b92478744b7dff3383ef6270d0c762d
```

Expected result: `VERIFIED`, seven events. The signed proof establishes integrity and conformance
of the supplied server-authoritative chain. It does not establish external truth, physical-person
presence, trusted time, or completeness against a compromised signer.
