-- Receipt material spans the immutable authority/evidence chain. Keep those
-- reads out of the legacy evidence-outbox credential by assigning the receipt
-- finalizer its own non-login role with an exact allowlist.
CREATE ROLE IF NOT EXISTS recallops_receipt;
GRANT USAGE ON SCHEMA public TO recallops_receipt;
GRANT SELECT ON TABLE approvals TO recallops_receipt;
GRANT SELECT ON TABLE authority_events TO recallops_receipt;
GRANT SELECT ON TABLE authority_ledger_heads TO recallops_receipt;
GRANT SELECT, UPDATE ON TABLE authority_receipts TO recallops_receipt;
GRANT SELECT ON TABLE judge_runs TO recallops_receipt;
GRANT SELECT ON TABLE memories TO recallops_receipt;
GRANT SELECT ON TABLE postcheck_assessments TO recallops_receipt;
GRANT SELECT ON TABLE postcheck_observations TO recallops_receipt;
GRANT SELECT ON TABLE postcheck_policy_verdicts TO recallops_receipt;
GRANT SELECT, UPDATE ON TABLE receipt_requests TO recallops_receipt;
GRANT SELECT ON TABLE release_evidence_records TO recallops_receipt;
GRANT SELECT ON TABLE sandbox_executions TO recallops_receipt;

REVOKE SELECT ON TABLE authority_events FROM recallops_outbox;
REVOKE SELECT ON TABLE authority_ledger_heads FROM recallops_outbox;
REVOKE INSERT, SELECT, UPDATE ON TABLE authority_receipts FROM recallops_outbox;
REVOKE SELECT ON TABLE judge_runs FROM recallops_outbox;
REVOKE INSERT, SELECT, UPDATE ON TABLE release_evidence_records FROM recallops_outbox;
REVOKE SELECT, UPDATE ON TABLE receipt_requests FROM recallops_outbox;
