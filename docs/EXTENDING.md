# Extending FIREWATCH v9 Ultra

## Add a deterministic rule

1. Place the rule in the appropriate module under `backend/app/checks/`.
2. Return the shared `FindingCandidate` structure; use a stable `FW-...` rule ID.
3. Add the rule family/mapping in `backend/app/check_catalog.py`.
4. Prefer response headers, bounded body signatures and hashes over storing raw response bodies.
5. Redact endpoint/evidence fields before persistence; `_store_finding` applies shared redaction as a backstop.
6. Add a unit test with a synthetic observation and a regression test for important false-positive cases.
7. Document whether the rule is passive, read-only active, a review candidate or requires human validation.

## Add a new report field or output

Update both HTML/JSON rendering and `report_extras.py`, register output formats in the orchestrator and API allow-list, and add coverage to tests. Do not expose raw secret material or unredacted query strings in new formats.

## External tool adapter

Adapters should be optional, isolated, and explicit in their guarantees. The current ZAP adapter calls the authenticated ZAP API for a bounded, context-scoped Traditional Spider followed by passive analysis. Form processing/submission are disabled and the Active Scanner is never invoked. Unit tests use a mocked API; deployed ZAP version, proxy chain, and actual integration must be validated in staging. New adapters must preserve the same authorized target policy, rate limits, authentication isolation, cancellation, and auditability.
