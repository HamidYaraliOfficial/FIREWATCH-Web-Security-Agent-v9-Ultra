# Changelog

## v9.0.0-ultra — 2026-10-18

- Add tenant API-key primitives with digest-only storage, role/scope validation, key expiry/revocation support and bootstrap/revocation utilities.
- Add versioned database migrations for tenancy, worker leases, audit/history and report storage hardening.
- Add startup fail-closed configuration checks for production topology, resource ceilings, CORS, egress proxy and ZAP integration.
- Add Docker egress-proxy network topology and production deployment guidance.
- Add worker leasing/heartbeat, retry ceiling, ownership-aware cancellation and compare-and-swap final state transitions.
- Restrict report download resolution to the current scan's report directory and bound HTTP response-body processing.
- Add passive-only ZAP API integration with API authentication, context/exclusions, proxy-chain verification, duration/alert limits and form processing disabled.
- Add report-bundle SHA-256 manifest and an independent path/size/hash verifier.
- Include Standards & Assurance register, 469 control objectives, Excel workbook, checklist API, evidence/review metadata, history and exports.
- Expand CI to Python 3.11–3.13, regression/coverage, Bandit, pip-audit, Docker image build, resolved runtime CycloneDX SBOM, and CodeQL workflow.
- Refresh release checklist, threat model, operations guide, production-readiness notes, test manifest and dependency inventory.

## Earlier v9 Pro changes

- Add Standards & Assurance checklist, 67 curated reference entries, 32 domains and workbook/JSON/CSV/Markdown exports.
- Add report bundle integrity checks, staged coverage runner, scope/credential isolation hardening and extensive regression matrices.

## Historical v4–v8

Historical changelog entries and test matrices document incremental scope, crawler, API discovery, redaction, reporting and test-suite expansion. Historic counts are not used as the current v9 Ultra verification result; use `VERIFICATION.md` and the generated `docs/TEST_MANIFEST_V9.json` for the current source.
