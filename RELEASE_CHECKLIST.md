# FIREWATCH v9 Ultra Release Checklist

## Local source and regression
- [x] `VERSION`, `backend/app/version.py`, API metadata and frontend branding show `9.0.0-ultra`; Python distribution metadata uses valid PEP 440 `9.0.0+ultra`.
- [x] `python scripts/export_assessment_plan.py` regenerates the v9 assessment JSON/CSV/catalog.
- [x] `python scripts/build_test_manifest.py` regenerates the test manifest/matrix from the currently collected pytest suite.
- [x] `python scripts/export_dependency_inventory.py` regenerates the declared dependency inventory; this is not a resolved SBOM or vulnerability audit.
- [x] Staged `python scripts/verify_release.py` invocations complete the same eight-shard coverage run with no FAIL results; any SKIP/UNVERIFIED check is tracked before production release.
- [x] Complete `pytest` suite passes; preserve the actual JUnit/CI log.
- [x] Combined statement coverage is measured with all eight shards from the same collection fingerprint and meets the configured minimum (local result: 81.76%).

## Security and production deployment
- [ ] Run Bandit and `pip-audit` in a network-enabled, tool-enabled environment.
- [ ] Build Docker images with Docker Engine; validate runtime user, filesystem permissions, resource limits, health checks and image scanning.
- [ ] Test DB migrations against an empty database and an upgrade from the previous release; test backup/restore.
- [ ] Test tenant boundary, role/scope matrix, key expiry/revocation, audit logging, report access and project-level authorization with PostgreSQL.
- [ ] Run SSRF/DNS-rebinding test harnesses with the enforced egress proxy/firewall; never test these against production or unauthorized services.
- [ ] Run ZAP passive-only smoke test; confirm forms are not submitted, Proxy Chain is configured/verified, and alert imports stay within scope and size limits.
- [ ] Test worker crash, lease expiry, lost heartbeat, cancellation, retry cap and failure during report generation.
- [ ] Run load/soak tests and record latency, memory, CPU, queue depth and error rates.
- [ ] Verify report bundle manifest and independently sign release/report artifacts if authenticity is required.
- [ ] Review SBOM, scan results, CodeQL and GitHub Actions; hosted checks must pass before tagging.

## Packaging and publication
- [x] Remove local DBs, `.env` files, secrets, browser caches, Python bytecode, test artifacts and coverage scratch files from the release archive.
- [x] Verify ZIP integrity and calculate SHA-256 after the final packaging step.
- [x] Ensure release notes, threat model, known limitations, standards register and exact test results match the artifact.
- [ ] Push to GitHub only after checking `git status --short`, then review CI/CodeQL and create tag `v9.0.0-ultra` only after required checks succeed.

Checks not executed in the local environment must be marked **unverified**, not passed. Passing this list is release evidence, not proof that the product or any target is vulnerability-free.
