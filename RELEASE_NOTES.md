# FIREWATCH Web Security Agent v9 Ultra — Release Notes

Release identifier: `9.0.0-ultra` (Python distribution metadata: `9.0.0+ultra`).

## Ultra hardening included

- Database-backed tenant API keys with stored key digests, expiry/revocation, role/scope validation, and an explicit bootstrap/revocation workflow.
- Tenant-aware scan access, project/tenant association, security audit events, checklist history, and report-download audit trails; verify deployment-specific authorization and database permissions before exposing to untrusted tenants.
- Startup configuration validation that fails closed for invalid resource ceilings, production defaults, unsafe CORS origins, SQLite/inline-worker topology, missing egress proxy, and invalid ZAP settings.
- Egress-proxy Docker topology and documentation, with application scope checks retained as defense in depth. Proxy/network enforcement must be validated in the deployment environment; this local package does not claim a complete defense against every DNS rebinding scenario.
- Worker leases, heartbeat, bounded retry attempts, lease ownership checks, cancellation/lost-lease behavior and compare-and-swap completion/failure transitions.
- Path-constrained report lookup and size-bounded HTTP response collection; report generation must finish before a scan can be marked completed.
- Passive-only ZAP integration with API-key handling, bounded request duration/alert import, scope context/exclusion setup, proxy-chain validation, disabled form processing and constrained spider threads. Active ZAP scanning is not automatically enabled.
- Report bundle manifests with report list, byte sizes and SHA-256 checksums plus an independent verifier. Hash manifests detect accidental tampering relative to the manifest, but do not authenticate the publisher; use trusted external signing for provenance.
- Standards & Assurance module: curated framework register and control checklist, evidence requirements, reviewer metadata, revision conflict handling, history and exports.
- CI workflow for Python 3.11–3.13, regression/coverage, dependency audit/static analysis, Docker image builds and resolved runtime CycloneDX SBOM generation, plus CodeQL configuration.

## Local verification record

- Pytest collection: **5,952 cases across 65 test modules** from the current source tree.
- Full regression suite without coverage instrumentation: passed, 100% completion, zero failures/errors reported.
- The release coverage runner uses deterministic module-balanced shards and enforces a combined Python statement-coverage threshold of **80%**. Combined Python statement coverage measured **81.76%** over eight shards using collection fingerprint `704eb4bd6f53318317b0ef7b7df423c2060c87f1d449b7bb423f74bac6468f7a`; every shard completed with zero failures/skips and the minimum gate is 80%.
- Python compilation, dashboard JavaScript syntax, publisher shell syntax, Docker Compose YAML parsing, repository hygiene, assessment-plan export, test manifest generation and dependency-inventory generation are part of the local release gate. GitHub-hosted action versions were checked against their official release pages on 2026-10-18; CI now uses checkout@v7, setup-python@v7, setup-node@v7, upload-artifact@v7 and CodeQL Action v4.

## Checks requiring a tool-enabled/hosted environment

Bandit, `pip-audit`, Docker image build, live ZAP integration, a real PostgreSQL migration/backup-restore rehearsal, hosted GitHub Actions and hosted CodeQL must not be described as passing unless their actual logs are retained for the exact release artifact. See `VERIFICATION.md` and `RELEASE_CHECKLIST.md`.

## Scope and claims

FIREWATCH is a scope-controlled assessment aid. Automated tests and code coverage are not vulnerability-detection rates. The curated standards crosswalk is not certification, legal advice, or a clause-complete copy of all referenced standards. Production use requires deployment-specific security review and human validation for business logic, authorization and high-impact findings.
