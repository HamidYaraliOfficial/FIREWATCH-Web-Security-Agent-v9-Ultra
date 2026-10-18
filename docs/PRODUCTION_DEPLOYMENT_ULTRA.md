# FIREWATCH v9 Ultra — Production Deployment

## Deployment boundary

Use the supplied Compose topology as a starting point, then adapt it to your environment. It is not a substitute for infrastructure review. The backend is bound to loopback on the host by default; publish it only through a configured HTTPS reverse proxy. The database, ZAP API, and egress proxy have no host-published ports in the supplied Compose file.

## Required preflight

1. Create a private environment file based on `.env.example`; never commit the real file.
2. Set `ENVIRONMENT=production`, a strong PostgreSQL password, persistent encryption key/secret-file, `FIREWATCH_TENANT_AUTH_ENABLED=true`, `FIREWATCH_ALLOW_MASTER_KEY=false`, `ALLOW_PRIVATE_TARGETS=false`, exact HTTPS `CORS_ORIGINS`, and `ENABLE_INLINE_WORKER=false`.
3. Configure network-level firewall policy. The scanner may only reach the egress proxy, database, required internal services, and explicitly approved dependencies. Keep proxy and database credentials out of source control.
4. Create a non-placeholder ZAP API key only if the optional ZAP profile is being enabled. The example secret is intentionally not accepted by the entrypoint.
5. Run `docker compose config -q`, build images, run migrations, create a tenant admin key, and validate `/health` and `/ready` in a staging network before production traffic.
6. Start API and worker with the same stable encryption key and database settings. Apply rate, body, time, concurrency, crawl depth and queue limits suitable for the engagement.
7. Run cross-tenant negative tests using independent tenant keys. Verify that a tenant cannot read or modify another tenant's projects, scans, evidence, findings, report, audit history or checklist.
8. Run a permitted local Demo scan through the same egress design; verify cancellation, retries, report bundle manifest, report-path confinement, truncated-body warnings, and ZAP passive-only settings.
9. Verify backups and perform a restore rehearsal before go-live. Define retention and deletion for scan data and reports.
10. Review successful GitHub Actions, CodeQL, dependency audit, Docker build, resolved SBOM, and release artifact hashes. Missing or skipped security jobs are not a production approval.

## Suggested production profile

```dotenv
ENVIRONMENT=production
FIREWATCH_TENANT_AUTH_ENABLED=true
FIREWATCH_ALLOW_MASTER_KEY=false
ALLOW_PRIVATE_TARGETS=false
ENABLE_INLINE_WORKER=false
CORS_ORIGINS=https://security.example.org
```

Also set `POSTGRES_PASSWORD`, `FIREWATCH_SECRET_KEY` or a mounted `FIREWATCH_SECRET_KEY_FILE`, and the deployment-specific `EGRESS_PROXY_URL` in the secret/configuration manager. Use a unique tenant key created through `scripts/create_tenant_key.py`; do not reuse a team-wide key for multiple customers.

## Known gaps requiring deployment validation

- App-level DNS prechecks do not pin a target IP to the final socket. Egress proxy and infrastructure firewall are required secondary controls; verify DNS rebinding behavior in your staging setup.
- SSO/OIDC, SCIM, external KMS integration and centralized SIEM integration are not implied by tenant API keys or audit rows.
- ZAP orchestration is passive-only and mocked in unit tests. A live ZAP image and API integration must pass staging CI before enabling the profile.
- The local authoring environment may not have Docker, Bandit, or pip-audit. A skipped check must be completed in CI or another trusted build environment.
- No scanner automatically proves absence of vulnerabilities or formal compliance.
