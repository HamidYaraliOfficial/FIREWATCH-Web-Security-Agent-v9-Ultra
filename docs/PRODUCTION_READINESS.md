# FIREWATCH v9 Ultra Production Readiness

This is a deployment checklist, not a certification. Do not publish an internet-facing instance until each item has an owner and completion evidence.

## Required configuration

- [ ] Set `ENVIRONMENT=production`.
- [ ] Keep `FIREWATCH_ALLOW_MASTER_KEY=false` and use database-backed tenant API keys. If an explicitly approved emergency master key is required, document it, use at least 32 random printable ASCII characters, store it in a secret manager and rotate after the incident.
- [ ] Use PostgreSQL or another explicitly supported production database; SQLite is rejected in production mode.
- [ ] Set `ALLOW_PRIVATE_TARGETS=false`; configure the dedicated `EGRESS_PROXY_URL` and enforce outbound egress allow-lists at the host/cloud network layer. Do not bypass the proxy.
- [ ] Set `ENABLE_INLINE_WORKER=false` and run the external worker topology.
- [ ] Use explicit CORS origins; public origins must use HTTPS.
- [ ] Set a stable `FIREWATCH_SECRET_KEY` from a secret manager or mount a persistent, access-controlled `FIREWATCH_SECRET_KEY_FILE`. Back it up securely; losing it makes saved encrypted credentials unrecoverable.
- [ ] Keep API and database ports private. Bind public ingress through a TLS reverse proxy/WAF.
- [ ] Configure resource requests/limits for backend, worker and browser processes.
- [ ] Set a suitable request timeout, concurrency ceiling and rate delay for each engagement.

## Before each assessment

- [ ] Confirm written authorization, exact hosts/ports, allowed paths, testing window and emergency contact.
- [ ] Confirm the target is not a third-party shared system outside the authorization.
- [ ] Confirm credentials belong to dedicated least-privileged test accounts and are not embedded in URLs.
- [ ] Set exclusions for destructive or irreversible paths and avoid mutating workflows.
- [ ] Agree request-rate limits with the service owner.
- [ ] Use a staging environment for browser-authenticated, role-comparison and canary testing when possible.

## Before each release

- [ ] Run `python scripts/verify_release.py` and retain the console/CI output.
- [ ] Run `bandit -q -r backend/app -lll -iii`.
- [ ] Run `pip-audit -r backend/requirements.txt` with package-index access and archive the resolved CycloneDX SBOM from the runtime image build.
- [ ] Build and inspect all Docker images, verify proxy ACLs, and run a local Demo Target end-to-end scan. The local authoring environment may not have Docker; CI build results are still required.
- [ ] Review the generated test and dependency inventories; commit no runtime reports, databases, credentials, coverage artifacts or local key files.
- [ ] Confirm the Python matrix, Docker build/SBOM job, Bandit, `pip-audit` and CodeQL completed in GitHub; resolve failures rather than relying only on local checks.
- [ ] Verify any distributed report ZIP with `python scripts/verify_report_bundle.py <bundle.zip>`.
- [ ] Sign release artifacts through a trusted CI signing workflow if publisher authenticity is required; the report manifest hashes alone are not a signature.

## Incident / cleanup checklist

- [ ] Stop workers and revoke assessment credentials.
- [ ] Rotate exposed API/encryption keys if compromise is suspected.
- [ ] Preserve required evidence securely, then delete target data according to the engagement's retention policy.
- [ ] Record the affected release, target scope, time window and response steps without publishing secrets in public issues.


## Ultra schema, tenant and worker gates

- [ ] Run `alembic upgrade head` before production API/worker startup. Current schema head: `0002_body_truncation`.
- [ ] Provision a separate tenant API key for each organization; assign least privilege, expiration/rotation and a documented owner. Do not use a shared global key as the normal tenant identity.
- [ ] Test cross-tenant reads/writes for scans, reports, evidence, assets, events, projects and standards-checklist state using independent API keys.
- [ ] Confirm the API/worker run with the same stable encryption key and persistent `/data` mount.
- [ ] Confirm worker Lease/Heartbeat behavior by terminating a worker mid-scan; verify stale jobs are retried only within the configured attempt count and the old worker cannot overwrite the new owner's result.
- [ ] Confirm response-body truncation appears in page metadata and reports; large responses must not cause unbounded memory growth.
- [ ] Confirm report download and report ZIP endpoints refuse database paths that resolve outside the scan's report directory.
- [ ] If enabling ZAP, create a non-placeholder API key secret, verify authenticated health/API access, ensure the Spider is context/exclusion-bound, POST form submissions are disabled, and the active scanner remains unused.
