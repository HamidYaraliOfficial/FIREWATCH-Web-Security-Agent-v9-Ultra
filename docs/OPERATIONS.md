# FIREWATCH v9 Ultra — Operations Guide

This guide describes the hardened single-tenant/team and tenant-key deployment paths. It is operational guidance, not a certification or guarantee that every deployment is secure.

## Runtime modes

### Local development / lab

- Use `ENVIRONMENT=development`, bind to loopback, and use a local demo target only when enabling private/loopback target access.
- `ENABLE_INLINE_WORKER=true` is for one API process only.
- Never use production credentials or real customer data in the demo database.

### Production API + external worker

- Use PostgreSQL, `ENVIRONMENT=production`, `ENABLE_INLINE_WORKER=false`, and run the `external-worker` Compose profile.
- Apply database migrations (`alembic upgrade head`) before API or worker startup. Current revision is listed in `migrations/versions/` and enforced by startup checks.
- Use a dedicated tenant API key per organization; keys are hashed in the database and the raw value is returned only during issuance. Store it in a secret manager and rotate/revoke on staff changes or suspected exposure.
- Keep the shared master key disabled. It is an emergency/development bypass only, not the normal tenant identity system.
- Bind the API to loopback or a private ingress interface; terminate HTTPS at a hardened reverse proxy/WAF. Keep PostgreSQL, ZAP, and the egress proxy unpublished.
- Set `ALLOW_PRIVATE_TARGETS=false` and configure `EGRESS_PROXY_URL`. Reinforce proxy ACLs with host/cloud egress firewall rules; do not treat application ScopePolicy as the only network boundary.

## Important environment variables

| Variable | Purpose | Production guidance |
|---|---|---|
| `ENVIRONMENT` | Runtime profile | `production` enables fail-closed guards |
| `FIREWATCH_TENANT_AUTH_ENABLED` | Database-backed tenant key auth | Keep enabled; pre-provision a least-privilege key |
| `FIREWATCH_ALLOW_MASTER_KEY` | Emergency global API-key bypass | `false` normally |
| `FIREWATCH_API_KEY` | Optional master key | Do not set unless explicitly approved and strong |
| `FIREWATCH_SECRET_KEY` / `FIREWATCH_SECRET_KEY_FILE` | Encryption key for sensitive fields | Stable, access-controlled, backed up separately |
| `DATABASE_URL` | SQLAlchemy URL | PostgreSQL for multi-process production |
| `EGRESS_PROXY_URL` | Scanner outbound proxy | Required in production; use trusted private endpoint |
| `ALLOW_PRIVATE_TARGETS` | Lab-only private/loopback targets | `false` in production |
| `ENABLE_INLINE_WORKER` | Inline queue consumer | `false` with multiple processes/external worker |
| `WORKER_LEASE_SECONDS` | Job ownership lease | Must exceed heartbeat interval and allow operational delays |
| `WORKER_HEARTBEAT_SECONDS` | Worker lease refresh | Must be comfortably below lease expiry |
| `REQUEST_TIMEOUT_SECONDS` | HTTP deadline | Bounded |
| `REQUEST_DELAY_MS` / `MAX_CONCURRENCY` | Request pacing and concurrency | Conservative and engagement-approved |
| `MAX_PAGES` / `MAX_DEPTH` / `MAX_ENDPOINTS` | Discovery ceilings | Do not raise without capacity testing |
| `REPORT_DIR` | Report storage root | Persistent, private volume with retention policy |
| `CORS_ORIGINS` | Browser origin allowlist | Exact HTTPS origins; no wildcard |
| `ENABLE_ZAP` / `ZAP_API_KEY` | Optional passive ZAP integration | Enable only with private authenticated API and test image |

## Tenant key lifecycle

Create a key with `python scripts/create_tenant_key.py --help`, provision only the required role/scopes, distribute the raw key via a secret manager, and revoke with `scripts/revoke_tenant_key.py`. Do not copy keys into the repository, browser local storage, public tickets, or target URLs. The application does not replace a full enterprise IdP: SSO/OIDC, SCIM lifecycle provisioning, centralized KMS integration, and independent multi-tenant penetration testing remain deployment/product work unless explicitly added.

## Egress and DNS

In the shipped Compose topology, scanner traffic uses the Squid egress proxy and its destination ACLs. Application-side DNS prechecks do not constitute socket-level DNS pinning. Do not bypass the proxy in production. Use cloud/host firewall policy, deny cloud metadata and organization-internal CIDRs, monitor denied traffic, and test the actual resolver/proxy combination for rebinding behavior before allowing customer targets.

The proxy's ACL is defense-in-depth and is not a universal substitute for an organization-specific destination allowlist. The app's hostname scope policy should be accompanied by approved host/port/path scope and an authorization record for every assessment.

## ZAP passive integration

ZAP is optional. When enabled, FIREWATCH authenticates to ZAP using the API key header, creates a temporary scan context restricted to ScopePolicy hosts/schemes/ports/exclusions, runs the Traditional Spider with form processing/submission disabled, drains passive scanning within a deadline, revalidates each alert against scope, imports bounded/redacted alerts, and removes the temporary context. It does **not** call ZAP's active scanner. Confirm the deployed ZAP image/version and proxy chain in integration CI before relying on it.

## Body limits and report storage

HTTP response bodies are read as raw streamed bytes with a 2,000,000-byte ceiling. The system does not transparently decompress an unexpected `Content-Encoding`; it records that the body was not analyzed. Reports include counts for truncated and unsupported-encoding bodies. Therefore a scan with these counts greater than zero has incomplete body analysis and must not be described as full-content inspection.

Report endpoints accept only resolved regular files beneath `REPORT_DIR/<scan-id>/`; a database path is not treated as authorization. Report ZIP manifests contain size and SHA-256 integrity hashes but are not digitally signed. Preserve reports as sensitive assessment artifacts and use the verifier on downloaded bundles.

## Recovery and observability

- `/health` is liveness; `/ready` checks readiness/dependencies.
- Use scan event and audit endpoints for lifecycle and report-download history.
- Job ownership uses lease owner, heartbeat, expiry and bounded retries. If a job stalls, inspect database/worker logs and lease fields before modifying records by hand.
- Test worker termination during a scan, DB outage, lost lease and API restart before production rollout.
- Maintain encrypted backups for the database and encryption key separately. Losing the encryption key can render encrypted credential data unrecoverable.
- Define report retention, customer deletion, incident-response ownership and evidence handling before production use.

## Troubleshooting

- `503` at startup in Production: validate environment, migration head, PostgreSQL, secret-key source, tenant key settings and `EGRESS_PROXY_URL`.
- `401/403`: inspect the key's active state, tenant, role and required scope; do not fall back to a shared global key without explicit approval.
- Target rejected: confirm the written scope, scheme, hostname, port, path exclusions and private-network policy.
- Credentials omitted: credentials are bound to the exact root origin and public HTTP is not permitted to receive them.
- Scan does not progress: verify API and external worker share the same DB and encryption key; inspect lease owner/heartbeat and attempt count.
- ZAP unavailable: validate secret length, private API reachability, proxy chain, ZAP health and compatibility with the deployed ZAP version.
