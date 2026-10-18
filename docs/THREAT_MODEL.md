# FIREWATCH v9 Ultra Threat Model

## Purpose and security boundary

FIREWATCH is an assessment coordinator for systems that the operator owns or is authorized to test. It is not a network isolation boundary, exploit framework, or proof that a target is secure. The operator's egress firewall/proxy and approved engagement scope remain authoritative.

## Assets to protect

- API keys, bearer tokens, cookies and authorization profile material.
- The scan database, encryption key and report directory.
- Target identifiers, endpoint inventory, finding details and evidence.
- The integrity and provenance of generated reports and release artifacts.
- The availability of the FIREWATCH service and assessed targets.

## Trust boundaries

1. Dashboard/client to FastAPI API.
2. API to persistence and encrypted secret storage.
3. Worker to assessed HTTP targets and optional browser process.
4. Worker to optional ZAP service.
5. Report archive and evidence crossing into a developer, ticketing system, or CI artifact store.
6. Source repository and CI build environment to public release packages.

## Principal threats and mitigations

| Threat | Mitigation in v9 | Residual risk |
|---|---|---|
| Unauthorized scan submission | Database-backed tenant API keys, hashed key storage, role/scope checks, production master-key opt-in, scope acknowledgement | Deployment still requires per-tenant provisioning, rotation, and secret-manager storage |
| SSRF/internal-service probing | strict URL/scope checks plus Compose egress proxy ACLs that deny private/reserved destinations, bounded read-only requests, no automatic redirects | Application DNS checks alone do not pin transport destinations; validate proxy ACLs and add host/cloud egress policies; do not bypass proxy |
| Credential forwarding | credentials are encrypted at rest and isolated to exact root origin | compromised host process or browser can still access in-memory credentials |
| Secret leaks in evidence/reports | redaction of URL/query/fields and bundle review tests | redaction is heuristic; review exports before sharing |
| Report/archive tampering or path abuse | SHA-256 manifest, path-constrained report resolution, bundle path and size validation | manifest is not signed; a hostile party can replace both report and manifest; sign release/report manifests externally when needed |
| Resource exhaustion | page/depth/endpoint/concurrency/time ceilings, capped streaming response body, lease-backed jobs and bounded retries | browser/container CPU, memory, disk and database capacity still require deployment limits and load/soak tests |
| Insecure production configuration | startup validation for limits, API key, database, private targets, worker topology, CORS and ZAP origin | secret rotation, TLS termination and network policies remain deployment responsibilities |
| Unsafe test behavior | built-in probes are bounded and non-destructive; manual/exploit-required cases are labeled separately | authorization/business logic still requires test fixtures and human review |
| Supply-chain drift | CI, Dependabot, CodeQL workflow and declared-dependency inventory | these workflows have to run in GitHub; local package audits need package-index access |

## Explicit non-goals

The default engine does not perform password guessing, credential stuffing, arbitrary write/delete requests, destructive workflow tests, executable XSS payloads, exploit-style SQL/OS injection, or weaponized SSRF. Review candidates are not proof of exploitability.

## Deployment assumptions

- Production is deployed behind TLS and an allow-listed ingress.
- Outbound traffic from the service is constrained by firewall/proxy policy to approved targets.
- The data volume and encryption key are access-controlled and backed up consistently.
- Reports and logs are treated as potentially confidential customer/security data.
- Operators use dedicated, least-privileged test identities and remove them after engagement.


## Ultra-specific assets and controls

- Response-body memory: HTTP response consumption is bounded while streaming; truncation is persisted and reported so partial content is not silently treated as complete.
- Report filesystem boundary: database-provided paths are accepted only when they resolve inside `REPORT_DIR/<scan UUID>/`.
- Job ownership: leased workers must own a live lease for state transitions; a stale worker must stop and cannot overwrite newer results.
- Schema trust: production startup requires the current Alembic head and refuses implicit production `create_all()` upgrades.
- ZAP context lifecycle: optional passive Spider contexts are constrained, form POST submission is disabled, and the per-scan context is removed in a `finally` block.
- Tenant authorization: API key scope and tenant namespacing are tested locally; a production rollout still requires real PostgreSQL multi-tenant acceptance testing, independent security review, and operating-system/cloud policy validation.
