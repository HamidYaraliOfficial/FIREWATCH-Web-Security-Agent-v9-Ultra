# FIREWATCH v9 Ultra — Verification Record

Release target: `FIREWATCH-WebSec-Agent-v9-Ultra`, runtime version `9.0.0-ultra` (Python distribution metadata: `9.0.0+ultra`).
Verification date: 2026-10-18.

## Confirmed in the local build environment

- Pytest collection: **5,952 test cases across 65 test modules** from the exact source tree used for this release candidate.
- Full regression suite without coverage instrumentation: **passed**, completed 100%, zero failures/errors reported by the process exit status.
- Combined Python statement coverage: **81.76%**, measured with eight deterministic module-balanced shards against collection fingerprint `704eb4bd6f53318317b0ef7b7df423c2060c87f1d449b7bb423f74bac6468f7a`. All eight shards completed with zero failures and the configured minimum is 80%.
- Local release checks: **9 PASS, 3 SKIP/UNVERIFIED, 0 FAIL** on each staged invocation. The final invocation reported the combined coverage result above. Staging was used because a single long coverage run exceeded the chat execution window; the runner validates the same collection fingerprint before combining shards.
- Python compilation, frontend JavaScript syntax (Node), publisher shell syntax (Bash), Docker Compose YAML parsing, repository hygiene, assessment-plan export, test manifest generation and declared-dependency inventory generation passed.
- Repository hygiene false positives were corrected: variable references such as `settings.zap_api_key` are not treated as secret values, and the CI Compose-validation password is generated from a run-specific placeholder rather than hard-coded.
- Worker leases, heartbeat, cancellation/lost-lease handling and report-finalization ownership are implemented and covered by local tests. This does not replace a production PostgreSQL failure-injection rehearsal.
- ZAP adapter is passive-only: API-key handling, bounded polling, scope context/exclusions, proxy-chain checks, constrained spider threads and disabled form processing. Active scanner automation is deliberately not enabled by default.
- Standards & Assurance workbook is an offline snapshot; edits made in Excel do not synchronize automatically with the live database/API.

## Not independently verified in this environment

The following require tools or infrastructure not proven available here and must be marked **UNVERIFIED** until logs are retained for this exact artifact:

- Bandit and `pip-audit` execution against the exact release dependency set (executables not installed locally).
- Docker Compose image build/run, image vulnerability scan and container isolation/resource-limit validation (Docker CLI not installed locally; Compose YAML was parsed successfully).
- Live ZAP daemon API, real proxy-chain behavior and passive-scan alert import in an isolated test network.
- Real PostgreSQL migration from a prior release, backup/restore rehearsal, concurrent worker/DB-outage failure injection and long-running load/soak tests.
- Hosted GitHub Actions and CodeQL on the user's repository, plus artifact signing and provenance verification.
- Independent third-party penetration test/security review.

## Residual risks and limitations

- Tenant API keys and project scopes are not a substitute for full SSO/SCIM or an independently reviewed enterprise identity lifecycle. Test object-level tenant isolation and report/evidence endpoints with PostgreSQL before multi-customer deployment.
- Egress proxying is defense in depth. DNS rebinding, IPv4/IPv6 routing and proxy ACL behavior must be tested in the target deployment; application URL validation alone is not a network sandbox.
- The ZAP adapter is passive-only and is not equivalent to full active DAST. Authentication workflow automation, business-logic testing, deep BOLA/IDOR proof, exploitable injection validation and specialist protocol tests may require test accounts, dedicated staging targets and human review.
- Report manifest hashes verify bytes relative to a manifest but are not publisher signatures.
- Standards register/checklist are curated crosswalks, not certification, legal advice, or a guarantee of clause-complete mapping.
- Test count and statement coverage measure FIREWATCH's own code behavior, not the proportion of target vulnerabilities discovered.

Passing local verification is evidence for the tested behaviors only; it is not a statement that FIREWATCH or any scanned target is vulnerability-free.
