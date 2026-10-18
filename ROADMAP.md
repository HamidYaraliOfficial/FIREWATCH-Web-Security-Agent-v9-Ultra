# Roadmap

## v8.0.0 — current

- Expanded deterministic regression coverage with adversarial URL scope matrices, recursive URL secret-redaction cases, OpenAPI authorization-declaration contracts, report-sink security tests, credential-origin matrices, crawler inventory fixtures, safe ZAP YAML serialization, request schema fuzz matrices, authorization review boundaries and inert parameter-probe limits.
- Fixed wildcard path exclusions so `/internal/*` does not accidentally exclude unrelated siblings such as `/internal-public`.
- Hardened nested URL redaction for repeatedly percent-encoded redirects and return URLs.
- Hardened Markdown report output against raw HTML and Markdown link injection; preserved CSV spreadsheet-formula neutralization.
- Corrected API technology classification to match a `graphql` path segment rather than any substring, expanded URL-like OpenAPI parameter review, hardened header-name whitespace handling, and rejected ZAP API port zero.
- Centralized the application version and refreshed generated test manifest/catalog, CI contract, README and release verification metadata.

## Planned hardening (not claimed as implemented)

- Egress proxy integration with DNS/IP pinning and auditable resolved-address policy.
- Authenticated Playwright login journeys using declarative workflows and secret injection at run time.
- Precision/recall evaluation with an independently curated set of synthetic vulnerable and safe applications.
- Authorization workflow support with designated test objects and per-route expected-role assertions.
- SARIF baseline integration, risk acceptance and richer scan trend analytics.
- External queue backend with multi-worker load/concurrency tests.
- Optional LLM-assisted planning behind deterministic policy enforcement and typed tool calls.
- Tenant isolation only after a dedicated threat model, authorization model and security review.

## Non-goals for default profiles

Unbounded scanning, password guessing, destructive business workflows, arbitrary write methods, exploit payload automation, weaponized SSRF and silent scope expansion remain out of scope for defaults.
