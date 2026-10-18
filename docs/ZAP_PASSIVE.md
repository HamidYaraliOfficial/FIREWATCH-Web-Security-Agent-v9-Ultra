# Optional OWASP ZAP Integration — Passive-only Contract

FIREWATCH's ZAP adapter invokes the authenticated ZAP API to perform a bounded Traditional Spider followed by passive scanning. It does not invoke the Active Scanner API.

## Required safeguards

- ZAP API access remains on the internal scanner network and uses a Docker secret with a non-placeholder strong key.
- API key values are sent in `X-ZAP-API-Key`, never query parameters.
- A per-scan Context is created from the explicit ScopePolicy hosts/schemes/ports and exclusions.
- Traditional Spider form processing and POST form submission are disabled; the spider thread count is bounded.
- Spider/passive queue polling has a deadline; imported alerts have a maximum count and must pass a second FIREWATCH scope check.
- Alert evidence and URLs are redacted before persistence.
- The per-scan Context is removed in a `finally` path after success, timeout, cancellation or error.
- No Active Scanner operation is called by FIREWATCH.

## Integration test plan

- Test malformed URL, missing/weak API key, unavailable ZAP, HTTP 401/403, spider timeout, passive queue timeout, context creation failure and context-removal failure.
- Verify that excluded/out-of-scope URLs are not imported and that redirects do not expand scope.
- Inspect ZAP API call logs to ensure `ascan` endpoints are never called and form submission stays disabled.
- Run a dedicated isolated ZAP container and Demo Target in staging. Unit tests use a mocked API and do not prove Docker networking or live-version compatibility.

Official reference: https://www.zaproxy.org/docs/api/ and https://www.zaproxy.org/docs/desktop/addons/spider/automation/.
