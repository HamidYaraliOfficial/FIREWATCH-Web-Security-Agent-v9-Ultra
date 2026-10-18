# FIREWATCH Ultra — Egress Security Architecture

## Defense in depth

1. **ScopePolicy:** validates scheme, normalized host, effective port, path exclusions and secret-bearing query rules before each application request.
2. **HTTP/browser client:** does not automatically follow redirects, restricts credentials to the exact root origin, limits concurrency/timeouts and caps raw response bytes.
3. **Egress proxy:** Squid destination ACLs block common private, loopback, link-local, multicast, reserved and documentation ranges. The Compose file does not publish this proxy to the host.
4. **Infrastructure controls:** production owners must enforce outbound destination/network ACLs at host, cluster, cloud firewall or dedicated scanner network. This is needed because app DNS checks do not pin the resolved IP to the final connection.
5. **Evidence and reporting:** redirect responses and incomplete body analyses are not treated as proof of a vulnerability or as full body inspection.

## Production requirements

- Keep `ALLOW_PRIVATE_TARGETS=false`.
- Never bypass `EGRESS_PROXY_URL` for scanner traffic.
- Deny cloud metadata services and organization-private ranges in infrastructure policy even if they are not listed in the sample ACL.
- Keep resolver configuration controlled; test CNAME chains, split DNS, IPv4/IPv6, DNS changes between precheck and connect, redirects and proxy CONNECT.
- Set explicit target scope and written authorization. Prefer a customer-specific egress policy, dedicated worker/network, and per-engagement isolation for sensitive assessments.
- Monitor proxy ACL denials and unexpected destinations; retain logs according to a defined policy without logging Authorization/Cookie values.

## Limitations

The included Squid ACL is a defensive baseline, not an exhaustive universal IANA special-purpose address database. It does not replace an environment-specific egress firewall, and it does not constitute a formal proof against all forms of DNS rebinding. Validate actual deployed Squid, resolver and network behavior before relying on it.
