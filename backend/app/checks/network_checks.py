from __future__ import annotations
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
from .base import FindingCandidate
from ..models import Severity


def _connect_through_proxy(proxy_url: str, target_host: str, target_port: int, timeout: float):
    proxy = urlparse(proxy_url)
    if proxy.scheme.lower() not in {"http", "https"} or not proxy.hostname:
        raise ValueError("Invalid egress proxy origin")
    if proxy.username is not None or proxy.password is not None or proxy.query or proxy.fragment or proxy.path not in {"", "/"}:
        raise ValueError("Egress proxy URL must be an origin without credentials or path")
    proxy_port = proxy.port or (443 if proxy.scheme.lower() == "https" else 80)
    raw = socket.create_connection((proxy.hostname, proxy_port), timeout=timeout)
    authority_host = f"[{target_host}]" if ":" in target_host else target_host
    authority = f"{authority_host}:{target_port}"
    request = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n\r\n".encode("ascii")
    raw.sendall(request)
    received = bytearray()
    while b"\r\n\r\n" not in received and len(received) < 16384:
        block = raw.recv(2048)
        if not block:
            break
        received.extend(block)
    header = bytes(received).split(b"\r\n", 1)[0]
    parts = header.split()
    if len(parts) < 2 or parts[1] != b"200":
        raw.close()
        raise ConnectionError("Egress proxy refused the TLS CONNECT tunnel")
    return raw


def inspect_tls(url: str, proxy_url: str | None = None):
    """Inspect TLS without bypassing the configured egress proxy when one is set."""
    out = []
    p = urlparse(url)
    if p.scheme != "https":
        return out
    host = p.hostname or ""
    port = p.port or 443
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        if proxy_url:
            raw = _connect_through_proxy(proxy_url, host, port, 5.0)
        else:
            raw = socket.create_connection((host, port), timeout=5)
        with raw:
            with ctx.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
                version = sock.version()
                cipher = sock.cipher()[0] if sock.cipher() else None
                der = sock.getpeercert(binary_form=True)
        if version not in {"TLSv1.3", "TLSv1.2"}:
            out.append(FindingCandidate("FW-TLS-001", "transport", "Unexpected TLS protocol version", Severity.MEDIUM, .98, url,
                f"TLS connection negotiated {version}.", "Legacy protocol versions can provide weaker cryptographic guarantees.",
                "Restrict service-side TLS to modern protocol versions.", f"Negotiated {version}."))
        if cipher and any(x in cipher.upper() for x in ("RC4", "3DES", "NULL", "EXPORT")):
            out.append(FindingCandidate("FW-TLS-002", "transport", "Weak TLS cipher negotiated", Severity.HIGH, .98, url,
                f"The scanner negotiated cipher {cipher}.", "Weak cryptographic suites may reduce transport security.",
                "Disable legacy/weak cipher suites at the edge.", f"Negotiated cipher: {cipher}."))
        if cert.get("notAfter"):
            expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
            days = (expiry - datetime.now(timezone.utc)).total_seconds() / 86400
            if days < 0:
                out.append(FindingCandidate("FW-TLS-003", "transport", "TLS certificate appears expired", Severity.HIGH, .99, url,
                    f"The validated certificate expired {abs(int(days))} day(s) ago.",
                    "Clients may reject the connection or users may be exposed to trust warnings.",
                    "Renew and deploy a valid certificate chain.", f"Certificate notAfter: {cert['notAfter']}.", evidence={"days_until_expiry": round(days, 2)}))
            elif days < 30:
                out.append(FindingCandidate("FW-TLS-003", "transport", "TLS certificate expires soon", Severity.MEDIUM, .97, url,
                    f"The validated certificate expires in approximately {int(days)} day(s).",
                    "An expired certificate can break availability and user trust.",
                    "Renew the certificate and verify automated renewal/monitoring.", f"Certificate notAfter: {cert['notAfter']}.", evidence={"days_until_expiry": round(days, 2)}))
        try:
            from cryptography import x509
            cert_obj = x509.load_der_x509_certificate(der)
            pub = cert_obj.public_key()
            key_size = getattr(pub, "key_size", None)
            if key_size and key_size < 2048:
                out.append(FindingCandidate("FW-TLS-004", "transport", "TLS certificate uses a small public key", Severity.HIGH, .98, url,
                    f"The certificate public key size is {key_size} bits.", "A weak public key can reduce cryptographic security.",
                    "Replace with an appropriately sized key (for RSA, typically at least 2048 bits) or a modern supported elliptic-curve key.",
                    f"Certificate public key size: {key_size} bits.", evidence={"key_size": key_size}))
        except Exception:
            pass
    except ssl.SSLCertVerificationError as exc:
        out.append(FindingCandidate("FW-TLS-004", "transport", "TLS certificate validation failed", Severity.HIGH, .98, url,
            "The TLS client could not validate the certificate hostname/trust chain.",
            "Users and clients may reject the connection; disabling verification would create interception risk.",
            "Deploy a certificate valid for the target hostname with a trusted complete chain.",
            f"Certificate validation exception: {type(exc).__name__}."))
    except Exception as exc:
        # Failure to inspect is evidence of a coverage gap, not proof of a target flaw.
        out.append(FindingCandidate("FW-TLS-005", "transport", "TLS inspection could not be completed", Severity.INFO, .95, url,
            "The agent could not complete TLS inspection from its configured network path.",
            "Transport posture could not be fully evaluated.",
            "Check the target reachability and trusted egress-proxy configuration, then re-run the inspection.",
            f"TLS inspection exception type: {type(exc).__name__}."))
    return out
