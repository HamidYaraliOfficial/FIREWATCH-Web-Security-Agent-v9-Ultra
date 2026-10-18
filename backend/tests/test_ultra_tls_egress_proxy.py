from app.checks.network_checks import _connect_through_proxy, inspect_tls
from app.models import Severity
import pytest

class FakeSocket:
    def __init__(self):
        self.sent = b""
        self.response = bytearray(b"HTTP/1.1 200 Connection established\r\nProxy-Agent: test\r\n\r\n")
        self.closed = False
        self.timeout = None
    def sendall(self, data): self.sent += data
    def recv(self, size):
        if not self.response: return b""
        out = bytes(self.response[:size]); del self.response[:size]; return out
    def close(self): self.closed = True
    def settimeout(self, value): self.timeout = value
    def __enter__(self): return self
    def __exit__(self, *args): self.close()


def test_ultra_tls_inspection_uses_explicit_proxy_connect(monkeypatch):
    fake = FakeSocket()
    monkeypatch.setattr("app.checks.network_checks.socket.create_connection", lambda address, timeout=0: fake)
    returned = _connect_through_proxy("http://egress-proxy:3128", "example.test", 443, 5)
    assert returned is fake
    assert b"CONNECT example.test:443 HTTP/1.1" in fake.sent
    assert b"Host: example.test:443" in fake.sent
    assert b"Proxy-Authorization" not in fake.sent


def test_ultra_http_targets_do_not_start_tls_socket():
    assert inspect_tls("http://example.test/") == []
