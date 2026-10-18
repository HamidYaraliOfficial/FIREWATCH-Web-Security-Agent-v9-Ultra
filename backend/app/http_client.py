from __future__ import annotations

import asyncio
import ipaddress
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Mapping
from urllib.parse import urlparse

import httpx

from .config import settings
from .scope import ScopePolicy


_AUTH_HEADER_NAMES = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "x-auth-token", "x-access-token",
    "x-session-token", "authentication",
}
_ALWAYS_BLOCKED_HEADERS = {
    "proxy-authorization", "proxy-connection", "host", "content-length",
    "transfer-encoding", "connection", "upgrade", "te", "trailer",
}



def credentials_allowed_for_root_origin(root_url: str, target_url: str, allow_private_targets: bool = False) -> bool:
    """Return whether configured authentication may be sent to the target origin.

    Origin matching includes scheme, normalized hostname, and effective port.
    Authentication is not sent over public cleartext HTTP.
    """
    try:
        root = urlparse(str(root_url))
        target = urlparse(str(target_url))
        if root.username is not None or root.password is not None or target.username is not None or target.password is not None:
            return False
        root_scheme = root.scheme.lower()
        target_scheme = target.scheme.lower()
        root_host = (root.hostname or "").lower().rstrip(".")
        target_host = (target.hostname or "").lower().rstrip(".")
        root_port = root.port or (443 if root_scheme == "https" else 80)
        target_port = target.port or (443 if target_scheme == "https" else 80)
        valid_scheme = target_scheme in {"http", "https"} and target_scheme == root_scheme
        # Never send credentials to public cleartext HTTP just because private
        # targets are enabled for a lab. The exception is limited to an explicit
        # loopback/private literal or an obvious local-only hostname; the egress
        # proxy remains a separate enforcement boundary for resolved destinations.
        private_local = False
        try:
            address = ipaddress.ip_address(root_host.strip("[]"))
            private_local = address.is_private or address.is_loopback or address.is_link_local
        except ValueError:
            private_local = root_host == "localhost" or root_host.endswith(".localhost")
        secure_channel = target_scheme == "https" or (allow_private_targets and private_local)
        return bool(root_host and target_host and root_host == target_host and valid_scheme
                    and root_port == target_port and secure_channel)
    except (TypeError, ValueError):
        return False

def _is_credential_header(name: str) -> bool:
    low = name.strip().lower()
    return (
        low in _AUTH_HEADER_NAMES
        or low.startswith("x-auth-")
        or low.endswith("-token")
        or "api-key" in low
        or "client-secret" in low
        or "session-id" in low
    )


@dataclass
class HTTPObservation:
    requested_url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    body: str
    elapsed_ms: float
    content_type: str
    body_sha256: str
    error: str | None = None
    set_cookies: list[str] | None = None
    body_truncated: bool = False
    body_encoding_unsupported: bool = False


class SafeHTTPClient:
    """Scoped HTTP client with conservative pacing and root-host credential isolation.

    Authentication material is sent only to the exact hostname in the root URL.
    Additional in-scope hosts can still be discovered, but credentials are not
    forwarded to them. Redirects are never followed automatically.
    """

    def __init__(self, scope: ScopePolicy, timeout: float | None = None,
                 delay_ms: int | None = None, headers: Mapping[str, str] | None = None):
        self.scope = scope
        self.timeout = timeout or settings.request_timeout_seconds
        self.delay_ms = settings.request_delay_ms if delay_ms is None else delay_ms
        self.headers = dict(headers or {})
        root = urlparse(scope.root_url)
        self.root_host = (root.hostname or "").lower().rstrip(".")
        self.root_scheme = root.scheme.lower()
        self.root_port = root.port or (443 if self.root_scheme == "https" else 80)
        self.client: httpx.AsyncClient | None = None
        self._last_request_at = 0.0
        self._lock = asyncio.Lock()

    async def __aenter__(self):
        base = {
            "User-Agent": settings.user_agent,
            "Accept": "text/html,application/json,text/plain,application/xml,*/*",
            # Avoid implicit decompression bombs. The bounded reader below accepts
            # identity bodies only; unexpectedly encoded bodies are flagged as
            # incomplete rather than decompressed into unbounded memory.
            "Accept-Encoding": "identity",
        }
        # In production every outbound request is routed through the explicitly
        # configured egress proxy. The proxy must enforce public-destination ACLs;
        # application-level ScopePolicy remains an independent second boundary.
        proxy = getattr(settings, "egress_proxy_url", "") or None
        if str(getattr(settings, "environment", "development")).lower() in {"production", "prod"} and not proxy:
            raise RuntimeError("EGRESS_PROXY_URL is required for production outbound HTTP")
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            headers=base,
            verify=True,
            trust_env=False,
            proxy=proxy,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )
        return self

    async def __aexit__(self, *_):
        if self.client:
            await self.client.aclose()

    async def _throttle(self):
        requested = max(0, self.delay_ms)
        effective = requested if self.scope.allow_private_targets else max(50, requested)
        gap = effective / 1000.0
        async with self._lock:
            elapsed = time.monotonic() - self._last_request_at
            if elapsed < gap:
                await asyncio.sleep(gap - elapsed)
            self._last_request_at = time.monotonic()

    def _headers_for(self, url: str, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        merged: dict[str, tuple[str, str]] = {}
        for source in (self.headers, extra or {}):
            for key, value in source.items():
                low = str(key).strip().lower()
                if not low or low in _ALWAYS_BLOCKED_HEADERS:
                    continue
                merged[low] = (str(key), str(value))
        # Authentication material is bound to the exact root origin (scheme, host, port),
        # not merely the host. Different services on the same host may have different trust.
        credentials_allowed = credentials_allowed_for_root_origin(
            self.scope.root_url, url, self.scope.allow_private_targets
        )
        result = {}
        for low, (original, value) in merged.items():
            if _is_credential_header(low) and not credentials_allowed:
                continue
            result[original] = value
        return result

    async def request(self, method: str, url: str,
                      headers: Mapping[str, str] | None = None,
                      content: str | bytes | None = None) -> HTTPObservation:
        if not self.client:
            raise RuntimeError("SafeHTTPClient must be used as an async context manager")
        clean = self.scope.validate_url(url)
        await self._throttle()
        start = time.perf_counter()
        try:
            # Stream the response and cap raw identity bytes while reading. The
            # client explicitly asks for identity encoding and does not auto-decode
            # compressed replies: an unexpected gzip/br/zstd response is marked as
            # incomplete rather than risk decompression-bomb memory expansion.
            max_response_bytes = 2_000_000
            body_buffer = bytearray()
            truncated = False
            encoding_unsupported = False
            async with self.client.stream(
                method.upper(), clean,
                headers=self._headers_for(clean, headers),
                content=content,
            ) as resp:
                content_encoding = (resp.headers.get("content-encoding") or "identity").strip().lower()
                if content_encoding not in {"", "identity"}:
                    encoding_unsupported = True  # body analysis intentionally skipped; headers remain usable
                else:
                    # MockTransport and a few custom transports may hand back an
                    # already-consumed in-memory response. Production network
                    # responses remain streamed; the fallback still caps what we copy.
                    if resp.is_stream_consumed:
                        async def _single_buffered_chunk():
                            yield resp.content
                        body_stream = _single_buffered_chunk()
                    else:
                        body_stream = resp.aiter_raw()
                    async for chunk in body_stream:
                        remaining = max_response_bytes - len(body_buffer)
                        if len(chunk) > remaining:
                            if remaining > 0:
                                body_buffer.extend(chunk[:remaining])
                            truncated = True
                            break
                        body_buffer.extend(chunk)
                raw_body = bytes(body_buffer)
                if encoding_unsupported:
                    body = ""
                else:
                    try:
                        encoding = resp.encoding or "utf-8"
                        body = raw_body.decode(encoding, errors="replace")
                    except (LookupError, UnicodeError):
                        body = raw_body.decode("utf-8", errors="replace")
                elapsed = (time.perf_counter() - start) * 1000
                cookies = resp.headers.get_list("set-cookie")
                normalized = {k.lower(): v for k, v in resp.headers.items()}
                if cookies:
                    normalized["set-cookie"] = "\n".join(cookies)
                return HTTPObservation(
                    clean, str(resp.url), resp.status_code, normalized, body,
                    round(elapsed, 2), resp.headers.get("content-type", ""),
                    sha256(raw_body).hexdigest(), None, cookies, truncated, encoding_unsupported,
                )
        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000
            # Exception strings can include URLs/query values; do not persist them verbatim.
            return HTTPObservation(
                clean, clean, 0, {}, "", round(elapsed, 2), "",
                sha256(b"").hexdigest(), type(exc).__name__, None,
            )
