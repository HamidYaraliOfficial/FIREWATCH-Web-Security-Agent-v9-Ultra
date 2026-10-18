"""Regression tests proving response bodies are bounded while streaming."""
import asyncio
import hashlib
import httpx

from app.http_client import SafeHTTPClient
from app.scope import ScopePolicy

MAX_BYTES = 2_000_000


def run_observation(payload: bytes):
    async def runner():
        policy = ScopePolicy.from_root("https://app.example.test/", allow_private_targets=True)
        async def handler(_request):
            return httpx.Response(200, headers={"content-type": "application/octet-stream"}, content=payload)
        client = SafeHTTPClient(policy, delay_ms=0)
        client.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
        try:
            return await client.request("GET", policy.root_url)
        finally:
            await client.__aexit__(None, None, None)
    return asyncio.run(runner())


def test_ultra_large_response_body_is_bounded_and_marked_truncated():
    payload = b"A" * (MAX_BYTES + 97)
    observed = run_observation(payload)
    assert len(observed.body.encode("utf-8")) == MAX_BYTES
    assert observed.body_truncated is True
    assert observed.body_sha256 == hashlib.sha256(payload[:MAX_BYTES]).hexdigest()


def test_ultra_exact_body_limit_is_not_marked_truncated():
    payload = b"B" * MAX_BYTES
    observed = run_observation(payload)
    assert len(observed.body.encode("utf-8")) == MAX_BYTES
    assert observed.body_truncated is False
    assert observed.body_sha256 == hashlib.sha256(payload).hexdigest()


def test_ultra_public_http_credentials_are_never_allowed_by_private_lab_flag():
    from app.http_client import credentials_allowed_for_root_origin
    assert not credentials_allowed_for_root_origin("http://public.example/", "http://public.example/", True)
    assert credentials_allowed_for_root_origin("http://127.0.0.1/", "http://127.0.0.1/", True)


def test_ultra_unexpected_content_encoding_is_not_decompressed_and_is_marked_incomplete():
    async def runner():
        policy = ScopePolicy.from_root("https://app.example.test/", allow_private_targets=True)
        async def handler(_request):
            return httpx.Response(200, headers={"content-encoding": "gzip", "content-type": "text/html"}, stream=httpx.ByteStream(b"\x1f\x8b" + b"X" * 100))
        client = SafeHTTPClient(policy, delay_ms=0)
        client.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
        try:
            return await client.request("GET", policy.root_url)
        finally:
            await client.__aexit__(None, None, None)
    observed = asyncio.run(runner())
    assert observed.body == ""
    assert observed.body_truncated is False
    assert observed.body_encoding_unsupported is True
    assert observed.status_code == 200


def test_ultra_report_records_incomplete_body_analysis(tmp_path):
    import json
    from types import SimpleNamespace
    from app.models import ScanStatus
    from app.report import render_json, render
    scan = SimpleNamespace(id="f9a0d933-49c0-4a67-8c8d-0b4bead84d22", target_url="https://app.example.test/",
                           status=ScanStatus.COMPLETED, truncated_page_count=2, unsupported_encoding_page_count=1)
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    render_json(scan, [], [], json_path, [])
    render(scan, [], [], html_path, [])
    meta = json.loads(json_path.read_text(encoding="utf-8"))["meta"]
    assert meta["truncated_response_bodies"] == 2
    assert meta["unsupported_encoding_bodies"] == 1
    html = html_path.read_text(encoding="utf-8")
    assert "Response bodies truncated by the byte limit: 2" in html
    assert "unsupported Content-Encoding: 1" in html
