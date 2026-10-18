from app.zap import ZAPAdapter
from app.scope import ScopePolicy
from app.models import Severity
import pytest


def test_ultra_zap_uses_header_not_query_for_api_key(tmp_path):
    adapter = ZAPAdapter("http://zap:8080", str(tmp_path), api_key="z" * 40)
    assert adapter._headers() == {"X-ZAP-API-Key": "z" * 40}
    assert "api_key" not in adapter.base_url and "apikey" not in adapter.base_url


def test_ultra_zap_context_regexes_include_scope_and_exclusions(tmp_path):
    policy = ScopePolicy.from_root("https://example.test/", exclusions=["/admin/*"], allow_private_targets=True)
    includes = ZAPAdapter._origin_regexes(policy)
    excludes = ZAPAdapter._exclude_regexes(policy)
    assert any("example\\.test" in p for p in includes)
    assert any("admin" in p for p in excludes)


@pytest.mark.asyncio
async def test_ultra_zap_passive_only_import_filters_out_of_scope_and_excluded_alerts(tmp_path, monkeypatch):
    policy = ScopePolicy.from_root("https://example.test/", exclusions=["/admin/*"], allow_private_targets=True)
    adapter = ZAPAdapter("http://zap:8080", str(tmp_path), api_key="z" * 40)
    calls = []
    async def fake_call(component, kind, name, params=None):
        calls.append((component, kind, name, params or {}))
        if (component, kind, name) == ("context", "action", "newContext"):
            return {"contextId": "1"}
        if (component, kind, name) == ("spider", "action", "scan"):
            return {"scan": "1"}
        if (component, kind, name) == ("spider", "view", "status"):
            return {"status": "100"}
        if (component, kind, name) == ("pscan", "view", "recordsToScan"):
            return {"recordsToScan": "0"}
        if (component, kind, name) == ("core", "view", "alerts"):
            return {"alerts": [
                {"pluginId":"1001", "url":"https://example.test/", "name":"Header issue", "risk":"Medium", "confidence":"High"},
                {"pluginId":"1002", "url":"https://example.test/admin/", "name":"Excluded", "risk":"High"},
                {"pluginId":"1003", "url":"https://evil.test/", "name":"Out of scope", "risk":"High"},
            ]}
        return {"ok": "true"}
    monkeypatch.setattr(adapter, "_call", fake_call)
    candidates = await adapter.run_passive(policy, "scan-test", max_duration_seconds=10)
    assert len(candidates) == 1
    assert candidates[0].severity == Severity.MEDIUM
    assert candidates[0].rule_id == "ZAP-1001"
    assert not any(component == "ascan" for component, *_ in calls)
    assert any(c[:3] == ("spider", "action", "setOptionPostForm") and c[3].get("Boolean") == "false" for c in calls)
    assert any(c[:3] == ("spider", "action", "setOptionProcessForm") and c[3].get("Boolean") == "false" for c in calls)
    assert any(c[:3] == ("context", "action", "removeContext") and c[3].get("contextName") == "FW_scan_test" for c in calls)
