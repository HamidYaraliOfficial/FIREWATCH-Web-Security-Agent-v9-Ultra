"""Authenticated, bounded, passive-only OWASP ZAP integration.

The adapter never calls ZAP's active scanner API. It configures the traditional
Spider not to process/submit forms, constrains URLs to a per-scan context, polls
within fixed deadlines, and revalidates every returned alert against FIREWATCH
ScopePolicy before it can become a finding.
"""
from __future__ import annotations

import asyncio
import json
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

import httpx
import yaml

from .models import Severity
from .checks.base import FindingCandidate
from .redaction import redact_data, redact_text, redact_url
from .scope import ScopePolicy, ScopeViolation


@dataclass(frozen=True)
class ZAPPlan:
    target_url: str
    plan_path: str


class ZAPAdapter:
    def __init__(self, base_url: str, workdir: str = "./reports/zap", api_key: str = "", timeout: float = 5.0):
        parsed = urlsplit(str(base_url).strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("ZAP base URL must be an absolute HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Credentials embedded in ZAP base URL are forbidden")
        if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
            raise ValueError("ZAP base URL must be an origin without path, query, or fragment")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("ZAP base URL has an invalid port") from exc
        if port == 0:
            raise ValueError("ZAP base URL port must be between 1 and 65535")
        self.base_url = str(base_url).rstrip("/")
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.api_key = str(api_key or "")
        self.timeout = max(1.0, min(float(timeout), 20.0))

    def write_plan(self, target_url: str) -> ZAPPlan:
        # Compatibility artifact for deployments that only want to verify passive
        # scan wait syntax. Production execution uses run_passive(), which builds a
        # context over the authenticated ZAP API and applies exclusions first.
        payload = {
            "env": {"contexts": [{
                "name": "FIREWATCH",
                "urls": [target_url],
                "includePaths": [target_url + ".*"],
                "excludePaths": [],
            }]},
            "jobs": [{"type": "passiveScan-wait", "parameters": {"maxDuration": 10}}],
        }
        path = self.workdir / "automation.yaml"
        path.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True), encoding="utf-8")
        return ZAPPlan(target_url, str(path))

    def _headers(self) -> dict[str, str]:
        # Never put the key in query strings or logs. Modern ZAP installations can
        # be configured to accept the standard X-ZAP-API-Key header.
        return {"X-ZAP-API-Key": self.api_key} if self.api_key else {}

    async def _call(self, component: str, kind: str, name: str, params: dict | None = None) -> dict:
        if not self.api_key:
            raise RuntimeError("ZAP_API_KEY is required for authenticated ZAP API access")
        url = f"{self.base_url}/JSON/{component}/{kind}/{name}/"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False, trust_env=False) as client:
            response = await client.get(url, params=params or {}, headers=self._headers())
            response.raise_for_status()
            data = response.json()
        if not isinstance(data, dict) or "error" in data:
            raise RuntimeError(f"ZAP API rejected {component}/{kind}/{name}")
        return data

    def health(self) -> bool:
        """Synchronous health check retained for health probes and compatibility tests."""
        try:
            req = urllib.request.Request(
                self.base_url + "/JSON/core/view/version/",
                headers=self._headers(), method="GET",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                payload = json.load(response)
            return bool(payload.get("version"))
        except Exception:
            return False

    async def health_async(self) -> bool:
        try:
            data = await self._call("core", "view", "version")
            return bool(data.get("version"))
        except Exception:
            return False

    @staticmethod
    def _origin_regexes(policy: ScopePolicy) -> list[str]:
        output: list[str] = []
        for host in sorted(policy.allowed_hosts):
            raw_host = f"[{host}]" if ":" in host else host
            for scheme in sorted(policy.allowed_schemes.get(host, frozenset({"http", "https"}))):
                for port in sorted(policy.allowed_ports.get(host, frozenset({80, 443}))):
                    default = 443 if scheme == "https" else 80
                    origin = f"{scheme}://{raw_host}" + (f":{port}" if port != default else "")
                    output.append("^" + re.escape(origin) + r"(?:/.*)?(?:\?.*)?$")
        return output

    @staticmethod
    def _exclude_regexes(policy: ScopePolicy) -> list[str]:
        result: list[str] = []
        for host in sorted(policy.allowed_hosts):
            raw_host = f"[{host}]" if ":" in host else host
            for scheme in sorted(policy.allowed_schemes.get(host, frozenset({"http", "https"}))):
                for port in sorted(policy.allowed_ports.get(host, frozenset({80, 443}))):
                    default = 443 if scheme == "https" else 80
                    origin = f"{scheme}://{raw_host}" + (f":{port}" if port != default else "")
                    for prefix in policy.excluded_prefixes:
                        p = str(prefix or "").strip()
                        if not p:
                            continue
                        if p.endswith("*"):
                            base = p[:-1]
                            tail = r".*"
                        else:
                            base = p
                            tail = r"(?:/.*)?(?:\?.*)?$"
                        if not base.startswith("/"):
                            base = "/" + base
                        result.append("^" + re.escape(origin + base) + tail)
        return result

    async def run_passive(
        self,
        policy: ScopePolicy,
        scan_id: str,
        *,
        max_duration_seconds: int = 90,
        max_alerts: int = 500,
        canceled: Callable[[], bool] | None = None,
    ) -> list[FindingCandidate]:
        """Run bounded Spider + passive scan, never active scanner, return scoped alerts."""
        if not self.api_key:
            raise RuntimeError("ZAP_API_KEY is required for the optional passive ZAP integration")
        max_duration_seconds = max(10, min(int(max_duration_seconds), 300))
        context_name = "FW_" + re.sub(r"[^A-Za-z0-9_]", "_", scan_id)[:40]
        await self._call("spider", "action", "setOptionProcessForm", {"Boolean": "false"})
        await self._call("spider", "action", "setOptionPostForm", {"Boolean": "false"})
        await self._call("spider", "action", "setOptionThreadCount", {"Integer": "2"})
        created = await self._call("context", "action", "newContext", {"contextName": context_name})
        if "contextId" not in created:
            raise RuntimeError("ZAP failed to create an isolated context")
        try:
            for expression in self._origin_regexes(policy):
                await self._call("context", "action", "includeInContext", {"contextName": context_name, "regex": expression})
            for expression in self._exclude_regexes(policy):
                await self._call("context", "action", "excludeFromContext", {"contextName": context_name, "regex": expression})

            started = await self._call("spider", "action", "scan", {
                "url": policy.root_url, "contextName": context_name, "recurse": "true",
                "subtreeOnly": "true", "maxChildren": "500",
            })
            scan_number = str(started.get("scan", ""))
            if not scan_number.isdigit():
                raise RuntimeError("ZAP Spider did not return a valid scan id")
            deadline = asyncio.get_running_loop().time() + max_duration_seconds
            while True:
                if canceled and canceled():
                    try:
                        await self._call("spider", "action", "stop", {"scanId": scan_number})
                    finally:
                        return []
                status = await self._call("spider", "view", "status", {"scanId": scan_number})
                try:
                    percent = int(status.get("status", "0"))
                except (TypeError, ValueError):
                    percent = 0
                if percent >= 100:
                    break
                if asyncio.get_running_loop().time() >= deadline:
                    await self._call("spider", "action", "stop", {"scanId": scan_number})
                    raise TimeoutError("ZAP passive Spider exceeded its time budget")
                await asyncio.sleep(0.5)

            # Passive scanning occurs as Spider requests are processed. Wait for its queue
            # to drain within the same overall deadline.
            passive_deadline = asyncio.get_running_loop().time() + min(30.0, max(5.0, max_duration_seconds / 2))
            queue_drained = False
            while asyncio.get_running_loop().time() < passive_deadline:
                if canceled and canceled():
                    return []
                records = await self._call("pscan", "view", "recordsToScan")
                try:
                    pending = int(records.get("recordsToScan", "0"))
                except (TypeError, ValueError):
                    pending = 0
                if pending <= 0:
                    queue_drained = True
                    break
                await asyncio.sleep(0.5)
            if not queue_drained:
                raise TimeoutError("ZAP passive scanning queue did not drain within the time budget")

            payload = await self._call("core", "view", "alerts", {"baseurl": policy.root_url, "start": "0", "count": str(max(1, min(max_alerts, 1000)))})
            alerts = payload.get("alerts", [])
            if not isinstance(alerts, list):
                return []
            candidates: list[FindingCandidate] = []
            seen: set[tuple[str, str]] = set()
            for alert in alerts[:max_alerts]:
                if not isinstance(alert, dict):
                    continue
                url = str(alert.get("url") or "")
                try:
                    scoped_url = policy.validate_url(url)
                except (ScopeViolation, ValueError):
                    continue
                plugin_id = re.sub(r"[^A-Za-z0-9_.-]", "", str(alert.get("pluginId") or "unknown"))[:80]
                signature = (plugin_id, redact_url(scoped_url))
                if signature in seen:
                    continue
                seen.add(signature)
                risk_raw = str(alert.get("risk") or "Informational").lower()
                severity = {
                    "high": Severity.HIGH, "medium": Severity.MEDIUM,
                    "low": Severity.LOW, "informational": Severity.INFO,
                }.get(risk_raw, Severity.INFO)
                confidence_raw = str(alert.get("confidence") or "Low").lower()
                confidence = {"high": .95, "medium": .78, "low": .55, "false positive": .1}.get(confidence_raw, .5)
                title = redact_text(str(alert.get("name") or f"ZAP passive alert {plugin_id}"))[:500]
                desc = redact_text(str(alert.get("description") or "ZAP passive scanner reported a candidate finding."))[:5000]
                solution = redact_text(str(alert.get("solution") or "Review the alert and apply the recommended secure configuration."))[:5000]
                evidence = {
                    "source": "OWASP ZAP passive scanner",
                    "plugin_id": plugin_id,
                    "risk": risk_raw,
                    "confidence": confidence_raw,
                    "method": str(alert.get("method") or "GET")[:16],
                    "parameter": redact_text(str(alert.get("param") or ""))[:200],
                    "evidence": redact_text(str(alert.get("evidence") or ""))[:1000],
                    "cwe_id": redact_text(str(alert.get("cweid") or ""))[:32],
                    "wasc_id": redact_text(str(alert.get("wascid") or ""))[:32],
                }
                candidates.append(FindingCandidate(
                    rule_id=f"ZAP-{plugin_id}", category="zap-passive", title=title,
                    severity=severity, confidence=confidence, endpoint=redact_url(scoped_url),
                    description=desc, impact=desc,
                    remediation=solution,
                    evidence_summary=f"ZAP passive alert: {title}",
                    references=[], evidence=redact_data(evidence),
                ))
            return candidates
        finally:
            # Remove per-scan contexts even on cancellation, timeout or API failure.
            # ZAP keeps contexts in its long-lived process; leaking one per scan would
            # grow memory and retained scope metadata over time.
            try:
                await self._call("context", "action", "removeContext", {"contextName": context_name})
            except Exception:
                pass
