from __future__ import annotations
import logging, asyncio, shutil
from datetime import datetime,timezone
from pathlib import Path
from sqlalchemy import select, func, update
from sqlalchemy.orm import Session
from .browser import BrowserDiscovery
from .config import settings
from .crawler import Crawler
from .evidence import normalize_candidate
from .models import Asset, Evidence, Finding, Page, Report, Scan, ScanEvent, ScanStatus
from .risk import calculate_risk
from .scope import ScopePolicy
from .checks.registry import run_page_rules
from .checks.base import FindingCandidate
from .models import Severity
from .checks.network_checks import inspect_tls
from .api_discovery import APIDiscovery
from .authz import AuthProfile, review_authorization
from .report import render,render_json
from .zap import ZAPAdapter
from .secret_store import reveal_config
from .parameter_probes import probe_reflected_query_inputs
from .check_catalog import coverage_matrix
from .report_extras import render_csv, render_markdown, render_sarif
from .redaction import redact_url, redact_data, redact_text
logger=logging.getLogger(__name__)
def utcnow(): return datetime.now(timezone.utc)
class ScanOrchestrator:
    def __init__(self, db: Session, worker_id: str | None = None, lease_lost: asyncio.Event | None = None):
        self.db = db
        self.worker_id = worker_id
        self.lease_lost = lease_lost

    def event(self, scan, phase, message, progress):
        safe_message = redact_text(str(message))[:1000]
        self.db.add(ScanEvent(scan_id=scan.id, phase=phase, message=safe_message, progress=float(progress)))
        self.db.commit()

    def _was_canceled(self, scan_id):
        status = self.db.scalar(select(Scan.status).where(Scan.id == scan_id))
        return status == ScanStatus.CANCELED

    def _should_stop(self, scan_id):
        return self._was_canceled(scan_id) or not self._owns_live_lease(scan_id)

    def _owns_live_lease(self, scan_id):
        if self.worker_id is None:
            return True
        if self.lease_lost is not None and self.lease_lost.is_set():
            return False
        row = self.db.execute(select(Scan.status, Scan.lease_owner, Scan.lease_expires_at).where(Scan.id == scan_id)).first()
        if row is None or row[0] != ScanStatus.RUNNING or row[1] != self.worker_id or row[2] is None:
            return False
        expiry = row[2]
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return expiry > utcnow()

    def _cancel_checkpoint(self, scan):
        if self._was_canceled(scan.id):
            if scan.finished_at is None:
                scan.finished_at = utcnow()
                self.db.commit()
            return True
        # A lost lease is a silent controlled exit: the replacement worker owns state.
        if not self._owns_live_lease(scan.id):
            return True
        return False
    def _headers(self,config):
        headers=dict(config.get('request_headers') or {})
        cookies=config.get('auth_cookies')
        if cookies and 'cookie' not in {k.lower() for k in headers}: headers['Cookie']=cookies
        return headers
    async def run(self,scan:Scan)->None:
        # Refresh before claiming the job so a cancellation issued between queue
        # selection and worker start cannot be overwritten by a stale ORM object.
        self.db.refresh(scan)
        if scan.status == ScanStatus.CANCELED:
            return
        if self.worker_id is not None:
            if not self._owns_live_lease(scan.id):
                return
        else:
            if scan.status != ScanStatus.RUNNING:
                scan.status = ScanStatus.RUNNING
            scan.started_at = scan.started_at or utcnow()
            self.db.commit()
        try:
            config=reveal_config(scan.config or {}); headers=self._headers(config)
            self._has_auth=bool(headers or config.get('authorization_profiles'))
            self.event(scan,'scope','Validating scope and scan policy',2)
            policy=ScopePolicy.from_root(scan.target_url,exclusions=config.get('exclusions',[]),allow_private_targets=settings.allow_private_targets,allowed_hosts=config.get('allowed_hosts',[]))
            if config.get('passive_only'): self.event(scan,'policy','Passive-only mode enabled; no active API introspection/browser workflows will be run',4)
            self.event(scan,'recon','Crawling target and building attack-surface inventory',8)
            crawler=Crawler(policy,max_pages=int(config.get('max_pages',settings.max_pages)),max_depth=int(config.get('max_depth',settings.max_depth)),delay_ms=int(config.get('request_delay_ms',settings.request_delay_ms)),respect_robots=bool(config.get('respect_robots',settings.respect_robots)),max_endpoints=int(config.get('max_endpoints',settings.max_endpoints)),headers=headers,max_concurrency=int(config.get('max_concurrency',settings.max_concurrency)),cancel_check=lambda: self._should_stop(scan.id))
            sitemap_urls=await crawler.discover_sitemaps()
            self.event(scan,'sitemap',f'Discovered {len(sitemap_urls)} same-scope sitemap URL candidates',7)
            pages=await crawler.crawl(seed_urls=sitemap_urls)
            if self._cancel_checkpoint(scan): return
            self.event(scan,'recon',f'Discovered {len(pages)} web pages/resources',28)
            truncated_page_count = sum(1 for page in pages if bool(getattr(page.observation, 'body_truncated', False)))
            unsupported_encoding_count = sum(1 for page in pages if bool(getattr(page.observation, 'body_encoding_unsupported', False)))
            for page_index, page in enumerate(pages):
                if page_index % 10 == 0 and self._cancel_checkpoint(scan):
                    return
                is_truncated = bool(getattr(page.observation, 'body_truncated', False))
                encoding_unsupported = bool(getattr(page.observation, 'body_encoding_unsupported', False))
                self.db.add(Page(scan_id=scan.id,url=redact_url(page.url),method='GET',status_code=page.observation.status_code,content_type=page.observation.content_type,title=page.title,depth=page.depth,headers=self._safe_headers(page.observation.headers),links=[redact_url(x) for x in page.links],resources=[redact_url(x) for x in page.resources],technologies=page.technologies,body_sha256=page.observation.body_sha256,body_truncated=is_truncated,body_encoding_unsupported=encoding_unsupported))
                self._asset(scan,page.url,'page',page.observation.status_code,page.observation.content_type,'crawler',{'depth':page.depth,'title':page.title,'technologies':page.technologies,'body_truncated':is_truncated,'body_encoding_unsupported':encoding_unsupported})
                for u in page.resources[:500]: self._asset(scan,u,'resource',None,None,'crawler',{})
                for u in page.js_endpoints[:500]: self._asset(scan,u,'js-api-candidate',None,None,'js-analysis',{})
                for candidate in run_page_rules(page,{'target':scan.target_url}): self._store_finding(scan,candidate)
            if truncated_page_count or unsupported_encoding_count:
                self.event(scan, 'coverage-limits', f'{truncated_page_count} response body/bodies exceeded the byte limit; {unsupported_encoding_count} body/bodies used unsupported content encoding and were not inspected. Findings may be incomplete for those pages.', 31)
            if config.get('enable_safe_parameter_probes',settings.enable_safe_parameter_probes) and not config.get('passive_only'):
                self.event(scan,'input-probes','Checking a bounded set of GET query parameters with harmless alphanumeric canaries only',34)
                probe_urls=[p.url for p in pages if '?' in p.url]
                reflected=await probe_reflected_query_inputs(policy,probe_urls,delay_ms=max(200,int(config.get('request_delay_ms',settings.request_delay_ms))),max_probes=settings.max_parameter_probes,headers=headers)
                for candidate in reflected: self._store_finding(scan,candidate)
                if self._cancel_checkpoint(scan): return
            profiles=[AuthProfile(str(x.get('name','profile')),dict(x.get('headers') or {})) for x in (config.get('authorization_profiles') or []) if isinstance(x,dict)]
            if len(profiles)>=2 and not config.get('passive_only'):
                authz_findings=await review_authorization(policy,[p.url for p in pages],profiles,delay_ms=int(config.get('request_delay_ms',settings.request_delay_ms)))
                for candidate in authz_findings: self._store_finding(scan,candidate)
            self.db.commit()
            if self._cancel_checkpoint(scan): return
            self.event(scan,'api','Discovering API specifications, GraphQL endpoints and OPTIONS/CORS posture',40)
            api=APIDiscovery(policy,delay_ms=int(config.get('request_delay_ms',settings.request_delay_ms)),headers=headers,max_endpoints=int(config.get('max_endpoints',settings.max_endpoints)))
            assets,api_findings,specs=await api.run(passive_only=bool(config.get('passive_only')))
            for url,kind,status,ct,meta in assets: self._asset(scan,url,kind,status,ct,'api-discovery',meta)
            for candidate in api_findings:self._store_finding(scan,candidate)
            if config.get('enable_api_introspection',settings.enable_api_introspection) and not config.get('passive_only'):
                graphqls=[x[0] for x in assets if x[1]=='graphql'][:10]
                for endpoint in graphqls:
                    if self._cancel_checkpoint(scan): return
                    result=await api.graphql_introspection(endpoint)
                    if result:
                        obs,data=result
                        types=data.get('data',{}).get('__schema',{}).get('types',[]) if isinstance(data,dict) else []
                        if types:
                            self._asset(scan,endpoint,'graphql-schema',obs.status_code,obs.content_type,'graphql-introspection',{'type_count':len(types)})
                            self._store_finding(scan,FindingCandidate('FW-GQL-002','graphql','GraphQL introspection enabled',Severity.LOW,.97,endpoint,'GraphQL introspection returned a schema to the supplied security-testing session.','Public schema exposure can simplify discovery of API capabilities.','Disable introspection in production when it is not required, or restrict it to trusted development/admin contexts.','Introspection query returned a schema.',evidence={'type_count':len(types)}))
                        else: self._asset(scan,endpoint,'graphql-endpoint',obs.status_code,obs.content_type,'graphql-introspection',{})
            self.db.commit()
            if self._cancel_checkpoint(scan): return
            self.event(scan,'transport','Inspecting TLS and redirect posture',58)
            for candidate in inspect_tls(scan.target_url, proxy_url=(settings.egress_proxy_url or None)): self._store_finding(scan,candidate)
            await self._redirect_checks(scan,policy,headers)
            self.event(scan,'metadata','Checking standard metadata and operational security endpoints',66)
            await self._metadata_checks(scan,policy,headers,active_checks=not bool(config.get('passive_only')))
            if config.get('enable_browser',settings.enable_browser) and not config.get('passive_only'):
                self.event(scan,'browser','Running same-origin browser discovery (no form submission)',75)
                try:
                    br=await BrowserDiscovery(policy,headers=headers,delay_ms=int(config.get('request_delay_ms',settings.request_delay_ms))).discover()
                    for u in br.resources: self._asset(scan,u,'browser-resource',None,None,'browser',{})
                    for u in br.requests: self._asset(scan,u,'browser-request',None,None,'browser',{})
                    for u in br.links: self._asset(scan,u,'browser-link',None,None,'browser',{})
                    if br.storage_keys: self._asset(scan,scan.target_url,'browser-storage',None,None,'browser',{'keys':br.storage_keys})
                    if br.cookies:
                        self._asset(scan,scan.target_url,'browser-cookies',None,None,'browser',{'count':len(br.cookies),'names':[c.get('name') for c in br.cookies[:100]]})
                except Exception as exc: self.event(scan,'browser',f'Browser discovery skipped: {type(exc).__name__}',84)
            if config.get('enable_zap', settings.enable_zap) and not config.get('passive_only'):
                self.event(scan, 'zap', 'Running bounded OWASP ZAP passive Spider; forms and active scanner are disabled', 88)
                try:
                    zap = ZAPAdapter(settings.zap_base_url, workdir=str(Path(settings.report_dir) / scan.id / 'zap'),
                                     api_key=settings.zap_api_key, timeout=min(10.0, settings.request_timeout_seconds))
                    if not await zap.health_async():
                        raise RuntimeError('ZAP health/API-key verification failed')
                    candidates = await zap.run_passive(
                        policy, scan.id, max_duration_seconds=int(config.get('zap_max_duration_seconds', 90)),
                        max_alerts=int(config.get('zap_max_alerts', 500)), canceled=lambda: self._should_stop(scan.id),
                    )
                    for candidate in candidates:
                        self._store_finding(scan, candidate)
                    self._asset(scan, scan.target_url, 'zap-passive-scan', None, None, 'zap',
                                {'alerts_imported': len(candidates), 'mode': 'passive-only', 'active_scanner_called': False})
                    self.db.commit()
                except Exception as exc:
                    self.event(scan, 'zap', f'ZAP passive integration unavailable: {type(exc).__name__}', 89)
                    logger.warning('ZAP passive integration failed for scan %s: %s', scan.id, type(exc).__name__)
            self.event(scan,'finalize','Deduplicating findings and rendering reports',90)
            if self._cancel_checkpoint(scan): return
            # Render report files and DB rows first. The report view is labelled
            # completed, but the persisted Scan remains RUNNING until the final
            # compare-and-swap transaction succeeds. A cancellation or lost lease
            # therefore cannot leave a completed database row without reports.
            if self._cancel_checkpoint(scan):
                return
            await self._write_reports(scan, pages, report_status=ScanStatus.COMPLETED, commit=False)
            finished = utcnow()
            self.db.add(ScanEvent(scan_id=scan.id, phase='complete', message='Scan completed', progress=100))
            predicate = [Scan.id == scan.id, Scan.status == ScanStatus.RUNNING]
            if self.worker_id is not None:
                predicate.extend([Scan.lease_owner == self.worker_id, Scan.lease_expires_at > finished])
            result = self.db.execute(
                update(Scan).where(*predicate).values(
                    status=ScanStatus.COMPLETED, finished_at=finished,
                    lease_owner=None, lease_expires_at=None,
                )
            )
            if result.rowcount != 1:
                self.db.rollback()
                # Output files may exist, but without report rows they are not
                # downloadable through the API. Remove the orphaned run folder.
                shutil.rmtree(Path(settings.report_dir) / scan.id, ignore_errors=True)
                self.db.refresh(scan)
                return
            self.db.commit()
            self.db.refresh(scan)
        except Exception as exc:
            self.db.rollback()
            if self._was_canceled(scan.id) or not self._owns_live_lease(scan.id):
                # Cancellation and lease loss are controlled exits. In particular,
                # an old worker must never overwrite the result of a replacement.
                return
            logger.exception('scan failed')
            predicate = [Scan.id == scan.id, Scan.status == ScanStatus.RUNNING]
            if self.worker_id is not None:
                predicate.append(Scan.lease_owner == self.worker_id)
            self.db.execute(update(Scan).where(*predicate).values(
                status=ScanStatus.FAILED, error=redact_text(str(exc))[:4000],
                finished_at=utcnow(), lease_owner=None, lease_expires_at=None,
            ))
            self.db.commit()
            raise
    def _safe_headers(self,h): return {k:('[REDACTED]' if k.lower() in {'authorization','cookie','set-cookie','x-api-key','proxy-authorization','www-authenticate'} else v) for k,v in h.items()}
    def _asset(self,scan,url,kind,status,ct,source,meta):
        safe_url=redact_url(url); safe_meta=redact_data(meta or {}); method=str((meta or {}).get('method','GET')).upper()
        if self.db.scalar(select(Asset.id).where(Asset.scan_id==scan.id,Asset.url==safe_url,Asset.kind==kind,Asset.method==method)) is None:
            self.db.add(Asset(scan_id=scan.id,url=safe_url,kind=kind,method=method,status_code=status,content_type=ct,source=source,authenticated=bool(getattr(self,'_has_auth',False)),metadata_json=safe_meta))
            # Sessions are configured with autoflush=False; flush so another
            # discovery source in this same transaction sees the new asset and
            # does not create a duplicate before the final scan commit.
            self.db.flush()
    def _store_finding(self,scan,c):
        c.endpoint=redact_url(c.endpoint)
        c.evidence_summary=redact_text(c.evidence_summary)
        c.evidence=redact_data(c.evidence or {})
        n=normalize_candidate(c)
        if self.db.scalar(select(Finding.id).where(Finding.scan_id==scan.id,Finding.dedupe_key==n.dedupe_key)): return
        f=Finding(scan_id=scan.id,rule_id=c.rule_id,category=c.category,title=c.title,severity=c.severity,confidence=max(0,min(1,c.confidence)),risk_score=calculate_risk(c.severity,c.confidence),endpoint=c.endpoint,description=c.description,impact=c.impact,remediation=c.remediation,references=c.references,evidence_summary=c.evidence_summary,dedupe_key=n.dedupe_key)
        self.db.add(f); self.db.flush(); self.db.add(Evidence(finding_id=f.id,kind='observation',data=c.evidence or {'summary':c.evidence_summary}))
    async def _redirect_checks(self,scan,policy,headers):
        from .http_client import SafeHTTPClient
        async with SafeHTTPClient(policy,delay_ms=int(scan.config.get('request_delay_ms',settings.request_delay_ms)),headers=headers) as client:
            obs=await client.request('GET',scan.target_url)
        loc=obs.headers.get('location') if obs else None
        if loc and scan.target_url.startswith('https://') and loc.startswith('http://'):
            from .checks.base import FindingCandidate
            from .models import Severity
            self._store_finding(scan,FindingCandidate('FW-TRANSPORT-001','transport','HTTPS redirects to HTTP',Severity.HIGH,.99,scan.target_url,'The target advertises a cleartext HTTP redirect destination.','A user can be downgraded to cleartext transport if they follow the redirect.','Keep canonical redirects on HTTPS and prevent cleartext downgrade paths.','Location header points from HTTPS to HTTP.',evidence={'location':loc}))
    async def _metadata_checks(self,scan,policy,headers,active_checks=True):
        from .http_client import SafeHTTPClient
        async with SafeHTTPClient(policy,delay_ms=int(scan.config.get('request_delay_ms',settings.request_delay_ms)),headers=headers) as client:
            p=urlparse(scan.target_url); base=f'{p.scheme}://{p.netloc}'
            for path in ('/.well-known/security.txt','/security.txt','/robots.txt','/sitemap.xml'):
                u=base+path; obs=await client.request('GET',u)
                if not obs.error and 200<=obs.status_code<400:
                    kind='security.txt' if 'security.txt' in path else path.lstrip('/')
                    self._asset(scan,u,kind,obs.status_code,obs.content_type,'metadata',{'length':len(obs.body)})
            if not active_checks: return
            # CORS reflection check using a synthetic untrusted origin; read-only GET only.
            probe_origin='https://firewatch.invalid'
            obs=await client.request('GET',scan.target_url,headers={'Origin':probe_origin})
            if obs.headers.get('access-control-allow-origin')==probe_origin:
                from .checks.base import FindingCandidate
                from .models import Severity
                self._store_finding(scan,FindingCandidate('FW-CORS-004','api','CORS origin reflection detected',Severity.MEDIUM,.9,scan.target_url,'The response reflected an arbitrary test Origin value in Access-Control-Allow-Origin.','Origin reflection can enable unintended cross-origin access when combined with sensitive resources or credentials.','Use a strict allow-list and validate origins server-side rather than reflecting arbitrary Origin values.','Injected test Origin was reflected.',evidence={'test_origin':probe_origin}))
            # One read-only preflight observation; no state-changing request is sent.
            pre=await client.request('OPTIONS',scan.target_url,headers={'Origin':'https://firewatch.invalid','Access-Control-Request-Method':'GET','Access-Control-Request-Headers':'authorization,content-type'})
            if not pre.error:
                acao=pre.headers.get('access-control-allow-origin',''); acac=pre.headers.get('access-control-allow-credentials','').lower(); methods=pre.headers.get('access-control-allow-methods','')
                if acao=='https://firewatch.invalid' and acac=='true':
                    from .checks.base import FindingCandidate
                    from .models import Severity
                    self._store_finding(scan,FindingCandidate('FW-CORS-005','api','Preflight reflects untrusted origin with credentials enabled',Severity.MEDIUM,.92,scan.target_url,'An OPTIONS preflight response reflected the synthetic untrusted Origin and enabled credentials.','If sensitive endpoints share this policy, untrusted browser origins may be able to read responses in a credentialed context.','Return only explicitly allow-listed origins; review credential policy and allowed methods/headers.','Preflight Origin was reflected while Access-Control-Allow-Credentials was true.',evidence={'allow_origin':acao,'allow_credentials':acac,'allow_methods':methods}))
            # Conservative diagnostic exposure probes: only bounded GETs, no secret values are retained.
            probe_paths={
                '/.git/HEAD': lambda b: b.strip().lower().startswith('ref: refs/') or bool(__import__('re').search(r'^[0-9a-f]{40}$',b.strip(),__import__('re').I)),
                '/.env': lambda b: bool(__import__('re').search(r'(?im)^(DB_PASSWORD|DATABASE_URL|APP_KEY|AWS_SECRET_ACCESS_KEY|SECRET_KEY)\s*=',b)),
                '/phpinfo.php': lambda b: 'phpinfo()' in b.lower() and 'php version' in b.lower(),
                '/server-status': lambda b: 'apache server status' in b.lower(),
                '/actuator/env': lambda b: 'propertysources' in b.lower() or 'activeprofiles' in b.lower(),
                '/_profiler': lambda b: 'profiler' in b.lower() and ('symfony' in b.lower() or 'toolbar' in b.lower()),
                '/elmah.axd': lambda b: 'elmah' in b.lower() and ('error log' in b.lower() or 'elmah.axd' in b.lower()),
                '/metrics': lambda b: bool(__import__('re').search(r'(?m)^(process_|http_server_|jvm_|python_)\w+\s',b)),
            }
            for path,detector in probe_paths.items():
                u=base+path
                obs=await client.request('GET',u)
                if obs.error or obs.status_code!=200: continue
                try: matched=bool(detector(obs.body[:300_000]))
                except Exception: matched=False
                if not matched: continue
                kind='diagnostic-exposure'
                self._asset(scan,u,kind,obs.status_code,obs.content_type,'safe-diagnostic-probe',{'signature_matched':True,'body_length':len(obs.body)})
                from .checks.base import FindingCandidate
                from .models import Severity
                severity=Severity.HIGH if path in {'/.env','/.git/HEAD','/actuator/env'} else Severity.MEDIUM
                self._store_finding(scan,FindingCandidate('FW-EXPOSE-001','information-disclosure','Potentially sensitive diagnostic/configuration endpoint exposed',severity,.96,u,f'A bounded read-only request matched a known diagnostic/configuration signature at `{path}`. The response body is not included in the finding.', 'Exposed runtime diagnostics, environment configuration, repository metadata, or metrics may reveal sensitive implementation details or credentials.', 'Restrict diagnostic endpoints to trusted administrative networks; remove repository/config artifacts from web roots; rotate secrets if an exposure is confirmed.', f'HTTP 200 and endpoint-specific signature matched at {path}.', evidence={'path':path,'status_code':obs.status_code,'body_length':len(obs.body),'signature_matched':True}))
    async def _write_reports(self, scan, pages, report_status=ScanStatus.COMPLETED, commit: bool = False):
        import copy
        report_dir=Path(settings.report_dir)/scan.id; report_dir.mkdir(parents=True,exist_ok=True)
        report_scan = copy.copy(scan)
        report_scan.status = report_status
        report_scan.finished_at = utcnow()
        report_scan.truncated_page_count = sum(1 for page in pages if bool(getattr(page.observation, 'body_truncated', False)))
        report_scan.unsupported_encoding_page_count = sum(1 for page in pages if bool(getattr(page.observation, 'body_encoding_unsupported', False)))
        findings=list(self.db.scalars(select(Finding).where(Finding.scan_id==scan.id).order_by(Finding.risk_score.desc())))
        events=list(self.db.scalars(select(ScanEvent).where(ScanEvent.scan_id==scan.id).order_by(ScanEvent.created_at.asc())))
        coverage=[{'phase':e.phase,'status':'completed' if e.progress>=100 else 'observed','details':e.message,'progress':e.progress} for e in events]
        matrix=coverage_matrix(findings)
        paths={
            'html':str(report_dir/'report.html'),
            'json':str(report_dir/'report.json'),
            'csv':str(report_dir/'findings.csv'),
            'markdown':str(report_dir/'report.md'),
            'sarif':str(report_dir/'report.sarif.json'),
        }
        render(report_scan,findings,events,paths['html'],coverage,coverage_catalog=matrix)
        render_json(report_scan,findings,events,paths['json'],coverage,coverage_catalog=matrix)
        render_csv(report_scan,findings,paths['csv'])
        render_markdown(report_scan,findings,coverage,paths['markdown'])
        render_sarif(report_scan,findings,paths['sarif'])
        self.db.query(Report).filter(Report.scan_id==scan.id).delete(synchronize_session=False)
        self.db.add_all([Report(scan_id=scan.id,format=fmt,path=path) for fmt,path in paths.items()])
        self.db.flush()
        if commit:
            self.db.commit()

from urllib.parse import urlparse
