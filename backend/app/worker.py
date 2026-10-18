from __future__ import annotations

import asyncio
import logging
import time

from .config import settings, validate_settings
from .db import SessionLocal, init_db
from .job_queue import claim_one as queue_claim_one, default_worker_id, renew_lease
from .models import Scan
from .orchestrator import ScanOrchestrator

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("firewatch.worker")


def claim_scan(worker_id: str | None = None) -> str | None:
    worker_id = worker_id or default_worker_id()
    with SessionLocal() as db:
        return queue_claim_one(db, worker_id)


def claim_one() -> str | None:
    """Backward-compatible claim entry point used by operations/tests."""
    return claim_scan(default_worker_id())


async def _heartbeat(scan_id: str, worker_id: str, stop: asyncio.Event, lease_lost: asyncio.Event) -> None:
    interval = max(1, min(int(settings.worker_heartbeat_seconds), int(settings.worker_lease_seconds) // 3))
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
            return
        except asyncio.TimeoutError:
            pass
        try:
            with SessionLocal() as db:
                if not renew_lease(db, scan_id, worker_id):
                    lease_lost.set()
                    log.warning("lease lost for scan %s; worker will stop", scan_id)
                    return
        except Exception as exc:
            # A transient DB failure must not let this process assume it still
            # owns the lease. Fail closed; the next worker can recover after expiry.
            log.error("lease heartbeat failed for scan %s: %s", scan_id, type(exc).__name__)
            lease_lost.set()
            return


async def process_claimed_scan(scan_id: str, worker_id: str | None = None) -> None:
    worker_id = worker_id or default_worker_id()
    stop = asyncio.Event()
    lease_lost = asyncio.Event()
    heartbeat_task = asyncio.create_task(_heartbeat(scan_id, worker_id, stop, lease_lost))
    try:
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            if scan is None or scan.lease_owner != worker_id:
                return
            await ScanOrchestrator(db, worker_id=worker_id, lease_lost=lease_lost).run(scan)
    finally:
        stop.set()
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass


async def run_once(worker_id: str | None = None) -> bool:
    worker_id = worker_id or default_worker_id()
    scan_id = claim_scan(worker_id)
    if scan_id is None:
        return False
    try:
        await process_claimed_scan(scan_id, worker_id)
    except Exception:
        log.exception("scan processing failed: %s", scan_id)
    return True


def main() -> None:
    errors = validate_settings(settings)
    if errors:
        raise RuntimeError("Invalid FIREWATCH configuration: " + "; ".join(errors))
    init_db()
    worker_id = default_worker_id()
    log.info("FIREWATCH worker started (%s)", worker_id)
    if str(settings.environment).lower() in {"production", "prod"} and str(settings.database_url).lower().startswith("sqlite"):
        raise RuntimeError("SQLite is not supported for production workers")
    while True:
        try:
            worked = asyncio.run(run_once(worker_id))
        except Exception:
            log.exception("worker loop iteration failed")
            worked = False
        if not worked:
            time.sleep(1)


if __name__ == "__main__":
    main()
