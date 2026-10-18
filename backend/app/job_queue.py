"""Lease-based PostgreSQL queue primitives for resilient scan workers.

Production relies on PostgreSQL row locks (`SKIP LOCKED`). SQLite is supported for
single-worker tests/development only and is not a production concurrency guarantee.
"""
from __future__ import annotations

import os
import socket
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from .config import settings
from .models import Scan, ScanStatus


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def default_worker_id(prefix: str = "worker") -> str:
    configured = os.getenv("FIREWATCH_WORKER_ID", "").strip()
    return configured[:160] if configured else f"{prefix}:{socket.gethostname()}:{os.getpid()}"


def claim_one(db: Session, worker_id: str, *, now: datetime | None = None) -> str | None:
    """Atomically claim the oldest queued or expired job and grant a lease.

    A RUNNING job with a missing lease is treated as stale (e.g. pre-Ultra rows).
    PostgreSQL uses `FOR UPDATE SKIP LOCKED` so multiple workers don't claim the
    same row. Callers should not claim production jobs with SQLite.
    """
    now = now or utcnow()
    expired_running = (Scan.status == ScanStatus.RUNNING) & or_(
        Scan.lease_expires_at.is_(None), Scan.lease_expires_at <= now
    )
    candidate = db.scalar(
        select(Scan)
        .where(or_(Scan.status == ScanStatus.QUEUED, expired_running))
        .order_by(Scan.created_at.asc())
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if candidate is None:
        return None
    if candidate.status == ScanStatus.RUNNING and int(candidate.attempt_count or 0) >= int(candidate.max_attempts or 3):
        candidate.status = ScanStatus.FAILED
        candidate.error = "Worker lease expired and maximum attempts were exhausted"
        candidate.finished_at = now
        candidate.lease_owner = None
        candidate.lease_expires_at = None
        candidate.heartbeat_at = now
        db.commit()
        return None
    candidate.status = ScanStatus.RUNNING
    candidate.lease_owner = worker_id[:160]
    candidate.lease_expires_at = now + timedelta(seconds=int(settings.worker_lease_seconds))
    candidate.heartbeat_at = now
    candidate.attempt_count = int(candidate.attempt_count or 0) + 1
    if candidate.started_at is None:
        candidate.started_at = now
    db.commit()
    return candidate.id


def renew_lease(db: Session, scan_id: str, worker_id: str, *, now: datetime | None = None) -> bool:
    """Renew only a lease that is still live and belongs to this worker."""
    now = now or utcnow()
    result = db.execute(
        update(Scan)
        .where(
            Scan.id == scan_id,
            Scan.status == ScanStatus.RUNNING,
            Scan.lease_owner == worker_id,
            Scan.lease_expires_at.is_not(None),
            Scan.lease_expires_at > now,
        )
        .values(heartbeat_at=now, lease_expires_at=now + timedelta(seconds=int(settings.worker_lease_seconds)))
    )
    db.commit()
    return result.rowcount == 1
