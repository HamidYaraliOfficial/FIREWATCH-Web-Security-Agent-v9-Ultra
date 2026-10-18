from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.job_queue import claim_one, renew_lease
from app.models import Scan, ScanStatus


def isolated_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return engine, Session()


def test_ultra_claim_sets_lease_and_attempt_count():
    engine, db = isolated_session()
    try:
        now = datetime(2026, 10, 18, 10, 0, tzinfo=timezone.utc)
        scan = Scan(target_url="https://example.test/", status=ScanStatus.QUEUED, config={})
        db.add(scan); db.commit()
        scan_id = claim_one(db, "worker-a", now=now)
        assert scan_id == scan.id
        db.refresh(scan)
        assert scan.status == ScanStatus.RUNNING
        assert scan.lease_owner == "worker-a"
        assert scan.attempt_count == 1
        assert scan.lease_expires_at is not None
    finally:
        db.close(); engine.dispose()


def test_ultra_heartbeat_renews_only_current_live_owner():
    engine, db = isolated_session()
    try:
        now = datetime(2026, 10, 18, 10, 0, tzinfo=timezone.utc)
        scan = Scan(target_url="https://example.test/", status=ScanStatus.QUEUED, config={})
        db.add(scan); db.commit()
        claim_one(db, "worker-a", now=now)
        assert renew_lease(db, scan.id, "worker-a", now=now + timedelta(seconds=5)) is True
        assert renew_lease(db, scan.id, "worker-b", now=now + timedelta(seconds=6)) is False
        assert renew_lease(db, scan.id, "worker-a", now=now + timedelta(seconds=1000)) is False
    finally:
        db.close(); engine.dispose()


def test_ultra_expired_lease_is_reclaimed_and_attempts_increment():
    engine, db = isolated_session()
    try:
        now = datetime(2026, 10, 18, 10, 0, tzinfo=timezone.utc)
        scan = Scan(target_url="https://example.test/", status=ScanStatus.RUNNING, config={},
                    lease_owner="dead-worker", lease_expires_at=now - timedelta(seconds=1), attempt_count=1, max_attempts=3)
        db.add(scan); db.commit()
        assert claim_one(db, "worker-b", now=now) == scan.id
        db.refresh(scan)
        assert scan.lease_owner == "worker-b"
        assert scan.attempt_count == 2
    finally:
        db.close(); engine.dispose()


def test_ultra_expired_lease_exhaustion_fails_closed():
    engine, db = isolated_session()
    try:
        now = datetime(2026, 10, 18, 10, 0, tzinfo=timezone.utc)
        scan = Scan(target_url="https://example.test/", status=ScanStatus.RUNNING, config={},
                    lease_owner="dead-worker", lease_expires_at=now - timedelta(seconds=1), attempt_count=3, max_attempts=3)
        db.add(scan); db.commit()
        assert claim_one(db, "worker-b", now=now) is None
        db.refresh(scan)
        assert scan.status == ScanStatus.FAILED
        assert scan.lease_owner is None
    finally:
        db.close(); engine.dispose()
