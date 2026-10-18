from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.db import Base
from app.auth_keys import generate_api_key, authenticate_database_key, validate_role_scopes, ROLE_SCOPES
from app.models import Tenant, TenantAPIKey
import pytest


def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine, expire_on_commit=False)()


def test_ultra_key_stores_only_hash_and_authenticates():
    engine, db = session()
    try:
        raw, prefix, digest = generate_api_key()
        tenant = Tenant(name="Unit tenant", slug="unit-tenant")
        db.add(tenant); db.flush()
        record = TenantAPIKey(tenant_id=tenant.id, key_prefix=prefix, key_hash=digest,
                              label="test-admin", role="admin", scopes=["*"], active=True)
        db.add(record); db.commit()
        matched = authenticate_database_key(db, raw)
        assert matched is not None
        assert matched[0].id == tenant.id
        assert matched[1].key_hash == digest
        assert raw not in record.key_hash
        assert authenticate_database_key(db, raw + "x") is None
    finally:
        db.close(); engine.dispose()


def test_ultra_expired_or_disabled_credentials_are_rejected():
    engine, db = session()
    try:
        raw, prefix, digest = generate_api_key()
        tenant = Tenant(name="Expired tenant", slug="expired-tenant")
        db.add(tenant); db.flush()
        record = TenantAPIKey(tenant_id=tenant.id, key_prefix=prefix, key_hash=digest,
            label="expired", role="viewer", scopes=list(ROLE_SCOPES["viewer"]), active=True,
            expires_at=datetime.now(timezone.utc) - timedelta(days=1))
        db.add(record); db.commit()
        assert authenticate_database_key(db, raw) is None
        record.expires_at = None; record.active = False; db.commit()
        assert authenticate_database_key(db, raw) is None
        tenant.active = False; record.active = True; db.commit()
        assert authenticate_database_key(db, raw) is None
    finally:
        db.close(); engine.dispose()


@pytest.mark.parametrize("role,scopes", [
    ("viewer", ["scans:write"]), ("operator", ["*"]), ("admin", ["unknown:permission"]),
    ("admin", []), ("other", ["app:read"]),
])
def test_ultra_invalid_role_scope_combinations_are_rejected(role, scopes):
    with pytest.raises(ValueError):
        validate_role_scopes(role, scopes)
