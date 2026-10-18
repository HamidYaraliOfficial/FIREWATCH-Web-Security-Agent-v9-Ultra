"""Add tenant key, audit and leased-worker columns.

Revision ID: 0001_ultra_tenancy_jobs
Revises:
Create Date: 2026-10-18
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0001_ultra_tenancy_jobs"
down_revision = None
branch_labels = None
depends_on = None

def _columns(bind, table):
    inspector = inspect(bind)
    if table not in inspector.get_table_names():
        return set()
    return {c["name"] for c in inspector.get_columns(table)}

def upgrade():
    bind = op.get_bind()
    # Fresh database: canonical metadata builds every table, including the newly
    # introduced tenant/audit tables. Existing databases are upgraded additively.
    from app.db import Base
    from app import models  # noqa: F401
    if "scans" not in inspect(bind).get_table_names():
        Base.metadata.create_all(bind=bind)
        return

    from app.models import Tenant, TenantAPIKey, SecurityAuditEvent
    Tenant.__table__.create(bind, checkfirst=True)
    TenantAPIKey.__table__.create(bind, checkfirst=True)
    SecurityAuditEvent.__table__.create(bind, checkfirst=True)

    col_map = {
        "projects": [sa.Column("tenant_id", sa.String(36), nullable=True)],
        "scans": [
            sa.Column("tenant_id", sa.String(36), nullable=True),
            sa.Column("lease_owner", sa.String(160), nullable=True),
            sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
        ],
    }
    for table, columns in col_map.items():
        existing = _columns(bind, table)
        if not existing:
            raise RuntimeError(f"Cannot migrate FIREWATCH schema: required table {table!r} is missing")
        for column in columns:
            if column.name not in existing:
                op.add_column(table, column)

    # PostgreSQL foreign keys are added explicitly so legacy rows remain nullable.
    if bind.dialect.name == "postgresql":
        inspector = inspect(bind)
        fks = {(fk.get("constrained_columns") or [None])[0] for fk in inspector.get_foreign_keys("projects")}
        if "tenant_id" not in fks:
            op.create_foreign_key("fk_projects_tenant_id", "projects", "tenants", ["tenant_id"], ["id"], ondelete="SET NULL")
        scan_fks = {(fk.get("constrained_columns") or [None])[0] for fk in inspector.get_foreign_keys("scans")}
        if "tenant_id" not in scan_fks:
            op.create_foreign_key("fk_scans_tenant_id", "scans", "tenants", ["tenant_id"], ["id"], ondelete="SET NULL")
    for table, column, index in [
        ("projects", "tenant_id", "ix_projects_tenant_id"),
        ("scans", "tenant_id", "ix_scans_tenant_id"),
        ("scans", "lease_owner", "ix_scans_lease_owner"),
        ("scans", "lease_expires_at", "ix_scans_lease_expires_at"),
        ("scans", "heartbeat_at", "ix_scans_heartbeat_at"),
    ]:
        if column in _columns(bind, table):
            existing_indexes = {i["name"] for i in inspect(bind).get_indexes(table)}
            if index not in existing_indexes:
                op.create_index(index, table, [column], unique=False)

def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        # Avoid pretending that SQLite can reliably remove all foreign keys in an
        # additive migration. Downgrade is intentionally a no-op for data safety.
        return
    for index, table in [
        ("ix_scans_heartbeat_at", "scans"), ("ix_scans_lease_expires_at", "scans"),
        ("ix_scans_lease_owner", "scans"), ("ix_scans_tenant_id", "scans"), ("ix_projects_tenant_id", "projects")]:
        try: op.drop_index(index, table_name=table)
        except Exception: pass
    for table, column in [("scans", "max_attempts"), ("scans", "attempt_count"), ("scans", "heartbeat_at"),
                          ("scans", "lease_expires_at"), ("scans", "lease_owner"), ("scans", "tenant_id"),
                          ("projects", "tenant_id")]:
        if column in _columns(bind, table):
            op.drop_column(table, column)
    for table in ("security_audit_events", "tenant_api_keys", "tenants"):
        if table in inspect(bind).get_table_names():
            op.drop_table(table)
