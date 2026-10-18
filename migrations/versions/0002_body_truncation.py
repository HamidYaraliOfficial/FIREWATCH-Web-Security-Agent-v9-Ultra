"""Record bounded response-body truncation state on crawled pages.

Revision ID: 0002_body_truncation
Revises: 0001_ultra_tenancy_jobs
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0002_body_truncation"
down_revision = "0001_ultra_tenancy_jobs"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if "pages" not in inspect(bind).get_table_names():
        raise RuntimeError("Cannot apply body-truncation migration: pages table is missing")
    columns = {column["name"] for column in inspect(bind).get_columns("pages")}
    if "body_truncated" not in columns:
        op.add_column("pages", sa.Column("body_truncated", sa.Boolean(), nullable=False, server_default=sa.false()))
    if "body_encoding_unsupported" not in columns:
        op.add_column("pages", sa.Column("body_encoding_unsupported", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        # SQLite downgrade schema rewrite is deliberately not attempted by this migration.
        return
    columns = {column["name"] for column in inspect(bind).get_columns("pages")}
    if "body_encoding_unsupported" in columns:
        op.drop_column("pages", "body_encoding_unsupported")
    if "body_truncated" in columns:
        op.drop_column("pages", "body_truncated")
