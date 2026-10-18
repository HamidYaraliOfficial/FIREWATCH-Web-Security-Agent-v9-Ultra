from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


engine_kwargs = {"future": True}
if settings.database_url.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(settings.database_url, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def init_db() -> None:
    """Initialize dev/test schemas; production schemas must be migrated explicitly.

    This prevents a running service from silently trying to evolve a production
    database via metadata.create_all(). Production rollout must run Alembic first.
    """
    from . import models  # noqa: F401
    environment = str(getattr(settings, "environment", "development")).lower()
    if environment in {"production", "prod"}:
        from sqlalchemy import inspect, text
        inspector = inspect(engine)
        if "alembic_version" not in inspector.get_table_names():
            raise RuntimeError("Production database is not migrated; run `alembic upgrade head` before starting FIREWATCH")
        with engine.connect() as connection:
            version = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
        if version != "0002_body_truncation":
            raise RuntimeError("Production database migration is not at the required FIREWATCH Ultra revision")
        required_columns = {"tenant_id", "lease_owner", "lease_expires_at", "heartbeat_at", "attempt_count", "max_attempts"}
        existing = {column["name"] for column in inspector.get_columns("scans")}
        missing = sorted(required_columns - existing)
        page_columns = {column["name"] for column in inspector.get_columns("pages")}
        for column_name in ("body_truncated", "body_encoding_unsupported"):
            if column_name not in page_columns:
                missing.append(f"pages.{column_name}")
        if missing:
            raise RuntimeError("Production schema lacks required Ultra columns: " + ", ".join(missing))
        return
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
