import os
import subprocess
import sys
from pathlib import Path
from sqlalchemy import create_engine, inspect, text

ROOT = Path(__file__).resolve().parents[2]


def test_ultra_fresh_database_migration_creates_required_schema(tmp_path):
    database = tmp_path / "fresh.db"
    env = dict(os.environ)
    env["DATABASE_URL"] = f"sqlite:///{database}"
    env["PYTHONPATH"] = str(ROOT / "backend")
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"), "upgrade", "head"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr[-4000:]
    engine = create_engine(f"sqlite:///{database}")
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        assert {"tenants", "tenant_api_keys", "security_audit_events", "scans", "projects", "alembic_version"}.issubset(tables)
        scan_columns = {c["name"] for c in inspector.get_columns("scans")}
        assert {"tenant_id", "lease_owner", "lease_expires_at", "heartbeat_at", "attempt_count", "max_attempts"}.issubset(scan_columns)
        page_columns = {c["name"] for c in inspector.get_columns("pages")}
        assert {"body_truncated", "body_encoding_unsupported"}.issubset(page_columns)
        with engine.connect() as connection:
            assert connection.execute(text("select version_num from alembic_version")).scalar_one() == "0002_body_truncation"
    finally:
        engine.dispose()
