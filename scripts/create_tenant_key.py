#!/usr/bin/env python3
"""Create a tenant and issue a database-backed API key once.

Example:
  PYTHONPATH=backend python scripts/create_tenant_key.py --name "Example Co" --slug example-co --role admin

The raw key is printed once to stdout. Do not redirect it to a tracked file or
paste it into issue trackers/chat. The database stores only its SHA-256 digest.
"""
from __future__ import annotations
import argparse
import getpass
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.auth_keys import ROLE_SCOPES, generate_api_key, validate_role_scopes
from app.db import SessionLocal, init_db
from app.models import Tenant, TenantAPIKey


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--slug", required=True, help="Stable lowercase tenant slug")
    parser.add_argument("--label", default="initial-admin", help="Non-secret label for this credential")
    parser.add_argument("--role", choices=sorted(ROLE_SCOPES), default="admin")
    parser.add_argument("--scopes", help="Comma-separated scopes; defaults to the selected role's permissions")
    args = parser.parse_args()
    if not args.slug or len(args.slug) > 80 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in args.slug):
        parser.error("--slug must use lowercase a-z, digits and hyphens (1..80 chars)")
    if not os.getenv("DATABASE_URL"):
        print("Refusing to create an operational tenant key without an explicit DATABASE_URL.", file=sys.stderr)
        return 2
    if os.getenv("ENVIRONMENT", "development").lower() in {"production", "prod"}:
        print("Production key provisioning must run after `alembic upgrade head`.", file=sys.stderr)
    init_db()
    scopes = validate_role_scopes(args.role, (args.scopes.split(",") if args.scopes else ROLE_SCOPES[args.role]))
    raw, prefix, digest = generate_api_key()
    with SessionLocal() as db:
        tenant = db.query(Tenant).filter(Tenant.slug == args.slug).one_or_none()
        if tenant is None:
            tenant = Tenant(name=args.name.strip()[:200], slug=args.slug)
            db.add(tenant)
            db.flush()
        elif not tenant.active:
            print("Refusing to issue a key for an inactive tenant.", file=sys.stderr)
            return 3
        credential = TenantAPIKey(tenant_id=tenant.id, key_prefix=prefix, key_hash=digest,
                                  label=args.label.strip()[:120] or "api-key", role=args.role, scopes=scopes, active=True)
        db.add(credential)
        db.commit()
        tenant_id = tenant.id
    print("TENANT_ID=" + tenant_id)
    print("KEY_ID=" + credential.id)
    print("KEY_PREFIX=" + prefix)
    print("API_KEY (shown once; copy to your secret manager now):")
    print(raw)
    print("Scopes: " + ",".join(scopes))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
