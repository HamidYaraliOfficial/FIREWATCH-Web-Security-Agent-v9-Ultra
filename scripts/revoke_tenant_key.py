#!/usr/bin/env python3
"""Revoke a database-backed FIREWATCH tenant API key by key id or public prefix."""
from __future__ import annotations
import argparse, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.db import SessionLocal, init_db
from app.models import TenantAPIKey

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--key-id")
    group.add_argument("--prefix", help="Public prefix, e.g. fwk_abcdef12_")
    parser.add_argument("--yes", action="store_true", help="Confirm revocation without interactive prompt")
    args = parser.parse_args()
    if not os.getenv("DATABASE_URL"):
        print("Refusing to revoke keys without an explicit DATABASE_URL.", file=sys.stderr)
        return 2
    init_db()
    with SessionLocal() as db:
        query = db.query(TenantAPIKey)
        credential = query.filter(TenantAPIKey.id == args.key_id).one_or_none() if args.key_id else query.filter(TenantAPIKey.key_prefix == args.prefix).one_or_none()
        if credential is None:
            print("API key not found.", file=sys.stderr)
            return 1
        if not credential.active:
            print("API key is already inactive.")
            return 0
        if not args.yes:
            answer = input(f"Revoke key {credential.id} ({credential.key_prefix}, tenant {credential.tenant_id})? Type REVOKE: ")
            if answer != "REVOKE":
                print("Canceled.")
                return 3
        credential.active = False
        db.commit()
        print(f"Revoked key id={credential.id}, prefix={credential.key_prefix}, tenant_id={credential.tenant_id}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
