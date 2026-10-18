"""Database-backed tenant API key primitives for FIREWATCH Ultra.

Only SHA-256 digests are stored. API key material is shown exactly once by the
administrative bootstrap CLI and must never be logged or returned by the API.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Tenant, TenantAPIKey

ROLE_SCOPES: dict[str, frozenset[str]] = {
    "viewer": frozenset({"app:read", "scans:read", "reports:read", "standards:read"}),
    "analyst": frozenset({"app:read", "scans:read", "reports:read", "standards:read"}),
    "operator": frozenset({"app:read", "scans:read", "scans:write", "reports:read", "standards:read", "standards:write"}),
    "admin": frozenset({"*"}),
}
VALID_SCOPES = frozenset({"app:read", "scans:read", "scans:write", "reports:read", "standards:read", "standards:write"})

@dataclass(frozen=True)
class Principal:
    actor: str
    role: str
    scopes: frozenset[str]
    tenant_id: str | None
    is_global_admin: bool = False
    api_key_id: str | None = None

    def allows(self, scope: str) -> bool:
        role_scopes = ROLE_SCOPES.get(self.role, frozenset())
        return "*" in self.scopes and "*" in role_scopes or (scope in self.scopes and scope in role_scopes)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def digest_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def key_prefix(raw_key: str) -> str:
    """Return a non-secret lookup prefix from the `fwk_<8hex>_<secret>` token."""
    bits = raw_key.split("_", 2)
    if len(bits) != 3 or bits[0] != "fwk" or len(bits[1]) != 8 or any(c not in "0123456789abcdef" for c in bits[1].lower()):
        return ""
    return f"fwk_{bits[1].lower()}_"


def generate_api_key() -> tuple[str, str, str]:
    prefix_fragment = secrets.token_hex(4)
    raw_key = f"fwk_{prefix_fragment}_{secrets.token_urlsafe(32)}"
    return raw_key, key_prefix(raw_key), digest_key(raw_key)


def authenticate_database_key(db: Session, raw_key: str) -> tuple[Tenant, TenantAPIKey] | None:
    prefix = key_prefix(raw_key)
    if not prefix:
        return None
    pair = db.execute(
        select(Tenant, TenantAPIKey)
        .join(TenantAPIKey, TenantAPIKey.tenant_id == Tenant.id)
        .where(TenantAPIKey.key_prefix == prefix, TenantAPIKey.active.is_(True), Tenant.active.is_(True))
    ).first()
    if not pair:
        return None
    tenant, credential = pair
    # Compare full digests in constant time after using the public prefix for lookup.
    import hmac
    if not hmac.compare_digest(credential.key_hash, digest_key(raw_key)):
        return None
    expiry = credential.expires_at
    if expiry is not None:
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= utcnow():
            return None
    return tenant, credential


def validate_role_scopes(role: str, scopes: Iterable[str]) -> list[str]:
    if role not in ROLE_SCOPES:
        raise ValueError("role must be viewer, analyst, operator, or admin")
    normalized = sorted({str(s).strip() for s in scopes if str(s).strip()})
    if not normalized:
        raise ValueError("at least one API scope is required")
    if "*" in normalized and role != "admin":
        raise ValueError("wildcard scope is only valid for admin role")
    unknown = set(normalized) - VALID_SCOPES - {"*"}
    if unknown:
        raise ValueError("unknown API scope: " + ", ".join(sorted(unknown)))
    allowed = ROLE_SCOPES[role]
    if "*" not in allowed and not set(normalized).issubset(allowed):
        raise ValueError("requested scope exceeds permissions granted by role")
    return normalized
