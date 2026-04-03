# ============================================================
# CYBERDUDEBIVASH AI — TENANT MIDDLEWARE (PRODUCTION HARDENED)
# Fixes: input validation, SQL injection guard, DB error handling
# ============================================================

import re
from fastapi import Request, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from core.database.models import APIKey, Tenant
from core.logging_config import get_logger

logger = get_logger("middleware.tenant")

# Regex to validate tenant_id — prevent injection via tenant header
_TENANT_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
# Prefix all valid API keys must start with
_API_KEY_PREFIX = "cdb-"
_API_KEY_MAX_LEN = 128


async def resolve_tenant(request: Request, db: Session) -> str:
    """
    Resolve tenant from request headers.
    Priority: x-api-key > x-tenant-id > 'default'
    """
    api_key_val = (request.headers.get("x-api-key") or "").strip()
    tenant_id_header = (request.headers.get("x-tenant-id") or "").strip()

    if api_key_val:
        # Validate format before DB query
        if len(api_key_val) > _API_KEY_MAX_LEN or not api_key_val.startswith(_API_KEY_PREFIX):
            raise HTTPException(status_code=401, detail="Invalid API key format")

        try:
            key = db.query(APIKey).filter(
                APIKey.key == api_key_val,
                APIKey.is_active == True,
            ).first()
        except Exception as e:
            logger.error(f"DB error on API key lookup: {e}")
            raise HTTPException(status_code=503, detail="Service temporarily unavailable")

        if not key:
            raise HTTPException(status_code=401, detail="Invalid or inactive API key")

        # Non-blocking last-used update
        try:
            key.last_used_at = datetime.now(timezone.utc)
            db.commit()
        except Exception:
            db.rollback()

        return key.tenant_id

    if tenant_id_header:
        # Validate format — prevent injection via header
        if not _TENANT_ID_RE.match(tenant_id_header):
            raise HTTPException(status_code=400, detail="Invalid tenant_id format")

        try:
            tenant = db.query(Tenant).filter(
                Tenant.id == tenant_id_header,
                Tenant.is_active == True,
            ).first()
        except Exception as e:
            logger.error(f"DB error on tenant lookup: {e}")
            raise HTTPException(status_code=503, detail="Service temporarily unavailable")

        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")

        return tenant_id_header

    return "default"
