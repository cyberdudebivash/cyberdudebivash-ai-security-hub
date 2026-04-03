# ============================================================
# CYBERDUDEBIVASH AI — USAGE SERVICE (HARDENED)
# Fixes: non-blocking write, safe pagination, datetime serialization
# ============================================================

from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime
from core.database.models import UsageLog
from core.logging_config import get_logger

logger = get_logger("service.usage")


def log_usage(
    db: Session,
    tenant_id: str,
    action: str,
    user_id: Optional[int] = None,
    tokens: int = 0,
    cost: float = 0.0,
    metadata: Optional[dict] = None,
) -> None:
    """Record usage. Never raises — failures are logged but don't fail the request."""
    if not tenant_id or not action:
        return

    try:
        usage = UsageLog(
            tenant_id=str(tenant_id)[:64],
            user_id=user_id,
            action=str(action)[:128],
            tokens_used=max(0, int(tokens)),
            cost=max(0.0, float(cost)),
            metadata=metadata or {},
        )
        db.add(usage)
        db.commit()
        logger.debug(f"Usage logged: action={action} tenant={tenant_id} cost={cost}")
    except Exception as e:
        db.rollback()
        logger.error(f"Usage log failed (non-critical): {e}")


def get_usage_summary(db: Session, tenant_id: str, limit: int = 50) -> dict:
    """Get paginated usage summary. Safe serialization of all fields."""
    try:
        logs = (
            db.query(UsageLog)
            .filter(UsageLog.tenant_id == tenant_id)
            .order_by(UsageLog.timestamp.desc())
            .limit(max(1, min(limit, 500)))  # clamp 1-500
            .all()
        )

        total_cost = sum(float(l.cost or 0) for l in logs)
        total_tokens = sum(int(l.tokens_used or 0) for l in logs)

        return {
            "tenant_id": tenant_id,
            "total_requests": len(logs),
            "total_tokens": total_tokens,
            "total_cost": round(total_cost, 6),
            "logs": [
                {
                    "action": l.action,
                    "cost": round(float(l.cost or 0), 6),
                    "tokens": int(l.tokens_used or 0),
                    "timestamp": l.timestamp.isoformat() if isinstance(l.timestamp, datetime) else str(l.timestamp),
                }
                for l in logs
            ],
        }
    except Exception as e:
        logger.error(f"Usage summary failed: {e}")
        return {"tenant_id": tenant_id, "total_requests": 0, "total_tokens": 0, "total_cost": 0.0, "logs": []}
