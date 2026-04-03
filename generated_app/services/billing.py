# ============================================================
# CYBERDUDEBIVASH AI — BILLING SERVICE (HARDENED)
# Fixes: SELECT FOR UPDATE to prevent race conditions on credits,
#        proper transaction isolation, safe float comparisons
# ============================================================

from sqlalchemy.orm import Session
from fastapi import HTTPException
from core.database.models import Subscription
from core.logging_config import get_logger

logger = get_logger("service.billing")

_FREE_CREDITS = 10.0
_CREDIT_EPSILON = 0.001  # float comparison tolerance


def check_and_consume_credits(db: Session, tenant_id: str, cost: float) -> float:
    """
    Atomically check and consume credits.
    Uses row-level locking to prevent concurrent over-spending.
    """
    if cost < 0:
        raise ValueError("Cost cannot be negative")
    if cost == 0:
        return 0.0

    try:
        # Lock the row to prevent concurrent deductions (optimistic for SQLite, locking for PG)
        sub = db.query(Subscription).filter(
            Subscription.tenant_id == tenant_id
        ).with_for_update().first()

        if not sub:
            # Auto-provision free tier
            sub = Subscription(tenant_id=tenant_id, plan="free", credits=_FREE_CREDITS)
            db.add(sub)
            db.flush()
            logger.info(f"Auto-provisioned free subscription: tenant={tenant_id}")

        if sub.credits < (cost - _CREDIT_EPSILON):
            raise HTTPException(
                status_code=402,
                detail=f"Insufficient credits. Required: {cost:.4f}, Available: {sub.credits:.4f}",
            )

        sub.credits = round(sub.credits - cost, 6)  # avoid float drift
        db.commit()
        logger.info(f"Credits consumed: tenant={tenant_id} cost={cost} remaining={sub.credits:.4f}")
        return sub.credits

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Credit deduction failed: tenant={tenant_id} error={e}")
        raise HTTPException(status_code=503, detail="Billing service temporarily unavailable")


def get_subscription(db: Session, tenant_id: str) -> dict:
    sub = db.query(Subscription).filter(Subscription.tenant_id == tenant_id).first()
    if not sub:
        return {"tenant_id": tenant_id, "plan": "none", "credits": 0.0, "status": "no_subscription"}
    return {
        "tenant_id": tenant_id,
        "plan": sub.plan,
        "credits": round(sub.credits, 4),
        "renewal_date": sub.renewal_date.isoformat() if sub.renewal_date else None,
        "status": "active",
    }


def add_credits(db: Session, tenant_id: str, amount: float) -> float:
    """Add credits to a subscription."""
    if amount <= 0:
        raise ValueError("Amount must be positive")

    sub = db.query(Subscription).filter(
        Subscription.tenant_id == tenant_id
    ).with_for_update().first()

    if not sub:
        sub = Subscription(tenant_id=tenant_id, plan="free", credits=amount)
        db.add(sub)
    else:
        sub.credits = round(sub.credits + amount, 6)

    db.commit()
    logger.info(f"Credits added: tenant={tenant_id} amount={amount} new_balance={sub.credits}")
    return sub.credits
