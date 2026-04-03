# ============================================================
# CYBERDUDEBIVASH AI — BILLING ROUTER (PRODUCTION HARDENED)
# ============================================================

from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session
from typing import Optional

from generated_app.database import get_db
from generated_app.middleware.tenant import resolve_tenant
from generated_app.services.billing import get_subscription, add_credits
from core.logging_config import get_logger, log_event

logger = get_logger("router.billing")
router = APIRouter(prefix="/billing", tags=["Billing"])


@router.get("/subscription")
async def get_sub(request: Request, db: Session = Depends(get_db)):
    """Get current tenant's subscription and credit balance."""
    tenant_id = await resolve_tenant(request, db)
    return get_subscription(db, tenant_id)


@router.post("/topup")
async def topup(request: Request, db: Session = Depends(get_db)):
    """Add credits to the current tenant (stub — wire to Stripe in production)."""
    tenant_id = await resolve_tenant(request, db)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    amount = body.get("amount")
    if amount is None:
        raise HTTPException(status_code=400, detail="amount field required")
    try:
        amount = float(amount)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="amount must be a number")
    if amount <= 0 or amount > 100000:
        raise HTTPException(status_code=400, detail="amount must be between 0 and 100000")

    new_balance = add_credits(db, tenant_id, amount)
    log_event("credits_added", {"tenant": tenant_id, "amount": amount, "new_balance": new_balance})
    return {
        "status": "success",
        "tenant_id": tenant_id,
        "credits_added": amount,
        "new_balance": round(new_balance, 4),
    }


@router.post("/checkout")
async def checkout():
    """Stripe checkout (configure STRIPE_SECRET_KEY to enable)."""
    from core.settings import settings
    if not settings.stripe_secret_key:
        return {
            "status": "not_configured",
            "message": "Set STRIPE_SECRET_KEY in .env to enable Stripe payments",
        }
    return {"status": "stripe_configured", "message": "Implement Stripe checkout here"}
