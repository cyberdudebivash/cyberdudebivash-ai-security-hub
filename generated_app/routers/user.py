# ============================================================
# CYBERDUDEBIVASH AI — USER ROUTER (PRODUCTION HARDENED)
# ============================================================

from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session

from generated_app.database import get_db
from generated_app.middleware.tenant import resolve_tenant
from generated_app.middleware.rate_limit import rate_limiter
from generated_app.services.usage import get_usage_summary, log_usage
from generated_app.services.billing import get_subscription, check_and_consume_credits
from generated_app.tasks.ai_tasks import run_autonomous_task
from core.logging_config import log_event, get_logger

logger = get_logger("router.user")
router = APIRouter(prefix="/user", tags=["User & Tenant"])


@router.post("/task")
async def submit_task(request: Request, db: Session = Depends(get_db)):
    """Submit an AI task for the current tenant."""
    tenant_id = await resolve_tenant(request, db)
    if not rate_limiter(tenant_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    task_prompt = str(body.get("task", "")).strip()
    if not task_prompt:
        raise HTTPException(status_code=400, detail="'task' field is required and cannot be empty")
    if len(task_prompt) > 10000:
        raise HTTPException(status_code=400, detail="Task prompt too long (max 10000 chars)")

    cost = 0.5
    check_and_consume_credits(db, tenant_id, cost)

    try:
        task = run_autonomous_task.delay({"task": task_prompt, "tenant_id": tenant_id})
    except Exception as e:
        logger.error(f"Task dispatch failed for tenant {tenant_id}: {e}")
        raise HTTPException(status_code=503, detail="Task queue unavailable. Ensure Redis is running.")

    log_usage(db, tenant_id, action="submit_task", cost=cost)
    log_event("user_task_dispatched", {"tenant": tenant_id, "task_id": task.id})

    return {
        "status": "accepted",
        "task_id": task.id,
        "tenant_id": tenant_id,
        "credits_consumed": cost,
        "poll": f"/tasks/{task.id}",
    }


@router.get("/usage")
async def usage(request: Request, db: Session = Depends(get_db)):
    """Get usage statistics for the current tenant."""
    tenant_id = await resolve_tenant(request, db)
    return get_usage_summary(db, tenant_id)


@router.get("/subscription")
async def subscription(request: Request, db: Session = Depends(get_db)):
    """Get subscription and credit balance."""
    tenant_id = await resolve_tenant(request, db)
    return get_subscription(db, tenant_id)


@router.get("/profile")
async def profile(request: Request, db: Session = Depends(get_db)):
    """Get current tenant profile."""
    from core.database.models import Tenant
    tenant_id = await resolve_tenant(request, db)
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        return {"tenant_id": tenant_id, "status": "default_tenant"}
    return {
        "tenant_id": tenant.id,
        "name": tenant.name,
        "is_active": tenant.is_active,
        "created_at": tenant.created_at.isoformat() if tenant.created_at else None,
    }
