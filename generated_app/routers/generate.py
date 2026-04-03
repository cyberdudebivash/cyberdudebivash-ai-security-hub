# ============================================================
# CYBERDUDEBIVASH AI — GENERATE ROUTER (PRODUCTION HARDENED)
# Proper async dispatching, input validation, usage tracking
# ============================================================

from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session

from generated_app.database import get_db
from generated_app.models import GenerateRequest, GenerateResponse
from generated_app.middleware.tenant import resolve_tenant
from generated_app.middleware.rate_limit import rate_limiter
from generated_app.services.usage import log_usage
from generated_app.tasks.ai_tasks import run_autonomous_task, run_code_generation
from core.logging_config import get_logger, log_event

logger = get_logger("router.generate")
router = APIRouter(prefix="/generate", tags=["AI Generation"])


@router.post("", response_model=GenerateResponse)
async def generate(
    req: GenerateRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Submit an AI task for async execution. Poll /tasks/{task_id} for result."""
    tenant_id = await resolve_tenant(request, db)
    if not rate_limiter(tenant_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    task_data = {
        "task": req.prompt,
        "tenant_id": tenant_id,
        "mode": req.mode,
        "metadata": req.metadata or {},
    }

    try:
        task = run_autonomous_task.delay(task_data)
    except Exception as e:
        logger.error(f"Task dispatch failed: {e}")
        raise HTTPException(status_code=503, detail="Task queue unavailable. Ensure Redis is running.")

    log_usage(db, tenant_id, action="generate_task", cost=0.1)
    log_event("generate_task_submitted", {"tenant": tenant_id, "task_id": task.id, "mode": req.mode})

    return GenerateResponse(
        task_id=task.id,
        status="queued",
        message=f"Task queued. Poll /tasks/{task.id} for result.",
    )


@router.post("/code")
async def generate_code_async(
    req: GenerateRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Queue code generation task."""
    tenant_id = await resolve_tenant(request, db)
    if not rate_limiter(tenant_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    try:
        task = run_code_generation.delay(req.prompt, tenant_id)
    except Exception as e:
        logger.error(f"Code generation dispatch failed: {e}")
        raise HTTPException(status_code=503, detail="Task queue unavailable")

    log_usage(db, tenant_id, action="generate_code", cost=0.1)
    return {"task_id": task.id, "status": "queued", "poll": f"/tasks/{task.id}"}


@router.post("/code/sync")
async def generate_code_sync(
    req: GenerateRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Synchronous code generation — blocks until complete."""
    import asyncio
    from concurrent.futures import ThreadPoolExecutor
    tenant_id = await resolve_tenant(request, db)
    if not rate_limiter(tenant_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    try:
        from core.router.router_manager import get_router
        router = get_router()
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=1) as pool:
            code = await loop.run_in_executor(pool, router.generate_code, req.prompt)
        log_usage(db, tenant_id, action="generate_code_sync", cost=0.1)
        return {"status": "completed", "generated_code": code}
    except Exception as e:
        logger.error(f"Sync code generation failed: {e}")
        raise HTTPException(status_code=503, detail=f"Code generation failed: {e}")
