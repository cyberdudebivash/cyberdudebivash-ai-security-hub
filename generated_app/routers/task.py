# ============================================================
# CYBERDUDEBIVASH AI — TASK ROUTER (PRODUCTION HARDENED)
# Full task lifecycle management, pagination, safe serialization
# ============================================================

from fastapi import APIRouter, HTTPException, Query
from celery.result import AsyncResult
from typing import Optional
import json

from generated_app.core.celery_app import celery_app
from core.logging_config import get_logger

logger = get_logger("router.task")
router = APIRouter(prefix="/tasks", tags=["Task Management"])


def _safe_result(result):
    """Safely serialize Celery task result — handles non-JSON-serializable values."""
    if result is None:
        return None
    try:
        json.dumps(result)
        return result
    except (TypeError, ValueError):
        return json.loads(json.dumps(result, default=str))


@router.get("/{task_id}")
def get_task_status(task_id: str):
    """Get real-time status and result of any async task."""
    if not task_id or len(task_id) > 64:
        raise HTTPException(status_code=400, detail="Invalid task_id")

    try:
        task = AsyncResult(task_id, app=celery_app)
        state = task.state

        base = {"task_id": task_id, "status": state.lower()}

        if state == "PENDING":
            return {**base, "status": "pending", "result": None}
        elif state == "STARTED":
            return {**base, "status": "processing", "result": None}
        elif state == "SUCCESS":
            return {**base, "status": "completed", "result": _safe_result(task.result)}
        elif state == "FAILURE":
            err = task.result
            return {
                **base,
                "status": "failed",
                "error": str(err) if err else "Unknown error",
                "result": None,
            }
        elif state == "RETRY":
            return {**base, "status": "retrying", "result": None}
        elif state == "REVOKED":
            return {**base, "status": "cancelled", "result": None}
        else:
            return {**base, "status": state.lower(), "result": None}

    except Exception as e:
        logger.error(f"Task status lookup failed for {task_id}: {e}")
        raise HTTPException(status_code=503, detail="Task status temporarily unavailable")


@router.delete("/{task_id}")
def cancel_task(task_id: str):
    """Cancel a pending or running task."""
    if not task_id or len(task_id) > 64:
        raise HTTPException(status_code=400, detail="Invalid task_id")
    try:
        celery_app.control.revoke(task_id, terminate=True, signal="SIGTERM")
        return {"task_id": task_id, "status": "cancellation_requested"}
    except Exception as e:
        logger.error(f"Task cancellation failed for {task_id}: {e}")
        raise HTTPException(status_code=503, detail="Cancellation request failed")


@router.get("/")
def list_active_tasks():
    """List all currently active and scheduled tasks."""
    try:
        inspect = celery_app.control.inspect(timeout=2.0)
        active = inspect.active() or {}
        reserved = inspect.reserved() or {}

        active_list = []
        for worker, tasks in active.items():
            for t in (tasks or []):
                active_list.append({
                    "task_id": t.get("id"),
                    "name": t.get("name"),
                    "worker": worker,
                    "state": "active",
                    "args": str(t.get("args", []))[:100],
                })

        scheduled_list = []
        for worker, tasks in reserved.items():
            for t in (tasks or []):
                scheduled_list.append({
                    "task_id": t.get("id"),
                    "name": t.get("name"),
                    "worker": worker,
                    "state": "scheduled",
                })

        return {
            "active_count": len(active_list),
            "scheduled_count": len(scheduled_list),
            "active": active_list,
            "scheduled": scheduled_list,
        }
    except Exception as e:
        logger.warning(f"Worker inspection failed: {e}")
        return {
            "active_count": 0,
            "scheduled_count": 0,
            "active": [],
            "scheduled": [],
            "note": "Workers may be unavailable or starting up",
        }
