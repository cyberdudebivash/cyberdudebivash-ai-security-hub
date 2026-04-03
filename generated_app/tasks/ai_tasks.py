# ============================================================
# CYBERDUDEBIVASH AI — AI CELERY TASKS (PRODUCTION HARDENED)
# Fixes: exponential backoff, task idempotency, result serialization
# ============================================================

from celery import Task
from celery.exceptions import SoftTimeLimitExceeded
from generated_app.core.celery_app import celery_app
from core.logging_config import get_logger

logger = get_logger("tasks.ai")


class BaseTaskWithRetry(Task):
    """Base task class with exponential backoff retry."""
    abstract = True

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        logger.error(f"Task {self.name}[{task_id}] permanently failed: {exc}")

    def on_retry(self, exc, task_id, args, kwargs, einfo):
        logger.warning(f"Task {self.name}[{task_id}] retrying: {exc}")


@celery_app.task(
    name="generated_app.tasks.ai_tasks.run_autonomous_task",
    bind=True,
    base=BaseTaskWithRetry,
    max_retries=3,
    default_retry_delay=10,
    queue="ai_tasks",
    acks_late=True,
)
def run_autonomous_task(self, task_data: dict) -> dict:
    """Execute a general AI task through the AutonomousEngine."""
    try:
        from core.agents.autonomous_engine import get_engine
        if not isinstance(task_data, dict):
            task_data = {"task": str(task_data)}

        task_str = task_data.get("task", "")
        if not task_str or not task_str.strip():
            return {"status": "error", "error": "Empty task", "results": []}

        engine = get_engine()
        result = engine.run(task_data)
        logger.info(f"Task completed: {task_str[:60]}")
        return _make_serializable(result)

    except SoftTimeLimitExceeded:
        logger.error(f"Task soft time limit exceeded for: {task_data.get('task', '')[:60]}")
        return {"status": "timeout", "error": "Task exceeded time limit", "results": []}
    except Exception as exc:
        logger.error(f"Task failed (attempt {self.request.retries + 1}): {exc}")
        countdown = min(10 * (2 ** self.request.retries), 300)  # exponential backoff, max 5min
        raise self.retry(exc=exc, countdown=countdown)


@celery_app.task(
    name="generated_app.tasks.ai_tasks.run_code_generation",
    bind=True,
    base=BaseTaskWithRetry,
    max_retries=2,
    default_retry_delay=15,
    queue="ai_tasks",
    acks_late=True,
)
def run_code_generation(self, prompt: str, tenant_id: str = "default") -> dict:
    """Generate production code via AI."""
    try:
        if not prompt or not str(prompt).strip():
            return {"status": "error", "error": "Empty prompt"}

        from core.router.router_manager import get_router
        router = get_router()
        code = router.generate_code(str(prompt)[:10000])
        return {
            "status": "completed",
            "prompt": str(prompt)[:100],
            "generated_code": code,
            "tenant_id": tenant_id,
        }
    except SoftTimeLimitExceeded:
        return {"status": "timeout", "error": "Code generation exceeded time limit"}
    except Exception as exc:
        logger.error(f"Code generation failed: {exc}")
        countdown = min(15 * (2 ** self.request.retries), 300)
        raise self.retry(exc=exc, countdown=countdown)


def _make_serializable(obj):
    """Ensure result is JSON-serializable for Celery backend."""
    import json
    try:
        json.dumps(obj)
        return obj
    except (TypeError, ValueError):
        import json as _json
        # Use str fallback for non-serializable objects
        return json.loads(json.dumps(obj, default=str))
