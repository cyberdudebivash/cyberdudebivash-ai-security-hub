# ============================================================
# CYBERDUDEBIVASH AI — SCHEDULER TASKS (HARDENED)
# Fixes: reuses agent instance across loop (no redundant init),
#        proper error isolation, idempotent execution
# ============================================================

from celery.exceptions import SoftTimeLimitExceeded
from generated_app.core.celery_app import celery_app
from core.logging_config import get_logger

logger = get_logger("tasks.scheduler")

# Configurable threat sweep targets
KNOWN_THREAT_INDICATORS = [
    {"target": "192.168.100.254", "type": "ip_address"},
    {"target": "suspicious-example.com", "type": "domain"},
]


@celery_app.task(
    name="generated_app.tasks.scheduler_tasks.scheduled_threat_sweep",
    queue="default",
    ignore_result=False,
    max_retries=1,
)
def scheduled_threat_sweep() -> dict:
    """Automated threat sweep every 4 hours."""
    logger.info("[Scheduler] Starting automated threat sweep")
    results = []
    errors = []

    try:
        # Create one agent instance — reuse across all indicators (Fix #14)
        from core.agents.cyber_agents import ThreatIntelAgent
        agent = ThreatIntelAgent()

        for indicator in KNOWN_THREAT_INDICATORS:
            try:
                result = agent.execute({
                    "target": indicator["target"],
                    "type": indicator.get("type"),
                })
                results.append({
                    "target": indicator["target"],
                    "status": result.get("status"),
                    "threat_level": result.get("output", {}).get("threat_level", "UNKNOWN"),
                })
            except Exception as e:
                logger.error(f"Threat sweep failed for {indicator['target']}: {e}")
                errors.append({"target": indicator["target"], "error": str(e)})

    except SoftTimeLimitExceeded:
        logger.error("[Scheduler] Threat sweep exceeded time limit")
        return {"status": "timeout", "checked": len(results), "errors": len(errors)}
    except Exception as e:
        logger.error(f"[Scheduler] Threat sweep agent init failed: {e}")
        return {"status": "error", "error": str(e)}

    logger.info(f"[Scheduler] Threat sweep complete: {len(results)} checked, {len(errors)} errors")
    return {
        "status": "completed",
        "checked": len(results),
        "errors_count": len(errors),
        "results": results,
        "errors": errors,
    }


@celery_app.task(
    name="generated_app.tasks.scheduler_tasks.scheduled_health_check",
    queue="default",
    ignore_result=False,
)
def scheduled_health_check() -> dict:
    """System health check every 15 minutes."""
    try:
        from core.database.db_engine import health_check as db_health
        from generated_app.core.redis_client import redis_health

        db_ok = db_health()
        redis_ok = redis_health()
        overall = "healthy" if (db_ok and redis_ok) else "degraded"

        if overall == "degraded":
            logger.warning(f"[Scheduler] Health DEGRADED: DB={db_ok} Redis={redis_ok}")
        else:
            logger.info(f"[Scheduler] Health OK: DB={db_ok} Redis={redis_ok}")

        return {"status": overall, "db": db_ok, "redis": redis_ok}
    except Exception as e:
        logger.error(f"[Scheduler] Health check failed: {e}")
        return {"status": "error", "error": str(e)}


@celery_app.task(
    name="generated_app.tasks.scheduler_tasks.scheduled_memory_cleanup",
    queue="default",
    ignore_result=False,
)
def scheduled_memory_cleanup() -> dict:
    """Daily memory deduplication and cleanup."""
    try:
        from core.memory.memory_store import get_memory
        mem = get_memory()
        stats_before = mem.stats()

        records = mem.get_all()
        before_count = len(records)

        if before_count > 400:
            # Keep only last 400 — uses thread-safe atomic write
            mem._write(records[-400:])
            logger.info(f"[Scheduler] Memory trimmed: {before_count} → 400 entries")

        stats_after = mem.stats()
        return {
            "status": "completed",
            "before_entries": stats_before["total_entries"],
            "after_entries": stats_after["total_entries"],
            "bytes_freed": max(0, stats_before["size_bytes"] - stats_after["size_bytes"]),
        }
    except Exception as e:
        logger.error(f"[Scheduler] Memory cleanup failed: {e}")
        return {"status": "error", "error": str(e)}
