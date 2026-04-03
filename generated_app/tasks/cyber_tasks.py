# ============================================================
# CYBERDUDEBIVASH AI — CYBERSECURITY CELERY TASKS (HARDENED)
# Fixes: exponential backoff, input validation, serialization,
#        soft time limit handling, idempotent execution
# ============================================================

from celery.exceptions import SoftTimeLimitExceeded
from generated_app.core.celery_app import celery_app
from core.logging_config import get_logger
import json

logger = get_logger("tasks.cyber")


def _safe_result(obj) -> dict:
    """Ensure task result is JSON-serializable."""
    try:
        json.dumps(obj)
        return obj
    except (TypeError, ValueError):
        return json.loads(json.dumps(obj, default=str))


def _exponential_countdown(retries: int, base: int = 15, max_wait: int = 300) -> int:
    return min(base * (2 ** retries), max_wait)


@celery_app.task(
    name="generated_app.tasks.cyber_tasks.run_threat_intel",
    bind=True, max_retries=3, queue="cyber_tasks", acks_late=True,
)
def run_threat_intel(self, target: str, indicator_type: str = None, tenant_id: str = "default") -> dict:
    try:
        if not target or not str(target).strip():
            return {"status": "error", "error": "Empty target"}
        from core.agents.cyber_agents import ThreatIntelAgent
        agent = ThreatIntelAgent()
        result = agent.execute({"target": str(target)[:500], "type": indicator_type})
        return _safe_result(result)
    except SoftTimeLimitExceeded:
        return {"status": "timeout", "error": "Threat intel task exceeded time limit"}
    except Exception as exc:
        logger.error(f"Threat intel failed for {target}: {exc}")
        raise self.retry(exc=exc, countdown=_exponential_countdown(self.request.retries))


@celery_app.task(
    name="generated_app.tasks.cyber_tasks.run_vulnerability_scan",
    bind=True, max_retries=3, queue="cyber_tasks", acks_late=True,
)
def run_vulnerability_scan(self, cve_id: str = None, software: str = None, version: str = None) -> dict:
    try:
        if not cve_id and not software:
            return {"status": "error", "error": "Must provide cve_id or software"}
        from core.agents.cyber_agents import VulnerabilityAgent
        agent = VulnerabilityAgent()
        return _safe_result(agent.execute({"cve_id": cve_id, "software": software, "version": version}))
    except SoftTimeLimitExceeded:
        return {"status": "timeout", "error": "Vulnerability scan exceeded time limit"}
    except Exception as exc:
        logger.error(f"Vuln scan failed: {exc}")
        raise self.retry(exc=exc, countdown=_exponential_countdown(self.request.retries))


@celery_app.task(
    name="generated_app.tasks.cyber_tasks.run_malware_analysis",
    bind=True, max_retries=3, queue="cyber_tasks", acks_late=True,
)
def run_malware_analysis(self, sample: str, sample_type: str = "hash", behavior: str = None) -> dict:
    try:
        if not sample or not str(sample).strip():
            return {"status": "error", "error": "Empty sample"}
        from core.agents.cyber_agents import MalwareAnalysisAgent
        agent = MalwareAnalysisAgent()
        return _safe_result(agent.execute({
            "sample": str(sample)[:500], "sample_type": sample_type or "hash",
            "behavior": behavior
        }))
    except SoftTimeLimitExceeded:
        return {"status": "timeout", "error": "Malware analysis exceeded time limit"}
    except Exception as exc:
        logger.error(f"Malware analysis failed: {exc}")
        raise self.retry(exc=exc, countdown=_exponential_countdown(self.request.retries))


@celery_app.task(
    name="generated_app.tasks.cyber_tasks.run_osint",
    bind=True, max_retries=3, queue="cyber_tasks", acks_late=True,
)
def run_osint(self, target: str, target_type: str = "organization") -> dict:
    try:
        if not target or not str(target).strip():
            return {"status": "error", "error": "Empty target"}
        from core.agents.cyber_agents import OSINTAgent
        agent = OSINTAgent()
        return _safe_result(agent.execute({"target": str(target)[:500], "target_type": target_type}))
    except SoftTimeLimitExceeded:
        return {"status": "timeout", "error": "OSINT task exceeded time limit"}
    except Exception as exc:
        logger.error(f"OSINT failed: {exc}")
        raise self.retry(exc=exc, countdown=_exponential_countdown(self.request.retries))


@celery_app.task(
    name="generated_app.tasks.cyber_tasks.run_security_audit",
    bind=True, max_retries=3, queue="cyber_tasks", acks_late=True,
)
def run_security_audit(self, code: str, language: str = "python", audit_type: str = "code") -> dict:
    try:
        if not code or not str(code).strip():
            return {"status": "error", "error": "Empty code"}
        # Enforce max code size in tasks too
        code_trimmed = str(code)[:50000]
        from core.agents.cyber_agents import SecurityAuditAgent
        agent = SecurityAuditAgent()
        return _safe_result(agent.execute({"code": code_trimmed, "language": language, "audit_type": audit_type}))
    except SoftTimeLimitExceeded:
        return {"status": "timeout", "error": "Security audit exceeded time limit"}
    except Exception as exc:
        logger.error(f"Security audit failed: {exc}")
        raise self.retry(exc=exc, countdown=_exponential_countdown(self.request.retries))


@celery_app.task(
    name="generated_app.tasks.cyber_tasks.run_swarm",
    bind=True, max_retries=2, queue="cyber_tasks", acks_late=True,
)
def run_swarm(self, task_data: dict) -> dict:
    try:
        if not isinstance(task_data, dict):
            task_data = {"task": str(task_data)}
        from core.agents.autonomous_engine import get_engine
        engine = get_engine()
        return _safe_result(engine.run(task_data))
    except SoftTimeLimitExceeded:
        return {"status": "timeout", "error": "Swarm task exceeded time limit"}
    except Exception as exc:
        logger.error(f"Swarm task failed: {exc}")
        raise self.retry(exc=exc, countdown=_exponential_countdown(self.request.retries))
