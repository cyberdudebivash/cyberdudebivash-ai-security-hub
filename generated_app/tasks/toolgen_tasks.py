# ============================================================
# CYBERDUDEBIVASH AI — CYBER TOOL ENGINE CELERY TASKS
# Async tool generation pipeline via Celery worker
# ============================================================

from celery.exceptions import SoftTimeLimitExceeded
from generated_app.core.celery_app import celery_app
from core.logging_config import get_logger
import json

logger = get_logger("tasks.toolgen")


def _safe_serialize(obj):
    try:
        json.dumps(obj)
        return obj
    except (TypeError, ValueError):
        return json.loads(json.dumps(obj, default=str))


@celery_app.task(
    name="generated_app.tasks.toolgen_tasks.generate_tools_from_intel",
    bind=True,
    max_retries=2,
    queue="cyber_tasks",
    acks_late=True,
)
def generate_tools_from_intel(
    self,
    raw_intel,
    source_type: str = "analysis",
    generate_tools: bool = True,
    generate_rules: bool = True,
    generate_playbooks: bool = True,
    tool_types=None,
    rule_types=None,
    tenant_id: str = "default",
) -> dict:
    """
    Full async pipeline: parse intel → classify → generate tools/rules/playbooks → store.
    """
    try:
        from core.cyber_tool_engine.engine import get_cyber_tool_engine
        engine = get_cyber_tool_engine()
        job = engine.generate_from_intel(
            raw_input=raw_intel,
            source_type=source_type,
            generate_tools=generate_tools,
            generate_rules=generate_rules,
            generate_playbooks=generate_playbooks,
            tool_types=tool_types,
            rule_types=rule_types,
        )
        result = job.to_dict()
        result["artifacts"] = {
            **{f"tool_{k}": v[:3000] for k, v in job.generated_tools.items()},
            **{f"rule_{k}": v[:3000] for k, v in job.generated_rules.items()},
            **{f"playbook_{k}": v[:2000] for k, v in job.generated_playbooks.items()},
        }
        logger.info(
            f"[ToolGen Task] Complete: tools={len(job.generated_tools)} "
            f"rules={len(job.generated_rules)} playbooks={len(job.generated_playbooks)}"
        )
        return _safe_serialize(result)

    except SoftTimeLimitExceeded:
        logger.error("[ToolGen Task] Soft time limit exceeded")
        return {"status": "timeout", "error": "Tool generation exceeded time limit"}
    except Exception as exc:
        logger.error(f"[ToolGen Task] Failed: {exc}")
        raise self.retry(exc=exc, countdown=min(30 * (2 ** self.request.retries), 300))


@celery_app.task(
    name="generated_app.tasks.toolgen_tasks.generate_tools_from_target",
    bind=True,
    max_retries=2,
    queue="cyber_tasks",
    acks_late=True,
)
def generate_tools_from_target(
    self,
    target: str,
    target_type: str = None,
    severity: str = "HIGH",
    context: str = None,
    tenant_id: str = "default",
) -> dict:
    """Generate tools from a raw target indicator (IP, CVE, domain, malware name)."""
    try:
        raw_intel = {
            "target": target,
            "indicator_type": target_type or "unknown",
            "threat_level": severity,
            "is_malicious": True,
            "summary": context or f"Threat analysis for {target}",
            "indicators_of_compromise": [target],
        }
        from core.cyber_tool_engine.engine import get_cyber_tool_engine
        job = get_cyber_tool_engine().generate_from_intel(
            raw_input=raw_intel, source_type="direct_target"
        )
        result = job.to_dict()
        result["artifacts"] = {
            **{f"tool_{k}": v[:3000] for k, v in job.generated_tools.items()},
            **{f"rule_{k}": v[:3000] for k, v in job.generated_rules.items()},
            **{f"playbook_{k}": v[:2000] for k, v in job.generated_playbooks.items()},
        }
        return _safe_serialize(result)

    except SoftTimeLimitExceeded:
        return {"status": "timeout", "error": "Tool generation exceeded time limit"}
    except Exception as exc:
        logger.error(f"[ToolGen Task] Target generation failed: {exc}")
        raise self.retry(exc=exc, countdown=30)


@celery_app.task(
    name="generated_app.tasks.toolgen_tasks.generate_tools_from_cve",
    bind=True,
    max_retries=2,
    queue="cyber_tasks",
    acks_late=True,
)
def generate_tools_from_cve(self, cve_id: str, tenant_id: str = "default") -> dict:
    """Generate vulnerability-specific detection tools and rules from a CVE."""
    try:
        raw_intel = {
            "cve_id": cve_id.upper(),
            "threat_level": "HIGH",
            "is_malicious": True,
            "threat_categories": ["exploit", "vulnerability"],
            "indicators_of_compromise": [cve_id.upper()],
            "summary": f"Vulnerability exploitation detection for {cve_id}",
            "attack_techniques": ["T1190"],
        }
        from core.cyber_tool_engine.engine import get_cyber_tool_engine
        job = get_cyber_tool_engine().generate_from_intel(
            raw_input=raw_intel, source_type="cve",
            generate_tools=True, generate_rules=True, generate_playbooks=True,
        )
        result = job.to_dict()
        result["artifacts"] = {
            **{f"tool_{k}": v[:3000] for k, v in job.generated_tools.items()},
            **{f"rule_{k}": v[:3000] for k, v in job.generated_rules.items()},
            **{f"playbook_{k}": v[:2000] for k, v in job.generated_playbooks.items()},
        }
        return _safe_serialize(result)

    except SoftTimeLimitExceeded:
        return {"status": "timeout", "error": "CVE tool generation exceeded time limit"}
    except Exception as exc:
        raise self.retry(exc=exc, countdown=30)


@celery_app.task(
    name="generated_app.tasks.toolgen_tasks.scheduled_threat_toolgen",
    queue="default",
)
def scheduled_threat_toolgen() -> dict:
    """
    Autonomous scheduled task: generates tools for top active threats.
    Runs on Celery Beat schedule.
    """
    generated = []
    try:
        from core.threat_memory.engine import get_threat_memory
        from core.cyber_tool_engine.engine import get_cyber_tool_engine

        tm = get_threat_memory()
        engine = get_cyber_tool_engine()

        # Get top active high-severity threats without existing tools
        active = [
            ioc for ioc in tm.get_active_threats(limit=10)
            if ioc.severity in ("CRITICAL", "HIGH")
        ]

        for ioc in active[:3]:  # process up to 3 per run
            intel = {
                "target": ioc.value,
                "indicator_type": ioc.ioc_type,
                "threat_level": ioc.severity,
                "is_malicious": True,
                "indicators_of_compromise": [ioc.value],
                "tags": ioc.tags,
            }
            job = engine.generate_from_intel(
                raw_input=intel, source_type="scheduled_auto",
                generate_tools=True, generate_rules=True, generate_playbooks=False,
            )
            generated.append({
                "ioc": ioc.value,
                "job_id": job.id,
                "tools": len(job.generated_tools),
                "rules": len(job.generated_rules),
                "status": job.status,
            })
            logger.info(f"[ScheduledToolgen] Generated tools for {ioc.value}: {job.status}")

    except Exception as e:
        logger.error(f"[ScheduledToolgen] Failed: {e}")
        return {"status": "error", "error": str(e)}

    return {"status": "completed", "generated": generated, "count": len(generated)}
