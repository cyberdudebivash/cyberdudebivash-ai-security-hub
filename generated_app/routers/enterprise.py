# ============================================================
# CYBERDUDEBIVASH AI — ENTERPRISE ROUTER
# All enterprise system endpoints: resilience, scaling,
# observability, chaos testing, monetization, threat memory
# ============================================================

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional

from generated_app.database import get_db
from core.logging_config import get_logger

logger = get_logger("router.enterprise")
router = APIRouter(prefix="/enterprise", tags=["Enterprise Systems"])


def _require_key(x_api_key: Optional[str] = Header(default=None, alias="x-api-key")):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="x-api-key required")
    return x_api_key


# ── Resilience ────────────────────────────────────────────────

@router.get("/resilience/status")
def resilience_status(_: str = Depends(_require_key)):
    """Full resilience orchestrator status: component health, circuit breakers, routing."""
    try:
        from core.resilience.orchestrator import get_orchestrator
        orch = get_orchestrator()
        return orch.health_report()
    except Exception as e:
        logger.error(f"Resilience status error: {e}")
        raise HTTPException(status_code=503, detail=str(e))


@router.get("/resilience/components/{component}")
def component_health(component: str, _: str = Depends(_require_key)):
    """Health details for a specific component."""
    try:
        from core.resilience.orchestrator import get_orchestrator
        orch = get_orchestrator()
        health = orch.registry.get_health(component)
        if not health:
            raise HTTPException(status_code=404, detail=f"Component '{component}' not registered")
        return health.to_dict()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.get("/resilience/circuit-breakers")
def circuit_breakers(_: str = Depends(_require_key)):
    """Status of all circuit breakers."""
    try:
        from core.resilience.orchestrator import get_orchestrator
        orch = get_orchestrator()
        return {
            name: cb.status()
            for name, cb in orch.registry._circuit_breakers.items()
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


# ── Scaling ───────────────────────────────────────────────────

@router.get("/scaling/status")
def scaling_status(_: str = Depends(_require_key)):
    """Auto-scaling engine status: queue depth, load factor, concurrency."""
    try:
        from core.scaling.engine import get_scaler
        return get_scaler().status()
    except Exception as e:
        logger.error(f"Scaling status error: {e}")
        raise HTTPException(status_code=503, detail=str(e))


@router.post("/scaling/evaluate")
def trigger_scaling_evaluation(_: str = Depends(_require_key)):
    """Manually trigger a scaling evaluation."""
    try:
        from core.scaling.engine import get_scaler
        scaler = get_scaler()
        scaler._evaluate_and_scale()
        return {"status": "evaluation_triggered", **scaler.status()}
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


# ── Observability ─────────────────────────────────────────────

@router.get("/observability/metrics")
def observability_metrics(_: str = Depends(_require_key)):
    """Full observability report: metrics, alerts, health scores."""
    try:
        from core.observability.metrics import get_observability
        return get_observability().full_report()
    except Exception as e:
        logger.error(f"Observability error: {e}")
        raise HTTPException(status_code=503, detail=str(e))


@router.get("/observability/alerts")
def active_alerts(_: str = Depends(_require_key)):
    """Current active alerts and recent alert history."""
    try:
        from core.observability.metrics import get_observability
        obs = get_observability()
        return {
            "active": obs.alerts.status(),
            "history": [a.to_dict() for a in obs.alerts.get_recent_history(20)],
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


# ── AI Super Router ───────────────────────────────────────────

@router.get("/ai-router/status")
def ai_router_status(_: str = Depends(_require_key)):
    """AI Super Router health: providers, cache stats, mode performance."""
    try:
        from core.ai_super_router.router import get_super_router
        return get_super_router().health()
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.post("/ai-router/cache/clear")
def clear_ai_cache(_: str = Depends(_require_key)):
    """Clear the AI response cache."""
    try:
        from core.ai_super_router.router import get_super_router
        get_super_router().cache.clear()
        return {"status": "cache_cleared"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.post("/ai-router/test")
async def test_ai_router(request_body: dict = None, _: str = Depends(_require_key)):
    """Test the AI Super Router with a prompt."""
    import asyncio
    from concurrent.futures import ThreadPoolExecutor
    try:
        body = request_body or {}
        prompt = str(body.get("prompt", "Analyze: 192.168.1.1"))[:1000]
        mode = str(body.get("mode", "threat_intel"))

        from core.ai_super_router.router import get_super_router
        router = get_super_router()
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = await loop.run_in_executor(pool, lambda: router.generate(prompt, mode))
        return result
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


# ── Threat Memory ─────────────────────────────────────────────

@router.get("/threat-memory/stats")
def threat_memory_stats(_: str = Depends(_require_key)):
    """Threat Memory Engine statistics."""
    try:
        from core.threat_memory.engine import get_threat_memory
        return get_threat_memory().statistics()
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.post("/threat-memory/lookup")
def lookup_ioc(target: str = Query(...), _: str = Depends(_require_key)):
    """Lookup a specific IOC in the threat memory database."""
    try:
        from core.threat_memory.engine import get_threat_memory
        tm = get_threat_memory()
        ioc = tm.lookup(target)
        if not ioc:
            return {"found": False, "target": target}
        return {"found": True, "ioc": ioc.to_dict()}
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.get("/threat-memory/active")
def active_threats(
    limit: int = Query(50, ge=1, le=200),
    _: str = Depends(_require_key),
):
    """Get most recently seen active IOCs."""
    try:
        from core.threat_memory.engine import get_threat_memory
        iocs = get_threat_memory().get_active_threats(limit=limit)
        return {"total": len(iocs), "iocs": [i.to_dict() for i in iocs]}
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.get("/threat-memory/patterns")
def threat_patterns(_: str = Depends(_require_key)):
    """Detected threat patterns (subnet clusters, domain families)."""
    try:
        from core.threat_memory.engine import get_threat_memory
        patterns = get_threat_memory().get_active_patterns(min_count=2)
        return {"total": len(patterns), "patterns": patterns}
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


# ── Monetization ──────────────────────────────────────────────

@router.get("/monetization/plans")
def list_plans():
    """List all available subscription plans."""
    from core.monetization.engine import MonetizationEngine
    return MonetizationEngine.list_plans()


@router.get("/monetization/usage/{tenant_id}")
def tenant_usage(
    tenant_id: str,
    db: Session = Depends(get_db),
    _: str = Depends(_require_key),
):
    """Full usage report for a specific tenant."""
    try:
        from core.monetization.engine import get_monetization
        return get_monetization().usage_report(tenant_id, db)
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.get("/monetization/action-costs")
def action_costs():
    """List of all action costs in credits."""
    from core.monetization.engine import ACTION_COSTS
    return {"action_costs": ACTION_COSTS}


# ── Chaos Engine ──────────────────────────────────────────────

@router.get("/chaos/status")
def chaos_status(_: str = Depends(_require_key)):
    """Chaos engine status and experiment log."""
    try:
        from core.chaos.engine import get_chaos_engine
        return get_chaos_engine().status()
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.post("/chaos/enable")
def enable_chaos(
    override_production: bool = Query(False),
    _: str = Depends(_require_key),
):
    """Enable the chaos engine. Requires override for production."""
    try:
        from core.chaos.engine import get_chaos_engine
        success = get_chaos_engine().enable(override_production)
        if not success:
            raise HTTPException(status_code=403, detail="Chaos engine blocked in production. Use override_production=true if intentional.")
        return {"status": "enabled"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.post("/chaos/disable")
def disable_chaos(_: str = Depends(_require_key)):
    """Disable the chaos engine."""
    from core.chaos.engine import get_chaos_engine
    get_chaos_engine().disable()
    return {"status": "disabled"}


@router.post("/chaos/scenario/{scenario}")
def run_chaos_scenario(scenario: str, _: str = Depends(_require_key)):
    """
    Run a named resilience scenario.
    Options: redis_failure, ai_timeout, high_load, full_chaos
    """
    valid = ["redis_failure", "ai_timeout", "high_load", "full_chaos"]
    if scenario not in valid:
        raise HTTPException(status_code=400, detail=f"Unknown scenario. Valid: {valid}")
    try:
        from core.chaos.engine import get_chaos_engine
        engine = get_chaos_engine()
        engine.enable(override_production=True)  # Scenarios always permitted
        result = engine.run_resilience_scenario(scenario)
        engine.disable()
        return result
    except Exception as e:
        logger.error(f"Chaos scenario failed: {e}")
        raise HTTPException(status_code=503, detail=str(e))


# ── Unified Enterprise Dashboard ──────────────────────────────

@router.get("/dashboard")
def enterprise_dashboard(_: str = Depends(_require_key)):
    """Complete enterprise dashboard — all systems in one response."""
    report = {
        "timestamp": __import__("time").time(),
        "system": "CYBERDUDEBIVASH AI v2.0.0",
    }

    # Resilience
    try:
        from core.resilience.orchestrator import get_orchestrator
        orch = get_orchestrator()
        health = orch.health_report()
        report["resilience"] = {
            "system_score": health.get("system_score"),
            "system_health": health.get("system_health"),
            "degradation_level": health.get("degradation_level"),
            "components": {k: v.get("state") for k, v in health.get("components", {}).items()},
        }
    except Exception as e:
        report["resilience"] = {"error": str(e)}

    # Scaling
    try:
        from core.scaling.engine import get_scaler
        scaler = get_scaler()
        s = scaler.status()
        report["scaling"] = {
            "concurrency": s.get("current_concurrency"),
            "queue_depth": s.get("current_metrics", {}).get("total_queue_depth"),
            "load_factor": s.get("current_metrics", {}).get("load_factor"),
            "backpressure": s.get("backpressure", {}).get("overloaded"),
        }
    except Exception as e:
        report["scaling"] = {"error": str(e)}

    # AI Router
    try:
        from core.ai_super_router.router import get_super_router
        ar = get_super_router()
        h = ar.health()
        report["ai_router"] = {
            "primary_available": h.get("primary_available"),
            "cache_hit_rate": h.get("cache", {}).get("hit_rate"),
            "cache_size": h.get("cache", {}).get("size"),
        }
    except Exception as e:
        report["ai_router"] = {"error": str(e)}

    # Threat Memory
    try:
        from core.threat_memory.engine import get_threat_memory
        stats = get_threat_memory().statistics()
        report["threat_memory"] = {
            "total_iocs": stats.get("total_iocs"),
            "active_iocs": stats.get("active_iocs"),
            "total_campaigns": stats.get("total_campaigns"),
            "total_patterns": stats.get("total_patterns"),
        }
    except Exception as e:
        report["threat_memory"] = {"error": str(e)}

    # Alerts
    try:
        from core.observability.metrics import get_observability
        obs = get_observability()
        alert_status = obs.alerts.status()
        report["alerts"] = {
            "active": alert_status.get("active_alerts"),
            "critical": alert_status.get("critical_alerts"),
        }
    except Exception as e:
        report["alerts"] = {"error": str(e)}

    return report
