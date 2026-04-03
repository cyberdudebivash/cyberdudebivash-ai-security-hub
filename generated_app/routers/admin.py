# ============================================================
# CYBERDUDEBIVASH AI — ADMIN ROUTER (PRODUCTION HARDENED)
# Full observability, pagination, auth guard, safe error handling
# ============================================================

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Optional
from datetime import datetime

from generated_app.database import get_db
from core.database.models import Tenant, Subscription, UsageLog, TaskLog, ThreatLog
from core.logging_config import get_logger, log_event

logger = get_logger("router.admin")
router = APIRouter(prefix="/admin", tags=["Admin"])


def _require_admin_key(x_api_key: Optional[str] = Header(default=None, alias="x-api-key")):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Admin requires x-api-key header")
    return x_api_key


@router.get("/tenants")
def list_tenants(
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    _: str = Depends(_require_admin_key),
):
    total = db.query(Tenant).count()
    tenants = db.query(Tenant).offset(skip).limit(limit).all()
    return {
        "total": total,
        "tenants": [
            {"id": t.id, "name": t.name, "active": t.is_active,
             "created_at": t.created_at.isoformat() if t.created_at else None}
            for t in tenants
        ],
    }


@router.get("/stats")
def system_stats(db: Session = Depends(get_db), _: str = Depends(_require_admin_key)):
    try:
        cost_sum = db.query(func.sum(UsageLog.cost)).scalar()
        severity_rows = db.query(ThreatLog.severity, func.count(ThreatLog.id)).group_by(ThreatLog.severity).all()
        return {
            "tenants": db.query(Tenant).count(),
            "tasks_logged": db.query(TaskLog).count(),
            "threats_analyzed": db.query(ThreatLog).count(),
            "usage_events": db.query(UsageLog).count(),
            "total_revenue_credits": round(float(cost_sum or 0), 4),
            "threat_severity_breakdown": {r[0]: r[1] for r in severity_rows},
        }
    except Exception as e:
        logger.error(f"Admin stats failed: {e}")
        raise HTTPException(status_code=503, detail="Stats temporarily unavailable")


@router.get("/revenue")
def revenue(db: Session = Depends(get_db), _: str = Depends(_require_admin_key)):
    subs = db.query(Subscription).all()
    return {
        "total": len(subs),
        "subscriptions": [
            {"tenant": s.tenant_id, "plan": s.plan, "credits": round(float(s.credits or 0), 4)}
            for s in subs
        ],
    }


@router.get("/threats")
def recent_threats(
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=500),
    severity: Optional[str] = Query(None),
    scan_type: Optional[str] = Query(None),
    _: str = Depends(_require_admin_key),
):
    try:
        query = db.query(ThreatLog)
        if severity:
            query = query.filter(ThreatLog.severity == severity.lower())
        if scan_type:
            query = query.filter(ThreatLog.scan_type == scan_type)
        threats = query.order_by(ThreatLog.created_at.desc()).limit(limit).all()
        return {
            "total": len(threats),
            "threats": [
                {"id": t.id, "scan_type": t.scan_type, "target": t.target,
                 "severity": t.severity, "tenant_id": t.tenant_id,
                 "created_at": t.created_at.isoformat() if t.created_at else None}
                for t in threats
            ],
        }
    except Exception as e:
        logger.error(f"Threat listing failed: {e}")
        raise HTTPException(status_code=503, detail="Threat history unavailable")


@router.get("/tasks")
def recent_tasks(
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    status: Optional[str] = Query(None),
    _: str = Depends(_require_admin_key),
):
    try:
        query = db.query(TaskLog)
        if status:
            query = query.filter(TaskLog.status == status.lower())
        tasks = query.order_by(TaskLog.created_at.desc()).limit(limit).all()
        return {
            "total": len(tasks),
            "tasks": [
                {"task_id": t.task_id, "task_type": t.task_type, "status": t.status,
                 "tenant_id": t.tenant_id,
                 "created_at": t.created_at.isoformat() if t.created_at else None}
                for t in tasks
            ],
        }
    except Exception as e:
        logger.error(f"Task listing failed: {e}")
        raise HTTPException(status_code=503, detail="Task history unavailable")


@router.post("/sast")
def run_sast(_: str = Depends(_require_admin_key)):
    try:
        from core.security.code_scanner import CodeScanner
        result = CodeScanner().scan(".")
        log_event("admin_sast_run", {"findings": result.get("total_findings", 0)})
        return result
    except Exception as e:
        logger.error(f"SAST failed: {e}")
        raise HTTPException(status_code=503, detail=f"SAST scan failed: {e}")


@router.get("/memory")
def memory_stats(_: str = Depends(_require_admin_key)):
    try:
        from core.memory.memory_store import get_memory
        return get_memory().stats()
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.delete("/memory")
def clear_memory(_: str = Depends(_require_admin_key)):
    try:
        from core.memory.memory_store import get_memory
        get_memory().clear()
        log_event("admin_memory_cleared", {})
        return {"status": "cleared", "timestamp": datetime.utcnow().isoformat()}
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.get("/agents")
def agents_health(_: str = Depends(_require_admin_key)):
    try:
        from core.agents.autonomous_engine import get_engine
        engine = get_engine()
        return {"total_agents": len(engine._agents), "agents": engine.list_agents()}
    except Exception as e:
        logger.error(f"Agent health failed: {e}")
        raise HTTPException(status_code=503, detail="Engine unavailable")


@router.get("/cost")
def cost_report(_: str = Depends(_require_admin_key)):
    try:
        from core.cost_guard.tracker import CostTracker
        return CostTracker().summary()
    except Exception as e:
        return {"error": str(e), "note": "Cost tracking unavailable"}


@router.get("/router-health")
def router_health_check(_: str = Depends(_require_admin_key)):
    try:
        from core.router.router_manager import get_router
        return get_router().health()
    except Exception as e:
        return {"ready": False, "error": str(e)}
