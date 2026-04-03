# ============================================================
# CYBERDUDEBIVASH AI — DASHBOARD ROUTER (PRODUCTION HARDENED)
# Real-time metrics, safe error handling, datetime serialization
# ============================================================

import time
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timezone

from generated_app.database import get_db
from generated_app.core.redis_client import redis_health
from core.database.db_engine import health_check as db_health
from core.database.models import TaskLog, ThreatLog, UsageLog, Tenant
from core.logging_config import get_logger

logger = get_logger("router.dashboard")
router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

_START_TIME = time.time()


@router.get("/")
def dashboard(db: Session = Depends(get_db)):
    """Complete system dashboard — real-time status."""
    try:
        uptime = int(time.time() - _START_TIME)
        db_ok = db_health()
        redis_ok = redis_health()

        stats = {
            "tenants": 0,
            "tasks_total": 0,
            "threats_analyzed": 0,
            "usage_events": 0,
            "threats_by_severity": {},
        }

        try:
            stats["tenants"] = db.query(Tenant).count()
            stats["tasks_total"] = db.query(TaskLog).count()
            stats["threats_analyzed"] = db.query(ThreatLog).count()
            stats["usage_events"] = db.query(UsageLog).count()
            sev_rows = (
                db.query(ThreatLog.severity, func.count(ThreatLog.id))
                .group_by(ThreatLog.severity)
                .all()
            )
            stats["threats_by_severity"] = {r[0]: r[1] for r in sev_rows}
        except Exception as e:
            logger.warning(f"Dashboard stats partial failure: {e}")

        return {
            "system": "CYBERDUDEBIVASH AI",
            "version": "2.0.0",
            "uptime_seconds": uptime,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "online",
            "components": {
                "api": "online",
                "database": "connected" if db_ok else "error",
                "redis": "connected" if redis_ok else "error",
            },
            "statistics": stats,
        }
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        raise HTTPException(status_code=503, detail="Dashboard temporarily unavailable")


@router.get("/agents")
def agents_dashboard():
    """Agent health and performance metrics."""
    try:
        from core.agents.autonomous_engine import get_engine
        engine = get_engine()
        agents = engine.list_agents()
        return {
            "total": len(agents),
            "agents": agents,
            "router_ready": engine.router.is_ready(),
        }
    except Exception as e:
        logger.error(f"Agent dashboard error: {e}")
        raise HTTPException(status_code=503, detail="Engine temporarily unavailable")


@router.get("/memory")
def memory_dashboard():
    """Memory store status and recent entries."""
    try:
        from core.memory.memory_store import get_memory
        mem = get_memory()
        stats = mem.stats()
        recent = mem.get_all()[-10:]
        return {
            **stats,
            "recent_tasks": [r.get("task", "")[:80] for r in recent],
        }
    except Exception as e:
        logger.error(f"Memory dashboard error: {e}")
        raise HTTPException(status_code=503, detail="Memory stats unavailable")


@router.get("/threats/recent")
def recent_threats_dashboard(db: Session = Depends(get_db)):
    """Last 10 threats detected."""
    try:
        threats = (
            db.query(ThreatLog)
            .order_by(ThreatLog.created_at.desc())
            .limit(10)
            .all()
        )
        return {
            "threats": [
                {
                    "target": t.target,
                    "severity": t.severity,
                    "scan_type": t.scan_type,
                    "created_at": t.created_at.isoformat() if t.created_at else None,
                }
                for t in threats
            ]
        }
    except Exception as e:
        logger.error(f"Recent threats error: {e}")
        return {"threats": []}
