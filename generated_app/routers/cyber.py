# ============================================================
# CYBERDUDEBIVASH AI — CYBERSECURITY ROUTER (HARDENED)
# Full input validation, structured error handling, DB logging,
# async-safe sync calls wrapped in thread executor
# ============================================================

import asyncio
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session
from typing import Any, Dict

from generated_app.database import get_db, ThreatLog
from generated_app.models import (
    ThreatIntelRequest, VulnScanRequest, MalwareRequest,
    OSINTRequest, SecurityAuditRequest, SwarmRequest,
)
from generated_app.middleware.tenant import resolve_tenant
from generated_app.middleware.rate_limit import rate_limiter
from generated_app.tasks.cyber_tasks import (
    run_threat_intel, run_vulnerability_scan, run_malware_analysis,
    run_osint, run_security_audit, run_swarm,
)
from core.logging_config import get_logger, log_event

logger = get_logger("router.cyber")
router = APIRouter(prefix="/cyber", tags=["Cybersecurity"])

# Shared thread pool for sync agent calls inside async endpoints
_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="cyber_sync")


async def _run_in_thread(fn, *args, **kwargs):
    """Run a blocking function in a thread pool — keeps event loop free."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_executor, lambda: fn(*args, **kwargs))


def _log_threat(db: Session, scan_type: str, target: str, result: Dict, tenant_id: str) -> None:
    """Persist threat finding to database. Non-throwing."""
    try:
        output = result.get("output", result)
        severity = str(output.get("threat_level", output.get("severity", "info"))).lower()
        threat = ThreatLog(
            scan_type=scan_type,
            target=str(target)[:500],
            severity=severity,
            findings=output,
            tenant_id=tenant_id,
        )
        db.add(threat)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.warning(f"ThreatLog persistence failed (non-critical): {e}")


# ── Threat Intelligence ───────────────────────────────────────
@router.post("/threat-intel")
async def threat_intel(
    req: ThreatIntelRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Async: queue threat intelligence analysis task."""
    tenant_id = await resolve_tenant(request, db)
    if not rate_limiter(tenant_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    log_event("threat_intel_queued", {"tenant": tenant_id, "target": req.target[:100]})
    task = run_threat_intel.delay(req.target, req.type, tenant_id)
    return {"task_id": task.id, "status": "queued", "target": req.target, "poll": f"/tasks/{task.id}"}


@router.post("/threat-intel/sync")
async def threat_intel_sync(
    req: ThreatIntelRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Sync: run threat intel immediately and return result."""
    tenant_id = await resolve_tenant(request, db)
    if not rate_limiter(tenant_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    from core.agents.cyber_agents import ThreatIntelAgent
    agent = ThreatIntelAgent()
    result = await _run_in_thread(
        agent.execute,
        {"target": req.target, "type": req.type, "context": req.context}
    )
    _log_threat(db, "threat_intel", req.target, result, tenant_id)
    log_event("threat_intel_sync_complete", {"tenant": tenant_id, "target": req.target[:100]})
    return result


# ── Vulnerability Analysis ────────────────────────────────────
@router.post("/vulnerability")
async def vulnerability_scan(
    req: VulnScanRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Async: queue vulnerability analysis."""
    tenant_id = await resolve_tenant(request, db)
    if not rate_limiter(tenant_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    if not req.cve_id and not req.software:
        raise HTTPException(status_code=400, detail="Provide cve_id or software name")
    task = run_vulnerability_scan.delay(req.cve_id, req.software, req.version)
    return {"task_id": task.id, "status": "queued", "poll": f"/tasks/{task.id}"}


@router.post("/vulnerability/sync")
async def vulnerability_sync(
    req: VulnScanRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Sync: run vulnerability analysis immediately."""
    tenant_id = await resolve_tenant(request, db)
    if not rate_limiter(tenant_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    if not req.cve_id and not req.software:
        raise HTTPException(status_code=400, detail="Provide cve_id or software name")

    from core.agents.cyber_agents import VulnerabilityAgent
    agent = VulnerabilityAgent()
    result = await _run_in_thread(
        agent.execute,
        {"cve_id": req.cve_id, "software": req.software, "version": req.version, "description": req.description}
    )
    _log_threat(db, "vulnerability", req.cve_id or req.software or "unknown", result, tenant_id)
    return result


# ── Malware Analysis ──────────────────────────────────────────
@router.post("/malware")
async def malware_analysis(
    req: MalwareRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Async: queue malware sample analysis."""
    tenant_id = await resolve_tenant(request, db)
    if not rate_limiter(tenant_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    task = run_malware_analysis.delay(req.sample, req.sample_type, req.behavior)
    return {"task_id": task.id, "status": "queued", "poll": f"/tasks/{task.id}"}


@router.post("/malware/sync")
async def malware_sync(
    req: MalwareRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Sync: run malware analysis immediately."""
    tenant_id = await resolve_tenant(request, db)
    if not rate_limiter(tenant_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    from core.agents.cyber_agents import MalwareAnalysisAgent
    agent = MalwareAnalysisAgent()
    result = await _run_in_thread(
        agent.execute,
        {"sample": req.sample, "sample_type": req.sample_type, "behavior": req.behavior}
    )
    _log_threat(db, "malware", req.sample, result, tenant_id)
    return result


# ── OSINT ─────────────────────────────────────────────────────
@router.post("/osint")
async def osint(
    req: OSINTRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Async: queue OSINT intelligence gathering."""
    tenant_id = await resolve_tenant(request, db)
    if not rate_limiter(tenant_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    task = run_osint.delay(req.target, req.target_type)
    return {"task_id": task.id, "status": "queued", "poll": f"/tasks/{task.id}"}


@router.post("/osint/sync")
async def osint_sync(
    req: OSINTRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Sync: run OSINT immediately."""
    tenant_id = await resolve_tenant(request, db)
    if not rate_limiter(tenant_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    from core.agents.cyber_agents import OSINTAgent
    agent = OSINTAgent()
    result = await _run_in_thread(
        agent.execute,
        {"target": req.target, "target_type": req.target_type}
    )
    _log_threat(db, "osint", req.target, result, tenant_id)
    return result


# ── Security Audit ────────────────────────────────────────────
@router.post("/audit")
async def security_audit(
    req: SecurityAuditRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Async: queue code security audit."""
    tenant_id = await resolve_tenant(request, db)
    if not rate_limiter(tenant_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    task = run_security_audit.delay(req.code, req.language, req.audit_type)
    return {"task_id": task.id, "status": "queued", "poll": f"/tasks/{task.id}"}


@router.post("/audit/sync")
async def audit_sync(
    req: SecurityAuditRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Sync: run security audit immediately."""
    tenant_id = await resolve_tenant(request, db)
    if not rate_limiter(tenant_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    from core.agents.cyber_agents import SecurityAuditAgent
    agent = SecurityAuditAgent()
    result = await _run_in_thread(
        agent.execute,
        {"code": req.code, "language": req.language, "audit_type": req.audit_type}
    )
    return result


# ── SAST (project-level) ──────────────────────────────────────
@router.post("/sast")
async def sast_scan(
    request: Request,
    db: Session = Depends(get_db),
):
    """Run SAST on the entire project codebase."""
    tenant_id = await resolve_tenant(request, db)
    if not rate_limiter(tenant_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    from core.security.code_scanner import CodeScanner
    scanner = CodeScanner()
    result = await _run_in_thread(scanner.scan, ".")
    log_event("sast_scan_complete", {"tenant": tenant_id, "findings": result.get("total_findings", 0)})
    return result


# ── Swarm ─────────────────────────────────────────────────────
@router.post("/swarm")
async def swarm(
    req: SwarmRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Async: run multi-agent swarm task."""
    tenant_id = await resolve_tenant(request, db)
    if not rate_limiter(tenant_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    task_data = {"task": req.task, "target": req.target, "tenant_id": tenant_id}
    task = run_swarm.delay(task_data)
    return {"task_id": task.id, "status": "queued", "poll": f"/tasks/{task.id}"}


@router.post("/swarm/sync")
async def swarm_sync(
    req: SwarmRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Sync: run multi-agent swarm immediately."""
    tenant_id = await resolve_tenant(request, db)
    if not rate_limiter(tenant_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    from core.agents.autonomous_engine import get_engine
    engine = get_engine()
    result = await _run_in_thread(
        engine.execute,
        req.task,
        tenant_id,
        None,
        {"target": req.target}
    )
    return result


# ── Agents Info ───────────────────────────────────────────────
@router.get("/agents")
async def list_agents():
    """List all registered agents with health metrics."""
    try:
        from core.agents.autonomous_engine import get_engine
        engine = get_engine()
        return {"agents": engine.list_agents(), "total": len(engine._agents)}
    except Exception as e:
        logger.error(f"Agent list failed: {e}")
        raise HTTPException(status_code=503, detail="Engine unavailable")


# ── Threat History ────────────────────────────────────────────
@router.get("/history")
async def threat_history(
    request: Request,
    limit: int = 20,
    severity: str = None,
    db: Session = Depends(get_db),
):
    """Get recent threat intelligence history for the current tenant."""
    tenant_id = await resolve_tenant(request, db)

    limit = max(1, min(limit, 100))
    query = db.query(ThreatLog).filter(ThreatLog.tenant_id == tenant_id)
    if severity:
        query = query.filter(ThreatLog.severity == severity.lower())

    threats = query.order_by(ThreatLog.created_at.desc()).limit(limit).all()
    return {
        "tenant_id": tenant_id,
        "total": len(threats),
        "threats": [
            {
                "id": t.id,
                "scan_type": t.scan_type,
                "target": t.target,
                "severity": t.severity,
                "created_at": t.created_at.isoformat() if t.created_at else None,
            }
            for t in threats
        ],
    }
