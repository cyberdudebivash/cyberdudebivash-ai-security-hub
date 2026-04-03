# ============================================================
# CYBERDUDEBIVASH AI — CYBER TOOL ENGINE API ROUTER
# Endpoints: generate tools, list catalog, download artifacts,
# manage jobs, view improvement metrics
# ============================================================

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from sqlalchemy.orm import Session
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from generated_app.database import get_db
from generated_app.middleware.tenant import resolve_tenant
from generated_app.middleware.rate_limit import rate_limiter
from core.logging_config import get_logger, log_event

logger = get_logger("router.cyber_tool_engine")
router = APIRouter(prefix="/toolgen", tags=["Cyber Tool Generation Engine"])


def _require_key(x_api_key: Optional[str] = Header(default=None, alias="x-api-key")):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="x-api-key required")
    return x_api_key


# ── Request Models ────────────────────────────────────────────
class GenerateFromIntelRequest(BaseModel):
    intel: Any = Field(..., description="Raw threat intel: dict, JSON string, or free text")
    source_type: str = Field(default="analysis", description="Source: analysis/feed/manual/cve")
    generate_tools: bool = True
    generate_rules: bool = True
    generate_playbooks: bool = True
    tool_types: Optional[List[str]] = None
    rule_types: Optional[List[str]] = None
    async_mode: bool = Field(default=False, description="Return immediately with job_id")


class GenerateFromTargetRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=500, description="IP, domain, CVE, malware name")
    target_type: Optional[str] = None
    context: Optional[str] = Field(default=None, max_length=2000)
    severity: str = Field(default="HIGH", pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$")
    async_mode: bool = False


# ── Endpoints ─────────────────────────────────────────────────

@router.get("/health")
def engine_health(_: str = Depends(_require_key)):
    """Cyber Tool Engine health and capability report."""
    try:
        from core.cyber_tool_engine.engine import get_cyber_tool_engine
        return get_cyber_tool_engine().health()
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.post("/generate")
async def generate_from_intel(
    req: GenerateFromIntelRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Full pipeline: ingest threat intelligence → generate all cybersecurity artifacts.

    Accepts any threat intel format:
    - Threat analysis result dict (from /cyber/threat-intel/sync)
    - Free text description
    - CVE data
    - Malware campaign report

    Returns generated YARA rules, Sigma rules, Snort/Suricata rules,
    Python scanners, IR playbooks, and SOC workflows.
    """
    tenant_id = await resolve_tenant(request, db)
    if not rate_limiter(tenant_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    try:
        from core.cyber_tool_engine.engine import get_cyber_tool_engine
        engine = get_cyber_tool_engine()

        if req.async_mode:
            job_id = engine.generate_async(
                raw_input=req.intel,
                source_type=req.source_type,
                generate_tools=req.generate_tools,
                generate_rules=req.generate_rules,
                generate_playbooks=req.generate_playbooks,
                tool_types=req.tool_types,
                rule_types=req.rule_types,
            )
            log_event("toolgen_async_started", {"tenant": tenant_id, "job_id": job_id})
            return {"job_id": job_id, "status": "pending", "poll": f"/toolgen/jobs/{job_id}"}

        # Synchronous generation
        job = engine.generate_from_intel(
            raw_input=req.intel,
            source_type=req.source_type,
            generate_tools=req.generate_tools,
            generate_rules=req.generate_rules,
            generate_playbooks=req.generate_playbooks,
            tool_types=req.tool_types,
            rule_types=req.rule_types,
        )

        log_event("toolgen_complete", {
            "tenant": tenant_id,
            "job_id": job.id,
            "tools_count": len(job.generated_tools),
            "rules_count": len(job.generated_rules),
            "playbooks_count": len(job.generated_playbooks),
            "stored": len(job.stored_tool_ids),
        })

        return _job_response(job)

    except Exception as e:
        logger.error(f"Tool generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Generation failed: {e}")


@router.post("/generate/target")
async def generate_from_target(
    req: GenerateFromTargetRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Generate tools from a raw target indicator (IP, domain, CVE, malware name).
    Automatically runs threat intelligence and then generates all artifacts.
    """
    tenant_id = await resolve_tenant(request, db)
    if not rate_limiter(tenant_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    # Build synthetic intel dict
    raw_intel = {
        "target": req.target,
        "indicator_type": req.target_type or "unknown",
        "threat_level": req.severity,
        "is_malicious": True,
        "summary": req.context or f"Threat intelligence for {req.target}",
        "recommendations": ["Investigate and block", "Monitor for related indicators"],
        "indicators_of_compromise": [req.target],
    }

    try:
        from core.cyber_tool_engine.engine import get_cyber_tool_engine
        engine = get_cyber_tool_engine()

        if req.async_mode:
            job_id = engine.generate_async(raw_intel, source_type="direct_target")
            return {"job_id": job_id, "status": "pending", "poll": f"/toolgen/jobs/{job_id}"}

        job = engine.generate_from_intel(raw_intel, source_type="direct_target")
        log_event("toolgen_from_target", {"tenant": tenant_id, "target": req.target})
        return _job_response(job)

    except Exception as e:
        logger.error(f"Target-based generation failed: {e}")
        raise HTTPException(status_code=503, detail=str(e))


@router.post("/generate/cve/{cve_id}")
async def generate_from_cve(
    cve_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Generate vulnerability-specific tools and detection rules from a CVE ID."""
    if not cve_id.upper().startswith("CVE-"):
        raise HTTPException(status_code=400, detail="Invalid CVE format (expected CVE-YYYY-XXXXX)")

    tenant_id = await resolve_tenant(request, db)

    raw_intel = {
        "cve_id": cve_id.upper(),
        "threat_level": "HIGH",
        "is_malicious": True,
        "threat_categories": ["exploit", "vulnerability"],
        "indicators_of_compromise": [cve_id.upper()],
        "summary": f"Vulnerability exploitation detection for {cve_id}",
        "attack_techniques": ["T1190"],  # Exploit Public-Facing Application
    }

    try:
        from core.cyber_tool_engine.engine import get_cyber_tool_engine
        job = get_cyber_tool_engine().generate_from_intel(
            raw_intel, source_type="cve",
            generate_tools=True, generate_rules=True, generate_playbooks=True,
        )
        return _job_response(job)
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


# ── Job Management ────────────────────────────────────────────

@router.get("/jobs/{job_id}")
def get_job(job_id: str, _: str = Depends(_require_key)):
    """Poll status of an async generation job."""
    try:
        from core.cyber_tool_engine.engine import get_cyber_tool_engine
        job = get_cyber_tool_engine().get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
        return _job_response(job)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.get("/jobs")
def list_jobs(
    limit: int = Query(20, ge=1, le=100),
    _: str = Depends(_require_key),
):
    """List recent generation jobs."""
    try:
        from core.cyber_tool_engine.engine import get_cyber_tool_engine
        return {"jobs": get_cyber_tool_engine().list_jobs(limit)}
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


# ── Tool Catalog ──────────────────────────────────────────────

@router.get("/catalog")
def tool_catalog(
    tool_type: Optional[str] = Query(None),
    tier: Optional[str] = Query(None),
    query: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    _: str = Depends(_require_key),
):
    """Browse the generated tool catalog with optional filters."""
    try:
        from core.cyber_tool_engine.engine import get_cyber_tool_engine
        tools = get_cyber_tool_engine().catalog(
            tool_type=tool_type, tier=tier, query=query, limit=limit
        )
        return {"total": len(tools), "tools": tools}
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.get("/catalog/stats")
def catalog_stats(_: str = Depends(_require_key)):
    """Tool catalog statistics: counts by type, tier, quality scores."""
    try:
        from core.cyber_tool_engine.engine import get_cyber_tool_engine
        return get_cyber_tool_engine().catalog_stats()
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.get("/catalog/{tool_id}")
def get_tool(tool_id: str, _: str = Depends(_require_key)):
    """Get metadata for a specific tool."""
    try:
        from core.cyber_tool_engine.storage.tool_storage import get_storage
        tool = get_storage().get(tool_id)
        if not tool:
            raise HTTPException(status_code=404, detail="Tool not found")
        return tool.to_dict()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.get("/catalog/{tool_id}/download")
def download_tool(
    tool_id: str,
    tenant_id: Optional[str] = Header(default=None, alias="x-tenant-id"),
    _: str = Depends(_require_key),
):
    """Download the content of a generated tool."""
    try:
        from core.cyber_tool_engine.storage.tool_storage import get_storage
        storage = get_storage()
        tool = storage.get(tool_id)
        if not tool:
            raise HTTPException(status_code=404, detail="Tool not found")

        content = storage.get_content(tool_id)
        if not content:
            raise HTTPException(status_code=404, detail="Tool content not found")

        log_event("tool_download", {
            "tool_id": tool_id, "tool_type": tool.tool_type,
            "tenant": tenant_id or "anonymous", "tier": tool.monetization_tier,
        })

        from fastapi.responses import PlainTextResponse
        ext_map = {
            "yara": "application/x-yara",
            "sigma": "text/yaml",
            "snort": "text/plain",
            "suricata": "text/plain",
            "ir_playbook": "text/markdown",
            "soc_workflow": "text/markdown",
        }
        media_type = ext_map.get(tool.tool_type, "text/plain")
        return PlainTextResponse(content=content, media_type=media_type)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


# ── Improvement Report ────────────────────────────────────────

@router.get("/improvement")
def improvement_report(_: str = Depends(_require_key)):
    """Continuous improvement engine report — best tool types per threat category."""
    try:
        from core.cyber_tool_engine.storage.tool_storage import get_improvement_engine
        return {
            "improvement_report": get_improvement_engine().improvement_report(),
            "note": "Shows average quality score per tool type per threat category",
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


# ── Helper ────────────────────────────────────────────────────

def _job_response(job) -> Dict:
    """Format a GenerationJob for API response."""
    response = job.to_dict()

    # Include actual generated content in response (truncated for large responses)
    artifacts = {}
    for name, content in job.generated_tools.items():
        artifacts[f"tool_{name}"] = content[:5000] + ("\n# [TRUNCATED]" if len(content) > 5000 else "")
    for name, content in job.generated_rules.items():
        artifacts[f"rule_{name}"] = content[:5000] + ("\n# [TRUNCATED]" if len(content) > 5000 else "")
    for name, content in job.generated_playbooks.items():
        artifacts[f"playbook_{name}"] = content[:3000] + ("\n[TRUNCATED]" if len(content) > 3000 else "")

    response["artifacts"] = artifacts
    response["artifact_count"] = len(artifacts)

    if job.classification:
        response["classification"] = job.classification.to_dict()

    return response
