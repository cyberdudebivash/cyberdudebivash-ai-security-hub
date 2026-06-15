"""
CYBERDUDEBIVASH® Multi-Agent Cybersecurity OS
FastAPI Application Entry Point — Production-grade, async, observable.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

# Optional observability — platform runs without these installed
try:
    import structlog
    _structlog_available = True
except ImportError:
    import logging as _logging
    _structlog_available = False

try:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentation
except ImportError:
    FastAPIInstrumentation = None  # type: ignore

from .routes import intel_router, soc_router, executive_router, ai_security_router
from .routes import compliance_router, customer_router, health_router
from .middleware.auth import verify_token
from .middleware.rate_limit import RateLimitMiddleware
from agents.core import (
    AgentRegistry, MasterOrchestrator, QualityGate, PolicyEngine
)
# ── Threat Intelligence ───────────────────────────────────────────────────────
from agents.threat_intel import (
    IOCIntelligenceAgent, CVEIntelligenceAgent,
    MalwareIntelligenceAgent, ThreatActorAgent,
    EnrichmentAgent, CampaignIntelligenceAgent,
    DarkWebMonitoringAgent, OSINTAgent, ZeroDayResearchAgent,
)
# ── SOC ───────────────────────────────────────────────────────────────────────
from agents.soc import (
    SOCTier1Agent, SOCTier2Agent, SOCTier3Agent,
    IncidentResponseAgent, ThreatHuntingAgent,
    DetectionEngineeringAgent, ForensicsAgent,
    PhishingAnalysisAgent, SIEMCorrelationAgent, RansomwareResponseAgent,
)
# ── Executive ─────────────────────────────────────────────────────────────────
from agents.executive import CISOAgent, CEOAgent, CROAgent, CTOAgent
# ── AI Security ───────────────────────────────────────────────────────────────
from agents.ai_security import (
    PromptInjectionAgent, AIGovernanceAgent,
    AIRedTeamAgent, AIRuntimeSecurityAgent, AIRiskAgent,
)
# ── Security Engineering ──────────────────────────────────────────────────────
from agents.security_engineering import (
    ComplianceAgent, SecurityArchitectureAgent, CloudSecurityAgent,
    DevSecOpsAgent, VulnerabilityAgent, PenetrationTestingAgent, RedTeamAgent,
    APISecurityAgent, ContainerSecurityAgent, IdentitySecurityAgent,
    NetworkSecurityAgent, EndpointSecurityAgent, SupplyChainSecurityAgent,
    DataLossPreventionAgent, ThreatModelingAgent, EmailSecurityAgent,
    WebApplicationSecurityAgent, IoTSecurityAgent, BlockchainSecurityAgent,
    PrivilegedAccessAgent, RegulatoryReportingAgent,
)
# ── Revenue ───────────────────────────────────────────────────────────────────
from agents.revenue import SubscriptionAgent, BillingAgent, OnboardingAgent, RenewalAgent
# ── Content / Research ────────────────────────────────────────────────────────
from agents.content import ResearchAgent, BlogAgent, WhitepaperAgent, ContentIntelligenceAgent
from agents.research import ThreatResearchAgent
# ── Customer ──────────────────────────────────────────────────────────────────
from agents.customer import CustomerSuccessAgent, MSSPAgent, VendorRiskAgent, CyberInsuranceAgent
from config.settings import settings
from config.ai_router import AIProviderRouter

if _structlog_available:
    logger = structlog.get_logger(__name__)
else:
    logger = _logging.getLogger(__name__)

# ─── Application state container ─────────────────────────────────────────────
class AppState:
    registry:     AgentRegistry
    orchestrator: MasterOrchestrator
    quality_gate: QualityGate
    policy:       PolicyEngine
    ai_router:    AIProviderRouter
    redis:        Any = None
    pg_pool:      Any = None
    qdrant:       Any = None

app_state = AppState()

# ─── Lifespan (startup + shutdown) ──────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize all services on startup, clean up on shutdown."""
    logger.info("macos.startup", version=settings.VERSION)

    # 1. Connect Redis
    try:
        import redis.asyncio as aioredis
        app_state.redis = aioredis.from_url(
            settings.REDIS_URL, decode_responses=True,
            max_connections=20, socket_connect_timeout=5,
        )
        await app_state.redis.ping()
        logger.info("redis.connected", url=settings.REDIS_URL)
    except Exception as e:
        logger.warning("redis.unavailable", error=str(e))
        app_state.redis = None

    # 2. Connect PostgreSQL
    try:
        import asyncpg
        app_state.pg_pool = await asyncpg.create_pool(
            settings.DATABASE_URL, min_size=2, max_size=20,
            command_timeout=30,
        )
        logger.info("postgres.connected")
    except Exception as e:
        logger.warning("postgres.unavailable", error=str(e))
        app_state.pg_pool = None

    # 3. Connect Qdrant
    try:
        from qdrant_client import AsyncQdrantClient
        app_state.qdrant = AsyncQdrantClient(url=settings.QDRANT_URL)
        logger.info("qdrant.connected", url=settings.QDRANT_URL)
    except Exception as e:
        logger.warning("qdrant.unavailable", error=str(e))
        app_state.qdrant = None

    # 4. Initialize AI provider router (provider-agnostic — no Anthropic hardcode)
    app_state.ai_router = AIProviderRouter(
        groq_api_key=settings.GROQ_API_KEY,
        deepseek_api_key=settings.DEEPSEEK_API_KEY,
        openrouter_api_key=settings.OPENROUTER_API_KEY,
        anthropic_api_key=settings.ANTHROPIC_API_KEY,  # optional
        cloudflare_account=settings.CF_ACCOUNT_ID,
        cloudflare_token=settings.CF_API_TOKEN,
    )
    await app_state.ai_router.initialize()
    logger.info("ai_router.initialized", active_providers=app_state.ai_router.active_provider_count)

    # 5. Build agent infrastructure
    app_state.quality_gate = QualityGate()
    app_state.policy       = PolicyEngine(redis_client=app_state.redis, pg_pool=app_state.pg_pool)

    # 6. Instantiate and register all agents
    shared_deps = dict(
        redis_client=app_state.redis,
        pg_pool=app_state.pg_pool,
        qdrant_client=app_state.qdrant,
        ai_router=app_state.ai_router,
    )
    app_state.registry = AgentRegistry(redis_client=app_state.redis)
    app_state.registry.register_all([
        # ── Threat Intelligence (9 agents) ────────────────────────────────
        IOCIntelligenceAgent(**shared_deps),
        CVEIntelligenceAgent(**shared_deps),
        MalwareIntelligenceAgent(**shared_deps),
        ThreatActorAgent(**shared_deps),
        EnrichmentAgent(**shared_deps),
        CampaignIntelligenceAgent(**shared_deps),
        DarkWebMonitoringAgent(**shared_deps),
        OSINTAgent(**shared_deps),
        ZeroDayResearchAgent(**shared_deps),
        # ── SOC (10 agents) ───────────────────────────────────────────────
        SOCTier1Agent(**shared_deps),
        SOCTier2Agent(**shared_deps),
        SOCTier3Agent(**shared_deps),
        IncidentResponseAgent(**shared_deps),
        ThreatHuntingAgent(**shared_deps),
        DetectionEngineeringAgent(**shared_deps),
        ForensicsAgent(**shared_deps),
        PhishingAnalysisAgent(**shared_deps),
        SIEMCorrelationAgent(**shared_deps),
        RansomwareResponseAgent(**shared_deps),
        # ── Executive (4 agents) ──────────────────────────────────────────
        CISOAgent(**shared_deps),
        CEOAgent(**shared_deps),
        CROAgent(**shared_deps),
        CTOAgent(**shared_deps),
        # ── AI Security (5 agents) ────────────────────────────────────────
        PromptInjectionAgent(**shared_deps),
        AIGovernanceAgent(**shared_deps),
        AIRedTeamAgent(**shared_deps),
        AIRuntimeSecurityAgent(**shared_deps),
        AIRiskAgent(**shared_deps),
        # ── Security Engineering (21 agents) ─────────────────────────────
        ComplianceAgent(**shared_deps),
        SecurityArchitectureAgent(**shared_deps),
        CloudSecurityAgent(**shared_deps),
        DevSecOpsAgent(**shared_deps),
        VulnerabilityAgent(**shared_deps),
        PenetrationTestingAgent(**shared_deps),
        RedTeamAgent(**shared_deps),
        APISecurityAgent(**shared_deps),
        ContainerSecurityAgent(**shared_deps),
        IdentitySecurityAgent(**shared_deps),
        NetworkSecurityAgent(**shared_deps),
        EndpointSecurityAgent(**shared_deps),
        SupplyChainSecurityAgent(**shared_deps),
        DataLossPreventionAgent(**shared_deps),
        ThreatModelingAgent(**shared_deps),
        EmailSecurityAgent(**shared_deps),
        WebApplicationSecurityAgent(**shared_deps),
        IoTSecurityAgent(**shared_deps),
        BlockchainSecurityAgent(**shared_deps),
        PrivilegedAccessAgent(**shared_deps),
        RegulatoryReportingAgent(**shared_deps),
        # ── Revenue (4 agents) ────────────────────────────────────────────
        SubscriptionAgent(**shared_deps),
        BillingAgent(**shared_deps),
        OnboardingAgent(**shared_deps),
        RenewalAgent(**shared_deps),
        # ── Content / Research (5 agents) ────────────────────────────────
        ResearchAgent(**shared_deps),
        BlogAgent(**shared_deps),
        WhitepaperAgent(**shared_deps),
        ContentIntelligenceAgent(**shared_deps),
        ThreatResearchAgent(**shared_deps),
        # ── Customer (4 agents) ───────────────────────────────────────────
        CustomerSuccessAgent(**shared_deps),
        MSSPAgent(**shared_deps),
        VendorRiskAgent(**shared_deps),
        CyberInsuranceAgent(**shared_deps),
    ])

    # 7. Build orchestrator
    app_state.orchestrator = MasterOrchestrator(
        agent_registry=app_state.registry,
        quality_gate=app_state.quality_gate,
        policy_engine=app_state.policy,
        redis_client=app_state.redis,
        pg_pool=app_state.pg_pool,
    )

    # 8. Start background health monitor
    await app_state.registry.start_health_monitor(interval_sec=30)

    logger.info(
        "macos.ready",
        version=settings.VERSION,
        agents=app_state.registry.count(),
        intents=len(app_state.orchestrator.get_diagnostics().get("supported_intents", [])),
    )

    yield  # ← app is now serving requests

    # Shutdown
    logger.info("macos.shutdown")
    if app_state.redis:
        await app_state.redis.aclose()
    if app_state.pg_pool:
        await app_state.pg_pool.close()


# ─── FastAPI App ─────────────────────────────────────────────────────────────
app = FastAPI(
    title="CYBERDUDEBIVASH® Multi-Agent Cybersecurity OS",
    version=settings.VERSION,
    lifespan=lifespan,
)

# Middleware
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


# ─── Routers ─────────────────────────────────────────────────────────────────
app.include_router(health_router)
app.include_router(intel_router,      prefix="/api/intel",      tags=["Threat Intel"])
app.include_router(soc_router,        prefix="/api/soc",        tags=["SOC"])
app.include_router(executive_router,  prefix="/api/executive",  tags=["Executive"])
app.include_router(ai_security_router,prefix="/api/ai-security",tags=["AI Security"])
app.include_router(compliance_router, prefix="/api/compliance", tags=["Compliance"])
app.include_router(customer_router,   prefix="/api/customer",   tags=["Customer"])


# ─── Core orchestration endpoint ─────────────────────────────────────────────
@app.post("/api/orchestrate", dependencies=[Depends(verify_token)])
async def orchestrate(request: Request):
    """
    Universal entry point — every request routes through MasterOrchestrator.
    Body: {intent, payload, context, org_id, user_id, tier}
    """
    body = await request.json()
    agent_request = AgentRequest(
        request_id=str(uuid.uuid4()),
        intent=body.get("intent", ""),
        payload=body.get("payload", {}),
        context=body.get("context", {}),
        org_id=body.get("org_id", "default"),
        user_id=body.get("user_id", ""),
        tier=body.get("tier", "FREE"),
    )
    result = await app_state.orchestrator.orchestrate(agent_request)
    return JSONResponse(content=result.model_dump())


@app.get("/api/agents", dependencies=[Depends(verify_token)])
async def list_agents():
    """List all registered agents and their capabilities."""
    return {"agents": app_state.registry.list_all()}


@app.get("/api/intents")
async def list_intents():
    """List all supported orchestration intents."""
    return app_state.orchestrator.get_diagnostics()


# ─── Entry point ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=False)
# NOTE: stale, undecorated duplicate of the orchestrate handler left by an
# incomplete merge. It is unreachable (no route decorator) but must remain
# syntactically valid; the canonical route is defined above at @app.post(
# "/api/orchestrate"). See Technical Debt report: orchestrate() signature
# mismatch between this module and MasterOrchestrator.orchestrate().
async def orchestrate(
    request: Request,
    body:    Dict[str, Any],
    auth:    Dict = Depends(verify_token),
):
    """
    Master orchestration endpoint.
    Routes any intent to the appropriate agent pipeline and returns quality-gated results.
    """
    intent  = body.get("intent")
    if not intent:
        raise HTTPException(status_code=400, detail="'intent' field is required")

    result = await request.app.state.orchestrator.orchestrate(
        session_id=body.get("session_id", str(uuid.uuid4())),
        user_id=auth["user_id"],
        tenant_id=auth["tenant_id"],
        intent=intent,
        payload=body.get("payload", {}),
        context=body.get("context", {}),
        tier=auth.get("tier", "FREE"),
        priority=body.get("priority", 5),
    )

    return JSONResponse(
        content=result.model_dump(),
        headers={"X-Quality-Score": str(result.quality_report.get("overall_score", 0))},
    )

# ─── Register all route modules ──────────────────────────────────────────────
app.include_router(health_router,      prefix="/v1/health",      tags=["Health"])
app.include_router(intel_router,       prefix="/v1/intel",       tags=["Threat Intelligence"])
app.include_router(soc_router,         prefix="/v1/soc",         tags=["SOC"])
app.include_router(executive_router,   prefix="/v1/executive",   tags=["Executive"])
app.include_router(ai_security_router, prefix="/v1/ai-security", tags=["AI Security"])
app.include_router(compliance_router,  prefix="/v1/compliance",  tags=["Compliance"])
app.include_router(customer_router,    prefix="/v1/customer",    tags=["Customer"])

if __name__ == "__main__":
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=8000,
        workers=1,
        loop="asyncio",
        log_level="info",
    )
