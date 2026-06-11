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

import structlog
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentation

from .routes import intel_router, soc_router, executive_router, ai_security_router
from .routes import compliance_router, customer_router, health_router
from .middleware.auth import verify_token
from .middleware.rate_limit import RateLimitMiddleware
from ..agents.core import (
    AgentRegistry, MasterOrchestrator, QualityGate, PolicyEngine
)
from ..agents.threat_intel import (
    IOCIntelligenceAgent, CVEIntelligenceAgent,
    MalwareIntelligenceAgent, ThreatActorAgent,
)
from ..agents.soc import SOCTier1Agent, IncidentResponseAgent, ThreatHuntingAgent
from ..agents.executive import CISOAgent, CEOAgent
from ..agents.ai_security import PromptInjectionAgent, AIGovernanceAgent
from ..agents.security_engineering import ComplianceAgent
from ..agents.customer import CustomerSuccessAgent
from ..agents.research import ThreatResearchAgent
from ..config.settings import settings
from ..config.ai_router import AIProviderRouter

logger = structlog.get_logger(__name__)

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
        # Threat Intel layer
        IOCIntelligenceAgent(**shared_deps),
        CVEIntelligenceAgent(**shared_deps),
        MalwareIntelligenceAgent(**shared_deps),
        ThreatActorAgent(**shared_deps),
        # SOC layer
        SOCTier1Agent(**shared_deps),
        IncidentResponseAgent(**shared_deps),
        ThreatHuntingAgent(**shared_deps),
        # Executive layer
        CISOAgent(**shared_deps),
        CEOAgent(**shared_deps),
        # AI Security layer
        PromptInjectionAgent(**shared_deps),
        AIGovernanceAgent(**shared_deps),
        # Security Engineering
        ComplianceAgent(**shared_deps),
        # Customer
        CustomerSuccessAgent(**shared_deps),
        # Research
        ThreatResearchAgent(**shared_deps),
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
        agents=len(app_state.registry),
        ai_providers=app_state.ai_router.active_provider_count,
    )

    # Attach state to app
    app.state.registry     = app_state.registry
    app.state.orchestrator = app_state.orchestrator
    app.state.quality_gate = app_state.quality_gate
    app.state.policy       = app_state.policy
    app.state.ai_router    = app_state.ai_router

    yield  # ← Application runs here

    # Shutdown
    logger.info("macos.shutdown")
    if app_state.pg_pool:
        await app_state.pg_pool.close()
    if app_state.redis:
        await app_state.redis.aclose()

# ─── FastAPI application ───────────────────────────────────────────────────────
app = FastAPI(
    title="CYBERDUDEBIVASH® Multi-Agent Cybersecurity OS",
    description="Production-grade AI cybersecurity platform with 50+ specialist agents",
    version=settings.VERSION,
    docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
    openapi_url="/openapi.json" if settings.ENVIRONMENT != "production" else None,
    lifespan=lifespan,
)

# ─── Middleware stack ─────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(RateLimitMiddleware)

# ─── OpenTelemetry instrumentation ───────────────────────────────────────────
FastAPIInstrumentation().instrument_app(app)

# ─── Request ID + timing middleware ──────────────────────────────────────────
@app.middleware("http")
async def request_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id
    request.state.start_time = time.monotonic()

    structlog.contextvars.bind_contextvars(request_id=request_id)

    response = await call_next(request)
    elapsed  = (time.monotonic() - request.state.start_time) * 1000

    response.headers["X-Request-ID"]    = request_id
    response.headers["X-Response-Time"] = f"{elapsed:.2f}ms"
    response.headers["X-Platform"]      = "CYBERDUDEBIVASH-MACOS"
    return response

# ─── Global exception handler ─────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("unhandled_exception", path=str(request.url), error=str(exc))
    return JSONResponse(
        status_code=500,
        content={
            "error":      "Internal server error",
            "request_id": getattr(request.state, "request_id", "unknown"),
            "platform":   "CYBERDUDEBIVASH MACOS",
        }
    )

# ─── Core orchestration endpoint ─────────────────────────────────────────────
@app.post("/v1/orchestrate", tags=["Orchestration"])
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
        workers=settings.WORKERS,
        loop="uvloop",
        http="httptools",
        log_level="info",
    )
