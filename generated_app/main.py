# ============================================================
# CYBERDUDEBIVASH AI SYSTEM — MAIN ENTRYPOINT (ENTERPRISE)
# Full enterprise systems: resilience, scaling, observability,
# AI super router, threat memory, monetization, chaos engine
# ============================================================

import time
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from starlette.middleware.base import BaseHTTPMiddleware

# ── Bootstrap logging FIRST ──────────────────────────────────
from core.logging_config import setup_logging, get_logger
setup_logging(level=os.getenv("LOG_LEVEL", "INFO"))
logger = get_logger("main")

from core.settings import settings
from core.database.db_engine import init_db, health_check as db_health
from generated_app.core.redis_client import redis_health

APP_NAME = settings.app_name
APP_VERSION = settings.app_version
START_TIME = time.time()

# ── Routers ───────────────────────────────────────────────────
from generated_app.routers import auth, cyber, task, generate, user, admin, billing, dashboard
from generated_app.routers import enterprise
from generated_app.routers import toolgen


# ============================================================
# OBSERVABILITY MIDDLEWARE
# ============================================================
class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.time()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        except Exception as exc:
            raise
        finally:
            duration_s = time.time() - start
            duration_ms = int(duration_s * 1000)
            try:
                from core.observability.metrics import get_observability
                get_observability().metrics.record_http_request(
                    method=request.method,
                    endpoint=request.url.path,
                    status_code=status_code,
                    duration_s=duration_s,
                )
            except Exception:
                pass
            logger.info(
                f"HTTP {request.method} {request.url.path} "
                f"→ {status_code} ({duration_ms}ms)"
            )


class BackpressureMiddleware(BaseHTTPMiddleware):
    """Reject requests when system is overloaded under sustained load."""
    _EXEMPT_PATHS = {"/health", "/metrics", "/system/status", "/enterprise/resilience/status"}

    async def dispatch(self, request: Request, call_next):
        if request.url.path not in self._EXEMPT_PATHS:
            try:
                from core.scaling.engine import get_scaler
                scaler = get_scaler()
                if scaler.backpressure.should_shed_load():
                    return JSONResponse(
                        status_code=503,
                        content={
                            "error": "Service overloaded",
                            "message": "System under high load. Please retry in 30 seconds.",
                            "retry_after": 30,
                        },
                        headers={"Retry-After": "30"},
                    )
            except Exception:
                pass  # Never block due to scaler error
        return await call_next(request)


# ============================================================
# LIFESPAN — Enterprise Startup Sequence
# ============================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 70)
    logger.info(f"  CYBERDUDEBIVASH AI SYSTEM v{APP_VERSION}")
    logger.info(f"  Environment: {settings.app_env}")
    logger.info("=" * 70)

    # 1. Database
    try:
        init_db()
        logger.info("✅ Database initialized")
    except Exception as e:
        logger.error(f"❌ Database init FAILED: {e}")

    # 2. Resilience Orchestrator
    try:
        from core.resilience.orchestrator import get_orchestrator
        orch = get_orchestrator()
        orch.initialize()
        logger.info("✅ Resilience Orchestrator started")
    except Exception as e:
        logger.error(f"❌ Resilience Orchestrator FAILED: {e}")

    # 3. Observability
    try:
        from core.observability.metrics import get_observability
        get_observability().start(interval=30.0)
        logger.info("✅ Observability Stack started")
    except Exception as e:
        logger.error(f"❌ Observability FAILED: {e}")

    # 4. Auto-Scaling Engine
    try:
        from core.scaling.engine import get_scaler
        get_scaler().start(interval_seconds=30.0)
        logger.info("✅ Auto-Scaling Engine started")
    except Exception as e:
        logger.error(f"❌ Auto-Scaling FAILED: {e}")

    # 5. AI Super Router
    try:
        from core.ai_super_router.router import get_super_router
        router = get_super_router()
        logger.info(f"✅ AI Super Router ready (primary: {router._primary_router is not None})")
    except Exception as e:
        logger.error(f"❌ AI Super Router FAILED: {e}")

    # 6. Threat Memory Engine
    try:
        from core.threat_memory.engine import get_threat_memory
        tm = get_threat_memory()
        stats = tm.statistics()
        logger.info(f"✅ Threat Memory Engine ready ({stats['total_iocs']} IOCs loaded)")
    except Exception as e:
        logger.error(f"❌ Threat Memory FAILED: {e}")

    # 7. Autonomous Engine pre-warm
    try:
        from core.agents.autonomous_engine import get_engine
        engine = get_engine()
        logger.info(f"✅ AutonomousEngine ready ({len(engine._agents)} agents)")
    except Exception as e:
        logger.error(f"❌ AutonomousEngine FAILED: {e}")

    # 8. Cyber Tool Generation Engine
    try:
        from core.cyber_tool_engine.engine import get_cyber_tool_engine
        te = get_cyber_tool_engine()
        h = te.health()
        ready = sum(1 for v in h.values() if v is True)
        logger.info(f"✅ Cyber Tool Engine ready ({ready}/7 components)")
    except Exception as e:
        logger.error(f"❌ Cyber Tool Engine FAILED: {e}")

    logger.info("🚀 CYBERDUDEBIVASH AI is ONLINE")
    yield

    # ── SHUTDOWN ──────────────────────────────────────────────
    logger.info("🛑 Shutting down enterprise systems...")
    try:
        from core.scaling.engine import get_scaler
        get_scaler().stop()
    except Exception:
        pass
    try:
        from core.observability.metrics import get_observability
        get_observability().stop()
    except Exception:
        pass
    try:
        from core.resilience.orchestrator import get_orchestrator
        get_orchestrator().registry.stop()
    except Exception:
        pass
    logger.info("✅ Shutdown complete")


# ============================================================
# FASTAPI APP
# ============================================================
app = FastAPI(
    title=APP_NAME,
    description=(
        "🔐 CYBERDUDEBIVASH AI — Enterprise Autonomous Cybersecurity Platform\n\n"
        "**Core Systems:** Threat Intel • Vulnerability • Malware • OSINT • Audit • Swarm\n\n"
        "**Enterprise:** Resilience Orchestrator • Auto-Scaling • AI Super Router • "
        "Threat Memory • Observability • Chaos Engine • Monetization"
    ),
    version=APP_VERSION,
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)

# ── Middleware Stack (order matters) ──────────────────────────
app.add_middleware(BackpressureMiddleware)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "x-api-key", "x-tenant-id"],
)

# ── Routers ───────────────────────────────────────────────────
app.include_router(auth.router)
app.include_router(cyber.router)
app.include_router(task.router)
app.include_router(generate.router)
app.include_router(user.router)
app.include_router(admin.router)
app.include_router(billing.router)
app.include_router(dashboard.router)
app.include_router(enterprise.router)
app.include_router(toolgen.router)
logger.info("All routers registered (including enterprise)")


# ============================================================
# CORE ENDPOINTS
# ============================================================
@app.get("/", tags=["System"])
async def root():
    return {
        "system": APP_NAME,
        "version": APP_VERSION,
        "status": "RUNNING",
        "enterprise": True,
        "docs": "/docs",
        "health": "/health",
        "dashboard": "/dashboard",
        "enterprise_dashboard": "/enterprise/dashboard",
    }


@app.get("/health", tags=["System"])
async def health():
    db_ok = db_health()
    redis_ok = redis_health()

    # Get orchestrator health if available
    system_score = 100
    degradation = "FULL"
    try:
        from core.resilience.orchestrator import get_orchestrator
        orch = get_orchestrator()
        system_score = orch.registry.get_system_score()
        degradation = orch.get_degradation_level()
    except Exception:
        pass

    overall = "healthy" if db_ok else "degraded"
    return JSONResponse(
        status_code=200 if overall == "healthy" else 503,
        content={
            "status": overall,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": APP_VERSION,
            "system_score": system_score,
            "degradation_level": degradation,
            "components": {
                "api": "online",
                "database": "connected" if db_ok else "error",
                "redis": "connected" if redis_ok else "error",
            },
        }
    )


@app.get("/metrics", tags=["System"])
async def metrics():
    try:
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
    except Exception:
        return Response("# Prometheus metrics unavailable\n", media_type="text/plain")


@app.get("/system/status", tags=["System"])
async def system_status():
    uptime = time.time() - START_TIME

    # Celery workers
    worker_status = "unknown"
    try:
        from generated_app.core.celery_app import celery_app
        inspect = celery_app.control.inspect(timeout=1.5)
        workers = inspect.ping()
        worker_status = "running" if workers else "no_workers_detected"
    except Exception:
        worker_status = "unreachable"

    # Engine
    engine_status = "error"
    try:
        from core.agents.autonomous_engine import get_engine
        engine = get_engine()
        engine_status = f"{len(engine._agents)}_agents_ready"
    except Exception:
        pass

    # Resilience
    resilience_data = {}
    try:
        from core.resilience.orchestrator import get_orchestrator
        orch = get_orchestrator()
        resilience_data = {
            "system_score": orch.registry.get_system_score(),
            "degradation_level": orch.get_degradation_level(),
        }
    except Exception:
        pass

    # Scaling
    scaling_data = {}
    try:
        from core.scaling.engine import get_scaler
        s = get_scaler().status()
        scaling_data = {
            "concurrency": s.get("current_concurrency"),
            "queue_depth": s.get("current_metrics", {}).get("total_queue_depth", 0),
            "overloaded": s.get("backpressure", {}).get("overloaded", False),
        }
    except Exception:
        pass

    return {
        "system": APP_NAME,
        "version": APP_VERSION,
        "status": "ACTIVE",
        "uptime_seconds": round(uptime, 1),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": {
            "api": "ONLINE",
            "database": "CONNECTED" if db_health() else "DOWN",
            "redis": "CONNECTED" if redis_health() else "DOWN",
            "celery_workers": worker_status.upper(),
            "autonomous_engine": engine_status,
        },
        "enterprise": {
            "resilience": resilience_data,
            "scaling": scaling_data,
        },
    }


@app.get("/docs", include_in_schema=False)
async def custom_docs():
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title=f"{APP_NAME} — Control Panel",
        swagger_ui_parameters={"defaultModelsExpandDepth": -1},
    )


@app.get("/openapi.json", include_in_schema=False)
async def openapi():
    return get_openapi(title=APP_NAME, version=APP_VERSION, routes=app.routes)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled: {type(exc).__name__}: {exc} — {request.method} {request.url.path}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal Server Error", "type": type(exc).__name__, "path": str(request.url.path)},
    )


@app.exception_handler(404)
async def not_found(request: Request, exc):
    return JSONResponse(status_code=404, content={"error": "Not Found", "path": str(request.url.path)})


@app.exception_handler(405)
async def method_not_allowed(request: Request, exc):
    return JSONResponse(status_code=405, content={"error": "Method Not Allowed"})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("generated_app.main:app", host="0.0.0.0", port=8000, reload=False)
