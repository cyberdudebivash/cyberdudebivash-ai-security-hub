"""Sliding-window rate limiting middleware backed by Redis."""
from __future__ import annotations
import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

RATE_LIMIT_PATHS = ["/v1/intel", "/v1/soc", "/v1/executive", "/v1/ai-security"]
BURST_LIMIT      = 20  # requests per 10s burst

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        redis = getattr(request.app.state, "redis", None)
        if not redis:
            return await call_next(request)

        path = str(request.url.path)
        if not any(path.startswith(p) for p in RATE_LIMIT_PATHS):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        key       = f"burst:{client_ip}"
        now       = time.time()
        window    = 10.0

        try:
            pipe = redis.pipeline()
            pipe.zremrangebyscore(key, 0, now - window)
            pipe.zcard(key)
            pipe.zadd(key, {str(now): now})
            pipe.expire(key, 30)
            results = await pipe.execute()
            count   = results[1]
            if count >= BURST_LIMIT:
                return JSONResponse(
                    status_code=429,
                    content={"error": "Rate limit exceeded", "retry_after": 10},
                    headers={"Retry-After": "10", "X-RateLimit-Limit": str(BURST_LIMIT)},
                )
        except Exception: pass

        return await call_next(request)
