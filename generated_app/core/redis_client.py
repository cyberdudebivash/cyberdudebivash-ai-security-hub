# ============================================================
# CYBERDUDEBIVASH AI — REDIS CLIENT (HARDENED)
# Fixes: connection pool with retry, health check with timeout,
#        graceful failure when Redis is unavailable at startup
# ============================================================

import os
import logging
from typing import Optional

logger = logging.getLogger("cdb_ai.redis")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


def _build_redis_client():
    """Build Redis client with connection pool and retry config."""
    try:
        import redis
        client = redis.Redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
            health_check_interval=30,
            max_connections=20,
        )
        return client
    except Exception as e:
        logger.error(f"Redis client creation failed: {e}")
        return None


redis_client = _build_redis_client()


def redis_health() -> bool:
    """Non-throwing Redis health check with timeout."""
    if redis_client is None:
        return False
    try:
        return redis_client.ping()
    except Exception as e:
        logger.debug(f"Redis health check failed: {e}")
        return False


def get_redis():
    """Return Redis client or None if unavailable."""
    return redis_client
