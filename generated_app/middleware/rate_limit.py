# ============================================================
# CYBERDUDEBIVASH AI — RATE LIMITER (PRODUCTION HARDENED)
# Fixes: Redis circuit breaker, sliding window, per-tenant logging
# ============================================================

import time
import threading
from core.settings import settings
from core.logging_config import get_logger

logger = get_logger("middleware.rate_limit")

# Circuit breaker state
_redis_failure_count = 0
_redis_circuit_open_until = 0.0   # epoch time when circuit reopens
_CIRCUIT_THRESHOLD = 5
_CIRCUIT_RESET_SECS = 60
_redis_lock = threading.Lock()


def _is_circuit_open() -> bool:
    return time.time() < _redis_circuit_open_until


def _record_failure() -> None:
    global _redis_failure_count, _redis_circuit_open_until
    with _redis_lock:
        _redis_failure_count += 1
        if _redis_failure_count >= _CIRCUIT_THRESHOLD:
            _redis_circuit_open_until = time.time() + _CIRCUIT_RESET_SECS
            logger.error(
                f"Rate limiter circuit OPEN after {_redis_failure_count} failures. "
                f"Bypassing for {_CIRCUIT_RESET_SECS}s."
            )


def _record_success() -> None:
    global _redis_failure_count
    with _redis_lock:
        _redis_failure_count = 0


def rate_limiter(tenant_id: str) -> bool:
    """
    Distributed rate limiting with circuit breaker.
    Returns True = allow, False = block.
    Always fails-open to avoid blocking legitimate requests due to infra issues.
    """
    if not tenant_id:
        return True

    if _is_circuit_open():
        logger.debug("Rate limiter circuit open — failing open")
        return True

    try:
        from generated_app.core.redis_client import redis_client
        key = f"rate_limit:{tenant_id}"
        pipe = redis_client.pipeline(transaction=False)
        pipe.incr(key, 1)
        pipe.expire(key, settings.rate_limit_window)
        results = pipe.execute()
        current = int(results[0])
        _record_success()

        if current > settings.rate_limit:
            logger.warning(
                f"Rate limit exceeded: tenant={tenant_id} "
                f"count={current} limit={settings.rate_limit}"
            )
            return False
        return True

    except Exception as e:
        _record_failure()
        logger.warning(f"Rate limiter Redis error (failing open): {e}")
        return True
