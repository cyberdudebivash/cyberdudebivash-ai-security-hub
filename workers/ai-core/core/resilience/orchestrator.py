# ============================================================
# CYBERDUDEBIVASH AI — GLOBAL RESILIENCE ORCHESTRATOR
# Central nervous system: monitors all components, assigns
# health scores, coordinates failover, routes traffic intelligently
# ============================================================

import time
import threading
import statistics
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from core.logging_config import get_logger

logger = get_logger("resilience.orchestrator")


# ── Health States ─────────────────────────────────────────────
class HealthState(str, Enum):
    HEALTHY   = "healthy"
    DEGRADED  = "degraded"
    CRITICAL  = "critical"
    DOWN      = "down"


@dataclass
class ComponentHealth:
    name: str
    state: HealthState = HealthState.HEALTHY
    score: float = 100.0          # 0–100
    latency_ms: float = 0.0
    error_rate: float = 0.0       # 0–1
    last_check: float = field(default_factory=time.time)
    consecutive_failures: int = 0
    total_checks: int = 0
    total_failures: int = 0
    message: str = ""

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "state": self.state.value,
            "score": round(self.score, 1),
            "latency_ms": round(self.latency_ms, 1),
            "error_rate": round(self.error_rate, 4),
            "consecutive_failures": self.consecutive_failures,
            "uptime_pct": round(
                ((self.total_checks - self.total_failures) / max(self.total_checks, 1)) * 100, 2
            ),
            "last_check_ago_s": round(time.time() - self.last_check, 1),
            "message": self.message,
        }


# ── Circuit Breaker ───────────────────────────────────────────
class CircuitBreaker:
    """
    Three-state circuit breaker: CLOSED → OPEN → HALF-OPEN → CLOSED
    Prevents cascading failures by stopping calls to failing services.
    """
    CLOSED    = "closed"
    OPEN      = "open"
    HALF_OPEN = "half_open"

    def __init__(self, name: str, threshold: int = 5,
                 reset_timeout: float = 60.0, half_open_calls: int = 2):
        self.name = name
        self.threshold = threshold
        self.reset_timeout = reset_timeout
        self.half_open_calls = half_open_calls
        self._state = self.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time = 0.0
        self._lock = threading.Lock()

    @property
    def state(self) -> str:
        with self._lock:
            if self._state == self.OPEN:
                if time.time() - self._last_failure_time >= self.reset_timeout:
                    self._state = self.HALF_OPEN
                    self._success_count = 0
                    logger.info(f"[CB:{self.name}] OPEN → HALF-OPEN")
            return self._state

    def is_allowed(self) -> bool:
        s = self.state
        if s == self.CLOSED:
            return True
        if s == self.HALF_OPEN:
            with self._lock:
                return self._success_count < self.half_open_calls
        return False  # OPEN

    def record_success(self) -> None:
        with self._lock:
            if self._state == self.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.half_open_calls:
                    self._state = self.CLOSED
                    self._failure_count = 0
                    logger.info(f"[CB:{self.name}] HALF-OPEN → CLOSED (recovered)")
            elif self._state == self.CLOSED:
                self._failure_count = max(0, self._failure_count - 1)

    def record_failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()
            if self._failure_count >= self.threshold:
                if self._state != self.OPEN:
                    logger.error(f"[CB:{self.name}] CLOSED → OPEN (failures={self._failure_count})")
                self._state = self.OPEN
                self._failure_count = 0

    def call(self, fn: Callable, *args, fallback=None, **kwargs):
        """Execute function through circuit breaker with fallback."""
        if not self.is_allowed():
            logger.warning(f"[CB:{self.name}] Circuit OPEN — returning fallback")
            return fallback() if callable(fallback) else fallback
        try:
            result = fn(*args, **kwargs)
            self.record_success()
            return result
        except Exception as e:
            self.record_failure()
            logger.error(f"[CB:{self.name}] Call failed: {e}")
            if fallback is not None:
                return fallback() if callable(fallback) else fallback
            raise

    def status(self) -> Dict:
        return {
            "name": self.name,
            "state": self.state,
            "failure_count": self._failure_count,
            "last_failure_ago_s": round(time.time() - self._last_failure_time, 1) if self._last_failure_time else None,
        }


# ── Health Check Registry ─────────────────────────────────────
class HealthCheckRegistry:
    """
    Registry of all component health checks.
    Runs checks on a background thread and maintains rolling health scores.
    """

    def __init__(self, check_interval: float = 15.0):
        self.check_interval = check_interval
        self._components: Dict[str, ComponentHealth] = {}
        self._checkers: Dict[str, Callable] = {}
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._lock = threading.RLock()
        self._thread: Optional[threading.Thread] = None
        self._running = False
        # Latency windows for rolling average
        self._latency_windows: Dict[str, List[float]] = {}

    def register(self, name: str, checker: Callable,
                 cb_threshold: int = 5, cb_reset: float = 60.0) -> None:
        """Register a component with its health check function."""
        with self._lock:
            self._components[name] = ComponentHealth(name=name)
            self._checkers[name] = checker
            self._circuit_breakers[name] = CircuitBreaker(name, cb_threshold, cb_reset)
            self._latency_windows[name] = []
        logger.info(f"[Registry] Registered component: {name}")

    def start(self) -> None:
        """Start background health checking."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="HealthCheckThread")
        self._thread.start()
        logger.info("[Registry] Health check background thread started")

    def stop(self) -> None:
        self._running = False

    def _run_loop(self) -> None:
        while self._running:
            self._check_all()
            time.sleep(self.check_interval)

    def _check_all(self) -> None:
        with self._lock:
            names = list(self._checkers.keys())
        for name in names:
            self._check_one(name)

    def _check_one(self, name: str) -> None:
        checker = self._checkers.get(name)
        cb = self._circuit_breakers.get(name)
        if not checker or not cb:
            return

        start = time.time()
        success = False
        message = ""
        try:
            result = checker()
            success = bool(result)
            message = str(result) if isinstance(result, str) else ("ok" if success else "check returned False")
        except Exception as e:
            message = str(e)[:200]

        latency_ms = (time.time() - start) * 1000

        with self._lock:
            comp = self._components[name]
            comp.total_checks += 1
            comp.last_check = time.time()
            comp.latency_ms = latency_ms

            # Rolling latency window (last 20 checks)
            window = self._latency_windows[name]
            window.append(latency_ms)
            if len(window) > 20:
                window.pop(0)

            if success:
                cb.record_success()
                comp.consecutive_failures = 0
                comp.message = message
            else:
                cb.record_failure()
                comp.total_failures += 1
                comp.consecutive_failures += 1
                comp.message = f"FAILED: {message}"

            # Compute health score
            comp.score = self._compute_score(comp, window)
            comp.error_rate = comp.total_failures / max(comp.total_checks, 1)
            comp.state = self._state_from_score(comp.score, comp.consecutive_failures)

    def _compute_score(self, comp: ComponentHealth, latency_window: List[float]) -> float:
        """
        Score = 100
          - 30 pts for consecutive failures
          - 40 pts for error rate
          - 30 pts for latency
        """
        score = 100.0

        # Consecutive failures penalty
        fail_penalty = min(comp.consecutive_failures * 10, 30)
        score -= fail_penalty

        # Error rate penalty
        rate_penalty = comp.error_rate * 40
        score -= rate_penalty

        # Latency penalty (based on rolling avg)
        if latency_window:
            avg_lat = statistics.mean(latency_window)
            if avg_lat > 5000:   score -= 30
            elif avg_lat > 2000: score -= 15
            elif avg_lat > 1000: score -= 5

        return max(0.0, score)

    def _state_from_score(self, score: float, consecutive_failures: int) -> HealthState:
        if consecutive_failures >= 5 or score < 20:
            return HealthState.DOWN
        if consecutive_failures >= 3 or score < 50:
            return HealthState.CRITICAL
        if score < 80:
            return HealthState.DEGRADED
        return HealthState.HEALTHY

    def get_health(self, name: str) -> Optional[ComponentHealth]:
        with self._lock:
            return self._components.get(name)

    def get_all_health(self) -> Dict[str, ComponentHealth]:
        with self._lock:
            return dict(self._components)

    def get_system_score(self) -> float:
        """Weighted average of all component scores."""
        with self._lock:
            if not self._components:
                return 100.0
            scores = [c.score for c in self._components.values()]
            return round(statistics.mean(scores), 1)

    def get_circuit_breaker(self, name: str) -> Optional[CircuitBreaker]:
        return self._circuit_breakers.get(name)

    def is_healthy(self, name: str) -> bool:
        comp = self.get_health(name)
        return comp is not None and comp.state in (HealthState.HEALTHY, HealthState.DEGRADED)

    def status_report(self) -> Dict:
        all_health = self.get_all_health()
        cbs = {n: cb.status() for n, cb in self._circuit_breakers.items()}
        system_score = self.get_system_score()

        overall = HealthState.HEALTHY
        for comp in all_health.values():
            if comp.state == HealthState.DOWN:
                overall = HealthState.DOWN
                break
            if comp.state == HealthState.CRITICAL:
                overall = HealthState.CRITICAL
            elif comp.state == HealthState.DEGRADED and overall == HealthState.HEALTHY:
                overall = HealthState.DEGRADED

        return {
            "system_health": overall.value,
            "system_score": system_score,
            "components": {n: c.to_dict() for n, c in all_health.items()},
            "circuit_breakers": cbs,
            "timestamp": time.time(),
        }


# ── Resilience Orchestrator ───────────────────────────────────
class ResilienceOrchestrator:
    """
    Central orchestrator that:
    1. Monitors all components via HealthCheckRegistry
    2. Makes intelligent routing decisions
    3. Enforces degradation strategies
    4. Coordinates failover
    """

    def __init__(self):
        self.registry = HealthCheckRegistry(check_interval=15.0)
        self._degradation_mode = False
        self._lock = threading.Lock()
        self._routing_table: Dict[str, str] = {}  # service → strategy
        logger.info("[Orchestrator] Initialized")

    def initialize(self) -> None:
        """Register all system components and start monitoring."""
        self._register_all_components()
        self.registry.start()
        logger.info("[Orchestrator] All components registered and monitoring started")

    def _register_all_components(self) -> None:
        # API (self-check)
        self.registry.register("api", self._check_api, cb_threshold=10, cb_reset=30.0)

        # Database
        self.registry.register("database", self._check_database, cb_threshold=5, cb_reset=60.0)

        # Redis
        self.registry.register("redis", self._check_redis, cb_threshold=5, cb_reset=30.0)

        # Celery workers
        self.registry.register("celery_workers", self._check_celery, cb_threshold=3, cb_reset=120.0)

        # AI Engine
        self.registry.register("ai_engine", self._check_ai_engine, cb_threshold=3, cb_reset=60.0)

    # ── Checkers ─────────────────────────────────────────────
    @staticmethod
    def _check_api() -> bool:
        return True  # If we're running, API is up

    @staticmethod
    def _check_database() -> bool:
        try:
            from core.database.db_engine import health_check
            return health_check()
        except Exception:
            return False

    @staticmethod
    def _check_redis() -> bool:
        try:
            from generated_app.core.redis_client import redis_health
            return redis_health()
        except Exception:
            return False

    @staticmethod
    def _check_celery() -> bool:
        try:
            from generated_app.core.celery_app import celery_app
            inspect = celery_app.control.inspect(timeout=2.0)
            result = inspect.ping()
            return bool(result)
        except Exception:
            return False

    @staticmethod
    def _check_ai_engine() -> bool:
        try:
            from core.router.router_manager import get_router
            router = get_router()
            return router.is_ready()
        except Exception:
            return False

    # ── Routing Decisions ─────────────────────────────────────
    def should_use_async(self) -> bool:
        """Should we route to Celery or process inline?"""
        return self.registry.is_healthy("celery_workers") and self.registry.is_healthy("redis")

    def should_use_ai(self) -> bool:
        """Is AI engine available?"""
        return self.registry.is_healthy("ai_engine")

    def should_accept_requests(self) -> bool:
        """Is the system healthy enough to accept requests?"""
        db = self.registry.get_health("database")
        api = self.registry.get_health("api")
        return (db is None or db.state != HealthState.DOWN) and \
               (api is None or api.state != HealthState.DOWN)

    def get_degradation_level(self) -> str:
        """
        Returns degradation level:
          FULL     — all systems healthy
          PARTIAL  — some systems degraded, core still works
          MINIMAL  — only critical paths available
          OFFLINE  — system cannot serve requests
        """
        score = self.registry.get_system_score()
        db_ok = self.registry.is_healthy("database")
        api_ok = self.registry.is_healthy("api")

        if not api_ok or not db_ok:
            return "OFFLINE"
        if score >= 80:
            return "FULL"
        if score >= 50:
            return "PARTIAL"
        return "MINIMAL"

    def execute_with_resilience(
        self,
        component: str,
        fn: Callable,
        fallback: Any = None,
        *args,
        **kwargs,
    ) -> Any:
        """Execute a function through the circuit breaker for that component."""
        cb = self.registry.get_circuit_breaker(component)
        if cb:
            return cb.call(fn, *args, fallback=fallback, **kwargs)
        # No circuit breaker registered — call directly
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            logger.error(f"[Orchestrator] {component} call failed: {e}")
            return fallback() if callable(fallback) else fallback

    def health_report(self) -> Dict:
        report = self.registry.status_report()
        report["degradation_level"] = self.get_degradation_level()
        report["routing"] = {
            "use_async": self.should_use_async(),
            "use_ai": self.should_use_ai(),
            "accept_requests": self.should_accept_requests(),
        }
        return report


# ── Singleton ─────────────────────────────────────────────────
_orchestrator: Optional[ResilienceOrchestrator] = None
_orch_lock = threading.Lock()


def get_orchestrator() -> ResilienceOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        with _orch_lock:
            if _orchestrator is None:
                _orchestrator = ResilienceOrchestrator()
    return _orchestrator
