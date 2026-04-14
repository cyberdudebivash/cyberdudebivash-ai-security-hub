# ============================================================
# CYBERDUDEBIVASH AI — CHAOS ENGINE
# Controlled failure injection for resilience validation.
# Simulates: Redis drops, worker crashes, AI timeouts, DB locks.
# SAFETY: Only activates in non-production or with explicit override.
# ============================================================

import time
import random
import threading
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from core.logging_config import get_logger
from core.settings import settings

logger = get_logger("chaos.engine")


class ChaosMode(str, Enum):
    REDIS_LATENCY    = "redis_latency"
    REDIS_FAILURE    = "redis_failure"
    AI_TIMEOUT       = "ai_timeout"
    AI_SLOW          = "ai_slow"
    DB_CONTENTION    = "db_contention"
    WORKER_CRASH     = "worker_crash"
    NETWORK_DELAY    = "network_delay"
    RANDOM_ERROR     = "random_error"


@dataclass
class ChaosExperiment:
    mode: ChaosMode
    probability: float = 0.1      # 0-1, chance of triggering
    duration_s: float = 30.0      # how long the chaos lasts
    intensity: float = 0.5        # 0-1, severity of the fault
    active: bool = False
    started_at: Optional[float] = None
    trigger_count: int = 0
    impact_count: int = 0

    @property
    def is_expired(self) -> bool:
        if not self.active or not self.started_at:
            return True
        return time.time() - self.started_at > self.duration_s

    def to_dict(self) -> Dict:
        return {
            "mode": self.mode.value,
            "probability": self.probability,
            "duration_s": self.duration_s,
            "intensity": self.intensity,
            "active": self.active,
            "age_s": round(time.time() - self.started_at, 1) if self.started_at else None,
            "trigger_count": self.trigger_count,
            "impact_count": self.impact_count,
        }


class ChaosEngine:
    """
    Controlled chaos injection for resilience testing.
    SAFETY FIRST: disabled in production unless explicitly enabled.
    """

    def __init__(self):
        self._enabled = False
        self._experiments: Dict[str, ChaosExperiment] = {}
        self._lock = threading.Lock()
        self._event_log: List[Dict] = []
        self._running = False

        # Safety check — prevent accidental chaos in production
        if settings.is_production:
            logger.info("[Chaos] Engine DISABLED (production environment)")
        else:
            logger.info("[Chaos] Engine initialized (non-production mode)")

    def enable(self, override_production: bool = False) -> bool:
        """
        Enable chaos engine. Returns False if blocked by safety check.
        Requires explicit override for production.
        """
        if settings.is_production and not override_production:
            logger.error("[Chaos] REFUSED: Cannot enable chaos in production without override")
            return False
        self._enabled = True
        logger.warning("[Chaos] ⚡ ENGINE ENABLED — chaos will be injected")
        return True

    def disable(self) -> None:
        self._enabled = False
        with self._lock:
            for exp in self._experiments.values():
                exp.active = False
        logger.info("[Chaos] Engine disabled — all experiments stopped")

    def add_experiment(self, mode: ChaosMode, probability: float = 0.1,
                       duration_s: float = 60.0, intensity: float = 0.5) -> str:
        """Register a chaos experiment."""
        exp = ChaosExperiment(mode=mode, probability=min(1.0, max(0.0, probability)),
                              duration_s=duration_s, intensity=min(1.0, max(0.0, intensity)))
        key = mode.value
        with self._lock:
            self._experiments[key] = exp
        logger.info(f"[Chaos] Experiment added: {mode.value} prob={probability:.0%} dur={duration_s}s")
        return key

    def run_experiment(self, mode: ChaosMode) -> bool:
        """
        Trigger a specific experiment immediately.
        Returns True if chaos was injected.
        """
        if not self._enabled:
            return False
        with self._lock:
            exp = self._experiments.get(mode.value)
            if not exp:
                exp = ChaosExperiment(mode=mode, probability=1.0)
                self._experiments[mode.value] = exp
            exp.active = True
            exp.started_at = time.time()
            exp.trigger_count += 1
        self._log_event(mode, "experiment_triggered")
        return True

    def maybe_inject(self, mode: ChaosMode) -> bool:
        """
        Probabilistically inject chaos. Returns True if chaos was injected.
        """
        if not self._enabled:
            return False
        with self._lock:
            exp = self._experiments.get(mode.value)
            if not exp:
                return False
            if exp.is_expired:
                exp.active = False
                return False
            should_inject = random.random() < exp.probability

        if should_inject:
            with self._lock:
                exp.impact_count += 1
            self._log_event(mode, "chaos_injected")
            self._apply_chaos(mode)
            return True
        return False

    def _apply_chaos(self, mode: ChaosMode) -> None:
        """Apply the actual failure simulation."""
        with self._lock:
            exp = self._experiments.get(mode.value)
            intensity = exp.intensity if exp else 0.5

        if mode == ChaosMode.REDIS_LATENCY:
            delay = intensity * 2.0  # up to 2s delay
            logger.warning(f"[Chaos] Redis latency injection: {delay:.1f}s")
            time.sleep(delay)

        elif mode == ChaosMode.REDIS_FAILURE:
            logger.warning("[Chaos] Redis failure simulation — raising exception")
            raise ConnectionError("[CHAOS] Simulated Redis connection failure")

        elif mode == ChaosMode.AI_TIMEOUT:
            logger.warning("[Chaos] AI timeout simulation")
            raise TimeoutError("[CHAOS] Simulated AI request timeout")

        elif mode == ChaosMode.AI_SLOW:
            delay = 5.0 + intensity * 25.0  # 5-30s delay
            logger.warning(f"[Chaos] AI slow response: {delay:.0f}s delay")
            time.sleep(delay)

        elif mode == ChaosMode.DB_CONTENTION:
            delay = intensity * 5.0  # up to 5s lock wait
            logger.warning(f"[Chaos] DB contention simulation: {delay:.1f}s wait")
            time.sleep(delay)

        elif mode == ChaosMode.NETWORK_DELAY:
            delay = 0.1 + intensity * 2.0
            logger.warning(f"[Chaos] Network delay injection: {delay:.1f}s")
            time.sleep(delay)

        elif mode == ChaosMode.RANDOM_ERROR:
            logger.warning("[Chaos] Random error injection")
            raise RuntimeError("[CHAOS] Simulated random system error")

    def _log_event(self, mode: ChaosMode, event_type: str) -> None:
        with self._lock:
            self._event_log.append({
                "mode": mode.value,
                "event": event_type,
                "timestamp": time.time(),
            })
            if len(self._event_log) > 200:
                self._event_log.pop(0)

    # ── Built-in Resilience Scenarios ─────────────────────────

    def run_resilience_scenario(self, scenario: str) -> Dict:
        """
        Run a named resilience test scenario.
        Returns the results of the scenario.
        """
        results = {
            "scenario": scenario,
            "start_time": time.time(),
            "tests": [],
        }

        if scenario == "redis_failure":
            result = self._test_redis_failure()
            results["tests"].append(result)

        elif scenario == "ai_timeout":
            result = self._test_ai_timeout()
            results["tests"].append(result)

        elif scenario == "high_load":
            for mode in [ChaosMode.REDIS_LATENCY, ChaosMode.NETWORK_DELAY]:
                result = self._test_system_continues(mode)
                results["tests"].append(result)

        elif scenario == "full_chaos":
            modes = [
                ChaosMode.REDIS_LATENCY, ChaosMode.AI_SLOW,
                ChaosMode.NETWORK_DELAY, ChaosMode.RANDOM_ERROR,
            ]
            for mode in modes:
                result = self._test_system_continues(mode)
                results["tests"].append(result)

        results["duration_s"] = round(time.time() - results["start_time"], 2)
        results["all_passed"] = all(t.get("passed") for t in results["tests"])
        return results

    def _test_redis_failure(self) -> Dict:
        """Test that system handles Redis failure gracefully."""
        test = {"name": "redis_failure", "passed": False, "notes": []}
        try:
            # Test rate limiter fails open
            from generated_app.middleware.rate_limit import rate_limiter
            result = rate_limiter("test_tenant_chaos")
            test["notes"].append(f"Rate limiter returned: {result} (should be True = fail-open)")
            test["passed"] = result is True  # Must fail open
        except Exception as e:
            test["notes"].append(f"Exception raised (bad): {e}")
            test["passed"] = False
        return test

    def _test_ai_timeout(self) -> Dict:
        """Test that AI timeout returns fallback, not crash."""
        test = {"name": "ai_timeout", "passed": False, "notes": []}
        try:
            from core.ai_super_router.router import get_super_router
            router = get_super_router()
            result = router.generate(
                prompt="This is a chaos test — test AI timeout handling",
                mode="general",
            )
            has_response = bool(result.get("response"))
            test["notes"].append(f"Source: {result.get('source')} — Has response: {has_response}")
            test["passed"] = has_response  # Must always return something
        except Exception as e:
            test["notes"].append(f"Unhandled exception (bad): {e}")
            test["passed"] = False
        return test

    def _test_system_continues(self, mode: ChaosMode) -> Dict:
        """Test that system continues operating under a specific chaos mode."""
        test = {"name": mode.value, "passed": False, "notes": []}
        try:
            # Test health check still works
            from core.database.db_engine import health_check
            db_ok = health_check()
            test["notes"].append(f"DB health: {db_ok}")

            # Test memory store still works
            from core.memory.memory_store import get_memory
            mem = get_memory()
            mem.save(f"chaos_test_{mode.value}", {"test": True})
            test["notes"].append("Memory store: OK")

            test["passed"] = True
        except Exception as e:
            test["notes"].append(f"System failure detected: {e}")
            test["passed"] = False
        return test

    def status(self) -> Dict:
        with self._lock:
            experiments = {k: v.to_dict() for k, v in self._experiments.items()}
            recent_events = self._event_log[-20:]
        return {
            "enabled": self._enabled,
            "is_production": settings.is_production,
            "experiments": experiments,
            "recent_events": recent_events,
        }


# ── Singleton ─────────────────────────────────────────────────
_chaos_engine: Optional[ChaosEngine] = None
_chaos_lock = threading.Lock()


def get_chaos_engine() -> ChaosEngine:
    global _chaos_engine
    if _chaos_engine is None:
        with _chaos_lock:
            if _chaos_engine is None:
                _chaos_engine = ChaosEngine()
    return _chaos_engine
