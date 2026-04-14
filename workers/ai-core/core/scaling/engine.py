# ============================================================
# CYBERDUDEBIVASH AI — AUTO-SCALING ENGINE
# Monitors queue depth + API latency, dynamically adjusts
# Celery worker concurrency, enforces backpressure
# ============================================================

import time
import threading
import statistics
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from core.logging_config import get_logger

logger = get_logger("scaling.engine")


@dataclass
class ScalingMetrics:
    """Point-in-time snapshot of system load metrics."""
    timestamp: float = field(default_factory=time.time)
    queue_depth_ai: int = 0
    queue_depth_cyber: int = 0
    queue_depth_default: int = 0
    active_workers: int = 0
    active_tasks: int = 0
    avg_task_latency_ms: float = 0.0
    redis_memory_mb: float = 0.0

    @property
    def total_queue_depth(self) -> int:
        return self.queue_depth_ai + self.queue_depth_cyber + self.queue_depth_default

    @property
    def load_factor(self) -> float:
        """0.0 = idle, 1.0 = at capacity, >1.0 = overloaded."""
        if self.active_workers == 0:
            return float(self.total_queue_depth) / 4  # assume 4 workers
        return (self.active_tasks + self.total_queue_depth) / max(self.active_workers * 4, 1)


# ── Scaling Policy ────────────────────────────────────────────
class ScalingPolicy:
    """
    Thresholds and rules for scaling decisions.
    All thresholds are configurable.
    """

    def __init__(self):
        self.scale_up_queue_threshold = 20     # queue > 20 → scale up
        self.scale_down_queue_threshold = 5    # queue < 5 → scale down
        self.scale_up_latency_threshold_ms = 5000   # avg latency > 5s → scale up
        self.max_concurrency = 16
        self.min_concurrency = 2
        self.default_concurrency = 4
        self.scale_up_step = 2
        self.scale_down_step = 1
        self.cooldown_seconds = 60      # minimum time between scaling events
        self.burst_threshold = 50       # queue > 50 → burst mode
        self.burst_concurrency = 12

    def should_scale_up(self, metrics: ScalingMetrics, current_concurrency: int) -> bool:
        if current_concurrency >= self.max_concurrency:
            return False
        if metrics.total_queue_depth > self.scale_up_queue_threshold:
            return True
        if metrics.avg_task_latency_ms > self.scale_up_latency_threshold_ms:
            return True
        return False

    def should_scale_down(self, metrics: ScalingMetrics, current_concurrency: int) -> bool:
        if current_concurrency <= self.min_concurrency:
            return False
        if metrics.total_queue_depth < self.scale_down_queue_threshold and \
           metrics.active_tasks < current_concurrency // 2:
            return True
        return False

    def target_concurrency(self, metrics: ScalingMetrics, current: int) -> int:
        # Burst mode
        if metrics.total_queue_depth > self.burst_threshold:
            return min(self.burst_concurrency, self.max_concurrency)

        if self.should_scale_up(metrics, current):
            return min(current + self.scale_up_step, self.max_concurrency)

        if self.should_scale_down(metrics, current):
            return max(current - self.scale_down_step, self.min_concurrency)

        return current


# ── Metrics Collector ─────────────────────────────────────────
class MetricsCollector:
    """Collects real-time metrics from Redis, Celery, and system."""

    def collect(self) -> ScalingMetrics:
        metrics = ScalingMetrics()

        # Queue depths via Redis
        try:
            from generated_app.core.redis_client import redis_client
            if redis_client:
                metrics.queue_depth_ai     = redis_client.llen("ai_tasks") or 0
                metrics.queue_depth_cyber  = redis_client.llen("cyber_tasks") or 0
                metrics.queue_depth_default = redis_client.llen("celery") or 0

                # Redis memory usage
                info = redis_client.info("memory")
                metrics.redis_memory_mb = float(info.get("used_memory", 0)) / (1024 * 1024)
        except Exception as e:
            logger.debug(f"[Collector] Redis metrics failed: {e}")

        # Celery worker/task info
        try:
            from generated_app.core.celery_app import celery_app
            inspect = celery_app.control.inspect(timeout=1.5)
            active = inspect.active() or {}
            metrics.active_workers = len(active)
            metrics.active_tasks = sum(len(tasks) for tasks in active.values())
        except Exception as e:
            logger.debug(f"[Collector] Celery metrics failed: {e}")

        return metrics


# ── Backpressure Controller ───────────────────────────────────
class BackpressureController:
    """
    Enforces backpressure when system is overloaded.
    Rejects or delays new tasks to protect the system.
    """

    def __init__(self):
        self._overloaded = False
        self._overload_since: Optional[float] = None
        self._lock = threading.Lock()

    def update(self, metrics: ScalingMetrics) -> None:
        with self._lock:
            was_overloaded = self._overloaded
            self._overloaded = metrics.load_factor > 1.5 or metrics.total_queue_depth > 100

            if self._overloaded and not was_overloaded:
                self._overload_since = time.time()
                logger.warning(
                    f"[Backpressure] OVERLOAD DETECTED: "
                    f"queue={metrics.total_queue_depth} load={metrics.load_factor:.2f}"
                )
            elif not self._overloaded and was_overloaded:
                logger.info("[Backpressure] System recovered from overload")
                self._overload_since = None

    def is_overloaded(self) -> bool:
        with self._lock:
            return self._overloaded

    def should_shed_load(self) -> bool:
        """True if we should actively reject new non-critical requests."""
        with self._lock:
            if not self._overloaded or not self._overload_since:
                return False
            # Only shed load after 30s of continuous overload
            return time.time() - self._overload_since > 30

    def status(self) -> Dict:
        with self._lock:
            return {
                "overloaded": self._overloaded,
                "overload_duration_s": round(time.time() - self._overload_since, 1)
                                       if self._overload_since else 0,
                "shed_load": self.should_shed_load(),
            }


# ── Auto-Scaling Engine ───────────────────────────────────────
class AutoScalingEngine:
    """
    Continuously monitors system load and adjusts Celery worker
    concurrency dynamically. Includes cooldown, burst handling,
    and backpressure.
    """

    def __init__(self):
        self.policy = ScalingPolicy()
        self.collector = MetricsCollector()
        self.backpressure = BackpressureController()
        self._current_concurrency = self.policy.default_concurrency
        self._last_scale_time = 0.0
        self._metrics_history: List[ScalingMetrics] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._scale_events: List[Dict] = []

    def start(self, interval_seconds: float = 30.0) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._scaling_loop,
            args=(interval_seconds,),
            daemon=True,
            name="AutoScalingThread",
        )
        self._thread.start()
        logger.info("[AutoScaling] Engine started")

    def stop(self) -> None:
        self._running = False

    def _scaling_loop(self, interval: float) -> None:
        while self._running:
            try:
                self._evaluate_and_scale()
            except Exception as e:
                logger.error(f"[AutoScaling] Loop error: {e}")
            time.sleep(interval)

    def _evaluate_and_scale(self) -> None:
        metrics = self.collector.collect()

        # Update backpressure
        self.backpressure.update(metrics)

        # Store metrics history (last 20 samples)
        with self._lock:
            self._metrics_history.append(metrics)
            if len(self._metrics_history) > 20:
                self._metrics_history.pop(0)
            current = self._current_concurrency

        # Check cooldown
        if time.time() - self._last_scale_time < self.policy.cooldown_seconds:
            return

        target = self.policy.target_concurrency(metrics, current)

        if target != current:
            self._apply_scaling(current, target, metrics)

    def _apply_scaling(self, current: int, target: int, metrics: ScalingMetrics) -> None:
        """Apply scaling decision to Celery workers."""
        direction = "UP" if target > current else "DOWN"

        event = {
            "timestamp": time.time(),
            "direction": direction,
            "from_concurrency": current,
            "to_concurrency": target,
            "queue_depth": metrics.total_queue_depth,
            "active_tasks": metrics.active_tasks,
            "load_factor": round(metrics.load_factor, 3),
        }

        try:
            from generated_app.core.celery_app import celery_app
            celery_app.control.broadcast(
                "pool_grow" if direction == "UP" else "pool_shrink",
                arguments={"n": abs(target - current)},
            )
            with self._lock:
                self._current_concurrency = target
                self._last_scale_time = time.time()
                self._scale_events.append(event)
                if len(self._scale_events) > 50:
                    self._scale_events.pop(0)

            logger.info(
                f"[AutoScaling] Scale {direction}: {current} → {target} "
                f"(queue={metrics.total_queue_depth} load={metrics.load_factor:.2f})"
            )
        except Exception as e:
            logger.warning(f"[AutoScaling] Scale command failed: {e}")

    def get_current_metrics(self) -> Optional[ScalingMetrics]:
        with self._lock:
            return self._metrics_history[-1] if self._metrics_history else None

    def status(self) -> Dict:
        metrics = self.get_current_metrics()
        return {
            "current_concurrency": self._current_concurrency,
            "policy": {
                "min": self.policy.min_concurrency,
                "max": self.policy.max_concurrency,
                "scale_up_queue_threshold": self.policy.scale_up_queue_threshold,
                "burst_threshold": self.policy.burst_threshold,
            },
            "current_metrics": {
                "total_queue_depth": metrics.total_queue_depth if metrics else 0,
                "active_workers": metrics.active_workers if metrics else 0,
                "active_tasks": metrics.active_tasks if metrics else 0,
                "load_factor": round(metrics.load_factor, 3) if metrics else 0,
                "redis_memory_mb": round(metrics.redis_memory_mb, 1) if metrics else 0,
            },
            "backpressure": self.backpressure.status(),
            "recent_scale_events": self._scale_events[-5:],
            "running": self._running,
        }


# ── Singleton ─────────────────────────────────────────────────
_scaler: Optional[AutoScalingEngine] = None
_scaler_lock = threading.Lock()


def get_scaler() -> AutoScalingEngine:
    global _scaler
    if _scaler is None:
        with _scaler_lock:
            if _scaler is None:
                _scaler = AutoScalingEngine()
    return _scaler
