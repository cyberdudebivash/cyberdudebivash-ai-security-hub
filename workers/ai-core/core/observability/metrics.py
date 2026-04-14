# ============================================================
# CYBERDUDEBIVASH AI — OBSERVABILITY STACK
# Prometheus metrics, threshold-based alerts, latency tracking,
# error rate monitoring, AI response time tracking
# ============================================================

import time
import threading
import statistics
from typing import Any, Callable, Dict, List, Optional
from collections import defaultdict, deque
from dataclasses import dataclass, field
from core.logging_config import get_logger

logger = get_logger("observability")


# ── Prometheus Integration ────────────────────────────────────
try:
    from prometheus_client import (
        Counter, Histogram, Gauge, Summary,
        REGISTRY, CollectorRegistry
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    logger.warning("[Observability] prometheus_client not available — using internal metrics only")


class MetricsRegistry:
    """
    Central registry for all system metrics.
    Uses Prometheus when available, falls back to internal counters.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._init_metrics()
        logger.info("[Observability] Metrics registry initialized")

    def _init_metrics(self):
        if PROMETHEUS_AVAILABLE:
            try:
                # HTTP Metrics
                self.http_requests_total = Counter(
                    "cdb_http_requests_total",
                    "Total HTTP requests",
                    ["method", "endpoint", "status_code"]
                )
                self.http_request_duration = Histogram(
                    "cdb_http_request_duration_seconds",
                    "HTTP request duration",
                    ["method", "endpoint"],
                    buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
                )
                self.http_requests_in_flight = Gauge(
                    "cdb_http_requests_in_flight",
                    "Current in-flight requests"
                )

                # Task Metrics
                self.task_submitted_total = Counter(
                    "cdb_tasks_submitted_total",
                    "Total tasks submitted",
                    ["task_type", "queue"]
                )
                self.task_completed_total = Counter(
                    "cdb_tasks_completed_total",
                    "Total tasks completed",
                    ["task_type", "status"]
                )
                self.task_duration = Histogram(
                    "cdb_task_duration_seconds",
                    "Task execution duration",
                    ["task_type"],
                    buckets=[1, 5, 15, 30, 60, 120, 300]
                )
                self.task_queue_depth = Gauge(
                    "cdb_task_queue_depth",
                    "Current task queue depth",
                    ["queue"]
                )

                # AI Metrics
                self.ai_requests_total = Counter(
                    "cdb_ai_requests_total",
                    "Total AI requests",
                    ["mode", "provider", "status"]
                )
                self.ai_response_duration = Histogram(
                    "cdb_ai_response_duration_seconds",
                    "AI response time",
                    ["mode", "provider"],
                    buckets=[0.5, 1, 2, 5, 10, 30, 60]
                )
                self.ai_confidence = Histogram(
                    "cdb_ai_confidence_score",
                    "AI response confidence scores",
                    ["mode"],
                    buckets=[0.1, 0.2, 0.3, 0.5, 0.7, 0.8, 0.9, 1.0]
                )
                self.ai_cache_hits = Counter(
                    "cdb_ai_cache_hits_total",
                    "AI response cache hits"
                )

                # System Metrics
                self.component_health_score = Gauge(
                    "cdb_component_health_score",
                    "Component health score (0-100)",
                    ["component"]
                )
                self.worker_count = Gauge("cdb_active_workers", "Active Celery workers")
                self.system_score = Gauge("cdb_system_health_score", "Overall system health score")

                # Threat Metrics
                self.threats_analyzed = Counter(
                    "cdb_threats_analyzed_total",
                    "Total threat analyses",
                    ["type", "severity"]
                )
                self.iocs_ingested = Counter(
                    "cdb_iocs_ingested_total",
                    "Total IOCs ingested",
                    ["ioc_type", "severity"]
                )

                # Business Metrics
                self.api_key_requests = Counter(
                    "cdb_api_key_requests_total",
                    "Requests per API key tier",
                    ["plan"]
                )
                self.credits_consumed = Counter(
                    "cdb_credits_consumed_total",
                    "Credits consumed",
                    ["action"]
                )

                self._prom_enabled = True
                logger.info("[Observability] Prometheus metrics initialized")
            except Exception as e:
                logger.warning(f"[Observability] Prometheus init partial failure: {e}")
                self._prom_enabled = False
        else:
            self._prom_enabled = False

        # Internal fallback counters (always active)
        self._counters: Dict[str, float] = defaultdict(float)
        self._gauges: Dict[str, float] = defaultdict(float)
        self._histograms: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))

    # ── Recording Methods ─────────────────────────────────────

    def record_http_request(self, method: str, endpoint: str,
                            status_code: int, duration_s: float) -> None:
        if self._prom_enabled:
            try:
                self.http_requests_total.labels(
                    method=method, endpoint=endpoint, status_code=str(status_code)
                ).inc()
                self.http_request_duration.labels(
                    method=method, endpoint=endpoint
                ).observe(duration_s)
            except Exception:
                pass
        # Internal
        self._counters[f"http.{method}.{status_code}"] += 1
        self._histograms[f"http.duration.{endpoint}"].append(duration_s * 1000)

    def record_task(self, task_type: str, queue: str, status: str, duration_s: float) -> None:
        if self._prom_enabled:
            try:
                self.task_completed_total.labels(task_type=task_type, status=status).inc()
                self.task_duration.labels(task_type=task_type).observe(duration_s)
            except Exception:
                pass
        self._counters[f"task.{task_type}.{status}"] += 1
        self._histograms[f"task.duration.{task_type}"].append(duration_s * 1000)

    def record_ai_request(self, mode: str, provider: str, status: str,
                          duration_s: float, confidence: float = 0.0,
                          from_cache: bool = False) -> None:
        if self._prom_enabled:
            try:
                self.ai_requests_total.labels(
                    mode=mode, provider=provider, status=status
                ).inc()
                self.ai_response_duration.labels(mode=mode, provider=provider).observe(duration_s)
                if confidence > 0:
                    self.ai_confidence.labels(mode=mode).observe(confidence)
                if from_cache:
                    self.ai_cache_hits.inc()
            except Exception:
                pass
        self._counters[f"ai.{mode}.{status}"] += 1
        self._histograms[f"ai.duration.{mode}"].append(duration_s * 1000)

    def record_threat(self, threat_type: str, severity: str) -> None:
        if self._prom_enabled:
            try:
                self.threats_analyzed.labels(type=threat_type, severity=severity).inc()
            except Exception:
                pass
        self._counters[f"threat.{threat_type}.{severity}"] += 1

    def record_ioc(self, ioc_type: str, severity: str) -> None:
        if self._prom_enabled:
            try:
                self.iocs_ingested.labels(ioc_type=ioc_type, severity=severity).inc()
            except Exception:
                pass
        self._counters[f"ioc.{ioc_type}.{severity}"] += 1

    def set_component_health(self, component: str, score: float) -> None:
        if self._prom_enabled:
            try:
                self.component_health_score.labels(component=component).set(score)
            except Exception:
                pass
        self._gauges[f"health.{component}"] = score

    def set_system_health(self, score: float) -> None:
        if self._prom_enabled:
            try:
                self.system_score.set(score)
            except Exception:
                pass
        self._gauges["health.system"] = score

    def set_queue_depth(self, queue: str, depth: int) -> None:
        if self._prom_enabled:
            try:
                self.task_queue_depth.labels(queue=queue).set(depth)
            except Exception:
                pass
        self._gauges[f"queue.{queue}"] = depth

    def set_worker_count(self, count: int) -> None:
        if self._prom_enabled:
            try:
                self.worker_count.set(count)
            except Exception:
                pass
        self._gauges["workers.active"] = count

    def increment_in_flight(self) -> None:
        if self._prom_enabled:
            try:
                self.http_requests_in_flight.inc()
            except Exception:
                pass

    def decrement_in_flight(self) -> None:
        if self._prom_enabled:
            try:
                self.http_requests_in_flight.dec()
            except Exception:
                pass

    # ── Reporting ─────────────────────────────────────────────

    def get_summary(self) -> Dict:
        summary = {
            "prometheus_enabled": self._prom_enabled,
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
        }
        # Add percentiles for key histograms
        for key, values in self._histograms.items():
            if values:
                vals = list(values)
                summary[f"p50_{key}_ms"] = round(statistics.median(vals), 1)
                if len(vals) >= 20:
                    summary[f"p95_{key}_ms"] = round(sorted(vals)[int(len(vals) * 0.95)], 1)
        return summary


# ── Alert Engine ──────────────────────────────────────────────
@dataclass
class Alert:
    id: str
    severity: str          # CRITICAL / WARNING / INFO
    component: str
    message: str
    timestamp: float = field(default_factory=time.time)
    resolved: bool = False
    resolved_at: Optional[float] = None

    def to_dict(self) -> Dict:
        return {**vars(self), "age_seconds": round(time.time() - self.timestamp, 1)}


class AlertEngine:
    """
    Threshold-based alert system.
    Fires alerts when metrics cross thresholds.
    Deduplicates to prevent alert storms.
    """

    # Alert thresholds
    THRESHOLDS = {
        "health_score_critical":    20.0,   # component health score < 20
        "health_score_warning":     50.0,   # component health score < 50
        "queue_depth_critical":     100,    # queue depth > 100
        "queue_depth_warning":      50,     # queue depth > 50
        "error_rate_critical":      0.5,    # >50% error rate
        "error_rate_warning":       0.2,    # >20% error rate
        "ai_latency_warning_s":     10.0,   # AI response > 10s
        "ai_latency_critical_s":    30.0,   # AI response > 30s
    }

    def __init__(self):
        self._active_alerts: Dict[str, Alert] = {}   # alert_key → Alert
        self._alert_history: List[Alert] = []
        self._lock = threading.Lock()
        self._alert_callbacks: List[Callable] = []

    def add_callback(self, fn: Callable) -> None:
        """Register a callback for new alerts (e.g., webhook, email)."""
        self._alert_callbacks.append(fn)

    def evaluate(self, component: str, metric: str, value: float) -> Optional[Alert]:
        """Evaluate a metric and fire alert if threshold crossed."""
        alert_key = f"{component}.{metric}"
        severity = None
        message = None

        if metric == "health_score":
            if value < self.THRESHOLDS["health_score_critical"]:
                severity = "CRITICAL"
                message = f"{component} health critically low: {value:.0f}/100"
            elif value < self.THRESHOLDS["health_score_warning"]:
                severity = "WARNING"
                message = f"{component} health degraded: {value:.0f}/100"

        elif metric == "queue_depth":
            if value > self.THRESHOLDS["queue_depth_critical"]:
                severity = "CRITICAL"
                message = f"Task queue critically deep: {value:.0f} items"
            elif value > self.THRESHOLDS["queue_depth_warning"]:
                severity = "WARNING"
                message = f"Task queue building up: {value:.0f} items"

        elif metric == "error_rate":
            if value > self.THRESHOLDS["error_rate_critical"]:
                severity = "CRITICAL"
                message = f"{component} error rate critical: {value*100:.0f}%"
            elif value > self.THRESHOLDS["error_rate_warning"]:
                severity = "WARNING"
                message = f"{component} error rate elevated: {value*100:.0f}%"

        elif metric == "ai_latency_s":
            if value > self.THRESHOLDS["ai_latency_critical_s"]:
                severity = "CRITICAL"
                message = f"AI response critically slow: {value:.0f}s"
            elif value > self.THRESHOLDS["ai_latency_warning_s"]:
                severity = "WARNING"
                message = f"AI response slow: {value:.0f}s"

        if severity:
            return self._fire_alert(alert_key, severity, component, message)
        else:
            self._resolve_alert(alert_key)
            return None

    def _fire_alert(self, key: str, severity: str, component: str, message: str) -> Alert:
        with self._lock:
            existing = self._active_alerts.get(key)
            if existing and not existing.resolved:
                # Deduplicate — don't re-fire same alert
                return existing

            import uuid
            alert = Alert(
                id=str(uuid.uuid4()),
                severity=severity,
                component=component,
                message=message,
            )
            self._active_alerts[key] = alert
            self._alert_history.append(alert)
            if len(self._alert_history) > 500:
                self._alert_history.pop(0)

        logger.warning(f"[Alert] {severity}: {message}")

        # Fire callbacks
        for cb in self._alert_callbacks:
            try:
                cb(alert)
            except Exception as e:
                logger.error(f"[Alert] Callback failed: {e}")

        return alert

    def _resolve_alert(self, key: str) -> None:
        with self._lock:
            alert = self._active_alerts.get(key)
            if alert and not alert.resolved:
                alert.resolved = True
                alert.resolved_at = time.time()
                logger.info(f"[Alert] Resolved: {alert.message}")

    def get_active_alerts(self) -> List[Alert]:
        with self._lock:
            return [a for a in self._active_alerts.values() if not a.resolved]

    def get_recent_history(self, limit: int = 50) -> List[Alert]:
        with self._lock:
            return self._alert_history[-limit:]

    def status(self) -> Dict:
        active = self.get_active_alerts()
        critical = [a for a in active if a.severity == "CRITICAL"]
        return {
            "active_alerts": len(active),
            "critical_alerts": len(critical),
            "alerts": [a.to_dict() for a in active],
        }


# ── Observability Manager ─────────────────────────────────────
class ObservabilityManager:
    """Integrates metrics + alerts + health reporting into one interface."""

    def __init__(self):
        self.metrics = MetricsRegistry()
        self.alerts = AlertEngine()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self, interval: float = 30.0) -> None:
        """Start background metrics collection and alert evaluation."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._collect_loop,
            args=(interval,),
            daemon=True,
            name="ObservabilityThread",
        )
        self._thread.start()
        logger.info("[Observability] Manager started")

    def stop(self) -> None:
        self._running = False

    def _collect_loop(self, interval: float) -> None:
        while self._running:
            try:
                self._collect_and_evaluate()
            except Exception as e:
                logger.error(f"[Observability] Collection loop error: {e}")
            time.sleep(interval)

    def _collect_and_evaluate(self) -> None:
        # Collect health scores and push to metrics + alert engine
        try:
            from core.resilience.orchestrator import get_orchestrator
            orch = get_orchestrator()
            report = orch.registry.status_report()
            system_score = report.get("system_score", 100)
            self.metrics.set_system_health(system_score)
            self.alerts.evaluate("system", "health_score", system_score)

            for comp_name, comp_data in report.get("components", {}).items():
                score = comp_data.get("score", 100)
                self.metrics.set_component_health(comp_name, score)
                self.alerts.evaluate(comp_name, "health_score", score)
                self.alerts.evaluate(comp_name, "error_rate", comp_data.get("error_rate", 0))
        except Exception as e:
            logger.debug(f"[Observability] Health collection failed: {e}")

        # Collect queue depths
        try:
            from generated_app.core.redis_client import redis_client
            if redis_client:
                for queue in ["ai_tasks", "cyber_tasks", "celery"]:
                    depth = redis_client.llen(queue) or 0
                    self.metrics.set_queue_depth(queue, depth)
                    self.alerts.evaluate(queue, "queue_depth", depth)
        except Exception as e:
            logger.debug(f"[Observability] Queue collection failed: {e}")

        # Worker count
        try:
            from generated_app.core.celery_app import celery_app
            inspect = celery_app.control.inspect(timeout=1.5)
            active = inspect.active() or {}
            self.metrics.set_worker_count(len(active))
        except Exception:
            pass

    def full_report(self) -> Dict:
        return {
            "metrics": self.metrics.get_summary(),
            "alerts": self.alerts.status(),
        }


# ── Singleton ─────────────────────────────────────────────────
_obs_manager: Optional[ObservabilityManager] = None
_obs_lock = threading.Lock()


def get_observability() -> ObservabilityManager:
    global _obs_manager
    if _obs_manager is None:
        with _obs_lock:
            if _obs_manager is None:
                _obs_manager = ObservabilityManager()
    return _obs_manager
