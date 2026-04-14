# ============================================================
# CYBERDUDEBIVASH AI — MONETIZATION ENGINE
# Subscription tiers, per-plan rate limits, usage enforcement,
# credit management, abuse prevention, billing hooks
# ============================================================

import time
import threading
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from core.logging_config import get_logger

logger = get_logger("monetization")


# ── Subscription Plans ────────────────────────────────────────
@dataclass(frozen=True)
class Plan:
    name: str
    requests_per_minute: int
    requests_per_day: int
    max_code_chars: int
    max_concurrent_tasks: int
    initial_credits: float
    ai_access: bool
    priority_queue: bool
    monthly_price_usd: float

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "requests_per_minute": self.requests_per_minute,
            "requests_per_day": self.requests_per_day,
            "max_code_chars": self.max_code_chars,
            "max_concurrent_tasks": self.max_concurrent_tasks,
            "initial_credits": self.initial_credits,
            "ai_access": self.ai_access,
            "priority_queue": self.priority_queue,
            "monthly_price_usd": self.monthly_price_usd,
        }


PLANS: Dict[str, Plan] = {
    "free": Plan(
        name="free",
        requests_per_minute=10,
        requests_per_day=100,
        max_code_chars=5_000,
        max_concurrent_tasks=2,
        initial_credits=10.0,
        ai_access=True,
        priority_queue=False,
        monthly_price_usd=0.0,
    ),
    "pro": Plan(
        name="pro",
        requests_per_minute=60,
        requests_per_day=5_000,
        max_code_chars=25_000,
        max_concurrent_tasks=10,
        initial_credits=100.0,
        ai_access=True,
        priority_queue=True,
        monthly_price_usd=49.0,
    ),
    "enterprise": Plan(
        name="enterprise",
        requests_per_minute=300,
        requests_per_day=50_000,
        max_code_chars=50_000,
        max_concurrent_tasks=50,
        initial_credits=99_999.0,
        ai_access=True,
        priority_queue=True,
        monthly_price_usd=299.0,
    ),
}

# Cost per action (in credits)
ACTION_COSTS: Dict[str, float] = {
    "threat_intel":         0.5,
    "vulnerability_scan":   0.5,
    "malware_analysis":     0.5,
    "osint":                1.0,
    "security_audit":       1.0,
    "code_generation":      0.5,
    "swarm":                2.0,
    "sast_scan":            0.5,
    "submit_task":          0.5,
    "generate_task":        0.5,
    "generate_code":        0.5,
    "generate_code_sync":   0.5,
    "default":              0.1,
}

# Abuse detection thresholds
ABUSE_THRESHOLDS = {
    "requests_per_10s": 30,    # > 30 req/10s = abuse
    "failed_auth_per_min": 10, # > 10 failed auth/min = brute force
    "large_payload_per_min": 5, # > 5 oversized payloads/min = scraping
}


# ── Usage Tracker ─────────────────────────────────────────────
class UsageTracker:
    """
    In-memory sliding window usage tracker.
    Tracks requests per minute/day per tenant.
    Falls back to pass-through if Redis is unavailable.
    """

    def __init__(self):
        self._windows: Dict[str, list] = {}   # tenant:window → list of timestamps
        self._lock = threading.Lock()

    def _window_key(self, tenant_id: str, window: str) -> str:
        return f"{tenant_id}:{window}"

    def _count_in_window(self, tenant_id: str, window_seconds: int) -> int:
        key = self._window_key(tenant_id, str(window_seconds))
        cutoff = time.time() - window_seconds
        with self._lock:
            times = self._windows.get(key, [])
            # Prune old entries
            times = [t for t in times if t > cutoff]
            self._windows[key] = times
            return len(times)

    def record_request(self, tenant_id: str) -> None:
        now = time.time()
        with self._lock:
            for window in [60, 86400]:  # 1 min, 1 day
                key = self._window_key(tenant_id, str(window))
                if key not in self._windows:
                    self._windows[key] = []
                self._windows[key].append(now)
                # Cap list size
                if len(self._windows[key]) > 10000:
                    self._windows[key] = self._windows[key][-5000:]

    def get_usage(self, tenant_id: str) -> Dict:
        return {
            "requests_last_minute": self._count_in_window(tenant_id, 60),
            "requests_last_day": self._count_in_window(tenant_id, 86400),
            "requests_last_10s": self._count_in_window(tenant_id, 10),
        }

    def is_within_limits(self, tenant_id: str, plan: Plan) -> Tuple[bool, str]:
        """Returns (allowed, reason)."""
        usage = self.get_usage(tenant_id)

        if usage["requests_last_minute"] >= plan.requests_per_minute:
            return False, f"Rate limit exceeded: {usage['requests_last_minute']}/{plan.requests_per_minute} req/min"

        if usage["requests_last_day"] >= plan.requests_per_day:
            return False, f"Daily limit exceeded: {usage['requests_last_day']}/{plan.requests_per_day} req/day"

        return True, "ok"

    def is_abusive(self, tenant_id: str) -> Tuple[bool, str]:
        """Detect abuse patterns."""
        usage = self.get_usage(tenant_id)
        if usage["requests_last_10s"] > ABUSE_THRESHOLDS["requests_per_10s"]:
            return True, f"Abuse detected: {usage['requests_last_10s']} req/10s"
        return False, ""


# ── Monetization Engine ───────────────────────────────────────
class MonetizationEngine:
    """
    Full monetization system:
    - Plan-based rate limiting
    - Credit management
    - Abuse prevention
    - Usage analytics
    """

    def __init__(self):
        self.tracker = UsageTracker()
        self._plan_cache: Dict[str, str] = {}   # tenant_id → plan_name
        self._lock = threading.Lock()
        logger.info("[Monetization] Engine initialized")

    def get_plan(self, tenant_id: str, db=None) -> Plan:
        """Get the plan for a tenant."""
        # Check cache first
        with self._lock:
            plan_name = self._plan_cache.get(tenant_id)
        if plan_name and plan_name in PLANS:
            return PLANS[plan_name]

        # Look up from DB
        if db is not None:
            try:
                from core.database.models import Subscription
                sub = db.query(Subscription).filter(Subscription.tenant_id == tenant_id).first()
                if sub and sub.plan in PLANS:
                    with self._lock:
                        self._plan_cache[tenant_id] = sub.plan
                    return PLANS[sub.plan]
            except Exception as e:
                logger.warning(f"[Monetization] Plan lookup failed: {e}")

        return PLANS["free"]  # Default to free

    def invalidate_plan_cache(self, tenant_id: str) -> None:
        with self._lock:
            self._plan_cache.pop(tenant_id, None)

    def check_and_enforce(
        self,
        tenant_id: str,
        action: str = "default",
        db=None,
        payload_size: int = 0,
    ) -> Tuple[bool, str, float]:
        """
        Full enforcement check.
        Returns (allowed, reason, credit_cost).
        """
        plan = self.get_plan(tenant_id, db)

        # 1. Abuse check
        is_abusive, abuse_reason = self.tracker.is_abusive(tenant_id)
        if is_abusive:
            logger.warning(f"[Monetization] Abuse: tenant={tenant_id} reason={abuse_reason}")
            return False, f"Abuse detected: {abuse_reason}", 0.0

        # 2. Rate limit check
        allowed, reason = self.tracker.is_within_limits(tenant_id, plan)
        if not allowed:
            return False, reason, 0.0

        # 3. Payload size check
        if payload_size > plan.max_code_chars:
            return False, f"Payload too large: {payload_size} > {plan.max_code_chars} chars for {plan.name} plan", 0.0

        # 4. Get credit cost
        cost = ACTION_COSTS.get(action, ACTION_COSTS["default"])

        # Pro/Enterprise gets 20% discount
        if plan.name in ("pro", "enterprise"):
            cost *= 0.8

        # 5. Record the request
        self.tracker.record_request(tenant_id)

        return True, "ok", round(cost, 4)

    def get_action_queue(self, action: str, tenant_id: str, db=None) -> str:
        """Return the appropriate Celery queue based on plan."""
        plan = self.get_plan(tenant_id, db)
        if plan.priority_queue:
            return f"{action}_priority" if action else "ai_tasks_priority"
        return "ai_tasks"

    def usage_report(self, tenant_id: str, db=None) -> Dict:
        """Full usage report for a tenant."""
        plan = self.get_plan(tenant_id, db)
        usage = self.tracker.get_usage(tenant_id)

        # Get credit balance
        credits = 0.0
        if db is not None:
            try:
                from core.database.models import Subscription
                sub = db.query(Subscription).filter(Subscription.tenant_id == tenant_id).first()
                if sub:
                    credits = float(sub.credits or 0)
            except Exception:
                pass

        return {
            "tenant_id": tenant_id,
            "plan": plan.to_dict(),
            "usage": {
                **usage,
                "requests_per_minute_limit": plan.requests_per_minute,
                "requests_per_day_limit": plan.requests_per_day,
                "percent_rpm": round(usage["requests_last_minute"] / plan.requests_per_minute * 100, 1),
                "percent_daily": round(usage["requests_last_day"] / plan.requests_per_day * 100, 1),
            },
            "credits_remaining": round(credits, 4),
            "action_costs": ACTION_COSTS,
        }

    @staticmethod
    def list_plans() -> Dict:
        return {name: plan.to_dict() for name, plan in PLANS.items()}


# ── Singleton ─────────────────────────────────────────────────
_monetization: Optional[MonetizationEngine] = None
_mon_lock = threading.Lock()


def get_monetization() -> MonetizationEngine:
    global _monetization
    if _monetization is None:
        with _mon_lock:
            if _monetization is None:
                _monetization = MonetizationEngine()
    return _monetization
