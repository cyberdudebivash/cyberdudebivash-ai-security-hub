"""
CYBERDUDEBIVASH® Multi-Agent Cybersecurity OS
Policy Engine — RBAC/ABAC enforcement for every agent action.
All agent actions are authorized before execution. No bypass.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import structlog
    logger = structlog.get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

from pydantic import BaseModel

# ─── Tier definitions ─────────────────────────────────────────────────────────
TIER_HIERARCHY = ["FREE", "STARTER", "PRO", "ENTERPRISE", "GLOBAL_ENTERPRISE"]

TIER_PERMISSIONS: Dict[str, Set[str]] = {
    "FREE": {
        "analyze_ioc", "lookup_cve", "analyze_alert", "support_request",
        "onboarding", "threat_brief",
    },
    "STARTER": {
        "analyze_ioc", "lookup_cve", "analyze_alert", "support_request",
        "onboarding", "threat_brief", "vulnerability_scan", "compliance_check",
        "cloud_security_check", "subscription_query",
    },
    "PRO": {
        "analyze_ioc", "lookup_cve", "analyze_alert", "support_request",
        "onboarding", "threat_brief", "vulnerability_scan", "compliance_check",
        "cloud_security_check", "subscription_query", "analyze_malware",
        "get_threat_actor", "threat_hunt", "create_detection", "incident_response",
        "architecture_review", "devsecops_review", "generate_blog", "threat_report",
        "assess_prompt_injection", "ai_governance_check", "renewal",
    },
    "ENTERPRISE": {
        # All PRO permissions plus:
        "analyze_ioc", "lookup_cve", "analyze_alert", "support_request",
        "onboarding", "threat_brief", "vulnerability_scan", "compliance_check",
        "cloud_security_check", "subscription_query", "analyze_malware",
        "get_threat_actor", "threat_hunt", "create_detection", "incident_response",
        "architecture_review", "devsecops_review", "generate_blog", "threat_report",
        "assess_prompt_injection", "ai_governance_check", "renewal",
        "ai_red_team", "ai_runtime_alert", "ai_risk_assessment", "critical_incident",
        "ciso_briefing", "board_report", "risk_register", "executive_summary",
        "revenue_metrics", "escalate_alert", "enrich_threat", "whitepaper",
        "campaign_intelligence",
    },
    "GLOBAL_ENTERPRISE": {
        "*"  # Wildcard — all intents permitted
    },
}

# ─── Rate limits per tier (requests/minute) ───────────────────────────────────
TIER_RATE_LIMITS: Dict[str, int] = {
    "FREE":              10,
    "STARTER":           30,
    "PRO":               100,
    "ENTERPRISE":        500,
    "GLOBAL_ENTERPRISE": 2000,
}

# ─── Sensitive intents requiring additional ABAC checks ───────────────────────
SENSITIVE_INTENTS: Set[str] = {
    "critical_incident", "board_report", "executive_summary",
    "ai_red_team", "ai_runtime_alert", "revenue_metrics",
}

class PolicyDecision(BaseModel):
    allowed:    bool
    reason:     str
    tier:       str
    intent:     str
    rate_limit: int
    checked_at: float = 0.0

    def __init__(self, **data):
        super().__init__(**data)
        self.checked_at = time.time()

class PolicyEngine:
    """
    RBAC/ABAC enforcement engine.
    Checks tier, rate limits, intent permissions, and sensitive-action guards.
    All decisions are logged to audit trail.
    """

    def __init__(self, redis_client: Any = None, pg_pool: Any = None):
        self.redis = redis_client
        self.db    = pg_pool
        self._decisions_log: List[Dict[str, Any]] = []
        self._rate_limited:  set = set()  # user_ids currently rate-limited

    async def check_request(
        self,
        user_id:   str,
        tenant_id: str,
        intent:    str,
        tier:      str = "FREE",
        context:   Dict[str, Any] = None,
    ) -> Tuple[bool, str]:
        """
        Returns (allowed: bool, reason: str).
        All rejections are logged to audit trail.
        """
        # 1. Normalize tier
        tier = tier.upper() if tier.upper() in TIER_HIERARCHY else "FREE"

        # 2. Check intent permission
        allowed_intents = TIER_PERMISSIONS.get(tier, set())
        if "*" not in allowed_intents and intent not in allowed_intents:
            reason = f"Intent '{intent}' not available on {tier} plan"
            await self._log_decision(user_id, tenant_id, intent, tier, False, reason)
            return False, reason

        # 3. Rate limit check
        if self.redis:
            within_limit = await self._check_rate_limit(user_id, tenant_id, tier)
            if not within_limit:
                limit = TIER_RATE_LIMITS[tier]
                reason = f"Rate limit exceeded: {limit} requests/min on {tier}"
                await self._log_decision(user_id, tenant_id, intent, tier, False, reason)
                return False, reason

        # 4. Sensitive intent ABAC guard
        if intent in SENSITIVE_INTENTS:
            abac_ok, abac_reason = await self._check_abac(user_id, tenant_id, intent, tier, context or {})
            if not abac_ok:
                await self._log_decision(user_id, tenant_id, intent, tier, False, abac_reason)
                return False, abac_reason

        await self._log_decision(user_id, tenant_id, intent, tier, True, "Permitted")
        return True, "Permitted"

    async def _check_rate_limit(self, user_id: str, tenant_id: str, tier: str) -> bool:
        """Sliding-window rate limit via Redis."""
        try:
            limit  = TIER_RATE_LIMITS.get(tier, 10)
            key    = f"ratelimit:{tenant_id}:{user_id}"
            now    = time.time()
            window = 60.0  # 1 minute window

            pipe   = self.redis.pipeline()
            pipe.zremrangebyscore(key, 0, now - window)
            pipe.zcard(key)
            pipe.zadd(key, {str(now): now})
            pipe.expire(key, 120)
            results = await pipe.execute()
            count   = results[1]
            return count < limit
        except Exception:
            return True  # Fail open if Redis unavailable

    async def _check_abac(
        self, user_id: str, tenant_id: str, intent: str, tier: str, context: Dict
    ) -> Tuple[bool, str]:
        """Attribute-based access control for sensitive intents."""
        if intent in {"board_report", "executive_summary", "ciso_briefing"}:
            # Must be ENTERPRISE or above
            tier_idx = TIER_HIERARCHY.index(tier) if tier in TIER_HIERARCHY else 0
            ent_idx  = TIER_HIERARCHY.index("ENTERPRISE")
            if tier_idx < ent_idx:
                return False, f"'{intent}' requires ENTERPRISE plan"
        if intent == "ai_red_team":
            # Requires explicit red-team authorization flag in context
            if not context.get("red_team_authorized"):
                return False, "AI Red Team requires explicit 'red_team_authorized' flag in request context"
        return True, "ABAC passed"

    async def _log_decision(
        self, user_id: str, tenant_id: str, intent: str,
        tier: str, allowed: bool, reason: str,
    ):
        entry = {
            "user_id": user_id, "tenant_id": tenant_id, "intent": intent,
            "tier": tier, "allowed": allowed, "reason": reason, "ts": time.time(),
        }
        self._decisions_log.append(entry)
        logger.info("policy.decision", **entry)

        if self.db:
            try:
                async with self.db.acquire() as conn:
                    await conn.execute("""
                        INSERT INTO policy_audit (user_id, tenant_id, intent, tier, allowed, reason, created_at)
                        VALUES ($1,$2,$3,$4,$5,$6,NOW())
                    """, user_id, tenant_id, intent, tier, allowed, reason)
            except Exception: pass

    def get_permissions(self, tier: str) -> List[str]:
        perms = TIER_PERMISSIONS.get(tier.upper(), set())
        if "*" in perms:
            return ["*"]
        return sorted(perms)

    def get_rate_limit(self, tier: str) -> int:
        return TIER_RATE_LIMITS.get(tier.upper(), 10)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_decisions":    len(self._decisions_log),
            "rate_limited_users": len(self._rate_limited),
            "recent_decisions": self._decisions_log[-10:] if self._decisions_log else [],
        }
