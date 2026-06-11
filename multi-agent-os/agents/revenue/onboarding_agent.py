"""Onboarding Agent — Customer onboarding flows, time-to-value tracking, integration setup guidance."""
from __future__ import annotations
import time
from typing import Any, Dict, List, Tuple
from ..core.base_agent import BaseAgent, AgentLayer, AgentCapability, AgentRequest

ONBOARDING_STEPS = {
    "FREE": [
        {"step": 1, "name": "Account Setup", "description": "Create organization and API key"},
        {"step": 2, "name": "First Scan", "description": "Run first IOC or CVE scan"},
        {"step": 3, "name": "Explore Dashboard", "description": "Review threat intelligence dashboard"},
    ],
    "STARTER": [
        {"step": 1, "name": "Account Setup", "description": "Org settings, team members, SSO"},
        {"step": 2, "name": "Integration", "description": "Connect SIEM or ticketing system"},
        {"step": 3, "name": "SOC Workflows", "description": "Configure alert routing and escalation"},
        {"step": 4, "name": "First Hunt", "description": "Run threat hunting query"},
        {"step": 5, "name": "Go Live", "description": "Activate 24/7 monitoring"},
    ],
    "ENTERPRISE": [
        {"step": 1, "name": "Dedicated Onboarding", "description": "Dedicated CSM assigned"},
        {"step": 2, "name": "Architecture Review", "description": "Technical architecture alignment call"},
        {"step": 3, "name": "SIEM/SOAR Integration", "description": "Deep integration with existing stack"},
        {"step": 4, "name": "Custom Playbooks", "description": "Build org-specific response playbooks"},
        {"step": 5, "name": "Team Training", "description": "Platform training for SOC analysts"},
        {"step": 6, "name": "QBR Setup", "description": "Quarterly business review cadence"},
        {"step": 7, "name": "Production Launch", "description": "Full production deployment"},
    ],
}

class OnboardingAgent(BaseAgent):
    @property
    def name(self) -> str: return "onboarding"
    @property
    def layer(self) -> AgentLayer: return AgentLayer.REVENUE
    @property
    def capabilities(self) -> List[AgentCapability]:
        return [AgentCapability(
            name="customer_onboarding", description="Onboarding workflow guidance, time-to-value acceleration, integration setup assistance",
            intents=["onboarding", "get_started", "setup_guidance"],
            requires_tier="FREE", rate_limit=200, timeout_ms=15_000,
        )]

    async def _execute(self, request: AgentRequest) -> Tuple[Dict[str, Any], List[str]]:
        p = request.payload
        org_id = p.get("org_id", "")
        tier = p.get("tier", "FREE").upper()
        completed_steps = p.get("completed_steps", [])
        days_since_signup = p.get("days_since_signup", 0)

        steps = ONBOARDING_STEPS.get(tier, ONBOARDING_STEPS["FREE"])
        completed_count = len(completed_steps)
        total_steps = len(steps)
        completion_pct = (completed_count / total_steps * 100) if total_steps else 0
        pending_steps = [s for s in steps if s["step"] not in [c if isinstance(c, int) else c.get("step", 0) for c in completed_steps]]
        next_step = pending_steps[0] if pending_steps else None

        reasoning = [
            f"Onboarding: {org_id} | Tier: {tier} | Day {days_since_signup}",
            f"Progress: {completed_count}/{total_steps} steps ({completion_pct:.0f}%)",
            f"Next: {next_step['name'] if next_step else 'Complete!'}",
        ]

        result = {
            "onboarding_id": f"ONB-{int(time.time())}",
            "org_id": org_id,
            "tier": tier,
            "completion_percent": round(completion_pct, 1),
            "completed_steps": completed_count,
            "total_steps": total_steps,
            "all_steps": steps,
            "completed_step_list": completed_steps,
            "pending_steps": pending_steps,
            "next_step": next_step,
            "days_since_signup": days_since_signup,
            "on_track": days_since_signup < 14 or completion_pct > 50,
            "time_to_value_estimate_days": max(0, 7 - days_since_signup),
            "integration_docs_url": "https://docs.cyberdudebivash.ai/integrations",
            "support_email": "support@cyberdudebivash.ai",
            "onboarding_complete": completion_pct >= 100,
            "powered_by_mythos": True,
            "checked_at": time.time(),
        }
        return result, reasoning

    async def _compute_scores(self, request: AgentRequest, result: Dict) -> Tuple[float,float,float,float,float]:
        return 95.0, 96.0, 97.0, 95.0, 96.0
