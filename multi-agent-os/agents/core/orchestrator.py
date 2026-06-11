"""
CYBERDUDEBIVASH® Multi-Agent Cybersecurity OS
Master Orchestrator — Routes every request through the correct agent pipeline.
Every request: Intent Classification → Agent Selection → Parallel Execution
             → Quality Gate → Final Approval → Response
No direct response path is permitted.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple, Type

try:
    import structlog
    logger = structlog.get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

try:
    from opentelemetry import trace
    _tracer = trace.get_tracer(__name__)
except ImportError:
    trace, _tracer = None, None  # type: ignore

from pydantic import BaseModel

from .base_agent import (
    AgentLayer, AgentRequest, AgentResponse, AgentStatus, BaseAgent, _NoopSpan
)
from .quality_gate import QualityGate, QualityReport
from .policy_engine import PolicyEngine

# ─── Intent → Layer routing table ────────────────────────────────────────────
INTENT_ROUTING: Dict[str, List[str]] = {
    # ── Threat Intelligence ───────────────────────────────────────────────────
    "analyze_ioc":              ["ioc_intelligence", "threat_actor", "enrichment"],
    "lookup_cve":               ["cve_intelligence", "vulnerability"],
    "analyze_malware":          ["malware_intelligence", "threat_actor"],
    "get_threat_actor":         ["threat_actor", "campaign_intelligence"],
    "threat_brief":             ["threat_research", "cve_intelligence", "malware_intelligence"],
    "enrich_threat":            ["enrichment", "ioc_intelligence"],
    "dark_web_monitor":         ["dark_web_monitoring", "enrichment"],
    "osint_scan":               ["osint", "enrichment"],
    "zero_day_alert":           ["zero_day_research", "cve_intelligence", "vulnerability"],
    "campaign_analysis":        ["campaign_intelligence", "threat_actor", "ioc_intelligence"],

    # ── AI Security ───────────────────────────────────────────────────────────
    "assess_prompt_injection":  ["prompt_injection", "ai_risk"],
    "ai_red_team":              ["ai_red_team", "ai_governance"],
    "ai_governance_check":      ["ai_governance", "compliance"],
    "ai_runtime_alert":         ["ai_runtime_security", "incident_response"],
    "ai_risk_assessment":       ["ai_risk", "ai_governance"],

    # ── SOC ───────────────────────────────────────────────────────────────────
    "analyze_alert":            ["soc_tier1", "enrichment"],
    "escalate_alert":           ["soc_tier2", "threat_hunting"],
    "critical_incident":        ["soc_tier3", "incident_response", "ciso"],
    "threat_hunt":              ["threat_hunting", "detection_engineering"],
    "create_detection":         ["detection_engineering", "soc_tier2"],
    "incident_response":        ["incident_response", "soc_tier3"],
    "analyze_phishing":         ["phishing_analysis", "enrichment", "soc_tier1"],
    "correlate_alerts":         ["siem_correlation", "threat_hunting"],
    "ransomware_response":      ["ransomware_response", "soc_tier3", "incident_response"],
    "forensic_investigation":   ["forensics", "soc_tier2", "detection_engineering"],

    # ── Security Engineering ──────────────────────────────────────────────────
    "architecture_review":      ["security_architecture", "cloud_security"],
    "compliance_check":         ["compliance", "ai_governance"],
    "vulnerability_scan":       ["vulnerability", "soc_tier1"],
    "devsecops_review":         ["devsecops", "vulnerability"],
    "cloud_security_check":     ["cloud_security", "security_architecture"],
    "pentest_planning":         ["penetration_testing", "security_architecture"],
    "red_team_exercise":        ["red_team", "detection_engineering", "threat_hunting"],
    "api_security_check":       ["api_security", "vulnerability"],
    "container_security":       ["container_security", "devsecops"],
    "identity_review":          ["identity_security", "privileged_access"],
    "network_security_check":   ["network_security", "security_architecture"],
    "endpoint_security":        ["endpoint_security", "vulnerability"],
    "supply_chain_check":       ["supply_chain_security", "devsecops"],
    "dlp_assessment":           ["data_loss_prevention", "compliance"],
    "threat_modeling":          ["threat_modeling", "security_architecture"],
    "email_security_check":     ["email_security", "phishing_analysis"],
    "web_app_security":         ["web_application_security", "api_security"],
    "iot_security":             ["iot_security", "network_security"],
    "blockchain_security":      ["blockchain_security", "vulnerability"],
    "pam_assessment":           ["privileged_access", "identity_security"],
    "regulatory_report":        ["regulatory_reporting", "compliance"],
    "vendor_risk_assessment":   ["vendor_risk", "compliance"],
    "cyber_insurance_assessment": ["cyber_insurance", "compliance", "vulnerability"],

    # ── Executive ─────────────────────────────────────────────────────────────
    "ciso_briefing":            ["ciso", "threat_research"],
    "board_report":             ["ceo", "ciso", "cro"],
    "risk_register":            ["ciso", "compliance"],
    "executive_summary":        ["ceo", "cto", "ciso"],
    "revenue_metrics":          ["cro", "subscription"],
    "technical_roadmap":        ["cto", "ciso"],
    "growth_strategy":          ["cro", "ceo"],

    # ── Customer / Revenue ────────────────────────────────────────────────────
    "onboarding":               ["onboarding", "customer_success"],
    "support_request":          ["customer_success", "soc_tier1"],
    "subscription_query":       ["subscription", "billing"],
    "renewal":                  ["renewal", "customer_success"],
    "billing_inquiry":          ["billing", "customer_success"],
    "mssp_dashboard":           ["mssp", "soc_tier1", "threat_research"],
    "plan_details":             ["subscription"],

    # ── Research / Content ────────────────────────────────────────────────────
    "generate_blog":            ["blog", "research", "content_intelligence"],
    "threat_report":            ["research", "threat_research"],
    "whitepaper":               ["whitepaper", "research"],
    "content_strategy":         ["content_intelligence", "research"],
    "research_query":           ["research", "threat_research"],
}

# ─── Parallel execution groups (agents that run simultaneously) ──────────────
PARALLEL_GROUPS: Dict[str, List[str]] = {
    "threat_intelligence":  ["ioc_intelligence", "threat_actor", "cve_intelligence"],
    "security_posture":     ["vulnerability", "compliance", "cloud_security"],
    "incident_triage":      ["soc_tier1", "enrichment", "threat_hunting"],
}

class OrchestrationResult(BaseModel):
    orchestration_id: str
    request_id:       str
    intent:           str
    agents_invoked:   List[str]
    agent_responses:  List[Dict[str, Any]]
    final_response:   Dict[str, Any]
    quality_report:   Dict[str, Any]
    approved:         bool
    total_time_ms:    float
    tokens_used:      int
    created_at:       float

class MasterOrchestrator:
    """
    Central command for all agent operations.
    Implements: classify → route → execute → validate → approve → deliver.
    """

    def __init__(
        self,
        agent_registry:   "AgentRegistry",
        quality_gate:     QualityGate,
        policy_engine:    PolicyEngine,
        redis_client:     Any = None,
        kafka_producer:   Any = None,
        pg_pool:          Any = None,
    ):
        self.registry     = agent_registry
        self.quality_gate = quality_gate
        self.policy       = policy_engine
        self.redis        = redis_client
        self.kafka        = kafka_producer
        self.db           = pg_pool
        self._orchestrations: Dict[str, OrchestrationResult] = {}

        logger.info("orchestrator.initialized", agents_registered=len(agent_registry))

    # ── Main orchestration entry point ────────────────────────────────────────
    async def orchestrate(
        self,
        session_id:  str,
        user_id:     str,
        tenant_id:   str,
        intent:      str,
        payload:     Dict[str, Any],
        context:     Dict[str, Any] = None,
        tier:        str = "FREE",
        priority:    int = 5,
    ) -> OrchestrationResult:

        orch_id  = str(uuid.uuid4())
        start_ms = time.monotonic() * 1000

        _ctx = (_tracer.start_as_current_span(
            "orchestrator.orchestrate",
            attributes={
                "orchestration.id": orch_id,
                "intent": intent,
                "tenant.id": tenant_id,
                "tier": tier,
            },
        ) if _tracer else _NoopSpan())
        with _ctx as span:
            logger.info("orchestration.start", orch_id=orch_id, intent=intent, tenant_id=tenant_id)

            # 1. Policy pre-check
            allowed, reason = await self.policy.check_request(user_id, tenant_id, intent, tier)
            if not allowed:
                return self._build_rejected_result(orch_id, intent, reason, start_ms)

            # 2. Classify intent and resolve agents
            agent_names = self._resolve_agents(intent)
            if not agent_names:
                agent_names = ["customer_success"]  # fallback

            # 3. Build agent requests
            request = AgentRequest(
                session_id=session_id, user_id=user_id, tenant_id=tenant_id,
                intent=intent, payload=payload, context=context or {},
                priority=priority, tier=tier,
            )

            # 4. Execute agents (parallel where safe, sequential where ordered)
            agent_responses = await self._execute_agents(agent_names, request)

            # 5. Quality gate validation
            qr = await self.quality_gate.validate_batch(agent_responses, intent, tier)

            # 6. Synthesize final response
            final = await self._synthesize_response(agent_responses, qr, intent, payload)

            # 7. Final approval gate
            approved = qr.overall_score >= 95.0 and not qr.hallucination_detected

            # 8. Audit persistence
            total_tokens = sum(r.get("tokens_used", 0) for r in agent_responses)
            elapsed = time.monotonic() * 1000 - start_ms
            await self._persist_audit(orch_id, tenant_id, user_id, intent, agent_names, qr, elapsed, approved)

            span.set_attribute("orchestration.quality", qr.overall_score)
            span.set_attribute("orchestration.approved", approved)
            span.set_attribute("orchestration.elapsed_ms", elapsed)

            result = OrchestrationResult(
                orchestration_id=orch_id,
                request_id=request.request_id,
                intent=intent,
                agents_invoked=agent_names,
                agent_responses=[r if isinstance(r, dict) else r.model_dump() for r in agent_responses],
                final_response=final,
                quality_report=qr.model_dump(),
                approved=approved,
                total_time_ms=elapsed,
                tokens_used=total_tokens,
                created_at=time.time(),
            )
            self._orchestrations[orch_id] = result
            logger.info("orchestration.complete", orch_id=orch_id, approved=approved, quality=qr.overall_score, elapsed_ms=elapsed)
            return result

    # ── Agent resolution ──────────────────────────────────────────────────────
    def _resolve_agents(self, intent: str) -> List[str]:
        """Map intent to ordered agent pipeline."""
        # Exact match first
        if intent in INTENT_ROUTING:
            return INTENT_ROUTING[intent]
        # Prefix match
        for key, agents in INTENT_ROUTING.items():
            if intent.startswith(key.split("_")[0]):
                return agents
        return []

    # ── Parallel + sequential execution ──────────────────────────────────────
    async def _execute_agents(
        self, agent_names: List[str], request: AgentRequest
    ) -> List[AgentResponse]:
        """
        First 2 agents run in parallel for speed.
        Subsequent agents run sequentially, receiving prior context.
        Quality gate runs after each batch.
        """
        responses: List[AgentResponse] = []

        # Parallel batch (first 2 agents)
        parallel = agent_names[:2]
        agents_parallel = [self.registry.get(n) for n in parallel if self.registry.get(n)]
        if agents_parallel:
            tasks = [a.process(request) for a in agents_parallel]
            batch = await asyncio.gather(*tasks, return_exceptions=True)
            for b in batch:
                if isinstance(b, AgentResponse):
                    responses.append(b)
                elif isinstance(b, Exception):
                    logger.error("agent.parallel_error", error=str(b))

        # Sequential remainder (enrichment agents get prior context)
        for name in agent_names[2:]:
            agent = self.registry.get(name)
            if not agent:
                continue
            enriched_request = request.model_copy(update={
                "context": {
                    **request.context,
                    "prior_results": [r.result for r in responses],
                }
            })
            try:
                resp = await agent.process(enriched_request)
                responses.append(enriched_request)
                responses.append(resp)
            except Exception as e:
                logger.error("agent.sequential_error", agent=name, error=str(e))

        return responses

    # ── Quality gate ──────────────────────────────────────────────────────────
    async def _apply_quality_gate(
        self, responses: List[AgentResponse], request: AgentRequest
    ) -> Tuple[bool, QualityReport]:
        """Run QualityGate over all agent responses."""
        if not responses:
            from .quality_gate import QualityReport
            return False, QualityReport(
                approved=False, accuracy=0, security=0,
                completeness=0, compliance=0, confidence=0,
                reason="No agent responses",
            )
        return await self.quality_gate.evaluate(responses, request)

    # ── Synthesize ────────────────────────────────────────────────────────────
    def _synthesize(
        self, responses: List[AgentResponse], request: AgentRequest
    ) -> Dict[str, Any]:
        """Merge agent results into a unified response."""
        merged: Dict[str, Any] = {"intent": request.intent, "agents": []}
        for resp in responses:
            merged["agents"].append({
                "agent": resp.agent_name,
                "status": resp.status.value,
                "result": resp.result,
                "confidence": resp.confidence,
            })
        # Primary result = first successful agent
        for resp in responses:
            if resp.status == AgentStatus.SUCCESS:
                merged.update(resp.result)
                break
        return merged

    # ── Diagnostics ───────────────────────────────────────────────────────────
    def get_diagnostics(self) -> Dict[str, Any]:
        """Return orchestrator runtime diagnostics."""
        return {
            "registered_agents": self.registry.count(),
            "supported_intents": list(INTENT_ROUTING.keys()),
            "parallel_groups": list(PARALLEL_GROUPS.keys()),
        }
  approved, elapsed_ms, created_at)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
                """, orch_id, tenant_id, user_id, intent,
                    ",".join(agents), qr.overall_score, approved, elapsed_ms)
        except Exception as e:
            logger.error("orchestrator.audit_persist_error", error=str(e))

    def _build_rejected_result(self, orch_id: str, intent: str, reason: str, start_ms: float) -> OrchestrationResult:
        return OrchestrationResult(
            orchestration_id=orch_id, request_id=str(uuid.uuid4()),
            intent=intent, agents_invoked=[],
            agent_responses=[],
            final_response={"error": "Policy rejected", "reason": reason, "upgrade_url": "https://cyberdudebivash.in/#pricing"},
            quality_report={"overall_score": 0, "approved": False},
            approved=False, total_time_ms=time.monotonic() * 1000 - start_ms,
            tokens_used=0, created_at=time.time(),
        )

    def get_orchestration(self, orch_id: str) -> Optional[OrchestrationResult]:
        return self._orchestrations.get(orch_id)

    async def health(self) -> Dict[str, Any]:
        return {
            "status": "operational",
            "agents_registered": len(self.registry),
            "total_orchestrations": len(self._orchestrations),
            "supported_intents": list(INTENT_ROUTING.keys()),
        }
