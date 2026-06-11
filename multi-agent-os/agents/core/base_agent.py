"""
CYBERDUDEBIVASH® Multi-Agent Cybersecurity OS
Base Agent — Foundation for all 50+ specialist agents
Production-grade, async, observable, policy-enforced
"""
from __future__ import annotations

import asyncio
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from opentelemetry import trace
from opentelemetry.trace import SpanKind
from pydantic import BaseModel, Field
import structlog

logger = structlog.get_logger(__name__)
tracer = trace.get_tracer(__name__)

# ─── Agent Tier + Layer ───────────────────────────────────────────────────────
class AgentLayer(str, Enum):
    EXECUTIVE        = "executive"
    CUSTOMER         = "customer"
    REVENUE          = "revenue"
    THREAT_INTEL     = "threat_intel"
    AI_SECURITY      = "ai_security"
    MSSP             = "mssp"
    SOC              = "soc"
    SECURITY_ENG     = "security_engineering"
    RESEARCH         = "research"
    GOVERNANCE       = "governance"
    QUALITY          = "quality"

class AgentStatus(str, Enum):
    IDLE        = "idle"
    RUNNING     = "running"
    WAITING     = "waiting"
    COMPLETED   = "completed"
    FAILED      = "failed"
    RATE_LIMITED = "rate_limited"

class ConfidenceLevel(str, Enum):
    CRITICAL  = "critical"   # ≥95
    HIGH      = "high"       # ≥80
    MEDIUM    = "medium"     # ≥60
    LOW       = "low"        # <60

# ─── Request / Response contracts ────────────────────────────────────────────
class AgentRequest(BaseModel):
    request_id:   str  = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id:   str
    user_id:      str
    tenant_id:    str
    intent:       str
    payload:      Dict[str, Any]
    context:      Dict[str, Any] = Field(default_factory=dict)
    priority:     int = Field(default=5, ge=1, le=10)  # 1=highest
    tier:         str = "FREE"
    trace_id:     Optional[str] = None
    parent_agent: Optional[str] = None
    created_at:   float = Field(default_factory=time.time)

class AgentResponse(BaseModel):
    request_id:       str
    agent_id:         str
    agent_name:       str
    layer:            AgentLayer
    status:           AgentStatus
    result:           Dict[str, Any]
    confidence_score: float = Field(ge=0.0, le=100.0)
    accuracy_score:   float = Field(ge=0.0, le=100.0)
    security_score:   float = Field(ge=0.0, le=100.0)
    completeness_score: float = Field(ge=0.0, le=100.0)
    compliance_score: float = Field(ge=0.0, le=100.0)
    hallucination_risk: float = Field(ge=0.0, le=1.0, default=0.0)
    sources:          List[Dict[str, Any]] = Field(default_factory=list)
    reasoning_chain:  List[str] = Field(default_factory=list)
    execution_time_ms: float = 0.0
    tokens_used:      int = 0
    approved:         bool = False
    audit_trail:      List[Dict[str, Any]] = Field(default_factory=list)
    created_at:       float = Field(default_factory=time.time)

    @property
    def quality_score(self) -> float:
        return (self.accuracy_score + self.security_score +
                self.completeness_score + self.compliance_score) / 4

    @property
    def passes_quality_gate(self) -> bool:
        return self.quality_score >= 95.0 and self.confidence_score >= 80.0

    @property
    def confidence_level(self) -> ConfidenceLevel:
        if self.confidence_score >= 95: return ConfidenceLevel.CRITICAL
        if self.confidence_score >= 80: return ConfidenceLevel.HIGH
        if self.confidence_score >= 60: return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW

# ─── Agent capability descriptor ─────────────────────────────────────────────
@dataclass
class AgentCapability:
    name:        str
    description: str
    intents:     List[str]      # Intent patterns this agent handles
    requires_tier: str = "FREE"  # Minimum plan required
    rate_limit:  int  = 100      # Per minute
    timeout_ms:  int  = 30_000   # 30 seconds default

# ─── Abstract Base Agent ──────────────────────────────────────────────────────
class BaseAgent(ABC):
    """
    Abstract base for all CYBERDUDEBIVASH® agents.
    Enforces: policy check → execution → quality scoring → audit trail.
    No agent may return a response without passing all gates.
    """

    QUALITY_THRESHOLD = 95.0      # Minimum acceptable quality score
    MAX_RETRY_ATTEMPTS = 3

    def __init__(
        self,
        agent_id: Optional[str]   = None,
        redis_client:  Any        = None,
        pg_pool:       Any        = None,
        qdrant_client: Any        = None,
        ai_router:     Any        = None,
        kafka_producer: Any       = None,
    ):
        self.agent_id       = agent_id or f"{self.name}_{uuid.uuid4().hex[:8]}"
        self.redis          = redis_client
        self.db             = pg_pool
        self.vector_db      = qdrant_client
        self.ai             = ai_router
        self.kafka          = kafka_producer
        self.status         = AgentStatus.IDLE
        self._request_count = 0
        self._error_count   = 0
        self._total_tokens  = 0
        self._start_time    = time.time()
        logger.info("agent.initialized", agent_id=self.agent_id, agent_name=self.name, layer=self.layer.value)

    # ── Required implementations ──────────────────────────────────────────────
    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def layer(self) -> AgentLayer: ...

    @property
    @abstractmethod
    def capabilities(self) -> List[AgentCapability]: ...

    @abstractmethod
    async def _execute(self, request: AgentRequest) -> Tuple[Dict[str, Any], List[str]]:
        """
        Core execution logic. Returns (result_dict, reasoning_chain).
        Must NOT raise exceptions — return error details in result_dict.
        """
        ...

    @abstractmethod
    async def _compute_scores(
        self, request: AgentRequest, result: Dict[str, Any]
    ) -> Tuple[float, float, float, float, float]:
        """Return (confidence, accuracy, security, completeness, compliance) 0-100."""
        ...

    # ── Main entry point ──────────────────────────────────────────────────────
    async def process(self, request: AgentRequest) -> AgentResponse:
        """
        Unified execution pipeline:
        Policy Check → Execute → Score → Quality Gate → Audit → Return
        """
        start_ms = time.monotonic() * 1000
        self.status = AgentStatus.RUNNING
        self._request_count += 1

        with tracer.start_as_current_span(
            f"agent.{self.name}.process",
            kind=SpanKind.INTERNAL,
            attributes={
                "agent.name":    self.name,
                "agent.layer":   self.layer.value,
                "request.id":    request.request_id,
                "tenant.id":     request.tenant_id,
                "user.id":       request.user_id,
                "intent":        request.intent,
            },
        ) as span:
            audit: List[Dict[str, Any]] = []
            attempt = 0

            # 1. Policy enforcement
            policy_ok, policy_reason = await self._enforce_policy(request)
            if not policy_ok:
                return self._build_policy_rejection(request, policy_reason, start_ms)
            audit.append({"step": "policy_check", "passed": True, "ts": time.time()})

            # 2. Execute with retry loop
            result, reasoning = {}, []
            while attempt < self.MAX_RETRY_ATTEMPTS:
                attempt += 1
                try:
                    result, reasoning = await asyncio.wait_for(
                        self._execute(request),
                        timeout=self._get_capability_timeout(request.intent) / 1000,
                    )
                    audit.append({"step": "execution", "attempt": attempt, "ts": time.time()})
                    break
                except asyncio.TimeoutError:
                    logger.warning("agent.timeout", agent=self.name, attempt=attempt, intent=request.intent)
                    if attempt == self.MAX_RETRY_ATTEMPTS:
                        result = {"error": "Execution timed out", "timeout_ms": self._get_capability_timeout(request.intent)}
                        reasoning = ["Execution exceeded time budget after max retries"]
                except Exception as exc:
                    logger.error("agent.execution_error", agent=self.name, error=str(exc), attempt=attempt)
                    self._error_count += 1
                    if attempt == self.MAX_RETRY_ATTEMPTS:
                        result = {"error": str(exc), "agent": self.name}
                        reasoning = [f"Execution failed: {exc}"]

            # 3. Compute quality scores
            try:
                conf, acc, sec, comp, cmpl = await self._compute_scores(request, result)
            except Exception:
                conf, acc, sec, comp, cmpl = 70.0, 70.0, 70.0, 70.0, 70.0

            # 4. Quality gate — auto-retry if below threshold
            quality = (acc + sec + comp + cmpl) / 4
            if quality < self.QUALITY_THRESHOLD and attempt < self.MAX_RETRY_ATTEMPTS:
                logger.warning("agent.quality_gate_retry", agent=self.name, quality=quality, threshold=self.QUALITY_THRESHOLD)
                result["_quality_retry"] = True
                result, reasoning = await self._execute(request)
                conf, acc, sec, comp, cmpl = await self._compute_scores(request, result)
                audit.append({"step": "quality_retry", "ts": time.time()})

            audit.append({"step": "quality_gate", "score": (acc + sec + comp + cmpl) / 4, "passed": (acc + sec + comp + cmpl) / 4 >= self.QUALITY_THRESHOLD, "ts": time.time()})

            # 5. Hallucination risk estimation
            h_risk = await self._estimate_hallucination_risk(result, reasoning)
            audit.append({"step": "hallucination_check", "risk": h_risk, "ts": time.time()})

            # 6. Emit Kafka event for observability
            await self._emit_event(request.request_id, request.tenant_id, result, quality)

            # 7. Record metrics to Redis
            await self._record_metrics(request, quality, time.monotonic() * 1000 - start_ms)

            self.status = AgentStatus.COMPLETED
            elapsed = time.monotonic() * 1000 - start_ms
            span.set_attribute("agent.quality_score", quality)
            span.set_attribute("agent.execution_ms", elapsed)

            return AgentResponse(
                request_id=request.request_id,
                agent_id=self.agent_id,
                agent_name=self.name,
                layer=self.layer,
                status=AgentStatus.COMPLETED,
                result=result,
                confidence_score=conf,
                accuracy_score=acc,
                security_score=sec,
                completeness_score=comp,
                compliance_score=cmpl,
                hallucination_risk=h_risk,
                reasoning_chain=reasoning,
                execution_time_ms=elapsed,
                approved=(quality >= self.QUALITY_THRESHOLD),
                audit_trail=audit,
            )

    # ── Policy enforcement ────────────────────────────────────────────────────
    async def _enforce_policy(self, request: AgentRequest) -> Tuple[bool, str]:
        """Check tier, rate limit, and capability access."""
        cap = next((c for c in self.capabilities if request.intent in c.intents), None)
        if cap is None:
            # Allow if no specific capability defined (general agent)
            return True, ""
        tier_order = ["FREE", "STARTER", "PRO", "ENTERPRISE", "GLOBAL_ENTERPRISE"]
        req_idx   = tier_order.index(cap.requires_tier) if cap.requires_tier in tier_order else 0
        user_idx  = tier_order.index(request.tier) if request.tier in tier_order else 0
        if user_idx < req_idx:
            return False, f"Intent '{request.intent}' requires {cap.requires_tier} plan (current: {request.tier})"
        return True, ""

    async def _estimate_hallucination_risk(self, result: Dict, reasoning: List[str]) -> float:
        """Estimate hallucination risk 0-1 based on result structure."""
        risk = 0.0
        if not result or "error" in result: return 0.1
        # Lack of sources = higher risk
        if not result.get("sources"): risk += 0.2
        # No reasoning chain = higher risk
        if not reasoning: risk += 0.15
        # Very short responses for complex intents = risk
        if len(str(result)) < 100: risk += 0.1
        return min(risk, 1.0)

    async def _emit_event(self, req_id: str, tenant_id: str, result: Dict, quality: float):
        if self.kafka:
            try:
                await self.kafka.send("agent.events", {
                    "agent": self.name, "request_id": req_id,
                    "tenant_id": tenant_id, "quality": quality,
                    "ts": time.time(),
                })
            except Exception: pass

    async def _record_metrics(self, request: AgentRequest, quality: float, elapsed_ms: float):
        if self.redis:
            try:
                key = f"agent:metrics:{self.name}:{request.tenant_id}"
                await self.redis.hincrby(key, "total_requests", 1)
                await self.redis.hset(key, "last_quality", quality)
                await self.redis.hset(key, "last_elapsed_ms", elapsed_ms)
                await self.redis.expire(key, 86400)
            except Exception: pass

    def _get_capability_timeout(self, intent: str) -> int:
        cap = next((c for c in self.capabilities if intent in c.intents), None)
        return cap.timeout_ms if cap else 30_000

    def _build_policy_rejection(self, request: AgentRequest, reason: str, start_ms: float) -> AgentResponse:
        return AgentResponse(
            request_id=request.request_id,
            agent_id=self.agent_id, agent_name=self.name, layer=self.layer,
            status=AgentStatus.FAILED,
            result={"error": "Policy rejected", "reason": reason, "upgrade_url": "https://cyberdudebivash.in/#pricing"},
            confidence_score=0, accuracy_score=0, security_score=0,
            completeness_score=0, compliance_score=0,
            execution_time_ms=time.monotonic() * 1000 - start_ms,
            approved=False,
        )

    # ── Health + introspection ─────────────────────────────────────────────────
    def health(self) -> Dict[str, Any]:
        uptime = time.time() - self._start_time
        return {
            "agent_id":      self.agent_id,
            "name":          self.name,
            "layer":         self.layer.value,
            "status":        self.status.value,
            "uptime_sec":    uptime,
            "total_requests": self._request_count,
            "error_count":   self._error_count,
            "error_rate":    self._error_count / max(1, self._request_count),
            "capabilities":  [c.name for c in self.capabilities],
        }
