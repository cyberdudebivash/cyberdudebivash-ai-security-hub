"""
CYBERDUDEBIVASH® Multi-Agent Cybersecurity OS
Agent Registry — Dynamic registration, capability discovery, health tracking.
All agents self-register at startup. Orchestrator queries registry by name or intent.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, Iterator, List, Optional, Type

import structlog
from pydantic import BaseModel

from .base_agent import AgentLayer, BaseAgent

logger = structlog.get_logger(__name__)

class AgentRecord(BaseModel):
    agent_id:       str
    name:           str
    layer:          AgentLayer
    intents:        List[str]
    status:         str = "healthy"
    registered_at:  float
    last_health_at: float = 0.0
    request_count:  int = 0
    error_rate:     float = 0.0
    avg_quality:    float = 0.0
    requires_tier:  str = "FREE"

class AgentRegistry:
    """
    Central registry for all CYBERDUDEBIVASH® specialist agents.
    Supports registration, lookup by name/intent/layer, and live health monitoring.
    """

    def __init__(self, redis_client: Any = None):
        self._agents:  Dict[str, BaseAgent]   = {}   # name → agent instance
        self._records: Dict[str, AgentRecord] = {}   # name → metadata
        self.redis = redis_client
        self._health_task: Optional[asyncio.Task] = None

    # ── Registration ──────────────────────────────────────────────────────────
    def register(self, agent: BaseAgent) -> None:
        name = agent.name
        if name in self._agents:
            logger.warning("registry.duplicate", name=name)
        self._agents[name] = agent

        intents = []
        for cap in agent.capabilities:
            intents.extend(cap.intents)

        self._records[name] = AgentRecord(
            agent_id=agent.agent_id,
            name=name,
            layer=agent.layer,
            intents=list(set(intents)),
            registered_at=time.time(),
        )
        logger.info("registry.registered", name=name, layer=agent.layer.value, intents=len(intents))

    def register_all(self, agents: List[BaseAgent]) -> None:
        for a in agents:
            self.register(a)
        logger.info("registry.bulk_register", count=len(agents), total=len(self._agents))

    # ── Lookup ────────────────────────────────────────────────────────────────
    def get(self, name: str) -> Optional[BaseAgent]:
        return self._agents.get(name)

    def get_by_intent(self, intent: str) -> List[BaseAgent]:
        """Return all agents that handle a given intent."""
        result = []
        for name, record in self._records.items():
            if intent in record.intents:
                agent = self._agents.get(name)
                if agent:
                    result.append(agent)
        return result

    def get_by_layer(self, layer: AgentLayer) -> List[BaseAgent]:
        return [
            self._agents[name]
            for name, rec in self._records.items()
            if rec.layer == layer and name in self._agents
        ]

    def get_healthy(self) -> List[BaseAgent]:
        return [
            self._agents[name]
            for name, rec in self._records.items()
            if rec.status == "healthy" and name in self._agents
        ]

    def best_for_intent(self, intent: str) -> Optional[BaseAgent]:
        """Return healthiest/highest-quality agent for an intent."""
        candidates = self.get_by_intent(intent)
        if not candidates:
            return None
        # Sort by avg_quality desc, then error_rate asc
        def score(a: BaseAgent) -> float:
            rec = self._records.get(a.name)
            if not rec: return 0.0
            return rec.avg_quality - rec.error_rate * 20
        return max(candidates, key=score)

    # ── Health monitoring ─────────────────────────────────────────────────────
    async def start_health_monitor(self, interval_sec: int = 30) -> None:
        self._health_task = asyncio.create_task(
            self._health_loop(interval_sec),
            name="agent_health_monitor"
        )
        logger.info("registry.health_monitor_started", interval=interval_sec)

    async def _health_loop(self, interval_sec: int) -> None:
        while True:
            await asyncio.sleep(interval_sec)
            for name, agent in list(self._agents.items()):
                try:
                    h = agent.health()
                    rec = self._records.get(name)
                    if rec:
                        rec.last_health_at = time.time()
                        rec.request_count  = h.get("total_requests", 0)
                        rec.error_rate     = h.get("error_rate", 0.0)
                        rec.status         = "healthy" if h.get("error_rate", 0) < 0.1 else "degraded"
                    if self.redis:
                        await self.redis.hset(
                            f"agent:health:{name}",
                            mapping={
                                "status":        rec.status if rec else "unknown",
                                "error_rate":    str(h.get("error_rate", 0)),
                                "request_count": str(h.get("total_requests", 0)),
                                "ts":            str(time.time()),
                            }
                        )
                        await self.redis.expire(f"agent:health:{name}", 120)
                except Exception as e:
                    logger.error("registry.health_check_error", name=name, error=str(e))
                    rec = self._records.get(name)
                    if rec:
                        rec.status = "unhealthy"

    def update_quality(self, agent_name: str, quality: float) -> None:
        rec = self._records.get(agent_name)
        if rec:
            # Rolling average (EMA)
            if rec.avg_quality == 0:
                rec.avg_quality = quality
            else:
                rec.avg_quality = 0.9 * rec.avg_quality + 0.1 * quality

    # ── Introspection ─────────────────────────────────────────────────────────
    def __len__(self) -> int:
        return len(self._agents)

    def __iter__(self) -> Iterator[BaseAgent]:
        return iter(self._agents.values())

    def list_all(self) -> List[Dict[str, Any]]:
        return [rec.model_dump() for rec in self._records.values()]

    def summary(self) -> Dict[str, Any]:
        total   = len(self._agents)
        healthy = sum(1 for r in self._records.values() if r.status == "healthy")
        by_layer: Dict[str, int] = {}
        for rec in self._records.values():
            by_layer[rec.layer.value] = by_layer.get(rec.layer.value, 0) + 1
        return {
            "total_agents":   total,
            "healthy_agents": healthy,
            "degraded":       total - healthy,
            "by_layer":       by_layer,
            "all_intents":    sorted({i for r in self._records.values() for i in r.intents}),
        }
