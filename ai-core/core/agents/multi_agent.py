# ============================================================
# CYBERDUDEBIVASH AI — MULTI-AGENT SWARM SYSTEM
# ============================================================

import time
import concurrent.futures
from typing import Any, Dict, List, Optional
from core.agents.base_agent import BaseAgent
from core.logging_config import get_logger

logger = get_logger("agent.swarm")


class MultiAgentSwarm:
    """
    Adaptive swarm controller.
    Agents are scored by success rate and prioritized accordingly.
    Fix #18: Real agent coordination — not clones.
    """

    def __init__(self, agents: List[BaseAgent], parallel: bool = False):
        self.agents = agents
        self.parallel = parallel

    def _rank_agents(self) -> List[BaseAgent]:
        return sorted(self.agents, key=lambda a: a.score, reverse=True)

    def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        ranked = self._rank_agents()
        results = []

        if self.parallel:
            results = self._run_parallel(ranked, task)
        else:
            results = self._run_sequential(ranked, task)

        return self._aggregate(results)

    def _run_sequential(self, agents: List[BaseAgent], task: Dict) -> List[Dict]:
        results = []
        for agent in agents:
            result = agent.execute(task)
            results.append(result)
        return results

    def _run_parallel(self, agents: List[BaseAgent], task: Dict) -> List[Dict]:
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(agents)) as executor:
            futures = {executor.submit(agent.execute, task): agent for agent in agents}
            for future in concurrent.futures.as_completed(futures, timeout=120):
                try:
                    results.append(future.result())
                except Exception as e:
                    agent = futures[future]
                    logger.error(f"[Swarm] Agent {agent.name} parallel failure: {e}")
                    results.append({"agent": agent.name, "status": "error", "error": str(e)})
        return results

    def _aggregate(self, results: List[Dict]) -> Dict[str, Any]:
        success = [r for r in results if r.get("status") == "success"]
        failed = [r for r in results if r.get("status") != "success"]
        return {
            "status": "completed",
            "total_agents": len(results),
            "successful": len(success),
            "failed": len(failed),
            "results": results,
        }
