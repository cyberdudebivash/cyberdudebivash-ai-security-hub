# ============================================================
# CYBERDUDEBIVASH AI — SWARM CONTROLLER
# ============================================================

import json
import os
from typing import Any, Dict, List
from core.agents.base_agent import BaseAgent
from core.logging_config import get_logger

logger = get_logger("swarm")

FEEDBACK_FILE = os.path.join("memory", "agent_feedback.json")


def _load_feedback() -> Dict:
    os.makedirs("memory", exist_ok=True)
    if not os.path.exists(FEEDBACK_FILE):
        return {}
    with open(FEEDBACK_FILE, "r") as f:
        return json.load(f)


def _save_feedback(data: Dict) -> None:
    os.makedirs("memory", exist_ok=True)
    with open(FEEDBACK_FILE, "w") as f:
        json.dump(data, f, indent=2)


def _get_agent_score(name: str) -> float:
    data = _load_feedback()
    if name not in data:
        return 0.5
    s, f = data[name].get("success", 0), data[name].get("fail", 0)
    total = s + f
    return s / total if total > 0 else 0.5


def _update_score(name: str, success: bool) -> None:
    data = _load_feedback()
    if name not in data:
        data[name] = {"success": 0, "fail": 0}
    key = "success" if success else "fail"
    data[name][key] += 1
    _save_feedback(data)


class SwarmController:
    """Adaptive swarm controller with performance-based agent ranking."""

    def __init__(self):
        from generated_app.agents.agents import CodeAgent, SecurityAgent, OptimizerAgent
        self.agents: List[BaseAgent] = [
            CodeAgent("CodeAgent"),
            SecurityAgent("SecurityAgent"),
            OptimizerAgent("OptimizerAgent"),
        ]

    def _rank(self) -> List[BaseAgent]:
        return sorted(self.agents, key=lambda a: _get_agent_score(a.name), reverse=True)

    def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        ranked = self._rank()
        results = []

        for agent in ranked:
            try:
                result = agent.execute(task)
                _update_score(agent.name, True)
                results.append(result)
            except Exception as e:
                _update_score(agent.name, False)
                logger.error(f"[Swarm] Agent {agent.name} failed: {e}")
                results.append({"agent": agent.name, "status": "error", "error": str(e)})

        success_count = sum(1 for r in results if r.get("status") == "success")
        return {
            "status": "completed",
            "total_agents": len(results),
            "successful": success_count,
            "results": results,
        }
