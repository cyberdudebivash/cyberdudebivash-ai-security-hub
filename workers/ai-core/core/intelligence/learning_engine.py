# ============================================================
# CYBERDUDEBIVASH AI — LEARNING ENGINE
# Tracks task outcomes and improves agent routing over time
# ============================================================

import json
import os
from datetime import datetime, timezone
from typing import Dict, List

LEARNING_FILE = os.path.join("memory", "learning_data.json")


class LearningEngine:
    """Records task outcomes and derives routing improvements."""

    def __init__(self, path: str = LEARNING_FILE):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def record(self, task: str, agent: str, success: bool, duration_ms: int) -> None:
        data = self._load()
        data.append({
            "task_snippet": task[:80],
            "agent": agent,
            "success": success,
            "duration_ms": duration_ms,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        # Keep last 1000
        self._write(data[-1000:])

    def best_agent_for(self, task: str) -> str:
        """Return the historically best-performing agent for a task keyword."""
        data = self._load()
        task_lower = task.lower()
        scores: Dict[str, Dict] = {}

        for record in data:
            snippet = record.get("task_snippet", "").lower()
            agent = record.get("agent", "")
            # Simple keyword overlap scoring
            if any(w in snippet for w in task_lower.split()):
                if agent not in scores:
                    scores[agent] = {"success": 0, "total": 0}
                scores[agent]["total"] += 1
                if record.get("success"):
                    scores[agent]["success"] += 1

        if not scores:
            return ""

        best = max(scores, key=lambda a: scores[a]["success"] / max(scores[a]["total"], 1))
        return best

    def summary(self) -> Dict:
        data = self._load()
        agents: Dict[str, Dict] = {}
        for r in data:
            a = r.get("agent", "unknown")
            if a not in agents:
                agents[a] = {"total": 0, "success": 0}
            agents[a]["total"] += 1
            if r.get("success"):
                agents[a]["success"] += 1
        return {
            "total_records": len(data),
            "agents": {
                a: {
                    "total": v["total"],
                    "success_rate": round(v["success"] / max(v["total"], 1), 3),
                }
                for a, v in agents.items()
            },
        }

    def _load(self) -> List[Dict]:
        if not os.path.exists(self.path):
            return []
        try:
            with open(self.path) as f:
                return json.load(f)
        except Exception:
            return []

    def _write(self, data: List[Dict]) -> None:
        with open(self.path, "w") as f:
            json.dump(data, f, indent=2, default=str)
