# ============================================================
# CYBERDUDEBIVASH AI — BASE AGENT
# ============================================================

import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from core.logging_config import get_logger


class BaseAgent(ABC):
    """Abstract base for all CyberDudeBivash agents."""

    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self.logger = get_logger(f"agent.{name}")
        self._success_count = 0
        self._fail_count = 0

    @abstractmethod
    def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute agent task. Must be implemented by subclass."""
        raise NotImplementedError

    def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Wrapper with timing, logging, and error handling."""
        start = time.time()
        self.logger.info(f"Agent [{self.name}] starting task")
        try:
            result = self.run(task)
            duration_ms = int((time.time() - start) * 1000)
            self._success_count += 1
            self.logger.info(f"Agent [{self.name}] completed in {duration_ms}ms")
            return {
                "agent": self.name,
                "status": "success",
                "duration_ms": duration_ms,
                "output": result,
            }
        except Exception as e:
            self._fail_count += 1
            self.logger.error(f"Agent [{self.name}] failed: {e}")
            return {
                "agent": self.name,
                "status": "error",
                "error": str(e),
                "output": None,
            }

    @property
    def score(self) -> float:
        total = self._success_count + self._fail_count
        return self._success_count / total if total > 0 else 0.5

    def health(self) -> Dict:
        return {
            "name": self.name,
            "description": self.description,
            "success": self._success_count,
            "failures": self._fail_count,
            "score": round(self.score, 3),
        }
