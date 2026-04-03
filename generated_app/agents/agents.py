# ============================================================
# CYBERDUDEBIVASH AI — SWARM AGENTS (generated_app layer)
# Fix #18: Real distinct agents, not clones
# ============================================================

from core.agents.base_agent import BaseAgent
from core.router.router_manager import get_router
from typing import Any, Dict


class CodeAgent(BaseAgent):
    """Generates production-grade code via AI."""

    def __init__(self, name: str = "CodeAgent"):
        super().__init__(name=name, description="AI code generation specialist")
        self.router = get_router()

    def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        prompt = task.get("task", task.get("prompt", ""))
        code = self.router.generate_code(prompt)
        return {"generated_code": code, "language": "python"}


class SecurityAgent(BaseAgent):
    """Performs AI-powered security analysis."""

    def __init__(self, name: str = "SecurityAgent"):
        super().__init__(name=name, description="AI security analysis specialist")
        self.router = get_router()

    def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        target = task.get("target", task.get("task", ""))
        analysis = self.router.generate_cyber(
            f"Perform security analysis on: {target}\n"
            "Return findings with severity levels (CRITICAL/HIGH/MEDIUM/LOW)."
        )
        return {"security_analysis": analysis, "target": target}


class OptimizerAgent(BaseAgent):
    """Optimizes code and system performance."""

    def __init__(self, name: str = "OptimizerAgent"):
        super().__init__(name=name, description="Code and performance optimizer")
        self.router = get_router()

    def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        code = task.get("code", task.get("task", ""))
        optimized = self.router.generate_code(
            f"Optimize the following code for performance and best practices:\n{code}"
        )
        return {"optimized_code": optimized}
