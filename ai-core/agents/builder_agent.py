from core.router.router_manager import get_router
from core.agents.base_agent import BaseAgent
from typing import Any, Dict

class BuilderAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="BuilderAgent", description="Builds code and projects")
        self.router = get_router()

    def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        prompt = task.get("task", task.get("prompt", ""))
        code = self.router.generate_code(prompt)
        return {"generated_code": code}
