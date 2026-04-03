# ============================================================
# CYBERDUDEBIVASH AI — PROMPT OPTIMIZER
# ============================================================

from typing import List, Dict


class PromptOptimizer:
    """Enhances prompts with memory context and best-practice structure."""

    CYBER_PREFIXES = {
        "threat": "You are an expert threat intelligence analyst. ",
        "vuln": "You are a senior vulnerability researcher. ",
        "malware": "You are a malware reverse-engineering specialist. ",
        "osint": "You are a professional OSINT investigator. ",
        "audit": "You are a certified application security engineer. ",
    }

    def optimize(self, task: str, memory_hits: List[Dict] = None) -> str:
        """Build an optimized prompt from task + memory context."""
        context_block = ""
        if memory_hits:
            lines = [f"  - [{h.get('timestamp','')[:10]}] {h.get('task','')}" for h in memory_hits[-3:]]
            context_block = "Previous related work:\n" + "\n".join(lines) + "\n\n"

        prefix = ""
        task_lower = task.lower()
        for key, val in self.CYBER_PREFIXES.items():
            if key in task_lower:
                prefix = val
                break

        return f"{prefix}{context_block}Current task:\n{task}\n\nProvide production-grade, actionable output."
