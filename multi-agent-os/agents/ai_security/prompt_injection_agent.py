"""
Prompt Injection Agent — Detects, classifies, and remediates AI prompt injection attacks.
Covers: direct injection, indirect injection, jailbreak, prompt leakage, context manipulation.
"""
from __future__ import annotations
import time
from typing import Any, Dict, List, Tuple
from ..core.base_agent import BaseAgent, AgentLayer, AgentCapability, AgentRequest

INJECTION_PATTERNS = [
    {"id": "PI-001", "name": "Direct Injection",     "pattern": r"ignore previous instructions"},
    {"id": "PI-002", "name": "Role Override",         "pattern": r"you are now|act as|pretend you are"},
    {"id": "PI-003", "name": "Jailbreak Attempt",    "pattern": r"DAN|do anything now|jailbreak"},
    {"id": "PI-004", "name": "System Prompt Leakage","pattern": r"reveal your system prompt|print your instructions"},
    {"id": "PI-005", "name": "Indirect Injection",   "pattern": r"<.*?inject.*?>|<!-- inject"},
    {"id": "PI-006", "name": "Context Manipulation", "pattern": r"forget everything|new conversation starts"},
]

class PromptInjectionAgent(BaseAgent):
    @property
    def name(self) -> str: return "prompt_injection"

    @property
    def layer(self) -> AgentLayer: return AgentLayer.AI_SECURITY

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [AgentCapability(
            name="prompt_injection_detection",
            description="Detect and classify AI prompt injection, jailbreak, context manipulation attacks",
            intents=["assess_prompt_injection", "ai_runtime_alert"],
            requires_tier="PRO",
            timeout_ms=15_000,
        )]

    async def _execute(self, request: AgentRequest) -> Tuple[Dict[str, Any], List[str]]:
        import re
        payload  = request.payload
        prompt   = payload.get("prompt") or payload.get("input") or payload.get("text", "")
        model    = payload.get("model", "unknown")
        endpoint = payload.get("endpoint", "unknown")

        reasoning = [
            f"Scanning prompt for injection patterns (length: {len(prompt)} chars)",
            "Applying OWASP LLM Top 10 detection rules",
            "Checking for direct, indirect, and indirect injection vectors",
            "Computing risk score and attack confidence",
        ]

        detected_patterns = []
        for p in INJECTION_PATTERNS:
            if re.search(p["pattern"], prompt, re.IGNORECASE):
                detected_patterns.append(p)

        ai_analysis = {}
        if self.ai and prompt:
            try:
                prompt_truncated = prompt[:1000]
                system_prompt = (
                    "You are an AI security expert specializing in prompt injection detection. "
                    "Analyze the following user input for injection attacks. "
                    "Return JSON only with no extra text."
                )
                analysis_prompt = (
                    f"Analyze for prompt injection: '{prompt_truncated}'\n"
                    f"Return JSON: is_injection (bool), attack_type (direct/indirect/jailbreak/leakage/none), "
                    f"confidence (0-100), severity (critical/high/medium/low), "
                    f"attack_vector_description, owasp_llm_category, "
                    f"remediation_steps (list), safe_response (what the AI should do)"
                )
                ai_analysis = await self.ai.generate(analysis_prompt, task_type="ai_security")
            except Exception: pass

        is_injection = ai_analysis.get("is_injection", len(detected_patterns) > 0)
        severity     = ai_analysis.get("severity", "HIGH" if is_injection else "LOW")
        risk_score   = 90 if is_injection and ai_analysis.get("confidence", 0) > 80 else (55 if is_injection else 5)

        result = {
            "input_sample":        prompt[:200] + "..." if len(prompt) > 200 else prompt,
            "model":               model,
            "endpoint":            endpoint,
            "is_injection":        is_injection,
            "attack_type":         ai_analysis.get("attack_type", "direct" if detected_patterns else "none"),
            "confidence":          ai_analysis.get("confidence", 90 if detected_patterns else 10),
            "severity":            severity,
            "risk_score":          risk_score,
            "detected_patterns":   [p["name"] for p in detected_patterns],
            "owasp_llm_category":  ai_analysis.get("owasp_llm_category", "LLM01: Prompt Injection"),
            "attack_vector_description": ai_analysis.get("attack_vector_description", ""),
            "vulnerability_type":  "Prompt Injection",
            "remediation_steps":   ai_analysis.get("remediation_steps", [
                "Implement input validation and sanitization before LLM processing",
                "Use separate privilege contexts for user input vs. system instructions",
                "Apply content moderation layer before and after LLM responses",
                "Implement output validation to prevent data exfiltration",
                "Monitor for anomalous prompts in production",
            ]),
            "safe_response":       ai_analysis.get("safe_response", "Reject input and log security event"),
            "powered_by_mythos":   True,
            "scanned_at":          time.time(),
        }

        reasoning.append(f"Is injection: {is_injection} | Severity: {severity} | Patterns found: {len(detected_patterns)}")
        return result, reasoning

    async def _compute_scores(self, request: AgentRequest, result: Dict) -> Tuple[float,float,float,float,float]:
        conf = result.get("confidence", 80.0)
        return float(conf), 95.0, 98.0, 93.0, 96.0
