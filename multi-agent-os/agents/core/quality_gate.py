"""
CYBERDUDEBIVASH® Multi-Agent Cybersecurity OS
Quality Gate — 5-dimension scoring enforced at ≥95/100
No response is approved below threshold.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    import structlog
    logger = structlog.get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

from pydantic import BaseModel, Field

# ─── Quality Report ────────────────────────────────────────────────────────────
class DimensionScore(BaseModel):
    name:    str
    score:   float = Field(ge=0, le=100)
    weight:  float = Field(ge=0, le=1)
    reasons: List[str] = Field(default_factory=list)

class QualityReport(BaseModel):
    accuracy_score:       float
    security_score:       float
    completeness_score:   float
    compliance_score:     float
    confidence_score:     float
    overall_score:        float
    hallucination_detected: bool
    hallucination_risk:   float
    approved:             bool
    fail_reasons:         List[str] = Field(default_factory=list)
    upgrade_triggers:     List[str] = Field(default_factory=list)
    evaluated_at:         float     = Field(default_factory=time.time)

    @property
    def passes(self) -> bool:
        return self.overall_score >= 95.0 and not self.hallucination_detected

# ─── Scoring rubrics per content type ─────────────────────────────────────────
THREAT_INTEL_REQUIRED_KEYS = {"ioc", "severity", "confidence", "ttps", "mitre_ids", "recommendation"}
COMPLIANCE_REQUIRED_KEYS   = {"framework", "controls", "gaps", "risk_score"}
SOC_REQUIRED_KEYS          = {"alert_id", "severity", "triage", "recommended_action"}
EXECUTIVE_REQUIRED_KEYS    = {"summary", "risk_level", "top_risks", "recommendations"}
AI_SECURITY_REQUIRED_KEYS  = {"vulnerability_type", "severity", "attack_vector", "remediation"}

INTENT_REQUIRED_KEYS: Dict[str, set] = {
    "analyze_ioc":          THREAT_INTEL_REQUIRED_KEYS,
    "lookup_cve":           {"cve_id", "severity", "cvss_score", "affected_systems", "remediation"},
    "analyze_malware":      {"malware_family", "ttps", "indicators", "mitre_ids"},
    "analyze_alert":        SOC_REQUIRED_KEYS,
    "compliance_check":     COMPLIANCE_REQUIRED_KEYS,
    "ciso_briefing":        EXECUTIVE_REQUIRED_KEYS,
    "board_report":         EXECUTIVE_REQUIRED_KEYS,
    "assess_prompt_injection": AI_SECURITY_REQUIRED_KEYS,
    "ai_red_team":          AI_SECURITY_REQUIRED_KEYS,
}

# Indicators of potential hallucination
HALLUCINATION_PATTERNS = [
    r"\bI don't know\b",
    r"\bI'm not sure\b",
    r"\bcould be\b.*\bor\b.*\bmaybe\b",
    r"\bprobably\b.*\bpossibly\b",
    r"\bsomething like\b",
    r"\bI believe\b.*\bbut not certain\b",
]

class QualityGate:
    """
    Evaluates agent responses across 5 weighted dimensions.
    Returns a QualityReport with pass/fail decision.
    """

    THRESHOLD = 95.0

    # Dimension weights must sum to 1.0
    WEIGHTS = {
        "accuracy":     0.30,
        "security":     0.25,
        "completeness": 0.20,
        "compliance":   0.15,
        "confidence":   0.10,
    }

    async def validate(
        self,
        response: Any,  # AgentResponse
        intent:   str,
        tier:     str = "FREE",
    ) -> QualityReport:
        """Validate a single AgentResponse."""
        from .base_agent import AgentResponse, AgentStatus  # local import to avoid circular

        if not isinstance(response, AgentResponse):
            return self._zero_report("Invalid response object")

        if response.status != AgentStatus.COMPLETED:
            return self._zero_report(f"Agent status: {response.status.value}")

        result = response.result or {}

        # Score each dimension
        acc  = self._score_accuracy(result, intent, response.reasoning_chain)
        sec  = self._score_security(result, response.agent_name)
        comp = self._score_completeness(result, intent, tier)
        cmpl = self._score_compliance(result, response.agent_name)
        conf = float(response.confidence_score)

        # Blend with agent-reported scores (50/50)
        acc  = (acc  + response.accuracy_score)     / 2
        sec  = (sec  + response.security_score)     / 2
        comp = (comp + response.completeness_score) / 2
        cmpl = (cmpl + response.compliance_score)   / 2

        overall = (
            acc  * self.WEIGHTS["accuracy"]     +
            sec  * self.WEIGHTS["security"]     +
            comp * self.WEIGHTS["completeness"] +
            cmpl * self.WEIGHTS["compliance"]   +
            conf * self.WEIGHTS["confidence"]
        )

        # Hallucination detection
        hall_detected, hall_risk = self._detect_hallucination(result, response.reasoning_chain)

        # Penalty for hallucination
        if hall_detected:
            overall = max(0.0, overall - 20.0)

        fail_reasons = []
        if acc  < self.THRESHOLD: fail_reasons.append(f"Accuracy {acc:.1f} < {self.THRESHOLD}")
        if sec  < self.THRESHOLD: fail_reasons.append(f"Security {sec:.1f} < {self.THRESHOLD}")
        if hall_detected:         fail_reasons.append("Hallucination detected in response")

        upgrade_triggers = self._compute_upgrade_triggers(result, tier, overall)

        return QualityReport(
            accuracy_score=round(acc, 2),
            security_score=round(sec, 2),
            completeness_score=round(comp, 2),
            compliance_score=round(cmpl, 2),
            confidence_score=round(conf, 2),
            overall_score=round(overall, 2),
            hallucination_detected=hall_detected,
            hallucination_risk=hall_risk,
            approved=overall >= self.THRESHOLD and not hall_detected,
            fail_reasons=fail_reasons,
            upgrade_triggers=upgrade_triggers,
        )

    async def validate_batch(
        self,
        responses: List[Any],
        intent:   str,
        tier:     str = "FREE",
    ) -> QualityReport:
        """Validate a batch — return aggregate quality report."""
        if not responses:
            return self._zero_report("No responses in batch")

        reports = [await self.validate(r, intent, tier) for r in responses]
        if not reports:
            return self._zero_report("No valid responses")

        # Weighted average by confidence score
        weights = [r.confidence_score for r in reports]
        total_w = sum(weights) or 1

        def wavg(attr):
            return sum(getattr(r, attr) * w for r, w in zip(reports, weights)) / total_w

        hall_any = any(r.hallucination_detected for r in reports)
        overall  = wavg("overall_score")
        if hall_any:
            overall = max(0.0, overall - 15.0)

        all_fails    = [f for r in reports for f in r.fail_reasons]
        all_triggers = list({t for r in reports for t in r.upgrade_triggers})

        return QualityReport(
            accuracy_score=round(wavg("accuracy_score"), 2),
            security_score=round(wavg("security_score"), 2),
            completeness_score=round(wavg("completeness_score"), 2),
            compliance_score=round(wavg("compliance_score"), 2),
            confidence_score=round(wavg("confidence_score"), 2),
            overall_score=round(overall, 2),
            hallucination_detected=hall_any,
            hallucination_risk=max(r.hallucination_risk for r in reports),
            approved=overall >= self.THRESHOLD and not hall_any,
            fail_reasons=all_fails[:10],
            upgrade_triggers=all_triggers[:5],
        )

    # ── Dimension scorers ─────────────────────────────────────────────────────
    def _score_accuracy(self, result: Dict, intent: str, reasoning: List[str]) -> float:
        score = 100.0
        required = INTENT_REQUIRED_KEYS.get(intent, set())
        if required:
            present = sum(1 for k in required if k in result or k in str(result).lower())
            ratio   = present / len(required)
            score   = 60.0 + ratio * 40.0  # 60 base, up to 100 with all keys
        # Deduct for error keys
        if "error" in result: score -= 20.0
        # Reward for reasoning chain
        if reasoning and len(reasoning) >= 3: score = min(100.0, score + 5.0)
        return max(0.0, score)

    def _score_security(self, result: Dict, agent_name: str) -> float:
        score = 95.0
        result_str = str(result).lower()
        # Penalize if sensitive data patterns appear in results
        sensitive_patterns = [r"\bpassword\s*=", r"\bsecret\s*=", r"\bapi_key\s*=", r"\btoken\s*=\s*[a-z0-9]{20,}"]
        for p in sensitive_patterns:
            if re.search(p, result_str):
                score -= 15.0
        # Penalize for injection patterns
        injection_patterns = [r"<script", r"javascript:", r"union select", r"exec\s*\("]
        for p in injection_patterns:
            if re.search(p, result_str, re.IGNORECASE):
                score -= 25.0
        return max(0.0, score)

    def _score_completeness(self, result: Dict, intent: str, tier: str) -> float:
        score = 70.0
        if not result: return 0.0
        # Structural completeness: more nested keys = more complete
        depth = self._dict_depth(result)
        score += min(20.0, depth * 5.0)
        # Sources attached
        if result.get("sources") or result.get("references"): score += 5.0
        # Recommendations present
        if result.get("recommendations") or result.get("remediation"): score += 5.0
        return min(100.0, score)

    def _score_compliance(self, result: Dict, agent_name: str) -> float:
        score = 90.0
        # Must include framework reference for compliance agents
        if "compliance" in agent_name.lower():
            if not result.get("framework") and not result.get("controls"):
                score -= 20.0
        # Must include MITRE refs for threat intel agents
        if "intel" in agent_name.lower() or "threat" in agent_name.lower():
            result_str = str(result)
            if "T" not in result_str and "mitre" not in result_str.lower():
                score -= 10.0
        return max(0.0, score)

    def _detect_hallucination(self, result: Dict, reasoning: List[str]) -> Tuple[bool, float]:
        text = str(result) + " ".join(reasoning or [])
        matches = sum(1 for p in HALLUCINATION_PATTERNS if re.search(p, text, re.IGNORECASE))
        risk = min(1.0, matches * 0.25)
        detected = matches >= 2 or risk >= 0.5
        return detected, risk

    def _compute_upgrade_triggers(self, result: Dict, tier: str, score: float) -> List[str]:
        triggers = []
        if tier == "FREE":
            triggers.append("Upgrade to PRO for full threat intelligence enrichment")
        if score < 80:
            triggers.append("Enterprise tier unlocks multi-agent cross-validation for higher accuracy")
        if result.get("_truncated"):
            triggers.append("Upgrade for complete report without content limits")
        return triggers

    def _dict_depth(self, d: Dict, depth: int = 0) -> int:
        if not isinstance(d, dict) or not d: return depth
        return max(self._dict_depth(v, depth + 1) for v in d.values())

    def _zero_report(self, reason: str) -> QualityReport:
        return QualityReport(
            accuracy_score=0, security_score=0, completeness_score=0,
            compliance_score=0, confidence_score=0, overall_score=0,
            hallucination_detected=False, hallucination_risk=0.0,
            approved=False, fail_reasons=[reason], upgrade_triggers=[],
        )
