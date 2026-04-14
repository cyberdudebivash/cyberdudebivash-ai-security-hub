# ============================================================
# CYBERDUDEBIVASH AI — CYBERSECURITY AGENTS (PRODUCTION HARDENED)
# All 5 agents: input validation, structured fallbacks,
# safe JSON parsing, timeout-aware
# ============================================================

import json
import re
import socket
import time
from typing import Any, Dict
from core.agents.base_agent import BaseAgent
from core.ai_super_router.router import get_super_router as get_router
from core.logging_config import get_logger

logger = get_logger("agents.cyber")

MAX_TARGET_LEN = 500
MAX_CODE_LEN = 50_000


def _safe_parse_json(raw: str, fallback: Dict) -> Dict:
    """Robustly extract JSON from AI response, with fallback."""
    if not raw:
        return fallback
    # Strip markdown code fences
    clean = re.sub(r"```(?:json)?", "", raw, flags=re.IGNORECASE).strip().rstrip("`").strip()
    # Try direct parse
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        pass
    # Try to find JSON object in the response
    match = re.search(r"\{.*\}", clean, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    logger.warning(f"JSON parse failed, using fallback. Raw prefix: {raw[:100]}")
    return {**fallback, "raw_response": raw[:500], "parse_error": True}


# ─────────────────────────────────────────────────────────────
class ThreatIntelAgent(BaseAgent):
    """Threat Intelligence — IPs, domains, hashes, URLs, CVEs."""

    def __init__(self):
        super().__init__("ThreatIntelAgent", "Analyzes threat indicators: IPs, domains, hashes, CVEs")
        self.router = get_router()

    def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        target = str(task.get("target", "")).strip()[:MAX_TARGET_LEN]
        if not target:
            return {"error": "No target provided", "threat_level": "UNKNOWN"}

        indicator_type = task.get("type") or self._detect_type(target)
        context = str(task.get("context", ""))[:500]

        prompt = self._build_prompt(target, indicator_type, context)
        raw = self.router.generate_threat_intel(prompt) if hasattr(self.router, "generate_simple") else self.router.route(prompt, mode="threat_intel")
        return self._parse(raw, target, indicator_type)

    def _detect_type(self, target: str) -> str:
        try:
            socket.inet_aton(target)
            return "ip_address"
        except OSError:
            pass
        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target):
            return "domain"
        if re.match(r"^[a-fA-F0-9]{32,64}$", target):
            return "file_hash"
        if target.upper().startswith("CVE-"):
            return "cve"
        if target.startswith(("http://", "https://")):
            return "url"
        return "unknown"

    def _build_prompt(self, target: str, itype: str, context: str) -> str:
        return f"""Perform threat intelligence analysis.

Type: {itype}
Target: {target}
Context: {context or "None"}

Return ONLY a JSON object with these exact fields:
{{
  "target": "{target}",
  "indicator_type": "{itype}",
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "threat_score": 0,
  "is_malicious": false,
  "threat_categories": [],
  "indicators_of_compromise": [],
  "attack_techniques": [],
  "geolocation": {{"country": "", "asn": "", "org": ""}},
  "recommendations": [],
  "mitigations": [],
  "references": [],
  "summary": ""
}}
Return ONLY the JSON object. No markdown, no explanation."""

    def _parse(self, raw: str, target: str, itype: str) -> Dict:
        fallback = {
            "target": target, "indicator_type": itype,
            "threat_level": "UNKNOWN", "threat_score": 0,
            "is_malicious": False, "summary": "Analysis failed — manual review required.",
            "recommendations": ["Perform manual investigation"],
        }
        result = _safe_parse_json(raw, fallback)
        result["analysis_source"] = "ai_threat_intel"
        return result


# ─────────────────────────────────────────────────────────────
class VulnerabilityAgent(BaseAgent):
    """Vulnerability Analysis — CVEs, exploits, patch priority."""

    def __init__(self):
        super().__init__("VulnerabilityAgent", "CVE analysis, exploit assessment, patch prioritization")
        self.router = get_router()

    def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        cve_id = str(task.get("cve_id", "")).strip()[:50]
        software = str(task.get("software", "")).strip()[:200]
        version = str(task.get("version", "")).strip()[:50]

        if not cve_id and not software:
            return {"error": "Provide cve_id or software", "severity": "UNKNOWN"}

        prompt = f"""Analyze this vulnerability in depth.

CVE: {cve_id or "Not specified"}
Software: {software or "Unknown"}
Version: {version or "Unknown"}

Return ONLY a JSON object:
{{
  "cve_id": "{cve_id}",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "cvss_score": 0.0,
  "description": "",
  "affected_systems": [],
  "exploit_available": false,
  "exploit_maturity": "None",
  "attack_vector": "Network",
  "patch_available": false,
  "patch_urgency": "Medium",
  "workarounds": [],
  "remediation_steps": [],
  "detection_methods": [],
  "iocs": [],
  "references": []
}}
Return ONLY the JSON. No markdown."""

        raw = self.router.generate_threat_intel(prompt) if hasattr(self.router, "generate_simple") else self.router.route(prompt, mode="threat_intel")
        fallback = {"cve_id": cve_id, "severity": "UNKNOWN", "description": "Analysis unavailable"}
        return _safe_parse_json(raw, fallback)


# ─────────────────────────────────────────────────────────────
class MalwareAnalysisAgent(BaseAgent):
    """Malware Analysis — hashes, behaviors, families, IOCs."""

    def __init__(self):
        super().__init__("MalwareAnalysisAgent", "Malware identification, behavioral analysis, IOC extraction")
        self.router = get_router()

    def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        sample = str(task.get("sample", "")).strip()[:MAX_TARGET_LEN]
        if not sample:
            return {"error": "No sample provided", "is_malicious": False}

        sample_type = str(task.get("sample_type", "hash"))[:20]
        behavior = str(task.get("behavior", ""))[:2000]

        prompt = f"""Perform malware analysis.

Sample: {sample}
Sample Type: {sample_type}
Behavior: {behavior or "Not provided"}

Return ONLY a JSON object:
{{
  "sample": "{sample}",
  "malware_family": "Unknown",
  "malware_type": "Unknown",
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "is_malicious": false,
  "confidence": 0,
  "behaviors": [],
  "persistence_mechanisms": [],
  "network_indicators": [],
  "file_indicators": [],
  "lateral_movement": [],
  "mitre_techniques": [],
  "yara_rules": [],
  "remediation": [],
  "prevention": []
}}
Return ONLY the JSON. No markdown."""

        raw = self.router.generate_threat_intel(prompt) if hasattr(self.router, "generate_simple") else self.router.route(prompt, mode="threat_intel")
        fallback = {"sample": sample, "is_malicious": False, "threat_level": "UNKNOWN",
                    "summary": "Malware analysis unavailable"}
        return _safe_parse_json(raw, fallback)


# ─────────────────────────────────────────────────────────────
class OSINTAgent(BaseAgent):
    """OSINT — attack surface mapping, threat actor correlation."""

    def __init__(self):
        super().__init__("OSINTAgent", "Open source intelligence gathering and analysis")
        self.router = get_router()

    def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        target = str(task.get("target", "")).strip()[:MAX_TARGET_LEN]
        if not target:
            return {"error": "No target provided", "risk_score": 0}

        target_type = str(task.get("target_type", "organization"))[:50]

        prompt = f"""Perform OSINT analysis.

Target: {target}
Target Type: {target_type}

Return ONLY a JSON object:
{{
  "target": "{target}",
  "target_type": "{target_type}",
  "attack_surface": {{
    "exposed_services": [],
    "exposed_technologies": [],
    "email_patterns": [],
    "subdomains": [],
    "ip_ranges": [],
    "social_media": []
  }},
  "threat_actors": [],
  "industry_threats": [],
  "data_exposures": [],
  "dark_web_mentions": [],
  "recommendations": [],
  "risk_score": 0,
  "executive_summary": ""
}}
Return ONLY the JSON. No markdown."""

        raw = self.router.generate_threat_intel(prompt) if hasattr(self.router, "generate_simple") else self.router.route(prompt, mode="threat_intel")
        fallback = {"target": target, "risk_score": 0, "executive_summary": "OSINT analysis unavailable"}
        return _safe_parse_json(raw, fallback)


# ─────────────────────────────────────────────────────────────
class SecurityAuditAgent(BaseAgent):
    """Security Audit — SAST, code review, config audit."""

    def __init__(self):
        super().__init__("SecurityAuditAgent", "Code and configuration security auditing")
        self.router = get_router()

    def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        code = str(task.get("code", task.get("content", ""))).strip()
        if not code:
            return {"error": "No code provided", "overall_risk": "UNKNOWN", "findings": []}

        # Enforce max size
        code = code[:MAX_CODE_LEN]
        language = str(task.get("language", "python"))[:20]
        audit_type = str(task.get("audit_type", "code"))[:20]

        prompt = f"""Perform a comprehensive security audit.

Language: {language}
Audit Type: {audit_type}
Content:
---
{code[:3000]}
---
{f"[...truncated, {len(code) - 3000} chars omitted...]" if len(code) > 3000 else ""}

Return ONLY a JSON object:
{{
  "audit_type": "{audit_type}",
  "language": "{language}",
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW|PASS",
  "total_findings": 0,
  "findings": [
    {{
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "category": "",
      "line": "N/A",
      "description": "",
      "code_snippet": "",
      "remediation": "",
      "cwe": ""
    }}
  ],
  "secure_code_score": 0,
  "owasp_violations": [],
  "summary": ""
}}
Return ONLY the JSON. No markdown."""

        raw = self.router.generate_cyber(prompt)
        fallback = {
            "audit_type": audit_type, "language": language,
            "overall_risk": "UNKNOWN", "total_findings": 0,
            "findings": [], "summary": "Security audit unavailable"
        }
        result = _safe_parse_json(raw, fallback)
        # Ensure total_findings is consistent with findings list
        if "findings" in result and isinstance(result["findings"], list):
            result["total_findings"] = len(result["findings"])
        return result
