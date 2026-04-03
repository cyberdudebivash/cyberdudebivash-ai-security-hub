# ============================================================
# CYBERDUDEBIVASH AI — TASK DECOMPOSER
# Breaks high-level cyber tasks into executable sub-steps
# ============================================================

import uuid
from typing import Any, Dict, List


TASK_TEMPLATES: Dict[str, List[Dict]] = {
    "threat_intel": [
        {"action": "osint_gather", "description": "Gather open-source intelligence"},
        {"action": "threat_analyze", "description": "Analyze threat indicators"},
        {"action": "generate_report", "description": "Generate threat intel report"},
    ],
    "vulnerability_assessment": [
        {"action": "identify_targets", "description": "Identify attack surface"},
        {"action": "scan_vulnerabilities", "description": "Scan for CVEs and weaknesses"},
        {"action": "prioritize", "description": "Prioritize by severity and exploitability"},
        {"action": "remediation_plan", "description": "Generate remediation plan"},
    ],
    "security_audit": [
        {"action": "sast_scan", "description": "Static code analysis"},
        {"action": "dependency_check", "description": "Check for vulnerable dependencies"},
        {"action": "config_review", "description": "Review security configurations"},
        {"action": "generate_report", "description": "Generate audit report"},
    ],
    "malware_analysis": [
        {"action": "static_analysis", "description": "Static malware analysis"},
        {"action": "behavior_analysis", "description": "Behavioral analysis"},
        {"action": "ioc_extraction", "description": "Extract indicators of compromise"},
        {"action": "generate_yara", "description": "Generate YARA detection rules"},
    ],
    "default": [
        {"action": "analyze", "description": "Analyze the task"},
        {"action": "execute", "description": "Execute the task"},
        {"action": "validate", "description": "Validate the output"},
    ],
}


class TaskDecomposer:
    """Breaks a high-level task into structured sub-steps."""

    def decompose(self, task: str) -> List[Dict[str, Any]]:
        template_key = self._detect_template(task)
        template = TASK_TEMPLATES.get(template_key, TASK_TEMPLATES["default"])

        steps = []
        for i, step in enumerate(template):
            steps.append({
                "id": str(uuid.uuid4()),
                "order": i + 1,
                "action": step["action"],
                "description": step["description"],
                "status": "pending",
                "task_context": task,
            })
        return steps

    def _detect_template(self, task: str) -> str:
        task_lower = task.lower()
        if any(k in task_lower for k in ["threat", "ioc", "indicator", "ip", "domain", "hash"]):
            return "threat_intel"
        if any(k in task_lower for k in ["vulnerability", "cve", "exploit", "patch"]):
            return "vulnerability_assessment"
        if any(k in task_lower for k in ["audit", "sast", "code review", "security scan"]):
            return "security_audit"
        if any(k in task_lower for k in ["malware", "virus", "ransomware", "trojan"]):
            return "malware_analysis"
        return "default"
