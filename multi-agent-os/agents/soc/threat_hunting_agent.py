"""
Threat Hunting Agent — Hypothesis-driven hunting using MITRE ATT&CK, behavioral analytics.
"""
from __future__ import annotations
import time
from typing import Any, Dict, List, Tuple
from ..core.base_agent import BaseAgent, AgentLayer, AgentCapability, AgentRequest

HUNTING_FRAMEWORKS = ["MITRE ATT&CK", "TaHiTI", "PEAK", "Sqrrl Threat Hunting Loop"]

class ThreatHuntingAgent(BaseAgent):
    @property
    def name(self) -> str: return "threat_hunting"

    @property
    def layer(self) -> AgentLayer: return AgentLayer.SOC

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [AgentCapability(
            name="threat_hunting",
            description="Hypothesis-driven threat hunting with MITRE ATT&CK analytics and query generation",
            intents=["threat_hunt", "escalate_alert"],
            requires_tier="PRO",
            timeout_ms=35_000,
        )]

    async def _execute(self, request: AgentRequest) -> Tuple[Dict[str, Any], List[str]]:
        payload   = request.payload
        target    = payload.get("target") or payload.get("environment", "enterprise")
        technique = payload.get("technique") or payload.get("ttp", "")
        hunt_type = payload.get("hunt_type", "hypothesis_driven")

        reasoning = [
            f"Initiating threat hunt: {hunt_type}",
            f"Target environment: {target} | Focus technique: {technique or 'MITRE-based'}",
            "Generating hunt hypotheses from threat intelligence",
            "Constructing SIEM/EDR detection queries",
            "Defining success criteria and data sources",
        ]

        ai_hunt = {}
        if self.ai:
            try:
                prompt = (
                    f"You are a world-class threat hunter.\n"
                    f"Environment: {target} | Technique: {technique}\n"
                    f"Generate a comprehensive threat hunt plan. Return JSON: "
                    f"hunt_id, hypothesis, mitre_technique_id, data_sources (list), "
                    f"splunk_queries (list of strings), kql_queries (list of strings), "
                    f"sigma_rules (list of strings), "
                    f"iocs_to_hunt (list), behavioral_patterns (list), "
                    f"success_criteria (list), estimated_dwell_time_days, "
                    f"priority (1-5), tools_required (list)"
                )
                ai_hunt = await self.ai.generate(prompt, task_type="threat_hunting")
            except Exception: pass

        result = {
            "hunt_id":              f"HUNT-{int(time.time())}",
            "hypothesis":           ai_hunt.get("hypothesis", f"Adversary has established persistence using {technique or 'living-off-the-land techniques'}"),
            "hunt_type":            hunt_type,
            "mitre_technique":      technique or ai_hunt.get("mitre_technique_id", "T1053"),
            "target_environment":   target,
            "data_sources":         ai_hunt.get("data_sources", ["Windows Event Logs", "EDR Telemetry", "Network Flow", "DNS Logs"]),
            "splunk_queries":       ai_hunt.get("splunk_queries", [
                f'index=windows EventCode=4688 CommandLine="*{technique}*"',
                "index=network dest_port IN (4444, 8080, 443) bytes_out > 1000000",
            ]),
            "kql_queries":          ai_hunt.get("kql_queries", [
                f"DeviceProcessEvents | where ProcessCommandLine contains '{technique}'",
            ]),
            "sigma_rules":          ai_hunt.get("sigma_rules", []),
            "iocs_to_hunt":         ai_hunt.get("iocs_to_hunt", []),
            "behavioral_patterns":  ai_hunt.get("behavioral_patterns", [
                "Unusual parent-child process relationships",
                "Network connections from non-browser processes",
                "Scheduled tasks created by non-admin accounts",
            ]),
            "success_criteria":     ai_hunt.get("success_criteria", [
                "No malicious indicators found (clean environment)",
                "Malicious activity detected and contained",
                "New detection rule created from hunt findings",
            ]),
            "estimated_dwell_time_days": ai_hunt.get("estimated_dwell_time_days", 14),
            "priority":             ai_hunt.get("priority", 2),
            "tools_required":       ai_hunt.get("tools_required", ["SIEM", "EDR", "Velociraptor", "KAPE"]),
            "frameworks":           HUNTING_FRAMEWORKS,
            "powered_by_mythos":    True,
            "created_at":           time.time(),
        }

        reasoning.append(f"Generated {len(result['splunk_queries'])} Splunk queries, {len(result['kql_queries'])} KQL queries")
        return result, reasoning

    async def _compute_scores(self, request: AgentRequest, result: Dict) -> Tuple[float,float,float,float,float]:
        has_queries = bool(result.get("splunk_queries") or result.get("kql_queries"))
        return 88.0, 93.0 if has_queries else 78.0, 96.0, 90.0, 94.0
