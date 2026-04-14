# ============================================================
# CYBERDUDEBIVASH AI — PLAYBOOK GENERATOR
# Generates SOC response workflows, IR playbooks, and
# threat mitigation procedures from threat intelligence.
# Outputs structured Markdown playbooks ready for SOC use.
# ============================================================

import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional
from core.cyber_tool_engine.parsers.threat_parser import ParsedThreatIntel
from core.cyber_tool_engine.classifiers.threat_classifier import ThreatClassification
from core.logging_config import get_logger

logger = get_logger("cyber_tool_engine.playbook_generator")


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _rule_id(prefix: str, intel: ParsedThreatIntel) -> str:
    content = f"{prefix}_{intel.threat_name}_{intel.malware_family}_{intel.threat_level}"
    return hashlib.sha256(content.encode()).hexdigest()[:8].upper()


class IRPlaybookGenerator:
    """
    Generates structured Incident Response playbooks.
    Covers detection → containment → eradication → recovery → lessons learned.
    """

    # Category-specific response actions
    RESPONSE_ACTIONS = {
        "ransomware": {
            "immediate": [
                "ISOLATE affected systems from network immediately (disconnect ethernet/disable WiFi)",
                "DO NOT restart or shut down infected systems — preserve volatile evidence",
                "Identify patient zero: first infected system based on file encryption timestamps",
                "Activate Incident Response team and notify CISO/Management",
                "Preserve backup integrity: verify offline backups are NOT encrypted",
                "Take memory dumps of affected systems before any remediation",
                "Document all encrypted file extensions and ransom note locations",
            ],
            "containment": [
                "Block all identified C2 IPs and domains at perimeter firewall",
                "Disable SMB laterally: block ports 445/139 between workstations",
                "Disable administrative shares (\\\\ADMIN$, \\\\C$) network-wide",
                "Revoke compromised user credentials immediately",
                "Enable enhanced logging on domain controllers",
                "Block affected user accounts at AD level",
                "Quarantine affected systems in separate VLAN",
            ],
            "eradication": [
                "Identify and terminate malicious processes on all systems",
                "Delete ransomware executables and dropper files",
                "Remove persistence mechanisms (registry run keys, scheduled tasks)",
                "Purge any webshells or backdoors discovered",
                "Clean or rebuild affected systems from known-good baseline",
                "Reset ALL privileged account passwords",
                "Rotate all service account credentials",
            ],
            "recovery": [
                "Restore from last known-good backup (verify backup integrity first)",
                "Deploy from clean image if backup unavailable",
                "Verify system integrity before reconnecting to network",
                "Implement application whitelisting on recovered systems",
                "Deploy EDR with behavioral monitoring before re-enabling",
                "Monitor for re-infection for 72 hours after recovery",
            ],
        },
        "backdoor": {
            "immediate": [
                "Isolate affected system from network",
                "Capture memory dump for forensic analysis",
                "Identify all active network connections from compromised system",
                "Determine scope: how long has backdoor been active?",
                "Identify lateral movement: what other systems were accessed?",
                "Preserve logs: system, security, network (minimum 90 days)",
            ],
            "containment": [
                "Block C2 IP addresses and domains at firewall",
                "Kill malicious process and prevent restart",
                "Block outbound communications to identified C2 infrastructure",
                "Audit all accounts: identify any created/modified by attacker",
                "Review and revoke any SSH keys or certificates added",
                "Enable NetFlow logging on all egress points",
            ],
            "eradication": [
                "Remove backdoor binary and all related files",
                "Remove persistence mechanisms (cron jobs, init scripts, WMI subscriptions)",
                "Audit and restore modified system binaries",
                "Check and restore PAM configuration if modified",
                "Rebuild system if rootkit activity suspected",
                "Reset all credentials that may have been exposed",
            ],
            "recovery": [
                "Rebuild from known-good baseline if rootkit suspected",
                "Deploy host-based IDS/IPS before return to production",
                "Enable enhanced process monitoring",
                "Implement strict egress filtering",
                "Monitor for 30 days for signs of re-compromise",
            ],
        },
        "phishing": {
            "immediate": [
                "Identify all recipients of the phishing email",
                "Pull headers to trace email origin",
                "Identify any users who clicked links or opened attachments",
                "Check web proxy logs for connections to phishing domain",
                "Immediately reset passwords for accounts that entered credentials",
                "Enable MFA for affected accounts if not already enabled",
            ],
            "containment": [
                "Block phishing domain at DNS/proxy/email gateway",
                "Remove phishing email from all mailboxes using admin tools",
                "Block sender domain and IP at email gateway",
                "Revoke access tokens for accounts that may be compromised",
                "Block any URLs in the phishing email across all proxies",
            ],
            "eradication": [
                "Scan endpoints of users who clicked for malware indicators",
                "Review MFA logs for unauthorized authentication attempts",
                "Audit OAuth app permissions for any unauthorized grants",
                "Check for inbox rules created to forward/delete emails",
                "Review identity provider logs for suspicious sign-ins",
            ],
            "recovery": [
                "Re-enable accounts after credential reset and MFA verification",
                "Provide security awareness training to affected users",
                "Report phishing infrastructure to abuse contacts",
                "Update email security filters with new indicators",
            ],
        },
    }

    DEFAULT_ACTIONS = {
        "immediate": [
            "Isolate affected systems from production network",
            "Preserve evidence: memory dumps, disk images, log files",
            "Activate Incident Response team",
            "Notify stakeholders per communication plan",
            "Document timeline of events",
        ],
        "containment": [
            "Block identified malicious IPs and domains at perimeter",
            "Revoke compromised credentials",
            "Enable enhanced logging across affected systems",
            "Segment affected systems in quarantine VLAN",
        ],
        "eradication": [
            "Remove malicious artifacts (binaries, scripts, persistence mechanisms)",
            "Patch exploited vulnerability if applicable",
            "Reset all potentially compromised credentials",
            "Verify system integrity",
        ],
        "recovery": [
            "Restore from clean backup or rebuild from baseline",
            "Verify system integrity before reconnection",
            "Monitor for 30 days for re-infection",
            "Deploy additional security controls to prevent recurrence",
        ],
    }

    def generate(self, intel: ParsedThreatIntel, classification: ThreatClassification) -> str:
        playbook_id = _rule_id("PB", intel)
        threat_name = intel.malware_family or intel.threat_name or classification.primary_category
        category = classification.primary_category

        actions = self.RESPONSE_ACTIONS.get(category, self.DEFAULT_ACTIONS)
        severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
            intel.threat_level, "⚪"
        )

        lines = []
        lines.append(f"# {severity_icon} INCIDENT RESPONSE PLAYBOOK: {threat_name.upper()}")
        lines.append(f"\n**Playbook ID:** CDB-IR-{playbook_id}")
        lines.append(f"**Threat:** {threat_name}")
        lines.append(f"**Category:** {classification.primary_category} / {classification.subcategory}")
        lines.append(f"**Severity:** {intel.threat_level} | **Urgency:** {classification.urgency}")
        lines.append(f"**Generated:** {_ts()} by CYBERDUDEBIVASH AI Engine")
        lines.append(f"**MITRE ATT&CK:** {', '.join(intel.mitre_techniques[:8]) or 'N/A'}")
        if intel.mitre_tactics:
            lines.append(f"**Tactics:** {', '.join(intel.mitre_tactics)}")
        lines.append(f"\n---")

        # Executive Summary
        lines.append(f"\n## 📋 Executive Summary\n")
        lines.append(f"{intel.threat_description or f'{threat_name} is a {classification.primary_category} threat requiring immediate response.'}")
        lines.append(f"\n**Kill Chain Phase:** {classification.kill_chain_phase}")
        lines.append(f"**Target OS:** {', '.join(classification.target_os)}")
        lines.append(f"**Target Sector:** {classification.target_sector}")
        lines.append(f"**Target Asset:** {classification.target_asset}")

        # Threat Indicators
        lines.append(f"\n---\n\n## 🎯 Threat Indicators\n")
        if intel.ips:
            lines.append(f"### Malicious IP Addresses ({len(intel.ips)})")
            lines.append("```")
            for ip in intel.ips[:30]:
                lines.append(ip)
            lines.append("```\n")
        if intel.domains:
            lines.append(f"### Malicious Domains ({len(intel.domains)})")
            lines.append("```")
            for domain in intel.domains[:30]:
                lines.append(domain)
            lines.append("```\n")
        if intel.file_hashes:
            lines.append(f"### File Hashes ({len(intel.file_hashes)})")
            lines.append("```")
            for h in intel.file_hashes[:20]:
                lines.append(h)
            lines.append("```\n")
        if intel.c2_servers:
            lines.append(f"### C2 Servers")
            lines.append("```")
            for c2 in intel.c2_servers[:15]:
                lines.append(c2)
            lines.append("```\n")
        if intel.cve_ids:
            lines.append(f"### CVEs: {', '.join(intel.cve_ids)}\n")

        # Response Phases
        lines.append("---\n\n## 🚨 Phase 1: IMMEDIATE ACTIONS (0-30 minutes)\n")
        lines.append("> ⚡ Execute immediately upon detection. Every minute matters.\n")
        for i, action in enumerate(actions.get("immediate", self.DEFAULT_ACTIONS["immediate"]), 1):
            lines.append(f"- [ ] **Step {i}:** {action}")
        lines.append(f"\n**Escalation:** If scope is > 10 systems → escalate to CISO immediately")
        lines.append(f"**Communication:** Notify legal/compliance if PII may be affected")

        lines.append("\n---\n\n## 🛡️ Phase 2: CONTAINMENT (30 min - 4 hours)\n")
        lines.append("> 🔒 Stop the spread. Isolate before eradicating.\n")
        for i, action in enumerate(actions.get("containment", self.DEFAULT_ACTIONS["containment"]), 1):
            lines.append(f"- [ ] **Step {i}:** {action}")

        # Network blocking commands
        if intel.ips or intel.domains:
            lines.append("\n### 🔥 Firewall Block Commands\n")
            lines.append("```bash")
            lines.append("# Linux/iptables — Block malicious IPs")
            for ip in intel.ips[:10]:
                lines.append(f"iptables -I INPUT -s {ip} -j DROP")
                lines.append(f"iptables -I OUTPUT -d {ip} -j DROP")
            lines.append("\n# Windows — Block via firewall (PowerShell as Admin)")
            for ip in intel.ips[:5]:
                lines.append(f'netsh advfirewall firewall add rule name="CDB-BLOCK-{ip}" dir=out action=block remoteip={ip}')
            lines.append("```\n")

        lines.append("---\n\n## 🔍 Phase 3: ERADICATION (4-24 hours)\n")
        lines.append("> 🧹 Remove all traces. Verify nothing remains.\n")
        for i, action in enumerate(actions.get("eradication", self.DEFAULT_ACTIONS["eradication"]), 1):
            lines.append(f"- [ ] **Step {i}:** {action}")

        # Detection commands
        lines.append("\n### 🔎 Detection Commands\n")
        lines.append("```bash")
        lines.append("# Search for malicious processes")
        lines.append("ps aux | grep -iE 'mimikatz|meterpreter|cobalt|beacon'")
        lines.append("\n# Check scheduled tasks (Linux)")
        lines.append("crontab -l && cat /etc/cron*/*")
        lines.append("\n# Check startup items (Linux)")
        lines.append("systemctl list-units --state=failed && ls /etc/systemd/system/")
        lines.append("\n# Check for hidden files")
        lines.append("find / -name '.*' -type f -newer /tmp 2>/dev/null | head -50")
        if intel.file_hashes:
            lines.append("\n# Search for known malicious hashes (MD5)")
            lines.append("find / -type f -exec md5sum {} \\; 2>/dev/null | grep -f malicious_hashes.txt")
        lines.append("```\n")

        lines.append("---\n\n## ♻️ Phase 4: RECOVERY (24-72 hours)\n")
        lines.append("> ✅ Return to normal operations safely.\n")
        for i, action in enumerate(actions.get("recovery", self.DEFAULT_ACTIONS["recovery"]), 1):
            lines.append(f"- [ ] **Step {i}:** {action}")

        # Hardening recommendations
        lines.append("\n---\n\n## 🏗️ Post-Incident Hardening\n")
        hardening = self._get_hardening_steps(classification)
        for step in hardening:
            lines.append(f"- [ ] {step}")

        # MITRE ATT&CK mapping
        if intel.mitre_techniques:
            lines.append(f"\n---\n\n## 🗺️ MITRE ATT&CK Mapping\n")
            lines.append("| Technique ID | Phase |")
            lines.append("|---|---|")
            for t in intel.mitre_techniques[:10]:
                phase = classification.attack_phase or "Unknown"
                lines.append(f"| [{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}) | {phase} |")

        # Lessons Learned Template
        lines.append("\n---\n\n## 📝 Lessons Learned (Complete Within 5 Days)\n")
        lines.append("| Question | Answer |")
        lines.append("|---|---|")
        lines.append("| How was the threat initially detected? | |")
        lines.append("| What was the initial attack vector? | |")
        lines.append("| How many systems were affected? | |")
        lines.append("| What data was accessed/exfiltrated? | |")
        lines.append("| How long was the attacker present? | |")
        lines.append("| What controls failed to prevent this? | |")
        lines.append("| What new controls will prevent recurrence? | |")
        lines.append("| Total business impact (hours/cost)? | |")

        lines.append(f"\n---\n\n*Generated by CYBERDUDEBIVASH AI Engine | Playbook ID: CDB-IR-{playbook_id} | {_ts()}*\n")

        return '\n'.join(lines)

    def _get_hardening_steps(self, classification: ThreatClassification) -> List[str]:
        base = [
            "Enable Multi-Factor Authentication (MFA) for all privileged accounts",
            "Implement network segmentation to limit lateral movement",
            "Deploy EDR/XDR solution with behavioral detection",
            "Enable comprehensive logging (Windows Event IDs: 4624,4625,4648,4672,4688,7045)",
            "Implement application whitelisting on critical systems",
            "Regular vulnerability scanning and patch management",
            "Backup verification: test restore procedures monthly",
        ]
        category_specific = {
            "ransomware": [
                "Implement 3-2-1 backup strategy (3 copies, 2 media types, 1 offsite)",
                "Restrict access to administrative shares (ADMIN$, C$)",
                "Deploy ransomware-specific behavioral detection",
                "Implement controlled folder access (Windows Defender)",
            ],
            "phishing": [
                "Deploy advanced email filtering (SPF, DKIM, DMARC)",
                "Enable Safe Links and Safe Attachments in email gateway",
                "Conduct phishing simulation training quarterly",
                "Implement browser isolation for web access",
            ],
            "backdoor": [
                "Implement strict egress filtering (deny all outbound except whitelisted)",
                "Deploy network traffic analysis (NTA) for anomaly detection",
                "Audit all scheduled tasks and startup items weekly",
                "Implement privileged access workstations (PAW)",
            ],
        }
        return base + category_specific.get(classification.primary_category, [])


class SOCWorkflowGenerator:
    """Generates SOC analyst triage workflows and runbooks."""

    def generate(self, intel: ParsedThreatIntel, classification: ThreatClassification) -> str:
        workflow_id = _rule_id("SOC", intel)
        threat_name = intel.malware_family or classification.primary_category or "Unknown"

        lines = []
        lines.append(f"# SOC TRIAGE WORKFLOW: {threat_name.upper()}")
        lines.append(f"\n**Workflow ID:** CDB-SOC-{workflow_id}")
        lines.append(f"**Severity:** {intel.threat_level} | **SLA:** {self._get_sla(intel.threat_level)}")
        lines.append(f"**Generated:** {_ts()}\n")
        lines.append("---")

        lines.append("\n## 🔔 Alert Triage Checklist\n")
        lines.append("**Time to acknowledge:** " + self._get_ack_time(intel.threat_level))
        lines.append("\n**Step 1 — Validate Alert:**")
        lines.append("- [ ] Confirm alert is not a false positive")
        lines.append("- [ ] Check if source system is a known asset")
        lines.append("- [ ] Verify IOC against threat intelligence")
        lines.append(f"- [ ] Cross-reference with known {threat_name} indicators")

        lines.append("\n**Step 2 — Scope Assessment:**")
        lines.append("- [ ] How many systems are affected?")
        lines.append("- [ ] What data is at risk?")
        lines.append("- [ ] Is the attack ongoing or historic?")
        lines.append("- [ ] Has lateral movement occurred?")

        lines.append("\n**Step 3 — Severity Determination:**")
        lines.append("```")
        lines.append("CRITICAL → Active breach + lateral movement + data exfiltration")
        lines.append("HIGH     → Active malware + contained to single system")
        lines.append("MEDIUM   → Suspicious indicators + no confirmed compromise")
        lines.append("LOW      → Historical IOCs + no active threat")
        lines.append("```")

        lines.append("\n**Step 4 — Escalation Matrix:**")
        lines.append("| Severity | Escalate To | Time Limit |")
        lines.append("|---|---|---|")
        lines.append("| CRITICAL | CISO + IR Team + Legal | 15 minutes |")
        lines.append("| HIGH | Security Manager + IR Lead | 30 minutes |")
        lines.append("| MEDIUM | Senior Analyst | 2 hours |")
        lines.append("| LOW | Analyst | Next business day |")

        lines.append("\n## 🔍 Investigation Commands\n")
        lines.append("```bash")
        lines.append("# Check if IOCs are present in SIEM")
        for ip in intel.ips[:5]:
            lines.append(f'# Search: dest_ip="{ip}" OR src_ip="{ip}"')
        for domain in intel.domains[:5]:
            lines.append(f'# Search: query="{domain}" OR dest_hostname="{domain}"')
        lines.append("")
        lines.append("# Splunk query template")
        lines.append('index=* earliest=-24h (')
        if intel.ips:
            ip_query = " OR ".join([f'dest_ip="{ip}"' for ip in intel.ips[:5]])
            lines.append(f'  {ip_query}')
        if intel.domains:
            domain_query = " OR ".join([f'query="{d}"' for d in intel.domains[:5]])
            lines.append(f'  OR {domain_query}')
        lines.append(') | stats count by src_ip, dest_ip, _time')
        lines.append("```")

        lines.append(f"\n---\n\n*SOC Workflow ID: CDB-SOC-{workflow_id} | {_ts()}*\n")
        return '\n'.join(lines)

    def _get_sla(self, threat_level: str) -> str:
        return {"CRITICAL": "4 hours", "HIGH": "8 hours", "MEDIUM": "24 hours", "LOW": "72 hours"}.get(
            threat_level.upper(), "24 hours"
        )

    def _get_ack_time(self, threat_level: str) -> str:
        return {"CRITICAL": "⚡ 5 minutes", "HIGH": "⚡ 15 minutes", "MEDIUM": "30 minutes", "LOW": "2 hours"}.get(
            threat_level.upper(), "30 minutes"
        )


class PlaybookGenerationEngine:
    """Orchestrates playbook and workflow generation."""

    def __init__(self):
        self.ir_playbook = IRPlaybookGenerator()
        self.soc_workflow = SOCWorkflowGenerator()

    def generate_all(
        self,
        intel: ParsedThreatIntel,
        classification: ThreatClassification,
    ) -> Dict[str, str]:
        results = {}
        try:
            results["ir_playbook"] = self.ir_playbook.generate(intel, classification)
        except Exception as e:
            logger.error(f"[PlaybookGen] IR playbook failed: {e}")
            results["ir_playbook"] = f"# Generation failed: {e}\n"
        try:
            results["soc_workflow"] = self.soc_workflow.generate(intel, classification)
        except Exception as e:
            logger.error(f"[PlaybookGen] SOC workflow failed: {e}")
            results["soc_workflow"] = f"# Generation failed: {e}\n"
        return results
