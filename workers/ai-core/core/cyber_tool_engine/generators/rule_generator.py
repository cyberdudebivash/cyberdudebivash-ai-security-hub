# ============================================================
# CYBERDUDEBIVASH AI — DETECTION RULE GENERATOR
# Generates production-grade YARA, Sigma, Snort, Suricata rules
# from parsed threat intelligence. All rules are fully functional.
# ============================================================

import re
import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional
from core.cyber_tool_engine.parsers.threat_parser import ParsedThreatIntel
from core.cyber_tool_engine.classifiers.threat_classifier import ThreatClassification
from core.logging_config import get_logger

logger = get_logger("cyber_tool_engine.rule_generator")


def _rule_id(prefix: str, intel: ParsedThreatIntel) -> str:
    """Generate a unique, deterministic rule identifier."""
    content = f"{prefix}_{intel.threat_name}_{intel.malware_family}_{intel.threat_level}"
    return hashlib.sha256(content.encode()).hexdigest()[:8].upper()


def _sanitize_name(name: str) -> str:
    """Sanitize a string for use as a rule name."""
    clean = re.sub(r'[^a-zA-Z0-9_]', '_', name.strip())
    clean = re.sub(r'_+', '_', clean).strip('_')
    return clean[:64] or "Unknown"


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class YARAGenerator:
    """
    Generates production-grade YARA rules.
    Supports file hash matching, string patterns, regex, and
    PE characteristics for malware detection.
    """

    def generate(self, intel: ParsedThreatIntel, classification: ThreatClassification) -> str:
        """Generate a complete YARA rule file."""
        rule_name = f"CDB_{_sanitize_name(intel.malware_family or intel.threat_name or classification.primary_category)}"
        rule_id = _rule_id("YARA", intel)

        lines = []
        lines.append(f'// CYBERDUDEBIVASH AI — Generated YARA Rule')
        lines.append(f'// Threat: {intel.malware_family or intel.threat_name}')
        lines.append(f'// Generated: {_ts()} | Rule ID: {rule_id}')
        lines.append(f'// Severity: {intel.threat_level} | Category: {classification.primary_category}')
        lines.append(f'// MITRE: {", ".join(intel.mitre_techniques[:5])}')
        lines.append('')
        lines.append(f'import "pe"')
        lines.append(f'import "hash"')
        lines.append('')
        lines.append(f'rule {rule_name}_{rule_id} {{')

        # Meta section
        lines.append('    meta:')
        lines.append(f'        author = "CYBERDUDEBIVASH AI Engine"')
        lines.append(f'        date = "{_ts()}"')
        lines.append(f'        version = "1.0"')
        lines.append(f'        description = "{(intel.threat_description or "Threat detection rule")[:120]}"')
        lines.append(f'        severity = "{intel.threat_level}"')
        lines.append(f'        category = "{classification.primary_category}"')
        lines.append(f'        malware_family = "{intel.malware_family or "unknown"}"')
        lines.append(f'        attack_techniques = "{", ".join(intel.mitre_techniques[:5])}"')
        lines.append(f'        rule_id = "CDB-{rule_id}"')
        lines.append(f'        reference = "CYBERDUDEBIVASH SENTINEL APEX"')

        # Strings section
        lines.append('    strings:')
        str_idx = 1

        # Hash strings (for hash-based detection)
        hash_conditions = []
        for h in intel.file_hashes[:10]:
            h_type = "md5" if len(h) == 32 else ("sha1" if len(h) == 40 else "sha256")
            if h_type == "sha256":
                lines.append(f'        // SHA256: {h}')
                hash_conditions.append(f'hash.sha256(0, filesize) == "{h.lower()}"')
            elif h_type == "md5":
                lines.append(f'        // MD5: {h}')
                hash_conditions.append(f'hash.md5(0, filesize) == "{h.lower()}"')

        # String patterns based on threat type
        if classification.primary_category == "ransomware":
            lines.append(f'        $ransom_note_1 = "Your files have been encrypted" ascii wide nocase')
            lines.append(f'        $ransom_note_2 = "Bitcoin" ascii wide nocase')
            lines.append(f'        $ransom_note_3 = "decrypt" ascii wide nocase')
            lines.append(f'        $ransom_ext = ".encrypted" ascii wide nocase')
            lines.append(f'        $ransom_key = "ransom" ascii wide nocase')
        elif classification.primary_category in ("backdoor", "rat"):
            lines.append(f'        $c2_connect_1 = "cmd.exe /c" ascii wide nocase')
            lines.append(f'        $c2_connect_2 = "powershell -enc" ascii wide nocase')
            lines.append(f'        $c2_connect_3 = "reverse_tcp" ascii wide nocase')
            lines.append(f'        $shell_str = "/bin/bash" ascii wide')
            lines.append(f'        $persistence = "CurrentVersion\\\\Run" ascii wide')
        elif classification.primary_category == "trojan":
            lines.append(f'        $steal_1 = "password" ascii wide nocase')
            lines.append(f'        $steal_2 = "credentials" ascii wide nocase')
            lines.append(f'        $steal_3 = "cookie" ascii wide nocase')
            lines.append(f'        $exfil = "POST" ascii wide')
        elif classification.subcategory == "exploit":
            lines.append(f'        $shellcode_1 = {{ 90 90 90 90 EB }}')
            lines.append(f'        $shellcode_2 = {{ 31 C0 50 68 }}')
            lines.append(f'        $rop_str = "\\\\x41\\\\x41\\\\x41" ascii')
        else:
            lines.append(f'        $suspicious_1 = "CreateRemoteThread" ascii wide')
            lines.append(f'        $suspicious_2 = "VirtualAllocEx" ascii wide')
            lines.append(f'        $suspicious_3 = "WriteProcessMemory" ascii wide')

        # Network IOC strings
        for i, domain in enumerate(intel.domains[:5]):
            lines.append(f'        $domain_{i+1} = "{domain}" ascii wide nocase')

        for i, ip in enumerate(intel.ips[:5]):
            lines.append(f'        $ip_{i+1} = "{ip}" ascii wide')

        for i, c2 in enumerate(intel.c2_servers[:3]):
            lines.append(f'        $c2_{i+1} = "{c2}" ascii wide nocase')

        # Registry keys
        for i, reg in enumerate(intel.registry_keys[:3]):
            safe_reg = reg.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'        $reg_{i+1} = "{safe_reg}" ascii wide nocase')

        # File paths
        for i, path in enumerate(intel.file_paths[:3]):
            safe_path = path.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'        $path_{i+1} = "{safe_path}" ascii wide nocase')

        # Conditions section
        lines.append('    condition:')

        conditions = []

        # Hash-based condition (highest confidence)
        if hash_conditions:
            hash_cond = " or\n                    ".join(hash_conditions)
            conditions.append(f'(\n                    {hash_cond}\n                )')

        # String-based conditions
        lines_count = sum(1 for l in lines if l.strip().startswith('$'))
        if lines_count > 0:
            if classification.primary_category == "ransomware":
                conditions.append('(2 of ($ransom_*))')
            elif classification.primary_category in ("backdoor", "rat"):
                conditions.append('(2 of ($c2_connect_*, $shell_str, $persistence))')
            elif intel.domains or intel.ips:
                ioc_parts = []
                if intel.domains[:5]:
                    ioc_parts.append('(1 of ($domain_*))')
                if intel.ips[:5]:
                    ioc_parts.append('(1 of ($ip_*))')
                if intel.c2_servers[:3]:
                    ioc_parts.append('(1 of ($c2_*))')
                if ioc_parts:
                    conditions.append("(" + " or ".join(ioc_parts) + ")")
            else:
                conditions.append('(2 of them)')

        # PE file condition for Windows malware
        if "windows" in classification.target_os and classification.primary_category in (
            "malware", "ransomware", "backdoor", "trojan", "rat", "worm", "dropper", "rootkit"
        ):
            conditions.insert(0, 'uint16(0) == 0x5A4D')  # MZ header check

        if conditions:
            lines.append('        ' + ' and\n        '.join(conditions))
        else:
            lines.append('        filesize < 50MB and (1 of them)')

        lines.append('}')
        lines.append('')

        return '\n'.join(lines)


class SigmaGenerator:
    """
    Generates production-grade Sigma rules for SIEM integration.
    Compatible with Splunk, Elastic, QRadar, Chronicle.
    """

    LOGSOURCE_MAP = {
        "windows": {"category": "process_creation", "product": "windows"},
        "linux": {"category": "process_creation", "product": "linux"},
        "network": {"category": "network_connection", "product": "windows"},
        "web": {"category": "webserver", "service": "apache"},
        "default": {"category": "process_creation", "product": "windows"},
    }

    def generate(self, intel: ParsedThreatIntel, classification: ThreatClassification) -> str:
        """Generate Sigma rule in YAML format."""
        rule_id = _rule_id("SIGMA", intel)
        rule_name = f"CDB_{_sanitize_name(intel.malware_family or intel.threat_name or classification.primary_category)}"
        threat_name = intel.malware_family or intel.threat_name or classification.primary_category

        # Determine log source
        logsource = self._get_logsource(classification)

        # Build detection fields
        detection = self._build_detection(intel, classification)

        lines = []
        lines.append(f'# CYBERDUDEBIVASH AI — Sigma Detection Rule')
        lines.append(f'# Generated: {_ts()} | Rule ID: CDB-SIGMA-{rule_id}')
        lines.append(f'# Severity: {intel.threat_level} | Category: {classification.primary_category}')
        lines.append('')
        lines.append(f'title: {threat_name} Detection - CDB-{rule_id}')
        lines.append(f'id: cdb-{rule_id.lower()}')
        lines.append(f'status: experimental')
        lines.append(f'description: |')
        lines.append(f'  Detects {threat_name} activity based on CYBERDUDEBIVASH threat intelligence.')
        lines.append(f'  {(intel.threat_description or "")[:200]}')
        lines.append(f'references:')
        lines.append(f'  - https://attack.mitre.org/')
        lines.append(f'  - https://cyberdudebivash.ai/threats/{rule_id.lower()}')
        lines.append(f'author: CYBERDUDEBIVASH AI Engine')
        lines.append(f'date: {_ts()}')
        lines.append(f'modified: {_ts()}')
        lines.append(f'tags:')
        for technique in intel.mitre_techniques[:8]:
            lines.append(f'  - attack.{technique.lower()}')
        for tactic in intel.mitre_tactics[:4]:
            lines.append(f'  - attack.{tactic.lower().replace(" ", "_")}')
        if classification.primary_category:
            lines.append(f'  - detection.{classification.primary_category}')
        lines.append(f'logsource:')
        for k, v in logsource.items():
            lines.append(f'  {k}: {v}')
        lines.append(f'detection:')
        lines.append(f'  {detection}')
        lines.append(f'  condition: selection')
        lines.append(f'fields:')
        lines.append(f'  - CommandLine')
        lines.append(f'  - Image')
        lines.append(f'  - ParentImage')
        lines.append(f'  - User')
        lines.append(f'  - DestinationIp')
        lines.append(f'  - DestinationHostname')
        lines.append(f'falsepositives:')
        lines.append(f'  - Legitimate administrative activity')
        lines.append(f'  - Security testing')
        lines.append(f'level: {self._map_level(intel.threat_level)}')

        return '\n'.join(lines)

    def _get_logsource(self, classification: ThreatClassification) -> Dict[str, str]:
        if classification.primary_category == "ddos":
            return {"category": "network_connection", "product": "zeek"}
        if classification.target_asset in ("server", "cloud"):
            return {"category": "process_creation", "product": "linux"}
        if "linux" in classification.target_os and "windows" not in classification.target_os:
            return self.LOGSOURCE_MAP["linux"]
        return self.LOGSOURCE_MAP["default"]

    def _build_detection(self, intel: ParsedThreatIntel, classification: ThreatClassification) -> str:
        lines = []

        if classification.primary_category == "ransomware":
            lines.append("selection:")
            lines.append("    CommandLine|contains:")
            lines.append("      - 'vssadmin delete shadows'")
            lines.append("      - 'wbadmin delete catalog'")
            lines.append("      - 'bcdedit /set {default} recoveryenabled No'")
            lines.append("      - 'cipher /w:'")
            lines.append("    Image|endswith:")
            lines.append("      - '\\\\vssadmin.exe'")
            lines.append("      - '\\\\wbadmin.exe'")
            lines.append("      - '\\\\bcdedit.exe'")

        elif classification.primary_category in ("backdoor", "rat"):
            lines.append("selection:")
            lines.append("    CommandLine|contains:")
            lines.append("      - '-enc '")
            lines.append("      - '-EncodedCommand'")
            lines.append("      - 'IEX('")
            lines.append("      - 'Invoke-Expression'")
            lines.append("      - 'DownloadString'")
            lines.append("      - 'WebClient'")
            if intel.ips:
                lines.append("    DestinationIp:")
                for ip in intel.ips[:10]:
                    lines.append(f"      - '{ip}'")
            if intel.domains:
                lines.append("    DestinationHostname|contains:")
                for domain in intel.domains[:10]:
                    lines.append(f"      - '{domain}'")

        elif classification.primary_category == "credential":
            lines.append("selection:")
            lines.append("    CommandLine|contains:")
            lines.append("      - 'sekurlsa'")
            lines.append("      - 'lsadump'")
            lines.append("      - 'kerberos'")
            lines.append("    Image|contains:")
            lines.append("      - 'mimikatz'")
            lines.append("      - 'lsass'")
            lines.append("    TargetImage|endswith:")
            lines.append("      - '\\\\lsass.exe'")

        elif intel.ips or intel.domains:
            lines.append("selection:")
            if intel.ips:
                lines.append("    DestinationIp:")
                for ip in intel.ips[:15]:
                    lines.append(f"      - '{ip}'")
            if intel.domains:
                lines.append("    DestinationHostname|contains:")
                for domain in intel.domains[:15]:
                    lines.append(f"      - '{domain}'")

        else:
            lines.append("selection:")
            lines.append("    CommandLine|contains:")
            lines.append("      - 'wscript.exe'")
            lines.append("      - 'mshta.exe'")
            lines.append("      - 'regsvr32.exe'")
            lines.append("      - 'rundll32.exe'")
            lines.append("    Image|endswith:")
            lines.append("      - '\\\\wscript.exe'")
            lines.append("      - '\\\\mshta.exe'")

        return '\n  '.join(lines)

    def _map_level(self, threat_level: str) -> str:
        return {
            "CRITICAL": "critical", "HIGH": "high",
            "MEDIUM": "medium", "LOW": "low", "INFO": "informational",
        }.get(threat_level.upper(), "medium")


class SnortSuricataGenerator:
    """
    Generates Snort/Suricata IDS/IPS network detection rules.
    Covers IP blocking, domain matching, C2 detection, protocol anomalies.
    """

    def generate_snort(self, intel: ParsedThreatIntel, classification: ThreatClassification) -> str:
        """Generate Snort rules."""
        rule_id = _rule_id("SNORT", intel)
        rules = []
        rules.append(f'# CYBERDUDEBIVASH AI — Snort Rules | Generated: {_ts()}')
        rules.append(f'# Threat: {intel.malware_family or classification.primary_category}')
        rules.append(f'# Severity: {intel.threat_level} | Rule ID: CDB-SNORT-{rule_id}')
        rules.append('')

        sid_base = int(rule_id[:4], 16) % 900000 + 100000
        sid = sid_base

        priority = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}.get(intel.threat_level, 3)
        classtype = self._get_classtype(classification.primary_category)
        rev = 1

        for ip in intel.ips[:20]:
            rules.append(
                f'alert ip any any -> {ip} any ('
                f'msg:"CYBERDUDEBIVASH {classification.primary_category.upper()} - Known Malicious IP {ip}"; '
                f'classtype:{classtype}; sid:{sid}; rev:{rev}; priority:{priority};)'
            )
            sid += 1
            rules.append(
                f'alert ip {ip} any -> any any ('
                f'msg:"CYBERDUDEBIVASH {classification.primary_category.upper()} - Inbound From Malicious IP {ip}"; '
                f'classtype:{classtype}; sid:{sid}; rev:{rev}; priority:{priority};)'
            )
            sid += 1

        for domain in intel.domains[:15]:
            safe = domain.replace(".", "\\.")
            rules.append(
                f'alert dns any any -> any 53 ('
                f'msg:"CYBERDUDEBIVASH {classification.primary_category.upper()} - Malicious Domain {domain}"; '
                f'dns.query; content:"{domain}"; nocase; '
                f'classtype:{classtype}; sid:{sid}; rev:{rev}; priority:{priority};)'
            )
            sid += 1

        for c2 in intel.c2_servers[:10]:
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', c2):
                rules.append(
                    f'alert tcp any any -> {c2} any ('
                    f'msg:"CYBERDUDEBIVASH C2 BEACON - {classification.malware_family or "Unknown"} to {c2}"; '
                    f'flow:established,to_server; '
                    f'classtype:trojan-activity; sid:{sid}; rev:{rev}; priority:1;)'
                )
                sid += 1

        if classification.primary_category == "ransomware":
            rules.append(
                f'alert smb any any -> $HOME_NET any ('
                f'msg:"CYBERDUDEBIVASH RANSOMWARE - SMB Lateral Spread Attempt"; '
                f'flow:established,to_server; content:"|FF|SMB"; '
                f'classtype:trojan-activity; sid:{sid}; rev:{rev}; priority:1;)'
            )

        return '\n'.join(rules) + '\n'

    def generate_suricata(self, intel: ParsedThreatIntel, classification: ThreatClassification) -> str:
        """Generate Suricata rules (EVE/unified2 format)."""
        rule_id = _rule_id("SURICATA", intel)
        rules = []
        rules.append(f'# CYBERDUDEBIVASH AI — Suricata Rules | Generated: {_ts()}')
        rules.append(f'# Threat: {intel.malware_family or classification.primary_category}')
        rules.append(f'# Severity: {intel.threat_level} | Rule ID: CDB-SURICATA-{rule_id}')
        rules.append('')

        sid_base = int(rule_id[:4], 16) % 800000 + 9000000
        sid = sid_base
        priority = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}.get(intel.threat_level, 3)
        classtype = self._get_classtype(classification.primary_category)

        for ip in intel.ips[:20]:
            rules.append(
                f'alert ip any any -> {ip} any ('
                f'msg:"CDB {classification.primary_category.upper()} Known C2/Malicious IP [{ip}]"; '
                f'classtype:{classtype}; sid:{sid}; rev:1; '
                f'metadata:affected_product Any, attack_target Client_Endpoint, '
                f'deployment Perimeter, severity {intel.threat_level}, '
                f'signature_severity {intel.threat_level};)'
            )
            sid += 1

        for domain in intel.domains[:15]:
            rules.append(
                f'alert dns any any -> any any ('
                f'msg:"CDB {classification.primary_category.upper()} Malicious Domain [{domain}]"; '
                f'dns.query; content:"{domain}"; nocase; isdataat:!1,relative; '
                f'classtype:{classtype}; sid:{sid}; rev:1; '
                f'metadata:severity {intel.threat_level};)'
            )
            sid += 1

        for url in intel.urls[:10]:
            try:
                path = url.split("/", 3)[3] if len(url.split("/")) > 3 else "/"
                rules.append(
                    f'alert http any any -> any any ('
                    f'msg:"CDB {classification.primary_category.upper()} Malicious URL Pattern"; '
                    f'http.uri; content:"{path[:60]}"; nocase; '
                    f'classtype:{classtype}; sid:{sid}; rev:1;)'
                )
                sid += 1
            except Exception:
                pass

        return '\n'.join(rules) + '\n'

    def _get_classtype(self, category: str) -> str:
        return {
            "ransomware": "trojan-activity",
            "backdoor": "trojan-activity",
            "rat": "trojan-activity",
            "botnet": "trojan-activity",
            "exploit": "attempted-admin",
            "phishing": "social-engineering",
            "ddos": "denial-of-service",
            "apt": "targeted-activity",
            "credential": "credential-theft",
        }.get(category, "misc-attack")


class RuleGenerationEngine:
    """Orchestrates generation of all rule types from threat intelligence."""

    def __init__(self):
        self.yara = YARAGenerator()
        self.sigma = SigmaGenerator()
        self.network = SnortSuricataGenerator()

    def generate_all(
        self,
        intel: ParsedThreatIntel,
        classification: ThreatClassification,
        rule_types: List[str] = None,
    ) -> Dict[str, str]:
        """Generate all requested rule types and return as dict."""
        rule_types = rule_types or intel.recommended_rules or ["yara", "sigma", "snort", "suricata"]
        results = {}

        for rule_type in rule_types:
            try:
                if rule_type == "yara":
                    results["yara"] = self.yara.generate(intel, classification)
                elif rule_type == "sigma":
                    results["sigma"] = self.sigma.generate(intel, classification)
                elif rule_type == "snort":
                    results["snort"] = self.network.generate_snort(intel, classification)
                elif rule_type == "suricata":
                    results["suricata"] = self.network.generate_suricata(intel, classification)
            except Exception as e:
                logger.error(f"[RuleGen] {rule_type} generation failed: {e}")
                results[rule_type] = f"# Generation failed: {e}\n"

        return results
