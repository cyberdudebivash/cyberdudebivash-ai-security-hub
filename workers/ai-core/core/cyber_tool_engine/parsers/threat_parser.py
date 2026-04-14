# ============================================================
# CYBERDUDEBIVASH AI — THREAT PARSING ENGINE
# Extracts IOCs, TTPs, MITRE techniques, and patterns from
# raw threat intelligence in any format (JSON, text, dict)
# ============================================================

import re
import json
import socket
import hashlib
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
from core.logging_config import get_logger

logger = get_logger("cyber_tool_engine.parser")


# ── Parsed Intelligence Object ────────────────────────────────
@dataclass
class ParsedThreatIntel:
    """Normalized, structured threat intelligence ready for classification and generation."""
    raw_input: str = ""
    source_type: str = "unknown"      # analysis / feed / manual / scan
    threat_name: str = ""
    threat_description: str = ""

    # IOCs
    ips: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    file_hashes: List[str] = field(default_factory=list)
    email_addresses: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    registry_keys: List[str] = field(default_factory=list)
    file_paths: List[str] = field(default_factory=list)
    mutexes: List[str] = field(default_factory=list)

    # Intelligence
    threat_level: str = "UNKNOWN"     # CRITICAL/HIGH/MEDIUM/LOW/INFO
    threat_score: int = 0             # 0-100
    is_malicious: bool = False
    threat_categories: List[str] = field(default_factory=list)   # malware, phishing, etc.
    threat_actor: str = ""
    target_sector: str = ""

    # MITRE ATT&CK
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_subtechniques: List[str] = field(default_factory=list)

    # Malware specifics
    malware_family: str = ""
    malware_type: str = ""            # ransomware/trojan/backdoor/worm/rat
    c2_servers: List[str] = field(default_factory=list)
    persistence_methods: List[str] = field(default_factory=list)
    evasion_techniques: List[str] = field(default_factory=list)
    lateral_movement: List[str] = field(default_factory=list)

    # CVE specifics
    cvss_score: float = 0.0
    affected_software: List[str] = field(default_factory=list)
    exploit_available: bool = False

    # Generation hints
    recommended_tools: List[str] = field(default_factory=list)
    recommended_rules: List[str] = field(default_factory=list)

    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def ioc_count(self) -> int:
        return (len(self.ips) + len(self.domains) + len(self.urls) +
                len(self.file_hashes) + len(self.cve_ids))

    @property
    def has_network_iocs(self) -> bool:
        return bool(self.ips or self.domains or self.urls or self.c2_servers)

    @property
    def has_file_iocs(self) -> bool:
        return bool(self.file_hashes or self.file_paths)

    def to_dict(self) -> Dict:
        return {k: v for k, v in vars(self).items()}


# ── IOC Extraction Patterns ───────────────────────────────────
class IOCExtractor:
    """Regex-based IOC extraction from text."""

    # IPv4 (not private ranges for threat intel context, but we include all)
    IP_RE = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    # Domain (not IPs, minimum 2 labels)
    DOMAIN_RE = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+(?:com|net|org|io|ru|cn|tk|pw|xyz|top|online|site|info|biz'
        r'|co|uk|de|fr|jp|kr|br|in|me|cc|tv|club|live|space|shop|app'
        r'|tech|ai|gov|edu|mil|int)\b',
        re.IGNORECASE
    )
    # URL
    URL_RE = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
    # MD5
    MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')
    # SHA1
    SHA1_RE = re.compile(r'\b[a-fA-F0-9]{40}\b')
    # SHA256
    SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
    # CVE
    CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE)
    # Email
    EMAIL_RE = re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b')
    # Windows registry
    REG_RE = re.compile(r'HK(?:EY_)?(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)[\\\/][^\s"\']+', re.IGNORECASE)
    # File paths
    WIN_PATH_RE = re.compile(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*')
    UNIX_PATH_RE = re.compile(r'(?:^|[\s"])(/(?:[a-zA-Z0-9._-]+/)*[a-zA-Z0-9._-]+)(?:[\s"]|$)')
    # MITRE techniques
    MITRE_RE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')

    def extract_from_text(self, text: str) -> Dict[str, List[str]]:
        """Extract all IOCs from freeform text."""
        if not text:
            return {}

        results = {
            "ips": list(set(self.IP_RE.findall(text))),
            "urls": list(set(self.URL_RE.findall(text))),
            "file_hashes": list(set(
                self.MD5_RE.findall(text) +
                self.SHA1_RE.findall(text) +
                self.SHA256_RE.findall(text)
            )),
            "cve_ids": list(set(self.CVE_RE.findall(text))),
            "email_addresses": list(set(self.EMAIL_RE.findall(text))),
            "registry_keys": list(set(self.REG_RE.findall(text))),
            "file_paths": list(set(
                self.WIN_PATH_RE.findall(text) + self.UNIX_PATH_RE.findall(text)
            )),
            "mitre_techniques": list(set(self.MITRE_RE.findall(text))),
        }

        # Domains — filter out IPs and too-short strings
        raw_domains = self.DOMAIN_RE.findall(text)
        results["domains"] = [
            d for d in set(raw_domains)
            if d not in results["ips"] and len(d) > 4
            and not d.replace(".", "").isdigit()
        ]

        # Remove URLs from domains (overlap)
        url_domains = set()
        for url in results["urls"]:
            m = re.match(r'https?://([^/]+)', url)
            if m:
                url_domains.add(m.group(1).split(":")[0])
        results["domains"] = [d for d in results["domains"] if d not in url_domains]

        return {k: v for k, v in results.items() if v}


# ── MITRE Mapper ──────────────────────────────────────────────
class MITREMapper:
    """Maps threat behaviors and keywords to MITRE ATT&CK framework."""

    TACTIC_MAP = {
        "initial_access": ["phishing", "spearphish", "watering hole", "supply chain", "exploit public", "drive-by"],
        "execution": ["powershell", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "macro", "script"],
        "persistence": ["registry run", "startup folder", "scheduled task", "service install", "boot", "autorun", "cron"],
        "privilege_escalation": ["uac bypass", "token impersonation", "privilege escalat", "sudo", "suid", "exploit local"],
        "defense_evasion": ["obfuscat", "encode", "base64", "pack", "antivirus bypass", "av evasion", "sandbox", "timestomp"],
        "credential_access": ["credential dump", "mimikatz", "lsass", "keylog", "password spray", "brute force", "kerberoast"],
        "discovery": ["network scan", "port scan", "enum", "whoami", "ipconfig", "netstat", "systeminfo", "ldap"],
        "lateral_movement": ["pass the hash", "pth", "rdp", "smb", "wmi", "psexec", "lateral", "pivot"],
        "collection": ["data staging", "screen capture", "keylog", "clipboard", "email collect", "archive"],
        "command_and_control": ["c2", "c&c", "beacon", "cobaltstrike", "cobalt strike", "metasploit", "rat", "reverse shell"],
        "exfiltration": ["exfiltrat", "data theft", "data leak", "ftp upload", "dns tunnel", "http post"],
        "impact": ["ransomware", "encrypt", "wipe", "destroy", "ddos", "defac", "data destruct"],
    }

    TECHNIQUE_MAP = {
        "T1566": ["phishing", "spearphish"],
        "T1059": ["powershell", "cmd.exe", "command interpreter"],
        "T1053": ["scheduled task", "cron job", "at command"],
        "T1547": ["registry run key", "startup folder", "autorun"],
        "T1548": ["uac bypass", "privilege escalation"],
        "T1003": ["credential dump", "lsass", "mimikatz", "sam database"],
        "T1110": ["brute force", "password spray", "credential stuffing"],
        "T1071": ["application layer protocol", "http c2", "dns c2"],
        "T1486": ["ransomware", "file encryption", "data encrypted for impact"],
        "T1041": ["exfiltration over c2", "exfiltration"],
        "T1078": ["valid accounts", "stolen credentials"],
        "T1021": ["remote services", "rdp", "smb", "ssh lateral"],
        "T1055": ["process injection", "dll injection", "shellcode"],
        "T1082": ["system information discovery", "systeminfo", "os fingerprint"],
        "T1190": ["exploit public-facing", "web exploit", "cve exploit"],
        "T1133": ["external remote services", "vpn abuse", "rdp external"],
        "T1046": ["network service scan", "port scan", "nmap"],
        "T1027": ["obfuscated files", "encoded payload", "base64 encode"],
        "T1204": ["user execution", "malicious file", "malicious link click"],
        "T1105": ["ingress tool transfer", "download tool", "certutil", "bitsadmin"],
    }

    def map_text(self, text: str) -> Tuple[List[str], List[str]]:
        """Returns (tactics, techniques) matched from text."""
        text_lower = text.lower()
        tactics = []
        techniques = []

        for tactic, keywords in self.TACTIC_MAP.items():
            if any(kw in text_lower for kw in keywords):
                tactics.append(tactic)

        for technique_id, keywords in self.TECHNIQUE_MAP.items():
            if any(kw in text_lower for kw in keywords):
                techniques.append(technique_id)

        # Also extract explicit Txxxx IDs from text
        explicit = re.findall(r'\bT\d{4}(?:\.\d{3})?\b', text)
        techniques = list(set(techniques + explicit))

        return list(set(tactics)), techniques


# ── Threat Parsing Engine ─────────────────────────────────────
class ThreatParsingEngine:
    """
    Main parsing engine.
    Accepts raw input (dict, JSON string, or free text) and returns
    a normalized ParsedThreatIntel object.
    """

    def __init__(self):
        self.extractor = IOCExtractor()
        self.mitre_mapper = MITREMapper()
        logger.info("[ThreatParser] Initialized")

    def parse(self, raw_input: Any, source_type: str = "unknown") -> ParsedThreatIntel:
        """Parse any raw threat intelligence input."""
        intel = ParsedThreatIntel(source_type=source_type)

        # Normalize to dict
        if isinstance(raw_input, str):
            try:
                data = json.loads(raw_input)
            except json.JSONDecodeError:
                data = {"raw_text": raw_input}
        elif isinstance(raw_input, dict):
            data = raw_input
        else:
            data = {"raw_text": str(raw_input)}

        intel.raw_input = json.dumps(data, default=str)[:5000]

        # Extract from structured fields first
        self._parse_structured(intel, data)

        # Extract from all text content
        all_text = self._flatten_to_text(data)
        self._parse_text(intel, all_text)

        # Map to MITRE
        full_text = all_text + " " + " ".join(intel.threat_categories)
        tactics, techniques = self.mitre_mapper.map_text(full_text)
        intel.mitre_tactics = list(set(intel.mitre_tactics + tactics))
        intel.mitre_techniques = list(set(intel.mitre_techniques + techniques))

        # Determine recommended tool types
        intel.recommended_tools = self._recommend_tools(intel)
        intel.recommended_rules = self._recommend_rules(intel)

        logger.info(
            f"[ThreatParser] Parsed: level={intel.threat_level} "
            f"iocs={intel.ioc_count} techniques={len(intel.mitre_techniques)} "
            f"tools={intel.recommended_tools}"
        )
        return intel

    def _parse_structured(self, intel: ParsedThreatIntel, data: Dict) -> None:
        """Extract from known structured fields."""
        intel.threat_level = str(data.get("threat_level", data.get("severity", "UNKNOWN"))).upper()
        intel.threat_score = int(data.get("threat_score", data.get("cvss_score", 0)) or 0)
        intel.is_malicious = bool(data.get("is_malicious", False))
        intel.threat_actor = str(data.get("threat_actor", "")).strip()
        intel.malware_family = str(data.get("malware_family", "")).strip()
        intel.malware_type = str(data.get("malware_type", "")).strip().lower()
        intel.threat_description = str(data.get("summary", data.get("description", ""))).strip()[:2000]
        intel.cvss_score = float(data.get("cvss_score", 0) or 0)
        intel.exploit_available = bool(data.get("exploit_available", False))

        # Lists
        cats = data.get("threat_categories", data.get("categories", []))
        intel.threat_categories = [str(c).lower() for c in (cats if isinstance(cats, list) else [])]

        techniques = data.get("mitre_techniques", data.get("attack_techniques", []))
        intel.mitre_techniques = [str(t) for t in (techniques if isinstance(techniques, list) else [])]

        affected = data.get("affected_systems", data.get("affected_software", []))
        intel.affected_software = [str(a) for a in (affected if isinstance(affected, list) else [])]

        persist = data.get("persistence_mechanisms", [])
        intel.persistence_methods = [str(p) for p in (persist if isinstance(persist, list) else [])]

        # IOCs from structured fields
        iocs = data.get("indicators_of_compromise", data.get("iocs", []))
        if isinstance(iocs, list):
            for ioc in iocs:
                if isinstance(ioc, str):
                    self._classify_and_add_ioc(intel, ioc)

        # Network indicators
        net = data.get("network_indicators", data.get("c2_servers", []))
        if isinstance(net, list):
            for item in net:
                if isinstance(item, str):
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', item):
                        if item not in intel.c2_servers:
                            intel.c2_servers.append(item)
                    else:
                        if item not in intel.domains:
                            intel.domains.append(item)

    def _parse_text(self, intel: ParsedThreatIntel, text: str) -> None:
        """Extract IOCs from freeform text."""
        extracted = self.extractor.extract_from_text(text)

        def merge(existing: list, new: list) -> list:
            combined = list(set(existing + new))
            return combined[:200]  # Cap at 200 per type

        intel.ips = merge(intel.ips, extracted.get("ips", []))
        intel.domains = merge(intel.domains, extracted.get("domains", []))
        intel.urls = merge(intel.urls, extracted.get("urls", []))
        intel.file_hashes = merge(intel.file_hashes, extracted.get("file_hashes", []))
        intel.cve_ids = merge(intel.cve_ids, extracted.get("cve_ids", []))
        intel.email_addresses = merge(intel.email_addresses, extracted.get("email_addresses", []))
        intel.registry_keys = merge(intel.registry_keys, extracted.get("registry_keys", []))
        intel.file_paths = merge(intel.file_paths, extracted.get("file_paths", []))
        explicit_techniques = extracted.get("mitre_techniques", [])
        intel.mitre_techniques = list(set(intel.mitre_techniques + explicit_techniques))

    def _classify_and_add_ioc(self, intel: ParsedThreatIntel, value: str) -> None:
        """Add an IOC to the appropriate list."""
        value = value.strip()
        if not value:
            return
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            if value not in intel.ips:
                intel.ips.append(value)
        elif re.match(r'^[a-fA-F0-9]{32,64}$', value):
            if value not in intel.file_hashes:
                intel.file_hashes.append(value)
        elif value.upper().startswith("CVE-"):
            if value not in intel.cve_ids:
                intel.cve_ids.append(value)
        elif value.startswith(("http://", "https://")):
            if value not in intel.urls:
                intel.urls.append(value)
        elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            if value not in intel.domains:
                intel.domains.append(value)

    def _flatten_to_text(self, data: Any, depth: int = 0) -> str:
        """Recursively extract all string values from a nested structure."""
        if depth > 5:
            return ""
        if isinstance(data, str):
            return data
        if isinstance(data, (int, float, bool)):
            return str(data)
        if isinstance(data, list):
            return " ".join(self._flatten_to_text(item, depth + 1) for item in data)
        if isinstance(data, dict):
            return " ".join(self._flatten_to_text(v, depth + 1) for v in data.values())
        return str(data)

    def _recommend_tools(self, intel: ParsedThreatIntel) -> List[str]:
        """Decide what tool types to generate based on intelligence."""
        tools = []
        if intel.has_network_iocs:
            tools.append("network_ioc_scanner")
        if intel.file_hashes:
            tools.append("file_hash_scanner")
        if intel.cve_ids:
            tools.append("vulnerability_scanner")
        if intel.malware_type in ("ransomware", "trojan", "backdoor", "rat", "worm"):
            tools.append("malware_detector")
            tools.append("behavior_monitor")
        if "credential" in " ".join(intel.threat_categories):
            tools.append("credential_monitor")
        if intel.c2_servers or any("c2" in t.lower() or "command" in t.lower() for t in intel.mitre_tactics):
            tools.append("c2_detector")
        if not tools:
            tools.append("generic_threat_hunter")
        return tools

    def _recommend_rules(self, intel: ParsedThreatIntel) -> List[str]:
        """Decide what detection rules to generate."""
        rules = []
        if intel.file_hashes or intel.file_paths or intel.registry_keys:
            rules.append("yara")
        if intel.has_network_iocs or intel.mitre_techniques:
            rules.append("sigma")
        if intel.ips or intel.domains:
            rules.append("snort")
            rules.append("suricata")
        if not rules:
            rules.append("sigma")
        return rules
