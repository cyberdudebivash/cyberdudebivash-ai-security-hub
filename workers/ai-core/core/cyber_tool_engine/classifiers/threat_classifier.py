# ============================================================
# CYBERDUDEBIVASH AI — THREAT CLASSIFICATION ENGINE
# Categorizes threats: malware family, attack pattern, target sector
# Maps to MITRE ATT&CK, assigns generation priority
# ============================================================

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from core.cyber_tool_engine.parsers.threat_parser import ParsedThreatIntel
from core.logging_config import get_logger

logger = get_logger("cyber_tool_engine.classifier")


@dataclass
class ThreatClassification:
    """Full classification result for a piece of threat intelligence."""
    # Primary classification
    primary_category: str = ""      # malware/phishing/exploit/botnet/apt/insider/ddos
    subcategory: str = ""           # ransomware/rat/keylogger/dropper/etc.
    attack_phase: str = ""          # initial_access/execution/persistence/etc.

    # Severity
    severity: str = "MEDIUM"
    urgency: str = "NORMAL"         # CRITICAL/HIGH/NORMAL/LOW
    confidence: float = 0.7

    # MITRE
    primary_tactic: str = ""
    technique_ids: List[str] = field(default_factory=list)
    kill_chain_phase: str = ""

    # Target
    target_os: List[str] = field(default_factory=list)    # windows/linux/macos/android
    target_sector: str = ""
    target_asset: str = ""           # endpoint/server/network/cloud/iot

    # Generation
    generation_priority: int = 5     # 1=highest, 10=lowest
    tool_complexity: str = "medium"  # simple/medium/complex
    estimated_tools: int = 1

    def to_dict(self) -> Dict:
        return vars(self)


class ThreatClassifier:
    """
    Multi-dimensional threat classifier.
    Combines keyword analysis, IOC types, and MITRE mapping
    to produce actionable classification.
    """

    # Category keywords
    CATEGORY_RULES = {
        "ransomware": {
            "keywords": ["ransomware", "encrypt", "ransom", "bitcoin", "decrypt", "locky",
                        "wannacry", "revil", "lockbit", "ryuk", "darkside", "maze", "conti"],
            "parent": "malware", "urgency": "CRITICAL", "priority": 1,
        },
        "rat": {
            "keywords": ["rat", "remote access trojan", "njrat", "quasar", "asyncrat",
                        "darkcomet", "nanocore", "remcos", "remote access tool"],
            "parent": "malware", "urgency": "HIGH", "priority": 2,
        },
        "backdoor": {
            "keywords": ["backdoor", "back door", "shellcode", "reverse shell", "bind shell",
                        "meterpreter", "cobaltstrike", "cobalt strike", "beacon"],
            "parent": "malware", "urgency": "HIGH", "priority": 2,
        },
        "trojan": {
            "keywords": ["trojan", "banker", "stealer", "infostealer", "emotet", "trickbot",
                        "dridex", "formbook", "agent tesla", "azorult"],
            "parent": "malware", "urgency": "HIGH", "priority": 2,
        },
        "worm": {
            "keywords": ["worm", "self-propagat", "network spread", "smb spread", "ms17-010"],
            "parent": "malware", "urgency": "CRITICAL", "priority": 1,
        },
        "dropper": {
            "keywords": ["dropper", "loader", "downloader", "stager", "bumblebee",
                        "guloader", "smokeloader", "privateloader"],
            "parent": "malware", "urgency": "HIGH", "priority": 3,
        },
        "rootkit": {
            "keywords": ["rootkit", "kernel", "ring 0", "bootkit", "uefi", "firmware"],
            "parent": "malware", "urgency": "CRITICAL", "priority": 1,
        },
        "botnet": {
            "keywords": ["botnet", "bot", "zombie", "c2", "command and control", "mirai",
                        "emotet botnet", "ddos bot", "irc bot"],
            "parent": "botnet", "urgency": "HIGH", "priority": 2,
        },
        "phishing": {
            "keywords": ["phishing", "spearphish", "credential harvest", "fake login",
                        "email lure", "social engineer"],
            "parent": "phishing", "urgency": "HIGH", "priority": 3,
        },
        "exploit": {
            "keywords": ["exploit", "cve-", "rce", "remote code execution", "lpe",
                        "local privilege escalation", "buffer overflow", "use after free",
                        "zero day", "0day", "poc", "proof of concept"],
            "parent": "exploit", "urgency": "CRITICAL", "priority": 1,
        },
        "apt": {
            "keywords": ["apt", "advanced persistent", "nation state", "state sponsored",
                        "fancy bear", "cozy bear", "lazarus", "sandworm", "equation group"],
            "parent": "apt", "urgency": "CRITICAL", "priority": 1,
        },
        "ddos": {
            "keywords": ["ddos", "denial of service", "flood", "amplification", "reflection",
                        "volumetric", "slowloris", "syn flood"],
            "parent": "ddos", "urgency": "HIGH", "priority": 3,
        },
        "credential": {
            "keywords": ["credential", "password", "hash dump", "mimikatz", "lsass",
                        "kerberoast", "pass the hash", "golden ticket"],
            "parent": "credential_theft", "urgency": "HIGH", "priority": 2,
        },
        "supply_chain": {
            "keywords": ["supply chain", "software supply", "third party", "solarwinds",
                        "npm package", "pypi", "dependency confusion"],
            "parent": "supply_chain", "urgency": "CRITICAL", "priority": 1,
        },
    }

    OS_INDICATORS = {
        "windows": ["windows", "exe", "dll", "registry", "powershell", "cmd.exe",
                   "ntfs", "hklm", "hkcu", "system32", "\\appdata\\", "tasklist"],
        "linux": ["linux", "bash", "elf", "/etc/", "/var/", "/tmp/", "cron", "chmod",
                 "sudo", "systemd", "iptables", "proc/"],
        "macos": ["macos", "osx", "mac os", ".dmg", "launchd", "plist", "mach-o",
                 "keychain", "/library/", "brew"],
        "android": ["android", "apk", "dalvik", "smali", "adb", "android.permission"],
        "ios": ["ios", "iphone", "ipad", "objective-c", "swift", ".ipa", "jailbreak"],
    }

    SECTOR_MAP = {
        "healthcare": ["hospital", "medical", "health", "patient", "pharma", "ehr"],
        "finance": ["bank", "financial", "trading", "crypto", "swift", "atm", "payment"],
        "energy": ["energy", "utility", "power grid", "scada", "ics", "oil", "gas"],
        "government": ["government", "military", "defense", "federal", "state agency"],
        "education": ["university", "school", "education", "student", "academic"],
        "technology": ["software", "tech", "saas", "cloud", "developer", "github"],
        "retail": ["retail", "ecommerce", "pos", "point of sale", "shopping"],
        "manufacturing": ["manufacturing", "factory", "industrial", "ics", "ot"],
    }

    def classify(self, intel: ParsedThreatIntel) -> ThreatClassification:
        """Produce full classification from parsed threat intelligence."""
        result = ThreatClassification()

        # Combine all available text for analysis
        text = " ".join([
            intel.threat_description,
            intel.malware_type,
            intel.malware_family,
            " ".join(intel.threat_categories),
            " ".join(intel.mitre_techniques),
            " ".join(intel.persistence_methods),
            " ".join(intel.evasion_techniques),
        ]).lower()

        # Primary category classification
        primary_cat, subcat, urgency, priority = self._classify_category(text, intel)
        result.primary_category = primary_cat
        result.subcategory = subcat
        result.urgency = urgency
        result.generation_priority = priority

        # Severity mapping
        result.severity = self._map_severity(intel.threat_level, urgency)

        # OS targeting
        result.target_os = self._detect_target_os(text)

        # Sector targeting
        result.target_sector = self._detect_sector(text)

        # Primary tactic from MITRE
        result.technique_ids = intel.mitre_techniques[:20]
        result.primary_tactic = intel.mitre_tactics[0] if intel.mitre_tactics else ""
        result.attack_phase = result.primary_tactic

        # Kill chain phase
        result.kill_chain_phase = self._get_kill_chain_phase(result.primary_tactic)

        # Target asset type
        result.target_asset = self._get_target_asset(text, result.target_os)

        # Tool complexity
        result.tool_complexity = self._estimate_complexity(intel)
        result.estimated_tools = self._estimate_tool_count(intel, result)

        # Confidence
        result.confidence = self._compute_confidence(intel, result)

        logger.info(
            f"[Classifier] category={result.primary_category}/{result.subcategory} "
            f"urgency={result.urgency} OS={result.target_os} priority={result.generation_priority}"
        )
        return result

    def _classify_category(self, text: str, intel: ParsedThreatIntel) -> Tuple[str, str, str, int]:
        """Returns (primary_category, subcategory, urgency, priority)."""
        best_match = None
        best_score = 0

        for subcat, rules in self.CATEGORY_RULES.items():
            score = sum(1 for kw in rules["keywords"] if kw in text)
            if score > best_score:
                best_score = score
                best_match = (rules["parent"], subcat, rules["urgency"], rules["priority"])

        # Also check intel fields directly
        malware_type = intel.malware_type.lower()
        if malware_type in self.CATEGORY_RULES:
            rules = self.CATEGORY_RULES[malware_type]
            best_match = (rules["parent"], malware_type, rules["urgency"], rules["priority"])

        # Fallback based on IOC types
        if not best_match or best_score == 0:
            if intel.cve_ids:
                return "exploit", "vulnerability", "HIGH", 2
            if intel.has_network_iocs:
                return "network_threat", "network_ioc", "MEDIUM", 4
            if intel.file_hashes:
                return "malware", "unknown_malware", "HIGH", 3
            return "generic", "unknown", "MEDIUM", 5

        return best_match

    def _map_severity(self, threat_level: str, urgency: str) -> str:
        mapping = {
            "CRITICAL": "CRITICAL", "HIGH": "HIGH",
            "MEDIUM": "MEDIUM", "LOW": "LOW", "INFO": "INFO",
        }
        sev = mapping.get(threat_level.upper(), "MEDIUM")
        if urgency == "CRITICAL" and sev not in ("CRITICAL",):
            sev = "HIGH"
        return sev

    def _detect_target_os(self, text: str) -> List[str]:
        detected = []
        for os_name, indicators in self.OS_INDICATORS.items():
            if any(ind in text for ind in indicators):
                detected.append(os_name)
        return detected if detected else ["windows"]  # default assumption

    def _detect_sector(self, text: str) -> str:
        for sector, keywords in self.SECTOR_MAP.items():
            if any(kw in text for kw in keywords):
                return sector
        return "general"

    def _get_kill_chain_phase(self, tactic: str) -> str:
        phase_map = {
            "initial_access": "Delivery",
            "execution": "Exploitation",
            "persistence": "Installation",
            "privilege_escalation": "Exploitation",
            "defense_evasion": "Exploitation",
            "credential_access": "Exploitation",
            "discovery": "Reconnaissance",
            "lateral_movement": "Lateral Movement",
            "collection": "Actions on Objectives",
            "command_and_control": "Command & Control",
            "exfiltration": "Actions on Objectives",
            "impact": "Actions on Objectives",
        }
        return phase_map.get(tactic, "Unknown")

    def _get_target_asset(self, text: str, os_list: List[str]) -> str:
        if any(kw in text for kw in ["server", "web server", "database", "sql", "nginx", "apache"]):
            return "server"
        if any(kw in text for kw in ["iot", "router", "camera", "embedded", "scada", "plc"]):
            return "iot"
        if any(kw in text for kw in ["cloud", "aws", "azure", "gcp", "s3 bucket", "kubernetes"]):
            return "cloud"
        if any(kw in text for kw in ["network", "firewall", "switch", "router", "vpn"]):
            return "network"
        return "endpoint"

    def _estimate_complexity(self, intel: ParsedThreatIntel) -> str:
        score = 0
        score += len(intel.mitre_techniques) * 2
        score += len(intel.threat_categories)
        score += 5 if intel.has_network_iocs and intel.has_file_iocs else 0
        score += 3 if intel.c2_servers else 0
        if score > 15:
            return "complex"
        if score > 7:
            return "medium"
        return "simple"

    def _estimate_tool_count(self, intel: ParsedThreatIntel, classification: ThreatClassification) -> int:
        count = len(intel.recommended_tools) + len(intel.recommended_rules)
        return max(1, min(count, 8))  # 1-8 tools per threat

    def _compute_confidence(self, intel: ParsedThreatIntel, classification: ThreatClassification) -> float:
        score = 0.3  # base
        if intel.threat_level != "UNKNOWN":
            score += 0.2
        if intel.mitre_techniques:
            score += 0.15
        if intel.ioc_count > 0:
            score += 0.15
        if intel.malware_family or intel.malware_type:
            score += 0.1
        if intel.threat_description:
            score += 0.1
        return min(round(score, 2), 1.0)
