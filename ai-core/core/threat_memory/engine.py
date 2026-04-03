# ============================================================
# CYBERDUDEBIVASH AI — THREAT MEMORY ENGINE
# Persistent IOC tracking, pattern correlation, campaign linking,
# temporal analysis, fast indexed retrieval
# ============================================================

import json
import os
import time
import uuid
import threading
import re
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict
from core.logging_config import get_logger

logger = get_logger("threat_memory")

THREAT_MEMORY_DIR = os.getenv("MEMORY_DIR", "memory")
IOC_DB_FILE = os.path.join(THREAT_MEMORY_DIR, "ioc_database.json")
CAMPAIGN_DB_FILE = os.path.join(THREAT_MEMORY_DIR, "campaign_database.json")
PATTERN_DB_FILE = os.path.join(THREAT_MEMORY_DIR, "pattern_database.json")


class IOCRecord:
    """Represents a single Indicator of Compromise."""

    def __init__(self, value: str, ioc_type: str, source: str = "system",
                 severity: str = "UNKNOWN", context: Dict = None):
        self.id = str(uuid.uuid4())
        self.value = value.strip()[:500]
        self.ioc_type = ioc_type        # ip, domain, hash, url, email, cve
        self.source = source
        self.severity = severity
        self.context = context or {}
        self.first_seen = datetime.now(timezone.utc).isoformat()
        self.last_seen = self.first_seen
        self.seen_count = 1
        self.is_active = True
        self.tags: List[str] = []
        self.related_iocs: List[str] = []  # IDs of related IOCs
        self.campaign_id: Optional[str] = None
        self.confidence: float = 0.5

    def to_dict(self) -> Dict:
        return vars(self)

    @classmethod
    def from_dict(cls, d: Dict) -> "IOCRecord":
        obj = cls.__new__(cls)
        obj.__dict__.update(d)
        return obj


class ThreatCampaign:
    """Links multiple IOCs into a coordinated threat campaign."""

    def __init__(self, name: str, description: str = ""):
        self.id = str(uuid.uuid4())
        self.name = name
        self.description = description
        self.ioc_ids: List[str] = []
        self.first_seen = datetime.now(timezone.utc).isoformat()
        self.last_activity = self.first_seen
        self.severity = "UNKNOWN"
        self.threat_actor: Optional[str] = None
        self.tactics: List[str] = []      # MITRE ATT&CK tactics
        self.techniques: List[str] = []   # MITRE ATT&CK techniques
        self.active = True

    def to_dict(self) -> Dict:
        return vars(self)

    @classmethod
    def from_dict(cls, d: Dict) -> "ThreatCampaign":
        obj = cls.__new__(cls)
        obj.__dict__.update(d)
        return obj


class ThreatPatternEngine:
    """
    Detects patterns across IOCs:
    - IP subnet clustering
    - Domain TLD/registrar correlation
    - Hash similarity
    - Temporal clustering (bursts)
    """

    def detect_subnet(self, ip: str) -> Optional[str]:
        """Extract /24 subnet from IP."""
        parts = ip.split(".")
        if len(parts) == 4:
            try:
                [int(p) for p in parts]
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            except ValueError:
                pass
        return None

    def detect_domain_pattern(self, domain: str) -> Optional[str]:
        """Extract TLD and second-level domain pattern."""
        parts = domain.split(".")
        if len(parts) >= 2:
            return f"*.{'.'.join(parts[-2:])}"
        return None

    def cluster_by_time(self, timestamps: List[str], window_hours: int = 24) -> List[List[str]]:
        """Group timestamps into time windows (burst detection)."""
        if not timestamps:
            return []
        parsed = []
        for ts in timestamps:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                parsed.append((ts, dt))
            except Exception:
                continue

        parsed.sort(key=lambda x: x[1])
        clusters = []
        current_cluster = []
        window = timedelta(hours=window_hours)

        for ts, dt in parsed:
            if not current_cluster:
                current_cluster.append(ts)
            else:
                last_dt = datetime.fromisoformat(current_cluster[-1].replace("Z", "+00:00"))
                if dt - last_dt <= window:
                    current_cluster.append(ts)
                else:
                    clusters.append(current_cluster)
                    current_cluster = [ts]

        if current_cluster:
            clusters.append(current_cluster)

        return [c for c in clusters if len(c) > 1]


class ThreatMemoryEngine:
    """
    Full threat intelligence memory system.
    Persistent IOC database with indexed search, correlation, and campaign linking.
    """

    def __init__(self):
        os.makedirs(THREAT_MEMORY_DIR, exist_ok=True)
        self._lock = threading.RLock()
        self._iocs: Dict[str, IOCRecord] = {}           # id → IOCRecord
        self._ioc_value_index: Dict[str, str] = {}      # value → id
        self._ioc_type_index: Dict[str, Set[str]] = defaultdict(set)  # type → set(ids)
        self._ioc_severity_index: Dict[str, Set[str]] = defaultdict(set)
        self._campaigns: Dict[str, ThreatCampaign] = {}
        self._patterns: Dict[str, Dict] = {}             # pattern → {count, ioc_ids}
        self._pattern_engine = ThreatPatternEngine()
        self._load_all()
        logger.info(f"[ThreatMemory] Loaded {len(self._iocs)} IOCs, {len(self._campaigns)} campaigns")

    # ── IOC Management ────────────────────────────────────────

    def ingest_ioc(self, value: str, ioc_type: str, severity: str = "UNKNOWN",
                   source: str = "system", context: Dict = None,
                   tags: List[str] = None) -> IOCRecord:
        """Add or update an IOC. Returns the IOC record."""
        value = value.strip()
        if not value:
            raise ValueError("IOC value cannot be empty")

        with self._lock:
            # Check for existing IOC
            existing_id = self._ioc_value_index.get(value)
            if existing_id:
                ioc = self._iocs[existing_id]
                ioc.seen_count += 1
                ioc.last_seen = datetime.now(timezone.utc).isoformat()
                if severity != "UNKNOWN":
                    ioc.severity = severity
                if context:
                    ioc.context.update(context)
                if tags:
                    ioc.tags = list(set(ioc.tags + tags))
                logger.debug(f"[ThreatMemory] Updated IOC: {value} (seen={ioc.seen_count})")
            else:
                ioc = IOCRecord(value, ioc_type, source, severity, context)
                if tags:
                    ioc.tags = tags
                self._iocs[ioc.id] = ioc
                self._ioc_value_index[value] = ioc.id
                self._ioc_type_index[ioc_type].add(ioc.id)
                self._ioc_severity_index[severity].add(ioc.id)
                logger.info(f"[ThreatMemory] New IOC: {ioc_type}:{value} severity={severity}")

            # Auto-detect patterns
            self._detect_and_index_pattern(ioc)

            # Persist
            self._save_iocs()

        return ioc

    def ingest_from_analysis(self, analysis_result: Dict, target: str = "") -> List[IOCRecord]:
        """
        Extract and ingest IOCs from a threat intel analysis result dict.
        """
        ingested = []
        try:
            output = analysis_result.get("output", analysis_result)

            # Extract IOCs from indicators_of_compromise
            for ioc_val in output.get("indicators_of_compromise", []):
                if ioc_val and isinstance(ioc_val, str):
                    ioc_type = self._auto_detect_type(ioc_val)
                    severity = output.get("threat_level", "UNKNOWN")
                    ioc = self.ingest_ioc(ioc_val, ioc_type, severity, "analysis",
                                         context={"source_analysis": str(target)[:100]})
                    ingested.append(ioc)

            # Also ingest the primary target if malicious
            if target and output.get("is_malicious"):
                tgt_type = self._auto_detect_type(target)
                severity = output.get("threat_level", "MEDIUM")
                ioc = self.ingest_ioc(target, tgt_type, severity, "direct_analysis",
                                      context=output,
                                      tags=output.get("threat_categories", []))
                ingested.append(ioc)

        except Exception as e:
            logger.warning(f"[ThreatMemory] IOC extraction failed: {e}")

        return ingested

    def _auto_detect_type(self, value: str) -> str:
        import socket
        try:
            socket.inet_aton(value)
            return "ip"
        except OSError:
            pass
        if re.match(r"^[a-fA-F0-9]{32,64}$", value):
            return "hash"
        if value.upper().startswith("CVE-"):
            return "cve"
        if value.startswith(("http://", "https://")):
            return "url"
        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value):
            return "domain"
        return "unknown"

    def _detect_and_index_pattern(self, ioc: IOCRecord) -> None:
        """Detect patterns (subnet, domain family) and index them."""
        pattern = None
        if ioc.ioc_type in ("ip", "ip_address"):
            pattern = self._pattern_engine.detect_subnet(ioc.value)
        elif ioc.ioc_type in ("domain",):
            pattern = self._pattern_engine.detect_domain_pattern(ioc.value)

        if pattern:
            if pattern not in self._patterns:
                self._patterns[pattern] = {"count": 0, "ioc_ids": [], "type": ioc.ioc_type}
            self._patterns[pattern]["count"] += 1
            if ioc.id not in self._patterns[pattern]["ioc_ids"]:
                self._patterns[pattern]["ioc_ids"].append(ioc.id)

    # ── Search & Retrieval ────────────────────────────────────

    def lookup(self, value: str) -> Optional[IOCRecord]:
        """Fast O(1) lookup by IOC value."""
        with self._lock:
            ioc_id = self._ioc_value_index.get(value.strip())
            return self._iocs.get(ioc_id) if ioc_id else None

    def is_known_malicious(self, value: str) -> Tuple[bool, str]:
        """Returns (is_malicious, severity)."""
        ioc = self.lookup(value)
        if not ioc:
            return False, "UNKNOWN"
        malicious_severities = {"CRITICAL", "HIGH", "MEDIUM"}
        return ioc.severity in malicious_severities, ioc.severity

    def search(self, query: str = None, ioc_type: str = None,
               severity: str = None, limit: int = 50) -> List[IOCRecord]:
        """Search IOCs with optional filters."""
        with self._lock:
            results = []

            if ioc_type:
                candidate_ids = self._ioc_type_index.get(ioc_type, set())
            elif severity:
                candidate_ids = self._ioc_severity_index.get(severity, set())
            else:
                candidate_ids = set(self._iocs.keys())

            for ioc_id in candidate_ids:
                ioc = self._iocs.get(ioc_id)
                if not ioc:
                    continue
                if query and query.lower() not in ioc.value.lower():
                    continue
                if severity and ioc.severity != severity:
                    continue
                results.append(ioc)

            # Sort by last_seen descending
            results.sort(key=lambda x: x.last_seen, reverse=True)
            return results[:limit]

    def get_active_threats(self, limit: int = 100) -> List[IOCRecord]:
        """Get most recently seen active IOCs."""
        with self._lock:
            active = [ioc for ioc in self._iocs.values() if ioc.is_active]
            active.sort(key=lambda x: x.last_seen, reverse=True)
            return active[:limit]

    # ── Campaign Management ────────────────────────────────────

    def create_campaign(self, name: str, ioc_ids: List[str],
                        threat_actor: str = None,
                        techniques: List[str] = None) -> ThreatCampaign:
        """Link multiple IOCs into a threat campaign."""
        with self._lock:
            campaign = ThreatCampaign(name)
            campaign.ioc_ids = [i for i in ioc_ids if i in self._iocs]
            campaign.threat_actor = threat_actor
            campaign.techniques = techniques or []

            # Compute campaign severity from IOC severities
            severity_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "UNKNOWN": 0}
            max_sev = 0
            for ioc_id in campaign.ioc_ids:
                ioc = self._iocs.get(ioc_id)
                if ioc:
                    max_sev = max(max_sev, severity_rank.get(ioc.severity, 0))
                    ioc.campaign_id = campaign.id

            reverse_rank = {v: k for k, v in severity_rank.items()}
            campaign.severity = reverse_rank.get(max_sev, "UNKNOWN")

            self._campaigns[campaign.id] = campaign
            self._save_campaigns()
            logger.info(f"[ThreatMemory] Campaign created: {name} ({len(campaign.ioc_ids)} IOCs)")
            return campaign

    def get_campaign(self, campaign_id: str) -> Optional[ThreatCampaign]:
        with self._lock:
            return self._campaigns.get(campaign_id)

    # ── Pattern Correlation ────────────────────────────────────

    def get_related_iocs(self, value: str) -> List[IOCRecord]:
        """Find IOCs related to the given value via pattern correlation."""
        with self._lock:
            ioc = self.lookup(value)
            if not ioc:
                return []

            related_ids: Set[str] = set()

            # Find via patterns
            for pattern, data in self._patterns.items():
                if ioc.id in data["ioc_ids"]:
                    related_ids.update(data["ioc_ids"])

            # Find via campaign
            if ioc.campaign_id:
                campaign = self._campaigns.get(ioc.campaign_id)
                if campaign:
                    related_ids.update(campaign.ioc_ids)

            # Find via explicit relationships
            related_ids.update(ioc.related_iocs)

            # Remove self
            related_ids.discard(ioc.id)

            return [self._iocs[rid] for rid in related_ids if rid in self._iocs]

    def get_active_patterns(self, min_count: int = 2) -> List[Dict]:
        """Return detected patterns with minimum IOC count."""
        with self._lock:
            return [
                {"pattern": p, **data}
                for p, data in self._patterns.items()
                if data["count"] >= min_count
            ]

    # ── Statistics ────────────────────────────────────────────

    def statistics(self) -> Dict:
        with self._lock:
            type_breakdown = {k: len(v) for k, v in self._ioc_type_index.items()}
            severity_breakdown = {k: len(v) for k, v in self._ioc_severity_index.items()}
            return {
                "total_iocs": len(self._iocs),
                "active_iocs": sum(1 for ioc in self._iocs.values() if ioc.is_active),
                "total_campaigns": len(self._campaigns),
                "total_patterns": len(self._patterns),
                "by_type": type_breakdown,
                "by_severity": severity_breakdown,
                "storage_file": IOC_DB_FILE,
            }

    # ── Persistence ───────────────────────────────────────────

    def _save_iocs(self) -> None:
        try:
            data = {ioc_id: ioc.to_dict() for ioc_id, ioc in self._iocs.items()}
            self._atomic_save(IOC_DB_FILE, data)
        except Exception as e:
            logger.error(f"[ThreatMemory] IOC save failed: {e}")

    def _save_campaigns(self) -> None:
        try:
            data = {cid: c.to_dict() for cid, c in self._campaigns.items()}
            self._atomic_save(CAMPAIGN_DB_FILE, data)
        except Exception as e:
            logger.error(f"[ThreatMemory] Campaign save failed: {e}")

    def _atomic_save(self, path: str, data: Any) -> None:
        import tempfile, fcntl
        dir_path = os.path.dirname(path)
        os.makedirs(dir_path, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", dir=dir_path, delete=False, suffix=".tmp") as tf:
            try:
                fcntl.flock(tf, fcntl.LOCK_EX)
                json.dump(data, tf, indent=2, default=str)
                tf.flush()
                os.fsync(tf.fileno())
            finally:
                fcntl.flock(tf, fcntl.LOCK_UN)
        os.replace(tf.name, path)

    def _load_all(self) -> None:
        # Load IOCs
        if os.path.exists(IOC_DB_FILE):
            try:
                with open(IOC_DB_FILE) as f:
                    data = json.load(f)
                for ioc_id, ioc_data in data.items():
                    ioc = IOCRecord.from_dict(ioc_data)
                    self._iocs[ioc_id] = ioc
                    self._ioc_value_index[ioc.value] = ioc_id
                    self._ioc_type_index[ioc.ioc_type].add(ioc_id)
                    self._ioc_severity_index[ioc.severity].add(ioc_id)
                    self._detect_and_index_pattern(ioc)
            except Exception as e:
                logger.warning(f"[ThreatMemory] IOC load failed: {e}")

        # Load campaigns
        if os.path.exists(CAMPAIGN_DB_FILE):
            try:
                with open(CAMPAIGN_DB_FILE) as f:
                    data = json.load(f)
                for cid, cdata in data.items():
                    self._campaigns[cid] = ThreatCampaign.from_dict(cdata)
            except Exception as e:
                logger.warning(f"[ThreatMemory] Campaign load failed: {e}")


# ── Singleton ─────────────────────────────────────────────────
_threat_memory: Optional[ThreatMemoryEngine] = None
_tm_lock = threading.Lock()


def get_threat_memory() -> ThreatMemoryEngine:
    global _threat_memory
    if _threat_memory is None:
        with _tm_lock:
            if _threat_memory is None:
                _threat_memory = ThreatMemoryEngine()
    return _threat_memory
