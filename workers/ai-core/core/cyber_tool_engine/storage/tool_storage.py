from typing import Any, Dict, List, Optional, Tuple
# ============================================================
# CYBERDUDEBIVASH AI — TOOL STORAGE, VALIDATOR & IMPROVEMENT LOOP
# Persists generated tools, validates quality, tracks versions,
# deduplicates, and feeds learning back into the generation pipeline
# ============================================================

import hashlib
import json
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from core.logging_config import get_logger

logger = get_logger("cyber_tool_engine.storage")

TOOLS_OUTPUT_DIR = os.getenv("TOOLS_OUTPUT_DIR", "tools_output")
CATALOG_FILE = os.path.join(TOOLS_OUTPUT_DIR, "tool_catalog.json")


# ── Tool Record ───────────────────────────────────────────────
@dataclass
class GeneratedTool:
    """Represents a single generated cybersecurity artifact."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tool_type: str = ""          # yara/sigma/snort/suricata/python_scanner/playbook
    category: str = ""           # tool/rule/playbook
    name: str = ""
    threat_name: str = ""
    threat_level: str = ""
    content_hash: str = ""       # SHA256 of content — for deduplication
    file_path: str = ""
    version: int = 1
    quality_score: float = 0.0   # 0-1
    is_validated: bool = False
    validation_errors: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    monetization_tier: str = "free"  # free/pro/enterprise
    download_count: int = 0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict:
        return vars(self)

    @classmethod
    def from_dict(cls, d: Dict) -> "GeneratedTool":
        obj = cls.__new__(cls)
        obj.__dict__.update(d)
        return obj


# ── Quality Validator ─────────────────────────────────────────
class ToolValidator:
    """
    Validates generated tools before storing and releasing.
    Checks: content completeness, syntax hints, security, usability.
    """

    def validate(self, tool_type: str, content: str) -> Tuple:
        """Returns (is_valid, quality_score 0-1, list_of_errors)."""
        errors = []
        score = 1.0

        if not content or len(content.strip()) < 50:
            return False, 0.0, ["Content is empty or too short"]

        if tool_type == "yara":
            is_ok, s, e = self._validate_yara(content)
            return is_ok, s, e

        elif tool_type == "sigma":
            is_ok, s, e = self._validate_sigma(content)
            return is_ok, s, e

        elif tool_type in ("snort", "suricata"):
            is_ok, s, e = self._validate_network_rule(content, tool_type)
            return is_ok, s, e

        elif tool_type in ("network_ioc_scanner", "file_hash_scanner", "behavior_monitor", "generic_threat_hunter"):
            is_ok, s, e = self._validate_python(content)
            return is_ok, s, e

        elif tool_type in ("ir_playbook", "soc_workflow"):
            is_ok, s, e = self._validate_playbook(content)
            return is_ok, s, e

        return True, score, errors

    def _validate_yara(self, content: str) -> tuple:
        errors = []
        score = 1.0

        if "rule " not in content:
            errors.append("Missing 'rule' keyword")
            score -= 0.5
        if "meta:" not in content:
            errors.append("Missing meta section")
            score -= 0.1
        if "strings:" not in content:
            errors.append("Missing strings section — rule may have no detection logic")
            score -= 0.2
        if "condition:" not in content:
            errors.append("Missing condition section — rule will not work")
            score -= 0.5
            return False, max(0.0, score), errors
        if "author" not in content:
            errors.append("Missing author in meta")
            score -= 0.05
        if '/*' not in content and '//' not in content:
            errors.append("Missing comments")
            score -= 0.05

        # Check for dangerous patterns
        if 'eval(' in content or 'exec(' in content:
            errors.append("Dangerous code pattern in YARA rule")
            return False, 0.0, errors

        return len(errors) == 0 or score > 0.5, max(0.0, score), errors

    def _validate_sigma(self, content: str) -> tuple:
        errors = []
        score = 1.0

        required = ["title:", "logsource:", "detection:", "condition:"]
        for req in required:
            if req not in content:
                errors.append(f"Missing required field: {req}")
                score -= 0.25

        if "level:" not in content:
            errors.append("Missing severity level")
            score -= 0.1
        if "tags:" not in content:
            errors.append("Missing MITRE tags")
            score -= 0.1

        return score > 0.5, max(0.0, score), errors

    def _validate_network_rule(self, content: str, rule_type: str) -> tuple:
        errors = []
        score = 1.0

        if "alert " not in content and "drop " not in content:
            errors.append("No alert or drop actions found")
            score -= 0.5
        if "msg:" not in content:
            errors.append("Missing msg field")
            score -= 0.3
        if "sid:" not in content:
            errors.append("Missing sid field")
            score -= 0.3

        line_count = content.count('\nalert ')
        if line_count == 0:
            errors.append("No valid rules generated")
            return False, 0.0, errors

        return score > 0.5, max(0.0, score), errors

    def _validate_python(self, content: str) -> tuple:
        errors = []
        score = 1.0

        required = ["def main(", "if __name__ == \"__main__\":", "argparse", "sys.exit"]
        for req in required:
            if req not in content:
                errors.append(f"Missing: {req}")
                score -= 0.15

        # Security checks — ensure no self-harm patterns in generated tools
        dangerous = ["os.remove(/", "shutil.rmtree(/", "subprocess.call(\x27rm -rf"]
        for danger in dangerous:
            if danger in content:
                errors.append(f"Potentially dangerous pattern: {danger}")
                score -= 0.3

        # Must have comments
        if content.count('#') < 5:
            errors.append("Insufficient documentation/comments")
            score -= 0.1

        # Must have error handling
        if "except" not in content:
            errors.append("No error handling found")
            score -= 0.2

        return score > 0.4, max(0.0, score), errors

    def _validate_playbook(self, content: str) -> tuple:
        errors = []
        score = 1.0

        required_sections = ["## ", "- [ ]", "Phase", "---"]
        for req in required_sections:
            if req not in content:
                errors.append(f"Missing section: {req}")
                score -= 0.1

        if len(content) < 500:
            errors.append("Playbook is too short to be useful")
            score -= 0.4

        checklist_items = content.count("- [ ]")
        if checklist_items < 5:
            errors.append(f"Too few action items: {checklist_items}")
            score -= 0.2

        return score > 0.5, max(0.0, score), errors


# ── Tool Storage Engine ────────────────────────────────────────
class ToolStorageEngine:
    """
    Persists generated tools to disk with catalog tracking.
    Supports deduplication, versioning, and retrieval.
    """

    def __init__(self):
        self._catalog: Dict[str, GeneratedTool] = {}
        self._content_hashes: Dict[str, str] = {}  # hash → tool_id
        self._lock = threading.RLock()
        self.validator = ToolValidator()
        self._ensure_dirs()
        self._load_catalog()
        logger.info(f"[ToolStorage] Initialized with {len(self._catalog)} tools in catalog")

    def _ensure_dirs(self):
        for subdir in ["scripts", "rules", "playbooks", "detectors"]:
            os.makedirs(os.path.join(TOOLS_OUTPUT_DIR, subdir), exist_ok=True)

    def _category_dir(self, tool_type: str) -> str:
        if tool_type in ("yara", "sigma", "snort", "suricata"):
            return "rules"
        if tool_type in ("ir_playbook", "soc_workflow"):
            return "playbooks"
        if tool_type in ("behavior_monitor",):
            return "detectors"
        return "scripts"

    def store(
        self,
        tool_type: str,
        content: str,
        threat_name: str,
        threat_level: str,
        mitre_techniques: List[str] = None,
    ) -> Optional[GeneratedTool]:
        """Validate, deduplicate, and store a generated tool."""
        if not content or not content.strip():
            logger.warning("[ToolStorage] Empty content — skipping")
            return None

        # Validate
        is_valid, quality_score, errors = self.validator.validate(tool_type, content)
        if not is_valid:
            logger.warning(f"[ToolStorage] Validation failed for {tool_type}: {errors}")
            return None

        # Deduplication
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        with self._lock:
            if content_hash in self._content_hashes:
                existing_id = self._content_hashes[content_hash]
                logger.info(f"[ToolStorage] Duplicate detected — updating existing tool {existing_id}")
                existing = self._catalog.get(existing_id)
                if existing:
                    existing.download_count += 0  # just touch
                    existing.updated_at = datetime.now(timezone.utc).isoformat()
                    self._save_catalog()
                    return existing

        # Determine monetization tier
        tier = self._determine_tier(tool_type, quality_score, threat_level)

        # Build file name
        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', threat_name)[:40]
        ext = {"yara": ".yar", "sigma": ".yml", "snort": ".rules",
               "suricata": ".rules", "ir_playbook": ".md", "soc_workflow": ".md"}.get(tool_type, ".py")
        subdir = self._category_dir(tool_type)
        filename = f"cdb_{safe_name}_{tool_type}_{content_hash[:6]}{ext}"
        file_path = os.path.join(TOOLS_OUTPUT_DIR, subdir, filename)

        # Write file
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception as e:
            logger.error(f"[ToolStorage] File write failed: {e}")
            return None

        # Create catalog record
        tool = GeneratedTool(
            tool_type=tool_type,
            category=subdir,
            name=f"{safe_name}_{tool_type}",
            threat_name=threat_name,
            threat_level=threat_level,
            content_hash=content_hash,
            file_path=file_path,
            quality_score=round(quality_score, 3),
            is_validated=True,
            validation_errors=errors,
            mitre_techniques=mitre_techniques or [],
            monetization_tier=tier,
        )

        with self._lock:
            self._catalog[tool.id] = tool
            self._content_hashes[content_hash] = tool.id
            self._save_catalog()

        logger.info(
            f"[ToolStorage] Stored: {tool_type} | {threat_name} | "
            f"quality={quality_score:.2f} | tier={tier} | {file_path}"
        )
        return tool

    def _determine_tier(self, tool_type: str, quality_score: float, threat_level: str) -> str:
        if threat_level in ("CRITICAL", "HIGH") and quality_score >= 0.8:
            return "enterprise"
        if threat_level in ("HIGH", "MEDIUM") and quality_score >= 0.6:
            return "pro"
        return "free"

    def search(self, query: str = None, tool_type: str = None,
               tier: str = None, limit: int = 50) -> List[GeneratedTool]:
        with self._lock:
            results = list(self._catalog.values())

        if tool_type:
            results = [t for t in results if t.tool_type == tool_type]
        if tier:
            results = [t for t in results if t.monetization_tier == tier]
        if query:
            q = query.lower()
            results = [t for t in results if q in t.name.lower() or q in t.threat_name.lower()]

        results.sort(key=lambda t: t.created_at, reverse=True)
        return results[:limit]

    def get(self, tool_id: str) -> Optional[GeneratedTool]:
        with self._lock:
            return self._catalog.get(tool_id)

    def get_content(self, tool_id: str) -> Optional[str]:
        tool = self.get(tool_id)
        if not tool:
            return None
        try:
            with open(tool.file_path, "r", encoding="utf-8") as f:
                tool.download_count += 1
                self._save_catalog()
                return f.read()
        except Exception as e:
            logger.error(f"[ToolStorage] Read failed for {tool_id}: {e}")
            return None

    def catalog_stats(self) -> Dict:
        with self._lock:
            tools = list(self._catalog.values())
        by_type = {}
        by_tier = {"free": 0, "pro": 0, "enterprise": 0}
        for t in tools:
            by_type[t.tool_type] = by_type.get(t.tool_type, 0) + 1
            by_tier[t.monetization_tier] = by_tier.get(t.monetization_tier, 0) + 1
        avg_quality = sum(t.quality_score for t in tools) / max(len(tools), 1)
        return {
            "total_tools": len(tools),
            "by_type": by_type,
            "by_tier": by_tier,
            "avg_quality_score": round(avg_quality, 3),
            "output_directory": TOOLS_OUTPUT_DIR,
        }

    def _save_catalog(self):
        try:
            data = {tid: tool.to_dict() for tid, tool in self._catalog.items()}
            import tempfile, fcntl
            os.makedirs(os.path.dirname(CATALOG_FILE), exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w", dir=os.path.dirname(CATALOG_FILE), delete=False, suffix=".tmp"
            ) as tf:
                try:
                    fcntl.flock(tf, fcntl.LOCK_EX)
                    json.dump(data, tf, indent=2, default=str)
                    tf.flush()
                    os.fsync(tf.fileno())
                finally:
                    fcntl.flock(tf, fcntl.LOCK_UN)
            os.replace(tf.name, CATALOG_FILE)
        except Exception as e:
            logger.error(f"[ToolStorage] Catalog save failed: {e}")

    def _load_catalog(self):
        if not os.path.exists(CATALOG_FILE):
            return
        try:
            with open(CATALOG_FILE) as f:
                data = json.load(f)
            with self._lock:
                for tid, tool_data in data.items():
                    tool = GeneratedTool.from_dict(tool_data)
                    self._catalog[tid] = tool
                    self._content_hashes[tool.content_hash] = tid
        except Exception as e:
            logger.warning(f"[ToolStorage] Catalog load failed: {e}")


# ── Continuous Improvement Loop ────────────────────────────────
class ContinuousImprovementEngine:
    """
    Tracks generation outcomes and improves future generations.
    - Records which tool types perform best per threat category
    - Avoids regenerating identical tools
    - Suggests enhancements based on quality scores
    """

    def __init__(self, storage: ToolStorageEngine):
        self.storage = storage
        self._performance: Dict[str, Dict] = {}  # category → {tool_type → avg_quality}
        self._lock = threading.Lock()

    def record_outcome(self, category: str, tool_type: str, quality_score: float):
        with self._lock:
            if category not in self._performance:
                self._performance[category] = {}
            existing = self._performance[category].get(tool_type, {"count": 0, "total": 0.0})
            existing["count"] += 1
            existing["total"] += quality_score
            self._performance[category][tool_type] = existing

    def best_tool_types(self, category: str, top_n: int = 3) -> List[str]:
        """Return the best-performing tool types for a given threat category."""
        with self._lock:
            perf = self._performance.get(category, {})
        if not perf:
            return ["network_ioc_scanner", "sigma", "yara"]
        scored = {
            tt: data["total"] / max(data["count"], 1)
            for tt, data in perf.items()
        }
        return sorted(scored, key=scored.get, reverse=True)[:top_n]

    def should_regenerate(self, threat_name: str, tool_type: str) -> bool:
        """Return True if we should generate a new version of this tool."""
        existing = self.storage.search(query=threat_name, tool_type=tool_type, limit=1)
        if not existing:
            return True
        # Regenerate if quality is below threshold
        return existing[0].quality_score < 0.5

    def improvement_report(self) -> Dict:
        with self._lock:
            report = {}
            for category, tools in self._performance.items():
                report[category] = {
                    tt: round(data["total"] / max(data["count"], 1), 3)
                    for tt, data in tools.items()
                }
        return report


# ── Singletons ─────────────────────────────────────────────────
_storage: Optional[ToolStorageEngine] = None
_improvement: Optional[ContinuousImprovementEngine] = None
_store_lock = threading.Lock()


def get_storage() -> ToolStorageEngine:
    global _storage
    if _storage is None:
        with _store_lock:
            if _storage is None:
                _storage = ToolStorageEngine()
    return _storage


def get_improvement_engine() -> ContinuousImprovementEngine:
    global _improvement
    if _improvement is None:
        with _store_lock:
            if _improvement is None:
                _improvement = ContinuousImprovementEngine(get_storage())
    return _improvement
