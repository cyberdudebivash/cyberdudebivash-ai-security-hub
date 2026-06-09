"""
CYBERDUDEBIVASH® SENTINEL APEX — Severity Recalibration Engine
Classification: Core Invariant Governance Module
Version: v30.0.2-Production-Hardened
Target: Cloudflare D1 / KV / R2 pipeline middleware
"""
from __future__ import annotations

import re
import time
import logging
from typing import Any

logger = logging.getLogger("severity_recalibration_engine")

# ── Active exploitation regex — present-participle indicators ────────────────
_EXPLOITATION_PATTERNS: re.Pattern[str] = re.compile(
    r"actively\s+exploit(?:ing|ed)|"
    r"under\s+active\s+attack|"
    r"mass\s+exploitation|"
    r"exploiting\s+in\s+the\s+wild|"
    r"in[\s-]the[\s-]wild|"
    r"weaponized|"
    r"zero[\s-]day\s+exploit|"
    r"emergency\s+patch",
    re.IGNORECASE,
)

# ── Threat classes that always trigger CRITICAL floor ────────────────────────
_CRITICAL_THREAT_CLASSES: frozenset[str] = frozenset(
    {"rce", "arbitrary_file_upload", "auth_bypass", "remote_code_execution",
     "code_injection", "deserialization", "sql_injection_rce", "os_command_injection"}
)


def _detect_active_exploitation(record: dict[str, Any]) -> bool:
    """Scan title, description, and summary fields for active-exploitation language."""
    scan_targets = [
        record.get("title", ""),
        record.get("description", ""),
        record.get("summary", ""),
        record.get("notes", ""),
    ]
    combined = " ".join(str(t) for t in scan_targets if t)
    return bool(_EXPLOITATION_PATTERNS.search(combined))


def enforce_sentinel_apex_severity_floors(record: dict[str, Any]) -> dict[str, Any]:
    """
    Production-grade severity floor enforcement gate.

    Rules (immutable governance — no downstream script may override):
      P0-GATE: cvss >= 9.0 OR active_exploitation OR cisa_kev OR critical threat class
               → severity=CRITICAL, priority=P1, risk_score=max(9.0, cvss), ioc_paywall_locked=True
      P1-GATE: 8.0 <= cvss < 9.0 AND current severity in LOW/MEDIUM
               → severity=HIGH, priority=P2, risk_score=max(7.5, cvss)
      P2-GATE: 7.0 <= cvss < 8.0 AND current severity == LOW
               → severity=MEDIUM, priority=P3, risk_score=max(5.0, cvss)
    """
    r = dict(record)  # non-destructive copy

    cvss: float = float(r.get("cvss_score", r.get("cvss", 0.0)) or 0.0)
    active_exploitation: bool = bool(r.get("active_exploitation", False)) or _detect_active_exploitation(r)
    cisa_kev: bool = bool(r.get("cisa_kev", r.get("kev_present", False)))
    threat_class: str = str(r.get("threat_class", r.get("class", ""))).lower()
    current_severity: str = str(r.get("severity", r.get("Severity", "UNKNOWN"))).upper()

    # ── P0 GATE: CRITICAL floor ──────────────────────────────────────────────
    if (
        cvss >= 9.0
        or active_exploitation
        or cisa_kev
        or threat_class in _CRITICAL_THREAT_CLASSES
    ):
        r["Severity"] = "CRITICAL"
        r["severity"] = "CRITICAL"
        r["priority"] = "P1"
        r["threat_level"] = "CRITICAL_SURGE"
        r["Risk Score"] = max(9.0, cvss)
        r["risk_score"] = max(9.0, cvss)
        r["active_exploitation_detected"] = active_exploitation
        # Enforce paywall lock on IOC data for CRITICAL tier
        if isinstance(r.get("ioc_paywall"), dict):
            r["ioc_paywall"]["locked"] = True
        else:
            r["ioc_paywall"] = {"locked": True}
        logger.info("[P0-GATE] %s locked to CRITICAL (cvss=%.1f kev=%s exploitation=%s)",
                    r.get("id", "UNKNOWN"), cvss, cisa_kev, active_exploitation)
        return r

    # ── P1 GATE: HIGH floor ──────────────────────────────────────────────────
    if 8.0 <= cvss < 9.0 and current_severity in {"LOW", "MEDIUM", "UNKNOWN"}:
        r["Severity"] = "HIGH"
        r["severity"] = "HIGH"
        r["priority"] = "P2"
        r["threat_level"] = "HIGH"
        r["Risk Score"] = max(7.5, cvss)
        r["risk_score"] = max(7.5, cvss)
        if isinstance(r.get("ioc_paywall"), dict):
            r["ioc_paywall"]["locked"] = True
        else:
            r["ioc_paywall"] = {"locked": True}
        logger.info("[P1-GATE] %s elevated to HIGH (cvss=%.1f)", r.get("id", "UNKNOWN"), cvss)
        return r

    # ── P2 GATE: MEDIUM floor ────────────────────────────────────────────────
    if 7.0 <= cvss < 8.0 and current_severity == "LOW":
        r["Severity"] = "MEDIUM"
        r["severity"] = "MEDIUM"
        r["priority"] = "P3"
        r["threat_level"] = "MEDIUM"
        r["Risk Score"] = max(5.0, cvss)
        r["risk_score"] = max(5.0, cvss)
        logger.info("[P2-GATE] %s elevated to MEDIUM (cvss=%.1f)", r.get("id", "UNKNOWN"), cvss)
        return r

    # No floor breached — return record with normalised keys
    r["Severity"] = current_severity
    r["Risk Score"] = cvss
    return r


def process_vulnerability_batch(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Process a batch of raw vulnerability records through the severity floor engine."""
    calibrated: list[dict[str, Any]] = []
    for record in records:
        try:
            calibrated.append(enforce_sentinel_apex_severity_floors(record))
        except Exception as exc:  # noqa: BLE001
            logger.error("[CALIBRATION-ERROR] Record %s failed: %s",
                         record.get("id", "?"), exc)
            calibrated.append(record)  # pass-through on error; never drop data
    return calibrated
