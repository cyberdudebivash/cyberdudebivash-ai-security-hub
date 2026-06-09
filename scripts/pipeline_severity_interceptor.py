"""
CYBERDUDEBIVASH® SENTINEL APEX — Pipeline Severity Interceptor Middleware
Classification: Ingestion Pre-Commit Gate
Version: v30.0.2-Production-Hardened

Inject this module into run_pipeline.py BEFORE any D1/KV/R2 write call:

    from scripts.pipeline_severity_interceptor import pre_commit_severity_gate
    records = pre_commit_severity_gate(records)

"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from scripts.severity_recalibration_engine import process_vulnerability_batch

logger = logging.getLogger("pipeline_severity_interceptor")


def pre_commit_severity_gate(
    records: list[dict[str, Any]],
    *,
    write_audit_log: bool = True,
    audit_log_path: str = "logs/severity_gate_audit.jsonl",
) -> list[dict[str, Any]]:
    """
    Pre-commit severity gate called immediately before database serialization.

    Guarantees:
    - No CRITICAL/HIGH vulnerability enters D1 with a degraded severity label.
    - All records with CVSS >= 7.0 are floor-validated.
    - Audit log is written for compliance traceability.

    Args:
        records: Raw vulnerability dicts from ingestion pipeline.
        write_audit_log: Whether to append audit entries to JSONL log file.
        audit_log_path: Path to audit log file.

    Returns:
        Calibrated records safe to commit to database.
    """
    if not records:
        return records

    pre_count = len(records)
    calibrated = process_vulnerability_batch(records)

    changed = sum(
        1 for orig, cal in zip(records, calibrated)
        if orig.get("severity", "").upper() != cal.get("Severity", "").upper()
    )

    logger.info("[SEVERITY-GATE] Processed %d records | %d severity floors enforced",
                pre_count, changed)

    if write_audit_log:
        log_path = Path(audit_log_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": int(time.time()),
            "records_processed": pre_count,
            "floors_enforced": changed,
        }
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    return calibrated


# ── Sentinel Blogger integration hook ───────────────────────────────────────
def enrich_blog_post_record(post_record: dict[str, Any]) -> dict[str, Any]:
    """
    Hook for sentinel_blogger.py — applies severity floor to the embedded
    CVE/vulnerability metadata inside a blog post record before publishing.
    """
    vuln_data = post_record.get("vulnerability_data")
    if isinstance(vuln_data, dict):
        post_record["vulnerability_data"] = enforce_single(vuln_data)
    elif isinstance(vuln_data, list):
        post_record["vulnerability_data"] = process_vulnerability_batch(vuln_data)
    return post_record


def enforce_single(record: dict[str, Any]) -> dict[str, Any]:
    from scripts.severity_recalibration_engine import enforce_sentinel_apex_severity_floors
    return enforce_sentinel_apex_severity_floors(record)
