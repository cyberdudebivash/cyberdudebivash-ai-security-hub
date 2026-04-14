# ============================================================
# CYBERDUDEBIVASH AI — SENTINEL APEX THREAT INTEL INTEGRATION
# Connects the APEX platform to the Cyber Tool Generation Engine.
# Ingests: IOC feeds, campaign alerts, CVE advisories, malware reports.
# ============================================================

import time
import threading
import json
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from core.logging_config import get_logger

logger = get_logger("sentinel_apex")


class SentinelAPEXConnector:
    """
    Sentinel APEX threat intelligence platform connector.
    
    Ingests threat intelligence from multiple sources and 
    automatically triggers the Cyber Tool Generation Engine
    to produce detection tools, rules, and playbooks.
    """

    def __init__(self):
        self._tool_engine = None
        self._threat_memory = None
        self._processed_ids = set()   # dedup tracker
        self._lock = threading.RLock()
        self._stats = {
            "intel_ingested": 0,
            "tools_generated": 0,
            "iocs_added": 0,
            "generation_errors": 0,
            "last_ingest": None,
        }
        self._running = False
        self._ingest_thread = None
        self._init_dependencies()
        logger.info("[SentinelAPEX] Connector initialized")

    def _init_dependencies(self) -> None:
        try:
            from core.cyber_tool_engine.engine import get_cyber_tool_engine
            self._tool_engine = get_cyber_tool_engine()
        except Exception as e:
            logger.error(f"[SentinelAPEX] Tool engine unavailable: {e}")

        try:
            from core.threat_memory.engine import get_threat_memory
            self._threat_memory = get_threat_memory()
        except Exception as e:
            logger.warning(f"[SentinelAPEX] Threat memory unavailable: {e}")

    # ── Primary Ingest Methods ────────────────────────────────

    def ingest_threat_analysis(
        self,
        analysis: Dict[str, Any],
        auto_generate: bool = True,
        source: str = "sentinel_apex",
    ) -> Dict[str, Any]:
        """
        Ingest a threat analysis result (from /cyber/threat-intel/sync)
        and optionally trigger tool generation.
        """
        if not analysis:
            return {"status": "error", "error": "Empty analysis"}

        # Deduplication
        fingerprint = self._fingerprint(analysis)
        with self._lock:
            if fingerprint in self._processed_ids:
                return {"status": "duplicate", "fingerprint": fingerprint}
            self._processed_ids.add(fingerprint)
            if len(self._processed_ids) > 10000:
                # Trim oldest entries
                self._processed_ids = set(list(self._processed_ids)[-5000:])

        result = {
            "fingerprint": fingerprint,
            "source": source,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "intel_ingested": False,
            "tools_generated": False,
            "job_id": None,
            "iocs_added": 0,
        }

        # Push IOCs to Threat Memory
        if self._threat_memory:
            try:
                iocs = self._threat_memory.ingest_from_analysis(
                    analysis,
                    target=analysis.get("target", analysis.get("output", {}).get("target", "")),
                )
                result["iocs_added"] = len(iocs)
                with self._lock:
                    self._stats["iocs_added"] += len(iocs)
                logger.info(f"[SentinelAPEX] {len(iocs)} IOCs added to threat memory")
            except Exception as e:
                logger.warning(f"[SentinelAPEX] IOC ingest failed: {e}")

        result["intel_ingested"] = True
        with self._lock:
            self._stats["intel_ingested"] += 1
            self._stats["last_ingest"] = datetime.now(timezone.utc).isoformat()

        # Auto-generate tools
        if auto_generate and self._tool_engine:
            try:
                # Use async generation to not block the request
                output = analysis.get("output", analysis)
                is_malicious = output.get("is_malicious", False)
                threat_level = output.get("threat_level", "UNKNOWN")

                # Only generate for medium+ threats
                if threat_level in ("CRITICAL", "HIGH", "MEDIUM") or is_malicious:
                    job_id = self._tool_engine.generate_async(
                        raw_input=analysis,
                        source_type=source,
                    )
                    result["job_id"] = job_id
                    result["tools_generated"] = True
                    with self._lock:
                        self._stats["tools_generated"] += 1
                    logger.info(f"[SentinelAPEX] Tool generation triggered: job={job_id}")
                else:
                    result["tools_generated"] = False
                    result["skip_reason"] = f"Threat level {threat_level} below threshold"

            except Exception as e:
                logger.error(f"[SentinelAPEX] Tool generation failed: {e}")
                with self._lock:
                    self._stats["generation_errors"] += 1
                result["generation_error"] = str(e)

        return result

    def ingest_ioc_feed(
        self,
        iocs: List[str],
        feed_name: str = "unknown",
        severity: str = "MEDIUM",
        auto_generate: bool = False,
    ) -> Dict[str, Any]:
        """
        Ingest a batch IOC feed. Optionally generates tools for critical/high IOCs.
        """
        added = []
        errors = []

        if self._threat_memory:
            for ioc_val in iocs[:1000]:  # Cap at 1000 per batch
                ioc_val = str(ioc_val).strip()
                if not ioc_val:
                    continue
                try:
                    ioc_type = self._classify_ioc(ioc_val)
                    ioc = self._threat_memory.ingest_ioc(
                        value=ioc_val,
                        ioc_type=ioc_type,
                        severity=severity,
                        source=feed_name,
                        tags=[feed_name, "ioc_feed"],
                    )
                    added.append(ioc_val)
                except Exception as e:
                    errors.append(f"{ioc_val}: {e}")

        with self._lock:
            self._stats["iocs_added"] += len(added)
            self._stats["intel_ingested"] += 1

        result = {
            "feed": feed_name,
            "submitted": len(iocs),
            "added": len(added),
            "errors": len(errors),
            "severity": severity,
        }

        # Generate tools for high-severity feeds
        if auto_generate and self._tool_engine and severity in ("CRITICAL", "HIGH") and added:
            intel = {
                "target": added[0],
                "threat_level": severity,
                "is_malicious": True,
                "indicators_of_compromise": added[:20],
                "summary": f"IOC feed: {feed_name} ({len(added)} indicators)",
                "tags": [feed_name, "ioc_feed"],
            }
            try:
                job_id = self._tool_engine.generate_async(
                    raw_input=intel, source_type=f"ioc_feed_{feed_name}"
                )
                result["job_id"] = job_id
            except Exception as e:
                logger.warning(f"[SentinelAPEX] Feed toolgen failed: {e}")

        logger.info(f"[SentinelAPEX] IOC feed '{feed_name}': {len(added)}/{len(iocs)} added")
        return result

    def ingest_malware_campaign(
        self,
        campaign_name: str,
        campaign_data: Dict[str, Any],
        auto_generate: bool = True,
    ) -> Dict[str, Any]:
        """
        Ingest a full malware campaign report and generate a complete toolset.
        """
        # Enrich with campaign context
        enriched = {
            **campaign_data,
            "threat_level": campaign_data.get("severity", "HIGH"),
            "is_malicious": True,
            "summary": campaign_data.get("description", f"Malware campaign: {campaign_name}"),
        }

        result = self.ingest_threat_analysis(
            enriched,
            auto_generate=auto_generate,
            source=f"campaign_{campaign_name}",
        )

        # Also create a campaign in threat memory
        if self._threat_memory and result.get("iocs_added", 0) > 0:
            try:
                # Link IOCs into a campaign
                ioc_ids = []
                for ioc_val in campaign_data.get("indicators_of_compromise", [])[:50]:
                    ioc = self._threat_memory.lookup(str(ioc_val))
                    if ioc:
                        ioc_ids.append(ioc.id)

                if ioc_ids:
                    campaign = self._threat_memory.create_campaign(
                        name=campaign_name,
                        ioc_ids=ioc_ids,
                        threat_actor=campaign_data.get("threat_actor"),
                        techniques=campaign_data.get("mitre_techniques", []),
                    )
                    result["campaign_id"] = campaign.id
            except Exception as e:
                logger.warning(f"[SentinelAPEX] Campaign linking failed: {e}")

        return result

    def ingest_cve_advisory(
        self,
        cve_id: str,
        cve_data: Dict[str, Any],
        auto_generate: bool = True,
    ) -> Dict[str, Any]:
        """
        Ingest a CVE advisory and generate vulnerability detection tools.
        """
        enriched = {
            "cve_id": cve_id.upper(),
            "threat_level": "HIGH" if float(cve_data.get("cvss_score", 7.0)) >= 7.0 else "MEDIUM",
            "is_malicious": True,
            "threat_categories": ["exploit", "vulnerability"],
            "indicators_of_compromise": [cve_id.upper()],
            "summary": cve_data.get("description", f"Vulnerability: {cve_id}"),
            "attack_techniques": ["T1190"],
            **cve_data,
        }

        return self.ingest_threat_analysis(
            enriched,
            auto_generate=auto_generate,
            source="cve_advisory",
        )

    # ── Batch Processing ──────────────────────────────────────

    def batch_ingest(
        self,
        items: List[Dict[str, Any]],
        source: str = "batch",
    ) -> Dict[str, Any]:
        """Process multiple threat intel items in sequence."""
        results = []
        for item in items[:50]:  # cap at 50 per batch
            try:
                result = self.ingest_threat_analysis(item, auto_generate=True, source=source)
                results.append(result)
            except Exception as e:
                results.append({"status": "error", "error": str(e)})
                logger.error(f"[SentinelAPEX] Batch item failed: {e}")

        return {
            "total": len(items),
            "processed": len(results),
            "tools_triggered": sum(1 for r in results if r.get("tools_generated")),
            "iocs_added": sum(r.get("iocs_added", 0) for r in results),
            "results": results,
        }

    # ── Helper Methods ────────────────────────────────────────

    def _fingerprint(self, data: Any) -> str:
        import hashlib
        try:
            text = json.dumps(data, sort_keys=True, default=str)
        except Exception:
            text = str(data)
        return hashlib.sha256(text.encode()).hexdigest()[:16]

    def _classify_ioc(self, value: str) -> str:
        import re, socket
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

    def stats(self) -> Dict:
        with self._lock:
            return {
                **self._stats,
                "unique_intel_seen": len(self._processed_ids),
                "tool_engine_ready": self._tool_engine is not None,
                "threat_memory_ready": self._threat_memory is not None,
            }


# ── Singleton ─────────────────────────────────────────────────
_apex: Optional[SentinelAPEXConnector] = None
_apex_lock = threading.Lock()


def get_sentinel_apex() -> SentinelAPEXConnector:
    global _apex
    if _apex is None:
        with _apex_lock:
            if _apex is None:
                _apex = SentinelAPEXConnector()
    return _apex
