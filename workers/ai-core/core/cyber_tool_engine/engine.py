# ============================================================
# CYBERDUDEBIVASH AI — MASTER CYBER TOOL GENERATION ENGINE
# Full pipeline: Intel → Parse → Classify → Generate → Validate → Store
# Integrates: Threat Memory, AI Super Router, Monetization
# ============================================================

import time
import threading
import uuid
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from core.logging_config import get_logger

logger = get_logger("cyber_tool_engine.master")


@dataclass
class GenerationJob:
    """Tracks a single tool generation job through the full pipeline."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: str = "pending"        # pending/parsing/classifying/generating/validating/complete/failed
    raw_input: Any = None
    source_type: str = "unknown"
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    error: Optional[str] = None

    # Pipeline results
    parsed_intel: Optional[Any] = None
    classification: Optional[Any] = None
    generated_tools: Dict[str, str] = field(default_factory=dict)
    generated_rules: Dict[str, str] = field(default_factory=dict)
    generated_playbooks: Dict[str, str] = field(default_factory=dict)
    stored_tool_ids: List[str] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        end = self.completed_at or time.time()
        return round(end - self.started_at, 2)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "status": self.status,
            "source_type": self.source_type,
            "duration_s": self.duration_s,
            "error": self.error,
            "stored_tool_ids": self.stored_tool_ids,
            "tools_generated": {
                "tools": list(self.generated_tools.keys()),
                "rules": list(self.generated_rules.keys()),
                "playbooks": list(self.generated_playbooks.keys()),
            },
            "intel_summary": self._intel_summary(),
        }

    def _intel_summary(self) -> Dict:
        if not self.parsed_intel:
            return {}
        return {
            "threat_level": self.parsed_intel.threat_level,
            "ioc_count": self.parsed_intel.ioc_count,
            "mitre_techniques": self.parsed_intel.mitre_techniques[:5],
            "threat_categories": self.parsed_intel.threat_categories[:5],
        }


class CyberToolGenerationEngine:
    """
    Master orchestrator for the autonomous cybersecurity tool generation pipeline.

    Pipeline:
    1. Ingest raw threat intelligence (any format)
    2. Parse → extract IOCs, TTPs, patterns
    3. Classify → determine threat type, MITRE mapping
    4. Generate Tools → Python scanners, detectors, monitors
    5. Generate Rules → YARA, Sigma, Snort, Suricata
    6. Generate Playbooks → IR workflows, SOC runbooks
    7. Validate → quality check all outputs
    8. Store → catalog with deduplication and monetization tier
    9. Learn → feed outcomes to improvement engine
    10. Integrate → push IOCs to Threat Memory
    """

    def __init__(self):
        # Lazy import all sub-engines (avoids circular imports at module load)
        self._parser = None
        self._classifier = None
        self._tool_gen = None
        self._rule_gen = None
        self._playbook_gen = None
        self._storage = None
        self._improvement = None
        self._threat_memory = None
        self._lock = threading.Lock()
        self._job_history: List[GenerationJob] = []
        self._init_all()
        logger.info("[CyberToolEngine] Master engine initialized")

    def _init_all(self):
        try:
            from core.cyber_tool_engine.parsers.threat_parser import ThreatParsingEngine
            self._parser = ThreatParsingEngine()
        except Exception as e:
            logger.error(f"[CyberToolEngine] Parser init failed: {e}")

        try:
            from core.cyber_tool_engine.classifiers.threat_classifier import ThreatClassifier
            self._classifier = ThreatClassifier()
        except Exception as e:
            logger.error(f"[CyberToolEngine] Classifier init failed: {e}")

        try:
            from core.cyber_tool_engine.generators.tool_generator import ToolGenerationEngine
            self._tool_gen = ToolGenerationEngine()
        except Exception as e:
            logger.error(f"[CyberToolEngine] Tool generator init failed: {e}")

        try:
            from core.cyber_tool_engine.generators.rule_generator import RuleGenerationEngine
            self._rule_gen = RuleGenerationEngine()
        except Exception as e:
            logger.error(f"[CyberToolEngine] Rule generator init failed: {e}")

        try:
            from core.cyber_tool_engine.generators.playbook_generator import PlaybookGenerationEngine
            self._playbook_gen = PlaybookGenerationEngine()
        except Exception as e:
            logger.error(f"[CyberToolEngine] Playbook generator init failed: {e}")

        try:
            from core.cyber_tool_engine.storage.tool_storage import get_storage, get_improvement_engine
            self._storage = get_storage()
            self._improvement = get_improvement_engine()
        except Exception as e:
            logger.error(f"[CyberToolEngine] Storage init failed: {e}")

        try:
            from core.threat_memory.engine import get_threat_memory
            self._threat_memory = get_threat_memory()
        except Exception as e:
            logger.warning(f"[CyberToolEngine] Threat memory unavailable: {e}")

    # ── Main Pipeline ─────────────────────────────────────────

    def generate_from_intel(
        self,
        raw_input: Any,
        source_type: str = "analysis",
        generate_tools: bool = True,
        generate_rules: bool = True,
        generate_playbooks: bool = True,
        tool_types: Optional[List[str]] = None,
        rule_types: Optional[List[str]] = None,
    ) -> GenerationJob:
        """
        Full pipeline: ingest raw intel → generate all cybersecurity artifacts.
        Returns a GenerationJob with all results.
        """
        job = GenerationJob(raw_input=raw_input, source_type=source_type)
        job.status = "parsing"
        logger.info(f"[CyberToolEngine] Job {job.id} started (source={source_type})")

        try:
            # ── STEP 1: Parse ────────────────────────────────
            if not self._parser:
                raise RuntimeError("Parser not initialized")
            intel = self._parser.parse(raw_input, source_type)
            job.parsed_intel = intel
            job.status = "classifying"

            # ── STEP 2: Classify ─────────────────────────────
            if not self._classifier:
                raise RuntimeError("Classifier not initialized")
            classification = self._classifier.classify(intel)
            job.classification = classification
            job.status = "generating"

            # ── STEP 3: Continuous Improvement — check if we should regenerate
            effective_tools = tool_types
            if self._improvement and not tool_types:
                best = self._improvement.best_tool_types(classification.primary_category)
                effective_tools = best if best else intel.recommended_tools

            # ── STEP 4: Generate Tools ────────────────────────
            if generate_tools and self._tool_gen:
                tools = self._tool_gen.generate_all(intel, classification, effective_tools)
                job.generated_tools = {k: v for k, v in tools.items() if v}
                logger.info(f"[CyberToolEngine] Generated {len(job.generated_tools)} tools")

            # ── STEP 5: Generate Rules ────────────────────────
            if generate_rules and self._rule_gen:
                rules = self._rule_gen.generate_all(intel, classification, rule_types)
                job.generated_rules = {k: v for k, v in rules.items() if v}
                logger.info(f"[CyberToolEngine] Generated {len(job.generated_rules)} rules")

            # ── STEP 6: Generate Playbooks ────────────────────
            if generate_playbooks and self._playbook_gen:
                playbooks = self._playbook_gen.generate_all(intel, classification)
                job.generated_playbooks = {k: v for k, v in playbooks.items() if v}
                logger.info(f"[CyberToolEngine] Generated {len(job.generated_playbooks)} playbooks")

            job.status = "storing"

            # ── STEP 7: Validate & Store ──────────────────────
            if self._storage:
                threat_name = intel.malware_family or intel.threat_name or classification.primary_category
                all_artifacts = {
                    **job.generated_tools,
                    **job.generated_rules,
                    **job.generated_playbooks,
                }
                for artifact_type, content in all_artifacts.items():
                    tool = self._storage.store(
                        tool_type=artifact_type,
                        content=content,
                        threat_name=threat_name,
                        threat_level=intel.threat_level,
                        mitre_techniques=intel.mitre_techniques,
                    )
                    if tool:
                        job.stored_tool_ids.append(tool.id)
                        # Record outcome for improvement
                        if self._improvement:
                            self._improvement.record_outcome(
                                classification.primary_category, artifact_type, tool.quality_score
                            )

            # ── STEP 8: Push IOCs to Threat Memory ───────────
            if self._threat_memory:
                try:
                    iocs_added = self._threat_memory.ingest_from_analysis(
                        raw_input if isinstance(raw_input, dict) else {"output": raw_input},
                        target=intel.threat_name or "unknown",
                    )
                    if iocs_added:
                        logger.info(f"[CyberToolEngine] Added {len(iocs_added)} IOCs to threat memory")
                except Exception as e:
                    logger.warning(f"[CyberToolEngine] Threat memory ingest failed (non-critical): {e}")

            job.status = "complete"
            job.completed_at = time.time()

            logger.info(
                f"[CyberToolEngine] Job {job.id} complete in {job.duration_s}s | "
                f"tools={len(job.generated_tools)} rules={len(job.generated_rules)} "
                f"playbooks={len(job.generated_playbooks)} stored={len(job.stored_tool_ids)}"
            )

        except Exception as e:
            job.status = "failed"
            job.error = str(e)
            job.completed_at = time.time()
            logger.error(f"[CyberToolEngine] Job {job.id} failed: {e}", exc_info=True)

        # Track history (last 100)
        with self._lock:
            self._job_history.append(job)
            if len(self._job_history) > 100:
                self._job_history.pop(0)

        return job

    def generate_async(self, raw_input: Any, source_type: str = "analysis", **kwargs) -> str:
        """Start generation in background thread. Returns job_id immediately."""
        job = GenerationJob(raw_input=raw_input, source_type=source_type)
        with self._lock:
            self._job_history.append(job)

        def _run():
            result = self.generate_from_intel(raw_input, source_type, **kwargs)
            with self._lock:
                for i, j in enumerate(self._job_history):
                    if j.id == job.id:
                        self._job_history[i] = result
                        break

        threading.Thread(target=_run, daemon=True, name=f"ToolGen-{job.id[:8]}").start()
        return job.id

    def get_job(self, job_id: str) -> Optional[GenerationJob]:
        with self._lock:
            for job in self._job_history:
                if job.id == job_id:
                    return job
        return None

    def list_jobs(self, limit: int = 20) -> List[Dict]:
        with self._lock:
            jobs = self._job_history[-limit:]
        return [j.to_dict() for j in reversed(jobs)]

    def catalog(self, **kwargs) -> List[Dict]:
        if not self._storage:
            return []
        tools = self._storage.search(**kwargs)
        return [t.to_dict() for t in tools]

    def catalog_stats(self) -> Dict:
        if not self._storage:
            return {}
        stats = self._storage.catalog_stats()
        if self._improvement:
            stats["improvement_report"] = self._improvement.improvement_report()
        return stats

    def health(self) -> Dict:
        return {
            "parser": self._parser is not None,
            "classifier": self._classifier is not None,
            "tool_generator": self._tool_gen is not None,
            "rule_generator": self._rule_gen is not None,
            "playbook_generator": self._playbook_gen is not None,
            "storage": self._storage is not None,
            "threat_memory": self._threat_memory is not None,
            "total_jobs": len(self._job_history),
            "catalog": self._storage.catalog_stats() if self._storage else {},
        }


# ── Singleton ─────────────────────────────────────────────────
_engine: Optional[CyberToolGenerationEngine] = None
_engine_lock = threading.Lock()


def get_cyber_tool_engine() -> CyberToolGenerationEngine:
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = CyberToolGenerationEngine()
    return _engine
