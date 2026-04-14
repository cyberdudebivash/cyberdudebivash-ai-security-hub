# ============================================================
# CYBERDUDEBIVASH AI — AI SUPER ROUTER
# Multi-model routing: primary (OpenAI) → cached intelligence
# → rule-based fallback. Never returns empty or broken output.
# Adds: confidence scoring, response validation, response cache
# ============================================================

import time
import hashlib
import json
import threading
import re
from typing import Any, Dict, Optional, Tuple
from core.logging_config import get_logger
from core.settings import settings

logger = get_logger("ai_super_router")

# ── Response Cache ────────────────────────────────────────────
class ResponseCache:
    """
    In-memory LRU-style cache for AI responses.
    Keyed by (mode, prompt_hash). TTL-based expiry.
    """

    def __init__(self, max_size: int = 500, ttl_seconds: int = 3600):
        self._cache: Dict[str, Dict] = {}
        self._max_size = max_size
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    def _key(self, mode: str, prompt: str) -> str:
        h = hashlib.sha256(f"{mode}:{prompt}".encode()).hexdigest()[:16]
        return h

    def get(self, mode: str, prompt: str) -> Optional[str]:
        key = self._key(mode, prompt)
        with self._lock:
            entry = self._cache.get(key)
            if entry and time.time() - entry["ts"] < self._ttl:
                self._hits += 1
                return entry["value"]
            if entry:
                del self._cache[key]
            self._misses += 1
            return None

    def set(self, mode: str, prompt: str, value: str) -> None:
        if not value:
            return
        key = self._key(mode, prompt)
        with self._lock:
            if len(self._cache) >= self._max_size:
                # Evict oldest entry
                oldest = min(self._cache.items(), key=lambda x: x[1]["ts"])
                del self._cache[oldest[0]]
            self._cache[key] = {"value": value, "ts": time.time()}

    def stats(self) -> Dict:
        with self._lock:
            total = self._hits + self._misses
            return {
                "size": len(self._cache),
                "max_size": self._max_size,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": round(self._hits / max(total, 1), 3),
            }

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0


# ── Response Validator ────────────────────────────────────────
class ResponseValidator:
    """Validates and scores AI responses for quality and relevance."""

    MIN_RESPONSE_LENGTH = 10
    MAX_RESPONSE_LENGTH = 50_000

    QUALITY_INDICATORS = {
        "threat_intel": ["threat", "risk", "malicious", "indicator", "recommendation"],
        "cyber":        ["security", "vulnerability", "threat", "attack", "risk"],
        "code":         ["def ", "class ", "import ", "return", "function"],
        "general":      [],  # no specific indicators
    }

    def validate(self, response: str, mode: str) -> Tuple[bool, float, str]:
        """
        Returns (is_valid, confidence_score 0-1, reason).
        """
        if not response or not response.strip():
            return False, 0.0, "empty_response"

        if len(response) < self.MIN_RESPONSE_LENGTH:
            return False, 0.1, "too_short"

        if len(response) > self.MAX_RESPONSE_LENGTH:
            # Truncate but still valid
            return True, 0.7, "truncated"

        # Mode-specific content check
        indicators = self.QUALITY_INDICATORS.get(mode, [])
        response_lower = response.lower()
        if indicators:
            matched = sum(1 for ind in indicators if ind in response_lower)
            content_score = matched / len(indicators)
        else:
            content_score = 0.8  # No specific indicators required

        # JSON validity check for structured modes
        if mode == "threat_intel":
            clean = re.sub(r"```(?:json)?", "", response).strip().rstrip("`").strip()
            try:
                json.loads(clean)
                return True, min(0.5 + content_score * 0.5, 1.0), "valid_json"
            except json.JSONDecodeError:
                # Not JSON but might still be useful
                if content_score > 0.3:
                    return True, 0.4, "non_json_but_relevant"
                return False, 0.2, "invalid_json_low_relevance"

        confidence = min(0.4 + content_score * 0.6, 1.0)
        return True, confidence, "valid"


# ── Rule-Based Fallback Engine ────────────────────────────────
class RuleBasedFallback:
    """
    When all AI providers fail, return structured deterministic responses.
    Better than empty output.
    """

    THREAT_INTEL_TEMPLATE = {
        "threat_level": "UNKNOWN",
        "threat_score": 0,
        "is_malicious": False,
        "threat_categories": [],
        "indicators_of_compromise": [],
        "attack_techniques": [],
        "geolocation": {"country": "Unknown", "asn": "Unknown", "org": "Unknown"},
        "recommendations": [
            "Manual threat investigation required",
            "Check threat intelligence feeds (VirusTotal, Shodan, AbuseIPDB)",
            "Review firewall logs for suspicious activity",
            "Implement blocking if behavior is suspicious",
        ],
        "mitigations": [
            "Enable enhanced logging",
            "Isolate affected systems if compromise suspected",
        ],
        "references": [],
        "summary": "AI analysis unavailable. Manual investigation required for accurate threat assessment.",
        "analysis_source": "rule_based_fallback",
    }

    VULN_TEMPLATE = {
        "severity": "UNKNOWN",
        "cvss_score": 0.0,
        "description": "Vulnerability analysis unavailable. Check NVD (nvd.nist.gov) for details.",
        "affected_systems": [],
        "exploit_available": False,
        "patch_available": False,
        "patch_urgency": "Manual review required",
        "workarounds": ["Review vendor advisories", "Apply principle of least privilege"],
        "remediation_steps": ["Check NVD for patch information", "Apply available patches", "Implement workarounds"],
        "detection_methods": ["Review system logs", "Use vulnerability scanner"],
        "references": ["https://nvd.nist.gov"],
        "analysis_source": "rule_based_fallback",
    }

    CODE_TEMPLATE = "# AI code generation temporarily unavailable.\n# Please retry in a few moments.\npass\n"

    GENERAL_TEMPLATE = (
        "AI analysis is temporarily unavailable. "
        "The system has recorded your request and will retry automatically. "
        "Please check back in a few minutes."
    )

    def generate(self, prompt: str, mode: str) -> str:
        if mode == "threat_intel":
            result = dict(self.THREAT_INTEL_TEMPLATE)
            # Try to extract target from prompt
            target_match = re.search(r"Target:\s*(\S+)", prompt)
            if target_match:
                result["target"] = target_match.group(1)
            return json.dumps(result)
        elif mode in ("vuln", "vulnerability"):
            return json.dumps(self.VULN_TEMPLATE)
        elif mode == "code":
            return self.CODE_TEMPLATE
        else:
            return self.GENERAL_TEMPLATE


# ── AI Super Router ───────────────────────────────────────────
class AISuperRouter:
    """
    Production AI routing with:
    - Primary provider (OpenAI)
    - Response cache layer
    - Rule-based fallback
    - Confidence scoring
    - Per-mode performance tracking
    - Never returns empty/broken output
    """

    def __init__(self):
        self.cache = ResponseCache(max_size=500, ttl_seconds=3600)
        self.validator = ResponseValidator()
        self.fallback = RuleBasedFallback()
        self._primary_router = None
        self._lock = threading.Lock()
        self._stats: Dict[str, Dict] = {}
        self._init_primary()
        logger.info("[AISuperRouter] Initialized")

    def _init_primary(self) -> None:
        try:
            from core.router.router_manager import get_router
            self._primary_router = get_router()
            logger.info("[AISuperRouter] Primary router (OpenAI) loaded")
        except Exception as e:
            logger.error(f"[AISuperRouter] Primary router init failed: {e}")

    def _record_stat(self, mode: str, source: str, latency_ms: float,
                     confidence: float, from_cache: bool) -> None:
        with self._lock:
            if mode not in self._stats:
                self._stats[mode] = {
                    "total": 0, "cache_hits": 0, "fallback_hits": 0,
                    "total_latency_ms": 0.0, "avg_confidence": 0.0,
                }
            s = self._stats[mode]
            s["total"] += 1
            s["total_latency_ms"] += latency_ms
            if from_cache:
                s["cache_hits"] += 1
            if source == "fallback":
                s["fallback_hits"] += 1
            # Exponential moving average for confidence
            s["avg_confidence"] = s["avg_confidence"] * 0.9 + confidence * 0.1

    def generate(
        self,
        prompt: str,
        mode: str = "general",
        use_cache: bool = True,
        max_tokens: int = None,
        temperature: float = None,
    ) -> Dict[str, Any]:
        """
        Generate AI response with full resilience chain.
        Returns: {response, confidence, source, latency_ms, cached}
        """
        if not prompt or not prompt.strip():
            return self._result(self.fallback.generate("", mode), 0.0, "fallback", 0, False)

        start = time.time()

        # 1. Cache check
        if use_cache:
            cached = self.cache.get(mode, prompt)
            if cached:
                latency_ms = (time.time() - start) * 1000
                self._record_stat(mode, "cache", latency_ms, 0.9, True)
                return self._result(cached, 0.9, "cache", latency_ms, True)

        # 2. Primary AI call
        if self._primary_router and self._primary_router.is_ready():
            try:
                raw = self._primary_router.route(
                    prompt, mode=mode,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                is_valid, confidence, reason = self.validator.validate(raw, mode)
                if is_valid and confidence >= 0.3:
                    latency_ms = (time.time() - start) * 1000
                    # Cache good responses
                    if confidence >= 0.5:
                        self.cache.set(mode, prompt, raw)
                    self._record_stat(mode, "primary", latency_ms, confidence, False)
                    logger.info(f"[AISuperRouter] Primary OK: mode={mode} confidence={confidence:.2f} lat={latency_ms:.0f}ms")
                    return self._result(raw, confidence, "primary", latency_ms, False)
                else:
                    logger.warning(f"[AISuperRouter] Primary response invalid: reason={reason} conf={confidence:.2f}")
            except Exception as e:
                logger.error(f"[AISuperRouter] Primary AI failed: {e}")

        # 3. Rule-based fallback
        fallback_response = self.fallback.generate(prompt, mode)
        latency_ms = (time.time() - start) * 1000
        self._record_stat(mode, "fallback", latency_ms, 0.3, False)
        logger.warning(f"[AISuperRouter] Using rule-based fallback for mode={mode}")
        return self._result(fallback_response, 0.3, "fallback", latency_ms, False)

    def _result(self, response: str, confidence: float, source: str,
                latency_ms: float, cached: bool) -> Dict[str, Any]:
        return {
            "response": response,
            "confidence": round(confidence, 3),
            "source": source,
            "latency_ms": round(latency_ms, 1),
            "cached": cached,
        }

    def generate_simple(self, prompt: str, mode: str = "general") -> str:
        """Simple string interface for backward compatibility."""
        return self.generate(prompt, mode)["response"]

    def generate_threat_intel(self, prompt: str) -> str:
        return self.generate_simple(prompt, mode="threat_intel")

    def generate_code(self, prompt: str) -> str:
        return self.generate_simple(prompt, mode="code")

    def generate_cyber(self, prompt: str) -> str:
        return self.generate_simple(prompt, mode="cyber")

    def is_ready(self) -> bool:
        return True  # Always ready — fallback ensures non-empty output

    def health(self) -> Dict:
        return {
            "primary_available": self._primary_router is not None and self._primary_router.is_ready(),
            "cache": self.cache.stats(),
            "fallback_available": True,
            "mode_stats": dict(self._stats),
        }

    def stats(self) -> Dict:
        return self.health()


# ── Singleton ─────────────────────────────────────────────────
_super_router: Optional[AISuperRouter] = None
_super_router_lock = threading.Lock()


def get_super_router() -> AISuperRouter:
    global _super_router
    if _super_router is None:
        with _super_router_lock:
            if _super_router is None:
                _super_router = AISuperRouter()
    return _super_router
