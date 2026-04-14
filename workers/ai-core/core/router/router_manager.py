# ============================================================
# CYBERDUDEBIVASH AI — ROUTER MANAGER (PRODUCTION HARDENED)
# Fixes: thread-safe singleton, graceful degradation, health probe
# ============================================================

import time
import logging
import threading
from core.settings import settings

logger = logging.getLogger("cdb_ai.router")

# FALLBACK_RESPONSES mirrors openai_router — used when router is unavailable
_DEGRADED_FALLBACKS = {
    "threat_intel": '{"threat_level":"UNKNOWN","threat_score":0,"is_malicious":false,"summary":"AI router unavailable. Manual review required.","recommendations":["Perform manual investigation"]}',
    "cyber": "Security analysis temporarily unavailable.",
    "code": "# Code generation temporarily unavailable.",
    "general": "AI response temporarily unavailable.",
}


class RouterManager:
    """
    Unified AI Router.
    - Thread-safe initialization (fix: race condition in singleton)
    - Graceful degradation when no provider available
    - Health check support
    """

    def __init__(self):
        self.routers = {}
        self.default_provider = "openai"
        self._lock = threading.Lock()
        self._init_routers()

    def _init_routers(self):
        if settings.openai_api_key and settings.openai_api_key.strip():
            try:
                from core.router.openai_router import OpenAIRouter
                self.routers["openai"] = OpenAIRouter()
                logger.info("OpenAI router loaded")
            except Exception as e:
                logger.error(f"OpenAI router failed to load: {e}")
        else:
            logger.warning("OPENAI_API_KEY not configured — AI features degraded")

        if not self.routers:
            logger.error("No AI routers available — system running in degraded mode")

    def route(
        self,
        prompt: str,
        mode: str = "general",
        provider: str = None,
        **kwargs,
    ) -> str:
        if not prompt or not prompt.strip():
            return _DEGRADED_FALLBACKS.get(mode, _DEGRADED_FALLBACKS["general"])

        provider = provider or self.default_provider

        if provider not in self.routers:
            if self.routers:
                provider = next(iter(self.routers))
                logger.warning(f"Provider '{provider}' not found — falling back")
            else:
                return self._degraded_response(prompt, mode)

        start = time.time()
        try:
            result = self.routers[provider].generate(prompt, mode=mode, **kwargs)
            duration = round(time.time() - start, 2)
            logger.info(f"Router [{provider}/{mode}] completed in {duration}s")
            return result
        except Exception as e:
            logger.error(f"Router [{provider}] failed: {e}")
            return self._degraded_response(prompt, mode)

    def generate_code(self, prompt: str) -> str:
        return self.route(prompt, mode="code")

    def generate_cyber(self, prompt: str) -> str:
        return self.route(prompt, mode="cyber")

    def generate_threat_intel(self, prompt: str) -> str:
        return self.route(prompt, mode="threat_intel")

    def _degraded_response(self, prompt: str, mode: str = "general") -> str:
        logger.error(f"All routers unavailable — degraded response for mode={mode}")
        return _DEGRADED_FALLBACKS.get(mode, _DEGRADED_FALLBACKS["general"])

    def is_ready(self) -> bool:
        return bool(self.routers)

    def health(self) -> dict:
        return {
            "providers": list(self.routers.keys()),
            "ready": self.is_ready(),
            "default": self.default_provider,
        }


# Thread-safe singleton
_router_manager: RouterManager = None
_router_lock = threading.Lock()


def get_router() -> RouterManager:
    global _router_manager
    if _router_manager is None:
        with _router_lock:  # Fix: double-checked locking
            if _router_manager is None:
                _router_manager = RouterManager()
    return _router_manager
