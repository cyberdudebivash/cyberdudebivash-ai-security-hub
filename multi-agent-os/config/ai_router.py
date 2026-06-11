"""
AI Provider Router — Provider-agnostic LLM orchestration.
Priority: Groq → DeepSeek → Cloudflare AI → OpenRouter → Anthropic (optional).
NO single-provider dependency. Automatic failover.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Dict, List, Optional

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

try:
    import structlog
    logger = structlog.get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

PROVIDER_PRIORITY = ["groq", "deepseek", "cloudflare", "openrouter", "anthropic"]

TASK_PROVIDER_MAP = {
    "threat_intel_analysis":  "groq",
    "vulnerability_analysis": "groq",
    "malware_analysis":       "deepseek",
    "executive_report":       "groq",
    "compliance_analysis":    "deepseek",
    "ai_security":            "groq",
    "ai_governance":          "deepseek",
    "threat_actor_analysis":  "groq",
    "incident_response":      "groq",
    "threat_hunting":         "groq",
    "soc_triage":             "cloudflare",
    "research":               "deepseek",
}

PROVIDER_MODELS = {
    "groq":        "llama-3.3-70b-versatile",
    "deepseek":    "deepseek-chat",
    "cloudflare":  "@cf/meta/llama-3.1-8b-instruct",
    "openrouter":  "meta-llama/llama-3.3-70b-instruct",
    "anthropic":   "claude-3-5-haiku-20241022",
}

class AIProviderRouter:
    """
    Routes AI generation requests to the optimal available provider.
    Supports automatic failover across all configured providers.
    Platform NEVER fails due to a single AI provider being down.
    """

    def __init__(
        self,
        groq_api_key:       str = "",
        deepseek_api_key:   str = "",
        openrouter_api_key: str = "",
        anthropic_api_key:  str = "",  # OPTIONAL
        cloudflare_account: str = "",
        cloudflare_token:   str = "",
    ):
        self._keys = {
            "groq":       groq_api_key,
            "deepseek":   deepseek_api_key,
            "openrouter": openrouter_api_key,
            "anthropic":  anthropic_api_key,
            "cloudflare": (cloudflare_account, cloudflare_token),
        }
        self._available: List[str]    = []
        self._latency:   Dict[str, float] = {}
        self._errors:    Dict[str, int]   = {}
        self._client     = httpx.AsyncClient(timeout=30.0)

    async def initialize(self):
        """Probe all providers and build available list."""
        self._available = []
        for provider in PROVIDER_PRIORITY:
            if await self._probe(provider):
                self._available.append(provider)
                logger.info("ai_router.provider_available", provider=provider)
            else:
                logger.warning("ai_router.provider_unavailable", provider=provider)
        if not self._available:
            logger.error("ai_router.no_providers", message="All AI providers unavailable — responses will be degraded")

    @property
    def active_provider_count(self) -> int:
        return len(self._available)

    async def generate(
        self,
        prompt:     str,
        task_type:  str = "general",
        max_tokens: int = 2000,
        temperature: float = 0.1,
    ) -> Dict[str, Any]:
        """
        Generate a response from the best available provider.
        Returns parsed JSON dict or empty dict on complete failure.
        """
        # Prefer task-specific provider if available
        preferred = TASK_PROVIDER_MAP.get(task_type)
        ordered   = []
        if preferred and preferred in self._available:
            ordered.append(preferred)
        ordered.extend(p for p in self._available if p != preferred)

        for provider in ordered:
            try:
                start  = time.monotonic()
                result = await self._call_provider(provider, prompt, max_tokens, temperature)
                self._latency[provider] = time.monotonic() - start
                self._errors[provider]  = 0
                return result
            except Exception as e:
                self._errors[provider] = self._errors.get(provider, 0) + 1
                logger.warning("ai_router.provider_error", provider=provider, error=str(e)[:100])
                if self._errors.get(provider, 0) >= 3:
                    if provider in self._available:
                        self._available.remove(provider)
                    logger.error("ai_router.provider_removed", provider=provider)

        logger.error("ai_router.all_providers_failed", task_type=task_type)
        return {}  # Graceful degradation — never raise, always return

    async def _call_provider(self, provider: str, prompt: str, max_tokens: int, temperature: float) -> Dict:
        model = PROVIDER_MODELS[provider]

        if provider == "groq":
            return await self._call_openai_compatible(
                "https://api.groq.com/openai/v1/chat/completions",
                self._keys["groq"], model, prompt, max_tokens, temperature
            )
        elif provider == "deepseek":
            return await self._call_openai_compatible(
                "https://api.deepseek.com/v1/chat/completions",
                self._keys["deepseek"], model, prompt, max_tokens, temperature
            )
        elif provider == "openrouter":
            return await self._call_openai_compatible(
                "https://openrouter.ai/api/v1/chat/completions",
                self._keys["openrouter"], model, prompt, max_tokens, temperature
            )
        elif provider == "cloudflare":
            return await self._call_cloudflare(prompt, model, max_tokens)
        elif provider == "anthropic":
            return await self._call_anthropic(prompt, max_tokens, temperature)
        return {}

    async def _call_openai_compatible(
        self, url: str, api_key: str, model: str,
        prompt: str, max_tokens: int, temperature: float
    ) -> Dict:
        resp = await self._client.post(
            url,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model":       model,
                "messages":    [{"role": "user", "content": prompt}],
                "max_tokens":  max_tokens,
                "temperature": temperature,
                "response_format": {"type": "json_object"},
            },
            timeout=30.0,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        return json.loads(content)

    async def _call_cloudflare(self, prompt: str, model: str, max_tokens: int) -> Dict:
        account, token = self._keys["cloudflare"]
        if not account or not token:
            raise ValueError("Cloudflare credentials not configured")
        resp = await self._client.post(
            f"https://api.cloudflare.com/client/v4/accounts/{account}/ai/run/{model}",
            headers={"Authorization": f"Bearer {token}"},
            json={"messages": [{"role": "user", "content": prompt}], "max_tokens": max_tokens},
        )
        resp.raise_for_status()
        text = resp.json().get("result", {}).get("response", "{}")
        try:
            return json.loads(text)
        except Exception:
            return {"text": text}

    async def _call_anthropic(self, prompt: str, max_tokens: int, temperature: float) -> Dict:
        """Anthropic is OPTIONAL — only called if configured and all other providers fail."""
        if not self._keys["anthropic"]:
            raise ValueError("Anthropic API key not configured (optional provider)")
        resp = await self._client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key":         self._keys["anthropic"],
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            },
            json={
                "model":      PROVIDER_MODELS["anthropic"],
                "max_tokens": max_tokens,
                "messages":   [{"role": "user", "content": prompt}],
            },
        )
        resp.raise_for_status()
        content = resp.json()["content"][0]["text"]
        try:
            return json.loads(content)
        except Exception:
            return {"text": content}

    async def _probe(self, provider: str) -> bool:
        """Quick health check for a provider."""
        try:
            result = await asyncio.wait_for(
                self._call_provider(provider, '{"health":"check"}', 10, 0),
                timeout=5.0
            )
            return True
        except Exception:
            return bool(
                (provider == "groq"       and self._keys["groq"])       or
                (provider == "deepseek"   and self._keys["deepseek"])   or
                (provider == "openrouter" and self._keys["openrouter"]) or
                (provider == "cloudflare" and all(self._keys["cloudflare"])) or
                (provider == "anthropic"  and self._keys["anthropic"])
            )

    async def status(self) -> Dict[str, Any]:
        return {
            "available_providers": self._available,
            "total_configured":    sum(1 for p in PROVIDER_PRIORITY if
                                       (p != "cloudflare" and self._keys.get(p)) or
                                       (p == "cloudflare" and all(self._keys.get("cloudflare", ())))),
            "latency_ms":   {k: round(v*1000, 1) for k, v in self._latency.items()},
            "error_counts": self._errors,
            "anthropic_status": "optional - " + ("configured" if self._keys.get("anthropic") else "not configured"),
        }
