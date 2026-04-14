# ============================================================
# CYBERDUDEBIVASH AI — OPENAI ROUTER (PRODUCTION HARDENED)
# Fixes: timeout, exponential backoff, input truncation, thread safety
# ============================================================

import time
import logging
from openai import OpenAI, RateLimitError, APIError, APITimeoutError, APIConnectionError
from core.settings import settings

logger = logging.getLogger("cdb_ai.router.openai")

# Maximum prompt characters we send to the API (prevent runaway costs)
MAX_PROMPT_CHARS = 20_000

SYSTEM_PROMPTS = {
    "code": (
        "You are a senior software engineer specializing in Python and FastAPI. "
        "Generate production-ready, clean, fully functional code. "
        "Return ONLY code with no explanations unless asked."
    ),
    "cyber": (
        "You are a senior cybersecurity analyst and threat intelligence expert. "
        "Provide detailed, accurate, actionable cybersecurity analysis. "
        "Structure your findings with severity levels (CRITICAL/HIGH/MEDIUM/LOW/INFO)."
    ),
    "general": (
        "You are CYBERDUDEBIVASH AI, an autonomous AI system. "
        "Provide expert-level, concise, production-grade responses."
    ),
    "threat_intel": (
        "You are a threat intelligence analyst. Analyze the provided data and return "
        "structured JSON with: threat_level, indicators, recommendations, mitigations. "
        "Return ONLY valid JSON, no markdown, no explanation."
    ),
}

FALLBACK_RESPONSES = {
    "threat_intel": '{"threat_level":"UNKNOWN","threat_score":0,"is_malicious":false,"summary":"AI analysis temporarily unavailable. Manual review required.","recommendations":["Perform manual investigation"],"mitigations":["Monitor for suspicious activity"]}',
    "cyber": "Security analysis temporarily unavailable. Please retry in a few moments.",
    "code": "# Code generation temporarily unavailable. Please retry.",
    "general": "AI response temporarily unavailable. Please retry.",
}


class OpenAIRouter:
    """
    Production OpenAI router.
    - Per-request timeout (no hung workers)
    - Exponential backoff with jitter
    - Input truncation guard
    - Structured fallback on all failure modes
    - Thread-safe (no shared mutable state)
    """

    def __init__(self):
        if not settings.openai_api_key:
            raise RuntimeError("OPENAI_API_KEY is not configured")
        # Each instance gets its own client — thread-safe
        self.client = OpenAI(
            api_key=settings.openai_api_key,
            timeout=settings.openai_timeout,  # Fix: timeout on every call
            max_retries=0,  # We handle retries ourselves with backoff
        )
        self.model = settings.openai_model
        self.timeout = settings.openai_timeout
        logger.info(f"OpenAI router initialized: model={self.model} timeout={self.timeout}s")

    def generate(
        self,
        prompt: str,
        mode: str = "general",
        max_tokens: int = None,
        temperature: float = None,
        json_mode: bool = False,
    ) -> str:
        if not prompt or not prompt.strip():
            logger.warning("Empty prompt received — returning fallback")
            return FALLBACK_RESPONSES.get(mode, FALLBACK_RESPONSES["general"])

        # Truncate oversized prompts
        if len(prompt) > MAX_PROMPT_CHARS:
            logger.warning(f"Prompt truncated from {len(prompt)} to {MAX_PROMPT_CHARS} chars")
            prompt = prompt[:MAX_PROMPT_CHARS] + "\n\n[TRUNCATED FOR LENGTH]"

        system_prompt = SYSTEM_PROMPTS.get(mode, SYSTEM_PROMPTS["general"])
        max_tok = max_tokens or settings.openai_max_tokens
        temp = temperature if temperature is not None else settings.openai_temperature

        kwargs = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": max_tok,
            "temperature": temp,
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        try:
            return self._call_with_retry(mode=mode, **kwargs)
        except Exception as e:
            logger.error(f"OpenAI router permanently failed for mode={mode}: {e}")
            return FALLBACK_RESPONSES.get(mode, FALLBACK_RESPONSES["general"])

    def _call_with_retry(self, mode: str = "general", retries: int = 3, **kwargs) -> str:
        last_exc = None
        for attempt in range(1, retries + 1):
            try:
                response = self.client.chat.completions.create(**kwargs)
                content = response.choices[0].message.content
                if not content:
                    raise ValueError("OpenAI returned empty content")
                logger.info(f"OpenAI call succeeded on attempt {attempt}/{retries}")
                return content

            except APITimeoutError as e:
                last_exc = e
                wait = min(2 ** attempt + (attempt * 0.5), 30)  # capped exponential backoff
                logger.warning(f"OpenAI timeout (attempt {attempt}/{retries}). Retrying in {wait:.1f}s")
                time.sleep(wait)

            except RateLimitError as e:
                last_exc = e
                wait = min(2 ** (attempt + 1), 60)  # longer wait for rate limits
                logger.warning(f"OpenAI rate limit hit (attempt {attempt}/{retries}). Waiting {wait}s")
                time.sleep(wait)

            except APIConnectionError as e:
                last_exc = e
                wait = min(2 ** attempt, 20)
                logger.warning(f"OpenAI connection error (attempt {attempt}/{retries}): {e}. Retrying in {wait}s")
                time.sleep(wait)

            except APIError as e:
                last_exc = e
                # Non-retriable API errors (4xx client errors)
                if hasattr(e, "status_code") and e.status_code and 400 <= e.status_code < 500:
                    logger.error(f"OpenAI client error {e.status_code} — not retrying: {e}")
                    raise RuntimeError(f"OpenAI client error: {e}")
                logger.error(f"OpenAI API error (attempt {attempt}/{retries}): {e}")
                time.sleep(min(2 ** attempt, 10))

            except Exception as e:
                last_exc = e
                logger.error(f"Unexpected OpenAI error (attempt {attempt}/{retries}): {e}")
                if attempt == retries:
                    break
                time.sleep(min(2 ** attempt, 10))

        raise RuntimeError(f"OpenAI exhausted {retries} retries. Last error: {last_exc}")
