# ============================================================
# CYBERDUDEBIVASH AI — SECURITY MIDDLEWARE (HARDENED)
# ============================================================

from fastapi import HTTPException, Request
from core.logging_config import get_logger

logger = get_logger("middleware.security")

# Patterns that indicate injection or abuse attempts
_INJECTION_PATTERNS = [
    "<script", "javascript:", "onload=", "onerror=",  # XSS
    "'; DROP", "UNION SELECT", "1=1--", "' OR '",    # SQLi
    "${7*7}", "{{7*7}}", "#{7*7}",                    # Template injection
    "../../../", "..\\..\\",                           # Path traversal
]


def detect_abuse(request_count: int, threshold: int = 10000) -> None:
    """Detect and block abusive traffic volumes."""
    if request_count > threshold:
        raise HTTPException(status_code=429, detail="Abuse detected — request volume exceeded")


def scan_for_injection(value: str) -> bool:
    """Return True if value contains potential injection patterns."""
    if not value:
        return False
    value_lower = value.lower()
    return any(p.lower() in value_lower for p in _INJECTION_PATTERNS)


def validate_request_headers(request: Request) -> None:
    """Validate critical request headers."""
    content_type = request.headers.get("content-type", "")
    if request.method in ("POST", "PUT", "PATCH"):
        if content_type and "application/json" not in content_type and "multipart" not in content_type:
            logger.warning(f"Unexpected content-type: {content_type} from {request.client}")
