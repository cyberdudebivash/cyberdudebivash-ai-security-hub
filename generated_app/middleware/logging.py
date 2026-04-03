# ============================================================
# CYBERDUDEBIVASH AI — LOGGING MIDDLEWARE
# ============================================================

from core.logging_config import log_event as _log_event
from typing import Any, Dict


def log_event(event_type: str, data: Dict[str, Any], level: str = "info") -> None:
    """Emit a structured log event — delegates to core logger."""
    try:
        _log_event(event_type, data, level)
    except Exception:
        pass  # Logging must never crash the request
