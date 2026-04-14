# ============================================================
# CYBERDUDEBIVASH AI — STRUCTURED LOGGING (PRODUCTION HARDENED)
# JSON logging, rotation, safe exception formatting
# ============================================================

import logging
import logging.handlers
import json
import sys
import os
import traceback
from datetime import datetime, timezone
from typing import Any, Dict


class JSONFormatter(logging.Formatter):
    """Production-grade JSON log formatter."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "module": record.module,
            "fn": record.funcName,
            "line": record.lineno,
        }

        # Attach exception if present
        if record.exc_info:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": traceback.format_exception(*record.exc_info)[-3:],  # last 3 frames
            }

        # Attach any extra fields
        standard_keys = {
            "name", "msg", "args", "created", "filename", "funcName",
            "levelname", "levelno", "lineno", "module", "msecs", "message",
            "pathname", "process", "processName", "relativeCreated",
            "stack_info", "thread", "threadName", "exc_info", "exc_text",
        }
        for key, val in record.__dict__.items():
            if key not in standard_keys and not key.startswith("_"):
                try:
                    json.dumps({key: val})
                    log_entry[key] = val
                except (TypeError, ValueError):
                    log_entry[key] = str(val)

        try:
            return json.dumps(log_entry, ensure_ascii=False)
        except Exception:
            return json.dumps({"ts": log_entry["ts"], "level": "ERROR",
                               "msg": "Log serialization failed", "raw": str(record.getMessage())})


_logging_configured = False


def setup_logging(level: str = "INFO") -> None:
    """
    Configure root logger. Idempotent — safe to call multiple times.
    """
    global _logging_configured
    if _logging_configured:
        return
    _logging_configured = True

    log_level = getattr(logging, level.upper(), logging.INFO)
    formatter = JSONFormatter()

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    console.setLevel(log_level)

    # Rotating file handler — 10MB per file, keep 5 files
    log_dir = os.getenv("LOG_DIR", "logs")
    os.makedirs(log_dir, exist_ok=True)
    file_handler = logging.handlers.RotatingFileHandler(
        filename=os.path.join(log_dir, "cdb_ai.log"),
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(log_level)

    # Root logger
    root = logging.getLogger()
    root.setLevel(log_level)
    root.handlers.clear()
    root.addHandler(console)
    root.addHandler(file_handler)

    # Suppress noisy libraries
    for noisy in ["uvicorn.access", "sqlalchemy.engine", "httpx", "httpcore"]:
        logging.getLogger(noisy).setLevel(logging.WARNING)

    logging.getLogger("cdb_ai").info(
        f"Logging configured: level={level} log_dir={log_dir}"
    )


def get_logger(name: str) -> logging.Logger:
    """Get a namespaced logger."""
    return logging.getLogger(f"cdb_ai.{name}")


def log_event(event_type: str, data: Dict[str, Any], level: str = "info") -> None:
    """Emit a structured event log."""
    logger = get_logger("events")
    log_data = {
        "event": event_type,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    # Safely merge data
    for k, v in (data or {}).items():
        try:
            json.dumps({k: v})
            log_data[k] = v
        except (TypeError, ValueError):
            log_data[k] = str(v)

    try:
        getattr(logger, level.lower())(json.dumps(log_data))
    except Exception:
        logger.warning(f"log_event failed for event_type={event_type}")
