# ============================================================
# CYBERDUDEBIVASH AI — UTILITIES
# ============================================================

import uuid
import hashlib
from datetime import datetime, timezone


def generate_id() -> str:
    return str(uuid.uuid4())

def short_id() -> str:
    return uuid.uuid4().hex[:12]

def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def hash_string(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()

def truncate(text: str, length: int = 100) -> str:
    return text[:length] + "..." if len(text) > length else text
