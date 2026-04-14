# ============================================================
# CYBERDUDEBIVASH AI — MEMORY SYSTEM (PRODUCTION HARDENED)
# Fixes: file locking for concurrent access, thread-safe singleton,
#        atomic writes, robust error recovery
# ============================================================

import json
import os
import uuid
import fcntl
import threading
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from core.logging_config import get_logger

logger = get_logger("memory")


def _get_memory_file() -> str:
    """Resolve memory file path at call time (not import time)."""
    memory_dir = os.getenv("MEMORY_DIR", os.path.join(os.getcwd(), "memory"))
    os.makedirs(memory_dir, exist_ok=True)
    return os.path.join(memory_dir, "memory_store.json")


class MemoryStore:
    """
    Persistent + contextual memory system.
    - File locking prevents concurrent write corruption
    - Atomic writes via temp file + rename
    - Thread-safe in-process lock
    - Deduplication on save
    """

    def __init__(self, path: str = None):
        self.path = path or _get_memory_file()
        self._lock = threading.RLock()  # reentrant for nested calls
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        if not os.path.exists(self.path):
            self._atomic_write([])
        logger.info(f"MemoryStore initialized at {self.path}")

    def save(self, task: str, output: Any, tags: List[str] = None) -> str:
        """Save a task result. Deduplicated and thread-safe."""
        if not task or not task.strip():
            return ""

        with self._lock:
            records = self._load_locked()
            # Deduplication
            records = [r for r in records if r.get("task", "").strip() != task.strip()]
            entry = {
                "id": str(uuid.uuid4()),
                "task": task[:500],  # cap task string
                "output": self._safe_serialize(output),
                "tags": tags or [],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            records.append(entry)
            # Rolling window
            if len(records) > 500:
                records = records[-500:]
            self._atomic_write(records)
            logger.debug(f"Memory saved: {task[:60]}")
            return entry["id"]

    def search(self, query: str, limit: int = 5) -> List[Dict]:
        """Thread-safe search by task content."""
        if not query:
            return []
        with self._lock:
            records = self._load_locked()
        query_lower = query.lower()
        matches = [r for r in records if query_lower in r.get("task", "").lower()]
        return matches[-limit:]

    def get_context(self, task: str, limit: int = 3) -> str:
        hits = self.search(task, limit=limit)
        if not hits:
            return ""
        lines = [f"- [{h['timestamp'][:10]}] {h['task']}" for h in hits]
        return "Previous related tasks:\n" + "\n".join(lines)

    def get_all(self) -> List[Dict]:
        with self._lock:
            return self._load_locked()

    def clear(self) -> None:
        with self._lock:
            self._atomic_write([])
        logger.info("Memory cleared")

    def stats(self) -> Dict:
        with self._lock:
            records = self._load_locked()
            size = os.path.getsize(self.path) if os.path.exists(self.path) else 0
        return {
            "total_entries": len(records),
            "memory_file": self.path,
            "size_bytes": size,
        }

    # ── Internal ──────────────────────────────────────────────

    def _load_locked(self) -> List[Dict]:
        """Load with file-level lock (call only from within self._lock context)."""
        if not os.path.exists(self.path):
            return []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                try:
                    fcntl.flock(f, fcntl.LOCK_SH)
                    data = json.load(f)
                    return data if isinstance(data, list) else []
                except json.JSONDecodeError:
                    logger.warning("Memory file corrupted — resetting")
                    return []
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)
        except (OSError, IOError) as e:
            logger.error(f"Memory read error: {e}")
            return []

    def _atomic_write(self, data: List[Dict]) -> None:
        """Atomic write: write to temp file then rename (prevents partial writes)."""
        try:
            dir_path = os.path.dirname(self.path)
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8",
                dir=dir_path, delete=False, suffix=".tmp"
            ) as tf:
                try:
                    fcntl.flock(tf, fcntl.LOCK_EX)
                    json.dump(data, tf, indent=2, default=str)
                    tf.flush()
                    os.fsync(tf.fileno())
                finally:
                    fcntl.flock(tf, fcntl.LOCK_UN)
            os.replace(tf.name, self.path)  # atomic on POSIX
        except Exception as e:
            logger.error(f"Memory write error: {e}")
            # Clean up temp file if it exists
            try:
                if "tf" in dir() and os.path.exists(tf.name):
                    os.unlink(tf.name)
            except Exception:
                pass

    def _safe_serialize(self, obj: Any) -> Any:
        """Ensure output is JSON-serializable."""
        try:
            json.dumps(obj, default=str)
            return obj
        except Exception:
            return str(obj)[:2000]

    # Keep backward-compat internal write for scheduler tasks
    def _write(self, data: List[Dict]) -> None:
        with self._lock:
            self._atomic_write(data)


# Thread-safe singleton
_memory_store: Optional[MemoryStore] = None
_memory_lock = threading.Lock()


def get_memory() -> MemoryStore:
    global _memory_store
    if _memory_store is None:
        with _memory_lock:
            if _memory_store is None:
                _memory_store = MemoryStore()
    return _memory_store
