# ============================================================
# CYBERDUDEBIVASH AI — RUNTIME WATCHER
# ============================================================

import threading
from typing import Callable
from core.logging_config import get_logger

logger = get_logger("runtime.watcher")


class RuntimeWatcher:
    """Watches a subprocess stderr stream and calls a callback on errors."""

    def __init__(self, process, on_error: Callable[[str], None]):
        self.process = process
        self.on_error = on_error

    def start(self) -> None:
        threading.Thread(target=self._watch, daemon=True).start()

    def _watch(self) -> None:
        if not self.process or not self.process.stderr:
            return
        for line in self.process.stderr:
            stripped = line.strip()
            if stripped:
                logger.warning(f"[Watcher] Runtime error: {stripped}")
                try:
                    self.on_error(stripped)
                except Exception as e:
                    logger.error(f"[Watcher] Error callback failed: {e}")
