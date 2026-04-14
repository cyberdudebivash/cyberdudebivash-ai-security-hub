# ============================================================
# CYBERDUDEBIVASH AI — APP RUNNER (subprocess manager)
# ============================================================

import subprocess
import signal
import sys
import time
import threading
from core.logging_config import get_logger

logger = get_logger("runtime.runner")


class AppRunner:
    """Manages a subprocess running a FastAPI/uvicorn application."""

    def __init__(self, module: str = "generated_app.main:app", port: int = 8001, cwd: str = "."):
        self.module = module
        self.port = port
        self.cwd = cwd
        self.process = None

    def start(self) -> None:
        logger.info(f"[Runner] Starting {self.module} on port {self.port}")
        self.process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", self.module,
             "--host", "127.0.0.1", "--port", str(self.port)],
            cwd=self.cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._stream_logs()

    def _stream_logs(self) -> None:
        def _stdout():
            for line in self.process.stdout:
                logger.info(f"[APP] {line.strip()}")

        def _stderr():
            for line in self.process.stderr:
                logger.warning(f"[APP-ERR] {line.strip()}")

        threading.Thread(target=_stdout, daemon=True).start()
        threading.Thread(target=_stderr, daemon=True).start()

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            logger.info("[Runner] Stopping process")
            self.process.send_signal(signal.SIGTERM)
            self.process.wait(timeout=10)

    def restart(self) -> None:
        logger.info("[Runner] Restarting")
        self.stop()
        time.sleep(1)
        self.start()

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None
