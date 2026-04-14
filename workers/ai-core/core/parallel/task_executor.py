# ============================================================
# CYBERDUDEBIVASH AI — PARALLEL TASK EXECUTOR
# ============================================================

import concurrent.futures
import time
from typing import Any, Callable, Dict, List, Optional
from core.logging_config import get_logger

logger = get_logger("parallel.executor")


class ParallelTaskExecutor:
    """Execute multiple tasks concurrently with timeout handling."""

    def __init__(self, max_workers: int = 4, timeout: int = 120):
        self.max_workers = max_workers
        self.timeout = timeout

    def execute_many(
        self,
        tasks: List[Dict[str, Any]],
        handler: Callable[[Dict], Any],
    ) -> List[Dict[str, Any]]:
        """Run all tasks through handler concurrently."""
        results = []
        start = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_map = {executor.submit(handler, task): task for task in tasks}

            for future in concurrent.futures.as_completed(future_map, timeout=self.timeout):
                task = future_map[future]
                try:
                    result = future.result(timeout=self.timeout)
                    results.append({"task": task, "status": "success", "result": result})
                except concurrent.futures.TimeoutError:
                    logger.warning(f"Task timed out: {task}")
                    results.append({"task": task, "status": "timeout", "result": None})
                except Exception as e:
                    logger.error(f"Task failed: {task} — {e}")
                    results.append({"task": task, "status": "error", "error": str(e)})

        duration = round(time.time() - start, 2)
        logger.info(f"Parallel execution: {len(results)} tasks in {duration}s")
        return results

    def execute_with_fallback(
        self,
        task: Dict[str, Any],
        primary: Callable,
        fallback: Callable,
    ) -> Any:
        """Try primary handler; fall back to secondary on failure."""
        try:
            return primary(task)
        except Exception as e:
            logger.warning(f"Primary handler failed ({e}), using fallback")
            return fallback(task)
