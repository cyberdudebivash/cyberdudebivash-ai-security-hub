# ============================================================
# CYBERDUDEBIVASH AI — FILE GENERATOR
# ============================================================

import os
from core.logging_config import get_logger

logger = get_logger("generators.file")


class FileGenerator:
    """Writes generated code to the workspace directory."""

    def __init__(self, base_dir: str = "workspace"):
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)

    def write_file(self, path: str, content: str) -> str:
        full_path = os.path.join(self.base_dir, path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info(f"File written: {full_path}")
        return full_path

    def read_file(self, path: str) -> str:
        full_path = os.path.join(self.base_dir, path)
        with open(full_path, "r", encoding="utf-8") as f:
            return f.read()

    def list_files(self) -> list:
        result = []
        for root, _, files in os.walk(self.base_dir):
            for f in files:
                result.append(os.path.relpath(os.path.join(root, f), self.base_dir))
        return result
