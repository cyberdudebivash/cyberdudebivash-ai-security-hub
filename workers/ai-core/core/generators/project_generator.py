# ============================================================
# CYBERDUDEBIVASH AI — PROJECT GENERATOR
# ============================================================

import os
from core.generators.file_generator import FileGenerator
from core.logging_config import get_logger

logger = get_logger("generators.project")

STANDARD_STRUCTURE = ["routers", "models", "services", "config", "tasks", "agents"]


class ProjectGenerator:
    """Scaffolds a full project from a code map dict."""

    def __init__(self, base_path: str = "workspace"):
        self.base_path = base_path
        self.file_gen = FileGenerator(base_path)

    def create_structure(self) -> None:
        for folder in STANDARD_STRUCTURE:
            path = os.path.join(self.base_path, folder)
            os.makedirs(path, exist_ok=True)
            init = os.path.join(path, "__init__.py")
            if not os.path.exists(init):
                open(init, "w").close()

    def generate_files(self, code_map: dict) -> None:
        for relative_path, content in code_map.items():
            self.file_gen.write_file(relative_path, content)

    def build_project(self, code_map: dict) -> None:
        self.create_structure()
        self.generate_files(code_map)
        logger.info(f"Project built at {self.base_path} with {len(code_map)} files")
