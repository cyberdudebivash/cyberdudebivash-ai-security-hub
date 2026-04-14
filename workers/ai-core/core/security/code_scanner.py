# ============================================================
# CYBERDUDEBIVASH AI — SAST CODE SCANNER
# ============================================================

import os
import re
from typing import Dict, List, Tuple
from core.logging_config import get_logger

logger = get_logger("security.scanner")

SAST_RULES: List[Tuple[str, str, str, str]] = [
    # (pattern, severity, category, description)
    (r"eval\s*\(", "HIGH", "code_injection", "Use of eval() — remote code execution risk"),
    (r"exec\s*\(", "HIGH", "code_injection", "Use of exec() — code injection risk"),
    (r"os\.system\s*\(", "HIGH", "command_injection", "os.system() — command injection risk"),
    (r"subprocess\.call\s*\(.*shell\s*=\s*True", "HIGH", "command_injection", "subprocess shell=True — command injection"),
    (r"pickle\.loads?\s*\(", "HIGH", "deserialization", "pickle.load() — insecure deserialization"),
    (r"yaml\.load\s*\([^)]*\)", "MEDIUM", "deserialization", "yaml.load() without Loader — insecure"),
    (r"SECRET\s*=\s*['\"][a-zA-Z0-9]", "HIGH", "hardcoded_secret", "Hardcoded secret value detected"),
    (r"password\s*=\s*['\"][a-zA-Z0-9]", "HIGH", "hardcoded_secret", "Hardcoded password detected"),
    (r"api_key\s*=\s*['\"][a-zA-Z0-9]", "HIGH", "hardcoded_secret", "Hardcoded API key detected"),
    (r"md5\s*\(", "MEDIUM", "weak_crypto", "MD5 is cryptographically weak"),
    (r"sha1\s*\(", "MEDIUM", "weak_crypto", "SHA1 is cryptographically weak"),
    (r"random\.random\s*\(", "LOW", "weak_random", "random.random() not suitable for security"),
    (r"SQL\s*=.*%s", "HIGH", "sql_injection", "String formatting in SQL — SQLi risk"),
    (r"SELECT.*\+.*request", "HIGH", "sql_injection", "Possible SQL injection via user input"),
    (r"DEBUG\s*=\s*True", "MEDIUM", "configuration", "DEBUG mode enabled in production"),
    (r"ALLOW_ALL_ORIGINS\s*=\s*True", "MEDIUM", "cors", "CORS allows all origins"),
    (r"verify\s*=\s*False", "MEDIUM", "ssl", "SSL verification disabled"),
    (r"os\.chmod\s*\(.*0o777", "MEDIUM", "file_permissions", "World-writable file permissions"),
    (r"open\s*\(.*['\"]w['\"].*request", "HIGH", "path_traversal", "Possible path traversal via user input"),
]


class CodeScanner:
    """SAST scanner for Python source files."""

    def scan_file(self, path: str) -> List[Dict]:
        findings = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for line_num, line in enumerate(lines, 1):
                for pattern, severity, category, description in SAST_RULES:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "file": path,
                            "line": line_num,
                            "severity": severity,
                            "category": category,
                            "description": description,
                            "code": line.strip()[:200],
                        })
        except Exception as e:
            logger.warning(f"Could not scan {path}: {e}")
        return findings

    def scan(self, project_path: str = ".") -> Dict:
        all_findings = []
        scanned_files = 0

        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if d not in {"__pycache__", ".git", "node_modules", "venv", ".venv"}]
            for fname in files:
                if fname.endswith(".py"):
                    path = os.path.join(root, fname)
                    findings = self.scan_file(path)
                    all_findings.extend(findings)
                    scanned_files += 1

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in all_findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        overall = "PASS"
        if severity_counts["CRITICAL"] > 0 or severity_counts["HIGH"] > 0:
            overall = "FAIL"
        elif severity_counts["MEDIUM"] > 0:
            overall = "WARNING"

        logger.info(f"SAST scan complete: {scanned_files} files, {len(all_findings)} findings")
        return {
            "scanned_files": scanned_files,
            "total_findings": len(all_findings),
            "severity_summary": severity_counts,
            "overall_status": overall,
            "findings": all_findings,
        }
