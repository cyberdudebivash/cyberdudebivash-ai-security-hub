# ============================================================
# CYBERDUDEBIVASH AI — GENERATED TOOL VALIDATOR
# Quality control: syntax check, security scan, completeness
# check for all generated artifacts before storage/release
# ============================================================

import ast
import re
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from core.logging_config import get_logger

logger = get_logger("cyber_tool_engine.validator")

# Security patterns that must NOT appear in generated tools
# (prevents generating malicious code)
FORBIDDEN_PATTERNS = [
    r"os\.system\(.*rm\s+-rf",
    r"subprocess.*shell=True.*rm",
    r"format.*\bC:\\\\\s*>",
    r"shutil\.rmtree\(['\"]\/['\"]",
    r"open\(['\"]\/etc\/shadow",
    r"chmod.*0o777.*\/etc",
]

# Quality indicators that SHOULD appear in production tools
QUALITY_INDICATORS = {
    "python": {
        "has_main":       (r"if __name__\s*==\s*['\"]__main__['\"]", 5),
        "has_logging":    (r"\bimport logging\b|\bfrom logging\b", 3),
        "has_argparse":   (r"\bimport argparse\b|\bargparse\b", 3),
        "has_docstring":  (r'"""[^"]+"""', 3),
        "has_error_handling": (r"\btry\b.*\bexcept\b", 5),
        "has_type_hints": (r"def \w+\([^)]*:[^)]*\)\s*->", 2),
    },
    "yara": {
        "has_meta":     (r"\bmeta\s*:", 4),
        "has_strings":  (r"\bstrings\s*:", 5),
        "has_condition":(r"\bcondition\s*:", 5),
        "has_author":   (r'\bauthor\s*=', 2),
        "has_date":     (r'\bdate\s*=', 1),
    },
    "sigma": {
        "has_title":      (r"^title\s*:", 5),
        "has_status":     (r"^status\s*:", 3),
        "has_logsource":  (r"^logsource\s*:", 5),
        "has_detection":  (r"^detection\s*:", 5),
        "has_condition":  (r"\s+condition\s*:", 4),
    },
    "snort": {
        "has_alert":    (r"^alert\s+", 5),
        "has_msg":      (r'\bmsg\s*:', 4),
        "has_sid":      (r'\bsid\s*:\s*\d+', 4),
        "has_rev":      (r'\brev\s*:\s*\d+', 2),
    },
    "suricata": {
        "has_alert":    (r"^alert\s+", 5),
        "has_msg":      (r'\bmsg\s*:', 4),
        "has_sid":      (r'\bsid\s*:\s*\d+', 4),
    },
    "markdown": {
        "has_heading":  (r"^#{1,3}\s+\w+", 3),
        "has_steps":    (r"^\d+\.", 4),
        "has_sections": (r"^##\s+", 3),
    },
}


@dataclass
class ValidationResult:
    """Result of artifact validation."""
    is_valid: bool = True
    quality_score: float = 0.0       # 0.0–1.0
    artifact_type: str = ""
    issues: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    quality_indicators_met: List[str] = field(default_factory=list)
    quality_indicators_missed: List[str] = field(default_factory=list)
    line_count: int = 0
    char_count: int = 0

    def to_dict(self) -> Dict:
        return {
            "is_valid": self.is_valid,
            "quality_score": round(self.quality_score, 3),
            "artifact_type": self.artifact_type,
            "issues": self.issues,
            "warnings": self.warnings,
            "quality_indicators_met": self.quality_indicators_met,
            "line_count": self.line_count,
            "char_count": self.char_count,
        }


class ArtifactValidator:
    """
    Multi-type validator for all generated cybersecurity artifacts.
    Checks: syntax, security, completeness, quality.
    """

    MIN_LENGTHS = {
        "python": 200,
        "yara":   100,
        "sigma":  150,
        "snort":   50,
        "suricata": 50,
        "markdown": 300,
        "bash":     50,
    }

    def validate(self, content: str, artifact_type: str) -> ValidationResult:
        """Validate any generated artifact."""
        result = ValidationResult(artifact_type=artifact_type)

        if not content or not content.strip():
            result.is_valid = False
            result.issues.append("Empty content")
            return result

        result.line_count = content.count("\n")
        result.char_count = len(content)

        # 1. Minimum length check
        min_len = self.MIN_LENGTHS.get(artifact_type, 50)
        if len(content) < min_len:
            result.issues.append(f"Content too short: {len(content)} chars (min {min_len})")
            result.is_valid = False

        # 2. Security check — no dangerous patterns
        for pattern in FORBIDDEN_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                result.issues.append(f"Forbidden pattern detected: {pattern[:50]}")
                result.is_valid = False

        # 3. Type-specific validation
        if artifact_type == "python":
            self._validate_python(content, result)
        elif artifact_type == "yara":
            self._validate_yara(content, result)
        elif artifact_type == "sigma":
            self._validate_sigma(content, result)
        elif artifact_type in ("snort", "suricata"):
            self._validate_network_rule(content, result, artifact_type)
        elif artifact_type in ("markdown", "ir_playbook", "soc_workflow"):
            self._validate_markdown(content, result)
        elif artifact_type == "bash":
            self._validate_bash(content, result)

        # 4. Quality scoring
        result.quality_score = self._compute_quality(content, artifact_type, result)

        logger.debug(
            f"[Validator] {artifact_type}: valid={result.is_valid} "
            f"score={result.quality_score:.2f} issues={len(result.issues)}"
        )
        return result

    def _validate_python(self, content: str, result: ValidationResult) -> None:
        """Python-specific validation."""
        # Syntax check via AST
        try:
            ast.parse(content)
            result.quality_indicators_met.append("syntax_valid")
        except SyntaxError as e:
            result.issues.append(f"Python syntax error: {e}")
            result.is_valid = False
            return

        # Check quality indicators
        indicators = QUALITY_INDICATORS.get("python", {})
        for name, (pattern, _) in indicators.items():
            if re.search(pattern, content, re.DOTALL | re.MULTILINE):
                result.quality_indicators_met.append(name)
            else:
                result.quality_indicators_missed.append(name)

        # Security checks for Python
        dangerous = [
            (r"\beval\s*\(", "eval() usage"),
            (r"\bexec\s*\(", "exec() usage"),
            (r"__import__\s*\(", "__import__ usage"),
            (r"subprocess.*shell\s*=\s*True", "shell=True in subprocess"),
        ]
        for pattern, label in dangerous:
            if re.search(pattern, content):
                result.warnings.append(f"Security warning: {label}")

    def _validate_yara(self, content: str, result: ValidationResult) -> None:
        """YARA rule validation."""
        indicators = QUALITY_INDICATORS.get("yara", {})
        for name, (pattern, _) in indicators.items():
            if re.search(pattern, content, re.MULTILINE):
                result.quality_indicators_met.append(name)
            else:
                result.quality_indicators_missed.append(name)

        # Check rule structure
        if not re.search(r"\brule\s+\w+", content):
            result.issues.append("No rule declaration found")
            result.is_valid = False
            return

        # Must have condition
        if "condition:" not in content:
            result.issues.append("No condition block in YARA rule")
            result.is_valid = False

        # Check for common YARA mistakes
        if re.search(r"\$\w+\s*=\s*\"\"", content):
            result.warnings.append("Empty string in YARA strings section")

    def _validate_sigma(self, content: str, result: ValidationResult) -> None:
        """Sigma rule validation."""
        indicators = QUALITY_INDICATORS.get("sigma", {})
        for name, (pattern, _) in indicators.items():
            if re.search(pattern, content, re.MULTILINE):
                result.quality_indicators_met.append(name)
            else:
                result.quality_indicators_missed.append(name)

        # Try YAML parse
        try:
            import yaml
            parsed = yaml.safe_load(content)
            if not isinstance(parsed, dict):
                result.issues.append("Sigma rule is not valid YAML dict")
                result.is_valid = False
                return
            # Required fields
            for req_field in ("title", "logsource", "detection"):
                if req_field not in parsed:
                    result.issues.append(f"Missing required Sigma field: {req_field}")
                    result.is_valid = False
        except ImportError:
            # yaml not installed — skip YAML parse, do regex checks
            if "title:" not in content:
                result.issues.append("No title field in Sigma rule")
        except Exception as e:
            result.warnings.append(f"Sigma YAML parse warning: {e}")

    def _validate_network_rule(self, content: str, result: ValidationResult,
                                rule_type: str) -> None:
        """Snort/Suricata rule validation."""
        indicators = QUALITY_INDICATORS.get(rule_type, {})
        for name, (pattern, _) in indicators.items():
            if re.search(pattern, content, re.MULTILINE):
                result.quality_indicators_met.append(name)
            else:
                result.quality_indicators_missed.append(name)

        # Each non-comment line should be a valid rule
        rule_lines = [l for l in content.split("\n")
                     if l.strip() and not l.strip().startswith("#")]
        valid_rules = sum(1 for l in rule_lines
                         if re.match(r"^(alert|drop|pass|reject|log)\s+", l.strip()))

        if rule_lines and valid_rules == 0:
            result.issues.append(f"No valid {rule_type} rules found")
            result.is_valid = False

        if valid_rules > 0:
            result.quality_indicators_met.append(f"{valid_rules}_valid_rules")

    def _validate_markdown(self, content: str, result: ValidationResult) -> None:
        """Markdown playbook validation."""
        indicators = QUALITY_INDICATORS.get("markdown", {})
        for name, (pattern, _) in indicators.items():
            if re.search(pattern, content, re.MULTILINE):
                result.quality_indicators_met.append(name)
            else:
                result.quality_indicators_missed.append(name)

        # Must have at least one heading
        if not re.search(r"^#", content, re.MULTILINE):
            result.issues.append("Playbook has no headings (not valid Markdown)")

    def _validate_bash(self, content: str, result: ValidationResult) -> None:
        """Bash script validation."""
        if not content.startswith("#!"):
            result.warnings.append("No shebang line")
        if "rm -rf /" in content or "rm -rf /*" in content:
            result.issues.append("Dangerous rm command detected")
            result.is_valid = False

    def _compute_quality(self, content: str, artifact_type: str,
                         result: ValidationResult) -> float:
        """Compute quality score 0.0–1.0."""
        if not result.is_valid:
            return 0.0

        indicators = QUALITY_INDICATORS.get(artifact_type, {})
        if not indicators:
            base = 0.6
        else:
            max_pts = sum(pts for _, pts in indicators.values())
            earned = sum(
                pts for name, (_, pts) in indicators.items()
                if name in result.quality_indicators_met
            )
            indicator_score = earned / max(max_pts, 1)
            base = 0.3 + (indicator_score * 0.5)

        # Length bonus
        min_len = self.MIN_LENGTHS.get(artifact_type, 50)
        if len(content) > min_len * 3:
            base += 0.1
        elif len(content) > min_len * 2:
            base += 0.05

        # Penalty for warnings
        base -= len(result.warnings) * 0.05
        base -= len(result.issues) * 0.1

        return round(max(0.0, min(1.0, base)), 3)


class ToolValidationEngine:
    """
    Validates all generated artifacts and assigns monetization tier
    based on quality score.
    """

    TIER_THRESHOLDS = {
        "enterprise": 0.85,
        "premium":    0.65,
        "free":       0.0,
    }

    def __init__(self):
        self.validator = ArtifactValidator()

    def validate_all(self, artifacts: Dict[str, str]) -> Dict[str, ValidationResult]:
        """Validate all artifacts in a generation job."""
        results = {}
        for name, content in artifacts.items():
            artifact_type = self._detect_type(name, content)
            results[name] = self.validator.validate(content, artifact_type)
        return results

    def assign_tier(self, quality_score: float) -> str:
        """Assign monetization tier based on quality score."""
        for tier, threshold in self.TIER_THRESHOLDS.items():
            if quality_score >= threshold:
                return tier
        return "free"

    def _detect_type(self, name: str, content: str) -> str:
        name_lower = name.lower()
        if "yara" in name_lower:
            return "yara"
        if "sigma" in name_lower:
            return "sigma"
        if "snort" in name_lower:
            return "snort"
        if "suricata" in name_lower:
            return "suricata"
        if "playbook" in name_lower or "workflow" in name_lower:
            return "markdown"
        if ".sh" in name_lower or "bash" in name_lower:
            return "bash"
        if content.strip().startswith("#!/") and "bash" in content[:20]:
            return "bash"
        if content.strip().startswith("rule "):
            return "yara"
        if "title:" in content[:50] and "detection:" in content:
            return "sigma"
        if re.match(r"^(alert|drop|pass)", content.strip()):
            return "snort"
        if content.strip().startswith("def ") or "import " in content[:100]:
            return "python"
        if content.strip().startswith("#"):
            return "markdown"
        return "python"  # default


# Singleton
_validator: Optional[ToolValidationEngine] = None

def get_validator() -> ToolValidationEngine:
    global _validator
    if _validator is None:
        _validator = ToolValidationEngine()
    return _validator
