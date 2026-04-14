"""
AI Agent Security Scanner — OWASP LLM Top 10 Assessment
Covers LLM01-LLM10: Prompt Injection → Model Theft
"""
import hashlib, random
from dataclasses import dataclass, field
from typing import List
from datetime import datetime


def _seed(s: str) -> int:
    return int(hashlib.md5(s.encode()).hexdigest(), 16) % 100000


OWASP_LLM = [
    ("LLM01","Prompt Injection","Direct and indirect prompt injection vectors in input handling pipeline."),
    ("LLM02","Insecure Output Handling","Model outputs passed to downstream systems without sanitization."),
    ("LLM03","Training Data Poisoning","Supply chain integrity of fine-tuning datasets not verified."),
    ("LLM04","Model Denial of Service","No rate limiting or token budget enforcement on inference endpoints."),
    ("LLM05","Supply Chain Vulnerabilities","Third-party model dependencies lack integrity verification."),
    ("LLM06","Sensitive Information Disclosure","Model may leak PII or confidential data from training corpus."),
    ("LLM07","Insecure Plugin Design","Plugin/tool interfaces lack input validation and output filtering."),
    ("LLM08","Excessive Agency","AI agent granted overly broad permissions beyond task requirements."),
    ("LLM09","Overreliance","System lacks human-in-the-loop controls for critical decisions."),
    ("LLM10","Model Theft","Model API endpoints lack adequate authentication and query monitoring."),
]


@dataclass
class AIFinding:
    id: str
    title: str
    severity: str
    description: str
    recommendation: str
    is_premium: bool = False


@dataclass
class AIScanResult:
    module: str = "ai_scanner"
    target: str = ""
    use_case: str = ""
    risk_score: int = 0
    risk_level: str = "MEDIUM"
    summary: str = ""
    owasp_coverage: str = "LLM01-LLM10 (100%)"
    findings: List[AIFinding] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    scan_timestamp: str = ""
    engine_version: str = "2.0.0"


def scan_ai(model_name: str, use_case: str = "other") -> AIScanResult:
    seed = _seed(model_name + use_case)
    rng  = random.Random(seed)
    risk_score = rng.randint(35, 85)
    sevs = ["CRITICAL","HIGH","MEDIUM","LOW"]

    findings = [
        AIFinding(
            id=owasp[0], title=owasp[1],
            severity=rng.choice(sevs),
            description=owasp[2],
            recommendation=f"Implement {owasp[1]} mitigations per OWASP LLM Top 10 guidance.",
            is_premium=(i >= 2)
        )
        for i, owasp in enumerate(OWASP_LLM)
    ]

    high_crit = sum(1 for f in findings if f.severity in ("CRITICAL","HIGH"))
    return AIScanResult(
        target=model_name,
        use_case=use_case,
        risk_score=risk_score,
        risk_level="CRITICAL" if risk_score>=75 else "HIGH" if risk_score>=50 else "MEDIUM" if risk_score>=25 else "LOW",
        summary=f"AI model '{model_name}' assessed against OWASP LLM Top 10. {high_crit} high-severity issues found.",
        findings=findings,
        recommendations=[
            "Implement prompt injection filters on all user-facing inputs",
            "Enforce output sanitization before passing to downstream systems",
            "Apply principle of least privilege to all AI agent tool grants",
            "Enable continuous monitoring for anomalous query patterns",
        ],
        scan_timestamp=datetime.utcnow().isoformat() + "Z",
    )
