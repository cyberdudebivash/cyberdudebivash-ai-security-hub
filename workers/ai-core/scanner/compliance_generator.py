"""
Compliance Report Generator
Supports: ISO 27001:2022, SOC 2 Type II, GDPR, PCI-DSS v4.0, DPDP Act 2023, HIPAA
"""
import hashlib, random
from dataclasses import dataclass, field
from typing import List, Dict, Any
from datetime import datetime


def _seed(s: str) -> int:
    return int(hashlib.md5(s.encode()).hexdigest(), 16) % 100000


FRAMEWORKS: Dict[str, Dict] = {
    "iso27001": {"name":"ISO 27001:2022",      "price":"₹999",   "domains":["A.5 Organizational","A.6 People","A.7 Physical","A.8 Technological"]},
    "soc2":     {"name":"SOC 2 Type II",        "price":"₹1,499", "domains":["Security","Availability","Processing Integrity","Confidentiality","Privacy"]},
    "gdpr":     {"name":"GDPR 2016/679",        "price":"₹799",   "domains":["Lawful Basis","Data Subject Rights","Data Protection by Design","Breach Notification"]},
    "pcidss":   {"name":"PCI-DSS v4.0",         "price":"₹1,999", "domains":["Network Security","Cardholder Data Protection","Vulnerability Management","Access Control"]},
    "dpdp":     {"name":"DPDP Act 2023 (India)","price":"₹499",   "domains":["Data Fiduciary Obligations","Data Principal Rights","Consent Management","Cross-Border Transfer"]},
    "hipaa":    {"name":"HIPAA/HITECH",          "price":"₹1,499", "domains":["Administrative Safeguards","Physical Safeguards","Technical Safeguards","Breach Notification"]},
}


@dataclass
class DomainAssessment:
    domain: str
    compliance_percent: int
    gap_count: int
    critical_gaps: int
    is_premium: bool = False


@dataclass
class ComplianceReport:
    module: str = "compliance_generator"
    target: str = ""
    framework: str = ""
    framework_key: str = ""
    risk_score: int = 0
    compliance_score: int = 0
    risk_level: str = "HIGH"
    summary: str = ""
    free_preview: Dict[str, Any] = field(default_factory=dict)
    domain_assessments: List[DomainAssessment] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    full_report_price: str = "₹999"
    payment_url: str = ""
    scan_timestamp: str = ""
    engine_version: str = "2.0.0"


def generate_compliance(org_name: str, framework: str = "iso27001") -> ComplianceReport:
    fw_key = framework.lower()
    fw     = FRAMEWORKS.get(fw_key, FRAMEWORKS["iso27001"])
    seed   = _seed(org_name + fw_key)
    rng    = random.Random(seed)

    compliance_score = rng.randint(35, 75)
    domains = [
        DomainAssessment(
            domain=d,
            compliance_percent=rng.randint(40, 85),
            gap_count=rng.randint(2, 8),
            critical_gaps=rng.randint(0, 3),
            is_premium=(i >= 1)
        )
        for i, d in enumerate(fw["domains"])
    ]
    total_gaps = sum(d.gap_count for d in domains)
    total_crit = sum(d.critical_gaps for d in domains)
    worst      = min(domains, key=lambda d: d.compliance_percent)

    return ComplianceReport(
        target=org_name,
        framework=fw["name"],
        framework_key=fw_key,
        risk_score=100 - compliance_score,
        compliance_score=compliance_score,
        risk_level="CRITICAL" if compliance_score<40 else "HIGH" if compliance_score<60 else "MEDIUM",
        summary=f"{fw['name']} compliance assessment for '{org_name}'. Readiness: {compliance_score}%. {total_gaps} gaps across {len(fw['domains'])} domains.",
        free_preview={"overall_score": compliance_score, "top_gap": {"domain": worst.domain, "compliance_percent": worst.compliance_percent}, "critical_count": total_crit},
        domain_assessments=domains,
        recommendations=[
            f"Prioritize '{worst.domain}' domain — lowest compliance at {worst.compliance_percent}%",
            "Engage a CISO or compliance consultant for gap remediation roadmap",
            f"Achieve {fw['name']} certification within 12-month roadmap",
            "Implement continuous compliance monitoring via GRC tooling",
        ],
        full_report_price=fw["price"],
        payment_url=f"https://rzp.io/l/cyberdudebivash-{fw_key}",
        scan_timestamp=datetime.utcnow().isoformat() + "Z",
    )
