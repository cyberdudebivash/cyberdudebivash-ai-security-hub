"""
CYBERDUDEBIVASH AI Security Hub — Scanner Adapter
Clean validated interface for all 5 scanner modules.
Standard response format for all modules.
"""
from typing import Dict, Any
from dataclasses import asdict

from .domain_scanner      import scan_domain
from .ai_scanner          import scan_ai
from .redteam_engine      import run_redteam
from .identity_scanner    import scan_identity
from .compliance_generator import generate_compliance

CONTACT = {
    "company":   "CyberDudeBivash Pvt. Ltd.",
    "website":   "https://cyberdudebivash.in",
    "email":     "cyberdudebivash@gmail.com",
    "enterprise":"bivashnayak.ai007@gmail.com",
    "phone":     "+918179881447",
}
MODULE_PRICES = {
    "domain": "₹199", "ai": "₹499",
    "redteam": "₹999", "identity": "₹799", "compliance": "₹499–₹1,999",
}


def _monetize(result_dict: dict, module: str) -> Dict[str, Any]:
    findings = result_dict.get("findings", [])
    free     = [f for f in findings if not f.get("is_premium", False)][:3]
    premium  = [f for f in findings if f.get("is_premium", False)]
    return {
        **result_dict,
        "findings": free,
        "premium_findings_count": len(premium),
        "is_premium_locked": True,
        "unlock_required": True,
        "unlock_price": MODULE_PRICES.get(module, "₹499"),
        "payment_url": f"https://rzp.io/l/cyberdudebivash-{module}",
        "upgrade_cta": f"Unlock {len(premium)} additional findings + full report for {MODULE_PRICES.get(module,'₹499')}",
        "contact": CONTACT,
    }


class ScannerAdapter:
    """Single entry point for all scan modules."""

    def scan_domain(self, domain: str) -> Dict[str, Any]:
        if not domain or len(domain.strip()) < 4:
            return {"status": "error", "message": "domain must be at least 4 characters"}
        result = asdict(scan_domain(domain.strip().lower()))
        return _monetize(result, "domain")

    def scan_ai(self, model_name: str, use_case: str = "other") -> Dict[str, Any]:
        if not model_name or len(model_name.strip()) < 2:
            return {"status": "error", "message": "model_name is required"}
        result = asdict(scan_ai(model_name.strip(), use_case or "other"))
        return _monetize(result, "ai")

    def scan_redteam(self, target_org: str, scope: str = "external") -> Dict[str, Any]:
        if not target_org or len(target_org.strip()) < 2:
            return {"status": "error", "message": "target_org is required"}
        result = asdict(run_redteam(target_org.strip(), scope or "external"))
        return _monetize(result, "redteam")

    def scan_identity(self, org_name: str, identity_provider: str = "other") -> Dict[str, Any]:
        if not org_name or len(org_name.strip()) < 2:
            return {"status": "error", "message": "org_name is required"}
        result = asdict(scan_identity(org_name.strip(), identity_provider or "other"))
        return _monetize(result, "identity")

    def generate_compliance(self, org_name: str, framework: str = "iso27001") -> Dict[str, Any]:
        if not org_name or len(org_name.strip()) < 2:
            return {"status": "error", "message": "org_name is required"}
        valid_fw = {"iso27001","soc2","gdpr","pcidss","dpdp","hipaa"}
        fw = (framework or "iso27001").lower()
        if fw not in valid_fw:
            fw = "iso27001"
        result = asdict(generate_compliance(org_name.strip(), fw))
        return _monetize(result, "compliance")
