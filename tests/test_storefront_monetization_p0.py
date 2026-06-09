"""
CYBERDUDEBIVASH® SENTINEL APEX — Production Governance & Validation Test Suite
Classification: Invariant Enforcement Test Rig
Version: v30.0.2-Testing-Parity

Run: pytest tests/test_storefront_monetization_p0.py -v
Expected: All PASS, exit code 0
"""
from __future__ import annotations

import json
import os
import sys
import hmac
import hashlib
import time

import pytest

# ── Path setup ───────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─────────────────────────────────────────────────────────────────────────────
# GATE 0: SOURCE CODE SYNTAX COMPILATION INTEGRITY
# ─────────────────────────────────────────────────────────────────────────────

def test_source_code_syntax_compilation_integrity():
    """Validates all modified pipeline scripts compile cleanly under Python 3.12."""
    import py_compile

    target_scripts = [
        "scripts/severity_recalibration_engine.py",
        "scripts/pipeline_severity_interceptor.py",
        "scripts/multi_rail_payment_processor.py",
    ]

    for script_path in target_scripts:
        if not os.path.exists(script_path):
            pytest.skip(f"Script not present in this env: {script_path}")
        try:
            result = py_compile.compile(script_path, doraise=True)
            assert result is not None, f"Compilation returned None for {script_path}"
        except py_compile.PyCompileError as e:
            pytest.fail(f"[GATE-0-FAILURE] Syntax error in {script_path}: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# GATE 1: P0 SEVERITY FLOOR — CRITICAL INVARIANT
# ─────────────────────────────────────────────────────────────────────────────

from scripts.severity_recalibration_engine import (  # noqa: E402
    enforce_sentinel_apex_severity_floors,
    process_vulnerability_batch,
)


@pytest.mark.parametrize("cvss,exploit,kev,cls", [
    (9.8, False, False, "rce"),
    (9.0, False, False, "generic"),
    (7.5, True,  False, "generic"),
    (7.5, False, True,  "generic"),
    (6.0, False, False, "auth_bypass"),
    (9.8, True,  True,  "arbitrary_file_upload"),
])
def test_p0_critical_floor_enforced(cvss, exploit, kev, cls):
    """No CRITICAL-tier record may exit calibration with a degraded severity."""
    record = {
        "id": f"CVE-TEST-{cvss}-{cls}",
        "cvss_score": cvss,
        "active_exploitation": exploit,
        "cisa_kev": kev,
        "threat_class": cls,
        "severity": "LOW",  # start degraded — gate must fix
    }
    result = enforce_sentinel_apex_severity_floors(record)
    assert result["Severity"] == "CRITICAL", (
        f"P0-GATE FAIL: CVSS={cvss} exploit={exploit} kev={kev} cls={cls} "
        f"got Severity={result['Severity']!r}"
    )
    assert result["Risk Score"] >= 9.0, f"P0-GATE FAIL: Risk Score {result['Risk Score']} < 9.0"
    assert result["ioc_paywall"]["locked"] is True, "P0-GATE FAIL: IOC paywall not locked for CRITICAL"


def test_p1_high_floor_enforced():
    """CVSS 8.x records marked LOW must be elevated to HIGH."""
    record = {"id": "CVE-TEST-H1", "cvss_score": 8.5, "severity": "LOW"}
    result = enforce_sentinel_apex_severity_floors(record)
    assert result["Severity"] == "HIGH", f"P1-GATE FAIL: got {result['Severity']}"
    assert result["Risk Score"] >= 7.5


def test_p2_medium_floor_enforced():
    """CVSS 7.x records marked LOW must be elevated to MEDIUM."""
    record = {"id": "CVE-TEST-M1", "cvss_score": 7.3, "severity": "LOW"}
    result = enforce_sentinel_apex_severity_floors(record)
    assert result["Severity"] == "MEDIUM", f"P2-GATE FAIL: got {result['Severity']}"
    assert result["Risk Score"] >= 5.0


def test_valid_high_not_downgraded():
    """A correctly HIGH-labelled record must not be touched."""
    record = {"id": "CVE-TEST-H2", "cvss_score": 8.2, "severity": "HIGH"}
    result = enforce_sentinel_apex_severity_floors(record)
    assert result["Severity"] in {"HIGH", "CRITICAL"}


def test_active_exploitation_text_detection():
    """Regex should detect 'actively exploiting' in description and trigger P0 gate."""
    record = {
        "id": "CVE-TEXT-EXPLOIT",
        "cvss_score": 7.0,
        "severity": "MEDIUM",
        "description": "Threat actors are actively exploiting this vulnerability in the wild.",
    }
    result = enforce_sentinel_apex_severity_floors(record)
    assert result["Severity"] == "CRITICAL", "Text-based exploitation detection failed"


def test_batch_processing_no_drop():
    """Batch processor must return same count as input — no data loss."""
    records = [
        {"id": "CVE-B1", "cvss_score": 9.8, "severity": "LOW"},
        {"id": "CVE-B2", "cvss_score": 8.5, "severity": "LOW"},
        {"id": "CVE-B3", "cvss_score": 5.0, "severity": "MEDIUM"},
    ]
    results = process_vulnerability_batch(records)
    assert len(results) == 3, "Batch dropped records"
    assert results[0]["Severity"] == "CRITICAL"
    assert results[1]["Severity"] == "HIGH"


# ─────────────────────────────────────────────────────────────────────────────
# GATE 2: PAYWALL SERIALIZATION — PREMIUM FIELD LEAKAGE
# ─────────────────────────────────────────────────────────────────────────────

PREMIUM_FIELDS = {
    "sigma_rule", "sigma", "kql_query", "kql",
    "suricata_rule", "suricata", "yara_rule", "yara",
    "soc_playbook", "full_ioc_array",
}


def _apply_scrub(record: dict) -> dict:
    """Mirror of the Worker's scrubPremiumFields logic in Python."""
    scrubbed = {}
    locked = False
    for k, v in record.items():
        if k in PREMIUM_FIELDS:
            locked = True
        else:
            scrubbed[k] = v
    if locked:
        scrubbed["_paywall"] = {"status": "LOCKED"}
    return scrubbed


def test_premium_fields_scrubbed_for_free_tier():
    """All premium keys must vanish from free-tier serialization output."""
    record = {
        "id": "CVE-PAYWALL-TEST",
        "title": "Test Vuln",
        "cvss_score": 9.8,
        "sigma_rule": "title: test\ndetection: ...",
        "kql_query": "DeviceNetworkEvents | ...",
        "yara_rule": "rule test { ... }",
        "soc_playbook": "1. Isolate host. 2. ...",
        "full_ioc_array": ["1.2.3.4", "evil.com"],
    }
    scrubbed = _apply_scrub(record)
    for field in PREMIUM_FIELDS:
        assert field not in scrubbed, f"PAYWALL LEAK: '{field}' present in free-tier output"
    assert "_paywall" in scrubbed, "Paywall notice not injected"


def test_non_premium_fields_preserved():
    """Non-premium fields must survive scrubbing intact."""
    record = {
        "id": "CVE-PRESERVE-TEST",
        "title": "Critical RCE",
        "cvss_score": 9.8,
        "sigma_rule": "secret...",
    }
    scrubbed = _apply_scrub(record)
    assert scrubbed["id"] == "CVE-PRESERVE-TEST"
    assert scrubbed["title"] == "Critical RCE"
    assert scrubbed["cvss_score"] == 9.8


# ─────────────────────────────────────────────────────────────────────────────
# GATE 3: MULTI-RAIL PAYMENT PROCESSOR
# ─────────────────────────────────────────────────────────────────────────────

from scripts.multi_rail_payment_processor import (  # noqa: E402
    MultiRailPaymentProcessor,
    generate_idempotent_txn_id,
    PLAN_CATALOG_INR,
    PLAN_CATALOG_USD,
    CRYPTO_WALLETS,
)


@pytest.fixture()
def processor():
    return MultiRailPaymentProcessor(razorpay_webhook_secret="test_webhook_secret_key")


def test_upi_payload_structure(processor):
    """UPI payload must contain a valid UPI deep-link string."""
    payload = processor.generate_upi_payment_payload("pro", "tenant-abc")
    assert payload["payment_rail"] == "UPI"
    assert payload["currency"] == "INR"
    assert payload["amount"] == "1499.00"
    link = payload["upi_deep_link"]
    assert link.startswith("upi://pay?")
    assert "bivash@cyberdudebivash.com" in link
    assert "SENTINEL_APEX_PRO_SUBSCRIPTION" in link


def test_upi_idempotency():
    """Same tenant + plan within 30-min window must return same txn_id."""
    tid1 = generate_idempotent_txn_id("tenant-xyz", "pro")
    tid2 = generate_idempotent_txn_id("tenant-xyz", "pro")
    assert tid1 == tid2, "Idempotency broken — different txn IDs in same window"


def test_invalid_plan_raises(processor):
    with pytest.raises(ValueError, match="Unknown plan"):
        processor.generate_upi_payment_payload("ultra", "tenant-abc")


def test_bank_wire_tracking_reference(processor):
    wire = processor.fetch_corporate_wire_instructions("TENANT-001")
    assert wire["payment_rail"] == "BANK_WIRE_NEFT_RTGS"
    assert "CDB-SYS-TENANT-001" in wire["tracking_reference"]
    assert wire["gstin_registry"] == "21ARKPN8270G1ZP"


@pytest.mark.parametrize("chain", ["ETH", "BSC", "TRON_TRC20"])
def test_crypto_node_initialization(processor, chain):
    result = processor.initialize_web3_cryptographic_node("pro", chain)
    assert result["payment_rail"] == "WEB3_CRYPTO"
    assert result["chain_context"] == chain
    assert result["destination_wallet"] == CRYPTO_WALLETS[chain]
    assert isinstance(result["amount_usd"], int)
    assert result["amount_usd"] > 0


def test_unsupported_chain_raises(processor):
    with pytest.raises(ValueError, match="unsupported"):
        processor.initialize_web3_cryptographic_node("pro", "SOLANA")


def test_razorpay_webhook_valid_signature(processor):
    """Authentic webhook signature must validate and trigger UPGRADE_TIER action."""
    secret = "test_webhook_secret_key"
    notes  = {"tenant_id": "t-001", "plan": "pro"}
    body   = json.dumps({
        "event": "payment.captured",
        "payload": {"payment": {"entity": {"amount": 149900, "notes": notes}}}
    }).encode()
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    result = processor.process_razorpay_webhook(body, sig)
    assert result["ok"] is True
    assert result["action"] == "UPGRADE_TIER"
    assert result["tenant_id"] == "t-001"
    assert result["plan"] == "pro"


def test_razorpay_webhook_invalid_signature(processor):
    """Tampered signature must be rejected with HTTP 401."""
    body = b'{"event":"payment.captured"}'
    result = processor.process_razorpay_webhook(body, "badsig000")
    assert result["ok"] is False
    assert result["http_status"] == 401


def test_checkout_initializer_all_rails(processor):
    result = processor.initialize_checkout(
        plan="enterprise",
        tenant_id="t-ent-001",
        rails=["upi", "bank", "crypto"],
        country_code="IN",
        crypto_chain="ETH",
    )
    assert result["ok"] is True
    assert result["currency"] == "INR"
    assert result["amount"] == PLAN_CATALOG_INR["enterprise"]
    assert "upi" in result
    assert "bank_wire" in result
    assert "crypto" in result


def test_checkout_usd_hides_upi(processor):
    """Non-IN country must not include UPI rail (UPI is INR-only)."""
    result = processor.initialize_checkout(
        plan="pro",
        tenant_id="t-us-001",
        rails=["upi", "bank", "crypto"],
        country_code="US",
    )
    assert result["currency"] == "USD"
    assert "upi" not in result, "UPI must not appear for non-INR transactions"


# ─────────────────────────────────────────────────────────────────────────────
# GATE 4: CRITICAL CVE PIPELINE — END-TO-END FLOW
# ─────────────────────────────────────────────────────────────────────────────

def test_cve_2024_58348_critical_locked():
    """CVE-2024-58348 (CVSS 9.8 RCE) must be CRITICAL + IOC locked."""
    record = {
        "id": "CVE-2024-58348",
        "title": "Unauthenticated Remote Code Execution via Deserialization",
        "cvss_score": 9.8,
        "threat_class": "rce",
        "severity": "LOW",
        "active_exploitation": False,
        "cisa_kev": False,
        "ioc_paywall": {"locked": False},
    }
    result = enforce_sentinel_apex_severity_floors(record)
    assert result["Severity"] == "CRITICAL"
    assert result["ioc_paywall"]["locked"] is True


def test_cve_2024_58349_critical_locked():
    """CVE-2024-58349 (CVSS 9.8 arbitrary upload) must be CRITICAL + IOC locked."""
    record = {
        "id": "CVE-2024-58349",
        "title": "Arbitrary File Upload to Remote Code Execution",
        "cvss_score": 9.8,
        "threat_class": "arbitrary_file_upload",
        "severity": "LOW",
        "ioc_paywall": {"locked": False},
    }
    result = enforce_sentinel_apex_severity_floors(record)
    assert result["Severity"] == "CRITICAL"
    assert result["ioc_paywall"]["locked"] is True


# ─────────────────────────────────────────────────────────────────────────────
# SUITE SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v", "--tb=short"]))
