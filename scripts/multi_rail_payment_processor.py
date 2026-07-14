"""
CYBERDUDEBIVASH® SENTINEL APEX — Multi-Rail Alternative Checkout Payments Engine
Classification: Core Financial Transaction Router
Version: v22.0.0-Stable-Enterprise / Python 3.12
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from typing import Any, Literal

# ─────────────────────────────────────────────────────────────────────────────
# PLAN CATALOGUE
# ─────────────────────────────────────────────────────────────────────────────

PLAN_CATALOG_INR: dict[str, int] = {
    "starter":    999,
    "pro":        1499,
    "enterprise": 4999,
}

PLAN_CATALOG_USD: dict[str, int] = {
    "starter":    6,
    "pro":        19,
    "enterprise": 59,
}

MERCHANT_UPI_ID    = "bivash@cyberdudebivash.com"
MERCHANT_NAME_ENC  = "CYBERDUDEBIVASH%20PVT%20LTD"
CORPORATE_NAME     = "CYBERDUDEBIVASH PRIVATE LIMITED"
GSTIN              = "21ARKPN8270G1ZP"
CIN                = "U74999OR2024PTC049281"

CRYPTO_WALLETS: dict[str, str] = {
    "ETH":        "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    "BSC":        "0x3fC91A3afd3b123456789bde454e4438f44e5529",
    "TRON_TRC20": "TYG8270G1ZPCorporateEnclaveHubLineUSDT",
}

SUPPORTED_CRYPTO_CHAINS: frozenset[str] = frozenset(CRYPTO_WALLETS.keys())


# ─────────────────────────────────────────────────────────────────────────────
# IDEMPOTENCY ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def generate_idempotent_txn_id(tenant_id: str, plan: str) -> str:
    """
    Deterministic UUIDv5-style transaction ID.
    Bucketed to 30-minute windows to prevent duplicate billing.
    """
    bucket_ts = int(time.time()) // 1800  # 30-min window
    raw = f"{tenant_id}|{plan}|{bucket_ts}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return f"CDB-{digest[:8].upper()}-{digest[8:16].upper()}"


# ─────────────────────────────────────────────────────────────────────────────
# MULTI-RAIL PAYMENT PROCESSOR
# ─────────────────────────────────────────────────────────────────────────────

class MultiRailPaymentProcessor:
    """
    Production-grade multi-rail payment adapter.
    Handles UPI deep-linking, corporate bank wire (NEFT/RTGS/IMPS),
    Razorpay webhook validation, and Web3 multi-chain crypto checkout.
    """

    def __init__(self, razorpay_webhook_secret: str = "") -> None:
        self.razorpay_webhook_secret = razorpay_webhook_secret

    # ── UPI ──────────────────────────────────────────────────────────────────

    def generate_upi_payment_payload(
        self,
        plan: str,
        tenant_id: str,
    ) -> dict[str, Any]:
        """
        Synthesizes a standards-compliant UPI deep-linking payload.
        """
        plan = plan.lower()
        price = PLAN_CATALOG_INR.get(plan)
        if price is None:
            raise ValueError(f"Unknown plan: '{plan}'. Valid: {list(PLAN_CATALOG_INR)}")

        txn_id = generate_idempotent_txn_id(tenant_id, plan)

        upi_string = (
            f"upi://pay?pa={MERCHANT_UPI_ID}"
            f"&pn={MERCHANT_NAME_ENC}"
            f"&tr={txn_id}"
            f"&am={price}.00"
            f"&cu=INR"
            f"&tn=SENTINEL_APEX_{plan.upper()}_SUBSCRIPTION"
        )

        return {
            "payment_rail": "UPI",
            "plan": plan,
            "currency": "INR",
            "amount": f"{price}.00",
            "txn_id": txn_id,
            "upi_deep_link": upi_string,
            "qr_endpoint": f"/api/v1/checkout/qr?txn={txn_id}&plan={plan}",
        }

    # ── BANK WIRE ─────────────────────────────────────────────────────────────

    def fetch_corporate_wire_instructions(self, tenant_id: str) -> dict[str, str]:
        """
        Returns structured NEFT/RTGS/IMPS wire instructions for enterprise buyers.
        """
        ref = f"CDB-SYS-{tenant_id.upper()}-{int(time.time())}"
        return {
            "payment_rail": "BANK_WIRE_NEFT_RTGS",
            "beneficiary_corporate_name": CORPORATE_NAME,
            "corporate_identification_number": CIN,
            "gstin_registry": GSTIN,
            "account_note": f"Verified corporate clearing account — GSTIN: {GSTIN}",
            "ifsc_hub": "Bhubaneswar Core Corporate Enclave Hub",
            "tracking_reference": ref,
            "instruction": (
                f"Transfer the exact plan amount to the verified account. "
                f"Include reference code '{ref}' in the payment narration/remarks field "
                f"for automated verification and instant tier activation."
            ),
        }

    # ── WEB3 / CRYPTO ─────────────────────────────────────────────────────────

    def initialize_web3_cryptographic_node(
        self,
        plan: str,
        target_chain: str,
    ) -> dict[str, Any]:
        """
        Provisions a Web3 payment monitoring context for layer-1 networks.
        """
        plan = plan.lower()
        target_chain = target_chain.upper()

        if target_chain not in SUPPORTED_CRYPTO_CHAINS:
            raise ValueError(
                f"Chain '{target_chain}' unsupported. Valid: {sorted(SUPPORTED_CRYPTO_CHAINS)}"
            )

        usd_amount = PLAN_CATALOG_USD.get(plan, 0)
        if usd_amount == 0:
            raise ValueError(f"Unknown plan: '{plan}'")

        stable_asset = "USDT" if target_chain == "TRON_TRC20" else "NATIVE_TOKEN"

        return {
            "payment_rail": "WEB3_CRYPTO",
            "chain_context": target_chain,
            "stable_asset": stable_asset,
            "amount_usd": usd_amount,
            "destination_wallet": CRYPTO_WALLETS[target_chain],
            "verify_endpoint": f"/api/v1/checkout/verify-crypto?chain={target_chain}&plan={plan}",
            "memo_instruction": f"Include tenant ID in memo/note field for account matching.",
        }

    # ── RAZORPAY WEBHOOK VALIDATOR ─────────────────────────────────────────────

    def validate_razorpay_webhook(
        self,
        body_raw: bytes,
        signature_header: str,
    ) -> bool:
        """
        HMAC-SHA256 webhook signature validation per Razorpay specification.
        Returns True only if signature is authentic.
        """
        if not self.razorpay_webhook_secret:
            raise RuntimeError("RAZORPAY_WEBHOOK_SECRET not configured")

        expected = hmac.new(
            key=self.razorpay_webhook_secret.encode("utf-8"),
            msg=body_raw,
            digestmod=hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(expected, signature_header)

    def process_razorpay_webhook(
        self,
        body_raw: bytes,
        signature_header: str,
    ) -> dict[str, Any]:
        """
        Full webhook processor: validates signature, extracts tenant/plan,
        returns upgrade instruction dict.
        """
        if not self.validate_razorpay_webhook(body_raw, signature_header):
            return {"ok": False, "error": "Invalid webhook signature", "http_status": 401}

        try:
            payload = json.loads(body_raw)
        except json.JSONDecodeError:
            return {"ok": False, "error": "Malformed JSON payload", "http_status": 400}

        event = payload.get("event", "")

        if event == "payment.captured":
            entity = (
                payload.get("payload", {})
                       .get("payment", {})
                       .get("entity", {})
            )
            notes     = entity.get("notes", {})
            tenant_id = notes.get("tenant_id", "")
            plan      = notes.get("plan", "pro")
            amount    = entity.get("amount", 0) / 100  # paise → rupees

            return {
                "ok": True,
                "event": event,
                "action": "UPGRADE_TIER",
                "tenant_id": tenant_id,
                "plan": plan,
                "amount_inr": amount,
                "activated_at": int(time.time()),
                "http_status": 200,
            }

        # Other events — acknowledge without action
        return {"ok": True, "event": event, "action": "NOOP", "http_status": 200}

    # ── CHECKOUT INITIALIZER (All Rails) ──────────────────────────────────────

    def initialize_checkout(
        self,
        plan: str,
        tenant_id: str,
        rails: list[str] | None = None,
        country_code: str = "IN",
        crypto_chain: str = "ETH",
    ) -> dict[str, Any]:
        """
        Master checkout initializer — returns all requested payment rail payloads.
        """
        plan      = plan.lower()
        rails     = [r.lower() for r in (rails or ["upi", "bank", "crypto"])]
        currency  = "INR" if country_code == "IN" else "USD"
        amount    = PLAN_CATALOG_INR.get(plan, 0) if currency == "INR" else PLAN_CATALOG_USD.get(plan, 0)
        txn_id    = generate_idempotent_txn_id(tenant_id, plan)

        result: dict[str, Any] = {
            "ok": True,
            "txn_id": txn_id,
            "plan": plan,
            "currency": currency,
            "amount": amount,
        }

        if "upi" in rails and currency == "INR":
            result["upi"] = self.generate_upi_payment_payload(plan, tenant_id)

        if "bank" in rails:
            result["bank_wire"] = self.fetch_corporate_wire_instructions(tenant_id)

        if "crypto" in rails:
            result["crypto"] = self.initialize_web3_cryptographic_node(plan, crypto_chain)

        return result
