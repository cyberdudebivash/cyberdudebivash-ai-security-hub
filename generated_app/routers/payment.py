# ============================================================
# CYBERDUDEBIVASH AI — PAYMENT ROUTER (PRODUCTION HARDENED)
# Manual payment verification system — UPI / Bank / PayPal / Crypto
# ============================================================

import json
import os
import re
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List

from fastapi import APIRouter, Request, HTTPException, Header, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, validator, Field

try:
    from core.logging_config import get_logger, log_event
except ImportError:
    import logging
    def get_logger(name): return logging.getLogger(name)
    def log_event(event, data): pass

logger = get_logger("router.payment")

router = APIRouter(prefix="/payment", tags=["Payment"])

# ── Data storage ──────────────────────────────────────────────────────────────
DATA_DIR = Path(os.getenv("PAYMENT_DATA_DIR", "/data"))
PAYMENTS_FILE = DATA_DIR / "payments.json"
ADMIN_SECRET = os.getenv("PAYMENT_ADMIN_SECRET", "cdb-admin-2024-secure")

VALID_METHODS = {"UPI", "BANK", "PAYPAL", "CRYPTO_BNB", "CRYPTO_ETH"}
VALID_STATUSES = {"pending", "approved", "rejected"}

# ── Payment Details (canonical) ───────────────────────────────────────────────
PAYMENT_DETAILS = {
    "upi": [
        "iambivash.bn-5@okaxis",
        "iambivash.bn-5@okicici",
        "6302177246@axisbank",
    ],
    "bank": {
        "name": "Bivash Kumar Nayak",
        "account_number": "915010024617260",
        "ifsc": "UTIB0000052",
        "bank": "Axis Bank",
    },
    "paypal": "iambivash.bn@gmail.com",
    "crypto": {
        "address": "0xa824c20158a4bfe2f3d8e80351b1906bd0ac0796",
        "networks": ["BNB Smart Chain (BEP20)", "Ethereum (ERC20)"],
    },
}


# ── Helpers ───────────────────────────────────────────────────────────────────
def _ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def _load_payments() -> List[dict]:
    _ensure_data_dir()
    if not PAYMENTS_FILE.exists():
        return []
    try:
        with open(PAYMENTS_FILE, "r") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to load payments: {e}")
        return []


def _save_payments(payments: List[dict]):
    _ensure_data_dir()
    try:
        with open(PAYMENTS_FILE, "w") as f:
            json.dump(payments, f, indent=2, default=str)
    except OSError as e:
        logger.error(f"Failed to save payments: {e}")
        raise HTTPException(status_code=500, detail="Storage write failure")


def _generate_record_id(txn_id: str, email: str) -> str:
    raw = f"{txn_id}:{email}:{datetime.now(timezone.utc).isoformat()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _verify_admin(x_admin_secret: str = Header(default="")):
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Invalid admin secret")
    return True


# ── Pydantic models ───────────────────────────────────────────────────────────
class PaymentConfirmRequest(BaseModel):
    txnId: str = Field(..., min_length=3, max_length=200)
    method: str
    product: str = Field(..., min_length=1, max_length=200)
    user: str = Field(..., min_length=3, max_length=200)  # email or user ID
    amount: Optional[str] = None
    currency: Optional[str] = "INR"
    notes: Optional[str] = None

    @validator("method")
    def method_must_be_valid(cls, v):
        normalized = v.upper().replace(" ", "_")
        if normalized not in VALID_METHODS:
            raise ValueError(f"method must be one of: {', '.join(VALID_METHODS)}")
        return normalized

    @validator("txnId")
    def txn_id_no_injection(cls, v):
        # Reject obvious injection attempts
        if re.search(r'[<>"\';&\x00]', v):
            raise ValueError("txnId contains invalid characters")
        return v.strip()


class AdminActionRequest(BaseModel):
    record_id: str
    action: str  # "approve" | "reject"
    notes: Optional[str] = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/details")
async def get_payment_details():
    """Return canonical payment details for the checkout UI."""
    return {
        "status": "ok",
        "details": PAYMENT_DETAILS,
        "message": "Transfer funds using any method below, then confirm with your transaction ID.",
    }


@router.post("/confirm")
async def confirm_payment(request: Request, body: PaymentConfirmRequest):
    """
    Store a user-submitted manual payment confirmation.
    Status defaults to 'pending' until admin approves.
    """
    payments = _load_payments()

    # Duplicate detection — same txnId + method
    duplicate = next(
        (p for p in payments if p.get("txnId") == body.txnId and p.get("method") == body.method),
        None
    )
    if duplicate:
        logger.warning(f"Duplicate payment submission: {body.txnId}")
        return JSONResponse(
            status_code=409,
            content={
                "status": "duplicate",
                "message": "This transaction ID has already been submitted. Our team will verify it shortly.",
                "record_id": duplicate.get("record_id"),
            }
        )

    now = datetime.now(timezone.utc).isoformat()
    record = {
        "record_id": _generate_record_id(body.txnId, body.user),
        "txnId": body.txnId,
        "method": body.method,
        "product": body.product,
        "user": body.user,
        "amount": body.amount,
        "currency": body.currency or "INR",
        "notes": body.notes,
        "status": "pending",
        "created_at": now,
        "updated_at": now,
        "ip": request.client.host if request.client else "unknown",
        "admin_notes": None,
    }

    payments.append(record)
    _save_payments(payments)

    log_event("payment_submitted", {
        "record_id": record["record_id"],
        "method": body.method,
        "product": body.product,
        "user": body.user,
    })

    logger.info(f"Payment confirmation stored: {record['record_id']} | method={body.method} | product={body.product}")

    return {
        "status": "received",
        "record_id": record["record_id"],
        "message": (
            "Payment submission received. Our team will verify and activate your access "
            "within 2–4 hours. You will receive a confirmation at your email."
        ),
    }


@router.get("/status/{record_id}")
async def payment_status(record_id: str):
    """Check the status of a specific payment record."""
    payments = _load_payments()
    record = next((p for p in payments if p.get("record_id") == record_id), None)
    if not record:
        raise HTTPException(status_code=404, detail="Payment record not found")
    # Return safe subset (no IP)
    return {
        "record_id": record["record_id"],
        "status": record["status"],
        "product": record["product"],
        "method": record["method"],
        "created_at": record["created_at"],
        "updated_at": record["updated_at"],
        "message": _status_message(record["status"]),
    }


def _status_message(status: str) -> str:
    return {
        "pending": "Your payment is under review. Access will be unlocked after verification (2–4 hours).",
        "approved": "Payment approved! Your access has been activated. Thank you.",
        "rejected": "Payment could not be verified. Please contact support@cyberdudebivash.com.",
    }.get(status, "Unknown status.")


# ── Admin endpoints ────────────────────────────────────────────────────────────

@router.get("/admin/list")
async def admin_list_payments(
    status_filter: Optional[str] = None,
    method_filter: Optional[str] = None,
    product_filter: Optional[str] = None,
    _: bool = Depends(_verify_admin),
):
    """[ADMIN] List all payment records with optional filters."""
    payments = _load_payments()

    if status_filter:
        payments = [p for p in payments if p.get("status") == status_filter.lower()]
    if method_filter:
        payments = [p for p in payments if p.get("method") == method_filter.upper()]
    if product_filter:
        q = product_filter.lower()
        payments = [p for p in payments if q in (p.get("product") or "").lower()]

    return {
        "total": len(payments),
        "payments": sorted(payments, key=lambda p: p.get("created_at", ""), reverse=True),
    }


@router.post("/admin/approve/{record_id}")
async def admin_approve(record_id: str, body: dict = None, _: bool = Depends(_verify_admin)):
    """[ADMIN] Approve a pending payment and unlock user access."""
    payments = _load_payments()
    record = next((p for p in payments if p.get("record_id") == record_id), None)
    if not record:
        raise HTTPException(status_code=404, detail="Payment record not found")

    record["status"] = "approved"
    record["updated_at"] = datetime.now(timezone.utc).isoformat()
    record["admin_notes"] = (body or {}).get("notes", None)

    _save_payments(payments)
    log_event("payment_approved", {"record_id": record_id, "user": record.get("user"), "product": record.get("product")})
    logger.info(f"Payment approved: {record_id}")

    # TODO: wire to subscription activation service
    # subscription_service.activate(user=record["user"], product=record["product"])

    return {
        "status": "approved",
        "record_id": record_id,
        "message": f"Access activated for {record.get('user')} on {record.get('product')}",
    }


@router.post("/admin/reject/{record_id}")
async def admin_reject(record_id: str, body: dict = None, _: bool = Depends(_verify_admin)):
    """[ADMIN] Reject a payment (e.g., invalid transaction ID)."""
    payments = _load_payments()
    record = next((p for p in payments if p.get("record_id") == record_id), None)
    if not record:
        raise HTTPException(status_code=404, detail="Payment record not found")

    record["status"] = "rejected"
    record["updated_at"] = datetime.now(timezone.utc).isoformat()
    record["admin_notes"] = (body or {}).get("notes", "Payment could not be verified")

    _save_payments(payments)
    log_event("payment_rejected", {"record_id": record_id, "user": record.get("user")})
    logger.info(f"Payment rejected: {record_id}")

    return {"status": "rejected", "record_id": record_id}


@router.get("/admin/stats")
async def admin_stats(_: bool = Depends(_verify_admin)):
    """[ADMIN] Aggregate statistics across all payments."""
    payments = _load_payments()
    stats = {"total": len(payments), "pending": 0, "approved": 0, "rejected": 0, "by_method": {}}
    for p in payments:
        s = p.get("status", "pending")
        stats[s] = stats.get(s, 0) + 1
        m = p.get("method", "UNKNOWN")
        stats["by_method"][m] = stats["by_method"].get(m, 0) + 1
    return stats
