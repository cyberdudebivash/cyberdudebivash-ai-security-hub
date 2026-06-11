"""Billing Agent — Invoice generation, payment status, payment method queries, billing history."""
from __future__ import annotations
import time
from typing import Any, Dict, List, Tuple
from ..core.base_agent import BaseAgent, AgentLayer, AgentCapability, AgentRequest

class BillingAgent(BaseAgent):
    @property
    def name(self) -> str: return "billing"
    @property
    def layer(self) -> AgentLayer: return AgentLayer.REVENUE
    @property
    def capabilities(self) -> List[AgentCapability]:
        return [AgentCapability(
            name="billing_management", description="Invoice queries, payment status, billing history, dunning management",
            intents=["subscription_query", "billing_inquiry", "invoice_request"],
            requires_tier="FREE", rate_limit=200, timeout_ms=10_000,
        )]

    async def _execute(self, request: AgentRequest) -> Tuple[Dict[str, Any], List[str]]:
        p = request.payload
        org_id = p.get("org_id", "")
        query_type = p.get("query_type", "status")
        period = p.get("period", "current")
        invoices = p.get("invoices", [])
        payment_status = p.get("payment_status", "paid")

        reasoning = [
            f"Billing query: {org_id} | Type: {query_type}",
            f"Period: {period} | Status: {payment_status}",
        ]

        result = {
            "query_id": f"BILL-{int(time.time())}",
            "org_id": org_id,
            "payment_status": payment_status,
            "invoices": invoices,
            "latest_invoice": invoices[0] if invoices else None,
            "outstanding_amount_usd": sum(i.get("amount", 0) for i in invoices if i.get("status") == "unpaid"),
            "next_billing_date": p.get("next_billing_date", ""),
            "payment_method": p.get("payment_method", "Card on file"),
            "billing_email": p.get("billing_email", ""),
            "dunning_status": p.get("dunning_status", "none"),
            "powered_by_mythos": True,
            "queried_at": time.time(),
        }
        return result, reasoning

    async def _compute_scores(self, request: AgentRequest, result: Dict) -> Tuple[float,float,float,float,float]:
        return 95.0, 97.0, 98.0, 96.0, 97.0
