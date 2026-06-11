import uuid
from fastapi import APIRouter, Request, Depends
from ..middleware.auth import verify_token
router = APIRouter()

@router.post("/analyze")
async def analyze(request: Request, body: dict, auth: dict = Depends(verify_token)):
    intent_map = {
        "executive": "ciso_briefing",
        "ai_security": "assess_prompt_injection",
        "compliance": "compliance_check",
        "customer": "support_request",
    }
    intent = body.get("intent") or intent_map.get("customer", "customer_analyze")
    result = await request.app.state.orchestrator.orchestrate(
        session_id=str(uuid.uuid4()), user_id=auth["user_id"],
        tenant_id=auth["tenant_id"], intent=intent,
        payload=body, tier=auth.get("tier","FREE"),
    )
    return result.model_dump()
