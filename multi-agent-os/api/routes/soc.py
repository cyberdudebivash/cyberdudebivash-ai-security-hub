import uuid
from fastapi import APIRouter, Request, Depends
from ..middleware.auth import verify_token
router = APIRouter()

@router.post("/alert")
async def triage_alert(request: Request, body: dict, auth: dict = Depends(verify_token)):
    result = await request.app.state.orchestrator.orchestrate(
        session_id=str(uuid.uuid4()), user_id=auth["user_id"],
        tenant_id=auth["tenant_id"], intent="analyze_alert",
        payload=body, tier=auth.get("tier","FREE"),
    )
    return result.model_dump()

@router.post("/incident")
async def create_incident(request: Request, body: dict, auth: dict = Depends(verify_token)):
    result = await request.app.state.orchestrator.orchestrate(
        session_id=str(uuid.uuid4()), user_id=auth["user_id"],
        tenant_id=auth["tenant_id"], intent="incident_response",
        payload=body, tier=auth.get("tier","FREE"),
    )
    return result.model_dump()

@router.post("/hunt")
async def threat_hunt(request: Request, body: dict, auth: dict = Depends(verify_token)):
    result = await request.app.state.orchestrator.orchestrate(
        session_id=str(uuid.uuid4()), user_id=auth["user_id"],
        tenant_id=auth["tenant_id"], intent="threat_hunt",
        payload=body, tier=auth.get("tier","FREE"),
    )
    return result.model_dump()
