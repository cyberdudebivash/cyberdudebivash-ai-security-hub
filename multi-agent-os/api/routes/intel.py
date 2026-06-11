import uuid
from fastapi import APIRouter, Request, Depends
from ..middleware.auth import verify_token
router = APIRouter()

@router.post("/ioc")
async def analyze_ioc(request: Request, body: dict, auth: dict = Depends(verify_token)):
    return await _orchestrate(request, auth, "analyze_ioc", body)

@router.post("/cve")
async def lookup_cve(request: Request, body: dict, auth: dict = Depends(verify_token)):
    return await _orchestrate(request, auth, "lookup_cve", body)

@router.post("/malware")
async def analyze_malware(request: Request, body: dict, auth: dict = Depends(verify_token)):
    return await _orchestrate(request, auth, "analyze_malware", body)

@router.post("/actor")
async def threat_actor(request: Request, body: dict, auth: dict = Depends(verify_token)):
    return await _orchestrate(request, auth, "get_threat_actor", body)

@router.post("/brief")
async def threat_brief(request: Request, body: dict, auth: dict = Depends(verify_token)):
    return await _orchestrate(request, auth, "threat_brief", body)

async def _orchestrate(request, auth, intent, payload):
    result = await request.app.state.orchestrator.orchestrate(
        session_id=str(uuid.uuid4()), user_id=auth["user_id"],
        tenant_id=auth["tenant_id"], intent=intent,
        payload=payload, tier=auth.get("tier","FREE"),
    )
    return result.model_dump()
