import time
from fastapi import APIRouter, Request
router = APIRouter()

@router.get("")
async def health(request: Request):
    registry = request.app.state.registry
    ai_router = request.app.state.ai_router
    return {
        "status":    "operational",
        "platform":  "CYBERDUDEBIVASH MACOS",
        "agents":    registry.summary() if registry else {},
        "ai_providers": await ai_router.status() if ai_router else {},
        "timestamp": time.time(),
    }

@router.get("/agents")
async def agent_health(request: Request):
    return request.app.state.registry.list_all()
