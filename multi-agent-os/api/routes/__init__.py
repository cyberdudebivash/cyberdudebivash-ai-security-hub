from .intel import router as intel_router
from .soc import router as soc_router
from .executive import router as executive_router
from .ai_security import router as ai_security_router
from .compliance import router as compliance_router
from .customer import router as customer_router
from .health import router as health_router

__all__ = [
    "intel_router", "soc_router", "executive_router",
    "ai_security_router", "compliance_router", "customer_router", "health_router",
]
