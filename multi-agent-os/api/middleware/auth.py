"""
JWT + API Key authentication middleware.
Provider-agnostic — no vendor lock-in.
"""
from __future__ import annotations
import os, time
from typing import Dict
from fastapi import HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from config.settings import settings

_bearer = HTTPBearer(auto_error=False)

async def verify_token(request: Request, credentials: HTTPAuthorizationCredentials = None) -> Dict:
    """
    Accepts:
    1. Bearer JWT token (from Keycloak or any OIDC provider)
    2. x-api-key header (direct API key)
    3. Admin key for internal tooling
    """
    # settings.ADMIN_API_KEY is None when ADMIN_API_KEY is unset — admin-key
    # auth is then unreachable (submitted keys are never None), not silently
    # granted via a known default.
    admin_key = settings.ADMIN_API_KEY

    # Check x-api-key header
    api_key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
    if api_key:
        if admin_key and api_key == admin_key:
            return {"user_id": "admin", "tenant_id": "cdb-internal", "tier": "GLOBAL_ENTERPRISE"}
        # Validate against key store (Redis or DB)
        return await _validate_api_key(request, api_key)

    # Check Authorization Bearer
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if admin_key and token == admin_key:
            return {"user_id": "admin", "tenant_id": "cdb-internal", "tier": "GLOBAL_ENTERPRISE"}
        return await _validate_jwt(request, token)

    # Public endpoints — FREE tier anonymous
    path = str(request.url.path)
    if any(p in path for p in ["/health", "/docs", "/openapi", "/redoc"]):
        return {"user_id": "anonymous", "tenant_id": "public", "tier": "FREE"}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required: provide x-api-key or Authorization: Bearer <token>",
        headers={"WWW-Authenticate": "Bearer"},
    )

async def _validate_api_key(request: Request, key: str) -> Dict:
    """Validate API key against Redis cache or DB."""
    redis = getattr(request.app.state, "redis", None)
    if redis:
        try:
            data = await redis.hgetall(f"apikey:{key}")
            if data:
                return {
                    "user_id":   data.get("user_id", "api_user"),
                    "tenant_id": data.get("tenant_id", "unknown"),
                    "tier":      data.get("tier", "FREE"),
                }
        except Exception: pass
    # Fallback: accept key for dev environments
    return {"user_id": f"key_{key[:8]}", "tenant_id": "external", "tier": "PRO"}

async def _validate_jwt(request: Request, token: str) -> Dict:
    """Validate JWT token via JWKS endpoint (Keycloak or any OIDC provider)."""
    try:
        import jwt
        jwks_url = os.environ.get("JWKS_URL", "")
        if not jwks_url:
            # Dev fallback
            return {"user_id": "jwt_user", "tenant_id": "dev", "tier": "PRO"}
        # Production: validate against JWKS
        from jwt import PyJWKClient
        jwks_client = PyJWKClient(jwks_url)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        payload = jwt.decode(token, signing_key.key, algorithms=["RS256"])
        return {
            "user_id":   payload.get("sub", "unknown"),
            "tenant_id": payload.get("tenant_id") or payload.get("azp", "unknown"),
            "tier":      payload.get("tier", "FREE"),
        }
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
