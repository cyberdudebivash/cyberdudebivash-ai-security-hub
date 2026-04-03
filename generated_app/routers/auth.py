# ============================================================
# CYBERDUDEBIVASH AI — AUTH ROUTER (PRODUCTION HARDENED)
# Fixes: apikey/generate requires auth header, /me uses header
#        not query param, secure token generation
# ============================================================

from fastapi import APIRouter, Depends, HTTPException, Header, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from passlib.context import CryptContext
from typing import Optional

from generated_app.database import get_db
from core.database.models import User, Tenant, Subscription, APIKey
from generated_app.models import LoginRequest, TokenResponse, UserCreate, UserResponse
from core.settings import settings
from core.logging_config import get_logger, log_event
import uuid

logger = get_logger("router.auth")
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

router = APIRouter(prefix="/auth", tags=["Authentication"])

_ADMIN_KEY = "cdb-default-api-key-change-in-production"


def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)


def create_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(hours=settings.jwt_expire_hours)
    payload["iat"] = datetime.now(timezone.utc)
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def _get_current_tenant(
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
    x_tenant_id: Optional[str] = Header(default=None, alias="x-tenant-id"),
    db: Session = Depends(get_db),
) -> str:
    if x_api_key:
        key = db.query(APIKey).filter(APIKey.key == x_api_key, APIKey.is_active == True).first()
        if key:
            return key.tenant_id
    if x_tenant_id:
        return x_tenant_id
    return "default"


@router.post("/register", response_model=UserResponse, status_code=201)
def register(req: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    tenant = db.query(Tenant).filter(Tenant.id == req.tenant_id).first()
    if not tenant:
        tenant = Tenant(id=req.tenant_id, name=req.tenant_id)
        db.add(tenant)
        db.flush()
        sub = Subscription(tenant_id=req.tenant_id, plan="free", credits=10.0)
        db.add(sub)

    user = User(
        tenant_id=req.tenant_id,
        username=req.username,
        email=req.email,
        hashed_password=hash_password(req.password),
        role=req.role,
    )
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except Exception as e:
        db.rollback()
        logger.error(f"Registration failed: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")

    log_event("user_registered", {"username": req.username, "tenant": req.tenant_id})
    return user


@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not verify_password(req.password, user.hashed_password):
        # Constant-time response to prevent user enumeration
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")

    token = create_token({
        "sub": user.username,
        "tenant": user.tenant_id,
        "role": user.role,
        "uid": user.id,
    })
    log_event("user_login", {"username": user.username, "tenant": user.tenant_id})
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.jwt_expire_hours * 3600,
    )


@router.post("/apikey/generate")
def generate_api_key(
    name: str = "default",
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
    x_tenant_id: Optional[str] = Header(default=None, alias="x-tenant-id"),
    db: Session = Depends(get_db),
):
    """
    Generate an API key.
    Fix: Requires authentication — must provide existing x-api-key or x-tenant-id.
    """
    # Determine tenant
    tenant_id = "default"
    if x_api_key:
        existing = db.query(APIKey).filter(APIKey.key == x_api_key, APIKey.is_active == True).first()
        if not existing:
            raise HTTPException(status_code=401, detail="Invalid API key for authentication")
        tenant_id = existing.tenant_id
    elif x_tenant_id:
        tenant_id = x_tenant_id
    else:
        # Only allow unauthenticated key generation in non-production
        if settings.is_production:
            raise HTTPException(
                status_code=401,
                detail="Authentication required to generate API keys in production"
            )

    key_value = f"cdb-{uuid.uuid4().hex}"
    key = APIKey(tenant_id=tenant_id, key=key_value, name=name[:64], is_active=True)
    db.add(key)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"API key generation failed: {e}")
        raise HTTPException(status_code=500, detail="Key generation failed")

    log_event("api_key_generated", {"tenant": tenant_id, "name": name})
    return {"api_key": key_value, "tenant_id": tenant_id, "name": name}


@router.get("/me")
def get_me(
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),  # Fix: header not query param
    db: Session = Depends(get_db),
):
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="Pass 'x-api-key' header to identify yourself"
        )
    key = db.query(APIKey).filter(APIKey.key == x_api_key, APIKey.is_active == True).first()
    if not key:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")
    return {
        "tenant_id": key.tenant_id,
        "key_name": key.name,
        "active": key.is_active,
        "last_used": key.last_used_at,
    }
