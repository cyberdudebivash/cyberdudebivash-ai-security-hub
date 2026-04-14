# ============================================================
# CYBERDUDEBIVASH AI — JWT HANDLER
# ============================================================

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from jose import jwt, JWTError
from core.settings import settings
from core.logging_config import get_logger

logger = get_logger("auth.jwt")


def create_access_token(data: Dict[str, Any], expires_hours: Optional[int] = None) -> str:
    payload = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(hours=expires_hours or settings.jwt_expire_hours)
    payload["exp"] = expire
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    except JWTError as e:
        logger.warning(f"JWT decode failed: {e}")
        return None


def verify_token(token: str) -> bool:
    return decode_token(token) is not None
