from fastapi import Request, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import ValidationError
from .config import settings
from .security import ALGORITHM
import logging
import time

logger = logging.getLogger("netvisor.deps")

reusable_oauth2 = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login"
)

def get_current_user(
    token: str = Depends(reusable_oauth2)
):
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[ALGORITHM]
        )
        return payload
    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )

def require_super_admin(user: dict = Depends(get_current_user)):
    if user.get("role") != 'super_admin':
        raise HTTPException(status_code=403, detail="Super Admin access required")
    return user

def require_org_admin(user: dict = Depends(get_current_user)):
    if user.get("role") not in ['super_admin', 'org_admin']:
        raise HTTPException(status_code=403, detail="Organization Admin access required")
    return user

# --- RATE LIMITER ---
last_requests = {}

def rate_limit(seconds_between: float = 0.1):
    def dependency(request: Request):
        client_ip = request.client.host
        now = time.time()
        # Cleanup old entries every 100 requests
        if len(last_requests) > 1000:
            cutoff = now - 60
            stale_keys = [k for k, v in last_requests.items() if v < cutoff]
            for k in stale_keys:
                del last_requests[k]
        if client_ip in last_requests:
            if now - last_requests[client_ip] < seconds_between:
                raise HTTPException(status_code=429, detail="Too many requests")
        last_requests[client_ip] = now
        return True
    return dependency
