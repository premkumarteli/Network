from fastapi import Request, HTTPException, Depends, status
from core.database import get_db_connection
import logging
import time

logger = logging.getLogger("netvisor.deps")

def get_current_user(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Session expired or not authenticated"
        )
    return {
        "user_id": user_id,
        "username": request.session.get("username"),
        "role": request.session.get("role"),
        "organization_id": request.session.get("organization_id")
    }

def require_super_admin(user: dict = Depends(get_current_user)):
    if user["role"] != 'super_admin':
        logger.warning(f"SuperAdmin access denied for {user['username']}")
        raise HTTPException(status_code=403, detail="Super Admin access required")
    return user

def require_org_admin(user: dict = Depends(get_current_user)):
    if user["role"] not in ['super_admin', 'org_admin']:
        logger.warning(f"OrgAdmin access denied for {user['username']}")
        raise HTTPException(status_code=403, detail="Organization Admin access required")
    return user

def admin_required(user: dict = Depends(get_current_user)):
    """Legacy compatibility - maps to org_admin in new system"""
    return require_org_admin(user)

def login_required(user: dict = Depends(get_current_user)):
    return user["username"] # Compatibility with existing code

# --- SIMPLE RATE LIMITER ---
last_requests = {}

def rate_limit(seconds_between: float = 0.1):
    def dependency(request: Request):
        client_ip = request.client.host
        now = time.time()
        if client_ip in last_requests:
            if now - last_requests[client_ip] < seconds_between:
                raise HTTPException(status_code=429, detail="Too many requests")
        last_requests[client_ip] = now
        return True
    return dependency
