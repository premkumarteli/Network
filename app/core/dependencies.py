from collections import deque
from fastapi import Request, HTTPException, Depends, status
from jose import jwt, JWTError
from pydantic import ValidationError
from datetime import datetime, timezone
from .config import settings
from .security import ALGORITHM
from ..db.session import get_db_connection
from ..services.auth_service import auth_service
from ..services.metrics_service import metrics_service
import logging
import time
import threading

logger = logging.getLogger("netvisor.deps")

def _resolve_request_token(request: Request) -> str:
    cookie_token = request.cookies.get(settings.AUTH_COOKIE_NAME)
    if cookie_token:
        return cookie_token

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    request: Request,
):
    conn = None
    try:
        resolved_token = _resolve_request_token(request)
        payload = jwt.decode(
            resolved_token, settings.SECRET_KEY, algorithms=[ALGORITHM]
        )
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        conn = get_db_connection()
        user = auth_service.get_user_by_id(conn, user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if str(user.get("status") or "active").lower() == "disabled":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is disabled",
            )
        locked_until = user.get("locked_until")
        if isinstance(locked_until, str):
            try:
                locked_until = datetime.strptime(locked_until, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                locked_until = None
        elif getattr(locked_until, "tzinfo", None) is None and locked_until is not None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if locked_until and locked_until > datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is locked",
            )
        return user
    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    finally:
        if conn:
            conn.close()

def require_super_admin(user: dict = Depends(get_current_user)):
    if user.get("role") != 'super_admin':
        raise HTTPException(status_code=403, detail="Super Admin access required")
    return user

def require_org_admin(user: dict = Depends(get_current_user)):
    if user.get("role") not in ['super_admin', 'org_admin']:
        raise HTTPException(status_code=403, detail="Organization Admin access required")
    return user

# --- RATE LIMITER ---
_rate_limit_buckets: dict[str, deque[float]] = {}
_rate_limit_lock = threading.Lock()


def _default_rate_limit_identity(request: Request) -> str:
    client_host = request.client.host if request.client else "unknown"
    return f"{client_host}:{request.url.path}"


def request_rate_limit(
    *,
    limit: int,
    window_seconds: float,
    bucket: str,
    key_builder=None,
):
    max_requests = max(int(limit or 1), 1)
    window = max(float(window_seconds or 1.0), 1.0)

    def dependency(request: Request):
        identity_builder = key_builder or _default_rate_limit_identity
        identity = str(identity_builder(request) or "anonymous")
        storage_key = f"{bucket}:{identity}"
        now = time.monotonic()
        cutoff = now - window

        with _rate_limit_lock:
            request_times = _rate_limit_buckets.setdefault(storage_key, deque())
            while request_times and request_times[0] <= cutoff:
                request_times.popleft()

            if len(request_times) >= max_requests:
                metrics_service.increment(
                    "rate_limit_rejections_total",
                    bucket=bucket,
                    path=request.url.path,
                )
                raise HTTPException(status_code=429, detail="Too many requests")

            request_times.append(now)

            if len(_rate_limit_buckets) > 10000:
                stale_keys = [
                    key
                    for key, timestamps in _rate_limit_buckets.items()
                    if not timestamps or timestamps[-1] <= cutoff
                ]
                for key in stale_keys:
                    _rate_limit_buckets.pop(key, None)

        metrics_service.set_gauge("rate_limit_active_buckets", len(_rate_limit_buckets))
        return True

    return dependency


def rate_limit(seconds_between: float = 0.1):
    limit = 1
    window = max(float(seconds_between or 0.1), 0.1)
    return request_rate_limit(limit=limit, window_seconds=window, bucket="compat_rate_limit")
