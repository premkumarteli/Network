from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
import secrets
from ..core.security import create_access_token
from ..core.dependencies import get_current_user, request_rate_limit
from ..db.session import get_db_connection
from ..schemas.user_schema import UserCreate, User
from ..schemas.token_schema import AuthSession, LogoutResponse
from ..services.auth_service import auth_service
from ..services.audit_service import audit_service
from ..services.metrics_service import metrics_service
from ..core.config import settings

router = APIRouter()

login_rate_limit = request_rate_limit(
    limit=settings.AUTH_LOGIN_RATE_LIMIT_PER_MINUTE,
    window_seconds=60,
    bucket="auth_login",
)
register_rate_limit = request_rate_limit(
    limit=settings.AUTH_REGISTER_RATE_LIMIT_PER_MINUTE,
    window_seconds=60,
    bucket="auth_register",
)


def _build_session_payload(user: dict) -> dict:
    return {
        "authenticated": True,
        "id": user.get("id"),
        "username": user.get("username", "User"),
        "email": user.get("email"),
        "role": user.get("role", "viewer"),
        "organization_id": user.get("organization_id"),
    }


def _set_auth_cookie(response: Response, request: Request, access_token: str, max_age_seconds: int) -> None:
    scheme = getattr(getattr(request, "url", None), "scheme", "http")
    secure_cookie = bool(settings.AUTH_COOKIE_SECURE or scheme == "https")
    response.set_cookie(
        key=settings.AUTH_COOKIE_NAME,
        value=access_token,
        max_age=max_age_seconds,
        httponly=True,
        secure=secure_cookie,
        samesite=(settings.AUTH_COOKIE_SAMESITE or "lax").lower(),
        path=settings.AUTH_COOKIE_PATH or "/",
        domain=settings.AUTH_COOKIE_DOMAIN or None,
    )


def _clear_auth_cookie(response: Response, request: Request) -> None:
    scheme = getattr(getattr(request, "url", None), "scheme", "http")
    secure_cookie = bool(settings.AUTH_COOKIE_SECURE or scheme == "https")
    response.delete_cookie(
        key=settings.AUTH_COOKIE_NAME,
        path=settings.AUTH_COOKIE_PATH or "/",
        domain=settings.AUTH_COOKIE_DOMAIN or None,
        secure=secure_cookie,
        httponly=True,
        samesite=(settings.AUTH_COOKIE_SAMESITE or "lax").lower(),
    )


def _set_csrf_cookie(response: Response, request: Request) -> str:
    scheme = getattr(getattr(request, "url", None), "scheme", "http")
    secure_cookie = bool(settings.AUTH_COOKIE_SECURE or scheme == "https")
    csrf_token = secrets.token_urlsafe(32)
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=max(int(settings.ACCESS_TOKEN_MINUTES or 30), 1) * 60,
        httponly=False,
        secure=secure_cookie,
        samesite=(settings.AUTH_COOKIE_SAMESITE or "lax").lower(),
        path=settings.AUTH_COOKIE_PATH or "/",
        domain=settings.AUTH_COOKIE_DOMAIN or None,
    )
    return csrf_token


def _clear_csrf_cookie(response: Response, request: Request) -> None:
    scheme = getattr(getattr(request, "url", None), "scheme", "http")
    secure_cookie = bool(settings.AUTH_COOKIE_SECURE or scheme == "https")
    response.delete_cookie(
        key=settings.CSRF_COOKIE_NAME,
        path=settings.AUTH_COOKIE_PATH or "/",
        domain=settings.AUTH_COOKIE_DOMAIN or None,
        secure=secure_cookie,
        httponly=False,
        samesite=(settings.AUTH_COOKIE_SAMESITE or "lax").lower(),
    )


@router.post("/login", response_model=AuthSession)
async def login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    _rate_limited: bool = Depends(login_rate_limit),
):
    conn = get_db_connection()
    try:
        user = auth_service.authenticate(conn, form_data.username, form_data.password)
        if not user:
            metrics_service.increment("user_login_failures_total")
            audit_service.log_auth_attempt(
                username=form_data.username,
                action="user_login_failed",
                details=f"client_ip: {request.client.host if request.client else 'unknown'}",
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        access_token_expires = timedelta(minutes=max(int(settings.ACCESS_TOKEN_MINUTES or 30), 1))
        access_token = create_access_token(
            subject=user["id"], expires_delta=access_token_expires,
            extra_claims={
                "role": user.get("role", "viewer"),
                "organization_id": user.get("organization_id"),
                "username": user.get("username"),
            }
        )
        _set_auth_cookie(
            response,
            request,
            access_token,
            max_age_seconds=max(int(access_token_expires.total_seconds()), 60),
        )
        _set_csrf_cookie(response, request)
        metrics_service.increment("user_login_success_total")
        audit_service.log_auth_attempt(
            username=user.get("username") or form_data.username,
            action="user_login_succeeded",
            organization_id=user.get("organization_id"),
            details=f"role: {user.get('role', 'viewer')}",
        )
        return _build_session_payload(user)
    finally:
        conn.close()

@router.post("/register", response_model=User)
async def register(
    user_in: UserCreate,
    _rate_limited: bool = Depends(register_rate_limit),
):
    if user_in.password != user_in.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    
    conn = get_db_connection()
    try:
        if not settings.ALLOW_SELF_REGISTER and auth_service.count_users(conn) > 0:
            metrics_service.increment("user_registration_rejections_total", reason="self_register_disabled")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Self-registration is disabled. Contact an administrator.",
            )
        user = auth_service.create_user(conn, user_in)
        if not user:
            metrics_service.increment("user_registration_rejections_total", reason="conflict")
            raise HTTPException(status_code=409, detail="Username or Email already exists")
        metrics_service.increment("user_registration_success_total")
        audit_service.log_auth_attempt(
            username=user.get("username") or user_in.username,
            action="user_registration_succeeded",
            organization_id=user.get("organization_id"),
        )
        return user
    finally:
        conn.close()


@router.post("/logout", response_model=LogoutResponse)
async def logout(request: Request, response: Response):
    _clear_auth_cookie(response, request)
    _clear_csrf_cookie(response, request)
    return {"status": "ok"}


@router.get("/me", response_model=AuthSession)
async def get_me(current_user: dict = Depends(get_current_user)):
    return _build_session_payload(current_user)
