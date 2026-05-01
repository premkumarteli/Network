from __future__ import annotations

import logging
import secrets

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from ..core.config import settings
from ..services.metrics_service import metrics_service

logger = logging.getLogger("netvisor.middleware.csrf")

_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_CSRF_EXEMPT_PATHS = {
    "/api/v1/auth/login",
    "/api/v1/auth/register",
}


class CSRFProtectionError(RuntimeError):
    pass


def _set_csrf_cookie(response, request: Request) -> str:
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


def validate_csrf_request(request: Request) -> None:
    if request.method.upper() not in _UNSAFE_METHODS:
        return

    if request.url.path in _CSRF_EXEMPT_PATHS:
        return

    if request.url.path.startswith("/socket.io"):
        return

    auth_cookie = request.cookies.get(settings.AUTH_COOKIE_NAME)
    if not auth_cookie:
        return

    csrf_cookie = request.cookies.get(settings.CSRF_COOKIE_NAME)
    csrf_header = request.headers.get(settings.CSRF_HEADER_NAME)

    if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
        metrics_service.increment("csrf_rejections_total", path=request.url.path, method=request.method.upper())
        logger.warning("Rejected CSRF-protected request for %s", request.url.path)
        raise CSRFProtectionError("CSRF validation failed")


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        try:
            validate_csrf_request(request)
        except CSRFProtectionError:
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF validation failed"},
            )

        response = await call_next(request)

        if (
            request.method.upper() not in _UNSAFE_METHODS
            and request.cookies.get(settings.AUTH_COOKIE_NAME)
            and not request.cookies.get(settings.CSRF_COOKIE_NAME)
        ):
            _set_csrf_cookie(response, request)

        return response
