from __future__ import annotations

import logging
from collections.abc import Mapping
from http.cookies import SimpleCookie

from jose import JWTError, jwt

from .core.config import settings
from .core.security import ALGORITHM
from .db.session import get_db_connection
from .services.auth_service import auth_service
from .services.metrics_service import metrics_service

logger = logging.getLogger("netvisor.realtime")

_socket_server = None

AUTHENTICATED_SOCKET_ROOM = "authenticated"
ORG_SOCKET_ROOM_PREFIX = "org:"


class SocketAuthenticationError(RuntimeError):
    pass


def configure_socket_server(server) -> None:
    global _socket_server
    _socket_server = server


def socket_room_for_organization(organization_id: str | None) -> str | None:
    normalized = str(organization_id or "").strip()
    if not normalized:
        return None
    return f"{ORG_SOCKET_ROOM_PREFIX}{normalized}"


def _parse_cookie_token(environ: Mapping[str, object]) -> str | None:
    cookie_header = ""
    for key in ("HTTP_COOKIE", "Cookie", "cookie"):
        value = environ.get(key)
        if value:
            cookie_header = str(value)
            break

    if not cookie_header:
        return None

    cookie = SimpleCookie()
    cookie.load(cookie_header)
    morsel = cookie.get(settings.AUTH_COOKIE_NAME)
    if not morsel:
        return None
    return morsel.value or None


def authenticate_socket_connection(environ: Mapping[str, object]) -> dict:
    token = _parse_cookie_token(environ)
    if not token:
        metrics_service.increment("socket_auth_failures_total", reason="missing_cookie")
        raise SocketAuthenticationError("Authentication required.")

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        metrics_service.increment("socket_auth_failures_total", reason="invalid_token")
        raise SocketAuthenticationError("Invalid authentication token.") from exc

    user_id = str(payload.get("sub") or "").strip()
    if not user_id:
        metrics_service.increment("socket_auth_failures_total", reason="missing_subject")
        raise SocketAuthenticationError("Invalid authentication token.")

    conn = get_db_connection()
    try:
        user = auth_service.get_user_by_id(conn, user_id)
    finally:
        conn.close()

    if not user:
        metrics_service.increment("socket_auth_failures_total", reason="unknown_user")
        raise SocketAuthenticationError("Authentication required.")

    if str(user.get("status") or "active").lower() == "disabled":
        metrics_service.increment("socket_auth_failures_total", reason="disabled_user")
        raise SocketAuthenticationError("User account is disabled.")

    organization_id = str(user.get("organization_id") or "").strip() or None
    metrics_service.increment("socket_auth_success_total")
    return {
        "user": user,
        "user_id": user.get("id"),
        "organization_id": organization_id,
        "role": user.get("role"),
    }


async def emit_event(event_name: str, payload: dict) -> None:
    if _socket_server is None:
        return

    try:
        room = None
        if isinstance(payload, dict):
            org_id = str(payload.get("organization_id") or "").strip()
            room = socket_room_for_organization(org_id) if org_id else AUTHENTICATED_SOCKET_ROOM
        await _socket_server.emit(event_name, payload, room=room)
    except Exception:
        logger.exception("Failed to emit realtime event %s", event_name)
