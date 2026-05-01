from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import ipaddress
import logging
from ..core.config import settings
from ..services.metrics_service import metrics_service

logger = logging.getLogger("netvisor.middleware.transport_security")


class TransportSecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    @staticmethod
    def _is_private_lan_host(host: str | None) -> bool:
        if not host:
            return False
        try:
            return ipaddress.ip_address(host).is_private
        except ValueError:
            return False

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        is_agent_endpoint = (
            path.startswith("/api/v1/collect/")
            or path.startswith("/api/v1/gateway/")
        )

        client_host = request.client.host if request.client else None
        is_local_request = (
            client_host in ("127.0.0.1", "localhost", "::1")
            or request.url.hostname in ("127.0.0.1", "localhost", "::1")
        )
        is_lan_http_allowed = bool(settings.ALLOW_LAN_HTTP and self._is_private_lan_host(client_host))

        forwarded_proto = str(request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
        effective_scheme = forwarded_proto or request.url.scheme.lower()

        if is_agent_endpoint and not is_local_request and not is_lan_http_allowed and effective_scheme != "https":
            client_host = client_host or "unknown"
            metrics_service.increment(
                "transport_https_rejections_total",
                path=path,
            )
            logger.warning(
                "Rejected non-HTTPS request to agent/gateway endpoint from non-local host: %s",
                client_host,
            )
            return JSONResponse(
                status_code=403,
                content={"detail": "HTTPS required for agent and gateway collection endpoints"},
            )

        response = await call_next(request)
        return response
