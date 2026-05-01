from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import logging
from ..core.config import settings
from ..services.metrics_service import metrics_service

logger = logging.getLogger("netvisor.middleware.transport_security")


class TransportSecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        is_agent_endpoint = (
            path.startswith("/api/v1/collect/")
            or path.startswith("/api/v1/gateway/")
        )

        is_local_request = (
            (request.client and (request.client.host in ("127.0.0.1", "localhost", "::1") or request.client.host.startswith("10.") or request.client.host.startswith("192.168.")))
            or
            request.url.hostname in ("127.0.0.1", "localhost")
        )

        forwarded_proto = str(request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
        effective_scheme = forwarded_proto or request.url.scheme.lower()

        if is_agent_endpoint and not is_local_request and not settings.DEBUG and effective_scheme != "https":
            client_host = request.client.host if request.client else "unknown"
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
