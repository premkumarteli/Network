from __future__ import annotations

import logging
import time
import uuid

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from ..services.metrics_service import metrics_service

logger = logging.getLogger("netvisor.middleware.request_context")


class RequestContextMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        request_id = str(request.headers.get("x-request-id") or "").strip() or uuid.uuid4().hex
        request.state.request_id = request_id
        start = time.perf_counter()

        response = await call_next(request)

        duration_seconds = max(time.perf_counter() - start, 0.0)
        status_code = int(getattr(response, "status_code", 200) or 200)
        status_class = f"{status_code // 100}xx"
        method = request.method.upper()
        path = request.url.path

        response.headers["X-Request-ID"] = request_id
        metrics_service.increment("http_requests_total", method=method, status_class=status_class)
        metrics_service.observe("http_request_duration_seconds", duration_seconds, method=method, status_class=status_class)

        if status_code >= 500 or duration_seconds >= 1.0:
            logger.warning(
                "request_id=%s method=%s path=%s status=%s duration_ms=%.2f",
                request_id,
                method,
                path,
                status_code,
                duration_seconds * 1000.0,
            )

        return response
