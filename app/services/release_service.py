from __future__ import annotations

from datetime import datetime, timezone

from ..core.config import settings


class ReleaseService:
    def __init__(self) -> None:
        self.started_at = datetime.now(timezone.utc)

    def snapshot(self) -> dict:
        now = datetime.now(timezone.utc)
        uptime_seconds = max((now - self.started_at).total_seconds(), 0.0)
        release_version = str(settings.RELEASE_VERSION or settings.VERSION or "").strip() or settings.VERSION
        return {
            "project_name": settings.PROJECT_NAME,
            "app_version": settings.VERSION,
            "release_version": release_version,
            "release_channel": str(settings.RELEASE_CHANNEL or "dev").strip() or "dev",
            "git_commit": str(settings.GIT_COMMIT or "").strip() or None,
            "build_timestamp": str(settings.BUILD_TIMESTAMP or "").strip() or None,
            "started_at": self.started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "uptime_seconds": round(uptime_seconds, 3),
        }


release_service = ReleaseService()
