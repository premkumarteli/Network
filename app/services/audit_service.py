from __future__ import annotations

import logging
from typing import Optional, Dict, Any
from datetime import datetime

from ..db.session import get_db_connection
from ..core.config import settings

logger = logging.getLogger("netvisor.audit")


class AuditService:
    def __init__(self):
        self.enabled = True  # Could be made configurable

    def _log_audit_event(
        self,
        organization_id: str,
        username: str,
        action: str,
        details: Optional[str] = None,
    ) -> None:
        if not self.enabled:
            return
            
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO audit_logs (organization_id, username, action, details, created_at)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    organization_id,
                    username,
                    action,
                    details,
                    datetime.now(),
                ),
            )
            conn.commit()
        except Exception as exc:
            logger.error(f"Failed to write audit log: {exc}")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    def log_agent_registration(
        self,
        organization_id: str,
        username: str,
        agent_id: str,
        action: str = "agent_registration",
        details: Optional[str] = None,
    ) -> None:
        """Log agent registration events."""
        audit_details = f"agent_id: {agent_id}"
        if details:
            audit_details += f"; {details}"
        self._log_audit_event(organization_id, username or "system", action, audit_details)

    def log_credential_rotation(
        self,
        organization_id: str,
        username: str,
        agent_id: str,
        action: str = "agent_credential_rotation",
    ) -> None:
        """Log agent credential rotation events."""
        self._log_audit_event(
            organization_id, 
            username or "system", 
            action, 
            f"agent_id: {agent_id}"
        )

    def log_inspection_toggle(
        self,
        organization_id: str,
        username: str,
        agent_id: str,
        device_ip: str,
        enabled: bool,
        action: str = "web_inspection_toggle",
    ) -> None:
        """Log web inspection enable/disable events."""
        status = "enabled" if enabled else "disabled"
        self._log_audit_event(
            organization_id,
            username or "system",
            action,
            f"agent_id: {agent_id}; device_ip: {device_ip}; inspection_{status}",
        )

    def log_ca_operation(
        self,
        organization_id: str,
        username: str,
        operation: str,  # install/remove/rotate
        action: str = "ca_operation",
    ) -> None:
        """Log CA install/remove/rotation events."""
        self._log_audit_event(
            organization_id,
            username or "system",
            action,
            f"ca_operation: {operation}",
        )

    def log_auth_attempt(
        self,
        *,
        username: str,
        action: str,
        organization_id: str | None = None,
        details: Optional[str] = None,
    ) -> None:
        self._log_audit_event(
            organization_id or "default-org-id",
            username or "unknown",
            action,
            details,
        )


# Global instance
audit_service = AuditService()
