from __future__ import annotations

from typing import Optional

from ..db.session import require_runtime_schema
from ..utils.network import classify_ip_scope, normalize_ip


class ExternalEndpointService:
    def __init__(self) -> None:
        self._schema_ready = False

    def ensure_table(self, db_conn) -> None:
        if self._schema_ready:
            return
        require_runtime_schema(db_conn)
        self._schema_ready = True

    def observe_endpoint(
        self,
        db_conn,
        *,
        endpoint_ip: str | None,
        organization_id: Optional[str],
        domain: Optional[str] = None,
        application: Optional[str] = None,
        byte_count: int = 0,
    ) -> None:
        normalized_ip = normalize_ip(endpoint_ip)
        if not normalized_ip or classify_ip_scope(normalized_ip) != "external":
            return

        self.ensure_table(db_conn)
        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO external_endpoints (
                    endpoint_ip,
                    organization_id,
                    last_domain,
                    last_application,
                    first_seen,
                    last_seen,
                    total_flows,
                    total_bytes
                )
                VALUES (%s, %s, %s, %s, UTC_TIMESTAMP(), UTC_TIMESTAMP(), 1, %s)
                ON DUPLICATE KEY UPDATE
                    organization_id = COALESCE(VALUES(organization_id), organization_id),
                    last_domain = COALESCE(NULLIF(VALUES(last_domain), ''), last_domain),
                    last_application = COALESCE(NULLIF(VALUES(last_application), ''), last_application),
                    last_seen = UTC_TIMESTAMP(),
                    total_flows = total_flows + 1,
                    total_bytes = total_bytes + VALUES(total_bytes)
                """,
                (
                    normalized_ip,
                    organization_id,
                    domain,
                    application,
                    max(int(byte_count or 0), 0),
                ),
            )
        finally:
            cursor.close()


external_endpoint_service = ExternalEndpointService()
