from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import logging
import secrets
from typing import Any

from fastapi import Request

from ..core.config import settings
from shared.security.agent_auth import (
    GATEWAY_BOOTSTRAP_KEY_HEADER,
    GATEWAY_ID_HEADER,
    KEY_VERSION_HEADER,
    NONCE_HEADER,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    verify_signature,
)
from .metrics_service import metrics_service

logger = logging.getLogger("netvisor.gateway_auth")


class GatewayAuthenticationError(ValueError):
    pass


@dataclass
class IssuedGatewayCredential:
    gateway_id: str
    key_version: int
    secret: str
    issued_at: str

    def as_response(self) -> dict[str, Any]:
        return {
            "gateway_id": self.gateway_id,
            "key_version": self.key_version,
            "secret": self.secret,
            "issued_at": self.issued_at,
        }


class GatewayAuthService:
    def _raise_auth_error(self, reason: str, message: str) -> None:
        metrics_service.increment("gateway_auth_failures_total", reason=reason)
        raise GatewayAuthenticationError(message)

    def _normalize_transport_pin(self, pin: dict[str, Any]) -> dict[str, str] | None:
        pin_type = str(pin.get("pin_type") or "spki_sha256").strip().lower()
        status = str(pin.get("status") or "active").strip().lower()
        pin_sha256 = str(pin.get("pin_sha256") or "").strip().upper()

        if pin_type not in {"spki_sha256", "cert_sha256"}:
            return None
        if status not in {"active", "next"}:
            return None
        if len(pin_sha256) != 64 or any(ch not in "0123456789ABCDEF" for ch in pin_sha256):
            return None

        normalized = {
            "pin_type": pin_type,
            "pin_sha256": pin_sha256,
            "status": status,
        }
        subject = str(pin.get("subject") or "").strip()
        if subject:
            normalized["subject"] = subject
        return normalized

    def _derive_secret(self, *, gateway_id: str, key_version: int, secret_salt: str) -> str:
        material = f"{gateway_id}:{key_version}:{secret_salt}".encode("utf-8")
        derived = hmac.new(settings.GATEWAY_MASTER_KEY.encode("utf-8"), material, hashlib.sha256).digest()
        return derived.hex()

    def _secret_hash(self, secret: str) -> str:
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()

    def _row_to_credential(self, row: dict) -> IssuedGatewayCredential:
        issued_at = row.get("issued_at")
        if issued_at and hasattr(issued_at, "strftime"):
            issued_at = issued_at.strftime("%Y-%m-%d %H:%M:%S")
        secret = self._derive_secret(
            gateway_id=str(row.get("gateway_id") or ""),
            key_version=int(row.get("key_version") or 1),
            secret_salt=str(row.get("secret_salt") or ""),
        )
        return IssuedGatewayCredential(
            gateway_id=str(row.get("gateway_id") or ""),
            key_version=int(row.get("key_version") or 1),
            secret=secret,
            issued_at=str(issued_at or ""),
        )

    def _fetch_active_credential_row(self, db_conn, *, gateway_id: str) -> dict | None:
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT gateway_id, key_version, secret_salt, issued_at
                FROM gateway_credentials
                WHERE gateway_id = %s AND status = 'active'
                ORDER BY key_version DESC
                LIMIT 1
                """,
                (gateway_id,),
            )
            return cursor.fetchone()
        finally:
            cursor.close()

    def get_active_credential(self, db_conn, *, gateway_id: str) -> IssuedGatewayCredential | None:
        row = self._fetch_active_credential_row(db_conn, gateway_id=gateway_id)
        return self._row_to_credential(row) if row else None

    def _next_key_version(self, db_conn, *, gateway_id: str) -> int:
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT COALESCE(MAX(key_version), 0) AS max_version
                FROM gateway_credentials
                WHERE gateway_id = %s
                """,
                (gateway_id,),
            )
            version_row = cursor.fetchone() or {}
            return int(version_row.get("max_version") or 0) + 1
        finally:
            cursor.close()

    def _insert_credential(
        self,
        db_conn,
        *,
        gateway_id: str,
        key_version: int,
        secret_salt: str,
        issued_at_expression: str = "UTC_TIMESTAMP()",
        rotated_at_expression: str = "NULL",
    ) -> None:
        secret = self._derive_secret(gateway_id=gateway_id, key_version=key_version, secret_salt=secret_salt)
        secret_hash = self._secret_hash(secret)
        cursor = db_conn.cursor()
        try:
            cursor.execute(
                f"""
                INSERT INTO gateway_credentials (
                    gateway_id,
                    key_version,
                    secret_salt,
                    secret_hash,
                    status,
                    issued_at,
                    rotated_at,
                    last_used_at
                )
                VALUES (%s, %s, %s, %s, 'active', {issued_at_expression}, {rotated_at_expression}, NULL)
                """,
                (gateway_id, key_version, secret_salt, secret_hash),
            )
        finally:
            cursor.close()

    def _fetch_credential_by_version(self, db_conn, *, gateway_id: str, key_version: int) -> IssuedGatewayCredential:
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT gateway_id, key_version, secret_salt, issued_at
                FROM gateway_credentials
                WHERE gateway_id = %s AND key_version = %s
                LIMIT 1
                """,
                (gateway_id, key_version),
            )
            row = cursor.fetchone()
            if not row:
                raise RuntimeError(f"Gateway credential {gateway_id}:{key_version} could not be reloaded after issuance.")
            return self._row_to_credential(row)
        finally:
            cursor.close()

    def issue_initial_credential(self, db_conn, *, gateway_id: str) -> IssuedGatewayCredential | None:
        if self._fetch_active_credential_row(db_conn, gateway_id=gateway_id):
            return None

        key_version = self._next_key_version(db_conn, gateway_id=gateway_id)
        secret_salt = secrets.token_hex(16)
        self._insert_credential(
            db_conn,
            gateway_id=gateway_id,
            key_version=key_version,
            secret_salt=secret_salt,
        )
        return self._fetch_credential_by_version(db_conn, gateway_id=gateway_id, key_version=key_version)

    def rotate_credential(self, db_conn, *, gateway_id: str) -> IssuedGatewayCredential:
        key_version = self._next_key_version(db_conn, gateway_id=gateway_id)
        secret_salt = secrets.token_hex(16)

        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                UPDATE gateway_credentials
                SET status = 'rotating'
                WHERE gateway_id = %s AND status = 'active'
                """,
                (gateway_id,),
            )
            self._insert_credential(
                db_conn,
                gateway_id=gateway_id,
                key_version=key_version,
                secret_salt=secret_salt,
                rotated_at_expression="UTC_TIMESTAMP()",
            )
            cursor.execute(
                """
                UPDATE gateway_credentials
                SET status = 'rotated'
                WHERE gateway_id = %s AND key_version < %s AND status IN ('active', 'rotating')
                """,
                (gateway_id, key_version),
            )
        finally:
            cursor.close()

        return self._fetch_credential_by_version(db_conn, gateway_id=gateway_id, key_version=key_version)

    def transport_pins(self) -> list[dict]:
        raw = str(settings.BACKEND_TLS_PINS_JSON or "[]").strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except ValueError:
            logger.warning("Invalid NETVISOR_BACKEND_TLS_PINS_JSON value; ignoring configured pinset.")
            return []
        if not isinstance(parsed, list):
            return []

        pins: list[dict] = []
        for pin in parsed:
            if not isinstance(pin, dict):
                continue
            normalized = self._normalize_transport_pin(pin)
            if normalized:
                pins.append(normalized)
            else:
                logger.warning("Ignoring invalid backend TLS pin entry for gateways: %s", pin)
        return pins

    def _nonce_seen(self, db_conn, *, gateway_id: str, key_version: int, nonce: str) -> bool:
        expires_before = datetime.now(timezone.utc) - timedelta(seconds=max(int(settings.AGENT_NONCE_TTL_SECONDS), 1))
        cursor = db_conn.cursor()
        try:
            cursor.execute(
                "DELETE FROM gateway_request_nonces WHERE created_at < %s",
                (expires_before.astimezone(timezone.utc).replace(tzinfo=None),),
            )
            try:
                expires_at = datetime.now(timezone.utc) + timedelta(seconds=max(int(settings.AGENT_NONCE_TTL_SECONDS), 1))
                cursor.execute(
                    """
                    INSERT INTO gateway_request_nonces (gateway_id, key_version, nonce, created_at, expires_at)
                    VALUES (%s, %s, %s, UTC_TIMESTAMP(), %s)
                    """,
                    (gateway_id, key_version, nonce, expires_at.astimezone(timezone.utc).replace(tzinfo=None)),
                )
                return False
            except Exception:
                return True
        finally:
            cursor.close()

    def authenticate_request(self, db_conn, request: Request, body: bytes) -> dict[str, Any]:
        provided_gateway_id = str(request.headers.get(GATEWAY_ID_HEADER) or "").strip()
        provided_version = str(request.headers.get(KEY_VERSION_HEADER) or "").strip()
        provided_timestamp = str(request.headers.get(TIMESTAMP_HEADER) or "").strip()
        provided_nonce = str(request.headers.get(NONCE_HEADER) or "").strip()
        provided_signature = str(request.headers.get(SIGNATURE_HEADER) or "").strip()

        using_signed_auth = any(
            [provided_gateway_id, provided_version, provided_timestamp, provided_nonce, provided_signature]
        )

        metrics_service.increment("gateway_auth_attempts_total", mode="signed")

        if not using_signed_auth:
            if request.headers.get(GATEWAY_BOOTSTRAP_KEY_HEADER):
                self._raise_auth_error(
                    "bootstrap_only",
                    "Signed gateway authentication is required for this operation. Re-register or rotate credentials first.",
                )
            self._raise_auth_error("missing_headers", "Missing required signed-gateway authentication headers.")

        if not all([provided_gateway_id, provided_version, provided_timestamp, provided_nonce, provided_signature]):
            self._raise_auth_error("missing_headers", "Missing required signed-gateway authentication headers.")

        try:
            key_version = int(provided_version)
            timestamp_value = int(provided_timestamp)
        except ValueError:
            self._raise_auth_error("invalid_header_format", "Invalid gateway authentication header format.")

        now = int(datetime.now(timezone.utc).timestamp())
        if abs(now - timestamp_value) > max(int(settings.AGENT_MAX_CLOCK_SKEW_SECONDS), 1):
            self._raise_auth_error("clock_skew", "Gateway request timestamp outside permitted skew.")

        if self._nonce_seen(
            db_conn,
            gateway_id=provided_gateway_id,
            key_version=key_version,
            nonce=provided_nonce,
        ):
            self._raise_auth_error("replay", "Replay detected for gateway request nonce.")

        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT gateway_id, key_version, secret_salt, status
                FROM gateway_credentials
                WHERE gateway_id = %s AND key_version = %s
                LIMIT 1
                """,
                (provided_gateway_id, key_version),
            )
            row = cursor.fetchone()
            if not row:
                self._raise_auth_error("unknown_credential", "Unknown gateway credential.")
            if str(row.get("status") or "") not in {"active", "rotating"}:
                self._raise_auth_error("inactive_credential", "Gateway credential is not active.")
            secret = self._derive_secret(
                gateway_id=provided_gateway_id,
                key_version=key_version,
                secret_salt=str(row.get("secret_salt") or ""),
            )
            path = request.url.path
            if request.url.query:
                path = f"{path}?{request.url.query}"
            if not verify_signature(
                secret=secret,
                provided_signature=provided_signature,
                method=request.method,
                path=path,
                timestamp=provided_timestamp,
                nonce=provided_nonce,
                body=body,
            ):
                self._raise_auth_error("invalid_signature", "Invalid gateway request signature.")
            cursor.execute(
                """
                UPDATE gateway_credentials
                SET last_used_at = UTC_TIMESTAMP()
                WHERE gateway_id = %s AND key_version = %s
                """,
                (provided_gateway_id, key_version),
            )
        finally:
            cursor.close()

        metrics_service.increment("gateway_auth_success_total", mode="signed")

        return {
            "auth_mode": "signed",
            "gateway_id": provided_gateway_id,
            "key_version": key_version,
        }


gateway_auth_service = GatewayAuthService()
