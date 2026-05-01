from __future__ import annotations

import ipaddress
import os
import hashlib
import json
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from shared.security import (
    GATEWAY_BOOTSTRAP_KEY_HEADER,
    GATEWAY_ID_HEADER,
    KEY_VERSION_HEADER,
    NONCE_HEADER,
    REENROLL_REQUEST_HEADER,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    sign_request,
)

from .state import GatewayStateStore


class GatewayApiClient:
    def __init__(
        self,
        *,
        state_path: Path,
        bootstrap_api_key: str,
        store: GatewayStateStore | None = None,
        initial_pins: list[dict] | None = None,
    ) -> None:
        self.session = requests.Session()
        self.bootstrap_api_key = str(bootstrap_api_key or "")
        self.allow_lan_http = str(os.getenv("NETVISOR_ALLOW_LAN_HTTP", "false")).strip().lower() in {"1", "true", "yes", "on"}
        self.store = store or GatewayStateStore(
            state_path,
            description="netvisor-gateway-transport-state",
        )
        self._state = self.store.load(
            {
                "gateway_credentials": None,
                "backend_tls_pins": list(initial_pins or []),
            }
        )
        if initial_pins and not self._state.get("backend_tls_pins"):
            self._state["backend_tls_pins"] = list(initial_pins)
            self._persist()

    def _persist(self) -> None:
        self.store.save(self._state)

    def seed_pins(self, pins: list[dict] | None) -> None:
        if not pins:
            return
        self._state["backend_tls_pins"] = list(pins)
        self._persist()

    def _credentials(self) -> dict | None:
        credentials = self._state.get("gateway_credentials")
        return credentials if isinstance(credentials, dict) else None

    def has_credentials(self) -> bool:
        credentials = self._credentials()
        return bool(credentials and credentials.get("secret"))

    def status_snapshot(self) -> dict:
        credentials = self._credentials() or {}
        return {
            "bootstrap_api_key_configured": bool(self.bootstrap_api_key),
            "has_credentials": self.has_credentials(),
            "credential_gateway_id": credentials.get("gateway_id"),
            "credential_key_version": credentials.get("key_version"),
            "backend_tls_pin_count": len(self._pinset()),
            "state_path": str(self.store.path),
        }

    def reset_enrollment(self, *, preserve_pins: bool = True) -> None:
        self._state["gateway_credentials"] = None
        if not preserve_pins:
            self._state["backend_tls_pins"] = []
        self._persist()

    def _pinset(self) -> list[dict]:
        pins = self._state.get("backend_tls_pins")
        return list(pins) if isinstance(pins, list) else []

    def _is_local_url(self, url: str) -> bool:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").strip().lower()
        return hostname in {"127.0.0.1", "localhost", "::1"}

    def _is_private_lan_url(self, url: str) -> bool:
        if not self.allow_lan_http:
            return False
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").strip().lower()
        if not hostname:
            return False
        try:
            return ipaddress.ip_address(hostname).is_private
        except ValueError:
            return False

    def _enforce_transport_policy(self, url: str) -> None:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if self._is_local_url(url):
            return
        if scheme != "https" and self._is_private_lan_url(url):
            return
        if scheme != "https":
            raise requests.exceptions.SSLError("Remote backend connections must use HTTPS.")
        if not self._pinset():
            raise requests.exceptions.SSLError(
                "Remote backend connections require configured TLS pins before first contact."
            )

    def bootstrap_post(
        self,
        url: str,
        *,
        json_body: Any,
        timeout: float = 10.0,
        reenroll: bool = False,
    ) -> requests.Response:
        self._enforce_transport_policy(url)
        headers = {GATEWAY_BOOTSTRAP_KEY_HEADER: self.bootstrap_api_key}
        if reenroll:
            headers[REENROLL_REQUEST_HEADER] = "1"
        response = self.session.post(url, json=json_body, headers=headers, timeout=timeout, stream=True)
        self._enforce_tls_pins(url, response)
        response.content
        self._consume_security_metadata(response)
        return response

    def request(
        self,
        method: str,
        url: str,
        *,
        json_body: Any = None,
        params: dict | None = None,
        timeout: float = 10.0,
    ) -> requests.Response:
        body_bytes = b""
        headers: dict[str, str] = {}
        if json_body is not None:
            body_bytes = json.dumps(json_body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"

        credentials = self._credentials()
        if credentials:
            timestamp = str(int(time.time()))
            nonce = uuid.uuid4().hex
            request_obj = requests.Request(
                method=method.upper(),
                url=url,
                params=params,
                data=body_bytes or None,
                headers=headers,
            )
            prepared = self.session.prepare_request(request_obj)
            signature = sign_request(
                secret=str(credentials.get("secret") or ""),
                method=prepared.method or method,
                path=prepared.path_url or "/",
                timestamp=timestamp,
                nonce=nonce,
                body=body_bytes,
            )
            prepared.headers[GATEWAY_ID_HEADER] = str(credentials.get("gateway_id") or "")
            prepared.headers[KEY_VERSION_HEADER] = str(credentials.get("key_version") or "")
            prepared.headers[TIMESTAMP_HEADER] = timestamp
            prepared.headers[NONCE_HEADER] = nonce
            prepared.headers[SIGNATURE_HEADER] = signature
        else:
            prepared = self.session.prepare_request(
                requests.Request(
                    method=method.upper(),
                    url=url,
                    params=params,
                    data=body_bytes or None,
                    headers={**headers, GATEWAY_BOOTSTRAP_KEY_HEADER: self.bootstrap_api_key},
                )
            )

        self._enforce_transport_policy(prepared.url or url)
        response = self.session.send(prepared, timeout=timeout, stream=True)
        self._enforce_tls_pins(prepared.url or url, response)
        response.content
        self._consume_security_metadata(response)
        return response

    def _consume_security_metadata(self, response: requests.Response) -> None:
        content_type = str(response.headers.get("Content-Type") or "").lower()
        if "json" not in content_type:
            return
        try:
            payload = response.json()
        except ValueError:
            return
        if not isinstance(payload, dict):
            return

        credentials = payload.get("gateway_credentials")
        if isinstance(credentials, dict) and credentials.get("secret"):
            self._state["gateway_credentials"] = {
                "gateway_id": str(credentials.get("gateway_id") or ""),
                "key_version": int(credentials.get("key_version") or 1),
                "secret": str(credentials.get("secret") or ""),
                "issued_at": credentials.get("issued_at"),
            }
        pins = payload.get("backend_tls_pins")
        if isinstance(pins, list):
            self._state["backend_tls_pins"] = pins
        if isinstance(credentials, dict) or isinstance(pins, list):
            self._persist()

    def _extract_peer_certificate(self, response: requests.Response) -> bytes | None:
        connection = getattr(response.raw, "connection", None) or getattr(response.raw, "_connection", None)
        sock = getattr(connection, "sock", None)
        if sock is None:
            return None
        try:
            return sock.getpeercert(binary_form=True)
        except Exception:
            return None

    def _pin_fingerprint(self, pin_type: str, certificate_der: bytes) -> str:
        if pin_type == "cert_sha256":
            return hashlib.sha256(certificate_der).hexdigest().upper()
        certificate = x509.load_der_x509_certificate(certificate_der)
        public_key_bytes = certificate.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(public_key_bytes).hexdigest().upper()

    def _enforce_tls_pins(self, url: str, response: requests.Response) -> None:
        parsed = urlparse(url)
        if parsed.scheme.lower() != "https":
            return
        pinset = [pin for pin in self._pinset() if str(pin.get("status") or "active") in {"active", "next"}]
        if not pinset:
            return
        certificate_der = self._extract_peer_certificate(response)
        if not certificate_der:
            response.close()
            raise requests.exceptions.SSLError("Backend TLS certificate could not be inspected for pinning.")
        matched = False
        for pin in pinset:
            expected = str(pin.get("pin_sha256") or "").upper()
            if not expected:
                continue
            actual = self._pin_fingerprint(str(pin.get("pin_type") or "spki_sha256"), certificate_der)
            if actual == expected:
                matched = True
                break
        if not matched:
            response.close()
            raise requests.exceptions.SSLError("Backend TLS pin mismatch.")
