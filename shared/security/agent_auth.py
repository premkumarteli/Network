from __future__ import annotations

import hashlib
import hmac
from urllib.parse import urlencode


AGENT_ID_HEADER = "X-Agent-Id"
GATEWAY_ID_HEADER = "X-Gateway-Id"
KEY_VERSION_HEADER = "X-NetVisor-Key-Version"
TIMESTAMP_HEADER = "X-NetVisor-Timestamp"
NONCE_HEADER = "X-NetVisor-Nonce"
SIGNATURE_HEADER = "X-NetVisor-Signature"
LEGACY_API_KEY_HEADER = "X-API-Key"
GATEWAY_BOOTSTRAP_KEY_HEADER = "X-Gateway-Key"
REENROLL_REQUEST_HEADER = "X-NetVisor-Reenroll"


def canonical_path(path: str, query_params: dict | None = None) -> str:
    normalized_path = path or "/"
    if not query_params:
        return normalized_path
    encoded = urlencode(query_params, doseq=True)
    return f"{normalized_path}?{encoded}" if encoded else normalized_path


def body_sha256_hex(body: bytes | str | None) -> str:
    if body is None:
        payload = b""
    elif isinstance(body, bytes):
        payload = body
    else:
        payload = body.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def signature_message(
    *,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body_digest: str,
) -> bytes:
    return "\n".join(
        [
            str(method or "GET").upper(),
            path or "/",
            str(timestamp or ""),
            str(nonce or ""),
            str(body_digest or ""),
        ]
    ).encode("utf-8")


def sign_request(
    *,
    secret: str | bytes,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes | str | None,
) -> str:
    secret_bytes = secret if isinstance(secret, bytes) else secret.encode("utf-8")
    body_digest = body_sha256_hex(body)
    message = signature_message(
        method=method,
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        body_digest=body_digest,
    )
    return hmac.new(secret_bytes, message, hashlib.sha256).hexdigest()


def verify_signature(
    *,
    secret: str | bytes,
    provided_signature: str,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes | str | None,
) -> bool:
    expected = sign_request(
        secret=secret,
        method=method,
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
    )
    return hmac.compare_digest(expected, str(provided_signature or ""))
