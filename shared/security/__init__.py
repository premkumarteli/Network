"""Shared transport security helpers."""

from .agent_auth import (
    AGENT_ID_HEADER,
    GATEWAY_BOOTSTRAP_KEY_HEADER,
    GATEWAY_ID_HEADER,
    KEY_VERSION_HEADER,
    LEGACY_API_KEY_HEADER,
    NONCE_HEADER,
    REENROLL_REQUEST_HEADER,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    body_sha256_hex,
    canonical_path,
    sign_request,
    signature_message,
    verify_signature,
)

__all__ = [
    "AGENT_ID_HEADER",
    "GATEWAY_BOOTSTRAP_KEY_HEADER",
    "GATEWAY_ID_HEADER",
    "KEY_VERSION_HEADER",
    "LEGACY_API_KEY_HEADER",
    "NONCE_HEADER",
    "REENROLL_REQUEST_HEADER",
    "SIGNATURE_HEADER",
    "TIMESTAMP_HEADER",
    "body_sha256_hex",
    "canonical_path",
    "sign_request",
    "signature_message",
    "verify_signature",
]
