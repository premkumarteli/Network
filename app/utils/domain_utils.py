from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Optional

import tldextract


_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=False,
    fallback_to_snapshot=True,
)


def normalize_host(value: object) -> Optional[str]:
    if value is None:
        return None

    host = str(value).strip().lower().rstrip(".")
    if not host or host == "-" or " " in host:
        return None

    if "://" in host:
        host = host.split("://", 1)[1]

    host = host.split("/", 1)[0]
    if host.startswith("*."):
        host = host[2:]

    if ":" in host and "." in host:
        candidate, maybe_port = host.rsplit(":", 1)
        if maybe_port.isdigit():
            host = candidate

    return host or None


@lru_cache(maxsize=8192)
def get_base_domain(value: object) -> Optional[str]:
    host = normalize_host(value)
    if not host:
        return None

    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass

    try:
        extracted = _EXTRACTOR(host)
    except Exception:
        return None

    if not extracted.domain or not extracted.suffix:
        return None
    return f"{extracted.domain}.{extracted.suffix}"


__all__ = ["get_base_domain", "normalize_host", "_EXTRACTOR"]
