"""Compatibility shim for shared service/domain intelligence helpers."""

from shared.intel.domain_intelligence import classify_domain, get_service_info, is_noise, is_sensitive_destination

__all__ = ["classify_domain", "get_service_info", "is_noise", "is_sensitive_destination"]
