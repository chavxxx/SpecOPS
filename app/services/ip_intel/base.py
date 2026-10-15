"""
Base Classes and Helper Functions for IP Reputation Providers
WISP Network & Data Solutions (WISPnet)
"""
import ipaddress
import time
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timezone

from app.models.ip_intel_schemas import (
    ProviderResult,
    ProviderType,
    ListingCategory,
    ReputationStatus
)

def get_utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def is_valid_ip(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False

def get_ip_version(ip_str: str) -> int:
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.version
    except ValueError:
        return 4

def is_private_or_special_ip(ip_str: str) -> Tuple[bool, str]:
    """
    Checks if an IP address is private, loopback, link-local, multicast, or documentation.
    Returns (is_special, reason).
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if ip.is_loopback:
            return True, "Loopback address (127.0.0.0/8 or ::1)"
        if ip.is_private:
            return True, "Private address (RFC 1918 / ULA)"
        if ip.is_link_local:
            return True, "Link-local address (169.254.0.0/16 or fe80::/10)"
        if ip.is_multicast:
            return True, "Multicast address"
        if ip.is_unspecified:
            return True, "Unspecified address (0.0.0.0 or ::)"
        
        # CGNAT Shared address space RFC 6598 (100.64.0.0/10)
        if ip.version == 4:
            cgnat_net = ipaddress.IPv4Network("100.64.0.0/10")
            if ip in cgnat_net:
                return True, "CGNAT Shared Address Space (RFC 6598 100.64.0.0/10)"
            
            # Documentation test networks (RFC 5737)
            for doc_net in [
                ipaddress.IPv4Network("192.0.2.0/24"),
                ipaddress.IPv4Network("198.51.100.0/24"),
                ipaddress.IPv4Network("203.0.113.0/24")
            ]:
                if ip in doc_net:
                    return True, f"Documentation/Test network ({doc_net})"
        elif ip.version == 6:
            # Documentation IPv6 (RFC 3849)
            doc_v6 = ipaddress.IPv6Network("2001:db8::/32")
            if ip in doc_v6:
                return True, "Documentation IPv6 network (2001:db8::/32)"

        return False, "Public routable address"
    except ValueError:
        return True, "Malformed IP address"

def format_dnsbl_query(ip_str: str, zone: str) -> str:
    """
    Formats an IP into the reversed octet format for DNSBL queries.
    IPv4: 1.2.3.4 -> 4.3.2.1.zone
    IPv6: 2001:db8::1 -> 1.0.0...8.b.d.0.1.0.0.2.zone
    """
    ip = ipaddress.ip_address(ip_str.strip())
    zone = zone.strip().rstrip(".")
    if ip.version == 4:
        octets = ip.exploded.split(".")
        reversed_octets = ".".join(reversed(octets))
        return f"{reversed_octets}.{zone}"
    else:
        # Full 32-nibble expansion
        hex_str = ip.exploded.replace(":", "")
        reversed_nibbles = ".".join(reversed(hex_str))
        return f"{reversed_nibbles}.{zone}"

class BaseReputationProvider(ABC):
    """Abstract Base Class for all IP Reputation & Blacklist Intelligence Providers"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.provider_id: str = config.get("provider_id", "unknown")
        self.provider_name: str = config.get("provider_name", "Unknown Provider")
        self.provider_type: ProviderType = ProviderType(config.get("provider_type", "dnsbl"))
        self.enabled: bool = bool(config.get("enabled", True))
        self.timeout_seconds: float = float(config.get("timeout_seconds", 5.0))
        self.rate_limit_rpm: int = int(config.get("rate_limit_rpm", 60))
        self.max_concurrent: int = int(config.get("max_concurrent", 5))
        self.documentation_url: str = config.get("documentation_url", "")
        self.supported_indicators: List[str] = config.get("supported_indicators", ["ipv4"])

    @abstractmethod
    async def check_ip(self, ip_str: str, depth: str = "standard") -> ProviderResult:
        """Executes a real reputation check against the external provider"""
        pass

    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Validates provider connectivity, credentials, and API service availability"""
        pass

    def get_quota_status(self) -> Optional[Dict[str, Any]]:
        """Returns quota limit and remaining quota if tracked"""
        limit = self.config.get("quota_limit")
        remaining = self.config.get("quota_remaining")
        reset_at = self.config.get("quota_reset_at")
        if limit is not None:
            return {
                "limit": limit,
                "remaining": remaining,
                "reset_at": reset_at,
                "percentage_used": round((1.0 - (remaining or 0) / limit) * 100, 1) if limit > 0 else 0.0
            }
        return None

    def get_documentation_url(self) -> str:
        return self.documentation_url
