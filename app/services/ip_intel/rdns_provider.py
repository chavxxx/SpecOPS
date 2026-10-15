"""
Reverse DNS & Forward-Confirmed Reverse DNS (FCrDNS) Validator
Verifies PTR records, FCrDNS parity, and dynamic consumer pool patterns for email reputation.
WISP Network & Data Solutions (WISPnet)
"""
import os
import re
import ipaddress
import logging
from typing import Dict, Any, Optional

from app.models.ip_intel_schemas import (
    ProviderResult,
    ProviderType,
    ListingCategory,
    ReputationStatus
)
from app.services.ip_intel.base import (
    BaseReputationProvider,
    get_utc_now_iso,
    is_private_or_special_ip
)
from app.services.ip_intel.dns_resolver import async_query_dns

logger = logging.getLogger(__name__)

DYNAMIC_HOST_PATTERNS = [
    re.compile(r"(dynamic|dyn|pool|dhcp|ppp|cgnat|broadband|dsl|dial|res|client|customer|cust)[-._0-9]", re.IGNORECASE),
    re.compile(r"\b[0-9]{1,3}[-._][0-9]{1,3}[-._][0-9]{1,3}[-._][0-9]{1,3}\b")
]

class ReverseDNSProvider(BaseReputationProvider):
    """Performs real PTR and Forward-Confirmed Reverse DNS validation"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.nameserver = os.getenv("DNSBL_NAMESERVER", "8.8.8.8")

    async def check_ip(self, ip_str: str, depth: str = "standard") -> ProviderResult:
        now = get_utc_now_iso()

        is_special, reason = is_private_or_special_ip(ip_str)
        if is_special:
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="unsupported",
                duration_ms=0.0,
                is_listed=False,
                listing_category=ListingCategory.NONE,
                risk_status=ReputationStatus.UNKNOWN,
                evidence_summary=f"Special IP address: {reason}",
                documentation_url=self.documentation_url
            )

        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="failed",
                duration_ms=0.0,
                is_listed=False,
                risk_status=ReputationStatus.INCOMPLETE,
                evidence_summary="Malformed IP address",
                documentation_url=self.documentation_url
            )

        # 1. Reverse PTR lookup
        ptr_name = ip_obj.reverse_pointer
        res_ptr = await async_query_dns(
            ptr_name,
            qtype_str="PTR",
            nameserver=self.nameserver,
            timeout=self.timeout_seconds
        )

        if res_ptr.status == "TIMEOUT":
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="timeout",
                duration_ms=res_ptr.duration_ms,
                is_listed=False,
                risk_status=ReputationStatus.INCOMPLETE,
                evidence_summary=f"PTR lookup timed out after {self.timeout_seconds}s.",
                error_type="TIMEOUT",
                documentation_url=self.documentation_url
            )

        if not res_ptr.answers:
            # Missing PTR record -> Significant email deliverability defect
            evidence = f"No Reverse DNS (PTR) record found for {ip_str}. Direct-to-MX mail delivery will likely be rejected by standard mail servers (RFC 1912)."
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="completed",
                duration_ms=res_ptr.duration_ms,
                is_listed=True,
                listing_category=ListingCategory.DELIVERABILITY,
                source_classification="Missing PTR Record (RFC 1912 non-compliant)",
                source_score=35.0,
                risk_status=ReputationStatus.SUSPICIOUS,
                evidence_summary=evidence,
                raw_reference={"ptr_query": ptr_name, "rcode": res_ptr.rcode},
                documentation_url=self.documentation_url
            )

        hostname = res_ptr.answers[0].rstrip(".")
        total_duration = res_ptr.duration_ms

        # 2. Forward DNS check (FCrDNS validation)
        qtype = "A" if ip_obj.version == 4 else "AAAA"
        res_fwd = await async_query_dns(
            hostname,
            qtype_str=qtype,
            nameserver=self.nameserver,
            timeout=self.timeout_seconds
        )
        total_duration += res_fwd.duration_ms

        fcrdns_valid = ip_str in res_fwd.answers
        is_dynamic = any(p.search(hostname) for p in DYNAMIC_HOST_PATTERNS)

        if not fcrdns_valid:
            evidence = f"Forward-Confirmed Reverse DNS (FCrDNS) Mismatch: PTR '{hostname}' resolves to {res_fwd.answers or 'NXDOMAIN'}, not {ip_str}."
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="completed",
                duration_ms=total_duration,
                is_listed=True,
                listing_category=ListingCategory.DELIVERABILITY,
                source_classification="FCrDNS Mismatch",
                source_score=30.0,
                risk_status=ReputationStatus.SUSPICIOUS,
                evidence_summary=evidence,
                raw_reference={"hostname": hostname, "forward_ips": res_fwd.answers},
                documentation_url=self.documentation_url
            )

        if is_dynamic:
            evidence = f"Valid FCrDNS to '{hostname}', but hostname matches generic consumer/dynamic pool pattern. Recommended to route outbound email via authenticated smart host."
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="completed",
                duration_ms=total_duration,
                is_listed=False,
                listing_category=ListingCategory.DELIVERABILITY,
                source_classification="Dynamic Pool Hostname Pattern",
                source_score=15.0,
                risk_status=ReputationStatus.CLEAN,
                evidence_summary=evidence,
                raw_reference={"hostname": hostname, "is_dynamic": True},
                documentation_url=self.documentation_url
            )

        # Fully valid static FCrDNS
        return ProviderResult(
            provider_id=self.provider_id,
            provider_name=self.provider_name,
            provider_type=self.provider_type,
            queried_ip=ip_str,
            check_timestamp=now,
            lookup_status="completed",
            duration_ms=total_duration,
            is_listed=False,
            listing_category=ListingCategory.NONE,
            source_classification=f"Verified FCrDNS ({hostname})",
            source_score=0.0,
            risk_status=ReputationStatus.CLEAN,
            evidence_summary=f"Verified Forward-Confirmed Reverse DNS (FCrDNS): {ip_str} <-> {hostname}.",
            raw_reference={"hostname": hostname, "fcrdns": True},
            documentation_url=self.documentation_url
        )

    async def health_check(self) -> Dict[str, Any]:
        res = await async_query_dns("8.8.8.8.in-addr.arpa", "PTR", nameserver=self.nameserver, timeout=3.0)
        return {
            "online": res.status == "NOERROR" and "dns.google" in res.answers,
            "provider_id": self.provider_id,
            "status": "healthy" if res.status == "NOERROR" else "degraded",
            "latency_ms": res.duration_ms
        }
