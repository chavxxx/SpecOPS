"""
DNS-Based Blacklist (DNSBL) Provider Adapter
Supports Spamhaus (ZEN/DBL), SpamCop, Barracuda, and custom DNSBL zones.
WISP Network & Data Solutions (WISPnet)
"""
import os
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
    format_dnsbl_query,
    get_utc_now_iso,
    is_private_or_special_ip
)
from app.services.ip_intel.dns_resolver import async_query_dns

logger = logging.getLogger(__name__)

class DNSBLProvider(BaseReputationProvider):
    """Adapter for querying DNSBL zones with protocol-accurate return code parsing"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.dns_zone = (config.get("dns_zone") or "").strip()
        self.nameserver = os.getenv("DNSBL_NAMESERVER", "8.8.8.8")

    async def check_ip(self, ip_str: str, depth: str = "standard") -> ProviderResult:
        now = get_utc_now_iso()
        
        # Check special/private IP addresses
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
                evidence_summary=f"Excluded from public DNSBL: {reason}",
                error_type="SPECIAL_IP_RANGE",
                documentation_url=self.documentation_url
            )

        if not self.dns_zone:
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
                evidence_summary="DNSBL zone not configured",
                error_type="ZONE_NOT_CONFIGURED",
                documentation_url=self.documentation_url
            )

        query_name = format_dnsbl_query(ip_str, self.dns_zone)
        
        # 1. Query A Record
        res = await async_query_dns(
            query_name,
            qtype_str="A",
            nameserver=self.nameserver,
            timeout=self.timeout_seconds
        )

        # 2. Parse response semantics based on provider
        if self.provider_id == "spamhaus_zen":
            return await self._parse_spamhaus(ip_str, res, query_name, now)
        elif self.provider_id == "spamcop":
            return await self._parse_spamcop(ip_str, res, query_name, now)
        elif self.provider_id == "barracuda":
            return await self._parse_barracuda(ip_str, res, query_name, now)
        else:
            return await self._parse_generic_dnsbl(ip_str, res, query_name, now)

    async def _parse_spamhaus(
        self,
        ip_str: str,
        res: Any,
        query_name: str,
        now: str
    ) -> ProviderResult:
        """
        Parses Spamhaus ZEN return codes:
        127.0.0.2 = SBL (Spam)
        127.0.0.3 = CSS (Snowshoe spam)
        127.0.0.4-7 = XBL/CBL (Exploits, Botnets, Malware)
        127.0.0.10-11 = PBL (Policy Block List - dynamic end-user ranges)
        127.255.255.252-255 = Blocked query / open resolver
        """
        if res.status == "NXDOMAIN":
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="completed",
                duration_ms=res.duration_ms,
                is_listed=False,
                listing_category=ListingCategory.NONE,
                risk_status=ReputationStatus.CLEAN,
                evidence_summary="Not listed in Spamhaus ZEN (NXDOMAIN)",
                raw_reference={"rcode": res.rcode, "resolver": res.nameserver},
                documentation_url=self.documentation_url
            )

        if res.status == "TIMEOUT":
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="timeout",
                duration_ms=res.duration_ms,
                is_listed=False,
                risk_status=ReputationStatus.INCOMPLETE,
                evidence_summary=f"DNS query timed out after {self.timeout_seconds}s via resolver {res.nameserver}",
                error_type="DNS_TIMEOUT",
                documentation_url=self.documentation_url
            )

        if res.status in ("REFUSED", "SERVFAIL", "ERROR"):
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="failed",
                duration_ms=res.duration_ms,
                is_listed=False,
                risk_status=ReputationStatus.INCOMPLETE,
                evidence_summary=f"DNS error {res.status} returned by resolver {res.nameserver}",
                error_type=f"DNS_{res.status}",
                documentation_url=self.documentation_url
            )

        # Inspect returned A records
        answers = res.answers
        is_blocked = any(a.startswith("127.255.255.") for a in answers)
        if is_blocked:
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="blocked",
                duration_ms=res.duration_ms,
                is_listed=False,
                risk_status=ReputationStatus.INCOMPLETE,
                evidence_summary="Spamhaus query blocked: Public open resolver detected (return code 127.255.255.x). Direct recursive resolver or DQS key required.",
                error_type="SPAMHAUS_QUERY_BLOCKED",
                raw_reference={"answers": answers, "resolver": res.nameserver},
                documentation_url=self.documentation_url
            )

        # Determine sublist classifications
        classifications = []
        highest_cat = ListingCategory.SPAM
        risk_status = ReputationStatus.LISTED
        score = 60.0

        for a in answers:
            if a == "127.0.0.2":
                classifications.append("SBL (Direct Spam Source)")
                highest_cat = ListingCategory.SPAM
                score = max(score, 75.0)
            elif a == "127.0.0.3":
                classifications.append("CSS (Snowshoe Spam)")
                highest_cat = ListingCategory.SPAM
                score = max(score, 70.0)
            elif a in ("127.0.0.4", "127.0.0.5", "127.0.0.6", "127.0.0.7"):
                classifications.append("XBL/CBL (Malware / Exploit / Botnet C2)")
                highest_cat = ListingCategory.BOTNET_C2
                risk_status = ReputationStatus.HIGH_RISK
                score = max(score, 90.0)
            elif a in ("127.0.0.10", "127.0.0.11"):
                classifications.append("PBL (ISP End-User Dynamic Port Block)")
                if highest_cat == ListingCategory.NONE:
                    highest_cat = ListingCategory.DELIVERABILITY
                score = max(score, 30.0)

        evidence = f"Listed in Spamhaus ZEN: {', '.join(classifications)} [{', '.join(answers)}]"
        
        return ProviderResult(
            provider_id=self.provider_id,
            provider_name=self.provider_name,
            provider_type=self.provider_type,
            queried_ip=ip_str,
            check_timestamp=now,
            lookup_status="completed",
            duration_ms=res.duration_ms,
            is_listed=True,
            listing_category=highest_cat,
            source_classification=", ".join(classifications),
            source_score=score,
            risk_status=risk_status,
            evidence_summary=evidence,
            raw_reference={"answers": answers, "query": query_name},
            documentation_url=self.documentation_url
        )

    async def _parse_spamcop(
        self,
        ip_str: str,
        res: Any,
        query_name: str,
        now: str
    ) -> ProviderResult:
        if res.status == "NXDOMAIN":
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="completed",
                duration_ms=res.duration_ms,
                is_listed=False,
                listing_category=ListingCategory.NONE,
                risk_status=ReputationStatus.CLEAN,
                evidence_summary="Not listed in SpamCop (NXDOMAIN)",
                documentation_url=self.documentation_url
            )
        elif res.status == "NOERROR" and "127.0.0.2" in res.answers:
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="completed",
                duration_ms=res.duration_ms,
                is_listed=True,
                listing_category=ListingCategory.SPAM,
                source_classification="SpamCop Active Blocklist (Reported spam source)",
                source_score=80.0,
                risk_status=ReputationStatus.LISTED,
                evidence_summary=f"Listed in SpamCop BL (IP reported for sending spam within past 48h) [{', '.join(res.answers)}]",
                raw_reference={"answers": res.answers},
                documentation_url=self.documentation_url
            )
        else:
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="failed" if res.status != "TIMEOUT" else "timeout",
                duration_ms=res.duration_ms,
                is_listed=False,
                risk_status=ReputationStatus.INCOMPLETE,
                evidence_summary=f"SpamCop lookup status: {res.status}",
                error_type=res.status,
                documentation_url=self.documentation_url
            )

    async def _parse_barracuda(
        self,
        ip_str: str,
        res: Any,
        query_name: str,
        now: str
    ) -> ProviderResult:
        if res.status == "NXDOMAIN":
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="completed",
                duration_ms=res.duration_ms,
                is_listed=False,
                listing_category=ListingCategory.NONE,
                risk_status=ReputationStatus.CLEAN,
                evidence_summary="Not listed in Barracuda BRBL (NXDOMAIN)",
                documentation_url=self.documentation_url
            )
        elif res.status == "NOERROR" and "127.0.0.2" in res.answers:
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="completed",
                duration_ms=res.duration_ms,
                is_listed=True,
                listing_category=ListingCategory.SPAM,
                source_classification="Barracuda Reputation Block List (BRBL)",
                source_score=75.0,
                risk_status=ReputationStatus.LISTED,
                evidence_summary=f"Listed in Barracuda BRBL [{', '.join(res.answers)}]",
                raw_reference={"answers": res.answers},
                documentation_url=self.documentation_url
            )
        else:
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="failed" if res.status != "TIMEOUT" else "timeout",
                duration_ms=res.duration_ms,
                is_listed=False,
                risk_status=ReputationStatus.INCOMPLETE,
                evidence_summary=f"Barracuda lookup status: {res.status}",
                error_type=res.status,
                documentation_url=self.documentation_url
            )

    async def _parse_generic_dnsbl(
        self,
        ip_str: str,
        res: Any,
        query_name: str,
        now: str
    ) -> ProviderResult:
        if res.status == "NXDOMAIN":
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="completed",
                duration_ms=res.duration_ms,
                is_listed=False,
                listing_category=ListingCategory.NONE,
                risk_status=ReputationStatus.CLEAN,
                evidence_summary=f"Not listed in {self.dns_zone} (NXDOMAIN)",
                documentation_url=self.documentation_url
            )
        elif res.status == "NOERROR" and res.answers:
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="completed",
                duration_ms=res.duration_ms,
                is_listed=True,
                listing_category=ListingCategory.SPAM,
                source_classification="DNSBL Active Listing",
                source_score=70.0,
                risk_status=ReputationStatus.LISTED,
                evidence_summary=f"Listed in {self.dns_zone} [{', '.join(res.answers)}]",
                raw_reference={"answers": res.answers},
                documentation_url=self.documentation_url
            )
        else:
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="failed" if res.status != "TIMEOUT" else "timeout",
                duration_ms=res.duration_ms,
                is_listed=False,
                risk_status=ReputationStatus.INCOMPLETE,
                evidence_summary=f"DNSBL query failed: {res.status}",
                error_type=res.status,
                documentation_url=self.documentation_url
            )

    async def health_check(self) -> Dict[str, Any]:
        """Tests DNSBL responsiveness using loopback test query"""
        # Test query to loopback zone or standard name
        res = await async_query_dns("one.one.one.one", "A", nameserver=self.nameserver, timeout=3.0)
        return {
            "online": res.status == "NOERROR",
            "provider_id": self.provider_id,
            "dns_zone": self.dns_zone,
            "nameserver": self.nameserver,
            "latency_ms": res.duration_ms,
            "status": "healthy" if res.status == "NOERROR" else "degraded"
        }
