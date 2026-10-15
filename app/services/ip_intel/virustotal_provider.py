"""
VirusTotal v3 IP Intelligence Provider Adapter
Queries VirusTotal v3 IP address endpoint for malicious engine detections and reputation.
WISP Network & Data Solutions (WISPnet)
"""
import httpx
import logging
import time
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

logger = logging.getLogger(__name__)

class VirusTotalProvider(BaseReputationProvider):
    """Adapter for VirusTotal v3 API"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.api_endpoint = (config.get("api_endpoint") or "https://www.virustotal.com/api/v3/ip_addresses/").rstrip("/")
        self.api_key = config.get("api_key")

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
                error_type="SPECIAL_IP_RANGE",
                documentation_url=self.documentation_url
            )

        if not self.api_key:
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="unsupported",
                duration_ms=0.0,
                is_listed=False,
                risk_status=ReputationStatus.UNKNOWN,
                evidence_summary="VirusTotal API key not configured. Enter a valid API key in Provider Management.",
                error_type="API_KEY_MISSING",
                documentation_url=self.documentation_url
            )

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        url = f"{self.api_endpoint}/{ip_str}"

        start_time = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                res = await client.get(url, headers=headers)
                duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

                if res.status_code == 200:
                    payload = res.json().get("data", {}).get("attributes", {})
                    stats = payload.get("last_analysis_stats", {})
                    malicious = int(stats.get("malicious", 0))
                    suspicious = int(stats.get("suspicious", 0))
                    harmless = int(stats.get("harmless", 0))
                    undetected = int(stats.get("undetected", 0))
                    reputation = int(payload.get("reputation", 0))
                    as_owner = payload.get("as_owner", "Unknown AS")

                    is_listed = malicious > 0 or suspicious >= 3
                    if malicious >= 3:
                        risk = ReputationStatus.HIGH_RISK
                        cat = ListingCategory.BOTNET_C2
                    elif malicious > 0 or suspicious >= 2:
                        risk = ReputationStatus.SUSPICIOUS
                        cat = ListingCategory.MALICIOUS_SCAN
                    else:
                        risk = ReputationStatus.CLEAN
                        cat = ListingCategory.NONE

                    evidence = f"Detections: {malicious} security vendors flagged as malicious, {suspicious} suspicious. AS: {as_owner}."

                    return ProviderResult(
                        provider_id=self.provider_id,
                        provider_name=self.provider_name,
                        provider_type=self.provider_type,
                        queried_ip=ip_str,
                        check_timestamp=now,
                        lookup_status="completed",
                        duration_ms=duration_ms,
                        is_listed=is_listed,
                        listing_category=cat,
                        source_classification=f"VT Detections: {malicious} malicious / {suspicious} suspicious",
                        source_score=float(malicious * 20),
                        risk_status=risk,
                        evidence_summary=evidence,
                        raw_reference={"stats": stats, "reputation": reputation, "as_owner": as_owner},
                        documentation_url=self.documentation_url
                    )

                elif res.status_code == 429:
                    return ProviderResult(
                        provider_id=self.provider_id,
                        provider_name=self.provider_name,
                        provider_type=self.provider_type,
                        queried_ip=ip_str,
                        check_timestamp=now,
                        lookup_status="rate_limited",
                        duration_ms=duration_ms,
                        is_listed=False,
                        risk_status=ReputationStatus.INCOMPLETE,
                        evidence_summary="VirusTotal quota exceeded (HTTP 429).",
                        error_type="RATE_LIMITED",
                        documentation_url=self.documentation_url
                    )
                elif res.status_code in (401, 403):
                    return ProviderResult(
                        provider_id=self.provider_id,
                        provider_name=self.provider_name,
                        provider_type=self.provider_type,
                        queried_ip=ip_str,
                        check_timestamp=now,
                        lookup_status="failed",
                        duration_ms=duration_ms,
                        is_listed=False,
                        risk_status=ReputationStatus.INCOMPLETE,
                        evidence_summary="VirusTotal API key rejected (HTTP 401/403).",
                        error_type="AUTH_FAILED",
                        documentation_url=self.documentation_url
                    )
                elif res.status_code == 404:
                    return ProviderResult(
                        provider_id=self.provider_id,
                        provider_name=self.provider_name,
                        provider_type=self.provider_type,
                        queried_ip=ip_str,
                        check_timestamp=now,
                        lookup_status="completed",
                        duration_ms=duration_ms,
                        is_listed=False,
                        listing_category=ListingCategory.NONE,
                        risk_status=ReputationStatus.CLEAN,
                        evidence_summary="IP not found in VirusTotal database (no detections recorded).",
                        documentation_url=self.documentation_url
                    )
                else:
                    return ProviderResult(
                        provider_id=self.provider_id,
                        provider_name=self.provider_name,
                        provider_type=self.provider_type,
                        queried_ip=ip_str,
                        check_timestamp=now,
                        lookup_status="failed",
                        duration_ms=duration_ms,
                        is_listed=False,
                        risk_status=ReputationStatus.INCOMPLETE,
                        evidence_summary=f"VirusTotal returned HTTP {res.status_code}",
                        error_type=f"HTTP_{res.status_code}",
                        documentation_url=self.documentation_url
                    )
        except httpx.TimeoutException:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="timeout",
                duration_ms=duration_ms,
                is_listed=False,
                risk_status=ReputationStatus.INCOMPLETE,
                evidence_summary=f"VirusTotal query timed out after {self.timeout_seconds}s.",
                error_type="TIMEOUT",
                documentation_url=self.documentation_url
            )
        except Exception as e:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.provider_name,
                provider_type=self.provider_type,
                queried_ip=ip_str,
                check_timestamp=now,
                lookup_status="failed",
                duration_ms=duration_ms,
                is_listed=False,
                risk_status=ReputationStatus.INCOMPLETE,
                evidence_summary=f"VirusTotal error: {str(e)}",
                error_type="CONNECTION_ERROR",
                error_message=str(e),
                documentation_url=self.documentation_url
            )

    async def health_check(self) -> Dict[str, Any]:
        if not self.api_key:
            return {
                "online": False,
                "provider_id": self.provider_id,
                "status": "awaiting_credentials",
                "message": "API key not configured"
            }
        res = await self.check_ip("8.8.8.8", depth="standard")
        return {
            "online": res.lookup_status in ("completed", "rate_limited"),
            "provider_id": self.provider_id,
            "status": "healthy" if res.lookup_status == "completed" else res.lookup_status,
            "latency_ms": res.duration_ms
        }
