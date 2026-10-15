"""
GreyNoise IP Intelligence Provider Adapter
Queries GreyNoise Community API to detect mass internet scanning and malicious scanner activity.
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

class GreyNoiseProvider(BaseReputationProvider):
    """Adapter for GreyNoise Community & Enterprise API"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.api_endpoint = (config.get("api_endpoint") or "https://api.greynoise.io/v3/community/").rstrip("/")
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

        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["key"] = self.api_key

        url = f"{self.api_endpoint}/{ip_str}"
        start_time = time.perf_counter()

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                res = await client.get(url, headers=headers)
                duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

                if res.status_code == 200:
                    payload = res.json()
                    noise = bool(payload.get("noise", False))
                    riot = bool(payload.get("riot", False))
                    classification = (payload.get("classification") or "unknown").lower()
                    name = payload.get("name") or "Unknown Scanner"
                    last_seen = payload.get("last_seen")

                    if classification == "malicious":
                        risk = ReputationStatus.HIGH_RISK
                        cat = ListingCategory.MALICIOUS_SCAN
                        is_listed = True
                        score = 85.0
                        evidence = f"GreyNoise classified IP as MALICIOUS scanner: {name}. Last seen: {last_seen}."
                    elif classification == "benign":
                        risk = ReputationStatus.CLEAN
                        cat = ListingCategory.NONE
                        is_listed = False
                        score = 0.0
                        evidence = f"GreyNoise classified IP as BENIGN known service: {name} (RIOT: {riot})."
                    elif noise:
                        risk = ReputationStatus.SUSPICIOUS
                        cat = ListingCategory.MALICIOUS_SCAN
                        is_listed = True
                        score = 50.0
                        evidence = f"GreyNoise detected internet-wide scanning activity: {name}."
                    else:
                        risk = ReputationStatus.CLEAN
                        cat = ListingCategory.NONE
                        is_listed = False
                        score = 0.0
                        evidence = "No mass internet scanning activity observed by GreyNoise."

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
                        source_classification=f"GreyNoise: {classification} ({name})",
                        source_score=score,
                        risk_status=risk,
                        evidence_summary=evidence,
                        raw_reference=payload,
                        documentation_url=self.documentation_url
                    )

                elif res.status_code == 404:
                    # Not observed by GreyNoise -> clean / no scanner noise
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
                        evidence_summary="IP not observed in GreyNoise mass scanner telemetry.",
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
                        evidence_summary="GreyNoise rate limit exceeded (HTTP 429).",
                        error_type="RATE_LIMITED",
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
                        evidence_summary=f"GreyNoise returned HTTP {res.status_code}",
                        error_type=f"HTTP_{res.status_code}",
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
                evidence_summary=f"GreyNoise error: {str(e)}",
                error_type="CONNECTION_ERROR",
                documentation_url=self.documentation_url
            )

    async def health_check(self) -> Dict[str, Any]:
        res = await self.check_ip("8.8.8.8", depth="standard")
        return {
            "online": res.lookup_status in ("completed", "rate_limited"),
            "provider_id": self.provider_id,
            "status": "healthy" if res.lookup_status == "completed" else res.lookup_status,
            "latency_ms": res.duration_ms
        }
