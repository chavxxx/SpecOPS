"""
Cisco Talos Intelligence Provider Adapter
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

class CiscoTalosProvider(BaseReputationProvider):
    """Adapter for Cisco Talos Reputation Intelligence"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.api_endpoint = config.get("api_endpoint")
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

        if not self.api_key and not self.api_endpoint:
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
                evidence_summary="Cisco Talos Intelligence requires an authorized enterprise API key or SenderBase subscription. Configure in Provider Management.",
                error_type="API_KEY_MISSING",
                documentation_url=self.documentation_url
            )

        start_time = time.perf_counter()
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        url = f"{self.api_endpoint}/{ip_str}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                res = await client.get(url, headers=headers)
                duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

                if res.status_code == 200:
                    payload = res.json()
                    reputation = (payload.get("email_score") or payload.get("reputation") or "neutral").lower()
                    threat_level = payload.get("threat_level", "none")

                    if reputation == "poor" or threat_level == "high":
                        risk = ReputationStatus.HIGH_RISK
                        is_listed = True
                        cat = ListingCategory.THREAT_ACTOR
                        score = 85.0
                    elif reputation == "questionable" or threat_level in ("medium", "elevated"):
                        risk = ReputationStatus.SUSPICIOUS
                        is_listed = True
                        cat = ListingCategory.ABUSE_REPORTS
                        score = 50.0
                    else:
                        risk = ReputationStatus.CLEAN
                        is_listed = False
                        cat = ListingCategory.NONE
                        score = 0.0

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
                        source_classification=f"Talos Reputation: {reputation.upper()}",
                        source_score=score,
                        risk_status=risk,
                        evidence_summary=f"Cisco Talos reports reputation as {reputation.upper()} (Threat level: {threat_level}).",
                        raw_reference=payload,
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
                        evidence_summary=f"Cisco Talos returned HTTP {res.status_code}",
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
                evidence_summary=f"Cisco Talos error: {str(e)}",
                error_type="CONNECTION_ERROR",
                documentation_url=self.documentation_url
            )

    async def health_check(self) -> Dict[str, Any]:
        return {
            "online": bool(self.api_key),
            "provider_id": self.provider_id,
            "status": "configured" if self.api_key else "awaiting_credentials",
            "message": "Ready" if self.api_key else "API key not configured"
        }
