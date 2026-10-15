"""
AbuseIPDB API Provider Adapter
Queries AbuseIPDB v2 check endpoint for confidence score, report volume, and categories.
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

class AbuseIPDBProvider(BaseReputationProvider):
    """Adapter for AbuseIPDB v2 Check API"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.api_endpoint = config.get("api_endpoint") or "https://api.abuseipdb.com/api/v2/check"
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
                evidence_summary="AbuseIPDB API key not configured. Enter a valid API key in Provider Management.",
                error_type="API_KEY_MISSING",
                documentation_url=self.documentation_url
            )

        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip_str,
            "maxAgeInDays": 90,
            "verbose": True if depth == "comprehensive" else False
        }

        start_time = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                res = await client.get(self.api_endpoint, headers=headers, params=params)
                duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

                # Track quota headers
                remaining = res.headers.get("x-ratelimit-remaining")
                if remaining is not None:
                    try:
                        self.config["quota_remaining"] = int(remaining)
                    except ValueError:
                        pass

                if res.status_code == 200:
                    payload = res.json().get("data", {})
                    score = float(payload.get("abuseConfidenceScore", 0.0))
                    total_reports = int(payload.get("totalReports", 0))
                    num_users = int(payload.get("numDistinctUsers", 0))
                    last_reported = payload.get("lastReportedAt")
                    usage_type = payload.get("usageType") or "Unknown"

                    is_listed = score > 0 or total_reports > 0
                    if score >= 80:
                        risk = ReputationStatus.HIGH_RISK
                        cat = ListingCategory.ABUSE_REPORTS
                    elif score >= 20:
                        risk = ReputationStatus.SUSPICIOUS
                        cat = ListingCategory.ABUSE_REPORTS
                    elif score > 0 or total_reports > 0:
                        risk = ReputationStatus.SUSPICIOUS
                        cat = ListingCategory.ABUSE_REPORTS
                    else:
                        risk = ReputationStatus.CLEAN
                        cat = ListingCategory.NONE

                    evidence = f"Abuse confidence: {score}%, Reports: {total_reports} from {num_users} distinct reporters."
                    if last_reported:
                        evidence += f" Last report: {last_reported}."

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
                        source_classification=f"AbuseIPDB Score {score}% ({usage_type})",
                        source_score=score,
                        risk_status=risk,
                        evidence_summary=evidence,
                        raw_reference={"data": payload},
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
                        evidence_summary="AbuseIPDB rate limit / quota exceeded (HTTP 429).",
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
                        evidence_summary="AbuseIPDB API key rejected or unauthorized (HTTP 401/403).",
                        error_type="AUTH_FAILED",
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
                        evidence_summary=f"AbuseIPDB returned HTTP {res.status_code}",
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
                evidence_summary=f"AbuseIPDB query timed out after {self.timeout_seconds}s.",
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
                evidence_summary=f"AbuseIPDB connection error: {str(e)}",
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
        # Lightweight check with test IP 8.8.8.8
        res = await self.check_ip("8.8.8.8", depth="standard")
        return {
            "online": res.lookup_status in ("completed", "rate_limited"),
            "provider_id": self.provider_id,
            "status": "healthy" if res.lookup_status == "completed" else res.lookup_status,
            "latency_ms": res.duration_ms,
            "quota_remaining": self.config.get("quota_remaining")
        }
