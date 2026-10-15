"""
IP Reputation Scanner & Orchestrator Service
Coordinates single lookups, provider caching, bulk scanning jobs, CIDR expansion,
and state transition auditing.
WISP Network & Data Solutions (WISPnet)
"""
import asyncio
import ipaddress
import logging
import time
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone

from app.database.db import get_db, DatabaseManager
from app.models.ip_intel_schemas import (
    SingleLookupRequest,
    SingleLookupResponse,
    ProviderResult,
    ReputationStatus,
    ListingCategory
)
from app.services.ip_intel.base import (
    BaseReputationProvider,
    is_valid_ip,
    get_ip_version,
    is_private_or_special_ip,
    get_utc_now_iso
)
from app.services.ip_intel.dnsbl_provider import DNSBLProvider
from app.services.ip_intel.abuseipdb_provider import AbuseIPDBProvider
from app.services.ip_intel.virustotal_provider import VirusTotalProvider
from app.services.ip_intel.greynoise_provider import GreyNoiseProvider
from app.services.ip_intel.cisco_talos_provider import CiscoTalosProvider
from app.services.ip_intel.rdns_provider import ReverseDNSProvider
from app.services.ip_intel.gaming_provider import GamingCompatibilityProvider
from app.services.ip_intel.scoring_engine import ReputationScoringEngine
from app.services.ip_intel.cgnat_correlation import CGNATReputationCorrelator
from app.services.notification_service import get_notification_service

logger = logging.getLogger(__name__)

class IPIntelScanner:
    """Central engine for executing reputation lookups and managing scan jobs"""

    def __init__(self, db: Optional[DatabaseManager] = None):
        self.db = db or get_db()
        self._running_scans: Dict[str, asyncio.Task] = {}

    def get_provider_instance(self, prov_conf: Dict[str, Any]) -> BaseReputationProvider:
        prov_id = prov_conf.get("provider_id", "")
        if prov_id in ("spamhaus_zen", "spamcop", "barracuda") or prov_conf.get("provider_type") == "dnsbl":
            return DNSBLProvider(prov_conf)
        elif prov_id == "abuseipdb":
            return AbuseIPDBProvider(prov_conf)
        elif prov_id == "virustotal":
            return VirusTotalProvider(prov_conf)
        elif prov_id == "greynoise":
            return GreyNoiseProvider(prov_conf)
        elif prov_id == "cisco_talos":
            return CiscoTalosProvider(prov_conf)
        elif prov_id == "rdns_ptr":
            return ReverseDNSProvider(prov_conf)
        elif prov_id == "gaming_compat" or prov_conf.get("provider_type") == "gaming_intel":
            return GamingCompatibilityProvider(prov_conf)
        else:
            return DNSBLProvider(prov_conf)

    async def check_ip(
        self,
        req: SingleLookupRequest,
        bypass_cache: bool = False
    ) -> SingleLookupResponse:
        ip_str = req.ip_address.strip()
        now = get_utc_now_iso()

        if not is_valid_ip(ip_str):
            return SingleLookupResponse(
                ip_address=ip_str,
                ip_version=4,
                overall_status=ReputationStatus.UNKNOWN,
                overall_score=0.0,
                score_factors=[],
                total_providers_checked=0,
                positive_findings_count=0,
                failed_checks_count=0,
                check_timestamp=now,
                explanation=f"Malformed IP address: '{ip_str}' is not a valid IPv4 or IPv6 address.",
                provider_results=[]
            )

        ip_ver = get_ip_version(ip_str)

        # Get all configured providers
        all_provs = self.db.get_providers_config()
        if req.providers:
            target_provs = [p for p in all_provs if p["provider_id"] in req.providers]
        else:
            target_provs = [p for p in all_provs if p["enabled"]]

        results: List[ProviderResult] = []

        # Execute queries across target providers with concurrency control
        async def query_provider(prov_dict: Dict[str, Any]) -> ProviderResult:
            prov_id = prov_dict["provider_id"]
            pos_ttl = prov_dict.get("cache_duration_positive_sec", 1800)
            neg_ttl = prov_dict.get("cache_duration_negative_sec", 7200)

            # Check cache
            if not bypass_cache:
                cached = self.db.get_cached_observation(ip_str, prov_id, max_age_seconds=max(pos_ttl, neg_ttl))
                if cached:
                    return ProviderResult(
                        provider_id=prov_id,
                        provider_name=cached["provider_name"],
                        provider_type=cached["listing_category"] if hasattr(cached, "provider_type") else prov_dict["provider_type"],
                        queried_ip=ip_str,
                        check_timestamp=cached["check_timestamp"],
                        lookup_status="completed",
                        duration_ms=cached.get("duration_ms", 0.0),
                        is_cached=True,
                        is_listed=bool(cached["is_listed"]),
                        listing_category=cached.get("listing_category", ListingCategory.NONE),
                        source_classification=cached.get("source_classification"),
                        source_score=cached.get("source_score"),
                        risk_status=cached.get("risk_status", ReputationStatus.UNKNOWN),
                        evidence_summary=cached.get("evidence_summary", "") + " (Cached)",
                        raw_reference=cached.get("raw_reference"),
                        documentation_url=prov_dict.get("documentation_url")
                    )

            # Raw provider lookup
            raw_prov = self.db.get_provider_raw(prov_id) or prov_dict
            adapter = self.get_provider_instance(raw_prov)
            res = await adapter.check_ip(ip_str, depth=req.depth)

            # Save to observation cache
            self.db.save_observation(res.model_dump())
            # Update provider health stats
            self.db.update_provider_runtime_stats(
                prov_id,
                success=res.lookup_status in ("completed", "unsupported"),
                error_msg=res.error_message,
                quota_remaining=adapter.config.get("quota_remaining")
            )
            return res

        # Execute with limit
        tasks = [query_provider(p) for p in target_provs]
        if tasks:
            results = await asyncio.gather(*tasks)

        # Evaluate score and classification
        status, score, factors, explanation = ReputationScoringEngine.evaluate(results)

        # Audit state transitions if tracked in inventory
        inv_item = self.db.get_ip_inventory_item(ip_str)
        listed_count = sum(1 for r in results if r.is_listed)
        failed_count = sum(1 for r in results if r.lookup_status in ("failed", "timeout", "blocked"))

        if inv_item:
            prev_status = inv_item.get("current_reputation_status")
            if prev_status != status.value:
                # Log transition
                event_type = "listing_detected" if status in (ReputationStatus.LISTED, ReputationStatus.HIGH_RISK) else (
                    "listing_cleared" if prev_status in ("LISTED", "HIGH_RISK") and status == ReputationStatus.CLEAN else "status_changed"
                )
                self.db.add_reputation_history_entry(
                    ip_address=ip_str,
                    event_type=event_type,
                    previous_status=prev_status,
                    new_status=status.value,
                    details=f"Status transitioned from {prev_status} to {status.value} (Score: {score}). Evidence: {explanation}",
                    triggered_by="scanner"
                )

                # Send notification if new listing detected
                if event_type == "listing_detected":
                    try:
                        notifier = get_notification_service()
                        notifier.notify_incident({
                            "incident_id": f"REP-{ip_str.replace('.', '-')}",
                            "title": f"IP Reputation Blacklist Alert: {ip_str} [{status.value}]",
                            "severity": "high" if status == ReputationStatus.HIGH_RISK else "medium",
                            "category": "ip_reputation",
                            "affected_public_ip": ip_str,
                            "evidence": {"explanation": explanation, "score": score, "listings": listed_count}
                        })
                    except Exception as e:
                        logger.debug(f"Notification error: {e}")

            # Update inventory record
            latest_abuse = next((r.evidence_summary for r in results if r.is_listed and r.listing_category == ListingCategory.ABUSE_REPORTS), None)
            self.db.update_ip_inventory_reputation(
                ip_address=ip_str,
                reputation_status=status.value,
                risk_score=score,
                active_listings=listed_count,
                latest_abuse=latest_abuse
            )

        # Deterministic CGNAT Correlation
        cgnat_brief = None
        if req.include_historical_cgnat:
            cgnat_brief = CGNATReputationCorrelator.correlate_cgnat(
                ip_str=ip_str,
                event_port=req.event_port,
                event_timestamp=req.event_timestamp,
                db=self.db
            )

        # Related Suricata Alerts
        suricata_count = 0
        recent_alerts = []
        if req.include_suricata:
            suricata_count, recent_alerts = CGNATReputationCorrelator.get_related_suricata_alerts(
                ip_str=ip_str,
                limit=10,
                db=self.db
            )

        # Flow summary
        flow_summary = None
        if req.include_akvorado:
            flow_summary = await CGNATReputationCorrelator.get_related_flow_summary(ip_str)

        return SingleLookupResponse(
            ip_address=ip_str,
            ip_version=ip_ver,
            overall_status=status,
            overall_score=score,
            score_factors=factors,
            total_providers_checked=len(results),
            positive_findings_count=listed_count,
            failed_checks_count=failed_count,
            check_timestamp=now,
            explanation=explanation,
            provider_results=list(results),
            cgnat_correlation=cgnat_brief,
            suricata_alerts_count=suricata_count,
            recent_suricata_alerts=recent_alerts,
            flow_summary=flow_summary
        )

    def expand_cidr(self, cidr_str: str, max_limit: int = 256) -> List[str]:
        """Expands CIDR to individual IP addresses with strict bounds safety"""
        net = ipaddress.ip_network(cidr_str.strip(), strict=False)
        total = net.num_addresses
        if total > max_limit:
            raise ValueError(f"CIDR {cidr_str} contains {total} addresses, exceeding safety limit of {max_limit}. Confirm range or scan smaller subnets.")
        
        # Omit network and broadcast for IPv4 subnets /30 or larger
        if net.version == 4 and net.prefixlen <= 30:
            return [str(ip) for ip in net.hosts()]
        else:
            return [str(ip) for ip in net]

    def start_bulk_scan_job(self, scan_id: str):
        """Dispatches bulk scan background task"""
        if scan_id in self._running_scans and not self._running_scans[scan_id].done():
            return
        task = asyncio.create_task(self._run_bulk_scan_worker(scan_id))
        self._running_scans[scan_id] = task

    async def _run_bulk_scan_worker(self, scan_id: str):
        logger.info(f"Starting bulk reputation scan job {scan_id}")
        self.db.set_scan_status(scan_id, "running")

        while True:
            scan = self.db.get_scan(scan_id)
            if not scan or scan.get("status") in ("paused", "cancelled"):
                logger.info(f"Scan {scan_id} paused or cancelled")
                break

            items = self.db.get_pending_scan_items(scan_id, limit=scan.get("concurrency_limit", 5))
            if not items:
                # All items processed
                self.db.update_scan_progress(scan_id)
                logger.info(f"Scan {scan_id} finished processing all targets")
                break

            async def process_item(item: Dict[str, Any]):
                ip = item["ip_address"]
                req = SingleLookupRequest(
                    ip_address=ip,
                    depth=scan.get("scan_depth", "standard"),
                    providers=scan.get("selected_providers") or None,
                    include_historical_cgnat=False,
                    include_suricata=False,
                    include_akvorado=False
                )
                try:
                    res = await self.check_ip(req)
                    self.db.update_scan_item_result(
                        item_id=item["id"],
                        status="completed",
                        reputation_status=res.overall_status.value,
                        active_listings=res.positive_findings_count
                    )
                except Exception as e:
                    self.db.update_scan_item_result(
                        item_id=item["id"],
                        status="failed",
                        error_message=str(e)
                    )

            await asyncio.gather(*[process_item(it) for it in items])
            self.db.update_scan_progress(scan_id)
            await asyncio.sleep(0.5)

_scanner_instance: Optional[IPIntelScanner] = None

def get_ip_intel_scanner() -> IPIntelScanner:
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = IPIntelScanner()
    return _scanner_instance
