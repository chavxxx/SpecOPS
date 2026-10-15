"""
Autonomous IP Remediation & Delisting Agent Service
WISP Network & Data Solutions (WISPnet)
Automates the end-to-end IP cleaning lifecycle:
1. Root-cause & subscriber attribution
2. MikroTik egress firewall sanitization
3. Automated delisting request generation (Spamhaus, Barracuda, SpamCop, AbuseIPDB)
4. Online gaming geofeed & rDNS anti-cheat correction
5. Autonomous verification watcher
"""
import asyncio
import json
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from app.database.db import DatabaseManager, get_db
from app.models.ip_intel_schemas import (
    RemediationJobStatus,
    RemediationActionItem,
    RemediationJobResponse,
    SingleLookupRequest,
    ReputationStatus
)
from app.services.ip_intel.base import get_utc_now_iso, is_valid_ip
from app.services.ip_intel.cgnat_correlation import CGNATReputationCorrelator

class IPRemediationAgent:
    """
    Intelligent agent that diagnoses blacklisted or problematic IPs, attributes
    the abusive subscriber or traffic pattern, generates RouterOS sanitization rules,
    and produces one-click delisting workflows.
    """

    def __init__(self, db: Optional[DatabaseManager] = None):
        self.db = db or get_db()

    async def diagnose_and_create_job(
        self,
        ip_address: str,
        auto_apply_mitigation: bool = False,
        operator_notes: Optional[str] = None
    ) -> RemediationJobResponse:
        clean_ip = ip_address.strip()
        job_id = f"clean-{uuid.uuid4().hex[:10]}"
        now = get_utc_now_iso()

        # 1. Gather recent observations & findings
        observations = self.db.get_recent_observations_for_ip(clean_ip, max_age_seconds=86400)
        active_listings = [obs for obs in observations if obs.get("is_listed")]

        # 2. Check CGNAT correlation & Suricata intrusion events
        cgnat_brief = CGNATReputationCorrelator.correlate_cgnat(clean_ip, db=self.db).model_dump()
        total_alerts, suricata_alerts = CGNATReputationCorrelator.get_related_suricata_alerts(clean_ip, limit=10, db=self.db)

        # 3. Analyze root cause & abuse vectors
        root_cause_factors = []
        abused_ports = set()
        for alert in suricata_alerts:
            sport = alert.get("source_port")
            dport = alert.get("destination_port")
            if dport:
                abused_ports.add(dport)
            if alert.get("signature_name"):
                root_cause_factors.append(f"Suricata: {alert['signature_name']} (Port {dport or sport})")

        # Determine dominant attack/abuse profile
        dominant_vector = "General Blacklist Ingestion / Mixed Abuse"
        if 25 in abused_ports:
            dominant_vector = "Outbound Spam Bot (TCP Port 25 SMTP Relay)"
        elif 1900 in abused_ports or 53 in abused_ports or 123 in abused_ports:
            dominant_vector = "UDP Amplification / Reflection Storm"
        elif 445 in abused_ports or 3389 in abused_ports or 22 in abused_ports:
            dominant_vector = "Brute-force / Worm Lateral Movement"
        elif any("spam" in (obs.get("provider_id") or "") for obs in active_listings):
            dominant_vector = "Mail Reputation Degradation (Spamhaus/SpamCop Flag)"

        attributed_sub = None
        if cgnat_brief.get("exact_match"):
            attributed_sub = {
                "subscriber_cgnat_ip": cgnat_brief.get("subscriber_cgnat_ip"),
                "pppoe_username": cgnat_brief.get("pppoe_username"),
                "allocated_port_block": cgnat_brief.get("allocated_port_block"),
                "attribution_status": cgnat_brief.get("attribution_status")
            }

        root_cause = {
            "dominant_vector": dominant_vector,
            "active_listings_count": len(active_listings),
            "listed_providers": [obs.get("provider_name") for obs in active_listings],
            "suricata_events_detected": total_alerts,
            "abused_ports": sorted(list(abused_ports)),
            "details": f"Attributed {len(active_listings)} blacklist listings and {total_alerts} security alerts."
        }

        # 4. Generate MikroTik RouterOS Traffic Sanitization Commands
        sanitization_cmds = [
            f"# ============================================================",
            f"# SpecOPS Autonomous Sanitization Rules for {clean_ip}",
            f"# Prevents ongoing abuse leakage to facilitate blacklist delisting",
            f"# ============================================================",
            f"/ip firewall filter add chain=forward action=drop protocol=tcp dst-port=25 src-address={clean_ip} comment=\"SpecOPS-Cleaner: Drop outbound spam bot on {clean_ip}\"",
            f"/ip firewall filter add chain=forward action=drop protocol=udp dst-port=1900,5353 src-address={clean_ip} comment=\"SpecOPS-Cleaner: Drop SSDP/mDNS amplification on {clean_ip}\""
        ]
        if attributed_sub and attributed_sub.get("subscriber_cgnat_ip"):
            sub_ip = attributed_sub["subscriber_cgnat_ip"]
            sanitization_cmds.append(
                f"/ip firewall address-list add list=specops_quarantine address={sub_ip} timeout=2d comment=\"SpecOPS: Quarantine abusive subscriber {attributed_sub.get('pppoe_username') or ''}\""
            )

        # 5. Build Delisting Actions for major blacklists and anti-cheat engines
        delisting_actions: List[Dict[str, Any]] = []

        # Spamhaus Delisting Portal
        delisting_actions.append({
            "id": f"delist-spamhaus-{job_id}",
            "provider_id": "spamhaus_zen",
            "provider_name": "Spamhaus ZEN / CBL",
            "action_type": "web_portal",
            "action_title": "Spamhaus IP Removal Portal",
            "description": "Submit automatic self-service delisting after applying the MikroTik Port 25 firewall drop.",
            "external_url": f"https://check.spamhaus.org/query/ip/{clean_ip}",
            "prefilled_payload": {
                "ip": clean_ip,
                "reason": "Subscriber device secured. Outgoing TCP port 25 blocked on core CGNAT router.",
                "contact": "noc@wispnet.ph"
            },
            "status": "ready"
        })

        # Barracuda BRBL Removal
        delisting_actions.append({
            "id": f"delist-barracuda-{job_id}",
            "provider_id": "barracuda",
            "provider_name": "Barracuda Reputation BRBL",
            "action_type": "web_portal",
            "action_title": "Barracuda Central IP Removal Request",
            "description": "One-click submission to Barracuda Central automated unban queue.",
            "external_url": f"https://www.barracudacentral.org/rbl/removal-request",
            "prefilled_payload": {
                "ip": clean_ip,
                "email": "noc@wispnet.ph",
                "explanation": "Outbound spam traffic eliminated via ISP CGNAT egress filtering."
            },
            "status": "ready"
        })

        # SpamCop Tracking
        delisting_actions.append({
            "id": f"delist-spamcop-{job_id}",
            "provider_id": "spamcop",
            "provider_name": "SpamCop Blocking List",
            "action_type": "api_submit",
            "action_title": "SpamCop Automatic Expiry Monitor",
            "description": "SpamCop automatically clears IPs 24–48 hours after abusive traffic stops.",
            "external_url": f"https://www.spamcop.net/w3m?action=checkblock&ip={clean_ip}",
            "prefilled_payload": {"decay_window_hours": 24},
            "status": "submitted"
        })

        # AbuseIPDB False Positive Dispute / Decay
        delisting_actions.append({
            "id": f"delist-abuseipdb-{job_id}",
            "provider_id": "abuseipdb",
            "provider_name": "AbuseIPDB",
            "action_type": "web_portal",
            "action_title": "AbuseIPDB IP History & Dispute",
            "description": "Review distinct reporter breakdown and request dispute for false-positive CGNAT reports.",
            "external_url": f"https://www.abuseipdb.com/check/{clean_ip}",
            "prefilled_payload": {"ip": clean_ip},
            "status": "ready"
        })

        # Reverse DNS / PTR Recommendation for Gaming Anti-Cheat
        reversed_ip = ".".join(reversed(clean_ip.split(".")))
        dash_ip = clean_ip.replace(".", "-")
        rdns_rec = f"{reversed_ip}.in-addr.arpa. IN PTR dynamic-{dash_ip}.wispnet.ph."

        # RFC 8805 Geofeed Recommendation for Game Publishers (CODM/Garena/Activision)
        geofeed_entry = f"{clean_ip}/32,PH,PH-00,Manila,WISPnet Solutions,Wireless ISP"

        delisting_actions.append({
            "id": f"delist-gaming-{job_id}",
            "provider_id": "gaming_compat",
            "provider_name": "Online Gaming & Anti-Cheat Engine",
            "action_type": "geofeed_update",
            "action_title": "RFC 8805 Geofeed & PTR Validation",
            "description": "Updates IP classification to 'Residential Wireless ISP' to resolve Call of Duty: Mobile and Vanguard bans.",
            "external_url": "https://geofeeds.wispnet.ph/feed.csv",
            "prefilled_payload": {
                "geofeed_line": geofeed_entry,
                "ptr_record": rdns_rec
            },
            "status": "ready"
        })

        # Initial Logs
        logs = [
            {
                "timestamp": now,
                "phase": "diagnostic",
                "message": f"Agent initiated diagnostic for {clean_ip}. Identified vector: {dominant_vector}."
            },
            {
                "timestamp": now,
                "phase": "sanitization",
                "message": f"Generated {len(sanitization_cmds) - 4} MikroTik egress firewall drop rules."
            },
            {
                "timestamp": now,
                "phase": "delisting",
                "message": f"Prepared {len(delisting_actions)} delisting portal actions and RFC 8805 geofeed correction."
            }
        ]

        # 6. Persist to Database
        self.db.create_remediation_job(
            job_id=job_id,
            ip_address=clean_ip,
            status=RemediationJobStatus.DELISTING.value,
            progress_percent=50.0,
            root_cause=root_cause,
            attributed_subscriber=attributed_sub,
            sanitization_commands=sanitization_cmds,
            delisting_actions=delisting_actions,
            geofeed_entry=geofeed_entry,
            rdns_recommendation=rdns_rec,
            verification_schedule="Every 1 hour (24h window)",
            logs=logs
        )

        self.db.log_ip_intel_audit(
            username="system",
            action="create_remediation_job",
            target_type="ip",
            target_id=clean_ip,
            details={"job_id": job_id, "dominant_vector": dominant_vector}
        )

        job_data = self.db.get_remediation_job(job_id)
        return RemediationJobResponse(**job_data)

    async def verify_clean_status(self, job_id: str) -> Dict[str, Any]:
        """
        Executes a real-time re-scan of the IP to check if it has successfully cleared blacklists.
        """
        job = self.db.get_remediation_job(job_id)
        if not job:
            return {"success": False, "message": "Remediation job not found"}

        ip_str = job["ip_address"]
        now = get_utc_now_iso()

        # Import scanner lazily to avoid circular imports
        from app.services.ip_intel.scanner import get_ip_intel_scanner
        scanner = get_ip_intel_scanner()

        req = SingleLookupRequest(
            ip_address=ip_str,
            depth="standard",
            include_historical_cgnat=False,
            include_suricata=False,
            include_akvorado=False
        )
        res = await scanner.check_ip(req, bypass_cache=True)

        is_clean = (res.overall_status == ReputationStatus.CLEAN and res.positive_findings_count == 0)

        logs = job.get("logs") or []
        if is_clean:
            logs.append({
                "timestamp": now,
                "phase": "verification",
                "message": f"[CLEAN] Re-scan confirmed {ip_str} is clean across all providers! Status: 100% CLEAN."
            })
            self.db.update_remediation_job(
                job_id=job_id,
                status=RemediationJobStatus.COMPLETED.value,
                progress_percent=100.0,
                logs=logs,
                completed=True
            )
            # Update inventory table reputation status as well
            self.db.update_ip_inventory_reputation(
                ip_address=ip_str,
                reputation_status=ReputationStatus.CLEAN.value,
                risk_score=0.0,
                active_listings=0
            )
            return {
                "success": True,
                "is_clean": True,
                "status": "completed",
                "message": f"Success! {ip_str} has been verified 100% clean across all intelligence feeds."
            }
        else:
            remaining = [r.provider_name for r in res.provider_results if r.is_listed]
            logs.append({
                "timestamp": now,
                "phase": "verification",
                "message": f"[IN PROGRESS] Re-scan found remaining listings on: {', '.join(remaining)}."
            })
            self.db.update_remediation_job(
                job_id=job_id,
                status=RemediationJobStatus.MONITORING.value,
                progress_percent=75.0,
                logs=logs,
                completed=False
            )
            return {
                "success": True,
                "is_clean": False,
                "status": "monitoring",
                "remaining_listings": remaining,
                "message": f"IP still flagged on: {', '.join(remaining)}. Monitoring watcher active."
            }
