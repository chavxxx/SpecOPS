"""
WISPnet CGNAT Subscriber Attribution Engine
Resolves pre-NAT subscriber IPs and historical PPPoE sessions from translated public IPs and ports.
"""
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
import ipaddress

from app.models.security_schemas import (
    AttributionLookupRequest,
    AttributionResult,
    AttributionStatus,
    CGNATMapping,
    SubscriberSession
)
from app.database.db import DatabaseManager, get_db

class CGNATAttributionEngine:
    def __init__(self, db: Optional[DatabaseManager] = None):
        self.db = db or get_db()

    def attribute(self, request: AttributionLookupRequest) -> AttributionResult:
        """
        Executes end-to-end subscriber attribution:
        1. Checks observation point (pre_cgnat vs post_cgnat).
        2. Validates public IP, port, and protocol.
        3. Queries authoritative mapping valid at the exact event timestamp.
        4. Queries active PPPoE session at that timestamp.
        5. Assigns deterministic status: verified, high_confidence, partial, unresolved, conflict.
        """
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        timestamp = request.timestamp or now_iso
        obs_point = request.observation_point or "post_cgnat"
        protocol = (request.protocol or "tcp").lower()

        # CASE 1: Pre-CGNAT observation
        if obs_point == "pre_cgnat" or request.original_source_ip:
            subscriber_ip = request.original_source_ip or request.public_ip
            session = self.db.find_active_session_at_timestamp(subscriber_ip, timestamp)
            username = session.pppoe_username if session else None
            session_id = session.session_id if session else None
            ac = session.access_concentrator if session else None

            # Also check if there is an active mapping for this subscriber
            mappings, _ = self.db.get_cgnat_mappings(subscriber_cgnat_ip=subscriber_ip, limit=1)
            mapping = mappings[0] if mappings else None

            status = AttributionStatus.VERIFIED if session else AttributionStatus.HIGH_CONFIDENCE
            explanation = (
                f"Observed on Pre-CGNAT sensor. Subscriber CGNAT IP {subscriber_ip} directly identified."
                + (f" Active PPPoE session resolved to user '{username}'." if session else " PPPoE session unrecorded at timestamp.")
            )

            return AttributionResult(
                attribution_status=status,
                subscriber_cgnat_ip=subscriber_ip,
                pppoe_username=username,
                session_id=session_id,
                access_concentrator=ac,
                public_ip=mapping.public_ip if mapping else request.public_ip,
                public_port=request.public_port,
                port_block_range=f"{mapping.port_start}-{mapping.port_end}" if mapping else None,
                protocol=protocol,
                event_timestamp=timestamp,
                mapping_id=mapping.mapping_id if mapping else None,
                mapping_version=mapping.mapping_version if mapping else None,
                mapping_effective_from=mapping.effective_from if mapping else None,
                mapping_effective_to=mapping.effective_to if mapping else None,
                observation_point=obs_point,
                attribution_method="pre_cgnat_direct_observation",
                confidence_explanation=explanation,
                supporting_evidence={
                    "sensor_observation_point": obs_point,
                    "subscriber_ip_observed": subscriber_ip,
                    "session_matched": bool(session),
                    "mapping_matched": bool(mapping)
                },
                unresolved_fields=[] if session else ["pppoe_username", "session_id"]
            )

        # CASE 2: Post-CGNAT observation (Public IP & Port block lookup)
        # Check if port is provided
        if request.public_port is None:
            return AttributionResult(
                attribution_status=AttributionStatus.PARTIAL,
                subscriber_cgnat_ip=None,
                pppoe_username=None,
                public_ip=request.public_ip,
                public_port=None,
                protocol=protocol,
                event_timestamp=timestamp,
                observation_point=obs_point,
                attribution_method="unresolved_missing_port",
                confidence_explanation=(
                    f"External observation on public IP {request.public_ip} without source port. "
                    "In a shared CGNAT architecture (1:32 ratio), subscriber attribution cannot be determined "
                    "without the translated source port. Subscriber identity will never be guessed."
                ),
                supporting_evidence={"public_ip": request.public_ip},
                unresolved_fields=["public_port", "subscriber_cgnat_ip", "pppoe_username"]
            )

        # Lookup in authoritative mapping table
        matching_mappings = self.db.find_cgnat_mapping(
            public_ip=request.public_ip,
            public_port=request.public_port,
            protocol=protocol,
            timestamp=timestamp
        )

        if not matching_mappings:
            # Check without timestamp to see if historical mapping existed at other times
            historical = self.db.find_cgnat_mapping(
                public_ip=request.public_ip,
                public_port=request.public_port,
                protocol=protocol,
                timestamp=None
            )
            if historical:
                explanation = (
                    f"No active mapping for {request.public_ip}:{request.public_port} at timestamp {timestamp}. "
                    f"Found {len(historical)} mapping(s) for different validity intervals."
                )
            else:
                explanation = f"No deterministic CGNAT mapping found for {request.public_ip}:{request.public_port} ({protocol})."

            return AttributionResult(
                attribution_status=AttributionStatus.UNRESOLVED,
                subscriber_cgnat_ip=None,
                pppoe_username=None,
                public_ip=request.public_ip,
                public_port=request.public_port,
                protocol=protocol,
                event_timestamp=timestamp,
                observation_point=obs_point,
                attribution_method="deterministic_mapping_lookup",
                confidence_explanation=explanation,
                supporting_evidence={"public_ip": request.public_ip, "public_port": request.public_port},
                unresolved_fields=["subscriber_cgnat_ip", "pppoe_username", "mapping_id"]
            )

        if len(matching_mappings) > 1:
            # Multiple concurrent conflicting mappings
            m_ids = [m.mapping_id for m in matching_mappings]
            return AttributionResult(
                attribution_status=AttributionStatus.CONFLICT,
                subscriber_cgnat_ip=None,
                pppoe_username=None,
                public_ip=request.public_ip,
                public_port=request.public_port,
                protocol=protocol,
                event_timestamp=timestamp,
                observation_point=obs_point,
                attribution_method="deterministic_mapping_lookup",
                confidence_explanation=f"Ambiguous or overlapping mappings detected for {request.public_ip}:{request.public_port}: {m_ids}",
                supporting_evidence={"conflicting_mapping_ids": m_ids},
                unresolved_fields=["subscriber_cgnat_ip", "pppoe_username"]
            )

        # Unique matching mapping resolved
        mapping = matching_mappings[0]
        subscriber_ip = mapping.subscriber_cgnat_ip

        # Lookup active session for this subscriber at the event timestamp
        session = self.db.find_active_session_at_timestamp(subscriber_ip, timestamp)
        username = session.pppoe_username if session else None
        session_id = session.session_id if session else None
        ac = session.access_concentrator if session else None

        if session:
            status = AttributionStatus.VERIFIED
            explanation = (
                f"Authoritative CGNAT port block {mapping.port_start}-{mapping.port_end} on {mapping.public_ip} "
                f"uniquely maps to subscriber CGNAT IP {subscriber_ip}. "
                f"Historical PPPoE session active at {timestamp} resolved to username '{username}' on AC {ac}."
            )
            unresolved = []
        else:
            status = AttributionStatus.HIGH_CONFIDENCE
            explanation = (
                f"Authoritative CGNAT port block {mapping.port_start}-{mapping.port_end} on {mapping.public_ip} "
                f"uniquely maps to subscriber CGNAT IP {subscriber_ip}. "
                f"PPPoE session was not captured or offline at exact event timestamp {timestamp}."
            )
            unresolved = ["pppoe_username", "session_id"]

        return AttributionResult(
            attribution_status=status,
            subscriber_cgnat_ip=subscriber_ip,
            pppoe_username=username,
            session_id=session_id,
            access_concentrator=ac,
            public_ip=request.public_ip,
            public_port=request.public_port,
            port_block_range=f"{mapping.port_start}-{mapping.port_end}",
            protocol=protocol,
            event_timestamp=timestamp,
            mapping_id=mapping.mapping_id,
            mapping_version=mapping.mapping_version,
            mapping_effective_from=mapping.effective_from,
            mapping_effective_to=mapping.effective_to,
            observation_point=obs_point,
            attribution_method="deterministic_port_block_correlation",
            confidence_explanation=explanation,
            supporting_evidence={
                "mapping_id": mapping.mapping_id,
                "port_start": mapping.port_start,
                "port_end": mapping.port_end,
                "subscriber_ip": subscriber_ip,
                "session_matched": bool(session),
                "router_id": mapping.router_id
            },
            unresolved_fields=unresolved
        )
