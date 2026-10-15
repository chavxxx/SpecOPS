"""
WISPnet Cross-Sensor Correlation Engine
Correlates Pre-CGNAT (subscriber-side) and Post-CGNAT (translated-side) events using 5-tuple,
deterministic port block boundaries, and clock drift tolerance.
"""
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timezone
import math

from app.models.security_schemas import (
    SecurityEvent,
    AttributionStatus,
    AttributionResult
)
from app.database.db import DatabaseManager, get_db
from app.services.cgnat_engine import parse_iso_datetime

class CrossSensorCorrelationEngine:
    def __init__(self, db: Optional[DatabaseManager] = None, timestamp_tolerance_seconds: float = 3.0):
        self.db = db or get_db()
        self.timestamp_tolerance_seconds = timestamp_tolerance_seconds

    def correlate(
        self,
        pre_event: SecurityEvent,
        post_event: SecurityEvent
    ) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Validates if pre_event (pre-NAT) and post_event (post-NAT) represent the same
        underlying network flow / attack.
        """
        # 1. Check protocol and destination match
        if pre_event.protocol.lower() != post_event.protocol.lower():
            return False, "Protocol mismatch", None

        if pre_event.destination_ip != post_event.destination_ip:
            return False, "Destination IP mismatch", None

        if pre_event.destination_port and post_event.destination_port:
            if pre_event.destination_port != post_event.destination_port:
                return False, "Destination port mismatch", None

        # 2. Check timestamp drift within tolerance
        t1 = parse_iso_datetime(pre_event.event_timestamp)
        t2 = parse_iso_datetime(post_event.event_timestamp)
        if not t1 or not t2:
            return False, "Invalid timestamp in event", None

        drift = abs((t1 - t2).total_seconds())
        if drift > self.timestamp_tolerance_seconds:
            return False, f"Timestamp drift {drift:.2f}s exceeds tolerance {self.timestamp_tolerance_seconds}s", None

        # 3. Check CGNAT deterministic port-block containment
        # post_event.source_ip and post_event.source_port must map to pre_event.source_ip
        if not post_event.source_port:
            return False, "Post-NAT event missing source port", None

        matching_mappings = self.db.find_cgnat_mapping(
            public_ip=post_event.source_ip,
            public_port=post_event.source_port,
            protocol=post_event.protocol,
            timestamp=post_event.event_timestamp
        )

        if not matching_mappings:
            return False, f"No CGNAT mapping found for post-NAT {post_event.source_ip}:{post_event.source_port}", None

        # Check if the subscriber IP in mapping matches the pre-NAT source IP
        mapping = matching_mappings[0]
        if mapping.subscriber_cgnat_ip != pre_event.source_ip:
            return False, (
                f"CGNAT mapping resolves to {mapping.subscriber_cgnat_ip}, "
                f"which differs from observed pre-NAT subscriber {pre_event.source_ip}"
            ), None

        evidence = {
            "pre_sensor_id": pre_event.sensor_id,
            "post_sensor_id": post_event.sensor_id,
            "subscriber_cgnat_ip": pre_event.source_ip,
            "original_source_port": pre_event.source_port,
            "translated_public_ip": post_event.source_ip,
            "translated_source_port": post_event.source_port,
            "port_block": f"{mapping.port_start}-{mapping.port_end}",
            "destination": f"{post_event.destination_ip}:{post_event.destination_port}",
            "protocol": post_event.protocol,
            "clock_drift_seconds": round(drift, 3),
            "mapping_id": mapping.mapping_id
        }
        return True, "Cross-sensor verified via 5-tuple and deterministic CGNAT mapping", evidence
