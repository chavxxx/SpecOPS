"""
WISPnet Suricata EVE JSON Ingestion & Normalization Engine
Parses alerts, flows, dns, tls, anomalies, deduplicates, enriches with CGNAT attribution,
stores raw events, and enqueues to OpenSearch.
"""
import json
import hashlib
import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone

from app.models.security_schemas import (
    SecurityEvent,
    SecuritySeverity,
    DetectionCategory,
    TrafficDirection,
    AttributionStatus,
    AttributionLookupRequest
)
from app.database.db import DatabaseManager, get_db
from app.services.attribution_engine import CGNATAttributionEngine

logger = logging.getLogger(__name__)

class SuricataIngestService:
    def __init__(
        self,
        db: Optional[DatabaseManager] = None,
        attribution_engine: Optional[CGNATAttributionEngine] = None
    ):
        self.db = db or get_db()
        self.attribution_engine = attribution_engine or CGNATAttributionEngine(self.db)

    def normalize_suricata_event(
        self,
        raw_event: Dict[str, Any],
        default_sensor_id: str = "sensor-post-cgnat-01",
        default_observation_point: str = "post_cgnat"
    ) -> Optional[SecurityEvent]:
        """
        Normalizes a Suricata EVE JSON document into a standardized WISPnet SecurityEvent.
        """
        event_type = raw_event.get("event_type", "alert")
        if event_type == "stats":
            # Update sensor health rather than creating security event
            self._handle_stats_event(raw_event, default_sensor_id)
            return None

        # Source & Destination 5-tuple
        src_ip = raw_event.get("src_ip")
        dst_ip = raw_event.get("dest_ip")
        if not src_ip or not dst_ip:
            return None

        src_port = raw_event.get("src_port")
        dst_port = raw_event.get("dest_port")
        proto = (raw_event.get("proto") or "tcp").lower()

        # Timestamp handling
        ts_raw = raw_event.get("timestamp")
        if ts_raw:
            try:
                # Suricata timestamp format: 2026-10-15T12:00:00.123456+0000 or Z
                clean_ts = ts_raw.replace("+0000", "Z")
                dt = datetime.fromisoformat(clean_ts.replace("Z", "+00:00"))
                event_ts = dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                event_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            event_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Stable deduplication hash: sha256 of core tuple & event attributes
        source_id = str(raw_event.get("flow_id") or raw_event.get("tx_id") or "")
        sig_id = None
        sig_name = None
        category = DetectionCategory.CUSTOM
        severity = SecuritySeverity.MEDIUM

        alert_info = raw_event.get("alert")
        if alert_info:
            sig_id = alert_info.get("signature_id")
            sig_name = alert_info.get("signature")
            category_raw = (alert_info.get("category") or "").lower()
            severity_num = alert_info.get("severity", 3)

            # Map Suricata severity: 1=Critical/High, 2=Medium, 3=Low, 4=Info
            if severity_num == 1:
                severity = SecuritySeverity.HIGH
            elif severity_num == 2:
                severity = SecuritySeverity.MEDIUM
            elif severity_num == 3:
                severity = SecuritySeverity.LOW
            else:
                severity = SecuritySeverity.INFORMATIONAL

            # Map signature category
            if any(k in category_raw for k in ["scan", "recon", "attempted-recon"]):
                category = DetectionCategory.PORT_SCANNING
            elif any(k in category_raw for k in ["dos", "ddos"]):
                category = DetectionCategory.OUTBOUND_DDOS
            elif any(k in category_raw for k in ["brute", "auth", "login"]):
                category = DetectionCategory.BRUTE_FORCE
            elif any(k in category_raw for k in ["c2", "trojan", "malware", "botnet"]):
                category = DetectionCategory.BOTNET_C2
            elif "dns" in category_raw:
                category = DetectionCategory.DNS_ANOMALY
        elif event_type == "dns":
            category = DetectionCategory.DNS_ANOMALY
            severity = SecuritySeverity.INFORMATIONAL
            sig_name = f"DNS Query: {raw_event.get('dns', {}).get('rrname', '')}"
        elif event_type == "anomaly":
            category = DetectionCategory.CUSTOM
            severity = SecuritySeverity.LOW
            sig_name = raw_event.get("anomaly", {}).get("event", "Network anomaly")

        dedup_seed = f"{event_type}_{default_sensor_id}_{event_ts}_{src_ip}_{src_port}_{dst_ip}_{dst_port}_{sig_id}_{sig_name}"
        event_id = "evt-" + hashlib.sha256(dedup_seed.encode("utf-8")).hexdigest()[:24]

        # Determine traffic direction
        # If src_ip is CGNAT subscriber space (100.64.0.0/10) or WISP public pool -> Outbound
        # If dst_ip is WISP public pool and src is external -> Inbound
        traffic_dir = TrafficDirection.OUTBOUND
        if default_observation_point == "pre_cgnat":
            traffic_dir = TrafficDirection.OUTBOUND
        elif src_ip.startswith("100.") or src_ip.startswith("157.119."):
            traffic_dir = TrafficDirection.OUTBOUND
        elif dst_ip.startswith("157.119."):
            traffic_dir = TrafficDirection.INBOUND

        # Packets and Bytes from flow / event stats
        flow_info = raw_event.get("flow", {})
        packets = flow_info.get("pkts_toserver", 0) + flow_info.get("pkts_toclient", 0)
        bytes_count = flow_info.get("bytes_toserver", 0) + flow_info.get("bytes_toclient", 0)
        if packets == 0:
            packets = 1
        if bytes_count == 0:
            bytes_count = raw_event.get("payload_printable_len") or 64

        # Run CGNAT Attribution lookup immediately
        attr_req = AttributionLookupRequest(
            public_ip=src_ip,
            public_port=src_port,
            protocol=proto,
            timestamp=event_ts,
            destination_ip=dst_ip,
            destination_port=dst_port,
            observation_point=default_observation_point,
            original_source_ip=src_ip if default_observation_point == "pre_cgnat" else None
        )
        attr_res = self.attribution_engine.attribute(attr_req)

        return SecurityEvent(
            event_id=event_id,
            source_event_id=source_id or None,
            event_timestamp=event_ts,
            received_timestamp=now_iso,
            sensor_id=default_sensor_id,
            observation_point=default_observation_point,
            source_ip=src_ip,
            source_port=src_port,
            destination_ip=dst_ip,
            destination_port=dst_port,
            protocol=proto,
            traffic_direction=traffic_dir,
            event_type=event_type,
            signature_id=sig_id,
            signature_name=sig_name,
            category=category,
            severity=severity,
            packets=packets,
            bytes=bytes_count,
            flow_id=str(raw_event.get("flow_id", "")),
            original_event_reference=event_id,
            attribution_status=attr_res.attribution_status,
            mapping_id=attr_res.mapping_id,
            subscriber_cgnat_ip=attr_res.subscriber_cgnat_ip,
            pppoe_username=attr_res.pppoe_username,
            attribution_method=attr_res.attribution_method,
            detection_rule_id=None,
            created_at=now_iso
        )

    def ingest_event(
        self,
        raw_event: Dict[str, Any],
        sensor_id: str = "sensor-post-cgnat-01",
        observation_point: str = "post_cgnat"
    ) -> Optional[SecurityEvent]:
        """
        Ingests a single Suricata event: normalizes, writes to DB & raw_events,
        and enqueues to OpenSearch durable buffer.
        """
        event = self.normalize_suricata_event(raw_event, sensor_id, observation_point)
        if not event:
            return None

        raw_str = json.dumps(raw_event)
        inserted = self.db.insert_security_event(event, raw_payload=raw_str)
        if inserted:
            # Enqueue to OpenSearch durable queue buffer
            self.db.enqueue_opensearch_doc(
                index_name="wisp-security-events",
                doc_id=event.event_id,
                document=event.model_dump()
            )
            # Update sensor heartbeat & health
            self.db.update_sensor_heartbeat(sensor_id, "healthy")
            self.db.update_integration_health("Suricata-IDS", "online", lag_ms=2.0)

        return event

    def ingest_batch(
        self,
        raw_events: List[Dict[str, Any]],
        sensor_id: str = "sensor-post-cgnat-01",
        observation_point: str = "post_cgnat"
    ) -> int:
        """Ingests a list of raw Suricata events"""
        count = 0
        for ev in raw_events:
            if self.ingest_event(ev, sensor_id, observation_point):
                count += 1
        return count

    def _handle_stats_event(self, raw_event: Dict[str, Any], sensor_id: str):
        """Updates sensor drops and packet telemetry from Suricata stats"""
        stats = raw_event.get("stats", {})
        capture = stats.get("capture", {})
        kernel_packets = capture.get("kernel_packets", 0)
        kernel_drops = capture.get("kernel_drops", 0)

        self.db.update_sensor_heartbeat(sensor_id, "healthy")
        self.db.update_integration_health(
            "Suricata-IDS",
            "online",
            lag_ms=1.5,
            queue_depth=kernel_drops
        )
