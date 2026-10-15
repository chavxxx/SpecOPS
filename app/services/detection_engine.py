"""
WISPnet Detection Rules Engine & Incident Correlation
Analyzes security events and flows, evaluates configurable rule thresholds and exclusions,
and correlates matching alerts into actionable security incidents.
"""
import uuid
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone, timedelta

from app.models.security_schemas import (
    SecurityEvent,
    Incident,
    DetectionRule,
    DetectionCategory,
    SecuritySeverity,
    IncidentStatus
)
from app.database.db import DatabaseManager, get_db

logger = logging.getLogger(__name__)

class DetectionEngine:
    def __init__(self, db: Optional[DatabaseManager] = None):
        self.db = db or get_db()

    def evaluate_event(self, event: SecurityEvent) -> Optional[Incident]:
        """
        Evaluates a normalized SecurityEvent against active detection rules,
        checks exclusions, and correlates into an Incident if criteria are met.
        """
        rules = self.db.get_detection_rules()
        active_rules = [r for r in rules if r.enabled]

        matching_rule: Optional[DetectionRule] = None

        for rule in active_rules:
            # Check exclusions (IPs or CIDRs)
            sub_ip = event.subscriber_cgnat_ip or event.source_ip
            if sub_ip in rule.exclusions or event.source_ip in rule.exclusions or event.destination_ip in rule.exclusions:
                continue

            # Check category match
            if rule.category == event.category or rule.category == DetectionCategory.CUSTOM:
                if self._check_rule_thresholds(rule, event):
                    matching_rule = rule
                    break

        # If a matching rule or high/critical event is triggered, correlate into an incident
        if matching_rule or event.severity in (SecuritySeverity.HIGH, SecuritySeverity.CRITICAL):
            return self._correlate_into_incident(event, matching_rule)

        return None

    def _check_rule_thresholds(self, rule: DetectionRule, event: SecurityEvent) -> bool:
        """Evaluates category-specific thresholds"""
        cfg = rule.threshold_configuration

        if rule.category == DetectionCategory.OUTBOUND_DDOS:
            min_pps = cfg.get("min_pps", 5000)
            min_bytes = cfg.get("min_bytes_per_sec", 10000000)
            if (event.packets and event.packets >= min_pps) or (event.bytes and event.bytes >= min_bytes):
                return True
            if event.protocol in ("udp", "icmp") and (event.packets or 0) >= (min_pps // 2):
                return True

        elif rule.category == DetectionCategory.BRUTE_FORCE:
            target_ports = cfg.get("target_ports", [22, 3389, 21, 25, 443])
            if event.destination_port in target_ports:
                return True

        elif rule.category == DetectionCategory.PORT_SCANNING:
            # If Suricata already flagged it as scanning or packets > threshold
            if event.category == DetectionCategory.PORT_SCANNING:
                return True

        elif rule.category == DetectionCategory.BOTNET_C2:
            if event.category == DetectionCategory.BOTNET_C2:
                return True

        elif rule.category == DetectionCategory.DNS_ANOMALY:
            if event.category == DetectionCategory.DNS_ANOMALY:
                return True

        elif rule.category == DetectionCategory.INBOUND_DDOS:
            if event.traffic_direction.value == "inbound" and (event.packets or 0) >= cfg.get("min_pps", 10000):
                return True

        # Default fallback: if category matches directly
        return rule.category == event.category

    def _correlate_into_incident(
        self,
        event: SecurityEvent,
        rule: Optional[DetectionRule] = None
    ) -> Incident:
        """
        Groups related alerts involving the same subscriber and category within a time window
        into a single incident.
        """
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        subscriber_key = event.subscriber_cgnat_ip or event.source_ip
        category_val = (rule.category if rule else event.category).value
        severity = rule.severity if rule else event.severity

        # Check for existing active incident in the last 15 minutes
        time_cutoff = (datetime.now(timezone.utc) - timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ")

        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT incident_id, title, event_count, total_bytes, total_packets, first_seen, evidence_summary_json
                FROM incidents
                WHERE affected_subscriber_ip = ?
                  AND category = ?
                  AND status IN ('new', 'investigating', 'confirmed_suspicious')
                  AND last_seen >= ?
                ORDER BY last_seen DESC LIMIT 1
            """, (subscriber_key, category_val, time_cutoff))
            row = cursor.fetchone()

            if row:
                # Correlate with existing incident
                inc_id = row[0]
                first_seen = row[5]
                existing_summary = {}
                try:
                    import json
                    existing_summary = json.loads(row[6]) if row[6] else {}
                except Exception:
                    pass

                # Update destinations list
                dest_list = existing_summary.get("destinations", [])
                new_dest = f"{event.destination_ip}:{event.destination_port}"
                if new_dest not in dest_list and len(dest_list) < 20:
                    dest_list.append(new_dest)
                existing_summary["destinations"] = dest_list
                existing_summary["last_signature"] = event.signature_name or existing_summary.get("last_signature")

                incident = Incident(
                    incident_id=inc_id,
                    title=row[1],
                    category=DetectionCategory(category_val),
                    severity=severity,
                    status=IncidentStatus.INVESTIGATING,
                    first_seen=first_seen,
                    last_seen=event.event_timestamp or now_iso,
                    affected_subscriber_ip=subscriber_key,
                    pppoe_username=event.pppoe_username,
                    affected_public_ip=event.source_ip if event.traffic_direction.value == "outbound" else event.destination_ip,
                    evidence_summary=existing_summary,
                    assigned_operator=None,
                    resolution_notes=None,
                    event_count=row[2] + 1,
                    total_bytes=row[3] + (event.bytes or 0),
                    total_packets=row[4] + (event.packets or 0),
                    created_at=first_seen,
                    updated_at=now_iso
                )
                self.db.upsert_incident(incident, linked_event_id=event.event_id)
                return incident

        # Create new incident
        inc_id = f"inc-{category_val}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}-{uuid.uuid4().hex[:6]}"
        rule_name = rule.name if rule else event.signature_name or f"{category_val.replace('_', ' ').title()} Alert"
        title = f"{rule_name} — {subscriber_key}"

        evidence = {
            "initial_event_id": event.event_id,
            "signature": event.signature_name,
            "signature_id": event.signature_id,
            "protocol": event.protocol,
            "destinations": [f"{event.destination_ip}:{event.destination_port}"],
            "attribution_status": event.attribution_status.value,
            "mapping_id": event.mapping_id,
            "rule_id": rule.rule_id if rule else None
        }

        incident = Incident(
            incident_id=inc_id,
            title=title,
            category=DetectionCategory(category_val),
            severity=severity,
            status=IncidentStatus.NEW,
            first_seen=event.event_timestamp or now_iso,
            last_seen=event.event_timestamp or now_iso,
            affected_subscriber_ip=subscriber_key,
            pppoe_username=event.pppoe_username,
            affected_public_ip=event.source_ip if event.traffic_direction.value == "outbound" else event.destination_ip,
            evidence_summary=evidence,
            assigned_operator=None,
            resolution_notes=None,
            event_count=1,
            total_bytes=event.bytes or 0,
            total_packets=event.packets or 0,
            created_at=now_iso,
            updated_at=now_iso
        )

        self.db.upsert_incident(incident, linked_event_id=event.event_id)
        # Log to audit log
        self.db.log_security_audit(
            operator_id="detection_engine",
            action="create_incident",
            target_type="incident",
            target_id=inc_id,
            outcome="success",
            sanitized_details={"title": title, "severity": severity.value, "subscriber": subscriber_key}
        )
        return incident
