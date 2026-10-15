"""
Automated tests for Detection Engine, Incident Correlation, and Notification Cooldowns
"""
import pytest
from datetime import datetime, timezone
from app.database.db import get_db
from app.models.security_schemas import (
    SecurityEvent,
    DetectionCategory,
    SecuritySeverity,
    TrafficDirection,
    AttributionStatus,
    IncidentStatus
)
from app.services.detection_engine import DetectionEngine
from app.services.notification_service import NotificationService

@pytest.fixture
def detection_fixture():
    db = get_db()
    with db._get_connection() as conn:
        conn.execute("DELETE FROM incidents")
        conn.execute("DELETE FROM incident_events")
        conn.execute("DELETE FROM notification_logs")
        conn.commit()
    return db

def test_detection_rule_evaluation_and_incident_correlation(detection_fixture):
    db = detection_fixture
    engine = DetectionEngine(db)

    # Create synthetic high pps DDoS event from subscriber 100.91.0.99
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ev1 = SecurityEvent(
        event_id="evt-ddos-1",
        event_timestamp=now_iso,
        received_timestamp=now_iso,
        sensor_id="sensor-post-cgnat-01",
        source_ip="157.119.69.129",
        source_port=2050,
        destination_ip="1.2.3.4",
        destination_port=80,
        protocol="udp",
        category=DetectionCategory.OUTBOUND_DDOS,
        severity=SecuritySeverity.CRITICAL,
        packets=6000, # Above 5000 min_pps threshold
        bytes=5000000,
        subscriber_cgnat_ip="100.91.0.99",
        pppoe_username="user_ddos_culprit",
        attribution_status=AttributionStatus.VERIFIED
    )

    inc1 = engine.evaluate_event(ev1)
    assert inc1 is not None
    assert inc1.affected_subscriber_ip == "100.91.0.99"
    assert inc1.event_count == 1
    assert inc1.severity == SecuritySeverity.CRITICAL

    # Send second event for same subscriber & category: must correlate into same incident!
    ev2 = SecurityEvent(
        event_id="evt-ddos-2",
        event_timestamp=now_iso,
        received_timestamp=now_iso,
        sensor_id="sensor-post-cgnat-01",
        source_ip="157.119.69.129",
        source_port=2051,
        destination_ip="1.2.3.5",
        destination_port=80,
        protocol="udp",
        category=DetectionCategory.OUTBOUND_DDOS,
        severity=SecuritySeverity.CRITICAL,
        packets=7000,
        bytes=6000000,
        subscriber_cgnat_ip="100.91.0.99",
        pppoe_username="user_ddos_culprit",
        attribution_status=AttributionStatus.VERIFIED
    )

    inc2 = engine.evaluate_event(ev2)
    assert inc2 is not None
    assert inc2.incident_id == inc1.incident_id # Same correlated incident!
    assert inc2.event_count == 2
    assert inc2.total_packets == 13000

def test_detection_exclusions_prevent_incident(detection_fixture):
    db = detection_fixture
    engine = DetectionEngine(db)

    # 1.1.1.1 is in the default port scanning exclusion list
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ev = SecurityEvent(
        event_id="evt-scan-excluded",
        event_timestamp=now_iso,
        received_timestamp=now_iso,
        sensor_id="sensor-post-cgnat-01",
        source_ip="157.119.69.129",
        source_port=2050,
        destination_ip="1.1.1.1", # Excluded destination
        destination_port=53,
        protocol="tcp",
        category=DetectionCategory.PORT_SCANNING,
        severity=SecuritySeverity.LOW,
        subscriber_cgnat_ip="100.91.0.99"
    )

    inc = engine.evaluate_event(ev)
    assert inc is None # Excluded from incident generation!

def test_notification_cooldowns_suppress_floods(detection_fixture):
    db = detection_fixture
    notif_svc = NotificationService(db)

    from app.models.security_schemas import Incident
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    inc = Incident(
        incident_id="inc-test-notif-1",
        title="Test Critical Incident",
        category=DetectionCategory.OUTBOUND_DDOS,
        severity=SecuritySeverity.CRITICAL,
        first_seen=now_iso,
        last_seen=now_iso,
        affected_subscriber_ip="100.91.0.50"
    )

    # First check: should alert
    assert notif_svc.should_alert(inc) is True

    # Immediate second check: must be suppressed by cooldown!
    assert notif_svc.should_alert(inc) is False
