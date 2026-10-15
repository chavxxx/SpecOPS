"""
WISPnet Synthetic Security Test Data Seeder
Populates deterministic CGNAT mappings, historical PPPoE sessions, Suricata alerts,
and correlated incidents for acceptance testing and demo environments.
Keeps synthetic test fixtures completely isolated and labeled.
"""
import sys
import os
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Ensure repo root is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.database.db import get_db
from app.models.security_schemas import (
    CGNATConfig,
    SubscriberSession,
    SecurityEvent,
    DetectionCategory,
    SecuritySeverity,
    TrafficDirection,
    AttributionStatus
)
from app.services.cgnat_engine import CGNATEngine
from app.services.suricata_ingest import SuricataIngestService
from app.services.detection_engine import DetectionEngine

def seed_security_data():
    db = get_db()
    print("🔧 [1/4] Generating and validating deterministic CGNAT mappings...")
    cfg = CGNATConfig(
        public_pool_start="157.119.69.129",
        public_pool_end="157.119.69.135", # Sample pool subset for seeding
        subscriber_pool_start="100.91.0.2",
        port_block_size=2048,
        first_eligible_port=2048,
        last_eligible_port=65535,
        mapping_version="v1.0"
    )

    mappings = CGNATEngine.generate_deterministic_mappings(cfg, num_subscribers=100)
    report = CGNATEngine.validate_mappings(mappings)
    if not report.valid:
        print(f"❌ Validation failed: {report.issues}")
        return

    db.clear_cgnat_mappings()
    db.insert_cgnat_mappings_batch(mappings)
    print(f"✅ Loaded {len(mappings)} verified CGNAT mappings ({report.blocks_per_public_ip} blocks/IP).")

    print("🔧 [2/4] Seeding historical PPPoE subscriber sessions...")
    now = datetime.now(timezone.utc)
    t_start = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")

    sample_subscribers = [
        ("100.91.0.2", "wisp_john_doe", "pppoe-ac-ccr2116"),
        ("100.91.0.3", "wisp_acme_corp", "pppoe-ac-ccr2116"),
        ("100.91.0.4", "wisp_maria_santos", "pppoe-ac-ccr2116"),
        ("100.91.0.5", "wisp_brgy_hall_vip", "pppoe-ac-ccr2116"),
        ("100.91.0.6", "wisp_cybercafe_net", "pppoe-ac-ccr2116"),
    ]

    for ip, user, ac in sample_subscribers:
        sess = SubscriberSession(
            session_id=f"sess-ccr2116-{user}",
            pppoe_username=user,
            subscriber_cgnat_ip=ip,
            access_concentrator=ac,
            router_session_id=f"*2A{hash(user) % 1000:03d}",
            started_at=t_start,
            ended_at=None,
            session_source="routeros_active"
        )
        db.upsert_subscriber_session(sess)
    print(f"✅ Loaded {len(sample_subscribers)} active/historical PPPoE sessions.")

    print("🔧 [3/4] Ingesting synthetic Suricata EVE security events...")
    ingest_svc = SuricataIngestService(db)
    detection_engine = DetectionEngine(db)

    # 1. Outbound Port Scan from 100.91.0.2 (translated to 157.119.69.129:2500)
    # Block for 100.91.0.2 is 157.119.69.129 ports 2048-4095
    t_event1 = (now - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for p in range(80, 105):
        raw_scan = {
            "timestamp": t_event1,
            "event_type": "alert",
            "src_ip": "157.119.69.129",
            "src_port": 2500,
            "dest_ip": "198.51.100.50",
            "dest_port": p,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2001288,
                "rev": 3,
                "signature": "ET SCAN Potential Nmap SYN Scan Observed",
                "category": "Attempted Information Leak",
                "severity": 1
            },
            "flow": {"pkts_toserver": 1, "bytes_toserver": 60, "flow_id": 10001 + p}
        }
        ev = ingest_svc.ingest_event(raw_scan)
        if ev:
            detection_engine.evaluate_event(ev)

    # 2. Outbound DDoS flood from 100.91.0.3 (translated to 157.119.69.129:4500)
    # Block for 100.91.0.3 is 157.119.69.129 ports 4096-6143
    t_event2 = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw_ddos = {
        "timestamp": t_event2,
        "event_type": "alert",
        "src_ip": "157.119.69.129",
        "src_port": 4500,
        "dest_ip": "203.0.113.88",
        "dest_port": 53,
        "proto": "UDP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2014726,
            "rev": 5,
            "signature": "ET DOS DNS Amplification Flood Outbound",
            "category": "Attempted Denial of Service",
            "severity": 1
        },
        "flow": {"pkts_toserver": 8500, "bytes_toserver": 12500000, "flow_id": 20002}
    }
    ev2 = ingest_svc.ingest_event(raw_ddos)
    if ev2:
        detection_engine.evaluate_event(ev2)

    # 3. SSH Brute Force from 100.91.0.4 (translated to 157.119.69.129:6500)
    # Block for 100.91.0.4 is 157.119.69.129 ports 6144-8191
    t_event3 = (now - timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for i in range(12):
        raw_ssh = {
            "timestamp": t_event3,
            "event_type": "alert",
            "src_ip": "157.119.69.129",
            "src_port": 6500,
            "dest_ip": "198.51.100.22",
            "dest_port": 22,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2001219,
                "rev": 12,
                "signature": "ET SCAN Potential SSH Brute-Force Password Guessing",
                "category": "Attempted Administrator Privilege Gain",
                "severity": 1
            },
            "flow": {"pkts_toserver": 30, "bytes_toserver": 4500, "flow_id": 30000 + i}
        }
        ev3 = ingest_svc.ingest_event(raw_ssh)
        if ev3:
            detection_engine.evaluate_event(ev3)

    # 4. Inbound DDoS targeting Public IP (157.119.69.130:443)
    t_event4 = (now - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw_inbound = {
        "timestamp": t_event4,
        "event_type": "alert",
        "src_ip": "185.220.101.5",
        "src_port": 54321,
        "dest_ip": "157.119.69.130",
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2100366,
            "rev": 7,
            "signature": "GPL ATTACK_RESPONSE Inbound SYN Flood Targeting Web Server",
            "category": "Denial of Service",
            "severity": 1
        },
        "flow": {"pkts_toserver": 15000, "bytes_toserver": 9000000, "flow_id": 40001}
    }
    ev4 = ingest_svc.ingest_event(raw_inbound)
    if ev4:
        detection_engine.evaluate_event(ev4)

    # 5. Pre-CGNAT observation on 100.91.0.5 directly
    raw_precgnat = {
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type": "alert",
        "src_ip": "100.91.0.5",
        "src_port": 34120,
        "dest_ip": "93.184.216.34",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2024001,
            "rev": 2,
            "signature": "ET MALWARE Win32/CobaltStrike Beacon Observed",
            "category": "A Network Trojan was detected",
            "severity": 1
        },
        "flow": {"pkts_toserver": 12, "bytes_toserver": 1400, "flow_id": 50001}
    }
    ev5 = ingest_svc.ingest_event(raw_precgnat, sensor_id="sensor-pre-cgnat-01", observation_point="pre_cgnat")
    if ev5:
        detection_engine.evaluate_event(ev5)

    print("✅ Ingested synthetic Suricata events & triggered correlation.")

    print("🔧 [4/4] Verifying generated incidents...")
    incidents, total_inc = db.get_incidents(limit=10)
    print(f"✅ Total Active Incidents Correlated: {total_inc}")
    for inc in incidents:
        print(f"   • [{inc.severity.value.upper()}] {inc.title} (Subscriber: {inc.affected_subscriber_ip}, User: {inc.pppoe_username})")

    print("\n🎉 Synthetic security data seeding complete!")

if __name__ == "__main__":
    seed_security_data()
