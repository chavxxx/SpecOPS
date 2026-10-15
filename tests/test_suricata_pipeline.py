"""
Automated tests for Suricata Ingestion Pipeline
Tests EVE JSON parsing, deduplication, raw preservation, stats telemetry, and buffer queueing.
"""
import pytest
from app.database.db import get_db
from app.models.security_schemas import CGNATMapping, SubscriberSession
from app.services.suricata_ingest import SuricataIngestService

@pytest.fixture
def suricata_fixture():
    db = get_db()
    with db._get_connection() as conn:
        conn.execute("DELETE FROM security_events")
        conn.execute("DELETE FROM raw_events")
        conn.execute("DELETE FROM opensearch_queue")
        conn.execute("DELETE FROM cgnat_mappings")
        conn.execute("DELETE FROM subscriber_sessions")
        conn.commit()

    # Seed mapping for 157.119.69.129:2048-4095 -> 100.91.0.2
    m = CGNATMapping(
        mapping_id="m-test-1",
        public_ip="157.119.69.129",
        port_start=2048,
        port_end=4095,
        protocol_scope="all",
        subscriber_cgnat_ip="100.91.0.2",
        effective_from="2026-01-01T00:00:00Z"
    )
    db.insert_cgnat_mappings_batch([m])

    sess = SubscriberSession(
        session_id="sess-test-1",
        pppoe_username="test_user_alpha",
        subscriber_cgnat_ip="100.91.0.2",
        access_concentrator="pppoe-ac-ccr2116",
        started_at="2026-01-01T00:00:00Z"
    )
    db.upsert_subscriber_session(sess)
    return db

def test_suricata_alert_ingest_and_enrichment(suricata_fixture):
    db = suricata_fixture
    service = SuricataIngestService(db)

    raw_eve = {
        "timestamp": "2026-10-15T08:30:00.000000+0000",
        "flow_id": 987654321,
        "event_type": "alert",
        "src_ip": "157.119.69.129",
        "src_port": 2500,
        "dest_ip": "198.51.100.10",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2000001,
            "rev": 1,
            "signature": "ET EXPLOIT Outbound Web Scan",
            "category": "Web Application Attack",
            "severity": 1
        },
        "flow": {"pkts_toserver": 5, "bytes_toserver": 450}
    }

    event = service.ingest_event(raw_eve)
    assert event is not None
    assert event.subscriber_cgnat_ip == "100.91.0.2"
    assert event.pppoe_username == "test_user_alpha"
    assert event.attribution_status.value == "verified"
    assert event.severity.value == "high"

    # Verify raw event preserved
    _, raw_payload = db.get_security_event_by_id(event.event_id)
    assert raw_payload is not None
    assert "ET EXPLOIT Outbound Web Scan" in raw_payload

    # Verify enqueued to OpenSearch buffer queue
    q_depth = db.get_opensearch_queue_depth()
    assert q_depth == 1

def test_suricata_deduplication(suricata_fixture):
    db = suricata_fixture
    service = SuricataIngestService(db)

    raw_eve = {
        "timestamp": "2026-10-15T09:00:00.000000+0000",
        "flow_id": 55555,
        "event_type": "alert",
        "src_ip": "157.119.69.129",
        "src_port": 2500,
        "dest_ip": "198.51.100.10",
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "signature_id": 2000002,
            "signature": "Duplicate Test Alert",
            "severity": 2
        }
    }

    ev1 = service.ingest_event(raw_eve)
    ev2 = service.ingest_event(raw_eve) # Identical duplicate

    assert ev1 is not None
    assert ev2 is not None
    assert ev1.event_id == ev2.event_id

    # Verify database has exactly 1 event
    events, total = db.get_security_events(limit=10)
    assert total == 1

def test_suricata_stats_event_updates_health_without_security_event(suricata_fixture):
    db = suricata_fixture
    service = SuricataIngestService(db)

    stats_eve = {
        "timestamp": "2026-10-15T09:10:00.000000+0000",
        "event_type": "stats",
        "stats": {
            "capture": {
                "kernel_packets": 150000,
                "kernel_drops": 0
            }
        }
    }

    result = service.ingest_event(stats_eve)
    assert result is None # Stats does not create security event

    # But health was updated
    health = [h for h in db.get_all_integration_health() if h.integration_name == "Suricata-IDS"]
    assert len(health) == 1
    assert health[0].connectivity == "online"
