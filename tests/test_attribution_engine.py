"""
Automated tests for WISPnet CGNAT Attribution Engine
Tests deterministic lookups, historical validity intervals, PPPoE session correlation,
missing ports, conflicts, and pre-NAT observations.
"""
import pytest
from datetime import datetime, timezone
from app.database.db import get_db
from app.models.security_schemas import (
    CGNATMapping,
    SubscriberSession,
    AttributionLookupRequest,
    AttributionStatus
)
from app.services.attribution_engine import CGNATAttributionEngine

@pytest.fixture
def attribution_fixture(tmp_path):
    db = get_db()
    # Clean test tables
    with db._get_connection() as conn:
        conn.execute("DELETE FROM cgnat_mappings")
        conn.execute("DELETE FROM subscriber_sessions")
        conn.commit()

    # Seed test mappings with historical validity intervals
    # Sub A in January 2026
    m1 = CGNATMapping(
        mapping_id="m-subA-jan",
        public_ip="157.119.69.129",
        port_start=2048,
        port_end=4095,
        protocol_scope="all",
        subscriber_cgnat_ip="100.91.0.10",
        effective_from="2026-01-01T00:00:00Z",
        effective_to="2026-01-31T23:59:59Z",
        source_of_truth="authoritative_test"
    )
    # Sub B in February 2026 (Reassignment of same port block)
    m2 = CGNATMapping(
        mapping_id="m-subB-feb",
        public_ip="157.119.69.129",
        port_start=2048,
        port_end=4095,
        protocol_scope="all",
        subscriber_cgnat_ip="100.91.0.20",
        effective_from="2026-02-01T00:00:00Z",
        effective_to="2026-12-31T23:59:59Z",
        source_of_truth="authoritative_test"
    )
    # Distinct block 4096-6143 for Sub C
    m3 = CGNATMapping(
        mapping_id="m-subC",
        public_ip="157.119.69.129",
        port_start=4096,
        port_end=6143,
        protocol_scope="all",
        subscriber_cgnat_ip="100.91.0.30",
        effective_from="2026-01-01T00:00:00Z",
        effective_to=None,
        source_of_truth="authoritative_test"
    )
    db.insert_cgnat_mappings_batch([m1, m2, m3])

    # Seed PPPoE active sessions
    sess_a = SubscriberSession(
        session_id="sess-subA",
        pppoe_username="user_subA_alpha",
        subscriber_cgnat_ip="100.91.0.10",
        access_concentrator="pppoe-ac-ccr2116",
        started_at="2026-01-10T08:00:00Z",
        ended_at="2026-01-25T18:00:00Z"
    )
    sess_b = SubscriberSession(
        session_id="sess-subB",
        pppoe_username="user_subB_beta",
        subscriber_cgnat_ip="100.91.0.20",
        access_concentrator="pppoe-ac-ccr2116",
        started_at="2026-02-05T10:00:00Z",
        ended_at=None
    )
    db.upsert_subscriber_session(sess_a)
    db.upsert_subscriber_session(sess_b)

    return db

def test_attribution_historical_reassignment(attribution_fixture):
    engine = CGNATAttributionEngine(attribution_fixture)

    # 1. Query for activity on 2026-01-15 (January): must resolve to Sub A!
    req_jan = AttributionLookupRequest(
        public_ip="157.119.69.129",
        public_port=2500,
        protocol="tcp",
        timestamp="2026-01-15T12:00:00Z"
    )
    res_jan = engine.attribute(req_jan)
    assert res_jan.attribution_status == AttributionStatus.VERIFIED
    assert res_jan.subscriber_cgnat_ip == "100.91.0.10"
    assert res_jan.pppoe_username == "user_subA_alpha"
    assert res_jan.mapping_id == "m-subA-jan"
    assert res_jan.port_block_range == "2048-4095"

    # 2. Query for activity on 2026-02-15 (February): must resolve to Sub B!
    req_feb = AttributionLookupRequest(
        public_ip="157.119.69.129",
        public_port=2500,
        protocol="tcp",
        timestamp="2026-02-15T14:30:00Z"
    )
    res_feb = engine.attribute(req_feb)
    assert res_feb.attribution_status == AttributionStatus.VERIFIED
    assert res_feb.subscriber_cgnat_ip == "100.91.0.20"
    assert res_feb.pppoe_username == "user_subB_beta"
    assert res_feb.mapping_id == "m-subB-feb"

    # 3. Query for activity before Jan 2026 (outside validity): must be UNRESOLVED!
    req_old = AttributionLookupRequest(
        public_ip="157.119.69.129",
        public_port=2500,
        protocol="tcp",
        timestamp="2025-11-01T00:00:00Z"
    )
    res_old = engine.attribute(req_old)
    assert res_old.attribution_status == AttributionStatus.UNRESOLVED
    assert res_old.subscriber_cgnat_ip is None

def test_attribution_missing_port_returns_partial_without_guessing(attribution_fixture):
    engine = CGNATAttributionEngine(attribution_fixture)

    req = AttributionLookupRequest(
        public_ip="157.119.69.129",
        public_port=None, # Missing port from abuse report
        timestamp="2026-02-15T12:00:00Z"
    )
    res = engine.attribute(req)
    assert res.attribution_status == AttributionStatus.PARTIAL
    assert res.subscriber_cgnat_ip is None
    assert res.pppoe_username is None
    assert "Subscriber identity will never be guessed" in res.confidence_explanation

def test_attribution_pre_cgnat_direct_observation(attribution_fixture):
    engine = CGNATAttributionEngine(attribution_fixture)

    req = AttributionLookupRequest(
        public_ip="100.91.0.20",
        observation_point="pre_cgnat",
        original_source_ip="100.91.0.20",
        timestamp="2026-02-10T10:00:00Z"
    )
    res = engine.attribute(req)
    assert res.attribution_status == AttributionStatus.VERIFIED
    assert res.subscriber_cgnat_ip == "100.91.0.20"
    assert res.pppoe_username == "user_subB_beta"
    assert res.attribution_method == "pre_cgnat_direct_observation"

def test_attribution_high_confidence_when_session_unrecorded(attribution_fixture):
    engine = CGNATAttributionEngine(attribution_fixture)

    # Sub C has mapping but no active session in db
    req = AttributionLookupRequest(
        public_ip="157.119.69.129",
        public_port=5000,
        protocol="tcp",
        timestamp="2026-03-01T00:00:00Z"
    )
    res = engine.attribute(req)
    assert res.attribution_status == AttributionStatus.HIGH_CONFIDENCE
    assert res.subscriber_cgnat_ip == "100.91.0.30"
    assert res.pppoe_username is None # Not invented
    assert "pppoe_username" in res.unresolved_fields
