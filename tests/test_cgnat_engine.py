"""
Automated tests for WISPnet CGNAT Mapping Engine & Validator
Tests port boundaries, transitions, alignment, overlaps, reassignments, and export/import.
"""
import pytest
from app.models.security_schemas import CGNATConfig, CGNATMapping
from app.services.cgnat_engine import CGNATEngine

def test_cgnat_generation_boundaries_and_transitions():
    cfg = CGNATConfig(
        public_pool_start="157.119.69.129",
        public_pool_end="157.119.69.130",
        subscriber_pool_start="100.91.0.2",
        port_block_size=2048,
        first_eligible_port=2048,
        last_eligible_port=65535,
        mapping_version="v1.0"
    )

    mappings = CGNATEngine.generate_deterministic_mappings(cfg, num_subscribers=60)
    assert len(mappings) == 60

    # First block of first public IP
    m0 = mappings[0]
    assert m0.public_ip == "157.119.69.129"
    assert m0.port_start == 2048
    assert m0.port_end == 4095
    assert m0.subscriber_cgnat_ip == "100.91.0.2"

    # Second block
    m1 = mappings[1]
    assert m1.public_ip == "157.119.69.129"
    assert m1.port_start == 4096
    assert m1.port_end == 6143
    assert m1.subscriber_cgnat_ip == "100.91.0.3"

    # Blocks per IP with span 63488 (2048 to 65535) is 31 blocks: 2048, 4096, ... 63488
    # The 31st block (index 30) should be on 157.119.69.129
    m30 = mappings[30]
    assert m30.public_ip == "157.119.69.129"
    assert m30.port_start == 63488
    assert m30.port_end == 65535
    assert m30.subscriber_cgnat_ip == "100.91.0.32"

    # The 32nd block (index 31) transitions to the next public IP 157.119.69.130!
    m31 = mappings[31]
    assert m31.public_ip == "157.119.69.130"
    assert m31.port_start == 2048
    assert m31.port_end == 4095
    assert m31.subscriber_cgnat_ip == "100.91.0.33"

def test_cgnat_validation_clean_table():
    cfg = CGNATConfig(
        public_pool_start="157.119.69.129",
        public_pool_end="157.119.69.130",
        subscriber_pool_start="100.91.0.2",
        port_block_size=2048,
        first_eligible_port=2048,
        last_eligible_port=65535
    )
    mappings = CGNATEngine.generate_deterministic_mappings(cfg, num_subscribers=20)
    report = CGNATEngine.validate_mappings(mappings)
    assert report.valid is True
    assert len(report.issues) == 0
    assert report.total_mappings_checked == 20
    assert report.unique_public_ips == 1
    assert report.unique_subscriber_ips == 20

def test_cgnat_validation_detects_overlapping_ports():
    bad_mappings = [
        CGNATMapping(
            mapping_id="m1",
            public_ip="157.119.69.129",
            port_start=2048,
            port_end=4095,
            subscriber_cgnat_ip="100.91.0.2",
            effective_from="2026-01-01T00:00:00Z"
        ),
        CGNATMapping(
            mapping_id="m2",
            public_ip="157.119.69.129",
            port_start=3000, # Overlaps with 2048-4095!
            port_end=5047,
            subscriber_cgnat_ip="100.91.0.3",
            effective_from="2026-01-01T00:00:00Z"
        )
    ]
    report = CGNATEngine.validate_mappings(bad_mappings)
    assert report.valid is False
    codes = [i.code for i in report.issues]
    assert "OVERLAPPING_PORT_BLOCK" in codes

def test_cgnat_validation_detects_duplicate_subscriber():
    bad_mappings = [
        CGNATMapping(
            mapping_id="m1",
            public_ip="157.119.69.129",
            port_start=2048,
            port_end=4095,
            subscriber_cgnat_ip="100.91.0.2",
            effective_from="2026-01-01T00:00:00Z"
        ),
        CGNATMapping(
            mapping_id="m2",
            public_ip="157.119.69.130",
            port_start=2048,
            port_end=4095,
            subscriber_cgnat_ip="100.91.0.2", # Duplicate subscriber active at same time!
            effective_from="2026-01-01T00:00:00Z"
        )
    ]
    report = CGNATEngine.validate_mappings(bad_mappings)
    assert report.valid is False
    codes = [i.code for i in report.issues]
    assert "DUPLICATE_SUBSCRIBER_ALLOCATION" in codes

def test_cgnat_validation_historical_reassignment_allowed_when_intervals_do_not_overlap():
    valid_reassigned_mappings = [
        # Block 2048-4095 assigned to Sub A in January
        CGNATMapping(
            mapping_id="m1-old",
            public_ip="157.119.69.129",
            port_start=2048,
            port_end=4095,
            subscriber_cgnat_ip="100.91.0.2",
            effective_from="2026-01-01T00:00:00Z",
            effective_to="2026-01-31T23:59:59Z"
        ),
        # Block 2048-4095 reassigned to Sub B in February
        CGNATMapping(
            mapping_id="m1-new",
            public_ip="157.119.69.129",
            port_start=2048,
            port_end=4095,
            subscriber_cgnat_ip="100.91.0.99",
            effective_from="2026-02-01T00:00:00Z",
            effective_to=None
        )
    ]
    report = CGNATEngine.validate_mappings(valid_reassigned_mappings)
    assert report.valid is True
    assert len(report.issues) == 0

def test_cgnat_validation_out_of_range_and_misaligned():
    bad_mappings = [
        CGNATMapping(
            mapping_id="bad-port",
            public_ip="157.119.69.129",
            port_start=1024, # Below first eligible port 2048
            port_end=3071,
            subscriber_cgnat_ip="100.91.0.2",
            effective_from="2026-01-01T00:00:00Z"
        ),
        CGNATMapping(
            mapping_id="bad-max",
            public_ip="157.119.69.129",
            port_start=64000,
            port_end=66047, # Exceeds 65535
            subscriber_cgnat_ip="100.91.0.3",
            effective_from="2026-01-01T00:00:00Z"
        )
    ]
    report = CGNATEngine.validate_mappings(bad_mappings, first_eligible_port=2048, last_eligible_port=65535)
    assert report.valid is False
    codes = [i.code for i in report.issues]
    assert "PORT_BELOW_MINIMUM" in codes
    assert "PORT_EXCEEDS_MAXIMUM" in codes

def test_cgnat_routeros_v7_export_and_csv_roundtrip():
    cfg = CGNATConfig(
        public_pool_start="157.119.69.129",
        public_pool_end="157.119.69.129",
        subscriber_pool_start="100.91.0.2",
        port_block_size=2048,
        first_eligible_port=2048,
        last_eligible_port=65535
    )
    mappings = CGNATEngine.generate_deterministic_mappings(cfg, num_subscribers=3)

    # Test RouterOS v7 export
    rsc = CGNATEngine.export_routeros_v7_script(mappings)
    assert "/ip firewall nat" in rsc
    assert "add chain=srcnat action=src-nat protocol=tcp src-address=100.91.0.2 to-addresses=157.119.69.129 to-ports=2048-4095" in rsc
    assert "add chain=srcnat action=src-nat protocol=udp src-address=100.91.0.2 to-addresses=157.119.69.129 to-ports=2048-4095" in rsc

    # Test CSV roundtrip
    csv_out = CGNATEngine.export_csv(mappings)
    assert "157.119.69.129" in csv_out
    imported = CGNATEngine.import_csv(csv_out)
    assert len(imported) == 3
    assert imported[0].subscriber_cgnat_ip == "100.91.0.2"
    assert imported[0].port_start == 2048
    assert imported[0].port_end == 4095
