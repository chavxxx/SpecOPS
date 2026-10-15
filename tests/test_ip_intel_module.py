"""
Comprehensive Test Suite for IP Reputation & Blacklist Intelligence Platform
WISP Network & Data Solutions (WISPnet)
"""
import pytest
import ipaddress
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.database.db import get_db
from app.models.ip_intel_schemas import (
    ProviderResult,
    ProviderType,
    ListingCategory,
    ReputationStatus,
    SingleLookupRequest
)
from app.services.ip_intel.base import (
    is_valid_ip,
    get_ip_version,
    is_private_or_special_ip,
    format_dnsbl_query
)
from app.services.ip_intel.dns_resolver import DNSQueryResult
from app.services.ip_intel.dnsbl_provider import DNSBLProvider
from app.services.ip_intel.abuseipdb_provider import AbuseIPDBProvider
from app.services.ip_intel.virustotal_provider import VirusTotalProvider
from app.services.ip_intel.greynoise_provider import GreyNoiseProvider
from app.services.ip_intel.rdns_provider import ReverseDNSProvider
from app.services.ip_intel.scoring_engine import ReputationScoringEngine
from app.services.ip_intel.cgnat_correlation import CGNATReputationCorrelator
from app.services.ip_intel.scanner import get_ip_intel_scanner

# ---------------------------------------------------------------------------
# 1. Base Helpers & IP Normalization Tests
# ---------------------------------------------------------------------------
def test_ip_validation_and_helpers():
    assert is_valid_ip("157.119.69.129") is True
    assert is_valid_ip("2001:db8::1") is True
    assert is_valid_ip("999.999.999.999") is False
    assert is_valid_ip("not-an-ip") is False

    assert get_ip_version("157.119.69.129") == 4
    assert get_ip_version("2001:db8::1") == 6

    # Test special IP checks
    assert is_private_or_special_ip("127.0.0.1")[0] is True
    assert is_private_or_special_ip("192.168.1.1")[0] is True
    assert is_private_or_special_ip("100.64.0.5")[0] is True  # RFC 6598 CGNAT
    assert is_private_or_special_ip("203.0.113.10")[0] is True  # Documentation IP
    assert is_private_or_special_ip("2001:db8::1")[0] is True  # Documentation IPv6
    assert is_private_or_special_ip("157.119.69.129")[0] is False  # Public ISP IP

    # Test DNSBL query formatting
    assert format_dnsbl_query("157.119.69.129", "zen.spamhaus.org") == "129.69.119.157.zen.spamhaus.org"

# ---------------------------------------------------------------------------
# 2. DNSBL Provider Parsing Tests (Spamhaus, SpamCop, Barracuda)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_spamhaus_zen_parsing_rules(monkeypatch):
    provider = DNSBLProvider({
        "provider_id": "spamhaus_zen",
        "provider_name": "Spamhaus ZEN",
        "provider_type": "dnsbl",
        "dns_zone": "zen.spamhaus.org"
    })

    # Case A: SBL Spam listing (127.0.0.2)
    async def mock_sbl(*args, **kwargs):
        return DNSQueryResult("query", "A", "NOERROR", 0, ["127.0.0.2"], 12.0, "8.8.8.8")
    monkeypatch.setattr("app.services.ip_intel.dnsbl_provider.async_query_dns", mock_sbl)
    res_sbl = await provider.check_ip("157.119.69.129")
    assert res_sbl.is_listed is True
    assert res_sbl.risk_status == ReputationStatus.LISTED
    assert res_sbl.listing_category == ListingCategory.SPAM
    assert "SBL" in res_sbl.source_classification

    # Case B: XBL Botnet/Malware listing (127.0.0.4) -> HIGH_RISK
    async def mock_xbl(*args, **kwargs):
        return DNSQueryResult("query", "A", "NOERROR", 0, ["127.0.0.4"], 15.0, "8.8.8.8")
    monkeypatch.setattr("app.services.ip_intel.dnsbl_provider.async_query_dns", mock_xbl)
    res_xbl = await provider.check_ip("157.119.69.129")
    assert res_xbl.is_listed is True
    assert res_xbl.risk_status == ReputationStatus.HIGH_RISK
    assert res_xbl.listing_category == ListingCategory.BOTNET_C2

    # Case C: Clean / Not Listed (NXDOMAIN)
    async def mock_nxdomain(*args, **kwargs):
        return DNSQueryResult("query", "A", "NXDOMAIN", 3, [], 10.0, "8.8.8.8")
    monkeypatch.setattr("app.services.ip_intel.dnsbl_provider.async_query_dns", mock_nxdomain)
    res_clean = await provider.check_ip("157.119.69.129")
    assert res_clean.is_listed is False
    assert res_clean.risk_status == ReputationStatus.CLEAN

    # Case D: Blocked Query (127.255.255.254 - Public resolver detected)
    async def mock_blocked(*args, **kwargs):
        return DNSQueryResult("query", "A", "NOERROR", 0, ["127.255.255.254"], 10.0, "8.8.8.8")
    monkeypatch.setattr("app.services.ip_intel.dnsbl_provider.async_query_dns", mock_blocked)
    res_blocked = await provider.check_ip("157.119.69.129")
    assert res_blocked.is_listed is False
    assert res_blocked.lookup_status == "blocked"
    assert res_blocked.risk_status == ReputationStatus.INCOMPLETE

    # Case E: DNS Timeout
    async def mock_timeout(*args, **kwargs):
        return DNSQueryResult("query", "A", "TIMEOUT", -1, [], 3000.0, "8.8.8.8")
    monkeypatch.setattr("app.services.ip_intel.dnsbl_provider.async_query_dns", mock_timeout)
    res_timeout = await provider.check_ip("157.119.69.129")
    assert res_timeout.lookup_status == "timeout"
    assert res_timeout.risk_status == ReputationStatus.INCOMPLETE

@pytest.mark.asyncio
async def test_spamcop_and_barracuda_parsing(monkeypatch):
    provider_cop = DNSBLProvider({
        "provider_id": "spamcop",
        "provider_name": "SpamCop",
        "provider_type": "dnsbl",
        "dns_zone": "bl.spamcop.net"
    })

    # Listed in SpamCop (127.0.0.2)
    async def mock_cop_listed(*args, **kwargs):
        return DNSQueryResult("query", "A", "NOERROR", 0, ["127.0.0.2"], 20.0, "8.8.8.8")
    monkeypatch.setattr("app.services.ip_intel.dnsbl_provider.async_query_dns", mock_cop_listed)
    res = await provider_cop.check_ip("157.119.69.129")
    assert res.is_listed is True
    assert res.risk_status == ReputationStatus.LISTED
    assert res.listing_category == ListingCategory.SPAM

# ---------------------------------------------------------------------------
# 3. AbuseIPDB Provider Tests
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_abuseipdb_provider_states(monkeypatch):
    # Case A: Missing API key returns unsupported
    prov_nokey = AbuseIPDBProvider({"provider_id": "abuseipdb", "provider_name": "AbuseIPDB", "provider_type": "abuse_api"})
    res_nokey = await prov_nokey.check_ip("157.119.69.129")
    assert res_nokey.lookup_status == "unsupported"
    assert "API key not configured" in res_nokey.evidence_summary

    # Case B: With API key & mocked HTTP 200 response
    prov_keyed = AbuseIPDBProvider({
        "provider_id": "abuseipdb",
        "provider_name": "AbuseIPDB",
        "provider_type": "abuse_api",
        "api_key": "test_api_key_123"
    })

    class MockResponse:
        status_code = 200
        headers = {"x-ratelimit-remaining": "995"}
        def json(self):
            return {
                "data": {
                    "ipAddress": "157.119.69.129",
                    "abuseConfidenceScore": 85,
                    "totalReports": 42,
                    "numDistinctUsers": 12,
                    "lastReportedAt": "2026-10-15T08:00:00Z",
                    "usageType": "Fixed Line ISP"
                }
            }

    async def mock_get(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)
    res_keyed = await prov_keyed.check_ip("157.119.69.129")
    assert res_keyed.lookup_status == "completed"
    assert res_keyed.is_listed is True
    assert res_keyed.risk_status == ReputationStatus.HIGH_RISK
    assert res_keyed.source_score == 85.0

# ---------------------------------------------------------------------------
# 4. Reverse DNS & FCrDNS Provider Tests
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_rdns_fcrdns_provider(monkeypatch):
    prov = ReverseDNSProvider({
        "provider_id": "rdns_ptr",
        "provider_name": "Reverse DNS",
        "provider_type": "email_reputation"
    })

    # Case A: Missing PTR record
    async def mock_no_ptr(qname, qtype_str, *args, **kwargs):
        return DNSQueryResult(qname, qtype_str, "NXDOMAIN", 3, [], 10.0, "8.8.8.8")
    monkeypatch.setattr("app.services.ip_intel.rdns_provider.async_query_dns", mock_no_ptr)
    res_noptr = await prov.check_ip("157.119.69.129")
    assert res_noptr.is_listed is True
    assert res_noptr.listing_category == ListingCategory.DELIVERABILITY
    assert res_noptr.risk_status == ReputationStatus.SUSPICIOUS

    # Case B: Valid FCrDNS static match
    async def mock_valid_fcrdns(qname, qtype_str, *args, **kwargs):
        if qtype_str == "PTR":
            return DNSQueryResult(qname, "PTR", "NOERROR", 0, ["static-gateway.wispnet.net"], 10.0, "8.8.8.8")
        else:
            return DNSQueryResult(qname, "A", "NOERROR", 0, ["157.119.69.129"], 10.0, "8.8.8.8")
    monkeypatch.setattr("app.services.ip_intel.rdns_provider.async_query_dns", mock_valid_fcrdns)
    res_valid = await prov.check_ip("157.119.69.129")
    assert res_valid.is_listed is False
    assert res_valid.risk_status == ReputationStatus.CLEAN

# ---------------------------------------------------------------------------
# 5. Reputation Scoring Engine Rules Tests
# ---------------------------------------------------------------------------
def test_scoring_engine_rules():
    # Case A: All completed clean -> CLEAN
    clean_res = [
        ProviderResult(
            provider_id="spamhaus_zen", provider_name="Spamhaus", provider_type=ProviderType.DNSBL,
            queried_ip="8.8.8.8", check_timestamp="2026-10-15T00:00:00Z", lookup_status="completed",
            is_listed=False, risk_status=ReputationStatus.CLEAN
        ),
        ProviderResult(
            provider_id="rdns_ptr", provider_name="rDNS", provider_type=ProviderType.EMAIL_REPUTATION,
            queried_ip="8.8.8.8", check_timestamp="2026-10-15T00:00:00Z", lookup_status="completed",
            is_listed=False, risk_status=ReputationStatus.CLEAN
        )
    ]
    status, score, factors, exp = ReputationScoringEngine.evaluate(clean_res)
    assert status == ReputationStatus.CLEAN
    assert score == 0.0

    # Case B: One verified listing -> LISTED
    one_listed = [
        ProviderResult(
            provider_id="spamcop", provider_name="SpamCop", provider_type=ProviderType.DNSBL,
            queried_ip="157.119.69.129", check_timestamp="2026-10-15T00:00:00Z", lookup_status="completed",
            is_listed=True, listing_category=ListingCategory.SPAM, risk_status=ReputationStatus.LISTED,
            evidence_summary="Listed in SpamCop BL"
        )
    ]
    status_b, score_b, factors_b, _ = ReputationScoringEngine.evaluate(one_listed)
    assert status_b == ReputationStatus.LISTED
    assert score_b >= 25.0

    # Case C: Multiple independent listings / severe botnet finding -> HIGH_RISK
    high_risk = [
        ProviderResult(
            provider_id="spamhaus_zen", provider_name="Spamhaus", provider_type=ProviderType.DNSBL,
            queried_ip="157.119.69.129", check_timestamp="2026-10-15T00:00:00Z", lookup_status="completed",
            is_listed=True, listing_category=ListingCategory.BOTNET_C2, risk_status=ReputationStatus.HIGH_RISK,
            evidence_summary="XBL botnet C2"
        ),
        ProviderResult(
            provider_id="abuseipdb", provider_name="AbuseIPDB", provider_type=ProviderType.ABUSE_API,
            queried_ip="157.119.69.129", check_timestamp="2026-10-15T00:00:00Z", lookup_status="completed",
            is_listed=True, listing_category=ListingCategory.ABUSE_REPORTS, source_score=90.0,
            risk_status=ReputationStatus.HIGH_RISK, evidence_summary="Confidence 90%"
        )
    ]
    status_c, score_c, factors_c, _ = ReputationScoringEngine.evaluate(high_risk)
    assert status_c == ReputationStatus.HIGH_RISK
    assert score_c >= 70.0

# ---------------------------------------------------------------------------
# 6. CGNAT Correlation & Attribution Integration Tests
# ---------------------------------------------------------------------------
def test_cgnat_attribution_correlation(tmp_path):
    db = get_db()
    # Seed a known CGNAT mapping
    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO cgnat_mappings (
                mapping_id, public_ip, port_start, port_end, subscriber_cgnat_ip,
                pppoe_username, effective_from, effective_to
            ) VALUES (
                'test-cgnat-map-1', '157.119.69.129', 2048, 4095, '100.91.0.2',
                'cust_00002@wispnet', '2026-01-01T00:00:00Z', NULL
            );
        """)
        cursor.execute("""
            INSERT OR REPLACE INTO subscriber_sessions (
                session_id, pppoe_username, subscriber_cgnat_ip, access_concentrator, started_at
            ) VALUES (
                'test-sess-1', 'cust_00002@wispnet', '100.91.0.2', 'core-ac', '2026-01-01T00:00:00Z'
            );
        """)
        conn.commit()

    # Case A: Exact port given (port 2500 within 2048-4095) -> Exact attribution!
    brief_exact = CGNATReputationCorrelator.correlate_cgnat(
        ip_str="157.119.69.129",
        event_port=2500,
        db=db
    )
    assert brief_exact.is_cgnat_public_pool is True
    assert brief_exact.exact_match is True
    assert brief_exact.subscriber_cgnat_ip == "100.91.0.2"
    assert brief_exact.pppoe_username == "cust_00002@wispnet"
    assert brief_exact.allocated_port_block == "2048-4095"

    # Case B: Missing port -> Strictly refuses to guess!
    brief_missing = CGNATReputationCorrelator.correlate_cgnat(
        ip_str="157.119.69.129",
        event_port=None,
        db=db
    )
    assert brief_missing.is_cgnat_public_pool is True
    assert brief_missing.exact_match is False
    assert brief_missing.subscriber_cgnat_ip is None  # Never guess
    assert brief_missing.attribution_status == "partial"

# ---------------------------------------------------------------------------
# 7. REST API Endpoints Integration Tests
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ip_intel_api_overview_and_check(admin_headers, analyst_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Overview KPIs endpoint
        res_ov = await client.get("/api/ip-intelligence/overview", headers=analyst_headers)
        assert res_ov.status_code == 200
        ov_data = res_ov.json()
        assert "total_monitored_ips" in ov_data
        assert "provider_summary" in ov_data

        # 2. Single IP lookup endpoint
        res_check = await client.post(
            "/api/ip-intelligence/check",
            headers=analyst_headers,
            json={"ip_address": "157.119.69.129", "depth": "standard"}
        )
        assert res_check.status_code == 200
        check_data = res_check.json()
        assert check_data["ip_address"] == "157.119.69.129"
        assert "overall_status" in check_data
        assert "overall_score" in check_data
        assert len(check_data["provider_results"]) > 0

        # 3. Public Inventory endpoints
        res_inv = await client.get("/api/ip-intelligence/inventory", headers=analyst_headers)
        assert res_inv.status_code == 200

        # Admin can add inventory
        res_add = await client.post(
            "/api/ip-intelligence/inventory",
            headers=admin_headers,
            json={
                "ip_address": "157.119.69.200",
                "cidr_allocation": "157.119.69.128/25",
                "purpose_role": "CGNAT Pool"
            }
        )
        assert res_add.status_code == 200
        assert res_add.json()["success"] is True

        # Test CIDR block addition
        res_add_cidr = await client.post(
            "/api/ip-intelligence/inventory",
            headers=admin_headers,
            json={
                "ip_address": "157.119.69.240/29",
                "purpose_role": "Core Infrastructure"
            }
        )
        assert res_add_cidr.status_code == 200
        data_cidr = res_add_cidr.json()
        assert data_cidr["success"] is True
        assert data_cidr["count"] == 6  # 6 usable host IPs in /29

        # Test hyphenated IP range addition
        res_add_range = await client.post(
            "/api/ip-intelligence/inventory",
            headers=admin_headers,
            json={
                "ip_address": "157.119.69.250-157.119.69.253",
                "purpose_role": "Static Business"
            }
        )
        assert res_add_range.status_code == 200
        data_range = res_add_range.json()
        assert data_range["success"] is True
        assert data_range["count"] == 4

        # Test invalid target rejected with 400
        res_add_invalid = await client.post(
            "/api/ip-intelligence/inventory",
            headers=admin_headers,
            json={"ip_address": "invalid-ip-or-range"}
        )
        assert res_add_invalid.status_code == 400

        # Analyst cannot add inventory (RBAC check)
        res_add_unauth = await client.post(
            "/api/ip-intelligence/inventory",
            headers=analyst_headers,
            json={"ip_address": "157.119.69.201"}
        )
        assert res_add_unauth.status_code == 403

        # Test Inventory Search & X-Total-Count Header
        res_search = await client.get("/api/ip-intelligence/inventory?search=157.119.69.250", headers=analyst_headers)
        assert res_search.status_code == 200
        assert "x-total-count" in res_search.headers
        search_items = res_search.json()
        assert len(search_items) >= 1
        assert any(it["ip_address"] == "157.119.69.250" for it in search_items)

        # Test Delete Inventory IP (Analyst forbidden, Admin allowed)
        res_del_unauth = await client.delete("/api/ip-intelligence/inventory/157.119.69.253", headers=analyst_headers)
        assert res_del_unauth.status_code == 403

        res_del_admin = await client.delete("/api/ip-intelligence/inventory/157.119.69.253", headers=admin_headers)
        assert res_del_admin.status_code == 200
        assert res_del_admin.json()["success"] is True

        # 4. Providers list and health test
        res_provs = await client.get("/api/ip-intelligence/providers", headers=analyst_headers)
        assert res_provs.status_code == 200
        provs = res_provs.json()
        assert len(provs) >= 9
        assert any(p["provider_id"] == "gaming_compat" for p in provs)

        # Admin tests provider connectivity (rDNS and gaming_compat)
        res_test = await client.post("/api/ip-intelligence/providers/rdns_ptr/test", headers=admin_headers)
        assert res_test.status_code == 200
        assert res_test.json()["provider_id"] == "rdns_ptr"

        res_test_gaming = await client.post("/api/ip-intelligence/providers/gaming_compat/test", headers=admin_headers)
        assert res_test_gaming.status_code == 200
        assert res_test_gaming.json()["provider_id"] == "gaming_compat"

        # 5. Online Gaming & Anti-Cheat Compatibility endpoint
        res_gaming = await client.get("/api/ip-intelligence/ip/157.119.69.129/gaming", headers=analyst_headers)
        assert res_gaming.status_code == 200
        gaming_data = res_gaming.json()
        assert gaming_data["ip_address"] == "157.119.69.129"
        assert gaming_data["overall_grade"] in ("A+", "A", "B", "C", "F")
        assert len(gaming_data["games"]) >= 8
        game_ids = [g["game_id"] for g in gaming_data["games"]]
        assert "codm_garena" in game_ids
        assert "codm_activision" in game_ids
        assert "mlbb" in game_ids
        assert "valorant_riot" in game_ids
        assert "roblox" in game_ids
