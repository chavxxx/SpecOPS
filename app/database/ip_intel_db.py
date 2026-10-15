"""
Database Mixin for IP Reputation & Blacklist Intelligence Module
Handles schema management, default provider seeding, observations caching,
inventory tracking, scan queue persistence, and audit logging.
"""
import sqlite3
import json
import uuid
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timezone

def get_utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

class IPIntelDatabaseMixin:
    """Mixin for DatabaseManager adding IP Intelligence and Blacklist tables and methods"""

    def _init_ip_intel_db(self, conn: sqlite3.Connection):
        cursor = conn.cursor()

        # 1. Public IP Inventory table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_intel_inventory (
                id TEXT PRIMARY KEY,
                ip_address TEXT UNIQUE NOT NULL,
                ip_version INTEGER NOT NULL,
                cidr_allocation TEXT,
                inventory_identifier TEXT,
                routing_context TEXT,
                purpose_role TEXT DEFAULT 'CGNAT Pool',
                monitoring_status TEXT DEFAULT 'active',
                current_reputation_status TEXT DEFAULT 'UNKNOWN',
                active_listing_count INTEGER DEFAULT 0,
                historical_listing_count INTEGER DEFAULT 0,
                risk_score REAL DEFAULT 0.0,
                latest_abuse_report TEXT,
                last_security_alert TEXT,
                last_checked_at TIMESTAMP,
                last_successful_lookup_at TIMESTAMP,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 2. Providers configuration table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_intel_providers (
                provider_id TEXT PRIMARY KEY,
                provider_name TEXT NOT NULL,
                provider_type TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                api_endpoint TEXT,
                api_key TEXT,
                auth_method TEXT DEFAULT 'none',
                dns_zone TEXT,
                timeout_seconds REAL DEFAULT 5.0,
                rate_limit_rpm INTEGER DEFAULT 60,
                max_concurrent INTEGER DEFAULT 5,
                cache_duration_positive_sec INTEGER DEFAULT 1800,
                cache_duration_negative_sec INTEGER DEFAULT 7200,
                supported_indicators TEXT DEFAULT '["ipv4"]',
                quota_limit INTEGER,
                quota_remaining INTEGER,
                quota_reset_at TIMESTAMP,
                last_successful_request_at TIMESTAMP,
                last_error TEXT,
                documentation_url TEXT,
                terms_notice TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 3. Observations / Results cache table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_intel_observations (
                observation_id TEXT PRIMARY KEY,
                ip_address TEXT NOT NULL,
                ip_version INTEGER NOT NULL,
                provider_id TEXT NOT NULL,
                provider_name TEXT NOT NULL,
                check_timestamp TIMESTAMP NOT NULL,
                lookup_status TEXT NOT NULL,
                duration_ms REAL DEFAULT 0.0,
                is_cached INTEGER DEFAULT 0,
                is_listed INTEGER DEFAULT 0,
                listing_category TEXT DEFAULT 'none',
                source_classification TEXT,
                source_score REAL,
                risk_status TEXT NOT NULL,
                evidence_summary TEXT,
                raw_record_json TEXT,
                error_type TEXT,
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 4. Reputation history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_intel_history (
                history_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                event_type TEXT NOT NULL,
                previous_status TEXT,
                new_status TEXT,
                details TEXT,
                triggered_by TEXT DEFAULT 'scanner',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 5. Scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_intel_scans (
                scan_id TEXT PRIMARY KEY,
                scan_type TEXT NOT NULL,
                target_count INTEGER DEFAULT 0,
                completed_count INTEGER DEFAULT 0,
                failed_count INTEGER DEFAULT 0,
                listed_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'pending',
                scan_depth TEXT DEFAULT 'standard',
                selected_providers TEXT,
                concurrency_limit INTEGER DEFAULT 5,
                progress_percent REAL DEFAULT 0.0,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                created_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 6. Scan items table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_intel_scan_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                attempts INTEGER DEFAULT 0,
                reputation_status TEXT,
                active_listings INTEGER DEFAULT 0,
                error_message TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 7. Investigations table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_intel_investigations (
                investigation_id TEXT PRIMARY KEY,
                ip_address TEXT NOT NULL,
                title TEXT NOT NULL,
                status TEXT DEFAULT 'open',
                severity TEXT DEFAULT 'medium',
                attributed_subscriber_ip TEXT,
                attributed_pppoe_user TEXT,
                port_block TEXT,
                time_window_start TIMESTAMP,
                time_window_end TIMESTAMP,
                evidence_summary TEXT,
                operator_notes TEXT,
                assigned_operator TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 8. Audit logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_intel_audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                details_json TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Indexes for fast querying
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_intel_inv_ip ON ip_intel_inventory (ip_address);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_intel_obs_ip_time ON ip_intel_observations (ip_address, check_timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_intel_obs_prov ON ip_intel_observations (provider_id, is_listed);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_intel_hist_ip ON ip_intel_history (ip_address, timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_intel_scan_items_scan ON ip_intel_scan_items (scan_id, status);")

        conn.commit()

        # Seed default providers if table empty
        self._seed_default_providers(cursor, conn)
        # Seed default CGNAT inventory pool if table empty
        self._seed_default_inventory(cursor, conn)

    def _seed_default_providers(self, cursor: sqlite3.Cursor, conn: sqlite3.Connection):
        cursor.execute("SELECT COUNT(*) FROM ip_intel_providers;")
        count = cursor.fetchone()[0]
        if count > 0:
            return

        providers = [
            (
                "spamhaus_zen",
                "Spamhaus ZEN",
                "dnsbl",
                1,
                None,
                None,
                "dns",
                "zen.spamhaus.org",
                5.0,
                60,
                5,
                1800,
                7200,
                json.dumps(["ipv4"]),
                None,
                None,
                None,
                "https://www.spamhaus.org/blocklists/zen/",
                "Requires direct recursive DNS resolver or commercial Data Query Service (DQS) key. Queries via public open resolvers (e.g. 8.8.8.8) are blocked."
            ),
            (
                "spamcop",
                "SpamCop Bl",
                "dnsbl",
                1,
                None,
                None,
                "dns",
                "bl.spamcop.net",
                5.0,
                60,
                5,
                1800,
                7200,
                json.dumps(["ipv4"]),
                None,
                None,
                None,
                "https://www.spamcop.net/bl.shtml",
                "DNS-based blacklist of verified spam-emitting IP addresses."
            ),
            (
                "barracuda",
                "Barracuda BRBL",
                "dnsbl",
                1,
                None,
                None,
                "dns",
                "b.barracudacentral.org",
                5.0,
                60,
                5,
                1800,
                7200,
                json.dumps(["ipv4"]),
                None,
                None,
                None,
                "https://www.barracudacentral.org/rbl",
                "Free with registration for non-commercial and ISP monitoring purposes."
            ),
            (
                "abuseipdb",
                "AbuseIPDB",
                "abuse_api",
                1,
                "https://api.abuseipdb.com/api/v2/check",
                None,
                "api_key_header",
                None,
                6.0,
                60,
                3,
                1800,
                7200,
                json.dumps(["ipv4", "ipv6"]),
                1000,
                1000,
                None,
                "https://docs.abuseipdb.com/",
                "Requires AbuseIPDB API key. Provides abuse confidence score, total reports, and distinct reporter metrics."
            ),
            (
                "virustotal",
                "VirusTotal",
                "threat_intel",
                1,
                "https://www.virustotal.com/api/v3/ip_addresses/",
                None,
                "api_key_header",
                None,
                8.0,
                4,
                2,
                3600,
                14400,
                json.dumps(["ipv4", "ipv6"]),
                500,
                500,
                None,
                "https://docs.virustotal.com/reference/ip-info",
                "Requires VirusTotal API key. Subject to public API rate limits (4 requests/min)."
            ),
            (
                "greynoise",
                "GreyNoise",
                "threat_intel",
                1,
                "https://api.greynoise.io/v3/community/",
                None,
                "api_key_header",
                None,
                5.0,
                30,
                3,
                3600,
                14400,
                json.dumps(["ipv4"]),
                None,
                None,
                None,
                "https://docs.greynoise.io/",
                "Identifies mass internet scanners, benign scanning services, and malicious scanning activity."
            ),
            (
                "cisco_talos",
                "Cisco Talos Intelligence",
                "threat_intel",
                1,
                None,
                None,
                "dns",
                None,
                5.0,
                30,
                3,
                3600,
                14400,
                json.dumps(["ipv4", "ipv6"]),
                None,
                None,
                None,
                "https://talosintelligence.com/",
                "Provides global threat telemetry and email reputation classification."
            ),
            (
                "rdns_ptr",
                "Reverse DNS & PTR Validator",
                "email_reputation",
                1,
                None,
                None,
                "none",
                None,
                4.0,
                120,
                10,
                3600,
                14400,
                json.dumps(["ipv4", "ipv6"]),
                None,
                None,
                None,
                "https://tools.ietf.org/html/rfc1912",
                "Performs Forward-Confirmed Reverse DNS (FCrDNS) validation to detect missing PTR or generic dynamic naming patterns."
            )
        ]

        cursor.executemany("""
            INSERT INTO ip_intel_providers (
                provider_id, provider_name, provider_type, enabled, api_endpoint, api_key,
                auth_method, dns_zone, timeout_seconds, rate_limit_rpm, max_concurrent,
                cache_duration_positive_sec, cache_duration_negative_sec, supported_indicators,
                quota_limit, quota_remaining, quota_reset_at, documentation_url, terms_notice
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, providers)
        conn.commit()

    def _seed_default_inventory(self, cursor: sqlite3.Cursor, conn: sqlite3.Connection):
        import ipaddress
        net = ipaddress.ip_network("157.119.69.128/25", strict=False)
        items = []
        for host in net.hosts():
            ip_str = str(host)
            items.append((
                str(uuid.uuid4()),
                ip_str,
                4,
                "157.119.69.128/25",
                "WISPnet-CGNAT-Pool",
                "CCR2116-Core",
                "CGNAT Pool",
                "active",
                "UNKNOWN",
                0,
                0,
                0.0,
                "Initial inventory seeded from authoritative CGNAT pool (157.119.69.129 - 157.119.69.254)"
            ))

        cursor.executemany("""
            INSERT OR IGNORE INTO ip_intel_inventory (
                id, ip_address, ip_version, cidr_allocation, inventory_identifier,
                routing_context, purpose_role, monitoring_status, current_reputation_status,
                active_listing_count, historical_listing_count, risk_score, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, items)
        conn.commit()

    # ------------------------------------------------------------------------
    # Inventory Management Methods
    # ------------------------------------------------------------------------
    def get_ip_inventory(
        self,
        monitoring_status: Optional[str] = None,
        reputation_status: Optional[str] = None,
        purpose_role: Optional[str] = None,
        search: Optional[str] = None,
        sort_by: str = "recent",
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM ip_intel_inventory WHERE 1=1"
        params: List[Any] = []
        if monitoring_status:
            query += " AND monitoring_status = ?"
            params.append(monitoring_status)
        if reputation_status:
            query += " AND current_reputation_status = ?"
            params.append(reputation_status)
        if purpose_role:
            query += " AND purpose_role = ?"
            params.append(purpose_role)
        if search:
            pattern = f"%{search.strip()}%"
            query += " AND (ip_address LIKE ? OR cidr_allocation LIKE ? OR purpose_role LIKE ? OR notes LIKE ?)"
            params.extend([pattern, pattern, pattern, pattern])

        if sort_by == "recent":
            query += " ORDER BY updated_at DESC, created_at DESC"
        elif sort_by == "ip_desc":
            query += " ORDER BY ip_address DESC"
        elif sort_by == "risk_desc":
            query += " ORDER BY risk_score DESC, active_listing_count DESC"
        elif sort_by == "ip_asc":
            query += " ORDER BY ip_address ASC"
        else:
            query += " ORDER BY updated_at DESC, created_at DESC"

        query += " LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in rows]

    def get_ip_inventory_count(
        self,
        monitoring_status: Optional[str] = None,
        reputation_status: Optional[str] = None,
        purpose_role: Optional[str] = None,
        search: Optional[str] = None
    ) -> int:
        query = "SELECT COUNT(*) FROM ip_intel_inventory WHERE 1=1"
        params: List[Any] = []
        if monitoring_status:
            query += " AND monitoring_status = ?"
            params.append(monitoring_status)
        if reputation_status:
            query += " AND current_reputation_status = ?"
            params.append(reputation_status)
        if purpose_role:
            query += " AND purpose_role = ?"
            params.append(purpose_role)
        if search:
            pattern = f"%{search.strip()}%"
            query += " AND (ip_address LIKE ? OR cidr_allocation LIKE ? OR purpose_role LIKE ? OR notes LIKE ?)"
            params.extend([pattern, pattern, pattern, pattern])

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchone()[0]

    def get_ip_inventory_item(self, ip_address: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ip_intel_inventory WHERE ip_address = ?;", (ip_address,))
            row = cursor.fetchone()
            if not row:
                return None
            cols = [d[0] for d in cursor.description]
            return dict(zip(cols, row))

    def delete_ip_inventory_item(self, ip_address: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM ip_intel_inventory WHERE ip_address = ?;", (ip_address,))
            conn.commit()
            return cursor.rowcount > 0

    def upsert_ip_inventory_item(
        self,
        ip_address: str,
        cidr_allocation: Optional[str] = None,
        inventory_identifier: Optional[str] = None,
        routing_context: Optional[str] = None,
        purpose_role: str = "CGNAT Pool",
        monitoring_status: str = "active",
        notes: Optional[str] = None
    ) -> str:
        version = 6 if ":" in ip_address else 4
        item_id = str(uuid.uuid4())
        now = get_utc_now_iso()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ip_intel_inventory (
                    id, ip_address, ip_version, cidr_allocation, inventory_identifier,
                    routing_context, purpose_role, monitoring_status, notes, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    cidr_allocation = COALESCE(excluded.cidr_allocation, ip_intel_inventory.cidr_allocation),
                    inventory_identifier = COALESCE(excluded.inventory_identifier, ip_intel_inventory.inventory_identifier),
                    routing_context = COALESCE(excluded.routing_context, ip_intel_inventory.routing_context),
                    purpose_role = excluded.purpose_role,
                    monitoring_status = excluded.monitoring_status,
                    notes = COALESCE(excluded.notes, ip_intel_inventory.notes),
                    updated_at = excluded.updated_at;
            """, (
                item_id, ip_address, version, cidr_allocation, inventory_identifier,
                routing_context, purpose_role, monitoring_status, notes, now, now
            ))
            conn.commit()
            return item_id

    def update_ip_inventory_reputation(
        self,
        ip_address: str,
        reputation_status: str,
        risk_score: float,
        active_listings: int,
        latest_abuse: Optional[str] = None,
        last_security_alert: Optional[str] = None
    ):
        now = get_utc_now_iso()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE ip_intel_inventory
                SET current_reputation_status = ?,
                    risk_score = ?,
                    active_listing_count = ?,
                    historical_listing_count = historical_listing_count + ?,
                    latest_abuse_report = COALESCE(?, latest_abuse_report),
                    last_security_alert = COALESCE(?, last_security_alert),
                    last_checked_at = ?,
                    last_successful_lookup_at = ?,
                    updated_at = ?
                WHERE ip_address = ?;
            """, (
                reputation_status,
                risk_score,
                active_listings,
                1 if active_listings > 0 else 0,
                latest_abuse,
                last_security_alert,
                now,
                now,
                now,
                ip_address
            ))
            conn.commit()

    # ------------------------------------------------------------------------
    # Provider Configuration Methods
    # ------------------------------------------------------------------------
    def get_providers_config(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ip_intel_providers ORDER BY provider_name ASC;")
            rows = cursor.fetchall()
            cols = [d[0] for d in cursor.description]
            results = []
            for row in rows:
                item = dict(zip(cols, row))
                item["enabled"] = bool(item["enabled"])
                item["has_api_key"] = bool(item.get("api_key"))
                item["api_key_masked"] = (
                    item["api_key"][:4] + "••••" + item["api_key"][-4:]
                    if item.get("api_key") and len(item["api_key"]) > 8 else "••••••••"
                ) if item.get("api_key") else None
                # Do not leak plaintext key
                item.pop("api_key", None)
                if isinstance(item.get("supported_indicators"), str):
                    try:
                        item["supported_indicators"] = json.loads(item["supported_indicators"])
                    except Exception:
                        item["supported_indicators"] = ["ipv4"]
                results.append(item)
            return results

    def get_provider_raw(self, provider_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ip_intel_providers WHERE provider_id = ?;", (provider_id,))
            row = cursor.fetchone()
            if not row:
                return None
            cols = [d[0] for d in cursor.description]
            item = dict(zip(cols, row))
            if isinstance(item.get("supported_indicators"), str):
                try:
                    item["supported_indicators"] = json.loads(item["supported_indicators"])
                except Exception:
                    item["supported_indicators"] = ["ipv4"]
            return item

    def update_provider_config(self, provider_id: str, updates: Dict[str, Any]):
        fields = []
        params = []
        for k, v in updates.items():
            if k in ("enabled", "api_endpoint", "api_key", "auth_method", "dns_zone",
                     "timeout_seconds", "rate_limit_rpm", "max_concurrent",
                     "cache_duration_positive_sec", "cache_duration_negative_sec"):
                fields.append(f"{k} = ?")
                params.append(int(v) if k == "enabled" else v)
        if not fields:
            return

        fields.append("updated_at = ?")
        params.append(get_utc_now_iso())
        params.append(provider_id)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"UPDATE ip_intel_providers SET {', '.join(fields)} WHERE provider_id = ?;", params)
            conn.commit()

    def update_provider_runtime_stats(
        self,
        provider_id: str,
        success: bool,
        error_msg: Optional[str] = None,
        quota_remaining: Optional[int] = None
    ):
        now = get_utc_now_iso()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if success:
                cursor.execute("""
                    UPDATE ip_intel_providers
                    SET last_successful_request_at = ?,
                        quota_remaining = COALESCE(?, quota_remaining),
                        last_error = NULL
                    WHERE provider_id = ?;
                """, (now, quota_remaining, provider_id))
            else:
                cursor.execute("""
                    UPDATE ip_intel_providers
                    SET last_error = ?,
                        quota_remaining = COALESCE(?, quota_remaining)
                    WHERE provider_id = ?;
                """, (error_msg, quota_remaining, provider_id))
            conn.commit()

    # ------------------------------------------------------------------------
    # Observations Cache & History Methods
    # ------------------------------------------------------------------------
    def save_observation(self, obs: Dict[str, Any]):
        obs_id = obs.get("observation_id") or str(uuid.uuid4())
        ip_addr = obs.get("ip_address") or obs.get("queried_ip") or ""
        version = 6 if ":" in ip_addr else 4
        lookup_status = getattr(obs.get("lookup_status"), "value", obs.get("lookup_status"))
        listing_category = getattr(obs.get("listing_category"), "value", obs.get("listing_category", "none"))
        risk_status = getattr(obs.get("risk_status"), "value", obs.get("risk_status"))

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ip_intel_observations (
                    observation_id, ip_address, ip_version, provider_id, provider_name,
                    check_timestamp, lookup_status, duration_ms, is_cached, is_listed,
                    listing_category, source_classification, source_score, risk_status,
                    evidence_summary, raw_record_json, error_type, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                obs_id, ip_addr, version, obs["provider_id"], obs["provider_name"],
                obs["check_timestamp"], lookup_status, obs.get("duration_ms", 0.0),
                int(obs.get("is_cached", False)), int(obs.get("is_listed", False)),
                listing_category, obs.get("source_classification"),
                obs.get("source_score"), risk_status, obs.get("evidence_summary", ""),
                json.dumps(obs.get("raw_reference", {})), obs.get("error_type"), obs.get("error_message")
            ))
            conn.commit()

    def get_cached_observation(self, ip_address: str, provider_id: str, max_age_seconds: int) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM ip_intel_observations
                WHERE ip_address = ? AND provider_id = ?
                  AND created_at >= datetime('now', '-' || ? || ' seconds')
                ORDER BY check_timestamp DESC LIMIT 1;
            """, (ip_address, provider_id, max_age_seconds))
            row = cursor.fetchone()
            if not row:
                return None
            cols = [d[0] for d in cursor.description]
            item = dict(zip(cols, row))
            item["is_cached"] = True
            item["is_listed"] = bool(item["is_listed"])
            if item.get("raw_record_json"):
                try:
                    item["raw_reference"] = json.loads(item["raw_record_json"])
                except Exception:
                    item["raw_reference"] = None
            return item

    def get_ip_reputation_history(self, ip_address: str, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM ip_intel_history
                WHERE ip_address = ?
                ORDER BY timestamp DESC LIMIT ?;
            """, (ip_address, limit))
            rows = cursor.fetchall()
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in rows]

    def add_reputation_history_entry(
        self,
        ip_address: str,
        event_type: str,
        previous_status: Optional[str],
        new_status: Optional[str],
        details: str,
        triggered_by: str = "scanner"
    ):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ip_intel_history (
                    ip_address, event_type, previous_status, new_status, details, triggered_by
                ) VALUES (?, ?, ?, ?, ?, ?);
            """, (ip_address, event_type, previous_status, new_status, details, triggered_by))
            conn.commit()

    # ------------------------------------------------------------------------
    # Scans Management Methods
    # ------------------------------------------------------------------------
    def create_bulk_scan(
        self,
        scan_type: str,
        target_ips: List[str],
        scan_depth: str = "standard",
        selected_providers: Optional[List[str]] = None,
        concurrency_limit: int = 5,
        created_by: str = "system"
    ) -> str:
        scan_id = str(uuid.uuid4())
        now = get_utc_now_iso()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ip_intel_scans (
                    scan_id, scan_type, target_count, status, scan_depth,
                    selected_providers, concurrency_limit, created_by, created_at
                ) VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?);
            """, (
                scan_id, scan_type, len(target_ips), scan_depth,
                json.dumps(selected_providers or []), concurrency_limit, created_by, now
            ))
            # Insert scan items
            items = [(scan_id, ip, "pending", 0) for ip in target_ips]
            cursor.executemany("""
                INSERT INTO ip_intel_scan_items (scan_id, ip_address, status, attempts)
                VALUES (?, ?, ?, ?);
            """, items)
            conn.commit()
            return scan_id

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ip_intel_scans WHERE scan_id = ?;", (scan_id,))
            row = cursor.fetchone()
            if not row:
                return None
            cols = [d[0] for d in cursor.description]
            item = dict(zip(cols, row))
            if isinstance(item.get("selected_providers"), str):
                try:
                    item["selected_providers"] = json.loads(item["selected_providers"])
                except Exception:
                    item["selected_providers"] = []
            return item

    def get_pending_scan_items(self, scan_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM ip_intel_scan_items
                WHERE scan_id = ? AND status IN ('pending', 'retrying')
                ORDER BY id ASC LIMIT ?;
            """, (scan_id, limit))
            rows = cursor.fetchall()
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in rows]

    def update_scan_item_result(
        self,
        item_id: int,
        status: str,
        reputation_status: Optional[str] = None,
        active_listings: int = 0,
        error_message: Optional[str] = None
    ):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE ip_intel_scan_items
                SET status = ?,
                    attempts = attempts + 1,
                    reputation_status = ?,
                    active_listings = ?,
                    error_message = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?;
            """, (status, reputation_status, active_listings, error_message, item_id))
            conn.commit()

    def update_scan_progress(self, scan_id: str):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
                    SUM(CASE WHEN active_listings > 0 THEN 1 ELSE 0 END) as listed
                FROM ip_intel_scan_items
                WHERE scan_id = ?;
            """, (scan_id,))
            row = cursor.fetchone()
            total, completed, failed, listed = row[0], row[1] or 0, row[2] or 0, row[3] or 0
            progress = round((completed + failed) / max(total, 1) * 100, 1)
            new_status = "completed" if (completed + failed) >= total and total > 0 else "running"

            cursor.execute("""
                UPDATE ip_intel_scans
                SET completed_count = ?,
                    failed_count = ?,
                    listed_count = ?,
                    progress_percent = ?,
                    status = CASE WHEN status IN ('cancelled', 'paused') THEN status ELSE ? END,
                    completed_at = CASE WHEN ? = 'completed' THEN CURRENT_TIMESTAMP ELSE completed_at END
                WHERE scan_id = ?;
            """, (completed, failed, listed, progress, new_status, new_status, scan_id))
            conn.commit()

    def set_scan_status(self, scan_id: str, status: str):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE ip_intel_scans SET status = ? WHERE scan_id = ?;", (status, scan_id))
            conn.commit()

    # ------------------------------------------------------------------------
    # Investigations Management Methods
    # ------------------------------------------------------------------------
    def create_investigation(
        self,
        ip_address: str,
        title: str,
        severity: str = "medium",
        operator_notes: Optional[str] = None,
        assigned_operator: Optional[str] = None
    ) -> str:
        inv_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
        now = get_utc_now_iso()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ip_intel_investigations (
                    investigation_id, ip_address, title, status, severity,
                    operator_notes, assigned_operator, created_at, updated_at
                ) VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?);
            """, (inv_id, ip_address, title, severity, operator_notes, assigned_operator, now, now))
            conn.commit()
            return inv_id

    def get_investigations(self, status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        query = "SELECT * FROM ip_intel_investigations WHERE 1=1"
        params: List[Any] = []
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC LIMIT ?;"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in rows]

    # ------------------------------------------------------------------------
    # Overview Statistics & Metrics
    # ------------------------------------------------------------------------
    def get_ip_intel_overview_stats(self, time_window_hours: int = 24) -> Dict[str, Any]:
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Monitored IPs
            cursor.execute("SELECT COUNT(*) FROM ip_intel_inventory WHERE monitoring_status = 'active';")
            total_monitored = cursor.fetchone()[0]

            # Currently listed IPs
            cursor.execute("SELECT COUNT(*) FROM ip_intel_inventory WHERE current_reputation_status IN ('LISTED', 'HIGH_RISK');")
            total_listed = cursor.fetchone()[0]

            # Recent abuse
            cursor.execute("SELECT COUNT(*) FROM ip_intel_inventory WHERE latest_abuse_report IS NOT NULL;")
            recent_abuse = cursor.fetchone()[0]

            # Deteriorating IPs (suspicious or listed)
            cursor.execute("SELECT COUNT(*) FROM ip_intel_inventory WHERE current_reputation_status IN ('SUSPICIOUS', 'HIGH_RISK');")
            deteriorating = cursor.fetchone()[0]

            # New listings in last N hours
            cursor.execute(f"""
                SELECT COUNT(DISTINCT ip_address) FROM ip_intel_history
                WHERE event_type = 'listing_detected'
                  AND timestamp >= datetime('now', '-{time_window_hours} hours');
            """)
            new_listings = cursor.fetchone()[0]

            # Resolved listings in last N hours
            cursor.execute(f"""
                SELECT COUNT(DISTINCT ip_address) FROM ip_intel_history
                WHERE event_type = 'listing_cleared'
                  AND timestamp >= datetime('now', '-{time_window_hours} hours');
            """)
            resolved_listings = cursor.fetchone()[0]

            # Failed checks in last N hours
            cursor.execute(f"""
                SELECT COUNT(*) FROM ip_intel_observations
                WHERE lookup_status IN ('failed', 'timeout', 'blocked')
                  AND check_timestamp >= datetime('now', '-{time_window_hours} hours');
            """)
            failed_checks = cursor.fetchone()[0]

            # Requiring review (High Risk or Suspicious)
            cursor.execute("SELECT COUNT(*) FROM ip_intel_inventory WHERE current_reputation_status IN ('HIGH_RISK', 'SUSPICIOUS');")
            requiring_review = cursor.fetchone()[0]

            # Open investigations
            cursor.execute("SELECT COUNT(*) FROM ip_intel_investigations WHERE status IN ('open', 'investigating');")
            open_inv = cursor.fetchone()[0]

            # Last scan timestamp
            cursor.execute("SELECT MAX(completed_at) FROM ip_intel_scans WHERE status = 'completed';")
            last_scan = cursor.fetchone()[0]

            # Provider summary
            cursor.execute("SELECT provider_id, provider_name, provider_type, enabled, quota_remaining, last_error FROM ip_intel_providers;")
            prov_rows = cursor.fetchall()
            prov_cols = [d[0] for d in cursor.description]
            provider_summary = [dict(zip(prov_cols, r)) for r in prov_rows]

            return {
                "total_monitored_ips": total_monitored,
                "total_listed_ips": total_listed,
                "total_recent_abuse_ips": recent_abuse,
                "total_deteriorating_ips": deteriorating,
                "new_listings_24h": new_listings,
                "resolved_listings_24h": resolved_listings,
                "failed_provider_checks": failed_checks,
                "ips_requiring_review": requiring_review,
                "open_investigations_count": open_inv,
                "last_successful_scan_at": last_scan,
                "provider_summary": provider_summary
            }

    # ------------------------------------------------------------------------
    # Audit Logging
    # ------------------------------------------------------------------------
    def log_ip_intel_audit(
        self,
        username: str,
        action: str,
        target_type: str,
        target_id: str,
        details: Optional[Dict[str, Any]] = None
    ):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ip_intel_audit_logs (
                    username, action, target_type, target_id, details_json
                ) VALUES (?, ?, ?, ?, ?);
            """, (username, action, target_type, target_id, json.dumps(details or {})))
            conn.commit()
