"""
Security & CGNAT Database Module for WISPnet
Provides schema management, queries, and persistence for CGNAT mappings, subscriber sessions,
security events, incidents, sensors, rules, health, and durable buffering.
"""
import sqlite3
import json
import uuid
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timezone

def get_utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
from app.models.security_schemas import (
    CGNATMapping,
    SubscriberSession,
    Sensor,
    SecurityEvent,
    Incident,
    DetectionRule,
    AuditLogEntry,
    IntegrationHealth,
    AttributionStatus,
    TrafficDirection,
    SecuritySeverity,
    IncidentStatus,
    DetectionCategory
)

class SecurityDatabaseMixin:
    """Mixin for DatabaseManager adding all security, CGNAT, sensor, and incident methods"""

    def _init_security_db(self, conn: sqlite3.Connection):
        cursor = conn.cursor()

        # 1. Sensors table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sensors (
                sensor_id TEXT PRIMARY KEY,
                sensor_name TEXT NOT NULL,
                sensor_type TEXT NOT NULL,
                observation_point TEXT NOT NULL,
                host TEXT NOT NULL,
                interface TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                last_seen TIMESTAMP,
                health_status TEXT DEFAULT 'healthy',
                version TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 2. CGNAT deterministic mappings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cgnat_mappings (
                mapping_id TEXT PRIMARY KEY,
                mapping_version TEXT DEFAULT 'v1.0',
                public_ip TEXT NOT NULL,
                port_start INTEGER NOT NULL,
                port_end INTEGER NOT NULL,
                protocol_scope TEXT DEFAULT 'all',
                subscriber_cgnat_ip TEXT NOT NULL,
                pppoe_username TEXT,
                router_id TEXT DEFAULT 'core-router-ccr2116',
                effective_from TIMESTAMP NOT NULL,
                effective_to TIMESTAMP,
                source_of_truth TEXT DEFAULT 'deterministic_algorithm',
                validation_status TEXT DEFAULT 'verified',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 3. Subscriber sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS subscriber_sessions (
                session_id TEXT PRIMARY KEY,
                pppoe_username TEXT NOT NULL,
                subscriber_cgnat_ip TEXT NOT NULL,
                access_concentrator TEXT NOT NULL,
                router_session_id TEXT,
                started_at TIMESTAMP NOT NULL,
                ended_at TIMESTAMP,
                session_source TEXT DEFAULT 'routeros_active',
                last_synchronized_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 4. Security events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                event_id TEXT PRIMARY KEY,
                source_event_id TEXT,
                event_timestamp TIMESTAMP NOT NULL,
                received_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                sensor_id TEXT NOT NULL,
                observation_point TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                source_port INTEGER,
                destination_ip TEXT NOT NULL,
                destination_port INTEGER,
                protocol TEXT DEFAULT 'tcp',
                traffic_direction TEXT DEFAULT 'outbound',
                event_type TEXT DEFAULT 'alert',
                signature_id INTEGER,
                signature_name TEXT,
                category TEXT DEFAULT 'custom',
                severity TEXT DEFAULT 'medium',
                packets INTEGER,
                bytes INTEGER,
                flow_id TEXT,
                original_event_reference TEXT,
                attribution_status TEXT DEFAULT 'unresolved',
                mapping_id TEXT,
                subscriber_cgnat_ip TEXT,
                pppoe_username TEXT,
                attribution_method TEXT,
                detection_rule_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 5. Incidents table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'medium',
                status TEXT NOT NULL DEFAULT 'new',
                first_seen TIMESTAMP NOT NULL,
                last_seen TIMESTAMP NOT NULL,
                affected_subscriber_ip TEXT,
                pppoe_username TEXT,
                affected_public_ip TEXT,
                evidence_summary_json TEXT DEFAULT '{}',
                assigned_operator TEXT,
                resolution_notes TEXT,
                event_count INTEGER DEFAULT 1,
                total_bytes INTEGER DEFAULT 0,
                total_packets INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 6. Incident events correlation table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incident_events (
                incident_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (incident_id, event_id)
            )
        """)

        # 7. Detection rules table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS detection_rules (
                rule_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                threshold_config_json TEXT DEFAULT '{}',
                time_window_seconds INTEGER DEFAULT 60,
                severity TEXT DEFAULT 'medium',
                exclusions_json TEXT DEFAULT '[]',
                created_by TEXT DEFAULT 'system',
                updated_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 8. Security audit logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_audit_logs (
                audit_id TEXT PRIMARY KEY,
                operator_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT,
                outcome TEXT DEFAULT 'success',
                sanitized_details_json TEXT DEFAULT '{}'
            )
        """)

        # 9. Integration health table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS integration_health (
                integration_name TEXT PRIMARY KEY,
                connectivity TEXT DEFAULT 'configured',
                last_successful_ingestion TIMESTAMP,
                last_event_timestamp TIMESTAMP,
                processing_lag_ms REAL DEFAULT 0.0,
                error_count INTEGER DEFAULT 0,
                queue_depth INTEGER DEFAULT 0,
                last_error TEXT,
                configuration_status TEXT DEFAULT 'configured',
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 10. OpenSearch durable queue buffer
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS opensearch_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                index_name TEXT NOT NULL,
                doc_id TEXT NOT NULL,
                document_json TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                attempts INTEGER DEFAULT 0,
                last_error TEXT,
                status TEXT DEFAULT 'pending'
            )
        """)

        # 11. Raw events preservation
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS raw_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                source_type TEXT NOT NULL,
                raw_payload TEXT NOT NULL,
                received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 12. Notification logs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notification_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT,
                rule_id TEXT,
                channel TEXT NOT NULL,
                recipient TEXT,
                subject TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                status TEXT DEFAULT 'sent',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Indexes for fast querying & forensic lookups
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cgnat_mappings_pub ON cgnat_mappings (public_ip, port_start, port_end, effective_from);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cgnat_mappings_sub ON cgnat_mappings (subscriber_cgnat_ip);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sub_sessions_ip_time ON subscriber_sessions (subscriber_cgnat_ip, started_at, ended_at);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sub_sessions_user ON subscriber_sessions (pppoe_username);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_time ON security_events (event_timestamp DESC);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_sub_ip ON security_events (subscriber_cgnat_ip);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_pub_ip ON security_events (source_ip, source_port);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_severity ON security_events (severity);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_category ON security_events (category);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_sub_ip ON incidents (affected_subscriber_ip);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_time ON incidents (last_seen DESC);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_opensearch_queue_status ON opensearch_queue (status, attempts);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_raw_events_eid ON raw_events (event_id);")

        # 13. Onboarded Routers (Core, AC, Border, Distribution, etc.)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS routers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'core',
                host TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 8728,
                username TEXT NOT NULL DEFAULT 'security_ro',
                password TEXT NOT NULL,
                use_ssl INTEGER DEFAULT 0,
                use_rest INTEGER DEFAULT 0,
                status TEXT DEFAULT 'untested',
                model TEXT,
                ros_version TEXT,
                cpu_load INTEGER,
                uptime TEXT,
                last_seen TIMESTAMP,
                last_error TEXT,
                notes TEXT DEFAULT '',
                enabled INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_routers_role ON routers (role);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_routers_status ON routers (status);")

        # Seed default sensors & default detection rules if not existing
        self._seed_default_security_entities(cursor)

    def _seed_default_security_entities(self, cursor: sqlite3.Cursor):
        # Default sensors: Pre-CGNAT and Post-CGNAT
        cursor.execute("SELECT COUNT(*) FROM sensors")
        if cursor.fetchone()[0] == 0:
            now = get_utc_now_iso()
            default_sensors = [
                ("sensor-pre-cgnat-01", "Pre-CGNAT Switch Mirror TAP", "suricata", "pre_cgnat", "100.91.0.1", "sfp-sfpplus1-subscriber-mirror", 1, now, "healthy", "Suricata 7.0.2"),
                ("sensor-post-cgnat-01", "Post-CGNAT Border Uplink TAP", "suricata", "post_cgnat", "157.119.69.129", "sfp-sfpplus2-wan-transit", 1, now, "healthy", "Suricata 7.0.2"),
                ("sensor-flow-akvorado", "Akvorado Flow Collector", "akvorado", "post_cgnat", "10.0.0.50", "ipfix-collector-01", 1, now, "healthy", "Akvorado 1.8.0")
            ]
            cursor.executemany("""
                INSERT INTO sensors (sensor_id, sensor_name, sensor_type, observation_point, host, interface, enabled, last_seen, health_status, version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, default_sensors)

        # Default detection rules
        cursor.execute("SELECT COUNT(*) FROM detection_rules")
        if cursor.fetchone()[0] == 0:
            now = get_utc_now_iso()
            default_rules = [
                ("rule-scan-outbound", "Outbound Port Scanning", "port_scanning", 1, json.dumps({"min_distinct_ports": 20, "min_distinct_ips": 15}), 60, "high", json.dumps(["100.91.0.1", "1.1.1.1", "8.8.8.8"])),
                ("rule-ddos-outbound", "Outbound DDoS Flood Indicators", "outbound_ddos", 1, json.dumps({"min_pps": 5000, "min_bytes_per_sec": 10000000, "min_conns_per_sec": 100}), 30, "critical", json.dumps([])),
                ("rule-auth-bruteforce", "Brute-Force & Credential Stuffing", "brute_force", 1, json.dumps({"target_ports": [22, 3389, 21, 25, 443], "max_attempts": 10}), 60, "high", json.dumps([])),
                ("rule-botnet-c2", "Botnet & Command-and-Control Communication", "botnet_c2", 1, json.dumps({"check_known_c2": True, "periodic_beacon_seconds": 60}), 120, "critical", json.dumps([])),
                ("rule-dns-anomaly", "DNS Anomaly & Tunneling Detection", "dns_anomaly", 1, json.dumps({"max_queries_per_min": 250, "max_unique_subdomains": 50}), 60, "medium", json.dumps([])),
                ("rule-ddos-inbound", "Inbound DDoS / Public IP Targeting", "inbound_ddos", 1, json.dumps({"min_pps": 10000, "syn_flood_threshold": 2000}), 30, "critical", json.dumps([])),
                ("rule-cgnat-abuse", "CGNAT Subscriber Abuse & Port Block Matching", "cgnat_abuse", 1, json.dumps({"require_valid_mapping": True}), 0, "high", json.dumps([]))
            ]
            cursor.executemany("""
                INSERT INTO detection_rules (rule_id, name, category, enabled, threshold_config_json, time_window_seconds, severity, exclusions_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], now, now) for r in default_rules])

        # Default routers (Core CCR2116 & PPPoE AC CCR2116)
        cursor.execute("SELECT COUNT(*) FROM routers")
        if cursor.fetchone()[0] == 0:
            now = get_utc_now_iso()
            default_routers = [
                ("router-core-ccr2116", "Core CCR2116 NAT Gateway", "core", "100.91.0.1", 8728, "security_ro", "********", 0, 0, "online", "CCR2116-12G-4S+", "v7.16", 14, "42d 18h", now, None, "Carrier CGNAT & BGP Core Gateway", 1, now, now),
                ("router-ac-ccr2116", "PPPoE AC CCR2116", "ac", "100.91.0.254", 8728, "security_ro", "********", 0, 0, "online", "CCR2116-12G-4S+", "v7.16", 22, "42d 18h", now, None, "Primary PPPoE / IPoE Access Concentrator", 1, now, now)
            ]
            cursor.executemany("""
                INSERT INTO routers (id, name, role, host, port, username, password, use_ssl, use_rest, status, model, ros_version, cpu_load, uptime, last_seen, last_error, notes, enabled, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, default_routers)

        # Default Integration Health entries
        cursor.execute("SELECT COUNT(*) FROM integration_health")
        if cursor.fetchone()[0] == 0:
            now = get_utc_now_iso()
            integrations = [
                ("RouterOS-Core", "online", now, now, 12.5, 0, 0, None, "configured"),
                ("RouterOS-PPPoE-AC", "online", now, now, 8.2, 0, 0, None, "configured"),
                ("Akvorado-Flow", "online", now, now, 45.0, 0, 0, None, "configured"),
                ("Suricata-IDS", "online", now, now, 5.0, 0, 0, None, "configured"),
                ("OpenSearch-Cluster", "online", now, now, 15.0, 0, 0, None, "configured")
            ]
            cursor.executemany("""
                INSERT INTO integration_health (integration_name, connectivity, last_successful_ingestion, last_event_timestamp, processing_lag_ms, error_count, queue_depth, last_error, configuration_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, integrations)

    # -------------------------------------------------------------
    # CGNAT MAPPINGS CRUD
    # -------------------------------------------------------------
    def get_cgnat_mappings(
        self,
        public_ip: Optional[str] = None,
        subscriber_cgnat_ip: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Tuple[List[CGNATMapping], int]:
        query = "SELECT * FROM cgnat_mappings WHERE 1=1"
        count_query = "SELECT COUNT(*) FROM cgnat_mappings WHERE 1=1"
        params: List[Any] = []
        count_params: List[Any] = []

        if public_ip:
            query += " AND public_ip = ?"
            count_query += " AND public_ip = ?"
            params.append(public_ip)
            count_params.append(public_ip)
        if subscriber_cgnat_ip:
            query += " AND subscriber_cgnat_ip = ?"
            count_query += " AND subscriber_cgnat_ip = ?"
            params.append(subscriber_cgnat_ip)
            count_params.append(subscriber_cgnat_ip)

        query += " ORDER BY public_ip ASC, port_start ASC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(count_query, count_params)
            total = cursor.fetchone()[0]

            cursor.execute(query, params)
            rows = cursor.fetchall()
            mappings = [
                CGNATMapping(
                    mapping_id=r["mapping_id"],
                    mapping_version=r["mapping_version"],
                    public_ip=r["public_ip"],
                    port_start=r["port_start"],
                    port_end=r["port_end"],
                    protocol_scope=r["protocol_scope"],
                    subscriber_cgnat_ip=r["subscriber_cgnat_ip"],
                    pppoe_username=r["pppoe_username"],
                    router_id=r["router_id"],
                    effective_from=r["effective_from"],
                    effective_to=r["effective_to"],
                    source_of_truth=r["source_of_truth"],
                    validation_status=r["validation_status"],
                    created_at=r["created_at"]
                )
                for r in rows
            ]
            return mappings, total

    def find_cgnat_mapping(
        self,
        public_ip: str,
        public_port: int,
        protocol: str = "tcp",
        timestamp: Optional[str] = None
    ) -> List[CGNATMapping]:
        """Finds matching mapping for a public IP and port at a given timestamp"""
        proto = protocol.lower()
        query = """
            SELECT * FROM cgnat_mappings
            WHERE public_ip = ?
              AND port_start <= ?
              AND port_end >= ?
              AND (protocol_scope = 'all' OR protocol_scope = ?)
        """
        params: List[Any] = [public_ip, public_port, public_port, proto]

        if timestamp:
            query += " AND effective_from <= ? AND (effective_to IS NULL OR effective_to >= ?)"
            params.extend([timestamp, timestamp])

        query += " ORDER BY effective_from DESC"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [
                CGNATMapping(
                    mapping_id=r["mapping_id"],
                    mapping_version=r["mapping_version"],
                    public_ip=r["public_ip"],
                    port_start=r["port_start"],
                    port_end=r["port_end"],
                    protocol_scope=r["protocol_scope"],
                    subscriber_cgnat_ip=r["subscriber_cgnat_ip"],
                    pppoe_username=r["pppoe_username"],
                    router_id=r["router_id"],
                    effective_from=r["effective_from"],
                    effective_to=r["effective_to"],
                    source_of_truth=r["source_of_truth"],
                    validation_status=r["validation_status"],
                    created_at=r["created_at"]
                )
                for r in rows
            ]

    def insert_cgnat_mappings_batch(self, mappings: List[CGNATMapping]) -> int:
        records = [
            (
                m.mapping_id or str(uuid.uuid4()),
                m.mapping_version,
                m.public_ip,
                m.port_start,
                m.port_end,
                m.protocol_scope,
                m.subscriber_cgnat_ip,
                m.pppoe_username,
                m.router_id,
                m.effective_from,
                m.effective_to,
                m.source_of_truth,
                m.validation_status
            )
            for m in mappings
        ]
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany("""
                INSERT OR REPLACE INTO cgnat_mappings (
                    mapping_id, mapping_version, public_ip, port_start, port_end,
                    protocol_scope, subscriber_cgnat_ip, pppoe_username, router_id,
                    effective_from, effective_to, source_of_truth, validation_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, records)
            conn.commit()
            return cursor.rowcount

    def clear_cgnat_mappings(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM cgnat_mappings")
            conn.commit()

    # -------------------------------------------------------------
    # SUBSCRIBER SESSIONS CRUD
    # -------------------------------------------------------------
    def get_subscriber_sessions(
        self,
        subscriber_cgnat_ip: Optional[str] = None,
        pppoe_username: Optional[str] = None,
        limit: int = 100
    ) -> List[SubscriberSession]:
        query = "SELECT * FROM subscriber_sessions WHERE 1=1"
        params: List[Any] = []

        if subscriber_cgnat_ip:
            query += " AND subscriber_cgnat_ip = ?"
            params.append(subscriber_cgnat_ip)
        if pppoe_username:
            query += " AND pppoe_username = ?"
            params.append(pppoe_username)

        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [
                SubscriberSession(
                    session_id=r["session_id"],
                    pppoe_username=r["pppoe_username"],
                    subscriber_cgnat_ip=r["subscriber_cgnat_ip"],
                    access_concentrator=r["access_concentrator"],
                    router_session_id=r["router_session_id"],
                    started_at=r["started_at"],
                    ended_at=r["ended_at"],
                    session_source=r["session_source"],
                    last_synchronized_at=r["last_synchronized_at"]
                )
                for r in rows
            ]

    def find_active_session_at_timestamp(
        self,
        subscriber_cgnat_ip: str,
        timestamp: str
    ) -> Optional[SubscriberSession]:
        """Finds session for a CGNAT IP that was active at the given timestamp"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM subscriber_sessions
                WHERE subscriber_cgnat_ip = ?
                  AND started_at <= ?
                  AND (ended_at IS NULL OR ended_at >= ?)
                ORDER BY started_at DESC LIMIT 1
            """, (subscriber_cgnat_ip, timestamp, timestamp))
            row = cursor.fetchone()
            if row:
                return SubscriberSession(
                    session_id=row["session_id"],
                    pppoe_username=row["pppoe_username"],
                    subscriber_cgnat_ip=row["subscriber_cgnat_ip"],
                    access_concentrator=row["access_concentrator"],
                    router_session_id=row["router_session_id"],
                    started_at=row["started_at"],
                    ended_at=row["ended_at"],
                    session_source=row["session_source"],
                    last_synchronized_at=row["last_synchronized_at"]
                )
            # Fallback: check most recent session
            cursor.execute("""
                SELECT * FROM subscriber_sessions
                WHERE subscriber_cgnat_ip = ?
                ORDER BY started_at DESC LIMIT 1
            """, (subscriber_cgnat_ip,))
            row = cursor.fetchone()
            if row:
                return SubscriberSession(
                    session_id=row["session_id"],
                    pppoe_username=row["pppoe_username"],
                    subscriber_cgnat_ip=row["subscriber_cgnat_ip"],
                    access_concentrator=row["access_concentrator"],
                    router_session_id=row["router_session_id"],
                    started_at=row["started_at"],
                    ended_at=row["ended_at"],
                    session_source=row["session_source"],
                    last_synchronized_at=row["last_synchronized_at"]
                )
            return None

    def upsert_subscriber_session(self, session: SubscriberSession) -> bool:
        now = get_utc_now_iso()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO subscriber_sessions (
                    session_id, pppoe_username, subscriber_cgnat_ip, access_concentrator,
                    router_session_id, started_at, ended_at, session_source, last_synchronized_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    subscriber_cgnat_ip = excluded.subscriber_cgnat_ip,
                    ended_at = excluded.ended_at,
                    last_synchronized_at = excluded.last_synchronized_at
            """, (
                session.session_id,
                session.pppoe_username,
                session.subscriber_cgnat_ip,
                session.access_concentrator,
                session.router_session_id,
                session.started_at,
                session.ended_at,
                session.session_source,
                now
            ))
            conn.commit()
            return True

    # -------------------------------------------------------------
    # SENSORS CRUD
    # -------------------------------------------------------------
    def get_sensors(self) -> List[Sensor]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sensors ORDER BY sensor_name ASC")
            rows = cursor.fetchall()
            return [
                Sensor(
                    sensor_id=r["sensor_id"],
                    sensor_name=r["sensor_name"],
                    sensor_type=r["sensor_type"],
                    observation_point=r["observation_point"],
                    host=r["host"],
                    interface=r["interface"],
                    enabled=bool(r["enabled"]),
                    last_seen=r["last_seen"],
                    health_status=r["health_status"],
                    version=r["version"],
                    created_at=r["created_at"],
                    updated_at=r["updated_at"]
                )
                for r in rows
            ]

    def update_sensor_heartbeat(self, sensor_id: str, health_status: str = "healthy"):
        now = get_utc_now_iso()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE sensors
                SET last_seen = ?, health_status = ?, updated_at = ?
                WHERE sensor_id = ?
            """, (now, health_status, now, sensor_id))
            conn.commit()

    # -------------------------------------------------------------
    # SECURITY EVENTS CRUD
    # -------------------------------------------------------------
    def insert_security_event(self, event: SecurityEvent, raw_payload: Optional[str] = None) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO security_events (
                    event_id, source_event_id, event_timestamp, received_timestamp,
                    sensor_id, observation_point, source_ip, source_port, destination_ip,
                    destination_port, protocol, traffic_direction, event_type, signature_id,
                    signature_name, category, severity, packets, bytes, flow_id,
                    original_event_reference, attribution_status, mapping_id, subscriber_cgnat_ip,
                    pppoe_username, attribution_method, detection_rule_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_id,
                event.source_event_id,
                event.event_timestamp,
                event.received_timestamp,
                event.sensor_id,
                event.observation_point,
                event.source_ip,
                event.source_port,
                event.destination_ip,
                event.destination_port,
                event.protocol,
                event.traffic_direction.value if hasattr(event.traffic_direction, 'value') else str(event.traffic_direction),
                event.event_type,
                event.signature_id,
                event.signature_name,
                event.category.value if hasattr(event.category, 'value') else str(event.category),
                event.severity.value if hasattr(event.severity, 'value') else str(event.severity),
                event.packets,
                event.bytes,
                event.flow_id,
                event.original_event_reference,
                event.attribution_status.value if hasattr(event.attribution_status, 'value') else str(event.attribution_status),
                event.mapping_id,
                event.subscriber_cgnat_ip,
                event.pppoe_username,
                event.attribution_method,
                event.detection_rule_id
            ))

            if raw_payload:
                cursor.execute("""
                    INSERT OR IGNORE INTO raw_events (event_id, source_type, raw_payload)
                    VALUES (?, ?, ?)
                """, (event.event_id, event.event_type, raw_payload))

            conn.commit()
            return cursor.rowcount > 0

    def get_security_events(
        self,
        cgnat_ip: Optional[str] = None,
        public_ip: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        attribution_status: Optional[str] = None,
        sensor_id: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Tuple[List[SecurityEvent], int]:
        query = "SELECT * FROM security_events WHERE 1=1"
        count_query = "SELECT COUNT(*) FROM security_events WHERE 1=1"
        params: List[Any] = []
        count_params: List[Any] = []

        if cgnat_ip:
            query += " AND subscriber_cgnat_ip = ?"
            count_query += " AND subscriber_cgnat_ip = ?"
            params.append(cgnat_ip)
            count_params.append(cgnat_ip)
        if public_ip:
            query += " AND (source_ip = ? OR destination_ip = ?)"
            count_query += " AND (source_ip = ? OR destination_ip = ?)"
            params.extend([public_ip, public_ip])
            count_params.extend([public_ip, public_ip])
        if severity:
            query += " AND severity = ?"
            count_query += " AND severity = ?"
            params.append(severity)
            count_params.append(severity)
        if category:
            query += " AND category = ?"
            count_query += " AND category = ?"
            params.append(category)
            count_params.append(category)
        if attribution_status:
            query += " AND attribution_status = ?"
            count_query += " AND attribution_status = ?"
            params.append(attribution_status)
            count_params.append(attribution_status)
        if sensor_id:
            query += " AND sensor_id = ?"
            count_query += " AND sensor_id = ?"
            params.append(sensor_id)
            count_params.append(sensor_id)
        if start_time:
            query += " AND event_timestamp >= ?"
            count_query += " AND event_timestamp >= ?"
            params.append(start_time)
            count_params.append(start_time)
        if end_time:
            query += " AND event_timestamp <= ?"
            count_query += " AND event_timestamp <= ?"
            params.append(end_time)
            count_params.append(end_time)

        query += " ORDER BY event_timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(count_query, count_params)
            total = cursor.fetchone()[0]

            cursor.execute(query, params)
            rows = cursor.fetchall()
            events = [
                SecurityEvent(
                    event_id=r["event_id"],
                    source_event_id=r["source_event_id"],
                    event_timestamp=r["event_timestamp"],
                    received_timestamp=r["received_timestamp"],
                    sensor_id=r["sensor_id"],
                    observation_point=r["observation_point"],
                    source_ip=r["source_ip"],
                    source_port=r["source_port"],
                    destination_ip=r["destination_ip"],
                    destination_port=r["destination_port"],
                    protocol=r["protocol"],
                    traffic_direction=TrafficDirection(r["traffic_direction"]) if r["traffic_direction"] in [e.value for e in TrafficDirection] else TrafficDirection.OUTBOUND,
                    event_type=r["event_type"],
                    signature_id=r["signature_id"],
                    signature_name=r["signature_name"],
                    category=DetectionCategory(r["category"]) if r["category"] in [e.value for e in DetectionCategory] else DetectionCategory.CUSTOM,
                    severity=SecuritySeverity(r["severity"]) if r["severity"] in [e.value for e in SecuritySeverity] else SecuritySeverity.MEDIUM,
                    packets=r["packets"],
                    bytes=r["bytes"],
                    flow_id=r["flow_id"],
                    original_event_reference=r["original_event_reference"],
                    attribution_status=AttributionStatus(r["attribution_status"]) if r["attribution_status"] in [e.value for e in AttributionStatus] else AttributionStatus.UNRESOLVED,
                    mapping_id=r["mapping_id"],
                    subscriber_cgnat_ip=r["subscriber_cgnat_ip"],
                    pppoe_username=r["pppoe_username"],
                    attribution_method=r["attribution_method"],
                    detection_rule_id=r["detection_rule_id"],
                    created_at=r["created_at"]
                )
                for r in rows
            ]
            return events, total

    def get_security_event_by_id(self, event_id: str) -> Optional[Tuple[SecurityEvent, Optional[str]]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM security_events WHERE event_id = ?", (event_id,))
            r = cursor.fetchone()
            if not r:
                return None
            event = SecurityEvent(
                event_id=r["event_id"],
                source_event_id=r["source_event_id"],
                event_timestamp=r["event_timestamp"],
                received_timestamp=r["received_timestamp"],
                sensor_id=r["sensor_id"],
                observation_point=r["observation_point"],
                source_ip=r["source_ip"],
                source_port=r["source_port"],
                destination_ip=r["destination_ip"],
                destination_port=r["destination_port"],
                protocol=r["protocol"],
                traffic_direction=TrafficDirection(r["traffic_direction"]) if r["traffic_direction"] in [e.value for e in TrafficDirection] else TrafficDirection.OUTBOUND,
                event_type=r["event_type"],
                signature_id=r["signature_id"],
                signature_name=r["signature_name"],
                category=DetectionCategory(r["category"]) if r["category"] in [e.value for e in DetectionCategory] else DetectionCategory.CUSTOM,
                severity=SecuritySeverity(r["severity"]) if r["severity"] in [e.value for e in SecuritySeverity] else SecuritySeverity.MEDIUM,
                packets=r["packets"],
                bytes=r["bytes"],
                flow_id=r["flow_id"],
                original_event_reference=r["original_event_reference"],
                attribution_status=AttributionStatus(r["attribution_status"]) if r["attribution_status"] in [e.value for e in AttributionStatus] else AttributionStatus.UNRESOLVED,
                mapping_id=r["mapping_id"],
                subscriber_cgnat_ip=r["subscriber_cgnat_ip"],
                pppoe_username=r["pppoe_username"],
                attribution_method=r["attribution_method"],
                detection_rule_id=r["detection_rule_id"],
                created_at=r["created_at"]
            )
            cursor.execute("SELECT raw_payload FROM raw_events WHERE event_id = ?", (event_id,))
            raw_row = cursor.fetchone()
            raw_payload = raw_row[0] if raw_row else None
            return event, raw_payload

    # -------------------------------------------------------------
    # INCIDENTS CRUD
    # -------------------------------------------------------------
    def get_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        subscriber_cgnat_ip: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Tuple[List[Incident], int]:
        query = "SELECT * FROM incidents WHERE 1=1"
        count_query = "SELECT COUNT(*) FROM incidents WHERE 1=1"
        params: List[Any] = []
        count_params: List[Any] = []

        if status:
            query += " AND status = ?"
            count_query += " AND status = ?"
            params.append(status)
            count_params.append(status)
        if severity:
            query += " AND severity = ?"
            count_query += " AND severity = ?"
            params.append(severity)
            count_params.append(severity)
        if category:
            query += " AND category = ?"
            count_query += " AND category = ?"
            params.append(category)
            count_params.append(category)
        if subscriber_cgnat_ip:
            query += " AND affected_subscriber_ip = ?"
            count_query += " AND affected_subscriber_ip = ?"
            params.append(subscriber_cgnat_ip)
            count_params.append(subscriber_cgnat_ip)

        query += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(count_query, count_params)
            total = cursor.fetchone()[0]

            cursor.execute(query, params)
            rows = cursor.fetchall()
            incidents = [
                Incident(
                    incident_id=r["incident_id"],
                    title=r["title"],
                    category=DetectionCategory(r["category"]) if r["category"] in [e.value for e in DetectionCategory] else DetectionCategory.CUSTOM,
                    severity=SecuritySeverity(r["severity"]) if r["severity"] in [e.value for e in SecuritySeverity] else SecuritySeverity.MEDIUM,
                    status=IncidentStatus(r["status"]) if r["status"] in [e.value for e in IncidentStatus] else IncidentStatus.NEW,
                    first_seen=r["first_seen"],
                    last_seen=r["last_seen"],
                    affected_subscriber_ip=r["affected_subscriber_ip"],
                    pppoe_username=r["pppoe_username"],
                    affected_public_ip=r["affected_public_ip"],
                    evidence_summary=json.loads(r["evidence_summary_json"]) if r["evidence_summary_json"] else {},
                    assigned_operator=r["assigned_operator"],
                    resolution_notes=r["resolution_notes"],
                    event_count=r["event_count"],
                    total_bytes=r["total_bytes"],
                    total_packets=r["total_packets"],
                    created_at=r["created_at"],
                    updated_at=r["updated_at"]
                )
                for r in rows
            ]
            return incidents, total

    def get_incident_by_id(self, incident_id: str) -> Optional[Tuple[Incident, List[SecurityEvent]]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
            r = cursor.fetchone()
            if not r:
                return None
            incident = Incident(
                incident_id=r["incident_id"],
                title=r["title"],
                category=DetectionCategory(r["category"]) if r["category"] in [e.value for e in DetectionCategory] else DetectionCategory.CUSTOM,
                severity=SecuritySeverity(r["severity"]) if r["severity"] in [e.value for e in SecuritySeverity] else SecuritySeverity.MEDIUM,
                status=IncidentStatus(r["status"]) if r["status"] in [e.value for e in IncidentStatus] else IncidentStatus.NEW,
                first_seen=r["first_seen"],
                last_seen=r["last_seen"],
                affected_subscriber_ip=r["affected_subscriber_ip"],
                pppoe_username=r["pppoe_username"],
                affected_public_ip=r["affected_public_ip"],
                evidence_summary=json.loads(r["evidence_summary_json"]) if r["evidence_summary_json"] else {},
                assigned_operator=r["assigned_operator"],
                resolution_notes=r["resolution_notes"],
                event_count=r["event_count"],
                total_bytes=r["total_bytes"],
                total_packets=r["total_packets"],
                created_at=r["created_at"],
                updated_at=r["updated_at"]
            )

            # Get linked events
            cursor.execute("""
                SELECT se.* FROM security_events se
                JOIN incident_events ie ON se.event_id = ie.event_id
                WHERE ie.incident_id = ?
                ORDER BY se.event_timestamp DESC
                LIMIT 100
            """, (incident_id,))
            rows = cursor.fetchall()
            events = [
                SecurityEvent(
                    event_id=er["event_id"],
                    source_event_id=er["source_event_id"],
                    event_timestamp=er["event_timestamp"],
                    received_timestamp=er["received_timestamp"],
                    sensor_id=er["sensor_id"],
                    observation_point=er["observation_point"],
                    source_ip=er["source_ip"],
                    source_port=er["source_port"],
                    destination_ip=er["destination_ip"],
                    destination_port=er["destination_port"],
                    protocol=er["protocol"],
                    traffic_direction=TrafficDirection(er["traffic_direction"]) if er["traffic_direction"] in [e.value for e in TrafficDirection] else TrafficDirection.OUTBOUND,
                    event_type=er["event_type"],
                    signature_id=er["signature_id"],
                    signature_name=er["signature_name"],
                    category=DetectionCategory(er["category"]) if er["category"] in [e.value for e in DetectionCategory] else DetectionCategory.CUSTOM,
                    severity=SecuritySeverity(er["severity"]) if er["severity"] in [e.value for e in SecuritySeverity] else SecuritySeverity.MEDIUM,
                    packets=er["packets"],
                    bytes=er["bytes"],
                    flow_id=er["flow_id"],
                    original_event_reference=er["original_event_reference"],
                    attribution_status=AttributionStatus(er["attribution_status"]) if er["attribution_status"] in [e.value for e in AttributionStatus] else AttributionStatus.UNRESOLVED,
                    mapping_id=er["mapping_id"],
                    subscriber_cgnat_ip=er["subscriber_cgnat_ip"],
                    pppoe_username=er["pppoe_username"],
                    attribution_method=er["attribution_method"],
                    detection_rule_id=er["detection_rule_id"],
                    created_at=er["created_at"]
                )
                for er in rows
            ]
            return incident, events

    def upsert_incident(self, incident: Incident, linked_event_id: Optional[str] = None) -> bool:
        now = get_utc_now_iso()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO incidents (
                    incident_id, title, category, severity, status, first_seen, last_seen,
                    affected_subscriber_ip, pppoe_username, affected_public_ip,
                    evidence_summary_json, assigned_operator, resolution_notes,
                    event_count, total_bytes, total_packets, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    title = excluded.title,
                    severity = excluded.severity,
                    last_seen = excluded.last_seen,
                    affected_subscriber_ip = excluded.affected_subscriber_ip,
                    pppoe_username = excluded.pppoe_username,
                    affected_public_ip = excluded.affected_public_ip,
                    evidence_summary_json = excluded.evidence_summary_json,
                    event_count = incidents.event_count + 1,
                    total_bytes = incidents.total_bytes + excluded.total_bytes,
                    total_packets = incidents.total_packets + excluded.total_packets,
                    updated_at = excluded.updated_at
            """, (
                incident.incident_id,
                incident.title,
                incident.category.value if hasattr(incident.category, 'value') else str(incident.category),
                incident.severity.value if hasattr(incident.severity, 'value') else str(incident.severity),
                incident.status.value if hasattr(incident.status, 'value') else str(incident.status),
                incident.first_seen,
                incident.last_seen,
                incident.affected_subscriber_ip,
                incident.pppoe_username,
                incident.affected_public_ip,
                json.dumps(incident.evidence_summary),
                incident.assigned_operator,
                incident.resolution_notes,
                incident.event_count,
                incident.total_bytes,
                incident.total_packets,
                incident.created_at or now,
                now
            ))

            if linked_event_id:
                cursor.execute("""
                    INSERT OR IGNORE INTO incident_events (incident_id, event_id)
                    VALUES (?, ?)
                """, (incident.incident_id, linked_event_id))

            conn.commit()
            return True

    def update_incident_status(
        self,
        incident_id: str,
        status: IncidentStatus,
        operator: Optional[str] = None,
        notes: Optional[str] = None
    ) -> bool:
        now = get_utc_now_iso()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE incidents
                SET status = ?,
                    assigned_operator = COALESCE(?, assigned_operator),
                    resolution_notes = COALESCE(?, resolution_notes),
                    updated_at = ?
                WHERE incident_id = ?
            """, (status.value, operator, notes, now, incident_id))
            conn.commit()
            return cursor.rowcount > 0

    # -------------------------------------------------------------
    # DETECTION RULES CRUD
    # -------------------------------------------------------------
    def get_detection_rules(self) -> List[DetectionRule]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM detection_rules ORDER BY name ASC")
            rows = cursor.fetchall()
            return [
                DetectionRule(
                    rule_id=r["rule_id"],
                    name=r["name"],
                    category=DetectionCategory(r["category"]) if r["category"] in [e.value for e in DetectionCategory] else DetectionCategory.CUSTOM,
                    enabled=bool(r["enabled"]),
                    threshold_configuration=json.loads(r["threshold_config_json"]) if r["threshold_config_json"] else {},
                    time_window_seconds=r["time_window_seconds"],
                    severity=SecuritySeverity(r["severity"]) if r["severity"] in [e.value for e in SecuritySeverity] else SecuritySeverity.MEDIUM,
                    exclusions=json.loads(r["exclusions_json"]) if r["exclusions_json"] else [],
                    created_by=r["created_by"],
                    updated_by=r["updated_by"],
                    created_at=r["created_at"],
                    updated_at=r["updated_at"]
                )
                for r in rows
            ]

    def update_detection_rule(
        self,
        rule_id: str,
        enabled: Optional[bool] = None,
        threshold_config: Optional[Dict[str, Any]] = None,
        time_window_seconds: Optional[int] = None,
        severity: Optional[str] = None,
        exclusions: Optional[List[str]] = None,
        operator: str = "admin"
    ) -> bool:
        now = get_utc_now_iso()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM detection_rules WHERE rule_id = ?", (rule_id,))
            row = cursor.fetchone()
            if not row:
                return False

            new_enabled = int(enabled) if enabled is not None else row["enabled"]
            new_threshold = json.dumps(threshold_config) if threshold_config is not None else row["threshold_config_json"]
            new_window = time_window_seconds if time_window_seconds is not None else row["time_window_seconds"]
            new_severity = severity if severity is not None else row["severity"]
            new_exclusions = json.dumps(exclusions) if exclusions is not None else row["exclusions_json"]

            cursor.execute("""
                UPDATE detection_rules
                SET enabled = ?, threshold_config_json = ?, time_window_seconds = ?,
                    severity = ?, exclusions_json = ?, updated_by = ?, updated_at = ?
                WHERE rule_id = ?
            """, (new_enabled, new_threshold, new_window, new_severity, new_exclusions, operator, now, rule_id))
            conn.commit()
            return cursor.rowcount > 0

    # -------------------------------------------------------------
    # INTEGRATION HEALTH CRUD
    # -------------------------------------------------------------
    def get_all_integration_health(self) -> List[IntegrationHealth]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM integration_health ORDER BY integration_name ASC")
            rows = cursor.fetchall()
            return [
                IntegrationHealth(
                    integration_name=r["integration_name"],
                    connectivity=r["connectivity"],
                    last_successful_ingestion=r["last_successful_ingestion"],
                    last_event_timestamp=r["last_event_timestamp"],
                    processing_lag_ms=r["processing_lag_ms"],
                    error_count=r["error_count"],
                    queue_depth=r["queue_depth"],
                    last_error=r["last_error"],
                    configuration_status=r["configuration_status"],
                    updated_at=r["updated_at"]
                )
                for r in rows
            ]

    def update_integration_health(
        self,
        name: str,
        connectivity: str,
        lag_ms: float = 0.0,
        error: Optional[str] = None,
        queue_depth: int = 0
    ):
        now = get_utc_now_iso()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO integration_health (
                    integration_name, connectivity, last_successful_ingestion,
                    last_event_timestamp, processing_lag_ms, error_count, queue_depth,
                    last_error, configuration_status, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'configured', ?)
                ON CONFLICT(integration_name) DO UPDATE SET
                    connectivity = excluded.connectivity,
                    last_successful_ingestion = CASE WHEN excluded.connectivity = 'online' THEN excluded.last_successful_ingestion ELSE integration_health.last_successful_ingestion END,
                    last_event_timestamp = excluded.last_event_timestamp,
                    processing_lag_ms = excluded.processing_lag_ms,
                    error_count = CASE WHEN excluded.connectivity = 'online' THEN 0 ELSE integration_health.error_count + 1 END,
                    queue_depth = excluded.queue_depth,
                    last_error = excluded.last_error,
                    updated_at = excluded.updated_at
            """, (name, connectivity, now, now, lag_ms, 1 if error else 0, queue_depth, error, now))
            conn.commit()

    # -------------------------------------------------------------
    # OPENSEARCH DURABLE QUEUE BUFFER
    # -------------------------------------------------------------
    def enqueue_opensearch_doc(self, index_name: str, doc_id: str, document: Dict[str, Any]) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO opensearch_queue (index_name, doc_id, document_json, status)
                VALUES (?, ?, ?, 'pending')
            """, (index_name, doc_id, json.dumps(document)))
            conn.commit()
            return cursor.lastrowid

    def get_pending_opensearch_docs(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, index_name, doc_id, document_json, attempts
                FROM opensearch_queue
                WHERE status = 'pending' AND attempts < 5
                ORDER BY id ASC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [
                {
                    "id": r["id"],
                    "index_name": r["index_name"],
                    "doc_id": r["doc_id"],
                    "document": json.loads(r["document_json"]),
                    "attempts": r["attempts"]
                }
                for r in rows
            ]

    def mark_opensearch_docs_completed(self, doc_ids: List[int]):
        if not doc_ids:
            return
        placeholders = ",".join("?" for _ in doc_ids)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"DELETE FROM opensearch_queue WHERE id IN ({placeholders})", doc_ids)
            conn.commit()

    def mark_opensearch_doc_failed(self, doc_id: int, error_msg: str):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE opensearch_queue
                SET attempts = attempts + 1,
                    last_error = ?,
                    status = CASE WHEN attempts >= 5 THEN 'dead_letter' ELSE 'pending' END
                WHERE id = ?
            """, (error_msg, doc_id))
            conn.commit()

    def get_opensearch_queue_depth(self) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM opensearch_queue WHERE status = 'pending'")
            return cursor.fetchone()[0]

    # -------------------------------------------------------------
    # SECURITY AUDIT LOGGING
    # -------------------------------------------------------------
    def log_security_audit(
        self,
        operator_id: str,
        action: str,
        target_type: str,
        target_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        outcome: str = "success",
        sanitized_details: Optional[Dict[str, Any]] = None
    ):
        audit_id = str(uuid.uuid4())
        now = get_utc_now_iso()
        det_json = json.dumps(sanitized_details or {})
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO security_audit_logs (
                    audit_id, operator_id, action, target_type, target_id,
                    timestamp, source_ip, outcome, sanitized_details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (audit_id, operator_id, action, target_type, target_id, now, source_ip, outcome, det_json))
            conn.commit()

    def log_audit_event(
        self,
        operator_id: str,
        action: str,
        target_type: str,
        target_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        outcome: str = "success",
        details: Optional[Dict[str, Any]] = None,
        sanitized_details: Optional[Dict[str, Any]] = None,
    ):
        return self.log_security_audit(
            operator_id=operator_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            source_ip=source_ip,
            outcome=outcome,
            sanitized_details=sanitized_details or details or {}
        )

    def get_security_audit_logs(self, limit: int = 100, offset: int = 0) -> Tuple[List[AuditLogEntry], int]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM security_audit_logs")
            total = cursor.fetchone()[0]

            cursor.execute("""
                SELECT * FROM security_audit_logs
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            """, (limit, offset))
            rows = cursor.fetchall()
            logs = [
                AuditLogEntry(
                    audit_id=r["audit_id"],
                    operator_id=r["operator_id"],
                    action=r["action"],
                    target_type=r["target_type"],
                    target_id=r["target_id"],
                    timestamp=r["timestamp"],
                    source_ip=r["source_ip"],
                    outcome=r["outcome"],
                    sanitized_details=json.loads(r["sanitized_details_json"]) if r["sanitized_details_json"] else {}
                )
                for r in rows
            ]
            return logs, total

    # -------------------------------------------------------------
    # SUBSCRIBER SECURITY PROFILE
    # -------------------------------------------------------------
    def get_subscriber_profile(self, cgnat_ip: str) -> Dict[str, Any]:
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Sessions history
            cursor.execute("""
                SELECT * FROM subscriber_sessions
                WHERE subscriber_cgnat_ip = ?
                ORDER BY started_at DESC LIMIT 50
            """, (cgnat_ip,))
            session_rows = cursor.fetchall()
            sessions = [
                {
                    "session_id": r["session_id"],
                    "pppoe_username": r["pppoe_username"],
                    "access_concentrator": r["access_concentrator"],
                    "started_at": r["started_at"],
                    "ended_at": r["ended_at"],
                    "session_source": r["session_source"]
                }
                for r in session_rows
            ]

            # 2. CGNAT Mapping history
            cursor.execute("""
                SELECT * FROM cgnat_mappings
                WHERE subscriber_cgnat_ip = ?
                ORDER BY effective_from DESC LIMIT 10
            """, (cgnat_ip,))
            mapping_rows = cursor.fetchall()
            mappings = [
                {
                    "mapping_id": r["mapping_id"],
                    "public_ip": r["public_ip"],
                    "port_start": r["port_start"],
                    "port_end": r["port_end"],
                    "protocol_scope": r["protocol_scope"],
                    "effective_from": r["effective_from"],
                    "effective_to": r["effective_to"],
                    "validation_status": r["validation_status"]
                }
                for r in mapping_rows
            ]

            # 3. Incidents
            cursor.execute("""
                SELECT * FROM incidents
                WHERE affected_subscriber_ip = ?
                ORDER BY last_seen DESC LIMIT 20
            """, (cgnat_ip,))
            incident_rows = cursor.fetchall()
            incidents = [
                {
                    "incident_id": r["incident_id"],
                    "title": r["title"],
                    "category": r["category"],
                    "severity": r["severity"],
                    "status": r["status"],
                    "first_seen": r["first_seen"],
                    "last_seen": r["last_seen"],
                    "event_count": r["event_count"]
                }
                for r in incident_rows
            ]

            # 4. Summary metrics
            cursor.execute("""
                SELECT COUNT(*), MIN(event_timestamp), MAX(event_timestamp),
                       SUM(COALESCE(bytes, 0)), SUM(COALESCE(packets, 0))
                FROM security_events
                WHERE subscriber_cgnat_ip = ?
            """, (cgnat_ip,))
            stats = cursor.fetchone()
            total_events = stats[0] or 0
            first_observed = stats[1]
            last_observed = stats[2]
            total_bytes = stats[3] or 0
            total_packets = stats[4] or 0

            # 5. Top categories
            cursor.execute("""
                SELECT category, COUNT(*) as cnt
                FROM security_events
                WHERE subscriber_cgnat_ip = ?
                GROUP BY category
                ORDER BY cnt DESC LIMIT 5
            """, (cgnat_ip,))
            category_counts = {r[0]: r[1] for r in cursor.fetchall()}

            return {
                "subscriber_cgnat_ip": cgnat_ip,
                "current_username": sessions[0]["pppoe_username"] if sessions else None,
                "sessions_history": sessions,
                "cgnat_mappings": mappings,
                "incidents": incidents,
                "metrics": {
                    "total_security_events": total_events,
                    "first_observed": first_observed,
                    "last_observed": last_observed,
                    "total_bytes": total_bytes,
                    "total_packets": total_packets,
                    "detection_categories": category_counts
                }
            }

    # -------------------------------------------------------------
    # SECURITY APP SETTINGS
    # -------------------------------------------------------------
    def get_security_settings(self, key: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value_json FROM app_settings WHERE key = ?", (key,))
            row = cursor.fetchone()
            if row and row[0]:
                return json.loads(row[0])
            return None

    def set_security_settings(self, key: str, value: Dict[str, Any]) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO app_settings (key, value_json)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = CURRENT_TIMESTAMP
            """, (key, json.dumps(value)))
            conn.commit()
            return True

    # -------------------------------------------------------------
    # ROUTER MANAGEMENT & ONBOARDING METHODS
    # -------------------------------------------------------------
    def get_routers(self, role: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if role and role.lower() != "all":
                cursor.execute("""
                    SELECT id, name, role, host, port, username, use_ssl, use_rest,
                           status, model, ros_version, cpu_load, uptime, last_seen, last_error, notes, enabled, created_at, updated_at
                    FROM routers WHERE role = ? ORDER BY created_at ASC
                """, (role.lower(),))
            else:
                cursor.execute("""
                    SELECT id, name, role, host, port, username, use_ssl, use_rest,
                           status, model, ros_version, cpu_load, uptime, last_seen, last_error, notes, enabled, created_at, updated_at
                    FROM routers ORDER BY created_at ASC
                """)
            cols = [col[0] for col in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def get_router(self, router_id: str, include_password: bool = False) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if include_password:
                cursor.execute("SELECT * FROM routers WHERE id = ?", (router_id,))
            else:
                cursor.execute("""
                    SELECT id, name, role, host, port, username, use_ssl, use_rest,
                           status, model, ros_version, cpu_load, uptime, last_seen, last_error, notes, enabled, created_at, updated_at
                    FROM routers WHERE id = ?
                """, (router_id,))
            row = cursor.fetchone()
            if not row:
                return None
            cols = [col[0] for col in cursor.description]
            return dict(zip(cols, row))

    def create_router(self, router_data: Dict[str, Any]) -> str:
        router_id = router_data.get("id") or f"router-{uuid.uuid4().hex[:8]}"
        now = get_utc_now_iso()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO routers (
                    id, name, role, host, port, username, password, use_ssl, use_rest,
                    status, model, ros_version, cpu_load, uptime, last_seen, last_error, notes, enabled, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                router_id,
                router_data["name"],
                router_data.get("role", "core"),
                router_data["host"],
                router_data.get("port", 8728),
                router_data.get("username", "security_ro"),
                router_data["password"],
                1 if router_data.get("use_ssl") else 0,
                1 if router_data.get("use_rest") else 0,
                router_data.get("status", "untested"),
                router_data.get("model"),
                router_data.get("ros_version"),
                router_data.get("cpu_load"),
                router_data.get("uptime"),
                router_data.get("last_seen"),
                router_data.get("last_error"),
                router_data.get("notes", ""),
                1 if router_data.get("enabled", True) else 0,
                now, now
            ))
            conn.commit()
            return router_id

    def update_router(self, router_id: str, updates: Dict[str, Any]) -> bool:
        allowed = ["name", "role", "host", "port", "username", "password", "use_ssl", "use_rest", "notes", "enabled"]
        query_parts = []
        params = []
        for k, v in updates.items():
            if k in allowed and v is not None:
                if k in ["use_ssl", "use_rest", "enabled"]:
                    query_parts.append(f"{k} = ?")
                    params.append(1 if v else 0)
                else:
                    query_parts.append(f"{k} = ?")
                    params.append(v)
        if not query_parts:
            return False

        query_parts.append("updated_at = CURRENT_TIMESTAMP")
        params.append(router_id)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"UPDATE routers SET {', '.join(query_parts)} WHERE id = ?", params)
            conn.commit()
            return cursor.rowcount > 0

    def delete_router(self, router_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM routers WHERE id = ?", (router_id,))
            conn.commit()
            return cursor.rowcount > 0

    def update_router_telemetry(
        self,
        router_id: str,
        status: str,
        model: Optional[str] = None,
        ros_version: Optional[str] = None,
        cpu_load: Optional[int] = None,
        uptime: Optional[str] = None,
        last_error: Optional[str] = None
    ) -> bool:
        now = get_utc_now_iso()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE routers SET
                    status = ?,
                    model = COALESCE(?, model),
                    ros_version = COALESCE(?, ros_version),
                    cpu_load = COALESCE(?, cpu_load),
                    uptime = COALESCE(?, uptime),
                    last_seen = ?,
                    last_error = ?,
                    updated_at = ?
                WHERE id = ?
            """, (status, model, ros_version, cpu_load, uptime, now if status == 'online' else None, last_error, now, router_id))
            conn.commit()
            return cursor.rowcount > 0

