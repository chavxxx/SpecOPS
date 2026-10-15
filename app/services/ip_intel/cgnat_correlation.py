"""
Deterministic CGNAT Correlation & Intrusion Telemetry Linker
Correlates IP reputation findings with historical CGNAT mappings, Suricata alerts, and Akvorado flows.
WISP Network & Data Solutions (WISPnet)
"""
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone
import logging

from app.database.db import get_db, DatabaseManager
from app.models.ip_intel_schemas import CGNATCorrelationBrief
from app.services.akvorado_adapter import get_akvorado_adapter

logger = logging.getLogger(__name__)

class CGNATReputationCorrelator:
    """Links reputation findings to authoritative CGNAT mappings without guessing"""

    @classmethod
    def correlate_cgnat(
        cls,
        ip_str: str,
        event_port: Optional[int] = None,
        event_timestamp: Optional[str] = None,
        db: Optional[DatabaseManager] = None
    ) -> CGNATCorrelationBrief:
        db = db or get_db()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        query_time = event_timestamp or now

        # 1. Query all mappings for this public IP
        with db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM cgnat_mappings
                WHERE public_ip = ?
                  AND effective_from <= ?
                  AND (effective_to IS NULL OR effective_to >= ?)
                ORDER BY port_start ASC;
            """, (ip_str, query_time, query_time))
            rows = cursor.fetchall()

        if not rows:
            return CGNATCorrelationBrief(
                is_cgnat_public_pool=False,
                public_ip=ip_str,
                subscriber_candidates_count=0,
                exact_match=False,
                subscriber_cgnat_ip=None,
                pppoe_username=None,
                allocated_port_block=None,
                attribution_status="unattributed",
                explanation=f"IP {ip_str} is not part of the active deterministic CGNAT public pool."
            )

        candidates_count = len(rows)

        # 2. If a specific source port is provided, pinpoint exact deterministic block
        if event_port and event_port > 0:
            matching_row = None
            for r in rows:
                if r["port_start"] <= event_port <= r["port_end"]:
                    matching_row = r
                    break

            if matching_row:
                sub_ip = matching_row["subscriber_cgnat_ip"]
                port_block = f"{matching_row['port_start']}-{matching_row['port_end']}"
                
                # Check active subscriber session at query_time
                with db._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT * FROM subscriber_sessions
                        WHERE subscriber_cgnat_ip = ?
                          AND started_at <= ?
                          AND (ended_at IS NULL OR ended_at >= ?)
                        ORDER BY started_at DESC LIMIT 1;
                    """, (sub_ip, query_time, query_time))
                    sess_row = cursor.fetchone()

                pppoe_user = sess_row["pppoe_username"] if sess_row else matching_row["pppoe_username"]
                status = "verified" if pppoe_user else "high_confidence"

                return CGNATCorrelationBrief(
                    is_cgnat_public_pool=True,
                    public_ip=ip_str,
                    subscriber_candidates_count=candidates_count,
                    exact_match=True,
                    subscriber_cgnat_ip=sub_ip,
                    pppoe_username=pppoe_user,
                    allocated_port_block=port_block,
                    attribution_status=status,
                    explanation=f"Exact match on port {event_port}: allocated to subscriber {sub_ip} (Block: {port_block}, PPPoE: {pppoe_user or 'Unrecorded'})."
                )

        # 3. Source port missing -> Strictly refuse to guess a subscriber!
        return CGNATCorrelationBrief(
            is_cgnat_public_pool=True,
            public_ip=ip_str,
            subscriber_candidates_count=candidates_count,
            exact_match=False,
            subscriber_cgnat_ip=None,
            pppoe_username=None,
            allocated_port_block=None,
            attribution_status="partial",
            explanation=f"Public CGNAT IP shared across {candidates_count} subscribers (2,048-port blocks). Exact subscriber attribution requires the observed source port."
        )

    @classmethod
    def get_related_suricata_alerts(
        cls,
        ip_str: str,
        limit: int = 10,
        db: Optional[DatabaseManager] = None
    ) -> Tuple[int, List[Dict[str, Any]]]:
        """Retrieves Suricata security alerts involving this IP in either source or destination roles"""
        db = db or get_db()
        with db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) FROM security_events
                WHERE source_ip = ? OR destination_ip = ?;
            """, (ip_str, ip_str))
            total_count = cursor.fetchone()[0]

            cursor.execute("""
                SELECT event_id, event_timestamp, observation_point, source_ip, source_port,
                       destination_ip, destination_port, protocol, signature_name, category,
                       severity, attribution_status, subscriber_cgnat_ip, pppoe_username
                FROM security_events
                WHERE source_ip = ? OR destination_ip = ?
                ORDER BY event_timestamp DESC LIMIT ?;
            """, (ip_str, ip_str, limit))
            rows = cursor.fetchall()
            cols = [d[0] for d in cursor.description]
            alerts = [dict(zip(cols, r)) for r in rows]
            return total_count, alerts

    @classmethod
    async def get_related_flow_summary(cls, ip_str: str) -> Dict[str, Any]:
        """Queries Akvorado flow metrics for this public IP"""
        adapter = get_akvorado_adapter()
        try:
            return adapter.get_traffic_analytics(time_window_minutes=60)
        except Exception as e:
            logger.debug(f"Could not retrieve Akvorado flow summary for {ip_str}: {e}")
            return {"status": "unavailable", "message": str(e)}
