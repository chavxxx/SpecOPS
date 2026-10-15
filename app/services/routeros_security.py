"""
WISPnet MikroTik RouterOS v7 Security & Session Collector Adapter
Connects to MikroTik CCR2116 Core Router and PPPoE Access Concentrator in read-only mode.
"""
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone
import uuid

from app.models.security_schemas import (
    SubscriberSession,
    CGNATMapping
)
from app.database.db import DatabaseManager, get_db
from app.services.mikrotik_client import MikroTikAPIClient, MikroTikAPIError

logger = logging.getLogger(__name__)

class RouterOSSecurityAdapter:
    def __init__(
        self,
        core_host: str = "100.91.0.1",
        core_port: int = 8728,
        core_user: str = "security_ro",
        core_pass: str = "",
        core_use_ssl: bool = False,
        core_use_rest: bool = False,
        ac_host: str = "100.91.0.254",
        ac_port: int = 8728,
        ac_user: str = "security_ro",
        ac_pass: str = "",
        ac_use_ssl: bool = False,
        ac_use_rest: bool = False,
        db: Optional[DatabaseManager] = None
    ):
        self.core_client = MikroTikAPIClient(
            host=core_host,
            port=core_port,
            username=core_user,
            password=core_pass,
            use_ssl=core_use_ssl,
            use_rest=core_use_rest,
            timeout=5.0
        )
        self.ac_client = MikroTikAPIClient(
            host=ac_host,
            port=ac_port,
            username=ac_user,
            password=ac_pass,
            use_ssl=ac_use_ssl,
            use_rest=ac_use_rest,
            timeout=5.0
        )
        self.db = db or get_db()

    def test_core_connection(self) -> Dict[str, Any]:
        """Tests connectivity and RouterOS v7 identification on Core Router (CCR2116)"""
        try:
            self.core_client.connect()
            identity = self.core_client.talk(["/system/identity/print"])
            resource = self.core_client.talk(["/system/resource/print"])
            self.core_client.close()

            name = identity[0].get("name", "CCR2116-Core") if identity else "CCR2116-Core"
            version = resource[0].get("version", "v7.15") if resource else "RouterOS v7"
            cpu_load = resource[0].get("cpu-load", "0") if resource else "0"
            uptime = resource[0].get("uptime", "unknown") if resource else "unknown"

            self.db.update_integration_health("RouterOS-Core", "online", lag_ms=10.0)
            return {
                "online": True,
                "name": name,
                "version": version,
                "cpu_load": int(cpu_load) if str(cpu_load).isdigit() else 0,
                "uptime": uptime,
                "model": resource[0].get("board-name", "CCR2116-12G-4S+") if resource else "CCR2116"
            }
        except Exception as e:
            logger.warning(f"Core router connection check failed: {e}")
            self.db.update_integration_health("RouterOS-Core", "degraded", error=str(e))
            return {
                "online": False,
                "error": str(e)
            }

    def test_ac_connection(self) -> Dict[str, Any]:
        """Tests connectivity and RouterOS v7 identification on PPPoE Access Concentrator (CCR2116)"""
        try:
            self.ac_client.connect()
            identity = self.ac_client.talk(["/system/identity/print"])
            resource = self.ac_client.talk(["/system/resource/print"])
            self.ac_client.close()

            name = identity[0].get("name", "CCR2116-PPPoE-AC") if identity else "CCR2116-PPPoE-AC"
            version = resource[0].get("version", "v7.15") if resource else "RouterOS v7"
            cpu_load = resource[0].get("cpu-load", "0") if resource else "0"
            uptime = resource[0].get("uptime", "unknown") if resource else "unknown"

            self.db.update_integration_health("RouterOS-PPPoE-AC", "online", lag_ms=8.0)
            return {
                "online": True,
                "name": name,
                "version": version,
                "cpu_load": int(cpu_load) if str(cpu_load).isdigit() else 0,
                "uptime": uptime,
                "model": resource[0].get("board-name", "CCR2116-12G-4S+") if resource else "CCR2116"
            }
        except Exception as e:
            logger.warning(f"PPPoE AC connection check failed: {e}")
            self.db.update_integration_health("RouterOS-PPPoE-AC", "degraded", error=str(e))
            return {
                "online": False,
                "error": str(e)
            }

    def harvest_active_pppoe_sessions(self, access_concentrator_id: str = "pppoe-ac-ccr2116") -> List[SubscriberSession]:
        """
        Reads active PPPoE and Hotspot sessions from RouterOS v7.
        Stores time-bounded session records in subscriber_sessions.
        """
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        sessions: List[SubscriberSession] = []

        try:
            self.ac_client.connect()
            raw_sessions = self.ac_client.talk(["/ppp/active/print"])
            self.ac_client.close()

            for item in raw_sessions:
                user = item.get("name")
                cgnat_ip = item.get("address")
                session_id = item.get(".id", str(uuid.uuid4()))

                if user and cgnat_ip:
                    sess = SubscriberSession(
                        session_id=f"sess-{access_concentrator_id}-{user}",
                        pppoe_username=user,
                        subscriber_cgnat_ip=cgnat_ip,
                        access_concentrator=access_concentrator_id,
                        router_session_id=session_id,
                        started_at=now_iso,
                        ended_at=None,
                        session_source="routeros_active",
                        last_synchronized_at=now_iso
                    )
                    self.db.upsert_subscriber_session(sess)
                    sessions.append(sess)

            # Also attempt to harvest active Hotspot sessions if running on this router
            try:
                self.ac_client.connect()
                raw_hotspot = self.ac_client.talk(["/ip/hotspot/active/print"])
                self.ac_client.close()

                for item in raw_hotspot:
                    user = item.get("user")
                    cgnat_ip = item.get("address")
                    session_id = item.get(".id", str(uuid.uuid4()))

                    if user and cgnat_ip:
                        sess = SubscriberSession(
                            session_id=f"sess-hs-{access_concentrator_id}-{user}",
                            pppoe_username=f"hs:{user}",
                            subscriber_cgnat_ip=cgnat_ip,
                            access_concentrator=access_concentrator_id,
                            router_session_id=session_id,
                            started_at=now_iso,
                            ended_at=None,
                            session_source="routeros_hotspot",
                            last_synchronized_at=now_iso
                        )
                        self.db.upsert_subscriber_session(sess)
                        sessions.append(sess)
            except Exception as e_hs:
                logger.debug(f"Hotspot harvest note on {access_concentrator_id}: {e_hs}")

            self.db.update_integration_health("RouterOS-PPPoE-AC", "online", lag_ms=12.0)
            return sessions

        except Exception as e:
            logger.error(f"Error harvesting subscriber active sessions: {e}")
            self.db.update_integration_health("RouterOS-PPPoE-AC", "degraded", error=str(e))
            return []

    def inspect_core_nat_rules(self) -> List[Dict[str, Any]]:
        """
        Reads active RouterOS v7 NAT firewall rules from Core Router
        Used to audit deployed CGNAT rules against the authoritative mapping table.
        """
        try:
            self.core_client.connect()
            rules = self.core_client.talk(["/ip/firewall/nat/print", "?chain=srcnat", "?action=src-nat"])
            self.core_client.close()
            self.db.update_integration_health("RouterOS-Core", "online", lag_ms=10.0)
            return rules
        except Exception as e:
            logger.warning(f"Failed to inspect Core Router NAT rules: {e}")
            self.db.update_integration_health("RouterOS-Core", "degraded", error=str(e))
            return []
