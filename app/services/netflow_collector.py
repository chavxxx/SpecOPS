"""
Carrier-Grade NetFlow v9 & IPFIX (v10) UDP Collector Engine
Receives and decodes real-time NetFlow telemetry streamed directly from MikroTik RouterOS hardware.
Binds to UDP port 2055, decodes RFC 7011 IPFIX / RFC 3954 NetFlow v9 records, correlates with active
PPPoE subscriber sessions and CGNAT pools, and writes directly into durable flow storage.
"""
import asyncio
import socket
import struct
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from app.database.db import get_db, DatabaseManager

logger = logging.getLogger("netflow_collector")

# IANA IP Protocol numbers
PROTO_MAP = {
    1: "icmp",
    2: "igmp",
    6: "tcp",
    17: "udp",
    41: "ipv6",
    47: "gre",
    50: "esp",
    51: "ah",
    58: "icmpv6",
    89: "ospf",
    132: "sctp"
}

def is_private_or_cgnat(ip_str: str) -> bool:
    """Checks if an IPv4 address is in CGNAT (100.64.0.0/10) or RFC 1918 private space"""
    try:
        octets = [int(p) for p in ip_str.split(".")]
        if len(octets) != 4:
            return False
        o1, o2 = octets[0], octets[1]
        # 100.64.0.0/10 (CGNAT Shared Address Space: 100.64.0.0 to 100.127.255.255)
        if o1 == 100 and (64 <= o2 <= 127):
            return True
        # 10.0.0.0/8
        if o1 == 10:
            return True
        # 172.16.0.0/12 (172.16.0.0 to 172.31.255.255)
        if o1 == 172 and (16 <= o2 <= 31):
            return True
        # 192.168.0.0/16
        if o1 == 192 and o2 == 168:
            return True
        return False
    except Exception:
        return False


class NetFlowProtocol(asyncio.DatagramProtocol):
    def __init__(self, collector: "NetFlowCollector"):
        self.collector = collector

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport
        logger.info(f"NetFlow/IPFIX UDP socket bound on {self.collector.host}:{self.collector.port}")

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        self.collector.process_datagram(data, addr)

    def error_received(self, exc: Exception):
        logger.warning(f"NetFlow UDP socket error: {exc}")

    def connection_lost(self, exc: Optional[Exception]):
        if exc:
            logger.error(f"NetFlow UDP socket closed with error: {exc}")
        else:
            logger.info("NetFlow UDP socket closed cleanly")


class NetFlowCollector:
    """
    High-performance asyncio UDP collector for MikroTik NetFlow v9 and IPFIX (v10).
    Maintains dynamic template state and batches flows into SQLite storage.
    """
    def __init__(self, host: str = "0.0.0.0", port: int = 2055, db: Optional[DatabaseManager] = None):
        self.host = host
        self.port = port
        self.db = db or get_db()
        self.running = False
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.protocol: Optional[NetFlowProtocol] = None
        
        # Templates: (source_addr, domain_id) -> {template_id: [(field_type, field_len, is_enterprise, enterprise_num), ...]}
        self.templates: Dict[Tuple[str, int], Dict[int, List[Tuple[int, int, bool, int]]]] = {}
        
        # Buffer and locks
        self.flow_buffer: List[Dict[str, Any]] = []
        self._flush_task: Optional[asyncio.Task] = None
        self._cache_reload_task: Optional[asyncio.Task] = None
        
        # Active subscriber IP -> username cache
        self.sub_cache: Dict[str, str] = {}
        self.total_packets_received = 0
        self.total_flows_decoded = 0

    def reload_subscriber_cache(self):
        """Loads subscriber sessions into high-speed memory lookup table"""
        try:
            cache = {}
            with self.db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT subscriber_cgnat_ip, pppoe_username FROM subscriber_sessions WHERE subscriber_cgnat_ip IS NOT NULL")
                for r in cursor.fetchall():
                    if r[0] and r[1]:
                        cache[r[0]] = r[1]
                cursor.execute("SELECT subscriber_cgnat_ip, pppoe_username FROM cgnat_mappings WHERE subscriber_cgnat_ip IS NOT NULL")
                for r in cursor.fetchall():
                    if r[0] and r[1] and r[0] not in cache:
                        cache[r[0]] = r[1]
            self.sub_cache = cache
        except Exception as e:
            logger.debug(f"Subscriber cache refresh error: {e}")

    async def start(self):
        if self.running:
            return
        self.running = True
        self.reload_subscriber_cache()
        
        loop = asyncio.get_running_loop()
        try:
            self.transport, self.protocol = await loop.create_datagram_endpoint(
                lambda: NetFlowProtocol(self),
                local_addr=(self.host, self.port)
            )
            self._flush_task = asyncio.create_task(self._periodic_flush())
            self._cache_reload_task = asyncio.create_task(self._periodic_cache_reload())
            logger.info(f"Carrier NetFlow & IPFIX Collector active on {self.host}:{self.port}")
            self.db.update_integration_health("Akvorado-Flow", "online", lag_ms=1.0)
        except Exception as e:
            logger.error(f"Failed to bind NetFlow UDP port {self.port}: {e}")
            self.running = False

    async def stop(self):
        self.running = False
        if self._flush_task:
            self._flush_task.cancel()
        if self._cache_reload_task:
            self._cache_reload_task.cancel()
        if self.transport:
            self.transport.close()
            self.transport = None
        # Final flush
        await self.flush_buffer()
        logger.info("NetFlow Collector stopped")

    def process_datagram(self, data: bytes, addr: Tuple[str, int]):
        """Processes an incoming NetFlow v9 or IPFIX datagram from a router"""
        if len(data) < 16:
            return
        self.total_packets_received += 1
        
        try:
            version = struct.unpack("!H", data[:2])[0]
            if version == 10:
                self._parse_ipfix(data, addr)
            elif version == 9:
                self._parse_netflow_v9(data, addr)
        except Exception as e:
            logger.debug(f"Error parsing flow datagram from {addr}: {e}")

    def _parse_ipfix(self, data: bytes, addr: Tuple[str, int]):
        """Decodes RFC 7011 IPFIX Packet"""
        if len(data) < 16:
            return
        version, length, export_time, seq, domain_id = struct.unpack("!HHIII", data[:16])
        key = (addr[0], domain_id)
        if key not in self.templates:
            self.templates[key] = {}

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        offset = 16
        data_len = min(len(data), length)

        while offset + 4 <= data_len:
            set_id, set_len = struct.unpack("!HH", data[offset:offset+4])
            if set_len < 4 or offset + set_len > data_len:
                break
            set_data = data[offset+4:offset+set_len]
            offset += set_len

            if set_id == 2:
                # IPFIX Template Set
                t_offset = 0
                while t_offset + 4 <= len(set_data):
                    t_id, f_count = struct.unpack("!HH", set_data[t_offset:t_offset+4])
                    t_offset += 4
                    fields = []
                    for _ in range(f_count):
                        if t_offset + 4 > len(set_data):
                            break
                        f_type, f_len = struct.unpack("!HH", set_data[t_offset:t_offset+4])
                        t_offset += 4
                        enterprise = bool(f_type & 0x8000)
                        f_type = f_type & 0x7FFF
                        ent_num = 0
                        if enterprise and t_offset + 4 <= len(set_data):
                            ent_num = struct.unpack("!I", set_data[t_offset:t_offset+4])[0]
                            t_offset += 4
                        fields.append((f_type, f_len, enterprise, ent_num))
                    self.templates[key][t_id] = fields

            elif set_id in self.templates[key]:
                # IPFIX Data Set
                fields = self.templates[key][set_id]
                rec_len = sum(f[1] for f in fields)
                if rec_len == 0:
                    continue
                d_offset = 0
                while d_offset + rec_len <= len(set_data):
                    flow_rec = self._extract_flow_record(set_data[d_offset:d_offset+rec_len], fields, now_iso, addr[0])
                    if flow_rec:
                        self.flow_buffer.append(flow_rec)
                        self.total_flows_decoded += 1
                    d_offset += rec_len

    def _parse_netflow_v9(self, data: bytes, addr: Tuple[str, int]):
        """Decodes RFC 3954 NetFlow v9 Packet"""
        if len(data) < 20:
            return
        version, count, sys_uptime, unix_secs, seq, source_id = struct.unpack("!HHIIII", data[:20])
        key = (addr[0], source_id)
        if key not in self.templates:
            self.templates[key] = {}

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        offset = 20

        while offset + 4 <= len(data):
            flowset_id, flowset_len = struct.unpack("!HH", data[offset:offset+4])
            if flowset_len < 4 or offset + flowset_len > len(data):
                break
            fs_data = data[offset+4:offset+flowset_len]
            offset += flowset_len

            if flowset_id == 0:
                # NetFlow v9 Template FlowSet
                t_offset = 0
                while t_offset + 4 <= len(fs_data):
                    t_id, f_count = struct.unpack("!HH", fs_data[t_offset:t_offset+4])
                    t_offset += 4
                    fields = []
                    for _ in range(f_count):
                        if t_offset + 4 > len(fs_data):
                            break
                        f_type, f_len = struct.unpack("!HH", fs_data[t_offset:t_offset+4])
                        t_offset += 4
                        fields.append((f_type, f_len, False, 0))
                    self.templates[key][t_id] = fields

            elif flowset_id in self.templates[key]:
                # NetFlow v9 Data FlowSet
                fields = self.templates[key][flowset_id]
                rec_len = sum(f[1] for f in fields)
                if rec_len == 0:
                    continue
                d_offset = 0
                while d_offset + rec_len <= len(fs_data):
                    flow_rec = self._extract_flow_record(fs_data[d_offset:d_offset+rec_len], fields, now_iso, addr[0])
                    if flow_rec:
                        self.flow_buffer.append(flow_rec)
                        self.total_flows_decoded += 1
                    d_offset += rec_len

    def _extract_flow_record(self, raw_bytes: bytes, fields: List[Tuple[int, int, bool, int]], now_iso: str, router_host: str) -> Optional[Dict[str, Any]]:
        """Parses a single binary flow record according to its field template"""
        flow = {}
        pos = 0
        for ft, fl, en, ent in fields:
            if pos + fl > len(raw_bytes):
                break
            val = raw_bytes[pos:pos+fl]
            pos += fl

            if ft == 8 and fl == 4:
                flow["src_ip"] = socket.inet_ntoa(val)
            elif ft == 12 and fl == 4:
                flow["dst_ip"] = socket.inet_ntoa(val)
            elif ft == 7 and fl in (2, 4):
                flow["src_port"] = int.from_bytes(val, "big")
            elif ft == 11 and fl in (2, 4):
                flow["dst_port"] = int.from_bytes(val, "big")
            elif ft == 4 and fl in (1, 2):
                flow["proto"] = int.from_bytes(val, "big")
            elif ft == 1:
                flow["bytes"] = int.from_bytes(val, "big")
            elif ft == 2:
                flow["packets"] = int.from_bytes(val, "big")

        src_ip = flow.get("src_ip")
        dst_ip = flow.get("dst_ip")
        if not src_ip or not dst_ip:
            return None

        # Resolve protocol name
        p_num = flow.get("proto", 6)
        proto_name = PROTO_MAP.get(p_num, str(p_num))

        # Determine Subscriber CGNAT IP & Observation Point
        sub_cgnat_ip = None
        obs_point = "post_cgnat"
        if is_private_or_cgnat(src_ip):
            sub_cgnat_ip = src_ip
            obs_point = "pre_cgnat"
        elif is_private_or_cgnat(dst_ip):
            sub_cgnat_ip = dst_ip
            obs_point = "pre_cgnat"

        username = None
        if sub_cgnat_ip and sub_cgnat_ip in self.sub_cache:
            username = self.sub_cache[sub_cgnat_ip]

        return {
            "flow_id": f"flow-real-{uuid.uuid4().hex[:12]}",
            "timestamp": now_iso,
            "sensor_id": f"sensor-flow-{router_host}",
            "observation_point": obs_point,
            "source_ip": src_ip,
            "source_port": flow.get("src_port", 0),
            "destination_ip": dst_ip,
            "destination_port": flow.get("dst_port", 0),
            "protocol": proto_name,
            "packets": max(1, flow.get("packets", 1)),
            "bytes": max(0, flow.get("bytes", 0)),
            "subscriber_cgnat_ip": sub_cgnat_ip,
            "pppoe_username": username,
            "router_id": f"router-{router_host.replace('.', '-')}"
        }

    async def flush_buffer(self) -> int:
        """Flushes in-memory decoded flow records to SQLite storage"""
        if not self.flow_buffer:
            return 0
        batch = self.flow_buffer[:300]
        self.flow_buffer = self.flow_buffer[300:]
        try:
            inserted = self.db.insert_flow_records_batch(batch)
            self.db.update_integration_health("Akvorado-Flow", "online", lag_ms=0.8)
            return inserted
        except Exception as e:
            logger.error(f"Error persisting real flow batch: {e}")
            return 0

    async def _periodic_flush(self):
        while self.running:
            try:
                await asyncio.sleep(1.5)
                await self.flush_buffer()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Periodic flow flush error: {e}")

    async def _periodic_cache_reload(self):
        while self.running:
            try:
                await asyncio.sleep(60.0)
                self.reload_subscriber_cache()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Cache reload loop error: {e}")


_collector_instance: Optional[NetFlowCollector] = None

def get_netflow_collector() -> NetFlowCollector:
    global _collector_instance
    if _collector_instance is None:
        _collector_instance = NetFlowCollector()
    return _collector_instance
