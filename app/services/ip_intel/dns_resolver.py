"""
Asynchronous Pure-Python DNS Resolver for DNSBL, PTR, and Reputation Lookups
WISP Network & Data Solutions (WISPnet)
"""
import socket
import struct
import time
import random
import asyncio
from typing import List, Tuple, Optional, Dict, Any

class DNSQueryResult:
    def __init__(
        self,
        qname: str,
        qtype: str,
        status: str,
        rcode: int,
        answers: List[str],
        duration_ms: float,
        nameserver: str
    ):
        self.qname = qname
        self.qtype = qtype
        self.status = status  # NOERROR, NXDOMAIN, REFUSED, SERVFAIL, TIMEOUT, ERROR
        self.rcode = rcode
        self.answers = answers
        self.duration_ms = duration_ms
        self.nameserver = nameserver

    def is_listed(self) -> bool:
        return self.status == "NOERROR" and len(self.answers) > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "qname": self.qname,
            "qtype": self.qtype,
            "status": self.status,
            "rcode": self.rcode,
            "answers": self.answers,
            "duration_ms": self.duration_ms,
            "nameserver": self.nameserver
        }

def _decode_name(data: bytes, offset: int) -> Tuple[str, int]:
    parts = []
    visited = set()
    orig_offset = offset
    stepped = False
    while offset < len(data):
        if offset in visited:
            break
        visited.add(offset)
        length = data[offset]
        if (length & 0xC0) == 0xC0:
            if not stepped:
                orig_offset = offset + 2
                stepped = True
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            offset = pointer
            continue
        elif length == 0:
            offset += 1
            break
        else:
            offset += 1
            parts.append(data[offset:offset + length].decode("ascii", errors="replace"))
            offset += length
    return ".".join(parts), (orig_offset if stepped else offset)

def _build_dns_query(qname: str, qtype: int = 1) -> Tuple[bytes, int]:
    tx_id = random.randint(1, 65535)
    flags = 0x0100  # Standard query with recursion desired
    header = struct.pack(">HHHHHH", tx_id, flags, 1, 0, 0, 0)
    
    question = b""
    for part in qname.strip(".").split("."):
        encoded = part.encode("ascii", errors="replace")
        question += bytes([len(encoded)]) + encoded
    question += b"\x00"
    question += struct.pack(">HH", qtype, 1)  # Class 1 = IN
    
    return header + question, tx_id

def _query_dns_sync(
    qname: str,
    qtype_str: str = "A",
    nameserver: str = "8.8.8.8",
    timeout: float = 3.0
) -> DNSQueryResult:
    qtype_map = {"A": 1, "PTR": 12, "TXT": 16, "AAAA": 28}
    qtype = qtype_map.get(qtype_str.upper(), 1)
    
    payload, tx_id = _build_dns_query(qname, qtype)
    start_time = time.perf_counter()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    
    try:
        sock.sendto(payload, (nameserver, 53))
        data, _ = sock.recvfrom(2048)
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        
        if len(data) < 12:
            return DNSQueryResult(qname, qtype_str, "ERROR", -1, [], duration_ms, nameserver)
            
        resp_id, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
        if resp_id != tx_id:
            return DNSQueryResult(qname, qtype_str, "ERROR", -1, [], duration_ms, nameserver)
            
        rcode = flags & 0x000F
        rcode_names = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
        status_name = rcode_names.get(rcode, f"RCODE_{rcode}")
        
        # Skip question section
        offset = 12
        for _ in range(qdcount):
            _, offset = _decode_name(data, offset)
            offset += 4  # type and class
            
        answers = []
        for _ in range(ancount):
            if offset >= len(data):
                break
            _, offset = _decode_name(data, offset)
            atype, aclass, ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            rdata_end = offset + rdlen
            
            if atype == 1 and rdlen == 4:  # A
                answers.append(socket.inet_ntoa(data[offset:rdata_end]))
            elif atype == 28 and rdlen == 16:  # AAAA
                answers.append(socket.inet_ntop(socket.AF_INET6, data[offset:rdata_end]))
            elif atype == 12:  # PTR
                ptr_name, _ = _decode_name(data, offset)
                answers.append(ptr_name)
            elif atype == 16:  # TXT
                txt_len = data[offset]
                txt_val = data[offset + 1:offset + 1 + txt_len].decode("utf-8", errors="replace")
                answers.append(txt_val)
                
            offset = rdata_end
            
        return DNSQueryResult(qname, qtype_str, status_name, rcode, answers, duration_ms, nameserver)
        
    except socket.timeout:
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return DNSQueryResult(qname, qtype_str, "TIMEOUT", -1, [], duration_ms, nameserver)
    except Exception as e:
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return DNSQueryResult(qname, qtype_str, "ERROR", -1, [], duration_ms, nameserver)
    finally:
        sock.close()

async def async_query_dns(
    qname: str,
    qtype_str: str = "A",
    nameserver: str = "8.8.8.8",
    timeout: float = 3.0
) -> DNSQueryResult:
    """Asynchronous wrapper for DNS queries offloaded to executor"""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        _query_dns_sync,
        qname,
        qtype_str,
        nameserver,
        timeout
    )
