"""
Native pure-Python MikroTik RouterOS API Client & REST Client
Supports RouterOS v6 & v7, standard API (8728), TLS API (8729), and REST API (80/443).
"""
import socket
import ssl
import hashlib
import binascii
import time
import random
import logging
import httpx
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)

class MikroTikAPIError(Exception):
    pass

class MikroTikAPIClient:
    def __init__(
        self,
        host: str,
        username: str = "admin",
        password: str = "",
        port: int = 8728,
        use_ssl: bool = False,
        use_rest: bool = False,
        timeout: float = 10.0
    ):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.use_ssl = use_ssl
        self.use_rest = use_rest
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.is_connected = False
        self._read_buffer = bytearray()

    # -------------------------------------------------------------
    # ROUTEROS BINARY PROTOCOL LENGTH ENCODING / DECODING
    # -------------------------------------------------------------
    def _encode_length(self, length: int) -> bytes:
        if length < 0x80:
            return bytes([length])
        elif length < 0x4000:
            length |= 0x8000
            return bytes([(length >> 8) & 0xFF, length & 0xFF])
        elif length < 0x200000:
            length |= 0xC00000
            return bytes([(length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
        elif length < 0x10000000:
            length |= 0xE0000000
            return bytes([(length >> 24) & 0xFF, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
        else:
            return bytes([0xF0, (length >> 24) & 0xFF, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])

    def _read_bytes(self, n: int) -> bytes:
        while len(self._read_buffer) < n:
            chunk = self.sock.recv(16384)
            if not chunk:
                raise MikroTikAPIError("Connection closed unexpectedly while reading bytes")
            self._read_buffer.extend(chunk)
        res = bytes(self._read_buffer[:n])
        del self._read_buffer[:n]
        return res

    def _read_byte(self) -> int:
        return self._read_bytes(1)[0]

    def _decode_length(self) -> int:
        b = self._read_byte()
        if (b & 0x80) == 0x00:
            return b
        elif (b & 0xC0) == 0x80:
            b2 = self._read_byte()
            return ((b & 0x3F) << 8) + b2
        elif (b & 0xE0) == 0xC0:
            b2 = self._read_byte()
            b3 = self._read_byte()
            return ((b & 0x1F) << 16) + (b2 << 8) + b3
        elif (b & 0xF0) == 0xE0:
            b2 = self._read_byte()
            b3 = self._read_byte()
            b4 = self._read_byte()
            return ((b & 0x0F) << 24) + (b2 << 16) + (b3 << 8) + b4
        elif b == 0xF0:
            b1 = self._read_byte()
            b2 = self._read_byte()
            b3 = self._read_byte()
            b4 = self._read_byte()
            return (b1 << 24) + (b2 << 16) + (b3 << 8) + b4
        else:
            raise MikroTikAPIError(f"Unsupported word length prefix: {b:02x}")

    def _write_word(self, word: str):
        data = word.encode('utf-8', errors='replace')
        len_bytes = self._encode_length(len(data))
        self.sock.sendall(len_bytes + data)

    def _read_word(self) -> str:
        length = self._decode_length()
        if length == 0:
            return ""
        data = self._read_bytes(length)
        return data.decode('utf-8', errors='replace')

    def _write_sentence(self, words: List[str]):
        buf = bytearray()
        for word in words:
            data = word.encode('utf-8', errors='replace')
            buf.extend(self._encode_length(len(data)))
            buf.extend(data)
        buf.extend(b'\x00')  # End of sentence
        self.sock.sendall(buf)

    def _read_sentence(self) -> List[str]:
        sentence = []
        while True:
            word = self._read_word()
            if word == "":
                break
            sentence.append(word)
        return sentence

    # -------------------------------------------------------------
    # CONNECTION & AUTHENTICATION
    # -------------------------------------------------------------
    # CONNECTION & AUTHENTICATION (RouterOS v6 & v7)
    # -------------------------------------------------------------
    def connect(self):
        if self.use_rest:
            # REST is stateless HTTP
            self.is_connected = True
            return

        self._read_buffer.clear()
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(self.timeout)
        try:
            raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except Exception:
            pass

        if self.use_ssl:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            try:
                ssl_ctx.set_ciphers('DEFAULT:@SECLEVEL=1')
            except Exception:
                pass
            self.sock = ssl_ctx.wrap_socket(raw_sock, server_hostname=self.host)
        else:
            self.sock = raw_sock

        try:
            self.sock.connect((self.host, self.port))
            self._login()
            self.is_connected = True
        except Exception as e:
            self.close()
            err_str = str(e)
            if "104" in err_str or "54" in err_str:
                hint = " (Connection reset by router. Check if router's IP service API has an Allowed-Address filter or if username/password is incorrect)"
            elif "111" in err_str or "61" in err_str:
                hint = f" (Connection refused on port {self.port}. Verify that the API service is enabled in MikroTik /ip service)"
            elif "timed out" in err_str.lower():
                hint = f" (Connection timed out reaching {self.host}:{self.port}. Check routing and firewall rules)"
            else:
                hint = ""
            raise MikroTikAPIError(f"Failed to connect to MikroTik at {self.host}:{self.port} - {err_str}{hint}")

    def _login(self):
        # Step 1: Send modern RouterOS v6.43+ / v7 plaintext login
        self._write_sentence(["/login", f"=name={self.username}", f"=password={self.password}"])
        response = self._read_sentence()

        if not response:
            raise MikroTikAPIError("Empty response received during login")

        reply_type = response[0]

        if reply_type == "!done":
            # Check if router challenged with a legacy hash token (RouterOS < 6.43)
            attrs = {}
            for item in response[1:]:
                if item.startswith("="):
                    parts = item[1:].split("=", 1)
                    if len(parts) == 2:
                        attrs[parts[0]] = parts[1]

            if "ret" in attrs:
                # Legacy challenge-response login (< RouterOS v6.43)
                challenge_hex = attrs["ret"]
                chal_bytes = binascii.unhexlify(challenge_hex)
                md5_hasher = hashlib.md5()
                md5_hasher.update(b'\x00' + self.password.encode('utf-8') + chal_bytes)
                response_hash = "00" + md5_hasher.hexdigest()

                self._write_sentence(["/login", f"=name={self.username}", f"=response={response_hash}"])
                legacy_res = self._read_sentence()
                if not legacy_res or legacy_res[0] != "!done":
                    raise MikroTikAPIError(f"Legacy authentication failed: {legacy_res}")
            # Logged in successfully
            return

        elif reply_type == "!trap":
            error_msg = "Unknown authentication failure"
            for item in response[1:]:
                if item.startswith("=message="):
                    error_msg = item.split("=", 2)[2]
            raise MikroTikAPIError(f"Login failed: {error_msg}")
        else:
            raise MikroTikAPIError(f"Unexpected response during login: {response}")

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        self.is_connected = False

    # -------------------------------------------------------------
    # QUERY & COMMAND EXECUTION
    # -------------------------------------------------------------
    def talk(self, words: List[str]) -> List[Dict[str, str]]:
        if self.use_rest:
            return self._talk_rest(words)

        if not self.is_connected or not self.sock:
            self.connect()

        self._write_sentence(words)
        results = []

        while True:
            sentence = self._read_sentence()
            if not sentence:
                break
            reply = sentence[0]
            if reply == "!re":
                entry = {}
                for item in sentence[1:]:
                    if item.startswith("="):
                        parts = item[1:].split("=", 1)
                        if len(parts) == 2:
                            entry[parts[0]] = parts[1]
                        elif len(parts) == 1:
                            entry[parts[0]] = ""
                results.append(entry)
            elif reply == "!done":
                break
            elif reply == "!trap":
                err = "Trap error"
                for item in sentence[1:]:
                    if item.startswith("=message="):
                        err = item.split("=", 2)[2]
                logger.debug(f"MikroTik API Trap on {self.host}: {err}")
                # Do not break here! RouterOS sends !done after !trap(s). We must consume until !done.
            elif reply == "!fatal":
                err = "Fatal error"
                for item in sentence[1:]:
                    if item.startswith("=message="):
                        err = item.split("=", 2)[2]
                logger.error(f"MikroTik API Fatal on {self.host}: {err}")
                self.close()
                raise MikroTikAPIError(f"Fatal error from MikroTik API: {err}")

        return results

    def _talk_rest(self, words: List[str]) -> List[Dict[str, str]]:
        """Universal handler for RouterOS v7 REST API"""
        if not words:
            return []
        path = words[0].strip('/')
        if path.endswith('/print'):
            path = path[:-6]
        
        protocol = "https" if self.use_ssl or self.port in [443, 8729] else "http"
        port = self.port if self.port not in [8728, 8729] else (443 if self.use_ssl else 80)
        url = f"{protocol}://{self.host}:{port}/rest/{path}"
        
        params = {}
        for w in words[1:]:
            if w.startswith("=.proplist="):
                params[".proplist"] = w.split("=", 2)[2]
            elif w.startswith("?"):
                parts = w[1:].split("=", 1)
                if len(parts) == 2:
                    params[parts[0]] = parts[1]
                elif len(parts) == 1:
                    params[parts[0]] = ""
            elif w.startswith("="):
                parts = w[1:].split("=", 1)
                if len(parts) == 2:
                    params[parts[0]] = parts[1]

        try:
            with httpx.Client(verify=False, timeout=self.timeout) as client:
                res = client.get(url, params=params, auth=(self.username, self.password))
                if res.status_code == 200:
                    data = res.json()
                    if isinstance(data, list):
                        return [{str(k): str(v) for k, v in item.items()} for item in data]
                    elif isinstance(data, dict):
                        return [{str(k): str(v) for k, v in data.items()}]
                    return []
                elif res.status_code == 404:
                    # Endpoint exists but table is empty
                    return []
                elif res.status_code == 401:
                    raise MikroTikAPIError("REST API authentication failed: invalid username or password")
                else:
                    logger.warning(f"REST API error {res.status_code} for {url}: {res.text}")
                    return []
        except httpx.ConnectError as e:
            raise MikroTikAPIError(f"REST API connection failed to {self.host}:{port} - {e}")
        except Exception as e:
            raise MikroTikAPIError(f"REST API error: {e}")

    def get_resource(self, path: str, queries: Optional[List[str]] = None) -> List[Dict[str, str]]:
        words = [path]
        if queries:
            words.extend(queries)
        return self.talk(words)

    # -------------------------------------------------------------
    # DIAGNOSTIC CONNECTION TEST
    # -------------------------------------------------------------
    def test_connection(self) -> Dict[str, Any]:
        start_time = time.time()
        # Check if router is a simulated demo router
        if self.password in ["simulated_password", "demo_password", "demo"]:
            latency_ms = round(random.uniform(1.1, 3.4), 2)
            board_model = "CCR2004-1G-12S+2XS"
            if "1072" in self.host or "metro" in self.host.lower() or "14" in self.host:
                board_model = "CCR1072-1G-8S+"
            elif "4011" in self.host or "mall" in self.host.lower() or "20" in self.host:
                board_model = "RB4011iGS+5HacQ2HnD"
            elif "1036" in self.host or "tower" in self.host.lower() or "30" in self.host:
                board_model = "CCR1036-8G-2S+"
            elif "hex" in self.host.lower() or "40" in self.host:
                board_model = "RB750Gr3"

            return {
                "online": True,
                "latency_ms": latency_ms,
                "routeros_version": "7.14.3",
                "board_name": board_model,
                "cpu_load": random.randint(12, 34),
                "uptime": f"{random.randint(10, 80)}d {random.randint(1, 23)}h {random.randint(1, 59)}m",
                "total_clients": 450,
                "pppoe_count": 250,
                "hotspot_count": 120,
                "dhcp_count": 60,
                "queue_count": 20,
                "error_message": None
            }

        try:
            self.connect()
            latency_ms = round((time.time() - start_time) * 1000, 2)

            # Gather system resource
            res_list = self.get_resource("/system/resource/print")
            sys_info = res_list[0] if res_list else {}

            # Gather routerboard info if available
            rb_list = self.get_resource("/system/routerboard/print")
            rb_info = rb_list[0] if rb_list else {}

            # Gather active counts with high-speed .proplist (sub-second response on large subscriber routers)
            pppoe_active = len(self.get_resource("/ppp/active/print", ["=.proplist=.id"]))
            hotspot_active = len(self.get_resource("/ip/hotspot/active/print", ["=.proplist=.id"]))
            dhcp_leases = len(self.get_resource("/ip/dhcp-server/lease/print", ["=.proplist=.id"]))
            queues = len(self.get_resource("/queue/simple/print", ["=.proplist=.id"]))

            self.close()

            return {
                "online": True,
                "latency_ms": latency_ms,
                "routeros_version": sys_info.get("version", "Unknown"),
                "board_name": rb_info.get("model", sys_info.get("board-name", "RouterOS Device")),
                "cpu_load": int(sys_info.get("cpu-load", 0)) if str(sys_info.get("cpu-load", "")).isdigit() else 0,
                "uptime": sys_info.get("uptime", "Unknown"),
                "total_clients": pppoe_active + hotspot_active + dhcp_leases + queues,
                "pppoe_count": pppoe_active,
                "hotspot_count": hotspot_active,
                "dhcp_count": dhcp_leases,
                "queue_count": queues,
                "error_message": None
            }
        except Exception as e:
            self.close()
            return {
                "online": False,
                "latency_ms": round((time.time() - start_time) * 1000, 2),
                "routeros_version": None,
                "board_name": None,
                "cpu_load": None,
                "uptime": None,
                "total_clients": 0,
                "pppoe_count": 0,
                "hotspot_count": 0,
                "dhcp_count": 0,
                "queue_count": 0,
                "error_message": str(e)
            }
