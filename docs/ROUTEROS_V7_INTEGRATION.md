# MikroTik RouterOS v7 CGNAT & Integration Architecture Guide
## Implementation Specification for CCR2116 Core Router and PPPoE Access Concentrator

---

### 1. RouterOS v7 Compatibility & Architecture Overview

This platform is purpose-built for **MikroTik RouterOS v7** running on CCR2116-12G-4S+ hardware.

Key architectural considerations for RouterOS v7:
1. **Linux 5.6+ Kernel & Routing Engine:** RouterOS v7 utilizes the modern Linux routing architecture and netfilter subsystem. Legacy RouterOS v6 syntax (e.g. `action=same` in NAT rules) is deprecated or behaves differently; explicit `action=src-nat` with discrete `to-addresses` and `to-ports` ranges is the standard for deterministic port allocation.
2. **Read-Only API Access:** All automated interactions from the SyncHavxxx platform are strictly read-only. No write operations, password changes, or firewall modifications are performed over the API.
3. **Multi-Router Topology:** The CCR2116 Core Router handles routing and CGNAT translation; a separate CCR2116 PPPoE Access Concentrator (AC) terminates subscriber PPPoE sessions. The platform connects to each independently with dedicated credential profiles.

---

### 2. Dedicated Read-Only Security User Setup

Run the following commands on **both** the CCR2116 Core Router and the CCR2116 PPPoE Access Concentrator via terminal or SSH to create a restricted, read-only API user:

```routeros
# 1. Create a dedicated read-only policy group
/user group
add name=security-ro \
    policy=read,api,test,!local,!telnet,!ssh,!ftp,!reboot,!write,!policy,!winbox,!password,!web,!sniff,!sensitive,!romon,!rest-api

# 2. Add the service account user (specify a strong, random password)
/user
add name=wisp-security \
    group=security-ro \
    password="<GENERATE_STRONG_RANDOM_PASSWORD_HERE>" \
    comment="SyncHavxxx Security Platform Read-Only Collector"

# 3. Restrict API service to authorized monitoring subnets (optional but recommended)
/ip service
set api address=10.0.0.0/24,192.168.100.0/24 disabled=no port=8728
set api-ssl address=10.0.0.0/24,192.168.100.0/24 disabled=no port=8729
```

---

### 3. Authoritative Deterministic CGNAT Firewall Rules (CCR2116 Core)

To implement fixed 2,048-port blocks per subscriber on RouterOS v7:
- **Public IP Pool:** `157.119.69.129` – `157.119.69.254` (Usable addresses in `157.119.69.128/25`).
- **Subscriber Pool:** `100.91.0.2` – `100.91.3.255` (Usable addresses in `100.91.0.0/22`).
- **Port Block Size:** 2,048 ports per subscriber.
- **Port Ranges:** Block 1 = `2048-4095`, Block 2 = `4096-6143`, ..., Block 31 = `63488-65535`.
- **Allocation Ratio:** 1:31 (31 subscribers per public IP).

#### RouterOS v7 Rule Template
```routeros
/ip firewall nat
# Block 1 for first subscriber on 157.119.69.129
add chain=srcnat action=src-nat to-addresses=157.119.69.129 to-ports=2048-4095 \
    protocol=tcp src-address=100.91.0.2 out-interface-list=WAN \
    comment="CGNAT-DET-157.119.69.129-2048-4095-100.91.0.2-tcp"
add chain=srcnat action=src-nat to-addresses=157.119.69.129 to-ports=2048-4095 \
    protocol=udp src-address=100.91.0.2 out-interface-list=WAN \
    comment="CGNAT-DET-157.119.69.129-2048-4095-100.91.0.2-udp"

# Block 2 for second subscriber on 157.119.69.129
add chain=srcnat action=src-nat to-addresses=157.119.69.129 to-ports=4096-6143 \
    protocol=tcp src-address=100.91.0.3 out-interface-list=WAN \
    comment="CGNAT-DET-157.119.69.129-4096-6143-100.91.0.3-tcp"
add chain=srcnat action=src-nat to-addresses=157.119.69.129 to-ports=4096-6143 \
    protocol=udp src-address=100.91.0.3 out-interface-list=WAN \
    comment="CGNAT-DET-157.119.69.129-4096-6143-100.91.0.3-udp"

# ... (Continue pattern up to Block 31: 63488-65535 for 100.91.0.32)

# Next Public IP: 157.119.69.130
add chain=srcnat action=src-nat to-addresses=157.119.69.130 to-ports=2048-4095 \
    protocol=tcp src-address=100.91.0.33 out-interface-list=WAN \
    comment="CGNAT-DET-157.119.69.130-2048-4095-100.91.0.33-tcp"
add chain=srcnat action=src-nat to-addresses=157.119.69.130 to-ports=2048-4095 \
    protocol=udp src-address=100.91.0.33 out-interface-list=WAN \
    comment="CGNAT-DET-157.119.69.130-2048-4095-100.91.0.33-udp"
```

> **Automated Export Capability:** The complete, fully validated RouterOS script for all 1,022 subscribers can be generated at any time directly from the platform web interface or via `GET /api/cgnat/export/routeros`.

---

### 4. FastTrack Firewall Bypass for CGNAT Flows

MikroTik RouterOS v7 includes IPv4 FastTrack to achieve multi-gigabit line-rate throughput. However, if FastTrack is enabled blindly across all traffic without firewall exemptions, connection tracking counters and initial NAT translations can bypass inspection filters.

To ensure **accurate connection tracking and deterministic CGNAT translation** while retaining high routing performance, add an exception for the CGNAT subnet:

```routeros
/ip firewall filter
# Place this rule BEFORE the general fasttrack rule:
add chain=forward action=accept connection-state=established,related \
    src-address=100.91.0.0/22 \
    comment="Bypass FastTrack for CGNAT subscribers to preserve NAT state"

add chain=forward action=accept connection-state=established,related \
    dst-address=100.91.0.0/22 \
    comment="Bypass FastTrack for CGNAT return traffic to preserve NAT state"

# Standard fasttrack rule follows:
add chain=forward action=fasttrack-connection connection-state=established,related \
    comment="FastTrack for non-CGNAT / public routed traffic"
```

---

### 5. IPFIX / NetFlow Traffic-Flow Export to Akvorado

Configure RouterOS v7 `traffic-flow` on the CCR2116 Core Router to export IPFIX flow records to the Akvorado flow collector:

```routeros
/ip traffic-flow
set enabled=yes \
    active-flow-timeout=1m \
    inactive-flow-timeout=15s \
    interfaces=all

/ip traffic-flow target
add dst-address=10.0.0.50 \
    port=2055 \
    version=ipfix \
    comment="Export flow records to Akvorado Collector"
```

---

### 6. Packet Mirroring / SPAN Configuration for Suricata TAPs

For hardware optical TAPs or switch SPAN ports feeding the Suricata IDS sensors:

#### A. Pre-CGNAT Observation (Interface facing PPPoE AC)
On the switch/trunk interconnecting the PPPoE AC and the Core Router:
- Mirror traffic on the subscriber-facing trunk interface (`sfp-sfpplus1`).
- Direct mirrored traffic to the dedicated Suricata Pre-NAT NIC (`sfp-sfpplus1-pre`).

#### B. Post-CGNAT Observation (Interface facing Upstream Transit)
On the Core Router or WAN switch:
- Mirror traffic on the upstream WAN interface (`sfp-sfpplus2`).
- Direct mirrored traffic to the dedicated Suricata Post-NAT NIC (`sfp-sfpplus2-post`).

On MikroTik hardware supporting switch port mirroring:
```routeros
/interface ethernet switch
set 0 mirror-source=sfp-sfpplus1 mirror-target=sfp-sfpplus3
```

---

### 7. PPPoE Session Harvesting Mechanics (CCR2116 PPPoE AC)

The platform's background harvester connects to the PPPoE Access Concentrator every 60 seconds (configurable) via read-only API and executes:

```routeros
/ppp/active/print
```

Attributes harvested and preserved into `subscriber_sessions`:
- `name`: PPPoE username (e.g., `cust_00124@wispnet`)
- `address`: Assigned CGNAT IP (e.g., `100.91.0.2`)
- `uptime`: Session duration
- `caller-id`: Subscriber CPE MAC address
- `.id`: RouterOS internal session identifier

When a subscriber disconnects, the platform marks the `ended_at` timestamp. Historical sessions are **never deleted**, allowing precise correlation of events that occurred days, weeks, or months in the past.
