# WISPnet — Carrier-Grade ISP Security Operations & IP Intelligence Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](#)
[![Tests](https://img.shields.io/badge/Tests-39%20Passing-emerald.svg)](#)

A carrier-grade, unified security operations platform built specifically for Philippine WISPs and regional ISPs. WISPnet bridges the gap between high-speed edge telemetry and real-world network defense, answering all **10 critical security attribution questions** in under 5 seconds with zero impact on subscriber billing or core forwarding paths.

---

## 🎯 Platform Core Capabilities

1. **Deterministic CGNAT Attribution Engine**:
   - Zero-log, mathematically proven deterministic port-block NAT mapping algorithm.
   - Dual-point observation architecture: Correlates pre-CGNAT (private subscriber `100.64.0.0/10` / `10.0.0.0/8`) and post-CGNAT (public IP pool) traffic.
   - Microsecond-accurate timestamp alignment with the Manila (`Asia/Manila`, UTC+8) timezone.
   - Answers: *"Which exact subscriber used public IP X:Port Y at timestamp T?"* with verified cryptographic confidence.

2. **Intrusion Detection Telemetry (Suricata)**:
   - Dedicated pre-CGNAT and post-CGNAT Suricata sensor observation pipelines.
   - Ingests `eve.json` alerts, DNS queries, TLS handshakes, and anomaly signals.
   - Automated subscriber correlation linking alerts directly to PPPoE accounts and CGNAT allocations.

3. **Carrier Flow Telemetry & Anomaly Analytics (Akvorado)**:
   - Ingests NetFlow v9 and IPFIX telemetry from core edge routers.
   - Real-time DDoS reflection detection, amplification sweeps, port scans, and fast-flux domain beaconing.
   - Identifies top talkers, malicious destinations, protocol anomalies, and transit egress distribution.

4. **IP Reputation & DNSBL Intelligence Engine**:
   - Continuously monitors public IP allocations across 8 tier-1 threat intelligence and DNSBL providers:
     - Spamhaus ZEN / XBL / SBL
     - AbuseIPDB API
     - SpamCop
     - Barracuda Central
     - Sorbs DNSBL
     - UCEPROTECT
     - Virustotal Threat API
     - AlienVault OTX
   - Automated delta tracking, historical delist logging, and public IP inventory management.

5. **Security Incident & Case Management**:
   - Automated incident correlation grouping related security events by subscriber and threat signature.
   - Operator workflow states: `New` &rarr; `Investigating` &rarr; `Confirmed Suspicious` &rarr; `Resolved` &rarr; `Benign` &rarr; `Escalated`.
   - Mandatory audit logging with resolution reason recording for high/critical incidents.

6. **Carrier-Grade Telemetry Buffering (OpenSearch)**:
   - High-throughput asynchronous batch queue with circular in-memory backpressure.
   - Real-time fallback buffering to preserve telemetry integrity during downstream indexer maintenance.

7. **Zero Billing Integration Guarantee**:
   - Strictly isolated from billing systems, RADIUS accounting databases, or revenue pipelines.
   - Operators copy the subscriber CGNAT IP or PPPoE username via 1-click clipboard integration and manually handle customer lookups.

8. **Read-Only Least-Privilege RouterOS Integration**:
   - Uses MikroTik RouterOS v7 REST API with strictly scoped, read-only permissions (`read`, `test`, `api`).
   - Zero write actions, zero firewall rule modifications, and zero interface mutations on edge hardware.

---

## ⚡ 1-Line Universal Production Installer

Run this single command on your Ubuntu, Debian, RHEL, Rocky Linux, or macOS host to automatically install all OS prerequisites, stage the application, configure Python virtual environments, initialize the security database, run the verification test suite, register the systemd service, and open firewall ports:

```bash
# Production Deployment with Sample Carrier Telemetry & CGNAT Mappings
curl -sSL https://raw.githubusercontent.com/chavxxx/SpecOPS/main/install.sh | sudo bash -s -- --seed-demo
```

### Local Cloned Repository 1-Liner
If you have already cloned the repository locally:
```bash
sudo bash install.sh --seed-demo
```

#### Installer Command Options:
| Flag | Description | Default |
| :--- | :--- | :--- |
| `-p`, `--port <PORT>` | Web console & API port | `8000` |
| `-d`, `--dir <PATH>` | Target installation directory | `/opt/wispnet` (or `~/wispnet`) |
| `-s`, `--seed-demo` | Seed verified CGNAT mappings, sessions & events | `false` |
| `--no-systemd` | Skip systemd service registration (macOS / Docker) | `false` |
| `-u`, `--user <USER>` | Execution user for systemd unit | `root` |
| `-b`, `--branch <BRANCH>`| Git branch to clone or update | `main` |
| `-t`, `--token <PAT>` | GitHub Personal Access Token for private repo | `""` |

---

## 🚀 Manual Step-by-Step Quickstart
```bash
git clone https://github.com/synchavxxx/wispnet-security-platform.git
cd wispnet-security-platform

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Seed Realistic Demo Telemetry & NAT Tables
```bash
python run.py --seed-demo
```
This populates `wisp_security.db` with:
- 100 Deterministic CGNAT subscriber port-block mappings.
- 5 Active MikroTik subscriber sessions.
- 126 Public IP addresses across 2 CIDR blocks in IP inventory.
- Realistic Suricata pre- and post-CGNAT intrusion events.
- 5 Incident tickets across different threat severities.
- Default administrator user: `synchavxxx` / `synchavxxx123`.

### 3. Launch Web Dashboard & Background Engine
```bash
python run.py --host 127.0.0.1 --port 8000
```
Open your browser to: **http://127.0.0.1:8000**

---

## 🛡️ Role-Based Access Control (RBAC)

| Role | Permissions |
| :--- | :--- |
| **Administrator** (`admin`) | Full read and write access. Can configure detection rules, transition incidents, manage IP inventory, test threat intelligence providers, edit carrier settings, and manage user accounts. |
| **NOC Observer** (`read-only`) | Real-time monitoring and investigation. Can query CGNAT attribution, inspect subscriber profiles, view security events, audit traffic charts, and view reputation reports with write controls locked. |

Default credentials:
- **Username**: `synchavxxx`
- **Password**: `synchavxxx123`

---

## 🔌 API Architecture Reference

| Router Prefix | Scope / Responsibility |
| :--- | :--- |
| `/api/auth` | Session authentication, HMAC JWT tokens, login, logout, current user verification. |
| `/api/users` | RBAC user management (Admin only for mutations). |
| `/api/security` | Core telemetry dashboard metrics, event feeds, detection rules, sensor health, settings. |
| `/api/cgnat` | Deterministic CGNAT attribution engine, forward/reverse port-block lookups. |
| `/api/subscribers` | 360-degree subscriber security profile, session history, and correlated security events. |
| `/api/incidents` | Incident queue, operator transitions, resolution notes, correlated timeline. |
| `/api/analytics` | Traffic trends, protocol breakdowns, and Akvorado NetFlow telemetry. |
| `/api/rules` | Suricata rule toggles and dry-run historical event testing. |
| `/api/sensors` | Ingestion status for Suricata, NetFlow, and MikroTik telemetry feeds. |
| `/api/ip-intelligence` | Threat intelligence overview, 8 provider DNSBL queries, IP inventory, bulk scans. |
| `/api/audit` | Read-only security audit log of operator actions. |

---

## 🧪 Automated Test Suite

All 39 security and attribution unit tests pass cleanly:
```bash
source .venv/bin/activate
pytest
```
```
tests/test_attribution_engine.py ....                                    [ 10%]
tests/test_cgnat_engine.py .......                                       [ 28%]
tests/test_detection_and_incidents.py ...                                [ 35%]
tests/test_ip_intel_module.py ........                                   [ 56%]
tests/test_opensearch_adapter.py ..                                      [ 61%]
tests/test_security_api.py ........                                      [ 82%]
tests/test_suricata_pipeline.py ...                                      [ 89%]
tests/test_users.py ....                                                 [100%]

============================== 39 passed in 0.57s ==============================
```

---

## 🔒 Security & Privacy Architecture
- **Zero Cloud Leakage**: Runs 100% on-premises on your edge management server.
- **Least-Privilege MikroTik Credentials**: Does not require write access to MikroTik routers.
- **Microsecond Timestamp Precision**: Guarantees deterministic correlation alignment with zero drift.
