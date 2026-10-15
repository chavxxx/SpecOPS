# WISPnet Security Platform Operational Runbooks
## Standard Operating Procedures for Network Engineers & Security Analysts

---

## RUNBOOK 1: Handling External Abuse Reports (Attribution & Investigation)

### Scenario
An external CERT, upstream ISP, or hosting provider sends an abuse notification stating:
> *"At 2026-10-15 08:30:15 UTC, your public IP 157.119.69.129 using source port 4250 launched a high-rate SSH brute-force attack against target 198.51.100.44:22."*

### Step-by-Step Operator Procedure

#### Step 1: Open the CGNAT Attribution Console
1. Navigate to the SyncHavxxx web console: `https://security.wispnet.internal` (or `http://localhost:8000`).
2. Log in with your network engineer or security analyst credentials.
3. Select the **CGNAT Attribution** tab in the main navigation.

#### Step 2: Query the Public 5-Tuple Coordinates
1. In the **Reverse Public Lookup** form:
   - **Public IP:** Enter `157.119.69.129`
   - **Source Port:** Enter `4250`
   - **Timestamp (UTC):** Enter `2026-10-15 08:30:15` (or leave blank for latest active mapping)
2. Click **Reverse Lookup Subscriber**.

#### Step 3: Interpret Attribution Results
The Attribution Engine will return one of the following states:

- **State 1: VERIFIED (Green Badge)**
  - **Subscriber CGNAT IP:** `100.91.0.3` (allocated port block `4096–6143`).
  - **PPPoE Username:** `cust_00003@wispnet`
  - **Confidence:** 100% verified against both deterministic mapping rules and active PPPoE session history.
- **State 2: HIGH CONFIDENCE (Blue Badge)**
  - **Subscriber CGNAT IP:** `100.91.0.3` is verified by the port block, but PPPoE session was not recorded at that exact second.
- **State 3: PARTIAL (Amber Badge)**
  - *Trigger:* The abuse report provided the public IP `157.119.69.129` but **omitted the source port** (or source port is 0).
  - *Action:* The platform displays all 31 subscribers sharing that public IP. **Do NOT guess a subscriber**. Request full 5-tuple logs from the reporting party before proceeding.

#### Step 4: Perform Manual Customer Lookup in Billing System
> **STRICT SECURITY RULE:** SyncHavxxx has no connection to billing. Do not attempt to query billing from this platform.
1. Click the **Copy** button next to the reported **PPPoE Username** (or **CGNAT IP**).
2. Open your billing / customer management CRM (e.g. Splynx, PowerCode, Sonar, Freeside).
3. Paste the username into the billing search box to locate the customer's contact details.

#### Step 5: Incident Resolution & Logging
1. If an incident was automatically created under the **Incidents** tab, locate Incident `#INC-...`.
2. Click **View / Manage Incident**.
3. Under **Resolution Notes**, enter the mandatory actions taken (e.g., *"Contacted subscriber cust_00003@wispnet via phone. Subscriber identified infected IoT DVR; quarantined device from local LAN. Outbound scans ceased."*).
4. Update status to **Resolved**. The note is permanently stored with your user audit trail.

---

## RUNBOOK 2: Production Deployment & Service Initialization

### Option A: Docker Compose Deployment (Recommended)

1. **Clone repository and configure environment:**
   ```bash
   cd /opt/wispnet/synchavxxx-integration
   cp .env.example .env
   # Edit .env and enter CCR2116 router credentials and secrets
   nano .env
   ```

2. **Launch the security platform stack:**
   ```bash
   docker compose -f docker-compose.security.yml up -d
   ```

3. **Verify running containers:**
   ```bash
   docker compose -f docker-compose.security.yml ps
   ```
   Expected running services:
   - `synchavxxx-security` (Port 8000)
   - `wisp-opensearch` (Port 9200)
   - `wisp-opensearch-dashboards` (Port 5601)
   - `wisp-grafana` (Port 3000)

4. **Verify Application Health:**
   ```bash
   curl -f http://localhost:8000/api/security/health
   ```

---

### Option B: Bare Metal Ubuntu 22.04 / 24.04 Deployment

1. **Install system dependencies:**
   ```bash
   sudo apt-get update
   sudo apt-get install -y python3 python3-venv python3-pip sqlite3 curl
   ```

2. **Initialize Python Virtual Environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. **Install & Start Systemd Service:**
   ```bash
   sudo python3 run.py --install-service
   sudo systemctl daemon-reload
   sudo systemctl enable --now synchavxxx.service
   sudo systemctl status synchavxxx.service
   ```

---

## RUNBOOK 3: Backup and Disaster Recovery

### Automated Backup Execution
The platform includes an automated, atomic backup script that backs up the SQLite database in WAL mode without table locks, exports CGNAT mapping CSVs, dumps detection rules, and generates SHA-256 integrity checksums:

```bash
# Execute backup
/opt/wispnet/synchavxxx-integration/scripts/backup_security.sh
```

### Scheduling Daily Backups via Crontab
Add the following line to `/etc/crontab` or `crontab -e`:
```cron
# Run daily security platform backup at 03:00 UTC
0 3 * * * root /opt/wispnet/synchavxxx-integration/scripts/backup_security.sh >> /var/log/wisp_backup.log 2>&1
```

### Disaster Recovery / Database Restoration
In the event of hardware failure or database corruption:

1. **Stop the running service:**
   ```bash
   sudo systemctl stop synchavxxx.service
   # or: docker compose -f docker-compose.security.yml stop synchavxxx-security
   ```

2. **Extract the desired backup archive:**
   ```bash
   cd /opt/wispnet/synchavxxx-integration/backups/security
   # Verify archive integrity
   shasum -a 256 -c wisp_security_backup_20261015_124833.tar.gz.sha256
   
   # Extract to temporary directory
   mkdir /tmp/restore_stage
   tar -xzf wisp_security_backup_20261015_124833.tar.gz -C /tmp/restore_stage
   ```

3. **Replace active SQLite database:**
   ```bash
   cp /tmp/restore_stage/synchavxxx.db /opt/wispnet/synchavxxx-integration/synchavxxx.db
   rm -rf /tmp/restore_stage
   ```

4. **Restart the service & verify:**
   ```bash
   sudo systemctl start synchavxxx.service
   curl -f http://localhost:8000/api/security/health
   ```

---

## RUNBOOK 4: OpenSearch Failover & Durable Buffer Verification

### Understanding the Zero-Event-Loss Buffer
When OpenSearch is unreachable (network maintenance, JVM garbage collection pause, or node reboot), the platform buffers all events in SQLite (`opensearch_queue`).

### Simulating & Recovering from an OpenSearch Outage
1. **Simulate Outage:** Stop the OpenSearch container or block port 9200.
2. **Observe System Behavior:**
   - Security events continue to be ingested and evaluated locally without errors.
   - Local database transactions complete normally.
   - Navigate to **Sensor & Integration Health** in the web console:
     - Integration `opensearch` will transition from `healthy` to `warning` or `critical`.
     - `Queue Depth` counter will increment.
     - `Processing Lag` will track duration since the last successful bulk delivery.
3. **Restore OpenSearch:** Restart the OpenSearch service.
4. **Automatic Queue Drainage:**
   - The background worker (`security_worker.py`) detects OpenSearch recovery on the next polling cycle.
   - Buffered batches are flushed via `_bulk` indexing.
   - Once queue depth reaches 0, integration health automatically returns to `healthy`.

---

## RUNBOOK 5: Operationalizing IP Reputation & Blacklist Intelligence

### Scenario
An external customer reports that their emails are bouncing due to their public IP being listed on Spamhaus or Barracuda, or an automated alert notifies the SOC of a worsening IP reputation score for a public CGNAT pool IP.

### Step-by-Step Operator Procedure

#### Step 1: Open IP Intelligence Console
1. Log in to the SyncHavxxx platform with analyst or admin privileges.
2. Click **IP Intelligence** in the main navigation.
3. Review the **Overview KPI Dashboard** for listed IPs, active abuse reports, and deteriorating trends.

#### Step 2: Perform Single IP Deep Lookup
1. Switch to the **Single IP Lookup** tab.
2. Enter the target public IP (e.g., `157.119.69.129`).
3. Select scan depth:
   - `Standard`: Fast parallel check across all enabled DNSBLs and cached intelligence.
   - `Deep`: Direct live API queries bypassing cache, evaluating FCrDNS and historical observations.
4. Optional: If the abuse report or bounce message included an outbound source port (e.g. `12345`), enter it in the **Event Port** field along with the event timestamp.
5. Click **Check IP Reputation**.

#### Step 3: Interpret Explainable Score & Provider Results
- **Overall Status:** Review badge (`CLEAN`, `LISTED`, `SUSPICIOUS`, `HIGH_RISK`, `UNKNOWN`, `INCOMPLETE`).
- **Risk Score (0–100):** View the factor breakdown explaining why points were added (e.g. `+40 Spamhaus XBL Botnet/C2 detected`, `+25 AbuseIPDB confidence score > 50%`).
- **Provider Breakdown Cards:**
  - `Spamhaus ZEN`: Inspect return code (127.0.0.2 SBL Spam, 127.0.0.4 XBL Botnet, 127.0.0.10 PBL Policy).
  - `AbuseIPDB`: Inspect total abuse reports, distinct reporters, and last reported timestamp.
  - `VirusTotal`: Inspect malicious security vendor engine detections.
  - `Reverse DNS`: Confirm if FCrDNS passes or if generic dynamic hostnames are assigned.

#### Step 4: Isolate Offending Subscriber via CGNAT Correlation
1. Scroll down to the **CGNAT & Subscriber Attribution** section.
2. If source port was supplied:
   - Identify the exact internal CGNAT IP (`100.91.x.x`) and assigned port block (`port_start - port_end`).
   - If a PPPoE session was active at that timestamp, the PPPoE username is displayed.
   - Click the **Copy** button next to the username/IP to search your billing/CRM system.
3. If source port was NOT supplied:
   - The platform strictly displays `PARTIAL` attribution and enumerates the candidate subscribers sharing that public IP. Contact the abuse reporter or check Suricata alerts around that timestamp to find the exact port.

#### Step 5: Correlate Suricata Alerts & Flow Volume
1. Review the **Related Suricata Security Alerts** table to see if the IP has triggered recent internal alerts (e.g. `ET MALWARE Outbound C2`, `ET SCAN Potential SSH Scan`).
2. Review the **Akvorado Flow Metrics** summary for top protocols and destination ports.

#### Step 6: Log Investigation or Open Delisting Ticket
1. In the IP Intelligence header, click **Create Investigation**.
2. Note findings, remediation steps taken with the subscriber, and delisting request confirmation numbers.
3. Close the investigation once delisting is confirmed.

---

## RUNBOOK 6: Threat Intelligence Provider Configuration & Credential Provisioning

### Configuring API Keys & Resolvers
To enable live checks for authenticated threat intelligence providers:

1. **AbuseIPDB v2:**
   - Sign up for a free or commercial API key at `https://www.abuseipdb.com/register`.
   - In SyncHavxxx, navigate to **IP Intelligence > Providers**.
   - Click **Edit Provider Config** for **AbuseIPDB**.
   - Enter your API Key in the `API Key` field and click **Save Configuration**.
   - The provider state immediately transitions from `awaiting_credentials` to `enabled`.

2. **VirusTotal v3:**
   - Obtain an API key from `https://www.virustotal.com/gui/user/apikey`.
   - Under **Providers**, edit **VirusTotal**, enter the API Key, and save.
   - Note: The platform enforces VirusTotal's public rate limit (4 requests per minute) with automatic queue throttling.

3. **Spamhaus Direct Recursive Resolver:**
   - Spamhaus blocks queries sent through public open resolvers (`8.8.8.8`, `1.1.1.1`), returning `127.255.255.254`.
   - For production ISP deployments, configure local BIND or Unbound recursive resolvers in `.env`:
     ```env
     DNS_RESOLVER_IP=127.0.0.1
     DNS_RESOLVER_PORT=53
     ```
   - Alternatively, if your ISP has a Spamhaus Data Query Service (DQS) key, set the zone in provider configuration:
     ```env
     SPAMHAUS_DQS_KEY=your_dqs_key_here
     ```
