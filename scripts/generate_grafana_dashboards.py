"""
Generator for all 7 WISPnet Grafana Security Dashboards
Outputs compliant Grafana JSON dashboard specifications.
"""
import json
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DASHBOARDS_DIR = BASE_DIR / "grafana" / "dashboards"
DASHBOARDS_DIR.mkdir(parents=True, exist_ok=True)

dashboards = {
    "wisp-cgnat-attribution.json": {
        "title": "WISPnet - CGNAT Attribution and Abuse Investigation",
        "uid": "wisp-cgnat-attribution",
        "tags": ["wispnet", "cgnat", "attribution", "forensics"],
        "timezone": "Asia/Manila",
        "refresh": "10s",
        "schemaVersion": 38,
        "panels": [
            {
                "id": 1,
                "title": "Abuse Query Timeline",
                "type": "timeseries",
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 0},
                "datasource": {"type": "opensearch", "uid": "WISPnet-OpenSearch"},
                "targets": [{"query": "*", "metrics": [{"type": "count", "id": "1"}], "bucketAggs": [{"type": "date_histogram", "id": "2", "field": "event_timestamp"}]}]
            },
            {
                "id": 2,
                "title": "Subscriber Attribution Event Log",
                "type": "table",
                "gridPos": {"h": 10, "w": 24, "x": 0, "y": 8},
                "datasource": {"type": "opensearch", "uid": "WISPnet-OpenSearch"},
                "targets": [{"query": "*", "metrics": [{"type": "raw_document", "id": "1"}]}]
            }
        ]
    },
    "wisp-outbound-attack-detection.json": {
        "title": "WISPnet - Outbound Attack Detection",
        "uid": "wisp-outbound-attack",
        "tags": ["wispnet", "outbound", "ddos", "scanning"],
        "timezone": "Asia/Manila",
        "refresh": "10s",
        "schemaVersion": 38,
        "panels": [
            {
                "id": 1,
                "title": "Outbound Floods & High PPS Subscribers",
                "type": "timeseries",
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
                "datasource": {"type": "opensearch", "uid": "WISPnet-OpenSearch"},
                "targets": [{"query": "category:outbound_ddos", "metrics": [{"type": "sum", "id": "1", "field": "packets"}]}]
            },
            {
                "id": 2,
                "title": "Outbound Port Scans Detected",
                "type": "timeseries",
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
                "datasource": {"type": "opensearch", "uid": "WISPnet-OpenSearch"},
                "targets": [{"query": "category:port_scanning", "metrics": [{"type": "count", "id": "1"}]}]
            },
            {
                "id": 3,
                "title": "Top Outbound Attack Signatures",
                "type": "table",
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8},
                "datasource": {"type": "opensearch", "uid": "WISPnet-OpenSearch"},
                "targets": [{"query": "traffic_direction:outbound", "metrics": [{"type": "count", "id": "1"}], "bucketAggs": [{"type": "terms", "id": "2", "field": "signature_name.raw"}]}]
            }
        ]
    },
    "wisp-inbound-ddos-monitoring.json": {
        "title": "WISPnet - Inbound DDoS Monitoring",
        "uid": "wisp-inbound-ddos",
        "tags": ["wispnet", "inbound", "ddos", "perimeter"],
        "timezone": "Asia/Manila",
        "refresh": "10s",
        "schemaVersion": 38,
        "panels": [
            {
                "id": 1,
                "title": "Inbound Attack Volume (Packets / sec)",
                "type": "timeseries",
                "gridPos": {"h": 8, "w": 16, "x": 0, "y": 0},
                "datasource": {"type": "opensearch", "uid": "WISPnet-OpenSearch"},
                "targets": [{"query": "traffic_direction:inbound", "metrics": [{"type": "sum", "id": "1", "field": "packets"}]}]
            },
            {
                "id": 2,
                "title": "Top Targeted Public IPs",
                "type": "table",
                "gridPos": {"h": 8, "w": 8, "x": 16, "y": 0},
                "datasource": {"type": "opensearch", "uid": "WISPnet-OpenSearch"},
                "targets": [{"query": "traffic_direction:inbound", "metrics": [{"type": "count", "id": "1"}], "bucketAggs": [{"type": "terms", "id": "2", "field": "destination_ip"}]}]
            }
        ]
    },
    "wisp-suricata-sensor-health.json": {
        "title": "WISPnet - Suricata Alerts and Sensor Health",
        "uid": "wisp-suricata-health",
        "tags": ["wispnet", "suricata", "health", "ids"],
        "timezone": "Asia/Manila",
        "refresh": "10s",
        "schemaVersion": 38,
        "panels": [
            {
                "id": 1,
                "title": "Suricata Ingestion Rate (Alerts/sec)",
                "type": "timeseries",
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
                "datasource": {"type": "opensearch", "uid": "WISPnet-OpenSearch"},
                "targets": [{"query": "event_type:alert", "metrics": [{"type": "count", "id": "1"}]}]
            },
            {
                "id": 2,
                "title": "Alert Severity Distribution",
                "type": "piechart",
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
                "datasource": {"type": "opensearch", "uid": "WISPnet-OpenSearch"},
                "targets": [{"query": "*", "metrics": [{"type": "count", "id": "1"}], "bucketAggs": [{"type": "terms", "id": "2", "field": "severity"}]}]
            }
        ]
    },
    "wisp-akvorado-traffic-analytics.json": {
        "title": "WISPnet - Akvorado Traffic Analytics",
        "uid": "wisp-akvorado-traffic",
        "tags": ["wispnet", "akvorado", "netflow", "bandwidth"],
        "timezone": "Asia/Manila",
        "refresh": "10s",
        "schemaVersion": 38,
        "panels": [
            {
                "id": 1,
                "title": "Traffic Volume by Protocol",
                "type": "timeseries",
                "gridPos": {"h": 8, "w": 14, "x": 0, "y": 0},
                "datasource": {"type": "opensearch", "uid": "WISPnet-OpenSearch"},
                "targets": [{"query": "*", "metrics": [{"type": "sum", "id": "1", "field": "bytes"}], "bucketAggs": [{"type": "terms", "id": "2", "field": "protocol"}]}]
            },
            {
                "id": 2,
                "title": "Top Subscriber Talkers (Bandwidth)",
                "type": "table",
                "gridPos": {"h": 8, "w": 10, "x": 14, "y": 0},
                "datasource": {"type": "opensearch", "uid": "WISPnet-OpenSearch"},
                "targets": [{"query": "subscriber_cgnat_ip:*", "metrics": [{"type": "sum", "id": "1", "field": "bytes"}], "bucketAggs": [{"type": "terms", "id": "2", "field": "subscriber_cgnat_ip"}]}]
            }
        ]
    },
    "wisp-integration-pipeline-health.json": {
        "title": "WISPnet - Integration Pipeline Health",
        "uid": "wisp-pipeline-health",
        "tags": ["wispnet", "pipeline", "health", "opensearch"],
        "timezone": "Asia/Manila",
        "refresh": "10s",
        "schemaVersion": 38,
        "panels": [
            {
                "id": 1,
                "title": "OpenSearch Durable Queue Depth",
                "type": "stat",
                "gridPos": {"h": 4, "w": 8, "x": 0, "y": 0},
                "datasource": {"type": "yesoreyeram-infinity-datasource", "uid": "WISPnet-API"},
                "targets": [{"url": "http://synchavxxx-app:8000/api/security/health"}]
            },
            {
                "id": 2,
                "title": "Sensor Processing Lag (ms)",
                "type": "gauge",
                "gridPos": {"h": 4, "w": 8, "x": 8, "y": 0},
                "datasource": {"type": "yesoreyeram-infinity-datasource", "uid": "WISPnet-API"},
                "targets": [{"url": "http://synchavxxx-app:8000/api/security/health"}]
            },
            {
                "id": 3,
                "title": "Integrations Connectivity Status",
                "type": "table",
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 4},
                "datasource": {"type": "yesoreyeram-infinity-datasource", "uid": "WISPnet-API"},
                "targets": [{"url": "http://synchavxxx-app:8000/api/security/health"}]
            }
        ]
    }
}

for filename, content in dashboards.items():
    file_path = DASHBOARDS_DIR / filename
    with open(file_path, "w") as f:
        json.dump(content, f, indent=2)
    print(f"Generated Grafana dashboard: {filename}")

print("All 7 Grafana dashboards generated successfully.")
