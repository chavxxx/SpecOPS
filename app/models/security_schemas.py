"""
Pydantic Schemas for WISPnet CGNAT Security Monitoring, Threat Detection & Subscriber Attribution Platform
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum

class AttributionStatus(str, Enum):
    VERIFIED = "verified"
    HIGH_CONFIDENCE = "high_confidence"
    PARTIAL = "partial"
    UNRESOLVED = "unresolved"
    CONFLICT = "conflict"

class TrafficDirection(str, Enum):
    OUTBOUND = "outbound"
    INBOUND = "inbound"
    INTERNAL = "internal"
    UNKNOWN = "unknown"

class SecuritySeverity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentStatus(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONFIRMED_SUSPICIOUS = "confirmed_suspicious"
    BENIGN = "benign"
    RESOLVED = "resolved"
    ESCALATED = "escalated"

class DetectionCategory(str, Enum):
    PORT_SCANNING = "port_scanning"
    OUTBOUND_DDOS = "outbound_ddos"
    BRUTE_FORCE = "brute_force"
    BOTNET_C2 = "botnet_c2"
    DNS_ANOMALY = "dns_anomaly"
    INBOUND_DDOS = "inbound_ddos"
    CGNAT_ABUSE = "cgnat_abuse"
    CUSTOM = "custom"

# -------------------------------------------------------------
# CGNAT MAPPING SCHEMAS
# -------------------------------------------------------------

class CGNATConfig(BaseModel):
    public_pool_start: str = Field(default="157.119.69.129", description="Public pool start IPv4")
    public_pool_end: str = Field(default="157.119.69.254", description="Public pool end IPv4")
    subscriber_pool_start: str = Field(default="100.91.0.2", description="Subscriber CGNAT pool start IPv4")
    port_block_size: int = Field(default=2048, description="Number of ports allocated per subscriber")
    first_eligible_port: int = Field(default=2048, description="First port in eligible dynamic range")
    last_eligible_port: int = Field(default=65535, description="Last port in eligible dynamic range")
    protocol_scope: str = Field(default="all", description="Protocol scope: tcp, udp, or all")
    mapping_version: str = Field(default="v1.0", description="Version identifier for this mapping configuration")
    effective_from: str = Field(default="2026-01-01T00:00:00Z", description="Effective start timestamp UTC")

class CGNATMapping(BaseModel):
    mapping_id: str
    mapping_version: str = "v1.0"
    public_ip: str
    port_start: int
    port_end: int
    protocol_scope: str = "all"
    subscriber_cgnat_ip: str
    pppoe_username: Optional[str] = None
    router_id: Optional[str] = "core-router-ccr2116"
    effective_from: str
    effective_to: Optional[str] = None
    source_of_truth: str = "deterministic_algorithm"
    validation_status: str = "verified"
    created_at: Optional[str] = None

class CGNATValidationIssue(BaseModel):
    severity: str # error, warning
    code: str
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)

class CGNATValidationReport(BaseModel):
    valid: bool
    total_mappings_checked: int
    unique_public_ips: int
    unique_subscriber_ips: int
    blocks_per_public_ip: int
    issues: List[CGNATValidationIssue] = Field(default_factory=list)
    timestamp: str

# -------------------------------------------------------------
# SUBSCRIBER SESSION SCHEMAS
# -------------------------------------------------------------

class SubscriberSession(BaseModel):
    session_id: str
    pppoe_username: str
    subscriber_cgnat_ip: str
    access_concentrator: str = "pppoe-ac-ccr2116"
    router_session_id: Optional[str] = None
    started_at: str
    ended_at: Optional[str] = None
    session_source: str = "routeros_active"
    last_synchronized_at: Optional[str] = None

# -------------------------------------------------------------
# SENSOR SCHEMAS
# -------------------------------------------------------------

class Sensor(BaseModel):
    sensor_id: str
    sensor_name: str
    sensor_type: str # suricata, akvorado, routeros_mirror, tap
    observation_point: str # pre_cgnat, post_cgnat
    host: str
    interface: str
    enabled: bool = True
    last_seen: Optional[str] = None
    health_status: str = "healthy" # healthy, degraded, offline
    version: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

class SensorCreate(BaseModel):
    sensor_id: Optional[str] = None
    sensor_name: str
    sensor_type: str = "suricata" # suricata, akvorado, routeros_mirror, tap
    observation_point: str = "pre_cgnat" # pre_cgnat, post_cgnat
    host: str
    interface: str
    enabled: bool = True
    health_status: str = "healthy"
    version: Optional[str] = None

# -------------------------------------------------------------
# ATTRIBUTION LOOKUP SCHEMAS
# -------------------------------------------------------------

class AttributionLookupRequest(BaseModel):
    public_ip: str
    public_port: Optional[int] = None
    protocol: str = "tcp"
    timestamp: Optional[str] = None # ISO format or UTC
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    observation_point: Optional[str] = "post_cgnat"
    original_source_ip: Optional[str] = None

class AttributionResult(BaseModel):
    attribution_status: AttributionStatus
    subscriber_cgnat_ip: Optional[str] = None
    pppoe_username: Optional[str] = None
    session_id: Optional[str] = None
    access_concentrator: Optional[str] = None
    public_ip: str
    public_port: Optional[int] = None
    port_block_range: Optional[str] = None # e.g. "2048-4095"
    protocol: str
    event_timestamp: str
    mapping_id: Optional[str] = None
    mapping_version: Optional[str] = None
    mapping_effective_from: Optional[str] = None
    mapping_effective_to: Optional[str] = None
    observation_point: str
    attribution_method: str
    confidence_explanation: str
    supporting_evidence: Dict[str, Any] = Field(default_factory=dict)
    unresolved_fields: List[str] = Field(default_factory=list)

# -------------------------------------------------------------
# SECURITY EVENT SCHEMAS
# -------------------------------------------------------------

class SecurityEvent(BaseModel):
    event_id: str
    source_event_id: Optional[str] = None
    event_timestamp: str
    received_timestamp: str
    sensor_id: str
    observation_point: str = "post_cgnat"
    source_ip: str
    source_port: Optional[int] = None
    destination_ip: str
    destination_port: Optional[int] = None
    protocol: str = "tcp"
    traffic_direction: TrafficDirection = TrafficDirection.OUTBOUND
    event_type: str = "alert" # alert, flow, dns, http, tls, anomaly
    signature_id: Optional[int] = None
    signature_name: Optional[str] = None
    category: DetectionCategory = DetectionCategory.CUSTOM
    severity: SecuritySeverity = SecuritySeverity.MEDIUM
    packets: Optional[int] = None
    bytes: Optional[int] = None
    flow_id: Optional[str] = None
    original_event_reference: Optional[str] = None
    attribution_status: AttributionStatus = AttributionStatus.UNRESOLVED
    mapping_id: Optional[str] = None
    subscriber_cgnat_ip: Optional[str] = None
    pppoe_username: Optional[str] = None
    attribution_method: Optional[str] = None
    detection_rule_id: Optional[str] = None
    created_at: Optional[str] = None

# -------------------------------------------------------------
# INCIDENT SCHEMAS
# -------------------------------------------------------------

class Incident(BaseModel):
    incident_id: str
    title: str
    category: DetectionCategory
    severity: SecuritySeverity
    status: IncidentStatus = IncidentStatus.NEW
    first_seen: str
    last_seen: str
    affected_subscriber_ip: Optional[str] = None
    pppoe_username: Optional[str] = None
    affected_public_ip: Optional[str] = None
    evidence_summary: Dict[str, Any] = Field(default_factory=dict)
    assigned_operator: Optional[str] = None
    resolution_notes: Optional[str] = None
    event_count: int = 1
    total_bytes: int = 0
    total_packets: int = 0
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

# -------------------------------------------------------------
# DETECTION RULE SCHEMAS
# -------------------------------------------------------------

class DetectionRule(BaseModel):
    rule_id: str
    name: str
    category: DetectionCategory
    enabled: bool = True
    threshold_configuration: Dict[str, Any] = Field(default_factory=dict)
    time_window_seconds: int = 60
    severity: SecuritySeverity = SecuritySeverity.MEDIUM
    exclusions: List[str] = Field(default_factory=list) # IPs or CIDRs to exclude
    created_by: str = "system"
    updated_by: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

# -------------------------------------------------------------
# AUDIT LOG SCHEMAS
# -------------------------------------------------------------

class AuditLogEntry(BaseModel):
    audit_id: str
    operator_id: str
    action: str
    target_type: str
    target_id: Optional[str] = None
    timestamp: str
    source_ip: Optional[str] = None
    outcome: str = "success"
    sanitized_details: Dict[str, Any] = Field(default_factory=dict)

# -------------------------------------------------------------
# INTEGRATION HEALTH SCHEMAS
# -------------------------------------------------------------

class IntegrationHealth(BaseModel):
    integration_name: str
    connectivity: str # online, offline, degraded
    last_successful_ingestion: Optional[str] = None
    last_event_timestamp: Optional[str] = None
    processing_lag_ms: float = 0.0
    error_count: int = 0
    queue_depth: int = 0
    last_error: Optional[str] = None
    configuration_status: str = "configured"
    updated_at: Optional[str] = None

# -------------------------------------------------------------
# ROUTER ONBOARDING & MANAGEMENT SCHEMAS
# -------------------------------------------------------------

class RouterRole(str, Enum):
    CORE = "core"                     # Core CGNAT / NAT444 / BGP Transit
    AC = "ac"                         # PPPoE Access Concentrator / IPoE Gateway
    BORDER = "border"                 # Transit Edge / Peering Router
    DISTRIBUTION = "distribution"     # Aggregation / Mid-haul Router
    CPE = "cpe"                       # Customer Edge / Fixed Wireless CPE
    OTHER = "other"                   # Generic Network Appliance

class RouterStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    UNTESTED = "untested"

class RouterBase(BaseModel):
    name: str = Field(..., description="Human-friendly router identifier")
    role: RouterRole = Field(default=RouterRole.CORE, description="Operational role in ISP architecture")
    host: str = Field(..., description="IP address or FQDN")
    port: int = Field(default=8728, description="API port (8728 api, 8729 api-ssl, 80/443 rest)")
    username: str = Field(default="security_ro", description="Read-only API username")
    use_ssl: bool = Field(default=False, description="Use TLS/SSL encryption for API connection")
    use_rest: bool = Field(default=False, description="Use RouterOS v7 REST API instead of binary API")
    notes: Optional[str] = Field(default="", description="Operator notes or rack location")
    enabled: bool = Field(default=True, description="Whether monitoring is enabled")

class RouterCreate(RouterBase):
    password: str = Field(..., description="Router API user password")

class RouterUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[RouterRole] = None
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    use_ssl: Optional[bool] = None
    use_rest: Optional[bool] = None
    notes: Optional[str] = None
    enabled: Optional[bool] = None

class Router(RouterBase):
    id: str
    status: RouterStatus = RouterStatus.UNTESTED
    model: Optional[str] = None
    ros_version: Optional[str] = None
    cpu_load: Optional[int] = None
    uptime: Optional[str] = None
    last_seen: Optional[str] = None
    last_error: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

class RouterTestResult(BaseModel):
    online: bool
    router_id: str
    name: str
    role: str
    host: str
    port: int
    model: Optional[str] = None
    ros_version: Optional[str] = None
    cpu_load: Optional[int] = None
    uptime: Optional[str] = None
    error: Optional[str] = None
    latency_ms: Optional[float] = None

