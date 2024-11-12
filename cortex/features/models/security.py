from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, field_serializer, field_validator
from enum import IntEnum


class EventSeverity(IntEnum):
    """Enum for event severity levels."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5


class AttackCategory(str):
    """Categories of attacks for better classification."""

    SQL_INJECTION = "sql_injection"
    DDOS = "ddos"
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    PROTOCOL_ABUSE = "protocol_abuse"
    MALWARE = "malware"
    RECONNAISSANCE = "reconnaissance"
    UNKNOWN = "unknown"


class SecurityEvent(BaseModel):
    """Model for security events with enhanced context."""

    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    event_type: str
    severity: EventSeverity
    raw_log: str = ""
    country_code: Optional[str] = None
    continent_code: Optional[str] = None
    connection_count: int = 1
    attack_category: Optional[str] = None
    attack_details: Optional[Dict[str, Any]] = None

    @field_serializer("timestamp")
    def serialize_datetime(self, dt: datetime) -> str:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_datetime(cls, value):
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f")
        raise ValueError(f"Invalid timestamp format: {value}")


class AttackPattern(BaseModel):
    """Enhanced model for attack patterns with detailed context."""

    pattern_id: str
    source_ips: List[str]
    geographic_data: Dict[str, Any]
    frequency: int
    attack_type: str
    attack_category: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    first_seen: datetime
    last_seen: datetime
    affected_ports: List[int]
    protocol_distribution: Dict[str, int]
    impact_score: float = Field(ge=0.0, le=1.0)
    tactics: List[str] = []
    techniques: List[str] = []
    affected_systems: List[str] = []
    mitigation_status: str = "pending"


class SecurityRule(BaseModel):
    """Enhanced model for security rules with implementation details."""

    rule_id: str
    rule_type: str
    rule_content: str
    priority: int = Field(ge=1, le=5)
    expiration: Optional[datetime] = None
    created_at: datetime
    status: str
    geographic_scope: Optional[List[str]] = None
    auto_approved: bool = False
    effectiveness_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    implementation_steps: List[str] = []
    dependencies: List[str] = []
    affected_services: List[str] = []
    rollback_procedure: Optional[str] = None


class AnomalyAlert(BaseModel):
    """Enhanced model for anomaly alerts with actionable context."""

    alert_id: str
    timestamp: datetime
    ip_address: str
    alert_type: str
    severity: int = Field(ge=1, le=5)
    baseline_value: float
    current_value: float
    recommendation: str
    requires_immediate_action: bool = False
    attack_category: Optional[str] = None
    affected_systems: List[str] = []
    potential_impact: str = ""
    mitigation_steps: List[str] = []
    investigation_priority: str = "medium"
    false_positive_likelihood: float = Field(ge=0.0, le=1.0)
    related_alerts: List[str] = []


class ThreatIndicator(BaseModel):
    """Model for tracking specific threat indicators."""

    indicator_id: str
    indicator_type: str
    value: str
    confidence: float = Field(ge=0.0, le=1.0)
    severity: int = Field(ge=1, le=5)
    first_seen: datetime
    last_seen: datetime
    source: str
    context: Dict[str, Any] = {}
    related_indicators: List[str] = []
    false_positive_rate: float = Field(ge=0.0, le=1.0)


class MitigationAction(BaseModel):
    """Model for specific mitigation actions."""

    action_id: str
    action_type: str
    target: str
    parameters: Dict[str, Any]
    priority: int = Field(ge=1, le=5)
    effectiveness: float = Field(ge=0.0, le=1.0)
    implementation_time: str
    resources_required: List[str]
    dependencies: List[str]
    rollback_procedure: str


class SecurityMetrics(BaseModel):
    """Model for tracking security metrics over time."""

    timestamp: datetime
    total_events: int
    unique_sources: int
    unique_destinations: int
    attack_distribution: Dict[str, int]
    severity_distribution: Dict[str, int]
    geographic_distribution: Dict[str, int]
    protocol_distribution: Dict[str, int]
    response_times: Dict[str, float]
    mitigation_effectiveness: Dict[str, float]
    false_positive_rates: Dict[str, float]


class ComplianceCheck(BaseModel):
    """Model for compliance-related checks and validations."""

    check_id: str
    standard: str
    requirement: str
    status: str
    last_checked: datetime
    findings: List[str]
    remediation_steps: List[str]
    priority: int = Field(ge=1, le=5)
    responsible_party: str
    due_date: Optional[datetime]
