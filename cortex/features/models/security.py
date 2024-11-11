from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, field_serializer, field_validator
from enum import IntEnum


class EventSeverity(IntEnum):
    """Enum for event severity levels."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3


class SecurityEvent(BaseModel):
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
    pattern_id: str
    source_ips: List[str]
    geographic_data: Dict[str, Any]
    frequency: int
    attack_type: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    first_seen: datetime
    last_seen: datetime
    affected_ports: List[int]
    protocol_distribution: Dict[str, int]


class SecurityRule(BaseModel):
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


class AnomalyAlert(BaseModel):
    alert_id: str
    timestamp: datetime
    ip_address: str
    alert_type: str
    severity: int = Field(ge=1, le=5)
    baseline_value: float
    current_value: float
    recommendation: str
    requires_immediate_action: bool = False
