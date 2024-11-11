"""Models for security analysis reports."""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime


@dataclass
class RiskAssessment:
    """Risk assessment data."""

    risk_level: str
    risk_score: float
    risk_factors: Dict[str, float]


@dataclass
class Pattern:
    """Attack pattern data."""

    pattern_id: str
    attack_type: str
    confidence_score: float
    source_ips: List[str]
    first_seen: datetime
    last_seen: datetime
    affected_ports: Optional[List[int]] = None


@dataclass
class Anomaly:
    """Security anomaly data."""

    alert_id: str
    alert_type: str
    severity: int
    recommendation: str
    requires_immediate_action: bool
    baseline_value: Optional[float] = None
    current_value: Optional[float] = None


@dataclass
class Statistics:
    """Event statistics data."""

    event_count: int
    unique_sources: int
    unique_destinations: int
    protocols: Dict[str, int] = field(default_factory=dict)
    event_types: Dict[str, int] = field(default_factory=dict)
    severity_distribution: Dict[str, int] = field(default_factory=dict)
    geographic_distribution: Dict[str, Dict[str, int]] = field(
        default_factory=lambda: {"countries": {}}
    )
    temporal_distribution: Dict[str, int] = field(default_factory=dict)


@dataclass
class LLMInsight:
    """LLM analysis insight."""

    timestamp: datetime
    analysis: str


@dataclass
class SecurityReport:
    """Complete security analysis report."""

    summary: Dict[str, Any]
    risk_assessment: RiskAssessment
    patterns: List[Pattern]
    anomalies: List[Anomaly]
    statistics: Statistics
    llm_analysis: Optional[Dict[str, Any]] = None
    llm_insights: Optional[List[LLMInsight]] = None


@dataclass
class ConsolidatedReport:
    """Consolidated report from multiple batch reports."""

    summary: Dict[str, Any]
    risk_assessment: RiskAssessment
    patterns: List[Pattern]
    anomalies: List[Anomaly]
    statistics: Statistics
    analysis_period: Dict[str, datetime]
    total_events_analyzed: int
    total_patterns_detected: int
    total_anomalies_detected: int
    llm_analysis: Optional[Dict[str, Any]] = None
    llm_insights: Optional[List[LLMInsight]] = None
