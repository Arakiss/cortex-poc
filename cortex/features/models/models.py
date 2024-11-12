"""Core models for security analysis."""

from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel


class SecurityReport(BaseModel):
    """Model for batch security reports with enhanced context."""

    summary: Dict[str, Any]
    risk_assessment: "RiskAssessment"
    patterns: List["Pattern"]
    anomalies: List["Anomaly"]
    statistics: "Statistics"
    llm_analysis: Optional[Dict[str, Any]] = None


class ConsolidatedReport(BaseModel):
    """Model for consolidated security reports with enhanced analysis."""

    summary: Dict[str, Any]
    analysis_period: Dict[str, datetime]
    total_events_analyzed: int
    total_patterns_detected: int
    total_anomalies_detected: int
    risk_assessment: "RiskAssessment"
    patterns: List["Pattern"]
    anomalies: List["Anomaly"]
    statistics: "Statistics"
    llm_insights: List["LLMInsight"]


class RiskAssessment(BaseModel):
    """Enhanced model for risk assessment with detailed factors."""

    risk_level: str
    risk_score: float
    risk_factors: Dict[str, Any]
    attack_vectors: Dict[str, float] = {}
    threat_categories: Dict[str, int] = {}
    impact_analysis: Dict[str, str] = {}
    mitigation_status: Dict[str, str] = {}
    trend_analysis: Dict[str, Any] = {}
    geographic_risks: Dict[str, float] = {}
    protocol_risks: Dict[str, float] = {}


class Pattern(BaseModel):
    """Enhanced model for attack patterns with detailed analysis."""

    pattern_id: str
    source_ips: List[str]
    geographic_data: Dict[str, Any]
    frequency: int
    attack_type: str
    confidence_score: float
    first_seen: str
    last_seen: str
    affected_ports: List[int]
    protocol_distribution: Dict[str, int]
    severity: float = 0.0
    impact_score: float = 0.0
    tactics: List[str] = []
    techniques: List[str] = []
    affected_systems: List[str] = []
    mitigation_status: str = "pending"
    related_patterns: List[str] = []
    false_positive_likelihood: float = 0.0


class Anomaly(BaseModel):
    """Enhanced model for anomalies with actionable context."""

    alert_id: str
    alert_type: str
    severity: int
    recommendation: str
    requires_immediate_action: bool
    baseline_value: float
    current_value: float
    attack_category: Optional[str] = None
    affected_systems: List[str] = []
    potential_impact: str = ""
    mitigation_steps: List[str] = []
    investigation_priority: str = "medium"
    false_positive_likelihood: float = 0.0
    related_alerts: List[str] = []
    temporal_context: Dict[str, Any] = {}


class Statistics(BaseModel):
    """Enhanced model for security statistics with trend analysis."""

    event_count: int
    unique_sources: int
    unique_destinations: int
    protocols: Dict[str, int] = {}
    event_types: Dict[str, int] = {}
    severity_distribution: Dict[str, int] = {}
    geographic_distribution: Dict[str, Dict[str, int]] = {}
    temporal_distribution: Dict[str, int] = {}
    attack_success_rates: Dict[str, float] = {}
    mitigation_effectiveness: Dict[str, float] = {}
    response_times: Dict[str, float] = {}
    trend_indicators: Dict[str, str] = {}


class LLMInsight(BaseModel):
    """Model for LLM-generated security insights with enhanced context."""

    timestamp: datetime
    analysis: str
    confidence_score: float = 0.0
    key_findings: List[str] = []
    recommendations: List[Dict[str, Any]] = []
    risk_factors: Dict[str, float] = {}
    mitigation_priorities: List[str] = []
    investigation_leads: List[str] = []


class ThreatIntelligence(BaseModel):
    """Model for threat intelligence data with actionable insights."""

    source: str
    indicators: List[Dict[str, Any]]
    confidence: float
    severity: int
    first_seen: datetime
    last_seen: datetime
    tactics: List[str] = []
    techniques: List[str] = []
    affected_systems: List[str] = []
    mitigation_status: str = "pending"
    related_threats: List[str] = []
    false_positive_rate: float = 0.0


class MitigationPlan(BaseModel):
    """Model for detailed mitigation planning."""

    plan_id: str
    priority: int
    status: str
    steps: List[Dict[str, Any]]
    dependencies: List[str]
    resources_required: List[str]
    estimated_completion: datetime
    actual_completion: Optional[datetime]
    effectiveness_metrics: Dict[str, float]
    rollback_procedure: str


SecurityReport.model_rebuild()
ConsolidatedReport.model_rebuild()
