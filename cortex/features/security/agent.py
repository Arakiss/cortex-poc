"""Security analysis agent implementation."""

import logging
import statistics
from datetime import datetime
from typing import List, Dict, Any, Union, Callable, Optional
from collections import defaultdict
import uuid
import json
import os

from pydantic import Field
from cortex.core.agents.agent import Agent
from cortex.core.agents import run
from cortex.core.llm.base_provider import LLMProvider
from cortex.features.models.security import SecurityEvent, EventSeverity, AnomalyAlert

# Configure logging
logger = logging.getLogger(__name__)


class SecurityAnalysisAgent(Agent):
    """Agent for security analysis that processes events and generates patterns."""

    name: str = "security_analysis_agent"
    role: str = "Security log analyzer for pattern detection and threat analysis"
    model: str = os.getenv("MODEL_NAME", "gpt-4o-mini")  # Use model from environment
    instructions: Union[str, Callable[..., str]] = (
        "You are a security analysis agent specialized in analyzing security logs and identifying attack patterns. "
        "Your analysis should focus on:\n"
        "1. Pattern-based threat detection across multiple log sources\n"
        "2. Geographic and temporal pattern analysis\n"
        "3. Protocol and port analysis\n"
        "4. Severity assessment and anomaly detection\n"
        "Provide detailed analysis with actionable recommendations."
    )
    functions: List[Callable[..., Union[str, "Agent", dict]]] = []
    tool_choice: Optional[str] = None
    parallel_tool_calls: bool = True

    # Add model fields with proper initialization
    events_processed: int = 0
    patterns_detected: List[Dict[str, Any]] = Field(default_factory=list)
    anomalies_detected: List[AnomalyAlert] = Field(default_factory=list)
    historical_metrics: Dict[str, List[float]] = Field(default_factory=lambda: defaultdict(list))

    class Config:
        arbitrary_types_allowed = True

    def __init__(self, **data):
        super().__init__(**data)
        self.historical_metrics = defaultdict(list)

    def _assess_overall_risk(
        self,
        patterns: List[Dict[str, Any]],
        anomalies: List[AnomalyAlert],
        statistics: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Evaluates the overall risk level based on all analyzed data."""
        risk_factors = {
            "pattern_risk": 0.0,
            "anomaly_risk": 0.0,
            "geographic_risk": 0.0,
            "protocol_risk": 0.0,
        }

        # Evaluate pattern risk
        if patterns:
            high_confidence_patterns = len([p for p in patterns if p["confidence_score"] > 0.7])
            risk_factors["pattern_risk"] = min(high_confidence_patterns / 10, 1.0)

        # Evaluate anomaly risk
        if anomalies:
            critical_anomalies = len([a for a in anomalies if a.requires_immediate_action])
            risk_factors["anomaly_risk"] = min(critical_anomalies / 5, 1.0)

        # Evaluate geographic risk
        country_dist = statistics.get("geographic_distribution", {}).get("countries", {})
        if country_dist:
            high_risk_countries = len(
                [
                    c
                    for c, count in country_dist.items()
                    if count > statistics.get("total_events", 0) * 0.1
                ]
            )
            risk_factors["geographic_risk"] = min(high_risk_countries / 5, 1.0)

        # Evaluate protocol risk
        protocol_dist = statistics.get("protocols", {})
        if protocol_dist:
            vulnerable_protocols = len(
                [p for p in protocol_dist.keys() if p.lower() in ["telnet", "ftp", "http"]]
            )
            risk_factors["protocol_risk"] = min(vulnerable_protocols / 3, 1.0)

        # Calculate overall risk score
        overall_risk_score = sum(risk_factors.values()) / len(risk_factors)
        risk_level = (
            "CRITICAL"
            if overall_risk_score > 0.8
            else "HIGH"
            if overall_risk_score > 0.6
            else "MEDIUM"
            if overall_risk_score > 0.3
            else "LOW"
        )

        return {
            "risk_score": overall_risk_score,
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "assessment_timestamp": datetime.now().isoformat(),
        }

    async def analyze_batch(
        self, events: List[Dict[str, Any]], llm_provider: LLMProvider
    ) -> Dict[str, Any]:
        """Analyzes a batch of security events."""
        try:
            normalized_events = []
            batch_metrics = defaultdict(list)

            # Normalize events and collect metrics
            for event in events:
                try:
                    if "severity" in event:
                        severity = event["severity"]
                        if isinstance(severity, int):
                            if severity > 3:
                                event["severity"] = EventSeverity.HIGH
                            elif severity < 1:
                                event["severity"] = EventSeverity.LOW
                            else:
                                event["severity"] = EventSeverity(severity)

                    security_event = SecurityEvent(**event)
                    normalized_events.append(security_event.model_dump())

                    # Collect metrics for anomaly detection
                    batch_metrics["connection_count"].append(security_event.connection_count)
                    batch_metrics["severity"].append(security_event.severity)

                except Exception as e:
                    logger.error(f"Error processing event: {str(e)}")
                    continue

            self.events_processed += len(normalized_events)

            # Update historical metrics
            for metric, values in batch_metrics.items():
                self.historical_metrics[metric].extend(values)

            # Detect patterns
            patterns = self._extract_patterns(normalized_events)

            # Detect anomalies
            anomalies = self._detect_anomalies(batch_metrics, normalized_events)

            # Calculate batch statistics
            batch_stats = self._calculate_batch_statistics(normalized_events)

            # Calculate risk assessment
            risk_assessment = self._assess_overall_risk(patterns, anomalies, batch_stats)

            # Process events using LLM for human-readable analysis
            prompt = (
                "Analyze the following security events and provide:\n"
                "1. Key findings and attack patterns\n"
                "2. Risk assessment and potential impact\n"
                "3. Specific recommendations for mitigation\n"
                "4. Geographic and temporal patterns\n"
                "5. Protocol-specific concerns\n\n"
                f"Events: {json.dumps(normalized_events, indent=2)}"
            )

            messages = [{"role": "user", "content": prompt}]
            try:
                llm_response = await run(
                    client=llm_provider, agent=self, messages=messages, debug=False, max_turns=4
                )
                llm_content = (
                    llm_response.messages[-1]["content"]
                    if llm_response and llm_response.messages
                    else None
                )
            except Exception as e:
                logger.error(f"Error in LLM processing: {str(e)}")
                llm_content = None

            # Calculate batch statistics
            batch_stats = self._calculate_batch_statistics(normalized_events)

            # Generate recommendations based on patterns and anomalies
            recommendations = self._generate_recommendations(patterns, anomalies, batch_stats)

            # Transformar las anomalías al formato esperado por Anomaly
            transformed_anomalies = []
            for anomaly in anomalies:
                transformed_anomalies.append(
                    {
                        "alert_id": anomaly.alert_id,
                        "alert_type": anomaly.alert_type,
                        "severity": anomaly.severity,
                        "recommendation": anomaly.recommendation,
                        "requires_immediate_action": anomaly.requires_immediate_action,
                        "baseline_value": anomaly.baseline_value,
                        "current_value": anomaly.current_value,
                    }
                )

            return {
                "timestamp": datetime.now(),
                "events_analyzed": len(normalized_events),
                "patterns": patterns,
                "anomalies": transformed_anomalies,
                "risk_assessment": risk_assessment,
                "llm_analysis": {
                    "raw_response": llm_content,
                    "recommendations": recommendations,
                },
                "batch_statistics": batch_stats,
                "metrics": {
                    metric: {
                        "mean": statistics.mean(values) if values else 0,
                        "std": statistics.stdev(values) if len(values) > 1 else 0,
                    }
                    for metric, values in batch_metrics.items()
                },
            }
        except Exception as e:
            logger.error(f"Error in analyze_batch: {str(e)}")
            return {
                "timestamp": datetime.now(),
                "events_analyzed": 0,
                "patterns": [],
                "anomalies": [],
                "risk_assessment": {
                    "risk_score": 0.0,
                    "risk_level": "LOW",
                    "risk_factors": {},
                    "assessment_timestamp": datetime.now().isoformat(),
                },
                "llm_analysis": None,
                "batch_statistics": {},
                "metrics": {},
            }

    def _detect_anomalies(
        self, batch_metrics: Dict[str, List[float]], events: List[Dict[str, Any]]
    ) -> List[AnomalyAlert]:
        """Detects anomalies in the current batch by comparing with historical metrics."""
        anomalies = []

        # Analyze connection counts
        connection_counts = self.historical_metrics.get("connection_count", [])
        if connection_counts:
            hist_mean = statistics.mean(connection_counts)
            hist_std = statistics.stdev(connection_counts) if len(connection_counts) > 1 else 0

            current_mean = statistics.mean(batch_metrics.get("connection_count", []) or [0])
            if abs(current_mean - hist_mean) > (2 * hist_std):
                anomalies.append(
                    AnomalyAlert(
                        alert_id=f"ANOM-{uuid.uuid4().hex[:8]}",
                        timestamp=datetime.now(),
                        ip_address="multiple",
                        alert_type="connection_frequency",
                        severity=4 if current_mean > hist_mean else 3,
                        baseline_value=hist_mean,
                        current_value=current_mean,
                        recommendation="Investigate unusual connection frequency pattern",
                        requires_immediate_action=current_mean > (hist_mean + 3 * hist_std),
                    )
                )

        # Analyze severity distribution
        severity_counts = defaultdict(int)
        for event in events:
            severity_counts[event["severity"]] += 1

        if severity_counts[EventSeverity.HIGH] > len(events) * 0.3:  # More than 30% high severity
            anomalies.append(
                AnomalyAlert(
                    alert_id=f"ANOM-{uuid.uuid4().hex[:8]}",
                    timestamp=datetime.now(),
                    ip_address="multiple",
                    alert_type="severity_spike",
                    severity=5,
                    baseline_value=len(events) * 0.1,  # Expected 10% high severity
                    current_value=severity_counts[EventSeverity.HIGH],
                    recommendation="Investigate high concentration of severe events",
                    requires_immediate_action=True,
                )
            )

        return anomalies

    def _calculate_batch_statistics(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculates detailed statistics for the batch."""
        stats = {
            "event_count": len(events),
            "unique_sources": len(set(e["source_ip"] for e in events)),
            "unique_destinations": len(set(e["destination_ip"] for e in events)),
            "protocols": defaultdict(int),
            "event_types": defaultdict(int),
            "severity_distribution": defaultdict(int),
            "geographic_distribution": defaultdict(lambda: defaultdict(int)),
            "temporal_distribution": defaultdict(int),
        }

        for event in events:
            stats["protocols"][event["protocol"]] += 1
            stats["event_types"][event["event_type"]] += 1
            stats["severity_distribution"][str(event["severity"])] += 1

            if event.get("country_code"):
                stats["geographic_distribution"]["countries"][event["country_code"]] += 1
            if event.get("continent_code"):
                stats["geographic_distribution"]["continents"][event["continent_code"]] += 1

            hour = datetime.fromisoformat(event["timestamp"]).hour
            stats["temporal_distribution"][hour] += 1

        # Convert defaultdicts to regular dicts for serialization
        return {k: dict(v) if isinstance(v, defaultdict) else v for k, v in stats.items()}

    def _extract_patterns(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extracts attack patterns from analyzed events."""
        patterns = []
        event_groups = defaultdict(list)

        # Group events by source IP and event type
        for event in events:
            key = (event["source_ip"], event["event_type"])
            event_groups[key].append(event)

        # Analyze each group for patterns
        for (source_ip, event_type), group in event_groups.items():
            if len(group) >= 3:  # Minimum events to consider a pattern
                first_event = min(group, key=lambda x: datetime.fromisoformat(x["timestamp"]))
                last_event = max(group, key=lambda x: datetime.fromisoformat(x["timestamp"]))

                # Calculate confidence score based on various factors
                frequency = len(group)
                time_span = (
                    datetime.fromisoformat(last_event["timestamp"])
                    - datetime.fromisoformat(first_event["timestamp"])
                ).total_seconds() / 3600  # Convert to hours

                if time_span > 0:
                    events_per_hour = frequency / time_span
                    confidence_score = min(events_per_hour / 10, 1.0)  # Normalize to 0-1
                else:
                    confidence_score = 1.0 if frequency > 5 else 0.7

                # Collect affected ports and protocols
                affected_ports = list(
                    set(
                        int(e.get("destination_port", 0))
                        for e in group
                        if e.get("destination_port")
                    )
                )
                protocol_dist = defaultdict(int)
                for e in group:
                    protocol_dist[e["protocol"]] += 1

                # Create pattern object
                pattern = {
                    "pattern_id": f"PTN-{uuid.uuid4().hex[:8]}",
                    "source_ips": [source_ip],
                    "geographic_data": {
                        "country": group[0].get("country_code"),
                        "continent": group[0].get("continent_code"),
                    },
                    "frequency": frequency,
                    "attack_type": event_type,
                    "confidence_score": confidence_score,
                    "first_seen": first_event["timestamp"],
                    "last_seen": last_event["timestamp"],
                    "affected_ports": affected_ports,
                    "protocol_distribution": dict(protocol_dist),
                }
                patterns.append(pattern)

        return patterns

    def _generate_recommendations(
        self,
        patterns: List[Dict[str, Any]],
        anomalies: List[AnomalyAlert],
        statistics: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Generates actionable recommendations based on patterns and anomalies."""
        recommendations = []

        # Pattern-based recommendations
        for pattern in patterns:
            if pattern["confidence_score"] > 0.7:
                recommendations.append(
                    {
                        "type": "pattern",
                        "priority": "high" if pattern["confidence_score"] > 0.9 else "medium",
                        "finding": f"Detected {pattern['attack_type']} pattern from {pattern['source_ips'][0]}",
                        "action": f"Implement blocking rules for {pattern['attack_type']} from identified source",
                        "details": {
                            "pattern_id": pattern["pattern_id"],
                            "affected_ports": pattern["affected_ports"],
                            "protocols": list(pattern["protocol_distribution"].keys()),
                        },
                    }
                )

        # Anomaly-based recommendations
        for anomaly in anomalies:
            recommendations.append(
                {
                    "type": "anomaly",
                    "priority": "critical" if anomaly.requires_immediate_action else "high",
                    "finding": f"Detected {anomaly.alert_type} anomaly",
                    "action": anomaly.recommendation,
                    "details": {
                        "alert_id": anomaly.alert_id,
                        "severity": anomaly.severity,
                        "baseline": anomaly.baseline_value,
                        "current": anomaly.current_value,
                    },
                }
            )

        # Protocol-based recommendations
        protocol_dist = statistics.get("protocols", {})
        vulnerable_protocols = [
            p for p in protocol_dist.keys() if p.lower() in ["telnet", "ftp", "http"]
        ]
        if vulnerable_protocols:
            recommendations.append(
                {
                    "type": "protocol",
                    "priority": "medium",
                    "finding": f"High usage of vulnerable protocols: {', '.join(vulnerable_protocols)}",
                    "action": "Consider upgrading to secure alternatives (SSH, SFTP, HTTPS)",
                    "details": {
                        "protocols": vulnerable_protocols,
                        "usage_counts": {p: protocol_dist[p] for p in vulnerable_protocols},
                    },
                }
            )

        return recommendations

    def _extract_ports(self, events: List[Dict[str, Any]]) -> List[int]:
        """Extracts affected ports from events."""
        ports = set()
        for event in events:
            if ":" in event["destination_ip"]:
                try:
                    port = int(event["destination_ip"].split(":")[-1])
                    ports.add(port)
                except ValueError:
                    continue
        return list(ports)

    def _get_protocol_distribution(self, events: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculates protocol distribution in events."""
        distribution = defaultdict(int)
        for event in events:
            distribution[event["protocol"]] += 1
        return dict(distribution)

    def _estimate_batch_cost(self, batch: List[Dict[str, Any]]) -> float:
        """Estimates the cost of processing a batch."""
        estimated_tokens = sum(len(str(event)) for event in batch) / 4
        return (estimated_tokens / 1000) * 0.01
