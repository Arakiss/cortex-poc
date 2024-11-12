"""Security analysis agent implementation."""

import logging
import json
import os
from datetime import datetime
from typing import List, Dict, Any, Union, Callable, Optional
from collections import defaultdict
import random
import traceback

from pydantic import Field
from cortex.core.agents.agent import Agent
from cortex.core.agents import run
from cortex.core.llm.base_provider import LLMProvider
from cortex.features.models.security import (
    SecurityEvent,
    EventSeverity,
    AnomalyAlert,
)

from .analyzers.attack_analyzer import AttackAnalyzer
from .analyzers.risk_assessor import RiskAssessor
from .analyzers.anomaly_detector import AnomalyDetector
from .analyzers.pattern_analyzer import PatternAnalyzer
from .analyzers.statistics_calculator import StatisticsCalculator

logger = logging.getLogger(__name__)


class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder for datetime objects."""

    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


class SecurityAnalysisAgent(Agent):
    """Agent for security analysis that processes events and generates patterns."""

    name: str = "security_analysis_agent"
    role: str = "Security log analyzer for pattern detection and threat analysis"
    model: str = os.getenv("MODEL_NAME", "gpt-4o-mini")
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

    # Processing metrics
    events_processed: int = 0
    patterns_detected: List[Dict[str, Any]] = Field(default_factory=list)
    anomalies_detected: List[AnomalyAlert] = Field(default_factory=list)

    # Analyzers
    attack_analyzer: AttackAnalyzer = Field(default_factory=AttackAnalyzer)
    risk_assessor: RiskAssessor = Field(default_factory=RiskAssessor)
    anomaly_detector: AnomalyDetector = Field(default_factory=AnomalyDetector)
    pattern_analyzer: Optional[PatternAnalyzer] = None
    statistics_calculator: StatisticsCalculator = Field(default_factory=StatisticsCalculator)

    def __init__(self, **data):
        """Initialize security analysis agent with its analyzers."""
        super().__init__(**data)
        # Initialize PatternAnalyzer after other analyzers are created
        self.pattern_analyzer = PatternAnalyzer(self.attack_analyzer, self.risk_assessor)

    def _get_event_severity(self, event: Dict[str, Any]) -> EventSeverity:
        """Extract severity from event, with fallbacks for different event types."""
        try:
            logger.debug(f"Processing event for severity: {json.dumps(event, default=str)[:200]}")

            # Direct severity field (ClamAV format)
            if "severity" in event:
                severity_value = event["severity"]
                if isinstance(severity_value, (int, float)):
                    logger.debug(f"Found direct severity: {severity_value}")
                    return self._convert_to_event_severity(severity_value)

            # Alert severity (EVE format)
            if "alert" in event:
                alert = event.get("alert", {})
                if isinstance(alert, dict) and "severity" in alert:
                    severity_value = alert["severity"]
                    if isinstance(severity_value, (int, float)):
                        logger.debug(f"Found alert severity: {severity_value}")
                        return self._convert_to_event_severity(severity_value)

            # Fallback severity based on event type
            event_type = event.get("event_type")
            if event_type in ["malware_detection", "attack", "intrusion"]:
                logger.debug(f"Using fallback severity for event type: {event_type}")
                return EventSeverity.HIGH

            logger.debug("Using default LOW severity")
            return EventSeverity.LOW

        except Exception as e:
            logger.error(
                f"Error getting severity: {str(e)}\nEvent: {json.dumps(event, default=str)[:200]}\nTraceback: {traceback.format_exc()}"
            )
            return EventSeverity.LOW

    def _convert_to_event_severity(self, severity: Union[int, float]) -> EventSeverity:
        """Convert numeric severity to EventSeverity enum."""
        try:
            if severity > 4:
                return EventSeverity.EMERGENCY
            elif severity > 3:
                return EventSeverity.CRITICAL
            elif severity > 2:
                return EventSeverity.HIGH
            elif severity > 1:
                return EventSeverity.MEDIUM
            return EventSeverity.LOW
        except Exception as e:
            logger.error(f"Error converting severity {severity}: {str(e)}")
            return EventSeverity.LOW

    def _normalize_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Normalizes different event formats into a standard structure."""
        try:
            logger.debug(f"Normalizing event: {json.dumps(event, default=str)[:200]}")

            # Base structure for normalized event
            normalized = {
                "timestamp": event.get("timestamp"),
                "source_ip": event.get("source_ip") or event.get("src_ip"),
                "destination_ip": event.get("destination_ip") or event.get("dest_ip"),
                "event_type": event.get("event_type"),
                "protocol": event.get("protocol") or event.get("proto"),
                "raw_data": {},
                "connection_count": 1,  # Default value
            }

            # Get severity first to avoid potential KeyError
            try:
                normalized["severity"] = self._get_event_severity(event)
            except Exception as e:
                logger.error(f"Error getting severity during normalization: {str(e)}")
                normalized["severity"] = EventSeverity.LOW

            # Handle ClamAV specific fields
            if "scan_details" in event:
                logger.debug("Processing ClamAV format")
                normalized["raw_data"]["scan_details"] = event["scan_details"]
                normalized["attack_type"] = "malware"
                normalized["attack_details"] = {
                    "malware_type": event["scan_details"].get("malware_type"),
                    "action_taken": event["scan_details"].get("action_taken"),
                    "file_type": event["scan_details"].get("file_type"),
                }

            # Handle EVE specific fields
            if "alert" in event:
                logger.debug("Processing EVE format")
                alert = event.get("alert", {})
                if isinstance(alert, dict):
                    normalized["raw_data"]["alert"] = alert
                    normalized["attack_type"] = "network"
                    normalized["attack_details"] = {
                        "signature": alert.get("signature"),
                        "category": alert.get("category"),
                        "signature_id": alert.get("signature_id"),
                    }

            # Add geographic data if available
            if "src_country" in event:
                normalized["source_country"] = event["src_country"]
                normalized["source_continent"] = event.get("src_continent")

            # Add protocol specific information
            for field in ["http", "port_scan", "anomaly", "geo_context", "auth", "protocol_info"]:
                if field in event:
                    normalized["raw_data"][field] = event[field]

            # Ensure all required fields are present
            required_fields = ["timestamp", "source_ip", "event_type", "severity"]
            missing_fields = [field for field in required_fields if not normalized.get(field)]

            if missing_fields:
                logger.warning(f"Missing required fields in event: {missing_fields}")
                return None

            logger.debug(
                f"Successfully normalized event: {json.dumps(normalized, default=str)[:200]}"
            )
            return normalized

        except Exception as e:
            logger.error(
                f"Error normalizing event: {str(e)}\nEvent: {json.dumps(event, default=str)[:200]}\nTraceback: {traceback.format_exc()}"
            )
            return None

    async def analyze_batch(
        self, events: List[Dict[str, Any]], llm_provider: LLMProvider
    ) -> Dict[str, Any]:
        """Analyzes a batch of security events with enhanced context."""
        try:
            logger.debug(f"Starting batch analysis of {len(events)} events")

            # Initialize metrics collection
            batch_metrics = defaultdict(list)
            normalized_events = []

            # Process events one at a time
            for event in events:
                try:
                    logger.debug(f"Processing event: {json.dumps(event, default=str)[:200]}")

                    # Normalize the event
                    normalized_event = self._normalize_event(event)

                    # Skip events that couldn't be normalized
                    if not normalized_event:
                        logger.warning("Event normalization failed, skipping")
                        continue

                    # Add attack categorization
                    try:
                        attack_category = self.attack_analyzer.categorize_attack(normalized_event)
                        if attack_category:
                            normalized_event["attack_category"] = attack_category
                            normalized_event["attack_details"] = (
                                self.attack_analyzer.extract_attack_details(normalized_event)
                            )
                    except Exception as e:
                        logger.error(f"Error in attack categorization: {str(e)}")
                        continue

                    # Convert to Pydantic model and back to dict
                    try:
                        logger.debug("Converting to SecurityEvent model")
                        security_event = SecurityEvent(**normalized_event)
                        normalized_event = security_event.model_dump()
                        normalized_events.append(normalized_event)

                        # Collect metrics for anomaly detection
                        batch_metrics["connection_count"].append(security_event.connection_count)
                        batch_metrics["severity"].append(security_event.severity)
                        if attack_category:
                            batch_metrics[attack_category].append(1)
                    except Exception as e:
                        logger.error(
                            f"Error converting to SecurityEvent: {str(e)}\nEvent: {json.dumps(normalized_event, default=str)[:200]}\nTraceback: {traceback.format_exc()}"
                        )
                        continue

                except Exception as e:
                    logger.error(
                        f"Error processing event: {str(e)}\nEvent: {json.dumps(event, default=str)[:200]}\nTraceback: {traceback.format_exc()}"
                    )
                    continue

            # Skip further processing if no events were normalized
            if not normalized_events:
                logger.error("No events could be normalized in the batch")
                raise ValueError("No events could be normalized")

            logger.info(f"Successfully normalized {len(normalized_events)} events")
            self.events_processed += len(normalized_events)

            # Update anomaly detector metrics
            self.anomaly_detector.update_metrics(batch_metrics)

            # Detect patterns and anomalies
            patterns = self.pattern_analyzer.extract_patterns(normalized_events)
            anomalies = self.anomaly_detector.detect_anomalies(
                batch_metrics, normalized_events, self.attack_analyzer.categorize_attack
            )

            # Calculate batch statistics
            batch_stats = self.statistics_calculator.calculate_batch_statistics(normalized_events)

            # Calculate risk assessment
            risk_assessment = self.risk_assessor.assess_overall_risk(
                patterns, anomalies, batch_stats
            )

            # Process a sample of events for LLM analysis
            if normalized_events:
                sample_size = min(5, len(normalized_events))
                sample_events = random.sample(normalized_events, sample_size)
            else:
                sample_events = []

            prompt = (
                "Analyze the following sample of security events and provide:\n"
                "1. Key findings and attack patterns\n"
                "2. Risk assessment and potential impact\n"
                "3. Specific recommendations for mitigation\n"
                "4. Geographic and temporal patterns\n"
                "5. Protocol-specific concerns\n\n"
                f"Sample Events: {json.dumps(sample_events, indent=2, cls=DateTimeEncoder)}"
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

            transformed_anomalies = [
                {
                    "alert_id": anomaly.alert_id,
                    "alert_type": anomaly.alert_type,
                    "severity": anomaly.severity,
                    "recommendation": anomaly.recommendation,
                    "requires_immediate_action": anomaly.requires_immediate_action,
                    "baseline_value": anomaly.baseline_value,
                    "current_value": anomaly.current_value,
                    "attack_category": anomaly.attack_category,
                    "affected_systems": anomaly.affected_systems,
                    "potential_impact": anomaly.potential_impact,
                    "mitigation_steps": anomaly.mitigation_steps,
                }
                for anomaly in anomalies
            ]

            logger.info("Batch analysis completed successfully")
            return {
                "timestamp": datetime.now().isoformat(),
                "events_analyzed": len(normalized_events),
                "patterns": patterns,
                "anomalies": transformed_anomalies,
                "risk_assessment": risk_assessment,
                "llm_analysis": {
                    "raw_response": llm_content,
                },
                "batch_statistics": batch_stats,
            }

        except Exception as e:
            logger.error(f"Error in analyze_batch: {str(e)}\nTraceback: {traceback.format_exc()}")
            return {
                "status": "error",
                "error": str(e),
                "traceback": traceback.format_exc(),
                "events_processed": 0,
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
            }
