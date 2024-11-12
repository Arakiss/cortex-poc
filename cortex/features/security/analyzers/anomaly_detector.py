"""Anomaly detection for security events."""

from datetime import datetime
from typing import Dict, List, Any
from collections import defaultdict
import uuid
import statistics
import logging

from cortex.features.models.security import AnomalyAlert

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Detects anomalies in security events."""

    def __init__(self):
        """Initialize anomaly detector with historical metrics."""
        self.historical_metrics = defaultdict(list)

    def update_metrics(self, metrics: Dict[str, List[float]]) -> None:
        """Update historical metrics with new data."""
        for metric, values in metrics.items():
            self.historical_metrics[metric].extend(values)

    def detect_anomalies(
        self, batch_metrics: Dict[str, List[float]], events: List[Dict[str, Any]], categorize_fn
    ) -> List[AnomalyAlert]:
        """Detects anomalies in the current batch with enhanced context."""
        anomalies = []

        # Group events by source IP and attack category
        ip_events = defaultdict(list)
        category_events = defaultdict(list)
        for event in events:
            ip_events[event["source_ip"]].append(event)
            attack_category = categorize_fn(event)
            if attack_category:
                category_events[attack_category].append(event)

        # Detect rapid succession anomalies
        self._detect_rapid_succession_anomalies(ip_events, anomalies, categorize_fn)

        # Detect severity spike anomalies
        self._detect_severity_spike_anomalies(ip_events, anomalies, categorize_fn)

        # Detect attack concentration anomalies
        self._detect_attack_concentration_anomalies(category_events, anomalies)

        return anomalies

    def _detect_rapid_succession_anomalies(
        self, ip_events: Dict[str, List[Dict]], anomalies: List[AnomalyAlert], categorize_fn
    ) -> None:
        """Detect events occurring in rapid succession."""
        for ip, ip_events_list in ip_events.items():
            if len(ip_events_list) >= 5:
                timestamps = [datetime.fromisoformat(e["timestamp"]) for e in ip_events_list]
                time_diffs = [
                    (timestamps[i + 1] - timestamps[i]).total_seconds()
                    for i in range(len(timestamps) - 1)
                ]

                if any(diff < 1.0 for diff in time_diffs):
                    anomalies.append(
                        AnomalyAlert(
                            alert_id=f"ANOM-{uuid.uuid4().hex[:8]}",
                            timestamp=datetime.now(),
                            ip_address=ip,
                            alert_type="rapid_succession",
                            severity=4,
                            baseline_value=5.0,
                            current_value=min(time_diffs),
                            recommendation=f"Investigate high-frequency events from {ip}",
                            requires_immediate_action=True,
                            attack_category=categorize_fn(ip_events_list[0]),
                            affected_systems=[e["destination_ip"] for e in ip_events_list],
                            potential_impact="Potential DDoS or automated attack",
                            mitigation_steps=[
                                "Implement rate limiting",
                                "Add IP to watchlist",
                                "Review firewall rules",
                            ],
                        )
                    )

    def _detect_severity_spike_anomalies(
        self, ip_events: Dict[str, List[Dict]], anomalies: List[AnomalyAlert], categorize_fn
    ) -> None:
        """Detect spikes in event severity."""
        for ip, ip_events_list in ip_events.items():
            try:
                high_severity_events = [
                    e for e in ip_events_list if e.get("alert", {}).get("severity", 0) >= 4
                ]
                if len(high_severity_events) > len(ip_events_list) * 0.3:
                    anomalies.append(
                        AnomalyAlert(
                            alert_id=f"ANOM-{uuid.uuid4().hex[:8]}",
                            timestamp=datetime.now(),
                            ip_address=ip,
                            alert_type="severity_spike",
                            severity=5,
                            baseline_value=len(ip_events_list) * 0.2,
                            current_value=len(high_severity_events),
                            recommendation=f"Investigate concentration of severe events from {ip}",
                            requires_immediate_action=True,
                            attack_category=categorize_fn(high_severity_events[0]),
                            affected_systems=[e["destination_ip"] for e in high_severity_events],
                            potential_impact="Critical security breach attempt",
                            mitigation_steps=[
                                "Block IP immediately",
                                "Analyze attack patterns",
                                "Review affected systems",
                            ],
                        )
                    )
            except Exception as e:
                logger.error(f"Error detecting severity spike anomalies: {str(e)}")

    def _detect_attack_concentration_anomalies(
        self, category_events: Dict[str, List[Dict]], anomalies: List[AnomalyAlert]
    ) -> None:
        """Detect high concentrations of specific attack types."""
        for category, category_events_list in category_events.items():
            if len(category_events_list) >= 10:
                # Calculate baseline from historical data
                if category in self.historical_metrics:
                    baseline = statistics.mean(self.historical_metrics[category])
                else:
                    baseline = len(category_events_list) * 0.5

                anomalies.append(
                    AnomalyAlert(
                        alert_id=f"ANOM-{uuid.uuid4().hex[:8]}",
                        timestamp=datetime.now(),
                        ip_address="multiple",
                        alert_type="attack_concentration",
                        severity=4,
                        baseline_value=baseline,
                        current_value=len(category_events_list),
                        recommendation=f"Investigate surge in {category} attacks",
                        requires_immediate_action=True,
                        attack_category=category,
                        affected_systems=list(
                            set(e["destination_ip"] for e in category_events_list)
                        ),
                        potential_impact="Coordinated attack campaign",
                        mitigation_steps=[
                            "Update security rules",
                            "Enable enhanced monitoring",
                            "Review defense mechanisms",
                        ],
                        false_positive_likelihood=0.1,
                    )
                )

    def _calculate_baseline(self, metric: str, current_value: float) -> float:
        """Calculate baseline value for a metric."""
        if metric in self.historical_metrics and self.historical_metrics[metric]:
            return statistics.mean(self.historical_metrics[metric])
        return current_value * 0.5

    def _is_anomalous(self, value: float, baseline: float, threshold: float = 2.0) -> bool:
        """Determine if a value is anomalous compared to baseline."""
        return abs(value - baseline) > (baseline * threshold)
