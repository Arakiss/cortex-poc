"""Pattern analysis for security events."""

from datetime import datetime
from typing import Dict, List, Any, Tuple
from collections import defaultdict
import uuid

from .risk_assessor import RiskAssessor


class PatternAnalyzer:
    """Analyzes patterns in security events."""

    def __init__(self, attack_analyzer, risk_assessor: RiskAssessor):
        """Initialize pattern analyzer."""
        self.attack_analyzer = attack_analyzer
        self.risk_assessor = risk_assessor

    def extract_patterns(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extracts attack patterns with enhanced analysis."""
        patterns = []
        event_groups = defaultdict(list)

        # Group events by attack category and source IP
        for event in events:
            attack_category = self.attack_analyzer.categorize_attack(event)
            if attack_category:
                key = (attack_category, event["source_ip"])
                event_groups[key].append(event)

        # Analyze each group for patterns
        for (category, source_ip), group in event_groups.items():
            if len(group) >= 3:  # Minimum events to constitute a pattern
                pattern = self._analyze_event_group(category, source_ip, group)
                if pattern:
                    patterns.append(pattern)

        return patterns

    def _analyze_event_group(
        self, category: str, source_ip: str, group: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Analyze a group of related events to identify patterns."""
        first_event = min(group, key=lambda x: datetime.fromisoformat(x["timestamp"]))
        last_event = max(group, key=lambda x: datetime.fromisoformat(x["timestamp"]))

        # Extract attack details
        attack_details = self.attack_analyzer.extract_attack_details(group[0])

        # Calculate pattern metrics
        severity = self.risk_assessor.assess_pattern_severity(group)
        confidence_score = self._calculate_confidence_score(group)
        impact_score = self.risk_assessor.calculate_impact_score(
            severity, len(group), confidence_score
        )

        # Analyze affected resources
        affected_ports = self._extract_affected_ports(group)
        protocol_dist = self._analyze_protocol_distribution(group)

        return {
            "pattern_id": f"PTN-{uuid.uuid4().hex[:8]}",
            "source_ips": [source_ip],
            "geographic_data": {
                "country": group[0].get("country_code"),
                "continent": group[0].get("continent_code"),
            },
            "frequency": len(group),
            "attack_type": category,
            "severity": severity,
            "confidence_score": confidence_score,
            "impact_score": impact_score,
            "first_seen": first_event["timestamp"],
            "last_seen": last_event["timestamp"],
            "affected_ports": affected_ports,
            "protocol_distribution": dict(protocol_dist),
            "attack_details": attack_details,
            "tactics": self.attack_analyzer.determine_tactics(category, attack_details),
            "techniques": self.attack_analyzer.determine_techniques(category, attack_details),
            "affected_systems": list(set(e["destination_ip"] for e in group)),
        }

    def _calculate_confidence_score(self, events: List[Dict[str, Any]]) -> float:
        """Calculate confidence score for a pattern."""
        if not events:
            return 0.0

        # Calculate time-based metrics
        timestamps = [datetime.fromisoformat(e["timestamp"]) for e in events]
        time_span = (max(timestamps) - min(timestamps)).total_seconds() / 3600  # hours

        frequency = len(events)
        if time_span > 0:
            events_per_hour = frequency / time_span
            time_based_confidence = min(events_per_hour / 10, 1.0)
        else:
            time_based_confidence = 1.0 if frequency > 5 else 0.7

        # Calculate consistency metrics
        severity_values = [e["alert"]["severity"] for e in events]
        severity_consistency = 1.0 if len(set(severity_values)) == 1 else 0.7

        # Calculate targeting consistency
        destinations = set(e["destination_ip"] for e in events)
        targeting_consistency = (
            1.0 if len(destinations) == 1 else (0.8 if len(destinations) <= 3 else 0.6)
        )

        # Weight and combine factors
        weights = {
            "time_based": 0.4,
            "severity": 0.3,
            "targeting": 0.3,
        }

        confidence_score = (
            time_based_confidence * weights["time_based"]
            + severity_consistency * weights["severity"]
            + targeting_consistency * weights["targeting"]
        )

        return confidence_score

    def _extract_affected_ports(self, events: List[Dict[str, Any]]) -> List[int]:
        """Extract unique affected ports from events."""
        return list(
            set(int(e.get("destination_port", 0)) for e in events if e.get("destination_port"))
        )

    def _analyze_protocol_distribution(self, events: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze protocol distribution in events."""
        protocol_dist = defaultdict(int)
        for event in events:
            protocol_dist[event["protocol"]] += 1
        return dict(protocol_dist)

    def _analyze_temporal_pattern(self, events: List[Dict[str, Any]]) -> Tuple[float, str]:
        """Analyze temporal patterns in events."""
        timestamps = [datetime.fromisoformat(e["timestamp"]) for e in events]
        time_diffs = [
            (timestamps[i + 1] - timestamps[i]).total_seconds() for i in range(len(timestamps) - 1)
        ]

        if not time_diffs:
            return 0.0, "single_occurrence"

        avg_diff = sum(time_diffs) / len(time_diffs)
        std_dev = (sum((x - avg_diff) ** 2 for x in time_diffs) / len(time_diffs)) ** 0.5

        if std_dev < avg_diff * 0.1:
            return avg_diff, "periodic"
        elif std_dev < avg_diff * 0.5:
            return avg_diff, "semi_periodic"
        else:
            return avg_diff, "irregular"
