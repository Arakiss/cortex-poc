"""Risk assessment for security events."""

from datetime import datetime
from typing import Dict, List, Any
from collections import defaultdict

from cortex.features.models.security import AnomalyAlert


class RiskAssessor:
    """Assesses security risks based on patterns and anomalies."""

    @staticmethod
    def assess_overall_risk(
        patterns: List[Dict[str, Any]],
        anomalies: List[AnomalyAlert],
        statistics: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Evaluates the overall risk level based on all analyzed data."""
        risk_factors = defaultdict(float)

        # Evaluate pattern risk
        if patterns:
            # Consider both quantity and confidence of patterns
            high_confidence_patterns = len([p for p in patterns if p["confidence_score"] > 0.7])
            pattern_severity = sum(p.get("severity", 0) for p in patterns) / len(patterns)
            risk_factors["pattern_risk"] = min(
                (high_confidence_patterns * pattern_severity) / 25, 1.0
            )

            # Analyze attack diversity
            attack_types = set(p["attack_type"] for p in patterns)
            risk_factors["attack_diversity"] = min(len(attack_types) / 5, 1.0)

            # Analyze geographic spread
            unique_countries = set()
            for pattern in patterns:
                if "geographic_data" in pattern and "country" in pattern["geographic_data"]:
                    unique_countries.add(pattern["geographic_data"]["country"])
            risk_factors["geographic_spread"] = min(len(unique_countries) / 10, 1.0)

        # Evaluate anomaly risk
        if anomalies:
            critical_anomalies = len([a for a in anomalies if a.requires_immediate_action])
            severity_score = sum(a.severity for a in anomalies) / (len(anomalies) * 5)
            risk_factors["anomaly_risk"] = min((critical_anomalies * severity_score) / 2, 1.0)

            # Analyze temporal concentration
            timestamps = [datetime.fromisoformat(a.timestamp.isoformat()) for a in anomalies]
            if len(timestamps) > 1:
                time_diffs = [
                    (timestamps[i + 1] - timestamps[i]).total_seconds()
                    for i in range(len(timestamps) - 1)
                ]
                avg_time_diff = sum(time_diffs) / len(time_diffs)
                risk_factors["temporal_concentration"] = min(3600 / max(avg_time_diff, 1), 1.0)

        # Evaluate protocol risk
        protocol_dist = statistics.get("protocols", {})
        if protocol_dist:
            vulnerable_protocols = len(
                [p for p in protocol_dist.keys() if p.lower() in ["telnet", "ftp", "http"]]
            )
            risk_factors["protocol_risk"] = min(vulnerable_protocols / 3, 1.0)

        # Calculate weighted risk score
        weights = {
            "pattern_risk": 0.3,
            "anomaly_risk": 0.3,
            "attack_diversity": 0.15,
            "geographic_spread": 0.1,
            "protocol_risk": 0.1,
            "temporal_concentration": 0.05,
        }

        risk_score = sum(
            risk_factors[factor] * weight
            for factor, weight in weights.items()
            if factor in risk_factors
        )

        # Determine risk level with context
        risk_level = (
            "CRITICAL"
            if risk_score > 0.8
            or (risk_factors["anomaly_risk"] > 0.8 and risk_factors["pattern_risk"] > 0.6)
            else "HIGH"
            if risk_score > 0.6 or risk_factors["pattern_risk"] > 0.7
            else "MEDIUM"
            if risk_score > 0.3 or risk_factors["anomaly_risk"] > 0.5
            else "LOW"
        )

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_factors": dict(risk_factors),
            "assessment_timestamp": datetime.now().isoformat(),
        }

    @staticmethod
    def calculate_impact_score(severity: float, frequency: int, confidence: float) -> float:
        """Calculate impact score based on multiple factors."""
        impact_factors = {
            "severity": severity / 5.0,
            "frequency": min(frequency / 20, 1.0),
            "confidence": confidence,
        }
        return sum(impact_factors.values()) / len(impact_factors)

    @staticmethod
    def assess_pattern_severity(events: List[Dict[str, Any]]) -> float:
        """Calculate severity score for a pattern of events."""
        if not events:
            return 0.0
        return sum(e["alert"]["severity"] for e in events) / len(events)

    @staticmethod
    def assess_protocol_risk(protocol: str) -> float:
        """Assess risk level for a specific protocol."""
        high_risk_protocols = {"telnet": 1.0, "ftp": 0.8, "http": 0.6}
        medium_risk_protocols = {"smtp": 0.4, "dns": 0.3}
        return high_risk_protocols.get(
            protocol.lower(), medium_risk_protocols.get(protocol.lower(), 0.1)
        )
