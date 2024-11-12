"""Statistics calculation for security events."""

from datetime import datetime
from typing import Dict, List, Any
from collections import defaultdict


class StatisticsCalculator:
    """Calculates statistics from security events."""

    @staticmethod
    def calculate_batch_statistics(events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate detailed statistics for a batch of events."""
        stats = {
            "event_count": len(events),
            "unique_sources": len(set(e["source_ip"] for e in events)),
            "unique_destinations": len(set(e["destination_ip"] for e in events)),
            "protocols": defaultdict(int),
            "event_types": defaultdict(int),
            "severity_distribution": defaultdict(int),
            "geographic_distribution": {
                "countries": defaultdict(int),
                "continents": defaultdict(int),
            },
            "temporal_distribution": defaultdict(int),
            "attack_categories": defaultdict(int),
            "attack_success_rates": defaultdict(float),
            "mitigation_effectiveness": defaultdict(float),
        }

        # Process each event
        for event in events:
            stats = StatisticsCalculator._update_protocol_stats(stats, event)
            stats = StatisticsCalculator._update_event_type_stats(stats, event)
            stats = StatisticsCalculator._update_severity_stats(stats, event)
            stats = StatisticsCalculator._update_geographic_stats(stats, event)
            stats = StatisticsCalculator._update_temporal_stats(stats, event)
            stats = StatisticsCalculator._update_attack_stats(stats, event)

        # Convert defaultdicts to regular dicts for serialization
        return StatisticsCalculator._finalize_stats(stats)

    @staticmethod
    def _update_protocol_stats(stats: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        """Update protocol-related statistics."""
        if "protocol" in event:
            stats["protocols"][event["protocol"]] += 1
        return stats

    @staticmethod
    def _update_event_type_stats(stats: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        """Update event type statistics."""
        if "event_type" in event:
            stats["event_types"][event["event_type"]] += 1
        return stats

    @staticmethod
    def _update_severity_stats(stats: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        """Update severity distribution statistics."""
        if "severity" in event:
            stats["severity_distribution"][str(event["severity"])] += 1
        return stats

    @staticmethod
    def _update_geographic_stats(stats: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        """Update geographic distribution statistics."""
        if "country_code" in event:
            stats["geographic_distribution"]["countries"][event["country_code"]] += 1
        if "continent_code" in event:
            stats["geographic_distribution"]["continents"][event["continent_code"]] += 1
        return stats

    @staticmethod
    def _update_temporal_stats(stats: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        """Update temporal distribution statistics."""
        if "timestamp" in event:
            hour = datetime.fromisoformat(event["timestamp"]).hour
            stats["temporal_distribution"][hour] += 1
        return stats

    @staticmethod
    def _update_attack_stats(stats: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        """Update attack-related statistics."""
        if "attack_category" in event:
            stats["attack_categories"][event["attack_category"]] += 1

            # Calculate success rates if available
            if "success" in event:
                category = event["attack_category"]
                current_rate = stats["attack_success_rates"].get(category, 0.0)
                count = stats["attack_categories"][category]
                stats["attack_success_rates"][category] = (
                    current_rate * (count - 1) + float(event["success"])
                ) / count

            # Calculate mitigation effectiveness if available
            if "mitigated" in event:
                category = event["attack_category"]
                current_effectiveness = stats["mitigation_effectiveness"].get(category, 0.0)
                count = stats["attack_categories"][category]
                stats["mitigation_effectiveness"][category] = (
                    current_effectiveness * (count - 1) + float(event["mitigated"])
                ) / count

        return stats

    @staticmethod
    def _finalize_stats(stats: Dict[str, Any]) -> Dict[str, Any]:
        """Convert defaultdicts to regular dicts for serialization."""
        return {
            k: (
                dict(v)
                if isinstance(v, defaultdict)
                else {k2: dict(v2) if isinstance(v2, defaultdict) else v2 for k2, v2 in v.items()}
                if isinstance(v, dict)
                else v
            )
            for k, v in stats.items()
        }

    @staticmethod
    def calculate_trend_statistics(
        current_stats: Dict[str, Any], previous_stats: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate trend statistics comparing current to previous batch."""
        trends = {
            "event_count_change": StatisticsCalculator._calculate_percentage_change(
                current_stats["event_count"], previous_stats["event_count"]
            ),
            "unique_sources_change": StatisticsCalculator._calculate_percentage_change(
                current_stats["unique_sources"], previous_stats["unique_sources"]
            ),
            "severity_trends": StatisticsCalculator._calculate_severity_trends(
                current_stats["severity_distribution"],
                previous_stats["severity_distribution"],
            ),
            "protocol_trends": StatisticsCalculator._calculate_protocol_trends(
                current_stats["protocols"], previous_stats["protocols"]
            ),
            "geographic_trends": StatisticsCalculator._calculate_geographic_trends(
                current_stats["geographic_distribution"],
                previous_stats["geographic_distribution"],
            ),
        }
        return trends

    @staticmethod
    def _calculate_percentage_change(current: float, previous: float) -> float:
        """Calculate percentage change between two values."""
        if previous == 0:
            return 100.0 if current > 0 else 0.0
        return ((current - previous) / previous) * 100

    @staticmethod
    def _calculate_severity_trends(
        current: Dict[str, int], previous: Dict[str, int]
    ) -> Dict[str, float]:
        """Calculate trends in severity distribution."""
        return {
            severity: StatisticsCalculator._calculate_percentage_change(
                current.get(severity, 0), previous.get(severity, 0)
            )
            for severity in set(current.keys()) | set(previous.keys())
        }

    @staticmethod
    def _calculate_protocol_trends(
        current: Dict[str, int], previous: Dict[str, int]
    ) -> Dict[str, float]:
        """Calculate trends in protocol usage."""
        return {
            protocol: StatisticsCalculator._calculate_percentage_change(
                current.get(protocol, 0), previous.get(protocol, 0)
            )
            for protocol in set(current.keys()) | set(previous.keys())
        }

    @staticmethod
    def _calculate_geographic_trends(
        current: Dict[str, Dict[str, int]], previous: Dict[str, Dict[str, int]]
    ) -> Dict[str, Dict[str, float]]:
        """Calculate trends in geographic distribution."""
        trends = {}
        for region_type in ["countries", "continents"]:
            current_region = current.get(region_type, {})
            previous_region = previous.get(region_type, {})
            trends[region_type] = {
                region: StatisticsCalculator._calculate_percentage_change(
                    current_region.get(region, 0), previous_region.get(region, 0)
                )
                for region in set(current_region.keys()) | set(previous_region.keys())
            }
        return trends
