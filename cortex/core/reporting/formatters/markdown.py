"""Markdown formatter for security reports.

This module is part of CoreSight, a lightweight and transparent micro-framework for orchestrating
LLM-based agents. CoreSight was created by Petru Arakiss (petruarakiss@gmail.com) and is used
under private license.

This is a forked version specifically modified for the Cortex POC project.

This module provides formatting utilities for converting security reports into markdown format,
with support for:
    - Report headers and summaries
    - Risk assessments
    - Attack patterns
    - Anomalies
    - LLM analysis and insights
    - Statistical data
"""

from typing import List, Dict, Any, Union
from ....features.models.models import (
    SecurityReport,
    Pattern,
    Anomaly,
    LLMInsight,
    RiskAssessment,
    Statistics,
    ConsolidatedReport,
)


class MarkdownFormatter:
    """Format security reports in markdown.

    This class provides static methods for formatting different sections of a security
    report into markdown format, maintaining consistent styling and structure.
    """

    @staticmethod
    def format_header(report: SecurityReport) -> List[str]:
        """Format report header section.

        Args:
            report: Security report to format

        Returns:
            List[str]: Formatted header lines
        """
        return [
            "# Security Analysis Report\n",
            f"**Generated at:** {report.summary['analysis_timestamp']}",
            f"**Events Analyzed:** {report.summary['events_analyzed']}",
            f"**Patterns Detected:** {report.summary['patterns_detected']}",
            f"**Anomalies Detected:** {report.summary['anomalies_detected']}\n",
        ]

    @staticmethod
    def format_risk_assessment(risk: RiskAssessment) -> List[str]:
        """Format risk assessment section."""
        lines = [
            "## Risk Assessment\n",
            f"**Overall Risk Level:** {risk.risk_level}",
            f"**Risk Score:** {risk.risk_score:.2f}\n",
            "### Risk Factors\n",
        ]

        for factor, score in risk.risk_factors.items():
            if isinstance(score, (int, float)):
                formatted_score = f"{score:.2f}"
            else:
                formatted_score = str(score)

            lines.append(f"- **{factor.replace('_', ' ').title()}:** {formatted_score}")

        lines.append("")
        return lines

    @staticmethod
    def format_pattern(pattern: Pattern) -> List[str]:
        """Format a single attack pattern."""
        lines = [
            f"### Pattern {pattern.pattern_id}\n",
            f"- **Type:** {pattern.attack_type}",
            f"- **Confidence:** {pattern.confidence_score:.2f}",
            f"- **Source IPs:** {', '.join(pattern.source_ips)}",
            f"- **First Seen:** {pattern.first_seen}",
            f"- **Last Seen:** {pattern.last_seen}",
        ]
        if pattern.affected_ports:
            lines.append(f"- **Affected Ports:** {', '.join(map(str, pattern.affected_ports))}")
        lines.append("")
        return lines

    @staticmethod
    def format_patterns(patterns: List[Pattern]) -> List[str]:
        """Format attack patterns section."""
        if not patterns:
            return []

        lines = ["## Attack Patterns\n"]
        for pattern in patterns:
            lines.extend(MarkdownFormatter.format_pattern(pattern))
        return lines

    @staticmethod
    def format_anomaly(anomaly: Anomaly) -> List[str]:
        """Format a single anomaly."""
        return [
            f"### Alert {anomaly.alert_id}\n",
            f"- **Type:** {anomaly.alert_type}",
            f"- **Severity:** {anomaly.severity}",
            f"- **Recommendation:** {anomaly.recommendation}",
            f"- **Requires Immediate Action:** {'Yes' if anomaly.requires_immediate_action else 'No'}",
            "",
        ]

    @staticmethod
    def format_anomalies(anomalies: List[Anomaly]) -> List[str]:
        """Format anomalies section."""
        if not anomalies:
            return []

        lines = ["## Detected Anomalies\n"]
        for anomaly in anomalies:
            lines.extend(MarkdownFormatter.format_anomaly(anomaly))
        return lines

    @staticmethod
    def format_llm_analysis(llm_analysis: Dict[str, Any]) -> List[str]:
        """Format LLM analysis section."""
        if not llm_analysis or "raw_response" not in llm_analysis:
            return []

        lines = ["## AI Analysis\n"]

        raw_response = llm_analysis["raw_response"]
        if isinstance(raw_response, dict):
            raw_response = str(raw_response)

        content = raw_response.replace("\\n", "\n").replace('\\"', '"')

        if "### " in content:
            sections = content.split("### ")
            sections = [s.strip() for s in sections if s.strip()]

            for section in sections:
                if section:
                    lines.extend([f"### {section}\n"])
        else:
            lines.extend([content, ""])

        if "recommendations" in llm_analysis and llm_analysis["recommendations"]:
            lines.extend(["\n### Recommendations\n"])
            for rec in llm_analysis["recommendations"]:
                lines.extend(
                    [
                        f"#### {rec['finding']}\n",
                        f"**Priority:** {rec['priority']}",
                        f"**Type:** {rec['type']}",
                        f"**Action:** {rec['action']}\n",
                        "**Details:**",
                    ]
                )
                for key, value in rec.get("details", {}).items():
                    lines.append(f"- {key}: {value}")
                lines.append("")

        return lines

    @staticmethod
    def format_statistics(stats: Statistics) -> List[str]:
        """Format statistics section."""
        lines = [
            "## Event Statistics\n",
            f"- **Total Events:** {stats.event_count}",
            f"- **Unique Sources:** {stats.unique_sources}",
            f"- **Unique Destinations:** {stats.unique_destinations}\n",
        ]

        if stats.protocols:
            lines.extend(
                [
                    "### Protocol Distribution\n",
                    *[f"- {protocol}: {count}" for protocol, count in stats.protocols.items()],
                    "",
                ]
            )

        if stats.event_types:
            lines.extend(
                [
                    "### Event Type Distribution\n",
                    *[
                        f"- {event_type}: {count}"
                        for event_type, count in stats.event_types.items()
                    ],
                    "",
                ]
            )

        if stats.severity_distribution:
            lines.extend(
                [
                    "### Severity Distribution\n",
                    *[
                        f"- Level {severity}: {count}"
                        for severity, count in stats.severity_distribution.items()
                    ],
                    "",
                ]
            )

        if stats.geographic_distribution.get("countries"):
            lines.extend(
                [
                    "### Geographic Distribution\n",
                    *[
                        f"- {country}: {count}"
                        for country, count in stats.geographic_distribution["countries"].items()
                    ],
                    "",
                ]
            )

        return lines

    @staticmethod
    def format_llm_insights(insights: List[LLMInsight]) -> List[str]:
        """Format LLM insights section for consolidated report."""
        if not insights:
            return []

        lines = ["## AI Analysis Timeline\n"]
        for insight in insights:
            lines.extend(
                [
                    f"### Analysis at {insight.timestamp}\n",
                    insight.analysis,
                    "",
                ]
            )
        return lines

    @classmethod
    def format_report(cls, report: Union[SecurityReport, ConsolidatedReport]) -> str:
        """Format security report as markdown."""
        lines = []

        lines.extend(cls.format_header(report))

        lines.extend(cls.format_risk_assessment(report.risk_assessment))

        if report.patterns:
            lines.extend(cls.format_patterns(report.patterns))

        if report.anomalies:
            lines.extend(cls.format_anomalies(report.anomalies))

        lines.extend(cls.format_statistics(report.statistics))

        if isinstance(report, SecurityReport) and report.llm_analysis:
            lines.extend(cls.format_llm_analysis(report.llm_analysis))
        elif isinstance(report, ConsolidatedReport) and report.llm_insights:
            lines.extend(cls._format_llm_insights(report.llm_insights))

        return "\n".join(lines)

    @staticmethod
    def _format_llm_insights(llm_insights: List[LLMInsight]) -> List[str]:
        """Format LLM insights section."""
        if not llm_insights:
            return []

        lines = ["## AI Analysis Timeline\n"]

        for insight in llm_insights:
            lines.extend(
                [f"### Analysis from {insight.timestamp.isoformat()}", insight.analysis, ""]
            )

        return lines
