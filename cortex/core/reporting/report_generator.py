"""Report generator for security analysis.

This module is part of CoreSight, a lightweight and transparent micro-framework for orchestrating
LLM-based agents. CoreSight was created by Petru Arakiss (petruarakiss@gmail.com) and is used
under private license.

This is a forked version specifically modified for the Cortex POC project.

This module handles the generation and management of security analysis reports, including:
    - Batch report creation and formatting
    - Consolidated report generation
    - Multi-format report saving (JSON, Markdown)
    - LLM analysis integration
    - Security rules generation
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
import json
import logging

from ...features.models.models import (
    SecurityReport,
    ConsolidatedReport,
    RiskAssessment,
    Pattern,
    Anomaly,
    Statistics,
    LLMInsight,
)
from .formatters.markdown import MarkdownFormatter
from .rule_generator import RuleGenerator

logger = logging.getLogger(__name__)


def extract_llm_content(llm_response: Dict[str, Any]) -> str:
    """Safely extract content from LLM response.

    Args:
        llm_response: Dictionary containing LLM analysis results

    Returns:
        str: Formatted content string or default message if no content found
    """
    if not llm_response:
        return "No analysis available"

    # Try different possible structures
    if isinstance(llm_response, dict):
        if "raw_response" in llm_response:
            if isinstance(llm_response["raw_response"], str):
                return llm_response["raw_response"]
            if isinstance(llm_response["raw_response"], dict):
                return llm_response["raw_response"].get("content", "No content available")

        if "recommendations" in llm_response:
            recommendations = llm_response["recommendations"]
            if isinstance(recommendations, list):
                return format_recommendations(recommendations)

    return "No analysis content found"


def format_recommendations(recommendations: List[Dict[str, Any]]) -> str:
    """Format recommendations into a markdown string.

    Args:
        recommendations: List of recommendation dictionaries

    Returns:
        str: Formatted markdown string
    """
    formatted_recs = ["## Recommendations\n"]
    for rec in recommendations:
        formatted_recs.extend(
            [
                f"### {rec['finding']}\n",
                f"**Priority:** {rec['priority']}",
                f"**Type:** {rec['type']}",
                f"**Action:** {rec['action']}\n",
                "**Details:**",
            ]
        )
        for key, value in rec.get("details", {}).items():
            formatted_recs.append(f"- {key}: {value}")
        formatted_recs.append("")
    return "\n".join(formatted_recs)


class ReportGenerator:
    """Generate and manage security analysis reports.

    This class handles the creation, formatting and saving of security reports
    in multiple formats, including batch and consolidated reports.

    Attributes:
        reports_dir: Directory path where reports will be saved
    """

    def __init__(self, reports_dir: Path):
        """Initialize report generator.

        Args:
            reports_dir: Path to directory for saving reports
        """
        self.reports_dir = reports_dir
        self.reports_dir.mkdir(exist_ok=True)
        self.rule_generator = RuleGenerator(reports_dir)

    def create_batch_report(self, batch_results: Dict[str, Any]) -> SecurityReport:
        """Create a report from batch analysis results."""
        # Filter statistics to only include defined fields
        valid_statistic_fields = {
            "event_count",
            "unique_sources",
            "unique_destinations",
            "protocols",
            "event_types",
            "severity_distribution",
            "geographic_distribution",
            "temporal_distribution",
        }

        filtered_statistics = {
            k: v
            for k, v in batch_results["batch_statistics"].items()
            if k in valid_statistic_fields
        }

        # Create report data structure
        report = SecurityReport(
            summary={
                "events_analyzed": batch_results["events_analyzed"],
                "patterns_detected": len(batch_results["patterns"]),
                "anomalies_detected": len(batch_results["anomalies"]),
                "analysis_timestamp": batch_results["timestamp"].isoformat(),
            },
            risk_assessment=RiskAssessment(
                risk_level=batch_results["risk_assessment"]["risk_level"],
                risk_score=batch_results["risk_assessment"]["risk_score"],
                risk_factors=batch_results["risk_assessment"]["risk_factors"],
            ),
            patterns=[Pattern(**p) for p in batch_results["patterns"]],
            anomalies=[Anomaly(**a) for a in batch_results["anomalies"]],
            statistics=Statistics(**filtered_statistics),
            llm_analysis=batch_results.get("llm_analysis"),
        )

        return report

    def save_batch_report(
        self, report: SecurityReport, timestamp: str
    ) -> tuple[Path, Path, Optional[Path]]:
        """Save batch report in multiple formats."""
        # Save JSON report
        json_path = self.reports_dir / f"security_report_{timestamp}.json"
        with open(json_path, "w") as f:
            json.dump(
                {
                    "summary": report.summary,
                    "risk_assessment": {
                        "risk_level": report.risk_assessment.risk_level,
                        "risk_score": report.risk_assessment.risk_score,
                        "risk_factors": report.risk_assessment.risk_factors,
                    },
                    "patterns": [vars(p) for p in report.patterns],
                    "anomalies": [vars(a) for a in report.anomalies],
                    "statistics": vars(report.statistics),
                    "llm_analysis": report.llm_analysis,
                },
                f,
                indent=2,
                default=str,
            )
        logger.info(f"JSON report saved to {json_path}")

        # Generate and save markdown report
        markdown = MarkdownFormatter.format_report(report)
        md_path = self.reports_dir / f"security_report_{timestamp}.md"
        with open(md_path, "w") as f:
            f.write(markdown)
        logger.info(f"Markdown report saved to {md_path}")

        # Save raw LLM response if available
        llm_path = None
        if report.llm_analysis:
            llm_path = self.reports_dir / f"llm_response_{timestamp}.md"
            with open(llm_path, "w") as f:
                f.write("# LLM Security Analysis\n\n")
                f.write(extract_llm_content(report.llm_analysis))
            logger.info(f"LLM response saved to {llm_path}")

        # Generate security rules
        self.rule_generator.generate_rules(report, timestamp)

        return json_path, md_path, llm_path

    def create_consolidated_report(self, batch_reports: List[SecurityReport]) -> ConsolidatedReport:
        """Create a consolidated report from multiple batch reports."""
        if not batch_reports:
            raise ValueError("No batch reports provided for consolidation")

        # Calculate consolidated statistics
        total_events = sum(r.summary["events_analyzed"] for r in batch_reports)
        total_patterns = sum(r.summary["patterns_detected"] for r in batch_reports)
        total_anomalies = sum(r.summary["anomalies_detected"] for r in batch_reports)

        # Combine statistics
        consolidated_stats = Statistics(
            event_count=total_events,
            unique_sources=sum(r.statistics.unique_sources for r in batch_reports),
            unique_destinations=sum(r.statistics.unique_destinations for r in batch_reports),
        )

        # Combine all patterns and anomalies
        all_patterns = []
        all_anomalies = []
        for report in batch_reports:
            all_patterns.extend(report.patterns)
            all_anomalies.extend(report.anomalies)

        # Calculate overall risk score
        risk_scores = [r.risk_assessment.risk_score for r in batch_reports]
        avg_risk_score = sum(risk_scores) / len(risk_scores)

        # Create consolidated report
        consolidated = ConsolidatedReport(
            summary={
                "analysis_timestamp": datetime.now().isoformat(),
                "events_analyzed": total_events,
                "patterns_detected": total_patterns,
                "anomalies_detected": total_anomalies,
            },
            analysis_period={
                "start": datetime.fromisoformat(batch_reports[0].summary["analysis_timestamp"]),
                "end": datetime.fromisoformat(batch_reports[-1].summary["analysis_timestamp"]),
            },
            total_events_analyzed=total_events,
            total_patterns_detected=total_patterns,
            total_anomalies_detected=total_anomalies,
            risk_assessment=RiskAssessment(
                risk_level="HIGH"
                if avg_risk_score > 0.7
                else "MEDIUM"
                if avg_risk_score > 0.3
                else "LOW",
                risk_score=avg_risk_score,
                risk_factors={},  # This would need a more sophisticated combination logic
            ),
            patterns=all_patterns,
            anomalies=all_anomalies,
            statistics=consolidated_stats,
            llm_insights=[
                LLMInsight(
                    timestamp=datetime.fromisoformat(r.summary["analysis_timestamp"]),
                    analysis=extract_llm_content(r.llm_analysis),
                )
                for r in batch_reports
                if r.llm_analysis
            ],
        )

        return consolidated

    def save_consolidated_report(self, report: ConsolidatedReport) -> tuple[Path, Path]:
        """Save consolidated report in multiple formats."""
        # Save JSON report
        json_path = self.reports_dir / "final_security_report.json"
        with open(json_path, "w") as f:
            json.dump(
                {
                    "summary": report.summary,
                    "analysis_period": {
                        "start": report.analysis_period["start"].isoformat(),
                        "end": report.analysis_period["end"].isoformat(),
                    },
                    "total_events_analyzed": report.total_events_analyzed,
                    "total_patterns_detected": report.total_patterns_detected,
                    "total_anomalies_detected": report.total_anomalies_detected,
                    "risk_assessment": {
                        "risk_level": report.risk_assessment.risk_level,
                        "risk_score": report.risk_assessment.risk_score,
                        "risk_factors": report.risk_assessment.risk_factors,
                    },
                    "patterns": [vars(p) for p in report.patterns],
                    "anomalies": [vars(a) for a in report.anomalies],
                    "statistics": vars(report.statistics),
                    "llm_insights": [
                        {
                            "timestamp": insight.timestamp.isoformat(),
                            "analysis": insight.analysis,
                        }
                        for insight in report.llm_insights
                    ]
                    if report.llm_insights
                    else [],
                },
                f,
                indent=2,
                default=str,
            )
        logger.info(f"Final JSON report saved to {json_path}")

        # Generate and save markdown report
        markdown = MarkdownFormatter.format_report(report)
        md_path = self.reports_dir / "final_security_report.md"
        with open(md_path, "w") as f:
            f.write(markdown)
        logger.info(f"Final markdown report saved to {md_path}")

        # Generate consolidated security rules
        self.rule_generator.generate_consolidated_rules(report)

        return json_path, md_path
