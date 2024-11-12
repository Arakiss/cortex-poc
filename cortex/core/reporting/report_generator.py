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
from collections import defaultdict

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
    """Safely extract content from LLM response."""
    if not llm_response:
        return "No analysis available"

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
    """Format recommendations into a markdown string."""
    formatted_recs = ["## Actionable Recommendations\n"]
    for rec in recommendations:
        formatted_recs.extend(
            [
                f"### {rec['finding']}\n",
                f"**Priority:** {rec['priority']}",
                f"**Type:** {rec['type']}",
                f"**Required Action:** {rec['action']}\n",
                "**Implementation Steps:**",
            ]
        )
        for step in rec.get("steps", []):
            formatted_recs.append(f"1. {step}")
        formatted_recs.append("\n**Technical Details:**")
        for key, value in rec.get("details", {}).items():
            formatted_recs.append(f"- {key}: {value}")
        formatted_recs.append("\n**Expected Impact:**")
        formatted_recs.append(f"- {rec.get('impact', 'No impact information provided')}\n")
    return "\n".join(formatted_recs)


class ReportGenerator:
    """Generate and manage security analysis reports."""

    def __init__(self, reports_dir: Path):
        """Initialize report generator."""
        self.reports_dir = reports_dir
        self.reports_dir.mkdir(exist_ok=True)
        self.rule_generator = RuleGenerator(reports_dir)

    def analyze_attack_patterns(self, patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze attack patterns to identify trends and severity."""
        if not patterns:
            return {}

        analysis = {
            "attack_types": defaultdict(int),
            "affected_systems": defaultdict(set),
            "temporal_progression": defaultdict(int),
            "severity_distribution": defaultdict(int),
            "most_targeted_ports": defaultdict(int),
        }

        for pattern in patterns:
            analysis["attack_types"][pattern["attack_type"]] += 1
            for ip in pattern.get("source_ips", []):
                analysis["affected_systems"][pattern["attack_type"]].add(ip)
            for port in pattern.get("affected_ports", []):
                analysis["most_targeted_ports"][port] += 1

        return {
            "primary_attack_vectors": dict(analysis["attack_types"]),
            "affected_systems": {k: len(v) for k, v in analysis["affected_systems"].items()},
            "most_targeted_ports": dict(
                sorted(analysis["most_targeted_ports"].items(), key=lambda x: x[1], reverse=True)[
                    :5
                ]
            ),
        }

    def calculate_risk_score(self, batch_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate detailed risk assessment based on multiple factors."""
        risk_factors = defaultdict(float)

        # Analyze anomalies
        if batch_results.get("anomalies"):
            anomaly_severity = sum(a.get("severity", 0) for a in batch_results["anomalies"])
            risk_factors["anomaly_risk"] = min(
                anomaly_severity / (len(batch_results["anomalies"]) * 5), 1.0
            )

        # Analyze attack patterns
        if batch_results.get("patterns"):
            pattern_risk = sum(p.get("confidence_score", 0) for p in batch_results["patterns"])
            risk_factors["pattern_risk"] = min(pattern_risk / len(batch_results["patterns"]), 1.0)

        # Calculate statistics-based risk
        stats = batch_results.get("batch_statistics", {})
        if stats:
            # Assess unique sources vs destinations ratio
            src_dst_ratio = stats.get("unique_sources", 0) / max(
                stats.get("unique_destinations", 1), 1
            )
            risk_factors["source_destination_ratio"] = min(src_dst_ratio / 10, 1.0)

        # Calculate final risk score
        risk_score = sum(risk_factors.values()) / max(len(risk_factors), 1)

        return {
            "risk_level": "HIGH" if risk_score > 0.7 else "MEDIUM" if risk_score > 0.3 else "LOW",
            "risk_score": risk_score,
            "risk_factors": dict(risk_factors),
        }

    def create_batch_report(self, batch_results: Dict[str, Any]) -> SecurityReport:
        """Create a report from batch analysis results with enhanced analysis."""
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

        if "geographic_distribution" in filtered_statistics:
            geo_dist = filtered_statistics["geographic_distribution"]
            if "countries" in geo_dist:
                geo_dist["countries"] = {
                    str(k): v for k, v in geo_dist["countries"].items() if k is not None
                }
            if "continents" in geo_dist:
                geo_dist["continents"] = {
                    str(k): v for k, v in geo_dist["continents"].items() if k is not None
                }

        if "temporal_distribution" in filtered_statistics:
            filtered_statistics["temporal_distribution"] = {
                str(k): v for k, v in filtered_statistics["temporal_distribution"].items()
            }

        timestamp = batch_results.get("timestamp", datetime.now())
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                logger.warning(f"Could not parse timestamp: {timestamp}, using current time")
                timestamp = datetime.now()

        try:
            report = SecurityReport(
                summary={
                    "events_analyzed": batch_results["events_analyzed"],
                    "patterns_detected": len(batch_results["patterns"]),
                    "anomalies_detected": len(batch_results["anomalies"]),
                    "analysis_timestamp": timestamp.isoformat(),
                },
                risk_assessment=RiskAssessment(
                    risk_level=batch_results.get("risk_level", "UNKNOWN"),
                    risk_score=batch_results.get("risk_score", 0.0),
                    risk_factors=batch_results.get("risk_factors", {}),
                ),
                patterns=[Pattern(**p) for p in batch_results["patterns"]],
                anomalies=[Anomaly(**a) for a in batch_results["anomalies"]],
                statistics=Statistics(**filtered_statistics),
                llm_analysis=batch_results.get("llm_analysis"),
            )
        except Exception as e:
            logger.error(f"Error creating SecurityReport: {str(e)}")
            raise

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
        """Create a consolidated report with enhanced analysis."""
        if not batch_reports:
            raise ValueError("No batch reports provided for consolidation")

        # Enhanced statistics aggregation
        total_events = sum(r.summary["events_analyzed"] for r in batch_reports)
        total_patterns = sum(r.summary["patterns_detected"] for r in batch_reports)
        total_anomalies = sum(r.summary["anomalies_detected"] for r in batch_reports)

        # Track attack progression
        attack_progression = defaultdict(lambda: {"count": 0, "severity": 0, "timestamps": []})
        for report in batch_reports:
            timestamp = datetime.fromisoformat(report.summary["analysis_timestamp"])
            for pattern in report.patterns:
                attack_progression[pattern.attack_type]["count"] += 1
                attack_progression[pattern.attack_type]["timestamps"].append(timestamp)

        # Analyze temporal patterns
        temporal_analysis = {
            attack_type: {
                "total_occurrences": data["count"],
                "first_seen": min(data["timestamps"]).isoformat(),
                "last_seen": max(data["timestamps"]).isoformat(),
                "duration_hours": (
                    max(data["timestamps"]) - min(data["timestamps"])
                ).total_seconds()
                / 3600,
            }
            for attack_type, data in attack_progression.items()
        }

        # Enhanced risk assessment
        risk_scores = [r.risk_assessment.risk_score for r in batch_reports]
        avg_risk_score = sum(risk_scores) / len(risk_scores)
        risk_trend = (
            "INCREASING"
            if risk_scores[-1] > risk_scores[0]
            else "DECREASING"
            if risk_scores[-1] < risk_scores[0]
            else "STABLE"
        )

        # Create consolidated report with enhanced analysis
        consolidated = ConsolidatedReport(
            summary={
                "analysis_timestamp": datetime.now().isoformat(),
                "events_analyzed": total_events,
                "patterns_detected": total_patterns,
                "anomalies_detected": total_anomalies,
                "attack_progression": dict(temporal_analysis),
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
                risk_factors={
                    "risk_trend": risk_trend,
                    "peak_risk_score": max(risk_scores),
                    "risk_volatility": max(risk_scores) - min(risk_scores),
                    "sustained_high_risk": sum(1 for score in risk_scores if score > 0.7)
                    / len(risk_scores),
                },
            ),
            patterns=[p for r in batch_reports for p in r.patterns],
            anomalies=[a for r in batch_reports for a in r.anomalies],
            statistics=Statistics(
                event_count=total_events,
                unique_sources=sum(r.statistics.unique_sources for r in batch_reports),
                unique_destinations=sum(r.statistics.unique_destinations for r in batch_reports),
                temporal_distribution=temporal_analysis,
            ),
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
