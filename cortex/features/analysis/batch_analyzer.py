"""Batch analysis functionality for security events."""

import logging
from typing import List, Dict, Any
from pathlib import Path

from cortex.core.llm import OpenAIProvider
from cortex.features.processors_engine import LogProcessor
from cortex.features.security import SecurityAnalysisAgent
from cortex.core.reporting.report_generator import ReportGenerator
from cortex.features.models.models import SecurityReport

logger = logging.getLogger(__name__)


class BatchAnalyzer:
    """Analyze security events in batches."""

    def __init__(
        self,
        log_dir: Path,
        reports_dir: Path,
        batch_size: int = 100,
        llm_provider: OpenAIProvider = None,
    ):
        """Initialize batch analyzer."""
        self.log_dir = log_dir
        self.batch_size = batch_size
        self.llm_provider = llm_provider
        self.agent = SecurityAnalysisAgent(name="SecurityAgent", role="Analyzer")
        self.log_processor = LogProcessor(log_dir, batch_size)
        self.report_generator = ReportGenerator(reports_dir)
        self.batch_reports: List[SecurityReport] = []
        self.input_files: List[Path] = []

    def set_input_files(self, files: List[Path]) -> None:
        """Set specific log files to analyze.

        Args:
            files: List of Path objects pointing to log files
        """
        self.input_files = files
        self.log_processor.input_files = files

    async def process_batches(self) -> bool:
        """Process all events in batches."""
        try:
            # Load and validate logs
            if not self.log_processor.load_logs():
                logger.error("Failed to load logs. Exiting.")
                return False

            # Get total events for tracking
            total_events = self.log_processor.stats["total_events"]
            processed_events = 0

            # Process each batch
            while processed_events < total_events:
                # Get next batch of events
                batch = self.log_processor.current_df[
                    processed_events : processed_events + self.batch_size
                ].to_dicts()

                # Analyze batch
                batch_results = await self.agent.analyze_batch(batch, self.llm_provider)

                # Update progress
                processed_events += len(batch)

                # Generate and save reports if there are findings
                if batch_results["anomalies"] or batch_results["patterns"]:
                    # Create report
                    report = self.report_generator.create_batch_report(batch_results)
                    self.batch_reports.append(report)

                    # Save reports
                    timestamp = report.summary["analysis_timestamp"].replace(":", "-")
                    self.report_generator.save_batch_report(report, timestamp)

            # Generate final consolidated report if we have any findings
            if self.batch_reports:
                consolidated = self.report_generator.create_consolidated_report(self.batch_reports)
                self.report_generator.save_consolidated_report(consolidated)

            return True

        except Exception as e:
            logger.error(f"Error in batch processing: {str(e)}")
            raise

    def get_progress_stats(self) -> Dict[str, Any]:
        """Get current progress statistics."""
        return {
            "total_batches": len(self.batch_reports),
            "total_patterns": sum(len(report.patterns) for report in self.batch_reports),
            "total_anomalies": sum(len(report.anomalies) for report in self.batch_reports),
            "last_analysis": self.batch_reports[-1].summary["analysis_timestamp"]
            if self.batch_reports
            else None,
        }

    def get_batch_reports(self) -> List[SecurityReport]:
        """Get all processed batch reports."""
        return self.batch_reports.copy()
