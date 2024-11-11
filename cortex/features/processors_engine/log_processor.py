# Standard library imports
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import logging
from datetime import datetime, timedelta

# Third-party imports
import polars as pl
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
)
from rich.console import Console


class LogProcessor:
    """Processes large log files efficiently using chunking and aggregation."""

    def __init__(self, logs_dir: Path, chunk_size: int = 1000):
        self.logs_dir = logs_dir
        self.chunk_size = chunk_size
        self.logger = logging.getLogger(__name__)
        self.console = Console()
        self.input_files: List[Path] = []

        # Common schema for all logs
        self.common_schema = {
            "timestamp": pl.Datetime,
            "source_ip": pl.Utf8,
            "destination_ip": pl.Utf8,
            "protocol": pl.Utf8,
            "event_type": pl.Utf8,
            "severity": pl.Int32,
            "connection_count": pl.Int32,
        }

        # Initialization of other attributes...
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.current_df: Optional[pl.DataFrame] = None
        self.original_df: Optional[pl.DataFrame] = None
        self.stats = self._init_stats()

    def _init_stats(self) -> Dict[str, Any]:
        """Initialize statistics dictionary."""
        return {
            "total_events": 0,
            "processed_files": 0,
            "processing_time": 0.0,
            "event_types": {},
            "severity_distribution": {},
            "patterns_detected": 0,
            "performance_metrics": {
                "events_per_second": 0.0,
                "avg_batch_time": 0.0,
                "memory_usage": 0,
            },
            "data_summary": {
                "date_range": {"start": None, "end": None},
                "unique_sources": 0,
                "unique_destinations": 0,
                "total_records": 0,
            },
        }

    def _normalize_eve_log(self, df: pl.DataFrame) -> pl.DataFrame:
        """Normalize Suricata EVE log format."""
        # Extract severity from alert.severity
        df = df.with_columns(
            [
                pl.col("alert").struct.field("severity").alias("severity"),
                pl.col("src_ip").alias("source_ip"),
                pl.col("proto").alias("protocol"),
                pl.lit(0).cast(pl.Int32).alias("connection_count"),
            ]
        )

        return df

    def _normalize_clamav_log(self, df: pl.DataFrame) -> pl.DataFrame:
        """Normalize ClamAV log format."""
        # Add connection_count with default value 0
        df = df.with_columns([pl.lit(0).cast(pl.Int32).alias("connection_count")])

        return df

    def _load_single_file(self, file_path: Path) -> Optional[pl.DataFrame]:
        """Load and normalize a single log file."""
        try:
            self.logger.debug(f"Loading file: {file_path}")

            # Check if file exists and has content
            if not file_path.exists():
                self.logger.warning(f"File does not exist: {file_path}")
                return self._create_empty_dataframe()

            if file_path.stat().st_size == 0:
                self.logger.warning(f"File is empty: {file_path}")
                return self._create_empty_dataframe()

            try:
                # Load the file as a DataFrame
                df = pl.scan_ndjson(file_path).collect()

                # Normalize based on log type
                if "alert" in df.columns:  # EVE log
                    df = self._normalize_eve_log(df)
                else:  # ClamAV log
                    df = self._normalize_clamav_log(df)

                # Select and cast columns according to common schema
                normalized_columns = []
                for col_name, col_type in self.common_schema.items():
                    if col_name in df.columns:
                        normalized_columns.append(
                            pl.col(col_name)
                            .cast(col_type)
                            .fill_null(0 if col_type in [pl.Int32, pl.Float64] else "")
                        )
                    else:
                        normalized_columns.append(
                            pl.lit(0 if col_type in [pl.Int32, pl.Float64] else "")
                            .cast(col_type)
                            .alias(col_name)
                        )

                return df.with_columns(normalized_columns).select(list(self.common_schema.keys()))

            except pl.exceptions.NoDataError:
                self.logger.warning(f"No valid data in file: {file_path}")
                return self._create_empty_dataframe()

        except Exception as e:
            self.logger.error(f"Error processing {file_path}: {str(e)}")
            return self._create_empty_dataframe()

    def _create_empty_dataframe(self) -> pl.DataFrame:
        """Create an empty DataFrame with the correct schema."""
        return pl.DataFrame(
            schema={
                "timestamp": pl.Datetime,
                "severity": pl.Int32,
                "connection_count": pl.Int32,
                "source_ip": pl.Utf8,
                "destination_ip": pl.Utf8,
                "protocol": pl.Utf8,
                "event_type": pl.Utf8,
            }
        )

    def load_logs(self) -> bool:
        """Load all log files into memory with progress tracking."""
        try:
            self.start_time = datetime.now()

            # Use input_files if set, else use all .jsonl files
            log_files = (
                self.input_files if self.input_files else list(self.logs_dir.glob("*.jsonl"))
            )

            if not log_files:
                self.logger.error("No .jsonl files found to process")
                return False

            dfs = []
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeRemainingColumn(),
                console=self.console,
            ) as progress:
                load_task = progress.add_task("[cyan]Loading log files...", total=len(log_files))

                for log_file in log_files:
                    df = self._load_single_file(log_file)
                    if df is not None:
                        dfs.append(df)
                        self.stats["processed_files"] += 1
                    progress.advance(load_task)

            if not dfs:
                self.current_df = self._create_empty_dataframe()
            else:
                self.current_df = pl.concat(dfs).sort("timestamp")

            self.original_df = self.current_df.clone()
            self._update_stats(self.current_df)
            self._update_performance_metrics()

            return True

        except Exception as e:
            self.logger.error(f"Critical error during log loading: {str(e)}")
            return False

    def _update_stats(self, df: pl.DataFrame):
        """Update processing statistics from DataFrame."""
        if len(df) == 0:
            return

        # Update event types distribution
        event_types = df.group_by("event_type").agg(pl.count()).to_dicts()
        for item in event_types:
            self.stats["event_types"][item["event_type"]] = item["count"]

        # Update severity distribution
        severity_dist = df.group_by("severity").agg(pl.count()).to_dicts()
        for item in severity_dist:
            self.stats["severity_distribution"][item["severity"]] = item["count"]

        # Update data summary
        self.stats["data_summary"].update(
            {
                "date_range": {
                    "start": df["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S")
                    if len(df) > 0
                    else None,
                    "end": df["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S")
                    if len(df) > 0
                    else None,
                },
                "unique_sources": df["source_ip"].n_unique(),
                "unique_destinations": df["destination_ip"].n_unique(),
                "total_records": len(df),
            }
        )

        self.stats["total_events"] = len(df)

    def _update_performance_metrics(self):
        """Update performance metrics."""
        if self.start_time and self.current_df is not None:
            processing_duration = max((datetime.now() - self.start_time).total_seconds(), 0.001)
            self.stats["performance_metrics"].update(
                {
                    "events_per_second": self.stats["total_events"] / processing_duration,
                    "avg_batch_time": processing_duration / max(self.stats["processed_files"], 1),
                    "memory_usage": self.current_df.estimated_size(),
                }
            )

    def filter_by_severity(self, min_severity: int) -> None:
        """Filter events by minimum severity level."""
        if self.current_df is not None:
            self.current_df = self.current_df.filter(pl.col("severity") >= min_severity)
            self._update_stats(self.current_df)

    def filter_by_timerange(self, start: datetime, end: datetime) -> None:
        """Filter events by time range."""
        if self.current_df is not None:
            self.current_df = self.current_df.filter(
                (pl.col("timestamp") >= start) & (pl.col("timestamp") <= end)
            )
            self._update_stats(self.current_df)

    def reset_filters(self) -> None:
        """Reset to original dataset."""
        if self.original_df is not None:
            self.current_df = self.original_df.clone()
            self._update_stats(self.current_df)

    def get_stats(self) -> Dict[str, Any]:
        """Get current processing statistics."""
        self._update_performance_metrics()
        return self.stats.copy()

    def has_more_data(self) -> bool:
        """Check if there are more events to process."""
        return self.current_df is not None and len(self.current_df) > 0

    def get_time_range(self) -> Optional[Tuple[datetime, datetime]]:
        """Get the time range of the current dataset."""
        if self.current_df is None or len(self.current_df) == 0:
            return None

        min_time = self.current_df["timestamp"].min()
        max_time = self.current_df["timestamp"].max()
        return (min_time, max_time)

    def filter_by_relative_time(self, time_window: timedelta) -> None:
        """Filter events within a relative time window from the most recent event.

        Args:
            time_window (timedelta): Time window to keep (e.g., last 24 hours)
        """
        if self.current_df is not None:
            latest_time = self.current_df["timestamp"].max()
            start_time = latest_time - time_window

            self.current_df = self.current_df.filter(pl.col("timestamp") >= start_time)
            self._update_stats(self.current_df)

    def get_batch(self, batch_size: Optional[int] = None) -> Optional[List[Dict[str, Any]]]:
        """Get next batch of events from the current DataFrame."""
        if self.current_df is None or len(self.current_df) == 0:
            return None

        size = batch_size or self.chunk_size
        batch = self.current_df.head(size)
        self.current_df = self.current_df.slice(size, len(self.current_df))

        return batch.to_dicts()

    def set_input_files(self, files: List[Path]) -> None:
        """Set specific input files to process."""
        self.input_files = files
