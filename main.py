"""Main application for security analysis."""

import asyncio
import os
from pathlib import Path
import logging
from typing import List, Optional
import click
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from functools import wraps

from cortex.core.llm import OpenAIProvider
from cortex.features.analysis.batch_analyzer import BatchAnalyzer

# Load environment variables and configure logging
load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment variables
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4-mini")
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "100"))
LOG_DIR = Path(os.getenv("LOG_DIR", "logs"))
REPORTS_DIR = Path("reports")

console = Console()


def coro(f):
    """Decorator to handle async click commands."""

    @wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper


@click.command()
@click.option(
    "--files",
    "-f",
    multiple=True,
    help="Specific log files to analyze (e.g., -f eve.jsonl -f clamav.jsonl)",
)
@click.option("--all", "-a", is_flag=True, help="Analyze all .jsonl files in the logs directory")
@coro
async def main(files: Optional[List[str]] = None, all: bool = False):
    """Main function to run security analysis."""
    try:
        # Initialize LLM provider
        llm_provider = OpenAIProvider(api_key=OPENAI_API_KEY)

        # Determine which files to analyze
        log_files = []
        if all:
            log_files = list(LOG_DIR.glob("*.jsonl"))
        elif files:
            log_files = [LOG_DIR / file for file in files if (LOG_DIR / file).exists()]

        if not log_files:
            console.print("[bold red]No log files found to analyze![/bold red]")
            return

        # Initialize batch analyzer
        analyzer = BatchAnalyzer(
            log_dir=LOG_DIR,
            reports_dir=REPORTS_DIR,
            batch_size=BATCH_SIZE,
            llm_provider=llm_provider,
        )

        # Set the files to analyze
        analyzer.set_input_files(log_files)

        console.print("[bold green]Starting security analysis...[/bold green]")
        console.print(f"Analyzing files: {', '.join(f.name for f in log_files)}")

        # Process batches with progress tracking
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        ) as progress:
            analysis_task = progress.add_task("[cyan]Analyzing security events...", total=100)

            # Process all batches
            success = await analyzer.process_batches()

            if success:
                progress.update(analysis_task, completed=100)
                stats = analyzer.get_progress_stats()
                console.print("\n[bold green]Analysis completed successfully![/bold green]")
                console.print(f"\nProcessed {stats['total_batches']} batches")
                console.print(f"Found {stats['total_patterns']} patterns")
                console.print(f"Detected {stats['total_anomalies']} anomalies")
                if stats["last_analysis"]:
                    console.print(f"Last analysis: {stats['last_analysis']}")
            else:
                console.print("\n[bold red]Analysis failed![/bold red]")

    except Exception as e:
        logger.error(f"Error in main execution: {str(e)}")
        raise


if __name__ == "__main__":
    main()
