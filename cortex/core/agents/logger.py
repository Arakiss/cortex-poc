"""Logging utilities for agent operations.

This module is part of CoreSight, a lightweight and transparent micro-framework for orchestrating
LLM-based agents. CoreSight was created by Petru Arakiss (petruarakiss@gmail.com) and is used
under private license.

This is a forked version specifically modified for the Cortex POC project.
"""

from datetime import datetime
from typing import Any


def format_timestamp(timestamp: datetime) -> str:
    """Format a timestamp for log messages."""
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")


def create_log_message(timestamp: str, message: str) -> str:
    """Create a formatted log message with timestamp."""
    return f"\033[97m[\033[90m{timestamp}\033[97m]\033[90m {message}\033[0m"


def format_log_content(*args: Any) -> str:
    """Format log message content from multiple arguments."""
    return " ".join(map(str, args))


def log_debug(enabled: bool, *args: Any) -> None:
    """Log a debug level message if logging is enabled.

    Args:
        enabled: Whether logging is enabled
        *args: Content to include in the log message
    """
    if not enabled:
        return

    timestamp = format_timestamp(datetime.now())
    message = create_log_message(timestamp, format_log_content(*args))
    print(message)
