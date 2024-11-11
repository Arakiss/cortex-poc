"""Utility functions for agent operations.

This module is part of CoreSight, a lightweight and transparent micro-framework for orchestrating
LLM-based agents. CoreSight was created by Petru Arakiss (petruarakiss@gmail.com) and is used
under private license.

This is a forked version specifically modified for the Cortex POC project.

This module provides a clean interface to various utility functions used throughout
the agents package. It re-exports the most commonly used functions from specialized
utility modules for easier access and better organization.

Re-exported functions:
    - log_debug: Debug logging utility
    - merge_nested_dicts: Recursive dictionary merging
    - merge_stream_chunk: Stream chunk merging for responses
    - function_to_json: Convert Python functions to JSON schema
    - ParameterSchema: Type definition for parameter schemas
    - FunctionSchema: Type definition for function schemas
"""

from .logger import log_debug
from .dict_utils import merge_nested_dicts, merge_stream_chunk
from .schema_utils import (
    convert_function_to_schema as function_to_json,
    ParameterSchema,
    FunctionSchema,
)

__all__ = [
    "log_debug",
    "merge_nested_dicts",
    "merge_stream_chunk",
    "function_to_json",
    "ParameterSchema",
    "FunctionSchema",
]
