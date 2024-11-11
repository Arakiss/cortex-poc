"""Dictionary manipulation utilities for agent operations.

This module is part of CoreSight, a lightweight and transparent micro-framework for orchestrating
LLM-based agents. CoreSight was created by Petru Arakiss (petruarakiss@gmail.com) and is used
under private license.

This is a forked version specifically modified for the Cortex POC project.
"""

from typing import Any, Dict


def merge_nested_dicts(target: Dict[str, Any], source: Dict[str, Any]) -> Dict[str, Any]:
    """Merge two dictionaries recursively, handling nested structures.

    Args:
        target: Base dictionary to merge into
        source: Dictionary whose values should be merged into target

    Returns:
        A new dictionary containing the merged values
    """
    result = target.copy()

    for key, value in source.items():
        if isinstance(value, str):
            result[key] = result.get(key, "") + value if isinstance(result.get(key), str) else value
        elif isinstance(value, dict):
            if key not in result or not isinstance(result[key], dict):
                result[key] = {}
            result[key] = merge_nested_dicts(result[key], value)
        else:
            result[key] = value

    return result


def merge_stream_chunk(response: Dict[str, Any], delta: Dict[str, Any]) -> Dict[str, Any]:
    """Merge a streaming response chunk into the accumulated response.

    Args:
        response: Accumulated response so far
        delta: New chunk to merge

    Returns:
        Updated response dictionary with the chunk merged in
    """
    result = response.copy()
    delta_copy = delta.copy()
    delta_copy.pop("role", None)

    result = merge_nested_dicts(result, delta_copy)

    tool_calls = delta_copy.get("tool_calls", [])
    if tool_calls and len(tool_calls) > 0:
        tool_call = tool_calls[0].copy()
        index = tool_call.pop("index")
        result["tool_calls"] = result.get("tool_calls", {})
        result["tool_calls"][index] = merge_nested_dicts(
            result["tool_calls"].get(
                index, {"function": {"arguments": "", "name": ""}, "id": "", "type": ""}
            ),
            tool_call,
        )

    return result
