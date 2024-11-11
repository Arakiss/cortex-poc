"""Handlers for agent tool calls and function execution.

This module is part of CoreSight, a lightweight and transparent micro-framework for orchestrating
LLM-based agents. CoreSight was created by Petru Arakiss (petruarakiss@gmail.com) and is used
under private license.

This is a forked version specifically modified for the Cortex POC project.
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Callable, Awaitable, Optional
import json

from .logger import log_debug
from .types import AgentFunction, Agent, Response, Result

CONTEXT_VARIABLES_KEY = "context_variables"

# Type definitions
AsyncFunction = Callable[..., Awaitable[Any]]
ToolCall = Dict[str, Any]


@dataclass(frozen=True)
class FunctionCallResult:
    """Immutable container for function call results."""

    tool_call_id: str
    tool_name: str
    content: str
    context_variables: Dict[str, Any]
    agent: Optional[Agent] = None


def process_raw_result(raw_result: Any, debug: bool) -> Result:
    """Pure function to process raw function results."""
    if isinstance(raw_result, Result):
        return raw_result
    elif isinstance(raw_result, str):
        return Result(value=raw_result)
    elif isinstance(raw_result, dict):
        return Result(value="", context_variables=raw_result)
    else:
        error_msg = "Function returned unsupported type."
        log_debug(debug, error_msg)
        return Result(value=error_msg)


def create_error_message(tool_call_id: str, tool_name: str, error: Exception) -> FunctionCallResult:
    """Pure function to create error message."""
    return FunctionCallResult(
        tool_call_id=tool_call_id,
        tool_name=tool_name,
        content=f"Error executing tool {tool_name}: {str(error)}",
        context_variables={},
    )


def create_success_message(tool_call_id: str, tool_name: str, result: Result) -> FunctionCallResult:
    """Pure function to create success message."""
    return FunctionCallResult(
        tool_call_id=tool_call_id,
        tool_name=tool_name,
        content=result.value,
        context_variables=result.context_variables,
        agent=result.agent,
    )


async def execute_tool_call(
    tool_call: ToolCall,
    function_map: Dict[str, AgentFunction],
    context_variables: Dict[str, Any],
    debug: bool,
) -> FunctionCallResult:
    """Pure function to execute a single tool call."""
    name = tool_call["function"]["name"]
    tool_id = tool_call["id"]

    func = function_map.get(name)
    if not func:
        log_debug(debug, f"Tool {name} not found in function map.")
        return FunctionCallResult(
            tool_call_id=tool_id,
            tool_name=name,
            content=f"Error: Tool {name} not found.",
            context_variables={},
        )

    try:
        args = json.loads(tool_call["function"]["arguments"])
        log_debug(debug, f"Processing tool call: {name} with arguments {args}")

        if CONTEXT_VARIABLES_KEY in func.__code__.co_varnames:
            args[CONTEXT_VARIABLES_KEY] = context_variables

        raw_result = (
            await func(**args)
            if isinstance(func, AsyncFunction) or hasattr(func, "__await__")
            else func(**args)
        )

        result = process_raw_result(raw_result, debug)
        return create_success_message(tool_id, name, result)

    except Exception as e:
        log_debug(debug, f"Error executing tool {name}: {str(e)}")
        return create_error_message(tool_id, name, e)


def create_tool_response(result: FunctionCallResult) -> Dict[str, Any]:
    """Pure function to create tool response message."""
    return {
        "role": "tool",
        "tool_call_id": result.tool_call_id,
        "tool_name": result.tool_name,
        "content": result.content,
    }


async def handle_tool_calls(
    tool_calls: List[ToolCall],
    functions: List[AgentFunction],
    context_variables: Dict[str, Any],
    debug: bool,
) -> Response:
    """
    Handle tool calls using functional composition and immutable data structures.

    This function orchestrates the execution of tool calls and aggregates their results
    into a single Response object.
    """
    function_map = {func.__name__: func for func in functions}
    results = []

    for tool_call in tool_calls:
        result = await execute_tool_call(
            tool_call=tool_call,
            function_map=function_map,
            context_variables=context_variables,
            debug=debug,
        )
        results.append(result)

    messages = [create_tool_response(result) for result in results]
    context_vars = {k: v for result in results for k, v in result.context_variables.items()}

    agent = next(
        (result.agent for result in results if result.agent is not None),
        None,
    )

    return Response(
        messages=messages,
        agent=agent,
        context_variables=context_vars,
    )
