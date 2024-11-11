"""Streaming functionality for agent operations.

This module is part of CoreSight, a lightweight and transparent micro-framework for orchestrating
LLM-based agents. CoreSight was created by Petru Arakiss (petruarakiss@gmail.com) and is used
under private license.

This is a forked version specifically modified for the Cortex POC project.

This module handles the streaming of LLM responses and tool calls, maintaining immutability
and functional programming principles throughout the process.
"""

from dataclasses import dataclass, field
from collections import defaultdict
from typing import List, Optional, Dict, Any, AsyncGenerator

from openai import OpenAI

from .core import get_chat_completion
from .logger import log_debug
from .dict_utils import merge_nested_dicts
from .handlers import handle_tool_calls
from .types import Agent, Response, ChatCompletionMessageToolCall, Function

CONTEXT_VARIABLES_KEY = "context_variables"

# Type definitions
JSONDict = Dict[str, Any]
Delta = Dict[str, Any]
StreamChunk = Dict[str, Any]


@dataclass(frozen=True)
class StreamingMessage:
    """Immutable container for streaming message state.

    Attributes:
        content: The message content
        sender: Name of the message sender
        role: Role of the sender (default: "assistant")
        function_call: Optional function call details
        tool_calls: Dictionary of tool calls made in this message
    """

    content: str = ""
    sender: str = ""
    role: str = "assistant"
    function_call: Optional[Dict[str, Any]] = None
    tool_calls: Dict[str, Dict[str, Any]] = field(default_factory=dict)


def create_empty_message(agent_name: str) -> StreamingMessage:
    """Pure function to create an empty message.

    Args:
        agent_name: Name of the agent creating the message

    Returns:
        StreamingMessage: A new empty message with default tool calls structure
    """
    return StreamingMessage(
        sender=agent_name,
        tool_calls=defaultdict(
            lambda: {"function": {"arguments": "", "name": ""}, "id": "", "type": ""}
        ),
    )


def process_delta(message: StreamingMessage, delta: Delta) -> StreamingMessage:
    """Pure function to process a delta update.

    Args:
        message: Current message state
        delta: Update to apply to the message

    Returns:
        StreamingMessage: New message with delta applied
    """
    if delta.get("role") == "assistant":
        delta["sender"] = message.sender

    delta_copy = delta.copy()
    delta_copy.pop("role", None)
    delta_copy.pop("sender", None)

    updated_content = merge_nested_dicts(
        {"content": message.content, "tool_calls": message.tool_calls},
        {"content": delta_copy.get("content", ""), "tool_calls": delta_copy.get("tool_calls", {})},
    )

    return StreamingMessage(
        content=updated_content["content"],
        sender=message.sender,
        role=message.role,
        function_call=message.function_call,
        tool_calls=updated_content["tool_calls"],
    )


def convert_tool_calls(message: StreamingMessage) -> List[ChatCompletionMessageToolCall]:
    """Pure function to convert tool calls to proper format.

    Args:
        message: Message containing tool calls to convert

    Returns:
        List[ChatCompletionMessageToolCall]: Formatted tool calls
    """
    if not message.tool_calls:
        return []

    return [
        ChatCompletionMessageToolCall(
            id=tool_call["id"],
            function=Function(
                name=tool_call["function"]["name"],
                arguments=tool_call["function"]["arguments"],
            ),
            type=tool_call["type"],
        )
        for tool_call in message.tool_calls.values()
    ]


async def run_and_stream(
    client: OpenAI,
    agent: Agent,
    messages: List[JSONDict],
    context_variables: Optional[Dict[str, Any]] = None,
    model_override: Optional[str] = None,
    debug: bool = False,
    max_turns: int = float("inf"),
    execute_tools: bool = True,
) -> AsyncGenerator[Dict[str, Any], None]:
    """Run the agent interaction and stream the response using functional composition.

    This function orchestrates the streaming process while maintaining immutability
    and functional programming principles.

    Args:
        client: OpenAI client instance
        agent: Agent configuration
        messages: History of messages
        context_variables: Optional variables to maintain context
        model_override: Optional model to use instead of agent's default
        debug: Enable debug logging
        max_turns: Maximum number of interaction turns
        execute_tools: Whether to execute tool calls

    Yields:
        Dict[str, Any]: Stream chunks including delimiters and final response
    """
    active_agent = agent
    context_vars = context_variables.copy() if context_variables else {}
    history = messages.copy()
    init_len = len(messages)

    while len(history) - init_len < max_turns:
        message = create_empty_message(active_agent.name)

        completion = await get_chat_completion(
            client=client,
            agent=active_agent,
            history=history,
            context_variables=context_vars,
            model_override=model_override,
            stream=True,
            debug=debug,
        )

        yield {"delim": "start"}
        async for chunk in completion:
            delta = chunk["choices"][0]["delta"]
            yield delta
            message = process_delta(message, delta)
        yield {"delim": "end"}

        tool_calls = convert_tool_calls(message)
        log_debug(debug, "Received completion:", message)
        history.append(message)

        if not tool_calls or not execute_tools:
            log_debug(debug, "Ending turn.")
            break

        partial_response = await handle_tool_calls(
            tool_calls,
            active_agent.functions,
            context_vars,
            debug,
        )
        history.extend(partial_response.messages)
        context_vars.update(partial_response.context_variables)
        if partial_response.agent:
            active_agent = partial_response.agent

    yield {
        "response": Response(
            messages=history[init_len:],
            agent=active_agent,
            context_variables=context_vars,
        )
    }
