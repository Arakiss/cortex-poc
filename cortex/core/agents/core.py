"""Core functionality for agent operations.

This module is part of CoreSight, a lightweight and transparent micro-framework for orchestrating
LLM-based agents. CoreSight was created by Petru Arakiss (petruarakiss@gmail.com) and is used
under private license.

This is a forked version specifically modified for the Cortex POC project.
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Union, AsyncGenerator, Callable

from openai.types.chat import ChatCompletion
from cortex.core.llm.base_provider import LLMProvider

from .logger import log_debug
from .utils import function_to_json
from .types import Agent, JSONDict

CONTEXT_VARIABLES_KEY = "context_variables"

ContextVariables = Dict[str, Any]

# Type definitions
Message = Dict[str, Any]
Tool = Dict[str, Any]
CompletionResult = Union[ChatCompletion, AsyncGenerator[Dict[str, Any], None]]


@dataclass(frozen=True)
class CompletionConfig:
    """Immutable configuration for chat completion."""

    model: str
    messages: List[Message]
    tools: Optional[List[Tool]]
    tool_choice: Optional[str]
    stream: bool


def prepare_tools(agent_functions: List[Callable[..., Any]]) -> List[Tool]:
    """Pure function to prepare tool configurations."""
    tools = [function_to_json(f) for f in agent_functions]

    for tool in tools:
        params = tool["function"]["parameters"]
        params["properties"].pop(CONTEXT_VARIABLES_KEY, None)
        if CONTEXT_VARIABLES_KEY in params.get("required", []):
            params["required"].remove(CONTEXT_VARIABLES_KEY)

    return tools


def create_system_message(
    instructions: Union[str, Callable[..., str]], context: ContextVariables
) -> Message:
    """Create system message with context-aware instructions."""
    content = instructions(context) if callable(instructions) else instructions
    return {"role": "system", "content": content}


def create_completion_config(
    agent: Agent,
    history: List[JSONDict],
    context_variables: Dict[str, Any],
    model_override: Optional[str],
    stream: bool,
) -> CompletionConfig:
    """Pure function to create completion configuration."""
    context_vars = {k: str(v) for k, v in context_variables.items()}
    system_msg = create_system_message(agent.instructions, context_vars)
    messages = [system_msg] + history
    tools = prepare_tools(agent.functions) if agent.functions else None

    return CompletionConfig(
        model=model_override or agent.model,
        messages=messages,
        tools=tools,
        tool_choice=agent.tool_choice,
        stream=stream,
    )


async def get_chat_completion(
    client: LLMProvider,
    agent: Agent,
    history: List[JSONDict],
    context_variables: Dict[str, Any],
    model_override: Optional[str],
    stream: bool,
    debug: bool,
) -> CompletionResult:
    """
    Get a chat completion from the LLM provider asynchronously.

    This function composes several pure functions to prepare the request
    and handles the interaction with the LLM provider.
    """
    try:
        config = create_completion_config(
            agent=agent,
            history=history,
            context_variables=context_variables,
            model_override=model_override,
            stream=stream,
        )

        log_debug(debug, "Getting chat completion for:", config.messages)

        return await client.get_chat_completion(
            model=config.model,
            messages=config.messages,
            tools=config.tools,
            tool_choice=config.tool_choice,
            stream=config.stream,
        )

    except Exception as e:
        log_debug(debug, f"Error in get_chat_completion: {str(e)}")
        raise
