"""Main agent execution and state management.

This module is part of CoreSight, a lightweight and transparent micro-framework for orchestrating
LLM-based agents. CoreSight was created by Petru Arakiss (petruarakiss@gmail.com) and is used
under private license.

This is a forked version specifically modified for the Cortex POC project.
"""

from dataclasses import dataclass
from typing import List, Union, Optional, Dict, Any, AsyncGenerator

from .core import get_chat_completion
from .logger import log_debug
from .handlers import handle_tool_calls
from .streaming import run_and_stream
from .types import Agent, Response

# Type definitions
JSONDict = Dict[str, Any]


@dataclass(frozen=True)
class AgentState:
    """Immutable container for agent state."""

    agent: Agent
    history: List[JSONDict]
    context_variables: Dict[str, Any]
    init_len: int


def create_initial_state(
    agent: Agent,
    messages: List[JSONDict],
    context_variables: Optional[Dict[str, Any]] = None,
) -> AgentState:
    """Pure function to create initial agent state."""
    return AgentState(
        agent=agent,
        history=messages.copy(),
        context_variables=context_variables.copy() if context_variables else {},
        init_len=len(messages),
    )


def process_tool_response(
    state: AgentState,
    partial_response: Response,
) -> AgentState:
    """Pure function to process tool response and update state."""
    new_history = state.history.copy()
    new_history.extend(partial_response.messages)

    new_context_vars = state.context_variables.copy()
    new_context_vars.update(partial_response.context_variables)

    return AgentState(
        agent=partial_response.agent or state.agent,
        history=new_history,
        context_variables=new_context_vars,
        init_len=state.init_len,
    )


def create_final_response(state: AgentState) -> Response:
    """Pure function to create final response from state."""
    return Response(
        messages=state.history[state.init_len :],
        agent=state.agent,
        context_variables=state.context_variables,
    )


async def run(
    client: Any,
    agent: Agent,
    messages: List[JSONDict],
    context_variables: Optional[Dict[str, Any]] = None,
    model_override: Optional[str] = None,
    stream: bool = False,
    debug: bool = False,
    max_turns: int = float("inf"),
    execute_tools: bool = True,
) -> Union[Response, AsyncGenerator[Dict[str, Any], None]]:
    """
    Run the agent interaction using functional composition and immutable state.

    This function orchestrates the agent interaction while maintaining pure functional
    principles and type safety.
    """
    if stream:
        return await run_and_stream(
            client=client,
            agent=agent,
            messages=messages,
            context_variables=context_variables,
            model_override=model_override,
            debug=debug,
            max_turns=max_turns,
            execute_tools=execute_tools,
        )

    state = create_initial_state(agent, messages, context_variables)

    while len(state.history) - state.init_len < max_turns:
        try:
            completion = await get_chat_completion(
                client=client,
                agent=state.agent,
                history=state.history,
                context_variables=state.context_variables,
                model_override=model_override,
                stream=False,
                debug=debug,
            )

            message = completion.choices[0].message.model_dump()
            log_debug(debug, "Received completion:", message)

            message["sender"] = state.agent.name
            new_history = state.history.copy()
            new_history.append(message)

            state = AgentState(
                agent=state.agent,
                history=new_history,
                context_variables=state.context_variables,
                init_len=state.init_len,
            )

            if not message.get("tool_calls") or not execute_tools:
                log_debug(debug, "Ending turn.")
                break

            partial_response = await handle_tool_calls(
                message["tool_calls"],
                state.agent.functions,
                state.context_variables,
                debug,
            )

            state = process_tool_response(state, partial_response)

        except Exception as e:
            log_debug(debug, f"Error in agent run: {str(e)}")
            raise

    return create_final_response(state)
