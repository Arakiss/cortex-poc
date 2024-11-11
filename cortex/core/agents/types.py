"""Type definitions and core data structures for agent operations.

This module is part of CoreSight, a lightweight and transparent micro-framework for orchestrating
LLM-based agents. CoreSight was created by Petru Arakiss (petruarakiss@gmail.com) and is used
under private license.

This is a forked version specifically modified for the Cortex POC project.
"""

from dataclasses import dataclass, field
from typing import List, Callable, Union, Optional, Dict, Any, Protocol, TypeVar, runtime_checkable
from typing_extensions import TypeAlias
from pydantic import BaseModel

# Type definitions
AgentFunction: TypeAlias = Callable[..., Union[str, "Agent", dict]]
JSONDict: TypeAlias = Dict[str, Any]


@dataclass(frozen=True)
class Function:
    """Immutable function call representation.

    Attributes:
        name: Name of the function to call
        arguments: JSON-encoded string of function arguments
    """

    name: str
    arguments: str


@dataclass(frozen=True)
class ChatCompletionMessageToolCall:
    """Immutable tool call representation within a chat completion message.

    Attributes:
        id: Unique identifier for this tool call
        function: Function to be called
        type: Type of tool call (default: "tool")
    """

    id: str
    function: Function
    type: str = "tool"


@runtime_checkable
class AgentProtocol(Protocol):
    """Protocol defining required agent behavior.

    This protocol ensures that all agent implementations provide the necessary
    interface for identification and execution.
    """

    @property
    def name(self) -> str:
        """Agent's identifier name.

        Returns:
            str: Unique name identifying this agent
        """
        ...

    @property
    def role(self) -> str:
        """Agent's role description.

        Returns:
            str: Description of this agent's purpose and capabilities
        """
        ...

    def run(self) -> None:
        """Execute agent's main functionality.

        This method should implement the core behavior of the agent.
        """
        ...


T = TypeVar("T", bound=AgentProtocol)


class Agent(BaseModel):
    """Base agent configuration using Pydantic.

    Attributes:
        name: Unique identifier for this agent
        role: Description of agent's purpose
        model: LLM model to use (default: "default-model")
        instructions: System prompt or instruction generator
        functions: List of available tool functions
        tool_choice: Optional specific tool to use
        parallel_tool_calls: Whether to allow parallel tool execution
    """

    name: str
    role: str
    model: str = "default-model"
    instructions: Union[str, Callable[..., str]] = "You are a helpful agent."
    functions: List[AgentFunction] = []
    tool_choice: Optional[str] = None
    parallel_tool_calls: bool = True

    class Config:
        arbitrary_types_allowed = True

    def model_post_init(self, __context: Any) -> None:
        """Validate agent configuration after initialization."""
        if not self._validate_name():
            raise ValueError("Agent name must be a single term without whitespace")

    def _validate_name(self) -> bool:
        """Ensure agent name is a single term without whitespace."""
        return len(self.name.split()) == 1


@dataclass(frozen=True)
class Result:
    """Immutable function result container.

    Attributes:
        value: String result of the function execution
        agent: Optional updated agent configuration
        context_variables: Updated context after execution
    """

    value: str = ""
    agent: Optional[Agent] = None
    context_variables: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Response:
    """Immutable response container.

    Attributes:
        messages: List of message exchanges
        agent: Optional updated agent configuration
        context_variables: Updated context after interaction
    """

    messages: List[Any] = field(default_factory=list)
    agent: Optional[Agent] = None
    context_variables: Dict[str, Any] = field(default_factory=dict)
