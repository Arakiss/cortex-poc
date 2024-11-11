"""Protocol definition for the core agent functionality.

This module is part of CoreSight, a lightweight and transparent micro-framework for orchestrating
LLM-based agents. CoreSight was created by Petru Arakiss (petruarakiss@gmail.com) and is used
under private license.

This is a forked version specifically modified for the Cortex POC project.
"""

from abc import ABC, abstractmethod


def validate_name(name: str) -> bool:
    """Validate that the agent's name is a single term without whitespace.

    Args:
        name: The agent name to validate

    Returns:
        bool: True if name is valid, False otherwise
    """
    return len(name.split()) == 1


class AgentProtocol(ABC):
    """Protocol definition that all agents must implement.

    This abstract base class defines the core interface that all agent implementations
    must follow to ensure consistent behavior across the system.
    """

    @abstractmethod
    def get_name(self) -> str:
        """Get the name of the agent.

        Returns:
            str: The unique identifier name of this agent
        """
        pass

    @abstractmethod
    def get_role(self) -> str:
        """Describe the agent's role.

        Returns:
            str: A description of this agent's purpose and capabilities
        """
        pass

    @abstractmethod
    def run(self) -> None:
        """Execute the agent's main functionality.

        This method should implement the core behavior of the agent.
        """
        pass
