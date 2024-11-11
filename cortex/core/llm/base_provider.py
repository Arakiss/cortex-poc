"""Base provider interface for LLM interactions.

This module is part of CoreSight, a lightweight and transparent micro-framework for orchestrating
LLM-based agents. CoreSight was created by Petru Arakiss (petruarakiss@gmail.com) and is used
under private license.

This is a forked version specifically modified for the Cortex POC project.

This module defines the abstract base class that all LLM providers must implement to ensure
consistent interaction patterns across different language models.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union, AsyncGenerator

from openai.types.chat import ChatCompletion


class LLMProvider(ABC):
    """Abstract base class for LLM provider implementations.

    This class defines the interface that all LLM providers must implement to ensure
    consistent behavior across different language model services.
    """

    @abstractmethod
    async def get_chat_completion(
        self,
        model: str,
        messages: List[Dict[str, Any]],
        tools: Optional[Any] = None,
        tool_choice: Optional[str] = None,
        stream: bool = False,
        **kwargs,
    ) -> Union[ChatCompletion, AsyncGenerator[Dict[str, Any], None]]:
        """Get a chat completion from the LLM provider asynchronously.

        Args:
            model: The model identifier to use for completion
            messages: List of message dictionaries to send to the model
            tools: Optional tools/functions available to the model
            tool_choice: Optional specific tool to use
            stream: Whether to stream the response
            **kwargs: Additional provider-specific arguments

        Returns:
            Union[ChatCompletion, AsyncGenerator]: Either a complete response or
                a stream of response chunks

        Note:
            The actual implementation should handle provider-specific details while
            maintaining this consistent interface.
        """
        pass
