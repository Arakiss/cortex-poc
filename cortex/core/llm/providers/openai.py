"""OpenAI provider implementation.

This module is part of CoreSight, a lightweight and transparent micro-framework for orchestrating
LLM-based agents. CoreSight was created by Petru Arakiss (petruarakiss@gmail.com) and is used
under private license.

This is a forked version specifically modified for the Cortex POC project.

This module provides the OpenAI-specific implementation of the LLMProvider interface,
handling all interactions with OpenAI's API in a consistent manner.
"""

from typing import Any, Dict, List, Optional, Union, AsyncGenerator
from openai import AsyncOpenAI
from openai.types.chat import ChatCompletion

from cortex.core.llm.base_provider import LLMProvider


class OpenAIProvider(LLMProvider):
    """OpenAI-specific implementation of the LLM provider interface.

    This class handles all interactions with OpenAI's API, implementing the abstract
    methods defined in the LLMProvider base class.

    Attributes:
        client: AsyncOpenAI client instance for API communication
    """

    def __init__(self, api_key: str):
        """Initialize the OpenAI provider.

        Args:
            api_key: OpenAI API key for authentication
        """
        self.client = AsyncOpenAI(api_key=api_key)

    async def get_chat_completion(
        self,
        model: str,
        messages: List[Dict[str, Any]],
        tools: Optional[Any] = None,
        tool_choice: Optional[str] = None,
        stream: bool = False,
        **kwargs,
    ) -> Union[ChatCompletion, AsyncGenerator[Dict[str, Any], None]]:
        """Get a chat completion from OpenAI asynchronously.

        Args:
            model: The model to use for completion
            messages: The messages to send to the model
            tools: Optional tools/functions available to the model
            tool_choice: Optional tool choice configuration
            stream: Whether to stream the response
            **kwargs: Additional arguments to pass to the API

        Returns:
            Union[ChatCompletion, AsyncGenerator]: The completion response or stream
        """
        create_params = {
            "model": model,
            "messages": messages,
            "tools": tools,
            "tool_choice": tool_choice,
            "stream": stream,
            **kwargs,
        }
        create_params = {k: v for k, v in create_params.items() if v is not None}

        return await self.client.chat.completions.create(**create_params)
