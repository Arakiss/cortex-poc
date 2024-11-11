"""LLM provider implementations.

This module is part of CoreSight, a lightweight and transparent micro-framework for orchestrating
LLM-based agents. CoreSight was created by Petru Arakiss (petruarakiss@gmail.com) and is used
under private license.

This is a forked version specifically modified for the Cortex POC project.

This module exports specific LLM provider implementations that conform to the LLMProvider
interface. Currently supported providers:
    - OpenAIProvider: Implementation for OpenAI's API
"""

from .openai import OpenAIProvider

__all__ = ["OpenAIProvider"]
