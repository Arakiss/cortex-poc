"""Language Model Provider Interface.

This module is part of CoreSight, a lightweight and transparent micro-framework for orchestrating
LLM-based agents. CoreSight was created by Petru Arakiss (petruarakiss@gmail.com) and is used
under private license.

This is a forked version specifically modified for the Cortex POC project.

This module provides the base interface and implementations for different LLM providers:
    - LLMProvider: Abstract base class defining the provider interface
    - OpenAIProvider: Implementation for OpenAI's API
"""

from .base_provider import LLMProvider
from .providers import OpenAIProvider

__all__ = ["LLMProvider", "OpenAIProvider"]
