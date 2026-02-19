"""
LLM Client - Abstract base class for LLM API clients.

Provides a common interface for different LLM providers (OpenAI, Azure, Ollama, etc.)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class LLMProvider(str, Enum):
    """Supported LLM providers."""

    OPENAI = "openai"
    AZURE = "azure"
    OLLAMA = "ollama"
    CUSTOM = "custom"


@dataclass
class TokenUsage:
    """Token usage statistics."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def __add__(self, other: "TokenUsage") -> "TokenUsage":
        """Add two TokenUsage instances."""
        return TokenUsage(
            prompt_tokens=self.prompt_tokens + other.prompt_tokens,
            completion_tokens=self.completion_tokens + other.completion_tokens,
            total_tokens=self.total_tokens + other.total_tokens,
        )


@dataclass
class LLMResponse:
    """Response from an LLM completion request."""

    content: str
    model: str
    provider: LLMProvider
    usage: TokenUsage = field(default_factory=TokenUsage)
    finish_reason: str | None = None
    raw_response: dict[str, Any] = field(default_factory=dict)
    latency_seconds: float = 0.0


class LLMClient(ABC):
    """
    Abstract base class for LLM clients.

    All LLM clients must implement this interface to be used with OpenCodeAgent.
    """

    def __init__(
        self,
        model: str,
        max_tokens: int = 4096,
        temperature: float = 0.1,
        timeout: int = 120,
        max_retries: int = 3,
    ):
        """
        Initialize the LLM client.

        Args:
            model: Model identifier (e.g., "gpt-4", "llama2").
            max_tokens: Maximum tokens in response.
            temperature: Sampling temperature (0.0-2.0).
            timeout: Request timeout in seconds.
            max_retries: Maximum retry attempts on failure.
        """
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout = timeout
        self.max_retries = max_retries
        self._total_usage = TokenUsage()

    @abstractmethod
    async def complete(
        self,
        prompt: str,
        **options,
    ) -> LLMResponse:
        """
        Generate a completion for the given prompt.

        Args:
            prompt: The input prompt.
            **options: Additional provider-specific options.

        Returns:
            LLMResponse containing the generated text and metadata.

        Raises:
            LLMError: If the request fails.
        """
        pass

    @abstractmethod
    async def complete_with_messages(
        self,
        messages: list[dict[str, str]],
        **options,
    ) -> LLMResponse:
        """
        Generate a completion using a chat message format.

        Args:
            messages: List of message dicts with 'role' and 'content'.
                     Roles: 'system', 'user', 'assistant'.
            **options: Additional provider-specific options.

        Returns:
            LLMResponse containing the generated text and metadata.

        Raises:
            LLMError: If the request fails.
        """
        pass

    async def complete_with_context(
        self,
        system_prompt: str,
        user_prompt: str,
        context: list[dict[str, str]] | None = None,
        **options,
    ) -> LLMResponse:
        """
        Generate a completion with system prompt and context.

        Args:
            system_prompt: System prompt for the LLM.
            user_prompt: User's query/prompt.
            context: Optional list of previous messages for context.
            **options: Additional provider-specific options.

        Returns:
            LLMResponse containing the generated text and metadata.
        """
        messages = [{"role": "system", "content": system_prompt}]

        if context:
            messages.extend(context)

        messages.append({"role": "user", "content": user_prompt})

        return await self.complete_with_messages(messages, **options)

    def get_total_usage(self) -> TokenUsage:
        """Get cumulative token usage across all requests."""
        return self._total_usage

    def reset_usage(self) -> None:
        """Reset token usage counter."""
        self._total_usage = TokenUsage()

    def _update_usage(self, usage: TokenUsage) -> None:
        """Update cumulative usage."""
        self._total_usage = self._total_usage + usage

    @property
    @abstractmethod
    def provider(self) -> LLMProvider:
        """Get the provider type."""
        pass

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Check if the client is available (e.g., API key configured)."""
        pass


class LLMError(Exception):
    """Base exception for LLM-related errors."""

    pass


class LLMConfigurationError(LLMError):
    """Raised when LLM client is not properly configured."""

    pass


class LLMRateLimitError(LLMError):
    """Raised when rate limit is exceeded."""

    def __init__(self, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class LLMTimeoutError(LLMError):
    """Raised when request times out."""

    pass


class LLMResponseError(LLMError):
    """Raised when response parsing fails."""

    pass
