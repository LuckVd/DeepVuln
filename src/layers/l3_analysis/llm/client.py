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
    """Base exception for LLM-related errors.

    Attributes:
        message: Error message.
        is_retryable: Whether the error can be retried.
        context: Additional context information (prompt preview, model, etc.).
        suggestion: Suggested action to resolve the error.
    """

    def __init__(
        self,
        message: str,
        is_retryable: bool = False,
        context: dict[str, Any] | None = None,
        suggestion: str | None = None,
    ):
        super().__init__(message)
        self.is_retryable = is_retryable
        self.context = context or {}
        self.suggestion = suggestion

    def __str__(self) -> str:
        parts = [super().__str__()]
        if self.context:
            context_str = ", ".join(f"{k}={v}" for k, v in self.context.items())
            parts.append(f"Context: {context_str}")
        if self.suggestion:
            parts.append(f"Suggestion: {self.suggestion}")
        return " | ".join(parts)


class LLMConfigurationError(LLMError):
    """Raised when LLM client is not properly configured."""

    def __init__(self, message: str, context: dict[str, Any] | None = None):
        super().__init__(
            message,
            is_retryable=False,
            context=context,
            suggestion="Check your API key and configuration settings.",
        )


class LLMRateLimitError(LLMError):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        message: str,
        retry_after: int | None = None,
        context: dict[str, Any] | None = None,
    ):
        super().__init__(
            message,
            is_retryable=True,
            context={**(context or {}), "retry_after": retry_after},
            suggestion=f"Wait {retry_after or 60} seconds before retrying.",
        )
        self.retry_after = retry_after


class LLMTimeoutError(LLMError):
    """Raised when request times out."""

    def __init__(
        self,
        message: str,
        timeout: int | None = None,
        context: dict[str, Any] | None = None,
    ):
        super().__init__(
            message,
            is_retryable=True,
            context={**(context or {}), "timeout": timeout},
            suggestion="Increase timeout or reduce input size.",
        )
        self.timeout = timeout


class LLMResponseError(LLMError):
    """Raised when response parsing fails."""

    def __init__(
        self,
        message: str,
        raw_response: str | None = None,
        context: dict[str, Any] | None = None,
    ):
        # Truncate raw response for logging
        preview = None
        if raw_response:
            preview = raw_response[:500] + "..." if len(raw_response) > 500 else raw_response
        super().__init__(
            message,
            is_retryable=False,
            context={**(context or {}), "response_preview": preview},
            suggestion="Check if the model output format matches expectations.",
        )
        self.raw_response = raw_response


class LLMEmptyResponseError(LLMError):
    """Raised when LLM returns an empty response."""

    def __init__(
        self,
        message: str = "LLM returned empty response",
        prompt_preview: str | None = None,
        context: dict[str, Any] | None = None,
    ):
        # Truncate prompt preview
        preview = None
        if prompt_preview:
            preview = prompt_preview[:300] + "..." if len(prompt_preview) > 300 else prompt_preview
        super().__init__(
            message,
            is_retryable=True,  # Might be a temporary issue
            context={**(context or {}), "prompt_preview": preview},
            suggestion="Input may be too long or model refused to respond. Try reducing input size.",
        )
        self.prompt_preview = prompt_preview


class LLMTruncatedResponseError(LLMError):
    """Raised when LLM response was truncated due to max_tokens limit."""

    def __init__(
        self,
        message: str = "LLM response was truncated",
        finish_reason: str | None = None,
        token_usage: dict[str, int] | None = None,
        context: dict[str, Any] | None = None,
    ):
        super().__init__(
            message,
            is_retryable=True,
            context={
                **(context or {}),
                "finish_reason": finish_reason,
                "token_usage": token_usage,
            },
            suggestion="Increase max_tokens or split the request into smaller parts.",
        )
        self.finish_reason = finish_reason
        self.token_usage = token_usage


class LLMJSONParseError(LLMError):
    """Raised when LLM response JSON parsing fails."""

    def __init__(
        self,
        message: str,
        parse_error: str | None = None,
        response_preview: str | None = None,
        context: dict[str, Any] | None = None,
    ):
        # Truncate response preview
        preview = None
        if response_preview:
            preview = response_preview[:500] + "..." if len(response_preview) > 500 else response_preview
        super().__init__(
            message,
            is_retryable=True,  # JSON format might be fixable with retry
            context={
                **(context or {}),
                "parse_error": parse_error,
                "response_preview": preview,
            },
            suggestion="The model returned malformed JSON. Try again with clearer format instructions.",
        )
        self.parse_error = parse_error
        self.response_preview = response_preview
