"""LLM client exceptions.

P15: Moved from src.layers.l3_analysis.llm.client to resolve circular dependencies.
These exceptions can now be used by both L1 and L3 layers.
"""

from typing import Any


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
