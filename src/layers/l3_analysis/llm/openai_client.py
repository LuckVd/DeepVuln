"""
OpenAI Client - LLM client for OpenAI and OpenAI-compatible APIs.

Supports:
- OpenAI API (GPT-4, GPT-3.5-turbo)
- Azure OpenAI
- Any OpenAI-compatible API (e.g., local models, other providers)
"""

import asyncio
import os
import time
from typing import Any

import httpx

from src.layers.l3_analysis.llm.client import (
    LLMClient,
    LLMConfigurationError,
    LLMEmptyResponseError,
    LLMError,
    LLMProvider,
    LLMRateLimitError,
    LLMResponse,
    LLMResponseError,
    LLMTimeoutError,
    LLMTruncatedResponseError,
    TokenUsage,
)


class OpenAIClient(LLMClient):
    """
    OpenAI API client.

    Can be configured for:
    - Standard OpenAI API
    - Azure OpenAI
    - Any OpenAI-compatible endpoint
    """

    def __init__(
        self,
        model: str = "gpt-4",
        api_key: str | None = None,
        base_url: str | None = None,
        organization: str | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.1,
        timeout: int = 120,
        max_retries: int = 3,
        is_azure: bool = False,
        azure_deployment: str | None = None,
        azure_api_version: str = "2024-02-15-preview",
    ):
        """
        Initialize the OpenAI client.

        Args:
            model: Model identifier (e.g., "gpt-4", "gpt-3.5-turbo").
            api_key: OpenAI API key. If not provided, uses OPENAI_API_KEY env var.
            base_url: API base URL. If not provided, uses default OpenAI URL.
            organization: OpenAI organization ID.
            max_tokens: Maximum tokens in response.
            temperature: Sampling temperature (0.0-2.0).
            timeout: Request timeout in seconds.
            max_retries: Maximum retry attempts.
            is_azure: Whether to use Azure OpenAI format.
            azure_deployment: Azure deployment name (required for Azure).
            azure_api_version: Azure API version.
        """
        super().__init__(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            timeout=timeout,
            max_retries=max_retries,
        )

        self.is_azure = is_azure
        self.azure_deployment = azure_deployment
        self.azure_api_version = azure_api_version

        # Get API key from parameter or environment
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key and not is_azure:
            # For Azure, API key might be named differently
            self.api_key = os.getenv("AZURE_OPENAI_API_KEY")

        # Set base URL
        if base_url:
            self.base_url = base_url.rstrip("/")
        elif is_azure:
            azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
            if azure_endpoint:
                self.base_url = azure_endpoint.rstrip("/")
            else:
                self.base_url = ""
        else:
            self.base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")

        self.organization = organization or os.getenv("OPENAI_ORG_ID")

        # HTTP client (lazy initialization)
        self._client: httpx.AsyncClient | None = None

    @property
    def provider(self) -> LLMProvider:
        """Get the provider type."""
        if self.is_azure:
            return LLMProvider.AZURE
        return LLMProvider.OPENAI

    @property
    def is_available(self) -> bool:
        """Check if the client is properly configured."""
        return bool(self.api_key)

    def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            headers = {
                "Content-Type": "application/json",
            }

            if self.is_azure:
                headers["api-key"] = self.api_key or ""
            else:
                headers["Authorization"] = f"Bearer {self.api_key}"

            if self.organization:
                headers["OpenAI-Organization"] = self.organization

            self._client = httpx.AsyncClient(
                headers=headers,
                timeout=self.timeout,
            )

        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    def _get_chat_url(self) -> str:
        """Get the chat completions URL."""
        if self.is_azure:
            return (
                f"{self.base_url}/openai/deployments/{self.azure_deployment}"
                f"/chat/completions?api-version={self.azure_api_version}"
            )
        return f"{self.base_url}/chat/completions"

    async def complete(
        self,
        prompt: str,
        **options,
    ) -> LLMResponse:
        """
        Generate a completion for the given prompt.

        Args:
            prompt: The input prompt.
            **options: Additional options (e.g., stop sequences).

        Returns:
            LLMResponse containing the generated text.
        """
        messages = [{"role": "user", "content": prompt}]
        return await self.complete_with_messages(messages, **options)

    async def complete_with_messages(
        self,
        messages: list[dict[str, str]],
        **options,
    ) -> LLMResponse:
        """
        Generate a completion using chat message format.

        Args:
            messages: List of message dicts with 'role' and 'content'.
            **options: Additional options.

        Returns:
            LLMResponse containing the generated text.

        Raises:
            LLMConfigurationError: If API key is not configured.
            LLMError: If the request fails.
        """
        if not self.is_available:
            raise LLMConfigurationError(
                "OpenAI API key not configured. Set OPENAI_API_KEY environment variable "
                "or pass api_key parameter."
            )

        client = self._get_client()

        # Build request body
        body: dict[str, Any] = {
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }

        # Set model (Azure uses deployment name)
        if not self.is_azure:
            body["model"] = self.model

        # Add optional parameters
        if "stop" in options:
            body["stop"] = options["stop"]
        if "top_p" in options:
            body["top_p"] = options["top_p"]
        if "presence_penalty" in options:
            body["presence_penalty"] = options["presence_penalty"]
        if "frequency_penalty" in options:
            body["frequency_penalty"] = options["frequency_penalty"]

        # Build context for error reporting
        error_context = {
            "model": self.model,
            "base_url": self.base_url,
            "max_tokens": self.max_tokens,
            "message_count": len(messages),
        }

        # Execute request with retries
        last_error: Exception | None = None

        for attempt in range(self.max_retries):
            try:
                start_time = time.time()

                response = await client.post(
                    self._get_chat_url(),
                    json=body,
                )

                latency = time.time() - start_time

                # Handle rate limiting
                if response.status_code == 429:
                    retry_after = response.headers.get("retry-after")
                    retry_seconds = int(retry_after) if retry_after else 60

                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(min(retry_seconds, 30))
                        continue

                    raise LLMRateLimitError(
                        "Rate limit exceeded",
                        retry_after=retry_seconds,
                        context=error_context,
                    )

                # Handle other errors
                if response.status_code != 200:
                    error_body = response.text[:1000]  # Truncate error body
                    raise LLMError(
                        f"OpenAI API error (status {response.status_code}): {error_body}",
                        is_retryable=response.status_code >= 500,  # Server errors are retryable
                        context={**error_context, "status_code": response.status_code},
                        suggestion="Check API status or try again later." if response.status_code >= 500 else "Check your request parameters.",
                    )

                # Parse response
                data = response.json()

                return self._parse_response(data, latency)

            except httpx.TimeoutException as e:
                last_error = LLMTimeoutError(
                    f"Request timed out after {self.timeout}s: {e}",
                    timeout=self.timeout,
                    context=error_context,
                )
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    continue

            except httpx.RequestError as e:
                last_error = LLMError(
                    f"Request failed: {e}",
                    is_retryable=True,  # Network errors are usually retryable
                    context={**error_context, "error_type": type(e).__name__},
                    suggestion="Check network connectivity and API endpoint.",
                )
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue

            except LLMRateLimitError:
                raise

            except LLMEmptyResponseError:
                raise  # Propagate empty response errors

            except LLMTruncatedResponseError:
                raise  # Propagate truncation errors

            except LLMError:
                raise

            except Exception as e:
                last_error = LLMError(
                    f"Unexpected error: {e}",
                    is_retryable=False,
                    context={**error_context, "error_type": type(e).__name__},
                )
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue

        raise last_error or LLMError("Max retries exceeded", context=error_context)

    def _parse_response(
        self,
        data: dict[str, Any],
        latency: float,
    ) -> LLMResponse:
        """Parse OpenAI API response.

        Raises:
            LLMResponseError: If response parsing fails.
            LLMEmptyResponseError: If LLM returns empty content.
            LLMTruncatedResponseError: If response was truncated due to token limit.
        """
        try:
            choices = data.get("choices", [])
            if not choices:
                raise LLMResponseError(
                    "No choices in response",
                    raw_response=str(data),
                    context={"model": self.model},
                )

            choice = choices[0]
            content = choice.get("message", {}).get("content", "")
            finish_reason = choice.get("finish_reason")

            # Extract usage
            usage_data = data.get("usage", {})
            usage = TokenUsage(
                prompt_tokens=usage_data.get("prompt_tokens", 0),
                completion_tokens=usage_data.get("completion_tokens", 0),
                total_tokens=usage_data.get("total_tokens", 0),
            )

            # Check for empty response
            if not content or not content.strip():
                raise LLMEmptyResponseError(
                    prompt_preview=None,  # Prompt not available here
                    context={
                        "model": self.model,
                        "finish_reason": finish_reason,
                        "usage": usage_data,
                    },
                )

            # Check for truncated response
            if finish_reason == "length":
                raise LLMTruncatedResponseError(
                    finish_reason=finish_reason,
                    token_usage=usage_data,
                    context={
                        "model": self.model,
                        "max_tokens": self.max_tokens,
                    },
                )

            # Update cumulative usage
            self._update_usage(usage)

            # Get model name
            model = data.get("model", self.model)

            return LLMResponse(
                content=content,
                model=model,
                provider=self.provider,
                usage=usage,
                finish_reason=finish_reason,
                raw_response=data,
                latency_seconds=latency,
            )

        except (KeyError, IndexError, TypeError) as e:
            raise LLMResponseError(
                f"Failed to parse response: {e}",
                raw_response=str(data),
                context={"model": self.model},
            )

    async def __aenter__(self) -> "OpenAIClient":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()
