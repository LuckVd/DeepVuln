"""
Ollama Client - LLM client for Ollama local models.

Ollama provides a simple API for running local LLMs like Llama, Mistral, etc.
API docs: https://github.com/ollama/ollama/blob/main/docs/api.md
"""

import asyncio
import os
import time
from typing import Any

import httpx

from src.layers.l3_analysis.llm.client import (
    LLMClient,
    LLMConfigurationError,
    LLMError,
    LLMProvider,
    LLMResponse,
    LLMResponseError,
    LLMTimeoutError,
    TokenUsage,
)


class OllamaClient(LLMClient):
    """
    Ollama API client for local LLM models.

    Requires Ollama to be running locally or accessible via network.
    """

    def __init__(
        self,
        model: str = "llama2",
        base_url: str | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.1,
        timeout: int = 300,  # Local models may be slower
        max_retries: int = 2,
    ):
        """
        Initialize the Ollama client.

        Args:
            model: Model name (e.g., "llama2", "mistral", "codellama").
            base_url: Ollama API URL. Default: http://localhost:11434
            max_tokens: Maximum tokens in response.
            temperature: Sampling temperature (0.0-2.0).
            timeout: Request timeout in seconds.
            max_retries: Maximum retry attempts.
        """
        super().__init__(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            timeout=timeout,
            max_retries=max_retries,
        )

        self.base_url = (base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")).rstrip("/")
        self._client: httpx.AsyncClient | None = None

    @property
    def provider(self) -> LLMProvider:
        """Get the provider type."""
        return LLMProvider.OLLAMA

    @property
    def is_available(self) -> bool:
        """Check if Ollama is running."""
        # Ollama doesn't require an API key, just needs to be running
        return True

    async def check_connection(self) -> bool:
        """
        Check if Ollama server is reachable.

        Returns:
            True if Ollama is running and accessible.
        """
        try:
            client = self._get_client()
            response = await client.get(f"{self.base_url}/api/tags", timeout=5.0)
            return response.status_code == 200
        except Exception:
            return False

    async def list_models(self) -> list[str]:
        """
        List available models.

        Returns:
            List of model names.
        """
        try:
            client = self._get_client()
            response = await client.get(f"{self.base_url}/api/tags", timeout=10.0)

            if response.status_code == 200:
                data = response.json()
                return [m.get("name", "") for m in data.get("models", [])]

            return []
        except Exception:
            return []

    async def pull_model(self, model: str | None = None) -> bool:
        """
        Pull/download a model.

        Args:
            model: Model name to pull. Uses self.model if not specified.

        Returns:
            True if successful.
        """
        model = model or self.model
        client = self._get_client()

        try:
            response = await client.post(
                f"{self.base_url}/api/pull",
                json={"name": model},
                timeout=600.0,  # Pulling can take a while
            )
            return response.status_code == 200
        except Exception:
            return False

    def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=self.timeout)

        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def complete(
        self,
        prompt: str,
        **options,
    ) -> LLMResponse:
        """
        Generate a completion for the given prompt.

        Args:
            prompt: The input prompt.
            **options: Additional options.

        Returns:
            LLMResponse containing the generated text.
        """
        return await self._generate(prompt=prompt, **options)

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
        """
        # Use chat API if available, otherwise convert to prompt
        return await self._chat(messages, **options)

    async def _generate(
        self,
        prompt: str,
        **options,
    ) -> LLMResponse:
        """Use the /api/generate endpoint."""
        client = self._get_client()

        body: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": self.max_tokens,
                "temperature": self.temperature,
            },
        }

        # Add additional options
        if "stop" in options:
            body["options"]["stop"] = options["stop"]
        if "top_p" in options:
            body["options"]["top_p"] = options["top_p"]
        if "top_k" in options:
            body["options"]["top_k"] = options["top_k"]

        last_error: Exception | None = None

        for attempt in range(self.max_retries):
            try:
                start_time = time.time()

                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json=body,
                )

                latency = time.time() - start_time

                if response.status_code != 200:
                    raise LLMError(
                        f"Ollama API error (status {response.status_code}): {response.text}"
                    )

                data = response.json()
                return self._parse_generate_response(data, latency)

            except httpx.TimeoutException as e:
                last_error = LLMTimeoutError(f"Request timed out: {e}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue

            except httpx.RequestError as e:
                last_error = LLMError(f"Request failed: {e}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue

            except LLMError:
                raise

            except Exception as e:
                last_error = LLMError(f"Unexpected error: {e}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue

        raise last_error or LLMError("Max retries exceeded")

    async def _chat(
        self,
        messages: list[dict[str, str]],
        **options,
    ) -> LLMResponse:
        """Use the /api/chat endpoint."""
        client = self._get_client()

        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "num_predict": self.max_tokens,
                "temperature": self.temperature,
            },
        }

        # Add additional options
        if "stop" in options:
            body["options"]["stop"] = options["stop"]
        if "top_p" in options:
            body["options"]["top_p"] = options["top_p"]
        if "top_k" in options:
            body["options"]["top_k"] = options["top_k"]

        last_error: Exception | None = None

        for attempt in range(self.max_retries):
            try:
                start_time = time.time()

                response = await client.post(
                    f"{self.base_url}/api/chat",
                    json=body,
                )

                latency = time.time() - start_time

                if response.status_code != 200:
                    # Fallback to generate if chat not supported
                    if response.status_code == 404:
                        prompt = self._messages_to_prompt(messages)
                        return await self._generate(prompt, **options)

                    raise LLMError(
                        f"Ollama API error (status {response.status_code}): {response.text}"
                    )

                data = response.json()
                return self._parse_chat_response(data, latency)

            except httpx.TimeoutException as e:
                last_error = LLMTimeoutError(f"Request timed out: {e}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue

            except httpx.RequestError as e:
                last_error = LLMError(f"Request failed: {e}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue

            except LLMError:
                raise

            except Exception as e:
                last_error = LLMError(f"Unexpected error: {e}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue

        raise last_error or LLMError("Max retries exceeded")

    def _messages_to_prompt(self, messages: list[dict[str, str]]) -> str:
        """Convert chat messages to a single prompt string."""
        parts = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")

            if role == "system":
                parts.append(f"System: {content}")
            elif role == "user":
                parts.append(f"User: {content}")
            elif role == "assistant":
                parts.append(f"Assistant: {content}")

        parts.append("Assistant:")
        return "\n\n".join(parts)

    def _parse_generate_response(
        self,
        data: dict[str, Any],
        latency: float,
    ) -> LLMResponse:
        """Parse /api/generate response."""
        try:
            content = data.get("response", "")

            # Ollama provides token counts
            eval_count = data.get("eval_count", 0)
            prompt_eval_count = data.get("prompt_eval_count", 0)

            usage = TokenUsage(
                prompt_tokens=prompt_eval_count,
                completion_tokens=eval_count,
                total_tokens=prompt_eval_count + eval_count,
            )

            self._update_usage(usage)

            return LLMResponse(
                content=content,
                model=data.get("model", self.model),
                provider=self.provider,
                usage=usage,
                finish_reason="stop" if data.get("done") else None,
                raw_response=data,
                latency_seconds=latency,
            )

        except (KeyError, TypeError) as e:
            raise LLMResponseError(f"Failed to parse response: {e}")

    def _parse_chat_response(
        self,
        data: dict[str, Any],
        latency: float,
    ) -> LLMResponse:
        """Parse /api/chat response."""
        try:
            message = data.get("message", {})
            content = message.get("content", "")

            # Ollama provides token counts
            eval_count = data.get("eval_count", 0)
            prompt_eval_count = data.get("prompt_eval_count", 0)

            usage = TokenUsage(
                prompt_tokens=prompt_eval_count,
                completion_tokens=eval_count,
                total_tokens=prompt_eval_count + eval_count,
            )

            self._update_usage(usage)

            return LLMResponse(
                content=content,
                model=data.get("model", self.model),
                provider=self.provider,
                usage=usage,
                finish_reason="stop" if data.get("done") else None,
                raw_response=data,
                latency_seconds=latency,
            )

        except (KeyError, TypeError) as e:
            raise LLMResponseError(f"Failed to parse response: {e}")

    async def __aenter__(self) -> "OllamaClient":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()
