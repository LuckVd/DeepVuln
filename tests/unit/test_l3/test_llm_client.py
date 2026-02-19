"""
Unit tests for LLM clients.

Tests OpenAI and Ollama client functionality without actual API calls.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from src.layers.l3_analysis.llm.client import (
    LLMClient,
    LLMError,
    LLMConfigurationError,
    LLMRateLimitError,
    LLMTimeoutError,
    LLMResponseError,
    LLMProvider,
    TokenUsage,
    LLMResponse,
)
from src.layers.l3_analysis.llm.openai_client import OpenAIClient
from src.layers.l3_analysis.llm.ollama_client import OllamaClient


class TestTokenUsage:
    """Tests for TokenUsage dataclass."""

    def test_default_values(self):
        """Test default initialization."""
        usage = TokenUsage()
        assert usage.prompt_tokens == 0
        assert usage.completion_tokens == 0
        assert usage.total_tokens == 0

    def test_custom_values(self):
        """Test custom initialization."""
        usage = TokenUsage(
            prompt_tokens=100,
            completion_tokens=50,
            total_tokens=150,
        )
        assert usage.prompt_tokens == 100
        assert usage.completion_tokens == 50
        assert usage.total_tokens == 150

    def test_addition(self):
        """Test adding TokenUsage instances."""
        usage1 = TokenUsage(prompt_tokens=100, completion_tokens=50, total_tokens=150)
        usage2 = TokenUsage(prompt_tokens=200, completion_tokens=100, total_tokens=300)

        result = usage1 + usage2

        assert result.prompt_tokens == 300
        assert result.completion_tokens == 150
        assert result.total_tokens == 450


class TestLLMResponse:
    """Tests for LLMResponse dataclass."""

    def test_default_values(self):
        """Test default initialization."""
        response = LLMResponse(
            content="Hello",
            model="gpt-4",
            provider=LLMProvider.OPENAI,
        )
        assert response.content == "Hello"
        assert response.model == "gpt-4"
        assert response.provider == LLMProvider.OPENAI
        assert response.finish_reason is None

    def test_custom_values(self):
        """Test custom initialization."""
        usage = TokenUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15)
        response = LLMResponse(
            content="Hello",
            model="gpt-4",
            provider=LLMProvider.OPENAI,
            usage=usage,
            finish_reason="stop",
            latency_seconds=1.5,
        )
        assert response.usage.total_tokens == 15
        assert response.finish_reason == "stop"
        assert response.latency_seconds == 1.5


class TestOpenAIClientInit:
    """Tests for OpenAIClient initialization."""

    def test_default_init(self):
        """Test default initialization."""
        client = OpenAIClient(api_key="test-key")
        assert client.model == "gpt-4"
        assert client.max_tokens == 4096
        assert client.temperature == 0.1
        assert client.timeout == 120

    def test_custom_init(self):
        """Test custom initialization."""
        client = OpenAIClient(
            model="gpt-3.5-turbo",
            api_key="test-key",
            max_tokens=2048,
            temperature=0.5,
            base_url="https://custom.api.com/v1",
        )
        assert client.model == "gpt-3.5-turbo"
        assert client.max_tokens == 2048
        assert client.temperature == 0.5
        assert client.base_url == "https://custom.api.com/v1"

    def test_azure_init(self):
        """Test Azure OpenAI initialization."""
        client = OpenAIClient(
            is_azure=True,
            api_key="azure-key",
            azure_deployment="my-deployment",
        )
        assert client.is_azure is True
        assert client.azure_deployment == "my-deployment"
        assert client.provider == LLMProvider.AZURE

    def test_provider_property(self):
        """Test provider property."""
        client = OpenAIClient(api_key="test-key")
        assert client.provider == LLMProvider.OPENAI

    def test_is_available_with_key(self):
        """Test is_available returns True with API key."""
        client = OpenAIClient(api_key="test-key")
        assert client.is_available is True

    def test_is_available_without_key(self):
        """Test is_available returns False without API key."""
        client = OpenAIClient(api_key=None)
        assert client.is_available is False


class TestOpenAIClientAPI:
    """Tests for OpenAI client API methods."""

    @pytest.fixture
    def client(self):
        """Create a client for testing."""
        return OpenAIClient(api_key="test-key")

    def test_get_chat_url(self, client):
        """Test chat URL generation."""
        url = client._get_chat_url()
        assert url == "https://api.openai.com/v1/chat/completions"

    def test_get_chat_url_custom_base(self):
        """Test chat URL with custom base URL."""
        client = OpenAIClient(
            api_key="test-key",
            base_url="https://custom.api.com",
        )
        url = client._get_chat_url()
        assert url == "https://custom.api.com/chat/completions"

    def test_get_chat_url_azure(self):
        """Test chat URL for Azure."""
        client = OpenAIClient(
            is_azure=True,
            api_key="test-key",
            azure_deployment="my-deployment",
            azure_api_version="2024-02-01",
        )
        client.base_url = "https://my-resource.openai.azure.com"
        url = client._get_chat_url()
        assert "openai/deployments/my-deployment" in url
        assert "api-version=2024-02-01" in url


class TestOpenAIClientResponseParsing:
    """Tests for OpenAI response parsing."""

    @pytest.fixture
    def client(self):
        """Create a client for testing."""
        return OpenAIClient(api_key="test-key")

    def test_parse_successful_response(self, client):
        """Test parsing a successful API response."""
        data = {
            "choices": [{
                "message": {"content": "Hello, world!"},
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15,
            },
            "model": "gpt-4",
        }

        response = client._parse_response(data, latency=1.0)

        assert response.content == "Hello, world!"
        assert response.model == "gpt-4"
        assert response.finish_reason == "stop"
        assert response.usage.total_tokens == 15
        assert response.latency_seconds == 1.0

    def test_parse_response_no_choices(self, client):
        """Test parsing response with no choices."""
        data = {"choices": []}

        with pytest.raises(LLMResponseError):
            client._parse_response(data, latency=1.0)

    def test_parse_response_updates_usage(self, client):
        """Test that parsing updates cumulative usage."""
        data = {
            "choices": [{
                "message": {"content": "test"},
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150,
            },
            "model": "gpt-4",
        }

        client._parse_response(data, latency=1.0)
        assert client.get_total_usage().total_tokens == 150

        client._parse_response(data, latency=1.0)
        assert client.get_total_usage().total_tokens == 300


class TestOllamaClientInit:
    """Tests for OllamaClient initialization."""

    def test_default_init(self):
        """Test default initialization."""
        client = OllamaClient()
        assert client.model == "llama2"
        assert client.base_url == "http://localhost:11434"
        assert client.max_tokens == 4096
        assert client.timeout == 300  # Ollama has longer timeout

    def test_custom_init(self):
        """Test custom initialization."""
        client = OllamaClient(
            model="mistral",
            base_url="http://custom.ollama:11434",
            max_tokens=2048,
        )
        assert client.model == "mistral"
        assert client.base_url == "http://custom.ollama:11434"
        assert client.max_tokens == 2048

    def test_provider_property(self):
        """Test provider property."""
        client = OllamaClient()
        assert client.provider == LLMProvider.OLLAMA

    def test_is_available(self):
        """Test is_available always returns True for Ollama."""
        client = OllamaClient()
        # Ollama doesn't require API key, just needs server running
        assert client.is_available is True


class TestOllamaClientHelpers:
    """Tests for Ollama client helper methods."""

    @pytest.fixture
    def client(self):
        """Create a client for testing."""
        return OllamaClient()

    def test_messages_to_prompt(self, client):
        """Test converting messages to prompt string."""
        messages = [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "Hello"},
        ]

        prompt = client._messages_to_prompt(messages)

        assert "System: You are helpful." in prompt
        assert "User: Hello" in prompt
        assert "Assistant:" in prompt


class TestOllamaClientResponseParsing:
    """Tests for Ollama response parsing."""

    @pytest.fixture
    def client(self):
        """Create a client for testing."""
        return OllamaClient()

    def test_parse_generate_response(self, client):
        """Test parsing /api/generate response."""
        data = {
            "response": "Hello, world!",
            "model": "llama2",
            "done": True,
            "prompt_eval_count": 10,
            "eval_count": 5,
        }

        response = client._parse_generate_response(data, latency=2.0)

        assert response.content == "Hello, world!"
        assert response.model == "llama2"
        assert response.finish_reason == "stop"
        assert response.usage.prompt_tokens == 10
        assert response.usage.completion_tokens == 5

    def test_parse_chat_response(self, client):
        """Test parsing /api/chat response."""
        data = {
            "message": {"content": "Hello!"},
            "model": "llama2",
            "done": True,
            "prompt_eval_count": 15,
            "eval_count": 8,
        }

        response = client._parse_chat_response(data, latency=1.5)

        assert response.content == "Hello!"
        assert response.model == "llama2"
        assert response.usage.total_tokens == 23


class TestLLMExceptions:
    """Tests for LLM exception classes."""

    def test_llm_error(self):
        """Test base LLMError."""
        error = LLMError("Something went wrong")
        assert str(error) == "Something went wrong"

    def test_llm_configuration_error(self):
        """Test LLMConfigurationError."""
        error = LLMConfigurationError("API key not configured")
        assert isinstance(error, LLMError)
        assert str(error) == "API key not configured"

    def test_llm_rate_limit_error(self):
        """Test LLMRateLimitError."""
        error = LLMRateLimitError("Rate limit exceeded", retry_after=60)
        assert isinstance(error, LLMError)
        assert error.retry_after == 60

    def test_llm_timeout_error(self):
        """Test LLMTimeoutError."""
        error = LLMTimeoutError("Request timed out")
        assert isinstance(error, LLMError)

    def test_llm_response_error(self):
        """Test LLMResponseError."""
        error = LLMResponseError("Failed to parse response")
        assert isinstance(error, LLMError)


class TestLLMProviderEnum:
    """Tests for LLMProvider enum."""

    def test_provider_values(self):
        """Test provider enum values."""
        assert LLMProvider.OPENAI.value == "openai"
        assert LLMProvider.AZURE.value == "azure"
        assert LLMProvider.OLLAMA.value == "ollama"
        assert LLMProvider.CUSTOM.value == "custom"
