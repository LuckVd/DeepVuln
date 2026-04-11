"""LLM configuration validation service."""

import time
from typing import Any, Dict, List, Optional
import requests


class LLMValidationService:
    """Service for validating LLM configurations and detecting capabilities."""

    # Known model context sizes (tokens)
    MODEL_CONTEXT_SIZES = {
        # OpenAI models
        "gpt-4": 8192,
        "gpt-4-32k": 32768,
        "gpt-4-turbo": 128000,
        "gpt-4-turbo-preview": 128000,
        "gpt-4o": 128000,
        "gpt-4o-mini": 128000,
        "gpt-3.5-turbo": 16385,
        "gpt-3.5-turbo-16k": 16385,
        "o1-preview": 128000,
        "o1-mini": 128000,

        # Anthropic models (via custom endpoint)
        "claude-3-opus": 200000,
        "claude-3-sonnet": 200000,
        "claude-3-haiku": 200000,
        "claude-3.5-sonnet": 200000,

        # DeepSeek
        "deepseek-chat": 128000,
        "deepseek-coder": 128000,

        # Default fallback
        "default": 4096,
    }

    def validate_config(
        self, config: Any, test_prompt: str = "Hello, are you working?"
    ) -> Dict[str, Any]:
        """Validate an LLM configuration by making a test API call.

        Args:
            config: LLMConfig object
            test_prompt: Test prompt to send

        Returns:
            Dictionary with validation result
        """
        start_time = time.time()

        try:
            # Prepare request
            headers = {"Content-Type": "application/json"}

            if config.api_key:
                headers["Authorization"] = f"Bearer {config.api_key}"

            # Build request body based on provider
            if config.provider == "openai" or config.provider == "custom":
                url = f"{config.base_url.rstrip('/')}/chat/completions"
                payload = {
                    "model": config.model,
                    "messages": [{"role": "user", "content": test_prompt}],
                    "max_tokens": 10,
                    "temperature": config.temperature,
                }
            elif config.provider == "ollama":
                url = f"{config.base_url.rstrip('/')}/api/chat"
                payload = {
                    "model": config.model,
                    "messages": [{"role": "user", "content": test_prompt}],
                    "stream": False,
                }
            else:
                return {
                    "success": False,
                    "message": f"Unsupported provider: {config.provider}",
                    "latency_ms": 0,
                }

            # Make request
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=config.timeout,
            )

            latency_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                data = response.json()

                # Extract model info from response
                model_info = {
                    "model": data.get("model", config.model),
                    "provider": config.provider,
                }

                # Get usage info if available
                if "usage" in data:
                    model_info["prompt_tokens"] = data["usage"].get("prompt_tokens", 0)
                    model_info["completion_tokens"] = data["usage"].get("completion_tokens", 0)

                return {
                    "success": True,
                    "message": "Connection successful",
                    "model_info": model_info,
                    "latency_ms": latency_ms,
                }
            else:
                return {
                    "success": False,
                    "message": f"API error: {response.status_code} - {response.text}",
                    "latency_ms": latency_ms,
                }

        except requests.exceptions.Timeout:
            return {
                "success": False,
                "message": f"Connection timeout after {config.timeout}s",
                "latency_ms": int((time.time() - start_time) * 1000),
            }
        except requests.exceptions.ConnectionError as e:
            return {
                "success": False,
                "message": f"Connection error: {str(e)}",
                "latency_ms": int((time.time() - start_time) * 1000),
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Validation failed: {str(e)}",
                "latency_ms": int((time.time() - start_time) * 1000),
            }

    def get_available_models(self, config: Any) -> List[str]:
        """Get available models from the LLM provider.

        Args:
            config: LLMConfig object

        Returns:
            List of available model names
        """
        try:
            if config.provider == "openai" or config.provider == "custom":
                # Try to fetch models from OpenAI-compatible API
                headers = {}
                if config.api_key:
                    headers["Authorization"] = f"Bearer {config.api_key}"

                url = f"{config.base_url.rstrip('/')}/models"
                response = requests.get(url, headers=headers, timeout=10)

                if response.status_code == 200:
                    data = response.json()
                    return [m["id"] for m in data.get("data", [])]
                else:
                    # Return common models as fallback
                    return self._get_common_models(config.provider)

            elif config.provider == "ollama":
                # Fetch models from Ollama
                url = f"{config.base_url.rstrip('/')}/api/tags"
                response = requests.get(url, timeout=10)

                if response.status_code == 200:
                    data = response.json()
                    return [m["name"] for m in data.get("models", [])]
                else:
                    return []

            else:
                return self._get_common_models(config.provider)

        except Exception:
            return self._get_common_models(config.provider)

    def _get_common_models(self, provider: str) -> List[str]:
        """Get common models for a provider.

        Args:
            provider: Provider name

        Returns:
            List of common model names
        """
        if provider == "openai" or provider == "custom":
            return [
                "gpt-4o",
                "gpt-4o-mini",
                "gpt-4-turbo",
                "gpt-4-turbo-preview",
                "gpt-4",
                "gpt-3.5-turbo",
                "o1-preview",
                "o1-mini",
            ]
        elif provider == "ollama":
            return [
                "llama2",
                "llama3",
                "llama3:70b",
                "mistral",
                "codellama",
            ]
        else:
            return []

    def detect_context_size(self, model: str, provider: str) -> int:
        """Auto-detect context size for a model.

        Args:
            model: Model name
            provider: Provider name

        Returns:
            Context size in tokens
        """
        # Try exact match first
        if model in self.MODEL_CONTEXT_SIZES:
            return self.MODEL_CONTEXT_SIZES[model]

        # Try partial match (for models with version suffixes)
        model_lower = model.lower()
        for known_model, size in self.MODEL_CONTEXT_SIZES.items():
            if known_model in model_lower or model_lower in known_model:
                return size

        # Provider-specific defaults
        if provider == "openai" or provider == "custom":
            if "gpt-4" in model_lower:
                return 128000  # Most GPT-4 variants now have 128K
            elif "gpt-3.5" in model_lower:
                return 16385

        # Return default fallback
        return self.MODEL_CONTEXT_SIZES["default"]
