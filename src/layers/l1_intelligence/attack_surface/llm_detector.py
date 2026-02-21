"""LLM-assisted HTTP entry point detection.

This module provides LLM-based detection for HTTP entry points
when static analysis fails to identify them in custom frameworks.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.attack_surface.models import (
    EntryPoint,
    EntryPointType,
    HTTPMethod,
)

logger = get_logger(__name__)


@dataclass
class LLMEntryPoint:
    """Entry point detected by LLM."""

    method: str
    path: str
    function: str
    line: int | None = None
    description: str | None = None


# Prompt template for LLM-based entry point detection
LLM_DETECTION_PROMPT = """Analyze the following Python code and identify all HTTP entry points (HTTP handlers, API endpoints, request handlers).

File: {file_path}

Code:
```python
{code}
```

For each HTTP entry point found, provide:
1. HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, or ALL if it handles multiple)
2. Path (URL path if known, or "/" if dynamic/unknown)
3. Function/method name that handles the request
4. Line number (if identifiable)

Important: Look for:
- Methods that handle HTTP requests (run(), handle_request(), etc.)
- Classes that process HTTP connections
- Functions called when receiving HTTP data
- Socket-based HTTP handlers
- Custom routing logic

Return JSON format:
{{
    "entry_points": [
        {{"method": "GET", "path": "/api/users", "function": "get_users", "line": 42}}
    ],
    "framework_type": "custom|flask|fastapi|django|stdlib|unknown",
    "confidence": 0.0-1.0,
    "notes": "optional notes about the detection"
}}

If no HTTP entry points are found, return:
{{"entry_points": [], "framework_type": "unknown", "confidence": 0.0}}
"""


class LLMHTTPDetector:
    """LLM-based HTTP entry point detector.

    Uses LLM to analyze code when static detection fails.
    """

    def __init__(self, llm_client: Any = None, model: str = "deepseek-chat"):
        """Initialize the LLM detector.

        Args:
            llm_client: LLM client instance (e.g., from l3_analysis).
            model: Model name to use for detection.
        """
        self.llm_client = llm_client
        self.model = model
        self.logger = get_logger(__name__)
        self._cache: dict[str, list[EntryPoint]] = {}

    async def detect(
        self,
        code: str,
        file_path: Path,
        use_cache: bool = True,
    ) -> list[EntryPoint]:
        """Detect HTTP entry points using LLM.

        Args:
            code: Source code content.
            file_path: Path to the source file.
            use_cache: Whether to use cached results.

        Returns:
            List of detected entry points.
        """
        cache_key = f"{file_path}:{hash(code)}"
        if use_cache and cache_key in self._cache:
            return self._cache[cache_key]

        if not self.llm_client:
            self.logger.warning("No LLM client configured, skipping LLM detection")
            return []

        try:
            prompt = LLM_DETECTION_PROMPT.format(
                file_path=str(file_path),
                code=code[:8000],  # Limit code size
            )

            response = await self._call_llm(prompt)
            entry_points = self._parse_response(response, file_path)

            if use_cache:
                self._cache[cache_key] = entry_points

            return entry_points

        except Exception as e:
            self.logger.error(f"LLM detection failed: {e}")
            return []

    async def _call_llm(self, prompt: str) -> str:
        """Call LLM with the given prompt.

        Args:
            prompt: The prompt to send.

        Returns:
            LLM response text.
        """
        if hasattr(self.llm_client, "chat"):
            # OpenAI-style client
            response = await self.llm_client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
            )
            return response.choices[0].message.content
        elif hasattr(self.llm_client, "ainvoke"):
            # LangChain-style client
            response = await self.llm_client.ainvoke(prompt)
            return str(response)
        else:
            raise ValueError("Unsupported LLM client type")

    def _parse_response(self, response: str, file_path: Path) -> list[EntryPoint]:
        """Parse LLM response into entry points.

        Args:
            response: LLM response text.
            file_path: Path to the source file.

        Returns:
            List of detected entry points.
        """
        entry_points = []

        try:
            # Extract JSON from response
            json_match = re.search(r"\{[\s\S]*\}", response)
            if not json_match:
                self.logger.warning("No JSON found in LLM response")
                return []

            data = json.loads(json_match.group())

            for ep_data in data.get("entry_points", []):
                method_str = ep_data.get("method", "ALL").upper()
                try:
                    method = HTTPMethod[method_str]
                except KeyError:
                    method = HTTPMethod.ALL

                entry = EntryPoint(
                    type=EntryPointType.HTTP,
                    method=method,
                    path=ep_data.get("path", "/"),
                    handler=ep_data.get("function", "unknown"),
                    file=str(file_path),
                    line=ep_data.get("line", 0),
                    framework="llm-detected",
                    metadata={
                        "framework_type": data.get("framework_type", "unknown"),
                        "confidence": data.get("confidence", 0.5),
                        "description": ep_data.get("description"),
                    },
                )
                entry_points.append(entry)

            self.logger.info(
                f"LLM detected {len(entry_points)} entry points in {file_path.name}"
            )

        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse LLM response as JSON: {e}")
        except Exception as e:
            self.logger.error(f"Error parsing LLM response: {e}")

        return entry_points

    def clear_cache(self) -> None:
        """Clear the detection cache."""
        self._cache.clear()


class HybridHTTPDetector:
    """Hybrid detector combining static and LLM-based detection.

    First attempts static detection, then falls back to LLM
    for files where no entry points were found.
    """

    def __init__(
        self,
        static_detectors: list[Any] | None = None,
        llm_client: Any = None,
        model: str = "deepseek-chat",
        enable_llm: bool = True,
    ):
        """Initialize the hybrid detector.

        Args:
            static_detectors: List of static detector instances.
            llm_client: LLM client for fallback detection.
            model: Model name for LLM detection.
            enable_llm: Whether to enable LLM fallback.
        """
        self.static_detectors = static_detectors or []
        self.llm_detector = (
            LLMHTTPDetector(llm_client, model) if enable_llm and llm_client else None
        )
        self.logger = get_logger(__name__)

    async def detect(
        self,
        code: str,
        file_path: Path,
        use_llm_fallback: bool = True,
    ) -> list[EntryPoint]:
        """Detect entry points using hybrid approach.

        Args:
            code: Source code content.
            file_path: Path to the source file.
            use_llm_fallback: Whether to use LLM fallback.

        Returns:
            List of detected entry points.
        """
        all_entry_points: list[EntryPoint] = []

        # Step 1: Run all static detectors
        for detector in self.static_detectors:
            try:
                entry_points = detector.detect(code, file_path)
                all_entry_points.extend(entry_points)
            except Exception as e:
                self.logger.debug(
                    f"Static detector {detector.__class__.__name__} failed: {e}"
                )

        # Step 2: If no entry points found and LLM is available, try LLM
        if (
            not all_entry_points
            and use_llm_fallback
            and self.llm_detector
            and self._should_use_llm(code, file_path)
        ):
            try:
                llm_entry_points = await self.llm_detector.detect(code, file_path)
                all_entry_points.extend(llm_entry_points)
            except Exception as e:
                self.logger.warning(f"LLM fallback failed: {e}")

        return all_entry_points

    def _should_use_llm(self, code: str, file_path: Path) -> bool:
        """Determine if LLM detection should be used for this file.

        Args:
            code: Source code content.
            file_path: Path to the source file.

        Returns:
            True if LLM detection should be attempted.
        """
        # Skip very small files
        if len(code) < 100:
            return False

        # Skip test files
        if "test" in file_path.name.lower():
            return False

        # Check for HTTP-related keywords
        http_indicators = [
            "http",
            "socket",
            "server",
            "request",
            "response",
            "handler",
            "route",
            "api",
        ]

        code_lower = code.lower()
        indicator_count = sum(1 for kw in http_indicators if kw in code_lower)

        # Only use LLM if file seems HTTP-related
        return indicator_count >= 2


def create_hybrid_detector(
    llm_client: Any = None,
    model: str = "deepseek-chat",
    enable_llm: bool = True,
) -> HybridHTTPDetector:
    """Create a hybrid HTTP detector with all available static detectors.

    Args:
        llm_client: LLM client for fallback detection.
        model: Model name for LLM detection.
        enable_llm: Whether to enable LLM fallback.

    Returns:
        Configured HybridHTTPDetector instance.
    """
    from src.layers.l1_intelligence.attack_surface.http_detector import (
        HTTP_DETECTORS,
    )

    static_detectors = [detector_cls() for detector_cls in HTTP_DETECTORS]

    return HybridHTTPDetector(
        static_detectors=static_detectors,
        llm_client=llm_client,
        model=model,
        enable_llm=enable_llm,
    )
