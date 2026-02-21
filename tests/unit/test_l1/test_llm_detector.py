"""Tests for LLM-assisted HTTP entry point detection."""

import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from src.layers.l1_intelligence.attack_surface.llm_detector import (
    LLMHTTPDetector,
    LLM_DETECTION_PROMPT,
    HybridHTTPDetector,
    create_hybrid_detector,
    LLMEntryPoint,
)
from src.layers.l1_intelligence.attack_surface.models import (
    EntryPoint,
    EntryPointType,
    HTTPMethod,
)


class TestLLMHTTPDetector:
    """Tests for LLMHTTPDetector."""

    @pytest.fixture
    def mock_llm_client(self):
        """Create a mock LLM client."""
        client = MagicMock()
        client.chat = MagicMock()
        client.chat.completions = MagicMock()
        client.chat.completions.create = AsyncMock()
        return client

    @pytest.fixture
    def detector(self, mock_llm_client):
        """Create a detector with mock client."""
        return LLMHTTPDetector(llm_client=mock_llm_client, model="test-model")

    def test_init(self, mock_llm_client):
        """Test detector initialization."""
        detector = LLMHTTPDetector(llm_client=mock_llm_client, model="test-model")
        assert detector.llm_client == mock_llm_client
        assert detector.model == "test-model"
        assert detector._cache == {}

    def test_init_without_client(self):
        """Test initialization without LLM client."""
        detector = LLMHTTPDetector()
        assert detector.llm_client is None

    @pytest.mark.asyncio
    async def test_detect_with_mock_client(self, detector, mock_llm_client):
        """Test detection with mock LLM response."""
        # Mock LLM response
        response_json = {
            "entry_points": [
                {"method": "GET", "path": "/api/users", "function": "get_users", "line": 42}
            ],
            "framework_type": "custom",
            "confidence": 0.9,
        }

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps(response_json)

        mock_llm_client.chat.completions.create.return_value = mock_response

        code = '''
class ApiHandler:
    def get_users(self):
        return self.send_json({"users": []})
'''
        entry_points = await detector.detect(code, Path("/test/api.py"))

        assert len(entry_points) == 1
        assert entry_points[0].method == HTTPMethod.GET
        assert entry_points[0].path == "/api/users"
        assert entry_points[0].handler == "get_users"
        assert entry_points[0].framework == "llm-detected"

    @pytest.mark.asyncio
    async def test_detect_multiple_entry_points(self, detector, mock_llm_client):
        """Test detection of multiple entry points."""
        response_json = {
            "entry_points": [
                {"method": "GET", "path": "/", "function": "handle_get", "line": 10},
                {"method": "POST", "path": "/upload", "function": "handle_post", "line": 20},
                {"method": "PUT", "path": "/update", "function": "handle_put", "line": 30},
            ],
            "framework_type": "custom",
            "confidence": 0.85,
        }

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps(response_json)

        mock_llm_client.chat.completions.create.return_value = mock_response

        code = "class Handler: pass"
        entry_points = await detector.detect(code, Path("/test/handler.py"))

        assert len(entry_points) == 3
        methods = {ep.method for ep in entry_points}
        assert HTTPMethod.GET in methods
        assert HTTPMethod.POST in methods
        assert HTTPMethod.PUT in methods

    @pytest.mark.asyncio
    async def test_detect_no_entry_points(self, detector, mock_llm_client):
        """Test detection when no entry points are found."""
        response_json = {
            "entry_points": [],
            "framework_type": "unknown",
            "confidence": 0.0,
        }

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps(response_json)

        mock_llm_client.chat.completions.create.return_value = mock_response

        code = '''
class Calculator:
    def add(self, a, b):
        return a + b
'''
        entry_points = await detector.detect(code, Path("/test/calc.py"))

        assert len(entry_points) == 0

    @pytest.mark.asyncio
    async def test_detect_with_caching(self, detector, mock_llm_client):
        """Test that caching works correctly."""
        response_json = {
            "entry_points": [
                {"method": "GET", "path": "/", "function": "handler", "line": 1}
            ],
            "framework_type": "custom",
            "confidence": 0.8,
        }

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps(response_json)

        mock_llm_client.chat.completions.create.return_value = mock_response

        code = "class Handler: pass"

        # First call should hit LLM
        entry_points1 = await detector.detect(code, Path("/test/handler.py"))
        assert len(entry_points1) == 1

        # Second call should use cache
        entry_points2 = await detector.detect(code, Path("/test/handler.py"))
        assert len(entry_points2) == 1

        # LLM should only be called once
        assert mock_llm_client.chat.completions.create.call_count == 1

    @pytest.mark.asyncio
    async def test_detect_without_llm_client(self):
        """Test detection fails gracefully without LLM client."""
        detector = LLMHTTPDetector()

        code = "class Handler: pass"
        entry_points = await detector.detect(code, Path("/test/handler.py"))

        assert len(entry_points) == 0

    def test_parse_response(self, detector):
        """Test parsing LLM response."""
        response = '''
Here are the detected entry points:
```json
{
    "entry_points": [
        {"method": "GET", "path": "/api/data", "function": "get_data", "line": 15}
    ],
    "framework_type": "custom",
    "confidence": 0.9
}
```
'''
        entry_points = detector._parse_response(response, Path("/test/api.py"))

        assert len(entry_points) == 1
        assert entry_points[0].method == HTTPMethod.GET
        assert entry_points[0].path == "/api/data"

    def test_parse_response_invalid_json(self, detector):
        """Test parsing invalid JSON response."""
        response = "This is not valid JSON at all"
        entry_points = detector._parse_response(response, Path("/test/api.py"))

        assert len(entry_points) == 0

    def test_parse_response_unknown_method(self, detector):
        """Test parsing response with unknown HTTP method."""
        response = json.dumps({
            "entry_points": [
                {"method": "CUSTOM", "path": "/", "function": "handler", "line": 1}
            ],
            "framework_type": "unknown",
            "confidence": 0.5,
        })

        entry_points = detector._parse_response(response, Path("/test/api.py"))

        assert len(entry_points) == 1
        # Unknown method should default to ALL
        assert entry_points[0].method == HTTPMethod.ALL

    def test_clear_cache(self, detector):
        """Test cache clearing."""
        detector._cache["key1"] = []
        detector._cache["key2"] = []

        detector.clear_cache()

        assert len(detector._cache) == 0


class TestHybridHTTPDetector:
    """Tests for HybridHTTPDetector."""

    @pytest.fixture
    def mock_static_detector(self):
        """Create a mock static detector."""
        detector = MagicMock()
        detector.detect = MagicMock(return_value=[])
        return detector

    @pytest.fixture
    def mock_llm_client(self):
        """Create a mock LLM client."""
        client = MagicMock()
        client.chat = MagicMock()
        client.chat.completions = MagicMock()
        client.chat.completions.create = AsyncMock()
        return client

    @pytest.fixture
    def hybrid_detector(self, mock_static_detector, mock_llm_client):
        """Create a hybrid detector with mocks."""
        return HybridHTTPDetector(
            static_detectors=[mock_static_detector],
            llm_client=mock_llm_client,
            enable_llm=True,
        )

    @pytest.mark.asyncio
    async def test_static_detection_succeeds(self, hybrid_detector, mock_static_detector):
        """Test that LLM is not called when static detection succeeds."""
        # Static detector finds entry points
        mock_static_detector.detect.return_value = [
            EntryPoint(
                type=EntryPointType.HTTP,
                method=HTTPMethod.GET,
                path="/",
                handler="handler",
                file="/test/handler.py",
                line=1,
                framework="custom",
            )
        ]

        code = '''
class HttpHandler:
    def handle_request(self):
        pass
'''
        entry_points = await hybrid_detector.detect(code, Path("/test/handler.py"))

        assert len(entry_points) == 1
        assert entry_points[0].framework == "custom"
        # Static detector should be called
        mock_static_detector.detect.assert_called_once()

    @pytest.mark.asyncio
    async def test_llm_fallback_when_static_fails(self, hybrid_detector, mock_static_detector, mock_llm_client):
        """Test LLM fallback when static detection fails."""
        # Static detector finds nothing
        mock_static_detector.detect.return_value = []

        # LLM finds entry points
        response_json = {
            "entry_points": [
                {"method": "POST", "path": "/submit", "function": "submit_handler", "line": 10}
            ],
            "framework_type": "custom",
            "confidence": 0.8,
        }

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps(response_json)

        mock_llm_client.chat.completions.create.return_value = mock_response

        # Code with enough HTTP indicators to trigger LLM fallback
        code = '''
class CustomHttpHandler:
    def submit_handler(self, request):
        return self.process(request)

    def handle_request(self):
        pass
'''
        entry_points = await hybrid_detector.detect(code, Path("/test/handler.py"))

        assert len(entry_points) == 1
        assert entry_points[0].framework == "llm-detected"
        assert entry_points[0].method == HTTPMethod.POST

    def test_should_use_llm_http_related(self, hybrid_detector):
        """Test LLM usage decision for HTTP-related files."""
        code = '''
class HttpHandler:
    def handle_request(self):
        response = self.process()
        return response
'''
        assert hybrid_detector._should_use_llm(code, Path("/test/handler.py")) is True

    def test_should_use_llm_non_http(self, hybrid_detector):
        """Test LLM usage decision for non-HTTP files."""
        code = '''
class Calculator:
    def add(self, a, b):
        return a + b
'''
        assert hybrid_detector._should_use_llm(code, Path("/test/calc.py")) is False

    def test_should_use_llm_test_file(self, hybrid_detector):
        """Test LLM usage decision for test files."""
        code = '''
class TestHandler:
    def test_request(self):
        assert True
'''
        # Test files should be skipped
        assert hybrid_detector._should_use_llm(code, Path("/test/test_handler.py")) is False

    def test_should_use_llm_small_file(self, hybrid_detector):
        """Test LLM usage decision for small files."""
        code = "pass"
        assert hybrid_detector._should_use_llm(code, Path("/test/small.py")) is False


class TestCreateHybridDetector:
    """Tests for create_hybrid_detector factory function."""

    @pytest.fixture
    def mock_llm_client(self):
        """Create a mock LLM client."""
        client = MagicMock()
        client.chat = MagicMock()
        client.chat.completions = MagicMock()
        client.chat.completions.create = AsyncMock()
        return client

    def test_create_with_defaults(self):
        """Test creating detector with default settings."""
        detector = create_hybrid_detector()

        assert detector is not None
        assert len(detector.static_detectors) > 0
        assert detector.llm_detector is None  # No client provided

    def test_create_with_llm_client(self, mock_llm_client):
        """Test creating detector with LLM client."""
        detector = create_hybrid_detector(
            llm_client=mock_llm_client,
            model="custom-model",
            enable_llm=True,
        )

        assert detector is not None
        assert detector.llm_detector is not None
        assert detector.llm_detector.model == "custom-model"

    def test_create_with_llm_disabled(self, mock_llm_client):
        """Test creating detector with LLM disabled."""
        detector = create_hybrid_detector(
            llm_client=mock_llm_client,
            enable_llm=False,
        )

        assert detector is not None
        assert detector.llm_detector is None

    def test_static_detectors_are_instantiated(self):
        """Test that all static detectors are instantiated."""
        detector = create_hybrid_detector()

        # Should have multiple static detectors
        assert len(detector.static_detectors) >= 5

        # Check some expected detector types
        detector_types = {d.__class__.__name__ for d in detector.static_detectors}
        assert "FlaskDetector" in detector_types
        assert "FastAPIDetector" in detector_types
        assert "CustomHTTPServerDetector" in detector_types


class TestLLMEntryPoint:
    """Tests for LLMEntryPoint dataclass."""

    def test_create_entry_point(self):
        """Test creating an LLMEntryPoint."""
        ep = LLMEntryPoint(
            method="GET",
            path="/api/test",
            function="test_handler",
            line=42,
            description="Test endpoint",
        )

        assert ep.method == "GET"
        assert ep.path == "/api/test"
        assert ep.function == "test_handler"
        assert ep.line == 42
        assert ep.description == "Test endpoint"

    def test_create_minimal(self):
        """Test creating a minimal LLMEntryPoint."""
        ep = LLMEntryPoint(
            method="POST",
            path="/",
            function="handler",
        )

        assert ep.method == "POST"
        assert ep.path == "/"
        assert ep.function == "handler"
        assert ep.line is None
        assert ep.description is None


class TestLLMDetectionPrompt:
    """Tests for LLM detection prompt."""

    def test_prompt_formatting(self):
        """Test that prompt is formatted correctly."""
        formatted = LLM_DETECTION_PROMPT.format(
            file_path="/test/handler.py",
            code="class Handler: pass",
        )

        assert "/test/handler.py" in formatted
        assert "class Handler: pass" in formatted
        assert "HTTP entry points" in formatted
        assert "JSON format" in formatted

    def test_prompt_includes_instructions(self):
        """Test that prompt includes detection instructions."""
        formatted = LLM_DETECTION_PROMPT.format(
            file_path="/test/handler.py",
            code="pass",
        )

        assert "HTTP method" in formatted
        assert "Path" in formatted
        assert "Function" in formatted
        assert "socket-based" in formatted.lower()
