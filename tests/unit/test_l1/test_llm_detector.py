"""Tests for LLM-assisted HTTP entry point detection."""

import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from src.layers.l1_intelligence.attack_surface.llm_detector import (
    LLMHTTPDetector,
    LLMFullDetector,
    ProjectTreeGenerator,
    HybridHTTPDetector,
    create_hybrid_detector,
    LLMEntryPoint,
    ProjectStructureAnalysis,
    FileAnalysisResult,
    PROJECT_STRUCTURE_PROMPT,
    ENTRY_POINT_DETECTION_PROMPT,
    BATCH_ENTRY_POINT_DETECTION_PROMPT,
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
        # Mock LLM response - need to mock complete method for new implementation
        response_json = {
            "entry_points": [
                {"method": "GET", "path": "/api/users", "handler": "get_users", "line": 42}
            ],
            "framework_detected": "custom",
            "confidence": 0.9,
        }

        mock_response = MagicMock()
        mock_response.content = json.dumps(response_json)

        # Mock the complete method (used by new implementation)
        mock_llm_client.complete = AsyncMock(return_value=mock_response)

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
                {"method": "GET", "path": "/", "handler": "handle_get", "line": 10},
                {"method": "POST", "path": "/upload", "handler": "handle_post", "line": 20},
                {"method": "PUT", "path": "/update", "handler": "handle_put", "line": 30},
            ],
            "framework_detected": "custom",
            "confidence": 0.85,
        }

        mock_response = MagicMock()
        mock_response.content = json.dumps(response_json)

        mock_llm_client.complete = AsyncMock(return_value=mock_response)

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
            "framework_detected": "unknown",
            "confidence": 0.0,
        }

        mock_response = MagicMock()
        mock_response.content = json.dumps(response_json)

        mock_llm_client.complete = AsyncMock(return_value=mock_response)

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
                {"method": "GET", "path": "/", "handler": "handler", "line": 1}
            ],
            "framework_detected": "custom",
            "confidence": 0.8,
        }

        mock_response = MagicMock()
        mock_response.content = json.dumps(response_json)

        mock_llm_client.complete = AsyncMock(return_value=mock_response)

        code = "class Handler: pass"

        # First call should hit LLM
        entry_points1 = await detector.detect(code, Path("/test/handler.py"))
        assert len(entry_points1) == 1

        # Second call should use cache
        entry_points2 = await detector.detect(code, Path("/test/handler.py"))
        assert len(entry_points2) == 1

        # LLM should only be called once
        assert mock_llm_client.complete.call_count == 1

    @pytest.mark.asyncio
    async def test_detect_without_llm_client(self):
        """Test detection fails gracefully without LLM client."""
        detector = LLMHTTPDetector()

        code = "class Handler: pass"
        entry_points = await detector.detect(code, Path("/test/handler.py"))

        assert len(entry_points) == 0

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
                {"method": "POST", "path": "/submit", "handler": "submit_handler", "line": 10}
            ],
            "framework_detected": "custom",
            "confidence": 0.8,
        }

        mock_response = MagicMock()
        mock_response.content = json.dumps(response_json)

        mock_llm_client.complete = AsyncMock(return_value=mock_response)

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
        formatted = ENTRY_POINT_DETECTION_PROMPT.format(
            file_path="/test/handler.py",
            language="Python",
            code="class Handler: pass",
        )

        assert "/test/handler.py" in formatted
        assert "class Handler: pass" in formatted
        assert "entry points" in formatted.lower()
        assert "JSON" in formatted

    def test_prompt_includes_instructions(self):
        """Test that prompt includes detection instructions."""
        formatted = ENTRY_POINT_DETECTION_PROMPT.format(
            file_path="/test/handler.py",
            language="Python",
            code="pass",
        )

        assert "HTTP" in formatted
        assert "RPC" in formatted
        assert "handler" in formatted.lower()


class TestProjectTreeGenerator:
    """Tests for ProjectTreeGenerator."""

    @pytest.fixture
    def generator(self):
        """Create a generator instance."""
        return ProjectTreeGenerator(max_depth=3, max_files=100)

    def test_generate_tree(self, generator, tmp_path):
        """Test generating project tree."""
        # Create a simple project structure
        (tmp_path / "main.py").write_text("print('hello')")
        (tmp_path / "handler.py").write_text("def handler(): pass")
        (tmp_path / "api").mkdir()
        (tmp_path / "api" / "routes.py").write_text("def routes(): pass")

        tree = generator.generate(tmp_path)

        assert tmp_path.name in tree
        assert "main.py" in tree
        assert "handler.py" in tree
        assert "api/" in tree
        assert "routes.py" in tree

    def test_generate_tree_skips_hidden_dirs(self, generator, tmp_path):
        """Test that hidden directories are skipped."""
        (tmp_path / "main.py").write_text("print('hello')")
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text("[core]")

        tree = generator.generate(tmp_path)

        assert "main.py" in tree
        assert ".git" not in tree

    def test_generate_tree_skips_node_modules(self, generator, tmp_path):
        """Test that node_modules is skipped."""
        (tmp_path / "main.py").write_text("print('hello')")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "package.js").write_text("module.exports = {}")

        tree = generator.generate(tmp_path)

        assert "main.py" in tree
        assert "node_modules" not in tree

    def test_detect_languages(self, generator, tmp_path):
        """Test language detection."""
        (tmp_path / "main.py").write_text("print('hello')")
        (tmp_path / "app.go").write_text("package main")
        (tmp_path / "index.ts").write_text("console.log('hi')")

        languages = generator.detect_languages(tmp_path)

        assert "Python" in languages
        assert "Go" in languages
        assert "TypeScript" in languages

    def test_get_source_files(self, generator, tmp_path):
        """Test getting source files."""
        (tmp_path / "main.py").write_text("print('hello')")
        (tmp_path / "handler.go").write_text("package main")
        (tmp_path / "test_main.py").write_text("def test(): pass")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "pkg.js").write_text("// pkg")

        source_files = generator.get_source_files(tmp_path)

        file_names = [f.name for f in source_files]
        assert "main.py" in file_names
        assert "handler.go" in file_names
        assert "test_main.py" not in file_names  # Test files skipped
        assert "pkg.js" not in file_names  # node_modules skipped


class TestLLMFullDetector:
    """Tests for LLMFullDetector."""

    @pytest.fixture
    def mock_llm_client(self):
        """Create a mock LLM client."""
        client = MagicMock()
        client.complete = AsyncMock()
        return client

    @pytest.fixture
    def detector(self, mock_llm_client):
        """Create a detector with mock client."""
        return LLMFullDetector(
            llm_client=mock_llm_client,
            model="test-model",
            max_files_to_analyze=10,
        )

    def test_init(self, mock_llm_client):
        """Test detector initialization."""
        detector = LLMFullDetector(llm_client=mock_llm_client, model="test-model")

        assert detector.llm_client == mock_llm_client
        assert detector.model == "test-model"
        assert detector._tree_generator is not None

    @pytest.mark.asyncio
    async def test_detect_full_phase1_structure_analysis(self, detector, mock_llm_client, tmp_path):
        """Test Phase 1: Project structure analysis."""
        # Create a simple project
        (tmp_path / "main.py").write_text("print('hello')")
        (tmp_path / "api.py").write_text("def handler(): pass")

        # Mock LLM response for structure analysis
        structure_response = json.dumps({
            "target_files": ["main.py", "api.py"],
            "target_dirs": [],
            "detected_languages": ["Python"],
            "detected_frameworks": [],
            "reasoning": "Found handler files"
        })

        # Mock LLM response for batch entry point detection (includes file field)
        batch_response = json.dumps({
            "files_analyzed": 2,
            "entry_points": [
                {"file": "api.py", "type": "http", "method": "GET", "path": "/", "handler": "handler", "line": 1}
            ],
            "framework_detected": "custom",
            "confidence": 0.8
        })

        mock_llm_client.complete.side_effect = [
            MagicMock(content=structure_response),
            MagicMock(content=batch_response),
        ]

        entry_points = await detector.detect_full(tmp_path)

        assert len(entry_points) >= 1
        assert mock_llm_client.complete.call_count >= 1

    @pytest.mark.asyncio
    async def test_analyze_project_structure(self, detector, mock_llm_client, tmp_path):
        """Test project structure analysis."""
        (tmp_path / "main.py").write_text("print('hello')")

        response_json = json.dumps({
            "target_files": ["main.py"],
            "target_dirs": [],
            "detected_languages": ["Python"],
            "detected_frameworks": [],
            "reasoning": "Main file"
        })

        mock_llm_client.complete.return_value = MagicMock(content=response_json)

        analysis = await detector._analyze_project_structure(tmp_path)

        assert len(analysis.target_files) == 1
        assert "main.py" in analysis.target_files
        assert analysis.detected_languages == ["Python"]

    @pytest.mark.asyncio
    async def test_analyze_file(self, detector, mock_llm_client, tmp_path):
        """Test single file analysis."""
        file_path = tmp_path / "handler.py"
        file_path.write_text('def handle_request(): pass')

        response_json = json.dumps({
            "entry_points": [
                {"type": "http", "method": "POST", "path": "/submit", "handler": "handle_request", "line": 1}
            ],
            "framework_detected": "custom",
            "confidence": 0.9
        })

        mock_llm_client.complete.return_value = MagicMock(content=response_json)

        result = await detector._analyze_file(file_path, tmp_path)

        assert len(result.entry_points) == 1
        assert result.entry_points[0].handler == "handle_request"
        assert result.entry_points[0].method == HTTPMethod.POST

    def test_resolve_target_files(self, detector, tmp_path):
        """Test resolving target files from LLM response."""
        (tmp_path / "main.py").write_text("print('hello')")
        (tmp_path / "api").mkdir()
        (tmp_path / "api" / "handler.py").write_text("def handler(): pass")

        target_files = ["main.py"]
        target_dirs = ["api/"]

        resolved = detector._resolve_target_files(tmp_path, target_files, target_dirs)

        assert len(resolved) == 2
        file_names = {f.name for f in resolved}
        assert "main.py" in file_names
        assert "handler.py" in file_names

    def test_create_entry_point_http(self, detector, tmp_path):
        """Test creating HTTP entry point from LLM response."""
        file_path = tmp_path / "handler.py"

        data = {
            "type": "http",
            "method": "GET",
            "path": "/api/users",
            "handler": "get_users",
            "line": 42,
            "auth_required": True,
            "params": ["id", "name"],
            "description": "Get users endpoint"
        }

        entry = detector._create_entry_point(data, file_path)

        assert entry is not None
        assert entry.type == EntryPointType.HTTP
        assert entry.method == HTTPMethod.GET
        assert entry.path == "/api/users"
        assert entry.handler == "get_users"
        assert entry.auth_required is True
        assert entry.params == ["id", "name"]

    def test_create_entry_point_cron(self, detector, tmp_path):
        """Test creating Cron entry point from LLM response."""
        file_path = tmp_path / "scheduler.py"

        data = {
            "type": "cron",
            "path": "0 * * * *",
            "handler": "hourly_task",
            "line": 10,
            "description": "Hourly cleanup task"
        }

        entry = detector._create_entry_point(data, file_path)

        assert entry is not None
        assert entry.type == EntryPointType.CRON
        assert entry.handler == "hourly_task"

    def test_create_entry_point_mq(self, detector, tmp_path):
        """Test creating MQ entry point from LLM response."""
        file_path = tmp_path / "consumer.py"

        data = {
            "type": "mq",
            "path": "user-events",
            "handler": "process_user_event",
            "line": 20,
            "description": "Process user events from queue"
        }

        entry = detector._create_entry_point(data, file_path)

        assert entry is not None
        assert entry.type == EntryPointType.MQ
        assert entry.handler == "process_user_event"

    def test_create_entry_point_with_invalid_params(self, detector, tmp_path):
        """Test creating entry point with invalid params format."""
        file_path = tmp_path / "handler.py"

        # Test with params as string (should be converted to list)
        data = {
            "type": "http",
            "method": "POST",
            "path": "/submit",
            "handler": "submit",
            "params": "id"  # Single string
        }

        entry = detector._create_entry_point(data, file_path)

        assert entry is not None
        # Params should be converted to list
        assert isinstance(entry.params, list)
        assert entry.params == ["id"]

    def test_create_entry_point_with_null_params(self, detector, tmp_path):
        """Test creating entry point with null params."""
        file_path = tmp_path / "handler.py"

        data = {
            "type": "http",
            "method": "POST",
            "path": "/submit",
            "handler": "submit",
            "params": None
        }

        entry = detector._create_entry_point(data, file_path)

        assert entry is not None
        assert isinstance(entry.params, list)
        assert entry.params == []

    def test_detect_language(self, detector):
        """Test language detection from file extension."""
        assert detector._detect_language(Path("/test/main.py")) == "Python"
        assert detector._detect_language(Path("/test/main.go")) == "Go"
        assert detector._detect_language(Path("/test/main.java")) == "Java"
        assert detector._detect_language(Path("/test/main.ts")) == "TypeScript"
        assert detector._detect_language(Path("/test/main.unknown")) == "Unknown"


class TestProjectStructureAnalysis:
    """Tests for ProjectStructureAnalysis dataclass."""

    def test_create_empty(self):
        """Test creating empty analysis."""
        analysis = ProjectStructureAnalysis()

        assert analysis.target_files == []
        assert analysis.target_dirs == []
        assert analysis.reasoning == ""
        assert analysis.detected_languages == []
        assert analysis.detected_frameworks == []

    def test_create_with_data(self):
        """Test creating analysis with data."""
        analysis = ProjectStructureAnalysis(
            target_files=["main.py", "handler.py"],
            target_dirs=["api/"],
            reasoning="Found HTTP handlers",
            detected_languages=["Python"],
            detected_frameworks=["Flask"],
        )

        assert len(analysis.target_files) == 2
        assert len(analysis.target_dirs) == 1
        assert analysis.reasoning == "Found HTTP handlers"


class TestFileAnalysisResult:
    """Tests for FileAnalysisResult dataclass."""

    def test_create_empty(self):
        """Test creating empty result."""
        result = FileAnalysisResult(file_path="/test/handler.py")

        assert result.file_path == "/test/handler.py"
        assert result.entry_points == []
        assert result.framework_detected == "unknown"
        assert result.confidence == 0.0
        assert result.error is None

    def test_create_with_error(self):
        """Test creating result with error."""
        result = FileAnalysisResult(
            file_path="/test/handler.py",
            error="Failed to read file"
        )

        assert result.error == "Failed to read file"


class TestPrompts:
    """Tests for prompt templates."""

    def test_project_structure_prompt(self):
        """Test project structure prompt formatting."""
        formatted = PROJECT_STRUCTURE_PROMPT.format(
            project_name="TestProject",
            project_tree="main.py\nhandler.py",
            languages="Python, Go",
        )

        assert "TestProject" in formatted
        assert "main.py" in formatted
        assert "handler.py" in formatted
        assert "Python, Go" in formatted
        assert "target_files" in formatted

    def test_entry_point_detection_prompt(self):
        """Test entry point detection prompt formatting."""
        formatted = ENTRY_POINT_DETECTION_PROMPT.format(
            file_path="/test/handler.py",
            language="Python",
            code="def handler(): pass",
        )

        assert "/test/handler.py" in formatted
        assert "Python" in formatted
        assert "def handler(): pass" in formatted
        assert "entry_points" in formatted
        assert "HTTP" in formatted
        assert "RPC" in formatted
        assert "Cron" in formatted


class TestBatchAnalysis:
    """Tests for batch LLM analysis."""

    @pytest.fixture
    def mock_llm_client(self):
        """Create a mock LLM client."""
        client = MagicMock()
        client.complete = AsyncMock()
        return client

    @pytest.fixture
    def detector(self, mock_llm_client):
        """Create a detector with mock client."""
        return LLMFullDetector(
            llm_client=mock_llm_client,
            model="test-model",
            max_files_to_analyze=100,
        )

    def test_build_batch_content(self, detector, tmp_path):
        """Test building batch content from multiple files."""
        # Create test files
        (tmp_path / "handler1.py").write_text("def handler1(): pass")
        (tmp_path / "handler2.py").write_text("def handler2(): pass")

        files = [
            tmp_path / "handler1.py",
            tmp_path / "handler2.py",
        ]

        content = detector._build_batch_content(files, tmp_path)

        assert "handler1.py" in content
        assert "handler2.py" in content
        assert "def handler1(): pass" in content
        assert "def handler2(): pass" in content
        assert "File:" in content
        assert "Language:" in content

    def test_build_batch_content_truncates_large_files(self, detector, tmp_path):
        """Test that large files are truncated."""
        # Create a large file
        large_content = "x" * 60000  # 60KB
        (tmp_path / "large.py").write_text(large_content)

        files = [tmp_path / "large.py"]

        content = detector._build_batch_content(files, tmp_path)

        assert "truncated" in content

    def test_build_batch_content_handles_read_errors(self, detector, tmp_path):
        """Test handling of read errors."""
        # Create a file that can't be read (non-existent in list)
        files = [
            tmp_path / "exists.py",
            tmp_path / "nonexistent.py",
        ]
        (tmp_path / "exists.py").write_text("def handler(): pass")

        # Should not raise, just skip the unreadable file
        content = detector._build_batch_content(files, tmp_path)

        assert "exists.py" in content
        assert "nonexistent.py" not in content

    def test_parse_batch_response(self, detector, tmp_path):
        """Test parsing batch LLM response."""
        response = json.dumps({
            "files_analyzed": 2,
            "entry_points": [
                {
                    "file": "handler1.py",
                    "type": "http",
                    "method": "GET",
                    "path": "/api/test",
                    "handler": "test_handler",
                    "line": 10,
                },
                {
                    "file": "handler2.py",
                    "type": "http",
                    "method": "POST",
                    "path": "/api/submit",
                    "handler": "submit_handler",
                    "line": 20,
                },
            ],
            "framework_detected": "custom",
            "confidence": 0.9,
        })

        entry_points = detector._parse_batch_response(response, tmp_path)

        assert len(entry_points) == 2
        assert entry_points[0].path == "/api/test"
        assert entry_points[0].method == HTTPMethod.GET
        assert entry_points[1].path == "/api/submit"
        assert entry_points[1].method == HTTPMethod.POST

    def test_parse_batch_response_missing_file(self, detector, tmp_path):
        """Test parsing batch response with missing file info."""
        response = json.dumps({
            "files_analyzed": 1,
            "entry_points": [
                {
                    "type": "http",
                    "method": "GET",
                    "path": "/api/test",
                    "handler": "test_handler",
                    # Missing "file" field
                },
            ],
            "framework_detected": "unknown",
            "confidence": 0.5,
        })

        entry_points = detector._parse_batch_response(response, tmp_path)

        # Entry points without file info should be skipped
        assert len(entry_points) == 0

    def test_parse_batch_response_empty(self, detector, tmp_path):
        """Test parsing empty batch response."""
        response = json.dumps({
            "files_analyzed": 2,
            "entry_points": [],
            "framework_detected": "unknown",
            "confidence": 0.0,
        })

        entry_points = detector._parse_batch_response(response, tmp_path)

        assert len(entry_points) == 0

    def test_parse_batch_response_invalid_json(self, detector, tmp_path):
        """Test parsing invalid JSON response."""
        response = "This is not valid JSON"

        entry_points = detector._parse_batch_response(response, tmp_path)

        assert len(entry_points) == 0

    @pytest.mark.asyncio
    async def test_analyze_files_batch_small(self, detector, mock_llm_client, tmp_path):
        """Test batch analysis with small number of files."""
        # Create test files
        (tmp_path / "handler.py").write_text("def handler(): pass")

        # Mock structure analysis response
        structure_response = json.dumps({
            "target_files": ["handler.py"],
            "target_dirs": [],
            "detected_languages": ["Python"],
            "detected_frameworks": [],
            "reasoning": "Test",
        })

        # Mock batch analysis response
        batch_response = json.dumps({
            "files_analyzed": 1,
            "entry_points": [
                {
                    "file": "handler.py",
                    "type": "http",
                    "method": "GET",
                    "path": "/test",
                    "handler": "handler",
                    "line": 1,
                }
            ],
            "framework_detected": "custom",
            "confidence": 0.8,
        })

        mock_llm_client.complete.side_effect = [
            MagicMock(content=structure_response),
            MagicMock(content=batch_response),
        ]

        entry_points = await detector.detect_full(tmp_path, batch_size=50, use_batch=True)

        assert len(entry_points) == 1
        assert entry_points[0].path == "/test"

    @pytest.mark.asyncio
    async def test_analyze_files_batch_multiple_batches(self, mock_llm_client, tmp_path):
        """Test batch analysis with multiple batches."""
        # Create detector with small batch size for testing
        detector = LLMFullDetector(
            llm_client=mock_llm_client,
            model="test-model",
            max_files_to_analyze=10,
        )

        # Create 5 test files with enough content to force multiple batches
        for i in range(5):
            # Each file is ~50 chars, so 5 files = ~250 chars
            (tmp_path / f"handler{i}.py").write_text(f"def handler{i}(): pass\n" * 2)

        # Mock structure analysis response
        structure_response = json.dumps({
            "target_files": [f"handler{i}.py" for i in range(5)],
            "target_dirs": [],
            "detected_languages": ["Python"],
            "detected_frameworks": [],
            "reasoning": "Test",
        })

        # Mock batch responses - provide enough responses for multiple batches
        batch_response = json.dumps({
            "files_analyzed": 3,
            "entry_points": [
                {
                    "file": "handler0.py",
                    "type": "http",
                    "method": "GET",
                    "path": "/api/0",
                    "handler": "handler0",
                    "line": 1,
                }
            ],
            "framework_detected": "custom",
            "confidence": 0.8,
        })

        batch_response2 = json.dumps({
            "files_analyzed": 2,
            "entry_points": [
                {
                    "file": "handler3.py",
                    "type": "http",
                    "method": "POST",
                    "path": "/api/3",
                    "handler": "handler3",
                    "line": 1,
                }
            ],
            "framework_detected": "custom",
            "confidence": 0.8,
        })

        # Provide more responses than needed to handle fallback scenarios
        mock_llm_client.complete.side_effect = [
            MagicMock(content=structure_response),
            MagicMock(content=batch_response),
            MagicMock(content=batch_response2),
            MagicMock(content=batch_response2),  # Extra for fallback
            MagicMock(content=batch_response2),  # Extra for fallback
            MagicMock(content=batch_response2),  # Extra for fallback
        ]

        # Use max_batch_chars=100 to create multiple batches (each file is ~50 chars)
        entry_points = await detector.detect_full(tmp_path, max_batch_chars=100, use_batch=True)

        # Should find entry points from batches
        assert len(entry_points) >= 1
        # Should have multiple LLM calls: 1 structure + multiple batches
        assert mock_llm_client.complete.call_count >= 2

    @pytest.mark.asyncio
    async def test_batch_size_parameter(self, mock_llm_client, tmp_path):
        """Test that max_batch_chars parameter is respected."""
        detector = LLMFullDetector(
            llm_client=mock_llm_client,
            model="test-model",
            max_files_to_analyze=100,
        )

        # Create 10 test files with enough content to force multiple batches
        for i in range(10):
            # Each file is ~20 chars, so 10 files = ~200 chars
            (tmp_path / f"file{i}.py").write_text(f"def func{i}(): pass")

        # Mock structure analysis
        structure_response = json.dumps({
            "target_files": [f"file{i}.py" for i in range(10)],
            "target_dirs": [],
            "detected_languages": ["Python"],
            "detected_frameworks": [],
            "reasoning": "Test",
        })

        # Mock batch responses
        batch_response = json.dumps({
            "files_analyzed": 5,
            "entry_points": [],
            "framework_detected": "unknown",
            "confidence": 0.0,
        })

        mock_llm_client.complete.side_effect = [
            MagicMock(content=structure_response),
            MagicMock(content=batch_response),
            MagicMock(content=batch_response),
        ]

        # With max_batch_chars=50, should have 2+ batches (each file is ~20 chars)
        await detector.detect_full(tmp_path, max_batch_chars=50, use_batch=True)

        # 1 structure + 2+ batches = 3+ calls
        assert mock_llm_client.complete.call_count >= 3

    @pytest.mark.asyncio
    async def test_detect_full_without_batch(self, mock_llm_client, tmp_path):
        """Test detect_full with batch disabled."""
        detector = LLMFullDetector(
            llm_client=mock_llm_client,
            model="test-model",
            max_files_to_analyze=10,
        )

        # Create 2 test files
        (tmp_path / "handler1.py").write_text("def handler1(): pass")
        (tmp_path / "handler2.py").write_text("def handler2(): pass")

        # Mock structure analysis
        structure_response = json.dumps({
            "target_files": ["handler1.py", "handler2.py"],
            "target_dirs": [],
            "detected_languages": ["Python"],
            "detected_frameworks": [],
            "reasoning": "Test",
        })

        # Mock individual file analysis
        file_response = json.dumps({
            "entry_points": [
                {
                    "type": "http",
                    "method": "GET",
                    "path": "/test",
                    "handler": "handler",
                    "line": 1,
                }
            ],
            "framework_detected": "custom",
            "confidence": 0.8,
        })

        mock_llm_client.complete.side_effect = [
            MagicMock(content=structure_response),
            MagicMock(content=file_response),
            MagicMock(content=file_response),
        ]

        # Run with use_batch=False
        entry_points = await detector.detect_full(tmp_path, batch_size=50, use_batch=False)

        # Should still work, but use individual file analysis
        assert len(entry_points) == 2
        # 1 structure + 2 individual files = 3 calls
        assert mock_llm_client.complete.call_count == 3


class TestBatchPrompt:
    """Tests for batch prompt template."""

    def test_batch_prompt_formatting(self):
        """Test that batch prompt is formatted correctly."""
        formatted = BATCH_ENTRY_POINT_DETECTION_PROMPT.format(
            file_count=5,
            files_content="File 1 content\nFile 2 content",
        )

        assert "5" in formatted
        assert "File 1 content" in formatted
        assert "entry_points" in formatted
        assert "HTTP" in formatted
        assert "RPC" in formatted
        assert "file" in formatted  # File field for batch response

    def test_batch_prompt_includes_all_types(self):
        """Test that batch prompt includes all entry point types."""
        formatted = BATCH_ENTRY_POINT_DETECTION_PROMPT.format(
            file_count=1,
            files_content="test",
        )

        assert "HTTP endpoints" in formatted
        assert "RPC/gRPC" in formatted
        assert "Message Queue" in formatted
        assert "Scheduled jobs" in formatted
        assert "WebSocket" in formatted
        assert "CLI commands" in formatted
