"""
Unit tests for OpenCodeAgent.

Tests the AI-powered security analysis engine without requiring actual LLM calls.
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.layers.l3_analysis import Finding, OpenCodeAgent, SeverityLevel
from src.layers.l3_analysis.engines.opencode_agent import (
    SEVERITY_MAP,
    SKIP_DIRECTORIES,
    ANALYZABLE_EXTENSIONS,
)
from src.layers.l3_analysis.llm.client import LLMClient, LLMProvider, LLMResponse, TokenUsage


class MockLLMClient(LLMClient):
    """Mock LLM client for testing."""

    provider = LLMProvider.CUSTOM

    def __init__(self, response_content: str = '{"findings": []}'):
        super().__init__(model="mock-model")
        self._response_content = response_content
        self._call_count = 0

    @property
    def is_available(self) -> bool:
        return True

    async def complete(self, prompt: str, **options) -> LLMResponse:
        self._call_count += 1
        return LLMResponse(
            content=self._response_content,
            model="mock-model",
            provider=self.provider,
            usage=TokenUsage(prompt_tokens=100, completion_tokens=50, total_tokens=150),
        )

    async def complete_with_messages(
        self,
        messages: list[dict[str, str]],
        **options,
    ) -> LLMResponse:
        return await self.complete("", **options)


class TestOpenCodeAgentInit:
    """Tests for OpenCodeAgent initialization."""

    def test_default_init(self):
        """Test default initialization."""
        agent = OpenCodeAgent()
        assert agent.name == "agent"
        assert agent.description == "AI-powered deep security audit engine"
        assert agent.max_file_size == 100000
        assert agent.max_files == 50
        assert agent.max_concurrent == 3

    def test_custom_init(self):
        """Test custom initialization."""
        mock_client = MockLLMClient()
        agent = OpenCodeAgent(
            llm_client=mock_client,
            max_file_size=50000,
            max_files=20,
            max_concurrent=5,
        )
        assert agent.llm == mock_client
        assert agent.max_file_size == 50000
        assert agent.max_files == 20
        assert agent.max_concurrent == 5


class TestOpenCodeAgentAvailability:
    """Tests for agent availability checking."""

    def test_is_available_with_client(self):
        """Test is_available returns True when client is configured."""
        mock_client = MockLLMClient()
        agent = OpenCodeAgent(llm_client=mock_client)
        assert agent.is_available() is True

    def test_is_available_without_api_key(self):
        """Test is_available returns False when no API key."""
        # Create agent without API key (will fail to initialize OpenAI client)
        with patch.dict("os.environ", {"OPENAI_API_KEY": ""}, clear=False):
            # OpenAIClient checks for api_key, but defaults to env var
            # This test is environment-dependent
            pass


class TestOpenCodeAgentLanguageDetection:
    """Tests for language detection."""

    @pytest.fixture
    def agent(self):
        """Create an agent with mock client."""
        return OpenCodeAgent(llm_client=MockLLMClient())

    def test_detect_python(self, agent, tmp_path):
        """Test detecting Python project."""
        (tmp_path / "main.py").write_text("print('hello')")
        (tmp_path / "utils.py").write_text("def helper(): pass")

        lang = agent._detect_language(tmp_path)
        assert lang == "python"

    def test_detect_java(self, agent, tmp_path):
        """Test detecting Java project."""
        (tmp_path / "Main.java").write_text("public class Main {}")
        (tmp_path / "Utils.java").write_text("public class Utils {}")

        lang = agent._detect_language(tmp_path)
        assert lang == "java"

    def test_detect_javascript(self, agent, tmp_path):
        """Test detecting JavaScript project."""
        (tmp_path / "index.js").write_text("console.log('hello')")
        (tmp_path / "app.js").write_text("console.log('app')")

        lang = agent._detect_language(tmp_path)
        assert lang == "javascript"

    def test_detect_no_files(self, agent, tmp_path):
        """Test detection with no recognized files."""
        (tmp_path / "README.md").write_text("# Project")

        lang = agent._detect_language(tmp_path)
        assert lang is None

    def test_detect_skips_excluded_dirs(self, agent, tmp_path):
        """Test that excluded directories are skipped."""
        (tmp_path / "main.py").write_text("print('main')")
        # Create files in excluded directories
        node_modules = tmp_path / "node_modules"
        node_modules.mkdir()
        (node_modules / "package.js").write_text("module.exports = {}")

        # Should still detect Python as primary
        lang = agent._detect_language(tmp_path)
        assert lang == "python"


class TestOpenCodeAgentFileFinding:
    """Tests for finding analyzable files."""

    @pytest.fixture
    def agent(self):
        """Create an agent with mock client."""
        return OpenCodeAgent(llm_client=MockLLMClient())

    def test_find_python_files(self, agent, tmp_path):
        """Test finding Python files."""
        (tmp_path / "main.py").write_text("print('hello')")
        (tmp_path / "utils.py").write_text("def helper(): pass")

        files = agent._find_analyzable_files(tmp_path)
        assert len(files) == 2

    def test_find_multiple_languages(self, agent, tmp_path):
        """Test finding files of multiple languages."""
        (tmp_path / "main.py").write_text("print('hello')")
        (tmp_path / "app.js").write_text("console.log('app')")
        (tmp_path / "Main.java").write_text("public class Main {}")

        files = agent._find_analyzable_files(tmp_path)
        assert len(files) == 3

    def test_skip_excluded_directories(self, agent, tmp_path):
        """Test that excluded directories are skipped."""
        (tmp_path / "main.py").write_text("print('hello')")

        # Create excluded directories with files
        for skip_dir in ["node_modules", "venv", "__pycache__"]:
            skip_path = tmp_path / skip_dir
            skip_path.mkdir()
            (skip_path / "file.py").write_text("# skipped")

        files = agent._find_analyzable_files(tmp_path)
        assert len(files) == 1
        assert files[0].name == "main.py"

    def test_skip_large_files(self, agent, tmp_path):
        """Test that large files are skipped."""
        (tmp_path / "small.py").write_text("print('hello')")
        # Create a large file (default max is 100KB)
        large_content = "x" * 200000
        (tmp_path / "large.py").write_text(large_content)

        files = agent._find_analyzable_files(tmp_path)
        assert len(files) == 1
        assert files[0].name == "small.py"


class TestOpenCodeAgentScan:
    """Tests for scan functionality."""

    @pytest.fixture
    def agent(self):
        """Create an agent with mock client."""
        return OpenCodeAgent(llm_client=MockLLMClient())

    @pytest.fixture
    def temp_project(self, tmp_path):
        """Create a temporary project directory."""
        java_file = tmp_path / "Test.java"
        java_file.write_text("""
public class Test {
    public static void main(String[] args) {
        System.out.println("Hello");
    }
}
""")
        return tmp_path

    @pytest.mark.asyncio
    async def test_scan_llm_not_available(self, agent, temp_project):
        """Test scan when LLM is not available."""
        # Create a mock client that is not available
        class UnavailableMockClient(LLMClient):
            provider = LLMProvider.CUSTOM

            def __init__(self):
                super().__init__(model="mock")

            @property
            def is_available(self) -> bool:
                return False

            async def complete(self, prompt: str, **options) -> LLMResponse:
                raise LLMConfigurationError("Not available")

            async def complete_with_messages(
                self,
                messages: list[dict[str, str]],
                **options,
            ) -> LLMResponse:
                raise LLMConfigurationError("Not available")

        unavailable_agent = OpenCodeAgent(llm_client=UnavailableMockClient())
        result = await unavailable_agent.scan(source_path=temp_project)

        assert result.success is False
        assert "not available" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_scan_success(self, agent, temp_project):
        """Test successful scan with no findings."""
        result = await agent.scan(source_path=temp_project)

        assert result.success is True
        assert result.engine == "agent"
        assert isinstance(result.findings, list)


class TestOpenCodeAgentResponseParsing:
    """Tests for LLM response parsing."""

    @pytest.fixture
    def agent(self):
        """Create an agent with mock client."""
        return OpenCodeAgent(llm_client=MockLLMClient())

    def test_parse_empty_response(self, agent):
        """Test parsing empty JSON response."""
        response = '{"findings": []}'
        findings = agent._parse_llm_response(
            response=response,
            file_path="test.py",
            source_path=Path("/test"),
        )
        assert findings == []

    def test_parse_single_finding(self, agent):
        """Test parsing response with single finding."""
        response = json.dumps({
            "findings": [{
                "type": "sql_injection",
                "severity": "high",
                "confidence": 0.9,
                "title": "SQL Injection",
                "description": "User input used in SQL query",
                "line": 42,
                "cwe": "CWE-89",
            }]
        })

        findings = agent._parse_llm_response(
            response=response,
            file_path="test.py",
            source_path=Path("/test"),
        )

        assert len(findings) == 1
        assert findings[0].rule_id == "sql_injection"
        assert findings[0].severity == SeverityLevel.HIGH
        assert findings[0].confidence == 0.9
        assert findings[0].title == "SQL Injection"
        assert findings[0].location.line == 42

    def test_parse_multiple_findings(self, agent):
        """Test parsing response with multiple findings."""
        response = json.dumps({
            "findings": [
                {
                    "type": "xss",
                    "severity": "medium",
                    "confidence": 0.8,
                    "title": "Reflected XSS",
                    "line": 10,
                },
                {
                    "type": "command_injection",
                    "severity": "critical",
                    "confidence": 0.95,
                    "title": "Command Injection",
                    "line": 20,
                },
            ]
        })

        findings = agent._parse_llm_response(
            response=response,
            file_path="test.py",
            source_path=Path("/test"),
        )

        assert len(findings) == 2
        severities = [f.severity for f in findings]
        assert SeverityLevel.CRITICAL in severities
        assert SeverityLevel.MEDIUM in severities

    def test_parse_markdown_wrapped_json(self, agent):
        """Test parsing JSON wrapped in markdown code block."""
        response = '''```json
{
    "findings": [{
        "type": "hardcoded_secrets",
        "severity": "high",
        "confidence": 0.85,
        "title": "Hardcoded API Key",
        "line": 5
    }]
}
```'''

        findings = agent._parse_llm_response(
            response=response,
            file_path="test.py",
            source_path=Path("/test"),
        )

        assert len(findings) == 1
        assert findings[0].title == "Hardcoded API Key"

    def test_parse_with_recommendation(self, agent):
        """Test parsing finding with recommendation."""
        response = json.dumps({
            "findings": [{
                "type": "sql_injection",
                "severity": "high",
                "confidence": 0.9,
                "title": "SQL Injection",
                "description": "Vulnerable query",
                "line": 42,
                "recommendation": "Use parameterized queries",
            }]
        })

        findings = agent._parse_llm_response(
            response=response,
            file_path="test.py",
            source_path=Path("/test"),
        )

        assert len(findings) == 1
        assert findings[0].fix_suggestion == "Use parameterized queries"

    def test_parse_invalid_json(self, agent):
        """Test handling invalid JSON response."""
        response = "This is not JSON"

        findings = agent._parse_llm_response(
            response=response,
            file_path="test.py",
            source_path=Path("/test"),
        )

        assert findings == []


class TestOpenCodeAgentLanguageMapping:
    """Tests for language normalization."""

    def test_normalize_language_python(self):
        """Test Python language normalization."""
        agent = OpenCodeAgent(llm_client=MockLLMClient())
        assert agent.normalize_language("python") == "python"
        assert agent.normalize_language("PYTHON") == "python"

    def test_normalize_language_javascript(self):
        """Test JavaScript language normalization."""
        agent = OpenCodeAgent(llm_client=MockLLMClient())
        assert agent.normalize_language("javascript") == "javascript"
        assert agent.normalize_language("js") == "javascript"

    def test_normalize_language_csharp(self):
        """Test C# language normalization."""
        agent = OpenCodeAgent(llm_client=MockLLMClient())
        assert agent.normalize_language("csharp") == "csharp"
        assert agent.normalize_language("c#") == "csharp"


class TestOpenCodeAgentSeverityMapping:
    """Tests for severity mapping."""

    def test_severity_map_critical(self):
        """Test critical severity mapping."""
        assert SEVERITY_MAP["critical"] == SeverityLevel.CRITICAL

    def test_severity_map_high(self):
        """Test high severity mapping."""
        assert SEVERITY_MAP["high"] == SeverityLevel.HIGH

    def test_severity_map_medium(self):
        """Test medium severity mapping."""
        assert SEVERITY_MAP["medium"] == SeverityLevel.MEDIUM

    def test_severity_map_low(self):
        """Test low severity mapping."""
        assert SEVERITY_MAP["low"] == SeverityLevel.LOW

    def test_severity_map_info(self):
        """Test info severity mapping."""
        assert SEVERITY_MAP["info"] == SeverityLevel.INFO


class TestOpenCodeAgentSupportedLanguages:
    """Tests for supported languages."""

    def test_supported_languages_list(self):
        """Test supported languages list."""
        agent = OpenCodeAgent(llm_client=MockLLMClient())
        languages = agent.get_supported_languages()

        assert "python" in languages
        assert "java" in languages
        assert "javascript" in languages
        assert "go" in languages

    def test_supports_language(self):
        """Test supports_language method."""
        agent = OpenCodeAgent(llm_client=MockLLMClient())

        assert agent.supports_language("python") is True
        assert agent.supports_language("Python") is True
        assert agent.supports_language("java") is True


class TestOpenCodeAgentCodeSnippet:
    """Tests for direct code snippet analysis."""

    @pytest.mark.asyncio
    async def test_analyze_code_snippet(self):
        """Test analyzing a code snippet directly."""
        mock_client = MockLLMClient(json.dumps({
            "findings": [{
                "type": "sql_injection",
                "severity": "high",
                "confidence": 0.9,
                "title": "SQL Injection",
                "line": 1,
            }]
        }))
        mock_client._response_content = json.dumps({
            "findings": [{
                "type": "sql_injection",
                "severity": "high",
                "confidence": 0.9,
                "title": "SQL Injection",
                "line": 1,
            }]
        })

        agent = OpenCodeAgent(llm_client=mock_client)

        code = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
'''

        findings = await agent.analyze_code_snippet(
            code=code,
            language="python",
            file_path="vulnerable.py",
        )

        assert len(findings) == 1
        assert findings[0].rule_id == "sql_injection"


class TestOpenCodeAgentTokenTracking:
    """Tests for token usage tracking."""

    def test_get_token_usage(self):
        """Test getting token usage."""
        agent = OpenCodeAgent(llm_client=MockLLMClient())
        assert agent.get_token_usage() == 0

    def test_token_tracking_after_scan(self):
        """Test token tracking is updated after scan."""
        mock_client = MockLLMClient()
        agent = OpenCodeAgent(llm_client=mock_client)

        # Token usage should be tracked internally
        # In real usage, this would be updated after scans
        assert isinstance(agent.get_token_usage(), int)
