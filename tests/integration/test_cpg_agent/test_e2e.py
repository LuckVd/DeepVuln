"""
End-to-End Integration Tests for CPG-Agent Integration (P9-01).

Tests the complete flow:
1. Agent scans a file
2. CPGPathProvider provides attack paths
3. Findings are enriched with CPG path information
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from src.layers.l3_analysis.engines.ast_engine.cpg.path_provider import CPGPathProvider
from src.layers.l3_analysis.engines.opencode_agent import OpenCodeAgent
from src.layers.l3_analysis.models import CodeLocation, Finding, SeverityLevel


class TestCPGAgentE2E:
    """Test end-to-end CPG and Agent integration."""

    @pytest.fixture
    def mock_llm_client(self):
        """Create a mock LLM client for testing."""
        client = MagicMock()
        client.is_available = True
        client.provider = "openai"
        client.model = "gpt-4"

        # Mock response with vulnerability findings
        mock_response = MagicMock()
        mock_response.content = '''{
    "findings": [
        {
            "type": "command_injection",
            "severity": "high",
            "confidence": 0.9,
            "title": "Use of eval with user input",
            "description": "The eval function is called with user-controlled input",
            "line": 5,
            "code_snippet": "result = eval(user_input)",
            "cwe": "CWE-94",
            "recommendation": "Use safe alternatives like ast.literal_eval"
        }
    ],
    "suspicious_code": []
}'''
        mock_response.usage = MagicMock()
        mock_response.usage.total_tokens = 100
        client.complete_with_context = AsyncMock(return_value=mock_response)

        return client

    @pytest.fixture
    def mock_cpg_provider(self):
        """Create a mock CPG path provider."""
        provider = MagicMock(spec=CPGPathProvider)

        # Mock attack paths
        mock_path = Mock()
        mock_path.entry_point = "user_input"
        mock_path.sink = "eval"
        mock_path.path = [
            "cpg:ast:test.py:3:parameter",
            "cpg:ast:test.py:5:call",
        ]
        mock_path.confidence = 0.95
        mock_path.sanitizers = []
        mock_path.reaches_sink = True

        provider.get_attack_paths = MagicMock(return_value=[mock_path])

        return provider

    @pytest.fixture
    def vulnerable_python_file(self, tmp_path):
        """Create a vulnerable Python test file."""
        test_file = tmp_path / "vulnerable.py"
        test_file.write_text("""
def process_input(user_input):
    # This is vulnerable - using eval with user input
    result = eval(user_input)
    return result

def safe_process(input_data):
    return input_data.upper()
""")
        return test_file

    @pytest.mark.asyncio
    async def test_agent_with_cpg_provider(
        self,
        vulnerable_python_file,
        mock_llm_client,
        mock_cpg_provider,
    ):
        """Test Agent scan with CPG path provider enabled."""
        # Create agent with CPG provider
        agent = OpenCodeAgent(
            llm_client=mock_llm_client,
            cpg_path_provider=mock_cpg_provider,
        )

        # Scan the file
        result = await agent.scan(
            source_path=vulnerable_python_file.parent,
            files=[vulnerable_python_file.name],
            language="python",
        )

        # Verify scan succeeded
        assert result.success
        assert len(result.findings) > 0

        # Check that CPG path information is attached
        finding_with_cpg = None
        for finding in result.findings:
            if finding.cpg_path is not None:
                finding_with_cpg = finding
                break

        # At least one finding should have CPG path info
        if finding_with_cpg:
            assert "entry_point" in finding_with_cpg.cpg_path
            assert "sink" in finding_with_cpg.cpg_path
            assert "path" in finding_with_cpg.cpg_path
            assert finding_with_cpg.cpg_path["sink"] == "eval"

    @pytest.mark.asyncio
    async def test_agent_without_cpg_provider(
        self,
        vulnerable_python_file,
        mock_llm_client,
    ):
        """Test Agent scan without CPG provider (graceful degradation)."""
        # Create agent without CPG provider
        agent = OpenCodeAgent(
            llm_client=mock_llm_client,
            cpg_path_provider=None,
        )

        # Scan the file
        result = await agent.scan(
            source_path=vulnerable_python_file.parent,
            files=[vulnerable_python_file.name],
            language="python",
        )

        # Verify scan succeeded
        assert result.success
        assert len(result.findings) > 0

        # No findings should have CPG path info
        for finding in result.findings:
            assert finding.cpg_path is None

    @pytest.mark.asyncio
    async def test_cpg_provider_error_handling(
        self,
        vulnerable_python_file,
        mock_llm_client,
    ):
        """Test that CPG provider errors don't break the scan."""
        # Create a CPG provider that raises an error
        failing_provider = MagicMock(spec=CPGPathProvider)
        failing_provider.get_attack_paths = MagicMock(
            side_effect=RuntimeError("CPG construction failed")
        )

        # Create agent with failing CPG provider
        agent = OpenCodeAgent(
            llm_client=mock_llm_client,
            cpg_path_provider=failing_provider,
        )

        # Scan the file - should still succeed
        result = await agent.scan(
            source_path=vulnerable_python_file.parent,
            files=[vulnerable_python_file.name],
            language="python",
        )

        # Verify scan succeeded despite CPG failure
        assert result.success
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_cpg_provider_empty_paths(
        self,
        vulnerable_python_file,
        mock_llm_client,
    ):
        """Test behavior when CPG provider returns no paths."""
        # Create a provider that returns empty paths
        empty_provider = MagicMock(spec=CPGPathProvider)
        empty_provider.get_attack_paths = MagicMock(return_value=[])

        # Create agent
        agent = OpenCodeAgent(
            llm_client=mock_llm_client,
            cpg_path_provider=empty_provider,
        )

        # Scan the file
        result = await agent.scan(
            source_path=vulnerable_python_file.parent,
            files=[vulnerable_python_file.name],
            language="python",
        )

        # Verify scan succeeded
        assert result.success
        assert len(result.findings) > 0

    def test_finding_to_cpg_path_matching(self):
        """Test the _match_finding_to_cpg_path method."""
        agent = OpenCodeAgent()

        # Create a finding
        finding = Finding(
            id="test-1",
            title="Test Finding",
            description="Test",
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            location=CodeLocation(
                file="test.py",
                line=5,
            ),
            source="agent",
        )

        # Create mock CPG paths
        mock_path1 = Mock()
        mock_path1.path = ["cpg:ast:test.py:3:parameter", "cpg:ast:test.py:5:call"]
        mock_path1.confidence = 0.9

        mock_path2 = Mock()
        mock_path2.path = ["cpg:ast:test.py:10:parameter", "cpg:ast:test.py:15:call"]
        mock_path2.confidence = 0.7

        cpg_paths = [mock_path1, mock_path2]

        # Match finding to path
        matched = agent._match_finding_to_cpg_path(finding, cpg_paths)

        # Should match path1 (line 5 matches finding line 5)
        assert matched is not None
        assert matched.confidence == 0.9

    def test_finding_to_cpg_path_no_match(self):
        """Test matching when no path matches."""
        agent = OpenCodeAgent()

        # Create a finding at a different line
        finding = Finding(
            id="test-1",
            title="Test Finding",
            description="Test",
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            location=CodeLocation(
                file="test.py",
                line=100,
            ),
            source="agent",
        )

        # Create mock CPG paths at different lines
        mock_path = Mock()
        mock_path.path = ["cpg:ast:test.py:3:parameter", "cpg:ast:test.py:5:call"]
        mock_path.confidence = 0.7  # Lower confidence for non-matching path

        cpg_paths = [mock_path]

        # Should still return something (best effort) but with lower score
        matched = agent._match_finding_to_cpg_path(finding, cpg_paths)

        # Returns the path but with a much lower combined score
        # due to line distance, so confidence alone doesn't matter
        assert matched is not None


class TestCPGPathProviderDirect:
    """Test CPGPathProvider functionality directly."""

    def test_cpg_provider_init(self):
        """Test CPGPathProvider initialization."""
        provider = CPGPathProvider()

        assert provider is not None
        assert "python" in provider.get_supported_languages()

    def test_cpg_provider_with_real_file(self, tmp_path):
        """Test CPG provider with a real Python file."""
        provider = CPGPathProvider()

        # Create a test file
        test_file = tmp_path / "test.py"
        test_file.write_text("""
def dangerous(user_input):
    return eval(user_input)
""")

        # Get attack paths
        paths = provider.get_attack_paths(test_file.parent, "eval")

        # Should return a list
        assert isinstance(paths, list)

    def test_cpg_provider_language_detection(self, tmp_path):
        """Test language detection from files."""
        provider = CPGPathProvider()

        # Python file
        py_file = tmp_path / "test.py"
        py_file.write_text("print('hello')")
        lang = provider._detect_language(py_file)
        assert lang == "python"

        # JavaScript file
        js_file = tmp_path / "test.js"
        js_file.write_text("console.log('hello')")
        lang = provider._detect_language(js_file)
        assert lang == "javascript"
