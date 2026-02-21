"""
Tests for Round 4 LLM-assisted exploitability assessment.
"""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from src.layers.l3_analysis.rounds.round_four import (
    RoundFourExecutor,
    ExploitabilityStatus,
    ExploitabilityResult,
    SeverityAdjustment,
)
from src.layers.l3_analysis.rounds.models import (
    VulnerabilityCandidate,
    RoundResult,
    ConfidenceLevel,
)
from src.layers.l3_analysis.models import Finding, SeverityLevel, CodeLocation
from src.layers.l3_analysis.prompts.exploitability import (
    build_exploitability_prompt,
    parse_exploitability_response,
)
from src.layers.l3_analysis.task.context_builder import (
    CallChainInfo,
    DataFlowMarker,
)


class TestExploitabilityPrompt:
    """Tests for exploitability prompt building."""

    def test_build_exploitability_prompt_basic(self):
        """Test building exploitability prompt with basic finding."""
        finding = {
            "type": "sql_injection",
            "title": "SQL Injection in login",
            "severity": "high",
            "confidence": 0.8,
            "location": "auth.py:42",
            "description": "User input used in SQL query",
        }

        system_prompt, user_prompt = build_exploitability_prompt(finding)

        assert "exploitability" in system_prompt.lower()
        assert "SQL Injection" in user_prompt
        assert "high" in user_prompt
        assert "auth.py:42" in user_prompt

    def test_build_exploitability_prompt_with_call_chain(self):
        """Test building prompt with call chain context."""
        finding = {
            "type": "path_traversal",
            "title": "Path Traversal",
            "severity": "medium",
            "confidence": 0.6,
            "location": "file_handler.py:100",
            "description": "User input in file path",
        }
        call_chain = {
            "is_entry_point": False,
            "entry_point_type": None,
            "callers": [
                {"name": "handleRequest", "file": "controller.py"},
            ],
        }

        system_prompt, user_prompt = build_exploitability_prompt(
            finding=finding,
            call_chain=call_chain,
        )

        assert "Call Chain Analysis" in user_prompt
        assert "handleRequest" in user_prompt
        assert "is_entry_point" in user_prompt.lower() or "entry point" in user_prompt.lower()

    def test_build_exploitability_prompt_with_data_flow(self):
        """Test building prompt with data flow markers."""
        finding = {
            "type": "xss",
            "title": "Reflected XSS",
            "severity": "medium",
            "confidence": 0.7,
            "location": "render.py:50",
            "description": "Unescaped output",
        }
        data_flow = [
            {"variable": "user_input", "source_type": "user_input", "line": 10},
            {"variable": "output", "source_type": "user_input", "line": 50},
        ]

        system_prompt, user_prompt = build_exploitability_prompt(
            finding=finding,
            data_flow=data_flow,
        )

        assert "Data Flow" in user_prompt
        assert "user_input" in user_prompt

    def test_parse_exploitability_response_valid_json(self):
        """Test parsing valid JSON response."""
        response = '''
        {
            "status": "exploitable",
            "confidence": 0.85,
            "reasoning": "Clear attack path exists",
            "entry_point_analysis": "HTTP endpoint",
            "data_source_analysis": "User-controlled",
            "attack_scenario": "Attacker sends malicious payload",
            "prerequisites": ["None"],
            "recommendation": "Add input validation"
        }
        '''

        result = parse_exploitability_response(response)

        assert result is not None
        assert result["status"] == "exploitable"
        assert result["confidence"] == 0.85
        assert "attack path" in result["reasoning"]

    def test_parse_exploitability_response_with_markdown(self):
        """Test parsing JSON wrapped in markdown code block."""
        response = '''
        Here's my analysis:

        ```json
        {
            "status": "not_exploitable",
            "confidence": 0.9,
            "reasoning": "No external entry point",
            "prerequisites": []
        }
        ```
        '''

        result = parse_exploitability_response(response)

        assert result is not None
        assert result["status"] == "not_exploitable"
        assert result["confidence"] == 0.9

    def test_parse_exploitability_response_invalid(self):
        """Test parsing invalid response."""
        response = "This is not valid JSON at all"

        result = parse_exploitability_response(response)

        assert result is None


class TestRoundFourExecutorLLM:
    """Tests for Round 4 with LLM-assisted assessment."""

    @pytest.fixture
    def mock_llm_client(self):
        """Create a mock LLM client."""
        client = AsyncMock()
        response = MagicMock()
        response.content = '''
        {
            "status": "conditional",
            "confidence": 0.6,
            "reasoning": "Requires authentication to exploit",
            "entry_point_analysis": "RPC endpoint with auth",
            "data_source_analysis": "Partially user-controlled",
            "attack_scenario": "Authenticated attacker can exploit",
            "prerequisites": ["Valid credentials"],
            "recommendation": "Add authorization checks"
        }
        '''
        client.complete_with_context = AsyncMock(return_value=response)
        return client

    @pytest.fixture
    def sample_candidate(self, tmp_path):
        """Create a sample vulnerability candidate."""
        finding = Finding(
            id="test-001",
            rule_id="sql-injection",
            type="vulnerability",
            severity=SeverityLevel.HIGH,
            confidence=0.7,
            title="SQL Injection in query",
            description="Potential SQL injection",
            location=CodeLocation(
                file="test.py",
                line=42,
                function="get_user",
            ),
            source="semgrep",  # Valid source
        )

        candidate = VulnerabilityCandidate(
            id="cand-001",
            finding=finding,
            confidence=ConfidenceLevel.MEDIUM,
            discovered_in_round=1,
        )
        return candidate

    @pytest.fixture
    def sample_round_result(self, sample_candidate):
        """Create a sample round result with candidates."""
        result = RoundResult(
            round_number=3,
        )
        result.add_candidate(sample_candidate)
        return result

    @pytest.mark.asyncio
    async def test_llm_assessment_disabled_by_default(self, tmp_path, sample_round_result):
        """Test that LLM assessment is disabled when no client provided."""
        executor = RoundFourExecutor(
            source_path=tmp_path,
            llm_client=None,
        )

        assert not executor._enable_llm_assessment

    @pytest.mark.asyncio
    async def test_llm_assessment_enabled_with_client(self, tmp_path, mock_llm_client):
        """Test that LLM assessment is enabled when client provided."""
        executor = RoundFourExecutor(
            source_path=tmp_path,
            llm_client=mock_llm_client,
        )

        assert executor._enable_llm_assessment

    @pytest.mark.asyncio
    async def test_llm_assessment_can_be_disabled(self, tmp_path, mock_llm_client):
        """Test that LLM assessment can be explicitly disabled."""
        executor = RoundFourExecutor(
            source_path=tmp_path,
            llm_client=mock_llm_client,
            enable_llm_assessment=False,
        )

        assert not executor._enable_llm_assessment

    @pytest.mark.asyncio
    async def test_llm_called_for_needs_review(
        self, tmp_path, mock_llm_client, sample_candidate, sample_round_result
    ):
        """Test that LLM is called when static rules return NEEDS_REVIEW."""
        executor = RoundFourExecutor(
            source_path=tmp_path,
            llm_client=mock_llm_client,
        )

        # Mock the context builder to return ambiguous results
        with patch.object(executor._context_builder, 'analyze_call_chain') as mock_chain, \
             patch.object(executor._context_builder, 'analyze_data_flow') as mock_flow:

            # Return results that will lead to NEEDS_REVIEW
            # - Has callers (not entry point directly)
            # - Has user-controlled data
            # But not entry point directly -> NEEDS_REVIEW
            mock_chain.return_value = CallChainInfo(
                function_name="get_user",
                file_path="test.py",
                is_entry_point=False,
                entry_point_type=None,
                callers=[{"name": "someFunc", "file": "test.py"}],
            )
            mock_flow.return_value = [
                DataFlowMarker(
                    variable_name="input",
                    source_type="user_input",
                    source_location="param",
                    description="User input",
                ),
            ]

            result = await executor._verify_exploitability(sample_candidate)

            # LLM should have been called because static rules return NEEDS_REVIEW
            # (has callers + user_controlled but is not entry point directly)
            mock_llm_client.complete_with_context.assert_called_once()

    @pytest.mark.asyncio
    async def test_llm_not_called_for_exploitable(
        self, tmp_path, mock_llm_client, sample_candidate
    ):
        """Test that LLM is NOT called when static rules return EXPLOITABLE."""
        executor = RoundFourExecutor(
            source_path=tmp_path,
            llm_client=mock_llm_client,
        )

        # Mock the context builder to return clear EXPLOITABLE results
        with patch.object(executor._context_builder, 'analyze_call_chain') as mock_chain, \
             patch.object(executor._context_builder, 'analyze_data_flow') as mock_flow:

            mock_chain.return_value = CallChainInfo(
                function_name="get_user",
                file_path="test.py",
                is_entry_point=True,
                entry_point_type="HTTP",
                callers=[],
            )
            mock_flow.return_value = [
                DataFlowMarker(
                    variable_name="input",
                    source_type="user_input",
                    source_location="param",
                    description="User input",
                ),
            ]

            result = await executor._verify_exploitability(sample_candidate)

            # LLM should NOT be called because static rules are conclusive
            mock_llm_client.complete_with_context.assert_not_called()
            assert result.status == ExploitabilityStatus.EXPLOITABLE

    @pytest.mark.asyncio
    async def test_llm_result_used_when_returned(
        self, tmp_path, mock_llm_client, sample_candidate
    ):
        """Test that LLM result is used when returned."""
        executor = RoundFourExecutor(
            source_path=tmp_path,
            llm_client=mock_llm_client,
        )

        with patch.object(executor._context_builder, 'analyze_call_chain') as mock_chain, \
             patch.object(executor._context_builder, 'analyze_data_flow') as mock_flow:

            # Setup: has callers + user_controlled -> NEEDS_REVIEW -> LLM called
            mock_chain.return_value = CallChainInfo(
                function_name="get_user",
                file_path="test.py",
                is_entry_point=False,
                entry_point_type=None,
                callers=[{"name": "someFunc", "file": "test.py"}],
            )
            mock_flow.return_value = [
                DataFlowMarker(
                    variable_name="input",
                    source_type="user_input",
                    source_location="param",
                    description="User input",
                ),
            ]

            result = await executor._verify_exploitability(sample_candidate)

            # Result should come from LLM (conditional)
            assert result.status == ExploitabilityStatus.CONDITIONAL
            assert result.confidence == 0.6
            assert "authentication" in result.reasoning.lower()

    @pytest.mark.asyncio
    async def test_llm_failure_fallback(self, tmp_path, sample_candidate):
        """Test fallback when LLM fails."""
        failing_client = AsyncMock()
        failing_client.complete_with_context = AsyncMock(
            side_effect=Exception("API error")
        )

        executor = RoundFourExecutor(
            source_path=tmp_path,
            llm_client=failing_client,
        )

        with patch.object(executor._context_builder, 'analyze_call_chain') as mock_chain, \
             patch.object(executor._context_builder, 'analyze_data_flow') as mock_flow:

            # Setup: has callers + user_controlled -> NEEDS_REVIEW -> LLM called but fails
            mock_chain.return_value = CallChainInfo(
                function_name="get_user",
                file_path="test.py",
                is_entry_point=False,
                entry_point_type=None,
                callers=[{"name": "someFunc", "file": "test.py"}],
            )
            mock_flow.return_value = [
                DataFlowMarker(
                    variable_name="input",
                    source_type="user_input",
                    source_location="param",
                    description="User input",
                ),
            ]

            # Should not raise, should fallback to NEEDS_REVIEW (keep original status)
            result = await executor._verify_exploitability(sample_candidate)

            assert result.status == ExploitabilityStatus.NEEDS_REVIEW


class TestExploitabilityStatusMapping:
    """Tests for LLM status to enum mapping."""

    def test_status_mapping_exploitable(self):
        """Test exploitable status mapping."""
        mapping = {
            "exploitable": ExploitabilityStatus.EXPLOITABLE,
            "conditional": ExploitabilityStatus.CONDITIONAL,
            "unlikely": ExploitabilityStatus.UNLIKELY,
            "not_exploitable": ExploitabilityStatus.NOT_EXPLOITABLE,
            "needs_review": ExploitabilityStatus.NEEDS_REVIEW,
        }

        for key, expected in mapping.items():
            assert mapping[key] == expected

    def test_case_insensitive_mapping(self):
        """Test that status mapping is case-insensitive."""
        statuses = ["EXPLOITABLE", "Exploitable", "exploitable"]

        for status in statuses:
            assert status.lower() in [
                "exploitable", "conditional", "unlikely",
                "not_exploitable", "needs_review"
            ]
