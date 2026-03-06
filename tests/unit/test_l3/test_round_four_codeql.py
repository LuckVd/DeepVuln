"""
Tests for Round 4 CodeQL Dataflow Integration.

Tests the integration of CodeQL dataflow results into RoundFourExecutor
for enhanced exploitability assessment.
"""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from src.layers.l3_analysis.rounds.round_four import (
    RoundFourExecutor,
    ExploitabilityStatus,
    ExploitabilityResult,
)
from src.layers.l3_analysis.rounds.models import (
    VulnerabilityCandidate,
    ConfidenceLevel,
    RoundResult,
)
from src.layers.l3_analysis.models import Finding, SeverityLevel, CodeLocation
from src.layers.l3_analysis.task.context_builder import (
    CallChainInfo,
    DataFlowMarker,
)


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def sample_codeql_finding():
    """Create a sample CodeQL finding with dataflow info."""
    finding = Finding(
        id="codeql-001",
        rule_id="py/sql-injection",
        type="vulnerability",
        severity=SeverityLevel.HIGH,
        confidence=0.9,
        title="SQL Injection vulnerability",
        description="User input flows to SQL query",
        location=CodeLocation(
            file="app.py",
            line=42,
            function="get_user",
        ),
        source="codeql",
        metadata={
            "has_dataflow": True,
            "sources": [
                {"type": "http_param", "description": "request.args.get('id')"}
            ],
            "sanitizers": [],
            "path": [
                {"line": 10, "description": "user input from HTTP"},
                {"line": 25, "description": "data flows through function"},
                {"line": 42, "description": "used in SQL query"},
            ],
            "codeql_confirmed": True,
        },
    )
    return finding


@pytest.fixture
def sample_codeql_finding_with_sanitizer():
    """Create a CodeQL finding with sanitizer detected."""
    finding = Finding(
        id="codeql-002",
        rule_id="py/xss",
        type="vulnerability",
        severity=SeverityLevel.MEDIUM,
        confidence=0.7,
        title="XSS vulnerability",
        description="User input flows to HTML output",
        location=CodeLocation(
            file="render.py",
            line=100,
            function="render_html",
        ),
        source="codeql",
        metadata={
            "has_dataflow": True,
            "sources": [
                {"type": "user_input", "description": "user provided content"}
            ],
            "sanitizers": [
                {"name": "html.escape", "effectiveness": "partial"}
            ],
            "path": [
                {"line": 50, "description": "user input"},
                {"line": 75, "description": "passed through html.escape"},
                {"line": 100, "description": "output to HTML"},
            ],
        },
    )
    return finding


@pytest.fixture
def sample_semgrep_finding():
    """Create a sample Semgrep finding without CodeQL data."""
    finding = Finding(
        id="semgrep-001",
        rule_id="sql-injection",
        type="vulnerability",
        severity=SeverityLevel.HIGH,
        confidence=0.8,
        title="Potential SQL Injection",
        description="Possible SQL injection",
        location=CodeLocation(
            file="db.py",
            line=200,
            function="execute_query",
        ),
        source="semgrep",
    )
    return finding


@pytest.fixture
def sample_candidate(sample_semgrep_finding):
    """Create a sample vulnerability candidate."""
    return VulnerabilityCandidate(
        id="cand-001",
        finding=sample_semgrep_finding,
        confidence=ConfidenceLevel.HIGH,
        discovered_in_round=1,
    )


# ============================================================
# Test CodeQL Index Building
# ============================================================

class TestCodeQLIndexBuilding:
    """Tests for CodeQL index building in RoundFourExecutor."""

    def test_executor_accepts_codeql_results(self, tmp_path):
        """Test that RoundFourExecutor accepts codeql_results parameter."""
        codeql_finding = Finding(
            id="codeql-001",
            rule_id="py/sql-injection",
            type="vulnerability",
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            title="SQL Injection",
            description="Test",
            location=CodeLocation(file="test.py", line=10),
            source="codeql",
        )

        executor = RoundFourExecutor(
            source_path=tmp_path,
            codeql_results=[codeql_finding],
        )

        assert executor._codeql_results is not None
        assert len(executor._codeql_results) == 1

    def test_codeql_index_built(self, tmp_path, sample_codeql_finding):
        """Test that CodeQL index is built correctly."""
        executor = RoundFourExecutor(
            source_path=tmp_path,
            codeql_results=[sample_codeql_finding],
        )

        assert executor._codeql_index is not None
        # Index should have entry for app.py:42
        assert "app.py:42" in executor._codeql_index

    def test_codeql_index_empty_when_none(self, tmp_path):
        """Test that CodeQL index is empty when no results provided."""
        executor = RoundFourExecutor(
            source_path=tmp_path,
            codeql_results=None,
        )

        assert executor._codeql_index == {}

    def test_codeql_index_empty_when_empty_list(self, tmp_path):
        """Test that CodeQL index is empty when empty list provided."""
        executor = RoundFourExecutor(
            source_path=tmp_path,
            codeql_results=[],
        )

        assert executor._codeql_index == {}

    def test_codeql_index_multiple_findings(self, tmp_path):
        """Test CodeQL index with multiple findings."""
        findings = [
            Finding(
                id=f"codeql-{i}",
                rule_id="test-rule",
                type="vulnerability",
                severity=SeverityLevel.HIGH,
                confidence=0.8,
                title=f"Test {i}",
                description="Test",
                location=CodeLocation(file=f"file{i}.py", line=(i + 1) * 10),
                source="codeql",
            )
            for i in range(5)
        ]

        executor = RoundFourExecutor(
            source_path=tmp_path,
            codeql_results=findings,
        )

        assert len(executor._codeql_index) == 5


# ============================================================
# Test CodeQL Dataflow Lookup
# ============================================================

class TestCodeQLDataflowLookup:
    """Tests for CodeQL dataflow lookup methods."""

    def test_get_codeql_dataflow_exact_match(
        self, tmp_path, sample_codeql_finding
    ):
        """Test exact match lookup for CodeQL dataflow."""
        executor = RoundFourExecutor(
            source_path=tmp_path,
            codeql_results=[sample_codeql_finding],
        )

        # Create a finding at the same location
        test_finding = Finding(
            id="test-001",
            rule_id="sql-injection",
            type="vulnerability",
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title="Test SQL",
            description="Test",
            location=CodeLocation(file="app.py", line=42),
            source="semgrep",
        )

        result = executor._get_codeql_dataflow(test_finding)
        assert result is not None
        assert result.id == "codeql-001"

    def test_get_codeql_dataflow_fuzzy_match(
        self, tmp_path, sample_codeql_finding
    ):
        """Test fuzzy match lookup (within 5 lines)."""
        executor = RoundFourExecutor(
            source_path=tmp_path,
            codeql_results=[sample_codeql_finding],
        )

        # Create a finding 3 lines away
        test_finding = Finding(
            id="test-002",
            rule_id="sql-injection",
            type="vulnerability",
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title="Test SQL",
            description="Test",
            location=CodeLocation(file="app.py", line=45),  # 3 lines away
            source="semgrep",
        )

        result = executor._get_codeql_dataflow(test_finding)
        # Should match due to fuzzy matching
        assert result is not None

    def test_get_codeql_dataflow_no_match_different_file(
        self, tmp_path, sample_codeql_finding
    ):
        """Test no match when file is different."""
        executor = RoundFourExecutor(
            source_path=tmp_path,
            codeql_results=[sample_codeql_finding],
        )

        # Create a finding in a different file
        test_finding = Finding(
            id="test-003",
            rule_id="sql-injection",
            type="vulnerability",
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title="Test SQL",
            description="Test",
            location=CodeLocation(file="other.py", line=42),  # Same line, different file
            source="semgrep",
        )

        result = executor._get_codeql_dataflow(test_finding)
        assert result is None

    def test_get_codeql_dataflow_no_match_too_far(
        self, tmp_path, sample_codeql_finding
    ):
        """Test no match when line is too far away."""
        executor = RoundFourExecutor(
            source_path=tmp_path,
            codeql_results=[sample_codeql_finding],
        )

        # Create a finding 10 lines away (outside fuzzy range)
        test_finding = Finding(
            id="test-004",
            rule_id="sql-injection",
            type="vulnerability",
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title="Test SQL",
            description="Test",
            location=CodeLocation(file="app.py", line=52),  # 10 lines away
            source="semgrep",
        )

        result = executor._get_codeql_dataflow(test_finding)
        assert result is None

    def test_get_codeql_dataflow_no_index(self, tmp_path):
        """Test lookup when no CodeQL results provided."""
        executor = RoundFourExecutor(
            source_path=tmp_path,
            codeql_results=None,
        )

        test_finding = Finding(
            id="test-005",
            rule_id="sql-injection",
            type="vulnerability",
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title="Test SQL",
            description="Test",
            location=CodeLocation(file="app.py", line=42),
            source="semgrep",
        )

        result = executor._get_codeql_dataflow(test_finding)
        assert result is None


# ============================================================
# Test CodeQL Dataflow Info Extraction
# ============================================================

class TestCodeQLDataflowInfoExtraction:
    """Tests for CodeQL dataflow info extraction."""

    def test_extract_dataflow_info_with_source(
        self, tmp_path, sample_codeql_finding
    ):
        """Test extracting dataflow info with user source."""
        executor = RoundFourExecutor(
            source_path=tmp_path,
            codeql_results=[sample_codeql_finding],
        )

        info = executor._extract_codeql_dataflow_info(sample_codeql_finding)

        assert info["has_user_source"] is True
        assert info["has_dangerous_sink"] is True

        assert info["path_length"] == 3

    def test_extract_dataflow_info_with_sanitizer(
        self, tmp_path, sample_codeql_finding_with_sanitizer
    ):
        """Test extracting dataflow info with sanitizer."""
        executor = RoundFourExecutor(
            source_path=tmp_path,
            codeql_results=[sample_codeql_finding_with_sanitizer],
        )

        info = executor._extract_codeql_dataflow_info(
            sample_codeql_finding_with_sanitizer
        )

        assert info["has_user_source"] is True
        assert len(info["sanitizers"]) > 0

    def test_extract_dataflow_info_no_metadata(self, tmp_path):
        """Test extracting dataflow info with no metadata."""
        finding = Finding(
            id="codeql-003",
            rule_id="test",
            type="vulnerability",
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title="Test",
            description="Test",
            location=CodeLocation(file="test.py", line=10),
            source="codeql",
        )

        executor = RoundFourExecutor(
            source_path=tmp_path,
            codeql_results=[finding],
        )

        info = executor._extract_codeql_dataflow_info(finding)

        assert info["has_user_source"] is False
        assert info["has_dangerous_sink"] is True  # Default

    def test_extract_dataflow_info_source_types(
        self, tmp_path
    ):
        """Test that various source types are recognized as user-controlled."""
        source_types = [
            "user_input",
            "http_param",
            "request_parameter",
            "remote_input",
        ]

        for source_type in source_types:
            finding = Finding(
                id="codeql-004",
                rule_id="test",
                type="vulnerability",
                severity=SeverityLevel.HIGH,
                confidence=0.8,
                title="Test",
                description="Test",
                location=CodeLocation(file="test.py", line=10),
                source="codeql",
                metadata={
                    "sources": [{"type": source_type, "description": "test"}]
                },
            )

            executor = RoundFourExecutor(
                source_path=tmp_path,
                codeql_results=[finding],
            )

            info = executor._extract_codeql_dataflow_info(finding)
            assert info["has_user_source"] is True, f"Source type {source_type} should be recognized"


# ============================================================
# Test Exploitability Assessment with CodeQL
# ============================================================

class TestExploitabilityWithCodeQL:
    """Tests for exploitability assessment using CodeQL dataflow."""

    @pytest.mark.asyncio
    async def test_exploitable_with_codeql_confirmation(
        self, tmp_path, sample_codeql_finding
    ):
        """Test EXPLOITABLE status when CodeQL confirms taint flow."""
        # Create a candidate at the CodeQL finding location
        finding = Finding(
            id="cand-003",
            rule_id="sql-injection",
            type="vulnerability",
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title="SQL Injection",
            description="Test",
            location=CodeLocation(file="app.py", line=42),
            source="semgrep",
        )
        candidate = VulnerabilityCandidate(
            id="cand-003",
            finding=finding,
            confidence=ConfidenceLevel.HIGH,
            discovered_in_round=1,
        )

        executor = RoundFourExecutor(
            source_path=tmp_path,
            codeql_results=[sample_codeql_finding],
        )

        # Mock context builder to return no entry point (CodeQL should take priority)
        with patch.object(executor._context_builder, 'analyze_call_chain') as mock_chain, \
             patch.object(executor._context_builder, 'analyze_data_flow') as mock_flow:

            mock_chain.return_value = CallChainInfo(
                function_name="get_user",
                file_path="app.py",
                is_entry_point=False,
                entry_point_type=None,
                callers=[],
            )
            mock_flow.return_value = []

            result = await executor._verify_exploitability(candidate)

            # CodeQL confirms exploitability
            assert result.status == ExploitabilityStatus.EXPLOITABLE
            assert result.confidence >= 0.85

            assert "CodeQL" in result.reasoning or "confirmed" in result.reasoning.lower()

    @pytest.mark.asyncio
    async def test_conditional_with_codeql_sanitizer(
        self, tmp_path, sample_codeql_finding_with_sanitizer
    ):
        """Test CONDITIONAL status when CodeQL detects sanitizers."""
        # Create candidate at the same location as CodeQL finding
        finding = Finding(
            id="cand-002",
            rule_id="xss",
            type="vulnerability",
            severity=SeverityLevel.MEDIUM,
            confidence=0.7,
            title="XSS vulnerability",
            description="Test",
            location=CodeLocation(file="render.py", line=100),
            source="semgrep",
        )
        candidate = VulnerabilityCandidate(
            id="cand-002",
            finding=finding,
            confidence=ConfidenceLevel.MEDIUM,
            discovered_in_round=1,
        )

        executor = RoundFourExecutor(
            source_path=tmp_path,
            codeql_results=[sample_codeql_finding_with_sanitizer],
        )

        result = await executor._verify_exploitability(candidate)

        # CodeQL detected sanitizers -> CONDITIONAL
        assert result.status == ExploitabilityStatus.CONDITIONAL
        assert "Sanitizers" in result.reasoning or "sanitizer" in result.reasoning.lower()

        assert "reduce" in result.reasoning.lower() or "conditional" in result.reasoning.lower()

    @pytest.mark.asyncio
    async def test_fallback_to_static_when_no_codeql(
        self, tmp_path, sample_candidate
    ):
        """Test fallback to static analysis when no CodeQL results."""
        executor = RoundFourExecutor(
            source_path=tmp_path,
            codeql_results=None,
        )

        # Mock context builder to return entry point
        with patch.object(executor._context_builder, 'analyze_call_chain') as mock_chain, \
             patch.object(executor._context_builder, 'analyze_data_flow') as mock_flow:

            mock_chain.return_value = CallChainInfo(
                function_name="execute_query",
                file_path="db.py",
                is_entry_point=True,
                entry_point_type="HTTP",
                callers=[],
            )
            mock_flow.return_value = [
                DataFlowMarker(
                    variable_name="user_input",
                    source_type="user_input",
                    source_location="param",
                    description="User input",
                )
            ]

            result = await executor._verify_exploitability(sample_candidate)
            # Should use static analysis fallback
            assert result.status == ExploitabilityStatus.EXPLOITABLE
            assert result.is_entry_point is True
            # Check for user-controlled in reasoning (actual output uses this phrasing)
            assert "user-controlled" in result.reasoning.lower() or "user input" in result.reasoning.lower()

    @pytest.mark.asyncio
    async def test_codeql_priority_over_static(
        self, tmp_path, sample_codeql_finding
    ):
        """Test that CodeQL result takes priority over static analysis."""
        # Create a candidate at CodeQL finding location
        finding = Finding(
            id="cand-004",
            rule_id="sql-injection",
            type="vulnerability",
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title="SQL Injection",
            description="Test",
            location=CodeLocation(file="app.py", line=42),
            source="semgrep",
        )
        candidate = VulnerabilityCandidate(
            id="cand-004",
            finding=finding,
            confidence=ConfidenceLevel.HIGH,
            discovered_in_round=1,
        )

        executor = RoundFourExecutor(
            source_path=tmp_path,
            codeql_results=[sample_codeql_finding],
        )

        # Even if static analysis says not exploitable, CodeQL should override
        with patch.object(executor._context_builder, 'analyze_call_chain') as mock_chain, \
             patch.object(executor._context_builder, 'analyze_data_flow') as mock_flow:

            mock_chain.return_value = CallChainInfo(
                function_name="get_user",
                file_path="app.py",
                is_entry_point=False,
                entry_point_type=None,
                callers=[],
            )
            mock_flow.return_value = []

            result = await executor._verify_exploitability(candidate)
            # CodeQL result should take priority
            assert result.status == ExploitabilityStatus.EXPLOITABLE


# ============================================================
# Test Integration Scenarios
# ============================================================

class TestCodeQLIntegrationScenarios:
    """Integration tests for CodeQL integration scenarios."""

    @pytest.mark.asyncio
    async def test_multiple_codeql_results_indexed(self, tmp_path):
        """Test that multiple CodeQL results are properly indexed."""
        findings = [
            Finding(
                id=f"codeql-{i}",
                rule_id="test-rule",
                type="vulnerability",
                severity=SeverityLevel.HIGH,
                confidence=0.8,
                title=f"Test {i}",
                description="Test",
                location=CodeLocation(file=f"file{i}.py", line=(i + 1) * 10),
                source="codeql",
                metadata={"has_dataflow": True},
            )
            for i in range(10)
        ]

        executor = RoundFourExecutor(
            source_path=tmp_path,
            codeql_results=findings,
        )

        assert len(executor._codeql_index) == 10
        # Verify each is accessible
        for i in range(10):
            key = f"file{i}.py:{(i + 1) * 10}"
            assert key in executor._codeql_index

    @pytest.mark.asyncio
    async def test_codeql_with_attack_surface_report(
        self, tmp_path, sample_codeql_finding
    ):
        """Test CodeQL integration works with attack surface report."""
        from src.layers.l1_intelligence.attack_surface.models import (
            AttackSurfaceReport,
            EntryPoint,
            EntryPointType,
            HTTPMethod,
        )

        # Create attack surface report
        report = AttackSurfaceReport(source_path=str(tmp_path))
        report.add_entry_point(EntryPoint(
            type=EntryPointType.HTTP,
            method=HTTPMethod.GET,
            path="/api/users/{id}",
            handler="get_user",
            file="app.py",
            line=40,
            framework="flask",
        ))

        executor = RoundFourExecutor(
            source_path=tmp_path,
            attack_surface_report=report,
            codeql_results=[sample_codeql_finding],
        )

        # Both attack surface and CodeQL should be available
        assert executor._attack_surface_report is not None
        assert executor._codeql_index is not None

    @pytest.mark.asyncio
    async def test_codeql_result_not_used_for_different_vulnerability(
        self, tmp_path, sample_codeql_finding, sample_candidate
    ):
        """Test that CodeQL result for one vulnerability is not used for another."""
        executor = RoundFourExecutor(
            source_path=tmp_path,
            codeql_results=[sample_codeql_finding],  # SQL injection at app.py:42
        )

        # sample_candidate is at db.py:200, different location
        result = executor._get_codeql_dataflow(sample_candidate.finding)
        # Should not find CodeQL match for this different location
        assert result is None


# ============================================================
# Test Backward Compatibility
# ============================================================

class TestBackwardCompatibility:
    """Tests for backward compatibility without CodeQL."""

    @pytest.mark.asyncio
    async def test_executor_works_without_codeql_results(self, tmp_path, sample_candidate):
        """Test that executor works correctly when no CodeQL results provided."""
        executor = RoundFourExecutor(
            source_path=tmp_path,
            codeql_results=None,
        )

        # Should work normally with static analysis
        with patch.object(executor._context_builder, 'analyze_call_chain') as mock_chain, \
             patch.object(executor._context_builder, 'analyze_data_flow') as mock_flow:

            mock_chain.return_value = CallChainInfo(
                function_name="test",
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
                )
            ]

            result = await executor._verify_exploitability(sample_candidate)

            # Should still work with static analysis
            assert result is not None

    def test_executor_with_empty_codeql_results(self, tmp_path):
        """Test that executor handles empty CodeQL results list."""
        executor = RoundFourExecutor(
            source_path=tmp_path,
            codeql_results=[],
        )

        assert executor._codeql_index == {}
        # Should not crash when trying to lookup
        finding = Finding(
            id="test",
            rule_id="test",
            type="vulnerability",
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title="Test",
            description="Test",
            location=CodeLocation(file="test.py", line=10),
            source="semgrep",
        )
        result = executor._get_codeql_dataflow(finding)
        assert result is None
