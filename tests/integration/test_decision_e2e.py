"""
End-to-end integration tests for CodeQL language decision.

Tests the complete decision flow including:
- Python project baseline decisions
- Java Maven project LLM decisions
- Multi-language project comparisons
- LLM vs Baseline strategy comparisons
"""

import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from src.layers.l3_analysis.decision import (
    BaselineStrategy,
    CodeQLLanguageDecider,
    DecisionConstraints,
    LanguageDecision,
    LanguageDecisionInput,
    LanguageDecisionMetrics,
    LanguageStructure,
    AttackSurfaceSummary,
    SemgrepSummary,
)
from src.layers.l3_analysis.decision.prompts import build_decision_prompt
from src.layers.l3_analysis.llm.client import (
    LLMClient,
    LLMResponse,
    LLMProvider,
)


# Mark all tests as integration
pytestmark = pytest.mark.integration


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def temp_project(tmp_path):
    """Create a temporary project directory."""
    return tmp_path


@pytest.fixture
def python_project(temp_project):
    """Create a Python project structure."""
    src_dir = temp_project / "src"
    src_dir.mkdir()
    (src_dir / "main.py").write_text("print('hello')\n")
    (temp_project / "requirements.txt").write_text("requests>=2.0\n")
    return temp_project


@pytest.fixture
def java_maven_project(temp_project):
    """Create a Java Maven project structure."""
    src_dir = temp_project / "src" / "main" / "java"
    src_dir.mkdir(parents=True)
    (src_dir / "Main.java").write_text("public class Main {}\n")
    (temp_project / "pom.xml").write_text("""<?xml version="1.0"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test</artifactId>
    <version>1.0.0</version>
    <properties>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
    </properties>
</project>
""")
    return temp_project


@pytest.fixture
def mixed_project(temp_project):
    """Create a mixed Python + JavaScript project."""
    py_dir = temp_project / "backend"
    py_dir.mkdir()
    (py_dir / "app.py").write_text("from flask import Flask\n")

    js_dir = temp_project / "frontend"
    js_dir.mkdir()
    (js_dir / "index.js").write_text("console.log('hello');\n")
    (js_dir / "package.json").write_text('{"name": "test", "version": "1.0.0"}\n')
    return temp_project


@pytest.fixture
def sample_decision_input():
    """Create a sample decision input for testing."""
    languages = [
        LanguageStructure(
            name="java",
            file_count=150,
            line_count=45000,
            percentage=45.0,
            role="primary",
        ),
        LanguageStructure(
            name="python",
            file_count=80,
            line_count=20000,
            percentage=20.0,
            role="secondary",
        ),
        LanguageStructure(
            name="javascript",
            file_count=100,
            line_count=25000,
            percentage=25.0,
            role="secondary",
        ),
    ]
    attack_surface = AttackSurfaceSummary(
        entry_points_by_language={"java": 120, "python": 50, "javascript": 80},
        total_endpoints=250,
    )
    semgrep_result = SemgrepSummary(
        findings_by_language={
            "java": {"critical": 1, "high": 3, "medium": 8, "low": 2},
            "python": {"critical": 0, "high": 2, "medium": 5, "low": 1},
        },
        total_findings=22,
    )
    return LanguageDecisionInput(
        languages=languages,
        attack_surface=attack_surface,
        semgrep_result=semgrep_result,
        constraints=DecisionConstraints(max_languages=3),
    )


@pytest.fixture
def mock_llm_client():
    """Create a mock LLM client."""
    mock_client = MagicMock(spec=LLMClient)
    mock_client.is_available = True
    return mock_client


# =============================================================================
# Baseline Decision Integration Tests
# =============================================================================


class TestBaselineDecisionE2E:
    """End-to-end tests for baseline decision strategy."""

    def test_python_project_baseline(self, python_project):
        """Test baseline decision on Python-only project."""
        languages = [
            LanguageStructure(
                name="python",
                file_count=20,
                line_count=5000,
                percentage=100.0,
                role="primary",
            ),
        ]
        input_data = LanguageDecisionInput(
            languages=languages,
            attack_surface=AttackSurfaceSummary(),
            constraints=DecisionConstraints(
                baseline_strategy=BaselineStrategy.HYBRID,
            ),
        )
        decider = CodeQLLanguageDecider(
            project_path=python_project,
            constraints=input_data.constraints,
        )
        decision = decider._make_baseline_decision(input_data)

        assert decision.decision_source == "baseline"
        assert "python" in decision.recommended_languages
        assert len(decision.recommended_languages) == 1

    def test_java_project_baseline(self, java_maven_project):
        """Test baseline decision on Java Maven project."""
        languages = [
            LanguageStructure(
                name="java",
                file_count=50,
                line_count=15000,
                percentage=100.0,
                role="primary",
            ),
        ]
        input_data = LanguageDecisionInput(
            languages=languages,
            attack_surface=AttackSurfaceSummary(),
            constraints=DecisionConstraints(
                baseline_strategy=BaselineStrategy.LANGUAGE_FIRST,
            ),
        )
        decider = CodeQLLanguageDecider(
            project_path=java_maven_project,
            constraints=input_data.constraints,
        )
        decision = decider._make_baseline_decision(input_data)

        assert decision.decision_source == "baseline"
        assert "java" in decision.recommended_languages
        assert "Language-first" in decision.reasoning_summary

    def test_all_baseline_strategies(self, sample_decision_input):
        """Test all baseline strategies produce valid decisions."""
        strategies = [
            BaselineStrategy.HYBRID,
            BaselineStrategy.LANGUAGE_FIRST,
            BaselineStrategy.ATTACK_SURFACE_FIRST,
            BaselineStrategy.SEMGREP_FIRST,
        ]
        decider = CodeQLLanguageDecider()

        for strategy in strategies:
            input_data = sample_decision_input.model_copy(
                update={"constraints": DecisionConstraints(baseline_strategy=strategy)}
            )
            decision = decider._make_baseline_decision(input_data)

            assert decision.decision_source == "baseline"
            assert len(decision.recommended_languages) > 0
            assert decision.confidence == 0.7


# =============================================================================
# LLM Decision Integration Tests
# =============================================================================


class TestLLMDecisionE2E:
    """End-to-end tests for LLM decision strategy."""

    @pytest.mark.asyncio
    async def test_llm_decision_success(self, sample_decision_input, mock_llm_client):
        """Test successful LLM decision flow."""
        llm_response = LLMResponse(
            content=json.dumps({
                "recommended_languages": ["java", "python"],
                "skipped_languages": ["javascript"],
                "confidence": 0.85,
                "recommendations": [
                    {
                        "language": "java",
                        "priority_score": 0.9,
                        "reasoning": "Primary language with most findings",
                    },
                    {
                        "language": "python",
                        "priority_score": 0.7,
                        "reasoning": "Secondary language with some findings",
                    },
                ],
            }),
            model="gpt-4",
            provider=LLMProvider.OPENAI,
        )
        mock_llm_client.complete_with_context = AsyncMock(return_value=llm_response)

        decider = CodeQLLanguageDecider(
            llm_client=mock_llm_client,
            constraints=DecisionConstraints(min_confidence=0.7),
        )
        result = await decider.decide(sample_decision_input)

        assert isinstance(result, LanguageDecision)
        assert result.decision_source == "llm"
        assert result.confidence >= 0.7
        assert "java" in result.recommended_languages

    @pytest.mark.asyncio
    async def test_llm_fallback_to_baseline(self, sample_decision_input, mock_llm_client):
        """Test that LLM failure falls back to baseline."""
        from src.layers.l3_analysis.llm.client import LLMError
        mock_llm_client.complete_with_context = AsyncMock(
            side_effect=LLMError("API unavailable")
        )

        decider = CodeQLLanguageDecider(
            llm_client=mock_llm_client,
            constraints=DecisionConstraints(min_confidence=0.7),
        )
        result = await decider.decide(sample_decision_input)

        assert isinstance(result, LanguageDecision)
        assert result.decision_source == "baseline"


# =============================================================================
# Strategy Comparison Tests
# =============================================================================


class TestStrategyComparisonE2E:
    """End-to-end tests comparing LLM and Baseline strategies."""

    def test_hybrid_vs_language_first(self, sample_decision_input):
        """Compare hybrid and language-first strategies."""
        decider = CodeQLLanguageDecider()

        hybrid_input = sample_decision_input.model_copy(
            update={"constraints": DecisionConstraints(baseline_strategy=BaselineStrategy.HYBRID)}
        )
        hybrid_decision = decider._make_baseline_decision(hybrid_input)

        lang_first_input = sample_decision_input.model_copy(
            update={"constraints": DecisionConstraints(baseline_strategy=BaselineStrategy.LANGUAGE_FIRST)}
        )
        lang_first_decision = decider._make_baseline_decision(lang_first_input)

        # Both should select the primary language first
        assert hybrid_decision.recommended_languages[0] == lang_first_decision.recommended_languages[0]

    def test_attack_surface_vs_semgrep_first(self, sample_decision_input):
        """Compare attack-surface-first and semgrep-first strategies."""
        decider = CodeQLLanguageDecider()

        attack_input = sample_decision_input.model_copy(
            update={"constraints": DecisionConstraints(baseline_strategy=BaselineStrategy.ATTACK_SURFACE_FIRST)}
        )
        attack_decision = decider._make_baseline_decision(attack_input)

        semgrep_input = sample_decision_input.model_copy(
            update={"constraints": DecisionConstraints(baseline_strategy=BaselineStrategy.SEMGREP_FIRST)}
        )
        semgrep_decision = decider._make_baseline_decision(semgrep_input)

        # Both strategies should produce valid decisions
        assert len(attack_decision.recommended_languages) > 0
        assert len(semgrep_decision.recommended_languages) > 0


# =============================================================================
# Prompt Building Tests
# =============================================================================


class TestPromptBuildingE2E:
    """End-to-end tests for prompt building."""

    def test_build_complete_prompt(self, sample_decision_input):
        """Test building a complete decision prompt."""
        prompt = build_decision_prompt(sample_decision_input)

        # Verify prompt contains key elements
        assert "java" in prompt
        assert "python" in prompt
        assert "javascript" in prompt
        assert "Security Priority" in prompt
        assert "Decision Principles" in prompt
        assert "json" in prompt.lower()

    def test_prompt_with_semgrep_results(self, sample_decision_input):
        """Test prompt includes Semgrep results when available."""
        prompt = build_decision_prompt(sample_decision_input)

        assert "critical" in prompt.lower()
        assert "high" in prompt.lower()

    def test_prompt_without_semgrep_results(self):
        """Test prompt without Semgrep results."""
        languages = [
            LanguageStructure(name="python", file_count=10, line_count=1000, percentage=100.0),
        ]
        input_data = LanguageDecisionInput(
            languages=languages,
            attack_surface=AttackSurfaceSummary(),
            semgrep_result=None,
        )
        prompt = build_decision_prompt(input_data)

        # Should still be a valid prompt
        assert "python" in prompt
        assert "Decision Principles" in prompt


# =============================================================================
# LanguageDecisionMetrics Integration Tests
# =============================================================================


class TestDecisionMetricsE2E:
    """End-to-end tests for LanguageDecisionMetrics."""

    def test_metrics_from_baseline_decision(self, sample_decision_input):
        """Test metrics collection with baseline decision."""
        import time

        decider = CodeQLLanguageDecider()
        start_time = time.perf_counter()
        decision = decider._make_baseline_decision(sample_decision_input)
        end_time = time.perf_counter()

        metrics = LanguageDecisionMetrics(
            decision_source=decision.decision_source,
            languages_selected=decision.recommended_languages,
            languages_skipped=decision.skipped_languages,
            decision_time_ms=(end_time - start_time) * 1000,
            scan_success=True,
            findings_count=0,
        )

        assert metrics.decision_source == "baseline"
        assert len(metrics.languages_selected) > 0
        assert metrics.decision_time_ms >= 0

    def test_metrics_summary_dict(self):
        """Test metrics can be converted to summary dict."""
        metrics = LanguageDecisionMetrics(
            decision_source="llm",
            languages_selected=["java", "python"],
            languages_skipped=["javascript"],
            decision_time_ms=150.5,
            findings_count=15,
        )
        summary = metrics.to_summary_dict()

        assert summary["decision_source"] == "llm"
        assert summary["languages_selected"] == ["java", "python"]
        assert summary["findings_count"] == 15


# =============================================================================
# Multi-Language Project Tests
# =============================================================================


class TestMultiLanguageProjectE2E:
    """End-to-end tests for multi-language projects."""

    def test_monorepo_python_java(self, mixed_project):
        """Test decision for Python+Java monorepo scenario."""
        languages = [
            LanguageStructure(
                name="python",
                file_count=30,
                line_count=8000,
                percentage=40.0,
                role="secondary",
            ),
            LanguageStructure(
                name="java",
                file_count=45,
                line_count=12000,
                percentage=60.0,
                role="primary",
            ),
        ]
        attack_surface = AttackSurfaceSummary(
            entry_points_by_language={"python": 30, "java": 80},
        )
        input_data = LanguageDecisionInput(
            languages=languages,
            attack_surface=attack_surface,
            constraints=DecisionConstraints(max_languages=2),
        )
        decider = CodeQLLanguageDecider(project_path=mixed_project)
        decision = decider._make_baseline_decision(input_data)

        # Both languages should be selected (within limit)
        assert len(decision.recommended_languages) <= 2
        assert "java" in decision.recommended_languages

    def test_javascript_typescript_mixed(self, temp_project):
        """Test decision for JS+TS project."""
        languages = [
            LanguageStructure(
                name="javascript",
                file_count=50,
                line_count=10000,
                percentage=50.0,
                role="secondary",
            ),
            LanguageStructure(
                name="typescript",
                file_count=50,
                line_count=10000,
                percentage=50.0,
                role="secondary",
            ),
        ]
        input_data = LanguageDecisionInput(
            languages=languages,
            attack_surface=AttackSurfaceSummary(),
            constraints=DecisionConstraints(max_languages=2),
        )
        decider = CodeQLLanguageDecider(project_path=temp_project)
        decision = decider._make_baseline_decision(input_data)

        # Both are CodeQL-supported, should be considered
        assert len(decision.recommended_languages) >= 1
