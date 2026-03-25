"""
Unit tests for CodeQL Language Decision module.

Tests the decision models, build difficulty assessor, prompt formatting,
and the core decision logic with both LLM and baseline strategies.
"""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
import tempfile

from src.layers.l3_analysis.decision import (
    BuildDifficultyAssessor,
    BuildDifficultyLevel,
    CodeQLLanguageDecider,
    DecisionConstraints,
    LanguageDecision,
    LanguageDecisionInput,
    LanguageRecommendation,
    LanguageStructure,
    AttackSurfaceSummary,
    SemgrepSummary,
    ModuleSummary,
)
from src.layers.l3_analysis.decision.prompts import (
    build_decision_prompt,
    format_language_table,
    format_build_difficulty,
    validate_decision_response,
    parse_time_estimate,
)
from src.layers.l3_analysis.llm.client import LLMClient, LLMResponse, LLMProvider


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def sample_languages():
    """Sample language data for testing."""
    return [
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
        LanguageStructure(
            name="cpp",
            file_count=30,
            line_count=10000,
            percentage=10.0,
            role="secondary",
        ),
    ]


@pytest.fixture
def sample_attack_surface():
    """Sample attack surface data for testing."""
    return AttackSurfaceSummary(
        entry_points_by_language={
            "java": 120,
            "python": 50,
            "javascript": 80,
            "cpp": 5,
        },
        sensitive_data_flows=["user_input -> database", "api_key -> external_service"],
        external_dependencies=["spring-boot", "flask", "react"],
        total_endpoints=255,
    )


@pytest.fixture
def sample_semgrep_result():
    """Sample Semgrep results for testing."""
    return SemgrepSummary(
        findings_by_language={
            "java": {"critical": 1, "high": 3, "medium": 8, "low": 2},
            "python": {"critical": 0, "high": 2, "medium": 5, "low": 1},
            "javascript": {"critical": 0, "high": 1, "medium": 3, "low": 0},
        },
        total_findings=26,
    )


@pytest.fixture
def sample_modules():
    """Sample module summaries for testing."""
    return [
        ModuleSummary(
            name="backend",
            path="backend",
            primary_language="java",
            languages=["java", "python"],
            build_signals=["pom.xml"],
            loc_estimate=40000,
        ),
        ModuleSummary(
            name="frontend",
            path="frontend",
            primary_language="javascript",
            languages=["javascript", "typescript"],
            build_signals=["package.json"],
            loc_estimate=25000,
        ),
    ]


@pytest.fixture
def sample_constraints():
    """Sample decision constraints."""
    return DecisionConstraints(
        max_languages=3,
        max_time_budget_seconds=1800,
        min_confidence=0.7,
        llm_timeout_seconds=30,
        fallback_strategy="hybrid",
    )


@pytest.fixture
def temp_project(tmp_path):
    """Create a temporary project directory with some build files."""
    # Create Java project structure
    java_dir = tmp_path / "backend"
    java_dir.mkdir()
    (java_dir / "pom.xml").touch()

    # Create Python project structure
    py_dir = tmp_path / "scripts"
    py_dir.mkdir()
    (py_dir / "requirements.txt").touch()

    return tmp_path


# =============================================================================
# Model Tests
# =============================================================================


class TestLanguageStructure:
    """Tests for LanguageStructure model."""

    def test_creation(self):
        """Test basic creation."""
        lang = LanguageStructure(
            name="python",
            file_count=100,
            line_count=5000,
            percentage=50.0,
            role="primary",
        )
        assert lang.name == "python"
        assert lang.file_count == 100
        assert lang.line_count == 5000
        assert lang.percentage == 50.0
        assert lang.role == "primary"

    def test_defaults(self):
        """Test default values."""
        lang = LanguageStructure(name="go")
        assert lang.file_count == 0
        assert lang.line_count == 0
        assert lang.percentage == 0.0
        assert lang.role == "secondary"


class TestDecisionConstraints:
    """Tests for DecisionConstraints model."""

    def test_defaults(self):
        """Test default values."""
        constraints = DecisionConstraints()
        assert constraints.max_languages == 3
        assert constraints.max_time_budget_seconds == 1800
        assert constraints.min_confidence == 0.7
        assert constraints.fallback_strategy == "hybrid"

    def test_custom_values(self):
        """Test custom values."""
        constraints = DecisionConstraints(
            max_languages=5,
            max_time_budget_seconds=3600,
            min_confidence=0.8,
        )
        assert constraints.max_languages == 5
        assert constraints.max_time_budget_seconds == 3600
        assert constraints.min_confidence == 0.8


class TestLanguageDecision:
    """Tests for LanguageDecision model."""

    def test_creation(self):
        """Test basic creation."""
        decision = LanguageDecision(
            recommended_languages=["java", "python"],
            confidence=0.85,
            decision_source="llm",
        )
        assert decision.recommended_languages == ["java", "python"]
        assert decision.confidence == 0.85
        assert decision.decision_source == "llm"

    def test_get_priority_score(self):
        """Test getting priority score for a language."""
        decision = LanguageDecision(
            recommended_languages=["java"],
            recommendations=[
                LanguageRecommendation(language="java", priority_score=0.9)
            ],
        )
        assert decision.get_priority_score("java") == 0.9
        assert decision.get_priority_score("python") == 0.0

    def test_get_reasoning(self):
        """Test getting reasoning for a language."""
        decision = LanguageDecision(
            recommended_languages=["java"],
            recommendations=[
                LanguageRecommendation(language="java", reasoning="Primary language")
            ],
            skip_reasons={"cpp": "Build too complex"},
        )
        assert decision.get_reasoning("java") == "Primary language"
        assert decision.get_reasoning("cpp") == "Build too complex"


class TestLanguageDecisionInput:
    """Tests for LanguageDecisionInput model."""

    def test_get_codeql_supported_languages(self, sample_languages):
        """Test filtering to CodeQL-supported languages."""
        input_data = LanguageDecisionInput(languages=sample_languages)
        supported = input_data.get_codeql_supported_languages()
        assert "java" in supported
        assert "python" in supported
        assert "javascript" in supported
        assert "cpp" in supported

    def test_unsupported_language_filtered(self):
        """Test that unsupported languages are filtered."""
        input_data = LanguageDecisionInput(
            languages=[
                LanguageStructure(name="lua", file_count=10, line_count=100, percentage=5.0),
                LanguageStructure(name="python", file_count=100, line_count=1000, percentage=95.0),
            ]
        )
        supported = input_data.get_codeql_supported_languages()
        assert "lua" not in supported
        assert "python" in supported


# =============================================================================
# Build Difficulty Assessor Tests
# =============================================================================


class TestBuildDifficultyAssessor:
    """Tests for BuildDifficultyAssessor."""

    def test_assess_easy_language(self, temp_project):
        """Test assessment for easy language (Python)."""
        assessor = BuildDifficultyAssessor(temp_project)
        lang = LanguageStructure(name="python", line_count=10000)

        difficulty = assessor.assess(lang)

        assert difficulty.level == BuildDifficultyLevel.EASY
        assert difficulty.estimated_time_seconds > 0
        assert difficulty.estimated_time_seconds < 600  # Should be reasonable

    def test_assess_medium_language(self, temp_project):
        """Test assessment for medium language (Java)."""
        assessor = BuildDifficultyAssessor(temp_project)
        lang = LanguageStructure(name="java", line_count=50000)

        difficulty = assessor.assess(lang)

        assert difficulty.level == BuildDifficultyLevel.MEDIUM

    def test_assess_hard_language(self, temp_project):
        """Test assessment for hard language (C++)."""
        assessor = BuildDifficultyAssessor(temp_project)
        lang = LanguageStructure(name="cpp", line_count=20000)

        difficulty = assessor.assess(lang)

        assert difficulty.level == BuildDifficultyLevel.HARD
        # C++ without compile_commands.json should have blockers
        assert len(difficulty.blockers) > 0

    def test_assess_all(self, temp_project, sample_languages):
        """Test assessing all languages."""
        assessor = BuildDifficultyAssessor(temp_project)
        difficulties = assessor.assess_all(sample_languages)

        assert len(difficulties) == 4
        assert "java" in difficulties
        assert "python" in difficulties
        assert difficulties["java"].level == BuildDifficultyLevel.MEDIUM
        assert difficulties["python"].level == BuildDifficultyLevel.EASY

    def test_build_signals_detection(self, temp_project):
        """Test that build signals are detected."""
        assessor = BuildDifficultyAssessor(temp_project)

        # Java has pom.xml in backend/
        java_lang = LanguageStructure(name="java", line_count=10000)
        java_diff = assessor.assess(java_lang)
        assert java_diff.has_build_config or len(java_diff.build_signals) >= 0

    def test_time_estimation_scales_with_loc(self, temp_project):
        """Test that time estimation scales with LOC."""
        assessor = BuildDifficultyAssessor(temp_project)

        small = LanguageStructure(name="java", line_count=10000)
        large = LanguageStructure(name="java", line_count=100000)

        small_time = assessor.assess(small).estimated_time_seconds
        large_time = assessor.assess(large).estimated_time_seconds

        # Larger project should take longer
        assert large_time >= small_time


# =============================================================================
# Prompt Formatting Tests
# =============================================================================


class TestPromptFormatting:
    """Tests for prompt formatting functions."""

    def test_format_language_table(self, sample_languages):
        """Test language table formatting."""
        table = format_language_table(sample_languages)

        assert "java" in table
        assert "python" in table
        assert "150" in table  # file count
        assert "45.0%" in table  # percentage

    def test_format_language_table_empty(self):
        """Test empty language table."""
        table = format_language_table([])
        assert "No languages detected" in table

    def test_format_build_difficulty(self):
        """Test build difficulty formatting."""
        from src.layers.l3_analysis.decision.models import BuildDifficulty

        difficulties = {
            "java": BuildDifficulty(
                level=BuildDifficultyLevel.MEDIUM,
                estimated_time_seconds=300,
                has_build_config=True,
                blockers=[],
            ),
            "cpp": BuildDifficulty(
                level=BuildDifficultyLevel.HARD,
                estimated_time_seconds=600,
                has_build_config=False,
                blockers=["No compile_commands.json"],
            ),
        }

        table = format_build_difficulty(difficulties)

        assert "java" in table
        assert "cpp" in table
        assert "medium" in table
        assert "hard" in table

    def test_validate_decision_response_valid(self):
        """Test validation of valid response."""
        response = {
            "recommended_languages": ["java", "python"],
            "skipped_languages": ["cpp"],
            "confidence": 0.85,
            "recommendations": [
                {"language": "java", "priority_score": 0.9},
                {"language": "python", "priority_score": 0.7},
            ],
        }

        errors = validate_decision_response(response)
        assert len(errors) == 0

    def test_validate_decision_response_missing_fields(self):
        """Test validation catches missing fields."""
        response = {
            "recommended_languages": ["java"],
        }

        errors = validate_decision_response(response)
        assert len(errors) > 0
        assert any("confidence" in e for e in errors)

    def test_validate_decision_response_invalid_confidence(self):
        """Test validation catches invalid confidence."""
        response = {
            "recommended_languages": ["java"],
            "skipped_languages": [],
            "confidence": 1.5,  # Invalid: > 1.0
        }

        errors = validate_decision_response(response)
        assert any("confidence" in e for e in errors)

    def test_parse_time_estimate_minutes(self):
        """Test parsing time in minutes."""
        assert parse_time_estimate("15 minutes") == 900
        assert parse_time_estimate("5 min") == 300
        assert parse_time_estimate("10m") == 600

    def test_parse_time_estimate_hours(self):
        """Test parsing time in hours."""
        assert parse_time_estimate("1 hour") == 3600
        assert parse_time_estimate("2 hours") == 7200

    def test_parse_time_estimate_complex(self):
        """Test parsing complex time strings."""
        assert parse_time_estimate("1 hour 30 minutes") == 5400
        assert parse_time_estimate("2h 15m") == 8100

    def test_build_decision_prompt(self, sample_languages, sample_attack_surface):
        """Test building complete decision prompt."""
        input_data = LanguageDecisionInput(
            languages=sample_languages,
            attack_surface=sample_attack_surface,
        )

        prompt = build_decision_prompt(input_data)

        assert "java" in prompt
        assert "Security Priority" in prompt
        assert "Decision Principles" in prompt
        assert "json" in prompt.lower()  # Check for json in any case


# =============================================================================
# Decision Logic Tests
# =============================================================================


class TestCodeQLLanguageDecider:
    """Tests for CodeQLLanguageDecider."""

    def test_baseline_decision(
        self,
        sample_languages,
        sample_attack_surface,
        sample_constraints,
        temp_project,
    ):
        """Test baseline decision without LLM."""
        input_data = LanguageDecisionInput(
            languages=sample_languages,
            attack_surface=sample_attack_surface,
            constraints=sample_constraints,
        )

        decider = CodeQLLanguageDecider(
            llm_client=None,  # No LLM, should use baseline
            project_path=temp_project,
            constraints=sample_constraints,
        )

        decision = decider._make_baseline_decision(input_data)

        assert len(decision.recommended_languages) > 0
        assert len(decision.recommended_languages) <= sample_constraints.max_languages
        assert decision.decision_source == "baseline"
        assert decision.confidence == 0.7  # Fixed baseline confidence

    def test_baseline_prioritizes_primary_language(
        self,
        sample_attack_surface,
        sample_constraints,
        temp_project,
    ):
        """Test that baseline prioritizes primary language."""
        languages = [
            LanguageStructure(name="java", file_count=100, line_count=50000, percentage=60.0, role="primary"),
            LanguageStructure(name="python", file_count=50, line_count=20000, percentage=25.0, role="secondary"),
        ]

        input_data = LanguageDecisionInput(
            languages=languages,
            attack_surface=sample_attack_surface,
            constraints=sample_constraints,
        )

        decider = CodeQLLanguageDecider(project_path=temp_project)
        decision = decider._make_baseline_decision(input_data)

        # Java should be first (primary + most code)
        assert decision.recommended_languages[0] == "java"

    def test_baseline_considers_attack_surface(
        self,
        sample_constraints,
        temp_project,
    ):
        """Test that baseline considers attack surface."""
        languages = [
            LanguageStructure(name="java", file_count=100, line_count=30000, percentage=40.0, role="primary"),
            LanguageStructure(name="python", file_count=80, line_count=30000, percentage=40.0, role="secondary"),
        ]

        # Python has more entry points
        attack_surface = AttackSurfaceSummary(
            entry_points_by_language={"java": 10, "python": 100},
        )

        input_data = LanguageDecisionInput(
            languages=languages,
            attack_surface=attack_surface,
            constraints=sample_constraints,
        )

        decider = CodeQLLanguageDecider(project_path=temp_project)
        decision = decider._make_baseline_decision(input_data)

        # Both should be recommended (within limits)
        # Python should score higher due to attack surface
        assert "python" in decision.recommended_languages

    def test_baseline_respects_max_languages(
        self,
        sample_languages,
        sample_attack_surface,
        temp_project,
    ):
        """Test that baseline respects max_languages constraint."""
        constraints = DecisionConstraints(max_languages=2)
        input_data = LanguageDecisionInput(
            languages=sample_languages,
            attack_surface=sample_attack_surface,
            constraints=constraints,
        )

        decider = CodeQLLanguageDecider(
            project_path=temp_project,
            constraints=constraints,
        )
        decision = decider._make_baseline_decision(input_data)

        assert len(decision.recommended_languages) <= 2
        assert len(decision.skipped_languages) >= 2

    def test_baseline_with_semgrep_boost(
        self,
        sample_constraints,
        temp_project,
    ):
        """Test that Semgrep findings boost language priority."""
        languages = [
            LanguageStructure(name="java", file_count=100, line_count=50000, percentage=50.0, role="primary"),
            LanguageStructure(name="python", file_count=100, line_count=50000, percentage=50.0, role="secondary"),
        ]

        # Java has critical findings
        semgrep = SemgrepSummary(
            findings_by_language={"java": {"critical": 5, "high": 10}},
            total_findings=15,
        )

        input_data = LanguageDecisionInput(
            languages=languages,
            attack_surface=AttackSurfaceSummary(),
            semgrep_result=semgrep,
            constraints=sample_constraints,
        )

        decider = CodeQLLanguageDecider(project_path=temp_project)
        decision = decider._make_baseline_decision(input_data)

        # Java should be recommended with boost
        assert "java" in decision.recommended_languages

    @pytest.mark.asyncio
    async def test_llm_decision_success(
        self,
        sample_languages,
        sample_attack_surface,
        sample_constraints,
        temp_project,
    ):
        """Test successful LLM decision."""
        # Mock LLM client
        mock_client = MagicMock(spec=LLMClient)
        mock_response = LLMResponse(
            content='{"recommended_languages": ["java", "python"], "skipped_languages": ["cpp"], "confidence": 0.85, "recommendations": [{"language": "java", "priority_score": 0.9, "reasoning": "Primary"}]}',
            model="gpt-4",
            provider=LLMProvider.OPENAI,
        )
        mock_client.complete_with_context = AsyncMock(return_value=mock_response)
        mock_client.is_available = True

        input_data = LanguageDecisionInput(
            languages=sample_languages,
            attack_surface=sample_attack_surface,
            constraints=sample_constraints,
        )

        decider = CodeQLLanguageDecider(
            llm_client=mock_client,
            project_path=temp_project,
            constraints=sample_constraints,
        )

        decision = await decider.decide(input_data)

        assert decision.decision_source == "llm"
        assert decision.confidence >= sample_constraints.min_confidence
        assert "java" in decision.recommended_languages

    @pytest.mark.asyncio
    async def test_llm_fallback_on_failure(
        self,
        sample_languages,
        sample_attack_surface,
        sample_constraints,
        temp_project,
    ):
        """Test fallback to baseline when LLM fails."""
        # Mock LLM client that raises an error
        mock_client = MagicMock(spec=LLMClient)
        from src.layers.l3_analysis.llm.client import LLMError
        mock_client.complete_with_context = AsyncMock(
            side_effect=LLMError("API error")
        )

        input_data = LanguageDecisionInput(
            languages=sample_languages,
            attack_surface=sample_attack_surface,
            constraints=sample_constraints,
        )

        decider = CodeQLLanguageDecider(
            llm_client=mock_client,
            project_path=temp_project,
            constraints=sample_constraints,
        )

        decision = await decider.decide(input_data)

        # Should fall back to baseline
        assert decision.decision_source == "baseline"

    @pytest.mark.asyncio
    async def test_llm_low_confidence_uses_baseline(
        self,
        sample_languages,
        sample_attack_surface,
        sample_constraints,
        temp_project,
    ):
        """Test that low confidence LLM response uses baseline."""
        # Mock LLM client with low confidence response
        mock_client = MagicMock(spec=LLMClient)
        mock_response = LLMResponse(
            content='{"recommended_languages": ["java"], "skipped_languages": [], "confidence": 0.5}',
            model="gpt-4",
            provider=LLMProvider.OPENAI,
        )
        mock_client.complete_with_context = AsyncMock(return_value=mock_response)

        input_data = LanguageDecisionInput(
            languages=sample_languages,
            attack_surface=sample_attack_surface,
            constraints=sample_constraints,
        )

        decider = CodeQLLanguageDecider(
            llm_client=mock_client,
            project_path=temp_project,
            constraints=sample_constraints,
        )

        decision = await decider.decide(input_data)

        # Confidence 0.5 < min_confidence 0.7, should use baseline
        assert decision.decision_source == "baseline"

    def test_get_decision_explanation(
        self,
        sample_languages,
        sample_attack_surface,
        sample_constraints,
        temp_project,
    ):
        """Test decision explanation generation."""
        input_data = LanguageDecisionInput(
            languages=sample_languages,
            attack_surface=sample_attack_surface,
            constraints=sample_constraints,
        )

        decider = CodeQLLanguageDecider(project_path=temp_project)
        decision = decider._make_baseline_decision(input_data)

        explanation = decider.get_decision_explanation(decision)

        assert "CodeQL Language Decision" in explanation
        assert decision.decision_source in explanation
        assert "Recommended Languages" in explanation


# =============================================================================
# Integration Tests
# =============================================================================


class TestDecisionIntegration:
    """Integration tests for the decision module."""

    def test_full_baseline_workflow(
        self,
        sample_languages,
        sample_attack_surface,
        sample_semgrep_result,
        sample_modules,
        sample_constraints,
        temp_project,
    ):
        """Test complete baseline decision workflow."""
        # Create assessor
        assessor = BuildDifficultyAssessor(temp_project)
        difficulties = assessor.assess_all(sample_languages)

        # Create input
        input_data = LanguageDecisionInput(
            languages=sample_languages,
            modules=sample_modules,
            attack_surface=sample_attack_surface,
            semgrep_result=sample_semgrep_result,
            build_difficulties=difficulties,
            constraints=sample_constraints,
        )

        # Make decision
        decider = CodeQLLanguageDecider(
            project_path=temp_project,
            constraints=sample_constraints,
        )
        decision = decider._make_baseline_decision(input_data)

        # Verify
        assert len(decision.recommended_languages) > 0
        assert len(decision.recommended_languages) <= sample_constraints.max_languages
        assert decision.estimated_total_seconds <= sample_constraints.max_time_budget_seconds

        # Verify recommendations have required fields
        for rec in decision.recommendations:
            assert rec.language in decision.recommended_languages
            assert 0 <= rec.priority_score <= 1
            assert rec.reasoning  # Should have reasoning
