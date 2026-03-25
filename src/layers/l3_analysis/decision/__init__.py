"""
CodeQL Language Decision Module

This module provides LLM-driven intelligent language selection for CodeQL scanning.
It analyzes project characteristics (languages, attack surface, Semgrep results, build difficulty)
and recommends which languages to prioritize for CodeQL deep scanning.

Key Components:
- CodeQLLanguageDecider: Main decision class with LLM and baseline strategies
- BuildDifficultyAssessor: Assesses build difficulty for each language
- LanguageDecisionInput: Input data model for the decision process
- LanguageDecision: Output data model with recommendations

Usage:
    from src.layers.l3_analysis.decision import (
        CodeQLLanguageDecider,
        LanguageDecisionInput,
        LanguageStructure,
        BuildDifficultyAssessor,
    )

    # Prepare input
    input_data = LanguageDecisionInput(
        languages=[LanguageStructure(name="java", file_count=100, line_count=50000, percentage=45.0)],
        attack_surface=AttackSurfaceSummary(entry_points_by_language={"java": 120}),
        constraints=DecisionConstraints(max_languages=3, max_time_budget_seconds=1800),
    )

    # Make decision
    decider = CodeQLLanguageDecider(llm_client=client)
    result = await decider.decide(input_data)
    print(result.recommended_languages)
"""

from .build_assessor import BuildDifficultyAssessor
from .language_decider import CodeQLLanguageDecider
from .models import (
    AttackSurfaceSummary,
    BuildDifficulty,
    BuildDifficultyLevel,
    DecisionConstraints,
    DecisionError,
    LanguageDecision,
    LanguageDecisionInput,
    LanguageRecommendation,
    LanguageStructure,
    ModuleSummary,
    SemgrepSummary,
    SkippedLanguage,
)

__all__ = [
    # Core decision
    "CodeQLLanguageDecider",
    "LanguageDecision",
    "LanguageDecisionInput",
    "DecisionError",
    "DecisionConstraints",
    # Input models
    "LanguageStructure",
    "BuildDifficulty",
    "BuildDifficultyLevel",
    "AttackSurfaceSummary",
    "SemgrepSummary",
    "ModuleSummary",
    # Output models
    "LanguageRecommendation",
    "SkippedLanguage",
    # Assessors
    "BuildDifficultyAssessor",
]
