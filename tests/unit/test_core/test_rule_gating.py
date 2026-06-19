"""Tests for RuleGatingEngine.

Covers the dict-vs-object tech_stack handling: ScanOrchestrator passes a *dict*
tech_stack (built by ``_detect_tech_stack_impl``) while RuleGatingEngine
historically only read attributes (``.primary_language.value``) off a TechStack
object — so a dict silently yielded ``primary_language=None`` and disabled every
language pack, making the Web main-path Semgrep scan return 0 findings.
"""

from types import SimpleNamespace

from src.core.rule_gating import ALL_LANGUAGE_PACKS, RuleGatingEngine
from src.layers.l1_intelligence.tech_stack_detector.models import Language


class TestRuleGatingTechStackShapes:
    """RuleGatingEngine must accept both dict and object tech stacks."""

    def test_dict_tech_stack_extracts_enum_primary_language(self):
        """Dict tech_stack (orchestrator shape) with Language enum primary."""
        tech_stack = {
            "primary_language": Language.PYTHON,
            "languages": [Language.PYTHON],
            "frameworks": ["flask"],
            "total_files": 1,
        }
        result = RuleGatingEngine(tech_stack=tech_stack).evaluate()

        assert result.primary_language == "python"
        # Python packs must be ENABLED (the bug disabled them → 0 findings).
        assert "python" in result.enabled_packs
        assert "python-lang-security" in result.enabled_packs
        assert "python" not in result.disabled_packs
        assert "python-lang-security" not in result.disabled_packs

    def test_dict_tech_stack_extracts_string_primary_language(self):
        """Dict tech_stack with a plain-string primary_language also works."""
        tech_stack = {"primary_language": "python", "languages": ["python"]}
        result = RuleGatingEngine(tech_stack=tech_stack).evaluate()

        assert result.primary_language == "python"
        assert "python" in result.enabled_packs
        assert "python" not in result.disabled_packs

    def test_object_tech_stack_still_works(self):
        """Object (attribute) tech_stack path is unchanged (regression)."""
        tech_stack = SimpleNamespace(
            primary_language=Language.PYTHON,
            secondary_languages=[Language.JAVASCRIPT],
            project_type=None,
            languages=[],
        )
        result = RuleGatingEngine(tech_stack=tech_stack).evaluate()

        assert result.primary_language == "python"
        assert "javascript" in result.secondary_languages
        assert "python" in result.enabled_packs
        assert "python" not in result.disabled_packs

    def test_no_tech_stack_fail_open(self):
        """No tech_stack → primary_language None, generic still enabled."""
        result = RuleGatingEngine(tech_stack=None).evaluate()

        assert result.primary_language is None
        # Fails open: generic baseline stays available.
        assert "generic" in ALL_LANGUAGE_PACKS
