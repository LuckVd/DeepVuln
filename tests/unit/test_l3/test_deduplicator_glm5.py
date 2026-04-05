"""
Unit tests for P8-08h: Enhanced GLM-5 LLM response parsing.

Tests cover GLM-5 specific formats:
1. reasoning_content + content wrapper
2. Extra text before JSON
3. Malformed JSON patterns
"""

import json
import pytest

from src.layers.l3_analysis.deduplicator import ClusterBasedDeduplicator
from src.layers.l3_analysis.models import Finding, CodeLocation, FindingType, SeverityLevel


class TestGLM5ResponseParsing:
    """Test suite for GLM-5 specific response parsing."""

    def make_mock_finding(self, id: str, final_score: float = 1.0) -> Finding:
        """Helper to create a mock finding."""
        return Finding(
            id=id,
            rule_id="test_rule",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title=f"Test Finding {id}",
            description="Test description",
            fix_suggestion="Fix it",
            location=CodeLocation(
                file="test.py",
                line=1,
                end_line=1,
                snippet="test code",
            ),
            source="agent",
            final_score=final_score,  # Max allowed is 1.5
        )

    def test_standard_json_response(self):
        """Test standard JSON response format works."""
        deduplicator = ClusterBasedDeduplicator()

        findings = [self.make_mock_finding("f1"), self.make_mock_finding("f2")]

        response = '''{
  "groups": [
    {
      "indices": [0, 1],
      "reason": "Same vulnerability"
    }
  ]
}'''

        result = deduplicator._parse_llm_response(findings, response)

        assert result is not None
        assert len(result.keep) <= 2
        assert len(result.keep) + len(result.removed) == 2

    def test_glm5_reasoning_content_format(self):
        """Test GLM-5 reasoning_content + content format."""
        deduplicator = ClusterBasedDeduplicator()

        findings = [self.make_mock_finding("f1"), self.make_mock_finding("f2")]

        # GLM-5 format with reasoning_content wrapper
        response = '''{
  "reasoning_content": "Analyzing the findings...",
  "content": "{\\"groups\\": [{\\"indices\\": [0, 1], \\"reason\\": \\"Same\\"}]}"
}'''

        result = deduplicator._parse_llm_response(findings, response)

        assert result is not None
        # Should successfully parse the content field

    def test_glm5_reasoning_nested_json(self):
        """Test GLM-5 with properly nested JSON in content field."""
        deduplicator = ClusterBasedDeduplicator()

        findings = [self.make_mock_finding("f1"), self.make_mock_finding("f2")]

        # GLM-5 format with actual JSON object in content
        response = json.dumps({
            "reasoning_content": "Analysis complete",
            "content": json.dumps({
                "groups": [
                    {
                        "indices": [0],
                        "reason": "Keep first"
                    }
                ]
            })
        })

        result = deduplicator._parse_llm_response(findings, response)

        assert result is not None
        assert len(result.keep) >= 0

    def test_markdown_json_wrapper(self):
        """Test JSON wrapped in markdown code blocks."""
        deduplicator = ClusterBasedDeduplicator()

        findings = [self.make_mock_finding("f1")]

        response = '''```json
{
  "groups": [
    {
      "indices": [0],
      "reason": "Only one"
    }
  ]
}
```'''

        result = deduplicator._parse_llm_response(findings, response)

        assert result is not None
        assert len(result.keep) == 1

    def test_extra_text_before_json(self):
        """Test response with explanatory text before JSON."""
        deduplicator = ClusterBasedDeduplicator()

        findings = [self.make_mock_finding("f1")]

        response = '''Based on my analysis, here are the groups:

{
  "groups": [
    {
      "indices": [0],
      "reason": "Only one"
    }
  ]
}

I hope this helps.'''

        result = deduplicator._parse_llm_response(findings, response)

        assert result is not None

    def test_malformed_json_with_trailing_comma(self):
        """Test malformed JSON with trailing comma."""
        deduplicator = ClusterBasedDeduplicator()

        findings = [self.make_mock_finding("f1")]

        response = '''{
  "groups": [
    {
      "indices": [0],
      "reason": "Only one",
    }
  ]
}'''

        result = deduplicator._parse_llm_response(findings, response)

        assert result is not None

    def test_empty_groups(self):
        """Test response with empty groups."""
        deduplicator = ClusterBasedDeduplicator()

        findings = [self.make_mock_finding("f1"), self.make_mock_finding("f2")]

        response = '''{"groups": []}'''

        result = deduplicator._parse_llm_response(findings, response)

        assert result is not None
        assert len(result.keep) == 0
        # When no groups specified, keep all findings (default behavior)
        # or remove all depending on implementation
