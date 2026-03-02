"""
Unit tests for Adversarial Verification Verifiers.

Tests for AttackerVerifier, DefenderVerifier, and ArbiterVerifier
with mocked LLM responses.
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.layers.l3_analysis.verification.attacker import AttackerVerifier
from src.layers.l3_analysis.verification.defender import DefenderVerifier
from src.layers.l3_analysis.verification.arbiter import ArbiterVerifier
from src.layers.l3_analysis.verification.models import (
    AdversarialVerdict,
    ArgumentStrength,
    TriggerConditions,
    VerificationArgument,
    VerdictType,
)


class MockLLMClient:
    """Mock LLM client for testing."""

    def __init__(self, response_content: str):
        self.response_content = response_content
        self.call_count = 00
        self.last_system_prompt = None
        self.last_user_prompt = None

    async def complete_with_context(self, system_prompt: str, user_prompt: str):
        """Mock the complete_with_context method."""
        self.call_count += 1
        self.last_system_prompt = system_prompt
        self.last_user_prompt = user_prompt

        response = MagicMock()
        response.content = self.response_content
        return response


class TestAttackerVerifier:
    """Tests for AttackerVerifier."""

    @pytest.fixture
    def sample_finding(self):
        """Sample vulnerability finding."""
        return {
            "id": "test-001",
            "type": "sql_injection",
            "severity": "high",
            "title": "SQL Injection",
            "description": "User input directly concatenated into SQL query",
            "location": "app.py:42",
            "code_snippet": 'query = f"SELECT * FROM users WHERE id = {user_input}"',
            "language": "python",
        }

    @pytest.fixture
    def attacker_response(self):
        """Sample attacker response."""
        return json.dumps({
            "claim": "This SQL injection is directly exploitable",
            "confidence": 0.95,
            "evidence": [
                "User input directly concatenated into SQL",
                "No parameterization or sanitization"
            ],
            "reasoning": "The f-string interpolation allows arbitrary SQL injection",
            "strength": "definitive",
            "poc_code": "1' OR '1'='1",
            "poc_type": "http_request",
            "exploitation_steps": [
                "1. Send GET /api/users?id=1'%20OR%20'1'='1",
                "2. Query becomes: SELECT * FROM users WHERE id = 1' OR '1'='1"
            ],
            "prerequisites": [],
            "counter_arguments": [],
            "bypass_techniques": []
        })

    @pytest.mark.asyncio
    async def test_analyze_success(self, sample_finding, attacker_response):
        """Test successful attacker analysis."""
        mock_client = MockLLMClient(attacker_response)
        verifier = AttackerVerifier(llm_client=mock_client)

        result = await verifier.analyze(
            finding=sample_finding,
            code_context=sample_finding["code_snippet"],
        )

        assert result.role == "attacker"
        assert result.confidence == 0.95
        assert result.strength == ArgumentStrength.DEFINITIVE
        assert result.poc_code == "1' OR '1'='1"
        assert len(result.exploitation_steps) == 2
        assert mock_client.call_count == 1

    @pytest.mark.asyncio
    async def test_analyze_with_round_number(self, sample_finding, attacker_response):
        """Test attacker analysis with round number."""
        mock_client = MockLLMClient(attacker_response)
        verifier = AttackerVerifier(llm_client=mock_client)

        result = await verifier.analyze(
            finding=sample_finding,
            code_context=sample_finding["code_snippet"],
            round_number=2,
        )

        assert result.round_number == 2

    @pytest.mark.asyncio
    async def test_rebut(self, sample_finding, attacker_response):
        """Test attacker rebuttal."""
        mock_client = MockLLMClient(attacker_response)
        verifier = AttackerVerifier(llm_client=mock_client)

        previous_attacker = VerificationArgument(
            role="attacker",
            claim="Previous claim",
            evidence=["Previous evidence"],
            reasoning="Previous reasoning",
            strength=ArgumentStrength.MODERATE,
            confidence=0.7,
            round_number=1,
        )
        defender_arg = VerificationArgument(
            role="defender",
            claim="Defense claim",
            evidence=["Defense evidence"],
            reasoning="Defense reasoning",
            strength=ArgumentStrength.MODERATE,
            confidence=0.6,
        )

        result = await verifier.rebut(
            finding=sample_finding,
            code_context=sample_finding["code_snippet"],
            defender_argument=defender_arg,
            previous_attacker_argument=previous_attacker,
        )

        assert result.role == "attacker"
        assert result.round_number == 2
        # Note: is_rebuttal is not a direct field, it's stored in the argument

    @pytest.mark.asyncio
    async def test_analyze_json_parse_error(self, sample_finding):
        """Test handling of JSON parse error."""
        mock_client = MockLLMClient("This is not valid JSON")
        verifier = AttackerVerifier(llm_client=mock_client)

        result = await verifier.analyze(
            finding=sample_finding,
            code_context=sample_finding["code_snippet"],
        )

        assert result.role == "attacker"
        assert result.strength == ArgumentStrength.WEAK
        assert result.confidence == 0.0
        assert "parsing failed" in result.reasoning.lower() or "error" in result.reasoning.lower()

    @pytest.mark.asyncio
    async def test_analyze_markdown_json(self, sample_finding, attacker_response):
        """Test parsing JSON from markdown code blocks."""
        markdown_response = f"```json\n{attacker_response}\n```"
        mock_client = MockLLMClient(markdown_response)
        verifier = AttackerVerifier(llm_client=mock_client)

        result = await verifier.analyze(
            finding=sample_finding,
            code_context=sample_finding["code_snippet"],
        )

        assert result.confidence == 0.95

    def test_get_quick_assessment(self, sample_finding):
        """Test quick assessment without LLM."""
        mock_client = MockLLMClient("")
        verifier = AttackerVerifier(llm_client=mock_client)

        assessment = verifier.get_quick_assessment(sample_finding)

        assert "initial_confidence" in assessment
        assert "vulnerability_type" in assessment
        assert assessment["vulnerability_type"] == "sql_injection"


class TestDefenderVerifier:
    """Tests for DefenderVerifier."""

    @pytest.fixture
    def sample_finding(self):
        """Sample vulnerability finding with defense."""
        return {
            "id": "test-002",
            "type": "sql_injection",
            "severity": "medium",
            "title": "Potential SQL Injection",
            "description": "SQL query with user input",
            "location": "app.py:50",
            "code_snippet": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
            "language": "python",
        }

    @pytest.fixture
    def defender_response(self):
        """Sample defender response."""
        return json.dumps({
            "claim": "This code uses parameterized queries and is NOT exploitable",
            "confidence": 0.95,
            "evidence": [
                "Uses %s placeholder for parameterization",
                "user_id passed as tuple parameter"
            ],
            "reasoning": "The parameterized query pattern prevents SQL injection",
            "strength": "definitive",
            "sanitizers_found": ["parameterized query (%s)"],
            "validation_checks": [],
            "framework_protections": ["Python DB-API"],
            "exploitation_barriers": [
                "Parameterized queries separate code from data by design"
            ],
            "false_positive_reasons": [
                "This is a well-known secure coding pattern"
            ],
            "counter_arguments": [],
        })

    @pytest.mark.asyncio
    async def test_analyze_success(self, sample_finding, defender_response):
        """Test successful defender analysis."""
        mock_client = MockLLMClient(defender_response)
        verifier = DefenderVerifier(llm_client=mock_client)

        result = await verifier.analyze(
            finding=sample_finding,
            code_context=sample_finding["code_snippet"],
        )

        assert result.role == "defender"
        assert result.confidence >= 0.95  # May be boosted by static analysis
        assert result.strength == ArgumentStrength.DEFINITIVE
        assert len(result.sanitizers_found) > 0
        assert mock_client.call_count == 1

    @pytest.mark.asyncio
    async def test_static_analysis_detects_parameterized_query(self, sample_finding):
        """Test static analysis detects parameterized query."""
        mock_client = MockLLMClient('{"claim": "Test", "confidence": 0.5, "reasoning": "", "strength": "moderate"}')
        verifier = DefenderVerifier(llm_client=mock_client, use_static_analysis=True)

        result = await verifier.analyze(
            finding=sample_finding,
            code_context=sample_finding["code_snippet"],
        )

        # Static analysis should find %s placeholder
        assert any("%s" in s for s in result.sanitizers_found)

    @pytest.mark.asyncio
    async def test_rebut(self, sample_finding, defender_response):
        """Test defender rebuttal."""
        mock_client = MockLLMClient(defender_response)
        verifier = DefenderVerifier(llm_client=mock_client)

        previous_defender = VerificationArgument(
            role="defender",
            claim="Previous defense",
            evidence=["Previous evidence"],
            reasoning="Previous reasoning",
            strength=ArgumentStrength.MODERATE,
            confidence=0.6,
            round_number=1,
        )
        attacker_arg = VerificationArgument(
            role="attacker",
            claim="Attack claim",
            evidence=["Attack evidence"],
            reasoning="Attack reasoning",
            strength=ArgumentStrength.STRONG,
            confidence=0.8,
        )

        result = await verifier.rebut(
            finding=sample_finding,
            code_context=sample_finding["code_snippet"],
            attacker_argument=attacker_arg,
            previous_defender_argument=previous_defender,
        )

        assert result.role == "defender"
        assert result.round_number == 2

    def test_static_defense_analysis_sql(self):
        """Test static analysis for SQL injection defenses."""
        mock_client = MockLLMClient("")
        verifier = DefenderVerifier(llm_client=mock_client, use_static_analysis=True)

        result = verifier._static_defense_analysis(
            code='cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
            vuln_type="sql_injection",
            language="python",
        )

        assert len(result["sanitizers"]) > 0
        assert any("%s" in s for s in result["sanitizers"])

    def test_static_defense_analysis_xss(self):
        """Test static analysis for XSS defenses."""
        mock_client = MockLLMClient("")
        verifier = DefenderVerifier(llm_client=mock_client, use_static_analysis=True)

        result = verifier._static_defense_analysis(
            code='return html.escape(user_input)',
            vuln_type="xss",
            language="python",
        )

        assert len(result["sanitizers"]) > 0

    def test_get_quick_assessment(self, sample_finding):
        """Test quick assessment without LLM."""
        mock_client = MockLLMClient("")
        verifier = DefenderVerifier(llm_client=mock_client)

        assessment = verifier.get_quick_assessment(
            finding=sample_finding,
            code=sample_finding["code_snippet"],
        )

        assert "defense_confidence" in assessment
        assert "has_defenses" in assessment
        assert assessment["has_defenses"] is True


class TestArbiterVerifier:
    """Tests for ArbiterVerifier."""

    @pytest.fixture
    def sample_finding(self):
        """Sample vulnerability finding."""
        return {
            "id": "test-003",
            "type": "sql_injection",
            "severity": "high",
            "title": "SQL Injection",
            "description": "Test vulnerability",
            "location": "app.py:60",
        }

    @pytest.fixture
    def attacker_argument(self):
        """Sample attacker argument."""
        return VerificationArgument(
            role="attacker",
            claim="This is exploitable",
            evidence=["Direct concatenation", "No sanitization"],
            reasoning="User input is directly concatenated",
            strength=ArgumentStrength.STRONG,
            confidence=0.85,
            poc_code="1' OR '1'='1",
            exploitation_steps=["Step 1", "Step 2"],
        )

    @pytest.fixture
    def defender_argument(self):
        """Sample defender argument."""
        return VerificationArgument(
            role="defender",
            claim="This is not exploitable",
            evidence=["Parameterized query"],
            reasoning="The code uses parameterized queries",
            strength=ArgumentStrength.DEFINITIVE,
            confidence=0.95,
            sanitizers_found=["%s placeholder"],
        )

    @pytest.fixture
    def confirmed_verdict_response(self):
        """Sample confirmed verdict response."""
        return json.dumps({
            "verdict": "confirmed",
            "confidence": 0.9,
            "summary": "Vulnerability confirmed - attacker has working PoC",
            "reasoning": "Attacker provides definitive evidence with working PoC",
            "attacker_strength": 0.85,
            "defender_strength": 0.3,
            "conditions": [],
            "recommended_action": "fix",
            "priority": "critical",
            "key_factors": ["Working PoC", "No effective defenses"]
        })

    @pytest.fixture
    def needs_review_response(self):
        """Sample needs_review verdict response."""
        return json.dumps({
            "verdict": "needs_review",
            "confidence": 0.5,
            "summary": "Cannot determine - requires manual review",
            "reasoning": "Both sides have similar strength",
            "attacker_strength": 0.55,
            "defender_strength": 0.5,
            "conditions": [],
            "recommended_action": "review",
            "priority": "medium",
            "key_factors": ["Close debate", "Need more context"]
        })

    @pytest.mark.asyncio
    async def test_evaluate_confirmed(self, sample_finding, attacker_argument, defender_argument, confirmed_verdict_response):
        """Test evaluation resulting in CONFIRMED."""
        mock_client = MockLLMClient(confirmed_verdict_response)
        verifier = ArbiterVerifier(llm_client=mock_client)

        verdict = await verifier.evaluate(
            finding=sample_finding,
            attacker_argument=attacker_argument,
            defender_argument=defender_argument,
        )

        assert verdict.verdict == VerdictType.CONFIRMED
        assert verdict.confidence == 0.9
        assert verdict.recommended_action == "fix"
        assert verdict.priority == "critical"

    @pytest.mark.asyncio
    async def test_evaluate_needs_review(self, sample_finding, attacker_argument, defender_argument, needs_review_response):
        """Test evaluation resulting in NEEDS_REVIEW."""
        mock_client = MockLLMClient(needs_review_response)
        verifier = ArbiterVerifier(llm_client=mock_client)

        verdict = await verifier.evaluate(
            finding=sample_finding,
            attacker_argument=attacker_argument,
            defender_argument=defender_argument,
        )

        assert verdict.verdict == VerdictType.NEEDS_REVIEW
        assert verdict.confidence == 0.5

    @pytest.mark.asyncio
    async def test_evaluate_with_debate_history(self, sample_finding, attacker_argument, defender_argument, confirmed_verdict_response):
        """Test evaluation with debate history."""
        mock_client = MockLLMClient(confirmed_verdict_response)
        verifier = ArbiterVerifier(llm_client=mock_client)

        debate_history = [
            {
                "round": 1,
                "attacker_claim": "Previous attacker claim",
                "attacker_confidence": 0.7,
                "defender_claim": "Previous defender claim",
                "defender_confidence": 0.6,
            }
        ]

        verdict = await verifier.evaluate(
            finding=sample_finding,
            attacker_argument=attacker_argument,
            defender_argument=defender_argument,
            debate_history=debate_history,
            round_number=2,
        )

        assert verdict.round_number == 2
        assert "Previous attacker claim" in mock_client.last_user_prompt

    @pytest.mark.asyncio
    async def test_heuristic_fallback(self, sample_finding, attacker_argument):
        """Test heuristic fallback when LLM fails."""
        mock_client = MockLLMClient("Invalid JSON")
        verifier = ArbiterVerifier(llm_client=mock_client, use_heuristic_fallback=True)

        # Strong attacker, weak defender
        weak_defender = VerificationArgument(
            role="defender",
            claim="Weak defense",
            evidence=[],
            reasoning="",
            strength=ArgumentStrength.WEAK,
            confidence=0.2,
        )

        verdict = await verifier.evaluate(
            finding=sample_finding,
            attacker_argument=attacker_argument,
            defender_argument=weak_defender,
        )

        # Should use heuristic and return CONFIRMED
        assert verdict.verdict == VerdictType.CONFIRMED
        assert "Heuristic" in verdict.reasoning

    def test_should_continue_debate(self, sample_finding):
        """Test should_continue_debate method."""
        mock_client = MockLLMClient("")
        conditions = TriggerConditions()
        verifier = ArbiterVerifier(
            llm_client=mock_client,
            trigger_conditions=conditions
        )

        # NEEDS_REVIEW should continue
        verdict_needs_review = AdversarialVerdict(
            verdict=VerdictType.NEEDS_REVIEW,
            confidence=0.5,
            summary="Test",
            reasoning="Test",
            attacker_strength=0.5,
            defender_strength=0.5,
        )
        should_continue, reason = verifier.should_continue_debate(
            verdict=verdict_needs_review,
            current_round=1,
            max_rounds=3,
        )
        assert should_continue is True

        # CONFIRMED with high confidence should not continue
        verdict_confirmed = AdversarialVerdict(
            verdict=VerdictType.CONFIRMED,
            confidence=0.9,
            summary="Test",
            reasoning="Test",
            attacker_strength=0.9,
            defender_strength=0.3,
        )
        should_continue, reason = verifier.should_continue_debate(
            verdict=verdict_confirmed,
            current_round=1,
            max_rounds=3,
        )
        assert should_continue is False

        # Max rounds reached should not continue
        should_continue, reason = verifier.should_continue_debate(
            verdict=verdict_needs_review,
            current_round=3,
            max_rounds=3,
        )
        assert should_continue is False
        assert "Maximum rounds" in reason

    def test_calculate_argument_strength(self, sample_finding):
        """Test _calculate_argument_strength method."""
        mock_client = MockLLMClient("")
        verifier = ArbiterVerifier(llm_client=mock_client)

        # Strong attacker with PoC
        strong_attacker = VerificationArgument(
            role="attacker",
            claim="Strong claim",
            evidence=["Evidence 1", "Evidence 2"],
            reasoning="Strong reasoning",
            strength=ArgumentStrength.DEFINITIVE,
            confidence=0.9,
            poc_code="1' OR '1'='1",
            exploitation_steps=["Step 1", "Step 2", "Step 3"],
            prerequisites=["Auth required"],
        )

        strength = verifier._calculate_argument_strength(strong_attacker)
        assert strength > 0.9  # Should be boosted by PoC and steps

        # Weak defender
        weak_defender = VerificationArgument(
            role="defender",
            claim="Weak claim",
            evidence=[],
            reasoning="",
            strength=ArgumentStrength.WEAK,
            confidence=0.2,
        )

        strength = verifier._calculate_argument_strength(weak_defender)
        assert strength < 0.3

    def test_get_verdict_explanation(self, sample_finding):
        """Test get_verdict_explanation method."""
        mock_client = MockLLMClient("")
        verifier = ArbiterVerifier(llm_client=mock_client)

        verdict = AdversarialVerdict(
            verdict=VerdictType.CONFIRMED,
            confidence=0.9,
            summary="Test summary",
            reasoning="Test reasoning",
            attacker_strength=0.9,
            defender_strength=0.3,
            recommended_action="fix",
            priority="critical",
            key_factors=["Factor 1", "Factor 2"],
            round_number=2,
        )

        explanation = verifier.get_verdict_explanation(verdict)

        assert "CONFIRMED" in explanation
        assert "90%" in explanation
        assert "fix" in explanation.lower()
        assert "critical" in explanation.lower()
        assert "Test summary" in explanation
        assert "Debate Rounds" in explanation
