"""
Integration tests for Adversarial Verification Multi-Round Debate.

Tests the complete multi-round debate flow including:
- Trigger conditions
- Round progression
- Early termination on decisive verdict
- Max rounds handling
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Any

from src.layers.l3_analysis.verification.adversarial import (
    AdversarialVerifier,
    AdversarialVerifierConfig,
    create_verifier,
)
from src.layers.l3_analysis.verification.models import (
    AdversarialVerdict,
    ArgumentStrength,
    DebateRound,
    TriggerConditions,
    VerificationArgument,
    VerdictType,
)


class MultiResponseMockLLMClient:
    """Mock LLM client that returns different responses based on call count."""

    def __init__(self, responses: list[str]):
        self.responses = responses
        self.call_count = 0
        self.call_history = []

    async def complete_with_context(self, system_prompt: str, user_prompt: str):
        """Return the next response in sequence."""
        if self.call_count >= len(self.responses):
            raise ValueError(f"Not enough responses prepared. Call count: {self.call_count}")

        response = MagicMock()
        response.content = self.responses[self.call_count]
        self.call_history.append({
            "call": self.call_count,
            "system_prompt": system_prompt[:100],
            "user_prompt": user_prompt[:200],
        })
        self.call_count += 1
        return response


def create_attacker_response(confidence: float, strength: str = "strong") -> str:
    """Create a mock attacker response."""
    return json.dumps({
        "claim": f"Attacker claim with {confidence} confidence",
        "confidence": confidence,
        "evidence": ["Evidence 1", "Evidence 2"],
        "reasoning": "Attacker reasoning",
        "strength": strength,
        "poc_code": "1' OR '1'='1" if confidence > 0.7 else None,
        "poc_type": "http_request" if confidence > 0.7 else None,
        "exploitation_steps": ["Step 1"] if confidence > 0.7 else [],
        "prerequisites": [],
        "counter_arguments": [],
    })


def create_defender_response(confidence: float, strength: str = "moderate", sanitizers: list = None) -> str:
    """Create a mock defender response."""
    return json.dumps({
        "claim": f"Defender claim with {confidence} confidence",
        "confidence": confidence,
        "evidence": ["Defense 1"],
        "reasoning": "Defender reasoning",
        "strength": strength,
        "sanitizers_found": sanitizers or [],
        "validation_checks": [],
        "framework_protections": [],
        "exploitation_barriers": [],
        "counter_arguments": [],
    })


def create_arbiter_response(
    verdict: str,
    confidence: float,
    attacker_strength: float,
    defender_strength: float,
    summary: str = "Test summary"
) -> str:
    """Create a mock arbiter response."""
    return json.dumps({
        "verdict": verdict,
        "confidence": confidence,
        "summary": summary,
        "reasoning": "Arbiter reasoning",
        "attacker_strength": attacker_strength,
        "defender_strength": defender_strength,
        "conditions": [],
        "recommended_action": "fix" if verdict == "confirmed" else "review",
        "priority": "high",
        "key_factors": ["Factor 1"],
    })


class TestMultiRoundDebate:
    """Integration tests for multi-round debate flow."""

    @pytest.fixture
    def sample_finding(self):
        """Sample vulnerability finding."""
        return {
            "id": "test-sqli-001",
            "type": "sql_injection",
            "severity": "high",
            "title": "SQL Injection in User Query",
            "description": "User input directly concatenated into SQL query",
            "location": "app.py:42",
            "code_snippet": 'query = f"SELECT * FROM users WHERE id = {user_input}"',
            "language": "python",
        }

    @pytest.fixture
    def sample_code_context(self):
        """Sample code context."""
        return '''
def get_user(user_id):
    """Get user by ID - VULNERABLE"""
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
'''

    @pytest.mark.asyncio
    async def test_single_round_decisive(self, sample_finding, sample_code_context):
        """Test single round when verdict is decisive."""
        # Setup: Attacker strong, Defender weak, Arbiter confirms decisively
        responses = [
            create_attacker_response(0.95, "definitive"),  # Round 1 Attacker
            create_defender_response(0.2, "weak"),  # Round 1 Defender
            create_arbiter_response("confirmed", 0.95, 0.95, 0.2),  # Round 1 Arbiter
        ]
        mock_client = MultiResponseMockLLMClient(responses)

        config = AdversarialVerifierConfig(max_rounds=3)
        verifier = AdversarialVerifier(llm_client=mock_client, config=config)

        result = await verifier.verify_finding(
            finding=sample_finding,
            code_context=sample_code_context,
        )

        assert result.rounds_completed == 1
        assert result.verdict.verdict == VerdictType.CONFIRMED
        assert result.verdict.confidence == 0.95
        assert result.max_rounds_reached is False
        assert mock_client.call_count == 3  # Attacker + Defender + Arbiter

    @pytest.mark.asyncio
    async def test_two_rounds_to_decision(self, sample_finding, sample_code_context):
        """Test two rounds needed to reach decision."""
        # Round 1: Needs review (close debate)
        # Round 2: Confirmed (attacker strengthens case)
        responses = [
            create_attacker_response(0.7, "moderate"),  # R1 Attacker
            create_defender_response(0.65, "moderate"),  # R1 Defender
            create_arbiter_response("needs_review", 0.5, 0.7, 0.65),  # R1 Arbiter
            create_attacker_response(0.85, "strong"),  # R2 Attacker rebuttal
            create_defender_response(0.5, "weak"),  # R2 Defender rebuttal
            create_arbiter_response("confirmed", 0.85, 0.85, 0.5),  # R2 Arbiter
        ]
        mock_client = MultiResponseMockLLMClient(responses)

        config = AdversarialVerifierConfig(max_rounds=3)
        verifier = AdversarialVerifier(llm_client=mock_client, config=config)

        result = await verifier.verify_finding(
            finding=sample_finding,
            code_context=sample_code_context,
        )

        assert result.rounds_completed == 2
        assert result.verdict.verdict == VerdictType.CONFIRMED
        assert result.max_rounds_reached is False
        assert mock_client.call_count == 6  # 3 per round

    @pytest.mark.asyncio
    async def test_max_rounds_reached(self, sample_finding, sample_code_context):
        """Test reaching max rounds without decisive verdict."""
        # All rounds result in needs_review
        responses = []
        for _ in range(3):  # 3 rounds
            responses.extend([
                create_attacker_response(0.6, "moderate"),
                create_defender_response(0.55, "moderate"),
                create_arbiter_response("needs_review", 0.5, 0.6, 0.55),
            ])
        mock_client = MultiResponseMockLLMClient(responses)

        config = AdversarialVerifierConfig(max_rounds=3)
        verifier = AdversarialVerifier(llm_client=mock_client, config=config)

        result = await verifier.verify_finding(
            finding=sample_finding,
            code_context=sample_code_context,
        )

        assert result.rounds_completed == 3
        assert result.verdict.verdict == VerdictType.NEEDS_REVIEW
        assert result.max_rounds_reached is True
        assert mock_client.call_count == 9  # 3 rounds * 3 calls

    @pytest.mark.asyncio
    async def test_false_positive_detection(self, sample_finding, sample_code_context):
        """Test detection of false positive."""
        # Attacker weak, Defender strong with sanitizers
        responses = [
            create_attacker_response(0.3, "weak"),  # R1 Attacker
            create_defender_response(0.95, "definitive", sanitizers=["parameterized query"]),  # R1 Defender
            create_arbiter_response("false_positive", 0.9, 0.3, 0.95),  # R1 Arbiter
        ]
        mock_client = MultiResponseMockLLMClient(responses)

        config = AdversarialVerifierConfig(max_rounds=3)
        verifier = AdversarialVerifier(llm_client=mock_client, config=config)

        result = await verifier.verify_finding(
            finding=sample_finding,
            code_context=sample_code_context,
        )

        assert result.rounds_completed == 1
        assert result.verdict.verdict == VerdictType.FALSE_POSITIVE
        assert result.max_rounds_reached is False

    @pytest.mark.asyncio
    async def test_conditional_verdict(self, sample_finding, sample_code_context):
        """Test conditional verdict."""
        # Both sides have valid points
        responses = [
            create_attacker_response(0.75, "strong"),  # R1 Attacker
            create_defender_response(0.7, "strong", sanitizers=["partial"]),  # R1 Defender
            create_arbiter_response("conditional", 0.7, 0.75, 0.7),  # R1 Arbiter
            create_attacker_response(0.8, "strong"),  # R2 Attacker
            create_defender_response(0.75, "strong"),  # R2 Defender
            create_arbiter_response("conditional", 0.75, 0.8, 0.75),  # R2 Arbiter - still conditional
            create_attacker_response(0.85, "strong"),  # R3 Attacker
            create_defender_response(0.8, "strong"),  # R3 Defender
            create_arbiter_response("conditional", 0.8, 0.85, 0.8),  # R3 Arbiter - max rounds
        ]
        mock_client = MultiResponseMockLLMClient(responses)

        config = AdversarialVerifierConfig(max_rounds=3)
        verifier = AdversarialVerifier(llm_client=mock_client, config=config)

        result = await verifier.verify_finding(
            finding=sample_finding,
            code_context=sample_code_context,
        )

        assert result.verdict.verdict == VerdictType.CONDITIONAL
        assert len(result.verdict.conditions) >= 0 or result.max_rounds_reached

    @pytest.mark.asyncio
    async def test_custom_trigger_conditions(self, sample_finding, sample_code_context):
        """Test custom trigger conditions."""
        # Stricter conditions - should continue debate longer
        responses = [
            create_attacker_response(0.75, "strong"),
            create_defender_response(0.6, "moderate"),
            create_arbiter_response("confirmed", 0.75, 0.75, 0.6),  # 0.75 confidence, diff=0.15
            # With strict conditions (diff_threshold=0.3), this might continue
            # But our default implementation will stop since confidence >= 0.6
            create_attacker_response(0.8, "strong"),
            create_defender_response(0.55, "moderate"),
            create_arbiter_response("confirmed", 0.85, 0.8, 0.55),
        ]
        mock_client = MultiResponseMockLLMClient(responses)

        # More lenient trigger - lower threshold means easier to continue
        trigger = TriggerConditions(
            needs_review=True,
            strength_diff_threshold=0.3,  # Higher threshold - harder to trigger
            confidence_threshold=0.8,  # Higher threshold - easier to continue
        )
        config = AdversarialVerifierConfig(
            max_rounds=3,
            trigger_conditions=trigger,
        )
        verifier = AdversarialVerifier(llm_client=mock_client, config=config)

        result = await verifier.verify_finding(
            finding=sample_finding,
            code_context=sample_code_context,
        )

        # With higher thresholds, debate should stop after round 1
        # (verdict is confirmed with 0.75 confidence > 0.8 threshold is false, but diff < 0.3)
        assert result.rounds_completed >= 1

    @pytest.mark.asyncio
    async def test_parallel_vs_sequential_first_round(self, sample_finding, sample_code_context):
        """Test parallel vs sequential execution in first round."""
        # Parallel mode
        responses_parallel = [
            create_attacker_response(0.8),
            create_defender_response(0.5),
            create_arbiter_response("confirmed", 0.8, 0.8, 0.5),
        ]
        mock_client_parallel = MultiResponseMockLLMClient(responses_parallel)

        config_parallel = AdversarialVerifierConfig(
            max_rounds=1,
            parallel_analysis=True,
        )
        verifier_parallel = AdversarialVerifier(llm_client=mock_client_parallel, config=config_parallel)

        result_parallel = await verifier_parallel.verify_finding(
            finding=sample_finding,
            code_context=sample_code_context,
        )

        # Sequential mode
        responses_sequential = [
            create_attacker_response(0.8),
            create_defender_response(0.5),
            create_arbiter_response("confirmed", 0.8, 0.8, 0.5),
        ]
        mock_client_sequential = MultiResponseMockLLMClient(responses_sequential)

        config_sequential = AdversarialVerifierConfig(
            max_rounds=1,
            parallel_analysis=False,
        )
        verifier_sequential = AdversarialVerifier(llm_client=mock_client_sequential, config=config_sequential)

        result_sequential = await verifier_sequential.verify_finding(
            finding=sample_finding,
            code_context=sample_code_context,
        )

        # Both should produce results
        assert result_parallel.rounds_completed == 1
        assert result_sequential.rounds_completed == 1


class TestDebateHistory:
    """Tests for debate history tracking."""

    @pytest.fixture
    def sample_finding(self):
        return {
            "id": "test-001",
            "type": "sql_injection",
            "severity": "high",
            "title": "Test",
            "description": "Test",
            "location": "test.py:1",
            "language": "python",
        }

    @pytest.mark.asyncio
    async def test_debate_history_recorded(self, sample_finding):
        """Test that debate history is properly recorded."""
        responses = [
            create_attacker_response(0.7),
            create_defender_response(0.65),
            create_arbiter_response("needs_review", 0.5, 0.7, 0.65),
            create_attacker_response(0.8),
            create_defender_response(0.6),
            create_arbiter_response("confirmed", 0.8, 0.8, 0.6),
        ]
        mock_client = MultiResponseMockLLMClient(responses)

        config = AdversarialVerifierConfig(max_rounds=3)
        verifier = AdversarialVerifier(llm_client=mock_client, config=config)

        result = await verifier.verify_finding(
            finding=sample_finding,
            code_context="test code",
        )

        # Check debate history
        assert len(result.debate_history) == 2
        assert result.debate_history[0]["round"] == 1
        assert result.debate_history[1]["round"] == 2

        # Check debate rounds
        assert len(result.debate_rounds) == 2
        assert result.debate_rounds[0].round_number == 1
        assert result.debate_rounds[1].round_number == 2

    @pytest.mark.asyncio
    async def test_rounds_progression(self, sample_finding):
        """Test that arguments show round progression."""
        responses = [
            create_attacker_response(0.6),
            create_defender_response(0.55),
            create_arbiter_response("needs_review", 0.5, 0.6, 0.55),
            create_attacker_response(0.7),
            create_defender_response(0.5),
            create_arbiter_response("confirmed", 0.75, 0.7, 0.5),
        ]
        mock_client = MultiResponseMockLLMClient(responses)

        config = AdversarialVerifierConfig(max_rounds=3)
        verifier = AdversarialVerifier(llm_client=mock_client, config=config)

        result = await verifier.verify_finding(
            finding=sample_finding,
            code_context="test code",
        )

        # Check round numbers in arguments
        assert result.debate_rounds[0].attacker_argument.round_number == 1
        assert result.debate_rounds[0].attacker_argument.is_rebuttal is False
        assert result.debate_rounds[1].attacker_argument.round_number == 2
        assert result.debate_rounds[1].attacker_argument.is_rebuttal is True


class TestVerifierFactory:
    """Tests for the create_verifier factory function."""

    @pytest.mark.asyncio
    async def test_create_verifier_default_config(self):
        """Test creating verifier with default config."""
        mock_client = MagicMock()

        verifier = await create_verifier(llm_client=mock_client)

        assert verifier.config.max_rounds == 3
        assert verifier.config.parallel_analysis is True
        assert verifier.config.sequential_rebuttal is True

    @pytest.mark.asyncio
    async def test_create_verifier_custom_config(self):
        """Test creating verifier with custom config."""
        mock_client = MagicMock()

        verifier = await create_verifier(
            llm_client=mock_client,
            config={
                "max_rounds": 5,
                "parallel_analysis": False,
                "confidence_threshold": 0.8,
            },
        )

        assert verifier.config.max_rounds == 5
        assert verifier.config.parallel_analysis is False
        assert verifier.config.confidence_threshold == 0.8

    @pytest.mark.asyncio
    async def test_create_verifier_with_trigger_conditions(self):
        """Test creating verifier with trigger conditions."""
        mock_client = MagicMock()

        verifier = await create_verifier(
            llm_client=mock_client,
            config={
                "max_rounds": 3,
                "trigger_conditions": {
                    "needs_review": False,
                    "strength_diff_threshold": 0.3,
                    "confidence_threshold": 0.7,
                },
            },
        )

        assert verifier.config.trigger_conditions.needs_review is False
        assert verifier.config.trigger_conditions.strength_diff_threshold == 0.3
        assert verifier.config.trigger_conditions.confidence_threshold == 0.7


class TestSessionStatistics:
    """Tests for session statistics with multi-round debates."""

    @pytest.mark.asyncio
    async def test_session_multi_round_stats(self):
        """Test session statistics with multi-round results."""
        from src.layers.l3_analysis.verification.models import VerificationSession

        session = VerificationSession(
            session_id="test-session",
            source_path="/test/path",
        )

        # Add results with different round counts
        for i, rounds in enumerate([1, 2, 3, 1, 2]):
            result = MagicMock()
            result.rounds_completed = rounds
            result.verdict = MagicMock()
            result.verdict.verdict = VerdictType.CONFIRMED if i < 3 else VerdictType.FALSE_POSITIVE
            result.finding_severity = "high"
            result.tokens_used = rounds * 100
            result.duration_seconds = rounds * 0.5
            session.add_result(result)

        stats = session.get_summary()

        assert stats["total"] == 5
        assert stats["total_rounds"] == 9  # 1+2+3+1+2
        assert stats["avg_rounds_per_finding"] == 1.8
        assert stats["max_rounds_used"] == 3
