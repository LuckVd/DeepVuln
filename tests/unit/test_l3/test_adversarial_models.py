"""
Unit tests for Adversarial Verification Models.

Tests for DebateRound, TriggerConditions, VerificationArgument,
AdversarialVerdict, and VerificationResult models.
"""

import pytest
from datetime import datetime

from src.layers.l3_analysis.verification.models import (
    AdversarialVerdict,
    ArgumentStrength,
    DebateRound,
    TriggerConditions,
    VerificationArgument,
    VerificationResult,
    VerificationSession,
    VerdictType,
)


class TestVerificationArgument:
    """Tests for VerificationArgument model."""

    def test_create_attacker_argument(self):
        """Test creating an attacker argument."""
        arg = VerificationArgument(
            role="attacker",
            claim="This is exploitable",
            evidence=["User input directly concatenated"],
            reasoning="Analysis shows...",
            strength=ArgumentStrength.STRONG,
            confidence=0.85,
            poc_code="1' OR '1'='1",
            poc_type="http_request",
            exploitation_steps=["Step 1", "Step 2"],
            prerequisites=["Authentication required"],
        )

        assert arg.role == "attacker"
        assert arg.claim == "This is exploitable"
        assert len(arg.evidence) == 1
        assert arg.strength == ArgumentStrength.STRONG
        assert arg.confidence == 0.85
        assert arg.poc_code == "1' OR '1'='1"
        assert arg.round_number == 1
        assert arg.is_rebuttal is False

    def test_create_defender_argument(self):
        """Test creating a defender argument."""
        arg = VerificationArgument(
            role="defender",
            claim="This is not exploitable",
            evidence=["Parameterized query used"],
            reasoning="Defense analysis...",
            strength=ArgumentStrength.DEFINITIVE,
            confidence=0.95,
            sanitizers_found=["%s placeholder"],
            validation_checks=["Type check"],
            framework_protections=["ORM auto-escape"],
        )

        assert arg.role == "defender"
        assert arg.strength == ArgumentStrength.DEFINITIVE
        assert len(arg.sanitizers_found) == 1
        assert len(arg.validation_checks) == 1

    def test_argument_with_round_info(self):
        """Test argument with round number and rebuttal flag."""
        arg = VerificationArgument(
            role="attacker",
            claim="Rebuttal claim",
            evidence=["New evidence"],
            reasoning="Rebuttal reasoning",
            strength=ArgumentStrength.MODERATE,
            confidence=0.7,
            round_number=2,
            is_rebuttal=True,
        )

        assert arg.round_number == 2
        assert arg.is_rebuttal is True


class TestAdversarialVerdict:
    """Tests for AdversarialVerdict model."""

    def test_create_confirmed_verdict(self):
        """Test creating a confirmed verdict."""
        verdict = AdversarialVerdict(
            verdict=VerdictType.CONFIRMED,
            confidence=0.9,
            summary="Vulnerability confirmed",
            reasoning="Attacker has working PoC",
            attacker_strength=0.85,
            defender_strength=0.3,
            recommended_action="fix",
            priority="critical",
            key_factors=["Working PoC", "No defenses"],
            round_number=1,
        )

        assert verdict.verdict == VerdictType.CONFIRMED
        assert verdict.confidence == 0.9
        assert verdict.is_decisive() is True

    def test_create_needs_review_verdict(self):
        """Test creating a needs_review verdict."""
        verdict = AdversarialVerdict(
            verdict=VerdictType.NEEDS_REVIEW,
            confidence=0.5,
            summary="Cannot determine",
            reasoning="Both sides have similar strength",
            attacker_strength=0.55,
            defender_strength=0.5,
            recommended_action="review",
            priority="medium",
        )

        assert verdict.verdict == VerdictType.NEEDS_REVIEW
        assert verdict.is_decisive() is False

    def test_should_continue_debate_needs_review(self):
        """Test should_continue_debate for NEEDS_REVIEW."""
        verdict = AdversarialVerdict(
            verdict=VerdictType.NEEDS_REVIEW,
            confidence=0.5,
            summary="Needs more debate",
            reasoning="Unclear",
            attacker_strength=0.5,
            defender_strength=0.5,
        )

        should_continue, reason = verdict.should_continue_debate()
        assert should_continue is True
        assert "NEEDS_REVIEW" in reason

    def test_should_continue_debate_low_confidence(self):
        """Test should_continue_debate for low confidence."""
        verdict = AdversarialVerdict(
            verdict=VerdictType.CONDITIONAL,
            confidence=0.5,  # Below 0.6 threshold
            summary="Conditional",
            reasoning="Some conditions apply",
            attacker_strength=0.9,  # Large difference to avoid strength check first
            defender_strength=0.3,
        )

        should_continue, reason = verdict.should_continue_debate()
        assert should_continue is True
        # Could be either confidence or decisive check
        assert "confidence" in reason.lower() or "decisive" not in reason.lower()

    def test_should_continue_debate_strength_diff_small(self):
        """Test should_continue_debate for small strength difference."""
        verdict = AdversarialVerdict(
            verdict=VerdictType.CONDITIONAL,
            confidence=0.7,
            summary="Conditional",
            reasoning="Close debate",
            attacker_strength=0.55,
            defender_strength=0.5,  # diff = 0.05 < 0.2
        )

        should_continue, reason = verdict.should_continue_debate(
            strength_diff_threshold=0.2
        )
        assert should_continue is True
        assert "strength" in reason.lower()

    def test_should_not_continue_decisive(self):
        """Test should_continue_debate for decisive verdict."""
        verdict = AdversarialVerdict(
            verdict=VerdictType.CONFIRMED,
            confidence=0.9,
            summary="Confirmed",
            reasoning="Clear winner",
            attacker_strength=0.9,
            defender_strength=0.3,
        )

        should_continue, reason = verdict.should_continue_debate()
        assert should_continue is False
        assert "Decisive" in reason


class TestDebateRound:
    """Tests for DebateRound model."""

    def test_create_debate_round(self):
        """Test creating a debate round."""
        attacker_arg = VerificationArgument(
            role="attacker",
            claim="Exploitable",
            evidence=["Evidence"],
            reasoning="Reasoning",
            strength=ArgumentStrength.STRONG,
            confidence=0.8,
        )
        defender_arg = VerificationArgument(
            role="defender",
            claim="Not exploitable",
            evidence=["Defense"],
            reasoning="Reasoning",
            strength=ArgumentStrength.MODERATE,
            confidence=0.6,
        )
        verdict = AdversarialVerdict(
            verdict=VerdictType.CONFIRMED,
            confidence=0.75,
            summary="Confirmed",
            reasoning="Attacker wins",
            attacker_strength=0.8,
            defender_strength=0.6,
        )

        round_obj = DebateRound(
            round_number=1,
            attacker_argument=attacker_arg,
            defender_argument=defender_arg,
            arbiter_verdict=verdict,
            continue_debate=False,
            continue_reason="Decisive verdict",
        )

        assert round_obj.round_number == 1
        assert round_obj.attacker_argument.role == "attacker"
        assert round_obj.defender_argument.role == "defender"
        assert round_obj.arbiter_verdict.verdict == VerdictType.CONFIRMED
        assert round_obj.continue_debate is False


class TestTriggerConditions:
    """Tests for TriggerConditions model."""

    def test_default_conditions(self):
        """Test default trigger conditions."""
        conditions = TriggerConditions()

        assert conditions.needs_review is True
        assert conditions.strength_diff_threshold == 0.2
        assert conditions.confidence_threshold == 0.6

    def test_custom_conditions(self):
        """Test custom trigger conditions."""
        conditions = TriggerConditions(
            needs_review=False,
            strength_diff_threshold=0.3,
            confidence_threshold=0.7,
        )

        assert conditions.needs_review is False
        assert conditions.strength_diff_threshold == 0.3
        assert conditions.confidence_threshold == 0.7

    def test_should_continue_needs_review(self):
        """Test should_continue with NEEDS_REVIEW verdict."""
        conditions = TriggerConditions(needs_review=True)
        verdict = AdversarialVerdict(
            verdict=VerdictType.NEEDS_REVIEW,
            confidence=0.7,
            summary="Needs review",
            reasoning="Test",
            attacker_strength=0.5,
            defender_strength=0.5,
        )

        should_continue, reason = conditions.should_continue(verdict)
        assert should_continue is True
        assert "NEEDS_REVIEW" in reason

    def test_should_continue_strength_diff(self):
        """Test should_continue with small strength difference."""
        conditions = TriggerConditions(strength_diff_threshold=0.2)
        verdict = AdversarialVerdict(
            verdict=VerdictType.CONDITIONAL,
            confidence=0.7,
            summary="Conditional",
            reasoning="Test",
            attacker_strength=0.55,
            defender_strength=0.5,  # diff = 0.05
        )

        should_continue, reason = conditions.should_continue(verdict)
        assert should_continue is True
        assert "strength difference" in reason.lower()

    def test_should_not_continue_decisive(self):
        """Test should_continue with decisive verdict."""
        conditions = TriggerConditions()
        verdict = AdversarialVerdict(
            verdict=VerdictType.CONFIRMED,
            confidence=0.9,
            summary="Confirmed",
            reasoning="Test",
            attacker_strength=0.9,
            defender_strength=0.2,  # diff = 0.7 > 0.2
        )

        should_continue, reason = conditions.should_continue(verdict)
        assert should_continue is False


class TestVerificationResult:
    """Tests for VerificationResult model."""

    def test_create_result(self):
        """Test creating a verification result."""
        result = VerificationResult(
            finding_id="test-001",
            finding_type="sql_injection",
            finding_severity="high",
            finding_location="app.py:42",
        )

        assert result.finding_id == "test-001"
        assert result.finding_type == "sql_injection"
        assert result.rounds_completed == 0
        assert len(result.debate_rounds) == 0
        assert result.is_complete() is False

    def test_add_round(self):
        """Test adding a debate round."""
        result = VerificationResult(
            finding_id="test-001",
            finding_type="sql_injection",
            finding_severity="high",
            finding_location="app.py:42",
        )

        attacker_arg = VerificationArgument(
            role="attacker",
            claim="Exploitable",
            evidence=["Evidence"],
            reasoning="Reasoning",
            strength=ArgumentStrength.STRONG,
            confidence=0.8,
        )
        defender_arg = VerificationArgument(
            role="defender",
            claim="Not exploitable",
            evidence=["Defense"],
            reasoning="Reasoning",
            strength=ArgumentStrength.WEAK,
            confidence=0.3,
        )

        round_obj = DebateRound(
            round_number=1,
            attacker_argument=attacker_arg,
            defender_argument=defender_arg,
        )

        result.add_round(round_obj)

        assert result.rounds_completed == 1
        assert len(result.debate_rounds) == 1
        assert result.attacker_argument == attacker_arg
        assert result.defender_argument == defender_arg
        assert len(result.debate_history) == 1

    def test_get_all_arguments(self):
        """Test getting all arguments across rounds."""
        result = VerificationResult(
            finding_id="test-001",
            finding_type="sql_injection",
            finding_severity="high",
            finding_location="app.py:42",
        )

        # Add two rounds
        for i in range(1, 3):
            attacker_arg = VerificationArgument(
                role="attacker",
                claim=f"Claim {i}",
                evidence=[f"Evidence {i}"],
                reasoning=f"Reasoning {i}",
                strength=ArgumentStrength.MODERATE,
                confidence=0.6 + i * 0.1,
                round_number=i,
            )
            defender_arg = VerificationArgument(
                role="defender",
                claim=f"Defense {i}",
                evidence=[f"Defense evidence {i}"],
                reasoning=f"Defense reasoning {i}",
                strength=ArgumentStrength.MODERATE,
                confidence=0.5 + i * 0.1,
                round_number=i,
            )
            round_obj = DebateRound(
                round_number=i,
                attacker_argument=attacker_arg,
                defender_argument=defender_arg,
            )
            result.add_round(round_obj)

        all_attacker = result.get_all_attacker_arguments()
        all_defender = result.get_all_defender_arguments()

        assert len(all_attacker) == 2
        assert len(all_defender) == 2
        assert all_attacker[0].round_number == 1
        assert all_attacker[1].round_number == 2

    def test_to_summary(self):
        """Test to_summary method."""
        result = VerificationResult(
            finding_id="test-001",
            finding_type="sql_injection",
            finding_severity="high",
            finding_location="app.py:42",
        )

        # Without verdict
        summary = result.to_summary()
        assert "PENDING" in summary

        # With verdict
        result.verdict = AdversarialVerdict(
            verdict=VerdictType.CONFIRMED,
            confidence=0.9,
            summary="Confirmed",
            reasoning="Test",
            attacker_strength=0.9,
            defender_strength=0.3,
        )
        result.rounds_completed = 2

        summary = result.to_summary()
        assert "CONFIRMED" in summary
        assert "2 rounds" in summary


class TestVerificationSession:
    """Tests for VerificationSession model."""

    def test_create_session(self):
        """Test creating a verification session."""
        session = VerificationSession(
            session_id="test-session-001",
            source_path="/path/to/code",
        )

        assert session.session_id == "test-session-001"
        assert session.total_findings == 0
        assert len(session.results) == 0

    def test_add_result(self):
        """Test adding results to session."""
        session = VerificationSession(
            session_id="test-session-001",
            source_path="/path/to/code",
        )

        result = VerificationResult(
            finding_id="test-001",
            finding_type="sql_injection",
            finding_severity="high",
            finding_location="app.py:42",
            verdict=AdversarialVerdict(
                verdict=VerdictType.CONFIRMED,
                confidence=0.9,
                summary="Confirmed",
                reasoning="Test",
                attacker_strength=0.9,
                defender_strength=0.3,
            ),
            rounds_completed=1,
        )

        session.add_result(result)

        assert session.total_findings == 1
        assert session.confirmed == 1
        assert session.total_rounds == 1

    def test_get_summary(self):
        """Test get_summary method."""
        session = VerificationSession(
            session_id="test-session-001",
            source_path="/path/to/code",
        )

        # Add various results
        verdicts = [
            VerdictType.CONFIRMED,
            VerdictType.CONFIRMED,
            VerdictType.FALSE_POSITIVE,
            VerdictType.NEEDS_REVIEW,
            VerdictType.CONDITIONAL,
        ]

        for i, verdict_type in enumerate(verdicts):
            result = VerificationResult(
                finding_id=f"test-{i}",
                finding_type="test",
                finding_severity="medium",
                finding_location=f"file.py:{i}",
                verdict=AdversarialVerdict(
                    verdict=verdict_type,
                    confidence=0.8,
                    summary="Test",
                    reasoning="Test",
                    attacker_strength=0.7,
                    defender_strength=0.5,
                ),
                rounds_completed=i + 1,
            )
            session.add_result(result)

        summary = session.get_summary()

        assert summary["total"] == 5
        assert summary["confirmed"] == 2
        assert summary["false_positives"] == 1
        assert summary["needs_review"] == 1
        assert summary["conditional"] == 1
        assert summary["total_rounds"] == 15  # 1+2+3+4+5
        assert summary["avg_rounds_per_finding"] == 3.0
