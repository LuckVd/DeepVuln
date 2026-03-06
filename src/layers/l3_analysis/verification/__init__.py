"""
L3.5 Adversarial Verification Layer

This module implements a three-role adversarial verification system:
- Attacker: Attempts to construct PoCs and prove exploitability
- Defender: Checks for sanitizers and defense mechanisms
- Arbiter: Makes final judgment based on both arguments

Enhanced with multi-round evolution:
- Strategy libraries for attackers and defenders
- Strategy evolution across rounds
- Learning from failures and successes
- Convergence detection
- Rule extraction for future use
"""

from .adversarial import AdversarialVerifier, AdversarialVerifierConfig
from .arbiter import ArbiterVerifier
from .attacker import AttackerVerifier
from .convergence import (
    ConvergenceChecker,
    ConvergenceConfig,
    ConvergenceReason,
    ConvergenceResult,
    ConvergenceState,
    RoundSummary,
)
from .defender import DefenderVerifier
from .enhanced_adversarial import (
    EnhancedAdversarialVerification,
    EnhancedVerificationConfig,
    create_enhanced_verifier,
)
from .models import (
    AdversarialVerdict,
    ArgumentStrength,
    DebateRound,
    TriggerConditions,
    VerdictType,
    VerificationArgument,
    VerificationResult,
    VerificationSession,
)

# Enhanced verification components
from .strategy_library import (
    AttackChainTemplate,
    AttackStrategy,
    BypassTechnique,
    DefenseMechanism,
    DefenseStrategy,
    EntryPoint,
    FailureRecord,
    PredictedAttack,
    StrategyLibrary,
    StrategyType,
    SuccessRecord,
    create_attacker_library,
    create_defender_library,
)

__all__ = [
    # Base models
    "AdversarialVerdict",
    "ArgumentStrength",
    "DebateRound",
    "TriggerConditions",
    "VerificationArgument",
    "VerificationResult",
    "VerificationSession",
    "VerdictType",
    # Base verifiers
    "AttackerVerifier",
    "DefenderVerifier",
    "ArbiterVerifier",
    "AdversarialVerifier",
    "AdversarialVerifierConfig",
    # Strategy library
    "AttackChainTemplate",
    "AttackStrategy",
    "BypassTechnique",
    "DefenseMechanism",
    "DefenseStrategy",
    "EntryPoint",
    "FailureRecord",
    "PredictedAttack",
    "StrategyLibrary",
    "StrategyType",
    "SuccessRecord",
    "create_attacker_library",
    "create_defender_library",
    # Convergence
    "ConvergenceChecker",
    "ConvergenceConfig",
    "ConvergenceReason",
    "ConvergenceResult",
    "ConvergenceState",
    "RoundSummary",
    # Enhanced verification
    "EnhancedAdversarialVerification",
    "EnhancedVerificationConfig",
    "create_enhanced_verifier",
]
