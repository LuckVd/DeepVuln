"""
L3.5 Adversarial Verification Layer

This module implements a three-role adversarial verification system:
- Attacker: Attempts to construct PoCs and prove exploitability
- Defender: Checks for sanitizers and defense mechanisms
- Arbiter: Makes final judgment based on both arguments

Pre-filter components (P8-08):
- VerificationGatekeeper: Smart gating for adversarial verification

Strategy library (Phase 18 / P6-子项5):
- StrategyLibrary: real attack/defense knowledge (bypass techniques, attack
  chains, defense mechanisms) wired into the base attacker/defender prompts.
"""

from .adversarial import AdversarialVerifier, AdversarialVerifierConfig
from .arbiter import ArbiterVerifier
from .attacker import AttackerVerifier
from .defender import DefenderVerifier
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
from .verification_gatekeeper import (
    VerificationGatekeeper,
    BatchGatekeeper,
    AutoDecision,
    should_verify_finding,
)

# Strategy library — real attack/defense knowledge used by the base prompts
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
    # Pre-filter (P8-08)
    "VerificationGatekeeper",
    "BatchGatekeeper",
    "AutoDecision",
    "should_verify_finding",
]
