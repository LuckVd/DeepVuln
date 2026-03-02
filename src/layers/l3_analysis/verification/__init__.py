"""
L3.5 Adversarial Verification Layer

This module implements a three-role adversarial verification system:
- Attacker: Attempts to construct PoCs and prove exploitability
- Defender: Checks for sanitizers and defense mechanisms
- Arbiter: Makes final judgment based on both arguments
"""

from .models import (
    AdversarialVerdict,
    VerificationArgument,
    VerificationResult,
    VerdictType,
)
from .attacker import AttackerVerifier
from .defender import DefenderVerifier
from .arbiter import ArbiterVerifier
from .adversarial import AdversarialVerifier, AdversarialVerifierConfig

__all__ = [
    "AdversarialVerdict",
    "VerificationArgument",
    "VerificationResult",
    "VerdictType",
    "AttackerVerifier",
    "DefenderVerifier",
    "ArbiterVerifier",
    "AdversarialVerifier",
    "AdversarialVerifierConfig",
]
