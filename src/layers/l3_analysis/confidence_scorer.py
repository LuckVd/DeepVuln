"""
P6-04d: Confidence Scorer Module

Integrated from code-audit/references/core/verification_methodology.md.
Provides systematic confidence scoring for vulnerability findings.

Confidence Formula:
    最终置信度 = 基础分 + 验证加分 - 不确定减分

Confidence Levels:
    - 已确认 (90-100): PoC成功执行，危害明确
    - 高置信 (70-89): 多项证据支持，极有可能存在
    - 中置信 (50-69): 存在可疑模式，需进一步验证
    - 低置信 (30-49): 可能误报，证据不足
    - 疑似误报 (0-29): 大概率误报
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ConfidenceLevel(str, Enum):
    """Confidence level classification based on score."""

    CONFIRMED = "confirmed"          # 90-100: PoC success, clear impact
    HIGH = "high"                    # 70-89: Strong evidence, very likely real
    MEDIUM = "medium"                # 50-69: Suspicious pattern, needs verification
    LOW = "low"                      # 30-49: Possible false positive
    LIKELY_FP = "likely_false_positive"  # 0-29: Probably false positive


# Base scores from static analysis
BASE_SCORES: dict[str, int] = {
    "dangerous_pattern": 30,         # Clear dangerous pattern identified
    "traceable_dataflow": 20,        # Data flow can be traced
    "no_sanitization": 10,           # No sanitization measures found
    "cross_engine_validation": 15,   # Confirmed by multiple engines
    "ast_level_match": 10,           # AST-level pattern match (not just text)
}

# Verification bonuses from dynamic analysis
VERIFICATION_BONUSES: dict[str, int] = {
    "poc_success": 40,               # PoC executed successfully
    "timing_confirmed": 25,          # Time-based verification confirmed
    "error_triggered": 20,           # Error message triggered
    "multi_payload_success": 15,     # Multiple payloads succeeded
    "oob_callback": 20,              # Out-of-band callback received
    "boolean_blind_success": 20,     # Boolean-based blind injection confirmed
}

# Uncertainty penalties
UNCERTAINTY_PENALTIES: dict[str, int] = {
    "possible_sanitization": 20,     # Possible sanitization exists
    "requires_auth": 15,             # Authentication required
    "requires_config": 10,           # Specific configuration needed
    "complex_call_chain": 10,        # Complex call chain
    "framework_protection": 15,      # Framework may auto-protect
    "single_engine_only": 5,         # Only one engine detected
    "low_confidence_source": 10,     # Source has low confidence
    "speculative_evidence": 15,      # Evidence is speculative
}


class ConfidenceFactor(BaseModel):
    """A single factor contributing to confidence score."""

    name: str = Field(..., description="Factor identifier")
    description: str = Field(..., description="Human-readable description")
    score_delta: int = Field(..., description="Score change (+ or -)")
    category: str = Field(..., description="Category: base/verification/uncertainty")


class ConfidenceReport(BaseModel):
    """
    P6-04d: Complete confidence scoring report.
    """

    # Final score
    score: int = Field(..., ge=0, le=100, description="Final confidence score (0-100)")
    level: ConfidenceLevel = Field(..., description="Confidence level classification")
    level_description: str = Field(..., description="Human-readable level description")

    # Score breakdown
    base_score: int = Field(default=0, description="Base score from static analysis")
    verification_bonus: int = Field(default=0, description="Bonus from verification")
    uncertainty_penalty: int = Field(default=0, description="Penalty from uncertainties")

    # Factors
    factors: list[ConfidenceFactor] = Field(
        default_factory=list,
        description="All factors contributing to score",
    )

    # Recommendations
    needs_verification: bool = Field(
        default=False,
        description="Whether additional verification is recommended",
    )
    verification_suggestions: list[str] = Field(
        default_factory=list,
        description="Suggested verification methods",
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "score": self.score,
            "level": self.level.value,
            "base_score": self.base_score,
            "verification_bonus": self.verification_bonus,
            "uncertainty_penalty": self.uncertainty_penalty,
            "factors": [(f.name, f.score_delta) for f in self.factors],
            "needs_verification": self.needs_verification,
        }


class ConfidenceScorer:
    """
    P6-04d: Confidence Scorer based on verification methodology.

    Usage:
        scorer = ConfidenceScorer()
        scorer.add_static_analysis({
            "dangerous_pattern": True,
            "traceable_dataflow": True,
        })
        scorer.add_dynamic_verification({
            "poc_success": True,
        })
        scorer.apply_uncertainty({
            "requires_auth": True,
        })
        report = scorer.generate_report()
    """

    # Level thresholds
    LEVEL_THRESHOLDS: list[tuple[int, ConfidenceLevel, str]] = [
        (90, ConfidenceLevel.CONFIRMED, "已确认 - PoC成功执行，危害明确"),
        (70, ConfidenceLevel.HIGH, "高置信 - 多项证据支持，极有可能存在"),
        (50, ConfidenceLevel.MEDIUM, "中置信 - 存在可疑模式，需进一步验证"),
        (30, ConfidenceLevel.LOW, "低置信 - 可能误报，证据不足"),
        (0, ConfidenceLevel.LIKELY_FP, "疑似误报 - 大概率误报"),
    ]

    def __init__(self):
        self._score = 0
        self._factors: list[ConfidenceFactor] = []
        self._base_score = 0
        self._verification_bonus = 0
        self._uncertainty_penalty = 0

    def add_static_analysis(self, findings: dict[str, bool]) -> "ConfidenceScorer":
        """
        Add base scores from static analysis.

        Args:
            findings: Dict of finding keys to boolean values.
                     Keys should be from BASE_SCORES.

        Returns:
            self for chaining
        """
        for key, value in findings.items():
            if value and key in BASE_SCORES:
                delta = BASE_SCORES[key]
                self._score += delta
                self._base_score += delta
                self._factors.append(ConfidenceFactor(
                    name=key,
                    description=self._get_base_description(key),
                    score_delta=delta,
                    category="base",
                ))
        return self

    def add_dynamic_verification(self, results: dict[str, bool]) -> "ConfidenceScorer":
        """
        Add verification bonuses from dynamic analysis.

        Args:
            results: Dict of verification keys to boolean values.
                    Keys should be from VERIFICATION_BONUSES.

        Returns:
            self for chaining
        """
        for key, value in results.items():
            if value and key in VERIFICATION_BONUSES:
                delta = VERIFICATION_BONUSES[key]
                self._score += delta
                self._verification_bonus += delta
                self._factors.append(ConfidenceFactor(
                    name=key,
                    description=self._get_verification_description(key),
                    score_delta=delta,
                    category="verification",
                ))
        return self

    def apply_uncertainty(self, uncertainties: dict[str, bool]) -> "ConfidenceScorer":
        """
        Apply penalties for uncertain factors.

        Args:
            uncertainties: Dict of uncertainty keys to boolean values.
                          Keys should be from UNCERTAINTY_PENALTIES.

        Returns:
            self for chaining
        """
        for key, value in uncertainties.items():
            if value and key in UNCERTAINTY_PENALTIES:
                delta = -UNCERTAINTY_PENALTIES[key]
                self._score += delta
                self._uncertainty_penalty += UNCERTAINTY_PENALTIES[key]
                self._factors.append(ConfidenceFactor(
                    name=key,
                    description=self._get_uncertainty_description(key),
                    score_delta=delta,
                    category="uncertainty",
                ))
        return self

    def get_score(self) -> int:
        """Get the current score (clamped to 0-100)."""
        return max(0, min(100, self._score))

    def get_level(self) -> ConfidenceLevel:
        """Get the confidence level for current score."""
        score = self.get_score()
        for threshold, level, _ in self.LEVEL_THRESHOLDS:
            if score >= threshold:
                return level
        return ConfidenceLevel.LIKELY_FP

    def generate_report(self) -> ConfidenceReport:
        """Generate a complete confidence report."""
        score = self.get_score()
        level = self.get_level()
        level_desc = ""

        for threshold, lvl, desc in self.LEVEL_THRESHOLDS:
            if lvl == level:
                level_desc = desc
                break

        # Determine if verification is needed
        needs_verification = level in [
            ConfidenceLevel.MEDIUM,
            ConfidenceLevel.LOW,
        ]

        # Generate verification suggestions
        suggestions = []
        if needs_verification:
            if score < 50:
                suggestions.append("Consider manual code review")
            if not any(f.name == "poc_success" for f in self._factors):
                suggestions.append("Attempt PoC generation and execution")
            if not any(f.name == "timing_confirmed" for f in self._factors):
                suggestions.append("Try time-based verification")
            if not any(f.name == "error_triggered" for f in self._factors):
                suggestions.append("Check for error-based verification")

        return ConfidenceReport(
            score=score,
            level=level,
            level_description=level_desc,
            base_score=self._base_score,
            verification_bonus=self._verification_bonus,
            uncertainty_penalty=self._uncertainty_penalty,
            factors=self._factors.copy(),
            needs_verification=needs_verification,
            verification_suggestions=suggestions,
        )

    def _get_base_description(self, key: str) -> str:
        """Get human-readable description for base factor."""
        descriptions = {
            "dangerous_pattern": "识别到明确的危险模式",
            "traceable_dataflow": "数据流可追踪",
            "no_sanitization": "未发现净化措施",
            "cross_engine_validation": "多引擎交叉验证",
            "ast_level_match": "AST级别模式匹配",
        }
        return descriptions.get(key, key)

    def _get_verification_description(self, key: str) -> str:
        """Get human-readable description for verification factor."""
        descriptions = {
            "poc_success": "PoC执行成功",
            "timing_confirmed": "时间延迟验证通过",
            "error_triggered": "错误信息触发成功",
            "multi_payload_success": "多Payload成功",
            "oob_callback": "带外回调确认",
            "boolean_blind_success": "布尔盲注确认",
        }
        return descriptions.get(key, key)

    def _get_uncertainty_description(self, key: str) -> str:
        """Get human-readable description for uncertainty factor."""
        descriptions = {
            "possible_sanitization": "可能存在净化措施",
            "requires_auth": "需要认证",
            "requires_config": "需要特定配置",
            "complex_call_chain": "调用链复杂",
            "framework_protection": "框架可能自动防护",
            "single_engine_only": "仅单一引擎检测",
            "low_confidence_source": "来源置信度低",
            "speculative_evidence": "证据具有推测性",
        }
        return descriptions.get(key, key)


__all__ = [
    "ConfidenceLevel",
    "ConfidenceFactor",
    "ConfidenceReport",
    "ConfidenceScorer",
    "BASE_SCORES",
    "VERIFICATION_BONUSES",
    "UNCERTAINTY_PENALTIES",
]
