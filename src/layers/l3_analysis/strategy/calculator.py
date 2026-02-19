"""
Priority Calculator

Calculates audit priority scores for targets based on multiple factors.
"""

from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.strategy.models import (
    AuditPriority,
    AuditPriorityLevel,
    AuditTarget,
    PriorityScore,
)


class PriorityCalculator:
    """
    Calculates audit priority for targets.

    Uses a weighted scoring system based on:
    - Attack surface exposure (35%)
    - Technology stack risk (25%)
    - Code complexity (20%)
    - Historical vulnerability risk (20%)
    """

    # Default weights for score components
    DEFAULT_WEIGHTS = {
        "attack_surface": 0.35,
        "tech_risk": 0.25,
        "complexity": 0.20,
        "history_risk": 0.20,
    }

    # Entry point type risk scores (higher = more risky)
    ENTRY_POINT_RISK_SCORES = {
        "http": 0.8,
        "rpc": 0.7,
        "grpc": 0.7,
        "mq": 0.6,
        "websocket": 0.75,
        "cli": 0.5,
        "cron": 0.4,
        "file": 0.6,
    }

    # HTTP method risk scores
    HTTP_METHOD_RISK_SCORES = {
        "POST": 0.9,
        "PUT": 0.85,
        "PATCH": 0.8,
        "DELETE": 0.85,
        "GET": 0.6,
        "HEAD": 0.3,
        "OPTIONS": 0.2,
    }

    # Framework risk scores (based on historical vulnerabilities)
    FRAMEWORK_RISK_SCORES = {
        # High risk frameworks
        "struts": 0.9,  # Apache Struts has many critical CVEs
        "django": 0.6,
        "flask": 0.55,
        "spring": 0.65,
        "express": 0.55,
        "fastapi": 0.5,
        "gin": 0.5,
        "echo": 0.5,
        "rails": 0.65,
        "laravel": 0.6,
        # Lower risk
        "aspnet": 0.55,
        "ktor": 0.45,
        "fiber": 0.45,
    }

    # File patterns that indicate higher risk
    HIGH_RISK_PATTERNS = [
        "auth", "login", "password", "credential", "token", "session",
        "payment", "checkout", "transfer", "admin", "config", "secret",
        "api", "upload", "download", "import", "export", "query",
    ]

    # File patterns that indicate lower risk (should be skipped)
    SKIP_PATTERNS = [
        "test", "spec", "mock", "fixture", "example", "sample",
        "docs", "readme", "changelog", "license",
        "__pycache__", "node_modules", "vendor",
    ]

    def __init__(
        self,
        weights: dict[str, float] | None = None,
        custom_config: dict[str, Any] | None = None,
    ):
        """
        Initialize the priority calculator.

        Args:
            weights: Custom weights for score components.
            custom_config: Custom configuration overrides.
        """
        self.logger = get_logger(__name__)
        self.weights = {**self.DEFAULT_WEIGHTS, **(weights or {})}
        self.config = custom_config or {}

        # Normalize weights to sum to 1.0
        total = sum(self.weights.values())
        if total > 0:
            self.weights = {k: v / total for k, v in self.weights.items()}

    def calculate(self, target: AuditTarget) -> AuditPriority:
        """
        Calculate priority for a single target.

        Args:
            target: The audit target to calculate priority for.

        Returns:
            AuditPriority with score breakdown and level.
        """
        score = PriorityScore(
            attack_surface_weight=self.weights["attack_surface"],
            tech_risk_weight=self.weights["tech_risk"],
            complexity_weight=self.weights["complexity"],
            history_risk_weight=self.weights["history_risk"],
        )

        # Calculate component scores
        score.attack_surface = self._calculate_attack_surface_score(target, score.factors, score.deductions)
        score.tech_risk = self._calculate_tech_risk_score(target, score.factors, score.deductions)
        score.complexity = self._calculate_complexity_score(target, score.factors, score.deductions)
        score.history_risk = self._calculate_history_risk_score(target, score.factors, score.deductions)

        # Calculate final weighted score
        score.final_score = score.calculate_weighted_score()

        # Determine priority level
        level = score.to_level(score.final_score)

        # Check for skip conditions
        if self._should_skip(target):
            level = AuditPriorityLevel.SKIP
            score.deductions.append("Target matches skip pattern (test/generated code)")

        return AuditPriority(
            level=level,
            attack_surface_score=score.attack_surface,
            tech_risk_score=score.tech_risk,
            complexity_score=score.complexity,
            history_risk_score=score.history_risk,
            final_score=score.final_score,
            factors=score.factors,
        )

    def calculate_batch(self, targets: list[AuditTarget]) -> list[AuditTarget]:
        """
        Calculate priority for multiple targets.

        Args:
            targets: List of audit targets.

        Returns:
            List of targets with priority assigned.
        """
        for target in targets:
            target.priority = self.calculate(target)
        return targets

    def _calculate_attack_surface_score(
        self,
        target: AuditTarget,
        factors: list[str],
        deductions: list[str],
    ) -> float:
        """
        Calculate attack surface exposure score.

        Based on:
        - Entry point type (HTTP, RPC, MQ, etc.)
        - HTTP method risk (POST > GET)
        - Authentication requirement
        - Parameter count
        """
        score = 0.0

        # Entry point type risk
        if target.entry_point_type:
            entry_score = self.ENTRY_POINT_RISK_SCORES.get(
                target.entry_point_type.lower(), 0.5
            )
            score += entry_score * 0.4
            if entry_score >= 0.7:
                factors.append(f"High-risk entry point type: {target.entry_point_type}")

        # HTTP method risk
        if target.http_method:
            method_score = self.HTTP_METHOD_RISK_SCORES.get(
                target.http_method.upper(), 0.5
            )
            score += method_score * 0.3
            if method_score >= 0.8:
                factors.append(f"High-risk HTTP method: {target.http_method}")

        # Authentication factor
        if not target.auth_required:
            score += 0.15
            factors.append("No authentication required")
        else:
            deductions.append("Authentication required")
            score -= 0.05

        # Parameter count (more params = more attack surface)
        param_count = len(target.params)
        if param_count > 5:
            score += 0.1
            factors.append(f"Many parameters ({param_count})")
        elif param_count > 0:
            score += 0.05 * (param_count / 5)

        # File path risk patterns
        file_lower = target.file_path.lower()
        for pattern in self.HIGH_RISK_PATTERNS:
            if pattern in file_lower:
                score += 0.05
                factors.append(f"High-risk pattern in path: {pattern}")
                break

        return min(1.0, max(0.0, score))

    def _calculate_tech_risk_score(
        self,
        target: AuditTarget,
        factors: list[str],
        deductions: list[str],
    ) -> float:
        """
        Calculate technology stack risk score.

        Based on:
        - Framework historical vulnerability data
        - Language-specific risks
        """
        score = 0.4  # Base score

        # Framework risk
        if target.framework:
            fw_lower = target.framework.lower()
            fw_score = self.FRAMEWORK_RISK_SCORES.get(fw_lower, 0.5)
            score = (score + fw_score) / 2

            if fw_score >= 0.7:
                factors.append(f"High-risk framework: {target.framework}")
            elif fw_score <= 0.45:
                deductions.append(f"Lower-risk framework: {target.framework}")

        # Language-specific adjustments
        if target.language:
            lang_lower = target.language.lower()
            if lang_lower in ("php", "perl"):
                score += 0.15
                factors.append(f"Higher-risk language: {target.language}")
            elif lang_lower in ("rust", "go"):
                score -= 0.05
                deductions.append(f"Memory-safe language: {target.language}")

        return min(1.0, max(0.0, score))

    def _calculate_complexity_score(
        self,
        target: AuditTarget,
        factors: list[str],
        deductions: list[str],
    ) -> float:
        """
        Calculate code complexity score.

        Based on:
        - Cyclomatic complexity
        - Lines of code
        """
        score = 0.3  # Base score

        # Cyclomatic complexity
        if target.cyclomatic_complexity:
            cc = target.cyclomatic_complexity
            if cc > 20:
                score += 0.4
                factors.append(f"Very high complexity (CC={cc})")
            elif cc > 10:
                score += 0.25
                factors.append(f"High complexity (CC={cc})")
            elif cc > 5:
                score += 0.1
            else:
                deductions.append(f"Low complexity (CC={cc})")

        # Lines of code
        if target.lines_of_code:
            loc = target.lines_of_code
            if loc > 500:
                score += 0.3
                factors.append(f"Large file ({loc} LOC)")
            elif loc > 200:
                score += 0.15
            elif loc < 50:
                deductions.append(f"Small file ({loc} LOC)")

        return min(1.0, max(0.0, score))

    def _calculate_history_risk_score(
        self,
        target: AuditTarget,
        factors: list[str],
        deductions: list[str],
    ) -> float:
        """
        Calculate historical vulnerability risk score.

        Based on:
        - Git history (security-related commits)
        - Known vulnerability patterns

        Note: This is a placeholder for future implementation.
        Currently returns a neutral score.
        """
        # TODO: Integrate with Git history analysis
        # - Check for security-related commits in file history
        # - Check for recent changes to security-critical code
        # - Check for known vulnerability patterns

        score = 0.3  # Neutral base score

        # Check for security-sensitive patterns in file path
        file_lower = target.file_path.lower()
        security_patterns = ["security", "auth", "crypto", "validation", "sanitize"]
        for pattern in security_patterns:
            if pattern in file_lower:
                score += 0.2
                factors.append(f"Security-related file: {pattern}")
                break

        return min(1.0, max(0.0, score))

    def _should_skip(self, target: AuditTarget) -> bool:
        """
        Determine if a target should be skipped.

        Args:
            target: The audit target to check.

        Returns:
            True if the target should be skipped.
        """
        file_lower = target.file_path.lower()
        name_lower = target.name.lower()

        for pattern in self.SKIP_PATTERNS:
            if pattern in file_lower or pattern in name_lower:
                return True

        # Skip generated files
        if file_lower.endswith((".min.js", ".min.css", ".pb.go", "_pb2.py")):
            return True

        # Skip lock files
        if file_lower.endswith(("package-lock.json", "yarn.lock", "poetry.lock", "go.sum")):
            return True

        return False

    def get_priority_distribution(
        self,
        targets: list[AuditTarget],
    ) -> dict[str, int]:
        """
        Get distribution of targets by priority level.

        Args:
            targets: List of targets with priorities calculated.

        Returns:
            Dictionary with count per priority level.
        """
        distribution = {level.value: 0 for level in AuditPriorityLevel}

        for target in targets:
            if target.priority:
                distribution[target.priority.level.value] += 1

        return distribution

    def get_statistics(self, targets: list[AuditTarget]) -> dict[str, Any]:
        """
        Get statistics about priority calculation.

        Args:
            targets: List of targets with priorities.

        Returns:
            Statistics dictionary.
        """
        if not targets:
            return {"total": 0}

        scores = [
            t.priority.final_score
            for t in targets
            if t.priority
        ]

        distribution = self.get_priority_distribution(targets)

        return {
            "total": len(targets),
            "with_priority": len(scores),
            "average_score": sum(scores) / len(scores) if scores else 0,
            "max_score": max(scores) if scores else 0,
            "min_score": min(scores) if scores else 0,
            "distribution": distribution,
        }
