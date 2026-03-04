"""
Rule Gating Engine - Dynamic rule selection based on project characteristics.

This module provides intelligent rule filtering to reduce false positives
by analyzing TechStack and AttackSurface before Semgrep execution.

Target: 40%+ noise reduction before rule execution.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

from src.core.logger.logger import get_logger


class GatingMode(str, Enum):
    """Rule gating modes."""

    NORMAL = "normal"
    RESTRICTED = "restricted"


# Language to Semgrep pack mapping
LANGUAGE_PACK_MAP: dict[str, list[str]] = {
    "python": ["python", "python-lang-security"],
    "javascript": ["javascript", "javascript-lang-security"],
    "typescript": ["typescript", "typescript-lang-security", "javascript"],
    "java": ["java", "java-lang-security"],
    "go": ["go", "go-lang-security"],
    "ruby": ["ruby", "ruby-lang-security"],
    "php": ["php", "php-lang-security"],
    "csharp": ["csharp", "csharp-lang-security"],
    "cpp": ["cpp", "cpp-lang-security"],
    "c": ["c", "c-lang-security"],
    "rust": ["rust", "rust-lang-security"],
    "kotlin": ["kotlin", "kotlin-lang-security", "java"],
    "swift": ["swift", "swift-lang-security"],
    "scala": ["scala", "scala-lang-security", "java"],
}

# All available language packs
ALL_LANGUAGE_PACKS: set[str] = {
    "python", "python-lang-security",
    "javascript", "javascript-lang-security",
    "typescript", "typescript-lang-security",
    "java", "java-lang-security",
    "go", "go-lang-security",
    "ruby", "ruby-lang-security",
    "php", "php-lang-security",
    "csharp", "csharp-lang-security",
    "cpp", "cpp-lang-security",
    "c", "c-lang-security",
    "rust", "rust-lang-security",
    "kotlin", "kotlin-lang-security",
    "swift", "swift-lang-security",
    "scala", "scala-lang-security",
    "generic",
}

# Attack surface related packs
ATTACK_SURFACE_PACKS: dict[str, str] = {
    "web": "web-security",
    "api": "api-security",
    "http": "http-security",
    "websocket": "websocket-security",
    "cli": "cli-security",
    "rest": "rest-api-security",
}

# Rules to disable when no HTTP endpoints
NO_HTTP_DISABLED_RULES: list[str] = [
    "xss",
    "sqli",
    "sql-injection",
    "ssrf",
    "server-side-request-forgery",
    "cors",
    "csrf",
    "cross-site-request-forgery",
    "open-redirect",
    "http-response-splitting",
    "request-smuggling",
    "host-header-injection",
    "cookie-security",
    "session-fixation",
    "insecure-cookie",
    "xml-external-entity",
    "xxe",
]

# Rule IDs to disable when no HTTP endpoints
NO_HTTP_DISABLED_RULE_IDS: list[str] = [
    "generic.xss",
    "generic.sqli",
    "generic.ssrf",
    "generic.csrf",
    "generic.cors",
    "generic.open-redirect",
    "generic.http-response-splitting",
    "generic.request-smuggling",
    "generic.host-header-injection",
    "generic.cookie-security",
    "generic.session-fixation",
    "generic.insecure-cookie",
    "generic.xxe",
]

# WebSocket related rules
WEBSOCKET_RULE_IDS: list[str] = [
    "detect-insecure-websocket",
    "websocket-insecure",
    "websocket-no-origin-check",
    "websocket-missing-auth",
]

# CLI project disabled packs
CLI_DISABLED_PACKS: list[str] = [
    "web-security",
    "http-security",
    "rest-api-security",
    "api-security",
    "websocket-security",
]

# Always enabled packs (safety baseline)
ALWAYS_ENABLED_PACKS: set[str] = {
    "security",
    "secrets",
    "default",
}

# Never auto-disable these packs
PROTECTED_PACKS: set[str] = {
    "custom",
    "security",
    "secrets",
}


@dataclass
class RuleGatingResult:
    """
    Result of rule gating evaluation.

    Contains all information needed to configure Semgrep execution.
    """

    enabled_packs: list[str] = field(default_factory=list)
    disabled_packs: list[str] = field(default_factory=list)
    disabled_rule_ids: list[str] = field(default_factory=list)
    mode: Literal["normal", "restricted"] = "normal"

    # Metadata
    primary_language: str | None = None
    secondary_languages: list[str] = field(default_factory=list)
    has_http: bool = True
    has_websocket: bool = True
    is_cli_project: bool = False
    restricted_reason: str | None = None

    # Statistics
    total_packs_available: int = 0
    packs_disabled_count: int = 0
    rules_disabled_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "enabled_packs": self.enabled_packs,
            "disabled_packs": self.disabled_packs,
            "disabled_rule_ids": self.disabled_rule_ids,
            "mode": self.mode,
            "primary_language": self.primary_language,
            "secondary_languages": self.secondary_languages,
            "has_http": self.has_http,
            "has_websocket": self.has_websocket,
            "is_cli_project": self.is_cli_project,
            "restricted_reason": self.restricted_reason,
            "statistics": {
                "total_packs_available": self.total_packs_available,
                "packs_disabled_count": self.packs_disabled_count,
                "rules_disabled_count": self.rules_disabled_count,
            },
        }

    def get_reduction_percentage(self) -> float:
        """Calculate the estimated noise reduction percentage."""
        if self.total_packs_available == 0:
            return 0.0
        return (self.packs_disabled_count / self.total_packs_available) * 100


class RuleGatingEngine:
    """
    Engine for dynamically gating Semgrep rules based on project characteristics.

    Uses TechStack and AttackSurface analysis to determine which rules
    are relevant and which can be safely disabled.

    Target: 40%+ noise reduction.
    """

    def __init__(
        self,
        tech_stack: Any | None = None,
        attack_surface: Any | None = None,
    ):
        """
        Initialize the rule gating engine.

        Args:
            tech_stack: TechStack object from tech_stack_detector.
            attack_surface: AttackSurfaceReport object from attack_surface detector.
        """
        self.logger = get_logger(__name__)
        self.tech_stack = tech_stack
        self.attack_surface = attack_surface

    def evaluate(self) -> RuleGatingResult:
        """
        Evaluate and generate rule gating configuration.

        Returns:
            RuleGatingResult with enabled/disabled packs and rules.
        """
        result = RuleGatingResult()

        # Extract tech stack info
        self._extract_tech_stack_info(result)

        # Extract attack surface info
        self._extract_attack_surface_info(result)

        # Determine mode (normal vs restricted)
        self._determine_mode(result)

        # Apply language-based gating
        self._apply_language_gating(result)

        # Apply attack surface-based gating
        self._apply_attack_surface_gating(result)

        # Apply restricted mode rules if needed
        if result.mode == "restricted":
            self._apply_restricted_mode(result)

        # Calculate statistics
        self._calculate_statistics(result)

        self.logger.info(
            f"Rule gating complete: mode={result.mode}, "
            f"enabled_packs={len(result.enabled_packs)}, "
            f"disabled_packs={len(result.disabled_packs)}, "
            f"disabled_rules={len(result.disabled_rule_ids)}, "
            f"reduction={result.get_reduction_percentage():.1f}%"
        )

        return result

    def _extract_tech_stack_info(self, result: RuleGatingResult) -> None:
        """Extract information from tech stack."""
        if not self.tech_stack:
            return

        # Get primary language
        if hasattr(self.tech_stack, "primary_language") and self.tech_stack.primary_language:
            result.primary_language = self.tech_stack.primary_language.value

        # Get secondary languages
        if hasattr(self.tech_stack, "secondary_languages"):
            result.secondary_languages = [
                lang.value for lang in self.tech_stack.secondary_languages
            ]

        # Check if CLI project
        if hasattr(self.tech_stack, "project_type") and self.tech_stack.project_type:
            project_type_value = (
                self.tech_stack.project_type.value
                if hasattr(self.tech_stack.project_type, "value")
                else str(self.tech_stack.project_type)
            )
            result.is_cli_project = project_type_value.lower() == "cli"

    def _extract_attack_surface_info(self, result: RuleGatingResult) -> None:
        """Extract information from attack surface."""
        if not self.attack_surface:
            return

        # Check HTTP endpoints
        if hasattr(self.attack_surface, "http_endpoints"):
            result.has_http = self.attack_surface.http_endpoints > 0

        # Check WebSocket endpoints
        if hasattr(self.attack_surface, "websocket_endpoints"):
            result.has_websocket = self.attack_surface.websocket_endpoints > 0

    def _determine_mode(self, result: RuleGatingResult) -> None:
        """Determine if restricted mode should be used."""
        result.mode = "normal"

        if not self.tech_stack:
            return

        # Check primary language LOC percentage
        primary_loc_percentage = 0.0
        if hasattr(self.tech_stack, "languages") and self.tech_stack.languages:
            for lang_info in self.tech_stack.languages:
                if hasattr(lang_info, "role") and lang_info.role == "primary":
                    primary_loc_percentage = lang_info.loc_percentage
                    break

        # Check language count
        language_count = 0
        if hasattr(self.tech_stack, "languages"):
            language_count = len(self.tech_stack.languages)

        # Trigger restricted mode conditions
        reasons = []

        if primary_loc_percentage < 50.0 and primary_loc_percentage > 0:
            reasons.append(f"primary LOC percentage ({primary_loc_percentage:.1f}%) < 50%")

        if language_count > 4:
            reasons.append(f"language count ({language_count}) > 4")

        if reasons:
            result.mode = "restricted"
            result.restricted_reason = "; ".join(reasons)
            self.logger.info(f"Restricted mode triggered: {result.restricted_reason}")

    def _apply_language_gating(self, result: RuleGatingResult) -> None:
        """Apply language-based rule pack gating."""
        # Determine which language packs to enable
        enabled_lang_packs: set[str] = set()

        # Add primary language packs
        if result.primary_language:
            primary_lower = result.primary_language.lower()
            if primary_lower in LANGUAGE_PACK_MAP:
                enabled_lang_packs.update(LANGUAGE_PACK_MAP[primary_lower])

        # Add secondary language packs
        for lang in result.secondary_languages:
            lang_lower = lang.lower()
            if lang_lower in LANGUAGE_PACK_MAP:
                enabled_lang_packs.update(LANGUAGE_PACK_MAP[lang_lower])

        # If no language detected, enable generic pack only
        if not enabled_lang_packs:
            enabled_lang_packs.add("generic")

        # Always add security baseline
        enabled_lang_packs.update(ALWAYS_ENABLED_PACKS)

        # Determine disabled packs
        all_lang_packs = ALL_LANGUAGE_PACKS.copy()
        disabled_packs = all_lang_packs - enabled_lang_packs - PROTECTED_PACKS

        result.enabled_packs = sorted(list(enabled_lang_packs))
        result.disabled_packs.extend(sorted(list(disabled_packs)))

    def _apply_attack_surface_gating(self, result: RuleGatingResult) -> None:
        """Apply attack surface-based rule gating."""
        # HTTP-based gating
        if not result.has_http:
            self.logger.info("No HTTP endpoints detected, disabling web-related rules")

            # Disable web-related packs
            web_packs = [
                "web-security",
                "http-security",
                "api-security",
                "rest-api-security",
            ]
            for pack in web_packs:
                if pack not in result.disabled_packs and pack not in PROTECTED_PACKS:
                    result.disabled_packs.append(pack)

            # Disable HTTP-related rule IDs
            result.disabled_rule_ids.extend(NO_HTTP_DISABLED_RULE_IDS)

        # WebSocket-based gating
        if not result.has_websocket:
            self.logger.info("No WebSocket endpoints detected, disabling websocket rules")
            result.disabled_rule_ids.extend(WEBSOCKET_RULE_IDS)

        # CLI project gating
        if result.is_cli_project:
            self.logger.info("CLI project detected, disabling web/API packs")
            for pack in CLI_DISABLED_PACKS:
                if pack not in result.disabled_packs and pack not in PROTECTED_PACKS:
                    result.disabled_packs.append(pack)

    def _apply_restricted_mode(self, result: RuleGatingResult) -> None:
        """Apply restricted mode rules."""
        self.logger.info("Applying restricted mode rules")

        # Disable generic security pack in restricted mode
        generic_packs = ["generic", "generic-security"]
        for pack in generic_packs:
            if pack not in result.disabled_packs and pack not in PROTECTED_PACKS:
                result.disabled_packs.append(pack)

        # Keep only high-confidence packs
        # In restricted mode, we're more conservative about rules
        high_confidence_suffixes = ["-lang-security", "security"]

        # Filter enabled packs to high-confidence only
        filtered_packs = []
        for pack in result.enabled_packs:
            # Keep if it's a protected pack
            if pack in PROTECTED_PACKS:
                filtered_packs.append(pack)
                continue

            # Keep if it matches high-confidence pattern
            for suffix in high_confidence_suffixes:
                if suffix in pack:
                    filtered_packs.append(pack)
                    break

        # Update enabled packs
        result.enabled_packs = list(set(filtered_packs))

    def _calculate_statistics(self, result: RuleGatingResult) -> None:
        """Calculate gating statistics."""
        result.total_packs_available = len(ALL_LANGUAGE_PACKS) + len(ATTACK_SURFACE_PACKS)
        result.packs_disabled_count = len(result.disabled_packs)
        result.rules_disabled_count = len(result.disabled_rule_ids)

    def get_enabled_pack_configs(self, base_path: str = "rules/semgrep") -> list[str]:
        """
        Get Semgrep --config arguments for enabled packs.

        Args:
            base_path: Base path for rule files.

        Returns:
            List of config paths.
        """
        result = self.evaluate()
        configs = []

        for pack in result.enabled_packs:
            configs.append(f"{base_path}/{pack}")

        return configs

    def get_exclude_rule_args(self) -> list[str]:
        """
        Get Semgrep --exclude-rule arguments.

        Returns:
            List of rule IDs to exclude.
        """
        result = self.evaluate()
        return result.disabled_rule_ids


def create_rule_gating_engine(
    tech_stack: Any | None = None,
    attack_surface: Any | None = None,
) -> RuleGatingEngine:
    """
    Factory function to create a RuleGatingEngine.

    Args:
        tech_stack: TechStack object.
        attack_surface: AttackSurfaceReport object.

    Returns:
        Configured RuleGatingEngine instance.
    """
    return RuleGatingEngine(
        tech_stack=tech_stack,
        attack_surface=attack_surface,
    )
