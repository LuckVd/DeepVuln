"""
CodeQL Language Decider - LLM-driven language selection for CodeQL scanning.

This module provides intelligent decision-making for which programming languages
should be prioritized for CodeQL deep scanning, using LLM analysis with fallback
to deterministic baseline strategies.
"""

import asyncio
import json
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.llm.client import LLMClient, LLMError, LLMJSONParseError

from .build_assessor import BuildDifficultyAssessor
from .models import (
    BaselineStrategy,
    DecisionConstraints,
    DecisionError,
    LanguageDecision,
    LanguageDecisionInput,
    LanguageRecommendation,
    LanguageStructure,
    SkippedLanguage,
)
from .prompts import (
    build_decision_prompt,
    build_system_prompt,
    parse_time_estimate,
    validate_decision_response,
)

logger = get_logger(__name__)


class CodeQLLanguageDecider:
    """
    LLM-driven CodeQL language selection decisioner.

    Analyzes project characteristics and recommends which languages to
    prioritize for CodeQL scanning, with fallback to deterministic baseline.
    """

    def __init__(
        self,
        llm_client: LLMClient | None = None,
        project_path: Path | None = None,
        constraints: DecisionConstraints | None = None,
    ):
        """
        Initialize the decider.

        Args:
            llm_client: LLM client for AI decision making.
            project_path: Root path of the project.
            constraints: Decision constraints configuration.
        """
        self.llm_client = llm_client
        self.project_path = project_path or Path.cwd()
        self.constraints = constraints or DecisionConstraints()
        self._build_assessor = BuildDifficultyAssessor(self.project_path)

    async def decide(self, input_data: LanguageDecisionInput) -> LanguageDecision | DecisionError:
        """
        Make a language selection decision.

        First attempts LLM-based decision, falls back to deterministic baseline
        if LLM fails or returns invalid results.

        Args:
            input_data: Complete input data for the decision.

        Returns:
            LanguageDecision on success, DecisionError on failure.
        """
        # Try LLM decision first
        if self.llm_client and self.constraints.min_confidence > 0:
            try:
                decision = await self._make_llm_decision(input_data)
                if decision and decision.confidence >= self.constraints.min_confidence:
                    logger.info(
                        f"LLM decision successful: languages={decision.recommended_languages}, "
                        f"confidence={decision.confidence:.2f}"
                    )
                    return decision
                elif decision:
                    logger.warning(
                        f"LLM confidence below threshold ({decision.confidence:.2f} < "
                        f"{self.constraints.min_confidence}), using baseline"
                    )
            except LLMError as e:
                logger.warning(f"LLM decision failed, falling back to baseline: {e}")
            except Exception as e:
                logger.error(f"Unexpected error in LLM decision: {e}")

        # Fall back to baseline
        baseline = self._make_baseline_decision(input_data)
        baseline.decision_source = "baseline"
        logger.info(f"Using baseline decision: languages={baseline.recommended_languages}")
        return baseline

    async def _make_llm_decision(self, input_data: LanguageDecisionInput) -> LanguageDecision | None:
        """
        Make decision using LLM.

        Args:
            input_data: Input data for decision.

        Returns:
            LanguageDecision or None if failed.
        """
        if not self.llm_client:
            return None

        # Build prompt
        prompt = build_decision_prompt(input_data)
        system_prompt = build_system_prompt()

        try:
            # Call LLM with timeout
            response = await asyncio.wait_for(
                self.llm_client.complete_with_context(
                    system_prompt=system_prompt,
                    user_prompt=prompt,
                ),
                timeout=self.constraints.llm_timeout_seconds,
            )

            # Parse JSON response
            content = response.content.strip()

            # Handle markdown code blocks
            if content.startswith("```"):
                lines = content.split("\n")
                content = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

            # Parse and validate
            parsed = json.loads(content)
            errors = validate_decision_response(parsed)

            if errors:
                logger.warning("LLM response validation failed", errors=errors)
                return None

            # Build decision from parsed response
            decision = self._build_decision_from_response(parsed, input_data)
            decision.decision_source = "llm"
            return decision

        except json.JSONDecodeError as e:
            logger.warning("Failed to parse LLM response as JSON", error=str(e))
            return None
        except asyncio.TimeoutError:
            logger.warning("LLM decision timed out")
            return None
        except LLMError as e:
            raise e
        except Exception as e:
            logger.error("Unexpected error in LLM decision", error=str(e))
            return None

    def _build_decision_from_response(
        self,
        response: dict[str, Any],
        input_data: LanguageDecisionInput,
    ) -> LanguageDecision:
        """
        Build LanguageDecision from LLM response.

        Args:
            response: Parsed JSON response from LLM.
            input_data: Original input data for enrichment.

        Returns:
            LanguageDecision object.
        """
        # Build recommendations
        recommendations = []
        rec_map = {}
        if "recommendations" in response:
            for rec in response["recommendations"]:
                rec_map[rec["language"].lower()] = rec
                recommendations.append(
                    LanguageRecommendation(
                        language=rec["language"],
                        priority_score=rec.get("priority_score", 0.5),
                        reasoning=rec.get("reasoning", ""),
                        estimated_time_seconds=rec.get("estimated_time_seconds", 0),
                    )
                )

        # Ensure all recommended languages have recommendations
        for lang in response.get("recommended_languages", []):
            if lang.lower() not in rec_map:
                recommendations.append(
                    LanguageRecommendation(
                        language=lang,
                        priority_score=0.5,
                        reasoning="Recommended by LLM",
                        estimated_time_seconds=0,
                    )
                )

        # Parse time estimate
        estimated_seconds = response.get("estimated_total_seconds", 0)
        if not estimated_seconds:
            estimated_seconds = parse_time_estimate(
                response.get("estimated_total_time", "")
            )

        # Apply time budget if needed
        time_budget_applied = False
        recommended = list(response.get("recommended_languages", []))
        if estimated_seconds > self.constraints.max_time_budget_seconds:
            recommended, estimated_seconds = self._apply_time_budget(
                recommendations,
                input_data,
            )
            time_budget_applied = True

        # Get skip reasons
        skip_reasons = response.get("skip_reasons", {})

        decision = LanguageDecision(
            recommended_languages=recommended,
            recommendations=recommendations,
            skipped_languages=response.get("skipped_languages", []),
            skip_reasons=skip_reasons,
            estimated_total_time=response.get("estimated_total_time", ""),
            estimated_total_seconds=estimated_seconds,
            confidence=response.get("confidence", 0.5),
            time_budget_applied=time_budget_applied,
            decision_source="llm",
            reasoning_summary=response.get("reasoning_summary", ""),
        )

        return decision

    def _apply_time_budget(
        self,
        recommendations: list[LanguageRecommendation],
        input_data: LanguageDecisionInput,
    ) -> tuple[list[str], int]:
        """
        Apply time budget constraint to recommendations.

        Args:
            recommendations: List of language recommendations.
            input_data: Input data for difficulty lookup.

        Returns:
            Tuple of (trimmed language list, total estimated time).
        """
        # Sort by priority score
        sorted_recs = sorted(recommendations, key=lambda x: x.priority_score, reverse=True)

        selected = []
        total_time = 0

        for rec in sorted_recs:
            # Get estimated time from build difficulties
            diff = input_data.build_difficulties.get(rec.language.lower())
            est_time = rec.estimated_time_seconds
            if diff and diff.estimated_time_seconds > 0:
                est_time = diff.estimated_time_seconds

            if total_time + est_time <= self.constraints.max_time_budget_seconds:
                selected.append(rec.language)
                total_time += est_time
            else:
                break

        return selected, total_time

    def _make_baseline_decision(self, input_data: LanguageDecisionInput) -> LanguageDecision:
        """
        Make decision using deterministic baseline strategy.

        Dispatches to specific strategy implementation based on constraints.

        Args:
            input_data: Input data for decision.

        Returns:
            LanguageDecision from baseline algorithm.
        """
        strategy = self.constraints.baseline_strategy

        if strategy == BaselineStrategy.LANGUAGE_FIRST:
            return self._language_first_baseline(input_data)
        elif strategy == BaselineStrategy.ATTACK_SURFACE_FIRST:
            return self._attack_surface_first_baseline(input_data)
        elif strategy == BaselineStrategy.SEMGREP_FIRST:
            return self._semgrep_first_baseline(input_data)
        else:
            # Default: hybrid strategy
            return self._hybrid_baseline(input_data)

    def _hybrid_baseline(self, input_data: LanguageDecisionInput) -> LanguageDecision:
        """
        Hybrid baseline: 60% language size + 40% attack surface.

        Args:
            input_data: Input data for decision.

        Returns:
            LanguageDecision from hybrid algorithm.
        """
        # Calculate scores for each language
        scores: dict[str, float] = {}
        max_entry_points = max(
            input_data.attack_surface.entry_points_by_language.values()
        ) if input_data.attack_surface.entry_points_by_language else 1

        for lang in input_data.languages:
            lang_name = lang.name.lower()

            # Language size score (60% weight)
            language_score = lang.percentage / 100.0  # Normalize to 0-1

            # Attack surface score (40% weight)
            entry_points = input_data.attack_surface.entry_points_by_language.get(lang_name, 0)
            attack_score = entry_points / max_entry_points if max_entry_points > 0 else 0

            # Combined score
            scores[lang_name] = 0.6 * language_score + 0.4 * attack_score

        # Get Semgrep severity boost
        if input_data.semgrep_result:
            for lang_name, counts in input_data.semgrep_result.findings_by_language.items():
                lang_lower = lang_name.lower()
                if lang_lower in scores:
                    # Boost for critical/high findings
                    critical = counts.get("critical", 0)
                    high = counts.get("high", 0)
                    boost = min(0.3, (critical * 0.1 + high * 0.05))  # Cap at 0.3
                    scores[lang_lower] = min(1.0, scores[lang_lower] + boost)

        return self._build_decision_from_scores(
            input_data, scores, "Hybrid baseline: 60% language size + 40% attack surface weight"
        )

    def _language_first_baseline(self, input_data: LanguageDecisionInput) -> LanguageDecision:
        """
        Language-first baseline: select primary/largest language(s).

        Args:
            input_data: Input data for decision.

        Returns:
            LanguageDecision with largest languages prioritized.
        """
        scores: dict[str, float] = {}

        for lang in input_data.languages:
            lang_name = lang.name.lower()
            # Pure language size score
            scores[lang_name] = lang.percentage / 100.0

        return self._build_decision_from_scores(
            input_data, scores, "Language-first baseline: prioritized by code size"
        )

    def _attack_surface_first_baseline(self, input_data: LanguageDecisionInput) -> LanguageDecision:
        """
        Attack-surface-first baseline: select languages with most entry points.

        Args:
            input_data: Input data for decision.

        Returns:
            LanguageDecision with highest attack surface languages.
        """
        scores: dict[str, float] = {}
        max_entry_points = max(
            input_data.attack_surface.entry_points_by_language.values()
        ) if input_data.attack_surface.entry_points_by_language else 1

        for lang in input_data.languages:
            lang_name = lang.name.lower()
            entry_points = input_data.attack_surface.entry_points_by_language.get(lang_name, 0)
            # Normalize to 0-1
            scores[lang_name] = entry_points / max_entry_points if max_entry_points > 0 else 0

        return self._build_decision_from_scores(
            input_data, scores, "Attack-surface-first baseline: prioritized by entry points"
        )

    def _semgrep_first_baseline(self, input_data: LanguageDecisionInput) -> LanguageDecision:
        """
        Semgrep-first baseline: select languages with most Semgrep findings.

        Args:
            input_data: Input data for decision.

        Returns:
            LanguageDecision with highest Semgrep findings languages.
        """
        scores: dict[str, float] = {}

        # Initialize all languages with base score
        for lang in input_data.languages:
            lang_name = lang.name.lower()
            scores[lang_name] = 0.1  # Small base score

        # Score based on Semgrep findings
        if input_data.semgrep_result:
            max_weighted = 1
            # Find max weighted score for normalization
            for counts in input_data.semgrep_result.findings_by_language.values():
                critical = counts.get("critical", 0) * 3
                high = counts.get("high", 0) * 2
                medium = counts.get("medium", 0) * 1
                low = counts.get("low", 0) * 0.5
                weighted = critical + high + medium + low
                max_weighted = max(max_weighted, weighted)

            for lang_name, counts in input_data.semgrep_result.findings_by_language.items():
                lang_lower = lang_name.lower()
                # Weight by severity
                critical = counts.get("critical", 0) * 3
                high = counts.get("high", 0) * 2
                medium = counts.get("medium", 0) * 1
                low = counts.get("low", 0) * 0.5
                total_weighted = critical + high + medium + low
                # Normalize to 0-1 range
                scores[lang_lower] = min(1.0, total_weighted / max_weighted) if max_weighted > 0 else 0.1

        return self._build_decision_from_scores(
            input_data, scores, "Semgrep-first baseline: prioritized by finding severity"
        )

    def _build_decision_from_scores(
        self,
        input_data: LanguageDecisionInput,
        scores: dict[str, float],
        reasoning_summary: str,
    ) -> LanguageDecision:
        """
        Build LanguageDecision from computed scores.

        Args:
            input_data: Input data for decision.
            scores: Language scores (0-1 range).
            reasoning_summary: Summary of scoring method.

        Returns:
            LanguageDecision with selected/skipped languages.
        """
        # Sort by score and apply constraints
        sorted_langs = sorted(scores.items(), key=lambda x: x[1], reverse=True)

        # Filter to CodeQL-supported languages
        codeql_supported = input_data.get_codeql_supported_languages()
        sorted_langs = [(lang, score) for lang, score in sorted_langs if lang in codeql_supported]

        # Apply time budget
        selected = []
        skipped = []
        skip_reasons = {}
        total_time = 0
        recommendations = []

        for lang, score in sorted_langs:
            diff = input_data.build_difficulties.get(lang)
            est_time = diff.estimated_time_seconds if diff else 300  # Default 5 min

            if (
                len(selected) < self.constraints.max_languages
                and total_time + est_time <= self.constraints.max_time_budget_seconds
            ):
                selected.append(lang)
                total_time += est_time
                recommendations.append(
                    LanguageRecommendation(
                        language=lang,
                        priority_score=score,
                        reasoning=self._get_baseline_reasoning(lang, score, input_data),
                        estimated_time_seconds=est_time,
                    )
                )
            else:
                skipped.append(lang)
                if len(selected) >= self.constraints.max_languages:
                    skip_reasons[lang] = "Exceeded maximum language limit"
                else:
                    skip_reasons[lang] = "Exceeded time budget"

        # Format total time
        minutes = total_time // 60
        seconds = total_time % 60
        time_str = f"{minutes} minutes" if seconds == 0 else f"{minutes}m {seconds}s"

        return LanguageDecision(
            recommended_languages=selected,
            recommendations=recommendations,
            skipped_languages=skipped,
            skip_reasons=skip_reasons,
            estimated_total_time=time_str,
            estimated_total_seconds=total_time,
            confidence=0.7,  # Baseline has fixed confidence
            time_budget_applied=len(skipped) > 0,
            decision_source="baseline",
            reasoning_summary=reasoning_summary,
        )

    def _get_baseline_reasoning(
        self,
        language: str,
        score: float,
        input_data: LanguageDecisionInput,
    ) -> str:
        """Generate reasoning for baseline recommendation."""
        lang_info = next(
            (l for l in input_data.languages if l.name.lower() == language),
            None
        )
        entry_points = input_data.attack_surface.entry_points_by_language.get(language, 0)

        parts = []
        if lang_info:
            parts.append(f"{lang_info.role} language ({lang_info.percentage:.1f}% of code)")
        if entry_points > 0:
            parts.append(f"{entry_points} entry points")

        if input_data.semgrep_result:
            counts = input_data.semgrep_result.findings_by_language.get(language, {})
            high = counts.get("high", 0)
            critical = counts.get("critical", 0)
            if critical > 0 or high > 0:
                parts.append(f"{critical} critical, {high} high Semgrep findings")

        return "; ".join(parts) if parts else f"Score: {score:.2f}"

    def get_decision_explanation(self, decision: LanguageDecision) -> str:
        """
        Generate human-readable explanation of the decision.

        Args:
            decision: The language decision to explain.

        Returns:
            Human-readable explanation string.
        """
        lines = []

        lines.append("## CodeQL Language Decision")
        lines.append(f"**Source**: {decision.decision_source}")
        lines.append(f"**Confidence**: {decision.confidence:.0%}")
        lines.append("")

        if decision.recommended_languages:
            lines.append("### Recommended Languages")
            for lang in decision.recommended_languages:
                rec = next(
                    (r for r in decision.recommendations if r.language == lang),
                    None
                )
                if rec:
                    lines.append(f"- **{lang}** (score: {rec.priority_score:.2f})")
                    if rec.reasoning:
                        lines.append(f"  - {rec.reasoning}")
                else:
                    lines.append(f"- **{lang}**")
            lines.append(f"\n**Estimated Time**: {decision.estimated_total_time}")

        if decision.skipped_languages:
            lines.append("\n### Skipped Languages")
            for lang in decision.skipped_languages:
                reason = decision.skip_reasons.get(lang, "Not recommended")
                lines.append(f"- {lang}: {reason}")

        if decision.time_budget_applied:
            lines.append("\n*Time budget constraint was applied.*")

        return "\n".join(lines)
