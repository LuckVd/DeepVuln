"""Preparation phase.

This phase handles tech stack detection and attack surface analysis.
"""

from pathlib import Path
from typing import Any
import logging


from .base import ScanPhase, PhaseResult

logger = logging.getLogger(__name__)


class PreparationPhase(ScanPhase):
    """Preparation phase (L1).

    This phase:
    - Detects the technology stack
    - Analyzes attack surface
    - Prepares file lists for engines
    """

    def __init__(self):
        super().__init__(
            name="L1_preparation",
            description="Tech Stack & Attack Surface Detection",
        )

    async def execute(
        self,
        context: "ScanContext",  # noqa: F821
    ) -> PhaseResult:
        """Execute preparation phase.

        Args:
            context: Scan context

        Returns:
            Phase result with detected tech stack and attack surface
        """
        # Import existing detectors
        from src.layers.l1_intelligence.tech_stack_detector.detector import TechStackDetector
        from src.layers.l1_intelligence.attack_surface.detector import AttackSurfaceDetector

        source_path = context.source_path

        # Detect tech stack
        tech_detector = TechStackDetector()
        tech_result = tech_detector.detect(source_path)

        # Get primary language
        primary_lang = "unknown"
        all_languages = []
        if tech_result.languages:
            primary_lang = tech_result.languages[0].language.value
            all_languages = [
                lang.language.value for lang in tech_result.languages
            ]

        logger.info(f"Detected primary language: {primary_lang}")
        logger.info(f"All languages: {all_languages}")

        # Initialize LLM client for attack surface detection if needed
        llm_client = None
        if context.config.model:
            from src.core.config import get_llm_config, get_openai_config
            from src.layers.l3_analysis.llm.openai_client import OpenAIClient

            try:
                llm_config = get_llm_config()
                openai_config = get_openai_config()
                llm_client = OpenAIClient(
                    model=context.config.model,
                    api_key=openai_config.get("api_key"),
                    base_url=openai_config.get("base_url"),
                    max_tokens=llm_config.get("max_tokens", 4096),
                )
            except Exception as e:
                logger.warning(f"Failed to initialize LLM client: {e}")

        # Detect attack surface
        surface_detector = AttackSurfaceDetector(
            llm_client=llm_client,
            enable_llm=llm_client is not None,
            llm_model=context.config.model or "gpt-4",
        )

        surface_report = await surface_detector.detect_attack_surface(
            source_path=source_path,
            primary_language=primary_lang,
        )

        # Update context statistics
        context.statistics.total_files = len(surface_report.files) if surface_report else 0
        context.statistics.indexed_files = context.statistics.total_files

        # Store results in context for later phases
        context.data = {  # type: ignore
            "primary_language": primary_lang,
            "all_languages": all_languages,
            "attack_surface": surface_report,
        }

        return PhaseResult(
            success=True,
            findings=[],
        )
