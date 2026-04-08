"""Attack surface detection service for web scanning.

This service wraps the CLI attack surface detection capabilities
for use in the web scanning pipeline (Phase 0 of ScanOrchestrator).

P14-01: AttackSurfaceDetection 集成
- 静态检测（endpoint/敏感函数）
- LLM 检测（语义分析）
- 并行检测模式
"""

import logging
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.attack_surface.detector import AttackSurfaceDetector
from src.layers.l1_intelligence.attack_surface.models import (
    AttackSurfaceReport,
    EntryPoint,
    EntryPointType,
)
from src.layers.l3_analysis.llm.client import LLMClient

logger = get_logger(__name__)


class DetectionMode(str, Enum):
    """Attack surface detection modes."""

    STATIC = "static"  # Static detection only (AST + regex)
    LLM_ENHANCE = "llm-enhance"  # Static + LLM enhancement
    LLM_FULL = "llm-full"  # Pure LLM-driven detection
    PARALLEL = "parallel"  # Static + LLM running in parallel


class AttackSurfaceDetectionConfig:
    """Configuration for attack surface detection.

    Attributes:
        mode: Detection mode (static/llm-enhance/llm-full/parallel)
        llm_model: LLM model name for LLM-based detection
        max_files: Maximum files to analyze for LLM mode
        max_batch_chars: Maximum characters per LLM batch
        static_only: If True, only use static detection (alias for mode=STATIC)
    """

    def __init__(
        self,
        mode: DetectionMode = DetectionMode.STATIC,
        llm_model: str = "deepseek-chat",
        max_files: int = 50,
        max_batch_chars: int = 25000,
        static_only: bool = False,
    ):
        self.mode = DetectionMode.STATIC if static_only else mode
        self.llm_model = llm_model
        self.max_files = max_files
        self.max_batch_chars = max_batch_chars
        self.static_only = static_only


class AttackSurfaceService:
    """Service for attack surface detection in web scanning pipeline.

    This service provides a wrapper around the CLI AttackSurfaceDetector,
    adapted for use in the async web scanning context.

    Integration Point: ScanOrchestrator Phase 0 (L1_Preparation)

    Usage:
        service = AttackSurfaceService(llm_client)
        report = await service.detect(source_path, config)
    """

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        db_session: Optional[AsyncSession] = None,
    ):
        """Initialize the attack surface service.

        Args:
            llm_client: Optional LLM client for LLM-based detection.
            db_session: Optional database session for storing results.
        """
        self.llm_client = llm_client
        self.db_session = db_session
        self.logger = logger

        # Lazy initialization of detector
        self._detector: Optional[AttackSurfaceDetector] = None

    def _get_detector(self, config: AttackSurfaceDetectionConfig) -> AttackSurfaceDetector:
        """Get or create the AttackSurfaceDetector instance.

        Args:
            config: Detection configuration.

        Returns:
            Configured AttackSurfaceDetector instance.
        """
        if self._detector is None:
            enable_llm = config.mode != DetectionMode.STATIC
            self._detector = AttackSurfaceDetector(
                llm_client=self.llm_client,
                enable_llm=enable_llm,
                llm_model=config.llm_model,
            )
        return self._detector

    async def detect(
        self,
        source_path: Path,
        config: Optional[AttackSurfaceDetectionConfig] = None,
        frameworks: Optional[list[str]] = None,
    ) -> AttackSurfaceReport:
        """Detect attack surface for a project.

        This is the main entry point for the service. It dispatches to the
        appropriate detection method based on the configured mode.

        Args:
            source_path: Path to source code.
            config: Detection configuration. If None, uses static-only mode.
            frameworks: Optional list of known frameworks to prioritize.

        Returns:
            AttackSurfaceReport with detected entry points.
        """
        if config is None:
            config = AttackSurfaceDetectionConfig(mode=DetectionMode.STATIC)

        self.logger.info(
            f"Starting attack surface detection for {source_path} "
            f"(mode={config.mode.value})"
        )

        detector = self._get_detector(config)

        # Dispatch based on mode
        if config.mode == DetectionMode.STATIC or config.static_only:
            return await self._detect_static(detector, source_path, frameworks)
        elif config.mode == DetectionMode.LLM_FULL:
            return await self._detect_llm_full(detector, source_path, config)
        elif config.mode == DetectionMode.PARALLEL:
            return await self._detect_parallel(detector, source_path, frameworks, config)
        else:  # LLM_ENHANCE
            return await self._detect_llm_enhance(detector, source_path, frameworks)

    async def _detect_static(
        self,
        detector: AttackSurfaceDetector,
        source_path: Path,
        frameworks: Optional[list[str]],
    ) -> AttackSurfaceReport:
        """Static detection only (fast, no LLM).

        Args:
            detector: AttackSurfaceDetector instance.
            source_path: Path to source code.
            frameworks: Optional list of known frameworks.

        Returns:
            AttackSurfaceReport with detected entry points.
        """
        self.logger.info("Running static-only detection...")
        report = detector.detect(source_path, frameworks)
        self.logger.info(
            f"Static detection complete: {report.total_entry_points} entry points"
        )
        return report

    async def _detect_llm_full(
        self,
        detector: AttackSurfaceDetector,
        source_path: Path,
        config: AttackSurfaceDetectionConfig,
    ) -> AttackSurfaceReport:
        """Pure LLM-driven detection (two-phase analysis).

        Phase 1: Analyze project structure to identify target files
        Phase 2: Analyze each target file to detect entry points

        Args:
            detector: AttackSurfaceDetector instance.
            source_path: Path to source code.
            config: Detection configuration.

        Returns:
            AttackSurfaceReport with detected entry points.
        """
        self.logger.info("Running full LLM detection...")
        report = await detector.detect_llm_full(
            source_path,
            max_files=config.max_files,
            max_batch_chars=config.max_batch_chars,
        )
        self.logger.info(
            f"LLM detection complete: {report.total_entry_points} entry points"
        )
        return report

    async def _detect_parallel(
        self,
        detector: AttackSurfaceDetector,
        source_path: Path,
        frameworks: Optional[list[str]],
        config: AttackSurfaceDetectionConfig,
    ) -> AttackSurfaceReport:
        """Parallel detection (static + LLM running concurrently).

        Both static and LLM detection run independently, results are merged.
        Duplicate detection is handled, and each entry point tracks its source.

        Args:
            detector: AttackSurfaceDetector instance.
            source_path: Path to source code.
            frameworks: Optional list of known frameworks.
            config: Detection configuration.

        Returns:
            AttackSurfaceReport with merged results.
        """
        self.logger.info("Running parallel detection (static + LLM)...")
        report = await detector.detect_parallel(
            source_path,
            frameworks=frameworks,
            max_files=config.max_files,
            max_batch_chars=config.max_batch_chars,
        )
        self.logger.info(
            f"Parallel detection complete: {report.total_entry_points} total entry points "
            f"(static: {report.static_found}, llm: {report.llm_found}, both: {report.both_found})"
        )
        return report

    async def _detect_llm_enhance(
        self,
        detector: AttackSurfaceDetector,
        source_path: Path,
        frameworks: Optional[list[str]],
    ) -> AttackSurfaceReport:
        """Static detection with LLM enhancement for files with no results.

        Args:
            detector: AttackSurfaceDetector instance.
            source_path: Path to source code.
            frameworks: Optional list of known frameworks.

        Returns:
            AttackSurfaceReport with enhanced results.
        """
        self.logger.info("Running static detection with LLM enhancement...")
        report = await detector.detect_async(
            source_path,
            frameworks=frameworks,
            use_llm_enhance=True,
        )
        self.logger.info(
            f"Enhanced detection complete: {report.total_entry_points} entry points"
        )
        return report

    def get_http_endpoints(self, report: AttackSurfaceReport) -> list[EntryPoint]:
        """Get only HTTP entry points from the report.

        Args:
            report: Attack surface report.

        Returns:
            List of HTTP entry points.
        """
        return report.get_http_endpoints()

    def get_unauthenticated_endpoints(self, report: AttackSurfaceReport) -> list[EntryPoint]:
        """Get entry points without authentication.

        Args:
            report: Attack surface report.

        Returns:
            List of unauthenticated entry points.
        """
        return report.get_unauthenticated()

    def get_summary(self, report: AttackSurfaceReport) -> dict[str, Any]:
        """Get summary statistics from the report.

        Args:
            report: Attack surface report.

        Returns:
            Dictionary with summary statistics.
        """
        return report.get_summary()

    def create_finding_context(self, report: AttackSurfaceReport) -> dict[str, Any]:
        """Create finding context from attack surface report.

        This context can be used by downstream scanning phases to
        prioritize analysis of entry points and attack vectors.

        Args:
            report: Attack surface report.

        Returns:
            Dictionary with finding context for downstream use.
        """
        return {
            "attack_surface": {
                "total_entry_points": report.total_entry_points,
                "http_endpoints": report.http_endpoints,
                "rpc_services": report.rpc_services,
                "grpc_services": report.grpc_services,
                "mq_consumers": report.mq_consumers,
                "cron_jobs": report.cron_jobs,
                "websocket_endpoints": report.websocket_endpoints,
                "unauthenticated_count": len(report.get_unauthenticated()),
            },
            "detection_sources": {
                "static_found": report.static_found,
                "llm_found": report.llm_found,
                "both_found": report.both_found,
            },
            "frameworks": report.frameworks_detected,
            "files_scanned": report.files_scanned,
            "entry_points": [
                {
                    "type": ep.type.value,
                    "method": ep.method.value if ep.method else None,
                    "path": ep.path,
                    "handler": ep.handler,
                    "file": ep.file,
                    "line": ep.line,
                    "auth_required": ep.auth_required,
                    "detection_source": ep.detection_source.value,
                }
                for ep in report.entry_points
            ],
        }


# Convenience factory function
def create_attack_surface_service(
    llm_client: Optional[LLMClient] = None,
    db_session: Optional[AsyncSession] = None,
) -> AttackSurfaceService:
    """Create an AttackSurfaceService instance.

    Args:
        llm_client: Optional LLM client for LLM-based detection.
        db_session: Optional database session.

    Returns:
        Configured AttackSurfaceService instance.
    """
    return AttackSurfaceService(llm_client=llm_client, db_session=db_session)
