"""Scan orchestrator for direct engine invocation.

This module provides the ScanOrchestrator class that replaces CLIAdapter
and directly invokes analysis engines (Semgrep, CodeQL, Agent) in the
current Python process using asyncio for concurrency.

Reference: DeepAudit's in-process scanning approach
"""

import asyncio
import logging
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from src.layers.l3_analysis.engines.base import BaseEngine, engine_registry
from src.layers.l3_analysis.models import ScanResult, Finding
from src.layers.l1_intelligence.tech_stack_detector.detector import TechStackDetector
from src.layers.l3_analysis.llm.client import LLMClient
from src.web.models.database import get_session_local
from src.web.models.scan import ScanStatus
from src.web.models.finding import Finding as FindingModel
from src.web.services.progress_broadcaster import (
    ProgressCallback,
    ProgressBroadcaster,
)
from src.web.services.attack_surface_service import (
    AttackSurfaceService,
    AttackSurfaceDetectionConfig,
    DetectionMode,
)
from src.core.models.attack_surface import AttackSurfaceReport
from src.web.services.verification_service import (
    VerificationService,
    create_verification_service,
)
from src.web.services.adjudication_service import (
    AdjudicationService,
    create_adjudication_service,
)
from src.web.services.adversarial_service import (
    AdversarialService,
    create_adversarial_service,
    create_adversarial_service_from_db,
)
from src.web.services.incremental_scan import (
    IncrementalScanService,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Scan Orchestrator
# ============================================================================


class ScanOrchestrator:
    """
    Orchestrates the complete scan workflow by directly invoking engines.

    This replaces CLIAdapter with a pure Python implementation that:
    - Prepares source code (ZIP extraction, file filtering)
    - Detects tech stack
    - Selects appropriate engines
    - Executes engines concurrently using asyncio.gather()
    - Merges and saves results

    Reference design: DeepAudit's process_zip_task() and scan_repo_task()
    """

    def __init__(
        self,
        scan_id: int,
        source_path: str,
        scan_config: Dict[str, Any],
        progress_callback: Optional[ProgressCallback] = None,
        db_session_factory: Optional[Callable[[], AsyncSession]] = None,
        llm_client: Optional[LLMClient] = None,
    ):
        """Initialize the scan orchestrator.

        Args:
            scan_id: ID of the scan in the database
            source_path: Path to the source code to scan
            scan_config: Scan configuration dictionary
            progress_callback: Optional progress callback for events
            db_session_factory: Factory function for creating DB sessions
            llm_client: Optional LLM client for LLM-based features
        """
        self.scan_id = scan_id
        self.source_path = source_path
        self.config = scan_config
        self.progress_callback = progress_callback or ProgressBroadcaster(
            scan_id, db_session_factory
        )
        self.db_session_factory = db_session_factory or get_session_local
        self.llm_client = llm_client

        # Runtime state
        self.temp_dir: Optional[Path] = None
        self.tech_stack: Optional[Dict[str, Any]] = None
        self.attack_surface_report_obj: Optional[AttackSurfaceReport] = None  # Original AttackSurfaceReport object
        self.attack_surface_report: Optional[Dict[str, Any]] = None  # Finding context dict
        self.scan_results: Dict[str, ScanResult] = {}
        self.adjudication_summary: Optional[Dict[str, Any]] = None

        # Statistics
        self.total_files = 0
        self.total_findings = 0
        self.total_tokens = 0
        self.start_time: Optional[datetime] = None

        # Token tracking for separation
        self._adversarial_tokens_used: int = 0  # Track tokens used by adversarial verification

        # Services (lazy initialization)
        self._attack_surface_service: Optional[AttackSurfaceService] = None
        self.incremental_scan_service: Optional[IncrementalScanService] = None
        self.incremental_files_to_scan: Optional[set] = None

    def _get_attack_surface_service(self) -> Optional[AttackSurfaceService]:
        """Get or create the AttackSurfaceService.

        P14-01: Lazy initialization of AttackSurfaceService.

        Returns:
            AttackSurfaceService instance if LLM client is available, None otherwise.
        """
        if self._attack_surface_service is None and self.llm_client:
            self._attack_surface_service = AttackSurfaceService(
                llm_client=self.llm_client,
                db_session=None,
            )
        return self._attack_surface_service

    async def execute_scan(self) -> Dict[str, Any]:
        """
        Execute the complete scan workflow.

        This is the main entry point that orchestrates all scan phases.

        Returns:
            Dictionary with scan results:
                - success: bool
                - findings_count: int
                - duration_seconds: float
                - error: str | None

        Raises:
            Exception: If the scan fails critically
        """
        self.start_time = datetime.now(timezone.utc)

        # Set scan configuration for progress callback
        # This enables dynamic weight calculation for optional phases
        self.progress_callback.set_scan_config(self.config)

        try:
            # Phase 0: L1_Preparation (P14-01 新增)
            # 包含 TechStackDetection + AttackSurfaceDetection
            await self.progress_callback.on_phase_start("l1_preparation")
            await self._run_l1_preparation()
            await self.progress_callback.on_phase_complete(
                "l1_preparation",
                {
                    "languages": self.tech_stack.get("languages", []),
                    "frameworks": self.tech_stack.get("frameworks", []),
                    "primary_language": self.tech_stack.get("primary_language"),
                    "total_files": self.tech_stack.get("total_files", 0),
                    "file_counts": self.tech_stack.get("file_counts", {}),
                    "attack_surface": self.attack_surface_report.get(
                        "total_entry_points", 0
                    ) if self.attack_surface_report else 0,
                }
            )

            # Phase 1: Prepare source code
            await self.progress_callback.on_phase_start("source_preparation")
            await self._prepare_source()
            await self.progress_callback.on_phase_complete(
                "source_preparation",
                {"total_files": self.total_files}
            )

            # Phase 2: Select engines
            await self.progress_callback.on_phase_start("engine_selection")
            engines = await self._select_engines()
            await self.progress_callback.on_phase_complete(
                "engine_selection",
                {"engines": list(engines.keys())}
            )

            # Phase 3: Execute engines (concurrent)
            await self.progress_callback.on_phase_start("engine_execution")
            await self._execute_engines(engines)
            # Build per-engine detail summary
            per_engine_details = {}
            for name, result in self.scan_results.items():
                per_engine_details[name] = {
                    "findings": len(result.findings),
                    "duration_seconds": getattr(result, 'duration_seconds', 0) or 0,
                    "tokens_used": 0,
                }
                if isinstance(result.raw_output, dict):
                    per_engine_details[name]["tokens_used"] = result.raw_output.get("total_tokens", 0)
                    # Extract agent file analysis data
                    if name == "agent":
                        per_engine_details[name]["files_analyzed"] = result.raw_output.get("files_analyzed", 0)
                        per_engine_details[name]["agent_total_files"] = result.raw_output.get("total_files", 0)
                        per_engine_details[name]["analyzed_file_paths"] = result.raw_output.get("analyzed_file_paths", [])
            await self.progress_callback.on_phase_complete(
                "engine_execution",
                {
                    "findings": sum(
                        len(r.findings) for r in self.scan_results.values()
                    ),
                    "per_engine_details": per_engine_details,
                }
            )

            # Phase 3.5: Exploitability Verification (P14-02)
            if self.config.get("llm_verify", True):
                await self.progress_callback.on_phase_start("exploitability_verification")
                verified_count = await self._run_exploitability_verification()
                await self.progress_callback.on_phase_complete(
                    "exploitability_verification",
                    {"verified_findings": verified_count}
                )

            # Phase 4: Deduplication and Adjudication (P14-03)
            await self.progress_callback.on_phase_start("deduplication_adjudication")
            adjudication_summary = await self._run_adjudication()
            await self.progress_callback.on_phase_complete(
                "deduplication_adjudication",
                {
                    "unique_findings": adjudication_summary.get("unique_findings", 0),
                    "duplicates_removed": adjudication_summary.get("duplicates_removed", 0),
                }
            )

            # Phase 5: Adversarial Verification (P14-04)
            if self.config.get("adversarial", False):
                await self.progress_callback.on_phase_start("adversarial_verification")
                adversarial_summary = await self._run_adversarial_verification()
                await self.progress_callback.on_phase_complete(
                    "adversarial_verification",
                    {
                        "verified_findings": adversarial_summary.get("verified_count", 0),
                        "confirmed": adversarial_summary.get("confirmed", 0),
                        "rejected": adversarial_summary.get("rejected", 0),
                    }
                )

            # Phase 6: Merge and save results
            await self.progress_callback.on_phase_start("result_merging")
            await self._finalize_results()
            await self.progress_callback.on_phase_complete(
                "result_merging",
                {"total_findings": self.total_findings}
            )

            # Phase 7: Token statistics (P14-05)
            await self.progress_callback.on_phase_start("token_statistics")
            token_stats = await self._update_token_statistics()
            await self.progress_callback.on_phase_complete(
                "token_statistics",
                {
                    "total_tokens": token_stats["total_tokens"],
                    "estimated_cost": token_stats["estimated_cost"],
                }
            )

            # Calculate duration
            duration_seconds = (
                datetime.now(timezone.utc) - self.start_time
            ).total_seconds()

            # Report completion
            tokens_used = 0
            if self.llm_client:
                usage = self.llm_client.get_total_usage()
                tokens_used = usage.total_tokens

            # Build per-phase token breakdown for scan_complete
            per_phase_tokens = {
                "agent_scan": token_stats.get("agent_scan_tokens", 0),
                "adversarial": self._adversarial_tokens_used,
                "total": token_stats.get("total_tokens", 0),
            }

            # Extract agent analysis data from per_engine_details
            agent_detail = per_engine_details.get("agent", {})

            await self.progress_callback.on_scan_complete(
                self.total_findings, duration_seconds, tokens_used,
                per_phase_tokens=per_phase_tokens,
                agent_analyzed_files=agent_detail.get("analyzed_file_paths", []),
                agent_files_analyzed=agent_detail.get("files_analyzed", 0),
            )

            return {
                "success": True,
                "findings_count": self.total_findings,
                "duration_seconds": duration_seconds,
            }

        except Exception as e:
            logger.exception(f"Scan {self.scan_id} failed: {e}")
            await self.progress_callback.on_scan_failed(str(e))
            await self._cleanup()
            return {
                "success": False,
                "error": str(e),
                "findings_count": 0,
                "duration_seconds": (
                    datetime.now(timezone.utc) - self.start_time
                ).total_seconds()
                if self.start_time
                else 0,
            }
        finally:
            await self._cleanup()

    # ========================================================================
    # Source Preparation
    # ========================================================================

    async def _prepare_source(self) -> None:
        """
        Prepare the source code for scanning.

        Handles:
        - ZIP file extraction (like DeepAudit's process_zip_task)
        - Directory structure detection
        - File filtering and counting

        Optimization: Reuses extracted directory from Phase 0 if available.

        Reference: DeepAudit scanner.py:297-350 (process_zip_task)
        """
        # Check if source_path was already set by Phase 0 (L1_Preparation)
        if self.source_path is not None:
            logger.info(f"Scan {self.scan_id}: Reusing extracted directory from Phase 0: {self.source_path}")
            # Update total_files count
            self.total_files = self._count_code_files()
            logger.info(f"Scan {self.scan_id}: {self.total_files} code files in {self.source_path}")
            return

        # Need to extract source (this happens when Phase 0 was skipped or source is not a ZIP)
        # Read source_path from the scan record
        async with self.db_session_factory() as db:
            from src.web.repositories.scan import ScanRepository
            scan_repo = ScanRepository()
            scan = await scan_repo.get(db, id=self.scan_id)
            if not scan:
                raise ValueError(f"Scan {self.scan_id} not found")

        source_path = Path(scan.source_path)

        # Handle ZIP files
        if source_path.suffix == ".zip":
            self.temp_dir = Path(
                tempfile.mkdtemp(prefix=f"deepvuln_scan_{self.scan_id}_")
            )

            try:
                logger.info(f"Extracting ZIP: {source_path} -> {self.temp_dir}")
                shutil.unpack_archive(source_path, self.temp_dir)

                # Find actual code directory
                self.source_path = self._find_code_directory(self.temp_dir)
                logger.info(f"Using code directory: {self.source_path}")

            except Exception as e:
                # Cleanup on failure
                if self.temp_dir and self.temp_dir.exists():
                    shutil.rmtree(self.temp_dir, ignore_errors=True)
                raise ValueError(f"Failed to extract ZIP: {e}")
        else:
            self.source_path = source_path

        # P14-06: Incremental scan mode
        if self.config.get("incremental", False):
            await self._prepare_incremental_scan()

        # Count total files (with basic filtering)
        self.total_files = self._count_code_files()
        logger.info(f"Scan {self.scan_id}: {self.total_files} code files in {self.source_path}")

    def _find_code_directory(self, extracted_dir: Path) -> Path:
        """
        Find the actual code directory from extracted ZIP.

        Implements smart directory detection similar to DeepAudit:
        - Single subdirectory -> use that
        - Project markers (package.json, pom.xml, etc.) -> use that
        - Default -> use root

        Reference: DeepAudit scanner.py extraction logic
        """
        items = list(extracted_dir.iterdir())

        # Single directory
        if len(items) == 1 and items[0].is_dir():
            return items[0]

        # Look for project markers
        markers = [
            "package.json",
            "pom.xml",
            "build.gradle",
            "requirements.txt",
            "go.mod",
            "Cargo.toml",
            "setup.py",
            "pyproject.toml",
            "Gemfile",
            "composer.json",
        ]

        for item in items:
            if item.is_dir():
                for marker in markers:
                    if (item / marker).exists():
                        return item

        # Default: use root directory
        return extracted_dir

    def _count_code_files(self) -> int:
        """
        Count code files while excluding common non-code directories.

        Excludes:
        - Version control (.git, .svn)
        - Dependencies (node_modules, vendor, __pycache__)
        - Build artifacts (dist, build, target)
        - IDE files (.idea, .vscode)
        - Documentation (docs, *_examples.md)

        Returns:
            Count of code files
        """
        exclude_dirs = {
            ".git", ".svn", ".hg",
            "node_modules", "vendor", "__pycache__",
            ".venv", "venv", "env", ".env",
            "dist", "build", "target", "out",
            ".idea", ".vscode", ".eclipse",
            "coverage", ".nyc_output",
            ".pytest_cache", ".mypy_cache",
            "bin", "obj", ".gradle",
        }

        exclude_files = {
            ".gitignore", ".dockerignore",
            "*.min.js", "*.min.css",
            "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
            "*.gz", "*.zip", "*.tar",
            "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.svg",
            "*.pdf", "*.doc", "*.docx",
        }

        count = 0
        for item in self.source_path.rglob("*"):
            # Skip excluded directories
            if any(part in exclude_dirs for part in item.parts):
                continue

            # Count files only (not directories)
            if item.is_file():
                # Check file extension
                ext = item.suffix.lower()
                # Skip common non-code extensions
                if ext in {'.min.js', '.min.css', '.map', '.lock', '.gz',
                          '.zip', '.tar', '.png', '.jpg', '.jpeg', '.gif',
                          '.ico', '.svg', '.pdf', '.doc', '.docx', '.exe',
                          '.dll', '.so', '.dylib', '.class', '.pyc'}:
                    continue

                # Skip specific file names
                if item.name in {'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
                                '.gitignore', '.dockerignore', 'LICENSE', 'README.md',
                                'README.rst', 'CONTRIBUTING.md'}:
                    continue

                count += 1

        return count

    async def _prepare_incremental_scan(self) -> None:
        """Prepare incremental scan by analyzing Git changes (P14-06).

        This method:
        1. Creates IncrementalScanService
        2. Analyzes Git changes between base_ref and head_ref
        3. Stores the list of files to scan for filtering

        Raises:
            ValueError: If not a Git repository or Git operations fail
        """
        from pathlib import Path as PathLib

        # Get incremental scan configuration
        base_ref = self.config.get("base_ref", "HEAD~1")
        head_ref = self.config.get("head_ref", "HEAD")

        logger.info(
            f"Preparing incremental scan: {base_ref}...{head_ref}"
        )

        # Create incremental scan service
        self.incremental_scan_service = IncrementalScanService(
            scan_id=self.scan_id,
        )

        # Analyze changes
        try:
            context = await self.incremental_scan_service.analyze_incremental_changes(
                source_path=PathLib(self.source_path),
                base_ref=base_ref,
                head_ref=head_ref,
            )

            # Store context for later use
            self.incremental_scan_service.context = context

            # Get files to scan
            self.incremental_files_to_scan = (
                self.incremental_scan_service.get_files_to_scan()
            )

            logger.info(
                f"Incremental scan: {len(self.incremental_files_to_scan)} files to scan "
                f"({context.added_files} added, {context.modified_files} modified)"
            )

            # Update progress
            await self.progress_callback.on_phase_start("incremental_analysis")
            await self.progress_callback.on_phase_complete(
                "incremental_analysis",
                {
                    "files_to_scan": len(self.incremental_files_to_scan),
                    "added_files": context.added_files,
                    "modified_files": context.modified_files,
                }
            )

        except Exception as e:
            logger.error(f"Incremental scan analysis failed: {e}")
            # P14-06e: Failure should terminate the scan (no auto-degrade)
            raise ValueError(
                f"Incremental scan failed: {e}. "
                f"Please ensure the source is a Git repository and refs are valid."
            ) from e

    # ========================================================================
    # Tech Stack Detection
    # ========================================================================

    async def _detect_tech_stack(self) -> Dict[str, Any]:
        """
        Detect the project's technology stack using TechStackDetector.

        Returns:
            Dictionary with comprehensive tech stack information
        """
        return await self._detect_tech_stack_impl()

    # ========================================================================
    # Engine Selection
    # ========================================================================

    async def _select_engines(self) -> Dict[str, BaseEngine]:
        """
        Select appropriate analysis engines based on config and tech stack.

        Returns:
            Dictionary of {engine_name: engine_instance}
        """
        from src.layers.l3_analysis.engines.semgrep import SemgrepEngine
        from src.layers.l3_analysis.engines.codeql import CodeQLEngine
        from src.layers.l3_analysis.engines.opencode_agent import OpenCodeAgent

        selected_engines = {}
        requested = self.config.get("engines", ["semgrep", "codeql", "agent"])

        # Semgrep - always available if requested
        if "semgrep" in requested:
            engine = SemgrepEngine()
            if engine.is_available():
                selected_engines["semgrep"] = engine
                logger.info(f"Scan {self.scan_id}: Semgrep engine selected")

        # CodeQL - check availability
        if "codeql" in requested:
            engine = CodeQLEngine()
            if engine.is_available():
                # Quick readiness check (P6-02)
                try:
                    readiness = await self._check_codeql_readiness(engine)
                    if readiness["ready"]:
                        selected_engines["codeql"] = engine
                        logger.info(f"Scan {self.scan_id}: CodeQL engine selected")
                    else:
                        await self.progress_callback.on_warning(
                            f"CodeQL not ready: {readiness['message']}"
                        )
                except Exception as e:
                    await self.progress_callback.on_warning(
                        f"CodeQL check failed: {e}"
                    )

        # Agent - check LLM config
        if "agent" in requested:
            # 只有在配置了 LLM 客户端时才启用 agent
            if self.llm_client and self.llm_client.is_available:
                engine = OpenCodeAgent(llm_client=self.llm_client)
                selected_engines["agent"] = engine
                logger.info(f"Scan {self.scan_id}: Agent engine selected")
            else:
                logger.warning(f"Scan {self.scan_id}: Agent engine requested but no LLM client available")

        # AST Engine - if available
        if "ast" in requested:
            from src.layers.l3_analysis.engines.ast_engine.ast_engine import (
                ASTEngine,
            )

            engine = ASTEngine()
            if engine.is_available():
                selected_engines["ast"] = engine
                logger.info(f"Scan {self.scan_id}: AST engine selected")

        if not selected_engines:
            raise RuntimeError("No analysis engines available")

        return selected_engines

    async def _check_codeql_readiness(
        self, engine: "CodeQLEngine"
    ) -> Dict[str, Any]:
        """Check CodeQL readiness with timeout."""
        try:
            return await asyncio.wait_for(
                engine.check_readiness(
                    self.source_path,
                    startup_timeout=15,
                ),
                timeout=20,
            )
        except asyncio.TimeoutError:
            return {"ready": False, "message": "Readiness check timed out"}

    # ========================================================================
    # Engine Execution
    # ========================================================================

    async def _execute_engines(self, engines: Dict[str, BaseEngine]) -> None:
        """
        Execute multiple engines concurrently using asyncio.gather.

        Implements the concurrent execution strategy:
        - CodeQL (CPU intensive) runs separately
        - Semgrep, Agent, AST run concurrently

        Reference: Plan Section 4.1 - Engine Grouping Strategy
        """
        # Split engines by execution strategy
        cpu_intensive = {}
        concurrent_engines = {}

        for name, engine in engines.items():
            if name == "codeql":
                cpu_intensive[name] = engine
            else:
                concurrent_engines[name] = engine

        # Execute CPU-intensive engines first (CodeQL)
        if cpu_intensive:
            for name, engine in cpu_intensive.items():
                try:
                    await self.progress_callback.on_engine_start(name)
                    result = await self._run_engine_with_timeout(name, engine)
                    self.scan_results[name] = result
                    await self.progress_callback.on_engine_complete(
                        name,
                        len(result.findings),
                        result.duration_seconds or 0,
                    )
                except Exception as e:
                    await self.progress_callback.on_engine_failed(name, str(e))

        # Execute other engines concurrently
        if concurrent_engines:
            tasks = []
            task_names = []

            for name, engine in concurrent_engines.items():
                task = asyncio.create_task(
                    self._run_engine_concurrent(name, engine)
                )
                tasks.append(task)
                task_names.append(name)

            # Wait for all concurrent tasks
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            for name, result in zip(task_names, results):
                if isinstance(result, Exception):
                    await self.progress_callback.on_engine_failed(
                        name, str(result)
                    )
                elif result:
                    self.scan_results[name] = result
                    await self.progress_callback.on_engine_complete(
                        name,
                        len(result.findings),
                        result.duration_seconds or 0,
                    )

    async def _run_engine_with_timeout(
        self, name: str, engine: BaseEngine
    ) -> ScanResult:
        """Run an engine with timeout protection."""
        timeout = self._get_engine_timeout(name)

        try:
            return await asyncio.wait_for(
                self._run_engine(name, engine),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            raise TimeoutError(f"Engine {name} timed out after {timeout}s")

    async def _run_engine_concurrent(
        self, name: str, engine: BaseEngine
    ) -> ScanResult:
        """Run an engine in concurrent mode."""
        timeout = self._get_engine_timeout(name)

        try:
            return await asyncio.wait_for(
                self._run_engine(name, engine),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            raise TimeoutError(f"Engine {name} timed out after {timeout}s")

    async def _run_engine(self, name: str, engine: BaseEngine) -> ScanResult:
        """Run a single engine and collect findings."""
        logger.info(f"Scan {self.scan_id}: Running {name} engine")

        # Build scan options based on engine type
        options = await self._build_engine_options(name, engine)

        # Execute scan
        result = await engine.scan(self.source_path, **options)

        # Report findings as they are discovered
        for finding in result.findings:
            await self.progress_callback.on_finding(finding)

        return result

    async def _build_engine_options(
        self, name: str, engine: BaseEngine
    ) -> Dict[str, Any]:
        """Build engine-specific scan options using tech stack information."""
        options = {}

        if name == "semgrep":
            # Basic tech stack info
            options["tech_stack"] = self.tech_stack
            options["use_rule_gating"] = True
            options["use_finding_budget"] = True

            # Framework-aware rule selection
            frameworks = self.tech_stack.get("frameworks", [])
            if frameworks:
                options["target_frameworks"] = frameworks
                logger.info(
                    f"Scan {self.scan_id}: Targeting frameworks: {frameworks}"
                )

            # Test file filtering - optional based on config
            skip_tests = self.config.get("skip_tests", False)
            has_tests = self.tech_stack.get("has_tests", False)
            if skip_tests and has_tests:
                options["exclude_patterns"] = [
                    "*/tests/*",
                    "*/test_*",
                    "*/__tests__/*",
                    "*/spec/*",
                ]
                logger.info(f"Scan {self.scan_id}: Excluding test files")

        elif name == "codeql":
            # Check if multi-language project
            is_multi_lang = await self._is_multi_language_project()
            if is_multi_lang:
                options["multi_language"] = True
                options["languages"] = self.tech_stack.get("languages", [])
                logger.info(
                    f"Scan {self.scan_id}: CodeQL multi-language mode: "
                    f"{options['languages']}"
                )

            # Use primary language for single-language projects
            primary_language = self.tech_stack.get("primary_language")
            if primary_language and not is_multi_lang:
                options["primary_language"] = primary_language
                logger.info(
                    f"Scan {self.scan_id}: CodeQL primary language: {primary_language}"
                )

        elif name == "agent":
            options["max_files"] = self.config.get("agent_max_files", 50)
            options["tech_stack"] = self.tech_stack

            # IMPORTANT: Pass orchestrator's LLM client to agent engine
            # This ensures token usage is tracked consistently
            if self.llm_client:
                options["llm_client"] = self.llm_client
                logger.info(f"Scan {self.scan_id}: Passing LLM client to agent engine")

            # Add database context for more informed analysis
            databases = self.tech_stack.get("databases", [])
            if databases:
                options["detected_databases"] = databases
                logger.info(f"Scan {self.scan_id}: Agent aware of databases: {databases}")

            # Add middleware context (API gateways, message queues, etc.)
            middleware = self.tech_stack.get("middleware", [])
            if middleware:
                options["detected_middleware"] = middleware

            # Framework-specific analysis hints
            frameworks = self.tech_stack.get("frameworks", [])
            if frameworks:
                options["detected_frameworks"] = frameworks

        elif name == "ast":
            # AST engine benefits from knowing the primary language
            primary_language = self.tech_stack.get("primary_language")
            if primary_language:
                options["primary_language"] = primary_language

        return options

    async def _is_multi_language_project(self) -> bool:
        """Check if this is a multi-language project."""
        languages = self.tech_stack.get("languages", [])
        return len(languages) > 1

    def _get_engine_timeout(self, engine_name: str) -> int:
        """Get timeout for an engine (in seconds)."""
        timeouts = {
            "semgrep": 300,  # 5 minutes
            "codeql": 1800,  # 30 minutes
            "agent": 600,  # 10 minutes
            "ast": 120,  # 2 minutes
        }
        return timeouts.get(engine_name, 300)

    # ========================================================================
    # Results Processing
    # ========================================================================

    async def _run_exploitability_verification(self) -> int:
        """Run exploitability verification on findings (P14-02).

        Returns:
            Number of findings verified
        """
        from src.layers.l3_analysis.models import Finding

        # Get verification configuration
        llm_verify = self.config.get("llm_verify", True)
        if not llm_verify:
            logger.info("LLM verification disabled (llm_verify=False)")
            return 0

        if not self.scan_results:
            logger.info("No findings to verify")
            return 0

        # Collect all findings from all engines
        all_findings: list[Finding] = []
        for engine_name, scan_result in self.scan_results.items():
            all_findings.extend(scan_result.findings)

        if not all_findings:
            logger.info("No findings to verify")
            return 0

        logger.info(f"Verifying {len(all_findings)} findings for exploitability")

        # Get CodeQL findings for dataflow analysis
        codeql_findings = []
        if "codeql" in self.scan_results:
            codeql_findings = self.scan_results["codeql"].findings
            logger.info(f"Using {len(codeql_findings)} CodeQL findings for dataflow analysis")

        # Create verification service
        verification_service = create_verification_service(
            source_path=self.source_path,
            llm_client=self.llm_client,
            attack_surface_report=self.attack_surface_report_obj,
            codeql_findings=codeql_findings,
            enable_llm_assessment=True,
        )

        # Verify findings in batch
        # P18: Use concurrency manager with config from database
        from src.core.llm import get_agent_scan_concurrency_manager_from_db
        concurrency_manager = await get_agent_scan_concurrency_manager_from_db(self.db_session_factory)
        verification_results = await verification_service.verify_findings_batch(
            findings=all_findings,
            max_concurrent=concurrency_manager.max_concurrent,
        )

        # Apply verification results to findings
        verified_count = 0
        for finding in all_findings:
            if finding.id not in verification_results:
                continue

            result = verification_results[finding.id]
            # Store verification result in finding metadata
            finding.metadata = finding.metadata or {}
            exploit_dict = verification_service.create_exploitability_dict(result)
            finding.metadata["exploitability_verification"] = exploit_dict
            verified_count += 1

            # Broadcast per-finding verification result
            await self.progress_callback.broadcast_event("verification_result", {
                "finding_id": finding.id or "unknown",
                "finding_title": getattr(finding, 'title', '') or '',
                "status": exploit_dict.get("status", ""),
                "confidence": result.confidence,
                "reasoning": getattr(result, 'reasoning', '') or '',
            })

            logger.debug(
                f"Finding {finding.id}: {result.status.value} "
                f"(confidence: {result.confidence:.2f})"
            )

        logger.info(f"Verified {verified_count} findings for exploitability")
        return verified_count

    async def _run_adjudication(self) -> dict[str, int]:
        """Run deduplication and adjudication on findings (P14-03).

        Returns:
            Summary dict with adjudication statistics
        """
        from src.layers.l3_analysis.models import Finding

        # Collect all findings from all engines
        all_findings: list[Finding] = []
        for engine_name, scan_result in self.scan_results.items():
            all_findings.extend(scan_result.findings)

        if not all_findings:
            logger.info("No findings to adjudicate")
            return {
                "total_findings": 0,
                "unique_findings": 0,
                "duplicates_removed": 0,
            }

        logger.info(f"Adjudicating {len(all_findings)} findings")

        # Create adjudication service
        adjudication_service = create_adjudication_service(
            enable_deduplication=True,
            enable_adjudication=True,
            cluster_distance_threshold=0.3,
            llm_client=self.llm_client,
        )

        # Run adjudication
        adjudicated_findings, summary = await adjudication_service.adjudicate_findings_batch(
            findings=all_findings,
        )

        # Update scan_results with adjudicated findings
        # We need to rebuild the scan_results with unique findings
        self.scan_results = {}
        for finding in adjudicated_findings:
            # Get the engine from metadata
            engine = finding.metadata.get("engine", "unknown") if finding.metadata else "unknown"
            if engine not in self.scan_results:
                self.scan_results[engine] = ScanResult(
                    engine=engine,
                    findings=[],
                    status="completed",
                    source_path=str(self.source_path),  # Add required source_path
                )
            self.scan_results[engine].findings.append(finding)

            # Broadcast per-finding adjudication result
            adj_data = finding.metadata.get("adjudication", {}) if finding.metadata else {}
            await self.progress_callback.broadcast_event("adjudication_result", {
                "finding_id": finding.id or "unknown",
                "finding_title": getattr(finding, 'title', '') or '',
                "vuln_type": str(getattr(finding, 'rule_id', '') or ''),
                "severity": str(getattr(finding, 'severity', '') or ''),
                "file_path": getattr(finding.location, 'file', '') if hasattr(finding, 'location') and finding.location else '',
                "final_status": adj_data.get("final_status", ""),
                "override_applied": adj_data.get("override_applied", False),
                "override_reason": adj_data.get("override_reason", ""),
                "evidence_strength": adj_data.get("evidence_strength"),
                "report_status": adj_data.get("report_status", ""),
            })

        # Store summary for later use in database
        self.adjudication_summary = summary.to_dict()

        logger.info(
            f"Adjudication complete: {summary.total_findings} total, "
            f"{summary.unique_findings} unique, "
            f"{summary.duplicates_removed} duplicates removed"
        )

        return {
            "total_findings": summary.total_findings,
            "unique_findings": summary.unique_findings,
            "duplicates_removed": summary.duplicates_removed,
        }

    async def _run_adversarial_verification(self) -> dict[str, int]:
        """Run adversarial verification on findings (P14-04).

        Returns:
            Summary dict with verification statistics
        """
        from src.layers.l3_analysis.models import Finding

        # Check if LLM client is available
        if not self.llm_client:
            logger.warning("Adversarial verification disabled: no LLM client")
            return {"verified_count": 0, "confirmed": 0, "rejected": 0}

        # Collect all findings from all engines
        all_findings: list[Finding] = []
        for engine_name, scan_result in self.scan_results.items():
            logger.info(f"Adversarial: {engine_name} has {len(scan_result.findings)} findings")
            all_findings.extend(scan_result.findings)

        if not all_findings:
            logger.info("No findings to verify adversarially")
            return {"verified_count": 0, "confirmed": 0, "rejected": 0}

        logger.info(f"Adversarial: collected {len(all_findings)} findings for verification")

        # Get adversarial configuration
        adversarial_config = self.config.get("adversarial", False)
        max_rounds = self.config.get("adversarial_max_rounds", 5)
        round_timeout = self.config.get("adversarial_round_timeout", 180)

        if not adversarial_config:
            logger.info("Adversarial verification disabled by config")
            return {"verified_count": 0, "confirmed": 0, "rejected": 0}

        logger.info(f"Starting adversarial verification for {len(all_findings)} findings")

        # Create adversarial service from database (verification type config)
        # P18-Bugfix: 传递现有的 llm_client 以正确统计 token
        adversarial_service = await create_adversarial_service_from_db(
            db_session_factory=self.db_session_factory,
            max_rounds=max_rounds,
            round_timeout=round_timeout,
            progress_callback=self._adversarial_progress_callback,
            llm_client=self.llm_client,  # 复用 orchestrator 的 llm_client
        )

        if adversarial_service is None:
            logger.warning("No verification LLM config found, skipping adversarial verification")
            return {"verified_count": 0, "confirmed": 0, "rejected": 0, "skipped": True}

        # Filter findings that should be verified
        findings_to_verify = [
            f for f in all_findings
            if adversarial_service.should_verify_finding(f)
        ]

        # Broadcast skipped findings
        skipped_findings = [f for f in all_findings if not adversarial_service.should_verify_finding(f)]
        for f in skipped_findings:
            skip_reason = "低严重等级" if hasattr(f, 'severity') and str(f.severity).lower() == 'info' else "低置信度"
            await self.progress_callback.broadcast_event("finding_skipped", {
                "finding_id": f.id or "unknown",
                "finding_title": getattr(f, 'title', '') or '',
                "severity": str(getattr(f, 'severity', '')),
                "reason": skip_reason,
            })

        if not findings_to_verify:
            logger.info("No findings met criteria for adversarial verification")
            return {"verified_count": 0, "confirmed": 0, "rejected": 0}

        logger.info(f"Verifying {len(findings_to_verify)} findings adversarially (filtered from {len(all_findings)})")

        # Track token usage before adversarial verification
        tokens_before = 0
        if self.llm_client:
            tokens_before = self.llm_client.get_total_usage().total_tokens

        # Verify findings in batch
        # P18: Use concurrency manager with config from database
        from src.core.llm import get_verification_concurrency_manager_from_db
        verification_manager = await get_verification_concurrency_manager_from_db(self.db_session_factory)
        verification_results = await adversarial_service.verify_findings_batch(
            findings=findings_to_verify,
            source_path=self.source_path,
            max_concurrent=verification_manager.max_concurrent,
        )

        # Track token usage after adversarial verification
        tokens_after = 0
        if self.llm_client:
            tokens_after = self.llm_client.get_total_usage().total_tokens
            self._adversarial_tokens_used = max(0, tokens_after - tokens_before)
            logger.info(f"Adversarial verification used {self._adversarial_tokens_used} tokens")

        # Apply results to findings
        confirmed = 0
        rejected = 0
        logger.info(f"Adversarial results: {len(verification_results)} entries, "
                     f"all_findings IDs: {[f.id for f in all_findings]}, "
                     f"result keys: {list(verification_results.keys())}")
        for finding_id, result in verification_results.items():
            status_val = result.get("status", "UNKNOWN")
            logger.info(f"Adversarial result: finding_id={finding_id}, status={status_val}, "
                         f"status_type={type(status_val)}, verdict={result.get('verdict')}")
            # Find the finding
            found = False
            for finding in all_findings:
                if finding.id == finding_id:
                    # Store result in finding metadata
                    finding.metadata = finding.metadata or {}
                    finding.metadata["adversarial_verification"] = result

                    found = True
                    # Update counters
                    if result.get("status") == "confirmed":
                        confirmed += 1
                    elif result.get("status") == "rejected":
                        rejected += 1

                    logger.info(
                        f"Finding {finding_id}: matched, status={result.get('status')} "
                        f"(confidence: {result.get('confidence', 0):.2f}), "
                        f"confirmed={confirmed}, rejected={rejected}"
                    )
                    break
            if not found:
                logger.warning(f"Finding {finding_id} not found in all_findings (IDs: {[f.id for f in all_findings[:5]]})")

        summary = {
            "verified_count": len(verification_results),
            "confirmed": confirmed,
            "rejected": rejected,
            "uncertain": len(verification_results) - confirmed - rejected,
        }

        logger.info(
            f"Adversarial verification complete: {summary['verified_count']} verified, "
            f"{summary['confirmed']} confirmed, {summary['rejected']} rejected"
        )

        return summary

    def _adversarial_progress_callback(
        self,
        event_type: str,
        data: dict[str, Any],
    ) -> None:
        """Progress callback for adversarial verification events.

        Args:
            event_type: Type of event (e.g., "adversarial_round")
            data: Event data
        """
        try:
            if hasattr(self.progress_callback, "broadcast_event"):
                # Schedule the async broadcast in the running event loop
                loop = asyncio.get_running_loop()
                loop.create_task(
                    self.progress_callback.broadcast_event(
                        event_type=event_type,
                        data=data,
                    )
                )
                logger.debug(f"Adversarial callback scheduled: {event_type} round={data.get('round')}")
            else:
                logger.warning(f"progress_callback has no broadcast_event method: {type(self.progress_callback)}")
        except RuntimeError:
            # No running event loop — try to get the Celery event loop
            logger.warning("No running event loop for adversarial callback, trying direct call")
            try:
                asyncio.get_event_loop().run_until_complete(
                    self.progress_callback.broadcast_event(event_type=event_type, data=data)
                )
            except Exception as e2:
                logger.warning(f"Adversarial callback fallback also failed: {e2}")
        except Exception as e:
            logger.warning(f"Failed to broadcast adversarial progress: {e}")

    async def _finalize_results(self) -> None:
        """
        Merge results from all engines and save to database.

        Implements:
        - Result merging and deduplication
        - Finding database insertion
        - Statistics update
        """
        all_findings = []

        # Collect findings from all engines
        for engine_name, scan_result in self.scan_results.items():
            logger.info(
                f"Scan {self.scan_id}: {engine_name} found "
                f"{len(scan_result.findings)} findings"
            )

            for finding in scan_result.findings:
                # Mark source engine
                if not finding.metadata:
                    finding.metadata = {}
                finding.metadata["source_engine"] = engine_name
                all_findings.append(finding)

        # Deduplication is handled by _run_adjudication(), skip here
        unique_findings = all_findings
        duplicates_removed = 0

        if duplicates_removed > 0:
            logger.info(
                f"Scan {self.scan_id}: Removed {duplicates_removed} duplicate findings"
            )

        # Save to database
        async with self.db_session_factory() as db:
            for finding_data in unique_findings:
                # Derive finding status from adversarial verification and adjudication
                finding_status = self._derive_finding_status(finding_data)

                finding = FindingModel(
                    scan_id=self.scan_id,
                    vuln_type=finding_data.rule_id or finding_data.type.value,
                    severity=finding_data.severity.value,
                    confidence=finding_data.confidence,
                    file_path=finding_data.location.file,
                    line_start=finding_data.location.line,
                    line_end=finding_data.location.end_line,
                    function_name=finding_data.location.function,
                    title=finding_data.title,
                    description=finding_data.description,
                    evidence=finding_data.location.snippet,
                    remediation=finding_data.fix_suggestion,
                    engine=finding_data.source,
                    status=finding_status,
                    extra_metadata=finding_data.metadata,
                )
                db.add(finding)

            await db.commit()

        self.total_findings = len(unique_findings)
        logger.info(
            f"Scan {self.scan_id}: Saved {self.total_findings} findings to database"
        )

    def _derive_finding_status(self, finding_data: Finding) -> str:
        """Derive finding status from adversarial verification and adjudication metadata.

        Priority: adversarial verification > adjudication > default pending

        Args:
            finding_data: Finding object with metadata containing verification results

        Returns:
            Status string: confirmed, false_positive, conditional, or pending
        """
        metadata = finding_data.metadata or {}

        # 1. Check adversarial verification result (highest priority)
        adversarial = metadata.get("adversarial_verification")
        if adversarial and isinstance(adversarial, dict):
            adv_status = adversarial.get("status", "")
            # Map adversarial status to finding status
            status_map = {
                "confirmed": "confirmed",
                "rejected": "false_positive",
                "uncertain": "conditional",
                "timeout": "conditional",
            }
            mapped = status_map.get(adv_status)
            if mapped:
                logger.debug(
                    f"Finding {finding_data.id}: status={mapped} from adversarial ({adv_status})"
                )
                return mapped

        # 2. Check adjudication result
        adjudication = metadata.get("adjudication")
        if adjudication and isinstance(adjudication, dict):
            adj_status = adjudication.get("final_status", "")
            status_map = {
                "confirmed": "confirmed",
                "false_positive": "false_positive",
                "conditional": "conditional",
                "not_exploitable": "false_positive",
                "informational": "conditional",
            }
            mapped = status_map.get(adj_status)
            if mapped:
                logger.debug(
                    f"Finding {finding_data.id}: status={mapped} from adjudication ({adj_status})"
                )
                return mapped

        # 3. Default pending
        return "pending"

    def _deduplicate_findings(
        self, findings: List[Finding]
    ) -> List[Finding]:
        """
        Remove duplicate findings based on location and rule.

        Deduplication key: (rule_id, file_path, line_number)

        Reference: ScanResult.deduplicate_findings() in models.py
        """
        seen = set()
        unique_findings = []

        for finding in findings:
            key = (
                finding.rule_id,
                finding.location.file,
                finding.location.line,
            )

            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)

        return unique_findings

    # ========================================================================
    # Resource Cleanup
    # ========================================================================

    async def _cleanup(self) -> None:
        """Clean up temporary resources."""
        if self.temp_dir and self.temp_dir.exists():
            try:
                shutil.rmtree(self.temp_dir, ignore_errors=True)
                logger.info(f"Scan {self.scan_id}: Cleaned up {self.temp_dir}")
            except Exception as e:
                logger.warning(f"Scan {self.scan_id}: Cleanup failed: {e}")
            finally:
                self.temp_dir = None

    # ========================================================================
    # Phase 0: L1_Preparation (P14-01)
    # ========================================================================

    async def _run_l1_preparation(self) -> None:
        """
        Run L1_Preparation phase (Phase 0).

        P14-01: 集成 AttackSurfaceDetection
        - TechStackDetection (已有)
        - AttackSurfaceDetection (新增)

        This phase runs before source preparation to gather intelligence
        about the project's attack surface, which can be used to optimize
        downstream scanning phases.
        """
        source_path = Path(self.source_path)

        # Handle ZIP files for path resolution
        if source_path.suffix == ".zip":
            # Extract ZIP for Phase 0 analysis (tech stack + attack surface)
            # The extracted directory will be reused in Phase 1 to avoid double extraction
            self.temp_dir = Path(
                tempfile.mkdtemp(prefix=f"deepvuln_l1_{self.scan_id}_")
            )
            try:
                logger.info(f"Phase 0: Extracting ZIP: {source_path} -> {self.temp_dir}")
                shutil.unpack_archive(source_path, self.temp_dir)
                self.source_path = self._find_code_directory(self.temp_dir)
                logger.info(f"Phase 0: Using code directory: {self.source_path}")
            except Exception as e:
                if self.temp_dir and self.temp_dir.exists():
                    shutil.rmtree(self.temp_dir, ignore_errors=True)
                    self.temp_dir = None
                raise ValueError(f"Failed to extract ZIP for L1 analysis: {e}")
        else:
            self.source_path = source_path

        # Step 1: TechStackDetection
        logger.info(f"Scan {self.scan_id}: Running TechStackDetection")
        self.tech_stack = await self._detect_tech_stack_for_l1()

        # Step 2: AttackSurfaceDetection (if enabled and LLM client available)
        self.attack_surface_report = None

        # Check if attack surface detection is enabled
        llm_detect = self.config.get("llm_detect", False)
        static_only = self.config.get("static_only", False)

        if not static_only and self._get_attack_surface_service():
            try:
                logger.info(f"Scan {self.scan_id}: Running AttackSurfaceDetection")

                # Determine detection mode
                if llm_detect:
                    detection_mode = DetectionMode.PARALLEL
                else:
                    detection_mode = DetectionMode.STATIC

                config = AttackSurfaceDetectionConfig(
                    mode=detection_mode,
                    static_only=static_only,
                )

                service = self._get_attack_surface_service()
                frameworks = self.tech_stack.get("frameworks", [])

                report = await service.detect(self.source_path, config, frameworks)

                # Store original report object for verification service
                self.attack_surface_report_obj = report

                # Store finding context for downstream use
                self.attack_surface_report = service.create_finding_context(report)

                logger.info(
                    f"Scan {self.scan_id}: AttackSurfaceDetection complete - "
                    f"{self.attack_surface_report['attack_surface']['total_entry_points']} entry points"
                )

            except Exception as e:
                logger.warning(f"Scan {self.scan_id}: AttackSurfaceDetection failed: {e}")
                await self.progress_callback.on_warning(
                    f"AttackSurfaceDetection failed: {e}"
                )

        # NOTE: Don't clean up temp_dir here - it will be reused by Phase 1
        # The temp_dir will be cleaned up at the end of the scan in _cleanup()

    async def _detect_tech_stack_for_l1(self) -> Dict[str, Any]:
        """
        Detect tech stack for L1_Preparation phase.

        This is a wrapper around _detect_tech_stack that handles the case
        where source_path hasn't been set yet.
        """
        # Reuse existing tech stack detection logic
        return await self._detect_tech_stack_impl()

    async def _detect_tech_stack_impl(self) -> Dict[str, Any]:
        """
        Implementation of tech stack detection.

        Extracted from _detect_tech_stack for reuse in L1 phase.
        """
        detector = TechStackDetector()
        tech_stack = detector.detect(self.source_path)

        # Convert to simplified format
        languages = [
            lang.language.value
            for lang in tech_stack.languages
        ]

        frameworks = [
            framework.name for framework in tech_stack.frameworks
        ]

        file_counts = {}
        for lang_info in tech_stack.languages:
            file_counts[lang_info.language.value] = lang_info.file_count

        return {
            "languages": languages,
            "primary_language": tech_stack.primary_language,
            "secondary_languages": tech_stack.secondary_languages or [],
            "frameworks": frameworks,
            "file_counts": file_counts,
            "total_loc": tech_stack.total_loc,
            "total_files": tech_stack.total_files,
            "project_type": tech_stack.project_type.value if tech_stack.project_type else "unknown",
            "has_tests": tech_stack.has_tests,
            "has_docs": tech_stack.has_docs,
            "is_monorepo": tech_stack.is_monorepo,
            "databases": [db.name for db in tech_stack.databases],
            "middleware": [mw.name for mw in tech_stack.middleware],
            "package_managers": tech_stack.package_managers,
            "build_tools": tech_stack.build_tools,
            "ci_cd": tech_stack.ci_cd,
            "_full_stack": tech_stack,
        }

    async def _update_token_statistics(self) -> Dict[str, Any]:
        """Update token usage statistics (P14-05).

        This method should be called during Phase 6 (Result_Finalization)
        to collect and store token usage information.

        Returns:
            Dictionary with token usage statistics
        """
        token_stats = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "agent_scan_tokens": 0,  # P14-05: Agent 扫描词元
            "adversarial_tokens": 0,  # P14-05: LLM 辩论词元
            "estimated_cost": 0.0,
        }

        logger.info(f"Token statistics check: llm_client={self.llm_client is not None}")

        # Collect tokens from orchestrator's LLM client
        if self.llm_client is not None:
            usage = self.llm_client.get_total_usage()
            logger.info(f"LLM client total tokens: {usage.total_tokens}")
            token_stats["prompt_tokens"] = usage.prompt_tokens
            token_stats["completion_tokens"] = usage.completion_tokens
            token_stats["total_tokens"] = usage.total_tokens

        # Collect tokens from engine raw_output (e.g., agent engine)
        # These are Agent 扫描词元
        agent_scan_tokens = 0
        for engine_name, scan_result in self.scan_results.items():
            if scan_result.raw_output and isinstance(scan_result.raw_output, dict):
                engine_tokens = scan_result.raw_output.get("total_tokens", 0)
                if engine_tokens:
                    logger.info(f"Engine {engine_name} tokens: {engine_tokens}")
                    agent_scan_tokens += engine_tokens

        # Use tracked adversarial tokens if available
        adversarial_tokens = self._adversarial_tokens_used

        # If we have engine tokens, use them; otherwise calculate
        if agent_scan_tokens > 0:
            token_stats["agent_scan_tokens"] = agent_scan_tokens
        else:
            # Fallback: total - adversarial = agent scan
            token_stats["agent_scan_tokens"] = max(
                0, token_stats["total_tokens"] - adversarial_tokens
            )

        # Use tracked adversarial tokens
        token_stats["adversarial_tokens"] = adversarial_tokens

        # Calculate estimated cost (using simple rate: $0.002 per 1K tokens)
        token_stats["estimated_cost"] = round(
            token_stats["total_tokens"] * 0.002 / 1000, 4
        )

        logger.info(f"Total token statistics: {token_stats}")

        # Update scan record with token usage
        if token_stats["total_tokens"] > 0:
            async with self.db_session_factory() as db:
                from src.web.repositories.scan import ScanRepository

                scan_repo = ScanRepository()
                scan = await scan_repo.get(db, id=self.scan_id)
                if scan:
                    # Update simple tokens_used field and token_usage JSON
                    logger.info(f"Scan {self.scan_id}: Updating token_usage: agent_scan_tokens={token_stats['agent_scan_tokens']}, adversarial_tokens={token_stats['adversarial_tokens']}")
                    await scan_repo.update(db, db_obj=scan, obj_in={
                        "tokens_used": token_stats["total_tokens"],
                        "token_usage": {
                            "prompt_tokens": token_stats["prompt_tokens"],
                            "completion_tokens": token_stats["completion_tokens"],
                            "total_tokens": token_stats["total_tokens"],
                            "agent_scan_tokens": token_stats["agent_scan_tokens"],
                            "adversarial_tokens": token_stats["adversarial_tokens"],
                            "estimated_cost": token_stats["estimated_cost"],
                        },
                    })
                    # Ensure the update is committed immediately
                    await db.commit()
                    logger.info(f"Scan {self.scan_id}: token_usage updated and committed")
                else:
                    logger.warning(f"Scan {self.scan_id}: Not found in database, cannot update token_usage")

        return token_stats


# ============================================================================
# Factory Function
# ============================================================================


def create_scan_orchestrator(
    scan_id: int,
    scan_config: Dict[str, Any],
    progress_callback: Optional[ProgressCallback] = None,
    llm_client: Optional[LLMClient] = None,
) -> ScanOrchestrator:
    """
    Factory function to create a ScanOrchestrator instance.

    Args:
        scan_id: ID of the scan
        scan_config: Scan configuration
        progress_callback: Optional progress callback
        llm_client: Optional LLM client for LLM-based features

    Returns:
        Configured ScanOrchestrator instance
    """
    return ScanOrchestrator(
        scan_id=scan_id,
        scan_config=scan_config,
        progress_callback=progress_callback,
        llm_client=llm_client,
    )
