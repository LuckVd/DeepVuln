"""Main attack surface detector with AST and regex support."""

from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.attack_surface.ast.base import (
    get_ast_detector_for_file,
)
from src.layers.l1_intelligence.attack_surface.http_detector import (
    get_detector_for_file as get_http_detector_for_file,
)
from src.layers.l1_intelligence.attack_surface.http_detector import (
    get_detector_for_framework as get_http_detector_for_framework,
)
from src.layers.l1_intelligence.attack_surface.models import (
    AttackSurfaceReport,
    EntryPoint,
)
from src.layers.l1_intelligence.attack_surface.mq_detector import (
    CronDetector,
    get_mq_detector_for_file,
    get_mq_detector_for_framework,
)
from src.layers.l1_intelligence.attack_surface.rpc_detector import (
    get_rpc_detector_for_file,
    get_rpc_detector_for_framework,
)

logger = get_logger(__name__)

# Detection mode constants
DETECT_MODE_STATIC = "static"  # Static detection only (default)
DETECT_MODE_LLM_ENHANCE = "llm-enhance"  # Static + LLM enhancement
DETECT_MODE_LLM_FULL = "llm-full"  # Full LLM-driven detection


# Re-export for convenience
__all__ = [
    "AttackSurfaceDetector",
    "DETECT_MODE_STATIC",
    "DETECT_MODE_LLM_ENHANCE",
    "DETECT_MODE_LLM_FULL",
]


class AttackSurfaceDetector:
    """Main detector for identifying attack entry points.

    Supports:
    - Static detection (AST + regex-based)
    - LLM-assisted detection (optional, for complex patterns)
    """

    def __init__(
        self,
        llm_client: Any = None,
        enable_llm: bool = False,
        llm_model: str = "deepseek-chat",
    ) -> None:
        """Initialize the detector.

        Args:
            llm_client: Optional LLM client for LLM-assisted detection.
            enable_llm: Whether to enable LLM-assisted detection.
            llm_model: LLM model name to use.
        """
        self.logger = get_logger(__name__)
        self._cron_detector = CronDetector()
        self.llm_client = llm_client
        self.enable_llm = enable_llm
        self.llm_model = llm_model
        self._llm_detector = None

        if enable_llm and llm_client:
            self._init_llm_detector()

    def _init_llm_detector(self) -> None:
        """Initialize LLM detector lazily."""
        try:
            from src.layers.l1_intelligence.attack_surface.llm_detector import (
                LLMHTTPDetector,
                LLMFullDetector,
            )

            self._llm_detector = LLMHTTPDetector(
                llm_client=self.llm_client,
                model=self.llm_model,
            )
            self._llm_full_detector = LLMFullDetector(
                llm_client=self.llm_client,
                model=self.llm_model,
            )
            self.logger.info(f"LLM detector initialized with model: {self.llm_model}")
        except ImportError as e:
            self.logger.warning(f"Failed to initialize LLM detector: {e}")
            self._llm_detector = None
            self._llm_full_detector = None

    def detect(self, source_path: Path, frameworks: list[str] | None = None) -> AttackSurfaceReport:
        """Detect attack surface for a project.

        Args:
            source_path: Path to source code.
            frameworks: Optional list of known frameworks to prioritize.

        Returns:
            Attack surface report.
        """
        self.logger.info(f"Detecting attack surface in {source_path}")

        report = AttackSurfaceReport(source_path=str(source_path))

        # Get framework-specific detectors
        http_detectors = []
        rpc_detectors = []
        mq_detectors = []

        if frameworks:
            for fw in frameworks:
                http_det = get_http_detector_for_framework(fw)
                if http_det:
                    http_detectors.append(http_det)
                rpc_det = get_rpc_detector_for_framework(fw)
                if rpc_det:
                    rpc_detectors.append(rpc_det)
                mq_det = get_mq_detector_for_framework(fw)
                if mq_det:
                    mq_detectors.append(mq_det)

        # Scan source files
        source_files = self._find_source_files(source_path)
        report.files_scanned = len(source_files)

        for file_path in source_files:
            try:
                entry_points = self._scan_file(
                    file_path, http_detectors, rpc_detectors, mq_detectors
                )
                for entry in entry_points:
                    report.add_entry_point(entry)
                    if entry.framework and entry.framework not in report.frameworks_detected:
                        report.frameworks_detected.append(entry.framework)

            except Exception as e:
                self.logger.warning(f"Error scanning {file_path}: {e}")
                report.errors.append(f"{file_path}: {e}")

        self.logger.info(
            f"Attack surface detection complete: {report.total_entry_points} entry points "
            f"(HTTP: {report.http_endpoints}, RPC: {report.rpc_services}, "
            f"gRPC: {report.grpc_services}, MQ: {report.mq_consumers}, Cron: {report.cron_jobs})"
        )

        return report

    async def detect_llm_full(
        self,
        source_path: Path,
        max_files: int = 50,
    ) -> AttackSurfaceReport:
        """Detect attack surface using full LLM-driven two-phase detection.

        This method uses LLM for both:
        1. Phase 1: Analyze project structure to identify target files
        2. Phase 2: Analyze each target file to detect entry points

        No static detectors are used - pure LLM detection.
        Supports any language and framework.

        Args:
            source_path: Path to source code.
            max_files: Maximum number of files to analyze in Phase 2.

        Returns:
            Attack surface report.
        """
        self.logger.info(f"Starting full LLM detection for {source_path}")

        report = AttackSurfaceReport(source_path=str(source_path))

        # Import and initialize LLMFullDetector
        try:
            from src.layers.l1_intelligence.attack_surface.llm_detector import LLMFullDetector
        except ImportError as e:
            self.logger.error(f"Failed to import LLMFullDetector: {e}")
            report.errors.append(f"LLM detection not available: {e}")
            return report

        if not self.llm_client:
            self.logger.error("LLM client not configured")
            report.errors.append("LLM client not configured")
            return report

        # Create LLM full detector
        llm_detector = LLMFullDetector(
            llm_client=self.llm_client,
            model=self.llm_model,
            max_files_to_analyze=max_files,
        )

        try:
            # Run full LLM detection
            entry_points = await llm_detector.detect_full(source_path)

            # Add entry points to report
            for entry in entry_points:
                report.add_entry_point(entry)
                if entry.framework and entry.framework not in report.frameworks_detected:
                    report.frameworks_detected.append(entry.framework)

            report.files_scanned = len(entry_points)  # Approximate

            self.logger.info(
                f"Full LLM detection complete: {report.total_entry_points} entry points "
                f"(HTTP: {report.http_endpoints}, RPC: {report.rpc_services}, "
                f"gRPC: {report.grpc_services}, MQ: {report.mq_consumers}, "
                f"Cron: {report.cron_jobs}, WebSocket: {report.websocket_endpoints})"
            )

        except Exception as e:
            self.logger.error(f"Full LLM detection failed: {e}")
            report.errors.append(f"LLM detection failed: {e}")

        return report

    async def detect_hybrid(
        self,
        source_path: Path,
        frameworks: list[str] | None = None,
        llm_mode: str = DETECT_MODE_LLM_ENHANCE,
    ) -> AttackSurfaceReport:
        """Detect attack surface with hybrid approach.

        Combines static detection with LLM detection based on mode:
        - static: Static detection only
        - llm-enhance: Static + LLM enhancement (default)
        - llm-full: Pure LLM-driven detection

        Args:
            source_path: Path to source code.
            frameworks: Optional list of known frameworks.
            llm_mode: LLM detection mode.

        Returns:
            Attack surface report.
        """
        if llm_mode == DETECT_MODE_LLM_FULL:
            return await self.detect_llm_full(source_path)

        # Static detection first
        report = self.detect(source_path, frameworks)

        # LLM enhancement if enabled
        if llm_mode == DETECT_MODE_LLM_ENHANCE and self._llm_detector:
            try:
                await self._llm_enhance(report, source_path)
            except Exception as e:
                self.logger.warning(f"LLM enhancement failed: {e}")

        return report

    async def detect_async(
        self,
        source_path: Path,
        frameworks: list[str] | None = None,
        use_llm_enhance: bool = True,
    ) -> AttackSurfaceReport:
        """Detect attack surface asynchronously with optional LLM enhancement.

        Args:
            source_path: Path to source code.
            frameworks: Optional list of known frameworks to prioritize.
            use_llm_enhance: Whether to use LLM to enhance detection (if enabled).

        Returns:
            Attack surface report.
        """
        # Run static detection first
        report = self.detect(source_path, frameworks)

        # Optionally enhance with LLM
        if use_llm_enhance and self._llm_detector and self.enable_llm:
            try:
                await self._llm_enhance(report, source_path)
            except Exception as e:
                self.logger.warning(f"LLM enhancement failed: {e}")

        return report

    async def _llm_enhance(self, report: AttackSurfaceReport, source_path: Path) -> None:
        """Enhance detection results with LLM.

        For files where static detection found nothing, try LLM detection.

        Args:
            report: The report to enhance.
            source_path: Path to source code.
        """
        if not self._llm_detector:
            return

        self.logger.info("Enhancing detection with LLM...")

        # Find files with no detected entry points
        files_with_entries = {Path(e.file) for e in report.entry_points}
        source_files = self._find_source_files(source_path)

        llm_found = 0
        for file_path in source_files:
            # Skip files that already have detected entry points
            if file_path in files_with_entries:
                continue

            # Skip non-HTTP related files
            try:
                content = file_path.read_text(encoding="utf-8")
                if not self._looks_like_http_file(content):
                    continue

                # Try LLM detection
                entry_points = await self._llm_detector.detect(content, file_path)
                for entry in entry_points:
                    report.add_entry_point(entry)
                    llm_found += 1
                    if entry.framework and entry.framework not in report.frameworks_detected:
                        report.frameworks_detected.append(entry.framework)

            except Exception as e:
                self.logger.debug(f"LLM detection failed on {file_path}: {e}")

        if llm_found > 0:
            self.logger.info(f"LLM enhancement found {llm_found} additional entry points")

    def _looks_like_http_file(self, content: str) -> bool:
        """Check if content looks like it might contain HTTP handling code.

        Args:
            content: File content.

        Returns:
            True if the content appears HTTP-related.
        """
        http_indicators = [
            "http",
            "server",
            "socket",
            "request",
            "response",
            "handler",
            "route",
            "api",
            "endpoint",
            "get",
            "post",
            "put",
            "delete",
        ]

        content_lower = content.lower()
        matches = sum(1 for kw in http_indicators if kw in content_lower)

        # Need at least 2 indicators and some minimal code size
        return matches >= 2 and len(content) >= 200

    def _find_source_files(self, source_path: Path) -> list[Path]:
        """Find source files to scan."""
        source_files: list[Path] = []

        # Extensions to scan (including RPC definition files)
        extensions = {".go", ".java", ".py", ".kt", ".ts", ".js", ".proto", ".thrift"}

        for ext in extensions:
            for file_path in source_path.rglob(f"*{ext}"):
                if self._should_skip_path(file_path):
                    continue
                source_files.append(file_path)

        return source_files

    def _should_skip_path(self, path: Path) -> bool:
        """Check if path should be skipped."""
        skip_dirs = {
            "node_modules",
            "venv",
            ".venv",
            "env",
            ".env",
            "__pycache__",
            ".git",
            "dist",
            "build",
            "target",
            "vendor",
            "test",
            "tests",
            "__tests__",
            "testdata",
            "examples",
            "docs",
        }
        for part in path.parts:
            if part.lower() in skip_dirs:
                return True
        return False

    def _scan_file(
        self,
        file_path: Path,
        http_detectors: list,
        rpc_detectors: list,
        mq_detectors: list,
    ) -> list[EntryPoint]:
        """Scan a single file for entry points.

        Uses a hybrid strategy:
        1. Try AST-based detection first (more accurate)
        2. Fall back to regex-based detection if AST fails or finds nothing
        3. For .proto/.thrift files, always use regex (no AST support)
        """
        entry_points: list[EntryPoint] = []

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            self.logger.debug(f"Could not read {file_path}: {e}")
            return entry_points

        ext = file_path.suffix

        # Phase 1: Try AST-based detection for supported languages
        if ext in (".java", ".py", ".go"):
            ast_detector = get_ast_detector_for_file(file_path)
            if ast_detector:
                try:
                    ast_results = ast_detector.detect(content, file_path)
                    if ast_results:
                        self.logger.debug(
                            f"AST detector found {len(ast_results)} entry points in {file_path}"
                        )
                        entry_points.extend(ast_results)
                        return entry_points  # AST found results, skip regex
                except Exception as e:
                    self.logger.debug(f"AST detector failed on {file_path}: {e}")

        # Phase 2: Fall back to regex-based detection
        # For proto/thrift files, always use regex (no AST support)
        # Try pre-configured HTTP detectors
        for detector in http_detectors:
            if self._file_matches_patterns(file_path, detector.file_patterns):
                try:
                    detected = detector.detect(content, file_path)
                    entry_points.extend(detected)
                except Exception as e:
                    self.logger.debug(f"HTTP detector {detector.framework_name} failed on {file_path}: {e}")

        # Try pre-configured RPC detectors
        for detector in rpc_detectors:
            if self._file_matches_patterns(file_path, detector.file_patterns):
                try:
                    detected = detector.detect(content, file_path)
                    entry_points.extend(detected)
                except Exception as e:
                    self.logger.debug(f"RPC detector {detector.framework_name} failed on {file_path}: {e}")

        # Try pre-configured MQ detectors
        for detector in mq_detectors:
            if self._file_matches_patterns(file_path, detector.file_patterns):
                try:
                    detected = detector.detect(content, file_path)
                    entry_points.extend(detected)
                except Exception as e:
                    self.logger.debug(f"MQ detector {detector.framework_name} failed on {file_path}: {e}")

        # Always try cron detector for supported files
        if self._file_matches_patterns(file_path, self._cron_detector.file_patterns):
            try:
                detected = self._cron_detector.detect(content, file_path)
                entry_points.extend(detected)
            except Exception as e:
                self.logger.debug(f"Cron detector failed on {file_path}: {e}")

        # If no results from pre-configured detectors, try auto-detection
        if not entry_points:
            # Try HTTP auto-detection
            file_http_detectors = get_http_detector_for_file(file_path)
            for detector in file_http_detectors:
                try:
                    detected = detector.detect(content, file_path)
                    entry_points.extend(detected)
                except Exception as e:
                    self.logger.debug(f"HTTP detector {detector.framework_name} failed on {file_path}: {e}")

            # Try RPC auto-detection
            file_rpc_detectors = get_rpc_detector_for_file(file_path)
            for detector in file_rpc_detectors:
                try:
                    detected = detector.detect(content, file_path)
                    entry_points.extend(detected)
                except Exception as e:
                    self.logger.debug(f"RPC detector {detector.framework_name} failed on {file_path}: {e}")

            # Try MQ auto-detection
            file_mq_detectors = get_mq_detector_for_file(file_path)
            for detector in file_mq_detectors:
                try:
                    detected = detector.detect(content, file_path)
                    entry_points.extend(detected)
                except Exception as e:
                    self.logger.debug(f"MQ detector {detector.framework_name} failed on {file_path}: {e}")

        return entry_points

    def _file_matches_patterns(self, file_path: Path, patterns: list[str]) -> bool:
        """Check if file matches any of the patterns."""
        for pattern in patterns:
            if pattern.startswith("*."):
                if file_path.suffix == pattern[1:]:
                    return True
            elif file_path.match(pattern):
                return True
        return False

    def detect_http_only(self, source_path: Path, frameworks: list[str] | None = None) -> list[EntryPoint]:
        """Detect only HTTP entry points."""
        report = self.detect(source_path, frameworks)
        return report.get_http_endpoints()

    def detect_endpoints_for_framework(
        self, source_path: Path, framework: str
    ) -> list[EntryPoint]:
        """Detect endpoints for a specific framework."""
        return self.detect(source_path, frameworks=[framework]).entry_points

    def generate_report_markdown(self, report: AttackSurfaceReport) -> str:
        """Generate a markdown report.

        Args:
            report: Attack surface report.

        Returns:
            Markdown formatted report.
        """
        lines = [
            "# Attack Surface Report",
            "",
            f"**Source:** `{report.source_path}`",
            f"**Files Scanned:** {report.files_scanned}",
            "",
            "## Summary",
            "",
            "| Type | Count |",
            "|------|-------|",
            f"| HTTP Endpoints | {report.http_endpoints} |",
            f"| RPC Services | {report.rpc_services} |",
            f"| gRPC Services | {report.grpc_services} |",
            f"| MQ Consumers | {report.mq_consumers} |",
            f"| Cron Jobs | {report.cron_jobs} |",
            f"| **Total** | **{report.total_entry_points}** |",
            "",
            f"**Frameworks Detected:** {', '.join(report.frameworks_detected) or 'None'}",
            "",
        ]

        # HTTP Endpoints
        http_entries = report.get_http_endpoints()
        if http_entries:
            lines.extend([
                "## HTTP Endpoints",
                "",
                "| Method | Path | Handler | File |",
                "|--------|------|---------|------|",
            ])
            for entry in http_entries:
                method = entry.method.value if entry.method else "ANY"
                short_file = Path(entry.file).name
                lines.append(f"| {method} | `{entry.path}` | `{entry.handler}` | {short_file}:{entry.line} |")
            lines.append("")

        # RPC Services
        rpc_entries = [e for e in report.entry_points if e.type.value == "rpc"]
        if rpc_entries:
            lines.extend([
                "## RPC Services",
                "",
                "| Service | Handler | Framework |",
                "|---------|---------|-----------|",
            ])
            for entry in rpc_entries:
                lines.append(f"| `{entry.path}` | `{entry.handler}` | {entry.framework} |")
            lines.append("")

        # gRPC Services
        grpc_entries = [e for e in report.entry_points if e.type.value == "grpc"]
        if grpc_entries:
            lines.extend([
                "## gRPC Services",
                "",
                "| Service/Method | File |",
                "|----------------|------|",
            ])
            for entry in grpc_entries:
                short_file = Path(entry.file).name
                lines.append(f"| `{entry.path}` | {short_file}:{entry.line} |")
            lines.append("")

        # MQ Consumers
        mq_entries = [e for e in report.entry_points if e.type.value == "mq"]
        if mq_entries:
            lines.extend([
                "## Message Queue Consumers",
                "",
                "| Queue/Topic | Handler | Framework |",
                "|-------------|---------|-----------|",
            ])
            for entry in mq_entries:
                lines.append(f"| `{entry.path}` | `{entry.handler}` | {entry.framework} |")
            lines.append("")

        # Cron Jobs
        cron_entries = [e for e in report.entry_points if e.type.value == "cron"]
        if cron_entries:
            lines.extend([
                "## Scheduled Tasks",
                "",
                "| Schedule | Handler | Framework |",
                "|----------|---------|-----------|",
            ])
            for entry in cron_entries:
                lines.append(f"| `{entry.path}` | `{entry.handler}` | {entry.framework} |")
            lines.append("")

        # Unauthenticated endpoints warning
        unauth = report.get_unauthenticated()
        if unauth:
            lines.extend([
                "## ⚠️ Unauthenticated Endpoints",
                "",
                f"Found **{len(unauth)}** entry points without authentication:",
                "",
            ])
            for entry in unauth[:10]:
                lines.append(f"- `{entry.to_display()}`")
            if len(unauth) > 10:
                lines.append(f"- ... and {len(unauth) - 10} more")
            lines.append("")

        return "\n".join(lines)
