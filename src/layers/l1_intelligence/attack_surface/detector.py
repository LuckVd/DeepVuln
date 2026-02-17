"""Main attack surface detector."""

from pathlib import Path

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.attack_surface.http_detector import (
    get_detector_for_file as get_http_detector_for_file,
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


class AttackSurfaceDetector:
    """Main detector for identifying attack entry points."""

    def __init__(self) -> None:
        """Initialize the detector."""
        self.logger = get_logger(__name__)
        self._cron_detector = CronDetector()

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
        """Scan a single file for entry points."""
        entry_points: list[EntryPoint] = []

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            self.logger.debug(f"Could not read {file_path}: {e}")
            return entry_points

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
