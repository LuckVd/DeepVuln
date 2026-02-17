"""Main attack surface detector."""

from pathlib import Path

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.attack_surface.http_detector import (
    get_detector_for_file,
    get_detector_for_framework,
)
from src.layers.l1_intelligence.attack_surface.models import (
    AttackSurfaceReport,
    EntryPoint,
)

logger = get_logger(__name__)


class AttackSurfaceDetector:
    """Main detector for identifying attack entry points."""

    def __init__(self) -> None:
        """Initialize the detector."""
        self.logger = get_logger(__name__)

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
        framework_detectors = []
        if frameworks:
            for fw in frameworks:
                detector = get_detector_for_framework(fw)
                if detector:
                    framework_detectors.append(detector)

        # Scan source files
        source_files = self._find_source_files(source_path)
        report.files_scanned = len(source_files)

        for file_path in source_files:
            try:
                entry_points = self._scan_file(file_path, framework_detectors)
                for entry in entry_points:
                    report.add_entry_point(entry)
                    if entry.framework and entry.framework not in report.frameworks_detected:
                        report.frameworks_detected.append(entry.framework)

            except Exception as e:
                self.logger.warning(f"Error scanning {file_path}: {e}")
                report.errors.append(f"{file_path}: {e}")

        self.logger.info(
            f"Attack surface detection complete: {report.total_entry_points} entry points "
            f"(HTTP: {report.http_endpoints}, RPC: {report.rpc_services})"
        )

        return report

    def _find_source_files(self, source_path: Path) -> list[Path]:
        """Find source files to scan.

        Args:
            source_path: Root path to search.

        Returns:
            List of source files.
        """
        source_files: list[Path] = []

        # Extensions to scan
        extensions = {".go", ".java", ".py", ".kt", ".ts", ".js"}

        for ext in extensions:
            for file_path in source_path.rglob(f"*{ext}"):
                if self._should_skip_path(file_path):
                    continue
                source_files.append(file_path)

        return source_files

    def _should_skip_path(self, path: Path) -> bool:
        """Check if path should be skipped.

        Args:
            path: Path to check.

        Returns:
            True if path should be skipped.
        """
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
        self, file_path: Path, framework_detectors: list
    ) -> list[EntryPoint]:
        """Scan a single file for entry points.

        Args:
            file_path: Path to source file.
            framework_detectors: Pre-configured framework detectors.

        Returns:
            List of detected entry points.
        """
        entry_points: list[EntryPoint] = []

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            self.logger.debug(f"Could not read {file_path}: {e}")
            return entry_points

        # Try framework-specific detectors first
        for detector in framework_detectors:
            if any(
                file_path.suffix == p[1:] if p.startswith("*.") else file_path.match(p)
                for p in detector.file_patterns
            ):
                try:
                    detected = detector.detect(content, file_path)
                    entry_points.extend(detected)
                except Exception as e:
                    self.logger.debug(f"Detector {detector.framework_name} failed on {file_path}: {e}")

        # If no results, try auto-detection based on file type
        if not entry_points:
            file_detectors = get_detector_for_file(file_path)
            for detector in file_detectors:
                try:
                    detected = detector.detect(content, file_path)
                    entry_points.extend(detected)
                except Exception as e:
                    self.logger.debug(f"Detector {detector.framework_name} failed on {file_path}: {e}")

        return entry_points

    def detect_http_only(self, source_path: Path, frameworks: list[str] | None = None) -> list[EntryPoint]:
        """Detect only HTTP entry points.

        Args:
            source_path: Path to source code.
            frameworks: Optional list of known frameworks.

        Returns:
            List of HTTP entry points.
        """
        report = self.detect(source_path, frameworks)
        return report.get_http_endpoints()

    def detect_endpoints_for_framework(
        self, source_path: Path, framework: str
    ) -> list[EntryPoint]:
        """Detect endpoints for a specific framework.

        Args:
            source_path: Path to source code.
            framework: Framework name.

        Returns:
            List of entry points.
        """
        return self.detect(source_path, frameworks=[framework]).entry_points
