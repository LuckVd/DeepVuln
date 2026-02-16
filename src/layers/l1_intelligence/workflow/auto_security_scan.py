"""Auto security scan workflow for code-based vulnerability detection."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.security_analyzer.analyzer import (
    SecurityAnalyzer,
    SecurityReport,
)
from src.layers.l1_intelligence.tech_stack_detector.detector import TechStackDetector


class ScanConfig(BaseModel):
    """Configuration for auto security scan."""

    # Scan options
    scan_dependencies: bool = True
    scan_frameworks: bool = True
    scan_code_patterns: bool = False  # Future: code pattern analysis

    # CVE lookup options
    lookup_cves: bool = True
    max_cves_per_dependency: int = 10
    include_low_severity: bool = False

    # Output options
    include_kev_only: bool = False
    min_confidence: float = 0.5

    # Performance options
    concurrent_lookups: int = 5
    timeout_seconds: int = 300


@dataclass
class ScanResult:
    """Result of auto security scan workflow."""

    success: bool
    report: SecurityReport | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    # Workflow metadata
    source_path: str = ""
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization.

        Returns:
            Dictionary representation.
        """
        return {
            "success": self.success,
            "source_path": self.source_path,
            "scan_duration_seconds": self.scan_duration_seconds,
            "errors": self.errors,
            "warnings": self.warnings,
            "report": self.report.model_dump() if self.report else None,
        }


class AutoSecurityScanner:
    """Auto security scanner that integrates with source acquisition workflow.

    This class orchestrates the automatic security analysis workflow:
    1. Scan dependencies from package files
    2. Detect technology stack
    3. Look up CVEs for dependencies and frameworks
    4. Generate security report
    """

    def __init__(
        self,
        intel_service: Any = None,
        config: ScanConfig | None = None,
    ) -> None:
        """Initialize the auto security scanner.

        Args:
            intel_service: IntelService instance for CVE lookup.
            config: Scan configuration.
        """
        self.logger = get_logger(__name__)
        self.intel_service = intel_service
        self.config = config or ScanConfig()

        # Initialize components
        self.security_analyzer = SecurityAnalyzer(
            intel_service=intel_service,
        )
        self.tech_detector = TechStackDetector()

    async def scan(self, source_path: Path) -> ScanResult:
        """Perform automatic security scan on source code.

        Args:
            source_path: Path to the source code.

        Returns:
            Scan result with security report.
        """
        import time

        start_time = time.time()
        self.logger.info(f"Starting auto security scan for {source_path}")

        result = ScanResult(
            success=False,
            source_path=str(source_path),
        )

        try:
            # Validate source path
            if not source_path.exists():
                result.errors.append(f"Source path does not exist: {source_path}")
                return result

            if not source_path.is_dir():
                result.errors.append(f"Source path is not a directory: {source_path}")
                return result

            # Run security analysis
            self.logger.info("Running security analysis...")
            report = await self.security_analyzer.analyze(source_path)

            # Apply filters based on config
            self._apply_filters(report)

            # Add warnings for detected issues
            if report.errors:
                result.warnings.extend(report.errors)

            result.report = report
            result.success = True

            self.logger.info(
                f"Auto security scan complete: "
                f"{report.total_vulnerabilities} vulnerabilities found, "
                f"{report.kev_count} known exploited"
            )

        except Exception as e:
            self.logger.error(f"Auto security scan failed: {e}")
            result.errors.append(str(e))

        # Calculate duration
        result.scan_duration_seconds = time.time() - start_time

        return result

    def _apply_filters(self, report: SecurityReport) -> None:
        """Apply configuration filters to the report.

        Args:
            report: Security report to filter.
        """
        # Filter by minimum confidence
        if self.config.min_confidence > 0:
            report.framework_vulns = [
                fv
                for fv in report.framework_vulns
                if fv.framework.confidence >= self.config.min_confidence
            ]

        # Filter low severity if configured
        if not self.config.include_low_severity:
            from src.layers.l1_intelligence.threat_intel.core.data_models import (
                SeverityLevel,
            )

            for dep_vuln in report.dependency_vulns:
                dep_vuln.cves = [
                    cve for cve in dep_vuln.cves if cve.severity != SeverityLevel.LOW
                ]
                dep_vuln.highest_severity = self.security_analyzer._get_highest_severity(
                    dep_vuln.cves
                )

            for fw_vuln in report.framework_vulns:
                fw_vuln.cves = [
                    cve for cve in fw_vuln.cves if cve.severity != SeverityLevel.LOW
                ]
                fw_vuln.highest_severity = self.security_analyzer._get_highest_severity(
                    fw_vuln.cves
                )

        # Filter KEV only if configured
        if self.config.include_kev_only:
            report.dependency_vulns = [dv for dv in report.dependency_vulns if dv.has_kev]
            report.framework_vulns = [fv for fv in report.framework_vulns if fv.has_kev]

        # Recalculate statistics after filtering
        self.security_analyzer._calculate_statistics(report)

    async def quick_scan(self, source_path: Path) -> dict[str, Any]:
        """Perform a quick scan for immediate feedback.

        This is a lighter-weight scan that only checks for:
        - Known exploited vulnerabilities (KEV)
        - Critical/High severity issues

        Args:
            source_path: Path to the source code.

        Returns:
            Quick scan summary.
        """
        self.logger.info(f"Running quick scan for {source_path}")

        # Use optimized config for quick scan
        quick_config = ScanConfig(
            scan_dependencies=True,
            scan_frameworks=True,
            lookup_cves=True,
            max_cves_per_dependency=5,
            include_low_severity=False,
            include_kev_only=False,
            concurrent_lookups=10,
            timeout_seconds=60,
        )

        # Temporarily use quick config
        original_config = self.config
        self.config = quick_config

        try:
            result = await self.scan(source_path)

            if not result.success or not result.report:
                return {
                    "success": False,
                    "errors": result.errors,
                }

            report = result.report

            return {
                "success": True,
                "source": str(source_path),
                "dependencies": report.dependencies_scanned,
                "frameworks": report.frameworks_detected,
                "critical_high": report.critical_count + report.high_count,
                "kev_count": report.kev_count,
                "has_issues": report.has_vulnerabilities,
                "needs_attention": report.has_critical_or_high or report.has_known_exploited,
                "duration": result.scan_duration_seconds,
            }

        finally:
            self.config = original_config

    def get_tech_stack_summary(self, source_path: Path) -> dict[str, Any]:
        """Get a quick summary of detected tech stack.

        Args:
            source_path: Path to the source code.

        Returns:
            Tech stack summary.
        """
        self.logger.info(f"Detecting tech stack for {source_path}")

        tech_stack = self.tech_detector.detect(source_path)

        return {
            "languages": [lang.value for lang in tech_stack.languages],
            "frameworks": [
                {
                    "name": fw.name,
                    "category": fw.category,
                    "version": fw.version,
                    "confidence": fw.confidence,
                }
                for fw in tech_stack.frameworks
            ],
            "databases": [db.name for db in tech_stack.databases],
            "middleware": [mw.name for mw in tech_stack.middleware],
            "build_tools": tech_stack.build_tools,
            "package_managers": tech_stack.package_managers,
            "ci_cd": tech_stack.ci_cd,
        }
