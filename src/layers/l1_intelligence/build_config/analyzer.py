"""Main build configuration security analyzer."""

from pathlib import Path

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.build_config.analyzers.cicd_analyzer import CICDAnalyzer
from src.layers.l1_intelligence.build_config.analyzers.dockerfile_analyzer import DockerfileAnalyzer
from src.layers.l1_intelligence.build_config.analyzers.gradle_analyzer import GradleAnalyzer
from src.layers.l1_intelligence.build_config.analyzers.maven_analyzer import MavenAnalyzer
from src.layers.l1_intelligence.build_config.analyzers.python_analyzer import PythonAnalyzer
from src.layers.l1_intelligence.build_config.analyzers.secrets_detector import SecretsDetector
from src.layers.l1_intelligence.build_config.base import BaseConfigAnalyzer
from src.layers.l1_intelligence.build_config.models import (
    BuildConfigReport,
    SecurityFinding,
)


class BuildConfigAnalyzer:
    """Main analyzer that orchestrates all configuration analyzers."""

    def __init__(self) -> None:
        """Initialize the build config analyzer with all sub-analyzers."""
        self.logger = get_logger(__name__)

        # Register all analyzers
        self.analyzers: list[BaseConfigAnalyzer] = [
            MavenAnalyzer(),
            GradleAnalyzer(),
            PythonAnalyzer(),
            DockerfileAnalyzer(),
            CICDAnalyzer(),
            SecretsDetector(),
        ]

    def analyze(self, source_path: Path) -> BuildConfigReport:
        """Analyze build configurations for security issues.

        Args:
            source_path: Path to the source code.

        Returns:
            BuildConfigReport with all findings.
        """
        report = BuildConfigReport(source_path=str(source_path))

        self.logger.info(f"Analyzing build configurations in {source_path}")

        for analyzer in self.analyzers:
            try:
                findings = analyzer.analyze(source_path, report)
                for finding in findings:
                    report.add_finding(finding)
                self.logger.debug(
                    f"{analyzer.__class__.__name__} found {len(findings)} findings"
                )
            except Exception as e:
                self.logger.error(f"Analyzer {analyzer.__class__.__name__} failed: {e}")
                report.scan_errors.append(f"{analyzer.__class__.__name__}: {e}")

        # Sort findings by risk level
        report.findings = self._sort_findings(report.findings)

        self.logger.info(
            f"Analysis complete: {len(report.findings)} findings from "
            f"{len(report.scanned_files)} files"
        )

        return report

    def _sort_findings(self, findings: list[SecurityFinding]) -> list[SecurityFinding]:
        """Sort findings by risk level.

        Args:
            findings: List of findings.

        Returns:
            Sorted list of findings.
        """
        risk_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }
        return sorted(findings, key=lambda f: risk_order.get(f.risk_level.value, 5))

    def analyze_file(self, file_path: Path) -> BuildConfigReport:
        """Analyze a single configuration file.

        Args:
            file_path: Path to the configuration file.

        Returns:
            BuildConfigReport with findings.
        """
        report = BuildConfigReport(source_path=str(file_path.parent))
        report.scanned_files.append(str(file_path))

        # Find appropriate analyzer
        for analyzer in self.analyzers:
            if analyzer.can_analyze(file_path):
                try:
                    findings = analyzer.analyze(file_path.parent, report)
                    for finding in findings:
                        report.add_finding(finding)
                except Exception as e:
                    self.logger.error(f"Analyzer {analyzer.__class__.__name__} failed: {e}")
                    report.scan_errors.append(f"{analyzer.__class__.__name__}: {e}")
                break

        return report

    def get_supported_files(self) -> list[str]:
        """Get list of all supported configuration files.

        Returns:
            List of supported file names/patterns.
        """
        files = []
        for analyzer in self.analyzers:
            files.extend(analyzer.supported_files)
        return list(set(files))
