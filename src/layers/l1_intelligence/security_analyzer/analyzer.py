"""Security analyzer for automated vulnerability detection."""

from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.dependency_scanner.base_scanner import (
    Dependency,
    Ecosystem,
    ScanResult,
)
from src.layers.l1_intelligence.dependency_scanner.npm_scanner import NpmScanner
from src.layers.l1_intelligence.dependency_scanner.python_scanner import PythonScanner
from src.layers.l1_intelligence.tech_stack_detector.detector import (
    Framework,
    TechStack,
    TechStackDetector,
)
from src.layers.l1_intelligence.threat_intel.core.data_models import (
    CVEInfo,
    SeverityLevel,
)


class DependencyVuln(BaseModel):
    """Vulnerability information for a dependency."""

    dependency: Dependency
    cves: list[CVEInfo] = Field(default_factory=list)
    highest_severity: SeverityLevel = SeverityLevel.INFO
    has_kev: bool = False
    kev_cves: list[str] = Field(default_factory=list)

    @property
    def cve_count(self) -> int:
        """Return number of CVEs."""
        return len(self.cves)


class FrameworkVuln(BaseModel):
    """Vulnerability information for a framework."""

    framework: Framework
    cves: list[CVEInfo] = Field(default_factory=list)
    highest_severity: SeverityLevel = SeverityLevel.INFO
    has_kev: bool = False
    kev_cves: list[str] = Field(default_factory=list)

    @property
    def cve_count(self) -> int:
        """Return number of CVEs."""
        return len(self.cves)


class SecurityReport(BaseModel):
    """Security analysis report."""

    # Source info
    source_path: str
    scanned_at: datetime = Field(default_factory=datetime.now)

    # Scan results
    dependencies_scanned: int = 0
    frameworks_detected: int = 0

    # Vulnerability counts
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # KEV info
    kev_count: int = 0
    kev_packages: list[str] = Field(default_factory=list)

    # Detailed results
    dependency_vulns: list[DependencyVuln] = Field(default_factory=list)
    framework_vulns: list[FrameworkVuln] = Field(default_factory=list)

    # Tech stack
    tech_stack: TechStack | None = None

    # Metadata
    scan_duration_seconds: float = 0.0
    errors: list[str] = Field(default_factory=list)

    @property
    def has_vulnerabilities(self) -> bool:
        """Check if any vulnerabilities were found."""
        return self.total_vulnerabilities > 0

    @property
    def has_critical_or_high(self) -> bool:
        """Check if any critical or high severity vulnerabilities."""
        return self.critical_count > 0 or self.high_count > 0

    @property
    def has_known_exploited(self) -> bool:
        """Check if any known exploited vulnerabilities."""
        return self.kev_count > 0

    def get_summary(self) -> dict[str, Any]:
        """Get summary of the report.

        Returns:
            Summary dictionary.
        """
        return {
            "source": self.source_path,
            "dependencies": self.dependencies_scanned,
            "frameworks": self.frameworks_detected,
            "vulnerabilities": self.total_vulnerabilities,
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "kev": self.kev_count,
        }


class SecurityAnalyzer:
    """Analyzer for automated security scanning."""

    def __init__(
        self,
        intel_service: Any = None,
        nvd_api_key: str | None = None,
        github_token: str | None = None,
    ) -> None:
        """Initialize the security analyzer.

        Args:
            intel_service: IntelService instance for CVE lookup.
            nvd_api_key: NVD API key.
            github_token: GitHub token.
        """
        self.logger = get_logger(__name__)
        self.intel_service = intel_service
        self.nvd_api_key = nvd_api_key
        self.github_token = github_token

        # Initialize scanners
        self.npm_scanner = NpmScanner()
        self.python_scanner = PythonScanner()
        self.tech_detector = TechStackDetector()

    async def analyze(self, source_path: Path) -> SecurityReport:
        """Perform security analysis on source code.

        Args:
            source_path: Path to the source code.

        Returns:
            Security analysis report.
        """
        start_time = datetime.now()
        self.logger.info(f"Starting security analysis of {source_path}")

        report = SecurityReport(source_path=str(source_path))

        try:
            # Step 1: Scan dependencies
            self.logger.info("Scanning dependencies...")
            scan_result = await self._scan_dependencies(source_path)
            report.dependencies_scanned = scan_result.total_dependencies
            report.errors.extend(scan_result.errors)

            # Step 2: Detect tech stack
            self.logger.info("Detecting tech stack...")
            tech_stack = self.tech_detector.detect(source_path)
            report.tech_stack = tech_stack
            report.frameworks_detected = len(tech_stack.frameworks)

            # Step 3: Lookup CVEs for dependencies
            self.logger.info("Looking up CVEs for dependencies...")
            dep_vulns = await self._lookup_dependency_vulns(scan_result)
            report.dependency_vulns = dep_vulns

            # Step 4: Lookup CVEs for frameworks
            self.logger.info("Looking up CVEs for frameworks...")
            fw_vulns = await self._lookup_framework_vulns(tech_stack)
            report.framework_vulns = fw_vulns

            # Step 5: Calculate statistics
            self._calculate_statistics(report)

        except Exception as e:
            self.logger.error(f"Security analysis failed: {e}")
            report.errors.append(str(e))

        # Calculate duration
        report.scan_duration_seconds = (datetime.now() - start_time).total_seconds()

        self.logger.info(
            f"Security analysis complete: {report.total_vulnerabilities} vulnerabilities, "
            f"{report.kev_count} KEV"
        )

        return report

    async def _scan_dependencies(self, source_path: Path) -> ScanResult:
        """Scan all dependency files.

        Args:
            source_path: Path to the source code.

        Returns:
            Combined scan result.
        """
        from src.layers.l1_intelligence.dependency_scanner.base_scanner import (
            CompositeScanner,
        )

        scanner = CompositeScanner()
        return scanner.scan(source_path)

    async def _lookup_dependency_vulns(
        self, scan_result: ScanResult
    ) -> list[DependencyVuln]:
        """Look up CVEs for dependencies using multiple sources.

        Args:
            scan_result: Dependency scan result.

        Returns:
            List of dependency vulnerability info.
        """
        vulns: list[DependencyVuln] = []

        if not self.intel_service:
            self.logger.warning("No IntelService available, skipping CVE lookup")
            return vulns

        # Ecosystem mapping for OSV API
        ecosystem_to_osv = {
            Ecosystem.NPM: "npm",
            Ecosystem.PYPI: "PyPI",
            Ecosystem.GO: "Go",
            Ecosystem.MAVEN: "Maven",
            Ecosystem.CARGO: "crates.io",
            Ecosystem.COMPOSER: "Packagist",
            Ecosystem.GEM: "RubyGems",
            Ecosystem.NUGET: "NuGet",
        }

        # Create OSV client once for all dependencies
        from src.layers.l1_intelligence.threat_intel.sources.advisories.osv_client import (
            OSVClient,
        )

        osv_client: OSVClient | None = None
        try:
            osv_client = OSVClient()
            await osv_client._get_session()  # Pre-initialize session
            self.logger.info("OSV client initialized for vulnerability lookup")
        except Exception as e:
            self.logger.warning(f"Failed to initialize OSV client: {e}")
            osv_client = None

        try:
            # Group dependencies by ecosystem for efficient lookup
            unique_packages = scan_result.get_unique_packages()
            self.logger.info(f"Looking up CVEs for {len(unique_packages)} unique packages")

            for dep in unique_packages:
                try:
                    all_cves: list[CVEInfo] = []
                    seen_cve_ids: set[str] = set()

                    # Try OSV API for ALL supported ecosystems
                    osv_ecosystem = ecosystem_to_osv.get(dep.ecosystem)
                    if osv_ecosystem and osv_client:
                        try:
                            osv_cves = await osv_client.query_by_package(
                                package_name=dep.name,
                                ecosystem=osv_ecosystem,
                                version=dep.version if dep.version != "*" else None,
                            )
                            for cve in osv_cves:
                                if cve.cve_id not in seen_cve_ids:
                                    seen_cve_ids.add(cve.cve_id)
                                    all_cves.append(cve)
                        except Exception as e:
                            self.logger.debug(f"OSV lookup failed for {dep.name}: {e}")

                    # Also search local database
                    query = dep.to_search_query()
                    db_cves = await self.intel_service.search_cves(query, limit=10)
                    for cve in db_cves:
                        if cve.cve_id not in seen_cve_ids:
                            seen_cve_ids.add(cve.cve_id)
                            all_cves.append(cve)

                    if all_cves:
                        # Filter to relevant CVEs
                        relevant_cves = self._filter_relevant_cves(all_cves, dep)

                        if relevant_cves:
                            dep_vuln = DependencyVuln(
                                dependency=dep,
                                cves=relevant_cves,
                                highest_severity=self._get_highest_severity(relevant_cves),
                                has_kev=any(c.kev for c in relevant_cves),
                                kev_cves=[c.cve_id for c in relevant_cves if c.kev],
                            )
                            vulns.append(dep_vuln)

                except Exception as e:
                    self.logger.warning(f"Failed to lookup CVEs for {dep.name}: {e}")
        finally:
            # Close OSV client session
            if osv_client:
                await osv_client.close()

        return vulns

    async def _lookup_framework_vulns(self, tech_stack: TechStack) -> list[FrameworkVuln]:
        """Look up CVEs for frameworks.

        Args:
            tech_stack: Detected tech stack.

        Returns:
            List of framework vulnerability info.
        """
        vulns: list[FrameworkVuln] = []

        if not self.intel_service:
            return vulns

        for framework in tech_stack.frameworks:
            try:
                # Search for CVEs related to this framework
                query = f"{framework.name} vulnerability"
                cves = await self.intel_service.search_cves(query, limit=10)

                if cves:
                    # Filter to relevant CVEs
                    relevant_cves = self._filter_framework_cves(cves, framework)

                    if relevant_cves:
                        fw_vuln = FrameworkVuln(
                            framework=framework,
                            cves=relevant_cves,
                            highest_severity=self._get_highest_severity(relevant_cves),
                            has_kev=any(c.kev for c in relevant_cves),
                            kev_cves=[c.cve_id for c in relevant_cves if c.kev],
                        )
                        vulns.append(fw_vuln)

            except Exception as e:
                self.logger.warning(f"Failed to lookup CVEs for {framework.name}: {e}")

        return vulns

    def _filter_relevant_cves(
        self, cves: list[CVEInfo], dep: Dependency
    ) -> list[CVEInfo]:
        """Filter CVEs to those relevant to the dependency.

        Args:
            cves: List of CVEs.
            dep: Dependency info.

        Returns:
            Filtered list of relevant CVEs.
        """
        from src.layers.l1_intelligence.security_analyzer.version_utils import (
            is_version_vulnerable,
        )

        relevant: list[CVEInfo] = []
        dep_name_lower = dep.name.lower()

        # For Go modules, extract the package name for better matching
        go_package_name = None
        if dep.ecosystem == Ecosystem.GO:
            # Extract package name from module path
            # e.g., "github.com/gin-gonic/gin" -> "gin"
            parts = dep.name.split("/")
            if parts:
                go_package_name = parts[-1].lower()

        # For Maven packages, extract artifact ID for matching
        # Format: "groupId:artifactId" -> extract "artifactId"
        maven_artifact_id = None
        maven_group_id = None
        if dep.ecosystem == Ecosystem.MAVEN and ":" in dep.name:
            parts = dep.name.split(":")
            if len(parts) == 2:
                maven_group_id = parts[0].lower()
                maven_artifact_id = parts[1].lower()

        for cve in cves:
            # Check if CVE is from advisory sources (already filtered by package name)
            if "github-advisory" in cve.tags or "go-vulndb" in cve.tags or "osv" in cve.tags:
                # Advisory sources provide precise matches by package name
                # Still check version if affected_versions is available
                if cve.affected_versions and dep.version and dep.version != "*":
                    if is_version_vulnerable(dep.version, cve.affected_versions):
                        relevant.append(cve)
                else:
                    relevant.append(cve)
                continue

            # Check if CVE description mentions the dependency
            desc_lower = cve.description.lower()

            # Check for dependency name in description
            name_match = dep_name_lower in desc_lower

            # For Go modules, also check package name
            if not name_match and go_package_name:
                name_match = go_package_name in desc_lower

            # For Maven packages, also check artifact ID
            if not name_match and maven_artifact_id:
                name_match = maven_artifact_id in desc_lower

            # Check for dependency name in affected products
            product_match = any(
                dep_name_lower in p.lower() for p in cve.affected_products
            )

            # For Go modules, also check if module path matches
            if not product_match and dep.ecosystem == Ecosystem.GO:
                product_match = any(
                    dep_name_lower == p.lower() or
                    p.lower().startswith(dep_name_lower + "/")
                    for p in cve.affected_products
                )

            # For Maven packages, also check artifact ID in affected products
            if not product_match and maven_artifact_id:
                product_match = any(
                    maven_artifact_id == p.lower() or
                    maven_artifact_id in p.lower()
                    for p in cve.affected_products
                )

            if name_match or product_match:
                # Check version if affected_versions is specified
                if cve.affected_versions and dep.version:
                    if is_version_vulnerable(dep.version, cve.affected_versions):
                        relevant.append(cve)
                else:
                    # No version constraint, include by default
                    relevant.append(cve)

        return relevant

    def _filter_framework_cves(
        self, cves: list[CVEInfo], framework: Framework
    ) -> list[CVEInfo]:
        """Filter CVEs to those relevant to the framework.

        Args:
            cves: List of CVEs.
            framework: Framework info.

        Returns:
            Filtered list of relevant CVEs.
        """
        relevant: list[CVEInfo] = []
        fw_name_lower = framework.name.lower()

        for cve in cves:
            desc_lower = cve.description.lower()

            # Check for framework name in description or affected products
            name_match = fw_name_lower in desc_lower
            product_match = any(
                fw_name_lower in p.lower() for p in cve.affected_products
            )

            if name_match or product_match:
                relevant.append(cve)

        return relevant

    def _get_highest_severity(self, cves: list[CVEInfo]) -> SeverityLevel:
        """Get highest severity from CVEs.

        Args:
            cves: List of CVEs.

        Returns:
            Highest severity level.
        """
        severity_order = [
            SeverityLevel.CRITICAL,
            SeverityLevel.HIGH,
            SeverityLevel.MEDIUM,
            SeverityLevel.LOW,
            SeverityLevel.INFO,
        ]

        for severity in severity_order:
            if any(c.severity == severity for c in cves):
                return severity

        return SeverityLevel.INFO

    def _calculate_statistics(self, report: SecurityReport) -> None:
        """Calculate vulnerability statistics.

        Args:
            report: Report to update.
        """
        total = 0
        critical = 0
        high = 0
        medium = 0
        low = 0
        info = 0
        kev = 0
        kev_packages: set[str] = set()

        # Count dependency vulnerabilities
        for dep_vuln in report.dependency_vulns:
            for cve in dep_vuln.cves:
                total += 1
                if cve.severity == SeverityLevel.CRITICAL:
                    critical += 1
                elif cve.severity == SeverityLevel.HIGH:
                    high += 1
                elif cve.severity == SeverityLevel.MEDIUM:
                    medium += 1
                elif cve.severity == SeverityLevel.LOW:
                    low += 1
                else:
                    info += 1

                if cve.kev:
                    kev += 1
                    kev_packages.add(dep_vuln.dependency.name)

        # Count framework vulnerabilities
        for fw_vuln in report.framework_vulns:
            for cve in fw_vuln.cves:
                total += 1
                if cve.severity == SeverityLevel.CRITICAL:
                    critical += 1
                elif cve.severity == SeverityLevel.HIGH:
                    high += 1
                elif cve.severity == SeverityLevel.MEDIUM:
                    medium += 1
                elif cve.severity == SeverityLevel.LOW:
                    low += 1
                else:
                    info += 1

                if cve.kev:
                    kev += 1
                    kev_packages.add(fw_vuln.framework.name)

        # Update report
        report.total_vulnerabilities = total
        report.critical_count = critical
        report.high_count = high
        report.medium_count = medium
        report.low_count = low
        report.info_count = info
        report.kev_count = kev
        report.kev_packages = list(kev_packages)
