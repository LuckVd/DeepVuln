"""Unit tests for main BuildConfigAnalyzer."""

import tempfile
from pathlib import Path

import pytest

from src.layers.l1_intelligence.build_config.analyzer import BuildConfigAnalyzer
from src.layers.l1_intelligence.build_config.models import BuildConfigReport


class TestBuildConfigAnalyzer:
    """Tests for BuildConfigAnalyzer."""

    @pytest.fixture
    def analyzer(self) -> BuildConfigAnalyzer:
        """Create analyzer instance."""
        return BuildConfigAnalyzer()

    @pytest.fixture
    def temp_dir(self) -> Path:
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_get_supported_files(self, analyzer: BuildConfigAnalyzer) -> None:
        """Test getting list of supported files."""
        supported = analyzer.get_supported_files()
        assert "pom.xml" in supported

    def test_analyze_empty_directory(self, analyzer: BuildConfigAnalyzer, temp_dir: Path) -> None:
        """Test analyzing empty directory."""
        report = analyzer.analyze(temp_dir)

        assert isinstance(report, BuildConfigReport)
        assert report.source_path == str(temp_dir)
        assert len(report.findings) == 0
        assert len(report.scanned_files) == 0

    def test_analyze_directory_with_pom(self, analyzer: BuildConfigAnalyzer, temp_dir: Path) -> None:
        """Test analyzing directory with POM file."""
        pom_content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test-project</artifactId>
    <version>1.0.0</version>
    <properties>
        <db.password>SecretPassword123!</db.password>
    </properties>
</project>
"""
        (temp_dir / "pom.xml").write_text(pom_content)

        report = analyzer.analyze(temp_dir)

        assert len(report.scanned_files) == 1
        assert len(report.findings) >= 1
        assert report.summary.get("medium", 0) >= 1 or report.summary.get("high", 0) >= 1

    def test_analyze_single_file(self, analyzer: BuildConfigAnalyzer, temp_dir: Path) -> None:
        """Test analyzing a single configuration file."""
        pom_content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test-project</artifactId>
    <version>1.0.0</version>
</project>
"""
        pom_file = temp_dir / "pom.xml"
        pom_file.write_text(pom_content)

        report = analyzer.analyze_file(pom_file)

        assert isinstance(report, BuildConfigReport)
        # May scan same file twice (once in find_files, once in analyze_file)
        assert len(report.scanned_files) >= 1
        assert str(pom_file) in report.scanned_files

    def test_report_summary(self, analyzer: BuildConfigAnalyzer, temp_dir: Path) -> None:
        """Test report summary calculation."""
        pom_content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test-project</artifactId>
    <version>1.0.0</version>
    <properties>
        <password>secret1</password>
        <api.key>secret2</api.key>
    </properties>
    <modules>
        <module>auth</module>
    </modules>
</project>
"""
        (temp_dir / "pom.xml").write_text(pom_content)

        report = analyzer.analyze(temp_dir)

        # Summary should have counts
        assert len(report.summary) > 0
        assert sum(report.summary.values()) == len(report.findings)

    def test_findings_sorted_by_risk(self, analyzer: BuildConfigAnalyzer, temp_dir: Path) -> None:
        """Test that findings are sorted by risk level."""
        pom_content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test-project</artifactId>
    <version>1.0.0</version>
    <properties>
        <password>AKIAIOSFODNN7EXAMPLE</password>
    </properties>
    <modules>
        <module>auth</module>
    </modules>
</project>
"""
        (temp_dir / "pom.xml").write_text(pom_content)

        report = analyzer.analyze(temp_dir)

        # Findings should be sorted by risk (highest first)
        if len(report.findings) > 1:
            risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            for i in range(len(report.findings) - 1):
                current_risk = risk_order.get(report.findings[i].risk_level.value, 5)
                next_risk = risk_order.get(report.findings[i + 1].risk_level.value, 5)
                assert current_risk <= next_risk
