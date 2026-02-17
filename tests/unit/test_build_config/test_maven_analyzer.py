"""Unit tests for Maven build configuration analyzer."""

import tempfile
from pathlib import Path

import pytest

from src.layers.l1_intelligence.build_config.analyzers.maven_analyzer import MavenAnalyzer
from src.layers.l1_intelligence.build_config.models import (
    BuildConfigReport,
    FindingCategory,
    SecurityRisk,
)


class TestMavenAnalyzer:
    """Tests for MavenAnalyzer."""

    @pytest.fixture
    def analyzer(self) -> MavenAnalyzer:
        """Create analyzer instance."""
        return MavenAnalyzer()

    @pytest.fixture
    def temp_dir(self) -> Path:
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_supported_files(self, analyzer: MavenAnalyzer) -> None:
        """Test supported file list."""
        assert "pom.xml" in analyzer.supported_files

    def test_can_analyze_pom_xml(self, analyzer: MavenAnalyzer, temp_dir: Path) -> None:
        """Test can_analyze method."""
        pom_file = temp_dir / "pom.xml"
        assert analyzer.can_analyze(pom_file)

        other_file = temp_dir / "build.gradle"
        assert not analyzer.can_analyze(other_file)

    def test_analyze_empty_pom(self, analyzer: MavenAnalyzer, temp_dir: Path) -> None:
        """Test analyzing minimal POM file."""
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

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        assert len(report.scanned_files) == 1
        assert len(findings) == 0  # No security issues in minimal POM

    def test_analyze_sensitive_properties(self, analyzer: MavenAnalyzer, temp_dir: Path) -> None:
        """Test detection of sensitive properties."""
        pom_content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test-project</artifactId>
    <version>1.0.0</version>
    <properties>
        <db.password>SuperSecret123!</db.password>
        <api.secret>aB1cD2eF3gH4iJ5kL6mN7oP8</api.secret>
        <normal.property>hello</normal.property>
    </properties>
</project>
"""
        pom_file = temp_dir / "pom.xml"
        pom_file.write_text(pom_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find at least 1 sensitive property (password is always flagged by name)
        sensitive_findings = [f for f in findings if f.category == FindingCategory.SECRETS]
        assert len(sensitive_findings) >= 1

        # Check that passwords are detected
        password_findings = [f for f in findings if "password" in f.title.lower()]
        assert len(password_findings) >= 1

    def test_analyze_profiles(self, analyzer: MavenAnalyzer, temp_dir: Path) -> None:
        """Test profile analysis."""
        pom_content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test-project</artifactId>
    <version>1.0.0</version>
    <profiles>
        <profile>
            <id>production</id>
            <properties>
                <db.password>ProdSecret456!</db.password>
            </properties>
        </profile>
        <profile>
            <id>development</id>
            <activation>
                <activeByDefault>true</activeByDefault>
            </activation>
            <properties>
                <db.password>DevSecret789!</db.password>
            </properties>
        </profile>
    </profiles>
</project>
"""
        pom_file = temp_dir / "pom.xml"
        pom_file.write_text(pom_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Check that profiles are parsed
        assert len(report.maven_profiles) == 2

        # Check that sensitive properties in profiles are detected
        profile_findings = [f for f in findings if "profile" in f.title.lower()]
        assert len(profile_findings) >= 2

    def test_analyze_plugins(self, analyzer: MavenAnalyzer, temp_dir: Path) -> None:
        """Test plugin analysis."""
        pom_content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test-project</artifactId>
    <version>1.0.0</version>
    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.8.1</version>
                <configuration>
                    <source>11</source>
                    <target>11</target>
                </configuration>
            </plugin>
            <plugin>
                <groupId>org.owasp</groupId>
                <artifactId>dependency-check-maven</artifactId>
                <version>6.5.0</version>
            </plugin>
        </plugins>
    </build>
</project>
"""
        pom_file = temp_dir / "pom.xml"
        pom_file.write_text(pom_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Check that plugins are parsed
        assert len(report.maven_plugins) == 2

        # Check plugin details
        compiler_plugin = next(
            (p for p in report.maven_plugins if p.artifact_id == "maven-compiler-plugin"), None
        )
        assert compiler_plugin is not None
        assert compiler_plugin.version == "3.8.1"

    def test_analyze_modules(self, analyzer: MavenAnalyzer, temp_dir: Path) -> None:
        """Test multi-module project analysis."""
        pom_content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>parent-project</artifactId>
    <version>1.0.0</version>
    <packaging>pom</packaging>
    <modules>
        <module>auth-service</module>
        <module>api-gateway</module>
        <module>common-lib</module>
    </modules>
</project>
"""
        pom_file = temp_dir / "pom.xml"
        pom_file.write_text(pom_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Check that modules are parsed
        assert len(report.maven_modules) == 3

        # Check that security-sensitive modules are detected
        info_findings = [f for f in findings if f.risk_level == SecurityRisk.INFO]
        assert len(info_findings) >= 1

        # Should mention auth and api-gateway as sensitive
        security_module_finding = next(
            (f for f in findings if "security-sensitive" in f.title.lower()), None
        )
        assert security_module_finding is not None
        assert "auth-service" in security_module_finding.evidence

    def test_placeholder_values_not_flagged(
        self, analyzer: MavenAnalyzer, temp_dir: Path
    ) -> None:
        """Test that placeholder values are not flagged as secrets."""
        pom_content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test-project</artifactId>
    <version>1.0.0</version>
    <properties>
        <db.password>${env.DB_PASSWORD}</db.password>
        <api.key>@api.key@</api.key>
    </properties>
</project>
"""
        pom_file = temp_dir / "pom.xml"
        pom_file.write_text(pom_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Placeholders should not be flagged as secrets
        secret_findings = [f for f in findings if f.category == FindingCategory.SECRETS]
        assert len(secret_findings) == 0

    def test_nested_pom_files(self, analyzer: MavenAnalyzer, temp_dir: Path) -> None:
        """Test analysis of nested POM files in multi-module project."""
        # Create parent POM
        parent_pom = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
    <packaging>pom</packaging>
    <modules>
        <module>module1</module>
    </modules>
    <properties>
        <parent.secret>ParentSecret123</parent.secret>
    </properties>
</project>
"""
        (temp_dir / "pom.xml").write_text(parent_pom)

        # Create module POM
        module_dir = temp_dir / "module1"
        module_dir.mkdir()
        module_pom = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>com.example</groupId>
        <artifactId>parent</artifactId>
        <version>1.0.0</version>
    </parent>
    <artifactId>module1</artifactId>
    <properties>
        <module.secret>ModuleSecret456</module.secret>
    </properties>
</project>
"""
        (module_dir / "pom.xml").write_text(module_pom)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should scan both POM files
        assert len(report.scanned_files) == 2

        # Should find secrets in both files
        secret_findings = [f for f in findings if f.category == FindingCategory.SECRETS]
        assert len(secret_findings) >= 2

    def test_malformed_pom(self, analyzer: MavenAnalyzer, temp_dir: Path) -> None:
        """Test handling of malformed POM file."""
        pom_content = """<?xml version="1.0" encoding="UTF-8"?>
<project>
    <invalid XML content
</project>
"""
        pom_file = temp_dir / "pom.xml"
        pom_file.write_text(pom_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should record error but not crash
        assert len(report.scan_errors) == 1
        assert len(findings) == 0

    def test_empty_properties(self, analyzer: MavenAnalyzer, temp_dir: Path) -> None:
        """Test handling of empty properties."""
        pom_content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test-project</artifactId>
    <version>1.0.0</version>
    <properties>
        <empty.property></empty.property>
        <whitespace.property>   </whitespace.property>
    </properties>
</project>
"""
        pom_file = temp_dir / "pom.xml"
        pom_file.write_text(pom_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should not crash and should not flag empty properties
        secret_findings = [f for f in findings if f.category == FindingCategory.SECRETS]
        assert len(secret_findings) == 0
