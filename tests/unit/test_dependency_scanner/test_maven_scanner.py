"""Unit tests for Maven/Gradle dependency scanner."""

from pathlib import Path

from src.layers.l1_intelligence.dependency_scanner.base_scanner import Ecosystem
from src.layers.l1_intelligence.dependency_scanner.maven_scanner import MavenScanner


class TestMavenScanner:
    """Tests for MavenScanner."""

    def test_ecosystem(self) -> None:
        """Test ecosystem is MAVEN."""
        scanner = MavenScanner()
        assert scanner.ecosystem == Ecosystem.MAVEN

    def test_supported_files(self) -> None:
        """Test supported files."""
        scanner = MavenScanner()
        assert "pom.xml" in scanner.supported_files
        assert "build.gradle" in scanner.supported_files
        assert "build.gradle.kts" in scanner.supported_files

    def test_can_scan_pom_xml(self, tmp_path: Path) -> None:
        """Test can_scan for pom.xml."""
        scanner = MavenScanner()
        pom_xml = tmp_path / "pom.xml"
        pom_xml.write_text('<project xmlns="http://maven.apache.org/POM/4.0.0"></project>')
        assert scanner.can_scan(pom_xml)

    def test_can_scan_build_gradle(self, tmp_path: Path) -> None:
        """Test can_scan for build.gradle."""
        scanner = MavenScanner()
        build_gradle = tmp_path / "build.gradle"
        build_gradle.write_text("dependencies { }")
        assert scanner.can_scan(build_gradle)

    def test_can_scan_build_gradle_kts(self, tmp_path: Path) -> None:
        """Test can_scan for build.gradle.kts."""
        scanner = MavenScanner()
        build_gradle_kts = tmp_path / "build.gradle.kts"
        build_gradle_kts.write_text("dependencies { }")
        assert scanner.can_scan(build_gradle_kts)

    def test_scan_empty_directory(self, tmp_path: Path) -> None:
        """Test scan on empty directory."""
        scanner = MavenScanner()
        deps = scanner.scan(tmp_path)
        assert deps == []

    def test_scan_no_java_files(self, tmp_path: Path) -> None:
        """Test scan with no Java files."""
        scanner = MavenScanner()
        (tmp_path / "README.md").write_text("# Test")
        deps = scanner.scan(tmp_path)
        assert deps == []

    def test_scan_simple_pom_xml(self, tmp_path: Path) -> None:
        """Test scan with simple pom.xml."""
        scanner = MavenScanner()
        pom_xml = tmp_path / "pom.xml"
        pom_xml.write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test-app</artifactId>
    <version>1.0.0</version>

    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.0</version>
        </dependency>
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-lang3</artifactId>
            <version>3.12.0</version>
        </dependency>
    </dependencies>
</project>
"""
        )

        deps = scanner.scan(tmp_path)
        assert len(deps) == 2

        # Check spring-core dependency
        spring_dep = next((d for d in deps if "spring-core" in d.name), None)
        assert spring_dep is not None
        assert spring_dep.version == "5.3.0"
        assert spring_dep.ecosystem == Ecosystem.MAVEN
        assert spring_dep.is_direct is True
        assert spring_dep.is_dev is False

    def test_scan_pom_xml_with_scope(self, tmp_path: Path) -> None:
        """Test scan with scope in pom.xml dependencies."""
        scanner = MavenScanner()
        pom_xml = tmp_path / "pom.xml"
        pom_xml.write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>

    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.0</version>
            <scope>compile</scope>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
"""
        )

        deps = scanner.scan(tmp_path)
        assert len(deps) == 2

        # Check test dependency is marked as dev
        junit_dep = next((d for d in deps if "junit" in d.name), None)
        assert junit_dep is not None
        assert junit_dep.is_dev is True

    def test_scan_pom_xml_with_optional(self, tmp_path: Path) -> None:
        """Test scan with optional dependencies."""
        scanner = MavenScanner()
        pom_xml = tmp_path / "pom.xml"
        pom_xml.write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>

    <dependencies>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <version>1.18.20</version>
            <optional>true</optional>
        </dependency>
        <dependency>
            <groupId>javax.servlet</groupId>
            <artifactId>servlet-api</artifactId>
            <version>4.0.1</version>
            <scope>provided</scope>
        </dependency>
    </dependencies>
</project>
"""
        )

        deps = scanner.scan(tmp_path)
        assert len(deps) == 2

        # Check optional dependency
        lombok_dep = next((d for d in deps if "lombok" in d.name), None)
        assert lombok_dep is not None
        assert lombok_dep.is_optional is True

        # Check provided scope is optional
        servlet_dep = next((d for d in deps if "servlet-api" in d.name), None)
        assert servlet_dep is not None
        assert servlet_dep.is_optional is True

    def test_scan_pom_xml_with_properties(self, tmp_path: Path) -> None:
        """Test scan with property substitution."""
        scanner = MavenScanner()
        pom_xml = tmp_path / "pom.xml"
        pom_xml.write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>

    <properties>
        <spring.version>5.3.20</spring.version>
        <junit.version>4.13.2</junit.version>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>${spring.version}</version>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>${junit.version}</version>
        </dependency>
    </dependencies>
</project>
"""
        )

        deps = scanner.scan(tmp_path)
        assert len(deps) == 2

        # Check version substitution
        spring_dep = next((d for d in deps if "spring-core" in d.name), None)
        assert spring_dep is not None
        assert spring_dep.version == "5.3.20"

        junit_dep = next((d for d in deps if "junit" in d.name), None)
        assert junit_dep is not None
        assert junit_dep.version == "4.13.2"

    def test_scan_build_gradle(self, tmp_path: Path) -> None:
        """Test scan with build.gradle."""
        scanner = MavenScanner()
        build_gradle = tmp_path / "build.gradle"
        build_gradle.write_text(
            """
plugins {
    id 'java'
}

repositories {
    mavenCentral()
}

dependencies {
    implementation 'org.springframework:spring-core:5.3.0'
    implementation 'org.apache.commons:commons-lang3:3.12.0'
    testImplementation 'junit:junit:4.13.2'
    compileOnly 'org.projectlombok:lombok:1.18.20'
}
"""
        )

        deps = scanner.scan(tmp_path)
        assert len(deps) == 4

        # Check regular dependency
        spring_dep = next((d for d in deps if "spring-core" in d.name), None)
        assert spring_dep is not None
        assert spring_dep.version == "5.3.0"
        assert spring_dep.is_dev is False
        assert spring_dep.is_optional is False

        # Check test dependency
        junit_dep = next((d for d in deps if "junit" in d.name), None)
        assert junit_dep is not None
        assert junit_dep.is_dev is True

        # Check compileOnly dependency
        lombok_dep = next((d for d in deps if "lombok" in d.name), None)
        assert lombok_dep is not None
        assert lombok_dep.is_optional is True

    def test_scan_build_gradle_kts(self, tmp_path: Path) -> None:
        """Test scan with build.gradle.kts (Kotlin DSL)."""
        scanner = MavenScanner()
        build_gradle_kts = tmp_path / "build.gradle.kts"
        build_gradle_kts.write_text(
            """
plugins {
    java
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.springframework:spring-core:5.3.0")
    implementation("org.apache.commons:commons-lang3:3.12.0")
    testImplementation("junit:junit:4.13.2")
    compileOnly("org.projectlombok:lombok:1.18.20")
}
"""
        )

        deps = scanner.scan(tmp_path)
        assert len(deps) == 4

        # Check regular dependency
        spring_dep = next((d for d in deps if "spring-core" in d.name), None)
        assert spring_dep is not None
        assert spring_dep.version == "5.3.0"

        # Check test dependency
        junit_dep = next((d for d in deps if "junit" in d.name), None)
        assert junit_dep is not None
        assert junit_dep.is_dev is True

    def test_scan_build_gradle_kts_named_params(self, tmp_path: Path) -> None:
        """Test scan with build.gradle.kts named parameters."""
        scanner = MavenScanner()
        build_gradle_kts = tmp_path / "build.gradle.kts"
        build_gradle_kts.write_text(
            """
dependencies {
    implementation(group = "org.springframework", name = "spring-core", version = "5.3.0")
}
"""
        )

        deps = scanner.scan(tmp_path)
        assert len(deps) == 1

        spring_dep = deps[0]
        assert spring_dep.name == "org.springframework:spring-core"
        assert spring_dep.version == "5.3.0"

    def test_scan_nested_pom_xml(self, tmp_path: Path) -> None:
        """Test scan with nested pom.xml files (multi-module)."""
        scanner = MavenScanner()

        # Root pom.xml
        root_pom = tmp_path / "pom.xml"
        root_pom.write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
    <packaging>pom</packaging>

    <dependencies>
        <dependency>
            <groupId>org.slf4j</groupId>
            <artifactId>slf4j-api</artifactId>
            <version>1.7.36</version>
        </dependency>
    </dependencies>
</project>
"""
        )

        # Submodule pom.xml
        subdir = tmp_path / "module1"
        subdir.mkdir()
        module_pom = subdir / "pom.xml"
        module_pom.write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>com.example</groupId>
        <artifactId>parent</artifactId>
        <version>1.0.0</version>
    </parent>

    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.0</version>
        </dependency>
    </dependencies>
</project>
"""
        )

        deps = scanner.scan(tmp_path)
        # Should find dependencies from both modules
        assert len(deps) == 2

    def test_scan_skip_target(self, tmp_path: Path) -> None:
        """Test that target directory is skipped."""
        scanner = MavenScanner()

        # Root pom.xml (empty dependencies)
        root_pom = tmp_path / "pom.xml"
        root_pom.write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
</project>
"""
        )

        # Target directory pom.xml (should be skipped)
        target_dir = tmp_path / "target"
        target_dir.mkdir()
        target_pom = target_dir / "pom.xml"
        target_pom.write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>com.example</groupId>
            <artifactId>should-be-skipped</artifactId>
            <version>1.0.0</version>
        </dependency>
    </dependencies>
</project>
"""
        )

        deps = scanner.scan(tmp_path)
        # Should not find the dependency in target
        assert len(deps) == 0

    def test_scan_gradle_with_comments(self, tmp_path: Path) -> None:
        """Test parsing build.gradle with comments."""
        scanner = MavenScanner()
        build_gradle = tmp_path / "build.gradle"
        build_gradle.write_text(
            """
dependencies {
    // This is a comment
    implementation 'org.springframework:spring-core:5.3.0' // inline comment
    /* multi-line
       comment */
    implementation 'org.apache.commons:commons-lang3:3.12.0'
}
"""
        )

        deps = scanner.scan(tmp_path)
        assert len(deps) == 2

    def test_scan_mixed_project(self, tmp_path: Path) -> None:
        """Test scanning project with both pom.xml and build.gradle."""
        scanner = MavenScanner()

        pom_xml = tmp_path / "pom.xml"
        pom_xml.write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.0</version>
        </dependency>
    </dependencies>
</project>
"""
        )

        gradle_dir = tmp_path / "gradle-subproject"
        gradle_dir.mkdir()
        build_gradle = gradle_dir / "build.gradle"
        build_gradle.write_text(
            """
dependencies {
    implementation 'org.apache.commons:commons-lang3:3.12.0'
}
"""
        )

        deps = scanner.scan(tmp_path)
        assert len(deps) == 2

    def test_scan_realistic_pom_xml(self, tmp_path: Path) -> None:
        """Test scanning a realistic pom.xml similar to Dubbo."""
        scanner = MavenScanner()
        pom_xml = tmp_path / "pom.xml"
        pom_xml.write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>org.apache.dubbo</groupId>
    <artifactId>dubbo</artifactId>
    <version>3.2.0</version>
    <packaging>pom</packaging>

    <properties>
        <spring.version>5.3.25</spring.version>
        <netty.version>4.1.92.Final</netty.version>
        <javassist.version>3.29.2-GA</javassist.version>
        <zookeeper.version>3.8.1</zookeeper.version>
        <curator.version>5.4.0</curator.version>
    </properties>

    <dependencies>
        <!-- Spring Framework -->
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-context</artifactId>
            <version>${spring.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-web</artifactId>
            <version>${spring.version}</version>
        </dependency>

        <!-- Netty -->
        <dependency>
            <groupId>io.netty</groupId>
            <artifactId>netty-all</artifactId>
            <version>${netty.version}</version>
        </dependency>

        <!-- Javassist -->
        <dependency>
            <groupId>org.javassist</groupId>
            <artifactId>javassist</artifactId>
            <version>${javassist.version}</version>
        </dependency>

        <!-- Test dependencies -->
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.mockito</groupId>
            <artifactId>mockito-core</artifactId>
            <version>4.11.0</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
"""
        )

        deps = scanner.scan(tmp_path)

        # Should have 6 dependencies
        assert len(deps) == 6

        # Check spring-context with property substitution
        spring_context = next((d for d in deps if "spring-context" in d.name), None)
        assert spring_context is not None
        assert spring_context.version == "5.3.25"

        # Check netty
        netty_dep = next((d for d in deps if "netty-all" in d.name), None)
        assert netty_dep is not None
        assert netty_dep.version == "4.1.92.Final"

        # Check test dependencies
        test_deps = [d for d in deps if d.is_dev]
        assert len(test_deps) == 2

    def test_scan_dependency_without_version(self, tmp_path: Path) -> None:
        """Test scanning dependency without version (managed by parent)."""
        scanner = MavenScanner()
        pom_xml = tmp_path / "pom.xml"
        pom_xml.write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <!-- version managed by parent -->
        </dependency>
    </dependencies>
</project>
"""
        )

        deps = scanner.scan(tmp_path)
        # Should still include the dependency with version "*"
        assert len(deps) == 1
        assert deps[0].version == "*"

    def test_scan_empty_dependencies(self, tmp_path: Path) -> None:
        """Test scanning pom.xml with no dependencies."""
        scanner = MavenScanner()
        pom_xml = tmp_path / "pom.xml"
        pom_xml.write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
</project>
"""
        )

        deps = scanner.scan(tmp_path)
        assert deps == []

    def test_scan_malformed_pom_xml(self, tmp_path: Path) -> None:
        """Test scanning malformed pom.xml."""
        scanner = MavenScanner()
        pom_xml = tmp_path / "pom.xml"
        pom_xml.write_text("<invalid><xml>")

        deps = scanner.scan(tmp_path)
        # Should handle gracefully and return empty list
        assert deps == []
