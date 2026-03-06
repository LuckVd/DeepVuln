"""
Tech stack detector for identifying project technologies.

This module provides comprehensive technology stack detection including:
- Full project scanning (no sampling)
- Primary/secondary language classification
- LOC statistics
- Project type identification
- Test/documentation detection
- Monorepo detection
"""

import json
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger

from .models import (
    DOC_DIRECTORIES,
    DOC_FILE_PATTERNS,
    EXTENSION_TO_LANGUAGE,
    PACKAGE_FILES,
    SKIP_DIRECTORIES,
    TEST_DIRECTORIES,
    TEST_FILE_PATTERNS,
    Database,
    Framework,
    Language,
    LanguageInfo,
    Middleware,
    ProjectType,
    TechStack,
)


class TechStackDetector:
    """
    Detector for project technology stack.

    Performs comprehensive analysis including:
    - Full project file scanning
    - LOC statistics per language
    - Primary/secondary language classification
    - Project type detection
    - Test/documentation presence detection
    - Monorepo detection
    """

    # Framework detection rules
    FRAMEWORK_RULES: dict[str, dict[str, Any]] = {
        # Python frameworks
        "django": {
            "files": ["settings.py", "manage.py"],
            "dependencies": ["django"],
            "category": "web",
        },
        "flask": {
            "files": ["app.py"],
            "dependencies": ["flask"],
            "category": "web",
        },
        "fastapi": {
            "files": [],
            "dependencies": ["fastapi"],
            "category": "web",
        },
        "tornado": {
            "files": [],
            "dependencies": ["tornado"],
            "category": "web",
        },
        "pyramid": {
            "files": [],
            "dependencies": ["pyramid"],
            "category": "web",
        },
        "celery": {
            "files": ["celery.py"],
            "dependencies": ["celery"],
            "category": "task-queue",
        },
        "sqlalchemy": {
            "files": [],
            "dependencies": ["sqlalchemy"],
            "category": "orm",
        },
        "click": {
            "files": [],
            "dependencies": ["click"],
            "category": "cli",
        },
        "argparse": {
            "files": [],
            "dependencies": [],
            "patterns": [r"import argparse"],
            "category": "cli",
        },
        # JavaScript/TypeScript frameworks
        "react": {
            "files": [],
            "dependencies": ["react"],
            "category": "frontend",
        },
        "vue": {
            "files": [],
            "dependencies": ["vue"],
            "category": "frontend",
        },
        "angular": {
            "files": ["angular.json"],
            "dependencies": ["@angular/core"],
            "category": "frontend",
        },
        "express": {
            "files": [],
            "dependencies": ["express"],
            "category": "web",
        },
        "next.js": {
            "files": ["next.config.js", "next.config.mjs"],
            "dependencies": ["next"],
            "category": "web",
        },
        "nestjs": {
            "files": ["nest-cli.json"],
            "dependencies": ["@nestjs/core"],
            "category": "web",
        },
        "fastify": {
            "files": [],
            "dependencies": ["fastify"],
            "category": "web",
        },
        "koa": {
            "files": [],
            "dependencies": ["koa"],
            "category": "web",
        },
        # Java frameworks
        "spring": {
            "files": ["pom.xml", "build.gradle"],
            "dependencies": ["springframework", "spring-boot"],
            "patterns": [r"org\.springframework"],
            "category": "web",
        },
        "spring-boot": {
            "files": ["pom.xml", "build.gradle"],
            "dependencies": ["spring-boot"],
            "category": "web",
        },
        "struts": {
            "files": ["pom.xml"],
            "dependencies": ["struts"],
            "category": "web",
        },
        "hibernate": {
            "files": ["pom.xml"],
            "dependencies": ["hibernate"],
            "category": "orm",
        },
        # Go frameworks
        "gin": {
            "files": [],
            "dependencies": ["gin-gonic"],
            "category": "web",
        },
        "echo": {
            "files": [],
            "dependencies": ["echo"],
            "category": "web",
        },
        "fiber": {
            "files": [],
            "dependencies": ["fiber"],
            "category": "web",
        },
        "hertz": {
            "files": [],
            "dependencies": ["hertz", "cloudwego/hertz"],
            "category": "web",
        },
        "cobra": {
            "files": [],
            "dependencies": ["cobra"],
            "category": "cli",
        },
        # PHP frameworks
        "laravel": {
            "files": ["artisan", "config/app.php"],
            "dependencies": ["laravel"],
            "category": "web",
        },
        "symfony": {
            "files": ["symfony.lock", "config/bundles.php"],
            "dependencies": ["symfony"],
            "category": "web",
        },
        # Ruby frameworks
        "rails": {
            "files": ["Gemfile", "config/application.rb"],
            "dependencies": ["rails"],
            "category": "web",
        },
    }

    # Database detection rules
    DATABASE_RULES: dict[str, dict[str, Any]] = {
        "mysql": {
            "dependencies": ["mysql", "mysql-connector", "pymysql", "mysql2"],
            "patterns": [r"mysql://", r"jdbc:mysql:"],
        },
        "postgresql": {
            "dependencies": ["psycopg", "pg", "postgresql", "postgres"],
            "patterns": [r"postgresql://", r"postgres://", r"jdbc:postgresql:"],
        },
        "mongodb": {
            "dependencies": ["mongodb", "mongoose", "pymongo", "mongoengine"],
            "patterns": [r"mongodb://", r"mongodb\+srv://"],
        },
        "redis": {
            "dependencies": ["redis", "aioredis", "ioredis"],
            "patterns": [r"redis://"],
        },
        "elasticsearch": {
            "dependencies": ["elasticsearch", "@elastic/elasticsearch"],
            "patterns": [r"elasticsearch", r"elastic.co"],
        },
        "sqlite": {
            "dependencies": ["sqlite3"],
            "patterns": [r"sqlite:", r"\.db", r"\.sqlite"],
        },
        "mariadb": {
            "dependencies": ["mariadb"],
            "patterns": [r"mariadb"],
        },
    }

    # Middleware/Service detection rules
    MIDDLEWARE_RULES: dict[str, dict[str, Any]] = {
        "kafka": {
            "dependencies": ["kafka-python", "kafkajs", "confluent-kafka"],
            "patterns": [r"kafka://", r"localhost:9092"],
        },
        "rabbitmq": {
            "dependencies": ["pika", "amqplib", "rabbitmq"],
            "patterns": [r"amqp://", r"rabbitmq"],
        },
        "nginx": {
            "files": ["nginx.conf", "default.conf"],
            "patterns": [],
        },
        "docker": {
            "files": ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
            "patterns": [],
        },
        "kubernetes": {
            "files": ["deployment.yaml", "k8s/", "kubernetes/"],
            "patterns": [],
        },
    }

    def __init__(self) -> None:
        """Initialize the detector."""
        self.logger = get_logger(__name__)
        self._scan_stats: dict[str, Any] = {}

    def detect(self, source_path: Path) -> TechStack:
        """
        Detect technology stack from source code.

        Performs full project scan without sampling.

        Args:
            source_path: Path to the source code.

        Returns:
            Detected technology stack with comprehensive project profile.
        """
        start_time = time.time()
        self.logger.info(f"Starting full tech stack detection in {source_path}")

        stack = TechStack(source_path=str(source_path))

        # Step 1: Full file scan with statistics
        language_stats, project_stats = self._scan_project_files(source_path)

        # Step 2: Build LanguageInfo list with LOC statistics
        stack.languages = self._build_language_info(language_stats, project_stats)

        # Step 3: Determine primary and secondary languages
        stack.total_loc = project_stats["total_loc"]
        stack.total_files = project_stats["total_source_files"]
        self._classify_languages(stack)

        # Step 4: Detect project characteristics
        stack.has_tests = project_stats["has_tests"]
        stack.has_docs = project_stats["has_docs"]
        stack.is_monorepo = project_stats["is_monorepo"]

        # Step 5: Detect project type
        stack.project_type = self._detect_project_type(source_path, stack, language_stats)

        # Step 6: Detect frameworks, databases, middleware
        stack.frameworks = self._detect_frameworks(source_path)
        stack.databases = self._detect_databases(source_path)
        stack.middleware = self._detect_middleware(source_path)

        # Step 7: Detect build tools and package managers
        stack.build_tools = self._detect_build_tools(source_path)
        stack.package_managers = self._detect_package_managers(source_path)
        stack.ci_cd = self._detect_cicd(source_path)

        # Store scan statistics
        scan_duration = time.time() - start_time
        self._scan_stats = {
            "duration_seconds": round(scan_duration, 2),
            "files_scanned": project_stats["total_files_scanned"],
            "directories_scanned": project_stats["directories_scanned"],
            "source_files": project_stats["total_source_files"],
            "total_loc": project_stats["total_loc"],
        }

        self.logger.info(
            f"Tech stack detection completed in {scan_duration:.2f}s: "
            f"primary={stack.primary_language}, "
            f"loc={stack.total_loc:,}, "
            f"files={stack.total_files}, "
            f"type={stack.project_type}"
        )

        return stack

    def _scan_project_files(
        self, source_path: Path
    ) -> tuple[dict[Language, dict[str, int]], dict[str, Any]]:
        """
        Perform full project file scan.

        Returns:
            Tuple of (language_stats, project_stats)
        """
        # language_stats: {Language: {"file_count": N, "line_count": N, "test_file_count": N, "doc_file_count": N}}
        language_stats: dict[Language, dict[str, int]] = defaultdict(
            lambda: {"file_count": 0, "line_count": 0, "test_file_count": 0, "doc_file_count": 0}
        )

        project_stats = {
            "total_files_scanned": 0,
            "directories_scanned": 0,
            "total_source_files": 0,
            "total_loc": 0,
            "has_tests": False,
            "has_docs": False,
            "is_monorepo": False,
            "package_file_count": defaultdict(int),
        }

        visited_dirs: set[str] = set()

        for file_path in source_path.rglob("*"):
            # Skip if not a file
            if not file_path.is_file():
                continue

            # Check if we should skip this path
            if self._should_skip_path(file_path, source_path):
                continue

            project_stats["total_files_scanned"] += 1

            # Track directory
            parent_dir = str(file_path.parent.relative_to(source_path))
            if parent_dir not in visited_dirs:
                visited_dirs.add(parent_dir)
                project_stats["directories_scanned"] += 1

            # Check for package files (monorepo detection)
            file_name = file_path.name
            if file_name in PACKAGE_FILES:
                project_stats["package_file_count"][file_name] += 1

            # Check for documentation
            if self._is_doc_file(file_path, source_path):
                project_stats["has_docs"] = True

            # Check extension for source code
            ext = file_path.suffix.lower()

            if ext not in EXTENSION_TO_LANGUAGE:
                continue

            language = EXTENSION_TO_LANGUAGE[ext]
            project_stats["total_source_files"] += 1

            # Check if test file
            is_test = self._is_test_file(file_path, source_path)
            if is_test:
                project_stats["has_tests"] = True
                language_stats[language]["test_file_count"] += 1

            # Count lines
            try:
                line_count = self._count_lines(file_path)
                language_stats[language]["file_count"] += 1
                language_stats[language]["line_count"] += line_count
                project_stats["total_loc"] += line_count

                if not is_test:
                    # Non-test source files contribute to main stats
                    pass
            except Exception as e:
                self.logger.debug(f"Could not read file {file_path}: {e}")

        # Determine monorepo status
        total_package_files = sum(project_stats["package_file_count"].values())
        unique_package_types = len(project_stats["package_file_count"])
        # Monorepo if multiple package.json/setup.py/etc OR multiple of same type
        project_stats["is_monorepo"] = (
            total_package_files > 3 or  # Many package files
            unique_package_types > 2 or  # Multiple package types
            any(count > 1 for count in project_stats["package_file_count"].values())
        )

        return dict(language_stats), project_stats

    def _should_skip_path(self, file_path: Path, source_path: Path) -> bool:
        """Check if a path should be skipped during scanning."""
        try:
            relative_path = file_path.relative_to(source_path)
            # Check each part of the relative path against skip directories
            for part in relative_path.parts:
                if part in SKIP_DIRECTORIES:
                    return True
                # Skip hidden directories (except .github which has CI config)
                if part.startswith(".") and part not in {".github", ".gitlab"}:
                    return True
            return False
        except ValueError:
            return True

    def _is_test_file(self, file_path: Path, source_path: Path) -> bool:
        """Check if a file is a test file."""
        # Check directory
        try:
            relative_path = file_path.relative_to(source_path)
            for part in relative_path.parts[:-1]:  # Exclude filename
                if part.lower() in TEST_DIRECTORIES:
                    return True
        except ValueError:
            pass

        # Check filename patterns
        file_name = file_path.name.lower()
        for pattern in TEST_FILE_PATTERNS:
            if pattern.lower() in file_name:
                return True

        return False

    def _is_doc_file(self, file_path: Path, source_path: Path) -> bool:
        """Check if a file is a documentation file."""
        # Check directory
        try:
            relative_path = file_path.relative_to(source_path)
            for part in relative_path.parts[:-1]:
                if part.lower() in DOC_DIRECTORIES:
                    return True
        except ValueError:
            pass

        # Check extension
        ext = file_path.suffix.lower()
        if ext in DOC_FILE_PATTERNS:
            return True

        # Check specific doc files
        file_name = file_path.name.lower()
        if file_name in {"readme.md", "readme.txt", "changelog.md", "license", "license.md"}:
            return True

        return False

    def _count_lines(self, file_path: Path) -> int:
        """Count non-empty lines in a file."""
        try:
            with open(file_path, encoding="utf-8", errors="replace") as f:
                count = 0
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):  # Non-empty, non-comment
                        count += 1
                return count
        except Exception:
            return 0

    def _build_language_info(
        self,
        language_stats: dict[Language, dict[str, int]],
        project_stats: dict[str, Any],
    ) -> list[LanguageInfo]:
        """Build list of LanguageInfo from statistics."""
        total_loc = project_stats["total_loc"]
        if total_loc == 0:
            total_loc = 1  # Avoid division by zero

        language_infos = []
        for language, stats in language_stats.items():
            if stats["file_count"] == 0:
                continue

            loc_percentage = (stats["line_count"] / total_loc) * 100

            info = LanguageInfo(
                language=language,
                file_count=stats["file_count"],
                line_count=stats["line_count"],
                test_file_count=stats["test_file_count"],
                doc_file_count=0,  # Doc files are not per-language
                role="secondary",  # Will be updated in _classify_languages
                loc_percentage=round(loc_percentage, 2),
            )
            language_infos.append(info)

        return language_infos

    def _classify_languages(self, stack: TechStack) -> None:
        """
        Classify languages as primary or secondary.

        Rules:
        - primary_language: Maximum LOC
        - secondary_languages: LOC percentage > 10%
        - Ignore languages with LOC percentage < 5%
        """
        if not stack.languages:
            return

        total_loc = stack.total_loc if stack.total_loc > 0 else 1

        # Sort by line count descending
        sorted_languages = sorted(
            stack.languages,
            key=lambda x: x.line_count,
            reverse=True,
        )

        # Filter out languages with < 5% LOC
        filtered_languages = [
            info for info in sorted_languages
            if info.loc_percentage >= 5.0 or info == sorted_languages[0]  # Keep primary even if < 5%
        ]

        # Update the list
        stack.languages = filtered_languages

        if not filtered_languages:
            return

        # Set primary language (highest LOC)
        primary_info = filtered_languages[0]
        primary_info.role = "primary"
        stack.primary_language = primary_info.language

        # Set secondary languages (> 10% LOC, excluding primary)
        secondary = []
        for info in filtered_languages[1:]:
            if info.loc_percentage >= 10.0:
                info.role = "secondary"
                secondary.append(info.language)

        stack.secondary_languages = secondary

    def _detect_project_type(
        self,
        source_path: Path,
        stack: TechStack,
        language_stats: dict[Language, dict[str, int]],
    ) -> ProjectType:
        """
        Detect the project type using heuristic rules.

        Types:
        - web: Web application (Flask, Django, Express, etc.)
        - api: API service (HTTP routes but no frontend)
        - cli: Command-line tool (argparse, click, no HTTP)
        - library: Library/package (no obvious entry point)
        - unknown: Cannot determine
        """
        # Check frameworks first
        web_frameworks = {"django", "flask", "fastapi", "express", "next.js", "nestjs", "spring", "spring-boot", "gin", "echo", "rails", "laravel"}
        cli_frameworks = {"click", "cobra", "argparse"}

        detected_web = False
        detected_cli = False

        for fw in stack.frameworks:
            fw_name = fw.name.lower()
            if fw_name in web_frameworks:
                detected_web = True
            if fw_name in cli_frameworks:
                detected_cli = True

        # Check for HTTP patterns in code
        if not detected_web:
            http_patterns = [
                r"@app\.route",
                r"@router\.",
                r"app\.listen",
                r"express\(\)",
                r"app\s*=\s*flask",
                r"@GetMapping|@PostMapping|@RequestMapping",
                r"func\s+main\(\).*http",
            ]
            if self._check_patterns_in_source(source_path, http_patterns):
                detected_web = True

        # Check for CLI patterns
        if not detected_cli:
            cli_patterns = [
                r"if\s+__name__\s*==\s*['\"]__main__['\"]",
                r"argparse\.ArgumentParser",
                r"@click\.command",
                r"func\s+main\(\)",
            ]
            if self._check_patterns_in_source(source_path, cli_patterns):
                detected_cli = True

        # Decision logic
        if detected_web:
            # Check if it's API-only (no frontend templates)
            has_templates = self._has_frontend_templates(source_path)
            if has_templates:
                return ProjectType.WEB
            else:
                return ProjectType.API

        if detected_cli:
            return ProjectType.CLI

        # Check for library indicators
        if self._is_library(source_path, stack):
            return ProjectType.LIBRARY

        return ProjectType.UNKNOWN

    def _check_patterns_in_source(self, source_path: Path, patterns: list[str]) -> bool:
        """Check if any patterns exist in source files."""
        # Limit search to avoid performance issues
        max_files = 50
        checked = 0

        for ext in [".py", ".js", ".ts", ".go", ".java", ".rb", ".php"]:
            for file_path in source_path.rglob(f"*{ext}"):
                if checked >= max_files:
                    break
                if self._should_skip_path(file_path, source_path):
                    continue
                try:
                    content = file_path.read_text(encoding="utf-8", errors="replace")
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            return True
                    checked += 1
                except Exception:
                    continue
            if checked >= max_files:
                break

        return False

    def _has_frontend_templates(self, source_path: Path) -> bool:
        """Check if project has frontend templates."""
        template_patterns = [
            "templates/**/*.html",
            "static/**/*.css",
            "views/**/*.ejs",
            "pages/**/*.tsx",
            "src/**/*.vue",
            "resources/views/**/*.blade.php",
            "app/views/**/*.erb",
        ]

        for pattern in template_patterns:
            if list(source_path.glob(pattern))[:1]:
                return True

        return False

    def _is_library(self, source_path: Path, stack: TechStack) -> bool:
        """Check if project appears to be a library."""
        # Library indicators:
        # - Has setup.py/pyproject.toml with package config
        # - No main entry point
        # - Has lib/ or src/lib/ structure

        # Check for package configuration
        has_setup = (source_path / "setup.py").exists() or (source_path / "pyproject.toml").exists()
        has_lib = (source_path / "lib").is_dir() or (source_path / "src" / "lib").is_dir()

        # Check for main entry point
        has_main = self._check_patterns_in_source(
            source_path,
            [r"if\s+__name__\s*==\s*['\"]__main__['\"]"]
        )

        if has_setup and not has_main:
            return True
        if has_lib:
            return True

        return False

    def _detect_frameworks(self, source_path: Path) -> list[Framework]:
        """Detect frameworks."""
        frameworks: list[Framework] = []
        detected: set[str] = set()

        for name, rule in self.FRAMEWORK_RULES.items():
            if name in detected:
                continue

            confidence = 0.0
            source_file = None

            # Check files
            for file_pattern in rule.get("files", []):
                if file_pattern.endswith("/"):
                    if (source_path / file_pattern.rstrip("/")).is_dir():
                        confidence += 0.5
                elif (source_path / file_pattern).exists():
                    confidence += 0.7
                    source_file = file_pattern

            # Check dependencies
            deps = rule.get("dependencies", [])
            if deps:
                found_deps = self._check_dependencies(source_path, deps)
                if found_deps:
                    confidence += 0.8
                    source_file = found_deps[0]

            # Check patterns in files
            patterns = rule.get("patterns", [])
            if patterns:
                if self._check_patterns_in_files(source_path, patterns):
                    confidence += 0.3

            if confidence >= 0.5:
                frameworks.append(
                    Framework(
                        name=name,
                        category=rule.get("category", "unknown"),
                        confidence=min(confidence, 1.0),
                        source_file=source_file,
                    )
                )
                detected.add(name)

        return frameworks

    def _detect_databases(self, source_path: Path) -> list[Database]:
        """Detect databases."""
        databases: list[Database] = []
        detected: set[str] = set()

        for name, rule in self.DATABASE_RULES.items():
            if name in detected:
                continue

            confidence = 0.0

            deps = rule.get("dependencies", [])
            if deps and self._check_dependencies(source_path, deps):
                confidence += 0.8

            patterns = rule.get("patterns", [])
            if patterns and self._check_patterns_in_files(source_path, patterns):
                confidence += 0.5

            if confidence >= 0.5:
                category = "nosql" if name in ["mongodb", "redis", "elasticsearch"] else "relational"
                databases.append(
                    Database(
                        name=name,
                        category=category,
                        confidence=min(confidence, 1.0),
                    )
                )
                detected.add(name)

        return databases

    def _detect_middleware(self, source_path: Path) -> list[Middleware]:
        """Detect middleware/services."""
        middleware: list[Middleware] = []
        detected: set[str] = set()

        for name, rule in self.MIDDLEWARE_RULES.items():
            if name in detected:
                continue

            confidence = 0.0

            for file_pattern in rule.get("files", []):
                if (source_path / file_pattern).exists():
                    confidence += 0.9
                    break

            deps = rule.get("dependencies", [])
            if deps and self._check_dependencies(source_path, deps):
                confidence += 0.8

            patterns = rule.get("patterns", [])
            if patterns and self._check_patterns_in_files(source_path, patterns):
                confidence += 0.3

            if confidence >= 0.5:
                category = "containerization" if name in ["docker", "kubernetes"] else "infrastructure"
                middleware.append(
                    Middleware(
                        name=name,
                        category=category,
                        confidence=min(confidence, 1.0),
                    )
                )
                detected.add(name)

        return middleware

    def _detect_build_tools(self, source_path: Path) -> list[str]:
        """Detect build tools."""
        tools: list[str] = []

        build_files = {
            "webpack.config.js": "webpack",
            "vite.config.js": "vite",
            "rollup.config.js": "rollup",
            "tsconfig.json": "typescript",
            "babel.config.js": "babel",
            ".eslintrc.js": "eslint",
            "pytest.ini": "pytest",
            "tox.ini": "tox",
            "Makefile": "make",
            "CMakeLists.txt": "cmake",
            "build.gradle": "gradle",
            "pom.xml": "maven",
        }

        for file_name, tool in build_files.items():
            if (source_path / file_name).exists():
                tools.append(tool)

        return tools

    def _detect_package_managers(self, source_path: Path) -> list[str]:
        """Detect package managers."""
        managers: list[str] = []

        lock_files = {
            "package-lock.json": "npm",
            "yarn.lock": "yarn",
            "pnpm-lock.yaml": "pnpm",
            "Pipfile.lock": "pipenv",
            "poetry.lock": "poetry",
            "go.sum": "go modules",
            "Cargo.lock": "cargo",
            "composer.lock": "composer",
            "Gemfile.lock": "bundler",
        }

        for file_name, manager in lock_files.items():
            if (source_path / file_name).exists():
                managers.append(manager)

        if (source_path / "requirements.txt").exists() and "pipenv" not in managers:
            managers.append("pip")

        return managers

    def _detect_cicd(self, source_path: Path) -> list[str]:
        """Detect CI/CD systems."""
        cicd: list[str] = []

        cicd_files = {
            ".github/workflows": "GitHub Actions",
            ".gitlab-ci.yml": "GitLab CI",
            ".travis.yml": "Travis CI",
            ".circleci/config.yml": "CircleCI",
            "Jenkinsfile": "Jenkins",
            "azure-pipelines.yml": "Azure Pipelines",
            ".cloudbuild.yaml": "Cloud Build",
        }

        for file_pattern, system in cicd_files.items():
            path = source_path / file_pattern
            if path.exists() and (path.is_file() or path.is_dir()):
                cicd.append(system)

        return cicd

    def _check_dependencies(self, source_path: Path, dep_names: list[str]) -> list[str]:
        """Check if any dependencies are present."""
        found: list[str] = []

        # Check package.json
        package_json = source_path / "package.json"
        if package_json.exists():
            deps = self._get_json_deps(package_json)
            for dep in dep_names:
                if dep.lower() in [d.lower() for d in deps]:
                    found.append("package.json")

        # Check requirements.txt
        requirements = source_path / "requirements.txt"
        if requirements.exists():
            content = requirements.read_text(encoding="utf-8").lower()
            for dep in dep_names:
                if dep.lower() in content:
                    found.append("requirements.txt")

        # Check pyproject.toml
        pyproject = source_path / "pyproject.toml"
        if pyproject.exists():
            content = pyproject.read_text(encoding="utf-8").lower()
            for dep in dep_names:
                if dep.lower() in content:
                    found.append("pyproject.toml")

        # Check pom.xml
        pom = source_path / "pom.xml"
        if pom.exists():
            content = pom.read_text(encoding="utf-8").lower()
            for dep in dep_names:
                if dep.lower() in content:
                    found.append("pom.xml")

        # Check go.mod
        go_mod = source_path / "go.mod"
        if go_mod.exists():
            content = go_mod.read_text(encoding="utf-8").lower()
            for dep in dep_names:
                if dep.lower() in content:
                    found.append("go.mod")

        return found

    def _get_json_deps(self, file_path: Path) -> list[str]:
        """Get dependency names from JSON file."""
        try:
            content = file_path.read_text(encoding="utf-8")
            data = json.loads(content)
            deps: list[str] = []
            deps.extend(data.get("dependencies", {}).keys())
            deps.extend(data.get("devDependencies", {}).keys())
            return deps
        except Exception:
            return []

    def _check_patterns_in_files(self, source_path: Path, patterns: list[str]) -> bool:
        """Check if patterns exist in configuration files."""
        config_files = [
            "settings.py",
            "config.py",
            "application.py",
            "config/database.yml",
            "config/database.py",
            ".env",
            "docker-compose.yml",
        ]

        for file_name in config_files:
            file_path = source_path / file_name
            if file_path.exists():
                try:
                    content = file_path.read_text(encoding="utf-8")
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            return True
                except Exception:
                    continue

        return False

    def get_scan_statistics(self) -> dict[str, Any]:
        """Get statistics from the last scan."""
        return self._scan_stats.copy()
