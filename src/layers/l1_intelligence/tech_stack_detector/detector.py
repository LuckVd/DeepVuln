"""Tech stack detector for identifying project technologies."""

import json
import re
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from src.core.logger.logger import get_logger


class Language(str, Enum):
    """Programming languages."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    GO = "go"
    RUST = "rust"
    PHP = "php"
    RUBY = "ruby"
    CSHARP = "csharp"
    CPP = "cpp"
    KOTLIN = "kotlin"
    SWIFT = "swift"


class Framework(BaseModel):
    """Detected framework."""

    name: str
    category: str  # web, mobile, desktop, testing, etc.
    version: str | None = None
    confidence: float = 1.0
    source_file: str | None = None


class Database(BaseModel):
    """Detected database."""

    name: str
    category: str  # relational, nosql, cache, etc.
    confidence: float = 1.0


class Middleware(BaseModel):
    """Detected middleware/service."""

    name: str
    category: str  # cache, queue, proxy, etc.
    confidence: float = 1.0


class TechStack(BaseModel):
    """Detected technology stack."""

    languages: list[Language] = Field(default_factory=list)
    frameworks: list[Framework] = Field(default_factory=list)
    databases: list[Database] = Field(default_factory=list)
    middleware: list[Middleware] = Field(default_factory=list)

    # Additional info
    build_tools: list[str] = Field(default_factory=list)
    package_managers: list[str] = Field(default_factory=list)
    ci_cd: list[str] = Field(default_factory=list)

    # Metadata
    confidence: float = Field(default=1.0, description="Overall detection confidence")
    source_path: str | None = None

    def get_all_keywords(self) -> list[str]:
        """Get all searchable keywords for CVE lookup.

        Returns:
            List of keywords.
        """
        keywords = []

        # Add frameworks
        for fw in self.frameworks:
            keywords.append(fw.name)
            if fw.version:
                keywords.append(f"{fw.name} {fw.version}")

        # Add databases
        for db in self.databases:
            keywords.append(db.name)

        # Add middleware
        for mw in self.middleware:
            keywords.append(mw.name)

        return list(set(keywords))


class TechStackDetector:
    """Detector for project technology stack."""

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

    def detect(self, source_path: Path) -> TechStack:
        """Detect technology stack from source code.

        Args:
            source_path: Path to the source code.

        Returns:
            Detected technology stack.
        """
        stack = TechStack(source_path=str(source_path))

        self.logger.info(f"Detecting tech stack in {source_path}")

        # Detect languages
        stack.languages = self._detect_languages(source_path)

        # Detect frameworks
        stack.frameworks = self._detect_frameworks(source_path)

        # Detect databases
        stack.databases = self._detect_databases(source_path)

        # Detect middleware
        stack.middleware = self._detect_middleware(source_path)

        # Detect build tools and package managers
        stack.build_tools = self._detect_build_tools(source_path)
        stack.package_managers = self._detect_package_managers(source_path)

        # Detect CI/CD
        stack.ci_cd = self._detect_cicd(source_path)

        self.logger.info(
            f"Detected: {len(stack.languages)} languages, "
            f"{len(stack.frameworks)} frameworks, "
            f"{len(stack.databases)} databases"
        )

        return stack

    def _detect_languages(self, source_path: Path) -> list[Language]:
        """Detect programming languages.

        Args:
            source_path: Path to the source code.

        Returns:
            List of detected languages.
        """
        languages: set[Language] = set()

        # File extension mapping
        extension_map: dict[str, Language] = {
            ".py": Language.PYTHON,
            ".js": Language.JAVASCRIPT,
            ".ts": Language.TYPESCRIPT,
            ".jsx": Language.JAVASCRIPT,
            ".tsx": Language.TYPESCRIPT,
            ".java": Language.JAVA,
            ".go": Language.GO,
            ".rs": Language.RUST,
            ".php": Language.PHP,
            ".rb": Language.RUBY,
            ".cs": Language.CSHARP,
            ".cpp": Language.CPP,
            ".c": Language.CPP,
            ".kt": Language.KOTLIN,
            ".swift": Language.SWIFT,
        }

        # Check for key files first
        key_files: dict[str, Language] = {
            "package.json": Language.JAVASCRIPT,
            "tsconfig.json": Language.TYPESCRIPT,
            "requirements.txt": Language.PYTHON,
            "pyproject.toml": Language.PYTHON,
            "Pipfile": Language.PYTHON,
            "pom.xml": Language.JAVA,
            "build.gradle": Language.JAVA,
            "go.mod": Language.GO,
            "Cargo.toml": Language.RUST,
            "composer.json": Language.PHP,
            "Gemfile": Language.RUBY,
        }

        for file_name, lang in key_files.items():
            if (source_path / file_name).exists():
                languages.add(lang)

        # Sample file extensions
        sample_size = 100
        count = 0

        for file_path in source_path.rglob("*"):
            if count >= sample_size:
                break
            if file_path.is_file():
                ext = file_path.suffix.lower()
                if ext in extension_map:
                    languages.add(extension_map[ext])
                    count += 1

        return list(languages)

    def _detect_frameworks(self, source_path: Path) -> list[Framework]:
        """Detect frameworks.

        Args:
            source_path: Path to the source code.

        Returns:
            List of detected frameworks.
        """
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
                    # Directory check
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
        """Detect databases.

        Args:
            source_path: Path to the source code.

        Returns:
            List of detected databases.
        """
        databases: list[Database] = []
        detected: set[str] = set()

        for name, rule in self.DATABASE_RULES.items():
            if name in detected:
                continue

            confidence = 0.0

            # Check dependencies
            deps = rule.get("dependencies", [])
            if deps and self._check_dependencies(source_path, deps):
                confidence += 0.8

            # Check patterns
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
        """Detect middleware/services.

        Args:
            source_path: Path to the source code.

        Returns:
            List of detected middleware.
        """
        middleware: list[Middleware] = []
        detected: set[str] = set()

        for name, rule in self.MIDDLEWARE_RULES.items():
            if name in detected:
                continue

            confidence = 0.0

            # Check files
            for file_pattern in rule.get("files", []):
                if (source_path / file_pattern).exists():
                    confidence += 0.9
                    break

            # Check dependencies
            deps = rule.get("dependencies", [])
            if deps and self._check_dependencies(source_path, deps):
                confidence += 0.8

            # Check patterns
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
        """Detect build tools.

        Args:
            source_path: Path to the source code.

        Returns:
            List of build tools.
        """
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
        """Detect package managers.

        Args:
            source_path: Path to the source code.

        Returns:
            List of package managers.
        """
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

        # Also check for package managers without lock files
        if (source_path / "requirements.txt").exists() and "pipenv" not in managers:
            managers.append("pip")

        return managers

    def _detect_cicd(self, source_path: Path) -> list[str]:
        """Detect CI/CD systems.

        Args:
            source_path: Path to the source code.

        Returns:
            List of CI/CD systems.
        """
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
        """Check if any dependencies are present.

        Args:
            source_path: Path to the source code.
            dep_names: Dependency names to check.

        Returns:
            List of found dependency files.
        """
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
        """Get dependency names from JSON file.

        Args:
            file_path: Path to JSON file.

        Returns:
            List of dependency names.
        """
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
        """Check if patterns exist in configuration files.

        Args:
            source_path: Path to the source code.
            patterns: Regex patterns to check.

        Returns:
            True if any pattern is found.
        """
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
