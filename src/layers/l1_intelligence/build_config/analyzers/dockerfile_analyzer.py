"""Dockerfile security analyzer."""

import re
from pathlib import Path

from src.layers.l1_intelligence.build_config.base import BaseConfigAnalyzer
from src.layers.l1_intelligence.build_config.models import (
    BuildConfigReport,
    FindingCategory,
    SecurityFinding,
    SecurityRisk,
)


class DockerfileAnalyzer(BaseConfigAnalyzer):
    """Analyzer for Dockerfile security issues."""

    supported_files = ["Dockerfile", "Dockerfile.*", "*.dockerfile"]
    category_name = "dockerfile"

    # Security rules for Dockerfile analysis
    SECURITY_RULES = [
        {
            "id": "DF001",
            "pattern": re.compile(r"^\s*USER\s+root\s*$", re.IGNORECASE | re.MULTILINE),
            "risk": SecurityRisk.HIGH,
            "title": "Running as root user",
            "description": "Container runs as root user, which increases the impact of potential container escape vulnerabilities.",
            "recommendation": "Create a non-root user and switch to it using USER instruction.",
            "references": ["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user"],
        },
        {
            "id": "DF002",
            "pattern": re.compile(r"^\s*ADD\s+https?://", re.IGNORECASE | re.MULTILINE),
            "risk": SecurityRisk.MEDIUM,
            "title": "Using ADD with remote URL",
            "description": "ADD with remote URLs downloads files without integrity verification.",
            "recommendation": "Use curl/wget with checksum verification, or COPY for local files.",
            "references": ["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy"],
        },
        {
            "id": "DF003",
            "pattern": re.compile(r"^\s*(?:RUN\s+)?apt-get\s+update\s*(?:&&\s*apt-get\s+install)?(?![\s\S]*?rm\s+-rf\s+/var/lib/apt/lists)", re.IGNORECASE | re.MULTILINE),
            "risk": SecurityRisk.LOW,
            "title": "apt-get without cache cleanup",
            "description": "Running apt-get without cleaning cache increases image size.",
            "recommendation": "Add 'rm -rf /var/lib/apt/lists/*' after apt-get install.",
            "references": [],
        },
        {
            "id": "DF004",
            "pattern": re.compile(r"^\s*EXPOSE\s+(?:22|23|21)\b", re.IGNORECASE | re.MULTILINE),
            "risk": SecurityRisk.MEDIUM,
            "title": "Exposing sensitive ports",
            "description": "Exposing SSH (22) or FTP (21/23) ports may indicate unnecessary services.",
            "recommendation": "Remove unnecessary service exposures. Use SSH only when required.",
            "references": [],
        },
        {
            "id": "DF005",
            "pattern": re.compile(r"^\s*ENV\s+.*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)\s*=", re.IGNORECASE | re.MULTILINE),
            "risk": SecurityRisk.HIGH,
            "title": "Sensitive data in ENV",
            "description": "ENV instruction contains potentially sensitive environment variable.",
            "recommendation": "Use Docker secrets, mounted volumes, or external secret management.",
            "references": ["https://docs.docker.com/engine/swarm/secrets/"],
        },
        {
            "id": "DF006",
            "pattern": re.compile(r"^\s*ARG\s+.*(?:PASSWORD|SECRET|TOKEN|KEY)\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE | re.MULTILINE),
            "risk": SecurityRisk.HIGH,
            "title": "Hardcoded secrets in ARG",
            "description": "ARG instruction contains hardcoded sensitive value.",
            "recommendation": "Pass secrets at build time using --build-arg or use BuildKit secrets.",
            "references": ["https://docs.docker.com/develop/develop-images/build_enhancements/"],
        },
        {
            "id": "DF007",
            "pattern": re.compile(r"^\s*RUN\s+.*(?:curl|wget)\s+.*\|\s*(?:sh|bash|zsh)", re.IGNORECASE | re.MULTILINE),
            "risk": SecurityRisk.HIGH,
            "title": "Piping curl to shell",
            "description": "Downloading and executing scripts without verification is dangerous.",
            "recommendation": "Download, verify checksum/signature, then execute separately.",
            "references": ["https://security.stackexchange.com/questions/168868/"],
        },
        {
            "id": "DF008",
            "pattern": re.compile(r"^\s*(?:FROM|RUN)\s+.*:latest\b", re.IGNORECASE | re.MULTILINE),
            "risk": SecurityRisk.LOW,
            "title": "Using latest tag",
            "description": "Using 'latest' tag makes builds non-reproducible and may introduce vulnerabilities.",
            "recommendation": "Pin to specific version tags for reproducibility.",
            "references": ["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"],
        },
        {
            "id": "DF009",
            "pattern": re.compile(r"^\s*COPY\s+.*\.\s+.*\.\s*$", re.IGNORECASE | re.MULTILINE),
            "risk": SecurityRisk.INFO,
            "title": "COPY with current directory",
            "description": "COPY . . may include unnecessary files. Consider using .dockerignore.",
            "recommendation": "Use specific paths or ensure .dockerignore is properly configured.",
            "references": [],
        },
        {
            "id": "DF010",
            "pattern": re.compile(r"^\s*RUN\s+.*chmod\s+(?:-R\s+)?(?:777|a\+rwx)", re.IGNORECASE | re.MULTILINE),
            "risk": SecurityRisk.MEDIUM,
            "title": "Overly permissive chmod",
            "description": "Setting permissions to 777 is overly permissive.",
            "recommendation": "Use least privilege permissions (e.g., 755 for directories, 644 for files).",
            "references": [],
        },
        {
            "id": "DF011",
            "pattern": re.compile(r"^\s*RUN\s+.*(?:apt|yum|apk|dnf)\s+(?:install|update|upgrade)\s*(?!.*--no-cache|.*--no-install-recommends)", re.IGNORECASE | re.MULTILINE),
            "risk": SecurityRisk.INFO,
            "title": "Package install without optimization",
            "description": "Consider using --no-cache (apk) or --no-install-recommends (apt) to reduce image size.",
            "recommendation": "Add appropriate flags to minimize installed packages.",
            "references": [],
        },
        {
            "id": "DF012",
            "pattern": re.compile(r"^\s*HEALTHCHECK\s+NONE", re.IGNORECASE | re.MULTILINE),
            "risk": SecurityRisk.INFO,
            "title": "Healthcheck disabled",
            "description": "HEALTHCHECK NONE disables any inherited health check.",
            "recommendation": "Consider implementing a proper health check for production containers.",
            "references": [],
        },
    ]

    def __init__(self) -> None:
        """Initialize Dockerfile analyzer."""
        super().__init__()

    def analyze(self, source_path: Path, report: BuildConfigReport) -> list[SecurityFinding]:
        """Analyze Dockerfiles for security issues.

        Args:
            source_path: Path to the source code.
            report: Report to add findings to.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        dockerfiles = self._find_dockerfiles(source_path)
        if not dockerfiles:
            return findings

        for dockerfile in dockerfiles:
            report.scanned_files.append(str(dockerfile))
            file_findings = self._analyze_dockerfile(dockerfile)
            findings.extend(file_findings)

        return findings

    def _find_dockerfiles(self, source_path: Path) -> list[Path]:
        """Find all Dockerfiles in the source path.

        Args:
            source_path: Source root path.

        Returns:
            List of Dockerfile paths.
        """
        dockerfiles: list[Path] = []

        # Find exact matches
        for f in source_path.rglob("Dockerfile"):
            if not self._should_skip_path(f):
                dockerfiles.append(f)

        # Find Dockerfile.* patterns
        for f in source_path.rglob("Dockerfile.*"):
            if not self._should_skip_path(f):
                dockerfiles.append(f)

        # Find *.dockerfile patterns
        for f in source_path.rglob("*.dockerfile"):
            if not self._should_skip_path(f):
                dockerfiles.append(f)

        return list(set(dockerfiles))

    def _analyze_dockerfile(self, dockerfile: Path) -> list[SecurityFinding]:
        """Analyze a single Dockerfile.

        Args:
            dockerfile: Path to the Dockerfile.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        content = self._safe_read_file(dockerfile)
        if not content:
            return findings

        source_file = str(dockerfile)

        # Apply each security rule
        for rule in self.SECURITY_RULES:
            for match in rule["pattern"].finditer(content):
                # Get line number
                line_num = content[:match.start()].count("\n") + 1

                findings.append(
                    SecurityFinding(
                        category=FindingCategory.DOCKERFILE,
                        risk_level=rule["risk"],
                        title=rule["title"],
                        description=rule["description"],
                        file_path=source_file,
                        line_start=line_num,
                        evidence=match.group(0).strip()[:100],
                        recommendation=rule["recommendation"],
                        references=rule["references"],
                    )
                )

        # Check for missing USER instruction (only if FROM exists)
        if re.search(r"^\s*FROM\s+", content, re.IGNORECASE | re.MULTILINE):
            if not re.search(r"^\s*USER\s+", content, re.IGNORECASE | re.MULTILINE):
                findings.append(
                    SecurityFinding(
                        category=FindingCategory.DOCKERFILE,
                        risk_level=SecurityRisk.MEDIUM,
                        title="No USER instruction found",
                        description="Dockerfile does not specify a non-root user. Container will run as root by default.",
                        file_path=source_file,
                        recommendation="Add USER instruction to run as non-root user.",
                        references=[
                            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user"
                        ],
                    )
                )

        # Check for missing HEALTHCHECK (only warn, not error)
        if re.search(r"^\s*FROM\s+", content, re.IGNORECASE | re.MULTILINE):
            if not re.search(r"^\s*HEALTHCHECK\s+", content, re.IGNORECASE | re.MULTILINE):
                findings.append(
                    SecurityFinding(
                        category=FindingCategory.DOCKERFILE,
                        risk_level=SecurityRisk.INFO,
                        title="No HEALTHCHECK instruction",
                        description="Consider adding a HEALTHCHECK instruction for better container management.",
                        file_path=source_file,
                        recommendation="Add HEALTHCHECK instruction to enable container health monitoring.",
                        references=[
                            "https://docs.docker.com/engine/reference/builder/#healthcheck"
                        ],
                    )
                )

        return findings
