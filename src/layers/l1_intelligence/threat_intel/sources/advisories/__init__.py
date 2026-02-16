"""Advisory sources for vulnerability data."""

from src.layers.l1_intelligence.threat_intel.sources.advisories.github_advisory import (
    GitHubAdvisoryClient,
)
from src.layers.l1_intelligence.threat_intel.sources.advisories.go_vulndb import (
    GoVulnDBClient,
)

__all__ = [
    "GitHubAdvisoryClient",
    "GoVulnDBClient",
]
