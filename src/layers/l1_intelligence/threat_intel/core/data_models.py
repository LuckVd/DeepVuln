"""Data models for threat intelligence."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SyncStatus(str, Enum):
    """Synchronization status."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


class CVEInfo(BaseModel):
    """CVE vulnerability information.

    Represents a single CVE entry with all associated metadata.
    """

    cve_id: str = Field(description="CVE identifier (e.g., CVE-2024-1234)")
    source: str = Field(description="Data source (nvd, cnnvd, etc.)")
    description: str = Field(description="Vulnerability description")
    description_zh: str | None = Field(default=None, description="Chinese description")

    # CVSS scores
    cvss_v2_score: float | None = Field(default=None, ge=0, le=10)
    cvss_v2_vector: str | None = Field(default=None)
    cvss_v3_score: float | None = Field(default=None, ge=0, le=10)
    cvss_v3_vector: str | None = Field(default=None)

    # Classification
    severity: SeverityLevel = Field(description="Severity level")
    cwe_ids: list[str] = Field(default_factory=list, description="CWE identifiers")

    # Affected products
    affected_products: list[str] = Field(default_factory=list)
    affected_versions: list[str] = Field(default_factory=list)

    # References
    references: list[str] = Field(default_factory=list)
    patches: list[str] = Field(default_factory=list)

    # PoC/Exploit status
    has_poc: bool = Field(default=False, description="Has known PoC")
    exploit_ids: list[str] = Field(default_factory=list)

    # Known exploited vulnerability
    kev: bool = Field(default=False, description="Known exploited vulnerability")
    ransomware_use: bool = Field(default=False, description="Used in ransomware")

    # Tags and dates
    tags: list[str] = Field(default_factory=list)
    published_date: datetime
    modified_date: datetime | None = None

    # Sync metadata
    synced_at: datetime | None = Field(default=None, description="Last sync time")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "cve_id": "CVE-2024-21762",
                    "source": "nvd",
                    "description": "Out-of-bounds write in FortiOS",
                    "cvss_v3_score": 9.8,
                    "severity": "critical",
                    "kev": True,
                }
            ]
        }
    }


class PoCInfo(BaseModel):
    """Proof of Concept / Exploit information."""

    poc_id: str = Field(description="Unique PoC identifier")
    source: str = Field(description="Data source (exploitdb, github, etc.)")
    cve_ids: list[str] = Field(default_factory=list, description="Related CVEs")

    title: str = Field(description="PoC title")
    description: str | None = Field(default=None)

    # Type classification
    poc_type: str = Field(default="poc", description="poc, exploit, dos, etc.")

    # Code location
    code_url: str | None = Field(default=None, description="URL to code")
    code_local_path: str | None = Field(default=None, description="Local path if downloaded")
    language: str | None = Field(default=None, description="Programming language")

    # Risk indicators
    verified: bool = Field(default=False, description="Verified to work")
    dangerous: bool = Field(default=False, description="May cause harm")

    # Metadata
    author: str | None = Field(default=None)
    published_date: datetime | None = None
    added_date: datetime = Field(default_factory=datetime.now)

    # GitHub specific
    stars: int = Field(default=0, description="GitHub stars if applicable")
    forks: int = Field(default=0)


class ThreatIntel(BaseModel):
    """Threat intelligence entry (IOCs, APT info, etc.)."""

    intel_id: str = Field(description="Unique identifier")
    source: str = Field(description="Data source")
    intel_type: str = Field(description="Type: ioc, apt, campaign, malware, etc.")

    title: str
    description: str

    # Indicators of Compromise
    iocs: list[dict] = Field(
        default_factory=list,
        description="IOCs (IPs, domains, hashes, URLs)",
    )

    # Relations
    related_cves: list[str] = Field(default_factory=list)
    related_malware: list[str] = Field(default_factory=list)
    mitre_attack: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs",
    )

    # Confidence
    confidence: int = Field(default=50, ge=0, le=100, description="Confidence level")

    # Dates
    created_date: datetime
    last_seen_date: datetime | None = None


class SearchResult(BaseModel):
    """Search result from search engines."""

    query: str = Field(description="Original search query")
    source: str = Field(description="Search engine source")

    title: str
    url: str
    snippet: str | None = Field(default=None, description="Result snippet")

    # Relevance
    relevance_score: float | None = Field(default=None, ge=0, le=1)

    # Entity extraction
    related_cves: list[str] = Field(default_factory=list)
    related_cwes: list[str] = Field(default_factory=list)

    # Metadata
    published_date: datetime | None = None
    fetched_at: datetime = Field(default_factory=datetime.now)


class SyncRecord(BaseModel):
    """Record of a synchronization operation."""

    source: str = Field(description="Data source name")
    sync_type: str = Field(description="full, incremental, recent")

    status: SyncStatus = Field(default=SyncStatus.PENDING)

    # Timing
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: float | None = None

    # Counts
    records_fetched: int = Field(default=0)
    records_added: int = Field(default=0)
    records_updated: int = Field(default=0)
    records_skipped: int = Field(default=0)

    # Error info
    error_message: str | None = None
    error_count: int = Field(default=0)

    # Last sync state
    last_sync_time: datetime | None = Field(
        default=None,
        description="Last successful sync timestamp",
    )
    next_sync_time: datetime | None = Field(default=None)


class ThreatIntelConfig(BaseModel):
    """Configuration for threat intelligence sources."""

    # NVD settings
    nvd_enabled: bool = Field(default=True)
    nvd_api_key: str | None = Field(default=None)
    nvd_rate_limit: int = Field(default=50, description="Requests per 30 seconds")

    # CISA KEV
    kev_enabled: bool = Field(default=True)

    # ExploitDB
    exploitdb_enabled: bool = Field(default=True)

    # GitHub
    github_enabled: bool = Field(default=True)
    github_token: str | None = Field(default=None)
    github_min_stars: int = Field(default=5)

    # Google Custom Search
    google_enabled: bool = Field(default=False)
    google_api_key: str | None = Field(default=None)
    google_cx: str | None = Field(default=None, description="Custom Search Engine ID")
    google_daily_limit: int = Field(default=100)

    # Storage
    storage_type: str = Field(default="sqlite")
    storage_path: str = Field(default="./data/threat_intel.db")
    cache_path: str = Field(default="./data/threat_intel/cache")

    # Sync schedule
    sync_enabled: bool = Field(default=True)
    recent_cves_schedule: str = Field(default="0 * * * *", description="Hourly")
    full_sync_schedule: str = Field(default="0 2 * * *", description="Daily at 2 AM")
