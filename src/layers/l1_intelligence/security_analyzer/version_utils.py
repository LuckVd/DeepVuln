"""Version comparison utilities for CVE matching."""

import re
from dataclasses import dataclass


@dataclass
class VersionRange:
    """Represents a version range constraint."""

    min_version: str | None = None
    max_version: str | None = None
    min_inclusive: bool = True
    max_inclusive: bool = False
    vulnerable: bool = True  # Whether this range represents vulnerable versions

    def contains(self, version: str) -> bool:
        """Check if a version is within this range.

        Args:
            version: Version string to check.

        Returns:
            True if version is within range.
        """
        normalized = normalize_version(version)

        if self.min_version:
            min_norm = normalize_version(self.min_version)
            cmp = compare_versions(normalized, min_norm)
            if cmp < 0 or (cmp == 0 and not self.min_inclusive):
                return False

        if self.max_version:
            max_norm = normalize_version(self.max_version)
            cmp = compare_versions(normalized, max_norm)
            if cmp > 0 or (cmp == 0 and not self.max_inclusive):
                return False

        return True


def normalize_version(version: str) -> str:
    """Normalize a version string for comparison.

    Args:
        version: Raw version string.

    Returns:
        Normalized version string.
    """
    if not version or version == "*":
        return "0.0.0"

    # Remove common prefixes
    version = version.lstrip("vV=~><^")

    # Remove pre-release suffixes for basic comparison
    # e.g., "1.0.0-alpha" -> "1.0.0"
    if "-" in version:
        parts = version.split("-")
        version = parts[0]

    # Remove build metadata
    if "+" in version:
        version = version.split("+")[0]

    # Ensure at least major.minor.patch format
    parts = version.split(".")
    while len(parts) < 3:
        parts.append("0")

    return ".".join(parts)  # Keep all parts, not just first 3


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings.

    Args:
        v1: First version.
        v2: Second version.

    Returns:
        -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
    """
    v1_parts = normalize_version(v1).split(".")
    v2_parts = normalize_version(v2).split(".")

    # Pad to same length
    max_len = max(len(v1_parts), len(v2_parts))
    v1_parts.extend(["0"] * (max_len - len(v1_parts)))
    v2_parts.extend(["0"] * (max_len - len(v2_parts)))

    for p1, p2 in zip(v1_parts, v2_parts):
        try:
            n1 = int(p1)
            n2 = int(p2)
        except ValueError:
            # Fall back to string comparison
            n1, n2 = p1, p2

        if n1 < n2:
            return -1
        elif n1 > n2:
            return 1

    return 0


def parse_version_range(range_str: str) -> VersionRange | None:
    """Parse a version range string.

    Supports formats:
    - ">= 1.0.0, < 2.0.0"
    - ">=1.0.0,<2.0.0"
    - "1.0.0 - 1.5.0"
    - "< 1.0.0"
    - ">= 1.0.0"
    - "= 1.0.0"
    - "1.0.0" (exact)

    Args:
        range_str: Version range string.

    Returns:
        VersionRange or None if parsing fails.
    """
    if not range_str:
        return None

    range_str = range_str.strip()

    # Handle simple exact version
    if re.match(r"^v?\d+\.\d+(\.\d+)?$", range_str):
        return VersionRange(
            min_version=range_str,
            max_version=range_str,
            min_inclusive=True,
            max_inclusive=True,
        )

    # Handle range with dash: "1.0.0 - 1.5.0"
    dash_match = re.match(r"^v?(\d+\.\d+(?:\.\d+)?)\s*-\s*v?(\d+\.\d+(?:\.\d+)?)$", range_str)
    if dash_match:
        return VersionRange(
            min_version=dash_match.group(1),
            max_version=dash_match.group(2),
            min_inclusive=True,
            max_inclusive=True,
        )

    # Handle comma-separated constraints
    if "," in range_str:
        constraints = [c.strip() for c in range_str.split(",")]
    else:
        constraints = [range_str]

    version_range = VersionRange()

    for constraint in constraints:
        constraint = constraint.strip()

        # >= X.Y.Z
        match = re.match(r"^>=\s*v?(\d+\.\d+(?:\.\d+)?)$", constraint)
        if match:
            version_range.min_version = match.group(1)
            version_range.min_inclusive = True
            continue

        # > X.Y.Z
        match = re.match(r"^>\s*v?(\d+\.\d+(?:\.\d+)?)$", constraint)
        if match:
            version_range.min_version = match.group(1)
            version_range.min_inclusive = False
            continue

        # <= X.Y.Z
        match = re.match(r"^<=\s*v?(\d+\.\d+(?:\.\d+)?)$", constraint)
        if match:
            version_range.max_version = match.group(1)
            version_range.max_inclusive = True
            continue

        # < X.Y.Z
        match = re.match(r"^<\s*v?(\d+\.\d+(?:\.\d+)?)$", constraint)
        if match:
            version_range.max_version = match.group(1)
            version_range.max_inclusive = False
            continue

        # = X.Y.Z
        match = re.match(r"^=\s*v?(\d+\.\d+(?:\.\d+)?)$", constraint)
        if match:
            version_range.min_version = match.group(1)
            version_range.max_version = match.group(1)
            version_range.min_inclusive = True
            version_range.max_inclusive = True
            continue

    # If we have at least one constraint, return the range
    if version_range.min_version or version_range.max_version:
        return version_range

    return None


def is_version_vulnerable(
    version: str,
    vulnerable_ranges: list[str],
    patched_versions: list[str] | None = None,
) -> bool:
    """Check if a version is vulnerable.

    Args:
        version: Version to check.
        vulnerable_ranges: List of vulnerable version range strings.
        patched_versions: List of patched version strings (versions that fix the issue).

    Returns:
        True if the version is vulnerable.
    """
    normalized = normalize_version(version)

    # First check if version is in patched versions
    if patched_versions:
        for patched in patched_versions:
            if compare_versions(normalized, normalize_version(patched)) >= 0:
                return False

    # Check if version falls within any vulnerable range
    for range_str in vulnerable_ranges:
        vuln_range = parse_version_range(range_str)
        if vuln_range and vuln_range.contains(normalized):
            return True

    return False


def extract_version_from_go_range(range_str: str) -> tuple[str | None, str | None]:
    """Extract min and max versions from Go vulnerability range format.

    Go vulndb uses formats like:
    - ">=1.0.0 <1.1.0"
    - ">=1.2.0"

    Args:
        range_str: Go version range string.

    Returns:
        Tuple of (min_version, max_version).
    """
    min_version = None
    max_version = None

    # Extract >= version
    match = re.search(r">=v?(\d+\.\d+(?:\.\d+)?)", range_str)
    if match:
        min_version = match.group(1)

    # Extract < version
    match = re.search(r"<v?(\d+\.\d+(?:\.\d+)?)", range_str)
    if match:
        max_version = match.group(1)

    return min_version, max_version
