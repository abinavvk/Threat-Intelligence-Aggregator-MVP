"""Centralized configuration and settings for Threat Intelligence Aggregator.

Defines filesystem paths, deterministic severity scoring thresholds,
supported indicator types, network client parameters, and logging defaults.
"""

from pathlib import Path
from typing import Dict, Set, Tuple

# Base filesystem paths
BASE_DIR: Path = Path(__file__).resolve().parent.parent
CONFIG_DIR: Path = BASE_DIR / "config"
MODULES_DIR: Path = BASE_DIR / "modules"
DATABASE_DIR: Path = BASE_DIR / "database"
FEEDS_DIR: Path = BASE_DIR / "feeds"
SAMPLES_DIR: Path = FEEDS_DIR / "samples"
OUTPUT_DIR: Path = BASE_DIR / "output"
BLOCKLISTS_DIR: Path = OUTPUT_DIR / "blocklists"
REPORTS_DIR: Path = OUTPUT_DIR / "reports"
LOGS_DIR: Path = BASE_DIR / "logs"
TESTS_DIR: Path = BASE_DIR / "tests"
DOCS_DIR: Path = BASE_DIR / "docs"

# Default file locations
DEFAULT_DB_PATH: Path = DATABASE_DIR / "threat_intelligence.db"
DEFAULT_LOG_PATH: Path = LOGS_DIR / "aggregator.log"

# Supported IOC Types (8 types strictly required)
SUPPORTED_IOC_TYPES: Tuple[str, ...] = (
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "email",
    "md5",
    "sha1",
    "sha256",
)

# Supported Feed Formats
SUPPORTED_FEED_FORMATS: Tuple[str, ...] = (
    "csv",
    "txt",
    "json",
)

# Deterministic Severity Scoring Thresholds
# HIGH: 5 or more distinct sources
# MEDIUM: 2 to 4 distinct sources
# LOW: 1 distinct source
SEVERITY_THRESHOLDS: Dict[str, Tuple[int, int | None]] = {
    "HIGH": (5, None),      # sources >= 5
    "MEDIUM": (2, 4),       # 2 <= sources <= 4
    "LOW": (1, 1),          # sources == 1
}

# Network ingestion settings
HTTP_TIMEOUT_SECONDS: int = 15
HTTP_USER_AGENT: str = "Threat-Intelligence-Aggregator/1.0 (+https://github.com/threat-intel-aggregator)"
HTTP_MAX_RETRIES: int = 3
MAX_FEED_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB safety limit for feeds

# Logging configuration
DEFAULT_LOG_LEVEL: str = "INFO"
LOG_FORMAT: str = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
LOG_DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"


def ensure_runtime_directories() -> None:
    """Ensure that all runtime and output directories exist on the filesystem."""
    for directory in (
        DATABASE_DIR,
        FEEDS_DIR,
        SAMPLES_DIR,
        OUTPUT_DIR,
        BLOCKLISTS_DIR,
        REPORTS_DIR,
        LOGS_DIR,
        DOCS_DIR,
    ):
        directory.mkdir(parents=True, exist_ok=True)


def calculate_severity(distinct_sources_count: int) -> str:
    """Deterministic severity calculation based on distinct source heuristic.

    Args:
        distinct_sources_count: Number of distinct intelligence feeds observing the indicator.

    Returns:
        Severity string: 'HIGH', 'MEDIUM', 'LOW', or 'UNKNOWN' if count < 1.
    """
    if distinct_sources_count >= 5:
        return "HIGH"
    elif distinct_sources_count >= 2:
        return "MEDIUM"
    elif distinct_sources_count == 1:
        return "LOW"
    return "UNKNOWN"

