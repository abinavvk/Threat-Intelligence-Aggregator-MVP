"""Unit tests verifying Phase 1 workspace layout, configuration, and architecture."""

import subprocess
import sys
from pathlib import Path

from config.settings import (
    BASE_DIR,
    BLOCKLISTS_DIR,
    DATABASE_DIR,
    DOCS_DIR,
    FEEDS_DIR,
    LOGS_DIR,
    OUTPUT_DIR,
    REPORTS_DIR,
    SAMPLES_DIR,
    SUPPORTED_IOC_TYPES,
    calculate_severity,
    ensure_runtime_directories,
)


def test_supported_ioc_types_count() -> None:
    """Verify that exactly 8 required IOC types are configured."""
    expected = {"ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256"}
    assert set(SUPPORTED_IOC_TYPES) == expected
    assert len(SUPPORTED_IOC_TYPES) == 8


def test_ensure_runtime_directories() -> None:
    """Verify that all core runtime directories are created and valid."""
    ensure_runtime_directories()
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
        assert directory.exists(), f"Expected directory to exist: {directory}"
        assert directory.is_dir(), f"Expected path to be a directory: {directory}"


def test_deterministic_severity_scoring() -> None:
    """Verify deterministic scoring rules:

    - >= 5: HIGH
    - 2-4: MEDIUM
    - 1: LOW
    - 0 or negative: UNKNOWN
    """
    assert calculate_severity(10) == "HIGH"
    assert calculate_severity(5) == "HIGH"
    assert calculate_severity(4) == "MEDIUM"
    assert calculate_severity(3) == "MEDIUM"
    assert calculate_severity(2) == "MEDIUM"
    assert calculate_severity(1) == "LOW"
    assert calculate_severity(0) == "UNKNOWN"
    assert calculate_severity(-1) == "UNKNOWN"


def test_cli_help_execution() -> None:
    """Verify CLI entrypoint returns 0 for --help."""
    main_script = BASE_DIR / "main.py"
    result = subprocess.run(
        [sys.executable, str(main_script), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "threat-intel-aggregator" in result.stdout
    assert "Supported IOC types:" in result.stdout


def test_cli_status_command() -> None:
    """Verify CLI status command returns 0 and displays status."""
    main_script = BASE_DIR / "main.py"
    result = subprocess.run(
        [sys.executable, str(main_script), "status"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "Threat Intelligence Aggregator (Non-AI)" in result.stdout
    assert "Supported IOC Types" in result.stdout
    assert "Status:" in result.stdout

