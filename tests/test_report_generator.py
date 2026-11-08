"""Unit and integration tests for Phase 9 IOC Report Generator.

Verifies Markdown, JSON, and CSV report generation, comprehensive analytics
(Executive Summary, IOC Statistics, Severity Model, Cross-Feed Correlation,
Source Contribution, Top Repeated Indicators, Data Quality, Feed Processing),
parameter filtering, filename collision handling, empty database resilience,
offline execution, and CLI invocation.
"""

import csv
import json
from pathlib import Path
import subprocess
import sys
import pytest

from config.settings import BASE_DIR, SUPPORTED_IOC_TYPES
from modules.database_manager import DatabaseManager
from modules.report_generator import (
    ReportGenerator,
    ReportResult,
    SUPPORTED_REPORT_FORMATS,
)


@pytest.fixture
def test_db_manager(tmp_path: Path) -> DatabaseManager:
    """Fixture providing a DatabaseManager instance with populated benchmark data."""
    db_file = tmp_path / "test_report.db"
    manager = DatabaseManager(db_path=db_file)
    manager.initialize_database()

    # 4 distinct intelligence feeds
    s1 = manager.insert_source(
        source_name="AlienVault_OTX",
        source_type="file",
        source_location="otx.csv",
        feed_format="csv",
        first_seen="2026-11-01T00:00:00Z",
    )
    s2 = manager.insert_source(
        source_name="AbuseCH_URLhaus",
        source_type="file",
        source_location="urlhaus.txt",
        feed_format="txt",
        first_seen="2026-11-02T00:00:00Z",
    )
    s3 = manager.insert_source(
        source_name="ThreatFox_Community",
        source_type="file",
        source_location="threatfox.json",
        feed_format="json",
        first_seen="2026-11-03T00:00:00Z",
    )
    s4 = manager.insert_source(
        source_name="CISA_Alerts",
        source_type="url",
        source_location="https://cisa.gov/feed.json",
        feed_format="json",
        first_seen="2026-11-04T00:00:00Z",
    )
    s5 = manager.insert_source(
        source_name="Shadowserver",
        source_type="file",
        source_location="shadowserver.csv",
        feed_format="csv",
        first_seen="2026-11-05T00:00:00Z",
    )

    # Indicator 1: HIGH severity IPv4 (5 sources)
    i1, _ = manager.insert_indicator("ipv4", "198.51.100.99", observed_at="2026-11-01T00:00:00Z")
    for sid in (s1, s2, s3, s4, s5):
        manager.insert_observation(i1, sid, "198.51.100.99", observed_at="2026-11-01T00:00:00Z", metadata={"tag": "c2"})

    # Indicator 2: MEDIUM severity Domain (3 sources, 4 observations)
    i2, _ = manager.insert_indicator("domain", "c2-beacon.example.com", observed_at="2026-11-02T00:00:00Z")
    for sid in (s1, s2, s3):
        manager.insert_observation(i2, sid, "c2-beacon.example.com", observed_at="2026-11-02T00:00:00Z", metadata={"tag": "beacon"})
    # Repeated observation in s1 (should increase total occurrences without inflating distinct count)
    manager.insert_observation(i2, s1, "c2-beacon.example.com", observed_at="2026-11-02T12:00:00Z")

    # Indicator 3: LOW severity IPv4 (1 source)
    i3, _ = manager.insert_indicator("ipv4", "192.0.2.1", observed_at="2026-11-03T00:00:00Z")
    manager.insert_observation(i3, s1, "192.0.2.1", observed_at="2026-11-03T00:00:00Z")

    # Indicator 4: LOW severity SHA256 (1 source)
    i4, _ = manager.insert_indicator("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    manager.insert_observation(i4, s2, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    # Indicator 5: LOW severity URL (1 source)
    i5, _ = manager.insert_indicator("url", "http://example.com/exploit.bin")
    manager.insert_observation(i5, s3, "http://example.com/exploit.bin")

    # Indicator 6: LOW severity IPv6 (1 source)
    i6, _ = manager.insert_indicator("ipv6", "2001:db8::1")
    manager.insert_observation(i6, s4, "2001:db8::1")

    # Indicator 7: LOW severity Email (1 source)
    i7, _ = manager.insert_indicator("email", "attacker@example.org")
    manager.insert_observation(i7, s1, "attacker@example.org")

    # Indicator 8: LOW severity MD5 (1 source)
    i8, _ = manager.insert_indicator("md5", "098f6bcd4621d373cade4e832627b4f6")
    manager.insert_observation(i8, s2, "098f6bcd4621d373cade4e832627b4f6")

    # Indicator 9: LOW severity SHA1 (1 source)
    i9, _ = manager.insert_indicator("sha1", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")
    manager.insert_observation(i9, s3, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")

    # Record sample feed ingestion runs
    manager.record_feed_run("otx.csv", "AlienVault_OTX", "csv", success=True, indicators_extracted=10)
    manager.record_feed_run("urlhaus.txt", "AbuseCH_URLhaus", "txt", success=True, indicators_extracted=5)
    manager.record_feed_run("bad_feed.json", "Broken_Feed", "json", success=False, error_message="HTTP 404 Not Found")

    yield manager
    manager.close()


def test_supported_report_formats() -> None:
    """Verify supported formats match 'md', 'json', and 'csv'."""
    formats = ReportGenerator.get_supported_formats()
    assert set(formats) == {"md", "json", "csv"}


def test_markdown_report_generation(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify Markdown report creates a properly formatted file containing all 8 sections."""
    out_dir = tmp_path / "reports"
    generator = ReportGenerator(db_manager=test_db_manager, output_dir=out_dir)

    result = generator.generate_report(format_type="md")

    assert result.format == "md"
    assert result.file_path.exists()
    assert result.file_path.suffix == ".md"
    assert result.total_indicators == 9

    content = result.file_path.read_text(encoding="utf-8")

    # Check all 8 required report sections
    assert "# Threat Intelligence Analysis & Audit Report" in content
    assert "## 1. Executive Summary" in content
    assert "## 2. IOC Category Statistics" in content
    assert "## 3. Severity Analysis & Scoring Model" in content
    assert "## 4. Cross-Feed Correlation & Consensus" in content
    assert "## 5. Intelligence Source Analysis" in content
    assert "## 6. Top Repeated Indicators" in content
    assert "## 7. Data Quality & Integrity Audit" in content
    assert "## 8. Feed Processing Summary" in content

    # Check specific indicators and heuristics
    assert "198.51.100.99" in content
    assert "c2-beacon.example.com" in content
    assert "HIGH" in content
    assert "MEDIUM" in content
    assert "LOW" in content
    assert "Heuristic Scoring Notice" in content


def test_json_report_generation(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify JSON report creates a structured document with all required schema elements."""
    out_dir = tmp_path / "reports"
    generator = ReportGenerator(db_manager=test_db_manager, output_dir=out_dir)

    result = generator.generate_report(format_type="json")

    assert result.format == "json"
    assert result.file_path.exists()

    with open(result.file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Validate top-level schema keys
    expected_keys = {
        "metadata",
        "executive_summary",
        "ioc_statistics",
        "severity_analysis",
        "cross_feed_correlations",
        "source_analysis",
        "top_repeated_indicators",
        "data_quality",
        "feed_processing_summary",
    }
    assert expected_keys.issubset(set(data.keys()))

    # Executive summary checks
    exec_sum = data["executive_summary"]
    assert exec_sum["total_unique_indicators"] == 9
    assert exec_sum["total_sources"] == 5
    assert exec_sum["cross_feed_indicators_count"] == 2
    assert exec_sum["severity_distribution"]["HIGH"]["count"] == 1
    assert exec_sum["severity_distribution"]["MEDIUM"]["count"] == 1
    assert exec_sum["severity_distribution"]["LOW"]["count"] == 7

    # IOC statistics checks (all 8 types present)
    ioc_stats = data["ioc_statistics"]
    for t in SUPPORTED_IOC_TYPES:
        assert t in ioc_stats
    assert ioc_stats["ipv4"]["count"] == 2
    assert ioc_stats["domain"]["count"] == 1


def test_csv_report_generation(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify CSV report exports tabular indicator and correlation findings with headers."""
    out_dir = tmp_path / "reports"
    generator = ReportGenerator(db_manager=test_db_manager, output_dir=out_dir)

    result = generator.generate_report(format_type="csv")

    assert result.format == "csv"
    assert result.file_path.exists()

    with open(result.file_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        expected_columns = [
            "indicator",
            "ioc_type",
            "severity",
            "distinct_sources_count",
            "total_occurrences",
            "is_cross_feed",
            "first_seen",
            "last_seen",
            "sources",
        ]
        assert reader.fieldnames == expected_columns
        rows = list(reader)
        assert len(rows) == 9

        # Verify high-severity row
        high_row = next(r for r in rows if r["indicator"] == "198.51.100.99")
        assert high_row["ioc_type"] == "ipv4"
        assert high_row["severity"] == "HIGH"
        assert int(high_row["distinct_sources_count"]) == 5
        assert high_row["is_cross_feed"] == "True"


def test_empty_database_behavior(tmp_path: Path) -> None:
    """Verify report generation handles an empty database gracefully without ZeroDivisionError."""
    db_file = tmp_path / "empty.db"
    manager = DatabaseManager(db_path=db_file)
    manager.initialize_database()

    generator = ReportGenerator(db_manager=manager, output_dir=tmp_path / "reports")

    # 1. Markdown on empty database
    res_md = generator.generate_report(format_type="md")
    assert res_md.total_indicators == 0
    content_md = res_md.file_path.read_text(encoding="utf-8")
    assert "`0` | 100.0% of canonical repository" in content_md
    assert "No indicators matched the correlation and consensus criteria." in content_md

    # 2. JSON on empty database
    res_json = generator.generate_report(format_type="json")
    with open(res_json.file_path, "r", encoding="utf-8") as f:
        data_json = json.load(f)
    assert data_json["executive_summary"]["total_unique_indicators"] == 0
    assert data_json["executive_summary"]["cross_feed_percentage"] == 0.0

    # 3. CSV on empty database
    res_csv = generator.generate_report(format_type="csv")
    with open(res_csv.file_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == 0

    manager.close()


def test_severity_statistics_and_thresholds(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify deterministic severity distribution and explanation of scoring heuristics."""
    generator = ReportGenerator(db_manager=test_db_manager, output_dir=tmp_path)
    data = generator.collect_report_data()

    dist = data["severity_analysis"]["distribution"]
    assert dist["HIGH"]["count"] == 1
    assert dist["MEDIUM"]["count"] == 1
    assert dist["LOW"]["count"] == 7

    thresh = data["severity_analysis"]["thresholds"]
    assert "distinct_sources >= 5" in thresh["HIGH"]
    assert "2 <= distinct_sources <= 4" in thresh["MEDIUM"]
    assert "distinct_sources == 1" in thresh["LOW"]


def test_cross_feed_correlation_details(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify cross-feed indicators accurately record distinct sources, sighting counts, and sources."""
    generator = ReportGenerator(db_manager=test_db_manager, output_dir=tmp_path)
    data = generator.collect_report_data(cross_feed_only=True)

    correlations = data["cross_feed_correlations"]
    assert len(correlations) == 2  # Only 198.51.100.99 (5 sources) and c2-beacon.example.com (3 sources)

    c2 = next(c for c in correlations if c["normalized_value"] == "c2-beacon.example.com")
    assert c2["distinct_sources_count"] == 3
    assert c2["total_occurrences"] == 4  # 4 sightings across 3 feeds
    assert len(c2["sources"]) == 3
    assert c2["severity"] == "MEDIUM"


def test_source_analysis_metrics(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify source analysis returns observations and unique indicator counts per registered source."""
    generator = ReportGenerator(db_manager=test_db_manager, output_dir=tmp_path)
    data = generator.collect_report_data()

    sources = data["source_analysis"]
    assert len(sources) == 5

    otx = next(s for s in sources if s["source_name"] == "AlienVault_OTX")
    assert otx["source_type"] == "file"
    assert otx["feed_format"] == "csv"
    assert otx["total_observations"] == 5  # i1, i2 (twice), i3, i7
    assert otx["unique_indicators"] == 4


def test_top_repeated_indicators(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify top repeated indicators are ordered by occurrences and respect limit."""
    generator = ReportGenerator(db_manager=test_db_manager, output_dir=tmp_path)

    # Top 2 indicators
    data = generator.collect_report_data(top=2)
    top_iocs = data["top_repeated_indicators"]
    assert len(top_iocs) == 2

    # First should be 198.51.100.99 (5 observations)
    assert top_iocs[0]["indicator"] == "198.51.100.99"
    assert top_iocs[0]["total_occurrences"] == 5

    # Second should be c2-beacon.example.com (4 observations)
    assert top_iocs[1]["indicator"] == "c2-beacon.example.com"
    assert top_iocs[1]["total_occurrences"] == 4


def test_filtering_options(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify report filtering by severity, category, and cross-feed flags."""
    generator = ReportGenerator(db_manager=test_db_manager, output_dir=tmp_path)

    # Filter by severity HIGH
    data_high = generator.collect_report_data(severity="HIGH")
    assert len(data_high["cross_feed_correlations"]) == 1
    assert data_high["cross_feed_correlations"][0]["normalized_value"] == "198.51.100.99"

    # Filter by IOC type domain
    data_domain = generator.collect_report_data(ioc_type="domain")
    assert len(data_domain["cross_feed_correlations"]) == 1
    assert data_domain["cross_feed_correlations"][0]["normalized_value"] == "c2-beacon.example.com"


def test_custom_output_path_and_directory_creation(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify custom output paths automatically create nested directories."""
    custom_dest = tmp_path / "deep" / "nested" / "my_custom_report.md"
    generator = ReportGenerator(db_manager=test_db_manager, output_dir=tmp_path)

    res = generator.generate_report(format_type="md", output_path=custom_dest)
    assert custom_dest.exists()
    assert res.file_path == custom_dest.resolve()


def test_filename_collision_avoidance(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify existing reports are not silently overwritten unless overwrite=True."""
    target_file = tmp_path / "collision_test.md"
    target_file.write_text("Existing report content", encoding="utf-8")

    generator = ReportGenerator(db_manager=test_db_manager, output_dir=tmp_path)

    # Without overwrite: should create collision_test_1.md
    res1 = generator.generate_report(format_type="md", output_path=target_file, overwrite=False)
    assert res1.file_path != target_file
    assert res1.file_path.name == "collision_test_1.md"
    assert target_file.read_text(encoding="utf-8") == "Existing report content"

    # With overwrite: should overwrite target_file
    res2 = generator.generate_report(format_type="md", output_path=target_file, overwrite=True)
    assert res2.file_path == target_file
    assert "Threat Intelligence Analysis" in target_file.read_text(encoding="utf-8")


def test_invalid_parameters_raise_value_errors(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify validation raises clear ValueErrors for invalid formats, types, severities, or limits."""
    generator = ReportGenerator(db_manager=test_db_manager, output_dir=tmp_path)

    with pytest.raises(ValueError, match="Unsupported report format: 'html'"):
        generator.generate_report(format_type="html")

    with pytest.raises(ValueError, match="Invalid severity filter: 'CRITICAL'"):
        generator.collect_report_data(severity="CRITICAL")

    with pytest.raises(ValueError, match="Unsupported IOC type: 'invalid_type'"):
        generator.collect_report_data(ioc_type="invalid_type")

    with pytest.raises(ValueError, match="top parameter must be >= 1"):
        generator.collect_report_data(top=0)


def test_utc_timestamps(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify generated timestamps adhere to UTC ISO 8601 formatting."""
    generator = ReportGenerator(db_manager=test_db_manager, output_dir=tmp_path)
    res = generator.generate_report(format_type="json")

    with open(res.file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    ts = data["metadata"]["generated_at"]
    assert "+00:00" in ts or "Z" in ts


def test_no_network_activity_during_report_generation(
    test_db_manager: DatabaseManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify report generation operates completely offline without network calls."""
    import socket

    def broken_socket(*args, **kwargs):
        raise RuntimeError("Prohibited network connection initiated during report generation!")

    monkeypatch.setattr(socket, "socket", broken_socket)

    generator = ReportGenerator(db_manager=test_db_manager, output_dir=tmp_path)
    res = generator.generate_report(format_type="md")
    assert res.file_path.exists()


def test_database_remains_unchanged_after_report_generation(
    test_db_manager: DatabaseManager, tmp_path: Path
) -> None:
    """Verify report generation is strictly read-only and leaves database unaltered."""
    initial_stats = test_db_manager.get_statistics()
    generator = ReportGenerator(db_manager=test_db_manager, output_dir=tmp_path)

    generator.generate_report(format_type="md")
    generator.generate_report(format_type="json")
    generator.generate_report(format_type="csv")

    post_stats = test_db_manager.get_statistics()
    assert initial_stats["total_indicators"] == post_stats["total_indicators"]
    assert initial_stats["total_sources"] == post_stats["total_sources"]
    assert initial_stats["total_observations"] == post_stats["total_observations"]


def test_feed_processing_summary_reporting(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify feed processing summary correctly reports successful and failed feed runs."""
    generator = ReportGenerator(db_manager=test_db_manager, output_dir=tmp_path)
    data = generator.collect_report_data()

    summary = data["feed_processing_summary"]
    assert summary["has_history"] is True
    assert summary["total_runs"] == 3
    assert summary["successful_runs"] == 2
    assert summary["failed_runs"] == 1
    assert len(summary["errors"]) == 1
    assert "HTTP 404 Not Found" in summary["errors"][0]["error_message"]


def test_cli_report_commands(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify CLI execution of report subcommand across all formats and filter combinations."""
    main_py = BASE_DIR / "main.py"
    db_file = test_db_manager.db_path

    # 1. Default Markdown report via CLI
    cmd1 = [
        sys.executable,
        str(main_py),
        "--db",
        str(db_file),
        "report",
        "--output",
        str(tmp_path / "cli_reports"),
    ]
    proc1 = subprocess.run(cmd1, capture_output=True, text=True, check=False)
    assert proc1.returncode == 0
    assert "THREAT INTELLIGENCE ANALYSIS REPORT" in proc1.stdout
    assert "Report generated successfully" in proc1.stdout

    # 2. JSON report with severity and cross-feed filtering via CLI
    cmd2 = [
        sys.executable,
        str(main_py),
        "--db",
        str(db_file),
        "report",
        "--format",
        "json",
        "--severity",
        "HIGH",
        "--cross-feed-only",
        "--output",
        str(tmp_path / "cli_reports"),
    ]
    proc2 = subprocess.run(cmd2, capture_output=True, text=True, check=False)
    assert proc2.returncode == 0
    assert "Export Format:        JSON" in proc2.stdout

    # 3. CSV report via CLI
    cmd3 = [
        sys.executable,
        str(main_py),
        "--db",
        str(db_file),
        "report",
        "--format",
        "csv",
        "--type",
        "ipv4",
        "--top",
        "5",
        "--output",
        str(tmp_path / "cli_reports"),
    ]
    proc3 = subprocess.run(cmd3, capture_output=True, text=True, check=False)
    assert proc3.returncode == 0
    assert "Export Format:        CSV" in proc3.stdout
