"""Unit and integration tests for Phase 8 IOC Blocklist Generator.

Verifies categorized exports (IPv4, IPv6, Domain, URL, Email, MD5, SHA1, SHA256),
multi-format serialization (TXT, CSV, JSON), multi-feed consensus filtering,
deterministic severity exclusion, filesystem isolation, and CLI execution.
"""

import csv
import json
from pathlib import Path
import subprocess
import sys
import pytest

from config.settings import BASE_DIR, SUPPORTED_IOC_TYPES
from modules.blocklist_generator import (
    BlocklistExportResult,
    BlocklistGenerator,
    SUPPORTED_EXPORT_FORMATS,
)
from modules.database_manager import DatabaseManager


@pytest.fixture
def test_db_manager(tmp_path: Path) -> DatabaseManager:
    """Fixture providing a DatabaseManager instance with populated benchmark threat data."""
    db_file = tmp_path / "test_blocklist.db"
    manager = DatabaseManager(db_path=db_file)
    manager.initialize_database()

    # Create 3 distinct intelligence feed sources
    s1 = manager.insert_source(
        source_name="AlienVault_OTX",
        source_type="file",
        source_location="otx_export.csv",
        feed_format="csv",
    )
    s2 = manager.insert_source(
        source_name="AbuseCH_URLhaus",
        source_type="file",
        source_location="urlhaus.txt",
        feed_format="txt",
    )
    s3 = manager.insert_source(
        source_name="ThreatFox_Community",
        source_type="file",
        source_location="threatfox.json",
        feed_format="json",
    )
    s4 = manager.insert_source(
        source_name="CISA_Alerts",
        source_type="file",
        source_location="cisa.json",
        feed_format="json",
    )
    s5 = manager.insert_source(
        source_name="Shadowserver_Drone",
        source_type="file",
        source_location="shadowserver.csv",
        feed_format="csv",
    )

    # 1. High-severity IPv4 (5 sources)
    i1, _ = manager.insert_indicator("ipv4", "198.51.100.99", observed_at="2026-11-01T00:00:00Z")
    for sid in (s1, s2, s3, s4, s5):
        manager.insert_observation(i1, sid, "198.51.100.99", observed_at="2026-11-01T00:00:00Z")

    # 2. Medium-severity IPv4 (2 sources)
    i2, _ = manager.insert_indicator("ipv4", "192.0.2.50", observed_at="2026-11-02T00:00:00Z")
    for sid in (s1, s2):
        manager.insert_observation(i2, sid, "192.0.2.50", observed_at="2026-11-02T00:00:00Z")

    # 3. Low-severity IPv4 (1 source)
    i3, _ = manager.insert_indicator("ipv4", "203.0.113.10", observed_at="2026-11-03T00:00:00Z")
    manager.insert_observation(i3, s1, "203.0.113.10", observed_at="2026-11-03T00:00:00Z")

    # 4. Medium-severity Domain (3 sources)
    i4, _ = manager.insert_indicator("domain", "c2-beacon.example.com", observed_at="2026-11-04T00:00:00Z")
    for sid in (s1, s2, s3):
        manager.insert_observation(i4, sid, "c2-beacon.example.com", observed_at="2026-11-04T00:00:00Z")

    # 5. Low-severity Domain (1 source)
    i5, _ = manager.insert_indicator("domain", "staging.example.net", observed_at="2026-11-05T00:00:00Z")
    manager.insert_observation(i5, s2, "staging.example.net", observed_at="2026-11-05T00:00:00Z")

    # 6. Low-severity SHA256 (1 source)
    i6, _ = manager.insert_indicator(
        "sha256",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        observed_at="2026-11-06T00:00:00Z",
    )
    manager.insert_observation(
        i6, s3, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        observed_at="2026-11-06T00:00:00Z",
    )

    # 7. Low-severity URL (1 source)
    i7, _ = manager.insert_indicator("url", "http://example.com/bad", observed_at="2026-11-07T00:00:00Z")
    manager.insert_observation(i7, s2, "http://example.com/bad", observed_at="2026-11-07T00:00:00Z")

    # 8. Low-severity Email (1 source)
    i8, _ = manager.insert_indicator("email", "phish@example.com", observed_at="2026-11-08T00:00:00Z")
    manager.insert_observation(i8, s1, "phish@example.com", observed_at="2026-11-08T00:00:00Z")

    # 9. Low-severity MD5 (1 source)
    i9, _ = manager.insert_indicator("md5", "098f6bcd4621d373cade4e832627b4f6", observed_at="2026-11-08T00:00:00Z")
    manager.insert_observation(i9, s1, "098f6bcd4621d373cade4e832627b4f6", observed_at="2026-11-08T00:00:00Z")

    # 10. Low-severity SHA1 (1 source)
    i10, _ = manager.insert_indicator("sha1", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", observed_at="2026-11-08T00:00:00Z")
    manager.insert_observation(i10, s2, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", observed_at="2026-11-08T00:00:00Z")

    # 11. Low-severity IPv6 (1 source)
    i11, _ = manager.insert_indicator("ipv6", "2001:db8::1", observed_at="2026-11-08T00:00:00Z")
    manager.insert_observation(i11, s3, "2001:db8::1", observed_at="2026-11-08T00:00:00Z")

    yield manager
    manager.close()


def test_supported_categories_and_formats() -> None:
    """Verify available categories match the 8 required IOC types and formats are txt, csv, json."""
    categories = BlocklistGenerator.get_available_categories()
    assert len(categories) == 8
    assert set(categories) == set(SUPPORTED_IOC_TYPES)

    formats = BlocklistGenerator.get_available_formats()
    assert set(formats) == {"txt", "csv", "json"}


def test_export_txt_single_category(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify TXT export outputs one canonical IOC per line without extra metadata or whitespace."""
    out_dir = tmp_path / "blocklists"
    generator = BlocklistGenerator(db_manager=test_db_manager, output_dir=out_dir)

    results = generator.generate_blocklist(ioc_type="ipv4", format_type="txt")
    assert len(results) == 1
    res = results[0]

    assert res.category == "ipv4"
    assert res.format == "txt"
    assert res.indicator_count == 3
    assert res.file_path.exists()

    content = res.file_path.read_text(encoding="utf-8")
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    assert len(lines) == 3
    assert "198.51.100.99" in lines
    assert "192.0.2.50" in lines
    assert "203.0.113.10" in lines


def test_export_csv_headers_and_columns(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify CSV export writes proper headers and accurate threat metadata columns."""
    out_dir = tmp_path / "blocklists"
    generator = BlocklistGenerator(db_manager=test_db_manager, output_dir=out_dir)

    results = generator.generate_blocklist(ioc_type="domain", format_type="csv")
    assert len(results) == 1
    res = results[0]

    assert res.file_path.exists()
    assert res.indicator_count == 2

    with open(res.file_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        expected_fields = [
            "ioc_type",
            "indicator",
            "severity",
            "distinct_sources_count",
            "total_occurrences",
            "first_seen",
            "last_seen",
        ]
        assert reader.fieldnames == expected_fields
        rows = list(reader)
        assert len(rows) == 2

        # Check c2-beacon.example.com row
        c2_row = next(r for r in rows if r["indicator"] == "c2-beacon.example.com")
        assert c2_row["ioc_type"] == "domain"
        assert c2_row["severity"] == "MEDIUM"
        assert int(c2_row["distinct_sources_count"]) == 3


def test_export_json_structure_and_metadata(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify JSON export creates structured object hierarchy with metadata and indicator objects."""
    out_dir = tmp_path / "blocklists"
    generator = BlocklistGenerator(db_manager=test_db_manager, output_dir=out_dir)

    results = generator.generate_blocklist(ioc_type="sha256", format_type="json")
    assert len(results) == 1
    res = results[0]

    assert res.file_path.exists()
    assert res.indicator_count == 1

    with open(res.file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "metadata" in data
    assert "indicators" in data
    assert data["metadata"]["total_indicators"] == 1
    assert data["metadata"]["filters"]["category"] == "sha256"

    ind = data["indicators"][0]
    assert ind["ioc_type"] == "sha256"
    assert ind["indicator"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert ind["severity"] == "LOW"
    assert ind["distinct_sources_count"] == 1
    assert "ThreatFox_Community" in ind["sources"]


def test_generate_all_categories_separate_files(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify exporting all categories produces separate files for each of the 8 supported IOC types."""
    out_dir = tmp_path / "blocklists"
    generator = BlocklistGenerator(db_manager=test_db_manager, output_dir=out_dir)

    results = generator.generate_blocklist(ioc_type="all", format_type="txt", combined=False)
    assert len(results) == 8

    generated_categories = {r.category for r in results}
    assert generated_categories == set(SUPPORTED_IOC_TYPES)

    for r in results:
        assert r.file_path.exists()
        assert r.format == "txt"


def test_generate_combined_blocklist(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify combined blocklist exports all indicator categories into a single unified file."""
    out_dir = tmp_path / "blocklists"
    generator = BlocklistGenerator(db_manager=test_db_manager, output_dir=out_dir)

    results = generator.generate_blocklist(ioc_type="all", format_type="csv", combined=True)
    assert len(results) == 1
    res = results[0]

    assert res.category == "all"
    assert res.file_path.name == "blocklist_all.csv"
    assert res.indicator_count == 11  # All 11 inserted indicators

    with open(res.file_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        types_in_file = {r["ioc_type"] for r in rows}
        assert types_in_file == set(SUPPORTED_IOC_TYPES)


def test_severity_filtering(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify filtering blocklists strictly by severity tier (HIGH, MEDIUM, LOW)."""
    out_dir = tmp_path / "blocklists"
    generator = BlocklistGenerator(db_manager=test_db_manager, output_dir=out_dir)

    # 1. HIGH severity only (only 198.51.100.99 has 5 sources)
    high_res = generator.generate_blocklist(ioc_type="ipv4", severity="HIGH", format_type="txt")
    assert high_res[0].indicator_count == 1
    content = high_res[0].file_path.read_text(encoding="utf-8").strip()
    assert content == "198.51.100.99"

    # 2. MEDIUM severity only (192.0.2.50 has 2 sources)
    med_res = generator.generate_blocklist(ioc_type="ipv4", severity="MEDIUM", format_type="txt")
    assert med_res[0].indicator_count == 1
    content = med_res[0].file_path.read_text(encoding="utf-8").strip()
    assert content == "192.0.2.50"

    # 3. LOW severity only (203.0.113.10 has 1 source)
    low_res = generator.generate_blocklist(ioc_type="ipv4", severity="LOW", format_type="txt")
    assert low_res[0].indicator_count == 1
    content = low_res[0].file_path.read_text(encoding="utf-8").strip()
    assert content == "203.0.113.10"


def test_min_sources_and_cross_feed_filtering(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify --min-sources and --cross-feed-only filters select corroborated indicators."""
    out_dir = tmp_path / "blocklists"
    generator = BlocklistGenerator(db_manager=test_db_manager, output_dir=out_dir)

    # Minimum sources = 2 on IPv4 (should return 198.51.100.99 with 5 sources and 192.0.2.50 with 2 sources)
    res_min2 = generator.generate_blocklist(ioc_type="ipv4", min_sources=2, format_type="txt")
    assert res_min2[0].indicator_count == 2

    # Cross-feed only on IPv4 (equivalent to min_sources=2)
    res_cross = generator.generate_blocklist(ioc_type="ipv4", cross_feed_only=True, format_type="txt")
    assert res_cross[0].indicator_count == 2
    content = res_cross[0].file_path.read_text(encoding="utf-8")
    assert "203.0.113.10" not in content  # Single-source indicator omitted


def test_exclude_low_severity_filter(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify --exclude-low filter excludes all single-source / LOW severity indicators."""
    out_dir = tmp_path / "blocklists"
    generator = BlocklistGenerator(db_manager=test_db_manager, output_dir=out_dir)

    # IPv4 has 3 indicators: 1 HIGH, 1 MEDIUM, 1 LOW
    res = generator.generate_blocklist(ioc_type="ipv4", exclude_low=True, format_type="txt")
    assert res[0].indicator_count == 2
    content = res[0].file_path.read_text(encoding="utf-8")
    assert "203.0.113.10" not in content


def test_invalid_parameters_raise_value_errors(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify validation raises clear ValueErrors for invalid category, format, or severity."""
    generator = BlocklistGenerator(db_manager=test_db_manager, output_dir=tmp_path)

    with pytest.raises(ValueError, match="Unsupported IOC type: 'invalid_type'"):
        generator.get_indicators_for_blocklist(ioc_type="invalid_type")

    with pytest.raises(ValueError, match="Invalid severity filter: 'CRITICAL'"):
        generator.get_indicators_for_blocklist(severity="CRITICAL")

    with pytest.raises(ValueError, match="min_sources must be >= 1"):
        generator.get_indicators_for_blocklist(min_sources=0)

    with pytest.raises(ValueError, match="Unsupported format 'xml'"):
        generator.generate_category_blocklist(category="ipv4", format_type="xml")


def test_custom_output_destination(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify custom output paths and non-existent parent directory auto-creation."""
    custom_dir = tmp_path / "custom_nested" / "deep_folder"
    generator = BlocklistGenerator(db_manager=test_db_manager, output_dir=custom_dir)

    custom_file = custom_dir / "my_custom_ipv4.txt"
    res = generator.generate_category_blocklist(category="ipv4", format_type="txt", output_path=custom_file)

    assert custom_file.exists()
    assert res.file_path == custom_file.resolve()
    assert res.indicator_count == 3


def test_database_records_unaltered_after_export(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify that generating blocklists does not modify, delete, or corrupt database indicators."""
    initial_stats = test_db_manager.get_statistics()
    generator = BlocklistGenerator(db_manager=test_db_manager, output_dir=tmp_path)

    generator.generate_blocklist(ioc_type="all", format_type="json", combined=False)
    generator.generate_blocklist(ioc_type="all", format_type="csv", combined=True)

    post_stats = test_db_manager.get_statistics()
    assert initial_stats["total_indicators"] == post_stats["total_indicators"]
    assert initial_stats["total_sources"] == post_stats["total_sources"]
    assert initial_stats["total_observations"] == post_stats["total_observations"]


def test_no_network_activity_during_blocklist_generation(
    test_db_manager: DatabaseManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify blocklist generation operates entirely offline with zero network requests."""
    import socket

    def broken_socket(*args, **kwargs):
        raise RuntimeError("Prohibited network connection initiated during blocklist generation!")

    monkeypatch.setattr(socket, "socket", broken_socket)

    generator = BlocklistGenerator(db_manager=test_db_manager, output_dir=tmp_path)
    results = generator.generate_blocklist(ioc_type="all", format_type="json", combined=True)
    assert len(results) == 1
    assert results[0].indicator_count == 11


def test_cli_blocklist_execution(test_db_manager: DatabaseManager, tmp_path: Path) -> None:
    """Verify CLI execution of blocklist subcommand with various flags."""
    main_py = BASE_DIR / "main.py"
    db_file = test_db_manager.db_path

    # 1. Single category export via CLI
    cmd1 = [
        sys.executable,
        str(main_py),
        "--db",
        str(db_file),
        "blocklist",
        "--type",
        "ipv4",
        "--format",
        "txt",
        "--output",
        str(tmp_path / "cli_blocklists"),
    ]
    proc1 = subprocess.run(cmd1, capture_output=True, text=True, check=False)
    assert proc1.returncode == 0
    assert "IOC BLOCKLIST EXPORT SUMMARY" in proc1.stdout
    assert "ipv4" in proc1.stdout
    assert (tmp_path / "cli_blocklists" / "blocklist_ipv4.txt").exists()

    # 2. Corroborated cross-feed CSV export via CLI
    cmd2 = [
        sys.executable,
        str(main_py),
        "--db",
        str(db_file),
        "blocklist",
        "--all",
        "--cross-feed-only",
        "--format",
        "csv",
        "--output",
        str(tmp_path / "cli_blocklists_cross"),
    ]
    proc2 = subprocess.run(cmd2, capture_output=True, text=True, check=False)
    assert proc2.returncode == 0
    assert "Cross-feed consensus only" in proc2.stdout
    assert (tmp_path / "cli_blocklists_cross" / "blocklist_ipv4.csv").exists()

    # 3. Missing category and --all fails gracefully with help message
    cmd3 = [sys.executable, str(main_py), "--db", str(db_file), "blocklist"]
    proc3 = subprocess.run(cmd3, capture_output=True, text=True, check=False)
    assert proc3.returncode == 1
    assert "Please specify an IOC category using --type" in proc3.stdout

