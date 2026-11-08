"""Unit and integration tests for Phase 10 End-to-End CLI Pipeline.

Verifies complete lifecycle orchestration (collection -> parsing -> validation ->
normalization -> deduplication -> persistence -> correlation -> summary),
multi-feed processing across CSV/TXT/JSON, error isolation, audit trails,
CLI argument handling, and offline execution guarantees.
"""

import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import MagicMock, patch
import pytest

from config.settings import BASE_DIR, SAMPLES_DIR
from modules.database_manager import DatabaseManager
from modules.pipeline import PipelineResult, ThreatIntelligencePipeline


@pytest.fixture
def temp_db_path(tmp_path: Path) -> Path:
    """Fixture providing a temporary database file path."""
    return tmp_path / "pipeline_test.db"


def test_pipeline_local_csv(temp_db_path: Path) -> None:
    """Verify complete pipeline execution on a local CSV sample feed."""
    csv_file = SAMPLES_DIR / "sample_feed.csv"
    assert csv_file.exists(), f"Sample feed not found: {csv_file}"

    pipeline = ThreatIntelligencePipeline(db_path=temp_db_path)
    result = pipeline.run(files=[csv_file])

    assert result.success is True
    assert result.feeds_supplied == 1
    assert result.successful_feeds == 1
    assert result.failed_feeds == 0
    assert result.total_candidates == 9
    assert result.valid_indicators == 9
    assert result.invalid_indicators == 0
    assert result.unique_normalized == 9
    assert result.new_database_records == 9

    # Verify SQLite persistence
    db = DatabaseManager(db_path=temp_db_path)
    stats = db.get_statistics()
    assert stats["total_indicators"] == 9
    assert stats["total_sources"] == 1
    assert stats["total_observations"] == 9
    db.close()


def test_pipeline_local_txt(temp_db_path: Path) -> None:
    """Verify complete pipeline execution on a local TXT sample feed."""
    txt_file = SAMPLES_DIR / "sample_feed.txt"
    assert txt_file.exists(), f"Sample feed not found: {txt_file}"

    pipeline = ThreatIntelligencePipeline(db_path=temp_db_path)
    result = pipeline.run(files=[txt_file])

    assert result.success is True
    assert result.successful_feeds == 1
    assert result.total_candidates == 15
    assert result.valid_indicators == 15
    assert result.unique_normalized == 15
    assert result.new_database_records == 15


def test_pipeline_local_json(temp_db_path: Path) -> None:
    """Verify complete pipeline execution on a local JSON sample feed."""
    json_file = SAMPLES_DIR / "sample_feed.json"
    assert json_file.exists(), f"Sample feed not found: {json_file}"

    pipeline = ThreatIntelligencePipeline(db_path=temp_db_path)
    result = pipeline.run(files=[json_file])

    assert result.success is True
    assert result.successful_feeds == 1
    assert result.total_candidates == 8
    assert result.valid_indicators == 8
    assert result.unique_normalized == 8
    assert result.new_database_records == 8


def test_pipeline_multiple_feeds_in_one_execution(temp_db_path: Path) -> None:
    """Verify ingesting CSV, TXT, and JSON feeds together in a single pipeline run."""
    sources = [
        SAMPLES_DIR / "sample_feed.csv",
        SAMPLES_DIR / "sample_feed.txt",
        SAMPLES_DIR / "sample_feed.json",
    ]

    pipeline = ThreatIntelligencePipeline(db_path=temp_db_path)
    result = pipeline.run(files=sources)

    assert result.success is True
    assert result.feeds_supplied == 3
    assert result.successful_feeds == 3
    assert result.failed_feeds == 0
    assert result.total_candidates == 32
    assert result.valid_indicators == 32
    assert result.unique_normalized == 30
    assert result.duplicate_observations == 2  # 192.0.2.15 and malicious-beacon.example.com appear in 2 feeds
    assert result.new_database_records == 30

    # Cross-feed corroboration check
    assert result.cross_feed_indicators == 2
    assert result.severity_distribution["MEDIUM"] == 2
    assert result.severity_distribution["LOW"] == 28


def test_pipeline_duplicate_iocs_and_provenance(temp_db_path: Path, tmp_path: Path) -> None:
    """Verify duplicate sightings in same feed increment observations without inflating distinct sources."""
    feed_path = tmp_path / "repeated.txt"
    feed_path.write_text(
        "192.0.2.1\n192.0.2.1\n192.0.2.1\n",
        encoding="utf-8",
    )

    pipeline = ThreatIntelligencePipeline(db_path=temp_db_path)
    result = pipeline.run(files=[feed_path])

    assert result.success is True
    assert result.total_candidates == 3
    assert result.valid_indicators == 3
    assert result.unique_normalized == 1
    assert result.duplicate_observations == 2
    assert result.new_database_records == 1

    # Verify database record has total_occurrences == 3 but distinct_sources_count == 1
    db = DatabaseManager(db_path=temp_db_path)
    ind = db.get_indicator("ipv4", "192.0.2.1")
    assert ind is not None
    assert ind["distinct_sources_count"] == 1
    assert ind["total_occurrences"] == 3
    assert ind["severity"] == "LOW"
    db.close()


def test_pipeline_invalid_ioc_handling(temp_db_path: Path, tmp_path: Path) -> None:
    """Verify invalid IOCs are captured, rejected from persistence, and reported in summary."""
    feed_path = tmp_path / "mixed.csv"
    feed_path.write_text(
        "type,indicator,description\n"
        "ipv4,192.0.2.1,valid ip\n"
        "ipv4,999.999.999.999,invalid ip\n"
        "domain,malicious.example.com,valid domain\n",
        encoding="utf-8",
    )

    pipeline = ThreatIntelligencePipeline(db_path=temp_db_path)
    result = pipeline.run(files=[feed_path])

    assert result.success is True
    assert result.total_candidates == 3
    assert result.valid_indicators == 2
    assert result.invalid_indicators == 1
    assert len(result.invalid_candidate_samples) == 1
    assert result.invalid_candidate_samples[0]["value"] == "999.999.999.999"

    # Only 2 valid indicators persisted
    db = DatabaseManager(db_path=temp_db_path)
    assert db.get_statistics()["total_indicators"] == 2
    db.close()


def test_pipeline_missing_file_isolation(temp_db_path: Path) -> None:
    """Verify failure in one feed does not prevent other valid feeds from processing."""
    valid_file = SAMPLES_DIR / "sample_feed.csv"
    missing_file = SAMPLES_DIR / "does_not_exist_404.csv"

    pipeline = ThreatIntelligencePipeline(db_path=temp_db_path)
    result = pipeline.run(files=[missing_file, valid_file])

    assert result.success is True  # Operational success: valid file was ingested
    assert result.feeds_supplied == 2
    assert result.successful_feeds == 1
    assert result.failed_feeds == 1
    assert len(result.failed_feed_details) == 1
    assert "does_not_exist_404.csv" in result.failed_feed_details[0]["source_location"]
    assert result.new_database_records == 9


def test_pipeline_all_files_missing(temp_db_path: Path, tmp_path: Path) -> None:
    """Verify pipeline reports failure when all supplied feeds cannot be collected."""
    missing1 = tmp_path / "nonexistent1.txt"
    missing2 = tmp_path / "nonexistent2.csv"

    pipeline = ThreatIntelligencePipeline(db_path=temp_db_path)
    result = pipeline.run(files=[missing1, missing2])

    assert result.success is False
    assert result.feeds_supplied == 2
    assert result.successful_feeds == 0
    assert result.failed_feeds == 2
    assert result.total_candidates == 0


def test_pipeline_empty_feed_handling(temp_db_path: Path, tmp_path: Path) -> None:
    """Verify empty feed is safely handled without raising exceptions."""
    empty_file = tmp_path / "empty.txt"
    empty_file.write_text("", encoding="utf-8")

    pipeline = ThreatIntelligencePipeline(db_path=temp_db_path)
    result = pipeline.run(files=[empty_file])

    assert result.success is True
    assert result.successful_feeds == 1
    assert result.total_candidates == 0
    assert result.new_database_records == 0


def test_pipeline_malformed_json_handling(temp_db_path: Path, tmp_path: Path) -> None:
    """Verify malformed JSON feed is handled gracefully without crashing."""
    broken_json = tmp_path / "broken.json"
    broken_json.write_text("{not valid json: true", encoding="utf-8")

    valid_csv = SAMPLES_DIR / "sample_feed.csv"

    pipeline = ThreatIntelligencePipeline(db_path=temp_db_path)
    result = pipeline.run(files=[broken_json, valid_csv])

    assert result.success is True
    assert result.successful_feeds == 2  # Read as raw text, but JSON parsing in parser handles error gracefully
    assert result.valid_indicators == 9  # Only valid CSV parsed


def test_pipeline_remote_url_mocked(temp_db_path: Path) -> None:
    """Verify pipeline successfully ingests remote HTTP/HTTPS feed with mocked network layer."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.raise_for_status.return_value = None
    mock_response.encoding = "utf-8"
    mock_response.headers = {"Content-Type": "text/plain", "Content-Length": "100"}
    mock_response.iter_content.return_value = [b"198.51.100.1\n", b"198.51.100.2\n"]

    pipeline = ThreatIntelligencePipeline(db_path=temp_db_path)

    with patch("modules.feed_collector.requests.get") as mock_get:
        mock_get.return_value.__enter__.return_value = mock_response
        result = pipeline.run(urls=["https://threat-intel.example.com/daily.txt"])

    assert result.success is True
    assert result.successful_feeds == 1
    assert result.total_candidates == 2
    assert result.new_database_records == 2


def test_pipeline_feed_ingestion_audit_records(temp_db_path: Path, tmp_path: Path) -> None:
    """Verify feed_ingestion_runs table captures audit records for both successful and failed feeds."""
    valid_file = SAMPLES_DIR / "sample_feed.csv"
    missing_file = tmp_path / "missing.txt"

    pipeline = ThreatIntelligencePipeline(db_path=temp_db_path)
    pipeline.run(files=[valid_file, missing_file])

    db = DatabaseManager(db_path=temp_db_path)
    runs = db.get_feed_runs()
    assert len(runs) == 2

    success_run = next(r for r in runs if r["success"] == 1)
    assert "sample_feed.csv" in success_run["source_location"]
    assert success_run["indicators_extracted"] == 9

    failed_run = next(r for r in runs if r["success"] == 0)
    assert "missing.txt" in failed_run["source_location"]
    assert failed_run["indicators_extracted"] == 0
    assert failed_run["error_message"] != ""
    db.close()


def test_pipeline_no_unexpected_network_access_for_local_files(
    temp_db_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify complete local pipeline executes with zero network connections."""
    import socket

    def broken_socket(*args, **kwargs):
        raise RuntimeError("Prohibited network call made during local pipeline execution!")

    monkeypatch.setattr(socket, "socket", broken_socket)

    csv_file = SAMPLES_DIR / "sample_feed.csv"
    pipeline = ThreatIntelligencePipeline(db_path=temp_db_path)
    result = pipeline.run(files=[csv_file])

    assert result.success is True
    assert result.new_database_records == 9


def test_pipeline_cli_execution(temp_db_path: Path) -> None:
    """Verify execution of python main.py pipeline with repeatable --file arguments."""
    main_py = BASE_DIR / "main.py"
    csv_file = SAMPLES_DIR / "sample_feed.csv"
    txt_file = SAMPLES_DIR / "sample_feed.txt"

    cmd = [
        sys.executable,
        str(main_py),
        "--db",
        str(temp_db_path),
        "pipeline",
        "--file",
        str(csv_file),
        "--file",
        str(txt_file),
    ]

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 0
    assert "THREAT INTELLIGENCE END-TO-END PIPELINE" in proc.stdout
    assert "PIPELINE EXECUTION SUMMARY" in proc.stdout
    assert "Feeds Supplied:           2" in proc.stdout
    assert "Successful Feeds:         2" in proc.stdout
    assert "Pipeline completed successfully." in proc.stdout

    # Verify DB has 22 unique indicators (9 from CSV + 15 from TXT - 2 shared duplicates)
    db = DatabaseManager(db_path=temp_db_path)
    assert db.get_statistics()["total_indicators"] == 22
    db.close()


def test_pipeline_cli_all_fail_exit_code(temp_db_path: Path, tmp_path: Path) -> None:
    """Verify pipeline returns exit code 1 when all supplied feeds fail."""
    main_py = BASE_DIR / "main.py"
    cmd = [
        sys.executable,
        str(main_py),
        "--db",
        str(temp_db_path),
        "pipeline",
        "--file",
        str(tmp_path / "nonexistent.txt"),
    ]

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 1
    assert "all supplied feeds failed" in proc.stdout


def test_pipeline_downstream_reports_and_blocklists(temp_db_path: Path, tmp_path: Path) -> None:
    """Verify --generate-report and --generate-blocklists flags trigger downstream artifacts."""
    main_py = BASE_DIR / "main.py"
    csv_file = SAMPLES_DIR / "sample_feed.csv"

    cmd = [
        sys.executable,
        str(main_py),
        "--db",
        str(temp_db_path),
        "pipeline",
        "--file",
        str(csv_file),
        "--generate-report",
        "--generate-blocklists",
    ]

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 0
    assert "Generating standard categorized blocklists" in proc.stdout
    assert "Generating comprehensive analytical Markdown report" in proc.stdout
