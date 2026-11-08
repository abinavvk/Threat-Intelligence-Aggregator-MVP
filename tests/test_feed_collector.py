"""Unit tests for the Feed Collector module (Phase 2)."""

from datetime import datetime
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from config.settings import SAMPLES_DIR
from modules.feed_collector import FeedCollector, FeedResult


@pytest.fixture
def collector() -> FeedCollector:
    """Fixture providing a default FeedCollector instance."""
    return FeedCollector(timeout=5, max_size_bytes=1024 * 1024)


def test_collect_csv_file_success(collector: FeedCollector, tmp_path: Path) -> None:
    """Test successful collection of a local CSV feed."""
    csv_file = tmp_path / "test_feed.csv"
    csv_file.write_text("indicator,type\n192.0.2.1,ipv4\n", encoding="utf-8")

    result = collector.collect_file(csv_file)

    assert result.success is True
    assert result.format == "csv"
    assert result.source_type == "file"
    assert result.source_name == "test_feed.csv"
    assert "192.0.2.1" in result.raw_content
    assert result.error == ""
    assert isinstance(result.fetched_at, str)


def test_collect_txt_file_success(collector: FeedCollector, tmp_path: Path) -> None:
    """Test successful collection of a local TXT feed."""
    txt_file = tmp_path / "test_feed.txt"
    txt_file.write_text("# Blocklist\n198.51.100.1\nexample.com\n", encoding="utf-8")

    result = collector.collect_file(txt_file)

    assert result.success is True
    assert result.format == "txt"
    assert result.source_type == "file"
    assert result.source_name == "test_feed.txt"
    assert "198.51.100.1" in result.raw_content
    assert result.error == ""


def test_collect_json_file_success(collector: FeedCollector, tmp_path: Path) -> None:
    """Test successful collection of a local JSON feed."""
    json_file = tmp_path / "test_feed.json"
    sample_data = {"indicators": [{"value": "203.0.113.5", "type": "ipv4"}]}
    json_file.write_text(json.dumps(sample_data), encoding="utf-8")

    result = collector.collect_file(json_file)

    assert result.success is True
    assert result.format == "json"
    assert result.source_type == "file"
    assert result.source_name == "test_feed.json"
    assert "203.0.113.5" in result.raw_content
    assert result.error == ""


def test_collect_missing_file(collector: FeedCollector, tmp_path: Path) -> None:
    """Test graceful handling when a specified local file does not exist."""
    missing_file = tmp_path / "non_existent_feed.csv"

    result = collector.collect_file(missing_file)

    assert result.success is False
    assert "File not found" in result.error
    assert result.raw_content == ""
    assert result.source_type == "file"


def test_collect_unsupported_file_extension(collector: FeedCollector, tmp_path: Path) -> None:
    """Test rejection of unsupported file extensions (e.g. .exe, .yaml, .pdf)."""
    bad_file = tmp_path / "malicious_payload.exe"
    bad_file.write_text("MZ...", encoding="utf-8")

    result = collector.collect_file(bad_file)

    assert result.success is False
    assert "Unsupported file extension" in result.error
    assert result.raw_content == ""


def test_collect_empty_file(collector: FeedCollector, tmp_path: Path) -> None:
    """Test handling of an empty local file (empty raw_content, success True)."""
    empty_file = tmp_path / "empty_feed.txt"
    empty_file.write_text("", encoding="utf-8")

    result = collector.collect_file(empty_file)

    assert result.success is True
    assert result.raw_content == ""
    assert result.format == "txt"
    assert result.error == ""


def test_collect_file_exceeding_max_size(tmp_path: Path) -> None:
    """Test that a file exceeding max_size_bytes is safely rejected."""
    tiny_collector = FeedCollector(max_size_bytes=50)
    large_file = tmp_path / "large_feed.txt"
    large_file.write_text("A" * 100, encoding="utf-8")

    result = tiny_collector.collect_file(large_file)

    assert result.success is False
    assert "exceeds maximum safety limit" in result.error
    assert result.raw_content == ""


@patch("modules.feed_collector.requests.get")
def test_collect_url_success(mock_get: MagicMock, collector: FeedCollector) -> None:
    """Test successful URL collection using mocked HTTP response."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status.return_value = None
    mock_resp.headers = {"Content-Type": "text/plain"}
    mock_resp.encoding = "utf-8"
    mock_resp.iter_content.return_value = [b"192.0.2.1\n", b"198.51.100.2\n"]
    mock_get.return_value.__enter__.return_value = mock_resp

    test_url = "https://example.com/feeds/ip_blocklist.txt"
    result = collector.collect_url(test_url)

    assert result.success is True
    assert result.source_type == "url"
    assert result.source_location == test_url
    assert result.format == "txt"
    assert "192.0.2.1" in result.raw_content
    assert result.error == ""


@patch("modules.feed_collector.requests.get")
def test_collect_url_http_error(mock_get: MagicMock, collector: FeedCollector) -> None:
    """Test HTTP 404/500 error handling during URL collection."""
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "404 Client Error: Not Found", response=mock_resp
    )
    mock_get.return_value.__enter__.return_value = mock_resp

    test_url = "https://example.com/feeds/missing.json"
    result = collector.collect_url(test_url)

    assert result.success is False
    assert "HTTP Error 404" in result.error
    assert result.raw_content == ""


@patch("modules.feed_collector.requests.get")
def test_collect_url_timeout(mock_get: MagicMock, collector: FeedCollector) -> None:
    """Test request timeout during URL collection."""
    mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")

    test_url = "https://example.com/feeds/slow.txt"
    result = collector.collect_url(test_url)

    assert result.success is False
    assert "Network timeout" in result.error
    assert result.raw_content == ""


def test_collect_url_invalid_or_unsupported_scheme(collector: FeedCollector) -> None:
    """Test rejection of non-HTTP schemes (ftp, file, gopher, etc.) and malformed URLs."""
    ftp_result = collector.collect_url("ftp://example.com/feed.txt")
    assert ftp_result.success is False
    assert "Unsupported URL scheme 'ftp'" in ftp_result.error

    file_result = collector.collect_url("file:///etc/passwd")
    assert file_result.success is False
    assert "Unsupported URL scheme 'file'" in file_result.error

    bad_url = collector.collect_url("not_a_valid_url")
    assert bad_url.success is False
    assert "Unsupported URL scheme" in bad_url.error


@patch("modules.feed_collector.requests.get")
def test_collect_url_streaming_size_limit(mock_get: MagicMock) -> None:
    """Test that stream download aborts if content exceeds max_size_bytes."""
    tiny_collector = FeedCollector(max_size_bytes=100)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status.return_value = None
    mock_resp.headers = {}
    mock_resp.iter_content.return_value = [b"A" * 60, b"B" * 60]
    mock_get.return_value.__enter__.return_value = mock_resp

    result = tiny_collector.collect_url("https://example.com/feed.txt")

    assert result.success is False
    assert "exceeded maximum limit" in result.error
    assert result.raw_content == ""


@patch("modules.feed_collector.requests.get")
def test_collect_many_partial_failure(
    mock_get: MagicMock, collector: FeedCollector, tmp_path: Path
) -> None:
    """Test that collect_many handles multiple feeds where one fails and others succeed."""
    good_file = tmp_path / "valid.txt"
    good_file.write_text("192.0.2.1", encoding="utf-8")
    missing_file = tmp_path / "absent.csv"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status.return_value = None
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.encoding = "utf-8"
    mock_resp.iter_content.return_value = [b'{"threats": []}']
    mock_get.return_value.__enter__.return_value = mock_resp

    sources = [str(good_file), str(missing_file), "https://example.com/threats.json"]
    results = collector.collect_many(sources)

    assert len(results) == 3
    assert results[0].success is True
    assert results[0].format == "txt"

    assert results[1].success is False
    assert "File not found" in results[1].error

    assert results[2].success is True
    assert results[2].format == "json"


def test_collect_samples_directory_feeds(collector: FeedCollector) -> None:
    """Test collection of the synthetic benchmark samples created in feeds/samples/."""
    csv_sample = SAMPLES_DIR / "sample_feed.csv"
    txt_sample = SAMPLES_DIR / "sample_feed.txt"
    json_sample = SAMPLES_DIR / "sample_feed.json"

    assert csv_sample.exists()
    assert txt_sample.exists()
    assert json_sample.exists()

    res_csv = collector.collect_file(csv_sample)
    assert res_csv.success is True
    assert "192.0.2.15" in res_csv.raw_content

    res_txt = collector.collect_file(txt_sample)
    assert res_txt.success is True
    assert "192.0.2.100" in res_txt.raw_content

    res_json = collector.collect_file(json_sample)
    assert res_json.success is True
    assert "192.0.2.200" in res_json.raw_content


def test_feed_result_metadata_and_timestamps(collector: FeedCollector, tmp_path: Path) -> None:
    """Test FeedResult contains valid ISO 8601 UTC timestamp and correct metadata dict."""
    test_file = tmp_path / "meta_test.csv"
    test_file.write_text("test", encoding="utf-8")

    result = collector.collect_file(test_file)
    as_dict = result.to_dict()

    assert as_dict["source_name"] == "meta_test.csv"
    assert as_dict["source_type"] == "file"
    assert as_dict["format"] == "csv"
    assert as_dict["success"] is True

    # Validate ISO 8601 timestamp parsing
    dt = datetime.fromisoformat(result.fetched_at)
    assert dt.tzinfo is not None

