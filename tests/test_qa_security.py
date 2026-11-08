"""Phase 11: Security, Quality Assurance, and Edge Case Regression Tests.

Validates:
1. SSRF mitigation: private/loopback IP rejections, manual redirect handling, DNS rebinding prevention.
2. Verification that no HTTP request is sent to a rejected redirect destination.
3. CSV formula injection neutralization in BlocklistGenerator and ReportGenerator.
4. Database schema view compatibility (feed_runs view) and last_seen updates on observation.
5. Repeated ingestion semantics (observation count increment vs. distinct source preservation).
6. Safe handling of malformed inputs and boundary edge cases.
"""

import csv
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from modules.blocklist_generator import BlocklistGenerator
from modules.database_manager import DatabaseManager
from modules.feed_collector import FeedCollector
from modules.normalizer import NormalizedIOC
from modules.ioc_parser import ParsedIOC
from modules.pipeline import ThreatIntelligencePipeline
from modules.report_generator import ReportGenerator


def test_ssrf_mitigation_loopback_and_private_ips() -> None:
    """Verify FeedCollector rejects SSRF targets (localhost, private, link-local IPs)."""
    collector = FeedCollector()

    # 1. Loopback IP
    res1 = collector.collect_url("http://127.0.0.1/bad_feed.txt")
    assert res1.success is False
    assert "restricted" in res1.error or "SSRF" in res1.error

    # 2. Localhost hostname
    res2 = collector.collect_url("http://localhost:8080/feed.csv")
    assert res2.success is False
    assert "localhost" in res2.error

    # 3. AWS / Cloud metadata link-local address
    res3 = collector.collect_url("http://169.254.169.254/latest/meta-data")
    assert res3.success is False
    assert "link-local" in res3.error or "restricted" in res3.error or "private" in res3.error

    # 4. RFC 1918 Private range (10.0.0.0/8)
    res4 = collector.collect_url("http://10.0.0.1/internal_threats.json")
    assert res4.success is False
    assert "private" in res4.error

    # 5. RFC 1918 Private range (192.168.0.0/16)
    res5 = collector.collect_url("http://192.168.1.50:8000/feed.txt")
    assert res5.success is False
    assert "private" in res5.error


def test_ssrf_manual_redirect_to_localhost_and_no_request_sent() -> None:
    """Verify redirect to localhost is blocked and NO request is dispatched to the localhost target."""
    collector = FeedCollector()

    mock_redirect_resp = MagicMock()
    mock_redirect_resp.status_code = 302
    mock_redirect_resp.headers = {"Location": "http://127.0.0.1:8080/admin"}

    with patch("modules.feed_collector.requests.get") as mock_get:
        mock_get.return_value = mock_redirect_resp
        res = collector.collect_url("https://example.com/initial_feed.txt")

    assert res.success is False
    assert "SSRF" in res.error or "restricted" in res.error or "loopback" in res.error
    # Exactly one request made (to initial URL), and ZERO requests made to 127.0.0.1
    assert mock_get.call_count == 1
    assert mock_get.call_args[0][0] == "https://example.com/initial_feed.txt"


def test_ssrf_manual_redirect_to_private_ipv4_and_no_request_sent() -> None:
    """Verify redirect to private IPv4 address (RFC 1918) is rejected without sending a request."""
    collector = FeedCollector()

    mock_redirect_resp = MagicMock()
    mock_redirect_resp.status_code = 301
    mock_redirect_resp.headers = {"Location": "http://192.168.1.1/secret_feed.csv"}

    with patch("modules.feed_collector.requests.get") as mock_get:
        mock_get.return_value = mock_redirect_resp
        res = collector.collect_url("https://example.com/feed.csv")

    assert res.success is False
    assert "private" in res.error or "restricted" in res.error
    assert mock_get.call_count == 1


def test_ssrf_manual_redirect_to_private_ipv6_and_no_request_sent() -> None:
    """Verify redirect to private IPv6 address (fc00::/7, fd00::/8) is rejected without sending a request."""
    collector = FeedCollector()

    mock_redirect_resp = MagicMock()
    mock_redirect_resp.status_code = 307
    mock_redirect_resp.headers = {"Location": "http://[fd00::1]/internal.json"}

    with patch("modules.feed_collector.requests.get") as mock_get:
        mock_get.return_value = mock_redirect_resp
        res = collector.collect_url("https://example.com/feed.json")

    assert res.success is False
    assert "private" in res.error or "restricted" in res.error
    assert mock_get.call_count == 1


def test_ssrf_redirect_chains_exceeding_maximum() -> None:
    """Verify redirect chains exceeding max_redirects are terminated with an error."""
    collector = FeedCollector(max_redirects=3)

    def side_effect(url, **kwargs):
        mock_r = MagicMock()
        mock_r.status_code = 302
        # Redirect to next URL in loop
        mock_r.headers = {"Location": f"{url}_next"}
        return mock_r

    with patch("modules.feed_collector.requests.get", side_effect=side_effect) as mock_get:
        res = collector.collect_url("https://example.com/loop")

    assert res.success is False
    assert "Maximum redirect limit" in res.error
    # Initial request + 3 redirects = 4 requests attempted before aborting
    assert mock_get.call_count == 4


def test_ssrf_hostname_resolving_to_private_ip() -> None:
    """Verify DNS rebinding mitigation: hostname resolving to private IP is rejected before connecting."""
    collector = FeedCollector()

    # Simulate getaddrinfo returning private IP for an external hostname
    fake_addrinfo = [(2, 0, 0, "", ("10.20.30.40", 80))]

    with patch("socket.getaddrinfo", return_value=fake_addrinfo):
        with patch("modules.feed_collector.requests.get") as mock_get:
            res = collector.collect_url("https://rebinding-attack.org/feed.txt")

    assert res.success is False
    assert "private network IP address" in res.error or "SSRF" in res.error
    # No HTTP request should ever be dispatched if DNS resolves to private IP
    assert mock_get.call_count == 0


def test_ssrf_public_destinations_continue_working_with_mocked_http() -> None:
    """Verify legitimate public destinations continue working properly with mocked HTTP requests."""
    collector = FeedCollector()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status.return_value = None
    mock_resp.headers = {"Content-Type": "text/plain", "Content-Length": "20"}
    mock_resp.encoding = "utf-8"
    mock_resp.iter_content.return_value = [b"198.51.100.1\n"]

    with patch("modules.feed_collector.requests.get", return_value=mock_resp) as mock_get:
        res = collector.collect_url("https://example.com/feed.txt")

    assert res.success is True
    assert "198.51.100.1" in res.raw_content
    assert mock_get.call_count == 1
    # Verify allow_redirects=False was passed
    assert mock_get.call_args[1].get("allow_redirects") is False


def test_ssrf_allow_private_networks_override() -> None:
    """Verify allow_private_networks=True allows lab or internal feed collection when explicitly enabled."""
    collector = FeedCollector(allow_private_networks=True)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status.return_value = None
    mock_resp.headers = {"Content-Type": "text/plain"}
    mock_resp.encoding = "utf-8"
    mock_resp.iter_content.return_value = [b"198.51.100.1\n"]

    with patch("modules.feed_collector.requests.get", return_value=mock_resp):
        res = collector.collect_url("http://127.0.0.1/feed.txt")

    assert res.success is True
    assert "198.51.100.1" in res.raw_content


def test_csv_formula_injection_mitigation_in_blocklists(tmp_path: Path) -> None:
    """Verify CSV export prepends a single quote to cells beginning with formula operators (=, +, -, @)."""
    db_path = tmp_path / "formula_test.db"
    out_dir = tmp_path / "blocklists"
    db = DatabaseManager(db_path=db_path)
    db.initialize_database()

    # Insert malicious indicators that attempt CSV formula execution
    s_id = db.insert_source("malicious_feed", "file", "feed.csv", "csv")
    formula_val = "=cmd|'/C calc'!A0"
    ind_id, _ = db.insert_indicator("domain", formula_val)
    db.insert_observation(ind_id, s_id, formula_val)

    generator = BlocklistGenerator(db_manager=db, output_dir=out_dir)
    results = generator.generate_blocklist(ioc_type="domain", format_type="csv")
    assert len(results) == 1
    csv_file = results[0].file_path

    with open(csv_file, "r", encoding="utf-8") as f:
        content = f.read()

    # The indicator should be escaped with a single quote: '=cmd|...
    assert "'=cmd|'/C calc'!A0" in content
    # It must not start raw as '=cmd|'
    assert "\n=cmd|" not in content
    db.close()


def test_csv_formula_injection_mitigation_in_reports(tmp_path: Path) -> None:
    """Verify ReportGenerator escapes formula trigger characters in CSV report exports."""
    db_path = tmp_path / "report_formula_test.db"
    out_dir = tmp_path / "reports"
    db = DatabaseManager(db_path=db_path)
    db.initialize_database()

    s_id = db.insert_source("@source_calc", "file", "feed.csv", "csv")
    formula_ioc = "+SUM(1,2)"
    ind_id, _ = db.insert_indicator("domain", formula_ioc)
    db.insert_observation(ind_id, s_id, formula_ioc)

    report_gen = ReportGenerator(db_manager=db, output_dir=out_dir)
    result = report_gen.generate_report(format_type="csv")

    with open(result.file_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "'+SUM(1,2)" in content
    assert "'@source_calc" in content
    db.close()


def test_ssrf_ipv4_mapped_ipv6_rejection() -> None:
    """Verify FeedCollector rejects IPv4-mapped IPv6 addresses for loopback, private, and link-local ranges."""
    collector = FeedCollector()

    res1 = collector.collect_url("http://[::ffff:127.0.0.1]/feed.txt")
    assert res1.success is False
    assert "restricted" in res1.error or "SSRF" in res1.error

    res2 = collector.collect_url("http://[::ffff:10.0.0.1]/feed.txt")
    assert res2.success is False
    assert "private" in res2.error

    res3 = collector.collect_url("http://[::ffff:169.254.169.254]/feed.txt")
    assert res3.success is False
    assert "restricted" in res3.error or "SSRF" in res3.error


def test_ssrf_multiple_dns_answers_with_prohibited_ip() -> None:
    """Verify that if DNS returns multiple IP addresses and any one is prohibited, it is rejected."""
    collector = FeedCollector()
    fake_addrinfo = [
        (2, 0, 0, "", ("93.184.215.14", 80)),
        (2, 0, 0, "", ("127.0.0.1", 80)),
    ]

    with patch("socket.getaddrinfo", return_value=fake_addrinfo):
        with patch("modules.feed_collector.requests.get") as mock_get:
            res = collector.collect_url("https://dual-homed-attack.org/feed.txt")

    assert res.success is False
    assert "loopback" in res.error or "SSRF" in res.error
    assert mock_get.call_count == 0


def test_feed_runs_view_and_summary_aliases(tmp_path: Path) -> None:
    """Verify feed_runs SQLite view works and get_feed_runs_summary alias is functional."""
    db_path = tmp_path / "audit_test.db"
    db = DatabaseManager(db_path=db_path)
    db.initialize_database()

    # Record a feed run
    db.record_feed_run(
        source_location="test_feed.csv",
        source_name="test_feed",
        feed_format="csv",
        success=True,
        indicators_extracted=10,
        error_message=None,
    )

    # Query using the compatibility view
    conn = db.get_connection()
    cursor = conn.execute("SELECT * FROM feed_runs")
    rows = cursor.fetchall()
    assert len(rows) == 1
    assert rows[0]["source_name"] == "test_feed"

    # Test alias
    summary = db.get_feed_runs_summary()
    assert summary["has_history"] is True
    assert summary["total_runs"] == 1
    assert summary["successful_runs"] == 1
    db.close()


def test_repeated_ingestion_semantics_and_last_seen_update(tmp_path: Path) -> None:
    """Verify repeated ingestion increments observations while preserving distinct sources and updating last_seen."""
    db_path = tmp_path / "repeat_test.db"
    db = DatabaseManager(db_path=db_path)
    db.initialize_database()

    t1 = "2026-11-01T00:00:00Z"
    t2 = "2026-11-08T12:00:00Z"

    # 1. First observation from source 1
    s1 = db.insert_source("feed_alpha", "file", "alpha.csv", "csv", first_seen=t1)
    ind_id, is_new = db.insert_indicator("ipv4", "198.51.100.1", observed_at=t1)
    assert is_new is True
    db.insert_observation(ind_id, s1, "198.51.100.1", observed_at=t1)

    rec1 = db.get_indicator_by_id(ind_id)
    assert rec1 is not None
    assert rec1["distinct_sources_count"] == 1
    assert rec1["total_occurrences"] == 1
    assert rec1["severity"] == "LOW"
    assert rec1["first_seen"] == t1
    assert rec1["last_seen"] == t1

    # 2. Repeated observation from SAME source at later time t2
    db.insert_observation(ind_id, s1, "198.51.100.1", observed_at=t2)

    rec2 = db.get_indicator_by_id(ind_id)
    assert rec2 is not None
    # Observations incremented
    assert rec2["total_occurrences"] == 2
    # Distinct sources NOT inflated
    assert rec2["distinct_sources_count"] == 1
    # Severity NOT inflated
    assert rec2["severity"] == "LOW"
    # Timestamps updated properly
    assert rec2["first_seen"] == t1
    assert rec2["last_seen"] == t2

    # 3. New observation from DIFFERENT source (feed_beta) at t2
    s2 = db.insert_source("feed_beta", "file", "beta.txt", "txt", first_seen=t2)
    db.insert_observation(ind_id, s2, "198.51.100.1", observed_at=t2)

    rec3 = db.get_indicator_by_id(ind_id)
    assert rec3 is not None
    assert rec3["total_occurrences"] == 3
    assert rec3["distinct_sources_count"] == 2
    assert rec3["severity"] == "MEDIUM"  # Promoted to MEDIUM due to >= 2 sources
    db.close()
