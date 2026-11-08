"""Unit tests for the IOC Parser module (Phase 3)."""

import json
from pathlib import Path
import pytest

from config.settings import SAMPLES_DIR, SUPPORTED_IOC_TYPES
from modules.feed_collector import FeedCollector, FeedResult
from modules.ioc_parser import IOCParser, ParsedIOC


@pytest.fixture
def parser() -> IOCParser:
    """Fixture providing an IOCParser instance."""
    return IOCParser()


def test_classify_all_eight_types(parser: IOCParser) -> None:
    """Verify classify_token correctly distinguishes each of the 8 supported IOC types."""
    assert parser.classify_token("192.0.2.1") == "ipv4"
    assert parser.classify_token("2001:db8::1") == "ipv6"
    assert parser.classify_token("malicious.example.com") == "domain"
    assert parser.classify_token("https://example.com/gate.php") == "url"
    assert parser.classify_token("phish@example.net") == "email"
    assert parser.classify_token("d41d8cd98f00b204e9800998ecf8427e") == "md5"
    assert parser.classify_token("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"
    assert (
        parser.classify_token(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        == "sha256"
    )


def test_false_positive_reduction(parser: IOCParser) -> None:
    """Verify that ordinary text, filenames, and numbers are not classified as IOCs."""
    assert parser.classify_token("report.pdf") is None
    assert parser.classify_token("data.csv") is None
    assert parser.classify_token("setup.exe") is None
    assert parser.classify_token("hello_world") is None
    assert parser.classify_token("12345") is None
    assert parser.classify_token("") is None
    assert parser.classify_token("   ") is None


def test_parse_csv_header_based(parser: IOCParser) -> None:
    """Verify CSV header-based parsing with indicator and metadata columns."""
    csv_content = (
        "indicator,threat_type,confidence\n"
        "192.0.2.55,c2_server,90\n"
        "malware.example.com,c2_domain,80\n"
        "5d41402abc4b2a76b9719d911017c592,hash,70\n"
    )
    source_info = {"source_name": "test.csv", "source_type": "file", "format": "csv"}

    iocs = parser.parse_csv(csv_content, source_info)

    assert len(iocs) == 3
    types = [i.ioc_type for i in iocs]
    assert "ipv4" in types
    assert "domain" in types
    assert "md5" in types

    # Check metadata preservation
    ipv4_ioc = next(i for i in iocs if i.value == "192.0.2.55")
    assert ipv4_ioc.metadata.get("threat_type") == "c2_server"
    assert ipv4_ioc.metadata.get("confidence") == "90"
    assert ipv4_ioc.source_name == "test.csv"


def test_parse_json_array_of_objects(parser: IOCParser) -> None:
    """Verify parsing of standard JSON arrays of indicator objects."""
    json_data = [
        {"value": "198.51.100.12", "type": "ipv4", "severity": "medium"},
        {"ioc": "https://example.org/tracker", "type": "url"},
        {"indicator": "phish-alert@example.org"},
    ]
    json_content = json.dumps(json_data)
    source_info = {"source_name": "intel.json", "source_type": "file", "format": "json"}

    iocs = parser.parse_json(json_content, source_info)

    assert len(iocs) == 3
    values = {i.value for i in iocs}
    assert "198.51.100.12" in values
    assert "https://example.org/tracker" in values
    assert "phish-alert@example.org" in values

    # Check metadata preserved from json object
    ip_ioc = next(i for i in iocs if i.value == "198.51.100.12")
    assert ip_ioc.metadata.get("severity") == "medium"


def test_parse_json_nested_structure(parser: IOCParser) -> None:
    """Verify parsing of nested JSON structures with metadata headers."""
    data = {
        "feed_info": {"author": "BlueTeam"},
        "data": {
            "threats": [
                {"value": "203.0.113.88", "type": "ipv4"},
                {"value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
            ]
        },
    }
    iocs = parser.parse_json(json.dumps(data), {"source_name": "nested.json"})

    assert len(iocs) == 2
    types = {i.ioc_type for i in iocs}
    assert "ipv4" in types
    assert "sha256" in types


def test_parse_txt_lines_comments_and_blank(parser: IOCParser) -> None:
    """Verify TXT parsing ignores blank lines and comments starting with # and //."""
    txt_content = (
        "# Daily CTI Feed\n"
        "\n"
        "192.0.2.10\n"
        "// Secondary comment\n"
        "2001:db8:1::99 # IPv6 endpoint\n"
        "\n"
        "beacon.example.net\n"
    )
    source_info = {"source_name": "blocklist.txt", "source_type": "file", "format": "txt"}

    iocs = parser.parse_txt(txt_content, source_info)

    assert len(iocs) == 3
    values = {i.value for i in iocs}
    assert "192.0.2.10" in values
    assert "2001:db8:1::99" in values
    assert "beacon.example.net" in values


def test_parse_text_unstructured_and_masking(parser: IOCParser) -> None:
    """Verify raw text extraction prevents URL host substrings from duplicating as separate IPs or domains."""
    unstructured = (
        "During incident triage, host 192.0.2.77 communicated with "
        "https://198.51.100.4/malware.bin and sent email to attacker@example.org. "
        "The hash was ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad."
    )
    iocs = parser.parse_text(unstructured, {"source_name": "incident.txt"})

    values = {i.value for i in iocs}
    assert "https://198.51.100.4/malware.bin" in values
    assert "192.0.2.77" in values
    assert "attacker@example.org" in values
    assert "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" in values

    # Ensure the IP inside the URL was masked and NOT extracted as an independent duplicate IP
    assert "198.51.100.4" not in values


def test_malformed_json_handling(parser: IOCParser) -> None:
    """Verify malformed JSON does not crash the parser and returns an empty list."""
    bad_json = "{\"indicator\": \"192.0.2.1\", broken..."
    iocs = parser.parse_json(bad_json, {"source_name": "broken.json"})
    assert iocs == []


def test_empty_feeds(parser: IOCParser) -> None:
    """Verify empty feed strings across all formats return empty lists."""
    assert parser.parse_csv("", {}) == []
    assert parser.parse_json("", {}) == []
    assert parser.parse_txt("", {}) == []
    assert parser.parse_text("", {}) == []


def test_failed_feed_result_handling(parser: IOCParser) -> None:
    """Verify FeedResult with success=False is skipped safely."""
    failed_result = FeedResult(
        source_name="missing.csv",
        source_type="file",
        source_location="/missing.csv",
        format="csv",
        raw_content="",
        fetched_at="2026-11-08T00:00:00Z",
        success=False,
        error="File not found",
    )
    iocs = parser.parse_feed(failed_result)
    assert iocs == []


def test_source_provenance_preservation(parser: IOCParser) -> None:
    """Verify that multiple feeds containing the same indicator preserve separate provenance."""
    feed1 = FeedResult(
        source_name="feed_alpha.txt",
        source_type="file",
        source_location="/feed_alpha.txt",
        format="txt",
        raw_content="192.0.2.1\n",
        fetched_at="2026-11-08T10:00:00Z",
        success=True,
    )
    feed2 = FeedResult(
        source_name="feed_beta.txt",
        source_type="url",
        source_location="https://example.com/feed_beta.txt",
        format="txt",
        raw_content="192.0.2.1\n",
        fetched_at="2026-11-08T11:00:00Z",
        success=True,
    )

    all_iocs = parser.parse_many([feed1, feed2])

    assert len(all_iocs) == 2
    assert all_iocs[0].value == "192.0.2.1"
    assert all_iocs[0].source_name == "feed_alpha.txt"
    assert all_iocs[0].source_type == "file"

    assert all_iocs[1].value == "192.0.2.1"
    assert all_iocs[1].source_name == "feed_beta.txt"
    assert all_iocs[1].source_type == "url"


def test_parse_sample_feeds(parser: IOCParser) -> None:
    """Verify parsing across all three benchmark sample feeds in feeds/samples/."""
    collector = FeedCollector()
    csv_file = SAMPLES_DIR / "sample_feed.csv"
    txt_file = SAMPLES_DIR / "sample_feed.txt"
    json_file = SAMPLES_DIR / "sample_feed.json"

    feed_results = collector.collect_many([csv_file, txt_file, json_file])
    assert len(feed_results) == 3
    assert all(f.success for f in feed_results)

    iocs = parser.parse_many(feed_results)

    # Check that all 8 IOC types are represented in the extracted sample iocs
    extracted_types = {ioc.ioc_type for ioc in iocs}
    for expected_type in SUPPORTED_IOC_TYPES:
        assert (
            expected_type in extracted_types
        ), f"Missing expected IOC type: {expected_type}"

    assert len(iocs) >= 20

