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


def test_parse_csv_with_comment_preamble_and_trailing(parser: IOCParser) -> None:
    """Verify CSV with leading # comments and trailing comments extracts only row indicators."""
    csv_content = (
        "################################################################\n"
        "# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (CSV)          #\n"
        "# Last updated: 2026-03-04 14:28:39 UTC                        #\n"
        "#                                                              #\n"
        "# Terms Of Use: https://feodotracker.abuse.ch/blocklist/       #\n"
        "# For questions please contact feodotracker [at] abuse.ch      #\n"
        "################################################################\n"
        "#\n"
        '"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"\n'
        '"2022-06-04 21:24:53","162.243.103.246","8080","offline","2026-03-07","Emotet"\n'
        '"2025-12-30 13:56:31","50.16.16.211","443","online","2026-03-12","QakBot"\n'
        "# END 2 entries\n"
    )
    iocs = parser.parse_csv(csv_content, {"source_name": "feodo.csv"})

    assert len(iocs) == 2
    assert all(ioc.ioc_type == "ipv4" for ioc in iocs)
    values = {ioc.value for ioc in iocs}
    assert values == {"162.243.103.246", "50.16.16.211"}

    # Ensure no terms of use URLs, domains, or metadata timestamps were extracted
    assert not any(ioc.ioc_type in ("url", "domain", "email") for ioc in iocs)
    assert not any("abuse.ch" in ioc.value for ioc in iocs)

    # Verify metadata captured accurately
    emotet_ioc = next(ioc for ioc in iocs if ioc.value == "162.243.103.246")
    assert emotet_ioc.metadata.get("malware") == "Emotet"
    assert emotet_ioc.metadata.get("c2_status") == "offline"
    assert emotet_ioc.metadata.get("dst_port") == "8080"


def test_parse_csv_dst_ip_and_aliases(parser: IOCParser) -> None:
    """Verify dst_ip, src_ip, and ip_address aliases are recognized and metadata columns ignored."""
    csv_content = (
        "dst_ip,description,reference_url,timestamp\n"
        "198.51.100.99,Known C2,https://intel.example.com/report,2026-01-01 12:00:00\n"
    )
    iocs = parser.parse_csv(csv_content, {"source_name": "intel_dst.csv"})

    assert len(iocs) == 1
    assert iocs[0].ioc_type == "ipv4"
    assert iocs[0].value == "198.51.100.99"
    # Metadata URL must NOT be extracted as an indicator candidate
    assert iocs[0].metadata.get("reference_url") == "https://intel.example.com/report"


def test_parse_csv_commented_header(parser: IOCParser) -> None:
    """Verify CSV where the header line itself starts with # is parsed correctly."""
    csv_content = (
        "# General comments\n"
        "# dst_ip,dst_port,malware\n"
        "203.0.113.10,443,Dridex\n"
        "203.0.113.11,80,TrickBot\n"
    )
    iocs = parser.parse_csv(csv_content, {"source_name": "commented_hdr.csv"})

    assert len(iocs) == 2
    assert {ioc.value for ioc in iocs} == {"203.0.113.10", "203.0.113.11"}
    assert all(ioc.ioc_type == "ipv4" for ioc in iocs)


def test_parse_csv_no_header_fallback_ignores_comments(parser: IOCParser) -> None:
    """Verify CSV without standard headers falls back to text parsing without extracting comments."""
    csv_content = (
        "# Terms of Use: https://example.com/terms\n"
        "# Contact: ops@example.com\n"
        "192.0.2.1,c2_node\n"
        "192.0.2.2,drop_site\n"
    )
    iocs = parser.parse_csv(csv_content, {"source_name": "no_header.csv"})

    values = {ioc.value for ioc in iocs}
    assert "192.0.2.1" in values
    assert "192.0.2.2" in values
    # Comment URL and email must NOT be extracted
    assert "https://example.com/terms" not in values
    assert "ops@example.com" not in values
    assert "example.com" not in values


def test_parse_text_comment_filtering(parser: IOCParser) -> None:
    """Verify parse_text() does not extract URLs, domains, or emails from comment lines."""
    text_content = (
        "# ====================================================\n"
        "# Project: Threat Aggregator (https://aggregator.example.org)\n"
        "# Feedback: security@aggregator.example.org\n"
        "// Support site: https://help.example.com\n"
        "# ====================================================\n"
        "Attacker host: 198.51.100.5\n"
        "Payload url: https://evil.example.net/payload.bin\n"
        "Phish email: evil@phishdomain.com\n"
    )
    iocs = parser.parse_text(text_content, {"source_name": "intel.txt"})

    values = {ioc.value for ioc in iocs}
    # Legitimate data lines extracted
    assert "198.51.100.5" in values
    assert "https://evil.example.net/payload.bin" in values
    assert "evil@phishdomain.com" in values

    # Comment metadata MUST NOT be extracted
    assert "https://aggregator.example.org" not in values
    assert "security@aggregator.example.org" not in values
    assert "aggregator.example.org" not in values
    assert "https://help.example.com" not in values
    assert "help.example.com" not in values


def test_parse_text_preserves_url_fragments(parser: IOCParser) -> None:
    """Verify parse_text() preserves URL fragments (#section) on legitimate data lines."""
    text_content = (
        "Malicious URI: https://malware.example.com/index.html#infection_routine\n"
        "# Comment line with https://terms.example.com/#anchor\n"
    )
    iocs = parser.parse_text(text_content, {"source_name": "anchors.txt"})

    urls = [ioc.value for ioc in iocs if ioc.ioc_type == "url"]
    assert "https://malware.example.com/index.html#infection_routine" in urls
    assert not any("terms.example.com" in u for u in urls)


def test_parse_txt_comments_and_inline_metadata(parser: IOCParser) -> None:
    """Verify parse_txt() skips full-line comments and strips inline comments for IP/domain tokens."""
    txt_content = (
        "# Threat Intelligence List\n"
        "// Another comment line\n"
        "192.0.2.77 # C2 server\n"
        "2001:db8::1 // IPv6 gateway\n"
        "malware.example.com # domain\n"
    )
    iocs = parser.parse_txt(txt_content, {"source_name": "list.txt"})

    values = {ioc.value for ioc in iocs}
    assert values == {"192.0.2.77", "2001:db8::1", "malware.example.com"}


def test_parse_csv_multiline_quoted_field_with_hash(parser: IOCParser) -> None:
    """Verify multiline quoted CSV fields containing # are not treated as comments."""
    csv_content = (
        'dst_ip,threat,description\n'
        '198.51.100.22,malware,"First line of description\n'
        '# This line starts with hash inside quotes\n'
        'Third line of description"\n'
    )
    iocs = parser.parse_csv(csv_content, {"source_name": "multiline.csv"})

    assert len(iocs) == 1
    ioc = iocs[0]
    assert ioc.ioc_type == "ipv4"
    assert ioc.value == "198.51.100.22"
    assert ioc.metadata.get("threat") == "malware"
    expected_desc = "First line of description\n# This line starts with hash inside quotes\nThird line of description"
    assert ioc.metadata.get("description") == expected_desc
    # Ensure no text from description leaked as an IOC
    assert not any(i.ioc_type in ("domain", "url", "email") for i in iocs)


def test_parse_csv_escaped_double_quotes(parser: IOCParser) -> None:
    """Verify escaped double quotes ("") inside CSV fields maintain column alignment."""
    csv_content = (
        'dst_ip,category,notes\n'
        '203.0.113.88,botnet,"Operator stated: ""Do not block this host"" in ticket #42"\n'
        '203.0.113.89,c2,"Server labeled ""active"" by analyst"\n'
    )
    iocs = parser.parse_csv(csv_content, {"source_name": "escaped_quotes.csv"})

    assert len(iocs) == 2
    assert {i.value for i in iocs} == {"203.0.113.88", "203.0.113.89"}
    assert all(i.ioc_type == "ipv4" for i in iocs)

    ioc1 = next(i for i in iocs if i.value == "203.0.113.88")
    assert ioc1.metadata.get("category") == "botnet"
    assert 'Operator stated: "Do not block this host" in ticket #42' in ioc1.metadata.get("notes", "")

    ioc2 = next(i for i in iocs if i.value == "203.0.113.89")
    assert ioc2.metadata.get("category") == "c2"
    assert 'Server labeled "active" by analyst' in ioc2.metadata.get("notes", "")


def test_parse_csv_multiple_ioc_columns(parser: IOCParser) -> None:
    """Verify CSV with multiple IOC columns (src_ip and dst_ip) extracts both indicators."""
    csv_content = (
        'src_ip,dst_ip,proto,timestamp\n'
        '192.0.2.10,198.51.100.20,tcp,2026-03-04 12:00:00\n'
        '192.0.2.11,198.51.100.21,udp,2026-03-04 12:01:00\n'
    )
    iocs = parser.parse_csv(csv_content, {"source_name": "multi_cols.csv"})

    assert len(iocs) == 4
    assert all(i.ioc_type == "ipv4" for i in iocs)
    values = {i.value for i in iocs}
    assert values == {"192.0.2.10", "198.51.100.20", "192.0.2.11", "198.51.100.21"}

    # Confirm proto and timestamp are preserved in metadata and not extracted as IOCs
    assert not any(i.ioc_type in ("domain", "url", "ipv6") for i in iocs)
    ioc = next(i for i in iocs if i.value == "192.0.2.10")
    assert ioc.metadata.get("proto") == "tcp"
    assert ioc.metadata.get("timestamp") == "2026-03-04 12:00:00"

