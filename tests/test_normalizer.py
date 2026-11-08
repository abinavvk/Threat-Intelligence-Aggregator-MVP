"""Unit tests for the IOC Normalization and Deduplication module (Phase 5)."""

from unittest.mock import patch
import pytest

from modules.ioc_parser import ParsedIOC
from modules.normalizer import DeduplicatedIOC, IOCNormalizer, NormalizedIOC
from modules.validator import ValidationResult


@pytest.fixture
def normalizer() -> IOCNormalizer:
    """Fixture providing an IOCNormalizer instance."""
    return IOCNormalizer()


def make_validation_result(
    value: str,
    ioc_type: str,
    is_valid: bool = True,
    source_name: str = "feed_1.txt",
    source_location: str = "/feeds/feed_1.txt",
    classification: str = "normal",
    reason: str = "Valid",
) -> ValidationResult:
    """Helper to synthesize a ValidationResult for testing."""
    orig_ioc = ParsedIOC(
        value=value,
        ioc_type=ioc_type,
        source_name=source_name,
        source_type="file",
        source_location=source_location,
        feed_format="txt",
        extracted_at="2026-11-08T00:00:00Z",
        raw_value=value,
        metadata={"feed_tag": "test_tag"},
    )
    return ValidationResult(
        value=value,
        ioc_type=ioc_type,
        is_valid=is_valid,
        validation_status="valid" if is_valid else "invalid",
        reason=reason,
        classification=classification,
        source_name=source_name,
        source_location=source_location,
        validated_at="2026-11-08T00:00:01Z",
        original_ioc=orig_ioc,
    )


# --- IP Normalization Tests ---

def test_ipv4_canonical_formatting(normalizer: IOCNormalizer) -> None:
    """Verify IPv4 canonical dotted-decimal representation."""
    assert normalizer.normalize_value("192.0.2.1", "ipv4") == "192.0.2.1"
    assert normalizer.normalize_value(" 198.51.100.42 ", "ipv4") == "198.51.100.42"


def test_ipv6_compressed_canonical_formatting(normalizer: IOCNormalizer) -> None:
    """Verify IPv6 compressed lowercase notation."""
    # Full uncompressed with leading zeroes
    uncompressed = "2001:0db8:0000:0000:0000:0000:0000:0001"
    assert normalizer.normalize_value(uncompressed, "ipv6") == "2001:db8::1"

    # Uppercase hex characters
    uppercase = "2001:0DB8:ABCD:0000:0000:0000:0000:0001"
    assert normalizer.normalize_value(uppercase, "ipv6") == "2001:db8:abcd::1"


# --- Domain Normalization Tests ---

def test_domain_lowercase_and_root_dot(normalizer: IOCNormalizer) -> None:
    """Verify lowercase conversion and removal of trailing DNS root dot."""
    assert normalizer.normalize_value("EXAMPLE.COM", "domain") == "example.com"
    assert normalizer.normalize_value("Malicious.Example.Net.", "domain") == "malicious.example.net"
    assert normalizer.normalize_value("SUB.C2.ORG...", "domain") == "sub.c2.org"


def test_domain_idna_handling(normalizer: IOCNormalizer) -> None:
    """Verify internationalized domain names are normalized to standard IDNA punycode."""
    assert normalizer.normalize_value("münchen.de", "domain") == "xn--mnchen-3ya.de"
    assert normalizer.normalize_value("XN--MNCHEN-3YA.DE", "domain") == "xn--mnchen-3ya.de"


# --- URL Normalization Tests ---

def test_url_scheme_hostname_and_port_stripping(normalizer: IOCNormalizer) -> None:
    """Verify URL scheme/host lowercased and default ports 80/443 stripped."""
    # Default port 80 stripped for HTTP
    http_url = "HTTP://EXAMPLE.COM:80/gate.php?id=123"
    assert normalizer.normalize_value(http_url, "url") == "http://example.com/gate.php?id=123"

    # Default port 443 stripped for HTTPS
    https_url = "HTTPS://EXAMPLE.COM:443/download"
    assert normalizer.normalize_value(https_url, "url") == "https://example.com/download"


def test_url_non_default_port_and_path_preservation(normalizer: IOCNormalizer) -> None:
    """Verify non-default ports, paths, queries, and fragments are strictly preserved."""
    custom_url = "https://EXAMPLE.com:8443/Path/To/File.bin?token=XYZ&version=2#section"
    expected = "https://example.com:8443/Path/To/File.bin?token=XYZ&version=2#section"
    assert normalizer.normalize_value(custom_url, "url") == expected


# --- Email Normalization Tests ---

def test_email_local_part_preservation_and_domain_lowercased(normalizer: IOCNormalizer) -> None:
    """Verify email domain portion is normalized to lowercase while local-part case is preserved."""
    email = "ThreatHunter.Ops+Drop@EXAMPLE.COM."
    expected = "ThreatHunter.Ops+Drop@example.com"
    assert normalizer.normalize_value(email, "email") == expected


# --- Hash Normalization Tests ---

def test_hash_lowercase_normalization(normalizer: IOCNormalizer) -> None:
    """Verify MD5, SHA1, and SHA256 hashes are lowercased without altering characters."""
    upper_md5 = "D41D8CD98F00B204E9800998ECF8427E"
    assert normalizer.normalize_value(upper_md5, "md5") == "d41d8cd98f00b204e9800998ecf8427e"

    upper_sha1 = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
    assert normalizer.normalize_value(upper_sha1, "sha1") == "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    upper_sha256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    assert normalizer.normalize_value(upper_sha256, "sha256") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# --- Invalid & Unsupported IOC Handling ---

def test_invalid_ioc_handling(normalizer: IOCNormalizer) -> None:
    """Verify invalid ValidationResult produces NormalizedIOC with normalized_value=None."""
    invalid_res = make_validation_result("999.999.1.1", "ipv4", is_valid=False, reason="Out of range")
    norm_ioc = normalizer.normalize_ioc(invalid_res)

    assert norm_ioc.is_valid is False
    assert norm_ioc.normalized_value is None
    assert norm_ioc.normalization_status == "invalid"
    assert "Out of range" in norm_ioc.validation_reason


def test_unknown_ioc_type_handling(normalizer: IOCNormalizer) -> None:
    """Verify unknown IOC type returns original value or handles gracefully."""
    res = make_validation_result("reg_val", "windows_registry", is_valid=True)
    norm = normalizer.normalize_ioc(res)
    assert norm.normalized_value == "reg_val"


# --- Deduplication & Provenance Tests ---

def test_deduplicate_equivalent_domains(normalizer: IOCNormalizer) -> None:
    """Verify equivalent domains collapse into a single canonical form while preserving provenance."""
    v1 = make_validation_result("EXAMPLE.COM", "domain", source_name="feed_alpha")
    v2 = make_validation_result("example.com.", "domain", source_name="feed_beta")
    v3 = make_validation_result("Example.Com", "domain", source_name="feed_gamma")

    norms = normalizer.normalize_many([v1, v2, v3])
    deduped = normalizer.deduplicate(norms)

    assert len(deduped) == 1
    d = deduped[0]
    assert d.normalized_value == "example.com"
    assert d.ioc_type == "domain"
    assert d.distinct_sources_count == 3
    assert set(d.sources) == {"feed_alpha", "feed_beta", "feed_gamma"}
    assert d.total_occurrences == 3
    assert set(d.original_values) == {"EXAMPLE.COM", "example.com.", "Example.Com"}


def test_deduplicate_equivalent_ipv6(normalizer: IOCNormalizer) -> None:
    """Verify uncompressed and compressed IPv6 notations deduplicate to the same canonical form."""
    v1 = make_validation_result("2001:0db8:0000:0000:0000:0000:0000:0001", "ipv6", source_name="feed_1")
    v2 = make_validation_result("2001:db8::1", "ipv6", source_name="feed_2")

    norms = normalizer.normalize_many([v1, v2])
    deduped = normalizer.deduplicate(norms)

    assert len(deduped) == 1
    assert deduped[0].normalized_value == "2001:db8::1"
    assert deduped[0].distinct_sources_count == 2
    assert deduped[0].total_occurrences == 2


def test_different_ioc_types_remain_separate(normalizer: IOCNormalizer) -> None:
    """Verify that different IOC types with identical text do not collapse together."""
    v_ip = make_validation_result("192.0.2.1", "ipv4", source_name="feed_ips")
    v_dom = make_validation_result("192.0.2.1", "domain", is_valid=False, source_name="feed_domains")

    norms = normalizer.normalize_many([v_ip, v_dom])
    deduped = normalizer.deduplicate(norms)

    # v_dom was invalid so not in valid deduplicated list
    assert len(deduped) == 1
    assert deduped[0].ioc_type == "ipv4"


def test_same_source_multiple_occurrences_not_inflating_sources(normalizer: IOCNormalizer) -> None:
    """Verify repeated entries in the SAME feed do not inflate distinct_sources_count."""
    v1 = make_validation_result("192.0.2.1", "ipv4", source_name="firewall_log.csv")
    v2 = make_validation_result("192.0.2.1", "ipv4", source_name="firewall_log.csv")
    v3 = make_validation_result("192.0.2.1", "ipv4", source_name="firewall_log.csv")

    norms = normalizer.normalize_many([v1, v2, v3])
    deduped = normalizer.deduplicate(norms)

    assert len(deduped) == 1
    d = deduped[0]
    assert d.distinct_sources_count == 1
    assert d.total_occurrences == 3
    assert d.sources == ["firewall_log.csv"]


def test_metadata_and_records_preservation(normalizer: IOCNormalizer) -> None:
    """Verify metadata and underlying records are preserved in DeduplicatedIOC."""
    v1 = make_validation_result("192.0.2.1", "ipv4", source_name="feed_a")
    v2 = make_validation_result("192.0.2.1", "ipv4", source_name="feed_b")

    norms = normalizer.normalize_many([v1, v2])
    deduped = normalizer.deduplicate(norms)

    assert len(deduped[0].records) == 2
    assert deduped[0].records[0].metadata["feed_tag"] == "test_tag"
    assert deduped[0].records[0].metadata["classification"] == "normal"


def test_no_network_activity_during_normalization(normalizer: IOCNormalizer) -> None:
    """Verify that normalization makes zero network or DNS calls."""
    with patch("socket.gethostbyname") as mock_dns, patch("requests.get") as mock_http:
        vals = [
            make_validation_result("EXAMPLE.COM", "domain"),
            make_validation_result("https://example.com:443/test", "url"),
            make_validation_result("2001:0db8::1", "ipv6"),
        ]
        norms = normalizer.normalize_many(vals)
        normalizer.deduplicate(norms)

        mock_dns.assert_not_called()
        mock_http.assert_not_called()

