"""Unit tests for the IOC Validator module (Phase 4)."""

from unittest.mock import patch
import pytest

from modules.ioc_parser import ParsedIOC
from modules.validator import IOCValidator, ValidationResult


@pytest.fixture
def validator() -> IOCValidator:
    """Fixture providing an IOCValidator instance."""
    return IOCValidator()


def create_sample_ioc(value: str, ioc_type: str, source_name: str = "test_feed.txt") -> ParsedIOC:
    """Helper to create test ParsedIOC objects."""
    return ParsedIOC(
        value=value,
        ioc_type=ioc_type,
        source_name=source_name,
        source_type="file",
        source_location=f"/feeds/{source_name}",
        feed_format="txt",
        extracted_at="2026-11-08T00:00:00Z",
        raw_value=value,
    )


# --- IPv4 Tests ---

def test_validate_ipv4_valid_public(validator: IOCValidator) -> None:
    """Verify validation and classification of public IPv4 addresses."""
    is_valid, reason, classification = validator.validate_ipv4("8.8.8.8")
    assert is_valid is True
    assert classification == "normal"
    assert "routable public" in reason


def test_validate_ipv4_out_of_range(validator: IOCValidator) -> None:
    """Verify rejection of IPv4 addresses with octets > 255."""
    is_valid, reason, classification = validator.validate_ipv4("256.100.0.1")
    assert is_valid is False
    assert classification == "unknown"
    assert "Invalid IPv4" in reason


def test_validate_ipv4_private(validator: IOCValidator) -> None:
    """Verify RFC 1918 private IPv4 classifications."""
    for ip_str in ("10.0.0.1", "172.16.50.1", "192.168.1.100"):
        is_valid, _, classification = validator.validate_ipv4(ip_str)
        assert is_valid is True
        assert classification == "private"


def test_validate_ipv4_loopback(validator: IOCValidator) -> None:
    """Verify loopback IPv4 classification."""
    is_valid, _, classification = validator.validate_ipv4("127.0.0.1")
    assert is_valid is True
    assert classification == "loopback"


def test_validate_ipv4_documentation(validator: IOCValidator) -> None:
    """Verify RFC 5737 documentation networks (TEST-NET-1, 2, 3) classification."""
    for doc_ip in ("192.0.2.1", "198.51.100.55", "203.0.113.200"):
        is_valid, reason, classification = validator.validate_ipv4(doc_ip)
        assert is_valid is True
        assert classification == "documentation"
        assert "RFC 5737" in reason


# --- IPv6 Tests ---

def test_validate_ipv6_valid_public(validator: IOCValidator) -> None:
    """Verify validation of public IPv6 addresses."""
    is_valid, _, classification = validator.validate_ipv6("2607:f8b0:4005:805::200e")
    assert is_valid is True
    assert classification == "normal"


def test_validate_ipv6_documentation(validator: IOCValidator) -> None:
    """Verify RFC 3849 IPv6 documentation prefix classification."""
    is_valid, reason, classification = validator.validate_ipv6("2001:db8::8a2e:370:7334")
    assert is_valid is True
    assert classification == "documentation"
    assert "RFC 3849" in reason


def test_validate_ipv6_loopback(validator: IOCValidator) -> None:
    """Verify IPv6 loopback address (::1)."""
    is_valid, _, classification = validator.validate_ipv6("::1")
    assert is_valid is True
    assert classification == "loopback"


def test_validate_ipv6_invalid(validator: IOCValidator) -> None:
    """Verify rejection of malformed IPv6 strings."""
    is_valid, reason, _ = validator.validate_ipv6("2001:xyz::1")
    assert is_valid is False
    assert "Invalid IPv6" in reason


# --- Domain Tests ---

def test_validate_domain_valid(validator: IOCValidator) -> None:
    """Verify validation of standard FQDN domains."""
    for dom in ("example.com", "sub.c2-server.example.net", "threat-intel.co.uk"):
        is_valid, _, classification = validator.validate_domain(dom)
        assert is_valid is True
        assert classification == "normal"


def test_validate_domain_rejections(validator: IOCValidator) -> None:
    """Verify rejection of invalid domain labels, hyphens, and IP representations."""
    # Label starts with hyphen
    assert validator.validate_domain("-bad.example.com")[0] is False
    # Label ends with hyphen
    assert validator.validate_domain("bad-.example.com")[0] is False
    # Consecutive dots / empty label
    assert validator.validate_domain("bad..com")[0] is False
    # IP address mistaken as domain
    is_valid, reason, _ = validator.validate_domain("192.0.2.1")
    assert is_valid is False
    assert "Value is an IP address" in reason
    # TLD is single char or numeric
    assert validator.validate_domain("example.1")[0] is False
    assert validator.validate_domain("example.a")[0] is False


def test_validate_domain_length_limits(validator: IOCValidator) -> None:
    """Verify rejection of label > 63 chars or total domain > 253 chars."""
    long_label = "a" * 64 + ".com"
    assert validator.validate_domain(long_label)[0] is False

    long_domain = ".".join(["a" * 60] * 5)  # 304 chars
    assert validator.validate_domain(long_domain)[0] is False


# --- URL Tests ---

def test_validate_url_valid(validator: IOCValidator) -> None:
    """Verify validation of valid HTTP and HTTPS URLs."""
    urls = [
        "https://example.com/gate.php?id=123",
        "http://192.0.2.1/malware.bin",
        "https://sub.threat.org:8443/download",
    ]
    for u in urls:
        is_valid, _, classification = validator.validate_url(u)
        assert is_valid is True
        assert classification == "normal"


def test_validate_url_unsupported_schemes(validator: IOCValidator) -> None:
    """Verify rejection of non-HTTP schemes."""
    for bad_url in ("ftp://example.com/file.txt", "file:///etc/shadow", "gopher://host/"):
        is_valid, reason, _ = validator.validate_url(bad_url)
        assert is_valid is False
        assert "Unsupported URL scheme" in reason


def test_validate_url_missing_host(validator: IOCValidator) -> None:
    """Verify rejection of URLs lacking a valid host."""
    is_valid, _, _ = validator.validate_url("http://")
    assert is_valid is False


# --- Email Tests ---

def test_validate_email_valid(validator: IOCValidator) -> None:
    """Verify validation of standard email syntax."""
    emails = ["alert@example.com", "phish.team+drop@example.org", "fraud_alert@domain.co.uk"]
    for em in emails:
        is_valid, _, classification = validator.validate_email(em)
        assert is_valid is True
        assert classification == "normal"


def test_validate_email_invalid(validator: IOCValidator) -> None:
    """Verify rejection of malformed email addresses."""
    assert validator.validate_email("no_at_sign.com")[0] is False
    assert validator.validate_email("two@@example.com")[0] is False
    assert validator.validate_email(".leadingdot@example.com")[0] is False
    assert validator.validate_email("user@bad_domain")[0] is False


# --- Hash Tests ---

def test_validate_hash_md5(validator: IOCValidator) -> None:
    """Verify MD5 32-character hexadecimal validation."""
    valid_md5 = "d41d8cd98f00b204e9800998ecf8427e"
    assert validator.validate_hash(valid_md5, "md5")[0] is True

    # 31 chars
    assert validator.validate_hash(valid_md5[:31], "md5")[0] is False
    # Non-hex char ('g')
    assert validator.validate_hash("g" + valid_md5[1:], "md5")[0] is False


def test_validate_hash_sha1(validator: IOCValidator) -> None:
    """Verify SHA1 40-character hexadecimal validation."""
    valid_sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert validator.validate_hash(valid_sha1, "sha1")[0] is True
    # 39 chars
    assert validator.validate_hash(valid_sha1[:39], "sha1")[0] is False
    # Non-hex
    assert validator.validate_hash("z" * 40, "sha1")[0] is False


def test_validate_hash_sha256(validator: IOCValidator) -> None:
    """Verify SHA256 64-character hexadecimal validation."""
    valid_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert validator.validate_hash(valid_sha256, "sha256")[0] is True
    # 63 chars
    assert validator.validate_hash(valid_sha256[:63], "sha256")[0] is False
    # Non-hex
    assert validator.validate_hash(valid_sha256[:-1] + "G", "sha256")[0] is False


# --- Bulk & Provenance Tests ---

def test_unknown_ioc_type_handling(validator: IOCValidator) -> None:
    """Verify graceful rejection when ParsedIOC has an unhandled IOC type."""
    bad_type_ioc = create_sample_ioc("something", "registry_key")
    result = validator.validate_ioc(bad_type_ioc)
    assert result.is_valid is False
    assert result.validation_status == "invalid"
    assert "Unknown or unsupported" in result.reason
    assert result.classification == "unknown"


def test_bulk_validation_and_provenance(validator: IOCValidator) -> None:
    """Verify validate_many processes mixed valid/invalid candidates and preserves provenance."""
    iocs = [
        create_sample_ioc("192.0.2.1", "ipv4", "feed_a.txt"),
        create_sample_ioc("999.999.1.1", "ipv4", "feed_b.txt"),
        create_sample_ioc("example.com", "domain", "feed_c.txt"),
        create_sample_ioc("bad..domain", "domain", "feed_d.txt"),
    ]

    results = validator.validate_many(iocs)

    assert len(results) == 4
    assert results[0].is_valid is True
    assert results[0].classification == "documentation"
    assert results[0].source_name == "feed_a.txt"

    assert results[1].is_valid is False
    assert results[1].source_name == "feed_b.txt"

    assert results[2].is_valid is True
    assert results[2].source_name == "feed_c.txt"

    assert results[3].is_valid is False
    assert results[3].source_name == "feed_d.txt"


def test_no_network_activity_during_validation(validator: IOCValidator) -> None:
    """Verify that validation does not perform any network calls (DNS or HTTP)."""
    with patch("socket.gethostbyname") as mock_dns, patch("requests.get") as mock_http:
        iocs = [
            create_sample_ioc("192.0.2.1", "ipv4"),
            create_sample_ioc("malicious.example.com", "domain"),
            create_sample_ioc("https://example.com/path", "url"),
            create_sample_ioc("test@example.org", "email"),
        ]
        validator.validate_many(iocs)

        mock_dns.assert_not_called()
        mock_http.assert_not_called()

