"""IOC Validator module for Threat Intelligence Aggregator.

Performs deterministic, RFC-compliant syntactic and structural validation across
all eight supported IOC types (IPv4, IPv6, Domain, URL, Email, MD5, SHA1, SHA256).
Categorizes IP addresses into standard Blue Team network classifications (normal,
private, documentation, loopback, reserved, special) without performing any DNS
queries, network transmissions, or code execution.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import logging
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from modules.ioc_parser import ParsedIOC

logger = logging.getLogger(__name__)

# Documentation IP networks defined by IETF RFCs
DOC_NETWORKS_V4 = [
    ipaddress.IPv4Network("192.0.2.0/24"),      # TEST-NET-1 (RFC 5737)
    ipaddress.IPv4Network("198.51.100.0/24"),  # TEST-NET-2 (RFC 5737)
    ipaddress.IPv4Network("203.0.113.0/24"),   # TEST-NET-3 (RFC 5737)
]
DOC_NETWORK_V6 = ipaddress.IPv6Network("2001:db8::/32")  # Documentation IPv6 (RFC 3849)

# Standard classification categories
VALID_STATUSES = ("valid", "invalid")
CLASSIFICATIONS = (
    "normal",
    "private",
    "reserved",
    "loopback",
    "documentation",
    "special",
    "unknown",
)


@dataclass
class ValidationResult:
    """Structured result of syntactic and structural IOC validation.

    Attributes:
        value: Cleaned indicator value validated.
        ioc_type: Specified IOC type category.
        is_valid: True if indicator conforms to syntax rules; False otherwise.
        validation_status: 'valid' or 'invalid'.
        reason: Descriptive diagnostic reasoning for validation status.
        classification: Network or indicator scope classification.
        source_name: Name of originating feed.
        source_location: File path or URL of originating feed.
        validated_at: ISO 8601 UTC timestamp of validation.
        original_ioc: The ParsedIOC candidate that was evaluated.
    """

    value: str
    ioc_type: str
    is_valid: bool
    validation_status: str
    reason: str
    classification: str
    source_name: str
    source_location: str
    validated_at: str
    original_ioc: ParsedIOC

    def to_dict(self) -> Dict[str, Any]:
        """Convert ValidationResult to dictionary."""
        return {
            "value": self.value,
            "ioc_type": self.ioc_type,
            "is_valid": self.is_valid,
            "validation_status": self.validation_status,
            "reason": self.reason,
            "classification": self.classification,
            "source_name": self.source_name,
            "source_location": self.source_location,
            "validated_at": self.validated_at,
        }


class IOCValidator:
    """Deterministic structural and syntactic validator for IOC candidates."""

    RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
    RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
    RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")

    RE_DOMAIN_LABEL = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
    RE_EMAIL_LOCAL = re.compile(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$")

    @staticmethod
    def _get_utc_timestamp() -> str:
        """Return current ISO 8601 UTC timestamp."""
        return datetime.now(timezone.utc).isoformat()

    def validate_ipv4(self, value: str) -> Tuple[bool, str, str]:
        """Validate an IPv4 address using standard ipaddress library.

        Returns:
            Tuple of (is_valid, reason, classification)
        """
        clean = value.strip()
        try:
            ip = ipaddress.IPv4Address(clean)
        except (ipaddress.AddressValueError, ValueError) as e:
            return False, f"Invalid IPv4 address syntax: {e}", "unknown"

        # Check documentation addresses (RFC 5737)
        for doc_net in DOC_NETWORKS_V4:
            if ip in doc_net:
                return True, "Valid documentation IPv4 address (RFC 5737)", "documentation"

        if ip.is_loopback:
            return True, "Valid loopback IPv4 address (RFC 1122)", "loopback"
        elif ip.is_private:
            return True, "Valid private IPv4 address (RFC 1918)", "private"
        elif ip.is_multicast:
            return True, "Valid multicast IPv4 address (RFC 5771)", "special"
        elif ip.is_link_local:
            return True, "Valid link-local IPv4 address (RFC 3927)", "special"
        elif ip.is_reserved:
            return True, "Valid reserved/IETF IPv4 address", "reserved"

        return True, "Valid routable public IPv4 address", "normal"

    def validate_ipv6(self, value: str) -> Tuple[bool, str, str]:
        """Validate an IPv6 address using standard ipaddress library.

        Returns:
            Tuple of (is_valid, reason, classification)
        """
        clean = value.strip()
        try:
            ip = ipaddress.IPv6Address(clean)
        except (ipaddress.AddressValueError, ValueError) as e:
            return False, f"Invalid IPv6 address syntax: {e}", "unknown"

        # Check documentation prefix (RFC 3849: 2001:db8::/32)
        if ip in DOC_NETWORK_V6:
            return True, "Valid documentation IPv6 address (RFC 3849)", "documentation"

        if ip.is_loopback:
            return True, "Valid loopback IPv6 address (::1)", "loopback"
        elif ip.is_private or ip.is_link_local:
            return True, "Valid local/private IPv6 address", "private"
        elif ip.is_multicast:
            return True, "Valid multicast IPv6 address", "special"
        elif ip.is_reserved:
            return True, "Valid reserved IPv6 address", "reserved"

        return True, "Valid routable public IPv6 address", "normal"

    def validate_domain(self, value: str) -> Tuple[bool, str, str]:
        """Validate an FQDN domain name according to RFC 1035 and RFC 1123.

        Returns:
            Tuple of (is_valid, reason, classification)
        """
        clean = value.strip().lower().rstrip(".")
        if not clean:
            return False, "Domain cannot be empty", "unknown"

        if len(clean) > 253:
            return False, f"Domain length ({len(clean)}) exceeds maximum allowed (253 chars)", "unknown"

        labels = clean.split(".")
        if len(labels) < 2:
            return False, "Domain must contain at least two labels (e.g., example.com)", "unknown"

        # Check if the domain is mistakenly an IP address
        try:
            ipaddress.ip_address(clean)
            return False, "Value is an IP address, not a valid domain name", "unknown"
        except ValueError:
            pass

        for label in labels:
            if not label:
                return False, "Domain contains empty label (consecutive dots)", "unknown"
            if len(label) > 63:
                return False, f"Label '{label}' exceeds maximum allowed length of 63 characters", "unknown"
            if not self.RE_DOMAIN_LABEL.match(label):
                return False, f"Label '{label}' contains invalid characters or malformed hyphen placement", "unknown"

        # Validate TLD (rightmost label)
        tld = labels[-1]
        if not tld.isalpha() or len(tld) < 2:
            return False, f"Top-level domain '{tld}' must consist of letters and be at least 2 chars", "unknown"

        return True, "Valid FQDN syntax", "normal"

    def validate_url(self, value: str) -> Tuple[bool, str, str]:
        """Validate an HTTP/HTTPS URL according to RFC 3986.

        Returns:
            Tuple of (is_valid, reason, classification)
        """
        clean = value.strip()
        parsed = urlparse(clean)

        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            return False, f"Unsupported URL scheme '{scheme or 'none'}'. Only http and https are valid.", "unknown"

        if not parsed.netloc:
            return False, "URL is missing network location (host)", "unknown"

        # Extract hostname portion (strip port or credentials if present)
        host = parsed.hostname
        if not host:
            return False, "URL does not contain a valid host component", "unknown"

        # Validate host as IP or domain
        is_ip = False
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            pass

        if is_ip:
            return True, "Valid HTTP/HTTPS URL with IP host", "normal"

        # Validate domain host
        is_valid_domain, reason, _ = self.validate_domain(host)
        if not is_valid_domain:
            return False, f"URL host is invalid: {reason}", "unknown"

        return True, "Valid HTTP/HTTPS URL", "normal"

    def validate_email(self, value: str) -> Tuple[bool, str, str]:
        """Validate an email address syntax according to conservative RFC 5322 rules.

        Returns:
            Tuple of (is_valid, reason, classification)
        """
        clean = value.strip()
        if "@" not in clean:
            return False, "Email must contain an '@' delimiter", "unknown"

        parts = clean.split("@")
        if len(parts) != 2:
            return False, "Email must contain exactly one '@' character", "unknown"

        local_part, domain_part = parts[0], parts[1]

        if not local_part or len(local_part) > 64:
            return False, f"Local part length ({len(local_part)}) invalid (must be 1-64 characters)", "unknown"

        if local_part.startswith(".") or local_part.endswith(".") or ".." in local_part:
            return False, "Local part cannot start/end with dot or contain consecutive dots", "unknown"

        if not self.RE_EMAIL_LOCAL.match(local_part):
            return False, "Local part contains invalid characters", "unknown"

        # Validate domain part
        is_valid_domain, reason, _ = self.validate_domain(domain_part)
        if not is_valid_domain:
            return False, f"Email domain portion is invalid: {reason}", "unknown"

        return True, "Valid email address syntax", "normal"

    def validate_hash(self, value: str, hash_type: str) -> Tuple[bool, str, str]:
        """Validate cryptographic hash digest format.

        Returns:
            Tuple of (is_valid, reason, classification)
        """
        clean = value.strip()
        h_type = hash_type.lower()

        if h_type == "md5":
            if len(clean) != 32:
                return False, f"MD5 hash must be exactly 32 hex characters (found {len(clean)})", "unknown"
            if not self.RE_MD5.match(clean):
                return False, "MD5 hash contains non-hexadecimal characters", "unknown"
            return True, "Valid 32-character hexadecimal MD5 hash", "normal"

        elif h_type == "sha1":
            if len(clean) != 40:
                return False, f"SHA1 hash must be exactly 40 hex characters (found {len(clean)})", "unknown"
            if not self.RE_SHA1.match(clean):
                return False, "SHA1 hash contains non-hexadecimal characters", "unknown"
            return True, "Valid 40-character hexadecimal SHA1 hash", "normal"

        elif h_type == "sha256":
            if len(clean) != 64:
                return False, f"SHA256 hash must be exactly 64 hex characters (found {len(clean)})", "unknown"
            if not self.RE_SHA256.match(clean):
                return False, "SHA256 hash contains non-hexadecimal characters", "unknown"
            return True, "Valid 64-character hexadecimal SHA256 hash", "normal"

        return False, f"Unsupported hash type '{hash_type}'", "unknown"

    def validate_ioc(self, parsed_ioc: ParsedIOC) -> ValidationResult:
        """Validate a single ParsedIOC candidate against syntax rules for its type.

        Args:
            parsed_ioc: ParsedIOC object to evaluate.

        Returns:
            ValidationResult containing validation status, reason, and classification.
        """
        val = parsed_ioc.value
        ioc_type = parsed_ioc.ioc_type.lower()
        timestamp = self._get_utc_timestamp()

        try:
            if ioc_type == "ipv4":
                is_valid, reason, classification = self.validate_ipv4(val)
            elif ioc_type == "ipv6":
                is_valid, reason, classification = self.validate_ipv6(val)
            elif ioc_type == "domain":
                is_valid, reason, classification = self.validate_domain(val)
            elif ioc_type == "url":
                is_valid, reason, classification = self.validate_url(val)
            elif ioc_type == "email":
                is_valid, reason, classification = self.validate_email(val)
            elif ioc_type in ("md5", "sha1", "sha256"):
                is_valid, reason, classification = self.validate_hash(val, ioc_type)
            else:
                is_valid = False
                reason = f"Unknown or unsupported IOC type: '{parsed_ioc.ioc_type}'"
                classification = "unknown"

        except Exception as e:
            logger.exception("Unexpected exception validating IOC %s (%s)", val, ioc_type)
            is_valid = False
            reason = f"Validation exception: {e}"
            classification = "unknown"

        return ValidationResult(
            value=val,
            ioc_type=ioc_type,
            is_valid=is_valid,
            validation_status="valid" if is_valid else "invalid",
            reason=reason,
            classification=classification,
            source_name=parsed_ioc.source_name,
            source_location=parsed_ioc.source_location,
            validated_at=timestamp,
            original_ioc=parsed_ioc,
        )

    def validate_many(self, parsed_iocs: Sequence[ParsedIOC]) -> List[ValidationResult]:
        """Validate multiple ParsedIOC candidates sequentially.

        Ensures individual failures or malformed candidates do not halt processing.

        Args:
            parsed_iocs: Sequence of ParsedIOC candidates.

        Returns:
            List of ValidationResult objects preserving input provenance.
        """
        results: List[ValidationResult] = []
        for ioc in parsed_iocs:
            try:
                res = self.validate_ioc(ioc)
                results.append(res)
            except Exception as e:
                logger.exception("Fatal validation error on IOC: %s", ioc)
                results.append(
                    ValidationResult(
                        value=ioc.value,
                        ioc_type=ioc.ioc_type,
                        is_valid=False,
                        validation_status="invalid",
                        reason=f"Processing error: {e}",
                        classification="unknown",
                        source_name=ioc.source_name,
                        source_location=ioc.source_location,
                        validated_at=self._get_utc_timestamp(),
                        original_ioc=ioc,
                    )
                )

        valid_count = sum(1 for r in results if r.is_valid)
        invalid_count = len(results) - valid_count
        logger.info(
            "Validated %d IOC candidates: %d valid, %d invalid",
            len(results),
            valid_count,
            invalid_count,
        )
        return results

