"""IOC Normalization and Deduplication module for Threat Intelligence Aggregator.

Transforms structurally valid IOC candidates into deterministic canonical representations,
collapses semantic duplicates across feeds, and preserves complete source provenance,
timestamps, and metadata without conducting any network lookups.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
import logging
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import SplitResult, urlsplit, urlunsplit

from modules.ioc_parser import ParsedIOC
from modules.validator import ValidationResult

logger = logging.getLogger(__name__)


@dataclass
class NormalizedIOC:
    """Standardized representation of a normalized Indicator of Compromise.

    Attributes:
        original_value: Raw candidate string prior to normalization.
        normalized_value: Canonical normalized representation, or None if invalid.
        ioc_type: Supported IOC type category.
        is_valid: True if candidate passed Phase 4 validation; False otherwise.
        normalization_status: 'normalized', 'invalid', or 'unsupported'.
        source_name: Name of originating intelligence feed.
        source_location: File path or URL of originating feed.
        normalized_at: ISO 8601 UTC timestamp of normalization.
        original_ioc: The ParsedIOC candidate object.
        metadata: Contextual dictionary carrying forward all previous pipeline metadata.
        validation_reason: Reason string from validator if invalid.
    """

    original_value: str
    normalized_value: Optional[str]
    ioc_type: str
    is_valid: bool
    normalization_status: str
    source_name: str
    source_location: str
    normalized_at: str
    original_ioc: ParsedIOC
    metadata: Dict[str, Any] = field(default_factory=dict)
    validation_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert NormalizedIOC instance to dictionary."""
        return {
            "original_value": self.original_value,
            "normalized_value": self.normalized_value,
            "ioc_type": self.ioc_type,
            "is_valid": self.is_valid,
            "normalization_status": self.normalization_status,
            "source_name": self.source_name,
            "source_location": self.source_location,
            "normalized_at": self.normalized_at,
            "metadata": self.metadata,
            "validation_reason": self.validation_reason,
        }


@dataclass
class DeduplicatedIOC:
    """Consolidated unique IOC representing one or more observations across feeds.

    Attributes:
        normalized_value: Canonical indicator string.
        ioc_type: Indicator type category.
        distinct_sources_count: Number of unique feed sources observing this indicator.
        sources: List of unique source feed names.
        source_locations: List of unique source locations (file paths or URLs).
        total_occurrences: Total observation count across all feeds (including repeats).
        original_values: List of distinct original raw values mapped to this canonical form.
        first_seen: Earliest recorded timestamp among observing feeds.
        last_seen: Latest recorded timestamp among observing feeds.
        records: All underlying NormalizedIOC instances maintaining full provenance.
    """

    normalized_value: str
    ioc_type: str
    distinct_sources_count: int
    sources: List[str]
    source_locations: List[str]
    total_occurrences: int
    original_values: List[str]
    first_seen: str
    last_seen: str
    records: List[NormalizedIOC] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert DeduplicatedIOC to dictionary."""
        return {
            "normalized_value": self.normalized_value,
            "ioc_type": self.ioc_type,
            "distinct_sources_count": self.distinct_sources_count,
            "sources": self.sources,
            "source_locations": self.source_locations,
            "total_occurrences": self.total_occurrences,
            "original_values": self.original_values,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


class IOCNormalizer:
    """Deterministic normalization and deduplication engine for threat intelligence indicators."""

    @staticmethod
    def _get_utc_timestamp() -> str:
        """Return current ISO 8601 UTC timestamp."""
        return datetime.now(timezone.utc).isoformat()

    def normalize_value(self, value: str, ioc_type: str) -> Optional[str]:
        """Convert a valid indicator string into its canonical representation.

        Args:
            value: Indicator string to normalize.
            ioc_type: One of the 8 supported types.

        Returns:
            Canonical string representation, or None if conversion fails.
        """
        clean = value.strip()
        t = ioc_type.lower()

        if t == "ipv4":
            try:
                return str(ipaddress.IPv4Address(clean))
            except ValueError:
                return None

        elif t == "ipv6":
            try:
                # Returns compressed lowercase canonical notation
                return str(ipaddress.IPv6Address(clean)).lower()
            except ValueError:
                return None

        elif t == "domain":
            dom = clean.rstrip(".")
            try:
                # Apply IDNA encoding safely for internationalized domain names
                idna_encoded = dom.encode("idna").decode("ascii")
                return idna_encoded.lower()
            except (UnicodeError, UnicodeDecodeError):
                return dom.lower()

        elif t == "url":
            try:
                parts = urlsplit(clean)
                scheme = parts.scheme.lower()

                # Extract and normalize netloc (host and port)
                netloc = parts.netloc
                host = parts.hostname or ""
                port = parts.port

                # Normalize host (IDNA domain or IP)
                is_ip = False
                try:
                    ip_obj = ipaddress.ip_address(host)
                    is_ip = True
                    norm_host = str(ip_obj)
                    if isinstance(ip_obj, ipaddress.IPv6Address):
                        norm_host = f"[{norm_host}]"
                except ValueError:
                    norm_host = host

                if not is_ip and host:
                    try:
                        norm_host = host.encode("idna").decode("ascii").lower()
                    except (UnicodeError, UnicodeDecodeError):
                        norm_host = host.lower()

                # Reconstruct netloc omitting default ports
                userinfo = ""
                if "@" in netloc:
                    userinfo = netloc.split("@", 1)[0] + "@"

                # Check default ports: 80 for http, 443 for https
                include_port = False
                if port is not None:
                    if scheme == "http" and port != 80:
                        include_port = True
                    elif scheme == "https" and port != 443:
                        include_port = True
                    elif scheme not in ("http", "https"):
                        include_port = True

                if include_port:
                    norm_netloc = f"{userinfo}{norm_host}:{port}"
                else:
                    norm_netloc = f"{userinfo}{norm_host}"

                # Ensure path starts with / if path is non-empty or netloc is present
                path = parts.path
                if not path and norm_netloc:
                    path = ""

                normalized_parts = SplitResult(
                    scheme=scheme,
                    netloc=norm_netloc,
                    path=path,
                    query=parts.query,
                    fragment=parts.fragment,
                )
                return urlunsplit(normalized_parts)

            except Exception as e:
                logger.warning("Error normalizing URL '%s': %s", value, e)
                return clean

        elif t == "email":
            if "@" not in clean:
                return clean
            local_part, domain_part = clean.split("@", 1)
            # Preserve local part exactly; normalize domain portion
            norm_dom = domain_part.rstrip(".")
            try:
                norm_dom = norm_dom.encode("idna").decode("ascii").lower()
            except (UnicodeError, UnicodeDecodeError):
                norm_dom = norm_dom.lower()
            return f"{local_part}@{norm_dom}"

        elif t in ("md5", "sha1", "sha256"):
            # Lowercase hexadecimal digest; preserve exact length
            return clean.lower()

        return clean

    def normalize_ioc(self, validation_result: ValidationResult) -> NormalizedIOC:
        """Process a ValidationResult and produce a NormalizedIOC.

        Args:
            validation_result: Result from IOCValidator.

        Returns:
            NormalizedIOC containing canonical value if valid, or None if invalid.
        """
        orig_ioc = validation_result.original_ioc
        timestamp = self._get_utc_timestamp()
        val = validation_result.value
        ioc_type = validation_result.ioc_type

        # Merge metadata from original candidate and validation
        meta = {**orig_ioc.metadata}
        meta["classification"] = validation_result.classification
        meta["validation_status"] = validation_result.validation_status

        if not validation_result.is_valid:
            return NormalizedIOC(
                original_value=val,
                normalized_value=None,
                ioc_type=ioc_type,
                is_valid=False,
                normalization_status="invalid",
                source_name=validation_result.source_name,
                source_location=validation_result.source_location,
                normalized_at=timestamp,
                original_ioc=orig_ioc,
                metadata=meta,
                validation_reason=validation_result.reason,
            )

        norm_val = self.normalize_value(val, ioc_type)
        if norm_val is None:
            return NormalizedIOC(
                original_value=val,
                normalized_value=None,
                ioc_type=ioc_type,
                is_valid=False,
                normalization_status="unsupported",
                source_name=validation_result.source_name,
                source_location=validation_result.source_location,
                normalized_at=timestamp,
                original_ioc=orig_ioc,
                metadata=meta,
                validation_reason=f"Failed to normalize valid candidate: {val}",
            )

        return NormalizedIOC(
            original_value=val,
            normalized_value=norm_val,
            ioc_type=ioc_type,
            is_valid=True,
            normalization_status="normalized",
            source_name=validation_result.source_name,
            source_location=validation_result.source_location,
            normalized_at=timestamp,
            original_ioc=orig_ioc,
            metadata=meta,
            validation_reason=validation_result.reason,
        )

    def normalize_many(
        self, validation_results: Sequence[ValidationResult]
    ) -> List[NormalizedIOC]:
        """Normalize a collection of ValidationResult objects sequentially.

        Args:
            validation_results: Sequence of ValidationResult objects.

        Returns:
            List of NormalizedIOC objects.
        """
        normalized_list: List[NormalizedIOC] = []
        for v in validation_results:
            try:
                norm = self.normalize_ioc(v)
                normalized_list.append(norm)
            except Exception as e:
                logger.exception("Unexpected error normalizing validation result: %s", v)
                normalized_list.append(
                    NormalizedIOC(
                        original_value=v.value,
                        normalized_value=None,
                        ioc_type=v.ioc_type,
                        is_valid=False,
                        normalization_status="invalid",
                        source_name=v.source_name,
                        source_location=v.source_location,
                        normalized_at=self._get_utc_timestamp(),
                        original_ioc=v.original_ioc,
                        metadata=v.original_ioc.metadata,
                        validation_reason=f"Normalization exception: {e}",
                    )
                )

        norm_count = sum(1 for n in normalized_list if n.is_valid and n.normalized_value)
        logger.info(
            "Normalized %d items: %d valid canonicalized, %d invalid/skipped",
            len(normalized_list),
            norm_count,
            len(normalized_list) - norm_count,
        )
        return normalized_list

    def deduplicate(
        self, normalized_iocs: Sequence[NormalizedIOC]
    ) -> List[DeduplicatedIOC]:
        """Group valid normalized indicators by (ioc_type, normalized_value).

        Consolidates repeated observations across feeds while preserving distinct sources,
        occurrence frequency, original raw values, and complete underlying records.

        Args:
            normalized_iocs: Sequence of NormalizedIOC objects.

        Returns:
            List of DeduplicatedIOC instances sorted by distinct_sources_count descending.
        """
        # Map: (ioc_type, normalized_value) -> List[NormalizedIOC]
        groups: Dict[Tuple[str, str], List[NormalizedIOC]] = defaultdict(list)

        for item in normalized_iocs:
            # Deduplicate valid normalized indicators only
            if item.is_valid and item.normalized_value:
                key = (item.ioc_type, item.normalized_value)
                groups[key].append(item)

        deduplicated: List[DeduplicatedIOC] = []

        for (ioc_type, norm_val), records in groups.items():
            # Distinct sources (ensures repeated occurrences in same source do not inflate count)
            unique_sources = sorted(list({r.source_name for r in records}))
            unique_locations = sorted(list({r.source_location for r in records}))
            unique_originals = sorted(list({r.original_value for r in records}))

            timestamps = [r.normalized_at for r in records if r.normalized_at]
            first_seen = min(timestamps) if timestamps else ""
            last_seen = max(timestamps) if timestamps else ""

            deduplicated.append(
                DeduplicatedIOC(
                    normalized_value=norm_val,
                    ioc_type=ioc_type,
                    distinct_sources_count=len(unique_sources),
                    sources=unique_sources,
                    source_locations=unique_locations,
                    total_occurrences=len(records),
                    original_values=unique_originals,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    records=records,
                )
            )

        # Sort primarily by distinct source count descending, then total occurrences, then value
        deduplicated.sort(
            key=lambda x: (x.distinct_sources_count, x.total_occurrences, x.normalized_value),
            reverse=True,
        )

        logger.info(
            "Deduplicated %d valid items into %d unique indicators",
            sum(len(r) for r in groups.values()),
            len(deduplicated),
        )
        return deduplicated

