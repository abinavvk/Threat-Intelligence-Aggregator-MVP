"""IOC Parser module for Threat Intelligence Aggregator.

Extracts candidate Indicators of Compromise (IOCs) across eight supported types:
IPv4, IPv6, Domain, URL, Email, MD5, SHA1, and SHA256 from CSV, TXT, and JSON feeds.
Preserves feed source provenance and metadata without executing or validating maliciousness.
"""

import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
import io
import json
import logging
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from config.settings import SUPPORTED_IOC_TYPES
from modules.feed_collector import FeedResult

logger = logging.getLogger(__name__)

# Standard column/key aliases used across threat feeds
IOC_VALUE_KEYS: Set[str] = {
    "indicator",
    "ioc",
    "value",
    "ip",
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "hash",
    "email",
    "sha256",
    "sha1",
    "md5",
}

IOC_TYPE_KEYS: Set[str] = {"type", "ioc_type", "indicator_type"}

# File extensions that should not be mistaken for domains in unstructured text
COMMON_FILE_EXTENSIONS: Set[str] = {
    "exe", "dll", "bin", "txt", "csv", "json", "pdf", "docx", "xlsx",
    "zip", "tar", "gz", "py", "sh", "bat", "ps1", "log", "tmp", "bak",
}


@dataclass
class ParsedIOC:
    """Standardized representation of an extracted candidate Indicator of Compromise.

    Attributes:
        value: Extracted candidate indicator string.
        ioc_type: One of the 8 supported types ('ipv4', 'ipv6', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256').
        source_name: Name of the originating feed.
        source_type: Ingestion medium category ('file' or 'url').
        source_location: File path or URL of the originating feed.
        feed_format: Format of the feed ('csv', 'txt', 'json').
        extracted_at: ISO 8601 UTC timestamp of extraction.
        raw_value: Raw token as originally parsed prior to stripping whitespace.
        metadata: Dictionary of auxiliary context/attributes associated with the indicator.
    """

    value: str
    ioc_type: str
    source_name: str
    source_type: str
    source_location: str
    feed_format: str
    extracted_at: str
    raw_value: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert ParsedIOC instance to a dictionary."""
        return {
            "value": self.value,
            "ioc_type": self.ioc_type,
            "source_name": self.source_name,
            "source_type": self.source_type,
            "source_location": self.source_location,
            "feed_format": self.feed_format,
            "extracted_at": self.extracted_at,
            "raw_value": self.raw_value,
            "metadata": self.metadata,
        }


class IOCParser:
    """Modular parser for extracting IOC candidates from threat intelligence feeds."""

    # Precompiled regular expressions for conservative extraction
    RE_IPV4 = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )
    RE_IPV6 = re.compile(
        r"\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|"
        r"(?:[0-9a-f]{1,4}:)*:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*|"
        r"::(?:[0-9a-f]{1,4}:)*[0-9a-f]{1,4}|"
        r"(?:[0-9a-f]{1,4}:){1,7}:|"
        r"::",
        re.IGNORECASE,
    )
    RE_URL = re.compile(
        r"\bhttps?://[^\s<>\"'{}|\\^`]+[^\s<>\"'{}|\\^`.,;:?!()]",
        re.IGNORECASE,
    )
    RE_EMAIL = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b"
    )
    RE_DOMAIN = re.compile(
        r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b"
    )
    RE_HASH_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
    RE_HASH_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
    RE_HASH_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

    @staticmethod
    def _get_utc_timestamp() -> str:
        """Return current ISO 8601 UTC timestamp."""
        return datetime.now(timezone.utc).isoformat()

    @classmethod
    def classify_token(cls, token: str) -> Optional[str]:
        """Determine if a token matches one of the 8 supported IOC types.

        Args:
            token: Candidate string to inspect.

        Returns:
            Type name ('ipv4', 'ipv6', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256') or None.
        """
        clean = token.strip()
        if not clean:
            return None

        # 1. URL Check
        if clean.lower().startswith(("http://", "https://")) and cls.RE_URL.fullmatch(clean):
            return "url"

        # 2. Email Check
        if "@" in clean and cls.RE_EMAIL.fullmatch(clean):
            return "email"

        # 3. Hashes (check strict length and hex characters)
        if len(clean) == 64 and cls.RE_HASH_SHA256.fullmatch(clean):
            return "sha256"
        if len(clean) == 40 and cls.RE_HASH_SHA1.fullmatch(clean):
            return "sha1"
        if len(clean) == 32 and cls.RE_HASH_MD5.fullmatch(clean):
            return "md5"

        # 4. IPv4 Check
        if cls.RE_IPV4.fullmatch(clean):
            return "ipv4"

        # 5. IPv6 Check
        if ":" in clean and cls.RE_IPV6.fullmatch(clean):
            return "ipv6"

        # 6. Domain Check (must not be an IP, must not end in common non-domain extension)
        if "." in clean and cls.RE_DOMAIN.fullmatch(clean):
            tld = clean.rsplit(".", 1)[-1].lower()
            if tld not in COMMON_FILE_EXTENSIONS:
                return "domain"

        return None

    def _create_ioc(
        self,
        value: str,
        ioc_type: str,
        source_info: Dict[str, Any],
        raw_value: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ParsedIOC:
        """Instantiate a standardized ParsedIOC object."""
        return ParsedIOC(
            value=value.strip(),
            ioc_type=ioc_type,
            source_name=source_info.get("source_name", "unknown_source"),
            source_type=source_info.get("source_type", "unknown_type"),
            source_location=source_info.get("source_location", ""),
            feed_format=source_info.get("format", "unknown"),
            extracted_at=self._get_utc_timestamp(),
            raw_value=raw_value if raw_value is not None else value,
            metadata=metadata or {},
        )

    def parse_csv(
        self, content: str, source_info: Optional[Dict[str, Any]] = None
    ) -> List[ParsedIOC]:
        """Parse structured CSV content and extract IOC candidates.

        Args:
            content: Raw CSV string.
            source_info: Metadata about the originating feed.

        Returns:
            List of ParsedIOC candidates.
        """
        source_info = source_info or {}
        results: List[ParsedIOC] = []

        if not content.strip():
            return results

        try:
            reader = csv.DictReader(io.StringIO(content))
            fieldnames = reader.fieldnames or []

            # Identify target column names
            value_col = None
            type_col = None

            for field in fieldnames:
                clean_field = field.strip().lower()
                if not value_col and clean_field in IOC_VALUE_KEYS:
                    value_col = field
                if not type_col and clean_field in IOC_TYPE_KEYS:
                    type_col = field

            # If no standard header found, fall back to line-based parsing
            if not value_col:
                return self.parse_text(content, source_info)

            for row in reader:
                val = (row.get(value_col) or "").strip()
                if not val:
                    continue

                # Determine or verify type
                explicit_type = (row.get(type_col) or "").strip().lower() if type_col else ""
                inferred_type = self.classify_token(val)

                chosen_type = explicit_type if explicit_type in SUPPORTED_IOC_TYPES else inferred_type

                if chosen_type:
                    # Collect auxiliary metadata from remaining columns
                    row_metadata = {
                        k: v.strip()
                        for k, v in row.items()
                        if k not in (value_col, type_col) and v is not None and v.strip() != ""
                    }
                    results.append(
                        self._create_ioc(
                            value=val,
                            ioc_type=chosen_type,
                            source_info=source_info,
                            raw_value=val,
                            metadata=row_metadata,
                        )
                    )

        except Exception as e:
            logger.warning("CSV structured parsing encountered error: %s. Falling back to text extraction.", e)
            return self.parse_text(content, source_info)

        return results

    def parse_json(
        self, content: str, source_info: Optional[Dict[str, Any]] = None
    ) -> List[ParsedIOC]:
        """Parse structured JSON content and extract IOC candidates.

        Args:
            content: Raw JSON string.
            source_info: Metadata about the originating feed.

        Returns:
            List of ParsedIOC candidates.
        """
        source_info = source_info or {}
        results: List[ParsedIOC] = []

        if not content.strip():
            return results

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error("JSON parsing failed (malformed JSON): %s", e)
            return results

        def extract_from_node(node: Any, parent_meta: Optional[Dict[str, Any]] = None) -> None:
            if isinstance(node, list):
                for item in node:
                    extract_from_node(item, parent_meta)
            elif isinstance(node, dict):
                # Search for IOC value key in dict
                val = None
                val_key = None
                type_val = None

                for k, v in node.items():
                    k_lower = k.strip().lower()
                    if not val and k_lower in IOC_VALUE_KEYS and isinstance(v, (str, int)):
                        val = str(v).strip()
                        val_key = k
                    if not type_val and k_lower in IOC_TYPE_KEYS and isinstance(v, str):
                        type_val = v.strip().lower()

                if val:
                    inferred_type = self.classify_token(val)
                    chosen_type = type_val if type_val in SUPPORTED_IOC_TYPES else inferred_type
                    if chosen_type:
                        node_meta = {
                            k: v
                            for k, v in node.items()
                            if k != val_key and not (k.strip().lower() in IOC_TYPE_KEYS)
                        }
                        if parent_meta:
                            node_meta = {**parent_meta, **node_meta}
                        results.append(
                            self._create_ioc(
                                value=val,
                                ioc_type=chosen_type,
                                source_info=source_info,
                                raw_value=val,
                                metadata=node_meta,
                            )
                        )
                else:
                    # Recursive descent for nested structures
                    meta_keys = {k: v for k, v in node.items() if not isinstance(v, (dict, list))}
                    for k, v in node.items():
                        if isinstance(v, (dict, list)):
                            extract_from_node(v, meta_keys)
            elif isinstance(node, str):
                inferred = self.classify_token(node)
                if inferred:
                    results.append(
                        self._create_ioc(
                            value=node,
                            ioc_type=inferred,
                            source_info=source_info,
                            raw_value=node,
                            metadata=parent_meta or {},
                        )
                    )

        extract_from_node(data)
        return results

    def parse_txt(
        self, content: str, source_info: Optional[Dict[str, Any]] = None
    ) -> List[ParsedIOC]:
        """Parse line-based plain text threat intelligence feeds.

        Args:
            content: Raw plain text string.
            source_info: Metadata about the originating feed.

        Returns:
            List of ParsedIOC candidates.
        """
        source_info = source_info or {}
        results: List[ParsedIOC] = []

        if not content.strip():
            return results

        lines = content.splitlines()
        for line in lines:
            line_str = line.strip()
            # Ignore empty lines and comment headers (# or //)
            if not line_str or line_str.startswith(("#", "//")):
                continue

            # Strip inline comments (e.g. "192.0.2.1 # C2")
            clean_line = line_str
            for comment_delim in ("#", "//"):
                if comment_delim in clean_line:
                    clean_line = clean_line.split(comment_delim, 1)[0].strip()

            if not clean_line:
                continue

            # Check if line itself is a single token
            tokens = clean_line.split()
            first_token = tokens[0].strip(" ,;")
            token_type = self.classify_token(first_token)

            if token_type:
                # First token is the indicator; any remaining tokens become metadata
                aux_meta = {}
                if len(tokens) > 1:
                    aux_meta["context"] = " ".join(tokens[1:])
                results.append(
                    self._create_ioc(
                        value=first_token,
                        ioc_type=token_type,
                        source_info=source_info,
                        raw_value=line_str,
                        metadata=aux_meta,
                    )
                )
            else:
                # Fall back to regex scan on this line
                line_iocs = self.parse_text(clean_line, source_info)
                results.extend(line_iocs)

        return results

    def parse_text(
        self, content: str, source_info: Optional[Dict[str, Any]] = None
    ) -> List[ParsedIOC]:
        """Extract IOC candidates from unstructured or mixed text.

        Employs span-masking to prevent substrings of URLs or Emails (such as an embedded IP
        or domain) from producing duplicate or false-positive indicators.

        Args:
            content: Unstructured text content.
            source_info: Metadata about the originating feed.

        Returns:
            List of ParsedIOC candidates.
        """
        source_info = source_info or {}
        results: List[ParsedIOC] = []

        if not content.strip():
            return results

        # Track character spans already claimed by higher-order indicators
        claimed_spans: List[Tuple[int, int]] = []

        def is_claimed(start: int, end: int) -> bool:
            return any(s <= start and end <= e for s, e in claimed_spans)

        # 1. Extract URLs first
        for match in self.RE_URL.finditer(content):
            start, end = match.span()
            claimed_spans.append((start, end))
            results.append(
                self._create_ioc(
                    value=match.group(0),
                    ioc_type="url",
                    source_info=source_info,
                    raw_value=match.group(0),
                )
            )

        # 2. Extract Emails second
        for match in self.RE_EMAIL.finditer(content):
            start, end = match.span()
            if not is_claimed(start, end):
                claimed_spans.append((start, end))
                results.append(
                    self._create_ioc(
                        value=match.group(0),
                        ioc_type="email",
                        source_info=source_info,
                        raw_value=match.group(0),
                    )
                )

        # 3. Extract Hashes (SHA256, SHA1, MD5)
        for match in self.RE_HASH_SHA256.finditer(content):
            start, end = match.span()
            if not is_claimed(start, end):
                claimed_spans.append((start, end))
                results.append(
                    self._create_ioc(
                        value=match.group(0),
                        ioc_type="sha256",
                        source_info=source_info,
                        raw_value=match.group(0),
                    )
                )

        for match in self.RE_HASH_SHA1.finditer(content):
            start, end = match.span()
            if not is_claimed(start, end):
                claimed_spans.append((start, end))
                results.append(
                    self._create_ioc(
                        value=match.group(0),
                        ioc_type="sha1",
                        source_info=source_info,
                        raw_value=match.group(0),
                    )
                )

        for match in self.RE_HASH_MD5.finditer(content):
            start, end = match.span()
            if not is_claimed(start, end):
                claimed_spans.append((start, end))
                results.append(
                    self._create_ioc(
                        value=match.group(0),
                        ioc_type="md5",
                        source_info=source_info,
                        raw_value=match.group(0),
                    )
                )

        # 4. Extract IPv4
        for match in self.RE_IPV4.finditer(content):
            start, end = match.span()
            if not is_claimed(start, end):
                claimed_spans.append((start, end))
                results.append(
                    self._create_ioc(
                        value=match.group(0),
                        ioc_type="ipv4",
                        source_info=source_info,
                        raw_value=match.group(0),
                    )
                )

        # 5. Extract IPv6
        for match in self.RE_IPV6.finditer(content):
            start, end = match.span()
            val = match.group(0)
            if ":" in val and len(val) >= 3 and not is_claimed(start, end):
                claimed_spans.append((start, end))
                results.append(
                    self._create_ioc(
                        value=val,
                        ioc_type="ipv6",
                        source_info=source_info,
                        raw_value=val,
                    )
                )

        # 6. Extract Domains (excluding file extensions)
        for match in self.RE_DOMAIN.finditer(content):
            start, end = match.span()
            val = match.group(0)
            tld = val.rsplit(".", 1)[-1].lower()
            if not is_claimed(start, end) and tld not in COMMON_FILE_EXTENSIONS:
                claimed_spans.append((start, end))
                results.append(
                    self._create_ioc(
                        value=val,
                        ioc_type="domain",
                        source_info=source_info,
                        raw_value=val,
                    )
                )

        return results

    def parse_feed(self, feed_result: FeedResult) -> List[ParsedIOC]:
        """Parse a single FeedResult into candidate IOCs based on its format.

        Args:
            feed_result: Successful FeedResult instance from FeedCollector.

        Returns:
            List of ParsedIOC candidates.
        """
        if not feed_result.success or not feed_result.raw_content:
            logger.info("Skipping uncollected or empty feed: %s", feed_result.source_name)
            return []

        source_info = {
            "source_name": feed_result.source_name,
            "source_type": feed_result.source_type,
            "source_location": feed_result.source_location,
            "format": feed_result.format,
        }

        fmt = feed_result.format.lower()
        if fmt == "csv":
            return self.parse_csv(feed_result.raw_content, source_info)
        elif fmt == "json":
            return self.parse_json(feed_result.raw_content, source_info)
        elif fmt == "txt":
            return self.parse_txt(feed_result.raw_content, source_info)
        else:
            return self.parse_text(feed_result.raw_content, source_info)

    def parse_many(self, feed_results: Sequence[FeedResult]) -> List[ParsedIOC]:
        """Parse multiple FeedResult objects, preserving source provenance across all feeds.

        Args:
            feed_results: Sequence of FeedResult objects.

        Returns:
            Aggregated list of all extracted ParsedIOC objects.
        """
        all_iocs: List[ParsedIOC] = []
        for feed in feed_results:
            try:
                iocs = self.parse_feed(feed)
                all_iocs.extend(iocs)
                logger.info(
                    "Extracted %d candidate IOCs from %s (%s)",
                    len(iocs),
                    feed.source_name,
                    feed.format,
                )
            except Exception as e:
                logger.exception("Failed to parse feed %s: %s", feed.source_name, e)

        return all_iocs
