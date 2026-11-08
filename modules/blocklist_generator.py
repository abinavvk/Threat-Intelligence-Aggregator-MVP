"""IOC Blocklist Generator for Threat Intelligence Aggregator.

Generates categorized, deterministic threat blocklists from correlated indicators
stored in SQLite. Supports export by IOC category or all categories across TXT,
CSV, and JSON formats with granular multi-feed consensus and severity filtering.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union
import csv

from config.settings import (
    BLOCKLISTS_DIR,
    DEFAULT_DB_PATH,
    SUPPORTED_IOC_TYPES,
    calculate_severity,
)
from modules.correlation import CorrelationEngine, CorrelationResult
from modules.database_manager import DatabaseManager

logger = logging.getLogger(__name__)

SUPPORTED_EXPORT_FORMATS = ("txt", "csv", "json")


def sanitize_csv_cell(value: Any) -> Any:
    """Neutralize potential CSV formula injection (DDE execution) in spreadsheet readers.

    Prefixes characters '=', '+', '-', '@', tab, and CR with a single quote.
    """
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


@dataclass
class BlocklistExportResult:
    """Standardized metadata representing a generated blocklist file.

    Attributes:
        category: IOC category name (e.g. 'ipv4', 'domain', or 'all').
        format: Export file format ('txt', 'csv', 'json').
        file_path: Filesystem path to the exported blocklist file.
        indicator_count: Number of indicators written to the blocklist.
        filters_applied: Summary of criteria filters used to generate the list.
        exported_at: UTC ISO 8601 timestamp of generation.
    """

    category: str
    format: str
    file_path: Path
    indicator_count: int
    filters_applied: Dict[str, Any]
    exported_at: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert export result to dictionary representation."""
        return {
            "category": self.category,
            "format": self.format,
            "file_path": str(self.file_path),
            "indicator_count": self.indicator_count,
            "filters_applied": self.filters_applied,
            "exported_at": self.exported_at,
        }


class BlocklistGenerator:
    """Generates categorized, format-flexible blocklists from correlated threat intelligence."""

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        db_path: Union[str, Path] = DEFAULT_DB_PATH,
        output_dir: Union[str, Path] = BLOCKLISTS_DIR,
    ) -> None:
        """Initialize BlocklistGenerator with database manager and destination directory.

        Args:
            db_manager: Existing DatabaseManager or None to create one.
            db_path: Database filesystem path if creating a new DatabaseManager.
            output_dir: Target directory for generated blocklist files.
        """
        self.db_manager = db_manager or DatabaseManager(db_path=db_path)
        self.correlation_engine = CorrelationEngine(db_manager=self.db_manager)
        self.output_dir = Path(output_dir).resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def get_available_categories() -> List[str]:
        """Return the list of supported IOC categories."""
        return list(SUPPORTED_IOC_TYPES)

    @staticmethod
    def get_available_formats() -> List[str]:
        """Return the list of supported export formats."""
        return list(SUPPORTED_EXPORT_FORMATS)

    @staticmethod
    def _get_utc_timestamp() -> str:
        """Return current ISO 8601 UTC timestamp."""
        return datetime.now(timezone.utc).isoformat()

    def get_indicators_for_blocklist(
        self,
        ioc_type: Optional[str] = None,
        severity: Optional[str] = None,
        min_sources: int = 1,
        exclude_low: bool = False,
        cross_feed_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """Retrieve and filter correlated indicators from SQLite storage.

        Args:
            ioc_type: Target category (e.g. 'ipv4') or None/'all' for all categories.
            severity: Filter by severity tier ('HIGH', 'MEDIUM', 'LOW').
            min_sources: Minimum number of distinct reporting feeds (default: 1).
            exclude_low: If True, exclude indicators classified as LOW severity.
            cross_feed_only: If True, require multi-feed consensus (min_sources >= 2).

        Returns:
            List of standardized indicator records sorted by distinct sources descending.

        Raises:
            ValueError: If ioc_type or severity is unrecognized or min_sources < 1.
        """
        if min_sources < 1:
            raise ValueError(f"min_sources must be >= 1, got {min_sources}")

        normalized_type: Optional[str] = None
        if ioc_type is not None and ioc_type.lower() != "all":
            normalized_type = ioc_type.lower()
            if normalized_type not in SUPPORTED_IOC_TYPES:
                raise ValueError(
                    f"Unsupported IOC type: '{ioc_type}'. "
                    f"Supported types: {', '.join(SUPPORTED_IOC_TYPES)}"
                )

        normalized_sev: Optional[str] = None
        if severity is not None:
            normalized_sev = severity.upper()
            if normalized_sev not in ("HIGH", "MEDIUM", "LOW"):
                raise ValueError(
                    f"Invalid severity filter: '{severity}'. "
                    f"Allowed values: HIGH, MEDIUM, LOW."
                )

        # Cross-feed implies at least 2 distinct sources
        effective_min_sources = max(min_sources, 2) if cross_feed_only else min_sources

        correlations: List[CorrelationResult] = self.correlation_engine.correlate_all(
            min_sources=effective_min_sources,
            severity=normalized_sev,
            ioc_type=normalized_type,
        )

        # Filter out invalid indicators if any exist in the database
        conn = self.db_manager.get_connection()
        cursor = conn.execute("SELECT id FROM indicators WHERE is_valid = 0")
        invalid_ids = {row["id"] for row in cursor.fetchall()}

        filtered: List[Dict[str, Any]] = []
        for c in correlations:
            if c.indicator_id in invalid_ids:
                continue

            if exclude_low and c.severity == "LOW":
                continue

            filtered.append(
                {
                    "indicator_id": c.indicator_id,
                    "ioc_type": c.ioc_type,
                    "indicator": c.normalized_value,
                    "normalized_value": c.normalized_value,
                    "severity": c.severity,
                    "distinct_sources_count": c.distinct_sources_count,
                    "total_occurrences": c.total_occurrences,
                    "sources": c.sources,
                    "first_seen": c.first_seen,
                    "last_seen": c.last_seen,
                }
            )

        return filtered

    def export_txt(
        self,
        indicators: Sequence[Dict[str, Any]],
        output_path: Union[str, Path],
    ) -> int:
        """Export canonical indicators to a line-delimited plain text file.

        One canonical IOC is written per line. Duplicate entries in the sequence
        are deduplicated while preserving order.

        Args:
            indicators: Sequence of indicator dictionaries.
            output_path: Target filesystem path for the output file.

        Returns:
            Count of indicators written to the file.
        """
        dest = Path(output_path).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)

        seen = set()
        unique_values: List[str] = []
        for item in indicators:
            val = item.get("indicator") or item.get("normalized_value")
            if val and val not in seen:
                seen.add(val)
                unique_values.append(val)

        # Write lines cleanly with UTF-8 encoding
        with open(dest, "w", encoding="utf-8") as f:
            for val in unique_values:
                f.write(f"{val}\n")

        logger.info("Exported %d indicators to TXT blocklist: %s", len(unique_values), dest)
        return len(unique_values)

    def export_csv(
        self,
        indicators: Sequence[Dict[str, Any]],
        output_path: Union[str, Path],
    ) -> int:
        """Export indicators to a structured CSV file with threat intelligence metadata.

        Columns:
            - ioc_type
            - indicator
            - severity
            - distinct_sources_count
            - total_occurrences
            - first_seen
            - last_seen

        Args:
            indicators: Sequence of indicator dictionaries.
            output_path: Target filesystem path for the output file.

        Returns:
            Count of indicators written to the CSV file.
        """
        dest = Path(output_path).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            "ioc_type",
            "indicator",
            "severity",
            "distinct_sources_count",
            "total_occurrences",
            "first_seen",
            "last_seen",
        ]

        count = 0
        with open(dest, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
            writer.writeheader()

            for item in indicators:
                indicator_val = item.get("indicator") or item.get("normalized_value", "")
                if not indicator_val:
                    continue

                row = {
                    "ioc_type": sanitize_csv_cell(item.get("ioc_type", "")),
                    "indicator": sanitize_csv_cell(indicator_val),
                    "severity": sanitize_csv_cell(item.get("severity", "")),
                    "distinct_sources_count": item.get("distinct_sources_count", 0),
                    "total_occurrences": item.get("total_occurrences", 0),
                    "first_seen": sanitize_csv_cell(item.get("first_seen", "")),
                    "last_seen": sanitize_csv_cell(item.get("last_seen", "")),
                }
                writer.writerow(row)
                count += 1

        logger.info("Exported %d indicators to CSV blocklist: %s", count, dest)
        return count

    def export_json(
        self,
        indicators: Sequence[Dict[str, Any]],
        output_path: Union[str, Path],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Export indicators to a structured JSON file containing indicator records and metadata.

        Args:
            indicators: Sequence of indicator dictionaries.
            output_path: Target filesystem path for the output file.
            metadata: Optional top-level metadata dictionary.

        Returns:
            Count of indicators written to the JSON file.
        """
        dest = Path(output_path).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)

        formatted_indicators = []
        for item in indicators:
            indicator_val = item.get("indicator") or item.get("normalized_value", "")
            if not indicator_val:
                continue

            formatted_indicators.append(
                {
                    "ioc_type": item.get("ioc_type", ""),
                    "indicator": indicator_val,
                    "severity": item.get("severity", ""),
                    "distinct_sources_count": item.get("distinct_sources_count", 0),
                    "total_occurrences": item.get("total_occurrences", 0),
                    "first_seen": item.get("first_seen", ""),
                    "last_seen": item.get("last_seen", ""),
                    "sources": item.get("sources", []),
                }
            )

        meta = {
            "generated_at": self._get_utc_timestamp(),
            "total_indicators": len(formatted_indicators),
        }
        if metadata:
            meta.update(metadata)

        payload = {
            "metadata": meta,
            "indicators": formatted_indicators,
        }

        with open(dest, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        logger.info("Exported %d indicators to JSON blocklist: %s", len(formatted_indicators), dest)
        return len(formatted_indicators)

    def generate_category_blocklist(
        self,
        category: str,
        format_type: str = "txt",
        severity: Optional[str] = None,
        min_sources: int = 1,
        exclude_low: bool = False,
        cross_feed_only: bool = False,
        output_path: Optional[Union[str, Path]] = None,
    ) -> BlocklistExportResult:
        """Generate a blocklist for a single specific IOC category.

        Args:
            category: Specific IOC category (e.g. 'ipv4', 'domain').
            format_type: Export format ('txt', 'csv', 'json').
            severity: Optional severity filter ('HIGH', 'MEDIUM', 'LOW').
            min_sources: Minimum reporting feeds required.
            exclude_low: Exclude indicators classified as LOW severity.
            cross_feed_only: Only include indicators observed across >= 2 feeds.
            output_path: Custom output file or directory path.

        Returns:
            BlocklistExportResult metadata object.

        Raises:
            ValueError: If category or format is unsupported.
        """
        fmt = format_type.lower()
        if fmt not in SUPPORTED_EXPORT_FORMATS:
            raise ValueError(
                f"Unsupported format '{format_type}'. Supported: {', '.join(SUPPORTED_EXPORT_FORMATS)}"
            )

        cat = category.lower()
        if cat not in SUPPORTED_IOC_TYPES:
            raise ValueError(
                f"Unsupported IOC category '{category}'. Supported: {', '.join(SUPPORTED_IOC_TYPES)}"
            )

        # Retrieve filtered indicators
        indicators = self.get_indicators_for_blocklist(
            ioc_type=cat,
            severity=severity,
            min_sources=min_sources,
            exclude_low=exclude_low,
            cross_feed_only=cross_feed_only,
        )

        # Determine target file path
        if output_path is not None:
            candidate = Path(output_path)
            if candidate.is_dir() or candidate.suffix == "" or str(output_path).endswith(("/", "\\")):
                candidate.mkdir(parents=True, exist_ok=True)
                dest_file = candidate / f"blocklist_{cat}.{fmt}"
            else:
                dest_file = candidate
        else:
            dest_file = self.output_dir / f"blocklist_{cat}.{fmt}"

        filters_summary = {
            "category": cat,
            "format": fmt,
            "severity": severity.upper() if severity else None,
            "min_sources": min_sources,
            "exclude_low": exclude_low,
            "cross_feed_only": cross_feed_only,
        }

        # Export according to chosen format
        if fmt == "txt":
            count = self.export_txt(indicators, dest_file)
        elif fmt == "csv":
            count = self.export_csv(indicators, dest_file)
        elif fmt == "json":
            count = self.export_json(indicators, dest_file, metadata={"filters": filters_summary})
        else:
            raise ValueError(f"Unknown format {fmt}")

        return BlocklistExportResult(
            category=cat,
            format=fmt,
            file_path=dest_file.resolve(),
            indicator_count=count,
            filters_applied=filters_summary,
            exported_at=self._get_utc_timestamp(),
        )

    def generate_all_categories(
        self,
        format_type: str = "txt",
        severity: Optional[str] = None,
        min_sources: int = 1,
        exclude_low: bool = False,
        cross_feed_only: bool = False,
        output_dir: Optional[Union[str, Path]] = None,
    ) -> List[BlocklistExportResult]:
        """Generate separate blocklists for all 8 supported IOC categories.

        Args:
            format_type: Export format ('txt', 'csv', 'json').
            severity: Optional severity filter.
            min_sources: Minimum reporting feeds required.
            exclude_low: Exclude LOW severity indicators.
            cross_feed_only: Multi-feed consensus requirement.
            output_dir: Custom destination directory.

        Returns:
            List of BlocklistExportResult objects, one per category.
        """
        dest_dir = Path(output_dir).resolve() if output_dir else self.output_dir
        dest_dir.mkdir(parents=True, exist_ok=True)

        results: List[BlocklistExportResult] = []
        for cat in SUPPORTED_IOC_TYPES:
            res = self.generate_category_blocklist(
                category=cat,
                format_type=format_type,
                severity=severity,
                min_sources=min_sources,
                exclude_low=exclude_low,
                cross_feed_only=cross_feed_only,
                output_path=dest_dir,
            )
            results.append(res)

        return results

    def generate_combined_blocklist(
        self,
        format_type: str = "txt",
        severity: Optional[str] = None,
        min_sources: int = 1,
        exclude_low: bool = False,
        cross_feed_only: bool = False,
        output_path: Optional[Union[str, Path]] = None,
    ) -> BlocklistExportResult:
        """Generate a single unified blocklist containing indicators across all categories.

        Args:
            format_type: Export format ('txt', 'csv', 'json').
            severity: Optional severity filter.
            min_sources: Minimum reporting feeds required.
            exclude_low: Exclude LOW severity indicators.
            cross_feed_only: Multi-feed consensus requirement.
            output_path: Custom output file or directory path.

        Returns:
            BlocklistExportResult for the unified blocklist.
        """
        fmt = format_type.lower()
        if fmt not in SUPPORTED_EXPORT_FORMATS:
            raise ValueError(
                f"Unsupported format '{format_type}'. Supported: {', '.join(SUPPORTED_EXPORT_FORMATS)}"
            )

        indicators = self.get_indicators_for_blocklist(
            ioc_type="all",
            severity=severity,
            min_sources=min_sources,
            exclude_low=exclude_low,
            cross_feed_only=cross_feed_only,
        )

        if output_path is not None:
            candidate = Path(output_path)
            if candidate.is_dir() or candidate.suffix == "" or str(output_path).endswith(("/", "\\")):
                candidate.mkdir(parents=True, exist_ok=True)
                dest_file = candidate / f"blocklist_all.{fmt}"
            else:
                dest_file = candidate
        else:
            dest_file = self.output_dir / f"blocklist_all.{fmt}"

        filters_summary = {
            "category": "all",
            "format": fmt,
            "severity": severity.upper() if severity else None,
            "min_sources": min_sources,
            "exclude_low": exclude_low,
            "cross_feed_only": cross_feed_only,
        }

        if fmt == "txt":
            count = self.export_txt(indicators, dest_file)
        elif fmt == "csv":
            count = self.export_csv(indicators, dest_file)
        elif fmt == "json":
            count = self.export_json(indicators, dest_file, metadata={"filters": filters_summary})
        else:
            raise ValueError(f"Unknown format {fmt}")

        return BlocklistExportResult(
            category="all",
            format=fmt,
            file_path=dest_file.resolve(),
            indicator_count=count,
            filters_applied=filters_summary,
            exported_at=self._get_utc_timestamp(),
        )

    def generate_blocklist(
        self,
        ioc_type: Optional[str] = None,
        format_type: str = "txt",
        severity: Optional[str] = None,
        min_sources: int = 1,
        exclude_low: bool = False,
        cross_feed_only: bool = False,
        output_path: Optional[Union[str, Path]] = None,
        combined: bool = False,
    ) -> List[BlocklistExportResult]:
        """High-level dispatcher for generating single, multi-category, or combined blocklists.

        Args:
            ioc_type: Category to export ('ipv4', etc.) or None/'all' for all categories.
            format_type: Export format ('txt', 'csv', 'json').
            severity: Optional severity filter.
            min_sources: Minimum reporting feeds required.
            exclude_low: Exclude LOW severity indicators.
            cross_feed_only: Multi-feed consensus requirement.
            output_path: Custom destination file or directory path.
            combined: When exporting all categories, if True combine into a single file.

        Returns:
            List of BlocklistExportResult metadata objects.
        """
        if ioc_type is None or ioc_type.lower() == "all":
            if combined:
                res = self.generate_combined_blocklist(
                    format_type=format_type,
                    severity=severity,
                    min_sources=min_sources,
                    exclude_low=exclude_low,
                    cross_feed_only=cross_feed_only,
                    output_path=output_path,
                )
                return [res]
            else:
                return self.generate_all_categories(
                    format_type=format_type,
                    severity=severity,
                    min_sources=min_sources,
                    exclude_low=exclude_low,
                    cross_feed_only=cross_feed_only,
                    output_dir=output_path,
                )
        else:
            res = self.generate_category_blocklist(
                category=ioc_type,
                format_type=format_type,
                severity=severity,
                min_sources=min_sources,
                exclude_low=exclude_low,
                cross_feed_only=cross_feed_only,
                output_path=output_path,
            )
            return [res]
