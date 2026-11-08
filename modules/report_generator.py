"""IOC Report Generator for Threat Intelligence Aggregator.

Generates comprehensive, multi-format threat intelligence reports (Markdown, JSON, CSV)
synthesizing cross-feed correlations, deterministic severity metrics, IOC distributions,
source contributions, data quality audits, and feed processing summaries.
"""

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from config.settings import (
    DEFAULT_DB_PATH,
    REPORTS_DIR,
    SEVERITY_THRESHOLDS,
    SUPPORTED_IOC_TYPES,
)
from modules.correlation import CorrelationEngine, CorrelationResult
from modules.database_manager import DatabaseManager

logger = logging.getLogger(__name__)

SUPPORTED_REPORT_FORMATS = ("md", "json", "csv")


def sanitize_csv_cell(value: Any) -> Any:
    """Neutralize potential CSV formula injection (DDE execution) in spreadsheet readers.

    Prefixes characters '=', '+', '-', '@', tab, and CR with a single quote.
    """
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


@dataclass
class ReportResult:
    """Standardized metadata representing a generated threat intelligence report.

    Attributes:
        format: Export format ('md', 'json', 'csv').
        file_path: Filesystem path to the generated report file.
        generated_at: UTC ISO 8601 timestamp of generation.
        total_indicators: Count of indicators analyzed/exported in the report.
        filters_applied: Summary of criteria filters used to generate the report.
    """

    format: str
    file_path: Path
    generated_at: str
    total_indicators: int
    filters_applied: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary representation."""
        return {
            "format": self.format,
            "file_path": str(self.file_path),
            "generated_at": self.generated_at,
            "total_indicators": self.total_indicators,
            "filters_applied": self.filters_applied,
        }


class ReportGenerator:
    """Generates structured cybersecurity threat intelligence reports in Markdown, JSON, and CSV."""

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        db_path: Union[str, Path] = DEFAULT_DB_PATH,
        output_dir: Union[str, Path] = REPORTS_DIR,
    ) -> None:
        """Initialize ReportGenerator with database access and output destination.

        Args:
            db_manager: Existing DatabaseManager instance or None.
            db_path: Database path if creating a new DatabaseManager.
            output_dir: Target directory for generated reports.
        """
        self.db_manager = db_manager or DatabaseManager(db_path=db_path)
        self.correlation_engine = CorrelationEngine(db_manager=self.db_manager)
        self.output_dir = Path(output_dir).resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def get_supported_formats() -> List[str]:
        """Return supported report file formats."""
        return list(SUPPORTED_REPORT_FORMATS)

    @staticmethod
    def _get_utc_timestamp() -> str:
        """Return current ISO 8601 UTC timestamp."""
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _escape_md(text: Any) -> str:
        """Escape Markdown pipe characters and special characters for safe table rendering."""
        if text is None:
            return ""
        s = str(text)
        return s.replace("|", "\\|").replace("\n", " ").strip()

    def resolve_destination(
        self,
        target_path: Optional[Union[str, Path]],
        format_type: str,
        overwrite: bool = False,
    ) -> Path:
        """Determine safe output destination path, avoiding silent file overwrites.

        Args:
            target_path: Custom output file or directory, or None for default.
            format_type: Format extension ('md', 'json', 'csv').
            overwrite: If True, allow overwriting existing file.

        Returns:
            Resolved unique Path object.
        """
        fmt = format_type.lower()
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
        default_filename = f"threat_report_{now_str}.{fmt}"

        if target_path is not None:
            candidate = Path(target_path)
            if candidate.is_dir() or candidate.suffix == "" or str(target_path).endswith(("/", "\\")):
                candidate.mkdir(parents=True, exist_ok=True)
                dest = candidate / default_filename
            else:
                dest = candidate
        else:
            dest = self.output_dir / default_filename

        dest = dest.resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)

        if overwrite or not dest.exists():
            return dest

        # Collision avoidance: append counter before extension
        stem = dest.stem
        suffix = dest.suffix
        parent = dest.parent
        counter = 1
        while True:
            unique_candidate = parent / f"{stem}_{counter}{suffix}"
            if not unique_candidate.exists():
                logger.info(
                    "Target report '%s' exists; saving with unique suffix to '%s'",
                    dest,
                    unique_candidate,
                )
                return unique_candidate
            counter += 1

    def collect_report_data(
        self,
        severity: Optional[str] = None,
        ioc_type: Optional[str] = None,
        cross_feed_only: bool = False,
        top: int = 10,
    ) -> Dict[str, Any]:
        """Aggregate comprehensive threat intelligence metrics across repository tables.

        Args:
            severity: Optional severity filter ('HIGH', 'MEDIUM', 'LOW').
            ioc_type: Optional IOC type filter.
            cross_feed_only: If True, restrict to cross-feed indicators (sources >= 2).
            top: Number of top repeated indicators to include (default: 10).

        Returns:
            Nested dictionary containing complete report analytics.
        """
        generated_at = self._get_utc_timestamp()

        # Validate inputs
        normalized_sev = severity.upper() if severity else None
        if normalized_sev and normalized_sev not in ("HIGH", "MEDIUM", "LOW"):
            raise ValueError(
                f"Invalid severity filter: '{severity}'. Allowed: HIGH, MEDIUM, LOW"
            )

        normalized_type = ioc_type.lower() if ioc_type else None
        if normalized_type and normalized_type not in SUPPORTED_IOC_TYPES and normalized_type != "all":
            raise ValueError(
                f"Unsupported IOC type: '{ioc_type}'. Supported: {', '.join(SUPPORTED_IOC_TYPES)}"
            )

        if top < 1:
            raise ValueError(f"top parameter must be >= 1, got {top}")

        # 1. Base statistics & repository state
        base_stats = self.db_manager.get_statistics()
        correlation_stats = self.correlation_engine.get_correlation_statistics()
        data_quality = self.db_manager.get_data_quality_metrics()
        source_stats = self.db_manager.get_source_statistics()
        feed_summary = self.db_manager.get_feed_run_summary()

        total_indicators = base_stats["total_indicators"]
        total_obs = base_stats["total_observations"]
        total_sources = base_stats["total_sources"]

        # Severity breakdown & percentages
        by_sev_raw = base_stats["by_severity"]
        sev_dist = {}
        for s in ("HIGH", "MEDIUM", "LOW"):
            count = by_sev_raw.get(s, 0)
            pct = (count / total_indicators * 100) if total_indicators > 0 else 0.0
            sev_dist[s] = {"count": count, "percentage": round(pct, 1)}

        # IOC type breakdown
        by_type_raw = base_stats["by_type"]
        type_dist = {}
        for t in SUPPORTED_IOC_TYPES:
            count = by_type_raw.get(t, 0)
            pct = (count / total_indicators * 100) if total_indicators > 0 else 0.0
            type_dist[t] = {"count": count, "percentage": round(pct, 1)}

        # 2. Correlated indicators matching requested filters
        effective_min = 2 if cross_feed_only else 1
        correlations = self.correlation_engine.correlate_all(
            min_sources=effective_min,
            severity=normalized_sev,
            ioc_type=normalized_type if normalized_type != "all" else None,
        )

        correlated_list = [c.to_dict() for c in correlations]

        # 3. Top repeated indicators
        top_repeated = self.db_manager.get_top_repeated_indicators(
            limit=top,
            ioc_type=normalized_type if normalized_type != "all" else None,
            severity=normalized_sev,
            cross_feed_only=cross_feed_only,
        )

        filters_summary = {
            "severity": normalized_sev,
            "ioc_type": normalized_type,
            "cross_feed_only": cross_feed_only,
            "top": top,
        }

        return {
            "metadata": {
                "generated_at": generated_at,
                "database_path": str(self.db_manager.db_path),
                "filters_applied": filters_summary,
            },
            "executive_summary": {
                "generated_at": generated_at,
                "total_unique_indicators": total_indicators,
                "total_observations": total_obs,
                "total_sources": total_sources,
                "cross_feed_indicators_count": correlation_stats["cross_feed_indicators_count"],
                "cross_feed_percentage": round(correlation_stats["cross_feed_percentage"], 1),
                "single_source_indicators_count": correlation_stats["single_source_indicators_count"],
                "severity_distribution": sev_dist,
            },
            "ioc_statistics": type_dist,
            "severity_analysis": {
                "distribution": sev_dist,
                "thresholds": {
                    "HIGH": "Observed across 5 or more distinct intelligence feeds (distinct_sources >= 5)",
                    "MEDIUM": "Observed across 2 to 4 distinct intelligence feeds (2 <= distinct_sources <= 4)",
                    "LOW": "Observed in exactly 1 intelligence feed (distinct_sources == 1)",
                },
                "heuristic_notice": (
                    "Severity ratings are deterministic heuristics based on multi-feed consensus "
                    "and corroboration density. They do not constitute absolute proof that an indicator is malicious."
                ),
            },
            "cross_feed_correlations": correlated_list,
            "source_analysis": source_stats,
            "top_repeated_indicators": top_repeated,
            "data_quality": data_quality,
            "feed_processing_summary": feed_summary,
        }

    def generate_markdown(
        self,
        data: Dict[str, Any],
        output_path: Optional[Union[str, Path]] = None,
        overwrite: bool = False,
    ) -> ReportResult:
        """Format aggregated metrics into a professional GitHub Flavored Markdown cybersecurity report.

        Args:
            data: Aggregated report dictionary from collect_report_data.
            output_path: Target filesystem path or directory.
            overwrite: If True, overwrite destination if it exists.

        Returns:
            ReportResult metadata object.
        """
        dest = self.resolve_destination(output_path, "md", overwrite=overwrite)

        meta = data["metadata"]
        exec_sum = data["executive_summary"]
        ioc_stats = data["ioc_statistics"]
        sev_analysis = data["severity_analysis"]
        correlations = data["cross_feed_correlations"]
        sources = data["source_analysis"]
        top_iocs = data["top_repeated_indicators"]
        dq = data["data_quality"]
        feed_summary = data["feed_processing_summary"]

        lines: List[str] = []

        # Title & Metadata
        lines.append("# Threat Intelligence Analysis & Audit Report")
        lines.append("")
        lines.append("> [!NOTE]")
        lines.append(f"> **Report Generated (UTC):** `{meta['generated_at']}`  ")
        lines.append(f"> **Database Target:** `{meta['database_path']}`  ")
        filters_str = ", ".join(
            f"{k}={v}" for k, v in meta["filters_applied"].items() if v is not None and v is not False
        )
        lines.append(f"> **Filters Applied:** `{filters_str or 'None (Full Repository)'}`")
        lines.append("")

        # 1. Executive Summary
        lines.append("## 1. Executive Summary")
        lines.append("")
        lines.append(
            "This report summarizes Indicators of Compromise (IOCs) ingested, validated, normalized, "
            "and correlated by the Threat Intelligence Aggregator. All evaluations utilize deterministic "
            "mathematical heuristics without external AI/LLM models."
        )
        lines.append("")
        lines.append("| Metric | Count | Percentage / Detail |")
        lines.append("|:---|:---:|:---|")
        lines.append(f"| **Total Unique Indicators** | `{exec_sum['total_unique_indicators']}` | 100.0% of canonical repository |")
        lines.append(f"| **Total Observations** | `{exec_sum['total_observations']}` | Individual feed sightings recorded |")
        lines.append(f"| **Distinct Threat Sources** | `{exec_sum['total_sources']}` | Active intelligence providers |")
        lines.append(
            f"| **Cross-Feed Corroborated (>= 2 Sources)** | `{exec_sum['cross_feed_indicators_count']}` | "
            f"`{exec_sum['cross_feed_percentage']}%` multi-feed consensus |"
        )
        lines.append(
            f"| **Single-Source Indicators** | `{exec_sum['single_source_indicators_count']}` | "
            f"`{100.0 - exec_sum['cross_feed_percentage']:.1f}%` isolated observations |"
        )
        lines.append("")

        # 2. IOC Statistics
        lines.append("## 2. IOC Category Statistics")
        lines.append("")
        lines.append("| IOC Category | Indicator Count | Share of Repository |")
        lines.append("|:---|:---:|:---:|")
        for t in SUPPORTED_IOC_TYPES:
            item = ioc_stats.get(t, {"count": 0, "percentage": 0.0})
            lines.append(f"| `{t}` | {item['count']} | {item['percentage']}% |")
        lines.append("")

        # 3. Severity Analysis
        lines.append("## 3. Severity Analysis & Scoring Model")
        lines.append("")
        lines.append(
            "Severity is deterministically calculated from the number of independent reporting feeds. "
            "Repeated observations from the same feed do not artificially inflate the score."
        )
        lines.append("")
        lines.append("| Severity Tier | Count | Percentage | Heuristic Threshold Definition |")
        lines.append("|:---|:---:|:---:|:---|")
        for sev in ("HIGH", "MEDIUM", "LOW"):
            dist = sev_analysis["distribution"].get(sev, {"count": 0, "percentage": 0.0})
            thresh = sev_analysis["thresholds"].get(sev, "")
            lines.append(f"| **{sev}** | `{dist['count']}` | {dist['percentage']}% | {thresh} |")
        lines.append("")
        lines.append("> [!IMPORTANT]")
        lines.append(f"> **Heuristic Scoring Notice:** {sev_analysis['heuristic_notice']}")
        lines.append("")

        # 4. Cross-Feed Correlation
        lines.append("## 4. Cross-Feed Correlation & Consensus")
        lines.append("")
        lines.append(
            "Indicators observed across multiple distinct intelligence feeds demonstrate heightened corroboration."
        )
        lines.append("")
        if correlations:
            lines.append("| ID | Type | Normalized Indicator | Severity | Distinct Feeds | Total Sightings | Reporting Sources | First Seen | Last Seen |")
            lines.append("|:---:|:---|:---|:---:|:---:|:---:|:---|:---|:---|")
            for c in correlations:
                val = self._escape_md(c["normalized_value"])
                srcs = self._escape_md(", ".join(c.get("sources", [])))
                fs = c.get("first_seen", "")[:19]
                ls = c.get("last_seen", "")[:19]
                lines.append(
                    f"| {c['indicator_id']} | `{c['ioc_type']}` | `{val}` | **{c['severity']}** | "
                    f"`{c['distinct_sources_count']}` | `{c['total_occurrences']}` | {srcs} | `{fs}` | `{ls}` |"
                )
        else:
            lines.append("*No indicators matched the correlation and consensus criteria.*")
        lines.append("")

        # 5. Source Analysis
        lines.append("## 5. Intelligence Source Analysis")
        lines.append("")
        lines.append("Aggregated contribution breakdown across registered intelligence feeds.")
        lines.append("")
        if sources:
            lines.append("| Source Name | Type | Feed Format | Total Observations | Unique IOCs | First Registered |")
            lines.append("|:---|:---:|:---:|:---:|:---:|:---|")
            for s in sources:
                s_name = self._escape_md(s["source_name"])
                lines.append(
                    f"| **{s_name}** | `{s['source_type']}` | `{s['feed_format']}` | "
                    f"`{s['total_observations']}` | `{s['unique_indicators']}` | `{s['first_seen'][:19]}` |"
                )
        else:
            lines.append("*No intelligence feed sources currently registered in database.*")
        lines.append("")

        # 6. Top Repeated Indicators
        lines.append("## 6. Top Repeated Indicators")
        lines.append("")
        lines.append(f"Top {len(top_iocs)} most frequently sighted threat indicators in repository:")
        lines.append("")
        if top_iocs:
            lines.append("| Rank | Indicator | Type | Severity | Total Sightings | Distinct Sources | Observing Feeds |")
            lines.append("|:---:|:---|:---:|:---:|:---:|:---:|:---|")
            for idx, item in enumerate(top_iocs, 1):
                val = self._escape_md(item["indicator"])
                srcs = self._escape_md(", ".join(item.get("sources", [])))
                lines.append(
                    f"| {idx} | `{val}` | `{item['ioc_type']}` | **{item['severity']}** | "
                    f"`{item['total_occurrences']}` | `{item['distinct_sources_count']}` | {srcs} |"
                )
        else:
            lines.append("*No repeated indicators found matching the criteria.*")
        lines.append("")

        # 7. Data Quality Audit
        lines.append("## 7. Data Quality & Integrity Audit")
        lines.append("")
        lines.append("| Quality Metric | Value | Interpretation |")
        lines.append("|:---|:---:|:---|")
        lines.append(f"| **Syntactically Valid IOCs** | `{dq['valid_indicators']}` | Conforms to strict RFC / cryptographic specs |")
        lines.append(f"| **Syntactically Invalid IOCs** | `{dq['invalid_indicators']}` | Flagged during ingestion (rejected from blocklists) |")
        lines.append(f"| **Duplicate Observations Collapsed** | `{dq['duplicate_observations']}` | Redundant sightings deduplicated into provenance records |")
        lines.append(f"| **Observations with Metadata** | `{dq['total_observations'] - dq['empty_metadata_observations']}` | `{dq['metadata_completeness_pct']:.1f}%` observation metadata completeness |")
        lines.append("")
        lines.append("### Data Limitations")
        lines.append(
            "- **Syntactic Validation:** Validation confirms syntactic correctness; indicators are not independently probed or scanned.\n"
            "- **Offline Processing:** No live DNS lookups or WHOIS lookups are executed to maintain analyst opsec.\n"
            "- **Source-Relative Scoring:** Corroboration relies entirely on the diversity and independence of feeds ingested."
        )
        lines.append("")

        # 8. Feed Processing Summary
        lines.append("## 8. Feed Processing Summary")
        lines.append("")
        if feed_summary.get("has_history"):
            lines.append(
                f"- **Total Feeds Processed:** `{feed_summary['total_runs']}`  \n"
                f"- **Successful Ingestion Runs:** `{feed_summary['successful_runs']}`  \n"
                f"- **Failed Ingestion Runs:** `{feed_summary['failed_runs']}`"
            )
            lines.append("")
            if feed_summary.get("errors"):
                lines.append("### Ingestion Errors Encountered")
                lines.append("")
                lines.append("| Source Name | Location | Error Message | Processed At |")
                lines.append("|:---|:---|:---|:---|")
                for err in feed_summary["errors"]:
                    sname = self._escape_md(err["source_name"])
                    loc = self._escape_md(err["source_location"])
                    emsg = self._escape_md(err["error_message"])
                    lines.append(f"| `{sname}` | `{loc}` | {emsg} | `{err['processed_at'][:19]}` |")
                lines.append("")
        else:
            lines.append(
                "> [!NOTE]\n"
                "> No persistent feed ingestion run history recorded in this database. "
                "(Run history tracking is active for CLI ingest operations)."
            )
            lines.append("")

        # Write to file
        with open(dest, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        logger.info("Markdown report successfully generated at: %s", dest)
        return ReportResult(
            format="md",
            file_path=dest,
            generated_at=meta["generated_at"],
            total_indicators=exec_sum["total_unique_indicators"],
            filters_applied=meta["filters_applied"],
        )

    def generate_json(
        self,
        data: Dict[str, Any],
        output_path: Optional[Union[str, Path]] = None,
        overwrite: bool = False,
    ) -> ReportResult:
        """Export comprehensive report analytics as a machine-readable JSON document.

        Args:
            data: Aggregated report dictionary from collect_report_data.
            output_path: Target filesystem path or directory.
            overwrite: If True, overwrite destination if it exists.

        Returns:
            ReportResult metadata object.
        """
        dest = self.resolve_destination(output_path, "json", overwrite=overwrite)

        with open(dest, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

        logger.info("JSON report successfully generated at: %s", dest)
        return ReportResult(
            format="json",
            file_path=dest,
            generated_at=data["metadata"]["generated_at"],
            total_indicators=data["executive_summary"]["total_unique_indicators"],
            filters_applied=data["metadata"]["filters_applied"],
        )

    def generate_csv(
        self,
        data: Dict[str, Any],
        output_path: Optional[Union[str, Path]] = None,
        overwrite: bool = False,
    ) -> ReportResult:
        """Export indicator and correlation analytics in structured RFC 4180 CSV format.

        Columns:
            - indicator
            - ioc_type
            - severity
            - distinct_sources_count
            - total_occurrences
            - is_cross_feed
            - first_seen
            - last_seen
            - sources

        Args:
            data: Aggregated report dictionary from collect_report_data.
            output_path: Target filesystem path or directory.
            overwrite: If True, overwrite destination if it exists.

        Returns:
            ReportResult metadata object.
        """
        dest = self.resolve_destination(output_path, "csv", overwrite=overwrite)

        fieldnames = [
            "indicator",
            "ioc_type",
            "severity",
            "distinct_sources_count",
            "total_occurrences",
            "is_cross_feed",
            "first_seen",
            "last_seen",
            "sources",
        ]

        correlations = data.get("cross_feed_correlations", [])

        with open(dest, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
            writer.writeheader()

            for item in correlations:
                srcs = item.get("sources", [])
                srcs_str = ";".join(srcs) if isinstance(srcs, list) else str(srcs)
                writer.writerow(
                    {
                        "indicator": sanitize_csv_cell(item.get("normalized_value") or item.get("indicator", "")),
                        "ioc_type": sanitize_csv_cell(item.get("ioc_type", "")),
                        "severity": sanitize_csv_cell(item.get("severity", "")),
                        "distinct_sources_count": item.get("distinct_sources_count", 0),
                        "total_occurrences": item.get("total_occurrences", 0),
                        "is_cross_feed": item.get("is_cross_feed", False),
                        "first_seen": sanitize_csv_cell(item.get("first_seen", "")),
                        "last_seen": sanitize_csv_cell(item.get("last_seen", "")),
                        "sources": sanitize_csv_cell(srcs_str),
                    }
                )

        logger.info("CSV report successfully generated at: %s", dest)
        return ReportResult(
            format="csv",
            file_path=dest,
            generated_at=data["metadata"]["generated_at"],
            total_indicators=len(correlations),
            filters_applied=data["metadata"]["filters_applied"],
        )

    def generate_report(
        self,
        format_type: str = "md",
        severity: Optional[str] = None,
        ioc_type: Optional[str] = None,
        cross_feed_only: bool = False,
        top: int = 10,
        output_path: Optional[Union[str, Path]] = None,
        overwrite: bool = False,
    ) -> ReportResult:
        """High-level dispatcher for generating reports in Markdown, JSON, or CSV.

        Args:
            format_type: 'md', 'json', or 'csv' (case-insensitive).
            severity: Optional severity filter.
            ioc_type: Optional IOC category filter.
            cross_feed_only: If True, require multi-source corroboration.
            top: Top repeated indicators count (default: 10).
            output_path: Custom destination file or directory path.
            overwrite: If True, allow overwriting existing file.

        Returns:
            ReportResult metadata object.

        Raises:
            ValueError: If format_type is unsupported.
        """
        fmt = format_type.lower()
        if fmt not in SUPPORTED_REPORT_FORMATS:
            raise ValueError(
                f"Unsupported report format: '{format_type}'. Supported: {', '.join(SUPPORTED_REPORT_FORMATS)}"
            )

        data = self.collect_report_data(
            severity=severity,
            ioc_type=ioc_type,
            cross_feed_only=cross_feed_only,
            top=top,
        )

        if fmt == "md":
            return self.generate_markdown(data, output_path=output_path, overwrite=overwrite)
        elif fmt == "json":
            return self.generate_json(data, output_path=output_path, overwrite=overwrite)
        elif fmt == "csv":
            return self.generate_csv(data, output_path=output_path, overwrite=overwrite)
        else:
            raise ValueError(f"Unknown format: {fmt}")
