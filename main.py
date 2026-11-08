"""Threat Intelligence Aggregator (Non-AI) - CLI Toolkit.

A deterministic cybersecurity Blue Team utility for collecting threat
intelligence feeds, extracting Indicators of Compromise (IOCs), validating,
normalizing, correlating repeated indicators, calculating risk levels,
and generating categorized blocklists and analytical reports.
"""

import argparse
from collections import Counter
import logging
import sys
from pathlib import Path
from typing import Any, List, Optional

# Add project root to path if executed directly
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import (
    BLOCKLISTS_DIR,
    DEFAULT_DB_PATH,
    DEFAULT_LOG_PATH,
    LOG_DATE_FORMAT,
    LOG_FORMAT,
    REPORTS_DIR,
    SUPPORTED_FEED_FORMATS,
    SUPPORTED_IOC_TYPES,
    ensure_runtime_directories,
)
from modules.blocklist_generator import BlocklistExportResult, BlocklistGenerator
from modules.correlation import CorrelationEngine, CorrelationResult
from modules.database_manager import DatabaseManager
from modules.feed_collector import FeedCollector, FeedResult
from modules.ioc_parser import IOCParser, ParsedIOC
from modules.normalizer import DeduplicatedIOC, IOCNormalizer, NormalizedIOC
from modules.pipeline import PipelineResult, ThreatIntelligencePipeline
from modules.report_generator import ReportGenerator, ReportResult
from modules.validator import IOCValidator, ValidationResult

logger = logging.getLogger("aggregator")


def setup_logging(verbose: bool = False, log_file: Path = DEFAULT_LOG_PATH) -> None:
    """Configure system logging for console and file output."""
    level = logging.DEBUG if verbose else logging.INFO
    log_file.parent.mkdir(parents=True, exist_ok=True)

    handlers = [
        logging.FileHandler(log_file, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ]

    logging.basicConfig(
        level=level,
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
        handlers=handlers,
        force=True,
    )


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the top-level CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="threat-intel-aggregator",
        description="Deterministic Threat Intelligence Aggregator (Non-AI CLI Toolkit)",
        epilog="Supported IOC types: " + ", ".join(SUPPORTED_IOC_TYPES),
    )
    parser.add_argument(
        "--version",
        action="version",
        version="Threat Intelligence Aggregator v1.9.0 (Phase 10 End-to-End CLI Integration)",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"Path to SQLite database file (default: {DEFAULT_DB_PATH})",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=DEFAULT_LOG_PATH,
        help=f"Path to log output file (default: {DEFAULT_LOG_PATH})",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose DEBUG logging to console",
    )

    subparsers = parser.add_subparsers(dest="command", help="Operational commands")

    # Status / Info command
    subparsers.add_parser("status", help="Display toolkit configuration and environment status")

    # Collect command (Phase 2)
    collect_parser = subparsers.add_parser(
        "collect",
        help="Collect threat intelligence feeds from local files and remote URLs",
    )
    collect_parser.add_argument(
        "--file", "-f",
        dest="files",
        nargs="+",
        metavar="PATH",
        help="One or more local feed file paths (CSV, TXT, JSON)",
    )
    collect_parser.add_argument(
        "--url", "-u",
        dest="urls",
        nargs="+",
        metavar="URL",
        help="One or more remote feed URLs (HTTP/HTTPS)",
    )

    # Parse command (Phase 3)
    parse_parser = subparsers.add_parser(
        "parse",
        help="Parse and extract candidate Indicators of Compromise from feeds",
    )
    parse_parser.add_argument(
        "--file", "-f",
        dest="files",
        nargs="+",
        metavar="PATH",
        required=True,
        help="One or more local feed file paths (CSV, TXT, JSON)",
    )

    # Validate command (Phase 4)
    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate syntax and classify network scope for extracted IOC candidates",
    )
    validate_parser.add_argument(
        "--file", "-f",
        dest="files",
        nargs="+",
        metavar="PATH",
        required=True,
        help="One or more local feed file paths (CSV, TXT, JSON)",
    )

    # Normalize command (Phase 5)
    normalize_parser = subparsers.add_parser(
        "normalize",
        help="Normalize valid IOCs into canonical representations and collapse duplicates",
    )
    normalize_parser.add_argument(
        "--file", "-f",
        dest="files",
        nargs="+",
        metavar="PATH",
        required=True,
        help="One or more local feed file paths (CSV, TXT, JSON)",
    )
    normalize_parser.add_argument(
        "--save",
        action="store_true",
        help="Persist normalized indicators directly to the SQLite database",
    )

    # Database management command (Phase 6)
    db_parser = subparsers.add_parser(
        "db",
        help="Database management, inspection, and threat queries",
    )
    db_subparsers = db_parser.add_subparsers(dest="db_action", help="Database actions")

    # db init
    db_subparsers.add_parser("init", help="Initialize SQLite schema and indexes")

    # db stats
    db_subparsers.add_parser("stats", help="Display repository statistics and breakdown")

    # db list
    list_parser = db_subparsers.add_parser("list", help="List stored indicators")
    list_parser.add_argument("--type", "-t", dest="ioc_type", help="Filter by IOC type")
    list_parser.add_argument("--severity", "-s", dest="severity", help="Filter by severity (HIGH, MEDIUM, LOW)")
    list_parser.add_argument("--limit", "-l", type=int, default=50, help="Maximum indicators to display (default: 50)")

    # db show <indicator_id>
    show_parser = db_subparsers.add_parser("show", help="Display detailed provenance for a specific indicator")
    show_parser.add_argument("indicator_id", type=int, help="Integer ID of the indicator")

    # db ingest
    ingest_parser = db_subparsers.add_parser("ingest", help="Ingest, normalize, and store feed files directly to database")
    ingest_parser.add_argument(
        "--file", "-f",
        dest="files",
        nargs="+",
        metavar="PATH",
        required=True,
        help="One or more feed file paths to ingest and persist",
    )

    # Correlate command (Phase 7)
    correlate_parser = subparsers.add_parser(
        "correlate",
        help="Correlate threat indicators across multiple feeds and calculate deterministic risk",
    )
    correlate_parser.add_argument(
        "--severity", "-s",
        dest="severity",
        choices=["HIGH", "MEDIUM", "LOW", "high", "medium", "low"],
        help="Filter correlations by severity tier",
    )
    correlate_parser.add_argument(
        "--type", "-t",
        dest="ioc_type",
        help="Filter correlations by IOC type (e.g. ipv4, domain, hash)",
    )
    correlate_parser.add_argument(
        "--min-sources", "-m",
        type=int,
        default=1,
        help="Minimum number of distinct observing feeds required (default: 1)",
    )
    correlate_parser.add_argument(
        "--indicator-id", "-i",
        type=int,
        dest="indicator_id",
        help="Correlate and inspect a single indicator by its integer ID",
    )

    # Blocklist command (Phase 8)
    blocklist_parser = subparsers.add_parser(
        "blocklist",
        help="Generate categorized threat blocklists in TXT, CSV, or JSON formats",
    )
    blocklist_parser.add_argument(
        "--type", "-t",
        dest="ioc_type",
        help="Target IOC category (e.g. ipv4, domain, sha256) or 'all'",
    )
    blocklist_parser.add_argument(
        "--format", "-f",
        dest="format",
        choices=["txt", "csv", "json", "TXT", "CSV", "JSON"],
        default="txt",
        help="Export file format: txt, csv, or json (default: txt)",
    )
    blocklist_parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="Export all supported IOC categories",
    )
    blocklist_parser.add_argument(
        "--combined",
        action="store_true",
        help="When exporting all categories, combine into a single file (blocklist_all.<format>)",
    )
    blocklist_parser.add_argument(
        "--severity", "-s",
        dest="severity",
        choices=["HIGH", "MEDIUM", "LOW", "high", "medium", "low"],
        help="Filter indicators by deterministic severity tier",
    )
    blocklist_parser.add_argument(
        "--min-sources", "-m",
        type=int,
        default=1,
        help="Minimum number of distinct reporting feeds required (default: 1)",
    )
    blocklist_parser.add_argument(
        "--exclude-low",
        action="store_true",
        help="Exclude indicators classified as LOW severity",
    )
    blocklist_parser.add_argument(
        "--cross-feed-only",
        action="store_true",
        help="Include only corroborated indicators observed across >= 2 distinct feeds",
    )
    blocklist_parser.add_argument(
        "--output", "-o",
        type=Path,
        dest="output",
        help="Custom destination directory or output file path",
    )

    # Report command (Phase 9)
    report_parser = subparsers.add_parser(
        "report",
        help="Generate comprehensive threat intelligence analytical and audit reports",
    )
    report_parser.add_argument(
        "--format", "-f",
        dest="format",
        choices=["md", "json", "csv", "MD", "JSON", "CSV"],
        default="md",
        help="Report export format: md (Markdown), json, or csv (default: md)",
    )
    report_parser.add_argument(
        "--output", "-o",
        type=Path,
        dest="output",
        help="Custom output file or directory path",
    )
    report_parser.add_argument(
        "--severity", "-s",
        dest="severity",
        choices=["HIGH", "MEDIUM", "LOW", "high", "medium", "low"],
        help="Filter report findings by severity tier",
    )
    report_parser.add_argument(
        "--type", "-t",
        dest="ioc_type",
        help="Filter report findings by IOC category (e.g. ipv4, domain, etc.)",
    )
    report_parser.add_argument(
        "--cross-feed-only",
        action="store_true",
        help="Restrict analysis to indicators corroborated across >= 2 distinct feeds",
    )
    report_parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of top repeated indicators to display (default: 10)",
    )
    report_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow overwriting existing report file if collision occurs",
    )

    # Pipeline command (Phase 10)
    pipeline_parser = subparsers.add_parser(
        "pipeline",
        help="Execute complete end-to-end ingestion, validation, normalization, and persistence pipeline",
    )
    pipeline_parser.add_argument(
        "--file", "-f",
        dest="files",
        action="append",
        nargs="+",
        metavar="PATH",
        help="Local feed file path (CSV, TXT, JSON); repeatable",
    )
    pipeline_parser.add_argument(
        "--url", "-u",
        dest="urls",
        action="append",
        nargs="+",
        metavar="URL",
        help="Remote feed URL (HTTP/HTTPS); repeatable",
    )
    pipeline_parser.add_argument(
        "--generate-report",
        action="store_true",
        help="Generate comprehensive Markdown report after ingestion completes",
    )
    pipeline_parser.add_argument(
        "--generate-blocklists",
        action="store_true",
        help="Generate standard categorized blocklists after ingestion completes",
    )

    return parser


def flatten_sources(raw_list: Optional[List[Any]]) -> List[str]:
    """Flatten nested lists from repeatable and space-separated CLI arguments."""
    if not raw_list:
        return []
    flat: List[str] = []
    for item in raw_list:
        if isinstance(item, list):
            flat.extend(str(x) for x in item)
        else:
            flat.append(str(item))
    return flat


def handle_collect(files: list[str] | None, urls: list[str] | None) -> int:
    """Execute feed collection across provided files and URLs, displaying a formatted summary."""
    collector = FeedCollector()
    sources = []
    if files:
        sources.extend(files)
    if urls:
        sources.extend(urls)

    if not sources:
        print("[!] Error: No feeds specified. Provide at least one --file or --url.")
        print("    Run 'threat-intel-aggregator collect --help' for usage examples.")
        return 1

    print(f"[*] Starting feed collection ({len(sources)} total source(s) queued)...")
    results = collector.collect_many(sources)

    print("\n" + "=" * 90)
    print(f"{'FEED COLLECTION SUMMARY':^90}")
    print("=" * 90)
    print(f"{'Source Name':<28} | {'Type':<6} | {'Format':<6} | {'Status':<9} | {'Payload':<10} | {'Details'}")
    print("-" * 90)

    success_count = 0
    failure_count = 0

    for res in results:
        status_str = "SUCCESS" if res.success else "FAILED"
        if res.success:
            success_count += 1
            payload_info = f"{len(res.raw_content)} chars"
            detail = f"Fetched {res.fetched_at[:19]}Z"
        else:
            failure_count += 1
            payload_info = "0 chars"
            detail = res.error

        src_name = res.source_name[:26] + ".." if len(res.source_name) > 28 else res.source_name
        print(f"{src_name:<28} | {res.source_type:<6} | {res.format:<6} | {status_str:<9} | {payload_info:<10} | {detail}")

    print("-" * 90)
    print(f"Total Attempted: {len(results)} | Succeeded: {success_count} | Failed: {failure_count}")
    print("=" * 90 + "\n")

    return 0 if failure_count == 0 else (0 if success_count > 0 else 1)


def handle_parse(files: list[str]) -> int:
    """Collect and extract candidate IOCs from specified feed files."""
    collector = FeedCollector()
    parser = IOCParser()

    print(f"[*] Ingesting and parsing {len(files)} feed file(s)...")
    feed_results = collector.collect_many(files)

    successful_feeds = [f for f in feed_results if f.success]
    failed_feeds = [f for f in feed_results if not f.success]

    parsed_iocs = parser.parse_many(successful_feeds)
    type_counts = Counter(ioc.ioc_type for ioc in parsed_iocs)

    print("\n" + "=" * 70)
    print(f"{'IOC CANDIDATE EXTRACTION SUMMARY':^70}")
    print("=" * 70)
    print(f"Total Feeds Attempted: {len(feed_results)}")
    print(f"Feeds Succeeded:      {len(successful_feeds)}")
    print(f"Feeds Failed:         {len(failed_feeds)}")
    print(f"Total IOC Candidates: {len(parsed_iocs)}")
    print("-" * 70)
    print(f"{'IOC Type':<20} | {'Candidate Count':>15} | {'Supported'}")
    print("-" * 70)

    for ioc_type in SUPPORTED_IOC_TYPES:
        count = type_counts.get(ioc_type, 0)
        print(f"{ioc_type:<20} | {count:>15} | YES")

    print("-" * 70)

    print(f"\n{'FEED PROVENANCE BREAKDOWN':^70}")
    print("-" * 70)
    print(f"{'Feed Name':<32} | {'Format':<8} | {'Candidates Extracted':>18}")
    print("-" * 70)
    for feed in successful_feeds:
        feed_iocs_count = sum(1 for i in parsed_iocs if i.source_name == feed.source_name)
        fname = feed.source_name[:30] + ".." if len(feed.source_name) > 32 else feed.source_name
        print(f"{fname:<32} | {feed.format:<8} | {feed_iocs_count:>18}")

    if failed_feeds:
        print("\n" + "!" * 70)
        print(f"{'FAILED FEEDS':^70}")
        print("!" * 70)
        for f in failed_feeds:
            print(f"- {f.source_name}: {f.error}")

    print("=" * 70)
    print("[i] Notice: Extraction identifies candidates only. Maliciousness is not established.")
    print("=" * 70 + "\n")

    return 0 if len(parsed_iocs) > 0 or len(failed_feeds) == 0 else 1


def handle_validate(files: list[str]) -> int:
    """Collect, extract, and validate candidate IOCs, presenting detailed classification metrics."""
    collector = FeedCollector()
    parser = IOCParser()
    validator = IOCValidator()

    print(f"[*] Ingesting and validating {len(files)} feed file(s)...")
    feed_results = collector.collect_many(files)

    successful_feeds = [f for f in feed_results if f.success]
    failed_feeds = [f for f in feed_results if not f.success]

    parsed_iocs = parser.parse_many(successful_feeds)
    validation_results = validator.validate_many(parsed_iocs)

    valid_results = [r for r in validation_results if r.is_valid]
    invalid_results = [r for r in validation_results if not r.is_valid]

    type_stats: dict[str, dict[str, int]] = {t: {"valid": 0, "invalid": 0, "total": 0} for t in SUPPORTED_IOC_TYPES}
    for r in validation_results:
        t = r.ioc_type
        if t not in type_stats:
            type_stats[t] = {"valid": 0, "invalid": 0, "total": 0}
        type_stats[t]["total"] += 1
        if r.is_valid:
            type_stats[t]["valid"] += 1
        else:
            type_stats[t]["invalid"] += 1

    classifications = Counter(r.classification for r in valid_results)

    print("\n" + "=" * 80)
    print(f"{'IOC VALIDATION & STRUCTURAL AUDIT SUMMARY':^80}")
    print("=" * 80)
    print(f"Total Feeds Ingested:      {len(successful_feeds)} (Failed: {len(failed_feeds)})")
    print(f"Total Candidates Extracted: {len(validation_results)}")
    print(f"Valid Indicators:          {len(valid_results)} ({len(valid_results)/max(len(validation_results), 1)*100:.1f}%)")
    print(f"Invalid Indicators:        {len(invalid_results)} ({len(invalid_results)/max(len(validation_results), 1)*100:.1f}%)")
    print("-" * 80)
    print(f"{'IOC Type':<16} | {'Valid':>8} | {'Invalid':>8} | {'Total':>8} | {'Pass Rate':>10}")
    print("-" * 80)

    for ioc_type in SUPPORTED_IOC_TYPES:
        stats = type_stats.get(ioc_type, {"valid": 0, "invalid": 0, "total": 0})
        v = stats["valid"]
        inv = stats["invalid"]
        tot = stats["total"]
        rate = f"{(v / tot * 100):.0f}%" if tot > 0 else "N/A"
        print(f"{ioc_type:<16} | {v:>8} | {inv:>8} | {tot:>8} | {rate:>10}")

    print("-" * 80)

    print(f"\n{'BLUE TEAM CLASSIFICATION BREAKDOWN (VALID IOCs)':^80}")
    print("-" * 80)
    print(f"{'Classification':<20} | {'Count':>10} | {'Description'}")
    print("-" * 80)
    desc_map = {
        "normal": "Public/routable indicator or standard hash/URL/email",
        "documentation": "IETF Benchmark/doc test ranges (RFC 5737 / RFC 3849)",
        "private": "Internal/Private RFC 1918 / ULA network space",
        "loopback": "Localhost loopback address (127.0.0.0/8 or ::1)",
        "reserved": "IETF or special reserved address space",
        "special": "Multicast or link-local address space",
        "unknown": "Unclassified or custom category",
    }
    for c_name, count in sorted(classifications.items(), key=lambda x: x[1], reverse=True):
        print(f"{c_name:<20} | {count:>10} | {desc_map.get(c_name, '')}")

    print("-" * 80)

    print(f"\n{'FEED PROVENANCE BREAKDOWN':^80}")
    print("-" * 80)
    print(f"{'Feed Name':<34} | {'Valid IOCs':>12} | {'Invalid IOCs':>14} | {'Total':>10}")
    print("-" * 80)
    for feed in successful_feeds:
        f_valid = sum(1 for r in validation_results if r.source_name == feed.source_name and r.is_valid)
        f_invalid = sum(1 for r in validation_results if r.source_name == feed.source_name and not r.is_valid)
        fname = feed.source_name[:32] + ".." if len(feed.source_name) > 34 else feed.source_name
        print(f"{fname:<34} | {f_valid:>12} | {f_invalid:>14} | {(f_valid + f_invalid):>10}")

    if invalid_results:
        print("\n" + "!" * 80)
        print(f"{'SAMPLE INVALID CANDIDATES REJECTED':^80}")
        print("!" * 80)
        for inv in invalid_results[:5]:
            print(f"- [{inv.ioc_type}] '{inv.value}' -> {inv.reason}")

    print("=" * 80)
    print("[i] Notice: Validation establishes syntactic validity only. Maliciousness is not established.")
    print("=" * 80 + "\n")

    return 0 if len(valid_results) > 0 or len(failed_feeds) == 0 else 1


def handle_normalize(files: list[str], save_db: bool = False, db_path: Path = DEFAULT_DB_PATH) -> int:
    """Ingest, extract, validate, normalize, and deduplicate IOCs from feed files."""
    collector = FeedCollector()
    parser = IOCParser()
    validator = IOCValidator()
    normalizer = IOCNormalizer()

    print(f"[*] Ingesting, validating, and normalizing {len(files)} feed file(s)...")
    feed_results = collector.collect_many(files)

    successful_feeds = [f for f in feed_results if f.success]
    failed_feeds = [f for f in feed_results if not f.success]

    parsed_iocs = parser.parse_many(successful_feeds)
    validation_results = validator.validate_many(parsed_iocs)
    normalized_iocs = normalizer.normalize_many(validation_results)
    deduplicated = normalizer.deduplicate(normalized_iocs)

    valid_count = sum(1 for n in normalized_iocs if n.is_valid)
    invalid_count = len(normalized_iocs) - valid_count
    unique_count = len(deduplicated)
    collapsed_duplicates = valid_count - unique_count

    type_valid: Counter[str] = Counter(n.ioc_type for n in normalized_iocs if n.is_valid)
    type_unique: Counter[str] = Counter(d.ioc_type for d in deduplicated)

    print("\n" + "=" * 80)
    print(f"{'IOC NORMALIZATION & DEDUPLICATION SUMMARY':^80}")
    print("=" * 80)
    print(f"Total Feeds Ingested:        {len(successful_feeds)} (Failed: {len(failed_feeds)})")
    print(f"Total Candidates Extracted:  {len(normalized_iocs)}")
    print(f"Valid Candidates:            {valid_count}")
    print(f"Invalid Candidates (kept):   {invalid_count}")
    print(f"Unique Canonical IOCs:       {unique_count}")
    print(f"Duplicate Observations:      {collapsed_duplicates}")
    print("-" * 80)
    print(f"{'IOC Type':<16} | {'Valid Total':>12} | {'Unique Canonical':>18} | {'Duplicates Collapsed':>22}")
    print("-" * 80)

    for ioc_type in SUPPORTED_IOC_TYPES:
        v_tot = type_valid.get(ioc_type, 0)
        u_tot = type_unique.get(ioc_type, 0)
        dups = v_tot - u_tot
        print(f"{ioc_type:<16} | {v_tot:>12} | {u_tot:>18} | {dups:>22}")

    print("-" * 80)

    repeated = [d for d in deduplicated if d.total_occurrences > 1 or d.distinct_sources_count > 1]
    print(f"\n{'REPEATED / CROSS-FEED INDICATORS IDENTIFIED':^80}")
    print("-" * 80)
    if repeated:
        print(f"{'Indicator (Canonical)':<32} | {'Type':<8} | {'Distinct':>8} | {'Total':>6} | {'Sources'}")
        print("-" * 80)
        for rep in repeated:
            val_display = rep.normalized_value[:30] + ".." if len(rep.normalized_value) > 32 else rep.normalized_value
            srcs = ", ".join(rep.sources)
            print(f"{val_display:<32} | {rep.ioc_type:<8} | {rep.distinct_sources_count:>8} | {rep.total_occurrences:>6} | {srcs}")
    else:
        print("No repeated or multi-source indicators detected in the provided feeds.")

    print("-" * 80)

    if save_db:
        print(f"[*] Persisting {len(normalized_iocs)} records to SQLite database: {db_path}...")
        db = DatabaseManager(db_path=db_path)
        stats = db.save_normalized_iocs(normalized_iocs)
        for feed in feed_results:
            extracted = sum(1 for p in parsed_iocs if p.source_location == feed.source_location) if feed.success else 0
            db.record_feed_run(
                source_location=feed.source_location,
                source_name=feed.source_name,
                feed_format=getattr(feed, "format", ""),
                success=feed.success,
                indicators_extracted=extracted,
                error_message=getattr(feed, "error", "") if not feed.success else None,
                processed_at=feed.fetched_at,
            )
        print(f"[+] Persistence complete: {stats['new_indicators']} new canonical IOCs, {stats['observations']} observations saved.")
        db.close()

    print("=" * 80)
    print("[i] Notice: Normalization produces canonical forms; distinct source correlation is ready for Phase 6/7.")
    print("=" * 80 + "\n")

    return 0 if unique_count > 0 or len(failed_feeds) == 0 else 1


def handle_db(args: argparse.Namespace) -> int:
    """Handle all database-related subcommands (init, stats, list, show, ingest)."""
    db = DatabaseManager(db_path=args.db)

    if args.db_action == "init":
        print(f"[*] Initializing SQLite database schema at: {args.db}")
        db.initialize_database()
        print("[+] Database schema, constraints, and indexes initialized successfully.")
        db.close()
        return 0

    if args.db_action == "stats":
        stats = db.get_statistics()
        print("\n" + "=" * 60)
        print(f"{'THREAT INTELLIGENCE REPOSITORY STATISTICS':^60}")
        print("=" * 60)
        print(f"Database Path:       {args.db}")
        print(f"Total Unique IOCs:   {stats['total_indicators']}")
        print(f"Total Feed Sources:  {stats['total_sources']}")
        print(f"Total Observations:  {stats['total_observations']}")
        print("-" * 60)
        print(f"{'Severity Tier':<20} | {'Indicator Count':>15}")
        print("-" * 60)
        for sev in ("HIGH", "MEDIUM", "LOW"):
            print(f"{sev:<20} | {stats['by_severity'].get(sev, 0):>15}")
        print("-" * 60)
        print(f"{'IOC Type':<20} | {'Indicator Count':>15}")
        print("-" * 60)
        for t in SUPPORTED_IOC_TYPES:
            print(f"{t:<20} | {stats['by_type'].get(t, 0):>15}")
        print("=" * 60 + "\n")
        db.close()
        return 0

    if args.db_action == "list":
        if args.ioc_type:
            indicators = db.get_indicators_by_type(args.ioc_type.lower(), limit=args.limit)
        elif args.severity:
            indicators = db.get_indicators_by_severity(args.severity.upper(), limit=args.limit)
        else:
            indicators = db.get_all_indicators(limit=args.limit)

        print("\n" + "=" * 90)
        print(f"{'STORED THREAT INDICATORS':^90}")
        print("=" * 90)
        print(f"{'ID':<6} | {'Type':<8} | {'Normalized Indicator':<34} | {'Severity':<8} | {'Sources':>7} | {'Seen':>6}")
        print("-" * 90)

        for ind in indicators:
            val = ind["normalized_value"]
            val_display = val[:32] + ".." if len(val) > 34 else val
            print(
                f"{ind['id']:<6} | {ind['ioc_type']:<8} | {val_display:<34} | {ind['severity']:<8} | "
                f"{ind['distinct_sources_count']:>7} | {ind['total_occurrences']:>6}"
            )

        print("-" * 90)
        print(f"Showing {len(indicators)} indicator(s).")
        print("=" * 90 + "\n")
        db.close()
        return 0

    if args.db_action == "show":
        indicator = db.get_indicator_by_id(args.indicator_id)
        if not indicator:
            print(f"[!] Error: Indicator ID {args.indicator_id} not found in database.")
            db.close()
            return 1

        sources = db.get_indicator_sources(args.indicator_id)

        print("\n" + "=" * 80)
        print(f"{'INDICATOR PROVENANCE & AUDIT TRAIL':^80}")
        print("=" * 80)
        print(f"Indicator ID:            {indicator['id']}")
        print(f"IOC Type:                {indicator['ioc_type']}")
        print(f"Canonical Value:         {indicator['normalized_value']}")
        print(f"Calculated Severity:     {indicator['severity']}")
        print(f"Distinct Sources Count:  {indicator['distinct_sources_count']}")
        print(f"Total Observations:      {indicator['total_occurrences']}")
        print(f"First Seen:              {indicator['first_seen']}")
        print(f"Last Seen:               {indicator['last_seen']}")
        print("-" * 80)
        print(f"{'OBSERVING FEEDS & PROVENANCE (' + str(len(sources)) + ' Observation(s))':^80}")
        print("-" * 80)
        print(f"{'Source Name':<28} | {'Format':<6} | {'Original Value':<24} | {'Observed At'}")
        print("-" * 80)

        for s in sources:
            orig_val = s['original_value']
            orig_disp = orig_val[:22] + ".." if len(orig_val) > 24 else orig_val
            obs_at = s['observed_at'][:19] if len(s['observed_at']) >= 19 else s['observed_at']
            print(f"{s['source_name']:<28} | {s['feed_format']:<6} | {orig_disp:<24} | {obs_at}")

        print("=" * 80 + "\n")
        db.close()
        return 0

    if args.db_action == "ingest":
        db.close()
        return handle_normalize(files=args.files, save_db=True, db_path=args.db)

    print("[!] Error: No database action specified. Choose: init, stats, list, show, ingest.")
    print("    Run 'threat-intel-aggregator db --help' for options.")
    db.close()
    return 1


def handle_correlate(args: argparse.Namespace) -> int:
    """Analyze and display cross-feed correlations and deterministic severity scores."""
    db = DatabaseManager(db_path=args.db)
    engine = CorrelationEngine(db_manager=db)

    if args.indicator_id:
        result = engine.correlate_indicator(args.indicator_id)
        if not result:
            print(f"[!] Error: Indicator ID {args.indicator_id} not found.")
            db.close()
            return 1

        print("\n" + "=" * 80)
        print(f"{'INDICATOR CORRELATION PROFILE':^80}")
        print("=" * 80)
        print(f"Indicator ID:          {result.indicator_id}")
        print(f"IOC Type:              {result.ioc_type}")
        print(f"Canonical Value:       {result.normalized_value}")
        print(f"Severity Tier:         {result.severity}")
        print(f"Cross-Feed Correlated: {'YES (Multi-Source)' if result.is_cross_feed else 'NO (Isolated)'}")
        print(f"Distinct Sources:      {result.distinct_sources_count}")
        print(f"Total Sightings:       {result.total_occurrences}")
        print(f"First Seen:            {result.first_seen}")
        print(f"Last Seen:             {result.last_seen}")
        print(f"Reporting Feeds:       {', '.join(result.sources)}")
        print("=" * 80 + "\n")
        db.close()
        return 0

    stats = engine.get_correlation_statistics()
    correlations = engine.correlate_all(
        min_sources=args.min_sources,
        severity=args.severity,
        ioc_type=args.ioc_type,
    )

    print("\n" + "=" * 90)
    print(f"{'CROSS-FEED IOC CORRELATION & CONSENSUS AUDIT':^90}")
    print("=" * 90)
    print(f"Total Indicators in Database: {stats['total_indicators_analyzed']}")
    print(f"Cross-Feed Correlated (>=2):  {stats['cross_feed_indicators_count']} ({stats['cross_feed_percentage']:.1f}%)")
    print(f"Single-Source Indicators:     {stats['single_source_indicators_count']}")
    print("-" * 90)
    print("Severity Distribution: " + ", ".join(f"{k}: {v}" for k, v in stats["by_severity"].items()))
    print("-" * 90)

    if not correlations:
        print("[i] No indicators matched the specified correlation filters.")
        print("=" * 90 + "\n")
        db.close()
        return 0

    print(f"{'ID':<6} | {'Type':<8} | {'Canonical Indicator':<30} | {'Sev':<6} | {'Sources':>7} | {'Total':>5} | {'Reporting Feeds'}")
    print("-" * 90)

    for c in correlations:
        val = c.normalized_value[:28] + ".." if len(c.normalized_value) > 30 else c.normalized_value
        srcs = ", ".join(c.sources)
        srcs_disp = srcs[:24] + ".." if len(srcs) > 26 else srcs
        print(
            f"{c.indicator_id:<6} | {c.ioc_type:<8} | {val:<30} | {c.severity:<6} | "
            f"{c.distinct_sources_count:>7} | {c.total_occurrences:>5} | {srcs_disp}"
        )

    print("-" * 90)
    print(f"Showing {len(correlations)} correlated indicator(s).")
    print("[i] Notice: Severity is a deterministic heuristic based on multi-feed consensus, not absolute proof of maliciousness.")
    print("=" * 90 + "\n")

    db.close()
    return 0


def handle_blocklist(args: argparse.Namespace) -> int:
    """Handle blocklist generation and export with configured filters and formatting."""
    if not args.ioc_type and not args.all:
        print("[!] Error: Please specify an IOC category using --type / -t, or export all categories using --all / -a.")
        print(f"    Available categories: {', '.join(SUPPORTED_IOC_TYPES)}")
        return 1

    category = "all" if args.all else args.ioc_type.lower()
    if category != "all" and category not in SUPPORTED_IOC_TYPES:
        print(f"[!] Error: Unsupported IOC type '{category}'.")
        print(f"    Supported types: {', '.join(SUPPORTED_IOC_TYPES)}")
        return 1

    db = DatabaseManager(db_path=args.db)
    # Determine output directory
    output_dir = BLOCKLISTS_DIR
    output_custom = args.output
    if output_custom:
        if output_custom.is_dir() or output_custom.suffix == "" or str(output_custom).endswith(("/", "\\")):
            output_dir = output_custom
            output_dir.mkdir(parents=True, exist_ok=True)

    generator = BlocklistGenerator(db_manager=db, output_dir=output_dir)

    format_choice = args.format.lower()
    severity_choice = args.severity.upper() if args.severity else None

    print(f"[*] Generating blocklist(s) for target: '{category.upper()}' [Format: {format_choice.upper()}]...")
    if severity_choice:
        print(f"    Filter: Severity = {severity_choice}")
    if args.min_sources > 1:
        print(f"    Filter: Min Distinct Sources = {args.min_sources}")
    if args.exclude_low:
        print("    Filter: Excluding LOW severity")
    if args.cross_feed_only:
        print("    Filter: Cross-feed consensus only (sources >= 2)")

    try:
        results = generator.generate_blocklist(
            ioc_type=category,
            format_type=format_choice,
            severity=severity_choice,
            min_sources=args.min_sources,
            exclude_low=args.exclude_low,
            cross_feed_only=args.cross_feed_only,
            output_path=output_custom,
            combined=args.combined,
        )
    except Exception as e:
        print(f"[!] Error generating blocklists: {e}")
        db.close()
        return 1

    total_indicators = sum(r.indicator_count for r in results)

    print("\n" + "=" * 90)
    print(f"{'IOC BLOCKLIST EXPORT SUMMARY':^90}")
    print("=" * 90)
    print(f"{'Category':<10} | {'Format':<6} | {'Count':>6} | {'Output Filesystem Destination'}")
    print("-" * 90)

    for r in results:
        print(f"{r.category:<10} | {r.format.upper():<6} | {r.indicator_count:>6} | {r.file_path}")

    print("-" * 90)
    print(f"[+] Total Blocklist Files Generated: {len(results)}")
    print(f"[+] Total Indicators Exported:       {total_indicators}")
    print("=" * 90 + "\n")

    db.close()
    return 0


def handle_report(args: argparse.Namespace) -> int:
    """Generate and export comprehensive cybersecurity threat intelligence report."""
    db = DatabaseManager(db_path=args.db)

    output_dir = REPORTS_DIR
    output_custom = args.output
    if output_custom:
        if output_custom.is_dir() or output_custom.suffix == "" or str(output_custom).endswith(("/", "\\")):
            output_dir = output_custom
            output_dir.mkdir(parents=True, exist_ok=True)

    generator = ReportGenerator(db_manager=db, output_dir=output_dir)

    format_choice = args.format.lower()
    severity_choice = args.severity.upper() if args.severity else None
    type_choice = args.ioc_type.lower() if args.ioc_type else None

    print(f"[*] Generating Threat Intelligence Report [Format: {format_choice.upper()}]...")
    if severity_choice:
        print(f"    Filter: Severity = {severity_choice}")
    if type_choice:
        print(f"    Filter: IOC Type = {type_choice}")
    if args.cross_feed_only:
        print("    Filter: Cross-feed consensus only (sources >= 2)")
    if args.top != 10:
        print(f"    Top Repeated Limit: {args.top}")

    try:
        result = generator.generate_report(
            format_type=format_choice,
            severity=severity_choice,
            ioc_type=type_choice,
            cross_feed_only=args.cross_feed_only,
            top=args.top,
            output_path=output_custom,
            overwrite=args.overwrite if hasattr(args, "overwrite") else False,
        )
    except Exception as e:
        print(f"[!] Error generating report: {e}")
        db.close()
        return 1

    stats = db.get_statistics()
    corr_stats = generator.correlation_engine.get_correlation_statistics()

    print("\n" + "=" * 90)
    print(f"{'THREAT INTELLIGENCE ANALYSIS REPORT':^90}")
    print("=" * 90)
    print(f"Destination:          {result.file_path}")
    print(f"Export Format:        {result.format.upper()}")
    print(f"Generated (UTC):      {result.generated_at[:19]}Z")
    print(f"Total Indicators:     {stats['total_indicators']}")
    print(f"Total Sources:        {stats['total_sources']}")
    print(f"Total Observations:   {stats['total_observations']}")
    print(f"Cross-Feed Consensus: {corr_stats['cross_feed_indicators_count']} ({corr_stats['cross_feed_percentage']:.1f}%)")
    print("-" * 90)
    print("Severity Breakdown:   " + ", ".join(f"{k}: {v}" for k, v in stats['by_severity'].items()))
    print("=" * 90)
    print(f"[+] Report generated successfully: {result.file_path}\n")

    db.close()
    return 0


def handle_pipeline(args: argparse.Namespace) -> int:
    """Execute complete end-to-end threat intelligence ingestion and correlation pipeline."""
    files = flatten_sources(args.files)
    urls = flatten_sources(args.urls)

    if not files and not urls:
        print("[!] Error: No feeds specified. Provide at least one --file or --url.")
        print("    Example: python main.py pipeline --file feeds/samples/sample_feed.csv --file feeds/samples/sample_feed.txt")
        return 1

    db_target = args.db
    print("=" * 90)
    print(f"{'THREAT INTELLIGENCE END-TO-END PIPELINE':^90}")
    print("=" * 90)
    print(f"Target Database: {db_target}")
    print(f"Sources Queued:  {len(files)} file(s), {len(urls)} remote URL(s)")
    print("-" * 90)

    pipeline = ThreatIntelligencePipeline(db_path=db_target)

    print("[*] Stage 1/8: Ingesting feeds from configured sources...")
    print("[*] Stage 2/8: Parsing content and extracting candidate indicators...")
    print("[*] Stage 3/8: Validating syntax against RFC and cryptographic specifications...")
    print("[*] Stage 4/8: Normalizing indicators to canonical representations...")
    print("[*] Stage 5/8: Deduplicating within batch and binding provenance...")
    print("[*] Stage 6/8: Persisting canonical records to SQLite database...")
    print("[*] Stage 7/8: Synchronizing cross-feed correlations and severity metrics...")
    if getattr(args, "generate_blocklists", False):
        print("[*] Stage 8a: Generating standard categorized blocklists...")
    if getattr(args, "generate_report", False):
        print("[*] Stage 8b: Generating comprehensive analytical Markdown report...")

    try:
        result = pipeline.run(
            files=files,
            urls=urls,
            generate_report=getattr(args, "generate_report", False),
            generate_blocklists=getattr(args, "generate_blocklists", False),
        )
    except Exception as e:
        print(f"[!] Critical Pipeline Error: {e}")
        return 1

    print("\n" + "=" * 90)
    print(f"{'PIPELINE EXECUTION SUMMARY':^90}")
    print("=" * 90)
    print(f"Database Location:          {result.database_location}")
    print(f"Execution Timestamps (UTC): {result.started_at[:19]}Z -> {result.completed_at[:19]}Z")
    print("-" * 90)
    print(f"FEED COLLECTION AUDIT:")
    print(f"  Feeds Supplied:           {result.feeds_supplied}")
    print(f"  Successful Feeds:         {result.successful_feeds}")
    print(f"  Failed Feeds:             {result.failed_feeds}")
    print("-" * 90)
    print(f"INDICATOR PROCESSING:")
    print(f"  Total Candidates Parsed:  {result.total_candidates}")
    val_rate = (result.valid_indicators / max(result.total_candidates, 1) * 100) if result.total_candidates > 0 else 0.0
    inv_rate = (result.invalid_indicators / max(result.total_candidates, 1) * 100) if result.total_candidates > 0 else 0.0
    print(f"  Syntactically Valid:      {result.valid_indicators} ({val_rate:.1f}%)")
    print(f"  Syntactically Invalid:    {result.invalid_indicators} ({inv_rate:.1f}%)")
    print(f"  Unique Canonical IOCs:    {result.unique_normalized}")
    print(f"  Batch Duplicate Sighting: {result.duplicate_observations}")
    print("-" * 90)
    print(f"DATABASE PERSISTENCE:")
    print(f"  New Indicators Added:     {result.new_database_records}")
    print(f"  Existing / Re-observed:   {result.existing_records_reobserved} observation(s)")
    print("-" * 90)
    print(f"CROSS-FEED CONSENSUS & RISK HEURISTICS:")
    print(f"  Cross-Feed Corroborated:  {result.cross_feed_indicators} (>= 2 independent feeds)")
    print("  Severity Breakdown:       " + ", ".join(f"{k}: {v}" for k, v in result.severity_distribution.items()))
    print("=" * 90)

    if result.failed_feed_details:
        print("\n" + "!" * 90)
        print(f"{'FEED COLLECTION WARNINGS / FAILURES':^90}")
        print("!" * 90)
        for fail in result.failed_feed_details:
            print(f"- Source: {fail['source_location']} ({fail['source_name']})")
            print(f"  Error:  {fail['error']}")
        print("!" * 90)

    if result.invalid_candidate_samples:
        print("\n" + "!" * 90)
        print(f"{'SAMPLE INVALID CANDIDATES REJECTED':^90}")
        print("!" * 90)
        for inv in result.invalid_candidate_samples[:5]:
            print(f"- [{inv['ioc_type']}] '{inv['value']}' -> {inv['reason']} (Source: {inv['source']})")
        print("!" * 90)

    if result.success:
        print("\n[+] Pipeline completed successfully.\n")
        return 0
    else:
        print("\n[!] Pipeline completed with errors: all supplied feeds failed.\n")
        return 1


def main() -> int:
    """CLI execution entrypoint."""
    ensure_runtime_directories()
    parser = create_parser()
    args = parser.parse_args()

    setup_logging(verbose=args.verbose, log_file=args.log_file)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "status":
        print("=== Threat Intelligence Aggregator (Non-AI) ===")
        print(f"Project Root: {PROJECT_ROOT}")
        print(f"Database Target: {args.db}")
        print(f"Supported Feed Formats: {', '.join(SUPPORTED_FEED_FORMATS)}")
        print(f"Supported IOC Types ({len(SUPPORTED_IOC_TYPES)}): {', '.join(SUPPORTED_IOC_TYPES)}")
        print("Status: Phase 10 End-to-End CLI Integration Operational.")
        return 0

    if args.command == "collect":
        return handle_collect(files=args.files, urls=args.urls)

    if args.command == "parse":
        return handle_parse(files=args.files)

    if args.command == "validate":
        return handle_validate(files=args.files)

    if args.command == "normalize":
        return handle_normalize(files=args.files, save_db=args.save, db_path=args.db)

    if args.command == "db":
        return handle_db(args)

    if args.command == "correlate":
        return handle_correlate(args)

    if args.command == "blocklist":
        return handle_blocklist(args)

    if args.command == "report":
        return handle_report(args)

    if args.command == "pipeline":
        return handle_pipeline(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
