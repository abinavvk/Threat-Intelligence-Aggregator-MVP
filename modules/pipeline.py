"""Unified Threat Intelligence Processing Pipeline.

Orchestrates the complete end-to-end Blue Team intelligence lifecycle:
Feed Collection -> Parsing -> Syntax Validation -> Normalization ->
Deduplication -> Relational Persistence -> Multi-Feed Correlation -> Audit Reporting.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from config.settings import DEFAULT_DB_PATH
from modules.blocklist_generator import BlocklistGenerator
from modules.correlation import CorrelationEngine
from modules.database_manager import DatabaseManager
from modules.feed_collector import FeedCollector, FeedResult
from modules.ioc_parser import IOCParser, ParsedIOC
from modules.normalizer import DeduplicatedIOC, IOCNormalizer, NormalizedIOC
from modules.report_generator import ReportGenerator
from modules.validator import IOCValidator, ValidationResult

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    """Standardized summary result of a completed end-to-end intelligence pipeline run.

    Attributes:
        feeds_supplied: Total count of feed files and URLs queued for ingestion.
        successful_feeds: Count of feeds successfully retrieved and read.
        failed_feeds: Count of feeds that failed during collection/network retrieval.
        total_candidates: Total candidate IOC tokens extracted by regex and parsers.
        valid_indicators: Count of extracted tokens that passed RFC syntax validation.
        invalid_indicators: Count of extracted tokens rejected by validation checks.
        unique_normalized: Count of distinct canonical IOCs after batch deduplication.
        duplicate_observations: Number of sightings collapsed as duplicate observations.
        new_database_records: Count of newly inserted canonical indicators in SQLite.
        existing_records_reobserved: Count of observations linked to pre-existing indicators.
        cross_feed_indicators: Count of indicators corroborated by >= 2 independent feeds.
        severity_distribution: Current repository severity tier counts (HIGH, MEDIUM, LOW).
        database_location: Filesystem path to the SQLite repository.
        failed_feed_details: List of failure details for feeds that could not be ingested.
        invalid_candidate_samples: Sample list of invalid IOC candidates and rejection reasons.
        success: True if at least one feed was successfully ingested and processed.
        started_at: UTC ISO 8601 timestamp when pipeline started.
        completed_at: UTC ISO 8601 timestamp when pipeline finished.
    """

    feeds_supplied: int
    successful_feeds: int
    failed_feeds: int
    total_candidates: int
    valid_indicators: int
    invalid_indicators: int
    unique_normalized: int
    duplicate_observations: int
    new_database_records: int
    existing_records_reobserved: int
    cross_feed_indicators: int
    severity_distribution: Dict[str, int]
    database_location: Path
    failed_feed_details: List[Dict[str, str]]
    invalid_candidate_samples: List[Dict[str, str]]
    success: bool
    started_at: str
    completed_at: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert pipeline result into dictionary representation."""
        return {
            "feeds_supplied": self.feeds_supplied,
            "successful_feeds": self.successful_feeds,
            "failed_feeds": self.failed_feeds,
            "total_candidates": self.total_candidates,
            "valid_indicators": self.valid_indicators,
            "invalid_indicators": self.invalid_indicators,
            "unique_normalized": self.unique_normalized,
            "duplicate_observations": self.duplicate_observations,
            "new_database_records": self.new_database_records,
            "existing_records_reobserved": self.existing_records_reobserved,
            "cross_feed_indicators": self.cross_feed_indicators,
            "severity_distribution": self.severity_distribution,
            "database_location": str(self.database_location),
            "failed_feed_details": self.failed_feed_details,
            "invalid_candidate_samples": self.invalid_candidate_samples,
            "success": self.success,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


class ThreatIntelligencePipeline:
    """Orchestrates the complete deterministic threat intelligence ingestion and analysis lifecycle."""

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        db_path: Union[str, Path] = DEFAULT_DB_PATH,
    ) -> None:
        """Initialize pipeline with shared database manager and operational modules.

        Args:
            db_manager: Existing DatabaseManager or None.
            db_path: Database path if initializing a new DatabaseManager.
        """
        self.db_manager = db_manager or DatabaseManager(db_path=db_path)
        self.collector = FeedCollector()
        self.parser = IOCParser()
        self.validator = IOCValidator()
        self.normalizer = IOCNormalizer()
        self.correlation_engine = CorrelationEngine(db_manager=self.db_manager)

    @staticmethod
    def _get_utc_timestamp() -> str:
        """Return current ISO 8601 UTC timestamp."""
        return datetime.now(timezone.utc).isoformat()

    def run(
        self,
        files: Optional[Sequence[Union[str, Path]]] = None,
        urls: Optional[Sequence[str]] = None,
        generate_report: bool = False,
        generate_blocklists: bool = False,
    ) -> PipelineResult:
        """Execute the end-to-end ingestion, validation, normalization, and correlation workflow.

        Execution stages:
            1. Collect feed content from local files and remote HTTP/HTTPS URLs.
            2. Parse supported CSV, TXT, and JSON formats.
            3. Extract candidate IOC tokens for all 8 supported indicator types.
            4. Validate syntax against RFC and cryptographic specifications.
            5. Normalize valid indicators to canonical representations.
            6. Deduplicate indicators while binding source provenance.
            7. Save normalized indicators and observations into SQLite storage.
            8. Synchronize multi-feed correlation and deterministic severity scores.
            9. Optionally generate reports or blocklists if requested.

        Args:
            files: List of local feed file paths.
            urls: List of remote HTTP/HTTPS feed URLs.
            generate_report: If True, generate analytical Markdown report after ingestion.
            generate_blocklists: If True, export categorized blocklists after ingestion.

        Returns:
            PipelineResult containing complete execution metrics.

        Raises:
            ValueError: If neither files nor urls are supplied.
        """
        started_at = self._get_utc_timestamp()
        sources: List[str] = []
        if files:
            sources.extend(str(f) for f in files)
        if urls:
            sources.extend(str(u) for u in urls)

        if not sources:
            raise ValueError("No feed sources supplied to pipeline. Provide at least one file or URL.")

        logger.info("Pipeline started with %d feed source(s) queued", len(sources))

        # -------------------------------------------------------------
        # Stage 1: Feed Collection
        # -------------------------------------------------------------
        feed_results: List[FeedResult] = self.collector.collect_many(sources)
        successful_feeds = [f for f in feed_results if f.success]
        failed_feeds = [f for f in feed_results if not f.success]

        failed_details: List[Dict[str, str]] = [
            {
                "source_location": f.source_location,
                "source_name": f.source_name,
                "error": getattr(f, "error", "") or "Unknown collection error",
            }
            for f in failed_feeds
        ]

        # Record failed feeds in the database audit log
        self.db_manager.initialize_database()
        for f in failed_feeds:
            self.db_manager.record_feed_run(
                source_location=f.source_location,
                source_name=f.source_name,
                feed_format=getattr(f, "format", ""),
                success=False,
                indicators_extracted=0,
                error_message=getattr(f, "error", ""),
                processed_at=f.fetched_at,
            )

        if not successful_feeds:
            logger.error("Pipeline terminated: all %d supplied feed source(s) failed collection", len(sources))
            stats = self.correlation_engine.get_correlation_statistics()
            return PipelineResult(
                feeds_supplied=len(sources),
                successful_feeds=0,
                failed_feeds=len(failed_feeds),
                total_candidates=0,
                valid_indicators=0,
                invalid_indicators=0,
                unique_normalized=0,
                duplicate_observations=0,
                new_database_records=0,
                existing_records_reobserved=0,
                cross_feed_indicators=stats["cross_feed_indicators_count"],
                severity_distribution=stats["by_severity"],
                database_location=self.db_manager.db_path,
                failed_feed_details=failed_details,
                invalid_candidate_samples=[],
                success=False,
                started_at=started_at,
                completed_at=self._get_utc_timestamp(),
            )

        # -------------------------------------------------------------
        # Stage 2: Parsing & Candidate Extraction
        # -------------------------------------------------------------
        parsed_iocs: List[ParsedIOC] = self.parser.parse_many(successful_feeds)
        total_candidates = len(parsed_iocs)
        logger.info("Extracted %d IOC candidate(s) from %d successful feed(s)", total_candidates, len(successful_feeds))

        # -------------------------------------------------------------
        # Stage 3: Syntax & Network Scope Validation
        # -------------------------------------------------------------
        validation_results: List[ValidationResult] = self.validator.validate_many(parsed_iocs)
        valid_results = [v for v in validation_results if v.is_valid]
        invalid_results = [v for v in validation_results if not v.is_valid]

        invalid_samples = [
            {
                "ioc_type": inv.ioc_type,
                "value": inv.value,
                "reason": inv.reason,
                "source": inv.source_name,
            }
            for inv in invalid_results[:10]
        ]

        logger.info(
            "Validation completed: %d valid, %d invalid (rejection rate: %.1f%%)",
            len(valid_results),
            len(invalid_results),
            (len(invalid_results) / max(total_candidates, 1) * 100),
        )

        # -------------------------------------------------------------
        # Stage 4: Normalization & Deduplication
        # -------------------------------------------------------------
        normalized_iocs: List[NormalizedIOC] = self.normalizer.normalize_many(validation_results)
        deduplicated: List[DeduplicatedIOC] = self.normalizer.deduplicate(normalized_iocs)
        unique_normalized_count = len(deduplicated)
        duplicate_obs_count = len(valid_results) - unique_normalized_count

        logger.info(
            "Normalization completed: %d unique canonical IOCs, %d duplicate observation(s) collapsed",
            unique_normalized_count,
            duplicate_obs_count,
        )

        # -------------------------------------------------------------
        # Stage 5: Database Persistence & Audit Run Logging
        # -------------------------------------------------------------
        db_save_stats = self.db_manager.save_normalized_iocs(normalized_iocs)
        new_records = db_save_stats["new_indicators"]
        existing_reobserved = db_save_stats["observations"] - new_records

        # Record successful feed runs in audit table
        for f in successful_feeds:
            extracted_count = sum(
                1 for p in parsed_iocs if p.source_location == f.source_location
            )
            self.db_manager.record_feed_run(
                source_location=f.source_location,
                source_name=f.source_name,
                feed_format=getattr(f, "format", ""),
                success=True,
                indicators_extracted=extracted_count,
                error_message=None,
                processed_at=f.fetched_at,
            )

        # -------------------------------------------------------------
        # Stage 6: Cross-Feed Correlation & Scoring Synchronization
        # -------------------------------------------------------------
        self.correlation_engine.refresh_correlations()
        corr_stats = self.correlation_engine.get_correlation_statistics()

        # -------------------------------------------------------------
        # Stage 7: Optional Downstream Artifact Generation
        # -------------------------------------------------------------
        if generate_blocklists:
            logger.info("Generating standard blocklists following pipeline execution...")
            blocklist_gen = BlocklistGenerator(db_manager=self.db_manager)
            blocklist_gen.generate_all_categories()

        if generate_report:
            logger.info("Generating comprehensive report following pipeline execution...")
            report_gen = ReportGenerator(db_manager=self.db_manager)
            report_gen.generate_report(format_type="md")

        completed_at = self._get_utc_timestamp()
        logger.info("Pipeline execution successfully completed in UTC: %s", completed_at)

        return PipelineResult(
            feeds_supplied=len(sources),
            successful_feeds=len(successful_feeds),
            failed_feeds=len(failed_feeds),
            total_candidates=total_candidates,
            valid_indicators=len(valid_results),
            invalid_indicators=len(invalid_results),
            unique_normalized=unique_normalized_count,
            duplicate_observations=duplicate_obs_count,
            new_database_records=new_records,
            existing_records_reobserved=existing_reobserved,
            cross_feed_indicators=corr_stats["cross_feed_indicators_count"],
            severity_distribution=corr_stats["by_severity"],
            database_location=self.db_manager.db_path,
            failed_feed_details=failed_details,
            invalid_candidate_samples=invalid_samples,
            success=True,
            started_at=started_at,
            completed_at=completed_at,
        )

