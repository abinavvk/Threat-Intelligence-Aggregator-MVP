"""IOC Correlation Engine for Threat Intelligence Aggregator.

Performs deterministic cross-feed correlation and heuristic risk assessment.
Identifies indicators corroborated across multiple distinct intelligence feeds,
counts unique provenance sources without inflating repeated observations,
and computes deterministic severity ratings according to Blue Team heuristics.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from config.settings import DEFAULT_DB_PATH, SUPPORTED_IOC_TYPES, calculate_severity
from modules.database_manager import DatabaseManager

logger = logging.getLogger(__name__)


@dataclass
class CorrelationResult:
    """Standardized result of cross-feed correlation analysis for a single indicator.

    Attributes:
        indicator_id: Integer primary key in indicators table.
        ioc_type: One of the 8 supported IOC types.
        normalized_value: Canonical indicator string.
        distinct_sources_count: Count of unique threat feeds reporting this IOC.
        total_occurrences: Total observations across all feeds (including repeat sightings).
        sources: List of unique source feed names reporting this indicator.
        severity: Deterministic severity classification ('HIGH', 'MEDIUM', 'LOW').
        first_seen: Earliest recorded observation timestamp (UTC ISO 8601).
        last_seen: Most recent recorded observation timestamp (UTC ISO 8601).
        is_cross_feed: True if observed by at least two distinct sources (sources >= 2).
    """

    indicator_id: int
    ioc_type: str
    normalized_value: str
    distinct_sources_count: int
    total_occurrences: int
    sources: List[str]
    severity: str
    first_seen: str
    last_seen: str
    is_cross_feed: bool = False

    def __post_init__(self) -> None:
        """Derive cross-feed status dynamically based on distinct sources count."""
        self.is_cross_feed = self.distinct_sources_count >= 2

    def to_dict(self) -> Dict[str, Any]:
        """Convert CorrelationResult to standard dictionary."""
        return {
            "indicator_id": self.indicator_id,
            "ioc_type": self.ioc_type,
            "normalized_value": self.normalized_value,
            "distinct_sources_count": self.distinct_sources_count,
            "total_occurrences": self.total_occurrences,
            "sources": self.sources,
            "severity": self.severity,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "is_cross_feed": self.is_cross_feed,
        }


class CorrelationEngine:
    """Correlation engine for analyzing threat indicators across multiple feeds."""

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        db_path: Union[str, Path] = DEFAULT_DB_PATH,
    ) -> None:
        """Initialize the correlation engine with a DatabaseManager instance.

        Args:
            db_manager: Existing DatabaseManager or None to create one.
            db_path: Path to database if creating a new DatabaseManager.
        """
        self.db_manager = db_manager or DatabaseManager(db_path=db_path)

    def correlate_indicator(self, indicator_id: int) -> Optional[CorrelationResult]:
        """Perform deep correlation analysis for a single indicator ID.

        Args:
            indicator_id: Primary key of the indicator.

        Returns:
            CorrelationResult populated with cross-feed metrics or None if not found.
        """
        indicator = self.db_manager.get_indicator_by_id(indicator_id)
        if not indicator:
            return None

        # Fetch all distinct sources observing this indicator
        sources_records = self.db_manager.get_indicator_sources(indicator_id)
        unique_sources = sorted(list({s["source_name"] for s in sources_records}))

        distinct_count = len(unique_sources)
        total_obs = len(sources_records) if sources_records else indicator["total_occurrences"]
        computed_severity = calculate_severity(distinct_count)

        # Timestamps
        obs_times = [s["observed_at"] for s in sources_records if s.get("observed_at")]
        first_seen = min(obs_times) if obs_times else indicator["first_seen"]
        last_seen = max(obs_times) if obs_times else indicator["last_seen"]

        return CorrelationResult(
            indicator_id=indicator["id"],
            ioc_type=indicator["ioc_type"],
            normalized_value=indicator["normalized_value"],
            distinct_sources_count=distinct_count,
            total_occurrences=total_obs,
            sources=unique_sources,
            severity=computed_severity,
            first_seen=first_seen,
            last_seen=last_seen,
        )

    def correlate_all(
        self,
        min_sources: int = 1,
        severity: Optional[str] = None,
        ioc_type: Optional[str] = None,
    ) -> List[CorrelationResult]:
        """Correlate all indicators in the database with optional criteria filters.

        Args:
            min_sources: Minimum number of distinct observing sources (default: 1).
            severity: Filter by severity ('HIGH', 'MEDIUM', 'LOW').
            ioc_type: Filter by IOC type category.

        Returns:
            List of CorrelationResult objects ordered by distinct_sources_count descending.
        """
        conn = self.db_manager.get_connection()
        self.db_manager.initialize_database()

        # Query all indicators with their distinct sources concatenated
        query = """
            SELECT
                i.id AS indicator_id,
                i.ioc_type,
                i.normalized_value,
                i.first_seen,
                i.last_seen,
                COUNT(DISTINCT o.source_id) AS computed_distinct_sources,
                COUNT(o.id) AS computed_total_obs,
                GROUP_CONCAT(DISTINCT s.source_name) AS source_names_concat
            FROM indicators i
            LEFT JOIN indicator_observations o ON i.id = o.indicator_id
            LEFT JOIN sources s ON o.source_id = s.id
            GROUP BY i.id
            ORDER BY computed_distinct_sources DESC, computed_total_obs DESC, i.id ASC
        """

        cursor = conn.execute(query)
        rows = cursor.fetchall()
        results: List[CorrelationResult] = []

        for row in rows:
            distinct_count = row["computed_distinct_sources"] or 0
            if distinct_count < min_sources:
                continue

            calculated_sev = calculate_severity(distinct_count)
            if severity and calculated_sev.upper() != severity.upper():
                continue

            current_type = row["ioc_type"].lower()
            if ioc_type and current_type != ioc_type.lower():
                continue

            source_names_raw = row["source_names_concat"] or ""
            sources = sorted(source_names_raw.split(",")) if source_names_raw else []

            results.append(
                CorrelationResult(
                    indicator_id=int(row["indicator_id"]),
                    ioc_type=current_type,
                    normalized_value=row["normalized_value"],
                    distinct_sources_count=distinct_count,
                    total_occurrences=int(row["computed_total_obs"] or 0),
                    sources=sources,
                    severity=calculated_sev,
                    first_seen=row["first_seen"],
                    last_seen=row["last_seen"],
                )
            )

        return results

    def get_cross_feed_indicators(self, min_sources: int = 2) -> List[CorrelationResult]:
        """Retrieve all indicators observed across at least two distinct intelligence feeds.

        Args:
            min_sources: Minimum distinct sources threshold (default: 2).

        Returns:
            List of correlated cross-feed indicators.
        """
        return self.correlate_all(min_sources=min_sources)

    def get_high_confidence_correlations(self) -> List[CorrelationResult]:
        """Retrieve indicators meeting the HIGH severity threshold (sources >= 5)."""
        return self.correlate_all(severity="HIGH")

    def get_correlation_statistics(self) -> Dict[str, Any]:
        """Compile comprehensive metrics on correlation depth, multi-feed consensus, and severity.

        Returns:
            Dictionary containing analytics summary.
        """
        all_correlated = self.correlate_all(min_sources=1)
        total_indicators = len(all_correlated)

        cross_feed_count = sum(1 for c in all_correlated if c.is_cross_feed)
        single_source_count = total_indicators - cross_feed_count

        by_severity: Dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        by_type: Dict[str, int] = {t: 0 for t in SUPPORTED_IOC_TYPES}
        sources_distribution: Dict[int, int] = {}

        for c in all_correlated:
            # Severity counts
            sev = c.severity if c.severity in by_severity else "UNKNOWN"
            by_severity[sev] += 1

            # Type counts
            if c.ioc_type in by_type:
                by_type[c.ioc_type] += 1
            else:
                by_type[c.ioc_type] = 1

            # Source count distribution
            s_count = c.distinct_sources_count
            sources_distribution[s_count] = sources_distribution.get(s_count, 0) + 1

        return {
            "total_indicators_analyzed": total_indicators,
            "cross_feed_indicators_count": cross_feed_count,
            "single_source_indicators_count": single_source_count,
            "cross_feed_percentage": (cross_feed_count / total_indicators * 100) if total_indicators > 0 else 0.0,
            "by_severity": by_severity,
            "by_type": by_type,
            "sources_distribution": dict(sorted(sources_distribution.items())),
        }

    def refresh_correlations(self) -> Dict[str, int]:
        """Synchronize stored indicator records with computed observation statistics.

        Ensures indicators.distinct_sources_count and indicators.severity match
        the live observation records in SQLite.

        Returns:
            Dictionary with counts of updated and total indicators.
        """
        conn = self.db_manager.get_connection()
        self.db_manager.initialize_database()

        query = """
            SELECT
                i.id AS indicator_id,
                COUNT(DISTINCT o.source_id) AS distinct_count,
                COUNT(o.id) AS total_obs,
                MIN(o.observed_at) AS min_obs,
                MAX(o.observed_at) AS max_obs
            FROM indicators i
            LEFT JOIN indicator_observations o ON i.id = o.indicator_id
            GROUP BY i.id
        """
        cursor = conn.execute(query)
        rows = cursor.fetchall()

        updated_count = 0
        with conn:
            for r in rows:
                ind_id = r["indicator_id"]
                distinct_count = r["distinct_count"] or 0
                total_obs = r["total_obs"] or 0
                severity = calculate_severity(distinct_count)

                conn.execute(
                    """
                    UPDATE indicators
                    SET distinct_sources_count = ?, total_occurrences = ?, severity = ?
                    WHERE id = ?
                    """,
                    (distinct_count, total_obs, severity, ind_id),
                )
                updated_count += 1

        logger.info("Refreshed correlation state across %d indicators", updated_count)
        return {"total": len(rows), "updated": updated_count}

