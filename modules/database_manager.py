"""SQLite Database Manager for Threat Intelligence Aggregator.

Provides relational persistence for threat indicators, intelligence sources, and
individual feed observations with parameterized queries, foreign key enforcement,
ACID transactions, distinct source correlation, and deterministic severity metrics.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from config.settings import DEFAULT_DB_PATH, calculate_severity
from modules.normalizer import DeduplicatedIOC, NormalizedIOC

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages SQLite storage, ACID transactions, and retrieval of threat intelligence."""

    def __init__(self, db_path: Union[str, Path] = DEFAULT_DB_PATH) -> None:
        """Initialize DatabaseManager with filesystem database path.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection: Optional[sqlite3.Connection] = None

    def get_connection(self) -> sqlite3.Connection:
        """Obtain an active SQLite connection with row factory and foreign keys enabled."""
        if self._connection is None:
            self._connection = sqlite3.connect(
                str(self.db_path),
                detect_types=sqlite3.PARSE_DECLTYPES,
                timeout=20.0,
            )
            self._connection.row_factory = sqlite3.Row
            # Enforce foreign key constraints
            self._connection.execute("PRAGMA foreign_keys = ON;")
            self._connection.execute("PRAGMA journal_mode = WAL;")
        return self._connection

    def close(self) -> None:
        """Commit outstanding changes and close database connection."""
        if self._connection is not None:
            try:
                self._connection.commit()
                self._connection.close()
            except Exception as e:
                logger.warning("Error closing database connection: %s", e)
            finally:
                self._connection = None

    def __enter__(self) -> "DatabaseManager":
        """Context manager entry."""
        self.get_connection()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit with rollback on exception."""
        if exc_type is not None:
            if self._connection:
                self._connection.rollback()
        self.close()

    @staticmethod
    def _get_utc_timestamp() -> str:
        """Return current ISO 8601 UTC timestamp."""
        return datetime.now(timezone.utc).isoformat()

    def initialize_database(self) -> None:
        """Create tables, constraints, and indexes if they do not exist."""
        conn = self.get_connection()
        with conn:
            # 1. Sources table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_name TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    source_location TEXT NOT NULL,
                    feed_format TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    UNIQUE(source_name, source_location)
                );
                """
            )

            # 2. Indicators table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_type TEXT NOT NULL,
                    normalized_value TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    distinct_sources_count INTEGER DEFAULT 1,
                    total_occurrences INTEGER DEFAULT 1,
                    severity TEXT NOT NULL,
                    is_valid INTEGER DEFAULT 1,
                    UNIQUE(ioc_type, normalized_value)
                );
                """
            )

            # 3. Indicator Observations table (provenance tracking)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS indicator_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator_id INTEGER NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
                    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
                    original_value TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    metadata TEXT,
                    UNIQUE(indicator_id, source_id, original_value, observed_at)
                );
                """
            )

            # 4. Feed Ingestion Runs table (audit trail for feed collection & ingestion)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS feed_ingestion_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_location TEXT NOT NULL,
                    source_name TEXT NOT NULL,
                    feed_format TEXT,
                    success INTEGER NOT NULL,
                    indicators_extracted INTEGER DEFAULT 0,
                    error_message TEXT,
                    processed_at TEXT NOT NULL
                );
                """
            )

            # Indexes for optimized query execution
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_indicators_type_val ON indicators(ioc_type, normalized_value);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_indicators_severity ON indicators(severity);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_observations_indicator ON indicator_observations(indicator_id);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_observations_source ON indicator_observations(source_id);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_feed_runs_processed_at ON feed_ingestion_runs(processed_at);"
            )

            # Compatibility view for feed_runs
            conn.execute(
                "CREATE VIEW IF NOT EXISTS feed_runs AS SELECT * FROM feed_ingestion_runs;"
            )

        logger.info("Database initialized successfully at: %s", self.db_path)

    def insert_source(
        self,
        source_name: str,
        source_type: str,
        source_location: str,
        feed_format: str,
        first_seen: Optional[str] = None,
    ) -> int:
        """Insert or retrieve a feed source record.

        Args:
            source_name: Identifier name of feed.
            source_type: 'file' or 'url'.
            source_location: File path or URL string.
            feed_format: 'csv', 'txt', or 'json'.
            first_seen: Optional ISO 8601 timestamp.

        Returns:
            The primary key integer ID of the source.
        """
        conn = self.get_connection()
        timestamp = first_seen or self._get_utc_timestamp()

        # Check existing source
        cursor = conn.execute(
            "SELECT id FROM sources WHERE source_name = ? AND source_location = ?",
            (source_name, source_location),
        )
        row = cursor.fetchone()
        if row:
            return int(row["id"])

        # Insert new source
        cursor = conn.execute(
            """
            INSERT INTO sources (source_name, source_type, source_location, feed_format, first_seen)
            VALUES (?, ?, ?, ?, ?)
            """,
            (source_name, source_type, source_location, feed_format, timestamp),
        )
        return int(cursor.lastrowid)

    def insert_indicator(
        self,
        ioc_type: str,
        normalized_value: str,
        observed_at: Optional[str] = None,
        is_valid: bool = True,
        severity: Optional[str] = None,
    ) -> Tuple[int, bool]:
        """Insert a new indicator or update an existing indicator.

        Args:
            ioc_type: Supported IOC type string.
            normalized_value: Canonical indicator string.
            observed_at: Observation timestamp.
            is_valid: Validity boolean.
            severity: Optional explicit severity, otherwise calculated.

        Returns:
            Tuple of (indicator_id, is_newly_inserted_boolean)
        """
        conn = self.get_connection()
        timestamp = observed_at or self._get_utc_timestamp()
        sev = severity or calculate_severity(1)

        cursor = conn.execute(
            "SELECT id, total_occurrences, first_seen, last_seen FROM indicators WHERE ioc_type = ? AND normalized_value = ?",
            (ioc_type, normalized_value),
        )
        row = cursor.fetchone()

        if row:
            ind_id = int(row["id"])
            new_total = int(row["total_occurrences"]) + 1
            new_last_seen = max(row["last_seen"], timestamp)
            conn.execute(
                """
                UPDATE indicators
                SET total_occurrences = ?, last_seen = ?
                WHERE id = ?
                """,
                (new_total, new_last_seen, ind_id),
            )
            return ind_id, False

        cursor = conn.execute(
            """
            INSERT INTO indicators (
                ioc_type, normalized_value, first_seen, last_seen,
                distinct_sources_count, total_occurrences, severity, is_valid
            ) VALUES (?, ?, ?, ?, 1, 1, ?, ?)
            """,
            (ioc_type, normalized_value, timestamp, timestamp, sev, 1 if is_valid else 0),
        )
        return int(cursor.lastrowid), True

    def insert_observation(
        self,
        indicator_id: int,
        source_id: int,
        original_value: str,
        observed_at: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Record an individual feed observation and update indicator distinct sources and severity.

        Args:
            indicator_id: Foreign key to indicators.id.
            source_id: Foreign key to sources.id.
            original_value: Raw token as originally parsed.
            observed_at: Timestamp of observation.
            metadata: Contextual dictionary.

        Returns:
            The observation record ID.
        """
        conn = self.get_connection()
        timestamp = observed_at or self._get_utc_timestamp()
        meta_json = json.dumps(metadata) if metadata else "{}"

        # Insert observation (ignore duplicate exact duplicate observation)
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO indicator_observations (
                indicator_id, source_id, original_value, observed_at, metadata
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (indicator_id, source_id, original_value, timestamp, meta_json),
        )
        obs_id = cursor.lastrowid

        # Recalculate distinct source count, total observations, and latest observation timestamp
        cur_stats = conn.execute(
            """
            SELECT COUNT(DISTINCT source_id) AS distinct_count,
                   COUNT(id) AS total_count,
                   MAX(observed_at) AS latest_observed
            FROM indicator_observations
            WHERE indicator_id = ?
            """,
            (indicator_id,),
        )
        row = cur_stats.fetchone()
        distinct_count = int(row["distinct_count"]) if row and row["distinct_count"] else 1
        total_count = int(row["total_count"]) if row and row["total_count"] else 1
        latest_observed = row["latest_observed"] if row and row["latest_observed"] else timestamp
        new_severity = calculate_severity(distinct_count)

        # Update indicator record with updated counts, severity, and last_seen
        conn.execute(
            """
            UPDATE indicators
            SET distinct_sources_count = ?, total_occurrences = ?, severity = ?, last_seen = ?
            WHERE id = ?
            """,
            (distinct_count, total_count, new_severity, latest_observed, indicator_id),
        )

        return int(obs_id) if obs_id else 0

    def save_normalized_iocs(
        self, normalized_iocs: Sequence[NormalizedIOC]
    ) -> Dict[str, int]:
        """Persist a collection of NormalizedIOC objects within an ACID transaction.

        Invalid indicators are counted and safely skipped from persistence.

        Args:
            normalized_iocs: Sequence of NormalizedIOC instances.

        Returns:
            Dictionary containing counts: {'total', 'saved_indicators', 'new_indicators', 'observations', 'skipped_invalid'}.
        """
        conn = self.get_connection()
        self.initialize_database()

        total = len(normalized_iocs)
        new_indicators_count = 0
        observations_count = 0
        skipped_invalid = 0

        # Cache source IDs to minimize lookups during bulk save
        source_cache: Dict[Tuple[str, str], int] = {}

        try:
            with conn:
                for item in normalized_iocs:
                    if not item.is_valid or not item.normalized_value:
                        skipped_invalid += 1
                        continue

                    # 1. Resolve source
                    src_key = (item.source_name, item.source_location)
                    if src_key not in source_cache:
                        source_id = self.insert_source(
                            source_name=item.source_name,
                            source_type=item.original_ioc.source_type,
                            source_location=item.source_location,
                            feed_format=item.original_ioc.feed_format,
                            first_seen=item.normalized_at,
                        )
                        source_cache[src_key] = source_id
                    else:
                        source_id = source_cache[src_key]

                    # 2. Insert or update indicator
                    ind_id, is_new = self.insert_indicator(
                        ioc_type=item.ioc_type,
                        normalized_value=item.normalized_value,
                        observed_at=item.normalized_at,
                        is_valid=True,
                    )
                    if is_new:
                        new_indicators_count += 1

                    # 3. Record observation
                    self.insert_observation(
                        indicator_id=ind_id,
                        source_id=source_id,
                        original_value=item.original_value,
                        observed_at=item.normalized_at,
                        metadata=item.metadata,
                    )
                    observations_count += 1

            logger.info(
                "Batch saved: %d processed, %d new indicators, %d observations, %d invalid skipped",
                total,
                new_indicators_count,
                observations_count,
                skipped_invalid,
            )

        except Exception as e:
            logger.exception("Transaction error in save_normalized_iocs, rolling back: %s", e)
            conn.rollback()
            raise

        return {
            "total": total,
            "saved_indicators": observations_count,
            "new_indicators": new_indicators_count,
            "observations": observations_count,
            "skipped_invalid": skipped_invalid,
        }

    def get_indicator_by_id(self, indicator_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a single indicator by its integer primary key."""
        conn = self.get_connection()
        cursor = conn.execute("SELECT * FROM indicators WHERE id = ?", (indicator_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_indicator(self, ioc_type: str, normalized_value: str) -> Optional[Dict[str, Any]]:
        """Retrieve an indicator by its composite natural key (ioc_type, normalized_value)."""
        conn = self.get_connection()
        cursor = conn.execute(
            "SELECT * FROM indicators WHERE ioc_type = ? AND normalized_value = ?",
            (ioc_type, normalized_value),
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_all_indicators(
        self, limit: Optional[int] = None, offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Retrieve indicators ordered by distinct sources count descending."""
        conn = self.get_connection()
        query = "SELECT * FROM indicators ORDER BY distinct_sources_count DESC, total_occurrences DESC"
        params: List[Any] = []

        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])

        cursor = conn.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]

    def get_indicators_by_type(
        self, ioc_type: str, limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve indicators filtered by IOC type."""
        conn = self.get_connection()
        query = "SELECT * FROM indicators WHERE ioc_type = ? ORDER BY distinct_sources_count DESC"
        params: List[Any] = [ioc_type]

        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)

        cursor = conn.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]

    def get_indicators_by_severity(
        self, severity: str, limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve indicators filtered by severity tier ('HIGH', 'MEDIUM', 'LOW')."""
        conn = self.get_connection()
        query = "SELECT * FROM indicators WHERE severity = ? ORDER BY distinct_sources_count DESC"
        params: List[Any] = [severity.upper()]

        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)

        cursor = conn.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]

    def get_indicator_sources(self, indicator_id: int) -> List[Dict[str, Any]]:
        """Retrieve all feed sources and observation provenance for a given indicator.

        Args:
            indicator_id: Indicator ID.

        Returns:
            List of dictionaries with source metadata and observation details.
        """
        conn = self.get_connection()
        cursor = conn.execute(
            """
            SELECT
                s.source_name,
                s.source_type,
                s.source_location,
                s.feed_format,
                o.original_value,
                o.observed_at,
                o.metadata
            FROM indicator_observations o
            JOIN sources s ON o.source_id = s.id
            WHERE o.indicator_id = ?
            ORDER BY o.observed_at ASC
            """,
            (indicator_id,),
        )
        results = []
        for row in cursor.fetchall():
            d = dict(row)
            if d.get("metadata"):
                try:
                    d["metadata"] = json.loads(d["metadata"])
                except Exception:
                    pass
            results.append(d)
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Compile comprehensive relational counts and distribution metrics."""
        conn = self.get_connection()
        self.initialize_database()

        total_indicators = conn.execute("SELECT COUNT(*) AS c FROM indicators").fetchone()["c"]
        total_sources = conn.execute("SELECT COUNT(*) AS c FROM sources").fetchone()["c"]
        total_observations = conn.execute("SELECT COUNT(*) AS c FROM indicator_observations").fetchone()["c"]

        # Counts by severity
        cur_sev = conn.execute("SELECT severity, COUNT(*) AS count FROM indicators GROUP BY severity")
        by_severity = {r["severity"]: r["count"] for r in cur_sev.fetchall()}

        # Counts by IOC type
        cur_type = conn.execute("SELECT ioc_type, COUNT(*) AS count FROM indicators GROUP BY ioc_type")
        by_type = {r["ioc_type"]: r["count"] for r in cur_type.fetchall()}

        return {
            "total_indicators": total_indicators,
            "total_sources": total_sources,
            "total_observations": total_observations,
            "by_severity": by_severity,
            "by_type": by_type,
        }

    def record_feed_run(
        self,
        source_location: str,
        source_name: str,
        feed_format: Optional[str] = None,
        success: bool = True,
        indicators_extracted: int = 0,
        error_message: Optional[str] = None,
        processed_at: Optional[str] = None,
    ) -> int:
        """Record a feed collection/ingestion run event for audit tracking.

        Args:
            source_location: File path or remote URL.
            source_name: Identifier name of feed.
            feed_format: 'csv', 'txt', 'json', etc.
            success: Boolean success status.
            indicators_extracted: Count of extracted IOCs from this run.
            error_message: Error string if feed processing failed.
            processed_at: UTC ISO 8601 timestamp.

        Returns:
            Integer primary key ID of the inserted run record.
        """
        conn = self.get_connection()
        self.initialize_database()
        timestamp = processed_at or self._get_utc_timestamp()

        with conn:
            cursor = conn.execute(
                """
                INSERT INTO feed_ingestion_runs (
                    source_location, source_name, feed_format, success,
                    indicators_extracted, error_message, processed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source_location,
                    source_name,
                    feed_format or "",
                    1 if success else 0,
                    indicators_extracted,
                    error_message or "",
                    timestamp,
                ),
            )
            run_id = cursor.lastrowid
        return int(run_id) if run_id else 0

    def get_feed_runs(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Retrieve recorded feed ingestion runs ordered by timestamp descending.

        Args:
            limit: Maximum records to return.

        Returns:
            List of feed run dictionaries.
        """
        conn = self.get_connection()
        self.initialize_database()
        query = "SELECT * FROM feed_ingestion_runs ORDER BY processed_at DESC, id DESC"
        params: List[Any] = []
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)

        cursor = conn.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]

    def get_feed_run_summary(self) -> Dict[str, Any]:
        """Compile a summary of feed ingestion runs and recent errors.

        Returns:
            Dictionary with counts and error details.
        """
        conn = self.get_connection()
        self.initialize_database()

        runs = self.get_feed_runs()
        total_runs = len(runs)
        successful_runs = sum(1 for r in runs if r["success"] == 1)
        failed_runs = total_runs - successful_runs

        errors = [
            {
                "source_location": r["source_location"],
                "source_name": r["source_name"],
                "error_message": r["error_message"],
                "processed_at": r["processed_at"],
            }
            for r in runs
            if r["success"] == 0
        ]

        return {
            "has_history": total_runs > 0,
            "total_runs": total_runs,
            "successful_runs": successful_runs,
            "failed_runs": failed_runs,
            "runs": runs,
            "errors": errors,
        }

    # Backward compatibility alias
    get_feed_runs_summary = get_feed_run_summary

    def get_source_statistics(self) -> List[Dict[str, Any]]:
        """Retrieve aggregated contribution metrics for each registered intelligence source.

        Returns:
            List of dictionaries containing source metrics ordered by total observations descending.
        """
        conn = self.get_connection()
        self.initialize_database()

        cursor = conn.execute(
            """
            SELECT
                s.id,
                s.source_name,
                s.source_type,
                s.source_location,
                s.feed_format,
                s.first_seen,
                COUNT(o.id) AS total_observations,
                COUNT(DISTINCT o.indicator_id) AS unique_indicators
            FROM sources s
            LEFT JOIN indicator_observations o ON s.id = o.source_id
            GROUP BY s.id
            ORDER BY total_observations DESC, unique_indicators DESC, s.source_name ASC
            """
        )
        return [dict(r) for r in cursor.fetchall()]

    def get_top_repeated_indicators(
        self,
        limit: int = 10,
        ioc_type: Optional[str] = None,
        severity: Optional[str] = None,
        cross_feed_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """Retrieve top most frequently observed indicators with optional criteria filters.

        Args:
            limit: Maximum indicators to return (default: 10).
            ioc_type: Filter by IOC type category.
            severity: Filter by severity tier ('HIGH', 'MEDIUM', 'LOW').
            cross_feed_only: If True, only indicators seen in >= 2 distinct feeds.

        Returns:
            List of indicator dictionaries with occurrence counts and reporting feeds.
        """
        conn = self.get_connection()
        self.initialize_database()

        conditions = ["i.is_valid = 1"]
        params: List[Any] = []

        if ioc_type is not None:
            conditions.append("LOWER(i.ioc_type) = LOWER(?)")
            params.append(ioc_type)

        if severity is not None:
            conditions.append("UPPER(i.severity) = UPPER(?)")
            params.append(severity)

        if cross_feed_only:
            conditions.append("i.distinct_sources_count >= 2")

        where_clause = "WHERE " + " AND ".join(conditions)

        query = f"""
            SELECT
                i.id AS indicator_id,
                i.ioc_type,
                i.normalized_value,
                i.severity,
                i.distinct_sources_count,
                i.total_occurrences,
                COUNT(DISTINCT o.source_id) AS computed_distinct_sources,
                COUNT(o.id) AS computed_total_obs,
                i.first_seen,
                i.last_seen,
                GROUP_CONCAT(DISTINCT s.source_name) AS source_names_concat
            FROM indicators i
            LEFT JOIN indicator_observations o ON i.id = o.indicator_id
            LEFT JOIN sources s ON o.source_id = s.id
            {where_clause}
            GROUP BY i.id
            ORDER BY computed_total_obs DESC, computed_distinct_sources DESC, i.id ASC
            LIMIT ?
        """
        params.append(limit)

        cursor = conn.execute(query, params)
        rows = cursor.fetchall()
        results: List[Dict[str, Any]] = []

        for row in rows:
            srcs_concat = row["source_names_concat"] or ""
            sources = sorted(srcs_concat.split(",")) if srcs_concat else []
            obs_count = max(int(row["computed_total_obs"] or 0), int(row["total_occurrences"] or 0))
            dist_count = max(int(row["computed_distinct_sources"] or 0), int(row["distinct_sources_count"] or 0))
            results.append(
                {
                    "indicator_id": row["indicator_id"],
                    "ioc_type": row["ioc_type"],
                    "indicator": row["normalized_value"],
                    "normalized_value": row["normalized_value"],
                    "severity": row["severity"],
                    "distinct_sources_count": dist_count,
                    "total_occurrences": obs_count,
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                    "sources": sources,
                }
            )
        return results

    def get_data_quality_metrics(self) -> Dict[str, Any]:
        """Compile data quality indicators including validity counts, duplicates, and missing metadata.

        Returns:
            Dictionary containing data quality audit figures.
        """
        conn = self.get_connection()
        self.initialize_database()

        # Indicator counts
        cur_ind = conn.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN is_valid = 1 THEN 1 ELSE 0 END) AS valid_count,
                SUM(CASE WHEN is_valid = 0 THEN 1 ELSE 0 END) AS invalid_count
            FROM indicators
            """
        ).fetchone()

        total_ind = cur_ind["total"] or 0
        valid_ind = cur_ind["valid_count"] or 0
        invalid_ind = cur_ind["invalid_count"] or 0

        # Observation counts and metadata completeness
        cur_obs = conn.execute(
            """
            SELECT
                COUNT(*) AS total_obs,
                SUM(CASE WHEN metadata IS NULL OR metadata = '' OR metadata = '{}' THEN 1 ELSE 0 END) AS empty_meta
            FROM indicator_observations
            """
        ).fetchone()

        total_obs = cur_obs["total_obs"] or 0
        empty_meta = cur_obs["empty_meta"] or 0
        duplicate_obs = max(0, total_obs - total_ind)

        return {
            "total_indicators": total_ind,
            "valid_indicators": valid_ind,
            "invalid_indicators": invalid_ind,
            "total_observations": total_obs,
            "duplicate_observations": duplicate_obs,
            "empty_metadata_observations": empty_meta,
            "metadata_completeness_pct": (
                ((total_obs - empty_meta) / total_obs * 100) if total_obs > 0 else 100.0
            ),
        }

