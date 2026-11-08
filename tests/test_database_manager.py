"""Unit tests for the SQLite Database Manager module (Phase 6)."""

import json
from pathlib import Path
import sqlite3
import pytest

from modules.database_manager import DatabaseManager
from modules.ioc_parser import ParsedIOC
from modules.normalizer import NormalizedIOC


@pytest.fixture
def temp_db(tmp_path: Path) -> DatabaseManager:
    """Fixture providing a DatabaseManager instance on a temporary SQLite database."""
    db_file = tmp_path / "test_threat_intel.db"
    manager = DatabaseManager(db_path=db_file)
    manager.initialize_database()
    yield manager
    manager.close()


def make_test_normalized_ioc(
    value: str,
    ioc_type: str,
    source_name: str = "feed_alpha.txt",
    is_valid: bool = True,
    metadata: dict = None,
) -> NormalizedIOC:
    """Helper to construct NormalizedIOC instances for testing."""
    orig_ioc = ParsedIOC(
        value=value,
        ioc_type=ioc_type,
        source_name=source_name,
        source_type="file",
        source_location=f"/feeds/{source_name}",
        feed_format="txt",
        extracted_at="2026-11-08T12:00:00Z",
        raw_value=value,
    )
    return NormalizedIOC(
        original_value=value,
        normalized_value=value.lower() if is_valid else None,
        ioc_type=ioc_type,
        is_valid=is_valid,
        normalization_status="normalized" if is_valid else "invalid",
        source_name=source_name,
        source_location=f"/feeds/{source_name}",
        normalized_at="2026-11-08T12:00:01Z",
        original_ioc=orig_ioc,
        metadata=metadata or {"tag": "c2_test"},
        validation_reason="" if is_valid else "Invalid syntax",
    )


def test_database_initialization_tables_and_indexes(temp_db: DatabaseManager) -> None:
    """Verify tables and indexes are successfully created upon initialization."""
    conn = temp_db.get_connection()
    cursor = conn.execute(
        "SELECT name, type FROM sqlite_master WHERE type IN ('table', 'index') ORDER BY name"
    )
    names = {row["name"] for row in cursor.fetchall()}

    # Required tables
    assert "indicators" in names
    assert "sources" in names
    assert "indicator_observations" in names

    # Required indexes
    assert "idx_indicators_type_val" in names
    assert "idx_indicators_severity" in names
    assert "idx_observations_indicator" in names
    assert "idx_observations_source" in names


def test_foreign_key_enforcement(temp_db: DatabaseManager) -> None:
    """Verify foreign key enforcement is active and rejects orphaned observations."""
    conn = temp_db.get_connection()
    with pytest.raises(sqlite3.IntegrityError):
        # Attempt to insert an observation pointing to non-existent indicator and source
        conn.execute(
            """
            INSERT INTO indicator_observations (indicator_id, source_id, original_value, observed_at)
            VALUES (9999, 9999, 'orphan.example.com', '2026-11-08T00:00:00Z')
            """
        )


def test_insert_source_idempotent(temp_db: DatabaseManager) -> None:
    """Verify inserting the same source name and location returns the existing source ID."""
    s1 = temp_db.insert_source("feed_a", "file", "/feeds/a.txt", "txt")
    s2 = temp_db.insert_source("feed_a", "file", "/feeds/a.txt", "txt")
    assert s1 == s2
    assert s1 > 0


def test_insert_indicator_and_deduplication(temp_db: DatabaseManager) -> None:
    """Verify inserting duplicate canonical IOC updates occurrences without duplicating rows."""
    ind_id1, is_new1 = temp_db.insert_indicator("ipv4", "192.0.2.1")
    assert is_new1 is True

    ind_id2, is_new2 = temp_db.insert_indicator("ipv4", "192.0.2.1")
    assert is_new2 is False
    assert ind_id1 == ind_id2

    # Check occurrences updated
    record = temp_db.get_indicator_by_id(ind_id1)
    assert record is not None
    assert record["total_occurrences"] == 2


def test_distinct_source_counting_and_severity_transitions(temp_db: DatabaseManager) -> None:
    """Verify severity transitions deterministically as distinct sources increase:

    1 source -> LOW
    2-4 sources -> MEDIUM
    >= 5 sources -> HIGH
    Repeated observations from the same source must not inflate distinct count.
    """
    ind_id, _ = temp_db.insert_indicator("ipv4", "198.51.100.1")

    # Source 1 (repeated twice)
    s1 = temp_db.insert_source("source_1", "file", "/s1.txt", "txt")
    temp_db.insert_observation(ind_id, s1, "198.51.100.1")
    temp_db.insert_observation(ind_id, s1, "198.51.100.1")  # repeat

    r1 = temp_db.get_indicator_by_id(ind_id)
    assert r1["distinct_sources_count"] == 1
    assert r1["severity"] == "LOW"

    # Source 2 (distinct) -> triggers MEDIUM
    s2 = temp_db.insert_source("source_2", "file", "/s2.txt", "txt")
    temp_db.insert_observation(ind_id, s2, "198.51.100.1")

    r2 = temp_db.get_indicator_by_id(ind_id)
    assert r2["distinct_sources_count"] == 2
    assert r2["severity"] == "MEDIUM"

    # Sources 3, 4, 5 -> triggers HIGH at 5
    s3 = temp_db.insert_source("source_3", "file", "/s3.txt", "txt")
    s4 = temp_db.insert_source("source_4", "file", "/s4.txt", "txt")
    s5 = temp_db.insert_source("source_5", "file", "/s5.txt", "txt")

    temp_db.insert_observation(ind_id, s3, "198.51.100.1")
    temp_db.insert_observation(ind_id, s4, "198.51.100.1")
    temp_db.insert_observation(ind_id, s5, "198.51.100.1")

    r3 = temp_db.get_indicator_by_id(ind_id)
    assert r3["distinct_sources_count"] == 5
    assert r3["severity"] == "HIGH"


def test_metadata_serialization(temp_db: DatabaseManager) -> None:
    """Verify observation metadata is serialized to JSON and deserialized properly."""
    ind_id, _ = temp_db.insert_indicator("domain", "c2.example.org")
    s_id = temp_db.insert_source("feed_meta", "file", "/meta.csv", "csv")
    meta = {"confidence": 95, "tags": ["apt", "trojan"]}

    temp_db.insert_observation(ind_id, s_id, "c2.example.org", metadata=meta)
    sources = temp_db.get_indicator_sources(ind_id)

    assert len(sources) == 1
    assert sources[0]["metadata"] == meta


def test_bulk_save_normalized_iocs(temp_db: DatabaseManager) -> None:
    """Verify save_normalized_iocs safely handles valid and invalid records in a transaction."""
    valid_1 = make_test_normalized_ioc("192.0.2.10", "ipv4", source_name="feed_1")
    valid_2 = make_test_normalized_ioc("192.0.2.10", "ipv4", source_name="feed_2")
    invalid_1 = make_test_normalized_ioc("bad_ip", "ipv4", is_valid=False)

    stats = temp_db.save_normalized_iocs([valid_1, valid_2, invalid_1])

    assert stats["total"] == 3
    assert stats["new_indicators"] == 1
    assert stats["observations"] == 2
    assert stats["skipped_invalid"] == 1

    # Verify indicator state in database
    ind = temp_db.get_indicator("ipv4", "192.0.2.10")
    assert ind is not None
    assert ind["distinct_sources_count"] == 2
    assert ind["severity"] == "MEDIUM"


def test_get_indicators_filtered_queries(temp_db: DatabaseManager) -> None:
    """Verify retrieval by type and severity."""
    i1 = make_test_normalized_ioc("192.0.2.1", "ipv4")
    i2 = make_test_normalized_ioc("example.com", "domain")
    temp_db.save_normalized_iocs([i1, i2])

    ips = temp_db.get_indicators_by_type("ipv4")
    assert len(ips) == 1
    assert ips[0]["normalized_value"] == "192.0.2.1"

    domains = temp_db.get_indicators_by_type("domain")
    assert len(domains) == 1
    assert domains[0]["normalized_value"] == "example.com"

    low_sev = temp_db.get_indicators_by_severity("LOW")
    assert len(low_sev) == 2


def test_get_statistics(temp_db: DatabaseManager) -> None:
    """Verify repository statistics compilation."""
    i1 = make_test_normalized_ioc("192.0.2.1", "ipv4", source_name="f1")
    i2 = make_test_normalized_ioc("example.com", "domain", source_name="f2")
    temp_db.save_normalized_iocs([i1, i2])

    stats = temp_db.get_statistics()
    assert stats["total_indicators"] == 2
    assert stats["total_sources"] == 2
    assert stats["total_observations"] == 2
    assert stats["by_type"]["ipv4"] == 1
    assert stats["by_type"]["domain"] == 1
    assert stats["by_severity"]["LOW"] == 2


def test_database_persistence_across_reconnect(tmp_path: Path) -> None:
    """Verify data persists when database connection is closed and reopened."""
    db_file = tmp_path / "persist.db"

    # Write data and close
    with DatabaseManager(db_path=db_file) as db1:
        i1 = make_test_normalized_ioc("2001:db8::1", "ipv6")
        db1.save_normalized_iocs([i1])

    # Reopen with fresh manager and verify data exists
    with DatabaseManager(db_path=db_file) as db2:
        ind = db2.get_indicator("ipv6", "2001:db8::1")
        assert ind is not None
        assert ind["normalized_value"] == "2001:db8::1"


def test_transaction_rollback_on_error(tmp_path: Path) -> None:
    """Verify that an error inside save_normalized_iocs rolls back the transaction."""
    db_file = tmp_path / "rollback.db"
    manager = DatabaseManager(db_path=db_file)
    manager.initialize_database()

    # Pre-populate with one valid indicator
    good1 = make_test_normalized_ioc("192.0.2.1", "ipv4")
    manager.save_normalized_iocs([good1])
    assert len(manager.get_all_indicators()) == 1

    # Attempt saving new indicators where an error is raised mid-transaction
    good2 = make_test_normalized_ioc("198.51.100.2", "ipv4")
    from unittest.mock import patch

    with patch.object(manager, "insert_observation", side_effect=RuntimeError("Simulated database failure")):
        with pytest.raises(RuntimeError):
            manager.save_normalized_iocs([good2])

    # Ensure database was rolled back and still only has the 1 initial indicator
    all_inds = manager.get_all_indicators()
    assert len(all_inds) == 1
    assert all_inds[0]["normalized_value"] == "192.0.2.1"
    manager.close()
