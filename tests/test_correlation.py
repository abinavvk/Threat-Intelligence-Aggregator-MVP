"""Unit tests for the IOC Correlation Engine module (Phase 7)."""

from pathlib import Path
from unittest.mock import patch
import pytest

from modules.correlation import CorrelationEngine, CorrelationResult
from modules.database_manager import DatabaseManager


@pytest.fixture
def temp_db(tmp_path: Path) -> DatabaseManager:
    """Fixture providing a clean initialized DatabaseManager on a temporary database."""
    db_file = tmp_path / "test_correlation.db"
    manager = DatabaseManager(db_path=db_file)
    manager.initialize_database()
    yield manager
    manager.close()


@pytest.fixture
def engine(temp_db: DatabaseManager) -> CorrelationEngine:
    """Fixture providing a CorrelationEngine bound to the temporary database."""
    return CorrelationEngine(db_manager=temp_db)


def test_correlate_indicator_single_source_low_severity(
    temp_db: DatabaseManager, engine: CorrelationEngine
) -> None:
    """Verify an indicator observed by 1 source produces LOW severity and is_cross_feed=False."""
    ind_id, _ = temp_db.insert_indicator("ipv4", "192.0.2.1")
    s_id = temp_db.insert_source("feed_alpha", "file", "/feeds/alpha.txt", "txt")
    temp_db.insert_observation(ind_id, s_id, "192.0.2.1")

    res = engine.correlate_indicator(ind_id)

    assert res is not None
    assert res.indicator_id == ind_id
    assert res.ioc_type == "ipv4"
    assert res.normalized_value == "192.0.2.1"
    assert res.distinct_sources_count == 1
    assert res.total_occurrences == 1
    assert res.sources == ["feed_alpha"]
    assert res.severity == "LOW"
    assert res.is_cross_feed is False


def test_correlate_indicator_two_sources_medium_severity(
    temp_db: DatabaseManager, engine: CorrelationEngine
) -> None:
    """Verify an indicator observed by 2 distinct sources produces MEDIUM severity and is_cross_feed=True."""
    ind_id, _ = temp_db.insert_indicator("domain", "c2.example.org")
    s1 = temp_db.insert_source("feed_1", "file", "/1.txt", "txt")
    s2 = temp_db.insert_source("feed_2", "url", "https://example.com/feed.json", "json")

    temp_db.insert_observation(ind_id, s1, "c2.example.org")
    temp_db.insert_observation(ind_id, s2, "C2.EXAMPLE.ORG.")

    res = engine.correlate_indicator(ind_id)

    assert res is not None
    assert res.distinct_sources_count == 2
    assert res.total_occurrences == 2
    assert res.sources == ["feed_1", "feed_2"]
    assert res.severity == "MEDIUM"
    assert res.is_cross_feed is True


def test_correlate_indicator_five_sources_high_severity(
    temp_db: DatabaseManager, engine: CorrelationEngine
) -> None:
    """Verify an indicator observed across 5 distinct sources achieves HIGH severity."""
    ind_id, _ = temp_db.insert_indicator("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    for i in range(1, 6):
        src_id = temp_db.insert_source(f"feed_{i}", "file", f"/{i}.txt", "txt")
        temp_db.insert_observation(ind_id, src_id, "e3b0c442...")

    res = engine.correlate_indicator(ind_id)

    assert res is not None
    assert res.distinct_sources_count == 5
    assert res.severity == "HIGH"
    assert res.is_cross_feed is True
    assert len(res.sources) == 5


def test_same_source_multiple_observations_no_inflation(
    temp_db: DatabaseManager, engine: CorrelationEngine
) -> None:
    """Verify repeated observations from the SAME feed do not inflate distinct sources count."""
    ind_id, _ = temp_db.insert_indicator("ipv4", "198.51.100.22")
    s1 = temp_db.insert_source("internal_firewall", "file", "/fw.log", "txt")

    # 4 distinct sightings in the SAME firewall log with different times
    temp_db.insert_observation(ind_id, s1, "198.51.100.22", observed_at="2026-11-08T01:00:00Z")
    temp_db.insert_observation(ind_id, s1, "198.51.100.22", observed_at="2026-11-08T02:00:00Z")
    temp_db.insert_observation(ind_id, s1, "198.51.100.22", observed_at="2026-11-08T03:00:00Z")
    temp_db.insert_observation(ind_id, s1, "198.51.100.22", observed_at="2026-11-08T04:00:00Z")

    res = engine.correlate_indicator(ind_id)

    assert res is not None
    assert res.distinct_sources_count == 1
    assert res.total_occurrences == 4
    assert res.severity == "LOW"
    assert res.is_cross_feed is False
    assert res.first_seen == "2026-11-08T01:00:00Z"
    assert res.last_seen == "2026-11-08T04:00:00Z"


def test_different_ioc_types_remain_separate(
    temp_db: DatabaseManager, engine: CorrelationEngine
) -> None:
    """Verify different IOC types with similar values are evaluated as separate indicators."""
    ip_id, _ = temp_db.insert_indicator("ipv4", "192.0.2.1")
    dom_id, _ = temp_db.insert_indicator("domain", "192.0.2.1.example.com")

    s1 = temp_db.insert_source("source_1", "file", "/1.txt", "txt")
    temp_db.insert_observation(ip_id, s1, "192.0.2.1")
    temp_db.insert_observation(dom_id, s1, "192.0.2.1.example.com")

    all_corr = engine.correlate_all()
    assert len(all_corr) == 2
    types = {c.ioc_type for c in all_corr}
    assert types == {"ipv4", "domain"}


def test_correlate_all_filters(temp_db: DatabaseManager, engine: CorrelationEngine) -> None:
    """Verify correlate_all filters by severity, IOC type, and min_sources."""
    # Setup: 1 HIGH sha256 (5 sources), 1 MEDIUM domain (2 sources), 1 LOW ipv4 (1 source)
    h_id, _ = temp_db.insert_indicator("sha256", "a" * 64)
    m_id, _ = temp_db.insert_indicator("domain", "test.example.org")
    l_id, _ = temp_db.insert_indicator("ipv4", "203.0.113.1")

    # Sources
    sources = [temp_db.insert_source(f"s_{i}", "file", f"/{i}.txt", "txt") for i in range(6)]

    for i in range(5):
        temp_db.insert_observation(h_id, sources[i], "a" * 64)

    temp_db.insert_observation(m_id, sources[0], "test.example.org")
    temp_db.insert_observation(m_id, sources[1], "test.example.org")

    temp_db.insert_observation(l_id, sources[0], "203.0.113.1")

    # Filter by min_sources = 2 (cross-feed only)
    cross_feed = engine.correlate_all(min_sources=2)
    assert len(cross_feed) == 2
    assert all(c.is_cross_feed for c in cross_feed)

    # Filter by severity = HIGH
    high_only = engine.correlate_all(severity="HIGH")
    assert len(high_only) == 1
    assert high_only[0].indicator_id == h_id

    # Filter by type = domain
    domains_only = engine.correlate_all(ioc_type="domain")
    assert len(domains_only) == 1
    assert domains_only[0].normalized_value == "test.example.org"


def test_correlation_statistics(temp_db: DatabaseManager, engine: CorrelationEngine) -> None:
    """Verify compile of correlation statistics dictionary."""
    id1, _ = temp_db.insert_indicator("ipv4", "192.0.2.1")
    id2, _ = temp_db.insert_indicator("domain", "cross.example.com")

    s1 = temp_db.insert_source("s1", "file", "/s1", "txt")
    s2 = temp_db.insert_source("s2", "file", "/s2", "txt")

    temp_db.insert_observation(id1, s1, "192.0.2.1")

    temp_db.insert_observation(id2, s1, "cross.example.com")
    temp_db.insert_observation(id2, s2, "cross.example.com")

    stats = engine.get_correlation_statistics()

    assert stats["total_indicators_analyzed"] == 2
    assert stats["cross_feed_indicators_count"] == 1
    assert stats["single_source_indicators_count"] == 1
    assert stats["cross_feed_percentage"] == 50.0
    assert stats["by_severity"]["MEDIUM"] == 1
    assert stats["by_severity"]["LOW"] == 1
    assert stats["sources_distribution"][1] == 1
    assert stats["sources_distribution"][2] == 1


def test_empty_database_handling(engine: CorrelationEngine) -> None:
    """Verify graceful handling when database has zero records."""
    assert engine.correlate_all() == []
    assert engine.correlate_indicator(999) is None
    stats = engine.get_correlation_statistics()
    assert stats["total_indicators_analyzed"] == 0
    assert stats["cross_feed_indicators_count"] == 0


def test_refresh_correlations(temp_db: DatabaseManager, engine: CorrelationEngine) -> None:
    """Verify refresh_correlations synchronizes indicator rows with observation records."""
    ind_id, _ = temp_db.insert_indicator("ipv4", "192.0.2.50")
    s1 = temp_db.insert_source("s1", "file", "/s1", "txt")
    s2 = temp_db.insert_source("s2", "file", "/s2", "txt")

    temp_db.insert_observation(ind_id, s1, "192.0.2.50")
    temp_db.insert_observation(ind_id, s2, "192.0.2.50")

    result = engine.refresh_correlations()
    assert result["updated"] == 1

    ind = temp_db.get_indicator_by_id(ind_id)
    assert ind["distinct_sources_count"] == 2
    assert ind["severity"] == "MEDIUM"


def test_no_network_activity_during_correlation(engine: CorrelationEngine) -> None:
    """Verify correlation executes purely in-memory/SQLite with no network or DNS calls."""
    with patch("socket.gethostbyname") as mock_dns, patch("requests.get") as mock_http:
        engine.correlate_all()
        engine.get_correlation_statistics()
        mock_dns.assert_not_called()
        mock_http.assert_not_called()

