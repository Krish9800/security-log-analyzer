"""Unit tests for Phase 4: Sliding Window State Engine."""

from datetime import UTC, datetime, timedelta

from loganalyzer.detectors.window import SlidingWindowState
from loganalyzer.models.events import LogEvent


def test_sliding_window_event_accumulation() -> None:
    """Test adding events within time window."""
    window = SlidingWindowState(window_seconds=60)
    base_time = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)

    evt1 = LogEvent(
        timestamp=base_time,
        event_type="AUTH_FAILED",
        source_ip="192.168.1.10",
        raw_message="failed 1",
    )
    evt2 = LogEvent(
        timestamp=base_time + timedelta(seconds=20),
        event_type="AUTH_FAILED",
        source_ip="192.168.1.10",
        raw_message="failed 2",
    )

    res1 = window.add_event("192.168.1.10", evt1)
    assert len(res1) == 1

    res2 = window.add_event("192.168.1.10", evt2)
    assert len(res2) == 2


def test_sliding_window_expiration() -> None:
    """Test that events older than window threshold are popped."""
    window = SlidingWindowState(window_seconds=30)
    base_time = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)

    evt_old = LogEvent(
        timestamp=base_time,
        event_type="AUTH_FAILED",
        source_ip="192.168.1.10",
        raw_message="old event",
    )
    evt_new = LogEvent(
        timestamp=base_time + timedelta(seconds=35),
        event_type="AUTH_FAILED",
        source_ip="192.168.1.10",
        raw_message="new event",
    )

    window.add_event("192.168.1.10", evt_old)
    active = window.add_event("192.168.1.10", evt_new)

    # evt_old should have been pruned because 35s > 30s
    assert len(active) == 1
    assert active[0].raw_message == "new event"


def test_distinct_attribute_count() -> None:
    """Test counting distinct attributes (e.g. port scanning)."""
    window = SlidingWindowState(window_seconds=60)
    base_time = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)

    # Add 4 events with 3 unique destination ports
    ports = [80, 443, 80, 8080]
    for i, port in enumerate(ports):
        evt = LogEvent(
            timestamp=base_time + timedelta(seconds=i),
            source_ip="203.0.113.5",
            destination_port=port,
            raw_message=f"hit port {port}",
        )
        window.add_event("203.0.113.5", evt)

    count = window.get_distinct_attribute_count(
        "203.0.113.5",
        lambda e: e.destination_port,
        base_time + timedelta(seconds=10),
    )
    assert count == 3


def test_prune_all_and_clear() -> None:
    """Test global pruning and clearing of buckets."""
    window = SlidingWindowState(window_seconds=30)
    base_time = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)

    evt = LogEvent(timestamp=base_time, raw_message="test")
    window.add_event("key1", evt)
    assert window.bucket_count() == 1

    # Pruning 40 seconds later should remove key1
    removed = window.prune_all(base_time + timedelta(seconds=40))
    assert removed == 1
    assert window.bucket_count() == 0

    # Test clear
    window.add_event("key2", evt)
    assert window.bucket_count() == 1
    window.clear()
    assert window.bucket_count() == 0


def test_max_buckets_eviction() -> None:
    """Test memory-bounding behavior when bucket limit is reached."""
    window = SlidingWindowState(window_seconds=60, max_buckets=2)
    base_time = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)

    window.add_event("k1", LogEvent(timestamp=base_time, raw_message="k1"))
    window.add_event("k2", LogEvent(timestamp=base_time, raw_message="k2"))
    assert window.bucket_count() == 2

    # Adding a 3rd key should evict oldest bucket k1
    window.add_event("k3", LogEvent(timestamp=base_time, raw_message="k3"))
    assert window.bucket_count() == 2
    assert len(window.get_active_events("k1", base_time)) == 0
    assert len(window.get_active_events("k3", base_time)) == 1
