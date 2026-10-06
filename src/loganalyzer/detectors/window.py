"""Memory-bounded sliding-window state engine for correlation and rate tracking."""

import threading
from collections import deque
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from loganalyzer.config.settings import settings
from loganalyzer.models.events import LogEvent


class SlidingWindowState:
    """Thread-safe sliding time window tracking events per entity key."""

    def __init__(
        self,
        window_seconds: int = 60,
        max_buckets: int | None = None,
    ) -> None:
        self.window_delta = timedelta(seconds=window_seconds)
        self.max_buckets = max_buckets or settings.max_active_tracking_buckets
        self._buckets: dict[str, deque[LogEvent]] = {}
        self._lock = threading.Lock()

    def add_event(self, key: str, event: LogEvent) -> list[LogEvent]:
        """Record an event for the specified key and prune expired events."""
        with self._lock:
            # Memory safety: if bucket count exceeds max_buckets and key is new, prune stale
            if key not in self._buckets and len(self._buckets) >= self.max_buckets:
                self._evict_oldest_bucket_unlocked()

            if key not in self._buckets:
                self._buckets[key] = deque()

            bucket = self._buckets[key]
            bucket.append(event)

            # Evict events older than window_delta relative to this event's timestamp
            cutoff = event.timestamp - self.window_delta
            while bucket and bucket[0].timestamp < cutoff:
                bucket.popleft()

            return list(bucket)

    def get_active_events(self, key: str, as_of: datetime) -> list[LogEvent]:
        """Retrieve events in the sliding window for key as of a given timestamp."""
        with self._lock:
            if key not in self._buckets:
                return []

            bucket = self._buckets[key]
            cutoff = as_of - self.window_delta
            while bucket and bucket[0].timestamp < cutoff:
                bucket.popleft()

            if not bucket:
                del self._buckets[key]
                return []

            return list(bucket)

    def get_distinct_attribute_count(
        self,
        key: str,
        attr_extractor: Callable[[LogEvent], Any],
        as_of: datetime,
    ) -> int:
        """Count distinct non-None attribute values observed in the active window."""
        active = self.get_active_events(key, as_of)
        distinct_vals = {attr_extractor(evt) for evt in active if attr_extractor(evt) is not None}
        return len(distinct_vals)

    def prune_all(self, as_of: datetime) -> int:
        """Purge expired entries across all tracking buckets. Returns count of removed buckets."""
        cutoff = as_of - self.window_delta
        removed_count = 0
        with self._lock:
            keys_to_delete: list[str] = []
            for key, bucket in self._buckets.items():
                while bucket and bucket[0].timestamp < cutoff:
                    bucket.popleft()
                if not bucket:
                    keys_to_delete.append(key)

            for key in keys_to_delete:
                del self._buckets[key]
                removed_count += 1

        return removed_count

    def _evict_oldest_bucket_unlocked(self) -> None:
        """Evict the bucket with the earliest head timestamp when memory bound is hit."""
        if not self._buckets:
            return

        oldest_key = next(iter(self._buckets))
        del self._buckets[oldest_key]

    def clear(self) -> None:
        """Clear all active window state."""
        with self._lock:
            self._buckets.clear()

    def bucket_count(self) -> int:
        """Return total active tracking keys."""
        with self._lock:
            return len(self._buckets)
