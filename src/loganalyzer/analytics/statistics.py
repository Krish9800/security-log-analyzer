"""Forensic statistical analysis and frequency distributions across security log events."""

from collections import Counter
from collections.abc import Iterable
from datetime import datetime

from pydantic import BaseModel, Field

from loganalyzer.core.sanitizer import is_private_ip
from loganalyzer.models.events import LogEvent


class LogStatistics(BaseModel):
    """Consolidated statistical telemetry from an analyzed batch of security events."""

    total_events: int = 0
    earliest_timestamp: datetime | None = None
    latest_timestamp: datetime | None = None

    # Distributions
    events_by_type: dict[str, int] = Field(default_factory=dict)
    events_by_severity: dict[str, int] = Field(default_factory=dict)
    events_by_protocol: dict[str, int] = Field(default_factory=dict)

    # Top-N Rankings
    top_source_ips: list[tuple[str, int]] = Field(default_factory=list)
    top_dest_ports: list[tuple[int, int]] = Field(default_factory=list)
    top_users: list[tuple[str, int]] = Field(default_factory=list)
    top_http_uris: list[tuple[str, int]] = Field(default_factory=list)

    # Internal vs External Traffic Ratio
    private_ip_event_count: int = 0
    public_ip_event_count: int = 0


class LogStatisticsCalculator:
    """Computes statistical aggregations and top-N distributions over log events."""

    @staticmethod
    def compute(events: Iterable[LogEvent], top_n: int = 10) -> LogStatistics:
        """Compute consolidated statistics across an iterable of LogEvents."""
        total = 0
        min_ts: datetime | None = None
        max_ts: datetime | None = None

        type_counts: Counter[str] = Counter()
        sev_counts: Counter[str] = Counter()
        proto_counts: Counter[str] = Counter()
        ip_counts: Counter[str] = Counter()
        port_counts: Counter[int] = Counter()
        user_counts: Counter[str] = Counter()
        uri_counts: Counter[str] = Counter()

        private_ips = 0
        public_ips = 0

        for event in events:
            total += 1

            # Timestamps
            if min_ts is None or event.timestamp < min_ts:
                min_ts = event.timestamp
            if max_ts is None or event.timestamp > max_ts:
                max_ts = event.timestamp

            # Categorical counters
            type_counts[event.event_type] += 1
            sev_counts[event.severity] += 1
            if event.protocol:
                proto_counts[event.protocol] += 1

            # Top IPs and Network scope
            if event.source_ip:
                ip_counts[event.source_ip] += 1
                if is_private_ip(event.source_ip):
                    private_ips += 1
                else:
                    public_ips += 1

            if event.destination_port is not None:
                port_counts[event.destination_port] += 1

            if event.username:
                user_counts[event.username] += 1

            if event.http_uri:
                uri_counts[event.http_uri] += 1

        return LogStatistics(
            total_events=total,
            earliest_timestamp=min_ts,
            latest_timestamp=max_ts,
            events_by_type=dict(type_counts),
            events_by_severity=dict(sev_counts),
            events_by_protocol=dict(proto_counts),
            top_source_ips=ip_counts.most_common(top_n),
            top_dest_ports=port_counts.most_common(top_n),
            top_users=user_counts.most_common(top_n),
            top_http_uris=uri_counts.most_common(top_n),
            private_ip_event_count=private_ips,
            public_ip_event_count=public_ips,
        )
