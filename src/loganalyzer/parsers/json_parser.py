"""Structured JSON log parser (ECS, Suricata, CloudTrail, generic JSON)."""

import json
from typing import Any

from loganalyzer.core.sanitizer import parse_utc_timestamp, sanitize_log_line
from loganalyzer.models.events import EventType, LogEvent, Severity
from loganalyzer.parsers.base import BaseLogParser


class JsonLogParser(BaseLogParser):
    """Parser for structured JSON formatted security log entries."""

    @property
    def source_name(self) -> str:
        return "json_ecs"

    def can_parse(self, line: str) -> bool:
        """Heuristic check for JSON string format."""
        if not line:
            return False
        stripped = line.strip()
        return stripped.startswith("{") and stripped.endswith("}")

    def parse_line(self, line: str) -> LogEvent | None:
        """Parse structured JSON line into canonical LogEvent."""
        cleaned = sanitize_log_line(line)
        if not cleaned:
            return None

        try:
            data: dict[str, Any] = json.loads(cleaned)
        except (json.JSONDecodeError, ValueError):
            return None

        # Extract timestamp
        ts_val = (
            data.get("timestamp")
            or data.get("@timestamp")
            or data.get("time")
            or data.get("ts")
            or data.get("date")
        )
        timestamp = parse_utc_timestamp(str(ts_val) if ts_val else None)

        # Extract IPs
        src_ip = (
            data.get("source_ip")
            or data.get("src_ip")
            or data.get("client_ip")
            or data.get("src")
            or (data.get("source", {}).get("ip") if isinstance(data.get("source"), dict) else None)
        )
        dst_ip = (
            data.get("destination_ip")
            or data.get("dest_ip")
            or data.get("dst_ip")
            or data.get("dst")
            or (
                data.get("destination", {}).get("ip")
                if isinstance(data.get("destination"), dict)
                else None
            )
        )

        # Extract Ports
        src_port = (
            data.get("source_port")
            or data.get("src_port")
            or data.get("spt")
            or (
                data.get("source", {}).get("port") if isinstance(data.get("source"), dict) else None
            )
        )
        dst_port = (
            data.get("destination_port")
            or data.get("dest_port")
            or data.get("dst_port")
            or data.get("dpt")
            or (
                data.get("destination", {}).get("port")
                if isinstance(data.get("destination"), dict)
                else None
            )
        )

        # Identity & Action
        username = (
            data.get("username")
            or data.get("user")
            or (data.get("user", {}).get("name") if isinstance(data.get("user"), dict) else None)
        )
        action = data.get("action") or data.get("event", {}).get("action")
        proto = data.get("protocol") or data.get("proto")

        # Map event type
        raw_type = str(data.get("event_type") or data.get("type") or "").upper()
        event_type: EventType
        if "AUTH_FAIL" in raw_type or "LOGIN_FAIL" in raw_type:
            event_type = "AUTH_FAILED"
        elif "AUTH_LOGIN" in raw_type or "LOGIN_SUCCESS" in raw_type:
            event_type = "AUTH_LOGIN"
        elif "SUDO" in raw_type:
            event_type = "SUDO_EXEC"
        elif "HTTP" in raw_type or "WEB" in raw_type:
            event_type = "HTTP_REQUEST"
        elif "DROP" in raw_type or "DENY" in raw_type:
            event_type = "FIREWALL_DROP"
        else:
            event_type = "GENERIC_EVENT"

        # Severity
        sev_raw = str(data.get("severity") or "INFORMATIONAL").upper()
        severity: Severity = "INFORMATIONAL"
        if sev_raw in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "INFORMATIONAL"):
            severity = sev_raw  # type: ignore[assignment]

        return LogEvent(
            timestamp=timestamp,
            source_type=self.source_name,
            event_type=event_type,
            severity=severity,
            source_ip=str(src_ip) if src_ip else None,
            destination_ip=str(dst_ip) if dst_ip else None,
            source_port=int(src_port) if src_port is not None else None,
            destination_port=int(dst_port) if dst_port is not None else None,
            protocol=str(proto).upper() if proto else None,
            username=str(username) if username else None,
            action=str(action).upper() if action else None,
            raw_message=cleaned,
            metadata=data,
        )
