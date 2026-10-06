"""Nginx and Apache web access log parser."""

import re

from loganalyzer.core.sanitizer import parse_utc_timestamp, sanitize_log_line
from loganalyzer.models.events import LogEvent, Severity
from loganalyzer.parsers.base import BaseLogParser

# Nginx/Apache Combined & Common Log Format regex
COMBINED_REGEX = re.compile(
    r"^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+\"([A-Z]+)\s+([^\"\s]+)\s+HTTP/[0-9\.]+\"\s+([0-9]{3})\s+([0-9\-]+)(?:\s+\"([^\"]*)\"\s+\"([^\"]*)\")?"
)


class WebLogParser(BaseLogParser):
    """Parser for Apache and Nginx access logs."""

    @property
    def source_name(self) -> str:
        return "nginx_combined"

    def can_parse(self, line: str) -> bool:
        """Heuristic check for web access log formatting."""
        if not line:
            return False
        return bool(
            ' "GET ' in line
            or ' "POST ' in line
            or ' "PUT ' in line
            or ' "DELETE ' in line
            or ' "HEAD ' in line
            or ' "OPTIONS ' in line
        )

    def parse_line(self, line: str) -> LogEvent | None:
        """Parse Nginx/Apache log line into canonical LogEvent."""
        cleaned = sanitize_log_line(line)
        if not cleaned:
            return None

        match = COMBINED_REGEX.match(cleaned)
        if not match:
            return None

        (
            client_ip,
            _identd,
            user_raw,
            ts_raw,
            method,
            uri,
            status_code_str,
            bytes_str,
            referer,
            user_agent,
        ) = match.groups()

        timestamp = parse_utc_timestamp(ts_raw)
        status_code = int(status_code_str)
        username = user_raw if user_raw != "-" else None

        # Severity heuristic based on HTTP status
        severity: Severity
        if status_code in (401, 403) or status_code >= 500:
            severity = "MEDIUM"
        elif status_code == 404:
            severity = "LOW"
        else:
            severity = "INFORMATIONAL"

        metadata = {
            "bytes_sent": int(bytes_str) if bytes_str != "-" else 0,
            "referer": referer if referer and referer != "-" else None,
        }

        return LogEvent(
            timestamp=timestamp,
            source_type=self.source_name,
            event_type="HTTP_REQUEST",
            severity=severity,
            source_ip=client_ip,
            destination_port=443 if "443" in cleaned else 80,
            protocol="TCP",
            username=username,
            action="ALLOW" if status_code < 400 else "DENY",
            http_method=method,
            http_uri=uri,
            http_status=status_code,
            user_agent=user_agent if user_agent and user_agent != "-" else None,
            raw_message=cleaned,
            metadata=metadata,
        )
