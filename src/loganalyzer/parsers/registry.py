"""Parser registry and automatic log format detection coordinator."""

from collections.abc import Iterable, Iterator
from pathlib import Path

from loganalyzer.core.sanitizer import sanitize_log_line
from loganalyzer.models.events import LogEvent
from loganalyzer.parsers.auth_parser import AuthLogParser
from loganalyzer.parsers.base import BaseLogParser
from loganalyzer.parsers.firewall_parser import FirewallLogParser
from loganalyzer.parsers.json_parser import JsonLogParser
from loganalyzer.parsers.web_parser import WebLogParser


class ParserRegistry:
    """Registry coordinating format auto-detection and multi-source log parsing."""

    def __init__(self, register_defaults: bool = True) -> None:
        self._parsers: list[BaseLogParser] = []
        if register_defaults:
            # Order: JSON first (strict structural syntax), then Auth, Web, Firewall
            self.register(JsonLogParser())
            self.register(AuthLogParser())
            self.register(WebLogParser())
            self.register(FirewallLogParser())

    def register(self, parser: BaseLogParser) -> None:
        """Register a new parser implementation."""
        self._parsers.append(parser)

    def parse_line(self, line: str) -> LogEvent | None:
        """Auto-detect format and parse single log line into a canonical LogEvent."""
        cleaned = sanitize_log_line(line)
        if not cleaned:
            return None

        # 1. Try parsers that match can_parse heuristic
        for parser in self._parsers:
            if parser.can_parse(cleaned):
                event = parser.parse_line(cleaned)
                if event:
                    return event

        # 2. Try remaining parsers as fallback
        for parser in self._parsers:
            event = parser.parse_line(cleaned)
            if event:
                return event

        # 3. Fallback: Generic unclassified event
        return LogEvent(
            source_type="unclassified",
            event_type="GENERIC_EVENT",
            severity="INFORMATIONAL",
            raw_message=cleaned,
        )

    def parse_stream(self, lines: Iterable[str]) -> Iterator[LogEvent]:
        """Parse an iterable stream of log lines yields canonical LogEvents."""
        for line in lines:
            event = self.parse_line(line)
            if event:
                yield event

    def parse_file(self, file_path: str | Path) -> list[LogEvent]:
        """Read and parse an entire log file into a list of LogEvents."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        events: list[LogEvent] = []
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                event = self.parse_line(line)
                if event:
                    events.append(event)
        return events


# Global default registry instance
default_registry = ParserRegistry()
