"""Abstract base class for log format parsers."""

from abc import ABC, abstractmethod

from loganalyzer.models.events import LogEvent


class BaseLogParser(ABC):
    """Abstract parser for converting raw log lines into canonical LogEvents."""

    @property
    @abstractmethod
    def source_name(self) -> str:
        """Name of the log source format (e.g., auth_log, nginx_combined)."""

    @abstractmethod
    def can_parse(self, line: str) -> bool:
        """Heuristic check to determine if this parser can handle the log line."""

    @abstractmethod
    def parse_line(self, line: str) -> LogEvent | None:
        """Parse raw log line into a normalized LogEvent or None if unparseable."""
