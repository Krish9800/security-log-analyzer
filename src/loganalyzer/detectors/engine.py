"""Detection engine coordinating threat rules against streaming security log events."""

from collections.abc import Iterable

from loganalyzer.detectors.rules import (
    BruteForceDetector,
    DetectionRule,
    PortScanDetector,
    PrivilegeEscalationDetector,
    WebAttackDetector,
)
from loganalyzer.models.events import LogEvent
from loganalyzer.models.incidents import Incident


class DetectionEngine:
    """Core correlation engine dispatching log events across registered threat detectors."""

    def __init__(self, register_defaults: bool = True) -> None:
        self._rules: list[DetectionRule] = []
        if register_defaults:
            self.register_rule(BruteForceDetector())
            self.register_rule(WebAttackDetector())
            self.register_rule(PortScanDetector())
            self.register_rule(PrivilegeEscalationDetector())

    def register_rule(self, rule: DetectionRule) -> None:
        """Register a detection rule into the engine pipeline."""
        self._rules.append(rule)

    def analyze_event(self, event: LogEvent) -> list[Incident]:
        """Dispatch a single event to all active rules and collect triggered incidents."""
        incidents: list[Incident] = []
        for rule in self._rules:
            incident = rule.process_event(event)
            if incident:
                incidents.append(incident)
        return incidents

    def analyze_stream(self, events: Iterable[LogEvent]) -> list[Incident]:
        """Process an entire stream of log events and return all generated incidents."""
        all_incidents: list[Incident] = []
        for event in events:
            new_incidents = self.analyze_event(event)
            if new_incidents:
                all_incidents.extend(new_incidents)
        return all_incidents


# Global default engine instance
default_engine = DetectionEngine()
