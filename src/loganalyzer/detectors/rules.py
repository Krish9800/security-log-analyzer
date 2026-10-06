"""Detection rules for Brute Force, Web Exploits, Port Scanning, and Privilege Escalation."""

import re
from abc import ABC, abstractmethod
from urllib.parse import unquote

from loganalyzer.config.settings import settings
from loganalyzer.detectors.window import SlidingWindowState
from loganalyzer.models.events import LogEvent, Severity
from loganalyzer.models.incidents import (
    MITRE_BRUTE_FORCE,
    MITRE_PORT_SCAN,
    MITRE_PRIV_ESC,
    MITRE_WEB_EXPLOIT,
    Incident,
    MITRETechnique,
)

# Web Attack Signatures (compiled for linear performance)
SQLI_REGEX = re.compile(
    r"(?i)(?:\bunion\s+all\s+select\b|\bunion\s+select\b|\bselect\s+.*\s+from\b|'\s*or\s*['\d]+=['\d]+|--\s*$|\binformation_schema\b|\bwaitfor\s+delay\b|\bexec\s*\(|\bdrop\s+table\b)",
)

XSS_REGEX = re.compile(
    r"(?i)(?:<script[\s>]|javascript:|onerror\s*=|onload\s*=|alert\(|<iframe[\s>]|document\.cookie|prompt\(|eval\()",
)

TRAVERSAL_REGEX = re.compile(
    r"(?:\.\./|\.\.\\|/etc/passwd|/etc/shadow|/windows/win\.ini|\bboot\.ini\b)",
)

PROBE_REGEX = re.compile(
    r"(?i)(?:/\.env\b|/\.git/|/wp-login\.php|/wp-admin|/phpmyadmin|/actuator(?:/health)?|/shell\.php|/c99\.php|/r57\.php)",
)

SUSPICIOUS_SUDO_REGEX = re.compile(
    r"(?i)(?:/bin/bash\b|/bin/sh\b|\bsu\b|\bpasswd\b|/etc/shadow\b|\bchmod\s+777\b|\bvisudo\b|\buseradd\b)",
)


class DetectionRule(ABC):
    """Abstract base class for stateful or heuristic threat detection rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique rule identifier (e.g., RULE-BRUTE-01)."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable rule name."""

    @property
    @abstractmethod
    def mitre(self) -> MITRETechnique | None:
        """Associated MITRE ATT&CK technique."""

    @abstractmethod
    def process_event(self, event: LogEvent) -> Incident | None:
        """Process event and return an Incident if rule conditions are satisfied."""


class BruteForceDetector(DetectionRule):
    """Detects multi-attempt authentication brute-force attacks across a sliding window."""

    def __init__(
        self,
        threshold: int | None = None,
        window_seconds: int | None = None,
    ) -> None:
        self.threshold = threshold or settings.brute_force_threshold
        self.window = SlidingWindowState(
            window_seconds=window_seconds or settings.brute_force_window_seconds
        )
        self._alerted_keys: dict[str, float] = {}

    @property
    def rule_id(self) -> str:
        return "RULE-BRUTE-01"

    @property
    def name(self) -> str:
        return "Authentication Brute Force Attack"

    @property
    def mitre(self) -> MITRETechnique | None:
        return MITRE_BRUTE_FORCE

    def process_event(self, event: LogEvent) -> Incident | None:
        if event.event_type != "AUTH_FAILED" or not event.source_ip:
            return None

        key = f"{event.source_ip}:{event.username or 'unknown'}"
        active_events = self.window.add_event(key, event)

        if len(active_events) >= self.threshold:
            # Debounce: avoid firing multiple incidents for same key within window
            ts_epoch = event.timestamp.timestamp()
            last_alerted = self._alerted_keys.get(key, 0.0)
            if ts_epoch - last_alerted < self.window.window_delta.total_seconds():
                return None

            self._alerted_keys[key] = ts_epoch

            samples = [e.raw_message for e in active_events[-5:]]
            evt_ids = [e.id for e in active_events]

            return Incident(
                title=f"Brute Force Detected from {event.source_ip}",
                description=(
                    f"Observed {len(active_events)} failed authentication attempts "
                    f"targeting user '{event.username or 'unknown'}' within "
                    f"{self.window.window_delta.total_seconds():.0f}s."
                ),
                severity="HIGH",
                mitre=self.mitre,
                attacker_ip=event.source_ip,
                target_user=event.username,
                first_seen=active_events[0].timestamp,
                last_seen=active_events[-1].timestamp,
                event_count=len(active_events),
                evidence_event_ids=evt_ids,
                evidence_samples=samples,
                confidence_score=0.95,
                recommended_action=f"Block IP {event.source_ip} at edge firewall and inspect targeted account.",
            )

        return None


class WebAttackDetector(DetectionRule):
    """Detects SQL Injection, Cross-Site Scripting, Directory Traversal, and Web Shell probes."""

    @property
    def rule_id(self) -> str:
        return "RULE-WEB-02"

    @property
    def name(self) -> str:
        return "Web Application Exploit Attempt"

    @property
    def mitre(self) -> MITRETechnique | None:
        return MITRE_WEB_EXPLOIT

    def process_event(self, event: LogEvent) -> Incident | None:
        if event.event_type != "HTTP_REQUEST" or not event.http_uri:
            return None

        # Inspect decoded URL to defeat URL-encoding obfuscation
        decoded_uri = unquote(unquote(event.http_uri))
        detected_types: list[str] = []

        if SQLI_REGEX.search(decoded_uri):
            detected_types.append("SQL Injection (SQLi)")
        if XSS_REGEX.search(decoded_uri):
            detected_types.append("Cross-Site Scripting (XSS)")
        if TRAVERSAL_REGEX.search(decoded_uri):
            detected_types.append("Path Traversal / Arbitrary File Read")
        if PROBE_REGEX.search(decoded_uri):
            detected_types.append("Web Shell / Sensitive Endpoint Reconnaissance")

        if not detected_types:
            return None

        attack_label = ", ".join(detected_types)
        severity: Severity = (
            "CRITICAL"
            if ("SQL Injection" in attack_label or "Traversal" in attack_label)
            else "HIGH"
        )

        return Incident(
            title=f"Web Exploit: {attack_label} from {event.source_ip or 'unknown'}",
            description=(
                f"Client attempted {attack_label} via URI pattern '{event.http_uri}' "
                f"with HTTP verb {event.http_method or 'GET'}."
            ),
            severity=severity,
            mitre=self.mitre,
            attacker_ip=event.source_ip,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            event_count=1,
            evidence_event_ids=[event.id],
            evidence_samples=[event.raw_message],
            confidence_score=0.90,
            recommended_action="Validate input sanitization on web application and ban attacking IP.",
        )


class PortScanDetector(DetectionRule):
    """Detects horizontal and vertical port scanning reconnaissance from single source IP."""

    def __init__(
        self,
        threshold: int | None = None,
        window_seconds: int | None = None,
    ) -> None:
        self.threshold = threshold or settings.port_scan_threshold
        self.window = SlidingWindowState(
            window_seconds=window_seconds or settings.port_scan_window_seconds
        )
        self._alerted_ips: dict[str, float] = {}

    @property
    def rule_id(self) -> str:
        return "RULE-SCAN-03"

    @property
    def name(self) -> str:
        return "Network Service Port Scan"

    @property
    def mitre(self) -> MITRETechnique | None:
        return MITRE_PORT_SCAN

    def process_event(self, event: LogEvent) -> Incident | None:
        if not event.source_ip or event.destination_port is None:
            return None

        key = event.source_ip
        active_events = self.window.add_event(key, event)

        distinct_ports = {
            e.destination_port for e in active_events if e.destination_port is not None
        }

        if len(distinct_ports) >= self.threshold:
            ts_epoch = event.timestamp.timestamp()
            last_alerted = self._alerted_ips.get(key, 0.0)
            if ts_epoch - last_alerted < self.window.window_delta.total_seconds():
                return None

            self._alerted_ips[key] = ts_epoch

            samples = [e.raw_message for e in active_events[-5:]]
            evt_ids = [e.id for e in active_events]

            return Incident(
                title=f"Port Scan Reconnaissance from {event.source_ip}",
                description=(
                    f"Detected connection attempts across {len(distinct_ports)} distinct destination "
                    f"ports from source {event.source_ip} within "
                    f"{self.window.window_delta.total_seconds():.0f}s."
                ),
                severity="MEDIUM",
                mitre=self.mitre,
                attacker_ip=event.source_ip,
                first_seen=active_events[0].timestamp,
                last_seen=active_events[-1].timestamp,
                event_count=len(active_events),
                evidence_event_ids=evt_ids,
                evidence_samples=samples,
                confidence_score=0.85,
                recommended_action=f"Apply rate limiting and drop traffic from scanning IP {event.source_ip}.",
            )

        return None


class PrivilegeEscalationDetector(DetectionRule):
    """Detects anomalous sudo executions and high-risk root command invocations."""

    @property
    def rule_id(self) -> str:
        return "RULE-PRIVESC-04"

    @property
    def name(self) -> str:
        return "Suspicious Privilege Escalation Command"

    @property
    def mitre(self) -> MITRETechnique | None:
        return MITRE_PRIV_ESC

    def process_event(self, event: LogEvent) -> Incident | None:
        if event.event_type != "SUDO_EXEC":
            return None

        cmd = event.metadata.get("command", "")
        if not cmd:
            return None

        if SUSPICIOUS_SUDO_REGEX.search(cmd):
            return Incident(
                title=f"High-Risk Sudo Command Executed by '{event.username}'",
                description=(
                    f"User '{event.username}' invoked high-risk elevated command '{cmd}' via sudo."
                ),
                severity="HIGH",
                mitre=self.mitre,
                target_user=event.username,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                event_count=1,
                evidence_event_ids=[event.id],
                evidence_samples=[event.raw_message],
                confidence_score=0.88,
                recommended_action="Verify authorized administrative maintenance window for this command.",
            )

        return None
