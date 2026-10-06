"""Unit tests for Phase 2 data models: LogEvent, Incident, and MITRE taxonomy."""

from datetime import UTC, datetime

from loganalyzer.models.events import LogEvent
from loganalyzer.models.incidents import (
    MITRE_BRUTE_FORCE,
    MITRE_PORT_SCAN,
    MITRE_PRIV_ESC,
    MITRE_WEB_EXPLOIT,
    Incident,
    MITRETechnique,
)


def test_log_event_creation_and_defaults() -> None:
    """Test valid LogEvent instantiation and defaults."""
    evt = LogEvent(
        source_type="auth_log",
        event_type="AUTH_FAILED",
        severity="HIGH",
        source_ip="192.168.1.50",
        source_port=44552,
        username="root",
        raw_message="Failed password for root from 192.168.1.50 port 44552 ssh2",
    )
    assert evt.id.startswith("evt-")
    assert evt.source_type == "auth_log"
    assert evt.event_type == "AUTH_FAILED"
    assert evt.severity == "HIGH"
    assert evt.source_ip == "192.168.1.50"
    assert evt.source_port == 44552
    assert evt.username == "root"


def test_log_event_ip_and_port_validation() -> None:
    """Test that invalid IP strings and port numbers are sanitized to None."""
    evt = LogEvent(
        source_ip="invalid-ip-string",
        destination_ip="999.999.999.999",
        source_port=99999,  # out of range
        destination_port=0,  # out of range
        raw_message="Test invalid network primitives",
    )
    assert evt.source_ip is None
    assert evt.destination_ip is None
    assert evt.source_port is None
    assert evt.destination_port is None


def test_log_event_raw_message_crlf_defense() -> None:
    """Verify that embedded CRLF in raw_message is cleaned during model validation."""
    evt = LogEvent(
        raw_message="GET /index.php HTTP/1.1\r\nInjected-Header: evil\n",
    )
    assert "\r" not in evt.raw_message
    assert "\n" not in evt.raw_message


def test_incident_creation_and_mitre_mapping() -> None:
    """Test Incident instantiation and MITRE ATT&CK association."""
    now = datetime.now(UTC)
    incident = Incident(
        title="SSH Brute Force Detected",
        description="Multiple failed SSH login attempts from 203.0.113.15",
        severity="HIGH",
        mitre=MITRE_BRUTE_FORCE,
        attacker_ip="203.0.113.15",
        target_user="root",
        first_seen=now,
        last_seen=now,
        event_count=8,
        evidence_samples=["Failed password for root from 203.0.113.15"],
        confidence_score=0.95,
        recommended_action="Block IP 203.0.113.15 at host firewall.",
    )

    assert incident.id.startswith("inc-")
    assert incident.mitre is not None
    assert incident.mitre.technique_id == "T1110"
    assert incident.mitre.name == "Brute Force"
    assert incident.mitre.tactic == "Credential Access"
    assert incident.event_count == 8
    assert incident.confidence_score == 0.95


def test_mitre_predefined_techniques() -> None:
    """Verify predefined MITRE taxonomy constants."""
    assert MITRE_WEB_EXPLOIT.technique_id == "T1190"
    assert MITRE_PORT_SCAN.technique_id == "T1046"
    assert MITRE_PRIV_ESC.technique_id == "T1548.003"

    custom = MITRETechnique(
        technique_id="T1078",
        name="Valid Accounts",
        tactic="Initial Access",
    )
    assert custom.technique_id == "T1078"
