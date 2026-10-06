"""Unit tests for Phase 7: Telemetry & Exporters (CEF, Markdown, JSON)."""

from datetime import UTC, datetime

from loganalyzer.analytics.correlator import ForensicCorrelator
from loganalyzer.models.events import LogEvent
from loganalyzer.models.incidents import MITRE_BRUTE_FORCE, Incident
from loganalyzer.reporters.cef_reporter import export_incident_cef, export_incidents_cef
from loganalyzer.reporters.json_reporter import export_json_report
from loganalyzer.reporters.markdown_reporter import export_markdown_report


def test_cef_reporter_formatting() -> None:
    """Test converting Incident to ArcSight CEF format with escaping."""
    now = datetime.now(UTC)
    incident = Incident(
        title="SSH Brute Force | Test",
        description="Observed failed password attempts; user=admin",
        severity="HIGH",
        mitre=MITRE_BRUTE_FORCE,
        attacker_ip="198.51.100.5",
        target_user="admin",
        first_seen=now,
        last_seen=now,
        event_count=5,
        confidence_score=0.95,
    )

    cef_line = export_incident_cef(incident)
    assert cef_line.startswith("CEF:0|SecurityLogAnalyzer|LogAnalyzer|0.1.0|INC-100|")
    assert "src=198.51.100.5" in cef_line
    assert "suser=admin" in cef_line
    assert "cs1=T1110" in cef_line
    assert "cs2=Brute Force" in cef_line
    assert "cs3=Credential Access" in cef_line
    assert "cn1=5" in cef_line

    # Test multi-line export
    multi = export_incidents_cef([incident, incident])
    assert multi.count("CEF:0") == 2


def test_markdown_and_json_report_export() -> None:
    """Test Markdown and JSON report exports."""
    now = datetime.now(UTC)
    events = [
        LogEvent(
            timestamp=now,
            event_type="AUTH_FAILED",
            source_ip="198.51.100.5",
            username="admin",
            raw_message="failed login",
        )
    ]
    incidents = [
        Incident(
            title="SSH Brute Force",
            description="5 failed attempts",
            severity="HIGH",
            mitre=MITRE_BRUTE_FORCE,
            attacker_ip="198.51.100.5",
            first_seen=now,
            last_seen=now,
        )
    ]

    report = ForensicCorrelator.correlate(events, incidents)

    # Test Markdown
    md_output = export_markdown_report(report)
    assert "# Security Log Forensic Investigation Report" in md_output
    assert "Total Events Processed" in md_output
    assert "Credential Access" in md_output
    assert "198.51.100.5" in md_output

    # Test JSON
    json_output = export_json_report(report)
    assert '"total_events": 1' in json_output
    assert '"report_sha256":' in json_output
    assert '"198.51.100.5"' in json_output
