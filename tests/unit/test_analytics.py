"""Unit tests for Phase 6: MITRE ATT&CK & Forensic Analytics."""

from datetime import UTC, datetime, timedelta

from loganalyzer.analytics.correlator import ForensicCorrelator
from loganalyzer.analytics.mitre_mapper import MitreAnalytics
from loganalyzer.analytics.statistics import LogStatisticsCalculator
from loganalyzer.models.events import LogEvent
from loganalyzer.models.incidents import (
    MITRE_BRUTE_FORCE,
    MITRE_WEB_EXPLOIT,
    Incident,
)


def test_statistics_calculator() -> None:
    """Test statistics and top-N calculation over log event samples."""
    base_time = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)

    events = [
        LogEvent(
            timestamp=base_time,
            event_type="HTTP_REQUEST",
            severity="INFORMATIONAL",
            source_ip="192.168.1.10",
            destination_port=80,
            protocol="TCP",
            http_uri="/index.html",
            raw_message="GET /index.html",
        ),
        LogEvent(
            timestamp=base_time + timedelta(seconds=1),
            event_type="HTTP_REQUEST",
            severity="HIGH",
            source_ip="8.8.8.8",
            destination_port=443,
            protocol="TCP",
            http_uri="/admin",
            raw_message="GET /admin",
        ),
        LogEvent(
            timestamp=base_time + timedelta(seconds=2),
            event_type="AUTH_FAILED",
            severity="HIGH",
            source_ip="8.8.8.8",
            destination_port=22,
            protocol="TCP",
            username="root",
            raw_message="Failed login",
        ),
    ]

    stats = LogStatisticsCalculator.compute(events, top_n=5)
    assert stats.total_events == 3
    assert stats.events_by_type["HTTP_REQUEST"] == 2
    assert stats.events_by_type["AUTH_FAILED"] == 1
    assert stats.events_by_severity["HIGH"] == 2
    assert stats.private_ip_event_count == 1  # 192.168.1.10
    assert stats.public_ip_event_count == 2  # 8.8.8.8 twice

    top_ips = dict(stats.top_source_ips)
    assert top_ips["8.8.8.8"] == 2
    assert top_ips["192.168.1.10"] == 1


def test_mitre_coverage_analytics() -> None:
    """Test MITRE ATT&CK tactic grouping and technique frequency."""
    now = datetime.now(UTC)
    incidents = [
        Incident(
            title="Web Attack",
            description="SQLi detected",
            severity="CRITICAL",
            mitre=MITRE_WEB_EXPLOIT,
            first_seen=now,
            last_seen=now,
        ),
        Incident(
            title="SSH Brute Force",
            description="Brute force detected",
            severity="HIGH",
            mitre=MITRE_BRUTE_FORCE,
            first_seen=now,
            last_seen=now,
        ),
    ]

    report = MitreAnalytics.generate_report(incidents)
    assert report.total_tagged_incidents == 2
    assert "Initial Access" in report.tactics_observed
    assert "Credential Access" in report.tactics_observed
    assert "T1190" in report.tactic_summaries["Initial Access"].technique_ids
    assert "T1110" in report.tactic_summaries["Credential Access"].technique_ids


def test_forensic_correlator_attacker_profiles() -> None:
    """Test multi-stage correlation, attacker risk scoring, and report fingerprint."""
    base_time = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)

    events = [
        LogEvent(
            timestamp=base_time,
            event_type="HTTP_REQUEST",
            source_ip="198.51.100.77",
            raw_message="event 1",
        ),
    ]

    incidents = [
        # Stage 1: Initial web attack
        Incident(
            title="Web Exploit Attempt",
            description="SQLi probe",
            severity="CRITICAL",
            mitre=MITRE_WEB_EXPLOIT,
            attacker_ip="198.51.100.77",
            first_seen=base_time,
            last_seen=base_time + timedelta(seconds=10),
        ),
        # Stage 2: Credential brute force
        Incident(
            title="SSH Brute Force",
            description="Failed logins",
            severity="HIGH",
            mitre=MITRE_BRUTE_FORCE,
            attacker_ip="198.51.100.77",
            target_user="admin",
            first_seen=base_time + timedelta(seconds=30),
            last_seen=base_time + timedelta(seconds=60),
        ),
    ]

    report = ForensicCorrelator.correlate(events, incidents)
    assert len(report.attacker_profiles) == 1
    profile = report.attacker_profiles[0]
    assert profile.attacker_ip == "198.51.100.77"
    assert profile.incident_count == 2
    assert "Initial Access" in profile.mitre_tactics
    assert "Credential Access" in profile.mitre_tactics
    assert "admin" in profile.targeted_users
    assert profile.threat_score >= 50.0  # CRITICAL(30) + HIGH(20)
    assert profile.first_activity == base_time
    assert profile.last_activity == base_time + timedelta(seconds=60)
    assert len(report.report_sha256) == 64
