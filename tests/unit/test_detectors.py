"""Unit tests for Phase 5 Threat Detection Rules and Engine."""

from datetime import UTC, datetime, timedelta

from loganalyzer.detectors.engine import DetectionEngine
from loganalyzer.detectors.rules import (
    BruteForceDetector,
    PortScanDetector,
    PrivilegeEscalationDetector,
    WebAttackDetector,
)
from loganalyzer.models.events import LogEvent


def test_brute_force_detection_trigger() -> None:
    """Test that brute force detector fires an incident upon reaching failure threshold."""
    detector = BruteForceDetector(threshold=3, window_seconds=60)
    base_time = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)

    incidents = []
    for i in range(3):
        evt = LogEvent(
            timestamp=base_time + timedelta(seconds=i * 5),
            event_type="AUTH_FAILED",
            source_ip="198.51.100.22",
            username="root",
            raw_message=f"Failed attempt {i + 1}",
        )
        inc = detector.process_event(evt)
        if inc:
            incidents.append(inc)

    assert len(incidents) == 1
    incident = incidents[0]
    assert "Brute Force Detected" in incident.title
    assert incident.attacker_ip == "198.51.100.22"
    assert incident.target_user == "root"
    assert incident.event_count == 3
    assert incident.mitre is not None
    assert incident.mitre.technique_id == "T1110"


def test_web_attack_detector_sqli_and_xss() -> None:
    """Test detecting SQL injection and XSS payloads in web URIs."""
    detector = WebAttackDetector()
    base_time = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)

    # SQL Injection
    evt_sqli = LogEvent(
        timestamp=base_time,
        event_type="HTTP_REQUEST",
        source_ip="203.0.113.88",
        http_method="GET",
        http_uri="/products?id=1%20UNION%20SELECT%20username,%20password%20FROM%20users",
        raw_message="GET /products?id=1 UNION SELECT ...",
    )
    inc_sqli = detector.process_event(evt_sqli)
    assert inc_sqli is not None
    assert "SQL Injection" in inc_sqli.title
    assert inc_sqli.severity == "CRITICAL"
    assert inc_sqli.mitre is not None
    assert inc_sqli.mitre.technique_id == "T1190"

    # Cross-Site Scripting (XSS)
    evt_xss = LogEvent(
        timestamp=base_time,
        event_type="HTTP_REQUEST",
        source_ip="203.0.113.89",
        http_method="POST",
        http_uri="/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
        raw_message="POST /search?q=<script>alert...",
    )
    inc_xss = detector.process_event(evt_xss)
    assert inc_xss is not None
    assert "Cross-Site Scripting" in inc_xss.title


def test_web_attack_detector_traversal_and_probe() -> None:
    """Test detecting path traversal and webshell probes."""
    detector = WebAttackDetector()
    base_time = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)

    # Path Traversal
    evt_lfi = LogEvent(
        timestamp=base_time,
        event_type="HTTP_REQUEST",
        source_ip="203.0.113.90",
        http_uri="/view?file=../../../../etc/passwd",
        raw_message="GET /view?file=../../../../etc/passwd",
    )
    inc_lfi = detector.process_event(evt_lfi)
    assert inc_lfi is not None
    assert "Path Traversal" in inc_lfi.title

    # Sensitive probe (/.env)
    evt_probe = LogEvent(
        timestamp=base_time,
        event_type="HTTP_REQUEST",
        source_ip="203.0.113.91",
        http_uri="/.env",
        raw_message="GET /.env",
    )
    inc_probe = detector.process_event(evt_probe)
    assert inc_probe is not None
    assert "Reconnaissance" in inc_probe.title


def test_port_scan_detection_trigger() -> None:
    """Test that port scan detector fires when distinct ports reach threshold."""
    detector = PortScanDetector(threshold=4, window_seconds=60)
    base_time = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)

    ports = [21, 22, 23, 80]
    incidents = []
    for i, port in enumerate(ports):
        evt = LogEvent(
            timestamp=base_time + timedelta(seconds=i),
            event_type="FIREWALL_DROP",
            source_ip="198.51.100.99",
            destination_port=port,
            raw_message=f"DROP port {port}",
        )
        inc = detector.process_event(evt)
        if inc:
            incidents.append(inc)

    assert len(incidents) == 1
    assert "Port Scan Reconnaissance" in incidents[0].title
    assert incidents[0].attacker_ip == "198.51.100.99"
    assert incidents[0].mitre is not None
    assert incidents[0].mitre.technique_id == "T1046"


def test_privilege_escalation_detection() -> None:
    """Test detecting high-risk sudo shell invocations."""
    detector = PrivilegeEscalationDetector()
    base_time = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)

    evt = LogEvent(
        timestamp=base_time,
        event_type="SUDO_EXEC",
        username="mallory",
        raw_message="mallory : TTY=pts/1 ; COMMAND=/bin/bash",
        metadata={"command": "/bin/bash"},
    )
    inc = detector.process_event(evt)
    assert inc is not None
    assert "High-Risk Sudo Command" in inc.title
    assert inc.target_user == "mallory"
    assert inc.mitre is not None
    assert inc.mitre.technique_id == "T1548.003"


def test_detection_engine_stream_processing() -> None:
    """Test DetectionEngine processing heterogeneous stream."""
    engine = DetectionEngine(register_defaults=True)
    base_time = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)

    events = [
        # Normal event
        LogEvent(
            timestamp=base_time,
            event_type="HTTP_REQUEST",
            http_uri="/index.html",
            raw_message="Normal web request",
        ),
        # Attack event (SQLi)
        LogEvent(
            timestamp=base_time + timedelta(seconds=1),
            event_type="HTTP_REQUEST",
            source_ip="10.0.0.1",
            http_uri="/login?user=' OR '1'='1",
            raw_message="SQLi attempt",
        ),
        # High risk sudo
        LogEvent(
            timestamp=base_time + timedelta(seconds=2),
            event_type="SUDO_EXEC",
            username="dev",
            raw_message="dev : TTY=pts/0 ; COMMAND=chmod 777 /etc/shadow",
            metadata={"command": "chmod 777 /etc/shadow"},
        ),
    ]

    incidents = engine.analyze_stream(events)
    assert len(incidents) == 2
    titles = [inc.title for inc in incidents]
    assert any("SQL Injection" in t for t in titles)
    assert any("High-Risk Sudo" in t for t in titles)
