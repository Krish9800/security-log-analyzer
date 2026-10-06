from pathlib import Path

import pytest

from loganalyzer.parsers.auth_parser import AuthLogParser
from loganalyzer.parsers.firewall_parser import FirewallLogParser
from loganalyzer.parsers.json_parser import JsonLogParser
from loganalyzer.parsers.registry import default_registry
from loganalyzer.parsers.web_parser import WebLogParser


def test_auth_parser_ssh_failed() -> None:
    """Test parsing Linux SSH authentication failure."""
    parser = AuthLogParser()
    line = (
        "Oct  6 14:30:00 srv-prod sshd[12345]: Failed password for invalid user admin "
        "from 192.168.1.100 port 45678 ssh2"
    )
    assert parser.can_parse(line) is True
    evt = parser.parse_line(line)
    assert evt is not None
    assert evt.event_type == "AUTH_FAILED"
    assert evt.severity == "HIGH"
    assert evt.source_ip == "192.168.1.100"
    assert evt.source_port == 45678
    assert evt.destination_port == 22
    assert evt.username == "admin"
    assert evt.action == "DENY"


def test_auth_parser_ssh_accepted() -> None:
    """Test parsing successful SSH authentication."""
    parser = AuthLogParser()
    line = (
        "Oct  6 14:31:00 srv-prod sshd[12346]: Accepted publickey for alice "
        "from 10.0.0.5 port 55123 ssh2"
    )
    evt = parser.parse_line(line)
    assert evt is not None
    assert evt.event_type == "AUTH_LOGIN"
    assert evt.severity == "INFORMATIONAL"
    assert evt.source_ip == "10.0.0.5"
    assert evt.username == "alice"
    assert evt.action == "ALLOW"


def test_auth_parser_sudo_exec() -> None:
    """Test parsing sudo privilege elevation command."""
    parser = AuthLogParser()
    line = (
        "Oct  6 14:32:00 srv-prod sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; "
        "USER=root ; COMMAND=/bin/bash"
    )
    evt = parser.parse_line(line)
    assert evt is not None
    assert evt.event_type == "SUDO_EXEC"
    assert evt.username == "alice"
    assert evt.metadata["target_user"] == "root"
    assert evt.metadata["command"] == "/bin/bash"


def test_web_parser_combined_requests() -> None:
    """Test parsing Nginx/Apache Combined access log lines."""
    parser = WebLogParser()

    # 200 OK
    line_ok = (
        '192.168.1.50 - frank [06/Oct/2026:14:30:00 +0000] "GET /api/v1/users HTTP/1.1" '
        '200 4521 "https://example.com" "Mozilla/5.0"'
    )
    assert parser.can_parse(line_ok) is True
    evt_ok = parser.parse_line(line_ok)
    assert evt_ok is not None
    assert evt_ok.event_type == "HTTP_REQUEST"
    assert evt_ok.severity == "INFORMATIONAL"
    assert evt_ok.source_ip == "192.168.1.50"
    assert evt_ok.username == "frank"
    assert evt_ok.http_method == "GET"
    assert evt_ok.http_uri == "/api/v1/users"
    assert evt_ok.http_status == 200

    # 401 Unauthorized
    line_unauth = (
        '203.0.113.10 - - [06/Oct/2026:14:32:00 +0000] "POST /login HTTP/1.1" '
        '401 230 "-" "curl/7.81.0"'
    )
    evt_unauth = parser.parse_line(line_unauth)
    assert evt_unauth is not None
    assert evt_unauth.http_status == 401
    assert evt_unauth.severity == "MEDIUM"
    assert evt_unauth.username is None


def test_firewall_parser_iptables_drop() -> None:
    """Test parsing Linux iptables kernel packet drops."""
    parser = FirewallLogParser()
    line = (
        "Oct  6 14:35:00 fw-node kernel: [IPTABLES-DROP]: IN=eth0 OUT= "
        "SRC=198.51.100.44 DST=192.168.1.1 PROTO=TCP SPT=49152 DPT=22"
    )
    assert parser.can_parse(line) is True
    evt = parser.parse_line(line)
    assert evt is not None
    assert evt.event_type == "FIREWALL_DROP"
    assert evt.severity == "MEDIUM"
    assert evt.source_ip == "198.51.100.44"
    assert evt.destination_ip == "192.168.1.1"
    assert evt.protocol == "TCP"
    assert evt.source_port == 49152
    assert evt.destination_port == 22
    assert evt.action == "DROP"


def test_json_parser_structured_log() -> None:
    """Test parsing ECS and generic JSON formatted log entries."""
    parser = JsonLogParser()
    line = (
        '{"timestamp": "2026-10-06T14:30:00Z", "source_ip": "10.0.0.50", '
        '"destination_port": 443, "type": "AUTH_FAILED", "username": "bob", "severity": "HIGH"}'
    )
    assert parser.can_parse(line) is True
    evt = parser.parse_line(line)
    assert evt is not None
    assert evt.event_type == "AUTH_FAILED"
    assert evt.severity == "HIGH"
    assert evt.source_ip == "10.0.0.50"
    assert evt.destination_port == 443
    assert evt.username == "bob"

    # Malformed JSON
    assert parser.parse_line("{invalid-json-payload") is None


def test_parser_registry_stream_and_fallback(tmp_path: Path) -> None:
    """Test ParserRegistry auto-detection, stream parsing, and file ingestion."""
    registry = default_registry

    lines = [
        "Oct  6 14:30:00 host sshd[1]: Failed password for root from 192.168.1.5 port 2222 ssh2",
        '10.0.0.1 - - [06/Oct/2026:14:31:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "-"',
        "Oct  6 14:32:00 host kernel: SRC=1.1.1.1 DST=2.2.2.2 PROTO=TCP SPT=10 DPT=80",
        '{"event_type": "AUTH_LOGIN", "user": "alice", "source_ip": "10.0.0.2"}',
        "Unknown unformatted arbitrary system message line",
    ]

    events = list(registry.parse_stream(lines))
    assert len(events) == 5
    assert events[0].event_type == "AUTH_FAILED"
    assert events[1].event_type == "HTTP_REQUEST"
    assert events[2].event_type == "FIREWALL_ACCEPT"
    assert events[3].event_type == "AUTH_LOGIN"
    assert events[4].event_type == "GENERIC_EVENT"

    # Test file parsing
    test_file = tmp_path / "sample.log"
    test_file.write_text("\n".join(lines), encoding="utf-8")

    file_events = registry.parse_file(test_file)
    assert len(file_events) == 5

    with pytest.raises(FileNotFoundError):
        registry.parse_file("non_existent_file_path.log")
