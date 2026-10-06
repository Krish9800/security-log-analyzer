"""Unit tests for Phase 1 foundation: settings, sanitizers, and redaction."""

from datetime import UTC, datetime

from loganalyzer.config.settings import LogAnalyzerSettings, settings
from loganalyzer.core.sanitizer import (
    is_private_ip,
    parse_utc_timestamp,
    redact_sensitive_data,
    sanitize_ip_or_none,
    sanitize_log_line,
    sanitize_port_or_none,
)


def test_settings_initialization() -> None:
    """Verify default settings configuration."""
    assert settings.app_name == "Security Log Analyzer"
    assert settings.brute_force_threshold == 5
    assert settings.brute_force_window_seconds == 60
    assert settings.port_scan_threshold == 10
    assert settings.max_log_line_length == 65536
    assert settings.redact_credentials is True


def test_custom_settings_instance() -> None:
    """Test custom configuration instantiate with overrides."""
    custom = LogAnalyzerSettings(
        brute_force_threshold=10,
        brute_force_window_seconds=120,
        environment="test",
    )
    assert custom.brute_force_threshold == 10
    assert custom.brute_force_window_seconds == 120
    assert custom.environment == "test"


def test_sanitize_log_line_crlf_defense() -> None:
    """Verify defense against CRLF injection and log forging."""
    # Embedded CRLF
    injected = "admin login failed\r\nOct 06 12:00:00 root login SUCCESS\n"
    cleaned = sanitize_log_line(injected)
    assert "\r" not in cleaned
    assert "\n" not in cleaned
    assert "admin login failed  Oct 06 12:00:00 root login SUCCESS" in cleaned

    # Null bytes
    null_payload = "GET /index.php\0.jpg HTTP/1.1\r\n"
    assert "\0" not in sanitize_log_line(null_payload)

    # Empty
    assert sanitize_log_line("") == ""

    # Length truncation
    long_line = "A" * 100
    assert len(sanitize_log_line(long_line, max_length=20)) == 20


def test_redact_sensitive_data() -> None:
    """Test redacting passwords, tokens, and secrets."""
    msg = "User alice failed auth: password=supersecret123 and token: my_secret_token"
    redacted = redact_sensitive_data(msg)
    assert "supersecret123" not in redacted
    assert "my_secret_token" not in redacted
    assert "password=[REDACTED]" in redacted
    assert "token:[REDACTED]" in redacted

    # Empty message
    assert redact_sensitive_data("") == ""


def test_sanitize_ip_or_none() -> None:
    """Test IPv4, IPv6, port-stripped normalization, and malformed rejection."""
    assert sanitize_ip_or_none("192.168.1.100") == "192.168.1.100"
    assert sanitize_ip_or_none("192.168.1.100:8080") == "192.168.1.100"
    assert sanitize_ip_or_none("10.0.0.1") == "10.0.0.1"
    assert sanitize_ip_or_none("::1") == "::1"
    assert sanitize_ip_or_none("[2001:db8::1]:443") == "2001:db8::1"

    # Invalid IPs
    assert sanitize_ip_or_none("999.999.999.999") is None
    assert sanitize_ip_or_none("not-an-ip") is None
    assert sanitize_ip_or_none(None) is None
    assert sanitize_ip_or_none("") is None


def test_is_private_ip() -> None:
    """Test detection of private and loopback addresses."""
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("10.0.0.5") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("::1") is True

    # Public IP
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False

    # Invalid string
    assert is_private_ip("invalid") is False


def test_sanitize_port_or_none() -> None:
    """Test TCP/UDP port range bounds."""
    assert sanitize_port_or_none(80) == 80
    assert sanitize_port_or_none("443") == 443
    assert sanitize_port_or_none("65535") == 65535
    assert sanitize_port_or_none("1") == 1

    # Out of range or non-integer
    assert sanitize_port_or_none(0) is None
    assert sanitize_port_or_none(65536) is None
    assert sanitize_port_or_none(-1) is None
    assert sanitize_port_or_none("abc") is None
    assert sanitize_port_or_none(None) is None


def test_parse_utc_timestamp() -> None:
    """Test heterogeneous timestamp parsing."""
    # ISO 8601
    dt_iso = parse_utc_timestamp("2026-10-06T14:30:00Z")
    assert dt_iso.year == 2026
    assert dt_iso.month == 10
    assert dt_iso.day == 6
    assert dt_iso.tzinfo == UTC

    # Syslog
    dt_syslog = parse_utc_timestamp("Oct  6 14:30:00")
    assert dt_syslog.month == 10
    assert dt_syslog.day == 6
    assert dt_syslog.hour == 14
    assert dt_syslog.tzinfo == UTC

    # Combined
    dt_comb = parse_utc_timestamp("06/Oct/2026:14:30:00 +0000")
    assert dt_comb.year == 2026
    assert dt_comb.month == 10
    assert dt_comb.day == 6

    # Epoch timestamp
    dt_epoch = parse_utc_timestamp("1760000000")
    assert isinstance(dt_epoch, datetime)
    assert dt_epoch.tzinfo == UTC

    # Fallback to now
    dt_fallback = parse_utc_timestamp(None)
    assert isinstance(dt_fallback, datetime)
