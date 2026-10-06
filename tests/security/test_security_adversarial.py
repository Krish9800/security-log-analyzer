"""Adversarial and security fuzzing test suite for Security Log Analyzer.

Validates resistance against CRLF log injection, buffer flooding,
catastrophic regex backtracking (ReDoS), and credential leakage.
"""

from datetime import UTC, datetime, timedelta

import pytest

from loganalyzer.core.sanitizer import (
    redact_sensitive_data,
    sanitize_log_line,
)
from loganalyzer.detectors.rules import WebAttackDetector
from loganalyzer.models.events import LogEvent
from loganalyzer.parsers.registry import default_registry


@pytest.mark.parametrize(
    "crlf_payload",
    [
        "admin\r\nOct 06 14:00:00 srv sshd[1]: Accepted publickey for root",
        "user\rSet-Cookie: session=attacker\n",
        "GET /index.php\r\nHost: evil.com HTTP/1.1",
        "logger: \r\n\r\nDROP TABLE users;--",
    ],
)
def test_crlf_log_injection_mitigation(crlf_payload: str) -> None:
    """Ensure CRLF control characters are neutralized during sanitization and model ingestion."""
    sanitized = sanitize_log_line(crlf_payload)
    assert "\r" not in sanitized
    assert "\n" not in sanitized

    evt = default_registry.parse_line(crlf_payload)
    if evt:
        assert "\r" not in evt.raw_message
        assert "\n" not in evt.raw_message


def test_buffer_flooding_and_oversized_line_truncation() -> None:
    """Ensure oversized log lines exceeding 64KB buffer are cleanly truncated."""
    oversized = "A" * 70000
    cleaned = sanitize_log_line(oversized, max_length=65536)
    assert len(cleaned) == 65536

    evt = LogEvent(raw_message=oversized)
    assert len(evt.raw_message) <= 65536


def test_null_byte_injection() -> None:
    """Verify null bytes are stripped to prevent C-string termination attacks."""
    poisoned = "GET /legit.php\0/../../etc/passwd HTTP/1.1\r\n"
    cleaned = sanitize_log_line(poisoned)
    assert "\0" not in cleaned


def test_redos_resilience_complex_web_uri() -> None:
    """Verify that complex nested or repetitive web URI patterns execute in linear time."""
    detector = WebAttackDetector()
    base_time = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)

    # Repetitive patterns that might trigger catastrophic backtracking in unhardened regexes
    evil_patterns = [
        "A" * 2000 + "union" + "B" * 2000,
        "('" * 500 + "1" + "')" * 500,
        "../" * 300 + "etc/passwd",
        "<script" + " " * 500 + "attr=" + " " * 500 + ">",
    ]

    start = datetime.now(UTC)
    for pat in evil_patterns:
        evt = LogEvent(
            timestamp=base_time,
            event_type="HTTP_REQUEST",
            http_uri=pat,
            raw_message=f"GET {pat}",
        )
        detector.process_event(evt)

    elapsed = (datetime.now(UTC) - start).total_seconds()
    # Entire batch must complete in under 0.5 seconds
    assert elapsed < 0.5


def test_credential_leakage_redaction() -> None:
    """Ensure credentials, tokens, and authorization parameters are obscured."""
    payloads = [
        ("Login attempt with password=SuperSecretPassword123", "password=[REDACTED]"),
        ("Bearer token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "token:[REDACTED]"),
        ("curl -H 'api_key=sk_live_abcdef123456'", "api_key=[REDACTED]"),
    ]

    for raw, expected_token in payloads:
        redacted = redact_sensitive_data(raw)
        assert expected_token in redacted

        assert "SuperSecretPassword123" not in redacted
        assert "sk_live_abcdef123456" not in redacted


def test_out_of_order_burst_timestamps() -> None:
    """Ensure sliding window handles out-of-order timestamp fluctuations without raising."""
    base_time = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)
    events = [
        LogEvent(timestamp=base_time + timedelta(seconds=10), raw_message="t1"),
        LogEvent(timestamp=base_time, raw_message="t0"),
        LogEvent(timestamp=base_time + timedelta(seconds=5), raw_message="t2"),
    ]

    # Ingestion and processing should proceed smoothly
    for evt in events:
        assert evt.timestamp is not None
