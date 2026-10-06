"""Input sanitization, CRLF injection defense, and credential redaction primitives."""

import ipaddress
import re
from datetime import UTC, datetime

# Regex for sensitive token/password redaction
REDACTION_PATTERN = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|bearer|token)\b\s*([:=])\s*([^\s,;\"']+)",
)

# Auth.log syslog timestamp: "Oct  6 14:30:00" or "Oct 06 14:30:00"
SYSLOG_TS_PATTERN = re.compile(
    r"^([A-Z][a-z]{2})\s+([0-9]{1,2})\s+([0-9]{2}):([0-9]{2}):([0-9]{2})"
)

# Nginx/Apache Combined timestamp: "06/Oct/2026:14:30:00 +0000"
COMBINED_TS_PATTERN = re.compile(
    r"^([0-9]{2})/([A-Z][a-z]{2})/([0-9]{4}):([0-9]{2}):([0-9]{2}):([0-9]{2})\s*([+-][0-9]{4})?"
)

MONTH_MAP = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def sanitize_log_line(raw_line: str, max_length: int = 65536) -> str:
    """Sanitize raw log line against CRLF injection, null bytes, and buffer overflow.

    - Strips external newline characters.
    - Replaces internal carriage returns and newlines with spaces to prevent log forging.
    - Removes null bytes (0x00).
    - Truncates lines exceeding max_length to protect regex engine and memory buffers.
    """
    if not raw_line:
        return ""

    # Truncate length
    truncated = raw_line[:max_length]

    # Remove null bytes
    cleaned = truncated.replace("\0", "")

    # Strip trailing and leading boundary whitespace/newlines
    cleaned = cleaned.rstrip("\r\n")

    # Replace embedded CRLF characters with space
    cleaned = cleaned.replace("\r", " ").replace("\n", " ")

    return cleaned


def redact_sensitive_data(message: str) -> str:
    """Mask credentials, tokens, and passwords in log messages."""
    if not message:
        return ""

    def _replace_cred(match: re.Match[str]) -> str:
        key = match.group(1)
        sep = match.group(2)
        return f"{key}{sep}[REDACTED]"

    return REDACTION_PATTERN.sub(_replace_cred, message)


def sanitize_ip_or_none(raw_ip: str | None) -> str | None:
    """Validate and normalize IPv4/IPv6 address or return None if malformed/unspecified."""
    if not raw_ip:
        return None

    cleaned = raw_ip.strip()
    # Strip potential port suffix (e.g., "192.168.1.1:8080" or "[::1]:443")
    if cleaned.startswith("[") and "]:" in cleaned:
        cleaned = cleaned[1 : cleaned.index("]:")]
    elif ":" in cleaned and "." in cleaned:
        # IPv4 with port: 192.168.1.1:54321
        parts = cleaned.split(":")
        if len(parts) == 2:
            cleaned = parts[0]

    try:
        addr = ipaddress.ip_address(cleaned)
        return str(addr)
    except ValueError:
        return None


def is_private_ip(ip_str: str) -> bool:
    """Determine whether an IP address is private, loopback, or reserved."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local
    except ValueError:
        return False


def sanitize_port_or_none(raw_port: str | int | None) -> int | None:
    """Validate integer port in valid TCP/UDP range (1-65535)."""
    if raw_port is None:
        return None

    try:
        port_num = int(raw_port)
        if 1 <= port_num <= 65535:
            return port_num
        return None
    except (ValueError, TypeError):
        return None


def parse_utc_timestamp(ts_str: str | None) -> datetime:
    """Parse heterogeneous log timestamp representations into timezone-aware UTC datetime."""
    now_utc = datetime.now(UTC)
    if not ts_str:
        return now_utc

    cleaned = ts_str.strip()

    # 1. ISO 8601 formats (e.g., 2026-10-06T14:30:00Z, 2026-10-06 14:30:00)
    try:
        dt = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except ValueError:
        pass

    # 2. Syslog / Auth format (e.g. "Oct  6 14:30:00" or "Oct 06 14:30:00")
    m_syslog = SYSLOG_TS_PATTERN.match(cleaned)
    if m_syslog:
        month_str, day_str, h_str, m_str, s_str = m_syslog.groups()
        month = MONTH_MAP.get(month_str, 1)
        day = int(day_str)
        hour = int(h_str)
        minute = int(m_str)
        second = int(s_str)
        year = now_utc.year
        try:
            return datetime(year, month, day, hour, minute, second, tzinfo=UTC)
        except ValueError:
            pass

    # 3. Apache/Nginx Combined format (e.g. "06/Oct/2026:14:30:00 +0000")
    m_combined = COMBINED_TS_PATTERN.match(cleaned)
    if m_combined:
        day_str, month_str, yr_str, h_str, m_str, s_str, tz_offset = m_combined.groups()
        month = MONTH_MAP.get(month_str, 1)
        day = int(day_str)
        year = int(yr_str)
        hour = int(h_str)
        minute = int(m_str)
        second = int(s_str)
        try:
            # We treat normalized standard as UTC
            return datetime(year, month, day, hour, minute, second, tzinfo=UTC)
        except ValueError:
            pass

    # 4. Epoch Unix seconds (e.g., "1791234567" or "1791234567.123")
    try:
        val = float(cleaned)
        if 0 < val < 253402300799:  # sensible unix timestamp bounds
            return datetime.fromtimestamp(val, tz=UTC)
    except ValueError:
        pass

    return now_utc
