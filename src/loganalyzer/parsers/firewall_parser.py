"""Linux iptables and nftables firewall log parser."""

import re

from loganalyzer.core.sanitizer import parse_utc_timestamp, sanitize_log_line
from loganalyzer.models.events import EventType, LogEvent, Severity
from loganalyzer.parsers.base import BaseLogParser

# Extraction patterns for key-value kernel firewall tokens
SRC_REGEX = re.compile(r"\bSRC=([0-9a-fA-F.:]+)\b")
DST_REGEX = re.compile(r"\bDST=([0-9a-fA-F.:]+)\b")
PROTO_REGEX = re.compile(r"\bPROTO=(\w+)\b")
SPT_REGEX = re.compile(r"\bSPT=(\d+)\b")
DPT_REGEX = re.compile(r"\bDPT=(\d+)\b")
IN_REGEX = re.compile(r"\bIN=(\S*)\b")
OUT_REGEX = re.compile(r"\bOUT=(\S*)\b")
SYSLOG_TS_PREFIX = re.compile(r"^([A-Z][a-z]{2}\s+[0-9]{1,2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2})")


class FirewallLogParser(BaseLogParser):
    """Parser for Linux iptables/nftables kernel packet filter logs."""

    @property
    def source_name(self) -> str:
        return "iptables"

    def can_parse(self, line: str) -> bool:
        """Heuristic check for kernel packet filter markers."""
        if not line:
            return False
        return bool("SRC=" in line and "DST=" in line and "PROTO=" in line)

    def parse_line(self, line: str) -> LogEvent | None:
        """Parse kernel firewall log line into canonical LogEvent."""
        cleaned = sanitize_log_line(line)
        if not cleaned:
            return None

        m_src = SRC_REGEX.search(cleaned)
        m_dst = DST_REGEX.search(cleaned)
        m_proto = PROTO_REGEX.search(cleaned)

        if not (m_src and m_dst and m_proto):
            return None

        src_ip = m_src.group(1)
        dst_ip = m_dst.group(1)
        protocol = m_proto.group(1).upper()

        m_spt = SPT_REGEX.search(cleaned)
        src_port = int(m_spt.group(1)) if m_spt else None

        m_dpt = DPT_REGEX.search(cleaned)
        dst_port = int(m_dpt.group(1)) if m_dpt else None

        m_in = IN_REGEX.search(cleaned)
        in_iface = m_in.group(1) if m_in else None

        m_out = OUT_REGEX.search(cleaned)
        out_iface = m_out.group(1) if m_out else None

        # Check timestamp if present in syslog prefix
        m_ts = SYSLOG_TS_PREFIX.match(cleaned)
        timestamp = parse_utc_timestamp(m_ts.group(1)) if m_ts else parse_utc_timestamp(None)

        # Check action / severity heuristic
        is_drop = "DROP" in cleaned.upper() or "REJECT" in cleaned.upper()
        event_type: EventType = "FIREWALL_DROP" if is_drop else "FIREWALL_ACCEPT"
        action = "DROP" if is_drop else "ACCEPT"
        severity: Severity = "MEDIUM" if is_drop else "INFORMATIONAL"

        metadata = {
            "interface_in": in_iface if in_iface else None,
            "interface_out": out_iface if out_iface else None,
        }

        return LogEvent(
            timestamp=timestamp,
            source_type=self.source_name,
            event_type=event_type,
            severity=severity,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol=protocol,
            action=action,
            raw_message=cleaned,
            metadata=metadata,
        )
