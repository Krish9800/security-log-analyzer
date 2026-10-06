"""Linux auth.log and secure authentication log parser."""

import re

from loganalyzer.core.sanitizer import parse_utc_timestamp, sanitize_log_line
from loganalyzer.models.events import LogEvent
from loganalyzer.parsers.base import BaseLogParser

# Leading syslog timestamp & host header pattern
HEADER_REGEX = re.compile(
    r"^([A-Z][a-z]{2}\s+[0-9]{1,2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2})\s+(\S+)\s+([a-zA-Z0-9_\-\.]+)(?:\[\d+\])?:\s+(.*)$"
)

# SSH failed password
SSH_FAILED_REGEX = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([0-9a-fA-F.:]+) port (\d+) ssh2"
)

# SSH accepted password or publickey
SSH_ACCEPTED_REGEX = re.compile(
    r"Accepted (password|publickey) for (\S+) from ([0-9a-fA-F.:]+) port (\d+) ssh2"
)

# Sudo execution
SUDO_REGEX = re.compile(r"(\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)")

# PAM authentication failure
PAM_FAILED_REGEX = re.compile(
    r"pam_unix\(.*:auth\):\s+authentication failure;.*?(?:rhost=([0-9a-fA-F.:]+))?.*?user=(\S+)"
)


class AuthLogParser(BaseLogParser):
    """Parser for Linux /var/log/auth.log and /var/log/secure authentication events."""

    @property
    def source_name(self) -> str:
        return "auth_log"

    def can_parse(self, line: str) -> bool:
        """Check if line looks like Linux syslog / auth log."""
        if not line:
            return False
        return bool(
            "sshd[" in line
            or "sudo:" in line
            or "pam_unix" in line
            or "authentication failure" in line
            or "Failed password" in line
            or "Accepted password" in line
        )

    def parse_line(self, line: str) -> LogEvent | None:
        """Parse Linux auth.log line into canonical LogEvent."""
        cleaned = sanitize_log_line(line)
        if not cleaned:
            return None

        m_header = HEADER_REGEX.match(cleaned)
        if m_header:
            ts_raw, _hostname, daemon, message = m_header.groups()
            timestamp = parse_utc_timestamp(ts_raw)
        else:
            daemon = "auth"
            message = cleaned
            timestamp = parse_utc_timestamp(None)

        # 1. SSH Failed password
        m_failed = SSH_FAILED_REGEX.search(message)
        if m_failed:
            user, ip, port = m_failed.groups()
            return LogEvent(
                timestamp=timestamp,
                source_type=self.source_name,
                event_type="AUTH_FAILED",
                severity="HIGH",
                source_ip=ip,
                source_port=int(port),
                destination_port=22,
                protocol="TCP",
                username=user,
                action="DENY",
                raw_message=cleaned,
                metadata={"daemon": daemon, "auth_mechanism": "ssh_password"},
            )

        # 2. SSH Accepted password or publickey
        m_accepted = SSH_ACCEPTED_REGEX.search(message)
        if m_accepted:
            auth_type, user, ip, port = m_accepted.groups()
            return LogEvent(
                timestamp=timestamp,
                source_type=self.source_name,
                event_type="AUTH_LOGIN",
                severity="INFORMATIONAL",
                source_ip=ip,
                source_port=int(port),
                destination_port=22,
                protocol="TCP",
                username=user,
                action="ALLOW",
                raw_message=cleaned,
                metadata={"daemon": daemon, "auth_mechanism": auth_type},
            )

        # 3. Sudo execution
        m_sudo = SUDO_REGEX.search(message)
        if m_sudo:
            invoker, target_user, cmd = m_sudo.groups()
            return LogEvent(
                timestamp=timestamp,
                source_type=self.source_name,
                event_type="SUDO_EXEC",
                severity="LOW" if target_user != "root" else "MEDIUM",
                username=invoker,
                action="EXEC",
                raw_message=cleaned,
                metadata={"target_user": target_user, "command": cmd.strip()},
            )

        # 4. PAM authentication failure
        m_pam = PAM_FAILED_REGEX.search(message)
        if m_pam:
            rhost, user = m_pam.groups()
            return LogEvent(
                timestamp=timestamp,
                source_type=self.source_name,
                event_type="AUTH_FAILED",
                severity="HIGH",
                source_ip=rhost if rhost else None,
                username=user,
                action="DENY",
                raw_message=cleaned,
                metadata={"daemon": daemon, "auth_mechanism": "pam"},
            )

        # Generic auth event
        return LogEvent(
            timestamp=timestamp,
            source_type=self.source_name,
            event_type="GENERIC_EVENT",
            severity="INFORMATIONAL",
            raw_message=cleaned,
            metadata={"daemon": daemon},
        )
