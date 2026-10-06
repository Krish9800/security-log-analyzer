"""Canonical security log event schema with normalization and validation."""

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from loganalyzer.core.sanitizer import (
    sanitize_ip_or_none,
    sanitize_log_line,
    sanitize_port_or_none,
)

EventType = Literal[
    "AUTH_LOGIN",
    "AUTH_FAILED",
    "SUDO_EXEC",
    "HTTP_REQUEST",
    "FIREWALL_DROP",
    "FIREWALL_ACCEPT",
    "GENERIC_EVENT",
]

Severity = Literal["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class LogEvent(BaseModel):
    """Normalized, canonical representation of a security log entry."""

    id: str = Field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source_type: str = Field(
        default="generic",
        description="Origin log source type (e.g. auth_log, nginx, iptables, json_ecs)",
    )
    event_type: EventType = Field(default="GENERIC_EVENT")
    severity: Severity = Field(default="INFORMATIONAL")

    # Network Primitives
    source_ip: str | None = Field(default=None, description="Client/Source IPv4 or IPv6")
    destination_ip: str | None = Field(default=None, description="Target/Destination IPv4 or IPv6")
    source_port: int | None = Field(default=None, ge=1, le=65535)
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | None = Field(default=None, description="Transport protocol (TCP, UDP, ICMP)")

    # Identity & Access
    username: str | None = Field(default=None, max_length=128)
    action: str | None = Field(
        default=None, description="Outcome action (e.g., ACCEPT, DROP, ALLOW, DENY)"
    )

    # Web Context
    http_method: str | None = Field(
        default=None, description="HTTP verb (e.g., GET, POST, PUT, DELETE)"
    )
    http_uri: str | None = Field(default=None, description="Requested URI path")
    http_status: int | None = Field(default=None, ge=100, le=599)
    user_agent: str | None = Field(default=None, max_length=512)

    # Raw Payload & Extended Metadata
    raw_message: str = Field(..., description="Original raw line before normalization")
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("source_ip", "destination_ip", mode="before")
    @classmethod
    def validate_ips(cls, v: str | None) -> str | None:
        """Validate and normalize IP address."""
        return sanitize_ip_or_none(v)

    @field_validator("source_port", "destination_port", mode="before")
    @classmethod
    def validate_ports(cls, v: int | str | None) -> int | None:
        """Validate TCP/UDP port bounds."""
        return sanitize_port_or_none(v)

    @field_validator("raw_message", mode="before")
    @classmethod
    def validate_raw(cls, v: str) -> str:
        """Sanitize raw log message against CRLF injection and null bytes."""
        return sanitize_log_line(v)
