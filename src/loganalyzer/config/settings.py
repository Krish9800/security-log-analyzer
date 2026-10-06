"""Configuration management using Pydantic Settings."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class LogAnalyzerSettings(BaseSettings):
    """Central settings for forensic analysis and threat detection thresholds."""

    app_name: str = "Security Log Analyzer"
    app_version: str = "0.1.0"
    environment: str = Field(default="development", description="Environment mode")

    # Threat Detection Sliding Window Thresholds
    brute_force_threshold: int = Field(
        default=5,
        ge=2,
        le=1000,
        description="Number of failed authentications required to trigger a brute force incident",
    )
    brute_force_window_seconds: int = Field(
        default=60,
        ge=5,
        le=3600,
        description="Time window in seconds for correlating failed authentication attempts",
    )
    port_scan_threshold: int = Field(
        default=10,
        ge=3,
        le=10000,
        description="Number of distinct destination ports accessed from single IP to trigger alert",
    )
    port_scan_window_seconds: int = Field(
        default=120,
        ge=10,
        le=7200,
        description="Time window in seconds for port scanning reconnaissance",
    )

    # Memory and Buffer Boundaries
    max_log_line_length: int = Field(
        default=65536,
        ge=1024,
        le=1048576,
        description="Maximum permissible raw log line length in bytes to mitigate ReDoS/memory exhaustion",
    )
    max_active_tracking_buckets: int = Field(
        default=10000,
        ge=100,
        le=1000000,
        description="Maximum active entities tracked in memory before LRU eviction",
    )

    # Privacy & Defense
    redact_credentials: bool = Field(
        default=True,
        description="Automatically mask passwords, tokens, and authorization headers in forensic reports",
    )

    # API Server Configuration
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65535)

    model_config = SettingsConfigDict(
        env_prefix="SLA_",
        env_file=".env",
        extra="ignore",
    )


settings = LogAnalyzerSettings()
