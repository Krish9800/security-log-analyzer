"""Pydantic schemas for the REST API endpoints."""

from typing import Literal

from pydantic import BaseModel, Field

from loganalyzer.analytics.correlator import ForensicAnalysisReport
from loganalyzer.models.incidents import Incident


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "ok"
    version: str
    active_rules_count: int


class AnalyzeRawLogsRequest(BaseModel):
    """Request payload containing raw log lines for analysis."""

    lines: list[str] = Field(
        ..., min_length=1, max_length=10000, description="Raw log lines to ingest"
    )
    min_severity: Literal["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = Field(
        default="INFORMATIONAL", description="Minimum incident severity filter"
    )


class AnalyzeResponse(BaseModel):
    """Consolidated response of analyzed incidents and forensic metrics."""

    total_events: int
    incident_count: int
    incidents: list[Incident]
    top_attacker_ips: list[str]
    report_sha256: str


class ExportReportResponse(BaseModel):
    """Exported forensic analysis report in requested syntax."""

    format: str
    content: str
    report: ForensicAnalysisReport | None = None
