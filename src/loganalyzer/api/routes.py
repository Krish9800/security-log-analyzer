"""REST API endpoints for log analysis and forensic exports."""

from typing import Any

from fastapi import APIRouter, Query, status

from loganalyzer.analytics.correlator import ForensicCorrelator
from loganalyzer.api.schemas import (
    AnalyzeRawLogsRequest,
    AnalyzeResponse,
    ExportReportResponse,
    HealthResponse,
)
from loganalyzer.config.settings import settings
from loganalyzer.detectors.engine import default_engine
from loganalyzer.parsers.registry import default_registry
from loganalyzer.reporters.cef_reporter import export_incidents_cef
from loganalyzer.reporters.json_reporter import export_json_report
from loganalyzer.reporters.markdown_reporter import export_markdown_report

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Return system health and active detection rules."""
    return HealthResponse(
        status="ok",
        version=settings.app_version,
        active_rules_count=len(default_engine._rules),
    )


@router.get("/api/v1/rules", response_model=list[dict[str, Any]])
def list_rules() -> list[dict[str, Any]]:
    """List all registered threat detection rules and their MITRE mappings."""
    return [
        {
            "rule_id": rule.rule_id,
            "name": rule.name,
            "mitre_technique": rule.mitre.technique_id if rule.mitre else None,
            "mitre_tactic": rule.mitre.tactic if rule.mitre else None,
        }
        for rule in default_engine._rules
    ]


@router.post(
    "/api/v1/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
)
def analyze_logs(req: AnalyzeRawLogsRequest) -> AnalyzeResponse:
    """Ingest and analyze raw log lines for threats and suspicious patterns."""
    events = list(default_registry.parse_stream(req.lines))
    incidents = default_engine.analyze_stream(events)

    sev_rank = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    min_rank = sev_rank.get(req.min_severity or "INFORMATIONAL", 0)
    filtered = [inc for inc in incidents if sev_rank.get(inc.severity, 0) >= min_rank]

    report = ForensicCorrelator.correlate(events, filtered)

    top_ips = [p.attacker_ip for p in report.attacker_profiles[:5]]

    return AnalyzeResponse(
        total_events=report.statistics.total_events,
        incident_count=len(filtered),
        incidents=filtered,
        top_attacker_ips=top_ips,
        report_sha256=report.report_sha256,
    )


@router.post(
    "/api/v1/analyze/export",
    response_model=ExportReportResponse,
    status_code=status.HTTP_200_OK,
)
def export_analysis(
    req: AnalyzeRawLogsRequest,
    format_type: str = Query(
        "json",
        alias="format",
        pattern="^(json|markdown|cef)$",
        description="Target export format",
    ),
) -> ExportReportResponse:
    """Analyze raw logs and export report in JSON, Markdown, or CEF format."""
    events = list(default_registry.parse_stream(req.lines))
    incidents = default_engine.analyze_stream(events)

    sev_rank = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    min_rank = sev_rank.get(req.min_severity or "INFORMATIONAL", 0)
    filtered = [inc for inc in incidents if sev_rank.get(inc.severity, 0) >= min_rank]

    report = ForensicCorrelator.correlate(events, filtered)

    content: str
    if format_type == "json":
        content = export_json_report(report)
    elif format_type == "markdown":
        content = export_markdown_report(report)
    else:  # cef
        content = export_incidents_cef(filtered)

    return ExportReportResponse(
        format=format_type,
        content=content,
        report=report if format_type == "json" else None,
    )
