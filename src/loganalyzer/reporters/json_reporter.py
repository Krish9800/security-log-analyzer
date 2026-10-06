"""Structured JSON report exporter."""

from loganalyzer.analytics.correlator import ForensicAnalysisReport


def export_json_report(report: ForensicAnalysisReport, indent: int = 2) -> str:
    """Serialize ForensicAnalysisReport to indented JSON format."""
    return report.model_dump_json(indent=indent)
