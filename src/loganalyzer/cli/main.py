"""Command-line interface for Security Log Analyzer."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from loganalyzer.analytics.correlator import ForensicCorrelator
from loganalyzer.config.settings import settings
from loganalyzer.detectors.engine import default_engine
from loganalyzer.parsers.registry import default_registry
from loganalyzer.reporters.cef_reporter import export_incidents_cef
from loganalyzer.reporters.json_reporter import export_json_report
from loganalyzer.reporters.markdown_reporter import export_markdown_report

app = typer.Typer(
    name="log-analyzer",
    help="Multi-Format Security Log Forensic Parser, Sliding-Window Threat Correlator & MITRE ATT&CK Tagger",
    add_completion=False,
)
rules_app = typer.Typer(help="Inspect and configure detection rules")
app.add_typer(rules_app, name="rules")

console = Console()


def _format_severity_badge(sev: str) -> str:
    """Format severity text with Rich ANSI colors."""
    if sev == "CRITICAL":
        return "[bold white on red] CRITICAL [/bold white on red]"
    if sev == "HIGH":
        return "[bold red]HIGH[/bold red]"
    if sev == "MEDIUM":
        return "[bold yellow]MEDIUM[/bold yellow]"
    if sev == "LOW":
        return "[cyan]LOW[/cyan]"
    return "[dim]INFO[/dim]"


@app.command("version")
def version_cmd() -> None:
    """Display engine version, author, and threat detection thresholds."""
    panel_text = (
        f"[bold cyan]{settings.app_name}[/bold cyan] v{settings.app_version}\n"
        f"Environment: [green]{settings.environment}[/green]\n"
        f"Brute Force Threshold: {settings.brute_force_threshold} failures / {settings.brute_force_window_seconds}s\n"
        f"Port Scan Threshold: {settings.port_scan_threshold} distinct ports / {settings.port_scan_window_seconds}s\n"
        f"Credential Redaction: {'ENABLED' if settings.redact_credentials else 'DISABLED'}"
    )
    console.print(Panel(panel_text, title="System Information", expand=False))


@rules_app.command("list")
def list_rules_cmd() -> None:
    """List registered detection rules and their MITRE ATT&CK mappings."""
    table = Table(title="Registered Threat Detection Rules", show_header=True)
    table.add_column("Rule ID", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("MITRE Technique", style="magenta")
    table.add_column("MITRE Tactic", style="green")

    for rule in default_engine._rules:
        tech_id = rule.mitre.technique_id if rule.mitre else "N/A"
        tech_name = rule.mitre.name if rule.mitre else "N/A"
        tactic = rule.mitre.tactic if rule.mitre else "N/A"
        table.add_row(rule.rule_id, rule.name, f"{tech_id} ({tech_name})", tactic)

    console.print(table)


@app.command("inspect")
def inspect_cmd(
    log_file: Annotated[Path, typer.Argument(help="Path to raw log file for forensic inspection")],
    limit: Annotated[int, typer.Option("--limit", "-l", help="Number of records to display")] = 15,
) -> None:
    """Display raw ingested events and normalized canonical attributes."""
    if not log_file.is_file():
        console.print(f"[bold red]Error: Log file '{log_file}' does not exist.[/bold red]")
        raise typer.Exit(code=1)

    events = default_registry.parse_file(log_file)
    if not events:
        console.print("[yellow]No log events could be parsed from file.[/yellow]")
        return

    table = Table(
        title=f"Forensic Log Inspection ({min(limit, len(events))} of {len(events)} events)",
        show_header=True,
    )
    table.add_column("Timestamp", style="dim")
    table.add_column("Source", style="cyan")
    table.add_column("Type", style="bold")
    table.add_column("Severity")
    table.add_column("Source IP", style="green")
    table.add_column("Dst Port", style="magenta")
    table.add_column("User", style="yellow")

    for evt in events[:limit]:
        table.add_row(
            evt.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            evt.source_type,
            evt.event_type,
            _format_severity_badge(evt.severity),
            evt.source_ip or "-",
            str(evt.destination_port) if evt.destination_port else "-",
            evt.username or "-",
        )

    console.print(table)


@app.command("analyze")
def analyze_cmd(
    log_file: Annotated[Path, typer.Argument(help="Path to target log file for analysis")],
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Report output format: terminal (rich), json, markdown, cef",
        ),
    ] = "terminal",
    output_path: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Optional file destination to save report"),
    ] = None,
    min_severity: Annotated[
        str,
        typer.Option(
            "--min-severity",
            "-s",
            help="Filter incidents: INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL",
        ),
    ] = "INFORMATIONAL",
) -> None:
    """Execute complete forensic ingestion, threat correlation, and report export."""
    if not log_file.is_file():
        console.print(f"[bold red]Error: File '{log_file}' not found.[/bold red]")
        raise typer.Exit(code=1)

    events = default_registry.parse_file(log_file)
    incidents = default_engine.analyze_stream(events)

    # Filter incidents by minimum severity threshold
    sev_rank = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    min_rank = sev_rank.get(min_severity.upper(), 0)
    filtered_incidents = [inc for inc in incidents if sev_rank.get(inc.severity, 0) >= min_rank]

    report = ForensicCorrelator.correlate(events, filtered_incidents)

    # Format output
    rendered_text: str = ""
    if output_format.lower() == "json":
        rendered_text = export_json_report(report)
    elif output_format.lower() == "markdown":
        rendered_text = export_markdown_report(report)
    elif output_format.lower() == "cef":
        rendered_text = export_incidents_cef(filtered_incidents)
    else:  # terminal (rich)
        # 1. Summary Panel
        stats = report.statistics
        summary_body = (
            f"Events Processed: [bold]{stats.total_events:,}[/bold] | "
            f"Incidents Flagged: [bold red]{len(filtered_incidents)}[/bold red] | "
            f"Adversary IPs: [bold yellow]{len(report.attacker_profiles)}[/bold yellow]\n"
            f"Internal Traffic: {stats.private_ip_event_count} | External Ingress: {stats.public_ip_event_count}\n"
            f"Integrity Digest: [dim]{report.report_sha256[:24]}...[/dim]"
        )
        console.print(Panel(summary_body, title="Forensic Analysis Summary", expand=False))

        # 2. MITRE Matrix Table
        if report.mitre_report.tactic_summaries:
            mitre_table = Table(title="Observed MITRE ATT&CK Tactics", show_header=True)
            mitre_table.add_column("Tactic", style="green")
            mitre_table.add_column("Technique IDs", style="magenta")
            mitre_table.add_column("Incidents", justify="right")
            for t_name, t_sum in report.mitre_report.tactic_summaries.items():
                mitre_table.add_row(
                    t_name, ", ".join(t_sum.technique_ids), str(t_sum.incident_count)
                )
            console.print(mitre_table)

        # 3. Incidents Table
        if filtered_incidents:
            inc_table = Table(title="Correlated Security Incidents", show_header=True)
            inc_table.add_column("Severity")
            inc_table.add_column("Title", style="bold")
            inc_table.add_column("Attacker IP", style="cyan")
            inc_table.add_column("Target User", style="yellow")
            inc_table.add_column("MITRE", style="magenta")

            for inc in filtered_incidents:
                mitre_str = inc.mitre.technique_id if inc.mitre else "-"
                inc_table.add_row(
                    _format_severity_badge(inc.severity),
                    inc.title,
                    inc.attacker_ip or "-",
                    inc.target_user or "-",
                    mitre_str,
                )
            console.print(inc_table)
        else:
            console.print("[green]No high-risk incidents flagged matching filter.[/green]")

    # Save to file if output_path specified
    if output_path:
        # If output was terminal, write markdown as default file format
        text_to_save = (
            rendered_text if output_format != "terminal" else export_markdown_report(report)
        )
        output_path.write_text(text_to_save, encoding="utf-8")
        console.print(f"[bold green]Report saved to {output_path}[/bold green]")
    elif output_format != "terminal":
        # Print string directly for json, markdown, or cef to stdout
        typer.echo(rendered_text)


if __name__ == "__main__":
    app()
