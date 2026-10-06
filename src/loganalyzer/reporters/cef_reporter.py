"""ArcSight Common Event Format (CEF:0) incident and threat exporter."""

from loganalyzer.models.incidents import Incident


def _escape_cef(val: str | None) -> str:
    """Escape backslashes, pipes, and equals signs according to CEF standards."""
    if not val:
        return ""
    return str(val).replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")


def _severity_to_cef_number(sev: str) -> int:
    """Map string severity to ArcSight CEF integer range (1-10)."""
    mapping = {
        "INFORMATIONAL": 1,
        "LOW": 3,
        "MEDIUM": 6,
        "HIGH": 8,
        "CRITICAL": 10,
    }
    return mapping.get(sev, 5)


def export_incident_cef(incident: Incident) -> str:
    """Convert an Incident into an ArcSight CEF event line."""
    cef_sev = _severity_to_cef_number(incident.severity)
    extensions = [
        f"msg={_escape_cef(incident.description)}",
        f"cn1={incident.event_count}",
        "cn1Label=EventCount",
        f"cfp1={incident.confidence_score}",
        "cfp1Label=ConfidenceScore",
    ]

    if incident.attacker_ip:
        extensions.append(f"src={incident.attacker_ip}")

    if incident.target_user:
        extensions.append(f"suser={_escape_cef(incident.target_user)}")

    if incident.mitre:
        extensions.extend(
            [
                f"cs1={_escape_cef(incident.mitre.technique_id)}",
                "cs1Label=MitreTechniqueId",
                f"cs2={_escape_cef(incident.mitre.name)}",
                "cs2Label=MitreTechniqueName",
                f"cs3={_escape_cef(incident.mitre.tactic)}",
                "cs3Label=MitreTactic",
            ]
        )

    ext_str = " ".join(extensions)
    header = (
        f"CEF:0|SecurityLogAnalyzer|LogAnalyzer|0.1.0|"
        f"INC-100|{_escape_cef(incident.title)}|{cef_sev}|{ext_str}"
    )
    return header


def export_incidents_cef(incidents: list[Incident]) -> str:
    """Convert a sequence of Incidents into multi-line CEF format."""
    return "\n".join(export_incident_cef(inc) for inc in incidents)
