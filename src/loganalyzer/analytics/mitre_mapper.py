"""MITRE ATT&CK matrix mapping and tactic-level threat aggregation."""

from collections import Counter
from collections.abc import Iterable

from pydantic import BaseModel, Field

from loganalyzer.models.incidents import Incident, MITRETactic


class TacticSummary(BaseModel):
    """Aggregation of incidents mapped to a specific MITRE ATT&CK tactic."""

    tactic: MITRETactic
    incident_count: int = 0
    technique_ids: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    severities: dict[str, int] = Field(default_factory=dict)


class MitreCoverageReport(BaseModel):
    """Matrix coverage of observed attack tactics and techniques."""

    total_tagged_incidents: int = 0
    tactics_observed: list[MITRETactic] = Field(default_factory=list)
    tactic_summaries: dict[str, TacticSummary] = Field(default_factory=dict)
    technique_frequencies: dict[str, int] = Field(default_factory=dict)


class MitreAnalytics:
    """Computes MITRE ATT&CK framework coverage from incident findings."""

    @staticmethod
    def generate_report(incidents: Iterable[Incident]) -> MitreCoverageReport:
        """Map and aggregate incidents against MITRE ATT&CK tactics and techniques."""
        tagged_count = 0
        tactic_map: dict[str, TacticSummary] = {}
        tech_counter: Counter[str] = Counter()

        for incident in incidents:
            if not incident.mitre:
                continue

            tagged_count += 1
            tactic_name = incident.mitre.tactic
            tech_id = incident.mitre.technique_id
            tech_name = incident.mitre.name

            tech_counter[f"{tech_id} - {tech_name}"] += 1

            if tactic_name not in tactic_map:
                tactic_map[tactic_name] = TacticSummary(tactic=tactic_name)

            summary = tactic_map[tactic_name]
            summary.incident_count += 1
            if tech_id not in summary.technique_ids:
                summary.technique_ids.append(tech_id)
            if tech_name not in summary.techniques:
                summary.techniques.append(tech_name)

            summary.severities[incident.severity] = summary.severities.get(incident.severity, 0) + 1

        tactics_list = sorted(tactic_map.keys())

        return MitreCoverageReport(
            total_tagged_incidents=tagged_count,
            tactics_observed=tactics_list,  # type: ignore[arg-type]
            tactic_summaries=tactic_map,
            technique_frequencies=dict(tech_counter),
        )
