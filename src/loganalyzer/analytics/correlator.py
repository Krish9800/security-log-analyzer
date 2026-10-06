"""Forensic correlation and attacker profile consolidation."""

import hashlib
import json
from datetime import UTC, datetime

from pydantic import BaseModel, Field

from loganalyzer.analytics.mitre_mapper import MitreAnalytics, MitreCoverageReport
from loganalyzer.analytics.statistics import LogStatistics, LogStatisticsCalculator
from loganalyzer.models.events import LogEvent
from loganalyzer.models.incidents import Incident


class AttackerProfile(BaseModel):
    """Consolidated profile of an adversary showing multi-stage attack tactics."""

    attacker_ip: str
    incident_count: int = 0
    incidents: list[Incident] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    targeted_users: list[str] = Field(default_factory=list)
    first_activity: datetime
    last_activity: datetime
    threat_score: float = Field(default=0.0, ge=0.0, le=100.0)


class ForensicAnalysisReport(BaseModel):
    """Comprehensive forensic report correlating log statistics, MITRE matrix, and threat incidents."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    statistics: LogStatistics
    mitre_report: MitreCoverageReport
    attacker_profiles: list[AttackerProfile] = Field(default_factory=list)
    incidents: list[Incident] = Field(default_factory=list)
    report_sha256: str = ""


class ForensicCorrelator:
    """Correlates individual events and detected incidents into consolidated attacker dossiers."""

    @classmethod
    def correlate(
        cls,
        events: list[LogEvent],
        incidents: list[Incident],
    ) -> ForensicAnalysisReport:
        """Build consolidated forensic report with attacker profiles and threat scores."""
        stats = LogStatisticsCalculator.compute(events)
        mitre_rep = MitreAnalytics.generate_report(incidents)

        # Consolidate attacker profiles
        profiles_map: dict[str, AttackerProfile] = {}
        for inc in incidents:
            ip = inc.attacker_ip
            if not ip:
                continue

            if ip not in profiles_map:
                profiles_map[ip] = AttackerProfile(
                    attacker_ip=ip,
                    first_activity=inc.first_seen,
                    last_activity=inc.last_seen,
                )

            prof = profiles_map[ip]
            prof.incident_count += 1
            prof.incidents.append(inc)

            if inc.first_seen < prof.first_activity:
                prof.first_activity = inc.first_seen
            if inc.last_seen > prof.last_activity:
                prof.last_activity = inc.last_seen

            if inc.mitre and inc.mitre.tactic not in prof.mitre_tactics:
                prof.mitre_tactics.append(inc.mitre.tactic)

            if inc.target_user and inc.target_user not in prof.targeted_users:
                prof.targeted_users.append(inc.target_user)

            # Accumulate threat score
            weight = {"CRITICAL": 30.0, "HIGH": 20.0, "MEDIUM": 10.0, "LOW": 5.0}.get(
                inc.severity, 2.0
            )
            prof.threat_score = min(100.0, prof.threat_score + weight)

        # Sort profiles by threat score descending
        sorted_profiles = sorted(profiles_map.values(), key=lambda p: p.threat_score, reverse=True)

        now = datetime.now(UTC)
        partial_rep = ForensicAnalysisReport(
            timestamp=now,
            statistics=stats,
            mitre_report=mitre_rep,
            attacker_profiles=sorted_profiles,
            incidents=incidents,
            report_sha256="",
        )

        # Compute deterministic SHA-256 fingerprint
        canonical_str = json.dumps(
            {
                "total_events": stats.total_events,
                "incident_count": len(incidents),
                "profiles": [p.attacker_ip for p in sorted_profiles],
                "tactics": mitre_rep.tactics_observed,
            },
            sort_keys=True,
        )
        digest = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
        partial_rep.report_sha256 = digest

        return partial_rep
