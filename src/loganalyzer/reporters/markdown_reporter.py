"""Markdown SOC forensic summary report generator."""

from loganalyzer.analytics.correlator import ForensicAnalysisReport


def export_markdown_report(report: ForensicAnalysisReport) -> str:
    """Render comprehensive Markdown forensic investigation report."""
    stats = report.statistics
    mitre = report.mitre_report

    lines: list[str] = [
        "# Security Log Forensic Investigation Report",
        "",
        f"**Report Generated**: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Forensic Integrity SHA-256**: `{report.report_sha256}`",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        "",
        f"- **Total Events Processed**: {stats.total_events:,}",
        f"- **Security Incidents Detected**: {len(report.incidents):,}",
        f"- **Identified Threat Actors (Adversary IPs)**: {len(report.attacker_profiles):,}",
        f"- **MITRE ATT&CK Tactics Observed**: {len(mitre.tactics_observed):,}",
        "",
        "| Metric | Count |",
        "|---|---|",
        f"| Private Internal Traffic Events | {stats.private_ip_event_count:,} |",
        f"| Public Ingress/Egress Events | {stats.public_ip_event_count:,} |",
        f"| Critical Severities Detected | {stats.events_by_severity.get('CRITICAL', 0):,} |",
        f"| High Severities Detected | {stats.events_by_severity.get('HIGH', 0):,} |",
        f"| Medium Severities Detected | {stats.events_by_severity.get('MEDIUM', 0):,} |",
        "",
        "---",
        "",
        "## 2. MITRE ATT&CK Framework Coverage",
        "",
    ]

    if mitre.tactic_summaries:
        lines.extend(
            [
                "| Tactic | Techniques Detected | Incident Count |",
                "|---|---|---|",
            ]
        )
        for tactic_name, summary in sorted(mitre.tactic_summaries.items()):
            tech_str = ", ".join(summary.technique_ids)
            lines.append(f"| **{tactic_name}** | {tech_str} | {summary.incident_count} |")
    else:
        lines.append("*No MITRE ATT&CK categorized threats observed.*")

    lines.extend(
        [
            "",
            "---",
            "",
            "## 3. High-Risk Attacker Dossiers",
            "",
        ]
    )

    if report.attacker_profiles:
        for idx, prof in enumerate(report.attacker_profiles[:5], 1):
            tactics = ", ".join(prof.mitre_tactics) if prof.mitre_tactics else "Unclassified"
            users = ", ".join(prof.targeted_users) if prof.targeted_users else "None"
            lines.extend(
                [
                    f"### Adversary #{idx}: `{prof.attacker_ip}`",
                    f"- **Threat Score**: **{prof.threat_score:.1f} / 100**",
                    f"- **Total Attack Events**: {prof.incident_count}",
                    f"- **Observed Tactics**: {tactics}",
                    f"- **Targeted Accounts**: {users}",
                    f"- **Activity Window**: {prof.first_activity.strftime('%H:%M:%S')} - {prof.last_activity.strftime('%H:%M:%S UTC')}",
                    "",
                ]
            )
    else:
        lines.append("*No adversary IP dossiers flagged.*")

    lines.extend(
        [
            "---",
            "",
            "## 4. Key Incident Findings & Recommended Remediation",
            "",
        ]
    )

    if report.incidents:
        for inc in report.incidents:
            lines.extend(
                [
                    f"#### [{inc.severity}] {inc.title}",
                    f"- **Description**: {inc.description}",
                    f"- **Attacker**: `{inc.attacker_ip or 'N/A'}` | **Target User**: `{inc.target_user or 'N/A'}`",
                    f"- **Recommended Remediation**: {inc.recommended_action}",
                    "",
                ]
            )
    else:
        lines.append("*No actionable security incidents identified.*")

    return "\n".join(lines)
