"""Security incident schemas with MITRE ATT&CK taxonomy mapping."""

import uuid
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

from loganalyzer.models.events import Severity

MITRETactic = Literal[
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


class MITRETechnique(BaseModel):
    """MITRE ATT&CK technique classification."""

    technique_id: str = Field(..., description="ID such as T1110 or T1190")
    name: str = Field(..., description="Descriptive name")
    tactic: MITRETactic
    url: str = Field(default="", description="Link to official MITRE matrix definition")


# Standard reference MITRE mappings
MITRE_BRUTE_FORCE = MITRETechnique(
    technique_id="T1110",
    name="Brute Force",
    tactic="Credential Access",
    url="https://attack.mitre.org/techniques/T1110/",
)

MITRE_WEB_EXPLOIT = MITRETechnique(
    technique_id="T1190",
    name="Exploit Public-Facing Application",
    tactic="Initial Access",
    url="https://attack.mitre.org/techniques/T1190/",
)

MITRE_PORT_SCAN = MITRETechnique(
    technique_id="T1046",
    name="Network Service Discovery",
    tactic="Discovery",
    url="https://attack.mitre.org/techniques/T1046/",
)

MITRE_PRIV_ESC = MITRETechnique(
    technique_id="T1548.003",
    name="Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    tactic="Privilege Escalation",
    url="https://attack.mitre.org/techniques/T1548/003/",
)


class Incident(BaseModel):
    """Correlated security incident derived from one or more suspicious log events."""

    id: str = Field(default_factory=lambda: f"inc-{uuid.uuid4().hex[:12]}")
    title: str = Field(..., description="Short descriptive title of the incident")
    description: str = Field(..., description="Forensic summary detailing attack vector")
    severity: Severity = Field(default="MEDIUM")
    mitre: MITRETechnique | None = Field(default=None)

    # Entities Involved
    attacker_ip: str | None = Field(default=None)
    target_user: str | None = Field(default=None)

    # Time Bounds
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Evidence Corroboration
    event_count: int = Field(default=1, ge=1)
    evidence_event_ids: list[str] = Field(default_factory=list)
    evidence_samples: list[str] = Field(default_factory=list)

    # Confidence & Action
    confidence_score: float = Field(default=0.8, ge=0.0, le=1.0)
    recommended_action: str = Field(
        default="Review host logs and isolate source IP if unauthorized."
    )
