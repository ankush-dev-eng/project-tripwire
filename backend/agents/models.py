"""Common Data Models for Agentic DAST Planning, Execution, and Verification."""

import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class VulnerabilityCategory(StrEnum):
    BOLA = "BOLA_IDOR"
    BOPLA = "BOPLA_MASS_ASSIGNMENT"
    SSRF = "SSRF_WEBHOOK_INJECTION"
    BUSINESS_LOGIC = "BUSINESS_LOGIC_TAMPERING"
    INJECTION = "INJECTION_SQLI_COMMAND"
    DATA_EXPOSURE = "EXCESSIVE_DATA_EXPOSURE"
    AUTH_SESSION = "BROKEN_AUTHENTICATION"
    API_HYGIENE = "API_HYGIENE_INFO_DISCLOSURE"


class SeverityLevel(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    VERIFIED = "VERIFIED"
    FIXED = "FIXED"
    REGRESSION = "REGRESSION"


@dataclass
class DoubleProof:
    """Verifiable double-confirmation evidence artifact."""

    primary_payload: Any
    primary_request: dict[str, Any]
    primary_response: dict[str, Any]
    primary_succeeded: bool
    negative_control_payload: Any
    negative_control_request: dict[str, Any]
    negative_control_response: dict[str, Any]
    negative_control_succeeded: bool
    reproduction_curl: str
    confidence_score: float = 1.0
    evidence_notes: str = ""

    def is_verified(self) -> bool:
        """Double proof holds only if primary exploit succeeded and negative control confirmed."""
        return (
            self.primary_succeeded
            and self.negative_control_succeeded
            and self.confidence_score >= 0.8
        )


@dataclass
class VulnerabilityFinding:
    """Standardized finding data structure across TRIPWIRE engine."""

    title: str
    category: VulnerabilityCategory
    severity: SeverityLevel
    target_endpoint: str
    method: str
    description: str
    proof: DoubleProof
    cwe_id: str
    remediation: str
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: FindingStatus = FindingStatus.VERIFIED
    discovered_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AttackPlanItem:
    """Targeted attack test vector formulated by AttackPlanner."""

    plan_id: str
    category: VulnerabilityCategory
    target_endpoint_id: str
    target_path: str
    method: str
    target_params: list[str] = field(default_factory=list)
    priority: int = 2  # 1 = Highest, 5 = Lowest
    description: str = ""
    context: dict[str, Any] = field(default_factory=dict)
