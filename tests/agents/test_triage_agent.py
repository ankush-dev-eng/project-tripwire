"""Unit Tests for Business-Context Severity Triage Agent."""

from backend.agents.models import (
    DoubleProof,
    FindingStatus,
    SeverityLevel,
    VulnerabilityCategory,
    VulnerabilityFinding,
)
from backend.agents.triage_agent import TriageAgent


def _make_dummy_finding(
    title: str,
    category: VulnerabilityCategory,
    endpoint: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        title=title,
        category=category,
        severity=SeverityLevel.LOW,
        target_endpoint=endpoint,
        method=method,
        description="Test finding description",
        cwe_id="CWE-200",
        remediation="Test remediation",
        status=FindingStatus.VERIFIED,
        proof=DoubleProof(
            primary_payload={},
            primary_request={"method": method, "url": endpoint, "headers": headers or {}},
            primary_response={"status_code": 200},
            primary_succeeded=True,
            negative_control_payload={},
            negative_control_request={"method": method, "url": f"{endpoint}-fake"},
            negative_control_response={"status_code": 404},
            negative_control_succeeded=True,
            reproduction_curl="curl ...",
        ),
    )


def test_triage_critical_payment_bola() -> None:
    triage = TriageAgent()
    finding = _make_dummy_finding(
        title="BOLA cross-tenant access to payment invoice",
        category=VulnerabilityCategory.BOLA,
        endpoint="/api/v3/bookings/pay",
        method="POST",
        headers={"Authorization": "Bearer token123"},
    )

    breakdown = triage.triage_finding(finding)

    # 0.95 (class) * 1.50 (payments) * 1.40 (cross-tenant) = 1.995 -> CRITICAL
    assert breakdown.triaged_severity == SeverityLevel.CRITICAL
    assert breakdown.final_score >= 1.50
    assert finding.severity == SeverityLevel.CRITICAL
    assert "payments_refunds" in breakdown.rationale
    assert "cross_tenant" in breakdown.rationale
    assert finding.metadata["triage"]["score"] == breakdown.final_score


def test_triage_search_catalog_low_impact() -> None:
    triage = TriageAgent()
    finding = _make_dummy_finding(
        title="SQL injection error handling on flight search",
        category=VulnerabilityCategory.INJECTION,
        endpoint="/api/v3/flights/search",
        headers={"Authorization": "Bearer token123"},
    )

    breakdown = triage.triage_finding(finding)

    # 0.85 (class) * 0.80 (search) * 1.0 (authenticated) = 0.68 -> LOW (< 0.70)
    assert breakdown.triaged_severity == SeverityLevel.LOW
    assert breakdown.final_score < 0.70
    assert finding.severity == SeverityLevel.LOW


def test_triage_shadow_route_penalty_boost() -> None:
    triage = TriageAgent()
    finding = _make_dummy_finding(
        title="Unauthenticated access to supplier internal sync",
        category=VulnerabilityCategory.API_HYGIENE,
        endpoint="/internal/supplier-sync",
    )

    normal_breakdown = triage.triage_finding(finding, is_shadow=False)
    shadow_breakdown = triage.triage_finding(finding, is_shadow=True)

    # Shadow route receives a 1.25x penalty multiplier
    assert shadow_breakdown.inventory_boost == 1.25
    assert shadow_breakdown.final_score > normal_breakdown.final_score
    assert "Visibility factor 1.25" in shadow_breakdown.rationale


def test_triage_zombie_route_penalty_boost() -> None:
    triage = TriageAgent()
    finding = _make_dummy_finding(
        title="Deprecated legacy quote endpoint logic error",
        category=VulnerabilityCategory.BUSINESS_LOGIC,
        endpoint="/api/partner/v2/quote",
    )

    normal_breakdown = triage.triage_finding(finding, is_zombie=False)
    zombie_breakdown = triage.triage_finding(finding, is_zombie=True)

    # Zombie route receives a 1.15x penalty multiplier
    assert zombie_breakdown.inventory_boost == 1.15
    assert zombie_breakdown.final_score > normal_breakdown.final_score
