"""Tests for TRIPWIRE REST API Endpoints."""

import httpx
import pytest

from backend.agents.models import (
    DoubleProof,
    FindingStatus,
    SeverityLevel,
    VulnerabilityCategory,
    VulnerabilityFinding,
)
from backend.api.app import api_app, orchestrator
from backend.safety.approval_gate import ApprovalGate
from backend.safety.audit_logger import AuditLogger
from backend.safety.http_client import SafeHttpClient
from backend.safety.kill_switch import KillSwitch
from backend.safety.rate_limiter import RateLimiter
from backend.safety.scope import ScopeManager
from lab.app import app


@pytest.fixture(autouse=True)
def setup_api_environment() -> None:
    ks = KillSwitch()
    ks.reset()
    transport = httpx.ASGITransport(app=app)
    client = SafeHttpClient(
        scope_manager=ScopeManager(kill_switch=ks),
        rate_limiter=RateLimiter(kill_switch=ks),
        approval_gate=ApprovalGate(mode="permissive"),
        audit_logger=AuditLogger(),
        kill_switch=ks,
        transport=transport,
    )
    orchestrator.client = client
    orchestrator.kill_switch = ks
    orchestrator.approval_gate = ApprovalGate(mode="strict")
    yield
    ks.reset()


@pytest.fixture
def test_client() -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=api_app)
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


@pytest.mark.asyncio
async def test_get_scan_status(test_client: httpx.AsyncClient) -> None:
    resp = await test_client.get("/api/scan/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "progress" in data
    assert "severity_breakdown" in data
    assert data["kill_switch_active"] is False


@pytest.mark.asyncio
async def test_safety_kill_and_disarm(test_client: httpx.AsyncClient) -> None:
    # 1. Trigger kill switch
    resp = await test_client.post("/api/safety/kill")
    assert resp.status_code == 200
    assert resp.json()["status"] == "KILL_SWITCH_ACTIVATED"
    assert orchestrator.kill_switch.is_active() is True

    # 2. Try starting scan while kill switch active -> should be rejected with 400
    scan_resp = await test_client.post(
        "/api/scan/start", json={"target_url": "http://127.0.0.1:8000"}
    )
    assert scan_resp.status_code == 400

    # 3. Disarm kill switch
    disarm_resp = await test_client.post("/api/safety/disarm")
    assert disarm_resp.status_code == 200
    assert disarm_resp.json()["status"] == "KILL_SWITCH_DISARMED"
    assert orchestrator.kill_switch.is_active() is False


@pytest.mark.asyncio
async def test_get_graph_and_inventory(test_client: httpx.AsyncClient) -> None:
    # Pre-populate dummy endpoint in KG
    orchestrator.kg.add_endpoint(method="GET", path="/api/v3/test")

    graph_resp = await test_client.get("/api/graph")
    assert graph_resp.status_code == 200
    graph_data = graph_resp.json()
    assert "nodes" in graph_data
    assert "edges" in graph_data
    assert any("GET /api/v3/test" in n["id"] for n in graph_data["nodes"])

    inv_resp = await test_client.get("/api/inventory")
    assert inv_resp.status_code == 200
    inv_data = inv_resp.json()
    assert "active" in inv_data
    assert "zombie" in inv_data
    assert "shadow" in inv_data


@pytest.mark.asyncio
async def test_findings_endpoints(test_client: httpx.AsyncClient) -> None:
    finding = VulnerabilityFinding(
        title="Test BOLA Finding",
        category=VulnerabilityCategory.BOLA,
        severity=SeverityLevel.CRITICAL,
        target_endpoint="/api/v3/bookings/1",
        method="GET",
        description="IDOR test",
        cwe_id="CWE-639",
        remediation="Check agency_id",
        status=FindingStatus.VERIFIED,
        proof=DoubleProof(
            primary_payload={},
            primary_request={"method": "GET", "url": "http://127.0.0.1:8000/api/v3/bookings/1"},
            primary_response={"status_code": 200},
            primary_succeeded=True,
            negative_control_payload={},
            negative_control_request={
                "method": "GET",
                "url": "http://127.0.0.1:8000/api/v3/bookings/fake",
            },
            negative_control_response={"status_code": 404},
            negative_control_succeeded=True,
            reproduction_curl="curl ...",
        ),
    )
    orchestrator.findings = [finding]

    # List all findings
    resp = await test_client.get("/api/findings")
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 1
    assert findings[0]["title"] == "Test BOLA Finding"

    # Get single finding
    single_resp = await test_client.get(f"/api/findings/{finding.finding_id}")
    assert single_resp.status_code == 200
    assert single_resp.json()["finding_id"] == finding.finding_id

    # Non-existent finding
    bad_resp = await test_client.get("/api/findings/nonexistent-id")
    assert bad_resp.status_code == 404


@pytest.mark.asyncio
async def test_approvals_workflow(test_client: httpx.AsyncClient) -> None:
    # Seed a pending approval in gate
    try:
        orchestrator.approval_gate.check_approval(
            "DELETE", "http://127.0.0.1:8000/api/v3/bookings/cancel"
        )
    except Exception as e:
        req_id = getattr(e, "request_id", None)

    assert req_id is not None

    # Verify pending approvals listing
    list_resp = await test_client.get("/api/approvals")
    assert list_resp.status_code == 200
    pending = list_resp.json()
    assert any(p["id"] == req_id for p in pending)

    # Approve request
    approve_resp = await test_client.post(
        f"/api/approvals/{req_id}/approve",
        json={"operator_id": "lead_auditor"},
    )
    assert approve_resp.status_code == 200
    assert approve_resp.json()["status"] == "APPROVED"
    assert "approval_token" in approve_resp.json()


@pytest.mark.asyncio
async def test_openapi_spec_endpoint(test_client: httpx.AsyncClient) -> None:
    resp = await test_client.get("/api/spec/openapi.json")
    assert resp.status_code == 200
    spec = resp.json()
    assert spec["openapi"] == "3.1.0"
    assert "paths" in spec
